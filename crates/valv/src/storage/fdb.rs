use async_trait::async_trait;
use foundationdb::{directory::Directory, tuple::unpack, RangeOption};
use prost::Message;

use super::errors::{Result, StorageError};

use crate::gen::valv::internal;

use super::interface::ValvStorage;

pub struct FoundationDB {
    pub database: foundationdb::Database,
    location: String,
}

impl FoundationDB {
    pub async fn new(location: &str) -> Result<FoundationDB> {
        Ok(FoundationDB {
            database: foundationdb::Database::new(None)?,
            location: location.to_string(),
        })
    }
}

impl FoundationDB {
    // Key structure
    // /{read-location}/{primary-location}/{tenant, e.g. composite key of tenant+project+environment}/keys/{key_id}/metadata
    async fn get_metadata_fdb_key(
        &self,
        trx: &foundationdb::Transaction,
        tenant: &str,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
        ];

        let tenant_subspace = match directory
            .create_or_open(
                // the transaction used to read/write the directory.
                trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
        {
            Ok(subspace) => subspace,
            Err(e) => return Err(StorageError::DirectoryLayer(e)),
        };

        let path = vec![String::from(key_id), String::from("metadata")];

        match tenant_subspace.pack(&path) {
            Ok(key) => Ok(key),
            Err(e) => Err(StorageError::DirectoryLayer(e)),
        }
    }

    // Key structure
    // /{read-location}/{primary-location}/{tenant}/keys/{key_id}/versions/{version_id}
    async fn get_version_fdb_key(
        &self,
        trx: &foundationdb::Transaction,
        tenant: &str,
        key_id: &str,
        version: u32,
    ) -> Result<Vec<u8>> {
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
        ];

        let tenant_subspace = match directory
            .create_or_open(
                // the transaction used to read/write the directory.
                trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
        {
            Ok(subspace) => subspace,
            Err(e) => return Err(StorageError::DirectoryLayer(e)),
        };

        let path = vec![
            String::from(key_id),
            String::from("versions"),
            version.to_string(),
        ];

        match tenant_subspace.pack(&path) {
            Ok(key) => Ok(key),
            Err(e) => Err(StorageError::DirectoryLayer(e)),
        }
    }
}

#[async_trait]
impl ValvStorage for FoundationDB {
    async fn get_key_metadata(
        &self,
        trx: &foundationdb::RetryableTransaction,
        tenant: &str,
        key_id: &str,
    ) -> Result<Option<internal::Key>> {
        let key = self.get_metadata_fdb_key(trx, tenant, key_id).await?;

        let key_value = trx.get(&key, false).await?;
        match key_value {
            Some(key_value) => {
                let key =
                    internal::Key::decode(&key_value[..]).map_err(StorageError::ProstDecode)?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    async fn list_key_metadata(
        &self,
        trx: &foundationdb::RetryableTransaction,
        tenant: &str,
    ) -> Result<Vec<internal::Key>> {
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
        ];

        let tenant_subspace = match directory
            .create_or_open(
                // the transaction used to read/write the directory.
                trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
        {
            Ok(subspace) => subspace,
            Err(e) => return Err(StorageError::DirectoryLayer(e)),
        };

        let range = match tenant_subspace.range() {
            Ok(range) => RangeOption::from(range),
            Err(e) => return Err(StorageError::DirectoryLayer(e)),
        };

        let key_values = trx.get_range(&range, 1_024, false).await?;

        let mut keys: Vec<internal::Key> = vec![];

        // The actual key is in the value, not the key from key_alues
        for key_value in key_values.into_iter() {
            // Skip if the key is not a metadata key
            if !key_value.key().ends_with(b"metadata\x00") {
                continue;
            }

            let key = internal::Key::decode(key_value.value())?;
            keys.push(key);
        }

        Ok(keys)
    }

    async fn update_key_metadata(
        &self,
        trx: &foundationdb::RetryableTransaction,
        tenant: &str,
        key: &internal::Key,
    ) -> Result<()> {
        let path = self.get_metadata_fdb_key(trx, tenant, &key.key_id).await?;

        trx.set(&path, &key.encode_to_vec());

        Ok(())
    }

    async fn get_key_version(
        &self,
        trx: &foundationdb::RetryableTransaction,
        tenant: &str,
        key_id: &str,
        version_id: u32,
    ) -> Result<Option<internal::KeyVersion>> {
        let version_key = self
            .get_version_fdb_key(trx, tenant, key_id, version_id)
            .await?;

        let key_value = trx.get(&version_key, false).await?;

        match key_value {
            Some(key_value) => {
                let version = internal::KeyVersion::decode(&key_value[..])
                    .map_err(StorageError::ProstDecode)?;
                Ok(Some(version))
            }
            None => Ok(None),
        }
    }

    async fn get_key_versions(
        &self,
        trx: &foundationdb::RetryableTransaction,
        tenant: &str,
        key_id: &str,
    ) -> Result<Vec<internal::KeyVersion>> {
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
            String::from(key_id),
            String::from("versions"),
        ];

        let versions_directory = match directory
            .create_or_open(
                // the transaction used to read/write the directory.
                trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
        {
            Ok(subspace) => subspace,
            Err(e) => return Err(StorageError::DirectoryLayer(e)),
        };

        let range = match versions_directory.range() {
            Ok(range) => RangeOption::from(range),
            Err(e) => return Err(StorageError::DirectoryLayer(e)),
        };

        let key_values = trx.get_range(&range, 1_024, false).await?;

        let mut key_versions: Vec<internal::KeyVersion> = vec![];

        for key_value in key_values.iter() {
            let test: Vec<u8> = unpack(key_value.value()).map_err(StorageError::TuplePacking)?;
            let version =
                internal::KeyVersion::decode(&test[..]).map_err(StorageError::ProstDecode)?;
            key_versions.push(version);
        }

        Ok(key_versions)
    }

    async fn append_key_version(
        &self,
        trx: &foundationdb::RetryableTransaction,
        tenant: &str,
        key: &internal::Key,
        key_version: &internal::KeyVersion,
    ) -> Result<()> {
        let version_key = self
            .get_version_fdb_key(trx, tenant, &key.key_id, key_version.version)
            .await?;

        trx.set(&version_key, &key_version.encode_to_vec());

        Ok(())
    }

    async fn update_key_version(
        &self,
        _trx: &foundationdb::RetryableTransaction,
        _tenant: &str,
        _key_id: &str,
        _version_id: u32,
        _version: &internal::KeyVersion,
    ) -> Result<()> {
        todo!()
    }
}
