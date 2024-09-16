use anyhow::anyhow;
use async_trait::async_trait;
use foundationdb::{
    directory::Directory,
    tuple::unpack,
    FdbError, RangeOption,
};
use prost::Message;

use crate::gen::valv::internal;

use super::interface::ValvStorage;

pub struct FoundationDB {
    database: foundationdb::Database,
    location: String,
}

impl FoundationDB {
    pub async fn new(location: &str) -> Result<FoundationDB, FdbError> {
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
    ) -> Vec<u8> {
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
        ];

        let tenant_subspace = directory
            .create_or_open(
                // the transaction used to read/write the directory.
                &trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
            .expect("could not create directory");

        let path = vec![String::from(key_id), String::from("metadata")];

        let key = tenant_subspace.pack(&path).unwrap();
        return key;
    }

    // Key structure
    // /{read-location}/{primary-location}/{tenant}/keys/{key_id}/versions/{version_id}
    async fn get_version_fdb_key(
        &self,
        trx: &foundationdb::Transaction,
        tenant: &str,
        key_id: &str,
        version: u32,
    ) -> Vec<u8> {
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
        ];

        let tenant_subspace = directory
            .create_or_open(
                // the transaction used to read/write the directory.
                &trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
            .unwrap();

        let path = vec![
            String::from(key_id),
            String::from("versions"),
            version.to_string(),
        ];

        let key = tenant_subspace.pack(&path).unwrap();

        return key;
    }
}

#[async_trait]
impl ValvStorage for FoundationDB {
    async fn get_key_metadata(
        &self,
        tenant: &str,
        key_id: &str,
    ) -> anyhow::Result<internal::Key> {
        let trx = self.database.create_trx()?;
        let key = self.get_metadata_fdb_key(&trx, tenant, key_id).await;

        let key_value = trx.get(&key, false).await?;
        match key_value {
            Some(key_value) => {
                let key = internal::Key::decode(&key_value[..]).expect("Failed to decode key");
                Ok(key)
            }
            None => Err(anyhow!("Key not found")),
        }
    }

    async fn list_key_metadata(&self, tenant: &str) -> anyhow::Result<Vec<internal::Key>> {
        let trx = self.database.create_trx()?;
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
        ];

        let tenant_subspace = directory
            .create_or_open(
                // the transaction used to read/write the directory.
                &trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
            .unwrap();

        let range = RangeOption::from(tenant_subspace.range().unwrap());

        let key_values = trx
            .get_range(&range, 1_024, false)
            .await
            .expect("failed to get keys");

        let mut keys: Vec<internal::Key> = vec![];

        // The actual key is in the value, not the key from key_alues
        for key_value in key_values.into_iter() {
            // Skip if the key is not a metadata key
            if !key_value.key().ends_with(b"metadata\x00") {
                continue
            }

            let key = internal::Key::decode(&key_value.value()[..]).expect("Failed to decode key");
            keys.push(key);
        }

        Ok(keys)
    }

    async fn update_key_metadata(
        &self,
        tenant: &str,
        key: internal::Key,
    ) -> anyhow::Result<()> {
        let trx = self.database.create_trx()?;
        let path = self.get_metadata_fdb_key(&trx, tenant, &key.key_id).await;

        trx.set(&path, &key.encode_to_vec());
        trx.commit().await.unwrap();

        Ok(())
    }

    async fn get_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        version_id: u32,
    ) -> anyhow::Result<internal::KeyVersion> {
        let trx = self.database.create_trx()?;
        
        let version_key = self.get_version_fdb_key(&trx, tenant, key_id, version_id).await;

        let key_value = trx.get(&version_key, false).await?;

        match key_value {
            Some(key_value) => {
                let version = internal::KeyVersion::decode(&key_value[..]).expect("Failed to decode key");
                Ok(version)
            }
            None => Err(anyhow!("Key not found")),
        }
    }

    async fn get_key_versions(&self, tenant: &str, key_id: &str) -> anyhow::Result<Vec<internal::KeyVersion>> {
        let trx = self.database.create_trx()?;
        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![
            String::from(self.location.as_str()),
            String::from(tenant),
            String::from("keys"),
            String::from(key_id),
            String::from("versions"),
        ];

        let versions_directory = directory
            .create_or_open(
                // the transaction used to read/write the directory.
                &trx,
                // the path used, which can view as a UNIX path like `/app/my-app`.
                &path, // do not use any custom prefix or layer
                None, None,
            )
            .await
            .unwrap();

        let range = RangeOption::from(versions_directory.range().unwrap());

        let key_values = trx
            .get_range(&range, 1_024, false)
            .await
            .expect("failed to get key versions");

        let mut key_versions: Vec<internal::KeyVersion> = vec![];

        for key_value in key_values.iter() {
            let test: Vec<u8> = unpack(&key_value.value()).expect("Failed to unpack key value");
            let version = internal::KeyVersion::decode(&test[..]).expect("Failed to decode key version");
            key_versions.push(version);
        }

        Ok(key_versions)
    }

    async fn append_key_version(
        &self,
        tenant: &str,
        key: internal::Key,
        key_version: internal::KeyVersion
    ) -> anyhow::Result<()> {
        let trx = self.database.create_trx()?;
        
        let version_key = self.get_version_fdb_key(&trx, tenant, &key.key_id, key_version.version).await;

        trx.set(&version_key, &key_version.encode_to_vec());
        trx.commit().await.unwrap();

        Ok(())
    }

    async fn update_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        version_id: u32,
        version: internal::KeyVersion
    ) -> anyhow::Result<()> {
        todo!()
    }
}
