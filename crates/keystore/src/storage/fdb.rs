use anyhow::anyhow;
use async_trait::async_trait;
use foundationdb::{
    directory::{Directory},
    tuple::{unpack, TuplePack},
    FdbError, RangeOption,
};

use super::interface::KeystoreStorage;

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
    // /{read-location}/{primary-location}/{tenant}/keys/{key_id}/metadata
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
        version: u8,
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
impl KeystoreStorage for FoundationDB {
    async fn get_key_metadata(
        &self,
        tenant: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let trx = self.database.create_trx()?;
        let key = self.get_metadata_fdb_key(&trx, tenant, key_id).await;

        let key_value = trx.get(&key, false).await?;
        match key_value {
            Some(key_value) => {
                let test: Vec<u8> = unpack(&key_value).expect("Failed to unpack key value");
                Ok(Some(test))
            }
            None => Err(anyhow!("Key not found")),
        }
    }

    async fn update_key_metadata(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()> {
        let trx = self.database.create_trx()?;
        let key = self.get_metadata_fdb_key(&trx, tenant, key_id).await;

        trx.set(&key, &value.pack_to_vec());
        trx.commit().await.unwrap();

        Ok(())
    }

    async fn get_key_versions(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
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

        let key_versions: Vec<Vec<u8>> = vec![];

        for key_value in key_values.iter() {
            println!("{:?}", key_value.key());
            //let version_data: Vec<u8> = unpack(&key_value.value()).expect("failed to decode key version");
        }

        Ok(vec![])
    }

    async fn append_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()> {
        let trx = self.database.create_trx()?;
        let key = self.get_metadata_fdb_key(&trx, tenant, key_id).await;

        Ok(())
    }

    async fn update_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()> {
        todo!()
    }
}
