use anyhow::anyhow;
use async_trait::async_trait;
use foundationdb::{
    directory::{Directory, DirectoryError},
    tuple::{unpack, TuplePack},
    FdbError,
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

#[async_trait]
impl KeystoreStorage for FoundationDB {
    async fn get_key_metadata(
        &self,
        tenant: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let trx = self.database.create_trx()?;

        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![String::from(self.location.as_str()), String::from(tenant)];

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

        let path = vec![String::from("metadata"), String::from(key_id)];

        let key = tenant_subspace.pack(&path).unwrap();

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

        let directory = foundationdb::directory::DirectoryLayer::default();

        let path = vec![String::from(self.location.as_str()), String::from(tenant)];

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

        let path = vec![String::from("metadata"), String::from(key_id)];

        let key = tenant_subspace.pack(&path).unwrap();

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
        todo!()
    }

    async fn append_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()> {
        todo!()
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
