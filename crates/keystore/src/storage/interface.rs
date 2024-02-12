use async_trait::async_trait;

#[async_trait]
pub trait KeystoreStorage {
    async fn get_key_metadata(&self, tenant: &str, key_id: &str)
        -> anyhow::Result<Option<Vec<u8>>>;
    async fn update_key_metadata(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()>;
    async fn get_key_versions(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<Vec<Vec<u8>>>;
    async fn append_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()>;
    async fn update_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        value: Vec<u8>,
    ) -> anyhow::Result<()>;
}
