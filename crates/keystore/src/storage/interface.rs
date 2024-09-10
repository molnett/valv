use async_trait::async_trait;

use crate::gen::keystore::internal;

#[async_trait]
pub trait KeystoreStorage {
    async fn get_key_metadata(&self, tenant: &str, key_id: &str)
        -> anyhow::Result<internal::Key>;
    async fn list_key_metadata(&self, tenant: &str) -> anyhow::Result<Vec<internal::Key>>;
    async fn update_key_metadata(
        &self,
        tenant: &str,
        key: internal::Key,
    ) -> anyhow::Result<()>;
    async fn get_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        version_id: u32,
    ) -> anyhow::Result<internal::KeyVersion>;
    async fn get_key_versions(&self, tenant: &str, key_id: &str) -> anyhow::Result<Vec<internal::KeyVersion>>;
    async fn append_key_version(
        &self,
        tenant: &str,
        key: internal::Key,
        key_version: internal::KeyVersion
    ) -> anyhow::Result<()>;
    async fn update_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        version_id: u32,
        version: internal::KeyVersion
    ) -> anyhow::Result<()>;
}
