use async_trait::async_trait;

use crate::{errors::Result, gen::valv::internal};

#[async_trait]
pub trait ValvStorage {
    async fn get_key_metadata(&self, tenant: &str, key_id: &str) -> Result<internal::Key>;
    async fn list_key_metadata(&self, tenant: &str) -> Result<Vec<internal::Key>>;
    async fn update_key_metadata(&self, tenant: &str, key: internal::Key) -> Result<()>;
    async fn get_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        version_id: u32,
    ) -> Result<internal::KeyVersion>;
    #[allow(unused)]
    async fn get_key_versions(
        &self,
        tenant: &str,
        key_id: &str,
    ) -> Result<Vec<internal::KeyVersion>>;
    async fn append_key_version(
        &self,
        tenant: &str,
        key: internal::Key,
        key_version: internal::KeyVersion,
    ) -> Result<()>;
    #[allow(unused)]
    async fn update_key_version(
        &self,
        tenant: &str,
        key_id: &str,
        version_id: u32,
        version: internal::KeyVersion,
    ) -> Result<()>;
}
