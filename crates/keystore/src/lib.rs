use std::{sync::Arc, time::UNIX_EPOCH};

use boring::error::ErrorStack;
use clock::Clock;
use gen::keystore::internal;
use prost::bytes::Buf;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use storage::{fdb::FoundationDB, interface::KeystoreStorage};

pub mod api;
pub mod clock;
pub mod gen;

//mod rotator;
mod storage;
mod tests;


pub mod valv {
    pub mod keystore {
        pub mod v1 {
            include!("gen/keystore.v1.rs");
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoKey {
    pub name: String,
    pub encrypted_value: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoKeyVersion {
    pub version: u32,
    pub wrapped_key: Vec<u8>,
}

pub struct KeyMaterial {
    pub name: String,
    pub decrypted_key: [u8; 32],
    pub iv: [u8; 12],
}

#[async_trait::async_trait]
pub trait KeystoreAPI: Send + Sync {
    async fn list_tenants(&self) -> Result<Vec<String>, anyhow::Error>;

    async fn create_key(&self, tenant: &str, name: &str) -> internal::Key;
    async fn get_key(&self, tenant: &str, name: &str) -> Option<internal::Key>;
    async fn list_keys(&self, tenant: &str) -> Option<Vec<internal::Key>>;
    async fn update_key(&self, tenant: &str, key: internal::Key) -> internal::Key;

    async fn get_key_version(&self, tenant: &str, key_name: &str, version_id: u32) -> Option<internal::KeyVersion>;

    async fn encrypt(&self, tenant: &str, key_name: &str, plaintext: Vec<u8>) -> Vec<u8>;
    async fn decrypt(&self, tenant: &str, key_name: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, ErrorStack>;
}

pub struct Keystore {
    clock: Arc<dyn Clock>,
    pub db: FoundationDB,
    pub master_key: Secret<[u8; 32]>,
}

impl Keystore {
    pub async fn new(clock: Arc<dyn Clock>) -> Keystore {
        Keystore {
            clock,
            db: FoundationDB::new("local").await.unwrap(),
            master_key: [0; 32].into(),
        }
    }

    pub fn set_master_key(&mut self, key: [u8; 32]) {
        self.master_key = Secret::new(key);
    }
}

#[async_trait::async_trait]
impl KeystoreAPI for Keystore {
    async fn list_tenants(&self) -> Result<Vec<String>, anyhow::Error> {
        self.db.list_tenants().await
    }

    async fn get_key(&self, tenant: &str, name: &str) -> Option<internal::Key> {
        let key = self
            .db
            .get_key_metadata(tenant, name)
            .await
            .unwrap();

        Some(key)
    }

    async fn list_keys(&self, tenant: &str) -> Option<Vec<internal::Key>> {
        let keys = self.db.list_key_metadata(tenant).await.unwrap();
        Some(keys)
    }

    async fn create_key(&self, tenant: &str, name: &str) -> internal::Key {
        let mut iv = [0; 12];
        let mut key = [0; 32];
        let mut tag = [0; 16];
        boring::rand::rand_bytes(&mut iv).unwrap();
        boring::rand::rand_bytes(&mut key).unwrap();

        let encrypted_key = boring::symm::encrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            self.master_key.expose_secret(),
            Some(&iv),
            &[],
            &key,
            &mut tag,
        )
        .unwrap();

        let mut encrypted_result = Vec::with_capacity(
            iv.len() +
            encrypted_key.len() +
            tag.len()
        );
    
        // Add IV, key material and tag to result
        encrypted_result.extend_from_slice(&iv);
        encrypted_result.extend_from_slice(&encrypted_key);
        encrypted_result.extend_from_slice(&tag);

        let key = internal::Key {
            key_id: name.to_string(),
            primary_version_id: 1.to_string(),
            purpose: "ENCRYPT_DECRYPT".to_string(),
            creation_time: Some(prost_types::Timestamp {
                seconds: self.clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                nanos: self.clock.now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i32,
            }),
            rotation_schedule: Some(prost_types::Duration {
                seconds: chrono::TimeDelta::days(30).num_seconds() as i64,
                nanos: 0,
            }),
            ..Default::default()
        };

        self.db
            .update_key_metadata(tenant, key.clone()).await.unwrap();

        let key_version = internal::KeyVersion {
            key_id: name.to_string(),
            key_material: encrypted_result.to_vec().into(),
            state: internal::KeyVersionState::Enabled as i32,
            version: 1,
            creation_time: Some(prost_types::Timestamp {
                seconds: self.clock.now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
                nanos: self.clock.now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as i32,
            }),
            ..Default::default()
        };

        self.db
            .append_key_version(
                tenant,
                key.clone(),
                key_version,
            )
            .await
            .unwrap();

        key
    }

    async fn update_key(&self, tenant: &str, key: internal::Key) -> internal::Key {
        self.db.update_key_metadata(tenant, key.clone()).await.unwrap();
        
        key
    }

    async fn get_key_version(&self, tenant: &str, key_name: &str, version_id: u32) -> Option<internal::KeyVersion> {
        let key_version = self.db.get_key_version(tenant, &key_name, version_id).await.unwrap();
        Some(key_version)
    }

    async fn encrypt(&self, tenant: &str, key_name: &str, plaintext: Vec<u8>) -> Vec<u8> {
        let key = self.db.get_key_metadata(tenant, &key_name).await.unwrap();
        let key_version = self.db.get_key_version(tenant, &key.key_id, key.primary_version_id.parse().unwrap()).await.unwrap();

        let (iv, remainder) = key_version.key_material.split_at(12);
        let (cipher, tag) = remainder.split_at(remainder.len() - 16);

        let decrypted_key_material = boring::symm::decrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            self.master_key.expose_secret(),
            Some(&iv),
            &[],
            &cipher,
            tag,
        ).expect("Failed to decrypt key material");

        let mut iv = [0; 12];
        boring::rand::rand_bytes(&mut iv).unwrap();

        let mut tag = [0; 16];

        let encrypted_key = boring::symm::encrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            &decrypted_key_material,
            Some(&iv),
            &[],
            &plaintext,
            &mut tag,
        )
        .unwrap();

        let mut encrypted_result = Vec::with_capacity(
            4 + // Key version (u32)
            iv.len() +
            encrypted_key.len() +
            tag.len()
        );
    
        // Add version, IV and encrypted key to result
        encrypted_result.extend_from_slice(&(key_version.version as u32).to_be_bytes());

        encrypted_result.extend_from_slice(&iv);
        encrypted_result.extend_from_slice(&encrypted_key);
        encrypted_result.extend_from_slice(&tag);

        encrypted_result
    }

    async fn decrypt(&self, tenant: &str, key_name: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
        let (key_version_id, remainder) = ciphertext.split_at(4);
        let (iv, remainder) = remainder.split_at(12);
        let (cipher, tag) = remainder.split_at(remainder.len() - 16);

        let key = self.db.get_key_metadata(tenant, &key_name).await.unwrap();
        let key_version_id = std::io::Cursor::new(key_version_id).get_u32();
        let key_version = self.db.get_key_version(tenant, &key.key_id, key_version_id).await.unwrap();

        let (kv_iv, kv_remainder) = key_version.key_material.split_at(12);
        let (kv_cipher, kv_tag) = kv_remainder.split_at(kv_remainder.len() - 16);

        let decrypted_key_material = boring::symm::decrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            self.master_key.expose_secret(),
            Some(&kv_iv),
            &[],
            &kv_cipher,
            kv_tag,
        ).expect("Failed to decrypt key material");

        boring::symm::decrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            &decrypted_key_material,
            Some(&iv),
            &[],
            &cipher,
            tag,
        )
    }
}

#[cfg(test)]
mod unittests {
    use super::*;
    use std::{panic, sync::Arc};
    use foundationdb::api::NetworkAutoStop;
    use tokio::sync::Mutex;

    struct MockClock {
        now: std::time::SystemTime,
    }

    impl Clock for MockClock {
        fn now(&self) -> std::time::SystemTime {
            self.now
        }
    }

    async fn setup_keystore() -> Arc<Mutex<Keystore>> {
        let mock_clock = Arc::new(MockClock {
            now: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000),
        });
        let mut keystore = Keystore::new(mock_clock).await;
        keystore.set_master_key([1; 32]);
        Arc::new(Mutex::new(keystore))
    }

    #[tokio::test]
    async fn run_all_tests() {
        let _guard = unsafe { foundationdb::boot() };

        let keystore = setup_keystore().await;

        test_create_and_get_key(&keystore).await;
        test_list_keys(&keystore).await;
        test_update_key(&keystore).await;
        test_encrypt_and_decrypt(&keystore).await;
        test_list_tenants(&keystore).await;
        test_get_key_version(&keystore).await;

    }

    async fn test_create_and_get_key(keystore: &Arc<Mutex<Keystore>>) {
        let tenant = "test_tenant";
        let key_name = "test_key";

        let created_key = keystore.lock().await.create_key(tenant, key_name).await;
        assert_eq!(created_key.key_id, key_name);

        let retrieved_key = keystore.lock().await.get_key(tenant, key_name).await.unwrap();
        assert_eq!(retrieved_key, created_key);
    }

    async fn test_list_keys(keystore: &Arc<Mutex<Keystore>>) {
        let tenant = "test_tenant_list";
        let key_names = vec!["key1", "key2", "key3"];

        for name in &key_names {
            keystore.lock().await.create_key(tenant, name).await;
        }

        let listed_keys = keystore.lock().await.list_keys(tenant).await.unwrap();
        assert_eq!(listed_keys.len(), key_names.len());
        for key in listed_keys {
            assert!(key_names.contains(&key.key_id.as_str()));
        }
    }

    async fn test_update_key(keystore: &Arc<Mutex<Keystore>>) {
        let tenant = "test_tenant_update";
        let key_name = "test_key_update";

        let mut created_key = keystore.lock().await.create_key(tenant, key_name).await;
        created_key.purpose = "SIGN_VERIFY".to_string();

        let updated_key = keystore.lock().await.update_key(tenant, created_key.clone()).await;
        assert_eq!(updated_key.purpose, "SIGN_VERIFY");

        let retrieved_key = keystore.lock().await.get_key(tenant, key_name).await.unwrap();
        assert_eq!(retrieved_key, updated_key);
    }

    async fn test_encrypt_and_decrypt(keystore: &Arc<Mutex<Keystore>>) {
        let tenant = "test_tenant_encrypt";
        let key_name = "test_key_encrypt";
        let plaintext = b"Hello, World!".to_vec();

        keystore.lock().await.create_key(tenant, key_name).await;

        let ciphertext = keystore.lock().await.encrypt(tenant, key_name, plaintext.clone()).await;
        assert_ne!(ciphertext, plaintext);

        let decrypted = keystore.lock().await.decrypt(tenant, key_name, ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    async fn test_list_tenants(keystore: &Arc<Mutex<Keystore>>) {
        let tenants = vec!["tenant1", "tenant2", "tenant3"];

        for tenant in &tenants {
            keystore.lock().await.create_key(tenant, "dummy_key").await;
        }

        let listed_tenants = keystore.lock().await.list_tenants().await.unwrap();
        assert_eq!(listed_tenants.len(), tenants.len());
        for tenant in tenants {
            assert!(listed_tenants.contains(&tenant.to_string()));
        }
    }

    async fn test_get_key_version(keystore: &Arc<Mutex<Keystore>>) {
        let tenant = "test_tenant_version";
        let key_name = "test_key_version";

        let created_key = keystore.lock().await.create_key(tenant, key_name).await;
        let version_id = created_key.primary_version_id.parse::<u32>().unwrap();

        let key_version = keystore.lock().await.get_key_version(tenant, key_name, version_id).await.unwrap();
        assert_eq!(key_version.key_id, key_name);
        assert_eq!(key_version.version, version_id);
    }
}
