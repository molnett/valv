
use boring::error::ErrorStack;
use gen::keystore::internal;
use prost::bytes::Buf;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use storage::{fdb::FoundationDB, interface::KeystoreStorage};

pub mod api;
mod gen;
mod storage;
mod tests;

pub mod valv {
    pub mod keystore {
        pub mod v1 {
            include!("gen/valv.keystore.v1.rs");
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
    async fn create_key(&self, name: String) -> internal::Key;
    async fn get_key(&self, name: String) -> Option<internal::Key>;

    async fn encrypt(&self, key_name: String, plaintext: Vec<u8>) -> Vec<u8>;
    async fn decrypt(&self, key_name: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, ErrorStack>;
}

pub struct Keystore {
    pub db: FoundationDB,
    pub master_key: Secret<[u8; 32]>,
}

impl Keystore {
    pub async fn new() -> Keystore {
        Keystore {
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
    async fn create_key(&self, name: String) -> internal::Key {
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
            key_id: name.clone(),
            primary_version_id: 1.to_string(),
            purpose: "ENCRYPT_DECRYPT".to_string(),
            ..Default::default()
        };

        self.db
            .update_key_metadata("molnett", key.clone()).await.unwrap();

        let key_version = internal::KeyVersion{
            key_id: name.clone(),
            key_material: encrypted_result.to_vec().into(),
            state: internal::KeyVersionState::Enabled as i32,
            version: 1,
            ..Default::default()
        };

        self.db
            .append_key_version(
                "molnett",
                key.clone(),
                key_version,
            )
            .await
            .unwrap();

        key
    }

    async fn get_key(&self, name: String) -> Option<internal::Key> {
        let key = self
            .db
            .get_key_metadata("molnett", name.as_str())
            .await
            .unwrap();

        Some(key)
    }

    async fn encrypt(&self, key_name: String, plaintext: Vec<u8>) -> Vec<u8> {
        let key = self.db.get_key_metadata("molnett", &key_name).await.unwrap();
        let key_version = self.db.get_key_version("molnett", &key.key_id, key.primary_version_id.parse().unwrap()).await.unwrap();

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

    async fn decrypt(&self, key_name: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
        let (key_version_id, remainder) = ciphertext.split_at(4);
        let (iv, remainder) = remainder.split_at(12);
        let (cipher, tag) = remainder.split_at(remainder.len() - 16);

        let key = self.db.get_key_metadata("molnett", &key_name).await.unwrap();
        let key_version_id = std::io::Cursor::new(key_version_id).get_u32();
        let key_version = self.db.get_key_version("molnett", &key.key_id, key_version_id).await.unwrap();

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
