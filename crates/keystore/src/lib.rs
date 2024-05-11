use std::{collections::HashMap, sync::RwLock};

use boring::error::ErrorStack;
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

pub struct DecryptedKey {
    pub name: String,
    pub decrypted_key: [u8; 32],
    pub iv: [u8; 12],
}

#[async_trait::async_trait]
pub trait KeystoreAPI: Send + Sync {
    fn list_crypto_keys(&self);
    async fn create_crypto_key(&self, name: String) -> CryptoKey;
    async fn get_crypto_key(&self, name: String) -> Option<CryptoKey>;

    fn encrypt(&self, key_name: String, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt(&self, key_name: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, ErrorStack>;
}

pub struct Keystore {
    pub db: FoundationDB,
    pub keys: RwLock<HashMap<String, CryptoKey>>,
    pub decrypted_keys_cache: RwLock<HashMap<String, DecryptedKey>>,
    pub master_key: Secret<[u8; 32]>,
}

impl Keystore {
    pub async fn new() -> Keystore {
        Keystore {
            db: FoundationDB::new("local").await.unwrap(),
            keys: RwLock::new(HashMap::new()),
            decrypted_keys_cache: RwLock::new(HashMap::new()),
            master_key: [0; 32].into(),
        }
    }

    pub fn set_master_key(&mut self, key: [u8; 32]) {
        self.master_key = Secret::new(key);
    }
}

#[async_trait::async_trait]
impl KeystoreAPI for Keystore {
    async fn create_crypto_key(&self, name: String) -> CryptoKey {
        let mut iv = [0; 12];
        let mut key = [0; 32];
        boring::rand::rand_bytes(&mut iv).unwrap();
        boring::rand::rand_bytes(&mut key).unwrap();

        let encrypted_key = boring::symm::encrypt(
            boring::symm::Cipher::aes_256_gcm(),
            self.master_key.expose_secret(),
            Some(&iv),
            &key,
        )
        .unwrap();

        let mut encrypted_result: [u8; 44] = [0; 44];
        let (one, two) = encrypted_result.split_at_mut(12);
        one.copy_from_slice(&iv);
        two.copy_from_slice(&encrypted_key);

        let crypto_key = CryptoKey {
            name: name.clone(),
            // IV + encrypted key
            encrypted_value: encrypted_result.to_vec(),
        };
        self.db
            .append_key_version(
                "molnett",
                name.clone().as_str(),
                bincode::serialize(&crypto_key).unwrap(),
            )
            .await
            .unwrap();
        self.db
            .update_key_metadata(
                "molnett",
                name.clone().as_str(),
                bincode::serialize(&crypto_key).unwrap(),
            )
            .await
            .unwrap();
        self.keys
            .write()
            .unwrap()
            .insert(name.clone(), crypto_key.clone());

        let decrypted_key = DecryptedKey {
            name: name.clone(),
            decrypted_key: key,
            iv,
        };
        self.decrypted_keys_cache
            .write()
            .unwrap()
            .insert(name.clone(), decrypted_key);

        println!("Created crypto key: {}", name);

        crypto_key
    }

    fn list_crypto_keys(&self) {
        println!("{:?}", self.keys.read().unwrap().keys());
    }

    async fn get_crypto_key(&self, name: String) -> Option<CryptoKey> {
        let key = self
            .db
            .get_key_metadata("molnett", name.as_str())
            .await
            .unwrap();

        key.as_ref().map(|k| bincode::deserialize(k).unwrap())
    }

    fn encrypt(&self, key_name: String, plaintext: Vec<u8>) -> Vec<u8> {
        println!("Encrypting with key: {}", key_name);
        let keys = self.keys.read().unwrap();
        let key = keys.get(&key_name).unwrap();
        let mut iv = [0; 12];
        boring::rand::rand_bytes(&mut iv).unwrap();

        let mut tag = [0; 16];

        let encrypted_key = boring::symm::encrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            &self
                .decrypted_keys_cache
                .read()
                .unwrap()
                .get(&key.name)
                .unwrap()
                .decrypted_key,
            Some(&iv),
            &[],
            &plaintext,
            &mut tag,
        )
        .unwrap();

        let mut encrypted_result: Vec<u8> = vec![];
        // Add IV and encrypted key to result
        encrypted_result.append(iv.to_vec().as_mut());
        encrypted_result.append(encrypted_key.to_vec().as_mut());
        encrypted_result.append(tag.to_vec().as_mut());

        encrypted_result
    }

    fn decrypt(&self, key_name: String, ciphertext: Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
        println!("Decrypting with key: {}", key_name);
        let keys = self.keys.read().unwrap();
        let key = keys.get(&key_name).unwrap();

        let (iv, remainder) = ciphertext.split_at(12);
        let (cipher, tag) = remainder.split_at(remainder.len() - 16);

        boring::symm::decrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            &self
                .decrypted_keys_cache
                .read()
                .unwrap()
                .get(&key.name)
                .unwrap()
                .decrypted_key,
            Some(&iv),
            &[],
            &cipher,
            tag,
        )
    }
}
