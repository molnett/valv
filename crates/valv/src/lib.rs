use core::panic;

use errors::{Result, ValvError};
use foundationdb::RetryableTransaction;
use gen::valv::internal;
use prost::bytes::Buf;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use storage::{fdb::FoundationDB, interface::ValvStorage};

pub mod api;
pub mod errors;
pub mod gen;
mod integration_tests;
mod storage;

pub mod valv {
    pub mod proto {
        pub mod v1 {
            #![allow(clippy::unwrap_used)]
            include!("gen/valv.v1.rs");
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoKey<'a> {
    pub name: &'a str,
    pub encrypted_value: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoKeyVersion {
    pub version: u32,
    pub wrapped_key: Vec<u8>,
}

pub struct KeyMaterial<'a> {
    pub name: &'a str,
    pub decrypted_key: [u8; 32],
    pub iv: [u8; 12],
}

#[async_trait::async_trait]
pub trait ValvAPI: Send + Sync {
    //async fn rotate_master_key(&self) -> Result<internal::Key>;
    async fn create_master_key(&self) -> Result<internal::Key>;

    async fn create_key(&self, tenant: &str, name: &str) -> Result<internal::Key>;
    // TODO: Separate get_key into get_key_metadata and get_key_with_primary_version
    async fn get_key(&self, tenant: &str, name: &str) -> Result<Option<internal::Key>>;
    async fn list_keys(&self, tenant: &str) -> Result<Option<Vec<internal::Key>>>;
    async fn update_key(&self, tenant: &str, key: internal::Key) -> Result<internal::Key>;

    //async fn rotate_key(&self, tenant: &str, name: &str) -> Result<()>;

    async fn get_key_version(
        &self,
        tenant: &str,
        key_name: &str,
        version_id: u32,
    ) -> Result<Option<internal::KeyVersion>>;

    async fn encrypt(&self, tenant: &str, key_name: &str, plaintext: Vec<u8>) -> Result<Vec<u8>>;
    async fn decrypt(&self, tenant: &str, key_name: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>>;
}

#[derive(PartialEq, Debug)]
pub enum ValvState {
    MissingMasterKey,
    Unlocked,
}

pub struct Valv {
    pub db: FoundationDB,
    root_key: Secret<[u8; 32]>,
    state: ValvState,
}

#[allow(clippy::expect_used)]
impl Valv {
    pub async fn new(key: [u8; 32]) -> Result<Valv> {
        let db = FoundationDB::new("local").await?;

        let mut valv = Valv {
            db,
            root_key: key.into(),
            state: ValvState::MissingMasterKey,
        };

        match valv.get_key("valv", "master_key").await {
            Ok(_) => {
                valv.state = ValvState::Unlocked;
            }
            Err(ValvError::KeyNotFound(_)) => {
                // Here we allow expect as we want to crash if we cannot create the master key.
                // Without a master key, the system is not functional.
                valv.create_master_key()
                    .await
                    .expect("Could not create master key");

                valv.state = ValvState::Unlocked;
            }
            Err(e) => {
                panic!(
                    "Could not attempt to get wrapped master key due to: {}",
                    e.to_string()
                );
            }
        }

        Ok(valv)
    }
}

#[async_trait::async_trait]
impl ValvAPI for Valv {
    async fn get_key(&self, tenant: &str, key_name: &str) -> Result<Option<internal::Key>> {
        assert_ne!(self.state, ValvState::MissingMasterKey);

        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;
                let key = self.db.get_key_metadata(&trx, tenant, key_name).await?;

                Ok(key)
            })
            .await;

        match trx_result {
            Ok(key) => Ok(key),
            Err(e) => {
                println!("Error getting key {}: {e}", key_name);
                Err(ValvError::Storage(storage::errors::StorageError::Binding(
                    e,
                )))
            }
        }
    }

    async fn list_keys(&self, tenant: &str) -> Result<Option<Vec<internal::Key>>> {
        assert_ne!(self.state, ValvState::MissingMasterKey);

        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;
                let keys = self.db.list_key_metadata(&trx, tenant).await?;

                Ok(Some(keys))
            })
            .await;

        match trx_result {
            Ok(keys) => Ok(keys),
            Err(e) => {
                println!("Error listing keys for tenant {}: {e}", tenant);
                Err(ValvError::Storage(storage::errors::StorageError::Binding(
                    e,
                )))
            }
        }
    }

    async fn create_master_key(&self) -> Result<internal::Key> {
        let mut iv = [0; 12];
        let mut key = [0; 32];
        let mut tag = [0; 16];
        boring::rand::rand_bytes(&mut iv)?;
        boring::rand::rand_bytes(&mut key)?;

        println!("encrypting with root key");

        let encrypted_key = boring::symm::encrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            self.root_key.expose_secret(),
            Some(&iv),
            &[],
            &key,
            &mut tag,
        )?;

        let encrypted_result: [u8; 4 + 12 + 32 + 16] = {
            let mut result = [0u8; 4 + 12 + 32 + 16];
            result[..4].copy_from_slice(&1_u32.to_be_bytes());
            result[4..16].copy_from_slice(&iv);
            result[16..16 + encrypted_key.len()].copy_from_slice(&encrypted_key);
            result[16 + encrypted_key.len()..].copy_from_slice(&tag);
            result
        };

        let key = internal::Key {
            key_id: "master_key".to_string(),
            primary_version_id: 1,
            purpose: "ENCRYPT_DECRYPT".to_string(),
            creation_time: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: chrono::Utc::now().timestamp_subsec_nanos() as i32,
            }),
            rotation_schedule: Some(prost_types::Duration {
                seconds: chrono::TimeDelta::days(30).num_seconds(),
                nanos: 0,
            }),
        };

        let key_version = internal::KeyVersion {
            key_id: "master_key".to_string(),
            key_material: encrypted_result.to_vec().into(),
            state: internal::KeyVersionState::Enabled as i32,
            version: 1,
            creation_time: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: chrono::Utc::now().timestamp_subsec_nanos() as i32,
            }),
            ..Default::default()
        };

        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;
                self.db.update_key_metadata(&trx, "valv", &key).await?;

                self.db
                    .append_key_version(&trx, "valv", &key, &key_version)
                    .await?;

                Ok(())
            })
            .await;

        match trx_result {
            Ok(_) => Ok(key),
            Err(e) => {
                println!("Error creating master key: {e}");
                Err(ValvError::Internal(e.to_string()))
            }
        }
    }

    async fn create_key(&self, tenant: &str, name: &str) -> Result<internal::Key> {
        assert_ne!(self.state, ValvState::MissingMasterKey);

        let key = self.get_key("valv", "master_key").await?;

        assert!(key.is_some());

        let master_key = match key {
            Some(key) => key,
            None => panic!(),
        };

        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;

                let material = self
                    .get_unwrapped_master_key_material(&trx, master_key.primary_version_id)
                    .await?;
                Ok(material)
            })
            .await;

        let unwrapped_master_key_material = match trx_result {
            Ok(key) => key,
            Err(e) => {
                println!("Error creating key {name}: {e}");
                return Err(ValvError::Internal(e.to_string()));
            }
        };

        let mut iv = [0; 12];
        let mut key = [0; 32];
        let mut tag = [0; 16];

        boring::rand::rand_bytes(&mut iv)?;
        boring::rand::rand_bytes(&mut key)?;

        let encrypted_key = boring::symm::encrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            &unwrapped_master_key_material,
            Some(&iv),
            &[],
            &key,
            &mut tag,
        )?;

        let mut encrypted_result =
            Vec::with_capacity(4 + iv.len() + encrypted_key.len() + tag.len());

        // Add IV, key material and tag to result
        encrypted_result.extend_from_slice(&1_u32.to_be_bytes());
        encrypted_result.extend_from_slice(&iv);
        encrypted_result.extend_from_slice(&encrypted_key);
        encrypted_result.extend_from_slice(&tag);

        let key = internal::Key {
            key_id: name.to_string(),
            primary_version_id: 1,
            purpose: "ENCRYPT_DECRYPT".to_string(),
            creation_time: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: chrono::Utc::now().timestamp_subsec_nanos() as i32,
            }),
            rotation_schedule: Some(prost_types::Duration {
                seconds: chrono::TimeDelta::days(30).num_seconds(),
                nanos: 0,
            }),
        };

        let key_version = internal::KeyVersion {
            key_id: name.to_string(),
            key_material: encrypted_result.to_vec().into(),
            state: internal::KeyVersionState::Enabled as i32,
            version: 1,
            creation_time: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: chrono::Utc::now().timestamp_subsec_nanos() as i32,
            }),
            ..Default::default()
        };

        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;
                self.db.update_key_metadata(&trx, tenant, &key).await?;

                self.db
                    .append_key_version(&trx, tenant, &key, &key_version)
                    .await?;

                Ok(())
            })
            .await;

        match trx_result {
            Ok(_) => Ok(key),
            Err(e) => {
                println!("Error creating key {name}: {e}");
                Err(ValvError::Internal(e.to_string()))
            }
        }
    }

    async fn update_key(&self, tenant: &str, key: internal::Key) -> Result<internal::Key> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;
                self.db.update_key_metadata(&trx, tenant, &key).await?;

                Ok(())
            })
            .await;

        match trx_result {
            Ok(_) => Ok(key),
            Err(e) => {
                println!("Error updating key {}: {e}", key.key_id);
                Err(ValvError::Storage(storage::errors::StorageError::Binding(
                    e,
                )))
            }
        }
    }

    /*async fn rotate_key(&self, tenant: &str, name: &str) -> Result<()> {
        Ok(())
    }*/

    async fn get_key_version(
        &self,
        tenant: &str,
        key_name: &str,
        version_id: u32,
    ) -> Result<Option<internal::KeyVersion>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;
                let key_version = self
                    .db
                    .get_key_version(&trx, tenant, key_name, version_id)
                    .await?;
                Ok(key_version)
            })
            .await;

        match trx_result {
            Ok(key_version) => Ok(key_version),
            Err(e) => {
                println!("Error getting key version {}: {e}", key_name);
                Err(ValvError::Storage(storage::errors::StorageError::Binding(
                    e,
                )))
            }
        }
    }

    async fn encrypt(&self, tenant: &str, key_name: &str, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                async {
                    let trx = trx;

                    let key = self.db.get_key_metadata(&trx, tenant, key_name).await?;

                    let key = match key {
                        Some(key) => key,
                        None => {
                            return Err(ValvError::KeyNotFound(key_name.to_string()).into());
                        }
                    };

                    let unwrapped_key_version_material = self
                        .get_unwrapped_key_material(&trx, tenant, key_name, key.primary_version_id)
                        .await?;

                    let mut iv = [0; 12];
                    boring::rand::rand_bytes(&mut iv).map_err(ValvError::BoringSSL)?;

                    let mut tag = [0; 16];

                    let encrypted_key = boring::symm::encrypt_aead(
                        boring::symm::Cipher::aes_256_gcm(),
                        &unwrapped_key_version_material,
                        Some(&iv),
                        &[],
                        &plaintext,
                        &mut tag,
                    )
                    .map_err(ValvError::BoringSSL)?;

                    let mut encrypted_result = Vec::with_capacity(
                        4 + // Key version (u32)
                        iv.len() +
                        encrypted_key.len() +
                        tag.len(),
                    );

                    // Add version, IV and encrypted key to result
                    encrypted_result.extend_from_slice(&(key.primary_version_id).to_be_bytes());

                    encrypted_result.extend_from_slice(&iv);
                    encrypted_result.extend_from_slice(&encrypted_key);
                    encrypted_result.extend_from_slice(&tag);

                    Ok(encrypted_result)
                }
            })
            .await;

        match trx_result {
            Ok(encrypted_result) => Ok(encrypted_result),
            Err(e) => {
                println!("Error encrypting key {}: {e}", key_name);
                Err(ValvError::Storage(storage::errors::StorageError::Binding(
                    e,
                )))
            }
        }
    }

    async fn decrypt(&self, tenant: &str, key_name: &str, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| async {
                let trx = trx;

                let (key_version_id, remainder) = ciphertext.split_at(4);
                let (iv, remainder) = remainder.split_at(12);
                let (cipher, tag) = remainder.split_at(remainder.len() - 16);

                let key = self.db.get_key_metadata(&trx, tenant, key_name).await?;

                let key = match key {
                    Some(key) => key,
                    None => {
                        return Err(ValvError::KeyNotFound(key_name.to_string()).into());
                    }
                };

                let key_version_id = std::io::Cursor::new(key_version_id).get_u32();
                let key_version = self
                    .db
                    .get_key_version(&trx, tenant, &key.key_id, key_version_id)
                    .await?;

                let key_version = match key_version {
                    Some(key_version) => key_version,
                    None => {
                        return Err(ValvError::KeyNotFound(key_name.to_string()).into());
                    }
                };

                let (master_key_version, kv_remainder) = key_version.key_material.split_at(4);
                let (kv_iv, kv_remainder) = kv_remainder.split_at(12);
                let (kv_cipher, kv_tag) = kv_remainder.split_at(kv_remainder.len() - 16);

                let master_key_version = std::io::Cursor::new(master_key_version).get_u32();

                let unwrapped_primary_master_key = self
                    .get_unwrapped_master_key_material(&trx, master_key_version)
                    .await?;

                let unwrapped_key_version_material = boring::symm::decrypt_aead(
                    boring::symm::Cipher::aes_256_gcm(),
                    &unwrapped_primary_master_key,
                    Some(kv_iv),
                    &[],
                    kv_cipher,
                    kv_tag,
                )
                .map_err(ValvError::BoringSSL)?;

                let plaintext = boring::symm::decrypt_aead(
                    boring::symm::Cipher::aes_256_gcm(),
                    &unwrapped_key_version_material,
                    Some(iv),
                    &[],
                    cipher,
                    tag,
                )
                .map_err(ValvError::BoringSSL)?;

                Ok(plaintext)
            })
            .await;

        match trx_result {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => {
                println!("Error decrypting key {}: {e}", key_name);
                Err(ValvError::Storage(storage::errors::StorageError::Binding(
                    e,
                )))
            }
        }
    }
}

impl Valv {
    async fn get_unwrapped_master_key_material(
        &self,
        trx: &RetryableTransaction,
        version: u32,
    ) -> Result<Vec<u8>> {
        assert_ne!(self.state, ValvState::MissingMasterKey);

        let key_version = self
            .db
            .get_key_version(trx, "valv", "master_key", version)
            .await?;

        let key_version = match key_version {
            Some(key_version) => key_version,
            None => {
                return Err(ValvError::KeyNotFound("master_key".to_string()));
            }
        };

        let (_, remainder) = key_version.key_material.split_at(4);
        let (iv, remainder) = remainder.split_at(12);
        let (cipher, tag) = remainder.split_at(remainder.len() - 16);

        let unwrapped_key_version_material = boring::symm::decrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            self.root_key.expose_secret(),
            Some(iv),
            &[],
            cipher,
            tag,
        )
        .map_err(ValvError::BoringSSL)?;

        println!("decrypted master with root");

        Ok(unwrapped_key_version_material)
    }
    async fn get_unwrapped_key_material(
        &self,
        trx: &RetryableTransaction,
        tenant: &str,
        key_name: &str,
        version: u32,
    ) -> Result<Vec<u8>> {
        let key_version = self
            .db
            .get_key_version(trx, tenant, key_name, version)
            .await?;

        let key_version = match key_version {
            Some(key_version) => key_version,
            None => {
                return Err(ValvError::KeyNotFound(key_name.to_string()));
            }
        };

        let (master_key_version, remainder) = key_version.key_material.split_at(4);
        let (iv, remainder) = remainder.split_at(12);
        let (cipher, tag) = remainder.split_at(remainder.len() - 16);

        let master_key_version = std::io::Cursor::new(master_key_version).get_u32();

        let master_key = self
            .get_unwrapped_master_key_material(trx, master_key_version)
            .await?;

        let unwrapped_key_version_material = boring::symm::decrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            &master_key,
            Some(iv),
            &[],
            cipher,
            tag,
        )
        .map_err(ValvError::BoringSSL)?;
        println!("decrypted normal key");

        Ok(unwrapped_key_version_material)
    }
}
