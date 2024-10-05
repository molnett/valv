use errors::{Result, ValvError};
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
pub trait ValvAPI: Send + Sync {
    // TODO: Separate get_key into get_key_metadata and get_key_with_primary_version

    async fn create_key(&self, tenant: String, name: String) -> Result<internal::Key>;
    async fn get_key(&self, tenant: String, name: String) -> Result<Option<internal::Key>>;
    async fn list_keys(&self, tenant: String) -> Result<Option<Vec<internal::Key>>>;
    async fn update_key(&self, tenant: String, key: internal::Key) -> Result<internal::Key>;

    async fn get_key_version(
        &self,
        tenant: String,
        key_name: String,
        version_id: u32,
    ) -> Result<Option<internal::KeyVersion>>;
    async fn encrypt(
        &self,
        tenant: String,
        key_name: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>>;
    async fn decrypt(
        &self,
        tenant: String,
        key_name: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>>;
}

pub struct Valv {
    pub db: FoundationDB,
    pub master_key: Secret<[u8; 32]>,
}

impl Valv {
    pub async fn new() -> Result<Valv> {
        Ok(Valv {
            db: FoundationDB::new("local").await?,
            master_key: [0; 32].into(),
        })
    }

    pub fn set_master_key(&mut self, key: [u8; 32]) {
        self.master_key = Secret::new(key);
    }
}

#[async_trait::async_trait]
impl ValvAPI for Valv {
    async fn get_key(&self, tenant: String, key_name: String) -> Result<Option<internal::Key>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();
                let key_name = key_name.clone();

                async move {
                    let key = self
                        .db
                        .get_key_metadata(&trx, tenant.as_str(), key_name.as_str())
                        .await?;

                    Ok(key)
                }
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

    async fn list_keys(&self, tenant: String) -> Result<Option<Vec<internal::Key>>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();

                async move {
                    let keys = self.db.list_key_metadata(&trx, tenant.as_str()).await?;

                    Ok(Some(keys))
                }
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

    async fn create_key(&self, tenant: String, name: String) -> Result<internal::Key> {
        let mut iv = [0; 12];
        let mut key = [0; 32];
        let mut tag = [0; 16];
        boring::rand::rand_bytes(&mut iv)?;
        boring::rand::rand_bytes(&mut key)?;

        let encrypted_key = boring::symm::encrypt_aead(
            boring::symm::Cipher::aes_256_gcm(),
            self.master_key.expose_secret(),
            Some(&iv),
            &[],
            &key,
            &mut tag,
        )?;

        let mut encrypted_result = Vec::with_capacity(iv.len() + encrypted_key.len() + tag.len());

        // Add IV, key material and tag to result
        encrypted_result.extend_from_slice(&iv);
        encrypted_result.extend_from_slice(&encrypted_key);
        encrypted_result.extend_from_slice(&tag);

        let key = internal::Key {
            key_id: name.clone(),
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
            key_id: name.clone(),
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
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();
                let key = key.clone();
                let key_version = key_version.clone();

                async move {
                    self.db
                        .update_key_metadata(&trx, tenant.as_str(), key.clone())
                        .await?;

                    self.db
                        .append_key_version(&trx, tenant.as_str(), key.clone(), key_version.clone())
                        .await?;

                    Ok(())
                }
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

    async fn update_key(&self, tenant: String, key: internal::Key) -> Result<internal::Key> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();
                let key = key.clone();

                async move {
                    self.db
                        .update_key_metadata(&trx, tenant.as_str(), key.clone())
                        .await?;

                    Ok(())
                }
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

    async fn get_key_version(
        &self,
        tenant: String,
        key_name: String,
        version_id: u32,
    ) -> Result<Option<internal::KeyVersion>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();
                let key_name = key_name.clone();

                async move {
                    let key_version = self
                        .db
                        .get_key_version(&trx, tenant.as_str(), &key_name, version_id)
                        .await?;
                    Ok(key_version)
                }
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

    async fn encrypt(
        &self,
        tenant: String,
        key_name: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();
                let key_name = key_name.clone();
                let plaintext = plaintext.clone();

                async move {
                    let key = self
                        .db
                        .get_key_metadata(&trx, tenant.as_str(), &key_name)
                        .await?;

                    let key = match key {
                        Some(key) => key,
                        None => {
                            return Err(ValvError::KeyNotFound(key_name).into());
                        }
                    };

                    let key_version = self
                        .db
                        .get_key_version(&trx, tenant.as_str(), &key.key_id, key.primary_version_id)
                        .await?;

                    let key_version = match key_version {
                        Some(key_version) => key_version,
                        None => {
                            return Err(ValvError::KeyNotFound(key_name).into());
                        }
                    };

                    let (iv, remainder) = key_version.key_material.split_at(12);
                    let (cipher, tag) = remainder.split_at(remainder.len() - 16);

                    let decrypted_key_material = boring::symm::decrypt_aead(
                        boring::symm::Cipher::aes_256_gcm(),
                        self.master_key.expose_secret(),
                        Some(iv),
                        &[],
                        cipher,
                        tag,
                    );

                    let decrypted_key_material = match decrypted_key_material {
                        Ok(decrypted_key_material) => decrypted_key_material,
                        Err(e) => {
                            return Err(ValvError::Internal(e.to_string()).into());
                        }
                    };

                    let mut iv = [0; 12];
                    boring::rand::rand_bytes(&mut iv).map_err(ValvError::BoringSSL)?;

                    let mut tag = [0; 16];

                    let encrypted_key = boring::symm::encrypt_aead(
                        boring::symm::Cipher::aes_256_gcm(),
                        &decrypted_key_material,
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
                    encrypted_result.extend_from_slice(&(key_version.version).to_be_bytes());

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

    async fn decrypt(
        &self,
        tenant: String,
        key_name: String,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let trx_result = self
            .db
            .database
            .run(|trx, _| {
                let trx = trx;
                let tenant = tenant.clone();
                let key_name = key_name.clone();
                let ciphertext = ciphertext.clone();

                async move {
                    let (key_version_id, remainder) = ciphertext.split_at(4);
                    let (iv, remainder) = remainder.split_at(12);
                    let (cipher, tag) = remainder.split_at(remainder.len() - 16);

                    let key = self
                        .db
                        .get_key_metadata(&trx, tenant.as_str(), &key_name)
                        .await?;

                    let key = match key {
                        Some(key) => key,
                        None => {
                            return Err(ValvError::KeyNotFound(key_name).into());
                        }
                    };

                    let key_version_id = std::io::Cursor::new(key_version_id).get_u32();
                    let key_version = self
                        .db
                        .get_key_version(&trx, tenant.as_str(), &key.key_id, key_version_id)
                        .await?;

                    let key_version = match key_version {
                        Some(key_version) => key_version,
                        None => {
                            return Err(ValvError::KeyNotFound(key_name).into());
                        }
                    };

                    let (kv_iv, kv_remainder) = key_version.key_material.split_at(12);
                    let (kv_cipher, kv_tag) = kv_remainder.split_at(kv_remainder.len() - 16);

                    let decrypted_key_material = boring::symm::decrypt_aead(
                        boring::symm::Cipher::aes_256_gcm(),
                        self.master_key.expose_secret(),
                        Some(kv_iv),
                        &[],
                        kv_cipher,
                        kv_tag,
                    )
                    .map_err(ValvError::BoringSSL)?;

                    let plaintext = boring::symm::decrypt_aead(
                        boring::symm::Cipher::aes_256_gcm(),
                        &decrypted_key_material,
                        Some(iv),
                        &[],
                        cipher,
                        tag,
                    )
                    .map_err(ValvError::BoringSSL)?;

                    Ok(plaintext)
                }
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
