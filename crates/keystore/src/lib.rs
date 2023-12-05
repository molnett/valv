use std::{collections::HashMap};

mod gen;

pub mod valv {
    pub mod keystore {
        pub mod v1 {
            include!("gen/valv.keystore.v1.rs");
        }
    }
}

#[derive(Clone)]
pub struct CryptoKey {
    pub name: String,
    pub encrypted_value: Vec<u8>,
}

pub struct DecryptedKey {
    pub name: String,
    pub decrypted_key: Vec<u8>,
}

pub trait KeystoreAPI {
    fn list_crypto_keys(&self);
    fn create_crypto_key(&mut self, name: String) -> CryptoKey;
}

pub struct Keystore {
    pub keys: HashMap<String, CryptoKey>,
    pub decrypted_keys_cache: HashMap<String, DecryptedKey>,
    pub master_key: [u8; 32],
}

impl Keystore {
    pub fn new() -> Keystore {
        Keystore {
            keys: HashMap::new(),
            decrypted_keys_cache: HashMap::new(),
            master_key: [0; 32],
        }
    }

    pub fn set_master_key(&mut self, key: [u8; 32]) {
        self.master_key = key;
    }
}

impl KeystoreAPI for Keystore {
    fn create_crypto_key(&mut self, name: String) -> CryptoKey {
        let mut iv = [0; 12];
        let mut key = [0; 256];
        boring::rand::rand_bytes(&mut iv).unwrap();
        boring::rand::rand_bytes(&mut key).unwrap();

        let encrypted_key = boring::symm::encrypt(
            boring::symm::Cipher::aes_256_gcm(),
            &self.master_key,
            Some(&iv),
            &key,
        ).unwrap();

        let crypto_key = CryptoKey {
            name: name.clone(),
            encrypted_value: encrypted_key,
        };
        self.keys.insert(name.clone(), crypto_key.clone());

        let decrypted_key = DecryptedKey {
            name: name.clone(),
            decrypted_key: key.to_vec(),
        };
        self.decrypted_keys_cache.insert(name, decrypted_key);
        
        crypto_key
    }

    fn list_crypto_keys(&self) {
        println!("{:?}", self.keys.keys());
    }
}
