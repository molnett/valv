use std::sync::Arc;

use crate::{Keystore, KeystoreAPI};

pub struct KeyRotator {
    keystore: Arc<Keystore>,
}

impl KeyRotator {
    pub fn new(keystore: Arc<Keystore>) -> Self {
        KeyRotator { keystore }
    }

    pub async fn run_rotation(&self) -> anyhow::Result<()> {
        let now = self.keystore.clock.now();
        let keys = self.keystore.list_keys(None).await?;

        for key in keys {
            if let Some(rotation_period) = key.rotation_period() {
                let last_rotated = key.last_rotated();
                if now.duration_since(last_rotated)? >= rotation_period {
                    self.rotate_key(&key)?;
                }
            }
        }

        Ok(())
    }

    async fn rotate_key(&self, key: &Key) -> Result<(), Box<dyn std::error::Error>> {
        // Implement key rotation logic here
        // This might involve generating a new key, updating the old key,
        // and storing the new key in the keystore
        println!("Rotating key: {}", key.name());
        // self.keystore.rotate_key(key.name())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;
    use std::time::Duration;

    // Implement tests for KeyRotator
    // You'll need to create a mock KeyStore for testing
}