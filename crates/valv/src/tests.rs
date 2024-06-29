#[cfg(test)]
mod tests {
    use crate::google::kms::{
        crypto_key::{CryptoKeyPurpose, RotationSchedule},
        crypto_key_version::{
            CryptoKeyVersionAlgorithm, CryptoKeyVersionState, CryptoKeyVersionView,
        },
        key_management_service_client::KeyManagementServiceClient,
        CreateCryptoKeyRequest, CreateCryptoKeyVersionRequest, CreateKeyRingRequest, CryptoKey,
        CryptoKeyVersion, CryptoKeyVersionTemplate, DecryptRequest, DecryptResponse,
        DestroyCryptoKeyVersionRequest, EncryptRequest, EncryptResponse, GetCryptoKeyRequest,
        GetCryptoKeyVersionRequest, GetKeyRingRequest, KeyRing, ListCryptoKeyVersionsRequest,
        ListCryptoKeyVersionsResponse, ListCryptoKeysRequest, ListCryptoKeysResponse,
        ListKeyRingsRequest, ListKeyRingsResponse, ProtectionLevel,
        UpdateCryptoKeyPrimaryVersionRequest, UpdateCryptoKeyRequest,
    };
    use std::time::Duration;
    use tonic::{Request, Response, Status};
    use uuid::Uuid;

    struct TestClient {
        client: KeyManagementServiceClient<tonic::transport::Channel>,
        project: String,
        location: String,
    }

    impl TestClient {
        async fn new(
            addr: &str,
            project: &str,
            location: &str,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let client = KeyManagementServiceClient::connect(addr.to_owned()).await?;
            Ok(Self {
                client,
                project: project.to_string(),
                location: location.to_string(),
            })
        }

        fn parent(&self) -> String {
            format!("projects/{}/locations/{}", self.project, self.location)
        }

        async fn create_key_ring(
            &mut self,
            key_ring_id: &str,
        ) -> Result<Response<KeyRing>, Status> {
            let request = Request::new(CreateKeyRingRequest {
                parent: self.parent(),
                key_ring_id: key_ring_id.to_string(),
                key_ring: None,
            });
            self.client.create_key_ring(request).await
        }

        async fn get_key_ring(&mut self, key_ring_id: &str) -> Result<Response<KeyRing>, Status> {
            let request = Request::new(GetKeyRingRequest {
                name: format!("{}/keyRings/{}", self.parent(), key_ring_id),
            });
            self.client.get_key_ring(request).await
        }

        async fn list_key_rings(
            &mut self,
            page_size: i32,
            page_token: &str,
        ) -> Result<Response<ListKeyRingsResponse>, Status> {
            let request = Request::new(ListKeyRingsRequest {
                parent: self.parent(),
                page_size,
                page_token: page_token.to_string(),
                filter: String::new(),
                order_by: String::new(),
            });
            self.client.list_key_rings(request).await
        }

        async fn create_crypto_key(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            purpose: CryptoKeyPurpose,
            version_template: Option<CryptoKeyVersionTemplate>,
        ) -> Result<Response<CryptoKey>, Status> {
            let request = Request::new(CreateCryptoKeyRequest {
                parent: format!("{}/keyRings/{}", self.parent(), key_ring_id),
                crypto_key_id: crypto_key_id.to_string(),
                crypto_key: Some(CryptoKey {
                    purpose: purpose as i32,
                    version_template,
                    ..Default::default()
                }),
                skip_initial_version_creation: false,
            });
            self.client.create_crypto_key(request).await
        }

        async fn get_crypto_key(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
        ) -> Result<Response<CryptoKey>, Status> {
            let request = Request::new(GetCryptoKeyRequest {
                name: format!(
                    "{}/keyRings/{}/cryptoKeys/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id
                ),
            });
            self.client.get_crypto_key(request).await
        }

        async fn list_crypto_keys(
            &mut self,
            key_ring_id: &str,
            page_size: i32,
            page_token: &str,
        ) -> Result<Response<ListCryptoKeysResponse>, Status> {
            let request = Request::new(ListCryptoKeysRequest {
                parent: format!("{}/keyRings/{}", self.parent(), key_ring_id),
                page_size,
                page_token: page_token.to_string(),
                version_view: CryptoKeyVersionView::Full as i32,
                filter: String::new(),
                order_by: String::new(),
            });
            self.client.list_crypto_keys(request).await
        }

        async fn encrypt(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            plaintext: &[u8],
        ) -> Result<Response<EncryptResponse>, Status> {
            let request = Request::new(EncryptRequest {
                name: format!(
                    "{}/keyRings/{}/cryptoKeys/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id
                ),
                plaintext: plaintext.to_vec(),
                ..Default::default()
            });
            self.client.encrypt(request).await
        }

        async fn decrypt(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            ciphertext: Vec<u8>,
        ) -> Result<Response<DecryptResponse>, Status> {
            let request = Request::new(DecryptRequest {
                name: format!(
                    "{}/keyRings/{}/cryptoKeys/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id
                ),
                ciphertext,
                ..Default::default()
            });
            self.client.decrypt(request).await
        }

        async fn create_crypto_key_version(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
        ) -> Result<Response<CryptoKeyVersion>, Status> {
            let request = Request::new(CreateCryptoKeyVersionRequest {
                parent: format!(
                    "{}/keyRings/{}/cryptoKeys/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id
                ),
                crypto_key_version: None,
            });
            self.client.create_crypto_key_version(request).await
        }

        async fn get_crypto_key_version(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            version_id: &str,
        ) -> Result<Response<CryptoKeyVersion>, Status> {
            let request = Request::new(GetCryptoKeyVersionRequest {
                name: format!(
                    "{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id,
                    version_id
                ),
            });
            self.client.get_crypto_key_version(request).await
        }

        async fn list_crypto_key_versions(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            page_size: i32,
            page_token: &str,
        ) -> Result<Response<ListCryptoKeyVersionsResponse>, Status> {
            let request = Request::new(ListCryptoKeyVersionsRequest {
                parent: format!(
                    "{}/keyRings/{}/cryptoKeys/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id
                ),
                page_size,
                page_token: page_token.to_string(),
                view: CryptoKeyVersionView::Full as i32,
                filter: String::new(),
                order_by: String::new(),
            });
            self.client.list_crypto_key_versions(request).await
        }

        async fn update_crypto_key_primary_version(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            version_id: &str,
        ) -> Result<Response<CryptoKey>, Status> {
            let request = Request::new(UpdateCryptoKeyPrimaryVersionRequest {
                name: format!(
                    "{}/keyRings/{}/cryptoKeys/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id
                ),
                crypto_key_version_id: version_id.to_string(),
            });
            self.client.update_crypto_key_primary_version(request).await
        }

        async fn destroy_crypto_key_version(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            version_id: &str,
        ) -> Result<Response<CryptoKeyVersion>, Status> {
            let request = Request::new(DestroyCryptoKeyVersionRequest {
                name: format!(
                    "{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
                    self.parent(),
                    key_ring_id,
                    crypto_key_id,
                    version_id
                ),
            });
            self.client.destroy_crypto_key_version(request).await
        }

        async fn update_crypto_key(
            &mut self,
            key_ring_id: &str,
            crypto_key_id: &str,
            rotation_period: Duration,
        ) -> Result<Response<CryptoKey>, Status> {
            let request = Request::new(UpdateCryptoKeyRequest {
                crypto_key: Some(CryptoKey {
                    name: format!(
                        "{}/keyRings/{}/cryptoKeys/{}",
                        self.parent(),
                        key_ring_id,
                        crypto_key_id
                    ),
                    rotation_schedule: Some(RotationSchedule::RotationPeriod(
                        prost_types::Duration {
                            seconds: rotation_period.as_secs() as i64,
                            nanos: rotation_period.subsec_nanos() as i32,
                        },
                    )),
                    ..Default::default()
                }),
                update_mask: Some(::prost_types::FieldMask {
                    paths: vec!["rotation_period".to_string()],
                }),
            });
            self.client.update_crypto_key(request).await
        }
    }

    async fn run_comprehensive_tests(
        client: &mut TestClient,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test KeyRing operations
        let key_ring_id = format!("test-keyring-{}", Uuid::new_v4());
        log::info!("Testing KeyRing operations");
        test_key_ring_operations(client, &key_ring_id).await?;

        // Test CryptoKey operations
        let crypto_key_id = format!("test-cryptokey-{}", Uuid::new_v4());
        log::info!("Testing CryptoKey operations");
        test_crypto_key_operations(client, &key_ring_id, &crypto_key_id).await?;

        // Test encryption and decryption
        log::info!("Testing encryption and decryption");
        test_encrypt_decrypt(client, &key_ring_id, &crypto_key_id).await?;

        // Test CryptoKeyVersion operations
        log::info!("Testing CryptoKeyVersion operations");
        test_crypto_key_version_operations(client, &key_ring_id, &crypto_key_id).await?;

        // Test rotation and state transitions
        log::info!("Testing rotation and state transitions");
        test_rotation_and_state_transitions(client, &key_ring_id).await?;

        // Test pagination
        log::info!("Testing pagination");
        test_pagination(client, &key_ring_id).await?;

        // Test error cases
        log::info!("Testing error cases");
        test_error_cases(client).await?;

        Ok(())
    }

    async fn test_key_ring_operations(
        client: &mut TestClient,
        key_ring_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create KeyRing
        let create_response = client.create_key_ring(key_ring_id).await?;
        assert!(create_response.get_ref().name.contains(key_ring_id));

        // Get KeyRing
        let get_response = client.get_key_ring(key_ring_id).await?;
        assert_eq!(get_response.get_ref().name, create_response.get_ref().name);

        // List KeyRings
        let list_response = client.list_key_rings(10, "").await?;
        assert!(list_response
            .get_ref()
            .key_rings
            .iter()
            .any(|kr| kr.name == create_response.get_ref().name));

        Ok(())
    }

    async fn test_crypto_key_operations(
        client: &mut TestClient,
        key_ring_id: &str,
        crypto_key_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create CryptoKey
        let create_response = client
            .create_crypto_key(
                key_ring_id,
                crypto_key_id,
                CryptoKeyPurpose::EncryptDecrypt,
                Some(CryptoKeyVersionTemplate {
                    protection_level: ProtectionLevel::Software as i32,
                    algorithm: CryptoKeyVersionAlgorithm::GoogleSymmetricEncryption as i32,
                }),
            )
            .await?;
        assert!(create_response.get_ref().name.contains(crypto_key_id));

        // Get CryptoKey
        let get_response = client.get_crypto_key(key_ring_id, crypto_key_id).await?;
        assert_eq!(get_response.get_ref().name, create_response.get_ref().name);

        // List CryptoKeys
        let list_response = client.list_crypto_keys(key_ring_id, 10, "").await?;
        assert!(list_response
            .get_ref()
            .crypto_keys
            .iter()
            .any(|ck| ck.name == create_response.get_ref().name));

        // Update CryptoKey (set rotation period)
        let rotation_period = Duration::from_secs(24 * 60 * 60); // 24 hours
        let update_response = client
            .update_crypto_key(key_ring_id, crypto_key_id, rotation_period)
            .await?;
        assert_eq!(
            update_response.get_ref().rotation_schedule,
            Some(RotationSchedule::RotationPeriod(prost_types::Duration {
                seconds: rotation_period.as_secs() as i64,
                nanos: rotation_period.subsec_nanos() as i32,
            })),
        );

        Ok(())
    }

    async fn test_encrypt_decrypt(
        client: &mut TestClient,
        key_ring_id: &str,
        crypto_key_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = b"Hello, World!";

        // Encrypt
        let encrypt_response = client
            .encrypt(key_ring_id, crypto_key_id, plaintext)
            .await?;
        assert!(!encrypt_response.get_ref().ciphertext.is_empty());

        // Decrypt
        let decrypt_response = client
            .decrypt(
                key_ring_id,
                crypto_key_id,
                encrypt_response.get_ref().ciphertext.clone(),
            )
            .await?;
        assert_eq!(decrypt_response.get_ref().plaintext, plaintext);

        Ok(())
    }

    async fn test_crypto_key_version_operations(
        client: &mut TestClient,
        key_ring_id: &str,
        crypto_key_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create CryptoKeyVersion
        let create_response = client
            .create_crypto_key_version(key_ring_id, crypto_key_id)
            .await?;
        let version_id = create_response.get_ref().name.split('/').last().unwrap();

        // Get CryptoKeyVersion
        let get_response = client
            .get_crypto_key_version(key_ring_id, crypto_key_id, version_id)
            .await?;
        assert_eq!(get_response.get_ref().name, create_response.get_ref().name);

        // List CryptoKeyVersions
        let list_response = client
            .list_crypto_key_versions(key_ring_id, crypto_key_id, 10, "")
            .await?;
        assert!(list_response
            .get_ref()
            .crypto_key_versions
            .iter()
            .any(|ckv| ckv.name == create_response.get_ref().name));

        // Update primary version
        let update_primary_response = client
            .update_crypto_key_primary_version(key_ring_id, crypto_key_id, version_id)
            .await?;
        assert_eq!(
            update_primary_response
                .get_ref()
                .primary
                .as_ref()
                .unwrap()
                .name,
            create_response.get_ref().name
        );

        // Destroy CryptoKeyVersion
        let destroy_response = client
            .destroy_crypto_key_version(key_ring_id, crypto_key_id, version_id)
            .await?;
        assert_eq!(
            destroy_response.get_ref().state,
            CryptoKeyVersionState::Destroyed as i32
        );

        Ok(())
    }

    async fn test_rotation_and_state_transitions(
        client: &mut TestClient,
        key_ring_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let crypto_key_id = format!("test-rotation-key-{}", Uuid::new_v4());

        // Create a CryptoKey with rotation period
        let rotation_period = Duration::from_secs(24 * 60 * 60); // 24 hours
        let create_response = client
            .create_crypto_key(
                key_ring_id,
                &crypto_key_id,
                CryptoKeyPurpose::EncryptDecrypt,
                Some(CryptoKeyVersionTemplate {
                    protection_level: ProtectionLevel::Software as i32,
                    algorithm: CryptoKeyVersionAlgorithm::GoogleSymmetricEncryption as i32,
                }),
            )
            .await?;

        client
            .update_crypto_key(key_ring_id, &crypto_key_id, rotation_period)
            .await?;

        // Create multiple versions
        for _ in 0..3 {
            client
                .create_crypto_key_version(key_ring_id, &crypto_key_id)
                .await?;
        }

        // List versions and check states
        let list_response = client
            .list_crypto_key_versions(key_ring_id, &crypto_key_id, 10, "")
            .await?;
        assert!(list_response.get_ref().crypto_key_versions.len() >= 3);

        // Destroy a non-primary version
        let version_to_destroy = list_response
            .get_ref()
            .crypto_key_versions
            .iter()
            .find(|v| {
                v.state == CryptoKeyVersionState::Enabled as i32
                    && v.name != create_response.get_ref().primary.as_ref().unwrap().name
            })
            .unwrap();
        let destroy_response = client
            .destroy_crypto_key_version(
                key_ring_id,
                &crypto_key_id,
                version_to_destroy.name.split('/').last().unwrap(),
            )
            .await?;
        assert_eq!(
            destroy_response.get_ref().state,
            CryptoKeyVersionState::Destroyed as i32
        );

        Ok(())
    }

    async fn test_pagination(
        client: &mut TestClient,
        key_ring_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create multiple CryptoKeys
        for i in 0..5 {
            client
                .create_crypto_key(
                    key_ring_id,
                    &format!("test-pagination-key-{}", i),
                    CryptoKeyPurpose::EncryptDecrypt,
                    None,
                )
                .await?;
        }

        // Test pagination of ListCryptoKeys
        let mut all_keys = Vec::new();
        let mut page_token = String::new();
        loop {
            let response = client.list_crypto_keys(key_ring_id, 2, &page_token).await?;
            all_keys.extend(response.get_ref().crypto_keys.clone());
            if response.get_ref().next_page_token.is_empty() {
                break;
            }
            page_token = response.get_ref().next_page_token.clone();
        }
        assert!(all_keys.len() >= 5);

        Ok(())
    }

    async fn test_error_cases(client: &mut TestClient) -> Result<(), Box<dyn std::error::Error>> {
        // Attempt to create a KeyRing with invalid ID
        let invalid_create_result = client.create_key_ring("invalid/id").await;
        assert!(invalid_create_result.is_err());

        // Attempt to get a non-existent KeyRing
        let non_existent_get_result = client.get_key_ring("non-existent-keyring").await;
        assert!(non_existent_get_result.is_err());

        // Attempt to create a CryptoKey in a non-existent KeyRing
        let invalid_crypto_key_result = client
            .create_crypto_key(
                "non-existent-keyring",
                "test-key",
                CryptoKeyPurpose::EncryptDecrypt,
                None,
            )
            .await;
        assert!(invalid_crypto_key_result.is_err());

        // Attempt to encrypt with a non-existent CryptoKey
        let invalid_encrypt_result = client
            .encrypt("non-existent-keyring", "non-existent-key", b"test")
            .await;
        assert!(invalid_encrypt_result.is_err());

        // Attempt to update primary version with a non-existent version
        let key_ring_id = format!("test-keyring-{}", Uuid::new_v4());
        let crypto_key_id = format!("test-cryptokey-{}", Uuid::new_v4());
        client.create_key_ring(&key_ring_id).await?;
        client
            .create_crypto_key(
                &key_ring_id,
                &crypto_key_id,
                CryptoKeyPurpose::EncryptDecrypt,
                None,
            )
            .await?;
        let invalid_update_result = client
            .update_crypto_key_primary_version(&key_ring_id, &crypto_key_id, "999")
            .await;
        assert!(invalid_update_result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn main() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();

        let mut client = TestClient::new("http://[::1]:50051", "my-project", "global").await?;

        println!("Running comprehensive tests...");
        run_comprehensive_tests(&mut client).await?;
        println!("All tests passed successfully!");

        Ok(())
    }
}
