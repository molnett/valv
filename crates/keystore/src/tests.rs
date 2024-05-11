#[cfg(test)]
mod tests {
    use crate::{
        api::server::API,
        valv::keystore::v1::{
            master_key_management_service_server::MasterKeyManagementServiceServer,
            CreateMasterKeyRequest, DecryptRequest, EncryptRequest, MasterKey,
        },
        Keystore, KeystoreAPI,
    };

    use std::{sync::Arc, time::Duration};
    use tonic::transport::Server;

    use crate::valv::keystore::v1::master_key_management_service_client::MasterKeyManagementServiceClient;
    use tokio::time::sleep;

    #[tokio::test]
    async fn server_test_suite() {
        let _guard = unsafe { foundationdb::boot() };

        test_keystore().await.expect("test_keystore error");
        test_create_master_key()
            .await
            .expect("test_create_master_key error");
        test_encrypt_decrypt().await;
    }

    async fn test_keystore() -> anyhow::Result<()> {
        let keystore = Keystore::new().await;
        let key = keystore.create_crypto_key("test".to_string()).await;
        let key_metadata = keystore.get_crypto_key(key.name).await;
        assert_eq!(key_metadata.unwrap().name, "test");

        Ok(())
    }

    async fn test_create_master_key() -> anyhow::Result<()> {
        // Start the server
        let addr = "0.0.0.0:8080".parse()?;
        let keystore = Keystore::new().await;
        let api = API {
            keystore: Arc::new(keystore),
        };
        let svc = MasterKeyManagementServiceServer::new(api);
        let server_handle = tokio::spawn(Server::builder().add_service(svc).serve(addr));

        // try to connect to the server
        let mut chan_is_err = false;
        for _ in 0..10 {
            let channel = tonic::transport::Channel::from_static("http://127.0.0.1:8080")
                .connect()
                .await;

            match channel {
                Ok(_) => {
                    chan_is_err = true;
                    break;
                }
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
            println!("Waiting for server to start...");
        }
        if !chan_is_err {
            panic!("Failed to connect to server");
        }

        // Wait for the server to start (adjust sleep duration as needed)
        // Create a client
        let channel = tonic::transport::Channel::from_static("http://127.0.0.1:8080")
            .connect()
            .await
            .expect("Failed to connect to server");

        let mut client = MasterKeyManagementServiceClient::new(channel);

        // Make the gRPC call
        let request = tonic::Request::new(CreateMasterKeyRequest {
            master_key: Some(MasterKey::default()),
            master_key_id: "test".to_string(),
        });
        let response = client.create_master_key(request).await?;

        // Assert the response
        assert_eq!(response.get_ref().master_key.is_some(), true);

        // Stop the server
        server_handle.abort();

        Ok(())
    }

    // Similar tests can be written for other API methods
    async fn test_encrypt_decrypt() {
        // Start the server
        let addr = "0.0.0.0:8080".parse().unwrap();
        let keystore = Keystore::new().await;
        let api = API {
            keystore: Arc::new(keystore),
        };
        let svc = MasterKeyManagementServiceServer::new(api);
        let server_handle = tokio::spawn(Server::builder().add_service(svc).serve(addr));

        let mut chan_is_err = false;
        for _ in 0..10 {
            let channel = tonic::transport::Channel::from_static("http://127.0.0.1:8080")
                .connect()
                .await;

            match channel {
                Ok(_) => {
                    chan_is_err = true;
                    break;
                }
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
            println!("Waiting for server to start...");
        }
        if !chan_is_err {
            panic!("Failed to connect to server");
        }

        // Wait for the server to start (adjust sleep duration as needed)
        // Create a client
        let channel = tonic::transport::Channel::from_static("http://127.0.0.1:8080")
            .connect()
            .await
            .expect("Failed to connect to server");

        let mut client = MasterKeyManagementServiceClient::new(channel);

        // Make the gRPC call
        let request = tonic::Request::new(CreateMasterKeyRequest {
            master_key: Some(MasterKey::default()),
            master_key_id: "test".to_string(),
        });
        let response = client.create_master_key(request).await.unwrap();

        // Assert the response
        assert_eq!(response.get_ref().master_key.is_some(), true);

        // Make the gRPC call to encrypt
        let encrypt_request = tonic::Request::new(EncryptRequest {
            master_key_id: response.get_ref().master_key.as_ref().unwrap().name.clone(),
            plaintext: vec![0; 32].into(),
        });
        let encrypt_response = client.encrypt(encrypt_request).await.unwrap();

        // Assert the encrypt response
        let original_ciphertext = encrypt_response.get_ref().ciphertext.clone();
        assert_eq!(
            encrypt_response.get_ref().name,
            response.get_ref().master_key.as_ref().unwrap().name
        );
        assert_eq!(original_ciphertext.len(), 60);

        // Make the gRPC call to decrypt with the original master key
        let decrypt_request = tonic::Request::new(DecryptRequest {
            master_key_id: response.get_ref().master_key.as_ref().unwrap().name.clone(),
            ciphertext: original_ciphertext.clone(),
        });
        let decrypt_response = client.decrypt(decrypt_request).await.unwrap();

        // Assert the decrypt response
        assert_eq!(decrypt_response.get_ref().plaintext.len(), 32);
        let decrypted_plaintext = decrypt_response.get_ref().plaintext.clone();
        assert_eq!(decrypted_plaintext, vec![0; 32]);

        // Make the gRPC call
        let request = tonic::Request::new(CreateMasterKeyRequest {
            master_key: Some(MasterKey::default()),
            master_key_id: "another_key".to_string(),
        });
        let response = client.create_master_key(request).await.unwrap();

        // Assert the response
        assert_eq!(response.get_ref().master_key.is_some(), true);
        // Make the gRPC call to decrypt with another master key
        let decrypt_request_another_key = tonic::Request::new(DecryptRequest {
            master_key_id: "another_key".to_string(),
            ciphertext: original_ciphertext,
        });
        let decrypt_response_another_key = client.decrypt(decrypt_request_another_key).await;

        // Assert the decrypt response
        // This should fail because the ciphertext was encrypted with a different master key
        assert_eq!(decrypt_response_another_key.is_err(), true);

        // Stop the server
        server_handle.abort();
        // Stop the server
        server_handle.abort();
    }

    // Similar tests can be written for other API methods
}
