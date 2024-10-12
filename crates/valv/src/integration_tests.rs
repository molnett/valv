#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use crate::{
        api::server::API,
        errors::ValvError,
        valv::proto::v1::{
            master_key_management_service_server::MasterKeyManagementServiceServer,
            CreateMasterKeyRequest, DecryptRequest, EncryptRequest, MasterKey,
        },
        Valv,
    };

    use std::{sync::Arc, time::Duration};
    use tonic::transport::Server;

    use crate::valv::proto::v1::master_key_management_service_client::MasterKeyManagementServiceClient;
    use tokio::time::sleep;

    const SERVER_ADDR: &str = "0.0.0.0:8080";
    const CLIENT_ADDR: &str = "http://127.0.0.1:8080";

    #[tokio::test]
    async fn server_test_suite() {
        let _guard = unsafe { foundationdb::boot() };

        println!("Running server test suite");

        println!("Testing create master key");
        test_create_master_key()
            .await
            .expect("test_create_master_key error");
        println!("Create master key test passed\n");

        println!("Testing encrypt/decrypt");
        test_encrypt_decrypt()
            .await
            .expect("test_encrypt_decrypt error");
        println!("Encrypt/decrypt test passed");
    }

    async fn setup_server(
    ) -> Result<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>, ValvError> {
        let addr = SERVER_ADDR.parse().expect("Invalid address");

        let master_key_bytes: [u8; 32] = "77aaee825aa561995d7bda258f9b76b0"
            .as_bytes()
            .try_into()
            .expect("Invalid master key");

        let valv = Valv::new(master_key_bytes).await?;

        let api = API {
            valv: Arc::new(valv),
        };

        let svc = MasterKeyManagementServiceServer::new(api);

        Ok(tokio::spawn(Server::builder().add_service(svc).serve(addr)))
    }

    async fn setup_client(
    ) -> Result<MasterKeyManagementServiceClient<tonic::transport::Channel>, tonic::transport::Error>
    {
        let channel = tonic::transport::Channel::from_static(CLIENT_ADDR)
            .connect()
            .await?;
        Ok(MasterKeyManagementServiceClient::new(channel))
    }

    async fn wait_for_server() {
        for _ in 0..10 {
            if tonic::transport::Channel::from_static(CLIENT_ADDR)
                .connect()
                .await
                .is_ok()
            {
                return;
            }
            sleep(Duration::from_millis(100)).await;
        }
        panic!("Failed to connect to server")
    }

    async fn test_create_master_key() -> Result<(), ValvError> {
        let server_handle = setup_server().await?;
        wait_for_server().await;

        let mut client = setup_client().await?;

        // Make the gRPC call
        let request = tonic::Request::new(CreateMasterKeyRequest {
            master_key: Some(MasterKey::default()),
            master_key_id: "test".to_string(),
            keyring_name: "test_tenant".to_string(),
        });
        let response = client.create_master_key(request).await.unwrap();

        // Assert the response
        assert!(response.get_ref().master_key.is_some());

        // Stop the server
        server_handle.abort();

        Ok(())
    }

    // Similar tests can be written for other API methods
    async fn test_encrypt_decrypt() -> Result<(), ValvError> {
        let server_handle = setup_server().await?;
        wait_for_server().await;

        let mut client = setup_client().await?;

        // Make the gRPC call
        let request = tonic::Request::new(CreateMasterKeyRequest {
            master_key: Some(MasterKey::default()),
            master_key_id: "test".to_string(),
            keyring_name: "test_tenant".to_string(),
        });
        let response = client.create_master_key(request).await.unwrap();

        // Assert the response
        assert!(response.get_ref().master_key.is_some());

        // Make the gRPC call to encrypt
        let encrypt_request = tonic::Request::new(EncryptRequest {
            master_key_id: response.get_ref().master_key.as_ref().unwrap().name.clone(),
            plaintext: vec![0; 32].into(),
            keyring_name: "test_tenant".to_string(),
        });
        println!("test step encrypted start");
        let encrypt_response = client.encrypt(encrypt_request).await.unwrap();
        println!("test step encrypted pass");
        // Assert the encrypt response
        let original_ciphertext = encrypt_response.get_ref().ciphertext.clone();
        assert_eq!(
            encrypt_response.get_ref().name,
            response.get_ref().master_key.as_ref().unwrap().name
        );
        assert_eq!(original_ciphertext.len(), 64);

        // Make the gRPC call to decrypt with the original master key
        let decrypt_request = tonic::Request::new(DecryptRequest {
            master_key_id: response.get_ref().master_key.as_ref().unwrap().name.clone(),
            ciphertext: original_ciphertext.clone(),
            keyring_name: "test_tenant".to_string(),
        });
        println!("test step decrypt start");
        let decrypt_response = client.decrypt(decrypt_request).await.unwrap();
        println!("test step decrypt pass");

        // Assert the decrypt response
        assert_eq!(decrypt_response.get_ref().plaintext.len(), 32);
        let decrypted_plaintext = decrypt_response.get_ref().plaintext.clone();
        assert_eq!(decrypted_plaintext, vec![0; 32]);

        // Make the gRPC call
        let request = tonic::Request::new(CreateMasterKeyRequest {
            master_key: Some(MasterKey::default()),
            master_key_id: "another_key".to_string(),
            keyring_name: "test_tenant".to_string(),
        });
        let response = client.create_master_key(request).await.unwrap();

        // Assert the response
        assert!(response.get_ref().master_key.is_some());

        // Make the gRPC call to decrypt with another master key
        println!("Decrypting with the wrong key, should fail");
        let decrypt_request_another_key = tonic::Request::new(DecryptRequest {
            master_key_id: "another_key".to_string(),
            ciphertext: original_ciphertext,
            keyring_name: "test_tenant".to_string(),
        });
        let decrypt_response_another_key = client.decrypt(decrypt_request_another_key).await;

        // Assert the decrypt response
        // This should fail because the ciphertext was encrypted with a different master key
        assert!(decrypt_response_another_key.is_err());

        // Stop the server
        server_handle.abort();

        Ok(())
    }
    // Similar tests can be written for other API methods
}
