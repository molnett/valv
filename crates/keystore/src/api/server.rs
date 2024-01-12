
use std::sync::Arc;

use crate::{valv::keystore::v1::{MasterKey, master_key_management_service_server::{MasterKeyManagementService, MasterKeyManagementServiceServer}, CreateMasterKeyRequest, CreateMasterKeyResponse, ListMasterKeysRequest, ListMasterKeysResponse, ListMasterKeyVersionsRequest, ListMasterKeyVersionsResponse, CreateMasterKeyVersionRequest, CreateMasterKeyVersionResponse, MasterKeyVersion, DestroyMasterKeyVersionRequest, DestroyMasterKeyVersionResponse, EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse}, KeystoreAPI, Keystore};

pub struct API {
    pub keystore: Arc<Keystore>
}

#[tonic::async_trait]
impl MasterKeyManagementService for API  {
    async fn create_master_key(
        &self,
        request: tonic::Request<CreateMasterKeyRequest>,
    ) -> Result<tonic::Response<CreateMasterKeyResponse>, tonic::Status> {
        let key = self.keystore.create_crypto_key(request.get_ref().master_key_id.clone());

        let reply = CreateMasterKeyResponse { master_key: Some(MasterKey{
            name: key.name,
            ..Default::default()
        }) };

        Ok(tonic::Response::new(reply))
    }

    async fn list_master_keys(
        &self,
        _request: tonic::Request<ListMasterKeysRequest>,
    ) -> Result<tonic::Response<ListMasterKeysResponse>, tonic::Status> {
        let reply = ListMasterKeysResponse { master_keys: vec![MasterKey::default()] };

        Ok(tonic::Response::new(reply))
    }

    async fn list_master_key_versions(
        &self,
        _request: tonic::Request<ListMasterKeyVersionsRequest>,
    ) -> Result<tonic::Response<ListMasterKeyVersionsResponse>, tonic::Status> {
        let reply = ListMasterKeyVersionsResponse { master_key_versions: vec![MasterKeyVersion::default()] };

        Ok(tonic::Response::new(reply))
    }

    async fn create_master_key_version(
        &self,
        _request: tonic::Request<CreateMasterKeyVersionRequest>,
    ) -> Result<tonic::Response<CreateMasterKeyVersionResponse>, tonic::Status> {
        let reply = CreateMasterKeyVersionResponse { master_key_version: Some(MasterKeyVersion::default()) };

        Ok(tonic::Response::new(reply))
    }

    async fn destroy_master_key_version(
        &self,
        _request: tonic::Request<DestroyMasterKeyVersionRequest>,
    ) -> Result<tonic::Response<DestroyMasterKeyVersionResponse>, tonic::Status> {
        let reply = DestroyMasterKeyVersionResponse { master_key_version: Some(MasterKeyVersion::default())};

        Ok(tonic::Response::new(reply))
    }

    async fn encrypt(
        &self,
        request: tonic::Request<EncryptRequest>,
    ) -> Result<tonic::Response<EncryptResponse>, tonic::Status> {
        let encrypted_value = self.keystore.encrypt(request.get_ref().master_key_id.clone(), request.get_ref().plaintext.clone().to_vec());

        let reply = crate::valv::keystore::v1::EncryptResponse {
            name: request.get_ref().master_key_id.clone(),
            ciphertext: encrypted_value.into(),
        };

        Ok(tonic::Response::new(reply))
    }

    async fn decrypt(
        &self,
        request: tonic::Request<DecryptRequest>,
    ) -> Result<tonic::Response<DecryptResponse>, tonic::Status> {
        let decrypted_result = self.keystore.decrypt(request.get_ref().master_key_id.clone(), request.get_ref().ciphertext.clone().to_vec());
        match decrypted_result {
            Ok(decrypted_value) => {
                let reply = DecryptResponse {
                    plaintext: decrypted_value.into(),
                };
                return Ok(tonic::Response::new(reply));
            },
            Err(_) => {
                return Err(tonic::Status::new(tonic::Code::InvalidArgument, "Invalid ciphertext"));
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tonic::transport::Server;

    use super::*;
    use crate::{valv::keystore::v1::master_key_management_service_client::MasterKeyManagementServiceClient, Keystore};
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_create_master_key() {
        // Start the server
        let addr = "0.0.0.0:8080".parse().unwrap();
        let keystore = Keystore::new();
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
                },
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

        // Stop the server
        server_handle.abort();
    }

    // Similar tests can be written for other API methods
    #[tokio::test]
    async fn test_encrypt_decrypt() {
        // Start the server
        let addr = "0.0.0.0:8080".parse().unwrap();
        let keystore = Keystore::new();
        let api = API {
            keystore: Arc::new(keystore)
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
                },
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
        assert_eq!(encrypt_response.get_ref().name, response.get_ref().master_key.as_ref().unwrap().name);
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
