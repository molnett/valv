pub mod google {
    pub mod kms {
        tonic::include_proto!("google.cloud.kms.v1");
    }
}

use google::kms::key_management_service_server::KeyManagementService;
use keystore::KeystoreAPI;
use tokio::sync::Mutex;

mod tests;

struct ValvAPI {
    pub keystore: Mutex<keystore::Keystore>,
}

#[tonic::async_trait]
impl KeyManagementService for ValvAPI {
    async fn list_key_rings(
        &self,
        _request: tonic::Request<google::kms::ListKeyRingsRequest>,
    ) -> Result<tonic::Response<google::kms::ListKeyRingsResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn list_crypto_keys(
        &self,
        _request: tonic::Request<google::kms::ListCryptoKeysRequest>,
    ) -> Result<tonic::Response<google::kms::ListCryptoKeysResponse>, tonic::Status> {
        self.keystore.lock().await.list_keys();
        return Ok(tonic::Response::new(google::kms::ListCryptoKeysResponse {
            crypto_keys: vec![google::kms::CryptoKey {
                name: "test".to_string(),
                purpose: google::kms::crypto_key::CryptoKeyPurpose::Unspecified as i32,
                crypto_key_backend: "keystore".to_string(),
                ..Default::default()
            }],
            next_page_token: "".to_string(),
            total_size: 0,
        }));
    }

    async fn list_crypto_key_versions(
        &self,
        _request: tonic::Request<google::kms::ListCryptoKeyVersionsRequest>,
    ) -> Result<tonic::Response<google::kms::ListCryptoKeyVersionsResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn list_import_jobs(
        &self,
        _request: tonic::Request<google::kms::ListImportJobsRequest>,
    ) -> Result<tonic::Response<google::kms::ListImportJobsResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn get_key_ring(
        &self,
        _request: tonic::Request<google::kms::GetKeyRingRequest>,
    ) -> Result<tonic::Response<google::kms::KeyRing>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn get_crypto_key(
        &self,
        _request: tonic::Request<google::kms::GetCryptoKeyRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn get_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::GetCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn get_public_key(
        &self,
        _request: tonic::Request<google::kms::GetPublicKeyRequest>,
    ) -> Result<tonic::Response<google::kms::PublicKey>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn get_import_job(
        &self,
        _request: tonic::Request<google::kms::GetImportJobRequest>,
    ) -> Result<tonic::Response<google::kms::ImportJob>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn create_key_ring(
        &self,
        _request: tonic::Request<google::kms::CreateKeyRingRequest>,
    ) -> Result<tonic::Response<google::kms::KeyRing>, tonic::Status> {
        self.keystore.lock().await.list_keys();
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn create_crypto_key(
        &self,
        request: tonic::Request<google::kms::CreateCryptoKeyRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        let keystore = self.keystore.lock().await;
        let encrypted_key = keystore
            .create_key(request.into_inner().crypto_key_id)
            .await;

        return Ok(tonic::Response::new(google::kms::CryptoKey {
            name: encrypted_key.name,
            purpose: google::kms::crypto_key::CryptoKeyPurpose::EncryptDecrypt as i32,
            crypto_key_backend: "keystore".to_string(),
            ..Default::default()
        }));
    }

    async fn create_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::CreateCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn import_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::ImportCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn create_import_job(
        &self,
        _request: tonic::Request<google::kms::CreateImportJobRequest>,
    ) -> Result<tonic::Response<google::kms::ImportJob>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn update_crypto_key(
        &self,
        _request: tonic::Request<google::kms::UpdateCryptoKeyRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn update_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::UpdateCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn encrypt(
        &self,
        _request: tonic::Request<google::kms::EncryptRequest>,
    ) -> Result<tonic::Response<google::kms::EncryptResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn decrypt(
        &self,
        _request: tonic::Request<google::kms::DecryptRequest>,
    ) -> Result<tonic::Response<google::kms::DecryptResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn update_crypto_key_primary_version(
        &self,
        _request: tonic::Request<google::kms::UpdateCryptoKeyPrimaryVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn destroy_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::DestroyCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn restore_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::RestoreCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn raw_encrypt(
        &self,
        _request: tonic::Request<google::kms::RawEncryptRequest>,
    ) -> Result<tonic::Response<google::kms::RawEncryptResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn raw_decrypt(
        &self,
        _request: tonic::Request<google::kms::RawDecryptRequest>,
    ) -> Result<tonic::Response<google::kms::RawDecryptResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn asymmetric_sign(
        &self,
        _request: tonic::Request<google::kms::AsymmetricSignRequest>,
    ) -> Result<tonic::Response<google::kms::AsymmetricSignResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn asymmetric_decrypt(
        &self,
        _request: tonic::Request<google::kms::AsymmetricDecryptRequest>,
    ) -> Result<tonic::Response<google::kms::AsymmetricDecryptResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn mac_sign(
        &self,
        _request: tonic::Request<google::kms::MacSignRequest>,
    ) -> Result<tonic::Response<google::kms::MacSignResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn mac_verify(
        &self,
        _request: tonic::Request<google::kms::MacVerifyRequest>,
    ) -> Result<tonic::Response<google::kms::MacVerifyResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn generate_random_bytes(
        &self,
        _request: tonic::Request<google::kms::GenerateRandomBytesRequest>,
    ) -> Result<tonic::Response<google::kms::GenerateRandomBytesResponse>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }
}

#[tokio::main]
async fn main() {
    let addr = "[::1]:50051".parse().unwrap();

    let mut key = [0; 32];
    boring::rand::rand_bytes(&mut key).unwrap();

    let mut store = keystore::Keystore::new().await;

    store.set_master_key(key);
    let api = ValvAPI {
        keystore: Mutex::new(store),
    };

    tonic::transport::Server::builder()
        .add_service(
            google::kms::key_management_service_server::KeyManagementServiceServer::new(api),
        )
        .serve(addr)
        .await
        .unwrap();
}
