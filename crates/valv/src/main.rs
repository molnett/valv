pub mod google {
    pub mod kms {
        tonic::include_proto!("google.cloud.kms.v1");
    }
}

use std::{sync::Arc, time::SystemTime};

use crc32c::crc32c;
use google::kms::{crypto_key::RotationSchedule, key_management_service_server::KeyManagementService};
use keystore::{gen::keystore::internal, Keystore, KeystoreAPI};
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
        request: tonic::Request<google::kms::ListCryptoKeysRequest>,
    ) -> Result<tonic::Response<google::kms::ListCryptoKeysResponse>, tonic::Status> {
        let keys = self.keystore.lock().await.list_keys(request.into_inner().parent.split('/').last().unwrap()).await;
        
        return Ok(tonic::Response::new(google::kms::ListCryptoKeysResponse {
            crypto_keys: keys.unwrap_or_default().into_iter().map(|key| {
                google::kms::CryptoKey {
                    name: key.key_id,
                    purpose: google::kms::crypto_key::CryptoKeyPurpose::EncryptDecrypt as i32,
                    crypto_key_backend: "keystore".to_string(),
                    ..Default::default()
                }
            }).collect(),
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
        request: tonic::Request<google::kms::GetCryptoKeyRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        let request = request.into_inner();
        
        let tenant_name = request.name.split('/').nth(5).unwrap();
        let key_name = request.name.split('/').last().unwrap();

        let key = self.keystore.lock().await.get_key(
            tenant_name,
            key_name,
        ).await;

        match key {
            Some(key) => {
                let primary = self.keystore.lock().await.get_key_version(tenant_name, key_name, key.primary_version_id.parse().unwrap()).await;

                return Ok(tonic::Response::new(keystore_key_to_google_key(key, primary.unwrap())));
            }
            None => {
                return Err(tonic::Status::not_found("key not found"));
            }
        }

        
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
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn create_crypto_key(
        &self,
        request: tonic::Request<google::kms::CreateCryptoKeyRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        let request = request.into_inner();
        
        let tenant_name = request.parent.split('/').nth(5).unwrap();
        let key_name = request.crypto_key_id;

        let keystore = self.keystore.lock().await;
        let key = keystore
            .create_key(
                tenant_name,
                key_name.clone().as_str(),
            )
            .await;

        let primary = keystore.get_key_version(tenant_name, key_name.as_str(), key.primary_version_id.parse().unwrap()).await;
        if primary.is_none() {
            return Err(tonic::Status::not_found("primary key version not found"));
        }

        return Ok(tonic::Response::new(keystore_key_to_google_key(key, primary.unwrap())));
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
        request: tonic::Request<google::kms::UpdateCryptoKeyRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKey>, tonic::Status> {
        let request = request.into_inner();

        if request.crypto_key.is_none() {
            return Err(tonic::Status::invalid_argument("crypto_key is required"));
        }

        let crypto_key = request.crypto_key.unwrap();

        let tenant_name = crypto_key.name.split('/').nth(5).unwrap();
        let key_name = crypto_key.name.split('/').last().unwrap();

        let keystore = self.keystore.lock().await;
        let key = keystore.get_key(tenant_name, key_name).await;

        let mut key = if key.is_none() {
            return Err(tonic::Status::not_found("key not found"));
        } else {
            key.unwrap()
        };

        let rotation_schedule: RotationSchedule = crypto_key.rotation_schedule.unwrap();
        
        let rotation_period = match rotation_schedule {
            RotationSchedule::RotationPeriod(period) => period,
        };

        key.rotation_schedule = Some(rotation_period.clone());

        let key = keystore.update_key(tenant_name, key).await;

        let primary = keystore.get_key_version(tenant_name, key_name, key.primary_version_id.parse().unwrap()).await;
        if primary.is_none() {
            return Err(tonic::Status::not_found("primary key version not found"));
        }

        return Ok(tonic::Response::new(keystore_key_to_google_key(key, primary.unwrap())));
    }

    async fn update_crypto_key_version(
        &self,
        _request: tonic::Request<google::kms::UpdateCryptoKeyVersionRequest>,
    ) -> Result<tonic::Response<google::kms::CryptoKeyVersion>, tonic::Status> {
        return Err(tonic::Status::unimplemented("unimplemented"));
    }

    async fn encrypt(
        &self,
        request: tonic::Request<google::kms::EncryptRequest>,
    ) -> Result<tonic::Response<google::kms::EncryptResponse>, tonic::Status> {
        let request = request.into_inner();

        let tenant_name = request.name.split('/').nth(5).unwrap();
        let key_name = request.name.split('/').last().unwrap();

        let ciphertext = self.keystore.lock().await.encrypt(tenant_name, key_name, request.plaintext).await;

        return Ok(tonic::Response::new(google::kms::EncryptResponse {
            name: 0.to_string(),
            ciphertext: ciphertext.clone(),
            ciphertext_crc32c: Some(crc32c(&ciphertext) as i64),
            ..Default::default()
        }));
    }

    async fn decrypt(
        &self,
        request: tonic::Request<google::kms::DecryptRequest>,
    ) -> Result<tonic::Response<google::kms::DecryptResponse>, tonic::Status> {
        let request = request.into_inner();

        let tenant_name = request.name.split('/').nth(5).unwrap();
        let key_name = request.name.split('/').last().unwrap();

        let result = self.keystore.lock().await.decrypt(tenant_name, key_name, request.ciphertext).await;

        match result {
            Ok(plaintext) => {
                return Ok(tonic::Response::new(google::kms::DecryptResponse {
                    plaintext: plaintext.clone(),
                    plaintext_crc32c: Some(crc32c(&plaintext) as i64),
                    ..Default::default()
                }));
            }
            Err(e) => {
                return Err(tonic::Status::internal(e.to_string()));
            }
        }
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

fn keystore_key_to_google_key(key: internal::Key, primary: internal::KeyVersion) -> google::kms::CryptoKey {
    let next_rotation_time = Some(prost_types::Timestamp {
        seconds: primary.creation_time.clone().unwrap().seconds + key.rotation_schedule.as_ref().unwrap().seconds,
        nanos: primary.creation_time.clone().unwrap().nanos + key.rotation_schedule.as_ref().unwrap().nanos,
    });

    google::kms::CryptoKey {
        name: key.key_id,
        purpose: google::kms::crypto_key::CryptoKeyPurpose::EncryptDecrypt as i32,
        crypto_key_backend: "keystore".to_string(),
        rotation_schedule: key.rotation_schedule.map(|rotation_schedule| {
            RotationSchedule::RotationPeriod(rotation_schedule)
        }),
        next_rotation_time: next_rotation_time,
        primary: Some(google::kms::CryptoKeyVersion {
            name: primary.version.to_string(),
            state: google::kms::crypto_key_version::CryptoKeyVersionState::Enabled as i32,
            create_time: Some(prost_types::Timestamp {
                seconds: primary.creation_time.clone().unwrap().seconds,
                nanos: primary.creation_time.unwrap().nanos,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::main]
async fn main() {
    let addr = "[::1]:50051".parse().unwrap();

    let _guard = unsafe { foundationdb::boot() };

    let mut key = [0; 32];
    boring::rand::rand_bytes(&mut key).unwrap();

    let mut keystore = Keystore::new(Arc::new(SystemTime::now())).await;

    keystore.set_master_key(key);
    let api = ValvAPI {
        keystore: Mutex::new(keystore),
    };

    tonic::transport::Server::builder()
        .add_service(
            google::kms::key_management_service_server::KeyManagementServiceServer::new(api),
        )
        .serve(addr)
        .await
        .unwrap();
}
