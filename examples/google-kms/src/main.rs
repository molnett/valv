pub mod google {
    pub mod kms {
        tonic::include_proto!("google.cloud.kms.v1");
    }
}

use crc32c::crc32c;
use google::kms::{
    crypto_key::RotationSchedule, key_management_service_server::KeyManagementService,
};
use tokio::sync::Mutex;
use valv::{gen::valv::internal, ValvAPI};

mod integration_tests;

struct GoogleKMS {
    pub valv: Mutex<valv::Valv>,
}

#[tonic::async_trait]
impl KeyManagementService for GoogleKMS {
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
        let keys = match request.into_inner().parent.split('/').last() {
            Some(key_id) => self.valv.lock().await.list_keys(key_id.to_string()).await,
            None => {
                return Err(tonic::Status::invalid_argument("key_id malformated"));
            }
        };

        match keys {
            Ok(keys) => {
                return Ok(tonic::Response::new(google::kms::ListCryptoKeysResponse {
                    crypto_keys: keys
                        .unwrap_or_default()
                        .into_iter()
                        .map(|key| google::kms::CryptoKey {
                            name: key.key_id,
                            purpose: google::kms::crypto_key::CryptoKeyPurpose::EncryptDecrypt
                                as i32,
                            crypto_key_backend: "valv".to_string(),
                            ..Default::default()
                        })
                        .collect(),
                    next_page_token: "".to_string(),
                    total_size: 0,
                }));
            }
            Err(e) => {
                println!("error: {}", e);
                return Err(tonic::Status::internal(e.to_string()));
            }
        }
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

        let tenant_name = match request.name.split('/').nth(5) {
            Some(tenant_name) => tenant_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("tenant_name malformated"));
            }
        };
        let key_name = match request.name.split('/').last() {
            Some(key_name) => key_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("key_name malformated"));
            }
        };

        let key = self
            .valv
            .lock()
            .await
            .get_key(tenant_name.clone(), key_name.clone())
            .await;

        match key {
            Ok(Some(key)) => {
                let primary = self
                    .valv
                    .lock()
                    .await
                    .get_key_version(tenant_name, key_name, key.primary_version_id)
                    .await;

                match primary {
                    Ok(Some(primary)) => {
                        return Ok(tonic::Response::new(valv_key_to_google_key(key, primary)));
                    }
                    Ok(None) => {
                        return Err(tonic::Status::not_found("primary key version not found"));
                    }
                    Err(e) => {
                        println!("error: {}", e);
                        return Err(tonic::Status::internal(e.to_string()));
                    }
                }
            }
            Ok(None) => {
                return Err(tonic::Status::not_found("key not found"));
            }
            Err(e) => {
                println!("error: {}", e);
                return Err(tonic::Status::internal(e.to_string()));
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

        let tenant_name = match request.parent.split('/').nth(5) {
            Some(tenant_name) => tenant_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("tenant_name malformated"));
            }
        };
        let key_name = request.crypto_key_id;

        let valv = self.valv.lock().await;
        let key = valv.create_key(tenant_name.clone(), key_name.clone()).await;

        match key {
            Ok(key) => {
                let primary = valv
                    .get_key_version(tenant_name, key_name, key.primary_version_id)
                    .await;
                match primary {
                    Ok(Some(primary)) => {
                        return Ok(tonic::Response::new(valv_key_to_google_key(key, primary)));
                    }
                    Ok(None) => {
                        return Err(tonic::Status::not_found("primary key version not found"));
                    }
                    Err(e) => {
                        println!("error: {}", e);
                        return Err(tonic::Status::internal(e.to_string()));
                    }
                }
            }
            Err(e) => {
                println!("error: {}", e);
                return Err(tonic::Status::internal(e.to_string()));
            }
        }
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

        let crypto_key = match request.crypto_key {
            Some(crypto_key) => crypto_key,
            None => {
                return Err(tonic::Status::invalid_argument("crypto_key is required"));
            }
        };

        let tenant_name = match crypto_key.name.split('/').nth(5) {
            Some(tenant_name) => tenant_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("tenant_name malformated"));
            }
        };
        let key_name = match crypto_key.name.split('/').last() {
            Some(key_name) => key_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("key_name malformated"));
            }
        };
        let valv = self.valv.lock().await;
        let key = valv.get_key(tenant_name.clone(), key_name.clone()).await;

        let mut key = match key {
            Ok(key) => match key {
                Some(key) => key,
                None => {
                    return Err(tonic::Status::not_found("key not found"));
                }
            },
            Err(e) => {
                println!("error: {}", e);
                return Err(tonic::Status::internal(e.to_string()));
            }
        };

        let rotation_schedule = match crypto_key.rotation_schedule {
            Some(rotation_schedule) => rotation_schedule,
            None => {
                return Err(tonic::Status::invalid_argument(
                    "rotation_schedule is required",
                ));
            }
        };

        let RotationSchedule::RotationPeriod(rotation_period) = rotation_schedule;

        key.rotation_schedule = Some(rotation_period.clone());

        let key = match valv.update_key(tenant_name.clone(), key).await {
            Ok(key) => key,
            Err(e) => {
                println!("error: {}", e);
                return Err(tonic::Status::internal(e.to_string()));
            }
        };

        let primary = valv
            .get_key_version(tenant_name, key_name, key.primary_version_id)
            .await;

        match primary {
            Ok(Some(primary)) => {
                return Ok(tonic::Response::new(valv_key_to_google_key(key, primary)));
            }
            Ok(None) => {
                return Err(tonic::Status::not_found("primary key version not found"));
            }
            Err(e) => {
                println!("error: {}", e);
                return Err(tonic::Status::internal(e.to_string()));
            }
        }
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

        let tenant_name = match request.name.split('/').nth(5) {
            Some(tenant_name) => tenant_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("tenant_name malformated"));
            }
        };
        let key_name = match request.name.split('/').last() {
            Some(key_name) => key_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("key_name malformated"));
            }
        };

        let ciphertext = self
            .valv
            .lock()
            .await
            .encrypt(tenant_name, key_name, request.plaintext)
            .await;

        match ciphertext {
            Ok(ciphertext) => {
                return Ok(tonic::Response::new(google::kms::EncryptResponse {
                    name: 0.to_string(),
                    ciphertext: ciphertext.clone(),
                    ciphertext_crc32c: Some(crc32c(&ciphertext) as i64),
                    ..Default::default()
                }));
            }
            Err(e) => {
                return Err(tonic::Status::internal(e.to_string()));
            }
        }
    }

    async fn decrypt(
        &self,
        request: tonic::Request<google::kms::DecryptRequest>,
    ) -> Result<tonic::Response<google::kms::DecryptResponse>, tonic::Status> {
        let request = request.into_inner();

        let tenant_name = match request.name.split('/').nth(5) {
            Some(tenant_name) => tenant_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("tenant_name malformated"));
            }
        };
        let key_name = match request.name.split('/').last() {
            Some(key_name) => key_name.to_string(),
            None => {
                return Err(tonic::Status::invalid_argument("key_name malformated"));
            }
        };

        let result = self
            .valv
            .lock()
            .await
            .decrypt(tenant_name, key_name, request.ciphertext)
            .await;

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

fn valv_key_to_google_key(
    key: internal::Key,
    primary: internal::KeyVersion,
) -> google::kms::CryptoKey {
    let mut crypto_key = google::kms::CryptoKey {
        name: key.key_id,
        purpose: google::kms::crypto_key::CryptoKeyPurpose::EncryptDecrypt as i32,
        crypto_key_backend: "valv".to_string(),
        rotation_schedule: key
            .rotation_schedule
            .as_ref()
            .map(|rotation_schedule| RotationSchedule::RotationPeriod(rotation_schedule.clone())),
        primary: Some(google::kms::CryptoKeyVersion {
            name: primary.version.to_string(),
            state: google::kms::crypto_key_version::CryptoKeyVersionState::Enabled as i32,

            ..Default::default()
        }),
        ..Default::default()
    };
    if let Some(creation_time) = primary.creation_time {
        crypto_key.create_time = Some(prost_types::Timestamp {
            seconds: creation_time.seconds,
            nanos: creation_time.nanos,
        });

        if let Some(rotation_schedule) = key.rotation_schedule.as_ref() {
            let next_rotation_time = Some(prost_types::Timestamp {
                seconds: creation_time.seconds + rotation_schedule.seconds,
                nanos: creation_time.nanos + rotation_schedule.nanos,
            });

            crypto_key.next_rotation_time = next_rotation_time;
        }
    }

    crypto_key
}

#[tokio::main]
async fn main() {
    #![allow(clippy::expect_used)]
    let addr = "[::1]:50051".parse().expect("failed to parse address");

    let _guard = unsafe { foundationdb::boot() };

    let mut key = [0; 32];
    boring::rand::rand_bytes(&mut key).expect("failed to generate random key");

    let mut store = valv::Valv::new().await.expect("failed to create valv");

    store.set_master_key(key);
    let api = GoogleKMS {
        valv: Mutex::new(store),
    };

    tonic::transport::Server::builder()
        .add_service(
            google::kms::key_management_service_server::KeyManagementServiceServer::new(api),
        )
        .serve(addr)
        .await
        .expect("failed to start grpc server");
}
