use std::sync::Arc;

use crate::{
    valv::valv::v1::{
        master_key_management_service_server::MasterKeyManagementService, CreateMasterKeyRequest,
        CreateMasterKeyResponse, CreateMasterKeyVersionRequest, CreateMasterKeyVersionResponse,
        DecryptRequest, DecryptResponse, DestroyMasterKeyVersionRequest,
        DestroyMasterKeyVersionResponse, EncryptRequest, EncryptResponse,
        ListMasterKeyVersionsRequest, ListMasterKeyVersionsResponse, ListMasterKeysRequest,
        ListMasterKeysResponse, MasterKey, MasterKeyVersion,
    },
    Valv, ValvAPI,
};

pub struct API {
    pub valv: Arc<Valv>,
}

#[tonic::async_trait]
impl MasterKeyManagementService for API {
    async fn create_master_key(
        &self,
        request: tonic::Request<CreateMasterKeyRequest>,
    ) -> Result<tonic::Response<CreateMasterKeyResponse>, tonic::Status> {
        let key = self
            .valv
            .create_key(
                request.get_ref().keyring_name.clone(),
                request.get_ref().master_key_id.clone(),
            )
            .await;

        let reply = CreateMasterKeyResponse {
            master_key: Some(MasterKey {
                name: key.key_id,
                ..Default::default()
            }),
        };

        Ok(tonic::Response::new(reply))
    }

    async fn list_master_keys(
        &self,
        _request: tonic::Request<ListMasterKeysRequest>,
    ) -> Result<tonic::Response<ListMasterKeysResponse>, tonic::Status> {
        let reply = ListMasterKeysResponse {
            master_keys: vec![MasterKey::default()],
        };

        Ok(tonic::Response::new(reply))
    }

    async fn list_master_key_versions(
        &self,
        _request: tonic::Request<ListMasterKeyVersionsRequest>,
    ) -> Result<tonic::Response<ListMasterKeyVersionsResponse>, tonic::Status> {
        let reply = ListMasterKeyVersionsResponse {
            master_key_versions: vec![MasterKeyVersion::default()],
        };

        Ok(tonic::Response::new(reply))
    }

    async fn create_master_key_version(
        &self,
        _request: tonic::Request<CreateMasterKeyVersionRequest>,
    ) -> Result<tonic::Response<CreateMasterKeyVersionResponse>, tonic::Status> {
        let reply = CreateMasterKeyVersionResponse {
            master_key_version: Some(MasterKeyVersion::default()),
        };

        Ok(tonic::Response::new(reply))
    }

    async fn destroy_master_key_version(
        &self,
        _request: tonic::Request<DestroyMasterKeyVersionRequest>,
    ) -> Result<tonic::Response<DestroyMasterKeyVersionResponse>, tonic::Status> {
        let reply = DestroyMasterKeyVersionResponse {
            master_key_version: Some(MasterKeyVersion::default()),
        };

        Ok(tonic::Response::new(reply))
    }

    async fn encrypt(
        &self,
        request: tonic::Request<EncryptRequest>,
    ) -> Result<tonic::Response<EncryptResponse>, tonic::Status> {
        let encrypted_value = self
            .valv
            .encrypt(
                request.get_ref().keyring_name.clone(),
                request.get_ref().master_key_id.clone(),
                request.get_ref().plaintext.clone().to_vec(),
            )
            .await;

        let reply = crate::valv::valv::v1::EncryptResponse {
            name: request.get_ref().master_key_id.clone(),
            ciphertext: encrypted_value.into(),
        };

        Ok(tonic::Response::new(reply))
    }

    async fn decrypt(
        &self,
        request: tonic::Request<DecryptRequest>,
    ) -> Result<tonic::Response<DecryptResponse>, tonic::Status> {
        let decrypted_result = self
            .valv
            .decrypt(
                request.get_ref().keyring_name.clone(),
                request.get_ref().master_key_id.clone(),
                request.get_ref().ciphertext.clone().to_vec(),
            )
            .await;
        match decrypted_result {
            Ok(decrypted_value) => {
                let reply = DecryptResponse {
                    plaintext: decrypted_value.into(),
                };
                return Ok(tonic::Response::new(reply));
            }
            Err(err) => {
                println!("Failed to decrypt ciphertext {err}");
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Invalid ciphertext",
                ));
            }
        }
    }
}
