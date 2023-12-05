// @generated
/// Generated client implementations.
pub mod master_key_management_service_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    #[derive(Debug, Clone)]
    pub struct MasterKeyManagementServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl MasterKeyManagementServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> MasterKeyManagementServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> MasterKeyManagementServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            MasterKeyManagementServiceClient::new(
                InterceptedService::new(inner, interceptor),
            )
        }
        /// Compress requests with the given encoding.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Enable decompressing responses.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        pub async fn create_master_key(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateMasterKeyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CreateMasterKeyResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/CreateMasterKey",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "CreateMasterKey",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_master_keys(
            &mut self,
            request: impl tonic::IntoRequest<super::ListMasterKeysRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListMasterKeysResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/ListMasterKeys",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "ListMasterKeys",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn list_master_key_versions(
            &mut self,
            request: impl tonic::IntoRequest<super::ListMasterKeyVersionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListMasterKeyVersionsResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/ListMasterKeyVersions",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "ListMasterKeyVersions",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn create_master_key_version(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateMasterKeyVersionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CreateMasterKeyVersionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/CreateMasterKeyVersion",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "CreateMasterKeyVersion",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn destroy_master_key_version(
            &mut self,
            request: impl tonic::IntoRequest<super::DestroyMasterKeyVersionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::DestroyMasterKeyVersionResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/DestroyMasterKeyVersion",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "DestroyMasterKeyVersion",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn encrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::EncryptRequest>,
        ) -> std::result::Result<
            tonic::Response<super::EncryptResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/Encrypt",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "Encrypt",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
        pub async fn decrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::DecryptRequest>,
        ) -> std::result::Result<
            tonic::Response<super::DecryptResponse>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/valv.keystore.v1.MasterKeyManagementService/Decrypt",
            );
            let mut req = request.into_request();
            req.extensions_mut()
                .insert(
                    GrpcMethod::new(
                        "valv.keystore.v1.MasterKeyManagementService",
                        "Decrypt",
                    ),
                );
            self.inner.unary(req, path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod master_key_management_service_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Generated trait containing gRPC methods that should be implemented for use with MasterKeyManagementServiceServer.
    #[async_trait]
    pub trait MasterKeyManagementService: Send + Sync + 'static {
        async fn create_master_key(
            &self,
            request: tonic::Request<super::CreateMasterKeyRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CreateMasterKeyResponse>,
            tonic::Status,
        >;
        async fn list_master_keys(
            &self,
            request: tonic::Request<super::ListMasterKeysRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListMasterKeysResponse>,
            tonic::Status,
        >;
        async fn list_master_key_versions(
            &self,
            request: tonic::Request<super::ListMasterKeyVersionsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListMasterKeyVersionsResponse>,
            tonic::Status,
        >;
        async fn create_master_key_version(
            &self,
            request: tonic::Request<super::CreateMasterKeyVersionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::CreateMasterKeyVersionResponse>,
            tonic::Status,
        >;
        async fn destroy_master_key_version(
            &self,
            request: tonic::Request<super::DestroyMasterKeyVersionRequest>,
        ) -> std::result::Result<
            tonic::Response<super::DestroyMasterKeyVersionResponse>,
            tonic::Status,
        >;
        async fn encrypt(
            &self,
            request: tonic::Request<super::EncryptRequest>,
        ) -> std::result::Result<tonic::Response<super::EncryptResponse>, tonic::Status>;
        async fn decrypt(
            &self,
            request: tonic::Request<super::DecryptRequest>,
        ) -> std::result::Result<tonic::Response<super::DecryptResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct MasterKeyManagementServiceServer<T: MasterKeyManagementService> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    struct _Inner<T>(Arc<T>);
    impl<T: MasterKeyManagementService> MasterKeyManagementServiceServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>>
    for MasterKeyManagementServiceServer<T>
    where
        T: MasterKeyManagementService,
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/valv.keystore.v1.MasterKeyManagementService/CreateMasterKey" => {
                    #[allow(non_camel_case_types)]
                    struct CreateMasterKeySvc<T: MasterKeyManagementService>(pub Arc<T>);
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::CreateMasterKeyRequest>
                    for CreateMasterKeySvc<T> {
                        type Response = super::CreateMasterKeyResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateMasterKeyRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).create_master_key(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateMasterKeySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/valv.keystore.v1.MasterKeyManagementService/ListMasterKeys" => {
                    #[allow(non_camel_case_types)]
                    struct ListMasterKeysSvc<T: MasterKeyManagementService>(pub Arc<T>);
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::ListMasterKeysRequest>
                    for ListMasterKeysSvc<T> {
                        type Response = super::ListMasterKeysResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListMasterKeysRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).list_master_keys(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ListMasterKeysSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/valv.keystore.v1.MasterKeyManagementService/ListMasterKeyVersions" => {
                    #[allow(non_camel_case_types)]
                    struct ListMasterKeyVersionsSvc<T: MasterKeyManagementService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::ListMasterKeyVersionsRequest>
                    for ListMasterKeyVersionsSvc<T> {
                        type Response = super::ListMasterKeyVersionsResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListMasterKeyVersionsRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).list_master_key_versions(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ListMasterKeyVersionsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/valv.keystore.v1.MasterKeyManagementService/CreateMasterKeyVersion" => {
                    #[allow(non_camel_case_types)]
                    struct CreateMasterKeyVersionSvc<T: MasterKeyManagementService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::CreateMasterKeyVersionRequest>
                    for CreateMasterKeyVersionSvc<T> {
                        type Response = super::CreateMasterKeyVersionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::CreateMasterKeyVersionRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).create_master_key_version(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = CreateMasterKeyVersionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/valv.keystore.v1.MasterKeyManagementService/DestroyMasterKeyVersion" => {
                    #[allow(non_camel_case_types)]
                    struct DestroyMasterKeyVersionSvc<T: MasterKeyManagementService>(
                        pub Arc<T>,
                    );
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::DestroyMasterKeyVersionRequest>
                    for DestroyMasterKeyVersionSvc<T> {
                        type Response = super::DestroyMasterKeyVersionResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<
                                super::DestroyMasterKeyVersionRequest,
                            >,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                (*inner).destroy_master_key_version(request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DestroyMasterKeyVersionSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/valv.keystore.v1.MasterKeyManagementService/Encrypt" => {
                    #[allow(non_camel_case_types)]
                    struct EncryptSvc<T: MasterKeyManagementService>(pub Arc<T>);
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::EncryptRequest>
                    for EncryptSvc<T> {
                        type Response = super::EncryptResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::EncryptRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move { (*inner).encrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/valv.keystore.v1.MasterKeyManagementService/Decrypt" => {
                    #[allow(non_camel_case_types)]
                    struct DecryptSvc<T: MasterKeyManagementService>(pub Arc<T>);
                    impl<
                        T: MasterKeyManagementService,
                    > tonic::server::UnaryService<super::DecryptRequest>
                    for DecryptSvc<T> {
                        type Response = super::DecryptResponse;
                        type Future = BoxFuture<
                            tonic::Response<Self::Response>,
                            tonic::Status,
                        >;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DecryptRequest>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move { (*inner).decrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => {
                    Box::pin(async move {
                        Ok(
                            http::Response::builder()
                                .status(200)
                                .header("grpc-status", "12")
                                .header("content-type", "application/grpc")
                                .body(empty_body())
                                .unwrap(),
                        )
                    })
                }
            }
        }
    }
    impl<T: MasterKeyManagementService> Clone for MasterKeyManagementServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    impl<T: MasterKeyManagementService> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: MasterKeyManagementService> tonic::server::NamedService
    for MasterKeyManagementServiceServer<T> {
        const NAME: &'static str = "valv.keystore.v1.MasterKeyManagementService";
    }
}
