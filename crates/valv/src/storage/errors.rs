use foundationdb::FdbBindingError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Generic FoundationDB error")]
    FoundationDB(#[from] foundationdb::FdbError),

    #[error("FoundationDB Binding error")]
    Binding(#[from] foundationdb::FdbBindingError),

    #[error("FoundationDBTuplePacking error")]
    TuplePacking(#[from] foundationdb::tuple::PackError),

    #[error("FoundationDB TransactionCommit error")]
    TransactionCommit(#[from] foundationdb::TransactionCommitError),

    #[error("FoundationDB DirectoryLayer error")]
    DirectoryLayer(foundationdb::directory::DirectoryError),

    #[error("BoringSSL error")]
    BoringSSL(#[from] boring::error::ErrorStack),

    #[error("Prost decode error")]
    ProstDecode(#[from] prost::DecodeError),
}

pub type Result<T> = std::result::Result<T, StorageError>;

impl From<StorageError> for FdbBindingError {
    fn from(error: StorageError) -> Self {
        FdbBindingError::CustomError(Box::new(error))
    }
}
