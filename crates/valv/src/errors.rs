use foundationdb::FdbBindingError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValvError {
    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("Storage error")]
    Storage(#[from] crate::storage::errors::StorageError),

    #[error("BoringSSL error")]
    BoringSSL(#[from] boring::error::ErrorStack),

    #[error("Serialization error")]
    Serialization(#[from] bincode::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Transport error")]
    Transport(#[from] tonic::transport::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ValvError>;

impl From<ValvError> for FdbBindingError {
    fn from(error: ValvError) -> Self {
        FdbBindingError::CustomError(Box::new(error))
    }
}
