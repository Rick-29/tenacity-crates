pub mod error;

pub mod v1;
pub mod v2;

pub use v1::V1Encryptor;

pub type EncryptorResult<T> = Result<T, error::EncryptorError>;