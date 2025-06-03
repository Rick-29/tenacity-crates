use rand_chacha::rand_core::OsError;

#[derive(Debug, thiserror::Error)]
pub enum EncryptorError {
    #[error("Argon2 error: {0}")]
    Argon2(argon2::Error),
    #[error("AES-GCM encryption error, {0}")]
    AesGcmEncryption(aes_gcm::Error),
    #[error("AES-GCM decryption error, {0}")]
    AesGcmDecryption(aes_gcm::Error),
    #[error("Rand OS error, {0}")]
    RandOs(#[from] OsError)
}

