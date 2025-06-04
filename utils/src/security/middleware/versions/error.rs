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
    RandOs(#[from] OsError),
    #[error("MagicCrypt Decryption error, {0}")]
    MagicCryptDecryption(#[from] magic_crypt::MagicCryptError),
    #[error("Std IO error, {0}")]
    Io(#[from] std::io::Error),
    #[error("Version Parsing error, recieved invalid value '{0}'")]
    VersionParsing(String)
}

