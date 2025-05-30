use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{password_hash::rand_core::{OsRng, RngCore}, Argon2};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
#[cfg(not(feature = "wasm"))]
use utoipa::ToSchema;

use crate::security::{middleware::traits::VersionTrait, TenacityEncryptor, TenacityMiddleware, TenacityMiddlewareStream};

use super::{error::EncryptorError, EncryptorResult};
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;
const DEFAULT_PASSWORD: &[u8] = b"ChipaTenacityWolf";
// This nonce is 12 bytes (96 bits) for AES-GCM compatibility
pub const DEFAULT_NONCE: [u8; 12] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC,
];
// This salt is 16 bytes (128 bits)
pub const DEFAULT_SALT: [u8; 16] = [
    0x0A, 0x1C, 0x2E, 0x30, 0x42, 0x54, 0x66, 0x78, // "ChipaTenacity" theme
    0x8A, 0x9C, 0xA1, 0xB3, 0xC5, 0xD7, 0xE9, 0xF1, // More unique bytes
];

#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2Encryptor {
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
}

impl Default for V2Encryptor {
    fn default() -> Self {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);     
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        Self {
            salt,
            nonce,
        }
    }
}



impl V2Encryptor {
    fn generate_key<P>(&self, secret: P) -> EncryptorResult<Key<Aes256Gcm>>
    where
        P: AsRef<[u8]> 
    {   
        let mut output_key = [0u8; KEY_SIZE];
        Argon2::default().hash_password_into(secret.as_ref(), &self.salt, &mut output_key).map_err(EncryptorError::Argon2)?;
        Ok(*Key::<Aes256Gcm>::from_slice(&output_key))
    }

    pub fn new_static() -> Self {
        Self {
            salt: DEFAULT_SALT,
            nonce: DEFAULT_NONCE,
        }
    }
}


#[async_trait::async_trait]
impl TenacityMiddleware for V2Encryptor {

    async fn encrypt_str<P>(&self, _secret: P, _data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send,
    {
        anyhow::bail!("Error, Unallowed: Can not encrypt string to string, use `encrypt_bytes` instead")
    }

    async fn decrypt_str<P>(&self, _secret: P, _data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send,
    {
        anyhow::bail!("Error, Unallowed: Can not decrypt string to string, use `decrypt_bytes` instead")
    }

    fn encrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);

        let ciphertext_with_tag = cipher.encrypt(Nonce::from_slice(&self.nonce), data.as_ref()).map_err(EncryptorError::AesGcmEncryption)?;
        Ok(Bytes::from(ciphertext_with_tag))
    }

    fn decrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);

        let ciphertext_with_tag = cipher.decrypt(Nonce::from_slice(&self.nonce), data.as_ref()).map_err(EncryptorError::AesGcmDecryption)?;
        Ok(Bytes::from(ciphertext_with_tag))
    }
}

impl TenacityMiddlewareStream for V2Encryptor {}

impl VersionTrait for V2Encryptor {
    fn base_encrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes> {
        self.encrypt_bytes(DEFAULT_PASSWORD, bytes)
    }

    fn base_decrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes> {
        self.decrypt_bytes(DEFAULT_PASSWORD, bytes)
    }
}

impl TenacityEncryptor for V2Encryptor {}

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use super::*;

    #[test]
    fn test_v2_encryptor_default() {
        let v2_encryptor = V2Encryptor::default();
        
        assert_eq!(v2_encryptor.salt.len(), SALT_SIZE);
        assert_eq!(v2_encryptor.nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_generate_key() {
        let secret = b"my_secret";
        let v2_encryptor = V2Encryptor::default();
        let result = v2_encryptor.generate_key(secret);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), KEY_SIZE);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let secret = b"my_secret";
        let data = read_to_string(r#"C:\Users\ayfmp\OneDrive\Projects\tenacity-crates\Cargo.lock"#).unwrap();
        let v2_encryptor = V2Encryptor::default();
        let cipher = v2_encryptor.encrypt_bytes(secret, data.as_bytes()).unwrap();
        let decrypted = v2_encryptor.decrypt_bytes(secret, &cipher).unwrap();
        assert_eq!(data.as_bytes(), decrypted.as_ref());
        assert_ne!(decrypted, cipher);
        dbg!(cipher.len());
        dbg!(decrypted.len());
    }
}