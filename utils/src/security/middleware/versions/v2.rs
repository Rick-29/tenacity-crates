use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use argon2::Argon2;
use rand::{rngs::OsRng, TryRngCore};
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
        Self {
            salt: DEFAULT_SALT,
            nonce: DEFAULT_NONCE,
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
        Ok(output_key.into())
    }

    pub fn new() -> EncryptorResult<Self> {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.try_fill_bytes(&mut salt)?;     
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.try_fill_bytes(&mut nonce)?;
        Ok(Self {
                    salt,
                    nonce,
                })
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

        let ciphertext_with_tag = cipher.encrypt(&self.nonce.into(), data.as_ref()).map_err(EncryptorError::AesGcmEncryption)?;
        Ok(Bytes::from(ciphertext_with_tag))
    }

    fn decrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);
        
        let ciphertext_with_tag = cipher.decrypt(&self.nonce.into(), data.as_ref()).map_err(EncryptorError::AesGcmDecryption)?;
        Ok(Bytes::from(ciphertext_with_tag))
    }
}

impl TenacityMiddlewareStream for V2Encryptor {}

impl VersionTrait for V2Encryptor {
    fn base_encrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes> {
        Self::default().encrypt_bytes(DEFAULT_PASSWORD, bytes)
    }

    fn base_decrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes> {
        Self::default().decrypt_bytes(DEFAULT_PASSWORD, bytes)
    }
}

impl TenacityEncryptor for V2Encryptor {}

#[cfg(test)]
mod tests {
    use std::{fs::{read_to_string, File, OpenOptions}, io::{BufReader, Cursor, Read, Seek, Write}};

    use aead::stream::NonceSize;
    use aes_gcm::{aead::{AeadMutInPlace, Buffer}, AeadCore, Nonce};
    use rand::rng;

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
    #[test]
    fn test_encrypt_decrypt_base() {
    
        let data = read_to_string(r#"C:\Users\ayfmp\OneDrive\Projects\tenacity-crates\Cargo.lock"#).unwrap();
        let cipher = V2Encryptor::new().unwrap().base_encrypt_bytes(data.as_bytes()).unwrap();
        let decrypted = V2Encryptor::new().unwrap().base_decrypt_bytes(&cipher).unwrap();
        assert_eq!(data.as_bytes(), decrypted.as_ref());
        assert_ne!(decrypted, cipher)
    }

    #[test]
    fn test_in_place() {
        use aead::stream::{EncryptorBE32, DecryptorBE32};
        let key: Key<Aes256Gcm> = [0u8; KEY_SIZE].into();
        let algorithm = Aes256Gcm::new(&key);
        let encryptor_test = V2Encryptor { salt: [0u8; SALT_SIZE], nonce: [0u8; NONCE_SIZE]};
        let nonce = &key[0..7];
        let mut encryptor = EncryptorBE32::from_aead(algorithm.clone(), nonce.into());
        let chunk_size = 1024;
		let mut ciphertext = Cursor::new(Vec::new());

        let mut data = OpenOptions::new().read(true).open("Cargo.toml").unwrap();
        let mut buf = Vec::with_capacity(chunk_size);
        ciphertext.write(&(chunk_size as u64).to_be_bytes()).unwrap();
        let ciphertext_test = encryptor_test.encrypt_bytes([0u8;KEY_SIZE], read_to_string("Cargo.toml").unwrap().as_bytes()).unwrap();
		// Prepend ciphertext with the nonce
		ciphertext.write(nonce).unwrap();

        while (&mut data).take(chunk_size as u64).read_to_end(&mut buf).unwrap() == chunk_size {

            let encrypted = encryptor.encrypt_next(buf.as_slice()).unwrap();
            std::io::Write::write(&mut ciphertext, &encrypted).unwrap();
            buf.clear();
        }
        let encrypted = encryptor.encrypt_last(buf.as_slice()).unwrap();
        std::io::Write::write(&mut ciphertext, &encrypted).unwrap();
        buf.clear();
        // loop {
        //     buf.clear();
		// 	let read_count = (&mut data).take(chunk_size as u64).read_to_end(&mut buf).unwrap();
		// 	if read_count == 0 {
		// 		// this indicates EOF
		// 		break;
		// 	}
		// 	// This works - contrary to examples I found on the internet - because:
		// 	// - Calling `encrypt_last()` is not actually necessary, `encrypt_next()` until the end
		// 	//   will do.
		// 	// - Encrypting empty chunks is fine.
		// 	// - Calling `decrypt_last()` is not necessary either, `decrypt_next()` until the end is
		// 	//   fine.
		// 	// If those conditions weren't true, usage would be much more complicated.
		// 	// And by the way `encrypt()` and `decrypt()` should never be called I think, I don't
		// 	// know why they exist.

		// 	let encrypted = encryptor.encrypt_next(buf.as_slice()).unwrap();
		// 	std::io::Write::write(&mut ciphertext, &encrypted).unwrap();
		// }

		ciphertext.rewind().unwrap();

        
        // dbg!(&ciphertext);
        let mut ciphertext_decrypted = Vec::new();

		// Read chunk size and nonce back
		let mut buf = [0u8; 8];
		ciphertext.read_exact(&mut buf).unwrap();
		let chunk_size = u64::from_be_bytes(buf);
        let mut nonce = [0u8; 7];
		ciphertext.read_exact(&mut nonce[..]).unwrap();

		// Initialize decryption
		let mut stream_decryptor = DecryptorBE32::from_aead(algorithm, &nonce.into());

		let mut buf = Vec::with_capacity((chunk_size + 16) as usize);
        while (&mut ciphertext).take(chunk_size + 16).read_to_end(&mut buf).unwrap() == (chunk_size +16) as usize {
            let mut decrypted = stream_decryptor.decrypt_next(buf.as_slice()).unwrap();
            ciphertext_decrypted.append(&mut decrypted);
            buf.clear();
        }
        let mut decrypted = stream_decryptor.decrypt_last(buf.as_slice()).unwrap();
        ciphertext_decrypted.append(&mut decrypted);
		// loop {
		// 	buf.clear();
		// 	let read_count = (&mut ciphertext).take(chunk_size + 16).read_to_end(&mut buf).unwrap();
		// 	if read_count == 0 {
		// 		// We have processed the last chunk, there are no more chunks in the ciphertext
		// 		break;
		// 	}
		// 	let mut decrypted = stream_decryptor.decrypt_next(buf.as_slice()).unwrap();
		// 	ciphertext_decrypted.append(&mut decrypted);
		// }

        dbg!(String::from_utf8(ciphertext_decrypted.clone()).unwrap());
        dbg!(ciphertext.into_inner().len());
        dbg!("Test: {}", ciphertext_test.len());
        dbg!(read_to_string("Cargo.toml").unwrap().len());
        dbg!(String::from_utf8(ciphertext_decrypted).unwrap().len());
    }
    // use aead_stream::{EncryptorBE32, Encryptor, StreamBE32};
    // let key: Key<Aes256Gcm> = [0u8; KEY_SIZE].into();
    // let algorithm = Aes256Gcm::new(&key);
    // let nonce = Aes256Gcm::generate_nonce_with_rng(&mut rng());
    // let encryptor: Encryptor<Aes256Gcm, StreamBE32<_>> = EncryptorBE32::new(&Array([0u8; KEY_SIZE]), &Aes256Gcm::generate_nonce().unwrap());


    
}