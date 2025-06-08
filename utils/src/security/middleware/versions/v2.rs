use std::io::{Cursor, Read, Write};
use aead::stream::{EncryptorBE32, DecryptorBE32};
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
        VersionTrait::encrypt_bytes(self, secret, data).map_err(anyhow::Error::from)
    }

    fn decrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        VersionTrait::decrypt_bytes(self, secret, data).map_err(anyhow::Error::from)
    }
}

impl TenacityMiddlewareStream for V2Encryptor {}

impl VersionTrait for V2Encryptor {
    const CONFIG_SIZE: usize = SALT_SIZE + NONCE_SIZE;
    const DEFAULT_KEY: &[u8] = DEFAULT_PASSWORD;
    const CHUNK_SIZE: usize = 1014 * 4;

    /// Serializes the salt and nonce into a single Bytes object.
    fn to_bytes(&self) -> Bytes {
        // Create a vector with the exact capacity needed.
        let mut config_bytes = Vec::with_capacity(Self::CONFIG_SIZE);
        // Append the salt and nonce.
        config_bytes.extend_from_slice(&self.salt);
        config_bytes.extend_from_slice(&self.nonce);
        // Convert the Vec to Bytes.
        Bytes::from(config_bytes)
    }

    /// Creates an instance from a byte slice, consuming the necessary bytes.
    fn from_bytes(self, bytes: &mut &[u8]) -> EncryptorResult<Self> {
        // 1. Check if there are enough bytes to read the config.
        if bytes.len() < Self::CONFIG_SIZE {
            return Err(EncryptorError::NotEnoughData);
        }

        // 2. Split the slice into the config part and the remainder.
        let (config_bytes, remainder) = bytes.split_at(Self::CONFIG_SIZE);

        // 3. Create a new V2Encryptor instance by parsing the config bytes.
        // We can use a cursor to read from the slice like a stream.
        let encryptor = self.from_stream(&mut Cursor::new(config_bytes))?;

        // 4. IMPORTANT: Advance the original slice to point to the remainder.
        *bytes = remainder;

        Ok(encryptor)
    }

        /// Creates an instance by reading exactly CONFIG_SIZE bytes from a stream.
    fn from_stream<R: Read>(self, source: &mut R) -> EncryptorResult<Self> {
        let mut config_buf = [0u8; Self::CONFIG_SIZE];

        // 1. Read the exact number of bytes for the configuration.
        // `read_exact` is perfect here; it returns an error if the stream ends prematurely.
        source.read_exact(&mut config_buf)?;

        // 2. Parse the buffer to get the salt.
        let salt = config_buf[0..SALT_SIZE]
            .try_into()
            .expect("Slice with incorrect length cannot be created from consts");

        // 3. Parse the rest of the buffer to get the nonce.
        let nonce = config_buf[SALT_SIZE..Self::CONFIG_SIZE]
            .try_into()
            .expect("Slice with incorrect length cannot be created from consts");
            
        // 4. Construct and return the struct.
        Ok(Self { salt, nonce })
    }


    fn encrypt_bytes<P: AsRef<[u8]> + Send, T: ?Sized + AsRef<[u8]>>(
            &self,
            secret: P,
            bytes: &T,
        ) -> EncryptorResult<Bytes> {
        let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);

        let ciphertext_with_tag = cipher.encrypt(&self.nonce.into(), bytes.as_ref()).map_err(EncryptorError::AesGcmEncryption)?;
        Ok(Bytes::from(ciphertext_with_tag))
    }

    fn decrypt_bytes<P: AsRef<[u8]> + Send, T: ?Sized + AsRef<[u8]>>(
            &self,
            secret: P,
            bytes: &T,
        ) -> EncryptorResult<Bytes> {
        let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);
        
        let ciphertext_with_tag = cipher.decrypt(&self.nonce.into(), bytes.as_ref()).map_err(EncryptorError::AesGcmDecryption)?;
        Ok(Bytes::from(ciphertext_with_tag))
    }

    fn encrypt_bytes_stream<R: Read, W: Write, P: AsRef<[u8]> + Send>(
            &self,
            secret: P,
            source: &mut R,
            destination: &mut W,
        ) -> EncryptorResult<u64> {
        let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);
        let mut encryptor = EncryptorBE32::from_aead(cipher, self.nonce[..7].into());
        let mut buf = Vec::with_capacity(Self::CHUNK_SIZE);

        let mut written: u64 = 0;

        // Encrypt all the data while the length os the data is equal to `Self::CHUNK_SIZE`
        while source.take(Self::CHUNK_SIZE as u64).read_to_end(&mut buf)? == Self::CHUNK_SIZE {
            let encrypted = encryptor.encrypt_next(buf.as_slice()).map_err(EncryptorError::AeadEncryption)?;
            written += Write::write(destination, &encrypted)? as u64;
            buf.clear();
        
        }
        // Encrypt last chunck smaller
        let encrypted = encryptor.encrypt_last(buf.as_slice()).map_err(EncryptorError::AeadEncryption)?;
        written += Write::write(destination, &encrypted)? as u64;
        buf.clear();

        Ok(written)
    }

    fn decrypt_bytes_stream<R: Read, W: Write, P: AsRef<[u8]> + Send>(
            &self,
            secret: P,
            source: &mut R,
            destination: &mut W,
        ) -> EncryptorResult<u64> {
            let key = self.generate_key(secret)?;
        let cipher = Aes256Gcm::new(&key);
        let mut encryptor = DecryptorBE32::from_aead(cipher, self.nonce[..7].into());
        let mut buf = Vec::with_capacity(Self::CHUNK_SIZE + 16); // Chunk size + MAC tag

        let mut written: u64 = 0;
        // Encrypt all the data while the length os the data is equal to `Self::CHUNK_SIZE`
        while source.take(Self::CHUNK_SIZE as u64 + 16).read_to_end(&mut buf)? == Self::CHUNK_SIZE + 16 {
            let encrypted = encryptor.decrypt_next(buf.as_slice()).map_err(EncryptorError::AeadDecryption)?;
            written += Write::write(destination, &encrypted)? as u64;
            buf.clear();
        }
        // Encrypt last chunck smaller
        let encrypted = encryptor.decrypt_next(buf.as_slice()).map_err(EncryptorError::AeadDecryption)?;
        written += Write::write(destination, &encrypted)? as u64;
        buf.clear();

        Ok(written)
    }
}

impl TenacityEncryptor for V2Encryptor {}

#[cfg(test)]
mod tests {
    use std::{fs::{read_to_string, OpenOptions}, io::{Cursor, Read, Seek, Write}};
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
        let cipher = VersionTrait::encrypt_bytes(&v2_encryptor, secret, data.as_bytes()).unwrap();
        let decrypted = VersionTrait::decrypt_bytes(&v2_encryptor, secret, &cipher).unwrap();
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
        ciphertext.write_all(&(chunk_size as u64).to_be_bytes()).unwrap();
        let ciphertext_test = VersionTrait::encrypt_bytes(&encryptor_test, [0u8;KEY_SIZE], read_to_string("Cargo.toml").unwrap().as_bytes()).unwrap();
		// Prepend ciphertext with the nonce
		ciphertext.write_all(nonce).unwrap();

        while (&mut data).take(chunk_size as u64).read_to_end(&mut buf).unwrap() == chunk_size {

            let encrypted = encryptor.encrypt_next(buf.as_slice()).unwrap();
            Write::write(&mut ciphertext, &encrypted).unwrap();
            buf.clear();
        }
        let encrypted = encryptor.encrypt_last(buf.as_slice()).unwrap();
        Write::write(&mut ciphertext, &encrypted).unwrap();
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
		// 	Write::write(&mut ciphertext, &encrypted).unwrap();
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