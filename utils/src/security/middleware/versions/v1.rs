use core::str;
use std::io::{Read, Write};

use bytes::Bytes;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use serde::{Deserialize, Serialize};

use crate::security::middleware::{
    traits::ConfigurableEncryptor,
    versions::{error::EncryptorError, EncryptorResult},
};

use super::super::traits::{
    TenacityEncryptor, TenacityMiddleware, TenacityMiddlewareStream, VersionTrait,
};

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
pub struct V1Encryptor;

impl V1Encryptor {
    const KEY: &[u8] = b"tenacity";
}

#[async_trait::async_trait]
impl TenacityMiddleware for V1Encryptor {
    async fn encrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send,
    {
        let mc = new_magic_crypt!(secret, 256);
        Ok(mc.encrypt_str_to_base64(data))
    }

    async fn decrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send,
    {
        let mc = new_magic_crypt!(secret, 256);
        mc.decrypt_base64_to_string(data)
            .map_err(|e| anyhow::anyhow!("Error decoding base64 body, {e}"))
    }

    fn encrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        VersionTrait::encrypt_bytes(self, &secret, data).map_err(anyhow::Error::from)
    }
    fn decrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        VersionTrait::decrypt_bytes(self, &secret, data).map_err(anyhow::Error::from)
    }
}

impl TenacityEncryptor for V1Encryptor {}

impl ConfigurableEncryptor for V1Encryptor {
    type Error = EncryptorError;

    fn size(&self) -> usize {
        0 // V1Encryptor does not have a size
    }

    fn from_bytes(self, _bytes: &mut &[u8]) -> EncryptorResult<Self>
    where
        Self: Sized,
    {
        Ok(V1Encryptor)
    }

    fn from_stream<R: Read>(self, _source: &mut R) -> EncryptorResult<Self>
    where
        Self: Sized,
    {
        Ok(V1Encryptor)
    }

    fn to_bytes(&self) -> Bytes {
        Bytes::new()
    }
}

impl VersionTrait for V1Encryptor {
    const DEFAULT_KEY: &[u8] = Self::KEY;

    fn encrypt_bytes<P: AsRef<[u8]> + Send, T: ?Sized + AsRef<[u8]>>(
        &self,
        secret: &P,
        bytes: &T,
    ) -> super::EncryptorResult<Bytes> {
        let mc: magic_crypt::MagicCrypt256 = new_magic_crypt!(secret, 256);
        let bytes = Bytes::from(mc.encrypt_bytes_to_bytes(bytes));
        Ok(bytes)
    }

    fn decrypt_bytes<P: AsRef<[u8]> + Send, T: ?Sized + AsRef<[u8]>>(
        &self,
        secret: &P,
        bytes: &T,
    ) -> super::EncryptorResult<Bytes> {
        let mc = new_magic_crypt!(secret, 256);
        mc.decrypt_bytes_to_bytes(bytes)
            .map_err(EncryptorError::from)
            .map(Bytes::from)
    }

    fn encrypt_bytes_stream<R: Read, W: Write, P: AsRef<[u8]> + Send>(
        &self,
        secret: &P,
        source: &mut R,
        destination: &mut W,
        chunk_size: u64,
    ) -> super::EncryptorResult<u64> {
        let mc = new_magic_crypt!(secret, 256);
        let mut written = 0;
        if chunk_size < 16 {
            return Err(EncryptorError::InvalidChunkSize {
                got: chunk_size as usize,
                min: 16,
            });
        }
        let mut buf = Vec::with_capacity(chunk_size as usize);
        while source.take(chunk_size).read_to_end(&mut buf)? == chunk_size as usize {
            let encrypted = mc.encrypt_bytes_to_bytes(&buf);
            destination.write_all(&encrypted)?;
            written += encrypted.len();
            buf.clear();
        }
        if !buf.is_empty() {
            let encrypted = mc.encrypt_bytes_to_bytes(&buf);
            destination.write_all(&encrypted)?;
            written += encrypted.len();
            buf.clear();
        }
        written.try_into().map_err(
            |e: std::num::TryFromIntError| EncryptorError::ConversionError {
                from: "usize".to_string(),
                to: "u64".to_string(),
                error: e.to_string(),
            },
        )
        // match chunk_size {
        //     128 => { mc.encrypt_reader_to_writer2::<U128>(source, destination)?; Ok(0) },
        //     256 => { mc.encrypt_reader_to_writer2::<U256>(source, destination)?; Ok(0) },
        //     512 => { mc.encrypt_reader_to_writer2::<U512>(source, destination)?; Ok(0) },
        //     2048 => { mc.encrypt_reader_to_writer2::<U2048>(source, destination)?; Ok(0) },
        //     4096 => { mc.encrypt_reader_to_writer2::<U4096>(source, destination)?; Ok(0) },
        //     8192 => { mc.encrypt_reader_to_writer2::<U8192>(source, destination)?; Ok(0) },
        //     16384 => { mc.encrypt_reader_to_writer2::<U16384>(source, destination)?; Ok(0) },
        //     32768 => { mc.encrypt_reader_to_writer2::<U32768>(source, destination)?; Ok(0) },
        //     65536 => { mc.encrypt_reader_to_writer2::<U65536>(source, destination)?; Ok(0) },
        //     _ => { mc.encrypt_reader_to_writer2::<U1024>(source, destination)?; Ok(0) },
        // }
    }

    fn decrypt_bytes_stream<R: Read, W: Write, P: AsRef<[u8]> + Send>(
        &self,
        secret: &P,
        source: &mut R,
        destination: &mut W,
        chunk_size: u64,
    ) -> super::EncryptorResult<u64> {
        let mc = new_magic_crypt!(secret, 256);
        let mut written = 0;
        if chunk_size < 16 {
            return Err(EncryptorError::InvalidChunkSize {
                got: chunk_size as usize,
                min: 16,
            });
        }

        let mut buf = Vec::with_capacity(chunk_size as usize + 16); // Tag size
        while source.take(chunk_size + 16).read_to_end(&mut buf)? == chunk_size as usize + 16 {
            let encrypted = mc.decrypt_bytes_to_bytes(&buf)?;
            destination.write_all(&encrypted)?;
            written += encrypted.len();
            buf.clear();
        }
        if !buf.is_empty() {
            let encrypted = mc.decrypt_bytes_to_bytes(&buf)?;
            destination.write_all(&encrypted)?;
            written += encrypted.len();
            buf.clear();
        }
        written.try_into().map_err(
            |e: std::num::TryFromIntError| EncryptorError::ConversionError {
                from: "usize".to_string(),
                to: "u64".to_string(),
                error: e.to_string(),
            },
        )
    }
}

impl TenacityMiddlewareStream for V1Encryptor {}
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::security::middleware::traits::TenacityMiddleware;
//     use rand::Rng;
//     #[tokio::test]
//     async fn test_encrypt_decrypt() -> anyhow::Result<()> {
//         let mut rng = rand::thread_rng();

//         for _ in 0..10_000 {
//             // Run 100 iterations
//             let id = Uuid::new_v4();

//             // Generate a random body
//             let body_length = rng.gen_range(1..2024); // Random length between 1 and 99
//             let body = Alphanumeric.sample_string(&mut rng, body_length);

//             let encrypted = V1Encryptor.encrypt(id, &body).await?;
//             let decrypted = V1Encryptor.decrypt(id, &encrypted).await?;

//             assert_eq!(
//                 body,
//                 decrypted.as_str(),
//                 "Decrypted body does not match original"
//             );

//             // Check that encrypted and decrypted bodies are different
//             assert_ne!(body, encrypted.as_str(), "Encrypted body matches original");
//         }

//         println!("All operations worked successfully");
//         Ok(())
//     }

//     #[test]
//     fn test_uuid_asref() -> anyhow::Result<()> {
//         for _ in 0..1024 {
//             let id = Uuid::new_v4();
//             let id_res = Uuid::from_slice(id.as_ref())?;
//             assert_eq!(id, id_res);
//         }

//         Ok(())
//     }

//     #[tokio::test]
//     async fn test_header_encryption() -> anyhow::Result<()> {
//         for _ in 0..100_000 {
//             let id = Uuid::new_v4();
//             let encrypted = V1Encryptor.encrypt_header(id).await?;
//             let decrypted = V1Encryptor.decrypt_header(&encrypted).await?;
//             assert_ne!(id.as_simple().to_string(), encrypted);
//             assert_eq!(id, decrypted);
//         }

//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use std::fs::{read_to_string, File};
    use std::io::Read;

    use super::*;

    #[test]
    fn test_base_encrypt() {
        let bytes = Bytes::from("Hello World");
        let encrypted = V1Encryptor.base_encrypt_bytes(&bytes.clone());

        let decrypted = V1Encryptor.base_decrypt_bytes(&encrypted.unwrap());
        assert_eq!(bytes, decrypted.unwrap());
    }

    #[test]
    fn test_large_file_stream() {
        // Test with a large file (like cargo.lock)
        let file_path = "tests/Cargo.lock";
        let mut file = File::open(file_path).unwrap();

        // Create a temporary file to write the encrypted data
        let temp_file = "tests/encrypted.chipa";
        let mut writer = File::create(temp_file).unwrap();

        // Encrypt the file
        let id = [0; 16]; // Dummy ID for testing
        let encryptor = V1Encryptor;
        let result = encryptor
            .encrypt_bytes_stream(
                &id,
                &mut file,
                &mut writer,
                1024, // Use a chunk size of 1KB
            )
            .unwrap();
        dbg!(result);
        // Now decrypt the file
        let decrypted_path = "tests/decrypted.txt";
        let mut decrypted_file = File::create(decrypted_path).unwrap();

        let decryptor = V1Encryptor;
        let decrypt_result = decryptor
            .decrypt_bytes_stream(
                &id,
                &mut File::open(temp_file).unwrap(),
                &mut decrypted_file,
                1024, // Use the same chunk size
            )
            .inspect_err(|e| println!("{}", e))
            .unwrap();
        dbg!(decrypt_result);
        // Verify the decrypted content
        // decrypted_file.read_to_string(&mut actual_content).unwrap();
        let actual_content = read_to_string(decrypted_path).unwrap();
        let expected_content = read_to_string(file_path).unwrap();
        assert_eq!(actual_content.trim_end(), expected_content.trim_end());
    }

    #[test]
    fn test_small_file_stream() -> Result<(), anyhow::Error> {
        // Test with a small file
        let file_path = "README.md";
        let mut file = File::open(file_path)?;

        // Create a temporary file to write the encrypted data
        let temp_file = format!("temp_{}.tmp", file_path);
        let mut writer = File::create(&temp_file)?;

        // Encrypt the file
        let id = [0; 16]; // Dummy ID for testing
        let encryptor = V1Encryptor;
        let result = encryptor.encrypt_bytes_stream(
            &id,
            &mut file,
            &mut writer,
            1024, // Use a chunk size of 1KB
        )?;
        dbg!(result);
        // Now decrypt the file
        let mut decrypted_file = File::create(format!("decrypted_{}", temp_file))?;

        let decryptor = V1Encryptor;
        let decrypt_result = decryptor.decrypt_bytes_stream(
            &id,
            &mut File::open(temp_file)?,
            &mut decrypted_file,
            1024, // Use the same chunk size
        )?;
        dbg!(decrypt_result);
        // Verify the decrypted content
        let mut actual_content = String::new();
        decrypted_file.read_to_string(&mut actual_content)?;
        let expected_content = read_to_string(file_path)?;
        assert_eq!(actual_content.trim_end(), expected_content.trim_end());
        Ok(())
    }
}
