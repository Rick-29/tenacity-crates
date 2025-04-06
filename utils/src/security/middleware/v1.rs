use core::str;
use std::str::FromStr;

use bytes::Bytes;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::distr::{Alphanumeric, SampleString};
use uuid::Uuid;

use crate::security::seed::{base_generator, generate_uuid, get_generator};

use super::traits::{TenacityEncryptor, TenacityMiddleware, TenacityMiddlewareStream};

const SECRET_LENGTH: usize = 128;

#[derive(Clone, Copy, Default)]
pub struct V1Encryptor;

#[async_trait::async_trait]
impl TenacityMiddleware for V1Encryptor {
    fn get_secret(&self, id: Uuid) -> anyhow::Result<String> {
        let mut rng = get_generator(id);

        Ok(Alphanumeric.sample_string(&mut rng, SECRET_LENGTH))
    }

    async fn encrypt_str(&self, secret: &str, data: &str) -> anyhow::Result<String> {
        let mc = new_magic_crypt!(secret, 256);
        Ok(mc.encrypt_str_to_base64(data))
    }

    async fn decrypt_str(&self, secret: &str, data: &str) -> anyhow::Result<String> {
        let mc = new_magic_crypt!(secret, 256);
        mc.decrypt_base64_to_string(data)
            .map_err(|e| anyhow::anyhow!("Error decoding base64 body, {e}"))
    }

    async fn encrypt_header(&self, data: Uuid) -> anyhow::Result<String> {
        let mut rng = self.generator()?;
        let id = data.simple().to_string();

        let secret = Alphanumeric.sample_string(&mut rng, 32);
        let mc = new_magic_crypt!(secret, 256);
        Ok(mc.encrypt_str_to_base64(id))
    }
    async fn decrypt_header(&self, data: &str) -> anyhow::Result<Uuid> {
        let mut rng = self.generator()?;
        let secret = Alphanumeric.sample_string(&mut rng, 32);
        let mc = new_magic_crypt!(secret, 256);
        let id = mc.decrypt_base64_to_string(data)?;
        Uuid::from_str(&id).map_err(anyhow::Error::from)
    }

    fn encrypt_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        secret: &str,
        data: &T,
    ) -> anyhow::Result<Bytes> {
        let mc: magic_crypt::MagicCrypt256 = new_magic_crypt!(secret, 256);
        let bytes = Bytes::from(mc.encrypt_bytes_to_bytes(data));
        Ok(bytes)
    }
    fn decrypt_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        secret: &str,
        data: &T,
    ) -> anyhow::Result<Bytes> {
        let mc = new_magic_crypt!(secret, 256);
        mc.decrypt_bytes_to_bytes(data)
            .map_err(anyhow::Error::from)
            .map(Bytes::from)
    }
}

impl TenacityEncryptor for V1Encryptor {
    fn advanced_generator(&self, id: impl AsRef<[u8]>) -> anyhow::Result<impl rand::Rng> {
        Ok(get_generator(Uuid::from_slice(id.as_ref())?))
    }

    fn generator(&self) -> anyhow::Result<impl rand::Rng> {
        Ok(base_generator())
    }

    fn generate_temporal_id(&self) -> anyhow::Result<Uuid> {
        generate_uuid()
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
