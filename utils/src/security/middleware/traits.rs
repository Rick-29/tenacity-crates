#[cfg(feature = "security")]
use axum::{body::Body, extract::Request, http::HeaderValue, response::Response};
use core::str;
use std::io::{Read, Write};
use std::str::FromStr;

use bytes::Bytes;
#[cfg(feature = "security")]
use hyper::header::CONTENT_LENGTH;

use futures_util::stream::StreamExt;
use futures_util::Stream;

use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use rand::distr::{Alphanumeric, SampleString};
use uuid::Uuid;

use crate::security::get_generator;
use crate::security::middleware::versions::EncryptorResult;
use crate::security::seed::{base_generator, generate_uuid};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

const SECRET_LENGTH: usize = 128;

#[async_trait::async_trait]
pub trait TenacityMiddleware: Clone + Copy + Send + Sync {
    fn get_secret(&self, id: Uuid) -> anyhow::Result<String> {
        let mut rng = get_generator(id);

        Ok(Alphanumeric.sample_string(&mut rng, SECRET_LENGTH))
    }
    async fn encrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send;

    async fn decrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send;

    async fn encrypt_header(&self, data: Uuid) -> anyhow::Result<String> {
        let mut rng = base_generator();
        let id = data.simple().to_string();

        let secret = Alphanumeric.sample_string(&mut rng, 32);
        let mc = new_magic_crypt!(secret, 256);
        Ok(mc.encrypt_str_to_base64(id))
    }
    async fn decrypt_header(&self, data: &str) -> anyhow::Result<Uuid> {
        let mut rng = base_generator();
        let secret = Alphanumeric.sample_string(&mut rng, 32);
        let mc = new_magic_crypt!(secret, 256);
        let id = mc.decrypt_base64_to_string(data)?;
        Uuid::from_str(&id).map_err(anyhow::Error::from)
    }

    fn encrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send;
    fn decrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send;

    async fn encrypt(&self, id: Uuid, data: &str) -> anyhow::Result<String> {
        let secret = self.get_secret(id)?;
        self.encrypt_str(&secret, data).await
    }

    async fn decrypt(&self, id: Uuid, data: &str) -> anyhow::Result<String> {
        let secret = self.get_secret(id)?;
        self.decrypt_str(&secret, data).await
    }

    #[cfg(feature = "security")]
    async fn encrypt_response(&self, id: Uuid, response: Response) -> anyhow::Result<Response> {
        let (mut parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;
        let body_str = str::from_utf8(&body_bytes)?;
        let encrypted_body = self.encrypt(id, body_str).await?;

        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(encrypted_body.len()));

        let body = Body::from(encrypted_body);

        let response = Response::from_parts(parts, body);

        Ok(response)
    }

    #[cfg(feature = "security")]
    async fn decrypt_request(&self, id: Uuid, request: Request) -> anyhow::Result<Request> {
        let (mut parts, body) = request.into_parts();

        let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;
        let body_str = str::from_utf8(&body_bytes)?;
        let decrypted_body = self.decrypt(id, body_str).await?;

        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from(decrypted_body.len()));

        let body = Body::from(decrypted_body);
        let request = Request::from_parts(parts, body);
        Ok(request)
    }
}

pub trait TenacityMiddlewareStream: TenacityMiddleware {
    // type Middleware: TenacityMiddleware + Default;

    fn encrypt_stream<O, E>(
        &self,
        id: Uuid,
        stream: impl Stream<Item = Result<O, E>>,
    ) -> anyhow::Result<impl Stream<Item = Result<Bytes, BoxError>>>
    where
        O: Into<Bytes>,
        E: Into<BoxError>,
    {
        let secret = self.get_secret(id)?;
        Ok(stream.then(move |item| {
            let value = secret.clone();
            async move {
                let inner = value.clone();
                match item {
                    Ok(bytes) => self
                        .encrypt_bytes(&inner, &bytes.into())
                        .map_err(BoxError::from),
                    Err(e) => Err(e.into()),
                }
            }
        }))
    }

    fn decrypt_stream<O, E>(
        &self,
        id: Uuid,
        stream: impl Stream<Item = Result<O, E>>,
    ) -> anyhow::Result<impl Stream<Item = Result<Bytes, BoxError>>>
    where
        O: Into<Bytes>,
        E: Into<BoxError>,
    {
        let secret = self.get_secret(id)?;
        Ok(stream.then(move |item| {
            let value = secret.clone();
            async move {
                let inner = value.clone();
                match item {
                    Ok(bytes) => self
                        .decrypt_bytes(inner.as_bytes(), &bytes.into())
                        .map_err(BoxError::from),
                    Err(e) => Err(e.into()),
                }
            }
        }))
    }
}

/// A trait for types that can be serialized and deserialized as part of an encryptor's configuration.
pub trait ConfigurableEncryptor: Sized {
    type Error;

    /// The size of the configuration in bytes, used for serialization.
    fn size(&self) -> usize;

    /// Creates an instance of the encryptor from a byte slice.
    ///
    /// This function reads `CONFIG_SIZE` bytes from the start of the slice,
    /// uses them to construct `Self`, and advances the slice past the bytes read.
    ///
    /// # Parameters
    /// - `bytes`: A mutable reference to a byte slice. The slice will be advanced
    ///           by `CONFIG_SIZE` upon success.
    ///
    /// # Returns
    /// A `Result` containing a new instance of `Self` on success, or an `EncryptorError`.
    #[allow(clippy::wrong_self_convention)]
    fn from_bytes(self, bytes: &mut &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Creates an instance of the encryptor from a readable stream.
    ///
    /// This function reads exactly `CONFIG_SIZE` bytes from the stream to construct `Self`.
    ///
    /// # Parameters
    /// - `source`: A mutable reference to a readable input stream.
    ///
    /// # Returns
    /// A `Result` containing a new instance of `Self` on success, or an `EncryptorError`.
    #[allow(clippy::wrong_self_convention)]
    fn from_stream<R: Read>(self, source: &mut R) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Serializes the encryptor's configuration into bytes.
    ///
    /// The returned bytes should be exactly `CONFIG_SIZE` in length and are suitable
    /// for prepending to a ciphertext stream.
    ///
    /// # Returns
    /// A `Bytes` object containing the serialized configuration.
    fn to_bytes(&self) -> Bytes;
}
/// Defines a contract for versioned encryption and decryption operations.
///
/// This trait provides methods for transforming byte data, either as complete
/// in-memory buffers or as streams. It supports two main modes of operation:
///
/// 1.  **Secret-based encryption/decryption:** Uses a user-provided secret (e.g., a password)
///     for cryptographic operations.
/// 2.  **Base encryption/decryption:** Implements a form of basic code obfuscation
///     or a default, fixed encryption mechanism that does not require a dynamic user secret.
///
/// Implementors of this trait are expected to handle the specifics of the
/// cryptographic algorithms for a particular "version" or configuration.
pub trait VersionTrait: Default + ConfigurableEncryptor {
    // /// The size in bytes required to serialize this encryptor's configuration.
    // /// This is the exact number of bytes that will be read by `from_bytes` or `from_stream`.
    // const CONFIG_SIZE: usize = 0;

    /// The default key used by the base encryption/decryption methods.
    const DEFAULT_KEY: &'static [u8];

    /// Default chunk size for stream-based operations, in bytes.
    const CHUNK_SIZE: usize = 1024; // 1 KiB

    /// Encrypts a slice of bytes using a provided secret.
    ///
    /// # Parameters
    /// - `secret`: The secret (e.g., password) to use for encryption. Must be `Send`
    ///             as it might be used in a concurrent context by the implementor.
    /// - `bytes`: The plaintext byte data to encrypt. This accepts any type that
    ///            can be referenced as a byte slice (e.g., `&[u8]`, `Vec<u8>`, `String`).
    ///
    /// # Returns
    /// A `Result` containing the encrypted data as `Bytes` on success,
    /// or an `EncryptorError` on failure.
    fn encrypt_bytes<P: AsRef<[u8]> + Send, T: ?Sized + AsRef<[u8]>>(
        &self,
        secret: &P,
        bytes: &T,
    ) -> EncryptorResult<Bytes>;

    /// Decrypts a slice of bytes using a provided secret.
    ///
    /// # Parameters
    /// - `secret`: The secret (e.g., password) used for encryption. Must be `Send`.
    /// - `bytes`: The ciphertext byte data to decrypt.
    ///
    /// # Returns
    /// A `Result` containing the decrypted (plaintext) data as `Bytes` on success,
    /// or an `EncryptorError` on failure (e.g., incorrect secret, corrupted data).
    fn decrypt_bytes<P: AsRef<[u8]> + Send, T: ?Sized + AsRef<[u8]>>(
        &self,
        secret: &P,
        bytes: &T,
    ) -> EncryptorResult<Bytes>;

    /// Encrypts data from a source stream and writes the encrypted output to a destination stream,
    /// using a provided secret.
    ///
    /// The source stream must implement `Read` and `Seek`. `Seek` might be used by
    /// the underlying encryption algorithm or to determine stream length.
    ///
    /// # Parameters
    /// - `secret`: The secret (e.g., password) for encryption. Must be `Send`.
    /// - `source`: A mutable reference to the readable and seekable input stream providing plaintext data.
    /// - `destination`: A mutable reference to the writable output stream for the ciphertext.
    /// - `chunk_size`: The size of each chunk to read from the source stream, in bytes. If `0`, the default chunk size is used.
    ///
    /// # Returns
    /// A `Result` containing the total number of bytes written to the `destination` stream on success,
    /// or an `EncryptorError` on failure.
    fn encrypt_bytes_stream<R: Read, W: Write, P: AsRef<[u8]> + Send>(
        &self,
        secret: &P,
        source: &mut R,
        destination: &mut W,
        chunck_size: u64,
    ) -> EncryptorResult<u64>;

    /// Decrypts data from a source stream and writes the decrypted output to a destination stream,
    /// using a provided secret.
    ///
    /// The source stream must implement `Read` and `Seek`.
    ///
    /// # Parameters
    /// - `secret`: The secret (e.g., password) used for decryption. Must be `Send`.
    /// - `source`: A mutable reference to the readable and seekable input stream providing ciphertext data.
    /// - `destination`: A mutable reference to the writable output stream for the plaintext.
    /// - `chunk_size`: The size of each chunk to read from the source stream, in bytes. If `0`, the default chunk size is used.
    ///
    /// # Returns
    /// A `Result` containing the total number of bytes written to the `destination` stream on success,
    /// or an `EncryptorError` on failure.
    fn decrypt_bytes_stream<R: Read, W: Write, P: AsRef<[u8]> + Send>(
        &self,
        secret: &P,
        source: &mut R,
        destination: &mut W,
        chunck_size: u64,
    ) -> EncryptorResult<u64>;

    /// Decrypts a slice of bytes using a base (e.g., fixed or internal)
    /// obfuscation/decryption mechanism.
    ///
    /// This method is intended for scenarios where a user-provided secret is not used,
    /// relying instead on a predefined transformation for basic obfuscation or a default key.
    ///
    /// # Parameters
    /// - `bytes`: The obfuscated/encrypted byte data to decrypt.
    ///
    /// # Returns
    /// A `Result` containing the de-obfuscated (plaintext) data as `Bytes` on success,
    /// or an `EncryptorError` on failure.
    fn base_decrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> EncryptorResult<Bytes> {
        self.decrypt_bytes(&Self::DEFAULT_KEY, bytes)
    }

    /// Encrypts/obfuscates a slice of bytes using a base (e.g., fixed or internal)
    /// obfuscation/encryption mechanism.
    ///
    /// This method does not require a user-provided secret and is suitable for
    /// basic code obfuscation or default encryption tasks.
    ///
    /// # Parameters
    /// - `bytes`: The plaintext byte data to encrypt/obfuscate.
    ///
    /// # Returns
    /// A `Result` containing the obfuscated (encrypted) data as `Bytes` on success,
    /// or an `EncryptorError` on failure.
    fn base_encrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> EncryptorResult<Bytes> {
        self.encrypt_bytes(&Self::DEFAULT_KEY, bytes)
    }

    /// Encrypts/obfuscates data from a source stream to a destination stream
    /// using a base (e.g., fixed or internal) mechanism.
    ///
    /// This stream-based version is for basic obfuscation without a user-provided secret.
    /// The source stream must implement `Read` and `Seek`.
    ///
    /// # Parameters
    /// - `source`: A mutable reference to the readable and seekable input stream.
    /// - `destination`: A mutable reference to the writable output stream.
    /// - `chunk_size`: The size of each chunk to read from the source stream, in bytes. If `0`, the default chunk size is used.
    ///
    /// # Returns
    /// A `Result` containing the total number of bytes written to the `destination` stream on success,
    /// or an `EncryptorError` on failure.
    fn base_encrypt_bytes_stream<R: Read, W: Write>(
        &self,
        source: &mut R,
        destination: &mut W,
        chunck_size: u64,
    ) -> EncryptorResult<u64> {
        self.encrypt_bytes_stream(&Self::DEFAULT_KEY, source, destination, chunck_size)
    }

    /// Decrypts/de-obfuscates data from a source stream to a destination stream
    /// using a base (e.g., fixed or internal) mechanism.
    ///
    /// This stream-based version is for de-obfuscating data that was processed
    /// using the `base_encrypt_bytes_stream` or `base_encrypt_bytes` methods.
    /// The source stream must implement `Read` and `Seek`.
    ///
    /// # Parameters
    /// - `source`: A mutable reference to the readable and seekable input stream providing obfuscated data.
    /// - `destination`: A mutable reference to the writable output stream for de-obfuscated data.
    /// - `chunk_size`: The size of each chunk to read from the source stream, in bytes. If `0`, the default chunk size is used.
    ///
    /// # Returns
    /// A `Result` containing the total number of bytes written to the `destination` stream on success,
    /// or an `EncryptorError` on failure.
    fn base_decrypt_bytes_stream<R: Read, W: Write>(
        &self,
        source: &mut R,
        destination: &mut W,
        chunck_size: u64,
    ) -> EncryptorResult<u64> {
        self.decrypt_bytes_stream(&Self::DEFAULT_KEY, source, destination, chunck_size)
    }
}

pub trait TenacityEncryptor: Clone + Copy {
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

#[cfg(test)]
mod tests {

    use core::pin::pin;

    use super::*;
    use crate::security::middleware::Version;
    use reqwest::get;
    use tokio::io::AsyncReadExt;
    use tokio_util::io::ReaderStream;

    #[tokio::test]
    #[ignore]
    async fn test_stream() -> anyhow::Result<()> {
        let file = tokio::fs::File::open("Config.toml").await?;
        let stream = ReaderStream::new(file);

        let mut original_file = tokio::fs::File::open("Config.toml").await?;
        let mut original_bytes = Vec::new();
        original_file.read_to_end(&mut original_bytes).await?;
        let encryptor = Version::V1.encryptor();
        let id = uuid::Uuid::new_v4();
        let encrypted_stream = encryptor.encrypt_stream(id, stream)?;
        let encryptor = Version::V1.encryptor();
        let mut file_buffer = Vec::new();
        let mut decrypted_stream = pin!(encryptor.decrypt_stream(id, encrypted_stream)?);
        while let Some(item) = decrypted_stream.next().await {
            match item {
                Ok(bytes) => file_buffer.extend(bytes.to_vec()),
                Err(e) => panic!("Error, {e}"),
            }
        }
        assert_eq!(file_buffer, original_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn test_stream_reqwest() -> anyhow::Result<()> {
        let request = get("https://docs.rs/reqwest/latest/reqwest/struct.Response.html").await?;
        let original_bytes = get("https://docs.rs/reqwest/latest/reqwest/struct.Response.html")
            .await?
            .bytes()
            .await?
            .to_vec();

        let encryptor = Version::V1.encryptor();
        let id = uuid::Uuid::new_v4();
        let encrypted_stream = encryptor.encrypt_stream(id, request.bytes_stream())?;
        let encryptor = Version::V1.encryptor();
        let mut file_buffer = Vec::new();
        let mut decrypted_stream = pin!(encryptor.decrypt_stream(id, encrypted_stream)?);
        while let Some(item) = decrypted_stream.next().await {
            match item {
                Ok(bytes) => file_buffer.extend(bytes.to_vec()),
                Err(e) => panic!("Error, {e}"),
            }
        }
        assert_eq!(file_buffer, original_bytes);

        Ok(())
    }

    #[tokio::test]
    async fn test_encrypt_stream() -> anyhow::Result<()> {
        let request = get("https://docs.rs/reqwest/latest/reqwest/struct.Response.html").await?;
        let original_bytes = get("https://docs.rs/reqwest/latest/reqwest/struct.Response.html")
            .await?
            .bytes()
            .await?
            .to_vec();

        let encryptor = Version::V1.encryptor();
        let id = uuid::Uuid::new_v4();
        let mut encrypted_stream = pin!(encryptor.encrypt_stream(id, request.bytes_stream())?);
        // let encryptor = Version::V1.encryptor();
        // let mut decrypted_stream = pin!(encryptor.decrypt_stream(id, encrypted_stream)?);
        let mut file_buffer = Vec::new();
        while let Some(item) = encrypted_stream.next().await {
            match item {
                Ok(bytes) => file_buffer.extend(bytes.to_vec()),
                Err(e) => panic!("Error, {e}"),
            }
        }
        assert_ne!(file_buffer, original_bytes);

        Ok(())
    }
}
