use core::str;

#[cfg(feature = "security")]
use axum::{body::Body, extract::Request, http::HeaderValue, response::Response};

use bytes::Bytes;
#[cfg(feature = "security")]
use hyper::header::CONTENT_LENGTH;

use futures_util::stream::StreamExt;
use futures_util::Stream;

use rand::Rng;
use uuid::Uuid;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait::async_trait]
pub trait TenacityMiddleware: Clone + Copy + Send + Sync {
    fn get_secret(&self, id: Uuid) -> anyhow::Result<String>;

    async fn encrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send;
    async fn decrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send;

    async fn encrypt_header(&self, data: Uuid) -> anyhow::Result<String>;
    async fn decrypt_header(&self, data: &str) -> anyhow::Result<Uuid>;

    fn encrypt_bytes<T, P>(
        &self,
        secret: P,
        data: &T,
    ) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send;
    fn decrypt_bytes<T, P>(
        &self,
        secret: P,
        data: &T,
    ) -> anyhow::Result<Bytes>
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
                    Ok(bytes) => self.encrypt_bytes(&inner, &bytes.into())
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

pub trait VersionTrait {
    fn base_decrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes>;
    fn base_encrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes>;
}

pub trait TenacityEncryptor: Clone + Copy {
    fn generator(&self) -> anyhow::Result<impl Rng>;
    fn advanced_generator(&self, id: impl AsRef<[u8]>) -> anyhow::Result<impl Rng>;
    fn generate_temporal_id(&self) -> anyhow::Result<Uuid>;
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
