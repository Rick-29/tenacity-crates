pub mod traits;
pub mod versions;

use core::{fmt, str};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use traits::{TenacityEncryptor, TenacityMiddlewareStream, VersionTrait};
use versions::{V1Encryptor, V2Encryptor};

#[cfg(not(feature = "wasm"))]
use utoipa::ToSchema;

use super::TenacityMiddleware;

#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(tag = "type")]
pub enum Version {
    #[default]
    V1,
    V2(V2Encryptor),
}

impl Version {
    pub fn encryptor(&self) -> impl TenacityEncryptor + TenacityMiddlewareStream  {
        match self {
            Self::V1 => V1Encryptor,
            _ => V1Encryptor // TODO: fix, this it's very badly written
            // Self::V2(v2) => Box::new(v2.clone())
        }
    }
}

impl VersionTrait for Version {
    fn base_decrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes> {
        match self {
            Self::V1 => V1Encryptor.base_decrypt_bytes(bytes),
            Self::V2(v2) => v2.base_decrypt_bytes(bytes),
        }
    }

    fn base_encrypt_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> anyhow::Result<Bytes> {
        match self {
            Self::V1 => V1Encryptor.base_encrypt_bytes(bytes),
            Self::V2(v2) => v2.base_encrypt_bytes(bytes),

        }
    }
}

impl TryFrom<u16> for Version {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::V1),
            2 => Ok(Version::V2(V2Encryptor::new_static())),
            _ => Err(anyhow!("Could parse u16 to Version")),
        }
    }
}

impl From<Version> for u16 {
    fn from(value: Version) -> Self {
        match value {
            Version::V1 => 1,
            Version::V2(_) => 2
        }
    }
}

impl TryFrom<&[u8]> for Version {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value_str = str::from_utf8(value).map_err(anyhow::Error::from)?;
        Self::try_from(value_str)
    }
}

impl TryFrom<&str> for Version {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2(V2Encryptor::new_static())),
            _ => Err(anyhow!("Could parse str to Version")),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "V1"),
            Self::V2(v2) => write!(f, "V2({:?})", v2)
        }
    }
}

#[async_trait]
impl TenacityMiddleware for Version {
    async fn encrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send,
    {
        match self {
            Self::V1 => V1Encryptor.encrypt_str(secret, data).await,
            Self::V2(v2) => v2.encrypt_str(secret, data).await,
        }
    }

    async fn decrypt_str<P>(&self, secret: P, data: &str) -> anyhow::Result<String>
    where
        P: AsRef<[u8]> + Send,
    {
        match self {
            Self::V1 => V1Encryptor.decrypt_str(secret, data).await,
            Self::V2(v2) => v2.decrypt_str(secret, data).await,
        }
    }

    fn encrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        match self {
            Self::V1 => V1Encryptor.encrypt_bytes(secret, data),
            Self::V2(v2) => v2.encrypt_bytes(secret, data),
        }    
    }

    fn decrypt_bytes<T, P>(&self, secret: P, data: &T) -> anyhow::Result<Bytes>
    where
        T: ?Sized + AsRef<[u8]>,
        P: AsRef<[u8]> + Send,
    {
        match self {
            Self::V1 => V1Encryptor.decrypt_bytes(secret, data),
            Self::V2(v2) => v2.decrypt_bytes(secret, data),
        }    
    }
}

impl TenacityMiddlewareStream for Version {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() -> anyhow::Result<()> {
        let version = "v1";
        let version1 = "V1";
        let v = Version::try_from(version)?;
        let v1 = Version::try_from(version1)?;

        let v2 = Version::try_from(version.as_bytes())?;
        let v3 = Version::try_from(version1.as_bytes())?;

        assert_eq!(v, Version::V1);
        assert_eq!(v1, Version::V1);
        assert_eq!(v2, Version::V1);
        assert_eq!(v3, Version::V1);

        Ok(())
    }
}
