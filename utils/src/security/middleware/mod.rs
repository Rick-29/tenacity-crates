pub mod traits;
pub mod v1;

use core::{fmt, str};

use anyhow::anyhow;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use traits::{TenacityEncryptor, TenacityMiddlewareStream, VersionTrait};
use v1::V1Encryptor;

#[cfg(not(feature = "wasm"))]
use utoipa::ToSchema;

#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum Version {
    #[default]
    V1,
}

impl Version {
    pub fn encryptor(&self) -> impl TenacityEncryptor + TenacityMiddlewareStream {
        match self {
            Self::V1 => V1Encryptor,
        }
    }
}

impl VersionTrait for Version {
    fn base_decrypt_bytes(&self, bytes: impl Into<Bytes>) -> anyhow::Result<Bytes> {
        match self {
            Self::V1 => V1Encryptor.base_decrypt_bytes(bytes),
        }
    }

    fn base_encrypt_bytes(&self, bytes: impl Into<Bytes>) -> anyhow::Result<Bytes> {
        match self {
            Self::V1 => V1Encryptor.base_encrypt_bytes(bytes),
        }
    }
}

impl TryFrom<u16> for Version {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Version::V1),
            _ => Err(anyhow!("Could parse u16 to Version")),
        }
        
    }
}

impl From<Version> for u16 {
    fn from(value: Version) -> Self {
        match value {
            Version::V1 => 1,
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
            _ => Err(anyhow!("Could parse str to Version")),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "V1"),
        }
    }
}

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
