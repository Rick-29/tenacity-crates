use anyhow::anyhow;
use bincode::config;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(not(feature = "wasm"))]
use utoipa::ToSchema;

use crate::security::Version;

use core::fmt;
use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::helper::to_id;

#[derive(Debug, Clone, Deserialize)]
pub struct UserUtils {
    pub info: UserInfo,
    pub license: License,
    pub subscriptions: HashSet<SubscriptionUtils>,
    pub level: Level,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct License {
    #[serde(
        serialize_with = "serialize_uuid",
        deserialize_with = "deserialize_uuid"
    )]
    pub license_id: Uuid,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct SubscriptionUtils {
    pub kind: SubscriptionKind,
    pub started_at: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub app: Application,
    #[serde(
        serialize_with = "serialize_uuid",
        deserialize_with = "deserialize_uuid"
    )]
    pub subscription_id: Uuid,
    pub token: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub enum SubscriptionKind {
    Lifetime,
    Yearly,
    Semester,
    Trimester,
    Monthly,
    #[default]
    Weekly,
    Custom(Duration),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub enum Application {
    #[default]
    None,
    Any(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub enum Level {
    #[default]
    None,
    Basic,
    Pro,
    Vip,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
// #[serde(untagged)]
pub enum UserInfo {
    Discord(DiscordUser),
    Basic(BasicUser),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct DiscordUser {
    pub discord_id: u64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub avatar_url: String,
    pub color: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct BaseDiscordUser {
    pub discord_id: u64,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct BasicUser {
    pub mail: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub enum ServerFileDownloadFormat {
    #[default]
    Download, // Add tag to automatically download file
    Secure(Version),  // Encrypt each chunk of bytes automatically
    Web,              // Add tag to display the file inline
    SubscriptionOnly, // The ServerFile only represents a subscription, it has no data
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct ApiError {
    pub error: String,
}

impl ServerFileDownloadFormat {
    pub fn header(&self) -> String {
        match self {
            Self::Download => "attachement".to_string(),
            Self::Web => "inline".to_string(),
            Self::Secure(_) => "attachement".to_string(),
            Self::SubscriptionOnly => "inline".to_string(),
        }
    }

    pub fn full_header(&self, name: Option<&str>, file_name: Option<&str>) -> String {
        let mut base = self.header();
        if let Some(f_name) = file_name {
            base.push_str(&format!("; filename*=\"{f_name}\"; filename=\"{f_name}\""));
        }
        if let Some(name) = name {
            base.push_str(&format!("; name=\"{name}\""));
        }
        base
    }
}

impl DiscordUser {
    fn to_basic(&self) -> BaseDiscordUser {
        BaseDiscordUser {
            discord_id: self.discord_id,
            name: self.name.clone(),
            created_at: self.created_at,
        }
    }
}

impl UserInfo {
    pub fn name(&self) -> &str {
        match self {
            Self::Basic(basic) => &basic.name,
            Self::Discord(discord) => &discord.name,
        }
    }

    pub fn from_parts(parts: (u64, String, DateTime<Utc>, String, u32)) -> Self {
        Self::Discord(DiscordUser {
            discord_id: parts.0,
            name: parts.1,
            created_at: parts.2,
            avatar_url: parts.3,
            color: parts.4,
        })
    }

    pub fn id(&self) -> anyhow::Result<Uuid> {
        let bytes = self.to_bytes()?;
        Ok(to_id(bytes.as_slice()))
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Basic(base) => {
                bincode::serde::encode_to_vec(base, config::standard()).map_err(anyhow::Error::from)
            }
            Self::Discord(discord) => {
                bincode::serde::encode_to_vec(discord.to_basic(), config::standard())
                    .map_err(anyhow::Error::from)
            }
        }
    }
}

impl From<String> for Application {
    fn from(s: String) -> Self {
        match s.as_ref() {
            "None" => Application::None,
            _ => Application::Any(s.to_string()),
        }
    }
}

impl fmt::Display for Application {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Any(name) => write!(f, "{name}"),
            // _ => write!(f, "Unknown Application"),
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for ApiError {}

impl TryFrom<String> for SubscriptionKind {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_ref() {
            "Lifetime" => Ok(SubscriptionKind::Lifetime),
            "Monthly" => Ok(SubscriptionKind::Monthly),
            "Trimester" => Ok(SubscriptionKind::Trimester),
            "Semester" => Ok(SubscriptionKind::Semester),
            "Yearly" => Ok(SubscriptionKind::Yearly),
            "Weekly" => Ok(SubscriptionKind::Weekly),
            _ if value.starts_with('C') => Ok(SubscriptionKind::Custom(
                value
                    .trim_start_matches('C')
                    .parse::<i64>()
                    .map(Duration::seconds)?,
            )),
            _ => Err(anyhow!("Couldn't parse into a subscription")),
        }
    }
}

impl fmt::Display for SubscriptionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lifetime => write!(f, "Lifetime"),
            Self::Yearly => write!(f, "Yearly"),
            Self::Semester => write!(f, "Semester"),
            Self::Trimester => write!(f, "Trimester"),
            Self::Monthly => write!(f, "Monthly"),
            Self::Weekly => write!(f, "Weekly"),
            Self::Custom(time_delta) => write!(f, "C{}", time_delta.num_seconds()),
        }
    }
}

impl Application {
    pub fn level(&self) -> Level {
        match self {
            Self::Any(_) => Level::None,
            Self::None => Level::None,
        }
    }

    pub fn id(&self) -> Uuid {
        match self {
            Self::None => to_id(b"None"),
            Self::Any(any) => to_id(any.as_bytes()),
        }
    }
}

impl<'de> Deserialize<'de> for Application {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Application::from(s))
    }
}

impl Serialize for Application {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SubscriptionKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SubscriptionKind::try_from(s).map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl Serialize for SubscriptionKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl SubscriptionKind {
    pub fn expiration(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Yearly => Some(Utc::now() + self.time().unwrap_or_default()),
            Self::Semester => Some(Utc::now() + self.time().unwrap_or_default()),
            Self::Trimester => Some(Utc::now() + self.time().unwrap_or_default()),
            Self::Monthly => Some(Utc::now() + self.time().unwrap_or_default()),
            Self::Weekly => Some(Utc::now() + self.time().unwrap_or_default()),
            Self::Custom(_) => Some(Utc::now() + self.time().unwrap_or_default()),
            Self::Lifetime => None,
        }
    }

    pub fn time(&self) -> Option<Duration> {
        match self {
            Self::Lifetime => None,
            Self::Yearly => Some(Duration::days(365)),
            Self::Semester => Some(Duration::days(173)),
            Self::Trimester => Some(Duration::days(92)),
            Self::Monthly => Some(Duration::days(31)),
            Self::Weekly => Some(Duration::days(7)),
            Self::Custom(time) => Some(time.to_owned()),
        }
    }
}

fn serialize_uuid<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&uuid.to_string())
}

pub fn deserialize_uuid<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Uuid::parse_str(&s).map_err(serde::de::Error::custom)
}
