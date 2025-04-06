use serde::{Deserialize, Serialize};

#[cfg(not(feature = "wasm"))]
use utoipa::ToSchema;
use uuid::Uuid;

use super::general::{Application, Level, ServerFileDownloadFormat, SubscriptionKind, UserInfo};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct JsonUserWrapper {
    #[serde(flatten)]
    pub info: UserInfo,
    pub subscription: Option<(SubscriptionKind, Application)>,
    pub level: Option<Level>,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct JsonSubscriptionWrapper {
    pub kind: SubscriptionKind,
    pub app: Application,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(not(feature = "wasm"), derive(ToSchema))]
pub struct JsonFileWrapper {
    pub file: String,
    pub owner: Option<Uuid>,
    pub name: Option<String>,
    pub level: Option<Level>,
    pub download: Option<ServerFileDownloadFormat>,
}
