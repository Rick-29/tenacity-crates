use anyhow::anyhow;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher};
use serde::{Deserialize, Serialize};
use std::fs::{read_to_string, File};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error};

pub use notify::{RecursiveMode, Watcher};

pub mod notifications;
pub use crate::config::notifications::Load;

#[cfg(any(feature = "domains", feature = "license", feature = "api"))]
pub mod domains;
#[cfg(any(feature = "domains", feature = "license", feature = "api"))]
pub use crate::config::domains::{serialize_domains, Domains};

#[cfg(feature = "logging")]
pub mod logging;
#[cfg(feature = "logging")]
pub use crate::config::logging::LoggingConfig;

#[cfg(feature = "credentials")]
pub mod credentials;
#[cfg(feature = "credentials")]
pub use crate::config::credentials::Credentials;

#[cfg(feature = "emoji")]
pub mod emojis;
#[cfg(feature = "emoji")]
pub use crate::config::emojis::{Emoji, EmojiConfig};

#[cfg(feature = "db")]
pub mod db;
#[cfg(feature = "db")]
pub use crate::config::db::DbConfig;
#[cfg(feature = "db")]
pub use tenacity_db::TenacityDB;

#[cfg(all(feature = "models", feature = "handler"))]
use crate::ai_models::detector::Detector;
#[cfg(all(feature = "models", feature = "handler"))]
use burn::backend::NdArray;

#[cfg(feature = "handler")]
pub mod handler;
#[cfg(feature = "handler")]
pub use crate::config::handler::HandlerConfig;

#[cfg(all(feature = "models", feature = "handler", feature = "emoji"))]
use tokio::sync::Mutex as TokioMutex;

#[cfg(all(
    feature = "models",
    feature = "handler",
    feature = "emoji",
    feature = "db"
))]
pub type HandlerParts = (
    HandlerConfig,
    EmojiConfig,
    DbConfig,
    Option<Arc<TokioMutex<Detector<NdArray>>>>,
    Arc<TenacityDB>,
);

pub const CONFIG: &str = "Config.toml";

#[derive(Debug, Clone, Default)]
pub struct Config {
    inner: Arc<Mutex<InnerConfig>>,
    #[cfg(feature = "db")]
    db: Arc<TenacityDB>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct InnerConfig {
    #[cfg(any(feature = "domains", feature = "license", feature = "api"))]
    pub domains: Domains,

    #[cfg(feature = "credentials")]
    pub credentials: Credentials,

    #[cfg(feature = "emoji")]
    pub emojis: EmojiConfig,

    #[cfg(feature = "handler")]
    pub handler: HandlerConfig,
    #[cfg(all(feature = "handler", feature = "models"))]
    #[serde(skip)]
    pub detector: Option<Arc<TokioMutex<Detector<NdArray>>>>,
    #[cfg(feature = "logging")]
    pub logs: LoggingConfig,
    #[cfg(feature = "db")]
    pub db: DbConfig,
}

// Impls
impl InnerConfig {
    pub fn load() -> anyhow::Result<Self> {
        match read_to_string(CONFIG) {
            Ok(s) => toml::from_str(&s).map_err(|e| anyhow!(e)),
            Err(_) => {
                let config = Self::default();
                let mut f = File::create(CONFIG)?;
                f.write_all(toml::to_string(&config)?.as_bytes())?;
                Ok(config)
            }
        }
    }
}

impl Config {
    pub async fn load() -> anyhow::Result<Self> {
        let inner_config = InnerConfig::load()?;
        // #[cfg(feature = "db")]
        // let path = inner_config.db.schema.clone();
        Ok(Self {
            inner: Arc::new(Mutex::new(inner_config)),
            #[cfg(feature = "db")]
            db: Arc::new(TenacityDB::new_memory().await?),
        })
    }

    pub fn init(&self) -> anyhow::Result<RecommendedWatcher> {
        let config_clone = Arc::clone(&self.inner);
        // Spawn a separate task to monitor config file changes
        let watcher: RecommendedWatcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        match InnerConfig::load() {
                            Ok(config) => {
                                *config_clone.lock().unwrap() = config;
                                debug!(target: "Notify", "New configuration loaded, {:?}", config_clone);
                            }
                            Err(e) => error!(target: "Notify", "Error loading config, {}", e),
                        }
                    }
                }
                Err(e) => error!(target: "Notify", "Error processing notify event: {}", e),
            },
            NotifyConfig::default()
                .with_poll_interval(Duration::from_secs(2))
                .with_compare_contents(true),
        )?;

        Ok(watcher)
    }

    pub fn arc_clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            #[cfg(feature = "db")]
            db: Arc::clone(&self.db),
        }
    }

    #[cfg(feature = "handler")]
    pub fn handler(&self) -> anyhow::Result<HandlerConfig> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.handler.clone())
    }

    #[cfg(feature = "credentials")]
    pub fn credentials(&self) -> anyhow::Result<Credentials> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.credentials.clone())
    }

    #[cfg(feature = "emoji")]
    pub fn emojis(&self) -> anyhow::Result<EmojiConfig> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.emojis.clone())
    }

    #[cfg(any(feature = "domains", feature = "license", feature = "api"))]
    pub fn domains(&self) -> anyhow::Result<Domains> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.domains.clone())
    }

    #[cfg(all(feature = "handler", feature = "models"))]
    pub fn detector(&self) -> anyhow::Result<Option<Arc<TokioMutex<Detector<NdArray>>>>> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.detector.clone())
    }

    #[cfg(feature = "logging")]
    pub fn logs(&self) -> anyhow::Result<LoggingConfig> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.logs.clone())
    }

    #[cfg(all(feature = "handler", feature = "models"))]
    pub fn set_detector(&self, detector: Detector<NdArray>) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        inner.detector = Some(Arc::new(TokioMutex::new(detector)));
        Ok(())
    }

    #[cfg(all(
        feature = "handler",
        feature = "models",
        feature = "emoji",
        feature = "db"
    ))]
    pub fn to_handler_parts(&self) -> anyhow::Result<HandlerParts> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok((
            inner.handler.clone(),
            inner.emojis.clone(),
            inner.db.clone(),
            inner.detector.clone(),
            Arc::clone(&self.db),
        ))
    }

    #[cfg(any(feature = "domains", feature = "license", feature = "api"))]
    pub fn url<T: core::fmt::Display>(&self, endpoint: &T, domain: &str) -> anyhow::Result<String> {
        self.domains()?.url(endpoint, domain)
    }

    #[cfg(feature = "db")]
    pub fn db(&self) -> &TenacityDB {
        &self.db
    }

    #[cfg(feature = "db")]
    pub fn db_config(&self) -> anyhow::Result<DbConfig> {
        let inner = self.inner.lock().map_err(|e| anyhow!("Error, {e}"))?;
        Ok(inner.db.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    #[tokio::test]
    async fn test_config_load() -> anyhow::Result<()> {
        let config = Config::load().await?;
        dbg!(&config);
        Ok(())
    }

    #[tokio::test]
    async fn test_config_edit() -> anyhow::Result<()> {
        let config = Config::load().await?;

        println!("Initial config:");
        println!("{:?}", config);

        // Start the init process
        let mut watcher = config.init()?;
        watcher.watch(Path::new(CONFIG), RecursiveMode::NonRecursive)?;

        // Simulate waiting for 30 seconds
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        println!("{:?}", config);
        Ok(())
    }
}
