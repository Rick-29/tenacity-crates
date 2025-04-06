use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(default = "default_credentials")]
    pub firestore: String,
    pub github: Option<GitHubConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    pub token: String,
    pub extensions: Vec<String>,
    accept: Option<String>,
    max_attachement_size: Option<u32>,
}

impl Credentials {
    pub fn github(&self) -> anyhow::Result<GitHubConfig> {
        self.github
            .clone()
            .ok_or(anyhow::anyhow!("Error loading github credentials"))
    }
}

impl GitHubConfig {
    pub fn accept(&self) -> String {
        self.accept
            .clone()
            .unwrap_or("application/vnd.github+json".to_string())
    }

    pub fn max_size(&self) -> u32 {
        self.max_attachement_size.unwrap_or(65_536)
    }
}

impl fmt::Display for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(hub) = &self.github {
            writeln!(f, "GitHub: {}\nExtensions: {:?}", hub.token, hub.extensions)?;
        }
        writeln!(f, "Firestore: {}", self.firestore)
    }
}

// Default values
fn default_credentials() -> String {
    "data/chipav2-d64de-firebase-adminsdk-r6z9u-2a30f97526.json".to_string()
}

// Default Impls
impl Default for Credentials {
    fn default() -> Self {
        Self {
            firestore: default_credentials(),
            github: None,
        }
    }
}
