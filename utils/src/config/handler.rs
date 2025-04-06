use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HandlerConfig {
    pub watch: HashSet<u64>,
    pub length: usize,
    pub threshold: f32,
    pub model_path: Option<String>,
    pub welcome: Vec<(u64, u64)>,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            watch: HashSet::new(),
            length: 250,
            threshold: 0.75,
            model_path: Some("assets/detector_burn.mpk".to_string()),
            welcome: Vec::new(),
        }
    }
}

impl fmt::Display for HandlerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // writeln!(f, "Handler:")?;

        writeln!(f, "Watch Channels: {:?}", self.watch)?;
        writeln!(f, "Message Length: {}", self.length)?;
        writeln!(f, "Threshold: {:.2}", self.threshold)?;
        writeln!(f, "Model Path: {:?}", self.model_path)?;
        Ok(())
    }
}
