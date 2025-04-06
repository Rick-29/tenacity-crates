use core::fmt;

use serde::{Deserialize, Serialize};

const SCHEMA: &str = "src/db/schema/user.toasty";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbConfig {
    pub schema: String,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            schema: default_shema(),
        }
    }
}

impl fmt::Display for DbConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Database Configuration: Schema = {}", self.schema)
    }
}

fn default_shema() -> String {
    SCHEMA.to_string()
}
