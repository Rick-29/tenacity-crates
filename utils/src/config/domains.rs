use core::fmt;
use std::{collections::HashMap, fmt::Display};

use anyhow::anyhow;
use serde::{ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone)]
pub struct Domains {
    pub domains: HashMap<String, String>,
}

// Impls

// Default Implementations
impl Default for Domains {
    fn default() -> Self {
        Self {
            domains: default_domains(),
        }
    }
}

impl Serialize for Domains {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.domains.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Domains {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let domains = match HashMap::<String, String>::deserialize(deserializer) {
            Ok(domains) => domains,
            Err(_) => default_domains(),
        };
        Ok(Domains { domains })
    }
}

impl Domains {
    pub fn url<T: Display>(&self, endpoint: &T, domain: &str) -> anyhow::Result<String> {
        let domain = match self.domains.get(domain) {
            Some(domain) => domain,
            None => return Err(anyhow!("Domain {domain} not found")),
        };
        let url = format!("{domain}{endpoint}");
        Ok(url)
    }
}

impl fmt::Display for Domains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // writeln!(f, "Domains (Name, Value)")?;
        for (name, value) in self.domains.iter() {
            writeln!(f, "{name}: {value}")?;
        }

        Ok(())
    }
}
// Defualt values
fn default_domains() -> HashMap<String, String> {
    let mut domains = HashMap::new();

    #[cfg(feature = "license")]
    domains.insert("license".into(), "http://localhost:2909".into());

    domains
}

pub fn serialize_domains<S>(domains: &Domains, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let domains = domains.domains.clone();
    let mut map = serializer.serialize_map(Some(domains.len()))?;
    for (k, v) in domains {
        map.serialize_entry(&k, &v)?;
    }
    map.end()
}
