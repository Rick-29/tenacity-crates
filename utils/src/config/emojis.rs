use anyhow::anyhow;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Display};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmojiConfig {
    pub emojis: HashMap<String, u64>,
    pub welcome_emojis: HashMap<String, u64>,
}

#[derive(Debug)]
pub struct Emoji {
    pub name: String,
    pub id: u64,
}

impl From<(String, u64)> for Emoji {
    fn from(value: (String, u64)) -> Self {
        Self {
            name: value.0,
            id: value.1,
        }
    }
}

impl Display for Emoji {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<:{}:{}>", self.name, self.id)
    }
}

impl EmojiConfig {
    pub fn get_welcome(&self) -> anyhow::Result<Emoji> {
        self.welcome_emojis
            .clone()
            .into_iter()
            .choose(&mut rand::rng())
            .map(Emoji::from)
            .ok_or(anyhow!("No elements available"))
    }
    pub fn get_emoji(&self) -> anyhow::Result<Emoji> {
        self.emojis
            .clone()
            .into_iter()
            .choose(&mut rand::rng())
            .map(Emoji::from)
            .ok_or(anyhow!("No elements available"))
    }
    pub fn welcome_emojis(&self) -> Vec<Emoji> {
        self.welcome_emojis
            .clone()
            .into_iter()
            .map(Emoji::from)
            .collect()
    }
    pub fn app_emojis(&self) -> Vec<Emoji> {
        self.emojis.clone().into_iter().map(Emoji::from).collect()
    }
}

impl Display for EmojiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Emojis:")?;
        for (name, id) in &self.emojis {
            write!(f, "  {}", Emoji::from((name.to_owned(), *id)))?;
        }
        write!(f, "\nWelcome Emojis:")?;
        for (name, id) in &self.welcome_emojis {
            write!(f, "  {}", Emoji::from((name.to_owned(), *id)))?;
        }
        Ok(())
    }
}
