use alloc::string::String;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TextRule {
    pub maximum_bytes: u64,
    pub nonblank: bool,
    pub description: String,
}

impl TextRule {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=16384).contains(&self.maximum_bytes)
                && !self.description.trim().is_empty()
                && self.description.len() <= 1024,
            "invalid required text domain rules"
        );
        Ok(())
    }

    pub fn accepts(&self, value: &str) -> bool {
        value.len() as u64 <= self.maximum_bytes && (!self.nonblank || !value.trim().is_empty())
    }
}
