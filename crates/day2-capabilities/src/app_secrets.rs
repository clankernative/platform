//! Operator-selected namespace for owner-managed application secrets.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU64, path::Path};

/// Values live in Secret Manager; this declaration contains host configuration only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub project_number: NonZeroU64,
    /// Explicitly injected, refreshed OAuth bearer token; never discovered from ADC.
    pub access_token_file: String,
}

impl Namespace {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.access_token_file.is_empty()
                && self.access_token_file.len() <= 4096
                && !self.access_token_file.chars().any(char::is_control)
                && Path::new(&self.access_token_file).is_absolute(),
            "app_secret_token_file_must_be_absolute"
        );
        Ok(())
    }
}

/// Scope-derived names fit the existing 80-byte provider-resource identity.
pub fn prefix(scope: &str) -> String {
    format!(
        "day2-{}-",
        &crate::Digest::new(scope.as_bytes()).as_str()[7..39]
    )
}
