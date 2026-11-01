//! Redacted observations from required portable DST campaigns. These receipts
//! describe completed oracle/replay work, never native or provider qualification.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Campaign {
    Oauth,
    InboundOauth,
    CredentialLifecycle,
    EnrollmentHandshake,
    StorageCurrentHandshake,
    StorageBootstrapHandshake,
    ServingHandshake,
    StorageLifecycle,
    NativeOauthConsumer,
    AppConnectionRequest,
    ShellConnectionRequest,
    HostLoop,
    CommandFixed,
    CommandGenerated,
    GoogleMappedRegistration,
    GoogleExternalRegistration,
    GitlabRegistration,
}

impl Campaign {
    pub const ALL: [Self; 17] = [
        Self::Oauth,
        Self::InboundOauth,
        Self::CredentialLifecycle,
        Self::EnrollmentHandshake,
        Self::StorageCurrentHandshake,
        Self::StorageBootstrapHandshake,
        Self::ServingHandshake,
        Self::StorageLifecycle,
        Self::NativeOauthConsumer,
        Self::AppConnectionRequest,
        Self::ShellConnectionRequest,
        Self::HostLoop,
        Self::CommandFixed,
        Self::CommandGenerated,
        Self::GoogleMappedRegistration,
        Self::GoogleExternalRegistration,
        Self::GitlabRegistration,
    ];

    pub fn required_seeds(self) -> Vec<u64> {
        match self {
            Self::CredentialLifecycle => vec![1, 19, 401],
            Self::EnrollmentHandshake
            | Self::StorageCurrentHandshake
            | Self::StorageBootstrapHandshake
            | Self::ServingHandshake => (1..=32).chain(100..132).collect(),
            Self::GoogleMappedRegistration
            | Self::GoogleExternalRegistration
            | Self::GitlabRegistration => (0..8).collect(),
            Self::NativeOauthConsumer => (0..56).collect(),
            Self::HostLoop => (0..64).collect(),
            Self::CommandFixed => vec![0, 1, 42, 3_664_912_422, 0xdeadbeef],
            Self::CommandGenerated => Vec::new(),
            _ => (0..32).collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    StateChanged,
    Accepted,
    Refused,
    Retried,
    Waited,
    Absent,
    RegistrationStepCompleted,
    DecisionCommitted,
    ProviderAccepted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub campaign: Campaign,
    pub seed: u64,
    pub transitions: BTreeMap<Transition, u64>,
}

/// Call only after the original history and its oracle/replay checks complete.
/// Counts come from observed results/state differences, not generated intent.
/// The verifier supplies a fresh private directory to its test children; ordinary
/// focused tests need no CI output directory and retain their existing behavior.
pub fn record(
    campaign: Campaign,
    seed: u64,
    transitions: impl IntoIterator<Item = (Transition, u64)>,
) -> Result<()> {
    let observation = Observation {
        campaign,
        seed,
        transitions: transitions.into_iter().filter(|(_, n)| *n > 0).collect(),
    };
    let Some(directory) = std::env::var_os("DAY2_DST_OBSERVATIONS") else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(&observation)?;
    ensure!(bytes.len() <= 4096, "DST observation byte bound");
    let mut file = tempfile::Builder::new()
        .prefix("observation-")
        .suffix(".json")
        .tempfile_in(directory)?;
    file.write_all(&bytes)?;
    let complete = file.path().with_extension("complete");
    file.persist_noclobber(complete)?;
    Ok(())
}
