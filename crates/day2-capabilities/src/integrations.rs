//! Reviewed live-provider profiles. These are authority inputs, never credentials.

use crate::resources::VersionRef;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum LiveConnection {
    /// An incoming webhook URL mounted as a secret, never serialized in configuration.
    SlackWebhook { credential_ref: VersionRef },
    Slack {
        credential_ref: VersionRef,
        /// Verifies inbound deliveries. A different kind of secret from the bot
        /// token above: that one is transmitted to Slack on every call, this one
        /// is never transmitted at all — it is local key material for checking an
        /// HMAC. They are kept apart by type as well as by name, so a signing
        /// secret cannot reach an Authorization header and a bot token cannot be
        /// accepted as a verification key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signing_secret_ref: Option<VersionRef>,
        workspace_id: String,
    },
    /// Any S3-compatible endpoint. `access_key_id` is an identifier rather than a
    /// secret — the secret access key is the mounted credential — so it belongs in
    /// reviewed configuration alongside the endpoint it authenticates against.
    ObjectStore {
        credential_ref: VersionRef,
        endpoint: String,
        region: String,
        bucket: String,
        access_key_id: String,
    },
    /// Linear's GraphQL API for work tracking.
    ///
    /// The credential is an OAuth access token, transmitted as a bearer. Linear
    /// also accepts a personal API key, which is sent *without* the `Bearer`
    /// prefix — the reviewed transport only speaks bearer, so an instance must
    /// mount an OAuth token rather than a personal key, and a personal key
    /// mounted here would be rejected by Linear rather than silently misread.
    LinearWork {
        credential_ref: VersionRef,
        /// The organization these issues belong to. Recorded so a grant cannot be
        /// pointed at another workspace by swapping the credential alone.
        organization_id: String,
    },
    /// A reviewed Gitea origin. The adapter supplies the fixed /api/v1 prefix.
    GiteaActions {
        credential_ref: VersionRef,
        endpoint: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signing_secret_ref: Option<VersionRef>,
    },
    /// GitHub Actions, for reading CI job outcomes.
    ///
    /// Named for GitHub rather than for a generic forge on purpose. Repository,
    /// pull request and issue concepts do generalise across forges and are worth
    /// a shared interface when something needs them; a CI job does not — GitLab
    /// pipelines and Gitea actions differ structurally, and a lowest common
    /// denominator invented for a single implementation would be a guess.
    ///
    /// `endpoint` exists so GitHub Enterprise works. It is the API host, not a
    /// generic forge selector.
    GitHubActions {
        credential_ref: VersionRef,
        endpoint: String,
    },
    Snowflake {
        credential_ref: VersionRef,
        account: String,
        role: String,
        warehouse: String,
    },
    OpenAi {
        credential_ref: VersionRef,
        project_id: String,
        organization_id: Option<String>,
    },
}

impl LiveConnection {
    /// The outbound credential. Its connection variant determines how it is used:
    /// SlackWebhook authenticates in the reviewed URL, never a bearer header.
    pub fn credential_ref(&self) -> &VersionRef {
        match self {
            Self::SlackWebhook { credential_ref }
            | Self::Slack { credential_ref, .. }
            | Self::Snowflake { credential_ref, .. }
            | Self::ObjectStore { credential_ref, .. }
            | Self::LinearWork { credential_ref, .. }
            | Self::GitHubActions { credential_ref, .. }
            | Self::GiteaActions { credential_ref, .. }
            | Self::OpenAi { credential_ref, .. } => credential_ref,
        }
    }

    /// The secret that verifies inbound deliveries, where the provider accepts
    /// them at all.
    pub fn verification_ref(&self) -> Option<&VersionRef> {
        match self {
            Self::Slack {
                signing_secret_ref, ..
            }
            | Self::GiteaActions {
                signing_secret_ref, ..
            } => signing_secret_ref.as_ref(),
            Self::SlackWebhook { .. }
            | Self::Snowflake { .. }
            | Self::OpenAi { .. }
            | Self::ObjectStore { .. }
            | Self::LinearWork { .. }
            | Self::GitHubActions { .. } => None,
        }
    }

    /// Every secret this connection declares, so that validation and mounting can
    /// cover all of them rather than only the first.
    ///
    /// `..` is forbidden in this function and every field is bound or explicitly
    /// discarded as `field: _`. That is deliberate and is not tidy-up-able: with
    /// `..`, adding a secret field to a variant would compile unchanged and the new
    /// secret would be silently unvalidated and unmounted. Written out, adding any
    /// field is a compile error here and the author has to decide whether the new
    /// thing is a secret.
    pub fn credential_refs(&self) -> Vec<&VersionRef> {
        match self {
            Self::SlackWebhook { credential_ref } => vec![credential_ref],
            Self::Slack {
                credential_ref,
                signing_secret_ref,
                workspace_id: _,
            } => [Some(credential_ref), signing_secret_ref.as_ref()]
                .into_iter()
                .flatten()
                .collect(),
            Self::Snowflake {
                credential_ref,
                account: _,
                role: _,
                warehouse: _,
            } => vec![credential_ref],
            Self::ObjectStore {
                credential_ref,
                endpoint: _,
                region: _,
                bucket: _,
                access_key_id: _,
            } => vec![credential_ref],
            Self::OpenAi {
                credential_ref,
                project_id: _,
                organization_id: _,
            } => vec![credential_ref],
            Self::LinearWork {
                credential_ref,
                organization_id: _,
            } => vec![credential_ref],
            Self::GiteaActions {
                credential_ref,
                endpoint: _,
                signing_secret_ref,
            } => [Some(credential_ref), signing_secret_ref.as_ref()]
                .into_iter()
                .flatten()
                .collect(),
            Self::GitHubActions {
                credential_ref,
                endpoint: _,
            } => vec![credential_ref],
        }
    }

    pub fn validate(&self) -> Result<()> {
        // Every declared secret, not only the outbound one: an unvalidated
        // reference is one that resolves to something nobody checked.
        for credential in self.credential_refs() {
            ensure!(credential.revision > 0, "invalid_credential_revision");
            identifier(&credential.id, 128)?;
        }
        ensure!(
            self.credential_refs().len()
                == self
                    .credential_refs()
                    .iter()
                    .map(|reference| (&reference.id, reference.revision))
                    .collect::<BTreeSet<_>>()
                    .len(),
            "duplicate_credential_reference"
        );
        match self {
            Self::SlackWebhook { .. } => Ok(()),
            Self::Slack { workspace_id, .. } => slack_id(workspace_id, b"T"),
            Self::ObjectStore {
                endpoint,
                region,
                bucket,
                access_key_id,
                ..
            } => {
                // Only https, and only a host: a store reached over plaintext or
                // through a path-carrying endpoint is not the store it claims.
                ensure!(
                    endpoint.starts_with("https://")
                        && endpoint.len() <= 253
                        && !endpoint[8..].contains('/')
                        && !endpoint[8..].is_empty(),
                    "invalid_object_endpoint"
                );
                ensure!(
                    (1..=32).contains(&region.len())
                        && region.bytes().all(|byte| byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'),
                    "invalid_object_region"
                );
                ensure!(
                    (1..=128).contains(&access_key_id.len())
                        && access_key_id
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric()),
                    "invalid_object_access_key_id"
                );
                crate::resources::validate_bucket(bucket)
            }
            Self::Snowflake {
                account,
                role,
                warehouse,
                ..
            } => {
                ensure!(
                    account.len() <= 180
                        && account.split('.').all(|part| {
                            !part.is_empty()
                                && part.len() <= 63
                                && !part.starts_with('-')
                                && !part.ends_with('-')
                                && part.bytes().all(|b| {
                                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
                                })
                        }),
                    "invalid_snowflake_account"
                );
                sql_identifier(role)?;
                sql_identifier(warehouse)
            }
            Self::GiteaActions { endpoint, .. } => {
                let host = endpoint.strip_prefix("https://").unwrap_or_default();
                ensure!(
                    !host.is_empty()
                        && host.len() <= 253
                        && host.split('.').all(|label| !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                    "invalid_gitea_endpoint"
                );
                Ok(())
            }
            Self::GitHubActions { endpoint, .. } => {
                // Host only, https only: an API base carrying a path is not the
                // API it claims to be, and plaintext would put the installation
                // token on the wire.
                ensure!(
                    endpoint.starts_with("https://")
                        && endpoint.len() <= 253
                        && !endpoint[8..].contains('/')
                        && !endpoint[8..].is_empty(),
                    "invalid_github_endpoint"
                );
                Ok(())
            }
            Self::LinearWork {
                organization_id, ..
            } => {
                ensure!(
                    !organization_id.trim().is_empty() && organization_id.len() <= 256,
                    "invalid_linear_organization"
                );
                Ok(())
            }
            Self::OpenAi {
                project_id,
                organization_id,
                ..
            } => {
                identifier(project_id, 128)?;
                ensure!(project_id.starts_with("proj_"), "invalid_openai_project");
                if let Some(organization) = organization_id {
                    identifier(organization, 128)?;
                    ensure!(
                        organization.starts_with("org-"),
                        "invalid_openai_organization"
                    );
                }
                Ok(())
            }
        }
    }
}

/// Where one grant's issues come from.
///
/// An application never names a view or a label: it reads whatever its grant
/// points at, exactly as a Slack grant fixes the channel. Letting an application
/// supply the view id would let a compliance queue read any view in the
/// workspace, which is the whole authority this target exists to bound.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LinearWorkSource {
    /// A saved Linear view, by id.
    CustomView {
        view_id: String,
        name: String,
        url: String,
    },
    /// Every issue carrying one label.
    Label { label: String },
}

impl LinearWorkSource {
    pub fn validate(&self) -> anyhow::Result<()> {
        let bounded = |value: &str, limit: usize| -> anyhow::Result<()> {
            anyhow::ensure!(
                !value.trim().is_empty() && value.len() <= limit,
                "linear_work_source_field"
            );
            Ok(())
        };
        match self {
            Self::CustomView { view_id, name, url } => {
                bounded(view_id, 128)?;
                bounded(name, 256)?;
                anyhow::ensure!(
                    url.starts_with("https://") && url.len() <= 2048,
                    "linear_work_source_url"
                );
                Ok(())
            }
            Self::Label { label } => bounded(label, 256),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SlackChannel {
    pub channel_id: String,
}

impl SlackChannel {
    pub fn validate(&self) -> Result<()> {
        // No user IDs that implicitly open a conversation; no direct messages.
        slack_id(&self.channel_id, b"CG")
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnowflakeScalarType {
    Text,
    Integer,
    Boolean,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SnowflakeScalar {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

impl SnowflakeScalar {
    pub fn scalar_type(&self) -> SnowflakeScalarType {
        match self {
            Self::Text(_) => SnowflakeScalarType::Text,
            Self::Integer(_) => SnowflakeScalarType::Integer,
            Self::Boolean(_) => SnowflakeScalarType::Boolean,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnowflakeView {
    pub database: String,
    pub schema: String,
    pub view: String,
    pub columns: Vec<String>,
    /// Every key is an approved column and a required equality parameter.
    /// Row security belongs in the approved view/role, not caller-chosen values.
    pub filters: BTreeMap<String, SnowflakeScalarType>,
    pub max_rows: u32,
}

impl SnowflakeView {
    pub fn validate(&self) -> Result<()> {
        sql_identifier(&self.database)?;
        sql_identifier(&self.schema)?;
        sql_identifier(&self.view)?;
        ensure!(
            !self.columns.is_empty() && self.columns.len() <= 64,
            "invalid_snowflake_columns"
        );
        let mut seen = BTreeSet::new();
        for column in &self.columns {
            sql_identifier(column)?;
            ensure!(seen.insert(column), "duplicate_snowflake_column");
        }
        ensure!(self.filters.len() <= 32, "invalid_snowflake_filters");
        for column in self.filters.keys() {
            sql_identifier(column)?;
        }
        ensure!(
            (1..=1000).contains(&self.max_rows),
            "invalid_snowflake_row_limit"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenAiText {
    pub model: String,
    pub max_input_bytes: u64,
    /// Operator-reviewed full billable model-context ceiling, not an estimate
    /// derived from the prompt's byte count. Reserved before every dispatch.
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub input_nanos_per_token: u64,
    pub output_nanos_per_token: u64,
}

impl OpenAiText {
    pub fn validate(&self) -> Result<()> {
        identifier(&self.model, 128)?;
        ensure!(
            (1..=1_048_576).contains(&self.max_input_bytes),
            "invalid_model_input_bytes"
        );
        ensure!(
            (1..=10_000_000).contains(&self.max_input_tokens),
            "invalid_model_input_tokens"
        );
        ensure!(
            (16..=1_000_000).contains(&self.max_output_tokens),
            "invalid_model_output_tokens"
        );
        ensure!(
            self.input_nanos_per_token > 0 && self.output_nanos_per_token > 0,
            "invalid_model_rates"
        );
        self.cost_microusd(self.max_input_tokens, self.max_output_tokens)?;
        Ok(())
    }

    pub fn cost_microusd(&self, input: u64, output: u64) -> Result<u64> {
        let nanos = (u128::from(input) * u128::from(self.input_nanos_per_token))
            .checked_add(u128::from(output) * u128::from(self.output_nanos_per_token))
            .ok_or_else(|| anyhow::anyhow!("model_cost_overflow"))?;
        u64::try_from(nanos.div_ceil(1000)).map_err(|_| anyhow::anyhow!("model_cost_overflow"))
    }
}

fn identifier(value: &str, max: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= max
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        "invalid_provider_identifier"
    );
    Ok(())
}

pub fn sql_identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control),
        "invalid_sql_identifier"
    );
    Ok(())
}

fn slack_id(value: &str, prefixes: &[u8]) -> Result<()> {
    ensure!(
        (2..=64).contains(&value.len())
            && prefixes.contains(&value.as_bytes()[0])
            && value
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "invalid_slack_identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_identity_and_rates_fail_closed() {
        let credential_ref = VersionRef {
            id: "credential".into(),
            revision: 1,
        };
        for account in [
            "evil.com/path",
            "a@evil",
            "a:443",
            "a..b",
            "-a",
            "a.",
            "a%2eb",
        ] {
            assert!(
                LiveConnection::Snowflake {
                    credential_ref: credential_ref.clone(),
                    account: account.into(),
                    role: "READER".into(),
                    warehouse: "WH".into()
                }
                .validate()
                .is_err()
            );
        }
        for channel in ["U123", "D123", "#general", "C12&team=T2", ""] {
            assert!(
                SlackChannel {
                    channel_id: channel.into()
                }
                .validate()
                .is_err()
            );
        }
        let profile = OpenAiText {
            model: "model-snapshot".into(),
            max_input_bytes: 100,
            max_input_tokens: 1000,
            max_output_tokens: 16,
            input_nanos_per_token: 1,
            output_nanos_per_token: 1001,
        };
        assert_eq!(profile.cost_microusd(1, 1).unwrap(), 2);
        assert!(profile.validate().is_ok());
        assert!(profile.cost_microusd(u64::MAX, u64::MAX).is_err());
    }
}
