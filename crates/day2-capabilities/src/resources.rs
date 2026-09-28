//! Provider-free resource policy authoring and deterministic grant resolution.
//! Catalogs describe desired authority; only a resolved, activated snapshot may
//! authorize execution. Provider credentials and mutable resource lookup stay out.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct VersionRef {
    pub id: String,
    pub revision: u64,
}

// Generated from the one provider table; see `crate::registry`.
pub use crate::registry::{Action, Provider, ResourceKind};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TopicScope {
    Any,
    Only { topics: BTreeSet<String> },
    Prefix { prefix: String },
}

impl TopicScope {
    pub fn contains(&self, topic: &str) -> bool {
        !topic.is_empty()
            && topic.len() <= 128
            && match self {
                Self::Any => true,
                Self::Only { topics } => topics.contains(topic),
                Self::Prefix { prefix } => topic.starts_with(prefix),
            }
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (_, Self::Any) => true,
            (Self::Only { topics }, parent) => topics.iter().all(|topic| parent.contains(topic)),
            (Self::Prefix { prefix }, Self::Prefix { prefix: parent }) => {
                prefix.starts_with(parent)
            }
            _ => false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Any => {}
            Self::Only { topics } => {
                ensure!(
                    !topics.is_empty() && topics.len() <= 256,
                    "invalid_notification_topic_scope"
                );
                for topic in topics {
                    bounded_text(topic, 128)?;
                }
            }
            Self::Prefix { prefix } => bounded_text(prefix, 128)?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceTarget {
    /// The invoking actor's mailbox. Any refers only to topics within that
    /// actor's mailbox; it never grants arbitrary recipient selection.
    NotificationMailbox {
        topics: TopicScope,
    },
    CartaIssuer {
        issuer_id: String,
    },
    GoogleDirectory {
        customer_id: String,
        email_domain: String,
        org_unit_prefix: String,
        /// Explicit operator-approved role (or email) to group email mapping.
        groups: BTreeMap<String, String>,
    },
    LinearOrganization {
        organization_id: String,
        email_domain: String,
    },
    /// One GitHub repository, and the CI jobs reachable within it.
    ///
    /// A grant names one repository. That is the whole of the authority: an
    /// application can read job outcomes in the repository it was granted and in
    /// no other, which matters because a CI log can contain anything a build
    /// printed — tokens, customer data, source.
    /// Actions in one explicitly granted Gitea organization. Reads only.
    GiteaOrganization {
        owner: String,
    },
    GitHubRepository {
        owner: String,
        repo: String,
    },
    /// One Linear work source, and the issues reachable through it.
    ///
    /// Deliberately a separate target from `LinearOrganization` rather than more
    /// actions on it. That one authorizes identity work — inviting people and
    /// suspending their accounts — and this one authorizes reading and reassigning
    /// issues. They are different authorities held by different applications: a
    /// compliance queue has no business suspending anyone, and folding both into
    /// one target would mean granting it that power in order to let it read a
    /// queue.
    LinearIssueSource {
        source: crate::integrations::LinearWorkSource,
    },
    /// A bucket and the key prefix a grant may reach. The prefix is the whole of
    /// the authority: an application can name any key beneath it and none outside,
    /// so two applications sharing a bucket cannot read each other's objects.
    ObjectBucket {
        bucket: String,
        key_prefix: String,
    },
    /// One operation of one other application in this instance.
    ///
    /// The grant names the exact operation, never an application: "may call
    /// people_ops" is not a thing an operator can express, because the blast
    /// radius of an application is every operation it will ever declare. The
    /// schema digest pins the shape the operator reviewed, so a callee that
    /// changes what it accepts fails the caller's *deployment* rather than the
    /// caller's 3am invocation.
    AppOperation {
        app: String,
        operation: String,
        schema_digest: String,
    },
    OperatorAlertDestination {
        destination: String,
        topics: TopicScope,
    },
    SlackWebhookDestination {
        /// SHA-256 of the exact operator-reviewed URL; the URL itself is secret.
        endpoint_sha256: String,
    },
    SlackChannel {
        channel: crate::integrations::SlackChannel,
    },
    SnowflakeView {
        query: crate::integrations::SnowflakeView,
    },
    OpenAiText {
        profile: crate::integrations::OpenAiText,
    },
}

impl ResourceTarget {
    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::NotificationMailbox { .. } => ResourceKind::NotificationMailbox,
            Self::CartaIssuer { .. } => ResourceKind::CartaIssuer,
            Self::GoogleDirectory { .. } => ResourceKind::GoogleDirectory,
            Self::LinearOrganization { .. } => ResourceKind::LinearOrganization,
            Self::LinearIssueSource { .. } => ResourceKind::LinearIssueSource,
            Self::GitHubRepository { .. } => ResourceKind::GitHubRepository,
            Self::GiteaOrganization { .. } => ResourceKind::GiteaOrganization,
            Self::OperatorAlertDestination { .. } => ResourceKind::OperatorAlertDestination,
            Self::SlackWebhookDestination { .. } => ResourceKind::SlackWebhookDestination,
            Self::SlackChannel { .. } => ResourceKind::SlackChannel,
            Self::SnowflakeView { .. } => ResourceKind::SnowflakeView,
            Self::OpenAiText { .. } => ResourceKind::OpenAiText,
            Self::ObjectBucket { .. } => ResourceKind::ObjectBucket,
            Self::AppOperation { .. } => ResourceKind::AppOperation,
        }
    }

    /// Whether this grant authorizes naming `key` in `bucket`.
    ///
    /// The whole of an object grant's authority. A presigned URL is a bearer
    /// capability for exactly the object it names, so a key admitted here is
    /// access handed out irrevocably — no later check can take back a signature
    /// already given to a client.
    ///
    /// The comparison is on the key as the application wrote it, never a
    /// normalised form. To a store a key is a flat string, so `a/../b` names a
    /// different object than `b`; normalising before comparing would let a key
    /// pass the prefix test and then address something else entirely.
    pub fn authorizes_object(&self, bucket: &str, key: &str) -> Result<()> {
        let Self::ObjectBucket {
            bucket: granted,
            key_prefix,
        } = self
        else {
            anyhow::bail!("resource_is_not_an_object_bucket")
        };
        ensure!(granted == bucket, "object_bucket_not_granted");
        object_key(key, false)?;
        ensure!(
            key.starts_with(key_prefix.as_str()),
            "object_key_outside_grant"
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::SlackWebhookDestination { endpoint_sha256 } => {
                ensure!(
                    endpoint_sha256.len() == 64
                        && endpoint_sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "invalid_slack_webhook_digest"
                );
                Ok(())
            }
            Self::SlackChannel { channel } => channel.validate(),
            Self::SnowflakeView { query } => query.validate(),
            Self::OpenAiText { profile } => profile.validate(),
            Self::NotificationMailbox { topics } => topics.validate(),
            Self::CartaIssuer { issuer_id } => bounded_text(issuer_id, 256),
            Self::ObjectBucket { bucket, key_prefix } => {
                bucket_name(bucket)?;
                object_key(key_prefix, true)
            }
            Self::AppOperation {
                app,
                operation,
                schema_digest,
            } => {
                name(app)?;
                delegated_operation(operation)?;
                ensure!(
                    schema_digest.len() == 71 && schema_digest.starts_with("sha256:"),
                    "invalid_delegated_schema_digest"
                );
                Ok(())
            }
            Self::GoogleDirectory {
                customer_id,
                email_domain,
                org_unit_prefix,
                groups,
            } => {
                bounded_text(customer_id, 256)?;
                email_domain_text(email_domain)?;
                org_unit_path(org_unit_prefix)?;
                ensure!(groups.len() <= 256, "google_group_mapping_budget");
                for (role, email) in groups {
                    bounded_text(role, 320)?;
                    ensure!(
                        email_in_domain(email, email_domain),
                        "invalid_google_group_mapping"
                    );
                }
                Ok(())
            }
            Self::LinearOrganization {
                organization_id,
                email_domain,
            } => {
                bounded_text(organization_id, 256)?;
                email_domain_text(email_domain)
            }
            Self::LinearIssueSource { source } => source.validate(),
            Self::GiteaOrganization { owner } => {
                ensure!(
                    !owner.is_empty()
                        && owner.len() <= 100
                        && owner
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                        && owner != "."
                        && owner != "..",
                    "invalid_gitea_organization"
                );
                Ok(())
            }
            Self::GitHubRepository { owner, repo } => {
                // GitHub's own rules: owners and repositories are bounded and
                // restricted, and interpolating anything else into a path would
                // let a grant reach outside the repository it names.
                for part in [owner, repo] {
                    ensure!(
                        !part.is_empty()
                            && part.len() <= 100
                            && part
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
                        "invalid_github_repository"
                    );
                }
                Ok(())
            }
            Self::OperatorAlertDestination {
                destination,
                topics,
            } => {
                bounded_text(destination, 256)?;
                topics.validate()
            }
        }
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (
                Self::SlackWebhookDestination { endpoint_sha256 },
                Self::SlackWebhookDestination {
                    endpoint_sha256: parent,
                },
            ) => endpoint_sha256 == parent,
            (Self::SlackChannel { channel }, Self::SlackChannel { channel: parent }) => {
                channel == parent
            }
            (Self::SnowflakeView { query }, Self::SnowflakeView { query: parent }) => {
                query == parent
            }
            (Self::OpenAiText { profile }, Self::OpenAiText { profile: parent }) => {
                profile == parent
            }
            (
                Self::NotificationMailbox { topics },
                Self::NotificationMailbox { topics: parent },
            ) => topics.is_subset_of(parent),
            (Self::CartaIssuer { issuer_id }, Self::CartaIssuer { issuer_id: parent }) => {
                issuer_id == parent
            }
            (
                Self::GoogleDirectory {
                    customer_id,
                    email_domain,
                    org_unit_prefix,
                    groups,
                },
                Self::GoogleDirectory {
                    customer_id: parent_customer,
                    email_domain: parent_domain,
                    org_unit_prefix: parent_prefix,
                    groups: parent_groups,
                },
            ) => {
                customer_id == parent_customer
                    && email_domain == parent_domain
                    && path_is_within(org_unit_prefix, parent_prefix)
                    && groups
                        .iter()
                        .all(|(role, email)| parent_groups.get(role) == Some(email))
            }
            (
                Self::LinearOrganization {
                    organization_id,
                    email_domain,
                },
                Self::LinearOrganization {
                    organization_id: parent_org,
                    email_domain: parent_domain,
                },
            ) => organization_id == parent_org && email_domain == parent_domain,
            // A work-source grant narrows only to the identical source. There is
            // no "subset of a view": an application either reads what the grant
            // points at or it does not.
            (
                Self::LinearIssueSource { source },
                Self::LinearIssueSource {
                    source: parent_source,
                },
            ) => source == parent_source,
            (Self::GiteaOrganization { owner }, Self::GiteaOrganization { owner: parent }) => {
                owner == parent
            }
            // A repository grant narrows only to the identical repository.
            (
                Self::GitHubRepository { owner, repo },
                Self::GitHubRepository {
                    owner: parent_owner,
                    repo: parent_repo,
                },
            ) => owner == parent_owner && repo == parent_repo,
            (
                Self::OperatorAlertDestination {
                    destination,
                    topics,
                },
                Self::OperatorAlertDestination {
                    destination: parent_destination,
                    topics: parent_topics,
                },
            ) => destination == parent_destination && topics.is_subset_of(parent_topics),
            // Same bucket, and a key prefix at or below the parent's. A prefix
            // is the whole of an object grant's authority, so narrowing means
            // reaching fewer keys and nothing else.
            (
                Self::ObjectBucket { bucket, key_prefix },
                Self::ObjectBucket {
                    bucket: parent_bucket,
                    key_prefix: parent_prefix,
                },
            ) => bucket == parent_bucket && key_prefix.starts_with(parent_prefix),
            // The identical operation, at the identical reviewed shape. There is
            // no subset of an operation: a caller either may invoke exactly
            // this one, as reviewed, or it may not.
            (
                Self::AppOperation {
                    app,
                    operation,
                    schema_digest,
                },
                Self::AppOperation {
                    app: parent_app,
                    operation: parent_operation,
                    schema_digest: parent_digest,
                },
            ) => {
                app == parent_app && operation == parent_operation && schema_digest == parent_digest
            }
            // Two different kinds never narrow to one another. Reached only by
            // a mismatched pair — every kind has an arm above, which
            // `narrowing::every_kind_narrows_to_itself` is what keeps true.
            _ => false,
        }
    }
}

/// S3 bucket naming, which every compatible vendor shares: lowercase, dotted or
/// hyphenated labels, 3 to 63 characters. Narrower than any one vendor allows, so
/// a name accepted here works on all of them.
/// An object key an application named, as opposed to a configured prefix.
pub fn validate_object_key(key: &str) -> Result<()> {
    object_key(key, false)
}

pub(crate) fn validate_bucket(bucket: &str) -> Result<()> {
    bucket_name(bucket)
}

fn bucket_name(bucket: &str) -> Result<()> {
    ensure!(
        (3..=63).contains(&bucket.len())
            && bucket.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"-.".contains(&byte))
            && bucket.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && bucket.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && !bucket.contains("..")
            && bucket.parse::<std::net::Ipv4Addr>().is_err(),
        "invalid_object_bucket"
    );
    Ok(())
}

/// An object key, or the prefix a grant is scoped to.
///
/// Traversal and absolute forms are refused rather than normalised. A key is a
/// flat string to the store, so `a/../b` is a *different object* from `b` rather
/// than the same one — normalising would silently retarget it, and comparing an
/// unnormalised key against a prefix would let one escape its grant.
fn object_key(key: &str, prefix: bool) -> Result<()> {
    ensure!(
        key.len() <= 1024
            && (prefix || !key.is_empty())
            && !key.starts_with('/')
            && !key.contains("//")
            && !key.split('/').any(|part| part == "." || part == "..")
            && key
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            && !key.contains('\\'),
        "invalid_object_key"
    );
    Ok(())
}

fn email_domain_text(domain: &str) -> Result<()> {
    bounded_text(domain, 253)?;
    ensure!(
        domain == domain.to_ascii_lowercase()
            && domain.split('.').count() >= 2
            && domain.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')),
        "invalid_resource_email_domain"
    );
    Ok(())
}

pub fn email_in_domain(email: &str, domain: &str) -> bool {
    email.len() <= 320
        && email.is_ascii()
        && !email
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        && email.rsplit_once('@').is_some_and(|(local, actual)| {
            !local.is_empty() && !local.contains('@') && actual.eq_ignore_ascii_case(domain)
        })
}

fn org_unit_path(path: &str) -> Result<()> {
    bounded_text(path, 512)?;
    ensure!(
        path.starts_with('/')
            && (path == "/" || !path.ends_with('/'))
            && !path.contains("//")
            && !path
                .split('/')
                .any(|segment| [".", ".."].contains(&segment)),
        "invalid_resource_org_unit_path"
    );
    Ok(())
}

pub fn path_is_within(path: &str, prefix: &str) -> bool {
    org_unit_path(path).is_ok()
        && org_unit_path(prefix).is_ok()
        && (prefix == "/"
            || path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/')))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDefinition {
    pub revision: u64,
    pub provider: Provider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<crate::integrations::LiveConnection>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceDefinition {
    pub revision: u64,
    pub connection: VersionRef,
    pub target: ResourceTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_calls_per_invocation: u64,
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=1_048_576).contains(&self.max_request_bytes)
                && (1..=4_194_304).contains(&self.max_response_bytes)
                && (1..=100_000).contains(&self.max_calls_per_invocation),
            "invalid_resource_limits"
        );
        Ok(())
    }

    pub fn is_subset_of(&self, parent: &Self) -> bool {
        self.max_request_bytes <= parent.max_request_bytes
            && self.max_response_bytes <= parent.max_response_bytes
            && self.max_calls_per_invocation <= parent.max_calls_per_invocation
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    Installation,
    App,
    Actor,
    Connection,
    InvocationRoot,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub calls: Option<u64>,
    pub bytes: Option<u64>,
    pub cost_microunits: Option<u64>,
    pub concurrency: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BudgetDefinition {
    pub revision: u64,
    pub scope: BudgetScope,
    pub period_seconds: u64,
    pub limits: BudgetLimits,
}

impl BudgetDefinition {
    pub fn validate(&self) -> Result<()> {
        revision(self.revision)?;
        ensure!(
            (1..=31_536_000).contains(&self.period_seconds),
            "invalid_budget_period"
        );
        let values = [
            self.limits.calls,
            self.limits.bytes,
            self.limits.cost_microunits,
            self.limits.concurrency,
        ];
        ensure!(
            values.iter().any(Option::is_some)
                && values
                    .iter()
                    .flatten()
                    .all(|value| *value > 0 && *value <= i64::MAX as u64),
            "invalid_budget_limits"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySlot {
    pub kind: ResourceKind,
    pub allowed_resources: BTreeSet<VersionRef>,
    pub actions: BTreeSet<Action>,
    pub limits: Limits,
    #[serde(default)]
    pub budgets: Vec<VersionRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReusablePolicy {
    pub revision: u64,
    pub owner: String,
    #[serde(default)]
    pub delegates: BTreeSet<String>,
    pub actors: BTreeSet<String>,
    pub allowed_apps: BTreeSet<String>,
    pub slots: BTreeMap<String, PolicySlot>,
    pub max_duration_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub policy: VersionRef,
    pub operation: String,
    pub bindings: BTreeMap<String, VersionRef>,
    /// Optional additional attenuation. None retains the policy's actor set.
    #[serde(default)]
    pub actors: Option<BTreeSet<String>>,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u32,
    pub connections: BTreeMap<String, ConnectionDefinition>,
    pub resources: BTreeMap<String, ResourceDefinition>,
    pub policies: BTreeMap<String, ReusablePolicy>,
    #[serde(default)]
    pub budgets: BTreeMap<String, BudgetDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedGrant {
    pub policy: VersionRef,
    pub resource: VersionRef,
    pub connection: VersionRef,
    pub provider: Provider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<crate::integrations::LiveConnection>,
    pub target: ResourceTarget,
    pub actions: BTreeSet<Action>,
    pub actors: BTreeSet<String>,
    pub limits: Limits,
    pub budgets: Vec<VersionRef>,
    pub expires_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedResources {
    pub operations: BTreeMap<String, BTreeMap<String, ResolvedGrant>>,
    pub budgets: BTreeMap<String, BudgetDefinition>,
}

fn bounded_text(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= maximum
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "invalid_resource_text"
    );
    Ok(())
}

fn name(value: &str) -> Result<()> {
    crate::Name::try_from(value.to_owned()).map(|_| ())
}

/// A dotted operation name, as an application registers it.
///
/// Checked here rather than deferred to the callee, because a grant naming an
/// operation that could not exist is an operator mistake worth refusing while
/// they are still looking at it.
fn delegated_operation(value: &str) -> Result<()> {
    ensure!(
        (1..=160).contains(&value.len())
            && value.split('.').count() == 2
            && value.split('.').all(|part| !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'_')),
        "invalid_delegated_operation"
    );
    Ok(())
}

fn revision(value: u64) -> Result<()> {
    ensure!(
        (1..=i64::MAX as u64).contains(&value),
        "invalid_resource_revision"
    );
    Ok(())
}

impl VersionRef {
    pub fn validate(&self) -> Result<()> {
        name(&self.id)?;
        revision(self.revision)
    }
}

use crate::registry::provider_matches;

fn validate_connection(
    provider: Provider,
    live: Option<&crate::integrations::LiveConnection>,
) -> Result<()> {
    use crate::integrations::LiveConnection;
    match (provider, live) {
        (Provider::SlackWebhook, Some(value @ LiveConnection::SlackWebhook { .. }))
        | (Provider::Slack, Some(value @ LiveConnection::Slack { .. }))
        | (Provider::Snowflake, Some(value @ LiveConnection::Snowflake { .. }))
        | (Provider::ObjectStore, Some(value @ LiveConnection::ObjectStore { .. }))
        | (Provider::LinearWork, Some(value @ LiveConnection::LinearWork { .. }))
        | (Provider::GitHubActions, Some(value @ LiveConnection::GitHubActions { .. }))
        | (Provider::GiteaActions, Some(value @ LiveConnection::GiteaActions { .. }))
        | (Provider::OpenAi, Some(value @ LiveConnection::OpenAi { .. })) => value.validate(),
        (
            Provider::LocalNotifications
            // Delegation reaches another application in this same instance, so
            // there is no endpoint and no credential. A connection here would be
            // a claim that something outside is being reached.
            | Provider::LocalDelegation
            | Provider::SyntheticCarta
            | Provider::SyntheticGoogleDirectory
            | Provider::SyntheticLinear
            | Provider::SyntheticOperatorAlerts,
            None,
        ) => Ok(()),
        _ => anyhow::bail!("resource_connection_configuration_mismatch"),
    }
}

impl Catalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported_resource_catalog_version");
        ensure!(
            self.connections.len() <= 256
                && self.resources.len() <= 4096
                && self.policies.len() <= 1024
                && self.budgets.len() <= 1024,
            "resource_catalog_budget"
        );
        let mut providers = BTreeSet::new();
        for (id, connection) in &self.connections {
            name(id)?;
            revision(connection.revision)?;
            validate_connection(connection.provider, connection.live.as_ref())?;
            if connection.live.is_none() {
                ensure!(
                    providers.insert(connection.provider),
                    "duplicate_local_provider_connection"
                );
            }
        }
        for (id, resource) in &self.resources {
            name(id)?;
            revision(resource.revision)?;
            resource.connection.validate()?;
            resource.target.validate()?;
            let connection = self
                .connections
                .get(&resource.connection.id)
                .context("resource_connection_missing")?;
            ensure!(
                connection.revision == resource.connection.revision,
                "resource_connection_revision_changed"
            );
            ensure!(
                provider_matches(connection.provider, resource.target.kind()),
                "resource_provider_kind_mismatch"
            );
        }
        for (id, budget) in &self.budgets {
            name(id)?;
            budget.validate()?;
        }
        for (id, policy) in &self.policies {
            name(id)?;
            revision(policy.revision)?;
            bounded_text(&policy.owner, 256)?;
            ensure!(
                !policy.actors.is_empty()
                    && policy.actors.len() <= 1024
                    && !policy.allowed_apps.is_empty()
                    && policy.allowed_apps.len() <= 1024
                    && !policy.slots.is_empty()
                    && policy.slots.len() <= 64,
                "invalid_reusable_policy_scope"
            );
            for actor in policy.actors.iter().chain(&policy.delegates) {
                bounded_text(actor, 256)?;
            }
            for app in &policy.allowed_apps {
                crate::Name::try_from(app.clone())?;
            }
            if let Some(duration) = policy.max_duration_seconds {
                ensure!(
                    (1..=31_536_000).contains(&duration),
                    "invalid_resource_duration"
                );
            }
            for (slot_name, slot) in &policy.slots {
                name(slot_name)?;
                slot.limits.validate()?;
                ensure!(
                    !slot.allowed_resources.is_empty()
                        && slot.allowed_resources.len() <= 256
                        && !slot.actions.is_empty()
                        && slot.actions.iter().all(|action| action.kind() == slot.kind),
                    "invalid_resource_policy_slot"
                );
                for resource in &slot.allowed_resources {
                    resource.validate()?;
                    ensure!(
                        self.resources
                            .get(&resource.id)
                            .is_some_and(|definition| definition.revision == resource.revision
                                && definition.target.kind() == slot.kind),
                        "policy_resource_kind_or_revision_mismatch"
                    );
                }
                let mut accounts = BTreeSet::new();
                for budget in &slot.budgets {
                    budget.validate()?;
                    ensure!(accounts.insert(&budget.id), "duplicate_resource_budget");
                    ensure!(
                        self.budgets
                            .get(&budget.id)
                            .is_some_and(|definition| definition.revision == budget.revision),
                        "resource_budget_revision_changed"
                    );
                }
            }
        }
        Ok(())
    }

    /// A changed definition needs a new version. Existing activated snapshots
    /// retain old definitions; desired attachments may remain stale until review.
    pub fn validate_successor(&self, next: &Self) -> Result<()> {
        next.validate()?;
        fn changed<T: PartialEq>(
            old: &BTreeMap<String, T>,
            next: &BTreeMap<String, T>,
            version: impl Fn(&T) -> u64,
        ) -> Result<()> {
            for (id, prior) in old {
                if let Some(current) = next.get(id) {
                    ensure!(
                        version(current) >= version(prior)
                            && (current == prior || version(current) > version(prior)),
                        "resource_definition_requires_new_revision: {id}"
                    );
                }
            }
            Ok(())
        }
        changed(&self.connections, &next.connections, |value| value.revision)?;
        changed(&self.resources, &next.resources, |value| value.revision)?;
        changed(&self.policies, &next.policies, |value| value.revision)?;
        changed(&self.budgets, &next.budgets, |value| value.revision)?;
        for (id, prior) in &self.budgets {
            if let Some(current) = next.budgets.get(id) {
                ensure!(
                    prior.scope == current.scope && prior.period_seconds == current.period_seconds,
                    "budget_lineage_is_immutable"
                );
            }
        }
        Ok(())
    }

    pub fn resolve(
        &self,
        app: &str,
        attachments: &[Attachment],
        now_ms: i64,
    ) -> Result<ResolvedResources> {
        self.validate()?;
        ensure!(
            now_ms >= 0 && attachments.len() <= 1024,
            "invalid_resource_resolution"
        );
        let mut resolved = ResolvedResources::default();
        for attachment in attachments {
            attachment.policy.validate()?;
            bounded_text(&attachment.operation, 128)?;
            let policy = self
                .policies
                .get(&attachment.policy.id)
                .context("resource_policy_missing")?;
            ensure!(
                policy.revision == attachment.policy.revision,
                "resource_policy_revision_changed"
            );
            ensure!(
                policy.allowed_apps.contains(app),
                "resource_policy_app_forbidden"
            );
            let actors = attachment.actors.as_ref().unwrap_or(&policy.actors);
            ensure!(
                !actors.is_empty() && actors.is_subset(&policy.actors),
                "resource_policy_actor_widening"
            );
            ensure!(
                attachment.bindings.len() == policy.slots.len(),
                "resource_bindings_incomplete"
            );
            if let Some(expires) = attachment.expires_at_ms {
                ensure!(expires > now_ms, "resource_attachment_expired");
                if let Some(duration) = policy.max_duration_seconds {
                    ensure!(
                        u64::try_from(expires - now_ms)?
                            <= duration
                                .checked_mul(1000)
                                .context("invalid_resource_duration")?,
                        "resource_attachment_duration_exceeded"
                    );
                }
            } else {
                ensure!(
                    policy.max_duration_seconds.is_none(),
                    "resource_attachment_expiry_required"
                );
            }
            for (slot_name, slot) in &policy.slots {
                let binding = attachment
                    .bindings
                    .get(slot_name)
                    .context("resource_binding_missing")?;
                binding.validate()?;
                ensure!(
                    slot.allowed_resources.contains(binding),
                    "resource_binding_outside_policy"
                );
                let resource = self
                    .resources
                    .get(&binding.id)
                    .context("resource_binding_missing")?;
                ensure!(
                    resource.revision == binding.revision,
                    "resource_binding_revision_changed"
                );
                let connection = &self.connections[&resource.connection.id];
                let grant = ResolvedGrant {
                    policy: attachment.policy.clone(),
                    resource: binding.clone(),
                    connection: resource.connection.clone(),
                    provider: connection.provider,
                    live: connection.live.clone(),
                    target: resource.target.clone(),
                    actions: slot.actions.clone(),
                    actors: actors.clone(),
                    limits: slot.limits.clone(),
                    budgets: slot.budgets.clone(),
                    expires_at_ms: attachment.expires_at_ms,
                };
                ensure!(
                    resolved
                        .operations
                        .entry(attachment.operation.clone())
                        .or_default()
                        .insert(slot_name.clone(), grant)
                        .is_none(),
                    "duplicate_operation_resource_binding"
                );
                for budget in &slot.budgets {
                    resolved
                        .budgets
                        .insert(budget.id.clone(), self.budgets[&budget.id].clone());
                }
            }
        }
        resolved.validate()?;
        Ok(resolved)
    }
}

impl ResolvedResources {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty() && self.budgets.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.operations.len() <= 1024 && self.budgets.len() <= 1024,
            "resolved_resource_budget"
        );
        for budget in self.budgets.values() {
            budget.validate()?;
        }
        let mut used = BTreeSet::new();
        for (operation, bindings) in &self.operations {
            bounded_text(operation, 128)?;
            ensure!(
                !bindings.is_empty() && bindings.len() <= 64,
                "invalid_resolved_bindings"
            );
            for (slot, grant) in bindings {
                name(slot)?;
                grant.policy.validate()?;
                grant.resource.validate()?;
                grant.connection.validate()?;
                validate_connection(grant.provider, grant.live.as_ref())?;
                grant.target.validate()?;
                grant.limits.validate()?;
                ensure!(
                    provider_matches(grant.provider, grant.target.kind())
                        && !grant.actions.is_empty()
                        && grant
                            .actions
                            .iter()
                            .all(|action| action.kind() == grant.target.kind())
                        && !grant.actors.is_empty(),
                    "invalid_resolved_resource_grant"
                );
                for actor in &grant.actors {
                    bounded_text(actor, 256)?;
                }
                if let Some(expires) = grant.expires_at_ms {
                    ensure!(expires > 0, "invalid_resource_expiry");
                }
                let mut accounts = BTreeSet::new();
                for budget in &grant.budgets {
                    budget.validate()?;
                    ensure!(accounts.insert(&budget.id), "duplicate_resource_budget");
                    ensure!(
                        self.budgets
                            .get(&budget.id)
                            .is_some_and(|definition| definition.revision == budget.revision),
                        "resolved_budget_revision_mismatch"
                    );
                    used.insert(&budget.id);
                }
                if grant.provider == Provider::Snowflake {
                    ensure!(
                        grant
                            .budgets
                            .iter()
                            .all(|reference| self.budgets[&reference.id]
                                .limits
                                .cost_microunits
                                .is_none()),
                        "snowflake_monetary_bound_not_qualified"
                    );
                }
                if grant.provider == Provider::OpenAi {
                    ensure!(
                        grant
                            .budgets
                            .iter()
                            .any(|reference| self.budgets[&reference.id]
                                .limits
                                .cost_microunits
                                .is_some()),
                        "model_monetary_budget_required"
                    );
                }
            }
        }
        ensure!(
            used.len() == self.budgets.len(),
            "unreferenced_resource_budget"
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
