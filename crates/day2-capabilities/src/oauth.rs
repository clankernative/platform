//! Portable OAuth authority contracts. Protocol state and secret material live in
//! the host, never in this provider-free crate or an application artifact.

use crate::{BindingRef, Digest, Name};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBindingPolicy {
    MappedHuman,
    ExplicitExternalAccount,
    InstallationAccount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOwner {
    CurrentHuman,
    Installation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlotOwner {
    Human { subject: String },
    Installation,
}

/// The unique v1 logical slot deliberately omits connection and binding
/// generation. Rebinding therefore cannot create a second active slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSlotKey {
    pub installation: Name,
    pub environment: Name,
    pub app: Name,
    pub requirement: String,
    pub owner: SlotOwner,
}

impl ConnectionSlotKey {
    pub fn id(&self, requirement: &ConnectionRequirement) -> Result<Digest> {
        requirement.validate()?;
        ensure!(
            self.requirement == requirement.logical_id,
            "connection slot requirement mismatch"
        );
        ensure!(
            matches!(
                (&self.owner, &requirement.owner),
                (SlotOwner::Human { .. }, ConnectionOwner::CurrentHuman)
                    | (SlotOwner::Installation, ConnectionOwner::Installation)
            ),
            "connection slot owner category mismatch"
        );
        if let SlotOwner::Human { subject } = &self.owner {
            ensure!(
                !subject.is_empty()
                    && subject.len() <= 256
                    && !subject.chars().any(|c| c.is_whitespace() || c.is_control()),
                "invalid OAuth human owner"
            );
        }
        Digest::of(&("oauth-connection-slot-v1", self))
    }
}

/// One authored requirement. `usage` is consent text, not nominal type identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRequirement {
    pub logical_id: String,
    pub revision: u32,
    pub capability: String,
    pub actions: BTreeSet<String>,
    pub owner: ConnectionOwner,
    pub account_policy: AccountBindingPolicy,
    pub usage: String,
}

/// Derived from one checked App.definition.connections registration. Instance
/// configuration selects this requirement; it never authors another copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDeclaration {
    pub registration: Name,
    pub requirement: ConnectionRequirement,
}

/// Company selection over one app-owned registration. This contains references,
/// never a second requirement declaration, provider scopes or secret bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConnectionBinding {
    pub namespace: crate::credentials::Namespace,
    pub requirement: Digest,
    pub profile: BindingRef,
    pub registration: BindingRef,
    pub custody: BindingRef,
    pub security_shell: SecurityOriginRef,
    pub account_binding: BindingRef,
    pub shell_attestation: BindingRef,
    pub product_return: ProductReturnRef,
    /// Names in InstallationControl.secrets, each with a numeric version.
    pub custody_verifier_secret: Name,
    pub custody_encryption_secret: Name,
    pub shell_attestation_secret: Name,
}

/// One authenticated security-shell workload for private app-host RPC. Target
/// locations and numeric IAP audiences reuse the ordinary selected app edges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellTransport {
    pub service_account: String,
}

/// Installation selection for the native GKE readiness adapter. These are
/// resource selectors and account ceilings, never evidence or a ready flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCatalog {
    pub version: u32,
    pub shell: GcpShellSelection,
    /// Bounds for the separate stateless, single-replica Linux shell launcher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_resources: Option<crate::runtime::Resources>,
    pub apps: BTreeMap<Name, RuntimeApp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpShellSelection {
    pub project: String,
    pub backend_service: String,
    pub url_map: String,
    pub https_proxy: String,
    pub forwarding_rule: String,
    /// Exact Kubernetes namespace/service recorded by the GKE ingress controller.
    pub kubernetes_service: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeApp {
    pub service_account: String,
    /// Keys are the app's declared connection registration names.
    pub accounts: BTreeMap<Name, GoogleAccountPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GoogleAccountPolicy {
    IapSubject,
    ExternalAccounts {
        allowed_tenants: BTreeSet<String>,
        allowed_subjects: Option<BTreeSet<String>>,
    },
}

impl RuntimeCatalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported OAuth runtime catalog version"
        );
        if let Some(resources) = &self.shell_resources {
            resources.validate()?;
        }
        ensure!(
            !self.apps.is_empty() && self.apps.len() <= 128,
            "OAuth runtime app budget"
        );
        let shell = &self.shell;
        ShellTransport {
            service_account: format!("readiness@{}.iam.gserviceaccount.com", shell.project),
        }
        .validate()?;
        for resource in [
            &shell.backend_service,
            &shell.url_map,
            &shell.https_proxy,
            &shell.forwarding_rule,
        ] {
            ensure!(
                (1..=63).contains(&resource.len())
                    && resource.as_bytes()[0].is_ascii_lowercase()
                    && resource
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && resource
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "invalid OAuth Compute resource selector"
            );
        }
        let parts: Vec<_> = shell.kubernetes_service.split('/').collect();
        ensure!(
            parts.len() == 2,
            "invalid OAuth Kubernetes service selector"
        );
        for part in parts {
            ensure!(
                !part.is_empty()
                    && part.len() <= 63
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && part.as_bytes()[0].is_ascii_alphanumeric()
                    && part
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric),
                "invalid OAuth Kubernetes service selector"
            );
        }
        for app in self.apps.values() {
            ShellTransport {
                service_account: app.service_account.clone(),
            }
            .validate()?;
            ensure!(
                !app.accounts.is_empty() && app.accounts.len() <= 64,
                "OAuth runtime account budget"
            );
            for policy in app.accounts.values() {
                if let GoogleAccountPolicy::ExternalAccounts {
                    allowed_tenants,
                    allowed_subjects,
                } = policy
                {
                    ensure!(
                        !allowed_tenants.is_empty()
                            && allowed_tenants.len() <= 64
                            && allowed_subjects
                                .as_ref()
                                .is_none_or(|s| !s.is_empty() && s.len() <= 64),
                        "OAuth external account ceiling budget"
                    );
                    for tenant in allowed_tenants {
                        crate::host_name(tenant)?;
                    }
                    for subject in allowed_subjects.iter().flatten() {
                        ensure!(
                            !subject.is_empty()
                                && subject.len() <= 256
                                && subject.bytes().all(|b| b.is_ascii_graphic()),
                            "invalid OAuth external account subject"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_selection_is_closed_bounded_and_contains_only_desired_selectors() -> Result<()> {
        let value = json!({"version":1,"shell":{"project":"company-tools","backend_service":"shell-backend","url_map":"shell-map","https_proxy":"shell-proxy","forwarding_rule":"shell-https","kubernetes_service":"tools/security-shell"},
            "apps":{"workspace":{"service_account":"app@company-tools.iam.gserviceaccount.com","accounts":{"calendar":{"kind":"external_accounts","allowed_tenants":["example.com"],"allowed_subjects":["immutable-google-subject"]}}}}});
        serde_json::from_value::<RuntimeCatalog>(value.clone())?.validate()?;
        let mut bounded = value.clone();
        bounded["shell_resources"] = json!({"memory_mib":512,"cpu_millis":500,"process_limit":1024,
            "process_limit_enforced_by":"pod","http_concurrency":4,"shutdown_seconds":30});
        let selected: RuntimeCatalog = serde_json::from_value(bounded.clone())?;
        selected.validate()?;
        assert_eq!(serde_json::to_value(selected)?, bounded);
        for field in ["ready", "replicas", "database", "command"] {
            let mut wrong = bounded.clone();
            wrong["shell_resources"][field] = json!(true);
            assert!(serde_json::from_value::<RuntimeCatalog>(wrong).is_err());
        }
        bounded["shell_resources"]["http_concurrency"] = json!(33);
        assert!(serde_json::from_value::<RuntimeCatalog>(bounded).is_err());
        for field in ["ready", "origin", "qualification", "receipt", "secret"] {
            let mut wrong = value.clone();
            wrong[field] = json!(true);
            assert!(serde_json::from_value::<RuntimeCatalog>(wrong).is_err());
        }
        for (field, substitution) in [
            ("project", "other/../project"),
            ("backend_service", "https://attacker.example"),
            ("url_map", "map?redirect=1"),
            ("https_proxy", "../proxy"),
            ("forwarding_rule", "https-rule/other"),
            ("kubernetes_service", "tools/app/extra"),
        ] {
            let mut wrong = value.clone();
            wrong["shell"][field] = json!(substitution);
            assert!(
                serde_json::from_value::<RuntimeCatalog>(wrong)?
                    .validate()
                    .is_err()
            );
        }
        let mut wrong = value.clone();
        wrong["apps"]["workspace"]["accounts"]["calendar"]["allowed_tenants"] = json!([]);
        assert!(
            serde_json::from_value::<RuntimeCatalog>(wrong)?
                .validate()
                .is_err()
        );
        let mut wrong = value.clone();
        wrong["apps"]["workspace"]["accounts"]["calendar"]["allowed_subjects"] = json!([]);
        assert!(
            serde_json::from_value::<RuntimeCatalog>(wrong)?
                .validate()
                .is_err()
        );
        let mut wrong = value;
        wrong["apps"]["workspace"]["service_account"] = json!("operator@example.com");
        assert!(
            serde_json::from_value::<RuntimeCatalog>(wrong)?
                .validate()
                .is_err()
        );
        Ok(())
    }
}

/// Desired client metadata only. Secret bytes and qualification receipts are
/// never part of the installation document. Addresses come from selected edges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCatalog {
    pub version: u32,
    pub reauthentication: GoogleWebClient,
    pub registrations: BTreeMap<Name, GoogleRegistrationClient>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleWebClient {
    pub client_id: String,
    /// Logical name in InstallationControl.secrets, with an exact numeric version.
    pub credential: Name,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleRegistrationClient {
    pub client: GoogleWebClient,
    /// Immutable Google subject of an isolated, explicitly selected canary user.
    pub canary_subject: String,
    pub canary_tenant: String,
}

impl GoogleWebClient {
    pub fn validate(&self) -> Result<()> {
        let local = self.client_id.strip_suffix(".apps.googleusercontent.com");
        ensure!(
            self.client_id.len() <= 255
                && local.is_some_and(|local| !local.is_empty()
                    && local
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')),
            "invalid Google web client"
        );
        Ok(())
    }
}

impl ClientCatalog {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported OAuth client catalog version"
        );
        ensure!(
            self.registrations.len() <= 128,
            "OAuth client catalog budget"
        );
        self.reauthentication.validate()?;
        for selected in self.registrations.values() {
            selected.client.validate()?;
            ensure!(
                selected.client.client_id != self.reauthentication.client_id
                    && selected.client.credential != self.reauthentication.credential,
                "OAuth reauthentication and provider clients must be distinct"
            );
            ensure!(
                !selected.canary_subject.is_empty()
                    && selected.canary_subject.len() <= 255
                    && selected
                        .canary_subject
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic()),
                "invalid Google canary subject"
            );
            crate::host_name(&selected.canary_tenant)?;
        }
        Ok(())
    }
}

impl ShellTransport {
    pub fn validate(&self) -> Result<()> {
        let (local, domain) = self
            .service_account
            .split_once('@')
            .ok_or_else(|| anyhow::anyhow!("invalid OAuth shell workload"))?;
        let project = domain
            .strip_suffix(".iam.gserviceaccount.com")
            .ok_or_else(|| anyhow::anyhow!("invalid OAuth shell workload domain"))?;
        ensure!(
            !local.is_empty()
                && self.service_account.len() <= 254
                && self
                    .service_account
                    .bytes()
                    .filter(|byte| *byte == b'@')
                    .count()
                    == 1
                && (6..=30).contains(&project.len())
                && project.as_bytes()[0].is_ascii_lowercase()
                && project
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && project
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && self
                    .service_account
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || b"@._-".contains(&byte)),
            "invalid OAuth shell workload"
        );
        Ok(())
    }
}

impl ConnectionRequirement {
    pub fn validate(&self) -> Result<()> {
        identifier(&self.logical_id)?;
        identifier(&self.capability)?;
        ensure!(self.revision > 0, "invalid requirement revision");
        ensure!(
            !self.actions.is_empty() && self.actions.len() <= 32,
            "invalid requirement action budget"
        );
        for action in &self.actions {
            identifier(action)?;
        }
        ensure!(
            !self.usage.trim().is_empty() && self.usage.len() <= 1024,
            "invalid connection usage"
        );
        ensure!(
            matches!(
                (&self.owner, &self.account_policy),
                (
                    ConnectionOwner::CurrentHuman,
                    AccountBindingPolicy::MappedHuman
                ) | (
                    ConnectionOwner::CurrentHuman,
                    AccountBindingPolicy::ExplicitExternalAccount
                ) | (
                    ConnectionOwner::Installation,
                    AccountBindingPolicy::InstallationAccount
                )
            ),
            "account policy does not match connection owner"
        );
        Ok(())
    }

    /// Stable across source moves, unrelated app changes and wire-only profile fixes.
    pub fn nominal_identity(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&(
            "oauth-requirement-nominal-v1",
            &self.logical_id,
            self.revision,
            &self.capability,
            &self.actions,
            &self.owner,
            &self.account_policy,
        ))
    }
}

/// An exact reviewed provider permission interpretation. String scopes alone
/// cannot establish that a profile revision has unchanged authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPermissionContract {
    pub requirement: Digest,
    pub profile: BindingRef,
    pub action_scopes: BTreeMap<String, BTreeSet<String>>,
    pub interpretation: Digest,
}

impl ProviderPermissionContract {
    pub fn validate(&self, requirement: &ConnectionRequirement) -> Result<()> {
        ensure!(
            self.requirement == requirement.nominal_identity()?,
            "provider mapping belongs to another requirement"
        );
        ensure!(
            self.action_scopes.keys().cloned().collect::<BTreeSet<_>>() == requirement.actions,
            "provider mapping must cover exactly the semantic actions"
        );
        for scopes in self.action_scopes.values() {
            ensure!(
                !scopes.is_empty() && scopes.len() <= 32,
                "invalid provider scope budget"
            );
            for scope in scopes {
                ensure!(
                    !scope.is_empty() && scope.len() <= 256 && !scope.chars().any(char::is_control),
                    "invalid provider scope"
                );
            }
        }
        Ok(())
    }

    pub fn consent_digest(&self, requirement: &ConnectionRequirement) -> Result<Digest> {
        self.validate(requirement)?;
        Digest::of(&("oauth-provider-permissions-v1", self))
    }
}

/// Immutable outbound consent evidence for one verified account and logical
/// slot. A later provider mapping cannot silently enlarge this ceiling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConsentAffinity {
    pub slot: Digest,
    pub account: Digest,
    pub registration: BindingRef,
    pub binding: BindingRef,
    pub security_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConsentCeiling {
    pub requirement: Digest,
    pub affinity: OutboundConsentAffinity,
    pub actions: BTreeSet<String>,
    pub permission: Digest,
    pub requested_scopes: BTreeSet<String>,
    pub accepted_scopes: BTreeSet<String>,
    pub digest: Digest,
}

impl OutboundConsentCeiling {
    pub fn derive(
        requirement: &ConnectionRequirement,
        permission: &ProviderPermissionContract,
        affinity: OutboundConsentAffinity,
        accepted_scopes: BTreeSet<String>,
    ) -> Result<Self> {
        let requirement_id = requirement.nominal_identity()?;
        let permission_id = permission.consent_digest(requirement)?;
        let requested_scopes = permission
            .action_scopes
            .values()
            .flat_map(|scopes| scopes.iter().cloned())
            .collect::<BTreeSet<_>>();
        ensure!(
            !requested_scopes.is_empty() && requested_scopes == accepted_scopes,
            "missing or unreviewed provider scopes"
        );
        ensure!(
            affinity.security_epoch > 0,
            "invalid outbound security epoch"
        );
        let actions = requirement.actions.clone();
        let digest = Digest::of(&(
            "oauth-outbound-consent-v1",
            &requirement_id,
            &affinity,
            &actions,
            &permission_id,
            &requested_scopes,
            &accepted_scopes,
        ))?;
        Ok(Self {
            requirement: requirement_id,
            affinity,
            actions,
            permission: permission_id,
            requested_scopes,
            accepted_scopes,
            digest,
        })
    }

    pub fn verify_digest(&self) -> Result<()> {
        let expected = Digest::of(&(
            "oauth-outbound-consent-v1",
            &self.requirement,
            &self.affinity,
            &self.actions,
            &self.permission,
            &self.requested_scopes,
            &self.accepted_scopes,
        ))?;
        ensure!(
            self.digest == expected,
            "outbound consent ceiling digest mismatch"
        );
        Ok(())
    }

    pub fn allows(
        &self,
        action: &str,
        requirement: &ConnectionRequirement,
        permission: &ProviderPermissionContract,
        affinity: &OutboundConsentAffinity,
    ) -> Result<bool> {
        self.verify_digest()?;
        Ok(self.requirement == requirement.nominal_identity()?
            && self.permission == permission.consent_digest(requirement)?
            && self.actions.contains(action)
            && &self.affinity == affinity)
    }
}

// Each address role has its own type. References pin reviewed instance bindings;
// no app-provided URL can be substituted for a callback, issuer or audience.
macro_rules! role_ref {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub BindingRef);
    };
}
role_ref!(SecurityOriginRef);
role_ref!(ProviderIssuerRef);
role_ref!(AuthorizationIssuerRef);
role_ref!(ResourceAudienceRef);
role_ref!(ProductReturnRef);
role_ref!(OAuthClientRedirectRef);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderCallbackRef(BindingRef);

impl ProviderCallbackRef {
    /// The callback identity is derived from the security shell and full
    /// connection-binding namespace, rather than an app-controlled URL.
    pub fn derive(
        security_origin: &SecurityOriginRef,
        profile: &BindingRef,
        binding_namespace: &str,
    ) -> Result<Self> {
        identifier(binding_namespace)?;
        let revision = Digest::of(&(
            "oauth-provider-callback-v1",
            security_origin,
            profile,
            binding_namespace,
        ))?;
        let id = crate::Name::try_from("oauth-provider-callback".to_owned())?;
        Ok(Self(BindingRef { id, revision }))
    }

    pub fn verify_derived(
        &self,
        security_origin: &SecurityOriginRef,
        profile: &BindingRef,
        binding_namespace: &str,
    ) -> Result<()> {
        ensure!(
            self == &Self::derive(security_origin, profile, binding_namespace)?,
            "provider callback binding mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityAction {
    LocalData {
        category: String,
        policy: Digest,
        write: bool,
    },
    Provider {
        requirement: Digest,
        action: String,
        permission: Digest,
        write: bool,
    },
    Resource {
        policy: Digest,
        write: bool,
    },
}

/// A path-preserving upper bound. A child cannot borrow another child's actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityNode {
    pub actions: BTreeSet<AuthorityAction>,
    pub children: BTreeMap<String, AuthorityNode>,
}

impl AuthorityNode {
    pub fn validate(&self) -> Result<()> {
        self.validate_at(0)
    }

    fn validate_at(&self, depth: usize) -> Result<()> {
        ensure!(depth <= 16, "authority dependency depth budget");
        ensure!(
            self.actions.len() <= 128 && self.children.len() <= 64,
            "authority node budget"
        );
        for action in &self.actions {
            match action {
                AuthorityAction::LocalData { category, .. } => identifier(category)?,
                AuthorityAction::Provider { action, .. } => identifier(action)?,
                AuthorityAction::Resource { .. } => {}
            }
        }
        for (edge, child) in &self.children {
            identifier(edge)?;
            child.validate_at(depth + 1)?;
        }
        Ok(())
    }

    pub fn is_within(&self, ceiling: &Self) -> bool {
        self.actions.is_subset(&ceiling.actions)
            && self.children.iter().all(|(edge, child)| {
                ceiling
                    .children
                    .get(edge)
                    .is_some_and(|allowed| child.is_within(allowed))
            })
    }

    fn has_write(&self) -> bool {
        self.actions.iter().any(|action| match action {
            AuthorityAction::LocalData { write, .. }
            | AuthorityAction::Provider { write, .. }
            | AuthorityAction::Resource { write, .. } => *write,
        }) || self.children.values().any(Self::has_write)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Query,
    Command,
}

/// Derived from one canonical registered operation, not an OAuth-specific list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationAuthorityContract {
    pub operation: String,
    pub version: u32,
    pub operation_contract: Digest,
    pub kind: OperationKind,
    pub closure: AuthorityNode,
    pub digest: Digest,
}

/// OAuth exposure is a separate selection over canonical operation contracts.
/// Its selectors pin exact permissions; adding a channel member cannot enlarge
/// a previously issued grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientChannelContract {
    pub channel: String,
    pub operations: BTreeMap<String, OperationAuthorityContract>,
    pub digest: Digest,
}

impl ClientChannelContract {
    pub fn derive(
        channel: String,
        operations: BTreeMap<String, OperationAuthorityContract>,
    ) -> Result<Self> {
        identifier(&channel)?;
        ensure!(
            !operations.is_empty() && operations.len() <= 256,
            "invalid OAuth channel membership budget"
        );
        for (key, operation) in &operations {
            operation.verify()?;
            ensure!(
                key == &operation.operation,
                "channel member identity mismatch"
            );
        }
        let digest = Digest::of(&("oauth-channel-consent-v1", &channel, &operations))?;
        Ok(Self {
            channel,
            operations,
            digest,
        })
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            *self == Self::derive(self.channel.clone(), self.operations.clone())?,
            "OAuth channel consent digest mismatch"
        );
        Ok(())
    }

    pub fn selector(&self, operation: &str) -> Result<Digest> {
        self.verify()?;
        let member = self
            .operations
            .get(operation)
            .ok_or_else(|| anyhow::anyhow!("operation is not exposed by OAuth channel"))?;
        Digest::of(&(
            "oauth-operation-selector-v1",
            &self.channel,
            &member.operation,
            member.version,
            &member.digest,
        ))
    }

    pub fn grant(
        &self,
        client: BindingRef,
        subject: String,
        audience: ResourceAudienceRef,
        roots: &BTreeSet<String>,
    ) -> Result<GrantCeiling> {
        self.verify()?;
        ensure!(!roots.is_empty(), "empty OAuth consent selection");
        let selected = roots
            .iter()
            .map(|root| {
                let member = self
                    .operations
                    .get(root)
                    .ok_or_else(|| anyhow::anyhow!("consent selected unexposed operation"))?;
                Ok((root.clone(), member.clone()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        GrantCeiling::derive(client, subject, audience, selected)
    }
}

impl OperationAuthorityContract {
    pub fn derive(
        operation: String,
        version: u32,
        operation_contract: Digest,
        kind: OperationKind,
        closure: AuthorityNode,
    ) -> Result<Self> {
        identifier(&operation)?;
        ensure!(version > 0, "invalid operation version");
        closure.validate()?;
        ensure!(
            !matches!(kind, OperationKind::Query) || !closure.has_write(),
            "query cannot reach a write"
        );
        let digest = Digest::of(&(
            "oauth-authority-v1",
            &operation,
            version,
            &operation_contract,
            &kind,
            &closure,
        ))?;
        Ok(Self {
            operation,
            version,
            operation_contract,
            kind,
            closure,
            digest,
        })
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            *self
                == Self::derive(
                    self.operation.clone(),
                    self.version,
                    self.operation_contract.clone(),
                    self.kind.clone(),
                    self.closure.clone(),
                )?,
            "operation authority digest mismatch"
        );
        Ok(())
    }
}

/// Immutable consent snapshot. Revocation and current channel exposure are
/// separate live checks; they cannot rewrite or enlarge this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCeiling {
    pub client: BindingRef,
    pub subject: String,
    pub audience: ResourceAudienceRef,
    pub roots: BTreeMap<String, OperationAuthorityContract>,
    pub digest: Digest,
}

impl GrantCeiling {
    pub fn derive(
        client: BindingRef,
        subject: String,
        audience: ResourceAudienceRef,
        roots: BTreeMap<String, OperationAuthorityContract>,
    ) -> Result<Self> {
        // Canonical identity-provider subjects are opaque principal identities,
        // e.g. IAP's accounts.google.com:<id>, not operation identifiers.
        ensure!(
            !subject.is_empty()
                && subject.len() <= 256
                && subject.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid grant principal"
        );
        ensure!(
            !roots.is_empty() && roots.len() <= 256,
            "invalid grant root budget"
        );
        for (key, root) in &roots {
            root.verify()?;
            ensure!(key == &root.operation, "grant root identity mismatch");
        }
        let digest = Digest::of(&(
            "oauth-grant-ceiling-v1",
            &client,
            &subject,
            &audience,
            &roots,
        ))?;
        Ok(Self {
            client,
            subject,
            audience,
            roots,
            digest,
        })
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            *self
                == Self::derive(
                    self.client.clone(),
                    self.subject.clone(),
                    self.audience.clone(),
                    self.roots.clone()
                )?,
            "grant ceiling digest mismatch"
        );
        Ok(())
    }

    /// The caller must separately check current channel membership, subject,
    /// client, audience, epochs and downstream target policies.
    pub fn allows(&self, current: &OperationAuthorityContract) -> Result<bool> {
        self.verify()?;
        current.verify()?;
        Ok(self.roots.get(&current.operation).is_some_and(|approved| {
            approved.version == current.version
                && approved.operation_contract == current.operation_contract
                && approved.kind == current.kind
                && current.closure.is_within(&approved.closure)
        }))
    }
}

fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte)),
        "invalid OAuth contract identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Name;

    fn pin(name: &str) -> BindingRef {
        BindingRef::pin(Name::try_from(name.to_owned()).unwrap(), &name).unwrap()
    }

    fn requirement() -> ConnectionRequirement {
        ConnectionRequirement {
            logical_id: "workspace.calendar".into(),
            revision: 1,
            capability: "google.calendar.events".into(),
            actions: BTreeSet::from(["list".into()]),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: AccountBindingPolicy::MappedHuman,
            usage: "Show calendar events".into(),
        }
    }

    fn root(children: BTreeMap<String, AuthorityNode>) -> OperationAuthorityContract {
        OperationAuthorityContract::derive(
            "ghostwright.publish".into(),
            1,
            Digest::of(&"operation").unwrap(),
            OperationKind::Command,
            AuthorityNode {
                actions: BTreeSet::new(),
                children,
            },
        )
        .unwrap()
    }

    fn grant(root: OperationAuthorityContract) -> GrantCeiling {
        GrantCeiling::derive(
            pin("client"),
            "human_1".into(),
            ResourceAudienceRef(pin("resource")),
            BTreeMap::from([(root.operation.clone(), root)]),
        )
        .unwrap()
    }

    #[test]
    fn requirement_nominal_identity_ignores_text_and_provider_wire_mapping() {
        let mut first = requirement();
        let identity = first.nominal_identity().unwrap();
        first.usage = "Different explanation".into();
        assert_eq!(identity, first.nominal_identity().unwrap());
        let mapping = ProviderPermissionContract {
            requirement: identity.clone(),
            profile: pin("profile"),
            action_scopes: BTreeMap::from([(
                "list".into(),
                BTreeSet::from(["calendar.read".into()]),
            )]),
            interpretation: Digest::of(&"read-v1").unwrap(),
        };
        let old_consent = mapping.consent_digest(&first).unwrap();
        let mut changed = mapping.clone();
        changed.interpretation = Digest::of(&"broader-read-v2").unwrap();
        assert_ne!(old_consent, changed.consent_digest(&first).unwrap());
        assert_eq!(identity, first.nominal_identity().unwrap());
        first.actions.insert("create".into());
        assert_ne!(identity, first.nominal_identity().unwrap());
        assert!(mapping.validate(&first).is_err());
    }

    #[test]
    fn requirement_wire_fixture_is_stable_and_closed() {
        let expected = concat!(
            "{\"logical_id\":\"workspace.calendar\",\"revision\":1,",
            "\"capability\":\"google.calendar.events\",\"actions\":[\"list\"],",
            "\"owner\":\"current_human\",\"account_policy\":\"mapped_human\",",
            "\"usage\":\"Show calendar events\"}"
        );
        let authored = requirement();
        assert_eq!(serde_json::to_string(&authored).unwrap(), expected);
        let decoded: ConnectionRequirement = serde_json::from_str(expected).unwrap();
        assert_eq!(
            decoded.nominal_identity().unwrap(),
            authored.nominal_identity().unwrap()
        );
        let mut unknown: serde_json::Value = serde_json::from_str(expected).unwrap();
        unknown["provider_scopes"] = serde_json::json!(["calendar.write"]);
        assert!(serde_json::from_value::<ConnectionRequirement>(unknown).is_err());
    }

    #[test]
    fn owner_policy_is_closed_and_required() {
        let mut requirement = requirement();
        requirement.account_policy = AccountBindingPolicy::InstallationAccount;
        assert!(requirement.validate().is_err());
        let mut encoded = serde_json::to_value(requirement).unwrap();
        encoded["account_policy"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<ConnectionRequirement>(encoded).is_err());
    }

    #[test]
    fn slot_identity_covers_owner_and_namespace_but_not_generation() {
        let mut slot = ConnectionSlotKey {
            installation: Name::try_from("company".to_owned()).unwrap(),
            environment: Name::try_from("production".to_owned()).unwrap(),
            app: Name::try_from("workspace".to_owned()).unwrap(),
            requirement: "workspace.calendar".into(),
            owner: SlotOwner::Human {
                subject: "human_1".into(),
            },
        };
        let first = slot.id(&requirement()).unwrap();
        slot.owner = SlotOwner::Human {
            subject: "human_2".into(),
        };
        assert_ne!(first, slot.id(&requirement()).unwrap());
        slot.owner = SlotOwner::Installation;
        assert!(slot.id(&requirement()).is_err());
        slot.owner = SlotOwner::Human {
            subject: "human_1".into(),
        };
        slot.requirement = "workspace.other".into();
        assert!(slot.id(&requirement()).is_err());
    }

    #[test]
    fn human_slot_owner_accepts_opaque_iap_principals_and_rejects_empty_or_ambiguous_text() {
        let mut slot = ConnectionSlotKey {
            installation: Name::try_from("company".to_owned()).unwrap(),
            environment: Name::try_from("production".to_owned()).unwrap(),
            app: Name::try_from("workspace".to_owned()).unwrap(),
            requirement: "workspace.calendar".into(),
            owner: SlotOwner::Installation,
        };
        for subject in ["ada@example.com", "accounts.google.com:1234567890"] {
            slot.owner = SlotOwner::Human {
                subject: subject.into(),
            };
            slot.id(&requirement()).unwrap();
        }
        for subject in [
            "",
            " ada@example.com",
            "ada\n@example.com",
            &"x".repeat(257),
        ] {
            slot.owner = SlotOwner::Human {
                subject: subject.into(),
            };
            assert!(slot.id(&requirement()).is_err());
        }
    }

    #[test]
    fn outbound_consent_rejects_profile_scope_expansion_without_changing_nominal_type() {
        let requirement = requirement();
        let nominal = requirement.nominal_identity().unwrap();
        let original = ProviderPermissionContract {
            requirement: nominal.clone(),
            profile: pin("google"),
            action_scopes: BTreeMap::from([(
                "list".into(),
                BTreeSet::from(["calendar.read".into()]),
            )]),
            interpretation: Digest::of(&"read-v1").unwrap(),
        };
        let slot = Digest::of(&"slot").unwrap();
        let account = Digest::of(&"stable account").unwrap();
        let affinity = OutboundConsentAffinity {
            slot,
            account,
            registration: pin("registration"),
            binding: pin("binding"),
            security_epoch: 1,
        };
        let ceiling = OutboundConsentCeiling::derive(
            &requirement,
            &original,
            affinity.clone(),
            BTreeSet::from(["calendar.read".into()]),
        )
        .unwrap();
        assert!(
            ceiling
                .allows("list", &requirement, &original, &affinity)
                .unwrap()
        );
        let mut broader = original;
        broader
            .action_scopes
            .get_mut("list")
            .unwrap()
            .insert("calendar.write".into());
        assert_eq!(nominal, requirement.nominal_identity().unwrap());
        assert!(
            !ceiling
                .allows("list", &requirement, &broader, &affinity)
                .unwrap()
        );
        let mut new_epoch = affinity;
        new_epoch.security_epoch = 2;
        assert!(
            !ceiling
                .allows("list", &requirement, &broader, &new_epoch)
                .unwrap()
        );
        let mut forged = ceiling;
        forged.actions.insert("create".into());
        assert!(forged.verify_digest().is_err());
    }

    #[test]
    fn consent_preserves_paths_and_refuses_new_authority() {
        let read = AuthorityAction::LocalData {
            category: "article".into(),
            policy: Digest::of(&"read").unwrap(),
            write: false,
        };
        let write = AuthorityAction::LocalData {
            category: "article".into(),
            policy: Digest::of(&"write").unwrap(),
            write: true,
        };
        let prior = root(BTreeMap::from([(
            "directory.lookup".into(),
            AuthorityNode {
                actions: BTreeSet::from([read.clone()]),
                children: BTreeMap::new(),
            },
        )]));
        let ceiling = grant(prior.clone());
        assert!(ceiling.allows(&prior).unwrap());
        let expanded = root(BTreeMap::from([(
            "directory.lookup".into(),
            AuthorityNode {
                actions: BTreeSet::from([read, write]),
                children: BTreeMap::new(),
            },
        )]));
        assert!(!ceiling.allows(&expanded).unwrap());
        let moved = root(BTreeMap::from([(
            "notices.send".into(),
            expanded.closure.children["directory.lookup"].clone(),
        )]));
        assert!(!ceiling.allows(&moved).unwrap());
        let mut tampered = ceiling;
        tampered.roots.insert("new.root".into(), expanded);
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn query_cannot_reach_provider_write_through_child() {
        let write = AuthorityNode {
            actions: BTreeSet::from([AuthorityAction::Provider {
                requirement: Digest::of(&"calendar").unwrap(),
                action: "create".into(),
                permission: Digest::of(&"scope").unwrap(),
                write: true,
            }]),
            children: BTreeMap::new(),
        };
        assert!(
            OperationAuthorityContract::derive(
                "app.query".into(),
                1,
                Digest::of(&"operation").unwrap(),
                OperationKind::Query,
                AuthorityNode {
                    actions: BTreeSet::new(),
                    children: BTreeMap::from([("child".into(), write)])
                },
            )
            .is_err()
        );
    }

    #[test]
    fn callback_identity_is_derived_from_every_binding_role() {
        let shell = SecurityOriginRef(pin("security"));
        let profile = pin("google");
        let callback =
            ProviderCallbackRef::derive(&shell, &profile, "installation.env.calendar").unwrap();
        callback
            .verify_derived(&shell, &profile, "installation.env.calendar")
            .unwrap();
        assert!(
            callback
                .verify_derived(&shell, &profile, "other.env.calendar")
                .is_err()
        );
        assert!(
            callback
                .verify_derived(&shell, &pin("other"), "installation.env.calendar")
                .is_err()
        );
    }

    #[test]
    fn adding_channel_member_changes_offer_but_not_old_grant() {
        let publish = root(BTreeMap::new());
        let initial = ClientChannelContract::derive(
            "mcp".into(),
            BTreeMap::from([(publish.operation.clone(), publish.clone())]),
        )
        .unwrap();
        let old_selector = initial.selector(&publish.operation).unwrap();
        let old_grant = initial
            .grant(
                pin("client"),
                "human_1".into(),
                ResourceAudienceRef(pin("resource")),
                &BTreeSet::from([publish.operation.clone()]),
            )
            .unwrap();
        let read = OperationAuthorityContract::derive(
            "ghostwright.read".into(),
            1,
            Digest::of(&"read-contract").unwrap(),
            OperationKind::Query,
            AuthorityNode {
                actions: BTreeSet::new(),
                children: BTreeMap::new(),
            },
        )
        .unwrap();
        let expanded = ClientChannelContract::derive(
            "mcp".into(),
            BTreeMap::from([
                (publish.operation.clone(), publish.clone()),
                (read.operation.clone(), read.clone()),
            ]),
        )
        .unwrap();
        assert_ne!(initial.digest, expanded.digest);
        assert_eq!(old_selector, expanded.selector(&publish.operation).unwrap());
        assert!(old_grant.allows(&publish).unwrap());
        assert!(!old_grant.allows(&read).unwrap());
    }
}
