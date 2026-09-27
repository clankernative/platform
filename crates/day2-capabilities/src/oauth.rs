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
            identifier(subject)?;
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
        identifier(&subject)?;
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
