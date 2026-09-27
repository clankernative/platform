//! Portable managed-credential declarations and selected-instance qualification.
//! This module carries no token bytes, verifier, vault operation or live permission.
//! Credential roots reuse the canonical operation authority contracts also used
//! by OAuth. A qualified binding is still not a runtime authorization decision.

use crate::{
    BindingRef, Digest, Name,
    oauth::{OperationAuthorityContract, ResourceAudienceRef, SecurityOriginRef},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub installation: Name,
    pub environment: Name,
    pub app: Name,
    pub binding_generation: u64,
}

impl Namespace {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.binding_generation > 0,
            "invalid credential binding generation"
        );
        Ok(())
    }
}

/// Source location is diagnostic evidence, never part of a stable family identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
}

impl SourceLocation {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.file.is_empty()
                && self.file.len() <= 1024
                && self.line > 0
                && !self.file.chars().any(char::is_control),
            "invalid credential declaration source location"
        );
        Ok(())
    }

    fn display(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

/// The variant fixes both principal class and target shape. A string flag or
/// optional subject cannot turn a client key into a personal or callback key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedProfile {
    Client,
    Personal,
    ResourceClient {
        model: Name,
    },
    ResourcePersonal {
        model: Name,
    },
    Impersonation {
        target: Name,
        reason_domain: Name,
        audience: ResourceAudienceRef,
    },
}

impl ManagedProfile {
    pub fn can_rotate(&self) -> bool {
        !matches!(self, Self::Impersonation { .. })
    }

    fn resource_model(&self) -> Option<&Name> {
        match self {
            Self::ResourceClient { model } | Self::ResourcePersonal { model } => Some(model),
            Self::Impersonation { target, .. } => Some(target),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode {
    Fixed,
    Selectable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyDeclaration {
    /// Code-facing registration name. It may change without changing `id`.
    pub registration: Name,
    /// Persisted purpose within one installed app.
    pub id: Name,
    pub profile: ManagedProfile,
    pub grant: GrantMode,
    /// Canonical registered roots, not scope strings or copied schemas.
    pub roots: Vec<String>,
    pub lifetime_seconds: u64,
    pub source: SourceLocation,
}

/// The build supplies these from its one registered operation catalog. It must
/// derive `authority` from the operation definition and its complete closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRoot {
    pub authority: OperationAuthorityContract,
    pub direct_ingress: bool,
    pub interactive_security: bool,
    /// `None` means no canonical bounded single-resource target is available.
    pub single_resource_model: Option<Name>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFamily {
    pub registration: Name,
    pub id: Name,
    pub profile: ManagedProfile,
    pub grant: GrantMode,
    pub roots: BTreeMap<String, OperationAuthorityContract>,
    pub lifetime_seconds: u64,
    pub source: SourceLocation,
    pub contract: Digest,
}

impl ManifestFamily {
    pub fn derive(
        declaration: FamilyDeclaration,
        catalog: &BTreeMap<String, CredentialRoot>,
    ) -> Result<Self> {
        declaration.source.validate()?;
        ensure!(
            !declaration.roots.is_empty() && declaration.roots.len() <= 64,
            "{}: empty or excessive credential roots",
            declaration.source.display()
        );
        ensure!(
            (1..=31_536_000).contains(&declaration.lifetime_seconds),
            "{}: invalid bounded credential lifetime",
            declaration.source.display()
        );
        if matches!(declaration.profile, ManagedProfile::Impersonation { .. }) {
            ensure!(
                declaration.lifetime_seconds <= 3600,
                "{}: impersonation lifetime exceeds v1 bound",
                declaration.source.display()
            );
        }
        let mut roots = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for name in &declaration.roots {
            ensure!(
                seen.insert(name),
                "{}: duplicate credential root {name}",
                declaration.source.display()
            );
            let root = catalog.get(name).with_context(|| {
                format!(
                    "{}: credential root {name} is not a registered operation",
                    declaration.source.display()
                )
            })?;
            root.authority.verify()?;
            ensure!(
                root.authority.operation == *name
                    && root.direct_ingress
                    && !root.interactive_security,
                "{}: credential root {name} is not eligible for direct ingress",
                declaration.source.display()
            );
            if let Some(model) = declaration.profile.resource_model() {
                ensure!(
                    root.single_resource_model.as_ref() == Some(model),
                    "{}: credential root {name} has no matching canonical single-resource target",
                    declaration.source.display()
                );
            }
            roots.insert(name.clone(), root.authority.clone());
        }
        let contract = Digest::of(&(
            "credential-family-contract-v1",
            &declaration.id,
            &declaration.profile,
            &declaration.grant,
            &roots,
            declaration.lifetime_seconds,
        ))?;
        Ok(Self {
            registration: declaration.registration,
            id: declaration.id,
            profile: declaration.profile,
            grant: declaration.grant,
            roots,
            lifetime_seconds: declaration.lifetime_seconds,
            source: declaration.source,
            contract,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let expected = Digest::of(&(
            "credential-family-contract-v1",
            &self.id,
            &self.profile,
            &self.grant,
            &self.roots,
            self.lifetime_seconds,
        ))?;
        ensure!(
            self.contract == expected,
            "credential family contract mismatch"
        );
        for (name, root) in &self.roots {
            root.verify()?;
            ensure!(name == &root.operation, "credential root identity mismatch");
        }
        Ok(())
    }
}

/// Build-time duplicate detection across the complete registered app artifact.
/// The generated-name key uses the same ASCII lowercase folding as the v1
/// generated Roc module names; an exact duplicate is also an error.
pub fn build_manifest(
    declarations: Vec<FamilyDeclaration>,
    catalog: &BTreeMap<String, CredentialRoot>,
) -> Result<Vec<ManifestFamily>> {
    ensure!(declarations.len() <= 64, "credential family budget");
    let mut ids = BTreeMap::<Name, SourceLocation>::new();
    let mut aliases = BTreeMap::<String, SourceLocation>::new();
    let mut result = Vec::new();
    for declaration in declarations {
        let source = declaration.source.clone();
        if let Some(first) = ids.insert(declaration.id.clone(), source.clone()) {
            anyhow::bail!(
                "duplicate credential family ID {} at {} and {}",
                declaration.id.as_str(),
                first.display(),
                source.display()
            );
        }
        let lowered = declaration.registration.as_str().to_ascii_lowercase();
        if let Some(first) = aliases.insert(lowered, source.clone()) {
            anyhow::bail!(
                "duplicate generated credential name at {} and {}",
                first.display(),
                source.display()
            );
        }
        result.push(ManifestFamily::derive(declaration, catalog)?);
    }
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagementPredicate {
    Creator,
    MemberOf { group: Name },
    CreatorOrMemberOf { group: Name },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementPolicy {
    pub identity_authority: BindingRef,
    pub issue: ManagementPredicate,
    pub read_metadata: ManagementPredicate,
    pub rotate: ManagementPredicate,
    pub revoke: ManagementPredicate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationProfile {
    AtomicReplace,
    BoundedOverlap { seconds: u32 },
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryProfile {
    AuthenticatedCreatorReveal,
    ProtectedSessionHandoff,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialFamilyBinding {
    pub namespace: Namespace,
    pub family: Name,
    pub approved_authority: BindingRef,
    pub management: BindingRef,
    pub rotation: RotationProfile,
    pub delivery: DeliveryProfile,
    pub verifier: BindingRef,
    pub custody: BindingRef,
    pub security_shell: SecurityOriginRef,
    pub audience: ResourceAudienceRef,
    pub epoch_store: BindingRef,
    pub max_lifetime_seconds: u64,
    pub reveal_window_seconds: u32,
    pub quota: BindingRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReceipt {
    pub namespace: Namespace,
    pub family: Name,
    pub family_contract: Digest,
    pub binding: Digest,
    pub management: Digest,
    pub approved_authority: Digest,
    pub composition: Digest,
}

/// Static qualification against a selected instance composition. `ready` and
/// current human/group permission are deliberately separate runtime checks.
pub fn qualify(
    family: &ManifestFamily,
    binding: Option<&CredentialFamilyBinding>,
    policy: &ManagementPolicy,
    approved_roots: &BTreeMap<String, OperationAuthorityContract>,
    composition: Digest,
) -> Result<QualificationReceipt> {
    family.verify()?;
    let binding = binding.with_context(|| {
        format!(
            "{}: CREDENTIAL_FAMILY_UNBOUND ({})",
            family.source.display(),
            family.id.as_str()
        )
    })?;
    binding.namespace.validate()?;
    ensure!(
        binding.family == family.id,
        "{}: CREDENTIAL_FAMILY_MISMATCH",
        family.source.display()
    );
    ensure!(
        family.lifetime_seconds <= binding.max_lifetime_seconds
            && binding.max_lifetime_seconds <= 31_536_000,
        "{}: CREDENTIAL_LIFETIME_EXCEEDS_LIMIT",
        family.source.display()
    );
    ensure!(
        (1..=3600).contains(&binding.reveal_window_seconds),
        "invalid credential reveal window"
    );
    ensure!(
        binding.management.revision == Digest::of(policy)?,
        "credential management policy revision mismatch"
    );
    match (&family.profile, &binding.rotation, &binding.delivery) {
        (
            ManagedProfile::Impersonation { audience, .. },
            RotationProfile::None,
            DeliveryProfile::ProtectedSessionHandoff,
        ) if audience == &binding.audience => {}
        (ManagedProfile::Impersonation { .. }, _, _) => {
            anyhow::bail!("incompatible impersonation binding profile")
        }
        (_, RotationProfile::AtomicReplace, DeliveryProfile::AuthenticatedCreatorReveal) => {}
        (
            _,
            RotationProfile::BoundedOverlap { seconds },
            DeliveryProfile::AuthenticatedCreatorReveal,
        ) if (1..=3600).contains(seconds) => {}
        _ => anyhow::bail!("incompatible managed credential binding profile"),
    }
    ensure!(
        approved_roots.len() == family.roots.len(),
        "approved credential authority does not match family roots"
    );
    for (name, root) in &family.roots {
        let approved = approved_roots
            .get(name)
            .context("missing approved credential root")?;
        root.verify()?;
        approved.verify()?;
        ensure!(
            root.version == approved.version
                && root.kind == approved.kind
                && root.operation_contract == approved.operation_contract
                && root.closure.is_within(&approved.closure),
            "credential root exceeds approved authority"
        );
    }
    ensure!(
        binding.approved_authority.revision
            == Digest::of(&("credential-approved-authority-v1", approved_roots,))?,
        "credential approved authority revision mismatch"
    );
    Ok(QualificationReceipt {
        namespace: binding.namespace.clone(),
        family: family.id.clone(),
        family_contract: family.contract.clone(),
        binding: Digest::of(binding)?,
        management: binding.management.revision.clone(),
        approved_authority: binding.approved_authority.revision.clone(),
        composition,
    })
}

/// Safe public audit identities. Existence and visibility require host checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageRef {
    pub namespace: Namespace,
    pub family: Name,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRef {
    pub lineage: LineageRef,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementSnapshot {
    pub lineage: LineageRef,
    pub head: VersionRef,
    pub revision: u64,
    pub state: ManagementState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementState {
    Active,
    Rotating,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub lineage: LineageRef,
    pub current_version: VersionRef,
    pub label: Option<String>,
    pub principal: String,
    pub resource: Option<String>,
    pub state: ManagementState,
    pub grant: Digest,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub summary: Summary,
    pub rotation: Option<ManagementSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyCursor {
    pub family: Name,
    pub opaque: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub after: FamilyCursor,
    pub limit: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListFailure {
    Denied,
    InvalidCursor,
    Unavailable,
    Throttled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionFailure {
    NotVisible,
    Unavailable,
    Throttled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Available,
    MayHaveBeenDelivered,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issued {
    pub lineage: LineageRef,
    pub version: VersionRef,
    pub delivery: DeliveryStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RotationOutcome {
    Rotated { issued: Box<Issued> },
    Conflict,
    RotationInProgress,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RevocationOutcome {
    Revoked { lineage: LineageRef, revision: u64 },
    AlreadyRevoked { lineage: LineageRef, revision: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionPage<T> {
    pub items: Vec<T>,
    pub next: Option<FamilyCursor>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{AuthorityAction, AuthorityNode, OperationKind};

    fn name(value: &str) -> Name {
        Name::try_from(value.to_owned()).unwrap()
    }

    fn pin(value: &str) -> BindingRef {
        BindingRef::pin(name(value), &value).unwrap()
    }

    fn root(name: &str, write: bool) -> CredentialRoot {
        CredentialRoot {
            authority: OperationAuthorityContract::derive(
                name.to_owned(),
                1,
                Digest::of(&name).unwrap(),
                if write {
                    OperationKind::Command
                } else {
                    OperationKind::Query
                },
                AuthorityNode {
                    actions: BTreeSet::from([AuthorityAction::LocalData {
                        category: "transcription".into(),
                        policy: Digest::of(&"own-transcription").unwrap(),
                        write,
                    }]),
                    children: BTreeMap::new(),
                },
            )
            .unwrap(),
            direct_ingress: true,
            interactive_security: false,
            single_resource_model: None,
        }
    }

    fn declaration(id: &str, registration: &str, line: u32) -> FamilyDeclaration {
        FamilyDeclaration {
            registration: name(registration),
            id: name(id),
            profile: ManagedProfile::Client,
            grant: GrantMode::Fixed,
            roots: vec!["SubmitTranscription".into(), "GetTranscription".into()],
            lifetime_seconds: 90 * 86400,
            source: SourceLocation {
                file: "ClientKeys.roc".into(),
                line,
            },
        }
    }

    fn catalog() -> BTreeMap<String, CredentialRoot> {
        BTreeMap::from([
            (
                "SubmitTranscription".into(),
                root("SubmitTranscription", true),
            ),
            ("GetTranscription".into(), root("GetTranscription", false)),
        ])
    }

    #[test]
    fn transcriber_family_uses_registered_canonical_roots() {
        let family = build_manifest(
            vec![declaration("transcription-client", "transcription", 4)],
            &catalog(),
        )
        .unwrap()
        .remove(0);
        family.verify().unwrap();
        assert_eq!(family.roots.len(), 2);
        let mut changed = family.clone();
        changed
            .roots
            .get_mut("SubmitTranscription")
            .unwrap()
            .version = 2;
        assert!(changed.verify().is_err());
        let mut unregistered = declaration("another-client", "other", 8);
        unregistered.roots.push("UnknownOperation".into());
        assert!(ManifestFamily::derive(unregistered, &catalog()).is_err());
        let mut duplicate = declaration("duplicate-client", "duplicate", 9);
        duplicate.roots.push("GetTranscription".into());
        assert!(
            ManifestFamily::derive(duplicate, &catalog())
                .unwrap_err()
                .to_string()
                .contains("duplicate credential root")
        );
    }

    #[test]
    fn duplicate_identity_and_lowered_alias_report_both_locations() {
        let duplicate = build_manifest(
            vec![
                declaration("transcription-client", "first", 3),
                declaration("transcription-client", "second", 9),
            ],
            &catalog(),
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("ClientKeys.roc:3"));
        assert!(duplicate.contains("ClientKeys.roc:9"));
        let alias = build_manifest(
            vec![
                declaration("first-client", "Transcription", 3),
                declaration("second-client", "transcription", 9),
            ],
            &catalog(),
        )
        .unwrap_err()
        .to_string();
        assert!(alias.contains("ClientKeys.roc:3"));
        assert!(alias.contains("ClientKeys.roc:9"));
    }

    #[test]
    fn resource_shape_and_security_root_fail_admission() {
        let mut resource = declaration("repository-client", "repository_keys", 2);
        resource.profile = ManagedProfile::ResourceClient {
            model: name("Repository"),
        };
        assert!(ManifestFamily::derive(resource, &catalog()).is_err());
        let mut roots = catalog();
        roots
            .get_mut("SubmitTranscription")
            .unwrap()
            .interactive_security = true;
        assert!(ManifestFamily::derive(declaration("client", "keys", 2), &roots).is_err());
    }

    #[test]
    fn qualification_pins_selected_instance_and_rejects_missing_or_excess_authority() {
        let family = ManifestFamily::derive(
            declaration("transcription-client", "transcription", 4),
            &catalog(),
        )
        .unwrap();
        let policy = ManagementPolicy {
            identity_authority: pin("directory"),
            issue: ManagementPredicate::MemberOf {
                group: name("issuers"),
            },
            read_metadata: ManagementPredicate::Creator,
            rotate: ManagementPredicate::Creator,
            revoke: ManagementPredicate::Creator,
        };
        let namespace = Namespace {
            installation: name("wonderly"),
            environment: name("development"),
            app: name("transcriber"),
            binding_generation: 3,
        };
        let approved = family.roots.clone();
        let binding = CredentialFamilyBinding {
            namespace: namespace.clone(),
            family: family.id.clone(),
            approved_authority: BindingRef {
                id: name("approved"),
                revision: Digest::of(&("credential-approved-authority-v1", &approved)).unwrap(),
            },
            management: BindingRef {
                id: name("managers"),
                revision: Digest::of(&policy).unwrap(),
            },
            rotation: RotationProfile::AtomicReplace,
            delivery: DeliveryProfile::AuthenticatedCreatorReveal,
            verifier: pin("verifier"),
            custody: pin("custody"),
            security_shell: SecurityOriginRef(pin("security")),
            audience: ResourceAudienceRef(pin("transcriber-api")),
            epoch_store: pin("epoch"),
            max_lifetime_seconds: 90 * 86400,
            reveal_window_seconds: 300,
            quota: pin("quota"),
        };
        assert!(
            qualify(
                &family,
                None,
                &policy,
                &approved,
                Digest::of(&"instance").unwrap()
            )
            .unwrap_err()
            .to_string()
            .contains("CREDENTIAL_FAMILY_UNBOUND")
        );
        let receipt = qualify(
            &family,
            Some(&binding),
            &policy,
            &approved,
            Digest::of(&"instance").unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.namespace, namespace);
        assert_eq!(receipt.family_contract, family.contract);
        let mut narrowed = approved.clone();
        narrowed.remove("GetTranscription");
        assert!(
            qualify(
                &family,
                Some(&binding),
                &policy,
                &narrowed,
                Digest::of(&"instance").unwrap()
            )
            .is_err()
        );
        let mut short = binding;
        short.max_lifetime_seconds = 30 * 86400;
        assert!(
            qualify(
                &family,
                Some(&short),
                &policy,
                &approved,
                Digest::of(&"instance").unwrap()
            )
            .unwrap_err()
            .to_string()
            .contains("CREDENTIAL_LIFETIME_EXCEEDS_LIMIT")
        );
    }

    #[test]
    fn public_issued_schema_has_only_safe_identity_and_status() {
        let lineage = LineageRef {
            namespace: Namespace {
                installation: name("wonderly"),
                environment: name("dev"),
                app: name("transcriber"),
                binding_generation: 1,
            },
            family: name("transcription-client"),
            id: "lineage-1".into(),
        };
        let issued = Issued {
            version: VersionRef {
                lineage: lineage.clone(),
                id: "version-1".into(),
            },
            lineage,
            delivery: DeliveryStatus::Available,
        };
        let json = serde_json::to_value(&issued).unwrap();
        assert_eq!(
            json.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["delivery", "lineage", "version"]
        );
        assert!(
            serde_json::from_value::<Issued>(serde_json::json!({
                "lineage": issued.lineage, "version": issued.version,
                "delivery": "available", "token": "forbidden"
            }))
            .is_err()
        );
    }
}
