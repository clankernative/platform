//! Portable managed-credential declarations and selected-instance qualification.
//! This module carries no token bytes, verifier, vault operation or live permission.
//! Credential roots reuse the canonical operation authority contracts also used
//! by OAuth. A qualified binding is still not a runtime authorization decision.

use crate::{
    BindingRef, Digest, Name,
    oauth::{GrantCeiling, OperationAuthorityContract, ResourceAudienceRef, SecurityOriginRef},
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

/// Portable selection DATA, not issuance or execution authority. Only an exact
/// current family can interpret it; current instance and principal checks remain
/// the caller's responsibility. Canonical roots are never supplied contracts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSelection {
    family_contract: Digest,
    roots: Vec<String>,
}

impl GrantSelection {
    /// Selected public root names, never supplied authority contracts.
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    pub fn new(family: &ManifestFamily, roots: Vec<String>) -> Result<Self> {
        family.verify()?;
        ensure!(
            matches!(
                family.profile,
                ManagedProfile::Client | ManagedProfile::Personal
            ),
            "unsupported credential selection profile"
        );
        ensure!(
            matches!(family.grant, GrantMode::Selectable),
            "credential family does not allow grant selection"
        );
        ensure!(
            !roots.is_empty() && roots.len() <= 64,
            "credential selection root budget"
        );
        let mut selected = BTreeSet::new();
        for root in roots {
            ensure!(
                family.roots.contains_key(&root),
                "unknown credential selection root"
            );
            ensure!(selected.insert(root), "duplicate credential selection root");
        }
        Ok(Self {
            family_contract: family.contract.clone(),
            roots: selected.into_iter().collect(),
        })
    }
}

/// Closed permission modes. A fixed family cannot consume caller selection,
/// and a selectable family cannot interpret omission as its complete grant.
pub enum IssuanceGrant<'a> {
    Fixed,
    Selected(&'a GrantSelection),
}

/// A successor preserves or narrows the actual predecessor, never today's
/// complete family. This is portable intent DATA, not current permission.
pub enum RotationGrant<'a> {
    KeepExisting,
    Narrow(&'a GrantSelection),
}

impl ManifestFamily {
    /// Resolve only admitted canonical contracts, preserving every selected
    /// root's complete child/path authority. No member is dropped or widened.
    pub fn issuance_roots(
        &self,
        request: IssuanceGrant<'_>,
    ) -> Result<BTreeMap<String, OperationAuthorityContract>> {
        self.verify()?;
        ensure!(
            matches!(
                self.profile,
                ManagedProfile::Client | ManagedProfile::Personal
            ),
            "unsupported credential issuance profile"
        );
        ensure!(
            !self.roots.is_empty() && self.roots.len() <= 64,
            "credential family root budget"
        );
        match (&self.grant, request) {
            (GrantMode::Fixed, IssuanceGrant::Fixed) => Ok(self.roots.clone()),
            (GrantMode::Selectable, IssuanceGrant::Selected(selection)) => {
                ensure!(
                    selection.family_contract == self.contract,
                    "credential selection family changed"
                );
                ensure!(
                    *selection == GrantSelection::new(self, selection.roots.clone())?,
                    "noncanonical credential selection"
                );
                selection
                    .roots
                    .iter()
                    .map(|name| {
                        Ok((
                            name.clone(),
                            self.roots
                                .get(name)
                                .context("credential selection root missing")?
                                .clone(),
                        ))
                    })
                    .collect()
            }
            _ => anyhow::bail!("credential grant mode mismatch"),
        }
    }

    /// Preserve the predecessor's subject, audience and authority binding while
    /// resolving an exact subset of its admitted canonical roots. The caller
    /// still owns current policy, epochs, deadlines and the predecessor CAS.
    pub fn rotation_ceiling(
        &self,
        predecessor: &GrantCeiling,
        request: RotationGrant<'_>,
    ) -> Result<GrantCeiling> {
        self.verify()?;
        ensure!(
            matches!(self.profile, ManagedProfile::Client | ManagedProfile::Personal),
            "unsupported credential rotation profile"
        );
        ensure!(
            !predecessor.roots.is_empty() && predecessor.roots.len() <= 64,
            "credential predecessor root budget"
        );
        predecessor.verify()?;
        for (name, root) in &predecessor.roots {
            ensure!(
                self.roots.get(name) == Some(root),
                "credential predecessor grant no longer admitted"
            );
        }
        let roots = match request {
            RotationGrant::KeepExisting => predecessor.roots.clone(),
            RotationGrant::Narrow(selection) => {
                let roots = self.issuance_roots(IssuanceGrant::Selected(selection))?;
                ensure!(
                    roots.iter().all(|(name, root)| predecessor.roots.get(name) == Some(root)),
                    "credential rotation cannot widen predecessor grant"
                );
                roots
            }
        };
        GrantCeiling::derive(
            predecessor.client.clone(),
            predecessor.subject.clone(),
            predecessor.audience.clone(),
            roots,
        )
    }

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

/// Instance-owned definitions shared by app-local family bindings. A binding
/// pins each definition by its content digest; changing an entry under the
/// same name cannot silently expand an existing family's authority.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCatalog {
    #[serde(default)]
    pub management: BTreeMap<String, ManagementPolicy>,
    #[serde(default)]
    pub approved_authority: BTreeMap<String, BTreeMap<String, OperationAuthorityContract>>,
}

impl CredentialCatalog {
    pub fn is_empty(&self) -> bool {
        self.management.is_empty() && self.approved_authority.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.management.len() <= 1024 && self.approved_authority.len() <= 1024,
            "credential catalog budget"
        );
        for id in self.management.keys().chain(self.approved_authority.keys()) {
            Name::try_from(id.clone())?;
        }
        for roots in self.approved_authority.values() {
            ensure!(
                !roots.is_empty() && roots.len() <= 64,
                "credential authority root budget"
            );
            for (name, root) in roots {
                root.verify()?;
                ensure!(
                    name == &root.operation,
                    "credential authority root identity mismatch"
                );
            }
        }
        Ok(())
    }
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

    fn selectable(profile: ManagedProfile) -> ManifestFamily {
        let mut definition = declaration("local-keys", "keys", 1);
        definition.profile = profile;
        definition.grant = GrantMode::Selectable;
        ManifestFamily::derive(definition, &catalog()).unwrap()
    }

    #[test]
    fn local_selection_preserves_exact_canonical_contracts_for_each_nonempty_subset() -> Result<()>
    {
        for profile in [ManagedProfile::Client, ManagedProfile::Personal] {
            let family = selectable(profile);
            let candidates = [
                vec!["GetTranscription".to_owned()],
                vec!["SubmitTranscription".to_owned()],
                vec![
                    "SubmitTranscription".to_owned(),
                    "GetTranscription".to_owned(),
                ],
            ];
            for names in candidates {
                let selection = GrantSelection::new(&family, names.clone())?;
                let expected = names
                    .into_iter()
                    .map(|name| (name.clone(), catalog()[&name].authority.clone()))
                    .collect::<BTreeMap<_, _>>();
                let actual = family.issuance_roots(IssuanceGrant::Selected(&selection))?;
                assert_eq!(actual, expected);
                assert_eq!(
                    selection.roots,
                    expected.keys().cloned().collect::<Vec<_>>()
                );
                let round_trip: GrantSelection =
                    serde_json::from_slice(&serde_json::to_vec(&selection)?)?;
                assert_eq!(
                    family.issuance_roots(IssuanceGrant::Selected(&round_trip))?,
                    expected
                );
            }
        }
        Ok(())
    }

    #[test]
    fn selection_rejects_omission_duplicates_unknown_members_and_excess_without_fallback()
    -> Result<()> {
        let family = selectable(ManagedProfile::Client);
        assert!(family.issuance_roots(IssuanceGrant::Fixed).is_err());
        for roots in [
            Vec::new(),
            vec!["GetTranscription".into(), "GetTranscription".into()],
            vec!["GetTranscription".into(), "UnknownOperation".into()],
            vec!["*".into()],
            vec!["GetTranscription".into(); 65],
        ] {
            assert!(GrantSelection::new(&family, roots).is_err());
        }
        let fixed = ManifestFamily::derive(declaration("local-keys", "keys", 1), &catalog())?;
        assert_eq!(fixed.issuance_roots(IssuanceGrant::Fixed)?, fixed.roots);
        assert!(GrantSelection::new(&fixed, vec!["GetTranscription".into()]).is_err());
        let selection = GrantSelection::new(&family, vec!["GetTranscription".into()])?;
        assert!(
            fixed
                .issuance_roots(IssuanceGrant::Selected(&selection))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn restored_selection_cannot_retarget_a_family_or_reinterpret_an_old_contract() -> Result<()> {
        let family = selectable(ManagedProfile::Client);
        let selected = GrantSelection::new(&family, vec!["GetTranscription".into()])?;
        let mut definition = declaration("foreign-family", "foreign", 1);
        definition.grant = GrantMode::Selectable;
        let foreign = ManifestFamily::derive(definition.clone(), &catalog())?;
        assert!(
            foreign
                .issuance_roots(IssuanceGrant::Selected(&selected))
                .is_err()
        );
        definition.id = family.id.clone();
        definition.lifetime_seconds -= 1;
        let changed = ManifestFamily::derive(definition, &catalog())?;
        assert!(
            changed
                .issuance_roots(IssuanceGrant::Selected(&selected))
                .is_err()
        );
        let personal = selectable(ManagedProfile::Personal);
        assert!(
            personal
                .issuance_roots(IssuanceGrant::Selected(&selected))
                .is_err()
        );
        let mut corrupted = family.clone();
        corrupted.roots.remove("SubmitTranscription");
        assert!(
            corrupted
                .issuance_roots(IssuanceGrant::Selected(&selected))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn selection_wire_is_data_and_cannot_bypass_canonical_family_validation() -> Result<()> {
        let family = selectable(ManagedProfile::Client);
        for roots in [
            vec![],
            vec!["GetTranscription", "GetTranscription"],
            vec!["GetTranscription", "UnknownOperation"],
            vec!["SubmitTranscription", "GetTranscription"],
        ] {
            let raw = serde_json::json!({"family_contract":family.contract,"roots":roots});
            let decoded: GrantSelection = serde_json::from_value(raw)?;
            assert!(
                family
                    .issuance_roots(IssuanceGrant::Selected(&decoded))
                    .is_err()
            );
        }
        let mut raw = serde_json::to_value(GrantSelection::new(
            &family,
            vec!["GetTranscription".into()],
        )?)?;
        raw["authorized"] = true.into();
        assert!(serde_json::from_value::<GrantSelection>(raw).is_err());
        assert!(
            family
                .issuance_roots(IssuanceGrant::Selected(&GrantSelection {
                    family_contract: Digest::of(&"foreign")?,
                    roots: vec!["GetTranscription".into()],
                }))
                .is_err()
        );
        Ok(())
    }

    fn rotation_predecessor(roots: BTreeMap<String, OperationAuthorityContract>) -> Result<GrantCeiling> {
        GrantCeiling::derive(
            pin("approved-client-authority"),
            "accounts.google.com:fixed-subject".into(),
            ResourceAudienceRef(pin("transcriber-api")),
            roots,
        )
    }

    #[test]
    fn rotation_keeps_or_narrows_each_predecessor_without_recovering_removed_roots() -> Result<()> {
        for profile in [ManagedProfile::Client, ManagedProfile::Personal] {
            let mut definition = declaration("local-keys", "keys", 1);
            definition.profile = profile;
            definition.grant = GrantMode::Selectable;
            let mut catalog = catalog();
            let child = root("NestedOperation", true).authority.closure;
            let parent = &mut catalog.get_mut("SubmitTranscription").unwrap().authority;
            let mut closure = parent.closure.clone();
            closure.children.insert("nested-path".into(), child);
            *parent = OperationAuthorityContract::derive(
                parent.operation.clone(), parent.version, parent.operation_contract.clone(),
                parent.kind.clone(), closure,
            )?;
            let family = ManifestFamily::derive(definition, &catalog)?;
            let names = ["GetTranscription", "SubmitTranscription"];
            for prior_bits in 1..4 {
                let prior_roots = names.iter().enumerate()
                    .filter(|(index, _)| prior_bits & (1 << index) != 0)
                    .map(|(_, name)| ((*name).to_owned(), catalog[*name].authority.clone()))
                    .collect();
                let predecessor = rotation_predecessor(prior_roots)?;
                let original = predecessor.clone();
                assert_eq!(family.rotation_ceiling(&predecessor, RotationGrant::KeepExisting)?, predecessor);
                for next_bits in 1..4 {
                    let selected_names = names.iter().enumerate()
                        .filter(|(index, _)| next_bits & (1 << index) != 0)
                        .map(|(_, name)| (*name).to_owned()).collect();
                    let selection = GrantSelection::new(&family, selected_names)?;
                    let result = family.rotation_ceiling(&predecessor, RotationGrant::Narrow(&selection));
                    if next_bits & !prior_bits != 0 {
                        assert!(result.is_err());
                        continue;
                    }
                    let next = result?;
                    let expected = names.iter().enumerate()
                        .filter(|(index, _)| next_bits & (1 << index) != 0)
                        .map(|(_, name)| ((*name).to_owned(), catalog[*name].authority.clone()))
                        .collect::<BTreeMap<_, _>>();
                    assert_eq!(next.roots, expected);
                    assert_eq!((&next.client, &next.subject, &next.audience),
                        (&original.client, &original.subject, &original.audience));
                    next.verify()?;
                    assert_eq!(family.rotation_ceiling(&next, RotationGrant::KeepExisting)?, next);
                    let original_selection = GrantSelection::new(&family, original.roots.keys().cloned().collect())?;
                    if next_bits != prior_bits {
                        assert!(family.rotation_ceiling(&next, RotationGrant::Narrow(&original_selection)).is_err());
                    }
                }
                assert_eq!(predecessor, original);
            }
        }
        Ok(())
    }

    #[test]
    fn rotation_refuses_changed_predecessors_and_foreign_or_noncanonical_selections() -> Result<()> {
        let family = selectable(ManagedProfile::Client);
        let predecessor = rotation_predecessor(family.roots.clone())?;
        let selected = GrantSelection::new(&family, vec!["GetTranscription".into()])?;
        let mut corrupt = predecessor.clone();
        corrupt.digest = Digest::of(&"different grant")?;
        assert!(family.rotation_ceiling(&corrupt, RotationGrant::KeepExisting).is_err());
        corrupt = predecessor.clone();
        corrupt.roots.clear();
        assert!(family.rotation_ceiling(&corrupt, RotationGrant::KeepExisting).is_err());
        let changed = rotation_predecessor(BTreeMap::from([
            ("GetTranscription".into(), root("GetTranscription", true).authority),
        ]))?;
        changed.verify()?;
        assert!(family.rotation_ceiling(&changed, RotationGrant::KeepExisting).is_err());
        assert!(family.rotation_ceiling(&changed, RotationGrant::Narrow(&selected)).is_err());
        for roots in [vec![], vec!["GetTranscription", "GetTranscription"],
            vec!["UnknownOperation"], vec!["SubmitTranscription", "GetTranscription"]] {
            let decoded: GrantSelection = serde_json::from_value(serde_json::json!({
                "family_contract":family.contract, "roots":roots,
            }))?;
            assert!(family.rotation_ceiling(&predecessor, RotationGrant::Narrow(&decoded)).is_err());
        }
        let personal = selectable(ManagedProfile::Personal);
        let foreign = GrantSelection::new(&personal, vec!["GetTranscription".into()])?;
        assert!(family.rotation_ceiling(&predecessor, RotationGrant::Narrow(&foreign)).is_err());
        let mut definition = declaration("local-keys", "keys", 1);
        definition.grant = GrantMode::Selectable;
        definition.roots = vec!["GetTranscription".into()];
        let reduced = ManifestFamily::derive(definition, &catalog())?;
        let narrower = GrantSelection::new(&reduced, vec!["GetTranscription".into()])?;
        assert!(reduced.rotation_ceiling(&predecessor, RotationGrant::KeepExisting).is_err());
        assert!(reduced.rotation_ceiling(&predecessor, RotationGrant::Narrow(&narrower)).is_err());
        assert!(reduced.rotation_ceiling(&rotation_predecessor(reduced.roots.clone())?, RotationGrant::Narrow(&selected)).is_err());
        let oversized = rotation_predecessor((0..65).map(|index| {
            let name = format!("Root{index}");
            (name.clone(), root(&name, false).authority)
        }).collect())?;
        assert!(family.rotation_ceiling(&oversized, RotationGrant::KeepExisting).is_err());
        Ok(())
    }

    #[test]
    fn fixed_rotation_has_no_selection_and_resource_rotation_remains_unavailable() -> Result<()> {
        let fixed = ManifestFamily::derive(declaration("local-keys", "keys", 1), &catalog())?;
        let predecessor = rotation_predecessor(fixed.roots.clone())?;
        assert_eq!(fixed.rotation_ceiling(&predecessor, RotationGrant::KeepExisting)?, predecessor);
        let selected = GrantSelection::new(&selectable(ManagedProfile::Client), vec!["GetTranscription".into()])?;
        assert!(fixed.rotation_ceiling(&predecessor, RotationGrant::Narrow(&selected)).is_err());
        let mut definition = declaration("resource-keys", "keys", 1);
        definition.profile = ManagedProfile::ResourceClient { model: name("Repository") };
        let mut catalog = catalog();
        for root in catalog.values_mut() {
            root.single_resource_model = Some(name("Repository"));
        }
        let resource = ManifestFamily::derive(definition, &catalog)?;
        assert!(resource.rotation_ceiling(&predecessor, RotationGrant::KeepExisting).is_err());
        Ok(())
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
