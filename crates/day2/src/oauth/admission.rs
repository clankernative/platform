//! Selected-instance OAuth composition. Requirements come from admitted app
//! artifacts; provider semantics come from reviewed host code. Qualification
//! does not establish external readiness or grant invocation authority.

use super::{
    approval_keys::{AccessTokenSource, GcpApprovalKeys, GcpSecretVersion},
    approval_registry::{
        AdmittedApproval, ApprovalAuthority, ApprovalKeyProvider, ApprovalKeyPurpose,
        ApprovalKeyRef, ApprovalTerms, SelectedApprovalAuthority,
    },
    connect, profiles,
};
use crate::artifact::{Instance, LoadedArtifact};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef, Digest, Name, SecretProvider,
    oauth::{
        AccountBindingPolicy, ConnectionRequirement, ConnectionSlotKey, OutboundConnectionBinding,
        ProviderPermissionContract, SlotOwner,
    },
};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, RwLock},
};

/// Only the reviewed host catalog constructs this value. It is deliberately not
/// deserializable from an instance document or an app's worker output.
pub(crate) struct ReviewedAccess {
    pub profile: profiles::ReviewedBrowserCodeProfile,
    pub capability: String,
    pub action_scopes: BTreeMap<String, std::collections::BTreeSet<String>>,
}

pub(crate) struct ReviewedCatalog {
    entries: BTreeMap<String, ReviewedAccess>,
}

impl ReviewedCatalog {
    pub(super) fn current(
        &self,
        requirement: &ConnectionRequirement,
        id: &Name,
    ) -> Result<(
        profiles::ReviewedBrowserCodeProfile,
        ProviderPermissionContract,
    )> {
        let entry = self
            .entries
            .get(id.as_str())
            .context("OAuth profile is not reviewed")?;
        self.resolve(requirement, &entry.profile.protocol.identity().binding)
    }

    #[cfg(test)]
    pub(super) fn entries(&self) -> impl Iterator<Item = &ReviewedAccess> {
        self.entries.values()
    }

    pub(crate) fn new(entries: Vec<ReviewedAccess>) -> Result<Self> {
        ensure!(entries.len() <= 64, "OAuth reviewed catalog budget");
        let mut selected = BTreeMap::new();
        for entry in entries {
            day2_contracts::names::identifier(&entry.capability)?;
            ensure!(
                !entry.action_scopes.is_empty() && entry.action_scopes.len() <= 32,
                "OAuth reviewed action budget"
            );
            for (action, scopes) in &entry.action_scopes {
                day2_contracts::names::identifier(action)?;
                ensure!(
                    !scopes.is_empty() && scopes.len() <= 32,
                    "OAuth reviewed scope budget"
                );
                for scope in scopes {
                    ensure!(
                        !scope.is_empty()
                            && scope.len() <= 256
                            && !scope.chars().any(char::is_whitespace)
                            && !scope.chars().any(char::is_control),
                        "invalid OAuth reviewed scope"
                    );
                }
            }
            let identity = entry.profile.protocol.identity();
            ensure!(
                identity.binding.revision == entry.profile.review_revision()?
                    && identity.scope_interpretation
                        == Digest::of(&(
                            "oauth-semantic-scope-map-v1",
                            &entry.capability,
                            &entry.action_scopes
                        ))?,
                "OAuth reviewed semantic scope mapping mismatch"
            );
            ensure!(
                selected
                    .insert(identity.binding.id.as_str().to_owned(), entry)
                    .is_none(),
                "duplicate OAuth reviewed profile"
            );
        }
        Ok(Self { entries: selected })
    }

    pub(super) fn resolve(
        &self,
        requirement: &ConnectionRequirement,
        profile: &BindingRef,
    ) -> Result<(
        profiles::ReviewedBrowserCodeProfile,
        ProviderPermissionContract,
    )> {
        let entry = self
            .entries
            .get(profile.id.as_str())
            .context("OAuth profile is not reviewed")?;
        ensure!(
            entry.profile.protocol.identity().binding == *profile
                && entry.capability == requirement.capability,
            "OAuth selected profile revision or capability mismatch"
        );
        ensure!(
            matches!(
                (&requirement.account_policy, entry.profile.account_evidence),
                (
                    AccountBindingPolicy::MappedHuman,
                    profiles::AccountEvidenceContract::MappedHuman
                ) | (
                    AccountBindingPolicy::ExplicitExternalAccount,
                    profiles::AccountEvidenceContract::ExternalAccount
                ) | (
                    AccountBindingPolicy::InstallationAccount,
                    profiles::AccountEvidenceContract::Installation
                )
            ),
            "OAuth selected profile cannot establish the required account policy"
        );
        let action_scopes = requirement
            .actions
            .iter()
            .map(|action| {
                Ok((
                    action.clone(),
                    entry
                        .action_scopes
                        .get(action)
                        .context("OAuth semantic action is not reviewed")?
                        .clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let permission = ProviderPermissionContract {
            requirement: requirement.nominal_identity()?,
            profile: profile.clone(),
            action_scopes,
            interpretation: entry
                .profile
                .protocol
                .identity()
                .scope_interpretation
                .clone(),
        };
        permission.validate(requirement)?;
        Ok((entry.profile.clone(), permission))
    }
}

struct SelectedConnection {
    requirement: ConnectionRequirement,
    permission: ProviderPermissionContract,
    reviewed: profiles::ReviewedBrowserCodeProfile,
    binding: OutboundConnectionBinding,
    custody_verifier: ApprovalKeyRef,
    custody_encryption: ApprovalKeyRef,
    shell_attestation: ApprovalKeyRef,
    client_credential: Option<BindingRef>,
}

type GcpBinding = (BindingRef, ApprovalKeyPurpose, GcpSecretVersion);

/// The browser shell fetches only attestation material. The app hosts own
/// custody key retrieval, readiness and SQLite settlement.
pub(crate) struct ArtifactShellSigner {
    state: RwLock<AuthorityState>,
}

impl ArtifactShellSigner {
    pub(crate) fn with_gcp(
        selected: QualifiedConnections,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Self> {
        let keys = Self::keys(&selected, tokens)?;
        Ok(Self {
            state: RwLock::new(AuthorityState { selected, keys }),
        })
    }

    fn keys(
        selected: &QualifiedConnections,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Option<Arc<dyn ApprovalKeyProvider>>> {
        let bindings: Vec<_> = selected
            .key_bindings
            .iter()
            .filter(|(_, purpose, _)| *purpose == ApprovalKeyPurpose::ShellAttestation)
            .cloned()
            .collect();
        if bindings.is_empty() {
            return Ok(None);
        }
        Ok(Some(Arc::new(GcpApprovalKeys::new(bindings, tokens)?)))
    }

    pub(crate) fn replace_with_gcp(
        &self,
        selected: QualifiedConnections,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<()> {
        let keys = Self::keys(&selected, tokens)?;
        *self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("OAuth shell selection lock poisoned"))? =
            AuthorityState { selected, keys };
        Ok(())
    }

    /// Current selection is held through the one-shot publication. Replacement
    /// waits for the bounded request, as it does for local approval settlement.
    pub(crate) fn publish_registration(
        &self,
        receipt: &super::registration::Receipt,
        publisher: &dyn super::shell_transport::RegistrationPublisher,
        headers: &axum::http::HeaderMap,
        now: i64,
    ) -> Result<()> {
        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth shell selection lock poisoned"))?;
        let proof = super::registration::publication::attest(
            receipt,
            &state.selected,
            state
                .keys
                .as_ref()
                .context("OAuth shell key provider missing")?
                .as_ref(),
            now,
        )?;
        publisher.publish_registration(proof, headers)
    }
}

impl super::shell_transport::ApprovalSigner for ArtifactShellSigner {
    fn attest(
        &self,
        view: &super::shell_transport::ApprovalView,
        session: &super::security_shell::ShellSession,
        now: i64,
    ) -> Result<super::external::FreshExternalApproval> {
        session.require_approval(view, now)?;
        let authenticated_at = session.authenticated_at();
        view.validate(&crate::iap::Verified {
            email: view.human().into(),
            subject: view.subject.clone(),
        })?;
        ensure!(
            authenticated_at > view.quarantined_at()
                && now >= authenticated_at
                && now - authenticated_at <= 300,
            "OAuth shell approval authentication is stale"
        );
        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth shell selection lock poisoned"))?;
        let mut found = None;
        for ((app, _), selected) in &state.selected.entries {
            if app != &view.app || selected.binding.requirement != view.requirement {
                continue;
            }
            ensure!(found.is_none(), "ambiguous OAuth shell selection");
            found = Some(selected);
        }
        let selected = found.context("OAuth shell requirement retired")?;
        super::shell_transport::routed_attempt(
            view.attempt(),
            &super::shell_transport::route_prefix(
                selected.binding.namespace.installation.as_str(),
                selected.binding.namespace.environment.as_str(),
                selected.binding.namespace.app.as_str(),
            )?,
        )?;
        let edge = state.selected.instance.apps[&view.app]
            .edge
            .as_ref()
            .context("OAuth app edge missing")?;
        let (_, shell) = state.selected.instance.security_edge()?;
        let slot = ConnectionSlotKey {
            installation: selected.binding.namespace.installation.clone(),
            environment: selected.binding.namespace.environment.clone(),
            app: selected.binding.namespace.app.clone(),
            requirement: selected.requirement.logical_id.clone(),
            owner: SlotOwner::Human {
                subject: view.human().into(),
            },
        };
        ensure!(
            selected.requirement.account_policy == AccountBindingPolicy::ExplicitExternalAccount
                && slot.id(&selected.requirement)?.as_str() == view.claim.slot
                && view.binding_namespace == binding_namespace(&selected.binding)?
                && view.permission == selected.permission.consent_digest(&selected.requirement)?
                && view.scopes
                    == selected
                        .permission
                        .action_scopes
                        .values()
                        .flatten()
                        .cloned()
                        .collect()
                && view.logical_id == selected.requirement.logical_id
                && view.usage == selected.requirement.usage
                && view.claim.security_origin == selected.binding.security_shell
                && view.claim.approval == selected.binding.account_binding
                && view.shell_origin == format!("{}/", shell.origin)
                && view.app_origin == format!("{}/", edge.origin),
            "OAuth approval view does not match selected shell authority"
        );
        let reference = &selected.shell_attestation;
        let key = state
            .keys
            .as_ref()
            .context("OAuth shell key provider missing")?
            .load(reference, ApprovalKeyPurpose::ShellAttestation)?;
        let now = session.observe_current(now)?;
        session.require_approval(view, now)?;
        ensure!(
            key.binding == reference.binding
                && key.version == reference.version
                && key.purpose == ApprovalKeyPurpose::ShellAttestation,
            "OAuth shell key identity mismatch"
        );
        super::external::ShellApprovalKeyLease::new(
            &key.bytes,
            key.version,
            view.claim.security_origin.clone(),
            view.claim.approval.clone(),
        )?
        .attest_view(
            &view.claim,
            view.digest()?,
            session.digest(),
            authenticated_at,
            now,
        )
    }
}

pub(crate) struct QualifiedConnections {
    instance: Instance,
    entries: BTreeMap<(String, String), SelectedConnection>,
    key_bindings: Vec<GcpBinding>,
}

impl QualifiedConnections {
    pub(crate) fn instance(&self) -> &Instance {
        &self.instance
    }

    /// A serving app admits its actual active artifact, which may differ from
    /// the instance's initial artifact after an authority transition. No sibling
    /// app artifact or database needs to be mounted in this pod.
    pub(crate) fn from_runtime(
        runtime: &crate::store::Runtime,
        catalog: &ReviewedCatalog,
    ) -> Result<Self> {
        let instance = Self::app_instance(Instance::load(runtime.instance_path())?, runtime.app())?;
        let artifacts = BTreeMap::from([(runtime.app().into(), runtime.artifact().clone())]);
        Self::qualify(&instance, &artifacts, catalog)
    }

    fn app_instance(mut instance: Instance, app: &str) -> Result<Instance> {
        ensure!(
            instance.apps.contains_key(app),
            "OAuth app is not installed"
        );
        instance.apps.retain(|name, _| name == app);
        if let Some(runtime) = &mut instance.oauth_runtime {
            runtime.apps.retain(|name, _| name.as_str() == app);
        }
        instance.credential_runtime = instance.credential_runtime.take().and_then(|mut runtime| {
            runtime.apps.retain(|name, _| name.as_str() == app);
            (!runtime.apps.is_empty()).then_some(runtime)
        });
        if let Some(control) = &mut instance.control {
            control.apps.retain(|name, _| name.as_str() == app);
            control
                .security_epochs
                .retain(|_, store| store.scope.app.as_str() == app);
            control
                .sources
                .retain(|name, _| control.apps.values().any(|binding| binding.source == *name));
            control.builders.retain(|name, _| {
                control.apps.values().any(|binding| {
                    binding
                        .build
                        .as_ref()
                        .is_some_and(|build| build.builder.id == *name)
                })
            });
            control.runtimes.retain(|name, _| {
                control.apps.values().any(|binding| {
                    binding
                        .build
                        .as_ref()
                        .is_some_and(|build| build.durability.id == *name)
                })
            });
        }
        if let Some(clients) = &mut instance.oauth_clients {
            clients.registrations.retain(|name, _| {
                instance.apps[app]
                    .oauth_connections
                    .values()
                    .any(|binding| binding.registration.id == *name)
            });
        }
        Instance::from_bytes(&serde_json::to_vec(&instance)?)
    }

    pub(crate) fn from_instance_file(path: &Path, catalog: &ReviewedCatalog) -> Result<Self> {
        let (instance, artifacts) = Self::load_instance_artifacts(path)?;
        Self::qualify(&instance, &artifacts, catalog)
    }

    /// Only the read-only setup command may replace desired pins. Serving
    /// constructors always compare the operator selection with admitted bytes.
    pub(super) fn prepare_instance_file(path: &Path) -> Result<Self> {
        use std::io::Read;
        let path = path.canonicalize()?;
        let mut bytes = Vec::new();
        let file = std::fs::File::open(&path)?;
        ensure!(
            file.metadata()?.is_file(),
            "OAuth setup requires a regular instance file"
        );
        file.take(1_048_577).read_to_end(&mut bytes)?;
        let instance = Self::prepare_desired_bytes(&bytes)?;
        let artifacts = Self::selected_artifacts(&path, &instance)?;
        Self::prepare_instance(instance, &artifacts)
    }

    /// Closed, bounded desired DATA only. Preserve the raw document so the full
    /// loader still sees fields whose refusal occurs before typed decoding.
    fn prepare_desired_bytes(bytes: &[u8]) -> Result<Instance> {
        let mut raw: serde_json::Value = crate::json::decode(bytes)?;
        let mut desired: Instance = serde_json::from_value(raw.clone())?;
        Self::repin_desired_epochs(&mut desired)?;
        for (app, binding) in &desired.apps {
            if binding.oauth_connections.is_empty() {
                continue;
            }
            let scope = day2_capabilities::security_epoch::AuthorityScope {
                installation: desired.installation.clone().try_into()?,
                environment: desired.environment.clone().try_into()?,
                app: app.clone().try_into()?,
            };
            let (alias, epoch) = desired
                .control
                .as_ref()
                .context("security_epoch_control_catalog_missing")?
                .security_epochs
                .iter()
                .find(|(_, epoch)| epoch.scope == scope)
                .context("security_epoch_store_missing")?;
            raw["control"]["security_epochs"][alias.as_str()]["key_set"] =
                serde_json::to_value(&epoch.key_set)?;
            for (name, family) in &binding.credential_families {
                raw["apps"][app]["credential_families"][name]["epoch_store"]["revision"] =
                    serde_json::to_value(&family.epoch_store.revision)?;
            }
        }
        Instance::from_bytes(&serde_json::to_vec(&raw)?)
    }

    /// Re-pin the selected desired digest; never create or change its authority
    /// resource, scope, UID, IAM, alias, lease or any live epoch/readiness fact.
    fn repin_desired_epochs(instance: &mut Instance) -> Result<()> {
        if let Some(control) = &instance.control {
            control.validate(instance.apps.keys().map(String::as_str))?;
        }
        let apps: Vec<_> = instance
            .apps
            .iter()
            .filter(|(_, binding)| !binding.oauth_connections.is_empty())
            .map(|(app, _)| app.clone())
            .collect();
        for app in apps {
            let scope = day2_capabilities::security_epoch::AuthorityScope {
                installation: instance.installation.clone().try_into()?,
                environment: instance.environment.clone().try_into()?,
                app: app.clone().try_into()?,
            };
            let selected: Vec<_> = instance
                .control
                .as_ref()
                .context("security_epoch_control_catalog_missing")?
                .security_epochs
                .iter()
                .filter(|(_, epoch)| epoch.scope == scope)
                .map(|(alias, _)| alias.clone())
                .collect();
            ensure!(!selected.is_empty(), "security_epoch_store_missing");
            ensure!(selected.len() == 1, "security_epoch_store_ambiguous");
            let key_set = instance.security_key_set(&app)?;
            let alias = &selected[0];
            ensure!(
                instance.apps[&app]
                    .credential_families
                    .values()
                    .all(|family| family.epoch_store.id == *alias),
                "credential_epoch_store_alias_mismatch"
            );
            let epoch = instance
                .control
                .as_mut()
                .unwrap()
                .security_epochs
                .get_mut(alias)
                .unwrap();
            epoch.key_set = key_set;
            let revision = Digest::of(epoch)?;
            for family in instance
                .apps
                .get_mut(&app)
                .unwrap()
                .credential_families
                .values_mut()
            {
                family.epoch_store.revision = revision.clone();
            }
        }
        Ok(())
    }

    fn load_instance_artifacts(
        path: &Path,
    ) -> Result<(Instance, BTreeMap<String, LoadedArtifact>)> {
        let path = path.canonicalize()?;
        let instance = Instance::load(&path)?;
        let artifacts = Self::selected_artifacts(&path, &instance)?;
        Ok((instance, artifacts))
    }

    fn selected_artifacts(
        path: &Path,
        instance: &Instance,
    ) -> Result<BTreeMap<String, LoadedArtifact>> {
        let parent = path.parent().context("OAuth instance directory missing")?;
        let mut artifacts = BTreeMap::new();
        for (app, selected) in &instance.apps {
            if selected.oauth_connections.is_empty() {
                continue;
            }
            artifacts.insert(
                app.clone(),
                LoadedArtifact::load(&parent.join(&selected.artifact))?,
            );
        }
        Ok(artifacts)
    }

    fn prepare_instance(
        instance: Instance,
        artifacts: &BTreeMap<String, LoadedArtifact>,
    ) -> Result<Self> {
        let mut instance = Self::prepare_desired_bytes(&serde_json::to_vec(&instance)?)?;
        let shell = live::shell_selection(&instance)?;
        let mapping = live::Facts::mapping_revision(&instance)?;
        let mut prepared = BTreeMap::new();
        for (app, selected) in &instance.apps {
            if selected.oauth_connections.is_empty() {
                continue;
            }
            let artifact = artifacts
                .get(app)
                .context("OAuth selected artifact missing")?;
            artifact.require_current_api()?;
            ensure!(
                artifact.contract().namespace == *app,
                "OAuth selected artifact namespace mismatch"
            );
            super::declaration::validate(
                &artifact.contract().connection_declarations,
                artifact.contract(),
            )?;
            for (name, selected_binding) in &selected.oauth_connections {
                let requirement = &artifact
                    .contract()
                    .connection_declarations
                    .iter()
                    .find(|entry| entry.registration.as_str() == name)
                    .context("OAuth selected requirement is not declared")?
                    .requirement;
                let mut binding = selected_binding.clone();
                let (reviewed, _) = super::catalog::current(requirement, &binding.profile)?;
                binding.profile = reviewed.protocol.identity().binding.clone();
                binding.requirement = requirement.nominal_identity()?;
                binding.security_shell = shell.origin.clone();
                let secrets = &instance
                    .control
                    .as_ref()
                    .context("OAuth secret catalog missing")?
                    .secrets;
                binding.custody.revision = custody_revision(
                    &instance,
                    &secrets[&binding.custody_verifier_secret],
                    &secrets[&binding.custody_encryption_secret],
                )?;
                binding.shell_attestation.revision = shell_key_revision(
                    &instance,
                    &shell.origin,
                    &secrets[&binding.shell_attestation_secret],
                )?;
                match requirement.account_policy {
                    AccountBindingPolicy::ExplicitExternalAccount => {
                        binding.account_binding = binding.shell_attestation.clone()
                    }
                    AccountBindingPolicy::MappedHuman => {
                        binding.account_binding.revision = mapping.clone()
                    }
                    AccountBindingPolicy::InstallationAccount => {
                        anyhow::bail!("installation accounts are not reviewed by this host")
                    }
                }
                prepared.insert((app.clone(), name.clone()), binding);
            }
        }
        for ((app, name), binding) in prepared {
            instance
                .apps
                .get_mut(&app)
                .context("OAuth app missing")?
                .oauth_connections
                .insert(name, binding);
        }
        Self::repin_desired_epochs(&mut instance)?;
        let instance = Instance::from_bytes(&serde_json::to_vec(&instance)?)?;
        Self::qualify(&instance, artifacts, &super::catalog::reviewed()?)
    }

    /// Requirements come from admitted artifacts, clients from the existing
    /// instance document, and shell qualification from the native live source.
    pub(crate) fn registration_targets(
        &self,
        shell: &profiles::SecurityShellEvidence,
    ) -> Result<Vec<super::registration::Target>> {
        super::clients::validate(&self.instance)?;
        let clients = self
            .instance
            .oauth_clients
            .as_ref()
            .context("OAuth clients not selected")?;
        let (identity, edge) = self.instance.security_edge()?;
        ensure!(
            shell.instance == instance_identity(&self.instance)?
                && shell.origin_url == format!("{}/", edge.origin),
            "OAuth registration shell evidence mismatch"
        );
        let control = self
            .instance
            .control
            .as_ref()
            .context("OAuth client secret catalog missing")?;
        self.entries
            .values()
            .map(|selected| {
                let client = clients
                    .registrations
                    .get(&selected.binding.registration.id)
                    .context("OAuth registration client missing")?;
                let canary = client.canary();
                let provider = client.client();
                let adapter = super::catalog::Adapter::selected(&selected.reviewed)?;
                adapter.validate_client(&provider)?;
                if matches!(
                    client,
                    day2_capabilities::oauth::RegistrationClient::LegacyGoogle(_)
                ) {
                    ensure!(
                        canary.provider_tenant == identity.hosted_domain,
                        "Google canary must use the shell's verified tenant"
                    );
                }
                let target = super::registration::Target::new(
                    &selected.requirement,
                    &selected.binding.profile,
                    instance_identity(&self.instance)?,
                    binding_namespace(&selected.binding)?,
                    shell.clone(),
                    super::registration::ClientSelection {
                        registration: selected.binding.registration.id.clone(),
                        secret: control.secrets[provider.credential()].clone(),
                        client: provider,
                        canary,
                    },
                )?;
                ensure!(
                    serde_json::to_value(&selected.binding.profile)?
                        == target.description()["profile"],
                    "OAuth registration profile mismatch"
                );
                ensure!(
                    selected.binding.security_shell == shell.origin,
                    "OAuth registration security origin changed"
                );
                Ok(target)
            })
            .collect()
    }

    pub(super) fn registration_publication(
        &self,
        registration: &BindingRef,
        namespace: &str,
        shell: &profiles::SecurityShellEvidence,
    ) -> Result<(
        &str,
        &OutboundConnectionBinding,
        &ApprovalKeyRef,
        super::registration::Target,
    )> {
        let mut found = None;
        for ((app, _), candidate) in &self.entries {
            if candidate.binding.registration == *registration
                && binding_namespace(&candidate.binding)? == namespace
            {
                ensure!(found.is_none(), "ambiguous registration publication");
                found = Some((app.as_str(), candidate));
            }
        }
        let (app, candidate) = found.context("registration publication selection retired")?;
        let target = self
            .registration_targets(shell)?
            .into_iter()
            .find(|target| target.publication_matches(&registration.id, namespace))
            .context("registration publication target missing")?;
        Ok((
            app,
            &candidate.binding,
            &candidate.shell_attestation,
            target,
        ))
    }

    fn qualify(
        instance: &Instance,
        artifacts: &BTreeMap<String, LoadedArtifact>,
        catalog: &ReviewedCatalog,
    ) -> Result<Self> {
        let instance = Instance::from_bytes(&serde_json::to_vec(instance)?)?;
        let mut entries = BTreeMap::new();
        let mut keys = BTreeMap::new();
        for (app, selected) in &instance.apps {
            if selected.oauth_connections.is_empty() {
                continue;
            }
            ensure!(selected.edge.is_some(), "OAuth selected app edge missing");
            let artifact = artifacts
                .get(app)
                .context("OAuth selected artifact missing")?;
            artifact.require_current_api()?;
            ensure!(
                artifact.contract().namespace == *app,
                "OAuth selected artifact namespace mismatch"
            );
            super::declaration::validate(
                &artifact.contract().connection_declarations,
                artifact.contract(),
            )?;
            let declarations = &artifact.contract().connection_declarations;
            for (name, binding) in &selected.oauth_connections {
                let requirement = declarations
                    .iter()
                    .find(|entry| entry.registration.as_str() == name)
                    .context("OAuth selected requirement is not declared")?
                    .requirement
                    .clone();
                ensure!(
                    requirement.nominal_identity()? == binding.requirement,
                    "OAuth selected requirement contract changed"
                );
                let (reviewed, permission) = catalog.resolve(&requirement, &binding.profile)?;
                // Abstract catalog admission is separate from executability.
                // A selected native runtime/client must have a reviewed wire
                // adapter; failure cannot skip provider/account validation.
                let native = match super::catalog::Adapter::selected(&reviewed) {
                    Ok(adapter) => Some(adapter),
                    Err(error)
                        if instance.oauth_runtime.is_some() || instance.oauth_clients.is_some() =>
                    {
                        return Err(error);
                    }
                    Err(_) => None,
                };
                if let Some(adapter) = native
                    && let Some(runtime) = &instance.oauth_runtime
                {
                    let policy = runtime
                        .apps
                        .get(&Name::try_from(app.clone())?)
                        .context("OAuth runtime app missing")?
                        .accounts
                        .get(&Name::try_from(name.clone())?)
                        .context("OAuth runtime account policy missing")?;
                    adapter.validate_account(&requirement, policy)?;
                }
                ensure!(
                    native.is_none() || instance.oauth_clients.is_some(),
                    "OAuth provider client selection missing"
                );
                let client_credential = instance
                    .oauth_clients
                    .as_ref()
                    .map(|clients| {
                        let client = clients
                            .registrations
                            .get(&binding.registration.id)
                            .context("OAuth registration client missing")?;
                        let client = client.client();
                        if let Some(adapter) = native {
                            adapter.validate_client(&client)?;
                        }
                        super::clients::selected_provider_credential(&instance, &client)
                    })
                    .transpose()?;
                let control = instance
                    .control
                    .as_ref()
                    .context("OAuth secret provider catalog missing")?;
                let verifier = &control.secrets[&binding.custody_verifier_secret];
                let encryption = &control.secrets[&binding.custody_encryption_secret];
                let attestation = &control.secrets[&binding.shell_attestation_secret];
                ensure!(
                    verifier != encryption && verifier != attestation && encryption != attestation,
                    "OAuth key roles must use distinct secret versions"
                );
                ensure!(
                    binding.custody.revision == custody_revision(&instance, verifier, encryption)?,
                    "OAuth custody secret selection changed"
                );
                ensure!(
                    binding.shell_attestation.revision
                        == shell_key_revision(&instance, &binding.security_shell, attestation)?,
                    "OAuth shell attestation secret selection changed"
                );
                if requirement.account_policy == AccountBindingPolicy::ExplicitExternalAccount {
                    ensure!(
                        binding.account_binding == binding.shell_attestation,
                        "OAuth external approval must use the selected shell attestation binding"
                    );
                }
                let custody_verifier = key_ref(&binding.custody, verifier);
                let custody_encryption = key_ref(&binding.custody, encryption);
                let shell_attestation = key_ref(&binding.shell_attestation, attestation);
                for (reference, purpose, secret) in [
                    (
                        &custody_verifier,
                        ApprovalKeyPurpose::CustodyVerifier,
                        verifier,
                    ),
                    (
                        &custody_encryption,
                        ApprovalKeyPurpose::CustodyEncryption,
                        encryption,
                    ),
                    (
                        &shell_attestation,
                        ApprovalKeyPurpose::ShellAttestation,
                        attestation,
                    ),
                ] {
                    let key = (reference.binding.id.as_str().to_owned(), purpose);
                    let value = (reference.binding.clone(), gcp_version(secret));
                    if let Some(previous) = keys.insert(key, value.clone()) {
                        ensure!(previous == value, "ambiguous OAuth key binding");
                    }
                }
                entries.insert(
                    (app.clone(), name.clone()),
                    SelectedConnection {
                        requirement,
                        permission,
                        reviewed,
                        binding: binding.clone(),
                        custody_verifier,
                        custody_encryption,
                        shell_attestation,
                        client_credential,
                    },
                );
                ensure!(entries.len() <= 128, "OAuth selected connection budget");
            }
        }
        ensure!(keys.len() <= 128, "OAuth selected key budget");
        let mut resources = std::collections::BTreeSet::new();
        let key_bindings = keys
            .into_iter()
            .map(|((_, purpose), (binding, secret))| {
                ensure!(
                    resources.insert((
                        secret.project_number,
                        secret.secret.clone(),
                        secret.version
                    )),
                    "ambiguous OAuth physical key binding"
                );
                Ok((binding, purpose, secret))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            instance,
            entries,
            key_bindings,
        })
    }
}

pub(crate) fn instance_identity(instance: &Instance) -> Result<BindingRef> {
    BindingRef::pin(
        Name::try_from("oauth_instance".to_owned())?,
        &(
            "oauth-instance-v1",
            &instance.installation,
            &instance.environment,
        ),
    )
}

pub(crate) fn custody_revision(
    instance: &Instance,
    verifier: &SecretProvider,
    encryption: &SecretProvider,
) -> Result<Digest> {
    Digest::of(&(
        "oauth-custody-secret-selection-v1",
        instance_identity(instance)?,
        verifier,
        encryption,
    ))
}

pub(crate) fn shell_key_revision(
    instance: &Instance,
    origin: &day2_capabilities::oauth::SecurityOriginRef,
    secret: &SecretProvider,
) -> Result<Digest> {
    Digest::of(&(
        "oauth-shell-secret-selection-v1",
        instance_identity(instance)?,
        origin,
        secret,
    ))
}

fn gcp_version(secret: &SecretProvider) -> GcpSecretVersion {
    let SecretProvider::GcpVersion {
        project_number,
        secret,
        version,
    } = secret;
    GcpSecretVersion {
        project_number: project_number.get(),
        secret: secret.as_str().into(),
        version: version.get(),
    }
}

fn key_ref(binding: &BindingRef, secret: &SecretProvider) -> ApprovalKeyRef {
    ApprovalKeyRef {
        binding: binding.clone(),
        version: gcp_version(secret).version.to_string(),
    }
}

pub(crate) fn binding_namespace(binding: &OutboundConnectionBinding) -> Result<String> {
    // The registered redirect belongs to the instance binding, not one human's
    // slot. The private attempt still pins its exact owner and unique slot.
    let digest = Digest::of(&(
        "oauth-selected-binding-namespace-v1",
        &binding.namespace,
        &binding.requirement,
        &binding.profile,
        &binding.registration.id,
        &binding.custody,
        &binding.security_shell,
        &binding.account_binding,
        &binding.shell_attestation,
        &binding.product_return,
    ))?;
    Ok(format!(
        "oauth_binding_{}",
        day2_assets::hash_part(digest.as_str())?
    ))
}

/// Readiness is resolved privately at request time, separately from desired
/// instance configuration. Its implementation must check current external
/// qualification; an operator-authored digest alone is not readiness.
pub(crate) trait OutboundReadiness: Send + Sync {
    fn selected_runtime(&self) -> Result<Option<Digest>> {
        Ok(None)
    }

    fn observe_identity(&self, _identity: &crate::iap::Verified, _now: i64) -> Result<()> {
        Ok(())
    }

    fn current(
        &self,
        binding: &OutboundConnectionBinding,
        slot: &ConnectionSlotKey,
        now: i64,
    ) -> Result<Option<profiles::OutboundInstanceEvidence>>;
}

#[path = "live_readiness.rs"]
pub(crate) mod live;

struct AuthorityState {
    selected: QualifiedConnections,
    keys: Option<Arc<dyn ApprovalKeyProvider>>,
}

pub(crate) struct ArtifactApprovalAuthority {
    state: RwLock<AuthorityState>,
    readiness: Arc<dyn OutboundReadiness>,
}

impl ArtifactApprovalAuthority {
    pub(crate) fn with_gcp(
        selected: QualifiedConnections,
        readiness: Arc<dyn OutboundReadiness>,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Self> {
        let keys = Self::gcp_keys(&selected, tokens)?;
        Ok(Self {
            state: RwLock::new(AuthorityState { selected, keys }),
            readiness,
        })
    }

    #[cfg(test)]
    pub(super) fn with_keys(
        selected: QualifiedConnections,
        readiness: Arc<dyn OutboundReadiness>,
        keys: Arc<dyn ApprovalKeyProvider>,
    ) -> Self {
        Self {
            state: RwLock::new(AuthorityState {
                selected,
                keys: Some(keys),
            }),
            readiness,
        }
    }

    fn gcp_keys(
        selected: &QualifiedConnections,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<Option<Arc<dyn ApprovalKeyProvider>>> {
        if selected.key_bindings.is_empty() {
            return Ok(None);
        }
        Ok(Some(Arc::new(GcpApprovalKeys::new(
            selected.key_bindings.clone(),
            tokens,
        )?)))
    }

    pub(crate) fn replace_with_gcp(
        &self,
        selected: QualifiedConnections,
        tokens: Arc<dyn AccessTokenSource>,
    ) -> Result<()> {
        let keys = Self::gcp_keys(&selected, tokens)?;
        *self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("OAuth selection lock poisoned"))? =
            AuthorityState { selected, keys };
        Ok(())
    }

    pub(crate) fn receive_registration(
        &self,
        proof: &super::registration::publication::Publication,
        app: &str,
        identity: &crate::iap::Verified,
        readiness: &super::registration::ProviderReadiness,
        now: i64,
    ) -> Result<()> {
        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth selection lock poisoned"))?;
        let receipt = super::registration::publication::verify(
            proof,
            app,
            identity,
            &state.selected,
            state
                .keys
                .as_ref()
                .context("OAuth selected key provider missing")?
                .as_ref(),
            now,
        )?;
        readiness.publish(receipt)
    }
}

impl ArtifactApprovalAuthority {
    fn terms(
        &self,
        state: &AuthorityState,
        app: &str,
        intent: &connect::ConnectIntent,
        callback: &connect::CallbackBinding,
        now: i64,
    ) -> Result<Option<ApprovalTerms>> {
        let selected = &state.selected;
        if let Some(runtime) = &selected.instance.oauth_runtime {
            ensure!(
                self.readiness.selected_runtime()? == Some(Digest::of(runtime)?),
                "OAuth live runtime selection changed"
            );
        }
        let mut found = None;
        for ((candidate_app, _), candidate) in &selected.entries {
            if candidate_app != app {
                continue;
            }
            let slot = ConnectionSlotKey {
                installation: candidate.binding.namespace.installation.clone(),
                environment: candidate.binding.namespace.environment.clone(),
                app: candidate.binding.namespace.app.clone(),
                requirement: candidate.requirement.logical_id.clone(),
                owner: match candidate.requirement.owner {
                    day2_capabilities::oauth::ConnectionOwner::CurrentHuman => SlotOwner::Human {
                        subject: intent.owner.clone(),
                    },
                    day2_capabilities::oauth::ConnectionOwner::Installation => {
                        SlotOwner::Installation
                    }
                },
            };
            let slot_id = slot.id(&candidate.requirement)?;
            if slot_id.as_str() != intent.slot {
                continue;
            }
            ensure!(found.is_none(), "ambiguous OAuth selected requirement");
            found = Some((candidate, slot));
        }
        let Some((candidate, slot)) = found else {
            return Ok(None);
        };
        // Mapped-human and installation connections do not enter the external
        // account approval shell. Their bindings still qualify above.
        if candidate.requirement.account_policy != AccountBindingPolicy::ExplicitExternalAccount {
            return Ok(None);
        }
        let expected_namespace = binding_namespace(&candidate.binding)?;
        ensure!(
            callback.binding_namespace() == expected_namespace,
            "OAuth selected binding generation changed"
        );
        let started = crate::oauth::effects::Instant::now();
        let Some(evidence) = self.readiness.current(&candidate.binding, &slot, now)? else {
            return Ok(None);
        };
        let (account, policy) = match &evidence.account {
            profiles::AccountBindingEvidence::MappedHuman { mapping, .. } => {
                (mapping, AccountBindingPolicy::MappedHuman)
            }
            profiles::AccountBindingEvidence::ExplicitExternal { approval, .. } => {
                (approval, AccountBindingPolicy::ExplicitExternalAccount)
            }
            profiles::AccountBindingEvidence::Installation { organization, .. } => {
                (organization, AccountBindingPolicy::InstallationAccount)
            }
        };
        ensure!(
            evidence.instance == instance_identity(&selected.instance)?
                && evidence.binding_namespace == expected_namespace
                && evidence.registration.registration == candidate.binding.registration
                && candidate
                    .client_credential
                    .as_ref()
                    .is_none_or(|credential| *credential == evidence.registration.client_credential)
                && evidence.shell.origin == candidate.binding.security_shell
                && evidence.custody == candidate.binding.custody
                && evidence.product_return == candidate.binding.product_return
                && *account == candidate.binding.account_binding
                && policy == candidate.requirement.account_policy,
            "OAuth readiness does not match selected instance binding"
        );
        let entry = AdmittedApproval {
            requirement: candidate.requirement.clone(),
            permission: candidate.permission.clone(),
            reviewed: candidate.reviewed.clone(),
            instance: evidence,
            custody_verifier: candidate.custody_verifier.clone(),
            custody_encryption: candidate.custody_encryption.clone(),
            shell_attestation: candidate.shell_attestation.clone(),
        };
        let authority = SelectedApprovalAuthority::new(
            &selected.instance,
            BTreeMap::from([((app.to_owned(), intent.slot.clone()), entry)]),
            state
                .keys
                .clone()
                .context("OAuth selected key provider missing")?,
        )?;
        let Some(terms) = authority.current(app, intent, callback, now)? else {
            return Ok(None);
        };
        // Exact-version key retrieval may consume the readiness lease. Check
        // the same live facts again before returning authority for settlement.
        let at = now
            .checked_add(i64::try_from(started.elapsed().as_secs())?)
            .context("OAuth readiness clock overflow")?;
        let Some(current) = self.readiness.current(&candidate.binding, &slot, at)? else {
            return Ok(None);
        };
        ensure!(
            current == terms.instance,
            "OAuth readiness changed during key acquisition"
        );
        Ok(Some(terms))
    }
}

impl ApprovalAuthority for ArtifactApprovalAuthority {
    fn observe_identity(&self, app: &str, identity: &crate::iap::Verified, now: i64) -> Result<()> {
        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth selection lock poisoned"))?;
        ensure!(
            state.selected.instance.apps.contains_key(app),
            "OAuth human observation app mismatch"
        );
        self.readiness.observe_identity(identity, now)
    }

    fn current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        callback: &connect::CallbackBinding,
        now: i64,
    ) -> Result<Option<ApprovalTerms>> {
        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth selection lock poisoned"))?;
        self.terms(&state, app, intent, callback, now)
    }

    fn with_current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        callback: &connect::CallbackBinding,
        now: i64,
        commit: &mut dyn FnMut(ApprovalTerms) -> Result<bool>,
    ) -> Result<bool> {
        let state = self
            .state
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth selection lock poisoned"))?;
        let Some(terms) = self.terms(&state, app, intent, callback, now)? else {
            return Ok(false);
        };
        commit(terms)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{approval_registry::ApprovalKeyMaterial, connect::CallbackBindingSpec};
    use super::*;
    use crate::artifact::Artifact;
    use day2_capabilities::{
        credentials::Namespace,
        oauth::{
            ConnectionDeclaration, ConnectionOwner, ProductReturnRef, ProviderCallbackRef,
            SecurityOriginRef,
        },
    };
    use serde_json::json;
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicUsize, Ordering},
    };

    fn name(raw: &str) -> Name {
        Name::try_from(raw.to_owned()).unwrap()
    }
    fn pin(raw: &str) -> BindingRef {
        BindingRef::pin(name(raw), &raw).unwrap()
    }

    struct Fixture {
        instance: Instance,
        artifacts: BTreeMap<String, LoadedArtifact>,
        catalog: ReviewedCatalog,
        evidence: profiles::OutboundInstanceEvidence,
        intent: connect::ConnectIntent,
        callback: connect::CallbackBinding,
    }

    impl Fixture {
        fn qualify(&self) -> Result<QualifiedConnections> {
            QualifiedConnections::qualify(&self.instance, &self.artifacts, &self.catalog)
        }
    }

    /// Exact test key roles remain separated: the mounted shell can load only
    /// attestation; the app authority owns verifier, encryption and attestation.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
    pub(in crate::oauth) struct ReplayKeyCounts {
        pub shell_attestation: usize,
        pub app_verifier: usize,
        pub app_encryption: usize,
        pub app_attestation: usize,
    }

    struct ReplayMountedKeys {
        shell: bool,
        selected: Vec<(ApprovalKeyRef, ApprovalKeyPurpose)>,
        counts: Arc<std::sync::Mutex<ReplayKeyCounts>>,
        delay: Arc<std::sync::atomic::AtomicBool>,
        advance: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    }

    impl ApprovalKeyProvider for ReplayMountedKeys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            ensure!(
                self.selected
                    .iter()
                    .any(|(expected, role)| expected == reference && *role == purpose),
                "replay selected key binding/version/purpose changed"
            );
            let mut counts = self.counts.lock().unwrap();
            match (self.shell, purpose) {
                (true, ApprovalKeyPurpose::ShellAttestation) => counts.shell_attestation += 1,
                (false, ApprovalKeyPurpose::CustodyVerifier) => counts.app_verifier += 1,
                (false, ApprovalKeyPurpose::CustodyEncryption) => counts.app_encryption += 1,
                (false, ApprovalKeyPurpose::ShellAttestation) => counts.app_attestation += 1,
                _ => anyhow::bail!("replay shell attempted custody access"),
            }
            drop(counts);
            let material = Keys::default().load(reference, purpose)?;
            if self.shell && self.delay.swap(false, Ordering::SeqCst) {
                (self.advance)()?;
            }
            Ok(material)
        }
    }

    pub(in crate::oauth) struct MountedReplayFixture {
        pub signer: Arc<ArtifactShellSigner>,
        pub registry: Arc<super::super::approval_registry::StoredApprovalRegistry>,
        pub attempt: String,
        pub slot: String,
        pub audience: String,
        pub client: String,
        original: connect::ConnectIntent,
        callback: connect::CallbackBinding,
        exchange: super::super::exchange::ExchangeBinding,
        expected_account: Digest,
        expected_scopes: Digest,
        expected_observed: super::super::account::ProviderAccount,
        custody: crate::managed_credentials::crypto::KeyLease,
        counts: Arc<std::sync::Mutex<ReplayKeyCounts>>,
        delay: Arc<std::sync::atomic::AtomicBool>,
    }

    impl MountedReplayFixture {
        pub fn key_counts(&self) -> ReplayKeyCounts {
            *self.counts.lock().unwrap()
        }

        pub fn delay_next_attestation(&self) {
            self.delay.store(true, Ordering::SeqCst);
        }

        /// Literal scheduled owner and admitted DATA remain independent of
        /// the post's result. Key use here is private cryptographic observation
        /// with the original fixture lease, not another provider acquisition.
        pub fn verify_rows(&self, db: &rusqlite::Connection) -> Result<Digest> {
            let (intent, state, account, scope): (
                connect::ConnectIntent,
                String,
                Option<String>,
                Option<String>,
            ) = db.query_row(
                "SELECT slot,expected_generation,expected_epoch,proposed_generation,owner,profile,
                    registration,callback,consent,expires_at,state,account,scope_evidence
                 FROM oauth_connect_attempts WHERE attempt=?1",
                [&self.attempt],
                |row| {
                    Ok((
                        connect::ConnectIntent {
                            attempt: self.attempt.clone(),
                            slot: row.get(0)?,
                            expected_generation: row.get(1)?,
                            expected_epoch: row.get(2)?,
                            proposed_generation: row.get(3)?,
                            owner: row.get(4)?,
                            profile: row.get(5)?,
                            registration: row.get(6)?,
                            callback: row.get(7)?,
                            consent: row.get(8)?,
                            expires_at: row.get(9)?,
                        },
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                    ))
                },
            )?;
            ensure!(
                intent == self.original
                    && intent.owner == "alice@example.com"
                    && intent.expected_epoch == 1
                    && intent.proposed_generation == 1,
                "replay original OAuth owner/intent/epoch changed"
            );
            ensure!(
                super::super::exchange::load_binding(db, &self.attempt)?.as_ref()
                    == Some(&self.exchange),
                "replay original OAuth registration/callback/namespace exchange changed"
            );
            let stored_callback: String = db.query_row(
                "SELECT binding FROM oauth_callback_bindings WHERE attempt=?1",
                [&self.attempt],
                |row| row.get(0),
            )?;
            ensure!(
                crate::json::decode::<connect::CallbackBinding>(stored_callback.as_bytes())?
                    == self.callback,
                "replay original OAuth callback/session changed"
            );
            let has_account = matches!(state.as_str(), "awaiting_account_approval" | "activated");
            ensure!(
                (account.as_deref(), scope.as_deref())
                    == if has_account {
                        (
                            Some(self.expected_account.as_str()),
                            Some(self.expected_scopes.as_str()),
                        )
                    } else {
                        (None, None)
                    },
                "replay wrong original OAuth provider account/scopes"
            );
            if state == "awaiting_account_approval" {
                let pending = super::super::custody::load_pending_external_identity(
                    db,
                    &self.custody,
                    &self.original,
                    &self.exchange,
                    self.expected_account.as_str(),
                    self.expected_scopes.as_str(),
                )?
                .context("replay original OAuth quarantine missing")?;
                ensure!(
                    pending.observed == self.expected_observed && pending.quarantined_at == 999,
                    "replay wrong original OAuth provider identity"
                );
            }
            let active: i64 =
                db.query_row("SELECT count(*) FROM oauth_connection_slots", [], |row| {
                    row.get(0)
                })?;
            let token_count: i64 =
                db.query_row("SELECT count(*) FROM oauth_private_tokens", [], |row| {
                    row.get(0)
                })?;
            ensure!(
                active == i64::from(state == "activated") && token_count == active,
                "replay OAuth publication outside original activation"
            );
            if active == 1 {
                let affinity = Digest::of(&(
                    "oauth-connection-affinity-v1",
                    &intent.owner,
                    &intent.profile,
                    &intent.registration,
                    &intent.callback,
                    &intent.consent,
                    self.expected_account.as_str(),
                    self.expected_scopes.as_str(),
                    1i64,
                    1i64,
                ))?;
                let exact: i64 = db.query_row("SELECT count(*) FROM oauth_connection_slots WHERE slot=?1 AND generation=1
                    AND token_version=1 AND security_epoch=1 AND profile=?2 AND account=?3 AND affinity=?4 AND status='active'",
                    rusqlite::params![self.slot,intent.profile,self.expected_account.as_str(),affinity.as_str()],|row| row.get(0))?;
                ensure!(exact == 1, "replay wrong OAuth slot/affinity/owner link");
                let (identity, key, nonce, ciphertext): (String, String, Vec<u8>, Vec<u8>) = db
                    .query_row(
                    "SELECT identity_digest,key_version,nonce,ciphertext FROM oauth_private_tokens
                     WHERE reference=?1 AND slot=?2 AND generation=1 AND account=?3",
                    rusqlite::params![
                        self.exchange.token_slot_ref,
                        self.slot,
                        self.expected_account.as_str()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                // Serialize the identity in the owning struct's declaration
                // order: Value maps have a different byte ordering for AAD.
                #[derive(serde::Serialize)]
                struct TokenIdentity<'a> {
                    purpose: &'a str,
                    attempt: &'a str,
                    slot: &'a str,
                    generation: i64,
                    security_epoch: i64,
                    profile: &'a BindingRef,
                    registration: &'a BindingRef,
                    callback: &'a ProviderCallbackRef,
                    custody: &'a BindingRef,
                    account: Option<&'a str>,
                }
                let expected = TokenIdentity {
                    purpose: "ConnectionTokens",
                    attempt: &intent.attempt,
                    slot: &intent.slot,
                    generation: 1,
                    security_epoch: 1,
                    profile: &self.exchange.profile,
                    registration: &self.exchange.registration,
                    callback: &self.exchange.callback,
                    custody: &self.exchange.custody,
                    account: Some(self.expected_account.as_str()),
                };
                ensure!(
                    identity
                        == Digest::of(&("oauth-private-material-identity-v1", &expected))?.as_str()
                        && key == self.custody.encryption_version,
                    "replay wrong OAuth token material identity"
                );
                let aad =
                    serde_json::to_vec(&("oauth-private-material-aes256gcm-v1", &expected, &key))?;
                let mut plaintext =
                    self.custody
                        .open_oauth(&aad, nonce.as_slice().try_into()?, &ciphertext)?;
                let token: serde_json::Value = crate::json::decode(&plaintext)?;
                plaintext.fill(0);
                ensure!(
                    token
                        == json!({"access_token":"private-replay-provider-token","refresh_token":"private-replay-provider-refresh-token","expires_in":3600}),
                    "replay published wrong original provider token"
                );
            }
            Digest::of(&(
                "original-oauth-owner-relations-v2",
                &intent.owner,
                &intent.profile,
                &intent.registration,
                &intent.callback,
                &intent.consent,
                &self.callback,
                &self.expected_account,
                &self.expected_scopes,
                &self.expected_observed,
            ))
        }
    }

    /// Synthetic current desired data and readiness, qualified normally. No
    /// verified-human scalar or local fake signer is returned by this helper.
    pub(in crate::oauth) fn mounted_replay_fixture(
        database: &std::path::Path,
        advance: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    ) -> Result<MountedReplayFixture> {
        use super::super::{
            approval_registry::ApprovalAuthority, exchange, profiles::OutboundQualification,
        };
        let mut facts = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        facts.intent.owner = "alice@example.com".into();
        facts.intent.attempt =
            super::super::shell_transport::scoped_attempt("company", "production", "workspace")?;
        facts.intent.expires_at = 1_300;
        let selected = facts.qualify()?;
        let choice = selected
            .entries
            .values()
            .next()
            .context("replay selected connection")?;
        let slot = ConnectionSlotKey {
            installation: choice.binding.namespace.installation.clone(),
            environment: choice.binding.namespace.environment.clone(),
            app: choice.binding.namespace.app.clone(),
            requirement: choice.requirement.logical_id.clone(),
            owner: SlotOwner::Human {
                subject: facts.intent.owner.clone(),
            },
        };
        facts.intent.slot = slot.id(&choice.requirement)?.as_str().into();
        if let profiles::AccountBindingEvidence::ExplicitExternal { owner, .. } =
            &mut facts.evidence.account
        {
            *owner = facts.intent.owner.clone();
        }
        let counts = Arc::new(std::sync::Mutex::new(ReplayKeyCounts::default()));
        let delay = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let app_keys = Arc::new(ReplayMountedKeys {
            shell: false,
            selected: vec![
                (
                    choice.custody_verifier.clone(),
                    ApprovalKeyPurpose::CustodyVerifier,
                ),
                (
                    choice.custody_encryption.clone(),
                    ApprovalKeyPurpose::CustodyEncryption,
                ),
                (
                    choice.shell_attestation.clone(),
                    ApprovalKeyPurpose::ShellAttestation,
                ),
            ],
            counts: counts.clone(),
            delay: delay.clone(),
            advance: advance.clone(),
        });
        let shell_keys = Arc::new(ReplayMountedKeys {
            shell: true,
            selected: vec![(
                choice.shell_attestation.clone(),
                ApprovalKeyPurpose::ShellAttestation,
            )],
            counts: counts.clone(),
            delay: delay.clone(),
            advance,
        });
        let readiness = Arc::new(Readiness {
            runtime: Digest::of(
                facts
                    .instance
                    .oauth_runtime
                    .as_ref()
                    .context("replay runtime data")?,
            )?,
            current: RwLock::new(Some(facts.evidence.clone())),
            calls: AtomicUsize::new(0),
        });
        let authority = Arc::new(ArtifactApprovalAuthority::with_keys(
            facts.qualify()?,
            readiness,
            app_keys,
        ));
        let terms = authority
            .current("workspace", &facts.intent, &facts.callback, 1_000)?
            .context("replay app selection unavailable")?;
        let input = || OutboundQualification {
            intent: &facts.intent,
            binding: &facts.callback,
            requirement: &terms.requirement,
            permission: &terms.permission,
            reviewed: &terms.reviewed,
            instance: &terms.instance,
        };
        let mut db = crate::store::open(database)?;
        // Same owning core definition used by mounted app-registry fixtures;
        // this standalone OAuth DB has no Runtime initialization entrance.
        db.execute_batch(crate::audit::PRINCIPALS_DDL)?;
        connect::install_schema(&db)?;
        let prepared = exchange::prepare_authorization(
            input(),
            &terms.custody_key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )?;
        let code_ref = prepared.code_ref().to_owned();
        ensure!(prepared.begin(&mut db, 997)?, "replay pending begin");
        let raw = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", "0123456789abcdefghijklmnopqrstuvwxyzABCDEF")
            .append_pair("code", "private-replay-provider-code")
            .append_pair("iss", &terms.reviewed.issuer_url)
            .finish();
        let outcome = exchange::handle_qualified_callback(
            &mut db,
            input(),
            super::super::outbound::CallbackIngress {
                attempt: &facts.intent.attempt,
                raw_query: raw.as_bytes(),
                route: &terms.instance.registration.callback,
                session: facts.callback.session(),
                issuer_binding: &terms.reviewed.issuer,
                code_ref: &code_ref,
                now: 998,
            },
            &terms.custody_key,
        )?;
        ensure!(
            matches!(
                outcome,
                super::super::outbound::CallbackOutcome::CodeAccepted { .. }
            ),
            "replay provider callback"
        );
        let permit = exchange::authorize_and_commit_qualified_exchange(&mut db, input(), 999)?
            .context("replay provider exchange permit")?;
        let scopes: BTreeSet<String> = terms
            .permission
            .action_scopes
            .values()
            .flatten()
            .cloned()
            .collect();
        let expected_scopes = Digest::of(&(
            "oauth-accepted-scopes-v1",
            terms.permission.consent_digest(&terms.requirement)?,
            &scopes,
        ))?;
        let body = serde_json::to_vec(
            &json!({"access_token":"private-replay-provider-token","refresh_token":"private-replay-provider-refresh-token",
            "token_type":"Bearer","expires_in":3600,"scope":scopes.into_iter().collect::<Vec<_>>().join(" ")}),
        )?;
        let response = match permit.send(|_| {
            Ok(exchange::TokenHttpResponse {
                status: 200,
                content_type: "application/json".into(),
                body,
            })
        }) {
            exchange::ExchangeObservation::Response(response) => response,
            exchange::ExchangeObservation::Uncertain(_) => {
                anyhow::bail!("replay provider exchange uncertain")
            }
        };
        let observed = super::super::account::ProviderAccount {
            issuer: terms.reviewed.issuer_url.clone(),
            subject: "replay-provider-subject".into(),
            tenant: "company".into(),
            display_email: "external@example.net".into(),
        };
        let prepared = response
            .validate_external(input(), &observed)?
            .prepare_quarantine(&terms.custody_key, 999)?;
        ensure!(
            super::super::external::quarantine_external(&mut db, prepared, input(), 999)?,
            "replay quarantine"
        );
        let expected_account = super::super::account::provider_account_digest(&observed)?;
        let exchange = super::super::exchange::load_binding(&db, &facts.intent.attempt)?
            .context("replay actual exchange binding")?;
        ensure!(
            exchange.profile == terms.permission.profile
                && exchange.registration == terms.instance.registration.registration
                && exchange.callback == terms.instance.registration.callback
                && exchange.custody == terms.instance.custody,
            "replay original admitted exchange selection changed"
        );
        drop(db);
        *counts.lock().unwrap() = ReplayKeyCounts::default();
        let signer = Arc::new(ArtifactShellSigner {
            state: RwLock::new(AuthorityState {
                selected: facts.qualify()?,
                keys: Some(shell_keys),
            }),
        });
        let registry = Arc::new(
            super::super::approval_registry::StoredApprovalRegistry::new(
                BTreeMap::from([("workspace".into(), database.to_path_buf())]),
                authority,
            )?,
        );
        Ok(MountedReplayFixture {
            signer,
            registry,
            attempt: facts.intent.attempt.clone(),
            slot: facts.intent.slot.clone(),
            audience: facts
                .instance
                .security_shell
                .as_ref()
                .unwrap()
                .iap_audience
                .clone(),
            client: facts
                .instance
                .oauth_clients
                .as_ref()
                .unwrap()
                .reauthentication
                .client_id
                .clone(),
            original: facts.intent,
            callback: facts.callback,
            exchange,
            expected_account,
            expected_scopes,
            expected_observed: observed,
            custody: terms.custody_key,
            counts,
            delay,
        })
    }

    fn reviewed_google_fixture() -> Result<Fixture> {
        let mut fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        fixture.catalog = super::super::google::catalog()?;
        let profile =
            super::super::google::reviewed(&AccountBindingPolicy::ExplicitExternalAccount)?
                .profile
                .protocol
                .identity()
                .binding
                .clone();
        fixture
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap()
            .profile = profile;
        Ok(fixture)
    }

    pub(in crate::oauth) fn publication_fixture()
    -> Result<(QualifiedConnections, profiles::SecurityShellEvidence)> {
        let mut fixture = reviewed_google_fixture()?;
        let target = fixture
            .qualify()?
            .registration_targets(&fixture.evidence.shell)?
            .remove(0);
        fixture
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap()
            .registration =
            serde_json::from_value(target.setup_description()?["registration_selection"].clone())?;
        Ok((fixture.qualify()?, fixture.evidence.shell))
    }

    /// Two companies use the same app declaration and platform code. Only the
    /// existing shared instance selectors choose clients and account ceilings.
    fn gitlab_instance(
        company: &str,
        client_id: &str,
        allowed: &[&str],
    ) -> Result<(Instance, BTreeMap<String, LoadedArtifact>)> {
        let mut baseline = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let mut instance = live::tests::selected()?.instance;
        instance.installation = company.into();
        instance.oauth_clients = Some(serde_json::from_value(json!({
            "version":2,"reauthentication":{"client_id":"123-reauth.apps.googleusercontent.com","credential":"reauth_client"},
            "registrations":{"calendar_registration":{"client":{"kind":"gitlab","client_id":client_id,"credential":"calendar_client"},
                "canary":{"qualification_subject":"accounts.google.com:qualification-human","provider_subject":"42","provider_tenant":"gitlab.com"}}}
        }))?);
        instance
            .oauth_runtime
            .as_mut()
            .unwrap()
            .apps
            .get_mut(&name("workspace"))
            .unwrap()
            .accounts
            .insert(
                name("calendar"),
                day2_capabilities::oauth::ProviderAccountPolicy::ExternalAccounts {
                    allowed_tenants: BTreeSet::from(["gitlab.com".into()]),
                    allowed_subjects: Some(allowed.iter().map(|s| (*s).to_owned()).collect()),
                },
            );
        let mut contract = baseline.artifacts["workspace"].contract().clone();
        let requirement = &mut contract.connection_declarations[0].requirement;
        requirement.capability = super::super::gitlab::CAPABILITY.into();
        requirement.actions = BTreeSet::from(["list_projects".into()]);
        requirement.account_policy = AccountBindingPolicy::ExplicitExternalAccount;
        let binding = instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap();
        binding.namespace.installation = name(company);
        binding.profile = super::super::gitlab::reviewed()?
            .profile
            .protocol
            .identity()
            .binding
            .clone();
        baseline.artifacts.insert(
            "workspace".into(),
            LoadedArtifact::from_contract_for_tests(
                "synthetic-artifact".into(),
                std::path::PathBuf::from("/fixture/workspace"),
                contract,
            ),
        );
        crate::oauth::clients::tests::select_desired_epoch(
            &mut instance,
            "workspace",
            "app@company-tools.iam.gserviceaccount.com",
        )?;
        Ok((instance, baseline.artifacts))
    }

    #[test]
    fn companies_select_provider_clients_and_policies_without_kernel_changes() -> Result<()> {
        let mut companies = Vec::new();
        for (company, client, ceiling) in [
            ("company_a", "a".repeat(64), vec!["42"]),
            ("company_b", "b".repeat(64), vec!["42", "43"]),
        ] {
            let (instance, artifacts) = gitlab_instance(company, &client, &ceiling)?;
            let mut selected = QualifiedConnections::prepare_instance(instance, &artifacts)?;
            live::setup_selected(&mut selected)?;
            let shell = live::shell_selection(&selected.instance)?;
            let target = selected.registration_targets(&shell)?.remove(0);
            let description = target.description();
            assert_eq!(description["client_id"], client);
            assert_eq!(description["scopes"], json!(["read_api", "read_user"]));
            assert_eq!(
                description["refresh_recovery"],
                "reauthorize_on_uncertainty"
            );
            assert!(description.get("access_type").is_none());
            let catalog = super::super::catalog::reviewed()?;
            QualifiedConnections::qualify(&selected.instance, &artifacts, &catalog)?;
            // Setup is reproducible and cannot synthesize a native live receipt.
            let mut repeat =
                QualifiedConnections::prepare_instance(selected.instance.clone(), &artifacts)?;
            assert_eq!(
                live::setup_selected(&mut repeat)?,
                live::setup_selected(&mut selected)?
            );
            // Exercise the signed publication path with the provider account
            // distinct from the selected shell qualification human.
            let world = super::super::simulation::World::new(20);
            let mut responses = super::super::registration::tests::gitlab_responses();
            for index in [3, 6, 9] {
                let mut body: serde_json::Value = serde_json::from_str(&responses[index].1)?;
                body["application"]["uid"] = json!(client);
                responses[index].1 = body.to_string();
            }
            world.script(responses, None);
            super::super::effects::scope(world, || -> Result<()> {
                let codes = super::super::simulation::registration_codes(&target)?;
                let mut campaign = super::super::registration::Session::new(
                    target.clone(),
                    codes,
                    Arc::new(super::super::registration::tests::TokensSource(
                        AtomicUsize::new(0),
                    )),
                )?;
                for action in super::super::simulation::REGISTRATION_ACTIONS {
                    campaign.call(crate::automation::Request {
                        protocol: 1,
                        action: action.into(),
                        input: "{}".into(),
                    })?;
                }
                let receipt = campaign.finish()?;
                let keys = super::super::registration::publication::tests::Keys::default();
                let proof =
                    super::super::registration::publication::attest(&receipt, &selected, &keys, 5)?;
                let human = crate::iap::Verified {
                    email: "human@example.com".into(),
                    subject: "accounts.google.com:qualification-human".into(),
                };
                super::super::registration::publication::verify(
                    &proof,
                    "workspace",
                    &human,
                    &selected,
                    &keys,
                    5,
                )?;
                let substituted = crate::iap::Verified {
                    email: human.email.clone(),
                    subject: "accounts.google.com:42".into(),
                };
                assert!(
                    super::super::registration::publication::verify(
                        &proof,
                        "workspace",
                        &substituted,
                        &selected,
                        &keys,
                        5
                    )
                    .is_err()
                );
                let mut other = selected.instance.clone();
                other.installation = "other_company".into();
                other
                    .apps
                    .get_mut("workspace")
                    .unwrap()
                    .oauth_connections
                    .get_mut("calendar")
                    .unwrap()
                    .namespace
                    .installation = name("other_company");
                crate::oauth::clients::tests::select_desired_epoch(
                    &mut other,
                    "workspace",
                    "app@company-tools.iam.gserviceaccount.com",
                )?;
                let mut other = QualifiedConnections::prepare_instance(other, &artifacts)?;
                live::setup_selected(&mut other)?;
                let prior = keys.calls();
                assert!(
                    super::super::registration::publication::verify(
                        &proof,
                        "workspace",
                        &human,
                        &other,
                        &keys,
                        5
                    )
                    .is_err()
                );
                assert_eq!(
                    keys.calls(),
                    prior,
                    "company substitution must fail before key acquisition"
                );
                Ok(())
            })?;
            let mut wrong = selected.instance.clone();
            let value = &mut wrong.oauth_clients.as_mut().unwrap().registrations;
            value.insert(name("calendar_registration"), serde_json::from_value(json!({"client":{"kind":"google",
                "client_id":"12345-fixture.apps.googleusercontent.com","credential":"calendar_client"},
                "canary":{"qualification_subject":"accounts.google.com:qualification-human","provider_subject":"42","provider_tenant":"gitlab.com"}}))?);
            assert!(QualifiedConnections::qualify(&wrong, &artifacts, &catalog).is_err());
            let mut wrong = selected.instance.clone();
            wrong
                .apps
                .get_mut("workspace")
                .unwrap()
                .oauth_connections
                .get_mut("calendar")
                .unwrap()
                .profile =
                super::super::google::reviewed(&AccountBindingPolicy::ExplicitExternalAccount)?
                    .profile
                    .protocol
                    .identity()
                    .binding
                    .clone();
            assert!(QualifiedConnections::qualify(&wrong, &artifacts, &catalog).is_err());
            companies.push((selected, target));
        }
        assert_ne!(
            companies[0].1.description()["client_credential"],
            companies[1].1.description()["client_credential"]
        );
        assert_ne!(
            companies[0].1.description()["callback_url"],
            companies[1].1.description()["callback_url"]
        );
        // A company B registration cannot be substituted into company A even
        // though both use the same reviewed profile and provider account.
        let first_shell = live::shell_selection(&companies[0].0.instance)?;
        let other = companies[1].1.registration_evidence()?;
        assert!(
            companies[0]
                .0
                .registration_publication(
                    &other.registration,
                    &binding_namespace(&companies[1].0.entries.values().next().unwrap().binding)?,
                    &first_shell
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn changed_selection_refuses_registration_publication_before_key_acquisition() -> Result<()> {
        let (mut selected, receipt) = super::super::registration::publication::tests::fixture()?;
        let keys = super::super::registration::publication::tests::Keys::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let proof =
            super::super::registration::publication::attest(&receipt, &selected, &keys, now)?;
        selected
            .entries
            .values_mut()
            .next()
            .unwrap()
            .binding
            .namespace
            .binding_generation += 1;
        assert!(
            super::super::registration::publication::attest(&receipt, &selected, &keys, now)
                .is_err()
        );
        assert!(
            super::super::registration::publication::verify(
                &proof,
                "workspace",
                &super::super::registration::publication::tests::identity(),
                &selected,
                &keys,
                now
            )
            .is_err()
        );
        selected.entries.clear();
        assert!(
            super::super::registration::publication::verify(
                &proof,
                "workspace",
                &super::super::registration::publication::tests::identity(),
                &selected,
                &keys,
                now
            )
            .is_err()
        );
        assert_eq!(keys.calls(), 1);
        Ok(())
    }

    #[test]
    fn google_target_uses_admitted_requirement_instance_client_and_independent_shell() -> Result<()>
    {
        let mut fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        fixture.catalog = super::super::google::catalog()?;
        let profile =
            super::super::google::reviewed(&AccountBindingPolicy::ExplicitExternalAccount)?
                .profile
                .protocol
                .identity()
                .binding
                .clone();
        fixture
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap()
            .profile = profile;
        let control = fixture.instance.control.as_mut().unwrap();
        for (logical, secret) in [
            ("reauth_client", "google_reauth"),
            ("calendar_client", "google_calendar"),
        ] {
            control.secrets.insert(name(logical), serde_json::from_value(json!({"kind":"gcp_version","project_number":12345,"secret":secret,"version":3}))?);
        }
        let registration = fixture.instance.apps["workspace"].oauth_connections["calendar"]
            .registration
            .id
            .as_str();
        fixture.instance.oauth_clients = Some(serde_json::from_value(json!({
            "version":1,"reauthentication":{"client_id":"123-reauth.apps.googleusercontent.com","credential":"reauth_client"},
            "registrations":{registration:{"client":{"client_id":"123-calendar.apps.googleusercontent.com","credential":"calendar_client"},
                "canary_subject":"112233","canary_tenant":"example.com"}}
        }))?);
        crate::oauth::clients::tests::select_desired_epoch(
            &mut fixture.instance,
            "workspace",
            "app@company-tools.iam.gserviceaccount.com",
        )?;
        let selected = fixture.qualify()?;
        let targets = selected.registration_targets(&fixture.evidence.shell)?;
        assert_eq!(targets.len(), 1);
        let setup = targets[0].setup_description()?;
        assert_eq!(
            serde_json::to_value(
                selected
                    .entries
                    .values()
                    .next()
                    .unwrap()
                    .client_credential
                    .as_ref()
                    .unwrap()
            )?,
            setup["client_credential"]
        );
        assert_eq!(
            setup["client_id"],
            "123-calendar.apps.googleusercontent.com"
        );
        assert_eq!(setup["credential_version"]["version"], 3);
        assert!(
            setup["callback_url"]
                .as_str()
                .unwrap()
                .starts_with("https://security.example.com/_day2/oauth/callback/")
        );
        assert_ne!(
            setup["callback_url"],
            "https://security.example.com/_day2/reauth/callback"
        );
        let mut shell = fixture.evidence.shell.clone();
        shell.origin_url = "https://security.other-company.example/".into();
        assert!(selected.registration_targets(&shell).is_err());
        let old_credential = setup["client_credential"].clone();
        fixture.instance.control.as_mut().unwrap().secrets.insert(name("calendar_client"),
            serde_json::from_value(json!({"kind":"gcp_version","project_number":12345,"secret":"google_calendar","version":4}))?);
        crate::oauth::clients::tests::select_desired_epoch(
            &mut fixture.instance,
            "workspace",
            "app@company-tools.iam.gserviceaccount.com",
        )?;
        let changed = fixture
            .qualify()?
            .registration_targets(&fixture.evidence.shell)?;
        assert_ne!(
            changed[0].setup_description()?["client_credential"],
            old_credential
        );
        assert_ne!(
            changed[0].setup_description()?["registration_selection"],
            setup["registration_selection"]
        );
        assert_eq!(
            changed[0].setup_description()?["callback_url"],
            setup["callback_url"]
        );
        shell = fixture.evidence.shell.clone();
        shell.qualification = Digest::of(&"substituted qualification")?;
        assert!(selected.registration_targets(&shell).is_err());
        let shared =
            fixture.instance.control.as_ref().unwrap().secrets[&name("attestation")].clone();
        fixture
            .instance
            .control
            .as_mut()
            .unwrap()
            .secrets
            .insert(name("calendar_client"), shared);
        assert!(fixture.qualify().is_err());
        Ok(())
    }

    #[test]
    fn app_projection_keeps_its_client_and_control_refs_without_sibling_artifacts() -> Result<()> {
        let mut fixture = reviewed_google_fixture()?;
        let sibling = fixture.instance.apps["workspace"].clone();
        let mut sibling = sibling;
        sibling.oauth_connections.clear();
        sibling.artifact = "/unmounted/sibling/artifact".into();
        sibling.edge.as_mut().unwrap().origin = "https://sibling.example.com".into();
        sibling.edge.as_mut().unwrap().iap_audience =
            "/projects/12345/global/backendServices/3".into();
        fixture.instance.apps.insert("sibling".into(), sibling);
        let control = fixture.instance.control.as_mut().unwrap();
        control.sources.insert(
            name("sibling_source"),
            day2_capabilities::SourceProvider::LocalGit {
                repository: "/unmounted/sibling/source".into(),
            },
        );
        control.apps.insert(
            name("sibling"),
            serde_json::from_value(json!({"source":"sibling_source"}))?,
        );
        for secret in ["reauth_client", "calendar_client", "sibling_client"] {
            control.secrets.insert(
                name(secret),
                serde_json::from_value(json!({
                    "kind":"gcp_version","project_number":12345,"secret":secret,"version":1
                }))?,
            );
        }
        fixture.instance.oauth_clients = Some(serde_json::from_value(json!({
            "version":1,"reauthentication":{"client_id":"123-reauth.apps.googleusercontent.com","credential":"reauth_client"},
            "registrations":{
                "calendar_registration":{"client":{"client_id":"123-calendar.apps.googleusercontent.com","credential":"calendar_client"},"canary_subject":"112233","canary_tenant":"example.com"},
                "sibling_registration":{"client":{"client_id":"123-sibling.apps.googleusercontent.com","credential":"sibling_client"},"canary_subject":"112233","canary_tenant":"example.com"}
            }
        }))?);
        crate::oauth::clients::tests::select_desired_epoch(
            &mut fixture.instance,
            "workspace",
            "app@company-tools.iam.gserviceaccount.com",
        )?;
        let all = Instance::from_bytes(&serde_json::to_vec(&fixture.instance)?)?;
        let selected = QualifiedConnections::app_instance(all, "workspace")?;
        assert_eq!(selected.apps.len(), 1);
        assert_eq!(selected.control.as_ref().unwrap().apps.len(), 1);
        assert_eq!(selected.control.as_ref().unwrap().sources.len(), 1);
        assert_eq!(
            selected.oauth_clients.as_ref().unwrap().registrations.len(),
            1
        );
        assert!(
            selected
                .oauth_clients
                .as_ref()
                .unwrap()
                .registrations
                .contains_key(&name("calendar_registration"))
        );
        assert_eq!(
            selected.apps["workspace"].oauth_connections,
            fixture.instance.apps["workspace"].oauth_connections
        );
        assert_eq!(
            QualifiedConnections::qualify(&selected, &fixture.artifacts, &fixture.catalog)?
                .entries
                .len(),
            1
        );
        Ok(())
    }

    fn multi_app_security_projection_fixture() -> Result<Instance> {
        // Reuse complete desired credential/OAuth metadata. This supplies no
        // native key, artifact or epoch readiness proof.
        let mut instance = crate::oauth::clients::tests::security_instance("sibling", true)?;
        let control = instance.control.as_mut().unwrap();
        control.sources.insert(
            name("sibling_source"),
            day2_capabilities::SourceProvider::LocalGit {
                repository: "/unmounted/sibling/source".into(),
            },
        );
        control.apps.get_mut(&name("sibling")).unwrap().source = name("sibling_source");
        let mut epoch = control.security_epochs[&name("credential-epoch")].clone();
        epoch.scope.app = name("workspace");
        epoch.key_set = instance.security_key_set("workspace")?;
        let control = instance.control.as_mut().unwrap();
        control
            .security_epochs
            .retain(|_, selected| selected.scope.app.as_str() != "workspace");
        control
            .security_epochs
            .insert(name("workspace_epoch"), epoch);
        Instance::from_bytes(&serde_json::to_vec(&instance)?)
    }

    #[test]
    fn app_projection_reloads_complete_selected_credential_and_epoch_catalogs() -> Result<()> {
        let all = multi_app_security_projection_fixture()?;
        assert_eq!(all.apps.len(), 2);
        assert_eq!(all.control.as_ref().unwrap().sources.len(), 2);
        assert_eq!(all.control.as_ref().unwrap().security_epochs.len(), 2);
        for app in ["workspace", "sibling"] {
            let projected = QualifiedConnections::app_instance(all.clone(), app)?;
            let reloaded = Instance::from_bytes(&serde_json::to_vec(&projected)?)?;
            assert_eq!(reloaded.apps.len(), 1);
            assert_eq!(
                serde_json::to_value(&reloaded.apps[app])?,
                serde_json::to_value(&all.apps[app])?
            );
            let control = reloaded.control.as_ref().unwrap();
            let source = &all.control.as_ref().unwrap().apps[&name(app)].source;
            assert_eq!(control.sources.len(), 1);
            assert_eq!(
                control.sources[source],
                all.control.as_ref().unwrap().sources[source]
            );
            assert_eq!(control.security_epochs.len(), 1);
            let (alias, epoch) = control.security_epochs.iter().next().unwrap();
            assert_eq!(epoch.scope.app.as_str(), app);
            assert_eq!(epoch, &all.control.as_ref().unwrap().security_epochs[alias]);
            if app == "workspace" {
                assert!(reloaded.credential_runtime.is_none());
                assert!(
                    serde_json::to_value(&reloaded)?
                        .get("credential_runtime")
                        .is_none()
                );
                assert_eq!(reloaded.oauth_runtime.as_ref().unwrap().apps.len(), 1);
            } else {
                let selected = reloaded.credential_runtime.as_ref().unwrap();
                assert_eq!(selected.apps.len(), 1);
                assert_eq!(
                    selected.apps[&name(app)],
                    all.credential_runtime.as_ref().unwrap().apps[&name(app)]
                );
                assert!(reloaded.oauth_runtime.as_ref().unwrap().apps.is_empty());
                assert_eq!(
                    reloaded.oauth_runtime.as_ref().unwrap().shell,
                    all.oauth_runtime.as_ref().unwrap().shell
                );
            }
        }
        Ok(())
    }

    #[test]
    fn app_projection_refuses_foreign_or_stale_security_selectors() -> Result<()> {
        let all = multi_app_security_projection_fixture()?;
        let projected = QualifiedConnections::app_instance(all.clone(), "workspace")?;
        let mut changed = projected.clone();
        changed.credential_runtime = all.credential_runtime.clone();
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("credential_runtime_app_selection_incomplete"),
            "{error:#}"
        );
        let mut changed = projected.clone();
        changed.control.as_mut().unwrap().security_epochs.insert(
            name("credential-epoch"),
            all.control.as_ref().unwrap().security_epochs[&name("credential-epoch")].clone(),
        );
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("security_epoch_app_not_installed"),
            "{error:#}"
        );
        let mut changed = projected;
        changed
            .control
            .as_mut()
            .unwrap()
            .security_epochs
            .get_mut(&name("workspace_epoch"))
            .unwrap()
            .key_set = Digest::of(&"substituted selected key set")?;
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("security_epoch_complete_key_set_mismatch"),
            "{error:#}"
        );
        let mut changed = QualifiedConnections::app_instance(all, "sibling")?;
        changed
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .get_mut(&name("sibling"))
            .unwrap()
            .attestation
            .revision = Digest::of(&"stale credential attestation")?;
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("credential attestation revision mismatch"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn setup_prepares_initial_and_rotated_pins_while_serving_refuses_old_selection() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let instance = live::tests::selected()?.instance;
        let mut draft = instance.clone();
        let stale = Digest::of(&"stale desired pin")?;
        let binding = draft
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap();
        binding.requirement = stale.clone();
        binding.profile.revision = stale.clone();
        binding.custody.revision = stale.clone();
        binding.security_shell.0.revision = stale.clone();
        binding.shell_attestation.revision = stale.clone();
        binding.account_binding.revision = stale.clone();
        binding.registration.revision = stale;
        let catalog = super::super::google::catalog()?;
        assert!(QualifiedConnections::qualify(&draft, &fixture.artifacts, &catalog).is_err());
        let mut prepared =
            QualifiedConnections::prepare_instance(draft.clone(), &fixture.artifacts)?;
        live::setup_selected(&mut prepared)?;
        Instance::from_bytes(&serde_json::to_vec(&prepared.instance)?)?;
        assert_eq!(
            prepared.instance.apps["workspace"].oauth_connections,
            instance.apps["workspace"].oauth_connections
        );

        let SecretProvider::GcpVersion { version, .. } = draft
            .control
            .as_mut()
            .unwrap()
            .secrets
            .get_mut(&name("encryption"))
            .unwrap();
        *version = std::num::NonZeroU64::new(version.get() + 1).unwrap();
        let rotated = QualifiedConnections::prepare_instance(draft.clone(), &fixture.artifacts)?;
        assert_ne!(
            rotated.instance.apps["workspace"].oauth_connections["calendar"].custody,
            instance.apps["workspace"].oauth_connections["calendar"].custody
        );
        assert!(QualifiedConnections::qualify(&draft, &fixture.artifacts, &catalog).is_err());
        let mut expected_control = draft.control.clone();
        let expected_epochs = &mut expected_control.as_mut().unwrap().security_epochs;
        for (alias, epoch) in &rotated.instance.control.as_ref().unwrap().security_epochs {
            assert_eq!(
                epoch.key_set,
                rotated.instance.security_key_set("workspace")?
            );
            expected_epochs.get_mut(alias).unwrap().key_set = epoch.key_set.clone();
        }
        assert_eq!(rotated.instance.control, expected_control);
        Instance::from_bytes(&serde_json::to_vec(&rotated.instance)?)?;
        assert_eq!(
            serde_json::to_value(&rotated.instance.apps["workspace"].edge)?,
            serde_json::to_value(&draft.apps["workspace"].edge)?
        );
        assert_eq!(
            rotated.instance.apps["workspace"].oauth_connections["calendar"].product_return,
            draft.apps["workspace"].oauth_connections["calendar"].product_return
        );
        Ok(())
    }

    #[test]
    fn setup_requires_existing_unique_exact_scoped_epoch_and_preserves_raw_refusals() -> Result<()>
    {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let instance = live::tests::selected()?.instance;
        let valid = QualifiedConnections::prepare_instance(instance.clone(), &fixture.artifacts)?;
        Instance::from_bytes(&serde_json::to_vec(&valid.instance)?)?;
        for mutation in 0..3 {
            let mut invalid = instance.clone();
            let control = invalid.control.as_mut().unwrap();
            let (alias, epoch) = control.security_epochs.iter().next().unwrap();
            let alias = alias.clone();
            let mut epoch = epoch.clone();
            match mutation {
                0 => control.security_epochs.clear(),
                1 => {
                    control
                        .security_epochs
                        .insert(name("duplicate-epoch"), epoch);
                }
                2 => {
                    epoch.scope.environment = name("foreign");
                    control.security_epochs.insert(alias, epoch);
                }
                _ => unreachable!(),
            }
            assert!(
                QualifiedConnections::prepare_instance(invalid, &fixture.artifacts).is_err(),
                "normalized forbidden epoch mutation {mutation}"
            );
        }
        let mut raw = serde_json::to_value(&instance)?;
        raw["apps"]["workspace"]["auditors"] = json!(["not-an-owner@example.com"]);
        let error =
            QualifiedConnections::prepare_desired_bytes(&serde_json::to_vec(&raw)?).unwrap_err();
        assert!(error.to_string().contains("auditors is retired"));
        raw["apps"]["workspace"]
            .as_object_mut()
            .unwrap()
            .remove("auditors");
        raw["control"]["security_epochs"]
            .as_object_mut()
            .unwrap()
            .remove(
                instance
                    .control
                    .as_ref()
                    .unwrap()
                    .security_epochs
                    .keys()
                    .next()
                    .unwrap()
                    .as_str(),
            );
        assert!(QualifiedConnections::prepare_desired_bytes(&serde_json::to_vec(&raw)?).is_err());
        Ok(())
    }

    #[test]
    fn setup_repins_combined_family_after_final_complete_key_selection() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let mut desired = crate::oauth::clients::tests::security_instance("workspace", true)?;
        let mut foreign = desired.clone();
        foreign
            .apps
            .get_mut("workspace")
            .unwrap()
            .credential_families
            .get_mut("agents")
            .unwrap()
            .epoch_store
            .id = name("foreign-epoch");
        let error = QualifiedConnections::prepare_instance(foreign, &fixture.artifacts)
            .err()
            .context("foreign epoch alias was admitted")?;
        assert!(
            error
                .to_string()
                .contains("credential_epoch_store_alias_mismatch")
        );
        let control_before = desired.control.clone();
        let SecretProvider::GcpVersion { version, .. } = desired
            .control
            .as_mut()
            .unwrap()
            .secrets
            .get_mut(&name("encryption"))
            .unwrap();
        *version = std::num::NonZeroU64::new(version.get() + 1).unwrap();
        let prepared = QualifiedConnections::prepare_instance(desired.clone(), &fixture.artifacts)?;
        let instance = Instance::from_bytes(&serde_json::to_vec(&prepared.instance)?)?;
        let epoch = &instance.control.as_ref().unwrap().security_epochs[&name("credential-epoch")];
        assert_eq!(epoch.key_set, instance.security_key_set("workspace")?);
        assert_eq!(
            instance.apps["workspace"].credential_families["agents"].epoch_store,
            BindingRef {
                id: name("credential-epoch"),
                revision: Digest::of(epoch)?
            }
        );
        let original = &control_before.as_ref().unwrap().security_epochs[&name("credential-epoch")];
        assert_eq!(epoch.scope, original.scope);
        assert_eq!(epoch.provider, original.provider);
        assert_eq!(epoch.max_lease_seconds, original.max_lease_seconds);
        let mut expected = desired.control.clone();
        expected
            .as_mut()
            .unwrap()
            .security_epochs
            .get_mut(&name("credential-epoch"))
            .unwrap()
            .key_set = epoch.key_set.clone();
        assert_eq!(instance.control, expected);
        Ok(())
    }

    #[test]
    fn setup_refuses_wrong_profile_artifact_and_secret_roles() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let instance = live::tests::selected()?.instance;
        let mut wrong = instance.clone();
        wrong
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap()
            .profile
            .id = name("google_calendar_mapped_v1");
        assert!(QualifiedConnections::prepare_instance(wrong, &fixture.artifacts).is_err());
        assert!(
            QualifiedConnections::prepare_instance(instance.clone(), &BTreeMap::new()).is_err()
        );
        let mut wrong = instance;
        wrong
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap()
            .custody_encryption_secret = name("verifier");
        assert!(QualifiedConnections::prepare_instance(wrong, &fixture.artifacts).is_err());
        Ok(())
    }

    // Synthetic evidence exercises composition only. It is not a provider
    // sandbox, real registration or production readiness receipt.
    fn fixture(policy: AccountBindingPolicy) -> Result<Fixture> {
        let mut instance = Instance::from_bytes(&serde_json::to_vec(&json!({
            "installation":"company","environment":"production",
            "identity":{"scheme":"google_iap","hosted_domain":"example.com"},
            "security_shell":{"origin":"https://security.example.com",
                "iap_audience":"/projects/12345/global/backendServices/2"},
            "apps":{"workspace":{"artifact":"artifacts/selected","readers":[],"writers":[],
                "edge":{"origin":"https://app.example.com",
                    "iap_audience":"/projects/12345/global/backendServices/1"}}},
            "control":{"version":1,"state_directory":"/srv/control","operators":["operator@example.com"],
                "sources":{"workspace_source":{"kind":"local_git","repository":"/srv/workspace"}},
                "apps":{"workspace":{"source":"workspace_source"}},
                "secrets":{
                    "verifier":{"kind":"gcp_version","project_number":12345,"secret":"oauth_verifier","version":7},
                    "encryption":{"kind":"gcp_version","project_number":12345,"secret":"oauth_encryption","version":9},
                    "attestation":{"kind":"gcp_version","project_number":12345,"secret":"oauth_attestation","version":11}
                }}
        }))?)?;
        let control = instance.control.as_mut().unwrap();
        control.secrets.insert(name("reauth_client"), serde_json::from_value(json!({"kind":"gcp_version","project_number":12345,"secret":"google_reauth","version":3}))?);
        control.secrets.insert(name("calendar_client"), serde_json::from_value(json!({"kind":"gcp_version","project_number":12345,"secret":"google_client_secret","version":7}))?);
        instance.oauth_clients = Some(serde_json::from_value(json!({
            "version":1,"reauthentication":{"client_id":"123-reauth.apps.googleusercontent.com","credential":"reauth_client"},
            "registrations":{"calendar_registration":{"client":{"client_id":"12345-fixture.apps.googleusercontent.com","credential":"calendar_client"},
                "canary_subject":"google-canary-subject","canary_tenant":"example.com"}}
        }))?);
        let account = match &policy {
            AccountBindingPolicy::MappedHuman => json!({"kind":"iap_subject"}),
            AccountBindingPolicy::ExplicitExternalAccount => json!({"kind":"external_accounts",
                "allowed_tenants":["example.com"],"allowed_subjects":null}),
            AccountBindingPolicy::InstallationAccount => unreachable!(),
        };
        instance.oauth_runtime = Some(serde_json::from_value(json!({
            "version":1,"shell":{"project":"company-tools","backend_service":"shell-backend","url_map":"shell-map",
                "https_proxy":"shell-proxy","forwarding_rule":"shell-https","kubernetes_service":"tools/security-shell"},
            "apps":{"workspace":{"service_account":"app@company-tools.iam.gserviceaccount.com","accounts":{"calendar":account}}}
        }))?);
        instance.oauth_shell_transport = Some(day2_capabilities::oauth::ShellTransport {
            service_account: "shell@company-tools.iam.gserviceaccount.com".into(),
        });
        let requirement = ConnectionRequirement {
            logical_id: "work_calendar".into(),
            revision: 1,
            capability: "google_calendar_events".into(),
            actions: BTreeSet::from(["list_events".into()]),
            owner: ConnectionOwner::CurrentHuman,
            account_policy: policy.clone(),
            usage: "Read availability.".into(),
        };
        let access = super::super::google::reviewed(&policy)?;
        let reviewed = access.profile.clone();
        let catalog = ReviewedCatalog::new(vec![access])?;
        let profile = reviewed.protocol.identity().binding.clone();
        let (_, permission) = catalog.resolve(&requirement, &profile)?;
        let instance_ref = instance_identity(&instance)?;
        let shell_url = "https://security.example.com/".to_owned();
        let qualification = Digest::of(&"synthetic-shell-readiness")?;
        let security_shell = SecurityOriginRef(BindingRef {
            id: name("security_origin"),
            revision: Digest::of(&(
                "oauth-security-shell-evidence-v1",
                &instance_ref,
                &shell_url,
                &qualification,
            ))?,
        });
        let secrets = &instance.control.as_ref().unwrap().secrets;
        let custody = BindingRef {
            id: name("oauth_custody"),
            revision: custody_revision(
                &instance,
                &secrets[&name("verifier")],
                &secrets[&name("encryption")],
            )?,
        };
        let shell_attestation = BindingRef {
            id: name("shell_attestation"),
            revision: shell_key_revision(
                &instance,
                &security_shell,
                &secrets[&name("attestation")],
            )?,
        };
        let mut selection = OutboundConnectionBinding {
            namespace: Namespace {
                installation: name("company"),
                environment: name("production"),
                app: name("workspace"),
                binding_generation: 1,
            },
            requirement: requirement.nominal_identity()?,
            profile: profile.clone(),
            registration: pin("calendar_registration"),
            custody: custody.clone(),
            security_shell: security_shell.clone(),
            account_binding: match policy {
                AccountBindingPolicy::ExplicitExternalAccount => shell_attestation.clone(),
                _ => pin("human_subject_map"),
            },
            shell_attestation,
            product_return: ProductReturnRef(pin("calendar_return")),
            custody_verifier_secret: name("verifier"),
            custody_encryption_secret: name("encryption"),
            shell_attestation_secret: name("attestation"),
        };
        let slot = ConnectionSlotKey {
            installation: name("company"),
            environment: name("production"),
            app: name("workspace"),
            requirement: requirement.logical_id.clone(),
            owner: SlotOwner::Human {
                subject: "human_1".into(),
            },
        };
        let namespace = binding_namespace(&selection)?;
        let callback_ref = ProviderCallbackRef::derive(&security_shell, &profile, &namespace)?;
        let callback_url = profiles::derived_callback_url(&shell_url, &callback_ref)?;
        let confirmation = Digest::of(&"synthetic-provider-confirmation")?;
        let client = instance.oauth_clients.as_ref().unwrap().registrations
            [&name("calendar_registration")]
            .client();
        let client_credential =
            super::super::clients::selected_provider_credential(&instance, &client)?;
        let class = profiles::ClientRegistrationClass::ConfidentialPkceS256;
        selection.registration.revision = Digest::of(&(
            "oauth-provider-registration-evidence-v1",
            &instance_ref,
            &profile,
            &reviewed.issuer,
            &security_shell,
            &callback_ref,
            &callback_url,
            &confirmation,
            &client_credential,
            class,
        ))?;
        let intent = connect::ConnectIntent {
            attempt: "attempt_1".into(),
            slot: slot.id(&requirement)?.as_str().into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: "human_1".into(),
            profile: profile.id.as_str().into(),
            registration: Digest::of(&selection.registration)?.as_str().into(),
            callback: Digest::of(&callback_ref)?.as_str().into(),
            consent: permission.consent_digest(&requirement)?.as_str().into(),
            expires_at: 100,
        };
        let callback = connect::CallbackBinding::from_secret_state(
            b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
            CallbackBindingSpec {
                issuer: reviewed.issuer.clone(),
                issuer_url: reviewed.issuer_url.clone(),
                security_origin: security_shell.clone(),
                profile: profile.clone(),
                callback: callback_ref.clone(),
                binding_namespace: namespace.clone(),
                session: Digest::of(&"private-session")?,
                product_return: selection.product_return.clone(),
            },
        )?;
        let mut constraints = profiles::ExternalAccountConstraints {
            binding: pin("account_constraints"),
            issuer_url: reviewed.issuer_url.clone(),
            allowed_tenants: BTreeSet::from(["company".into()]),
            allowed_subjects: None,
        };
        constraints.binding.revision = Digest::of(&(
            "oauth-external-account-constraints-v1",
            &constraints.binding.id,
            &constraints.issuer_url,
            &constraints.allowed_tenants,
            &constraints.allowed_subjects,
        ))?;
        let evidence = profiles::OutboundInstanceEvidence {
            instance: instance_ref.clone(),
            binding_namespace: namespace,
            app_origin_url: "https://app.example.com/".into(),
            shell: profiles::SecurityShellEvidence {
                instance: instance_ref.clone(),
                origin: security_shell.clone(),
                origin_url: shell_url,
                qualification,
            },
            registration: profiles::ProviderRegistrationEvidence {
                instance: instance_ref.clone(),
                registration: selection.registration.clone(),
                profile,
                issuer: reviewed.issuer,
                security_origin: security_shell,
                callback: callback_ref,
                callback_url,
                provider_confirmation: confirmation,
                client_credential,
                class,
            },
            custody,
            account: match policy {
                AccountBindingPolicy::ExplicitExternalAccount => {
                    profiles::AccountBindingEvidence::ExplicitExternal {
                        instance: instance_ref,
                        approval: selection.account_binding.clone(),
                        constraints,
                        owner: "human_1".into(),
                    }
                }
                _ => profiles::AccountBindingEvidence::MappedHuman {
                    instance: instance_ref,
                    mapping: selection.account_binding.clone(),
                    owner: "human_1".into(),
                },
            },
            product_return: selection.product_return.clone(),
        };
        instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .insert("calendar".into(), selection);
        crate::oauth::clients::tests::select_desired_epoch(
            &mut instance,
            "workspace",
            "app@company-tools.iam.gserviceaccount.com",
        )?;
        let mut artifact: Artifact = serde_json::from_value(json!({
            "format":14,"namespace":"workspace","roc_version":"test","worker_digest":"test","schema_digest":"test",
            "sources":{},"admission":"local-spike-only","schema":{"models":{},"inputs":{},"foreign_keys":[]},
            "operations":[],"declarations":{"commands":{},"queries":{},"connections":{"calendar":"current_human"}}
        }))?;
        artifact.connection_declarations = vec![ConnectionDeclaration {
            registration: name("calendar"),
            requirement,
        }];
        let artifacts = BTreeMap::from([(
            "workspace".into(),
            LoadedArtifact::from_contract_for_tests(
                "synthetic-artifact".into(),
                "/fixture/artifact".into(),
                artifact,
            ),
        )]);
        Ok(Fixture {
            instance,
            artifacts,
            catalog,
            evidence,
            intent,
            callback,
        })
    }

    #[test]
    fn selection_derives_requirement_and_only_declared_action_scopes() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let qualified = fixture.qualify()?;
        let selected = &qualified.entries[&("workspace".into(), "calendar".into())];
        assert_eq!(
            selected.permission.action_scopes,
            BTreeMap::from([(
                "list_events".into(),
                BTreeSet::from([
                    "https://www.googleapis.com/auth/calendar.events.readonly".into(),
                    "https://www.googleapis.com/auth/userinfo.email".into(),
                    "openid".into(),
                ])
            )])
        );
        assert_eq!(qualified.key_bindings.len(), 3);
        let roundtrip = Instance::from_bytes(&serde_json::to_vec(&fixture.instance)?)?;
        assert_eq!(
            roundtrip.apps["workspace"].oauth_connections,
            fixture.instance.apps["workspace"].oauth_connections
        );
        let mut raw = serde_json::to_value(&fixture.instance)?;
        raw["apps"]["workspace"]["oauth_connections"]["calendar"]["provider_scopes"] =
            json!(["calendar.write"]);
        assert!(Instance::from_bytes(&serde_json::to_vec(&raw)?).is_err());
        Ok(())
    }

    #[test]
    fn startup_requires_a_reviewed_provider_host_and_dedicated_edge() -> Result<()> {
        let mut facts = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        // Complete runtime metadata selects native composition, not live readiness.
        assert!(super::super::host::require_providers(
            &facts.instance,
            "workspace",
            true,
            None
        )?);
        let runtime = facts
            .instance
            .oauth_runtime
            .take()
            .context("fixture runtime")?;
        assert!(
            super::super::host::require_providers(&facts.instance, "workspace", true, None)
                .is_err()
        );
        assert_eq!(
            super::super::host::require_providers(&facts.instance, "workspace", true, None)
                .unwrap_err()
                .to_string(),
            "OAuth provider host is not published"
        );
        facts.instance.oauth_runtime = Some(runtime);
        let providers = super::super::host::Providers {
            catalog: ReviewedCatalog::new(Vec::new())?,
            registrations: None,
            readiness: Arc::new(Readiness {
                runtime: Digest::of(facts.instance.oauth_runtime.as_ref().unwrap())?,
                current: RwLock::new(None),
                calls: AtomicUsize::new(0),
            }),
        };
        assert!(
            super::super::host::require_providers(
                &facts.instance,
                "workspace",
                false,
                Some(&providers)
            )
            .is_err()
        );
        facts.instance.oauth_shell_transport = None;
        assert!(
            super::super::host::require_providers(
                &facts.instance,
                "workspace",
                true,
                Some(&providers)
            )
            .is_err()
        );
        assert_eq!(
            super::super::host::require_providers(
                &facts.instance,
                "workspace",
                true,
                Some(&providers)
            )
            .unwrap_err()
            .to_string(),
            "OAuth shell transport missing"
        );
        facts.instance.oauth_shell_transport = Some(day2_capabilities::oauth::ShellTransport {
            service_account: "security@company.iam.gserviceaccount.com".into(),
        });
        let workload = super::super::workload::IapWorkload::from_gke_instance(&facts.instance)?;
        for (app, url) in [
            ("workspace", "https://app.example.com/"),
            ("other", "https://app.example.com/_day2/oauth/approval"),
            (
                "workspace",
                "https://other.example.com/_day2/oauth/approval",
            ),
        ] {
            assert!(
                super::super::shell_transport::PrivateBearerSource::bearer(
                    &workload,
                    app,
                    &url::Url::parse(url)?
                )
                .is_err()
            );
        }
        assert!(super::super::host::require_providers(
            &facts.instance,
            "workspace",
            true,
            Some(&providers)
        )?);
        assert!(
            QualifiedConnections::qualify(&facts.instance, &facts.artifacts, &providers.catalog)
                .is_err()
        );
        facts
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .clear();
        assert!(!super::super::host::require_providers(
            &facts.instance,
            "workspace",
            true,
            None
        )?);
        Ok(())
    }

    #[test]
    fn selection_rejects_cross_instance_stale_and_unbound_contracts() -> Result<()> {
        for mutation in 0..17 {
            let mut fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
            let binding = fixture
                .instance
                .apps
                .get_mut("workspace")
                .unwrap()
                .oauth_connections
                .get_mut("calendar")
                .unwrap();
            match mutation {
                0 => binding.namespace.installation = name("other"),
                1 => binding.namespace.environment = name("other"),
                2 => binding.namespace.app = name("other"),
                3 => binding.namespace.binding_generation = 0,
                4 => binding.requirement = Digest::of(&"stale-requirement")?,
                5 => binding.profile.revision = Digest::of(&"stale-profile")?,
                6 => binding.custody_verifier_secret = name("missing"),
                7 => binding.custody_encryption_secret = name("verifier"),
                8 => binding.account_binding = pin("different_approval"),
                9 => fixture.instance.apps.get_mut("workspace").unwrap().edge = None,
                10 => fixture.artifacts.clear(),
                11 => {
                    let selection = fixture
                        .instance
                        .apps
                        .get_mut("workspace")
                        .unwrap()
                        .oauth_connections
                        .remove("calendar")
                        .unwrap();
                    fixture
                        .instance
                        .apps
                        .get_mut("workspace")
                        .unwrap()
                        .oauth_connections
                        .insert("undeclared".into(), selection);
                }
                12 => fixture.instance.control = None,
                13 => fixture.instance.security_shell = None,
                14..=16 => {
                    let mut contract = fixture.artifacts["workspace"].contract().clone();
                    match mutation {
                        14 => contract.namespace = "other_app".into(),
                        15 => contract.format = 13,
                        _ => contract.connection_declarations.clear(),
                    }
                    fixture.artifacts.insert(
                        "workspace".into(),
                        LoadedArtifact::from_contract_for_tests(
                            "synthetic-artifact".into(),
                            "/fixture/artifact".into(),
                            contract,
                        ),
                    );
                }
                _ => unreachable!(),
            }
            assert!(fixture.qualify().is_err(), "mutation {mutation}");
        }
        let mut fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let SecretProvider::GcpVersion { version, .. } = fixture
            .instance
            .control
            .as_mut()
            .unwrap()
            .secrets
            .get_mut(&name("encryption"))
            .unwrap();
        *version = 10.try_into()?;
        assert!(fixture.qualify().is_err());
        let mut raw = serde_json::to_value(&fixture.instance)?;
        raw["control"]["secrets"]["encryption"]["version"] = json!(0);
        assert!(Instance::from_bytes(&serde_json::to_vec(&raw)?).is_err());
        raw["control"]["secrets"]["encryption"]["version"] = json!("latest");
        assert!(Instance::from_bytes(&serde_json::to_vec(&raw)?).is_err());
        Ok(())
    }

    #[test]
    fn catalog_rejects_unreviewed_scope_interpretation_and_policy() -> Result<()> {
        let external = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let entry = external.catalog.entries.into_values().next().unwrap();
        let mut scopes = entry.action_scopes.clone();
        scopes
            .get_mut("list_events")
            .unwrap()
            .insert("calendar.write".into());
        assert!(
            ReviewedCatalog::new(vec![ReviewedAccess {
                profile: entry.profile,
                capability: entry.capability,
                action_scopes: scopes
            }])
            .is_err()
        );
        let mut mapped = fixture(AccountBindingPolicy::MappedHuman)?;
        mapped.catalog = fixture(AccountBindingPolicy::ExplicitExternalAccount)?.catalog;
        assert!(mapped.qualify().is_err());
        Ok(())
    }

    struct Readiness {
        runtime: Digest,
        current: RwLock<Option<profiles::OutboundInstanceEvidence>>,
        calls: AtomicUsize,
    }
    impl OutboundReadiness for Readiness {
        fn selected_runtime(&self) -> Result<Option<Digest>> {
            Ok(Some(self.runtime.clone()))
        }

        fn current(
            &self,
            _: &OutboundConnectionBinding,
            _: &ConnectionSlotKey,
            _: i64,
        ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.current.read().unwrap().clone())
        }
    }

    #[derive(Default)]
    struct Keys {
        calls: AtomicUsize,
    }

    #[test]
    fn changed_runtime_catalog_refuses_old_facts_before_cloud_or_key_acquisition() -> Result<()> {
        struct PinnedFacts {
            revision: Digest,
            calls: AtomicUsize,
        }
        impl OutboundReadiness for PinnedFacts {
            fn selected_runtime(&self) -> Result<Option<Digest>> {
                Ok(Some(self.revision.clone()))
            }
            fn current(
                &self,
                _: &OutboundConnectionBinding,
                _: &ConnectionSlotKey,
                _: i64,
            ) -> Result<Option<profiles::OutboundInstanceEvidence>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("retired source must not run")
            }
        }
        let facts = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let mut selected = facts.qualify()?;
        let mut config: day2_capabilities::oauth::RuntimeCatalog = serde_json::from_value(
            json!({"version":1,"shell":{"project":"company-tools","backend_service":"shell-backend","url_map":"shell-map","https_proxy":"shell-proxy","forwarding_rule":"shell-https","kubernetes_service":"tools/security-shell"},
            "apps":{"workspace":{"service_account":"app@company-tools.iam.gserviceaccount.com","accounts":{"calendar":{"kind":"external_accounts","allowed_tenants":["example.com"],"allowed_subjects":null}}}}}),
        )?;
        config.validate()?;
        let source = Arc::new(PinnedFacts {
            revision: Digest::of(&config)?,
            calls: AtomicUsize::new(0),
        });
        config
            .apps
            .get_mut(&name("workspace"))
            .unwrap()
            .service_account = "replacement@company-tools.iam.gserviceaccount.com".into();
        selected.instance.oauth_runtime = Some(config);
        let keys = Arc::new(Keys::default());
        let authority =
            ArtifactApprovalAuthority::with_keys(selected, source.clone(), keys.clone());
        assert!(
            authority
                .current("workspace", &facts.intent, &facts.callback, 5)
                .is_err()
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
        Ok(())
    }
    impl ApprovalKeyProvider for Keys {
        fn load(
            &self,
            reference: &ApprovalKeyRef,
            purpose: ApprovalKeyPurpose,
        ) -> Result<ApprovalKeyMaterial> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (version, byte) = match purpose {
                ApprovalKeyPurpose::CustodyVerifier => ("7", 7),
                ApprovalKeyPurpose::CustodyEncryption => ("9", 9),
                ApprovalKeyPurpose::ShellAttestation => ("11", 11),
            };
            ensure!(
                reference.version == version,
                "unexpected selected key version"
            );
            Ok(ApprovalKeyMaterial {
                binding: reference.binding.clone(),
                version: version.into(),
                purpose,
                bytes: [byte; 32],
            })
        }
    }

    struct NoTokens;
    impl AccessTokenSource for NoTokens {
        fn access_token(&self) -> Result<String> {
            panic!("removed selection must not acquire a token")
        }
    }

    #[test]
    fn authority_rechecks_readiness_and_exact_keys_then_revokes_removed_selection() -> Result<()> {
        let mut fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let readiness = Arc::new(Readiness {
            runtime: Digest::of(fixture.instance.oauth_runtime.as_ref().unwrap())?,
            current: RwLock::new(Some(fixture.evidence.clone())),
            calls: AtomicUsize::new(0),
        });
        let keys = Arc::new(Keys::default());
        let authority = ArtifactApprovalAuthority::with_keys(
            fixture.qualify()?,
            readiness.clone(),
            keys.clone(),
        );
        for _ in 0..2 {
            assert!(
                authority
                    .current("workspace", &fixture.intent, &fixture.callback, 5)?
                    .is_some()
            );
        }
        assert_eq!(readiness.calls.load(Ordering::SeqCst), 4);
        assert_eq!(keys.calls.load(Ordering::SeqCst), 6);
        *readiness.current.write().unwrap() = None;
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)?
                .is_none()
        );
        assert_eq!(keys.calls.load(Ordering::SeqCst), 6);
        *readiness.current.write().unwrap() = Some(fixture.evidence.clone());
        fixture
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .clear();
        fixture.instance.oauth_runtime = None;
        fixture.instance.oauth_clients = None;
        fixture
            .instance
            .control
            .as_mut()
            .unwrap()
            .security_epochs
            .clear();
        authority.replace_with_gcp(fixture.qualify()?, Arc::new(NoTokens))?;
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)?
                .is_none()
        );
        assert_eq!(readiness.calls.load(Ordering::SeqCst), 5);
        assert_eq!(keys.calls.load(Ordering::SeqCst), 6);
        Ok(())
    }

    #[test]
    fn readiness_retired_during_key_acquisition_cannot_reach_settlement() -> Result<()> {
        struct RetiringKeys {
            keys: Keys,
            readiness: Arc<Readiness>,
        }
        impl ApprovalKeyProvider for RetiringKeys {
            fn load(
                &self,
                reference: &ApprovalKeyRef,
                purpose: ApprovalKeyPurpose,
            ) -> Result<ApprovalKeyMaterial> {
                let material = self.keys.load(reference, purpose)?;
                if purpose == ApprovalKeyPurpose::ShellAttestation {
                    *self.readiness.current.write().unwrap() = None;
                }
                Ok(material)
            }
        }
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let readiness = Arc::new(Readiness {
            runtime: Digest::of(fixture.instance.oauth_runtime.as_ref().unwrap())?,
            current: RwLock::new(Some(fixture.evidence.clone())),
            calls: AtomicUsize::new(0),
        });
        let keys = Arc::new(RetiringKeys {
            keys: Keys::default(),
            readiness: readiness.clone(),
        });
        let authority = ArtifactApprovalAuthority::with_keys(
            fixture.qualify()?,
            readiness.clone(),
            keys.clone(),
        );
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)?
                .is_none()
        );
        *readiness.current.write().unwrap() = Some(fixture.evidence);
        let mut settlements = 0;
        assert!(!authority.with_current(
            "workspace",
            &fixture.intent,
            &fixture.callback,
            5,
            &mut |_| {
                settlements += 1;
                Ok(true)
            }
        )?);
        assert_eq!(settlements, 0);
        assert_eq!(keys.keys.calls.load(Ordering::SeqCst), 6);
        assert_eq!(readiness.calls.load(Ordering::SeqCst), 4);
        Ok(())
    }

    #[test]
    fn authority_rejects_other_owner_stale_generation_and_substituted_readiness_before_keys()
    -> Result<()> {
        let mut fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let readiness = Arc::new(Readiness {
            runtime: Digest::of(fixture.instance.oauth_runtime.as_ref().unwrap())?,
            current: RwLock::new(Some(fixture.evidence.clone())),
            calls: AtomicUsize::new(0),
        });
        let keys = Arc::new(Keys::default());
        let authority = ArtifactApprovalAuthority::with_keys(
            fixture.qualify()?,
            readiness.clone(),
            keys.clone(),
        );
        let mut other_owner = fixture.intent.clone();
        other_owner.owner = "human_2".into();
        assert!(
            authority
                .current("workspace", &other_owner, &fixture.callback, 5)?
                .is_none()
        );
        assert!(
            authority
                .current("other", &fixture.intent, &fixture.callback, 5)?
                .is_none()
        );
        for mutation in 0..10 {
            let mut evidence = fixture.evidence.clone();
            match mutation {
                0 => evidence.instance = pin("other_instance"),
                1 => evidence.binding_namespace = "other_namespace".into(),
                2 => evidence.registration.registration = pin("other_registration"),
                3 => evidence.custody = pin("other_custody"),
                4 => evidence.product_return = ProductReturnRef(pin("other_return")),
                5 => evidence.app_origin_url = "https://other.example/".into(),
                6 => {
                    evidence.registration.provider_confirmation = Digest::of(&"other_confirmation")?
                }
                7 => {
                    evidence.account = profiles::AccountBindingEvidence::MappedHuman {
                        instance: evidence.instance.clone(),
                        mapping: pin("human_subject_map"),
                        owner: "human_1".into(),
                    }
                }
                8 => evidence.shell.origin_url = "https://other.example/".into(),
                9 => evidence.registration.callback_url = "https://app.example.com/callback".into(),
                _ => unreachable!(),
            }
            *readiness.current.write().unwrap() = Some(evidence);
            assert!(
                authority
                    .current("workspace", &fixture.intent, &fixture.callback, 5)
                    .is_err(),
                "mutation {mutation}"
            );
        }
        fixture
            .instance
            .apps
            .get_mut("workspace")
            .unwrap()
            .oauth_connections
            .get_mut("calendar")
            .unwrap()
            .namespace
            .binding_generation += 1;
        crate::oauth::clients::tests::select_desired_epoch(
            &mut fixture.instance,
            "workspace",
            "app@company-tools.iam.gserviceaccount.com",
        )?;
        let next = fixture.qualify()?;
        authority.replace_with_gcp(next, Arc::new(NoTokens))?;
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)
                .is_err()
        );
        assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn changed_client_credential_refuses_old_readiness_before_reading_keys() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let readiness = Arc::new(Readiness {
            runtime: Digest::of(fixture.instance.oauth_runtime.as_ref().unwrap())?,
            current: RwLock::new(Some(fixture.evidence.clone())),
            calls: AtomicUsize::new(0),
        });
        let keys = Arc::new(Keys::default());
        let mut selected = fixture.qualify()?;
        selected
            .entries
            .values_mut()
            .next()
            .unwrap()
            .client_credential = Some(fixture.evidence.registration.client_credential.clone());
        let authority = ArtifactApprovalAuthority::with_keys(selected, readiness, keys.clone());
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)?
                .is_some()
        );
        let key_reads = keys.calls.load(Ordering::SeqCst);
        let mut selected = fixture.qualify()?;
        selected
            .entries
            .values_mut()
            .next()
            .unwrap()
            .client_credential = Some(pin("rotated_client_credential"));
        authority.replace_with_gcp(selected, Arc::new(NoTokens))?;
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)
                .is_err()
        );
        assert_eq!(keys.calls.load(Ordering::SeqCst), key_reads);
        Ok(())
    }

    #[test]
    fn mapped_human_selection_does_not_enter_external_account_approval() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::MappedHuman)?;
        let readiness = Arc::new(Readiness {
            runtime: Digest::of(fixture.instance.oauth_runtime.as_ref().unwrap())?,
            current: RwLock::new(Some(fixture.evidence.clone())),
            calls: AtomicUsize::new(0),
        });
        let keys = Arc::new(Keys::default());
        let authority = ArtifactApprovalAuthority::with_keys(
            fixture.qualify()?,
            readiness.clone(),
            keys.clone(),
        );
        assert!(
            authority
                .current("workspace", &fixture.intent, &fixture.callback, 5)?
                .is_none()
        );
        assert_eq!(readiness.calls.load(Ordering::SeqCst), 0);
        assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn file_selection_loads_the_instance_selected_artifact_path() -> Result<()> {
        let fixture = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        std::fs::write(&path, serde_json::to_vec(&fixture.instance)?)?;
        // No caller-supplied artifact map can substitute for the missing path.
        assert!(QualifiedConnections::from_instance_file(&path, &fixture.catalog).is_err());
        Ok(())
    }

    #[test]
    fn shell_signer_loads_only_attestation_and_rejects_changed_selected_presentation_before_keys()
    -> Result<()> {
        use super::super::security_shell::FreshAuthenticator;
        use super::super::shell_transport::{ApprovalSigner, ApprovalView};
        let clock = super::super::simulation::World::new(905);
        super::super::effects::scope(clock.clone(), || {
            struct OnlyShell(AtomicUsize);
            impl ApprovalKeyProvider for OnlyShell {
                fn load(
                    &self,
                    reference: &ApprovalKeyRef,
                    purpose: ApprovalKeyPurpose,
                ) -> Result<ApprovalKeyMaterial> {
                    assert_eq!(
                        purpose,
                        ApprovalKeyPurpose::ShellAttestation,
                        "shell must never acquire custody keys"
                    );
                    self.0.fetch_add(1, Ordering::SeqCst);
                    Keys::default().load(reference, purpose)
                }
            }
            let mut facts = fixture(AccountBindingPolicy::ExplicitExternalAccount)?;
            facts.intent.owner = "ada@example.com".into();
            let slot = ConnectionSlotKey {
                installation: name("company"),
                environment: name("production"),
                app: name("workspace"),
                requirement: "work_calendar".into(),
                owner: SlotOwner::Human {
                    subject: facts.intent.owner.clone(),
                },
            };
            let selected = facts.qualify()?;
            let choice = &selected.entries[&("workspace".into(), "calendar".into())];
            let filtered = ArtifactShellSigner::keys(&selected, Arc::new(NoTokens))?.unwrap();
            for (reference, purpose) in [
                (
                    &choice.custody_verifier,
                    ApprovalKeyPurpose::CustodyVerifier,
                ),
                (
                    &choice.custody_encryption,
                    ApprovalKeyPurpose::CustodyEncryption,
                ),
            ] {
                assert!(
                    filtered.load(reference, purpose).is_err(),
                    "custody is not registered in the shell key provider"
                );
            }
            let observed = super::super::account::ProviderAccount {
                issuer: choice.reviewed.issuer_url.clone(),
                subject: "provider-subject".into(),
                tenant: "external-tenant".into(),
                display_email: "external@example.net".into(),
            };
            let permission = choice.permission.consent_digest(&choice.requirement)?;
            let scopes = choice
                .permission
                .action_scopes
                .values()
                .flatten()
                .cloned()
                .collect();
            let mut view = ApprovalView {
                app: "workspace".into(),
                subject: "accounts.google.com:12345".into(),
                requirement: choice.binding.requirement.clone(),
                permission: permission.clone(),
                logical_id: choice.requirement.logical_id.clone(),
                usage: choice.requirement.usage.clone(),
                scopes,
                observed: observed.clone(),
                binding_namespace: binding_namespace(&choice.binding)?,
                terms: Digest::of(&"app-owned current readiness terms")?,
                shell_origin: "https://security.example.com/".into(),
                app_origin: "https://app.example.com/".into(),
                claim: super::super::external::ApprovalClaim {
                    attempt: super::super::shell_transport::scoped_attempt(
                        "company",
                        "production",
                        "workspace",
                    )?,
                    slot: slot.id(&choice.requirement)?.as_str().into(),
                    generation: 1,
                    human: facts.intent.owner.clone(),
                    account: super::super::account::provider_account_digest(&observed)?
                        .as_str()
                        .into(),
                    scope_evidence: String::new(),
                    challenge: Digest::of(&"one pending challenge")?,
                    security_origin: choice.binding.security_shell.clone(),
                    approval: choice.binding.account_binding.clone(),
                    quarantined_at: 4,
                },
            };
            view.claim.scope_evidence =
                Digest::of(&("oauth-accepted-scopes-v1", &permission, &view.scopes))?
                    .as_str()
                    .into();
            let keys = Arc::new(OnlyShell(AtomicUsize::new(0)));
            let signer = ArtifactShellSigner {
                state: RwLock::new(AuthorityState {
                    selected,
                    keys: Some(keys.clone()),
                }),
            };
            let session = Digest::of(&"fresh shell session")?;
            let identity = crate::iap::Verified {
                email: view.human().into(),
                subject: view.subject.clone(),
            };
            let intent = super::super::fresh_auth::FreshIntent::approval(&view, &identity)?;
            let (authenticator, headers, callback) =
                super::super::shell_oidc::fixture_login(&identity, intent, 5, 5, 5)?;
            let identity = authenticator.identify(&headers, 5)?;
            let google = authenticator.complete(&callback, &identity, 5)?;
            let fresh = super::super::security_shell::ShellSession::approval_signed_fixture(
                &view,
                &identity,
                google,
                session.clone(),
                5,
            )?;
            // A refused original lifetime is terminal. Keep this negative control's
            // proof separate from the retirement and post-key-load controls below.
            let intent = super::super::fresh_auth::FreshIntent::approval(&view, &identity)?;
            let (authenticator, headers, callback) =
                super::super::shell_oidc::fixture_login(&identity, intent, 5, 5, 5)?;
            let identity = authenticator.identify(&headers, 5)?;
            let google = authenticator.complete(&callback, &identity, 5)?;
            let future_entry = super::super::security_shell::ShellSession::approval_signed_fixture(
                &view,
                &identity,
                google,
                session.clone(),
                5,
            )?;
            clock.advance(1);
            let proof = signer.attest(&view, &fresh, 6)?;
            assert_eq!(proof.preview, Some(view.digest()?));
            assert_eq!(keys.0.load(Ordering::SeqCst), 1);
            for mutation in 0..7 {
                let mut wrong = view.clone();
                match mutation {
                    0 => wrong.usage = "Changed consent wording".into(),
                    1 => wrong.claim.slot = Digest::of(&"another human slot")?.as_str().into(),
                    2 => wrong.binding_namespace = "retired_namespace".into(),
                    3 => wrong.app_origin = "https://other.example/".into(),
                    4 => wrong.claim.approval = pin("other_approval"),
                    5 => {
                        wrong.scopes.insert("calendar.write".into());
                        wrong.claim.scope_evidence = Digest::of(&(
                            "oauth-accepted-scopes-v1",
                            &wrong.permission,
                            &wrong.scopes,
                        ))?
                        .as_str()
                        .into();
                    }
                    6 => {
                        wrong.claim.attempt = super::super::shell_transport::scoped_attempt(
                            "company",
                            "staging",
                            "workspace",
                        )?
                    }
                    _ => unreachable!(),
                }
                assert!(
                    signer.attest(&wrong, &fresh, 6).is_err(),
                    "mutation {mutation}"
                );
            }
            let stale = super::super::security_shell::ShellSession::approval_fixture(
                &view,
                &identity,
                4,
                session.clone(),
            )?;
            assert!(signer.attest(&view, &stale, 6).is_err());
            assert!(signer.attest(&view, &future_entry, 306).is_err());
            assert_eq!(keys.0.load(Ordering::SeqCst), 1);
            let expiry_selected = facts.qualify()?;
            facts
                .instance
                .apps
                .get_mut("workspace")
                .unwrap()
                .oauth_connections
                .clear();
            facts.instance.oauth_runtime = None;
            facts.instance.oauth_clients = None;
            facts
                .instance
                .control
                .as_mut()
                .unwrap()
                .security_epochs
                .clear();
            signer.replace_with_gcp(facts.qualify()?, Arc::new(NoTokens))?;
            assert!(signer.attest(&view, &fresh, 6).is_err());
            assert_eq!(keys.0.load(Ordering::SeqCst), 1);
            // The preview digest includes the human's immutable IAP subject too.
            let original_view = view.clone();
            let digest = view.digest()?;
            view.subject = "accounts.google.com:replacement".into();
            assert_ne!(view.digest()?, digest);
            struct ExpiringKey {
                clock: Arc<super::super::simulation::World>,
                calls: AtomicUsize,
            }
            impl ApprovalKeyProvider for ExpiringKey {
                fn load(
                    &self,
                    reference: &ApprovalKeyRef,
                    purpose: ApprovalKeyPurpose,
                ) -> Result<ApprovalKeyMaterial> {
                    assert_eq!(purpose, ApprovalKeyPurpose::ShellAttestation);
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    self.clock.advance(300);
                    Keys::default().load(reference, purpose)
                }
            }
            let delayed = Arc::new(ExpiringKey {
                clock: clock.clone(),
                calls: AtomicUsize::new(0),
            });
            let expiring = ArtifactShellSigner {
                state: RwLock::new(AuthorityState {
                    selected: expiry_selected,
                    keys: Some(delayed.clone()),
                }),
            };
            assert!(expiring.attest(&original_view, &fresh, 6).is_err());
            assert_eq!(
                delayed.calls.load(Ordering::SeqCst),
                1,
                "control must reach actual key load before refusing expired original proof"
            );
            Ok(())
        })
    }
}
