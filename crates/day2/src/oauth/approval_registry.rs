//! Durable approval lookup. The browser supplies only an attempt identifier;
//! current contracts and keys come from a host-owned admission authority.

use super::{connect, external, profiles, security_shell, shell_transport};
use crate::{artifact::Instance, managed_credentials::crypto::KeyLease};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    BindingRef,
    oauth::{ConnectionRequirement, ProviderPermissionContract},
};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};

/// Current admitted facts for a stored attempt. The authority must resolve
/// these from the selected installation and reviewed host catalog, and obtain
/// exact-version key leases from the credential provider on every lookup.
/// App input and the browser request cannot construct this value.
pub(crate) struct ApprovalTerms {
    pub requirement: ConnectionRequirement,
    pub permission: ProviderPermissionContract,
    pub reviewed: profiles::ReviewedBrowserCodeProfile,
    pub instance: profiles::OutboundInstanceEvidence,
    pub custody_key: KeyLease,
    pub shell_key: external::ShellApprovalKeyLease,
}

pub(crate) trait ApprovalAuthority: Send + Sync {
    fn observe_identity(
        &self,
        _app: &str,
        _identity: &crate::iap::Verified,
        _now: i64,
    ) -> Result<()> {
        Ok(())
    }

    fn current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
        now: i64,
    ) -> Result<Option<ApprovalTerms>>;

    /// Hold current selection through the local settlement transaction. A
    /// resolver that cannot provide this lease cannot authorize a commit.
    fn with_current(
        &self,
        _app: &str,
        _intent: &connect::ConnectIntent,
        _binding: &connect::CallbackBinding,
        _now: i64,
        _commit: &mut dyn FnMut(ApprovalTerms) -> Result<bool>,
    ) -> Result<bool> {
        anyhow::bail!("OAuth authority cannot lease settlement")
    }
}

/// Key material is fetched on every approval request. The provider must use a
/// pinned secret version and return its actual identity with the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ApprovalKeyPurpose {
    CustodyVerifier,
    CustodyEncryption,
    ShellAttestation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApprovalKeyRef {
    pub binding: BindingRef,
    pub version: String,
}

pub(crate) struct ApprovalKeyMaterial {
    pub binding: BindingRef,
    pub version: String,
    pub purpose: ApprovalKeyPurpose,
    pub bytes: [u8; 32],
}

pub(crate) trait ApprovalKeyProvider: Send + Sync {
    fn load(
        &self,
        reference: &ApprovalKeyRef,
        purpose: ApprovalKeyPurpose,
    ) -> Result<ApprovalKeyMaterial>;
}

#[derive(Clone)]
pub(crate) struct AdmittedApproval {
    pub requirement: ConnectionRequirement,
    pub permission: ProviderPermissionContract,
    pub reviewed: profiles::ReviewedBrowserCodeProfile,
    pub instance: profiles::OutboundInstanceEvidence,
    pub custody_verifier: ApprovalKeyRef,
    pub custody_encryption: ApprovalKeyRef,
    pub shell_attestation: ApprovalKeyRef,
}

/// A replaceable, host-selected admission snapshot. Callers replace the whole
/// set after qualification; an absent entry removes approval immediately.
pub(crate) struct SelectedApprovalAuthority {
    app_origins: BTreeMap<String, String>,
    shell_origin: String,
    entries: RwLock<BTreeMap<(String, String), AdmittedApproval>>,
    keys: Arc<dyn ApprovalKeyProvider>,
}

impl SelectedApprovalAuthority {
    pub(crate) fn new(
        instance: &Instance,
        entries: BTreeMap<(String, String), AdmittedApproval>,
        keys: Arc<dyn ApprovalKeyProvider>,
    ) -> Result<Self> {
        let (_, shell) = instance.security_edge()?;
        let app_origins = instance
            .apps
            .iter()
            .filter_map(|(app, binding)| {
                binding
                    .edge
                    .as_ref()
                    .map(|edge| (app.clone(), format!("{}/", edge.origin)))
            })
            .collect();
        let authority = Self {
            app_origins,
            shell_origin: format!("{}/", shell.origin),
            entries: RwLock::new(BTreeMap::new()),
            keys,
        };
        authority.replace(entries)?;
        Ok(authority)
    }

    pub(crate) fn replace(
        &self,
        entries: BTreeMap<(String, String), AdmittedApproval>,
    ) -> Result<()> {
        ensure!(entries.len() <= 128, "OAuth approval admission budget");
        for ((app, slot), entry) in &entries {
            ensure!(
                self.app_origins.get(app) == Some(&entry.instance.app_origin_url)
                    && entry.instance.shell.origin_url == self.shell_origin
                    && slot.len() <= 256
                    && !slot.is_empty(),
                "OAuth approval admission does not match selected installation"
            );
            ensure!(
                entry.instance.custody == entry.custody_encryption.binding
                    && entry.instance.custody == entry.custody_verifier.binding
                    && matches!(
                        &entry.instance.account,
                        profiles::AccountBindingEvidence::ExplicitExternal { approval, .. }
                            if approval == &entry.shell_attestation.binding
                    ),
                "OAuth approval key binding mismatch"
            );
            for key in [
                &entry.custody_verifier,
                &entry.custody_encryption,
                &entry.shell_attestation,
            ] {
                ensure!(
                    !key.version.is_empty()
                        && key.version.len() <= 64
                        && key
                            .version
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                    "invalid OAuth approval key version"
                );
            }
        }
        *self
            .entries
            .write()
            .map_err(|_| anyhow::anyhow!("OAuth admission lock poisoned"))? = entries;
        Ok(())
    }

    fn key(&self, reference: &ApprovalKeyRef, purpose: ApprovalKeyPurpose) -> Result<[u8; 32]> {
        let loaded = self.keys.load(reference, purpose)?;
        ensure!(
            loaded.binding == reference.binding
                && loaded.version == reference.version
                && loaded.purpose == purpose,
            "OAuth approval key identity mismatch"
        );
        Ok(loaded.bytes)
    }
}

impl SelectedApprovalAuthority {
    fn terms(
        &self,
        entry: &AdmittedApproval,
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
    ) -> Result<ApprovalTerms> {
        profiles::qualify_outbound_connect(
            intent,
            binding,
            &entry.requirement,
            &entry.permission,
            &entry.reviewed,
            &entry.instance,
        )?;
        let verifier = self.key(&entry.custody_verifier, ApprovalKeyPurpose::CustodyVerifier)?;
        let encryption = self.key(
            &entry.custody_encryption,
            ApprovalKeyPurpose::CustodyEncryption,
        )?;
        let shell = self.key(
            &entry.shell_attestation,
            ApprovalKeyPurpose::ShellAttestation,
        )?;
        let custody_key = KeyLease::new(
            &verifier,
            &encryption,
            entry.custody_verifier.version.clone(),
            entry.custody_encryption.version.clone(),
        )?;
        let profiles::AccountBindingEvidence::ExplicitExternal { approval, .. } =
            &entry.instance.account
        else {
            anyhow::bail!("OAuth approval requires explicit external account");
        };
        let shell_key = external::ShellApprovalKeyLease::new(
            &shell,
            entry.shell_attestation.version.clone(),
            entry.instance.shell.origin.clone(),
            approval.clone(),
        )?;
        Ok(ApprovalTerms {
            requirement: entry.requirement.clone(),
            permission: entry.permission.clone(),
            reviewed: entry.reviewed.clone(),
            instance: entry.instance.clone(),
            custody_key,
            shell_key,
        })
    }
}

impl ApprovalAuthority for SelectedApprovalAuthority {
    fn current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
        _: i64,
    ) -> Result<Option<ApprovalTerms>> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth admission lock poisoned"))?;
        let Some(entry) = entries.get(&(app.to_owned(), intent.slot.clone())) else {
            return Ok(None);
        };
        Ok(Some(self.terms(entry, intent, binding)?))
    }

    fn with_current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
        _: i64,
        commit: &mut dyn FnMut(ApprovalTerms) -> Result<bool>,
    ) -> Result<bool> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth admission lock poisoned"))?;
        let Some(entry) = entries.get(&(app.to_owned(), intent.slot.clone())) else {
            return Ok(false);
        };
        // Replacement waits until the SQLite commit (or rollback) finishes.
        commit(self.terms(entry, intent, binding)?)
    }
}

/// The registry scans the host-selected OAuth app databases before consulting
/// admission. Two apps may never answer the same opaque attempt identifier.
pub(crate) struct StoredApprovalRegistry {
    app_databases: BTreeMap<String, PathBuf>,
    authority: Arc<dyn ApprovalAuthority>,
}

impl StoredApprovalRegistry {
    fn owner(&self, attempt: &str) -> Result<Option<String>> {
        let mut owner = None;
        for (app, path) in &self.app_databases {
            let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            db.busy_timeout(Duration::from_secs(2))?;
            db.pragma_update(None, "trusted_schema", false)?;
            if connect::state(&db, attempt)?.is_some() {
                ensure!(owner.is_none(), "ambiguous OAuth approval attempt");
                owner = Some(app.clone());
            }
        }
        Ok(owner)
    }

    fn view(
        &self,
        attempt: &str,
        identity: &crate::iap::Verified,
        now: i64,
    ) -> Result<shell_transport::HostLookup> {
        use security_shell::ApprovalRegistry;
        let Some(app) = self.owner(attempt)? else {
            return Ok(shell_transport::HostLookup {
                owned: false,
                view: None,
            });
        };
        let db = crate::store::open(&self.app_databases[&app])?;
        let Some((intent, _)) = connect::pending_approval(&db, attempt, now)? else {
            return Ok(shell_transport::HostLookup {
                owned: true,
                view: None,
            });
        };
        ensure!(
            intent.owner == identity.email,
            "OAuth approval human mismatch"
        );
        crate::iap::bind_subject(&db, identity, now)?;
        drop(db);
        self.authority.observe_identity(&app, identity, now)?;
        let Some(context) = self.resolve(attempt, now)? else {
            return Ok(shell_transport::HostLookup {
                owned: true,
                view: None,
            });
        };
        ensure!(
            context.intent.owner == identity.email,
            "OAuth approval human mismatch"
        );
        let db = crate::store::open(&context.db)?;
        crate::iap::bind_subject(&db, identity, now)?;
        let pending = external::load_pending_external(
            &db,
            context.qualification(),
            &context.custody_key,
            now,
        )?;
        let view = pending
            .map(|pending| {
                shell_transport::ApprovalView::from_pending(&app, &context, &pending, identity)
            })
            .transpose()?;
        Ok(shell_transport::HostLookup { owned: true, view })
    }

    fn confirm(
        &self,
        attempt: &str,
        expected: &day2_capabilities::Digest,
        identity: &crate::iap::Verified,
        evidence: external::FreshExternalApproval,
        now: i64,
        clock: &dyn Fn() -> Result<i64>,
    ) -> Result<bool> {
        ensure!(
            evidence.preview.as_ref() == Some(expected),
            "OAuth confirmation does not bind its preview"
        );
        let Some(app) = self.owner(attempt)? else {
            return Ok(false);
        };
        let path = &self.app_databases[&app];
        let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.pragma_update(None, "trusted_schema", false)?;
        let Some((intent, binding)) = connect::pending_approval(&db, attempt, now)? else {
            return Ok(false);
        };
        ensure!(
            intent.owner == identity.email && evidence.human == identity.email,
            "OAuth confirmation human mismatch"
        );
        drop(db);
        let db = crate::store::open(path)?;
        crate::iap::bind_subject(&db, identity, now)?;
        drop(db);
        self.authority.observe_identity(&app, identity, now)?;
        let mut evidence = Some(evidence);
        self.authority
            .with_current(&app, &intent, &binding, now, &mut |terms| {
                // Re-read the clock after key acquisition and the pending state
                // after obtaining the selection lease. No network call occurs in
                // the SQLite settlement transaction.
                let at = clock()?;
                ensure!(at >= now, "OAuth host clock moved backwards");
                let context = security_shell::ApprovalContext {
                    db: path.clone(),
                    intent: intent.clone(),
                    binding: binding.clone(),
                    requirement: terms.requirement,
                    permission: terms.permission,
                    reviewed: terms.reviewed,
                    instance: terms.instance,
                    custody_key: terms.custody_key,
                    shell_key: terms.shell_key,
                };
                let mut db = crate::store::open(path)?;
                crate::iap::bind_subject(&db, identity, at)?;
                let Some(pending) = external::load_pending_external(
                    &db,
                    context.qualification(),
                    &context.custody_key,
                    at,
                )?
                else {
                    return Ok(false);
                };
                let view = shell_transport::ApprovalView::from_pending(
                    &app, &context, &pending, identity,
                )?;
                if view.digest()? != *expected {
                    return Ok(false);
                }
                external::approve_external(
                    &mut db,
                    context.qualification(),
                    &context.custody_key,
                    &context.shell_key,
                    evidence
                        .take()
                        .context("OAuth confirmation already consumed")?,
                    at,
                )
            })
    }

    pub(crate) fn new(
        app_databases: BTreeMap<String, PathBuf>,
        authority: Arc<dyn ApprovalAuthority>,
    ) -> Result<Self> {
        ensure!(
            !app_databases.is_empty() && app_databases.len() <= 128,
            "invalid OAuth approval app database set"
        );
        let mut paths = BTreeSet::new();
        let mut selected = BTreeMap::new();
        for (app, path) in app_databases {
            crate::schema::identifier(&app)?;
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "invalid OAuth app database path"
            );
            let path = path.canonicalize()?;
            ensure!(paths.insert(path.clone()), "duplicate OAuth app database");
            selected.insert(app, path);
        }
        Ok(Self {
            app_databases: selected,
            authority,
        })
    }
}

/// A private receiver holds exactly one app's database and credential authority.
/// The shell cannot ask this backend to select another app or filesystem path.
pub(crate) struct StoredAppApprovals {
    app: String,
    registry: StoredApprovalRegistry,
    clock: Arc<dyn Fn() -> Result<i64> + Send + Sync>,
}

impl StoredAppApprovals {
    pub(crate) fn new(
        app: String,
        path: PathBuf,
        authority: Arc<dyn ApprovalAuthority>,
    ) -> Result<Self> {
        Ok(Self {
            registry: StoredApprovalRegistry::new(
                BTreeMap::from([(app.clone(), path)]),
                authority,
            )?,
            app,
            clock: Arc::new(crate::oauth::effects::wall_time),
        })
    }

    #[cfg(test)]
    pub(super) fn set_clock(&mut self, clock: Arc<dyn Fn() -> Result<i64> + Send + Sync>) {
        self.clock = clock;
    }
}

impl shell_transport::AppApprovals for StoredAppApprovals {
    fn app(&self) -> &str {
        &self.app
    }

    fn lookup(
        &self,
        attempt: &str,
        identity: &crate::iap::Verified,
        now: i64,
    ) -> Result<shell_transport::HostLookup> {
        self.registry.view(attempt, identity, now)
    }

    fn confirm(
        &self,
        attempt: &str,
        expected: &day2_capabilities::Digest,
        identity: &crate::iap::Verified,
        evidence: external::FreshExternalApproval,
        now: i64,
    ) -> Result<bool> {
        self.registry.confirm(
            attempt,
            expected,
            identity,
            evidence,
            now,
            self.clock.as_ref(),
        )
    }
}

/// Local adapters exist only for the existing browser fixture campaigns. The
/// production shell constructor uses authenticated RemoteApprovals and has no
/// database registry or custody keys.
#[cfg(test)]
pub(super) struct LocalShellApprovals(pub Arc<StoredApprovalRegistry>);

#[cfg(test)]
impl shell_transport::ShellApprovals for LocalShellApprovals {
    fn pending(
        &self,
        attempt: &str,
        identity: &crate::iap::Verified,
        _: &axum::http::HeaderMap,
        now: i64,
    ) -> Result<Option<shell_transport::ApprovalView>> {
        Ok(self.0.view(attempt, identity, now)?.view)
    }

    fn confirm(
        &self,
        view: &shell_transport::ApprovalView,
        identity: &crate::iap::Verified,
        _: &axum::http::HeaderMap,
        evidence: external::FreshExternalApproval,
        now: i64,
    ) -> Result<bool> {
        self.0.confirm(
            view.attempt(),
            &view.digest()?,
            identity,
            evidence,
            now,
            &|| Ok(now),
        )
    }
}

#[cfg(test)]
impl shell_transport::ApprovalSigner for LocalShellApprovals {
    fn attest(
        &self,
        view: &shell_transport::ApprovalView,
        session: day2_capabilities::Digest,
        authenticated_at: i64,
        now: i64,
    ) -> Result<external::FreshExternalApproval> {
        use security_shell::ApprovalRegistry;
        let context = self
            .0
            .resolve(view.attempt(), now)?
            .context("OAuth test approval disappeared")?;
        context
            .shell_key
            .attest_view(&view.claim, view.digest()?, session, authenticated_at, now)
    }
}

impl security_shell::ApprovalRegistry for StoredApprovalRegistry {
    fn resolve(&self, attempt: &str, now: i64) -> Result<Option<security_shell::ApprovalContext>> {
        let mut found = None;
        let mut owner_seen = false;
        for (app, path) in &self.app_databases {
            let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            db.busy_timeout(Duration::from_secs(2))?;
            db.pragma_update(None, "trusted_schema", false)?;
            if connect::state(&db, attempt)?.is_some() {
                ensure!(!owner_seen, "ambiguous OAuth approval attempt");
                owner_seen = true;
                if let Some((intent, binding)) = connect::pending_approval(&db, attempt, now)? {
                    found = Some((app, path, intent, binding));
                }
            }
        }
        let Some((app, path, intent, binding)) = found else {
            return Ok(None);
        };
        let Some(terms) = self.authority.current(app, &intent, &binding, now)? else {
            return Ok(None);
        };
        profiles::qualify_outbound_connect(
            &intent,
            &binding,
            &terms.requirement,
            &terms.permission,
            &terms.reviewed,
            &terms.instance,
        )?;
        Ok(Some(security_shell::ApprovalContext {
            db: path.clone(),
            intent,
            binding,
            requirement: terms.requirement,
            permission: terms.permission,
            reviewed: terms.reviewed,
            instance: terms.instance,
            custody_key: terms.custody_key,
            shell_key: terms.shell_key,
        }))
    }
}
