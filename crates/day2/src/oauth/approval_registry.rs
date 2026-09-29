//! Durable approval lookup. The browser supplies only an attempt identifier;
//! current contracts and keys come from a host-owned admission authority.

use super::{connect, external, profiles, security_shell};
use crate::{artifact::Instance, managed_credentials::crypto::KeyLease};
use anyhow::{Result, ensure};
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
    fn current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
        now: i64,
    ) -> Result<Option<ApprovalTerms>>;
}

/// Key material is fetched on every approval request. The provider must use a
/// pinned secret version and return its actual identity with the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl ApprovalAuthority for SelectedApprovalAuthority {
    fn current(
        &self,
        app: &str,
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
        _now: i64,
    ) -> Result<Option<ApprovalTerms>> {
        // Keep the read lease through key acquisition. Once replace returns,
        // no request can finish using the retired admission snapshot.
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("OAuth admission lock poisoned"))?;
        let Some(entry) = entries.get(&(app.to_owned(), intent.slot.clone())) else {
            return Ok(None);
        };
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
        Ok(Some(ApprovalTerms {
            requirement: entry.requirement.clone(),
            permission: entry.permission.clone(),
            reviewed: entry.reviewed.clone(),
            instance: entry.instance.clone(),
            custody_key,
            shell_key,
        }))
    }
}

/// The registry scans the host-selected OAuth app databases before consulting
/// admission. Two apps may never answer the same opaque attempt identifier.
pub(crate) struct StoredApprovalRegistry {
    app_databases: BTreeMap<String, PathBuf>,
    authority: Arc<dyn ApprovalAuthority>,
}

impl StoredApprovalRegistry {
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
