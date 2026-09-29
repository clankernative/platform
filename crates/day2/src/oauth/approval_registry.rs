//! Durable approval lookup. The browser supplies only an attempt identifier;
//! current contracts and keys come from a host-owned admission authority.

use super::{connect, external, profiles, security_shell};
use crate::managed_credentials::crypto::KeyLease;
use anyhow::{Result, ensure};
use day2_capabilities::oauth::{ConnectionRequirement, ProviderPermissionContract};
use rusqlite::{Connection, OpenFlags};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Arc,
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
