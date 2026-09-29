//! Durable approval lookup. The browser supplies only an attempt identifier;
//! current contracts and keys come from a host-owned admission authority.

use super::{connect, external, profiles, security_shell};
use crate::{managed_credentials::crypto::KeyLease, store::open};
use anyhow::Result;
use day2_capabilities::oauth::{ConnectionRequirement, ProviderPermissionContract};
use std::{path::PathBuf, sync::Arc};

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
        intent: &connect::ConnectIntent,
        binding: &connect::CallbackBinding,
        now: i64,
    ) -> Result<Option<ApprovalTerms>>;
}

/// The registry reads one current SQLite attempt before consulting admission.
/// It never accepts an intent or callback binding from the caller.
pub(crate) struct StoredApprovalRegistry {
    db: PathBuf,
    authority: Arc<dyn ApprovalAuthority>,
}

impl StoredApprovalRegistry {
    pub(crate) fn new(db: PathBuf, authority: Arc<dyn ApprovalAuthority>) -> Self {
        Self { db, authority }
    }
}

impl security_shell::ApprovalRegistry for StoredApprovalRegistry {
    fn resolve(&self, attempt: &str, now: i64) -> Result<Option<security_shell::ApprovalContext>> {
        let db = open(&self.db)?;
        let Some((intent, binding)) = connect::pending_approval(&db, attempt, now)? else {
            return Ok(None);
        };
        let Some(terms) = self.authority.current(&intent, &binding, now)? else {
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
