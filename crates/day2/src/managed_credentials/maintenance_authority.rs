//! Exact verifier-maintenance selection from an explicitly trusted local source.
//! This is not a maintenance original, native owner, provider or operator route.

use super::{Target, VerifierAuthority, VerifierSelection};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{CredentialFamilyBinding, ManifestFamily},
};
use std::sync::Mutex;

/// DATA selected by independent maintenance policy, never by token possession,
/// creator visibility, a browser input or the target's stored key version.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub binding: CredentialFamilyBinding,
    pub family: ManifestFamily,
    pub version: String,
    pub target: Digest,
    pub selection: VerifierSelection,
}

/// A missing grant is an explicit current denial. `checked_at` belongs to this
/// observation; the grant's original observation and expiry must not be renewed.
pub(crate) struct Observation {
    pub checked_at: i64,
    pub grant: Option<Grant>,
}

/// Explicit trusted port: independently check current maintenance permission,
/// policy revision, exact target, epoch and key selection on EVERY call. This
/// must be local and nonblocking, including when invoked inside caller SQL.
/// A copied record or a successful key fetch is not an implementation of this
/// contract. A future native caller still needs its genuine original/SQL owner.
pub(crate) trait Source {
    fn observe(&self, target: &Target, now: i64) -> Result<Observation>;
}

/// One attempt's current selection and process-local refusal memory only.
/// Construction grants nothing, loads no keys and observes no clock. The source
/// must enforce the original deadline; constructing another adapter cannot
/// create or renew a maintenance original.
pub(crate) struct CurrentAuthority<'source> {
    source: &'source dyn Source,
    state: Mutex<State>,
}

struct State {
    first: Option<Grant>,
    last_checked_at: Option<i64>,
    refused: bool,
}

impl<'source> CurrentAuthority<'source> {
    pub(crate) fn new(source: &'source dyn Source) -> Self {
        Self {
            source,
            state: Mutex::new(State {
                first: None,
                last_checked_at: None,
                refused: false,
            }),
        }
    }
}

impl VerifierAuthority for CurrentAuthority<'_> {
    fn authorize(&self, target: &Target, now: i64) -> Result<VerifierSelection> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("credential maintenance source lock poisoned"))?;
        ensure!(!state.refused, "credential maintenance attempt refused");
        // Errors and panics cannot leave a reusable positive observation. The
        // lock is poisoned on panic; every Result error leaves refusal latched.
        state.refused = true;
        ensure!(
            now >= 0 && state.last_checked_at.is_none_or(|previous| now >= previous),
            "credential maintenance clock rewound"
        );
        let observed = self.source.observe(target, now)?;
        ensure!(
            observed.checked_at == now,
            "credential maintenance observation is not current"
        );
        let grant = observed.grant.context("credential maintenance denied")?;
        ensure!(
            grant.binding == target.binding
                && grant.family == target.family
                && grant.version == target.identity.version
                && grant.target == target.fingerprint,
            "credential maintenance target changed"
        );
        let selection = &grant.selection;
        super::validate_verifier_selection(selection, target, now)?;
        ensure!(
            state.first.as_ref().is_none_or(|first| first == &grant),
            "credential maintenance original selection changed"
        );
        let result = selection.clone();
        if state.first.is_none() {
            state.first = Some(grant);
        }
        state.last_checked_at = Some(now);
        state.refused = false;
        Ok(result)
    }
}
