//! Explicit disposable app-verification evidence. This adapter is never installed
//! by Runtime::load or a web server and does not claim provider/browser readiness.
use super::{
    crypto::KeyLease,
    issuance::{self, Authority, Confirmation, ReadyKeys},
};
use crate::{
    authority_state,
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{CredentialFamilyBinding, ManagementPolicy, ManagementPredicate},
};
use rusqlite::params;
use std::sync::Arc;

struct DisposableAuthority {
    verifier: [u8; 32],
    encryption: [u8; 32],
}

impl Authority for DisposableAuthority {
    fn prepare(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<ReadyKeys> {
        ensure!(
            binding.namespace.installation.as_str() == "localdev"
                && binding.namespace.environment.as_str() == "disposable"
                && matches!(management.issue, ManagementPredicate::Creator)
                && !actor.is_empty()
                && !subject.is_empty(),
            "disposable credential verification binding required"
        );
        Ok(ReadyKeys {
            keys: KeyLease::new(
                &self.verifier,
                &self.encryption,
                "disposable-verifier-1".into(),
                "disposable-encryption-1".into(),
            )?,
            binding: Digest::of(binding)?,
            security_epoch: 1,
            valid_until: now + 31_536_001,
            max_active_lineages: 1000,
        })
    }

    fn validate(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        ready: &ReadyKeys,
        now: i64,
    ) -> Result<()> {
        let current = self.prepare(binding, management, actor, subject, now)?;
        ensure!(
            ready.binding == current.binding
                && ready.security_epoch == current.security_epoch
                && now < ready.valid_until,
            "disposable credential readiness changed"
        );
        Ok(())
    }
}

pub(crate) fn install(runtime: Runtime) -> Result<Runtime> {
    if !runtime
        .artifact()
        .contract()
        .app_contract
        .as_ref()
        .is_some_and(|app| {
            app.operations
                .values()
                .any(|op| op.credential_access.mutation().is_some())
        })
    {
        return Ok(runtime);
    }
    ensure!(
        runtime.integrations().is_simulated(),
        "credential verification requires disposable providers"
    );
    let mut verifier = [0u8; 32];
    let mut encryption = [0u8; 32];
    super::effects::fill_secret(&mut verifier)?;
    super::effects::fill_secret(&mut encryption)?;
    Ok(
        runtime.with_credential_authority(Arc::new(DisposableAuthority {
            verifier,
            encryption,
        })),
    )
}

pub(crate) fn confirm(
    runtime: &Runtime,
    operation: &str,
    actor: &str,
    invocation: &str,
    input: &serde_json::Value,
    now: i64,
) -> Result<()> {
    ensure!(
        runtime.integrations().is_simulated(),
        "credential verification requires disposable providers"
    );
    let access = issuance::access(runtime, operation)?;
    let (_, family) = access
        .mutation()
        .context("credential verification family missing")?;
    let mut db = open(runtime.db())?;
    let tx = crate::write_queue::immediate(&mut db)?;
    let active = authority_state::authorize_in(&tx, runtime, operation, actor)?;
    let selected = active
        .document
        .credentials
        .get(family)
        .context("credential verification family inactive")?;
    let subject = format!(
        "verification/{}",
        Digest::new(actor.as_bytes())
            .as_str()
            .trim_start_matches("sha256:")
    );
    let ready = runtime.credential_authority()?.prepare(
        &selected.binding,
        &selected.management,
        actor,
        &subject,
        now,
    )?;
    let confirmation = Confirmation {
        invocation: invocation.into(),
        operation: operation.into(),
        actor: actor.into(),
        subject,
        session: format!("verification-{invocation}"),
        input: input.clone(),
        family: family.into(),
        intent: super::lifecycle::intent(access, input)?,
        artifact: runtime.artifact().id().into(),
        authority: active.stamp,
        binding: ready.binding,
        security_epoch: ready.security_epoch,
        authenticated_at: now,
        approved_at: now,
        expires_at: now + 300,
    };
    tx.execute(
        "INSERT INTO day2_credential_confirmations VALUES (?1, ?2)",
        params![invocation, serde_json::to_string(&confirmation)?],
    )?;
    tx.commit()?;
    Ok(())
}
