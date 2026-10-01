//! The ordinary command transaction's private credential issuance adapter.
//! Browser confirmation is separate from app inputs and public result codecs.
use super::{crypto::KeyLease, store};
use crate::{
    authority_state, protocol,
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{CredentialFamilyBinding, GrantMode, ManagedProfile, ManagementPolicy},
    oauth::GrantCeiling,
};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A selected host adapter must resolve purpose-bound exact-version keys,
/// current epoch/clock readiness and issuer permission. No default adapter
/// exists. prepare may call a provider; validate must use current local evidence
/// and must not perform external I/O inside the product transaction.
pub(crate) trait Authority: Send + Sync {
    fn prepare(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<ReadyKeys>;
    fn validate(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        ready: &ReadyKeys,
        now: i64,
    ) -> Result<()>;
}

pub(crate) struct ReadyKeys {
    pub keys: KeyLease,
    pub binding: Digest,
    pub security_epoch: u64,
    pub valid_until: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Confirmation {
    pub invocation: String,
    pub operation: String,
    pub actor: String,
    pub subject: String,
    pub session: String,
    pub input: Value,
    pub family: String,
    pub label: String,
    pub artifact: String,
    pub authority: authority_state::AuthorityStamp,
    pub binding: Digest,
    pub security_epoch: u64,
    pub authenticated_at: i64,
    pub approved_at: i64,
    pub expires_at: i64,
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_credential_confirmations (
        invocation TEXT PRIMARY KEY, confirmation TEXT NOT NULL
    ) STRICT;",
    )?;
    Ok(())
}

pub(super) fn load(db: &Connection, invocation: &str) -> Result<Option<Confirmation>> {
    db.query_row(
        "SELECT confirmation FROM day2_credential_confirmations WHERE invocation=?1",
        [invocation],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|raw| crate::json::decode(raw.as_bytes()))
    .transpose()
}

pub(crate) fn access<'a>(
    runtime: &'a Runtime,
    operation: &str,
) -> Result<&'a crate::app_contract::CredentialAccess> {
    static ORDINARY: crate::app_contract::CredentialAccess =
        crate::app_contract::CredentialAccess {
            enabled: false,
            local_reads: Vec::new(),
            metadata_reads: Vec::new(),
            issues: Vec::new(),
            issue_label: String::new(),
            interactive: false,
        };
    Ok(runtime
        .artifact()
        .contract()
        .app_contract
        .as_ref()
        .and_then(|app| app.operations.get(operation))
        .map(|op| &op.credential_access)
        .unwrap_or(&ORDINARY))
}

/// Every acceptance channel uses this guard. A cookie, actor string, delegated
/// invocation or ordinary handler context cannot substitute a confirmation.
pub(crate) fn require_confirmation(
    db: &Connection,
    runtime: &Runtime,
    operation: &str,
    actor: &str,
    invocation: &str,
    input: &Value,
    now: i64,
) -> Result<()> {
    let access = access(runtime, operation)?;
    if !access.interactive {
        return Ok(());
    }
    let proof = load(db, invocation)?.ok_or(crate::error::Failure::Forbidden)?;
    let active = authority_state::authorize_in(db, runtime, operation, actor)?;
    ensure!(
        proof.operation == operation
            && proof.actor == actor
            && proof.input == *input
            && proof.artifact == runtime.artifact().id(),
        "credential confirmation does not match invocation"
    );
    let completed = db
        .query_row(
            "SELECT status!='pending' FROM day2_invocations WHERE id=?1",
            [invocation],
            |row| row.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(false);
    if !completed {
        ensure!(
            proof.authority == active.stamp
                && proof.approved_at <= now
                && now < proof.expires_at
                && proof.authenticated_at <= proof.approved_at
                && proof.approved_at - proof.authenticated_at <= 300,
            "credential confirmation expired or authority changed"
        );
    }
    Ok(())
}

impl Runtime {
    pub(crate) fn with_credential_authority(
        mut self,
        authority: std::sync::Arc<dyn Authority>,
    ) -> Self {
        self.credentials = Some(authority);
        self
    }

    /// Provider calls finish before preparation or the SQLite writer lock.
    pub(crate) fn prepare_credential_keys(&self, invocation: &str) -> Result<Option<ReadyKeys>> {
        let db = open(self.db())?;
        let pending: bool = db.query_row(
            "SELECT status='pending' FROM day2_invocations WHERE id=?1",
            [invocation],
            |row| row.get(0),
        )?;
        if !pending {
            return Ok(None);
        }
        let Some(proof) = load(&db, invocation)? else {
            return Ok(None);
        };
        let active = authority_state::current(&db)?;
        let selected = active
            .document
            .credentials
            .get(&proof.family)
            .context("credential family inactive")?;
        let now = self.host().now_ms()?.div_euclid(1000);
        ensure!(
            now >= proof.approved_at && now < proof.expires_at,
            "credential confirmation expired"
        );
        let ready = self.credential_authority()?.prepare(
            &selected.binding,
            &selected.management,
            &proof.actor,
            &proof.subject,
            now,
        )?;
        ensure!(
            ready.binding == proof.binding
                && ready.security_epoch == proof.security_epoch
                && now < ready.valid_until,
            "credential readiness changed"
        );
        Ok(Some(ready))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueInput {
    registration: String,
    invocation: String,
    label: String,
}

pub(crate) fn stage(
    tx: &Transaction<'_>,
    runtime: &Runtime,
    request: &protocol::Request,
    instruction: &protocol::Instruction,
    ready: &ReadyKeys,
) -> Result<String> {
    ensure!(
        instruction.decode()? == protocol::Step::CredentialIssue,
        "credential issuance instruction required"
    );
    let input: IssueInput = crate::json::decode(instruction.data.as_bytes())?;
    let origin = crate::store::invocation_context(tx, &request.context.invocation_id)?;
    ensure!(
        origin == request.context
            && origin.caller.is_empty()
            && origin.authenticated.is_empty()
            && origin.authentication == "request"
            && input.invocation == origin.invocation_id,
        "credential issuance requires a direct confirmed invocation"
    );
    let value: Value = crate::json::decode(request.input.as_bytes())?;
    let now = runtime.host().now_ms()?.div_euclid(1000);
    require_confirmation(
        tx,
        runtime,
        &request.operation,
        &origin.actor,
        &origin.invocation_id,
        &value,
        now,
    )?;
    let proof = load(tx, &origin.invocation_id)?.context("credential confirmation missing")?;
    let access = access(runtime, &request.operation)?;
    ensure!(
        access.issues == [proof.family.clone()]
            && value.get(&access.issue_label).and_then(Value::as_str) == Some(input.label.as_str())
            && input.label == proof.label,
        "credential intent changed after confirmation"
    );
    ensure!(
        !request
            .observations
            .iter()
            .any(|entry| entry.instruction.kind == "credential_issue"),
        "one credential issuance per management command"
    );
    let family = runtime
        .artifact()
        .contract()
        .credential_manifest
        .iter()
        .find(|family| {
            family.registration.as_str() == input.registration && family.id.as_str() == proof.family
        })
        .context("credential issue family mismatch")?;
    ensure!(
        matches!(family.grant, GrantMode::Fixed)
            && matches!(
                family.profile,
                ManagedProfile::Client | ManagedProfile::Personal
            ),
        "unsupported credential issuance profile"
    );
    let active = authority_state::require_invocation_in(
        tx,
        runtime,
        &origin.invocation_id,
        &request.operation,
        &origin.actor,
    )?;
    active.document.validate(runtime.artifact())?;
    let selected = active
        .document
        .credentials
        .get(&proof.family)
        .context("credential family inactive")?;
    let binding = &selected.binding;
    ensure!(
        ready.binding == Digest::of(binding)?
            && ready.binding == proof.binding
            && ready.security_epoch == proof.security_epoch
            && now < ready.valid_until,
        "credential readiness changed"
    );
    runtime.credential_authority()?.validate(
        binding,
        &selected.management,
        &proof.actor,
        &proof.subject,
        ready,
        now,
    )?;
    let principal = match family.profile {
        ManagedProfile::Personal => proof.subject.clone(),
        _ => format!(
            "client/{}",
            Digest::of(&(
                "credential-client-v1",
                &binding.namespace,
                &proof.invocation
            ))?
            .as_str()
            .trim_start_matches("sha256:")
        ),
    };
    let ceiling = GrantCeiling::derive(
        binding.approved_authority.clone(),
        principal.clone(),
        binding.audience.clone(),
        family.roots.clone(),
    )?;
    let expires_at = proof
        .approved_at
        .checked_add(i64::try_from(family.lifetime_seconds)?)
        .context("credential lifetime overflow")?;
    ensure!(
        expires_at <= ready.valid_until,
        "credential grant readiness expires before requested lifetime"
    );
    let reveal_until = proof
        .approved_at
        .checked_add(i64::from(binding.reveal_window_seconds))
        .context("credential reveal overflow")?
        .min(expires_at);
    let prepared = store::prepare_issue(
        &ready.keys,
        family,
        store::IssueIntent {
            namespace: binding.namespace.clone(),
            family: proof.family,
            family_contract: family.contract.clone(),
            invocation: proof.invocation,
            instruction_slot: u32::try_from(request.observations.len())?,
            principal,
            creator: proof.actor.clone(),
            recipient: proof.actor,
            session: proof.session,
            label: input.label.clone(),
            ceiling,
            issued_at: proof.approved_at,
            expires_at,
            grant_valid_until: expires_at,
            reveal_until,
            security_epoch: ready.security_epoch,
        },
    )?;
    let pending = store::stage_issue(tx, prepared)?;
    let receipt = pending.public_identity();
    let lineage = day2_capabilities::credentials::LineageRef {
        namespace: binding.namespace.clone(),
        family: family.id.clone(),
        id: receipt.lineage.clone(),
    };
    Ok(serde_json::to_string(&serde_json::json!({
        "lineage": super::encode_ref(&input.registration, &lineage)?,
        "version": receipt.version, "label": input.label, "expires_at": expires_at,
    }))?)
}

pub(crate) fn validate_commit(
    db: &Connection,
    runtime: &Runtime,
    request: &protocol::Request,
    ready: Option<&ReadyKeys>,
) -> Result<()> {
    if !access(runtime, &request.operation)?.interactive {
        return Ok(());
    }
    let now = runtime.host().now_ms()?.div_euclid(1000);
    require_confirmation(
        db,
        runtime,
        &request.operation,
        &request.context.actor,
        &request.context.invocation_id,
        &crate::json::decode(request.input.as_bytes())?,
        now,
    )?;
    if request
        .observations
        .iter()
        .any(|entry| entry.instruction.kind == "credential_issue" && entry.error.is_empty())
    {
        let proof =
            load(db, &request.context.invocation_id)?.context("credential confirmation missing")?;
        let active = authority_state::current(db)?;
        let selected = active
            .document
            .credentials
            .get(&proof.family)
            .context("credential family inactive")?;
        runtime.credential_authority()?.validate(
            &selected.binding,
            &selected.management,
            &proof.actor,
            &proof.subject,
            ready.context("credential readiness missing")?,
            now,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Fault, replay};
    use std::path::PathBuf;

    fn world() -> Result<(tempfile::TempDir, Runtime)> {
        let artifact = PathBuf::from(std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("build credential-metadata-conformance and set DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")?);
        let directory = tempfile::tempdir()?;
        let runtime = crate::development::create_for(
            &artifact,
            &directory.path().join("instance"),
            None,
            "alice@example.com",
        )?;
        Ok((directory, super::super::verification::install(runtime)?))
    }

    fn confirmed(runtime: &Runtime, operation: &str, id: &str) -> Result<()> {
        let input = serde_json::json!({"label":"Transcription client"});
        let now = runtime.host().now_ms()?.div_euclid(1000);
        super::super::verification::confirm(
            runtime,
            operation,
            "alice@example.com",
            id,
            &input,
            now,
        )?;
        runtime.accept(operation, "alice@example.com", id, &input, now)
    }

    fn counts(runtime: &Runtime) -> Result<(i64, i64)> {
        let db = open(runtime.db())?;
        Ok((
            db.query_row("SELECT count(*) FROM day2_credential_lineages", [], |row| {
                row.get(0)
            })?,
            db.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))?,
        ))
    }

    #[test]
    fn native_issuance_rolls_back_and_recovers_the_same_public_receipt() -> Result<()> {
        let (_directory, runtime) = world()?;
        let operation = "credential_metadata.create_client";
        let input = serde_json::json!({"label":"Transcription client"});
        let now = runtime.host().now_ms()?.div_euclid(1000);
        assert!(
            runtime
                .accept(operation, "alice@example.com", "ordinary", &input, now)
                .is_err()
        );
        assert_eq!(counts(&runtime)?, (0, 0));
        confirmed(&runtime, operation, "rollback")?;
        assert!(runtime.execute("rollback", Fault::BeforeCommit).is_err());
        assert_eq!(counts(&runtime)?, (0, 0));
        let first = runtime.execute("rollback", Fault::None)?;
        assert_eq!(first.status, "success", "{first:?}");
        assert_eq!(counts(&runtime)?, (1, 1));
        assert_eq!(first, runtime.execute("rollback", Fault::None)?);
        let trace = runtime.trace("rollback")?;
        replay(runtime.artifact(), &trace)?;
        let raw = serde_json::to_string(&trace)?;
        for forbidden in [
            "d2c1.",
            "ciphertext",
            "verifier_key",
            "session",
            "security_epoch",
        ] {
            assert!(
                !raw.contains(forbidden),
                "secret or private delivery evidence in app trace: {forbidden}"
            );
        }
        let db = open(runtime.db())?;
        let principal: String = db.query_row(
            "SELECT principal FROM day2_credential_lineages",
            [],
            |row| row.get(0),
        )?;
        assert!(principal.starts_with("client/"));
        assert_ne!(principal, "alice@example.com");
        confirmed(&runtime, operation, "lost-response")?;
        assert!(
            runtime
                .execute("lost-response", Fault::AfterCommit)
                .is_err()
        );
        let recovered = runtime.execute("lost-response", Fault::None)?;
        assert_eq!(recovered.status, "success");
        assert_eq!(recovered, runtime.execute("lost-response", Fault::None)?);
        assert_eq!(counts(&runtime)?, (2, 2));
        Ok(())
    }

    #[test]
    fn personal_issuance_uses_the_confirmed_subject_and_missing_readiness_denies() -> Result<()> {
        let (_directory, mut runtime) = world()?;
        confirmed(&runtime, "credential_metadata.create_personal", "personal")?;
        let outcome = runtime.execute("personal", Fault::None)?;
        assert_eq!(outcome.status, "success", "{outcome:?}");
        let db = open(runtime.db())?;
        let principal: String = db.query_row(
            "SELECT principal FROM day2_credential_lineages",
            [],
            |row| row.get(0),
        )?;
        assert!(principal.starts_with("verification/"));
        confirmed(&runtime, "credential_metadata.create_client", "no-keys")?;
        runtime.credentials = None;
        assert!(runtime.execute("no-keys", Fault::None).is_err());
        assert_eq!(counts(&runtime)?, (1, 1));
        Ok(())
    }

    #[test]
    fn hostile_issue_rejects_changed_label_family_principal_and_second_mutation() -> Result<()> {
        let (_directory, runtime) = world()?;
        confirmed(&runtime, "credential_metadata.create_client", "hostile")?;
        let ready = runtime.prepare_credential_keys("hostile")?.unwrap();
        let mut db = open(runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let mut request = protocol::Request {
            operation: "credential_metadata.create_client".into(),
            input: serde_json::json!({"label":"Transcription client"}).to_string(),
            context: crate::store::invocation_context(&tx, "hostile")?,
            observations: Vec::new(),
        };
        let mut instruction = protocol::Instruction { kind: "credential_issue".into(), model: crate::credential_codegen::ISSUE.into(),
            data: serde_json::json!({"registration":"clients", "invocation":"hostile", "label":"changed"}).to_string(), ..Default::default() };
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        instruction.data = serde_json::json!({"registration":"personal", "invocation":"hostile", "label":"Transcription client"}).to_string();
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        instruction.data = serde_json::json!({"registration":"clients", "invocation":"hostile", "label":"Transcription client", "subject":"someone-else"}).to_string();
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        instruction.data = serde_json::json!({"registration":"clients", "invocation":"hostile", "label":"Transcription client"}).to_string();
        let original_actor = request.context.actor.clone();
        request.context.actor = "bob@example.com".into();
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        request.context.actor = original_actor;
        let public = stage(&tx, &runtime, &request, &instruction, &ready)?;
        request.observations.push(protocol::Observation {
            instruction: instruction.clone(),
            result: public,
            error: String::new(),
        });
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        tx.rollback()?;
        assert_eq!(counts(&runtime)?, (0, 0));
        Ok(())
    }

    #[test]
    fn expired_confirmation_prevents_issuance_but_completed_receipt_is_recoverable() -> Result<()> {
        let (_directory, runtime) = world()?;
        let at = runtime.host().now_ms()?;
        let simulation = crate::simulation::Simulation::new(runtime, [19; 32], at)?;
        let runtime = simulation.runtime();
        confirmed(runtime, "credential_metadata.create_client", "done")?;
        let receipt = runtime.execute("done", Fault::None)?;
        confirmed(runtime, "credential_metadata.create_client", "expired")?;
        simulation.set_time(at + 301_000)?;
        assert!(runtime.execute("expired", Fault::None).is_err());
        assert_eq!(runtime.execute("done", Fault::None)?, receipt);
        assert_eq!(counts(runtime)?, (1, 1));
        Ok(())
    }
}
