//! The ordinary command transaction's private credential issuance adapter.
//! Browser confirmation is separate from app inputs and public result codecs.
use super::{
    crypto::{KeyLease, VerifierLease},
    lifecycle::{self, Intent},
    store,
};
use crate::{authority_state, protocol, store::Runtime};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{
        CredentialFamilyBinding, GrantMode, ManagedProfile, ManagementPolicy, ManagementPredicate,
    },
    oauth::GrantCeiling,
};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{
    Deserialize, Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::Value;

/// A selected host adapter must resolve purpose-bound exact-version keys,
/// current epoch/clock readiness and issuer permission. No default adapter
/// exists. prepare may call a provider; validate must use current local evidence
/// and must not perform external I/O inside the product transaction.
pub(crate) trait Authority: Send + Sync {
    /// Local current evidence only; called under the invocation writer lock.
    fn verification_epoch(
        &self,
        _binding: &CredentialFamilyBinding,
        _management: &ManagementPolicy,
        _verifier_version: &str,
        _now: i64,
    ) -> Result<Option<u64>> {
        anyhow::bail!("credential verification readiness unavailable")
    }

    /// Resolve keys before taking an app writer lock. No token is passed to providers.
    fn verification_keys(
        &self,
        _binding: &CredentialFamilyBinding,
        _management: &ManagementPolicy,
        _now: i64,
    ) -> Result<VerifierLease> {
        anyhow::bail!("credential verification key provider unavailable")
    }

    fn personal_actor(
        &self,
        _binding: &CredentialFamilyBinding,
        _management: &ManagementPolicy,
        _subject: &str,
        _now: i64,
    ) -> Result<String> {
        anyhow::bail!("credential subject mapping unavailable")
    }

    fn check_shell(&self, _binding: &CredentialFamilyBinding, _origin: &str) -> Result<()> {
        anyhow::bail!("credential security shell selection unavailable")
    }
    fn reveal_epoch(
        &self,
        _binding: &CredentialFamilyBinding,
        _management: &ManagementPolicy,
        _actor: &str,
        _subject: &str,
        _now: i64,
    ) -> Result<u64> {
        anyhow::bail!("credential delivery readiness unavailable")
    }
    fn human_keys(
        &self,
        _binding: &CredentialFamilyBinding,
        _management: &ManagementPolicy,
        _actor: &str,
        _subject: &str,
        _permit: &store::HumanRevealPermit,
        _now: i64,
    ) -> Result<KeyLease> {
        anyhow::bail!("credential delivery key provider unavailable")
    }
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
    pub max_active_lineages: u32,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Confirmation {
    pub invocation: String,
    pub operation: String,
    pub actor: String,
    pub subject: String,
    pub session: String,
    pub input: Value,
    pub family: String,
    pub intent: Intent,
    pub artifact: String,
    pub authority: authority_state::AuthorityStamp,
    pub binding: Digest,
    pub security_epoch: u64,
    pub authenticated_at: i64,
    pub approved_at: i64,
    pub expires_at: i64,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "context",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum ConfirmationOrigin {
    Credential(crate::oauth::fresh_auth::CredentialContextData),
    DisposableVerification(VerificationContextData),
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerificationContextData {
    pub purpose: VerificationPurpose,
    pub scope: String,
    pub app: String,
    pub artifact: String,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum VerificationPurpose {
    DisposableCredentialVerification,
}

/// Checked durable DATA, never a fresh-human or runtime readiness witness.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredConfirmation {
    pub confirmation: Confirmation,
    pub original: ConfirmationOrigin,
    pub commitment: Digest,
}

/// Captured by the actual Runtime before provider I/O. No caller-supplied hash
/// can manufacture this fence, and the key provider API remains ReadyKeys.
pub(crate) struct PreparedCredential {
    ready: ReadyKeys,
    confirmation: Digest,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $trait:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::check;
        }};
    }
    assert_not_impl!(PreparedCredential, Clone);
    assert_not_impl!(PreparedCredential, Copy);
    assert_not_impl!(PreparedCredential, Default);
    assert_not_impl!(PreparedCredential, std::fmt::Debug);
    assert_not_impl!(PreparedCredential, serde::Serialize);
    assert_not_impl!(PreparedCredential, serde::Deserialize<'static>);
    assert_not_impl!(PreparedCredential, std::ops::Deref);
    assert_not_impl!(PreparedCredential, AsRef<str>);
    assert_not_impl!(PreparedCredential, AsRef<[u8]>);
    assert_not_impl!(PreparedCredential, std::borrow::Borrow<str>);
    assert_not_impl!(PreparedCredential, std::borrow::Borrow<[u8]>);
};

struct SortedValue<'a>(&'a Value);

const RECORD_BYTE_LIMIT: usize = 1_048_576;

// Debit the complete fixed record framing and arbitrary input before sorting
// keys or serializing. Both record forms have the same input depth and node
// count: the stored commitment leaf replaces the preimage domain leaf.
fn check_record_structure(proof: &Confirmation, original: &ConfirmationOrigin) -> Result<()> {
    fn text(bytes: usize, text_bytes: &mut usize) -> Result<()> {
        *text_bytes = text_bytes
            .checked_add(bytes)
            .context("credential JSON byte overflow")?;
        ensure!(
            *text_bytes <= RECORD_BYTE_LIMIT,
            "credential JSON byte budget"
        );
        Ok(())
    }
    fn bounded(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        text_bytes: &mut usize,
    ) -> Result<()> {
        *nodes += 1;
        ensure!(
            depth <= 32 && *nodes <= 20_000,
            "credential JSON structure budget"
        );
        match value {
            Value::Object(values) => {
                for key in values.keys() {
                    text(key.len(), text_bytes)?;
                }
                for value in values.values() {
                    bounded(value, depth + 1, nodes, text_bytes)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    bounded(value, depth + 1, nodes, text_bytes)?;
                }
            }
            Value::String(value) => text(value.len(), text_bytes)?,
            _ => {}
        }
        Ok(())
    }
    let intent_nodes = match &proof.intent {
        Intent::Issue { .. } | Intent::Revoke { .. } => 3,
        Intent::Rotate { .. } => 5,
    };
    let original_nodes = match original {
        ConfirmationOrigin::Credential(context) => {
            // Adding a context field must also revisit fixed node accounting.
            let crate::oauth::fresh_auth::CredentialContextData {
                purpose: _,
                scope: _,
                app: _,
                artifact: _,
                app_origin: _,
                shell_origin: _,
                attempt: _,
                pending_challenge: _,
                human: _,
                subject: _,
                pending_created_at: _,
                pending_expires_at: _,
                authenticated_at: _,
                proof_deadline: _,
            } = context;
            17
        }
        ConfirmationOrigin::DisposableVerification(context) => {
            let VerificationContextData {
                purpose: _,
                scope: _,
                app: _,
                artifact: _,
            } = context;
            7
        }
    };
    bounded(
        &proof.input,
        2,
        &mut (18 + intent_nodes + original_nodes),
        &mut 0,
    )
}

// The serializer cannot grow an output allocation beyond the byte limit, even
// when JSON escaping makes a small in-memory string much larger on the wire.
struct BoundedJson {
    bytes: Box<[u8]>,
    used: usize,
}

impl std::io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| std::io::Error::other("credential JSON byte budget"))?;
        self.bytes[self.used..end].copy_from_slice(bytes);
        self.used = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut output = BoundedJson {
        bytes: vec![0; RECORD_BYTE_LIMIT].into_boxed_slice(),
        used: 0,
    };
    serde_json::to_writer(&mut output, value)?;
    let mut bytes = output.bytes.into_vec();
    bytes.truncate(output.used);
    Ok(bytes)
}

impl Serialize for SortedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_unstable();
                let mut map = serializer.serialize_map(Some(keys.len()))?;
                for key in keys {
                    map.serialize_entry(key, &SortedValue(&values[key.as_str()]))?;
                }
                map.end()
            }
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&SortedValue(value))?;
                }
                sequence.end()
            }
            value => value.serialize(serializer),
        }
    }
}

fn commitment(confirmation: &Confirmation, original: &ConfirmationOrigin) -> Result<Digest> {
    check_record_structure(confirmation, original)?;
    struct CanonicalIntent<'a>(&'a Intent);
    impl Serialize for CanonicalIntent<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(match self.0 {
                Intent::Issue { .. } | Intent::Revoke { .. } => 2,
                Intent::Rotate { .. } => 4,
            }))?;
            map.serialize_entry("action", self.0.action())?;
            match self.0 {
                Intent::Issue { label } => map.serialize_entry("label", label)?,
                Intent::Rotate {
                    lineage,
                    head,
                    revision,
                } => {
                    map.serialize_entry("head", head)?;
                    map.serialize_entry("lineage", lineage)?;
                    map.serialize_entry("revision", revision)?;
                }
                Intent::Revoke { lineage } => map.serialize_entry("lineage", lineage)?,
            }
            map.end()
        }
    }
    #[derive(Serialize)]
    struct CanonicalAuthority<'a> {
        epoch: &'a str,
        revision: u64,
    }
    #[derive(Serialize)]
    struct CanonicalConfirmation<'a> {
        invocation: &'a str,
        operation: &'a str,
        actor: &'a str,
        subject: &'a str,
        session: &'a str,
        input: SortedValue<'a>,
        family: &'a str,
        intent: CanonicalIntent<'a>,
        artifact: &'a str,
        authority: CanonicalAuthority<'a>,
        binding: &'a Digest,
        security_epoch: u64,
        authenticated_at: i64,
        approved_at: i64,
        expires_at: i64,
    }
    // Exhaustive field patterns make a newly added member require an explicit
    // canonical representation instead of silently escaping the commitment.
    let Confirmation {
        invocation,
        operation,
        actor,
        subject,
        session,
        input,
        family,
        intent,
        artifact,
        authority,
        binding,
        security_epoch,
        authenticated_at,
        approved_at,
        expires_at,
    } = confirmation;
    let authority_state::AuthorityStamp { epoch, revision } = authority;
    let body = CanonicalConfirmation {
        invocation,
        operation,
        actor,
        subject,
        session,
        input: SortedValue(input),
        family,
        intent: CanonicalIntent(intent),
        artifact,
        authority: CanonicalAuthority {
            epoch,
            revision: *revision,
        },
        binding,
        security_epoch: *security_epoch,
        authenticated_at: *authenticated_at,
        approved_at: *approved_at,
        expires_at: *expires_at,
    };
    let bytes = bounded_json(&("credential-confirmation-record-v1", body, original))?;
    let _: Value = crate::json::decode(&bytes)?;
    Ok(Digest::new(&bytes))
}

fn validate_record_data(proof: &Confirmation, original: &ConfirmationOrigin) -> Result<()> {
    check_record_structure(proof, original)?;
    for value in [
        &proof.invocation,
        &proof.operation,
        &proof.session,
        &proof.family,
    ] {
        store::validate_id(value)?;
    }
    crate::authority::valid_actor(&proof.actor)?;
    ensure!(
        !proof.subject.is_empty()
            && proof.subject.len() <= 256
            && proof.subject.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid credential confirmation subject"
    );
    ensure!(
        proof.artifact.len() == 71 && proof.authority.epoch.len() == 71,
        "invalid credential digest length"
    );
    Digest::try_from(proof.artifact.clone())?;
    Digest::try_from(proof.authority.epoch.clone())?;
    ensure!(
        proof.security_epoch > 0
            && proof.authority.revision > 0
            && proof.input.is_object()
            && proof.authenticated_at >= 0
            && proof.authenticated_at <= proof.approved_at
            && proof.approved_at < proof.expires_at
            && proof
                .expires_at
                .checked_sub(proof.authenticated_at)
                .is_some_and(|seconds| seconds <= 300),
        "invalid credential confirmation authority or time"
    );
    store::validate_restored_intent(&proof.intent, &proof.family)?;
    let (scope, app, artifact) = match original {
        ConfirmationOrigin::Credential(context) => {
            context.validate_origins()?;
            store::validate_id(&context.attempt)?;
            ensure!(
                context.human == proof.actor
                    && context.subject == proof.subject
                    && context.authenticated_at == proof.authenticated_at
                    && context.pending_created_at >= 0
                    && context
                        .pending_expires_at
                        .checked_sub(context.pending_created_at)
                        == Some(300)
                    && context.authenticated_at > context.pending_created_at
                    && proof.expires_at == context.pending_expires_at.min(context.proof_deadline),
                "invalid original credential confirmation context"
            );
            (&context.scope, &context.app, &context.artifact)
        }
        ConfirmationOrigin::DisposableVerification(context) => {
            (&context.scope, &context.app, &context.artifact)
        }
    };
    ensure!(
        scope.len() <= 242 && app.len() <= 80,
        "invalid credential original scope length"
    );
    let mut components = scope.split('/');
    let (Some(installation), Some(environment), Some(scoped_app), None) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        anyhow::bail!("invalid credential original scope");
    };
    for name in [installation, environment, scoped_app, app.as_str()] {
        day2_capabilities::Name::try_from(name.to_owned())?;
    }
    ensure!(scoped_app == app, "credential original scope app changed");
    ensure!(
        artifact == &proof.artifact,
        "credential original artifact changed"
    );
    Ok(())
}

fn validate_record(record: &StoredConfirmation) -> Result<()> {
    validate_record_data(&record.confirmation, &record.original)?;
    ensure!(
        commitment(&record.confirmation, &record.original)? == record.commitment,
        "credential confirmation commitment changed"
    );
    Ok(())
}

pub(super) fn encode_record(
    confirmation: Confirmation,
    original: ConfirmationOrigin,
) -> Result<String> {
    validate_record_data(&confirmation, &original)
        .map_err(|_| anyhow::anyhow!("invalid credential confirmation record"))?;
    let digest = commitment(&confirmation, &original)?;
    let record = StoredConfirmation {
        confirmation,
        original,
        commitment: digest,
    };
    validate_record(&record)
        .map_err(|_| anyhow::anyhow!("invalid credential confirmation record"))?;
    let raw = String::from_utf8(bounded_json(&record)?)?;
    // The stored envelope/digest and canonical preimage have independent limits.
    decode_record(&record.confirmation.invocation, raw.as_bytes())?;
    Ok(raw)
}

pub(super) fn decode_record(invocation: &str, body: &[u8]) -> Result<StoredConfirmation> {
    fn decode(invocation: &str, body: &[u8]) -> Result<StoredConfirmation> {
        let value: Value = crate::json::decode(body)?;
        ensure!(value.is_object(), "credential record object required");
        let proof = &value["confirmation"];
        let original = &value["original"];
        ensure!(
            proof.is_object()
                && original.is_object()
                && original["context"].is_object()
                && proof["authority"].is_object()
                && proof["intent"].is_object()
                && proof["input"].is_object(),
            "credential record maps required"
        );
        let record: StoredConfirmation = serde_json::from_value(value)?;
        ensure!(
            record.confirmation.invocation == invocation,
            "credential record key changed"
        );
        validate_record(&record)?;
        Ok(record)
    }
    decode(invocation, body).map_err(|_| anyhow::anyhow!("invalid credential confirmation record"))
}

/// Negative history fixtures may recompute a self-consistent digest without
/// granting validity. This never constructs a prepared or fresh-human owner.
#[cfg(test)]
pub(crate) fn rehash_fixture_value(value: &mut Value) -> Result<()> {
    let proof: Confirmation = serde_json::from_value(value["confirmation"].clone())?;
    let original: ConfirmationOrigin = serde_json::from_value(value["original"].clone())?;
    value["commitment"] = serde_json::to_value(commitment(&proof, &original)?)?;
    Ok(())
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    super::ingress::install(db)?;
    super::browser::install(db)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_credential_confirmations (
        invocation TEXT PRIMARY KEY, confirmation TEXT NOT NULL
    ) STRICT;",
    )?;
    Ok(())
}

pub(super) fn load(db: &Connection, invocation: &str) -> Result<Option<StoredConfirmation>> {
    let mut statement =
        db.prepare("SELECT confirmation FROM day2_credential_confirmations WHERE invocation=?1")?;
    let mut rows = statement.query([invocation])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    // Debit and decode borrowed bytes before allocating a copied row string.
    decode_record(invocation, row.get_ref(0)?.as_str()?.as_bytes()).map(Some)
}

pub(super) fn require_runtime_record(
    db: &Connection,
    runtime: &Runtime,
    invocation: &str,
) -> Result<StoredConfirmation> {
    let record = load(db, invocation)?.ok_or(crate::error::Failure::Forbidden)?;
    let (scope, app, artifact) = match &record.original {
        ConfirmationOrigin::Credential(context) => {
            (&context.scope, &context.app, &context.artifact)
        }
        ConfirmationOrigin::DisposableVerification(context) => {
            ensure!(
                runtime.integrations().is_simulated(),
                "disposable credential runtime required"
            );
            let active = authority_state::current(db)?;
            let selected = active
                .document
                .credentials
                .get(&record.confirmation.family)
                .context("credential family inactive")?;
            ensure!(
                selected.binding.namespace.installation.as_str() == "localdev"
                    && selected.binding.namespace.environment.as_str() == "disposable"
                    && selected.management.issue == ManagementPredicate::Creator,
                "disposable credential selection required"
            );
            (&context.scope, &context.app, &context.artifact)
        }
    };
    ensure!(
        scope == runtime.scope() && app == runtime.app() && artifact == runtime.artifact().id(),
        "credential confirmation runtime changed"
    );
    let access = access(runtime, &record.confirmation.operation)?;
    ensure!(
        access.interactive
            && access.mutation()
                == Some((
                    record.confirmation.intent.action(),
                    record.confirmation.family.as_str()
                ))
            && lifecycle::intent(access, &record.confirmation.input)? == record.confirmation.intent,
        "credential original operation intent changed"
    );
    let mut statement =
        db.prepare("SELECT operation,actor,input,artifact FROM day2_invocations WHERE id=?1")?;
    let mut rows = statement.query([invocation])?;
    if let Some(row) = rows.next()? {
        let input: Value = crate::json::decode(row.get_ref(2)?.as_str()?.as_bytes())?;
        ensure!(
            row.get_ref(0)?.as_str()? == record.confirmation.operation
                && row.get_ref(1)?.as_str()? == record.confirmation.actor
                && input == record.confirmation.input
                && row.get_ref(3)?.as_str()? == record.confirmation.artifact,
            "credential owning invocation changed"
        );
    }
    Ok(record)
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
            rotations: Vec::new(),
            revocations: Vec::new(),
            issue_label: String::new(),
            management_lineage: String::new(),
            rotation_head: String::new(),
            rotation_revision: String::new(),
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
    let record = require_runtime_record(db, runtime, invocation)?;
    let proof = &record.confirmation;
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
                && proof
                    .approved_at
                    .checked_sub(proof.authenticated_at)
                    .is_some_and(|seconds| seconds <= 300),
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

    /// The read snapshot ends before resolving keys or taking an app writer lock.
    pub(crate) fn prepare_credential_keys(
        &self,
        invocation: &str,
    ) -> Result<Option<PreparedCredential>> {
        let prepared = self.sql_read(|read| {
            let (operation, pending): (String, bool) = read.query_row(
                "SELECT operation,status='pending' FROM day2_invocations WHERE id=?1",
                [invocation],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if !access(self, &operation)?.interactive {
                ensure!(
                    load(&read, invocation)?.is_none(),
                    "unexpected credential confirmation"
                );
                return Ok(None);
            }
            // Final selected role and exact owning invocation are checked even for
            // terminal reuse, before returning None or calling any key provider.
            let record = require_runtime_record(&read, self, invocation)?;
            if !pending {
                return Ok(None);
            }
            let proof = &record.confirmation;
            let active =
                authority_state::authorize_in(&read, self, &proof.operation, &proof.actor)?;
            let selected = active
                .document
                .credentials
                .get(&proof.family)
                .context("credential family inactive")?;
            let now = self.host().now_ms()?.div_euclid(1000);
            ensure!(
                proof.authority == active.stamp
                    && Digest::of(&selected.binding)? == proof.binding
                    && now >= proof.approved_at
                    && now < proof.expires_at,
                "credential confirmation expired"
            );
            Ok(Some((record, active, now)))
        })?;
        let Some((record, active, now)) = prepared else {
            return Ok(None);
        };
        let proof = &record.confirmation;
        let selected = active
            .document
            .credentials
            .get(&proof.family)
            .context("credential family inactive")?;
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
        Ok(Some(PreparedCredential {
            ready,
            confirmation: record.commitment,
        }))
    }
}

pub(crate) fn stage(
    tx: &Transaction<'_>,
    runtime: &Runtime,
    request: &protocol::Request,
    instruction: &protocol::Instruction,
    prepared: &PreparedCredential,
) -> Result<String> {
    let ready = &prepared.ready;
    ensure!(
        instruction.decode()? == protocol::Step::CredentialMutation,
        "credential lifecycle instruction required"
    );
    let input: Value = crate::json::decode(instruction.data.as_bytes())?;
    let registration = input
        .get("registration")
        .and_then(Value::as_str)
        .context("credential registration missing")?;
    let origin = crate::store::invocation_context(tx, &request.context.invocation_id)?;
    ensure!(
        origin == request.context
            && origin.caller.is_empty()
            && origin.authenticated.is_empty()
            && origin.authentication == "request"
            && input.get("invocation").and_then(Value::as_str)
                == Some(origin.invocation_id.as_str()),
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
    let record = require_runtime_record(tx, runtime, &origin.invocation_id)?;
    ensure!(
        record.commitment == prepared.confirmation,
        "prepared credential confirmation changed"
    );
    let proof = record.confirmation;
    let access = access(runtime, &request.operation)?;
    ensure!(
        access.mutation() == Some((proof.intent.action(), proof.family.as_str()))
            && lifecycle::intent(access, &value)? == proof.intent
            && input
                == proof
                    .intent
                    .instruction(registration, &origin.invocation_id)
            && instruction.kind == format!("credential_{}", proof.intent.action()),
        "credential intent changed after confirmation"
    );
    ensure!(
        !request.observations.iter().any(|entry| matches!(
            entry.instruction.kind.as_str(),
            "credential_issue" | "credential_rotate" | "credential_revoke"
        )),
        "one credential lifecycle mutation per management command"
    );
    let family = runtime
        .artifact()
        .contract()
        .credential_manifest
        .iter()
        .find(|family| {
            family.registration.as_str() == registration && family.id.as_str() == proof.family
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
    if !matches!(proof.intent, Intent::Issue { .. }) {
        return lifecycle::stage(tx, request, &proof, family, selected, ready);
    }
    let Intent::Issue { label } = &proof.intent else {
        unreachable!()
    };
    ensure!(
        (1..=10_000).contains(&ready.max_active_lineages),
        "credential issuance quota unavailable"
    );
    let namespace = Digest::of(&("credential-namespace-v1", &binding.namespace))?;
    let active_count: u32 = tx.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM day2_credential_lineages l
        JOIN day2_credential_versions v ON v.id=l.head AND v.lineage=l.id
        WHERE l.namespace=?1 AND l.family=?2 AND l.state='active' AND v.state='active'
          AND l.grant_valid_until>?4 AND v.expires_at>?4 LIMIT ?3)",
        rusqlite::params![
            namespace.as_str(),
            family.id.as_str(),
            ready.max_active_lineages,
            now
        ],
        |row| row.get(0),
    )?;
    ensure!(
        active_count < ready.max_active_lineages,
        "credential issuance quota exhausted"
    );
    let principal = match family.profile {
        ManagedProfile::Personal => proof.subject.clone(),
        _ => format!(
            "client/{}/{}",
            family.id.as_str(),
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
            label: label.clone(),
            ceiling,
            issued_at: proof.approved_at,
            expires_at,
            grant_valid_until: ready.valid_until,
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
        "lineage": super::encode_ref(registration, &lineage)?,
        "version": receipt.version, "label": label, "expires_at": expires_at,
    }))?)
}

pub(crate) fn validate_commit(
    db: &Connection,
    runtime: &Runtime,
    request: &protocol::Request,
    prepared: Option<&PreparedCredential>,
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
    let prepared = prepared.context("credential preparation missing")?;
    let record = require_runtime_record(db, runtime, &request.context.invocation_id)?;
    ensure!(
        record.commitment == prepared.confirmation,
        "prepared credential confirmation changed"
    );
    if request.observations.iter().any(|entry| {
        matches!(
            entry.instruction.kind.as_str(),
            "credential_issue" | "credential_rotate" | "credential_revoke"
        ) && entry.error.is_empty()
    }) {
        let proof = &record.confirmation;
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
            &prepared.ready,
            now,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::open;
    use crate::store::{Fault, replay};
    use std::path::PathBuf;

    // Literal preimage/hash authored independently of the Rust codec. These
    // values are synthetic DATA, never a signed original pending/proof owner.
    const GOLDEN_PREIMAGE: &str = r#"["credential-confirmation-record-v1",{"invocation":"invocation-1","operation":"IssueKey","actor":"alice@example.com","subject":"accounts.google.com:human-1","session":"session-1","input":{"alpha":7,"label":"Golden key","zeta":{"a":[true,null,"text"],"z":2}},"family":"api_keys","intent":{"action":"issue","label":"Golden key"},"artifact":"sha256:1111111111111111111111111111111111111111111111111111111111111111","authority":{"epoch":"sha256:2222222222222222222222222222222222222222222222222222222222222222","revision":7},"binding":"sha256:3333333333333333333333333333333333333333333333333333333333333333","security_epoch":4,"authenticated_at":1010,"approved_at":1011,"expires_at":1290},{"kind":"credential","context":{"purpose":"credential_intent","scope":"localdev/disposable/app","app":"app","artifact":"sha256:1111111111111111111111111111111111111111111111111111111111111111","app_origin":"https://app.example.com","shell_origin":"https://shell.example.com","attempt":"attempt-1","pending_challenge":"sha256:4444444444444444444444444444444444444444444444444444444444444444","human":"alice@example.com","subject":"accounts.google.com:human-1","pending_created_at":1000,"pending_expires_at":1300,"authenticated_at":1010,"proof_deadline":1290}}]"#;
    const GOLDEN_DIGEST: &str =
        "sha256:10950b7c4fd37f242ec258ebe9c2c98f4d077a15c1a2e0587fcc07cc07f1400f";

    fn golden() -> Result<(Confirmation, ConfirmationOrigin)> {
        let value: Value = crate::json::decode(GOLDEN_PREIMAGE.as_bytes())?;
        Ok((
            serde_json::from_value(value[1].clone())?,
            serde_json::from_value(value[2].clone())?,
        ))
    }

    #[test]
    fn complete_record_has_independent_golden_and_binds_every_member() -> Result<()> {
        let (proof, original) = golden()?;
        assert_eq!(commitment(&proof, &original)?.as_str(), GOLDEN_DIGEST);
        assert_eq!(
            Digest::new(GOLDEN_PREIMAGE.as_bytes()).as_str(),
            GOLDEN_DIGEST
        );
        let body: Value = crate::json::decode(encode_record(proof, original)?.as_bytes())?;
        for path in [
            "/confirmation/invocation",
            "/confirmation/operation",
            "/confirmation/actor",
            "/confirmation/subject",
            "/confirmation/session",
            "/confirmation/input/alpha",
            "/confirmation/input/zeta/a/0",
            "/confirmation/input/zeta/z",
            "/confirmation/family",
            "/confirmation/intent/label",
            "/confirmation/artifact",
            "/confirmation/authority/epoch",
            "/confirmation/authority/revision",
            "/confirmation/binding",
            "/confirmation/security_epoch",
            "/confirmation/authenticated_at",
            "/confirmation/approved_at",
            "/confirmation/expires_at",
            "/original/context/scope",
            "/original/context/app",
            "/original/context/artifact",
            "/original/context/app_origin",
            "/original/context/shell_origin",
            "/original/context/attempt",
            "/original/context/pending_challenge",
            "/original/context/human",
            "/original/context/subject",
            "/original/context/pending_created_at",
            "/original/context/pending_expires_at",
            "/original/context/authenticated_at",
            "/original/context/proof_deadline",
        ] {
            let mut changed = body.clone();
            let value = changed.pointer_mut(path).unwrap();
            *value = match value {
                Value::String(text) if text.starts_with("sha256:") => {
                    Digest::new(b"changed").as_str().into()
                }
                Value::String(text) => format!("{text}x").into(),
                Value::Number(number) => (number.as_i64().unwrap() + 1).into(),
                Value::Bool(value) => (!*value).into(),
                _ => panic!("unexpected golden mutation role"),
            };
            let old = changed["commitment"].clone();
            rehash_fixture_value(&mut changed)?;
            assert_ne!(changed["commitment"], old, "unbound {path}");
        }
        // Fixed closed tags cannot be relabelled as another producer or purpose.
        for path in [
            "/original/kind",
            "/original/context/purpose",
            "/confirmation/intent/action",
        ] {
            let mut changed = body.clone();
            *changed.pointer_mut(path).unwrap() = "unknown".into();
            assert!(decode_record("invocation-1", changed.to_string().as_bytes()).is_err());
        }
        let (mut reordered, original) = golden()?;
        reordered.input = serde_json::from_str(
            r#"{"zeta":{"z":2,"a":[true,null,"text"]},"label":"Golden key","alpha":7}"#,
        )?;
        assert_eq!(commitment(&reordered, &original)?.as_str(), GOLDEN_DIGEST);
        Ok(())
    }

    #[test]
    fn record_wire_rejects_old_maps_sequences_duplicates_and_budget_bypasses() -> Result<()> {
        let (proof, original) = golden()?;
        let raw = encode_record(proof, original)?;
        let body: Value = crate::json::decode(raw.as_bytes())?;
        // Independently declared positional field order is valid for Serde's
        // unchecked DATA structs. The checked codec must still require maps.
        let positional = Value::Array(vec![
            body["confirmation"].clone(),
            body["original"].clone(),
            body["commitment"].clone(),
        ]);
        let unchecked: StoredConfirmation = serde_json::from_value(positional.clone())?;
        validate_record(&unchecked)?;
        assert!(decode_record("invocation-1", positional.to_string().as_bytes()).is_err());
        for (pointer, fields) in [
            (
                "/confirmation",
                vec![
                    "invocation",
                    "operation",
                    "actor",
                    "subject",
                    "session",
                    "input",
                    "family",
                    "intent",
                    "artifact",
                    "authority",
                    "binding",
                    "security_epoch",
                    "authenticated_at",
                    "approved_at",
                    "expires_at",
                ],
            ),
            (
                "/original/context",
                vec![
                    "purpose",
                    "scope",
                    "app",
                    "artifact",
                    "app_origin",
                    "shell_origin",
                    "attempt",
                    "pending_challenge",
                    "human",
                    "subject",
                    "pending_created_at",
                    "pending_expires_at",
                    "authenticated_at",
                    "proof_deadline",
                ],
            ),
            ("/confirmation/authority", vec!["epoch", "revision"]),
        ] {
            let mut changed = body.clone();
            let object = changed.pointer(pointer).unwrap();
            let positional =
                Value::Array(fields.iter().map(|field| object[*field].clone()).collect());
            *changed.pointer_mut(pointer).unwrap() = positional;
            let unchecked: StoredConfirmation = serde_json::from_value(changed.clone())?;
            validate_record(&unchecked)?;
            assert!(
                decode_record("invocation-1", changed.to_string().as_bytes()).is_err(),
                "accepted valid positional DATA at {pointer}"
            );
        }
        for pointer in [
            "",
            "/confirmation",
            "/original",
            "/original/context",
            "/confirmation/authority",
            "/confirmation/intent",
            "/confirmation/input",
        ] {
            let mut changed = body.clone();
            let value = changed.pointer_mut(pointer).unwrap();
            *value = value
                .as_object()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>()
                .into();
            assert!(
                decode_record("invocation-1", changed.to_string().as_bytes()).is_err(),
                "sequence at {pointer}"
            );
        }
        for pointer in [
            "/commitment",
            "/original",
            "/confirmation/authenticated_at",
            "/original/context/proof_deadline",
        ] {
            let mut changed = body.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            changed
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(decode_record("invocation-1", changed.to_string().as_bytes()).is_err());
        }
        for digest in [
            format!("{GOLDEN_DIGEST}\0suffix"),
            GOLDEN_DIGEST.to_ascii_uppercase(),
            "sha256:0".into(),
        ] {
            let mut changed = body.clone();
            changed["commitment"] = digest.into();
            assert!(decode_record("invocation-1", changed.to_string().as_bytes()).is_err());
        }
        assert!(
            decode_record("invocation-1", body["confirmation"].to_string().as_bytes()).is_err()
        );
        assert!(decode_record("wrong-row", raw.as_bytes()).is_err());
        let duplicate = format!(
            "{},\"commitment\":\"{}\"}}",
            raw.trim_end_matches('}'),
            GOLDEN_DIGEST
        );
        assert!(decode_record("invocation-1", duplicate.as_bytes()).is_err());
        let escaped = raw.replace("\"alpha\":7", "\"alpha\":7,\"\\u0061lpha\":8");
        assert!(decode_record("invocation-1", escaped.as_bytes()).is_err());
        let mut changed = body.clone();
        changed["confirmation"]["input"]["large"] = "x".repeat(1_048_576).into();
        assert!(decode_record("invocation-1", changed.to_string().as_bytes()).is_err());
        changed = body.clone();
        changed["confirmation"]["input"]["nodes"] = vec![0_u8; 20_000].into();
        assert!(decode_record("invocation-1", changed.to_string().as_bytes()).is_err());
        changed = body;
        changed["confirmation"]["input"]["deep"] =
            serde_json::from_str(&format!("{}0{}", "[".repeat(32), "]".repeat(32)))?;
        assert!(decode_record("invocation-1", changed.to_string().as_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn current_table_reopens_but_noncurrent_body_never_repairs() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("records.sqlite");
        let db = Connection::open(&path)?;
        install(&db)?;
        let (proof, original) = golden()?;
        let raw = encode_record(proof, original)?;
        db.execute(
            "INSERT INTO day2_credential_confirmations(invocation,confirmation) VALUES (?1,?2)",
            ["invocation-1", &raw],
        )?;
        drop(db);
        let db = Connection::open(path)?;
        assert_eq!(
            load(&db, "invocation-1")?.unwrap().commitment.as_str(),
            GOLDEN_DIGEST
        );
        let before: String = db.query_row(
            "SELECT confirmation FROM day2_credential_confirmations",
            [],
            |row| row.get(0),
        )?;
        for raw in [
            "{}".to_owned(),
            before.replace(GOLDEN_DIGEST, Digest::new(b"forged").as_str()),
        ] {
            db.execute(
                "UPDATE day2_credential_confirmations SET confirmation=?1",
                [&raw],
            )?;
            assert!(load(&db, "invocation-1").is_err());
            assert_eq!(
                db.query_row(
                    "SELECT confirmation FROM day2_credential_confirmations",
                    [],
                    |row| row.get::<_, String>(0)
                )?,
                raw
            );
        }
        Ok(())
    }

    #[test]
    fn encoder_rejects_in_memory_depth_nodes_and_escaped_output_overflow() -> Result<()> {
        for case in 0..4 {
            let (mut proof, original) = golden()?;
            let value = match case {
                0 => Value::String("x".repeat(RECORD_BYTE_LIMIT + 1)),
                1 => Value::String("\0".repeat(RECORD_BYTE_LIMIT / 5)),
                2 => vec![0_u8; 20_000].into(),
                _ => {
                    let mut value = Value::Null;
                    for _ in 0..32 {
                        value = Value::Array(vec![value]);
                    }
                    value
                }
            };
            proof.input["overflow"] = value;
            assert!(
                encode_record(proof, original).is_err(),
                "encoded oversized case {case}"
            );
        }
        let mut writer = BoundedJson {
            bytes: vec![0; RECORD_BYTE_LIMIT].into_boxed_slice(),
            used: 0,
        };
        std::io::Write::write_all(&mut writer, &vec![b'x'; RECORD_BYTE_LIMIT])?;
        assert!(std::io::Write::write_all(&mut writer, b"y").is_err());
        assert_eq!(writer.used, RECORD_BYTE_LIMIT);
        assert_eq!(writer.bytes.len(), RECORD_BYTE_LIMIT);
        assert!(writer.bytes.iter().all(|byte| *byte == b'x'));
        Ok(())
    }

    fn world() -> Result<(tempfile::TempDir, Runtime)> {
        let artifact = PathBuf::from(std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("build credential-metadata-conformance and set DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")?);
        let directory = tempfile::tempdir()?;
        let runtime = crate::development::create_verification_for(
            &artifact,
            &directory.path().join("instance"),
            None,
            "alice@example.com",
        )?;
        Ok((directory, super::super::verification::install(runtime)?))
    }

    fn deterministic_world(
        seed: u8,
    ) -> Result<(tempfile::TempDir, Runtime, crate::simulation::Simulation)> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let artifact = PathBuf::from(std::env::var_os("DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")
            .context("build credential-metadata-conformance and set DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT")?);
        // Actual artifact-derived desired DATA, strict loader, and selected
        // deterministic Host BEFORE the first database initialization.
        let instance =
            crate::development::verification_instance_data(&artifact, None, "alice@example.com")?;
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("instance.json");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&serde_json::to_vec(&instance)?)?;
        file.sync_all()?;
        let runtime = Runtime::load(&path, "app")?;
        ensure!(
            !runtime.db().exists(),
            "deterministic fixture database already exists"
        );
        let simulation = crate::simulation::Simulation::new(runtime, [seed; 32], 1_000_000)?;
        simulation.runtime().initialize()?;
        let runtime = super::super::verification::install(simulation.runtime().clone())?;
        Ok((directory, runtime, simulation))
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

    fn confirm_input(runtime: &Runtime, operation: &str, id: &str, input: &Value) -> Result<()> {
        let now = runtime.host().now_ms()?.div_euclid(1000);
        super::super::verification::confirm(
            runtime,
            operation,
            "alice@example.com",
            id,
            input,
            now,
        )?;
        runtime.accept(operation, "alice@example.com", id, input, now)
    }

    #[test]
    fn final_selected_role_refuses_disposable_history_including_terminal_reuse() -> Result<()> {
        let hooks = super::super::simulation::World::new(29);
        super::super::effects::scope(hooks, || -> Result<()> {
            let (_directory, runtime, _simulation) = deterministic_world(29)?;
            let calls = std::sync::Arc::new([
                std::sync::atomic::AtomicUsize::new(0),
                std::sync::atomic::AtomicUsize::new(0),
            ]);
            let runtime = runtime
                .clone()
                .with_credential_authority(std::sync::Arc::new(CountedAuthority {
                    inner: runtime.credentials.as_ref().unwrap().clone(),
                    calls: calls.clone(),
                }));
            let current_calls = || {
                calls
                    .each_ref()
                    .map(|value| value.load(std::sync::atomic::Ordering::SeqCst))
            };
            confirmed(
                &runtime,
                "credential_metadata.create_client",
                "role-pending",
            )?;
            let before_calls = current_calls();
            let db = open(runtime.db())?;
            let before: String = db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='role-pending'", [], |row| row.get(0))?;
            // Metadata loading is deliberately role-agnostic. Execution is not.
            let local = Runtime::load(runtime.instance_path(), runtime.app())?
                .with_credential_authority(runtime.credentials.as_ref().unwrap().clone());
            // Preserve the intentionally local provider role while replacing its
            // System clock/entropy with explicit deterministic host inputs.
            let local_inputs =
                crate::simulation::Simulation::with_scripted_providers(local, [29; 32], 1_000_000)?;
            let local = local_inputs.runtime().clone();
            let hybrid = local.clone().with_integrations(
                crate::integration_host::Host::simulated_providers_with_app_calls(
                    runtime.db(),
                    runtime.scope(),
                ),
            );
            let input = serde_json::json!({"label":"Transcription client"});
            for selected in [&local, &hybrid] {
                assert!(selected.prepare_credential_keys("role-pending").is_err());
                assert!(
                    selected
                        .accept(
                            "credential_metadata.create_client",
                            "alice@example.com",
                            "role-pending",
                            &input,
                            runtime.host().now_ms()?.div_euclid(1000)
                        )
                        .is_err()
                );
                assert!(selected.execute("role-pending", Fault::None).is_err());
                assert_eq!(
                    current_calls(),
                    before_calls,
                    "nonsimulated refusal reached key preparation/validation"
                );
            }
            assert_eq!(counts(&runtime)?, (0, 0));
            assert_eq!(db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='role-pending'", [], |row| row.get::<_, String>(0))?, before);
            let outcome = runtime.execute("role-pending", Fault::None)?;
            assert_eq!(outcome.status, "success");
            let committed_calls = current_calls();
            assert!(
                committed_calls[0] > before_calls[0] && committed_calls[1] > before_calls[1],
                "positive simulated execution did not exercise delegated key counters"
            );
            for selected in [&local, &hybrid] {
                assert!(selected.prepare_credential_keys("role-pending").is_err());
                assert!(selected.execute("role-pending", Fault::None).is_err());
                assert_eq!(
                    current_calls(),
                    committed_calls,
                    "terminal role refusal reached key provider"
                );
            }
            let simulated = local.with_integrations(crate::integration_host::Host::simulated(
                runtime.db(),
                runtime.scope(),
            ));
            assert!(simulated.prepare_credential_keys("role-pending")?.is_none());
            assert_eq!(simulated.execute("role-pending", Fault::None)?, outcome);
            assert_eq!(
                current_calls(),
                committed_calls,
                "simulated terminal reuse prepared or validated lifecycle keys"
            );
            assert_eq!(counts(&runtime)?, (1, 1));
            Ok(())
        })
    }

    struct CountedAuthority {
        inner: std::sync::Arc<dyn Authority>,
        calls: std::sync::Arc<[std::sync::atomic::AtomicUsize; 2]>,
    }

    impl Authority for CountedAuthority {
        fn prepare(
            &self,
            binding: &CredentialFamilyBinding,
            management: &ManagementPolicy,
            actor: &str,
            subject: &str,
            now: i64,
        ) -> Result<ReadyKeys> {
            self.calls[0].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.prepare(binding, management, actor, subject, now)
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
            self.calls[1].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner
                .validate(binding, management, actor, subject, ready, now)
        }
    }

    struct PausedAuthority {
        inner: std::sync::Arc<dyn Authority>,
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl Authority for PausedAuthority {
        fn prepare(
            &self,
            binding: &CredentialFamilyBinding,
            management: &ManagementPolicy,
            actor: &str,
            subject: &str,
            now: i64,
        ) -> Result<ReadyKeys> {
            let ready = self
                .inner
                .prepare(binding, management, actor, subject, now)?;
            self.entered.send(())?;
            self.release
                .lock()
                .map_err(|_| anyhow::anyhow!("fixture gate poisoned"))?
                .recv()?;
            Ok(ready)
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
            self.inner
                .validate(binding, management, actor, subject, ready, now)
        }
    }

    #[test]
    fn provider_pause_rehash_and_expiry_refuse_actual_business_commit() -> Result<()> {
        for action in [0_u8, 1, 2] {
            let hooks = super::super::simulation::World::new(23);
            super::super::effects::scope(hooks.clone(), || -> Result<()> {
                let (directory, runtime, simulation) = deterministic_world(23)?;
                confirmed(&runtime, "credential_metadata.create_client", "paused")?;
                let db = open(runtime.db())?;
                let old = load(&db, "paused")?.unwrap().commitment;
                let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
                let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
                let paused = runtime
                    .clone()
                    .with_credential_authority(std::sync::Arc::new(PausedAuthority {
                        inner: runtime.credentials.as_ref().unwrap().clone(),
                        entered: entered_tx,
                        release: std::sync::Mutex::new(release_rx),
                    }));
                let hooks = hooks.clone();
                let worker = std::thread::spawn(move || {
                    super::super::effects::scope(hooks, || paused.execute("paused", Fault::None))
                });
                let mutation = (|| -> Result<()> {
                    entered_rx.recv_timeout(std::time::Duration::from_secs(5))?;
                    if action == 2 {
                        let cutoff = load(&db, "paused")?.unwrap().confirmation.expires_at;
                        simulation.set_time(
                            cutoff.checked_mul(1000).context("fixture clock overflow")?,
                        )?;
                    } else if action == 1 {
                        let raw: String = db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='paused'", [], |row| row.get(0))?;
                        let mut changed: Value = crate::json::decode(raw.as_bytes())?;
                        changed["confirmation"]["session"] = "changed-valid-session".into();
                        rehash_fixture_value(&mut changed)?;
                        db.execute("UPDATE day2_credential_confirmations SET confirmation=?1 WHERE invocation='paused'", [changed.to_string()])?;
                        ensure!(
                            load(&db, "paused")?.unwrap().commitment != old,
                            "fixture replacement was not self-consistent and different"
                        );
                    }
                    Ok(())
                })();
                let release = release_tx.send(());
                let joined = worker.join();
                let result = (|| -> Result<()> {
                    mutation?;
                    release?;
                    let outcome =
                        joined.map_err(|_| anyhow::anyhow!("fixture executor panicked"))?;
                    if action == 0 {
                        ensure!(
                            outcome?.status == "success",
                            "unchanged paused command did not succeed"
                        );
                        ensure!(
                            counts(&runtime)? == (1, 1),
                            "unchanged command model counts differ"
                        );
                    } else {
                        let expected = if action == 1 {
                            "prepared credential confirmation changed"
                        } else {
                            "credential confirmation expired or authority changed"
                        };
                        match outcome {
                            Err(error) => ensure!(
                                format!("{error:#}").contains(expected),
                                "unrelated executor refusal"
                            ),
                            Ok(outcome) => {
                                ensure!(outcome.status == "failure", "changed command succeeded");
                                let trace = runtime.trace("paused")?;
                                ensure!(
                                    trace
                                        .request
                                        .observations
                                        .iter()
                                        .any(|entry| entry.error == expected),
                                    "expected fence refusal absent from actual trace"
                                );
                            }
                        }
                        ensure!(
                            counts(&runtime)? == (0, 0),
                            "refused command committed product or lineage"
                        );
                        ensure!(
                            db.query_row(
                                "SELECT count(*) FROM day2_credential_receipts",
                                [],
                                |row| row.get::<_, i64>(0)
                            )? == 0,
                            "refused command committed credential receipt"
                        );
                    }
                    Ok(())
                })();
                if result.is_err() {
                    use std::io::Write;
                    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                    // Keep original state before any fallible encoding or write.
                    let path = directory.keep();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                    let evidence = serde_json::to_vec(&serde_json::json!({
                        "seed":23,"schedule":["actual_prepare","provider_ready_ack",action,"release","writer"],
                        "artifact":runtime.artifact().id(),"source":Digest::new(include_bytes!("issuance.rs")),
                        "toolchain":Digest::new(include_bytes!("../../../../toolchain.json")),
                        "trace":runtime.trace("paused").ok(),"first_commitment":old,
                        "outcome":"model_or_exact_fence_refusal_diverged; original database retained",
                    }))?;
                    ensure!(
                        evidence.len() <= 1_048_576,
                        "counterexample evidence budget"
                    );
                    let mut file = std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(path.join("confirmation-counterexample.json"))?;
                    file.write_all(&evidence)?;
                    file.sync_all()?;
                    eprintln!("private confirmation counterexample: {}", path.display());
                }
                result
            })?;
        }
        Ok(())
    }

    #[test]
    fn captured_fence_is_required_even_without_a_lifecycle_observation() -> Result<()> {
        let hooks = super::super::simulation::World::new(36);
        super::super::effects::scope(hooks, || -> Result<()> {
            let (_directory, runtime, _simulation) = deterministic_world(36)?;
            confirmed(
                &runtime,
                "credential_metadata.create_client",
                "empty-observations",
            )?;
            let prepared = runtime
                .prepare_credential_keys("empty-observations")?
                .unwrap();
            let mut db = open(runtime.db())?;
            let tx = crate::write_queue::immediate(&mut db)?;
            let request = protocol::Request {
                operation: "credential_metadata.create_client".into(),
                input: serde_json::json!({"label":"Transcription client"}).to_string(),
                context: crate::store::invocation_context(&tx, "empty-observations")?,
                observations: Vec::new(),
            };
            assert!(validate_commit(&tx, &runtime, &request, None).is_err());
            validate_commit(&tx, &runtime, &request, Some(&prepared))?;
            let raw: String = tx.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='empty-observations'", [], |row| row.get(0))?;
            let mut changed: Value = crate::json::decode(raw.as_bytes())?;
            changed["confirmation"]["session"] = "changed-valid-session".into();
            rehash_fixture_value(&mut changed)?;
            tx.execute("UPDATE day2_credential_confirmations SET confirmation=?1 WHERE invocation='empty-observations'", [changed.to_string()])?;
            assert!(load(&tx, "empty-observations")?.is_some());
            assert!(validate_commit(&tx, &runtime, &request, Some(&prepared)).is_err());
            tx.rollback()?;
            assert_eq!(counts(&runtime)?, (0, 0));
            Ok(())
        })
    }

    #[test]
    fn two_real_executors_reuse_one_record_and_one_business_transition() -> Result<()> {
        let hooks = super::super::simulation::World::new(31);
        super::super::effects::scope(hooks.clone(), || -> Result<()> {
            let (directory, runtime, _simulation) = deterministic_world(31)?;
            confirmed(
                &runtime,
                "credential_metadata.create_client",
                "two-executors",
            )?;
            let db = open(runtime.db())?;
            let before: String = db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='two-executors'", [], |row| row.get(0))?;
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let workers: Vec<_> = (0..2)
                .map(|_| {
                    let runtime = runtime.clone();
                    let barrier = barrier.clone();
                    let hooks = hooks.clone();
                    std::thread::spawn(move || {
                        super::super::effects::scope(hooks, || {
                            barrier.wait();
                            runtime.execute("two-executors", Fault::None)
                        })
                    })
                })
                .collect();
            let joined: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
            let result = (|| -> Result<()> {
                let outcomes = joined
                    .into_iter()
                    .map(|result| {
                        result.map_err(|_| anyhow::anyhow!("fixture executor panicked"))?
                    })
                    .collect::<Result<Vec<_>>>()?;
                ensure!(
                    outcomes[0].status == "success" && outcomes[0] == outcomes[1],
                    "two executors returned different outcomes"
                );
                ensure!(
                    counts(&runtime)? == (1, 1),
                    "two executors duplicated or lost product/lineage"
                );
                ensure!(
                    db.query_row("SELECT count(*) FROM day2_credential_receipts", [], |row| {
                        row.get::<_, i64>(0)
                    })? == 1,
                    "two executors duplicated or lost credential receipt"
                );
                ensure!(db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='two-executors'", [], |row| row.get::<_, String>(0))? == before,
                "two executors replaced original approval");
                replay(runtime.artifact(), &runtime.trace("two-executors")?)?;
                Ok(())
            })();
            if result.is_err() {
                use std::io::Write;
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let path = directory.keep();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                let evidence = serde_json::to_vec(&serde_json::json!({
                    "seed":31,"schedule":["both_executors_ready","release_shared_barrier","same_invocation"],
                    "artifact":runtime.artifact().id(),"source":Digest::new(include_bytes!("issuance.rs")),
                    "toolchain":Digest::new(include_bytes!("../../../../toolchain.json")),
                    "trace":runtime.trace("two-executors").ok(),
                    "outcome":"first-winner model diverged; original database retained",
                }))?;
                ensure!(
                    evidence.len() <= 1_048_576,
                    "counterexample evidence budget"
                );
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path.join("two-executor-counterexample.json"))?;
                file.write_all(&evidence)?;
                file.sync_all()?;
                eprintln!("private two-executor counterexample: {}", path.display());
            }
            result
        })
    }

    #[test]
    fn compiled_worker_reply_corruption_rolls_back_exact_staging_and_recovers() -> Result<()> {
        let hooks = super::super::simulation::World::new(37);
        super::super::effects::scope(hooks, || -> Result<()> {
            let (directory, runtime, _simulation) = deterministic_world(37)?;
            confirmed(
                &runtime,
                "credential_metadata.create_client",
                "corrupted-target",
            )?;
            confirmed(&runtime, "credential_metadata.create_client", "unrelated")?;
            let db = open(runtime.db())?;
            let original: String = db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='corrupted-target'", [], |row| row.get(0))?;
            let actual_counts = || -> Result<[i64; 7]> {
                let mut counts = [0; 7];
                for (slot, table) in [
                    "entries",
                    "key_receipts",
                    "day2_credential_lineages",
                    "day2_credential_versions",
                    "day2_credential_material",
                    "day2_credential_deliveries",
                    "day2_credential_receipts",
                ]
                .into_iter()
                .enumerate()
                {
                    counts[slot] =
                        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                            row.get(0)
                        })?;
                }
                Ok(counts)
            };
            let mut evidence = None;
            let result = (|| -> Result<()> {
                let fault =
                    crate::store::credential_reply_test_fault::effects_after_credential_mutation(
                        &runtime,
                        "corrupted-target",
                    )?;
                ensure!(
                    crate::store::credential_reply_test_fault::effects_after_credential_mutation(
                        &runtime,
                        "corrupted-target"
                    )
                    .is_err(),
                    "overlapping reply-fault scope accepted"
                );
                ensure!(
                    runtime.execute("unrelated", Fault::None)?.status == "success",
                    "unrelated invocation was corrupted"
                );
                ensure!(
                    fault.observed().is_none(),
                    "reply-fault selector crossed invocation"
                );
                let baseline = actual_counts()?;
                ensure!(
                    baseline == [1; 7],
                    "unrelated actual command baseline differs"
                );
                let execution = runtime.execute("corrupted-target", Fault::None);
                evidence = fault.observed();
                let refusal = execution
                    .err()
                    .context("corrupted worker reply reached commit")?;
                ensure!(
                    refusal.to_string()
                        == "interactive credential commands permit only local transactions",
                    "unrelated worker/runtime failure masked rollback oracle"
                );
                let staged = evidence.as_ref().context(
                    "reply corruption did not follow actual expected worker continuation",
                )?;
                ensure!(
                    staged.original_kind == "pending"
                        && staged.original_instruction == "create"
                        && staged.original_model == "key_receipts"
                        && staged.consumed == staged.observations.len(),
                    "original successful compiled-worker continuation was not captured"
                );
                ensure!(
                    staged.counts == [2, 1, 2, 2, 2, 2, 2],
                    "real credential and product staging was not reached"
                );
                ensure!(
                    staged
                        .observations
                        .iter()
                        .any(|(kind, _)| kind == "credential_issue")
                        && staged
                            .observations
                            .iter()
                            .any(|(kind, model)| kind == "create" && model == "entries"),
                    "actual successful lifecycle/product observations absent"
                );
                ensure!(
                    actual_counts()? == baseline,
                    "refused Effects reply retained staged rows"
                );
                let pending: (String, Option<String>) = db.query_row(
                    "SELECT status,outcome FROM day2_invocations WHERE id='corrupted-target'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                ensure!(
                    pending == ("pending".into(), None),
                    "refused Effects reply published a completion"
                );
                ensure!(
                    db.query_row(
                        "SELECT count(*) FROM day2_execution WHERE invocation='corrupted-target'",
                        [],
                        |row| row.get::<_, i64>(0)
                    )? == 0,
                    "refused Effects reply published a continuation"
                );
                drop(fault);
                let recovered = runtime.execute("corrupted-target", Fault::None)?;
                ensure!(
                    recovered.status == "success"
                        && runtime.execute("corrupted-target", Fault::None)? == recovered,
                    "original invocation did not recover exactly once after fault scope dropped"
                );
                ensure!(
                    actual_counts()? == [2; 7],
                    "recovery duplicated or lost actual business transition"
                );
                ensure!(db.query_row("SELECT confirmation FROM day2_credential_confirmations WHERE invocation='corrupted-target'", [], |row| row.get::<_, String>(0))? == original,
                    "response corruption or recovery renewed original approval");
                replay(runtime.artifact(), &runtime.trace("corrupted-target")?)?;
                Ok(())
            })();
            if result.is_err() {
                use std::io::Write;
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let path = directory.keep();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "seed":37,"artifact":runtime.artifact().id(),
                    "schedule":["unrelated_actual_success","actual_target_credential_and_entries","real_pending_key_receipts","corrupt_effects_reply","rollback","drop_scope","recover"],
                    "staging_data":evidence,"trace":runtime.trace("corrupted-target").ok(),
                    "source":Digest::new(include_bytes!("issuance.rs")),
                    "host_source":Digest::new(include_bytes!("../store.rs")),
                    "toolchain":Digest::new(include_bytes!("../../../../toolchain.json")),
                    "meaning":"actual compiled-worker RESPONSE-CORRUPTION; not malicious binary admission; original SQLite retained",
                }))?;
                ensure!(bytes.len() <= 1_048_576, "reply-corruption evidence budget");
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path.join("reply-corruption-counterexample.json"))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                eprintln!(
                    "private reply-corruption counterexample: {}",
                    path.display()
                );
            }
            result
        })
    }

    #[test]
    fn native_lifecycle_is_atomic_terminal_and_recovers_after_reopen() -> Result<()> {
        for kind in ["client", "personal"] {
            let (_directory, runtime) = world()?;
            let simulation = crate::simulation::Simulation::new(runtime, [21; 32], 1_000_000)?;
            let runtime = simulation.runtime();
            confirmed(
                runtime,
                &format!("credential_metadata.create_{kind}"),
                "issued",
            )?;
            let issued = runtime.execute("issued", Fault::None)?;
            assert_eq!(issued.status, "success", "{issued:?}");
            let db = open(runtime.db())?;
            let original: (String, String) = db.query_row(
                "SELECT principal,grant_digest FROM day2_credential_lineages",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let expected = serde_json::json!({"lineage":issued.result["lineage"],"head":issued.result["version"],"revision":1});
            let rotate = format!("credential_metadata.rotate_{kind}");
            // An expired bearer can rotate while its independent frozen grant remains valid.
            simulation.set_time(4_601_000)?;
            confirm_input(runtime, &rotate, "rotate", &expected)?;
            confirm_input(runtime, &rotate, "stale", &expected)?;
            assert!(runtime.execute("rotate", Fault::BeforeCommit).is_err());
            assert_eq!(
                db.query_row("SELECT count(*) FROM day2_credential_versions", [], |row| {
                    row.get::<_, i64>(0)
                })?,
                1
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM key_receipts", [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
            let rotated = runtime.execute("rotate", Fault::None)?;
            assert_eq!(rotated.status, "success", "{rotated:?}");
            assert_eq!(rotated.result["status"], "rotated");
            assert_eq!(rotated.result["lineage"], issued.result["lineage"]);
            assert_ne!(rotated.result["version"], issued.result["version"]);
            let retained: (String, String) = db.query_row(
                "SELECT principal,grant_digest FROM day2_credential_lineages",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(original, retained);
            let stale = runtime.execute("stale", Fault::None)?;
            assert_eq!(stale.result["status"], "conflict");
            assert_eq!(
                db.query_row("SELECT count(*) FROM day2_credential_versions", [], |row| {
                    row.get::<_, i64>(0)
                })?,
                2
            );
            let next = serde_json::json!({"lineage":rotated.result["lineage"],"head":rotated.result["version"],"revision":2});
            confirm_input(runtime, &rotate, "lost-rotation", &next)?;
            assert!(
                runtime
                    .execute("lost-rotation", Fault::AfterCommit)
                    .is_err()
            );
            let reopened = Runtime::load(runtime.instance_path(), runtime.app())?
                .with_integrations(crate::integration_host::Host::simulated(
                    runtime.db(),
                    runtime.scope(),
                ))
                .with_credential_authority(runtime.credentials.as_ref().unwrap().clone());
            let recovered = reopened.execute("lost-rotation", Fault::None)?;
            assert_eq!(recovered.result["status"], "rotated");
            assert_eq!(reopened.execute("lost-rotation", Fault::None)?, recovered);
            assert_eq!(
                db.query_row("SELECT count(*) FROM day2_credential_versions", [], |row| {
                    row.get::<_, i64>(0)
                })?,
                3
            );
            let revoke = format!("credential_metadata.revoke_{kind}");
            let target = serde_json::json!({"lineage":issued.result["lineage"]});
            confirm_input(runtime, &revoke, "revoke", &target)?;
            assert!(runtime.execute("revoke", Fault::BeforeCommit).is_err());
            assert_eq!(
                db.query_row("SELECT state FROM day2_credential_lineages", [], |row| {
                    row.get::<_, String>(0)
                })?,
                "active"
            );
            assert!(runtime.execute("revoke", Fault::AfterCommit).is_err());
            let revoked = reopened.execute("revoke", Fault::None)?;
            assert_eq!(revoked.result["status"], "revoked");
            assert_eq!(reopened.execute("revoke", Fault::None)?, revoked);
            confirm_input(runtime, &revoke, "revoke-again", &target)?;
            let repeated = runtime.execute("revoke-again", Fault::None)?;
            assert_eq!(repeated.result["status"], "already_revoked");
            assert_eq!(repeated.result["revision"], revoked.result["revision"]);
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM day2_credential_versions WHERE state!='revoked'",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM day2_credential_deliveries WHERE state!='closed'",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                0
            );
            let terminal = serde_json::json!({"lineage":recovered.result["lineage"],"head":recovered.result["version"],"revision":3});
            confirm_input(runtime, &rotate, "terminal", &terminal)?;
            assert_eq!(
                runtime.execute("terminal", Fault::None)?.result["status"],
                "conflict"
            );
            for id in [
                "rotate",
                "stale",
                "lost-rotation",
                "revoke",
                "revoke-again",
                "terminal",
            ] {
                let trace = runtime.trace(id)?;
                replay(runtime.artifact(), &trace)?;
                let raw = serde_json::to_string(&trace)?;
                for private in [
                    "d2c1.",
                    "ciphertext",
                    "security_epoch",
                    "verifier_key",
                    "session",
                ] {
                    assert!(!raw.contains(private));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_lifecycle_rejects_changed_target_and_personal_subject() -> Result<()> {
        let (_directory, runtime) = world()?;
        confirmed(&runtime, "credential_metadata.create_personal", "issued")?;
        let issued = runtime.execute("issued", Fault::None)?;
        let operation = "credential_metadata.rotate_personal";
        let input = serde_json::json!({"lineage":issued.result["lineage"],"head":issued.result["version"],"revision":1});
        confirm_input(&runtime, operation, "hostile", &input)?;
        let ready = runtime.prepare_credential_keys("hostile")?.unwrap();
        let mut db = open(runtime.db())?;
        let tx = db.transaction()?;
        let request = protocol::Request {
            operation: operation.into(),
            input: input.to_string(),
            context: crate::store::invocation_context(&tx, "hostile")?,
            observations: Vec::new(),
        };
        let proof = load(&tx, "hostile")?.unwrap().confirmation;
        let original: String = tx.query_row(
            "SELECT principal FROM day2_credential_lineages",
            [],
            |row| row.get(0),
        )?;
        let mut wire = proof.intent.instruction("personal", "hostile");
        wire["head"] = "changed".into();
        let mut instruction = protocol::Instruction {
            kind: "credential_rotate".into(),
            model: crate::credential_codegen::ROTATE.into(),
            data: wire.to_string(),
            ..Default::default()
        };
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        instruction.data = proof.intent.instruction("clients", "hostile").to_string();
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        instruction.data = proof.intent.instruction("personal", "hostile").to_string();
        tx.execute(
            "UPDATE day2_credential_lineages SET principal='another-human'",
            [],
        )?;
        assert!(stage(&tx, &runtime, &request, &instruction, &ready).is_err());
        tx.execute(
            "UPDATE day2_credential_lineages SET principal=?1",
            [&original],
        )?;
        let public = stage(&tx, &runtime, &request, &instruction, &ready)?;
        let mut repeated = request.clone();
        repeated.observations.push(protocol::Observation {
            instruction: instruction.clone(),
            result: public,
            error: String::new(),
        });
        assert!(stage(&tx, &runtime, &repeated, &instruction, &ready).is_err());
        tx.rollback()?;
        assert_eq!(counts(&runtime)?, (1, 1));
        Ok(())
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
        // Exercise the actual staged credential and product rows under the
        // same writer before the real host phase guard refuses Effects. This
        // is host/SQLite conformance, not a compiled hostile-worker claim.
        let public: Value = crate::json::decode(request.observations[0].result.as_bytes())?;
        let product = protocol::Instruction {
            kind: "create".into(),
            model: "entries".into(),
            data: serde_json::json!({"note":public["lineage"]}).to_string(),
            ..Default::default()
        };
        let active = authority_state::require_invocation_in(
            &tx,
            &runtime,
            "hostile",
            &request.operation,
            &request.context.actor,
        )?;
        let empty_domains = crate::domain::Catalog::new();
        let domains = runtime
            .artifact()
            .contract()
            .app_contract
            .as_ref()
            .map(|contract| &contract.domains)
            .unwrap_or(&empty_domains);
        crate::store::effect(
            &tx,
            crate::store::StorageContract {
                schema: &runtime.artifact().contract().schema,
                domains,
            },
            runtime.scope(),
            &request,
            &product,
            crate::store::EffectContext {
                scope: runtime.scope(),
                policy: active.policy()?,
                operation: &request.operation,
                entropy: runtime.inputs().entropy.as_ref(),
            },
        )?;
        for table in [
            "entries",
            "day2_credential_lineages",
            "day2_credential_versions",
            "day2_credential_receipts",
        ] {
            assert_eq!(
                tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
        }
        let effects = protocol::Instruction {
            kind: "effects".into(),
            ..Default::default()
        };
        let refusal = crate::credential_authority::check_step(
            runtime.artifact().contract(),
            &request.operation,
            effects.decode()?,
        )
        .unwrap_err();
        assert_eq!(
            refusal.to_string(),
            "interactive credential commands permit only local transactions"
        );
        tx.rollback()?;
        assert_eq!(counts(&runtime)?, (0, 0));
        for table in [
            "day2_credential_versions",
            "day2_credential_receipts",
            "day2_credential_deliveries",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
                0
            );
        }
        assert_eq!(
            db.query_row(
                "SELECT status FROM day2_invocations WHERE id='hostile'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "pending"
        );
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
