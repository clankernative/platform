//! Host-owned selection and invocation-affine references for product reads.
use super::profiles;
use crate::managed_credentials::crypto::KeyLease;
use anyhow::Result;
use day2_capabilities::{
    Digest,
    oauth::{ConnectionRequirement, OutboundConnectionBinding, ProviderPermissionContract},
};

#[derive(Clone)]
pub(crate) struct Selection {
    pub requirement: ConnectionRequirement,
    pub permission: ProviderPermissionContract,
    pub reviewed: profiles::ReviewedBrowserCodeProfile,
    pub binding: OutboundConnectionBinding,
    pub instance: profiles::OutboundInstanceEvidence,
    pub slot: Digest,
}

impl Selection {
    pub(super) fn identity(&self) -> Result<Digest> {
        Digest::of(&(
            "oauth-product-use-selection-v1",
            &self.requirement,
            &self.permission,
            &self.binding,
            &self.instance,
            &self.slot,
        ))
    }
}

/// Available only to the native serving composition. Worker instructions and
/// instance JSON cannot supply an authority implementation or key lease.
pub(crate) trait Authority: Send + Sync {
    fn current(
        &self,
        app: &str,
        registration: &str,
        owner: &str,
        now: i64,
    ) -> Result<Option<Selection>>;
    fn custody(
        &self,
        app: &str,
        registration: &str,
        owner: &str,
        expected: &Digest,
        now: i64,
    ) -> Result<Option<KeyLease>>;
    fn refresh_client(
        &self,
        app: &str,
        registration: &str,
        owner: &str,
        expected: &Digest,
        now: i64,
    ) -> Result<Option<super::refresh::ClientCredential>>;
    fn with_current(
        &self,
        app: &str,
        registration: &str,
        owner: &str,
        now: i64,
        commit: &mut dyn FnMut(&Selection) -> Result<bool>,
    ) -> Result<bool>;
}

use crate::{
    authority_state::AuthorityStamp,
    protocol::{Instruction, Observation, Request},
    store::{self, Runtime},
};
use anyhow::{Context as _, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const HANDLE_SECONDS: i64 = 60;
const MAX_HANDLES: i64 = 128;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Claims {
    invocation: String,
    operation: String,
    actor: String,
    subject: String,
    scope: String,
    artifact: String,
    authority: AuthorityStamp,
    registration: String,
    requirement: Digest,
    selection: Digest,
    slot: String,
    generation: i64,
    token_version: i64,
    security_epoch: i64,
    profile: String,
    account: String,
    affinity: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveInput {
    registration: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    registration: String,
    reference: String,
    window: super::calendar::Window,
}

pub(crate) fn observation(name: &str) -> bool {
    [
        crate::connection_codegen::RESOLVE,
        crate::connection_codegen::LIST_EVENTS,
    ]
    .contains(&name)
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    super::connect::install_schema(db)?;
    super::schema::install_current(db, "oauth_use_schema_version", 1,
        "CREATE TABLE IF NOT EXISTS oauth_use_schema_version(version INTEGER PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS oauth_use_handles(
             reference TEXT PRIMARY KEY, invocation TEXT NOT NULL REFERENCES day2_invocations(id),
             claims TEXT NOT NULL CHECK(length(claims) <= 8192 AND json_valid(claims))
         );",
        &[super::schema::Invariant { table: "oauth_use_handles", predicate:
            "length(reference) BETWEEN 40 AND 64 AND length(invocation) > 0 AND
             length(claims) BETWEEN 1 AND 8192 AND json_valid(claims) AND json_type(claims) = 'object'" }],
    )
}

/// Consult the same sealed durable-origin records used by app delegation.
/// Actor text, local sign-in and workload identity cannot establish a human.
fn human(db: &Connection, runtime: &Runtime, request: &Request) -> Result<Option<String>> {
    ensure!(
        store::invocation_context(db, &request.context.invocation_id)? == request.context,
        "connection invocation origin changed"
    );
    let root = crate::resources::root_in(db, &request.context.invocation_id)?;
    let subject: Option<String> = db
        .query_row(
            "SELECT subject FROM day2_principals WHERE email=?1",
            [&request.context.actor],
            |row| row.get(0),
        )
        .optional()?;
    let Some(subject) = subject else {
        return Ok(None);
    };
    let inherited: Option<String> = db
        .query_row(
            "SELECT evidence FROM day2_inherited_origins WHERE invocation=?1",
            [&root],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(inherited) = inherited {
        let origin: crate::delegation_commands::InheritedOrigin =
            crate::json::decode(inherited.as_bytes())?;
        if origin.actor == request.context.actor
            && origin.principal == request.context.actor
            && origin.subject_digest == crate::digest(subject.as_bytes())
            && !request.context.caller.is_empty()
        {
            return Ok(Some(subject));
        }
        return Ok(None);
    }
    let matches: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_invocations i JOIN day2_invocation_origins o ON o.invocation=i.id
         WHERE i.id=?1 AND i.actor=?2 AND i.trigger='request' AND i.authenticated='' AND i.caller=''
           AND o.kind='iap' AND o.principal=?2 AND o.subject=?3)",
        params![root, request.context.actor, subject], |row| row.get(0),
    )?;
    let _ = runtime;
    Ok(matches.then_some(subject))
}

fn declaration<'a>(runtime: &'a Runtime, registration: &str) -> Result<&'a ConnectionRequirement> {
    runtime
        .artifact()
        .contract()
        .connection_declarations
        .iter()
        .find(|entry| entry.registration.as_str() == registration)
        .map(|entry| &entry.requirement)
        .context("undeclared connection requirement")
}

fn unavailable(problem: &str) -> String {
    json!({"Unavailable": problem}).to_string()
}

fn require_action(
    db: &Connection,
    runtime: &Runtime,
    request: &Request,
    action: &str,
) -> Result<()> {
    let active = crate::authority_state::require_invocation_in(
        db,
        runtime,
        &request.context.invocation_id,
        &request.operation,
        &request.context.actor,
    )?;
    let operation = runtime.artifact().route(&request.operation)?;
    ensure!(
        active
            .policy()?
            .operations
            .get(&operation.name)
            .is_some_and(|permissions| permissions.observations.contains(action)),
        crate::error::Failure::CapabilityForbidden
    );
    Ok(())
}

fn capture(
    db: &Connection,
    selection: &Selection,
    request: &Request,
    runtime: &Runtime,
    registration: &str,
    subject: String,
    now: i64,
) -> Result<Option<Claims>> {
    let row: Option<(i64, i64, i64, String, String, String, String)> = db.query_row(
        "SELECT generation,token_version,security_epoch,profile,account,affinity,status FROM oauth_connection_slots WHERE slot=?1",
        [selection.slot.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    ).optional()?;
    let Some((generation, token_version, security_epoch, profile, account, affinity, status)) = row
    else {
        return Ok(None);
    };
    ensure!(
        status == "active" && token_version > 0,
        "connection reauthorization required"
    );
    let authority = crate::authority_state::require_invocation_in(
        db,
        runtime,
        &request.context.invocation_id,
        &request.operation,
        &request.context.actor,
    )?
    .stamp;
    ensure!(
        declaration(runtime, registration)? == &selection.requirement,
        "selected connection requirement changed"
    );
    let claims = Claims {
        invocation: request.context.invocation_id.clone(),
        operation: request.operation.clone(),
        actor: request.context.actor.clone(),
        subject,
        scope: runtime.scope().into(),
        artifact: runtime.artifact().id().into(),
        authority,
        registration: registration.into(),
        requirement: selection.requirement.nominal_identity()?,
        selection: selection.identity()?,
        slot: selection.slot.as_str().into(),
        generation,
        token_version,
        security_epoch,
        profile,
        account,
        affinity,
        issued_at: now,
        expires_at: now
            .checked_add(HANDLE_SECONDS)
            .context("connection use deadline overflow")?,
    };
    activation(db, &claims, selection)?;
    Ok(Some(claims))
}

fn activation(
    db: &Connection,
    claims: &Claims,
    selection: &Selection,
) -> Result<(
    super::connect::ConnectIntent,
    super::exchange::ExchangeBinding,
)> {
    let count: i64 = db.query_row("SELECT count(*) FROM oauth_connect_attempts WHERE slot=?1 AND proposed_generation=?2 AND state='activated' AND account=?3", params![claims.slot, claims.generation, claims.account], |row| row.get(0))?;
    ensure!(
        count == 1 && claims.token_version > 0,
        "exact OAuth activation material missing"
    );
    let (intent, callback): (super::connect::ConnectIntent, String) = db.query_row(
        "SELECT a.attempt,a.expected_generation,a.expected_epoch,a.owner,a.profile,a.registration,a.callback,a.consent,a.expires_at,b.binding
         FROM oauth_connect_attempts a JOIN oauth_callback_bindings b ON b.attempt=a.attempt
         WHERE a.slot=?1 AND a.proposed_generation=?2 AND a.state='activated' AND a.account=?3",
        params![claims.slot, claims.generation, claims.account],
        |row| Ok((super::connect::ConnectIntent {
            attempt: row.get(0)?, slot: claims.slot.clone(), expected_generation: row.get(1)?, expected_epoch: row.get(2)?,
            proposed_generation: claims.generation, owner: row.get(3)?, profile: row.get(4)?, registration: row.get(5)?,
            callback: row.get(6)?, consent: row.get(7)?, expires_at: row.get(8)?,
        }, row.get(9)?)),
    )?;
    ensure!(
        intent.owner == claims.actor
            && intent.expected_epoch == claims.security_epoch
            && intent.profile == claims.profile,
        "OAuth activated owner or epoch changed"
    );
    let callback = crate::json::decode(callback.as_bytes())?;
    let qualified = super::profiles::OutboundQualification {
        intent: &intent,
        binding: &callback,
        requirement: &selection.requirement,
        permission: &selection.permission,
        reviewed: &selection.reviewed,
        instance: &selection.instance,
    };
    super::profiles::qualify_outbound_connect(
        &intent,
        &callback,
        &selection.requirement,
        &selection.permission,
        &selection.reviewed,
        &selection.instance,
    )?;
    let binding = super::exchange::load_binding(db, &intent.attempt)?
        .context("exact activated exchange binding missing")?;
    ensure!(
        binding.matches_current(&qualified)?,
        "activated exchange binding changed"
    );
    Ok((intent, binding))
}

/// Derived from durable human acceptance and current local authority. Neither
/// worker data nor instance JSON can construct the private refresh settlement pin.
pub(super) struct RefreshContext {
    intent: super::connect::ConnectIntent,
    binding: super::exchange::ExchangeBinding,
    eligibility: super::store::RefreshEligibility,
    pin: Digest,
}

impl RefreshContext {
    pub(super) fn intent(&self) -> &super::connect::ConnectIntent {
        &self.intent
    }
    pub(super) fn binding(&self) -> &super::exchange::ExchangeBinding {
        &self.binding
    }
    pub(super) fn eligibility(&self) -> &super::store::RefreshEligibility {
        &self.eligibility
    }
    pub(super) fn pin(&self) -> &Digest {
        &self.pin
    }
}

pub(super) fn refresh_context(
    db: &Connection,
    runtime: &Runtime,
    request: &Request,
    registration: &str,
    subject: &str,
    selection: &Selection,
    now: i64,
) -> Result<Option<RefreshContext>> {
    runtime.check_binding(db)?;
    require_action(db, runtime, request, crate::connection_codegen::RESOLVE)?;
    ensure!(
        human(db, runtime, request)?.as_deref() == Some(subject),
        "refresh human changed"
    );
    let Some(claims) = capture(
        db,
        selection,
        request,
        runtime,
        registration,
        subject.to_owned(),
        now,
    )?
    else {
        return Ok(None);
    };
    let (intent, binding) = activation(db, &claims, selection)?;
    let eligibility = super::store::RefreshEligibility {
        slot: claims.slot,
        generation: claims.generation,
        base_version: claims.token_version,
        security_epoch: claims.security_epoch,
        profile: claims.profile,
        account: claims.account,
        affinity: claims.affinity,
    };
    let pin = Digest::of(&(
        "oauth-current-refresh-authority-v1",
        &claims.invocation,
        &claims.operation,
        &claims.actor,
        &claims.subject,
        &claims.scope,
        &claims.artifact,
        &claims.authority,
        &claims.registration,
        &claims.requirement,
        &claims.selection,
        &eligibility,
    ))?;
    Ok(Some(RefreshContext {
        intent,
        binding,
        eligibility,
        pin,
    }))
}

fn load(
    db: &Connection,
    runtime: &Runtime,
    request: &Request,
    registration: &str,
    reference: &str,
    now: i64,
) -> Result<Claims> {
    ensure!(
        reference.starts_with("cu1_") && reference.len() <= 64,
        "invalid connection use reference"
    );
    let encoded: String = db.query_row(
        "SELECT claims FROM oauth_use_handles WHERE reference=?1 AND invocation=?2",
        params![reference, request.context.invocation_id],
        |row| row.get(0),
    )?;
    ensure!(encoded.len() <= 8192, "connection use byte budget");
    let claims: Claims = crate::json::decode(encoded.as_bytes())?;
    let active = crate::authority_state::require_invocation_in(
        db,
        runtime,
        &request.context.invocation_id,
        &request.operation,
        &request.context.actor,
    )?;
    ensure!(
        claims.invocation == request.context.invocation_id
            && claims.operation == request.operation
            && claims.actor == request.context.actor
            && claims.scope == runtime.scope()
            && claims.artifact == runtime.artifact().id()
            && claims.registration == registration
            && claims.authority == active.stamp
            && claims.requirement == declaration(runtime, registration)?.nominal_identity()?
            && human(db, runtime, request)?.as_deref() == Some(claims.subject.as_str())
            && now >= claims.issued_at
            && now < claims.expires_at
            && claims
                .expires_at
                .checked_sub(claims.issued_at)
                .is_some_and(|duration| duration > 0 && duration <= HANDLE_SECONDS),
        "connection use authority or invocation changed"
    );
    let matches: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM oauth_connection_slots WHERE slot=?1 AND generation=?2 AND token_version=?3
         AND security_epoch=?4 AND profile=?5 AND account=?6 AND affinity=?7 AND status='active'
         AND NOT EXISTS(SELECT 1 FROM oauth_refresh_attempts r WHERE r.slot=?1 AND r.generation=?2 AND r.base_version=?3
             AND r.state IN ('ready','may_have_been_sent','uncertain')))",
        params![claims.slot, claims.generation, claims.token_version, claims.security_epoch, claims.profile, claims.account, claims.affinity],
        |row| row.get(0),
    )?;
    ensure!(matches, "connection use generation or account changed");
    Ok(claims)
}

fn resolve(
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
    serving: &mut super::native_management::RuntimeConsumer<'_, '_>,
) -> Result<String> {
    let input: ResolveInput = crate::json::decode(instruction.data.as_bytes())?;
    let requirement = declaration(runtime, &input.registration)?;
    ensure!(
        requirement.owner == day2_capabilities::oauth::ConnectionOwner::CurrentHuman,
        "unsupported connection owner"
    );
    let mut db = store::open(runtime.db())?;
    let snapshot = db.transaction()?;
    runtime.check_binding(&snapshot)?;
    require_action(
        &snapshot,
        runtime,
        request,
        crate::connection_codegen::RESOLVE,
    )?;
    let subject = human(&snapshot, runtime, request)?;
    serving.commit(snapshot)?;
    let Some(subject) = subject else {
        return Ok(unavailable("PermissionDenied"));
    };
    let Some(authority) = runtime.connections.as_deref() else {
        return Ok(unavailable("BindingUnavailable"));
    };
    let started = super::effects::wall_time()?;
    let Some(selection) = authority.current(
        runtime.app(),
        &input.registration,
        &request.context.actor,
        started,
    )?
    else {
        return Ok(unavailable("BindingUnavailable"));
    };
    let now = super::effects::wall_time()?;
    ensure!(
        now >= started && now - started <= 10,
        "connection readiness deadline exceeded"
    );
    let refresh = super::refresh::ensure_current(
        runtime,
        request,
        &input.registration,
        &subject,
        &selection,
        now,
        serving,
    )?;
    if let Some(problem) = refresh.problem() {
        return Ok(unavailable(problem));
    }
    let mut nonce = [0u8; 32];
    super::effects::fill(&mut nonce)?;
    use base64::Engine as _;
    let reference = format!(
        "cu1_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
    );
    let tx = crate::write_queue::immediate(&mut db)?;
    let now = super::effects::wall_time()?;
    if !refresh.validate(&tx, now)? {
        serving.commit(tx)?;
        return Ok(unavailable("ReauthRequired"));
    }
    runtime.check_binding(&tx)?;
    ensure!(
        human(&tx, runtime, request)?.as_deref() == Some(subject.as_str()),
        "connection human changed during readiness"
    );
    let pending: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM oauth_connect_attempts WHERE slot=?1 AND owner=?2 AND state='awaiting_account_approval')",
        params![selection.slot.as_str(), request.context.actor], |row| row.get(0),
    )?;
    let status: Option<String> = tx
        .query_row(
            "SELECT status FROM oauth_connection_slots WHERE slot=?1",
            [selection.slot.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if pending && status.as_deref() != Some("active") {
        return Ok(unavailable("AccountApprovalRequired"));
    }
    if status.as_deref() == Some("disabled") {
        return Ok(unavailable("NeedsConnection"));
    }
    let claims = match capture(
        &tx,
        &selection,
        request,
        runtime,
        &input.registration,
        subject,
        now,
    ) {
        Ok(Some(claims)) => claims,
        Ok(None) => return Ok(unavailable("NeedsConnection")),
        Err(_) => return Ok(unavailable("ReauthRequired")),
    };
    tx.execute("DELETE FROM oauth_use_handles WHERE json_extract(claims,'$.expires_at') <= ?1 OR invocation IN (SELECT id FROM day2_invocations WHERE status != 'pending')", [now])?;
    let count: i64 = tx.query_row("SELECT count(*) FROM oauth_use_handles", [], |row| {
        row.get(0)
    })?;
    if count >= MAX_HANDLES {
        return Ok(unavailable("CapacityDeferred"));
    }
    tx.execute(
        "INSERT INTO oauth_use_handles VALUES(?1,?2,?3)",
        params![
            reference,
            claims.invocation,
            serde_json::to_string(&claims)?
        ],
    )?;
    serving.commit(tx)?;
    Ok(json!({"Available": reference}).to_string())
}

pub(crate) fn execute(
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
) -> Result<String> {
    ensure!(
        instruction.kind == "observe",
        "connection read requires observation phase"
    );
    ensure!(
        [
            crate::connection_codegen::RESOLVE,
            crate::connection_codegen::LIST_EVENTS
        ]
        .contains(&instruction.model.as_str()),
        "unknown connection observation"
    );
    // Reject malformed DATA before acquiring any native operation scope.
    if instruction.model == crate::connection_codegen::RESOLVE {
        let _: ResolveInput = crate::json::decode(instruction.data.as_bytes())?;
    } else {
        let _: ReadInput = crate::json::decode(instruction.data.as_bytes())?;
    }
    let phase = if instruction.model == crate::connection_codegen::RESOLVE {
        super::native_management::RuntimePhase::Refresh
    } else {
        super::native_management::RuntimePhase::Read
    };
    super::native_management::with_runtime_consumer(runtime, phase, |serving| {
        execute_current(runtime, request, instruction, serving)
    })
}

fn execute_current(
    runtime: &Runtime,
    request: &Request,
    instruction: &Instruction,
    serving: &mut super::native_management::RuntimeConsumer<'_, '_>,
) -> Result<String> {
    ensure!(
        instruction.kind == "observe",
        "connection read requires observation phase"
    );
    if instruction.model == crate::connection_codegen::RESOLVE {
        return resolve(runtime, request, instruction, serving);
    }
    ensure!(
        instruction.model == crate::connection_codegen::LIST_EVENTS,
        "unknown connection observation"
    );
    let input: ReadInput = crate::json::decode(instruction.data.as_bytes())?;
    let started = super::effects::wall_time()?;
    let mut db = store::open(runtime.db())?;
    let snapshot = db.transaction()?;
    runtime.check_binding(&snapshot)?;
    require_action(
        &snapshot,
        runtime,
        request,
        crate::connection_codegen::LIST_EVENTS,
    )?;
    let mut claims = load(
        &snapshot,
        runtime,
        request,
        &input.registration,
        &input.reference,
        started,
    )?;
    serving.commit(snapshot)?;
    if !input.window.valid() {
        return Ok(json!("InvalidWindow").to_string());
    }
    let Some(authority) = runtime.connections.as_deref() else {
        return Ok(unavailable("BindingUnavailable"));
    };
    let Some(selection) =
        authority.current(runtime.app(), &input.registration, &claims.actor, started)?
    else {
        return Ok(unavailable("BindingUnavailable"));
    };
    ensure!(
        selection.identity()? == claims.selection
            && selection.requirement.capability == super::google::CAPABILITY
            && selection.requirement.actions.contains("list_events"),
        "connection provider action or selection changed"
    );
    let selected_at = super::effects::wall_time()?;
    if selected_at < started {
        let tx = crate::write_queue::immediate(&mut db)?;
        refuse(&tx, &claims)?;
        serving.commit(tx)?;
        return Ok(unavailable("ReauthRequired"));
    }
    serving.check()?;
    let Some(key) = authority.custody(
        runtime.app(),
        &input.registration,
        &claims.actor,
        &claims.selection,
        selected_at,
    )?
    else {
        return Ok(unavailable("BindingUnavailable"));
    };
    let now = super::effects::wall_time()?;
    if now < selected_at {
        let tx = crate::write_queue::immediate(&mut db)?;
        refuse(&tx, &claims)?;
        serving.commit(tx)?;
        return Ok(unavailable("ReauthRequired"));
    }
    let snapshot = crate::write_queue::immediate(&mut db)?;
    let current = load(
        &snapshot,
        runtime,
        request,
        &input.registration,
        &input.reference,
        now,
    )?;
    ensure!(
        current == claims,
        "connection use changed during key retrieval"
    );
    let (intent, binding) = activation(&snapshot, &claims, &selection)?;
    serving.check()?;
    let token = super::custody::load_access(
        &snapshot,
        &key,
        &intent,
        &binding,
        &claims.account,
        claims.token_version,
        now,
    )?;
    if let Some(token) = &token {
        claims.expires_at = claims.expires_at.min(token.expires_at);
        snapshot.execute(
            "UPDATE oauth_use_handles SET claims=?1 WHERE reference=?2 AND invocation=?3",
            params![
                serde_json::to_string(&claims)?,
                input.reference,
                request.context.invocation_id
            ],
        )?;
    }
    serving.commit(snapshot)?;
    let Some(token) = token else {
        return Ok(unavailable("ReauthRequired"));
    };
    let result = serving.send(|| super::calendar::list(&token, &input.window))?;
    let at = super::effects::wall_time()?;
    if at < now || at >= token.expires_at {
        let tx = crate::write_queue::immediate(&mut db)?;
        refuse(&tx, &claims)?;
        serving.commit(tx)?;
        return Ok(unavailable("ReauthRequired"));
    }
    let Some(current) = authority.current(runtime.app(), &input.registration, &claims.actor, at)?
    else {
        return Ok(unavailable("BindingUnavailable"));
    };
    ensure!(
        current.identity()? == claims.selection,
        "connection selection changed during provider read"
    );
    let completed_at = super::effects::wall_time()?;
    if completed_at < at || completed_at >= token.expires_at {
        let tx = crate::write_queue::immediate(&mut db)?;
        refuse(&tx, &claims)?;
        serving.commit(tx)?;
        return Ok(unavailable("ReauthRequired"));
    }
    let snapshot = db.transaction()?;
    load(
        &snapshot,
        runtime,
        request,
        &input.registration,
        &input.reference,
        completed_at,
    )?;
    serving.commit(snapshot)?;
    Ok(result)
}

fn refuse(db: &Connection, claims: &Claims) -> Result<()> {
    super::custody::refuse_access(
        db,
        &claims.slot,
        claims.generation,
        claims.token_version,
        claims.security_epoch,
        &claims.profile,
        &claims.account,
    )
}

/// Runs inside the final/replay transaction. Only local pins and the clock are
/// inspected here; readiness, key retrieval and provider I/O are already closed.
pub(crate) fn validate_cached(
    db: &Connection,
    runtime: &Runtime,
    request: &Request,
    observation: &Observation,
) -> Result<()> {
    require_action(db, runtime, request, &observation.instruction.model)?;
    let now = super::effects::wall_time()?;
    if observation.instruction.model == crate::connection_codegen::RESOLVE {
        let input: ResolveInput = crate::json::decode(observation.instruction.data.as_bytes())?;
        let result: Value = crate::json::decode(observation.result.as_bytes())?;
        if let Some(reference) = result.get("Available").and_then(Value::as_str) {
            load(db, runtime, request, &input.registration, reference, now)?;
        } else {
            let _ = declaration(runtime, &input.registration)?;
        }
    } else {
        let input: ReadInput = crate::json::decode(observation.instruction.data.as_bytes())?;
        load(
            db,
            runtime,
            request,
            &input.registration,
            &input.reference,
            now,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod refresh_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{artifact::LoadedArtifact, audit::Trigger, authority_state, store::ActingAs};
    use day2_capabilities::{
        Name,
        oauth::{AccountBindingPolicy, ConnectionDeclaration, ConnectionOwner},
    };
    use std::{collections::BTreeSet, fs, sync::Arc, time::Duration};

    struct Clock;
    impl super::super::effects::Hooks for Clock {
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("unscripted provider observation")
        }

        fn domain(&self) -> u64 {
            6302
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(100)
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn fill(&self, _bytes: &mut [u8]) -> Result<()> {
            anyhow::bail!("unexpected entropy in cached validation")
        }
        fn send(
            &self,
            _request: reqwest::blocking::Request,
        ) -> Result<super::super::effects::Response> {
            panic!("provider I/O inside cached commit validation")
        }
    }

    // This is host conformance with real SQLite/acceptance/authority. Native
    // admission and generated type behavior are separate integration tests.
    struct Fixture {
        _directory: tempfile::TempDir,
        runtime: Runtime,
        request: Request,
        claims: Claims,
        reference: String,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let artifact_directory = directory.path().join("host-contract");
            fs::create_dir(&artifact_directory)?;
            let instance_path = directory.path().join("instance.json");
            let requirement = ConnectionRequirement {
                logical_id: "work_calendar".into(),
                revision: 1,
                capability: "google_calendar_events".into(),
                actions: BTreeSet::from(["list_events".into()]),
                owner: ConnectionOwner::CurrentHuman,
                account_policy: AccountBindingPolicy::MappedHuman,
                usage: "Read work events.".into(),
            };
            let contract = serde_json::from_value(json!({
                "format":crate::artifact::CURRENT_FORMAT,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,"roc_version":"host-test","worker_digest":"host-test","schema_digest":"host-test",
                "schema":{"models":{"entries":{"fields":{"note":"text"}}},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
                "operations":[{"name":"read","kind":"query","input_type":"input","output_type":""}],
                "connection_declarations":[ConnectionDeclaration { registration: Name::try_from("calendar".to_owned())?, requirement: requirement.clone() }],
                "sources":{},"admission":"local-spike-only"
            }))?;
            fs::write(
                &instance_path,
                serde_json::to_vec(&json!({
                    "installation":"calendar","environment":"test","apps":{"app":{"artifact":artifact_directory,
                        "readers":["alice","bob"],"writers":["alice"],"authority":{"version":1,"admins":["admin"],
                            "operations":{"read":{"actors":["alice","bob"],"mode":{"kind":"read"},"models":{},
                                "observations":[crate::connection_codegen::RESOLVE,crate::connection_codegen::LIST_EVENTS]}}}
                    }}
                }))?,
            )?;
            let runtime = Runtime::from_artifact_for_tests(
                instance_path,
                "app".into(),
                directory.path().join("app.sqlite"),
                LoadedArtifact::from_contract_for_tests(
                    "host-calendar-artifact".into(),
                    artifact_directory,
                    contract,
                ),
            )?;
            runtime.initialize()?;
            let mut db = store::open(runtime.db())?;
            let identity = crate::iap::Verified {
                email: "alice".into(),
                subject: "accounts.google.com:alice".into(),
            };
            crate::iap::bind_subject(&db, &identity, 100)?;
            runtime.accept_on_behalf_of_verified(
                "read",
                ActingAs {
                    authenticated: "alice",
                    actor: "alice",
                    trigger: Trigger::Request,
                },
                "invocation_1",
                &json!({}),
                100,
                Some(&identity),
            )?;
            let request = Request {
                operation: "read".into(),
                input: "{}".into(),
                context: store::invocation_context(&db, "invocation_1")?,
                observations: Vec::new(),
            };
            let claims = Claims {
                invocation: "invocation_1".into(),
                operation: "read".into(),
                actor: "alice".into(),
                subject: identity.subject,
                scope: runtime.scope().into(),
                artifact: runtime.artifact().id().into(),
                authority: authority_state::current(&db)?.stamp,
                registration: "calendar".into(),
                requirement: requirement.nominal_identity()?,
                selection: Digest::of(&"selected-readiness")?,
                slot: "slot_1".into(),
                generation: 1,
                token_version: 1,
                security_epoch: 1,
                profile: "profile_1".into(),
                account: "account_1".into(),
                affinity: "affinity_1".into(),
                issued_at: 100,
                expires_at: 160,
            };
            let reference = format!("cu1_{}", "x".repeat(43));
            let tx = crate::write_queue::immediate(&mut db)?;
            tx.execute("INSERT INTO oauth_connection_slots VALUES('slot_1',1,1,1,'profile_1','account_1','affinity_1','active')", [])?;
            tx.execute(
                "INSERT INTO oauth_use_handles VALUES(?1,'invocation_1',?2)",
                params![reference, serde_json::to_string(&claims)?],
            )?;
            tx.commit()?;
            Ok(Self {
                _directory: directory,
                runtime,
                request,
                claims,
                reference,
            })
        }

        fn observation(&self, read: bool) -> Observation {
            Observation {
                instruction: Instruction {
                    kind: "observe".into(),
                    model: if read { crate::connection_codegen::LIST_EVENTS } else { crate::connection_codegen::RESOLVE }.into(),
                    data: if read {
                        json!({"registration":"calendar","reference":self.reference,"window":{"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"}})
                    } else { json!({"registration":"calendar"}) }.to_string(),
                    ..Default::default()
                },
                result: if read { json!({"Listed":[]}) } else { json!({"Available":self.reference}) }.to_string(), error: String::new(),
            }
        }
    }

    #[test]
    fn cached_product_reads_recheck_owner_generation_binding_and_final_authority() -> Result<()> {
        super::super::effects::scope(Arc::new(Clock), || -> Result<()> {
            let fixture = Fixture::new()?;
            for read in [false, true] {
                let mut db = store::open(fixture.runtime.db())?;
                let tx = crate::write_queue::immediate(&mut db)?;
                crate::resources::validate_cached(
                    &tx,
                    &fixture.runtime,
                    &fixture.request,
                    &fixture.observation(read),
                )?;
                for field in [
                    "generation",
                    "token_version",
                    "security_epoch",
                    "profile",
                    "account",
                    "affinity",
                    "status",
                ] {
                    let change = match field {
                        "generation" | "token_version" | "security_epoch" => "2",
                        "status" => "'disabled'",
                        _ => "'substituted'",
                    };
                    tx.execute_batch("SAVEPOINT changed_use;")?;
                    tx.execute(
                        &format!("UPDATE oauth_connection_slots SET {field}={change}"),
                        [],
                    )?;
                    assert!(
                        crate::resources::validate_cached(
                            &tx,
                            &fixture.runtime,
                            &fixture.request,
                            &fixture.observation(read)
                        )
                        .is_err(),
                        "{field} changed after the provider read but still passed final commit"
                    );
                    tx.execute_batch("ROLLBACK TO changed_use; RELEASE changed_use;")?;
                }
                assert!(
                    load(
                        &tx,
                        &fixture.runtime,
                        &fixture.request,
                        "other_requirement",
                        &fixture.reference,
                        100
                    )
                    .is_err()
                );
                assert!(
                    load(
                        &tx,
                        &fixture.runtime,
                        &fixture.request,
                        "calendar",
                        "cu1_forged",
                        100
                    )
                    .is_err()
                );
                assert!(
                    load(
                        &tx,
                        &fixture.runtime,
                        &fixture.request,
                        "calendar",
                        &fixture.reference,
                        99
                    )
                    .is_err()
                );
                assert!(
                    load(
                        &tx,
                        &fixture.runtime,
                        &fixture.request,
                        "calendar",
                        &fixture.reference,
                        160
                    )
                    .is_err()
                );
                let mut forged = fixture.request.clone();
                forged.context.actor = "bob".into();
                assert!(
                    load(
                        &tx,
                        &fixture.runtime,
                        &forged,
                        "calendar",
                        &fixture.reference,
                        100
                    )
                    .is_err()
                );
                tx.commit()?;
            }
            let mut db = store::open(fixture.runtime.db())?;
            let previous = authority_state::current(&db)?;
            let mut document = previous.document;
            document
                .policy
                .as_mut()
                .context("fixture policy")?
                .operations
                .get_mut("read")
                .unwrap()
                .observations
                .clear();
            authority_state::apply(
                &fixture.runtime,
                &authority_state::LocalOperator::assert_local("admin")?,
                &authority_state::ApplyAuthority {
                    request_id: "revoke_calendar_reads".into(),
                    expected: Some(fixture.claims.authority.clone()),
                    document,
                },
            )?;
            let tx = crate::write_queue::immediate(&mut db)?;
            assert!(
                crate::resources::validate_cached(
                    &tx,
                    &fixture.runtime,
                    &fixture.request,
                    &fixture.observation(true)
                )
                .is_err()
            );
            Ok(())
        })
    }

    #[test]
    fn actor_text_without_durable_verified_human_origin_cannot_resolve() -> Result<()> {
        let fixture = Fixture::new()?;
        fixture
            .runtime
            .accept("read", "bob", "local_invocation", &json!({}), 100)?;
        let mut db = store::open(fixture.runtime.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        let request = Request {
            operation: "read".into(),
            input: "{}".into(),
            context: store::invocation_context(&tx, "local_invocation")?,
            observations: Vec::new(),
        };
        assert!(human(&tx, &fixture.runtime, &request)?.is_none());
        Ok(())
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProviderCase {
        Complete,
        Continuation,
        RevokedContinuation,
        Expired,
        Rewound,
        RewoundKey,
        ReadinessExpired,
        ReadinessRewound,
        Late,
        MissingMarker,
    }

    struct ProductPort {
        case: ProviderCase,
        db: std::path::PathBuf,
        now: std::sync::atomic::AtomicI64,
        ticks: std::sync::atomic::AtomicU64,
        entropy: std::sync::atomic::AtomicU64,
        sends: std::sync::atomic::AtomicUsize,
    }

    impl super::super::effects::Hooks for ProductPort {
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("unscripted provider observation")
        }

        fn domain(&self) -> u64 {
            6303
        }

        fn wall_time(&self) -> Result<i64> {
            Ok(self.now.load(std::sync::atomic::Ordering::SeqCst))
        }

        fn monotonic(&self) -> Duration {
            Duration::from_secs(self.ticks.load(std::sync::atomic::Ordering::SeqCst))
        }

        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            let counter = self
                .entropy
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .to_le_bytes();
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = counter[index % counter.len()];
            }
            Ok(())
        }

        fn send(
            &self,
            request: reqwest::blocking::Request,
        ) -> Result<super::super::effects::Response> {
            use std::sync::atomic::Ordering::SeqCst;
            assert_eq!(
                self.sends.fetch_add(1, SeqCst),
                0,
                "no second bearer dispatch or retry"
            );
            assert_eq!(request.method(), reqwest::Method::GET);
            assert_eq!(request.url().host_str(), Some("www.googleapis.com"));
            assert_eq!(
                request.url().path(),
                "/calendar/v3/calendars/primary/events"
            );
            assert!(
                !request
                    .url()
                    .query_pairs()
                    .any(|(name, _)| name == "pageToken")
            );
            let authorization = &request.headers()[reqwest::header::AUTHORIZATION];
            assert_eq!(
                authorization.to_str()?,
                "Bearer private_runtime_calendar_access"
            );
            assert!(authorization.is_sensitive());
            // Acquiring an immediate writer proves the host has closed its
            // business transaction before entering the simulated provider.
            let mut db = store::open(&self.db)?;
            let tx = crate::write_queue::immediate(&mut db)?;
            assert_eq!(
                tx.query_row(
                    "SELECT count(*) FROM day2_observation_attempts WHERE observation IS NULL",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
            if self.case == ProviderCase::RevokedContinuation {
                tx.execute("UPDATE oauth_connection_slots SET status='disabled',security_epoch=security_epoch+1", [])?;
            }
            tx.commit()?;
            match self.case {
                ProviderCase::Expired => self.now.store(303, SeqCst),
                ProviderCase::Rewound => self.now.store(99, SeqCst),
                ProviderCase::ReadinessRewound => self.now.store(110, SeqCst),
                ProviderCase::Late => self.ticks.store(3, SeqCst),
                _ => (),
            }
            let mut body = json!({"kind":"calendar#events","items":[{
                "id":"event_1","summary":"Work meeting","start":{"dateTime":"2026-10-13T10:00:00Z"},
                "end":{"dateTime":"2026-10-13T11:00:00Z"}
            }]});
            if matches!(
                self.case,
                ProviderCase::Continuation | ProviderCase::RevokedContinuation
            ) {
                body["nextPageToken"] = "private_cursor".into();
            }
            if self.case == ProviderCase::MissingMarker {
                body.as_object_mut().unwrap().remove("kind");
            }
            Ok(super::super::effects::Response::Simulated {
                status: reqwest::StatusCode::OK,
                headers: reqwest::header::HeaderMap::from_iter([(
                    reqwest::header::CONTENT_TYPE,
                    reqwest::header::HeaderValue::from_static("application/json"),
                )]),
                body: std::io::Cursor::new(serde_json::to_vec(&body)?),
                peer: None,
            })
        }
    }

    struct ProductAuthority {
        selection: Selection,
        port: Arc<ProductPort>,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl Authority for ProductAuthority {
        fn refresh_client(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &Digest,
            _: i64,
        ) -> Result<Option<super::super::refresh::ClientCredential>> {
            anyhow::bail!("unexpected refresh of an unexpired original test token")
        }

        fn with_current(
            &self,
            app: &str,
            registration: &str,
            owner: &str,
            now: i64,
            commit: &mut dyn FnMut(&Selection) -> Result<bool>,
        ) -> Result<bool> {
            let Some(current) = self.current(app, registration, owner, now)? else {
                return Ok(false);
            };
            commit(&current)
        }

        fn current(
            &self,
            app: &str,
            registration: &str,
            owner: &str,
            _: i64,
        ) -> Result<Option<Selection>> {
            ensure!(
                app == "app" && registration == "calendar" && owner == "alice@example.com",
                "unexpected native selection"
            );
            let mut db = store::open(&self.port.db)?;
            crate::write_queue::immediate(&mut db)?.commit()?;
            let call = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.port.case == ProviderCase::RewoundKey && call == 1 {
                self.port
                    .now
                    .store(110, std::sync::atomic::Ordering::SeqCst);
            }
            if call == 2 {
                match self.port.case {
                    ProviderCase::ReadinessExpired => self
                        .port
                        .now
                        .store(303, std::sync::atomic::Ordering::SeqCst),
                    ProviderCase::ReadinessRewound => self
                        .port
                        .now
                        .store(105, std::sync::atomic::Ordering::SeqCst),
                    _ => (),
                }
            }
            Ok(Some(self.selection.clone()))
        }

        fn custody(
            &self,
            _: &str,
            _: &str,
            _: &str,
            expected: &Digest,
            now: i64,
        ) -> Result<Option<KeyLease>> {
            assert_eq!(&self.selection.identity()?, expected);
            let mut db = store::open(&self.port.db)?;
            crate::write_queue::immediate(&mut db)?.commit()?;
            if self.port.case == ProviderCase::RewoundKey && now == 110 {
                self.port
                    .now
                    .store(105, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(Some(super::super::profiles::tests::exchange_key()))
        }
    }

    // Host-only simulated readiness and HTTP; the artifact, generated typed
    // clients, human acceptance, original exchange/custody, observation journal
    // and final decision all use their ordinary implementations.
    pub(super) fn product_selection(
        runtime: &Runtime,
    ) -> Result<(
        Selection,
        super::super::profiles::tests::QualificationFixture,
    )> {
        use super::super::{
            admission,
            connect::{CallbackBinding, CallbackBindingSpec, ConnectIntent},
            profiles::*,
        };
        use day2_capabilities::{
            BindingRef,
            credentials::Namespace,
            oauth::{
                ConnectionSlotKey, ProductReturnRef, ProviderCallbackRef, SecurityOriginRef,
                SlotOwner,
            },
        };
        let name = |value: &str| Name::try_from(value.to_owned());
        let pin = |value: &str| BindingRef::pin(name(value)?, &value);
        let requirement = declaration(runtime, "calendar")?.clone();
        let access = super::super::google::reviewed(&requirement.account_policy)?;
        let reviewed = access.profile.clone();
        let (_, permission) = admission::ReviewedCatalog::new(vec![access])?
            .resolve(&requirement, &reviewed.protocol.identity().binding)?;
        let instance_ref = pin("simulated_instance")?;
        let shell_url = "https://security.example.com/".to_owned();
        let qualification = Digest::of(&"simulated-shell-readiness")?;
        let origin = SecurityOriginRef(BindingRef {
            id: name("security_origin")?,
            revision: Digest::of(&(
                "oauth-security-shell-evidence-v1",
                &instance_ref,
                &shell_url,
                &qualification,
            ))?,
        });
        let mut binding = OutboundConnectionBinding {
            namespace: Namespace {
                installation: name("localdev")?,
                environment: name("disposable")?,
                app: name("app")?,
                binding_generation: 1,
            },
            requirement: requirement.nominal_identity()?,
            profile: permission.profile.clone(),
            registration: pin("calendar_registration")?,
            custody: pin("oauth_custody")?,
            security_shell: origin.clone(),
            account_binding: pin("human_subject_map")?,
            shell_attestation: pin("shell_attestation")?,
            product_return: ProductReturnRef(pin("calendar_return")?),
            custody_verifier_secret: name("verifier")?,
            custody_encryption_secret: name("encryption")?,
            shell_attestation_secret: name("attestation")?,
        };
        let slot = ConnectionSlotKey {
            installation: binding.namespace.installation.clone(),
            environment: binding.namespace.environment.clone(),
            app: binding.namespace.app.clone(),
            requirement: requirement.logical_id.clone(),
            owner: SlotOwner::Human {
                subject: "alice@example.com".into(),
            },
        }
        .id(&requirement)?;
        let namespace = admission::binding_namespace(&binding)?;
        let callback = ProviderCallbackRef::derive(&origin, &permission.profile, &namespace)?;
        let callback_url = derived_callback_url(&shell_url, &callback)?;
        let confirmation = Digest::of(&"simulated-provider-confirmation")?;
        let client_credential = pin("calendar_client_credential")?;
        let class = ClientRegistrationClass::ConfidentialPkceS256;
        binding.registration.revision = Digest::of(&(
            "oauth-provider-registration-evidence-v1",
            &instance_ref,
            &permission.profile,
            &reviewed.issuer,
            &origin,
            &callback,
            &callback_url,
            &confirmation,
            &client_credential,
            class,
        ))?;
        let intent = ConnectIntent {
            attempt: "original_attempt".into(),
            slot: slot.as_str().into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: "alice@example.com".into(),
            profile: permission.profile.id.as_str().into(),
            registration: Digest::of(&binding.registration)?.as_str().into(),
            callback: Digest::of(&callback)?.as_str().into(),
            consent: permission.consent_digest(&requirement)?.as_str().into(),
            expires_at: 900,
        };
        let callback_binding = CallbackBinding::from_secret_state(
            b"0123456789abcdefghijklmnopqrstuvwxyzABCDEF",
            CallbackBindingSpec {
                issuer: reviewed.issuer.clone(),
                issuer_url: reviewed.issuer_url.clone(),
                security_origin: origin.clone(),
                profile: permission.profile.clone(),
                callback: callback.clone(),
                binding_namespace: namespace.clone(),
                session: Digest::of(&"private-session")?,
                product_return: binding.product_return.clone(),
            },
        )?;
        let instance = OutboundInstanceEvidence {
            instance: instance_ref.clone(),
            binding_namespace: namespace,
            app_origin_url: "https://app.example.com/".into(),
            shell: SecurityShellEvidence {
                instance: instance_ref.clone(),
                origin: origin.clone(),
                origin_url: shell_url,
                qualification,
            },
            registration: ProviderRegistrationEvidence {
                instance: instance_ref.clone(),
                registration: binding.registration.clone(),
                profile: permission.profile.clone(),
                issuer: reviewed.issuer.clone(),
                security_origin: origin,
                callback,
                callback_url,
                provider_confirmation: confirmation,
                client_credential,
                class,
            },
            custody: binding.custody.clone(),
            account: AccountBindingEvidence::MappedHuman {
                instance: instance_ref,
                mapping: binding.account_binding.clone(),
                owner: intent.owner.clone(),
            },
            product_return: binding.product_return.clone(),
        };
        let fixture = super::super::profiles::tests::QualificationFixture {
            intent,
            binding: callback_binding,
            requirement: requirement.clone(),
            permission: permission.clone(),
            reviewed: reviewed.clone(),
            instance: instance.clone(),
        };
        Ok((
            Selection {
                requirement,
                permission,
                reviewed,
                binding,
                instance,
                slot,
            },
            fixture,
        ))
    }

    #[test]
    fn compiled_calendar_runtime_uses_real_custody_and_fences_dispatch_and_completion() -> Result<()>
    {
        use super::super::{
            account::{MappedHumanEvidence, ProviderAccount},
            effects,
            exchange::{self, ExchangeObservation, TokenHttpResponse},
            outbound::{CallbackIngress, CallbackOutcome},
            profiles::AccountBindingEvidence,
        };
        use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering::SeqCst};
        let artifact_path = std::env::var("DAY2_TEST_OAUTH_CALENDAR_ARTIFACT")
            .context("compiled Calendar artifact required")?;
        for case in [
            ProviderCase::Complete,
            ProviderCase::Continuation,
            ProviderCase::RevokedContinuation,
            ProviderCase::Expired,
            ProviderCase::Rewound,
            ProviderCase::RewoundKey,
            ProviderCase::ReadinessExpired,
            ProviderCase::ReadinessRewound,
            ProviderCase::Late,
            ProviderCase::MissingMarker,
        ] {
            let directory = tempfile::tempdir()?;
            let instance_path = directory.path().join("instance.json");
            let instance = crate::development::verification_instance_data(
                std::path::Path::new(&artifact_path),
                None,
                "alice@example.com",
            )?;
            fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
            let mut runtime = Runtime::from_artifact_for_tests(
                instance_path,
                "app".into(),
                directory.path().join("app.sqlite"),
                LoadedArtifact::load(std::path::Path::new(&artifact_path))?,
            )?;
            runtime.initialize()?;
            let port = Arc::new(ProductPort {
                case,
                db: runtime.db().to_owned(),
                now: AtomicI64::new(100),
                ticks: AtomicU64::new(0),
                entropy: AtomicU64::new(1),
                sends: AtomicUsize::new(0),
            });
            effects::scope(port.clone(), || -> Result<()> {
                let (selection, fixture) = product_selection(&runtime)?;
                let authority = Arc::new(ProductAuthority {
                    selection,
                    port: port.clone(),
                    reads: AtomicUsize::new(0),
                });
                runtime.connections = Some(authority.clone());
                let mut db = store::open(runtime.db())?;
                let key = super::super::profiles::tests::exchange_key();
                let prepared = exchange::prepare_authorization(
                    fixture.input(),
                    &key,
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
                )?;
                let code_ref = prepared.code_ref().to_owned();
                assert!(prepared.begin(&mut db, 1)?);
                let raw = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("state", "0123456789abcdefghijklmnopqrstuvwxyzABCDEF")
                    .append_pair("code", "secret_original_code")
                    .append_pair("iss", &fixture.reviewed.issuer_url)
                    .finish();
                assert!(matches!(
                    exchange::handle_qualified_callback(
                        &mut db,
                        fixture.input(),
                        CallbackIngress {
                            attempt: &fixture.intent.attempt,
                            raw_query: raw.as_bytes(),
                            route: &fixture.instance.registration.callback,
                            session: fixture.binding.session(),
                            issuer_binding: &fixture.reviewed.issuer,
                            code_ref: &code_ref,
                            now: 2
                        },
                        &key,
                        None,
                    )?,
                    CallbackOutcome::CodeAccepted { .. }
                ));
                let permit =
                    exchange::authorize_and_commit_qualified_exchange(&mut db, fixture.input(), 3)?
                        .context("qualified original permit")?;
                let scopes = fixture
                    .permission
                    .action_scopes
                    .values()
                    .flatten()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(" ");
                let ExchangeObservation::Response(response) = permit.send(|_| Ok(TokenHttpResponse { status: 200, content_type: "application/json".into(),
                    body: serde_json::to_vec(&json!({"access_token":"private_runtime_calendar_access","refresh_token":"private_runtime_refresh","token_type":"Bearer","expires_in":300,"scope":scopes}))? })) else { anyhow::bail!("original exchange response lost"); };
                let AccountBindingEvidence::MappedHuman { mapping, .. } = &fixture.instance.account
                else {
                    anyhow::bail!("expected mapped human");
                };
                let mapped = MappedHumanEvidence {
                    human: fixture.intent.owner.clone(),
                    issuer: fixture.reviewed.issuer_url.clone(),
                    provider_subject: "google-alice".into(),
                    tenant: "example.com".into(),
                    mapping_revision: mapping.revision.clone(),
                };
                let account = ProviderAccount {
                    issuer: mapped.issuer.clone(),
                    subject: mapped.provider_subject.clone(),
                    tenant: mapped.tenant.clone(),
                    display_email: "alice@example.com".into(),
                };
                let settlement = response
                    .validate_mapped(fixture.input(), &mapped, &account)?
                    .prepare_tokens(&key)?;
                assert!(exchange::settle_mapped(
                    &mut db,
                    settlement,
                    fixture.input(),
                    &mapped.mapping_revision,
                    4
                )?);
                let human = crate::iap::Verified {
                    email: "alice@example.com".into(),
                    subject: "accounts.google.com:google-alice".into(),
                };
                crate::iap::bind_subject(&db, &human, 100)?;
                let input = json!({"start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z"});
                let outcome = runtime.invoke_verified(
                    "oauthcalendar.list_events",
                    store::RequestIdentity {
                        actor: &human.email,
                        origin: Some(&human),
                    },
                    "product_read",
                    &input,
                    100,
                    store::Fault::None,
                );
                if matches!(
                    case,
                    ProviderCase::RevokedContinuation
                        | ProviderCase::Expired
                        | ProviderCase::Rewound
                        | ProviderCase::RewoundKey
                        | ProviderCase::ReadinessExpired
                        | ProviderCase::ReadinessRewound
                ) {
                    let error = outcome.expect_err("invalidated Use must refuse actual completion");
                    let expected = if matches!(
                        case,
                        ProviderCase::Expired
                            | ProviderCase::Rewound
                            | ProviderCase::ReadinessExpired
                    ) {
                        "connection use authority or invocation changed"
                    } else {
                        "connection use generation or account changed"
                    };
                    assert_eq!(error.to_string(), expected, "{case:?}: {error:#}");
                    assert_ne!(
                        db.query_row(
                            "SELECT status FROM day2_invocations WHERE id='product_read'",
                            [],
                            |row| row.get::<_, String>(0)
                        )?,
                        "success"
                    );
                } else {
                    let outcome =
                        outcome.with_context(|| format!("{case:?} native Calendar execution"))?;
                    if case == ProviderCase::Complete {
                        assert_eq!(outcome.status, "success", "{outcome:?}");
                        assert_eq!(outcome.result["status"], "ok", "{outcome:?}");
                        assert_eq!(outcome.result["events"]["items"][0]["id"], "event_1");
                        assert_eq!(outcome.result["events"]["has_more"], false);
                        assert_eq!(
                        db.query_row(
                            "SELECT count(*) FROM day2_observation_attempts WHERE invocation='product_read' AND observation IS NOT NULL",
                            [],
                            |row| row.get::<_, i64>(0)
                        )?,
                        2
                    );
                    } else {
                        assert!(
                            outcome.status != "success" || outcome.result["status"] != "ok",
                            "invalid provider result completed: {outcome:?}"
                        );
                        if matches!(
                            case,
                            ProviderCase::Continuation
                                | ProviderCase::Late
                                | ProviderCase::MissingMarker
                        ) {
                            assert_eq!(outcome.status, "success", "{outcome:?}");
                            assert_eq!(
                                outcome.result["status"],
                                if case == ProviderCase::MissingMarker {
                                    "provider_unavailable"
                                } else {
                                    "capacity_deferred"
                                }
                            );
                            assert_eq!(outcome.result["events"]["items"], json!([]));
                        }
                    }
                }
                assert_eq!(
                    port.sends.load(SeqCst),
                    usize::from(case != ProviderCase::RewoundKey)
                );
                assert_eq!(
                    db.query_row("SELECT count(*) FROM entries", [], |row| row
                        .get::<_, i64>(0))?,
                    0
                );
                let encoded: String = db.query_row(
                    "SELECT claims FROM oauth_use_handles WHERE invocation='product_read'",
                    [],
                    |row| row.get(0),
                )?;
                let claims: Claims = crate::json::decode(encoded.as_bytes())?;
                assert_eq!(claims.subject, human.subject);
                assert_eq!(claims.selection, authority.selection.identity()?);
                let journal = db
                    .prepare(
                        "SELECT observation FROM day2_observation_attempts WHERE invocation='product_read' AND observation IS NOT NULL ORDER BY ordinal,attempt",
                    )?
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
                    .join(" ");
                assert!(
                    !journal.contains("private_runtime") && !journal.contains("private_cursor")
                );
                if matches!(
                    case,
                    ProviderCase::Expired
                        | ProviderCase::Rewound
                        | ProviderCase::RewoundKey
                        | ProviderCase::ReadinessExpired
                        | ProviderCase::ReadinessRewound
                ) {
                    assert_eq!(
                        db.query_row("SELECT status FROM oauth_connection_slots", [], |row| {
                            row.get::<_, String>(0)
                        })?,
                        "reauth_required"
                    );
                    // This fresh invocation runs resolve again after the wall
                    // clock recovers/rewinds, and must never recover a Use.
                    port.now.store(100, SeqCst);
                    let retry = runtime.invoke_verified(
                        "oauthcalendar.list_events",
                        store::RequestIdentity {
                            actor: &human.email,
                            origin: Some(&human),
                        },
                        "after_clock_recovery",
                        &input,
                        100,
                        store::Fault::None,
                    )?;
                    assert_eq!(retry.status, "success", "{retry:?}");
                    assert_eq!(retry.result["status"], "reauth_required", "{retry:?}");
                    assert_eq!(
                        port.sends.load(SeqCst),
                        usize::from(case != ProviderCase::RewoundKey)
                    );
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}
