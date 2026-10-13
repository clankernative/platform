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
        status == "active" && token_version == 1,
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
        count == 1 && claims.token_version == 1,
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
         AND security_epoch=?4 AND profile=?5 AND account=?6 AND affinity=?7 AND status='active')",
        params![claims.slot, claims.generation, claims.token_version, claims.security_epoch, claims.profile, claims.account, claims.affinity],
        |row| row.get(0),
    )?;
    ensure!(matches, "connection use generation or account changed");
    Ok(claims)
}

fn resolve(runtime: &Runtime, request: &Request, instruction: &Instruction) -> Result<String> {
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
    snapshot.commit()?;
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
    let mut nonce = [0u8; 32];
    super::effects::fill(&mut nonce)?;
    use base64::Engine as _;
    let reference = format!(
        "cu1_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
    );
    let tx = crate::write_queue::immediate(&mut db)?;
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
    tx.commit()?;
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
    if instruction.model == crate::connection_codegen::RESOLVE {
        return resolve(runtime, request, instruction);
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
    snapshot.commit()?;
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
    let Some(key) = authority.custody(
        runtime.app(),
        &input.registration,
        &claims.actor,
        &claims.selection,
        started,
    )?
    else {
        return Ok(unavailable("BindingUnavailable"));
    };
    let now = super::effects::wall_time()?;
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
    snapshot.commit()?;
    let Some(token) = token else {
        return Ok(unavailable("ReauthRequired"));
    };
    let result = super::calendar::list(&token, &input.window)?;
    let at = super::effects::wall_time()?;
    if at < now || at >= token.expires_at {
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
    let snapshot = db.transaction()?;
    load(
        &snapshot,
        runtime,
        request,
        &input.registration,
        &input.reference,
        at,
    )?;
    snapshot.commit()?;
    Ok(result)
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
                "format":crate::artifact::CURRENT_FORMAT,"roc_version":"host-test","worker_digest":"host-test","schema_digest":"host-test",
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
}
