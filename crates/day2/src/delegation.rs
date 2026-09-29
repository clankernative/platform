//! App-to-app delegation: one application reading another's published operation.
//!
//! The call never leaves the instance. Both applications are installed here,
//! their databases are siblings under one state directory, and the host loads
//! the callee the same way it loads the caller. There is no socket, no
//! credential and no transport — which is why the provider that carries it
//! declares no connection.
//!
//! What it is *not* is a way to borrow authority. A delegated call runs as the
//! same actor the caller was running as, and the callee's own policy decides
//! independently whether that actor may run that operation. The grant says the
//! caller may ask; it never says the answer is yes. A compromised caller can
//! therefore reach nothing the person it is acting for could not already reach
//! by calling the callee directly.
use crate::store::Runtime;
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

/// Host-private root evidence. The assertion itself stays at the edge; only
/// the verified account binding is retained for later issuer admission.
pub(crate) fn upgrade_origin(connection: &rusqlite::Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_invocation_origins(
            invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id),
            principal TEXT NOT NULL, subject TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind='iap')) STRICT;",
    )?;
    Ok(())
}

pub(crate) fn record_root_origin(
    connection: &rusqlite::Connection,
    invocation: &str,
    initiator: &str,
    verified: Option<&crate::iap::Verified>,
    new_invocation: bool,
) -> Result<()> {
    let recorded: Option<(String, String)> = connection
        .query_row(
            "SELECT principal,subject FROM day2_invocation_origins WHERE invocation=?1",
            [invocation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match (verified, recorded) {
        (Some(identity), None) if new_invocation => {
            ensure!(
                identity.email == initiator,
                "invocation_origin_principal_changed"
            );
            let bound: String = connection.query_row(
                "SELECT subject FROM day2_principals WHERE email=?1",
                [initiator],
                |row| row.get(0),
            )?;
            ensure!(
                bound == identity.subject,
                "invocation_origin_subject_changed"
            );
            connection.execute(
                "INSERT INTO day2_invocation_origins VALUES(?1,?2,?3,'iap')",
                params![invocation, initiator, identity.subject],
            )?;
        }
        (Some(identity), Some((principal, subject))) => ensure!(
            identity.email == initiator
                && identity.email == principal
                && identity.subject == subject,
            "invocation_origin_changed"
        ),
        (None, None) => {}
        _ => anyhow::bail!("invocation_origin_changed"),
    }
    Ok(())
}

/// Host-owned dispatch for a query whose grant and durable invocation context
/// have already been checked. Implementations must authenticate the receiver
/// and preserve the call's actor, causal identity, and target contract.
pub trait AppCallPort: Send + Sync {
    fn query(&self, caller: &Runtime, call: &Call) -> Result<String>;
}

/// A remote signer must inherit its actor and chain from the current durable
/// invocation. A `Call` by itself is not identity evidence.
pub struct OriginEvidence {
    pub root: String,
    pub principal: String,
    pub subject: String,
}

pub fn verify_origin(runtime: &Runtime, call: &Call) -> Result<OriginEvidence> {
    ensure!(call.caller == runtime.app(), "delegated_caller_changed");
    let mut connection = crate::store::open(runtime.db())?;
    let tx = connection.transaction()?;
    runtime.check_binding(&tx)?;
    let origin: Option<(String, String, String, String, i64, String)> = tx
        .query_row(
            "SELECT operation,actor,caller,artifact,now,status FROM day2_invocations WHERE id=?1",
            params![call.origin],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let (operation, actor, chain, artifact, now, status) =
        origin.ok_or_else(|| anyhow::anyhow!("delegated_origin_missing"))?;
    ensure!(
        actor == call.actor
            && chain == call.chain
            && artifact == runtime.artifact().id()
            && now == call.now
            && status == "pending",
        "delegated_origin_changed"
    );
    crate::authority_state::require_invocation_in(
        &tx,
        runtime,
        &call.origin,
        &operation,
        &call.actor,
    )?;
    let root = crate::resources::root_in(&tx, &call.origin)?;
    let root_identity: Option<(String, String, String, String, String, String)> = tx
        .query_row(
            "SELECT i.actor,i.trigger,i.authenticated,i.caller,o.principal,o.subject
             FROM day2_invocations i JOIN day2_invocation_origins o ON o.invocation=i.id
             WHERE i.id=?1 AND o.kind='iap'",
            [&root],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let (root_actor, trigger, authenticated, root_caller, principal, subject) =
        root_identity.ok_or_else(|| anyhow::anyhow!("delegated_origin_evidence_missing"))?;
    ensure!(
        trigger == "request"
            && root_caller.is_empty()
            && root_actor == call.actor
            && (authenticated.is_empty() && principal == root_actor || authenticated == principal),
        "delegated_origin_evidence_changed"
    );
    let bound: String = tx.query_row(
        "SELECT subject FROM day2_principals WHERE email=?1",
        [&principal],
        |row| row.get(0),
    )?;
    ensure!(bound == subject, "delegated_origin_subject_changed");
    tx.commit()?;
    Ok(OriginEvidence {
        root,
        principal,
        subject,
    })
}

/// The recorded chain, as applications.
///
/// Stored as one dotted string rather than a list, because the column is also
/// what a cycle check reads and a prefix test on text is the cheapest form of
/// "have we been here already".
pub(crate) fn chain(recorded: &str) -> Vec<String> {
    if recorded.is_empty() {
        Vec::new()
    } else {
        recorded.split('.').map(str::to_owned).collect()
    }
}

/// How deep a delegated call may go.
///
/// Small on purpose. Each hop is another application's policy, another audit
/// record and another failure mode between a person and their answer; a chain
/// long enough to need a bigger number is a design nobody reviewed.
pub(crate) const MAXIMUM_DEPTH: usize = 4;

/// The chain a callee should record, refusing a cycle or an over-deep call.
pub(crate) fn extend(recorded: &str, caller: &str, callee: &str) -> Result<String> {
    let mut chain = chain(recorded);
    chain.push(caller.to_owned());
    ensure!(chain.len() <= MAXIMUM_DEPTH, "delegation_too_deep");
    ensure!(
        !chain.iter().any(|app| app == callee),
        "delegation_cycle: {callee} is already in this call chain"
    );
    Ok(chain.join("."))
}

/// One application reading another's published operation.
///
/// Four checks, and each is load-bearing:
///
/// The callee must be installed here. Delegation never leaves the instance, so
/// an operator can see the whole graph in one file.
///
/// The operation must be a query. A read can be answered inside the caller's
/// preparation phase and recorded as an observation, so it replays. A write
/// cannot: two applications are two databases and there is no transaction
/// across them, so a delegated command belongs on the effect path with a
/// receipt, which is a separate piece of work rather than a looser check here.
///
/// The shape must be the one the operator reviewed. The grant carries a digest
/// of the operation's input and output schemas, so a callee that changes what
/// it accepts fails the caller's deployment instead of its 3am invocation.
///
/// The chain must not already contain the callee. A→B→A is a loop that spends a
/// budget and reads as a hang.
pub fn read(runtime: &Runtime, call: &Call) -> Result<String> {
    // Authorization-only checks have no step. They must never dispatch: an
    // actual read needs a stable identity to deduplicate the callee invocation.
    ensure!(!call.step.is_empty(), "delegated_read_requires_a_step");
    // Cycle and depth are properties of the call, not of the callee, so they are
    // checked before anything is loaded and hold identically offline.
    ensure!(call.caller == runtime.app(), "delegated_caller_changed");
    let chain = extend(&call.chain, &call.caller, &call.app)?;

    // A campaign stands up one application, so the other one is not installed to
    // ask. Its answer comes from the recorded world instead -- and the checks
    // that need the callee's contract cannot run here, which is exactly why the
    // grant's schema digest is checked when the instance is deployed rather than
    // when the call is made.
    if runtime.integrations().is_simulated() {
        return crate::integrations::simulated::delegated_read(
            runtime.db(),
            runtime.scope(),
            &call.app,
            &call.operation,
            &call.input,
        );
    }

    if let Some(port) = runtime.app_call_port() {
        return port.query(runtime, call);
    }

    let callee = Runtime::load(runtime.instance_path(), &call.app)
        .map_err(|_| anyhow::anyhow!("delegated_app_not_installed: {}", call.app))?;
    // A compiled import is release-managed. Its package digest establishes the
    // API shape, while the journal and activated database establish which code
    // and authority are actually serving it.
    let fence = if call.contract_digest.is_some() || runtime.artifact().contract().imports.is_some()
    {
        Some(crate::release_binding::Fence::begin(runtime, &callee)?)
    } else {
        None
    };
    let result = execute_callee(&callee, call, &chain);
    if let Some(fence) = &fence {
        fence.check(runtime, &callee)?;
    }
    result
}

/// Receiver entry after a host adapter has verified the signed workload proof
/// and fenced the actual serving generation around this invocation.
pub fn receive_verified(
    callee: &Runtime,
    verified: &crate::delegation_wire::VerifiedQuery,
) -> Result<String> {
    let request = verified.query();
    ensure!(
        request.target.runtime_scope() == callee.scope()
            && request.target == crate::delegation_wire::Scope::from_runtime(callee)?,
        "delegated_target_changed"
    );
    let call = Call {
        app: request.target.app.clone(),
        operation: request.operation.clone(),
        schema_digest: request.schema_digest.clone(),
        contract_digest: request.contract_digest.clone(),
        input: serde_json::to_string(&request.input)?,
        actor: request.actor.clone(),
        origin: request.origin.clone(),
        step: request.step.clone(),
        chain: request.chain.clone(),
        caller: request.source.app.clone(),
        now: request.now,
    };
    let chain = extend(&call.chain, &call.caller, &call.app)?;
    execute_callee(callee, &call, &chain)
}

fn execute_callee(callee: &Runtime, call: &Call, chain: &str) -> Result<String> {
    let definition = callee
        .artifact()
        .route(&call.operation)
        .map_err(|_| anyhow::anyhow!("delegated_operation_unknown: {}", call.operation))?;
    ensure!(
        definition.kind == "query",
        "delegated_operation_is_not_a_query: {}",
        call.operation
    );
    let actual = schema_digest(callee, &call.operation)?;
    ensure!(
        actual == call.schema_digest,
        "delegated_schema_changed: {} now has {actual}",
        call.operation
    );
    if let Some(expected) = &call.contract_digest {
        let package = callee
            .artifact()
            .contract()
            .export_manifest
            .as_ref()
            .and_then(|manifest| manifest.exports.get(&call.operation))
            .ok_or_else(|| anyhow::anyhow!("delegated_contract_not_exported"))?;
        ensure!(
            &package.digest == expected,
            "delegated_contract_changed: {}",
            call.operation
        );
    }
    // Derived from the caller's invocation and the step within it, so a retried
    // preparation reaches the same invocation of the callee rather than a second
    // one, and a replay of the caller reuses the receipt the first run left.
    let id = format!(
        "dlg_{}",
        &crate::digest(&serde_json::to_vec(&(&call.origin, &call.step))?)["sha256:".len()..][..32]
    );
    let input: Value = serde_json::from_str(&call.input)?;
    // The calling application is who authenticated to the callee; the principal
    // the work is for is unchanged. That is the same pair impersonation records,
    // on the same columns — an application acting for a person is one case of it.
    let authenticated = format!("app:{}", call.caller);
    callee.accept_delegated(
        &call.operation,
        &id,
        &input,
        call.now,
        crate::store::Cause::delegated(&call.actor, chain, &authenticated),
    )?;
    let outcome = callee.execute(&id, crate::store::Fault::None)?;
    ensure!(
        outcome.status == "success",
        "delegated_call_failed: {}",
        outcome.error
    );
    Ok(serde_json::to_string(&outcome.result)?)
}

/// What the caller is asking for, resolved from its grant and its context.
#[derive(Clone)]
pub struct Call {
    pub app: String,
    pub operation: String,
    pub schema_digest: String,
    pub contract_digest: Option<String>,
    pub input: String,
    pub actor: String,
    pub origin: String,
    pub step: String,
    pub chain: String,
    pub caller: String,
    pub now: i64,
}

/// The reviewed shape of one operation: what it accepts and what it returns.
///
/// Derived from the callee's own contract rather than declared beside it, so
/// the digest an operator reviews cannot drift from the schema that will run.
pub fn schema_digest(runtime: &Runtime, operation: &str) -> Result<String> {
    schema_digest_for_artifact(runtime.artifact(), operation)
}

pub fn schema_digest_for_artifact(
    artifact: &crate::artifact::LoadedArtifact,
    operation: &str,
) -> Result<String> {
    let definition = artifact.route(operation)?;
    let schema = &artifact.contract().schema;
    let input = schema.inputs.get(&definition.input_type);
    let output = schema.inputs.get(&definition.output_type);
    Ok(crate::digest(&serde_json::to_vec(&(
        &definition.kind,
        input,
        output,
    ))?))
}
