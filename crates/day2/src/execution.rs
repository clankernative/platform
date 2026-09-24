//! Persisted command phases and dependent external effects. App transactions and
//! provider calls never share a database transaction or a distributed commit.
use crate::{
    protocol::*,
    store::{self, Fault, Runtime},
};
use anyhow::{Context as _, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_execution (
        invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id),
        phase TEXT NOT NULL CHECK(phase IN ('effects','complete')),
        trace TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS day2_external_effects (
        invocation TEXT NOT NULL REFERENCES day2_invocations(id),
        ordinal INTEGER NOT NULL, identity TEXT NOT NULL UNIQUE,
        instruction TEXT NOT NULL, observation TEXT,
        PRIMARY KEY(invocation,ordinal)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS day2_external_attempts (
        identity TEXT PRIMARY KEY,
        effect TEXT NOT NULL REFERENCES day2_external_effects(identity),
        ordinal INTEGER NOT NULL CHECK(ordinal > 0),
        authority_epoch TEXT NOT NULL,
        authority_revision INTEGER NOT NULL CHECK(authority_revision > 0),
        observation TEXT,
        UNIQUE(effect,ordinal)
    ) STRICT;",
    )?;
    Ok(())
}

pub(crate) fn load(connection: &Connection, id: &str) -> Result<Option<(Phase, Trace)>> {
    let value: Option<(String, String)> = connection
        .query_row(
            "SELECT phase,trace FROM day2_execution WHERE invocation=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    value
        .map(|(phase, trace)| Ok((Phase::persisted(&phase)?, serde_json::from_str(&trace)?)))
        .transpose()
}

pub(crate) fn begin(runtime: &Runtime, connection: &Transaction<'_>, trace: &Trace) -> Result<()> {
    ensure!(
        trace
            .request
            .observations
            .last()
            .is_some_and(|entry| entry.instruction.only_kind("effects") && entry.error.is_empty()),
        "missing_effect_boundary"
    );
    connection.execute(
        "INSERT INTO day2_execution VALUES(?1,'effects',?2)",
        params![
            trace.request.context.invocation_id,
            serde_json::to_string(trace)?
        ],
    )?;
    let cause: String = connection
        .query_row(
            "SELECT trigger FROM day2_invocations WHERE id=?1",
            [&trace.request.context.invocation_id],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| crate::audit::Trigger::Request.as_str().to_owned());
    let cause = match cause.as_str() {
        "schedule" => crate::audit::Trigger::Schedule,
        "command_request" => crate::audit::Trigger::CommandRequest,
        _ => crate::audit::Trigger::Request,
    };
    crate::audit::record_attempt(
        connection,
        runtime,
        crate::audit::Attempt {
            kind: crate::audit::AttemptKind::ExecutionAttempt,
            // The cause is the invocation's own, recorded when it was admitted;
            // an execution attempt does not get to decide what caused it.
            trigger: cause,
            identity: &trace.request.context.invocation_id,
            actor: &trace.request.context.actor,
            initiator: &trace.request.context.actor,
            operation: &trace.request.operation,
            outcome: crate::audit::AttemptOutcome::Accepted,
            reason: None,
            at_ms: trace
                .request
                .context
                .now
                .checked_mul(1000)
                .context("audit_clock")?,
        },
    )?;
    Ok(())
}

fn save(
    runtime: &Runtime,
    previous: &Trace,
    next: &Trace,
    phase: Phase,
    settlement: bool,
) -> Result<()> {
    let phase = phase.persistence_code()?;
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if settlement {
        let authority = previous
            .guard
            .as_ref()
            .and_then(|guard| guard.authority.as_ref())
            .context("settlement_authority_missing")?;
        check_settlement_binding(
            &tx,
            runtime,
            &previous.request.context.invocation_id,
            authority,
        )?;
    } else {
        runtime.check_binding(&tx)?;
        require_authority(&tx, runtime, previous)?;
    }
    // A competing executor may already have advanced. The next iteration reloads
    // the winner's transcript; it never overwrites a more advanced execution.
    tx.execute("UPDATE day2_execution SET phase=?1,trace=?2 WHERE invocation=?3 AND phase='effects' AND trace=?4", params![phase, serde_json::to_string(next)?, next.request.context.invocation_id, serde_json::to_string(previous)?])?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn advance(runtime: &Runtime, id: &str, fault: Fault) -> Result<bool> {
    if runtime.artifact().contract().format < 13 {
        return Ok(false);
    }
    let connection = store::open(runtime.db())?;
    let Some((phase, _)) = load(&connection, id)? else {
        return Ok(false);
    };
    if phase == Phase::Complete {
        return Ok(true);
    }
    drop(connection);
    let mut worker = runtime.worker(Phase::Effects)?;
    for _ in 0..64 {
        let Some(work) = claim_with_worker(runtime, id, &mut worker)? else {
            return Ok(true);
        };
        let permit = admit_dispatch(runtime, &work)?;
        let result = perform(runtime, permit)?;
        if result.called_provider && fault == Fault::AfterExternal(work.ordinal as usize + 1) {
            return Err(fault.interruption("simulated_loss_after_provider_acceptance"));
        }
        settle(runtime, &work, result)?;
    }
    bail!("external_step_budget")
}

/// A journaled intent. This is not authority to call the provider.
pub(crate) struct Work {
    database: std::path::PathBuf,
    trace: Trace,
    instruction: Instruction,
    ordinal: i64,
    identity: String,
}

#[cfg(test)]
impl Work {
    pub(crate) fn from_intent_for_tests(
        runtime: &Runtime,
        trace: Trace,
        instruction: Instruction,
        ordinal: i64,
        identity: String,
    ) -> Self {
        Self {
            database: runtime.db().to_path_buf(),
            trace,
            instruction,
            ordinal,
            identity,
        }
    }
}

pub(crate) struct Performed {
    observation: Observation,
    called_provider: bool,
    attempt: Option<String>,
    effect: String,
    reservation: Option<crate::budget::Reservation>,
    usage: crate::resources::ProviderUsage,
    correlation: Vec<crate::integrations::ExchangeCorrelation>,
}

/// A single admitted provider attempt, deliberately not Clone. Its commit is
/// the revocation cutoff: an already admitted attempt may finish after revoke.
pub(crate) struct DispatchPermit {
    database: std::path::PathBuf,
    artifact: String,
    scope: String,
    instruction: Instruction,
    effect: String,
    attempt: Option<String>,
    capability: Option<crate::capabilities::Authorized>,
    recorded: Option<Observation>,
    reservation: Option<crate::budget::Reservation>,
}

fn require_authority(
    connection: &Connection,
    runtime: &Runtime,
    trace: &Trace,
) -> Result<crate::authority_state::ActiveAuthority> {
    let active = crate::authority_state::require_invocation_in(
        connection,
        runtime,
        &trace.request.context.invocation_id,
        &trace.request.operation,
        &trace.request.context.actor,
    )?;
    ensure!(
        trace.guard.as_ref().is_some_and(|guard| {
            guard.authority.as_ref() == Some(&active.stamp)
                && active.policy().is_ok_and(|policy| &guard.policy == policy)
        }),
        crate::error::Failure::EffectAuthorityChanged
    );
    for observation in &trace.request.observations {
        crate::resources::validate_cached(connection, runtime, &trace.request, observation)?;
    }
    Ok(active)
}

pub(crate) fn claim(runtime: &Runtime, id: &str) -> Result<Option<Work>> {
    let connection = store::open(runtime.db())?;
    let Some((phase, _)) = load(&connection, id)? else {
        return Ok(None);
    };
    if phase == Phase::Complete {
        return Ok(None);
    }
    drop(connection);
    let mut worker = runtime.worker(Phase::Effects)?;
    claim_with_worker(runtime, id, &mut worker)
}

fn claim_with_worker(
    runtime: &Runtime,
    id: &str,
    worker: &mut crate::host::Session,
) -> Result<Option<Work>> {
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (phase, current) = load(&tx, id)?.context("execution_journal_missing")?;
    if phase == Phase::Complete {
        return Ok(None);
    }
    let mut trace = current;
    ensure!(
        trace.artifact == runtime.artifact().id() && trace.scope == runtime.scope(),
        "execution_binding_changed"
    );
    require_authority(&tx, runtime, &trace)?;
    let response: Response = worker.exchange(&trace.request)?;
    tx.commit()?;
    let reply = response.decode()?;
    ensure!(
        response.consumed == trace.request.observations.len(),
        "effect_replay_mismatch"
    );
    ensure!(
        !trace
            .request
            .observations
            .iter()
            .any(|observation| !observation.error.is_empty())
            || matches!(reply, Reply::Failed(_)),
        "effect_failure_must_abort"
    );
    let previous = trace.clone();
    if matches!(reply, Reply::Failed(_)) {
        save(runtime, &previous, &trace, Phase::Complete, false)?;
        return Ok(None);
    }
    let Reply::Pending(step) = reply else {
        bail!("missing_completion_boundary")
    };
    Phase::Effects.advance(step)?;
    let instruction = response.instruction.clone();
    if step == Step::Boundary(Boundary::Complete) {
        trace.request.observations.push(Observation {
            instruction,
            result: "{}".into(),
            error: String::new(),
        });
        save(runtime, &previous, &trace, Phase::Complete, false)?;
        return Ok(None);
    }
    ensure!(
        matches!(step, Step::External { .. }),
        "external_phase_database_io_forbidden"
    );
    let declaration = runtime
        .artifact()
        .contract()
        .app_contract
        .as_ref()
        .and_then(|definition| definition.operations.get(&trace.request.operation))
        .context("command_contract_missing")?;
    ensure!(
        declaration
            .execution
            .effects
            .iter()
            .any(|effect| effect.kind == "external" && effect.command == instruction.model),
        "undeclared_external_effect"
    );
    let ordinal = trace
        .request
        .observations
        .iter()
        .filter(|entry| entry.instruction.kind == "external")
        .count();
    ensure!(
        ordinal < 32 && trace.request.observations.len() < 64,
        "external_effect_budget"
    );
    let ordinal = i64::try_from(ordinal)?;
    let identity = format!(
        "fx_{}",
        &crate::digest(format!("{}\n{id}\n{ordinal}", runtime.scope()).as_bytes())[7..]
    );
    let encoded = serde_json::to_string(&instruction)?;
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    runtime.check_binding(&tx)?;
    let active = require_authority(&tx, runtime, &trace)?;
    crate::capabilities::authorized(
        &tx,
        runtime,
        &trace.request,
        &instruction,
        active.policy()?,
        &identity,
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO day2_external_effects VALUES(?1,?2,?3,?4,NULL)",
        params![id, ordinal, identity, encoded],
    )?;
    let stored: String = tx.query_row(
        "SELECT instruction FROM day2_external_effects WHERE invocation=?1 AND ordinal=?2",
        params![id, ordinal],
        |row| row.get(0),
    )?;
    ensure!(stored == encoded, "external_intent_mismatch");
    tx.commit()?;

    Ok(Some(Work {
        database: runtime.db().to_path_buf(),
        trace: previous,
        instruction,
        ordinal,
        identity,
    }))
}

fn check_work(runtime: &Runtime, work: &Work) -> Result<()> {
    ensure!(
        work.database == runtime.db()
            && work.trace.artifact == runtime.artifact().id()
            && work.trace.scope == runtime.scope(),
        "execution_binding_changed"
    );
    Ok(())
}

/// Settlement authenticates the original journal, not the currently active
/// artifact. An activation must not erase outcomes of previously admitted calls.
pub(crate) fn check_settlement_binding(
    connection: &Connection,
    runtime: &Runtime,
    invocation: &str,
    authority: &crate::authority_state::AuthorityStamp,
) -> Result<()> {
    let scope: String =
        connection.query_row("SELECT value FROM day2_meta WHERE key='scope'", [], |row| {
            row.get(0)
        })?;
    let artifact: String = connection.query_row(
        "SELECT artifact FROM day2_invocations WHERE id=?1",
        [invocation],
        |row| row.get(0),
    )?;
    ensure!(
        scope == runtime.scope() && artifact == runtime.artifact().id(),
        "execution_binding_changed"
    );
    ensure!(
        crate::authority_state::invocation_stamp(connection, invocation)? == *authority,
        "settlement_authority_mismatch"
    );
    Ok(())
}

/// Reserve one attempt under the same writer lock used by policy activation.
/// Every retry gets a new attempt identity and retains the original effect ID.
pub(crate) fn admit_dispatch(runtime: &Runtime, work: &Work) -> Result<DispatchPermit> {
    check_work(runtime, work)?;
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    runtime.check_binding(&tx)?;
    let active = require_authority(&tx, runtime, &work.trace)?;
    let capability = crate::capabilities::authorized(
        &tx,
        runtime,
        &work.trace.request,
        &work.instruction,
        active.policy()?,
        &work.identity,
    )?;
    let (instruction, recorded): (String, Option<String>) = tx.query_row(
        "SELECT instruction,observation FROM day2_external_effects WHERE identity=?1 AND invocation=?2 AND ordinal=?3",
        params![work.identity, work.trace.request.context.invocation_id, work.ordinal],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        instruction == serde_json::to_string(&work.instruction)?,
        "external_intent_mismatch"
    );
    let recorded = recorded
        .map(|value| serde_json::from_str::<Observation>(&value))
        .transpose()?;
    if let Some(recorded) = &recorded {
        crate::resources::validate_cached(&tx, runtime, &work.trace.request, recorded)?;
    }
    let mut reservation = None;
    let attempt = if recorded.is_none() {
        let prior: i64 = tx.query_row(
            "SELECT coalesce(max(ordinal),0) FROM day2_external_attempts WHERE effect=?1",
            [&work.identity],
            |row| row.get(0),
        )?;
        ensure!(
            prior == 0 || capability.retries_are_idempotent(),
            "external_outcome_requires_reconciliation"
        );
        let ordinal = prior.checked_add(1).context("external_attempt_overflow")?;
        let attempt = format!("{}_attempt_{ordinal}", work.identity);
        crate::resources::record_use(&tx, &attempt, capability.resource())?;
        reservation = Some(crate::resources::reserve_in(
            &tx,
            runtime,
            &work.trace.request,
            &work.instruction,
            &attempt,
            capability.resource(),
            capability.quote(),
        )?);
        tx.execute(
            "INSERT INTO day2_external_attempts VALUES(?1,?2,?3,?4,?5,NULL)",
            params![
                attempt,
                work.identity,
                ordinal,
                active.stamp.epoch,
                i64::try_from(active.stamp.revision)?
            ],
        )?;
        Some(attempt)
    } else {
        None
    };
    tx.commit()?;
    Ok(DispatchPermit {
        database: runtime.db().to_path_buf(),
        artifact: runtime.artifact().id().to_owned(),
        scope: runtime.scope().to_owned(),
        instruction: work.instruction.clone(),
        effect: work.identity.clone(),
        attempt,
        capability: recorded.is_none().then_some(capability),
        recorded,
        reservation,
    })
}

/// The permit is consumed without reopening authority. Provider calls never
/// hold the application transaction and may outlive a subsequent revocation.
pub(crate) fn perform(runtime: &Runtime, permit: DispatchPermit) -> Result<Performed> {
    ensure!(
        permit.database == runtime.db()
            && permit.artifact == runtime.artifact().id()
            && permit.scope == runtime.scope(),
        "execution_binding_changed"
    );
    if let Some(observation) = permit.recorded {
        return Ok(Performed {
            observation,
            called_provider: false,
            attempt: None,
            effect: permit.effect,
            reservation: None,
            correlation: Vec::new(),
            usage: crate::resources::ProviderUsage {
                known: true,
                ..Default::default()
            },
        });
    }
    let capability = permit.capability.context("dispatch_permit_missing")?;
    let resource = capability.resource().clone();
    let completed = crate::capabilities::execute(
        runtime,
        capability,
        &permit.effect,
        permit
            .attempt
            .as_deref()
            .context("dispatch_attempt_missing")?,
    );
    let result = completed.result.and_then(|result| {
        crate::resources::validate_result(&resource, &result)?;
        Ok(result)
    });
    let observation = match result {
        Ok(result) => Observation {
            instruction: permit.instruction,
            result,
            error: String::new(),
        },
        Err(error) => Observation {
            instruction: permit.instruction,
            result: String::new(),
            error: crate::error::observation_code(&error),
        },
    };
    let observation = crate::resources::bounded_observation(observation)?;
    Ok(Performed {
        observation,
        called_provider: completed.usage.dispatched,
        attempt: permit.attempt,
        effect: permit.effect,
        reservation: permit.reservation,
        usage: completed.usage,
        correlation: completed.correlation,
    })
}

/// Record knowledge of an already performed effect even when authority changed
/// while the provider was responding. The next claim/perform reauthorizes.
pub(crate) fn settle(runtime: &Runtime, work: &Work, result: Performed) -> Result<()> {
    check_work(runtime, work)?;
    ensure!(result.effect == work.identity, "external_attempt_mismatch");
    let encoded = serde_json::to_string(&result.observation)?;
    ensure!(encoded.len() <= 65_536, "external_result_budget");
    let id = &work.trace.request.context.invocation_id;
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let authority = work
        .trace
        .guard
        .as_ref()
        .and_then(|guard| guard.authority.as_ref())
        .context("settlement_authority_missing")?;
    check_settlement_binding(&tx, runtime, id, authority)?;
    if let Some(reservation) = &result.reservation {
        crate::resources::settle_in(&tx, reservation, result.usage)?;
    }
    if let Some(attempt) = result.attempt {
        crate::resources::record_correlation_in(&tx, &attempt, &result.correlation)?;
        tx.execute("UPDATE day2_external_attempts SET observation=?1 WHERE identity=?2 AND effect=?3 AND observation IS NULL", params![encoded, attempt, work.identity])?;
        let settled: String = tx.query_row(
            "SELECT observation FROM day2_external_attempts WHERE identity=?1 AND effect=?2",
            params![attempt, work.identity],
            |row| row.get(0),
        )?;
        ensure!(settled == encoded, "external_attempt_result_mismatch");
    }
    tx.execute("UPDATE day2_external_effects SET observation=?1 WHERE invocation=?2 AND ordinal=?3 AND observation IS NULL",
        params![encoded, id, work.ordinal])?;
    let winner: String = tx.query_row(
        "SELECT observation FROM day2_external_effects WHERE invocation=?1 AND ordinal=?2 AND identity=?3",
        params![id, work.ordinal, work.identity], |row| row.get(0))?;
    let observation: Observation = serde_json::from_str(&winner)?;
    ensure!(
        observation.instruction == work.instruction,
        "external_intent_mismatch"
    );
    tx.commit()?;
    let mut next = work.trace.clone();
    next.request.observations.push(observation);
    save(runtime, &work.trace, &next, Phase::Effects, true)
}
