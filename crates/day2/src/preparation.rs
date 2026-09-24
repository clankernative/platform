//! Read-only observation journal. The decision transaction never spans a provider call.
use crate::{protocol::*, store, store::Runtime};
use anyhow::{Context as _, Result, bail, ensure};
use rusqlite::{Connection, TransactionBehavior, params};

const MAX_OBSERVATIONS: usize = 32;
const MAX_OBSERVATION_BYTES: usize = 65_536;

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_preparation (
            invocation TEXT NOT NULL REFERENCES day2_invocations(id),
            ordinal INTEGER NOT NULL, observation TEXT NOT NULL,
            PRIMARY KEY(invocation,ordinal)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_observation_attempts (
            invocation TEXT NOT NULL REFERENCES day2_invocations(id),
            ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
            attempt INTEGER NOT NULL CHECK(attempt > 0),
            instruction TEXT NOT NULL,
            authority_epoch TEXT NOT NULL,
            authority_revision INTEGER NOT NULL CHECK(authority_revision > 0),
            observation TEXT,
            PRIMARY KEY(invocation,ordinal,attempt)
        ) STRICT;",
    )?;
    Ok(())
}

fn recorded(connection: &Connection, id: &str) -> Result<Vec<Observation>> {
    let mut statement = connection.prepare(
        "SELECT ordinal,observation FROM day2_preparation WHERE invocation=?1 ORDER BY ordinal",
    )?;
    let mut observations = Vec::new();
    for row in statement.query_map([id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })? {
        let (ordinal, encoded) = row?;
        let ordinal = usize::try_from(ordinal)?;
        ensure!(ordinal == observations.len(), "preparation_journal_gap");
        ensure!(
            ordinal < MAX_OBSERVATIONS && encoded.len() <= MAX_OBSERVATION_BYTES,
            "preparation_budget"
        );
        observations.push(serde_json::from_str(&encoded)?);
    }
    Ok(observations)
}

pub(crate) fn prepare(runtime: &Runtime, id: &str) -> Result<Vec<Observation>> {
    if runtime.artifact().contract().format < 13 {
        return Ok(Vec::new());
    }
    let mut connection = store::open(runtime.db())?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    runtime.check_binding(&tx)?;
    upgrade(&tx)?;
    let (operation, input, actor, artifact, status): (String, String, String, String, String) = tx
        .query_row(
            "SELECT operation,input,actor,artifact,status FROM day2_invocations WHERE id=?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    ensure!(
        artifact == runtime.artifact().id(),
        "pinned_artifact_unavailable"
    );
    if status != "pending" {
        // Completed receipts have their own authority-aware retrieval path.
        // Do not turn an old receipt into blocked unfinished work here.
        return Ok(Vec::new());
    }
    let active =
        crate::authority_state::require_invocation_in(&tx, runtime, id, &operation, &actor)?;
    let policy = active.policy()?.clone();
    let definition = runtime.artifact().route(&operation)?;
    let durable = definition.kind == "command";
    let registered_operation = definition.name.clone();
    let mut request = Request {
        operation: operation.clone(),
        input,
        context: store::invocation_context(&tx, id)?,
        observations: if durable {
            recorded(&tx, id)?
        } else {
            Vec::new()
        },
    };
    tx.commit()?;
    let mut worker = runtime.worker(Phase::Prepare)?;
    loop {
        // Keep the authority snapshot valid while pure code consumes recorded
        // inputs. Activation can only commit before or after this replay step.
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::authority_state::require_invocation_in(
            &tx,
            runtime,
            id,
            &operation,
            &request.context.actor,
        )?;
        for observation in &request.observations {
            crate::resources::validate_cached(&tx, runtime, &request, observation)?;
        }
        let response = worker.exchange(&request)?;
        tx.commit()?;
        let reply = response.decode()?;
        ensure!(
            response.consumed == request.observations.len(),
            "preparation_replay_mismatch"
        );
        ensure!(
            !request
                .observations
                .iter()
                .any(|observation| !observation.error.is_empty())
                || matches!(reply, Reply::Failed(_)),
            "preparation_failure_must_abort"
        );
        if matches!(reply, Reply::Failed(_)) {
            // The ordinary transaction runner records the typed failure and audit.
            return Ok(request.observations);
        }
        let Reply::Pending(step) = reply else {
            bail!("missing_decision_boundary")
        };
        Phase::Prepare.advance(step)?;
        let instruction = response.instruction.clone();
        if step == Step::Boundary(Boundary::Decide) {
            // This observation belongs to the decision transaction, not the frozen
            // preparation journal. Revalidation may refuse this boundary.
            request.observations.push(Observation {
                instruction,
                result: "{}".into(),
                error: String::new(),
            });
            return Ok(request.observations);
        }
        ensure!(
            request.observations.len() < MAX_OBSERVATIONS,
            "preparation_step_budget"
        );
        // Ordered pages record host continuation handles and their invocation
        // pins. Reserve the local writer before reading rows, avoiding a deferred
        // snapshot-to-writer race with another preparation. This transaction still
        // ends before any provider call, and permits no application mutation.
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        runtime.check_binding(&tx)?;
        let active = crate::authority_state::require_invocation_in(
            &tx,
            runtime,
            id,
            &operation,
            &request.context.actor,
        )?;
        let mut admitted_attempt = None;
        let mut provider_usage = None;
        let result = if matches!(step, Step::Database(_)) {
            let result = store::effect(
                &tx,
                &runtime.artifact().contract().schema,
                runtime.scope(),
                &request,
                &instruction,
                &policy,
                &registered_operation,
            );
            tx.commit()?;
            result
        } else if matches!(step, Step::Observe { .. })
            && [crate::resources::BIND, crate::resources::ATTENUATE]
                .contains(&instruction.model.as_str())
        {
            let result = crate::resources::host_operation(&tx, runtime, &request, &instruction)?
                .context("resource_host_operation")?;
            tx.commit()?;
            Ok(result)
        } else if matches!(step, Step::Observe { .. }) {
            // The observation's position in this invocation, which is what makes
            // a name derived here survive a retry: the same read, retried, is
            // the same step and so reaches the same place.
            let ordinal = i64::try_from(request.observations.len())?;
            let capability = crate::capabilities::authorized(
                &tx,
                runtime,
                &request,
                &instruction,
                active.policy()?,
                &format!("ob_{id}_{ordinal}"),
            )?;
            let prior: i64 = tx.query_row(
                "SELECT coalesce(max(attempt),0) FROM day2_observation_attempts WHERE invocation=?1 AND ordinal=?2",
                params![id, ordinal], |row| row.get(0),
            )?;
            let attempt = prior
                .checked_add(1)
                .context("observation_attempt_overflow")?;
            let identity = format!(
                "observation_{}",
                &crate::digest(&serde_json::to_vec(&(
                    runtime.scope(),
                    &active.stamp,
                    id,
                    ordinal,
                    attempt
                ))?)[7..]
            );
            let resource = capability.resource().clone();
            crate::resources::record_use(&tx, &identity, &resource)?;
            let reservation = crate::resources::reserve_in(
                &tx,
                runtime,
                &request,
                &instruction,
                &identity,
                &resource,
                capability.quote(),
            )?;
            tx.execute(
                "INSERT INTO day2_observation_attempts VALUES(?1,?2,?3,?4,?5,?6,NULL)",
                params![
                    id,
                    ordinal,
                    attempt,
                    serde_json::to_string(&instruction)?,
                    active.stamp.epoch,
                    i64::try_from(active.stamp.revision)?
                ],
            )?;
            // Release the application database before crossing a provider boundary.
            tx.commit()?;
            let completed = crate::capabilities::observe(runtime, capability, &identity);
            admitted_attempt = Some((
                ordinal,
                attempt,
                reservation,
                resource,
                identity,
                completed.correlation,
            ));
            provider_usage = Some(completed.usage);
            completed.result
        } else {
            bail!("preparation_write_forbidden: {}", instruction.kind);
        };
        let result = if let Some((_, _, _, resource, _, _)) = &admitted_attempt {
            result.and_then(|result| {
                crate::resources::validate_result(resource, &result)?;
                Ok(result)
            })
        } else {
            result
        };
        let observation = match result {
            Ok(result) => Observation {
                instruction,
                result,
                error: String::new(),
            },
            Err(error) => Observation {
                instruction,
                result: String::new(),
                error: crate::error::observation_code(&error),
            },
        };
        let observation = crate::resources::bounded_observation(observation)?;
        let encoded = serde_json::to_string(&observation)?;
        ensure!(
            encoded.len() <= MAX_OBSERVATION_BYTES,
            "preparation_result_budget"
        );
        if let Some((ordinal, attempt, reservation, _, identity, correlation)) = admitted_attempt {
            // Retain provider knowledge even if policy changed during the call.
            // A separate reauthorization below gates use by application code.
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            crate::execution::check_settlement_binding(&tx, runtime, id, &active.stamp)?;
            crate::resources::record_correlation_in(&tx, &identity, &correlation)?;
            tx.execute(
                "UPDATE day2_observation_attempts SET observation=?1 WHERE invocation=?2 AND ordinal=?3 AND attempt=?4",
                params![encoded, id, ordinal, attempt],
            )?;
            crate::resources::settle_in(
                &tx,
                &reservation,
                provider_usage.context("provider_usage_missing")?,
            )?;
            tx.commit()?;
        }
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        runtime.check_binding(&tx)?;
        crate::authority_state::require_invocation_in(
            &tx,
            runtime,
            id,
            &operation,
            &request.context.actor,
        )?;
        if !durable {
            tx.commit()?;
            request.observations.push(observation);
            continue;
        }
        let ordinal = i64::try_from(request.observations.len())?;
        tx.execute(
            "INSERT OR IGNORE INTO day2_preparation VALUES(?1,?2,?3)",
            params![id, ordinal, encoded],
        )?;
        // Concurrent read-only executors must use the first journaled observation,
        // even if their live reads returned different values.
        let winner: String = tx.query_row(
            "SELECT observation FROM day2_preparation WHERE invocation=?1 AND ordinal=?2",
            params![id, ordinal],
            |row| row.get(0),
        )?;
        let winner: Observation = serde_json::from_str(&winner)?;
        ensure!(
            winner.instruction == observation.instruction,
            "preparation_branch_mismatch"
        );
        tx.commit()?;
        request.observations.push(winner);
    }
}

/// Conservative read-set validation also covers bounded predicate reads. A
/// prepared row never authenticates a mutation or child invocation by itself.
pub(crate) fn validate_local(
    runtime: &Runtime,
    connection: &Connection,
    request: &Request,
    policy: &crate::authority::Policy,
    operation: &str,
) -> Result<()> {
    for observation in &request.observations {
        if observation.instruction.kind == "decide" {
            break;
        }
        if observation.error.is_empty()
            && matches!(
                observation.instruction.kind.as_str(),
                "get" | "page" | "find" | "select_page"
            )
        {
            let current = store::effect(
                connection,
                &runtime.artifact().contract().schema,
                runtime.scope(),
                request,
                &observation.instruction,
                policy,
                operation,
            )?;
            ensure!(
                current == observation.result,
                crate::error::Failure::PreparationConflict
            );
        }
    }
    Ok(())
}
