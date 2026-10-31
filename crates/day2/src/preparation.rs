//! Read-only observation journal. The decision transaction never spans a provider call.
use crate::{protocol::*, store, store::Runtime};
use anyhow::{Context as _, Result, bail, ensure};
use rusqlite::{Connection, params};

const MAX_OBSERVATIONS: usize = 32;
const MAX_OBSERVATION_BYTES: usize = 65_536;

// Results of one SQL unit, not native storage permission. Provider work begins
// only after the transaction and its actual Current scope have both closed.
enum PreparedStep {
    Local(Result<String>),
    Connection {
        ordinal: i64,
        attempt: i64,
    },
    External {
        ordinal: i64,
        attempt: i64,
        capability: Box<crate::capabilities::Authorized>,
        resource: Box<crate::resources::ResourceUse>,
        reservation: crate::budget::Reservation,
        identity: String,
    },
}

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

pub(crate) fn prepare_using(
    runtime: &Runtime,
    id: &str,
    sql: &mut store::ExecutionSql<'_, '_, '_>,
) -> Result<Vec<Observation>> {
    sql.require_runtime(runtime)?;
    if runtime.artifact().contract().format < 13 {
        return Ok(Vec::new());
    }
    let Some((operation, policy, durable, registered_operation, mut request)) =
        sql.decide(|tx| {
            runtime.check_binding(tx)?;
            let (operation, input, actor, artifact, status): (
                String,
                String,
                String,
                String,
                String,
            ) = tx.query_row(
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
                return Ok(store::SqlDecision::Rollback(None));
            }
            let active =
                crate::authority_state::require_invocation_in(tx, runtime, id, &operation, &actor)?;
            let policy = active.policy()?.clone();
            let definition = runtime.artifact().route(&operation)?;
            let durable = definition.kind == "command";
            let registered_operation = definition.name.clone();
            let request = Request {
                operation: operation.clone(),
                input,
                context: store::invocation_context(tx, id)?,
                observations: if durable {
                    recorded(tx, id)?
                } else {
                    Vec::new()
                },
            };
            Ok(store::SqlDecision::Commit(Some((
                operation,
                policy,
                durable,
                registered_operation,
                request,
            ))))
        })?
    else {
        return Ok(Vec::new());
    };
    let mut worker = runtime.worker(Phase::Prepare)?;
    loop {
        // Keep the authority snapshot valid while pure code consumes recorded
        // inputs. Activation can only commit before or after this replay step.
        let response = sql.write(|tx| {
            crate::authority_state::require_invocation_in(
                tx,
                runtime,
                id,
                &operation,
                &request.context.actor,
            )?;
            for observation in &request.observations {
                crate::resources::validate_cached(tx, runtime, &request, observation)?;
            }
            worker.exchange(&request)
        })?;
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
        crate::credential_authority::check_step(runtime.artifact().contract(), &operation, step)?;
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
        if matches!(step, Step::Observe { .. })
            && !crate::oauth::usage::observation(&instruction.model)
            && ![
                crate::resources::BIND,
                crate::resources::ATTENUATE,
                crate::audit::HISTORY,
            ]
            .contains(&instruction.model.as_str())
        {
            sql.require_external_capability()?;
        }
        // Ordered pages record host continuation handles and their invocation
        // pins. Reserve the local writer before reading rows, avoiding a deferred
        // snapshot-to-writer race with another preparation. This transaction still
        // ends before any provider call, and permits no application mutation.
        let (authority, prepared) = sql.write(|tx| {
        runtime.check_binding(tx)?;
        let active = crate::authority_state::require_invocation_in(
            tx,
            runtime,
            id,
            &operation,
            &request.context.actor,
        )?;
        let prepared = if matches!(step, Step::Database(_)) {
            let result = store::effect(
                tx,
                store::StorageContract {
                    schema: &runtime.artifact().contract().schema,
                    domains: &crate::domain::Catalog::new(),
                },
                runtime.scope(),
                &request,
                &instruction,
                store::EffectContext {
                    scope: runtime.scope(),
                    policy: &policy,
                    operation: &registered_operation,
                    entropy: runtime.inputs().entropy.as_ref(),
                },
            );
            PreparedStep::Local(result)
        } else if matches!(step, Step::Observe { .. })
            && [crate::resources::BIND, crate::resources::ATTENUATE]
                .contains(&instruction.model.as_str())
        {
            let result = crate::resources::host_operation(tx, runtime, &request, &instruction)?
                .context("resource_host_operation")?;
            PreparedStep::Local(Ok(result))
        } else if matches!(step, Step::Observe { .. })
            && crate::credential_codegen::observation(&instruction.model)
        {
            let result = crate::managed_credentials::observe(tx, runtime, &request, &instruction);
            PreparedStep::Local(result)
        } else if matches!(step, Step::Observe { .. })
            && crate::oauth::usage::observation(&instruction.model)
        {
            let ordinal = i64::try_from(request.observations.len())?;
            let prior: i64 = tx.query_row(
                "SELECT coalesce(max(attempt),0) FROM day2_observation_attempts WHERE invocation=?1 AND ordinal=?2",
                params![id, ordinal], |row| row.get(0),
            )?;
            if prior >= 3 {
                PreparedStep::Local(Ok(serde_json::json!({"Unavailable":"CapacityDeferred"}).to_string()))
            } else {
                let attempt = prior + 1;
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
                PreparedStep::Connection { ordinal, attempt }
            }
        } else if matches!(step, Step::Observe { .. }) && instruction.model == crate::audit::HISTORY
        {
            // The application's own history: host data under the same write
            // lock, reaching no provider, so there is nothing to reserve, budget
            // or settle. The grant is checked against current authority first,
            // exactly as a provider read's is.
            crate::audit::require_history(active.policy()?, runtime, &operation)?;
            let result = crate::audit::history(tx, runtime, &request, &instruction);
            PreparedStep::Local(result)
        } else if matches!(step, Step::Observe { .. }) {
            // The observation's position in this invocation, which is what makes
            // a name derived here survive a retry: the same read, retried, is
            // the same step and so reaches the same place.
            let ordinal = i64::try_from(request.observations.len())?;
            let capability = crate::capabilities::authorized(
                tx,
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
            crate::resources::record_use(tx, &identity, &resource)?;
            let reservation = crate::resources::reserve_in(
                tx,
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
            PreparedStep::External {
                ordinal,
                attempt,
                capability: Box::new(capability),
                reservation,
                resource: Box::new(resource),
                identity,
            }
        } else {
            bail!("preparation_write_forbidden: {}", instruction.kind);
        };
        Ok((active.stamp, prepared))
        })?;
        let mut admitted_attempt = None;
        let mut provider_usage = None;
        let mut connection_attempt = None;
        let result = match prepared {
            PreparedStep::Local(result) => result,
            PreparedStep::Connection { ordinal, attempt } => {
                connection_attempt = Some((ordinal, attempt));
                sql.connection(&request, &instruction)
            }
            PreparedStep::External {
                ordinal,
                attempt,
                capability,
                resource,
                reservation,
                identity,
            } => {
                let completed = crate::capabilities::observe(runtime, *capability, &identity);
                admitted_attempt = Some((
                    ordinal,
                    attempt,
                    reservation,
                    *resource,
                    identity,
                    completed.correlation,
                ));
                provider_usage = Some(completed.usage);
                completed.result
            }
        };
        let result = match result {
            Err(primary) if sql.check_cleanup().is_err() => return Err(primary),
            other => other,
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
        if let Some((ordinal, attempt)) = connection_attempt {
            sql.write(|tx| {
            crate::execution::check_settlement_binding(tx, runtime, id, &authority)?;
            tx.execute(
                "UPDATE day2_observation_attempts SET observation=?1 WHERE invocation=?2 AND ordinal=?3 AND attempt=?4",
                params![encoded, id, ordinal, attempt],
            )?;
            Ok(())
            })?;
        }
        if let Some((ordinal, attempt, reservation, _, identity, correlation)) = admitted_attempt {
            // Retain provider knowledge even if policy changed during the call.
            // A separate reauthorization below gates use by application code.
            sql.write(|tx| {
            crate::execution::check_settlement_binding(tx, runtime, id, &authority)?;
            crate::resources::record_correlation_in(tx, &identity, &correlation)?;
            tx.execute(
                "UPDATE day2_observation_attempts SET observation=?1 WHERE invocation=?2 AND ordinal=?3 AND attempt=?4",
                params![encoded, id, ordinal, attempt],
            )?;
            crate::resources::settle_in(
                tx,
                &reservation,
                provider_usage.context("provider_usage_missing")?,
            )?;
            Ok(())
            })?;
        }
        let winner = sql.write(|tx| {
            runtime.check_binding(tx)?;
            crate::authority_state::require_invocation_in(
                tx,
                runtime,
                id,
                &operation,
                &request.context.actor,
            )?;
            if !durable {
                return Ok(observation);
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
            Ok(winner)
        })?;
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
                "get" | "page" | "find" | "select_page" | "count"
            )
        {
            let current = store::effect(
                connection,
                store::StorageContract {
                    schema: &runtime.artifact().contract().schema,
                    domains: &crate::domain::Catalog::new(),
                },
                runtime.scope(),
                request,
                &observation.instruction,
                store::EffectContext {
                    scope: runtime.scope(),
                    policy,
                    operation,
                    entropy: runtime.inputs().entropy.as_ref(),
                },
            )?;
            ensure!(
                current == observation.result,
                crate::error::Failure::PreparationConflict
            );
        }
    }
    Ok(())
}
