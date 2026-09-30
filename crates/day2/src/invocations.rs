//! Atomic child-command requests. Scheduling is private; app authors name commands.
use crate::{
    authority::Policy,
    protocol::*,
    store::{self, Runtime},
};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub command: String,
    pub input_type: String,
    pub output_type: String,
    pub payload: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invocation {
    pub id: String,
    pub parent: String,
    pub operation: String,
    pub status: String,
    /// Why a non-success invocation failed. Empty for a success, and for a child
    /// listing, which reads status from the table rather than from an outcome.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub invocation_id: String,
    pub operation: String,
    pub status: String,
    pub result: serde_json::Value,
    pub error: String,
    pub children: Vec<Invocation>,
}

/// Public receipts are actor-bound and contain no prepared facts or provider payloads.
pub fn status(runtime: &Runtime, id: &str, actor: &str) -> Result<Receipt> {
    status_as(runtime, id, actor, None)
}

pub(crate) fn status_on_behalf_of(
    runtime: &Runtime,
    id: &str,
    actor: &str,
    authenticated: &str,
) -> Result<Receipt> {
    status_as(runtime, id, actor, Some(authenticated))
}

fn status_as(
    runtime: &Runtime,
    id: &str,
    actor: &str,
    authenticated: Option<&str>,
) -> Result<Receipt> {
    let mut database = store::open(runtime.db())?;
    let connection = database.transaction()?;
    runtime.check_binding(&connection)?;
    let (operation, owner, artifact, status, outcome): (
        String,
        String,
        String,
        String,
        Option<String>,
    ) = connection
        .query_row(
            "SELECT operation,actor,artifact,status,outcome FROM day2_invocations WHERE id=?1",
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
        )
        .optional()?
        .context(crate::error::Failure::NotFound)?;
    ensure!(owner == actor, crate::error::Failure::Forbidden);
    ensure!(
        artifact == runtime.artifact().id(),
        crate::error::Failure::ArtifactBindingChanged
    );
    let authority = crate::authority_state::authorize_in(&connection, runtime, &operation, actor)?;
    if let Some(authenticated) = authenticated {
        let rule = authority.policy()?.may_act_as(
            authenticated,
            actor,
            "request",
            &runtime.operators()?,
        )?;
        let same_request: bool = connection.query_row(
            "SELECT COALESCE(NULLIF(authenticated,''),actor)=?2 AND delegation_rule=?3
             AND trigger='request' AND caller='' FROM day2_invocations WHERE id=?1",
            params![id, authenticated, rule],
            |row| row.get(0),
        )?;
        ensure!(same_request, crate::error::Failure::Forbidden);
    }
    let blocked = status == "pending" && crate::authority_state::is_blocked(&connection, id)?;
    let outcome = if status == "pending" {
        None
    } else {
        Some(store::completed_outcome(
            &connection,
            id,
            outcome.as_deref(),
            authority.policy()?,
        )?)
    };
    Ok(Receipt {
        invocation_id: id.into(),
        operation,
        status: if blocked { "blocked".into() } else { status },
        result: outcome
            .as_ref()
            .map_or(serde_json::Value::Null, |value| value.result.clone()),
        error: if blocked {
            "authority_policy_changed".into()
        } else {
            outcome.map_or(String::new(), |value| value.error)
        },
        children: children_in(&connection, id)?,
    })
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_command_requests (
        id TEXT PRIMARY KEY REFERENCES day2_invocations(id),
        parent TEXT NOT NULL REFERENCES day2_invocations(id),
        ordinal INTEGER NOT NULL, model TEXT NOT NULL, target TEXT NOT NULL,
        version INTEGER NOT NULL, policy TEXT NOT NULL,
        UNIQUE(parent,ordinal)
    ) STRICT;",
    )?;
    Ok(())
}

pub(crate) fn request(
    runtime: &Runtime,
    connection: &rusqlite::Transaction<'_>,
    origin: &Request,
    instruction: &Instruction,
    policy: &Policy,
    operation: &str,
) -> Result<String> {
    ensure!(
        matches!(instruction.decode()?, crate::protocol::Step::Request { .. }),
        "invalid_command_request"
    );
    let envelope: CommandRequest = serde_json::from_str(&instruction.data)?;
    let definition = runtime.artifact().route(&envelope.command)?;
    ensure!(
        definition.kind == "command"
            && definition.input_type == envelope.input_type
            && definition.output_type == envelope.output_type,
        "command_request_contract_mismatch"
    );
    ensure!(
        policy.operations[operation]
            .commands
            .contains(&envelope.command),
        "command_request_forbidden"
    );
    policy.authorize(&envelope.command, &origin.context.actor)?;
    let authority = crate::authority_state::require_invocation_in(
        connection,
        runtime,
        &origin.context.invocation_id,
        &origin.operation,
        &origin.context.actor,
    )?;
    crate::authority_state::authorize_in(
        connection,
        runtime,
        &envelope.command,
        &origin.context.actor,
    )?;
    let input = serde_json::from_str(&envelope.payload)?;
    let schema = &runtime.artifact().contract().schema;
    schema.inputs[&definition.input_type].validate_input(&input)?;
    if let Some(contract) = &runtime.artifact().contract().app_contract {
        crate::domain::record(
            &contract.domains,
            &schema.inputs[&definition.input_type],
            &input,
        )?;
    }
    let model = schema
        .models
        .get(&instruction.model)
        .context("unknown_command_target")?;
    let row = store::get(connection, &instruction.model, model, instruction.id)?;
    ensure!(
        row.version == instruction.expected_version,
        crate::error::Failure::Conflict
    );
    let start = origin
        .observations
        .iter()
        .rposition(|entry| matches!(entry.instruction.kind.as_str(), "decide" | "complete"))
        .map_or(0, |at| at + 1);
    ensure!(
        origin.observations[start..]
            .iter()
            .any(|entry| store::observed_target(entry, &instruction.model, &row)),
        "command_target_requires_transaction_observation"
    );
    for name in [operation, envelope.command.as_str()] {
        policy.check_read(
            name,
            &instruction.model,
            &origin.context.actor,
            &serde_json::from_str(&row.data)?,
        )?;
    }
    let ordinal = origin
        .observations
        .iter()
        .filter(|entry| entry.instruction.kind == "request")
        .count();
    ensure!(ordinal < 8, "command_request_budget");
    let active: i64 = connection.query_row(
        "SELECT COUNT(*) FROM day2_invocations i WHERE status='pending' AND NOT EXISTS(SELECT 1 FROM day2_authority_blocks b WHERE b.invocation=i.id)",
        [],
        |row| row.get(0),
    )?;
    ensure!(active < 1000, "active_invocation_budget");
    let id = format!(
        "cmd_{}",
        &crate::digest(
            format!(
                "{}\n{}\n{ordinal}",
                runtime.scope(),
                origin.context.invocation_id
            )
            .as_bytes()
        )[7..]
    );
    let ordinal = i64::try_from(ordinal)?;
    // One local transaction includes the business edit, accepted child input,
    // captured target, authority evidence and the parent's final receipt.
    connection.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trigger) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7)", params![id, envelope.command, origin.context.actor, serde_json::to_string(&input)?, runtime.artifact().id(), origin.context.now, crate::audit::Trigger::CommandRequest.as_str()])?;
    crate::authority_state::pin_invocation(connection, &id, &authority.stamp)?;
    crate::resources::inherit_root(connection, &id, &origin.context.invocation_id)?;
    crate::resources::capture_root_budgets(connection, &id, &envelope.command, &authority)?;
    let parent_seed: Vec<u8> = connection.query_row(
        "SELECT seed FROM day2_id_seeds WHERE invocation=?1",
        [&origin.context.invocation_id],
        |row| row.get(0),
    )?;
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(parent_seed);
    hash.update(id.as_bytes());
    connection.execute(
        "INSERT INTO day2_id_seeds VALUES(?1,?2)",
        params![id, hash.finalize().to_vec()],
    )?;
    connection.execute(
        "INSERT INTO day2_command_requests VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            id,
            origin.context.invocation_id,
            ordinal,
            instruction.model,
            instruction.id.to_string(),
            row.version,
            captured_policy(policy)?
        ],
    )?;
    Ok("{}".into())
}

/// A request captures the authority it was admitted under by digest. The value is
/// only ever compared with the policy in force when the request runs, and a full
/// copy per request grew an app's database by the policy's size on every request.
/// The policy serializes deterministically (ordered maps and sets only).
fn captured_policy(policy: &Policy) -> Result<String> {
    Ok(crate::digest(serde_json::to_string(policy)?.as_bytes()))
}

/// Rows written before digests keep the policy itself and compare as before.
fn same_policy(captured: &str, policy: &Policy) -> Result<bool> {
    if captured.starts_with("sha256:") {
        Ok(captured == captured_policy(policy)?)
    } else {
        Ok(serde_json::from_str::<Policy>(captured)? == *policy)
    }
}

pub(crate) fn validate_target(
    runtime: &Runtime,
    connection: &Connection,
    id: &str,
    policy: &Policy,
) -> Result<()> {
    let target: Option<(String, String, i64, String)> = connection
        .query_row(
            "SELECT model,target,version,policy FROM day2_command_requests WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if let Some((model, target, version, captured)) = target {
        ensure!(same_policy(&captured, policy)?, "command_authority_changed");
        let row = store::get(
            connection,
            &model,
            &runtime.artifact().contract().schema.models[&model],
            crate::identity::parse_public_or_legacy(&target)?,
        )?;
        ensure!(row.version == version, crate::error::Failure::Conflict);
    }
    Ok(())
}

pub(crate) fn validate_requests(
    runtime: &Runtime,
    connection: &Connection,
    request: &Request,
) -> Result<()> {
    let parent = &request.context.invocation_id;
    let start = request
        .observations
        .iter()
        .rposition(|entry| entry.instruction.kind == "complete")
        .map_or(0, |at| {
            request.observations[..at]
                .iter()
                .filter(|entry| entry.instruction.kind == "request")
                .count()
        });
    let mut statement = connection.prepare(
        "SELECT model,target,version FROM day2_command_requests WHERE parent=?1 AND ordinal>=?2",
    )?;
    for target in statement.query_map(params![parent, i64::try_from(start)?], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })? {
        let (model, target, version) = target?;
        let row = store::get(
            connection,
            &model,
            &runtime.artifact().contract().schema.models[&model],
            crate::identity::parse_public_or_legacy(&target)?,
        )?;
        ensure!(
            row.version == version,
            "command_target_changed_after_request"
        );
    }
    Ok(())
}

pub fn children(runtime: &Runtime, parent: &str) -> Result<Vec<Invocation>> {
    let connection = store::open(runtime.db())?;
    runtime.check_binding(&connection)?;
    children_in(&connection, parent)
}

fn children_in(connection: &Connection, parent: &str) -> Result<Vec<Invocation>> {
    let mut statement = connection.prepare("SELECT i.id,r.parent,i.operation,CASE WHEN EXISTS(SELECT 1 FROM day2_authority_blocks b WHERE b.invocation=i.id) THEN 'blocked' ELSE i.status END FROM day2_command_requests r JOIN day2_invocations i ON i.id=r.id WHERE r.parent=?1 ORDER BY r.ordinal")?;
    Ok(statement
        .query_map([parent], |row| {
            Ok(Invocation {
                id: row.get(0)?,
                parent: row.get(1)?,
                operation: row.get(2)?,
                status: row.get(3)?,
                error: String::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// A bounded scheduler tick. Multiple workers may race; the invocation receipt
/// and SQLite transaction determine the winner, not process-local ownership.
pub fn drain(runtime: &Runtime, budget: usize) -> Result<Vec<Invocation>> {
    ensure!(budget <= 1000, "invocation_drain_budget");
    let mut completed = Vec::new();
    let mut interrupted = Vec::new();
    let mut first_error = None;
    for _ in 0..budget {
        let connection = store::open(runtime.db())?;
        runtime.check_binding(&connection)?;
        let commands: Vec<_> = runtime
            .artifact()
            .contract()
            .operations
            .iter()
            .filter(|operation| operation.kind == "command")
            .map(|operation| operation.name.clone())
            .collect();
        let next: Option<(String,String,String)> = connection.query_row("SELECT i.id,COALESCE(r.parent,''),i.operation FROM day2_invocations i LEFT JOIN day2_command_requests r ON i.id=r.id WHERE i.status='pending' AND i.artifact=?1 AND NOT EXISTS(SELECT 1 FROM day2_authority_blocks b WHERE b.invocation=i.id) AND i.operation IN (SELECT value FROM json_each(?2)) AND i.id NOT IN (SELECT value FROM json_each(?3)) AND NOT EXISTS(SELECT 1 FROM day2_external_effects e JOIN day2_external_retries q ON q.effect=e.identity WHERE e.invocation=i.id AND e.observation IS NULL AND q.due_ms>?4) ORDER BY i.rowid LIMIT 1", params![runtime.artifact().id(),serde_json::to_string(&commands)?,serde_json::to_string(&interrupted)?,runtime.host().now_ms()?], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        let Some((id, parent, operation)) = next else {
            break;
        };
        let continuing = crate::execution::phase(&connection, &id)?.is_some();
        drop(connection);
        let outcome = match runtime.execute(&id, store::Fault::None) {
            Ok(outcome) => outcome,
            Err(error) => {
                interrupted.push(id);
                first_error.get_or_insert(error);
                continue;
            }
        };
        if outcome.status != "pending" {
            completed.push(Invocation {
                id,
                parent,
                operation,
                status: outcome.status,
                error: outcome.error,
            });
        } else if continuing {
            // A waiting continuation must not monopolize this tick. A newly
            // committed effect boundary is ready to continue in this tick.
            interrupted.push(id);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(completed)
}

#[cfg(test)]
mod captured_policy_tests {
    use super::*;

    fn policy(admin: &str) -> Policy {
        serde_json::from_value(serde_json::json!({
            "version": 1, "admins": [admin],
            "operations": {"app.list": {"actors": ["alice"], "mode": {"kind": "read"}, "models": {}}}
        }))
        .unwrap()
    }

    #[test]
    fn requests_capture_a_digest_and_still_accept_legacy_copies() -> Result<()> {
        let current = policy("owner");
        let captured = captured_policy(&current)?;
        assert!(captured.starts_with("sha256:") && captured.len() == 71);
        assert!(captured.len() < serde_json::to_string(&current)?.len());
        assert!(same_policy(&captured, &current)?);
        assert!(!same_policy(&captured, &policy("other"))?);
        // A row written before digests holds the policy JSON itself.
        let legacy = serde_json::to_string(&current)?;
        assert!(same_policy(&legacy, &current)?);
        assert!(!same_policy(&legacy, &policy("other"))?);
        Ok(())
    }
}
