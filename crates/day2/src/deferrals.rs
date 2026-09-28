//! Durable command deferrals, admitted only when they become due.
use crate::{
    authority::Policy,
    protocol::*,
    store::{self, Runtime},
};
use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

pub const MAX_DEFERRAL_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const MAX_UNOFFERED_DEFERRALS: i64 = 1000;
const OFFER_BATCH: i64 = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deferral {
    pub command: String,
    pub input_type: String,
    pub output_type: String,
    pub payload: String,
    #[serde(default)]
    pub due: Option<u64>,
    #[serde(default)]
    pub delay: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offered {
    pub id: String,
    pub outcome: String,
    pub reason: String,
}

pub(crate) fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_deferrals(
        id TEXT PRIMARY KEY, parent TEXT NOT NULL REFERENCES day2_invocations(id),
        ordinal INTEGER NOT NULL, command TEXT NOT NULL, input_type TEXT NOT NULL,
        output_type TEXT NOT NULL, input TEXT NOT NULL, actor TEXT NOT NULL,
        model TEXT NOT NULL, target TEXT NOT NULL, due_ms INTEGER NOT NULL,
        offered_ms INTEGER, UNIQUE(parent,ordinal)) STRICT;
        CREATE INDEX IF NOT EXISTS day2_deferrals_due ON day2_deferrals(offered_ms,due_ms);",
    )?;
    Ok(())
}

pub(crate) fn defer(
    runtime: &Runtime,
    connection: &rusqlite::Transaction<'_>,
    origin: &Request,
    instruction: &Instruction,
    policy: &Policy,
    operation: &str,
) -> Result<String> {
    ensure!(
        matches!(instruction.decode()?, Step::Defer { .. }),
        "invalid_deferral"
    );
    let envelope: Deferral = serde_json::from_str(&instruction.data)?;
    let definition = runtime.artifact().route(&envelope.command)?;
    ensure!(
        definition.kind == "command"
            && definition.input_type == envelope.input_type
            && definition.output_type == envelope.output_type,
        "deferral_contract_mismatch"
    );
    ensure!(
        policy
            .operations
            .get(operation)
            .is_some_and(|entry| entry.commands.contains(&envelope.command)),
        "deferral_not_permitted"
    );
    policy.authorize(&envelope.command, &origin.context.actor)?;
    crate::authority_state::require_invocation_in(
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
    let input: serde_json::Value = serde_json::from_str(&envelope.payload)?;
    let schema = &runtime.artifact().contract().schema;
    schema.inputs[&definition.input_type].validate_input(&input)?;
    let model = schema
        .models
        .get(&instruction.model)
        .context("unknown_deferral_target")?;
    let row = store::get(connection, &instruction.model, model, instruction.id)?;
    ensure!(
        crate::invocations::observed_target_in_decision(
            &origin.observations,
            &instruction.model,
            &row,
        ),
        "deferral_target_requires_transaction_observation"
    );
    for name in [operation, envelope.command.as_str()] {
        policy.check_read(
            name,
            &instruction.model,
            &origin.context.actor,
            &serde_json::from_str(&row.data)?,
        )?;
    }
    let due = match (envelope.due, envelope.delay) {
        (Some(due), None) => i64::try_from(due).context("deferral_due_overflow")?,
        (None, Some(delay)) => origin
            .context
            .now
            .checked_add(i64::try_from(delay).context("deferral_due_overflow")?)
            .context("deferral_due_overflow")?,
        _ => anyhow::bail!("invalid_deferral_time"),
    };
    ensure!(due >= origin.context.now, "deferral_due_in_past");
    ensure!(
        due <= origin.context.now.saturating_add(MAX_DEFERRAL_SECONDS),
        "deferral_due_too_far"
    );
    let due_ms = due.checked_mul(1000).context("deferral_due_overflow")?;
    let outstanding: i64 = connection.query_row(
        "SELECT COUNT(*) FROM day2_deferrals WHERE offered_ms IS NULL",
        [],
        |row| row.get(0),
    )?;
    ensure!(outstanding < MAX_UNOFFERED_DEFERRALS, "deferral_budget");
    let ordinal = crate::invocations::checked_child_ordinal(&origin.observations)?;
    let id = format!(
        "dfr_{}",
        &crate::digest(
            format!(
                "{}\n{}\n{ordinal}",
                runtime.scope(),
                origin.context.invocation_id
            )
            .as_bytes()
        )[7..]
    );
    connection.execute("INSERT INTO day2_deferrals(id,parent,ordinal,command,input_type,output_type,input,actor,model,target,due_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![id,origin.context.invocation_id,i64::try_from(ordinal)?,envelope.command,envelope.input_type,envelope.output_type,serde_json::to_string(&input)?,origin.context.actor,instruction.model,instruction.id.to_string(),due_ms])?;
    Ok("{}".into())
}

pub fn tick(runtime: &Runtime, now_ms: i64) -> Result<Vec<Offered>> {
    let connection = store::open(runtime.db())?;
    runtime.check_binding(&connection)?;
    let mut statement = connection.prepare(
        "SELECT id,parent,command,input_type,output_type,input,actor FROM day2_deferrals WHERE offered_ms IS NULL AND due_ms<=?1 ORDER BY due_ms,id LIMIT ?2",
    )?;
    let due = statement
        .query_map(params![now_ms, OFFER_BATCH], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    drop(connection);
    let mut offered = Vec::new();
    for (id, parent, command, input_type, output_type, input, actor) in due {
        let mut database = store::open(runtime.db())?;
        let tx = database.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        runtime.check_binding(&tx)?;
        let already: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_deferrals WHERE id=?1 AND offered_ms IS NOT NULL) OR EXISTS(SELECT 1 FROM day2_invocations WHERE id=?1)", [&id], |row| row.get(0))?;
        if already {
            tx.commit()?;
            continue;
        }
        let operation = runtime.artifact().route(&command).ok();
        let authority = crate::authority_state::current(&tx)?;
        tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trigger) VALUES(?1,?2,?3,?4,?5,?6,'pending','deferral')", params![id, command, actor, input, runtime.artifact().id(), now_ms.div_euclid(1000)])?;
        let mut reason = None;
        let parsed_input = serde_json::from_str::<serde_json::Value>(&input);
        let compatible = operation.is_some_and(|operation| {
            operation.kind == "command"
                && operation.input_type == input_type
                && operation.output_type == output_type
        }) && parsed_input.as_ref().is_ok_and(|value| {
            runtime
                .artifact()
                .contract()
                .schema
                .inputs
                .get(&input_type)
                .is_some_and(|schema| schema.validate_input(value).is_ok())
        });
        if !compatible {
            reason = Some("deferral_incompatible");
        } else if crate::authority_state::authorize_in(&tx, runtime, &command, &actor).is_err() {
            reason = Some("deferral_forbidden");
        }
        // Admitted or blocked, the offered invocation belongs to its parent's
        // root, so a later reissue stays within the same root-wide budgets.
        crate::resources::inherit_root(&tx, &id, &parent)?;
        if let Some(block_reason) = reason {
            crate::authority_state::block_invocation(&tx, &id, block_reason)?;
        } else {
            crate::authority_state::pin_invocation(&tx, &id, &authority.stamp)?;
            crate::resources::capture_root_budgets(&tx, &id, &command, &authority)?;
            let parent_seed: Vec<u8> = tx.query_row(
                "SELECT seed FROM day2_id_seeds WHERE invocation=?1",
                [&parent],
                |row| row.get(0),
            )?;
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            hash.update(parent_seed);
            hash.update(id.as_bytes());
            tx.execute(
                "INSERT INTO day2_id_seeds VALUES(?1,?2)",
                params![id, hash.finalize().to_vec()],
            )?;
        }
        tx.execute(
            "UPDATE day2_deferrals SET offered_ms=?1 WHERE id=?2 AND offered_ms IS NULL",
            params![now_ms, id],
        )?;
        tx.commit()?;
        offered.push(Offered {
            id,
            outcome: if reason.is_some() {
                "blocked"
            } else {
                "admitted"
            }
            .into(),
            reason: reason.unwrap_or("").into(),
        });
    }
    Ok(offered)
}

pub(crate) fn fence_restored(connection: &Connection, artifact: &str) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_deferrals')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(());
    }

    let pending = {
        let mut statement = connection.prepare(
            "SELECT id,command,input,actor,parent FROM day2_deferrals WHERE offered_ms IS NULL ORDER BY id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if pending.is_empty() {
        return Ok(());
    }
    let offered_ms = crate::resource_admin::now_ms()?;
    for (id, command, input, actor, parent) in pending {
        connection.execute(
            "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status,trigger) VALUES(?1,?2,?3,?4,?5,?6,'pending','deferral')",
            params![id, command, actor, input, artifact, offered_ms.div_euclid(1000)],
        )?;
        crate::resources::inherit_root(connection, &id, &parent)?;
        crate::authority_state::block_invocation(connection, &id, "deferral_restored")?;
        connection.execute(
            "UPDATE day2_deferrals SET offered_ms=?1 WHERE id=?2 AND offered_ms IS NULL",
            params![offered_ms, id],
        )?;
    }
    Ok(())
}

pub(crate) fn check_compatible(
    connection: &Connection,
    target: &crate::artifact::LoadedArtifact,
) -> Result<()> {
    let mut statement = connection.prepare("SELECT id,command,input_type,output_type,input FROM day2_deferrals WHERE offered_ms IS NULL ORDER BY id")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut incompatible = Vec::new();
    for row in rows {
        let (id, command, input_type, output_type, input) = row?;
        let compatible = target.route(&command).is_ok_and(|definition| {
            definition.kind == "command"
                && definition.input_type == input_type
                && definition.output_type == output_type
        }) && target
            .contract()
            .schema
            .inputs
            .get(&input_type)
            .is_some_and(|schema| {
                serde_json::from_str::<serde_json::Value>(&input)
                    .is_ok_and(|value| schema.validate_input(&value).is_ok())
            });
        if !compatible {
            incompatible.push(id);
        }
    }
    ensure!(
        incompatible.is_empty(),
        "activation_incompatible_deferrals: {}",
        incompatible.join(",")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferral_bounds_are_thirty_days() {
        assert_eq!(MAX_DEFERRAL_SECONDS, 2_592_000);
        assert_eq!(MAX_UNOFFERED_DEFERRALS, 1000);
    }
}
