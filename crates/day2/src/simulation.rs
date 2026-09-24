//! Host-side simulation controls. These are not Roc capabilities or app inputs.
//! The same admitted runtime, SQLite journals and capability adapter execute each
//! action; the scheduler supplies entropy, time and worker failure observations.
use crate::{
    execution,
    host::{Host, WorkerAction},
    protocol::{Phase, Request, Response},
    store::Runtime,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    path::Path,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkerFailure {
    Timeout,
    Crash,
}

struct State {
    now_ms: i64,
    failures: VecDeque<WorkerFailure>,
    events: Vec<Value>,
}

struct Inputs {
    seed: [u8; 32],
    state: Mutex<State>,
}

impl Host for Inputs {
    fn entropy(&self, scope: &str, invocation: &str) -> Result<[u8; 32]> {
        // Independent identities do not depend on incidental PRNG draw order.
        let encoded =
            serde_json::to_vec(&("day2-simulation-entropy-v1", self.seed, scope, invocation))?;
        let seed: [u8; 32] = Sha256::digest(encoded).into();
        self.state
            .lock()
            .unwrap()
            .events
            .push(json!({"entropy":invocation,"scope":scope,"seed":seed}));
        Ok(seed)
    }

    fn now_ms(&self) -> Result<i64> {
        Ok(self.state.lock().unwrap().now_ms)
    }

    fn worker_action(&self, _phase: Phase, _request: &Request) -> Result<WorkerAction> {
        Ok(match self.state.lock().unwrap().failures.pop_front() {
            Some(WorkerFailure::Timeout) => WorkerAction::Timeout,
            Some(WorkerFailure::Crash) => WorkerAction::Crash,
            None => WorkerAction::Run,
        })
    }

    fn record_exchange(
        &self,
        phase: Phase,
        request: &Request,
        result: &Result<Response>,
    ) -> Result<()> {
        let result = match result {
            Ok(response) => serde_json::to_value(response)?,
            Err(error) => json!({"error":crate::error::observation_code(error)}),
        };
        self.state
            .lock()
            .unwrap()
            .events
            .push(json!({"phase":format!("{phase:?}"),"request":request,"response":result}));
        Ok(())
    }

    fn deadline(&self, _phase: Phase, _started: Instant) -> Result<()> {
        // Real watchdogs remain in Worker. A real adapter failure fails the
        // campaign; modeled deadlines arrive through worker_action instead.
        Ok(())
    }
}

pub struct Simulation {
    runtime: Runtime,
    inputs: Arc<Inputs>,
}

/// A journaled external intent, obtained only from a validated invocation.
pub struct Effect {
    work: execution::Work,
}

/// Provider knowledge which may be lost before settlement, independently of DB state.
pub struct EffectResult {
    work: execution::Work,
    result: execution::Performed,
}

/// A particular admitted provider attempt. Keeping admission separate makes the
/// exact revocation cutoff and a pause before provider I/O reproducible.
pub struct AdmittedEffect {
    work: execution::Work,
    permit: execution::DispatchPermit,
}

impl Simulation {
    /// Every provider runs offline, including the three that reach a network in
    /// live mode. Before their simulations existed, a campaign touching Slack,
    /// Snowflake or OpenAI had no offline path and failed at the socket; the
    /// whole provider surface is now deterministic and journaled.
    ///
    /// Offline is the default because a campaign that can reach a network is not
    /// a deterministic campaign. A caller that has deliberately installed its own
    /// provider host wants [`Simulation::with_scripted_providers`] instead — this
    /// constructor replaces one rather than running against it.
    pub fn new(runtime: Runtime, seed: [u8; 32], now_ms: i64) -> Result<Self> {
        let database = runtime.db().to_path_buf();
        let scope = runtime.scope().to_owned();
        let simulated = crate::integration_host::Host::simulated(&database, &scope);
        Self::build(runtime.with_integrations(simulated), seed, now_ms)
    }

    /// Keep the provider host the caller installed. For tests that script a
    /// transport in order to observe adapter accounting against a planned
    /// sequence of replies; the host input controls — clock, entropy, worker
    /// failures — are identical to [`Simulation::new`].
    pub fn with_scripted_providers(runtime: Runtime, seed: [u8; 32], now_ms: i64) -> Result<Self> {
        Self::build(runtime, seed, now_ms)
    }

    fn build(runtime: Runtime, seed: [u8; 32], now_ms: i64) -> Result<Self> {
        ensure!(
            (0..=253_402_300_799_000).contains(&now_ms),
            "invalid_simulation_clock"
        );
        let inputs = Arc::new(Inputs {
            seed,
            state: Mutex::new(State {
                now_ms,
                failures: VecDeque::new(),
                events: Vec::new(),
            }),
        });
        Ok(Self {
            runtime: runtime.with_host(inputs.clone()),
            inputs,
        })
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn set_time(&self, now_ms: i64) -> Result<()> {
        let mut state = self.inputs.state.lock().unwrap();
        ensure!(
            (state.now_ms..=253_402_300_799_000).contains(&now_ms),
            "invalid_simulation_clock"
        );
        state.now_ms = now_ms;
        state.events.push(json!({"time_ms":now_ms}));
        Ok(())
    }

    pub fn fail_next_worker(&self, failure: WorkerFailure) {
        let mut state = self.inputs.state.lock().unwrap();
        state.failures.push_back(failure);
        state.events.push(json!({"next_worker_failure":failure}));
    }

    pub fn claim_effect(&self, invocation: &str) -> Result<Option<Effect>> {
        self.inputs
            .state
            .lock()
            .unwrap()
            .events
            .push(json!({"claim":invocation}));
        Ok(execution::claim(&self.runtime, invocation)?.map(|work| Effect { work }))
    }

    pub fn perform_effect(&self, effect: Effect) -> Result<EffectResult> {
        self.perform_admitted_effect(self.admit_effect(effect)?)
    }

    pub fn admit_effect(&self, effect: Effect) -> Result<AdmittedEffect> {
        let permit = execution::admit_dispatch(&self.runtime, &effect.work)?;
        self.inputs
            .state
            .lock()
            .unwrap()
            .events
            .push(json!({"provider":"admitted"}));
        Ok(AdmittedEffect {
            work: effect.work,
            permit,
        })
    }

    pub fn perform_admitted_effect(&self, effect: AdmittedEffect) -> Result<EffectResult> {
        let result = execution::perform(&self.runtime, effect.permit)?;
        self.inputs
            .state
            .lock()
            .unwrap()
            .events
            .push(json!({"provider":"performed"}));
        Ok(EffectResult {
            work: effect.work,
            result,
        })
    }

    pub fn settle_effect(&self, result: EffectResult) -> Result<()> {
        execution::settle(&self.runtime, &result.work, result.result)?;
        self.inputs
            .state
            .lock()
            .unwrap()
            .events
            .push(json!({"provider":"settled"}));
        Ok(())
    }

    /// Exercise the same native handle boundary with a hostile worker payload.
    /// These host controls never grant an operation or dispatch provider I/O.
    pub fn resource_probe(
        &self,
        invocation: &str,
        capability: &str,
        mut data: Value,
    ) -> Result<Value> {
        if capability == crate::resources::BIND {
            data["invocation"] = json!(invocation);
        }
        let mut connection = crate::store::open(self.runtime.db())?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        let (operation, input) = tx.query_row(
            "SELECT operation,input FROM day2_invocations WHERE id=?1",
            [invocation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let request = Request {
            operation,
            input,
            context: crate::store::invocation_context(&tx, invocation)?,
            observations: Vec::new(),
        };
        let instruction: crate::protocol::Instruction = serde_json::from_value(json!({
            "kind":if crate::capabilities::WRITES.contains(&capability) {"external"} else {"observe"},
            "model":capability,"id":"","expected_version":0,"data":data.to_string(),
            "filter_field":"","filter_value":"","after":"","limit":0,
        }))?;
        let result =
            match crate::resources::host_operation(&tx, &self.runtime, &request, &instruction)? {
                Some(result) => serde_json::from_str(&result)?,
                None => {
                    let active = crate::authority_state::require_invocation_in(
                        &tx,
                        &self.runtime,
                        invocation,
                        &request.operation,
                        &request.context.actor,
                    )?;
                    crate::capabilities::authorized(
                        &tx,
                        &self.runtime,
                        &request,
                        &instruction,
                        active.policy()?,
                        "",
                    )?;
                    json!({"allowed":true})
                }
            };
        tx.commit()?;
        Ok(result)
    }

    /// Canonical logical state, including partial journals and independent provider
    /// state. Retry/audit histories are compared only for identical scenarios.
    pub fn snapshot(&self) -> Result<Value> {
        // Enumerated from the provider registry rather than listed here, so a
        // provider admitted with a simulation appears in the campaign's diff
        // without anyone remembering to add it. An absent world is Null, which
        // is how a scenario that never configured that provider reads.
        let mut snapshot = serde_json::Map::new();
        snapshot.insert("journal".into(), database(self.runtime.db())?);
        for world in crate::capabilities::LOCAL_PROVIDER_DATABASES {
            let path = self.runtime.db().with_file_name(world);
            let state = if path.exists() {
                database(&path)?
            } else {
                Value::Null
            };
            snapshot.insert(snapshot_key(world), state);
        }
        snapshot.insert(
            "host".into(),
            json!(self.inputs.state.lock().unwrap().events),
        );
        Ok(Value::Object(snapshot))
    }
}

/// The snapshot key for a provider world, derived from its file name so a new
/// provider needs no entry here. The notification mailbox keeps its original
/// `provider` key: recorded campaign evidence and existing scenarios name it,
/// and renaming it would invalidate replay against stored traces.
fn snapshot_key(world: &str) -> String {
    if world == "notifications.sqlite" {
        return "provider".into();
    }
    format!("{}_provider", world.split('.').next().unwrap_or(world))
}

fn database(path: &Path) -> Result<Value> {
    use rusqlite::{Connection, OpenFlags, types::ValueRef};
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let transaction = connection.transaction()?;
    let tables = transaction.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut snapshot = serde_json::Map::new();
    for table in tables {
        let name = table.replace('"', "\"\"");
        let columns = transaction
            .prepare(&format!("SELECT * FROM \"{name}\" LIMIT 0"))?
            .column_count();
        let order = (1..=columns)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = transaction.prepare(&format!(
            "SELECT * FROM \"{name}\" ORDER BY {order} LIMIT 10001"
        ))?;
        let mut rows = statement.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            ensure!(values.len() < 10_000, "simulation_snapshot_budget");
            let mut fields = Vec::new();
            for column in 0..columns {
                fields.push(match row.get_ref(column)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(value) => json!(value),
                    ValueRef::Real(value) => json!(value),
                    ValueRef::Text(value) => {
                        json!(std::str::from_utf8(value).context("journal UTF-8")?)
                    }
                    ValueRef::Blob(value) => json!({"bytes":value}),
                });
            }
            values.push(json!(fields));
        }
        snapshot.insert(table, json!(values));
    }
    transaction.commit()?;
    Ok(Value::Object(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_is_per_invocation_and_clock_is_explicit() -> Result<()> {
        let inputs = Inputs {
            seed: [42; 32],
            state: Mutex::new(State {
                now_ms: 7000,
                failures: VecDeque::new(),
                events: vec![],
            }),
        };
        let expected = inputs.entropy("scope", "one")?;
        assert_ne!(expected, inputs.entropy("scope", "two")?);
        assert_eq!(expected, inputs.entropy("scope", "one")?);
        assert_ne!(expected, inputs.entropy("other", "one")?);
        assert_eq!(inputs.now_ms()?, 7000);
        Ok(())
    }
}
