//! Host-only SQLite regressions for how traces store their policy and how
//! compaction treats external-effect observations. No app artifact, worker or
//! Roc build is involved: each test opens a real database with the platform
//! schema and an activated authority, and writes journal rows the way the host
//! does.
use super::*;
use crate::{
    authority::{Mode, OperationPolicy, Policy as AccessPolicy},
    authority_state::{ActiveAuthority, AuthorityDocument},
    protocol::{Context, Observation},
};
use std::collections::{BTreeMap, BTreeSet};

const SCOPE: &str = "synthetic-scope";
const ARTIFACT: &str = "synthetic-artifact";

/// A policy shaped like a real app's: every operation, each with its own grant.
/// The admin address is what the tests look for to tell an embedded copy apart.
fn access_policy(admin: &str) -> AccessPolicy {
    AccessPolicy {
        version: 1,
        admins: BTreeSet::from([admin.into()]),
        delegations: BTreeMap::new(),
        constraints: BTreeMap::new(),
        operations: (0..32)
            .map(|index| {
                (
                    format!("synthetic.operation_{index:02}"),
                    OperationPolicy {
                        actors: (0..24)
                            .map(|actor| format!("person-{actor:02}@example.com"))
                            .collect(),
                        mode: Mode::CurrentState,
                        models: BTreeMap::new(),
                        commands: BTreeSet::new(),
                        observations: BTreeSet::new(),
                        effects: BTreeSet::new(),
                    },
                )
            })
            .collect(),
    }
}

fn active(policy: AccessPolicy) -> ActiveAuthority {
    ActiveAuthority {
        stamp: AuthorityStamp {
            epoch: crate::digest(b"journal-test-epoch"),
            revision: 1,
        },
        document: AuthorityDocument {
            managed_secrets: None,
            security: None,
            hosted_domain: None,
            resources: Default::default(),
            credentials: Default::default(),
            enabled: true,
            readers: BTreeSet::new(),
            writers: BTreeSet::new(),
            policy: Some(policy),
        },
        artifact_id: ARTIFACT.into(),
        artifact_path: "/admitted/synthetic".into(),
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    db: std::path::PathBuf,
    active: ActiveAuthority,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let db = directory.path().join("app.sqlite");
        let active = active(access_policy("owner@example.com"));
        let mut connection = crate::store::open(&db)?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        tx.execute_batch(crate::store::PLATFORM_DDL)?;
        tx.execute(
            "INSERT INTO day2_meta(key,value) VALUES('scope',?1)",
            [SCOPE],
        )?;
        crate::audit::upgrade(&tx)?;
        crate::execution::upgrade(&tx)?;
        crate::preparation::upgrade(&tx)?;
        crate::authority_state::upgrade(&tx)?;
        crate::authority_state::store_record_in(&tx, &active, "operator", "journal-test")?;
        tx.commit()?;
        Ok(Self {
            _directory: directory,
            db,
            active,
        })
    }

    fn connection(&self) -> Result<Connection> {
        crate::store::open(&self.db)
    }

    fn policy(&self) -> &AccessPolicy {
        self.active.policy().unwrap()
    }

    fn trace(&self, id: &str, status: &str) -> Trace {
        Trace {
            format: 2,
            artifact: ARTIFACT.into(),
            scope: SCOPE.into(),
            request: Request {
                operation: "synthetic.operation_00".into(),
                input: "{}".into(),
                context: Context {
                    invocation_id: id.into(),
                    actor: "person-00@example.com".into(),
                    now: 0,
                    authentication: "request".into(),
                    caller: Vec::new(),
                    authenticated: String::new(),
                    delegation_rule: String::new(),
                },
                observations: Vec::new(),
            },
            outcome: if status == "failure" {
                Outcome {
                    status: status.into(),
                    result: serde_json::Value::Null,
                    error: "synthetic_failure".into(),
                }
            } else {
                Outcome {
                    status: status.into(),
                    result: serde_json::json!({"id": id}),
                    error: String::new(),
                }
            },
            guard: Some(ExecutionGuard {
                policy: self.policy().clone(),
                authority: Some(self.active.stamp.clone()),
                precondition_row: None,
                error: String::new(),
            }),
        }
    }

    /// Accept an invocation under the active authority and, unless it is still
    /// pending, complete it with its trace in the stored form, as the host does.
    fn invocation(&self, id: &str, now: i64, status: &str) -> Result<Trace> {
        let trace = self.trace(id, status);
        let mut connection = self.connection()?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        tx.execute(
            "INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status)
             VALUES(?1,?2,?3,'{}',?4,?5,'pending')",
            params![
                id,
                trace.request.operation,
                trace.request.context.actor,
                ARTIFACT,
                now
            ],
        )?;
        crate::authority_state::pin_invocation(&tx, id, &self.active.stamp)?;
        if status != "pending" {
            tx.execute(
                "UPDATE day2_invocations SET status=?2,outcome=?3,trace=?4 WHERE id=?1",
                params![
                    id,
                    status,
                    serde_json::to_string(&trace.outcome)?,
                    store_trace(&tx, &trace)?
                ],
            )?;
            tx.execute(
                "INSERT INTO day2_audit VALUES(?1,?2,?3,?4,?5)",
                params![
                    id,
                    trace.request.context.actor,
                    trace.request.operation,
                    status,
                    now
                ],
            )?;
        }
        tx.commit()?;
        Ok(trace)
    }

    /// One external effect with a provider response, plus its attempts: one
    /// settled with the same response and one whose response was lost.
    fn effect(&self, id: &str, response: Option<&str>) -> Result<Option<String>> {
        let connection = self.connection()?;
        let instruction = crate::protocol::Instruction {
            kind: "external".into(),
            model: "synthetic.send.v1".into(),
            ..Default::default()
        };
        let observation = response
            .map(|result| {
                serde_json::to_string(&Observation {
                    instruction: instruction.clone(),
                    result: result.into(),
                    error: String::new(),
                })
            })
            .transpose()?;
        let identity = format!("fx_{id}");
        connection.execute(
            "INSERT INTO day2_external_effects VALUES(?1,0,?2,?3,?4)",
            params![
                id,
                identity,
                serde_json::to_string(&instruction)?,
                observation
            ],
        )?;
        for (ordinal, settled) in [(1, None), (2, observation.as_deref())] {
            connection.execute(
                "INSERT INTO day2_external_attempts VALUES(?1,?2,?3,?4,1,?5)",
                params![
                    format!("{identity}_attempt_{ordinal}"),
                    identity,
                    ordinal,
                    self.active.stamp.epoch,
                    settled
                ],
            )?;
        }
        Ok(observation)
    }

    fn effects(&self, id: &str) -> Result<(Option<String>, Vec<Option<String>>)> {
        let connection = self.connection()?;
        let effect = connection.query_row(
            "SELECT observation FROM day2_external_effects WHERE invocation=?1",
            [id],
            |row| row.get(0),
        )?;
        let attempts = connection
            .prepare(
                "SELECT a.observation FROM day2_external_attempts a
                 JOIN day2_external_effects e ON e.identity=a.effect
                 WHERE e.invocation=?1 ORDER BY a.ordinal",
            )?
            .query_map([id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok((effect, attempts))
    }

    fn stored(&self, id: &str) -> Result<Option<String>> {
        Ok(self.connection()?.query_row(
            "SELECT trace FROM day2_invocations WHERE id=?1",
            [id],
            |row| row.get(0),
        )?)
    }

    fn policies(&self) -> Result<i64> {
        Ok(self
            .connection()?
            .query_row("SELECT count(*) FROM day2_trace_policies", [], |row| {
                row.get(0)
            })?)
    }

    fn outcome(&self, id: &str, policy: &AccessPolicy) -> Result<Outcome> {
        let connection = self.connection()?;
        let outcome: Option<String> = connection.query_row(
            "SELECT outcome FROM day2_invocations WHERE id=?1",
            [id],
            |row| row.get(0),
        )?;
        crate::store::completed_outcome(&connection, id, outcome.as_deref(), policy)
    }
}

fn compacted_marker(raw: &str) -> String {
    serde_json::json!({"compacted": crate::digest(raw.as_bytes())}).to_string()
}

#[test]
fn policy_is_stored_once_across_many_invocations_and_every_reader_resolves_it() -> Result<()> {
    let fixture = Fixture::new()?;
    let embedded = serde_json::to_string(fixture.policy())?.len();
    let mut traces = Vec::new();
    for index in 0..200 {
        let status = if index % 2 == 0 { "success" } else { "failure" };
        traces.push(fixture.invocation(&format!("done-{index}"), 0, status)?);
    }
    let pending = fixture.invocation("pending", 0, "pending")?;
    let connection = fixture.connection()?;
    connection.execute(
        "INSERT INTO day2_execution VALUES('pending','effects',?1)",
        [store_trace(&connection, &pending)?],
    )?;

    assert_eq!(fixture.policies()?, 1, "one policy, however many traces");
    let digest = policy_digest(fixture.policy())?;
    for trace in &traces {
        let id = &trace.request.context.invocation_id;
        let stored = fixture.stored(id)?.context("stored trace")?;
        assert!(
            stored.len() < embedded,
            "a stored trace is smaller than the policy it names"
        );
        assert!(!stored.contains("owner@example.com"), "{stored}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stored)?["guard"]["policy"],
            digest.as_str()
        );
        // Inspection, replay and evidence read the resolved trace.
        assert_eq!(&load_trace(&fixture.connection()?, &stored)?, trace);
        // The receipt path resolves it and compares it with the active policy.
        assert_eq!(&fixture.outcome(id, fixture.policy())?, &trace.outcome);
    }
    // The effects phase reads its journal through the same resolver.
    let (_, resumed) =
        crate::execution::load(&fixture.connection()?, "pending")?.context("execution journal")?;
    assert_eq!(resumed, pending);

    // A changed policy is still a changed policy: the reference does not weaken
    // the receipt's authority check.
    let mut changed = fixture.policy().clone();
    changed.admins.insert("someone-else@example.com".into());
    let stale = fixture.outcome("done-0", &changed).unwrap_err();
    assert_eq!(
        crate::error::classify(&stale),
        crate::error::Failure::ReceiptPolicyChanged,
        "{stale:#}"
    );
    Ok(())
}

#[test]
fn trace_policy_references_fail_closed() -> Result<()> {
    let fixture = Fixture::new()?;
    let trace = fixture.invocation("done", 0, "success")?;
    let stored = fixture.stored("done")?.context("stored trace")?;
    let connection = fixture.connection()?;
    let digest = policy_digest(fixture.policy())?;

    // A trace with its policy embedded is not a stored trace.
    let embedded = load_trace(&connection, &serde_json::to_string(&trace)?).unwrap_err();
    assert!(
        format!("{embedded:#}").contains("invalid_invocation_trace"),
        "{embedded:#}"
    );

    // A reference to a policy that was never stored.
    let unknown = stored.replace(&digest, &crate::digest(b"unknown"));
    let missing = load_trace(&connection, &unknown).unwrap_err();
    assert!(
        format!("{missing:#}").contains("trace_policy_missing"),
        "{missing:#}"
    );

    // A policy row whose bytes are not its canonical serialisation.
    let spaced = serde_json::to_string_pretty(fixture.policy())?;
    let spaced_digest = crate::digest(spaced.as_bytes());
    connection.execute(
        "INSERT INTO day2_trace_policies VALUES(?1,?2)",
        params![spaced_digest, spaced],
    )?;
    let noncanonical =
        load_trace(&connection, &stored.replace(&digest, &spaced_digest)).unwrap_err();
    assert!(
        format!("{noncanonical:#}").contains("trace_policy_digest_mismatch"),
        "{noncanonical:#}"
    );

    // An edited policy row no longer matches its digest, and every reader
    // refuses it: the receipt path, the trace reader and compaction.
    connection.execute(
        "UPDATE day2_trace_policies SET policy=?2 WHERE digest=?1",
        params![
            digest,
            serde_json::to_string(&access_policy("intruder@example.com"))?
        ],
    )?;
    let tampered = load_trace(&connection, &stored).unwrap_err();
    assert!(
        format!("{tampered:#}").contains("trace_policy_digest_mismatch"),
        "{tampered:#}"
    );
    assert!(fixture.outcome("done", fixture.policy()).is_err());
    // Compaction refuses to turn the tampered reference into a receipt.
    assert!(compact_before(&fixture.db, 50, 500).is_err());
    assert!(fixture.stored("done")?.is_some());
    // A removed row leaves every trace that names it unreadable, never resolved
    // to something else.
    connection.execute("DELETE FROM day2_trace_policies WHERE digest=?1", [&digest])?;
    let removed = load_trace(&connection, &stored).unwrap_err();
    assert!(
        format!("{removed:#}").contains("trace_policy_missing"),
        "{removed:#}"
    );
    assert!(fixture.outcome("done", fixture.policy()).is_err());
    Ok(())
}

#[test]
fn compaction_replaces_effect_observations_and_completed_outcomes_still_replay() -> Result<()> {
    let fixture = Fixture::new()?;
    let response = r#"{"provider":"synthetic","body":"a large provider response"}"#;
    let done = fixture.invocation("done", 0, "success")?;
    let observed = fixture
        .effect("done", Some(response))?
        .context("observation")?;
    fixture.invocation("unresolved", 0, "failure")?;
    fixture.effect("unresolved", None)?;
    fixture.invocation("pending", 0, "pending")?;
    let pending = fixture.effect("pending", Some(response))?;
    fixture.invocation("young", 100, "success")?;
    let young = fixture.effect("young", Some(response))?;

    assert_eq!(compact_before(&fixture.db, 50, 500)?, 2);

    // The completed invocation's responses are digests now, never NULL: an
    // effect without an observation reads as one whose outcome is unknown.
    let marker = compacted_marker(&observed);
    assert_eq!(
        fixture.effects("done")?,
        (Some(marker.clone()), vec![None, Some(marker.clone())])
    );
    assert!(
        serde_json::from_str::<Observation>(&marker).is_err(),
        "a reader that needs the response fails closed"
    );
    let unresolved: bool = fixture.connection()?.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_external_effects WHERE invocation='done' AND observation IS NULL)",
        [],
        |row| row.get(0),
    )?;
    assert!(!unresolved, "a settled effect stays settled");
    // An effect that never settled stays unknown, as it was.
    assert_eq!(fixture.effects("unresolved")?, (None, vec![None, None]));
    // Pending and young work are untouched.
    assert_eq!(
        fixture.effects("pending")?,
        (pending.clone(), vec![None, pending])
    );
    assert_eq!(
        fixture.effects("young")?,
        (young.clone(), vec![None, young])
    );

    // A retry of the completed command is still answered with its outcome, and
    // the receipt's policy digest is the reference the trace held.
    assert!(fixture.stored("done")?.is_none());
    assert_eq!(fixture.outcome("done", fixture.policy())?, done.outcome);
    let receipt: String = fixture.connection()?.query_row(
        "SELECT receipt FROM day2_invocations WHERE id='done'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        Receipt::parse(&receipt)?.policy,
        Some(policy_digest(fixture.policy())?)
    );
    let mut changed = fixture.policy().clone();
    changed.admins.clear();
    assert_eq!(
        crate::error::classify(&fixture.outcome("done", &changed).unwrap_err()),
        crate::error::Failure::ReceiptPolicyChanged
    );

    // Idempotent: nothing left to compact, and the digests stay as they are.
    assert_eq!(compact_before(&fixture.db, 50, 500)?, 0);
    assert_eq!(
        fixture.effects("done")?,
        (Some(marker.clone()), vec![None, Some(marker)])
    );
    Ok(())
}

#[test]
fn schema_upgrade_rewrites_embedded_policies_and_compacts_earlier_receipts() -> Result<()> {
    let fixture = Fixture::new()?;
    // Write the journal as a host before schema 11 left it: full policies in
    // every trace, and a compacted invocation that kept its provider response.
    let done = fixture.invocation("done", 0, "success")?;
    let pending = fixture.invocation("pending", 0, "pending")?;
    fixture.invocation("compacted", 0, "success")?;
    let observed = fixture
        .effect("compacted", Some(r#"{"provider":"synthetic"}"#))?
        .context("observation")?;
    {
        let connection = fixture.connection()?;
        connection.execute(
            "UPDATE day2_invocations SET input='{}',trace=?2,receipt=NULL WHERE id=?1",
            params!["done", serde_json::to_string(&done)?],
        )?;
        connection.execute(
            "UPDATE day2_invocations SET trace=NULL,input='',receipt='{\"format\":1,\"input\":\"x\",\"policy\":null}' WHERE id='compacted'",
            [],
        )?;
        connection.execute(
            "UPDATE day2_external_effects SET observation=?1 WHERE invocation='compacted'",
            [&observed],
        )?;
        connection.execute(
            "UPDATE day2_external_attempts SET observation=?1 WHERE ordinal=2 AND effect='fx_compacted'",
            [&observed],
        )?;
        connection.execute(
            "INSERT INTO day2_execution VALUES('pending','effects',?1)",
            [serde_json::to_string(&pending)?],
        )?;
        connection.execute(
            "UPDATE day2_invocations SET trace=?1 WHERE id='pending'",
            [serde_json::to_string(&pending)?],
        )?;
        connection.execute_batch(
            "DROP TABLE day2_trace_policies;
             UPDATE day2_meta SET value='10' WHERE key='host_schema';",
        )?;
    }
    let upgrade = || -> Result<()> {
        let mut connection = fixture.connection()?;
        let tx = crate::write_queue::immediate(&mut connection)?;
        crate::audit::upgrade(&tx)?;
        tx.commit()?;
        Ok(())
    };
    upgrade()?;
    let connection = fixture.connection()?;
    crate::audit::require_current_schema(&connection)?;
    // One schema object: security admission charges each object on every scan.
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE tbl_name='day2_trace_policies'",
            [],
            |row| row.get::<_, i64>(0),
        )?,
        1
    );
    assert_eq!(fixture.policies()?, 1);
    for (id, trace) in [("done", &done), ("pending", &pending)] {
        let stored = fixture.stored(id)?.context("stored trace")?;
        assert!(!stored.contains("owner@example.com"), "{stored}");
        assert_eq!(&load_trace(&connection, &stored)?, trace);
    }
    let (_, resumed) =
        crate::execution::load(&connection, "pending")?.context("execution journal")?;
    assert_eq!(resumed, pending);
    assert_eq!(fixture.outcome("done", fixture.policy())?, done.outcome);
    let marker = compacted_marker(&observed);
    assert_eq!(
        fixture.effects("compacted")?,
        (Some(marker.clone()), vec![None, Some(marker)])
    );

    // A repeated upgrade, as after a reset schema marker, changes nothing.
    let before: Vec<Option<String>> = ["done", "pending"]
        .into_iter()
        .map(|id| fixture.stored(id))
        .collect::<Result<_>>()?;
    connection.execute(
        "UPDATE day2_meta SET value='10' WHERE key='host_schema'",
        [],
    )?;
    upgrade()?;
    let after: Vec<Option<String>> = ["done", "pending"]
        .into_iter()
        .map(|id| fixture.stored(id))
        .collect::<Result<_>>()?;
    assert_eq!(before, after);
    assert_eq!(fixture.policies()?, 1);
    Ok(())
}
