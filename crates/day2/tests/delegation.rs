//! The delegation mechanism, at the seam where one application reaches another.
//!
//! What is tested here is the host's side of a delegated read: which calls it
//! refuses, what identity the callee runs under, and what the record says
//! afterwards. `request_identity.rs` separately exercises the application-facing
//! path from a real authenticated session through Roc's `Delegate.query` and a
//! resolved resource grant to a native callee.
use anyhow::{Context as _, Result};
use day2::{
    artifact::{AppBinding, Instance},
    delegation,
    store::Runtime,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

struct Pair {
    directory: tempfile::TempDir,
    caller: Runtime,
}

impl Pair {
    /// Two applications in one instance, from one artifact: what differs is the
    /// name each is installed under, which is all delegation addresses.
    fn new() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify with compiled fixtures")?;
        let directory = tempfile::tempdir()?;
        let policy: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/authority-policies/reports.json"
        ))?;
        let binding = |artifact: &PathBuf| AppBinding {
            security: None,
            runtime: None,
            retention: Default::default(),
            journal: None,
            resource_policies: Vec::new(),
            schedules: Default::default(),
            ingress: Default::default(),
            authority: Some(serde_json::from_value(policy.clone()).expect("policy")),
            artifact: artifact.to_string_lossy().into(),
            readers: BTreeSet::from(["alice".into()]),
            writers: BTreeSet::from(["alice".into()]),
            auditors: BTreeSet::from(["alice".into()]),
            edge: None,
        };
        let instance = Instance {
            installation: "delegationco".into(),
            environment: "test".into(),
            branding: None,
            control: None,
            resources: None,
            apps: BTreeMap::from([
                ("caller".into(), binding(&artifact)),
                ("callee".into(), binding(&artifact)),
            ]),
            identity: None,
        };
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let caller = Runtime::load(&path, "caller")?;
        caller.initialize()?;
        let callee = Runtime::load(&path, "callee")?;
        callee.initialize()?;
        Ok(Self { directory, caller })
    }

    fn callee(&self) -> Result<Runtime> {
        Runtime::load(&self.directory.path().join("instance.json"), "callee")
    }

    fn call(&self, operation: &str, digest: &str) -> delegation::Call {
        delegation::Call {
            app: "callee".into(),
            operation: operation.into(),
            schema_digest: digest.into(),
            input: json!({"after":"","limit":20}).to_string(),
            actor: "alice".into(),
            origin: "origin-invocation".into(),
            step: "ob_origin-invocation_0".into(),
            chain: String::new(),
            caller: "caller".into(),
            now: 100,
        }
    }

    fn digest_of(&self, operation: &str) -> Result<String> {
        delegation::schema_digest(&self.callee()?, operation)
    }
}

/// A delegated read runs as the caller's actor and says where it came from.
///
/// The two facts the whole design rests on. If the actor changed, delegation
/// would be impersonation and the callee's policy would be deciding about the
/// wrong person. If the chain were absent, "who asked for this" would have to
/// be reconstructed by joining two applications' audit logs on a timestamp.
#[test]
fn a_delegated_read_runs_as_the_same_actor_and_records_the_chain() -> Result<()> {
    let pair = Pair::new()?;
    let digest = pair.digest_of("reports.list")?;
    let answer = delegation::read(&pair.caller, &pair.call("reports.list", &digest))?;
    assert!(answer.contains("items"), "unexpected answer: {answer}");

    let callee = pair.callee()?;
    let connection = rusqlite::Connection::open(callee.db())?;
    let (actor, caller, trigger, count): (String, String, String, i64) = connection.query_row(
        "SELECT actor,caller,trigger,(SELECT count(*) FROM day2_invocations) FROM day2_invocations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(actor, "alice", "the callee ran as somebody else");
    assert_eq!(caller, "caller", "the callee cannot say who asked");
    assert_eq!(trigger, "delegated");
    assert_eq!(count, 1);

    // The same read, retried, reaches the same invocation of the callee rather
    // than opening a second one -- otherwise a retried preparation would bill
    // twice and leave two receipts for one question.
    delegation::read(&pair.caller, &pair.call("reports.list", &digest))?;
    let after: i64 = connection.query_row("SELECT count(*) FROM day2_invocations", [], |row| {
        row.get(0)
    })?;
    assert_eq!(
        after, 1,
        "a retried delegated read opened a second invocation"
    );
    Ok(())
}

/// Every refusal, against a call that is otherwise entirely valid.
#[test]
fn a_delegated_read_is_refused_unless_every_condition_holds() -> Result<()> {
    let pair = Pair::new()?;
    let digest = pair.digest_of("reports.list")?;
    // The code, not the message. `contains` would accept a refusal whose code
    // merely starts with the one meant — which is exactly how a renamed error
    // slips past a test that looks like it is checking something.
    let refusal = |call: delegation::Call| -> String {
        let failure = delegation::read(&pair.caller, &call)
            .expect_err("delegated read should be refused")
            .to_string();
        failure
            .split(':')
            .next()
            .expect("a refusal names a code")
            .to_owned()
    };

    let mut no_step = pair.call("reports.list", &digest);
    no_step.step.clear();
    assert_eq!(refusal(no_step), "delegated_read_requires_a_step");

    // An application that is not installed here. Delegation never leaves the
    // instance, so the whole graph is visible in one file.
    let mut elsewhere = pair.call("reports.list", &digest);
    elsewhere.app = "somewhere_else".into();
    assert_eq!(refusal(elsewhere), "delegated_app_not_installed");

    // An operation the callee does not publish.
    let mut unknown = pair.call("reports.invented", &digest);
    assert_eq!(refusal(unknown.clone()), "delegated_operation_unknown");
    unknown.operation = "reports.list".into();

    // A command. A write cannot be answered inside the caller's preparation
    // phase: two applications are two databases with no transaction across
    // them, so a delegated command belongs on the effect path with a receipt.
    let command = pair.call("reports.submit", &pair.digest_of("reports.submit")?);
    assert_eq!(refusal(command), "delegated_operation_is_not_a_query");

    // A shape the operator did not review.
    let stale = pair.call("reports.list", &format!("sha256:{}", "0".repeat(64)));
    assert_eq!(refusal(stale), "delegated_schema_changed");

    // A cycle: the callee is already in the chain that reached here.
    let mut cycle = pair.call("reports.list", &digest);
    cycle.chain = "callee.caller".into();
    assert_eq!(refusal(cycle), "delegation_cycle");

    // And a chain longer than anyone reviewed.
    let mut deep = pair.call("reports.list", &digest);
    deep.chain = "a.b.c.d".into();
    assert_eq!(refusal(deep), "delegation_too_deep");
    Ok(())
}
