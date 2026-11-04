use super::super::tests::{current, initial, intent, version};
use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

#[cfg(unix)]
mod process;

struct Fixture {
    selected: EpochStore,
    reserved: super::super::Plan,
    state: State,
    authority: Current,
    report: TargetReport,
}

fn fixture(seed: u64) -> Fixture {
    let (selected, source) = initial();
    let intent = intent(&selected, seed);
    let authority = current(&selected, &intent, &source);
    let request =
        super::super::Request::new(&selected, intent.clone(), &authority, 1000, &source).unwrap();
    let reserved = request
        .prepare(&selected, &authority, 1000, &source, None)
        .unwrap();
    let mut snapshot = source;
    snapshot.root = Some(Versioned {
        value: reserved.advance.root.clone(),
        version: version(3),
    });
    snapshot.sentinel = Some(Versioned {
        value: reserved.advance.sentinel.clone(),
        version: version(3),
    });
    let state = State {
        snapshot,
        advance: Versioned {
            value: reserved.advance.receipt.clone(),
            version: version(3),
        },
        reservation: Versioned {
            value: reserved.receipt.clone(),
            version: version(3),
        },
    };
    let report = TargetReport {
        intent: intent.commitment(&selected).unwrap(),
        archive: intent.archive.image.clone(),
        target_incarnation: intent.target_incarnation.clone(),
        target_epoch: 2,
        image: Digest::of(&("disabled-target-image", seed)).unwrap(),
        schema: intent.archive.schema.clone(),
        artifact: intent.archive.artifact.clone(),
        reset_observation: Digest::of(&("untrusted-reset-observation", seed)).unwrap(),
    };
    Fixture {
        selected,
        reserved,
        state,
        authority,
        report,
    }
}

impl Fixture {
    fn disposition(&self, completed: bool) -> Disposition {
        if completed {
            Disposition::Completed {
                report: self.report.clone(),
            }
        } else {
            Disposition::Refused {
                reason: Refusal::OperatorCancelled,
            }
        }
    }

    fn request(&self, completed: bool) -> Request {
        Request::new(
            &self.selected,
            &self.reserved,
            &self.state,
            &self.authority,
            1001,
            self.disposition(completed),
        )
        .unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    body: Value,
    version: u64,
}
type Rows = BTreeMap<String, Row>;

fn seed_rows(state: &State) -> Result<Rows> {
    let s = &state.snapshot;
    let mut rows = BTreeMap::new();
    for (name, body, token) in [
        (
            "root",
            serde_json::to_value(&s.root.as_ref().unwrap().value)?,
            3,
        ),
        (
            "sentinel",
            serde_json::to_value(&s.sentinel.as_ref().unwrap().value)?,
            3,
        ),
        (
            "create",
            serde_json::to_value(&s.create.as_ref().unwrap().value)?,
            1,
        ),
        (
            "activate",
            serde_json::to_value(&s.activate.as_ref().unwrap().value)?,
            2,
        ),
        ("advance", serde_json::to_value(&state.advance.value)?, 3),
        (
            "reservation",
            serde_json::to_value(&state.reservation.value)?,
            3,
        ),
    ] {
        rows.insert(
            name.into(),
            Row {
                body,
                version: token,
            },
        );
    }
    Ok(rows)
}

struct Provider {
    db: Connection,
}
impl Provider {
    fn open(path: &Path, seed: &State) -> Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS records(name TEXT PRIMARY KEY,body TEXT NOT NULL,version INTEGER NOT NULL) STRICT;
            CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY) STRICT;")?;
        let count: i64 = db.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
        if count == 0 {
            let tx = db.unchecked_transaction()?;
            for (name, row) in seed_rows(seed)? {
                tx.execute(
                    "INSERT INTO records VALUES(?1,?2,?3)",
                    params![
                        name,
                        serde_json::to_string(&row.body)?,
                        i64::try_from(row.version)?
                    ],
                )?;
            }
            tx.commit()?;
        }
        Ok(Self { db })
    }

    fn rows(&self) -> Result<Rows> {
        let mut query = self
            .db
            .prepare("SELECT name,body,version FROM records ORDER BY name")?;
        let raw = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raw.into_iter()
            .map(|(name, body, version)| {
                Ok((
                    name,
                    Row {
                        body: crate::json::decode_evidence(body.as_bytes())?,
                        version: version.try_into()?,
                    },
                ))
            })
            .collect()
    }

    fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<Versioned<T>>> {
        let raw: Option<(String, i64)> = self
            .db
            .query_row(
                "SELECT body,version FROM records WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        raw.map(|(body, token)| {
            Ok(Versioned {
                value: crate::json::decode_evidence(body.as_bytes())?,
                version: version(token.try_into()?),
            })
        })
        .transpose()
    }

    fn state(&self) -> Result<State> {
        Ok(State {
            snapshot: Snapshot {
                root: self.read("root")?,
                sentinel: self.read("sentinel")?,
                create: self.read("create")?,
                activate: self.read("activate")?,
            },
            advance: self
                .read("advance")?
                .ok_or_else(|| anyhow::anyhow!("fixture_advance_missing"))?,
            reservation: self
                .read("reservation")?
                .ok_or_else(|| anyhow::anyhow!("fixture_reservation_missing"))?,
        })
    }

    fn sends(&self) -> Result<u64> {
        Ok(self
            .db
            .query_row("SELECT count(*) FROM attempts", [], |r| r.get::<_, i64>(0))?
            .try_into()?)
    }

    fn stage(
        &mut self,
        f: &Fixture,
        request: &Request,
        plan: &Plan,
        current: &Current,
        at: i64,
        mut checkpoint: impl FnMut(Cut) -> Result<()>,
    ) -> Result<()> {
        plan.revalidate(
            &f.selected,
            request,
            current,
            at,
            &self.state()?,
            self.read("terminal")?.as_ref(),
        )?;
        self.db.execute("INSERT INTO attempts DEFAULT VALUES", [])?;
        checkpoint(Cut::BeforeWrite)?;
        let tx = self.db.transaction()?;
        // Complete value+token CAS for ALL six captured records. The fixture's
        // initial token domain is explicit; no selected version is restamped.
        let captured = seed_rows(&plan.before)?;
        for (name, row) in captured {
            let token = match name.as_str() {
                "root" => &plan.before.snapshot.root.as_ref().unwrap().version,
                "sentinel" => &plan.before.snapshot.sentinel.as_ref().unwrap().version,
                "create" => &plan.before.snapshot.create.as_ref().unwrap().version,
                "activate" => &plan.before.snapshot.activate.as_ref().unwrap().version,
                "advance" => &plan.before.advance.version,
                "reservation" => &plan.before.reservation.version,
                _ => unreachable!(),
            };
            let stored: Option<(String, i64)> = tx
                .query_row(
                    "SELECT body,version FROM records WHERE name=?1",
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((body, revision)) = stored else {
                anyhow::bail!("fixture_cas_missing");
            };
            ensure!(
                version(revision.try_into()?) == *token
                    && crate::json::decode_evidence::<Value>(body.as_bytes())? == row.body,
                "fixture_cas_changed"
            );
        }
        checkpoint(Cut::AfterCompare)?;
        tx.execute(
            "INSERT INTO records VALUES('terminal',?1,4)",
            [serde_json::to_string(&plan.receipt)?],
        )?;
        checkpoint(Cut::AfterWrite)?;
        tx.commit()?;
        checkpoint(Cut::AfterCommit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cut {
    BeforeWrite,
    AfterCompare,
    AfterWrite,
    AfterCommit,
    Complete,
}

/// The terminal oracle shares only immutable DATA seeds and codec/hash formats.
/// It never calls the settlement reducer, request digest, capture or readback.
fn reference_receipt(
    f: &Fixture,
    state: &State,
    authority: &Current,
    at: i64,
    decision: &Disposition,
) -> Result<Value> {
    let s = &state.snapshot;
    let capture = Digest::of(&(
        "day2-secure-restore-settlement-state-v1",
        s.root.as_ref().map(|r| (&r.value, &r.version)),
        s.sentinel.as_ref().map(|r| (&r.value, &r.version)),
        s.create.as_ref().map(|r| (&r.value, &r.version)),
        s.activate.as_ref().map(|r| (&r.value, &r.version)),
        (&state.advance.value, &state.advance.version),
        (&state.reservation.value, &state.reservation.version),
    ))?;
    let original = Digest::of(&(
        "day2-secure-restore-request-v1",
        &f.reserved.receipt.request,
    ))?;
    let request = Digest::of(&(
        "day2-secure-restore-settlement-request-v1",
        original,
        capture.clone(),
        decision,
        authority,
        at,
    ))?;
    Ok(
        json!({"format":"day2_secure_restore_settlement_v1", "operation":f.reserved.receipt.request.intent.operation,
        "request":request,"reserved":capture,"disposition":decision,"policy":"reissue_and_reauthorize_v1","prepared_at":at}),
    )
}

#[test]
fn exact_completion_and_explicit_refusal_leave_all_authority_fenced() -> Result<()> {
    for completed in [false, true] {
        let f = fixture(1);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.sqlite");
        let mut db = Provider::open(&path, &f.state)?;
        let original = db.rows()?;
        let request = f.request(completed);
        let plan = request.prepare(&f.selected, &f.authority, 1001, &f.state, None)?;
        assert_eq!(
            serde_json::to_value(&plan.receipt)?,
            reference_receipt(&f, &f.state, &f.authority, 1001, &f.disposition(completed))?
        );
        db.stage(&f, &request, &plan, &f.authority, 1001, |_| Ok(()))?;
        drop(db);
        let db = Provider::open(&path, &f.state)?;
        let mut rows = db.rows()?;
        rows.remove("terminal");
        assert_eq!(rows, original);
        let state = db.state()?;
        assert!(matches!(
            reconcile(
                &f.selected,
                &request,
                &plan,
                &state,
                db.read("terminal")?.as_ref()
            )?,
            Outcome::Recorded(_)
        ));
        assert!(
            plan.revalidate(
                &f.selected,
                &request,
                &f.authority,
                1001,
                &state,
                db.read("terminal")?.as_ref()
            )
            .is_err()
        );
        // The actual existing activation consumer still rejects this authority.
        let old = f
            .reserved
            .before
            .activate
            .as_ref()
            .unwrap()
            .value
            .request
            .clone();
        assert!(super::super::super::reconcile(&f.selected, &old, &state.snapshot).is_err());
        // Historical private rows still block the REAL ordinary-restore check.
        db.db
            .execute_batch("CREATE TABLE day2_credential_material(value TEXT) STRICT;")?;
        let tx = db.db.unchecked_transaction()?;
        crate::store::require_no_managed_credential_restore_state(&tx)?;
        tx.execute(
            "INSERT INTO day2_credential_material VALUES('synthetic-old-row')",
            [],
        )?;
        assert!(crate::store::require_no_managed_credential_restore_state(&tx).is_err());
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn report_binding_and_closed_wire_refuse_substitution() -> Result<()> {
    let f = fixture(2);
    for field in [
        "intent",
        "archive",
        "target_incarnation",
        "target_epoch",
        "schema",
        "artifact",
    ] {
        let mut value = serde_json::to_value(&f.report)?;
        value[field] = if field == "target_epoch" {
            json!(3)
        } else {
            json!(Digest::new(b"foreign"))
        };
        let report: TargetReport = crate::json::decode_evidence(&serde_json::to_vec(&value)?)?;
        assert!(
            Request::new(
                &f.selected,
                &f.reserved,
                &f.state,
                &f.authority,
                1001,
                Disposition::Completed { report }
            )
            .is_err()
        );
    }
    for text in [
        r#"{"refused":{"reason":"unknown"}}"#,
        r#"{"refused":{"reason":"operator_cancelled","extra":0}}"#,
        r#"{"refused":{"reason":"operator_cancelled"},"refused":{"reason":"operator_cancelled"}}"#,
    ] {
        assert!(crate::json::decode_evidence::<Disposition>(text.as_bytes()).is_err());
    }
    Ok(())
}

#[test]
fn expiry_revocation_key_loss_and_rewind_cannot_create_even_a_refusal_plan() -> Result<()> {
    let f = fixture(3);
    for completed in [false, true] {
        let request = f.request(completed);
        for change in 0..9 {
            let mut current = f.authority.clone();
            let mut at = 1001;
            match change {
                0 => current.enabled = false,
                1 => current.available_keys.clear(),
                2 => at = 1005,
                3 => at = 999,
                4 => current.observed_at = 999,
                5 => current.grant.revision = Digest::new(b"changed"),
                6 => current.grant.expires_at = 1200,
                7 => current.grant.clock_domain = Digest::new(b"other-domain"),
                _ => current.grant.fence.receipt = Digest::new(b"another-fence"),
            }
            assert!(
                request
                    .prepare(&f.selected, &current, at, &f.state, None)
                    .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn every_current_record_value_and_token_fences_stale_settlement() -> Result<()> {
    let f = fixture(4);
    let request = f.request(true);
    let plan = request.prepare(&f.selected, &f.authority, 1001, &f.state, None)?;
    for i in 0..12 {
        let mut state = f.state.clone();
        match i {
            0 => state.snapshot.root.as_mut().unwrap().version = version(9),
            1 => state.snapshot.sentinel.as_mut().unwrap().version = version(9),
            2 => state.snapshot.create.as_mut().unwrap().version = version(9),
            3 => state.snapshot.activate.as_mut().unwrap().version = version(9),
            4 => state.advance.version = version(9),
            5 => state.reservation.version = version(9),
            6 => state.snapshot.root.as_mut().unwrap().value.epoch = 3.try_into()?,
            7 => state.snapshot.root = f.reserved.before.root.clone(),
            8 => state.snapshot.sentinel = f.reserved.before.sentinel.clone(),
            9 => state.snapshot.create = None,
            10 => state.snapshot.activate = None,
            _ => {
                state.reservation.value.request.intent.target_incarnation = Digest::new(b"foreign")
            }
        }
        assert!(
            plan.revalidate(&f.selected, &request, &f.authority, 1001, &state, None)
                .is_err()
        );
        assert_eq!(
            reconcile(&f.selected, &request, &plan, &state, None)?,
            Outcome::Conflict
        );
    }
    Ok(())
}

#[test]
fn complete_and_refuse_compete_for_one_key_and_unknown_reply_never_renews() -> Result<()> {
    let f = fixture(5);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.sqlite");
    for first in [false, true] {
        let sub = path.with_extension(if first { "complete" } else { "refuse" });
        let mut db = Provider::open(&sub, &f.state)?;
        let a = f.request(first);
        let b = f.request(!first);
        let pa = a.prepare(&f.selected, &f.authority, 1001, &f.state, None)?;
        let pb = b.prepare(&f.selected, &f.authority, 1001, &f.state, None)?;
        assert!(
            db.stage(&f, &a, &pa, &f.authority, 1001, |cut| {
                ensure!(cut != Cut::AfterCommit, "lost_reply");
                Ok(())
            })
            .is_err()
        );
        assert!(matches!(
            reconcile(
                &f.selected,
                &a,
                &pa,
                &db.state()?,
                db.read("terminal")?.as_ref()
            )?,
            Outcome::Recorded(_)
        ));
        assert_eq!(
            reconcile(
                &f.selected,
                &b,
                &pb,
                &db.state()?,
                db.read("terminal")?.as_ref()
            )?,
            Outcome::Conflict
        );
        assert!(
            db.stage(&f, &b, &pb, &f.authority, 1001, |_| Ok(()))
                .is_err()
        );
        let mut expired = f.authority.clone();
        expired.enabled = false;
        assert!(
            pa.revalidate(
                &f.selected,
                &a,
                &expired,
                1100,
                &db.state()?,
                db.read("terminal")?.as_ref()
            )
            .is_err()
        );
        assert_eq!(db.sends()?, 1);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    Prepare(bool),
    Send(Cut),
    Tick,
    Revoke,
    LoseKey,
    Rewrite(String),
    AdvanceEpoch,
    RestoreOldRoot,
    Reopen,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    rows: Rows,
    sends: u64,
    prepared: bool,
    accepted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    actual: Observation,
    expected: Observation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    steps: Vec<Step>,
    fault: Fault,
    failure: Option<Box<Failure>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Fault {
    None,
    BeforeTemp,
    BeforeProvider,
    Event(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Fixture,
    TemporaryDirectory,
    Provider,
    Model,
    Event,
    Observe,
    Compare,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frontier {
    rows: Option<Rows>,
    model: Option<Rows>,
    sends: Option<u64>,
    now: Option<i64>,
    authority: Option<Current>,
    actual_plan: Option<Value>,
    expected_plan: Option<Value>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    stage: Stage,
    index: usize,
    event: Option<usize>,
    frontier: Frontier,
}

fn history(seed: u64, events: &[Event], wrong_oracle: bool) -> Run {
    history_with_fault(seed, events, wrong_oracle, Fault::None)
}
fn history_with_fault(seed: u64, events: &[Event], wrong_oracle: bool, fault: Fault) -> Run {
    let mut steps = Vec::new();
    let mut stage = Stage::Fixture;
    let mut frontier = Frontier::default();
    let mut event_index = None;
    let result = (|| -> Result<()> {
        let f = fixture(seed);
        frontier.authority = Some(f.authority.clone());
        frontier.now = Some(1001);
        stage = Stage::TemporaryDirectory;
        ensure!(fault != Fault::BeforeTemp, "forced_temp_failure");
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("state.sqlite");
        stage = Stage::Provider;
        ensure!(fault != Fault::BeforeProvider, "forced_provider_failure");
        let mut db = Provider::open(&path, &f.state)?;
        frontier.rows = Some(db.rows()?);
        frontier.sends = Some(db.sends()?);
        stage = Stage::Model;
        let mut authority = f.authority.clone();
        let mut now = 1001;
        let mut model = seed_rows(&f.state)?;
        let original = model.clone();
        let mut sends = 0;
        let mut prepared = None;
        let mut actual_request = None;
        let mut actual_plan = None;
        // Original intent and epoch constraints are external to the transition;
        // the oracle follows explicit history facts, never actual observations.
        let mut enabled = true;
        let mut keys = true;
        let mut epoch_ok = true;
        for (index, event) in events.iter().enumerate() {
            event_index = Some(index);
            stage = Stage::Observe;
            frontier = Frontier {
                rows: Some(db.rows()?),
                model: Some(model.clone()),
                sends: Some(db.sends()?),
                now: Some(now),
                authority: Some(authority.clone()),
                actual_plan: actual_plan
                    .as_ref()
                    .map(|p: &Plan| serde_json::to_value(&p.receipt))
                    .transpose()?,
                expected_plan: prepared.as_ref().map(|(_, r): &(Rows, Value)| r.clone()),
            };
            stage = Stage::Event;
            ensure!(fault != Fault::Event(index), "forced_event_failure");
            let mut expected_accept = true;
            let actual_accept;
            match event {
                Event::Prepare(complete) => {
                    expected_accept = enabled
                        && keys
                        && (1001..1005).contains(&now)
                        && epoch_ok
                        && !model.contains_key("terminal");
                    let candidate = (|| -> Result<(Request, Plan)> {
                        let observed = db.state()?;
                        let request = Request::new(
                            &f.selected,
                            &f.reserved,
                            &observed,
                            &authority,
                            now,
                            f.disposition(*complete),
                        )?;
                        let plan = request.prepare(
                            &f.selected,
                            &authority,
                            now,
                            &observed,
                            db.read("terminal")?.as_ref(),
                        )?;
                        Ok((request, plan))
                    })();
                    actual_accept = candidate.is_ok();
                    if let Ok((request, plan)) = candidate {
                        actual_plan = Some(plan);
                        actual_request = Some(request);
                    }
                    if expected_accept {
                        prepared = Some((
                            model.clone(),
                            reference_receipt(
                                &f,
                                &reference_state(&model)?,
                                &authority,
                                now,
                                &f.disposition(*complete),
                            )?,
                        ));
                    } else {
                        actual_request = None;
                        actual_plan = None;
                        prepared = None;
                    }
                }
                Event::Send(cut) => {
                    expected_accept = prepared
                        .as_ref()
                        .is_some_and(|(capture, _)| capture == &model)
                        && enabled
                        && keys
                        && now < 1005
                        && epoch_ok
                        && !model.contains_key("terminal");
                    actual_accept = match (&actual_request, &actual_plan) {
                        (Some(request), Some(plan)) => db
                            .stage(&f, request, plan, &authority, now, |c| {
                                ensure!(c != *cut, "planned_cut");
                                Ok(())
                            })
                            .is_ok(),
                        _ => false,
                    };
                    if expected_accept {
                        sends += 1;
                        if matches!(cut, Cut::AfterCommit | Cut::Complete) {
                            let (_, body) = prepared.as_ref().unwrap();
                            model.insert(
                                "terminal".into(),
                                Row {
                                    body: body.clone(),
                                    version: 4,
                                },
                            );
                        }
                        expected_accept = *cut == Cut::Complete;
                        if wrong_oracle && *cut == Cut::AfterCommit {
                            model.remove("terminal");
                        }
                    }
                }
                Event::Tick => {
                    now += 1;
                    actual_accept = true;
                }
                Event::Revoke => {
                    enabled = false;
                    authority.enabled = false;
                    actual_accept = true;
                }
                Event::LoseKey => {
                    keys = false;
                    authority.available_keys.clear();
                    actual_accept = true;
                }
                Event::Rewrite(name) => {
                    ensure!(original.contains_key(name), "history_record_name");
                    model.get_mut(name).unwrap().version += 1;
                    db.db
                        .execute("UPDATE records SET version=version+1 WHERE name=?1", [name])?;
                    actual_accept = true;
                }
                Event::AdvanceEpoch | Event::RestoreOldRoot => {
                    epoch_ok = false;
                    let body = if matches!(event, Event::AdvanceEpoch) {
                        let mut b = original["root"].body.clone();
                        b["epoch"] = json!("3");
                        b
                    } else {
                        serde_json::to_value(&f.reserved.before.root.as_ref().unwrap().value)?
                    };
                    model.get_mut("root").unwrap().body = body.clone();
                    model.get_mut("root").unwrap().version += 1;
                    db.db.execute(
                        "UPDATE records SET body=?1,version=version+1 WHERE name='root'",
                        [serde_json::to_string(&body)?],
                    )?;
                    actual_accept = true;
                }
                Event::Reopen => {
                    drop(db);
                    db = Provider::open(&path, &f.state)?;
                    actual_accept = true;
                }
            }
            stage = Stage::Observe;
            frontier.model = Some(model.clone());
            frontier.now = Some(now);
            frontier.authority = Some(authority.clone());
            frontier.actual_plan = actual_plan
                .as_ref()
                .map(|p| serde_json::to_value(&p.receipt))
                .transpose()?;
            frontier.expected_plan = prepared.as_ref().map(|(_, r)| r.clone());
            frontier.rows = Some(db.rows()?);
            frontier.sends = Some(db.sends()?);
            let actual = Observation {
                rows: db.rows()?,
                sends: db.sends()?,
                prepared: actual_plan.is_some(),
                accepted: actual_accept,
            };
            let expected = Observation {
                rows: model.clone(),
                sends,
                prepared: prepared.is_some(),
                accepted: expected_accept,
            };
            let equal = actual == expected;
            stage = Stage::Compare;
            steps.push(Step { actual, expected });
            ensure!(equal, "history_disagreement");
        }
        Ok(())
    })();
    Run {
        failure: result.err().map(|_| Box::new(Failure {
            stage,
            index: steps.len(),
            event: event_index,
            frontier,
        })),
        steps,
        fault,
    }
}

/// Only the independent reference needs typed immutable rows for wire hashing;
/// it never reads the provider. Every value AND version comes from model state.
fn reference_state(rows: &Rows) -> Result<State> {
    fn record<T: serde::de::DeserializeOwned>(rows: &Rows, name: &str) -> Result<Versioned<T>> {
        let row = &rows[name];
        Ok(Versioned {
            value: crate::json::decode_evidence(&serde_json::to_vec(&row.body)?)?,
            version: version(row.version),
        })
    }
    Ok(State {
        snapshot: Snapshot {
            root: Some(record(rows, "root")?),
            sentinel: Some(record(rows, "sentinel")?),
            create: Some(record(rows, "create")?),
            activate: Some(record(rows, "activate")?),
        },
        advance: record(rows, "advance")?,
        reservation: record(rows, "reservation")?,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "part", rename_all = "snake_case", deny_unknown_fields)]
enum Part {
    Input {
        source: Digest,
        seed: u64,
        events: Vec<Event>,
        wrong_oracle: bool,
    },
    Run {
        index: usize,
        count: usize,
        fault: Fault,
        failure: Option<Box<Failure>>,
    },
    Step {
        run: usize,
        index: usize,
        value: Box<Step>,
    },
    End,
}
fn source() -> Result<Digest> {
    Digest::of(&(
        include_str!("../completion.rs"),
        include_str!("tests.rs"),
        include_str!("tests/process.rs"),
        include_str!("../../restore.rs"),
        include_str!("../tests.rs"),
        include_str!("../../../tests.rs"),
        include_str!("../../../../store.rs"),
        include_str!("../../../../managed_credentials/store.rs"),
        include_str!("../../advance.rs"),
        include_str!("../../../kernel.rs"),
        include_str!("../../../../json.rs"),
        include_str!("../../../../../../../Cargo.lock"),
        include_str!("../../../../../../day2-capabilities/src/lib.rs"),
        include_str!("../../../../../../day2-capabilities/src/security_epoch.rs"),
    ))
}

fn archive(seed: u64, events: &[Event], wrong: bool, runs: &[Run; 2]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut append = |part: Part| -> Result<()> {
        let bytes = serde_json::to_vec(&part)?;
        ensure!(bytes.len() <= 256 * 1024, "settlement_part_bound");
        encoder.write_all(&bytes)?;
        encoder.write_all(b"\n")?;
        Ok(())
    };
    append(Part::Input {
        source: source()?,
        seed,
        events: events.to_vec(),
        wrong_oracle: wrong,
    })?;
    for (index, run) in runs.iter().enumerate() {
        append(Part::Run {
            index,
            count: run.steps.len(),
            fault: run.fault,
            failure: run.failure.clone(),
        })?;
        for (i, step) in run.steps.iter().enumerate() {
            append(Part::Step {
                run: index,
                index: i,
                value: Box::new(step.clone()),
            })?;
        }
    }
    append(Part::End)?;
    let bytes = encoder.finish()?;
    ensure!(bytes.len() <= 2 * 1024 * 1024, "settlement_archive_bound");
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<(u64, Vec<Event>, bool, [Run; 2])> {
    fn contents(bytes: &[u8]) -> Result<(u64, Vec<Event>, bool, [Run; 2])> {
        use std::io::Read;
        ensure!(bytes.len() <= 2 * 1024 * 1024, "archive_bound");
        let mut decoder = flate2::bufread::GzDecoder::new(bytes);
        let mut plain = Vec::new();
        decoder
            .by_ref()
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut plain)?;
        ensure!(
            plain.len() <= 16 * 1024 * 1024 && decoder.into_inner().is_empty(),
            "archive_complete"
        );
        ensure!(plain.last() == Some(&b'\n'), "archive_last_marker");
        let parts = plain[..plain.len() - 1]
            .split(|b| *b == b'\n')
            .map(|line| {
                ensure!(line.len() <= 256 * 1024, "part_bound");
                crate::json::decode_evidence::<Part>(line)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut it = parts.into_iter();
        let Some(Part::Input {
            source: captured,
            seed,
            events,
            wrong_oracle,
        }) = it.next()
        else {
            anyhow::bail!("input");
        };
        ensure!(
            captured == source()? && events.len() <= 24,
            "source_or_events"
        );
        for event in &events {
            if let Event::Rewrite(name) = event {
                ensure!(
                    [
                        "root",
                        "sentinel",
                        "create",
                        "activate",
                        "advance",
                        "reservation"
                    ]
                    .contains(&name.as_str()),
                    "record_name"
                );
            }
        }
        let mut runs = Vec::new();
        for expected in 0..2 {
            let Some(Part::Run {
                index,
                count,
                fault,
                failure,
            }) = it.next()
            else {
                anyhow::bail!("run");
            };
            ensure!(index == expected && count <= events.len(), "count");
            let mut steps = Vec::new();
            for i in 0..count {
                let Some(Part::Step { run, index, value }) = it.next() else {
                    anyhow::bail!("step");
                };
                ensure!(run == expected && index == i, "step_order");
                steps.push(*value);
            }
            ensure!(
                failure.as_ref().is_some_and(|f| f.index == count)
                    || failure.is_none() && count == events.len(),
                "failure_prefix"
            );
            ensure!(
                !matches!(fault,Fault::Event(i) if i>=events.len()),
                "fault_index"
            );
            runs.push(Run {
                steps,
                fault,
                failure,
            });
        }
        ensure!(
            matches!(it.next(), Some(Part::End)) && it.next().is_none(),
            "end"
        );
        Ok((seed, events, wrong_oracle, runs.try_into().unwrap()))
    }
    contents(bytes).map_err(|_| anyhow::anyhow!("restore_settlement_replay_refused"))
}
fn replay(bytes: &[u8]) -> Result<bool> {
    let (seed, events, wrong, runs) = decode(bytes)?;
    let mut equal = true;
    for saved in runs {
        let actual = history_with_fault(seed, &events, wrong, saved.fault);
        equal &= serde_json::to_value(saved)? == serde_json::to_value(actual)?;
    }
    Ok(equal)
}
fn retain(bytes: &[u8]) -> Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/control-slot-replays");
    std::fs::create_dir_all(&base)?;
    let path = tempfile::Builder::new()
        .prefix("restore-settlement-")
        .tempdir_in(base)?
        .keep();
    let file = path.join("replay.json.gz");
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&file)?;
    out.write_all(bytes)?;
    out.sync_all()?;
    Ok(file)
}

#[test]
fn generated_terminal_histories_compare_independent_complete_state_twice() -> Result<()> {
    for seed in 0..64u64 {
        let mut events = vec![
            Event::Prepare(seed % 2 == 0),
            Event::Send(Cut::AfterWrite),
            Event::Reopen,
        ];
        let mut n = seed + 1;
        for _ in 0..12 {
            n = n.wrapping_mul(6364136223846793005).wrapping_add(1);
            events.push(match n % 10 {
                0 => Event::Prepare(false),
                1 => Event::Prepare(true),
                2 => Event::Send(Cut::AfterCommit),
                3 => Event::Send(Cut::Complete),
                4 => Event::Tick,
                5 => Event::Revoke,
                6 => Event::LoseKey,
                7 => Event::Rewrite(
                    [
                        "root",
                        "sentinel",
                        "create",
                        "activate",
                        "advance",
                        "reservation",
                    ][(n as usize / 10) % 6]
                        .into(),
                ),
                8 => Event::AdvanceEpoch,
                _ => Event::Reopen,
            });
        }
        let runs = [history(seed, &events, false), history(seed, &events, false)];
        let bytes = archive(seed, &events, false, &runs)?;
        if runs.iter().any(|r| r.failure.is_some()) || !replay(&bytes).is_ok_and(|equal| equal) {
            let file = retain(&bytes)?;
            anyhow::bail!(
                "restore_settlement_history_refused replay={}",
                file.display()
            );
        }
    }
    Ok(())
}

#[test]
fn uncertain_completion_false_oracle_and_restored_active_history_replay_closed() -> Result<()> {
    for events in [
        vec![
            Event::Prepare(true),
            Event::Send(Cut::AfterCommit),
            Event::Reopen,
        ],
        vec![
            Event::Prepare(false),
            Event::RestoreOldRoot,
            Event::Send(Cut::Complete),
            Event::Reopen,
        ],
    ] {
        let wrong = matches!(events.get(1), Some(Event::Send(_)));
        let runs = [history(77, &events, wrong), history(77, &events, wrong)];
        assert_eq!(runs.iter().any(|r| r.failure.is_some()), wrong);
        let bytes = archive(77, &events, wrong, &runs)?;
        let path = retain(&bytes)?;
        assert!(replay(&std::fs::read(path)?)?);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut extra = bytes.clone();
        extra.extend_from_slice(&bytes);
        assert!(decode(&extra).is_err());
        let mut oversized = events.clone();
        oversized.resize(25, Event::Reopen);
        assert!(
            decode(&archive(
                77,
                &oversized,
                false,
                &[
                    history(77, &oversized, false),
                    history(77, &oversized, false)
                ]
            )?)
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn optional_terminal_replay_requires_exact_current_source() -> Result<()> {
    if let Some(path) = std::env::var_os("DAY2_RESTORE_SETTLEMENT_REPLAY") {
        let metadata = std::fs::metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 2 * 1024 * 1024,
            "replay_file_bound"
        );
        assert!(replay(&std::fs::read(path)?)?);
    }
    Ok(())
}

#[test]
fn setup_and_second_run_failures_keep_the_complete_available_frontier() -> Result<()> {
    let events = vec![
        Event::Prepare(true),
        Event::Tick,
        Event::Send(Cut::AfterCommit),
        Event::Reopen,
    ];
    for fault in [Fault::BeforeTemp, Fault::BeforeProvider, Fault::Event(2)] {
        let runs = [
            history(91, &events, false),
            history_with_fault(91, &events, false, fault),
        ];
        assert!(runs[0].failure.is_none());
        let failure = runs[1].failure.as_ref().unwrap();
        assert!(failure.frontier.authority.is_some());
        if fault == Fault::Event(2) {
            assert_eq!(failure.index, 2);
            assert_eq!(failure.event, Some(2));
            assert_eq!(failure.stage, Stage::Event);
            assert!(failure.frontier.rows.is_some() && failure.frontier.model.is_some());
            assert!(
                failure.frontier.actual_plan.is_some() && failure.frontier.expected_plan.is_some()
            );
            assert_eq!(failure.frontier.now, Some(1002));
        }
        let bytes = archive(91, &events, false, &runs)?;
        let path = retain(&bytes)?;
        assert!(replay(&std::fs::read(path)?)?);
    }
    Ok(())
}

#[test]
fn replay_parser_closes_unknown_fields_and_requires_both_complete_run_records() -> Result<()> {
    use std::io::{Read, Write};
    let events = vec![Event::Prepare(true), Event::Send(Cut::AfterCommit)];
    let runs = [history(92, &events, false), history(92, &events, false)];
    let bytes = archive(92, &events, false, &runs)?;
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice()).read_to_end(&mut raw)?;
    let mut lines = raw
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(Vec::from)
        .collect::<Vec<_>>();
    let mut input: Value = crate::json::decode_evidence(&lines[0])?;
    input.as_object_mut().unwrap().insert(
        "RESTORE_SETTLEMENT_PRIVATE_FIELD_CANARY".into(),
        json!(true),
    );
    lines[0] = serde_json::to_vec(&input)?;
    for mutated in [
        lines,
        vec![
            raw.split(|b| *b == b'\n').next().unwrap().to_vec(),
            b"{\"part\":\"end\"}".to_vec(),
        ],
    ] {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        for line in mutated {
            encoder.write_all(&line)?;
            encoder.write_all(b"\n")?;
        }
        let refused = decode(&encoder.finish()?)
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected_closed_parser_refusal"))?;
        assert!(
            refused.to_string() == "restore_settlement_replay_refused",
            "replay parser error escaped its closed boundary"
        );
    }
    Ok(())
}
