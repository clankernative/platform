//! Replayable independent DATA/disposition oracle. The campaign never constructs
//! a NativeRestoreApproval, Controller original, creator/P3 or serving owner.
use super::*;
use crate::security_epoch::restore_staging::Disposition;
use std::{
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
};

const MAX_EVENTS: usize = 24;
const MAX_BYTES: usize = 262_144;
const NAMES: [&str; 8] = [
    "root",
    "sentinel",
    "create",
    "activate",
    "advance",
    "reservation",
    "terminal",
    "consumed",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Send { cut: Cut },
    Observe {},
    Reopen {},
    Rewrite { record: usize },
    Revoke {},
    RemoveKeys {},
    Expire {},
    CheckKnown {},
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    format: u32,
    source: Digest,
    seed: u64,
    events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Data,
    Refused,
    Unknown,
    Acknowledged,
    Applied,
    NotApplied,
    Conflict,
    Known,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    decision: Decision,
    sends: u32,
    restored: bool,
    records: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    input: Input,
    expected: Vec<Observation>,
    actual: Vec<Observation>,
    failure: Option<FailurePoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "point", rename_all = "snake_case", deny_unknown_fields)]
enum FailurePoint {
    Input {},
    Fixture {},
    Provider {},
    Event { index: usize },
}

pub(super) fn source() -> Result<Digest> {
    Digest::of(&(
        include_str!("../../writer.rs"),
        include_str!("../../completion.rs"),
        include_str!("../../approval_use.rs"),
        include_str!("../../../../kernel.rs"),
        include_str!("../../../restore.rs"),
        include_str!("../../../advance.rs"),
        include_str!("../../tests.rs"),
        include_str!("../../../../tests.rs"),
        include_str!("../tests.rs"),
        include_str!("history.rs"),
        include_str!("../../../../restore_staging/writer/dispatch.rs"),
    ))
}

fn validate(input: &Input) -> Result<()> {
    ensure!(
        input.format == 1
            && input.source == source()?
            && !input.events.is_empty()
            && input.events.len() <= MAX_EVENTS
            && serde_json::to_vec(input)?.len() <= MAX_BYTES,
        "writer_history_input_identity_or_bound"
    );
    for event in &input.events {
        if let Event::Rewrite { record } = event {
            ensure!(*record < 8, "writer_history_record_bound");
        }
    }
    Ok(())
}

fn retain(trace: &Trace) -> Result<std::path::PathBuf> {
    let bytes = serde_json::to_vec(trace)?;
    ensure!(bytes.len() <= MAX_BYTES, "writer_history_trace_bound");
    let dir = tempfile::Builder::new()
        .prefix("day2-writer-history-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?
        .keep();
    let path = dir.join("replay.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(path)
}

// Independent abstract oracle: no production prepare/reconcile/plan is called.
// Versions changing without values still count as a foreign history. A local
// original is spent before the possible send; reopening cannot restore it.
struct Oracle {
    used: bool,
    known: bool,
    refused: bool,
    dirty: bool,
    restored: bool,
    enabled: bool,
    keys: bool,
    expired: bool,
    sends: u32,
}

impl Oracle {
    fn new() -> Self {
        Self {
            used: false,
            known: false,
            refused: false,
            dirty: false,
            restored: false,
            enabled: true,
            keys: true,
            expired: false,
            sends: 0,
        }
    }

    fn step(&mut self, event: &Event) -> Observation {
        let decision = match event {
            Event::Revoke {} => {
                self.enabled = false;
                self.refused = true;
                Decision::Data
            }
            Event::RemoveKeys {} => {
                self.keys = false;
                self.refused = true;
                Decision::Data
            }
            Event::Expire {} => {
                self.expired = true;
                self.refused = true;
                Decision::Data
            }
            Event::Rewrite { .. } => {
                self.dirty = true;
                Decision::Data
            }
            Event::Reopen {} => {
                self.refused = true;
                Decision::Data
            }
            Event::Observe {} => {
                if self.dirty {
                    Decision::Conflict
                } else if self.restored {
                    Decision::Applied
                } else {
                    Decision::NotApplied
                }
            }
            Event::CheckKnown {} => {
                if self.known && !self.refused {
                    Decision::Known
                } else {
                    self.refused = true;
                    Decision::Refused
                }
            }
            Event::Send { cut } => {
                if self.used || self.refused {
                    self.refused = true;
                    Decision::Refused
                } else {
                    self.used = true;
                    if self.dirty || !self.enabled || !self.keys || self.expired || self.restored {
                        self.refused = true;
                        Decision::Refused
                    } else {
                        self.sends += 1;
                        if matches!(cut, Cut::AfterCommit | Cut::Complete) {
                            self.restored = true;
                        }
                        if *cut == Cut::Complete {
                            self.known = true;
                            Decision::Acknowledged
                        } else {
                            self.refused = true;
                            Decision::Unknown
                        }
                    }
                }
            }
        };
        Observation {
            decision,
            sends: self.sends,
            restored: self.restored,
            records: if self.restored { 9 } else { 8 },
        }
    }
}

struct Driver {
    f: Fixture,
    plan: Plan,
    provider: Provider,
    path: std::path::PathBuf,
    disposition: Disposition,
    target: Digest,
    image: Digest,
    holder: Digest,
    incarnation: Digest,
    at: i64,
    sends: u32,
}

impl Driver {
    fn step(&mut self, event: &Event) -> Result<Observation> {
        let decision = match event {
            Event::Revoke {} => {
                self.f.authority.enabled = false;
                self.disposition.refuse();
                Decision::Data
            }
            Event::RemoveKeys {} => {
                self.f.authority.available_keys.clear();
                self.disposition.refuse();
                Decision::Data
            }
            Event::Expire {} => {
                self.at = self.f.authority.ready_until;
                self.disposition.refuse();
                Decision::Data
            }
            Event::Rewrite { record } => {
                self.provider.db.execute(
                    "UPDATE records SET token=token+10 WHERE name=?1",
                    [NAMES[*record]],
                )?;
                Decision::Data
            }
            Event::Reopen {} => {
                self.disposition.refuse();
                self.provider = Provider::open(&self.path, &self.f.before)?;
                Decision::Data
            }
            Event::CheckKnown {} => {
                if self.disposition.require_known(&self.target).is_ok() {
                    Decision::Known
                } else {
                    Decision::Refused
                }
            }
            Event::Observe {} => {
                let r = Provider::read(&self.provider.db)?;
                let committed = r.get("writer");
                let mut s = self.f.before.clone();
                macro_rules! record {
                    ($name:literal, $ty:ty) => {{
                        let row = r.get($name).context("writer_history_missing_row")?;
                        Versioned {
                            value: serde_json::from_value::<$ty>(row.value.clone())?,
                            version: version(u64::from(row.token)),
                        }
                    }};
                }
                s.settled.snapshot.root = Some(record!("root", AuthorityRecord));
                s.settled.snapshot.sentinel = Some(record!("sentinel", SentinelRecord));
                s.settled.snapshot.create =
                    Some(record!("create", crate::security_epoch::kernel::Receipt));
                s.settled.snapshot.activate =
                    Some(record!("activate", crate::security_epoch::kernel::Receipt));
                s.settled.advance =
                    record!("advance", crate::security_epoch::kernel::advance::Receipt);
                s.settled.reservation = record!("reservation", super::super::super::Receipt);
                s.terminal = record!("terminal", completion::Receipt);
                s.consumed = record!("consumed", approval_use::UseRecord);
                let receipt = committed
                    .map(|row| {
                        Ok::<_, anyhow::Error>(Versioned {
                            value: serde_json::from_value::<Receipt>(row.value.clone())?,
                            version: version(u64::from(row.token)),
                        })
                    })
                    .transpose()?;
                match reconcile(
                    &self.f.selected,
                    &self.f.request,
                    &self.plan,
                    &s,
                    receipt.as_ref(),
                )? {
                    Outcome::Applied(_) => Decision::Applied,
                    Outcome::NotApplied => Decision::NotApplied,
                    Outcome::Conflict => Decision::Conflict,
                }
            }
            Event::Send { cut } => match self.disposition.arm(&self.target) {
                Err(_) => Decision::Refused,
                Ok(flight) => {
                    // Preparation is still DATA. No synthetic role or approval
                    // is promoted; the fixture never runs native code.
                    match self.f.request.prepare(
                        &self.f.selected,
                        &self.f.authority,
                        self.at,
                        &self.f.before,
                        None,
                    ) {
                        Err(_) => {
                            drop(flight);
                            Decision::Refused
                        }
                        Ok(plan) => {
                            if Provider::read(&self.provider.db)? != rows(&plan.before)? {
                                drop(flight);
                                Decision::Refused
                            } else {
                                self.sends += 1;
                                let result = self.provider.send(&self.f, &plan, self.at, |point| {
                                    ensure!(
                                        point != *cut || *cut == Cut::Complete,
                                        "writer_history_unknown"
                                    );
                                    Ok(())
                                });
                                if result.is_ok() {
                                    flight.known()?;
                                    Decision::Acknowledged
                                } else {
                                    drop(flight);
                                    Decision::Unknown
                                }
                            }
                        }
                    }
                }
            },
        };
        let r = Provider::read(&self.provider.db)?;
        let restored = r
            .get("root")
            .is_some_and(|row| row.value["phase"]["phase"] == "restored_first_holder");
        if restored {
            let text = r["root"].value["phase"]["restoration"]["report"]
                .as_str()
                .context("writer_history_report_encoding")?;
            let report: Value = crate::json::decode(text.as_bytes())?;
            ensure!(
                report["target_epoch"] == 2
                    && report["image"] == self.image.as_str()
                    && report["target_incarnation"] == self.incarnation.as_str()
                    && r["root"].value["phase"]["restoration"]["holder"]["process_incarnation"]
                        == self.holder.as_str(),
                "writer_history_target_or_holder_changed"
            );
        }
        Ok(Observation {
            decision,
            sends: self.sends,
            restored,
            records: r.len(),
        })
    }
}

fn replay(input: &Input) -> Result<Vec<Observation>> {
    let dir = tempfile::tempdir()?;
    replay_at(input, &dir.path().join("provider.sqlite"))
}

// The trace exists before validation, fixture or provider setup. On failure its
// actual prefix is complete, even when it is empty. Invalid oversized input is
// refused rather than silently truncated to manufacture a retainable bundle.
fn replay_at(input: &Input, path: &std::path::Path) -> Result<Vec<Observation>> {
    let mut trace = Trace {
        input: input.clone(),
        expected: Vec::new(),
        actual: Vec::new(),
        failure: Some(FailurePoint::Input {}),
    };
    let result = (|| {
        validate(input)?;
        trace.failure = Some(FailurePoint::Fixture {});
        let f = fixture(input.seed, true)?;
        let plan = f
            .request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
        trace.failure = Some(FailurePoint::Provider {});
        let provider = Provider::open(path, &f.before)?;
        let mut driver = Driver {
            target: f.before.commitment()?,
            f,
            plan,
            provider,
            path: path.to_owned(),
            disposition: Disposition::fresh(),
            image: Digest::of(&("actually-reset-fixture-image", input.seed))?,
            holder: Digest::of(&("new-process", input.seed))?,
            incarnation: Digest::of(&("new-database-incarnation", input.seed))?,
            at: 1002,
            sends: 0,
        };
        let mut oracle = Oracle::new();
        for (index, event) in input.events.iter().enumerate() {
            trace.failure = Some(FailurePoint::Event { index });
            trace.expected.push(oracle.step(event));
            trace.actual.push(driver.step(event)?);
            ensure!(trace.expected == trace.actual, "writer_history_mismatch");
        }
        Ok::<_, anyhow::Error>(())
    })();
    if let Err(error) = result {
        return Err(match retain(&trace) {
            Ok(path) => error.context(format!(
                "writer_history_failure retained {}",
                path.display()
            )),
            Err(_) => error.context("writer_history_failure bundle_not_written"),
        });
    }
    trace.failure = None;
    Ok(trace.actual)
}

#[test]
fn generated_writer_histories_match_independent_oracle_and_twice_replay() -> Result<()> {
    let source = source()?;
    let mut state = 0x7a4e_9d2b_6c11_a555u64;
    for seed in 0..64 {
        let mut events = vec![Event::Observe {}];
        for _ in 0..18 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            events.push(match (state >> 32) % 14 {
                0 => Event::Revoke {},
                1 => Event::RemoveKeys {},
                2 => Event::Expire {},
                3 => Event::Reopen {},
                4 => Event::Rewrite {
                    record: ((state >> 48) % 8) as usize,
                },
                5 => Event::CheckKnown {},
                6 => Event::Observe {},
                value => Event::Send {
                    cut: [
                        Cut::BeforeCompare,
                        Cut::AfterCompare,
                        Cut::AfterRoot,
                        Cut::BeforeCommit,
                        Cut::AfterCommit,
                        Cut::Complete,
                    ][(value as usize - 7) % 6],
                },
            });
        }
        let input = Input {
            format: 1,
            source: source.clone(),
            seed,
            events,
        };
        let encoded = serde_json::to_vec(&input)?;
        let decoded: Input = crate::json::decode(&encoded)?;
        assert_eq!(replay(&input)?, replay(&decoded)?);
    }
    Ok(())
}

#[test]
fn unknown_applied_or_not_applied_never_rearms_original_or_adopts_after_reopen() -> Result<()> {
    for cut in [
        Cut::BeforeCompare,
        Cut::AfterCompare,
        Cut::AfterRoot,
        Cut::BeforeCommit,
        Cut::AfterCommit,
    ] {
        let input = Input {
            format: 1,
            source: source()?,
            seed: 66,
            events: vec![
                Event::Send { cut },
                Event::Observe {},
                Event::Send { cut: Cut::Complete },
                Event::Reopen {},
                Event::Observe {},
                Event::CheckKnown {},
                Event::Send { cut: Cut::Complete },
            ],
        };
        let actual = replay(&input)?;
        assert_eq!(actual[0].decision, Decision::Unknown);
        assert_eq!(actual[2].decision, Decision::Refused);
        assert_eq!(actual[5].decision, Decision::Refused);
        assert_eq!(actual[6].sends, 1);
    }
    Ok(())
}

#[test]
fn known_activation_remains_historical_after_revocation_and_reopen() -> Result<()> {
    let input = Input {
        format: 1,
        source: source()?,
        seed: 77,
        events: vec![
            Event::Send { cut: Cut::Complete },
            Event::Observe {},
            Event::CheckKnown {},
            Event::Revoke {},
            Event::Observe {},
            Event::CheckKnown {},
            Event::Reopen {},
            Event::Send { cut: Cut::Complete },
        ],
    };
    let actual = replay(&input)?;
    assert_eq!(actual[0].decision, Decision::Acknowledged);
    assert_eq!(actual[1].decision, Decision::Applied);
    assert_eq!(actual[2].decision, Decision::Known);
    assert_eq!(actual[4].decision, Decision::Applied);
    assert_eq!(actual[5].decision, Decision::Refused);
    assert_eq!(actual[7].decision, Decision::Refused);
    Ok(())
}

#[test]
fn setup_failure_retains_complete_empty_prefixes_and_primary_error_privately() -> Result<()> {
    let input = Input {
        format: 1,
        source: source()?,
        seed: 82,
        events: vec![Event::Observe {}],
    };
    let dir = tempfile::tempdir()?;
    // Opening an actual directory as SQLite fails before any campaign event.
    let error = replay_at(&input, dir.path()).unwrap_err();
    assert!(error.downcast_ref::<rusqlite::Error>().is_some());
    let outer = error.chain().next().unwrap().to_string();
    let path = std::path::Path::new(
        outer
            .strip_prefix("writer_history_failure retained ")
            .context("retained_bundle_path")?,
    );
    let raw = std::fs::read(path)?;
    let trace: Trace = crate::json::decode(&raw)?;
    assert_eq!(trace.failure, Some(FailurePoint::Provider {}));
    assert!(trace.expected.is_empty() && trace.actual.is_empty());
    assert_eq!(
        serde_json::to_vec(&trace.input)?,
        serde_json::to_vec(&input)?
    );
    assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(raw.len() <= MAX_BYTES);
    Ok(())
}
