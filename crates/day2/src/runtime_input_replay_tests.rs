//! Saved histories for the two synthetic runtime-input fixtures. These replay
//! host inputs and SQLite observations, not native Roc workers or provider I/O.
use super::{read_coverage_tests, selection_tests};
use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::Path,
};

const MAX_BYTES: u64 = 1_048_576;
const MAX_STEPS: usize = 16;

pub(super) fn capture<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    // A failed world is discarded immediately. Catch native fixture/action
    // panics only to retain their stage and leave the test/replay failed.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            ensure!(
                message.len() <= 4000,
                "input history panic exceeds error budget"
            );
            bail!("input history native panic: {message}");
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", content = "value", deny_unknown_fields)]
pub(super) enum Recorded<T> {
    Ok(T),
    Error(String),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum FailureKind {
    Fixture,
    Native,
    Oracle,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
    pub step: Option<usize>,
    pub kind: FailureKind,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct History<I, A, O> {
    pub inputs: I,
    pub actions: Vec<A>,
    pub observations: Vec<Recorded<O>>,
    pub fixture_error: Option<String>,
    pub failure: Option<Failure>,
}

impl<I, A, O> History<I, A, O> {
    pub fn new(inputs: I, actions: Vec<A>) -> Self {
        Self {
            inputs,
            actions,
            observations: Vec::new(),
            fixture_error: None,
            failure: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.actions.is_empty() && self.actions.len() <= MAX_STEPS,
            "input history action budget"
        );
        ensure!(
            self.observations.len() <= self.actions.len(),
            "input history observation budget"
        );
        for observed in &self.observations {
            if let Recorded::Error(error) = observed {
                ensure!(error.len() <= 4096, "input history error budget");
            }
        }
        if let Some(error) = &self.fixture_error {
            ensure!(error.len() <= 4096, "input history fixture error budget");
        }
        match &self.failure {
            None => ensure!(
                self.fixture_error.is_none()
                    && self
                        .observations
                        .iter()
                        .all(|o| matches!(o, Recorded::Ok(_))),
                "input history missing failure"
            ),
            Some(Failure {
                step: None,
                kind: FailureKind::Fixture,
            }) => ensure!(
                self.fixture_error.is_some() && self.observations.is_empty(),
                "input history fixture failure shape"
            ),
            Some(Failure {
                step: Some(step),
                kind,
            }) => {
                ensure!(
                    *step < self.actions.len()
                        && self.observations.len() == step + 1
                        && self.fixture_error.is_none(),
                    "input history failure position"
                );
                ensure!(
                    matches!(
                        (kind, self.observations.last()),
                        (FailureKind::Native, Some(Recorded::Error(_)))
                            | (FailureKind::Oracle, Some(Recorded::Ok(_)))
                    ),
                    "input history failure kind"
                );
            }
            _ => bail!("input history failure shape"),
        }
        Ok(())
    }

    pub fn fixture_failed(&mut self, error: &anyhow::Error) {
        self.fixture_error = Some(error.to_string());
        self.failure = Some(Failure {
            step: None,
            kind: FailureKind::Fixture,
        });
    }
}

impl<I, A, O: PartialEq> History<I, A, O> {
    // Record before returning an error, so the caller can checkpoint the exact
    // failing observation and its position before propagating the failed check.
    pub fn observe(&mut self, actual: Result<O>, expected: &O) -> Result<()> {
        let step = self.observations.len();
        let (recorded, failure) = match actual {
            Ok(value) => {
                let failure = (&value != expected).then_some(FailureKind::Oracle);
                (Recorded::Ok(value), failure)
            }
            Err(error) => (
                Recorded::Error(error.to_string()),
                Some(FailureKind::Native),
            ),
        };
        self.observations.push(recorded);
        if let Some(kind) = failure {
            self.failure = Some(Failure {
                step: Some(step),
                kind,
            });
            bail!("input history {kind:?} failure at step {step}");
        }
        Ok(())
    }

    pub fn compare_saved(&self, saved: &Self, step: usize) -> Result<()> {
        if let Some(recorded) = saved.observations.get(step) {
            ensure!(
                self.observations.get(step) == Some(recorded),
                "input history recorded observation mismatch at step {step}"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "fixture", content = "history", deny_unknown_fields)]
pub(super) enum Case {
    Ids(read_coverage_tests::IdHistory),
    Cursors(selection_tests::CursorHistory),
}

impl Case {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Ids(history) => read_coverage_tests::validate_id_history(history),
            Self::Cursors(history) => selection_tests::validate_cursor_history(history),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    format: u8,
    implementation: String,
    case: Case,
}

fn implementation() -> String {
    // Pin the exercised decision/codec code, synthetic fixtures, replay oracle,
    // dependency lock and toolchains. Signing or rebasing alone does not alter
    // this identity; changing covered source bytes requires a new history.
    let sources: &[(&str, &[u8])] = &[
        ("host_inputs", include_bytes!("host_inputs.rs")),
        ("host", include_bytes!("host.rs")),
        ("store", include_bytes!("store.rs")),
        ("simulation", include_bytes!("simulation.rs")),
        ("protocol", include_bytes!("protocol.rs")),
        ("identity", include_bytes!("identity.rs")),
        ("schema", include_bytes!("schema.rs")),
        ("authority", include_bytes!("authority.rs")),
        ("authority_state", include_bytes!("authority_state.rs")),
        ("artifact", include_bytes!("artifact.rs")),
        ("json", include_bytes!("json.rs")),
        ("journal", include_bytes!("journal.rs")),
        ("write_queue", include_bytes!("write_queue.rs")),
        ("error", include_bytes!("error.rs")),
        ("id_fixture", include_bytes!("read_coverage_tests.rs")),
        ("replay", include_bytes!("runtime_input_replay_tests.rs")),
        ("dependencies", include_bytes!("../../../Cargo.lock")),
        ("rust", include_bytes!("../../../rust-toolchain.toml")),
        ("toolchain", include_bytes!("../../../toolchain.json")),
    ];
    let identities: Vec<_> = sources
        .iter()
        .map(|(name, bytes)| (*name, crate::digest(bytes)))
        .collect();
    crate::digest(&serde_json::to_vec(&identities).expect("fixed source identities serialize"))
}

pub(super) fn command(path: &Path) -> String {
    let quoted = path.to_string_lossy().replace('\'', "'\"'\"'");
    format!(
        "DAY2_RUNTIME_INPUT_REPLAY='{quoted}' cargo test --locked -p day2 --lib store::input_replay_tests::replay_saved_runtime_input_history -- --exact"
    )
}

pub(super) fn checkpoint(path: &Path, case: Case) -> Result<()> {
    case.validate()?;
    let saved = Saved {
        format: 1,
        implementation: implementation(),
        case,
    };
    let bytes = serde_json::to_vec_pretty(&saved)?;
    ensure!(bytes.len() as u64 <= MAX_BYTES, "input history byte budget");
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("input history directory")?)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

fn read(path: &Path) -> Result<Saved> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "input history requires a regular file");
    ensure!(metadata.len() <= MAX_BYTES, "input history byte budget");
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_BYTES, "input history byte budget");
    let saved: Saved = crate::json::decode(&bytes).context("decode runtime input history")?;
    ensure!(saved.format == 1, "unsupported input history format");
    ensure!(
        saved.implementation == implementation(),
        "input history implementation changed"
    );
    saved.case.validate()?;
    Ok(saved)
}

pub(super) fn replay(path: &Path) -> Result<()> {
    match read(path)?.case {
        Case::Ids(history) => read_coverage_tests::check_id_history(&history, None).map(|_| ()),
        Case::Cursors(history) => selection_tests::check_cursor_history(&history, None).map(|_| ()),
    }
    .with_context(|| {
        format!(
            "saved runtime input replay failed; repeat: {}",
            command(path)
        )
    })
}

#[test]
fn replay_saved_runtime_input_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_RUNTIME_INPUT_REPLAY") else {
        return Ok(());
    };
    replay(Path::new(&path))
}

fn id_case() -> Result<Case> {
    Ok(Case::Ids(read_coverage_tests::check_id_history(
        &read_coverage_tests::id_history(false),
        None,
    )?))
}

#[test]
fn saved_histories_replay_both_fixtures_and_preserve_partial_inputs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("saved 'history.json");
    let cases = [
        id_case()?,
        Case::Cursors(selection_tests::check_cursor_history(
            &selection_tests::cursor_history(7),
            None,
        )?),
    ];
    for case in cases {
        checkpoint(&path, case.clone())?;
        let before = std::fs::read(&path)?;
        replay(&path)?;
        assert_eq!(std::fs::read(&path)?, before);
        let partial = match case {
            Case::Ids(mut history) => {
                history.observations.truncate(2);
                Case::Ids(history)
            }
            Case::Cursors(mut history) => {
                history.observations.truncate(1);
                Case::Cursors(history)
            }
        };
        checkpoint(&path, partial)?;
        let mut bytes = std::fs::read(&path)?;
        bytes.resize(MAX_BYTES as usize, b' ');
        std::fs::write(&path, &bytes)?;
        replay(&path)?;
        assert_eq!(
            std::fs::read(&path)?,
            bytes,
            "replay must not replace retained evidence"
        );
    }
    assert!(command(&path).contains("'\"'\"'"));
    Ok(())
}

#[test]
fn saved_history_format_identity_shape_and_observations_fail_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("history.json");
    checkpoint(&path, id_case()?)?;
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let mut candidates = Vec::new();
    let mut changed = original.clone();
    changed["format"] = serde_json::json!(2);
    candidates.push(changed);
    let mut changed = original.clone();
    changed["implementation"] = serde_json::json!("stale");
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["fixture"] = serde_json::json!("Unknown");
    candidates.push(changed);
    let mut changed = original.clone();
    changed["unexpected"] = serde_json::json!(true);
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["history"]["observations"][0]["value"]["unexpected"] = serde_json::json!(true);
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["history"]["actions"][3]["unexpected"] = serde_json::json!(true);
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["history"]["inputs"]["seed"][0] = serde_json::json!(0);
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["history"]["observations"][4]["value"]["monotonic_ns"] = serde_json::json!(0);
    candidates.push(changed);
    let mut changed = original.clone();
    let action = changed["case"]["history"]["actions"][0].clone();
    changed["case"]["history"]["actions"] = serde_json::json!(vec![action; MAX_STEPS + 1]);
    candidates.push(changed);
    let mut changed = original.clone();
    let observed = changed["case"]["history"]["observations"][0].clone();
    changed["case"]["history"]["observations"] = serde_json::json!(vec![observed; MAX_STEPS + 1]);
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["history"]["failure"] = serde_json::json!({"step":99,"kind":"Oracle"});
    candidates.push(changed);
    let mut changed = original.clone();
    changed["case"]["history"]["observations"][0] =
        serde_json::json!({"status":"Error","value":"native failure"});
    candidates.push(changed);
    for (index, candidate) in candidates.into_iter().enumerate() {
        let bytes = serde_json::to_vec(&candidate)?;
        std::fs::write(&path, &bytes)?;
        ensure!(
            replay(&path).is_err(),
            "malformed history candidate {index} accepted"
        );
        assert_eq!(std::fs::read(&path)?, bytes);
    }
    checkpoint(
        &path,
        Case::Cursors(selection_tests::check_cursor_history(
            &selection_tests::cursor_history(0),
            None,
        )?),
    )?;
    let mut changed: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    changed["case"]["history"]["observations"][0]["value"]["page"]["next_after"] =
        serde_json::json!("changed");
    std::fs::write(&path, serde_json::to_vec(&changed)?)?;
    assert!(replay(&path).is_err());
    for malformed in [b"{".as_slice(), b"{\"format\":1,\"format\":1}".as_slice()] {
        std::fs::write(&path, malformed)?;
        assert!(read(&path).is_err());
    }
    assert!(read(directory.path()).is_err());
    std::fs::write(&path, vec![b' '; MAX_BYTES as usize + 1])?;
    assert!(read(&path).unwrap_err().to_string().contains("byte budget"));
    Ok(())
}

#[test]
fn checkpoint_retains_clock_failure_position_and_replay_never_accepts_it() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("failed-clock.json");
    let observed =
        read_coverage_tests::check_id_history(&read_coverage_tests::id_history(false), None)?;
    let Recorded::Ok(expected) = &observed.observations[4] else {
        bail!("missing elapsed-clock observation");
    };
    let mut broken = serde_json::to_value(expected)?;
    broken["monotonic_ns"] = serde_json::json!(0);
    broken["input_monotonic_ns"] = serde_json::json!(0);
    let broken = serde_json::from_value(broken)?;
    let mut failed = observed.clone();
    failed.observations.truncate(4);
    assert!(failed.observe(Ok(broken), expected).is_err());
    assert_eq!(
        failed.failure,
        Some(Failure {
            step: Some(4),
            kind: FailureKind::Oracle
        })
    );
    checkpoint(&path, Case::Ids(failed))?;
    let before = std::fs::read(&path)?;
    let saved = read(&path)?;
    assert!(
        matches!(saved.case, Case::Ids(history) if history.failure.as_ref().is_some_and(|failure| failure.step == Some(4)))
    );
    assert!(replay(&path).is_err());
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn fixture_and_native_failures_keep_their_stage_and_cannot_become_successful_replay() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("failure.json");
    let mut fixture = read_coverage_tests::id_history(false);
    fixture.fixture_failed(&anyhow::anyhow!("injected fixture failure"));
    checkpoint(&path, Case::Ids(fixture))?;
    let before = std::fs::read(&path)?;
    assert!(replay(&path).is_err());
    assert_eq!(std::fs::read(&path)?, before);
    let observed =
        read_coverage_tests::check_id_history(&read_coverage_tests::id_history(false), None)?;
    let Recorded::Ok(expected) = &observed.observations[0] else {
        bail!("missing initial observation");
    };
    for actual in [
        Err(anyhow::anyhow!("injected native failure")),
        capture(|| -> Result<read_coverage_tests::IdObservation> {
            panic!("injected native panic")
        }),
    ] {
        let mut native = read_coverage_tests::id_history(false);
        assert!(native.observe(actual, expected).is_err());
        checkpoint(&path, Case::Ids(native))?;
        let before = std::fs::read(&path)?;
        assert!(replay(&path).is_err());
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}
