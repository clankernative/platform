use super::*;
use std::io::{Read as _, Write as _};

const MAX_EVENTS: usize = 24;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_DECODED_BYTES: usize = 16 * 1024 * 1024;
const MAX_PART_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Prepare {},
    Apply { cut: Cut },
    Observe {},
    Reopen {},
    Disable {},
    Expire {},
    RemoveAdvance {},
    RemoveLedger {},
    RewriteRoot {},
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    source: Digest,
    seed: u64,
    keys: u8,
    events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Prepared,
    Refused,
    Acknowledged,
    Uncertain,
    Applied,
    NotApplied,
    Conflict,
    Data,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    decision: Decision,
    rows: Vec<Row>,
    sends: u64,
    prepared: Option<Digest>,
    enabled: bool,
    at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureStage {
    Fixture,
    TemporaryDirectory,
    ProviderSetup,
    ReferenceSetup,
    RequestSetup,
    Step,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    actual: Vec<Observation>,
    expected: Vec<Observation>,
    failure: Option<(FailureStage, usize)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    format: u32,
    input: Input,
    first: Run,
    second: Run,
}

fn source() -> Result<Digest> {
    Digest::of(&(
        "day2-secure-restore-history-v1",
        std::env::consts::OS,
        std::env::consts::ARCH,
        include_str!("history.rs"),
        include_str!("../tests.rs"),
        include_str!("../../restore.rs"),
        include_str!("../../advance.rs"),
        include_str!("../../../kernel.rs"),
        include_str!("../../../tests.rs"),
        include_str!("../../../../json.rs"),
        include_str!("../../../../../../day2-capabilities/src/lib.rs"),
        include_str!("../../../../../../day2-capabilities/src/security_epoch.rs"),
        include_str!("../../../../../../../Cargo.lock"),
    ))
}

fn validate(input: &Input) -> Result<()> {
    ensure!(
        input.source == source()?
            && (1..=32).contains(&input.keys)
            && !input.events.is_empty()
            && input.events.len() <= MAX_EVENTS,
        "restore_replay_identity_or_bound"
    );
    Ok(())
}

fn fixture(input: &Input) -> Result<(EpochStore, Snapshot, Intent, Current)> {
    validate(input)?;
    let (selected, before) = initial();
    let mut intent = intent(&selected, input.seed);
    intent.archive.required_keys = (0..input.keys)
        .map(|n| ExactKey {
            binding: BindingRef {
                id: format!("custody-{n:02}").try_into().unwrap(),
                revision: Digest::of(&("key-binding", n)).unwrap(),
            },
            version: format!("version-{n:02}-{}", "x".repeat(100)),
            purpose: KeyPurpose::CustodyEncryption,
        })
        .collect();
    let current = current(&selected, &intent, &before);
    Ok((selected, before, intent, current))
}

/// Event-only reference. It owns immutable initial/derived wire rows and its own
/// symbolic preparation, clock, source and attempt history. No actual Result or
/// readback is fed into the next expectation.
struct Model {
    rows: Vec<Row>,
    initial: Vec<Row>,
    after: Vec<Row>,
    prepared: Option<Digest>,
    expected_receipt: Digest,
    enabled: bool,
    at: i64,
    sends: u64,
}

impl Model {
    fn new(
        selected: &EpochStore,
        before: &Snapshot,
        intent: &Intent,
        current: &Current,
    ) -> Result<Self> {
        let initial = initial_rows(before)?;
        let after = expected(selected, intent, current, before, 1000)?;
        let expected_receipt: Digest = serde_json::from_value(
            after
                .iter()
                .find(|r| r.name.starts_with("restore/"))
                .unwrap()
                .body["request_digest"]
                .clone(),
        )?;
        Ok(Self {
            rows: initial.clone(),
            initial,
            after,
            prepared: None,
            expected_receipt,
            enabled: true,
            at: 1000,
            sends: 0,
        })
    }

    fn step(&mut self, event: Event) -> Observation {
        let permitted = self.enabled && self.at == 1000 && self.rows == self.initial;
        let decision = match event {
            Event::Prepare {} if permitted => {
                self.prepared = Some(self.expected_receipt.clone());
                Decision::Prepared
            }
            Event::Prepare {} => Decision::Refused,
            Event::Apply { cut } if permitted && self.prepared.is_some() => {
                self.sends += 1;
                if cut.committed() {
                    self.rows = self.after.clone();
                }
                if cut == Cut::Complete {
                    Decision::Acknowledged
                } else {
                    Decision::Uncertain
                }
            }
            Event::Apply { .. } => Decision::Refused,
            Event::Observe {} => {
                if self.prepared.is_none() {
                    Decision::Refused
                } else if self.rows == self.initial {
                    Decision::NotApplied
                } else if self.rows.len() == self.after.len()
                    && self.rows.iter().zip(&self.after).all(|(actual, after)| {
                        actual.name == after.name
                            && actual.body == after.body
                            && (!matches!(actual.name.as_str(), "root" | "sentinel")
                                || actual.version != 2)
                    })
                {
                    Decision::Applied
                } else {
                    Decision::Conflict
                }
            }
            Event::Reopen {} => Decision::Data,
            Event::Disable {} => {
                self.enabled = false;
                Decision::Data
            }
            Event::Expire {} => {
                self.at = 1100;
                Decision::Data
            }
            Event::RemoveAdvance {} => {
                self.rows.retain(|r| !r.name.starts_with("advance/"));
                Decision::Data
            }
            Event::RemoveLedger {} => {
                self.rows.retain(|r| !r.name.starts_with("restore/"));
                Decision::Data
            }
            Event::RewriteRoot {} => {
                self.rows
                    .iter_mut()
                    .find(|r| r.name == "root")
                    .unwrap()
                    .version += 1;
                Decision::Data
            }
        };
        Observation {
            decision,
            rows: self.rows.clone(),
            sends: self.sends,
            prepared: self.prepared.clone(),
            enabled: self.enabled,
            at: self.at,
        }
    }
}

fn run(input: &Input, wrong: bool) -> Result<Run> {
    run_with_setup(input, wrong, None)
}

fn run_with_setup(input: &Input, wrong: bool, injected: Option<FailureStage>) -> Result<Run> {
    // Reject foreign/oversized programs before execution, but every admitted
    // setup failure thereafter becomes a retained closed prefix.
    validate(input)?;
    let mut report = Run {
        actual: vec![],
        expected: vec![],
        failure: None,
    };
    let mut stage = FailureStage::Fixture;
    let setup = (|| -> Result<_> {
        ensure!(injected != Some(stage), "restore_injected_setup_refusal");
        let (selected, before, intent, current) = fixture(input)?;
        stage = FailureStage::TemporaryDirectory;
        ensure!(injected != Some(stage), "restore_injected_setup_refusal");
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("outside-backup-epoch.sqlite");
        stage = FailureStage::ProviderSetup;
        ensure!(injected != Some(stage), "restore_injected_setup_refusal");
        let provider = Provider::open(&path, &before)?;
        stage = FailureStage::ReferenceSetup;
        ensure!(injected != Some(stage), "restore_injected_setup_refusal");
        let model = Model::new(&selected, &before, &intent, &current)?;
        stage = FailureStage::RequestSetup;
        ensure!(injected != Some(stage), "restore_injected_setup_refusal");
        let request = Request::new(&selected, intent.clone(), &current, 1000, &before)?;
        Ok((selected, current, directory, path, provider, model, request))
    })();
    let (selected, mut current, _directory, path, mut provider, mut model, request) = match setup {
        Ok(value) => value,
        Err(_) => {
            report.failure = Some((stage, 0));
            return Ok(report);
        }
    };
    let mut plan = None;
    let mut at = 1000;
    for (index, event) in input.events.iter().copied().enumerate() {
        let mut wanted = model.step(event);
        if wrong && matches!(event, Event::Observe {}) && wanted.decision == Decision::Applied {
            // False oracle says a lost response rolled back the committed fence.
            wanted.decision = Decision::NotApplied;
        }
        report.expected.push(wanted);
        let actual = (|| -> Result<Observation> {
            let decision = match event {
                Event::Prepare {} => match request.prepare(
                    &selected,
                    &current,
                    at,
                    &provider.snapshot()?,
                    provider
                        .read(&format!("restore/{}", request.intent.operation.as_str()))?
                        .as_ref(),
                ) {
                    Ok(prepared) => {
                        plan = Some(prepared);
                        Decision::Prepared
                    }
                    Err(_) => Decision::Refused,
                },
                Event::Apply { cut } => match &plan {
                    None => Decision::Refused,
                    Some(plan) => {
                        let prior = provider.sends()?;
                        let result = provider.apply_cut(&selected, &current, at, plan, cut);
                        match (result.is_ok(), provider.sends()? > prior) {
                            (true, true) => Decision::Acknowledged,
                            (false, true) => Decision::Uncertain,
                            (false, false) => Decision::Refused,
                            (true, false) => anyhow::bail!("restore_fixture_missing_send"),
                        }
                    }
                },
                Event::Observe {} => match &plan {
                    None => Decision::Refused,
                    Some(plan) => match provider.outcome(&selected, plan)? {
                        Outcome::Applied(_) => Decision::Applied,
                        Outcome::NotApplied => Decision::NotApplied,
                        Outcome::Conflict => Decision::Conflict,
                    },
                },
                Event::Reopen {} => {
                    provider.reopen(&path)?;
                    Decision::Data
                }
                Event::Disable {} => {
                    current.enabled = false;
                    Decision::Data
                }
                Event::Expire {} => {
                    at = 1100;
                    Decision::Data
                }
                Event::RemoveAdvance {} => {
                    provider
                        .db
                        .execute("DELETE FROM records WHERE name GLOB 'advance/*'", [])?;
                    Decision::Data
                }
                Event::RemoveLedger {} => {
                    provider
                        .db
                        .execute("DELETE FROM records WHERE name GLOB 'restore/*'", [])?;
                    Decision::Data
                }
                Event::RewriteRoot {} => {
                    provider
                        .db
                        .execute("UPDATE records SET version=version+1 WHERE name='root'", [])?;
                    Decision::Data
                }
            };
            Ok(Observation {
                decision,
                rows: provider.rows()?,
                sends: provider.sends()?,
                prepared: plan.as_ref().map(|p| p.receipt.request_digest.clone()),
                enabled: current.enabled,
                at,
            })
        })();
        match actual {
            Ok(observed) => report.actual.push(observed),
            Err(_) => {
                report.failure = Some((FailureStage::Step, index));
                break;
            }
        }
    }
    Ok(report)
}

fn divergent(run: &Run) -> bool {
    run.failure.is_some() || run.actual != run.expected
}

fn reproduces(actual: &Run, saved: &Run) -> bool {
    actual.actual == saved.actual && actual.failure == saved.failure
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "part", rename_all = "snake_case", deny_unknown_fields)]
enum Part {
    Header {
        format: u32,
        input: Input,
    },
    Run {
        run: u8,
        actual: usize,
        expected: usize,
        failure: Option<(FailureStage, usize)>,
    },
    Cut {
        run: u8,
        index: usize,
        actual: Option<Observation>,
        expected: Option<Observation>,
    },
    End {},
}

fn validate_run(run: &Run, events: usize) -> Result<()> {
    let a = run.actual.len();
    let e = run.expected.len();
    ensure!(a <= events && e <= events, "restore_run_length");
    match run.failure {
        None => ensure!(
            a == events && e == events,
            "restore_incomplete_unfailed_run"
        ),
        Some((FailureStage::Step, index)) => {
            ensure!(index == a && e == a + 1, "restore_step_prefix")
        }
        Some((_, index)) => ensure!(index == 0 && a == 0 && e == 0, "restore_setup_prefix"),
    }
    Ok(())
}

fn encode(bundle: &Bundle) -> Result<Vec<u8>> {
    validate(&bundle.input)?;
    let mut raw = Vec::new();
    let mut append = |part: Part| -> Result<()> {
        let bytes = serde_json::to_vec(&part)?;
        ensure!(bytes.len() <= MAX_PART_BYTES, "restore_history_part_bound");
        raw.extend_from_slice(&bytes);
        raw.push(b'\n');
        ensure!(
            raw.len() <= MAX_DECODED_BYTES,
            "restore_history_decoded_bound"
        );
        Ok(())
    };
    append(Part::Header {
        format: bundle.format,
        input: bundle.input.clone(),
    })?;
    for (id, run) in [(0, &bundle.first), (1, &bundle.second)] {
        validate_run(run, bundle.input.events.len())?;
        append(Part::Run {
            run: id,
            actual: run.actual.len(),
            expected: run.expected.len(),
            failure: run.failure,
        })?;
        for index in 0..run.actual.len().max(run.expected.len()) {
            append(Part::Cut {
                run: id,
                index,
                actual: run.actual.get(index).cloned(),
                expected: run.expected.get(index).cloned(),
            })?;
        }
    }
    append(Part::End {})?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&raw)?;
    let bytes = gzip.finish()?;
    ensure!(bytes.len() <= MAX_BYTES, "restore_history_encoded_bound");
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Bundle> {
    // Untrusted field names/values must not escape through serde's Display.
    // Use the same bounded parser, with one closed admission error boundary.
    decode_contents(bytes).map_err(|_| anyhow::anyhow!("secure_restore_replay_refused"))
}

fn decode_contents(bytes: &[u8]) -> Result<Bundle> {
    ensure!(bytes.len() <= MAX_BYTES, "restore_history_encoded_bound");
    let mut reader = flate2::bufread::GzDecoder::new(bytes);
    let mut raw = Vec::new();
    reader
        .by_ref()
        .take((MAX_DECODED_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= MAX_DECODED_BYTES && reader.into_inner().is_empty(),
        "restore_history_decoded_or_trailing_bound"
    );
    let mut lines = raw.split(|b| *b == b'\n');
    let mut next = || -> Result<Part> {
        let bytes = lines.next().context("restore_missing_part")?;
        ensure!(bytes.len() <= MAX_PART_BYTES, "restore_history_part_bound");
        let part: Part = crate::json::decode_evidence(bytes)?;
        ensure!(
            serde_json::to_vec(&part)? == bytes,
            "restore_noncanonical_part"
        );
        Ok(part)
    };
    let Part::Header { format, input } = next()? else {
        anyhow::bail!("restore_header_order");
    };
    ensure!(format == 1, "restore_history_format");
    validate(&input)?;
    let mut runs = Vec::new();
    for id in [0, 1] {
        let Part::Run {
            run,
            actual,
            expected,
            failure,
        } = next()?
        else {
            anyhow::bail!("restore_run_order");
        };
        ensure!(
            run == id && actual <= input.events.len() && expected <= input.events.len(),
            "restore_run_count_or_identity"
        );
        let mut trace = Run {
            actual: Vec::new(),
            expected: Vec::new(),
            failure,
        };
        for index in 0..actual.max(expected) {
            let Part::Cut {
                run,
                index: observed,
                actual: a,
                expected: e,
            } = next()?
            else {
                anyhow::bail!("restore_cut_order");
            };
            ensure!(
                run == id
                    && observed == index
                    && a.is_some() == (index < actual)
                    && e.is_some() == (index < expected),
                "restore_cut_count_or_identity"
            );
            if let Some(a) = a {
                trace.actual.push(a);
            }
            if let Some(e) = e {
                trace.expected.push(e);
            }
        }
        validate_run(&trace, input.events.len())?;
        runs.push(trace);
    }
    ensure!(matches!(next()?, Part::End {}), "restore_end_order");
    ensure!(
        lines.next() == Some(b"".as_slice()) && lines.next().is_none(),
        "restore_extra_or_unterminated_part"
    );
    let second = runs.pop().unwrap();
    let first = runs.pop().unwrap();
    Ok(Bundle {
        format,
        input,
        first,
        second,
    })
}

#[derive(Debug)]
struct SavedFailure(std::path::PathBuf);
impl std::fmt::Display for SavedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("secure_restore_failure_saved")
    }
}
impl std::error::Error for SavedFailure {}

fn retain(bundle: &Bundle) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let directory = tempfile::Builder::new()
        .prefix("restore-")
        .tempdir_in({
            let path =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/control-slot-replays");
            std::fs::create_dir_all(&path)?;
            path
        })?
        .keep();
    let path = directory.join("replay.json.gz");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&encode(bundle)?)?;
    file.sync_all()?;
    Ok(path)
}

fn check(input: &Input, wrong_first: bool, wrong_second: bool) -> Result<()> {
    validate(input)?;
    let first = run(input, wrong_first)?;
    let second = run(input, wrong_second)?;
    record(input, first, second)
}

fn record(input: &Input, first: Run, second: Run) -> Result<()> {
    if divergent(&first) || divergent(&second) || first != second {
        let path = retain(&Bundle {
            format: 1,
            input: input.clone(),
            first,
            second,
        })?;
        return Err(SavedFailure(path).into());
    }
    Ok(())
}

fn input(seed: u64, cut: Cut) -> Result<Input> {
    let mut events = vec![
        Event::Prepare {},
        Event::Apply { cut },
        Event::Observe {},
        Event::Reopen {},
        Event::Observe {},
    ];
    let mut random = seed.wrapping_add(17);
    for n in 0..10 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        events.push(match random % 5 {
            0 => Event::Observe {},
            1 => Event::Reopen {},
            2 => Event::Prepare {},
            3 => Event::Disable {},
            _ if n % 2 == 0 => Event::RemoveAdvance {},
            _ => Event::RewriteRoot {},
        });
    }
    events.extend([
        Event::Expire {},
        Event::Apply { cut: Cut::Complete },
        Event::Observe {},
    ]);
    Ok(Input {
        source: source()?,
        seed,
        keys: 1,
        events,
    })
}

#[test]
fn generated_restore_histories_compare_complete_independent_rows_and_replay_twice() -> Result<()> {
    for seed in 0..4 {
        for cut in Cut::ALL {
            check(&input(seed, cut)?, false, false)?;
        }
    }
    Ok(())
}

#[test]
fn every_admitted_setup_failure_retains_input_and_the_completed_first_run() -> Result<()> {
    let input = input(14, Cut::AfterCommit)?;
    for stage in [
        FailureStage::Fixture,
        FailureStage::TemporaryDirectory,
        FailureStage::ProviderSetup,
        FailureStage::ReferenceSetup,
        FailureStage::RequestSetup,
    ] {
        let first = run(&input, false)?;
        let second = run_with_setup(&input, false, Some(stage))?;
        assert_eq!(second.failure, Some((stage, 0)));
        let expected = first.clone();
        let error = record(&input, first, second.clone()).unwrap_err();
        let path = &error
            .downcast_ref::<SavedFailure>()
            .context("saved setup failure missing")?
            .0;
        let saved = decode(&std::fs::read(path)?)?;
        assert_eq!(saved.first, expected);
        assert_eq!(saved.second, second);
        assert_eq!(saved.input.events.len(), input.events.len());
    }
    Ok(())
}

#[test]
fn identical_observation_prefixes_cannot_substitute_a_different_failure_frontier() -> Result<()> {
    let input = input(15, Cut::AfterCommit)?;
    let fixture = run_with_setup(&input, false, Some(FailureStage::Fixture))?;
    let provider = run_with_setup(&input, false, Some(FailureStage::ProviderSetup))?;
    assert_eq!(fixture.actual, provider.actual);
    assert_ne!(fixture.failure, provider.failure);
    assert!(!reproduces(&provider, &fixture));
    assert!(reproduces(&fixture, &fixture));
    let correct = run(&input, false)?;
    let wrong = run(&input, true)?;
    assert!(divergent(&wrong));
    // A deliberately false reference remains historical, but the full actual
    // result and exact failure frontier must independently reproduce.
    assert!(reproduces(&correct, &wrong));
    Ok(())
}

#[test]
fn committed_uncertainty_and_second_run_divergence_have_lossless_replay_bundles() -> Result<()> {
    for (first, second) in [(true, false), (false, true)] {
        let input = input(7, Cut::AfterCommit)?;
        let error = check(&input, first, second).unwrap_err();
        let path = &error
            .downcast_ref::<SavedFailure>()
            .context("saved restore failure missing")?
            .0;
        let bundle = decode(&std::fs::read(path)?)?;
        assert_eq!(divergent(&bundle.first), first);
        assert_eq!(divergent(&bundle.second), second);
        assert_eq!(bundle.first.actual.len(), input.events.len());
        assert_eq!(bundle.second.actual.len(), input.events.len());
        assert_eq!(run(&bundle.input, false)?.actual, bundle.first.actual);
        assert_eq!(run(&bundle.input, false)?.actual, bundle.second.actual);
    }
    Ok(())
}

#[test]
fn maximum_restore_manifest_and_history_fit_the_unchanged_evidence_decoder() -> Result<()> {
    let mut input = input(9, Cut::AfterCommit)?;
    input.keys = 32;
    while input.events.len() < MAX_EVENTS {
        input.events.push(Event::Observe {});
    }
    let first = run(&input, false)?;
    let second = run(&input, false)?;
    assert!(!divergent(&first) && first == second);
    let bundle = Bundle {
        format: 1,
        input,
        first,
        second,
    };
    let encoded = encode(&bundle)?;
    let decoded = decode(&encoded)?;
    let marker = "RESTORE_REPLAY_PRIVATE_FIELD_CANARY";
    let mut unknown = serde_json::to_value(Part::Header {
        format: 1,
        input: decoded.input.clone(),
    })?;
    unknown
        .as_object_mut()
        .unwrap()
        .insert(marker.into(), serde_json::json!(true));
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&serde_json::to_vec(&unknown)?)?;
    let invalid = gzip.finish()?;
    // The same parser's original error really contains the synthetic field;
    // the actual reader boundary must replace it, not merely omit saved text.
    let unredacted = decode_contents(&invalid)
        .err()
        .context("missing raw decoder refusal")?;
    assert!(unredacted.to_string().contains(marker));
    let refused = decode(&invalid)
        .err()
        .context("missing closed decoder refusal")?;
    assert!(
        refused.to_string() == "secure_restore_replay_refused",
        "replay error boundary was not closed"
    );
    assert_eq!(decoded.first, bundle.first);
    assert_eq!(decoded.second, bundle.second);
    let mut trailing = encoded.clone();
    trailing.extend_from_slice(b"foreign");
    assert!(decode(&trailing).is_err());
    let mut stale = decoded.input.clone();
    stale.source = Digest::new(b"other-source");
    assert!(check(&stale, false, false).is_err());
    stale = decoded.input.clone();
    stale.events.push(Event::Observe {});
    assert!(check(&stale, false, false).is_err());
    Ok(())
}

#[test]
fn replay_saved_secure_restore_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_SECURE_RESTORE_REPLAY") else {
        return Ok(());
    };
    let mut file = std::fs::File::open(path)?;
    ensure!(file.metadata()?.is_file(), "restore_replay_not_regular");
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let bundle = decode(&bytes)?;
    ensure!(
        divergent(&bundle.first) || divergent(&bundle.second) || bundle.first != bundle.second,
        "restore_replay_not_a_counterexample"
    );
    let first = run(&bundle.input, false)?;
    let second = run(&bundle.input, false)?;
    ensure!(
        reproduces(&first, &bundle.first) && reproduces(&second, &bundle.second),
        "restore_replay_observations_changed"
    );
    Ok(())
}
