use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSnapshot {
    root: (AuthorityRecord, super::super::super::UpdateTime),
    sentinel: (SentinelRecord, super::super::super::UpdateTime),
    create: (InitialReceipt, super::super::super::UpdateTime),
    activate: (InitialReceipt, super::super::super::UpdateTime),
}

impl SavedSnapshot {
    fn save(snapshot: &Snapshot) -> Self {
        Self {
            root: (
                snapshot.root.as_ref().unwrap().value.clone(),
                snapshot.root.as_ref().unwrap().version.clone(),
            ),
            sentinel: (
                snapshot.sentinel.as_ref().unwrap().value.clone(),
                snapshot.sentinel.as_ref().unwrap().version.clone(),
            ),
            create: (
                snapshot.create.as_ref().unwrap().value.clone(),
                snapshot.create.as_ref().unwrap().version.clone(),
            ),
            activate: (
                snapshot.activate.as_ref().unwrap().value.clone(),
                snapshot.activate.as_ref().unwrap().version.clone(),
            ),
        }
    }

    fn load(&self) -> Snapshot {
        Snapshot {
            root: Some(Versioned {
                value: self.root.0.clone(),
                version: self.root.1.clone(),
            }),
            sentinel: Some(Versioned {
                value: self.sentinel.0.clone(),
                version: self.sentinel.1.clone(),
            }),
            create: Some(Versioned {
                value: self.create.0.clone(),
                version: self.create.1.clone(),
            }),
            activate: Some(Versioned {
                value: self.activate.0.clone(),
                version: self.activate.1.clone(),
            }),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    format: u32,
    source: Digest,
    selection: EpochStore,
    before: SavedSnapshot,
    operation: Digest,
    cut: Cut,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Report {
    actual: Value,
    expected: Value,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureStage {
    FirstRun,
    ReplayRun,
    ModelComparison,
}

#[derive(Debug)]
struct SavedFailure(std::path::PathBuf);

impl std::fmt::Display for SavedFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("epoch_advance_history_failure_saved")
    }
}

impl std::error::Error for SavedFailure {}

fn source() -> Result<Digest> {
    Digest::of(&(
        "day2-first-epoch-advance-history-v1",
        std::env::consts::OS,
        std::env::consts::ARCH,
        include_str!("history.rs"),
        include_str!("../tests.rs"),
        include_str!("../../advance.rs"),
        include_str!("../../../kernel.rs"),
        include_str!("../../../tests.rs"),
        include_str!("../../../../json.rs"),
        include_str!("../../../../../../day2-capabilities/src/lib.rs"),
        include_str!("../../../../../../day2-capabilities/src/security_epoch.rs"),
        include_str!("../../../../../../day2-capabilities/src/oauth.rs"),
        include_str!("../../../../../../../Cargo.lock"),
    ))
}

fn rows(
    before: &Snapshot,
    after: Option<&(AuthorityRecord, SentinelRecord, Receipt)>,
) -> Result<Value> {
    let mut records = std::collections::BTreeMap::from([
        (
            "root".to_owned(),
            (
                serde_json::to_value(&before.root.as_ref().unwrap().value)?,
                2,
            ),
        ),
        (
            "sentinel".to_owned(),
            (
                serde_json::to_value(&before.sentinel.as_ref().unwrap().value)?,
                2,
            ),
        ),
        (
            "create".to_owned(),
            (
                serde_json::to_value(&before.create.as_ref().unwrap().value)?,
                1,
            ),
        ),
        (
            "activate".to_owned(),
            (
                serde_json::to_value(&before.activate.as_ref().unwrap().value)?,
                2,
            ),
        ),
    ]);
    if let Some((root, sentinel, receipt)) = after {
        records.insert("root".into(), (serde_json::to_value(root)?, 3));
        records.insert("sentinel".into(), (serde_json::to_value(sentinel)?, 3));
        records.insert(
            receipt.request.operation.as_str().into(),
            (serde_json::to_value(receipt)?, 3),
        );
    }
    Ok(json!(
        records
            .into_iter()
            .map(|(name, (body, version))| json!({"name":name,"body":body,"version":version}))
            .collect::<Vec<_>>()
    ))
}

fn run(history: &History) -> Result<Report> {
    validate_input(history)?;
    let before = history.before.load();
    let request = Request::new(&history.selection, history.operation.clone(), &before)?;
    let reference = expected(&request, &before)?;
    let applied = matches!(history.cut, Cut::Known | Cut::AfterCommit);
    // Predict before executing the adapter. This is a complete-row oracle,
    // including immutable history, receipt identity and provider versions.
    let expected = json!({
        "acknowledged":matches!(history.cut,Cut::Known),
        "rows":rows(&before,applied.then_some(&reference))?,
        "sends":1,
        "classification":if applied {"applied"} else {"not_applied"},
        "initial_requests_reconcile":[!applied,!applied],
    });
    let mut provider = Provider::new(&before)?;
    let acknowledged = provider
        .apply(&request.prepare(&history.selection, &before)?, history.cut)
        .is_ok();
    ensure!(
        provider.db.is_autocommit(),
        "epoch_advance_history_open_transaction"
    );
    let observed = provider.snapshot()?;
    let stored = provider.read::<Receipt>(request.operation.as_str())?;
    let classified = match reconcile(&history.selection, &request, &observed, stored.as_ref()) {
        Ok(Outcome::Applied(_)) => "applied",
        Ok(Outcome::NotApplied) => "not_applied",
        Err(_) => "refused",
    };
    let create = InitialRequest::CreateInitialAuthority {
        bootstrap: request.activation.request.bootstrap().clone(),
    };
    let initial = [&create, &request.activation.request]
        .map(|old| super::super::super::reconcile(&history.selection, old, &observed).is_ok());
    Ok(Report {
        actual: json!({"acknowledged":acknowledged,"rows":provider.rows()?,"sends":provider.sends(),"classification":classified,"initial_requests_reconcile":initial}),
        expected,
    })
}

fn decode(bytes: &[u8]) -> Result<History> {
    ensure!(bytes.len() <= 65_536, "epoch_advance_history_input_budget");
    crate::json::decode(bytes)
}

fn validate_input(history: &History) -> Result<()> {
    ensure!(
        history.format == 1 && history.source == source()?,
        "epoch_advance_history_source"
    );
    require_fixture_versions(&history.before.load())
}

fn save_failure(
    history: &History,
    stage: FailureStage,
    first: Option<&Report>,
    replay: Option<&Report>,
) -> Result<std::path::PathBuf> {
    let bundle = json!({"input":history,"failure_stage":stage,"first":first,"replay":replay});
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    ensure!(
        bytes.len() <= 262_144,
        "epoch_advance_history_output_budget"
    );
    let id = Digest::of(&bundle)?;
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/epoch-advance-failures");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", &id.as_str()[7..]));
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => file.write_all(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                std::fs::read(&path)? == bytes,
                "epoch_advance_history_saved_bytes_changed"
            );
        }
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

fn retain(
    error: anyhow::Error,
    history: &History,
    stage: FailureStage,
    first: Option<&Report>,
    replay: Option<&Report>,
) -> anyhow::Error {
    match save_failure(history, stage, first, replay) {
        Ok(path) => error.context(SavedFailure(path)),
        Err(_) => error.context("epoch_advance_history_retention_refused"),
    }
}

fn check_with(history: &History, runner: fn(&History) -> Result<Report>) -> Result<()> {
    let encoded = serde_json::to_vec(history)?;
    let history = decode(&encoded)?;
    // Invalid source/bounds/fixture metadata refuse before executing a history.
    // Once admitted, any unexpected runner error retains this complete input.
    validate_input(&history)?;
    let first = runner(&history)
        .map_err(|error| retain(error, &history, FailureStage::FirstRun, None, None))?;
    let replay = runner(&decode(&encoded)?)
        .map_err(|error| retain(error, &history, FailureStage::ReplayRun, Some(&first), None))?;
    if first.actual != first.expected || replay != first {
        return Err(retain(
            anyhow::anyhow!("epoch_advance_history_divergence"),
            &history,
            FailureStage::ModelComparison,
            Some(&first),
            Some(&replay),
        ));
    }
    Ok(())
}

fn check(history: &History) -> Result<()> {
    check_with(history, run)
}

#[test]
fn complete_conditional_histories_replay_against_the_independent_model() -> Result<()> {
    for seed in 0u64..4 {
        for cut in [
            Cut::Known,
            Cut::BeforeWrite,
            Cut::AfterRoot,
            Cut::AfterSentinel,
            Cut::AfterCommit,
        ] {
            let (selection, before) = initial();
            check(&History {
                format: 1,
                source: source()?,
                selection,
                before: SavedSnapshot::save(&before),
                operation: Digest::of(&("advance", seed))?,
                cut,
            })?;
        }
    }
    Ok(())
}

#[test]
fn stale_or_oversized_replay_inputs_refuse_before_provider_execution() -> Result<()> {
    let (selection, before) = initial();
    let history = History {
        format: 1,
        source: Digest::new(b"foreign source"),
        selection,
        before: SavedSnapshot::save(&before),
        operation: Digest::new(b"advance"),
        cut: Cut::Known,
    };
    assert!(run(&history).is_err());
    assert!(decode(&vec![b' '; 65_537]).is_err());
    for component in ["root", "sentinel", "create", "activate"] {
        let mut changed = history.clone();
        changed.source = source()?;
        match component {
            "root" => changed.before.root.1 = version(9),
            "sentinel" => changed.before.sentinel.1 = version(9),
            "create" => changed.before.create.1 = version(9),
            "activate" => changed.before.activate.1 = version(9),
            _ => unreachable!(),
        }
        assert!(run(&changed).is_err(), "{component}");
        assert!(
            Provider::new(&changed.before.load()).is_err(),
            "{component}"
        );
    }
    Ok(())
}

#[test]
fn unexpected_prepare_error_retains_complete_input_and_original_error_without_display() -> Result<()>
{
    #[derive(Debug)]
    struct Refusal;
    impl std::fmt::Display for Refusal {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign error must not be formatted")
        }
    }
    impl std::error::Error for Refusal {}
    fn failed_prepare(_: &History) -> Result<Report> {
        Err(anyhow::Error::new(Refusal))
    }
    let (selection, before) = initial();
    let history = History {
        format: 1,
        source: source()?,
        selection,
        before: SavedSnapshot::save(&before),
        operation: Digest::new(b"prepare-error-retention-control"),
        cut: Cut::Known,
    };
    let error = check_with(&history, failed_prepare).unwrap_err();
    assert!(error.downcast_ref::<Refusal>().is_some());
    let path = &error
        .downcast_ref::<SavedFailure>()
        .context("valid input was not retained")?
        .0;
    let saved: Value = crate::json::decode(&std::fs::read(path)?)?;
    assert_eq!(saved["input"], serde_json::to_value(&history)?);
    assert_eq!(saved["failure_stage"], json!("first_run"));
    assert_eq!(saved["first"], Value::Null);
    assert_eq!(saved["replay"], Value::Null);
    Ok(())
}

#[test]
fn replay_saved_first_advance_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_REPLAY_EPOCH_ADVANCE") else {
        return Ok(());
    };
    let metadata = std::fs::metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 262_144,
        "epoch_advance_history_file_budget"
    );
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Bundle {
        input: History,
        #[serde(rename = "failure_stage")]
        _failure_stage: FailureStage,
        #[serde(rename = "first")]
        _first: Value,
        #[serde(rename = "replay")]
        _replay: Value,
    }
    let saved: Bundle = crate::json::decode(&std::fs::read(path)?)?;
    // Saved outcomes are diagnostics, never the oracle for the replay.
    check(&saved.input)
}
