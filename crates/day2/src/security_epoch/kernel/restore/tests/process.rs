//! Actual ordinary SQLite process loss, never a native maintenance producer.
use super::*;
use std::{
    io::{Read as _, Write as _},
    os::unix::process::ExitStatusExt as _,
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt as _;

const CHILD: &str = "security_epoch::kernel::restore::tests::process::restore_child";
const CONFIG: &str = "DAY2_SECURE_RESTORE_CHILD";
const WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Behavior {
    Pause,
    Complete,
    ExitAtCheckpoint,
    SkipCheckpoint,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format: u32,
    database: std::path::PathBuf,
    seed: u64,
    cut: Cut,
    behavior: Behavior,
}

fn marker(cut: Cut) -> [u8; 16] {
    let mut marker = [0u8; 16];
    marker[..8].copy_from_slice(b"D2REST01");
    marker[8] = match cut {
        Cut::BeforeWrite => 1,
        Cut::AfterRoot => 2,
        Cut::AfterSentinel => 3,
        Cut::AfterAdvanceReceipt => 4,
        Cut::AfterRestoreLedger => 5,
        Cut::AfterCommit => 6,
        Cut::Complete => 7,
    };
    marker
}

#[test]
fn restore_child() -> Result<()> {
    let Some(path) = std::env::var_os(CONFIG) else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "restore_child_config_bound");
        let config: Config = crate::json::decode(&bytes)?;
        ensure!(
            config.format == 1 && config.database.is_absolute(),
            "restore_child_config_identity"
        );
        let (selected, before) = initial();
        let intent = intent(&selected, config.seed);
        let current = current(&selected, &intent, &before);
        let plan = Request::new(&selected, intent, &current, 1000, &before)?
            .prepare(&selected, &current, 1000, &before, None)?;
        let mut provider = Provider::open(&config.database, &before)?;
        provider.apply(&selected, &current, 1000, &plan, |reached| {
            if reached == config.cut
                && !matches!(
                    config.behavior,
                    Behavior::Complete | Behavior::SkipCheckpoint
                )
            {
                std::io::stderr().write_all(&marker(reached))?;
                std::io::stderr().flush()?;
                if matches!(config.behavior, Behavior::ExitAtCheckpoint) {
                    std::process::exit(0);
                }
                let mut byte = [0];
                std::io::stdin().read_exact(&mut byte)?;
                anyhow::bail!("restore_child_was_released_without_death");
            }
            Ok(())
        })?;
        std::io::stderr().write_all(&marker(Cut::Complete))?;
        std::io::stderr().flush()?;
        Ok(())
    })();
    if result.is_err() {
        // No SQL/provider/parser error text is written into the protocol.
        std::io::stderr().write_all(&[0xFF; 16])?;
        std::io::stderr().flush()?;
        anyhow::bail!("restore_child_refused");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exit {
    checkpoint: [u8; 16],
    code: Option<i32>,
    signal: Option<i32>,
    eof: bool,
    kill_requested: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    phase: RoundStage,
    spawned: bool,
    checkpoint: Option<[u8; 16]>,
    kill_requested: bool,
    code: Option<i32>,
    signal: Option<i32>,
    reaped: bool,
    eof: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RoundStage {
    #[default]
    Setup,
    Launch,
    Checkpoint,
    Wait,
    EndOfPipe,
    Readback,
    Complete,
}

fn require_death(exit: &Exit, cut: Cut) -> Result<()> {
    ensure!(
        exit.checkpoint == marker(cut)
            && exit.signal == Some(9)
            && exit.code.is_none()
            && exit.eof
            && exit.kill_requested,
        "restore_child_checkpoint_or_signal_missing"
    );
    Ok(())
}

async fn execute(config: &Config, input: &Path, kill: bool, attempt: &mut Attempt) -> Result<Exit> {
    attempt.phase = RoundStage::Launch;
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .arg("--exact")
        .arg(CHILD)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env_clear()
        .env(CONFIG, input)
        .env("TMPDIR", std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let mut child = command.spawn()?;
    attempt.spawned = true;
    let mut pipe = child.stderr.take().context("restore_child_pipe_missing")?;
    let result = (async {
        attempt.phase = RoundStage::Checkpoint;
        let mut checkpoint = [0; 16];
        tokio::time::timeout(WAIT, pipe.read_exact(&mut checkpoint)).await??;
        attempt.checkpoint = Some(checkpoint);
        ensure!(
            checkpoint
                == marker(
                    if matches!(
                        config.behavior,
                        Behavior::Complete | Behavior::SkipCheckpoint
                    ) {
                        Cut::Complete
                    } else {
                        config.cut
                    }
                ),
            "restore_child_unexpected_checkpoint"
        );
        if kill {
            child.start_kill()?;
            attempt.kill_requested = true;
        }
        attempt.phase = RoundStage::Wait;
        let status = tokio::time::timeout(WAIT, child.wait()).await??;
        attempt.reaped = true;
        attempt.code = status.code();
        attempt.signal = status.signal();
        let mut extra = [0];
        attempt.phase = RoundStage::EndOfPipe;
        let eof = tokio::time::timeout(WAIT, pipe.read(&mut extra)).await?? == 0;
        attempt.eof = Some(eof);
        Ok::<_, anyhow::Error>(Exit {
            checkpoint,
            code: status.code(),
            signal: status.signal(),
            eof,
            kill_requested: kill,
        })
    })
    .await;
    if result.is_err() {
        if child.start_kill().is_ok() {
            attempt.kill_requested = true;
        }
        if let Ok(Ok(status)) = tokio::time::timeout(WAIT, child.wait()).await {
            attempt.reaped = true;
            attempt.code = status.code();
            attempt.signal = status.signal();
        }
    }
    result
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrashObservation {
    seed: u64,
    cut: Cut,
    exit: Exit,
    rows: Vec<Row>,
    expected: Vec<Row>,
    sends: u64,
}

async fn round(seed: u64, cut: Cut, attempt: &mut Attempt) -> Result<CrashObservation> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("epoch.sqlite");
    let (selected, before) = initial();
    let intent = intent(&selected, seed);
    let current = current(&selected, &intent, &before);
    drop(Provider::open(&path, &before)?);
    let config = Config {
        format: 1,
        database: path.clone(),
        seed,
        cut,
        behavior: Behavior::Pause,
    };
    let input = directory.path().join("input.json");
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&input)?;
        file.write_all(&serde_json::to_vec(&config)?)?;
        file.sync_all()?;
    }
    let exit = execute(&config, &input, true, attempt).await?;
    require_death(&exit, cut)?;
    attempt.phase = RoundStage::Readback;
    let provider = Provider::open(&path, &before)?;
    let rows = provider.rows()?;
    let expected = if cut.committed() {
        super::expected(&selected, &intent, &current, &before, 1000)?
    } else {
        initial_rows(&before)?
    };
    let sends = provider.sends()?;
    attempt.phase = RoundStage::Complete;
    Ok(CrashObservation {
        seed,
        cut,
        exit,
        rows,
        expected,
        sends,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutRun {
    attempt: Attempt,
    observation: Option<CrashObservation>,
    failed: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    format: u32,
    source: Digest,
    seed: u64,
    cut: Cut,
    first: CutRun,
    second: Option<CutRun>,
}

fn source() -> Result<Digest> {
    Digest::of(&(
        "day2-restore-process-loss-v1",
        std::env::consts::OS,
        std::env::consts::ARCH,
        include_str!("process.rs"),
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

async fn observed_round(seed: u64, cut: Cut) -> CutRun {
    let mut attempt = Attempt::default();
    match round(seed, cut, &mut attempt).await {
        Ok(observation) => CutRun {
            attempt,
            observation: Some(observation),
            failed: false,
        },
        Err(_) => CutRun {
            attempt,
            observation: None,
            failed: true,
        },
    }
}

fn agrees(run: &CutRun) -> bool {
    !run.failed
        && run.attempt.reaped
        && run.observation.as_ref().is_some_and(|r| {
            r.rows == r.expected && r.sends == 1 && require_death(&r.exit, r.cut).is_ok()
        })
}

fn retain(failure: &Failure) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/control-slot-replays");
    std::fs::create_dir_all(&parent)?;
    let directory = tempfile::Builder::new()
        .prefix("restore-crash-")
        .tempdir_in(parent)?
        .keep();
    let mut encoded = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let bytes = serde_json::to_vec(failure)?;
    ensure!(bytes.len() <= 1024 * 1024, "restore_crash_evidence_bound");
    encoded.write_all(&bytes)?;
    let path = directory.join("replay.json.gz");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&encoded.finish()?)?;
    file.sync_all()?;
    Ok(path)
}

fn decode(bytes: &[u8]) -> Result<Failure> {
    ensure!(bytes.len() <= 1024 * 1024, "restore_crash_encoded_bound");
    let mut gzip = flate2::bufread::GzDecoder::new(bytes);
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut gzip)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= 1024 * 1024 && gzip.into_inner().is_empty(),
        "restore_crash_decoded_or_trailing_bound"
    );
    let failure: Failure = crate::json::decode_evidence(&raw)?;
    ensure!(
        failure.format == 1 && failure.source == source()? && failure.cut != Cut::Complete,
        "restore_crash_source_or_case_changed"
    );
    ensure!(
        !agrees(&failure.first)
            || failure
                .second
                .as_ref()
                .is_none_or(|r| !agrees(r) || r != &failure.first),
        "restore_crash_not_a_counterexample"
    );
    Ok(failure)
}

#[tokio::test]
async fn replay_saved_secure_restore_process_loss() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_SECURE_RESTORE_CRASH_REPLAY") else {
        return Ok(());
    };
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "restore_crash_replay_not_regular"
    );
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let failure = decode(&bytes)?;
    // An unresolved saved child is not permission to launch another process.
    for run in std::iter::once(&failure.first).chain(failure.second.iter()) {
        ensure!(
            !run.attempt.spawned || run.attempt.reaped,
            "restore_crash_saved_cleanup_unresolved"
        );
    }
    let first = observed_round(failure.seed, failure.cut).await;
    ensure!(
        first == failure.first,
        "restore_crash_first_prefix_not_reproduced"
    );
    if let Some(second) = &failure.second {
        ensure!(
            observed_round(failure.seed, failure.cut).await == *second,
            "restore_crash_second_prefix_not_reproduced"
        );
    }
    Ok(())
}

#[test]
fn incomplete_child_failure_records_preserve_closed_stage_and_unresolved_cleanup() -> Result<()> {
    let first = CutRun {
        attempt: Attempt {
            spawned: true,
            phase: RoundStage::Checkpoint,
            checkpoint: Some([0xFF; 16]),
            ..Attempt::default()
        },
        observation: None,
        failed: true,
    };
    let failure = Failure {
        format: 1,
        source: source()?,
        seed: 7,
        cut: Cut::AfterRoot,
        first: first.clone(),
        second: None,
    };
    let path = retain(&failure)?;
    let bytes = std::fs::read(&path)?;
    let saved = decode(&bytes)?;
    assert_eq!(saved.first, first);
    assert!(saved.second.is_none());
    assert!(!saved.first.attempt.reaped);
    let mut trailing = bytes;
    trailing.extend_from_slice(b"foreign");
    assert!(decode(&trailing).is_err());
    Ok(())
}

#[tokio::test]
async fn actual_process_loss_before_each_write_and_after_commit_reopens_without_partial_restore()
-> Result<()> {
    for seed in 0..2 {
        for cut in Cut::ALL.into_iter().filter(|cut| *cut != Cut::Complete) {
            let first = observed_round(seed, cut).await;
            let second = if !first.attempt.spawned || first.attempt.reaped {
                Some(observed_round(seed, cut).await)
            } else {
                None
            };
            // These rows contain only synthetic metadata, never custody bytes.
            if !agrees(&first) || second.as_ref().is_none_or(|r| !agrees(r) || r != &first) {
                retain(&Failure {
                    format: 1,
                    source: source()?,
                    seed,
                    cut,
                    first,
                    second,
                })?;
                anyhow::bail!("restore_process_loss_failure_saved");
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn normal_completion_and_clean_checkpoint_exit_cannot_impersonate_process_loss() -> Result<()>
{
    for behavior in [
        Behavior::Complete,
        Behavior::SkipCheckpoint,
        Behavior::ExitAtCheckpoint,
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("epoch.sqlite");
        let (_, before) = initial();
        drop(Provider::open(&path, &before)?);
        let config = Config {
            format: 1,
            database: path,
            seed: 17,
            cut: Cut::AfterRoot,
            behavior,
        };
        let input = directory.path().join("input.json");
        std::fs::write(&input, serde_json::to_vec(&config)?)?;
        let exit = execute(&config, &input, false, &mut Attempt::default()).await?;
        assert_eq!(exit.code, Some(0));
        assert!(exit.eof);
        assert!(require_death(&exit, config.cut).is_err());
        let mut substituted = exit;
        substituted.checkpoint = marker(Cut::AfterRoot);
        substituted.kill_requested = true;
        assert!(require_death(&substituted, config.cut).is_err());
    }
    Ok(())
}
