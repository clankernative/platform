//! Actual ordinary SQLite child death/reopen. No native holder/P3 or power-loss
//! durability is supplied by this portable process experiment.
use super::*;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    io::{Read as _, Write as _},
    os::unix::process::ExitStatusExt as _,
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt as _;

const CHILD: &str = "security_epoch::kernel::restore::writer::tests::process::writer_child";
const CONFIG: &str = "DAY2_RESTORE_WRITER_CHILD";
const WAIT: Duration = Duration::from_secs(20);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database: std::path::PathBuf,
    source: Digest,
    seed: u64,
    cut: Cut,
    early_exit: bool,
}

fn marker(cut: Cut) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(b"D2WRIT01");
    value[8] = match cut {
        Cut::BeforeCompare => 1,
        Cut::AfterCompare => 2,
        Cut::AfterRoot => 3,
        Cut::BeforeCommit => 4,
        Cut::AfterCommit => 5,
        Cut::Complete => 6,
    };
    value
}

#[test]
fn writer_child() -> Result<()> {
    let Some(path) = std::env::var_os(CONFIG) else {
        return Ok(());
    };
    let result = (|| -> Result<()> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "writer_child_config_bound");
        let config: Config = crate::json::decode(&bytes)?;
        ensure!(
            config.database.is_absolute() && config.source == source()?,
            "writer_child_database_path_or_source"
        );
        if config.early_exit {
            return Ok(());
        }
        let f = fixture(config.seed, true)?;
        let p = f
            .request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
        let mut provider = Provider::open(&config.database, &f.before)?;
        provider.send(&f, &p, 1002, |cut| {
            if cut == config.cut {
                std::io::stderr().write_all(&marker(cut))?;
                std::io::stderr().flush()?;
                let mut byte = [0];
                std::io::stdin().read_exact(&mut byte)?;
                anyhow::bail!("writer_child_released_without_death");
            }
            Ok(())
        })
    })();
    if result.is_err() {
        std::io::stderr().write_all(&[0xFF; 16])?;
        std::io::stderr().flush()?;
        anyhow::bail!("writer_child_refused");
    }
    Ok(())
}

const MAX_TRACE_BYTES: usize = 1_048_576;
const CUTS: [Cut; 5] = [
    Cut::BeforeCompare,
    Cut::AfterCompare,
    Cut::AfterRoot,
    Cut::BeforeCommit,
    Cut::AfterCommit,
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Death {
    checkpoint: Option<[u8; 16]>,
    partial_marker: Vec<u8>,
    kill_requested: bool,
    reaped: bool,
    signal: Option<i32>,
    code: Option<i32>,
    eof: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Point {
    Setup,
    CreateProvider,
    Input,
    Execute,
    Readback,
    CheckDeath,
    CheckState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutTrace {
    cut: Cut,
    point: Point,
    directory: Option<std::path::PathBuf>,
    death: Death,
    expected: Option<Rows>,
    actual: Option<Rows>,
    checked: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    format: u32,
    source: Digest,
    seed: u64,
    cuts: Vec<Cut>,
    early_exit: bool,
    setup_failure: bool,
    point: Point,
    prefix: Vec<CutTrace>,
}

fn source() -> Result<Digest> {
    Digest::of(&(include_str!("process.rs"), history::source()?))
}

fn require_death(death: &Death, cut: Cut) -> Result<()> {
    ensure!(
        death.checkpoint == Some(marker(cut))
            && death.kill_requested
            && death.reaped
            && death.signal == Some(9)
            && death.code.is_none()
            && death.eof,
        "writer_child_death_not_proven"
    );
    Ok(())
}

async fn execute(input: &std::path::Path, death: &mut Death) -> Result<()> {
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
    let mut pipe = child.stderr.take().context("writer_child_pipe_missing")?;
    let mut bytes = [0u8; 16];
    let mut count = 0;
    let observed = tokio::time::timeout(WAIT, async {
        while count < bytes.len() {
            let n = pipe.read(&mut bytes[count..]).await?;
            if n == 0 {
                break;
            }
            count += n;
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    death.partial_marker = bytes[..count].to_vec();
    if matches!(observed, Ok(Ok(()))) && count == bytes.len() {
        death.checkpoint = Some(bytes);
    }
    // Reaping and EOF observations are recorded before checkpoint validation.
    // A timeout remains unknown; kill_on_drop still owns terminal child cleanup.
    death.kill_requested = child.start_kill().is_ok();
    let waited = tokio::time::timeout(WAIT, child.wait()).await;
    let eof = if let Ok(Ok(status)) = &waited {
        death.reaped = true;
        death.signal = status.signal();
        death.code = status.code();
        let mut tail = [0u8; 1];
        Some(tokio::time::timeout(WAIT, pipe.read(&mut tail)).await)
    } else {
        None
    };
    if let Some(Ok(Ok(count))) = &eof {
        death.eof = *count == 0;
    }
    // Cleanup observations above are mandatory even on a primary marker-read
    // failure. Keep that first typed cause when wait/EOF also fail.
    observed??;
    waited??;
    if let Some(eof) = eof {
        eof??;
    }
    Ok(())
}

fn retain(trace: &Trace) -> Result<std::path::PathBuf> {
    let bytes = serde_json::to_vec(trace)?;
    ensure!(bytes.len() <= MAX_TRACE_BYTES, "writer_death_trace_bound");
    let directory = tempfile::Builder::new()
        .prefix("day2-writer-death-failure-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?
        .keep();
    let path = directory.join("replay.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(path)
}

async fn campaign(cuts: &[Cut], early_exit: bool, setup_failure: bool) -> Result<Vec<CutTrace>> {
    ensure!(
        !cuts.is_empty() && cuts.len() <= CUTS.len(),
        "writer_death_cut_bound"
    );
    let mut trace = Trace {
        format: 1,
        source: source()?,
        seed: 20,
        cuts: cuts.to_vec(),
        early_exit,
        setup_failure,
        point: Point::Setup,
        prefix: Vec::new(),
    };
    let mut directories = Vec::new();
    let result = async {
        let f = fixture(trace.seed, true)?;
        let plan = f
            .request
            .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
        for cut in cuts {
            trace.prefix.push(CutTrace {
                cut: *cut,
                point: Point::CreateProvider,
                directory: None,
                death: Death::default(),
                expected: None,
                actual: None,
                checked: false,
            });
            let row = trace.prefix.last_mut().unwrap();
            let mut expected = rows(&f.before)?;
            if *cut == Cut::AfterCommit {
                expected.insert(
                    "root".into(),
                    Row {
                        value: serde_json::to_value(&plan.root)?,
                        token: 5,
                    },
                );
                expected.insert(
                    "sentinel".into(),
                    Row {
                        value: serde_json::to_value(&plan.sentinel)?,
                        token: 5,
                    },
                );
                expected.insert(
                    "writer".into(),
                    Row {
                        value: serde_json::to_value(&plan.receipt)?,
                        token: 5,
                    },
                );
            }
            row.expected = Some(expected);
            let dir = tempfile::Builder::new()
                .prefix("day2-writer-death-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?;
            row.directory = Some(dir.path().to_owned());
            let database = if setup_failure {
                dir.path().to_owned()
            } else {
                dir.path().join("provider.sqlite")
            };
            directories.push(dir);
            drop(Provider::open(&database, &f.before)?);
            // The private directory already excludes other users; make every
            // retained fixture file private too, without changing global umask.
            std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600))?;
            row.point = Point::Input;
            let input = row.directory.as_ref().unwrap().join("input.json");
            let config = Config {
                database,
                source: trace.source.clone(),
                seed: trace.seed,
                cut: *cut,
                early_exit,
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&input)?;
            file.write_all(&serde_json::to_vec(&config)?)?;
            file.sync_all()?;
            row.point = Point::Execute;
            let execution = execute(&input, &mut row.death).await;
            // Capture actual readback on a reaped child even if its marker was
            // absent/false. This never treats zero exit as a controlled death.
            let readback = if row.death.reaped {
                if execution.is_ok() {
                    row.point = Point::Readback;
                }
                Provider::open(&config.database, &f.before)
                    .and_then(|provider| Provider::read(&provider.db))
                    .map(|actual| row.actual = Some(actual))
            } else {
                Ok(())
            };
            execution?;
            readback?;
            row.point = Point::CheckDeath;
            require_death(&row.death, *cut)?;
            row.point = Point::CheckState;
            let actual = row
                .actual
                .as_ref()
                .context("writer_death_readback_missing")?;
            let committed = *cut == Cut::AfterCommit;
            ensure!(
                Some(actual) == row.expected.as_ref(),
                "writer_death_commit_cut_changed"
            );
            if committed {
                let mut reopened = Provider::open(&config.database, &f.before)?;
                ensure!(
                    reopened.send(&f, &plan, 1002, |_| Ok(())).is_err(),
                    "writer_death_reapplication_accepted"
                );
                ensure!(
                    &Provider::read(&reopened.db)? == actual,
                    "writer_death_reapplication_changed_state"
                );
            } else {
                ensure!(*actual == rows(&f.before)?, "writer_death_partial_commit");
            }
            row.checked = true;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        // Keep all original owned fixture directories on failure. Their names,
        // exact source/cut and full observed prefix are joined by replay.json.
        for directory in directories {
            let _ = directory.keep();
        }
        return Err(match retain(&trace) {
            Ok(path) => error.context(format!("writer_death_failure retained {}", path.display())),
            Err(_) => error.context("writer_death_failure bundle_not_written"),
        });
    }
    Ok(trace.prefix)
}

#[tokio::test(flavor = "current_thread")]
async fn real_process_loss_cuts_preserve_atomic_writer_state_and_never_regrant() -> Result<()> {
    let actual = campaign(&CUTS, false, false).await?;
    assert_eq!(actual.len(), CUTS.len());
    assert!(actual.iter().all(|row| row.checked));
    Ok(())
}

fn retained(error: &anyhow::Error) -> Result<(std::path::PathBuf, Trace)> {
    let outer = error.chain().next().unwrap().to_string();
    let path = std::path::PathBuf::from(
        outer
            .strip_prefix("writer_death_failure retained ")
            .context("writer_death_bundle_path")?,
    );
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let raw = std::fs::read(&path)?;
    assert!(raw.len() <= MAX_TRACE_BYTES);
    let trace: Trace = crate::json::decode(&raw)?;
    assert_eq!(trace.source, source()?);
    Ok((path, trace))
}

#[tokio::test(flavor = "current_thread")]
async fn early_zero_exit_is_not_a_checkpoint_and_retains_actual_failure_prefix() -> Result<()> {
    let error = match campaign(&[Cut::BeforeCommit], true, false).await {
        Ok(_) => anyhow::bail!("writer_false_death_passed"),
        Err(error) => error,
    };
    let (_, trace) = retained(&error)?;
    let row = &trace.prefix[0];
    assert_eq!(row.point, Point::CheckDeath);
    assert!(row.death.reaped && row.death.eof);
    assert!(row.death.checkpoint.is_none());
    assert_eq!(row.death.code, Some(0));
    assert!(row.actual.as_ref().is_some_and(|rows| rows.len() == 8));
    assert!(!row.checked);
    assert!(row.directory.as_ref().unwrap().exists());
    let false_success = Death {
        checkpoint: Some(marker(row.cut)),
        reaped: true,
        code: Some(0),
        eof: true,
        ..Death::default()
    };
    assert!(require_death(&false_success, row.cut).is_err());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn provider_setup_failure_keeps_source_cut_and_primary_error_before_child() -> Result<()> {
    let error = match campaign(&[Cut::AfterRoot], false, true).await {
        Ok(_) => anyhow::bail!("writer_false_setup_passed"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<rusqlite::Error>().is_some());
    let (_, trace) = retained(&error)?;
    assert_eq!(trace.prefix.len(), 1);
    assert_eq!(trace.prefix[0].point, Point::CreateProvider);
    assert!(trace.prefix[0].actual.is_none() && !trace.prefix[0].death.reaped);
    assert!(trace.prefix[0].directory.as_ref().unwrap().exists());
    Ok(())
}
