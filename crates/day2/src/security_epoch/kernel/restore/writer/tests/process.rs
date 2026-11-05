//! Actual ordinary SQLite child death/reopen. No native holder/P3 or power-loss
//! durability is supplied by this portable process experiment.
use super::*;
use std::os::unix::fs::OpenOptionsExt as _;
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
        ensure!(config.database.is_absolute(), "writer_child_database_path");
        if config.early_exit {
            return Ok(());
        }
        let f = fixture(20, true)?;
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

#[derive(Clone, Debug, Serialize)]
struct Death {
    checkpoint: Option<[u8; 16]>,
    kill_requested: bool,
    signal: Option<i32>,
    code: Option<i32>,
    eof: bool,
}

fn require_death(death: &Death, cut: Cut) -> Result<()> {
    ensure!(
        death.checkpoint == Some(marker(cut))
            && death.kill_requested
            && death.signal == Some(9)
            && death.code.is_none()
            && death.eof,
        "writer_child_death_not_proven"
    );
    Ok(())
}

async fn execute(config: &Config, input: &std::path::Path) -> Result<Death> {
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
    let checkpoint = match tokio::time::timeout(WAIT, pipe.read_exact(&mut bytes)).await {
        Ok(Ok(_)) => Some(bytes),
        _ => None,
    };
    // Reap even an invalid or missing checkpoint. Its zero exit must not become
    // proof of the controlled boundary; no free-running child is left behind.
    let kill_requested = child.start_kill().is_ok();
    let status = tokio::time::timeout(WAIT, child.wait()).await??;
    let mut tail = [0u8; 1];
    let eof = tokio::time::timeout(WAIT, pipe.read(&mut tail)).await?? == 0;
    let death = Death {
        checkpoint,
        kill_requested,
        signal: status.signal(),
        code: status.code(),
        eof,
    };
    if !config.early_exit {
        require_death(&death, config.cut)?;
    }
    Ok(death)
}

#[tokio::test(flavor = "current_thread")]
async fn real_process_loss_cuts_preserve_atomic_writer_state_and_never_regrant() -> Result<()> {
    let f = fixture(20, true)?;
    let plan = f
        .request
        .prepare(&f.selected, &f.authority, 1002, &f.before, None)?;
    let mut trace = Vec::new();
    for cut in [
        Cut::BeforeCompare,
        Cut::AfterCompare,
        Cut::AfterRoot,
        Cut::BeforeCommit,
        Cut::AfterCommit,
    ] {
        let dir = tempfile::Builder::new()
            .prefix("day2-writer-death-")
            .tempdir()?;
        let database = dir.path().join("provider.sqlite");
        drop(Provider::open(&database, &f.before)?);
        let input = dir.path().join("input.json");
        let config = Config {
            database,
            cut,
            early_exit: false,
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input)?;
        file.write_all(&serde_json::to_vec(&config)?)?;
        file.sync_all()?;
        let death = execute(&config, &input).await?;
        require_death(&death, cut)?;
        let mut reopened = Provider::open(&config.database, &f.before)?;
        let actual = Provider::read(&reopened.db)?;
        let committed = cut == Cut::AfterCommit;
        assert_eq!(actual.contains_key("writer"), committed);
        if committed {
            assert!(reopened.send(&f, &plan, 1002, |_| Ok(())).is_err());
            assert_eq!(Provider::read(&reopened.db)?, actual);
        } else {
            assert_eq!(actual, rows(&f.before)?);
        }
        trace.push((cut, death, actual));
    }
    assert_eq!(trace.len(), 5);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn early_zero_exit_is_not_a_checkpoint_or_writer_death_receipt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = Config {
        database: dir.path().join("unused.sqlite"),
        cut: Cut::BeforeCommit,
        early_exit: true,
    };
    let input = dir.path().join("input.json");
    std::fs::write(&input, serde_json::to_vec(&config)?)?;
    let actual = execute(&config, &input).await?;
    assert!(require_death(&actual, config.cut).is_err());
    let false_success = Death {
        checkpoint: Some(marker(config.cut)),
        kill_requested: false,
        signal: None,
        code: Some(0),
        eof: true,
    };
    assert!(require_death(&false_success, config.cut).is_err());
    Ok(())
}
