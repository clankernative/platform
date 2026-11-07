//! Actual SIGKILL/reopen cuts at both durable commits, never power-loss or
//! native issuer qualification. No provider credential or environment is logged.
use super::*;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _},
};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read as _, Write as _},
    os::unix::process::ExitStatusExt as _,
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt as _;

const CHILD: &str = "security_epoch::restore_webauthn::store::tests::process::challenge_child";
const CONFIG: &str = "DAY2_RESTORE_WEBAUTHN_CHILD";
const WAIT: Duration = Duration::from_secs(20);

fn stable_fixture() -> Fixture {
    // Published synthetic P-256 test key, RFC6979 A.2.5, never enrolled in a
    // production registry: https://www.rfc-editor.org/rfc/rfc6979.txt .
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let private = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let public = hex(concat!(
        "04",
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
    ));
    let mut f = fixture();
    f.signer = EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &private,
        &public,
        &SystemRandom::new(),
    )
    .unwrap();
    f.key.record.public_key = f.signer.public_key().as_ref().to_vec();
    f.challenge.enrollment = f.key.binding().unwrap();
    f
}

fn cut(n: u8) -> Result<Cut> {
    Ok(match n {
        1 => Cut::AfterClaim,
        2 => Cut::AfterSignature,
        3 => Cut::AfterCounter,
        4 => Cut::BeforeCommit,
        5 => Cut::AfterCommit,
        _ => anyhow::bail!("challenge_child_cut"),
    })
}

fn marker(n: u8) -> [u8; 16] {
    let mut b = [0; 16];
    b[..8].copy_from_slice(b"D2CHAL01");
    b[8] = n;
    b
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    database: std::path::PathBuf,
    cut: u8,
    exit_at_cut: bool,
}

#[test]
fn challenge_child() -> Result<()> {
    let Some(config) = std::env::var_os(CONFIG) else {
        return Ok(());
    };
    let mut bytes = Vec::new();
    std::fs::File::open(config)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "challenge_child_config_bound");
    let config: Config = crate::json::decode(&bytes)?;
    ensure!(config.database.is_absolute(), "challenge_child_path");
    if (6..=10).contains(&config.cut) {
        return journal_child(&config);
    }
    if (11..=13).contains(&config.cut) {
        return execution_attempt_child(&config);
    }
    let selected = cut(config.cut)?;
    let f = stable_fixture();
    let mut db = Connection::open(config.database)?;
    let id = prepare(&mut db, &f);
    let _reset = inject(move |reached| {
        if reached == selected {
            std::io::stderr().write_all(&marker(config.cut))?;
            std::io::stderr().flush()?;
            if config.exit_at_cut {
                std::process::exit(0)
            }
            let mut release = [0];
            std::io::stdin().read_exact(&mut release)?;
            anyhow::bail!("challenge_child_released_without_death");
        }
        Ok(())
    });
    complete(
        &mut db,
        &f.key,
        &id,
        &f.challenge.request,
        1001,
        &f.assertion(7, 0x0d),
    )?;
    anyhow::bail!("challenge_child_missing_checkpoint")
}

fn journal_child(config: &Config) -> Result<()> {
    let mut f = stable_fixture();
    let record = super::super::signing::tests::statement(&mut f)?;
    let mut db = Connection::open(&config.database)?;
    let id = prepare(&mut db, &f);
    complete(
        &mut db,
        &f.key,
        &id,
        &f.challenge.request,
        1001,
        &f.assertion(7, 0x0d),
    )?;
    let pause = || -> Result<()> {
        std::io::stderr().write_all(&marker(config.cut))?;
        std::io::stderr().flush()?;
        if config.exit_at_cut {
            std::process::exit(0);
        }
        let mut release = [0];
        std::io::stdin().read_exact(&mut release)?;
        anyhow::bail!("journal_child_released_without_death")
    };
    let tx = db.transaction()?;
    prepare_signing(&tx, &f.key, &id, &record.statement, 7)?;
    if config.cut == 6 {
        pause()?;
    }
    tx.commit()?;
    if config.cut == 7 {
        pause()?;
    }
    let tx = db.transaction()?;
    mark_may_sign(&tx, &f.key, &id, &record.statement)?;
    if config.cut == 8 {
        pause()?;
    }
    tx.commit()?;
    if config.cut == 9 {
        pause()?;
    }
    let tx = db.transaction()?;
    record_publication(&tx, &f.key, &id, &record)?;
    tx.commit()?;
    if config.cut == 10 {
        pause()?;
    }
    anyhow::bail!("journal_child_missing_checkpoint")
}

fn execution_attempt_child(config: &Config) -> Result<()> {
    let mut f = stable_fixture();
    let mut db = Connection::open(&config.database)?;
    let (signed, operation, completion) = super::attempts::execution_fixture(&mut db, &mut f)?;
    let pause = || -> Result<()> {
        std::io::stderr().write_all(&marker(config.cut))?;
        std::io::stderr().flush()?;
        if config.exit_at_cut { std::process::exit(0); }
        let mut release = [0];
        std::io::stdin().read_exact(&mut release)?;
        anyhow::bail!("execution_attempt_released_without_death")
    };
    if config.cut == 11 { pause()?; }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    mark_may_execute(&tx, &f.key, &f.challenge, &signed, &operation, (7, completion.0, &completion.1))?;
    if config.cut == 12 { pause()?; }
    tx.commit()?;
    if config.cut == 13 { pause()?; }
    anyhow::bail!("execution_attempt_missing_checkpoint")
}

struct Exit {
    checkpoint: [u8; 16],
    signal: Option<i32>,
    code: Option<i32>,
    eof: bool,
    kill_requested: bool,
}

fn require_death(exit: &Exit, n: u8) -> Result<()> {
    ensure!(
        exit.checkpoint == marker(n)
            && exit.signal == Some(9)
            && exit.code.is_none()
            && exit.eof
            && exit.kill_requested,
        "challenge_child_death_not_proven"
    );
    Ok(())
}

async fn execute(config: &Config, input: &std::path::Path, kill: bool) -> Result<Exit> {
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
    let mut child = command.spawn()?;
    // Keep the actual parent pipe open until the requested kill is reaped;
    // child.wait must not turn an unrequested EOF into a checkpoint exit.
    let _held_stdin = child.stdin.take().context("challenge_child_stdin")?;
    let mut pipe = child.stderr.take().context("challenge_child_pipe")?;
    let result = (async {
        let mut checkpoint = [0; 16];
        tokio::time::timeout(WAIT, pipe.read_exact(&mut checkpoint)).await??;
        ensure!(
            checkpoint == marker(config.cut),
            "challenge_child_checkpoint"
        );
        if kill {
            child.start_kill()?;
        }
        let status = tokio::time::timeout(WAIT, child.wait()).await??;
        let mut extra = [0];
        let eof = tokio::time::timeout(WAIT, pipe.read(&mut extra)).await?? == 0;
        Ok(Exit {
            checkpoint,
            signal: status.signal(),
            code: status.code(),
            eof,
            kill_requested: kill,
        })
    })
    .await;
    if result.is_err() {
        // Preserve the checkpoint/IO primary result while closing the actual
        // owned child even on setup, timeout or protocol failure.
        let _ = child.start_kill();
        let _ = tokio::time::timeout(WAIT, child.wait()).await;
    }
    result
}

#[tokio::test(flavor = "current_thread")]
async fn signing_journal_real_child_death_preserves_attempt_state_without_reconstructing_owner()
-> Result<()> {
    for n in 6..=10 {
        let root = tempfile::tempdir()?;
        let config = Config {
            database: root.path().join("outside-restore.sqlite"),
            cut: n,
            exit_at_cut: false,
        };
        let input = root.path().join("journal-cut.json");
        std::fs::write(&input, serde_json::to_vec(&config)?)?;
        let exit = execute(&config, &input, true).await?;
        require_death(&exit, n)?;
        let mut db = Connection::open(&config.database)?;
        assert_eq!(observed(&db), ("verified".into(), 2, 7));
        let row: Option<(String, bool)> = db
            .query_row(
                "SELECT state,signed_record IS NOT NULL FROM main.restore_approval_issuance",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        // Independent table from actual transaction boundaries. A committed
        // MaySign/published row remains DATA, never a resumed native signer.
        let expected = match n {
            6 => None,
            7 | 8 => Some(("prepared".into(), false)),
            9 => Some(("may_sign".into(), false)),
            10 => Some(("published".into(), true)),
            _ => unreachable!(),
        };
        assert_eq!(row, expected, "cut {n}");
        let mut f = stable_fixture();
        let _record = super::super::signing::tests::statement(&mut f)?;
        let id = challenge_id(&f.challenge)?;
        assert!(
            complete(
                &mut db,
                &f.key,
                &id,
                &f.challenge.request,
                1002,
                &f.assertion(8, 0x0d)
            )
            .is_err()
        );
        assert_eq!(observed(&db), ("verified".into(), 2, 7));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn execution_grant_attempt_real_child_death_prevents_fresh_login_reuse_after_commit() -> Result<()> {
    for cut in 11..=13 {
        let root = tempfile::tempdir()?;
        let config = Config { database: root.path().join("outside-restore.sqlite"), cut, exit_at_cut: false };
        let input = root.path().join("execution-cut.json");
        std::fs::write(&input, serde_json::to_vec(&config)?)?;
        require_death(&execute(&config, &input, true).await?, cut)?;
        let mut db = Connection::open(&config.database)?;
        let stored: i64 = db.query_row("SELECT count(*) FROM main.restore_approval_execution_attempts", [], |row| row.get(0))?;
        // Independent commit-cut table, not the child's result/reconciliation.
        // Before known claim commit the native sender cannot have started. A
        // durable claim remains spent even if no provider reply was recorded.
        let spent = cut == 13;
        assert_eq!(stored, i64::from(spent), "cut {cut}");
        let mut f = stable_fixture();
        let signed = super::super::signing::tests::statement(&mut f)?;
        let operation = Digest::new(b"new login and operation after child death");
        let completion = super::attempts::fresh_execution(&mut db, &mut f, &signed, &operation)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let marked = mark_may_execute(&tx, &f.key, &f.challenge, &signed, &operation, (8, completion.0, &completion.1));
        assert_eq!(marked.is_ok(), !spent, "cut {cut}");
        tx.commit()?;
        // The primitive returns only (); no row can recover the lost native
        // completion, original, stopped cohort or delivery/commit permission.
        assert_eq!(db.query_row("SELECT count(*) FROM main.restore_approval_execution_attempts", [], |row| row.get::<_,i64>(0))?, 1);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn execution_attempt_child_success_is_not_accepted_as_requested_death() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = Config { database: root.path().join("outside-restore.sqlite"), cut: 13, exit_at_cut: true };
    let input = root.path().join("not-a-death.json");
    std::fs::write(&input, serde_json::to_vec(&config)?)?;
    let exit = execute(&config, &input, false).await?;
    assert!(require_death(&exit, 13).is_err());
    let db = Connection::open(&config.database)?;
    assert_eq!(db.query_row("SELECT count(*) FROM main.restore_approval_execution_attempts", [], |row| row.get::<_,i64>(0))?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_child_death_preserves_single_use_and_atomic_final_counter() -> Result<()> {
    for n in 1..=5 {
        let root = tempfile::tempdir()?;
        let database = root.path().join("outside-restore.sqlite");
        let config = Config {
            database: database.clone(),
            cut: n,
            exit_at_cut: false,
        };
        let input = root.path().join("cut.json");
        std::fs::write(&input, serde_json::to_vec(&config)?)?;
        let exit = execute(&config, &input, true).await?;
        require_death(&exit, n)?;
        // Independent expected state is determined by the selected commit cut,
        // not by the child error or a production reconciliation helper.
        let expected = if n == 5 {
            ("verified".into(), 2, 7)
        } else {
            ("claimed".into(), 1, 0)
        };
        let mut db = Connection::open(&database)?;
        assert_eq!(observed(&db), expected);
        let f = stable_fixture();
        let id = challenge_id(&f.challenge)?;
        assert!(
            complete(
                &mut db,
                &f.key,
                &id,
                &f.challenge.request,
                1002,
                &f.assertion(8, 0x0d)
            )
            .is_err()
        );
        assert_eq!(observed(&db), expected);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn normal_exit_after_checkpoint_is_not_accepted_as_child_death() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = Config {
        database: root.path().join("outside-restore.sqlite"),
        cut: 1,
        exit_at_cut: true,
    };
    let input = root.path().join("cut.json");
    std::fs::write(&input, serde_json::to_vec(&config)?)?;
    let exit = execute(&config, &input, false).await?;
    assert_eq!(exit.code, Some(0));
    assert!(require_death(&exit, 1).is_err());
    assert_eq!(
        observed(&Connection::open(&config.database)?),
        ("claimed".into(), 1, 0)
    );
    Ok(())
}
