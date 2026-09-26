//! Online, verified backup of one app, for scheduled off-cluster copies.
//!
//!   day2-backup <instance.json> <app> <output-dir>
//!
//! The same native operations as `day2 platform backup` (ops/Backup.roc), with
//! no logic of its own: `backup::take` snapshots the app database and its local
//! provider stores through SQLite's online backup API over read-only
//! connections, each bounded by a 15 s deadline, and copies the active
//! artifact; `backup::verify` then re-checks the stored bundle. Neither takes
//! day2-serve's lock, so this runs beside a serving pod on the same state
//! volume. The output directory must not exist. A partial directory carries no
//! backup.json and is not a backup.
//!
//! This binary ships in the distroless runtime image, which has no shell and no
//! Roc workflow runner, so it calls the two capabilities directly in the order
//! the Roc recipe does. On success it prints the manifest summary as one JSON
//! line; any failure exits non-zero.
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use day2_ops::backup;
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};

fn run() -> Result<Value> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 3,
        "usage: day2-backup INSTANCE_JSON APP OUTPUT_DIR"
    );
    let instance = PathBuf::from(&arguments[0]);
    let app = arguments[1].to_str().context("app name must be UTF-8")?;
    let output = PathBuf::from(&arguments[2]);
    let taken = backup::take(&instance, app, &output)?;
    let verified = backup::verify(&output)?;
    ensure!(
        verified.database == taken.database
            && verified.artifact == taken.artifact
            && verified.provider_databases == taken.provider_databases
            && verified.authority == taken.authority,
        "verified backup differs from the snapshot taken"
    );
    Ok(json!({
        "backup": output.canonicalize()?,
        "format": verified.format,
        "app": verified.app,
        "installation": verified.instance.installation,
        "environment": verified.instance.environment,
        "scope": verified.scope,
        "artifact": verified.artifact,
        "database": verified.database,
        "provider_databases": verified.provider_databases,
        "authority": verified.authority,
        "verified": true,
    }))
}

fn main() -> ExitCode {
    match run() {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("day2-backup: {error:#}");
            ExitCode::FAILURE
        }
    }
}
