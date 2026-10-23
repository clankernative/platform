//! Online, verified backup of one app, optionally copied to Cloud Storage.
//!
//!   day2-backup <instance.json> <app> <output-dir>
//!       [--upload-gcs <bucket> --object-prefix <prefix>]
//!
//! The same native operations as `day2 platform backup` (ops/Backup.roc), with
//! no backup logic of its own: `backup::take` snapshots the app database and
//! its local provider stores through SQLite's online backup API over read-only
//! connections, each copied inside one read transaction (a consistent snapshot
//! that the app's concurrent commits cannot restart) and failing after 15 s
//! without progress or after 15 s plus its size at 8 MiB/s, and copies the
//! active artifact; `backup::verify` then re-checks the stored bundle. Neither
//! takes day2-serve's lock, so this runs beside a serving pod on the same state
//! volume. The output directory must not exist. A partial directory carries no
//! backup.json and is not a backup.
//!
//! With `--upload-gcs`, the verified bundle is then uploaded file by file to
//! `gs://<bucket>/<prefix>/<UTC yyyymmddThhmmssZ>/<relative path>` using the
//! GKE metadata server's Workload Identity token, never replacing an object,
//! and `<...>/COMPLETE` is written last (see `day2_ops::offsite`). The binary
//! appends the timestamp itself, so every run has a fresh prefix.
//!
//! This binary ships in the distroless runtime image, which has no shell and no
//! Roc workflow runner, so it calls the capabilities directly in the order the
//! Roc recipe does. On success it prints one JSON summary line; any failure
//! exits non-zero.
#![forbid(unsafe_code)]
use anyhow::{Context, Result, bail, ensure};
use day2_ops::{backup, offsite};
use serde_json::{Value, json};
use std::{ffi::OsString, path::PathBuf, process::ExitCode, time::SystemTime};

const USAGE: &str = "usage: day2-backup INSTANCE_JSON APP OUTPUT_DIR [--include-state-subpath PATH]... [--include-state-sqlite PATH]... [--upload-gcs BUCKET --object-prefix PREFIX]";

struct Upload {
    bucket: String,
    prefix: String,
}

struct BackupOptions {
    instance: PathBuf,
    app: String,
    output: PathBuf,
    upload: Option<Upload>,
    state_subpaths: Vec<String>,
    sqlite_paths: Vec<String>,
}

fn text(value: &OsString, what: &str) -> Result<String> {
    Ok(value
        .to_str()
        .with_context(|| format!("{what} must be UTF-8"))?
        .to_owned())
}

fn parse(arguments: &[OsString]) -> Result<BackupOptions> {
    ensure!(arguments.len() >= 3, "{USAGE}");
    let (mut upload, mut state_subpaths, mut sqlite_paths) = (None, Vec::new(), Vec::new());
    let mut index = 3;
    while index < arguments.len() {
        match text(&arguments[index], "backup option")?.as_str() {
            "--upload-gcs" if index + 3 < arguments.len() && upload.is_none() => {
                let candidate = Upload {
                    bucket: text(&arguments[index + 1], "bucket")?,
                    prefix: text(&arguments[index + 3], "object prefix")?,
                };
                ensure!(
                    text(&arguments[index + 2], "object prefix option")? == "--object-prefix",
                    "{USAGE}"
                );
                offsite::validate_bucket(&candidate.bucket)?;
                offsite::validate_prefix(&candidate.prefix)?;
                upload = Some(candidate);
                index += 4;
            }
            "--include-state-subpath" if index + 1 < arguments.len() => {
                state_subpaths.push(text(&arguments[index + 1], "companion state subpath")?);
                index += 2;
            }
            "--include-state-sqlite" if index + 1 < arguments.len() => {
                sqlite_paths.push(text(&arguments[index + 1], "companion SQLite path")?);
                index += 2;
            }
            _ => bail!("{USAGE}"),
        }
    }
    for path in &state_subpaths {
        backup::validate_companion_state_subpath(path)?;
    }
    for path in &sqlite_paths {
        backup::validate_companion_sqlite_path(path)?;
    }
    Ok(BackupOptions {
        instance: PathBuf::from(&arguments[0]),
        app: text(&arguments[1], "app name")?,
        output: PathBuf::from(&arguments[2]),
        upload,
        state_subpaths,
        sqlite_paths,
    })
}

fn run() -> Result<Value> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    // Arguments are checked before any snapshot is taken.
    let options = parse(&arguments)?;
    let taken = backup::take_with_companion_state(
        &options.instance,
        &options.app,
        &options.output,
        &options.state_subpaths,
        &options.sqlite_paths,
    )?;
    let verified = backup::verify(&options.output)?;
    ensure!(
        verified.database == taken.database
            && verified.artifact == taken.artifact
            && verified.provider_databases == taken.provider_databases
            && verified.companion_state == taken.companion_state
            && verified.authority == taken.authority,
        "verified backup differs from the snapshot taken"
    );
    let mut summary = json!({
        "backup": options.output.canonicalize()?,
        "format": verified.format,
        "app": verified.app,
        "installation": verified.instance.installation,
        "environment": verified.instance.environment,
        "scope": verified.scope,
        "artifact": verified.artifact,
        "database": verified.database,
        "provider_databases": verified.provider_databases,
        "companion_state": verified.companion_state,
        "authority": verified.authority,
        "verified": true,
    });
    if let Some(upload) = options.upload {
        let prefix = format!(
            "{}/{}",
            upload.prefix,
            offsite::utc_stamp(SystemTime::now())?
        );
        summary["upload"] = offsite::upload_gcs(
            &options.output,
            &upload.bucket,
            &prefix,
            &offsite::Endpoints::google(),
        )?;
    }
    Ok(summary)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_bounded_companion_paths_and_exact_upload_options() {
        let parsed = parse(&args(&[
            "instance.json",
            "reports",
            "/backup/snapshot",
            "--include-state-subpath",
            "companions/executor",
            "--include-state-sqlite",
            "companions/executor/store.sqlite",
            "--upload-gcs",
            "example-backups",
            "--object-prefix",
            "reports",
        ]))
        .unwrap();
        assert_eq!(parsed.state_subpaths, ["companions/executor"]);
        assert_eq!(parsed.sqlite_paths, ["companions/executor/store.sqlite"]);
        assert_eq!(parsed.upload.unwrap().prefix, "reports");
    }

    #[test]
    fn refuses_traversal_duplicate_upload_and_unrecognized_options() {
        assert!(
            parse(&args(&[
                "instance.json",
                "reports",
                "/backup",
                "--include-state-subpath",
                "companions/../outside",
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "instance.json",
                "reports",
                "/backup",
                "--upload-gcs",
                "example-backups",
                "--object-prefix",
                "reports",
                "--upload-gcs",
                "example-backups",
                "--object-prefix",
                "reports",
            ]))
            .is_err()
        );
        assert!(
            parse(&args(&[
                "instance.json",
                "reports",
                "/backup",
                "--shell",
                "echo"
            ]))
            .is_err()
        );
    }
}
