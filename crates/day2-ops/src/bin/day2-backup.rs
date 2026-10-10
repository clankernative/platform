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

const USAGE: &str =
    "usage: day2-backup INSTANCE_JSON APP OUTPUT_DIR [--upload-gcs BUCKET --object-prefix PREFIX]";

struct Upload {
    bucket: String,
    prefix: String,
}

fn text(value: &OsString, what: &str) -> Result<String> {
    Ok(value
        .to_str()
        .with_context(|| format!("{what} must be UTF-8"))?
        .to_owned())
}

fn parse(arguments: &[OsString]) -> Result<(PathBuf, String, PathBuf, Option<Upload>)> {
    ensure!(arguments.len() >= 3, "{USAGE}");
    let upload = match &arguments[3..] {
        [] => None,
        [flag, bucket, prefix_flag, prefix]
            if flag == "--upload-gcs" && prefix_flag == "--object-prefix" =>
        {
            let upload = Upload {
                bucket: text(bucket, "bucket")?,
                prefix: text(prefix, "object prefix")?,
            };
            offsite::validate_bucket(&upload.bucket)?;
            offsite::validate_prefix(&upload.prefix)?;
            Some(upload)
        }
        _ => bail!("{USAGE}"),
    };
    Ok((
        PathBuf::from(&arguments[0]),
        text(&arguments[1], "app name")?,
        PathBuf::from(&arguments[2]),
        upload,
    ))
}

fn run() -> Result<Value> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    // Arguments are checked before any snapshot is taken.
    let (instance, app, output, upload) = parse(&arguments)?;
    let taken = backup::take(&instance, &app, &output)?;
    let verified = backup::verify(&output)?;
    ensure!(
        verified.database == taken.database
            && verified.artifact == taken.artifact
            && verified.provider_databases == taken.provider_databases
            && verified.authority == taken.authority,
        "verified backup differs from the snapshot taken"
    );
    let mut summary = json!({
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
    });
    if let Some(upload) = upload {
        let prefix = format!(
            "{}/{}",
            upload.prefix,
            offsite::utc_stamp(SystemTime::now())?
        );
        summary["upload"] = offsite::upload_gcs(
            &output,
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
