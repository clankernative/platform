//! Atomic export of exact active selections for protected app-host mounts.
use anyhow::{Context, Result, ensure};
use day2_control::{journal::Journal, release::ReleaseTarget};
use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::PathBuf};

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 3,
        "usage: day2-serving-snapshot JOURNAL TARGETS_JSON OUTPUT"
    );
    let targets_path = PathBuf::from(&arguments[1]);
    ensure!(
        fs::metadata(&targets_path)?.len() <= 16_384,
        "serving_target_byte_budget"
    );
    let targets: Vec<ReleaseTarget> = day2::json::decode(&fs::read(targets_path)?)?;
    let snapshot =
        Journal::open_readonly(&PathBuf::from(&arguments[0]))?.serving_snapshot(&targets)?;
    let output = PathBuf::from(&arguments[2]);
    let parent = output.parent().context("snapshot parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec(&snapshot)?)?;
    file.as_file().sync_all()?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    file.persist(&output)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
