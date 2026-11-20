//! Inputs and evidence for the operator qualification sessions,
//! `carta-qualify` and `google-workspace-qualify`, neither part of verify:
//! bounded reads of a reviewed profile and an owner-private secret or token,
//! the new owner-private evidence directory, the guard that refuses evidence
//! containing a private value, and create-new private evidence files.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const MAX_INPUT_BYTES: u64 = 16 * 1024;

/// A bounded regular file read from the opened descriptor, never through a link.
pub(crate) fn bounded(path: &Path, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.len() <= MAX_INPUT_BYTES
            && (!private || metadata.permissions().mode() & 0o077 == 0),
        "{} must be a bounded{} regular file",
        path.display(),
        if private { " owner-private" } else { "" }
    );
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_INPUT_BYTES, "input byte budget");
    Ok(bytes)
}

/// Wall time, only to refuse an expired profile before a secret is read.
pub(crate) fn now() -> Result<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?)
}

/// The new owner-private evidence directory; an existing one is refused.
pub(crate) fn create_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .context("evidence directory must be new")
}

/// Refuse evidence that contains `value`, which must not be empty.
pub(crate) fn refuse_containing(bytes: &[u8], value: &str, refusal: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes()),
        "{refusal}"
    );
    Ok(())
}

/// A create-new 0600 evidence file, synced with its directory. No existing
/// path is overwritten.
pub(crate) fn publish(directory: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(path)
}
