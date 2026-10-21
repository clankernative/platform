//! Explicit live Carta qualification. An operator runs it with a reviewed
//! playground profile and a private secret file; it is never part of verify.
//! The receipt holds counts, shapes and field names only, and every run reports
//! `provider_qualified: false` until a reviewer accepts its evidence.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const MAX_INPUT_BYTES: u64 = 16 * 1024;

/// A bounded regular file read from the opened descriptor, never through a link.
fn bounded(path: &Path, private: bool) -> Result<Vec<u8>> {
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

pub fn execute(profile: &Path, secret: &Path, evidence: &Path) -> Result<()> {
    let profile: day2::carta_qualification::QualificationProfile =
        day2::json::decode(&bounded(profile, false)?)?;
    let secret = String::from_utf8(bounded(secret, true)?)
        .context("secret encoding")?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(evidence)
        .context("evidence directory must be new")?;
    // The scratch store holds real records; it is discarded with this directory.
    let scratch = tempfile::tempdir_in(evidence)?;
    let receipt =
        day2::carta_qualification::qualify(&profile, secret, &scratch.path().join("carta.sqlite"))?;
    drop(scratch);
    let path = evidence.join("receipt.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    file.sync_all()?;
    File::open(evidence)?.sync_all()?;
    println!(
        "carta qualification {}: {}",
        receipt["outcome"].as_str().unwrap_or("unknown"),
        path.display()
    );
    Ok(())
}
