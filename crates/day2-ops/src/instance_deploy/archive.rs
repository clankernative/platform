//! The off-cluster copies of a deploy's private backup directory, at the
//! earlier controller's paths:
//! `gs://<project>-<app>-backups/deployments/<commit>/<uuid4 hex>/<phase>/<directory name>/<relative path>`,
//! where `<phase>` is `before-activation` or `after-activation` and
//! `<directory name>` is the backup directory's own name (as `gcloud storage cp
//! --recursive` places it). The upload never replaces an object; then a listing
//! of the phase must name exactly the local manifest's files, each with the
//! same size and CRC32C. Nothing here reads or logs a file's contents beyond
//! hashing them.
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, ffi::OsString, fs, io::Read, path::Path};

pub const BEFORE: &str = "before-activation";
pub const AFTER: &str = "after-activation";

/// The most files and the deepest nesting a backup directory may hold, as for
/// a scheduled backup's upload.
pub const MAX_FILES: usize = 32_768;
pub const MAX_DEPTH: usize = 16;

/// `gs://<project>-<app>-backups/deployments/<commit>/<uuid>/`.
pub fn prefix(bucket: &str, commit: &str, uuid: &str) -> Result<String> {
    crate::offsite::validate_bucket(bucket)?;
    ensure!(
        crate::instance_source::commit(commit),
        "invalid release source commit"
    );
    ensure!(
        crate::instance_source::lower_hex(uuid, 32),
        "invalid archive uuid"
    );
    Ok(format!("gs://{bucket}/deployments/{commit}/{uuid}/"))
}

/// A version 4 UUID's 32 hex digits, as Python's `uuid.uuid4().hex`.
pub fn uuid4(random: [u8; 16]) -> String {
    let mut bytes = random;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One file of a backup directory: its `/`-joined path below the directory,
/// its size and its CRC32C as GCS reports it (base64 of the big-endian value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub crc32c: String,
}

/// What a phase's copy holds, for the receipt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub objects: u64,
    pub bytes: u64,
}

/// The directory's regular files, sorted by name. Links, devices, FIFOs and
/// sockets are refused, as are names that are not UTF-8 or hold a control
/// character, more than `MAX_FILES` files and nesting deeper than `MAX_DEPTH`.
pub fn manifest(directory: &Path) -> Result<Vec<Entry>> {
    let metadata =
        fs::symlink_metadata(directory).with_context(|| format!("read {}", directory.display()))?;
    ensure!(
        metadata.is_dir(),
        "the backup directory must be a directory, not a link"
    );
    let mut entries = Vec::new();
    walk(directory, "", 0, &mut entries)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn walk(directory: &Path, relative: &str, depth: usize, out: &mut Vec<Entry>) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "the backup directory nests too deeply");
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        names.push(entry?.file_name());
    }
    names.sort();
    for name in names {
        let text = name
            .to_str()
            .filter(|text| !text.chars().any(char::is_control))
            .context("a backup file name is not printable UTF-8")?;
        let path = directory.join(&name);
        let joined = if relative.is_empty() {
            text.to_owned()
        } else {
            format!("{relative}/{text}")
        };
        let metadata = fs::symlink_metadata(&path)?;
        let kind = metadata.file_type();
        if kind.is_dir() {
            walk(&path, &joined, depth + 1, out)?;
        } else if kind.is_file() {
            ensure!(
                out.len() < MAX_FILES,
                "the backup directory holds too many files"
            );
            let (size, crc32c) = checksum(&path)?;
            ensure!(
                size == metadata.len(),
                "a backup file changed while it was read"
            );
            out.push(Entry {
                name: joined,
                size,
                crc32c,
            });
        } else {
            bail!("the backup directory may hold only files and directories: {joined}");
        }
    }
    Ok(())
}

/// A file's size and CRC32C, read without following a link.
fn checksum(path: &Path) -> Result<(u64, String)> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let mut crc = Crc32c::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        crc.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((size, base64(&crc.finish().to_be_bytes())))
}

/// The objects a phase must hold: `<phase prefix><directory name>/<name>`, as
/// object names (without `gs://<bucket>/`).
pub fn expected(
    prefix: &str,
    phase: &str,
    directory: &str,
    entries: &[Entry],
) -> Result<BTreeMap<String, (u64, String)>> {
    ensure!(phase == BEFORE || phase == AFTER, "unknown archive phase");
    let (_, path) = prefix
        .strip_prefix("gs://")
        .and_then(|rest| rest.split_once('/'))
        .context("invalid archive prefix")?;
    let mut objects = BTreeMap::new();
    for entry in entries {
        objects.insert(
            format!("{path}{phase}/{directory}/{}", entry.name),
            (entry.size, entry.crc32c.clone()),
        );
    }
    Ok(objects)
}

/// `gcloud storage cp --recursive --no-clobber <directory> <prefix><phase>/`:
/// gcloud places the directory itself under the destination, and never
/// replaces an object that exists.
pub fn upload_args(directory: &Path, prefix: &str, phase: &str) -> Vec<OsString> {
    vec![
        "storage".into(),
        "cp".into(),
        "--recursive".into(),
        "--no-clobber".into(),
        directory.into(),
        format!("{prefix}{phase}/").into(),
    ]
}

/// `gcloud storage objects list <prefix><phase>/** --format=json(name,size,crc32c_hash)`.
pub fn list_args(prefix: &str, phase: &str) -> Vec<OsString> {
    vec![
        "storage".into(),
        "objects".into(),
        "list".into(),
        format!("{prefix}{phase}/**").into(),
        "--format=json(name,size,crc32c_hash)".into(),
    ]
}

/// A listing (`[{name, size, crc32c_hash}, ...]`) must name exactly the
/// expected objects, each with its size and CRC32C. The error names the first
/// difference by object name only.
pub fn verify(listing: &[u8], expected: &BTreeMap<String, (u64, String)>) -> Result<Totals> {
    let value: Value =
        serde_json::from_slice(listing).context("the archive listing is not JSON")?;
    let items = value
        .as_array()
        .context("the archive listing is not a list")?;
    let mut listed = BTreeMap::new();
    for item in items {
        let name = item["name"]
            .as_str()
            .context("an archive object has no name")?;
        let size = match &item["size"] {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        }
        .with_context(|| format!("archive object {name} has no size"))?;
        let crc = item["crc32c_hash"]
            .as_str()
            .with_context(|| format!("archive object {name} has no CRC32C"))?;
        ensure!(
            listed
                .insert(name.to_owned(), (size, crc.to_owned()))
                .is_none(),
            "archive object {name} is listed twice"
        );
    }
    for (name, wanted) in expected {
        match listed.get(name) {
            None => bail!("archive object {name} is missing after the upload"),
            Some(found) if found != wanted => {
                bail!("archive object {name} differs from the local backup")
            }
            Some(_) => {}
        }
    }
    if let Some(extra) = listed.keys().find(|name| !expected.contains_key(*name)) {
        bail!("archive object {extra} is not in the local backup");
    }
    Ok(Totals {
        objects: expected.len() as u64,
        bytes: expected.values().map(|(size, _)| size).sum(),
    })
}

/// The directory's own name, which the archive keeps.
pub fn directory_name(directory: &Path) -> Result<String> {
    directory
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .context("the backup directory has no name")
}

/// Whether the backup directory holds something to archive.
pub fn nonempty(directory: &Path) -> Result<bool> {
    let mut entries = fs::read_dir(directory)?;
    match entries.next() {
        Some(entry) => {
            entry?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The CRC32C (Castagnoli) checksum GCS reports.
pub struct Crc32c(u32);

const fn table() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

const TABLE: [u32; 256] = table();

impl Crc32c {
    pub fn new() -> Self {
        Self(!0)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = TABLE[((self.0 ^ u32::from(*byte)) & 0xff) as usize] ^ (self.0 >> 8);
        }
    }

    pub fn finish(&self) -> u32 {
        !self.0
    }
}

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

/// Standard, padded base64.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().enumerate().fold(0_u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for position in 0..4 {
            if position <= chunk.len() {
                out.push(ALPHABET[((value >> (18 - 6 * position)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Where a phase's copy went, for the receipt and messages.
pub fn phase_uri(prefix: &str, phase: &str) -> String {
    format!("{prefix}{phase}/")
}
