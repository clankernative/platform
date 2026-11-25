//! The checked app artifact and the app's source inputs, byte for byte as the
//! app repositories' `publish_artifact.py pack` wrote them, because the deploy
//! side recomputes the source inputs from the forge archive and reads the
//! archive's layout:
//! - Files are every entry below a root, in the order `sorted(root.rglob("*"))`
//!   gives: by path parts, each compared by code point. Links are refused;
//!   each file must be regular, singly linked, without setuid or setgid, with
//!   a name of at most 1024 bytes and no backslash. At most 4096 files and
//!   128 MiB in all; at least one.
//! - The source inputs are `crate::source_inputs` over those files, the one
//!   implementation the deploy side uses for the forge archive.
//! - `app.tar.gz` holds each artifact file as `<artifact id>/<name>`, mode 0555
//!   if any execute bit is set and 0444 otherwise, owner 0, mtime 0, in
//!   Python's pax format (a `path` record for a name over 100 bytes or not
//!   ASCII), closed with two zero blocks and padded to a 10240-byte record.
//!   The gzip header names `app.tar`, mtime 0, best compression.
use anyhow::{Context, Result, ensure};
use day2::sdk_release::BlobIdentity;
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// publish_artifact.LIMIT: each file and all files together.
pub const LIMIT: u64 = 128 << 20;
/// The most files a root may hold.
pub const FILE_LIMIT: usize = 4096;
const BLOCK: usize = 512;
const RECORD: usize = BLOCK * 20;

/// One file below a root: its path parts, size and sha256 hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub parts: Vec<String>,
    pub size: u64,
    pub hex: String,
}

impl File {
    pub fn name(&self) -> String {
        self.parts.join("/")
    }
}

/// publish_artifact.files: every file below `root`, in Python's path order.
pub fn files(root: &Path) -> Result<Vec<File>> {
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.file_type().is_dir(),
        "real input directory required"
    );
    let mut paths = Vec::new();
    collect(root, &mut Vec::new(), &mut paths)?;
    paths.sort();
    let mut result = Vec::new();
    let mut total = 0;
    for parts in paths {
        let path = parts
            .iter()
            .fold(root.to_path_buf(), |path, part| path.join(part));
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(!metadata.file_type().is_symlink(), "artifact links refused");
        if metadata.is_dir() {
            continue;
        }
        let name = parts.join("/");
        ensure!(
            !name.contains('\\') && name.len() <= 1024 && metadata.mode() & 0o6000 == 0,
            "unsafe artifact entry"
        );
        let (size, hex) = identity(&path)?;
        total += size;
        result.push(File { parts, size, hex });
        ensure!(
            total <= LIMIT && result.len() <= FILE_LIMIT,
            "artifact byte/file budget"
        );
    }
    ensure!(!result.is_empty(), "artifact cannot be empty");
    Ok(result)
}

fn collect(directory: &Path, parts: &mut Vec<String>, paths: &mut Vec<Vec<String>>) -> Result<()> {
    ensure!(parts.len() < 64, "artifact nesting budget");
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("artifact names must be UTF-8"))?;
        parts.push(name);
        paths.push(parts.clone());
        ensure!(paths.len() <= 4 * FILE_LIMIT, "artifact byte/file budget");
        if entry.file_type()?.is_dir() {
            collect(&entry.path(), parts, paths)?;
        }
        parts.pop();
    }
    Ok(())
}

/// publish_artifact.identity: a bounded, singly linked regular file's size and sha256 hex.
fn identity(path: &Path) -> Result<(u64, String)> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1 && metadata.len() <= LIMIT,
        "bounded regular artifact file required"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "artifact file changed while it was read"
    );
    Ok((metadata.len(), hex(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    day2::digest(bytes)["sha256:".len()..].to_owned()
}

/// The app root's source inputs, as the deploy side recomputes them from the
/// forge archive: `crate::source_inputs` over every file below the root.
pub fn source_inputs(app: &Path) -> Result<String> {
    let files = files(app)?
        .into_iter()
        .map(|file| crate::source_inputs::SourceFile {
            name: file.name().chars().map(u32::from).collect(),
            size: file.size,
            hex: file.hex,
        })
        .collect();
    Ok(crate::source_inputs::digest(files))
}

/// The selected artifact `id` (64 hex) in `artifact`, written to
/// `output/app.tar.gz`, whose identity is returned.
pub fn pack(artifact: &Path, id: &str, output: &Path) -> Result<BlobIdentity> {
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid checked artifact"
    );
    let before = files(artifact)?;
    let definition: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact.join("artifact.json"))?)
            .context("invalid artifact definition")?;
    ensure!(
        definition["worker_digest"].as_str()
            == Some(format!("sha256:{}", identity(&artifact.join("worker"))?.1).as_str()),
        "checked worker changed before publication"
    );
    let archive = output.join("app.tar.gz");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&archive)?;
    let mut compressed = flate2::GzBuilder::new()
        .filename("app.tar")
        .mtime(0)
        .write(std::io::BufWriter::new(file), flate2::Compression::best());
    let mut offset = 0;
    for entry in &before {
        let path: PathBuf = entry
            .parts
            .iter()
            .fold(artifact.to_path_buf(), |path, part| path.join(part));
        let bytes = fs::read(&path)?;
        ensure!(
            bytes.len() as u64 == entry.size && hex(&bytes) == entry.hex,
            "checked artifact changed during publication"
        );
        let executable = fs::metadata(&path)?.mode() & 0o111 != 0;
        let header = header(
            &format!("{id}/{}", entry.name()),
            if executable { 0o555 } else { 0o444 },
            entry.size,
        );
        compressed.write_all(&header)?;
        compressed.write_all(&bytes)?;
        let padding = (BLOCK - bytes.len() % BLOCK) % BLOCK;
        compressed.write_all(&vec![0; padding])?;
        offset += header.len() + bytes.len() + padding;
    }
    compressed.write_all(&[0; BLOCK * 2])?;
    offset += BLOCK * 2;
    compressed.write_all(&vec![0; (RECORD - offset % RECORD) % RECORD])?;
    compressed
        .finish()?
        .into_inner()
        .map_err(|error| error.into_error())?
        .sync_all()?;
    ensure!(
        files(artifact)? == before,
        "checked artifact changed during publication"
    );
    let bytes = fs::read(&archive)?;
    Ok(BlobIdentity::of(&bytes))
}

/// tarfile's pax header blocks for one regular file.
pub(super) fn header(name: &str, mode: u32, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if !name.is_ascii() || name.len() > 100 {
        let record = pax_record("path", name);
        out.extend(ustar("././@PaxHeader", 0, record.len() as u64, b'x'));
        out.extend_from_slice(&record);
        out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
    }
    out.extend(ustar(name, mode, size, b'0'));
    out
}

/// One `"%d %s=%s\n"` record whose length counts its own digits.
fn pax_record(keyword: &str, value: &str) -> Vec<u8> {
    let length = keyword.len() + value.len() + 3;
    let mut total = 0;
    loop {
        let next = length + total.to_string().len();
        if next == total {
            break;
        }
        total = next;
    }
    format!("{total} {keyword}={value}\n").into_bytes()
}

/// tarfile's ustar header block: name as ASCII with `?` for any other
/// character, cut at 100 bytes; empty owner names and device fields.
fn ustar(name: &str, mode: u32, size: u64, kind: u8) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    let ascii: Vec<u8> = name
        .chars()
        .map(|character| {
            if character.is_ascii() {
                character as u8
            } else {
                b'?'
            }
        })
        .take(100)
        .collect();
    block[..ascii.len()].copy_from_slice(&ascii);
    let octal = |field: &mut [u8], value: u64| {
        let digits = format!("{value:0width$o}", width = field.len() - 1);
        field[..digits.len()].copy_from_slice(digits.as_bytes());
        field[digits.len()] = 0;
    };
    octal(&mut block[100..108], u64::from(mode));
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], 0);
    block[148..156].copy_from_slice(b"        ");
    block[156] = kind;
    block[257..265].copy_from_slice(b"ustar\x0000");
    let checksum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
    let digits = format!("{checksum:06o}\0");
    block[148..155].copy_from_slice(digits.as_bytes());
    block
}
