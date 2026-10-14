use anyhow::{Context, Result, ensure};
use day2::{
    automation::{Request, ui},
    build_dependencies,
};
use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tar::{Archive, EntryType};

const MAX_ARCHIVE: u64 = 8_000_000;
const MAX_EXTRACTED: u64 = 80_000_000;
const MAX_FILES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Start,
    Inspected,
    Fetched,
    Extracted,
    Verified,
    Published,
    Receipted,
}

pub struct Session {
    root: PathBuf,
    phase: Phase,
    archive: Option<Vec<u8>>,
    staging: Option<tempfile::TempDir>,
    receipt: Option<ui::DependencyReceipt>,
}

impl Session {
    pub fn new(root: &Path) -> Result<Self> {
        ensure!(root.is_absolute(), "Platform root must be absolute");
        let root_meta = fs::symlink_metadata(root)?;
        ensure!(
            root_meta.is_dir() && !root_meta.file_type().is_symlink(),
            "Platform root must be a real directory"
        );
        Ok(Self {
            root: root.to_path_buf(),
            phase: Phase::Start,
            archive: None,
            staging: None,
            receipt: None,
        })
    }

    pub fn effect(&mut self, request: Request) -> Result<Value> {
        ui::dispatch_install(self, &request)?.context("unsupported UI dependency effect")
    }

    pub fn is_complete(&self) -> bool {
        self.phase == Phase::Receipted
    }

    fn destination(&self) -> Result<PathBuf> {
        let cli = self.root.join("cli");
        if let Ok(meta) = fs::symlink_metadata(&cli) {
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "Platform cli path must be a real directory"
            );
        }
        let destination = build_dependencies::installation_path(&self.root)?;
        let parent = destination.parent().context("dependency install parent")?;
        if let Ok(meta) = fs::symlink_metadata(parent) {
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "dependency install parent must be a real directory"
            );
        }
        Ok(destination)
    }
}

impl ui::InstallHost for Session {
    fn inspect(&mut self, _input: ui::Empty) -> Result<ui::Inspection> {
        ensure!(
            self.phase == Phase::Start,
            "dependency inspect out of order"
        );
        let destination = self.destination()?;
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                let bundle = build_dependencies::installed(&self.root).context("installed managed UI dependency is corrupt; remove it deliberately before reinstalling")?;
                self.receipt = Some(bundle.receipt());
                self.phase = Phase::Published;
                Ok(ui::Inspection { installed: true })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.phase = Phase::Inspected;
                Ok(ui::Inspection { installed: false })
            }
            Err(error) => Err(error.into()),
        }
    }

    fn fetch(&mut self, _input: ui::Empty) -> Result<ui::Fetched> {
        ensure!(
            self.phase == Phase::Inspected,
            "dependency fetch out of order"
        );
        let pin = build_dependencies::download_pin()?;
        let url = format!(
            "https://github.com/clankernative/clanker-ui/releases/download/v{}/{}",
            pin.release, pin.archive
        );
        let client = reqwest::blocking::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(30))
            .build()?;
        let response = client.get(url).send()?.error_for_status()?;
        if let Some(length) = response.content_length() {
            ensure!(
                length == pin.bytes,
                "managed dependency archive size mismatch"
            );
        }
        let mut bytes = Vec::with_capacity(pin.bytes as usize);
        response.take(MAX_ARCHIVE + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == pin.bytes,
            "managed dependency archive size mismatch"
        );
        ensure!(
            sha(&bytes) == pin.sha256,
            "managed dependency archive digest mismatch"
        );
        self.archive = Some(bytes);
        self.phase = Phase::Fetched;
        Ok(ui::Fetched { fetched: true })
    }

    fn extract(&mut self, _input: ui::Empty) -> Result<ui::Extracted> {
        ensure!(
            self.phase == Phase::Fetched,
            "dependency extract out of order"
        );
        let bytes = self.archive.as_ref().context("verified archive missing")?;
        let cli = self.root.join("cli");
        match fs::symlink_metadata(&cli) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "Platform cli path must be a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&cli)?,
            Err(error) => return Err(error.into()),
        }
        let destination = self.destination()?;
        let parent = destination.parent().context("dependency install parent")?;
        match fs::symlink_metadata(parent) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "dependency install parent must be a real directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(parent)?,
            Err(error) => return Err(error.into()),
        }
        let staging = tempfile::Builder::new()
            .prefix(".clanker-ui-")
            .tempdir_in(parent)?;
        extract_archive(bytes, staging.path())?;
        self.staging = Some(staging);
        self.phase = Phase::Extracted;
        Ok(ui::Extracted { extracted: true })
    }

    fn verify(&mut self, _input: ui::Empty) -> Result<ui::Verified> {
        ensure!(
            self.phase == Phase::Extracted,
            "dependency verify out of order"
        );
        let pin = build_dependencies::download_pin()?;
        let stage = self
            .staging
            .as_ref()
            .context("extracted dependency missing")?;
        let bundle = build_dependencies::verify_staged(stage.path(), &pin.target)?;
        self.receipt = Some(bundle.receipt());
        self.phase = Phase::Verified;
        Ok(ui::Verified { verified: true })
    }

    fn publish(&mut self, _input: ui::Empty) -> Result<ui::Published> {
        ensure!(
            self.phase == Phase::Verified,
            "dependency publish requires successful verification"
        );
        let stage = self
            .staging
            .as_ref()
            .context("verified dependency missing")?;
        let destination = self.destination()?;
        match rustix::fs::renameat_with(
            rustix::fs::CWD,
            stage.path(),
            rustix::fs::CWD,
            &destination,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(error) if error == rustix::io::Errno::EXIST => {
                let existing = build_dependencies::installed(&self.root)
                    .context("existing dependency blocks immutable publish")?;
                ensure!(
                    Some(existing.receipt()) == self.receipt,
                    "a different dependency was published concurrently"
                );
            }
            Err(error) => return Err(error).context("atomically publish verified dependency"),
        }
        self.staging.take();
        let installed = build_dependencies::installed(&self.root)?;
        ensure!(
            Some(installed.receipt()) == self.receipt,
            "published dependency identity changed"
        );
        self.phase = Phase::Published;
        Ok(ui::Published { published: true })
    }

    fn receipt(&mut self, _input: ui::Empty) -> Result<ui::JsonReceipt<ui::DependencyReceipt>> {
        ensure!(
            self.phase == Phase::Published,
            "dependency receipt requested before publication/inspection"
        );
        let receipt = self
            .receipt
            .clone()
            .context("verified dependency receipt missing")?;
        self.phase = Phase::Receipted;
        Ok(ui::JsonReceipt(receipt))
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn extract_archive(bytes: &[u8], destination: &Path) -> Result<()> {
    ensure!(
        bytes.len() as u64 <= MAX_ARCHIVE,
        "archive byte budget exceeded"
    );
    let decoder = GzDecoder::new(bytes).take(MAX_EXTRACTED + 1);
    let mut archive = Archive::new(decoder);
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    let mut count = 0usize;
    for entry in archive.entries()? {
        let mut entry = entry?;
        count += 1;
        ensure!(count <= MAX_FILES, "archive file count budget exceeded");
        let path = entry.path()?.into_owned();
        let kind = entry.header().entry_type();
        let raw = path.to_str().context("non-UTF8 archive path")?;
        let relative = if kind == EntryType::Directory {
            raw.trim_end_matches('/')
        } else {
            raw
        };
        ensure!(
            !relative.is_empty()
                && !relative.starts_with('/')
                && !relative.contains('\\')
                && relative
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && Path::new(relative)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "unsafe archive path"
        );
        ensure!(seen.insert(relative.to_owned()), "duplicate archive path");
        let target = destination.join(relative);
        if kind == EntryType::Directory {
            fs::create_dir_all(&target)?;
            ensure!(
                fs::symlink_metadata(&target)?.is_dir(),
                "archive directory collision"
            );
            continue;
        }
        ensure!(
            kind == EntryType::Regular,
            "archive links and special files are forbidden"
        );
        let size = entry.size();
        let mode = entry.header().mode()?;
        ensure!(
            mode & !0o777 == 0,
            "archive member has unsafe permission bits"
        );
        ensure!(
            size <= 16 * 1024 * 1024,
            "archive member exceeds byte budget"
        );
        total = total
            .checked_add(size)
            .context("archive byte budget overflow")?;
        ensure!(
            total <= MAX_EXTRACTED,
            "extracted archive exceeds byte budget"
        );
        let parent = target.parent().context("archive member parent")?;
        fs::create_dir_all(parent)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .with_context(|| format!("create archive member {}", target.display()))?;
        let copied = std::io::copy(&mut entry, &mut output)?;
        ensure!(copied == size, "archive member size changed");
        output.sync_all()?;
        set_mode(&target, mode)?;
    }
    ensure!(
        seen.contains("manifest.json") && seen.contains("provider-pin.json"),
        "archive lacks required metadata"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2::automation::Request;
    use serde_json::json;

    fn request(action: &str, input: &str) -> Request {
        Request {
            protocol: 1,
            action: action.into(),
            input: input.into(),
        }
    }

    #[test]
    fn enforces_empty_inputs_and_order() {
        let temp = tempfile::tempdir().unwrap();
        let mut session = Session::new(temp.path()).unwrap();
        assert!(
            session
                .effect(request("ui-dependency-fetch", "{}"))
                .is_err()
        );
        assert!(
            session
                .effect(request("ui-dependency-inspect", "[]"))
                .is_err()
        );
        assert_eq!(
            session
                .effect(request("ui-dependency-inspect", "{}"))
                .unwrap(),
            json!({"installed":false})
        );
        assert!(
            session
                .effect(request("ui-dependency-publish", "{}"))
                .is_err()
        );
        assert!(
            !build_dependencies::installation_path(temp.path())
                .unwrap()
                .exists()
        );
    }

    #[test]
    fn malicious_archive_paths_and_links_are_rejected() {
        for name in ["../escape", "/absolute", "folder/../../escape", "./dot"] {
            let temp = tempfile::tempdir().unwrap();
            let bytes = test_archive(name, EntryType::Regular);
            assert!(extract_archive(&bytes, temp.path()).is_err());
            assert!(!temp.path().join("escape").exists());
        }
        let temp = tempfile::tempdir().unwrap();
        let bytes = test_archive("link", EntryType::Symlink);
        assert!(extract_archive(&bytes, temp.path()).is_err());
    }

    fn test_archive(name: &str, kind: EntryType) -> Vec<u8> {
        let mut encoder =
            flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::default());
        {
            let mut builder = tar::Builder::new(&mut encoder);
            let mut header = tar::Header::new_gnu();
            header.set_path("safe-name").unwrap();
            if name != "safe-name" {
                let path_bytes = name.as_bytes();
                assert!(path_bytes.len() < 100);
                header.as_mut_bytes()[..100].fill(0);
                header.as_mut_bytes()[..path_bytes.len()].copy_from_slice(path_bytes);
            }
            header.set_entry_type(kind);
            header.set_size(if kind == EntryType::Regular { 1 } else { 0 });
            header.set_mode(0o644);
            header.set_cksum();
            let data = if kind == EntryType::Regular {
                b"x".as_slice()
            } else {
                b"".as_slice()
            };
            if kind == EntryType::Symlink {
                header.set_link_name("/tmp/target").unwrap();
                header.set_cksum();
            }
            builder.append(&header, data).unwrap();
            builder.finish().unwrap();
        }
        encoder.finish().unwrap()
    }
}
