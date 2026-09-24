//! Company-owned Git storage. Only fixed plumbing commands run; source is never executed.
use crate::{Digest, GitOid, source::SourceSnapshot};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeMap<String, Vec<u8>>",
    into = "BTreeMap<String, Vec<u8>>"
)]
pub struct SourceBundle(BTreeMap<String, Vec<u8>>);
impl SourceBundle {
    pub fn from_files(files: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        Self::try_from(files)
    }
    pub fn capture(root: &Path) -> Result<Self> {
        fn visit(
            root: &Path,
            directory: &Path,
            files: &mut BTreeMap<String, Vec<u8>>,
            total: &mut u64,
        ) -> Result<()> {
            ensure!(
                directory.strip_prefix(root)?.components().count() <= 16
                    && fs::symlink_metadata(directory)?.is_dir(),
                "source directory type or depth"
            );
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                // Repository metadata is not application source, including worktree .git files.
                if entry.file_name() == ".git" {
                    continue;
                }
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    visit(root, &entry.path(), files, total)?;
                } else {
                    ensure!(
                        kind.is_file(),
                        "source symlinks and special files forbidden"
                    );
                    let size = entry.metadata()?.len();
                    *total = total.checked_add(size).context("source byte overflow")?;
                    ensure!(
                        size <= 2 * 1024 * 1024 && *total <= 16 * 1024 * 1024 && files.len() < 4096,
                        "source capture budget"
                    );
                    files.insert(
                        entry
                            .path()
                            .strip_prefix(root)?
                            .to_str()
                            .context("source UTF-8 path")?
                            .to_owned(),
                        fs::read(entry.path())?,
                    );
                }
            }
            Ok(())
        }
        ensure!(
            fs::symlink_metadata(root)?.is_dir(),
            "source root must be a real directory"
        );
        let root = root.canonicalize()?;
        let mut files = BTreeMap::new();
        visit(&root, &root, &mut files, &mut 0)?;
        Self::from_files(files)
    }
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.0
    }
    pub fn digest(&self) -> Result<Digest> {
        Ok(self.snapshot(zero_oid()?)?.digest().clone())
    }
    pub fn snapshot(&self, commit: GitOid) -> Result<SourceSnapshot> {
        Ok(SourceSnapshot::from_files(commit, self.0.clone())?)
    }
}
impl TryFrom<BTreeMap<String, Vec<u8>>> for SourceBundle {
    type Error = anyhow::Error;
    fn try_from(files: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        SourceSnapshot::from_files(zero_oid()?, files.clone())?;
        for path in files.keys() {
            let name = Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .context("source file name")?;
            let extension = Path::new(path)
                .extension()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            ensure!(
                name == ".gitignore"
                    || ([
                        "roc", "html", "css", "js", "json", "md", "svg", "png", "jpg", "jpeg",
                        "webp", "ico", "woff", "woff2", "txt"
                    ]
                    .contains(&extension)
                        && !["package.json", "package-lock.json", "credentials.json"]
                            .contains(&name)),
                "source file outside application source contract: {path}"
            );
        }
        Ok(Self(files))
    }
}
impl From<SourceBundle> for BTreeMap<String, Vec<u8>> {
    fn from(bundle: SourceBundle) -> Self {
        bundle.0
    }
}
fn zero_oid() -> Result<GitOid> {
    GitOid::try_from("0".repeat(40))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceChange {
    Export { bundle: SourceBundle },
    Propose { base: GitOid, bundle: SourceBundle },
}
impl SourceChange {
    pub fn bundle(&self) -> &SourceBundle {
        match self {
            Self::Export { bundle } | Self::Propose { bundle, .. } => bundle,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReceipt {
    pub commit: GitOid,
    pub reference: String,
    pub source: Digest,
}

pub trait SourceControl: Send + Sync {
    fn apply(&self, id: &Digest, change: &SourceChange) -> Result<SourceReceipt>;
    fn snapshot(&self, commit: &GitOid) -> Result<SourceSnapshot>;
}

pub struct LocalGit {
    repository: PathBuf,
}
impl LocalGit {
    pub fn open(repository: &Path, owner: &Digest) -> Result<Self> {
        let parent = repository.parent().context("repository parent")?;
        private_directory(parent)?;
        let result = Self {
            repository: repository.to_path_buf(),
        };
        if !repository.exists() {
            // Publish initialized ownership and Git metadata together; a crash must not
            // leave an unowned repository at the configured authority path.
            let staging = tempfile::tempdir_in(parent)?;
            let output = fixed_git()
                .args(["init", "--bare", "--template=", "--initial-branch=main"])
                .arg(staging.path())
                .output()?;
            ensure!(
                output.status.success(),
                "source_repository_initialization_failed"
            );
            let mut marker = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(staging.path().join("day2-owner"))?;
            marker.write_all(owner.as_str().as_bytes())?;
            marker.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
            }
            fs::File::open(staging.path())?.sync_all()?;
            if let Err(error) = fs::rename(staging.path(), repository) {
                ensure!(
                    repository.exists(),
                    "source repository publication failed: {error}"
                );
            }
            fs::File::open(parent)?.sync_all()?;
        }
        ensure!(
            fs::symlink_metadata(repository)?.is_dir() && repository.canonicalize()? == repository,
            "repository path must not contain symlinks"
        );
        ensure!(
            fs::read_to_string(repository.join("day2-owner"))? == owner.as_str(),
            "repository authority mismatch"
        );
        ensure!(
            result
                .git(&["rev-parse", "--is-bare-repository"], None)?
                .trim()
                == "true",
            "managed source must be a bare repository"
        );
        Ok(result)
    }
    fn git(&self, args: &[&str], input: Option<&[u8]>) -> Result<String> {
        let bytes = self.git_bytes(args, input)?;
        Ok(String::from_utf8(bytes)?)
    }
    pub(crate) fn repository(&self) -> &Path {
        &self.repository
    }
    pub(crate) fn git_bytes(&self, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut command = fixed_git();
        command
            .arg("--git-dir")
            .arg(&self.repository)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = command.spawn()?;
        if let Some(input) = input {
            child.stdin.take().context("git stdin")?.write_all(input)?;
        }
        let output = child.wait_with_output()?;
        ensure!(output.status.success(), "source_git_operation_failed");
        ensure!(
            output.stdout.len() <= 32 * 1024 * 1024,
            "source output budget"
        );
        Ok(output.stdout)
    }
    fn reference(&self, reference: &str) -> Result<Option<GitOid>> {
        let output = fixed_git()
            .arg("--git-dir")
            .arg(&self.repository)
            .args(["show-ref", "--verify", "--hash", reference])
            .output()?;
        if !output.status.success() {
            let probe = fixed_git()
                .arg("--git-dir")
                .arg(&self.repository)
                .args(["show-ref", "--verify", "--quiet", reference])
                .output()?;
            if probe.status.code() == Some(1) {
                return Ok(None);
            }
        }
        ensure!(output.status.success(), "source_ref_read_failed");
        Ok(Some(GitOid::try_from(
            String::from_utf8(output.stdout)?.trim().to_owned(),
        )?))
    }
    fn tree(&self, files: &BTreeMap<String, Vec<u8>>) -> Result<GitOid> {
        let mut entries = BTreeMap::new();
        let mut directories: BTreeMap<String, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
        for (path, bytes) in files {
            if let Some((directory, suffix)) = path.split_once('/') {
                directories
                    .entry(directory.to_owned())
                    .or_default()
                    .insert(suffix.to_owned(), bytes.clone());
            } else {
                let blob = self.git(&["hash-object", "-w", "--stdin"], Some(bytes))?;
                entries.insert(
                    path.clone(),
                    format!("100644 blob {}\t{}\0", blob.trim(), path),
                );
            }
        }
        for (name, files) in directories {
            entries.insert(
                format!("{name}/"),
                format!("040000 tree {}\t{name}\0", self.tree(&files)?.as_str()),
            );
        }
        let input = entries.into_values().collect::<String>();
        GitOid::try_from(
            self.git(&["mktree", "-z"], Some(input.as_bytes()))?
                .trim()
                .to_owned(),
        )
    }
}
impl SourceControl for LocalGit {
    fn apply(&self, id: &Digest, change: &SourceChange) -> Result<SourceReceipt> {
        let reference = match change {
            SourceChange::Export { .. } => "refs/heads/main".to_owned(),
            SourceChange::Propose { .. } => format!("refs/heads/day2/{}", &id.as_str()[7..]),
        };
        let existing = self.reference(&reference)?;
        if existing.is_none()
            && let SourceChange::Propose { base, .. } = change
        {
            ensure!(
                self.reference("refs/heads/main")?.as_ref() == Some(base),
                "source_base_revision_conflict"
            );
        }
        let tree = self.tree(change.bundle().files())?;
        let message = format!("Day2 source {}\n", id.as_str());
        let mut args = vec!["commit-tree", tree.as_str()];
        if let SourceChange::Propose { base, .. } = change {
            args.extend(["-p", base.as_str()]);
        }
        let commit =
            GitOid::try_from(self.git(&args, Some(message.as_bytes()))?.trim().to_owned())?;
        match existing {
            Some(existing) => ensure!(existing == commit, "source_revision_conflict"),
            None => {
                // Verify the caller's base and create the proposal in one Git ref transaction.
                let verify = match change {
                    SourceChange::Export { .. } => String::new(),
                    SourceChange::Propose { base, .. } => {
                        format!("verify refs/heads/main {}\n", base.as_str())
                    }
                };
                let transaction = format!(
                    "start\n{verify}create {reference} {}\nprepare\ncommit\n",
                    commit.as_str()
                );
                if self
                    .git(&["update-ref", "--stdin"], Some(transaction.as_bytes()))
                    .is_err()
                {
                    match self.reference(&reference)? {
                        Some(current) => ensure!(current == commit, "source_revision_conflict"),
                        None => {
                            if let SourceChange::Propose { base, .. } = change {
                                ensure!(
                                    self.reference("refs/heads/main")?.as_ref() == Some(base),
                                    "source_base_revision_conflict"
                                );
                            }
                            anyhow::bail!("source_git_operation_failed");
                        }
                    }
                }
            }
        }
        Ok(SourceReceipt {
            commit,
            reference,
            source: change.bundle().digest()?,
        })
    }
    fn snapshot(&self, commit: &GitOid) -> Result<SourceSnapshot> {
        let listing = self.git_bytes(&["ls-tree", "-r", "-z", commit.as_str()], None)?;
        let mut files = BTreeMap::new();
        for entry in listing
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            ensure!(files.len() < 4096, "source file budget");
            let entry = std::str::from_utf8(entry)?;
            let (header, path) = entry.split_once('\t').context("git tree record")?;
            let mut parts = header.split(' ');
            ensure!(
                parts.next() == Some("100644") && parts.next() == Some("blob"),
                "source requires regular non-executable files"
            );
            let oid = GitOid::try_from(parts.next().context("git blob identity")?.to_owned())?;
            ensure!(parts.next().is_none(), "invalid git tree record");
            ensure!(
                files
                    .insert(
                        path.to_owned(),
                        self.git_bytes(&["cat-file", "blob", oid.as_str()], None)?
                    )
                    .is_none(),
                "duplicate source path"
            );
        }
        Ok(SourceSnapshot::from_files(commit.clone(), files)?)
    }
}

pub(crate) fn fixed_git() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "Day2 Platform")
        .env("GIT_AUTHOR_EMAIL", "platform@day2.invalid")
        .env("GIT_COMMITTER_NAME", "Day2 Platform")
        .env("GIT_COMMITTER_EMAIL", "platform@day2.invalid")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "gc.auto=0",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "core.fsync=all",
            "-c",
            "core.fsyncMethod=fsync",
        ]);
    command
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    let created = !path.exists();
    fs::create_dir_all(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_dir() && path.canonicalize()? == path,
        "operator directory must not contain symlinks"
    );
    #[cfg(unix)]
    if created {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
