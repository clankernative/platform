//! What a candidate session reaches outside itself from the deploy job, with
//! closed verbs: the instance's release state through `gcloud storage`, and the
//! build host through `gcloud compute ssh` and `scp` over IAP as the apply
//! identity. The argument lists are pure functions, pinned by tests; tests also
//! run the adapter against a stub `gcloud`, and substitute fakes above it.
use super::Mode;
use crate::maintenance::{self, Sink, Supervision};
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

/// The instance's release state: reads at an exact generation, writes only
/// while the generation is the one read, and replaced logs.
pub trait Store {
    /// The object at `uri` and its generation, or nothing when it is absent.
    /// Any failure other than absence is a refusal, never absence.
    fn read(&mut self, uri: &str) -> Result<Option<(Vec<u8>, String)>>;
    /// Write `file` to `uri` only while its generation is still `generation`
    /// (`0`: only if absent).
    fn write(&mut self, file: &Path, uri: &str, generation: &str) -> Result<()>;
    /// Write `file` to `uri`, replacing what is there: a build log or a reuse
    /// proof.
    fn put(&mut self, file: &Path, uri: &str) -> Result<()>;
}

/// The build host and how to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub project: String,
    pub zone: String,
    /// The apply identity: OS Login derives the SSH user from gcloud's
    /// account, not from the runner's metadata account.
    pub account: String,
}

/// What a remote CLI run returned: its exit code (`None` when killed), its
/// stdout and its stderr, bounded. The stderr is for the job log only.
#[derive(Debug)]
pub struct Remote {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The build host, by private job directory: create it, copy files in and
/// out, run one native candidate command in it as root, remove it.
pub trait BuildHost {
    fn create(&mut self, target: &Target, remote: &str) -> Result<()>;
    fn upload(&mut self, target: &Target, files: &[PathBuf], destination: &str) -> Result<()>;
    fn run(
        &mut self,
        target: &Target,
        remote: &str,
        mode: Mode,
        timeout: Duration,
    ) -> Result<Remote>;
    fn download(&mut self, target: &Target, sources: &[String], destination: &Path) -> Result<()>;
    fn remove(&mut self, target: &Target, remote: &str) -> Result<()>;
}

/// A private job directory on the build host: `/tmp/day2-build-<32 hex>` or
/// `/tmp/day2-sdk-probe-<32 hex>`. Nothing else is ever put in a remote
/// command line.
pub fn remote_directory(value: &str) -> bool {
    ["/tmp/day2-build-", "/tmp/day2-sdk-probe-"]
        .iter()
        .any(|prefix| {
            value
                .strip_prefix(prefix)
                .is_some_and(|hex| crate::instance_source::lower_hex(hex, 32))
        })
}

/// What scp may read or write on the build host: a job directory with a final
/// slash, its `cli/` directory, or its result or build log.
pub fn remote_path(value: &str) -> bool {
    let Some((index, _)) = value.match_indices('/').nth(2) else {
        return false;
    };
    let (directory, rest) = (&value[..index], &value[index + 1..]);
    remote_directory(directory)
        && (rest.is_empty() || rest == "cli/" || matches!(rest, "result.json" | "build.log"))
}

/// The last 2000 characters of a tool's stderr.
pub fn tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let characters: Vec<char> = text.trim().chars().collect();
    characters[characters.len().saturating_sub(2000)..]
        .iter()
        .collect()
}

/// Whether gcloud reported an object absent: a word `404`, `does not exist` or
/// `No URLs matched`.
pub fn absent(stderr: &str) -> bool {
    let status = stderr.match_indices("404").any(|(index, _)| {
        let word = |c: char| c.is_alphanumeric() || c == '_';
        stderr[..index].chars().next_back().is_none_or(|c| !word(c))
            && stderr[index + 3..].chars().next().is_none_or(|c| !word(c))
    });
    status || stderr.contains("does not exist") || stderr.contains("No URLs matched")
}

fn strings<const N: usize>(values: [&str; N]) -> Vec<OsString> {
    values.map(OsString::from).to_vec()
}

/// `gcloud storage objects describe <uri> --format=value(generation)`.
pub fn describe_args(uri: &str) -> Vec<OsString> {
    strings([
        "storage",
        "objects",
        "describe",
        uri,
        "--format=value(generation)",
    ])
}

/// `gcloud storage cat <uri>#<generation>`.
pub fn cat_args(uri: &str, generation: &str) -> Vec<OsString> {
    strings(["storage", "cat", &format!("{uri}#{generation}")])
}

/// `gcloud storage cp <file> <uri> --if-generation-match=<generation>`.
pub fn write_args(file: &Path, uri: &str, generation: &str) -> Vec<OsString> {
    vec![
        "storage".into(),
        "cp".into(),
        file.into(),
        uri.into(),
        format!("--if-generation-match={generation}").into(),
    ]
}

/// `gcloud storage cp <file> <uri>`.
pub fn put_args(file: &Path, uri: &str) -> Vec<OsString> {
    vec!["storage".into(), "cp".into(), file.into(), uri.into()]
}

/// `gcloud compute ssh <host> ... --command=<command>`, through IAP as the
/// apply identity.
pub fn ssh_args(target: &Target, command: &str) -> Vec<OsString> {
    strings([
        "compute",
        "ssh",
        &target.host,
        &format!("--project={}", target.project),
        &format!("--zone={}", target.zone),
        &format!("--account={}", target.account),
        "--tunnel-through-iap",
        "--quiet",
        &format!("--command={command}"),
    ])
}

fn scp_args(target: &Target) -> Vec<OsString> {
    strings([
        "compute",
        "scp",
        &format!("--project={}", target.project),
        &format!("--zone={}", target.zone),
        &format!("--account={}", target.account),
        "--tunnel-through-iap",
        "--quiet",
        "--compress",
    ])
}

/// `gcloud compute scp ... <files> <host>:<destination>`.
pub fn upload_args(target: &Target, files: &[PathBuf], destination: &str) -> Vec<OsString> {
    let mut args = scp_args(target);
    args.extend(files.iter().map(OsString::from));
    args.push(format!("{}:{destination}", target.host).into());
    args
}

/// `gcloud compute scp ... <host>:<source>... <destination>`.
pub fn download_args(target: &Target, sources: &[String], destination: &Path) -> Vec<OsString> {
    let mut args = scp_args(target);
    args.extend(
        sources
            .iter()
            .map(|source| OsString::from(format!("{}:{source}", target.host))),
    );
    args.push(destination.into());
    args
}

/// The remote commands, for a validated job directory only.
pub fn create_command(remote: &str) -> String {
    format!("install -d -m 0700 {remote} {remote}/cli")
}

pub fn run_command(remote: &str, mode: Mode) -> String {
    format!(
        "sudo {remote}/cli/day2 instance candidate {} {remote} --agent",
        mode.name()
    )
}

pub fn remove_command(remote: &str) -> String {
    format!("sudo rm -rf -- {remote}")
}

/// `gcloud storage` and `gcloud compute ssh|scp`, with the job's ambient
/// (federated apply identity) credentials. Each runs in its own process group,
/// killed whole at its deadline so no ssh or IAP helper outlives it. A failed
/// command's stderr goes to the job log; errors carry only what failed and its
/// exit status.
pub struct Gcloud {
    /// The executable, else `gcloud` from `PATH`.
    program: Option<PathBuf>,
}

impl Gcloud {
    pub fn native() -> Self {
        Self { program: None }
    }

    pub fn at(program: PathBuf) -> Self {
        Self {
            program: Some(program),
        }
    }

    fn gcloud(&self, args: Vec<OsString>, timeout: Duration) -> Result<maintenance::Finished> {
        let mut command = maintenance::tool("gcloud", self.program.as_deref())?;
        command.args(args);
        maintenance::supervise(
            &mut command,
            Supervision {
                stdin: None,
                timeout,
                interrupted: None,
                sink: Sink::Capture,
                group: true,
            },
        )
        .map_err(|error| {
            if error.to_string() == "timed out" {
                anyhow::anyhow!("gcloud timed out after {} s", timeout.as_secs())
            } else {
                error.context("run gcloud")
            }
        })
    }

    fn checked(&self, args: Vec<OsString>, timeout: Duration, what: &str) -> Result<Vec<u8>> {
        let finished = self.gcloud(args, timeout)?;
        if !finished.status.success() {
            log_tail(what, &finished.stderr);
            bail!("{what} failed ({})", exit(finished.status.code()));
        }
        Ok(finished.stdout)
    }
}

/// A failed command's stderr, to the job's stderr (the job log), line by line.
pub fn log_tail(what: &str, stderr: &[u8]) {
    for line in tail(stderr).lines() {
        eprintln!("{what}: {line}");
    }
}

/// An exit status as a failure message names it.
pub fn exit(code: Option<i32>) -> String {
    code.map_or_else(|| "killed".to_owned(), |code| format!("exit {code}"))
}

impl Store for Gcloud {
    fn read(&mut self, uri: &str) -> Result<Option<(Vec<u8>, String)>> {
        let described = self.gcloud(describe_args(uri), Duration::from_secs(120))?;
        if !described.status.success() {
            if absent(&String::from_utf8_lossy(&described.stderr)) {
                return Ok(None);
            }
            log_tail("read private release state", &described.stderr);
            bail!(
                "cannot read private release state (authentication/network errors are not absence)"
            );
        }
        let generation = String::from_utf8(described.stdout)?.trim().to_owned();
        ensure!(
            !generation.is_empty()
                && generation.bytes().all(|b| b.is_ascii_digit())
                && generation != "0",
            "invalid release state generation"
        );
        let bytes = self.checked(
            cat_args(uri, &generation),
            Duration::from_secs(300),
            "read private release state",
        )?;
        Ok(Some((bytes, generation)))
    }

    fn write(&mut self, file: &Path, uri: &str, generation: &str) -> Result<()> {
        ensure!(
            !generation.is_empty() && generation.bytes().all(|b| b.is_ascii_digit()),
            "release generation required"
        );
        self.checked(
            write_args(file, uri, generation),
            Duration::from_secs(300),
            "write private release state",
        )?;
        Ok(())
    }

    fn put(&mut self, file: &Path, uri: &str) -> Result<()> {
        self.checked(
            put_args(file, uri),
            Duration::from_secs(300),
            "write private build evidence",
        )?;
        Ok(())
    }
}

impl BuildHost for Gcloud {
    fn create(&mut self, target: &Target, remote: &str) -> Result<()> {
        ensure!(remote_directory(remote), "invalid build host job directory");
        self.checked(
            ssh_args(target, &create_command(remote)),
            Duration::from_secs(120),
            "create the build host job directory",
        )?;
        Ok(())
    }

    fn upload(&mut self, target: &Target, files: &[PathBuf], destination: &str) -> Result<()> {
        ensure!(
            remote_path(destination) && destination.ends_with('/'),
            "invalid build host destination"
        );
        self.checked(
            upload_args(target, files, destination),
            Duration::from_secs(1800),
            "copy to the build host",
        )?;
        Ok(())
    }

    fn run(
        &mut self,
        target: &Target,
        remote: &str,
        mode: Mode,
        timeout: Duration,
    ) -> Result<Remote> {
        ensure!(
            remote_directory(remote) && mode.native(),
            "invalid build host command"
        );
        let finished = self.gcloud(ssh_args(target, &run_command(remote, mode)), timeout)?;
        Ok(Remote {
            code: finished.status.code(),
            stdout: finished.stdout,
            stderr: finished.stderr,
        })
    }

    fn download(&mut self, target: &Target, sources: &[String], destination: &Path) -> Result<()> {
        ensure!(
            sources.iter().all(|source| remote_path(source)),
            "invalid build host source"
        );
        self.checked(
            download_args(target, sources, destination),
            Duration::from_secs(600),
            "copy from the build host",
        )?;
        Ok(())
    }

    fn remove(&mut self, target: &Target, remote: &str) -> Result<()> {
        ensure!(remote_directory(remote), "invalid build host job directory");
        self.checked(
            ssh_args(target, &remove_command(remote)),
            Duration::from_secs(120),
            "remove the build host job directory",
        )?;
        Ok(())
    }
}

/// Write `bytes` to a new private file (0600), synced. If writing or syncing
/// fails, the partial file this call created is removed; an existing path is
/// refused by the exclusive create and never touched.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let error = anyhow::Error::from(error).context(format!("write {}", path.display()));
        return Err(match std::fs::remove_file(path) {
            Ok(()) => error,
            Err(_) => error.context(format!(
                "the partial file {} could not be removed",
                path.display()
            )),
        });
    }
    Ok(())
}
