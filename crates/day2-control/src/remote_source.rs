//! A company repository on a Git host, read at exact commits.
//!
//! People push to the host as usual; the control plane only reads. A build names
//! an exact commit, which is fetched once over HTTPS into a bare cache repository
//! the control plane owns, and every later read of that commit is served from the
//! cache. So a credential is needed only the first time a commit is seen, and a
//! build worker that snapshots an accepted commit never touches the network.
//!
//! Fetching goes through the same fixed Git runner as local sources: no user or
//! system configuration, no credential helpers, no prompts, no redirects, and no
//! transport but HTTPS to the configured URL. A credential travels as an
//! `Authorization` header scoped to that URL, set through Git's environment
//! configuration so it is never on a command line.
use crate::{
    Digest, GitOid,
    local_source::{LocalGit, SourceChange, SourceControl, SourceReceipt, fixed_git},
    source::{SecretRef, SecretResolver, SourceSnapshot},
};
use anyhow::{Result, bail, ensure};
use base64::Engine as _;
use std::{path::Path, process::Stdio};

pub struct RemoteGit {
    cache: LocalGit,
    url: String,
    protocol: &'static str,
    credential: Credential,
}

pub enum Credential {
    None,
    Secret {
        resolver: Box<dyn SecretResolver + Send + Sync>,
        reference: SecretRef,
    },
    /// The source declares a credential but this process was given no way to
    /// resolve it. Commits already in the cache can still be read.
    Unavailable,
}

impl RemoteGit {
    /// `url` must be the HTTPS URL the instance declares; see
    /// `SourceProvider::remote_url`.
    pub fn open(cache: &Path, owner: &Digest, url: String, credential: Credential) -> Result<Self> {
        ensure!(url.starts_with("https://"), "remote source requires https");
        Ok(Self {
            cache: LocalGit::open(cache, owner)?,
            url,
            protocol: "https",
            credential,
        })
    }

    /// Tests fetch from a local repository over the file transport.
    #[doc(hidden)]
    pub fn open_file_for_tests(cache: &Path, owner: &Digest, repository: &Path) -> Result<Self> {
        Ok(Self {
            cache: LocalGit::open(cache, owner)?,
            url: format!("file://{}", repository.display()),
            protocol: "file",
            credential: Credential::None,
        })
    }

    fn cached(&self, commit: &GitOid) -> bool {
        self.cache
            .git_bytes(&["cat-file", "-t", commit.as_str()], None)
            .is_ok_and(|kind| kind == b"commit\n")
    }

    fn fetch(&self, commit: &GitOid) -> Result<()> {
        let mut command = fixed_git();
        // Per-protocol settings take precedence over the runner's
        // `protocol.allow=never`, so exactly one transport is opened.
        command.args([
            "-c",
            &format!("protocol.{}.allow=always", self.protocol),
            "-c",
            "credential.helper=",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.lowSpeedLimit=1024",
            "-c",
            "http.lowSpeedTime=30",
            "-c",
            "fetch.recurseSubmodules=false",
        ]);
        match &self.credential {
            Credential::None => {}
            Credential::Secret {
                resolver,
                reference,
            } => {
                let token = resolver.resolve(reference)?;
                // Hosts accept a token as the Basic password under any user
                // name: Gitea, GitLab and GitHub alike.
                let basic = base64::engine::general_purpose::STANDARD
                    .encode(format!("day2:{}", token.expose()));
                command
                    .env("GIT_CONFIG_COUNT", "1")
                    .env("GIT_CONFIG_KEY_0", format!("http.{}.extraHeader", self.url))
                    .env(
                        "GIT_CONFIG_VALUE_0",
                        format!("Authorization: Basic {basic}"),
                    );
            }
            Credential::Unavailable => bail!("source_credential_unavailable"),
        }
        let status = command
            .arg("--git-dir")
            .arg(self.cache.repository())
            .args([
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--depth=1",
                &self.url,
                commit.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        ensure!(status.success(), "source_fetch_failed");
        ensure!(self.cached(commit), "source_commit_unavailable");
        Ok(())
    }
}

impl SourceControl for RemoteGit {
    fn apply(&self, _: &Digest, _: &SourceChange) -> Result<SourceReceipt> {
        bail!("source_provider_read_only")
    }
    fn snapshot(&self, commit: &GitOid) -> Result<SourceSnapshot> {
        if !self.cached(commit) {
            self.fetch(commit)?;
        }
        self.cache.snapshot(commit)
    }
}
