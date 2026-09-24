//! Bounded source acquisition and check publication. No Git execution, hooks,
//! archive extraction, ambient credentials, or automatic mutation retries.

use crate::{Digest, GitOid};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{
    blocking::{Client, Response},
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha1::{Digest as _, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{Read, Write},
    path::Path,
    time::Duration,
};
use url::Url;

pub const MAX_FILES: usize = 512;
pub const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_ENTRIES: usize = 1024;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHECKS: usize = 400;
pub const CHECK_NAME: &str = "day2 / verification";
const API_VERSION: &str = "2026-03-10";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    InvalidInput,
    Unauthorized,
    NotFound,
    RateLimited,
    Transient,
    Integrity,
    Unsupported,
    Limit,
    LocalIo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceError {
    pub class: FailureClass,
    pub code: &'static str,
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}
impl std::error::Error for SourceError {}
impl SourceError {
    fn new(class: FailureClass, code: &'static str) -> Self {
        Self { class, code }
    }
    pub fn retryable(&self) -> bool {
        matches!(
            self.class,
            FailureClass::RateLimited | FailureClass::Transient
        )
    }
}
type Result<T> = std::result::Result<T, SourceError>;
fn invalid(code: &'static str) -> SourceError {
    SourceError::new(FailureClass::InvalidInput, code)
}
fn integrity(code: &'static str) -> SourceError {
    SourceError::new(FailureClass::Integrity, code)
}
fn limit(code: &'static str) -> SourceError {
    SourceError::new(FailureClass::Limit, code)
}
fn local_io(_: std::io::Error) -> SourceError {
    SourceError::new(FailureClass::LocalIo, "source_local_io")
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef(String);
impl SecretRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for SecretRef {
    type Error = SourceError;
    fn try_from(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(invalid("invalid_secret_reference"));
        }
        Ok(Self(value))
    }
}
impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.0
    }
}

pub struct SecretValue(String);
impl SecretValue {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 8192 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid("invalid_secret_value"));
        }
        Ok(Self(value))
    }
}
impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}
pub trait SecretResolver {
    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue>;
    /// Pins provider configuration and logical-reference versions, never bytes.
    fn binding_revision(&self) -> Digest;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckBinding {
    pub app_id: u64,
    pub credential: SecretRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubBinding {
    pub owner: String,
    pub repository: String,
    pub repository_id: u64,
    #[serde(default)]
    pub subdirectory: Option<String>,
    #[serde(default)]
    pub credential: Option<SecretRef>,
    #[serde(default)]
    pub checks: Option<CheckBinding>,
}
impl GithubBinding {
    pub fn validate(&self) -> Result<()> {
        for value in [&self.owner, &self.repository] {
            if value.is_empty()
                || value.len() > 100
                || matches!(value.as_str(), "." | "..")
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                return Err(invalid("invalid_github_repository"));
            }
        }
        if self.repository_id == 0 || self.checks.as_ref().is_some_and(|check| check.app_id == 0) {
            return Err(invalid("invalid_github_identity"));
        }
        if let Some(path) = &self.subdirectory {
            validate_path(path)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEvidence {
    pub commit: GitOid,
    pub digest: Digest,
    pub files: usize,
    pub bytes: usize,
    pub repository_id: Option<u64>,
    pub tree: Option<GitOid>,
}

#[derive(Clone)]
pub struct SourceSnapshot {
    files: BTreeMap<String, Vec<u8>>,
    evidence: SourceEvidence,
}
impl fmt::Debug for SourceSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSnapshot")
            .field("evidence", &self.evidence)
            .finish()
    }
}
impl SourceSnapshot {
    pub fn from_files(commit: GitOid, files: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        if files.is_empty() || files.len() > MAX_FILES {
            return Err(limit("source_file_count"));
        }
        validate_paths(files.keys().map(String::as_str))?;
        let mut bytes = 0;
        let mut manifest = BTreeMap::new();
        for (path, content) in &files {
            if content.len() > MAX_FILE_BYTES {
                return Err(limit("source_file_bytes"));
            }
            bytes += content.len();
            if bytes > MAX_SOURCE_BYTES {
                return Err(limit("source_total_bytes"));
            }
            manifest.insert(path, (content.len(), Digest::new(content)));
        }
        let digest = Digest::of(&("day2-source-v1", manifest))
            .map_err(|_| integrity("source_manifest_encoding"))?;
        let evidence = SourceEvidence {
            commit,
            digest,
            files: files.len(),
            bytes,
            repository_id: None,
            tree: None,
        };
        Ok(Self { files, evidence })
    }
    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }
    pub fn commit(&self) -> &GitOid {
        &self.evidence.commit
    }
    pub fn digest(&self) -> &Digest {
        &self.evidence.digest
    }
    pub fn evidence(&self) -> &SourceEvidence {
        &self.evidence
    }

    /// The parent directory belongs to the trusted executor. The destination must
    /// be fresh; never merge into an existing checkout or follow source symlinks.
    pub fn materialize(&self, target: &Path) -> Result<()> {
        fs::create_dir(target).map_err(local_io)?;
        for (path, bytes) in &self.files {
            let destination = target.join(path);
            let parent = destination
                .parent()
                .ok_or_else(|| invalid("invalid_source_destination"))?;
            fs::create_dir_all(parent).map_err(local_io)?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(destination)
                .map_err(local_io)?
                .write_all(bytes)
                .map_err(local_io)?;
        }
        Ok(())
    }
}

fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 512 || path.split('/').count() > 16 {
        return Err(invalid("invalid_source_path"));
    }
    for part in path.split('/') {
        if part.is_empty()
            || part.len() > 100
            || matches!(part, "." | "..")
            || part.eq_ignore_ascii_case(".git")
            || part.ends_with('.')
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(invalid("invalid_source_path"));
        }
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(invalid("nonportable_source_path"));
        }
    }
    Ok(())
}

fn validate_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut spellings = BTreeMap::new();
    let mut files = BTreeSet::new();
    for path in paths {
        validate_path(path)?;
        if !files.insert(path) {
            return Err(integrity("duplicate_source_path"));
        }
        validate_spelling(path, &mut spellings)?;
    }
    for path in &files {
        let mut parent = *path;
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if files.contains(prefix) {
                return Err(invalid("source_file_directory_collision"));
            }
            parent = prefix;
        }
    }
    Ok(())
}

fn validate_spelling(path: &str, spellings: &mut BTreeMap<String, String>) -> Result<()> {
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        if spellings
            .insert(prefix.to_ascii_lowercase(), prefix.clone())
            .is_some_and(|previous| previous != prefix)
        {
            return Err(invalid("source_path_case_collision"));
        }
    }
    Ok(())
}

pub struct GithubSource {
    client: Client,
    endpoint: Url,
}
impl GithubSource {
    pub fn binding_revision(
        &self,
        binding: &GithubBinding,
        secrets: &dyn SecretResolver,
    ) -> Result<Digest> {
        binding.validate()?;
        Digest::of(&(
            "day2-github-binding-v1",
            self.endpoint.as_str(),
            API_VERSION,
            binding,
            secrets.binding_revision(),
        ))
        .map_err(|_| integrity("github_binding_encoding"))
    }
    pub fn public_api() -> Result<Self> {
        Self::new("https://api.github.com/")
    }
    /// Endpoint configuration is company-controlled. HTTP is allowed only on
    /// loopback for conformance fixtures; redirects never carry credentials.
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint = Url::parse(endpoint).map_err(|_| invalid("invalid_github_endpoint"))?;
        let loopback = endpoint.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if (endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback))
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(invalid("invalid_github_endpoint"));
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .user_agent("day2-control/0.1")
            .build()
            .map_err(|_| invalid("github_client_configuration"))?;
        Ok(Self { client, endpoint })
    }

    fn url(&self, binding: &GithubBinding, segments: &[&str]) -> Result<Url> {
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .map_err(|_| invalid("invalid_github_endpoint"))?
            .pop_if_empty()
            .extend(["repos", &binding.owner, &binding.repository])
            .extend(segments.iter().copied());
        Ok(url)
    }
    fn headers(
        &self,
        credential: Option<&SecretRef>,
        secrets: &dyn SecretResolver,
    ) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static(API_VERSION),
        );
        if let Some(reference) = credential {
            let token = secrets.resolve(reference)?;
            let mut value = HeaderValue::from_str(&format!("Bearer {}", token.0))
                .map_err(|_| invalid("invalid_secret_value"))?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }
        Ok(headers)
    }
    fn get<T: DeserializeOwned>(&self, url: Url, headers: &HeaderMap) -> Result<T> {
        let response = self
            .client
            .get(url)
            .headers(headers.clone())
            .send()
            .map_err(|_| SourceError::new(FailureClass::Transient, "github_read_transport"))?;
        if response.status().as_u16() != 200 {
            return Err(response_error(&response));
        }
        read_json(response)
    }
    fn repository(&self, binding: &GithubBinding, headers: &HeaderMap) -> Result<()> {
        binding.validate()?;
        let repository: Repository = self.get(self.url(binding, &[])?, headers)?;
        if repository.id != binding.repository_id
            || !repository
                .full_name
                .eq_ignore_ascii_case(&format!("{}/{}", binding.owner, binding.repository))
        {
            return Err(integrity("github_repository_identity_changed"));
        }
        Ok(())
    }
    fn tree(
        &self,
        binding: &GithubBinding,
        oid: &GitOid,
        recursive: bool,
        headers: &HeaderMap,
    ) -> Result<Tree> {
        let mut url = self.url(binding, &["git", "trees", oid.as_str()])?;
        if recursive {
            url.query_pairs_mut().append_pair("recursive", "1");
        }
        let tree: Tree = self.get(url, headers)?;
        if tree.sha != oid.as_str() {
            return Err(integrity("github_tree_identity_changed"));
        }
        if tree.truncated || tree.tree.len() > MAX_TREE_ENTRIES {
            return Err(limit("github_tree_incomplete_or_large"));
        }
        Ok(tree)
    }

    pub fn fetch(
        &self,
        binding: &GithubBinding,
        commit: &GitOid,
        secrets: &dyn SecretResolver,
    ) -> Result<SourceSnapshot> {
        binding.validate()?;
        let headers = self.headers(binding.credential.as_ref(), secrets)?;
        self.repository(binding, &headers)?;
        let resolved: Commit = self.get(
            self.url(binding, &["git", "commits", commit.as_str()])?,
            &headers,
        )?;
        if resolved.sha != commit.as_str() {
            return Err(integrity("github_commit_identity_changed"));
        }
        let mut tree = git_oid(resolved.tree.sha)?;
        if let Some(directory) = &binding.subdirectory {
            for component in directory.split('/') {
                let parent = self.tree(binding, &tree, false, &headers)?;
                let entries: Vec<_> = parent
                    .tree
                    .iter()
                    .filter(|entry| entry.path == component)
                    .collect();
                if entries.len() != 1 {
                    return Err(SourceError::new(
                        FailureClass::NotFound,
                        "github_source_directory_missing",
                    ));
                }
                let entry = entries[0];
                if entry.kind != "tree" || entry.mode != "040000" {
                    return Err(SourceError::new(
                        FailureClass::Unsupported,
                        "github_source_directory_not_tree",
                    ));
                }
                tree = git_oid(entry.sha.clone())?;
            }
        }
        let entries = self.tree(binding, &tree, true, &headers)?.tree;
        let mut paths = BTreeSet::new();
        let mut directories = BTreeSet::new();
        let mut spellings = BTreeMap::new();
        let mut files = Vec::new();
        let mut total = 0;
        for entry in entries {
            validate_path(&entry.path)?;
            validate_spelling(&entry.path, &mut spellings)?;
            if !paths.insert(entry.path.clone()) {
                return Err(integrity("duplicate_source_path"));
            }
            git_oid(entry.sha.clone())?;
            match (entry.kind.as_str(), entry.mode.as_str()) {
                ("tree", "040000") => {
                    directories.insert(entry.path);
                }
                ("blob", "100644") => {
                    let bytes = entry
                        .size
                        .ok_or_else(|| integrity("github_blob_size_missing"))?;
                    if bytes > MAX_FILE_BYTES as u64 {
                        return Err(limit("source_file_bytes"));
                    }
                    total += bytes;
                    if total > MAX_SOURCE_BYTES as u64 || files.len() >= MAX_FILES {
                        return Err(limit("source_total_budget"));
                    }
                    files.push(entry);
                }
                _ => {
                    return Err(SourceError::new(
                        FailureClass::Unsupported,
                        "github_unsupported_file_mode",
                    ));
                }
            }
        }
        for path in &paths {
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if !directories.contains(prefix) {
                    return Err(integrity("github_tree_parent_missing"));
                }
                parent = prefix;
            }
        }
        validate_paths(files.iter().map(|entry| entry.path.as_str()))?;
        let mut contents = BTreeMap::new();
        for entry in files {
            let blob: Blob =
                self.get(self.url(binding, &["git", "blobs", &entry.sha])?, &headers)?;
            if blob.sha != entry.sha || blob.encoding != "base64" || Some(blob.size) != entry.size {
                return Err(integrity("github_blob_metadata_changed"));
            }
            let encoded: Vec<u8> = blob
                .content
                .bytes()
                .filter(|byte| !matches!(*byte, b'\r' | b'\n'))
                .collect();
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| integrity("github_blob_encoding"))?;
            if bytes.len() as u64 != blob.size || git_blob_oid(&bytes) != entry.sha {
                return Err(integrity("github_blob_digest_mismatch"));
            }
            contents.insert(entry.path, bytes);
        }
        let mut snapshot = SourceSnapshot::from_files(commit.clone(), contents)?;
        snapshot.evidence.repository_id = Some(binding.repository_id);
        snapshot.evidence.tree = Some(tree);
        Ok(snapshot)
    }

    pub fn observe_check(
        &self,
        binding: &GithubBinding,
        publication: &CheckPublication,
        secrets: &dyn SecretResolver,
    ) -> Result<CheckObservation> {
        binding.validate()?;
        let check = binding.checks.as_ref().ok_or_else(|| {
            SourceError::new(FailureClass::Unsupported, "github_checks_not_bound")
        })?;
        let headers = self.headers(Some(&check.credential), secrets)?;
        self.repository(binding, &headers)?;
        self.observe_with_headers(binding, publication, &headers)
    }
    fn observe_with_headers(
        &self,
        binding: &GithubBinding,
        publication: &CheckPublication,
        headers: &HeaderMap,
    ) -> Result<CheckObservation> {
        let mut found = None;
        let mut seen = 0;
        let mut ids = BTreeSet::new();
        let mut total = None;
        for page in 1..=4 {
            let mut url = self.url(
                binding,
                &["commits", publication.commit.as_str(), "check-runs"],
            )?;
            url.query_pairs_mut()
                .append_pair("check_name", CHECK_NAME)
                .append_pair("filter", "all")
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let response: Checks = self.get(url, headers)?;
            if response.total_count > MAX_CHECKS || response.check_runs.len() > 100 {
                return Err(limit("github_check_scan_budget"));
            }
            if total
                .replace(response.total_count)
                .is_some_and(|previous| previous != response.total_count)
            {
                return Err(integrity("github_check_pagination_changed"));
            }
            let count = response.check_runs.len();
            for run in response.check_runs {
                if !ids.insert(run.id) {
                    return Err(integrity("github_check_pagination_changed"));
                }
                if run.external_id.as_deref() == Some(publication.effect_id.as_str()) {
                    let receipt = check_receipt(binding, publication, &run)?;
                    if found.replace(receipt).is_some() {
                        return Err(integrity("github_duplicate_effect_checks"));
                    }
                }
            }
            seen += count;
            if seen == response.total_count {
                return Ok(found.map_or(CheckObservation::Missing, CheckObservation::Found));
            }
            if count == 0 || seen > response.total_count {
                return Err(integrity("github_check_pagination_changed"));
            }
        }
        Err(limit("github_check_scan_budget"))
    }

    /// Call only under a durable, single-owner first-attempt fence. On Ambiguous,
    /// observe repeatedly; a missing observation never authorizes another POST.
    /// GitHub external_id is correlation, not a server-enforced idempotency key.
    pub fn publish_check_once(
        &self,
        binding: &GithubBinding,
        publication: &CheckPublication,
        secrets: &dyn SecretResolver,
    ) -> std::result::Result<CheckReceipt, CheckPublishError> {
        binding.validate().map_err(CheckPublishError::Rejected)?;
        let check = binding.checks.as_ref().ok_or_else(|| {
            CheckPublishError::Rejected(SourceError::new(
                FailureClass::Unsupported,
                "github_checks_not_bound",
            ))
        })?;
        let headers = self
            .headers(Some(&check.credential), secrets)
            .map_err(CheckPublishError::Rejected)?;
        self.repository(binding, &headers)
            .map_err(CheckPublishError::Rejected)?;
        if let CheckObservation::Found(receipt) = self
            .observe_with_headers(binding, publication, &headers)
            .map_err(CheckPublishError::Rejected)?
        {
            return Ok(receipt);
        }
        let url = self
            .url(binding, &["check-runs"])
            .map_err(CheckPublishError::Rejected)?;
        let response = self
            .client
            .post(url)
            .headers(headers)
            .json(&serde_json::json!({
                "name":CHECK_NAME,"head_sha":publication.commit,"external_id":publication.effect_id,
                "status":"completed","conclusion":publication.conclusion,
                "output":{"title":"Day2 verification","summary":publication.summary()}
            }))
            .send()
            .map_err(|_| CheckPublishError::Ambiguous("github_check_transport_ambiguous"))?;
        if response.status().as_u16() != 201 {
            if response.status().is_server_error()
                || response.status().is_success()
                || response.status().as_u16() == 408
            {
                return Err(CheckPublishError::Ambiguous(
                    "github_check_response_ambiguous",
                ));
            }
            return Err(CheckPublishError::Rejected(response_error(&response)));
        }
        let run = read_json(response)
            .map_err(|_| CheckPublishError::Ambiguous("github_check_receipt_ambiguous"))?;
        check_receipt(binding, publication, &run)
            .map_err(|_| CheckPublishError::Ambiguous("github_check_receipt_ambiguous"))
    }
}

fn git_oid(value: String) -> Result<GitOid> {
    value
        .try_into()
        .map_err(|_| integrity("github_invalid_object_id"))
}
fn git_blob_oid(bytes: &[u8]) -> String {
    let mut digest = Sha1::new();
    digest.update(format!("blob {}\0", bytes.len()));
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}
fn response_error(response: &Response) -> SourceError {
    let status = response.status().as_u16();
    if status == 429
        || (status == 403
            && (response.headers().get("retry-after").is_some()
                || response
                    .headers()
                    .get("x-ratelimit-remaining")
                    .is_some_and(|value| value == "0")))
    {
        return SourceError::new(FailureClass::RateLimited, "github_rate_limited");
    }
    match status {
        401 | 403 => SourceError::new(FailureClass::Unauthorized, "github_unauthorized"),
        404 => SourceError::new(FailureClass::NotFound, "github_not_found"),
        408 | 425 | 500..=599 => {
            SourceError::new(FailureClass::Transient, "github_temporarily_unavailable")
        }
        300..=399 => SourceError::new(FailureClass::Unsupported, "github_redirect_forbidden"),
        _ => SourceError::new(FailureClass::InvalidInput, "github_request_rejected"),
    }
}
fn read_json<T: DeserializeOwned>(response: Response) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_JSON_BYTES as u64)
    {
        return Err(limit("github_response_byte_budget"));
    }
    let mut body = Vec::new();
    response
        .take(MAX_JSON_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| SourceError::new(FailureClass::Transient, "github_read_transport"))?;
    if body.len() > MAX_JSON_BYTES {
        return Err(limit("github_response_byte_budget"));
    }
    serde_json::from_slice(&body).map_err(|_| integrity("github_invalid_response"))
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
    full_name: String,
}
#[derive(Deserialize)]
struct Commit {
    sha: String,
    tree: TreeIdentity,
}
#[derive(Deserialize)]
struct TreeIdentity {
    sha: String,
}
#[derive(Deserialize)]
struct Tree {
    sha: String,
    truncated: bool,
    tree: Vec<TreeEntry>,
}
#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
    size: Option<u64>,
}
#[derive(Deserialize)]
struct Blob {
    sha: String,
    encoding: String,
    content: String,
    size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    Success,
    Failure,
}
impl CheckConclusion {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPublication {
    pub commit: GitOid,
    pub effect_id: Digest,
    pub evidence: Digest,
    pub conclusion: CheckConclusion,
}
impl CheckPublication {
    pub fn summary(&self) -> String {
        format!("Verification evidence: {}", self.evidence.as_str())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReceipt {
    pub id: u64,
    pub publication: CheckPublication,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckObservation {
    Missing,
    Found(CheckReceipt),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckPublishError {
    Rejected(SourceError),
    Ambiguous(&'static str),
}
impl fmt::Display for CheckPublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(error) => error.fmt(formatter),
            Self::Ambiguous(code) => formatter.write_str(code),
        }
    }
}
impl std::error::Error for CheckPublishError {}
#[derive(Deserialize)]
struct Checks {
    total_count: usize,
    check_runs: Vec<CheckRun>,
}
#[derive(Deserialize)]
struct CheckRun {
    id: u64,
    name: String,
    head_sha: String,
    external_id: Option<String>,
    status: String,
    conclusion: Option<String>,
    output: CheckOutput,
    app: CheckApp,
}
#[derive(Deserialize)]
struct CheckOutput {
    title: Option<String>,
    summary: Option<String>,
}
#[derive(Deserialize)]
struct CheckApp {
    id: u64,
}
fn check_receipt(
    binding: &GithubBinding,
    publication: &CheckPublication,
    run: &CheckRun,
) -> Result<CheckReceipt> {
    if run.id == 0
        || run.name != CHECK_NAME
        || run.head_sha != publication.commit.as_str()
        || run.external_id.as_deref() != Some(publication.effect_id.as_str())
        || run.status != "completed"
        || run.conclusion.as_deref() != Some(publication.conclusion.as_str())
        || run.output.title.as_deref() != Some("Day2 verification")
        || run.output.summary.as_deref() != Some(publication.summary().as_str())
        || binding
            .checks
            .as_ref()
            .is_none_or(|binding| binding.app_id != run.app.id)
    {
        return Err(integrity("github_check_conflict"));
    }
    Ok(CheckReceipt {
        id: run.id,
        publication: publication.clone(),
    })
}
