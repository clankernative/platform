//! Qualified SDK releases in an instance's state bucket, for `day2 instance
//! release publish` and `day2 instance release fetch`. The CLI renders the
//! request from day2.json (the derived state bucket and the project's registry)
//! and InstanceRelease.roc chooses the step order; this adapter validates the
//! request and refuses any step out of order.
//!
//! Byte for byte what the instance's Python publisher and consumer did, so
//! releases and caches written by either serve the other:
//! - Objects live at `gs://<project>-tofu-state/day2/platform-releases/sha256/<hex>`
//!   and are created only if absent. An object that already exists is accepted
//!   only after a download of its exact generation matches the digest. The
//!   manifest is published last, so an incomplete publication never has a
//!   selectable release, and its bytes are `Release::encode`.
//! - The local cache is `$DAY2_RELEASE_CACHE`, else
//!   `~/.cache/day2-platform-releases`: blobs at `<hex>` (0444), an operator at
//!   `<hex>.operator/` (CLI executables 0555, other files 0444), each key
//!   guarded by a flock on `<key>.lock` (0600), with temporary directories
//!   inside the root. Every hit is verified again, file by file. Instance CI
//!   images bake an operator at
//!   `/opt/day2-platform-releases/<hex>.operator/cli/day2`.
//!
//! The approved manifest digest is the trust input; nothing here builds the
//! platform or runs a qualification.
use anyhow::{Context, Result, bail, ensure};
use day2::sdk_release::{
    self, BlobIdentity, DISTRIBUTION_LIMIT, Distribution, EVIDENCE_LIMIT, Evidence, FILE_LIMIT,
    Image, MANIFEST_LIMIT, OPERATOR_FILES, PROFILE, Release, TARGET,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Where a release's blobs live in the instance's state bucket.
pub const OBJECTS: &str = "day2/platform-releases/sha256";

/// The cache under `$HOME` when `DAY2_RELEASE_CACHE` is unset.
pub const DEFAULT_CACHE: &str = ".cache/day2-platform-releases";

const REQUEST_LIMIT: u64 = 65_536;

/// The blobs a publication uploads before its manifest, in upload order.
pub const PUBLISHED: [&str; 4] = ["native", "strict", "distribution", "operator"];

/// The blobs a fetch reads, each bound by the one before it.
pub const FETCHED: [&str; 4] = ["manifest", "distribution", "native", "strict"];

/// What a session may do: publish writes create-only objects and a new manifest
/// file; fetch only reads objects and writes the local cache.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Publish,
    Fetch,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Fetch => "fetch",
        }
    }
}

/// The CLI's rendered request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub mode: Mode,
    /// The instance's derived OpenTofu state bucket, `<project>-tofu-state`.
    pub bucket: String,
    /// The project's Artifact Registry, `<region>-docker.pkg.dev/<project>`.
    pub registry: String,
    /// Publish only: the operator's publication request.
    pub publication: Option<PathBuf>,
    /// Publish only: the new manifest file.
    pub output: Option<PathBuf>,
    /// Fetch only: the approved manifest.
    pub reference: Option<BlobIdentity>,
}

/// What an operator publishes: the qualified images and the local files of the
/// distribution, operator archive and evidence. Relative paths are read from the
/// current directory.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    profile: String,
    platform_commit: String,
    runtime: Image,
    tooling: Image,
    distribution: PathBuf,
    operator: PathBuf,
    native: PathBuf,
    strict: PathBuf,
}

fn project(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The request's derived names belong to one project, and its fields to its mode.
pub fn validate(request: &Request) -> Result<()> {
    let bucket_project = request
        .bucket
        .strip_suffix("-tofu-state")
        .filter(|name| project(name))
        .context("the release bucket must be the instance's <project>-tofu-state")?;
    let (region, registry_project) = request
        .registry
        .split_once("-docker.pkg.dev/")
        .context("the release registry must be the instance's <region>-docker.pkg.dev/<project>")?;
    ensure!(
        !region.is_empty()
            && region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && registry_project == bucket_project,
        "the release registry and bucket must be the instance project's"
    );
    match (
        request.mode,
        &request.publication,
        &request.output,
        &request.reference,
    ) {
        (Mode::Publish, Some(_), Some(_), None) => Ok(()),
        (Mode::Fetch, None, None, Some(reference)) => {
            reference.check(MANIFEST_LIMIT)?;
            Ok(())
        }
        (Mode::Publish, ..) => bail!("a publication names its request and new manifest file only"),
        (Mode::Fetch, ..) => bail!("a fetch names its approved manifest only"),
    }
}

/// Whether an object create failed only because the object already exists: one
/// of gcloud's `ERROR:` lines reports HTTP 412, `PreconditionFailed` or
/// `conditionNotMet`, or says a precondition was not met. gcloud reports it as
/// `ERROR: (gcloud.storage.cp) HTTPError 412: At least one of the pre-conditions
/// you specified did not hold.` Nothing outside those lines counts, and a 412
/// inside a path or name (`acme-412-state`, `/builds/412/`) is not a status.
pub fn precondition_failed(message: &str) -> bool {
    message
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("ERROR:"))
        .any(|line| {
            let lower = line.to_ascii_lowercase();
            let status = lower.match_indices("412").any(|(index, _)| {
                lower[..index]
                    .chars()
                    .next_back()
                    .is_none_or(|c| c == ' ' || c == '(')
                    && lower[index + 3..]
                        .chars()
                        .next()
                        .is_none_or(|c| matches!(c, ' ' | ':' | ')' | ','))
            });
            let not_met = lower
                .find("precondition")
                .is_some_and(|start| lower[start..].contains("not met"));
            status
                || lower.contains("preconditionfailed")
                || lower.contains("conditionnotmet")
                || not_met
        })
}

/// What an object create did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Created {
    New,
    /// The object already existed; its bytes still need verifying.
    Existing,
}

/// The external tools a release uses, with closed verbs: `gcloud storage` for
/// objects and `docker` for images. Tests substitute fakes.
pub trait Tools {
    /// `gcloud storage objects describe <uri> --format=json(size,generation)`.
    fn describe(&mut self, uri: &str) -> Result<String>;
    /// `gcloud storage cp <uri>#<generation> <destination>`.
    fn download(&mut self, uri: &str, generation: &str, destination: &Path) -> Result<()>;
    /// `gcloud storage cp <source> <uri> --if-generation-match=0`.
    fn create(&mut self, source: &Path, uri: &str) -> Result<Created>;
    /// `docker pull --platform=linux/amd64 <image>`.
    fn pull(&mut self, image: &str) -> Result<()>;
    /// `docker image inspect --format {{.Id}} <image>`, trimmed.
    fn image_id(&mut self, image: &str) -> Result<String>;
}

pub fn describe_args(uri: &str) -> Vec<OsString> {
    [
        "storage",
        "objects",
        "describe",
        uri,
        "--format=json(size,generation)",
    ]
    .map(OsString::from)
    .to_vec()
}

pub fn download_args(uri: &str, generation: &str, destination: &Path) -> Vec<OsString> {
    vec![
        "storage".into(),
        "cp".into(),
        format!("{uri}#{generation}").into(),
        destination.into(),
    ]
}

pub fn create_args(source: &Path, uri: &str) -> Vec<OsString> {
    vec![
        "storage".into(),
        "cp".into(),
        source.into(),
        uri.into(),
        "--if-generation-match=0".into(),
    ]
}

pub fn pull_args(image: &str) -> Vec<OsString> {
    ["pull", "--platform=linux/amd64", image]
        .map(OsString::from)
        .to_vec()
}

pub fn inspect_args(image: &str) -> Vec<OsString> {
    ["image", "inspect", "--format", "{{.Id}}", image]
        .map(OsString::from)
        .to_vec()
}

/// gcloud and docker from `PATH`, bounded by the deadlines the instance
/// publisher used. They keep the operator's or CI's ambient credentials.
pub struct Native;

impl Native {
    fn run(&self, program: &str, args: Vec<OsString>, seconds: u64) -> Result<String> {
        let mut command = Command::new(crate::maintenance::on_path(program)?);
        command.args(args);
        crate::maintenance::bounded(&mut command, None, Duration::from_secs(seconds), None)
    }
}

impl Tools for Native {
    fn describe(&mut self, uri: &str) -> Result<String> {
        self.run("gcloud", describe_args(uri), 120)
            .with_context(|| format!("describe {uri}"))
    }

    fn download(&mut self, uri: &str, generation: &str, destination: &Path) -> Result<()> {
        self.run("gcloud", download_args(uri, generation, destination), 300)
            .with_context(|| format!("download {uri}#{generation}"))?;
        Ok(())
    }

    fn create(&mut self, source: &Path, uri: &str) -> Result<Created> {
        match self.run("gcloud", create_args(source, uri), 300) {
            Ok(_) => Ok(Created::New),
            Err(error) if precondition_failed(&format!("{error:#}")) => Ok(Created::Existing),
            Err(error) => Err(error
                .context(format!("publish {uri}"))
                .context("release publication failed; existing bytes were not replaced")),
        }
    }

    fn pull(&mut self, image: &str) -> Result<()> {
        self.run("docker", pull_args(image), 600)
            .with_context(|| format!("pull {image}"))?;
        Ok(())
    }

    fn image_id(&mut self, image: &str) -> Result<String> {
        Ok(self
            .run("docker", inspect_args(image), 120)
            .with_context(|| format!("inspect {image}"))?
            .trim()
            .to_owned())
    }
}

/// `DAY2_RELEASE_CACHE`, else `~/.cache/day2-platform-releases`.
pub fn cache_root() -> Result<PathBuf> {
    match std::env::var_os("DAY2_RELEASE_CACHE") {
        Some(value) => {
            ensure!(
                !value.is_empty(),
                "DAY2_RELEASE_CACHE must name a directory"
            );
            Ok(PathBuf::from(value))
        }
        None => Ok(PathBuf::from(
            std::env::var_os("HOME").context("HOME is required for the release cache")?,
        )
        .join(DEFAULT_CACHE)),
    }
}

/// The local, digest-addressed release cache.
pub struct Cache {
    root: PathBuf,
    objects: String,
}

impl Cache {
    /// Open (creating it 0700 if needed) the cache at `root` for the objects
    /// under `objects` (`gs://<bucket>/day2/platform-releases/sha256`).
    pub fn open(root: &Path, objects: &str) -> Result<Self> {
        let root = std::path::absolute(root)?;
        if let Some(parent) = root.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::DirBuilder::new().mode(0o700).create(&root) {
            Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => {
                return Err(error).context("platform release cache");
            }
            _ => {}
        }
        ensure!(
            fs::symlink_metadata(&root)?.is_dir(),
            "invalid platform release cache: {}",
            root.display()
        );
        Ok(Self {
            root,
            objects: objects.to_owned(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The cached blob `expected`, verified again on a hit. On a miss, the
    /// object's size and generation are read first and exactly that generation
    /// is downloaded into the cache, verified, made read-only, synced and renamed
    /// in, and the rename is synced too.
    pub fn fetch(
        &self,
        expected: &BlobIdentity,
        limit: u64,
        tools: &mut dyn Tools,
    ) -> Result<PathBuf> {
        let key = expected.check(limit)?;
        let path = self.root.join(key);
        let _lock = sdk_release::lock(&self.root.join(format!("{key}.lock")))?;
        if fs::symlink_metadata(&path).is_ok() {
            ensure!(
                sdk_release::identity(&path, limit).ok().as_ref() == Some(expected),
                "cached release bytes changed: {}",
                path.display()
            );
            return Ok(path);
        }
        let uri = format!("{}/{key}", self.objects);
        let metadata: Value = day2::json::decode(tools.describe(&uri)?.as_bytes())?;
        let text = |value: &Value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        };
        let generation = text(&metadata["generation"]).filter(|generation| {
            generation.starts_with(|c: char| ('1'..='9').contains(&c))
                && generation.bytes().all(|b| b.is_ascii_digit())
        });
        let Some(generation) =
            generation.filter(|_| text(&metadata["size"]) == Some(expected.bytes.to_string()))
        else {
            bail!("published release size or generation mismatch: {uri}");
        };
        let directory = tempfile::Builder::new()
            .prefix("download-")
            .tempdir_in(&self.root)?;
        let pending = directory.path().join(key);
        tools.download(&uri, &generation, &pending)?;
        ensure!(
            sdk_release::identity(&pending, limit).ok().as_ref() == Some(expected),
            "published release digest mismatch: {uri}#{generation}"
        );
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o444))?;
        fs::File::open(&pending)?.sync_all()?;
        fs::rename(&pending, &path)?;
        sync_directory(&self.root)?;
        Ok(path)
    }

    /// The cached blob's bytes, read and checked again against `expected`.
    fn read(&self, expected: &BlobIdentity, limit: u64, tools: &mut dyn Tools) -> Result<Vec<u8>> {
        let path = self.fetch(expected, limit, tools)?;
        sdk_release::verify(&path, expected, limit).context("cached release bytes changed")
    }

    /// The release's operator CLI. Every operator file is verified on every
    /// call, so a baked or earlier extraction is used only while it is exactly
    /// the qualified bytes. A missing operator is extracted from the verified
    /// archive: exactly the fixed files, regular files only, each of its
    /// qualified size and digest; no archive metadata is kept.
    pub fn operator(
        &self,
        release: &Release,
        distribution: &Distribution,
        tools: &mut dyn Tools,
    ) -> Result<PathBuf> {
        let name = format!("{}.operator", release.operator.check(FILE_LIMIT)?);
        let root = self.root.join(&name);
        let _lock = sdk_release::lock(&self.root.join(format!("{name}.lock")))?;
        let linked = |path: &Path| {
            fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        };
        ensure!(!linked(&root), "invalid operator cache directory");
        if fs::symlink_metadata(&root).is_err() {
            let archive = self.fetch(&release.operator, FILE_LIMIT, tools)?;
            let directory = tempfile::Builder::new()
                .prefix("operator-")
                .tempdir_in(&self.root)?;
            let pending = directory.path().join("operator");
            fs::create_dir_all(pending.join("cli"))?;
            extract(&archive, &pending, distribution)?;
            fs::rename(&pending, &root)?;
            sync_directory(&self.root)?;
        }
        ensure!(
            !linked(&root) && !linked(&root.join("cli")) && !linked(&root.join("licenses")),
            "invalid operator cache directory"
        );
        for (file, expected) in &distribution.operator_files {
            ensure!(
                sdk_release::identity(&root.join(file), FILE_LIMIT)
                    .ok()
                    .as_ref()
                    == Some(expected),
                "cached operator executable changed: {file}"
            );
        }
        Ok(root.join("cli/day2"))
    }
}

/// Extract exactly the fixed operator files from a verified gzip tar archive.
pub fn extract(archive: &Path, pending: &Path, distribution: &Distribution) -> Result<()> {
    let mut entries =
        tar::Archive::new(flate2::read::MultiGzDecoder::new(fs::File::open(archive)?));
    let mut seen = BTreeSet::new();
    for entry in entries.entries()? {
        let mut entry = entry?;
        let name = String::from_utf8(entry.path_bytes().into_owned()).ok();
        let kind = entry.header().entry_type();
        let expected = name
            .as_deref()
            .filter(|name| OPERATOR_FILES.contains(name))
            .and_then(|name| distribution.operator_files.get(name));
        let (Some(name), Some(expected)) = (name, expected) else {
            bail!("unsafe operator archive entry");
        };
        ensure!(
            (kind.is_file() || kind == tar::EntryType::Continuous)
                && entry.size() == expected.bytes
                && seen.insert(name.clone()),
            "unsafe operator archive entry: {name}"
        );
        let path = pending.join(&name);
        fs::create_dir_all(path.parent().context("operator file directory")?)?;
        let mut destination = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        std::io::copy(&mut (&mut entry).take(expected.bytes), &mut destination)?;
        destination.sync_all()?;
        drop(destination);
        ensure!(
            sdk_release::identity(&path, FILE_LIMIT).ok().as_ref() == Some(expected),
            "operator executable differs from qualified bytes: {name}"
        );
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(sdk_release::operator_mode(&name)),
        )?;
    }
    ensure!(
        seen.len() == OPERATOR_FILES.len(),
        "incomplete operator archive"
    );
    Ok(())
}

/// Make a rename into the cache root durable.
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

/// Upload a file create-only as the object named by `expected`. The file is
/// hashed again immediately before the upload and after it, and must be
/// `expected` both times, so a file changed after preparation is never
/// uploaded. If the object already exists, an interrupted publication resumes
/// only after a download of the object's exact generation, into a fresh private
/// cache, matches `expected`.
pub fn publish(
    path: &Path,
    expected: &BlobIdentity,
    limit: u64,
    objects: &str,
    tools: &mut dyn Tools,
) -> Result<()> {
    let uri = format!("{objects}/{}", expected.check(limit)?);
    let unchanged = |stage: &str| -> Result<()> {
        ensure!(
            sdk_release::identity(path, limit).ok().as_ref() == Some(expected),
            "release output changed {stage} publication: {}",
            path.display()
        );
        Ok(())
    };
    unchanged("before")?;
    if tools.create(path, &uri)? == Created::Existing {
        let directory = tempfile::Builder::new()
            .prefix("verify-published-release-")
            .tempdir()?;
        Cache::open(directory.path(), objects)?
            .fetch(expected, limit, tools)
            .context("an existing release object differs from the bytes being published")?;
    }
    unchanged("during")
}

/// One publication input: its file, byte budget and identity when prepared.
struct Input {
    path: PathBuf,
    limit: u64,
    identity: BlobIdentity,
}

pub struct Publish {
    objects: String,
    release: Release,
    inputs: BTreeMap<&'static str, Input>,
    output: PathBuf,
    verified: BTreeSet<String>,
    /// How many of `PUBLISHED`, in order, are uploaded.
    published: usize,
}

pub struct Fetch {
    cache: Cache,
    registry: String,
    reference: BlobIdentity,
    release: Option<Release>,
    distribution: Option<Distribution>,
    native: Option<Value>,
    files: BTreeMap<&'static str, PathBuf>,
}

enum State {
    Publish(Box<Publish>),
    Fetch(Box<Fetch>),
}

pub struct Session {
    tools: Box<dyn Tools>,
    state: State,
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "{} budget", path.display());
    Ok(bytes)
}

impl Session {
    /// Validate the CLI's request for a session the host started in `mode`.
    /// A publication is validated completely here (identities, manifest,
    /// distribution and evidence) before anything is pulled or uploaded. A fetch
    /// opens `cache`, or the cache the environment names.
    pub fn prepare(
        raw: &Path,
        mode: Mode,
        tools: Box<dyn Tools>,
        cache: Option<PathBuf>,
    ) -> Result<Self> {
        let request: Request = day2::json::decode(&read_bounded(raw, REQUEST_LIMIT)?)?;
        ensure!(
            request.mode == mode,
            "the host started an instance release {} but the request is for an instance release {}",
            mode.name(),
            request.mode.name()
        );
        validate(&request)?;
        let objects = format!("gs://{}/{OBJECTS}", request.bucket);
        let state = match request.mode {
            Mode::Publish => State::Publish(Box::new(Publish::prepare(&request, objects)?)),
            Mode::Fetch => {
                let root = match cache {
                    Some(root) => root,
                    None => cache_root()?,
                };
                State::Fetch(Box::new(Fetch {
                    cache: Cache::open(&root, &objects)?,
                    registry: request.registry.clone(),
                    reference: request.reference.clone().context("approved manifest")?,
                    release: None,
                    distribution: None,
                    native: None,
                    files: BTreeMap::new(),
                }))
            }
        };
        Ok(Self { tools, state })
    }

    /// Publish: pull an image and require its ID to be the qualified one.
    pub fn image(&mut self, name: &str) -> Result<Value> {
        let State::Publish(publish) = &mut self.state else {
            bail!("only a publication verifies images");
        };
        let image = match name {
            "runtime" => publish.release.runtime.clone(),
            "tooling" => publish.release.tooling.clone(),
            _ => bail!("unknown release image {name}"),
        };
        ensure!(
            !publish.verified.contains(name),
            "the {name} image is verified once"
        );
        self.tools.pull(&image.image)?;
        let id = self.tools.image_id(&image.image)?;
        ensure!(
            id == image.config,
            "published image differs from qualified image config: {} is {id}, not {}",
            image.image,
            image.config
        );
        publish.verified.insert(name.to_owned());
        Ok(json!({"image": image.image, "config": image.config}))
    }

    /// Publish: upload one input create-only, after both images are verified.
    /// Fetch: read one blob into the cache and check it against what came before.
    pub fn blob(&mut self, name: &str) -> Result<Value> {
        match &mut self.state {
            State::Publish(publication) => {
                ensure!(
                    publication.verified.len() == 2,
                    "both images are verified before anything is published"
                );
                let expected = PUBLISHED.get(publication.published).copied();
                let Some(next) = expected.filter(|next| *next == name) else {
                    bail!(
                        "publication uploads {} next, not {name}",
                        expected.unwrap_or("the manifest")
                    );
                };
                let input = &publication.inputs[next];
                publish(
                    &input.path,
                    &input.identity,
                    input.limit,
                    &publication.objects,
                    self.tools.as_mut(),
                )?;
                publication.published += 1;
                Ok(
                    json!({"name": name, "digest": input.identity.digest, "bytes": input.identity.bytes}),
                )
            }
            State::Fetch(fetch) => fetch.blob(name, self.tools.as_mut()),
        }
    }

    /// Publish: write the manifest file create-only and publish it, last.
    pub fn manifest(&mut self) -> Result<Value> {
        let State::Publish(publish) = &mut self.state else {
            bail!("only a publication writes a manifest");
        };
        ensure!(
            publish.published == PUBLISHED.len(),
            "every blob is published before the manifest"
        );
        let bytes = publish.release.encode()?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&publish.output)
            .with_context(|| {
                format!(
                    "instance release publish requires a new manifest file: {}",
                    publish.output.display()
                )
            })?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        let reference = BlobIdentity::of(&bytes);
        self::publish(
            &publish.output,
            &reference,
            MANIFEST_LIMIT,
            &publish.objects,
            self.tools.as_mut(),
        )?;
        let files = Files {
            manifest: text(&publish.output)?.to_owned(),
            distribution: None,
            native: None,
            strict: None,
        };
        let receipt = Receipt::new(
            Mode::Publish,
            &reference,
            &publish.release,
            &publish.objects,
            files,
            None,
        )?;
        Ok(serde_json::to_value(receipt)?)
    }

    /// Fetch: the verified operator CLI, after the manifest, distribution and
    /// evidence are bound.
    pub fn operator(&mut self) -> Result<Value> {
        let State::Fetch(fetch) = &mut self.state else {
            bail!("only a fetch installs an operator");
        };
        ensure!(
            fetch.files.len() == FETCHED.len(),
            "the manifest, distribution and evidence are verified before the operator"
        );
        let (Some(release), Some(distribution)) = (&fetch.release, &fetch.distribution) else {
            bail!("the manifest and distribution are verified before the operator");
        };
        let cli = fetch
            .cache
            .operator(release, distribution, self.tools.as_mut())?;
        let cached = |name: &str| text(&fetch.files[name]).map(str::to_owned);
        let files = Files {
            manifest: cached("manifest")?,
            distribution: Some(cached("distribution")?),
            native: Some(cached("native")?),
            strict: Some(cached("strict")?),
        };
        let receipt = Receipt::new(
            Mode::Fetch,
            &fetch.reference,
            release,
            &fetch.cache.objects,
            files,
            Some((&fetch.cache.root, &cli)),
        )?;
        Ok(serde_json::to_value(receipt)?)
    }
}

/// What a release command reports: what the CLI prints, and the paths a caller
/// uses. The host owns this shape; the CLI decodes only it and passes it through
/// verbatim, and cli/fixtures/release-receipt.json pins it for both sides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: u32,
    pub mode: Mode,
    pub reference: BlobIdentity,
    pub platform_commit: String,
    pub profile: String,
    pub target: String,
    pub runtime_image: String,
    pub tooling_image: String,
    pub objects: String,
    pub files: Files,
    /// Fetch only: the cache root and the verified operator CLI.
    pub cache: Option<String>,
    pub cli: Option<String>,
}

/// The manifest file (the new file a publication wrote, or the cached blob a
/// fetch verified) and, for a fetch, the cached distribution and evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    pub manifest: String,
    pub distribution: Option<String>,
    pub native: Option<String>,
    pub strict: Option<String>,
}

impl Receipt {
    fn new(
        mode: Mode,
        reference: &BlobIdentity,
        release: &Release,
        objects: &str,
        files: Files,
        installed: Option<(&Path, &Path)>,
    ) -> Result<Self> {
        let (cache, cli) = match installed {
            Some((cache, cli)) => (Some(text(cache)?.to_owned()), Some(text(cli)?.to_owned())),
            None => (None, None),
        };
        Ok(Self {
            format: 1,
            mode,
            reference: reference.clone(),
            platform_commit: release.platform_commit.clone(),
            profile: release.profile.clone(),
            target: release.target.clone(),
            runtime_image: release.runtime.image.clone(),
            tooling_image: release.tooling.image.clone(),
            objects: objects.to_owned(),
            files,
            cache,
            cli,
        })
    }
}

/// A path the CLI reports, which must be UTF-8.
fn text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

impl Publish {
    fn prepare(request: &Request, objects: String) -> Result<Self> {
        let raw = request
            .publication
            .as_ref()
            .context("publication request")?;
        let output = std::path::absolute(request.output.as_ref().context("manifest file")?)?;
        // Refuse a reused manifest file before anything is pulled or uploaded;
        // the write is create-only too.
        ensure!(
            fs::symlink_metadata(&output).is_err(),
            "instance release publish requires a new manifest file: {}",
            output.display()
        );
        ensure!(
            output.parent().is_some_and(Path::is_dir),
            "the new manifest file's directory must exist: {}",
            output.display()
        );
        let bytes = read_bounded(raw, EVIDENCE_LIMIT)?;
        let value: Value = day2::json::decode(&bytes)?;
        ensure!(
            value.is_object() && value["profile"] == PROFILE,
            "explicit SDK release profile required: only {PROFILE} releases are published"
        );
        let publication: Publication =
            serde_json::from_value(value).context("invalid release publication request")?;
        let mut inputs = BTreeMap::new();
        for (name, path, limit) in [
            ("native", &publication.native, EVIDENCE_LIMIT),
            ("strict", &publication.strict, EVIDENCE_LIMIT),
            (
                "distribution",
                &publication.distribution,
                DISTRIBUTION_LIMIT,
            ),
            ("operator", &publication.operator, FILE_LIMIT),
        ] {
            let path = std::path::absolute(path)?;
            let identity = sdk_release::identity(&path, limit)
                .with_context(|| format!("the publication's {name}"))?;
            inputs.insert(
                name,
                Input {
                    path,
                    limit,
                    identity,
                },
            );
        }
        let release = Release {
            version: 1,
            platform_commit: publication.platform_commit,
            profile: publication.profile,
            target: TARGET.to_owned(),
            runtime: publication.runtime,
            tooling: publication.tooling,
            distribution: inputs["distribution"].identity.clone(),
            operator: inputs["operator"].identity.clone(),
            evidence: Evidence {
                native: inputs["native"].identity.clone(),
                strict: inputs["strict"].identity.clone(),
            },
        };
        release.validate()?;
        release.pinned_under(&request.registry)?;
        let read = |name: &str| {
            let input = &inputs[name];
            sdk_release::verify(&input.path, &input.identity, input.limit)
                .with_context(|| format!("the publication's {name} changed"))
        };
        let distribution: Distribution = day2::json::decode(&read("distribution")?)?;
        distribution.bind(&release)?;
        let native: Value = day2::json::decode_evidence(&read("native")?)?;
        let strict: Value = day2::json::decode_evidence(&read("strict")?)?;
        sdk_release::bind_evidence(&release, &distribution, &native, &strict)?;
        Ok(Self {
            objects,
            release,
            inputs,
            output,
            verified: BTreeSet::new(),
            published: 0,
        })
    }
}

/// A release's manifest and its native evidence in the cache, verified and
/// bound with its distribution and strict evidence exactly as a fetch binds
/// them, without installing its operator.
pub struct Verified {
    pub release: Release,
    pub manifest: PathBuf,
    pub native: PathBuf,
}

/// Read `reference`'s manifest, distribution and evidence through `cache` as a
/// fetch does, the manifest pinned under `registry`.
pub fn verified(
    cache: Cache,
    registry: &str,
    reference: &BlobIdentity,
    tools: &mut dyn Tools,
) -> Result<Verified> {
    let mut fetch = Fetch {
        cache,
        registry: registry.to_owned(),
        reference: reference.clone(),
        release: None,
        distribution: None,
        native: None,
        files: BTreeMap::new(),
    };
    for name in FETCHED {
        fetch.blob(name, tools)?;
    }
    Ok(Verified {
        release: fetch.release.context("manifest")?,
        manifest: fetch.files.remove("manifest").context("manifest")?,
        native: fetch.files.remove("native").context("native evidence")?,
    })
}

impl Fetch {
    /// Each blob in `FETCHED` order: the manifest (pinned in the instance's
    /// registry), then the distribution it names, then its evidence.
    fn blob(&mut self, name: &str, tools: &mut dyn Tools) -> Result<Value> {
        let expected = FETCHED.get(self.files.len()).copied();
        let Some(next) = expected.filter(|next| *next == name) else {
            bail!(
                "fetch reads {} next, not {name}",
                expected.unwrap_or("nothing more")
            );
        };
        let (identity, limit) = match (name, &self.release) {
            ("manifest", _) => (self.reference.clone(), MANIFEST_LIMIT),
            ("distribution", Some(release)) => (release.distribution.clone(), DISTRIBUTION_LIMIT),
            ("native", Some(release)) => (release.evidence.native.clone(), EVIDENCE_LIMIT),
            ("strict", Some(release)) => (release.evidence.strict.clone(), EVIDENCE_LIMIT),
            _ => bail!("the manifest is verified first"),
        };
        let bytes = self.cache.read(&identity, limit, tools)?;
        match name {
            "manifest" => {
                let release = Release::decode(&bytes)?;
                release.pinned_under(&self.registry)?;
                self.release = Some(release);
            }
            "distribution" => {
                let distribution: Distribution = day2::json::decode(&bytes)?;
                distribution.bind(self.release.as_ref().context("manifest")?)?;
                self.distribution = Some(distribution);
            }
            "native" => self.native = Some(day2::json::decode_evidence(&bytes)?),
            _ => {
                let strict: Value = day2::json::decode_evidence(&bytes)?;
                sdk_release::bind_evidence(
                    self.release.as_ref().context("manifest")?,
                    self.distribution.as_ref().context("distribution")?,
                    self.native.as_ref().context("native evidence")?,
                    &strict,
                )?;
            }
        }
        let path = self.cache.root.join(identity.check(limit)?);
        let reported = json!({"name": name, "digest": identity.digest, "bytes": identity.bytes,
            "path": text(&path)?});
        self.files.insert(next, path);
        Ok(reported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::{cell::RefCell, os::unix::fs::MetadataExt, rc::Rc};

    const REGISTRY: &str = "us-central1-docker.pkg.dev/exampleco-tools";
    const GOLDEN_MANIFEST: &[u8] =
        include_bytes!("../../day2/fixtures/sdk-release/manifest-cc689326.json");
    const GOLDEN_RECEIPT: &str = include_str!("../../../cli/fixtures/release-receipt.json");
    const BUCKET: &str = "exampleco-tools-tofu-state";
    const OBJECTS_URI: &str = "gs://exampleco-tools-tofu-state/day2/platform-releases/sha256";

    #[derive(Default)]
    struct World {
        objects: BTreeMap<String, (Vec<u8>, u64)>,
        images: BTreeMap<String, String>,
        calls: Vec<String>,
        denied: bool,
        /// Lock files to try while an object is described, and what each try found:
        /// (described key, lock file, whether another holder had it).
        probes: Vec<PathBuf>,
        held: Vec<(String, PathBuf, bool)>,
    }

    #[derive(Clone, Default)]
    struct Fake(Rc<RefCell<World>>);

    impl Fake {
        fn calls(&self) -> Vec<String> {
            self.0.borrow().calls.clone()
        }

        fn store(&self, bytes: &[u8]) -> BlobIdentity {
            let identity = BlobIdentity::of(bytes);
            let uri = format!("{OBJECTS_URI}/{}", identity.check(u64::MAX).unwrap());
            self.0.borrow_mut().objects.insert(uri, (bytes.to_vec(), 7));
            identity
        }

        fn replace(&self, identity: &BlobIdentity, bytes: &[u8]) {
            let uri = format!("{OBJECTS_URI}/{}", identity.check(u64::MAX).unwrap());
            self.0.borrow_mut().objects.insert(uri, (bytes.to_vec(), 7));
        }
    }

    impl Tools for Fake {
        fn describe(&mut self, uri: &str) -> Result<String> {
            let mut world = self.0.borrow_mut();
            let key = uri.rsplit('/').next().unwrap().to_owned();
            world.calls.push(format!("describe {key}"));
            for probe in world.probes.clone() {
                let held = fs::File::open(&probe).is_ok_and(|file| {
                    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
                });
                world.held.push((key.clone(), probe, held));
            }
            ensure!(!world.denied, "403 permission denied");
            let (bytes, generation) = world.objects.get(uri).context("404 not found")?;
            Ok(
                json!({"size": bytes.len().to_string(), "generation": generation.to_string()})
                    .to_string(),
            )
        }

        fn download(&mut self, uri: &str, generation: &str, destination: &Path) -> Result<()> {
            let mut world = self.0.borrow_mut();
            world.calls.push(format!(
                "download {}#{generation}",
                uri.rsplit('/').next().unwrap()
            ));
            let (bytes, current) = world.objects.get(uri).context("404 not found")?;
            ensure!(generation == current.to_string(), "412 generation");
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?
                .write_all(bytes)?;
            Ok(())
        }

        fn create(&mut self, source: &Path, uri: &str) -> Result<Created> {
            let mut world = self.0.borrow_mut();
            world
                .calls
                .push(format!("create {}", uri.rsplit('/').next().unwrap()));
            if world.objects.contains_key(uri) {
                return Ok(Created::Existing);
            }
            world.objects.insert(uri.to_owned(), (fs::read(source)?, 7));
            Ok(Created::New)
        }

        fn pull(&mut self, image: &str) -> Result<()> {
            self.0.borrow_mut().calls.push(format!("pull {image}"));
            Ok(())
        }

        fn image_id(&mut self, image: &str) -> Result<String> {
            let mut world = self.0.borrow_mut();
            world.calls.push(format!("inspect {image}"));
            world.images.get(image).cloned().context("no such image")
        }
    }

    fn files() -> BTreeMap<&'static str, Vec<u8>> {
        OPERATOR_FILES
            .iter()
            .map(|name| {
                let bytes = if name.ends_with(".json") {
                    b"{}".to_vec()
                } else {
                    format!("qualified native bytes of {name}").into_bytes()
                };
                (*name, bytes)
            })
            .collect()
    }

    fn archive(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (name, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o777);
            if !kind.is_file() {
                header.set_link_name("/outside").unwrap();
            }
            // Raw names, so a traversal reaches the extractor as written.
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn operator_archive() -> Vec<u8> {
        let files = files();
        let entries: Vec<_> = files
            .iter()
            .map(|(name, bytes)| (*name, tar::EntryType::Regular, bytes.as_slice()))
            .collect();
        archive(&entries)
    }

    /// A synthetic release in the fake bucket, whose evidence binds it.
    struct Fixture {
        release: Release,
        distribution: Distribution,
        native: Value,
        strict: Value,
        operator: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let digest = |label: &str| day2::digest(label.as_bytes());
        let operator = operator_archive();
        let distribution = Distribution {
            format: 1,
            target: TARGET.into(),
            inputs: digest("inputs"),
            workflow_sources: digest("workflows"),
            toolchain: digest("toolchain"),
            worker: BlobIdentity::of(b"!<arch>\nworker"),
            operator: BlobIdentity::of(&operator),
            operator_files: files()
                .iter()
                .map(|(name, bytes)| ((*name).to_owned(), BlobIdentity::of(bytes)))
                .collect(),
        };
        let raw_distribution = serde_json::to_vec_pretty(&distribution).unwrap();
        let (runtime, tooling) = (digest("runtime config"), digest("tooling config"));
        let native = json!({
            "format": 1, "status": "passed", "scope": PROFILE, "source_revision": "a".repeat(40),
            "runtime_image": runtime, "tooling_image": tooling,
            "workflow": distribution.workflow_sources, "toolchain": distribution.toolchain,
            "platform": digest("platform"), "platform_inventory": digest("inventory"),
            "artifact": digest("fixture app"), "environment": {"architecture": "x86_64"},
            "tooling_distribution": {
                "distribution": day2::digest(&raw_distribution),
                "operator": distribution.operator, "worker": distribution.worker,
            },
        });
        let raw_native = serde_json::to_vec(&native).unwrap();
        let strict = json!({
            "status": "strict-admission-passed", "qualification": false,
            "qualification_digest": day2::digest(&raw_native),
            "runtime_image": runtime, "tooling_image": tooling,
            "platform": native["platform"], "platform_inventory": native["platform_inventory"],
            "artifact": native["artifact"],
        });
        let release = Release {
            version: 1,
            platform_commit: "a".repeat(40),
            profile: PROFILE.into(),
            target: TARGET.into(),
            runtime: Image {
                image: format!("{REGISTRY}/home/day2-runtime@{runtime}"),
                config: runtime,
            },
            tooling: Image {
                image: format!("{REGISTRY}/home/day2-tooling@{tooling}"),
                config: tooling,
            },
            distribution: BlobIdentity::of(&raw_distribution),
            operator: BlobIdentity::of(&operator),
            evidence: Evidence {
                native: BlobIdentity::of(&raw_native),
                strict: BlobIdentity::of(&serde_json::to_vec(&strict).unwrap()),
            },
        };
        Fixture {
            release,
            distribution,
            native,
            strict,
            operator,
        }
    }

    impl Fixture {
        /// Publish every blob and the manifest into the fake bucket; returns the manifest reference.
        fn upload(&self, fake: &Fake) -> BlobIdentity {
            fake.store(&serde_json::to_vec_pretty(&self.distribution).unwrap());
            fake.store(&serde_json::to_vec(&self.native).unwrap());
            fake.store(&serde_json::to_vec(&self.strict).unwrap());
            fake.store(&self.operator);
            fake.store(&self.release.encode().unwrap())
        }

        /// The publication's local files and its request.
        fn publication(&self, directory: &Path) -> PathBuf {
            let write = |name: &str, bytes: &[u8]| {
                let path = directory.join(name);
                fs::write(&path, bytes).unwrap();
                path
            };
            let request = json!({
                "profile": PROFILE,
                "platform_commit": self.release.platform_commit,
                "runtime": self.release.runtime,
                "tooling": self.release.tooling,
                "distribution": write("distribution.json", &serde_json::to_vec_pretty(&self.distribution).unwrap()),
                "operator": write("operator.tar.gz", &self.operator),
                "native": write("native.json", &serde_json::to_vec(&self.native).unwrap()),
                "strict": write("strict.json", &serde_json::to_vec(&self.strict).unwrap()),
            });
            write("publication.json", &serde_json::to_vec(&request).unwrap())
        }
    }

    fn request_file(directory: &Path, request: &Value) -> PathBuf {
        let path = directory.join("request.json");
        fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
        path
    }

    fn fetch_session(directory: &Path, fake: &Fake, reference: &BlobIdentity) -> Result<Session> {
        let request = request_file(
            directory,
            &json!({"mode": "fetch", "bucket": BUCKET, "registry": REGISTRY,
                "publication": null, "output": null, "reference": reference}),
        );
        Session::prepare(
            &request,
            Mode::Fetch,
            Box::new(fake.clone()),
            Some(directory.join("cache")),
        )
    }

    /// Cache.load then Cache.operator, through the session's steps.
    fn fetch(directory: &Path, fake: &Fake, reference: &BlobIdentity) -> Result<Value> {
        let mut session = fetch_session(directory, fake, reference)?;
        for name in FETCHED {
            session.blob(name)?;
        }
        session.operator()
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn requests_name_one_projects_bucket_and_registry_and_their_modes_fields() {
        let reference = BlobIdentity::of(b"manifest");
        let fetch = Request {
            mode: Mode::Fetch,
            bucket: BUCKET.into(),
            registry: REGISTRY.into(),
            publication: None,
            output: None,
            reference: Some(reference.clone()),
        };
        validate(&fetch).unwrap();
        let publish = Request {
            mode: Mode::Publish,
            publication: Some("request.json".into()),
            output: Some("manifest.json".into()),
            reference: None,
            ..fetch.clone()
        };
        validate(&publish).unwrap();
        let refused = |change: &dyn Fn(&mut Request)| {
            let mut changed = fetch.clone();
            change(&mut changed);
            validate(&changed).is_err()
        };
        assert!(refused(&|r| r.bucket = "exampleco-tools-state".into()));
        assert!(refused(&|r| r.bucket = "Exampleco-tools-tofu-state".into()));
        assert!(refused(&|r| r.bucket = "x-tofu-state".into()));
        assert!(refused(
            &|r| r.registry = "us-central1-docker.pkg.dev/other-project".into()
        ));
        assert!(refused(
            &|r| r.registry = "us-central1-docker.pkg.dev/exampleco-tools/".into()
        ));
        assert!(refused(&|r| r.registry = "gcr.io/exampleco-tools".into()));
        assert!(refused(
            &|r| r.registry = "us-central1-docker.pkg.dev/exampleco-tools/day2".into()
        ));
        assert!(refused(&|r| r.reference = None));
        assert!(refused(&|r| r.output = Some("manifest.json".into())));
        assert!(refused(&|r| r.reference.as_mut().unwrap().bytes = 65_537));
        assert!(refused(
            &|r| r.reference.as_mut().unwrap().digest = "sha256:x".into()
        ));
        assert!(refused(&|r| r.mode = Mode::Publish));
        let mut changed = publish.clone();
        changed.reference = Some(reference);
        assert!(validate(&changed).is_err());
        changed = publish;
        changed.output = None;
        assert!(validate(&changed).is_err());
    }

    #[test]
    fn tools_run_the_exact_commands_the_instance_publisher_ran() {
        let strings = |args: Vec<OsString>| -> Vec<String> {
            args.into_iter()
                .map(|arg| arg.into_string().unwrap())
                .collect()
        };
        assert_eq!(
            strings(describe_args("gs://b/o")),
            [
                "storage",
                "objects",
                "describe",
                "gs://b/o",
                "--format=json(size,generation)"
            ]
        );
        assert_eq!(
            strings(download_args("gs://b/o", "7", Path::new("/c/d"))),
            ["storage", "cp", "gs://b/o#7", "/c/d"]
        );
        assert_eq!(
            strings(create_args(Path::new("/f"), "gs://b/o")),
            ["storage", "cp", "/f", "gs://b/o", "--if-generation-match=0"]
        );
        assert_eq!(
            strings(pull_args("r/i@sha256:x")),
            ["pull", "--platform=linux/amd64", "r/i@sha256:x"]
        );
        assert_eq!(
            strings(inspect_args("r/i@sha256:x")),
            ["image", "inspect", "--format", "{{.Id}}", "r/i@sha256:x"]
        );
        // As maintenance::bounded reports a failed command: stderr's tail, then the status.
        for refused in [
            "Copying file:///r/manifest.json to gs://b/o\nERROR: (gcloud.storage.cp) HTTPError 412: At least one of the pre-conditions you specified did not hold. (exit status: 1)",
            "ERROR: (gcloud.storage.cp) HTTPError 412: At least one of the pre-conditions you specified did not hold.",
            "  ERROR: PreconditionFailed",
            "ERROR: conditionNotMet",
            "ERROR: (gcloud.storage.cp) the precondition was not met",
        ] {
            assert!(precondition_failed(refused), "{refused}");
        }
        for failed in [
            "ERROR: (gcloud.storage.cp) HTTPError 403: caller does not have storage.objects.create access",
            // A path or project containing 412 is not a precondition, outside an ERROR line or in one.
            "Copying file:///builds/412 412/manifest.json to gs://acme-412-tofu-state/o\nERROR: (gcloud.storage.cp) HTTPError 403: denied (exit status: 1)",
            "ERROR: (gcloud.storage.cp) HTTPError 403: no access to gs://acme-412-tofu-state/day2",
            "ERROR: (gcloud.storage.cp) file:///builds/412/manifest.json: No such file or directory",
            "WARNING: HTTPError 412: retried\nERROR: (gcloud.storage.cp) HTTPError 503: unavailable",
            "precondition was not met",
            "HTTPError 4120",
            "",
        ] {
            assert!(!precondition_failed(failed), "{failed}");
        }
    }

    #[test]
    fn many_apps_fetch_shared_bytes_once_and_run_no_build_commands() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let mut cli = None;
        for _ in 0..20 {
            let receipt = fetch(directory.path(), &fake, &reference)?;
            let receipt: Receipt = serde_json::from_value(receipt)?;
            assert_eq!(receipt.platform_commit, fixture.release.platform_commit);
            assert_eq!(receipt.runtime_image, fixture.release.runtime.image);
            assert_eq!(receipt.tooling_image, fixture.release.tooling.image);
            let receipt = serde_json::to_value(receipt)?;
            let path = PathBuf::from(receipt["cli"].as_str().unwrap());
            assert!(path.is_file());
            assert_eq!(cli.get_or_insert(path.clone()), &path);
        }
        // Five immutable blobs, one metadata read and one generation-pinned download each.
        let calls = fake.calls();
        assert_eq!(calls.len(), 10, "{calls:?}");
        assert!(
            calls
                .iter()
                .all(|call| call.starts_with("describe ") || call.ends_with("#7"))
        );
        Ok(())
    }

    #[test]
    fn the_cache_layout_and_modes_match_the_baked_operator() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let receipt = fetch(directory.path(), &fake, &reference)?;
        let root = std::path::absolute(directory.path().join("cache"))?;
        let key = |identity: &BlobIdentity| identity.check(u64::MAX).unwrap().to_owned();
        let operator = root.join(format!("{}.operator", key(&fixture.release.operator)));
        assert_eq!(
            PathBuf::from(receipt["cli"].as_str().unwrap()),
            operator.join("cli/day2")
        );
        assert_eq!(PathBuf::from(receipt["cache"].as_str().unwrap()), root);
        // The receipt names each cached blob a caller reads next.
        for (name, identity) in [
            ("manifest", &reference),
            ("distribution", &fixture.release.distribution),
            ("native", &fixture.release.evidence.native),
            ("strict", &fixture.release.evidence.strict),
        ] {
            assert_eq!(
                PathBuf::from(receipt["files"][name].as_str().unwrap()),
                root.join(key(identity)),
                "{name}"
            );
        }
        assert_eq!(mode(&root), 0o700);
        let mut expected = BTreeSet::new();
        for identity in [
            &reference,
            &fixture.release.distribution,
            &fixture.release.evidence.native,
            &fixture.release.evidence.strict,
            &fixture.release.operator,
        ] {
            assert_eq!(mode(&root.join(key(identity))), 0o444);
            assert_eq!(mode(&root.join(format!("{}.lock", key(identity)))), 0o600);
            expected.insert(key(identity));
            expected.insert(format!("{}.lock", key(identity)));
        }
        let operator_name = format!("{}.operator", key(&fixture.release.operator));
        expected.insert(format!("{operator_name}.lock"));
        expected.insert(operator_name);
        // No temporary directory is left behind.
        let listed: BTreeSet<_> = fs::read_dir(&root)?
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(listed, expected);
        for (name, bytes) in files() {
            assert_eq!(fs::read(operator.join(name))?, bytes);
            assert_eq!(mode(&operator.join(name)), sdk_release::operator_mode(name));
        }
        assert_eq!(mode(&operator.join("cli/day2")), 0o555);
        assert_eq!(mode(&operator.join("cli/day2-workflows.json")), 0o444);
        assert_eq!(mode(&operator.join("licenses/LICENSE")), 0o444);
        Ok(())
    }

    #[test]
    fn altered_downloads_blobs_and_operator_files_are_refused_on_every_hit() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let original = fixture.release.encode()?;
        let mut altered = original.clone();
        *altered.last_mut().unwrap() = b' ';
        fake.replace(&reference, &altered);
        let error = fetch(directory.path(), &fake, &reference).unwrap_err();
        assert!(
            format!("{error:#}").contains("digest mismatch"),
            "{error:#}"
        );
        fake.replace(&reference, &original);
        let receipt = fetch(directory.path(), &fake, &reference)?;
        let cli = PathBuf::from(receipt["cli"].as_str().unwrap());
        // A tampered cached blob.
        let root = directory.path().join("cache");
        let native = root.join(fixture.release.evidence.native.check(u64::MAX)?);
        fs::set_permissions(&native, fs::Permissions::from_mode(0o644))?;
        fs::write(&native, b"{}")?;
        let error = fetch(directory.path(), &fake, &reference).unwrap_err();
        assert!(
            format!("{error:#}").contains("cached release bytes changed"),
            "{error:#}"
        );
        fs::write(&native, serde_json::to_vec(&fixture.native)?)?;
        fetch(directory.path(), &fake, &reference)?;
        // A tampered operator file.
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o755))?;
        fs::write(&cli, b"changed executable")?;
        let error = fetch(directory.path(), &fake, &reference).unwrap_err();
        assert!(
            format!("{error:#}").contains("cached operator executable changed"),
            "{error:#}"
        );
        // A linked operator directory.
        fs::write(&cli, files()["cli/day2"].as_slice())?;
        fetch(directory.path(), &fake, &reference)?;
        let operator = cli.parent().unwrap().parent().unwrap().to_owned();
        let moved = directory.path().join("moved");
        fs::rename(&operator, &moved)?;
        std::os::unix::fs::symlink(&moved, &operator)?;
        let error = fetch(directory.path(), &fake, &reference).unwrap_err();
        assert!(
            format!("{error:#}").contains("invalid operator cache directory"),
            "{error:#}"
        );
        assert!(fake.calls().iter().all(|call| !call.starts_with("create")));
        Ok(())
    }

    #[test]
    fn a_baked_operator_needs_no_archive_and_is_still_checked_file_by_file() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let receipt = fetch(directory.path(), &fake, &reference)?;
        let root = directory.path().join("cache");
        fs::remove_file(root.join(fixture.release.operator.check(u64::MAX)?))?;
        let calls = fake.calls().len();
        assert_eq!(
            fetch(directory.path(), &fake, &reference)?["cli"],
            receipt["cli"]
        );
        assert_eq!(fake.calls().len(), calls);
        let cli = PathBuf::from(receipt["cli"].as_str().unwrap());
        let license = cli
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("licenses/LICENSE");
        fs::set_permissions(&license, fs::Permissions::from_mode(0o644))?;
        fs::write(&license, b"changed notice")?;
        let error = fetch(directory.path(), &fake, &reference).unwrap_err();
        assert!(
            format!("{error:#}").contains("cached operator executable changed"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn published_metadata_must_match_and_permission_errors_are_not_misses() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let cache = Cache::open(&directory.path().join("cache"), OBJECTS_URI)?;
        let mut tools = fake.clone();
        let mut wrong = reference.clone();
        wrong.bytes += 1;
        let error = cache.fetch(&wrong, MANIFEST_LIMIT, &mut tools).unwrap_err();
        assert!(
            format!("{error:#}").contains("size or generation"),
            "{error:#}"
        );
        for generation in [0, 1] {
            fake.0
                .borrow_mut()
                .objects
                .values_mut()
                .for_each(|object| object.1 = generation);
            let result = cache.fetch(&reference, MANIFEST_LIMIT, &mut tools);
            assert_eq!(result.is_ok(), generation == 1, "{generation}");
        }
        fake.0.borrow_mut().denied = true;
        let error = cache
            .fetch(
                &fixture.release.distribution,
                DISTRIBUTION_LIMIT,
                &mut tools,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("permission denied"),
            "{error:#}"
        );
        // A blob that is not in the bucket is an error, never an empty release.
        fake.0.borrow_mut().denied = false;
        let missing = BlobIdentity::of(b"never published");
        assert!(cache.fetch(&missing, MANIFEST_LIMIT, &mut tools).is_err());
        // A cache that is a link is refused.
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path().join("cache"), &link)?;
        assert!(Cache::open(&link, OBJECTS_URI).is_err());
        let file = directory.path().join("file");
        fs::write(&file, b"")?;
        assert!(Cache::open(&file, OBJECTS_URI).is_err());
        Ok(())
    }

    #[test]
    fn a_fetch_binds_the_registry_distribution_and_evidence_in_order() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let mut session = fetch_session(directory.path(), &fake, &reference)?;
        assert!(session.operator().is_err());
        assert!(session.blob("distribution").is_err());
        assert!(session.image("runtime").is_err());
        assert!(session.manifest().is_err());
        session.blob("manifest")?;
        assert!(session.blob("manifest").is_err());
        assert!(session.blob("native").is_err());
        session.blob("distribution")?;
        session.blob("native")?;
        assert!(session.operator().is_err());
        session.blob("strict")?;
        assert!(session.blob("strict").is_err());
        session.operator()?;
        // A manifest pinned in another project's registry is refused.
        let mut other = fixture.release.clone();
        other.runtime.image = other
            .runtime
            .image
            .replace("exampleco-tools", "other-project");
        let foreign = fake.store(&other.encode()?);
        let mut session = fetch_session(directory.path(), &fake, &foreign)?;
        let error = session.blob("manifest").unwrap_err();
        assert!(format!("{error:#}").contains("pinned under"), "{error:#}");
        // Evidence for another release is refused before any operator is installed.
        let mut strict = fixture.strict.clone();
        strict["qualification_digest"] = json!(day2::digest(b"another receipt"));
        let mut release = fixture.release.clone();
        release.evidence.strict = fake.store(&serde_json::to_vec(&strict)?);
        let unbound = fake.store(&release.encode()?);
        let mut session = fetch_session(directory.path(), &fake, &unbound)?;
        for name in ["manifest", "distribution", "native"] {
            session.blob(name)?;
        }
        assert!(session.blob("strict").is_err());
        assert!(session.operator().is_err());
        // A rolling manifest is refused.
        let mut rolling = serde_json::to_value(&fixture.release)?;
        rolling["profile"] = json!("linux_sqlite_rwo_v1");
        rolling["evidence"]["rolling"] = json!(fixture.release.evidence.native);
        let rolling = fake.store(&serde_json::to_vec(&rolling)?);
        let mut session = fetch_session(directory.path(), &fake, &rolling)?;
        assert!(session.blob("manifest").is_err());
        // The host's mode wins over the request's.
        let request = request_file(
            directory.path(),
            &json!({"mode": "fetch", "bucket": BUCKET, "registry": REGISTRY,
                "publication": null, "output": null, "reference": reference}),
        );
        assert!(Session::prepare(&request, Mode::Publish, Box::new(fake.clone()), None).is_err());
        Ok(())
    }

    #[test]
    fn operator_archives_carry_exactly_the_fixed_regular_files() -> Result<()> {
        let fixture = fixture();
        let files = files();
        let regular = |name: &'static str| (name, tar::EntryType::Regular, files[name].as_slice());
        let complete: Vec<_> = OPERATOR_FILES.iter().copied().map(regular).collect();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("complete", archive(&complete)),
            ("extra member", {
                let mut entries = complete.clone();
                entries.push(("cli/arbitrary-hook", tar::EntryType::Regular, b"hook"));
                archive(&entries)
            }),
            ("missing member", archive(&complete[1..])),
            ("duplicate member", {
                let mut entries = complete.clone();
                entries.push(regular("cli/day2"));
                archive(&entries)
            }),
            ("traversal", {
                let mut entries = complete.clone();
                entries[0].0 = "../escape";
                archive(&entries)
            }),
            ("dot prefix", {
                let mut entries = complete.clone();
                entries[0].0 = "./cli/day2";
                archive(&entries)
            }),
            ("symlink", {
                let mut entries = complete.clone();
                entries[0] = ("cli/day2", tar::EntryType::Symlink, b"");
                archive(&entries)
            }),
            ("hard link", {
                let mut entries = complete.clone();
                entries[0] = ("cli/day2", tar::EntryType::Link, b"");
                archive(&entries)
            }),
            ("directory", {
                let mut entries = complete.clone();
                entries.insert(0, ("cli/", tar::EntryType::Directory, b""));
                archive(&entries)
            }),
            ("wrong size", {
                let mut entries = complete.clone();
                entries[0].2 = b"short";
                archive(&entries)
            }),
            ("wrong digest", {
                let mut entries = complete.clone();
                let same_size = vec![b'x'; files["cli/day2"].len()];
                entries[0].2 = Box::leak(same_size.into_boxed_slice());
                archive(&entries)
            }),
            ("not gzip", b"plain bytes".to_vec()),
        ];
        for (case, bytes) in cases {
            let directory = tempfile::tempdir()?;
            let fake = Fake::default();
            let cache = Cache::open(&directory.path().join("cache"), OBJECTS_URI)?;
            let mut release = fixture.release.clone();
            let mut distribution = fixture.distribution.clone();
            release.operator = fake.store(&bytes);
            distribution.operator = release.operator.clone();
            let result = cache.operator(&release, &distribution, &mut fake.clone());
            assert_eq!(result.is_ok(), case == "complete", "{case}: {result:?}");
            if case != "complete" {
                let operator = cache
                    .root()
                    .join(format!("{}.operator", release.operator.check(u64::MAX)?));
                assert!(fs::symlink_metadata(operator).is_err(), "{case}");
                assert!(fs::symlink_metadata(directory.path().join("escape")).is_err());
                // Only the archive, its lock and the operator lock remain.
                assert_eq!(fs::read_dir(cache.root())?.count(), 3, "{case}");
            }
        }
        Ok(())
    }

    fn publish_session(directory: &Path, fake: &Fake, fixture: &Fixture) -> Result<Session> {
        let publication = fixture.publication(directory);
        let request = request_file(
            directory,
            &json!({"mode": "publish", "bucket": BUCKET, "registry": REGISTRY,
                "publication": publication, "output": directory.join("manifest.json"),
                "reference": null}),
        );
        fake.0.borrow_mut().images = BTreeMap::from([
            (
                fixture.release.runtime.image.clone(),
                fixture.release.runtime.config.clone(),
            ),
            (
                fixture.release.tooling.image.clone(),
                fixture.release.tooling.config.clone(),
            ),
        ]);
        Session::prepare(&request, Mode::Publish, Box::new(fake.clone()), None)
    }

    fn publish_all(session: &mut Session) -> Result<Value> {
        for image in ["runtime", "tooling"] {
            session.image(image)?;
        }
        for name in PUBLISHED {
            session.blob(name)?;
        }
        session.manifest()
    }

    #[test]
    fn a_publication_verifies_images_then_publishes_blobs_and_the_manifest_last() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let mut session = publish_session(directory.path(), &fake, &fixture)?;
        assert!(session.blob("native").is_err());
        assert!(session.manifest().is_err());
        assert!(session.operator().is_err());
        let receipt = publish_all(&mut session)?;
        let bytes = fs::read(directory.path().join("manifest.json"))?;
        assert_eq!(bytes, fixture.release.encode()?);
        assert_eq!(receipt["reference"], json!(BlobIdentity::of(&bytes)));
        assert_eq!(receipt["objects"], OBJECTS_URI);
        let key = |bytes: &[u8]| BlobIdentity::of(bytes).check(u64::MAX).unwrap().to_owned();
        assert_eq!(
            fake.calls(),
            [
                format!("pull {}", fixture.release.runtime.image),
                format!("inspect {}", fixture.release.runtime.image),
                format!("pull {}", fixture.release.tooling.image),
                format!("inspect {}", fixture.release.tooling.image),
                format!("create {}", key(&serde_json::to_vec(&fixture.native)?)),
                format!("create {}", key(&serde_json::to_vec(&fixture.strict)?)),
                format!(
                    "create {}",
                    key(&serde_json::to_vec_pretty(&fixture.distribution)?)
                ),
                format!("create {}", key(&fixture.operator)),
                format!("create {}", key(&bytes)),
            ]
        );
        // What was published fetches and verifies.
        let fetched = fetch(directory.path(), &fake, &BlobIdentity::of(&bytes))?;
        for field in [
            "reference",
            "platform_commit",
            "profile",
            "target",
            "runtime_image",
            "tooling_image",
        ] {
            assert_eq!(fetched[field], receipt[field], "{field}");
        }
        assert_eq!(
            receipt["files"],
            json!({"manifest": directory.path().join("manifest.json"), "distribution": null,
                "native": null, "strict": null})
        );
        assert!(receipt["cache"].is_null() && receipt["cli"].is_null());
        Ok(())
    }

    #[test]
    fn publishing_again_verifies_existing_objects_and_never_replaces_them() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        // An earlier, interrupted publication created every blob.
        fixture.upload(&fake);
        let before = fake.0.borrow().objects.clone();
        let mut session = publish_session(directory.path(), &fake, &fixture)?;
        publish_all(&mut session)?;
        assert_eq!(fake.0.borrow().objects, before);
        let calls = fake.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.starts_with("create"))
                .count(),
            5
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.starts_with("download"))
                .count(),
            5
        );
        // An existing object with other bytes under the same name fails the publication.
        let fake = Fake::default();
        let other = tempfile::tempdir()?;
        let mut session = publish_session(other.path(), &fake, &fixture)?;
        fake.replace(
            &BlobIdentity::of(&serde_json::to_vec(&fixture.native)?),
            b"other bytes",
        );
        session.image("runtime")?;
        session.image("tooling")?;
        let error = session.blob("native").unwrap_err();
        assert!(
            format!("{error:#}").contains("existing release object differs"),
            "{error:#}"
        );
        assert!(session.manifest().is_err());
        assert!(fs::symlink_metadata(other.path().join("manifest.json")).is_err());
        Ok(())
    }

    #[test]
    fn a_publication_is_validated_completely_before_it_pulls_or_uploads() -> Result<()> {
        let fixture = fixture();
        let attempt = |change: &dyn Fn(&Path, &mut Value)| -> Result<Session> {
            let directory = tempfile::tempdir()?;
            let fake = Fake::default();
            let publication = fixture.publication(directory.path());
            let mut value: Value = serde_json::from_slice(&fs::read(&publication)?)?;
            change(directory.path(), &mut value);
            fs::write(&publication, serde_json::to_vec(&value)?)?;
            let request = request_file(
                directory.path(),
                &json!({"mode": "publish", "bucket": BUCKET, "registry": REGISTRY,
                    "publication": publication, "output": directory.path().join("manifest.json"),
                    "reference": null}),
            );
            let session = Session::prepare(&request, Mode::Publish, Box::new(fake.clone()), None);
            assert!(fake.calls().is_empty());
            session
        };
        attempt(&|_, _| {})?;
        type Change = Box<dyn Fn(&Path, &mut Value)>;
        let refused: Vec<(&str, Change)> = vec![
            (
                "rolling",
                Box::new(|_: &Path, v: &mut Value| v["profile"] = json!("linux_sqlite_rwo_v1")),
            ),
            (
                "unknown field",
                Box::new(|_: &Path, v: &mut Value| v["rolling"] = json!("rolling.json")),
            ),
            (
                "missing field",
                Box::new(|_: &Path, v: &mut Value| {
                    v.as_object_mut().unwrap().remove("strict");
                }),
            ),
            (
                "commit",
                Box::new(|_: &Path, v: &mut Value| v["platform_commit"] = json!("main")),
            ),
            (
                "unpinned image",
                Box::new(|_: &Path, v: &mut Value| {
                    v["runtime"]["image"] = json!(format!("{REGISTRY}/home/day2-runtime:latest"));
                }),
            ),
            (
                "foreign registry",
                Box::new(|_: &Path, v: &mut Value| {
                    let image = v["runtime"]["image"]
                        .as_str()
                        .unwrap()
                        .replace("exampleco-tools", "other-project");
                    v["runtime"]["image"] = json!(image);
                }),
            ),
            (
                "evidence for another runtime",
                Box::new(|_: &Path, v: &mut Value| {
                    v["runtime"]["config"] = json!(day2::digest(b"another runtime"));
                    let image = format!(
                        "{REGISTRY}/home/day2-runtime@{}",
                        day2::digest(b"another runtime")
                    );
                    v["runtime"]["image"] = json!(image);
                }),
            ),
            (
                "missing file",
                Box::new(|d: &Path, v: &mut Value| v["native"] = json!(d.join("missing.json"))),
            ),
            (
                "empty file",
                Box::new(|d: &Path, v: &mut Value| {
                    fs::write(d.join("empty.json"), b"").unwrap();
                    v["strict"] = json!(d.join("empty.json"));
                }),
            ),
            (
                "linked file",
                Box::new(|d: &Path, v: &mut Value| {
                    std::os::unix::fs::symlink(d.join("operator.tar.gz"), d.join("linked"))
                        .unwrap();
                    v["operator"] = json!(d.join("linked"));
                }),
            ),
            (
                "another distribution",
                Box::new(|d: &Path, v: &mut Value| {
                    fs::write(d.join("other.json"), br#"{"format":1}"#).unwrap();
                    v["distribution"] = json!(d.join("other.json"));
                }),
            ),
            (
                "existing manifest",
                Box::new(|d: &Path, _: &mut Value| {
                    fs::write(d.join("manifest.json"), b"").unwrap()
                }),
            ),
        ];
        for (case, change) in refused {
            assert!(attempt(change.as_ref()).is_err(), "{case}");
        }
        // An image whose ID differs from the qualified config is refused before any upload.
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let mut session = publish_session(directory.path(), &fake, &fixture)?;
        fake.0.borrow_mut().images.insert(
            fixture.release.tooling.image.clone(),
            day2::digest(b"another build"),
        );
        session.image("runtime")?;
        assert!(session.image("runtime").is_err());
        let error = session.image("tooling").unwrap_err();
        assert!(
            format!("{error:#}").contains("differs from qualified image config"),
            "{error:#}"
        );
        assert!(session.blob("native").is_err());
        assert!(fake.calls().iter().all(|call| !call.starts_with("create")));
        Ok(())
    }
    #[test]
    fn the_receipt_is_the_shape_the_cli_decodes() -> Result<()> {
        let reference = BlobIdentity::of(GOLDEN_MANIFEST);
        let release = Release::decode(GOLDEN_MANIFEST)?;
        let cache = Path::new("/opt/day2-platform-releases");
        let blob = |identity: &BlobIdentity| {
            text(&cache.join(identity.check(u64::MAX).unwrap())).map(str::to_owned)
        };
        let cli = cache.join(format!(
            "{}.operator/cli/day2",
            release.operator.check(u64::MAX)?
        ));
        let receipt = Receipt::new(
            Mode::Fetch,
            &reference,
            &release,
            "gs://wonderly-internal-tools-tofu-state/day2/platform-releases/sha256",
            Files {
                manifest: blob(&reference)?,
                distribution: Some(blob(&release.distribution)?),
                native: Some(blob(&release.evidence.native)?),
                strict: Some(blob(&release.evidence.strict)?),
            },
            Some((cache, &cli)),
        )?;
        assert_eq!(
            serde_json::to_string_pretty(&receipt)? + "\n",
            GOLDEN_RECEIPT
        );
        assert_eq!(serde_json::from_str::<Receipt>(GOLDEN_RECEIPT)?, receipt);
        let mut extra: Value = serde_json::from_str(GOLDEN_RECEIPT)?;
        extra["release"] = json!({});
        assert!(serde_json::from_value::<Receipt>(extra).is_err());
        Ok(())
    }

    #[test]
    fn a_held_lock_excludes_another_holder_until_it_is_dropped() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("key.lock");
        let guard = sdk_release::lock(&path)?;
        assert_eq!(mode(&path), 0o600);
        assert!(matches!(
            fs::File::open(&path)?.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(guard);
        assert!(fs::File::open(&path)?.try_lock().is_ok());
        let linked = directory.path().join("linked.lock");
        std::os::unix::fs::symlink(&path, &linked)?;
        assert!(sdk_release::lock(&linked).is_err());
        Ok(())
    }

    #[test]
    fn a_key_stays_locked_while_it_is_fetched_and_extracted() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let reference = fixture.upload(&fake);
        let root = std::path::absolute(directory.path().join("cache"))?;
        let key = |identity: &BlobIdentity| identity.check(u64::MAX).unwrap().to_owned();
        let (manifest, archive) = (key(&reference), key(&fixture.release.operator));
        let locks = [
            root.join(format!("{manifest}.lock")),
            root.join(format!("{archive}.lock")),
            root.join(format!("{archive}.operator.lock")),
        ];
        fake.0.borrow_mut().probes = locks.to_vec();
        fetch(directory.path(), &fake, &reference)?;
        let world = fake.0.borrow();
        let held = |described: &str, lock: &Path| {
            world
                .held
                .iter()
                .any(|(key, path, held)| key == described && path == lock && *held)
        };
        // Another holder is shut out of a key while its object is read, and of
        // an operator while its archive is fetched for extraction.
        assert!(held(&manifest, &locks[0]), "{:?}", world.held);
        assert!(held(&archive, &locks[1]), "{:?}", world.held);
        assert!(held(&archive, &locks[2]), "{:?}", world.held);
        assert!(!held(&manifest, &locks[1]));
        // Nothing stays locked afterwards.
        for lock in &locks {
            assert!(
                fs::File::open(lock)?.try_lock().is_ok(),
                "{}",
                lock.display()
            );
        }
        Ok(())
    }

    #[test]
    fn a_linked_operator_subdirectory_is_refused() -> Result<()> {
        for linked in ["cli", "licenses"] {
            let directory = tempfile::tempdir()?;
            let fake = Fake::default();
            let reference = fixture().upload(&fake);
            let receipt = fetch(directory.path(), &fake, &reference)?;
            let cli = PathBuf::from(receipt["cli"].as_str().unwrap());
            let operator = cli.parent().unwrap().parent().unwrap().to_owned();
            // The same, verified files, reached through a link.
            let moved = directory.path().join("moved");
            fs::rename(operator.join(linked), &moved)?;
            std::os::unix::fs::symlink(&moved, operator.join(linked))?;
            let error = fetch(directory.path(), &fake, &reference).unwrap_err();
            assert!(
                format!("{error:#}").contains("invalid operator cache directory"),
                "{linked}: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn an_input_changed_after_preparation_is_never_uploaded() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fake = Fake::default();
        let fixture = fixture();
        let mut session = publish_session(directory.path(), &fake, &fixture)?;
        session.image("runtime")?;
        session.image("tooling")?;
        // Blobs go up in their fixed order.
        assert!(session.blob("strict").is_err());
        session.blob("native")?;
        fs::write(directory.path().join("strict.json"), br#"{"changed":true}"#)?;
        let error = session.blob("strict").unwrap_err();
        assert!(
            format!("{error:#}").contains("changed before publication"),
            "{error:#}"
        );
        let creates = fake
            .calls()
            .into_iter()
            .filter(|call| call.starts_with("create"))
            .count();
        assert_eq!(creates, 1);
        assert!(session.blob("distribution").is_err());
        assert!(session.manifest().is_err());
        assert!(fs::symlink_metadata(directory.path().join("manifest.json")).is_err());
        Ok(())
    }
}
