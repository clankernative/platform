//! Native file adapter for `day2 instance extension` and app CI's extension
//! check. Release rules live in `day2::chrome_extension`; this module reads an
//! app's extension source and downloads and writes its signed downloads or an
//! unpacked local build, always against the extension day2.json pins for the
//! app. `fleet` also reads the edge's request logs for the release downloads,
//! read-only.
use anyhow::{Context, Result, bail, ensure};
use day2::{
    chrome_extension::{self as extension, Binding, DownloadRequest, Files},
    public_downloads,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const MAX_DEPTH: usize = 16;
/// macOS Finder metadata is never extension source.
const IGNORED: &str = ".DS_Store";
/// A fleet report reads at most this many request log entries and refuses a
/// window that holds more rather than summarizing part of it.
const MAX_LOG_ENTRIES: usize = 20_000;

/// The command a `day2 instance extension` session runs; the host's action
/// fixes it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Verify,
    Pack,
    Local,
    Policy,
    Fleet,
}

impl Mode {
    pub const ALL: [Self; 5] = [
        Self::Verify,
        Self::Pack,
        Self::Local,
        Self::Policy,
        Self::Fleet,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Pack => "pack",
            Self::Local => "local",
            Self::Policy => "policy",
            Self::Fleet => "fleet",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.name() == name)
    }
}

/// What the CLI hands the host for `day2 instance extension <mode>`, derived
/// from day2.json: the app, its source, its pin and the mode's own input.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub mode: Mode,
    pub app_id: String,
    /// The app root, which holds `.chrome-extension/` and `public-downloads/`.
    pub source: PathBuf,
    /// day2.json's pin for the app; only `verify` accepts an app without one.
    pub extension: Option<Binding>,
    /// pack: the signing key's PEM file, outside the app.
    pub key: Option<PathBuf>,
    /// local: the new directory for the unpacked build.
    pub output: Option<PathBuf>,
    /// fleet: the instance's GCP project, whose edge logs the downloads.
    pub project: Option<String>,
}

impl Request {
    fn validate(&self) -> Result<()> {
        ensure!(
            crate::ci_fetch::app_id(&self.app_id),
            "an instance extension request names an app ID"
        );
        let wanted = match self.mode {
            Mode::Pack => [true, false, false],
            Mode::Local => [false, true, false],
            Mode::Fleet => [false, false, true],
            Mode::Verify | Mode::Policy => [false, false, false],
        };
        ensure!(
            [
                self.key.is_some(),
                self.output.is_some(),
                self.project.is_some()
            ] == wanted,
            "an instance extension {} request names only its own inputs",
            self.mode.name()
        );
        match &self.extension {
            Some(binding) => {
                binding.validate()?;
                ensure!(
                    binding.crx == format!("{}.crx", self.app_id),
                    "the extension's CRX is <app>.crx, as day2.json derives it"
                );
            }
            None => ensure!(
                self.mode == Mode::Verify,
                "day2.json pins no Chrome extension for {}",
                self.app_id
            ),
        }
        Ok(())
    }

    fn pinned(&self) -> Result<&Binding> {
        self.extension
            .as_ref()
            .with_context(|| format!("day2.json pins no Chrome extension for {}", self.app_id))
    }
}

/// One `day2 instance extension` command. The recipe names each step; the
/// session runs only its mode's, and `pack`'s verification after it.
pub struct Session {
    request: Request,
    done: Vec<Mode>,
}

impl Session {
    pub fn new(mode: Mode, request: Request) -> Result<Self> {
        ensure!(
            request.mode == mode,
            "the instance extension request is for {}, not {}",
            request.mode.name(),
            mode.name()
        );
        request.validate()?;
        Ok(Self {
            request,
            done: Vec::new(),
        })
    }

    pub fn step(&mut self, name: &str) -> Result<Value> {
        let step = Mode::from_name(name)
            .with_context(|| format!("unknown instance extension step: {name}"))?;
        let mode = self.request.mode;
        let expected = match (mode, self.done.as_slice()) {
            (_, []) => mode,
            (Mode::Pack, [Mode::Pack]) => Mode::Verify,
            _ => bail!("instance extension {} runs nothing more", mode.name()),
        };
        ensure!(
            step == expected,
            "instance extension {} runs {} next, not {name}",
            mode.name(),
            expected.name()
        );
        let source = &self.request.source;
        let value = match step {
            Mode::Verify => verify(source, self.request.extension.as_ref())?,
            Mode::Pack => pack(
                source,
                self.request.pinned()?,
                self.request.key.as_deref().context("pack names a key")?,
            )?,
            Mode::Local => local(
                source,
                self.request.pinned()?,
                self.request
                    .output
                    .as_deref()
                    .context("local names an output")?,
            )?,
            Mode::Policy => policy(source, self.request.pinned()?)?,
            Mode::Fleet => fleet(
                source,
                self.request.pinned()?,
                self.request
                    .project
                    .as_deref()
                    .context("fleet names a project")?,
            )?,
        };
        self.done.push(step);
        Ok(value)
    }
}

/// Verify the app's extension release against day2.json's pin. An app without
/// one may have neither extension source nor downloads.
pub fn verify(app: &Path, binding: Option<&Binding>) -> Result<Value> {
    let downloads = downloads(app)?;
    let Some(binding) = binding else {
        ensure!(
            !present(app)?,
            "chrome_extension_unpinned: day2.json pins no Chrome extension for this app; remove {}/ or pin its ID",
            extension::DIRECTORY
        );
        extension::verify_unpinned(&downloads)?;
        return Ok(json!({"pinned": false}));
    };
    let release = extension::verify(binding, &source(app)?, &downloads)?;
    Ok(json!({"pinned": true, "release": release}))
}

/// Sign the current sources and replace the release in `public-downloads/`.
pub fn pack(app: &Path, binding: &Binding, key: &Path) -> Result<Value> {
    let source = source(app)?;
    let package = extension::pack(
        binding,
        &source,
        &downloads(app)?,
        &signing_key(app, key)?,
        &ring::rand::SystemRandom::new(),
    )?;
    let directory = app.join(public_downloads::SOURCE_DIRECTORY);
    fs::create_dir_all(&directory)?;
    replace(&directory, &binding.crx, &package.crx)?;
    replace(
        &directory,
        extension::UPDATE_MANIFEST,
        &package.update_manifest,
    )?;
    Ok(json!({
        "release": package.release,
        "policy": extension::policy(binding, &source)?,
    }))
}

/// Write an unpacked build into a new directory.
pub fn local(app: &Path, binding: &Binding, output: &Path) -> Result<Value> {
    let overlay = app
        .join(extension::DIRECTORY)
        .join(extension::LOCAL_DIRECTORY);
    let overlay = match fs::symlink_metadata(&overlay) {
        Err(error) if error.kind() == ErrorKind::NotFound => Files::new(),
        _ => tree(&overlay)?,
    };
    let files = extension::local(binding, &source(app)?, &downloads(app)?, &overlay)?;
    ensure!(
        fs::symlink_metadata(output).is_err_and(|error| error.kind() == ErrorKind::NotFound),
        "chrome_extension_local: {} already exists; choose a new directory",
        output.display()
    );
    for (path, bytes) in &files {
        let target = output.join(path);
        fs::create_dir_all(target.parent().context("local extension path")?)?;
        fs::write(target, bytes)?;
    }
    Ok(json!({
        "directory": output,
        "files": files.len(),
        "release_identity": overlay.is_empty(),
    }))
}

pub fn policy(app: &Path, binding: &Binding) -> Result<Value> {
    extension::policy(binding, &source(app)?)
}

/// Report how managed browsers are taking up the app's verified release, from
/// the last day of the GCP project's load-balancer request logs. It reads with
/// the operator's gcloud credentials and needs no browser-policy access.
pub fn fleet(app: &Path, binding: &Binding, project: &str) -> Result<Value> {
    ensure!(
        (6..=30).contains(&project.len())
            && project.starts_with(|first: char| first.is_ascii_lowercase())
            && !project.ends_with('-')
            && project
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "chrome_extension_fleet_project: expected a GCP project ID"
    );
    let release = extension::verify(binding, &source(app)?, &downloads(app)?)?;
    let directory = release
        .update_url
        .strip_suffix(extension::UPDATE_MANIFEST)
        .context("chrome_extension_fleet: the release has no update manifest URL")?;
    let output = crate::maintenance::bounded(
        Command::new(crate::maintenance::on_path("gcloud")?).args([
            "logging",
            "read",
            &format!(
                "resource.type=\"http_load_balancer\" AND httpRequest.requestUrl:\"{directory}\""
            ),
            "--project",
            project,
            &format!("--freshness={}h", extension::FLEET_WINDOW_HOURS),
            &format!("--limit={MAX_LOG_ENTRIES}"),
            "--format=json(httpRequest.requestUrl,httpRequest.status,httpRequest.remoteIp)",
        ]),
        None,
        Duration::from_secs(300),
        None,
    )
    .context("chrome_extension_fleet_logs: gcloud logging read")?;
    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "httpRequest")]
        request: Option<Request>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Request {
        request_url: Option<String>,
        status: Option<u16>,
        remote_ip: Option<String>,
    }
    let entries: Vec<Entry> = serde_json::from_str(&output)
        .context("chrome_extension_fleet_logs: unexpected gcloud output")?;
    ensure!(
        entries.len() < MAX_LOG_ENTRIES,
        "chrome_extension_fleet_log_budget: more than {} requests in {} hours",
        MAX_LOG_ENTRIES - 1,
        extension::FLEET_WINDOW_HOURS
    );
    // gcloud returns the newest entries first; the summary reads oldest first.
    let requests = entries
        .into_iter()
        .rev()
        .filter_map(|entry| {
            let request = entry.request?;
            Some(DownloadRequest {
                url: request.request_url?,
                status: request.status?,
                client: request.remote_ip.unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_value(extension::fleet(
        &release, &requests,
    )?)?)
}

/// Whether the app has a `.chrome-extension/` directory, which only a pinned
/// extension may.
fn present(app: &Path) -> Result<bool> {
    match fs::symlink_metadata(app.join(extension::DIRECTORY)) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        metadata => {
            ensure!(
                metadata?.file_type().is_dir(),
                "chrome_extension_source: {} must be a directory",
                extension::DIRECTORY
            );
            Ok(true)
        }
    }
}

fn source(app: &Path) -> Result<Files> {
    tree(
        &app.join(extension::DIRECTORY)
            .join(extension::SOURCE_DIRECTORY),
    )
}

/// Regular files below `root`, keyed by relative `/` path. Symlinks are refused.
fn tree(root: &Path) -> Result<Files> {
    fn visit(directory: &Path, prefix: &str, depth: usize, files: &mut Files) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "chrome_extension_source_depth");
        let mut entries = fs::read_dir(directory)?
            .take(extension::MAX_FILES + 1)
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(
            entries.len() <= extension::MAX_FILES,
            "chrome_extension_file_count"
        );
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("chrome_extension_path: non-UTF-8 file name"))?;
            if name == IGNORED {
                continue;
            }
            let path = format!("{prefix}{name}");
            let kind = entry.file_type()?;
            ensure!(
                !kind.is_symlink(),
                "chrome_extension_path: symlink {path} is not allowed"
            );
            if kind.is_dir() {
                visit(&entry.path(), &format!("{path}/"), depth + 1, files)?;
            } else {
                files.insert(
                    path,
                    day2_assets::read_regular(&entry.path(), extension::MAX_SOURCE_BYTES)?,
                );
                ensure!(
                    files.len() <= extension::MAX_FILES,
                    "chrome_extension_file_count"
                );
            }
        }
        Ok(())
    }
    ensure!(
        fs::symlink_metadata(root)
            .with_context(|| format!("chrome_extension_source: {} is missing", root.display()))?
            .is_dir(),
        "chrome_extension_source: {} must be a directory",
        root.display()
    );
    let mut files = Files::new();
    visit(root, "", 0, &mut files)?;
    Ok(files)
}

/// The complete flat `public-downloads/` directory.
fn downloads(app: &Path) -> Result<Files> {
    let directory = app.join(public_downloads::SOURCE_DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Files::new()),
        metadata => ensure!(metadata?.is_dir(), "public_download_directory_type"),
    }
    let entries = fs::read_dir(&directory)?
        .take(public_downloads::MAX_FILES + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() <= public_downloads::MAX_FILES,
        "public_download_count_budget"
    );
    let mut files = Files::new();
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("public_download_filename"))?;
        files.insert(
            name,
            day2_assets::read_regular(&entry.path(), public_downloads::MAX_FILE_BYTES)?,
        );
    }
    Ok(files)
}

/// Read a PEM signing key that lives outside the app. A regular key file must be
/// private to its owner; a pipe such as `<(gcloud secrets versions access …)`
/// keeps the key off disk.
fn signing_key(app: &Path, key: &Path) -> Result<Vec<u8>> {
    if let (Ok(app), Ok(real)) = (app.canonicalize(), key.canonicalize()) {
        ensure!(
            !real.starts_with(&app),
            "chrome_extension_signing_key: keep the signing key outside the app"
        );
    }
    let metadata = fs::metadata(key).with_context(|| {
        format!(
            "chrome_extension_signing_key: cannot read {}",
            key.display()
        )
    })?;
    #[cfg(unix)]
    if metadata.is_file() {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "chrome_extension_signing_key: {} must not be readable by group or others",
            key.display()
        );
    }
    ensure!(
        !metadata.is_dir(),
        "chrome_extension_signing_key: expected a PEM file"
    );
    let mut bytes = Vec::new();
    fs::File::open(key)?
        .take(extension::MAX_KEY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= extension::MAX_KEY_BYTES,
        "chrome_extension_signing_key_budget"
    );
    Ok(bytes)
}

fn replace(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let partial = directory.join(format!(".{name}.partial"));
    fs::write(&partial, bytes)?;
    fs::rename(&partial, directory.join(name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn app() -> Result<tempfile::TempDir> {
        let app = tempfile::tempdir()?;
        fs::create_dir_all(app.path().join(".chrome-extension/src/icons"))?;
        fs::write(app.path().join(".chrome-extension/src/background.js"), b"1")?;
        fs::write(app.path().join(".chrome-extension/src/icons/a.png"), b"2")?;
        fs::write(app.path().join(".chrome-extension/src/.DS_Store"), b"x")?;
        Ok(app)
    }

    fn binding() -> Binding {
        Binding {
            id: "aenkglomgaiikbngepnbfminfpfgmape".into(),
            crx: "reminders.crx".into(),
            update_url: "https://reminders.example.com/downloads/updates.xml".into(),
        }
    }

    fn request(mode: Mode) -> Request {
        Request {
            mode,
            app_id: "reminders".into(),
            source: "/work/reminders/app".into(),
            extension: Some(binding()),
            key: None,
            output: None,
            project: None,
        }
    }

    fn refusal<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected a refusal"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn apps_without_a_pin_may_not_publish_extension_releases() -> Result<()> {
        let app = tempfile::tempdir()?;
        assert_eq!(verify(app.path(), None)?, json!({"pinned": false}));
        fs::create_dir(app.path().join("public-downloads"))?;
        fs::write(app.path().join("public-downloads/tool.crx"), b"crx")?;
        assert!(refusal(verify(app.path(), None)).contains("chrome_extension_unpinned"));
        fs::remove_file(app.path().join("public-downloads/tool.crx"))?;
        fs::create_dir(app.path().join(".chrome-extension"))?;
        assert!(refusal(verify(app.path(), None)).contains("remove .chrome-extension/"));
        assert!(refusal(verify(app.path(), Some(&binding()))).contains("src is missing"));
        Ok(())
    }

    #[test]
    fn requests_name_their_modes_inputs_and_a_pin_for_the_app() {
        let mut pack = request(Mode::Pack);
        pack.key = Some("/dev/fd/63".into());
        assert!(Session::new(Mode::Pack, pack.clone()).is_ok());
        assert!(
            refusal(Session::new(Mode::Verify, pack.clone())).contains("is for pack, not verify")
        );
        let mut keyed = request(Mode::Policy);
        keyed.key = pack.key.clone();
        assert!(refusal(Session::new(Mode::Policy, keyed)).contains("only its own inputs"));
        assert!(Session::new(Mode::Local, request(Mode::Local)).is_err());
        let mut unpinned = request(Mode::Policy);
        unpinned.extension = None;
        assert!(
            refusal(Session::new(Mode::Policy, unpinned.clone()))
                .contains("pins no Chrome extension for reminders")
        );
        unpinned.mode = Mode::Verify;
        assert!(Session::new(Mode::Verify, unpinned).is_ok());
        let mut renamed = request(Mode::Verify);
        renamed.app_id = "notes".into();
        assert!(refusal(Session::new(Mode::Verify, renamed)).contains("<app>.crx"));
    }

    #[test]
    fn sessions_run_their_mode_then_only_packs_verification() -> Result<()> {
        let app = tempfile::tempdir()?;
        let mut unpinned = request(Mode::Verify);
        unpinned.source = app.path().into();
        unpinned.extension = None;
        let mut session = Session::new(Mode::Verify, unpinned)?;
        assert!(refusal(session.step("pack")).contains("runs verify next, not pack"));
        assert_eq!(session.step("verify")?, json!({"pinned": false}));
        assert!(refusal(session.step("verify")).contains("runs nothing more"));
        let mut pack = request(Mode::Pack);
        pack.key = Some("/dev/fd/63".into());
        let mut session = Session::new(Mode::Pack, pack)?;
        assert!(refusal(session.step("verify")).contains("runs pack next, not verify"));
        assert!(refusal(session.step("sign")).contains("unknown instance extension step"));
        Ok(())
    }

    #[test]
    fn source_trees_skip_finder_metadata_and_refuse_symlinks() -> Result<()> {
        let app = app()?;
        let files = source(app.path())?;
        assert_eq!(
            files.keys().collect::<Vec<_>>(),
            ["background.js", "icons/a.png"]
        );
        symlink(
            app.path().join(".chrome-extension/src/background.js"),
            app.path().join(".chrome-extension/src/link.js"),
        )?;
        assert!(format!("{:#}", source(app.path()).unwrap_err()).contains("symlink"));
        Ok(())
    }

    #[test]
    fn signing_keys_stay_private_and_outside_the_app() -> Result<()> {
        let app = app()?;
        let inside = app.path().join("key.pem");
        fs::write(&inside, b"key")?;
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o600))?;
        assert!(
            format!("{:#}", signing_key(app.path(), &inside).unwrap_err())
                .contains("outside the app")
        );

        let outside = tempfile::tempdir()?;
        let shared = outside.path().join("key.pem");
        fs::write(&shared, b"key")?;
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o644))?;
        assert!(
            format!("{:#}", signing_key(app.path(), &shared).unwrap_err())
                .contains("group or others")
        );
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o600))?;
        assert_eq!(signing_key(app.path(), &shared)?, b"key");
        Ok(())
    }

    #[test]
    fn local_builds_require_a_new_directory() -> Result<()> {
        let app = app()?;
        let existing = tempfile::tempdir()?;
        let message = refusal(local(app.path(), &binding(), existing.path()));
        assert!(
            message.contains("manifest.json is missing") || message.contains("already exists"),
            "{message}"
        );
        Ok(())
    }
}
