//! Native file adapter for `day2 platform extension`. Release rules live in
//! `day2::chrome_extension`; this module reads an app's declared extension and
//! writes its signed downloads or an unpacked local build. `fleet` also reads
//! the edge's request logs for the release downloads, read-only.
use anyhow::{Context, Result, ensure};
use day2::{
    chrome_extension::{self as extension, Config, DownloadRequest, Files},
    public_downloads,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{ErrorKind, Read},
    path::Path,
    process::Command,
    time::Duration,
};

const MAX_CONFIG_BYTES: u64 = 4096;
const MAX_DEPTH: usize = 16;
/// macOS Finder metadata is never extension source.
const IGNORED: &str = ".DS_Store";
/// A fleet report reads at most this many request log entries and refuses a
/// window that holds more rather than summarizing part of it.
const MAX_LOG_ENTRIES: usize = 20_000;

pub fn verify(app: &Path) -> Result<Value> {
    let downloads = downloads(app)?;
    let Some(config) = declaration(app)? else {
        extension::verify_undeclared(&downloads)?;
        return Ok(json!({"declared": false}));
    };
    let release = extension::verify(&config, &source(app)?, &downloads)?;
    Ok(json!({"declared": true, "release": release}))
}

/// Sign the current sources and replace the release in `public-downloads/`.
pub fn pack(app: &Path, key: &Path) -> Result<Value> {
    let config = required(app)?;
    let source = source(app)?;
    let package = extension::pack(
        &config,
        &source,
        &downloads(app)?,
        &signing_key(app, key)?,
        &ring::rand::SystemRandom::new(),
    )?;
    let directory = app.join(public_downloads::SOURCE_DIRECTORY);
    fs::create_dir_all(&directory)?;
    replace(&directory, &config.package, &package.crx)?;
    replace(
        &directory,
        extension::UPDATE_MANIFEST,
        &package.update_manifest,
    )?;
    Ok(json!({
        "release": package.release,
        "policy": extension::policy(&config, &source)?,
    }))
}

/// Write an unpacked build into a new directory.
pub fn local(app: &Path, output: &Path) -> Result<Value> {
    let config = required(app)?;
    let overlay = app
        .join(extension::DIRECTORY)
        .join(extension::LOCAL_DIRECTORY);
    let overlay = match fs::symlink_metadata(&overlay) {
        Err(error) if error.kind() == ErrorKind::NotFound => Files::new(),
        _ => tree(&overlay)?,
    };
    let files = extension::local(&config, &source(app)?, &overlay)?;
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

pub fn policy(app: &Path) -> Result<Value> {
    extension::policy(&required(app)?, &source(app)?)
}

/// Report how managed browsers are taking up the app's verified release, from
/// the last day of the GCP project's load-balancer request logs. It reads with
/// the operator's gcloud credentials and needs no browser-policy access.
pub fn fleet(app: &Path, project: &str) -> Result<Value> {
    ensure!(
        (6..=30).contains(&project.len())
            && project.starts_with(|first: char| first.is_ascii_lowercase())
            && !project.ends_with('-')
            && project
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "chrome_extension_fleet_project: expected a GCP project ID"
    );
    let config = required(app)?;
    let release = extension::verify(&config, &source(app)?, &downloads(app)?)?;
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

fn required(app: &Path) -> Result<Config> {
    declaration(app)?.with_context(|| {
        format!(
            "chrome_extension_config: {} has no {}/{}",
            app.display(),
            extension::DIRECTORY,
            extension::CONFIG_FILE
        )
    })
}

/// `None` when the app has no `.chrome-extension/` directory at all.
fn declaration(app: &Path) -> Result<Option<Config>> {
    let directory = app.join(extension::DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        metadata => ensure!(
            metadata?.file_type().is_dir(),
            "chrome_extension_config: {} must be a directory",
            extension::DIRECTORY
        ),
    }
    let bytes =
        day2_assets::read_regular(&directory.join(extension::CONFIG_FILE), MAX_CONFIG_BYTES)
            .with_context(|| {
                format!(
                    "chrome_extension_config: declare the extension in {}/{}",
                    extension::DIRECTORY,
                    extension::CONFIG_FILE
                )
            })?;
    extension::config(&bytes).map(Some)
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
        fs::write(
            app.path().join(".chrome-extension/extension.json"),
            br#"{"id":"aenkglomgaiikbngepnbfminfpfgmape","package":"reminders.crx"}"#,
        )?;
        fs::write(app.path().join(".chrome-extension/src/background.js"), b"1")?;
        fs::write(app.path().join(".chrome-extension/src/icons/a.png"), b"2")?;
        fs::write(app.path().join(".chrome-extension/src/.DS_Store"), b"x")?;
        Ok(app)
    }

    #[test]
    fn apps_without_a_declaration_may_not_publish_extension_releases() -> Result<()> {
        let app = tempfile::tempdir()?;
        assert_eq!(verify(app.path())?, json!({"declared": false}));
        fs::create_dir(app.path().join("public-downloads"))?;
        fs::write(app.path().join("public-downloads/tool.crx"), b"crx")?;
        assert!(
            format!("{:#}", verify(app.path()).unwrap_err())
                .contains("chrome_extension_undeclared")
        );
        fs::create_dir(app.path().join(".chrome-extension"))?;
        assert!(format!("{:#}", verify(app.path()).unwrap_err()).contains("declare the extension"));
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
        let message = format!("{:#}", local(app.path(), existing.path()).unwrap_err());
        assert!(
            message.contains("manifest.json is missing") || message.contains("already exists"),
            "{message}"
        );
        Ok(())
    }
}
