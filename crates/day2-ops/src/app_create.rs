//! Atomic authoring capabilities; recipe, UI policy and scaffold text live in Roc.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{IsTerminal, Write},
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub destination: PathBuf,
    pub name: String,
    pub ui: String,
    pub bundle: String,
    pub bundle_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    path: String,
    bytes: usize,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Package {
    name: String,
    version: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    target: String,
    tool_version: String,
    source_revision: String,
    provider: String,
    assembly_protocol: u32,
    binding_abi: u32,
    template_engine: String,
    executable: Entry,
    package: Package,
    entries: Vec<Entry>,
}

pub struct Session {
    stage: tempfile::TempDir,
    parent: fs::File,
    destination: PathBuf,
    pub source: PathBuf,
    pub provider_pin: Option<PathBuf>,
    operator_pin: Option<PathBuf>,
    name: String,
    written: bool,
    identified: bool,
    verified_artifact: Option<PathBuf>,
    build_input: Option<String>,
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && path.split('/').count() <= 10
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}

fn no_links(path: &Path) -> Result<()> {
    let mut cursor = PathBuf::new();
    for part in path.components() {
        ensure!(
            !matches!(part, Component::ParentDir),
            "parent traversal forbidden"
        );
        cursor.push(part);
        ensure!(
            !fs::symlink_metadata(&cursor)?.file_type().is_symlink(),
            "symlink ancestor forbidden"
        );
    }
    Ok(())
}

fn regular(root: &Path, path: &str, budget: u64) -> Result<Vec<u8>> {
    ensure!(relative(path), "unsafe captured path");
    let path = root.join(path);
    no_links(&path)?;
    day2::assets::read_regular(&path, budget)
}

fn write(root: &Path, path: &str, bytes: &[u8]) -> Result<()> {
    ensure!(relative(path), "unsafe scaffold path");
    let path = root.join(path);
    fs::create_dir_all(path.parent().context("scaffold parent")?)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn tree_digest(root: &Path) -> Result<String> {
    fn visit(
        root: &Path,
        prefix: &str,
        hash: &mut Sha256,
        count: &mut usize,
        total: &mut usize,
    ) -> Result<()> {
        ensure!(prefix.split('/').count() <= 10, "scaffold tree depth");
        let mut entries = fs::read_dir(root.join(prefix))?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            *count += 1;
            ensure!(*count <= 8192, "scaffold tree entry budget");
            let path = if prefix.is_empty() {
                entry
                    .file_name()
                    .to_str()
                    .context("scaffold filename")?
                    .to_owned()
            } else {
                format!(
                    "{prefix}/{}",
                    entry.file_name().to_str().context("scaffold filename")?
                )
            };
            let kind = entry.file_type()?;
            ensure!(!kind.is_symlink(), "scaffold tree symlink");
            if kind.is_dir() {
                visit(root, &path, hash, count, total)?;
            } else {
                ensure!(kind.is_file(), "scaffold tree special file");
                let bytes = regular(root, &path, 1_048_576)?;
                *total = total
                    .checked_add(bytes.len())
                    .context("scaffold tree bytes")?;
                ensure!(*total <= 64 * 1024 * 1024, "scaffold tree byte budget");
                hash.update(path.as_bytes());
                hash.update([0]);
                hash.update(sha(&bytes).as_bytes());
                hash.update([0]);
            }
        }
        Ok(())
    }
    let mut hash = Sha256::new();
    visit(root, "", &mut hash, &mut 0, &mut 0)?;
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// One bounded terminal answer; question order and UI decisions belong to Roc.
pub fn prompt_answer(question: &str) -> Result<Value> {
    ensure!(
        question.len() <= 256 && !question.bytes().any(|b| b < 32 || b == 127),
        "prompt budget or controls"
    );
    ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "noninteractive app-create requires --ui none|html|clanker"
    );
    fn answer(question: &str) -> Result<bool> {
        eprint!("{question} [y/N]: ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        ensure!(
            std::io::stdin().read_line(&mut line)? > 0,
            "prompt cancelled"
        );
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Ok(true),
            "" | "n" | "no" => Ok(false),
            _ => anyhow::bail!("answer yes or no; nothing was created"),
        }
    }
    Ok(json!({"yes": answer(question)?}))
}

impl Session {
    pub fn begin(options: Options) -> Result<Self> {
        day2::schema::identifier(&options.name)?;
        ensure!(options.name.len() <= 48, "app name budget");
        ensure!(
            ["none", "html", "clanker"].contains(&options.ui.as_str()),
            "unsupported UI choice"
        );
        ensure!(
            (options.ui == "clanker")
                == (!options.bundle.is_empty() && !options.bundle_sha256.is_empty())
                && (options.ui == "clanker"
                    || (options.bundle.is_empty() && options.bundle_sha256.is_empty())),
            "bundle approval is required only for Clanker"
        );
        ensure!(
            !options
                .destination
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
                && !options.destination.as_os_str().is_empty(),
            "unsafe destination path"
        );
        let parent_path = options
            .destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        no_links(parent_path)?;
        let parent_path = parent_path.canonicalize()?;
        let leaf = options
            .destination
            .file_name()
            .context("fresh destination name required")?;
        let destination = parent_path.join(leaf);
        match fs::symlink_metadata(&destination) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("destination must be fresh; nothing was changed"),
        }
        let parent = fs::File::open(&parent_path)?;
        let stage = tempfile::Builder::new()
            .prefix(".day2-app-create-")
            .tempdir_in(&parent_path)?;
        let source = stage.path().join("app");
        fs::create_dir(&source)?;
        let mut session = Self {
            stage,
            parent,
            destination,
            source,
            provider_pin: None,
            operator_pin: None,
            name: options.name,
            written: false,
            identified: false,
            verified_artifact: None,
            build_input: None,
        };
        if options.ui == "clanker" {
            session.capture_bundle(Path::new(&options.bundle), &options.bundle_sha256)?;
        }
        Ok(session)
    }

    fn capture_bundle(&mut self, root: &Path, approval: &str) -> Result<()> {
        no_links(root)?;
        let manifest_bytes = regular(root, "manifest.json", 1_048_576)?;
        ensure!(
            sha(&manifest_bytes) == approval,
            "approved bundle manifest digest mismatch"
        );
        let manifest: Manifest = day2::json::decode(&manifest_bytes)?;
        let target = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-x86_64",
            ("macos", "aarch64") => "macos-aarch64",
            _ => anyhow::bail!("installed bundle host unsupported"),
        };
        ensure!(
            manifest.schema_version == 1
                && manifest.target == target
                && manifest.provider == "clanker-ui.native"
                && manifest.assembly_protocol == 2
                && manifest.binding_abi == 2
                && manifest.template_engine == "minijinja-2.12.0"
                && !manifest.tool_version.is_empty()
                && manifest.source_revision.len() == 40
                && manifest.executable.path == "bin/clanker-ui"
                && manifest.executable.bytes <= 64 * 1024 * 1024
                && manifest.package.name == "@clanker/vanilla"
                && !manifest.package.version.is_empty()
                && !manifest.entries.is_empty()
                && manifest.entries.len() <= 4096,
            "unsupported installed bundle manifest"
        );
        let installed_pin: Value =
            day2::json::decode(&regular(root, "provider-pin.json", 1_048_576)?)?;
        ensure!(
            installed_pin
                == json!({
                    "schemaVersion":1,"provider":manifest.provider,"assemblyProtocol":2,"bindingAbi":2,
                    "targets":{target:{"executable":"bin/clanker-ui","digest":manifest.executable.digest}}
                }),
            "installed provider pin must name only the reviewed manifest executable"
        );
        self.operator_pin = Some(root.canonicalize()?.join("provider-pin.json"));
        let executable = regular(root, &manifest.executable.path, 64 * 1024 * 1024)?;
        ensure!(
            executable.len() == manifest.executable.bytes
                && sha(&executable) == manifest.executable.digest,
            "bundle executable mismatch"
        );
        // Recreate the generic operator pin from approved captured executable bytes.
        // The app lock does not authorize any executable or fetch any dependency.
        let adapter = self.stage.path().join("adapter");
        fs::write(&adapter, executable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700))?;
        }
        let pin = self.stage.path().join("provider-pin.json");
        fs::write(
            &pin,
            serde_json::to_vec(&json!({
                "schemaVersion":1,"provider":manifest.provider,"assemblyProtocol":2,"bindingAbi":2,
                "targets":{target:{"executable":"adapter","digest":manifest.executable.digest}}
            }))?,
        )?;
        let mut sorted = manifest.entries.iter().collect::<Vec<_>>();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));
        let mut hash = Sha256::new();
        let mut names = BTreeSet::new();
        let mut total = 0usize;
        let mut inputs = Vec::new();
        for entry in sorted {
            ensure!(
                relative(&entry.path)
                    && names.insert(entry.path.to_ascii_lowercase())
                    && entry.bytes <= 1_048_576,
                "unsafe/colliding bundle member"
            );
            total = total
                .checked_add(entry.bytes)
                .context("bundle byte overflow")?;
            ensure!(total <= 32 * 1024 * 1024, "bundle byte budget");
            let bytes = regular(root, &format!("package/{}", entry.path), 1_048_576)?;
            ensure!(
                bytes.len() == entry.bytes && sha(&bytes) == entry.digest,
                "bundle package member mismatch"
            );
            write(
                &self.source,
                &format!(".ui-dependencies/vanilla/{}", entry.path),
                &bytes,
            )?;
            hash.update(entry.path.as_bytes());
            hash.update([0]);
            hash.update(entry.bytes.to_string().as_bytes());
            hash.update([0]);
            hash.update(entry.digest.as_bytes());
            hash.update(b"\n");
            inputs.push(json!({"path":entry.path,"bytes":entry.bytes,"digest":entry.digest}));
        }
        ensure!(
            format!("sha256:{:x}", hash.finalize()) == manifest.package.digest,
            "bundle package manifest mismatch"
        );
        write(
            &self.source,
            "ui/ui.lock.json",
            &serde_json::to_vec_pretty(&json!({
                "schemaVersion":1,"provider":manifest.provider,
                "package":{"name":manifest.package.name,"version":manifest.package.version,
                    "path":"../.ui-dependencies/vanilla","digest":manifest.package.digest,"inputs":inputs}
            }))?,
        )?;
        self.provider_pin = Some(pin);
        Ok(())
    }

    pub fn write_files(&mut self, files: Vec<SourceFile>) -> Result<()> {
        ensure!(
            !self.written && !files.is_empty() && files.len() <= 32,
            "scaffold write state/budget"
        );
        let mut names = BTreeSet::new();
        for file in &files {
            ensure!(
                relative(&file.path)
                    && names.insert(file.path.to_ascii_lowercase())
                    && file.content.len() <= 128_000
                    && ["roc", "md", "html", "css"].contains(
                        &Path::new(&file.path)
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("")
                    )
                    && !file.path.starts_with(".ui-dependencies/")
                    && file.path != "model-identities.json",
                "unsafe scaffold file or budget"
            );
        }
        for file in files {
            write(&self.source, &file.path, file.content.as_bytes())?;
        }
        self.written = true;
        Ok(())
    }

    pub fn identity(&mut self, table: &str, roc_type: &str) -> Result<()> {
        ensure!(self.written && !self.identified, "identity authoring state");
        day2::identity::register_model(&self.source, table, roc_type)?;
        self.identified = true;
        Ok(())
    }

    pub fn check_build_source(&mut self, source: &Path) -> Result<()> {
        ensure!(
            self.identified && self.build_input.is_none() && source.canonicalize()? == self.source,
            "build must use identified captured app exactly once"
        );
        self.build_input = Some(tree_digest(&self.source)?);
        Ok(())
    }

    /// Called only by the ordinary native build adapter after its verified build succeeds.
    pub fn built(&mut self, artifact: &Path) -> Result<()> {
        ensure!(
            self.build_input.as_deref() == Some(tree_digest(&self.source)?.as_str()),
            "scaffold changed during build"
        );
        let loaded = day2::artifact::LoadedArtifact::load(artifact)?;
        ensure!(
            loaded.contract().namespace == self.name,
            "created artifact namespace mismatch"
        );
        self.verified_artifact = Some(artifact.to_path_buf());
        Ok(())
    }

    pub fn publish(&mut self, artifact: &Path) -> Result<Value> {
        ensure!(
            self.verified_artifact.as_deref() == Some(artifact),
            "ordinary verified build required before publication"
        );
        ensure!(
            self.build_input.as_deref() == Some(tree_digest(&self.source)?.as_str()),
            "scaffold changed after build"
        );
        let leaf = self
            .destination
            .file_name()
            .context("publication destination")?;
        let staged = self
            .stage
            .path()
            .file_name()
            .context("publication staging")?;
        // Anchored same-parent atomic directory publication. No check-then-rename overwrite.
        self.parent.sync_all()?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        rustix::fs::renameat_with(
            &self.parent,
            Path::new(staged).join("app"),
            &self.parent,
            leaf,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("atomic no-clobber app publication unavailable");
        Ok(
            json!({"source":self.destination,"artifact":artifact,"ui_provider":self.provider_pin.is_some(),"operator_pin":self.operator_pin,"operator_pin_environment":"DAY2_UI_PROVIDER_PIN_JSON","next":["day2 platform local-dev ."]}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // macOS's default temporary directory can traverse /var -> /private/var.
    // Test fixtures use the real parent; production still rejects link ancestors.
    fn private_test_root() -> Result<tempfile::TempDir> {
        Ok(tempfile::tempdir_in(std::env::temp_dir().canonicalize()?)?)
    }

    fn options(destination: PathBuf) -> Options {
        Options {
            destination,
            name: "starter".into(),
            ui: "none".into(),
            bundle: "".into(),
            bundle_sha256: "".into(),
        }
    }

    #[test]
    fn fresh_destination_and_rollback() -> Result<()> {
        let root = private_test_root()?;
        let output = root.path().join("app");
        let session = Session::begin(options(output.clone()))?;
        let staging = session.stage.path().to_path_buf();
        assert!(!output.exists());
        drop(session);
        assert!(!staging.exists());
        fs::create_dir(&output)?;
        fs::write(output.join("keep"), "unchanged")?;
        assert!(Session::begin(options(output.clone())).is_err());
        assert_eq!(fs::read_to_string(output.join("keep"))?, "unchanged");
        Ok(())
    }

    #[test]
    fn unsafe_sources_and_unverified_publication_fail() -> Result<()> {
        let root = private_test_root()?;
        let output = root.path().join("app");
        let mut session = Session::begin(options(output.clone()))?;
        for path in [
            "../escape.roc",
            "/absolute.roc",
            "a//b.roc",
            "a/./b.roc",
            "a\\b.roc",
            "build.sh",
            "model-identities.json",
        ] {
            assert!(
                session
                    .write_files(vec![SourceFile {
                        path: path.into(),
                        content: "x".into()
                    }])
                    .is_err()
            );
        }
        assert!(session.publish(Path::new("fake-artifact")).is_err());
        assert!(!output.exists());
        Ok(())
    }

    #[test]
    fn case_collisions_and_invalid_names_fail_before_write() -> Result<()> {
        let root = private_test_root()?;
        let mut session = Session::begin(options(root.path().join("app")))?;
        assert!(
            session
                .write_files(vec![
                    SourceFile {
                        path: "A.roc".into(),
                        content: "a".into()
                    },
                    SourceFile {
                        path: "a.roc".into(),
                        content: "b".into()
                    }
                ])
                .is_err()
        );
        assert!(!session.source.join("A.roc").exists());
        let mut bad = options(root.path().join("bad"));
        bad.name = "../bad".into();
        assert!(Session::begin(bad).is_err());
        Ok(())
    }

    fn bundle_fixture(root: &Path, package_name: &str) -> Result<String> {
        fs::create_dir_all(root.join("bin"))?;
        fs::create_dir_all(root.join("package"))?;
        let executable = b"capture-only fixture, never executed";
        let package = b"opaque fixture package bytes";
        fs::write(root.join("bin/clanker-ui"), executable)?;
        fs::write(root.join("package/ui-package.json"), package)?;
        let digest = sha(package);
        let mut hash = Sha256::new();
        hash.update(format!("ui-package.json\0{}\0{}\n", package.len(), digest).as_bytes());
        let target = if std::env::consts::OS == "macos" {
            "macos-aarch64"
        } else {
            "linux-x86_64"
        };
        let manifest = json!({
            "schemaVersion":1,"target":target,"toolVersion":"0.1.0","sourceRevision":"a".repeat(40),
            "provider":"clanker-ui.native","assemblyProtocol":2,"bindingAbi":2,"templateEngine":"minijinja-2.12.0",
            "executable":{"path":"bin/clanker-ui","bytes":executable.len(),"digest":sha(executable)},
            "package":{"name":package_name,"version":"0.7.0","digest":format!("sha256:{:x}",hash.finalize())},
            "entries":[{"path":"ui-package.json","bytes":package.len(),"digest":digest}]
        });
        let bytes = serde_json::to_vec(&manifest)?;
        fs::write(root.join("manifest.json"), &bytes)?;
        fs::write(
            root.join("provider-pin.json"),
            serde_json::to_vec(&json!({
                "schemaVersion":1,"provider":"clanker-ui.native","assemblyProtocol":2,"bindingAbi":2,
                "targets":{target:{"executable":"bin/clanker-ui","digest":sha(executable)}}
            }))?,
        )?;
        Ok(sha(&bytes))
    }

    #[test]
    fn approved_bundle_capture_is_offline_exact_and_outside_ui() -> Result<()> {
        let root = private_test_root()?;
        let bundle = root.path().join("installed");
        let approval = bundle_fixture(&bundle, "@clanker/vanilla")?;
        let mut settings = options(root.path().join("app"));
        settings.ui = "clanker".into();
        settings.bundle = bundle.display().to_string();
        settings.bundle_sha256 = approval;
        let session = Session::begin(settings)?;
        assert_eq!(
            fs::read(
                session
                    .source
                    .join(".ui-dependencies/vanilla/ui-package.json")
            )?,
            b"opaque fixture package bytes"
        );
        assert!(!session.source.join("ui/provider-package").exists());
        let lock: Value = day2::json::decode(&fs::read(session.source.join("ui/ui.lock.json"))?)?;
        assert_eq!(lock["schemaVersion"], 1);
        assert_eq!(lock["package"]["name"], "@clanker/vanilla");
        assert_eq!(lock["package"]["path"], "../.ui-dependencies/vanilla");
        assert_eq!(session.operator_pin, Some(bundle.join("provider-pin.json")));
        assert!(session.provider_pin.as_ref().unwrap().is_file());
        assert!(!root.path().join("app").exists());
        Ok(())
    }

    #[test]
    fn bundle_approval_tampering_and_nonvanilla_are_refused() -> Result<()> {
        let root = private_test_root()?;
        let bundle = root.path().join("installed");
        let approval = bundle_fixture(&bundle, "@clanker/vanilla")?;
        let make = |sha: String| Options {
            destination: root.path().join("app"),
            name: "starter".into(),
            ui: "clanker".into(),
            bundle: bundle.display().to_string(),
            bundle_sha256: sha,
        };
        assert!(Session::begin(make(sha(b"wrong"))).is_err());
        fs::write(bundle.join("bin/clanker-ui"), b"tampered")?;
        assert!(Session::begin(make(approval)).is_err());
        let approval = bundle_fixture(&bundle, "not-vanilla")?;
        assert!(Session::begin(make(approval)).is_err());
        let approval = bundle_fixture(&bundle, "@clanker/vanilla")?;
        fs::write(bundle.join("package/ui-package.json"), b"tampered")?;
        assert!(Session::begin(make(approval)).is_err());
        let approval = bundle_fixture(&bundle, "@clanker/vanilla")?;
        fs::write(bundle.join("provider-pin.json"), b"{}")?;
        assert!(Session::begin(make(approval)).is_err());
        assert!(!root.path().join("app").exists());
        Ok(())
    }

    #[test]
    fn publication_is_atomic_and_refuses_a_racing_destination() -> Result<()> {
        let root = private_test_root()?;
        for race in [false, true] {
            let output = root.path().join(if race { "raced" } else { "fresh" });
            let mut session = Session::begin(options(output.clone()))?;
            session.write_files(vec![SourceFile {
                path: "README.md".into(),
                content: "captured".into(),
            }])?;
            // Test-only direct state injection isolates the native rename boundary;
            // production can set these fields only after the ordinary build adapter.
            session.build_input = Some(tree_digest(&session.source)?);
            session.verified_artifact = Some(PathBuf::from("verified-test-artifact"));
            if race {
                fs::create_dir(&output)?;
                fs::write(output.join("keep"), "racer")?;
            }
            let result = session.publish(Path::new("verified-test-artifact"));
            if race {
                assert!(result.is_err());
                assert_eq!(fs::read_to_string(output.join("keep"))?, "racer");
            } else {
                result?;
                assert_eq!(fs::read_to_string(output.join("README.md"))?, "captured");
            }
        }
        Ok(())
    }

    #[test]
    fn post_build_source_mutation_refuses_publication() -> Result<()> {
        let root = private_test_root()?;
        let mut session = Session::begin(options(root.path().join("app")))?;
        session.write_files(vec![SourceFile {
            path: "README.md".into(),
            content: "captured".into(),
        }])?;
        session.build_input = Some(tree_digest(&session.source)?);
        session.verified_artifact = Some(PathBuf::from("verified-test-artifact"));
        fs::write(session.source.join("README.md"), "changed")?;
        assert!(
            session
                .publish(Path::new("verified-test-artifact"))
                .is_err()
        );
        assert!(!root.path().join("app").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_ancestors_and_destination_are_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = private_test_root()?;
        symlink(root.path(), root.path().join("alias"))?;
        assert!(Session::begin(options(root.path().join("alias/app"))).is_err());
        symlink(root.path().join("missing"), root.path().join("output"))?;
        assert!(Session::begin(options(root.path().join("output"))).is_err());
        assert!(Session::begin(options(root.path().join("../escape"))).is_err());
        Ok(())
    }
}
