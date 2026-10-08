//! Atomic authoring capabilities; recipe, UI policy and scaffold text live in Roc.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
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
    legal: Vec<Entry>,
}

mod bundle;
pub(crate) mod core;
#[cfg(test)]
mod evidence_tests;
#[cfg(test)]
pub(crate) mod simulation;
#[cfg(test)]
mod state_machine;

use core::{Admission, Creation, Node, Ports, Snapshot};

pub struct Session {
    pub source: PathBuf,
    pub provider_pin: Option<PathBuf>,
    engine: Creation<Native>,
}

struct Native {
    stage: tempfile::TempDir,
    parent: fs::File,
    destination: PathBuf,
    source: PathBuf,
    provider_pin: Option<PathBuf>,
    operator_pin: Option<PathBuf>,
}

pub(crate) fn sha(bytes: &[u8]) -> String {
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

// Native enumeration debits bounds before allocating; the shared evidence guard
// checks the complete snapshot again. Neither adapter silently truncates state.
fn snapshot(root: &Path) -> Result<Snapshot> {
    fn visit(
        root: &Path,
        prefix: &str,
        snapshot: &mut Snapshot,
        count: &mut usize,
        total: &mut usize,
    ) -> Result<()> {
        ensure!(prefix.split('/').count() <= 10, "scaffold tree depth");
        for entry in fs::read_dir(root.join(prefix))? {
            *count += 1;
            ensure!(*count <= 8192, "scaffold tree entry budget");
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("scaffold filename")?;
            let path = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            ensure!(relative(&path), "scaffold tree path/depth");
            let kind = entry.file_type()?;
            let node = if kind.is_symlink() {
                Node::Link
            } else if kind.is_dir() {
                Node::Directory
            } else if kind.is_file() {
                let bytes = regular(root, &path, 1_048_576)?;
                *total = total
                    .checked_add(bytes.len())
                    .context("scaffold tree bytes")?;
                ensure!(*total <= 64 * 1024 * 1024, "scaffold tree byte budget");
                Node::File(bytes)
            } else {
                Node::Special
            };
            ensure!(!matches!(node, Node::Link), "scaffold tree symlink");
            ensure!(!matches!(node, Node::Special), "scaffold tree special file");
            let directory = matches!(node, Node::Directory);
            snapshot.0.insert(path.clone(), node);
            if directory {
                visit(root, &path, snapshot, count, total)?;
            }
        }
        Ok(())
    }
    no_links(root)?;
    let mut snapshot = Snapshot::default();
    visit(root, "", &mut snapshot, &mut 0, &mut 0)?;
    snapshot.digest()?;
    Ok(snapshot)
}

#[cfg(test)]
fn tree_digest(root: &Path) -> Result<String> {
    snapshot(root)?.digest()
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

impl Native {
    fn begin(options: Options) -> Result<Self> {
        core::validate_options(&options)?;
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
        };
        if options.ui == "clanker" {
            session.capture_bundle(Path::new(&options.bundle), &options.bundle_sha256)?;
        }
        Ok(session)
    }

    fn capture_bundle(&mut self, root: &Path, approval: &str) -> Result<()> {
        struct Reader<'a>(&'a Path);

        impl bundle::Reader for Reader<'_> {
            fn read(&self, path: &str, budget: u64) -> Result<Vec<u8>> {
                regular(self.0, path, budget)
            }
        }
        no_links(root)?;
        let target = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "linux-x86_64",
            ("macos", "aarch64") => "macos-aarch64",
            _ => anyhow::bail!("installed bundle host unsupported"),
        };
        let capture = bundle::capture(&Reader(root), approval, target)?;
        for (path, bytes) in capture.files {
            write(&self.source, &path, &bytes)?;
        }
        self.operator_pin = Some(root.canonicalize()?.join("provider-pin.json"));
        // Only the closed approved executable is recreated, not app authority.
        let adapter = self.stage.path().join("adapter");
        fs::write(&adapter, capture.executable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&adapter, fs::Permissions::from_mode(0o700))?;
        }
        let pin = self.stage.path().join("provider-pin.json");
        fs::write(&pin, capture.pin)?;
        self.provider_pin = Some(pin);
        Ok(())
    }
}

impl Session {
    pub fn begin(options: Options) -> Result<Self> {
        let name = options.name.clone();
        let port = Native::begin(options)?;
        let source = port.source.clone();
        let provider_pin = port.provider_pin.clone();
        Ok(Self {
            source: source.clone(),
            provider_pin,
            engine: Creation::new(name, source, port)?,
        })
    }

    pub fn write_files(&mut self, files: Vec<SourceFile>) -> Result<()> {
        self.engine.write_files(files)
    }

    pub fn identity(
        &mut self,
        table: &str,
        roc_type: &str,
        entropy: &dyn day2::host_inputs::Entropy,
    ) -> Result<()> {
        self.engine.identity(table, roc_type, entropy)
    }

    pub fn check_build_source(&mut self, source: &Path) -> Result<()> {
        self.engine.check_build_source(source)
    }

    /// Called only by the ordinary native build adapter after its verified build succeeds.
    pub fn built(&mut self, artifact: &Path) -> Result<()> {
        self.engine.built(artifact)
    }

    pub fn publish(&mut self, artifact: &Path) -> Result<Value> {
        self.engine.publish(artifact)
    }
}

impl Ports for Native {
    fn snapshot(&self) -> Result<Snapshot> {
        snapshot(&self.source)
    }

    fn resolve_source(&self, source: &Path) -> Result<PathBuf> {
        no_links(source)?;
        Ok(source.canonicalize()?)
    }

    fn write(&mut self, files: &std::collections::BTreeMap<String, Vec<u8>>) -> Result<()> {
        for (path, bytes) in files {
            if path == day2::identity::REGISTRY_FILE {
                // Preserve the native registry's atomic no-clobber authoring
                // boundary; bytes and entropy decisions belong to the pure core.
                let mut temporary = tempfile::NamedTempFile::new_in(&self.source)?;
                temporary.write_all(bytes)?;
                temporary.as_file().sync_all()?;
                temporary.persist_noclobber(self.source.join(path))?;
            } else {
                write(&self.source, path, bytes)?;
            }
        }
        Ok(())
    }

    fn admit(&self, artifact: &Path) -> Result<Admission> {
        let loaded = day2::artifact::LoadedArtifact::load(artifact)?;
        Ok(Admission {
            artifact: artifact.to_path_buf(),
            identity: loaded.id().to_owned(),
            namespace: loaded.contract().namespace.clone(),
        })
    }

    fn publish(&mut self, artifact: &Path) -> Result<Value> {
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
        let staging = session.engine.port.stage.path().to_path_buf();
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
        for path in [
            "../escape.roc",
            "/absolute.roc",
            "a//b.roc",
            "a/./b.roc",
            "a\\b.roc",
            "build.sh",
            "model-identities.json",
        ] {
            let mut session = Session::begin(options(output.clone()))?;
            let error = session
                .write_files(vec![SourceFile {
                    path: path.into(),
                    content: "x".into(),
                }])
                .unwrap_err();
            assert!(
                error.to_string().contains("unsafe scaffold file or budget"),
                "{path}: {error}"
            );
            assert!(!output.exists());
        }
        let mut session = Session::begin(options(output.clone()))?;
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
        fs::create_dir_all(root.join("legal"))?;
        let license = b"opaque fixture project legal bytes";
        let notices = b"opaque fixture third-party legal bytes";
        fs::write(root.join("legal/LICENSE"), license)?;
        fs::write(root.join("legal/NOTICES.txt"), notices)?;
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
            "entries":[{"path":"ui-package.json","bytes":package.len(),"digest":digest}],
            "legal":[
                {"path":"legal/LICENSE","bytes":license.len(),"digest":sha(license)},
                {"path":"legal/NOTICES.txt","bytes":notices.len(),"digest":sha(notices)}
            ]
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
    fn scaffold_tree_entry_budget_is_checked_before_listing_allocation() -> Result<()> {
        let root = private_test_root()?;
        for index in 0..8192 {
            fs::write(root.path().join(format!("input-{index}")), b"x")?;
        }
        assert!(tree_digest(root.path()).is_ok());
        fs::write(root.path().join("one-too-many"), b"x")?;
        let error = tree_digest(root.path()).unwrap_err();
        assert!(error.to_string().contains("scaffold tree entry budget"));
        Ok(())
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
        assert_eq!(
            session.engine.port.operator_pin,
            Some(bundle.join("provider-pin.json"))
        );
        assert!(session.provider_pin.as_ref().unwrap().is_file());
        assert!(!root.path().join("app").exists());
        Ok(())
    }

    #[test]
    fn bundle_legal_capture_preserves_notices_without_changing_package_inputs() -> Result<()> {
        let root = private_test_root()?;
        let bundle = root.path().join("installed");
        let approval = bundle_fixture(&bundle, "@clanker/vanilla")?;
        let session = Session::begin(Options {
            destination: root.path().join("app"),
            name: "starter".into(),
            ui: "clanker".into(),
            bundle: bundle.display().to_string(),
            bundle_sha256: approval,
        })?;
        for name in ["LICENSE", "NOTICES.txt"] {
            assert_eq!(
                fs::read(session.source.join(".ui-dependencies/legal").join(name))?,
                fs::read(bundle.join("legal").join(name))?
            );
        }
        assert!(!session.source.join("ui/legal").exists());
        assert!(
            !session
                .source
                .join(".ui-dependencies/vanilla/legal")
                .exists()
        );
        let manifest: Value = day2::json::decode(&fs::read(bundle.join("manifest.json"))?)?;
        let lock: Value = day2::json::decode(&fs::read(session.source.join("ui/ui.lock.json"))?)?;
        assert_eq!(lock["package"]["digest"], manifest["package"]["digest"]);
        assert_eq!(lock["package"]["inputs"], manifest["entries"]);
        assert_eq!(lock["package"]["inputs"].as_array().unwrap().len(), 1);
        Ok(())
    }

    #[test]
    fn bundle_legal_shape_and_byte_failures_refuse_publication() -> Result<()> {
        let root = private_test_root()?;
        for mutation in 0..13 {
            let bundle = root.path().join(format!("installed-{mutation}"));
            bundle_fixture(&bundle, "@clanker/vanilla")?;
            let path = bundle.join("manifest.json");
            let mut manifest: Value = day2::json::decode(&fs::read(&path)?)?;
            match mutation {
                0 => {
                    manifest.as_object_mut().unwrap().remove("legal");
                }
                1 => manifest["legal"] = json!([]),
                2 => {
                    let extra = manifest["legal"][0].clone();
                    manifest["legal"].as_array_mut().unwrap().push(extra);
                }
                3 => manifest["legal"].as_array_mut().unwrap().swap(0, 1),
                4 => manifest["legal"][0]["path"] = "../LICENSE".into(),
                5 => manifest["legal"][0]["path"] = "legal/license".into(),
                6 => manifest["legal"][0]["bytes"] = 0.into(),
                7 => manifest["legal"][0]["bytes"] = (1_048_576 + 1).into(),
                8 => fs::write(bundle.join("legal/NOTICES.txt"), b"tampered")?,
                9 => manifest["legal"][1]["digest"] = sha(b"wrong").into(),
                10 => fs::remove_file(bundle.join("legal/LICENSE"))?,
                11 => manifest["legal"][0]["unknown"] = true.into(),
                12 => {
                    manifest["legal"][1]["bytes"] = 1_048_577.into();
                    fs::write(bundle.join("legal/NOTICES.txt"), vec![b'x'; 1_048_577])?;
                }
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&manifest)?;
            fs::write(path, &bytes)?;
            let output = root.path().join(format!("app-{mutation}"));
            // Approve the mutated manifest so the legal guard, not an unrelated
            // outer manifest checksum mismatch, must reject the selected input.
            let result = Session::begin(Options {
                destination: output.clone(),
                name: "starter".into(),
                ui: "clanker".into(),
                bundle: bundle.display().to_string(),
                bundle_sha256: sha(&bytes),
            });
            assert!(result.is_err(), "legal mutation {mutation} accepted");
            assert!(!output.exists(), "legal mutation {mutation} published");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bundle_legal_symlinks_are_refused_even_for_matching_bytes() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = private_test_root()?;
        for directory in [false, true] {
            let bundle = root.path().join(if directory { "dir" } else { "file" });
            let approval = bundle_fixture(&bundle, "@clanker/vanilla")?;
            if directory {
                fs::rename(bundle.join("legal"), bundle.join("legal-real"))?;
                symlink(bundle.join("legal-real"), bundle.join("legal"))?;
            } else {
                fs::rename(bundle.join("legal/LICENSE"), bundle.join("license-real"))?;
                symlink(bundle.join("license-real"), bundle.join("legal/LICENSE"))?;
            }
            let output = root
                .path()
                .join(if directory { "app-dir" } else { "app-file" });
            assert!(
                Session::begin(Options {
                    destination: output.clone(),
                    name: "starter".into(),
                    ui: "clanker".into(),
                    bundle: bundle.display().to_string(),
                    bundle_sha256: approval,
                })
                .is_err()
            );
            assert!(!output.exists());
        }
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
            // Isolate the unchanged atomic native rename port, just as the
            // original test's injected build state did. The shared guard itself
            // is exercised separately by the complete no-FS state-machine campaign.
            if race {
                fs::create_dir(&output)?;
                fs::write(output.join("keep"), "racer")?;
            }
            let result = session
                .engine
                .port
                .publish(Path::new("verified-test-artifact"));
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
        session.engine.test_built(Admission {
            artifact: PathBuf::from("verified-test-artifact"),
            identity: "test-artifact".into(),
            namespace: "starter".into(),
        })?;
        fs::write(session.source.join("README.md"), "changed")?;
        let error = session
            .publish(Path::new("verified-test-artifact"))
            .unwrap_err();
        assert!(error.to_string().contains("captured scaffold changed"));
        assert!(!root.path().join("app").exists());
        Ok(())
    }

    #[test]
    fn native_and_memory_identity_evidence_match_and_both_reject_capture_tamper() -> Result<()> {
        use super::simulation::{Memory, SeededEntropy};
        let root = private_test_root()?;
        let output = root.path().join("app");
        let mut native = Session::begin(options(output.clone()))?;
        let mut memory = Memory::begin(&options(output.clone()))?;
        native.write_files(super::state_machine::sources())?;
        memory.write_files(super::state_machine::sources())?;
        native.identity("starters", "Models.StarterRecord", &SeededEntropy::new(130))?;
        memory.identity("starters", "Models.StarterRecord", &SeededEntropy::new(130))?;
        let captured = memory.port.snapshot()?;
        assert_eq!(
            fs::read(native.source.join(day2::identity::REGISTRY_FILE))?,
            captured.bytes(day2::identity::REGISTRY_FILE)?
        );
        assert_eq!(native.engine.port.snapshot()?.digest()?, captured.digest()?);
        fs::write(native.source.join("README.md"), "tampered")?;
        memory
            .port
            .tree
            .0
            .insert("README.md".into(), Node::File(b"tampered".to_vec()));
        let source = native.source.clone();
        assert!(native.check_build_source(&source).is_err());
        assert!(
            memory
                .check_build_source(Path::new("/captured-source"))
                .is_err()
        );
        assert!(!output.exists());
        assert_eq!(memory.port.publications, 0);
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
