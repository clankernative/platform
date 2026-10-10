//! The session against a scripted kubectl (a fake pod filesystem on disk), an
//! in-memory registry serving a real gzip layer, and a scripted prompt.
use super::*;
use std::{cell::RefCell, rc::Rc};

const NAMESPACE: &str = "app-example";
const STATEFULSET: &str = "day2-example";

struct Image {
    reference: String,
    artifact_id: String,
    blobs: BTreeMap<String, Vec<u8>>,
}

/// An app image whose single layer holds `srv/day2/artifacts/<id>/`.
fn image(worker: &[u8], extra: Option<(&str, tar::EntryType)>) -> Image {
    let manifest = json!({"format": 1, "worker_digest": day2::digest(worker)});
    let artifact_json = serde_json::to_vec(&manifest).unwrap();
    let artifact_id = day2::digest(&artifact_json)
        .trim_start_matches("sha256:")
        .to_owned();
    let mut builder = tar::Builder::new(Vec::new());
    let mut add = |path: &str, bytes: &[u8], kind: tar::EntryType| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(bytes.len() as u64);
        header.set_mode(if kind.is_dir() { 0o555 } else { 0o444 });
        if kind == tar::EntryType::Symlink {
            header.set_link_name("/etc/passwd").unwrap();
        }
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    };
    let root = format!("srv/day2/artifacts/{artifact_id}");
    add(
        "srv/day2/other/ignored.txt",
        b"not the artifact",
        tar::EntryType::Regular,
    );
    add(&format!("{root}/"), b"", tar::EntryType::Directory);
    add(
        &format!("{root}/artifact.json"),
        &artifact_json,
        tar::EntryType::Regular,
    );
    add(&format!("{root}/worker"), worker, tar::EntryType::Regular);
    if let Some((name, kind)) = extra {
        add(&format!("{root}/{name}"), b"", kind);
    }
    let tar = builder.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&tar).unwrap();
    let layer = gzip.finish().unwrap();
    let layer_digest = day2::digest(&layer);
    let manifest =
        serde_json::to_vec(&json!({"schemaVersion": 2, "layers": [{"digest": layer_digest}]}))
            .unwrap();
    let manifest_digest = day2::digest(&manifest);
    Image {
        reference: format!("registry.test/day2/example@{manifest_digest}"),
        artifact_id,
        blobs: BTreeMap::from([
            (
                format!("day2/example/manifests/{manifest_digest}"),
                manifest,
            ),
            (format!("day2/example/blobs/{layer_digest}"), layer),
        ]),
    }
}

struct FakeRegistry(BTreeMap<String, Vec<u8>>);

impl Registry for FakeRegistry {
    fn get(&mut self, host: &str, path: &str, _accept: &str, limit: u64) -> Result<Vec<u8>> {
        assert_eq!(host, "registry.test");
        let bytes = self
            .0
            .get(path)
            .cloned()
            .with_context(|| format!("no {path}"))?;
        ensure!(bytes.len() as u64 <= limit, "limit");
        Ok(bytes)
    }
}

struct FakePrompt {
    answer: bool,
    asked: Rc<RefCell<usize>>,
}

impl Prompt for FakePrompt {
    fn confirm(&mut self, _question: &str, _word: &str) -> Result<bool> {
        *self.asked.borrow_mut() += 1;
        Ok(self.answer)
    }
}

/// kubectl against a pod whose filesystem is a directory on disk.
struct FakeCluster {
    calls: Rc<RefCell<Vec<Vec<String>>>>,
    pod_root: PathBuf,
    running_image: String,
    instance: String,
    other_sessions: String,
    fail_on: Option<String>,
    drop_on_copy_out: Option<String>,
    annotations: Rc<RefCell<BTreeMap<String, String>>>,
    replicas: u64,
    /// What `authority inspect` reports the database activates.
    active_artifact: String,
    /// The bytes the in-pod backup takes of the app's store.
    store: &'static [u8],
    /// What `stat` reports for the files at the top of the state volume.
    volume: Vec<(&'static str, u64)>,
    /// Every manifest applied, in order.
    applied: Rc<RefCell<Vec<String>>>,
}

/// A store whose credential unit predates the target's schema.
const OLD_CREDENTIAL_STORE: &[u8] = b"day2_credential_schema_version=1";

impl FakeCluster {
    fn pod_path(&self, remote: &str) -> PathBuf {
        self.pod_root.join(remote.trim_start_matches('/'))
    }

    fn copy(from: &Path, to: &Path) -> Result<()> {
        if from.is_dir() {
            fs::create_dir_all(to)?;
            for entry in fs::read_dir(from)? {
                let entry = entry?;
                Self::copy(&entry.path(), &to.join(entry.file_name()))?;
            }
        } else {
            fs::create_dir_all(to.parent().unwrap())?;
            fs::write(to, fs::read(from)?)?;
        }
        Ok(())
    }

    fn sums(&self, remote: &str) -> Result<String> {
        let mut out = String::new();
        for (relative, digest) in local_manifest(&self.pod_path(remote))? {
            out.push_str(&format!(
                "{}  {remote}/{relative}\n",
                digest.trim_start_matches("sha256:")
            ));
        }
        Ok(out)
    }

    /// `day2 admit`: what the target build reports opening the store beside
    /// the instance, refusing the credential unit it does not support.
    fn admit(&self, instance: &str, app: &str) -> Result<String> {
        let instance = self.pod_path(instance);
        let store = fs::read(
            instance
                .parent()
                .unwrap()
                .join(".state")
                .join(format!("{app}.sqlite")),
        )?;
        ensure!(
            store != OLD_CREDENTIAL_STORE,
            "Error: unsupported credential schema version"
        );
        let desired: Value = serde_json::from_slice(&fs::read(&instance)?)?;
        let artifact = desired["apps"][app]["artifact"]
            .as_str()
            .unwrap()
            .trim_start_matches("artifacts/")
            .to_owned();
        Ok(json!({"admitted": true, "scope": "exampleco/production/example_app", "artifact": format!("sha256:{artifact}")}).to_string())
    }

    fn host(&self, request: &str) -> Result<String> {
        let request: Value = serde_json::from_str(request)?;
        let args: Vec<String> = serde_json::from_str(request["input"].as_str().unwrap())?;
        let result = match args[0].as_str() {
            "backup" => {
                let output = self.pod_path(&args[3]);
                fs::create_dir_all(output.join("artifacts"))?;
                fs::write(output.join("app.sqlite"), self.store)?;
                fs::write(output.join("backup.json"), b"{}")?;
                fs::write(output.join("artifacts/marker"), b"artifact")?;
                json!({"verified": true})
            }
            "authority" if args[1] == "inspect" => json!({
                "scope": "exampleco/production/example_app",
                "active": {"stamp": {"epoch": "sha256:e", "revision": 3}, "artifact_id": self.active_artifact,
                    "document": {"readers": ["domain:example.com"], "writers": [], "policy": {"operations": {"x": {}}}}}
            }),
            "authority" => json!({"receipt": {"stamp": {"revision": 4}}, "action": args[1]}),
            other => bail!("unexpected workflow {other}"),
        };
        Ok(
            json!({"protocol": 1, "ok": true, "result": result.to_string(), "error": ""})
                .to_string(),
        )
    }
}

impl Cluster for FakeCluster {
    fn kubectl(
        &mut self,
        args: &[String],
        stdin: Option<&[u8]>,
        _timeout: Duration,
    ) -> Result<String> {
        self.calls.borrow_mut().push(args.to_vec());
        assert_eq!(&args[..2], ["-n", NAMESPACE]);
        if args[2] == "apply" {
            let manifest = String::from_utf8(stdin.unwrap_or_default().to_vec())?;
            self.applied.borrow_mut().push(manifest);
        }
        let joined = args.join(" ");
        if let Some(fail) = &self.fail_on
            && joined.contains(fail.as_str())
        {
            bail!("injected failure at {fail}");
        }
        let args: Vec<&str> = args[2..].iter().map(String::as_str).collect();
        Ok(match args.as_slice() {
            ["get", "statefulset", STATEFULSET, "-o", "json"] => json!({
                "metadata": {"annotations": *self.annotations.borrow()},
                "spec": {"replicas": self.replicas, "template": {"spec": {"containers": [{"image": self.running_image}]}}}
            })
            .to_string(),
            ["annotate", "--overwrite", "statefulset", STATEFULSET, annotation] => {
                let (key, value) = annotation.split_once('=').unwrap();
                self.annotations
                    .borrow_mut()
                    .insert(key.to_owned(), value.to_owned());
                String::new()
            }
            ["get", "pods", "-l", MAINTENANCE_LABEL, "-o", "name"] => self.other_sessions.clone(),
            ["scale", "statefulset", STATEFULSET, replicas] => {
                self.replicas = replicas.trim_start_matches("--replicas=").parse()?;
                String::new()
            }
            ["get", "configmap", _, "-o", "json"] => json!({"data": {"instance.json": self.instance}}).to_string(),
            ["get", "pod", _, "--ignore-not-found", "-o", "name"] => String::new(),
            ["get", "pod", _, "-o", "json"] => json!({"status": {"conditions": [{"type": "PodScheduled", "status": "False",
                "message": "0/3 nodes are available: 3 Insufficient ephemeral-storage."}]}})
            .to_string(),
            ["scale" | "apply" | "wait" | "delete" | "rollout", ..] => String::new(),
            ["cp", "--retries=5", from, to] => {
                if let Some((_, remote)) = to.split_once(':') {
                    Self::copy(Path::new(from), &self.pod_path(remote))?;
                } else {
                    let (_, remote) = from.split_once(':').unwrap();
                    Self::copy(&self.pod_path(remote), Path::new(to))?;
                    if let Some(name) = &self.drop_on_copy_out {
                        fs::remove_file(Path::new(to).join(name))?;
                    }
                }
                String::new()
            }
            ["exec", _, "--", "mkdir", "-p", path] => {
                fs::create_dir_all(self.pod_path(path))?;
                String::new()
            }
            ["exec", _, "--", "mkdir", paths @ ..] => {
                for path in paths {
                    fs::create_dir(self.pod_path(path))?;
                }
                String::new()
            }
            ["exec", _, "--", "cp", from, to] => {
                Self::copy(&self.pod_path(from), &self.pod_path(to))?;
                String::new()
            }
            ["exec", _, "--", "rm", "-rf", paths @ ..] => {
                for path in paths {
                    fs::remove_dir_all(self.pod_path(path))?;
                }
                String::new()
            }
            ["exec", _, "--", "mv", from, to] => {
                fs::rename(self.pod_path(from), self.pod_path(to))?;
                String::new()
            }
            ["exec", _, "--", DAY2, "admit", instance, app] => self.admit(instance, app)?,
            ["exec", pod, "--", "find", STATE, "-maxdepth", "1", "-type", "f", "-exec", "stat", "-c", "%s %n", "{}", "+"] => {
                assert!(pod.ends_with("-measure"), "measured from the probe");
                self.volume
                    .iter()
                    .map(|(name, size)| format!("{size} {STATE}/{name}\n"))
                    .collect()
            }
            ["exec", _, "--", "find", root, ..] => self.sums(root)?,
            ["exec", _, "--", "sha256sum", file] => {
                format!("{}  {file}\n", day2::digest(&fs::read(self.pod_path(file))?).trim_start_matches("sha256:"))
            }
            ["exec", _, "--", HOST, request] => self.host(request)?,
            ["exec", _, "--", DAY2, "migration-plan", .., plan] => {
                fs::write(self.pod_path(plan), br#"{"format":1,"add_nullable_text":[]}"#)?;
                String::new()
            }
            ["exec", _, "--", DAY2, "migration-apply", ..] => r#"{"applied":true}"#.into(),
            ["exec", _, "--", "cat", file] => fs::read_to_string(self.pod_path(file))?,
            other => bail!("unexpected kubectl {other:?}"),
        })
    }
}

struct Harness {
    directory: tempfile::TempDir,
    calls: Rc<RefCell<Vec<Vec<String>>>>,
    annotations: Rc<RefCell<BTreeMap<String, String>>>,
    asked: Rc<RefCell<usize>>,
    applied: Rc<RefCell<Vec<String>>>,
    running: Image,
    target: Image,
}

impl Harness {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().unwrap(),
            calls: Rc::default(),
            annotations: Rc::default(),
            asked: Rc::default(),
            applied: Rc::default(),
            running: image(b"old worker", None),
            target: image(b"new worker", None),
        }
    }

    fn instance(artifact: &str) -> String {
        json!({"apps": {"example_app": {"artifact": format!("artifacts/{artifact}")}}}).to_string()
    }

    fn request(&self, operation: Operation) -> PathBuf {
        let target_file = self.directory.path().join("target-instance.json");
        fs::write(&target_file, Self::instance(&self.target.artifact_id)).unwrap();
        let mut request = json!({
            "namespace": NAMESPACE, "statefulset": STATEFULSET, "configmap": "day2-example-instance",
            "app": "example_app", "pvc": "data",
            "app_image": self.running.reference, "artifact_id": self.running.artifact_id,
            "tooling_image": "registry.test/day2/tooling@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "operator": "ops@example.com",
            "pod_label": {"key": "platform.example.com/service", "value": "background"},
            "backup_dir": self.directory.path().join("backups"),
        });
        if operation == Operation::AuthorityApply || operation.targeted() {
            request["request_id"] = "release-1".into();
        }
        if operation.targeted() {
            request["target"] = json!({"instance": target_file, "app_image": self.target.reference,
                "artifact_id": self.target.artifact_id});
        }
        let path = self.directory.path().join("request.json");
        fs::write(&path, request.to_string()).unwrap();
        path
    }

    fn tools(&self, configure: impl FnOnce(&mut FakeCluster), answer: bool) -> Tools {
        let mut blobs = self.running.blobs.clone();
        blobs.extend(self.target.blobs.clone());
        let mut cluster = FakeCluster {
            calls: self.calls.clone(),
            pod_root: self.directory.path().join("pod"),
            running_image: self.running.reference.clone(),
            instance: Self::instance(&self.running.artifact_id),
            other_sessions: String::new(),
            fail_on: None,
            drop_on_copy_out: None,
            annotations: self.annotations.clone(),
            replicas: 1,
            active_artifact: "sha256:a".into(),
            store: b"database",
            volume: vec![
                ("example_app.sqlite", 8),
                ("example_app.sqlite-shm", 32_768),
                ("unrelated.bin", 1 << 40),
            ],
            applied: self.applied.clone(),
        };
        configure(&mut cluster);
        Tools {
            cluster: Box::new(cluster),
            registry: Box::new(FakeRegistry(blobs)),
            prompt: Box::new(FakePrompt {
                answer,
                asked: self.asked.clone(),
            }),
        }
    }

    fn open(
        &self,
        operation: Operation,
        configure: impl FnOnce(&mut FakeCluster),
        answer: bool,
    ) -> Result<Session> {
        Session::open(
            operation.name(),
            &self.request(operation),
            self.tools(configure, answer),
        )
    }

    fn verbs(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .map(|call| match call[2].as_str() {
                "exec" => format!("exec {}", call[5].rsplit('/').next().unwrap()),
                "scale" => format!("scale {}", call[5]),
                "delete" if call[4].ends_with("-measure") => "delete probe".to_owned(),
                verb => verb.to_owned(),
            })
            .collect()
    }

    fn scaled_up(&self) -> bool {
        self.verbs().iter().any(|verb| verb == "scale --replicas=1")
    }

    fn deleted_pod(&self) -> bool {
        self.verbs().iter().any(|verb| verb == "delete")
    }

    fn journal(&self) -> Vec<String> {
        let backups = self.directory.path().join("backups");
        let file = fs::read_dir(&backups)
            .unwrap()
            .flatten()
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".session.json")
            })
            .unwrap();
        let journal: Value = serde_json::from_slice(&fs::read(file.path()).unwrap()).unwrap();
        journal["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["step"].as_str().unwrap().to_owned())
            .collect()
    }
}

fn prepare(session: &mut Session) -> Result<()> {
    session.artifacts()?;
    session.stop()?;
    session.measure()?;
    session.start_pod()?;
    Ok(())
}

#[test]
fn inspect_stops_runs_and_restores_the_app() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Inspect, |_| {}, true)?;
    prepare(&mut session)?;
    let summary = session.workflow("authority-inspect")?;
    assert_eq!(summary["stamp"]["revision"], 3);
    ensure!(
        session.workflow("backup").is_err(),
        "inspect takes no backup"
    );
    let receipt = session.finish()?;
    assert_eq!(receipt["replicas_restored"], true);
    drop(session);
    let verbs = harness.verbs();
    let position = |verb: &str| verbs.iter().position(|v| v == verb).unwrap();
    assert!(position("scale --replicas=0") < position("apply"));
    assert!(position("apply") < position("exec day2-host"));
    assert!(position("delete") < position("scale --replicas=1"));
    assert_eq!(*harness.asked.borrow(), 0);
    assert_eq!(harness.journal().last().map(String::as_str), Some("finish"));
    Ok(())
}

#[test]
fn backup_copies_a_verified_private_bundle() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Backup, |_| {}, true)?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    let copied = session.copy_backup()?;
    let directory = PathBuf::from(copied["backup"].as_str().unwrap());
    assert!(directory.join("app.sqlite").is_file() && directory.join("instance.json").is_file());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&directory)?.permissions().mode() & 0o777,
        0o700
    );
    session.finish()?;
    drop(session);
    assert!(harness.scaled_up() && harness.deleted_pod());
    Ok(())
}

#[test]
fn a_truncated_backup_copy_is_refused_and_marked_incomplete() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Backup,
        |cluster| cluster.drop_on_copy_out = Some("app.sqlite".into()),
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    let error = session.copy_backup().unwrap_err();
    assert!(format!("{error:#}").contains("differs"));
    ensure!(
        session.finish().is_err(),
        "a backup without a verified copy cannot finish"
    );
    drop(session);
    let names: Vec<String> = fs::read_dir(harness.directory.path().join("backups"))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().any(|name| name.ends_with(".INCOMPLETE")),
        "{names:?}"
    );
    assert!(harness.scaled_up() && harness.deleted_pod());
    assert_eq!(
        harness.journal().last().map(String::as_str),
        Some("aborted")
    );
    Ok(())
}

#[test]
fn a_failure_before_the_fence_removes_the_pod_and_restores_the_app() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| cluster.fail_on = Some("migration-plan".into()),
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    ensure!(session.migration("plan").is_err(), "injected");
    ensure!(session.mark_activated().is_err(), "nothing was activated");
    drop(session);
    assert!(harness.deleted_pod() && harness.scaled_up());
    assert!(harness.annotations.borrow().is_empty());
    Ok(())
}

#[test]
fn a_store_the_target_refuses_stops_activate_before_the_fence_and_restores_the_app() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| cluster.store = OLD_CREDENTIAL_STORE,
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    let error = format!("{:#}", session.admission().unwrap_err());
    assert!(
        error.starts_with("target_store_admission_refused")
            && error.contains(&harness.target.artifact_id)
            && error.contains("unsupported credential schema version"),
        "{error}"
    );
    ensure!(
        session.admission().is_err()
            && session.confirm().is_err()
            && session.fence().is_err()
            && session.migration("apply").is_err(),
        "a refused store is never confirmed, fenced or migrated"
    );
    drop(session);
    assert!(harness.deleted_pod() && harness.scaled_up());
    assert_eq!(*harness.asked.borrow(), 0);
    assert!(harness.annotations.borrow().is_empty());
    // Only the copy was migrated and activated; the instance over the app's
    // volume was never touched.
    for call in harness.calls.borrow().iter() {
        let call = call.join(" ");
        if call.contains("migration-apply") || call.contains(r#"\"activate\""#) {
            assert!(call.contains(ADMISSION_INSTANCE), "{call}");
        }
    }
    let steps = harness.journal();
    assert!(
        steps.contains(&"target-admission-refused".to_owned())
            && !steps
                .iter()
                .any(|step| step == "confirmed" || step == "fence"),
        "{steps:?}"
    );
    assert_eq!(steps.last().map(String::as_str), Some("aborted"));
    Ok(())
}

#[test]
fn after_the_fence_the_old_image_is_never_restarted() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        // Only the real activation; the rehearsal activates its copy.
        |cluster| cluster.fail_on = Some(format!(r#"\"activate\",\"{TARGET}\""#)),
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    session.admission()?;
    session.confirm()?;
    session.fence()?;
    session.migration("apply")?;
    ensure!(
        session.workflow("authority-activate").is_err(),
        "a stamp is required first"
    );
    session.workflow("authority-inspect")?;
    ensure!(session.workflow("authority-activate").is_err(), "injected");
    ensure!(
        session.mark_activated().is_err(),
        "a failed activation is never marked"
    );
    drop(session);
    assert!(harness.deleted_pod());
    assert!(harness.annotations.borrow().is_empty());
    assert!(
        !harness.scaled_up(),
        "the old image must not restart after migration"
    );
    Ok(())
}

#[test]
fn activate_leaves_the_app_stopped_for_the_new_image() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    let admitted = session.admission()?;
    assert_eq!(
        admitted["artifact"],
        format!("sha256:{}", harness.target.artifact_id)
    );
    ensure!(session.admission().is_err(), "admitted once");
    session.confirm()?;
    session.fence()?;
    session.migration("apply")?;
    ensure!(
        session.mark_activated().is_err(),
        "only a successful activation is marked"
    );
    session.workflow("authority-inspect")?;
    ensure!(
        session.finish().is_err(),
        "activate cannot finish before it is marked"
    );
    session.workflow("authority-activate")?;
    assert!(harness.annotations.borrow().is_empty());
    session.mark_activated()?;
    ensure!(session.mark_activated().is_err(), "marked once");
    let receipt = session.finish()?;
    assert_eq!(receipt["replicas_restored"], false);
    assert_eq!(receipt["target_admission"], admitted);
    drop(session);
    assert!(harness.deleted_pod() && !harness.scaled_up());
    assert_eq!(*harness.asked.borrow(), 1);
    // The rehearsal migrated and activated its copy, then removed it, before
    // the real steps ran on the instance over the app's volume.
    let calls: Vec<String> = harness
        .calls
        .borrow()
        .iter()
        .map(|call| call.join(" "))
        .collect();
    let at_call = |needle: &str| calls.iter().position(|call| call.contains(needle)).unwrap();
    assert!(
        at_call(&format!("migration-apply {ADMISSION_INSTANCE}"))
            < at_call(&format!("admit {ADMISSION_INSTANCE}"))
            && at_call(&format!("admit {ADMISSION_INSTANCE}"))
                < at_call(&format!("migration-apply {TARGET}"))
    );
    // The rehearsal moved the in-pod backup into its copy and removed both.
    let scratch: Vec<String> = fs::read_dir(harness.directory.path().join("pod/srv/day2"))?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !scratch
            .iter()
            .any(|name| name == "admission" || name.starts_with("backup-")),
        "{scratch:?}"
    );
    assert_eq!(
        *harness.annotations.borrow(),
        BTreeMap::from([(
            ACTIVATED.to_owned(),
            format!("sha256:{}", harness.target.artifact_id)
        )])
    );
    let steps = harness.journal();
    let at = |step: &str| steps.iter().position(|s| s == step).unwrap();
    assert!(
        at("backup-copied") < at("migration-plan")
            && at("migration-plan") < at("target-admission")
            && at("target-admission") < at("target-admitted")
            && at("target-admitted") < at("confirmed")
            && at("confirmed") < at("fence")
    );
    assert!(
        at("fence") < at("migration-applied")
            && at("migration-applied") < at("authority-activated")
            && at("authority-activated") < at("mark-activated")
            && at("mark-activated") < at("activation-marked")
    );
    Ok(())
}

/// The `sizeLimit` and ephemeral-storage values of an applied manifest.
fn sizes(manifest: &str) -> (String, Vec<String>) {
    let value = |line: &str, key: &str| {
        line.split_once(key).map(|(_, rest)| {
            rest.trim_start_matches(' ')
                .split([' ', ',', '}'])
                .next()
                .unwrap()
                .to_owned()
        })
    };
    let limit = manifest
        .lines()
        .find_map(|line| value(line, "sizeLimit:"))
        .unwrap();
    let ephemeral = manifest
        .lines()
        .filter_map(|line| value(line, "ephemeral-storage:"))
        .collect();
    (limit, ephemeral)
}

#[test]
fn scratch_holds_the_operations_copies_of_the_store() {
    let gib = 1 << 30;
    let store = 5 * gib / 2;
    let artifacts = 64 * MIB;
    // activate: the backup (then the rehearsal's copy) and the migration's
    // WAL and temporary files, a quarter more, the artifacts twice, slack.
    let activate = scratch_bytes(Operation::Activate.store_copies(), store, artifacts);
    assert_eq!(activate, (5_120 + 1_280 + 128 + 256) * MIB);
    assert!(activate >= 2 * store + 2 * artifacts);
    assert_eq!(
        scratch_bytes(Operation::Backup.store_copies(), store, artifacts),
        (2_560 + 640 + 128 + 256) * MIB
    );
    // Operations that copy no store, and small stores, keep the floor.
    for operation in [Operation::Inspect, Operation::MarkActivated] {
        assert_eq!(
            scratch_bytes(operation.store_copies(), store, artifacts),
            SCRATCH_FLOOR
        );
    }
    assert_eq!(scratch_bytes(2, 8 << 20, 1 << 20), SCRATCH_FLOOR);
    // Whole MiB, rounded up.
    assert_eq!(scratch_bytes(1, SCRATCH_FLOOR, 1) % MIB, 0);
    assert!(scratch_bytes(1, SCRATCH_FLOOR, 1) > SCRATCH_FLOOR + SCRATCH_FLOOR / 4 + SCRATCH_SLACK);
}

#[test]
fn activate_sizes_the_pod_from_a_large_store() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| {
            // 2.5 GiB of stores: the database, its WAL and a provider store.
            cluster.volume = vec![
                ("example_app.sqlite", 2_336 * MIB),
                ("example_app.sqlite-wal", 160 * MIB),
                ("example_app.sqlite-shm", 32_768),
                ("notifications.sqlite", 64 * MIB),
                ("lost+found.bin", 1 << 40),
            ];
        },
        true,
    )?;
    session.artifacts()?;
    ensure!(
        session.measure().is_err(),
        "the store is measured once stopped"
    );
    session.stop()?;
    ensure!(session.start_pod().is_err(), "the pod is sized first");
    let sized = session.measure()?;
    ensure!(session.measure().is_err(), "measured once");
    assert_eq!(
        sized["stores"],
        json!({"example_app.sqlite": 2_336 * MIB, "example_app.sqlite-wal": 160 * MIB,
            "notifications.sqlite": 64 * MIB})
    );
    let artifacts = sized["artifacts"].as_u64().unwrap();
    assert!(artifacts > 0 && artifacts < MIB);
    // 2 × 2.5 GiB, a quarter more and 256 MiB, the artifacts' bytes rounding up a MiB.
    assert_eq!(sized["scratch"], "6657Mi");
    assert_eq!(sized["ephemeral_storage"], "6721Mi");
    session.start_pod()?;
    let applied = harness.applied.borrow().clone();
    assert_eq!(applied.len(), 2);
    // The probe, small, then the maintenance pod with the derived size as its
    // scratch limit and its ephemeral-storage request and limit.
    assert!(applied[0].contains("-measure\n"));
    assert_eq!(sizes(&applied[0]), ("64Mi".into(), vec!["128Mi".into(); 2]));
    assert!(!applied[1].contains("-measure"));
    assert_eq!(
        sizes(&applied[1]),
        ("6657Mi".into(), vec!["6721Mi".into(); 2])
    );
    assert!(applied[1].contains("{ name: SQLITE_TMPDIR, value: /srv/day2 }"));
    drop(session);
    let verbs = harness.verbs();
    let at = |verb: &str| verbs.iter().position(|v| v == verb).unwrap();
    let applies: Vec<usize> = (0..verbs.len()).filter(|i| verbs[*i] == "apply").collect();
    assert!(at("scale --replicas=0") < applies[0]);
    assert!(applies[0] < at("delete probe") && at("delete probe") < applies[1]);
    assert!(harness.deleted_pod() && harness.scaled_up());
    let steps = harness.journal();
    let at = |step: &str| steps.iter().position(|s| s == step).unwrap();
    assert!(
        at("stop") < at("measure") && at("measure") < at("scratch") && at("scratch") < at("pod")
    );
    Ok(())
}

#[test]
fn a_small_store_keeps_the_floor_and_inspect_measures_nothing() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Backup, |_| {}, true)?;
    prepare(&mut session)?;
    drop(session);
    let applied = harness.applied.borrow().clone();
    assert_eq!(
        sizes(&applied[1]),
        ("1024Mi".into(), vec!["1088Mi".into(); 2])
    );
    let harness = Harness::new();
    let mut session = harness.open(Operation::Inspect, |_| {}, true)?;
    session.artifacts()?;
    session.stop()?;
    let sized = session.measure()?;
    assert_eq!(
        (sized["copies"].clone(), sized["scratch"].clone()),
        (json!(0), json!("1024Mi"))
    );
    session.start_pod()?;
    drop(session);
    assert_eq!(harness.applied.borrow().len(), 1, "no probe");
    assert!(!harness.verbs().contains(&"delete probe".to_owned()));
    Ok(())
}

#[test]
fn a_store_that_cannot_be_measured_stops_before_the_pod_and_restores_the_app() -> Result<()> {
    for configure in [
        (|cluster: &mut FakeCluster| cluster.volume = vec![("other_app.sqlite", 8)])
            as fn(&mut FakeCluster),
        |cluster| cluster.fail_on = Some("%s %n".into()),
    ] {
        let harness = Harness::new();
        let mut session = harness.open(Operation::Activate, configure, true)?;
        session.artifacts()?;
        session.stop()?;
        let error = format!("{:#}", session.measure().unwrap_err());
        assert!(
            error.starts_with("maintenance_scratch_unmeasured: the stores of example_app on data")
                && (error.contains("no example_app.sqlite on the state volume")
                    || error.contains("injected")),
            "{error}"
        );
        ensure!(session.start_pod().is_err(), "an unsized pod never starts");
        drop(session);
        assert_eq!(harness.applied.borrow().len(), 1, "only the probe");
        let verbs = harness.verbs();
        assert!(verbs.iter().filter(|verb| *verb == "delete probe").count() >= 1);
        assert!(!verbs.iter().any(|verb| verb == "delete") && harness.scaled_up());
        let steps = harness.journal();
        assert!(!steps.contains(&"scratch".to_owned()) && !steps.contains(&"pod".to_owned()));
        assert_eq!(steps.last().map(String::as_str), Some("aborted"));
    }
    Ok(())
}

#[test]
fn a_pod_no_node_can_hold_names_its_size_and_the_schedulers_reason() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Backup,
        // The maintenance pod's wait, not the probe's.
        |cluster| cluster.fail_on = Some("z --timeout=600s".into()),
        true,
    )?;
    session.artifacts()?;
    session.stop()?;
    session.measure()?;
    let error = format!("{:#}", session.start_pod().unwrap_err());
    assert!(
        error.contains("requests 1088Mi of ephemeral storage (1024Mi scratch); not scheduled: 0/3 nodes are available: 3 Insufficient ephemeral-storage."),
        "{error}"
    );
    drop(session);
    assert!(harness.deleted_pod() && harness.scaled_up());
    Ok(())
}

#[test]
fn a_failed_activation_mark_names_the_recovery_command() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| cluster.fail_on = Some("annotate".into()),
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    session.admission()?;
    session.confirm()?;
    session.fence()?;
    session.migration("apply")?;
    session.workflow("authority-inspect")?;
    session.workflow("authority-activate")?;
    let error = format!("{:#}", session.mark_activated().unwrap_err());
    let request = harness.directory.path().join("request.json");
    assert!(
        error.contains(&format!(
            "day2 platform maintain mark-activated {}",
            request.display()
        )),
        "{error}"
    );
    drop(session);
    assert!(harness.deleted_pod() && !harness.scaled_up());
    assert!(harness.annotations.borrow().is_empty());
    Ok(())
}

/// What a failed stamp after a successful `activate` leaves: the old image
/// stopped, and the database activating the target.
fn activated(harness: &Harness) -> impl FnOnce(&mut FakeCluster) {
    let artifact = format!("sha256:{}", harness.target.artifact_id);
    move |cluster| {
        cluster.replicas = 0;
        cluster.active_artifact = artifact;
    }
}

#[test]
fn mark_activated_stamps_the_artifact_the_database_activated() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::MarkActivated, activated(&harness), true)?;
    prepare(&mut session)?;
    ensure!(
        session.workflow("backup").is_err() && session.mark_activated().is_err(),
        "no backup, and nothing is marked before the database is read"
    );
    session.workflow("authority-inspect")?;
    let marked = session.mark_activated()?;
    assert_eq!(marked["already_marked"], false);
    ensure!(session.mark_activated().is_err(), "marked once");
    let receipt = session.finish()?;
    assert_eq!(receipt["replicas_restored"], false);
    drop(session);
    assert!(harness.deleted_pod() && !harness.scaled_up());
    assert_eq!(*harness.asked.borrow(), 0);
    let value = format!("sha256:{}", harness.target.artifact_id);
    assert_eq!(
        *harness.annotations.borrow(),
        BTreeMap::from([(ACTIVATED.to_owned(), value.clone())])
    );
    let steps = harness.journal();
    let at = |step: &str| steps.iter().position(|s| s == step).unwrap();
    assert!(
        at("open") < at("pod")
            && at("pod") < at("authority-inspect")
            && at("authority-inspect") < at("mark-activated")
            && at("mark-activated") < at("activation-marked")
            && at("activation-marked") < at("finish")
    );
    // A rerun on the stamped app changes nothing and succeeds.
    let rerun = Harness::new();
    rerun
        .annotations
        .borrow_mut()
        .insert(ACTIVATED.into(), value.clone());
    let mut session = rerun.open(Operation::MarkActivated, activated(&rerun), true)?;
    prepare(&mut session)?;
    session.workflow("authority-inspect")?;
    assert_eq!(session.mark_activated()?["already_marked"], true);
    session.finish()?;
    drop(session);
    assert!(!rerun.verbs().iter().any(|verb| verb == "annotate"));
    assert_eq!(
        *rerun.annotations.borrow(),
        BTreeMap::from([(ACTIVATED.to_owned(), value)])
    );
    Ok(())
}

#[test]
fn mark_activated_refuses_another_database_artifact_or_a_changed_workload() -> Result<()> {
    let harness = Harness::new();
    // The database still activates another artifact.
    let artifact = harness.target.artifact_id.clone();
    let mut session = harness.open(
        Operation::MarkActivated,
        |cluster| cluster.replicas = 0,
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("authority-inspect")?;
    let error = format!("{:#}", session.mark_activated().unwrap_err());
    assert!(
        error.contains("activates sha256:a") && error.contains(&artifact),
        "{error}"
    );
    ensure!(
        session.finish().is_err(),
        "an unmarked session cannot finish"
    );
    drop(session);
    assert!(harness.deleted_pod() && !harness.scaled_up());
    assert!(harness.annotations.borrow().is_empty());
    // A running app, another running image or another stamp: refused at open.
    let calls = harness.calls.borrow().len();
    let running = harness
        .open(
            Operation::MarkActivated,
            |cluster| cluster.active_artifact = format!("sha256:{artifact}"),
            true,
        )
        .err()
        .context("running app")?;
    assert!(format!("{running:#}").contains("0 replicas"));
    let image = harness
        .open(
            Operation::MarkActivated,
            |cluster| {
                activated(&harness)(cluster);
                cluster.running_image = harness.target.reference.clone();
            },
            true,
        )
        .err()
        .context("another image")?;
    assert!(format!("{image:#}").contains("the StatefulSet runs"));
    harness
        .annotations
        .borrow_mut()
        .insert(ACTIVATED.into(), "sha256:another".into());
    let other = harness
        .open(Operation::MarkActivated, activated(&harness), true)
        .err()
        .context("another stamp")?;
    assert!(format!("{other:#}").contains("already marked activated for sha256:another"));
    assert!(
        harness.verbs()[calls..].iter().all(|verb| verb == "get"),
        "refused before anything changed"
    );
    Ok(())
}

#[test]
fn the_fence_and_migration_apply_refuse_steps_out_of_order() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    ensure!(
        session.migration("plan").is_err(),
        "plan needs a verified backup"
    );
    session.workflow("backup")?;
    session.copy_backup()?;
    ensure!(
        session.fence().is_err(),
        "fence needs a plan and a confirmation"
    );
    ensure!(session.migration("apply").is_err(), "apply needs the fence");
    ensure!(session.admission().is_err(), "admission needs the plan");
    session.migration("plan")?;
    ensure!(
        session.confirm().is_err(),
        "confirm after the target admitted the store"
    );
    ensure!(
        session.fence().is_err(),
        "fence needs the target's admission"
    );
    session.admission()?;
    ensure!(session.fence().is_err(), "fence needs a confirmation");
    ensure!(session.migration("apply").is_err(), "apply needs the fence");
    drop(session);
    assert!(harness.scaled_up());
    assert!(
        !harness.calls.borrow().iter().any(|call| call
            .join(" ")
            .contains(&format!("migration-apply {TARGET}"))),
        "only the rehearsal's copy was migrated"
    );
    Ok(())
}

#[test]
fn a_refused_confirmation_changes_nothing_and_restores_the_app() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, false)?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    session.admission()?;
    ensure!(session.confirm().is_err(), "the operator said no");
    ensure!(session.fence().is_err(), "no fence without a confirmation");
    drop(session);
    assert!(harness.scaled_up() && harness.deleted_pod());
    assert!(
        !harness.calls.borrow().iter().any(|call| call
            .join(" ")
            .contains(&format!("migration-apply {TARGET}"))),
        "only the rehearsal's copy was migrated"
    );
    Ok(())
}

#[test]
fn authority_apply_needs_a_backup_a_stamp_and_a_confirmation() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::AuthorityApply, |_| {}, true)?;
    prepare(&mut session)?;
    ensure!(
        session.workflow("authority-apply").is_err(),
        "needs backup and confirmation"
    );
    session.workflow("backup")?;
    session.copy_backup()?;
    ensure!(
        session.confirm().is_err(),
        "confirm after reading the stamp"
    );
    session.workflow("authority-inspect")?;
    ensure!(
        session.admission().is_err(),
        "store admission belongs to activate"
    );
    session.confirm()?;
    session.workflow("authority-apply")?;
    let receipt = session.finish()?;
    assert_eq!(receipt["replicas_restored"], true);
    Ok(())
}

#[test]
fn a_second_session_or_a_different_running_image_is_refused_before_anything_changes() -> Result<()>
{
    let harness = Harness::new();
    let error = harness
        .open(
            Operation::Backup,
            |cluster| cluster.other_sessions = "pod/day2-maintenance-x\n".into(),
            true,
        )
        .err()
        .context("second session")?;
    assert!(format!("{error:#}").contains("another maintenance session"));
    let error = harness
        .open(Operation::Backup, |cluster| cluster.running_image = "registry.test/day2/example@sha256:1111111111111111111111111111111111111111111111111111111111111111".into(), true)
        .err()
        .context("different image")?;
    assert!(format!("{error:#}").contains("the StatefulSet runs"));
    assert!(
        !harness
            .verbs()
            .iter()
            .any(|verb| verb == "scale --replicas=0")
    );
    Ok(())
}

#[test]
fn requests_are_validated_per_operation() {
    let harness = Harness::new();
    let request: Request =
        serde_json::from_slice(&fs::read(harness.request(Operation::Activate)).unwrap()).unwrap();
    assert!(request.validate(Operation::Activate).is_ok());
    assert!(
        request.validate(Operation::Backup).is_err(),
        "only activate takes a target"
    );
    let mut unpinned = request.clone();
    unpinned.app_image = "registry.test/day2/example:latest".into();
    assert!(unpinned.validate(Operation::Activate).is_err());
    let mut untargeted = request.clone();
    untargeted.target = None;
    assert!(untargeted.validate(Operation::Activate).is_err());
    let mut injected = request;
    injected.namespace = "app-example --all-namespaces".into();
    assert!(injected.validate(Operation::Activate).is_err());
}

#[test]
fn artifacts_are_extracted_read_only_and_verified() -> Result<()> {
    let good = image(b"worker", None);
    let output = tempfile::tempdir()?;
    let receipt = fetch_artifact(
        &mut FakeRegistry(good.blobs.clone()),
        &good.reference,
        &good.artifact_id,
        output.path(),
    )?;
    assert_eq!(receipt["files"], 2);
    let worker = output.path().join(&good.artifact_id).join("worker");
    let manifest = output.path().join(&good.artifact_id).join("artifact.json");
    assert_eq!(
        receipt["bytes"],
        fs::metadata(&worker)?.len() + fs::metadata(&manifest)?.len()
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(&worker)?.permissions().mode() & 0o222, 0);
    assert!(!output.path().join("other").exists());
    writable(output.path());

    let linked = image(b"worker", Some(("escape", tar::EntryType::Symlink)));
    let output = tempfile::tempdir()?;
    let error = fetch_artifact(
        &mut FakeRegistry(linked.blobs.clone()),
        &linked.reference,
        &linked.artifact_id,
        output.path(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("non-regular"));
    writable(output.path());

    let mut tampered = good.blobs.clone();
    for (path, bytes) in tampered.iter_mut() {
        if path.contains("/blobs/") {
            bytes.push(0);
        }
    }
    let output = tempfile::tempdir()?;
    let error = fetch_artifact(
        &mut FakeRegistry(tampered),
        &good.reference,
        &good.artifact_id,
        output.path(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("digest mismatch"));

    let wrong = image(b"another worker", None);
    let output = tempfile::tempdir()?;
    let error = fetch_artifact(
        &mut FakeRegistry(good.blobs),
        &good.reference,
        &wrong.artifact_id,
        output.path(),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("holds no"));
    Ok(())
}

#[test]
fn the_reviewed_pod_template_renders_completely() -> Result<()> {
    let values = [
        ("DAY2_MAINT_NAMESPACE", NAMESPACE),
        ("DAY2_MAINT_POD", "day2-maintenance-20260926t000000z"),
        (
            "DAY2_MAINT_TOOLING_IMAGE",
            "registry.test/day2/tooling@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        ("DAY2_MAINT_PVC", "data"),
        (
            "DAY2_MAINT_SERVICE_LABEL_KEY",
            "platform.example.com/service",
        ),
        ("DAY2_MAINT_SERVICE_LABEL_VALUE", "background"),
        ("DAY2_MAINT_DEADLINE_SECONDS", "3600"),
        ("DAY2_MAINT_SCRATCH", "6657Mi"),
        ("DAY2_MAINT_EPHEMERAL_STORAGE", "6721Mi"),
    ];
    let rendered = render_template(POD_TEMPLATE, &values)?;
    assert!(!rendered.contains("${"));
    assert!(
        rendered.contains("claimName: data")
            && rendered.contains("automountServiceAccountToken: false")
    );
    assert_eq!(
        sizes(&rendered),
        ("6657Mi".into(), vec!["6721Mi".into(); 2])
    );
    assert!(
        render_template(POD_TEMPLATE, &values[..8]).is_err(),
        "every placeholder must be filled"
    );
    assert!(render_template("${DAY2_MAINT_POD} ${UNKNOWN}", &values).is_err());
    let mut hostile = values;
    hostile[1].1 = "x\n  hostNetwork: true";
    assert!(render_template(POD_TEMPLATE, &hostile).is_err());
    Ok(())
}
