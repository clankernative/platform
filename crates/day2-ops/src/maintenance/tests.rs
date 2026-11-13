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

/// Another app image of `image`'s artifact: the same artifact layer over
/// another runtime layer, as baking the same artifact into a new platform
/// build's runtime produces.
fn rebased(image: &Image) -> Image {
    let (_, layer) = image
        .blobs
        .iter()
        .find(|(path, _)| path.contains("/blobs/"))
        .unwrap();
    let layer_digest = day2::digest(layer);
    let manifest = serde_json::to_vec(&json!({"schemaVersion": 2, "layers": [
        {"digest": day2::digest(b"another runtime")}, {"digest": layer_digest}]}))
    .unwrap();
    let manifest_digest = day2::digest(&manifest);
    Image {
        reference: format!("registry.test/day2/example@{manifest_digest}"),
        artifact_id: image.artifact_id.clone(),
        blobs: BTreeMap::from([
            (
                format!("day2/example/manifests/{manifest_digest}"),
                manifest,
            ),
            (format!("day2/example/blobs/{layer_digest}"), layer.clone()),
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
    release: Rc<RefCell<Value>>,
    running_image: String,
    instance: String,
    released_instance: Option<String>,
    other_sessions: String,
    rollout_claim: String,
    helper_service: bool,
    backup_template: Option<Value>,
    backup_receipt: Option<Value>,
    backup_failed: bool,
    fail_on: Option<String>,
    denied_operator: Option<String>,
    drop_on_copy_out: Option<String>,
    annotations: Rc<RefCell<BTreeMap<String, String>>>,
    replicas: u64,
    workload_kind: WorkloadKind,
    /// What `authority inspect` reports the database activates.
    active_artifact: String,
    /// The bytes the in-pod backup takes of the app's store.
    store: &'static [u8],
    /// What `stat` reports for the files at the top of the state volume.
    volume: Vec<(&'static str, u64)>,
    /// Every manifest applied, in order.
    applied: Rc<RefCell<Vec<String>>>,
    prepared: bool,
    after_prepare: Option<(String, Value)>,
    growth_after_stop: u64,
    lose_fence_reply: bool,
    hide_fenced_checkpoint: bool,
    lose_activation_reply: bool,
}

/// A store whose credential unit predates the target's schema.
const OLD_CREDENTIAL_STORE: &[u8] = b"day2_credential_schema_version=1";

impl FakeCluster {
    fn helper(&self, name: &str) -> Value {
        let digest = self
            .annotations
            .borrow()
            .get(activation::ANNOTATION)
            .and_then(|raw| serde_json::from_str::<ActivationIntent>(raw).ok())
            .map(|intent| intent.request_digest)
            .unwrap_or_default();
        let _ = name;
        self.observed("helper",json!({"metadata":{"uid":"helper-uid","annotations":{
            "day2.dev/rollout-request":digest}},"spec":{"nodeName":"node-a",
            "containers":[{"image":"registry.test/day2/tooling@sha256:0000000000000000000000000000000000000000000000000000000000000000"}],
            "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data"}}]},
            "status":{"conditions":[{"type":"Ready","status":"True"},
                {"type":"PodScheduled","status":"False","message":"0/3 nodes are available: 3 Insufficient ephemeral-storage."}]}}))
    }

    fn controller(&self) -> Value {
        self.observed("controller", json!({
            "metadata":{"uid":"controller-uid","resourceVersion":"1","annotations":*self.annotations.borrow()},
            "spec":{"replicas":self.replicas,"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":1,"maxUnavailable":0}},
                "template":{"metadata":{"annotations":self.template_annotations()},"spec":{
                    "containers":[{"name":"day2","image":self.running_image}],
                    "volumes":[{"name":"state","persistentVolumeClaim":{"claimName":"data"}},
                        {"name":"instance","configMap":{"name":if self.released_instance.is_some(){"released-instance"}else{"day2-example-instance"}}}]}}}}))
    }

    fn observed(&self, kind: &str, mut value: Value) -> Value {
        if self.prepared
            && let Some((path, replacement)) = &self.after_prepare
            && let Some(path) = path.strip_prefix(kind)
        {
            *value.pointer_mut(path).expect("known test field") = replacement.clone();
        }
        value
    }

    fn incumbent(&self) -> Value {
        self.observed("pod", json!({"metadata":{"name":"incumbent","uid":"incumbent-uid",
            "ownerReferences":[{"uid":if self.workload_kind == WorkloadKind::Deployment {
                "replicaset-uid"} else {"controller-uid"},"controller":true}]},
            "spec":{"nodeName":"node-a","containers":[{"name":"day2","image":self.running_image}],
                "volumes":[{"name":"state","persistentVolumeClaim":{"claimName":self.rollout_claim}}]},
            "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}))
    }

    fn template_annotations(&self) -> Value {
        self.released_instance.as_ref().map_or_else(|| json!({}), |raw| {
            let instance: Value = serde_json::from_str(raw).unwrap();
            let artifact = instance["apps"]["example_app"]["artifact"].as_str().unwrap();
            json!({"day2.dev/artifact":artifact.replacen("artifacts/", "sha256:", 1),
                "day2.dev/instance-sha256":day2::digest(raw.as_bytes()).trim_start_matches("sha256:")})
        })
    }

    fn backup_template(&self) -> Value {
        self.backup_template.clone().unwrap_or_else(|| json!({
            "metadata":{"labels":{"app.kubernetes.io/name":"day2-example-backup"}},
            "spec":{"serviceAccountName":"backup","automountServiceAccountToken":false,"restartPolicy":"Never",
                "containers":[{"name":"backup","image":self.running_image,
                    "command":["/usr/local/bin/day2-backup"],
                    "args":["/srv/day2/instance.json","example_app","/backup/snapshot","--upload-gcs",
                        "example-backups","--object-prefix","example_app"],
                    "securityContext":{"allowPrivilegeEscalation":false,"privileged":false,
                        "readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}],
                "volumes":[{"name":"state","persistentVolumeClaim":{"claimName":"data"}},
                    {"name":"instance","configMap":{"name":"day2-example-instance"}},
                    {"name":"tmp","emptyDir":{}},{"name":"backup","emptyDir":{}}]}}))
    }

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
        let artifact = self.selected_artifact(&instance, app)?;
        Ok(json!({"admitted": true, "scope": "exampleco/production/example_app", "artifact": format!("sha256:{artifact}")}).to_string())
    }

    fn selected_artifact(&self, instance: &Path, app: &str) -> Result<String> {
        let desired: Value = serde_json::from_slice(&fs::read(instance)?)?;
        let relative = desired["apps"][app]["artifact"].as_str().unwrap();
        let manifest: Value = serde_json::from_slice(&fs::read(
            instance
                .parent()
                .unwrap()
                .join(relative)
                .join("artifact.json"),
        )?)?;
        let artifact = relative.trim_start_matches("artifacts/").to_owned();
        ensure!(
            day2::digest(&serde_json::to_vec(&manifest)?) == format!("sha256:{artifact}"),
            "selected artifact identity mismatch"
        );
        Ok(artifact)
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
        if args[2] == "apply" || args[2] == "create" {
            let manifest = String::from_utf8(stdin.unwrap_or_default().to_vec())?;
            self.applied.borrow_mut().push(manifest);
        }
        let joined = args.join(" ");
        if self.hide_fenced_checkpoint
            && args[2] == "get"
            && matches!(args[3].as_str(), "statefulset" | "deployment")
            && self
                .annotations
                .borrow()
                .get(activation::ANNOTATION)
                .is_some_and(|raw| {
                    serde_json::from_str::<ActivationIntent>(raw).unwrap().phase
                        == ActivationPhase::Fenced
                })
        {
            bail!("injected API unavailable after fence response loss");
        }
        if let Some(fail) = &self.fail_on
            && joined.contains(fail.as_str())
        {
            bail!("injected failure at {fail}");
        }
        let args: Vec<&str> = args[2..].iter().map(String::as_str).collect();
        Ok(match args.as_slice() {
            ["get", kind @ ("statefulset" | "deployment"), STATEFULSET, "-o", "json"] => {
                self.workload_kind = if *kind == "deployment" {WorkloadKind::Deployment} else {WorkloadKind::Statefulset};
                self.controller().to_string()
            },
            ["annotate", "--overwrite", "statefulset" | "deployment", STATEFULSET, annotation] => {
                let (key, value) = annotation.split_once('=').unwrap();
                self.annotations
                    .borrow_mut()
                    .insert(key.to_owned(), value.to_owned());
                String::new()
            }
            ["get", "pods", "-l", MAINTENANCE_LABEL, "-o", "name"] => self.other_sessions.clone(),
            ["get", "pods", "-l", MAINTENANCE_LABEL, "-o", "json"] => json!({"items":[]}).to_string(),
            ["get", "services", "-o", "json"] => json!({"items":[{"spec":{"selector":{"app.kubernetes.io/name":if self.helper_service {"day2-maintenance"} else {STATEFULSET}}}}]}).to_string(),
            ["get", "replicasets", "-o", "json"] => json!({"items":[{"metadata":{"uid":"replicaset-uid","ownerReferences":[{"uid":"controller-uid","controller":true}]}}]}).to_string(),
            ["get", "pvc", "data", "-o", "json"] => self.observed("pvc", json!({"metadata":{"uid":"pvc-uid"},"spec":{"accessModes":["ReadWriteOnce"]},"status":{"phase":"Bound"}})).to_string(),
            ["get", "job", _, "-o", "json"] => json!({"metadata":{"uid":"backup-job-uid"},
                "status":{"conditions":[{"type":if self.backup_failed {"Failed"} else {"Complete"},"status":"True"}]}}).to_string(),
            ["get", "pods", "-l", selector, "-o", "json"] if selector.starts_with("batch.kubernetes.io/job-name=") => {
                let job: Value = self.applied.borrow().iter().rev()
                    .find_map(|raw| serde_json::from_str::<Value>(raw).ok().filter(|v| v["kind"] == "Job"))
                    .context("backup Job was not created")?;
                json!({"items":[{"metadata":{"name":"backup-pod",
                    "annotations":job["spec"]["template"]["metadata"]["annotations"],
                    "ownerReferences":[{"uid":"backup-job-uid","kind":"Job","controller":true}]},
                    "spec":{"nodeName":"node-a","containers":[{"image":self.running_image}]},
                    "status":{"phase":"Succeeded","containerStatuses":[{"name":"backup","imageID":self.running_image,
                        "state":{"terminated":{"exitCode":0}}}]}}]}).to_string()
            }
            ["get", "cronjob", "day2-example-backup", "-o", "json"] =>
                json!({"spec":{"jobTemplate":{"spec":{"template":self.backup_template()}}}}).to_string(),
            ["logs", _, "-c", "backup", "--tail=1"] => {
                let job: Value = self.applied.borrow().iter().rev()
                    .find_map(|raw| serde_json::from_str::<Value>(raw).ok().filter(|v| v["kind"] == "Job"))
                    .context("backup job was not created")?;
                let prefix = format!("{}/20261107T120000Z",
                    job["spec"]["template"]["spec"]["containers"][0]["args"][6].as_str().unwrap());
                let source: Value = serde_json::from_str(&self.instance)?;
                let artifact = source["apps"]["example_app"]["artifact"].as_str().unwrap().trim_start_matches("artifacts/");
                self.backup_receipt.clone().unwrap_or_else(|| json!({"verified":true,"app":"example_app",
                    "artifact":format!("sha256:{artifact}"),
                    "upload":{"bucket":"example-backups","prefix":prefix,"objects":4,"bytes":4096,
                        "complete":format!("gs://example-backups/{prefix}/COMPLETE")}})).to_string()
            }
            ["get", "pods", "-l", _, "-o", "json"] => json!({"items":[self.incumbent()]}).to_string(),
            ["get", "pod", "incumbent", "-o", "json"] => self.incumbent().to_string(),
            ["patch", "statefulset" | "deployment", STATEFULSET, "--type=json", "-p", patch] => {
                let patch: Value = serde_json::from_str(patch)?;
                let mut current = self.controller();
                for op in patch.as_array().unwrap() {
                    let path=op["path"].as_str().unwrap();
                    match op["op"].as_str().unwrap() {
                        "test" => ensure!(current.pointer(path) == Some(&op["value"]), "mock JSON patch precondition failed: {path}"),
                        "add" | "replace" => { *current.pointer_mut(path).expect("mock known patch path")=op["value"].clone(); },
                        other=>bail!("unsupported mock patch operation {other}"),
                    }
                }
                self.replicas=current["spec"]["replicas"].as_u64().unwrap();
                *self.annotations.borrow_mut()=serde_json::from_value(current["metadata"]["annotations"].clone())?;
                if self.lose_fence_reply && self.annotations.borrow().get(activation::ANNOTATION)
                    .is_some_and(|raw| serde_json::from_str::<ActivationIntent>(raw).unwrap().phase == ActivationPhase::Fenced) {
                    self.lose_fence_reply = false;
                    bail!("injected lost fence response after server commit");
                }
                if self.lose_activation_reply && self.annotations.borrow().get(activation::ANNOTATION)
                    .is_some_and(|raw|serde_json::from_str::<ActivationIntent>(raw).unwrap().phase==ActivationPhase::Activated) {
                    self.lose_activation_reply=false;
                    bail!("injected lost approval response after server commit");
                }
                "{}".into()
            }
            ["scale", "statefulset" | "deployment", STATEFULSET, replicas] => {
                self.replicas = replicas.trim_start_matches("--replicas=").parse()?;
                String::new()
            }
            ["get", "configmap", name, "-o", "json"] => self.observed("configmap", json!({"data": {"instance.json":
                if *name == "released-instance" {self.released_instance.as_ref().unwrap()} else {&self.instance}}})).to_string(),
            ["get", "pod", _, "--ignore-not-found", "-o", "name"] => String::new(),
            ["get", "pod", name, "--ignore-not-found", "-o", "json"] => {
                let applied = self.applied.borrow().iter().any(|raw| raw.contains(&format!("  name: {name}\n")));
                let removed = self.calls.borrow().iter().any(|call| call[2]=="delete"
                    && ((call[3]=="pod" && call[4]==*name)
                        || (call[3]=="--raw" && call[4].ends_with(&format!("/pods/{name}")))));
                if !applied || removed {String::new()} else {
                    self.helper(name).to_string()
                }
            }
            ["delete", "--raw", path, "-f", "-"] => {
                assert!(path.starts_with("/api/v1/namespaces/app-example/pods/day2-maintenance-"));
                let options:Value=serde_json::from_slice(stdin.unwrap())?;
                ensure!(options["preconditions"]["uid"]=="helper-uid", "mock UID precondition failed");
                String::new()
            }
            ["get", "pod", name, "-o", "json"] => self.helper(name).to_string(),
            ["scale" | "apply" | "create" | "wait" | "delete" | "rollout", ..] => String::new(),
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
            ["exec", _, "--", "cp", "-a", from, to]
            | ["exec", _, "--", "cp", from, to] => {
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
            ["exec", _, "--", DAY2, "rollout-inspect", CURRENT, _] => self.release.borrow().to_string(),
            ["exec", _, "--", DAY2, "rollout-prepare", instance, app, target, ..] => {
                self.selected_artifact(&self.pod_path(instance), app)?;
                self.selected_artifact(&self.pod_path(target), app)?;
                json!({"phase":"prepared"}).to_string()
            }
            ["exec", _, "--", DAY2, "rollout-bind" | "rollout-transition", ..] => "{}".into(),
            ["exec", _, "--", DAY2, "rollout-probe", CURRENT, _, _, _, _] => {
                self.release.borrow_mut()["probe"] = json!({"status":"verified"});
                json!({"requested":true}).to_string()
            }
            ["exec", _, "--", DAY2, "admit", instance, app] => self.admit(instance, app)?,
            ["exec", _, "--", DAY2, "admit-maintenance", instance, app, operator] => {
                ensure!(self.denied_operator.as_deref() != Some(*operator), "Error: maintenance_operator_required");
                self.admit(instance, app)?
            }
            ["exec", _, "--", "find", STATE, "-maxdepth", "1", "-type", "f", "-exec", "stat", "-c", "%s %n", "{}", "+"] => {
                let mut result: String = self.volume
                    .iter()
                    .map(|(name, size)| format!("{size} {STATE}/{name}\n"))
                    .collect();
                if self.replicas == 0 && self.growth_after_stop > 0 {
                    result.push_str(&format!("{} {STATE}/example_app.sqlite-wal\n", self.growth_after_stop));
                }
                result
            }
            ["exec", _, "--", "find", root, ..] => self.sums(root)?,
            ["exec", _, "--", "sha256sum", file] => {
                if *file == TARGET { self.prepared = true; }
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
    release: Rc<RefCell<Value>>,
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
            release: Rc::default(),
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
            if operation == Operation::Rollout {
                request["placement"] =
                    json!({"controller_uid":"controller-uid","pvc_uid":"pvc-uid","node":"node-a"});
                request["offsite_backup"] = json!({"cronjob":"day2-example-backup",
                    "bucket":"example-backups","service_account":"backup"});
                request["target"]["probe"] = json!({"actor":"alice","command":"create","input":{},"query":"read","query_input":{},"expected":{}});
            }
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
            release: self.release.clone(),
            running_image: self.running.reference.clone(),
            instance: Self::instance(&self.running.artifact_id),
            other_sessions: String::new(),
            rollout_claim: "data".into(),
            backup_template: None,
            backup_receipt: None,
            backup_failed: false,
            released_instance: None,
            helper_service: false,
            fail_on: None,
            denied_operator: None,
            drop_on_copy_out: None,
            annotations: self.annotations.clone(),
            replicas: 1,
            workload_kind: WorkloadKind::Statefulset,
            active_artifact: "sha256:a".into(),
            store: b"database",
            volume: vec![
                ("example_app.sqlite", 8),
                ("example_app.sqlite-shm", 32_768),
                ("unrelated.bin", 1 << 40),
            ],
            applied: self.applied.clone(),
            prepared: false,
            after_prepare: None,
            growth_after_stop: 0,
            lose_fence_reply: false,
            hide_fenced_checkpoint: false,
            lose_activation_reply: false,
        };
        configure(&mut cluster);
        fs::create_dir_all(cluster.pod_path(STATE)).unwrap();
        let database = cluster.pod_path(&format!("{STATE}/example_app.sqlite"));
        if !database.exists() {
            fs::write(database, cluster.store).unwrap();
        }
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
                "patch" if matches!(call[3].as_str(), "statefulset" | "deployment") => {
                    let patch: Value = serde_json::from_str(call.last().unwrap()).unwrap();
                    match patch
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|op| op["path"] == "/spec/replicas" && op["op"] == "replace")
                    {
                        Some(op) => format!("scale --replicas={}", op["value"]),
                        None => "patch".into(),
                    }
                }
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
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
    if session.operation == Operation::Activate {
        session.measure()?;
        session.start_pod()?;
        session.stop()?;
        session.verify_preparation()?;
    } else {
        session.stop()?;
        session.measure()?;
        session.start_pod()?;
    }
    Ok(())
}

#[test]
fn activation_prepares_on_the_incumbent_node_without_opening_a_store() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    session.artifacts()?;
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
    session.measure()?;
    session.start_pod()?;
    for workflow in ["backup", "authority-inspect", "authority-activate"] {
        assert!(session.workflow(workflow).is_err());
    }
    assert!(session.migration("plan").is_err());
    assert!(session.fence().is_err());
    assert!(session.verify_preparation().is_err());
    assert!(
        harness
            .applied
            .borrow()
            .iter()
            .all(|pod| pod.contains("key: metadata.name")
                && pod.contains("values: [node-a]")
                && !pod.contains("nodeName:"))
    );
    assert!(
        !harness
            .verbs()
            .iter()
            .any(|verb| verb.starts_with("scale") || verb == "exec day2-host")
    );
    for manifest in harness.applied.borrow().iter() {
        let init = manifest
            .split("  initContainers:\n")
            .nth(1)
            .unwrap()
            .split("  containers:\n")
            .next()
            .unwrap();
        assert!(init.contains(&harness.target.reference));
        assert!(init.contains("day2-health") && init.contains("--help"));
        assert!(!init.contains("volumeMounts") && !init.contains(STATE));
    }
    let journal: Value = serde_json::from_slice(&fs::read(&session.journal)?)?;
    assert_eq!(journal["format"], 2);
    assert_eq!(journal["request"], session.request_json);
    assert_eq!(
        journal["request_digest"],
        day2::digest(session.request_json.as_bytes())
    );
    assert_eq!(
        journal["target_instance"],
        session.target_instance.as_deref().unwrap()
    );
    assert_eq!(journal["source_controller_uid"], "controller-uid");
    assert_eq!(journal["source_pvc_uid"], "pvc-uid");
    assert_eq!(journal["source_pod"]["metadata"]["uid"], "incumbent-uid");
    // Simulate process death without its destructor: preparation has never
    // changed replicas, readiness or the live store, even without cleanup.
    let work = session.work.path().to_owned();
    std::mem::forget(session);
    assert!(!harness.verbs().iter().any(|verb| verb.starts_with("scale")));
    writable(&work);
    fs::remove_dir_all(work)?;
    Ok(())
}

#[test]
fn activation_preparation_failures_do_not_stop_or_restart_the_source() -> Result<()> {
    for point in ["%s %n", "z --timeout=600s", "cp --retries=5", "sha256sum"] {
        let harness = Harness::new();
        let mut session = harness.open(
            Operation::Activate,
            |cluster| cluster.fail_on = Some(point.into()),
            true,
        )?;
        session.artifacts()?;
        if matches!(
            session.operation,
            Operation::Activate | Operation::MarkActivated
        ) {
            session.begin_preparation()?;
        }
        let result = session.measure().and_then(|_| session.start_pod());
        assert!(result.is_err(), "{point}");
        drop(session);
        assert!(
            !harness.verbs().iter().any(|verb| verb.starts_with("scale")),
            "{point}"
        );
        assert!(
            !harness
                .journal()
                .iter()
                .any(|step| step == "stop" || step == "fence")
        );
    }
    Ok(())
}

#[test]
fn activation_refuses_changed_source_bindings_before_stopping() -> Result<()> {
    for (path, value) in [
        ("controller/metadata/uid", json!("replacement-controller")),
        (
            "controller/spec/template/spec/containers/0/image",
            json!("replacement-image"),
        ),
        ("controller/spec/replicas", json!(2)),
        ("pvc/metadata/uid", json!("replacement-claim")),
        ("configmap/data/instance.json", json!("changed instance")),
        ("pod/metadata/uid", json!("replacement-pod")),
        ("helper/metadata/uid", json!("replacement-helper")),
        ("pod/spec/nodeName", json!("node-b")),
        ("pod/status/conditions/0/status", json!("False")),
    ] {
        let harness = Harness::new();
        let mut session = harness.open(
            Operation::Activate,
            |cluster| {
                cluster.after_prepare = Some((path.into(), value));
            },
            true,
        )?;
        session.artifacts()?;
        if matches!(
            session.operation,
            Operation::Activate | Operation::MarkActivated
        ) {
            session.begin_preparation()?;
        }
        session.measure()?;
        session.start_pod()?;
        assert!(session.stop().is_err(), "{path}");
        drop(session);
        assert!(
            !harness.verbs().iter().any(|verb| verb.starts_with("scale")),
            "{path}"
        );
        assert!(!harness.journal().iter().any(|step| step == "stop"));
    }
    Ok(())
}

#[test]
fn activation_growth_beyond_reserved_scratch_restores_before_opening_a_store() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| cluster.growth_after_stop = 4 * SCRATCH_FLOOR,
        true,
    )?;
    session.artifacts()?;
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
    session.measure()?;
    session.start_pod()?;
    session.stop()?;
    let error = format!("{:#}", session.verify_preparation().unwrap_err());
    assert!(error.contains("activation_preparation_outgrown"), "{error}");
    assert!(session.workflow("backup").is_err());
    drop(session);
    assert!(harness.scaled_up());
    assert!(!harness.verbs().iter().any(|verb| verb == "exec day2-host"));
    Ok(())
}

#[test]
fn activation_preparation_and_checked_stop_support_both_controllers() -> Result<()> {
    for kind in ["statefulset", "deployment"] {
        let harness = Harness::new();
        let path = harness.request(Operation::Activate);
        let mut request: Value = serde_json::from_slice(&fs::read(&path)?)?;
        request["workload_kind"] = json!(kind);
        fs::write(&path, serde_json::to_vec(&request)?)?;
        let mut session = Session::open("activate", &path, harness.tools(|_| {}, true))?;
        prepare(&mut session)?;
        drop(session);
        let calls = harness.calls.borrow();
        let patches: Vec<Value> = calls
            .iter()
            .filter(|call| {
                call[2] == "patch"
                    && serde_json::from_str::<Value>(call.last().unwrap())
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|op| op["path"] == "/spec/replicas" && op["op"] == "replace")
            })
            .map(|call| {
                assert_eq!(call[3], kind);
                serde_json::from_str(call.last().unwrap()).unwrap()
            })
            .collect();
        assert_eq!(patches.len(), 2);
        for patch in &patches {
            assert!(patch.as_array().unwrap().iter().any(|op| op["op"] == "test"
                && op["path"] == "/metadata/uid"
                && op["value"] == "controller-uid"));
            assert!(
                patch
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|op| op["op"] == "test" && op["path"] == "/metadata/resourceVersion")
            );
            assert!(
                patch
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|op| op["op"] == "test" && op["path"] == "/spec/template")
            );
        }
    }
    Ok(())
}

fn kill_operator(session: Session) -> (PathBuf, PathBuf) {
    let paths = (session.journal.clone(), session.work.path().to_owned());
    std::mem::forget(session);
    paths
}

#[test]
fn saved_activation_recovers_before_and_after_the_stop_without_original_input_files() -> Result<()>
{
    for stopped in [false, true] {
        let harness = Harness::new();
        let mut session = harness.open(Operation::Activate, |_| {}, true)?;
        session.artifacts()?;
        session.begin_preparation()?;
        session.measure()?;
        session.start_pod()?;
        if stopped {
            session.stop()?;
        }
        let (journal, work) = kill_operator(session);
        fs::remove_file(harness.directory.path().join("request.json"))?;
        fs::remove_file(harness.directory.path().join("target-instance.json"))?;
        let mut recovery = Recovery::open(
            &journal,
            harness.tools(
                |cluster| {
                    cluster.replicas = if stopped { 0 } else { 1 };
                },
                true,
            ),
        )?;
        assert!(recovery.restore().is_err());
        recovery.claim()?;
        assert!(recovery.restore().is_err());
        recovery.cleanup()?;
        let restored = recovery.restore()?;
        assert_eq!(restored["replicas_restored"], true);
        assert_eq!(restored["target_only"], false);
        let before = harness.calls.borrow().len();
        // Repeating after a lost recovery response cannot stop or republish.
        let mut repeated = Recovery::open(&journal, harness.tools(|_| {}, true))?;
        repeated.claim()?;
        repeated.cleanup()?;
        repeated.restore()?;
        assert!(
            !harness.calls.borrow()[before..]
                .iter()
                .any(|call| call[2] == "patch" || call[2] == "delete")
        );
        writable(&work);
        fs::remove_dir_all(work)?;
    }
    Ok(())
}

#[test]
fn recovery_claim_prevents_the_original_operator_from_opening_the_store() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    let mut recovery = Recovery::open(
        &session.journal,
        harness.tools(|cluster| cluster.replicas = 0, true),
    )?;
    recovery.claim()?;
    assert!(session.workflow("backup").is_err());
    recovery.cleanup()?;
    recovery.restore()?;
    drop(session);
    assert!(!harness.verbs().iter().any(|verb| verb == "exec day2-host"));
    Ok(())
}

#[test]
fn a_lost_fence_response_never_restores_the_old_runtime() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| {
            cluster.lose_fence_reply = true;
            cluster.hide_fenced_checkpoint = true;
        },
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    session.admission()?;
    session.confirm()?;
    let journal = session.journal.clone();
    assert!(format!("{:#}", session.fence().unwrap_err()).contains("lost fence response"));
    assert!(session.state.fenced);
    drop(session);
    let mut recovery = Recovery::open(
        &journal,
        harness.tools(|cluster| cluster.replicas = 0, true),
    )?;
    recovery.claim()?;
    recovery.cleanup()?;
    let receipt = recovery.restore()?;
    assert_eq!(receipt["target_only"], true);
    assert_eq!(receipt["replicas_restored"], false);
    assert!(!harness.scaled_up());
    Ok(())
}

#[test]
fn lost_fence_and_approval_responses_resolve_the_exact_committed_transaction() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(
        Operation::Activate,
        |cluster| {
            cluster.lose_fence_reply = true;
            cluster.lose_activation_reply = true;
        },
        true,
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    session.admission()?;
    session.confirm()?;
    session.fence()?;
    assert!(session.fence().is_err());
    session.migration("apply")?;
    session.workflow("authority-inspect")?;
    session.workflow("authority-activate")?;
    session.store_admission()?;
    session.mark_activated()?;
    session.finish()?;
    assert!(!harness.scaled_up());
    assert_eq!(
        harness.annotations.borrow().get(ACTIVATED),
        Some(&harness.target.reference)
    );
    let intent: ActivationIntent =
        serde_json::from_str(&harness.annotations.borrow()[activation::ANNOTATION])?;
    assert_eq!(intent.phase, ActivationPhase::Activated);
    Ok(())
}

#[test]
fn a_fence_winning_before_recovery_claim_refuses_source_restore() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    let (journal, work) = kill_operator(session);
    let mut recovery = Recovery::open(
        &journal,
        harness.tools(|cluster| cluster.replicas = 0, true),
    )?;
    let mut intent: ActivationIntent =
        serde_json::from_str(&harness.annotations.borrow()[activation::ANNOTATION])?;
    intent.phase = ActivationPhase::Fenced;
    harness.annotations.borrow_mut().insert(
        activation::ANNOTATION.into(),
        serde_json::to_string(&intent)?,
    );
    assert!(recovery.claim().is_err());
    assert!(recovery.restore().is_err());
    assert!(!harness.scaled_up());
    writable(&work);
    fs::remove_dir_all(work)?;
    Ok(())
}

#[test]
fn recovery_refuses_replacement_controller_claim_template_or_instance() -> Result<()> {
    for (path, value) in [
        ("controller/metadata/uid", json!("replacement")),
        (
            "controller/spec/template/spec/containers/0/image",
            json!("replacement"),
        ),
        ("pvc/metadata/uid", json!("replacement")),
        ("configmap/data/instance.json", json!("replacement")),
    ] {
        let harness = Harness::new();
        let mut session = harness.open(Operation::Activate, |_| {}, true)?;
        prepare(&mut session)?;
        let (journal, work) = kill_operator(session);
        let before = harness.calls.borrow().len();
        let result = Recovery::open(
            &journal,
            harness.tools(
                |cluster| {
                    cluster.replicas = 0;
                    cluster.prepared = true;
                    cluster.after_prepare = Some((path.into(), value));
                },
                true,
            ),
        );
        assert!(result.is_err(), "{path}");
        assert!(
            !harness.calls.borrow()[before..]
                .iter()
                .any(|call| call[2] == "patch" || call[2] == "delete")
        );
        writable(&work);
        fs::remove_dir_all(work)?;
    }
    Ok(())
}

#[test]
fn recovery_refuses_a_changed_helper_without_starting_the_source() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    let (journal, work) = kill_operator(session);
    let mut recovery = Recovery::open(
        &journal,
        harness.tools(
            |cluster| {
                cluster.replicas = 0;
                cluster.prepared = true;
                cluster.after_prepare = Some((
                    "helper/spec/containers/0/image".into(),
                    json!("replacement"),
                ));
            },
            true,
        ),
    )?;
    recovery.claim()?;
    assert!(recovery.cleanup().is_err());
    assert!(recovery.restore().is_err());
    assert!(!harness.scaled_up());
    writable(&work);
    fs::remove_dir_all(work)?;
    Ok(())
}

#[test]
fn fenced_activation_can_resume_only_the_exact_saved_target() -> Result<()> {
    for same_artifact in [false, true] {
        let mut harness = Harness::new();
        if same_artifact {
            harness.target = rebased(&harness.running);
        }
        let mut session = harness.open(Operation::Activate, |_| {}, true)?;
        prepare(&mut session)?;
        session.workflow("backup")?;
        session.copy_backup()?;
        session.migration("plan")?;
        session.admission()?;
        session.confirm()?;
        session.fence()?;
        let (journal, work) = kill_operator(session);
        let mut recovery = Recovery::open(
            &journal,
            harness.tools(|cluster| cluster.replicas = 0, true),
        )?;
        recovery.claim()?;
        recovery.cleanup()?;
        assert_eq!(recovery.restore()?["target_only"], true);
        let request = harness.directory.path().join("request.json");
        let target = harness.directory.path().join("target-instance.json");
        let original = fs::read(&target)?;
        fs::write(&target, b"{\"apps\":{}}")?;
        assert!(
            Session::open(
                "activate",
                &request,
                harness.tools(|cluster| cluster.replicas = 0, true)
            )
            .is_err()
        );
        fs::write(&target, original)?;
        let mut resumed = Session::open(
            "activate",
            &request,
            harness.tools(|cluster| cluster.replicas = 0, true),
        )?;
        assert!(resumed.state.fenced);
        prepare(&mut resumed)?;
        assert!(resumed.migration("apply").is_err());
        resumed.workflow("backup")?;
        resumed.copy_backup()?;
        resumed.migration("plan")?;
        resumed.admission()?;
        resumed.confirm()?;
        resumed.fence()?;
        resumed.migration("apply")?;
        resumed.workflow("authority-inspect")?;
        resumed.workflow("authority-activate")?;
        assert!(
            resumed.mark_activated().is_err(),
            "live target admission is mandatory"
        );
        resumed.store_admission()?;
        resumed.mark_activated()?;
        resumed.finish()?;
        drop(resumed);
        assert!(!harness.scaled_up());
        writable(&work);
        fs::remove_dir_all(work)?;
    }
    Ok(())
}

#[test]
fn recovery_refuses_modified_request_and_target_evidence_before_mutation() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    let (journal, work) = kill_operator(session);
    let original: Value = serde_json::from_slice(&fs::read(&journal)?)?;
    for field in [
        "session",
        "request",
        "target_instance",
        "source_controller_uid",
        "source_pvc_uid",
    ] {
        let mut changed = original.clone();
        changed[field] = json!("modified");
        let path = harness
            .directory
            .path()
            .join(format!("changed-{field}.json"));
        fs::write(&path, serde_json::to_vec(&changed)?)?;
        let before = harness.calls.borrow().len();
        assert!(
            Recovery::open(&path, harness.tools(|cluster| cluster.replicas = 0, true)).is_err(),
            "{field}"
        );
        assert!(
            !harness.calls.borrow()[before..]
                .iter()
                .any(|call| call[2] == "patch" || call[2] == "delete")
        );
    }
    writable(&work);
    fs::remove_dir_all(work)?;
    Ok(())
}

#[test]
fn recovery_after_approval_only_cleans_up_even_if_the_target_is_running() -> Result<()> {
    for target_running in [false, true] {
        let harness = Harness::new();
        let mut session = harness.open(Operation::Activate, |_| {}, true)?;
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
        session.store_admission()?;
        session.mark_activated()?;
        let (journal, work) = kill_operator(session);
        let before = harness.calls.borrow().len();
        let mut recovery = Recovery::open(
            &journal,
            harness.tools(
                |cluster| {
                    cluster.replicas = if target_running { 1 } else { 0 };
                    if target_running {
                        cluster.running_image = harness.target.reference.clone();
                        cluster.instance = Harness::instance(&harness.target.artifact_id);
                    }
                },
                true,
            ),
        )?;
        recovery.claim()?;
        recovery.cleanup()?;
        let receipt = recovery.restore()?;
        assert_eq!(receipt["target_only"], true);
        assert_eq!(receipt["activation_approved"], true);
        assert!(
            !harness.calls.borrow()[before..]
                .iter()
                .any(|call| call[2] == "patch" || call[2] == "scale")
        );
        writable(&work);
        fs::remove_dir_all(work)?;
    }
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
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
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
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
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
fn an_unauthorized_maintenance_operator_is_refused_before_the_fence_and_restores_the_app()
-> Result<()> {
    let harness = Harness::new();
    let operator = "infra@example.com";
    let path = harness.request(Operation::Activate);
    let mut request: Value = serde_json::from_slice(&fs::read(&path)?)?;
    request["operator"] = operator.into();
    fs::write(&path, serde_json::to_vec(&request)?)?;
    let mut session = Session::open(
        "activate",
        &path,
        harness.tools(
            |cluster| cluster.denied_operator = Some(operator.into()),
            true,
        ),
    )?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    let error = format!("{:#}", session.admission().unwrap_err());
    assert!(
        error.starts_with("target_store_admission_refused")
            && error.contains("maintenance_operator_required"),
        "{error}"
    );
    ensure!(
        session.confirm().is_err()
            && session.fence().is_err()
            && session.migration("apply").is_err(),
        "an unauthorized maintenance operator never reaches the fence"
    );
    drop(session);
    assert!(harness.deleted_pod() && harness.scaled_up());
    assert_eq!(*harness.asked.borrow(), 0);
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
    let calls: Vec<String> = harness
        .calls
        .borrow()
        .iter()
        .map(|call| call.join(" "))
        .collect();
    assert!(calls.iter().any(|call| call.contains(&format!(
        "admit-maintenance {ADMISSION_INSTANCE} example_app {operator}"
    ))));
    for call in calls {
        if call.contains("migration-apply") || call.contains(r#"\"activate\""#) {
            assert!(call.contains(ADMISSION_INSTANCE), "{call}");
        }
    }
    assert!(
        !harness
            .journal()
            .iter()
            .any(|step| step == "fence" || step == "authority-activated")
    );
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
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
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
    session.store_admission()?;
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
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
            < at_call(&format!(
                "admit-maintenance {ADMISSION_INSTANCE} example_app ops@example.com"
            ))
            && at_call(&format!(
                "admit-maintenance {ADMISSION_INSTANCE} example_app ops@example.com"
            )) < at_call(&format!("migration-apply {TARGET}"))
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
        harness.annotations.borrow().get(ACTIVATED),
        Some(&harness.target.reference)
    );
    let intent: ActivationIntent =
        serde_json::from_str(&harness.annotations.borrow()[activation::ANNOTATION])?;
    assert_eq!(intent.phase, ActivationPhase::Activated);
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

/// A new image of the running artifact carries another day2-serve, whose store
/// admission is just as unknown as a new artifact's: `activate` rehearses it
/// the same way and stamps the new image.
#[test]
fn activate_takes_a_new_image_of_the_running_artifact() -> Result<()> {
    let mut harness = Harness::new();
    harness.target = rebased(&harness.running);
    assert_ne!(harness.target.reference, harness.running.reference);
    let mut session = harness.open(Operation::Activate, |_| {}, true)?;
    prepare(&mut session)?;
    // The pod holds the one artifact both images carry.
    let artifacts: Vec<String> =
        fs::read_dir(harness.directory.path().join("pod/srv/day2/artifacts"))?
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
    assert_eq!(artifacts, [harness.running.artifact_id.clone()]);
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    let admitted = session.admission()?;
    assert_eq!(
        admitted["artifact"],
        format!("sha256:{}", harness.running.artifact_id)
    );
    session.confirm()?;
    session.fence()?;
    session.migration("apply")?;
    session.workflow("authority-inspect")?;
    session.workflow("authority-activate")?;
    session.store_admission()?;
    let marked = session.mark_activated()?;
    assert_eq!(marked["activated_image"], harness.target.reference);
    session.finish()?;
    drop(session);
    assert!(harness.deleted_pod() && !harness.scaled_up());
    assert_eq!(
        harness.annotations.borrow().get(ACTIVATED),
        Some(&harness.target.reference)
    );
    let intent: ActivationIntent =
        serde_json::from_str(&harness.annotations.borrow()[activation::ANNOTATION])?;
    assert_eq!(intent.phase, ActivationPhase::Activated);
    Ok(())
}

/// The database activated the running artifact before any session, so
/// `mark-activated` cannot show that a new image of it was rehearsed; a failed
/// stamp names `activate` again instead.
#[test]
fn a_new_image_of_the_running_artifact_is_marked_only_by_activate() -> Result<()> {
    let mut harness = Harness::new();
    harness.target = rebased(&harness.running);
    let refused = harness
        .open(
            Operation::MarkActivated,
            |cluster| cluster.replicas = 0,
            true,
        )
        .err()
        .context("mark-activated for the running artifact")?;
    assert!(
        format!("{refused:#}").contains("cannot vouch"),
        "{refused:#}"
    );
    assert!(harness.calls.borrow().is_empty(), "refused before kubectl");
    let mut session = harness.open(
        Operation::Activate,
        |cluster| cluster.fail_on = Some("day2.dev/activated-image".into()),
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
    session.store_admission()?;
    let error = format!("{:#}", session.mark_activated().unwrap_err());
    let request = harness.directory.path().join("request.json");
    assert!(
        error.contains(&format!(
            "day2 platform maintain activate {}",
            request.display()
        )),
        "{error}"
    );
    drop(session);
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED) && !harness.scaled_up());
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
        .rsplit_once("  containers:\n")
        .map_or(manifest, |(_, main)| main)
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
    // WAL and temporary files, a quarter more, the artifacts three times, slack.
    let activate = scratch_bytes(Operation::Activate.store_copies(), store, artifacts);
    assert_eq!(activate, (5_120 + 1_280 + 192 + 256) * MIB);
    assert!(activate >= 2 * store + 3 * artifacts);
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
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
    ensure!(
        session.stop().is_err(),
        "activation cannot stop before preparation"
    );
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
    session.stop()?;
    session.verify_preparation()?;
    drop(session);
    let verbs = harness.verbs();
    let at = |verb: &str| verbs.iter().position(|v| v == verb).unwrap();
    let applies: Vec<usize> = (0..verbs.len()).filter(|i| verbs[*i] == "apply").collect();
    assert!(applies[1] < at("scale --replicas=0"));
    assert!(applies[0] < at("delete probe") && at("delete probe") < applies[1]);
    assert!(harness.deleted_pod() && harness.scaled_up());
    let steps = harness.journal();
    let at = |step: &str| steps.iter().position(|s| s == step).unwrap();
    assert!(
        at("measure") < at("scratch")
            && at("scratch") < at("pod")
            && at("pod") < at("stop")
            && at("stop") < at("preparation-verified")
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
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
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
fn activation_measurement_failure_keeps_the_source_serving() -> Result<()> {
    for configure in [
        (|cluster: &mut FakeCluster| cluster.volume = vec![("other_app.sqlite", 8)])
            as fn(&mut FakeCluster),
        |cluster| cluster.fail_on = Some("%s %n".into()),
    ] {
        let harness = Harness::new();
        let mut session = harness.open(Operation::Activate, configure, true)?;
        session.artifacts()?;
        if matches!(
            session.operation,
            Operation::Activate | Operation::MarkActivated
        ) {
            session.begin_preparation()?;
        }
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
        assert!(
            !verbs
                .iter()
                .any(|verb| verb == "delete" || verb.starts_with("scale"))
        );
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
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
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
        |cluster| cluster.fail_on = Some("day2.dev/activated-image".into()),
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
    session.store_admission()?;
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
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
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
    let value = harness.target.reference.clone();
    assert_eq!(harness.annotations.borrow().get(ACTIVATED), Some(&value));
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
    assert_eq!(rerun.annotations.borrow().get(ACTIVATED), Some(&value));
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
    assert!(!harness.annotations.borrow().contains_key(ACTIVATED));
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
    // A target names another image; it may keep the running artifact, which
    // only `activate` can then mark.
    let mut running = request.clone();
    running.target.as_mut().unwrap().app_image = request.app_image.clone();
    assert!(running.validate(Operation::Activate).is_err());
    let mut rebuilt = request.clone();
    rebuilt.target.as_mut().unwrap().artifact_id = request.artifact_id.clone();
    assert!(rebuilt.validate(Operation::Activate).is_ok());
    assert!(rebuilt.validate(Operation::MarkActivated).is_err());
    assert!(request.validate(Operation::MarkActivated).is_ok());
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

#[test]
fn rollout_helpers_stay_on_incumbent_node_and_failure_never_scales_it() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Rollout, |_| {}, true)?;
    session.artifacts()?;
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
    session.stop()?;
    session.measure()?;
    session.start_pod()?;
    assert!(session.rollout("promote").is_err());
    session.close()?;
    let calls = harness.calls.borrow();
    assert!(
        !calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "scale"))
    );
    for rendered in harness.applied.borrow().iter() {
        assert!(rendered.contains("nodeName: node-a"));
        assert!(rendered.contains("day2.dev/rollout-request: sha256:"));
        assert!(rendered.contains("app.kubernetes.io/name: day2-maintenance"));
    }
    Ok(())
}

#[test]
fn rolling_rehearsal_opens_both_artifacts_beside_its_disposable_instance() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Rollout, |_| {}, true)?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    session.migration("plan")?;
    assert_eq!(
        session.admission()?["artifact"],
        format!("sha256:{}", harness.target.artifact_id)
    );
    assert!(
        !harness
            .directory
            .path()
            .join("pod/srv/day2/admission")
            .exists(),
        "the admitted copy is discarded"
    );
    drop(session);
    assert!(!harness.scaled_up());
    Ok(())
}

#[test]
fn offline_deployment_maintenance_stops_and_restores_the_selected_controller() -> Result<()> {
    let harness = Harness::new();
    let path = harness.request(Operation::Inspect);
    let mut request: Value = serde_json::from_slice(&fs::read(&path)?)?;
    request["workload_kind"] = json!("deployment");
    fs::write(&path, serde_json::to_vec(&request)?)?;
    let mut session = Session::open("inspect", &path, harness.tools(|_| {}, true))?;
    session.artifacts()?;
    if matches!(
        session.operation,
        Operation::Activate | Operation::MarkActivated
    ) {
        session.begin_preparation()?;
    }
    session.stop()?;
    session.close()?;
    let calls = harness.calls.borrow();
    assert!(calls.iter().any(|call| {
        call.windows(3)
            .any(|args| args == ["scale", "deployment", STATEFULSET])
    }));
    assert!(
        !calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "statefulset"))
    );
    assert!(
        calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "--replicas=0"))
    );
    assert!(
        calls
            .iter()
            .any(|call| call.iter().any(|arg| arg == "--replicas=1"))
    );
    Ok(())
}

#[test]
fn rolling_offsite_backup_binds_source_identity_and_never_stops_service() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Rollout, |_| {}, true)?;
    prepare(&mut session)?;
    session.workflow("backup")?;
    session.copy_backup()?;
    let receipt = session.offsite_backup()?;
    assert_eq!(receipt["source_image"], harness.running.reference);
    assert_eq!(
        receipt["source_artifact"],
        format!("sha256:{}", harness.running.artifact_id)
    );
    assert!(
        receipt["upload"]["complete"]
            .as_str()
            .unwrap()
            .ends_with("/COMPLETE")
    );
    let job: Value = harness
        .applied
        .borrow()
        .iter()
        .find_map(|raw| {
            serde_json::from_str::<Value>(raw)
                .ok()
                .filter(|v| v["kind"] == "Job")
        })
        .context("backup Job")?;
    assert_eq!(job["spec"]["template"]["spec"]["nodeName"], "node-a");
    assert_eq!(job["spec"]["backoffLimit"], 0);
    assert_eq!(
        job["spec"]["template"]["spec"]["serviceAccountName"],
        "backup"
    );
    session.close()?;
    assert!(
        !harness
            .calls
            .borrow()
            .iter()
            .any(|call| call.iter().any(|arg| arg == "scale"))
    );
    assert!(
        harness
            .calls
            .borrow()
            .iter()
            .any(|call| call.windows(2).any(|v| v == ["delete", "job"]))
    );
    Ok(())
}

#[test]
fn rolling_backup_template_changes_and_missing_completion_fail_before_preparation() -> Result<()> {
    for pointer in [
        "/spec/serviceAccountName",
        "/spec/containers/0/image",
        "/spec/containers/0/command/0",
        "/spec/containers/0/args/4",
        "/spec/volumes/0/persistentVolumeClaim/claimName",
        "/spec/volumes/1/configMap/name",
        "/spec/containers/0/securityContext/readOnlyRootFilesystem",
    ] {
        let harness = Harness::new();
        let mut session = harness.open(
            Operation::Rollout,
            |cluster| {
                let mut template = cluster.backup_template();
                *template.pointer_mut(pointer).unwrap() = json!("another-value");
                cluster.backup_template = Some(template);
            },
            true,
        )?;
        prepare(&mut session)?;
        session.workflow("backup")?;
        session.copy_backup()?;
        assert!(session.offsite_backup().is_err(), "{pointer}");
        session.close()?;
        assert!(!harness.calls.borrow().iter().any(|call| {
            call.iter()
                .any(|arg| matches!(arg.as_str(), "scale" | "rollout-prepare" | "create"))
        }));
    }
    for receipt in [json!({"verified":true}), json!({"verified":false})] {
        let harness = Harness::new();
        let mut session = harness.open(
            Operation::Rollout,
            |cluster| {
                cluster.backup_receipt = Some(receipt);
            },
            true,
        )?;
        prepare(&mut session)?;
        session.workflow("backup")?;
        session.copy_backup()?;
        assert!(session.offsite_backup().is_err());
        assert!(session.state.offsite_backup.is_none());
        session.close()?;
        assert!(!harness.calls.borrow().iter().any(|call| {
            call.iter()
                .any(|arg| matches!(arg.as_str(), "scale" | "rollout-prepare"))
        }));
    }
    Ok(())
}

#[test]
fn rolling_prepare_cannot_bypass_the_offsite_gate_and_backup_failure_keeps_incumbent() -> Result<()>
{
    for fail in [false, true] {
        let harness = Harness::new();
        let mut session = harness.open(
            Operation::Rollout,
            |cluster| {
                if fail {
                    cluster.backup_failed = true;
                }
            },
            true,
        )?;
        prepare(&mut session)?;
        session.workflow("backup")?;
        session.copy_backup()?;
        session.migration("plan")?;
        session.admission()?;
        session.confirm()?;
        assert!(
            session
                .rollout("prepare")
                .unwrap_err()
                .to_string()
                .contains("offsite_backup_completion_required")
        );
        if fail {
            assert!(
                session
                    .offsite_backup()
                    .unwrap_err()
                    .to_string()
                    .contains("offsite_backup_job_failed")
            );
        }
        assert!(session.state.offsite_backup.is_none());
        session.close()?;
        assert!(!harness.calls.borrow().iter().any(|call| {
            call.iter().any(|arg| arg == "scale")
                || call
                    .windows(2)
                    .any(|args| args == ["rollout-prepare", CURRENT])
        }));
    }
    Ok(())
}

#[test]
fn rolling_preflight_refuses_another_claim_and_a_serving_helper() -> Result<()> {
    for helper_service in [false, true] {
        let harness = Harness::new();
        let error = match harness.open(
            Operation::Rollout,
            |cluster| {
                cluster.helper_service = helper_service;
                if !helper_service {
                    cluster.rollout_claim = "another-claim".into();
                }
            },
            true,
        ) {
            Ok(_) => bail!("unsafe topology admitted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains(if helper_service {
                "maintenance_pod_must_not_match_a_service"
            } else {
                "rollout_pod_owner_or_claim_changed"
            }),
            "{error}"
        );
        assert!(!harness.calls.borrow().iter().any(|call| {
            call.iter()
                .any(|arg| matches!(arg.as_str(), "scale" | "patch" | "apply"))
        }));
    }
    Ok(())
}

#[test]
fn rolling_request_refuses_replacement_controller_claim_or_node_before_mutation() -> Result<()> {
    for field in ["controller_uid", "pvc_uid", "node"] {
        let harness = Harness::new();
        let path = harness.request(Operation::Rollout);
        let mut request: Value = serde_json::from_slice(&fs::read(&path)?)?;
        request["placement"][field] = json!("replacement");
        fs::write(&path, serde_json::to_vec(&request)?)?;
        let error = match Session::open("rollout", &path, harness.tools(|_| {}, true)) {
            Ok(_) => bail!("changed placement admitted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains("rollout_captured_placement_changed"),
            "{field}: {error}"
        );
        assert!(!harness.calls.borrow().iter().any(|call| {
            call.iter()
                .any(|arg| matches!(arg.as_str(), "scale" | "apply" | "create" | "patch"))
        }));
    }
    Ok(())
}

#[test]
fn resumed_release_requires_exact_target_instance_bytes_before_any_step() -> Result<()> {
    let harness = Harness::new();
    let request = harness.request(Operation::Rollout);
    let request_bytes = fs::read(&request)?;
    let target = harness.directory.path().join("target-instance.json");
    let original = fs::read(&target)?;
    let release = json!({"id":"release-1", "source_image":harness.running.reference,
        "target_image":harness.target.reference,"target":format!("sha256:{}",harness.target.artifact_id),
        "target_instance_digest":day2::digest(&original),"phase":"prepared",
        "placement":{"controller_uid":"controller-uid","pvc_uid":"pvc-uid","node":"node-a","request_digest":day2::digest(&request_bytes)}});
    *harness.release.borrow_mut() = release;
    // The same request and exact target bytes can resume.
    let mut session = Session::open("rollout", &request, harness.tools(|_| {}, true))?;
    session.state.pod = true;
    assert_eq!(session.rollout_resume()?["resuming"], true);
    let journal = session.journal.clone();
    drop(session);
    fs::remove_file(journal)?;
    let mut changed: Value = serde_json::from_slice(&original)?;
    changed["apps"]["example_app"]["readers"] = json!(["unreviewed-reader"]);
    fs::write(&target, serde_json::to_vec(&changed)?)?;
    assert_eq!(fs::read(&request)?, request_bytes);
    let mut session = Session::open("rollout", &request, harness.tools(|_| {}, true))?;
    session.state.pod = true;
    assert!(
        format!("{:#}", session.rollout_resume().unwrap_err())
            .contains("rollout_target_instance_changed")
    );
    // Even a caller that bypasses the recipe's resume step cannot deploy it.
    session.state.resumed = true;
    for step in ["prepare", "deploy"] {
        assert!(
            format!("{:#}", session.rollout(step).unwrap_err())
                .contains("rollout_target_instance_changed")
        );
    }
    Ok(())
}

#[test]
fn completed_rollout_resumes_using_its_exact_live_instance_after_bootstrap_reconciliation()
-> Result<()> {
    for changed in [false, true] {
        let harness = Harness::new();
        let path = harness.request(Operation::Rollout);
        let request = fs::read(&path)?;
        let target = fs::read_to_string(harness.directory.path().join("target-instance.json"))?;
        *harness.release.borrow_mut() = json!({"id":"release-1", "source_image":harness.running.reference,
            "target_image":harness.target.reference,"target":format!("sha256:{}",harness.target.artifact_id),
            "target_instance_digest":day2::digest(target.as_bytes()),"phase":"complete",
            "placement":{"controller_uid":"controller-uid","pvc_uid":"pvc-uid","node":"node-a",
                "request_digest":day2::digest(&request)}});
        harness
            .annotations
            .borrow_mut()
            .insert("day2.dev/rollout".into(), "release-1".into());
        let mut session = Session::open(
            "rollout",
            &path,
            harness.tools(
                |cluster| {
                    cluster.running_image = harness.target.reference.clone();
                    cluster.instance = "overwritten bootstrap metadata must never be read".into();
                    cluster.released_instance = Some(if changed {
                        target.clone() + " "
                    } else {
                        target.clone()
                    });
                },
                true,
            ),
        )?;
        if changed {
            assert!(
                session
                    .artifacts()
                    .unwrap_err()
                    .to_string()
                    .contains("rollout_current_instance_changed")
            );
        } else {
            prepare(&mut session)?;
            assert_eq!(session.rollout_resume()?["resuming"], true);
            for step in [
                "prepare", "bind", "admit", "deploy", "observe", "probe", "promote", "wait",
                "complete",
            ] {
                session.rollout(step)?;
            }
        }
        session.close()?;
        assert!(!harness.calls.borrow().iter().any(|call| {
            call.iter().any(|arg| arg == "scale")
                || call
                    .windows(3)
                    .any(|args| args == ["get", "configmap", "day2-example-instance"])
        }));
    }
    Ok(())
}

#[test]
fn release_probe_only_publishes_then_observes_the_candidate_result() -> Result<()> {
    let harness = Harness::new();
    let mut session = harness.open(Operation::Rollout, |_| {}, true)?;
    session.state.pod = true;
    session.state.resumed = true;
    session.state.candidate_observed = true;
    *harness.release.borrow_mut() = json!({"id":"release-1","phase":"serving",
        "target":format!("sha256:{}",harness.target.artifact_id),
        "target_instance_digest":day2::digest(session.target_instance.as_ref().unwrap().as_bytes())});
    session.rollout("probe")?;
    assert!(session.state.probe_verified);
    let calls = harness.calls.borrow();
    assert!(
        calls
            .iter()
            .any(|args| args.iter().any(|arg| arg == "rollout-probe"))
    );
    assert!(!calls.iter().any(|args| {
        args.iter()
            .any(|arg| arg == "release-probe" || arg == "invoke")
    }));
    Ok(())
}
