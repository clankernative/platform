//! Tests for `day2 instance candidate`, against a fake forge, release bucket,
//! state bucket and build host. The fake build host runs the real native
//! session against a fake Docker, so the job and the build host are tested
//! together. Every fixture is synthetic.
use super::native::{self, Docker, Native, Output, Ran, Secret, Slot, Slots, Token, Verb};
use super::*;
use crate::instance_source::{
    Controls,
    tests::{
        BUCKET, COMMIT, Fake, PLATFORM, PREFIX, REGISTRY, SERVER, TOKEN, bytes, comment, entry,
        pax, roc_json, route_main_with, tarball,
    },
};
use day2::sdk_release::{Distribution, Evidence, Image, OPERATOR_FILES, PROFILE, Release, TARGET};
use std::{
    cell::RefCell,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    rc::Rc,
};

const GOLDEN_RECEIPT: &str = include_str!("../../../../cli/fixtures/candidate-receipt.json");

/// The synthetic instance's forge, registry and state bucket.
fn scope() -> record::Scope<'static> {
    record::Scope {
        server: SERVER,
        org: "tools",
        registry: REGISTRY,
        bucket: BUCKET,
    }
}
const OTHER: &str = "89abcdef0123456789abcdef0123456789abcdef";
const ARTIFACT: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const IMAGE_DIGEST: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const PROTOCOL_ERROR: &str = "Error: No such file or directory (os error 2)";

/// A qualified release whose distribution and evidence bind it, its images
/// mirrored under the app's own repository.
struct Published {
    release: Release,
    manifest: Vec<u8>,
    distribution: Vec<u8>,
    native: Vec<u8>,
    strict: Vec<u8>,
}

fn published() -> Published {
    let digest = |label: &str| day2::digest(label.as_bytes());
    let blob = |label: &str| BlobIdentity::of(label.as_bytes());
    let operator = blob("operator archive");
    let distribution = Distribution {
        format: 1,
        target: TARGET.into(),
        inputs: digest("inputs"),
        workflow_sources: digest("workflows"),
        toolchain: digest("toolchain"),
        worker: blob("!<arch>\nworker"),
        operator: operator.clone(),
        operator_files: OPERATOR_FILES
            .iter()
            .map(|name| ((*name).to_owned(), blob(name)))
            .collect(),
    };
    let runtime = digest("runtime config");
    let tooling = digest("tooling config");
    let raw_distribution = serde_json::to_vec_pretty(&distribution).unwrap();
    let native = json!({
        "format": 1, "status": "passed", "scope": PROFILE, "source_revision": PLATFORM,
        "runtime_image": runtime, "tooling_image": tooling,
        "workflow": distribution.workflow_sources, "toolchain": distribution.toolchain,
        "platform": digest("platform"), "platform_inventory": digest("inventory"),
        "artifact": digest("fixture app"), "environment": {"architecture": "x86_64"},
        "tooling_distribution": {"distribution": day2::digest(&raw_distribution),
            "operator": operator, "worker": distribution.worker},
    });
    let raw_native = serde_json::to_vec(&native).unwrap();
    let mut strict = json!({"status": "strict-admission-passed", "qualification": false,
        "qualification_digest": day2::digest(&raw_native)});
    for field in [
        "runtime_image",
        "tooling_image",
        "platform",
        "platform_inventory",
        "artifact",
    ] {
        strict[field] = native[field].clone();
    }
    let raw_strict = serde_json::to_vec(&strict).unwrap();
    let release = Release {
        version: 1,
        platform_commit: PLATFORM.into(),
        profile: PROFILE.into(),
        target: TARGET.into(),
        runtime: Image {
            image: format!("{REGISTRY}/links/day2-runtime@{runtime}"),
            config: runtime,
        },
        tooling: Image {
            image: format!("{REGISTRY}/links/day2-tooling@{tooling}"),
            config: tooling,
        },
        distribution: BlobIdentity::of(&raw_distribution),
        operator,
        evidence: Evidence {
            native: BlobIdentity::of(&raw_native),
            strict: BlobIdentity::of(&raw_strict),
            rolling: None,
        },
    };
    Published {
        manifest: release.encode().unwrap(),
        release,
        distribution: raw_distribution,
        native: raw_native,
        strict: raw_strict,
    }
}

/// The app's source archive: its CI controls (selecting `manifest`) and the
/// app under `app/`.
fn source_archive(manifest: &[u8], extra: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
    let roc = roc_json(PLATFORM);
    let own: [(&[u8], u8, &[u8]); 9] = [
        (b"links-app/", b'5', b""),
        (b"links-app/.ci/roc.json", b'0', &roc),
        (b"links-app/.ci/platform-release.json", b'0', manifest),
        (b"links-app/.ci/publish_artifact.py", b'0', b"# synthetic\n"),
        (b"links-app/.ci/sdk_release.py", b'0', b"# synthetic\n"),
        (
            b"links-app/.gitea/workflows/roc.yml",
            b'0',
            b"name: synthetic\n",
        ),
        (b"links-app/app/App.roc", b'0', b"app [main!] {}\n"),
        (b"links-app/app/Links.roc", b'0', b"module [links]\n"),
        (b"links-app/README.md", b'0', b"outside the app\n"),
    ];
    let entries: Vec<(&[u8], u8, &[u8])> = own.into_iter().chain(extra.iter().copied()).collect();
    tarball(&entries, &comment())
}

/// A checked artifact archive, as app CI publishes one.
fn artifact_archive(files: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, mode, data) in files {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(data.len() as u64);
        header.set_mode(*mode);
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, *data).unwrap();
    }
    let raw = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw).unwrap();
    encoder.finish().unwrap()
}

fn checked_artifact() -> Vec<u8> {
    artifact_archive(&[
        (
            &format!("{ARTIFACT}/artifact.json"),
            0o444,
            b"{\"artifact\":1}\n",
        ),
        (
            &format!("{ARTIFACT}/worker"),
            0o555,
            b"\x7fELF synthetic worker",
        ),
        (&format!("{ARTIFACT}/verification.json"), 0o444, b"{}\n"),
    ])
}

fn hex(index: u64) -> String {
    format!("{index:032x}")
}

/// The fake state bucket: objects with generations, and every call.
#[derive(Default)]
struct StoreWorld {
    objects: BTreeMap<String, (Vec<u8>, u64)>,
    calls: Vec<String>,
    denied: bool,
}

#[derive(Clone, Default)]
struct FakeStore(Rc<RefCell<StoreWorld>>);

impl tools::Store for FakeStore {
    fn read(&mut self, uri: &str) -> Result<Option<(Vec<u8>, String)>> {
        let mut world = self.0.borrow_mut();
        world.calls.push(format!("read {uri}"));
        ensure!(
            !world.denied,
            "cannot read private release state (authentication/network errors are not absence)"
        );
        Ok(world
            .objects
            .get(uri)
            .map(|(bytes, generation)| (bytes.clone(), generation.to_string())))
    }

    fn write(&mut self, file: &Path, uri: &str, generation: &str) -> Result<()> {
        let mut world = self.0.borrow_mut();
        let name = file.file_name().unwrap().to_str().unwrap().to_owned();
        world
            .calls
            .push(format!("write {uri} from {name} if {generation}"));
        let current = world
            .objects
            .get(uri)
            .map_or(0, |(_, generation)| *generation);
        ensure!(
            current.to_string() == generation,
            "write private release state failed (exit 1): HTTPError 412"
        );
        world
            .objects
            .insert(uri.to_owned(), (fs::read(file)?, current + 1));
        Ok(())
    }

    fn put(&mut self, file: &Path, uri: &str) -> Result<()> {
        let mut world = self.0.borrow_mut();
        let name = file.file_name().unwrap().to_str().unwrap().to_owned();
        world.calls.push(format!("put {uri} from {name}"));
        let generation = world
            .objects
            .get(uri)
            .map_or(0, |(_, generation)| *generation);
        world
            .objects
            .insert(uri.to_owned(), (fs::read(file)?, generation + 1));
        Ok(())
    }
}

/// The fake Docker: each verb, its stdin, and scripted answers.
#[derive(Default)]
struct DockerWorld {
    verbs: Vec<Verb>,
    stdins: Vec<Option<Vec<u8>>>,
    timeouts: Vec<Duration>,
    export: Option<PathBuf>,
    native_digest: String,
    protocol: Option<(i32, String)>,
    failing: Option<&'static str>,
    no_seed: bool,
    /// A copy out of the image that lands as a link to this host file.
    linked: Option<(&'static str, PathBuf)>,
    /// The admission output holds a float.
    float: bool,
    /// How long `create` takes.
    slow_create: Duration,
}

#[derive(Clone, Default)]
struct FakeDocker(Rc<RefCell<DockerWorld>>);

impl Docker for FakeDocker {
    fn run(
        &mut self,
        verb: &Verb,
        _auth: Option<&Path>,
        stdin: Option<&[u8]>,
        output: Output<'_>,
        timeout: Duration,
    ) -> Result<Ran> {
        let mut world = self.0.borrow_mut();
        world.verbs.push(verb.clone());
        world.stdins.push(stdin.map(<[u8]>::to_vec));
        world.timeouts.push(timeout);
        if matches!(verb, Verb::Create { .. }) {
            std::thread::sleep(world.slow_create);
        }
        if let Output::Log(mut log) | Output::Split(mut log) = output {
            writeln!(log, "docker {}", verb.name())?;
        }
        let done = |stdout: Vec<u8>| {
            Ok(Ran {
                code: Some(0),
                stdout,
                stderr: Vec::new(),
            })
        };
        let name = match verb {
            Verb::Push { .. } => "push",
            Verb::Build { .. } => "build",
            Verb::Security { .. } => "security",
            _ => "",
        };
        if world.failing == Some(name) {
            return Ok(Ran {
                code: Some(1),
                stdout: Vec::new(),
                stderr: b"synthetic failure".to_vec(),
            });
        }
        match verb {
            Verb::Login { .. } => {
                assert_eq!(stdin, Some(b"synthetic-registry-token".as_slice()));
                done(Vec::new())
            }
            Verb::CopyOut {
                path, destination, ..
            } => {
                if path == native::SEEDS[0] || (world.no_seed && path == native::SEEDS[1]) {
                    return Ok(Ran {
                        code: Some(1),
                        stdout: Vec::new(),
                        stderr: b"no such path".to_vec(),
                    });
                }
                if let Some((linked, target)) = &world.linked
                    && path.ends_with(linked)
                {
                    std::os::unix::fs::symlink(target, destination)?;
                    return done(Vec::new());
                }
                fs::write(
                    destination,
                    if path.ends_with("Dockerfile") {
                        b"FROM runtime\n".as_slice()
                    } else {
                        b"// synthetic ABI seed\n".as_slice()
                    },
                )?;
                done(Vec::new())
            }
            Verb::Start { export, .. } => {
                world.export = Some(export.clone());
                done(Vec::new())
            }
            Verb::Protocol { .. } | Verb::Probe { .. } => {
                let (code, stderr) = world
                    .protocol
                    .clone()
                    .unwrap_or((1, PROTOCOL_ERROR.to_owned()));
                Ok(Ran {
                    code: Some(code),
                    stdout: Vec::new(),
                    stderr: stderr.into_bytes(),
                })
            }
            Verb::Security { artifact, .. } => {
                let id = artifact.rsplit('/').next().unwrap();
                let mut output = json!({"version": 1, "artifact": format!("sha256:{id}"),
                    "containment": {"kind": "linux_qualified_v1",
                        "evidence": {"receipt_digest": world.native_digest, "checks": ["synthetic"]}},
                    "platform_inventory": day2::digest(b"inventory"), "roc_version": "synthetic"});
                if world.float {
                    output["score"] = json!(0.5);
                }
                done(output.to_string().into_bytes())
            }
            Verb::Sha256 { path, .. } => {
                let relative = path.strip_prefix("/qualification-export/").unwrap();
                let bytes = fs::read(world.export.as_ref().unwrap().join(relative))?;
                let digest = day2::digest(&bytes);
                done(format!("{}  {path}\n", &digest[7..]).into_bytes())
            }
            Verb::RepoDigests { tag } => {
                let (repository, _) = tag.rsplit_once(':').unwrap();
                done(
                    json!([
                        format!("{repository}@sha256:{IMAGE_DIGEST}"),
                        format!("{REGISTRY}/links/other@sha256:{IMAGE_DIGEST}")
                    ])
                    .to_string()
                    .into_bytes(),
                )
            }
            Verb::FindOperations { .. } => done(
                b"/workspace/platform/artifacts/operations/check-1/run.log\n/etc/passwd\n".to_vec(),
            ),
            Verb::Head { .. } => done(b"synthetic operation log\n".to_vec()),
            _ => done(Vec::new()),
        }
    }
}

struct FakeToken;

impl Token for FakeToken {
    fn fetch(&mut self) -> Result<Secret> {
        Ok(Secret::new("synthetic-registry-token".into()))
    }
}

#[derive(Clone)]
struct FakeSlots(Rc<RefCell<(PathBuf, Vec<String>)>>);

impl FakeSlots {
    fn slot(&self, name: &str, index: Option<usize>) -> Result<Slot> {
        let directory = self.0.borrow().0.join(name);
        fs::create_dir_all(directory.join("docker-auth"))?;
        fs::create_dir_all(directory.join("staging"))?;
        Ok(Slot {
            index,
            directory,
            lock: None,
        })
    }
}

impl Slots for FakeSlots {
    fn acquire(&mut self, wait: Duration) -> Result<Slot> {
        assert!(wait <= native::SLOT_WAIT);
        self.0.borrow_mut().1.push("acquire".into());
        self.slot("slot-1", Some(1))
    }

    fn probe(&mut self, wait: Duration) -> Result<Slot> {
        assert!(wait <= native::PROBE_WAIT);
        self.0.borrow_mut().1.push("probe".into());
        self.slot("slot-probe", None)
    }

    fn release(&mut self, slot: &Slot) {
        let name = slot.directory.file_name().unwrap().to_str().unwrap();
        self.0.borrow_mut().1.push(format!("release {name}"));
        let _ = fs::remove_dir_all(&slot.directory);
    }
}

fn native_effects(docker: &FakeDocker, slots: &FakeSlots) -> native::Effects {
    let mut counter = 100;
    native::Effects {
        docker: Box::new(docker.clone()),
        token: Box::new(FakeToken),
        slots: Box::new(slots.clone()),
        random: Box::new(move || {
            counter += 1;
            Ok(hex(counter))
        }),
    }
}

/// The fake build host: its job directories under a local root, every call,
/// and the real native session run against the fake Docker.
struct HostWorld {
    root: PathBuf,
    calls: Vec<String>,
    docker: FakeDocker,
    slots: FakeSlots,
    failing_upload: bool,
    failing_create: bool,
    /// A run that ends as ssh reports a lost connection: exit 255 and this.
    lost: Option<&'static str>,
}

#[derive(Clone)]
struct FakeHost(Rc<RefCell<HostWorld>>);

impl FakeHost {
    fn local(&self, remote: &str) -> PathBuf {
        self.0
            .borrow()
            .root
            .join(remote.strip_prefix("/tmp/").unwrap())
    }
}

impl tools::BuildHost for FakeHost {
    fn create(&mut self, target: &tools::Target, remote: &str) -> Result<()> {
        assert_eq!(target.host, BUILD_HOST);
        assert_eq!(
            target.account,
            "tools-infra@exampleco-tools.iam.gserviceaccount.com"
        );
        assert!(tools::remote_directory(remote), "{remote}");
        self.0.borrow_mut().calls.push(format!("create {remote}"));
        let local = self.local(remote);
        fs::DirBuilder::new().mode(0o700).create(&local)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(local.join("cli"))?;
        ensure!(
            !self.0.borrow().failing_create,
            "create the build host job directory failed (killed)"
        );
        Ok(())
    }

    fn upload(
        &mut self,
        _target: &tools::Target,
        files: &[PathBuf],
        destination: &str,
    ) -> Result<()> {
        let names: Vec<&str> = files
            .iter()
            .map(|file| file.file_name().unwrap().to_str().unwrap())
            .collect();
        self.0
            .borrow_mut()
            .calls
            .push(format!("upload {} to {destination}", names.join(" ")));
        ensure!(
            !self.0.borrow().failing_upload,
            "copy to the build host failed (exit 255)"
        );
        let local = self.local(destination.trim_end_matches('/'));
        for file in files {
            fs::copy(file, local.join(file.file_name().unwrap()))?;
        }
        Ok(())
    }

    fn run(
        &mut self,
        _target: &tools::Target,
        remote: &str,
        mode: Mode,
        _timeout: Duration,
    ) -> Result<tools::Remote> {
        self.0
            .borrow_mut()
            .calls
            .push(format!("run {} in {remote}", mode.name()));
        let (docker, slots, lost) = {
            let world = self.0.borrow();
            (world.docker.clone(), world.slots.clone(), world.lost)
        };
        if let Some(message) = lost {
            return Ok(tools::Remote {
                code: Some(255),
                stdout: Vec::new(),
                stderr: message.as_bytes().to_vec(),
            });
        }
        let job = self.local(remote);
        let ran = (|| -> Result<Value> {
            let mut session = Native::prepare(mode, &job, native_effects(&docker, &slots))?;
            let mut last = Value::Null;
            for step in Native::steps(mode) {
                last = session.step(step)?;
            }
            Ok(last)
        })();
        Ok(match ran {
            Ok(receipt) => tools::Remote {
                code: Some(0),
                stdout: json!({"ok": true, "result": {"receipt": receipt}})
                    .to_string()
                    .into_bytes(),
                stderr: Vec::new(),
            },
            Err(error) => tools::Remote {
                code: Some(6),
                stdout: json!({"ok": false, "error": {"code": "candidate_failed",
                    "message": format!("{error:#}")}})
                .to_string()
                .into_bytes(),
                stderr: b"synthetic remote stderr\n".to_vec(),
            },
        })
    }

    fn download(
        &mut self,
        _target: &tools::Target,
        sources: &[String],
        destination: &Path,
    ) -> Result<()> {
        self.0
            .borrow_mut()
            .calls
            .push(format!("download {}", sources.join(" ")));
        for source in sources {
            let local = self.local(source);
            fs::copy(&local, destination.join(local.file_name().unwrap()))
                .with_context(|| format!("no {source}"))?;
        }
        Ok(())
    }

    fn remove(&mut self, _target: &tools::Target, remote: &str) -> Result<()> {
        self.0.borrow_mut().calls.push(format!("remove {remote}"));
        // As root's `rm -rf`: the write-protected artifact tree goes too.
        let local = self.local(remote);
        let mut pending = vec![local.clone()];
        while let Some(path) = pending.pop() {
            if fs::symlink_metadata(&path)?.is_dir() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                for entry in fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            }
        }
        fs::remove_dir_all(local)?;
        Ok(())
    }
}

/// A forge, release bucket, state bucket, build host and Docker in one world,
/// with the app's source, its checked artifact and a published release.
struct World {
    fake: Fake,
    store: FakeStore,
    host: FakeHost,
    docker: FakeDocker,
    slots: FakeSlots,
    directory: tempfile::TempDir,
    published: Published,
    archive: Vec<u8>,
    artifact: Vec<u8>,
    inputs: String,
    binding: Value,
}

impl World {
    fn new() -> Self {
        Self::with_source(&[])
    }

    fn with_source(extra: &[(&[u8], u8, &[u8])]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let published = published();
        let archive = source_archive(&published.manifest, extra);
        let inputs = source_inputs(&archive, "app").unwrap();
        let controls = Controls::read(&archive).unwrap().digest();
        let reference = BlobIdentity::of(&published.manifest);
        let binding = json!({
            "app": "links",
            "repository": "tools/links-app",
            "directory": "app",
            "runtime_image": format!("{REGISTRY}/links/day2-runtime@{}", published.release.runtime.config),
            "tooling_image": format!("{REGISTRY}/links/day2-tooling@{}", published.release.tooling.config),
            "image_repository": format!("{REGISTRY}/links/links"),
            "source": {"forge": "gitea", "server": SERVER, "repository": "tools/links-app",
                "repository_id": 42, "branch": "main"},
            "qualified_release": {"digest": reference.digest, "bytes": reference.bytes},
            "verification": {"version": 1, "seed": 42, "cases": 4},
            "ci_artifact": {"version": 1, "workflow": "roc.yml", "job": "roc", "digest": controls},
        });
        let fake = Fake::default();
        for blob in [
            &published.manifest,
            &published.distribution,
            &published.native,
            &published.strict,
        ] {
            let identity = BlobIdentity::of(blob);
            fake.0.borrow_mut().objects.insert(
                format!(
                    "gs://{BUCKET}/{}/{}",
                    instance_release::OBJECTS,
                    &identity.digest[7..]
                ),
                blob.clone(),
            );
        }
        for commit in [COMMIT, OTHER] {
            fake.route(
                &format!("{PREFIX}/archive/{commit}.tar.gz"),
                vec![bytes(archive.clone())],
            );
        }
        let artifact = checked_artifact();
        let docker = FakeDocker::default();
        docker.0.borrow_mut().native_digest = published.release.evidence.native.digest.clone();
        let slots = FakeSlots(Rc::new(RefCell::new((
            directory.path().to_owned(),
            Vec::new(),
        ))));
        let host_root = directory.path().join("build-host");
        fs::create_dir(&host_root).unwrap();
        let host = FakeHost(Rc::new(RefCell::new(HostWorld {
            root: host_root,
            calls: Vec::new(),
            docker: docker.clone(),
            slots: slots.clone(),
            failing_upload: false,
            failing_create: false,
            lost: None,
        })));
        let cli = directory.path().join("cli");
        fs::create_dir(&cli).unwrap();
        for name in CLI_FILES {
            fs::write(cli.join(name), format!("synthetic {name}\n")).unwrap();
        }
        let world = Self {
            fake,
            store: FakeStore::default(),
            host,
            docker,
            slots,
            directory,
            published,
            archive,
            artifact,
            inputs,
            binding,
        };
        world.route_checked(COMMIT);
        world
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn sdk(&self) -> String {
        BlobIdentity::of(&self.published.manifest).digest
    }

    /// The job log's receipt for `commit`'s checked artifact.
    fn receipt(&self, commit: &str) -> Value {
        let sdk = BlobIdentity::of(&self.published.manifest);
        let archive = BlobIdentity::of(&self.artifact);
        json!({"version": 1, "repository": "tools/links-app", "source_commit": commit,
            "source_inputs": self.inputs, "artifact_id": ARTIFACT,
            "sdk_release": {"digest": sdk.digest, "bytes": sdk.bytes},
            "verification": {"version": 1, "seed": 42, "cases": 4},
            "archive": {"digest": archive.digest, "bytes": archive.bytes},
            "artifact_name": format!("day2-checked-app-{commit}-{}", "ef".repeat(16)),
            "examples": 12, "generated": 40, "upload_id": (1_u64 << 63) - 1})
    }

    fn route_checked(&self, commit: &str) {
        assert_eq!(commit, COMMIT, "the fake main run is COMMIT's");
        route_main_with(&self.fake, &self.receipt(commit), &self.artifact);
    }

    fn instance(&self) -> Instance {
        Instance {
            server: SERVER.into(),
            org: "tools".into(),
            registry: REGISTRY.into(),
            bucket: BUCKET.into(),
            project: "exampleco-tools".into(),
            zone: "us-central1-a".into(),
            apply_identity: "tools-infra@exampleco-tools.iam.gserviceaccount.com".into(),
            build_host: BUILD_HOST.into(),
            apps: vec![
                App {
                    id: "links".into(),
                    sdk: self.sdk(),
                    verification: 4,
                },
                App {
                    id: "notes".into(),
                    sdk: day2::digest(b"another release"),
                    verification: 6,
                },
            ],
        }
    }

    fn effects(&self, cli: bool) -> Effects {
        let mut counter = 0;
        Effects::Job(Box::new(JobEffects {
            source: instance_source::Effects {
                transport: Box::new(self.fake.clone()),
                clock: Box::new(self.fake.clone()),
                tools: Box::new(self.fake.clone()),
                cache: Some(self.path("cache")),
                token: Some(TOKEN.into()),
            },
            store: Box::new(self.store.clone()),
            host: Box::new(self.host.clone()),
            cli: cli.then(|| self.path("cli")),
            random: Box::new(move || {
                counter += 1;
                Ok(hex(counter))
            }),
        }))
    }

    fn request(&self, mode: Mode, commit: &str, output: &str) -> Value {
        fs::write(self.path("binding.json"), self.binding.to_string()).unwrap();
        let path = |name: &str| json!(self.path(name));
        match mode {
            Mode::Build => json!({"mode": "build", "instance": self.instance(),
                "binding": path("binding.json"), "commit": commit, "app_id": null,
                "candidate": null, "output": path(output), "job": null}),
            Mode::Preflight => json!({"mode": "preflight", "instance": self.instance(),
                "binding": null, "commit": null, "app_id": null, "candidate": path(output),
                "output": null, "job": null}),
            _ => json!({"mode": "check", "instance": self.instance(), "binding": null,
                "commit": null, "app_id": "links", "candidate": path(output), "output": null,
                "job": null}),
        }
    }

    fn session_with(&self, mode: Mode, request: &Value, cli: bool) -> Result<Session> {
        let raw = self.path("request.json");
        fs::write(&raw, request.to_string())?;
        Session::prepare(&raw, mode, self.effects(cli))
    }

    /// The build recipe: its steps, as InstanceCandidate.roc chooses them.
    fn build(&self, commit: &str, output: &str) -> Result<(Value, Vec<String>)> {
        let mut session = self.session_with(
            Mode::Build,
            &self.request(Mode::Build, commit, output),
            true,
        )?;
        let mut steps = Vec::new();
        let mut step = |name: &str| -> Result<Value> {
            steps.push(name.to_owned());
            session.step(name)
        };
        let receipt = (|| -> Result<Value> {
            if step("stored")?["found"] == true {
                return step("record");
            }
            for name in ["archive", "inputs", "controls"] {
                step(name)?;
            }
            if step("cached")?["found"] == true {
                step("reuse")?;
            } else {
                for name in [
                    "run", "job", "artifact", "download", "attempt", "release", "stage", "native",
                    "collect",
                ] {
                    step(name)?;
                }
            }
            step("record")
        })();
        drop(step);
        receipt.map(|receipt| (receipt, steps))
    }

    fn object(&self, uri: &str) -> Option<Vec<u8>> {
        self.store
            .0
            .borrow()
            .objects
            .get(uri)
            .map(|(bytes, _)| bytes.clone())
    }

    fn digest(&self) -> String {
        record::binding_digest(&self.binding).unwrap()
    }

    fn uri(&self, kind: &str, name: &str) -> String {
        format!(
            "gs://{BUCKET}/day2/app-releases/links/{kind}/{}/{name}",
            self.digest()
        )
    }
}

fn error<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("accepted"),
        Err(error) => format!("{:#}", instance_source::reported(error)),
    }
}

/// A candidate record a native build of the synthetic `links` app wrote, and its qualified release's manifest: what a
/// selection names, for other modules' tests.
pub(crate) fn selected_candidate() -> (Value, Vec<u8>) {
    let world = World::new();
    world.build(COMMIT, "candidate.json").unwrap();
    let bytes = fs::read(world.path("candidate.json")).unwrap();
    (
        record::decode(&bytes).unwrap(),
        world.published.manifest.clone(),
    )
}

#[test]
fn modes_name_their_commands() {
    for mode in Mode::ALL {
        assert_eq!(Mode::from_name(mode.name()), Some(mode));
    }
    assert!(Mode::NativeBuild.native() && Mode::NativeProbe.native());
    assert!(!Mode::Build.native() && !Mode::Check.native());
    assert_eq!(Mode::from_name("compile"), None);
}

#[test]
fn a_new_commit_is_built_on_the_build_host_and_both_records_are_created() -> Result<()> {
    let world = World::new();
    let (receipt, steps) = world.build(COMMIT, "candidate.json")?;
    assert_eq!(
        steps,
        [
            "stored", "archive", "inputs", "controls", "cached", "run", "job", "artifact",
            "download", "attempt", "release", "stage", "native", "collect", "record"
        ]
    );
    let record = world
        .object(&world.uri("candidates", &format!("{COMMIT}.json")))
        .unwrap();
    let inputs = world
        .object(&world.uri("checked-inputs", &format!("{}.json", &world.inputs[7..])))
        .unwrap();
    // A native build's candidate and checked-inputs records are the same bytes.
    assert_eq!(record, inputs);
    assert_eq!(fs::read(world.path("candidate.json"))?, record);
    let value: Value = serde_json::from_slice(&record)?;
    assert_eq!(record::encode(&value)?, record);
    record::check(&value, "links", &scope())?;
    assert_eq!(value["binding"], world.binding);
    assert_eq!(value["source_commit"], COMMIT);
    assert_eq!(value["checked_commit"], COMMIT);
    assert_eq!(value["source_inputs"], world.inputs);
    assert_eq!(value["artifact_id"], ARTIFACT);
    assert_eq!(
        value["image"],
        format!("{REGISTRY}/links/links@sha256:{IMAGE_DIGEST}")
    );
    assert_eq!(value["ci_artifact"]["receipt"], world.receipt(COMMIT));
    let log = world.uri("builds", &format!("{COMMIT}.log"));
    assert_eq!(value["build_log"], log);
    // The native log, as the build host wrote it: the promotion header first.
    let text = String::from_utf8(world.object(&log).unwrap())?;
    let header = format!(
        "Promoting checked main artifact; no app compilation or campaign rerun\n{}\n",
        String::from_utf8(day2::python_json::dumps(
            &value["ci_artifact"],
            day2::python_json::Layout::Default
        )?)?
    );
    assert!(text.starts_with(&header), "{text}");
    assert!(text.contains("Native build by the instance's day2 CLI: cli/day2 sha256:"));
    assert!(text.contains("Verified native maintenance protocol before application mutation\n"));
    // Records are created only while absent; the log is put; each from the
    // local file name the earlier controller used.
    let store = world.store.0.borrow().calls.clone();
    assert_eq!(
        store,
        [
            format!(
                "read {}",
                world.uri("candidates", &format!("{COMMIT}.json"))
            ),
            format!(
                "read {}",
                world.uri("checked-inputs", &format!("{}.json", &world.inputs[7..]))
            ),
            format!("put {log} from build.log"),
            format!(
                "write {} from record.json if 0",
                world.uri("checked-inputs", &format!("{}.json", &world.inputs[7..]))
            ),
            format!(
                "write {} from record.json if 0",
                world.uri("candidates", &format!("{COMMIT}.json"))
            ),
        ]
    );
    // The build host's job directory: created, filled, run, emptied, removed.
    let remote = format!("/tmp/day2-build-{}", hex(1));
    assert_eq!(
        world.host.0.borrow().calls,
        [
            format!("create {remote}"),
            format!(
                "upload request.json source.tar.gz ci-artifact.tar.gz qualified-release.json qualification.json to {remote}/"
            ),
            format!("upload day2 day2-host day2-workflows day2-workflows.json to {remote}/cli/"),
            format!("run native-build in {remote}"),
            format!("download {remote}/result.json {remote}/build.log"),
            format!("remove {remote}"),
        ]
    );
    // Python's order of Docker verbs; the token only ever on stdin.
    let docker = world.docker.0.borrow();
    let names: Vec<&str> = docker.verbs.iter().map(Verb::name).collect();
    assert_eq!(
        names,
        [
            "rm",
            "login",
            "create",
            "cp",
            "cp",
            "rm",
            "run",
            "exec",
            "exec",
            "cp",
            "exec",
            "exec",
            "cp",
            "build",
            "login",
            "push",
            "image inspect",
            "rm",
            "image rm"
        ]
    );
    for verb in &docker.verbs {
        assert!(
            !verb
                .args()
                .iter()
                .any(|arg| arg.to_string_lossy().contains("synthetic-registry-token")),
            "{verb:?}"
        );
    }
    assert!(
        matches!(&docker.verbs[0], Verb::RemoveForce { container } if container == "day2-app-slot-1")
    );
    let Verb::Start { seed, .. } = &docker.verbs[6] else {
        panic!("{:?}", docker.verbs[6]);
    };
    assert!(seed.is_some());
    assert_eq!(
        world.slots.0.borrow().1,
        ["acquire".to_owned(), "release slot-1".to_owned()]
    );
    // The receipt is the shape the CLI decodes.
    let mut decoded: Receipt = serde_json::from_value(receipt)?;
    assert_eq!(decoded.outcome.as_deref(), Some("built"));
    assert_eq!(
        decoded.candidate.as_ref().unwrap().digest,
        day2::digest(&record)
    );
    decoded.candidate.as_mut().unwrap().path = "/work/candidate.json".into();
    assert_eq!(
        serde_json::to_string_pretty(&decoded)? + "\n",
        GOLDEN_RECEIPT
    );
    assert_eq!(serde_json::from_str::<Receipt>(GOLDEN_RECEIPT)?, decoded);
    Ok(())
}

#[test]
fn a_stored_candidate_is_returned_without_reading_the_forge_or_the_build_host() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "first.json")?;
    let forge = world.fake.calls().len();
    let host = world.host.0.borrow().calls.len();
    let (receipt, steps) = world.build(COMMIT, "second.json")?;
    assert_eq!(steps, ["stored", "record"]);
    assert_eq!(receipt["outcome"], "stored");
    assert_eq!(receipt["transfer"], Value::Null);
    assert_eq!(world.fake.calls().len(), forge);
    assert_eq!(world.host.0.borrow().calls.len(), host);
    assert_eq!(
        fs::read(world.path("second.json"))?,
        fs::read(world.path("first.json"))?
    );
    // A stored record that is not this binding's and commit's is refused.
    let uri = world.uri("candidates", &format!("{COMMIT}.json"));
    let mut changed: Value = serde_json::from_slice(&world.object(&uri).unwrap())?;
    changed["binding"]["directory"] = json!("other");
    world
        .store
        .0
        .borrow_mut()
        .objects
        .insert(uri, (record::encode(&changed)?, 2));
    assert_eq!(
        error(world.build(COMMIT, "third.json")),
        "release evidence must remain in private app release state"
    );
    Ok(())
}

#[test]
fn the_same_app_inputs_at_another_commit_reuse_the_checked_result_with_a_proof() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "first.json")?;
    let cached: Value = serde_json::from_slice(&fs::read(world.path("first.json"))?)?;
    let host = world.host.0.borrow().calls.len();
    let (receipt, steps) = world.build(OTHER, "other.json")?;
    assert_eq!(
        steps,
        [
            "stored", "archive", "inputs", "controls", "cached", "reuse", "record"
        ]
    );
    assert_eq!(receipt["outcome"], "reused");
    assert_eq!(world.host.0.borrow().calls.len(), host);
    let log = world.uri("builds", &format!("{OTHER}.log"));
    let proof = world.object(&log).unwrap();
    assert_eq!(
        proof,
        format!(
            "{{\"artifact_id\": \"{ARTIFACT}\", \"binding\": \"{}\", \"checked_commit\": \"{COMMIT}\", \
             \"checked_log\": \"{}\", \"image\": \"{REGISTRY}/links/links@sha256:{IMAGE_DIGEST}\", \
             \"kind\": \"checked-input-reuse\", \"source_commit\": \"{OTHER}\", \"source_inputs\": \"{}\", \
             \"version\": 1}}\n",
            world.digest(),
            world.uri("builds", &format!("{COMMIT}.log")),
            world.inputs
        )
        .into_bytes()
    );
    let reused: Value = serde_json::from_slice(&fs::read(world.path("other.json"))?)?;
    assert_eq!(reused, record::reused(&cached, OTHER, &log));
    assert_eq!(
        world.object(&world.uri("candidates", &format!("{OTHER}.json"))),
        Some(record::encode(&reused)?)
    );
    assert!(
        world
            .store
            .0
            .borrow()
            .calls
            .contains(&format!("put {log} from reuse.json"))
    );
    Ok(())
}

#[test]
fn a_cached_result_for_the_same_commit_keeps_its_native_log() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "first.json")?;
    let candidates = world.uri("candidates", &format!("{COMMIT}.json"));
    world.store.0.borrow_mut().objects.remove(&candidates);
    let log = world.uri("builds", &format!("{COMMIT}.log"));
    let native_log = world.object(&log);
    let (receipt, _) = world.build(COMMIT, "again.json")?;
    assert_eq!(receipt["outcome"], "reused");
    assert_eq!(world.object(&log), native_log);
    assert_eq!(
        fs::read(world.path("again.json"))?,
        fs::read(world.path("first.json"))?
    );
    Ok(())
}

#[test]
fn a_cached_result_with_another_identity_is_refused_not_rebuilt() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "first.json")?;
    let inputs = world.uri("checked-inputs", &format!("{}.json", &world.inputs[7..]));
    let mut cached: Value = serde_json::from_slice(&world.object(&inputs).unwrap())?;
    cached["checked_commit"] = json!(OTHER);
    world
        .store
        .0
        .borrow_mut()
        .objects
        .insert(inputs, (record::encode(&cached)?, 2));
    let host = world.host.0.borrow().calls.len();
    assert_eq!(
        error(world.build(OTHER, "other.json")),
        "checked artifact belongs to another source/SDK/profile"
    );
    assert_eq!(world.host.0.borrow().calls.len(), host);
    Ok(())
}

#[test]
fn a_failed_native_build_keeps_its_log_as_evidence_and_removes_the_job() -> Result<()> {
    let world = World::new();
    world.docker.0.borrow_mut().failing = Some("push");
    assert_eq!(
        error(world.build(COMMIT, "candidate.json")),
        "docker push exited 1"
    );
    let log = world.uri("builds", &format!("{COMMIT}.log"));
    let text = String::from_utf8(world.object(&log).unwrap())?;
    // A Docker failure keeps the native operation logs, then the error.
    assert!(text.contains(
        "\nNative operation evidence: /workspace/platform/artifacts/operations/check-1/run.log\nsynthetic operation log\n"
    ));
    assert!(
        text.ends_with("\nnative build failed: docker push exited 1\n"),
        "{text}"
    );
    // The build host's stderr reaches the job log, never the error.
    let announced = world.fake.0.borrow().announced.clone();
    assert!(announced.contains(&"build host: synthetic remote stderr".to_owned()));
    assert_eq!(
        announced.last().unwrap(),
        &format!("build failed; private evidence: {log}")
    );
    let remote = format!("/tmp/day2-build-{}", hex(1));
    let calls = world.host.0.borrow().calls.clone();
    assert_eq!(calls.last().unwrap(), &format!("remove {remote}"));
    assert!(calls.contains(&format!("download {remote}/build.log")));
    // No record is written for a failed build, and nothing is left behind.
    assert!(
        world
            .object(&world.uri("candidates", &format!("{COMMIT}.json")))
            .is_none()
    );
    assert!(!world.path("candidate.json").exists());
    let docker = world.docker.0.borrow();
    let tail: Vec<&str> = docker.verbs[docker.verbs.len() - 2..]
        .iter()
        .map(Verb::name)
        .collect();
    assert_eq!(tail, ["rm", "image rm"]);
    Ok(())
}

#[test]
fn a_tooling_image_without_the_maintenance_protocol_is_refused_before_admission() -> Result<()> {
    let world = World::new();
    world.docker.0.borrow_mut().protocol = Some((2, "usage: day2 ...".to_owned()));
    assert_eq!(
        error(world.build(COMMIT, "candidate.json")),
        "SDK lacks the required offline admission protocol; select a compatible SDK release before \
         deployment (no application was stopped)"
    );
    let log = world.uri("builds", &format!("{COMMIT}.log"));
    let text = String::from_utf8(world.object(&log).unwrap())?;
    assert!(text.contains("SDK protocol probe refused (exit 2):\nusage: day2 ...\n"));
    // A refusal is not a Docker failure: no operation logs are read.
    assert!(!text.contains("Native operation evidence"));
    let docker = world.docker.0.borrow();
    assert!(
        !docker
            .verbs
            .iter()
            .any(|verb| matches!(verb, Verb::Security { .. }))
    );
    Ok(())
}

#[test]
fn a_failed_copy_removes_the_job_and_a_missing_seed_is_generated_natively() -> Result<()> {
    let world = World::new();
    world.host.0.borrow_mut().failing_upload = true;
    assert_eq!(
        error(world.build(COMMIT, "candidate.json")),
        "copy to the build host failed (exit 255)"
    );
    assert_eq!(
        world.fake.0.borrow().announced.last().unwrap(),
        "build failed before evidence could be archived"
    );
    let remote = format!("/tmp/day2-build-{}", hex(1));
    assert_eq!(
        world.host.0.borrow().calls.last().unwrap(),
        &format!("remove {remote}")
    );
    let world = World::new();
    world.docker.0.borrow_mut().no_seed = true;
    world.build(COMMIT, "candidate.json")?;
    let text = String::from_utf8(
        world
            .object(&world.uri("builds", &format!("{COMMIT}.log")))
            .unwrap(),
    )?;
    assert!(text.contains("No prepackaged ABI seed; using native tooling generation\n"));
    let docker = world.docker.0.borrow();
    assert!(
        !docker
            .verbs
            .iter()
            .any(|verb| matches!(verb, Verb::InstallSeed { .. }))
    );
    Ok(())
}

#[test]
fn reads_that_are_not_absence_and_concurrent_creates_are_refused() -> Result<()> {
    let world = World::new();
    world.store.0.borrow_mut().denied = true;
    assert_eq!(
        error(world.build(COMMIT, "candidate.json")),
        "cannot read private release state (authentication/network errors are not absence)"
    );
    // Another run created the candidate record during this build.
    let world = World::new();
    let uri = world.uri("candidates", &format!("{COMMIT}.json"));
    let mut session = world.session_with(
        Mode::Build,
        &world.request(Mode::Build, COMMIT, "candidate.json"),
        true,
    )?;
    for name in [
        "stored", "archive", "inputs", "controls", "cached", "run", "job", "artifact", "download",
        "attempt", "release", "stage", "native", "collect",
    ] {
        session.step(name)?;
    }
    world
        .store
        .0
        .borrow_mut()
        .objects
        .insert(uri, (b"{}".to_vec(), 1));
    assert!(error(session.step("record")).contains("412"));
    assert!(!world.path("candidate.json").exists());
    Ok(())
}

#[test]
fn a_transient_forge_read_stays_retryable() -> Result<()> {
    let world = World::new();
    world
        .fake
        .route(&format!("{PREFIX}/archive/{COMMIT}.tar.gz"), vec![None]);
    assert_eq!(
        error(world.build(COMMIT, "candidate.json")),
        "retryable: source_temporarily_unavailable"
    );
    assert!(world.host.0.borrow().calls.is_empty());
    Ok(())
}

#[test]
fn ci_controls_that_are_not_approved_cannot_reuse_a_cached_result() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "first.json")?;
    let changed = source_archive(
        &world.published.manifest,
        &[(b"links-app/.ci/extra.sh", b'0', b"echo changed\n")],
    );
    world.fake.route(
        &format!("{PREFIX}/archive/{OTHER}.tar.gz"),
        vec![bytes(changed)],
    );
    assert_eq!(
        error(world.build(OTHER, "other.json")),
        "source CI differs from the instance-approved contract"
    );
    assert!(
        world
            .object(&world.uri("candidates", &format!("{OTHER}.json")))
            .is_none()
    );
    Ok(())
}

#[test]
fn the_build_host_runs_only_the_linux_cli_and_requests_name_their_own_inputs() -> Result<()> {
    let world = World::new();
    let request = world.request(Mode::Build, COMMIT, "candidate.json");
    let mut session = world.session_with(Mode::Build, &request, false)?;
    for name in [
        "stored", "archive", "inputs", "controls", "cached", "run", "job", "artifact", "download",
        "attempt", "release",
    ] {
        session.step(name)?;
    }
    assert!(error(session.step("stage")).starts_with("the build host runs this CLI"));
    assert!(world.host.0.borrow().calls.is_empty());
    // The host fixes the mode, and a request names only its mode's inputs.
    assert!(
        error(world.session_with(Mode::Check, &request, true))
            .contains("the request is for an instance candidate build")
    );
    let mut extra = request.clone();
    extra["app_id"] = json!("links");
    assert_eq!(
        error(world.session_with(Mode::Build, &extra, true)),
        "an instance candidate build request names only its own inputs"
    );
    let mut foreign = request.clone();
    foreign["instance"]["build_host"] = json!("another-vm");
    assert_eq!(
        error(world.session_with(Mode::Build, &foreign, true)),
        "the build host must be the instance's day2-x86-qualify"
    );
    let mut identity = request.clone();
    identity["instance"]["apply_identity"] =
        json!("someone@exampleco-tools.iam.gserviceaccount.com");
    assert!(
        error(world.session_with(Mode::Build, &identity, true)).starts_with("the apply identity")
    );
    fs::write(world.path("candidate.json"), "existing")?;
    assert!(error(world.session_with(Mode::Build, &request, true)).contains("requires a new file"));
    // Steps run once, in order.
    fs::remove_file(world.path("candidate.json"))?;
    let mut session = world.session_with(Mode::Build, &request, true)?;
    assert_eq!(
        error(session.step("archive")),
        "instance candidate build runs stored next, not archive"
    );
    Ok(())
}

#[test]
fn check_validates_a_candidate_as_the_controller_did() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "candidate.json")?;
    let candidate: Value = serde_json::from_slice(&fs::read(world.path("candidate.json"))?)?;
    let check = |value: &Value| -> Result<Value> {
        fs::write(world.path("check.json"), value.to_string())?;
        let mut session = world.session_with(
            Mode::Check,
            &world.request(Mode::Check, COMMIT, "check.json"),
            true,
        )?;
        session.step("validate")
    };
    let receipt = check(&candidate)?;
    assert_eq!(
        receipt,
        json!({"format": 1, "mode": "check", "app_id": "links", "commit": COMMIT, "outcome": null,
            "candidate": null, "record": null, "build_log": candidate["build_log"],
            "image": candidate["image"], "artifact_id": ARTIFACT, "tooling_image": null,
            "transfer": null, "slot": null, "result": null, "log": null})
    );
    let refused = |change: &dyn Fn(&mut Value), message: &str| {
        let mut value = candidate.clone();
        change(&mut value);
        assert_eq!(error(check(&value)), message);
    };
    refused(
        &|value| value["binding"]["app"] = json!("notes"),
        "release belongs to another app",
    );
    refused(
        &|value| value["image"] = json!(format!("{REGISTRY}/notes/links@sha256:{IMAGE_DIGEST}")),
        "release images must be pinned and app-local",
    );
    refused(
        &|value| value["image"] = json!(format!("{REGISTRY}/links/other@sha256:{IMAGE_DIGEST}")),
        "release image mismatch",
    );
    refused(
        &|value| value["build_log"] = json!("gs://elsewhere/log"),
        "release evidence must remain in private app release state",
    );
    refused(
        &|value| value["artifact_id"] = json!("ab".repeat(32)),
        "candidate native admission belongs to another artifact",
    );
    refused(
        &|value| value["security_requirements"]["version"] = json!(true),
        "candidate native admission belongs to another artifact",
    );
    refused(
        &|value| value["source_inputs"] = json!("sha256:short"),
        "invalid checked app inputs",
    );
    refused(
        &|value| value["version"] = json!(2),
        "unsupported deployment candidate version",
    );
    refused(
        &|value| value["extra"] = json!(1),
        "invalid deployment candidate fields",
    );
    // The earlier controller's unqualified and unchecked candidates are not supported.
    refused(
        &|value| {
            let object = value.as_object_mut().unwrap();
            object.remove("ci_artifact");
        },
        "deployment candidates without a qualified SDK release and a checked main artifact are not supported",
    );
    refused(
        &|value| {
            let object = value["binding"].as_object_mut().unwrap();
            object.remove("ci_artifact");
        },
        "builds without a qualified SDK release and a checked main artifact are not supported: the binding \
         must name qualified_release, verification and ci_artifact",
    );
    refused(
        &|value| value["checked_commit"] = json!(OTHER),
        "checked artifact belongs to another source/SDK/profile",
    );
    // A float has no Python-compatible digest.
    refused(
        &|value| value["binding"]["source"]["repository_id"] = json!(4.5),
        "invalid_native_repository_id",
    );
    // The binding's source must be an app repository on the instance's forge.
    refused(
        &|value| value["binding"]["source"]["server"] = json!("https://git.example.org"),
        "the binding's source server is not day2.json's forge.server",
    );
    let repository = |name: &'static str| {
        move |value: &mut Value| {
            value["binding"]["repository"] = json!(name);
            value["binding"]["source"]["repository"] = json!(name);
            value["ci_artifact"]["receipt"]["repository"] = json!(name);
        }
    };
    refused(
        &repository("people/links-app"),
        "the binding's repository is not in day2.json's forge.org",
    );
    for platform in ["tools/day2-ci", "tools/day2-instance", "tools/Day2-CI"] {
        refused(
            &repository(platform),
            "the binding's repository is a platform repository (day2-<name>), not an app's",
        );
    }
    Ok(())
}

#[test]
fn preflight_probes_the_tooling_image_on_the_build_host_and_always_cleans_up() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "candidate.json")?;
    let before = world.host.0.borrow().calls.len();
    let docker_before = world.docker.0.borrow().verbs.len();
    let mut session = world.session_with(
        Mode::Preflight,
        &world.request(Mode::Preflight, COMMIT, "candidate.json"),
        true,
    )?;
    session.step("validate")?;
    session.step("stage")?;
    let receipt = session.step("probe")?;
    assert_eq!(receipt["mode"], "preflight");
    assert_eq!(receipt["tooling_image"], world.binding["tooling_image"]);
    assert!(receipt["transfer"]["bytes"].as_u64().unwrap() > 0);
    let remote = format!("/tmp/day2-sdk-probe-{}", hex(1));
    assert_eq!(
        world.host.0.borrow().calls[before..],
        [
            format!("create {remote}"),
            format!("upload request.json to {remote}/"),
            format!("upload day2 day2-host day2-workflows day2-workflows.json to {remote}/cli/"),
            format!("run native-probe in {remote}"),
            format!("remove {remote}"),
        ]
    );
    let docker = world.docker.0.borrow();
    let names: Vec<&str> = docker.verbs[docker_before..]
        .iter()
        .map(Verb::name)
        .collect();
    assert_eq!(names, ["login", "run --rm"]);
    drop(docker);
    // A refused protocol is the controller's message; the job is removed.
    world.docker.0.borrow_mut().protocol = Some((0, String::new()));
    let mut session = world.session_with(
        Mode::Preflight,
        &world.request(Mode::Preflight, COMMIT, "candidate.json"),
        true,
    )?;
    session.step("validate")?;
    session.step("stage")?;
    assert_eq!(
        error(session.step("probe")),
        "SDK lacks the required offline admission protocol; select a compatible SDK release before \
         deployment (no application was stopped)"
    );
    assert!(
        world
            .host
            .0
            .borrow()
            .calls
            .last()
            .unwrap()
            .starts_with("remove /tmp/day2-sdk-probe-")
    );
    // A candidate for an app day2.json does not name is refused before the build host.
    let mut foreign: Value = serde_json::from_slice(&fs::read(world.path("candidate.json"))?)?;
    foreign["binding"]["app"] = json!("absent");
    fs::write(world.path("foreign.json"), foreign.to_string())?;
    let mut session = world.session_with(
        Mode::Preflight,
        &world.request(Mode::Preflight, COMMIT, "foreign.json"),
        true,
    )?;
    assert_eq!(
        error(session.step("validate")),
        "the candidate's app absent is not in day2.json"
    );
    Ok(())
}

/// A build host job directory filled as the deploy job fills one.
fn native_job(world: &World) -> Result<(PathBuf, NativeRequest)> {
    let job = world.path("job");
    fs::DirBuilder::new().mode(0o700).create(&job)?;
    fs::create_dir(job.join("cli"))?;
    let mut files = BTreeMap::new();
    for (name, bytes) in [
        ("source.tar.gz", world.archive.clone()),
        ("ci-artifact.tar.gz", world.artifact.clone()),
        ("qualified-release.json", world.published.manifest.clone()),
        ("qualification.json", world.published.native.clone()),
    ] {
        fs::write(job.join(name), &bytes)?;
        files.insert(name.to_owned(), BlobIdentity::of(&bytes));
    }
    for name in CLI_FILES {
        let bytes = format!("synthetic {name}\n").into_bytes();
        fs::write(job.join("cli").join(name), &bytes)?;
        files.insert(format!("cli/{name}"), BlobIdentity::of(&bytes));
    }
    let proof =
        json!({"version": 1, "run": 7, "attempt": 1, "job": 31, "receipt": world.receipt(COMMIT)});
    let request = NativeRequest {
        format: 1,
        mode: Mode::NativeBuild,
        registry: REGISTRY.into(),
        app: "links".into(),
        binding: Some(world.binding.clone()),
        source_commit: Some(COMMIT.into()),
        source_inputs: Some(world.inputs.clone()),
        ci_artifact: Some(proof),
        tooling_image: None,
        files,
        budget_seconds: NATIVE_BUDGET,
    };
    fs::write(job.join("request.json"), serde_json::to_vec(&request)?)?;
    Ok((job, request))
}

fn native_run(world: &World, job: &Path, mode: Mode) -> Result<Value> {
    let mut session = Native::prepare(mode, job, native_effects(&world.docker, &world.slots))?;
    let mut last = Value::Null;
    for step in Native::steps(mode) {
        last = session.step(step)?;
    }
    Ok(last)
}

#[test]
fn the_build_host_checks_every_job_file_before_it_takes_a_slot() -> Result<()> {
    let world = World::new();
    let (job, request) = native_job(&world)?;
    fs::write(job.join("cli/day2"), "tampered")?;
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeBuild)),
        "the native job's cli/day2 differs from the request"
    );
    assert!(world.slots.0.borrow().1.is_empty());
    assert!(world.docker.0.borrow().verbs.is_empty());
    fs::write(job.join("cli/day2"), "synthetic day2\n")?;
    let mut changed = request.clone();
    changed.mode = Mode::NativeProbe;
    fs::write(job.join("request.json"), serde_json::to_vec(&changed)?)?;
    assert!(
        error(native_run(&world, &job, Mode::NativeBuild))
            .contains("the job is for another command")
    );
    let mut changed = request.clone();
    changed.binding.as_mut().unwrap()["tooling_image"] = json!(format!(
        "{REGISTRY}/links/day2-tooling@{}",
        day2::digest(b"other")
    ));
    fs::write(job.join("request.json"), serde_json::to_vec(&changed)?)?;
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeBuild)),
        "builder images differ from the qualified release"
    );
    let mut changed = request.clone();
    changed.source_inputs = Some(format!("sha256:{}", "00".repeat(32)));
    fs::write(job.join("request.json"), serde_json::to_vec(&changed)?)?;
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeBuild)),
        "builder received different app source inputs"
    );
    // The build log records the refusal; the job's outputs are its owner's.
    let log = fs::read_to_string(job.join("build.log"))?;
    assert!(log.ends_with("native build failed: builder received different app source inputs\n"));
    let mut changed = request.clone();
    changed.binding.as_mut().unwrap()["directory"] = json!("../app");
    fs::write(job.join("request.json"), serde_json::to_vec(&changed)?)?;
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeBuild)),
        "invalid source subdirectory"
    );
    // The build host reads no day2.json, but never builds a platform repository.
    let mut changed = request.clone();
    let binding = changed.binding.as_mut().unwrap();
    binding["repository"] = json!("tools/DAY2-ci");
    binding["source"]["repository"] = json!("tools/DAY2-ci");
    fs::write(job.join("request.json"), serde_json::to_vec(&changed)?)?;
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeBuild)),
        "the binding's repository is a platform repository (day2-<name>), not an app's"
    );
    // A job directory others can read is refused.
    fs::set_permissions(&job, fs::Permissions::from_mode(0o755))?;
    assert!(
        error(native_run(&world, &job, Mode::NativeBuild))
            .starts_with("the native job directory must be a private directory")
    );
    Ok(())
}

#[test]
fn the_native_probe_names_only_an_app_local_pinned_image() -> Result<()> {
    let world = World::new();
    let job = world.path("probe");
    fs::DirBuilder::new().mode(0o700).create(&job)?;
    fs::create_dir(job.join("cli"))?;
    let mut files = BTreeMap::new();
    for name in CLI_FILES {
        let bytes = format!("synthetic {name}\n").into_bytes();
        fs::write(job.join("cli").join(name), &bytes)?;
        files.insert(format!("cli/{name}"), BlobIdentity::of(&bytes));
    }
    let mut request = NativeRequest {
        format: 1,
        mode: Mode::NativeProbe,
        registry: REGISTRY.into(),
        app: "links".into(),
        binding: None,
        source_commit: None,
        source_inputs: None,
        ci_artifact: None,
        tooling_image: world.binding["tooling_image"].as_str().map(str::to_owned),
        files,
        budget_seconds: PROBE_BUDGET,
    };
    fs::write(job.join("request.json"), serde_json::to_vec(&request)?)?;
    let receipt = native_run(&world, &job, Mode::NativeProbe)?;
    assert_eq!(receipt["app_id"], "links");
    assert_eq!(world.slots.0.borrow().1, ["probe", "release slot-probe"]);
    request.tooling_image = Some(format!(
        "{REGISTRY}/notes/day2-tooling@{}",
        day2::digest(b"x")
    ));
    fs::write(job.join("request.json"), serde_json::to_vec(&request)?)?;
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeProbe)),
        "SDK probe requires a pinned app-local image"
    );
    Ok(())
}

#[test]
fn the_checked_artifact_is_extracted_for_transport_only() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let receipt = |archive: &[u8]| {
        let identity = BlobIdentity::of(archive);
        json!({"artifact_id": ARTIFACT, "archive": {"digest": identity.digest, "bytes": identity.bytes}})
    };
    let extracted = |files: &[(&str, u32, &[u8])]| -> Result<String> {
        let archive = artifact_archive(files);
        let path = directory.path().join("artifact.tar.gz");
        fs::write(&path, &archive)?;
        let destination = tempfile::tempdir_in(directory.path())?;
        native::extract(&path, destination.path(), &receipt(&archive))
    };
    let id = |name: &str| format!("{ARTIFACT}/{name}");
    let complete = [
        (id("artifact.json"), 0o444, b"{}".as_slice()),
        (id("worker"), 0o555, b"elf".as_slice()),
        (id("verification.json"), 0o444, b"{}".as_slice()),
    ];
    let files: Vec<(&str, u32, &[u8])> = complete
        .iter()
        .map(|(n, m, d)| (n.as_str(), *m, *d))
        .collect();
    assert_eq!(extracted(&files)?, ARTIFACT);
    let refused = |extra: (&str, u32, &[u8]), message: &str| {
        let mut all = files.clone();
        all.push(extra);
        assert_eq!(error(extracted(&all)), message, "{}", extra.0);
    };
    refused(
        (&id("writable"), 0o644, b"x"),
        "unsafe checked artifact entry",
    );
    refused(
        ("other/artifact.json", 0o444, b"x"),
        "unsafe checked artifact entry",
    );
    refused(
        (&id("a/../b"), 0o444, b"x"),
        "unsafe checked artifact entry",
    );
    refused(
        (&format!("{ARTIFACT}//double"), 0o444, b"x"),
        "unsafe checked artifact entry",
    );
    refused(
        (&id("worker"), 0o555, b"again"),
        "unsafe checked artifact entry",
    );
    assert_eq!(
        error(extracted(&files[..2])),
        "checked artifact is incomplete"
    );
    let path = directory.path().join("artifact.tar.gz");
    let destination = tempfile::tempdir_in(directory.path())?;
    let archive = artifact_archive(&files);
    fs::write(&path, &archive)?;
    let mut changed = receipt(&archive);
    changed["archive"]["bytes"] = json!(1);
    assert_eq!(
        error(native::extract(&path, destination.path(), &changed)),
        "checked artifact archive changed"
    );
    Ok(())
}

#[test]
fn the_registry_token_is_never_formatted() {
    assert_eq!(
        format!("{:?}", Secret::new("synthetic-registry-token".into())),
        "Secret(<redacted>)"
    );
}

#[test]
fn verbs_are_the_earlier_build_hosts_docker_commands() {
    let args = |verb: Verb| -> Vec<String> {
        verb.args()
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(
        args(Verb::Start {
            name: "day2-app-slot-0".into(),
            image: "tooling".into(),
            export: PathBuf::from("/tmp/day2-build-x/artifacts"),
            seed: Some(PathBuf::from("/tmp/day2-build-x/roc_platform_abi.rs")),
        }),
        [
            "run",
            "--detach",
            "--name",
            "day2-app-slot-0",
            "--env",
            "DAY2_PRECOMPILED_TOOLING=1",
            "--network=none",
            "--memory=6g",
            "--memory-swap=6g",
            "--cpus=4",
            "--pids-limit=512",
            "--cgroupns=private",
            "--tmpfs",
            "/workspace/platform/artifacts:rw,exec,nosuid,nodev,size=1g",
            "--tmpfs",
            "/workspace/platform/crates/worker/generated:rw,nosuid,nodev,size=64m",
            "--mount",
            "type=bind,source=/tmp/day2-build-x/artifacts,target=/qualification-export",
            "--mount",
            "type=bind,source=/tmp/day2-build-x/roc_platform_abi.rs,target=/qualification-abi-seed,readonly",
            "tooling",
            "sleep",
            "infinity"
        ]
    );
    assert_eq!(
        args(Verb::Probe {
            image: "tooling".into(),
            absent: "/tmp/day2-sdk-protocol-x.json".into()
        }),
        [
            "run",
            "--rm",
            "--network=none",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=64",
            "--entrypoint=/workspace/platform/build-out/bin/day2",
            "tooling",
            "admit-maintenance",
            "/tmp/day2-sdk-protocol-x.json",
            "sdk-probe",
            "sdk-probe@example.invalid"
        ]
    );
    assert_eq!(
        args(Verb::Login {
            host: "us-central1-docker.pkg.dev".into()
        }),
        [
            "login",
            "-u",
            "oauth2accesstoken",
            "--password-stdin",
            "us-central1-docker.pkg.dev"
        ]
    );
    assert_eq!(
        args(Verb::Build {
            runtime: "runtime".into(),
            artifact_id: "ab".into(),
            dockerfile: PathBuf::from("/j/Dockerfile"),
            tag: "repo:tag".into(),
            context: PathBuf::from("/j"),
        }),
        [
            "build",
            "--build-arg",
            "DAY2_RUNTIME_IMAGE=runtime",
            "--build-arg",
            "ARTIFACT_ID=ab",
            "-f",
            "/j/Dockerfile",
            "-t",
            "repo:tag",
            "/j"
        ]
    );
}

#[test]
fn remote_paths_and_absence_are_recognized_exactly() {
    assert!(tools::remote_directory(&format!(
        "/tmp/day2-build-{}",
        hex(1)
    )));
    assert!(tools::remote_directory(&format!(
        "/tmp/day2-sdk-probe-{}",
        hex(1)
    )));
    assert!(!tools::remote_directory("/tmp/day2-build-; rm -rf /"));
    assert!(!tools::remote_directory(&format!(
        "/tmp/day2-build-{}/x",
        hex(1)
    )));
    assert!(tools::absent(
        "ERROR: (gcloud.storage.objects.describe) gs://b/k not found: 404."
    ));
    assert!(tools::absent(
        "The following URLs matched no objects or files: No URLs matched"
    ));
    assert!(!tools::absent(
        "ERROR: HTTPError 403: caller lacks access to b/x4040"
    ));
    assert!(!tools::absent("network unreachable"));
}

#[test]
fn the_build_hosts_envelope_is_its_last_line_and_its_message_is_kept() -> Result<()> {
    let remote = |code: i32, stdout: &str| tools::Remote {
        code: Some(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: b"Permission denied (publickey).".to_vec(),
    };
    let ok = r#"{"ok": true, "result": {"receipt": {"mode": "native-probe"}}}"#;
    assert_eq!(
        remote_outcome(&remote(0, ok), "probe")?["mode"],
        "native-probe"
    );
    let noisy = format!("Warning: Permanently added 'compute.1' (ED25519)\n{ok}\n\n");
    assert_eq!(
        remote_outcome(&remote(0, &noisy), "probe")?["mode"],
        "native-probe"
    );
    let refused = r#"{"ok": false, "error": {"message": "SDK lacks the protocol"}}"#;
    assert_eq!(
        error(remote_outcome(&remote(6, refused), "probe")),
        "SDK lacks the protocol"
    );
    assert_eq!(
        error(remote_outcome(
            &remote(255, "ssh: connect failed\n"),
            "native probe"
        )),
        "native probe failed on the build host (exit 255)"
    );
    assert_eq!(
        error(remote_outcome(
            &remote(0, "not an envelope"),
            "native build"
        )),
        "native build failed on the build host (exit 0)"
    );
    Ok(())
}

#[test]
fn records_and_digests_are_pythons_bytes() -> Result<()> {
    // Python: json.dumps(value, sort_keys=True) and its sha256.
    let binding = json!({"b": 1, "a": "\u{e9}", "c": {"z": [true, null], "y": "x"}});
    assert_eq!(
        record::encode(&binding)?,
        b"{\"a\": \"\\u00e9\", \"b\": 1, \"c\": {\"y\": \"x\", \"z\": [true, null]}}\n".to_vec()
    );
    assert_eq!(
        record::binding_digest(&binding)?,
        "a40d799ecc16721d912316a25845c92b0cacd7fd536df0a5fe18b076acb8ab23"
    );
    assert!(record::encode(&json!({"a": 1.0})).is_err());
    assert_eq!(
        record::decode(b"{\"a\": 1, \"a\": 2}")
            .unwrap_err()
            .to_string(),
        "duplicate JSON field"
    );
    assert_eq!(
        record::candidate_uri(BUCKET, "links", "d", COMMIT),
        format!("gs://{BUCKET}/day2/app-releases/links/candidates/d/{COMMIT}.json")
    );
    assert_eq!(
        record::inputs_uri(BUCKET, "links", "d", "sha256:abc"),
        format!("gs://{BUCKET}/day2/app-releases/links/checked-inputs/d/abc.json")
    );
    Ok(())
}

/// One member, written exactly: a raw ustar name (with an optional ustar
/// prefix), a pax path, or a GNU long name; regular, directory or link.
enum Name<'a> {
    Plain(&'a [u8]),
    Prefixed(&'a [u8], &'a [u8]),
    Pax(&'a [u8]),
    Gnu(&'a [u8]),
}

fn member(builder: &mut tar::Builder<Vec<u8>>, name: Name<'_>, kind: u8, data: &[u8]) {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_size(data.len() as u64);
    header.set_mode(if kind == b'5' { 0o755 } else { 0o644 });
    if kind == b'2' || kind == b'1' {
        header.set_link_name("target").unwrap();
    }
    let short = |header: &mut tar::Header, name: &[u8]| {
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
    };
    match name {
        Name::Plain(name) => short(&mut header, name),
        Name::Prefixed(prefix, name) => {
            header.as_ustar_mut().unwrap().prefix[..prefix.len()].copy_from_slice(prefix);
            short(&mut header, name);
        }
        Name::Pax(name) => {
            entry(builder, b"PaxHeader", b'x', &pax("path", name));
            short(&mut header, b"pax-placeholder");
        }
        Name::Gnu(name) => {
            let mut long = tar::Header::new_gnu();
            long.set_entry_type(tar::EntryType::new(b'L'));
            long.set_size(name.len() as u64 + 1);
            long.as_old_mut().name[..13].copy_from_slice(b"././@LongLink");
            long.set_cksum();
            builder
                .append(&long, [name, b"\0"].concat().as_slice())
                .unwrap();
            short(&mut header, &name[..99]);
        }
    }
    header.set_cksum();
    builder.append(&header, data).unwrap();
}

fn archive(members: Vec<(Name<'_>, u8, &[u8])>) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    entry(&mut builder, b"pax_global_header", b'g', &comment());
    for (name, kind, data) in members {
        member(&mut builder, name, kind, data);
    }
    let raw = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw).unwrap();
    encoder.finish().unwrap()
}

const LONG: &[u8] = b"r/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/long/file.roc";

/// A root app: controls excluded, names ordered by parts, UTF-8 and
/// non-UTF-8 names, dot and double-slash segments, a GNU long name, a ustar
/// prefix, and a link outside the app.
fn root_vector() -> Vec<u8> {
    archive(vec![
        (Name::Plain(b"r/"), b'5', b""),
        (Name::Plain(b"r/App.roc"), b'0', b"app [main!] {}\n"),
        (Name::Plain(b"r/a/b.roc"), b'0', b"b\n"),
        (Name::Plain(b"r/a-b.roc"), b'0', b"a-b\n"),
        (Name::Plain(b"r/a.b"), b'0', b"a.b\n"),
        (Name::Plain(b"r/z/y/x.roc"), b'0', b"x\n"),
        (Name::Plain(b"r/.ci/roc.json"), b'0', b"{}"),
        (Name::Plain(b"r/.ci/link"), b'2', b""),
        (
            Name::Plain(b"r/.gitea/workflows/roc.yml"),
            b'0',
            b"name: x\n",
        ),
        (Name::Plain(b"r/README.md"), b'0', b"readme\n"),
        (Name::Pax("r/\u{e9}t\u{e9}.roc".as_bytes()), b'0', b"utf8\n"),
        (Name::Pax(b"r/caf\xe9.txt"), b'0', b"latin1\n"),
        (
            Name::Pax("r/emoji-\u{1f600}.txt".as_bytes()),
            b'0',
            b"astral\n",
        ),
        (Name::Pax(b"r/d\xff/x.roc"), b'0', b"invalid dir\n"),
        (Name::Plain(b"r/./dot/./x.roc"), b'0', b"dot\n"),
        (Name::Plain(b"r/a//double.roc"), b'0', b"double\n"),
        (Name::Gnu(LONG), b'0', b"long\n"),
        (
            Name::Prefixed(b"r/prefixed", b"file.roc"),
            b'0',
            b"prefixed\n",
        ),
        (Name::Plain(b"r/empty.roc"), b'0', b""),
        // Code point order, not byte or UTF-16 order: byte order puts a lone
        // 0xC3 (U+DCC3) before U+00E9, and UTF-16 order puts U+1F600 first.
        (Name::Pax(b"r/\xc3A"), b'0', b"surrogate escape\n"),
        (Name::Pax("r/\u{e9}".as_bytes()), b'0', b"e acute\n"),
        (Name::Pax("r/\u{fffd}".as_bytes()), b'0', b"replacement\n"),
        (Name::Pax("r/\u{1f600}".as_bytes()), b'0', b"astral\n"),
    ])
}

/// An app in a subdirectory of a monorepo, beside a similarly named one.
fn monorepo_vector() -> Vec<u8> {
    archive(vec![
        (Name::Plain(b"m/"), b'5', b""),
        (Name::Plain(b"m/apps/links/"), b'5', b""),
        (
            Name::Plain(b"m/apps/links/App.roc"),
            b'0',
            b"app [main!] {}\n",
        ),
        (Name::Plain(b"m/apps/links/src/Main.roc"), b'0', b"main\n"),
        (
            Name::Plain(b"m/apps/linksother/x.roc"),
            b'0',
            b"not the app\n",
        ),
        (Name::Plain(b"m/apps/other/App.roc"), b'0', b"another app\n"),
        (Name::Plain(b"m/root-link"), b'2', b""),
        (Name::Plain(b"m/.ci/x"), b'0', b"control\n"),
        (Name::Pax(b"m/apps/links/\xfe.roc"), b'0', b"invalid\n"),
    ])
}

/// What the earlier build tooling computed for the vectors, on Linux, from the
/// archives `write_vectors` writes.
const ROOT_INPUTS: &str = "sha256:cc85ad79dfc46d6fc97f70eb289954ba42ad5f09a35c17e68cb729cb9f19b26f";
const MONOREPO_INPUTS: &str =
    "sha256:d96c129b9cd539a29987eb9c78514a40837d7669c89b830d232f49c234473aa6";

#[test]
fn source_inputs_are_the_earlier_toolings_for_every_name_shape() -> Result<()> {
    assert_eq!(source_inputs(&root_vector(), ".")?, ROOT_INPUTS);
    assert_eq!(
        source_inputs(&monorepo_vector(), "apps/links")?,
        MONOREPO_INPUTS
    );
    // The archive's order and prefix and the controls are not inputs.
    let reordered = archive(vec![
        (Name::Plain(b"other-root/z/y/x.roc"), b'0', b"x\n"),
        (
            Name::Plain(b"other-root/App.roc"),
            b'0',
            b"app [main!] {}\n",
        ),
    ]);
    let ordered = archive(vec![
        (Name::Plain(b"r/App.roc"), b'0', b"app [main!] {}\n"),
        (Name::Plain(b"r/.ci/new"), b'0', b"control\n"),
        (Name::Plain(b"r/z/y/x.roc"), b'0', b"x\n"),
    ]);
    assert_eq!(
        source_inputs(&reordered, ".")?,
        source_inputs(&ordered, ".")?
    );
    // Every byte and name of the app is.
    let changed = archive(vec![
        (Name::Plain(b"r/App.roc"), b'0', b"app [main!] {}\n"),
        (Name::Plain(b"r/z/y/x.roc"), b'0', b"y\n"),
    ]);
    assert_ne!(source_inputs(&changed, ".")?, source_inputs(&ordered, ".")?);
    Ok(())
}

#[test]
fn source_archives_python_would_not_extract_are_refused() {
    let app: (Name<'_>, u8, &[u8]) = (Name::Plain(b"r/App.roc"), b'0', b"app\n");
    let refused = |members: Vec<(Name<'_>, u8, &[u8])>, directory: &str, message: &str| {
        assert_eq!(error(source_inputs(&archive(members), directory)), message);
    };
    refused(
        vec![app, (Name::Plain(b"r/App.roc"), b'0', b"again\n")],
        ".",
        "duplicate source archive file",
    );
    refused(
        vec![
            (Name::Plain(b"r/a"), b'0', b"file\n"),
            (Name::Plain(b"r/a/b"), b'0', b"below\n"),
        ],
        ".",
        "source archive file below another file",
    );
    refused(
        vec![
            (Name::Plain(b"r/a/b"), b'0', b"file\n"),
            (Name::Plain(b"r/a"), b'0', b"over a directory\n"),
        ],
        ".",
        "duplicate source archive file",
    );
    refused(
        vec![
            (Name::Plain(b"r/App.roc"), b'0', b"app\n"),
            (Name::Plain(b"r/link"), b'2', b""),
        ],
        ".",
        "source archive links/special files refused",
    );
    refused(
        vec![
            (Name::Plain(b"r/App.roc"), b'0', b"app\n"),
            (Name::Plain(b"r/.ci/hard"), b'1', b""),
        ],
        ".",
        "source archive links/special files refused",
    );
    refused(
        vec![
            (Name::Plain(b"r/App.roc"), b'0', b"app\n"),
            (Name::Plain(b"s/x"), b'0', b"x\n"),
        ],
        ".",
        "source archive has multiple roots",
    );
    refused(
        vec![(Name::Plain(b"/r/App.roc"), b'0', b"app\n")],
        ".",
        "unsafe source archive path",
    );
    refused(
        vec![(Name::Plain(b"r/../App.roc"), b'0', b"app\n")],
        ".",
        "unsafe source archive path",
    );
    refused(
        vec![(Name::Plain(b"r/Main.roc"), b'0', b"main\n")],
        ".",
        "app entrypoint missing",
    );
    refused(
        vec![(Name::Plain(b"r/"), b'5', b"")],
        ".",
        "source archive is empty",
    );
    refused(
        vec![(Name::Plain(b"r"), b'0', b"root file\n")],
        ".",
        "source archive needs a repository directory",
    );
    refused(
        vec![(Name::Plain(b"r/App.roc"), b'0', b"app\n")],
        "../r",
        "invalid source subdirectory",
    );
    let mut many: Vec<(Name<'_>, u8, &[u8])> = Vec::new();
    let names: Vec<Vec<u8>> = (0..=instance_source::ENTRY_LIMIT)
        .map(|index| format!("r/{index}").into_bytes())
        .collect();
    for name in &names {
        many.push((Name::Plain(name), b'5', b""));
    }
    refused(many, ".", "source archive exceeds budget");
}

/// Writes the vectors, and the refused archives, for the earlier tooling to
/// read: `DAY2_CANDIDATE_VECTORS=<new directory>`.
#[test]
fn write_vectors() -> Result<()> {
    let Some(directory) = std::env::var_os("DAY2_CANDIDATE_VECTORS") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    fs::create_dir(&directory)?;
    fs::write(directory.join("root.tar.gz"), root_vector())?;
    fs::write(directory.join("monorepo.tar.gz"), monorepo_vector())?;
    Ok(())
}

/// Golden checks against a private copy of an instance's release state, run by
/// hand: `DAY2_CANDIDATE_GOLDEN=<directory>`, holding
/// `<app>/{candidates,checked-inputs,builds}/<digest>/<name>` as the bucket
/// does, `archives/<app>/<commit>.tar.gz` (source archives at checked commits),
/// and `artifacts/<app>/<commit>.tar.gz` with `<commit>.python.json`, the
/// earlier tooling's extraction listing. No instance data is in the repository.
#[test]
fn live_records_golden() -> Result<()> {
    let Some(root) = std::env::var_os("DAY2_CANDIDATE_GOLDEN") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let children = |path: &Path| -> Result<Vec<PathBuf>> {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()?;
        entries.sort();
        Ok(entries)
    };
    let name = |path: &Path| path.file_name().unwrap().to_str().unwrap().to_owned();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut checked: Vec<(String, Value)> = Vec::new();
    for app_directory in children(&root)? {
        let app = name(&app_directory);
        if app == "archives" || app == "artifacts" || !app_directory.join("builds").is_dir() {
            continue;
        }
        for kind in ["candidates", "checked-inputs"] {
            let directory = app_directory.join(kind);
            if !directory.is_dir() {
                continue;
            }
            for digest_directory in children(&directory)? {
                let digest = name(&digest_directory);
                for file in children(&digest_directory)? {
                    let bytes = fs::read(&file)?;
                    let value = record::decode(&bytes)?;
                    // G2: the record's bytes are its encoding; G1: its digest and log path.
                    assert_eq!(record::encode(&value)?, bytes, "{}", file.display());
                    assert_eq!(record::binding_digest(&value["binding"])?, digest);
                    let log = value["build_log"].as_str().unwrap();
                    assert_eq!(log.split('/').rev().nth(1), Some(digest.as_str()));
                    *counts.entry("records re-encoded").or_default() += 1;
                    let commit = value["source_commit"].as_str().unwrap();
                    let builds = app_directory.join("builds").join(&digest);
                    let evidence = fs::read(builds.join(format!("{commit}.log"))).ok();
                    if kind == "candidates"
                        && value["checked_commit"].is_string()
                        && value["checked_commit"] != value["source_commit"]
                    {
                        // G5: a reused candidate and its proof, rebuilt from the cached result.
                        let inputs = value["source_inputs"].as_str().unwrap();
                        let cached = record::decode(&fs::read(
                            app_directory
                                .join("checked-inputs")
                                .join(&digest)
                                .join(format!("{}.json", &inputs[7..])),
                        )?)?;
                        assert_eq!(record::reused(&cached, commit, log), value);
                        let proof = record::reuse_proof(&digest, commit, inputs, &cached);
                        assert_eq!(Some(record::encode(&proof)?), evidence);
                        *counts.entry("reuse proofs rebuilt").or_default() += 1;
                    }
                    if !value.as_object().unwrap().contains_key("ci_artifact") {
                        *counts.entry("older shapes").or_default() += 1;
                        continue;
                    }
                    let runtime = value["binding"]["runtime_image"].as_str().unwrap();
                    let registry = runtime.split(&format!("/{app}/")).next().unwrap();
                    let bucket = log
                        .strip_prefix("gs://")
                        .and_then(|rest| rest.split('/').next())
                        .unwrap();
                    // G3: the controller's validation accepts every current record, on the forge its
                    // binding names.
                    let binding = &value["binding"];
                    let server = binding["source"]["server"].as_str().unwrap();
                    let org = binding["repository"]
                        .as_str()
                        .unwrap()
                        .split('/')
                        .next()
                        .unwrap();
                    record::check(
                        &value,
                        &app,
                        &record::Scope {
                            server,
                            org,
                            registry,
                            bucket,
                        },
                    )?;
                    *counts.entry("records checked").or_default() += 1;
                    if kind == "checked-inputs"
                        && let Some(text) = evidence
                    {
                        // G6: the native log's promotion header.
                        let header = format!(
                            "Promoting checked main artifact; no app compilation or campaign rerun\n{}\n",
                            String::from_utf8(day2::python_json::dumps(
                                &value["ci_artifact"],
                                day2::python_json::Layout::Default
                            )?)?
                        );
                        assert!(text.starts_with(header.as_bytes()), "{}", file.display());
                        *counts.entry("log headers").or_default() += 1;
                        checked.push((app.clone(), value.clone()));
                    }
                }
            }
        }
    }
    // G4: the source inputs of each checked commit's archive.
    for (app, value) in &checked {
        let commit = value["checked_commit"].as_str().unwrap();
        let path = root
            .join("archives")
            .join(app)
            .join(format!("{commit}.tar.gz"));
        if let Ok(archive) = fs::read(&path) {
            let directory = value["binding"]["directory"].as_str().unwrap();
            assert_eq!(
                source_inputs(&archive, directory)?,
                value["source_inputs"],
                "{}",
                path.display()
            );
            *counts.entry("archives' source inputs").or_default() += 1;
        }
        // The checked artifact, extracted as the earlier tooling extracted it.
        let artifact = root
            .join("artifacts")
            .join(app)
            .join(format!("{commit}.tar.gz"));
        if artifact.is_file() {
            let destination = tempfile::tempdir()?;
            let receipt = &value["ci_artifact"]["receipt"];
            let id = native::extract(&artifact, destination.path(), receipt)?;
            let mut listing = Vec::new();
            let mut pending = vec![destination.path().join(&id)];
            while let Some(path) = pending.pop() {
                for entry in fs::read_dir(&path)? {
                    let path = entry?.path();
                    let metadata = fs::symlink_metadata(&path)?;
                    if metadata.is_dir() {
                        pending.push(path);
                    } else {
                        let relative = path.strip_prefix(destination.path())?;
                        let digest = day2::digest(&fs::read(&path)?);
                        listing.push(json!([
                            relative.to_str().unwrap(),
                            std::os::unix::fs::MetadataExt::mode(&metadata) & 0o7777,
                            digest
                        ]));
                    }
                }
            }
            listing.sort_by_key(|entry| entry[0].as_str().unwrap().to_owned());
            let python: Value = serde_json::from_slice(&fs::read(
                root.join("artifacts")
                    .join(app)
                    .join(format!("{commit}.python.json")),
            )?)?;
            assert_eq!(Value::Array(listing), python, "{}", artifact.display());
            *counts.entry("artifacts extracted").or_default() += 1;
        }
    }
    eprintln!("live golden: {counts:?}");
    Ok(())
}

#[test]
fn a_lost_connection_logs_the_build_hosts_stderr_and_leaves_its_directory() -> Result<()> {
    let world = World::new();
    world.host.0.borrow_mut().lost = Some("Permission denied (publickey).");
    let message = error(world.build(COMMIT, "candidate.json"));
    // The error carries what failed, never the remote stderr.
    assert_eq!(message, "native build failed on the build host (exit 255)");
    let announced = world.fake.0.borrow().announced.clone();
    assert!(announced.contains(&"build host: Permission denied (publickey).".to_owned()));
    let remote = format!("/tmp/day2-build-{}", hex(1));
    // A session that may still be running keeps its directory, and says so.
    assert!(announced.iter().any(|line| line.starts_with(&format!(
        "the build host's job directory {remote} is left in place"
    ))));
    let calls = world.host.0.borrow().calls.clone();
    assert!(!calls.contains(&format!("remove {remote}")), "{calls:?}");
    assert!(world.host.local(&remote).is_dir());
    assert!(
        world
            .object(&world.uri("candidates", &format!("{COMMIT}.json")))
            .is_none()
    );
    Ok(())
}

#[test]
fn a_create_that_fails_after_making_the_directory_still_removes_it() -> Result<()> {
    let world = World::new();
    world.host.0.borrow_mut().failing_create = true;
    assert_eq!(
        error(world.build(COMMIT, "candidate.json")),
        "create the build host job directory failed (killed)"
    );
    let remote = format!("/tmp/day2-build-{}", hex(1));
    assert_eq!(
        world.host.0.borrow().calls.last().unwrap(),
        &format!("remove {remote}")
    );
    assert!(!world.host.local(&remote).exists());
    Ok(())
}

#[test]
fn files_copied_out_of_the_tooling_image_must_be_regular_files() -> Result<()> {
    for (linked, verb) in [("roc_platform_abi.rs", "run"), ("Dockerfile", "build")] {
        let world = World::new();
        let secret = world.path("host-secret");
        fs::write(&secret, "host only\n")?;
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
        world.docker.0.borrow_mut().linked = Some((linked, secret.clone()));
        let message = error(world.build(COMMIT, "candidate.json"));
        assert!(message.contains("must be a regular file"), "{message}");
        assert!(message.contains("not a regular file"), "{message}");
        // Nothing was changed, mounted or built through the link.
        assert_eq!(fs::metadata(&secret)?.mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&secret)?, "host only\n");
        let docker = world.docker.0.borrow();
        if verb == "run" {
            assert!(!docker.verbs.iter().any(|v| matches!(v, Verb::Start { .. })));
        } else {
            assert!(!docker.verbs.iter().any(|v| matches!(v, Verb::Build { .. })));
        }
    }
    Ok(())
}

#[test]
fn the_build_host_stops_at_its_budget_and_caps_every_docker_command() -> Result<()> {
    let world = World::new();
    world.build(COMMIT, "candidate.json")?;
    // Every step's Docker command had at most what was left of the budget.
    let budget = Duration::from_secs(NATIVE_BUDGET);
    assert!(
        world
            .docker
            .0
            .borrow()
            .timeouts
            .iter()
            .all(|timeout| *timeout <= budget)
    );
    let world = World::new();
    let (job, mut request) = native_job(&world)?;
    request.budget_seconds = 1;
    fs::write(job.join("request.json"), serde_json::to_vec(&request)?)?;
    world.docker.0.borrow_mut().slow_create = Duration::from_millis(1100);
    assert_eq!(
        error(native_run(&world, &job, Mode::NativeBuild)),
        "the build host's native-build exceeded its 1 s budget"
    );
    let docker = world.docker.0.borrow();
    let names: Vec<&str> = docker.verbs.iter().map(Verb::name).collect();
    // No Docker command ran after the budget, but the cleanup did.
    assert_eq!(names, ["rm", "login", "create", "rm"]);
    assert!(
        docker.timeouts[..3]
            .iter()
            .all(|timeout| *timeout <= Duration::from_secs(1))
    );
    assert_eq!(docker.timeouts[3], Duration::from_secs(120));
    drop(docker);
    let mut changed = request.clone();
    changed.budget_seconds = native::BUDGET_LIMIT + 1;
    fs::write(job.join("request.json"), serde_json::to_vec(&changed)?)?;
    assert!(error(native_run(&world, &job, Mode::NativeBuild)).contains("budget must be 1 to"));
    Ok(())
}

#[test]
fn admission_output_that_cannot_be_recorded_is_refused_before_the_push() -> Result<()> {
    let world = World::new();
    world.docker.0.borrow_mut().float = true;
    let message = error(world.build(COMMIT, "candidate.json"));
    assert!(
        message.starts_with("the native admission evidence cannot be recorded"),
        "{message}"
    );
    let docker = world.docker.0.borrow();
    assert!(
        !docker
            .verbs
            .iter()
            .any(|verb| matches!(verb, Verb::Push { .. } | Verb::Build { .. }))
    );
    Ok(())
}

/// An executable stub in `directory`, a POSIX shell script.
fn stub(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn target() -> tools::Target {
    tools::Target {
        host: BUILD_HOST.into(),
        project: "exampleco-tools".into(),
        zone: "us-central1-a".into(),
        account: "tools-infra@exampleco-tools.iam.gserviceaccount.com".into(),
    }
}

/// Each recorded invocation's arguments.
fn calls(log: &Path) -> Vec<Vec<String>> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .split("--end--\n")
        .filter(|call| !call.is_empty())
        .map(|call| call.lines().map(str::to_owned).collect())
        .collect()
}

#[test]
fn gcloud_runs_exactly_its_closed_verbs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let log = directory.path().join("calls");
    let program = stub(
        directory.path(),
        "gcloud",
        &format!(
            r#"for arg in "$@"; do printf '%s\n' "$arg" >> '{log}'; done
printf -- '--end--\n' >> '{log}'
case "$3" in
  describe) case "$4" in
    *absent*) echo 'ERROR: (gcloud.storage.objects.describe) not found: 404.' >&2; exit 1;;
    *denied*) echo 'ERROR: 403 the caller does not have access' >&2; exit 1;;
  esac
  echo 7; exit 0;;
esac
case "$2" in
  cat) printf '{{"a": 1}}';;
  ssh) case "$*" in *native-probe*) printf 'noise\n{{"ok": true, "result": {{"receipt": {{"mode": "native-probe"}}}}}}\n'; echo 'remote warning' >&2;; esac;;
  cp) case "$4" in *fail*) echo 'ERROR: HTTPError 412: precondition' >&2; exit 1;; esac;;
esac
exit 0
"#,
            log = log.display()
        ),
    );
    let mut gcloud = tools::Gcloud::at(program);
    let store: &mut dyn tools::Store = &mut gcloud;
    let uri = "gs://exampleco-tools-tofu-state/day2/app-releases/links/candidates/d/c.json";
    assert_eq!(
        store.read(uri)?,
        Some((b"{\"a\": 1}".to_vec(), "7".to_owned()))
    );
    assert_eq!(store.read("gs://b/absent.json")?, None);
    // A failure that is not absence is a refusal, and its stderr is not in it.
    assert_eq!(
        error(store.read("gs://b/denied.json")),
        "cannot read private release state (authentication/network errors are not absence)"
    );
    let file = directory.path().join("record.json");
    fs::write(&file, b"{}\n")?;
    store.write(&file, uri, "0")?;
    store.put(&file, "gs://b/builds/d/c.log")?;
    assert_eq!(
        error(store.put(&file, "gs://b/fail.log")),
        "write private build evidence failed (exit 1)"
    );
    let file_arg = file.to_str().unwrap().to_owned();
    let mut expected: Vec<Vec<String>> = vec![
        [
            "storage",
            "objects",
            "describe",
            uri,
            "--format=value(generation)",
        ]
        .map(str::to_owned)
        .to_vec(),
        ["storage", "cat", &format!("{uri}#7")]
            .map(str::to_owned)
            .to_vec(),
        [
            "storage",
            "objects",
            "describe",
            "gs://b/absent.json",
            "--format=value(generation)",
        ]
        .map(str::to_owned)
        .to_vec(),
        [
            "storage",
            "objects",
            "describe",
            "gs://b/denied.json",
            "--format=value(generation)",
        ]
        .map(str::to_owned)
        .to_vec(),
        ["storage", "cp", &file_arg, uri, "--if-generation-match=0"]
            .map(str::to_owned)
            .to_vec(),
        ["storage", "cp", &file_arg, "gs://b/builds/d/c.log"]
            .map(str::to_owned)
            .to_vec(),
        ["storage", "cp", &file_arg, "gs://b/fail.log"]
            .map(str::to_owned)
            .to_vec(),
    ];
    assert_eq!(calls(&log), expected);
    let host: &mut dyn tools::BuildHost = &mut gcloud;
    let remote = format!("/tmp/day2-sdk-probe-{}", hex(9));
    host.create(&target(), &remote)?;
    host.upload(
        &target(),
        std::slice::from_ref(&file),
        &format!("{remote}/"),
    )?;
    let ran = host.run(
        &target(),
        &remote,
        Mode::NativeProbe,
        Duration::from_secs(30),
    )?;
    assert_eq!(ran.code, Some(0));
    assert_eq!(
        remote_outcome(&ran, "native probe")?["mode"],
        "native-probe"
    );
    assert_eq!(String::from_utf8_lossy(&ran.stderr), "remote warning\n");
    host.download(
        &target(),
        &[
            format!("{remote}/result.json"),
            format!("{remote}/build.log"),
        ],
        directory.path(),
    )?;
    host.remove(&target(), &remote)?;
    let ssh = |command: String| -> Vec<String> {
        [
            "compute",
            "ssh",
            BUILD_HOST,
            "--project=exampleco-tools",
            "--zone=us-central1-a",
            "--account=tools-infra@exampleco-tools.iam.gserviceaccount.com",
            "--tunnel-through-iap",
            "--quiet",
            &format!("--command={command}"),
        ]
        .map(str::to_owned)
        .to_vec()
    };
    let scp: Vec<String> = [
        "compute",
        "scp",
        "--project=exampleco-tools",
        "--zone=us-central1-a",
        "--account=tools-infra@exampleco-tools.iam.gserviceaccount.com",
        "--tunnel-through-iap",
        "--quiet",
        "--compress",
    ]
    .map(str::to_owned)
    .to_vec();
    expected.extend([
        ssh(format!("install -d -m 0700 {remote} {remote}/cli")),
        [
            scp.clone(),
            vec![file_arg.clone(), format!("{BUILD_HOST}:{remote}/")],
        ]
        .concat(),
        ssh(format!(
            "sudo {remote}/cli/day2 instance candidate native-probe {remote} --agent"
        )),
        [
            scp,
            vec![
                format!("{BUILD_HOST}:{remote}/result.json"),
                format!("{BUILD_HOST}:{remote}/build.log"),
                directory.path().to_str().unwrap().to_owned(),
            ],
        ]
        .concat(),
        ssh(format!("sudo rm -rf -- {remote}")),
    ]);
    assert_eq!(calls(&log), expected);
    // Nothing outside a job directory reaches a remote command line.
    assert!(
        host.create(&target(), "/tmp/day2-build-; rm -rf /")
            .is_err()
    );
    assert!(host.upload(&target(), &[], "/etc/").is_err());
    assert!(
        host.download(&target(), &["/etc/shadow".to_owned()], directory.path())
            .is_err()
    );
    assert_eq!(calls(&log).len(), expected.len());
    for path in [
        format!("{remote}/"),
        format!("{remote}/cli/"),
        format!("{remote}/result.json"),
        format!("{remote}/build.log"),
    ] {
        assert!(tools::remote_path(&path), "{path}");
    }
    for path in [
        remote.clone(),
        format!("{remote}/request.json"),
        format!("{remote}/../x"),
        "/tmp/day2-build-x/".to_owned(),
    ] {
        assert!(!tools::remote_path(&path), "{path}");
    }
    Ok(())
}

#[test]
fn a_gcloud_past_its_deadline_is_killed_with_everything_it_started() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("helper-survived");
    let program = stub(
        directory.path(),
        "gcloud",
        &format!("(sleep 2; touch '{}') &\nsleep 30\n", marker.display()),
    );
    let mut gcloud = tools::Gcloud::at(program);
    let host: &mut dyn tools::BuildHost = &mut gcloud;
    let started = std::time::Instant::now();
    let remote = format!("/tmp/day2-build-{}", hex(3));
    assert_eq!(
        error(host.run(
            &target(),
            &remote,
            Mode::NativeBuild,
            Duration::from_secs(1)
        )),
        "gcloud timed out after 1 s"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    std::thread::sleep(Duration::from_secs(3));
    assert!(!marker.exists(), "the helper outlived its group");
    Ok(())
}

#[test]
fn docker_receives_the_token_on_stdin_only() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let record = directory.path().join("record");
    fs::create_dir(&record)?;
    let program = stub(
        directory.path(),
        "docker",
        &format!(
            r#"for arg in "$@"; do printf '%s\n' "$arg" >> '{record}/argv'; done
printf '%s' "$DOCKER_CONFIG" > '{record}/config'
cat > '{record}/stdin'
echo out
echo err >&2
case "$1" in rm) exit 3;; push) sleep 30;; esac
exit 0
"#,
            record = record.display()
        ),
    );
    let mut docker = native::DockerCli::at(program);
    let auth = directory.path().join("docker-auth");
    fs::create_dir(&auth)?;
    let login = Verb::Login {
        host: "us-central1-docker.pkg.dev".into(),
    };
    let ran = docker.run(
        &login,
        Some(&auth),
        Some(b"synthetic-registry-token"),
        Output::Capture,
        Duration::from_secs(20),
    )?;
    assert_eq!(
        (ran.code, ran.stdout.as_slice(), ran.stderr.as_slice()),
        (Some(0), &b"out\n"[..], &b"err\n"[..])
    );
    let argv = fs::read_to_string(record.join("argv"))?;
    let expected: Vec<String> = login
        .args()
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(argv.lines().collect::<Vec<_>>(), expected);
    assert!(!argv.contains("synthetic-registry-token"));
    assert_eq!(fs::read(record.join("stdin"))?, b"synthetic-registry-token");
    assert_eq!(
        fs::read_to_string(record.join("config"))?,
        auth.to_str().unwrap()
    );
    // Output to the build log, or stdout captured beside it; exit codes pass.
    let log_path = directory.path().join("build.log");
    let log = fs::File::create(&log_path)?;
    fs::remove_file(record.join("argv"))?;
    let create = Verb::Create {
        name: "day2-app-slot-0".into(),
        image: "tooling".into(),
    };
    let ran = docker.run(
        &create,
        None,
        None,
        Output::Log(&log),
        Duration::from_secs(20),
    )?;
    assert!(ran.stdout.is_empty() && ran.stderr.is_empty());
    let sha = Verb::Sha256 {
        container: "day2-app-slot-0".into(),
        path: "/x".into(),
    };
    let ran = docker.run(
        &sha,
        None,
        None,
        Output::Split(&log),
        Duration::from_secs(20),
    )?;
    assert_eq!(ran.stdout, b"out\n");
    assert_eq!(fs::read_to_string(&log_path)?, "out\nerr\nerr\n");
    assert_eq!(fs::read(record.join("stdin"))?, b"");
    let remove = Verb::Remove {
        container: "day2-app-slot-0".into(),
    };
    assert_eq!(
        docker
            .run(
                &remove,
                None,
                None,
                Output::Capture,
                Duration::from_secs(20)
            )?
            .code,
        Some(3)
    );
    // A command past its deadline is killed.
    let started = std::time::Instant::now();
    let push = Verb::Push {
        tag: "repo:tag".into(),
    };
    assert_eq!(
        error(docker.run(&push, None, None, Output::Capture, Duration::from_secs(1))),
        "timed out after 1 s"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    Ok(())
}

#[test]
fn build_slots_are_flocks_on_the_earlier_lock_files_with_fresh_private_directories() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut slots = native::HostSlots {
        locks: root.path().join("locks"),
        runs: root.path().join("runs"),
    };
    let first = slots.acquire(Duration::from_secs(1))?;
    assert_eq!(first.index, Some(0));
    fs::write(first.auth().join("config.json"), "stale")?;
    let second = slots.acquire(Duration::from_secs(1))?;
    assert_eq!(second.index, Some(1));
    // Both slots held: a third build waits out its budget, then is refused.
    let started = std::time::Instant::now();
    assert_eq!(
        error(slots.acquire(Duration::from_secs(1))),
        "native build pool wait budget exhausted"
    );
    assert!(started.elapsed() >= Duration::from_secs(1));
    let mut names: Vec<String> = fs::read_dir(root.path().join("locks"))?
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["0", "1"]);
    for directory in [
        root.path().join("locks"),
        first.directory.clone(),
        first.staging(),
    ] {
        assert_eq!(
            fs::metadata(&directory)?.mode() & 0o777,
            0o700,
            "{}",
            directory.display()
        );
    }
    // A released slot is taken again with a fresh, empty directory.
    slots.release(&first);
    drop(first);
    let again = slots.acquire(Duration::from_secs(1))?;
    assert_eq!(again.index, Some(0));
    assert!(fs::read_dir(again.auth())?.next().is_none());
    drop((second, again));
    // The probe has its own lock and directory; a stale token directory goes.
    let probe = slots.probe(Duration::from_secs(1))?;
    assert_eq!(probe.index, None);
    fs::write(probe.auth().join("config.json"), "stale")?;
    assert_eq!(
        error(slots.probe(Duration::ZERO)),
        "native probe lock wait budget exhausted"
    );
    drop(probe);
    let probe = slots.probe(Duration::from_secs(1))?;
    assert!(fs::read_dir(probe.auth())?.next().is_none());
    drop(probe);
    // A lock directory others can enter is refused, and said why.
    fs::set_permissions(root.path().join("locks"), fs::Permissions::from_mode(0o755))?;
    let message = error(slots.acquire(Duration::from_secs(1)));
    assert!(
        message.starts_with("the native build lock directory"),
        "{message}"
    );
    assert!(
        message.contains("with mode 0700; it is a directory owned by uid"),
        "{message}"
    );
    assert!(message.ends_with("with mode 0755"), "{message}");
    Ok(())
}

/// Holds both build slots in a separate process for the test below.
#[test]
fn slot_holder() {
    let Some(root) = std::env::var_os("DAY2_TEST_HOLD_SLOTS") else {
        return;
    };
    let root = PathBuf::from(root);
    let mut slots = native::HostSlots {
        locks: root.join("locks"),
        runs: root.join("runs"),
    };
    let held = (
        slots.acquire(Duration::from_secs(5)).unwrap(),
        slots.acquire(Duration::from_secs(5)).unwrap(),
    );
    fs::write(root.join("held"), "").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !root.join("release").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(held);
}

#[test]
fn build_slots_exclude_another_process() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut holder = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "instance_candidate::tests::slot_holder",
            "--test-threads=1",
        ])
        .env("DAY2_TEST_HOLD_SLOTS", root.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !root.path().join("held").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the holder never held its slots"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut slots = native::HostSlots {
        locks: root.path().join("locks"),
        runs: root.path().join("runs"),
    };
    assert_eq!(
        error(slots.acquire(Duration::from_secs(1))),
        "native build pool wait budget exhausted"
    );
    fs::write(root.path().join("release"), "")?;
    assert!(holder.wait()?.success());
    assert!(slots.acquire(Duration::from_secs(5))?.index.is_some());
    Ok(())
}

#[test]
fn write_protect_removes_write_bits_and_refuses_links() -> Result<()> {
    let root = tempfile::tempdir()?;
    let tree = root.path().join(ARTIFACT);
    fs::create_dir_all(tree.join("nested"))?;
    fs::write(tree.join("artifact.json"), "{}")?;
    fs::write(tree.join("nested/worker"), "elf")?;
    fs::set_permissions(
        tree.join("nested/worker"),
        fs::Permissions::from_mode(0o755),
    )?;
    native::write_protect(&tree)?;
    let mode = |path: &Path| fs::symlink_metadata(path).unwrap().mode() & 0o777;
    assert_eq!(mode(&tree.join("artifact.json")), 0o444);
    assert_eq!(mode(&tree.join("nested/worker")), 0o555);
    assert_eq!(mode(&tree.join("nested")) & 0o222, 0);
    assert_eq!(mode(&tree) & 0o222, 0);
    for directory in [tree.clone(), tree.join("nested")] {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
    }
    std::os::unix::fs::symlink("/etc/hosts", tree.join("nested/link"))?;
    assert_eq!(
        error(native::write_protect(&tree)),
        "artifact links refused"
    );
    for directory in [tree.clone(), tree.join("nested")] {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
