use super::*;
use day2::sdk_release::{Evidence, Image, PROFILE, TARGET};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

pub(crate) const SERVER: &str = "https://git.example.com";
pub(crate) const PREFIX: &str = "https://git.example.com/api/v1/repos/tools/links-app";
pub(crate) const REGISTRY: &str = "us-central1-docker.pkg.dev/exampleco-tools";
pub(crate) const BUCKET: &str = "exampleco-tools-tofu-state";
pub(crate) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const PLATFORM: &str = "fedcba9876543210fedcba9876543210fedcba98";
pub(crate) const UPLOAD: u64 = (1 << 63) - 1;
pub(crate) const TOKEN: &str = "synthetic-forge-token";
const GOLDEN_RECEIPT: &str = include_str!("../../../../cli/fixtures/source-receipt.json");

pub(crate) fn inputs() -> String {
    format!("sha256:{}", "ab".repeat(32))
}

/// A fake forge, gcloud and clock in one world.
#[derive(Default)]
pub(crate) struct World {
    /// Responses per URL; the last one repeats.
    pub(crate) routes: BTreeMap<String, VecDeque<Option<Response>>>,
    /// Each request's URL and whether it carried the token.
    pub(crate) calls: Vec<(String, bool)>,
    pub(crate) objects: BTreeMap<String, Vec<u8>>,
    pub(crate) now: Duration,
    pub(crate) sleeps: Vec<Duration>,
    pub(crate) announced: Vec<String>,
}

#[derive(Clone, Default)]
pub(crate) struct Fake(pub(crate) Rc<RefCell<World>>);

fn clone_response(response: &Response) -> Response {
    Response {
        status: response.status,
        location: response.location.clone(),
        body: response.body.clone(),
    }
}

impl Fake {
    /// Serve `responses` for `url` in order; `None` is a connection failure.
    pub(crate) fn route(&self, url: &str, responses: Vec<Option<Response>>) {
        self.0
            .borrow_mut()
            .routes
            .insert(url.to_owned(), responses.into());
    }

    pub(crate) fn calls(&self) -> Vec<(String, bool)> {
        self.0.borrow().calls.clone()
    }
}

impl Transport for Fake {
    fn get(&mut self, url: &str, token: Option<&str>, limit: u64) -> Result<Response> {
        let mut world = self.0.borrow_mut();
        assert!(token.is_none_or(|token| token == TOKEN));
        world.calls.push((url.to_owned(), token.is_some()));
        let queue = world
            .routes
            .get_mut(url)
            .unwrap_or_else(|| panic!("unexpected request {url}"));
        let response = if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().unwrap().as_ref().map(clone_response)
        };
        let Some(mut response) = response else {
            return Err(Retryable(TEMPORARY).into());
        };
        response.body.truncate(usize::try_from(limit + 1).unwrap());
        Ok(response)
    }
}

impl Clock for Fake {
    fn now(&mut self) -> Duration {
        self.0.borrow().now
    }

    fn sleep(&mut self, duration: Duration) {
        let mut world = self.0.borrow_mut();
        world.now += duration;
        world.sleeps.push(duration);
    }

    fn announce(&mut self, line: &str) {
        self.0.borrow_mut().announced.push(line.to_owned());
    }
}

impl instance_release::Tools for Fake {
    fn describe(&mut self, uri: &str) -> Result<String> {
        let world = self.0.borrow();
        let bytes = world.objects.get(uri).context("404 not found")?;
        Ok(json!({"size": bytes.len().to_string(), "generation": "7"}).to_string())
    }

    fn download(&mut self, uri: &str, _generation: &str, destination: &Path) -> Result<()> {
        let bytes = self.0.borrow().objects.get(uri).cloned().context("404")?;
        fs::write(destination, bytes)?;
        Ok(())
    }

    fn create(&mut self, _source: &Path, _uri: &str) -> Result<instance_release::Created> {
        bail!("a source session never publishes")
    }

    fn pull(&mut self, _image: &str) -> Result<()> {
        bail!("a source session never pulls")
    }

    fn image_id(&mut self, _image: &str) -> Result<String> {
        bail!("a source session never inspects images")
    }
}

pub(crate) fn ok(value: Value) -> Option<Response> {
    bytes(value.to_string().into_bytes())
}

pub(crate) fn bytes(body: Vec<u8>) -> Option<Response> {
    Some(Response {
        status: 200,
        location: None,
        body,
    })
}

pub(crate) fn status(code: u16) -> Option<Response> {
    Some(Response {
        status: code,
        location: None,
        body: Vec::new(),
    })
}

fn redirect(location: &str) -> Option<Response> {
    Some(Response {
        status: 302,
        location: Some(location.to_owned()),
        body: Vec::new(),
    })
}

/// A synthetic qualified release pinned under the instance's registry.
pub(crate) fn manifest() -> Vec<u8> {
    let digest = |label: &str| day2::digest(label.as_bytes());
    let blob = |label: &str| BlobIdentity::of(label.as_bytes());
    Release {
        version: 1,
        platform_commit: PLATFORM.into(),
        profile: PROFILE.into(),
        target: TARGET.into(),
        runtime: Image {
            image: format!("{REGISTRY}/links/day2-runtime@{}", digest("runtime")),
            config: digest("runtime config"),
        },
        tooling: Image {
            image: format!("{REGISTRY}/links/day2-tooling@{}", digest("tooling")),
            config: digest("tooling config"),
        },
        distribution: blob("distribution"),
        operator: blob("operator"),
        evidence: Evidence {
            native: blob("native"),
            strict: blob("strict"),
            rolling: None,
        },
    }
    .encode()
    .unwrap()
}

/// One tar entry with a raw name, written exactly as given.
pub(crate) fn entry(builder: &mut tar::Builder<Vec<u8>>, name: &[u8], kind: u8, data: &[u8]) {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_size(data.len() as u64);
    header.set_mode(if kind == b'5' { 0o755 } else { 0o644 });
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    header.set_cksum();
    builder.append(&header, data).unwrap();
}

/// A pax record, `<length> <key>=<value>\n`.
pub(crate) fn pax(key: &str, value: &[u8]) -> Vec<u8> {
    let body = [format!(" {key}=").as_bytes(), value, b"\n"].concat();
    let mut length = body.len() + 1;
    while length.to_string().len() + body.len() != length {
        length += 1;
    }
    [length.to_string().as_bytes(), &body].concat()
}

/// A gzip tar, as git archive writes one: a pax global comment, then the
/// entries. A name in `long` is written through a pax path record.
pub(crate) fn tarball(entries: &[(&[u8], u8, &[u8])], global: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    entry(&mut builder, b"pax_global_header", b'g', global);
    for (name, kind, data) in entries {
        if name.len() > 100 || !name.is_ascii() {
            entry(&mut builder, b"PaxHeader", b'x', &pax("path", name));
            entry(&mut builder, b"long-name-placeholder", *kind, data);
        } else {
            entry(&mut builder, name, *kind, data);
        }
    }
    let raw = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw).unwrap();
    encoder.finish().unwrap()
}

pub(crate) fn comment() -> Vec<u8> {
    pax("comment", COMMIT.as_bytes())
}

pub(crate) fn roc_json(platform: &str) -> Vec<u8> {
    json!({"schemaVersion": 1, "platformRevision": platform, "appRoot": "app",
        "campaign": {"seed": 42, "cases": 4}, "unitTests": ["tests/Unit.roc"], "testSources": []})
    .to_string()
    .into_bytes()
}

/// The app's source archive at COMMIT, with the given `.ci/roc.json`.
pub(crate) fn source(roc: &[u8]) -> Vec<u8> {
    source_with(roc, &[])
}

/// The app's source archive at COMMIT, with the given `.ci/roc.json` and
/// `extra` entries after its own.
pub(crate) fn source_with(roc: &[u8], extra: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
    let release = manifest();
    let own: [(&[u8], u8, &[u8]); 8] = [
        (b"links-app/", b'5', b""),
        (b"links-app/.ci/roc.json", b'0', roc),
        (b"links-app/.ci/platform-release.json", b'0', &release),
        (
            b"links-app/.ci/publish_artifact.py",
            b'0',
            b"# synthetic publisher\n",
        ),
        (
            b"links-app/.ci/sdk_release.py",
            b'0',
            b"# synthetic selector\n",
        ),
        (b"links-app/.ci/README.md", b'0', b"prose\n"),
        (
            b"links-app/.gitea/workflows/roc.yml",
            b'0',
            b"name: synthetic\n",
        ),
        (b"links-app/app/main.roc", b'0', b"app [main!] {}\n"),
    ];
    let entries: Vec<(&[u8], u8, &[u8])> = own.into_iter().chain(extra.iter().copied()).collect();
    tarball(&entries, &comment())
}

pub(crate) fn instance(sdk: &str) -> Instance {
    Instance {
        server: SERVER.into(),
        org: "tools".into(),
        registry: REGISTRY.into(),
        bucket: BUCKET.into(),
        apps: vec![
            App {
                id: "links".into(),
                sdk: sdk.into(),
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

/// The binding deploy.py would build for the synthetic app, whose repository
/// name is not the derived `tools/links`.
pub(crate) fn binding(controls: &str) -> Value {
    let release = BlobIdentity::of(&manifest());
    json!({
        "app": "links",
        "repository": "tools/links-app",
        "directory": "app",
        "runtime_image": format!("{REGISTRY}/links/day2-runtime@{}", day2::digest(b"runtime")),
        "tooling_image": format!("{REGISTRY}/links/day2-tooling@{}", day2::digest(b"tooling")),
        "image_repository": format!("{REGISTRY}/links/links"),
        "source": {"forge": "gitea", "server": SERVER, "repository": "tools/links-app",
            "repository_id": 42, "branch": "main"},
        "qualified_release": {"digest": release.digest, "bytes": release.bytes},
        "verification": {"version": 1, "seed": 42, "cases": 4},
        "ci_artifact": {"version": 1, "workflow": "roc.yml", "job": "roc", "digest": controls},
    })
}

pub(crate) fn controls_digest() -> String {
    Controls::read(&source(&roc_json(PLATFORM)))
        .unwrap()
        .digest()
}

pub(crate) struct Scenario {
    pub(crate) fake: Fake,
    pub(crate) directory: tempfile::TempDir,
    pub(crate) binding: Value,
    pub(crate) sdk: String,
}

impl Scenario {
    pub(crate) fn new() -> Self {
        let fake = Fake::default();
        let release = manifest();
        let reference = BlobIdentity::of(&release);
        fake.0.borrow_mut().objects.insert(
            format!(
                "gs://{BUCKET}/{}/{}",
                instance_release::OBJECTS,
                reference.check(u64::MAX).unwrap()
            ),
            release,
        );
        Self {
            fake,
            directory: tempfile::tempdir().unwrap(),
            binding: binding(&controls_digest()),
            sdk: reference.digest,
        }
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    pub(crate) fn effects(&self) -> Effects {
        Effects {
            transport: Box::new(self.fake.clone()),
            clock: Box::new(self.fake.clone()),
            tools: Box::new(self.fake.clone()),
            cache: Some(self.path("cache")),
            token: Some(TOKEN.into()),
        }
    }

    /// The CLI's request for `mode`, with the files it names written.
    fn request(&self, mode: Mode) -> Value {
        fs::write(self.path("binding.json"), self.binding.to_string()).unwrap();
        let path = |name: &str| json!(self.path(name));
        let (binding, commit, inputs_value, archive, output) = match mode {
            Mode::Head => (
                path("binding.json"),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ),
            Mode::Archive => (
                path("binding.json"),
                json!(COMMIT),
                Value::Null,
                Value::Null,
                path("source.tar.gz"),
            ),
            Mode::Controls => (
                Value::Null,
                Value::Null,
                Value::Null,
                path("source.tar.gz"),
                Value::Null,
            ),
            Mode::VerifyControls => (
                path("binding.json"),
                Value::Null,
                Value::Null,
                path("source.tar.gz"),
                Value::Null,
            ),
            Mode::CheckedArtifact => (
                path("binding.json"),
                json!(COMMIT),
                json!(inputs()),
                Value::Null,
                path("ci-artifact.tar.gz"),
            ),
        };
        let instance = if mode == Mode::Controls {
            Value::Null
        } else {
            serde_json::to_value(instance(&self.sdk)).unwrap()
        };
        json!({"mode": mode, "instance": instance, "binding": binding, "commit": commit,
            "inputs": inputs_value, "archive": archive, "output": output})
    }

    fn session_with(&self, mode: Mode, request: &Value) -> Result<Session> {
        let raw = self.path("request.json");
        fs::write(&raw, request.to_string())?;
        Session::prepare(&raw, mode, self.effects())
    }

    fn session(&self, mode: Mode) -> Result<Session> {
        self.session_with(mode, &self.request(mode))
    }

    /// Every step of `mode`; the last one's receipt.
    fn run(&self, mode: Mode) -> Result<Value> {
        let mut session = self.session(mode)?;
        let mut last = Value::Null;
        for step in mode.steps() {
            last = session.step(step)?;
        }
        Ok(last)
    }
}

fn error(result: Result<Value>) -> String {
    format!("{:#}", reported(result.expect_err("refused")))
}

#[test]
fn modes_name_their_commands_and_steps() {
    for mode in Mode::ALL {
        assert_eq!(Mode::from_name(mode.name()), Some(mode));
        assert_eq!(serde_json::to_value(mode).unwrap(), json!(mode.name()));
    }
    assert_eq!(Mode::from_name("publish"), None);
    assert_eq!(
        Mode::CheckedArtifact.steps(),
        ["run", "job", "artifact", "download", "attempt"]
    );
}

#[test]
fn a_retryable_failure_is_reported_as_its_code_alone() {
    let error = anyhow::Error::from(Retryable(TEMPORARY)).context("reading the main runs");
    assert_eq!(
        format!("{:#}", reported(error)),
        "retryable: source_temporarily_unavailable"
    );
    let permanent = anyhow!("source_metadata_http_404").context("head");
    assert_eq!(
        format!("{:#}", reported(permanent)),
        "head: source_metadata_http_404"
    );
}

#[test]
fn the_binding_is_validated_as_python_did_then_against_day2_json() -> Result<()> {
    let scenario = Scenario::new();
    let instance = instance(&scenario.sdk);
    let valid = Binding::check(scenario.binding.clone(), &instance)?;
    assert_eq!(
        (valid.app.as_str(), valid.repository.as_str()),
        ("links", "tools/links-app")
    );
    let refused = |change: &dyn Fn(&mut Value), code: &str| {
        let mut value = scenario.binding.clone();
        change(&mut value);
        let message = format!("{:#}", Binding::check(value, &instance).unwrap_err());
        assert_eq!(message, code);
    };
    refused(
        &|value| value["extra"] = json!(1),
        "invalid candidate build binding",
    );
    // The earlier controller's shapes without a checked main artifact, or also
    // without a qualified SDK, compiled on the build host: not supported.
    let unported = "builds without a qualified SDK release and a checked main artifact are not \
                    supported: the binding must name qualified_release, verification and ci_artifact";
    refused(
        &|value| {
            value.as_object_mut().unwrap().remove("ci_artifact");
        },
        unported,
    );
    refused(
        &|value| {
            let object = value.as_object_mut().unwrap();
            for field in ["ci_artifact", "verification", "qualified_release"] {
                object.remove(field);
            }
        },
        unported,
    );
    refused(
        &|value| {
            value.as_object_mut().unwrap().remove("verification");
        },
        "invalid candidate build binding",
    );
    refused(
        &|value| value["app"] = json!("Links"),
        "invalid deployment app ID",
    );
    refused(
        &|value| value["qualified_release"]["bytes"] = json!(1236.0),
        "invalid qualified release blob",
    );
    refused(
        &|value| value["qualified_release"]["bytes"] = json!(true),
        "invalid qualified release blob",
    );
    refused(
        &|value| value["verification"]["cases"] = json!(3),
        "unsupported app verification profile",
    );
    refused(
        &|value| value["verification"]["seed"] = json!(true),
        "unsupported app verification profile",
    );
    refused(
        &|value| value["ci_artifact"]["job"] = json!("check"),
        "invalid checked-artifact CI contract",
    );
    refused(
        &|value| value["repository"] = json!(".tools/links-app"),
        "invalid deployment source repository",
    );
    refused(
        &|value| value["source"]["extra"] = json!(1),
        "invalid_source_identity",
    );
    refused(
        &|value| value["source"]["forge"] = json!("Gitea"),
        "invalid_source_forge",
    );
    refused(
        &|value| value["source"]["server"] = json!("https://git.example.com/path"),
        "invalid_source_origin",
    );
    refused(
        &|value| value["source"]["server"] = json!("https://user@git.example.com"),
        "invalid_source_origin",
    );
    refused(
        &|value| value["source"]["repository_id"] = json!(0),
        "invalid_native_repository_id",
    );
    refused(
        &|value| value["source"]["branch"] = json!("main..x"),
        "invalid_source_branch",
    );
    refused(
        &|value| value["source"]["repository"] = json!("tools/other"),
        "release source mismatch",
    );
    refused(
        &|value| value["source"]["branch"] = json!("release"),
        "checked-artifact source requires Gitea main",
    );
    refused(
        &|value| value["source"]["forge"] = json!("github"),
        "checked-artifact source requires Gitea main",
    );
    refused(
        &|value| value["directory"] = json!("../app"),
        "invalid app source directory",
    );
    refused(
        &|value| {
            value["runtime_image"] = json!(format!(
                "{REGISTRY}/notes/day2-runtime@{}",
                day2::digest(b"r")
            ))
        },
        "runtime must be a pinned app-local image",
    );
    refused(
        &|value| value["tooling_image"] = json!(format!("{REGISTRY}/links/day2-tooling:latest")),
        "pinned app-local tooling required",
    );
    refused(
        &|value| {
            value["image_repository"] =
                json!(format!("{REGISTRY}/links/links@{}", day2::digest(b"i")))
        },
        "pinned app-local bootstrap image required",
    );
    // Identity mismatches against day2.json.
    refused(
        &|value| {
            for path in ["runtime_image", "tooling_image", "image_repository"] {
                value[path] = json!(value[path].as_str().unwrap().replace("/links/", "/other/"));
            }
            value["app"] = json!("other");
        },
        "the binding's app other is not in day2.json",
    );
    refused(
        &|value| value["source"]["server"] = json!("https://git.example.org"),
        "the binding's source server is not day2.json's forge.server",
    );
    refused(
        &|value| {
            value["repository"] = json!("people/links-app");
            value["source"]["repository"] = json!("people/links-app");
        },
        "the binding's repository is not in day2.json's forge.org",
    );
    // The platform's own repositories (day2-<name>, in any case) are never an app's source.
    for platform in ["tools/day2-ci", "tools/day2-instance", "tools/Day2-Ci"] {
        refused(
            &|value| {
                value["repository"] = json!(platform);
                value["source"]["repository"] = json!(platform);
            },
            "the binding's repository is a platform repository (day2-<name>), not an app's",
        );
    }
    refused(
        &|value| value["qualified_release"]["digest"] = json!(day2::digest(b"another release")),
        "the binding's qualified release is not day2.json's apps.links.sdk",
    );
    refused(
        &|value| value["verification"]["cases"] = json!(6),
        "the binding's verification cases are not day2.json's apps.links.verification",
    );
    // A string repository ID is a valid identity, and a repository named
    // other than the app is allowed.
    let mut named = scenario.binding.clone();
    named["source"]["repository_id"] = json!("repo:42");
    assert!(Binding::check(named, &instance).is_ok());
    // Only a name starting with day2- is the platform's.
    for name in ["tools/day2ci", "tools/links-day2-app", "tools/day2"] {
        let mut named = scenario.binding.clone();
        named["repository"] = json!(name);
        named["source"]["repository"] = json!(name);
        assert!(Binding::check(named, &instance).is_ok(), "{name}");
    }
    assert!(platform_repository("tools/day2-") && platform_repository("tools/DAY2-x"));
    assert!(!platform_repository("tools/day2") && !platform_repository("day2-tools/links"));
    Ok(())
}

#[test]
fn a_duplicate_key_is_refused_in_the_binding_responses_and_receipts() -> Result<()> {
    let scenario = Scenario::new();
    let mut request = scenario.request(Mode::Head);
    request["binding"] = json!(scenario.path("duplicate.json"));
    let text = scenario.binding.to_string();
    fs::write(
        scenario.path("duplicate.json"),
        text.replacen(
            "\"app\":\"links\"",
            "\"app\":\"links\",\"app\":\"links\"",
            1,
        ),
    )?;
    let raw = scenario.path("request.json");
    fs::write(&raw, request.to_string())?;
    let refused = Session::prepare(&raw, Mode::Head, scenario.effects())
        .err()
        .unwrap();
    assert!(format!("{refused:#}").contains("invalid binding JSON"));
    assert_eq!(
        format!(
            "{:#}",
            decode(br#"{"id":1,"nested":{"a":1,"a":2}}"#).unwrap_err()
        ),
        "duplicate_event_field"
    );
    assert_eq!(format!("{:#}", decode(b"{").unwrap_err()), "invalid JSON");
    let oversized = serde_json::to_vec(&"x".repeat(JSON_LIMIT as usize))?;
    assert_eq!(
        format!("{:#}", decode(&oversized).unwrap_err()),
        "event_byte_limit"
    );
    // Python bounds a document by bytes alone, not by its node count.
    assert!(decode(serde_json::to_vec(&vec![0_u8; 100_000])?.as_slice()).is_ok());
    scenario
        .fake
        .route(PREFIX, vec![bytes(br#"{"id":42,"id":42}"#.to_vec())]);
    assert_eq!(error(scenario.run(Mode::Head)), "duplicate_event_field");
    Ok(())
}

#[test]
fn the_request_names_only_its_modes_inputs_and_the_host_fixes_the_mode() -> Result<()> {
    let scenario = Scenario::new();
    let mut request = scenario.request(Mode::Head);
    assert!(scenario.session_with(Mode::Archive, &request).is_err());
    request["commit"] = json!(COMMIT);
    let refused = scenario.session_with(Mode::Head, &request).err().unwrap();
    assert!(format!("{refused:#}").contains("names only its own inputs"));
    for mode in [Mode::Archive, Mode::CheckedArtifact] {
        let mut request = scenario.request(mode);
        request["commit"] = json!(COMMIT.to_uppercase());
        let refused = scenario.session_with(mode, &request).err().unwrap();
        assert_eq!(
            format!("{refused:#}"),
            format!("{} requires an exact commit", mode.name())
        );
    }
    let mut request = scenario.request(Mode::CheckedArtifact);
    request["inputs"] = json!("sha256:short");
    assert!(
        scenario
            .session_with(Mode::CheckedArtifact, &request)
            .is_err()
    );
    let mut request = scenario.request(Mode::Head);
    request["instance"]["bucket"] = json!("other-project-tofu-state");
    assert!(scenario.session_with(Mode::Head, &request).is_err());
    let mut request = scenario.request(Mode::Head);
    request["unknown"] = json!(1);
    assert!(scenario.session_with(Mode::Head, &request).is_err());
    // An output must be new, in an existing directory.
    fs::write(scenario.path("source.tar.gz"), b"reviewed")?;
    let refused = scenario.session(Mode::Archive).err().unwrap();
    assert!(format!("{refused:#}").contains("requires a new file"));
    assert_eq!(fs::read(scenario.path("source.tar.gz"))?, b"reviewed");
    let mut request = scenario.request(Mode::Archive);
    request["output"] = json!(scenario.path("missing/source.tar.gz"));
    assert!(scenario.session_with(Mode::Archive, &request).is_err());
    // An archive to read must be a regular file.
    let mut request = scenario.request(Mode::Controls);
    request["archive"] = json!(scenario.path("absent.tar.gz"));
    assert!(scenario.session_with(Mode::Controls, &request).is_err());
    std::os::unix::fs::symlink(
        scenario.path("source.tar.gz"),
        scenario.path("linked.tar.gz"),
    )?;
    request["archive"] = json!(scenario.path("linked.tar.gz"));
    assert!(scenario.session_with(Mode::Controls, &request).is_err());
    Ok(())
}

#[test]
fn steps_run_once_in_their_modes_order() -> Result<()> {
    let scenario = Scenario::new();
    fs::write(scenario.path("source.tar.gz"), source(&roc_json(PLATFORM)))?;
    let mut session = scenario.session(Mode::VerifyControls)?;
    let refused = session.step("release").unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "instance source verify-controls runs controls next, not release"
    );
    session.step("controls")?;
    assert!(session.step("controls").is_err());
    session.step("release")?;
    assert_eq!(
        format!("{:#}", session.step("release").unwrap_err()),
        "instance source verify-controls runs nothing more next, not release"
    );
    let mut session = scenario.session(Mode::CheckedArtifact)?;
    assert!(session.step("download").is_err());
    assert!(scenario.fake.calls().is_empty());
    Ok(())
}

#[test]
fn head_reads_the_same_repository_and_an_exact_branch_commit() -> Result<()> {
    let scenario = Scenario::new();
    let branch = format!("{PREFIX}/branches/main");
    scenario
        .fake
        .route(PREFIX, vec![ok(json!({"id": 42, "name": "links-app"}))]);
    scenario.fake.route(
        &branch,
        vec![ok(json!({"name": "main", "commit": {"id": COMMIT}}))],
    );
    let receipt: Receipt = serde_json::from_value(scenario.run(Mode::Head)?)?;
    assert_eq!(
        (
            receipt.mode,
            receipt.commit.as_deref(),
            receipt.app_id.as_deref()
        ),
        (Mode::Head, Some(COMMIT), Some("links"))
    );
    assert!(receipt.archive.is_none() && receipt.proof.is_none());
    assert_eq!(
        scenario.fake.calls(),
        [(PREFIX.to_owned(), true), (branch.clone(), true)]
    );
    let refused = |repository: Option<Response>, head: Option<Response>, code: &str| {
        scenario.fake.route(PREFIX, vec![repository]);
        scenario.fake.route(&branch, vec![head]);
        assert_eq!(error(scenario.run(Mode::Head)), code);
    };
    refused(
        ok(json!({"id": 43})),
        ok(json!({"commit": {"id": COMMIT}})),
        "source_repository_identity_changed",
    );
    refused(
        ok(json!({"id": 42.0})),
        ok(json!({"commit": {"id": COMMIT}})),
        "source_repository_identity_changed",
    );
    refused(status(404), None, "source_metadata_http_404");
    refused(status(301), None, "source_metadata_http_301");
    refused(
        ok(json!({"id": 42})),
        status(403),
        "source_metadata_http_403",
    );
    refused(
        ok(json!({"id": 42})),
        ok(json!({"commit": {"id": "0".repeat(40)}})),
        "source_branch_commit_invalid",
    );
    refused(
        ok(json!({"id": 42})),
        ok(json!({"commit": {"id": COMMIT.to_uppercase()}})),
        "source_branch_commit_invalid",
    );
    refused(ok(json!({"name": "x"})), None, "source response lacks id");
    for code in [408, 429, 500, 503, 599] {
        refused(
            status(code),
            None,
            "retryable: source_temporarily_unavailable",
        );
    }
    refused(None, None, "retryable: source_temporarily_unavailable");
    refused(
        bytes(vec![b' '; JSON_LIMIT as usize + 1]),
        None,
        "source_response_byte_limit",
    );
    Ok(())
}

#[test]
fn a_branch_name_is_quoted_as_one_path_segment() {
    assert_eq!(quote("release/2026.11"), "release%2F2026.11");
    assert_eq!(quote("a-b_c~"), "a-b_c~");
}

#[test]
fn archive_writes_the_commits_archive_to_a_new_file() -> Result<()> {
    let scenario = Scenario::new();
    let url = format!("{PREFIX}/archive/{COMMIT}.tar.gz");
    let archive = source(&roc_json(PLATFORM));
    scenario.fake.route(&url, vec![bytes(archive.clone())]);
    let receipt: Receipt = serde_json::from_value(scenario.run(Mode::Archive)?)?;
    let identity = BlobIdentity::of(&archive);
    assert_eq!(
        receipt.archive,
        Some(File {
            path: text(&scenario.path("source.tar.gz"))?.to_owned(),
            digest: identity.digest,
            bytes: identity.bytes,
        })
    );
    assert_eq!(fs::read(scenario.path("source.tar.gz"))?, archive);
    fs::remove_file(scenario.path("source.tar.gz"))?;
    scenario.fake.route(&url, vec![status(404)]);
    assert_eq!(
        error(scenario.run(Mode::Archive)),
        "source_archive_http_404"
    );
    scenario.fake.route(&url, vec![status(502)]);
    assert_eq!(
        error(scenario.run(Mode::Archive)),
        "retryable: source_temporarily_unavailable"
    );
    scenario
        .fake
        .route(&url, vec![bytes(vec![0; ARCHIVE_LIMIT as usize + 1])]);
    assert_eq!(
        error(scenario.run(Mode::Archive)),
        "source_response_byte_limit"
    );
    assert!(!scenario.path("source.tar.gz").exists());
    Ok(())
}

/// The digest Python's ci_artifact.py printed for the same tree: dot
/// segments and doubled slashes normalized, a non-ASCII name (through a pax
/// path) and a non-UTF-8 one, Markdown and `.ci/roc.json` excluded.
#[test]
fn the_control_digest_is_pythons() -> Result<()> {
    let archive = tarball(
        &[
            (b"links-app/", b'5', b""),
            (b"links-app/.ci/", b'5', b""),
            (
                b"links-app/.ci/roc.json",
                b'0',
                b"{\"synthetic\": \"app-owned\"}\n",
            ),
            (
                b"links-app/.ci/platform-release.json",
                b'0',
                b"{\"synthetic\": true}\n",
            ),
            (
                b"links-app/.ci/publish_artifact.py",
                b'0',
                b"# synthetic publisher\n",
            ),
            (
                b"links-app/.ci/sdk_release.py",
                b'0',
                b"# synthetic selector\n",
            ),
            (b"links-app/.ci/README.md", b'0', b"prose\n"),
            (b"links-app//.ci/./policy.json", b'0', b"{\"policy\": 1}\n"),
            ("links-app/.ci/na\u{ef}ve.json".as_bytes(), b'0', b"[]\n"),
            (b"links-app/.ci/\xff.bin", b'0', b"\x00\x01"),
            (b"links-app/.ci/lib/", b'5', b""),
            (b"links-app/.ci/lib/tool.mjs", b'0', b"export {};\n"),
            (
                b"links-app/.gitea/workflows/roc.yml",
                b'0',
                b"name: synthetic\n",
            ),
            (
                b"links-app/.gitea/workflows/other.yml",
                b'0',
                b"name: other\n",
            ),
            (b"links-app/app/main.roc", b'0', b"app [main!] {}\n"),
        ],
        &comment(),
    );
    let controls = Controls::read(&archive)?;
    assert_eq!(
        String::from_utf8(controls.document())?,
        concat!(
            r#"{"files":[[".ci/lib/tool.mjs",11,"8e609bb71c20b858c77f0e9f90bb1319db8477b13f9f965f1a1e18524bf50881"],"#,
            r#"[".ci/na\u00efve.json",3,"37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"],"#,
            r#"[".ci/platform-release.json",20,"729cd4435656683931ea719191f6786bbca51754bd7e573f413a655d71fdde49"],"#,
            r#"[".ci/policy.json",14,"acafce7725bc3ebb71fbd339229b9d299e34d8727da62e67101106d27a5ddf02"],"#,
            r#"[".ci/publish_artifact.py",22,"fa3f7fba64b20141a877df4a8730564339d02621e33ab617e44c2d8a91bd60d9"],"#,
            r#"[".ci/sdk_release.py",21,"d4e92d16e1294e4f54e091246bb9752a9f4e4e55256e8732ee706a59ff532665"],"#,
            r#"[".ci/\udcff.bin",2,"b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2"],"#,
            r#"[".gitea/workflows/roc.yml",16,"db9f74b184c0b66b84c86dbfaaad64c879caf242bacfb7ae2e3129cd552eb188"]],"version":1}"#,
        )
    );
    assert_eq!(
        controls.digest(),
        "sha256:4d8d8efc9009a13de8d2a7cd7c7dd62ec643e5b6d111ec474a793b2475a59bf5"
    );
    Ok(())
}

#[test]
fn controls_reports_the_digest_of_an_archive() -> Result<()> {
    let scenario = Scenario::new();
    let archive = source(&roc_json(PLATFORM));
    fs::write(scenario.path("source.tar.gz"), &archive)?;
    let receipt: Receipt = serde_json::from_value(scenario.run(Mode::Controls)?)?;
    assert_eq!(receipt.controls, Some(controls_digest()));
    assert_eq!(
        receipt.archive.map(|file| file.digest),
        Some(BlobIdentity::of(&archive).digest)
    );
    assert!(receipt.app_id.is_none() && receipt.commit.is_none());
    assert!(scenario.fake.calls().is_empty());
    // App-owned roc.json and prose never change the digest; another control does.
    let other = source(&roc_json("0".repeat(40).as_str()));
    assert_eq!(Controls::read(&other)?.digest(), controls_digest());
    Ok(())
}

#[test]
fn control_inventory_refuses_unsafe_and_unbounded_archives() {
    let required = |extra: &[(&[u8], u8, &[u8])]| {
        let mut entries: Vec<(&[u8], u8, &[u8])> = vec![
            (b"app/.ci/roc.json", b'0', b"{}"),
            (b"app/.ci/platform-release.json", b'0', b"{}"),
            (b"app/.ci/publish_artifact.py", b'0', b"#"),
            (b"app/.ci/sdk_release.py", b'0', b"#"),
            (b"app/.gitea/workflows/roc.yml", b'0', b"name: x\n"),
        ];
        entries.extend_from_slice(extra);
        tarball(&entries, &comment())
    };
    let refused = |archive: Vec<u8>, code: &str| {
        let message = format!("{:#}", Controls::read(&archive).err().expect("refused"));
        assert_eq!(message, code);
    };
    assert!(Controls::read(&required(&[])).is_ok());
    refused(
        tarball(&[(b"app/.ci/roc.json", b'0', b"{}")], &comment()),
        "checked-artifact CI controls missing",
    );
    refused(
        required(&[(b"other/file", b'0', b"x")]),
        "CI source archive has multiple roots",
    );
    refused(
        required(&[(b"app/../x", b'0', b"x")]),
        "unsafe CI source archive path",
    );
    refused(
        required(&[(b"/app/x", b'0', b"x")]),
        "unsafe CI source archive path",
    );
    refused(
        required(&[(b"./", b'5', b"")]),
        "unsafe CI source archive path",
    );
    refused(
        required(&[(b"app/.ci/./roc.json", b'0', b"{}")]),
        "CI controls must be bounded unique regular files",
    );
    refused(
        required(&[(b"app/.ci/link", b'2', b"")]),
        "CI controls must be bounded unique regular files",
    );
    let big = vec![0_u8; CONTROL_LIMIT as usize + 1];
    refused(
        required(&[(b"app/.ci/big.bin", b'0', &big)]),
        "CI controls must be bounded unique regular files",
    );
    let member = vec![0_u8; MEMBER_LIMIT as usize + 1];
    refused(
        required(&[(b"app/data.bin", b'0', &member)]),
        "CI source archive exceeds budget",
    );
    let names: Vec<Vec<u8>> = (0..ENTRY_LIMIT)
        .map(|n| format!("app/f{n}").into_bytes())
        .collect();
    let many: Vec<(&[u8], u8, &[u8])> = names
        .iter()
        .map(|name| (name.as_slice(), b'0', &b""[..]))
        .collect();
    refused(required(&many), "CI source archive exceeds budget");
    // Data on a directory or link entry, which tarfile would not skip.
    refused(
        required(&[(b"app/dir/", b'5', b"x")]),
        "unsupported CI source archive entry",
    );
    refused(
        required(&[(b"app/link", b'2', b"x")]),
        "unsupported CI source archive entry",
    );
    refused(required(&[(b"app/sparse", b'S', b"")]), UNSUPPORTED);
    refused(
        tarball(&[(b"app/x", b'0', b"x")], &pax("path", b"elsewhere")),
        "unsupported CI source archive pax global header",
    );
    // Prose under .ci and app files outside it are never controls.
    assert!(Controls::read(&required(&[(b"app/.ci/NOTES.md", b'5', b"")])).is_ok());
    refused(b"not gzip".to_vec(), "unreadable CI source archive");
}

#[test]
fn control_inventory_bounds_the_whole_archive() {
    let member = vec![0_u8; MEMBER_LIMIT as usize];
    let names: Vec<Vec<u8>> = (0..9).map(|n| format!("app/f{n}").into_bytes()).collect();
    let entries: Vec<(&[u8], u8, &[u8])> = names
        .iter()
        .map(|name| (name.as_slice(), b'0', member.as_slice()))
        .collect();
    let message = format!(
        "{:#}",
        Controls::read(&tarball(&entries, &comment()))
            .err()
            .unwrap()
    );
    assert_eq!(message, "CI source archive exceeds budget");
}

#[test]
fn verify_controls_binds_the_archive_to_the_binding_and_its_release() -> Result<()> {
    let scenario = Scenario::new();
    fs::write(scenario.path("source.tar.gz"), source(&roc_json(PLATFORM)))?;
    let receipt: Receipt = serde_json::from_value(scenario.run(Mode::VerifyControls)?)?;
    assert_eq!(receipt.platform_commit.as_deref(), Some(PLATFORM));
    assert_eq!(receipt.controls, Some(controls_digest()));
    // The manifest came through the release cache, verified.
    let reference = BlobIdentity::of(&manifest());
    assert!(
        scenario
            .path("cache")
            .join(reference.check(u64::MAX)?)
            .is_file()
    );
    let refused = |roc: Vec<u8>, code: &str| {
        fs::remove_file(scenario.path("source.tar.gz")).unwrap();
        fs::write(scenario.path("source.tar.gz"), source(&roc)).unwrap();
        assert_eq!(error(scenario.run(Mode::VerifyControls)), code);
    };
    let roc: Value = serde_json::from_slice(&roc_json(PLATFORM))?;
    let with = |change: &dyn Fn(&mut Value)| {
        let mut value = roc.clone();
        change(&mut value);
        value.to_string().into_bytes()
    };
    refused(
        roc_json(&"0".repeat(40)),
        "source CI app/SDK/verification profile mismatch",
    );
    refused(
        with(&|value| value["appRoot"] = json!(".")),
        "source CI app/SDK/verification profile mismatch",
    );
    refused(
        with(&|value| value["campaign"]["cases"] = json!(6)),
        "source CI app/SDK/verification profile mismatch",
    );
    refused(
        with(&|value| value["campaign"]["cases"] = json!(4.0)),
        "source CI app/SDK/verification profile mismatch",
    );
    refused(
        with(&|value| value["schemaVersion"] = json!(true)),
        "source CI app/SDK/verification profile mismatch",
    );
    refused(
        with(&|value| value["extra"] = json!(1)),
        "source CI app/SDK/verification profile mismatch",
    );
    refused(
        with(&|value| value["unitTests"] = json!(["../Escape.roc"])),
        "unsafe pure Roc test declaration",
    );
    refused(
        with(&|value| value["testSources"] = json!(["tests//Unit.roc"])),
        "unsafe pure Roc test declaration",
    );
    refused(
        br#"{"schemaVersion":1,"schemaVersion":1}"#.to_vec(),
        "duplicate_event_field",
    );
    // Another control, or another selected release, is another contract.
    let mut changed = scenario.binding.clone();
    changed["ci_artifact"]["digest"] = json!(day2::digest(b"approved elsewhere"));
    let other = Scenario {
        binding: changed,
        ..Scenario::new()
    };
    fs::write(other.path("source.tar.gz"), source(&roc_json(PLATFORM)))?;
    assert_eq!(
        error(other.run(Mode::VerifyControls)),
        "source CI differs from the instance-approved contract"
    );
    Ok(())
}

#[test]
fn verify_controls_refuses_a_release_that_is_not_the_one_published() -> Result<()> {
    let scenario = Scenario::new();
    fs::write(scenario.path("source.tar.gz"), source(&roc_json(PLATFORM)))?;
    scenario.fake.0.borrow_mut().objects.clear();
    assert!(scenario.run(Mode::VerifyControls).is_err());
    Ok(())
}

#[test]
fn verify_controls_checks_the_approved_digest_before_reading_the_bucket() -> Result<()> {
    let scenario = Scenario {
        binding: binding(&day2::digest(b"approved elsewhere")),
        ..Scenario::new()
    };
    fs::write(scenario.path("source.tar.gz"), source(&roc_json(PLATFORM)))?;
    // No release is published: a bucket read would fail first.
    scenario.fake.0.borrow_mut().objects.clear();
    let mut session = scenario.session(Mode::VerifyControls)?;
    assert_eq!(
        format!("{:#}", session.step("controls").unwrap_err()),
        "source CI differs from the instance-approved contract"
    );
    assert!(!scenario.path("cache").exists());
    Ok(())
}

/// The bytes of the checked app archive, and the ZIP Gitea serves them in.
pub(crate) fn artifact() -> Vec<u8> {
    b"synthetic checked app archive".repeat(100)
}

#[derive(Clone, Copy)]
pub(crate) struct Zip<'a> {
    name: &'a [u8],
    method: u16,
    flags: u16,
    descriptor: Option<bool>,
    file_type: u32,
    crc: Option<u32>,
    entries: u16,
}

pub(crate) const ZIP: Zip<'static> = Zip {
    name: b"app.tar.gz",
    method: 0,
    flags: 0x8,
    descriptor: Some(true),
    file_type: 0o100_644,
    crc: None,
    entries: 1,
};

/// A ZIP laid out as the upload transport writes one: a streamed entry whose
/// local header has no CRC or sizes, a signed data descriptor, one central
/// header and the end record.
pub(crate) fn zip(data: &[u8], shape: Zip<'_>) -> Vec<u8> {
    let mut checksum = flate2::Crc::new();
    checksum.update(data);
    let crc = shape.crc.unwrap_or(checksum.sum());
    let stored = if shape.method == 8 {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    } else {
        data.to_vec()
    };
    let (compressed, size) = (stored.len() as u32, data.len() as u32);
    let le16 = |value: u16| value.to_le_bytes();
    let le32 = |value: u32| value.to_le_bytes();
    let mut out = Vec::new();
    out.extend(le32(0x0403_4b50));
    out.extend(le16(20));
    out.extend(le16(shape.flags));
    out.extend(le16(shape.method));
    out.extend(le16(0x82d7));
    out.extend(le16(0x5d75));
    if shape.descriptor.is_some() {
        out.extend([0; 12]);
    } else {
        out.extend(le32(crc));
        out.extend(le32(compressed));
        out.extend(le32(size));
    }
    out.extend(le16(shape.name.len() as u16));
    out.extend(le16(0));
    out.extend(shape.name);
    out.extend(&stored);
    match shape.descriptor {
        Some(true) => {
            out.extend(le32(0x0807_4b50));
            out.extend(le32(crc));
            out.extend(le32(compressed));
            out.extend(le32(size));
        }
        Some(false) => {
            out.extend(le32(crc));
            out.extend(le32(compressed));
            out.extend(le32(size));
        }
        None => {}
    }
    let directory = out.len() as u32;
    out.extend(le32(0x0201_4b50));
    out.extend(le16(0x032d));
    out.extend(le16(20));
    out.extend(le16(shape.flags));
    out.extend(le16(shape.method));
    out.extend(le16(0x82d7));
    out.extend(le16(0x5d75));
    out.extend(le32(crc));
    out.extend(le32(compressed));
    out.extend(le32(size));
    out.extend(le16(shape.name.len() as u16));
    out.extend([0; 8]);
    out.extend(le32((shape.file_type << 16) | 0x20));
    out.extend(le32(0));
    out.extend(shape.name);
    let directory_size = out.len() as u32 - directory;
    out.extend(le32(0x0605_4b50));
    out.extend([0; 4]);
    out.extend(le16(shape.entries));
    out.extend(le16(shape.entries));
    out.extend(le32(directory_size));
    out.extend(le32(directory));
    out.extend(le16(0));
    out
}

#[test]
fn the_zip_reader_accepts_only_the_transports_one_verified_entry() {
    let data = artifact();
    let expected = BlobIdentity::of(&data);
    for shape in [
        ZIP,
        Zip {
            descriptor: Some(false),
            ..ZIP
        },
        Zip {
            descriptor: None,
            flags: 0,
            ..ZIP
        },
        Zip { method: 8, ..ZIP },
        Zip {
            file_type: 0,
            ..ZIP
        },
    ] {
        assert_eq!(unpack_zip(&zip(&data, shape), &expected).unwrap(), data);
    }
    let refused = |raw: Vec<u8>, identity: &BlobIdentity, code: &str| {
        assert_eq!(
            format!("{:#}", unpack_zip(&raw, identity).unwrap_err()),
            code
        );
    };
    refused(
        zip(
            &data,
            Zip {
                name: b"app.tar",
                ..ZIP
            },
        ),
        &expected,
        ONLY_ARCHIVE,
    );
    refused(
        zip(&data, Zip { entries: 2, ..ZIP }),
        &expected,
        ONLY_ARCHIVE,
    );
    refused(
        zip(&data, Zip { flags: 0x9, ..ZIP }),
        &expected,
        "invalid artifact ZIP entry",
    );
    refused(
        zip(
            &data,
            Zip {
                file_type: 0o120_777,
                ..ZIP
            },
        ),
        &expected,
        "invalid artifact ZIP entry",
    );
    refused(
        zip(
            &data,
            Zip {
                crc: Some(1),
                ..ZIP
            },
        ),
        &expected,
        INVALID_ZIP,
    );
    refused(
        zip(&data, Zip { flags: 0x28, ..ZIP }),
        &expected,
        INVALID_ZIP,
    );
    refused(
        zip(&data, Zip { method: 12, ..ZIP }),
        &expected,
        INVALID_ZIP,
    );
    let other = BlobIdentity::of(b"other bytes of the same size... no");
    refused(zip(&data, ZIP), &other, "invalid artifact ZIP entry");
    let same_size = BlobIdentity {
        digest: day2::digest(b"x"),
        bytes: expected.bytes,
    };
    refused(
        zip(&data, ZIP),
        &same_size,
        "downloaded artifact differs from the native CI job receipt",
    );
    // Bytes before, after or inside the layout.
    let mut prepended = b"junk".to_vec();
    prepended.extend(zip(&data, ZIP));
    refused(prepended, &expected, INVALID_ZIP);
    let mut appended = zip(&data, ZIP);
    appended.extend(b"junk");
    refused(appended, &expected, INVALID_ZIP);
    let mut descriptor = zip(&data, ZIP);
    let at = 30 + 10 + data.len() + 4;
    descriptor[at] ^= 1;
    refused(descriptor, &expected, INVALID_ZIP);
    let mut local = zip(&data, ZIP);
    local[8] = 8;
    refused(local, &expected, INVALID_ZIP);
    refused(vec![0; 10], &expected, INVALID_ZIP);
    refused(
        vec![0; ZIP_LIMIT as usize + 1],
        &expected,
        "artifact ZIP exceeds byte budget",
    );
}

#[test]
fn markers_match_pythons_regex() {
    let cases = [
        (
            "2026-11-21T05:00:00.1234567Z DAY2_CHECKED_APP_V1 {\"a\":1}",
            Some("{\"a\":1}"),
        ),
        ("2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {}\r", Some("{}")),
        ("2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {}\r\r", None),
        ("2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {\r}", None),
        ("2026-11-21T05:00:00Z  DAY2_CHECKED_APP_V1 {}", None),
        ("2026-11-21T05:00:00Z\tDAY2_CHECKED_APP_V1 {}", None),
        (" 2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {}", None),
        ("2026-Z DAY2_CHECKED_APP_V1 {}", None),
        ("2026-xZ DAY2_CHECKED_APP_V1 {}", Some("{}")),
        ("2026-ZZ DAY2_CHECKED_APP_V1 {}", Some("{}")),
        (
            "\u{663}\u{660}\u{662}\u{666}-11Z DAY2_CHECKED_APP_V1 {}",
            Some("{}"),
        ),
        ("2026-11\u{1c}Z DAY2_CHECKED_APP_V1 {}", None),
        ("2026-11\u{a0}Z DAY2_CHECKED_APP_V1 {}", None),
        ("2026-11\u{200b}Z DAY2_CHECKED_APP_V1 {}", Some("{}")),
        ("2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {} trailing", None),
        (
            "2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {a}}",
            Some("{a}}"),
        ),
        ("2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {", None),
        (
            "2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {\u{b}}",
            Some("{\u{b}}"),
        ),
        (
            "2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {\u{2028}}",
            Some("{\u{2028}}"),
        ),
        ("2026-11-21T05:00:00Z foo DAY2_CHECKED_APP_V1 {}", None),
        ("2026-11-21T05:00:00ZDAY2_CHECKED_APP_V1 {}", None),
        ("2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1{}", None),
        ("x\r2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {}", None),
        (
            "2026-11-21T05:00:00Z DAY2_CHECKED_APP_V1 {\"x\":\"}\"} {}",
            Some("{\"x\":\"}\"} {}"),
        ),
    ];
    for (line, expected) in cases {
        assert_eq!(
            markers(line),
            expected.into_iter().collect::<Vec<_>>(),
            "{line:?}"
        );
    }
    let log = cases.map(|(line, _)| line).join("\n") + "\n";
    assert_eq!(
        markers(&log),
        cases
            .iter()
            .filter_map(|(_, expected)| *expected)
            .collect::<Vec<_>>()
    );
}

#[test]
fn urlsplit_splits_as_python_does() {
    let split = urlsplit("HTTPS://storage.googleapis.com/b/o?X-Goog-Signature=s#");
    assert_eq!(
        split,
        Split {
            scheme: "https".into(),
            netloc: "storage.googleapis.com".into(),
            path: "/b/o".into(),
            query: "X-Goog-Signature=s".into(),
            fragment: String::new(),
        }
    );
    assert_eq!(urlsplit("//host:443/p").netloc, "host:443");
    assert_eq!(urlsplit("/relative").scheme, "");
    assert_eq!(urlsplit("https://a@b/c").netloc, "a@b");
    assert!(storage_host("bucket.name_1.storage.googleapis.com"));
    assert!(!storage_host(".storage.googleapis.com"));
    assert!(!storage_host("Bucket.storage.googleapis.com"));
    assert!(!storage_host("evil.com/x.storage.googleapis.com"));
}

/// The job receipt the synthetic main run's log carries.
pub(crate) fn job_receipt(sdk: &BlobIdentity) -> Value {
    let archive = BlobIdentity::of(&artifact());
    json!({"version": 1, "repository": "tools/links-app", "source_commit": COMMIT,
        "source_inputs": inputs(), "artifact_id": "cd".repeat(32),
        "sdk_release": {"digest": sdk.digest, "bytes": sdk.bytes},
        "verification": {"version": 1, "seed": 42, "cases": 4},
        "archive": {"digest": archive.digest, "bytes": archive.bytes},
        "artifact_name": format!("day2-checked-app-{COMMIT}-{}", "ef".repeat(16)),
        "examples": 12, "generated": 40, "upload_id": UPLOAD})
}

pub(crate) fn run_json(id: u64, attempt: u64, status: &str, conclusion: &str) -> Value {
    json!({"id": id, "head_sha": COMMIT, "event": "push", "path": "roc.yml@refs/heads/main",
        "workflow_repository_id": 42, "repository": {"id": 42, "full_name": "tools/links-app"},
        "workflow_commit_sha": COMMIT, "head_branch": "main", "run_attempt": attempt,
        "status": status, "conclusion": conclusion})
}

pub(crate) fn log(receipts: &[&Value]) -> Vec<u8> {
    let mut log = String::from("2026-11-21T05:00:00.0000000Z Checking app\n");
    for receipt in receipts {
        log.push_str(&format!(
            "2026-11-21T05:00:01.0000000Z DAY2_CHECKED_APP_V1 {receipt}\r\n"
        ));
    }
    log.push_str("2026-11-21T05:00:02.0000000Z Done\n");
    log.into_bytes()
}

pub(crate) struct Main {
    pub(crate) runs: String,
    pub(crate) jobs: String,
    pub(crate) logs: String,
    pub(crate) metadata: String,
    pub(crate) zip: String,
    pub(crate) raw: String,
    pub(crate) run: String,
}

/// Route a successful main run, job, upload and download for COMMIT.
pub(crate) fn route_main(scenario: &Scenario) -> Main {
    let sdk = BlobIdentity::of(&manifest());
    route_main_with(&scenario.fake, &job_receipt(&sdk), &artifact())
}

/// As route_main, for a job log carrying `receipt` and an upload of `data`.
pub(crate) fn route_main_with(fake: &Fake, receipt: &Value, data: &[u8]) -> Main {
    let main = Main {
        runs: format!("{PREFIX}/actions/workflows/roc.yml/runs?branch=main&limit=50"),
        jobs: format!("{PREFIX}/actions/runs/7/jobs"),
        logs: format!("{PREFIX}/actions/jobs/31/logs"),
        metadata: format!("{PREFIX}/actions/artifacts/{UPLOAD}"),
        zip: format!("{PREFIX}/actions/artifacts/{UPLOAD}/zip"),
        raw: format!("{PREFIX}/actions/artifacts/{UPLOAD}/zip/raw?sig=synthetic&expires=1"),
        run: format!("{PREFIX}/actions/runs/7"),
    };
    let mut older = run_json(6, 1, "completed", "success");
    older["event"] = json!("pull_request");
    let mut other = run_json(9, 1, "completed", "success");
    other["head_sha"] = json!("f".repeat(40));
    fake.route(
        &main.runs,
        vec![ok(json!({"total_count": 3, "workflow_runs": [other, run_json(7, 1, "completed", "success"), older]}))],
    );
    let job = json!({"id": 31, "name": "roc", "run_id": 7, "head_sha": COMMIT, "run_attempt": 1,
        "status": "completed", "conclusion": "success"});
    let scope = json!({"id": 30, "name": "scope", "run_id": 7, "head_sha": COMMIT, "run_attempt": 1,
        "status": "completed", "conclusion": "success"});
    fake.route(&main.jobs, vec![ok(json!({"jobs": [scope, job]}))]);
    fake.route(&main.logs, vec![bytes(log(&[receipt]))]);
    let raw = zip(data, ZIP);
    fake.route(
        &main.metadata,
        vec![ok(json!({"id": UPLOAD, "name": receipt["artifact_name"], "expired": false,
            "size_in_bytes": raw.len(), "workflow_run": {"id": 7, "repository_id": 42, "head_sha": COMMIT}}))],
    );
    fake.route(&main.zip, vec![redirect(&main.raw)]);
    fake.route(&main.raw, vec![bytes(raw)]);
    fake.route(
        &main.run,
        vec![ok(
            json!({"id": 7, "run_attempt": 1, "status": "completed", "conclusion": "success"}),
        )],
    );
    main
}

#[test]
fn checked_artifact_returns_pythons_proof_and_writes_the_archive_last() -> Result<()> {
    let scenario = Scenario::new();
    let main = route_main(&scenario);
    let receipt = scenario.run(Mode::CheckedArtifact)?;
    let sdk = BlobIdentity::of(&manifest());
    let expected =
        json!({"version": 1, "run": 7, "attempt": 1, "job": 31, "receipt": job_receipt(&sdk)});
    assert_eq!(receipt["proof"], expected);
    // The receipt's integers stay integers: 2**63 - 1 round-trips exactly.
    assert!(
        receipt
            .to_string()
            .contains("\"upload_id\":9223372036854775807")
    );
    assert_eq!(fs::read(scenario.path("ci-artifact.tar.gz"))?, artifact());
    // The token went to the forge and the exact same-origin raw route only.
    assert_eq!(
        scenario.fake.calls(),
        [
            (main.runs, true),
            (main.jobs, true),
            (main.logs, true),
            (main.metadata, true),
            (main.zip, true),
            (main.raw, true),
            (main.run, true),
        ]
    );
    let binding = Binding::check(scenario.binding.clone(), &instance(&scenario.sdk))?;
    proof(&receipt["proof"], &binding.value, COMMIT, &inputs())?;
    assert!(
        proof(
            &receipt["proof"],
            &binding.value,
            COMMIT,
            &format!("sha256:{}", "00".repeat(32))
        )
        .is_err()
    );
    assert!(scenario.fake.0.borrow().announced.is_empty());
    Ok(())
}

#[test]
fn the_receipt_is_the_shape_the_cli_decodes() -> Result<()> {
    let scenario = Scenario::new();
    route_main(&scenario);
    let mut receipt: Receipt = serde_json::from_value(scenario.run(Mode::CheckedArtifact)?)?;
    receipt.archive.as_mut().unwrap().path = "/work/ci-artifact.tar.gz".into();
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
fn the_main_run_is_waited_for_within_the_job_then_given_up_as_retryable() -> Result<()> {
    let scenario = Scenario::new();
    let main = route_main(&scenario);
    scenario.fake.route(
        &main.runs,
        vec![
            ok(json!({"workflow_runs": []})),
            ok(json!({"workflow_runs": [run_json(7, 1, "running", "")]})),
            ok(json!({"workflow_runs": [run_json(7, 1, "completed", "success")]})),
        ],
    );
    scenario.run(Mode::CheckedArtifact)?;
    {
        let world = scenario.fake.0.borrow();
        assert_eq!(world.announced, [WAITING]);
        assert_eq!(world.sleeps, [POLL, POLL]);
    }
    fs::remove_file(scenario.path("ci-artifact.tar.gz"))?;
    // A run that never finishes is retryable once the wait is over.
    let pending = Scenario::new();
    let main = route_main(&pending);
    pending.fake.route(
        &main.runs,
        vec![ok(
            json!({"workflow_runs": [run_json(7, 1, "running", "")]}),
        )],
    );
    assert_eq!(
        error(pending.run(Mode::CheckedArtifact)),
        "retryable: checked_main_artifact_not_ready"
    );
    let world = pending.fake.0.borrow();
    assert_eq!(world.announced, [WAITING]);
    assert_eq!(world.now, WAIT);
    assert!(world.sleeps.iter().all(|sleep| *sleep <= POLL));
    assert_eq!(world.sleeps.len(), 105);
    assert!(!pending.path("ci-artifact.tar.gz").exists());
    Ok(())
}

#[test]
fn only_this_repositorys_successful_push_run_of_this_commit_counts() -> Result<()> {
    let refused = |run: Value, code: &str| {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        scenario
            .fake
            .route(&main.runs, vec![ok(json!({"workflow_runs": [run]}))]);
        assert_eq!(error(scenario.run(Mode::CheckedArtifact)), code);
        assert!(!scenario.path("ci-artifact.tar.gz").exists());
    };
    let identity = "main CI workflow identity mismatch";
    for (key, value) in [
        ("workflow_repository_id", json!(43)),
        ("repository", json!({"id": "42"})),
        ("repository", Value::Null),
        ("workflow_commit_sha", json!("f".repeat(40))),
        ("head_branch", json!("release")),
        ("run_attempt", json!(0)),
        ("run_attempt", json!(true)),
    ] {
        let mut run = run_json(7, 1, "completed", "success");
        run[key] = value;
        refused(run, identity);
    }
    refused(
        run_json(7, 1, "completed", "failure"),
        "main CI did not succeed; retry deployment after fixing CI",
    );
    let mut nameless = run_json(7, 1, "completed", "success");
    nameless.as_object_mut().unwrap().remove("status");
    refused(nameless, "source response lacks status");
    // A dispatched or pull request run, or another commit's, never matches.
    for (key, value) in [
        ("event", json!("workflow_dispatch")),
        ("path", json!("other.yml@refs/heads/main")),
        ("head_sha", json!("f".repeat(40))),
    ] {
        let mut run = run_json(7, 1, "completed", "success");
        run[key] = value;
        refused(run, "retryable: checked_main_artifact_not_ready");
    }
    // The newest matching run decides, and a failed newer attempt is final.
    let scenario = Scenario::new();
    let main = route_main(&scenario);
    scenario.fake.route(
        &main.runs,
        vec![ok(
            json!({"workflow_runs": [run_json(7, 1, "completed", "success"),
            run_json(8, 1, "completed", "cancelled")]}),
        )],
    );
    assert_eq!(
        error(scenario.run(Mode::CheckedArtifact)),
        "main CI did not succeed; retry deployment after fixing CI"
    );
    Ok(())
}

#[test]
fn the_job_and_its_one_log_receipt_must_be_this_attempts() -> Result<()> {
    let sdk = BlobIdentity::of(&manifest());
    let receipt = job_receipt(&sdk);
    let refused = |change: &dyn Fn(&Scenario, &Main), code: &str| {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        change(&scenario, &main);
        assert_eq!(error(scenario.run(Mode::CheckedArtifact)), code);
        assert!(!scenario.path("ci-artifact.tar.gz").exists());
    };
    let job = json!({"id": 31, "name": "roc", "run_id": 7, "head_sha": COMMIT, "run_attempt": 1,
        "status": "completed", "conclusion": "success"});
    for (key, value) in [
        ("run_id", json!(6)),
        ("head_sha", json!("f".repeat(40))),
        ("run_attempt", json!(2)),
        ("conclusion", json!("skipped")),
    ] {
        let mut changed = job.clone();
        changed[key] = value;
        refused(
            &|scenario, main| {
                scenario
                    .fake
                    .route(&main.jobs, vec![ok(json!({"jobs": [changed.clone()]}))])
            },
            "native CI job identity/result mismatch",
        );
    }
    refused(
        &|scenario, main| {
            scenario.fake.route(
                &main.jobs,
                vec![ok(json!({"jobs": [job.clone(), job.clone()]}))],
            )
        },
        "one native CI job required",
    );
    refused(
        &|scenario, main| {
            scenario
                .fake
                .route(&main.jobs, vec![ok(json!({"jobs": []}))])
        },
        "one native CI job required",
    );
    // Exactly one receipt line: none, or a second one an app test printed.
    let marker = "one uploaded-artifact receipt required from the native job log";
    refused(
        &|scenario, main| scenario.fake.route(&main.logs, vec![bytes(log(&[]))]),
        marker,
    );
    refused(
        &|scenario, main| {
            scenario
                .fake
                .route(&main.logs, vec![bytes(log(&[&receipt, &receipt]))])
        },
        marker,
    );
    refused(
        &|scenario, main| {
            scenario
                .fake
                .route(&main.logs, vec![bytes(b"\xff\xfe".to_vec())])
        },
        "native job log is not UTF-8",
    );
    refused(
        &|scenario, main| scenario.fake.route(&main.logs, vec![status(404)]),
        "source_http_404",
    );
    let line = |value: &Value| bytes(log(&[value]));
    let mut changed = receipt.clone();
    changed["extra"] = json!(1);
    refused(
        &|scenario, main| scenario.fake.route(&main.logs, vec![line(&changed)]),
        "invalid checked-artifact receipt fields",
    );
    let belongs = "checked artifact belongs to another source/SDK/profile";
    for (key, value) in [
        ("repository", json!("tools/other")),
        ("source_commit", json!("f".repeat(40))),
        (
            "source_inputs",
            json!(format!("sha256:{}", "00".repeat(32))),
        ),
        (
            "sdk_release",
            json!({"digest": sdk.digest, "bytes": sdk.bytes + 1}),
        ),
        (
            "verification",
            json!({"version": 1, "seed": 42, "cases": 6}),
        ),
        (
            "verification",
            json!({"version": true, "seed": 42, "cases": 4}),
        ),
        ("version", json!(2)),
    ] {
        let mut changed = receipt.clone();
        changed[key] = value;
        refused(
            &|scenario, main| scenario.fake.route(&main.logs, vec![line(&changed)]),
            belongs,
        );
    }
    let upload = "invalid checked artifact or upload identity";
    for (key, value) in [
        ("upload_id", json!(1_u64 << 63)),
        ("upload_id", json!(0)),
        ("upload_id", json!(true)),
        ("upload_id", json!(1.0)),
        ("examples", json!(-1)),
        ("generated", json!(0)),
        ("artifact_id", json!("CD".repeat(32))),
        (
            "artifact_name",
            json!(format!(
                "day2-checked-app-{}-{}",
                "f".repeat(40),
                "ef".repeat(16)
            )),
        ),
    ] {
        let mut changed = receipt.clone();
        changed[key] = value;
        refused(
            &|scenario, main| scenario.fake.route(&main.logs, vec![line(&changed)]),
            upload,
        );
    }
    let mut changed = receipt.clone();
    changed["archive"]["bytes"] = json!(ARTIFACT_LIMIT + 1);
    refused(
        &|scenario, main| scenario.fake.route(&main.logs, vec![line(&changed)]),
        "invalid qualified release blob",
    );
    let duplicate = log(&[&receipt]);
    let text =
        String::from_utf8(duplicate)?.replacen("{\"archive\"", "{\"examples\":1,\"archive\"", 1);
    refused(
        &|scenario, main| {
            scenario
                .fake
                .route(&main.logs, vec![bytes(text.clone().into_bytes())])
        },
        "duplicate_event_field",
    );
    Ok(())
}

#[test]
fn an_expired_or_foreign_upload_is_refused() -> Result<()> {
    let sdk = BlobIdentity::of(&manifest());
    let receipt = job_receipt(&sdk);
    let metadata = json!({"id": UPLOAD, "name": receipt["artifact_name"], "expired": false,
        "size_in_bytes": 1000, "workflow_run": {"id": 7, "repository_id": 42, "head_sha": COMMIT}});
    let mut cases = Vec::new();
    for (key, value) in [
        ("expired", json!(true)),
        ("expired", json!(0)),
        ("expired", Value::Null),
        ("id", json!(UPLOAD - 1)),
        ("name", json!("day2-checked-app-other")),
        ("size_in_bytes", json!(0)),
        ("size_in_bytes", json!(ZIP_LIMIT + 1)),
        ("size_in_bytes", json!(1000.0)),
        (
            "workflow_run",
            json!({"id": 8, "repository_id": 42, "head_sha": COMMIT}),
        ),
        (
            "workflow_run",
            json!({"id": 7, "repository_id": 43, "head_sha": COMMIT}),
        ),
        (
            "workflow_run",
            json!({"id": 7, "repository_id": 42, "head_sha": "f".repeat(40)}),
        ),
        ("workflow_run", Value::Null),
    ] {
        let mut changed = metadata.clone();
        changed[key] = value;
        cases.push(changed);
    }
    let mut missing = metadata.clone();
    missing.as_object_mut().unwrap().remove("expired");
    cases.push(missing);
    for changed in cases {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        scenario.fake.route(&main.metadata, vec![ok(changed)]);
        assert_eq!(
            error(scenario.run(Mode::CheckedArtifact)),
            "uploaded artifact belongs to another run/source or has expired"
        );
        assert!(
            scenario
                .fake
                .calls()
                .iter()
                .all(|(url, _)| *url != main.zip)
        );
    }
    Ok(())
}

#[test]
fn a_rerun_that_starts_during_the_download_supersedes_the_artifact() -> Result<()> {
    for latest in [
        json!({"run_attempt": 2, "status": "running", "conclusion": ""}),
        json!({"run_attempt": 1, "status": "running", "conclusion": ""}),
        json!({"run_attempt": 1, "status": "completed", "conclusion": "failure"}),
    ] {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        scenario.fake.route(&main.run, vec![ok(latest)]);
        assert_eq!(
            error(scenario.run(Mode::CheckedArtifact)),
            "main CI attempt changed during artifact download"
        );
        // Nothing was written for the superseded attempt.
        assert!(!scenario.path("ci-artifact.tar.gz").exists());
    }
    Ok(())
}

#[test]
fn artifact_redirects_are_allowlisted_and_credentials_stay_on_the_raw_route() -> Result<()> {
    let accepted = |location: &str, token: bool| {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        let raw = scenario.fake.0.borrow().routes[&main.raw].clone_front();
        scenario.fake.route(&main.zip, vec![redirect(location)]);
        scenario.fake.route(location, vec![raw]);
        scenario.run(Mode::CheckedArtifact).unwrap();
        let calls = scenario.fake.calls();
        assert!(calls.contains(&(location.to_owned(), token)), "{location}");
    };
    accepted(
        &format!("{PREFIX}/actions/artifacts/{UPLOAD}/zip/raw"),
        true,
    );
    accepted(
        &format!("{PREFIX}/actions/artifacts/{UPLOAD}/zip/raw?sig=s&expires=1#"),
        true,
    );
    accepted(
        &format!("{PREFIX}/actions/artifacts/{UPLOAD}/zip/other"),
        false,
    );
    accepted(
        &format!("{PREFIX}/actions/artifacts/{UPLOAD}/zip/raw/../raw"),
        false,
    );
    accepted(
        "https://storage.googleapis.com/bucket/object?X-Goog-Signature=s",
        false,
    );
    accepted(
        "https://day2-artifacts.storage.googleapis.com/object?X-Goog-Signature=s",
        false,
    );
    let refused = |location: Option<&str>, code: &str| {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        let response = match location {
            Some(location) => redirect(location),
            None => status(302),
        };
        scenario.fake.route(&main.zip, vec![response]);
        assert_eq!(
            error(scenario.run(Mode::CheckedArtifact)),
            code,
            "{location:?}"
        );
        assert_eq!(
            scenario.fake.calls().last().map(|(url, _)| url.clone()),
            Some(main.zip)
        );
    };
    let redirect_refused = "checked_artifact_redirect_refused";
    refused(None, redirect_refused);
    refused(Some("http://storage.googleapis.com/b/o"), redirect_refused);
    refused(Some("https://evil.example.com/b/o"), redirect_refused);
    refused(
        Some("https://storage.googleapis.com.evil.example.com/b/o"),
        redirect_refused,
    );
    refused(
        Some("https://user@storage.googleapis.com/b/o"),
        redirect_refused,
    );
    refused(
        Some("https://storage.googleapis.com:443/b/o"),
        redirect_refused,
    );
    refused(Some("https://git.example.com:443/x"), redirect_refused);
    refused(
        Some("https://storage.googleapis.com/b/o#fragment"),
        redirect_refused,
    );
    refused(
        Some("/api/v1/repos/tools/links-app/actions/artifacts/1/zip/raw"),
        redirect_refused,
    );
    refused(Some("https://GIT.example.com/x"), redirect_refused);
    for code in [301, 303, 307, 308, 404] {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        let mut response = redirect("https://storage.googleapis.com/b/o");
        response.as_mut().unwrap().status = code;
        scenario.fake.route(&main.zip, vec![response]);
        assert_eq!(
            error(scenario.run(Mode::CheckedArtifact)),
            format!("checked_artifact_download_http_{code}")
        );
    }
    // A second redirect is never followed.
    let scenario = Scenario::new();
    let main = route_main(&scenario);
    scenario.fake.route(
        &main.raw,
        vec![redirect("https://storage.googleapis.com/b/o")],
    );
    assert_eq!(
        error(scenario.run(Mode::CheckedArtifact)),
        "checked_artifact_download_http_302"
    );
    // A transient storage failure is retryable.
    let scenario = Scenario::new();
    let main = route_main(&scenario);
    scenario.fake.route(&main.raw, vec![status(503)]);
    assert_eq!(
        error(scenario.run(Mode::CheckedArtifact)),
        "retryable: source_temporarily_unavailable"
    );
    Ok(())
}

#[test]
fn a_zip_that_is_not_the_receipts_archive_is_refused() -> Result<()> {
    for (raw, code) in [
        (zip(b"other bytes", ZIP), "invalid artifact ZIP entry"),
        (
            zip(
                &artifact(),
                Zip {
                    name: b"app.zip",
                    ..ZIP
                },
            ),
            ONLY_ARCHIVE,
        ),
        (
            vec![0; ZIP_LIMIT as usize + 1],
            "source_response_byte_limit",
        ),
    ] {
        let scenario = Scenario::new();
        let main = route_main(&scenario);
        scenario.fake.route(&main.raw, vec![bytes(raw)]);
        assert_eq!(error(scenario.run(Mode::CheckedArtifact)), code);
        assert!(!scenario.path("ci-artifact.tar.gz").exists());
    }
    Ok(())
}

#[test]
fn without_a_token_reads_are_unauthenticated() -> Result<()> {
    let scenario = Scenario::new();
    scenario.fake.route(PREFIX, vec![ok(json!({"id": 42}))]);
    scenario.fake.route(
        &format!("{PREFIX}/branches/main"),
        vec![ok(json!({"commit": {"id": COMMIT}}))],
    );
    let raw = scenario.path("request.json");
    fs::write(&raw, scenario.request(Mode::Head).to_string())?;
    let mut effects = scenario.effects();
    effects.token = None;
    let mut session = Session::prepare(&raw, Mode::Head, effects)?;
    session.step("head")?;
    assert!(scenario.fake.calls().iter().all(|(_, token)| !token));
    Ok(())
}

trait CloneFront {
    fn clone_front(&self) -> Option<Response>;
}

impl CloneFront for VecDeque<Option<Response>> {
    fn clone_front(&self) -> Option<Response> {
        self.front().unwrap().as_ref().map(clone_response)
    }
}

/// What a minimal HTTP/1.1 server received, and serves one fixed response.
fn serve(response: &'static [u8]) -> (String, std::sync::mpsc::Receiver<String>) {
    serve_holding(response, Duration::ZERO)
}

/// As `serve`, keeping the connection open for `hold` after the response.
fn serve_holding(
    response: &'static [u8],
    hold: Duration,
) -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{BufRead, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        let _ = sender.send(head);
        let _ = stream.write_all(response);
        let _ = stream.flush();
        std::thread::sleep(hold);
    });
    (origin, receiver)
}

#[test]
fn the_native_transport_never_follows_a_redirect_and_sends_the_token_only_when_asked() -> Result<()>
{
    let mut native = Native::build(false, TIMEOUT)?;
    let (origin, seen) = serve(
        b"HTTP/1.1 302 Found\r\nLocation: https://storage.googleapis.com/b/o\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
    );
    let response = native.get(&format!("{origin}/zip"), Some(TOKEN), 10)?;
    assert_eq!(
        (
            response.status,
            response.location.as_deref(),
            response.body.len()
        ),
        (302, Some("https://storage.googleapis.com/b/o"), 0)
    );
    let head = seen.recv()?.to_ascii_lowercase();
    assert!(head.starts_with("get /zip http/1.1\r\n"));
    assert!(head.contains("accept: application/json\r\n"));
    assert!(head.contains(&format!("authorization: token {TOKEN}\r\n")));
    let (origin, seen) =
        serve(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n0123456789ab");
    let response = native.get(&format!("{origin}/json"), None, 10)?;
    assert_eq!((response.status, response.body.len()), (200, 11));
    assert!(!seen.recv()?.to_ascii_lowercase().contains("authorization"));
    // A refused connection is a retryable transport failure.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let failure = native
        .get(&format!("http://{closed}/"), None, 10)
        .unwrap_err();
    assert!(failure.downcast_ref::<Retryable>().is_some());
    // The production transport speaks HTTPS only.
    let refused = Native::new()?
        .get(&format!("{origin}/json"), None, 10)
        .unwrap_err();
    assert_eq!(format!("{refused:#}"), "invalid source URL");
    Ok(())
}

#[test]
fn a_dropped_connection_short_body_or_timeout_is_retryable() -> Result<()> {
    let retryable = |native: &mut Native, response: &'static [u8], hold: Duration| {
        let (origin, _seen) = serve_holding(response, hold);
        let failure = native
            .get(&format!("{origin}/archive"), Some(TOKEN), 1000)
            .unwrap_err();
        assert_eq!(
            format!("{:#}", reported(failure)),
            "retryable: source_temporarily_unavailable",
            "{}",
            String::from_utf8_lossy(response)
        );
    };
    let mut native = Native::build(false, Duration::from_millis(300))?;
    // A disconnect before the response headers.
    retryable(&mut native, b"", Duration::ZERO);
    // A body shorter than its Content-Length.
    retryable(
        &mut native,
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
        Duration::ZERO,
    );
    // A body that fails mid-stream.
    retryable(
        &mut native,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10\r\nabc",
        Duration::ZERO,
    );
    // No response headers in time, and a body read that stalls.
    retryable(&mut native, b"", Duration::from_secs(2));
    retryable(
        &mut native,
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc",
        Duration::from_secs(2),
    );
    // A non-2xx status stays the caller's to classify; its body is never read.
    let (origin, _seen) =
        serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx");
    assert_eq!(native.get(&format!("{origin}/x"), None, 10)?.status, 404);
    Ok(())
}

#[test]
fn a_failed_write_removes_only_the_file_it_created() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("new.tar.gz");
    let failed = create_new(&path, |file| {
        file.write_all(b"partial")?;
        Err(std::io::Error::other("no space left on device"))
    });
    assert!(failed.is_err());
    assert!(!path.exists());
    // An existing file is refused before anything is written, and kept.
    fs::write(&path, b"reviewed")?;
    assert!(create_new(&path, |file| file.write_all(b"other")).is_err());
    assert!(create_new(&path, |_| Err(std::io::Error::other("refused"))).is_err());
    assert_eq!(fs::read(&path)?, b"reviewed");
    let written = directory.path().join("written");
    write_new(&written, b"verified")?;
    assert_eq!(fs::read(&written)?, b"verified");
    Ok(())
}

#[derive(Clone, Copy)]
enum Magic {
    Ustar,
    Gnu,
    Old,
}

/// One raw tar header declaring `size`, with `magic` and a prefix field.
fn raw_header(name: &[u8], kind: u8, size: u64, magic: Magic, prefix: &[u8]) -> Vec<u8> {
    let mut header = match magic {
        Magic::Ustar => tar::Header::new_ustar(),
        Magic::Gnu => tar::Header::new_gnu(),
        Magic::Old => tar::Header::new_old(),
    };
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_size(size);
    header.set_mode(0o644);
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    let mut bytes = header.as_bytes().to_vec();
    // The raw type byte: the tar crate writes an old-style regular `\0` as `0`.
    bytes[156] = kind;
    bytes[345..345 + prefix.len()].copy_from_slice(prefix);
    bytes[148..156].fill(b' ');
    let sum: u32 = bytes.iter().map(|b| u32::from(*b)).sum();
    bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    bytes
}

/// A raw member: its header (with the data's size) and its data.
fn member(name: &[u8], kind: u8, data: &[u8], magic: Magic) -> (Vec<u8>, Vec<u8>) {
    (
        raw_header(name, kind, data.len() as u64, magic, b""),
        data.to_vec(),
    )
}

fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(raw).unwrap();
    encoder.finish().unwrap()
}

/// A gzip tar of raw members after the five required controls.
fn raw_tarball(extra: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut members = vec![
        member(b"app/", b'5', b"", Magic::Ustar),
        member(b"app/.ci/roc.json", b'0', b"{}", Magic::Ustar),
        member(b"app/.ci/platform-release.json", b'0', b"{}", Magic::Ustar),
        member(b"app/.ci/publish_artifact.py", b'0', b"#", Magic::Ustar),
        member(b"app/.ci/sdk_release.py", b'0', b"#", Magic::Ustar),
        member(
            b"app/.gitea/workflows/roc.yml",
            b'0',
            b"name: x\n",
            Magic::Ustar,
        ),
    ];
    members.extend_from_slice(extra);
    let mut raw = Vec::new();
    for (header, data) in &members {
        raw.extend_from_slice(header);
        raw.extend_from_slice(data);
        raw.resize(raw.len().next_multiple_of(512), 0);
    }
    raw.extend([0; 1024]);
    gzip(&raw)
}

fn control_names(archive: &[u8]) -> Result<Vec<String>> {
    Ok(Controls::read(archive)?
        .files
        .keys()
        .map(|name| name.iter().map(|c| char::from_u32(*c).unwrap()).collect())
        .collect())
}

#[test]
fn extension_headers_apply_as_tarfile_applies_them_whatever_the_magic() -> Result<()> {
    // pax and GNU long-name headers apply to the next member even without
    // ustar or GNU magic, as tarfile applies them.
    let archive = raw_tarball(&[
        member(
            b"PaxHeader",
            b'x',
            &pax("path", b"app/.ci/policy.json"),
            Magic::Old,
        ),
        member(b"placeholder", b'0', b"{}", Magic::Old),
        member(
            b"././@LongLink",
            b'L',
            b"app/.ci/long-name.json\0",
            Magic::Old,
        ),
        member(b"placeholder", b'0', b"[]", Magic::Old),
        member(b"././@LongLink", b'L', b"app/.ci/same.json\0", Magic::Gnu),
        member(
            b"PaxHeader",
            b'x',
            &pax("path", b"app/.ci/same.json"),
            Magic::Ustar,
        ),
        member(b"placeholder", b'0', b"1", Magic::Gnu),
        // A canonical pax size equal to the header's, and other harmless records.
        member(
            b"PaxHeader",
            b'x',
            &[
                pax("size", b"2"),
                pax("mtime", b"1.5"),
                pax("hdrcharset", b"BINARY"),
            ]
            .concat(),
            Magic::Ustar,
        ),
        member(b"app/.ci/sized.json", b'0', b"{}", Magic::Ustar),
        // A ustar prefix joins its name; an old-style regular entry named with a
        // final slash is a directory, never a control.
        (
            raw_header(b".ci/prefixed.json", b'0', 2, Magic::Ustar, b"app"),
            b"{}".to_vec(),
        ),
        member(b"app/.ci/directory/", 0, b"", Magic::Old),
    ]);
    assert_eq!(
        control_names(&archive)?,
        [
            ".ci/long-name.json",
            ".ci/platform-release.json",
            ".ci/policy.json",
            ".ci/prefixed.json",
            ".ci/publish_artifact.py",
            ".ci/roc.json",
            ".ci/same.json",
            ".ci/sdk_release.py",
            ".ci/sized.json",
            ".gitea/workflows/roc.yml",
        ]
    );
    Ok(())
}

#[test]
fn extension_shapes_tarfile_reads_differently_are_refused() {
    let refused = |extra: Vec<(Vec<u8>, Vec<u8>)>, code: &str| {
        let message = format!(
            "{:#}",
            Controls::read(&raw_tarball(&extra)).err().expect("refused")
        );
        assert_eq!(message, code);
    };
    let pax_header = |records: &[u8]| member(b"PaxHeader", b'x', records, Magic::Ustar);
    let file = || member(b"app/.ci/x.json", b'0', b"{}", Magic::Ustar);
    // A GNU long name beside a different pax path, in either order.
    refused(
        vec![
            member(b"././@LongLink", b'L', b"app/.ci/a.json\0", Magic::Gnu),
            pax_header(&pax("path", b"app/.ci/b.json")),
            file(),
        ],
        UNSUPPORTED,
    );
    refused(
        vec![
            pax_header(&pax("path", b"app/.ci/b.json")),
            member(b"././@LongLink", b'L', b"app/.ci/a.json\0", Magic::Gnu),
            file(),
        ],
        UNSUPPORTED,
    );
    // A NUL in a name.
    refused(
        vec![pax_header(&pax("path", b"app/.ci/a\0b.json")), file()],
        UNSUPPORTED,
    );
    // A non-ustar header whose prefix field is not empty.
    refused(
        vec![(
            raw_header(b"app/.ci/x.json", b'0', 2, Magic::Gnu, b"\x01"),
            b"{}".to_vec(),
        )],
        UNSUPPORTED,
    );
    refused(
        vec![(
            raw_header(b"app/.ci/x.json", b'0', 2, Magic::Old, b"app"),
            b"{}".to_vec(),
        )],
        UNSUPPORTED,
    );
    // Solaris and sparse entries.
    refused(
        vec![member(b"app/.ci/x.json", b'X', b"", Magic::Ustar)],
        UNSUPPORTED,
    );
    refused(
        vec![member(b"app/sparse", b'S', b"", Magic::Gnu)],
        UNSUPPORTED,
    );
    // GNU sparse records, and a pax size that is not canonical or not the header's.
    refused(
        vec![
            pax_header(&pax("GNU.sparse.name", b"app/.ci/y.json")),
            file(),
        ],
        UNSUPPORTED,
    );
    for size in [" 2", "+2", "0_2", "", "2.0", "3"] {
        refused(
            vec![pax_header(&pax("size", size.as_bytes())), file()],
            UNSUPPORTED,
        );
    }
    // A duplicate record, two pax headers for one member, malformed records.
    refused(
        vec![
            pax_header(&[pax("path", b"app/a"), pax("path", b"app/b")].concat()),
            file(),
        ],
        UNSUPPORTED,
    );
    refused(
        vec![
            pax_header(&pax("path", b"app/a")),
            pax_header(&pax("path", b"app/b")),
            file(),
        ],
        UNSUPPORTED,
    );
    refused(vec![pax_header(b"99 path=app/a\n"), file()], UNSUPPORTED);
    refused(vec![pax_header(b"13 pathapp/a\n"), file()], UNSUPPORTED);
    // An extension before a global header, or with no member after it.
    refused(
        vec![
            pax_header(&pax("path", b"app/.ci/x.json")),
            member(b"pax_global_header", b'g', &comment(), Magic::Ustar),
            file(),
        ],
        GLOBAL,
    );
    refused(
        vec![pax_header(&pax("path", b"app/.ci/x.json"))],
        UNSUPPORTED,
    );
    // Data on an old-style directory entry, which tarfile would not skip.
    refused(
        vec![member(b"app/.ci/directory/", 0, b"x", Magic::Old)],
        UNSUPPORTED,
    );
}

#[test]
fn extension_headers_are_capped_before_their_data_is_read() {
    // A few hundred bytes of gzip declaring gigabytes of extension data are
    // refused at the header, before anything is allocated for the data.
    for kind in *b"xgLK" {
        let mut raw = raw_header(b"app/huge", kind, (8 << 30) - 1, Magic::Ustar, b"");
        raw.extend([0; 1024]);
        let archive = gzip(&raw);
        assert!(archive.len() < 1024);
        let message = format!("{:#}", Controls::read(&archive).err().unwrap());
        assert_eq!(message, BUDGET, "{}", char::from(kind));
    }
    let mut raw = raw_header(b"app/.ci/huge", b'0', (8 << 30) - 1, Magic::Ustar, b"");
    raw.extend([0; 1024]);
    assert_eq!(
        format!("{:#}", Controls::read(&gzip(&raw)).err().unwrap()),
        BUDGET
    );
}

#[test]
fn decompression_stops_at_the_stream_budget() -> Result<()> {
    // Global headers are not members, so only the stream bound stops them.
    // `1048576 comment=<filler>\n` is exactly EXTENSION_LIMIT bytes.
    let comment = pax("comment", &vec![b'a'; EXTENSION_LIMIT as usize - 17]);
    assert_eq!(comment.len() as u64, EXTENSION_LIMIT);
    let header = raw_header(
        b"pax_global_header",
        b'g',
        EXTENSION_LIMIT,
        Magic::Ustar,
        b"",
    );
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    for _ in 0..=STREAM_LIMIT / EXTENSION_LIMIT {
        encoder.write_all(&header)?;
        encoder.write_all(&comment)?;
    }
    encoder.write_all(&[0; 1024])?;
    let archive = encoder.finish()?;
    assert_eq!(
        format!("{:#}", Controls::read(&archive).err().unwrap()),
        BUDGET
    );
    Ok(())
}
