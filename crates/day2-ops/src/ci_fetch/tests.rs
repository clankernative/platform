use super::*;
use crate::instance_source::{
    Response,
    tests::{Fake, TOKEN as FORGE_TOKEN, bytes, comment, ok, status},
};
use std::{io::Write, os::unix::fs::PermissionsExt};

const SERVER: &str = "https://git.example.com";
const PREFIX: &str = "https://git.example.com/api/v1/repos/tools/links";
const HEAD: &str = "1111111111111111111111111111111111111111";
const BASE: &str = "2222222222222222222222222222222222222222";
const WORKFLOW: &str = "3333333333333333333333333333333333333333";
const REPOSITORY_ID: u64 = 17;
const GOLDEN_REPORT: &str = include_str!("../../../../cli/fixtures/ci-fetch-report.json");

/// The source adapter's fake clock, without jitter.
impl Waiting for Fake {
    fn jitter(&mut self, _most: u64) -> u64 {
        0
    }
}

fn environment(event: &str, path: &Path) -> Environment {
    Environment {
        event_name: event.to_owned(),
        event_path: path.to_path_buf(),
        repository: "tools/links".to_owned(),
        server: SERVER.to_owned(),
        sha: HEAD.to_owned(),
        run: 41,
        attempt: 2,
        workflow_sha: Some(WORKFLOW.to_owned()),
    }
}

fn variables(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    move |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| OsString::from(value))
    }
}

const RUNNER: [(&str, &str); 8] = [
    ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_EVENT_PATH", "/runner/event.json"),
    ("GITHUB_REPOSITORY", "tools/links"),
    ("GITHUB_SERVER_URL", "https://git.example.com/"),
    ("GITHUB_SHA", HEAD),
    ("GITHUB_RUN_ID", "41"),
    ("GITHUB_RUN_ATTEMPT", "2"),
    ("GITHUB_WORKFLOW_SHA", WORKFLOW),
];

fn without(name: &str) -> Vec<(&'static str, &'static str)> {
    RUNNER.into_iter().filter(|(key, _)| *key != name).collect()
}

fn with(name: &str, value: &'static str) -> Vec<(&'static str, &'static str)> {
    RUNNER
        .into_iter()
        .map(|(key, old)| (key, if key == name { value } else { old }))
        .collect()
}

#[test]
fn the_runner_environment_is_read_exactly_and_never_echoed() -> Result<()> {
    let read = Environment::read(variables(&RUNNER))?;
    assert_eq!(
        read,
        environment("pull_request", Path::new("/runner/event.json"))
    );
    // A runner that does not export the workflow commit leaves it unknown.
    let read = Environment::read(variables(&without("GITHUB_WORKFLOW_SHA")))?;
    assert_eq!(read.workflow_sha, None);
    for name in [
        "GITHUB_EVENT_NAME",
        "GITHUB_EVENT_PATH",
        "GITHUB_REPOSITORY",
        "GITHUB_SERVER_URL",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ] {
        let error = format!(
            "{:#}",
            Environment::read(variables(&without(name))).unwrap_err()
        );
        assert!(error.contains(name), "{error}");
    }
    for (name, value) in [
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "one"),
        ("GITHUB_RUN_ATTEMPT", "-1"),
        ("GITHUB_SHA", "1111111"),
        ("GITHUB_SHA", "0000000000000000000000000000000000000000"),
        (
            "GITHUB_WORKFLOW_SHA",
            "ABCDEF1111111111111111111111111111111111",
        ),
        ("GITHUB_SERVER_URL", "http://git.example.com"),
        ("GITHUB_SERVER_URL", "https://git.example.com/sub"),
        ("GITHUB_EVENT_PATH", "event.json"),
        // Platform repositories, other orgs' shapes and names that are no app ID.
        ("GITHUB_REPOSITORY", "tools/day2-ci"),
        ("GITHUB_REPOSITORY", "tools/day2instance"),
        ("GITHUB_REPOSITORY", "Tools/links"),
        ("GITHUB_REPOSITORY", "tools/links-app"),
        ("GITHUB_REPOSITORY", "tools/tofu"),
        ("GITHUB_REPOSITORY", "links"),
    ] {
        let error = format!(
            "{:#}",
            Environment::read(variables(&with(name, value))).unwrap_err()
        );
        assert!(error.contains(name), "{name}: {error}");
        assert!(!error.contains(value), "{error} echoes {value}");
    }
    Ok(())
}

fn push_payload() -> Value {
    json!({
        "ref": MAIN, "before": BASE, "after": HEAD,
        "repository": {"id": REPOSITORY_ID, "full_name": "tools/links"},
    })
}

fn pull_payload() -> Value {
    json!({
        "action": "synchronized",
        "number": 9,
        "pull_request": {
            "number": 9,
            "head": {"sha": HEAD, "ref": "feature", "repo_id": REPOSITORY_ID},
            "base": {"sha": BASE, "ref": "main", "repo_id": REPOSITORY_ID},
            "merge_base": BASE,
        },
        "repository": {"id": REPOSITORY_ID, "full_name": "tools/links"},
    })
}

fn refused(event: &str, payload: Value) -> String {
    let environment = environment(event, Path::new("/runner/event.json"));
    format!("{:#}", trigger(&environment, &payload).unwrap_err())
}

#[test]
fn only_a_push_to_main_and_a_same_repository_pull_request_are_checked() {
    let push = environment("push", Path::new("/e"));
    assert_eq!(
        trigger(&push, &push_payload()).unwrap(),
        (Trigger::Push, REPOSITORY_ID)
    );
    let pull = environment("pull_request", Path::new("/e"));
    assert_eq!(
        trigger(&pull, &pull_payload()).unwrap(),
        (
            Trigger::PullRequest {
                number: 9,
                base: BASE.into()
            },
            REPOSITORY_ID
        )
    );
    // Any other event, whatever its payload.
    for event in [
        "workflow_dispatch",
        "pull_request_target",
        "schedule",
        "release",
    ] {
        let error = refused(event, pull_payload());
        assert!(error.contains("only for pull_request and push"), "{error}");
        assert!(!error.contains(event), "{error}");
    }
    // A push to another branch or tag, or of another commit.
    let mut branch = push_payload();
    branch["ref"] = json!("refs/heads/release");
    assert!(refused("push", branch).contains("only to refs/heads/main"));
    let mut tag = push_payload();
    tag["ref"] = json!("refs/tags/main");
    assert!(refused("push", tag).contains("only to refs/heads/main"));
    let mut other = push_payload();
    other["after"] = json!(BASE);
    assert!(refused("push", other).contains("not GITHUB_SHA"));
    // A fork's pull request, a deleted head repository, another head commit.
    let mut fork = pull_payload();
    fork["pull_request"]["head"]["repo_id"] = json!(18);
    assert!(refused("pull_request", fork).contains("another repository"));
    let mut deleted = pull_payload();
    deleted["pull_request"]["head"]["repo_id"] = json!(-1);
    assert!(refused("pull_request", deleted).contains("another repository"));
    let mut foreign_base = pull_payload();
    foreign_base["pull_request"]["base"]["repo_id"] = json!(18);
    assert!(refused("pull_request", foreign_base).contains("another repository"));
    let mut moved = pull_payload();
    moved["pull_request"]["head"]["sha"] = json!(BASE);
    assert!(refused("pull_request", moved).contains("not GITHUB_SHA"));
    // The merge base Gitea computed must be a full commit.
    for base in [json!(""), json!("2222"), json!(null), json!("0".repeat(40))] {
        let mut baseless = pull_payload();
        baseless["pull_request"]["merge_base"] = base;
        assert!(refused("pull_request", baseless).contains("no merge base"));
    }
    // The payload must describe the run's repository.
    let mut renamed = pull_payload();
    renamed["repository"]["full_name"] = json!("tools/other");
    assert!(refused("pull_request", renamed).contains("not GITHUB_REPOSITORY"));
    let mut unnamed = push_payload();
    unnamed["repository"]["id"] = json!(true);
    assert!(refused("push", unnamed).contains("no repository ID"));
    let mut numberless = pull_payload();
    numberless["pull_request"]["number"] = json!("9");
    assert!(refused("pull_request", numberless).contains("no pull request"));
}

/// One tar member with a mode and, for a symlink, its target.
fn member(builder: &mut tar::Builder<Vec<u8>>, name: &str, kind: u8, mode: u32, data: &[u8]) {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_mode(mode);
    if kind == b'2' {
        header.set_size(0);
        // An empty target stays the header's zeroed link name field.
        if !data.is_empty() {
            header
                .set_link_name(std::str::from_utf8(data).unwrap())
                .unwrap();
        }
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();
    } else {
        header.set_size(data.len() as u64);
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }
}

/// A gzip tar as git archive writes one: a pax global comment, then members.
fn archive(members: &[(&str, u8, u32, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    crate::instance_source::tests::entry(&mut builder, b"pax_global_header", b'g', &comment());
    for (name, kind, mode, data) in members {
        member(&mut builder, name, *kind, *mode, data);
    }
    let raw = builder.into_inner().unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw).unwrap();
    encoder.finish().unwrap()
}

/// An app repository as Gitea archives it: the app, a ui script, a tool, prose
/// and a top-level link to an app module, as Home has.
fn repository(app: &[u8]) -> Vec<u8> {
    archive(&[
        ("links/", b'5', 0o775, b""),
        ("links/README.md", b'0', 0o664, b"# Links\n"),
        (
            "links/LaunchUrl.roc",
            b'2',
            0o777,
            b"app/domain/LaunchUrl.roc",
        ),
        ("links/app/", b'5', 0o775, b""),
        ("links/app/App.roc", b'0', 0o664, app),
        ("links/app/domain/", b'5', 0o775, b""),
        (
            "links/app/domain/LaunchUrl.roc",
            b'0',
            0o664,
            b"LaunchUrl :: [].{}\n",
        ),
        ("links/app/ui/app.js", b'0', 0o664, b"export const a = 1;\n"),
        ("links/tools/run", b'0', 0o775, b"tool\n"),
    ])
}

#[test]
fn a_tree_is_unpacked_with_deploys_refusals_and_has_deploys_source_inputs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let bytes = repository(b"App :: [].{}\n");
    let head = directory.path().join("head");
    let unpacked = crate::instance_candidate::unpack(&bytes, Some(APP), &head)?;
    assert_eq!(
        unpacked,
        crate::instance_candidate::Unpacked {
            files: 5,
            bytes: 65,
            directories: 4,
            links: 1
        }
    );
    // One identity: the tree day2 ci check reads, and the archive deploy reads.
    assert_eq!(
        crate::ci_check::source_inputs(&head.join("app"))?,
        crate::instance_candidate::source_inputs(&bytes, APP)?
    );
    let mode = |path: &str| {
        fs::symlink_metadata(head.join(path))
            .unwrap()
            .permissions()
            .mode()
    };
    assert_eq!(mode("tools/run") & 0o777, 0o755);
    assert_eq!(mode("README.md") & 0o777, 0o644);
    assert_eq!(
        fs::read_link(head.join("LaunchUrl.roc"))?,
        PathBuf::from("app/domain/LaunchUrl.roc")
    );
    // The router sees the link without following it.
    let tree = crate::ci_check::read_tree(&head)?;
    assert!(matches!(
        tree.get("LaunchUrl.roc"),
        Some(crate::ci_check::Entry::Symlink { .. })
    ));
    // The destination must be new.
    assert!(crate::instance_candidate::unpack(&bytes, Some(APP), &head).is_err());
    Ok(())
}

#[test]
fn unpacking_refuses_what_deploy_refuses_and_anything_that_could_escape() {
    let refused = |members: &[(&str, u8, u32, &[u8])], app: Option<&str>| {
        let directory = tempfile::tempdir().unwrap();
        let error = crate::instance_candidate::unpack(
            &archive(members),
            app,
            &directory.path().join("tree"),
        )
        .unwrap_err();
        format!("{error:#}")
    };
    let app: (&str, u8, u32, &[u8]) = ("r/app/App.roc", b'0', 0o644, b"App\n");
    // A link inside the app, as deploy refuses; outside it, a link is kept.
    assert!(refused(&[app, ("r/app/link", b'2', 0o777, b"App.roc")], Some(APP)).contains("links"));
    // Nothing below a link or a file, even outside the app.
    assert!(
        refused(
            &[
                app,
                ("r/out", b'2', 0o777, b"/etc"),
                ("r/out/passwd", b'0', 0o644, b"x")
            ],
            Some(APP)
        )
        .contains("below a file or link")
    );
    assert!(
        refused(
            &[
                app,
                ("r/file", b'0', 0o644, b"x"),
                ("r/file/inner", b'0', 0o644, b"x")
            ],
            None
        )
        .contains("below a file or link")
    );
    // No path twice, and no hard links, devices or FIFOs anywhere.
    assert!(
        refused(
            &[app, ("r/x", b'0', 0o644, b"1"), ("r/x", b'0', 0o644, b"2")],
            None
        )
        .contains("duplicate")
    );
    assert!(
        refused(
            &[app, ("r/x", b'2', 0o777, b"a"), ("r/x", b'5', 0o755, b"")],
            None
        )
        .contains("duplicate")
    );
    for kind in *b"1346" {
        assert!(refused(&[app, ("r/special", kind, 0o644, b"")], None).contains("special"));
    }
    // Unsafe paths and more than one root.
    assert!(refused(&[app, ("r/../x", b'0', 0o644, b"x")], None).contains("unsafe"));
    assert!(refused(&[app, ("/r/x", b'0', 0o644, b"x")], None).contains("unsafe"));
    assert!(refused(&[app, ("s/x", b'0', 0o644, b"x")], None).contains("multiple roots"));
    assert!(refused(&[("r", b'0', 0o644, b"x")], None).contains("repository directory"));
    assert!(refused(&[app, ("r/link", b'2', 0o777, b"")], None).contains("without a target"));
    // A name the tree reader could not read back.
    let mut builder = tar::Builder::new(Vec::new());
    crate::instance_source::tests::entry(&mut builder, b"r/app/App.roc", b'0', b"App\n");
    crate::instance_source::tests::entry(&mut builder, b"r/\xff", b'0', b"x");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let error = crate::instance_candidate::unpack(
        &encoder.finish().unwrap(),
        None,
        &directory.path().join("tree"),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("UTF-8"));
}

#[test]
fn a_pax_or_gnu_link_target_is_tarfiles() -> Result<()> {
    use crate::instance_source::tests::{entry, pax};
    let tree = |extensions: &[(&[u8], u8, Vec<u8>)]| -> Result<PathBuf> {
        let mut builder = tar::Builder::new(Vec::new());
        entry(&mut builder, b"r/", b'5', b"");
        entry(&mut builder, b"r/app/App.roc", b'0', b"App\n");
        for (name, kind, data) in extensions {
            entry(&mut builder, name, *kind, data);
        }
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("short").unwrap();
        header.as_old_mut().name[..6].copy_from_slice(b"r/link");
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&builder.into_inner().unwrap()).unwrap();
        let directory = tempfile::tempdir()?;
        let tree = directory.path().join("t");
        crate::instance_candidate::unpack(&encoder.finish()?, Some(APP), &tree)?;
        Ok(fs::read_link(tree.join("link"))?)
    };
    let long = "l".repeat(150);
    assert_eq!(tree(&[])?, PathBuf::from("short"));
    assert_eq!(
        tree(&[(b"PaxHeader", b'x', pax("linkpath", long.as_bytes()))])?,
        PathBuf::from(&long)
    );
    assert_eq!(
        tree(&[(b"././@LongLink", b'K', [long.as_bytes(), b"\0"].concat())])?,
        PathBuf::from(&long)
    );
    // A pax target beside a different GNU one is refused, as for names.
    assert!(
        tree(&[
            (b"././@LongLink", b'K', b"other\0".to_vec()),
            (b"PaxHeader", b'x', pax("linkpath", long.as_bytes())),
        ])
        .is_err()
    );
    Ok(())
}

/// A fake forge and runner for one run.
struct Run {
    fake: Fake,
    directory: tempfile::TempDir,
    event: String,
    token: Option<String>,
}

impl Run {
    fn new(event: &str, payload: &Value) -> Self {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("payload.json"),
            serde_json::to_vec(payload).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.path().join("request.json"),
            json!({"directory": directory.path().join("ci")}).to_string(),
        )
        .unwrap();
        let fake = Fake::default();
        fake.route(
            PREFIX,
            vec![ok(json!({"id": REPOSITORY_ID, "full_name": "tools/links"}))],
        );
        fake.route(
            &format!("{PREFIX}/archive/{HEAD}.tar.gz"),
            vec![bytes(repository(b"App :: [].{}\n"))],
        );
        fake.route(
            &format!("{PREFIX}/archive/{BASE}.tar.gz"),
            vec![bytes(repository(b"App :: [].{ old }\n"))],
        );
        Self {
            fake,
            directory,
            event: event.to_owned(),
            token: Some(FORGE_TOKEN.to_owned()),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn effects(&self) -> Effects {
        Effects {
            transport: Box::new(self.fake.clone()),
            waiting: Box::new(self.fake.clone()),
            environment: environment(&self.event, &self.path("payload.json")),
            token: self.token.clone(),
        }
    }

    fn session(&self) -> Result<Session> {
        Session::prepare(&self.path("request.json"), self.effects())
    }

    /// The recipe's order: repository, event, head, base when planned, result.
    fn fetch(&self) -> Result<Value> {
        let mut session = self.session()?;
        session.step("repository")?;
        let planned = session.step("event")?;
        session.step("head")?;
        if planned["base"] == true {
            session.step("base")?;
        }
        session.step("result")
    }
}

#[test]
fn a_pull_request_fetches_its_head_and_merge_base_and_records_the_run() -> Result<()> {
    let run = Run::new("pull_request", &pull_payload());
    let report: Report = serde_json::from_value(run.fetch()?)?;
    let ci = run.path("ci");
    let event = Event {
        format: 1,
        repository: "tools/links".into(),
        repository_id: REPOSITORY_ID,
        event: "pull_request".into(),
        head: HEAD.into(),
        base: Some(BASE.into()),
        pull_request: Some(9),
        run: 41,
        attempt: 2,
        workflow_commit: Some(WORKFLOW.into()),
    };
    assert_eq!(report.event, event);
    assert_eq!(Event::read(&ci)?, event);
    assert_eq!(fs::read(ci.join("head/app/App.roc"))?, b"App :: [].{}\n");
    assert_eq!(
        fs::read(ci.join("base/app/App.roc"))?,
        b"App :: [].{ old }\n"
    );
    assert_eq!(
        report.source_inputs,
        crate::ci_check::source_inputs(&ci.join("head/app"))?
    );
    assert_eq!(fs::metadata(&ci)?.permissions().mode() & 0o777, 0o700);
    // Every read went to the job's own repository, with the job token.
    assert_eq!(
        run.fake.calls(),
        [
            (PREFIX.to_owned(), true),
            (format!("{PREFIX}/archive/{HEAD}.tar.gz"), true),
            (format!("{PREFIX}/archive/{BASE}.tar.gz"), true),
        ]
    );
    Ok(())
}

#[test]
fn a_push_to_main_fetches_only_its_head_so_every_lane_runs() -> Result<()> {
    let run = Run::new("push", &push_payload());
    let report: Report = serde_json::from_value(run.fetch()?)?;
    assert_eq!(report.base, None);
    assert_eq!(report.event.base, None);
    assert_eq!(report.event.pull_request, None);
    assert!(!run.path("ci/base").exists());
    assert_eq!(run.fake.calls().len(), 2);
    // The base step is not part of a push's order.
    fs::remove_dir_all(run.path("ci"))?;
    let mut session = run.session()?;
    session.step("repository")?;
    session.step("event")?;
    session.step("head")?;
    let error = format!("{:#}", session.step("base").unwrap_err());
    assert!(error.contains("runs result next"), "{error}");
    Ok(())
}

#[test]
fn steps_run_once_in_order() -> Result<()> {
    let run = Run::new("pull_request", &pull_payload());
    let mut session = run.session()?;
    for (name, expected) in [("event", "repository"), ("result", "repository")] {
        let error = format!("{:#}", session.step(name).unwrap_err());
        assert!(error.contains(&format!("runs {expected} next")), "{error}");
    }
    session.step("repository")?;
    assert!(session.step("repository").is_err());
    session.step("event")?;
    session.step("head")?;
    assert!(session.step("result").is_err());
    session.step("base")?;
    session.step("result")?;
    assert!(format!("{:#}", session.step("result").unwrap_err()).contains("nothing more"));
    Ok(())
}

#[test]
fn the_forge_must_still_say_what_the_event_said() -> Result<()> {
    let failed = |route: &str, response: Option<Response>| -> String {
        let run = Run::new("pull_request", &pull_payload());
        run.fake.route(route, vec![response]);
        format!("{:#}", run.fetch().unwrap_err())
    };
    // The token reads another repository than the event's.
    assert!(
        failed(PREFIX, ok(json!({"id": 99, "full_name": "tools/links"})))
            .contains("not the event's")
    );
    // A refused read fails at once, with the controller's code.
    assert!(failed(PREFIX, status(404)).contains("source_http_404"));
    assert!(
        failed(&format!("{PREFIX}/archive/{HEAD}.tar.gz"), status(403))
            .contains("source_archive_http_403")
    );
    Ok(())
}

#[test]
fn a_transient_forge_failure_is_retried_within_the_deadline() -> Result<()> {
    let run = Run::new("push", &push_payload());
    let url = format!("{PREFIX}/archive/{HEAD}.tar.gz");
    run.fake.route(
        &url,
        vec![status(502), None, bytes(repository(b"App :: [].{}\n"))],
    );
    run.fetch()?;
    assert_eq!(
        run.fake.0.borrow().sleeps,
        [Duration::from_secs(2), Duration::from_secs(4)]
    );
    // Always failing: the last failure, once the next pause no longer fits.
    let run = Run::new("push", &push_payload());
    run.fake.route(&url, vec![status(503)]);
    let error = format!("{:#}", run.fetch().unwrap_err());
    assert_eq!(error, "retryable: source_temporarily_unavailable");
    // Pauses of 2, 4, 8 and then 16 s while each and 5 s more fit in 120 s.
    let sleeps = run.fake.0.borrow().sleeps.clone();
    assert_eq!(
        sleeps,
        [2, 4, 8, 16, 16, 16, 16, 16, 16].map(Duration::from_secs)
    );
    assert!(sleeps.iter().sum::<Duration>() + Duration::from_secs(16 + 5) > DEADLINE);
    assert_eq!(run.fake.0.borrow().announced.len(), sleeps.len());
    Ok(())
}

#[test]
fn a_run_needs_its_token_a_new_directory_and_a_readable_event() -> Result<()> {
    let mut run = Run::new("push", &push_payload());
    run.token = None;
    let error = format!("{:#}", run.session().err().unwrap());
    assert!(error.contains("GITHUB_TOKEN"), "{error}");
    assert!(!run.path("ci").exists());
    run.token = Some(FORGE_TOKEN.to_owned());
    fs::create_dir(run.path("ci"))?;
    assert!(format!("{:#}", run.session().err().unwrap()).contains("new directory"));
    fs::remove_dir(run.path("ci"))?;
    fs::write(run.path("payload.json"), b"{\"ref\":1,\"ref\":2}")?;
    assert!(format!("{:#}", run.session().err().unwrap()).contains("event payload"));
    assert!(!run.path("ci").exists());
    // The token is never part of a failure.
    let run = Run::new("pull_request", &pull_payload());
    run.fake.route(PREFIX, vec![status(401)]);
    assert!(!format!("{:#}", run.fetch().unwrap_err()).contains(FORGE_TOKEN));
    Ok(())
}

#[test]
fn the_event_record_is_exact() -> Result<()> {
    let run = Run::new("pull_request", &pull_payload());
    run.fetch()?;
    let ci = run.path("ci");
    let mut value: Value = serde_json::from_slice(&fs::read(ci.join(EVENT_FILE))?)?;
    let write = |value: &Value| {
        let mut file = fs::File::create(ci.join(EVENT_FILE)).unwrap();
        file.write_all(value.to_string().as_bytes()).unwrap();
    };
    let original = value.clone();
    for change in [
        json!({"format": 2}),
        json!({"event": "workflow_dispatch"}),
        json!({"base": null}),
        json!({"pull_request": null}),
        json!({"head": "1111"}),
        json!({"repository": "tools/day2-ci"}),
        json!({"attempt": 0}),
        json!({"extra": true}),
    ] {
        for (key, field) in change.as_object().unwrap() {
            value[key] = field.clone();
        }
        write(&value);
        assert!(Event::read(&ci).is_err(), "{change}");
        value = original.clone();
    }
    write(&original);
    assert_eq!(Event::read(&ci)?.app(), "links");
    Ok(())
}

#[test]
fn the_report_is_the_shape_the_cli_decodes() -> Result<()> {
    let golden: Report = serde_json::from_str(GOLDEN_REPORT)?;
    assert_eq!(
        serde_json::to_value(&golden)?,
        serde_json::from_str::<Value>(GOLDEN_REPORT)?
    );
    let run = Run::new("pull_request", &pull_payload());
    let report = run.fetch()?;
    let keys = |value: &Value| {
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    let golden: Value = serde_json::from_str(GOLDEN_REPORT)?;
    assert_eq!(keys(&report), keys(&golden));
    assert_eq!(keys(&report["event"]), keys(&golden["event"]));
    assert_eq!(keys(&report["head"]), keys(&golden["head"]));
    Ok(())
}
