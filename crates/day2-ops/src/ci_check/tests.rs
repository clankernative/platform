use super::*;
use std::{io::Read, os::unix::fs::PermissionsExt};

fn write(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A repository with an app, a ui module, extension sources, prose and tooling.
fn repository() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    write(root, "README.md", b"# App\n");
    write(root, "app/App.roc", b"App :: [].{}\n");
    write(root, "app/model-identities.json", b"{}\n");
    write(root, "app/domain/Rules.roc", b"Rules :: [].{}\n");
    write(root, "app/domain/README.md", b"rules\n");
    write(root, "app/ui/app.js", b"export const a = 1;\n");
    write(root, "app/ui/NOTES.md", b"notes\n");
    write(root, "app/.chrome-extension/extension.json", b"{}\n");
    write(
        root,
        "app/.chrome-extension/src/background.js",
        b"chrome.x();\n",
    );
    write(root, "app/.clanker/scenes/home.json", b"{}\n");
    write(root, "tools/script.mjs", b"export {};\n");
    write(root, "tools/data.txt", b"data\n");
    write(root, "LaunchUrl.roc", b"LaunchUrl :: [].{}\n");
    directory
}

/// The lanes and reasons for a change to the head, and optionally the base.
fn routed(head_change: impl FnOnce(&Path), base_change: impl FnOnce(&Path)) -> Route {
    let base = repository();
    let head = repository();
    head_change(head.path());
    base_change(base.path());
    route(
        &read_tree(head.path()).unwrap(),
        Some(&read_tree(base.path()).unwrap()),
    )
}

fn lanes(change: impl FnOnce(&Path)) -> (Vec<&'static str>, Vec<(String, Vec<String>)>) {
    let routed = routed(change, |_| {});
    (
        routed.lanes.names(),
        routed
            .reasons
            .into_iter()
            .map(|reason| (reason.path, reason.lanes))
            .collect(),
    )
}

const NONE: [&str; 0] = [];
const ALL: [&str; 3] = ["native", "extension", "javascript"];

#[test]
fn routing_asks_the_build_capture_rules() {
    // No base, and identical trees, run every lane: routing only narrows a
    // pull request's gate.
    let head = repository();
    let tree = read_tree(head.path()).unwrap();
    assert_eq!(route(&tree, None).lanes, Lanes::ALL);
    assert!(!route(&tree, None).base);
    let identical = route(&tree, Some(&tree));
    assert_eq!((identical.lanes, identical.changed), (Lanes::ALL, 0));
    assert_eq!(
        lanes(|root| write(root, "app/domain/Rules.roc", b"Rules :: [].{ a = 1 }\n")).0,
        ["native"]
    );
    // UI resources, including prose there, are captured; prose elsewhere is not.
    assert_eq!(
        lanes(|root| write(root, "app/ui/NOTES.md", b"more\n")).0,
        ["native"]
    );
    assert_eq!(
        lanes(|root| write(root, "app/domain/README.md", b"x\n")).0,
        NONE
    );
    assert_eq!(lanes(|root| write(root, "README.md", b"x\n")).0, NONE);
    assert_eq!(lanes(|root| write(root, "tools/data.txt", b"x\n")).0, NONE);
    // Captured JavaScript selects both lanes; tooling JavaScript only its own.
    assert_eq!(
        lanes(|root| write(root, "app/ui/app.js", b"export const a = 2;\n")).0,
        ["native", "javascript"]
    );
    assert_eq!(
        lanes(|root| write(root, "tools/script.mjs", b"export { };\n")).0,
        ["javascript"]
    );
    // Any Roc source selects the formatter's lane.
    assert_eq!(
        lanes(|root| write(root, "LaunchUrl.roc", b"LaunchUrl :: [].{ }\n")).0,
        ["native"]
    );
    // Extension sources are never captured.
    assert_eq!(
        lanes(|root| write(
            root,
            "app/.chrome-extension/src/background.js",
            b"chrome.y();\n"
        ))
        .0,
        ["extension", "javascript"]
    );
    assert_eq!(
        lanes(|root| write(root, "app/.chrome-extension/src/new.js", b"chrome.y();\n")).0,
        ["extension", "javascript"]
    );
}

#[test]
fn routing_is_conservative_about_topology_modes_and_links() {
    // Adding or removing even skipped prose where the build walks.
    assert_eq!(
        lanes(|root| write(root, "app/domain/NEW.md", b"x\n")).0,
        ["native"]
    );
    assert_eq!(
        lanes(|root| fs::remove_file(root.join("app/domain/README.md")).unwrap()).0,
        ["native"]
    );
    // A refused input.
    assert_eq!(
        lanes(|root| write(root, "app/domain/tool.mjs", b"export {};\n")).0,
        ["native", "javascript"]
    );
    // A mode change anywhere.
    assert_eq!(
        lanes(|root| {
            fs::set_permissions(
                root.join("tools/data.txt"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap()
        })
        .0,
        ["native"]
    );
    // A symlink anywhere.
    let (selected, reasons) =
        lanes(|root| std::os::unix::fs::symlink("data.txt", root.join("tools/link.txt")).unwrap());
    assert_eq!(selected, ["native"]);
    assert_eq!(
        reasons,
        [("tools/link.txt".to_owned(), vec!["native".to_owned()])]
    );
    // A special file anywhere: a socket outside the app.
    let (selected, reasons) = lanes(|root| {
        std::os::unix::net::UnixListener::bind(root.join("tools/control.sock")).unwrap();
    });
    assert_eq!(selected, ["native"]);
    assert_eq!(reasons[0].0, "tools/control.sock");
    // A file that became a directory.
    assert_eq!(
        lanes(|root| {
            fs::remove_file(root.join("tools/data.txt")).unwrap();
            write(root, "tools/data.txt/inner", b"x\n");
        })
        .0,
        ["native"]
    );
    // The app root itself changing kind.
    let app = routed(
        |root| {
            fs::remove_dir_all(root.join("app")).unwrap();
            write(root, "app", b"not a directory\n");
        },
        |_| {},
    );
    assert!(app.lanes.native);
    assert!(app.reasons.iter().any(|reason| reason.path == "app"
        && reason.change == "kind"
        && reason.rules.contains(&"app root changed kind".to_owned())));
}

#[test]
fn skipped_directories_route_by_whether_the_build_walks_them() {
    // A fresh extension directory is a new entry where the build walks.
    let fresh = routed(
        |_| {},
        |base| fs::remove_dir_all(base.join("app/.chrome-extension")).unwrap(),
    );
    assert_eq!(fresh.lanes.names(), ALL);
    assert!(fresh.reasons.iter().all(|reason| {
        reason
            .rules
            .contains(&"entry added or removed where the build walks".to_owned())
    }));
    // Inside a skipped root directory present in both trees, nothing native.
    assert_eq!(
        lanes(|root| write(root, "app/.clanker/scenes/home.json", b"{ }\n")).0,
        NONE
    );
    assert_eq!(
        lanes(|root| write(root, "app/.clanker/scenes/nested/new.json", b"{}\n")).0,
        NONE
    );
    // Design data is skipped only at the app root: below ui/ it is a captured
    // resource, elsewhere the build refuses it.
    assert_eq!(
        lanes(|root| write(root, "app/ui/.clanker/x.json", b"{}\n")).0,
        ["native"]
    );
    let (selected, reasons) = lanes(|root| write(root, "app/domain/.clanker/x.json", b"{}\n"));
    assert_eq!(selected, ["native"]);
    assert!(reasons[0].1.contains(&"native".to_owned()));
}

#[test]
fn reasons_are_bounded_but_every_changed_path_counts() {
    let many = routed(
        |root| {
            for index in 0..route::REASON_LIMIT + 44 {
                write(root, &format!("tools/notes/{index:04}.txt"), b"x\n");
            }
        },
        |_| {},
    );
    assert_eq!(many.changed, route::REASON_LIMIT + 44);
    assert_eq!(many.reasons.len(), route::REASON_LIMIT);
    assert_eq!(many.lanes, Lanes::default());
}

#[test]
fn source_inputs_match_publish_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    write(root, "b.roc", b"b\n");
    write(root, "a/z.roc", b"z\n");
    write(root, "a.b", b"ab\n");
    write(root, "\u{e9}.md", b"e\n");
    // Python's sorted(Path) orders by path parts: a/z.roc before a.b.
    let names: Vec<String> = files(root).unwrap().iter().map(File::name).collect();
    assert_eq!(names, ["a/z.roc", "a.b", "b.roc", "\u{e9}.md"]);
    // publish_artifact.source_identity over the same tree.
    assert_eq!(
        source_inputs(root).unwrap(),
        "sha256:a6326087a32a51ccf2f1ccfe8460281149a7c59bf399f894ffd16e50190fc2bd"
    );
    std::os::unix::fs::symlink("b.roc", root.join("c.roc")).unwrap();
    assert!(source_inputs(root).is_err());
}

#[test]
fn a_source_tree_and_its_forge_archive_have_one_source_identity() -> Result<()> {
    use crate::instance_source::tests::{comment, tarball};
    let files: [(&str, &[u8]); 5] = [
        ("App.roc", b"App :: [].{}\n"),
        ("b.roc", b"b\n"),
        ("a/z.roc", b"z\n"),
        ("a.b", b"ab\n"),
        ("\u{e9}.md", b"e\n"),
    ];
    let directory = tempfile::tempdir()?;
    let mut entries: Vec<(Vec<u8>, u8, Vec<u8>)> = vec![
        (b"repo/".to_vec(), b'5', vec![]),
        (b"repo/.ci/".to_vec(), b'5', vec![]),
        (b"repo/.ci/roc.json".to_vec(), b'0', b"{}".to_vec()),
        (b"repo/README.md".to_vec(), b'0', b"# App\n".to_vec()),
        (b"repo/app/".to_vec(), b'5', vec![]),
        (b"repo/app/a/".to_vec(), b'5', vec![]),
    ];
    write(directory.path(), "README.md", b"# App\n");
    for (name, bytes) in files {
        write(directory.path(), &format!("app/{name}"), bytes);
        entries.push((
            format!("repo/app/{name}").into_bytes(),
            b'0',
            bytes.to_vec(),
        ));
    }
    let entries: Vec<(&[u8], u8, &[u8])> = entries
        .iter()
        .map(|(name, kind, data)| (name.as_slice(), *kind, data.as_slice()))
        .collect();
    let archive = tarball(&entries, &comment());
    let from_tree = source_inputs(&directory.path().join("app"))?;
    let from_archive = crate::instance_candidate::source_inputs(&archive, "app")?;
    // publish_artifact.source_identity over the same app directory.
    let oracle = "sha256:96dfab8bcd3fd7f3d02cc8cc29d020b9bcd1b543f036ce2658230e10e0c6bc4f";
    assert_eq!(
        (from_tree.as_str(), from_archive.as_str()),
        (oracle, oracle)
    );
    Ok(())
}

#[test]
fn pax_headers_match_tarfile() {
    let short = artifact::header("ab/c", 0o444, 3);
    assert_eq!(short.len(), 512);
    assert_eq!(&short[..4], b"ab/c");
    assert_eq!(&short[100..108], b"0000444\0");
    assert_eq!(&short[124..136], b"00000000003\0");
    assert_eq!(&short[257..265], b"ustar\x0000");
    assert_eq!(&short[329..345], &[0; 16]);
    let long = "x".repeat(101);
    let headers = artifact::header(&long, 0o555, 1);
    assert_eq!(headers.len(), 1536);
    assert_eq!(&headers[..14], b"././@PaxHeader");
    assert_eq!(headers[156], b'x');
    assert_eq!(&headers[512..520], b"111 path");
    assert_eq!(headers[1024 + 156], b'0');
}

const ID: &str = "abababababababababababababababababababababababababababababababab";

/// A selected artifact under `platform/artifacts/<ID>`, with `current.json`
/// naming it: a worker, a long and a non-ASCII name and Python's part order.
fn selected_artifact(platform: &Path) -> PathBuf {
    let artifact = platform.join("artifacts").join(ID);
    let worker: &[u8] = b"\x7fELF worker";
    let long = format!("web_resources/{}.js", "x".repeat(40));
    let files: [(&str, &[u8]); 6] = [
        ("worker", worker),
        ("verification.json", b"{}"),
        ("a/z.txt", b"z"),
        ("a.b", b"ab"),
        (&long, b"export {};\n"),
        ("assets/\u{e9}t\u{e9}.png", b"png"),
    ];
    for (name, bytes) in files {
        write(&artifact, name, bytes);
    }
    fs::set_permissions(artifact.join("worker"), fs::Permissions::from_mode(0o755)).unwrap();
    write(
        &artifact,
        "artifact.json",
        format!("{{\"worker_digest\": \"{}\"}}", day2::digest(worker)).as_bytes(),
    );
    write(
        platform,
        "artifacts/current.json",
        format!("{{\"artifact\":\"sha256:{ID}\"}}").as_bytes(),
    );
    artifact
}

#[test]
fn pack_writes_publish_artifacts_archive() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let artifact = selected_artifact(directory.path());
    let output = directory.path().join("out");
    fs::create_dir(&output)?;
    let archive = pack(&artifact, ID, &output)?;
    let bytes = fs::read(output.join("app.tar.gz"))?;
    assert_eq!(archive, day2::sdk_release::BlobIdentity::of(&bytes));
    // The gzip header publish_artifact.py wrote: FNAME app.tar, mtime 0, best.
    assert_eq!(&bytes[..10], b"\x1f\x8b\x08\x08\x00\x00\x00\x00\x02\xff");
    assert_eq!(&bytes[10..18], b"app.tar\0");
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice()).read_to_end(&mut tar)?;
    // The uncompressed bytes publish_artifact.pack wrote for this artifact.
    assert_eq!(
        day2::digest(&tar),
        "sha256:976dcfeb1ed586b16c4712aea6a9c53201a2cbcdc7764bd5d375c4f64caf3976"
    );
    let mut archive = tar::Archive::new(tar.as_slice());
    let entries: Vec<(String, u32, u64)> = archive
        .entries()?
        .map(|entry| {
            let entry = entry?;
            Ok((
                entry.path()?.to_string_lossy().into_owned(),
                entry.header().mode()?,
                entry.header().mtime()?,
            ))
        })
        .collect::<Result<_>>()?;
    let long = format!("web_resources/{}.js", "x".repeat(40));
    let expected: Vec<(String, u32, u64)> = [
        ("a/z.txt", 0o444),
        ("a.b", 0o444),
        ("artifact.json", 0o444),
        ("assets/\u{e9}t\u{e9}.png", 0o444),
        ("verification.json", 0o444),
        (long.as_str(), 0o444),
        ("worker", 0o555),
    ]
    .into_iter()
    .map(|(name, mode)| (format!("{ID}/{name}"), mode, 0))
    .collect();
    assert_eq!(entries, expected);
    Ok(())
}

const GOLDEN_REPORT: &str = include_str!("../../../../cli/fixtures/ci-check-report.json");

#[test]
fn the_report_shape_is_pinned_for_the_cli() -> Result<()> {
    let names = |lanes: &[&str]| lanes.iter().map(|lane| (*lane).to_owned()).collect();
    let inputs = format!("sha256:{}", "ab".repeat(32));
    let report = Report {
        format: 1,
        lanes: names(&ALL),
        base: true,
        changed: 3,
        reasons: vec![
            Reason {
                path: "README.md".into(),
                change: "modified".into(),
                lanes: vec![],
                rules: vec![],
            },
            Reason {
                path: "app/.chrome-extension/src/background.js".into(),
                change: "modified".into(),
                lanes: names(&["extension", "javascript"]),
                rules: vec!["extension source".into(), "JavaScript".into()],
            },
            Reason {
                path: "app/ui/app.js".into(),
                change: "modified".into(),
                lanes: names(&["native", "javascript"]),
                rules: vec!["build input".into(), "JavaScript".into()],
            },
        ],
        javascript_files: Some(3),
        roc_files: Some(12),
        extension_declared: Some(true),
        source_inputs: inputs.clone(),
        artifact: "written".into(),
        output: Some("/work/ci".into()),
        receipt: Some(Receipt {
            version: 1,
            source_inputs: inputs,
            artifact_id: "cd".repeat(32),
            sdk_distribution: day2::sdk_release::BlobIdentity {
                digest: format!("sha256:{}", "ef".repeat(32)),
                bytes: 1204,
            },
            verification: Verification {
                version: 1,
                seed: SEED,
                cases: 4,
            },
            archive: day2::sdk_release::BlobIdentity {
                digest: "sha256:a789e3fa1ffe742748bda51e387abc56427e3e1a35c1d220cf52be0d9a7f6195"
                    .into(),
                bytes: 2900,
            },
            examples: 12,
            generated: 40,
            lanes: names(&ALL),
        }),
        reuse: None,
    };
    assert_eq!(serde_json::to_string_pretty(&report)? + "\n", GOLDEN_REPORT);
    assert_eq!(serde_json::from_str::<Report>(GOLDEN_REPORT)?, report);
    let mut extra: Value = serde_json::from_str(GOLDEN_REPORT)?;
    extra["receipt"]["repository"] = json!("tools/links-app");
    assert!(serde_json::from_value::<Report>(extra).is_err());
    // A receipt always names its SDK.
    let mut unnamed: Value = serde_json::from_str(GOLDEN_REPORT)?;
    unnamed["receipt"]["sdk_distribution"] = Value::Null;
    assert!(serde_json::from_value::<Report>(unnamed).is_err());
    Ok(())
}

/// A session with `sdk` as the tooling's SDK identity.
fn session_with(
    head: &Path,
    base: Option<&Path>,
    work: &Path,
    sdk: Option<day2::sdk_release::BlobIdentity>,
) -> Result<Session> {
    session_reusing(head, base, work, sdk, None)
}

/// A session that names `reuse` as `ci reuse`'s directory.
fn session_reusing(
    head: &Path,
    base: Option<&Path>,
    work: &Path,
    sdk: Option<day2::sdk_release::BlobIdentity>,
    reuse: Option<&Path>,
) -> Result<Session> {
    let request = work.join("request.json");
    fs::write(
        &request,
        serde_json::to_vec(&Request {
            head: head.to_path_buf(),
            base: base.map(Path::to_path_buf),
            cases: 4,
            output: work.join("out"),
            reuse: reuse.map(Path::to_path_buf),
        })?,
    )?;
    Session::with_sdk(&request, &work.join("platform"), sdk)
}

fn session(head: &Path, base: Option<&Path>, work: &Path) -> Result<Session> {
    session_with(head, base, work, None)
}

#[test]
fn a_session_runs_only_its_lanes_in_order() -> Result<()> {
    let base = repository();
    let head = repository();
    write(head.path(), "tools/script.mjs", b"export const a = 1;\n");
    let work = tempfile::tempdir()?;
    let mut checked = session(head.path(), Some(base.path()), work.path())?;
    assert!(checked.step("javascript").is_err(), "route first");
    let mut checked = session(head.path(), Some(base.path()), work.path())?;
    assert_eq!(checked.step("route")?["javascript"], true);
    assert!(checked.step("route").is_err(), "once");
    assert!(checked.step("format").is_err(), "no native lane");
    assert!(checked.step("artifact").is_err(), "no native lane");
    assert!(
        checked.step("result").is_err(),
        "the JavaScript lane has not run"
    );
    // Files that parse go on to the SDK's pinned linter; without it the lane
    // fails closed, and keeps the tool's log the error names.
    let mut checked = session(head.path(), Some(base.path()), work.path())?;
    checked.step("route")?;
    let error = format!("{:#}", checked.step("javascript").unwrap_err());
    assert!(error.contains("start platform tool"), "{error}");
    assert!(!work.path().join("out").exists());
    assert_eq!(
        fs::read_dir(work.path().join("platform/artifacts/operations"))?.count(),
        1
    );
    // Syntax findings name their file, line and rule; a file that does not
    // parse is not linted.
    for path in [
        "tools/script.mjs",
        "app/ui/app.js",
        "app/.chrome-extension/src/background.js",
    ] {
        write(head.path(), path, b"export const = 1;\n");
    }
    let mut checked = session(head.path(), Some(base.path()), work.path())?;
    checked.step("route")?;
    let error = checked.step("javascript").unwrap_err().to_string();
    assert!(
        error.starts_with("3 JavaScript finding(s) in 3 file(s): ")
            && error.contains("tools/script.mjs:1: ")
            && error.contains(" (syntax)"),
        "{error}"
    );
    // Only a tested build of the head tree's app, with the fixed seed and the
    // request's cases.
    write(head.path(), "app/App.roc", b"App :: [].{ a = 1 }\n");
    let mut checked = session(head.path(), Some(base.path()), work.path())?;
    checked.step("route")?;
    let app = head.path().join("app");
    checked.building(&app, "42", 4, true)?;
    assert!(checked.building(&app, "42", 4, false).is_err());
    assert!(checked.building(&app, "43", 4, true).is_err());
    assert!(checked.building(&app, "42", 5, true).is_err());
    assert!(checked.building(base.path(), "42", 4, true).is_err());
    assert!(checked.step("artifact").is_err(), "build first");
    Ok(())
}

#[test]
fn minified_javascript_is_refused_as_unlintable() -> Result<()> {
    let head = repository();
    write(head.path(), "app/ui/vendor.min.js", b"var a=1;\n");
    write(head.path(), "tools/lib-min.mjs", b"export{};\n");
    let work = tempfile::tempdir()?;
    let mut checked = session(head.path(), None, work.path())?;
    checked.step("route")?;
    let error = checked.step("javascript").unwrap_err().to_string();
    assert!(
        error.starts_with("the platform lints only JavaScript source it can check")
            && error.ends_with(": app/ui/vendor.min.js, tools/lib-min.mjs"),
        "{error}"
    );
    // Nothing ran: the linter's directory was never made.
    assert!(!work.path().join("platform/artifacts/operations").exists());
    Ok(())
}

/// A session that built `head`'s app, for the artifact step.
fn built(
    head: &Path,
    base: Option<&Path>,
    work: &Path,
    sdk: Option<day2::sdk_release::BlobIdentity>,
) -> Result<Session> {
    let artifact = selected_artifact(&work.join("platform"));
    let mut checked = session_with(head, base, work, sdk)?;
    checked.step("route")?;
    let app = head.join("app");
    checked.building(&app, "42", 4, true)?;
    checked.built(day2::development::BuildReceipt {
        artifact: artifact.clone(),
        verification: day2::development::BuildVerification {
            artifact: format!("sha256:{ID}"),
            seed: "42".into(),
            examples: 0,
            generated: 1,
            checks: CHECKS.iter().map(|check| (*check).to_owned()).collect(),
            evidence: artifact.join("verification.json"),
        },
    });
    // The lanes the recipe ran before the artifact step.
    checked.javascript = Some(3);
    checked.format = Some(2);
    checked.extension_verified(&app, &json!({ "declared": false }))?;
    Ok(checked)
}

#[test]
fn only_a_complete_run_on_a_qualified_sdk_writes_an_artifact() -> Result<()> {
    let sdk = day2::sdk_release::BlobIdentity::of(b"distribution");
    // Every lane, a qualified SDK: the archive and the receipt.
    let head = repository();
    let work = tempfile::tempdir()?;
    let mut checked = built(head.path(), None, work.path(), Some(sdk.clone()))?;
    assert_eq!(checked.step("artifact")?["artifact"], "written");
    let report: Report = serde_json::from_value(checked.step("result")?)?;
    let receipt = report.receipt.clone().context("receipt")?;
    assert_eq!(
        (report.artifact.as_str(), report.output.as_deref()),
        ("written", Some(work.path().join("out").as_path()))
    );
    assert_eq!(receipt.sdk_distribution, sdk);
    assert_eq!(receipt.lanes, ALL);
    assert_eq!(
        serde_json::from_slice::<Receipt>(&fs::read(work.path().join("out/receipt.json"))?)?,
        receipt
    );
    assert!(work.path().join("out/app.tar.gz").is_file());
    // Without an SDK identity every check runs, but nothing is written.
    let work = tempfile::tempdir()?;
    let mut checked = built(head.path(), None, work.path(), None)?;
    assert_eq!(checked.step("artifact")?["artifact"], "no_sdk_identity");
    let report: Report = serde_json::from_value(checked.step("result")?)?;
    assert_eq!(
        (report.artifact.as_str(), &report.output, &report.receipt),
        ("no_sdk_identity", &None, &None)
    );
    assert!(!work.path().join("out").exists());
    // A routed run that skipped a lane is only a gate.
    let base = repository();
    write(
        head.path(),
        "app/domain/Rules.roc",
        b"Rules :: [].{ a = 1 }\n",
    );
    let work = tempfile::tempdir()?;
    let mut checked = built(head.path(), Some(base.path()), work.path(), Some(sdk))?;
    assert_eq!(checked.step("artifact")?["artifact"], "routed");
    let report: Report = serde_json::from_value(checked.step("result")?)?;
    assert_eq!(
        (
            report.artifact.as_str(),
            report.lanes.as_slice(),
            &report.receipt
        ),
        ("routed", ["native".to_owned()].as_slice(), &None)
    );
    assert!(!work.path().join("out").exists());
    Ok(())
}

#[test]
fn a_request_names_real_trees_an_app_and_a_new_output() -> Result<()> {
    let head = repository();
    let work = tempfile::tempdir()?;
    assert!(session(head.path(), None, work.path()).is_ok());
    assert!(session(&work.path().join("missing"), None, work.path()).is_err());
    fs::create_dir(work.path().join("out"))?;
    assert!(
        session(head.path(), None, work.path()).is_err(),
        "output exists"
    );
    fs::remove_dir(work.path().join("out"))?;
    fs::remove_file(head.path().join("app/App.roc"))?;
    assert!(
        session(head.path(), None, work.path()).is_err(),
        "no App.roc"
    );
    Ok(())
}

#[test]
fn a_bounded_generated_mount_gets_the_tooling_images_reviewed_abi() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let platform = directory.path().join("platform");
    let seed = directory.path().join("roc_platform_abi.rs");
    let target = platform.join("crates/worker/generated/roc_platform_abi.rs");
    // No seed: the build could not check its glue, so the check refuses.
    assert!(seed_abi(&platform, &seed).is_err());
    fs::write(&seed, b"// reviewed ABI\n")?;
    seed_abi(&platform, &seed)?;
    assert_eq!(fs::read(&target)?, b"// reviewed ABI\n");
    // An ABI already in place is never replaced.
    fs::write(&seed, b"// another ABI\n")?;
    seed_abi(&platform, &seed)?;
    assert_eq!(fs::read(&target)?, b"// reviewed ABI\n");
    Ok(())
}

/// `ci reuse`'s directory for a hit: its record and the result an earlier
/// main run stored for `head`'s app, checked with `cases` on `sdk`.
fn reuse_hit(
    work: &Path,
    head: &Path,
    sdk: &day2::sdk_release::BlobIdentity,
    cases: u64,
) -> Result<(PathBuf, Receipt)> {
    use crate::ci_reuse::{Object, Record, Source};
    let directory = work.join("reuse");
    fs::create_dir(&directory)?;
    let archive = b"an earlier main run's archive".to_vec();
    let receipt = Receipt {
        version: 1,
        source_inputs: source_inputs(&head.join("app"))?,
        artifact_id: ID.into(),
        sdk_distribution: sdk.clone(),
        verification: Verification {
            version: 1,
            seed: SEED,
            cases,
        },
        archive: day2::sdk_release::BlobIdentity::of(&archive),
        examples: 3,
        generated: 6,
        lanes: ALL.map(str::to_owned).to_vec(),
    };
    fs::write(directory.join("app.tar.gz"), &archive)?;
    fs::write(directory.join("receipt.json"), receipt.bytes()?)?;
    let key = format!(
        "{}/{}-{cases}/40/1",
        "5d".repeat(32),
        &receipt.source_inputs["sha256:".len()..]
    );
    let object = |file: &str, generation: &str| Object {
        name: format!("{key}/{file}"),
        generation: generation.into(),
        time_created: "2026-11-25T18:15:00.250Z".into(),
    };
    let record = Record {
        format: 1,
        reused: true,
        reason: None,
        source: Some(Source {
            run: 40,
            attempt: 1,
            head: "1".repeat(40),
            workflow_commit: "3".repeat(40),
            started_at: "2026-11-25T18:00:00Z".into(),
            completed_at: "2026-11-25T18:20:00Z".into(),
            bucket: "exampleco-tools-links-ci".into(),
            receipt: object("receipt.json", "1700000000000002"),
            artifact: object("artifact.tar.gz", "1700000000000001"),
        }),
    };
    fs::write(
        directory.join("reuse.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    Ok((directory, receipt))
}

#[test]
fn a_reused_result_is_verified_again_and_written_as_a_built_one() -> Result<()> {
    let sdk = day2::sdk_release::BlobIdentity::of(b"distribution");
    let head = repository();
    let work = tempfile::tempdir()?;
    let (reuse, receipt) = reuse_hit(work.path(), head.path(), &sdk, 4)?;
    let mut checked = session_reusing(
        head.path(),
        None,
        work.path(),
        Some(sdk.clone()),
        Some(&reuse),
    )?;
    let route = checked.step("route")?;
    assert_eq!(
        (&route["reused"], &route["native"], &route["javascript"]),
        (&json!(true), &json!(true), &json!(true))
    );
    // The native build and its campaign do not run.
    let app = head.path().join("app");
    assert!(checked.building(&app, "42", 4, true).is_err());
    // The cheap lanes do; the recipe ran them before the artifact step.
    checked.javascript = Some(3);
    checked.format = Some(2);
    checked.extension_verified(&app, &json!({ "declared": false }))?;
    assert_eq!(checked.step("artifact")?["artifact"], "reused");
    let report: Report = serde_json::from_value(checked.step("result")?)?;
    assert_eq!(
        (report.artifact.as_str(), report.output.as_deref()),
        ("reused", Some(work.path().join("out").as_path()))
    );
    assert_eq!(report.receipt.as_ref(), Some(&receipt));
    assert_eq!(report.lanes, ALL);
    assert!(report.reuse.as_ref().is_some_and(|record| record.reused));
    // OUTPUT is exactly what a built artifact's would be: the archive and the
    // receipt, byte for byte, and nothing else.
    assert_eq!(
        fs::read(work.path().join("out/app.tar.gz"))?,
        fs::read(reuse.join("app.tar.gz"))?
    );
    assert_eq!(
        fs::read(work.path().join("out/receipt.json"))?,
        fs::read(reuse.join("receipt.json"))?
    );
    assert_eq!(fs::read_dir(work.path().join("out"))?.count(), 2);
    Ok(())
}

#[test]
fn a_reused_result_that_fails_verification_is_a_refusal_not_a_rebuild() -> Result<()> {
    let sdk = day2::sdk_release::BlobIdentity::of(b"distribution");
    let head = repository();
    let refused = |change: &dyn Fn(&Path, &Receipt),
                   sdk: Option<day2::sdk_release::BlobIdentity>| {
        let work = tempfile::tempdir().unwrap();
        let (reuse, receipt) = reuse_hit(
            work.path(),
            head.path(),
            &day2::sdk_release::BlobIdentity::of(b"distribution"),
            4,
        )
        .unwrap();
        change(&reuse, &receipt);
        let error = session_reusing(head.path(), None, work.path(), sdk, Some(&reuse))
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        assert!(!work.path().join("out").exists());
        error
    };
    let rewrite = |reuse: &Path, receipt: &Receipt| {
        fs::write(reuse.join("receipt.json"), receipt.bytes().unwrap()).unwrap();
    };
    // The control: unchanged, it is accepted.
    assert_eq!(refused(&|_, _| {}, Some(sdk.clone())), "");
    for (change, expected) in [
        (
            Box::new(|reuse: &Path, receipt: &Receipt| {
                let mut receipt = receipt.clone();
                receipt.source_inputs = format!("sha256:{}", "ab".repeat(32));
                rewrite(reuse, &receipt);
            }) as Box<dyn Fn(&Path, &Receipt)>,
            "other source inputs",
        ),
        (
            Box::new(|reuse: &Path, receipt: &Receipt| {
                let mut receipt = receipt.clone();
                receipt.verification.cases = 6;
                rewrite(reuse, &receipt);
            }),
            "another case count",
        ),
        (
            Box::new(|reuse: &Path, receipt: &Receipt| {
                let mut receipt = receipt.clone();
                receipt.verification.seed = 43;
                rewrite(reuse, &receipt);
            }),
            "invalid ci check receipt",
        ),
        (
            Box::new(|reuse: &Path, receipt: &Receipt| {
                let mut receipt = receipt.clone();
                receipt.sdk_distribution = day2::sdk_release::BlobIdentity::of(b"another");
                rewrite(reuse, &receipt);
            }),
            "another SDK's tooling distribution",
        ),
        (
            Box::new(|reuse: &Path, receipt: &Receipt| {
                let mut receipt = receipt.clone();
                receipt.lanes.pop();
                rewrite(reuse, &receipt);
            }),
            "invalid ci check receipt",
        ),
        (
            Box::new(|reuse: &Path, _: &Receipt| {
                fs::write(reuse.join("app.tar.gz"), b"other bytes").unwrap();
            }),
            "not the archive its receipt names",
        ),
        (
            Box::new(|reuse: &Path, receipt: &Receipt| {
                fs::write(
                    reuse.join("receipt.json"),
                    serde_json::to_vec_pretty(receipt).unwrap(),
                )
                .unwrap();
            }),
            "not as ci check writes one",
        ),
        (
            Box::new(|reuse: &Path, _: &Receipt| {
                fs::write(reuse.join("extra"), b"x").unwrap();
            }),
            "must hold exactly",
        ),
        (
            Box::new(|reuse: &Path, _: &Receipt| {
                fs::remove_file(reuse.join("app.tar.gz")).unwrap();
            }),
            "must hold exactly",
        ),
        (
            Box::new(|reuse: &Path, _: &Receipt| {
                let path = reuse.join("reuse.json");
                let text = fs::read_to_string(&path)
                    .unwrap()
                    .replace("-4/40/1/", "-6/40/1/");
                fs::write(path, text).unwrap();
            }),
            "objects of another key",
        ),
    ] {
        let error = refused(&*change, Some(sdk.clone()));
        assert!(
            error.starts_with("the reused result fails verification") && error.contains(expected),
            "{expected}: {error}"
        );
    }
    // Only the SDK's precompiled tooling, whose identity the receipt names,
    // verifies a reused result.
    assert!(refused(&|_, _| {}, None).contains("no SDK identity"));
    // A pull request routes against its base and never reuses.
    let work = tempfile::tempdir()?;
    let (reuse, _) = reuse_hit(work.path(), head.path(), &sdk, 4)?;
    let base = repository();
    let error = session_reusing(
        head.path(),
        Some(base.path()),
        work.path(),
        Some(sdk),
        Some(&reuse),
    )
    .err()
    .context("a routed run with a reuse directory")?;
    assert!(error.to_string().contains("only a push run"), "{error:#}");
    Ok(())
}

#[test]
fn a_reuse_miss_builds_as_always_and_reports_why() -> Result<()> {
    let sdk = day2::sdk_release::BlobIdentity::of(b"distribution");
    let head = repository();
    let work = tempfile::tempdir()?;
    let reuse = work.path().join("reuse");
    fs::create_dir(&reuse)?;
    let record = crate::ci_reuse::Record {
        format: 1,
        reused: false,
        reason: Some(crate::ci_reuse::ABSENT.into()),
        source: None,
    };
    fs::write(reuse.join("reuse.json"), serde_json::to_vec(&record)?)?;
    let artifact = selected_artifact(&work.path().join("platform"));
    let mut checked = session_reusing(
        head.path(),
        None,
        work.path(),
        Some(sdk.clone()),
        Some(&reuse),
    )?;
    assert_eq!(checked.step("route")?["reused"], false);
    let app = head.path().join("app");
    checked.building(&app, "42", 4, true)?;
    checked.built(day2::development::BuildReceipt {
        artifact: artifact.clone(),
        verification: day2::development::BuildVerification {
            artifact: format!("sha256:{ID}"),
            seed: "42".into(),
            examples: 0,
            generated: 1,
            checks: CHECKS.iter().map(|check| (*check).to_owned()).collect(),
            evidence: artifact.join("verification.json"),
        },
    });
    checked.javascript = Some(3);
    checked.format = Some(2);
    checked.extension_verified(&app, &json!({ "declared": false }))?;
    assert_eq!(checked.step("artifact")?["artifact"], "written");
    let report: Report = serde_json::from_value(checked.step("result")?)?;
    assert_eq!(report.artifact, "written");
    assert_eq!(report.reuse, Some(record));
    // A miss record beside a result is not a miss.
    let work = tempfile::tempdir()?;
    let reuse = work.path().join("reuse");
    fs::create_dir(&reuse)?;
    fs::write(
        reuse.join("reuse.json"),
        serde_json::to_vec(&crate::ci_reuse::Record {
            format: 1,
            reused: false,
            reason: Some("absent".into()),
            source: None,
        })?,
    )?;
    fs::write(reuse.join("app.tar.gz"), b"x")?;
    assert!(session_reusing(head.path(), None, work.path(), Some(sdk), Some(&reuse)).is_err());
    Ok(())
}

/// A session for `request` on `sdk`'s tooling, routed, with the lanes the
/// recipe runs before the artifact step: for a reused result, which the
/// session verified when it started.
pub(crate) fn reusing(
    request: &Path,
    platform: &Path,
    sdk: day2::sdk_release::BlobIdentity,
) -> Result<Session> {
    let mut checked = Session::with_sdk(request, platform, Some(sdk))?;
    ensure!(checked.step("route")?["reused"] == true, "nothing reused");
    checked.javascript = Some(1);
    checked.format = Some(1);
    let app = checked.app();
    checked.extension_verified(&app, &json!({ "declared": false }))?;
    Ok(checked)
}
