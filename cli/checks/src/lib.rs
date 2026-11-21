//! Process-level checks for the Roc binary. There is no Rust CLI implementation.
#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .canonicalize()
            .expect("current CLI source directory")
    }

    fn compiler() -> Command {
        let cli = root();
        // Admission rehashes both archives and complete trees against source
        // pins; a missing/poisoned input cannot consult a warm default cache.
        let admitted = Command::new(cli.join("xtask"))
            .arg("admit-roc-packages")
            .current_dir(cli.parent().unwrap())
            .status()
            .unwrap();
        assert!(
            admitted.success(),
            "run xtask bootstrap and cli for current offline package inputs"
        );
        let pins: Value =
            serde_json::from_str(include_str!("../../../build/bazel/roc-packages.json")).unwrap();
        let mut command = Command::new(cli.join("../../.toolchains/roc"));
        for p in pins["packages"].as_array().unwrap() {
            let name = p["name"].as_str().unwrap();
            let version = p["version"].as_str().unwrap();
            let archive = p["archive"].as_str().unwrap();
            let hash = archive.strip_suffix(".tar.zst").unwrap();
            command
                .arg("--replace-dep")
                .arg(format!(
                    "https://github.com/roc-lang/{name}/releases/download/{version}/{archive}"
                ))
                .arg(cli.join(".cache/roc-packages").join(hash).join("main.roc"));
        }
        command
    }

    fn binary() -> &'static PathBuf {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        BINARY.get_or_init(|| {
            let root = root();
            // Use the gate installation with its source-bound distribution receipt.
            // CLI checks do not compile another Rust host.
            assert!(
                root.join("day2-host").is_file(),
                "run xtask cli before CLI checks"
            );
            for name in ["day2-workflows", "day2-workflows.json"] {
                let temporary = tempfile::NamedTempFile::new_in(&root).unwrap();
                fs::copy(root.join("../build-out/bin").join(name), temporary.path())
                    .expect("run xtask cli before CLI checks");
                temporary.persist(root.join(name)).unwrap();
            }
            for args in [
                vec!["check", "main.roc"],
                vec!["test", "main.roc"],
                vec!["build", "main.roc", "--output=day2"],
            ] {
                let output = compiler()
                    .args(args)
                    .current_dir(&root)
                    .env("ROC_CACHE_DIR", root.join(".cache"))
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            root.join("day2")
        })
    }

    #[test]
    fn compiler_checks_use_local_packages_with_network_unavailable_and_poisoned_default_cache() {
        let scratch = Scratch::new();
        let pins: Value =
            serde_json::from_str(include_str!("../../../build/bazel/roc-packages.json")).unwrap();
        for p in pins["packages"].as_array().unwrap() {
            let hash = p["archive"]
                .as_str()
                .unwrap()
                .strip_suffix(".tar.zst")
                .unwrap();
            let cached = scratch.0.join("roc/packages").join(hash);
            fs::create_dir_all(&cached).unwrap();
            fs::write(
                cached.join("main.roc"),
                "intentionally invalid package contents",
            )
            .unwrap();
        }
        let output = compiler()
            .args(["check", "--no-cache", "main.roc"])
            .current_dir(root())
            .env("ROC_CACHE_DIR", &scratch.0)
            .env("XDG_CACHE_HOME", &scratch.0)
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("https_proxy", "http://127.0.0.1:1")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "offline current-source compiler check failed: code {:?}, stderr bytes {}",
            output.status.code(),
            output.stderr.len()
        );
    }

    fn run(args: &[&str], instance: Option<&Path>) -> Output {
        run_with(args, instance, &[])
    }

    fn run_with(args: &[&str], instance: Option<&Path>, env: &[(&str, &Path)]) -> Output {
        let mut command = Command::new(binary());
        command
            .args(args)
            .envs(env.iter().copied())
            .env_remove("DAY2_INSTANCE")
            .stdin(Stdio::null());
        if let Some(path) = instance {
            command.env("DAY2_INSTANCE", path);
        }
        // File-backed captures avoid pipe deadlocks and bound each CLI invocation.
        let capture = Scratch::new();
        let stdout = capture.0.join("stdout");
        let stderr = capture.0.join("stderr");
        command
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap());
        let mut child = command.spawn().unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("CLI failed to finish within 5 seconds: {args:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    fn envelope(output: &Output, code: i32) -> Value {
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value =
            serde_json::from_slice(&output.stdout).expect("stdout must be exactly one JSON value");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["exit_code"], code);
        assert_eq!(value["ok"], code == 0);
        assert_eq!(value["error"].is_null(), code == 0);
        if code != 0 {
            assert_eq!(value["error"]["exit_code"], code);
            assert_eq!(value["error"]["retryable"], false);
            assert!(value["result"].is_null() && value["context"].is_null());
        } else if value["command"] == "app.describe" {
            let operations = value["result"]["operations"].as_array().unwrap();
            assert_eq!(value["result"]["operation_count"], operations.len());
            assert!(
                operations.len() as u64 <= value["result"]["total_operations"].as_u64().unwrap()
            );
            assert!(!operations.is_empty());
            assert_eq!(value["context"]["catalog_validation"], "checked");
            for operation in operations {
                assert!(matches!(
                    (operation["kind"].as_str(), operation["effect"].as_str()),
                    (Some("query"), Some("read")) | (Some("command"), Some("write"))
                ));
            }
        }
        value
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "day2-cli-{}-{stamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn instance(&self, artifact: &Value) -> PathBuf {
            fs::create_dir(self.0.join("artifact")).unwrap();
            fs::write(
                self.0.join("artifact/artifact.json"),
                serde_json::to_vec(artifact).unwrap(),
            )
            .unwrap();
            let path = self
                .0
                .join("instance with ' quotes $(echo injected) `echo injected` [glob].json");
            fs::write(&path, serde_json::to_vec(&json!({"installation":"testco", "environment":"sandbox", "apps":{"links":{"artifact":"artifact", "readers":[], "writers":[]}}})).unwrap()).unwrap();
            path
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn fixture() -> Value {
        serde_json::from_slice(&fs::read(root().join("fixtures/links-artifact.json")).unwrap())
            .unwrap()
    }

    #[test]
    fn reports_discovery_accepts_current_contract_and_hides_internal_commands() {
        let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
            .expect("run xtask verify or set DAY2_TEST_REPORTS_ARTIFACT");
        let scratch = Scratch::new();
        let path = scratch.0.join("reports.json");
        fs::write(&path, serde_json::to_vec(&json!({"installation":"testco","environment":"sandbox","apps":{"reports":{"artifact":PathBuf::from(artifact),"readers":[],"writers":[]}}})).unwrap()).unwrap();
        let described = envelope(
            &run(&["app", "describe", "reports", "--agent"], Some(&path)),
            0,
        );
        assert_eq!(described["result"]["operation_count"], 4);
        let operations = described["result"]["operations"].as_array().unwrap();
        assert!(operations.iter().all(|operation| matches!(
            operation["name"].as_str().unwrap(),
            "reports.submit" | "reports.revise" | "reports.list" | "reports.detail"
        )));
        assert!(
            operations
                .iter()
                .find(|operation| operation["name"] == "reports.list")
                .unwrap()["output_type"]
                .as_str()
                .unwrap()
                .starts_with("CollectionPage(")
        );
        assert!(
            operations
                .iter()
                .find(|operation| operation["name"] == "reports.submit")
                .unwrap()["output_type"]
                .as_str()
                .unwrap()
                .contains("version : RowVersion")
        );
    }

    #[test]
    fn managed_ui_lock_command_preserves_exact_app_pins() {
        let scratch = Scratch::new();
        let source = scratch.0.canonicalize().unwrap().join("app");
        fs::create_dir(&source).unwrap();
        let generate = || {
            Command::new(binary())
                .args(["platform", "ui-lock"])
                .arg(&source)
                .output()
                .unwrap()
        };
        let first = generate();
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let path = source.join("ui/ui.lock.json");
        let authored = fs::read(&path).unwrap();
        let lock: Value = serde_json::from_slice(&authored).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&first.stdout).unwrap(),
            lock
        );
        assert_eq!(lock["schemaVersion"], 2);
        assert!(lock["package"].get("path").is_none());
        assert_eq!(lock["package"]["version"], "0.8.2");
        assert_eq!(
            lock["package"]["digest"],
            "sha256:e91113e53ad41b66c9a4376c1cee756b4a76876bc864bc6ee5fc04127661b6b1"
        );
        assert_eq!(lock["package"]["inputs"].as_array().unwrap().len(), 461);
        assert!(generate().status.success());
        assert_eq!(fs::read(&path).unwrap(), authored);
        let mut changed = lock;
        changed["package"]["version"] = json!("9.9.9");
        let changed = serde_json::to_vec(&changed).unwrap();
        fs::write(&path, &changed).unwrap();
        assert!(!generate().status.success());
        assert_eq!(fs::read(&path).unwrap(), changed);
    }

    #[test]
    fn roc_infrastructure_description_produces_a_real_pinned_opentofu_plan() {
        let configuration = std::env::var_os("DAY2_TEST_TOFU_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| root().join("../.cache/tofu.json"));
        let scratch = Scratch::new();
        let output = scratch.0.join("infra");
        let result = Command::new(binary())
            .args(["platform", "infra", "plan"])
            .arg(configuration)
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let receipt: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(receipt["applied"], false);
        let plan: Value =
            serde_json::from_slice(&fs::read(output.join("show.log")).unwrap()).unwrap();
        let changes = plan["resource_changes"].as_array().unwrap();
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .all(|change| change["change"]["actions"] == json!(["create"]))
        );
        assert!(
            changes
                .iter()
                .any(|change| change["address"] == "terraform_data.app_reports")
        );
        assert!(output.join("plan.bin").is_file());
    }

    #[test]
    fn checked_types_cannot_be_forged_or_decoded_around_their_constructors() {
        // Build the real app first: a broken compiler/import cannot count as proof.
        let _ = binary();
        let scratch = Scratch::new();
        for entry in fs::read_dir(root()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "roc") {
                let target = scratch.0.join(path.file_name().unwrap());
                let source = fs::read_to_string(&path).unwrap();
                let source = if path.file_name().unwrap() == "main.roc" {
                    source.replace(
                        "../ops/main.roc",
                        root().join("../ops/main.roc").to_str().unwrap(),
                    )
                } else {
                    source
                };
                fs::write(target, source).unwrap();
            }
        }
        fs::copy(root().join("help.txt"), scratch.0.join("help.txt")).unwrap();
        fs::create_dir(scratch.0.join("fixtures")).unwrap();
        fs::copy(
            root().join("fixtures/links-artifact.json"),
            scratch.0.join("fixtures/links-artifact.json"),
        )
        .unwrap();
        fs::copy(
            root().join("fixtures/release-receipt.json"),
            scratch.0.join("fixtures/release-receipt.json"),
        )
        .unwrap();
        let check = || {
            compiler()
                .args(["check", "--no-cache", "main.roc"])
                .current_dir(&scratch.0)
                .env("ROC_CACHE_DIR", root().join(".cache"))
                .output()
                .unwrap()
        };
        let positive = check();
        assert!(
            positive.status.success(),
            "positive compile control failed: {}",
            String::from_utf8_lossy(&positive.stdout)
        );
        let original = fs::read_to_string(scratch.0.join("main.roc")).unwrap();
        let (header, _) = original
            .split_once("\nimport ")
            .expect("CLI imports must follow its complete app dependency header");
        let fixture_source =
            |snippet: &str| format!("{header}\nimport pf.Stdout\nimport pf.OsStr\n{snippet}\n");
        fs::write(
            scratch.0.join("main.roc"),
            fixture_source(
                "main! : List(OsStr.OsStr) => Try({}, [Exit(I32)])\nmain! = |_| Stdout.line!(\"checked\").map_err(|_| Exit(1))",
            ),
        )
        .unwrap();
        let positive = check();
        assert!(
            positive.status.success(),
            "fixture wrapper positive compile control failed: {}{}",
            String::from_utf8_lossy(&positive.stdout),
            String::from_utf8_lossy(&positive.stderr)
        );
        let mut fixtures: Vec<_> = fs::read_dir(root().join("checks/compile-fail"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        fixtures.sort();
        for path in fixtures {
            let snippet = fs::read_to_string(&path).unwrap();
            let expected = snippet
                .lines()
                .next()
                .unwrap()
                .strip_prefix("# Expected diagnostic: ")
                .unwrap();
            fs::write(scratch.0.join("main.roc"), fixture_source(&snippet)).unwrap();
            let output = check();
            let diagnostic = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.status.code(),
                Some(1),
                "expected type error for {path:?}: {diagnostic}"
            );
            assert!(
                diagnostic.contains(expected),
                "wrong failure for {path:?}; expected {expected:?}: {diagnostic}"
            );
        }
    }

    fn reject_artifact(artifact: &Value, label: &str) {
        let scratch = Scratch::new();
        let path = scratch.instance(artifact);
        // Broken, unselected declarations must still invalidate a filtered view.
        let output = run(
            &[
                "app",
                "describe",
                "links",
                "--operation=links.list",
                "--agent",
            ],
            Some(&path),
        );
        assert_eq!(
            output.status.code(),
            Some(5),
            "accepted {label}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            envelope(&output, 5)["error"]["code"],
            "invalid_catalog",
            "{label}"
        );
    }

    #[test]
    fn catalog_graph_and_contract_contradictions_fail_before_filtering() {
        let cases = [
            ("/operations", json!([])),
            ("/schema/models", json!({})),
            ("/schema/inputs", json!({})),
            ("/schema/models/links/fields", json!({})),
            ("/schema/models/links/fields/id", json!("integer")),
            ("/schema/models/links/fields/version", json!("integer")),
            ("/schema/models/links/fields/created_at", json!("integer")),
            ("/schema/models/links/roc_type", json!("lowercase.Type")),
            (
                "/schema/inputs/create/fields/title",
                json!({"text_domain":{"roc_type":"Title;Injected"}}),
            ),
            (
                "/schema/inputs/create/fields/title",
                json!({"text_domain":{"roc_type":"Title","extra":true}}),
            ),
            (
                "/schema/inputs/create/fields/title",
                json!({"text_domain":{"roc_type":"Title"},"reference":{"target":"links"}}),
            ),
            (
                "/schema/inputs/get_link/fields/link_id",
                json!({"reference":{"target":"missing"}}),
            ),
            (
                "/schema/inputs/get_link/fields/link_id",
                json!({"reference":{"target":"links","extra":true}}),
            ),
            (
                "/schema/inputs/unused",
                json!({"fields":{"bad":"unknown_codec"}}),
            ),
            ("/schema/inputs/create/fields/bad-name", json!("text")),
            ("/schema/inputs/create/fields/day2_secret", json!("text")),
            ("/schema/inputs/create/fields/sqlite_table", json!("text")),
            ("/schema/inputs/create_title", json!({"fields":{}})),
            (
                "/schema/models/snapshot",
                json!({"roc_type":"Models.Other","fields":{"title":"text"}}),
            ),
            (
                "/schema/models/all_links",
                json!({"roc_type":"Models.Other","fields":{"title":"text"}}),
            ),
            (
                "/schema/models/other",
                json!({"roc_type":"Models.Link","fields":{"title":"text"}}),
            ),
            (
                "/schema/models/links/fields/parent",
                json!({"reference":{"target":"links"}}),
            ),
            (
                "/schema/foreign_keys",
                json!([{"model":"links","field":"title","target":"links"}]),
            ),
            ("/operations/0/name", json!("Links.create")),
            ("/operations/0/name", json!("links..create")),
            ("/operations/0/name", json!("links.list")),
            ("/operations/0/kind", json!("transaction")),
            ("/operations/0/input_type", json!("missing")),
            ("/operations/0/output_type", json!("link")),
            ("/operations/2/output_type", json!("missing")),
            ("/operations/2/output_type", json!("bad-name")),
            ("/operations/2/extra", json!(true)),
            ("/outputs/link/shape", json!("text")),
            ("/outputs/link/shape", json!({"list":"string","record":{}})),
            ("/outputs/link/shape/record/id", json!("integer")),
            ("/outputs/link/roc_type", json!("I64")),
            ("/outputs/link/roc_type", json!("U32")),
            ("/outputs/link/roc_type", json!("RowVersion")),
            (
                "/schema/inputs/create/fields/title",
                json!({"unsigned":"U128"}),
            ),
            ("/outputs/link/roc_type", json!("Json.Injected")),
            ("/outputs/link/roc_type", json!("Example.Type\ninjected")),
            ("/outputs/link/roc_type", json!("List(Str")),
            ("/outputs/link/extra", json!(true)),
            ("/admission", json!("trusted")),
            ("/roc_version", json!("")),
            ("/schema_digest", json!("sha256:wrong")),
            ("/worker_digest", json!("unknown:identity")),
            ("/sources/extra", json!("sha256:invalid")),
            ("/pages", json!({})),
            ("/assets", json!([])),
            ("/unknown_top_level_field", json!(true)),
        ];
        for (pointer, value) in cases {
            let mut artifact = fixture();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            artifact.pointer_mut(parent).unwrap()[key] = value;
            reject_artifact(&artifact, pointer);
        }
        let mut artifact = fixture();
        artifact["schema"]["models"]["links"]
            .as_object_mut()
            .unwrap()
            .remove("roc_type");
        reject_artifact(&artifact, "missing nominal model type");
        let mut artifact = fixture();
        artifact["operations"] = json!(vec![artifact["operations"][0].clone(); 129]);
        reject_artifact(&artifact, "too many operations");
        let mut artifact = fixture();
        artifact["schema"]["inputs"]["create"]["fields"] = Value::Object(
            (0..33)
                .map(|i| (format!("field_{i}"), json!("text")))
                .collect(),
        );
        reject_artifact(&artifact, "too many input fields");
        let mut artifact = fixture();
        artifact["schema"]["models"]["links"]["fields"]["parent"] =
            json!({"reference":{"target":"links"}});
        let fk = json!({"model":"links","field":"parent","target":"links"});
        artifact["schema"]["foreign_keys"] = json!([fk.clone(), fk]);
        reject_artifact(&artifact, "duplicate foreign key");
        let mut artifact = fixture();
        artifact["format"] = json!(5);
        artifact["templates"] = json!({});
        reject_artifact(&artifact, "typed outputs before format 6");
    }

    #[test]
    fn instances_require_valid_identity_and_complete_bindings() {
        let invalid = [
            ("/installation", json!("")),
            ("/installation", json!("Company Name")),
            ("/environment", json!("PROD")),
            ("/apps", json!({})),
            ("/apps/links/artifact", json!("  ")),
            ("/apps/links/artifact", json!("artifact\ninjected")),
            ("/apps/links/readers", json!("everyone")),
            ("/apps/links/writers", json!([42])),
            ("/apps/links/auditors", json!([""])),
            ("/apps/links/authority", json!([])),
            ("/apps/links/unknown", json!(true)),
            ("/apps/unused", json!({"artifact":"artifact","readers":[]})),
            (
                "/apps/INVALID",
                json!({"artifact":"artifact","readers":[],"writers":[]}),
            ),
            ("/branding", json!(false)),
        ];
        for (pointer, replacement) in invalid {
            let scratch = Scratch::new();
            let path = scratch.instance(&fixture());
            let mut instance: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            instance.pointer_mut(parent).unwrap()[key] = replacement;
            fs::write(&path, serde_json::to_vec(&instance).unwrap()).unwrap();
            assert_eq!(
                envelope(
                    &run(&["app", "describe", "links", "--agent"], Some(&path)),
                    5
                )["error"]["code"],
                "invalid_instance",
                "{pointer}"
            );
        }
    }

    #[test]
    fn json_syntax_and_resource_limits_are_checked_before_decoding() {
        let raw = fs::read_to_string(root().join("fixtures/links-artifact.json")).unwrap();
        let mut cases = vec![
            raw.replacen("\"format\": 8", "\"format\": 8, \"format\": 8", 1),
            raw.replacen("\"format\": 8", "\"format\": 8, \"for\\u006dat\": 8", 1),
            raw.replacen(
                "\"fields\": {",
                "\"fields\": { \"expected_version\": \"integer\",",
                1,
            ),
            raw.replacen("\"bytes\": 259", "\"bytes\": 259, \"by\\u0074es\": 259", 1),
            raw.replacen("\"format\": 8", "\"format\": 08", 1),
            raw.replacen("\"format\": 8", "\"format\": 8.0", 1),
            raw.replacen("\"format\": 8", "\"format\": 8e0", 1),
            raw.replacen("\"format\": 8", "\"format\": -1", 1),
            raw.replacen("\"format\": 8", "\"format\": 18446744073709551616", 1),
            raw.replacen("\"local-spike-only\"", "\"\\ud800\"", 1),
            format!("{raw} {{}}"),
            format!("{{\"nest\":{}0{}}}", "[".repeat(33), "]".repeat(33)),
            format!("{{\"values\":[{}]}}", vec!["null"; 20_000].join(",")),
        ];
        cases.extend(
            [
                "[1,]",
                "{\"x\":1,}",
                "{\"x\":\"\\q\"}",
                "{\"x\":\"bad\nnewline\"}",
                "null",
            ]
            .map(str::to_owned),
        );
        for (index, text) in cases.into_iter().enumerate() {
            let scratch = Scratch::new();
            let path = scratch.instance(&fixture());
            fs::write(scratch.0.join("artifact/artifact.json"), &text).unwrap();
            let output = run(&["app", "describe", "links", "--agent"], Some(&path));
            assert_eq!(
                output.status.code(),
                Some(5),
                "JSON syntax case {index} was accepted"
            );
            let value = envelope(&output, 5);
            assert!(matches!(
                value["error"]["code"].as_str(),
                Some("invalid_artifact" | "invalid_catalog")
            ));
        }
        for text in [
            r#"{"installation":"testco","installation":"testco","environment":"sandbox","apps":{}}"#,
            r#"{"installation":"testco","environment":"sandbox","apps":{"links":{"artifact":"a","artifact":"b","readers":[],"writers":[]}}}"#,
        ] {
            let scratch = Scratch::new();
            let path = scratch.instance(&fixture());
            fs::write(&path, text).unwrap();
            assert_eq!(
                envelope(
                    &run(&["app", "describe", "links", "--agent"], Some(&path)),
                    5
                )["error"]["code"],
                "invalid_instance"
            );
        }
    }

    #[test]
    fn contradictory_flags_and_invalid_names_cannot_reach_loading() {
        let cases: &[(&[&str], &str)] = &[
            (&["--operation", "links.list"], "missing_command"),
            (&["--demo"], "missing_command"),
            (&["--help", "--version"], "conflicting_options"),
            (&["--version", "--help"], "conflicting_options"),
            (
                &["--version", "app", "describe", "links"],
                "conflicting_options",
            ),
            (
                &["app", "describe", "links", "--demo", "--help"],
                "conflicting_options",
            ),
            (
                &[
                    "app",
                    "describe",
                    "links",
                    "--operation=links.list",
                    "--operation=links.list",
                ],
                "duplicate_option",
            ),
            (
                &["app", "describe", "links", "--demo", "--demo"],
                "duplicate_option",
            ),
            (&["app", "describe", "Links", "--demo"], "invalid_app_name"),
            (&["app", "describe", "", "--demo"], "invalid_app_name"),
            (
                &["app", "describe", "day2_app", "--demo"],
                "invalid_app_name",
            ),
            (
                &["app", "describe", "sqlite_table", "--demo"],
                "invalid_app_name",
            ),
            (
                &["app", "describe", "links", "--operation=links..list"],
                "invalid_operation_name",
            ),
            (
                &["app", "describe", "links", "--operation=links.List"],
                "invalid_operation_name",
            ),
            (
                &["app", "describe", "links\nextra", "--demo"],
                "invalid_arguments",
            ),
            (
                &["app", "describe", "links", "--instance=  "],
                "invalid_arguments",
            ),
        ];
        for (args, expected) in cases {
            // Also demonstrate mode selection works when --agent follows the error.
            let mut args = args.to_vec();
            args.push("--agent");
            assert_eq!(envelope(&run(&args, None), 2)["error"]["code"], *expected);
        }
        for name in ["a".repeat(49), "x".repeat(16_385)] {
            assert_eq!(
                run(&["app", "describe", &name, "--demo", "--agent"], None)
                    .status
                    .code(),
                Some(2)
            );
        }
        let mut args = vec!["--agent"; 129];
        assert_eq!(
            envelope(&run(&args, None), 2)["error"]["code"],
            "invalid_arguments"
        );
        args.truncate(128);
        envelope(&run(&args, None), 0);
        assert_eq!(
            envelope(
                &run(
                    &["app", "describe", "links", "--agent"],
                    Some(Path::new("  "))
                ),
                3
            )["error"]["code"],
            "invalid_context"
        );
    }

    #[test]
    fn checked_output_shapes_are_bounded_and_primitive_contracts_agree() {
        for (shape, annotation) in [
            (json!({"record":{}}), "{  }"),
            (json!("string"), "Str"),
            (json!("integer"), "I64"),
            (json!({"unsigned":"U8"}), "U8"),
            (json!({"unsigned":"U16"}), "U16"),
            (json!({"unsigned":"U32"}), "U32"),
            (json!({"unsigned":"U64"}), "U64"),
            (json!("row_version"), "RowVersion"),
            (json!("cursor"), "Cursor"),
            (json!("page_size"), "PageSize"),
            (json!("boolean"), "Bool"),
            (json!({"list":"string"}), "List(Str)"),
        ] {
            let mut artifact = fixture();
            artifact["outputs"]["link"] = json!({"shape":shape, "roc_type":annotation});
            let scratch = Scratch::new();
            let path = scratch.instance(&artifact);
            let value = envelope(
                &run(
                    &[
                        "app",
                        "describe",
                        "links",
                        "--operation=links.detail",
                        "--agent",
                    ],
                    Some(&path),
                ),
                0,
            );
            assert_eq!(value["result"]["operations"][0]["output_type"], annotation);
        }
        let mut artifact = fixture();
        let fields: serde_json::Map<String, Value> = (0..65)
            .map(|i| (format!("field_{i}"), json!("string")))
            .collect();
        artifact["outputs"]["link"] =
            json!({"roc_type":"Contracts.TooWide", "shape":{"record":fields}});
        reject_artifact(&artifact, "output field budget");
        let mut shape = json!("string");
        for _ in 0..16 {
            shape = json!({"list":shape});
        }
        artifact["outputs"]["link"] = json!({"roc_type":"Contracts.TooDeep","shape":shape});
        reject_artifact(&artifact, "output nesting budget");
        let fields: serde_json::Map<String, Value> = (0..64)
            .map(|i| (format!("field_{i}"), json!("string")))
            .collect();
        let contracts: serde_json::Map<String, Value> = (0..17)
            .map(|i| {
                (
                    format!("output_{i}"),
                    json!({"roc_type":"Contracts.Wide","shape":{"record":fields}}),
                )
            })
            .collect();
        artifact["outputs"] = Value::Object(contracts);
        reject_artifact(&artifact, "output node budget");
    }

    #[test]
    fn every_input_kind_keeps_its_actual_wire_representation() {
        let mut artifact = fixture();
        artifact["schema"]["inputs"]["create"]["fields"] = json!({
            "number":"integer", "label":"text", "enabled":"boolean", "note":"optional_text",
            "record":{"reference":{"target":"links"}}, "title":{"text_domain":{"roc_type":"Title"}}, "url":"web_url",
            "revision":"row_version", "count":{"unsigned":"U32"}, "after":"cursor", "limit":"page_size"
        });
        let scratch = Scratch::new();
        let path = scratch.instance(&artifact);
        let value = envelope(
            &run(
                &[
                    "app",
                    "describe",
                    "links",
                    "--operation=links.create",
                    "--agent",
                ],
                Some(&path),
            ),
            0,
        );
        let operation = &value["result"]["operations"][0];
        let example: Value =
            serde_json::from_str(operation["example_input_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            example,
            json!({"number":1,"label":"example","enabled":false,"note":"None","record":"1","title":"example","url":"https://example.com/plan","revision":1,"count":0,"after":"0","limit":20})
        );
        let fields = operation["input_fields"].as_array().unwrap();
        assert!(
            fields
                .iter()
                .all(|field| field["required"] == true && field["nullable"] == false)
        );
        assert_eq!(
            fields.iter().find(|field| field["name"] == "note").unwrap()["roc_type"],
            "[None, Some(Str)]"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_context_and_special_files_are_rejected_without_blocking() {
        use std::{
            ffi::OsString,
            os::unix::{ffi::OsStringExt, fs::symlink, net::UnixListener},
        };
        let scratch = Scratch::new();
        let path = scratch.instance(&fixture());
        let link = scratch.0.join("symlink.json");
        symlink(&path, &link).unwrap();
        let socket = scratch.0.join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        for invalid in [&scratch.0, &link, &socket] {
            assert_eq!(
                envelope(
                    &run(&["app", "describe", "links", "--agent"], Some(invalid)),
                    3
                )["error"]["code"],
                "metadata_unreadable"
            );
        }
        let invalid = PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
        assert_eq!(
            envelope(
                &run(&["app", "describe", "links", "--agent"], Some(&invalid)),
                3
            )["error"]["code"],
            "invalid_context"
        );
        let output = Command::new(binary())
            .args(["app", "describe"])
            .arg(OsString::from_vec(vec![0xff]))
            .args(["--demo", "--agent"])
            .env_remove("DAY2_INSTANCE")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(envelope(&output, 2)["error"]["code"], "invalid_arguments");
        fs::write(&path, [0xff]).unwrap();
        assert_eq!(
            envelope(
                &run(&["app", "describe", "links", "--agent"], Some(&path)),
                3
            )["error"]["code"],
            "metadata_unreadable"
        );
    }

    #[test]
    fn demo_and_examples_match_real_contract_types() {
        let value = envelope(
            &run(&["app", "describe", "links", "--demo", "--agent"], None),
            0,
        );
        assert_eq!(value["context"]["source"], "demo");
        assert_eq!(value["result"]["operation_count"], 4);
        for operation in value["result"]["operations"].as_array().unwrap() {
            let example: Value =
                serde_json::from_str(operation["example_input_json"].as_str().unwrap()).unwrap();
            for field in operation["input_fields"].as_array().unwrap() {
                let input = &example[field["name"].as_str().unwrap()];
                assert!(match field["json_type"].as_str().unwrap() {
                    "string" => input.is_string() || field["nullable"] == true && input.is_null(),
                    "integer" => input.is_i64(),
                    "boolean" => input.is_boolean(),
                    _ => false,
                });
            }
        }
        for action in value["next_actions"].as_array().unwrap() {
            let argv: Vec<&str> = action["argv"]
                .as_array()
                .unwrap()
                .iter()
                .skip(1)
                .map(|arg| arg.as_str().unwrap())
                .collect();
            assert!(
                run(&argv, None).status.success(),
                "suggested action failed: {argv:?}"
            );
        }
    }

    #[test]
    fn help_and_version_need_no_context_even_in_agent_mode() {
        for args in [
            vec!["--agent"],
            vec!["app", "describe", "--help", "--agent"],
            vec!["--version", "--json"],
        ] {
            let value = envelope(&run(&args, None), 0);
            assert_eq!(
                value["result"]["implemented_commands"],
                json!([
                    "app.describe",
                    "instance.check",
                    "instance.render",
                    "instance.plan",
                    "instance.apply",
                    "instance.release.publish",
                    "instance.release.fetch"
                ])
            );
            assert_eq!(value["result"]["supports_authentication"], false);
            assert_eq!(value["result"]["supports_invocation"], false);
            assert_eq!(value["result"]["supports_remote_access"], false);
        }
    }

    #[test]
    fn filtering_is_exact_and_keeps_total_count() {
        let value = envelope(
            &run(
                &[
                    "--json",
                    "app",
                    "describe",
                    "links",
                    "--demo",
                    "--operation=links.list",
                ],
                None,
            ),
            0,
        );
        assert_eq!(value["result"]["operation_count"], 1);
        assert_eq!(value["result"]["total_operations"], 4);
        let operation = &value["result"]["operations"][0];
        assert_eq!(operation["name"], "links.list");
        assert_eq!(
            serde_json::from_str::<Value>(operation["example_input_json"].as_str().unwrap())
                .unwrap(),
            json!({"after":0,"limit":20})
        );
    }

    #[test]
    fn semantic_failures_keep_stdout_parseable() {
        let cases: &[(&[&str], i32, &str)] = &[
            (
                &["app", "describe", "links", "--bogus", "--agent"],
                2,
                "unknown_option",
            ),
            (&["app", "describe", "--agent"], 2, "missing_argument"),
            (
                &["app", "describe", "links", "--instance", "--agent"],
                2,
                "missing_option_value",
            ),
            (
                &[
                    "app",
                    "describe",
                    "links",
                    "--instance=x",
                    "--demo",
                    "--agent",
                ],
                2,
                "conflicting_options",
            ),
            (
                &[
                    "app",
                    "describe",
                    "links",
                    "--instance=x",
                    "--instance=y",
                    "--agent",
                ],
                2,
                "duplicate_option",
            ),
            (
                &["app", "describe", "links", "--agent"],
                3,
                "context_required",
            ),
            (
                &[
                    "app",
                    "describe",
                    "links",
                    "--instance=/does/not/exist",
                    "--agent",
                ],
                3,
                "metadata_unreadable",
            ),
            (
                &["app", "describe", "crm", "--demo", "--agent"],
                4,
                "app_not_found",
            ),
            (
                &[
                    "app",
                    "describe",
                    "links",
                    "--demo",
                    "--operation=links.lst",
                    "--agent",
                ],
                4,
                "operation_not_found",
            ),
        ];
        for (args, code, error) in cases {
            let value = envelope(&run(args, None), *code);
            assert_eq!(value["error"]["code"], *error);
            assert!(!value["next_actions"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn human_output_is_readable_when_piped_and_errors_use_stderr() {
        let success = run(&["app", "describe", "links", "--demo"], None);
        let text = String::from_utf8(success.stdout).unwrap();
        assert!(success.status.success() && success.stderr.is_empty());
        for content in [
            "DEMO / bundled example",
            "READ",
            "WRITE",
            "Example input",
            "NEXT",
        ] {
            assert!(text.contains(content));
        }
        assert!(!text.contains('\x1b'));
        let failure = run(&["app", "describe", "links"], None);
        assert_eq!(failure.status.code(), Some(3));
        assert!(failure.stdout.is_empty());
        assert!(
            String::from_utf8(failure.stderr)
                .unwrap()
                .contains("--instance")
        );
    }

    #[test]
    fn local_metadata_resolves_relative_paths_and_is_read_only() {
        let scratch = Scratch::new();
        let path = scratch.instance(&fixture());
        let before = fs::read(&path).unwrap();
        let value = envelope(
            &run(&["app", "describe", "links", "--agent"], Some(&path)),
            0,
        );
        assert_eq!(value["context"]["source"], "local_instance");
        assert_eq!(value["context"]["installation"], "testco");
        assert_eq!(value["context"]["permissions"], "not_evaluated");
        assert_eq!(value["context"]["artifact_integrity"], "not_verified");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!scratch.0.join(".state").exists());
        for action in value["next_actions"].as_array().unwrap() {
            let argv: Vec<&str> = action["argv"]
                .as_array()
                .unwrap()
                .iter()
                .skip(1)
                .map(|arg| arg.as_str().unwrap())
                .collect();
            assert!(run(&argv, None).status.success());
            // Parse the displayed command as shell arguments, without invoking it.
            // Dollar substitutions, backticks, quotes, and globs in the path must
            // remain literal and recover exactly the machine argv.
            let script = format!(
                "set -- {}; printf '%s\\n' \"$@\"",
                action["command"].as_str().unwrap()
            );
            let parsed = Command::new("/bin/sh")
                .args(["-c", &script])
                .output()
                .unwrap();
            assert!(parsed.status.success() && parsed.stderr.is_empty());
            let displayed = String::from_utf8(parsed.stdout).unwrap();
            let expected: Vec<&str> = action["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|arg| arg.as_str().unwrap())
                .collect();
            assert_eq!(displayed.lines().collect::<Vec<_>>(), expected);
        }
        let override_value = envelope(
            &run(
                &["app", "describe", "links", "--demo", "--agent"],
                Some(&path),
            ),
            0,
        );
        assert_eq!(override_value["context"]["source"], "demo");
        let explicit = envelope(
            &run(
                &[
                    "app",
                    "describe",
                    "links",
                    "--instance",
                    path.to_str().unwrap(),
                    "--agent",
                ],
                Some(Path::new("/does/not/exist")),
            ),
            0,
        );
        assert_eq!(explicit["context"]["source"], "local_instance");
    }

    #[test]
    fn malformed_and_future_metadata_fail_closed() {
        for (mut artifact, expected) in [
            (fixture(), "unsupported_artifact"),
            (fixture(), "unknown_codec"),
            (fixture(), "invalid_catalog"),
        ] {
            match expected {
                "unsupported_artifact" => artifact["format"] = json!(99),
                "unknown_codec" => {
                    artifact["schema"]["inputs"]["create"]["fields"]["title"] =
                        json!("new_unknown_codec")
                }
                _ => artifact["operations"][0]["input_type"] = json!("missing_contract"),
            }
            let scratch = Scratch::new();
            let path = scratch.instance(&artifact);
            let value = envelope(
                &run(&["app", "describe", "links", "--agent"], Some(&path)),
                5,
            );
            assert_eq!(
                value["error"]["code"],
                if expected == "unknown_codec" {
                    "invalid_catalog"
                } else {
                    expected
                }
            );
        }
        let scratch = Scratch::new();
        let path = scratch.instance(&fixture());
        fs::write(&path, "{bad json").unwrap();
        assert_eq!(
            envelope(
                &run(&["app", "describe", "links", "--agent"], Some(&path)),
                5
            )["error"]["code"],
            "invalid_instance"
        );
        fs::write(&path, vec![b' '; 1_048_577]).unwrap();
        assert_eq!(
            envelope(
                &run(&["app", "describe", "links", "--agent"], Some(&path)),
                5
            )["error"]["code"],
            "metadata_too_large"
        );
    }

    const SPEC: &str = r#"{"kind":"instance","version":1,"installation":"exampleco",
"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools"},
"domains":{"people":"example.com","apps":"apps.example.com"},
"operators":["ada@example.com","grace@example.com"],
"apps":{"go":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"automatic",
"extension":"jldmikbinomhomcbmeppagennfohakni","owners":["lin@example.com"],"size":"standard",
"verification":4,"schedules":"enabled"},
"home":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"manual","extension":null,
"owners":["kay@example.com","lin@example.com"],"size":"large","verification":6,"schedules":"paused"}}}"#;

    fn check_spec(spec: &str) -> Output {
        let scratch = Scratch::new();
        fs::write(scratch.0.join("day2.json"), spec).unwrap();
        run(
            &["instance", "check", scratch.0.to_str().unwrap(), "--agent"],
            None,
        )
    }

    #[test]
    fn instance_spec_derives_every_fixed_name() {
        let value = envelope(&check_spec(SPEC), 0);
        assert_eq!(value["command"], "instance.check");
        assert_eq!(value["context"]["spec_validation"], "checked");
        assert!(
            value["context"]["spec_path"]
                .as_str()
                .unwrap()
                .ends_with("/day2.json")
        );
        let result = &value["result"];
        assert_eq!(
            result["platform_repository"],
            "github.com/clankernative/platform"
        );
        assert_eq!(
            result["platform_commit"],
            "fe4320b189b98ed08fccc183db3e70aee76319ee"
        );
        assert_eq!(
            result["repositories"],
            json!({"instance": "tools/instance", "app_ci": "tools/app-ci"})
        );
        assert_eq!(
            result["required_check"],
            "tools/app-ci: day2 / verification (pull_request)"
        );
        assert_eq!(
            result["artifact_registry"],
            "us-central1-docker.pkg.dev/exampleco-tools"
        );
        assert_eq!(
            result["sdk_registry"],
            "us-central1-docker.pkg.dev/exampleco-tools/day2"
        );
        assert_eq!(result["tofu_state_bucket"], "exampleco-tools-tofu-state");
        assert_eq!(
            result["platform_state_prefixes"],
            json!({"project": "foundation", "cluster": "platform/cluster", "tenancy": "platform/tenancy",
                   "app_edge": "platform/app", "day2": "day2"})
        );
        assert_eq!(
            result["cluster"],
            json!({"name": "day2", "kube_context": "gke_exampleco-tools_us-central1-a_day2"})
        );
        assert_eq!(result["app_namespace_prefix"], "app-");
        assert_eq!(
            result["operators"],
            json!(["ada@example.com", "grace@example.com"])
        );
        // The instance's apply identity is <org>-infra in its project; every app's admins add it to the owners.
        assert_eq!(
            result["apply_identity"],
            "tools-infra@exampleco-tools.iam.gserviceaccount.com"
        );
        assert_eq!(
            result["apps"],
            json!([
                {
                    "id": "go",
                    "delivery": "automatic",
                    "sdk": "sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848",
                    "owners": ["lin@example.com"],
                    "admins": ["lin@example.com", "tools-infra@exampleco-tools.iam.gserviceaccount.com"],
                    "size": "standard",
                    "verification": 4,
                    "schedules": "enabled",
                    "extension": {
                        "id": "jldmikbinomhomcbmeppagennfohakni",
                        "update_url": "https://go.apps.example.com/downloads/updates.xml",
                        "downloads": ["/downloads/go.crx", "/downloads/updates.xml"],
                        "signing_secret": "go-chrome-extension-signing-key"
                    },
                    "repository": "tools/go",
                    "hostname": "go.apps.example.com",
                    "namespace": "app-go",
                    "image": "us-central1-docker.pkg.dev/exampleco-tools/go/go",
                    "state_bucket": "exampleco-tools-go-state",
                    "state_prefix": "day2-app/go",
                    "edge_state_prefix": "platform/app/go",
                    "backup_bucket": "exampleco-tools-go-backups",
                    "runtime_resources": {"memory_mib": 512, "cpu_millis": 1000, "process_limit": 1024,
                                          "http_concurrency": 4, "shutdown_seconds": 30},
                    "sqlite_storage_gb": 5
                },
                {
                    "id": "home",
                    "delivery": "manual",
                    "sdk": "sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848",
                    "owners": ["kay@example.com", "lin@example.com"],
                    "admins": ["kay@example.com", "lin@example.com", "tools-infra@exampleco-tools.iam.gserviceaccount.com"],
                    "size": "large",
                    "verification": 6,
                    "schedules": "paused",
                    "extension": null,
                    "repository": "tools/home",
                    "hostname": "home.apps.example.com",
                    "namespace": "app-home",
                    "image": "us-central1-docker.pkg.dev/exampleco-tools/home/home",
                    "state_bucket": "exampleco-tools-home-state",
                    "state_prefix": "day2-app/home",
                    "edge_state_prefix": "platform/app/home",
                    "backup_bucket": "exampleco-tools-home-backups",
                    "runtime_resources": {"memory_mib": 2048, "cpu_millis": 1000, "process_limit": 1024,
                                          "http_concurrency": 4, "shutdown_seconds": 30},
                    "sqlite_storage_gb": 5
                }
            ])
        );
        let argv = value["next_actions"][0]["argv"].as_array().unwrap();
        assert_eq!(
            argv[..3],
            [json!("day2"), json!("instance"), json!("check")]
        );
        assert!(!argv.contains(&json!("--agent")));
    }

    #[test]
    fn instance_spec_rejects_every_unchecked_shape() {
        let cases = [
            (r#""kind":"instance""#, r#""kind":"app""#),
            (r#""version":1,"#, r#""version":2,"#),
            (r#""version":1,"#, r#""version":"1","#),
            (r#""version":1,"#, ""),
            (r#""version":1,"#, r#""version":1,"extra":true,"#),
            (
                r#""installation":"exampleco""#,
                r#""installation":"Example Co""#,
            ),
            ("fe4320b189b98ed08fccc183db3e70aee76319ee", "fe4320b1"),
            (
                "fe4320b189b98ed08fccc183db3e70aee76319ee",
                "FE4320B189B98ED08FCCC183DB3E70AEE76319EE",
            ),
            (
                r#""project":"exampleco-tools""#,
                r#""project":"exampleco-tools-""#,
            ),
            (r#""project":"exampleco-tools""#, r#""project":"Exampleco""#),
            (r#""region":"us-central1""#, r#""region":"us_central1""#),
            (r#""zone":"us-central1-a""#, r#""zone":"europe-west4-a""#),
            (r#""zone":"us-central1-a""#, r#""zone":"us-central1""#),
            (
                r#""zone":"us-central1-a""#,
                r#""zone":"us-central1-a","network":"default""#,
            ),
            (r#""kind":"gitea""#, r#""kind":"github""#),
            ("https://git.example.com", "http://git.example.com"),
            ("https://git.example.com", "https://git.example.com/tools"),
            ("https://git.example.com", "https://git.example.com:3000"),
            (r#""org":"tools""#, r#""org":"Tools""#),
            (r#""org":"tools""#, r#""org":"-tools""#),
            // <org>-infra must fit GCP's 30-byte service-account ID.
            (r#""org":"tools""#, r#""org":"ttttttttttttttttttttttttt""#),
            (r#""org":"tools""#, r#""org":"1tools""#),
            (r#""people":"example.com""#, r#""people":"example""#),
            (r#""apps":"apps.example.com""#, r#""apps":"localhost""#),
            (
                r#""apps":"apps.example.com""#,
                r#""apps":"Apps.Example.com""#,
            ),
            (
                r#""ada@example.com","grace@example.com""#,
                r#""grace@example.com","ada@example.com""#,
            ),
            (
                r#""ada@example.com","grace@example.com""#,
                r#""ada@example.com","ada@example.com""#,
            ),
            (r#""ada@example.com","grace@example.com""#, ""),
            (r#""ada@example.com""#, r#""ada@elsewhere.com""#),
            (r#""ada@example.com""#, r#""Ada@example.com""#),
            (r#""go":{"#, r#""zebra":{"#),
            (r#""go":{"#, r#""go-links":{"#),
            (r#""go":{"#, r#""go_links":{"#),
            (r#""go":{"#, r#""g":{"#),
            (r#""go":{"#, r#""instance":{"#),
            (r#""go":{"#, r#""day2":{"#),
            (r#""go":{"#, r#""tofu":{"#),
            (r#""go":{"#, r#""abcdefghijklmnopqrstu":{"#),
            (r#""go":{"sdk":"sha256:"#, r#""go":{"sdk":"sha512:"#),
            (r#""go":{"sdk":"sha256:98fb"#, r#""go":{"sdk":"sha256:98FB"#),
            (r#""delivery":"automatic""#, r#""delivery":"auto""#),
            (r#""delivery":"manual""#, r#""delivery":"manual","cases":6"#),
            (
                r#""delivery":"manual""#,
                r#""delivery":"manual","repository":"tools/golinks""#,
            ),
            // Per-app choices: wrong types, out-of-range values and closed tags.
            (r#""verification":4,"#, r#""verification":"4","#),
            (r#""verification":4,"#, r#""verification":4.5,"#),
            (r#""verification":4,"#, r#""verification":-4,"#),
            (r#""verification":4,"#, r#""verification":3,"#),
            (r#""verification":4,"#, r#""verification":101,"#),
            (r#""verification":6,"#, r#""verification":null,"#),
            (r#""size":"standard""#, r#""size":"small""#),
            (r#""size":"large""#, r#""size":"Large""#),
            (r#""schedules":"enabled""#, r#""schedules":"disabled""#),
            (r#""schedules":"paused""#, r#""schedules":false"#),
            // Owners: a sorted, unique, non-empty list of people at domains.people.
            (r#""owners":["lin@example.com"]"#, r#""owners":[]"#),
            (
                r#""owners":["lin@example.com"]"#,
                r#""owners":"lin@example.com""#,
            ),
            (r#""owners":["lin@example.com"]"#, r#""owners":[7]"#),
            (
                r#""owners":["lin@example.com"]"#,
                r#""owners":["lin@elsewhere.com"]"#,
            ),
            (
                r#""owners":["lin@example.com"]"#,
                r#""owners":["Lin@example.com"]"#,
            ),
            (
                r#"["kay@example.com","lin@example.com"]"#,
                r#"["lin@example.com","kay@example.com"]"#,
            ),
            (
                r#"["kay@example.com","lin@example.com"]"#,
                r#"["kay@example.com","kay@example.com"]"#,
            ),
            // Extension: null or a 32-letter a-p Chrome extension ID.
            (
                "jldmikbinomhomcbmeppagennfohakni",
                "jldmikbinomhomcbmeppagennfohakn",
            ),
            (
                "jldmikbinomhomcbmeppagennfohakni",
                "jldmikbinomhomcbmeppagennfohaknip",
            ),
            (
                "jldmikbinomhomcbmeppagennfohakni",
                "qldmikbinomhomcbmeppagennfohakni",
            ),
            (
                "jldmikbinomhomcbmeppagennfohakni",
                "JLDMIKBINOMHOMCBMEPPAGENNFOHAKNI",
            ),
            (r#""extension":null"#, r#""extension":"""#),
            (r#""extension":null"#, r#""extension":false"#),
            // An extension ID is one global identity, so two apps can't pin it.
            (
                r#""extension":null"#,
                r#""extension":"jldmikbinomhomcbmeppagennfohakni""#,
            ),
            // Every per-app field is required.
            (r#""extension":null,"#, ""),
            (r#","schedules":"enabled""#, ""),
            (r#""size":"large","#, ""),
            (r#""owners":["lin@example.com"],"#, ""),
            (r#""verification":6,"#, ""),
        ];
        for (old, new) in cases {
            assert_eq!(SPEC.matches(old).count(), 1, "ambiguous case {old}");
            let edited = SPEC.replacen(old, new, 1);
            let value = envelope(&check_spec(&edited), 5);
            assert_eq!(value["command"], "instance.check", "{old} -> {new}");
            assert_eq!(value["error"]["code"], "invalid_spec", "{old} -> {new}");
        }
        let empty = SPEC.replacen(
            &SPEC[SPEC.find(r#""apps":{"go""#).unwrap() + 7..SPEC.len() - 1],
            "{}",
            1,
        );
        assert_eq!(
            envelope(&check_spec(&empty), 5)["error"]["code"],
            "invalid_spec"
        );
        let duplicate = SPEC.replacen(r#""home":{"#, r#""go":{"#, 1);
        assert_eq!(
            envelope(&check_spec(&duplicate), 5)["error"]["code"],
            "invalid_spec"
        );
    }

    #[test]
    fn instance_render_lists_every_root_backend_in_apply_order() {
        let scratch = Scratch::new();
        fs::write(scratch.0.join("day2.json"), SPEC).unwrap();
        let directory = scratch.0.to_str().unwrap();
        let value = envelope(&run(&["instance", "render", directory, "--agent"], None), 0);
        assert_eq!(value["command"], "instance.render");
        assert_eq!(value["context"]["spec_validation"], "checked");
        assert_eq!(value["result"]["installation"], "exampleco");
        let shared = "exampleco-tools-tofu-state";
        let root = |root: &str, app: Value, stack: &str, bucket: &str, prefix: &str| {
            json!({"root": root, "app_id": app, "stack": stack,
                   "backend": {"bucket": bucket, "prefix": prefix}})
        };
        let mut roots = value["result"]["roots"].clone();
        for entry in roots.as_array_mut().unwrap() {
            assert!(entry["tfvars_json"].is_string(), "{entry}");
            entry.as_object_mut().unwrap().remove("tfvars_json");
        }
        assert_eq!(
            roots,
            json!([
                root(
                    "project",
                    Value::Null,
                    "deploy/gke/stacks/project",
                    shared,
                    "foundation"
                ),
                root(
                    "cluster",
                    Value::Null,
                    "deploy/gke/stacks/cluster",
                    shared,
                    "platform/cluster"
                ),
                root(
                    "tenancy",
                    Value::Null,
                    "deploy/gke/stacks/tenancy",
                    shared,
                    "platform/tenancy"
                ),
                root(
                    "app-edge",
                    json!("go"),
                    "deploy/gke/stacks/app-edge",
                    shared,
                    "platform/app/go"
                ),
                root(
                    "app-edge",
                    json!("home"),
                    "deploy/gke/stacks/app-edge",
                    shared,
                    "platform/app/home"
                ),
                root(
                    "day2-app",
                    json!("go"),
                    "deploy/gke/stacks/day2-app",
                    "exampleco-tools-go-state",
                    "day2-app/go"
                ),
                root(
                    "day2-app",
                    json!("home"),
                    "deploy/gke/stacks/day2-app",
                    "exampleco-tools-home-state",
                    "day2-app/home"
                ),
            ])
        );
        let actions = value["next_actions"].as_array().unwrap();
        assert_eq!(
            actions[0]["argv"],
            json!(["day2", "instance", "render", directory])
        );
        assert_eq!(
            actions[1]["argv"],
            json!(["day2", "instance", "check", directory, "--agent"])
        );
        // Check points at render, so either command reaches the other.
        let checked = envelope(&check_spec(SPEC), 0);
        assert_eq!(
            checked["next_actions"][1]["argv"].as_array().unwrap()[..3],
            [json!("day2"), json!("instance"), json!("render")]
        );
        // Text lists one line per root and keeps stderr empty.
        let text = run(&["instance", "render", directory], None);
        assert_eq!(text.status.code(), Some(0));
        assert!(text.stderr.is_empty());
        let stdout = String::from_utf8(text.stdout).unwrap();
        assert!(
            stdout.starts_with("DAY2  /  instance exampleco  /  OpenTofu inputs"),
            "{stdout}"
        );
        assert!(
            stdout.contains("STATE BACKENDS  /  7 core roots, in apply order"),
            "{stdout}"
        );
        assert!(
            stdout.contains("  day2-app/home           exampleco-tools-home-state / day2-app/home"),
            "{stdout}"
        );
    }

    #[test]
    fn instance_render_names_real_gcs_stacks_and_fits_every_app_id() {
        let scratch = Scratch::new();
        fs::write(scratch.0.join("day2.json"), SPEC).unwrap();
        let directory = scratch.0.to_str().unwrap();
        let value = envelope(&run(&["instance", "render", directory, "--agent"], None), 0);
        // Every rendered stack is a platform source directory with a GCS backend.
        let platform = root().parent().unwrap().to_owned();
        for entry in value["result"]["roots"].as_array().unwrap() {
            let stack = entry["stack"].as_str().unwrap();
            let versions = fs::read_to_string(platform.join(stack).join("versions.tf"))
                .unwrap_or_else(|error| panic!("{stack}: {error}"));
            assert!(versions.contains(r#"backend "gcs""#), "{stack}");
        }
        // The longest valid app ID (20 bytes) keeps a separated text column.
        let longest = "h".repeat(20);
        fs::write(
            scratch.0.join("day2.json"),
            SPEC.replacen(r#""home":{"#, &format!(r#""{longest}":{{"#), 1),
        )
        .unwrap();
        let text = run(&["instance", "render", directory], None);
        assert_eq!(text.status.code(), Some(0), "{text:?}");
        let stdout = String::from_utf8(text.stdout).unwrap();
        assert!(
            stdout.contains(&format!(
                "  day2-app/{longest}  exampleco-tools-{longest}-state / day2-app/{longest}"
            )),
            "{stdout}"
        );
    }

    #[test]
    fn instance_render_derives_each_root_variable_from_the_spec() {
        let scratch = Scratch::new();
        fs::write(scratch.0.join("day2.json"), SPEC).unwrap();
        let directory = scratch.0.to_str().unwrap();
        let value = envelope(&run(&["instance", "render", directory, "--agent"], None), 0);
        let variables = |label: &str| -> Value {
            let entry = value["result"]["roots"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| match entry["app_id"].as_str() {
                    Some(app) => format!("{}/{app}", entry["root"].as_str().unwrap()) == label,
                    None => entry["root"] == label,
                })
                .unwrap_or_else(|| panic!("{label}"));
            serde_json::from_str(entry["tfvars_json"].as_str().unwrap()).unwrap()
        };
        let context = "gke_exampleco-tools_us-central1-a_day2";
        let operators = json!(["user:ada@example.com", "user:grace@example.com"]);
        assert_eq!(
            variables("project"),
            json!({
                "project_id": "exampleco-tools",
                "region": "us-central1",
                "state_bucket_name": "exampleco-tools-tofu-state",
                "state_prefixes": {"foundation": "foundation/", "cluster": "platform/cluster/",
                                   "tenancy": "platform/tenancy/", "app": "platform/app/", "day2": "day2/"}
            })
        );
        assert_eq!(
            variables("cluster"),
            json!({
                "project_id": "exampleco-tools",
                "region": "us-central1",
                "zone": "us-central1-a",
                "cluster_name": "day2",
                "cluster_labels": {"managed_by": "opentofu", "stack": "platform-cluster", "environment": "day2"},
                "subnet_cidr": "10.10.0.0/20",
                "pod_cidr": "10.20.0.0/16",
                "service_cidr": "10.30.0.0/20",
                "shared_node_pod_pids_limit": 1024
            })
        );
        assert_eq!(
            variables("tenancy"),
            json!({"kube_context": context, "app_namespace_prefix": "app-"})
        );
        // Operators reach every app, deploy it by hand and hold its off-site backups. Owners (kay and lin)
        // get no deploy authority.
        let edge = variables("app-edge/home");
        assert_eq!(edge["deployer_subjects"], operators);
        assert_eq!(edge["domain"], "home.apps.example.com");
        assert_eq!(edge["kube_context"], context);
        assert_eq!(
            edge["iap_members"],
            json!([
                "domain:example.com",
                "user:ada@example.com",
                "user:grace@example.com"
            ])
        );
        assert_eq!(edge["offsite_backup_readers"], operators);
        assert_eq!(edge["kube_dns_service_ip"], "10.30.0.10");
        assert_eq!(
            edge["cluster_cidrs"],
            json!(["10.20.0.0/16", "10.30.0.0/20", "10.10.0.0/20"])
        );
        // The size preset sets memory; every other limit and the volume are shared.
        let standard = variables("day2-app/go");
        let large = variables("day2-app/home");
        assert_eq!(standard["runtime_resources"]["memory_mib"], 512);
        assert_eq!(large["runtime_resources"]["memory_mib"], 2048);
        assert_eq!(
            large,
            json!({
                "kube_context": context,
                "app_id": "home",
                "namespace": "app-home",
                "installation": "exampleco",
                "environment": "production",
                "hosted_domain": "example.com",
                "admins": ["kay@example.com", "lin@example.com", "tools-infra@exampleco-tools.iam.gserviceaccount.com"],
                "edge_origin": "https://home.apps.example.com",
                "runtime_resources": {"memory_mib": 2048, "cpu_millis": 1000, "process_limit": 1024,
                                      "http_concurrency": 4, "shutdown_seconds": 30},
                "pod_pids_limit": 1024,
                "backup_bucket": "exampleco-tools-home-backups"
            })
        );
        // Text lists each root's variables as tfvars lines.
        let text = run(&["instance", "render", directory], None);
        let stdout = String::from_utf8(text.stdout).unwrap();
        assert!(
            stdout.contains("VARIABLES  /  rendered from the spec"),
            "{stdout}"
        );
        assert!(
            stdout.contains(
                "  tenancy\n    kube_context = \"gke_exampleco-tools_us-central1-a_day2\"\n"
            ),
            "{stdout}"
        );
    }

    #[test]
    fn instance_render_variables_are_declared_by_their_stacks() {
        let scratch = Scratch::new();
        fs::write(scratch.0.join("day2.json"), SPEC).unwrap();
        let directory = scratch.0.to_str().unwrap();
        let value = envelope(&run(&["instance", "render", directory, "--agent"], None), 0);
        let platform = root().parent().unwrap().to_owned();
        for entry in value["result"]["roots"].as_array().unwrap() {
            let stack = entry["stack"].as_str().unwrap();
            let mut declared = String::new();
            for file in fs::read_dir(platform.join(stack)).unwrap() {
                let path = file.unwrap().path();
                if path.extension().is_some_and(|extension| extension == "tf") {
                    declared.push('\n');
                    declared.push_str(&fs::read_to_string(&path).unwrap());
                }
            }
            let variables: Value =
                serde_json::from_str(entry["tfvars_json"].as_str().unwrap()).unwrap();
            for name in variables.as_object().unwrap().keys() {
                assert!(
                    declared.contains(&format!("\nvariable \"{name}\" {{")),
                    "{stack} does not declare {name}"
                );
            }
        }
    }

    #[test]
    fn instance_render_variables_pass_their_stacks_declarations() {
        let configuration = std::env::var_os("DAY2_TEST_TOFU_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| root().join("../.cache/tofu.json"));
        let pinned: Value = serde_json::from_slice(&fs::read(configuration).unwrap()).unwrap();
        let tofu = PathBuf::from(pinned["engine"]["path"].as_str().unwrap());
        let scratch = Scratch::new();
        fs::write(scratch.0.join("day2.json"), SPEC).unwrap();
        let directory = scratch.0.to_str().unwrap();
        let value = envelope(&run(&["instance", "render", directory, "--agent"], None), 0);
        let platform = root().parent().unwrap().to_owned();
        for (index, entry) in value["result"]["roots"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            let stack = entry["stack"].as_str().unwrap();
            let document = entry["tfvars_json"].as_str().unwrap();
            let rendered: Value = serde_json::from_str(document).unwrap();
            let names: Vec<&String> = rendered.as_object().unwrap().keys().collect();
            // A module of exactly the stack's own declarations of the rendered variables, so OpenTofu applies
            // their types, defaults and validation blocks to the rendered document.
            let mut module = String::new();
            for file in fs::read_dir(platform.join(stack)).unwrap() {
                let path = file.unwrap().path();
                if path.extension().is_none_or(|extension| extension != "tf") {
                    continue;
                }
                let mut copying = false;
                for line in fs::read_to_string(&path).unwrap().lines() {
                    copying = copying
                        || names
                            .iter()
                            .any(|name| line == format!("variable \"{name}\" {{"));
                    if copying {
                        module.push_str(line);
                        module.push('\n');
                        copying = line != "}";
                    }
                }
            }
            let work = scratch.0.join(format!("root-{index}"));
            fs::create_dir(&work).unwrap();
            fs::write(work.join("variables.tf"), module).unwrap();
            fs::write(work.join("rendered.tfvars.json"), document).unwrap();
            let fields: Vec<String> = names
                .iter()
                .map(|name| format!("{name}=var.{name}"))
                .collect();
            fs::write(
                work.join("expression"),
                format!("jsonencode({{{}}})\n", fields.join(",")),
            )
            .unwrap();
            let output = Command::new(&tofu)
                .args(["console", "-no-color", "-var-file=rendered.tfvars.json"])
                .current_dir(&work)
                .stdin(Stdio::from(
                    fs::File::open(work.join("expression")).unwrap(),
                ))
                .output()
                .unwrap();
            let printed = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{stack}: {printed}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let encoded: String =
                serde_json::from_str(printed.trim().lines().last().unwrap()).unwrap();
            let evaluated: Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(evaluated, rendered, "{stack}");
        }
    }

    #[test]
    fn instance_render_fails_exactly_as_check_does() {
        let scratch = Scratch::new();
        let directory = scratch.0.to_str().unwrap();
        let render = |args: &[&str], code: i32| {
            let value = envelope(&run(args, None), code);
            assert_eq!(value["command"], "instance.render", "{args:?}");
            assert!(value["result"].is_null(), "{args:?}");
            value["error"]["code"].clone()
        };
        assert_eq!(
            render(&["instance", "render", directory, "--agent"], 3),
            "metadata_unreadable"
        );
        fs::write(
            scratch.0.join("day2.json"),
            SPEC.replacen(r#""org":"tools""#, r#""org":"Tools""#, 1),
        )
        .unwrap();
        assert_eq!(
            render(&["instance", "render", directory, "--agent"], 5),
            "invalid_spec"
        );
        for args in [
            vec!["instance", "render", "--agent"],
            vec!["--agent", "instance", "render"],
        ] {
            assert_eq!(render(args.as_slice(), 2), "missing_argument");
        }
        for args in [
            vec!["instance", "render", directory, "--demo", "--agent"],
            vec![
                "instance",
                "--agent",
                "render",
                directory,
                "--operation",
                "links.list",
            ],
        ] {
            assert_eq!(render(args.as_slice(), 2), "conflicting_options");
        }
    }

    #[test]
    fn instance_plan_validates_before_it_runs_and_fails_closed() {
        let scratch = Scratch::new();
        let instance = scratch.0.join("instance");
        let platform = scratch.0.join("platform");
        let output = scratch.0.join("plan");
        fs::create_dir(&instance).unwrap();
        fs::create_dir(&platform).unwrap();
        let (directory, checkout, new) = (
            instance.to_str().unwrap(),
            platform.to_str().unwrap(),
            output.to_str().unwrap(),
        );
        let plan = |args: &[&str], code: i32| {
            let value = envelope(&run(args, None), code);
            assert_eq!(value["command"], "instance.plan", "{args:?}");
            assert!(value["result"].is_null(), "{args:?}");
            (
                value["error"]["code"].clone(),
                value["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        // The spec is validated before anything runs, exactly as check and render validate it.
        assert_eq!(
            plan(
                &["instance", "plan", directory, checkout, new, "--agent"],
                3
            )
            .0,
            "metadata_unreadable"
        );
        fs::write(
            instance.join("day2.json"),
            SPEC.replacen(r#""org":"tools""#, r#""org":"Tools""#, 1),
        )
        .unwrap();
        assert_eq!(
            plan(
                &["instance", "plan", directory, checkout, new, "--agent"],
                5
            )
            .0,
            "invalid_spec"
        );
        for args in [
            vec!["instance", "plan", "--agent"],
            vec!["instance", "plan", directory, "--agent"],
            vec!["instance", "plan", directory, checkout, "--agent"],
        ] {
            assert_eq!(plan(args.as_slice(), 2).0, "missing_argument");
        }
        assert_eq!(
            plan(
                &[
                    "instance", "plan", directory, checkout, new, "--demo", "--agent"
                ],
                2
            )
            .0,
            "conflicting_options"
        );
        // A valid spec still needs every root's committed inputs at their fixed paths, then a
        // checkout containing its platform commit; nothing is written before either check.
        fs::write(instance.join("day2.json"), SPEC).unwrap();
        let (code, message) = plan(
            &["instance", "plan", directory, checkout, new, "--agent"],
            6,
        );
        assert_eq!(code, "plan_failed");
        assert!(message.contains("gcp/config/project.tfvars"), "{message}");
        fs::create_dir_all(instance.join("gcp/config/app-edge")).unwrap();
        for inputs in [
            "project",
            "cluster",
            "tenancy",
            "app-edge/go",
            "app-edge/home",
        ] {
            fs::write(instance.join(format!("gcp/config/{inputs}.tfvars")), "").unwrap();
        }
        let (code, message) = plan(
            &["instance", "plan", directory, checkout, new, "--agent"],
            6,
        );
        assert_eq!(code, "plan_failed");
        assert!(message.contains("platform commit"), "{message}");
        assert!(!output.exists());
        // A plan never reuses an output directory.
        fs::create_dir(&output).unwrap();
        let (code, message) = plan(
            &["instance", "plan", directory, checkout, new, "--agent"],
            6,
        );
        assert_eq!(code, "plan_failed");
        assert!(message.contains("new output directory"), "{message}");
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    }

    #[test]
    fn instance_apply_validates_before_it_runs_and_fails_closed() {
        let scratch = Scratch::new();
        let instance = scratch.0.join("instance");
        let platform = scratch.0.join("platform");
        let reviewed = scratch.0.join("plan");
        let output = scratch.0.join("apply");
        fs::create_dir(&instance).unwrap();
        fs::create_dir(&platform).unwrap();
        let (directory, checkout, plan, new) = (
            instance.to_str().unwrap(),
            platform.to_str().unwrap(),
            reviewed.to_str().unwrap(),
            output.to_str().unwrap(),
        );
        let apply = |args: &[&str], code: i32| {
            let value = envelope(&run(args, None), code);
            assert_eq!(value["command"], "instance.apply", "{args:?}");
            assert!(value["result"].is_null(), "{args:?}");
            (
                value["error"]["code"].clone(),
                value["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        // An apply names the plan that was reviewed.
        for args in [
            vec!["instance", "apply", "--agent"],
            vec!["instance", "apply", directory, checkout, "--agent"],
            vec!["instance", "apply", directory, checkout, new, "--agent"],
        ] {
            assert_eq!(apply(args.as_slice(), 2).0, "missing_argument");
        }
        assert_eq!(
            apply(
                &[
                    "instance", "apply", directory, checkout, plan, new, "--demo", "--agent"
                ],
                2
            )
            .0,
            "conflicting_options"
        );
        // The spec is validated before anything runs.
        assert_eq!(
            apply(
                &[
                    "instance", "apply", directory, checkout, plan, new, "--agent"
                ],
                3
            )
            .0,
            "metadata_unreadable"
        );
        // The host validates the apply request as it validates a plan's: a checkout
        // without the platform commit is refused before anything is written.
        fs::write(instance.join("day2.json"), SPEC).unwrap();
        fs::create_dir_all(instance.join("gcp/config/app-edge")).unwrap();
        for inputs in [
            "project",
            "cluster",
            "tenancy",
            "app-edge/go",
            "app-edge/home",
        ] {
            fs::write(instance.join(format!("gcp/config/{inputs}.tfvars")), "").unwrap();
        }
        let (code, message) = apply(
            &[
                "instance", "apply", directory, checkout, plan, new, "--agent",
            ],
            6,
        );
        assert_eq!(code, "apply_failed");
        assert!(message.contains("platform commit"), "{message}");
        assert!(!output.exists());
    }

    #[test]
    fn instance_release_validates_before_it_runs_and_fails_closed() {
        let scratch = Scratch::new();
        let instance = scratch.0.join("instance");
        fs::create_dir(&instance).unwrap();
        let request = scratch.0.join("request.json");
        let manifest = scratch.0.join("manifest.json");
        // Neither gcloud nor docker is on PATH, so nothing here can reach a bucket or registry.
        let tools = scratch.0.join("no-tools");
        fs::create_dir(&tools).unwrap();
        let cache = scratch.0.join("cache");
        let digest = format!("sha256:{}", "ab".repeat(32));
        let (directory, requested, new) = (
            instance.to_str().unwrap(),
            request.to_str().unwrap(),
            manifest.to_str().unwrap(),
        );
        let release = |args: &[&str], code: i32| {
            let value = envelope(
                &run_with(
                    args,
                    None,
                    &[
                        ("PATH", tools.as_path()),
                        ("DAY2_RELEASE_CACHE", cache.as_path()),
                    ],
                ),
                code,
            );
            assert!(value["result"].is_null(), "{args:?}");
            (
                value["command"].as_str().unwrap().to_owned(),
                value["error"]["code"].as_str().unwrap().to_owned(),
                value["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        let publish = [
            "instance", "release", "publish", directory, requested, new, "--agent",
        ];
        let fetch = [
            "instance",
            "release",
            "fetch",
            directory,
            digest.as_str(),
            "1236",
            "--agent",
        ];
        for (args, command) in [
            (
                vec!["instance", "release", "--agent"],
                "instance.release.fetch",
            ),
            (
                vec![
                    "instance", "release", "publish", directory, requested, "--agent",
                ],
                "instance.release.publish",
            ),
            (
                vec![
                    "instance",
                    "release",
                    "fetch",
                    directory,
                    digest.as_str(),
                    "--agent",
                ],
                "instance.release.fetch",
            ),
        ] {
            let (reported, code, _) = release(args.as_slice(), 2);
            assert_eq!(
                (reported.as_str(), code.as_str()),
                (command, "missing_argument"),
                "{args:?}"
            );
        }
        // Only a canonical approved reference reaches the host.
        for (reference, size) in [
            ("sha256:ab", "1236"),
            (digest.as_str(), "0"),
            (digest.as_str(), "65537"),
            (digest.as_str(), "01236"),
        ] {
            let args = [
                "instance", "release", "fetch", directory, reference, size, "--agent",
            ];
            assert_eq!(release(&args, 2).1, "invalid_arguments", "{args:?}");
        }
        let mut demo = publish.to_vec();
        demo.push("--demo");
        assert_eq!(release(&demo, 2).1, "conflicting_options");
        // The spec is validated before anything runs, exactly as check and render validate it.
        assert_eq!(release(&publish, 3).1, "metadata_unreadable");
        assert_eq!(release(&fetch, 3).1, "metadata_unreadable");
        fs::write(
            instance.join("day2.json"),
            SPEC.replacen(r#""org":"tools""#, r#""org":"Tools""#, 1),
        )
        .unwrap();
        assert_eq!(release(&fetch, 5).1, "invalid_spec");
        fs::write(instance.join("day2.json"), SPEC).unwrap();
        // The host validates the publication before it pulls or uploads anything.
        let (command, code, message) = release(&publish, 6);
        assert_eq!(
            (command.as_str(), code.as_str()),
            ("instance.release.publish", "release_failed")
        );
        assert!(message.contains("request.json"), "{message}");
        fs::write(
            &request,
            serde_json::to_vec(&json!({"profile": "linux_sqlite_rwo_v1"})).unwrap(),
        )
        .unwrap();
        let (_, _, message) = release(&publish, 6);
        assert!(message.contains("only linux_sqlite_single_v1"), "{message}");
        assert!(!manifest.exists());
        // A publication never overwrites a manifest file.
        fs::write(&manifest, b"reviewed").unwrap();
        let (_, _, message) = release(&publish, 6);
        assert!(message.contains("new manifest file"), "{message}");
        assert_eq!(fs::read(&manifest).unwrap(), b"reviewed");
        // A fetch refuses a cache that is not a directory, then a missing gcloud.
        fs::write(&cache, b"").unwrap();
        let (command, code, message) = release(&fetch, 6);
        assert_eq!(
            (command.as_str(), code.as_str()),
            ("instance.release.fetch", "release_failed")
        );
        assert!(message.contains("platform release cache"), "{message}");
        fs::remove_file(&cache).unwrap();
        let (_, _, message) = release(&fetch, 6);
        assert!(message.contains("gcloud"), "{message}");
        // Only the key's lock was created; nothing was cached.
        let cached: Vec<_> = fs::read_dir(&cache)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(cached, [format!("{}.lock", "ab".repeat(32))]);
    }

    #[test]
    fn instance_check_reads_only_its_fixed_spec_file() {
        let scratch = Scratch::new();
        let directory = scratch.0.to_str().unwrap();
        let check = |args: &[&str], code: i32| {
            let value = envelope(&run(args, None), code);
            assert_eq!(value["command"], "instance.check", "{args:?}");
            value["error"]["code"].clone()
        };
        // Only DIRECTORY/day2.json is read; no other name or path selects a spec.
        fs::write(scratch.0.join("instance.json"), SPEC).unwrap();
        assert_eq!(
            check(&["instance", "check", directory, "--agent"], 3),
            "metadata_unreadable"
        );
        fs::create_dir(scratch.0.join("day2.json")).unwrap();
        assert_eq!(
            check(&["instance", "check", directory, "--agent"], 3),
            "metadata_unreadable"
        );
        fs::remove_dir(scratch.0.join("day2.json")).unwrap();
        fs::write(scratch.0.join("day2.json"), vec![b' '; 1_048_577]).unwrap();
        assert_eq!(
            check(&["instance", "check", directory, "--agent"], 5),
            "metadata_too_large"
        );
        fs::write(scratch.0.join("day2.json"), SPEC).unwrap();
        for args in [
            vec!["--agent", "instance", "check"],
            vec!["instance", "check", "--agent"],
        ] {
            assert_eq!(check(args.as_slice(), 2), "missing_argument");
        }
        for args in [
            vec!["instance", "check", directory, "--demo", "--agent"],
            vec![
                "instance",
                "check",
                directory,
                "--operation",
                "links.list",
                "--agent",
            ],
            vec![
                "--instance",
                "a.json",
                "instance",
                "check",
                directory,
                "--agent",
            ],
        ] {
            assert_eq!(check(args.as_slice(), 2), "conflicting_options");
        }
        // Relative directories and trailing separators name the same file.
        for relative in [".", "./", "../", "./."] {
            let directory = if relative == "../" {
                format!("../{}", scratch.0.file_name().unwrap().to_str().unwrap())
            } else {
                relative.to_owned()
            };
            let output = Command::new(binary())
                .args(["instance", "check", &directory, "--agent"])
                .current_dir(&scratch.0)
                .env_remove("DAY2_INSTANCE")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let path = envelope(&output, 0)["context"]["spec_path"]
                .as_str()
                .unwrap()
                .to_owned();
            assert!(
                path.starts_with('/') && path.ends_with("/day2.json"),
                "{path}"
            );
            assert!(!path.contains("/./") && !path.contains("//"), "{path}");
        }
        // Text failures keep stdout empty and explain the field on stderr.
        fs::write(
            scratch.0.join("day2.json"),
            SPEC.replacen(r#""org":"tools""#, r#""org":"Tools""#, 1),
        )
        .unwrap();
        let text = run(&["instance", "check", directory], None);
        assert_eq!(text.status.code(), Some(5));
        assert!(text.stdout.is_empty());
        let stderr = String::from_utf8(text.stderr).unwrap();
        assert!(stderr.starts_with("DAY2  /  invalid_spec"), "{stderr}");
        assert!(stderr.contains("forge.org"), "{stderr}");
    }
}
