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
            .to_owned()
    }

    fn binary() -> &'static PathBuf {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        BINARY.get_or_init(|| {
            let root = root();
            // Keep the host installed by the gate with its distribution receipt.
            // A nested, narrower Cargo build would replace the workspace's
            // dependency artifacts and force the next campaign to rebuild them.
            assert!(
                root.join("day2-host").is_file(),
                "run xtask cli before CLI checks"
            );
            for name in ["day2-workflows", "day2-workflows.json"] {
                let temporary = tempfile::NamedTempFile::new_in(&root).unwrap();
                fs::copy(root.join("../target/debug").join(name), temporary.path())
                    .expect("run xtask cli before CLI checks");
                temporary.persist(root.join(name)).unwrap();
            }
            let roc = root.join("../../.toolchains/roc");
            for args in [
                vec!["check", "main.roc"],
                vec!["test", "main.roc"],
                vec!["build", "main.roc", "--output=day2"],
            ] {
                let output = Command::new(&roc)
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

    fn run(args: &[&str], instance: Option<&Path>) -> Output {
        let mut command = Command::new(binary());
        command
            .args(args)
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
        let check = || {
            Command::new(root().join("../../.toolchains/roc"))
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
                json!(["app.describe"])
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
}
