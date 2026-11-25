//! Exercise the compiled Roc workflows through the real private protocol. Failure
//! injection verifies that policy cannot proceed to later effects after a failed
//! native check, while the Reports integration tests exercise the real adapters.
use anyhow::{Result, bail};
use day2::automation;
use serde::Deserialize;
use serde_json::{Value, json};

#[test]
fn protected_restore_recipe_only_returns_browser_navigation_and_refuses_authority_flags()
-> Result<()> {
    let runner = automation::runner()?;
    let expected =
        json!({"kind":"protected_restore_browser_navigation_v1", "execution":"unavailable"});
    let mut calls = Vec::new();
    let actual = automation::run(
        &runner,
        &[
            "platform",
            "restore",
            "protected",
            "current-instance.json",
            "calendar",
        ],
        |request| {
            calls.push(request.action.clone());
            assert_eq!(request.action, "restore-browser-entry");
            assert_eq!(
                request.decode::<Value>()?,
                json!({"instance":"current-instance.json","app_name":"calendar"})
            );
            Ok(expected.clone())
        },
    )?;
    assert_eq!(calls, ["restore-browser-entry"]);
    assert_eq!(actual, expected);
    for malformed in [
        vec!["platform", "restore", "protected"],
        vec!["platform", "restore", "protected", "current-instance.json"],
    ] {
        let mut calls = 0;
        let result = automation::run(&runner, &malformed, |_| {
            calls += 1;
            bail!("malformed protected navigation reached write-capable restore fallback")
        });
        assert!(result.is_err());
        assert_eq!(calls, 0);
    }
    for extra in [
        "--approved",
        "--execute",
        "--actor=admin@example.com",
        "--url=https://foreign.example.com",
    ] {
        let mut calls = 0;
        let result = automation::run(
            &runner,
            &[
                "platform",
                "restore",
                "protected",
                "current-instance.json",
                "calendar",
                extra,
            ],
            |_| {
                calls += 1;
                bail!("invalid restore navigation reached native capability")
            },
        );
        assert!(result.is_err());
        assert_eq!(calls, 0);
    }
    let result = automation::run(
        &runner,
        &[
            "platform",
            "restore",
            "protected",
            "current-instance.json",
            "calendar",
        ],
        |_| bail!("injected current-instance refusal"),
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn restore_inspection_only_verifies_the_exact_archive_without_entering_restore() -> Result<()> {
    let expected = json!({
        "kind":"restore_archive_inspection_v1",
        "manifest_commitment":"sha256:fixture-only-archive",
        "scope":"example/sandbox/app",
        "app":"app",
        "artifact":"sha256:fixture-only-artifact",
        "database":"sha256:fixture-only-database"
    });
    let mut effects = Vec::new();
    let actual = automation::run(
        &automation::runner()?,
        &["platform", "restore", "inspect", "chosen-archive"],
        |request| {
            effects.push(request.action.clone());
            assert_eq!(request.action, "backup-verify");
            assert_eq!(
                request.decode::<Value>()?,
                json!({"directory":"chosen-archive"})
            );
            Ok(expected.clone())
        },
    )?;
    assert_eq!(effects, ["backup-verify"]);
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn restore_inspection_refusal_and_extra_arguments_never_copy_or_claim_approval() -> Result<()> {
    let runner = automation::runner()?;
    let mut effects = Vec::new();
    let refused = automation::run(
        &runner,
        &["platform", "restore", "inspect", "chosen-archive"],
        |request| {
            effects.push(request.action.clone());
            bail!("injected archive verification refusal")
        },
    );
    assert!(refused.is_err());
    assert_eq!(effects, ["backup-verify"]);
    for suffix in ["--approved", "--execute", "replacement-directory"] {
        let mut calls = 0;
        let refused = automation::run(
            &runner,
            &["platform", "restore", "inspect", "chosen-archive", suffix],
            |_| {
                calls += 1;
                bail!("invalid inspection reached a native capability")
            },
        );
        assert!(refused.is_err());
        assert_eq!(calls, 0);
    }
    Ok(())
}

#[test]
fn owners_recipe_forwards_one_bounded_atomic_operation() -> Result<()> {
    for action in ["list", "check", "add", "remove"] {
        let mut effects = Vec::new();
        let result = automation::run(
            &automation::runner()?,
            &[
                "platform",
                "owners",
                action,
                "instance.json",
                "reports",
                "operator",
                "{}",
            ],
            |request| {
                effects.push(request.action.clone());
                assert_eq!(
                    request.decode::<Value>()?,
                    json!({"action":action,"instance":"instance.json","app_name":"reports","operator":"operator","input_json":"{}"})
                );
                Ok(json!({"protocol":1,"kind":"app-owners"}))
            },
        )?;
        assert_eq!(effects, ["app-owners"]);
        assert_eq!(result["kind"], "app-owners");
    }
    Ok(())
}

#[test]
fn ui_lock_command_emits_the_native_source_record() -> Result<()> {
    let mut effects = Vec::new();
    let receipt = automation::run(
        &automation::runner()?,
        &["platform", "ui-lock", "fixture-source"],
        |request| {
            effects.push(request.action.clone());
            assert_eq!(
                request.decode::<Value>()?,
                json!({"source":"fixture-source"})
            );
            Ok(json!({"fixture":true}))
        },
    )?;
    assert_eq!(effects, ["ui-lock"]);
    assert_eq!(receipt, json!({"fixture":true}));
    Ok(())
}

#[test]
fn extension_commands_route_to_their_native_capabilities() -> Result<()> {
    for (arguments, expected, input) in [
        (
            vec!["extension", "verify", "app"],
            vec!["chrome-extension-verify"],
            json!({"source":"app"}),
        ),
        (
            vec!["extension", "policy", "app"],
            vec!["chrome-extension-policy"],
            json!({"source":"app"}),
        ),
        (
            vec!["extension", "local", "app", "unpacked"],
            vec!["chrome-extension-local"],
            json!({"source":"app","output":"unpacked"}),
        ),
        (
            vec!["extension", "fleet", "app", "exampleco-tools"],
            vec!["chrome-extension-fleet"],
            json!({"source":"app","project":"exampleco-tools"}),
        ),
    ] {
        let mut effects = Vec::new();
        let mut all = vec!["platform"];
        all.extend(&arguments);
        let receipt = automation::run(&automation::runner()?, &all, |request| {
            effects.push(request.action.clone());
            assert_eq!(request.decode::<Value>()?, input);
            Ok(json!({"fixture":true}))
        })?;
        assert_eq!(effects, expected);
        assert_eq!(receipt, json!({"fixture":true}));
    }
    Ok(())
}

#[test]
fn extension_pack_verifies_the_written_release_before_reporting_it() -> Result<()> {
    let mut effects = Vec::new();
    let receipt = automation::run(
        &automation::runner()?,
        &["platform", "extension", "pack", "app", "/dev/fd/63"],
        |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "chrome-extension-pack" => {
                    assert_eq!(
                        request.decode::<Value>()?,
                        json!({"source":"app","key":"/dev/fd/63"})
                    );
                    Ok(json!({"release":{"version":"2"}}))
                }
                "chrome-extension-verify" => Ok(json!({"declared":true})),
                action => bail!("unexpected effect {action}"),
            }
        },
    )?;
    assert_eq!(
        effects,
        ["chrome-extension-pack", "chrome-extension-verify"]
    );
    assert_eq!(receipt, json!({"release":{"version":"2"}}));

    let mut after_failure = Vec::new();
    assert!(
        automation::run(
            &automation::runner()?,
            &["platform", "extension", "pack", "app", "key.pem"],
            |request| {
                after_failure.push(request.action.clone());
                bail!("chrome_extension_signing_key")
            },
        )
        .is_err()
    );
    assert_eq!(after_failure, ["chrome-extension-pack"]);
    for incomplete in [
        vec!["platform", "extension", "pack", "app"],
        vec!["platform", "extension", "local", "app"],
        vec!["platform", "extension", "sign", "app"],
    ] {
        assert!(
            automation::run(&automation::runner()?, &incomplete, |_| bail!(
                "invalid extension usage reached native effects"
            ))
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn check_verifies_the_extension_release_before_building() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["platform", "check", "app", "42", "1"],
        |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "chrome-extension-verify" => {
                    assert_eq!(request.decode::<Value>()?, json!({"source":"app"}));
                    bail!("chrome_extension_stale")
                }
                action => bail!("unexpected effect {action}"),
            }
        },
    );
    assert!(format!("{:#}", result.unwrap_err()).contains("chrome_extension_stale"));
    assert_eq!(effects, ["chrome-extension-verify"]);
    Ok(())
}

#[test]
fn check_is_one_build_whose_required_verification_uses_the_requested_campaign() -> Result<()> {
    let built = build_receipt(
        "/platform/artifacts/0000",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "42",
    );
    let mut effects = Vec::new();
    let receipt = automation::run(
        &automation::runner()?,
        &["platform", "check", "fixture-source", "42", "4"],
        |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "build-source" => {
                    assert_eq!(
                        request.decode::<Value>()?,
                        json!({"source":"fixture-source","seed":"42","cases":4})
                    );
                    Ok(serde_json::to_value(&built)?)
                }
                "chrome-extension-verify" => Ok(json!({"declared":false})),
                // A second campaign would start with dev-create.
                action => bail!("unexpected check capability: {action}"),
            }
        },
    )?;
    assert_eq!(effects, ["chrome-extension-verify", "build-source"]);
    assert_eq!(receipt, serde_json::to_value(&built.verification)?);
    Ok(())
}

#[test]
fn bundled_ui_recipe_uses_verified_installation_without_network() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(&automation::runner()?, &["ui-dependency"], |request| {
        effects.push(request.action.clone());
        assert_eq!(request.decode::<Value>()?, json!({}));
        Ok(if request.action == "ui-dependency-inspect" {
            json!({"installed": true})
        } else {
            json!({"verified": true})
        })
    })?;
    assert_eq!(effects, ["ui-dependency-inspect", "ui-dependency-receipt"]);
    Ok(())
}

#[test]
fn bundled_ui_recipe_verifies_before_atomic_publication() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(&automation::runner()?, &["ui-dependency"], |request| {
        effects.push(request.action.clone());
        Ok(if request.action == "ui-dependency-inspect" {
            json!({"installed": false})
        } else {
            json!({})
        })
    })?;
    assert_eq!(
        effects,
        [
            "ui-dependency-inspect",
            "ui-dependency-fetch",
            "ui-dependency-extract",
            "ui-dependency-verify",
            "ui-dependency-publish",
            "ui-dependency-receipt",
        ]
    );
    Ok(())
}

#[test]
fn rejected_ui_dependency_never_reaches_publication() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(&automation::runner()?, &["ui-dependency"], |request| {
        effects.push(request.action.clone());
        if request.action == "ui-dependency-verify" {
            bail!("injected bundle digest rejection");
        }
        Ok(if request.action == "ui-dependency-inspect" {
            json!({"installed": false})
        } else {
            json!({})
        })
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected bundle digest rejection")
    );
    assert_eq!(
        effects.last().map(String::as_str),
        Some("ui-dependency-verify")
    );
    Ok(())
}

#[test]
fn stale_or_modified_workflow_executables_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = automation::runner()?;
    let executable = directory.path().join("day2-workflows");
    std::fs::copy(&original, &executable)?;
    let metadata = executable.with_extension("json");
    std::fs::copy(original.with_extension("json"), &metadata)?;
    assert!(automation::checked_runner(&executable).is_ok());
    let mut pin: Value = serde_json::from_slice(&std::fs::read(&metadata)?)?;
    pin["sources"] = "stale-recipe".into();
    std::fs::write(&metadata, serde_json::to_vec(&pin)?)?;
    assert!(automation::checked_runner(&executable).is_err());
    pin["sources"] = automation::source_digest().into();
    pin["toolchain"] = "another-compiler".into();
    std::fs::write(&metadata, serde_json::to_vec(&pin)?)?;
    assert!(automation::checked_runner(&executable).is_err());
    pin["toolchain"] = automation::toolchain_digest().into();
    std::fs::write(&metadata, serde_json::to_vec(&pin)?)?;
    assert!(automation::checked_runner(&executable).is_ok());
    let mut legacy = pin.clone();
    legacy.as_object_mut().unwrap().remove("toolchain");
    std::fs::write(&metadata, serde_json::to_vec(&legacy)?)?;
    assert!(automation::checked_runner(&executable).is_err());
    std::fs::write(&metadata, serde_json::to_vec(&pin)?)?;
    std::fs::write(&executable, b"modified executable")?;
    assert!(automation::checked_runner(&executable).is_err());
    Ok(())
}

#[test]
fn credential_discovery_is_required_before_binding_and_refusal_stops_the_build() -> Result<()> {
    for refused in [false, true] {
        let mut effects = Vec::new();
        let result = automation::run(&automation::runner()?, &["build-recipe"], |request| {
            effects.push(request.action.clone());
            if refused && request.action == "build-credential-contract" {
                bail!("injected credential declaration rejection");
            }
            Ok(json!({}))
        });
        let position = |name: &str| effects.iter().position(|effect| effect == name).unwrap();
        assert!(position("build-app-types") < position("build-credential-contract"));
        assert!(position("build-host") < position("build-credential-contract"));
        assert!(position("build-connection-contract") < position("build-operation-handles"));
        assert!(position("build-operation-handles") < position("build-credential-contract"));
        if refused {
            assert!(result.is_err());
            assert_eq!(
                effects.last().map(String::as_str),
                Some("build-credential-contract")
            );
            assert!(!effects.iter().any(|effect| matches!(
                effect.as_str(),
                "build-bind" | "build-link" | "build-publish"
            )));
        } else {
            result?;
            assert!(position("build-credential-contract") < position("build-bind"));
        }
    }
    Ok(())
}

#[test]
fn the_tested_build_runs_the_app_tests_after_its_check_and_before_linking() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(
        &automation::runner()?,
        &["build-tested-recipe"],
        |request| {
            effects.push(request.action.clone());
            Ok(json!({}))
        },
    )?;
    let position = |name: &str| effects.iter().position(|effect| effect == name).unwrap();
    assert!(position("build-check") + 1 == position("build-test"));
    assert!(position("build-test") + 1 == position("build-link"));
    let mut untested = Vec::new();
    automation::run(&automation::runner()?, &["build-recipe"], |request| {
        untested.push(request.action.clone());
        Ok(json!({}))
    })?;
    assert!(!untested.iter().any(|effect| effect == "build-test"));
    assert_eq!(untested.len() + 1, effects.len());
    Ok(())
}

/// The effects `day2 ci check`'s recipe requests for a route, with each
/// session step named.
fn ci_check_effects(route: Value) -> Result<Vec<String>> {
    let built = build_receipt(
        "/platform/artifacts/0000",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "42",
    );
    let mut effects = Vec::new();
    automation::run(
        &automation::runner()?,
        &["ci-check-session", "/work/request.json"],
        |request| {
            let input = request.decode::<Value>()?;
            match request.action.as_str() {
                "ci-check-prepare" => {
                    assert_eq!(input, json!({"request": "/work/request.json"}));
                    effects.push(request.action.clone());
                    Ok(json!({}))
                }
                "ci-check-step" => {
                    let name = input["name"].as_str().unwrap_or_default().to_owned();
                    effects.push(name.clone());
                    Ok(if name == "route" {
                        route.clone()
                    } else {
                        json!({})
                    })
                }
                "chrome-extension-verify" => {
                    assert_eq!(input, json!({"source": "/work/head/app"}));
                    effects.push(request.action.clone());
                    Ok(json!({"declared": false}))
                }
                "build-source" => {
                    assert_eq!(
                        input,
                        json!({"source": "/work/head/app", "seed": "42", "cases": 6, "tests": true})
                    );
                    effects.push(request.action.clone());
                    Ok(serde_json::to_value(&built)?)
                }
                action => bail!("unexpected CI check capability: {action}"),
            }
        },
    )?;
    Ok(effects)
}

#[test]
fn ci_check_runs_each_selected_lane_once_in_order() -> Result<()> {
    let route = |native: bool, extension: bool, javascript: bool| {
        json!({
            "root": "/work/head/app", "seed": 42, "cases": 6,
            "native": native, "extension": extension, "javascript": javascript,
        })
    };
    assert_eq!(
        ci_check_effects(route(true, true, true))?,
        [
            "ci-check-prepare",
            "route",
            "javascript",
            "format",
            "chrome-extension-verify",
            "build-source",
            "artifact",
            "result",
        ]
    );
    assert_eq!(
        ci_check_effects(route(false, true, false))?,
        [
            "ci-check-prepare",
            "route",
            "chrome-extension-verify",
            "result"
        ]
    );
    assert_eq!(
        ci_check_effects(route(false, false, false))?,
        ["ci-check-prepare", "route", "result"]
    );
    Ok(())
}

#[test]
fn rejected_compiler_admission_prevents_linking_and_publication() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(&automation::runner()?, &["build-recipe"], |request| {
        effects.push(request.action.clone());
        if request.action == "build-admission" {
            bail!("injected compiler rejection");
        }
        Ok(json!({}))
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("injected compiler rejection")
    );
    assert_eq!(effects.last().map(String::as_str), Some("build-admission"));
    assert!(
        !effects
            .iter()
            .any(|name| name == "build-link" || name == "build-publish")
    );
    Ok(())
}

#[test]
fn roc_selects_one_example_and_stops_before_command_drain_when_replay_fails() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["exercise", "chosen", "0"],
        |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "dev-examples" => Ok(json!([
                    {"name":"ignored","error":"","steps":[{"kind":"command","operation":"must_not_run","payload":"{}"}]},
                    {"name":"chosen","error":"","steps":[{"kind":"command","operation":"submit","payload":"{}"}]}
                ])),
                "dev-example" => {
                    assert_eq!(request.decode::<Value>()?["name"], "chosen");
                    Ok(json!({}))
                }
                "dev-invoke" => {
                    assert_eq!(request.decode::<Value>()?["operation"], "submit");
                    Ok(json!({}))
                }
                "dev-replay" => bail!("replay mismatch"),
                _ => Ok(json!({})),
            }
        },
    );
    assert!(result.unwrap_err().to_string().contains("replay mismatch"));
    assert!(
        !effects
            .iter()
            .any(|name| ["dev-drain", "dev-finish", "dev-samples"].contains(&name.as_str()))
    );
    Ok(())
}

#[test]
fn generated_example_is_prepared_at_its_ordered_stage_before_shared_checks() -> Result<()> {
    let mut actions = Vec::new();
    let mut invoked = Vec::new();
    let mut current_snapshot = "empty".to_owned();
    automation::run(
        &automation::runner()?,
        &["exercise", "chosen", "0"],
        |request| {
            actions.push(request.action.clone());
            match request.action.as_str() {
                "dev-examples" => Ok(json!([{
                    "name":"chosen",
                    "error":"",
                    "steps":[
                        {"kind":"command","operation":"create","payload":"{}"},
                        {"kind":"generated","operation":"add","payload":"0"}
                    ]
                }])),
                "dev-example" => Ok(json!({})),
                "dev-prepare-example" => {
                    assert_eq!(
                        actions.get(actions.len() - 2).map(String::as_str),
                        Some("dev-step-complete")
                    );
                    assert_eq!(current_snapshot, "space-created");
                    Ok(json!({
                        "kind":"command",
                        "operation":"add",
                        "payload":format!(r#"{{"space":"{current_snapshot}"}}"#)
                    }))
                }
                "dev-invoke" => {
                    let input: Value = request.decode()?;
                    assert_eq!(input["kind"], "command");
                    match input["operation"].as_str().unwrap() {
                        "create" => current_snapshot = "space-created".into(),
                        "add" => assert_eq!(input["payload"], r#"{"space":"space-created"}"#),
                        operation => panic!("unexpected generated example operation: {operation}"),
                    }
                    invoked.push(input["operation"].as_str().unwrap().to_owned());
                    Ok(json!({}))
                }
                _ => Ok(json!({})),
            }
        },
    )?;
    assert_eq!(invoked, ["create", "add"]);
    let prepared = actions
        .iter()
        .position(|action| action == "dev-prepare-example")
        .unwrap();
    let invoked = actions
        .iter()
        .rposition(|action| action == "dev-invoke")
        .unwrap();
    assert_eq!(invoked, prepared + 1);
    assert_eq!(
        &actions[invoked + 1..invoked + 9],
        [
            "dev-assert",
            "dev-replay",
            "dev-duplicate",
            "dev-invalid",
            "dev-properties",
            "dev-drain",
            "dev-properties",
            "dev-step-complete",
        ]
    );
    Ok(())
}

#[test]
fn generated_cases_use_the_same_checks_as_examples_and_empty_apps_are_explicit() -> Result<()> {
    for count in [0, 3] {
        let mut invoked = Vec::new();
        let mut replayed = 0;
        let mut properties = 0;
        let mut finished = false;
        automation::run(
            &automation::runner()?,
            &["exercise", "", &count.to_string()],
            |request| {
                match request.action.as_str() {
                "dev-examples" => Ok(json!([])),
                "dev-samples" => Ok(json!((0..count).map(|index| json!({"generator":"reports","operation":"submit","seed":index.to_string(),"input":format!("{{\"index\":{index}}}"),"error":""})).collect::<Vec<_>>())),
                "dev-setups" => Ok(json!([])),
                "dev-prepare-sample" => Ok(json!({"kind":"command","operation":"submit","payload":format!("{{\"index\":{}}}", invoked.len())})),
                "dev-invoke" => { invoked.push(request.decode::<Value>()?["payload"].clone()); Ok(json!({})) }
                "dev-replay" => { replayed += 1; Ok(json!({})) }
                "dev-properties" => { properties += 1; Ok(json!({})) }
                "dev-finish" => { finished = true; Ok(json!({})) }
                _ => Ok(json!({})),
            }
            },
        )?;
        assert_eq!(invoked.len(), count);
        assert_eq!(replayed, count);
        assert_eq!(properties, 1 + count * 2);
        assert!(finished);
    }
    Ok(())
}

#[test]
fn roc_checks_each_declared_setup_before_generating_the_positive_input() -> Result<()> {
    for fail_replay in [false, true] {
        let mut invoked = Vec::new();
        let mut actions = Vec::new();
        let result = automation::run(&automation::runner()?, &["exercise", "", "1"], |request| {
            actions.push(request.action.clone());
            match request.action.as_str() {
                "dev-examples" => Ok(json!([])),
                "dev-samples" => Ok(json!([{
                    "generator":"read", "operation":"read", "seed":"42", "input":"", "error":""
                }])),
                "dev-setups" => Ok(json!([
                    {"kind":"command", "operation":"prepare_first", "payload":"{}"},
                    {"kind":"command", "operation":"prepare_second", "payload":"{}"}
                ])),
                "dev-prepare-sample" => {
                    assert_eq!(invoked, ["prepare_first", "prepare_second"]);
                    Ok(json!({"kind":"command", "operation":"read", "payload":"{}"}))
                }
                "dev-invoke" => {
                    invoked.push(
                        request.decode::<Value>()?["operation"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                    );
                    Ok(json!({}))
                }
                "dev-replay" if fail_replay => bail!("setup replay mismatch"),
                _ => Ok(json!({})),
            }
        });
        if fail_replay {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("setup replay mismatch")
            );
            assert_eq!(invoked, ["prepare_first"]);
            assert!(
                !actions
                    .iter()
                    .any(|action| action == "dev-prepare-sample" || action == "dev-finish")
            );
        } else {
            result?;
            assert_eq!(invoked, ["prepare_first", "prepare_second", "read"]);
            for check in [
                "dev-assert",
                "dev-replay",
                "dev-duplicate",
                "dev-invalid",
                "dev-drain",
                "dev-step-complete",
            ] {
                assert_eq!(
                    actions
                        .iter()
                        .filter(|action| action.as_str() == check)
                        .count(),
                    3,
                    "{check}"
                );
            }
            assert_eq!(
                actions
                    .iter()
                    .filter(|action| action.as_str() == "dev-properties")
                    .count(),
                7
            );
        }
    }
    Ok(())
}

#[test]
fn failed_infrastructure_validation_prevents_plan_and_receipt() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &[
            "platform",
            "infra",
            "plan",
            "approved.json",
            "new-directory",
        ],
        |request| match request.action.as_str() {
            "infra-settings" => Ok(
                json!({"installation":"exampleco","environment":"sandbox","apps":["reports"],"configuration_digest":"sha256:approved"}),
            ),
            "infra-prepare" => {
                let input: Value = request.decode()?;
                assert_eq!(input["graph"]["resources"][1]["key"], "app_reports");
                assert_eq!(input["configuration_digest"], "sha256:approved");
                Ok(json!({}))
            }
            "infra-command" => {
                let input: Value = request.decode()?;
                effects.push(input["operation"].as_str().unwrap().to_owned());
                if input["operation"] == "validate" {
                    bail!("invalid infrastructure");
                }
                Ok(json!({}))
            }
            _ => panic!(
                "unexpected effect after failed validation: {}",
                request.action
            ),
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("invalid infrastructure")
    );
    assert_eq!(effects, ["version", "init", "validate"]);
    Ok(())
}

/// Runs an instance session against a fake host: `failing` lists the
/// `label operation` steps that fail, and `unreleased` the day2-app roots whose
/// app has no release selection. Returns the effects in order.
fn instance_session(session: &str, failing: &[&str]) -> Result<Vec<String>> {
    instance_session_with(session, failing, &[])
}

fn instance_session_with(
    session: &str,
    failing: &[&str],
    unreleased: &[&str],
) -> Result<Vec<String>> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/InstanceRoots.roc")
    );
    let mut effects = Vec::new();
    let receipt = automation::run(
        &automation::runner()?,
        &[session, "/private/instance/request.json"],
        |request| {
            let input: Value = request.decode()?;
            match request.action.as_str() {
                "instance-roots-prepare" => {
                    // The host reads the CLI's rendered request from its file.
                    assert_eq!(input, json!({"request": "/private/instance/request.json"}));
                    effects.push("prepare".to_owned());
                    Ok(json!({"roots":[
                        {"label":"project","shared":true,"needs":[],"release":false},
                        {"label":"cluster","shared":true,"needs":[],"release":false},
                        {"label":"app-edge/home","shared":false,"needs":[],"release":false},
                        {"label":"app-edge/go","shared":false,"needs":[],"release":false},
                        {"label":"day2-app/home","shared":false,"needs":["app-edge/home"],"release":true},
                        {"label":"day2-app/go","shared":false,"needs":["app-edge/go"],"release":true},
                    ]}))
                }
                "instance-roots-credentials" => {
                    effects.push("credentials".to_owned());
                    Ok(json!({}))
                }
                "instance-roots-operation" => {
                    let step = format!(
                        "{} {}",
                        input["label"].as_str().unwrap(),
                        input["operation"].as_str().unwrap()
                    );
                    let ok = !failing.contains(&step.as_str());
                    let released = !unreleased.contains(&input["label"].as_str().unwrap());
                    let release = input["operation"] == "release";
                    effects.push(step);
                    Ok(if release {
                        json!({ "ok": ok, "released": ok && released, "release": null })
                    } else {
                        json!({ "ok": ok })
                    })
                }
                "instance-roots-receipt" => {
                    effects.push("receipt".to_owned());
                    Ok(json!({"ok": false}))
                }
                _ => panic!("unexpected instance effect: {}", request.action),
            }
        },
    )?;
    assert_eq!(receipt, json!({"ok": false}));
    Ok(effects)
}

#[test]
fn instance_plan_reads_credentials_once_and_stops_only_the_failed_root() -> Result<()> {
    assert_eq!(
        instance_session(
            "instance-plan-session",
            &["cluster plan", "app-edge/home plan"]
        )?,
        [
            "prepare",
            "credentials",
            "project init",
            "project plan",
            "project show",
            "cluster init",
            "cluster plan",
            "app-edge/home init",
            "app-edge/home plan",
            "app-edge/go init",
            "app-edge/go plan",
            "app-edge/go show",
            "day2-app/home release",
            "day2-app/home init",
            "day2-app/home plan",
            "day2-app/home show",
            "day2-app/go release",
            "day2-app/go init",
            "day2-app/go plan",
            "day2-app/go show",
            "receipt",
        ]
    );
    Ok(())
}

#[test]
fn a_day2_app_root_reads_its_release_first_and_an_unreleased_app_runs_nothing_else() -> Result<()> {
    let effects = instance_session_with(
        "instance-plan-session",
        &["day2-app/go release"],
        &["day2-app/home"],
    )?;
    assert_eq!(
        effects[effects.len() - 3..],
        ["day2-app/home release", "day2-app/go release", "receipt"]
    );
    Ok(())
}

#[test]
fn instance_apply_stops_at_a_failed_shared_root_but_not_at_an_app_edge() -> Result<()> {
    let applied = |label: &str| {
        ["init", "plan", "show", "apply"].map(|operation| format!("{label} {operation}"))
    };
    let released = |label: &str| {
        let mut steps = vec![format!("{label} release")];
        steps.extend(applied(label));
        steps
    };
    // An app edge that fails stops only itself and its app's day2-app root.
    let mut expected = vec!["prepare".to_owned(), "credentials".to_owned()];
    expected.extend(applied("project"));
    expected.extend(applied("cluster"));
    expected.extend(applied("app-edge/home"));
    expected.extend(applied("app-edge/go"));
    expected.extend(released("day2-app/go"));
    expected.push("receipt".to_owned());
    assert_eq!(
        instance_session("instance-apply-session", &["app-edge/home apply"])?,
        expected
    );
    // A shared root that fails, here at a refused or failed apply, stops every later root.
    let mut expected = vec!["prepare".to_owned(), "credentials".to_owned()];
    expected.extend(applied("project"));
    expected.extend(applied("cluster"));
    expected.push("receipt".to_owned());
    assert_eq!(
        instance_session("instance-apply-session", &["cluster apply"])?,
        expected
    );
    // A day2-app root that fails stops only itself; an unreleased one runs nothing after its release.
    let mut expected = vec!["prepare".to_owned(), "credentials".to_owned()];
    for label in ["project", "cluster", "app-edge/home", "app-edge/go"] {
        expected.extend(applied(label));
    }
    expected.extend([
        "day2-app/home release".to_owned(),
        "day2-app/home init".to_owned(),
    ]);
    expected.push("day2-app/go release".to_owned());
    expected.push("receipt".to_owned());
    assert_eq!(
        instance_session_with(
            "instance-apply-session",
            &["day2-app/home init"],
            &["day2-app/go"]
        )?,
        expected
    );
    Ok(())
}

#[test]
fn instance_sessions_have_no_platform_entry() -> Result<()> {
    for session in ["instance-plan", "instance-apply"] {
        let result = automation::run(
            &automation::runner()?,
            &["platform", session, "/private/instance/request.json"],
            |request| panic!("unexpected effect: {}", request.action),
        );
        assert!(result.is_err(), "{session}");
    }
    Ok(())
}

/// Runs a release session against a fake host in which the step `failing`
/// fails. Returns the session's result and its effects in order.
fn release_session(session: &str, failing: &str) -> Result<(Result<Value>, Vec<String>)> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/InstanceRelease.roc")
    );
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &[session, "/private/release/request.json"],
        |request| {
            let input: Value = request.decode()?;
            let step = match request.action.as_str() {
                "instance-release-prepare" => {
                    // The host reads the CLI's rendered request from its file.
                    assert_eq!(input, json!({"request": "/private/release/request.json"}));
                    "prepare".to_owned()
                }
                "instance-release-image" => format!("image {}", input["name"].as_str().unwrap()),
                "instance-release-blob" => format!("blob {}", input["name"].as_str().unwrap()),
                "instance-release-manifest" | "instance-release-operator" => {
                    assert_eq!(input, json!({}));
                    request
                        .action
                        .trim_start_matches("instance-release-")
                        .to_owned()
                }
                _ => panic!("unexpected release effect: {}", request.action),
            };
            effects.push(step.clone());
            if step == failing {
                bail!("injected {step} refusal");
            }
            Ok(json!({ "step": step }))
        },
    );
    Ok((result, effects))
}

#[test]
fn release_publication_verifies_images_then_blobs_and_publishes_the_manifest_last() -> Result<()> {
    let (result, effects) = release_session("instance-release-publish-session", "")?;
    assert_eq!(result?, json!({"step": "manifest"}));
    assert_eq!(
        effects,
        [
            "prepare",
            "image runtime",
            "image tooling",
            "blob native",
            "blob strict",
            "blob distribution",
            "blob operator",
            "manifest",
        ]
    );
    // A refused image stops before anything is uploaded; a failed upload stops
    // before the manifest, so no release becomes selectable.
    let (result, effects) = release_session("instance-release-publish-session", "image tooling")?;
    assert!(result.is_err());
    assert_eq!(effects, ["prepare", "image runtime", "image tooling"]);
    let (result, effects) =
        release_session("instance-release-publish-session", "blob distribution")?;
    assert!(result.is_err());
    assert_eq!(
        effects.last().map(String::as_str),
        Some("blob distribution")
    );
    assert!(!effects.iter().any(|step| step == "manifest"));
    Ok(())
}

#[test]
fn release_fetch_binds_each_blob_before_the_operator() -> Result<()> {
    let (result, effects) = release_session("instance-release-fetch-session", "")?;
    assert_eq!(result?, json!({"step": "operator"}));
    assert_eq!(
        effects,
        [
            "prepare",
            "blob manifest",
            "blob distribution",
            "blob native",
            "blob strict",
            "operator",
        ]
    );
    let (result, effects) = release_session("instance-release-fetch-session", "blob native")?;
    assert!(result.is_err());
    assert_eq!(
        effects,
        [
            "prepare",
            "blob manifest",
            "blob distribution",
            "blob native"
        ]
    );
    for session in ["instance-release-publish", "instance-release-fetch"] {
        let result = automation::run(
            &automation::runner()?,
            &["platform", session, "/private/release/request.json"],
            |request| panic!("unexpected effect: {}", request.action),
        );
        assert!(result.is_err(), "{session}");
    }
    Ok(())
}

/// Runs a source session against a fake host in which the step `failing`
/// fails. Returns the session's result and its effects in order.
fn source_session(session: &str, failing: &str) -> Result<(Result<Value>, Vec<String>)> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/InstanceSource.roc")
    );
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &[session, "/private/source/request.json"],
        |request| {
            let input: Value = request.decode()?;
            let step = match request.action.as_str() {
                "instance-source-prepare" => {
                    // The host reads the CLI's rendered request from its file.
                    assert_eq!(input, json!({"request": "/private/source/request.json"}));
                    "prepare".to_owned()
                }
                "instance-source-step" => input["name"].as_str().unwrap().to_owned(),
                _ => panic!("unexpected source effect: {}", request.action),
            };
            effects.push(step.clone());
            if step == failing {
                bail!("retryable: source_temporarily_unavailable");
            }
            Ok(json!({ "step": step }))
        },
    );
    Ok((result, effects))
}

#[test]
fn source_sessions_prepare_then_run_each_step_in_order() -> Result<()> {
    for (session, steps) in [
        ("instance-source-head-session", vec!["head"]),
        ("instance-source-archive-session", vec!["archive"]),
        ("instance-source-controls-session", vec!["controls"]),
        (
            "instance-source-verify-controls-session",
            vec!["controls", "release"],
        ),
        (
            "instance-source-checked-artifact-session",
            vec!["run", "job", "artifact", "download", "attempt"],
        ),
    ] {
        let (result, effects) = source_session(session, "")?;
        assert_eq!(result?, json!({"step": steps.last().unwrap()}), "{session}");
        let mut expected = vec!["prepare"];
        expected.extend(&steps);
        assert_eq!(effects, expected, "{session}");
    }
    // A failed step stops the session, and its error reaches the host verbatim:
    // nothing is written after a refused download, and controls that are not the
    // approved ones stop the check before the release is read.
    let (result, effects) = source_session("instance-source-checked-artifact-session", "download")?;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "retryable: source_temporarily_unavailable"
    );
    assert_eq!(effects, ["prepare", "run", "job", "artifact", "download"]);
    let (result, effects) = source_session("instance-source-verify-controls-session", "controls")?;
    assert!(result.is_err());
    assert_eq!(effects, ["prepare", "controls"]);
    let (result, effects) = source_session("instance-source-head-session", "prepare")?;
    assert!(result.is_err());
    assert_eq!(effects, ["prepare"]);
    for mode in crate::instance_source::Mode::ALL {
        let session = format!("instance-source-{}", mode.name());
        let result = automation::run(
            &automation::runner()?,
            &["platform", &session, "/private/source/request.json"],
            |request| panic!("unexpected effect: {}", request.action),
        );
        assert!(result.is_err(), "{session}");
    }
    Ok(())
}

/// Runs a candidate session against a fake host whose lookups find what
/// `found` names and in which the step `failing` fails. Returns the session's
/// result and its effects in order.
fn candidate_session(
    session: &str,
    found: &[&str],
    failing: &str,
) -> Result<(Result<Value>, Vec<String>)> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/InstanceCandidate.roc")
    );
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &[session, "/private/candidate/request.json"],
        |request| {
            let input: Value = request.decode()?;
            let step = match request.action.as_str() {
                "instance-candidate-prepare" => {
                    assert_eq!(input, json!({"request": "/private/candidate/request.json"}));
                    "prepare".to_owned()
                }
                "instance-candidate-step" => input["name"].as_str().unwrap().to_owned(),
                _ => panic!("unexpected candidate effect: {}", request.action),
            };
            effects.push(step.clone());
            if step == failing {
                bail!("retryable: source_temporarily_unavailable");
            }
            if step == "stored" || step == "cached" {
                return Ok(json!({ "found": found.contains(&step.as_str()) }));
            }
            Ok(json!({ "step": step }))
        },
    );
    Ok((result, effects))
}

fn deploy_session(path: &str, failing: &str) -> Result<(Result<Value>, Vec<String>)> {
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &[
            "instance-deploy-session",
            "/private/deploy.json",
            "/private/roots.json",
        ],
        |request| {
            let input: Value = request.decode()?;
            let step = match request.action.as_str() {
                "instance-deploy-prepare" => {
                    assert_eq!(input["request"], "/private/deploy.json");
                    "prepare".to_owned()
                }
                "instance-deploy-step" => input["name"].as_str().unwrap().to_owned(),
                "instance-roots-prepare" => {
                    assert_eq!(input["request"], "/private/roots.json");
                    "roots-prepare".to_owned()
                }
                "instance-roots-operation" => {
                    assert_eq!(input["label"], "day2-app/links");
                    format!("roots-{}", input["operation"].as_str().unwrap())
                }
                "instance-roots-credentials" => "roots-credentials".to_owned(),
                "instance-roots-summary" => "roots-summary".to_owned(),
                "instance-roots-receipt" => "roots-receipt".to_owned(),
                action => panic!("unexpected deploy effect {action}"),
            };
            effects.push(step.clone());
            if step == failing {
                bail!("cannot {step}");
            }
            Ok(match step.as_str() {
                "roots-prepare" | "roots-summary" => {
                    json!({"roots": [{"label": "day2-app/links", "shared": false, "needs": [], "release": true}]})
                }
                "roots-release" => json!({
                    "ok": true, "released": true, "release": {"candidate": "candidate", "commit": "commit",
                    "image": "image", "artifact_id": "artifact", "tooling_image": "tooling"},
                }),
                "roots-target" => {
                    json!({"ok": true, "instance": {"path": "instance.json", "digest": "target", "bytes": 42}})
                }
                "observe" => {
                    let release: Value = serde_json::from_str(input["detail"].as_str().unwrap())?;
                    assert_eq!(release["candidate"], "candidate");
                    json!({"path": path})
                }
                "target" => {
                    let target: Value = serde_json::from_str(input["detail"].as_str().unwrap())?;
                    assert_eq!(target["digest"], "target");
                    json!({})
                }
                "finish" => {
                    let outcome: Value = serde_json::from_str(input["detail"].as_str().unwrap())?;
                    if let Some(error) = outcome["error"].as_str() {
                        bail!("classified: {error}");
                    }
                    json!({"finished": true})
                }
                _ => json!({"ok": true}),
            })
        },
    );
    Ok((result, effects))
}

#[test]
fn deploy_recipe_orders_the_root_apply_after_backup_and_activation() -> Result<()> {
    let prefix = [
        "prepare",
        "operator",
        "credentials",
        "roots-prepare",
        "roots-credentials",
        "roots-release",
        "roots-init",
        "observe",
    ];
    let fresh = [
        "roots-summary",
        "roots-target",
        "target",
        "deadline",
        "backup",
        "archive-before",
        "activate",
    ];
    let roll = [
        "apply",
        "roots-summary",
        "roots-selected",
        "roots-plan",
        "roots-show",
        "roots-apply",
        "applied",
        "rollout",
        "readback",
        "archive-after",
        "roots-receipt",
        "finish",
    ];
    let (result, observed) = deploy_session("fresh", "")?;
    assert_eq!(result?, json!({"finished": true}));
    assert_eq!(observed, [prefix.as_slice(), &fresh, &roll].concat());
    for path in ["install", "serving", "activated"] {
        let (result, observed) = deploy_session(path, "")?;
        assert_eq!(result?, json!({"finished": true}));
        assert_eq!(observed, [prefix.as_slice(), &["deadline"], &roll].concat());
    }
    Ok(())
}

#[test]
fn deploy_recipe_archives_and_classifies_failure_without_advancing_the_workload() -> Result<()> {
    for failure in [
        "observe",
        "roots-target",
        "backup",
        "archive-before",
        "activate",
        "roots-apply",
        "rollout",
    ] {
        let (result, steps) = deploy_session("fresh", failure)?;
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("classified: cannot {failure}")
        );
        assert_eq!(
            &steps[steps.len() - 4..],
            &[failure, "archive-after", "roots-receipt", "finish"]
        );
    }
    let result = automation::run(
        &automation::runner()?,
        &[
            "platform",
            "instance-deploy-session",
            "/private/deploy.json",
            "/private/roots.json",
        ],
        |_| panic!("deploy session is not a platform operation"),
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn candidate_sessions_prepare_then_run_each_step_in_order() -> Result<()> {
    let built = [
        "prepare", "stored", "archive", "inputs", "controls", "cached", "run", "job", "artifact",
        "download", "attempt", "release", "stage", "native", "collect", "record",
    ];
    for (session, found, steps) in [
        ("instance-candidate-build-session", vec![], built.to_vec()),
        (
            "instance-candidate-build-session",
            vec!["stored"],
            vec!["prepare", "stored", "record"],
        ),
        (
            "instance-candidate-build-session",
            vec!["cached"],
            vec![
                "prepare", "stored", "archive", "inputs", "controls", "cached", "reuse", "record",
            ],
        ),
        (
            "instance-candidate-preflight-session",
            vec![],
            vec!["prepare", "validate", "stage", "probe"],
        ),
        (
            "instance-candidate-check-session",
            vec![],
            vec!["prepare", "validate"],
        ),
        (
            "instance-candidate-native-build-session",
            vec![],
            vec![
                "prepare", "request", "slot", "inputs", "artifact", "tooling", "protocol",
                "security", "package", "push", "result",
            ],
        ),
        (
            "instance-candidate-native-probe-session",
            vec![],
            vec!["prepare", "request", "probe"],
        ),
    ] {
        let (result, effects) = candidate_session(session, &found, "")?;
        assert_eq!(result?, json!({"step": steps.last().unwrap()}), "{session}");
        assert_eq!(effects, steps, "{session}");
    }
    // A failed step stops the session, and its error reaches the host verbatim:
    // a refused CI-control check never reaches the cached lookup or the build host.
    let (result, effects) = candidate_session("instance-candidate-build-session", &[], "controls")?;
    assert_eq!(
        format!("{:#}", result.unwrap_err()),
        "retryable: source_temporarily_unavailable"
    );
    assert_eq!(
        effects,
        ["prepare", "stored", "archive", "inputs", "controls"]
    );
    let (result, effects) = candidate_session("instance-candidate-build-session", &[], "native")?;
    assert!(result.is_err());
    assert_eq!(effects.last().unwrap(), "native");
    for mode in crate::instance_candidate::Mode::ALL {
        let session = format!("instance-candidate-{}", mode.name());
        let result = automation::run(
            &automation::runner()?,
            &["platform", &session, "/private/candidate/request.json"],
            |request| panic!("unexpected effect: {}", request.action),
        );
        assert!(result.is_err(), "{session}");
    }
    Ok(())
}

#[test]
fn centralized_ci_runs_the_shared_roc_campaign_before_publishing_evidence() -> Result<()> {
    let mut finished = false;
    let mut receipt = false;
    let mut simulation = false;
    automation::run(
        &automation::runner()?,
        &["ci-recipe"],
        |request| match request.action.as_str() {
            "simulation-open" => {
                assert_eq!(request.decode::<Value>()?["cases"], 8);
                Ok(json!({"regressions":[0],"cases":[0]}))
            }
            "simulation-receipt" => {
                simulation = true;
                Ok(json!({}))
            }
            "ci-materialize" => {
                assert!(simulation);
                Ok(json!({}))
            }
            "ci-development" => {
                Ok(json!({"artifact":"pinned-artifact","output":"private-evidence"}))
            }
            "dev-create" => {
                let input: Value = request.decode()?;
                assert_eq!(input["artifact"], "pinned-artifact");
                assert_eq!(input["output"], "private-evidence");
                assert_eq!(input["count"], 16);
                Ok(json!({}))
            }
            "dev-examples" | "dev-samples" => Ok(json!([])),
            "dev-finish" => {
                finished = true;
                Ok(json!({}))
            }
            "ci-evidence" => {
                assert!(simulation);
                assert!(finished);
                receipt = true;
                Ok(json!({}))
            }
            _ => Ok(json!({})),
        },
    )?;
    assert!(receipt);
    Ok(())
}

#[test]
fn control_simulation_runs_corpus_then_cases_and_replays_each_before_receipt() -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Index {
        index: u32,
    }

    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/Simulation.roc")
    );
    let mut effects = Vec::new();
    let mut regression = 0;
    let mut generated = 0;
    automation::run(
        &automation::runner()?,
        &["simulate-control", "42", "2"],
        |request| {
            let input: Value = request.decode()?;
            effects.push((request.action.clone(), input.clone()));
            match request.action.as_str() {
                "simulation-open" => {
                    assert_eq!(input, json!({"seed":"42","cases":2}));
                    return Ok(json!({"regressions":[0,1],"cases":[0,1]}));
                }
                "simulation-regression" => {
                    // Roc's `{ index }` is a block, not a one-field record.
                    let value: Index = request.decode()?;
                    assert_eq!(value.index, regression);
                    regression += 1;
                }
                "simulation-case" => {
                    let value: Index = request.decode()?;
                    assert_eq!(value.index, generated);
                    generated += 1;
                }
                "simulation-check-replay" | "simulation-receipt" => {
                    assert_eq!(input, json!({}));
                }
                _ => bail!("unexpected simulation effect"),
            }
            Ok(json!({}))
        },
    )?;
    assert_eq!(
        effects
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        [
            "simulation-open",
            "simulation-regression",
            "simulation-check-replay",
            "simulation-regression",
            "simulation-check-replay",
            "simulation-case",
            "simulation-check-replay",
            "simulation-case",
            "simulation-check-replay",
            "simulation-receipt",
        ]
    );
    assert_eq!(effects[3].1, json!({"index":1}));
    assert_eq!(effects[5].1, json!({"index":0}));
    assert_eq!((regression, generated), (2, 2));
    Ok(())
}

#[test]
fn failed_simulation_replay_blocks_ci_and_control_verification() -> Result<()> {
    for recipe in ["ci-recipe", "control-verify"] {
        let mut effects = Vec::new();
        let result = automation::run(&automation::runner()?, &[recipe], |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "simulation-open" => Ok(json!({"regressions":[0],"cases":[0]})),
                "simulation-regression" => Ok(json!({})),
                "simulation-check-replay" => bail!("injected control replay mismatch"),
                _ => bail!("unexpected effect after simulation failure"),
            }
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected control replay mismatch")
        );
        assert_eq!(
            effects,
            [
                "simulation-open",
                "simulation-regression",
                "simulation-check-replay"
            ]
        );
    }
    for count in ["0", "129"] {
        assert!(
            automation::run(
                &automation::runner()?,
                &["simulate-control", "42", count],
                |_| bail!("invalid campaign reached host")
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn control_replay_uses_the_exact_operator_trace_path() -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Replay {
        trace: String,
    }

    let mut count = 0;
    automation::run(
        &automation::runner()?,
        &["replay-control", "/evidence/trace.json"],
        |request| {
            count += 1;
            assert_eq!(request.action, "simulation-replay");
            let value: Replay = request.decode()?;
            assert_eq!(value.trace, "/evidence/trace.json");
            assert_eq!(
                request.decode::<Value>()?,
                json!({"trace":"/evidence/trace.json"})
            );
            Ok(json!({"status":"reproduced"}))
        },
    )?;
    assert_eq!(count, 1);
    Ok(())
}

const PROVIDER_PROBES: [&str; 10] = [
    "provider-open",
    "provider-aliases",
    "provider-lost-ack-dispatch",
    "provider-lost-ack-observe",
    "provider-late-hold",
    "provider-late-observe",
    "provider-late-deliver",
    "provider-late-reconcile",
    "provider-quiescence",
    "provider-receipt",
];

#[test]
fn provider_conformance_runs_fixed_probes_without_claiming_fixture_qualification() -> Result<()> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/ProviderConformance.roc")
    );
    let receipt = json!({
        "observations": ["canonical_aliases", "late_application"],
        "qualified": false,
        "unfulfilled": ["exact_effect_attribution", "deployment_controller_quiescence"]
    });
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["provider-conformance"],
        |request| {
            assert_eq!(request.decode::<Value>()?, json!({}));
            effects.push(request.action.clone());
            if request.action == "provider-receipt" {
                Ok(receipt.clone())
            } else {
                Ok(json!({}))
            }
        },
    )?;
    assert_eq!(effects, PROVIDER_PROBES);
    assert_eq!(result, receipt);
    Ok(())
}

#[test]
fn provider_conformance_stops_at_every_failed_boundary_without_retry() -> Result<()> {
    let runner = automation::runner()?;
    for (index, failed) in PROVIDER_PROBES.iter().enumerate() {
        let mut effects = Vec::new();
        let result = automation::run(&runner, &["provider-conformance"], |request| {
            assert_eq!(request.decode::<Value>()?, json!({}));
            effects.push(request.action.clone());
            if request.action == *failed {
                bail!("injected provider probe failure: {failed}");
            }
            Ok(json!({}))
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected provider probe failure")
        );
        assert_eq!(effects, PROVIDER_PROBES[..=index]);
    }
    Ok(())
}

#[test]
fn provider_conformance_rejects_unknown_recipe_and_supplied_configuration_arguments() -> Result<()>
{
    let runner = automation::runner()?;
    for arguments in [
        vec!["provider-conformance-unknown"],
        vec!["provider-conformance", "untrusted-profile.json"],
        vec!["provider-conformance", "--skip-quiescence"],
    ] {
        let mut effects = 0;
        let result = automation::run(&runner, &arguments, |_| {
            effects += 1;
            bail!("unadmitted recipe reached native host");
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown private workflow")
        );
        assert_eq!(effects, 0);
    }
    Ok(())
}

const CARTA_QUALIFICATION_STEPS: [&str; 5] = [
    "carta-qualification-open",
    "carta-qualification-scratch",
    "carta-qualification-collect",
    "carta-qualification-discard",
    "carta-qualification-receipt",
];

#[test]
fn carta_qualification_runs_fixed_steps_and_returns_the_guarded_receipt_result() -> Result<()> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/CartaQualification.roc")
    );
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["carta-qualification"],
        |request| {
            assert_eq!(request.decode::<Value>()?, json!({}));
            effects.push(request.action.clone());
            if request.action == "carta-qualification-receipt" {
                Ok(json!({"outcome":"captured"}))
            } else {
                Ok(json!({}))
            }
        },
    )?;
    assert_eq!(effects, CARTA_QUALIFICATION_STEPS);
    assert_eq!(result, json!({"outcome":"captured"}));
    Ok(())
}

#[test]
fn carta_qualification_stops_at_every_failed_step_without_retry() -> Result<()> {
    let runner = automation::runner()?;
    for (index, failed) in CARTA_QUALIFICATION_STEPS.iter().enumerate() {
        let mut effects = Vec::new();
        let result = automation::run(&runner, &["carta-qualification"], |request| {
            effects.push(request.action.clone());
            if request.action == *failed {
                bail!("injected carta qualification failure: {failed}");
            }
            Ok(json!({}))
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected carta qualification failure")
        );
        assert_eq!(effects, CARTA_QUALIFICATION_STEPS[..=index]);
    }
    for arguments in [
        vec!["carta-qualification", "profile.json"],
        vec!["carta-qualification", "--production"],
    ] {
        let mut effects = 0;
        let result = automation::run(&runner, &arguments, |_| {
            effects += 1;
            bail!("unadmitted recipe reached native host");
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown private workflow")
        );
        assert_eq!(effects, 0);
    }
    Ok(())
}

const GOOGLE_WORKSPACE_QUALIFICATION_READS: [&str; 8] = [
    "google-workspace-qualification-open",
    "google-workspace-qualification-directory",
    "google-workspace-qualification-calendars",
    "google-workspace-qualification-events",
    "google-workspace-qualification-event",
    "google-workspace-qualification-conferences",
    "google-workspace-qualification-share-alias",
    "google-workspace-qualification-share",
];

/// The recipe's steps when the share asks for checks (`check`) and the
/// `visible_at`-th check, if any, finds the permission.
fn google_workspace_qualification_steps(check: bool, visible_at: Option<usize>) -> Vec<String> {
    let checks = match (check, visible_at) {
        (false, _) => 0,
        (true, Some(at)) => at,
        (true, None) => 7,
    };
    GOOGLE_WORKSPACE_QUALIFICATION_READS
        .iter()
        .map(|step| (*step).to_owned())
        .chain((0..checks).map(|_| "google-workspace-qualification-check".to_owned()))
        .chain([
            "google-workspace-qualification-discard".to_owned(),
            "google-workspace-qualification-receipt".to_owned(),
        ])
        .collect()
}

/// A host that answers the share and each check as `check` and `visible_at`
/// say, recording every step it is asked for.
fn google_workspace_qualification_host(
    check: bool,
    visible_at: Option<usize>,
    effects: &mut Vec<String>,
    request: &automation::Request,
) -> Result<Value> {
    assert_eq!(request.decode::<Value>()?, json!({}));
    effects.push(request.action.clone());
    let checks = effects
        .iter()
        .filter(|step| *step == "google-workspace-qualification-check")
        .count();
    Ok(match request.action.as_str() {
        "google-workspace-qualification-share" => json!({ "check": check }),
        "google-workspace-qualification-check" => json!({ "visible": Some(checks) == visible_at }),
        "google-workspace-qualification-receipt" => json!({"creates_sent":1}),
        _ => json!({}),
    })
}

#[test]
fn google_workspace_qualification_orders_reads_share_and_checks_until_listed() -> Result<()> {
    assert!(
        automation::SOURCES
            .iter()
            .any(|(name, _)| *name == "ops/GoogleWorkspaceQualification.roc")
    );
    let runner = automation::runner()?;
    // Listed at the third check; never listed, so seven; nothing to check.
    for (check, visible_at) in [(true, Some(3)), (true, None), (false, None)] {
        let mut effects = Vec::new();
        let result = automation::run(&runner, &["google-workspace-qualification"], |request| {
            google_workspace_qualification_host(check, visible_at, &mut effects, &request)
        })?;
        assert_eq!(
            effects,
            google_workspace_qualification_steps(check, visible_at)
        );
        assert_eq!(result, json!({"creates_sent":1}));
    }
    Ok(())
}

#[test]
fn google_workspace_qualification_stops_at_every_failed_step_without_retry() -> Result<()> {
    let runner = automation::runner()?;
    let steps = google_workspace_qualification_steps(true, Some(2));
    for index in 0..steps.len() {
        let mut effects = Vec::new();
        let result = automation::run(&runner, &["google-workspace-qualification"], |request| {
            if effects.len() == index {
                effects.push(request.action.clone());
                bail!("injected google workspace qualification failure");
            }
            google_workspace_qualification_host(true, Some(2), &mut effects, &request)
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("injected google workspace qualification failure")
        );
        assert_eq!(effects, steps[..=index]);
    }
    for arguments in [
        vec!["google-workspace-qualification", "profile.json"],
        vec!["google-workspace-qualification", "--skip-share"],
    ] {
        let mut effects = 0;
        let result = automation::run(&runner, &arguments, |_| {
            effects += 1;
            bail!("unadmitted recipe reached native host");
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown private workflow")
        );
        assert_eq!(effects, 0);
    }
    Ok(())
}

#[test]
fn local_lifecycle_and_invalid_settings_never_build_or_reset_data() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(
        &automation::runner()?,
        &["platform", "local-dev", "--status"],
        |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "local-resolve" => request.decode(),
                "local-status" => Ok(json!({"running":false})),
                _ => bail!("lifecycle command attempted a mutation"),
            }
        },
    )?;
    assert_eq!(effects, ["local-resolve", "local-status"]);
    for arguments in [
        vec!["--generated", "0"],
        vec!["--example", "demo", "--backup", "/data"],
        vec!["--stop", "--reset"],
        vec!["--port", "65536"],
    ] {
        let mut all = vec!["platform", "local-dev"];
        all.extend(arguments);
        assert!(
            automation::run(&automation::runner()?, &all, |_| bail!(
                "invalid options reached native effects"
            ))
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn failed_watched_build_recovers_without_pausing_the_working_server() -> Result<()> {
    let mut effects = Vec::new();
    let mut builds = 0;
    let mut waits = 0;
    automation::run(
        &automation::runner()?,
        &["platform", "local-dev"],
        |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "local-resolve" => request.decode(),
                "local-prepare" => Ok(json!({"running":false})),
                "build-source" => {
                    builds += 1;
                    if builds == 2 {
                        bail!("invalid edited Roc source")
                    }
                    Ok(serde_json::to_value(build_receipt(
                        "/admitted",
                        "sha256:0000",
                        "3664912422",
                    ))?)
                }
                "local-open" => {
                    // Only the selected path, not the receipt's verification.
                    assert_eq!(request.decode::<Value>()?, json!({"artifact":"/admitted"}));
                    Ok(json!({"fresh":true}))
                }
                "local-wait" => {
                    waits += 1;
                    Ok(json!({"changed":waits==1,"stopped":waits==2}))
                }
                _ => Ok(json!({})),
            }
        },
    )?;
    assert_eq!(builds, 2);
    assert!(
        !effects
            .iter()
            .any(|effect| effect == "local-pause" || effect == "local-campaign")
    );
    assert_eq!(
        &effects[effects.len() - 4..],
        [
            "local-error",
            "local-recover",
            "local-wait",
            "local-shutdown"
        ]
    );
    Ok(())
}

#[test]
fn maintain_activate_runs_every_guarded_step_in_order() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(
        &automation::runner()?,
        &["platform", "maintain", "activate", "request.json"],
        |request| {
            let step = match request.action.as_str() {
                "maintenance-workflow" => format!(
                    "workflow:{}",
                    request.decode::<Value>()?["workflow"]
                        .as_str()
                        .unwrap_or_default()
                ),
                "maintenance-migration" => format!(
                    "migration:{}",
                    request.decode::<Value>()?["step"]
                        .as_str()
                        .unwrap_or_default()
                ),
                "maintenance-open" => {
                    let input: Value = request.decode()?;
                    assert_eq!(
                        input,
                        json!({"operation": "activate", "request": "request.json"})
                    );
                    "open".into()
                }
                other => other.trim_start_matches("maintenance-").to_owned(),
            };
            effects.push(step);
            Ok(json!({"source_serving":true}))
        },
    )?;
    assert_eq!(
        effects,
        [
            "open",
            "artifacts",
            "begin-preparation",
            "measure",
            "pod",
            "operation-claim",
            "workflow:backup",
            "copy-backup",
            "rehearsal-copy",
            "migration:plan",
            "admission",
            "online-prepared",
            "stop",
            "verify-preparation",
            "workflow:backup",
            "copy-backup",
            "rehearsal-copy",
            "migration:plan",
            "admission",
            "confirm",
            "fence",
            "migration:apply",
            "workflow:authority-inspect",
            "workflow:authority-activate",
            "store-admission",
            "mark-activated",
            "finish",
        ]
    );
    Ok(())
}

#[test]
fn maintain_mark_activated_reads_the_database_before_it_marks() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(
        &automation::runner()?,
        &["platform", "maintain", "mark-activated", "request.json"],
        |request| {
            let step = match request.action.as_str() {
                "maintenance-workflow" => format!(
                    "workflow:{}",
                    request.decode::<Value>()?["workflow"]
                        .as_str()
                        .unwrap_or_default()
                ),
                "maintenance-open" => {
                    assert_eq!(
                        request.decode::<Value>()?,
                        json!({"operation": "mark-activated", "request": "request.json"})
                    );
                    "open".into()
                }
                other => other.trim_start_matches("maintenance-").to_owned(),
            };
            effects.push(step);
            Ok(json!({"source_serving":true}))
        },
    )?;
    assert_eq!(
        effects,
        [
            "open",
            "artifacts",
            "begin-preparation",
            "stop",
            "measure",
            "pod",
            "operation-claim",
            "workflow:authority-inspect",
            "mark-activated",
            "finish",
        ]
    );
    Ok(())
}

#[test]
fn activation_preparation_refusal_never_calls_stop() -> Result<()> {
    for refused in [
        "maintenance-begin-preparation",
        "maintenance-measure",
        "maintenance-pod",
        "maintenance-operation-claim",
        "maintenance-workflow",
        "maintenance-copy-backup",
        "maintenance-rehearsal-copy",
        "maintenance-migration",
        "maintenance-admission",
        "maintenance-online-prepared",
    ] {
        let mut effects = Vec::new();
        let result = automation::run(
            &automation::runner()?,
            &["platform", "maintain", "activate", "request.json"],
            |request| {
                effects.push(request.action.clone());
                if request.action == refused {
                    bail!("preparation refused");
                }
                Ok(json!({"source_serving":true}))
            },
        );
        assert!(result.is_err());
        assert_eq!(effects.last().map(String::as_str), Some(refused));
        assert!(
            !effects
                .iter()
                .any(|step| step == "maintenance-stop" || step == "maintenance-fence")
        );
    }
    Ok(())
}

#[test]
fn activation_recovery_orders_claim_cleanup_and_restore_without_a_new_activation() -> Result<()> {
    let mut effects = Vec::new();
    automation::run(
        &automation::runner()?,
        &["platform", "maintain", "recover", "private.session.json"],
        |request| {
            if request.action == "maintenance-recovery-open" {
                assert_eq!(
                    request.decode::<Value>()?,
                    json!({"journal":"private.session.json"})
                );
            }
            effects.push(request.action.clone());
            Ok(json!({"source_serving":true}))
        },
    )?;
    assert_eq!(
        effects,
        [
            "maintenance-recovery-open",
            "maintenance-recovery-claim",
            "maintenance-recovery-cleanup",
            "maintenance-recovery-restore"
        ]
    );
    Ok(())
}

#[test]
fn maintain_stops_at_a_refused_store_admission_before_the_confirmation() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["platform", "maintain", "activate", "request.json"],
        |request| {
            effects.push(request.action.clone());
            if request.action == "maintenance-admission" {
                bail!("target_store_admission_refused: unsupported credential schema version");
            }
            Ok(json!({"source_serving":true}))
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("target_store_admission_refused")
    );
    let at = |name: &str| effects.iter().position(|effect| effect == name);
    assert!(at("maintenance-migration") < at("maintenance-admission"));
    assert_eq!(
        effects.last().map(String::as_str),
        Some("maintenance-admission")
    );
    assert!(!effects.iter().any(|name| {
        [
            "maintenance-confirm",
            "maintenance-fence",
            "maintenance-finish",
        ]
        .contains(&name.as_str())
    }));
    Ok(())
}

#[test]
fn maintain_stops_at_a_refused_confirmation_before_the_fence() -> Result<()> {
    let mut effects = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["platform", "maintain", "activate", "request.json"],
        |request| {
            effects.push(request.action.clone());
            if request.action == "maintenance-confirm" {
                bail!("not confirmed; nothing was changed");
            }
            Ok(json!({"source_serving":true}))
        },
    );
    assert!(result.unwrap_err().to_string().contains("not confirmed"));
    assert_eq!(
        effects.last().map(String::as_str),
        Some("maintenance-confirm")
    );
    assert!(
        !effects
            .iter()
            .any(|name| name == "maintenance-fence" || name == "maintenance-finish")
    );
    let mut inspected = Vec::new();
    automation::run(
        &automation::runner()?,
        &["platform", "maintain", "inspect", "request.json"],
        |request| {
            inspected.push(request.action.clone());
            Ok(json!({"source_serving":true}))
        },
    )?;
    assert!(
        !inspected
            .iter()
            .any(|name| name == "maintenance-copy-backup" || name == "maintenance-confirm")
    );
    assert!(
        automation::run(
            &automation::runner()?,
            &["platform", "maintain", "restart", "request.json"],
            |_| Ok(json!({"source_serving":true}))
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn rolling_release_proves_candidate_before_promotion_without_an_offline_fence() -> Result<()> {
    for resuming in [false, true] {
        let mut steps = Vec::new();
        automation::run(
            &automation::runner()?,
            &["platform", "maintain", "rollout", "request.json"],
            |request| {
                let input: Value = request.decode()?;
                steps.push(match request.action.as_str() {
                    "maintenance-rollout" => format!(
                        "rollout:{}",
                        input["step"].as_str().ok_or_else(|| anyhow::anyhow!(
                            "runtime step missing in {}",
                            request.input
                        ))?
                    ),
                    "maintenance-migration" => {
                        format!(
                            "migration:{}",
                            input["step"].as_str().ok_or_else(|| anyhow::anyhow!(
                                "runtime step missing in {}",
                                request.input
                            ))?
                        )
                    }
                    "maintenance-workflow" => {
                        format!("workflow:{}", input["workflow"].as_str().unwrap())
                    }
                    other => other.trim_start_matches("maintenance-").into(),
                });
                Ok(if request.action == "maintenance-rollout-resume" {
                    json!({"resuming":resuming})
                } else {
                    json!({})
                })
            },
        )?;
        let mut expected = vec![
            "open",
            "artifacts",
            "stop",
            "measure",
            "pod",
            "rollout-resume",
        ];
        if !resuming {
            expected.extend([
                "offsite-backup",
                "operation-claim",
                "workflow:backup",
                "copy-backup",
                "rehearsal-copy",
                "migration:plan",
                "admission",
                "confirm",
            ]);
        }
        if resuming {
            expected.push("operation-claim");
        }
        expected.extend([
            "rollout:prepare",
            "rollout:bind",
            "rollout:admit",
            "rollout:deploy",
            "rollout:observe",
            "rollout:probe",
            "rollout:promote",
            "rollout:wait",
            "rollout:complete",
            "finish",
        ]);
        assert_eq!(steps, expected);
    }
    let mut steps = Vec::new();
    let result = automation::run(
        &automation::runner()?,
        &["platform", "maintain", "rollout", "request.json"],
        |request| {
            let input: Value = request.decode()?;
            steps.push(request.action.clone());
            if request.action == "maintenance-rollout" && input["step"] == "probe" {
                bail!("candidate write failed");
            }
            Ok(if request.action == "maintenance-rollout-resume" {
                json!({"resuming":false})
            } else {
                json!({})
            })
        },
    );
    assert!(result.is_err());
    assert_ne!(steps.last().map(String::as_str), Some("maintenance-finish"));
    Ok(())
}

#[test]
fn runtime_handoff_recipe_preserves_order_on_every_failure_and_bounds_source_recovery() -> Result<()>
{
    let runner = automation::runner()?;
    let execute = |resuming: bool,
                   refuse: Option<&str>,
                   recover_forever: bool|
     -> (Result<Value>, Vec<String>) {
        let mut steps = Vec::new();
        let result = automation::run(
            &runner,
            &["platform", "maintain", "runtime-rollout", "request.json"],
            |request| {
                let input: Value = request.decode()?;
                let step = if request.action == "maintenance-runtime-rollout" {
                    format!(
                        "runtime:{}",
                        input["step"].as_str().ok_or_else(|| anyhow::anyhow!(
                            "runtime step missing in {}",
                            request.input
                        ))?
                    )
                } else if request.action == "maintenance-workflow" {
                    format!("workflow:{}", input["workflow"].as_str().unwrap())
                } else {
                    request.action.trim_start_matches("maintenance-").into()
                };
                steps.push(step.clone());
                if refuse == Some(step.as_str()) {
                    bail!("injected capability refusal");
                }
                Ok(if step == "runtime:resume" {
                    json!({"resuming":resuming,"aborted":false})
                } else if step == "runtime:recover" {
                    json!({"remaining":recover_forever})
                } else {
                    json!({})
                })
            },
        );
        (result, steps)
    };
    let (result, fresh) = execute(false, None, false);
    result?;
    let index = |step: &str| fresh.iter().position(|s| s == step).unwrap();
    assert!(index("offsite-backup") < index("workflow:backup"));
    assert!(index("runtime:rehearsal-check") < index("runtime:claim"));
    assert!(index("runtime:confirm") < index("runtime:claim"));
    assert!(index("runtime:claim") < index("runtime:prepare"));
    assert!(index("runtime:probe") < index("runtime:withdraw"));
    assert!(index("runtime:drain") < index("runtime:quiesce"));
    assert!(index("runtime:transport-stop") < index("runtime:pause"));
    assert!(
        index("runtime:retarget") < index("runtime:adopt")
            && index("runtime:adopt") < index("runtime:unpause")
    );
    assert!(index("runtime:source-gone") < index("runtime:recover"));
    assert!(
        index("runtime:complete") < index("runtime:backup-select")
            && index("runtime:backup-select") < index("runtime:release")
    );
    assert!(
        !fresh
            .iter()
            .any(|s| matches!(s.as_str(), "fence" | "migration:apply" | "mark-activated"))
    );
    for (position, step) in fresh.iter().enumerate() {
        let (result, observed) = execute(false, Some(step), false);
        assert!(result.is_err(), "failure at {step} was ignored");
        assert_eq!(
            observed,
            fresh[..=position],
            "actions continued after {step}"
        );
    }
    let (result, resumed) = execute(true, None, false);
    result?;
    assert!(!resumed.iter().any(|s| matches!(
        s.as_str(),
        "offsite-backup" | "workflow:backup" | "copy-backup"
    )));
    let (result, exhausted) = execute(true, None, true);
    assert!(result.is_err());
    assert_eq!(
        exhausted
            .iter()
            .filter(|s| s.as_str() == "runtime:recover")
            .count(),
        32
    );
    assert!(!exhausted.iter().any(|s| s == "runtime:complete"));
    Ok(())
}

#[test]
fn policy_aborted_runtime_retry_only_cleans_its_never_public_candidate() -> Result<()> {
    let mut steps = Vec::new();
    automation::run(
        &automation::runner()?,
        &["platform", "maintain", "runtime-rollout", "request.json"],
        |request| {
            let input: Value = request.decode()?;
            let step = if request.action == "maintenance-runtime-rollout" {
                format!(
                    "runtime:{}",
                    input["step"].as_str().ok_or_else(|| anyhow::anyhow!(
                        "runtime step missing in {}",
                        request.input
                    ))?
                )
            } else {
                request.action.clone()
            };
            steps.push(step.clone());
            Ok(if step == "runtime:resume" {
                json!({"resuming":true,"aborted":true})
            } else {
                json!({})
            })
        },
    )?;
    assert!(steps.iter().any(|step| step == "runtime:abort-cleanup"));
    assert!(!steps.iter().any(|step| matches!(
        step.as_str(),
        "runtime:promote" | "runtime:pause" | "maintenance-offsite-backup" | "maintenance-fence"
    )));
    assert_eq!(steps.last().map(String::as_str), Some("maintenance-finish"));
    Ok(())
}

/// A build receipt of the shared type the xtask build writes and `build-source`
/// decodes, so these tests exercise ops/Build.roc's `Receipt` against it.
fn build_receipt(artifact: &str, id: &str, seed: &str) -> day2::development::BuildReceipt {
    day2::development::BuildReceipt {
        artifact: artifact.into(),
        verification: day2::development::BuildVerification {
            artifact: id.into(),
            seed: seed.into(),
            examples: 3,
            generated: 136,
            checks: vec![
                "empty-state-properties".into(),
                "command-trace-replay".into(),
            ],
            evidence: std::path::Path::new(artifact).join("verification.json"),
        },
    }
}

#[test]
fn scheduled_backup_recipe_orders_real_protocol_steps_and_stops_on_each_refusal() -> Result<()> {
    let runner = automation::runner()?;
    for (mode, expected) in [
        ("local-only", vec!["backup-snapshot", "backup-verify"]),
        (
            "with-upload",
            vec!["backup-snapshot", "backup-verify", "backup-upload"],
        ),
    ] {
        for refused_at in 0..=expected.len() {
            let mut calls = Vec::new();
            let result = automation::run(
                &runner,
                &["scheduled-backup", "instance", "app", "chosen", mode],
                |request| {
                    let input = request.decode::<Value>()?;
                    assert_eq!(request.action, expected[calls.len()]);
                    let expected_input = match request.action.as_str() {
                        "backup-snapshot" => {
                            json!({"instance":"instance","app_name":"app","output":"chosen"})
                        }
                        "backup-verify" => json!({"directory":"chosen"}),
                        "backup-upload" => json!({}),
                        _ => unreachable!(),
                    };
                    assert_eq!(input, expected_input);
                    calls.push(request.action);
                    if calls.len() == refused_at + 1 {
                        bail!("injected bounded native refusal");
                    }
                    // Deliberately untrusted DATA: sequencing cannot depend on a
                    // child claiming the archive was verified/uploaded.
                    Ok(json!({"not_authority":true}))
                },
            );
            assert_eq!(calls, expected[..expected.len().min(refused_at + 1)]);
            if refused_at < expected.len() {
                assert!(result.is_err());
            } else {
                assert_eq!(result?, json!({"scheduled_backup":"complete"}));
            }
        }
    }
    let mut calls = 0;
    assert!(
        automation::run(
            &runner,
            &[
                "scheduled-backup",
                "instance",
                "app",
                "chosen",
                "unknown-mode"
            ],
            |_| {
                calls += 1;
                Ok(json!({}))
            }
        )
        .is_err()
    );
    assert_eq!(calls, 0);
    Ok(())
}
