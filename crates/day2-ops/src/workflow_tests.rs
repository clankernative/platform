//! Exercise the compiled Roc workflows through the real private protocol. Failure
//! injection verifies that policy cannot proceed to later effects after a failed
//! native check, while the Reports integration tests exercise the real adapters.
use anyhow::{Result, bail};
use day2::automation;
use serde::Deserialize;
use serde_json::{Value, json};

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
                    {"name":"ignored","error":"","steps":[{"operation":"must_not_run","input":"{}"}]},
                    {"name":"chosen","error":"","steps":[{"operation":"submit","input":"{}"}]}
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
                "dev-prepare-sample" => Ok(json!({"operation":"submit","input":format!("{{\"index\":{}}}", invoked.len())})),
                "dev-invoke" => { invoked.push(request.decode::<Value>()?["input"].clone()); Ok(json!({})) }
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
                    Ok(json!({"artifact":"/admitted"}))
                }
                "local-open" => Ok(json!({"fresh":true})),
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
            Ok(json!({}))
        },
    )?;
    assert_eq!(
        effects,
        [
            "open",
            "artifacts",
            "stop",
            "pod",
            "workflow:backup",
            "copy-backup",
            "migration:plan",
            "confirm",
            "fence",
            "migration:apply",
            "workflow:authority-inspect",
            "workflow:authority-activate",
            "mark-activated",
            "finish",
        ]
    );
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
            Ok(json!({}))
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
            Ok(json!({}))
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
            |_| Ok(json!({}))
        )
        .is_err()
    );
    Ok(())
}
