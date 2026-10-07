//! Recipe checks use the reviewed Roc runner, real identity authoring, and a
//! deliberately simulated build port. They do not claim native app qualification.
use crate::app_create::SourceFile;
use anyhow::{Context, Result, bail};
use day2::automation;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    files: Vec<SourceFile>,
}

#[test]
fn app_creation_scaffold_variants_have_complete_registered_ownership_contracts() -> Result<()> {
    let runner = automation::runner()?;
    for ui in ["none", "html", "clanker"] {
        let stage = tempfile::tempdir()?;
        let source = stage.path().join("app");
        fs::create_dir(&source)?;
        let mut effects = Vec::new();
        let mut arguments = vec!["platform", "app-create", "fresh-app", "hello", "--ui", ui];
        if ui == "clanker" {
            arguments.extend([
                "--bundle",
                "/approved/install",
                "--bundle-sha256",
                "sha256:reviewed-test-port",
            ]);
        }
        let result = automation::run(&runner, &arguments, |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "app-create-begin" => {
                    let options: Value = request.decode()?;
                    assert_eq!(options["ui"], ui);
                    Ok(json!({"source":source}))
                }
                "app-create-write" => {
                    let files: Files = request.decode()?;
                    for file in files.files {
                        let path = source.join(file.path);
                        fs::create_dir_all(path.parent().context("scaffold parent")?)?;
                        fs::write(path, file.content)?;
                    }
                    Ok(json!({}))
                }
                "app-create-identity" => {
                    let input: Value = request.decode()?;
                    day2::identity::register_model(
                        &source,
                        input["table"].as_str().unwrap(),
                        input["roc_type"].as_str().unwrap(),
                    )?;
                    Ok(json!({}))
                }
                "build-source" => {
                    assert_eq!(
                        request.decode::<Value>()?["source"],
                        source.to_str().unwrap()
                    );
                    let models = fs::read_to_string(source.join("storage/Models.roc"))?;
                    let registry = fs::read_to_string(source.join("model-identities.json"))?;
                    day2::app_inference::schema_source(
                        &registry,
                        &BTreeMap::from([("Models".into(), models)]),
                    )?;
                    let app = fs::read_to_string(source.join("App.roc"))?;
                    assert_eq!(day2::app_inference::namespace(&app)?, "hello");
                    assert_eq!(app.matches("Welcome.definition").count(), 1);
                    assert!(app.contains("StarterInvariants.ownership"));
                    let operation = fs::read_to_string(source.join("queries/welcome/Welcome.roc"))?;
                    assert!(operation.contains("Api.query"));
                    assert!(operation.contains("example: |_| Ok"));
                    assert!(operation.contains("before == after and output.message"));
                    assert!(operation.contains("Query.succeed"));
                    assert!(fs::read_to_string(source.join("AGENTS.md"))?.contains("educational"));
                    if ui == "none" {
                        assert!(!source.join("ui").exists());
                        assert!(!source.join("pages").exists());
                    } else {
                        let html = fs::read_to_string(source.join("ui/pages/welcome.html"))?;
                        assert!(html.contains("{{ welcome.message }}"));
                        assert!(source.join("pages/Routes.roc").is_file());
                        assert!(source.join("ui/AGENTS.md").is_file());
                        if ui == "clanker" {
                            assert!(html.contains("<cui-card><cui-slot name=\"body\""));
                            assert!(html.contains("href=\"{{ routes.welcome() }}\""));
                            assert!(!html.contains("href=\"/\""));
                            assert!(source.join("ui/clanker-theme.css").is_file());
                            assert!(
                                fs::read_to_string(source.join("README.md"))?
                                    .contains("DAY2_UI_PROVIDER_PIN_JSON")
                            );
                        } else {
                            assert!(!html.contains("cui-"));
                            assert!(!source.join("ui/clanker-theme.css").exists());
                        }
                    }
                    Ok(json!({"artifact":"/simulated-admitted-artifact"}))
                }
                "app-create-publish" => Ok(json!({"source":"fresh-app"})),
                _ => bail!("unexpected creation effect"),
            }
        })?;
        assert_eq!(result["source"], "fresh-app");
        assert_eq!(
            effects,
            [
                "app-create-begin",
                "app-create-write",
                "app-create-identity",
                "build-source",
                "app-create-publish"
            ]
        );
    }
    Ok(())
}

#[test]
fn app_creation_failed_build_never_publishes_and_parse_errors_have_no_effects() -> Result<()> {
    let runner = automation::runner()?;
    let mut effects = Vec::new();
    assert!(
        automation::run(
            &runner,
            &[
                "platform",
                "app-create",
                "fresh-app",
                "hello",
                "--ui",
                "html"
            ],
            |request| {
                effects.push(request.action.clone());
                match request.action.as_str() {
                    "app-create-begin" => Ok(json!({"source":"/captured-source"})),
                    "app-create-write" | "app-create-identity" => Ok(json!({})),
                    "build-source" => bail!("injected verification failure"),
                    _ => bail!("unexpected publication"),
                }
            }
        )
        .is_err()
    );
    assert_eq!(
        effects,
        [
            "app-create-begin",
            "app-create-write",
            "app-create-identity",
            "build-source"
        ]
    );
    for rest in [
        vec!["--ui", "unknown"],
        vec!["--ui", "clanker"],
        vec!["--ui", "html", "--ui", "none"],
        vec!["--ui"],
        vec!["--ui", "none", "--bundle", "/unapproved"],
        vec!["--script", "anything"],
    ] {
        let mut arguments = vec!["platform", "app-create", "fresh-app", "hello"];
        arguments.extend(rest);
        let mut called = false;
        assert!(
            automation::run(&runner, &arguments, |_| {
                called = true;
                bail!("invalid parser reached host")
            })
            .is_err()
        );
        assert!(!called);
    }
    Ok(())
}

#[test]
fn app_creation_help_is_effect_free() -> Result<()> {
    let result = automation::run(
        &automation::runner()?,
        &["platform", "app-create", "--help"],
        |_| bail!("help performed an effect"),
    )?;
    assert!(
        result["usage"]
            .as_str()
            .unwrap_or_default()
            .contains("app-create")
    );
    assert!(
        result["default_package"]
            .as_str()
            .unwrap_or_default()
            .contains("@clanker/vanilla")
    );
    Ok(())
}
