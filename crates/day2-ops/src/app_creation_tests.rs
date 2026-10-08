//! Recipe checks run the reviewed Roc runner and the same mandatory creation
//! guards as production, with bounded no-filesystem evidence/admission ports.
use crate::app_create::{
    Options, SourceFile,
    core::{Creation, Ports},
    simulation::{Memory, SeededEntropy, bundle_fixture},
};
use anyhow::{Context, Result, bail};
use day2::automation;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    files: Vec<SourceFile>,
}

#[test]
fn app_creation_scaffold_variants_have_complete_registered_ownership_contracts() -> Result<()> {
    let runner = automation::runner()?;
    for ui in ["none", "html", "clanker"] {
        let source = PathBuf::from("/captured-source");
        let mut creation: Option<Creation<Memory>> = None;
        let entropy = SeededEntropy::new(130);
        let mut effects = Vec::new();
        let approval = super::app_create::sha(&bundle_fixture().0["manifest.json"]);
        let mut arguments = vec!["platform", "app-create", "fresh-app", "hello", "--ui", ui];
        if ui == "clanker" {
            arguments.extend([
                "--bundle",
                "/approved/install",
                "--bundle-sha256",
                &approval,
            ]);
        }
        let result = automation::run(&runner, &arguments, |request| {
            effects.push(request.action.clone());
            match request.action.as_str() {
                "app-create-begin" => {
                    let options: Options = request.decode()?;
                    assert_eq!(options.ui, ui);
                    creation = Some(Memory::begin(&options)?);
                    Ok(json!({"source":source}))
                }
                "app-create-write" => {
                    creation
                        .as_mut()
                        .context("creation required")?
                        .write_files(request.decode::<Files>()?.files)?;
                    Ok(json!({}))
                }
                "app-create-identity" => {
                    let input: Value = request.decode()?;
                    creation.as_mut().context("creation required")?.identity(
                        input["table"].as_str().unwrap(),
                        input["roc_type"].as_str().unwrap(),
                        &entropy,
                    )?;
                    Ok(json!({}))
                }
                "build-source" => {
                    assert_eq!(
                        request.decode::<Value>()?["source"],
                        source.to_str().unwrap()
                    );
                    let creation = creation.as_mut().context("creation required")?;
                    creation.check_build_source(&source)?;
                    let snapshot = creation.port.snapshot()?;
                    let read = |path| -> Result<String> {
                        Ok(std::str::from_utf8(snapshot.bytes(path)?)?.to_owned())
                    };
                    let models = read("storage/Models.roc")?;
                    let registry = read("model-identities.json")?;
                    day2::app_inference::schema_source(
                        &registry,
                        &BTreeMap::from([("Models".into(), models)]),
                    )?;
                    let app = read("App.roc")?;
                    assert_eq!(day2::app_inference::namespace(&app)?, "hello");
                    assert_eq!(app.matches("Welcome.definition").count(), 1);
                    assert!(app.contains("StarterInvariants.ownership"));
                    let operation = read("queries/welcome/Welcome.roc")?;
                    assert!(operation.contains("Api.query"));
                    assert!(operation.contains("example: |_| Ok"));
                    assert!(operation.contains("before == after and output.message"));
                    assert!(operation.contains("Query.succeed"));
                    assert!(read("AGENTS.md")?.contains("educational"));
                    if ui == "none" {
                        assert!(!snapshot.0.keys().any(|p| p.starts_with("ui/")));
                        assert!(!snapshot.0.keys().any(|p| p.starts_with("pages/")));
                    } else {
                        let html = read("ui/pages/welcome.html")?;
                        assert!(html.contains("{{ welcome.message }}"));
                        assert!(snapshot.0.contains_key("pages/Routes.roc"));
                        assert!(snapshot.0.contains_key("ui/AGENTS.md"));
                        if ui == "clanker" {
                            assert!(html.contains("<cui-card><cui-slot name=\"body\""));
                            assert!(html.contains("href=\"{{ routes.welcome() }}\""));
                            assert!(!html.contains("href=\"/\""));
                            assert!(snapshot.0.contains_key("ui/clanker-theme.css"));
                            let readme = read("README.md")?;
                            assert!(readme.contains("DAY2_UI_PROVIDER_PIN_JSON"));
                            assert!(readme.contains(".ui-dependencies/legal"));
                            assert!(readme.contains("app-owned code keeps its own rights"));
                        } else {
                            assert!(!html.contains("cui-"));
                            assert!(!snapshot.0.contains_key("ui/clanker-theme.css"));
                        }
                    }

                    let artifact = Path::new("/simulated-admitted-artifact");
                    creation.port.verified(artifact, "hello");
                    creation.built(artifact)?;
                    Ok(json!({"artifact":artifact}))
                }
                "app-create-publish" => {
                    let input: Value = request.decode()?;
                    creation
                        .as_mut()
                        .context("creation required")?
                        .publish(Path::new(input["artifact"].as_str().unwrap()))
                }
                _ => bail!("unexpected creation effect"),
            }
        })?;
        assert_eq!(result["source"], "fresh-app");
        assert_eq!(creation.unwrap().port.publications, 1);
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
    let mut creation: Option<Creation<Memory>> = None;
    let entropy = SeededEntropy::new(130);
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
                    "app-create-begin" => {
                        creation = Some(Memory::begin(&request.decode()?)?);
                        Ok(json!({"source":"/captured-source"}))
                    }
                    "app-create-write" => {
                        creation
                            .as_mut()
                            .context("creation required")?
                            .write_files(request.decode::<Files>()?.files)?;
                        Ok(json!({}))
                    }
                    "app-create-identity" => {
                        let input: Value = request.decode()?;
                        creation.as_mut().context("creation required")?.identity(
                            input["table"].as_str().unwrap(),
                            input["roc_type"].as_str().unwrap(),
                            &entropy,
                        )?;
                        Ok(json!({}))
                    }
                    "build-source" => {
                        let creation = creation.as_mut().context("creation required")?;
                        creation.check_build_source(Path::new("/captured-source"))?;
                        creation.built(Path::new("/not-admitted"))?;
                        bail!("unadmitted build unexpectedly accepted")
                    }
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
    let creation = creation.as_mut().context("creation required")?;
    assert_eq!(creation.port.publications, 0);
    assert!(creation.publish(Path::new("/not-admitted")).is_err());
    assert_eq!(creation.port.publications, 0);
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
