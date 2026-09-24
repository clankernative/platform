//! The CLI consumes this read-only projection of the shared Instance contract.
//! Provider/authority schemas are decoded once by Rust, not reauthored in Roc.
use anyhow::{Result, ensure};
use day2::artifact::Instance;
use serde_json::{Value, json};
use std::{fs, path::Path};

pub fn instance(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= 1_048_576,
        "bounded regular instance file required"
    );
    let raw = fs::read(path)?;
    ensure!(raw.len() <= 1_048_576, "instance byte budget");
    let instance = Instance::from_bytes(&raw)?;
    day2::schema::identifier(&instance.installation)?;
    day2::schema::identifier(&instance.environment)?;
    ensure!(
        !instance.apps.is_empty() && instance.apps.len() <= 128,
        "instance app count"
    );
    if let Some(control) = &instance.control {
        control.validate(instance.apps.keys().map(String::as_str))?;
    }
    let mut apps = serde_json::Map::new();
    for (name, binding) in &instance.apps {
        day2::schema::identifier(name)?;
        ensure!(
            !binding.artifact.trim().is_empty() && binding.artifact.len() <= 4096,
            "artifact path budget"
        );
        for actors in [&binding.readers, &binding.writers, &binding.auditors] {
            ensure!(actors.len() <= 512, "actor count budget");
            for actor in actors {
                ensure!(
                    !actor.trim().is_empty()
                        && actor.len() <= 256
                        && !actor.chars().any(char::is_control),
                    "actor label"
                );
            }
        }
        apps.insert(name.clone(), json!({"artifact": binding.artifact, "readers":binding.readers, "writers":binding.writers, "auditors":binding.auditors}));
    }
    Ok(json!({"installation":instance.installation,"environment":instance.environment,"apps":apps}))
}

pub fn artifact(path: &Path) -> Result<Value> {
    let artifact = day2::artifact::LoadedArtifact::load(path)?;
    artifact.require_current_api()?;
    let catalog = day2::operation_catalog::Catalog::from_artifact(artifact.contract())?;
    let meaning = catalog.endpoints.values().map(|endpoint| {
        let inputs = endpoint.input_schema["properties"].as_object().expect("input properties").iter().map(|(name, field)| {
            let description = field["description"].as_str().unwrap_or("");
            let rules = field["x-day2-domain-description"].as_str().unwrap_or("");
            let bounds = field["x-day2-max-utf8-bytes"].as_u64().map(|maximum| format!(" At most {maximum} UTF-8 bytes.{}", if field["x-day2-nonblank"] == true { " Nonblank text is required." } else { "" })).unwrap_or_default();
                json!({"name":name,"description":format!("{description} {rules}{bounds}").trim()})
        }).collect::<Vec<_>>();
        json!({"name":endpoint.operation.name,"description":endpoint.description,"example_input_json":endpoint.request_example.to_string(),"inputs":inputs})
    }).collect::<Vec<_>>();
    let mut schema = serde_json::to_value(&artifact.contract().schema)?;
    // Registration aliases are internal compiler evidence; field kinds retain
    // their nominal domain identity in this public projection.
    schema
        .as_object_mut()
        .expect("serialized schema")
        .remove("domains");
    // Internal model keys are admitted by the shared decoder. Discovery carries
    // each reference's public prefix without exporting the private registry key.
    for model in schema["models"]
        .as_object_mut()
        .expect("serialized models")
        .values_mut()
    {
        model
            .as_object_mut()
            .expect("serialized model")
            .remove("identity");
    }
    // Discovery has its own small versioned projection. New private artifact
    // metadata (documentation, workers, assets, etc.) cannot break the CLI.
    Ok(json!({
        "version":1,
        "meaning":serde_json::to_string(&meaning)?,
        "schema":schema,
        "outputs":artifact.contract().outputs,
        "operations":catalog.endpoints.values().map(|endpoint| &endpoint.operation).collect::<Vec<_>>()
    }))
}
