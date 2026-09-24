use anyhow::Result;
use day2::artifact::Instance;
use day2_capabilities::{BindingRef, Digest, Name, SourceProvider};
use serde_json::{Value, json};
use std::path::Path;

fn fixture(root: &Path) -> Result<Value> {
    let source = SourceProvider::LocalGit {
        repository: root.join("repositories/reports.git").display().to_string(),
    };
    let source = BindingRef::pin(Name::try_from("reports-source".to_owned())?, &source)?;
    Ok(json!({
        "installation":"example","environment":"development",
        "apps":{
            "reports":{"artifact":"fixture","readers":[],"writers":[]},
            "links":{"artifact":"fixture","readers":[],"writers":[]}
        },
        "control":{
            "version":1,"state_directory":root.join("control"),"operators":["operator@example.com"],
            "sources":{"reports-source":{"kind":"local_git","repository":root.join("repositories/reports.git")}},
            "apps":{"reports":{"source":"reports-source","build":{
                "source":source,
                "builder":{"id":"local-builder","revision":Digest::new(b"fixture builder")},
                "durability":{"id":"local-temporal","revision":Digest::new(b"fixture runtime")},
                "platform":Digest::new(b"fixture platform"),"recipe":Digest::new(b"fixture recipe")
            }}},
            "builders":{"local-builder":{"kind":"local_macos","platform_root":root.join("platform"),
                "toolchains":root.join("toolchains"),"xtask":root.join("xtask"),"rust":root.join("rust"),"registry":root.join("registry")}},
            "runtimes":{"local-temporal":{"kind":"temporal_local","endpoint":"127.0.0.1:7233","namespace":"example","task_queue":"reports-builds"}}
        }
    }))
}

fn load(root: &Path, value: &Value) -> Result<Instance> {
    let path = root.join("instance.json");
    std::fs::write(&path, serde_json::to_vec(value)?)?;
    Instance::load(&path)
}

#[test]
fn retired_app_job_bindings_are_rejected() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let value = fixture(&root)?;
    load(&root, &value)?;
    for binding in [
        json!({"kind":"local"}),
        json!({"kind":"temporal","endpoint":"http://127.0.0.1:7233","namespace":"example","task_queue":"reports"}),
    ] {
        let mut retired = value.clone();
        retired["apps"]["reports"]["background"] = binding;
        assert!(load(&root, &retired).is_err());
    }
    Ok(())
}

#[test]
fn control_references_are_checked_before_runtime_binding_lookup() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let value = fixture(&root)?;
    let mut missing_runtime = value.clone();
    missing_runtime["control"]["runtimes"] = json!({});
    assert!(load(&root, &missing_runtime).is_err());
    let mut wrong_source = value.clone();
    wrong_source["control"]["apps"]["reports"]["source"] = json!("unbound");
    assert!(load(&root, &wrong_source).is_err());
    let mut uninstalled = value.clone();
    uninstalled["control"]["apps"]["ghost"] = uninstalled["control"]["apps"]["reports"].clone();
    assert!(load(&root, &uninstalled).is_err());
    let mut unbound_secret = value;
    unbound_secret["control"]["apps"]["reports"]["provider_secrets"] = json!({"read":"unapproved"});
    assert!(load(&root, &unbound_secret).is_err());
    Ok(())
}

#[test]
fn control_endpoints_and_names_use_the_connected_runtime_contract() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let original = fixture(&root)?;
    for endpoint in [
        "http://127.0.0.1:7233/",
        "http://localhost:7233",
        "https://127.0.0.1:7233",
        "http://192.0.2.1:7233",
    ] {
        let mut value = original.clone();
        value["control"]["runtimes"]["local-temporal"]["endpoint"] = json!(endpoint);
        assert!(load(&root, &value).is_err(), "{endpoint}");
    }
    let mut value = original;
    value["control"]["runtimes"]["local-temporal"]["task_queue"] = json!("reports.build");
    assert!(load(&root, &value).is_err());
    Ok(())
}
