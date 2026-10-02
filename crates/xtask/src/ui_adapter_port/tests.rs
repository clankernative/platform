use super::*;
use std::collections::BTreeMap;

#[test]
fn path_and_digest_validation_is_closed() {
    for good in ["pages/index.html", "package/ui-package.json", "ui/app.css"] {
        assert!(safe_rel(good));
    }
    for bad in ["", "../x", "a/../b", "/tmp/x", "a\\b", "a//b", "a;whoami"] {
        assert!(!safe_rel(bad), "{bad}");
    }
    assert!(safe_lock_path("../clanker-native-ui/packages/vanilla"));
    assert!(safe_lock_path("../../packages/vanilla"));
    for bad in [
        "packages/vanilla",
        "../../../packages/x",
        "../a/../../b",
        "../a//b",
        "../a\\b",
    ] {
        assert!(!safe_lock_path(bad), "{bad}");
    }
    assert!(valid_digest(&format!("sha256:{}", "a".repeat(64))));
    assert!(!valid_digest("sha256:wrong"));
}

#[test]
fn captured_non_clanker_apps_are_unchanged_without_a_lock_or_pin() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("app");
    let captured = temp.path().join("captured");
    fs::create_dir_all(captured.join("ui/pages")).unwrap();
    fs::write(
        captured.join("ui/pages/index.html"),
        "<main>ordinary</main>",
    )
    .unwrap();
    let before = fs::read(captured.join("ui/pages/index.html")).unwrap();
    let mut hashes = BTreeMap::new();
    expand(&app, &captured, &mut hashes).unwrap();
    assert_eq!(
        fs::read(captured.join("ui/pages/index.html")).unwrap(),
        before
    );
    assert!(hashes.is_empty());
}

#[test]
fn no_lock_leaves_sources_unchanged_and_normal_admission_rejects_assembly_tags() {
    let temp = tempfile::tempdir().unwrap();
    let captured = temp.path().join("captured");
    fs::create_dir_all(captured.join("ui/pages")).unwrap();
    let page = captured.join("ui/pages/index.html");
    fs::write(&page, "<cui-button label=\"x\" />").unwrap();
    let original = fs::read(&page).unwrap();
    expand_with_pin(
        temp.path(),
        &captured,
        &mut BTreeMap::new(),
        Path::new("unused pin"),
    )
    .unwrap();
    assert!(day2::web_templates::parse_checked(std::str::from_utf8(&original).unwrap()).is_err());
    assert_eq!(fs::read(page).unwrap(), original);
}

#[test]
fn pin_verifies_protocol_target_and_executable_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("adapter");
    fs::write(&executable, b"verified executable bytes").unwrap();
    let pin = Pin {
        schema_version: 1,
        package: "@clanker/vanilla".into(),
        adapter_protocol: 1,
        runtime_abi: 1,
        targets: BTreeMap::from([(
            target_key().unwrap().to_owned(),
            TargetPin {
                executable: executable.display().to_string(),
                digest: sha(b"verified executable bytes"),
            },
        )]),
    };
    assert!(pin_digest(&pin, &executable).is_ok());
    fs::write(&executable, b"tampered").unwrap();
    assert!(pin_digest(&pin, &executable).is_err());
}

#[test]
fn strict_lock_rejects_unknown_fields_and_invalid_schema() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lock.json");
    fs::write(&path, br#"{"schemaVersion":1,"package":"p","version":"1","path":"../pkg","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}"#).unwrap();
    assert!(parse_lock(&path).is_err());
    fs::write(&path, br#"{"schemaVersion":2,"package":"p","version":"1","path":"../pkg","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#).unwrap();
    assert!(parse_lock(&path).is_err());
}

#[cfg(unix)]
#[test]
fn captured_ui_symlink_is_rejected_before_child_execution() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    fs::create_dir_all(source.join("ui")).unwrap();
    fs::create_dir_all(&target).unwrap();
    symlink(&target, source.join("ui/escape")).unwrap();
    assert!(copy_tree_checked(&source.join("ui"), &temp.path().join("private-ui")).is_err());
}

#[test]
fn response_protocol_requires_final_abi_fields_and_rejects_unknown_fields() {
    let valid = serde_json::json!({
        "schemaVersion":1,"ok":true,"command":"expand","diagnostics":[],
        "data":{"schemaVersion":1,"runtimeAbi":1,"templateEngine":"minijinja-2.12.0","packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","templates":{"pages/index.html":"<main />"},"bindings":[],"entrypoints":[],"resources":[],"inputs":[],"consumedInputs":[]}
    });
    assert!(serde_json::from_value::<Envelope>(valid.clone()).is_ok());
    let mut wrong = valid.clone();
    wrong["data"]["runtimeAbi"] = 2.into();
    assert_ne!(
        serde_json::from_value::<Envelope>(wrong)
            .unwrap()
            .data
            .runtime_abi,
        1
    );
    let mut unknown = valid;
    unknown["data"]["future"] = true.into();
    assert!(serde_json::from_value::<Envelope>(unknown).is_err());
}

#[test]
fn generic_entrypoint_loader_is_sorted_and_uses_only_declared_relative_modules() {
    let entries = vec!["ui/z/module.js".to_owned(), "ui/a/module.js".to_owned()];
    assert_eq!(
        entrypoint_loader(&entries).unwrap(),
        "import './a/module.js';\nimport './z/module.js';\n"
    );
    assert!(entrypoint_loader(&["ui/../escape.js".into()]).is_err());
    assert!(entrypoint_loader(&["ui/a/module.wasm".into()]).is_err());
}

#[cfg(unix)]
#[test]
fn subprocess_timeout_kills_only_the_adapter_child() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("adapter");
    fs::write(&executable, b"#!/bin/sh\nwhile :; do :; done\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let error = run_adapter_with_timeout(
        &executable,
        temp.path(),
        temp.path(),
        Duration::from_millis(50),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("timeout"));
}

#[test]
fn resource_policy_rejects_non_ui_paths_and_unknown_kinds() {
    let lock = Lock {
        schema_version: 1,
        package: "p".into(),
        version: "1".into(),
        path: "../pkg".into(),
        digest: format!("sha256:{}", "a".repeat(64)),
    };
    let bundle = Bundle {
        schema_version: 1,
        runtime_abi: 1,
        template_engine: "minijinja-2.12.0".into(),
        package_digest: lock.digest.clone(),
        templates: BTreeMap::new(),
        bindings: vec![],
        entrypoints: vec![],
        resources: vec![Resource {
            path: "assets/x.js".into(),
            source: None,
            content: Some("x".into()),
            digest: sha(b"x"),
            bytes: 1,
            kind: "module".into(),
        }],
        inputs: vec![],
        consumed_inputs: vec![],
    };
    assert!(
        validate_bundle(
            &bundle,
            &lock,
            &BTreeMap::new(),
            Path::new("."),
            &BTreeMap::new()
        )
        .is_err()
    );
}
