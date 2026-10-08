use super::*;
use std::collections::BTreeMap;

fn generic_package() -> (LockedPackage, BTreeMap<String, Vec<u8>>) {
    let files = BTreeMap::from([
        ("foo.d.ts".to_owned(), b"opaque declaration data".to_vec()),
        (
            "payload.bin".to_owned(),
            b"provider-owned opaque bytes".to_vec(),
        ),
    ]);
    let inputs = files
        .iter()
        .map(|(path, bytes)| Input {
            path: path.clone(),
            digest: sha(bytes),
            bytes: bytes.len(),
        })
        .collect::<Vec<_>>();
    let digest = manifest_digest(&inputs).unwrap();
    (
        LockedPackage {
            name: "example-provider-package".into(),
            version: "0.1.0".into(),
            path: "../../package".into(),
            digest,
            inputs,
        },
        files,
    )
}

fn generic_lock() -> Lock {
    let (package, _) = generic_package();
    Lock {
        schema_version: 1,
        provider: "opaque-provider".into(),
        package,
    }
}

#[test]
fn path_and_digest_validation_is_closed() {
    for good in ["pages/index.html", "package/foo.d.ts", "ui/app.css"] {
        assert!(safe_rel(good));
    }
    for bad in ["", "../x", "a/../b", "/tmp/x", "a\\b", "a//b", "a;whoami"] {
        assert!(!safe_rel(bad));
    }
    assert!(safe_lock_path("../provider-package/files"));
    assert!(safe_lock_path("../../packages/opaque"));
    for bad in [
        "packages/opaque",
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
fn captured_non_provider_apps_are_unchanged_without_a_lock_or_pin() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("app");
    let captured = temp.path().join("captured");
    fs::create_dir_all(captured.join("ui/pages")).unwrap();
    fs::write(
        captured.join("ui/pages/index.html"),
        "<main>ordinary</main>",
    )
    .unwrap();
    fs::write(captured.join("ui/app.js"), b"not provider input").unwrap();
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
fn no_lock_does_not_touch_sources_or_execute_an_adapter() {
    let temp = tempfile::tempdir().unwrap();
    let captured = temp.path().join("captured");
    fs::create_dir_all(captured.join("ui/pages")).unwrap();
    let page = captured.join("ui/pages/index.html");
    fs::write(&page, "<cui-opaque-component />").unwrap();
    let marker = temp.path().join("executed");
    let executable = temp.path().join("adapter");
    fs::write(
        &executable,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let original = fs::read(&page).unwrap();
    let mut hashes = BTreeMap::new();
    expand_with_pin(temp.path(), &captured, &mut hashes, &executable).unwrap();
    assert_eq!(fs::read(&page).unwrap(), original);
    assert!(!marker.exists());
    assert!(hashes.is_empty());
    assert!(day2::web_templates::parse_checked(std::str::from_utf8(&original).unwrap()).is_err());
}

#[test]
fn generic_pin_requires_protocol_two_binding_abi_two_and_matching_executable_digest() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("adapter");
    fs::write(&executable, b"verified executable bytes").unwrap();
    let mut pin = Pin {
        schema_version: 1,
        provider: "opaque-provider".into(),
        assembly_protocol: 2,
        binding_abi: 2,
        targets: BTreeMap::from([(
            target_key().unwrap().to_owned(),
            TargetPin {
                executable: executable.display().to_string(),
                digest: sha(b"verified executable bytes"),
            },
        )]),
    };
    assert!(pin_digest(&pin, &executable).is_ok());
    pin.assembly_protocol = 1;
    assert!(pin_digest(&pin, &executable).is_err());
    pin.assembly_protocol = 2;
    pin.binding_abi = 1;
    assert!(pin_digest(&pin, &executable).is_err());
    pin.binding_abi = 2;
    pin.targets.remove(target_key().unwrap());
    assert!(pin_digest(&pin, &executable).is_err());
    pin.targets.insert(
        target_key().unwrap().into(),
        TargetPin {
            executable: executable.display().to_string(),
            digest: sha(b"verified executable bytes"),
        },
    );
    fs::write(&executable, b"tampered").unwrap();
    assert!(pin_digest(&pin, &executable).is_err());
}

#[test]
fn strict_generic_lock_rejects_unknown_fields_and_invalid_schema() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lock.json");
    let lock = generic_lock();
    fs::write(&path, serde_json::to_vec(&lock).unwrap()).unwrap();
    assert_eq!(parse_lock(&path).unwrap().provider, "opaque-provider");
    let mut json = serde_json::to_value(lock).unwrap();
    json["unexpected"] = true.into();
    fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(parse_lock(&path).is_err());
    json.as_object_mut().unwrap().remove("unexpected");
    json["schemaVersion"] = 2.into();
    fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert!(parse_lock(&path).is_err());
}

#[test]
fn generic_lock_tampering_missing_inputs_traversal_and_case_collisions_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("package");
    fs::create_dir_all(&root).unwrap();
    let (package, files) = generic_package();
    for (path, bytes) in &files {
        fs::write(root.join(path), bytes).unwrap();
    }
    assert_eq!(package_inputs(&root, &package).unwrap().len(), 2);

    let mut changed = package.clone();
    changed.inputs[0].digest = sha(b"tampered digest");
    assert!(manifest_digest(&changed.inputs).unwrap() != changed.digest);
    assert!(package_inputs(&root, &changed).is_err());
    fs::write(root.join("foo.d.ts"), b"tampered bytes").unwrap();
    assert!(package_inputs(&root, &package).is_err());
    fs::write(root.join("foo.d.ts"), &files["foo.d.ts"]).unwrap();

    let missing_file_root = temp.path().join("missing-file");
    fs::create_dir_all(&missing_file_root).unwrap();
    fs::write(missing_file_root.join("foo.d.ts"), &files["foo.d.ts"]).unwrap();
    assert!(package_inputs(&missing_file_root, &package).is_err());

    let mut missing = package.clone();
    missing.inputs.retain(|input| input.path != "foo.d.ts");
    assert!(package_inputs(&root, &missing).is_err());

    let mut traversal = package.clone();
    traversal.inputs[0].path = "../escape".into();
    traversal.digest = manifest_digest(&traversal.inputs).unwrap_or_default();
    assert!(package_inputs(&root, &traversal).is_err());

    let mut duplicate = package.clone();
    duplicate.inputs.push(duplicate.inputs[0].clone());
    assert!(manifest_digest(&duplicate.inputs).is_err());
    let mut collision = package;
    let mut case_variant = collision.inputs[0].clone();
    case_variant.path = case_variant.path.to_ascii_uppercase();
    collision.inputs.push(case_variant);
    assert!(manifest_digest(&collision.inputs).is_err());
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
fn response_envelope_requires_fields_and_rejects_unknown_fields() {
    let valid = serde_json::json!({
        "schemaVersion":1,"ok":true,"command":"assemble","diagnostics":[],
        "data":{"schemaVersion":1,"runtimeAbi":2,"templateEngine":"minijinja-2.12.0","packageDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","templates":{},"resources":[],"inputs":[],"consumedInputs":[]}
    });
    assert!(serde_json::from_value::<Envelope>(valid.clone()).is_ok());
    for required in ["runtimeAbi", "templateEngine", "consumedInputs"] {
        let mut missing = valid.clone();
        missing["data"].as_object_mut().unwrap().remove(required);
        assert!(
            serde_json::from_value::<Envelope>(missing).is_err(),
            "{required}"
        );
    }
    let mut unknown = valid.clone();
    unknown["data"]["future"] = true.into();
    assert!(serde_json::from_value::<Envelope>(unknown).is_err());
    for legacy in ["bindings", "entrypoints"] {
        let mut legacy_field = valid.clone();
        legacy_field["data"][legacy] = serde_json::json!([]);
        assert!(
            serde_json::from_value::<Envelope>(legacy_field).is_err(),
            "legacy {legacy} must be rejected"
        );
    }
}

#[test]
fn resource_policy_rejects_non_ui_paths() {
    let package = generic_lock().package;
    let lock = Lock {
        schema_version: 1,
        provider: "opaque-provider".into(),
        package,
    };
    let bundle = Bundle {
        schema_version: 1,
        runtime_abi: 2,
        template_engine: "minijinja-2.12.0".into(),
        package_digest: lock.package.digest.clone(),
        templates: BTreeMap::new(),
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
            &UiSnapshot::default(),
            &BTreeMap::new()
        )
        .is_err()
    );
}

#[test]
fn adapter_failures_report_stdout_diagnostics() {
    let out = br#"{"diagnostics":[{"code":"PROV001","message":"invalid provider output","severity":"error"}],"ok":false,"schemaVersion":1}"#;
    assert_eq!(adapter_failure(out, b""), "PROV001 invalid provider output");
    assert_eq!(
        adapter_failure(out, b"boom\n"),
        "PROV001 invalid provider output; boom"
    );
    assert_eq!(adapter_failure(b"not json", b"crashed"), "crashed");
    assert_eq!(adapter_failure(b"", b""), "no diagnostics");
}
