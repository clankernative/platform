use super::port::SimulatedAssembler;
use super::*;

fn request() -> AssemblyRequest {
    let inputs = vec![Input {
        path: "foo.d.ts".into(),
        digest: sha(b"opaque"),
        bytes: 6,
    }];
    AssemblyRequest {
        schema_version: 1,
        assembly_protocol: 2,
        provider: "test-provider".into(),
        target: AssemblyTarget {
            binding_abi: 2,
            template_engine: "minijinja-2.12.0".into(),
        },
        package: LockedPackage {
            name: "opaque-package".into(),
            version: "1".into(),
            path: "private".into(),
            digest: manifest_digest(&inputs).unwrap(),
            inputs,
        },
        ui: "captured-ui".into(),
    }
}

// Minimal synthetic protocol bytes for unit tests; not a producer capture or CLI evidence.
fn synthetic_response() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "ok": true, "command": "assemble", "diagnostics": [],
        "data": {
            "schemaVersion": 1, "runtimeAbi": 2, "templateEngine": "minijinja-2.12.0",
            "packageDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "templates": {}, "resources": [], "inputs": [], "consumedInputs": []
        }
    })).unwrap()
}

#[test]
fn simulated_assembler_rejects_request_mismatch() {
    let expected_request = request();
    let adapter = SimulatedAssembler {
        expected_request: expected_request.clone(),
        recorded_response: synthetic_response(),
    };
    let mut changed = expected_request;
    changed.provider = "different-provider".into();
    assert!(matches!(
        adapter.assemble(&changed),
        Err(AssemblyFailure::InvalidResponse(_))
    ));
}

#[test]
fn simulated_assembler_rejects_malformed_and_wrong_protocol_responses() {
    let malformed = SimulatedAssembler {
        expected_request: request(),
        recorded_response: b"not-json".to_vec(),
    };
    assert!(matches!(
        malformed.assemble(&request()),
        Err(AssemblyFailure::InvalidResponse(_))
    ));

    let mut wrong_protocol: serde_json::Value =
        serde_json::from_slice(&synthetic_response()).unwrap();
    wrong_protocol["command"] = "expand".into();
    let adapter = SimulatedAssembler {
        expected_request: request(),
        recorded_response: serde_json::to_vec(&wrong_protocol).unwrap(),
    };
    match adapter.assemble(&request()) {
        Err(AssemblyFailure::InvalidResponse(message)) => {
            assert!(message.contains("protocol mismatch"));
        }
        _ => panic!("expected protocol mismatch"),
    }
}

#[test]
fn simulated_assembler_preserves_provider_rejection_as_typed_failure() {
    let mut value: serde_json::Value = serde_json::from_slice(&synthetic_response()).unwrap();
    value["ok"] = false.into();
    value["diagnostics"] = serde_json::json!([{"code":"P001","message":"cannot assemble"}]);
    let adapter = SimulatedAssembler {
        expected_request: request(),
        recorded_response: serde_json::to_vec(&value).unwrap(),
    };
    match adapter.assemble(&request()) {
        Err(AssemblyFailure::ProviderRejected(message)) => {
            assert!(message.contains("cannot assemble"))
        }
        _ => panic!("expected provider rejection"),
    }
}

#[test]
fn simulated_assembler_maps_null_error_data_to_typed_provider_rejection() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "ok": false,
        "command": "assemble",
        "data": null,
        "diagnostics": [{"code":"P001", "message":"provider declined"}]
    }))
    .unwrap();
    let adapter = SimulatedAssembler {
        expected_request: request(),
        recorded_response: bytes,
    };
    match adapter.assemble(&request()) {
        Err(AssemblyFailure::ProviderRejected(message)) => {
            assert!(message.contains("provider declined"))
        }
        _ => panic!("expected typed provider rejection"),
    }
}

#[test]
fn simulated_assembler_rejects_success_response_without_bundle() {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "ok": true,
        "command": "assemble",
        "data": null,
        "diagnostics": []
    }))
    .unwrap();
    let adapter = SimulatedAssembler {
        expected_request: request(),
        recorded_response: bytes,
    };
    match adapter.assemble(&request()) {
        Err(AssemblyFailure::InvalidResponse(message)) => assert!(message.contains("no bundle")),
        _ => panic!("expected invalid missing-data response"),
    }
}

#[cfg(unix)]
#[test]
fn process_adapter_nonzero_exit_remains_typed_provider_rejection() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("adapter");
    fs::write(&executable, b"#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = ProcessAssembler {
        executable: &executable,
        timeout: Duration::from_secs(1),
    };
    let mut request = request();
    request.ui = temp.path().display().to_string();
    match adapter.assemble(&request) {
        Err(AssemblyFailure::ProviderRejected(message)) => {
            assert!(message.contains("no diagnostics"))
        }
        outcome => panic!("expected typed provider rejection, got {outcome:?}"),
    }
}

type ApplicationFixture = (
    AssemblyRequest,
    Lock,
    BTreeMap<String, Vec<u8>>,
    Bundle,
    BTreeMap<String, String>,
);

fn application_fixture(root: &Path) -> ApplicationFixture {
    fs::create_dir_all(root.join("ui/pages")).unwrap();
    let source = b"<main>source</main>";
    fs::write(root.join("ui/pages/index.html"), source).unwrap();
    let actual_inputs: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("foo.d.ts".into(), b"opaque locked provider input".to_vec()),
        (
            "styles.css".into(),
            b".proof { display: block; }\n".to_vec(),
        ),
    ]);
    fs::create_dir(root.join("package")).unwrap();
    let package_inputs = actual_inputs
        .iter()
        .map(|(path, bytes)| {
            fs::write(root.join("package").join(path), bytes).unwrap();
            Input {
                path: path.clone(),
                digest: sha(bytes),
                bytes: bytes.len(),
            }
        })
        .collect::<Vec<_>>();
    let package_digest = manifest_digest(&package_inputs).unwrap();
    let package = LockedPackage {
        name: "opaque-package".into(),
        version: "1".into(),
        path: "../package".into(),
        digest: package_digest.clone(),
        inputs: package_inputs.clone(),
    };
    let lock = Lock {
        schema_version: 1,
        provider: "test-provider".into(),
        package: package.clone(),
    };
    fs::write(root.join(LOCK), serde_json::to_vec(&lock).unwrap()).unwrap();
    let admitted_lock = parse_lock(&root.join(LOCK)).unwrap();
    assert_eq!(
        super::package_inputs(&root.join("package"), &admitted_lock.package).unwrap(),
        actual_inputs
    );
    let mut private_package = package;
    private_package.path = root.join("package").display().to_string();
    let request = AssemblyRequest {
        schema_version: 1,
        assembly_protocol: 2,
        provider: "test-provider".into(),
        target: AssemblyTarget {
            binding_abi: 2,
            template_engine: "minijinja-2.12.0".into(),
        },
        package: private_package,
        ui: root.join("ui").display().to_string(),
    };
    let mut inputs = package_inputs
        .iter()
        .map(|input| Input {
            path: format!("package/{}", input.path),
            digest: input.digest.clone(),
            bytes: input.bytes,
        })
        .collect::<Vec<_>>();
    inputs.push(Input {
        path: "ui/pages/index.html".into(),
        digest: sha(source),
        bytes: source.len(),
    });
    let stylesheet = &actual_inputs["styles.css"];
    let bundle = Bundle {
        schema_version: 1,
        runtime_abi: 2,
        template_engine: "minijinja-2.12.0".into(),
        package_digest,
        templates: BTreeMap::from([("pages/index.html".into(), "<main>expanded</main>".into())]),
        resources: vec![Resource {
            path: "ui/provider.css".into(),
            source: Some("styles.css".into()),
            content: None,
            digest: sha(stylesheet),
            bytes: stylesheet.len(),
            kind: "stylesheet".into(),
        }],
        inputs,
        consumed_inputs: vec![],
    };
    let hashes = BTreeMap::from([
        ("app/ui/pages/index.html".into(), sha(source)),
        (
            format!("app/{LOCK}"),
            sha(&serde_json::to_vec(&lock).unwrap()),
        ),
    ]);
    (request, lock, actual_inputs, bundle, hashes)
}

// Synthetic protocol bytes for exercising admission/staging only; not real producer evidence.
fn synthetic_bundle_response(bundle: &Bundle) -> Vec<u8> {
    let inputs = bundle
        .inputs
        .iter()
        .map(|input| {
            serde_json::json!({
                "path": input.path, "digest": input.digest, "bytes": input.bytes
            })
        })
        .collect::<Vec<_>>();
    let resources = bundle
        .resources
        .iter()
        .map(|resource| {
            serde_json::json!({
                "path": resource.path, "source": resource.source, "content": resource.content,
                "digest": resource.digest, "bytes": resource.bytes, "kind": resource.kind,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1, "ok": true, "command": "assemble", "diagnostics": [],
        "data": {
            "schemaVersion": bundle.schema_version, "runtimeAbi": bundle.runtime_abi,
            "templateEngine": bundle.template_engine, "packageDigest": bundle.package_digest,
            "templates": bundle.templates, "resources": resources,
            "inputs": inputs, "consumedInputs": bundle.consumed_inputs
        }
    }))
    .unwrap()
}

#[test]
fn simulated_assembly_runs_real_admission_and_staging_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let (request, lock, package, bundle, mut hashes) = application_fixture(temp.path());
    let adapter = SimulatedAssembler {
        expected_request: request.clone(),
        recorded_response: synthetic_bundle_response(&bundle),
    };
    assemble_and_stage(
        &adapter,
        &mut FilePublication {
            captured: temp.path(),
        },
        &request,
        &lock,
        &package,
        &mut hashes,
    )
    .unwrap();
    assert_eq!(
        fs::read(temp.path().join("ui/pages/index.html")).unwrap(),
        b"<main>expanded</main>"
    );
    assert_eq!(hashes["ui/package"], lock.package.digest);
    assert_eq!(
        hashes["app/ui/pages/index.html"],
        sha(b"<main>expanded</main>")
    );
    assert_eq!(
        fs::read(temp.path().join("ui/provider.css")).unwrap(),
        package["styles.css"]
    );
    assert_eq!(hashes["app/ui/provider.css"], sha(&package["styles.css"]));
    assert!(temp.path().join(LOCK).exists());
    assert!(
        !hashes.contains_key("ui-provider/executable"),
        "simulation is not executable-pin evidence"
    );
}

#[test]
fn simulated_assembly_rejects_tampered_inputs_and_resources_without_partial_staging() {
    for tamper_resource in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (request, lock, package, mut bundle, mut hashes) = application_fixture(temp.path());
        if tamper_resource {
            bundle.resources[0].digest = sha(b"tampered");
        } else {
            bundle.inputs[0].digest = sha(b"tampered");
        }
        let original_hashes = hashes.clone();
        let adapter = SimulatedAssembler {
            expected_request: request.clone(),
            recorded_response: synthetic_bundle_response(&bundle),
        };
        assert!(
            assemble_and_stage(
                &adapter,
                &mut FilePublication {
                    captured: temp.path()
                },
                &request,
                &lock,
                &package,
                &mut hashes
            )
            .is_err()
        );
        assert_eq!(
            fs::read(temp.path().join("ui/pages/index.html")).unwrap(),
            b"<main>source</main>"
        );
        assert!(!temp.path().join("ui/provider.css").exists());
        assert_eq!(hashes, original_hashes);
    }
}

#[cfg(unix)]
#[test]
fn process_adapter_timeout_is_a_typed_failure() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("adapter");
    // Minimal process-adapter test data; no generated or component-specific CLI fixture.
    fs::write(&executable, b"#!/bin/sh\nsleep 2\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = ProcessAssembler {
        executable: &executable,
        timeout: Duration::from_millis(30),
    };
    let mut request = request();
    request.ui = temp.path().display().to_string();
    let error = adapter.assemble(&request).unwrap_err();
    assert!(matches!(error, AssemblyFailure::Timeout), "got {error:?}");
}

#[cfg(unix)]
#[test]
fn process_adapter_deadline_covers_descendant_held_output_pipes() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("adapter");
    fs::write(&executable, b"#!/bin/sh\n/bin/sleep 1 &\nexit 0\n").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = ProcessAssembler {
        executable: &executable,
        timeout: Duration::from_millis(30),
    };
    let mut request = request();
    request.ui = temp.path().display().to_string();
    let started = Instant::now();
    assert!(matches!(
        adapter.assemble(&request),
        Err(AssemblyFailure::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_millis(700));
}
