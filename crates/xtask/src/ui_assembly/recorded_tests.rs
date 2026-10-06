use super::port::SimulatedAssembler;
use super::*;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ui_assembly/fixtures/clanker-ui-v1")
}

type CapturedFixture = (
    tempfile::TempDir,
    Lock,
    BTreeMap<String, Vec<u8>>,
    BTreeMap<String, String>,
    AssemblyRequest,
);

fn captured() -> CapturedFixture {
    let temp = tempfile::tempdir().unwrap();
    copy_tree_checked(&fixture().join("app/ui"), &temp.path().join("ui")).unwrap();
    let lock = parse_lock(&temp.path().join(LOCK)).unwrap();
    let inputs = package_inputs(&fixture().join("package"), &lock.package).unwrap();
    let response: Envelope =
        serde_json::from_slice(include_bytes!("fixtures/clanker-ui-v1/response.json")).unwrap();
    let hashes = response
        .data
        .inputs
        .iter()
        .filter_map(|input| {
            input
                .path
                .strip_prefix("ui/")
                .map(|_| (format!("app/{}", input.path), input.digest.clone()))
        })
        .collect();
    let mut package = lock.package.clone();
    package.path = fixture().join("package").display().to_string();
    let request = AssemblyRequest {
        schema_version: 1,
        assembly_protocol: 2,
        provider: lock.provider.clone(),
        target: AssemblyTarget {
            binding_abi: 2,
            template_engine: "minijinja-2.12.0".into(),
        },
        package,
        ui: temp.path().join("ui").display().to_string(),
    };
    (temp, lock, inputs, hashes, request)
}

fn assert_recorded_outputs(captured: &Path) {
    let response: Envelope =
        serde_json::from_slice(include_bytes!("fixtures/clanker-ui-v1/response.json")).unwrap();
    for (path, html) in &response.data.templates {
        assert_eq!(
            checked(&captured.join("ui"), path).unwrap(),
            html.as_bytes()
        );
    }
    for resource in &response.data.resources {
        let bytes = checked(captured, &resource.path).unwrap();
        assert_eq!(bytes.len(), resource.bytes);
        assert_eq!(sha(&bytes), resource.digest);
    }
}

#[test]
fn recorded_provider_response_runs_real_host_admission_and_staging() {
    let (captured, lock, inputs, mut hashes, request) = captured();
    let adapter = SimulatedAssembler {
        expected_request: request.clone(),
        recorded_response: include_bytes!("fixtures/clanker-ui-v1/response.json").to_vec(),
    };
    assemble_and_stage(
        &adapter,
        &request,
        &lock,
        &inputs,
        captured.path(),
        &mut hashes,
    )
    .unwrap();
    assert_recorded_outputs(captured.path());
    assert_eq!(hashes.get(PACKAGE_KEY), Some(&lock.package.digest));
    assert!(
        !hashes.contains_key("ui-provider/executable"),
        "simulation is not executable-pin evidence"
    );
    assert!(captured.path().join(LOCK).exists());
}

#[test]
fn tampered_recording_cannot_bypass_real_host_admission() {
    let (captured, lock, inputs, mut hashes, request) = captured();
    let original = checked(&captured.path().join("ui"), "pages/proof.html").unwrap();
    let mut response: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/clanker-ui-v1/response.json")).unwrap();
    response["data"]["inputs"][0]["digest"] = format!("sha256:{}", "a".repeat(64)).into();
    let adapter = SimulatedAssembler {
        expected_request: request.clone(),
        recorded_response: serde_json::to_vec(&response).unwrap(),
    };
    assert!(
        assemble_and_stage(
            &adapter,
            &request,
            &lock,
            &inputs,
            captured.path(),
            &mut hashes
        )
        .is_err()
    );
    assert_eq!(
        checked(&captured.path().join("ui"), "pages/proof.html").unwrap(),
        original
    );
    assert!(!hashes.contains_key(PACKAGE_KEY));
}

#[test]
#[ignore = "requires a separately operator-trusted producer executable pin"]
fn real_provider_matches_recorded_contract() {
    let (captured, _, _, mut hashes, _) = captured();
    let pin =
        std::env::var_os("DAY2_UI_TEST_PROVIDER_PIN_JSON").expect("explicit operator pin required");
    expand_with_pin(
        &fixture().join("app"),
        captured.path(),
        &mut hashes,
        Path::new(&pin),
    )
    .unwrap();
    assert_recorded_outputs(captured.path());
    assert!(hashes.contains_key("ui-provider/executable"));
}
