use super::*;

const CONTRACT: &str = "components/sample/browser.d.ts";

fn package_fixture(root: &Path, contracts: Option<serde_json::Value>) {
    fs::create_dir_all(root.join("components/sample")).unwrap();
    fs::write(
        root.join("ui-package.json"),
        br#"{"schemaVersion":1,"theme":"theme.css"}"#,
    )
    .unwrap();
    fs::write(root.join("theme.css"), b"/* theme */").unwrap();
    fs::write(
        root.join("components/sample/fragment.html"),
        b"<p>sample</p>",
    )
    .unwrap();
    fs::write(root.join("components/sample/styles.css"), b"/* sample */").unwrap();
    let mut component = serde_json::json!({
        "status": "ready",
        "assets": {
            "template": "components/sample/fragment.html",
            "styles": "components/sample/styles.css",
            "scripts": []
        },
        "fixtures": []
    });
    if let Some(contracts) = contracts {
        component["assets"]["contracts"] = contracts;
    }
    fs::write(
        root.join("components/sample/component.json"),
        serde_json::to_vec(&component).unwrap(),
    )
    .unwrap();
}

#[test]
fn captures_declared_contract_bytes_but_not_undeclared_files() {
    let temp = tempfile::tempdir().unwrap();
    package_fixture(temp.path(), Some(serde_json::json!([CONTRACT])));
    let bytes = b"export interface SamplePort { cancel(): void; }";
    fs::write(temp.path().join(CONTRACT), bytes).unwrap();
    fs::write(
        temp.path().join("components/sample/undeclared.js"),
        b"unused",
    )
    .unwrap();
    let inputs = package_inputs(temp.path()).unwrap();
    assert_eq!(inputs[CONTRACT], bytes);
    assert_eq!(inputs.len(), 6);
    assert!(!inputs.contains_key("components/sample/undeclared.js"));
    fs::write(temp.path().join(CONTRACT), b"changed contract").unwrap();
    assert_ne!(
        inputs[CONTRACT],
        package_inputs(temp.path()).unwrap()[CONTRACT]
    );
}

#[test]
fn contracts_are_optional_for_existing_packages() {
    for contracts in [None, Some(serde_json::json!([]))] {
        let temp = tempfile::tempdir().unwrap();
        package_fixture(temp.path(), contracts);
        assert_eq!(package_inputs(temp.path()).unwrap().len(), 5);
    }
}

#[test]
fn rejects_malformed_contract_declarations() {
    for contracts in [
        serde_json::Value::Null,
        serde_json::json!(CONTRACT),
        serde_json::json!([false]),
    ] {
        let temp = tempfile::tempdir().unwrap();
        package_fixture(temp.path(), Some(contracts));
        assert!(package_inputs(temp.path()).is_err());
    }
}

#[test]
fn rejects_missing_escaping_and_oversized_contract_files() {
    for path in [CONTRACT, "../outside.d.ts", "/outside.d.ts"] {
        let temp = tempfile::tempdir().unwrap();
        package_fixture(temp.path(), Some(serde_json::json!([path])));
        assert!(package_inputs(temp.path()).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    package_fixture(temp.path(), Some(serde_json::json!([CONTRACT])));
    fs::write(temp.path().join(CONTRACT), vec![b'x'; MAX_FILE + 1]).unwrap();
    assert!(package_inputs(temp.path()).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_contract_files() {
    let temp = tempfile::tempdir().unwrap();
    package_fixture(temp.path(), Some(serde_json::json!([CONTRACT])));
    fs::write(temp.path().join("real.d.ts"), b"contract").unwrap();
    std::os::unix::fs::symlink(temp.path().join("real.d.ts"), temp.path().join(CONTRACT)).unwrap();
    assert!(package_inputs(temp.path()).is_err());
}

#[test]
fn locked_contract_inputs_are_required_and_not_automatically_staged() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, lock, mut package, hashes) = super::fixture_bundle(temp.path());
    let bytes = b"export interface SamplePort {}";
    package.insert(CONTRACT.into(), bytes.to_vec());
    assert!(validate_bundle(&bundle, &lock, &package, temp.path(), &hashes).is_err());
    bundle.inputs.push(Input {
        path: format!("package/{CONTRACT}"),
        bytes: bytes.len(),
        digest: sha(bytes),
    });
    validate_bundle(&bundle, &lock, &package, temp.path(), &hashes).unwrap();
    assert!(bundle.resources.is_empty());
    assert!(bundle.entrypoints.is_empty());
    apply_bundle(&bundle, &package, temp.path()).unwrap();
    assert!(!temp.path().join("ui").join(CONTRACT).exists());
    package.insert(CONTRACT.into(), b"modified bytes".to_vec());
    assert!(validate_bundle(&bundle, &lock, &package, temp.path(), &hashes).is_err());
}
