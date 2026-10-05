use super::*;

#[path = "contracts_tests.rs"]
mod contract_tests;

fn fixture_bundle(
    captured: &Path,
) -> (
    Bundle,
    Lock,
    BTreeMap<String, Vec<u8>>,
    BTreeMap<String, String>,
) {
    fs::create_dir_all(captured.join("ui/pages")).unwrap();
    let html = b"<main>source</main>";
    fs::write(captured.join("ui/pages/index.html"), html).unwrap();
    fs::write(captured.join("ui/app.js"), b"/* unused app-owned module */").unwrap();
    let package = BTreeMap::from([("ui-package.json".into(), b"locked manifest".to_vec())]);
    let digest = sha(b"test package identity");
    let lock = Lock {
        schema_version: 1,
        package: "@clanker/vanilla".into(),
        version: "0.7.0".into(),
        path: "../../package".into(),
        digest: digest.clone(),
    };
    let inputs = vec![
        Input {
            path: "package/ui-package.json".into(),
            bytes: 15,
            digest: sha(b"locked manifest"),
        },
        Input {
            path: "ui/pages/index.html".into(),
            bytes: html.len(),
            digest: sha(html),
        },
    ];
    let bundle = Bundle {
        schema_version: 1,
        runtime_abi: 1,
        template_engine: "minijinja-2.12.0".into(),
        package_digest: digest,
        templates: BTreeMap::from([("pages/index.html".into(), "<main>expanded</main>".into())]),
        bindings: vec![],
        entrypoints: vec![],
        resources: vec![],
        inputs,
        consumed_inputs: vec![],
    };
    let hashes = BTreeMap::from([
        ("app/ui/pages/index.html".into(), sha(html)),
        (
            "app/ui/app.js".into(),
            sha(b"/* unused app-owned module */"),
        ),
    ]);
    (bundle, lock, package, hashes)
}
#[test]
fn input_manifest_can_omit_unused_app_assets_but_not_locked_inputs_or_templates() {
    let temp = tempfile::tempdir().unwrap();
    let (mut b, lock, package, hashes) = fixture_bundle(temp.path());
    validate_bundle(&b, &lock, &package, temp.path(), &hashes).unwrap();
    b.inputs.remove(0);
    assert!(validate_bundle(&b, &lock, &package, temp.path(), &hashes).is_err());
    let (mut b, lock, package, hashes) = fixture_bundle(temp.path());
    b.templates.clear();
    assert!(validate_bundle(&b, &lock, &package, temp.path(), &hashes).is_err());
}
#[test]
fn source_digest_and_original_snapshot_hash_mismatches_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (b, lock, package, mut hashes) = fixture_bundle(temp.path());
    hashes.insert("app/ui/pages/index.html".into(), sha(b"changed"));
    assert!(validate_bundle(&b, &lock, &package, temp.path(), &hashes).is_err());
    hashes.insert(
        "app/ui/pages/index.html".into(),
        sha(b"<main>source</main>"),
    );
    fs::write(
        temp.path().join("ui/pages/index.html"),
        b"changed after capture",
    )
    .unwrap();
    assert!(validate_bundle(&b, &lock, &package, temp.path(), &hashes).is_err());
}
#[test]
fn staging_uses_verified_resource_bytes_and_collisions_cause_no_partial_write() {
    let temp = tempfile::tempdir().unwrap();
    let (mut b, _, mut package, _) = fixture_bundle(temp.path());
    let font = b"captured font bytes";
    package.insert("fonts/test.woff2".into(), font.to_vec());
    b.resources.push(Resource {
        path: "ui/fonts/test.woff2".into(),
        source: Some("fonts/test.woff2".into()),
        content: None,
        bytes: font.len(),
        digest: sha(font),
        kind: "font".into(),
    });
    apply_bundle(&b, &package, temp.path()).unwrap();
    assert_eq!(
        fs::read(temp.path().join("ui/fonts/test.woff2")).unwrap(),
        font
    );
    let (mut b, _, package, _) = fixture_bundle(temp.path());
    b.resources.push(Resource {
        path: "ui/app.js".into(),
        source: None,
        content: Some("overwrite app module".into()),
        bytes: 20,
        digest: sha(b"overwrite app module"),
        kind: "module".into(),
    });
    let before = fs::read(temp.path().join("ui/pages/index.html")).unwrap();
    assert!(apply_bundle(&b, &package, temp.path()).is_err());
    assert_eq!(
        fs::read(temp.path().join("ui/pages/index.html")).unwrap(),
        before
    );
    assert_eq!(
        fs::read(temp.path().join("ui/app.js")).unwrap(),
        b"/* unused app-owned module */"
    );
}
#[cfg(unix)]
#[test]
fn dangling_lock_symlink_does_not_silently_disable_adapter_admission() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    symlink("missing-lock.json", temp.path().join(LOCK)).unwrap();
    assert!(lock_present(temp.path()).unwrap());
    assert!(parse_lock(&temp.path().join(LOCK)).is_err());
}
