use super::*;

fn capture_fixture(captured: &Path) -> UiSnapshot {
    FilePublication { captured }.capture().unwrap()
}

fn publish_fixture(
    bundle: &Bundle,
    package: &BTreeMap<String, Vec<u8>>,
    captured: &Path,
) -> Result<()> {
    let mut publication = FilePublication { captured };
    let snapshot = publication.capture()?;
    let plan = plan_bundle(bundle, package, &snapshot)?;
    publication.publish(&snapshot, &plan)
}

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
    let package: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("foo.d.ts".into(), b"opaque declaration data".to_vec()),
        (
            "payload.bin".into(),
            b"provider-owned opaque bytes".to_vec(),
        ),
    ]);
    let package_inputs = package
        .iter()
        .map(|(path, bytes)| Input {
            path: path.clone(),
            digest: sha(bytes),
            bytes: bytes.len(),
        })
        .collect::<Vec<_>>();
    let package_digest = manifest_digest(&package_inputs).unwrap();
    let locked_package = LockedPackage {
        name: "example-provider-package".into(),
        version: "0.1.0".into(),
        path: "../../package".into(),
        digest: package_digest.clone(),
        inputs: package_inputs.clone(),
    };
    let mut inputs = package_inputs
        .into_iter()
        .map(|mut input| {
            input.path = format!("package/{}", input.path);
            input
        })
        .collect::<Vec<_>>();
    inputs.push(Input {
        path: "ui/pages/index.html".into(),
        bytes: html.len(),
        digest: sha(html),
    });
    let lock = Lock {
        schema_version: 1,
        provider: "opaque-provider".into(),
        package: locked_package,
    };
    let bundle = Bundle {
        schema_version: 1,
        runtime_abi: 2,
        template_engine: "minijinja-2.12.0".into(),
        package_digest,
        templates: BTreeMap::from([("pages/index.html".into(), "<main>expanded</main>".into())]),
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
fn bundle_accepts_runtime_abi_two_and_rejects_abi_one_or_unknown_resource_kind() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    validate_bundle(&bundle, &lock, &package, &ui, &hashes).unwrap();
    bundle.runtime_abi = 1;
    let error = validate_bundle(&bundle, &lock, &package, &ui, &hashes).unwrap_err();
    assert!(error.to_string().contains("runtime ABI"));
    bundle.runtime_abi = 2;
    bundle.resources.push(Resource {
        path: "ui/module.js".into(),
        source: None,
        content: Some("export {};".into()),
        digest: sha(b"export {};"),
        bytes: 10,
        kind: "module".into(),
    });
    validate_bundle(&bundle, &lock, &package, &ui, &hashes).unwrap();
    bundle.resources[0].kind = "executable".into();
    assert!(
        validate_bundle(&bundle, &lock, &package, &ui, &hashes)
            .unwrap_err()
            .to_string()
            .contains("unknown resource kind")
    );
}

#[test]
fn input_closure_requires_every_locked_package_input_and_captured_template() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    validate_bundle(&bundle, &lock, &package, &ui, &hashes).unwrap();
    bundle
        .inputs
        .retain(|input| input.path != "package/foo.d.ts");
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    bundle.templates.clear();
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
}

#[test]
fn ordinary_ui_package_module_uses_resource_digest_collision_and_staging_checks() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    let module = b"import './feature.js';\\n";
    bundle.resources.push(Resource {
        path: "ui/ui-package.js".into(),
        source: None,
        content: Some(String::from_utf8(module.to_vec()).unwrap()),
        digest: sha(module),
        bytes: module.len(),
        kind: "module".into(),
    });
    validate_bundle(&bundle, &lock, &package, &ui, &hashes).unwrap();
    publish_fixture(&bundle, &package, temp.path()).unwrap();
    assert_eq!(
        fs::read(temp.path().join("ui/ui-package.js")).unwrap(),
        module
    );

    bundle.resources[0].digest = sha(b"wrong module bytes");
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
    bundle.resources[0].digest = sha(module);
    bundle.resources[0].path = "ui/pages/index.html".into();
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
}

#[test]
fn unused_app_resources_may_be_omitted_but_claimed_source_hash_must_match_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let (bundle, lock, package, mut hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    validate_bundle(&bundle, &lock, &package, &ui, &hashes).unwrap();
    hashes.insert(
        "app/ui/pages/index.html".into(),
        sha(b"different captured hash"),
    );
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
    hashes.insert(
        "app/ui/pages/index.html".into(),
        sha(b"<main>source</main>"),
    );
    fs::write(
        temp.path().join("ui/pages/index.html"),
        b"changed after capture",
    )
    .unwrap();
    let ui = capture_fixture(temp.path());
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
}

#[test]
fn staging_uses_verified_resource_bytes_and_collision_causes_no_partial_write() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, _, mut package, _) = fixture_bundle(temp.path());
    let font = b"captured font bytes";
    package.insert("fonts/test.woff2".into(), font.to_vec());
    bundle.resources.push(Resource {
        path: "ui/fonts/test.woff2".into(),
        source: Some("fonts/test.woff2".into()),
        content: None,
        bytes: font.len(),
        digest: sha(font),
        kind: "font".into(),
    });
    publish_fixture(&bundle, &package, temp.path()).unwrap();
    assert_eq!(
        fs::read(temp.path().join("ui/fonts/test.woff2")).unwrap(),
        font
    );

    let (mut bundle, _, package, _) = fixture_bundle(temp.path());
    bundle.resources.push(Resource {
        path: "ui/app.js".into(),
        source: None,
        content: Some("overwrite app module".into()),
        bytes: 20,
        digest: sha(b"overwrite app module"),
        kind: "module".into(),
    });
    let before_page = fs::read(temp.path().join("ui/pages/index.html")).unwrap();
    let before_js = fs::read(temp.path().join("ui/app.js")).unwrap();
    assert!(publish_fixture(&bundle, &package, temp.path()).is_err());
    assert_eq!(
        fs::read(temp.path().join("ui/pages/index.html")).unwrap(),
        before_page
    );
    assert_eq!(fs::read(temp.path().join("ui/app.js")).unwrap(), before_js);
}

#[test]
fn provider_cannot_emit_or_consume_the_captured_ui_lock() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    bundle.resources.push(Resource {
        path: "ui/ui.lock.json".into(),
        source: None,
        content: Some("replacement".into()),
        digest: sha(b"replacement"),
        bytes: 11,
        kind: "metadata".into(),
    });
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());

    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    bundle.consumed_inputs.push("ui/ui.lock.json".into());
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
}

#[test]
fn output_case_fold_and_prefix_collisions_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    bundle.resources.push(Resource {
        path: "ui/pages/INDEX.html".into(),
        source: None,
        content: Some("other".into()),
        digest: sha(b"other"),
        bytes: 5,
        kind: "metadata".into(),
    });
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());

    let (mut bundle, lock, package, hashes) = fixture_bundle(temp.path());
    let ui = capture_fixture(temp.path());
    bundle.resources.push(Resource {
        path: "ui/pages/index.html/child.css".into(),
        source: None,
        content: Some("child".into()),
        digest: sha(b"child"),
        bytes: 5,
        kind: "stylesheet".into(),
    });
    assert!(validate_bundle(&bundle, &lock, &package, &ui, &hashes).is_err());
}

#[test]
fn captured_package_snapshot_is_immutable_when_mutable_original_changes() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    fs::create_dir_all(&original).unwrap();
    let (package_meta, files) = {
        let (lock, files) = fixture_bundle_package();
        (lock, files)
    };
    for (path, bytes) in &files {
        fs::write(original.join(path), bytes).unwrap();
    }
    let captured = package_inputs(&original, &package_meta).unwrap();
    let private = temp.path().join("private-package");
    capture_package(&captured, &private).unwrap();
    fs::write(original.join("foo.d.ts"), b"mutated original package").unwrap();
    assert_eq!(
        fs::read(private.join("foo.d.ts")).unwrap(),
        b"opaque declaration data"
    );
    assert_eq!(captured["foo.d.ts"], b"opaque declaration data");
}

fn fixture_bundle_package() -> (LockedPackage, BTreeMap<String, Vec<u8>>) {
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
    let package = LockedPackage {
        name: "example-provider-package".into(),
        version: "0.1.0".into(),
        path: "../../package".into(),
        digest: manifest_digest(&inputs).unwrap(),
        inputs,
    };
    (package, files)
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
