//! Opt-in host conformance against a provider-owned corpus, never a bundled provider package.
use super::*;

#[test]
#[ignore = "requires an operator-approved provider pin and an external expected-output fixture"]
fn external_provider_matches_expected_outputs() {
    let fixture = PathBuf::from(
        std::env::var_os("DAY2_UI_TEST_FIXTURE").expect("explicit external fixture required"),
    );
    let pin = PathBuf::from(
        std::env::var_os("DAY2_UI_TEST_PROVIDER_PIN_JSON").expect("explicit operator pin required"),
    );
    assert!(fixture.is_absolute() && pin.is_absolute());
    let captured = tempfile::tempdir().unwrap();
    copy_tree_checked(&fixture.join("app/ui"), &captured.path().join("ui")).unwrap();
    let expected: Envelope = serde_json::from_slice(
        &day2::assets::read_regular(&fixture.join("response.json"), MAX_STDOUT as u64).unwrap(),
    )
    .unwrap();
    assert!(expected.ok && expected.command == "assemble");
    let snapshot = FilePublication {
        captured: captured.path(),
    }
    .capture()
    .unwrap();
    let mut hashes = snapshot
        .files
        .iter()
        .map(|(path, bytes)| (format!("app/ui/{path}"), sha(bytes)))
        .collect::<BTreeMap<_, _>>();
    expand_with_pin(&fixture.join("app"), captured.path(), &mut hashes, &pin).unwrap();
    for (path, html) in &expected.data.templates {
        assert_eq!(
            checked(&captured.path().join("ui"), path).unwrap(),
            html.as_bytes()
        );
    }
    for resource in &expected.data.resources {
        let bytes = checked(captured.path(), &resource.path).unwrap();
        assert_eq!(bytes.len(), resource.bytes);
        assert_eq!(sha(&bytes), resource.digest);
    }
    assert_eq!(hashes.get(PACKAGE_KEY), Some(&expected.data.package_digest));
    assert!(hashes.contains_key("ui-provider/executable"));
}
