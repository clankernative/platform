use super::*;

#[test]
fn local_build_provider_without_ui_keeps_legacy_serialized_identity() {
    let legacy = serde_json::json!({
        "kind": "local_macos",
        "platform_root": "/opt/platform",
        "toolchains": "/opt/toolchains",
        "xtask": "/opt/xtask",
        "rust": "/opt/rust",
        "registry": "/opt/registry"
    });
    let provider: BuildProvider = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(provider).unwrap(), legacy);
}

#[test]
fn ui_assembly_paths_and_package_key_are_typed_and_bounded() {
    let valid = serde_json::json!({
        "provider_pin": "/opt/ui/provider.json",
        "package_root": "/opt/ui/package",
        "package_key": "clanker-vanilla"
    });
    let provider: UiAssemblyProvider = serde_json::from_value(valid).unwrap();
    assert_eq!(provider.package_key.as_str(), "clanker-vanilla");
    assert!(provider.validate().is_ok());
    let relative: UiAssemblyProvider = serde_json::from_value(serde_json::json!({
        "provider_pin": "relative/provider.json",
        "package_root": "/opt/ui/package",
        "package_key": "clanker-vanilla"
    }))
    .unwrap();
    assert!(relative.validate().is_err());
    assert!(
        serde_json::from_value::<UiAssemblyProvider>(serde_json::json!({
            "provider_pin": "/opt/ui/provider.json",
            "package_root": "/opt/ui/package",
            "package_key": "../package"
        }))
        .is_err()
    );
}
