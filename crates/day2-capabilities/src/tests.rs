use super::*;

#[test]
fn local_build_provider_has_no_app_selected_ui_assembly_configuration() {
    let configuration = serde_json::json!({
        "kind": "local_macos",
        "platform_root": "/opt/platform",
        "toolchains": "/opt/toolchains",
        "xtask": "/opt/xtask",
        "rust": "/opt/rust",
        "registry": "/opt/registry"
    });
    let provider: BuildProvider = serde_json::from_value(configuration).unwrap();
    let serialized = serde_json::to_value(provider).unwrap();
    assert!(serialized.get("ui_assembly").is_none());
    assert!(
        serde_json::from_value::<BuildProvider>(serde_json::json!({
            "kind": "local_macos",
            "platform_root": "/opt/platform",
            "toolchains": "/opt/toolchains",
            "xtask": "/opt/xtask",
            "rust": "/opt/rust",
            "registry": "/opt/registry",
            "ui_assembly": {
                "provider_pin": "/opt/ui/provider.json",
                "package_root": "/opt/ui/package",
                "package_key": "clanker-vanilla"
            }
        }))
        .is_err()
    );
}
