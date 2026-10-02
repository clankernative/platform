use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Source {
    abi_version: u32,
    origin: String,
    files: std::collections::BTreeMap<String, String>,
}

#[test]
fn vendored_runtime_matches_its_canonical_source_pins() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("vendor/clanker-ui-runtime");
    let source: Source = serde_json::from_slice(
        &std::fs::read(root.join("SOURCE.json")).expect("runtime source pin exists"),
    )
    .expect("runtime source pin is valid JSON");

    assert_eq!(source.abi_version, 1);
    assert_eq!(
        source.origin,
        "internal-tools/clanker-native-ui/crates/clanker-ui-runtime"
    );
    let canonical_pins = [
        (
            "Cargo.toml",
            "7606e1ef15d50b9671c1257fd869c1af2412ef24ab4907f3b4e22e0295d076da",
        ),
        (
            "src/lib.rs",
            "6a3623f6403d92f3c5fb7a9ad24a7cd5912c89e5393c1afc74ec82a30c1d6bd1",
        ),
    ];
    assert_eq!(source.files.len(), canonical_pins.len());
    for (relative_path, canonical_digest) in canonical_pins {
        assert_eq!(
            source.files.get(relative_path).map(String::as_str),
            Some(canonical_digest)
        );
        let bytes = std::fs::read(root.join(relative_path))
            .unwrap_or_else(|error| panic!("cannot read vendored {relative_path}: {error}"));
        let actual_digest = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(
            actual_digest, canonical_digest,
            "vendored {relative_path} changed"
        );
    }
}
