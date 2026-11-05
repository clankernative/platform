use super::*;
use serde_json::{Value, json};

fn selection() -> Result<KeySelection> {
    Ok(KeySelection {
        version: KeyVersion::try_from("projects/one-project/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/7".to_owned())?,
        public_key:[7;32],
    })
}

#[test]
fn exact_public_selection_roundtrips_and_commits_version_and_key() -> Result<()> {
    let original = selection()?;
    original.validate()?;
    let decoded: KeySelection = serde_json::from_slice(&serde_json::to_vec(&original)?)?;
    assert_eq!(original, decoded);
    assert_eq!(original.commitment()?, decoded.commitment()?);
    let mut version = original.clone();
    version.version = KeyVersion::try_from(
        original
            .version
            .as_str()
            .replace("Versions/7", "Versions/8"),
    )?;
    let mut material = original.clone();
    material.public_key[0] ^= 1;
    for changed in [version, material] {
        changed.validate()?;
        assert_ne!(original, changed);
        assert_ne!(original.commitment()?, changed.commitment()?);
    }
    assert_ne!(
        original.commitment()?,
        Digest::of(&("another-purpose", &original))?
    );
    Ok(())
}

#[test]
fn aliases_urls_noncanonical_versions_and_path_substitutions_refuse() -> Result<()> {
    let key = selection()?.version.as_str().to_owned();
    for changed in [
        key.replace("Versions/7", "Versions/0"),
        key.replace("Versions/7", "Versions/07"),
        key.replace("Versions/7", "Versions/-1"),
        key.replace("Versions/7", "Versions/+7"),
        key.replace("Versions/7", "Versions/18446744073709551616"),
        key.replace("Versions/7", "Versions/current"),
        key.replace("/cryptoKeyVersions/7", ""),
        key.replace("approval/", "../"),
        key.replace("approval/", "%2fother/"),
        key.replace("approval/", "another.key/"),
        key.replace("approval/", "another\\key/"),
        key.replace("approval/", "another key/"),
        key.replace("one-project/", "/"),
        key.replace("locations/global", "regions/global"),
        key.replace("approval/", &format!("{}/", "a".repeat(64))),
        format!("https://cloudkms.googleapis.com/v1/{key}"),
        format!("{key}/"),
        format!("{key}?alt=json"),
        format!("{key}#fragment"),
        "a".repeat(513),
    ] {
        assert!(KeyVersion::try_from(changed.clone()).is_err(), "{changed}");
        assert!(serde_json::from_value::<KeyVersion>(json!(changed)).is_err());
    }
    Ok(())
}

#[test]
fn private_or_configurable_crypto_fields_and_malformed_public_material_refuse() -> Result<()> {
    let original = selection()?;
    for field in [
        "private_key",
        "algorithm",
        "provider",
        "signer",
        "authorized",
        "origin",
    ] {
        let mut value = serde_json::to_value(&original)?;
        value
            .as_object_mut()
            .expect("selection")
            .insert(field.into(), json!(true));
        assert!(
            serde_json::from_value::<KeySelection>(value).is_err(),
            "{field}"
        );
    }
    for bytes in [vec![], vec![7; 31], vec![7; 33]] {
        let mut invalid = serde_json::to_value(&original)?;
        invalid["public_key"] = json!(bytes);
        assert!(serde_json::from_value::<KeySelection>(invalid).is_err());
    }
    let mut zero = original.clone();
    zero.public_key = [0; 32];
    assert!(zero.validate().is_err());
    assert!(zero.commitment().is_err());
    for version in [
        Value::Null,
        json!(7),
        json!({"name":original.version.as_str()}),
    ] {
        let mut value = serde_json::to_value(&original)?;
        value["version"] = version;
        assert!(serde_json::from_value::<KeySelection>(value).is_err());
    }
    let encoded = serde_json::to_string(&original)?;
    let duplicate = encoded.replacen("{", "{\"version\":\"forged\",", 1);
    assert!(serde_json::from_str::<KeySelection>(&duplicate).is_err());
    Ok(())
}
