use super::*;
use serde_json::{Value, json};

fn fields() -> [Vec<u8>; 5] {
    [
        vec![1, 2],
        vec![3, 0x26],
        vec![0x20, 1],
        [vec![0x21, 0x58, 0x20], (0..32).collect()].concat(),
        [vec![0x22, 0x58, 0x20], (32..64).collect()].concat(),
    ]
}

fn key() -> AdminPasskey {
    AdminPasskey {
        email: "admin@example.test".into(),
        subject: "iap-subject".into(),
        credential_id: vec![1, 2, 3],
        user_handle: vec![4, 5],
        cose_key: PublicCoseKey::try_from([vec![0xa5], fields().concat()].concat()).unwrap(),
        backup_eligible: false,
        rp_id: "restore.example.test".into(),
        origin: "https://restore.example.test".into(),
    }
}

fn registry() -> Registry {
    Registry {
        version: 1,
        keys: BTreeMap::from([(Name::try_from("primary".to_owned()).unwrap(), key())]),
    }
}

#[test]
fn public_cose_is_order_independent_and_preserves_coordinate_zeroes() {
    let canonical = key().cose_key;
    assert_eq!(canonical.uncompressed_p256()[0], 4);
    assert_eq!(
        &canonical.uncompressed_p256()[1..],
        &(0..64).collect::<Vec<_>>()
    );
    let fields = fields();
    let mut count = 0;
    for a in 0..5 {
        for b in 0..5 {
            for c in 0..5 {
                for d in 0..5 {
                    for e in 0..5 {
                        let order = [a, b, c, d, e];
                        if order.into_iter().collect::<BTreeSet<_>>().len() != 5 {
                            continue;
                        }
                        let bytes = [
                            vec![0xa5],
                            order.into_iter().flat_map(|i| fields[i].clone()).collect(),
                        ]
                        .concat();
                        let parsed = PublicCoseKey::try_from(bytes).unwrap();
                        assert_eq!(parsed, canonical);
                        assert_eq!(parsed.cose_bytes(), canonical.cose_bytes());
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 120);
    let encoded = serde_json::to_vec(&canonical).unwrap();
    assert_eq!(
        serde_json::from_slice::<PublicCoseKey>(&encoded).unwrap(),
        canonical
    );
}

#[test]
fn cose_rejects_private_duplicate_alternate_and_nonminimal_shapes() {
    let valid = key().cose_key.cose_bytes();
    let mut bad = vec![
        vec![],
        vec![0xa5],
        valid[..76].to_vec(),
        [valid.clone(), vec![0]].concat(),
    ];
    for (index, replacement) in [
        (0, 0xbf),
        (1, 0x18),
        (2, 3),
        (3, 1),
        (4, 0x25),
        (6, 2),
        (7, 0x23),
        (8, 0x59),
        (9, 0x1f),
        (42, 0x21),
    ] {
        let mut bytes = valid.clone();
        bytes[index] = replacement;
        bad.push(bytes);
    }
    // CBOR tag and nonminimal integer labels cannot be normalized into the profile.
    bad.push([vec![0xd8, 0x18], valid.clone()].concat());
    bad.push([vec![0xa5, 0x18], valid[1..].to_vec()].concat());
    for bytes in bad {
        assert!(PublicCoseKey::try_from(bytes).is_err());
    }
    for value in [
        json!("PRIVATE-INPUT"),
        json!([256]),
        json!([-1]),
        json!([1.5]),
        json!([true]),
        json!(vec![0; 78]),
    ] {
        let err = serde_json::from_value::<PublicCoseKey>(value)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("PRIVATE-INPUT"));
    }
}

#[test]
fn configuration_rejects_aliases_duplicates_unknowns_and_sequence_structs() {
    let encoded = serde_json::to_string(&registry()).unwrap();
    assert_eq!(
        serde_json::from_str::<Registry>(&encoded).unwrap(),
        registry()
    );
    for raw in [
        encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        encoded.replacen(
            "\"primary\":",
            &format!(
                "\"primary\":{},\"pri\\u006dary\":",
                serde_json::to_string(&key()).unwrap()
            ),
            1,
        ),
        encoded.replacen(
            "\"subject\":",
            "\"email\":\"admin@example.test\",\"subject\":",
            1,
        ),
        encoded.replacen("\"version\":1", "\"PRIVATE-INPUT\":1,\"version\":1", 1),
        encoded.replacen("\"subject\":", "\"PRIVATE-INPUT\":1,\"subject\":", 1),
    ] {
        let err = serde_json::from_str::<Registry>(&raw)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("PRIVATE-INPUT"));
    }
    let mut value = serde_json::to_value(key()).unwrap();
    value.as_object_mut().unwrap().remove("backup_eligible");
    assert!(serde_json::from_value::<AdminPasskey>(value).is_err());
    assert!(serde_json::from_value::<Registry>(json!([1, {}])).is_err());
    assert!(
        serde_json::from_value::<AdminPasskey>(json!(
            serde_json::to_value(key())
                .unwrap()
                .as_object()
                .unwrap()
                .values()
                .collect::<Vec<_>>()
        ))
        .is_err()
    );
}

#[test]
fn rp_and_origin_are_exact_canonical_https_and_never_suffix_matches() {
    for (rp, origin) in [
        ("restore.example.test", "https://restore.example.test"),
        ("restore.example.test", "https://restore.example.test:8443"),
    ] {
        let mut k = key();
        k.rp_id = rp.into();
        k.origin = origin.into();
        k.validate().unwrap();
    }
    for (rp, origin) in [
        ("Restore.example.test", "https://restore.example.test"),
        ("127.0.0.1", "https://127.0.0.1"),
        ("localhost", "https://localhost"),
        ("a-.example.test", "https://a-.example.test"),
        ("a..test", "https://a..test"),
        ("restore.example.test", "http://restore.example.test"),
        ("restore.example.test", "https://restore.example.test/"),
        ("restore.example.test", "https://restore.example.test:443"),
        ("restore.example.test", "https://restore.example.test:08443"),
        ("restore.example.test", "https://restore.example.test:0"),
        ("restore.example.test", "https://restore.example.test:65536"),
        (
            "restore.example.test",
            "https://restore.example.test.evil.test",
        ),
        (
            "restore.example.test",
            "https://restore.example.test@evil.test",
        ),
        ("restore.example.test", "https://restore.example.test?x=1"),
        ("restore.example.test", "https://restore.example.test#x"),
        ("restore.example.test", "https://child.restore.example.test"),
    ] {
        let mut k = key();
        k.rp_id = rp.into();
        k.origin = origin.into();
        assert!(k.validate().is_err());
    }
}

#[test]
fn credential_selection_is_unique_and_admin_binding_is_unambiguous() {
    let mut r = registry();
    let label = Name::try_from("second".to_owned()).unwrap();
    r.keys.insert(label.clone(), key());
    assert!(r.validate().is_err());
    r.keys.get_mut(&label).unwrap().credential_id.push(4);
    r.validate().unwrap();
    r.keys.get_mut(&label).unwrap().subject = "other-subject".into();
    assert!(r.validate().is_err());
    r.keys.get_mut(&label).unwrap().subject = key().subject;
    r.keys.get_mut(&label).unwrap().email = "other@example.test".into();
    assert!(r.validate().is_err());
    // Service-shaped subjects are not banned by configuration shape. Actual
    // current policy.admins and a verified assertion must decide membership.
    let mut k = key();
    k.email = "operator@project.iam.gserviceaccount.com".into();
    k.validate().unwrap();
    for email in [
        "Admin@example.test",
        "a@@example.test",
        "@example.test",
        "a @example.test",
        "domain:a@example.test",
        "credential_client:a@example.test",
    ] {
        let mut k = key();
        k.email = email.into();
        assert!(k.validate().is_err());
    }
}

#[test]
fn unicode_admins_roundtrip_as_distinct_exact_identity_bytes() {
    let mut r = registry();
    let nfc = "álîce@example.org";
    let nfd = "a\u{301}lîce@example.org";
    let primary = r.keys.values_mut().next().unwrap();
    primary.email = nfc.to_owned();
    primary.subject = "opaque-主体".to_owned();
    let mut second = key();
    second.email = nfd.to_owned();
    second.subject = "opaque-主體".to_owned();
    second.credential_id.push(99);
    r.keys
        .insert(Name::try_from("second".to_owned()).unwrap(), second);
    r.validate().unwrap();
    let decoded: Registry = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(decoded, r);
    let identities = decoded
        .keys
        .values()
        .map(|k| (k.email.as_str(), k.subject.as_str()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        identities,
        BTreeSet::from([(nfc, "opaque-主体"), (nfd, "opaque-主體")])
    );
    let mut maximum = key();
    maximum.email = format!("{}@a", "x".repeat(254));
    assert_eq!(maximum.email.len(), 256);
    assert_eq!(
        serde_json::from_value::<AdminPasskey>(serde_json::to_value(&maximum).unwrap()).unwrap(),
        maximum
    );
}

#[test]
fn fields_and_total_registry_bytes_are_bounded_before_use() {
    for (field, value) in [
        ("credential_id", json!([])),
        ("credential_id", json!(vec![1; 1024])),
        ("user_handle", json!([])),
        ("user_handle", json!(vec![1; 65])),
        ("credential_id", json!("PRIVATE-INPUT")),
        ("subject", json!("x".repeat(1025))),
        ("email", json!("x".repeat(257))),
        ("rp_id", json!("x".repeat(254))),
        ("origin", json!("x".repeat(2049))),
    ] {
        let mut value_key = serde_json::to_value(key()).unwrap();
        value_key[field] = value;
        let err = serde_json::from_value::<AdminPasskey>(value_key)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("PRIVATE-INPUT"));
    }
    let mut r = registry();
    r.version = 2;
    assert!(r.validate().is_err());
    r.version = 1;
    r.keys.clear();
    assert!(r.validate().is_err());
    for i in 0..128u16 {
        let mut k = key();
        k.credential_id = vec![255; 1023];
        k.credential_id[..2].copy_from_slice(&i.to_be_bytes());
        r.keys.insert(Name::try_from(format!("key{i}")).unwrap(), k);
    }
    // Each entry individually fits but the whole configuration exceeds 512 KiB.
    for k in r.keys.values() {
        k.validate().unwrap();
    }
    assert!(serde_json::to_vec(&r).unwrap().len() > MAX_REGISTRY_BYTES);
    assert!(r.validate().is_err());
    assert!(serde_json::from_value::<Registry>(serde_json::to_value(&r).unwrap()).is_err());
    for k in r.keys.values_mut() {
        k.credential_id.truncate(2);
    }
    r.validate().unwrap();
    let mut extra = key();
    extra.credential_id = vec![255, 255];
    r.keys
        .insert(Name::try_from("one_too_many".to_owned()).unwrap(), extra);
    assert!(r.validate().is_err());
    assert!(serde_json::from_value::<Registry>(serde_json::to_value(&r).unwrap()).is_err());
}

#[test]
fn registry_content_digest_is_not_an_aba_or_current_authority_proof() {
    let original = registry();
    let digest = original.content_digest().unwrap();
    let mut replacement = original.clone();
    replacement
        .keys
        .values_mut()
        .next()
        .unwrap()
        .user_handle
        .push(99);
    assert_ne!(replacement.content_digest().unwrap(), digest);
    replacement = original.clone();
    replacement
        .keys
        .values_mut()
        .next()
        .unwrap()
        .backup_eligible = true;
    assert_ne!(replacement.content_digest().unwrap(), digest);
    // Returning to the identical reviewed DATA returns the identical hash. A
    // genuine supplier must separately fence a non-reusable admitted revision.
    assert_eq!(original.clone().content_digest().unwrap(), digest);
}

#[test]
fn installation_contract_keeps_registry_in_reviewed_control_only() {
    let base = json!({"version":1,"state_directory":"/var/lib/day2/control","operators":["operator@example.test"],"sources":{},"apps":{}});
    let mut control: crate::InstallationControl = serde_json::from_value(base.clone()).unwrap();
    control.validate([]).unwrap();
    assert!(
        serde_json::to_value(&control)
            .unwrap()
            .get("restore_passkeys")
            .is_none()
    );
    control.restore_passkeys = Some(registry());
    assert!(control.validate([]).is_err()); // operator-only packaging cannot enroll.
    let mut full = base;
    full["sources"] = json!({"source":{"kind":"local_git","repository":"/opt/app"}});
    full["apps"] = json!({"app":{"source":"source"}});
    full["restore_passkeys"] = serde_json::to_value(registry()).unwrap();
    let mut control: crate::InstallationControl = serde_json::from_value(full).unwrap();
    control.validate(["app"]).unwrap();
    control.restore_passkeys.as_mut().unwrap().keys.clear();
    assert!(control.validate(["app"]).is_err());
    // Valid parsed metadata grants no authority by itself; there is deliberately
    // no TrustedKey/native/approval constructor in this provider-free contract.
    let value: Value = serde_json::to_value(registry()).unwrap();
    assert_eq!(value["keys"]["primary"]["backup_eligible"], false);
}
