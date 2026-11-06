use super::*;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _},
};

struct Fixture {
    signer: EcdsaKeyPair,
    key: TrustedKey<'static>,
    challenge: Challenge,
}

fn fixture() -> Fixture {
    // Owned synthetic authenticator INPUT. No test scalar enters a production
    // registry or approval factory; the unchanged verifier consumes signed bytes.
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let signer =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng).unwrap();
    let key = TrustedKey {
        record: KeyRecord {
            admin: Digest::new(b"exact admin email and subject"),
            registry: Digest::new(b"reviewed registry"),
            revision: 1,
            credential_id: b"owned credential id".to_vec(),
            user_handle: b"exact enrolled user".to_vec(),
            public_key: signer.public_key().as_ref().to_vec(),
            rp_id: "restore.example.test".into(),
            origin: "https://restore.example.test".into(),
            backup_eligible: true,
        },
        source: KeySource::Fixture,
    };
    let challenge = Challenge {
        request: Digest::new(b"complete archive target epoch executor request"),
        nonce: [71; 32],
        enrollment: key.binding().unwrap(),
    };
    Fixture {
        signer,
        key,
        challenge,
    }
}

impl Fixture {
    fn client(&self) -> serde_json::Value {
        serde_json::json!({
            "type":"webauthn.get",
            "challenge":self.challenge.encoded().unwrap(),
            "origin":self.key.record.origin,
            "crossOrigin":false,
        })
    }

    fn assertion(&self, counter: u32, flags: u8) -> Assertion {
        let mut authenticator_data = digest(&SHA256, self.key.record.rp_id.as_bytes())
            .as_ref()
            .to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        let mut assertion = Assertion {
            credential_id: self.key.record.credential_id.clone(),
            client_data_json: serde_json::to_vec(&self.client()).unwrap(),
            authenticator_data,
            signature: Vec::new(),
            user_handle: Some(self.key.record.user_handle.clone()),
        };
        self.sign(&mut assertion);
        assertion
    }

    fn sign(&self, assertion: &mut Assertion) {
        // Construct the WebAuthn signed message independently of verify().
        let hash = digest(&SHA256, &assertion.client_data_json);
        let signed: Vec<u8> = assertion
            .authenticator_data
            .iter()
            .chain(hash.as_ref())
            .copied()
            .collect();
        assertion.signature = self
            .signer
            .sign(&SystemRandom::new(), &signed)
            .unwrap()
            .as_ref()
            .to_vec();
    }

    fn verify(&self, assertion: &Assertion, counter: u32) -> Result<AssertionFacts> {
        verify(
            &self.key,
            &self.challenge,
            &self.challenge.request,
            counter,
            assertion,
        )
    }
}

#[test]
fn real_es256_assertions_require_presence_and_user_verification() {
    let f = fixture();
    for flags in [0x0d, 0x1d] {
        assert_eq!(
            f.verify(&f.assertion(9, flags), 8).unwrap(),
            AssertionFacts {
                counter: 9,
                backed_up: flags == 0x1d,
            }
        );
    }
    // Every counterexample has a valid signature, so missing UP/UV cannot hide
    // behind a failed cryptographic check.
    for flags in [0, 0x09, 0x0c, 0x0f, 0x2d, 0x4d, 0x8d, 0x15] {
        assert!(
            f.verify(&f.assertion(9, flags), 8).is_err(),
            "flags {flags}"
        );
    }
    let mut non_backup = fixture();
    non_backup.key.record.backup_eligible = false;
    non_backup.challenge.enrollment = non_backup.key.binding().unwrap();
    assert!(non_backup.verify(&non_backup.assertion(9, 0x05), 8).is_ok());
    for flags in [0x0d, 0x15, 0x1d] {
        assert!(
            non_backup
                .verify(&non_backup.assertion(9, flags), 8)
                .is_err()
        );
    }
}

#[test]
fn counterless_passkeys_work_but_positive_counters_cannot_reset_or_repeat() {
    let f = fixture();
    for (stored, received, allowed) in [
        (0, 0, true),
        (0, 1, true),
        (1, 2, true),
        (u32::MAX - 1, u32::MAX, true),
        (1, 0, false),
        (1, 1, false),
        (9, 8, false),
        (u32::MAX, u32::MAX, false),
        (u32::MAX, 0, false),
    ] {
        assert_eq!(
            f.verify(&f.assertion(received, 0x0d), stored).is_ok(),
            allowed
        );
    }
    // Repeated stateless verification is intentionally not a one-use permit.
    // The next store slice must consume this challenge durably, including 0/0.
    let assertion = f.assertion(0, 0x0d);
    assert!(f.verify(&assertion, 0).is_ok());
    assert!(f.verify(&assertion, 0).is_ok());
}

#[test]
fn client_type_challenge_origin_and_cross_origin_are_exact() {
    let f = fixture();
    let baseline = f.assertion(4, 0x0d);
    for (name, value) in [
        ("type", serde_json::json!("webauthn.create")),
        ("challenge", serde_json::json!("another-request")),
        (
            "challenge",
            serde_json::json!(format!("{}=", f.challenge.encoded().unwrap())),
        ),
        ("origin", serde_json::json!("https://other.example.test")),
        (
            "origin",
            serde_json::json!("https://restore.example.test:8443"),
        ),
        ("origin", serde_json::json!("https://restore.example.test/")),
        ("crossOrigin", serde_json::json!(true)),
        ("crossOrigin", serde_json::Value::Null),
        (
            "topOrigin",
            serde_json::json!("https://restore.example.test"),
        ),
        ("tokenBinding", serde_json::json!({"status":"present"})),
    ] {
        let mut client = f.client();
        client[name] = value;
        let mut changed = baseline.clone();
        changed.client_data_json = serde_json::to_vec(&client).unwrap();
        f.sign(&mut changed);
        assert!(f.verify(&changed, 3).is_err(), "field {name}");
    }
    let mut client = f.client();
    client.as_object_mut().unwrap().remove("crossOrigin");
    let mut omitted = baseline;
    omitted.client_data_json = serde_json::to_vec(&client).unwrap();
    f.sign(&mut omitted);
    assert!(f.verify(&omitted, 3).is_ok());
}

#[test]
fn challenge_binds_the_request_nonce_and_complete_enrolled_key() {
    let f = fixture();
    let assertion = f.assertion(7, 0x0d);
    assert!(
        verify(
            &f.key,
            &f.challenge,
            &Digest::new(b"other archive/target/epoch/executor"),
            6,
            &assertion
        )
        .is_err()
    );
    let mut changed = f.challenge.clone();
    changed.nonce[0] ^= 1;
    assert!(verify(&f.key, &changed, &changed.request, 6, &assertion).is_err());
    changed = f.challenge.clone();
    changed.request = Digest::new(b"other request even if caller agrees");
    assert!(verify(&f.key, &changed, &changed.request, 6, &assertion).is_err());
    for slot in 0..10 {
        let mut record = f.key.record.clone();
        match slot {
            0 => record.admin = Digest::new(b"different admin subject"),
            1 => record.registry = Digest::new(b"different reviewed registry"),
            2 => record.revision += 1,
            3 => record.credential_id.push(1),
            4 => record.user_handle.push(1),
            5 => record.public_key[1] ^= 1,
            6 => record.rp_id = "other.example.test".into(),
            7 => record.origin = "https://restore.example.test:8443".into(),
            8 => record.backup_eligible = false,
            9 => record.origin = "https://other.example.test".into(),
            _ => unreachable!(),
        }
        let key = TrustedKey {
            record,
            source: KeySource::Fixture,
        };
        assert!(
            verify(&key, &f.challenge, &f.challenge.request, 6, &assertion).is_err(),
            "binding {slot}"
        );
    }
}

#[test]
fn selected_user_handle_and_credential_cannot_be_substituted() {
    let f = fixture();
    let baseline = f.assertion(1, 0x0d);
    for handle in [Vec::new(), b"another user".to_vec(), vec![0; 65]] {
        let mut changed = baseline.clone();
        changed.user_handle = Some(handle);
        assert!(f.verify(&changed, 0).is_err());
    }
    let mut changed = baseline.clone();
    changed.credential_id = b"another credential".to_vec();
    assert!(f.verify(&changed, 0).is_err());
    changed = baseline;
    changed.user_handle = None;
    assert!(f.verify(&changed, 0).is_ok());
}

#[test]
fn signature_covers_original_client_json_and_all_authenticator_bytes() {
    let f = fixture();
    let baseline = f.assertion(8, 0x0d);
    let mut changed = baseline.clone();
    changed.client_data_json.push(b' ');
    assert!(f.verify(&changed, 7).is_err());
    f.sign(&mut changed);
    assert!(f.verify(&changed, 7).is_ok());
    changed = baseline.clone();
    changed.authenticator_data[36] = 9;
    assert!(f.verify(&changed, 7).is_err());
    f.sign(&mut changed);
    assert!(f.verify(&changed, 7).is_ok());
    changed = baseline.clone();
    changed.authenticator_data[0] ^= 1;
    f.sign(&mut changed);
    assert!(f.verify(&changed, 7).is_err());
    let other = fixture();
    changed = baseline;
    other.sign(&mut changed);
    assert!(f.verify(&changed, 7).is_err());
}

#[test]
fn malformed_and_oversized_inputs_fail_with_closed_errors() {
    let f = fixture();
    let baseline = f.assertion(2, 0x0d);
    let full_client = serde_json::to_string(&f.client()).unwrap();
    let mut duplicate = baseline.clone();
    duplicate.client_data_json =
        format!("{{\"\\u0074ype\":\"webauthn.get\",{}", &full_client[1..]).into_bytes();
    f.sign(&mut duplicate);
    assert!(f.verify(&duplicate, 1).is_err());
    for bytes in [
        br#"{"type":"webauthn.get","\u0074ype":"webauthn.get"}"#.to_vec(),
        br#"["webauthn.get","challenge","https://restore.example.test",false]"#.to_vec(),
        vec![b' '; MAX_CLIENT_DATA + 1],
        b"private parser material \xff".to_vec(),
    ] {
        let mut changed = baseline.clone();
        changed.client_data_json = bytes;
        f.sign(&mut changed);
        let error = f.verify(&changed, 1).unwrap_err().to_string();
        assert!(error.starts_with("restore_passkey_"));
        assert!(!error.contains("private parser material"));
    }
    for length in [0, 36, 38, 1024] {
        let mut changed = baseline.clone();
        changed.authenticator_data.resize(length, 0);
        f.sign(&mut changed);
        assert!(f.verify(&changed, 1).is_err());
    }
    for length in [0, 7, 73, 4096] {
        let mut changed = baseline.clone();
        changed.signature.resize(length, 0);
        assert!(f.verify(&changed, 1).is_err());
    }
}

#[test]
fn registry_origin_and_key_shapes_are_closed() {
    let f = fixture();
    for origin in [
        "http://restore.example.test",
        "https://user@restore.example.test",
        "https://restore.example.test/path",
        "https://restore.example.test?query",
        "https://restore.example.test#fragment",
        "https://127.0.0.1",
        "https://RESTORE.example.test",
        "https://restore.example.test:443",
    ] {
        let mut record = f.key.record.clone();
        record.origin = origin.into();
        assert!(
            TrustedKey {
                record,
                source: KeySource::Fixture
            }
            .validate()
            .is_err()
        );
    }
    for slot in 0..5 {
        let mut record = f.key.record.clone();
        match slot {
            0 => record.revision = 0,
            1 => record.credential_id.clear(),
            2 => record.credential_id.resize(MAX_CREDENTIAL_ID + 1, 0),
            3 => record.user_handle.clear(),
            4 => record.public_key[0] = 3,
            _ => unreachable!(),
        }
        assert!(
            TrustedKey {
                record,
                source: KeySource::Fixture
            }
            .validate()
            .is_err()
        );
    }
}

fn require_closed_source(source: &str) -> Result<()> {
    let file = syn::parse_file(source)?;
    let trusted = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "TrustedKey" => Some(item),
            _ => None,
        })
        .unwrap();
    ensure!(
        trusted.attrs.iter().all(|a| a.path().is_ident("doc")),
        "trusted input gained a derive"
    );
    ensure!(
        trusted
            .fields
            .iter()
            .all(|f| matches!(f.vis, syn::Visibility::Inherited)),
        "trusted input gained public fields"
    );
    ensure!(
        trusted
            .fields
            .iter()
            .any(|f| f.ident.as_ref().is_some_and(|id| id == "source")
                && matches!(&f.ty, syn::Type::Path(path) if path.path.segments.len()==1 && path.path.segments[0].ident=="KeySource")),
        "trusted input lost closed source"
    );
    let origin = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Enum(item) if item.ident == "KeySource" => Some(item),
            _ => None,
        })
        .unwrap();
    let production = origin
        .variants
        .iter()
        .filter(|v| !v.attrs.iter().any(|a| a.path().is_ident("cfg")))
        .collect::<Vec<_>>();
    ensure!(
        production.len() == 1 && production[0].ident == "Registry",
        "trusted input gained scalar source"
    );
    let syn::Fields::Unnamed(fields) = &production[0].fields else {
        anyhow::bail!("registry origin not retained")
    };
    ensure!(
        fields.unnamed.len() == 1
            && matches!(&fields.unnamed[0].ty,syn::Type::Path(p) if p.path.segments.len()==2 && p.path.segments[0].ident=="registry" && p.path.segments[1].ident=="Origin"),
        "registry origin not retained"
    );
    ensure!(
        origin
            .variants
            .iter()
            .filter(|v| v.ident != "Registry")
            .all(|v| v.attrs.iter().any(|a| a.path().is_ident("cfg")
                && a.meta
                    .require_list()
                    .is_ok_and(|l| l.tokens.to_string() == "test"))),
        "production fixture source added"
    );
    use syn::visit::Visit;
    struct Calls(usize);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == "check_local"
                && matches!(&*node.receiver,syn::Expr::Path(p) if p.path.is_ident("source"))
            {
                self.0 += 1;
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let mut calls = Calls(0);
    for item in &file.items {
        if let syn::Item::Impl(item) = item
            && matches!(&*item.self_ty,syn::Type::Path(p) if p.path.segments.last().is_some_and(|s|s.ident=="TrustedKey"))
        {
            for method in &item.items {
                if let syn::ImplItem::Fn(method) = method
                    && method.sig.ident == "validate"
                {
                    calls.visit_block(&method.block);
                }
            }
        }
    }
    ensure!(calls.0 == 1, "trusted source check removed");
    Ok(())
}

#[test]
fn production_trusted_key_requires_the_scoped_registry_origin() {
    let source = include_str!("../restore_webauthn.rs");
    require_closed_source(source).unwrap();
    for (from, to) in [
        ("source: KeySource<'owner>,", "source: (),"),
        ("record: KeyRecord,", "pub record: KeyRecord,"),
        (
            "enum KeySource<'owner> {",
            "enum KeySource<'owner> { Production,",
        ),
        ("Registry(registry::Origin<'owner>)", "Registry(())"),
        ("source.check_local()?", "Ok(())"),
        (
            "pub(super) struct TrustedKey",
            "#[derive(Clone)] pub(super) struct TrustedKey",
        ),
    ] {
        assert_eq!(source.matches(from).count(), 1);
        assert!(require_closed_source(&source.replace(from, to)).is_err());
    }
}

#[test]
fn only_actual_browser_assertion_rejections_have_the_closed_denial_type() {
    let f = fixture();
    let baseline = f.assertion(9, 0x0d);
    let mut cases = Vec::new();
    let mut altered = baseline.clone();
    altered.credential_id.push(0);
    cases.push((altered, 8, "restore_passkey_assertion_shape_or_identity"));
    let mut altered = baseline.clone();
    altered.client_data_json = b"not JSON".to_vec();
    cases.push((altered, 8, "restore_passkey_invalid_client_data"));
    let mut altered = baseline.clone();
    let mut client = f.client();
    client["origin"] = serde_json::json!("https://another.example.test");
    altered.client_data_json = serde_json::to_vec(&client).unwrap();
    f.sign(&mut altered);
    cases.push((altered, 8, "restore_passkey_client_binding_changed"));
    let mut altered = baseline.clone();
    altered.authenticator_data[0] ^= 1;
    f.sign(&mut altered);
    cases.push((altered, 8, "restore_passkey_rp_changed"));
    cases.push((
        f.assertion(9, 0x09),
        8,
        "restore_passkey_flags_or_verification_changed",
    ));
    cases.push((baseline.clone(), 9, "restore_passkey_counter_not_advanced"));
    let mut altered = baseline.clone();
    let last = altered.signature.last_mut().unwrap();
    *last ^= 1;
    cases.push((altered, 8, "restore_passkey_signature_invalid"));
    for (assertion, stored, expected) in cases {
        let error = f.verify(&assertion, stored).unwrap_err();
        assert!(error.is::<AssertionDenied>());
        assert_eq!(error.to_string(), expected);
    }
    let error = verify(
        &f.key,
        &f.challenge,
        &Digest::new(b"other server intent"),
        8,
        &baseline,
    )
    .unwrap_err();
    assert!(!error.is::<AssertionDenied>());
    let mut key = f.key;
    key.record.revision = 0;
    let error = verify(&key, &f.challenge, &f.challenge.request, 8, &baseline).unwrap_err();
    assert!(!error.is::<AssertionDenied>());
}
