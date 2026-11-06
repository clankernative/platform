use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

fn selection(public_key: [u8; 32]) -> Result<KeySelection> {
    Ok(KeySelection {
        version: "projects/approval-project/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/7".to_owned().try_into()?,
        public_key,
    })
}

fn statement() -> Result<ApprovalStatement> {
    let request = super::super::tests::request()?;
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("fixed fixture key");
    Ok(ApprovalStatement {
        request,
        approver: AdminIdentity {
            email: "approver@example.org".into(),
            subject: "approver-subject".into(),
        },
        registry: Digest::new(b"actual-current-registry-binding"),
        credential: Digest::new(b"selected-passkey-id"),
        assertion: Digest::new(b"actual-verified-assertion-and-challenge"),
        signing_key: selection(key.public_key().as_ref().try_into()?)?.commitment()?,
    })
}

fn signed(statement: ApprovalStatement) -> Result<(SignedApprovalRecord, KeySelection)> {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("fixed fixture key");
    // Independent fixture encoder fixes the actual purpose string rather than
    // calling the implementation's signature-input method to create evidence.
    let frame = serde_json::to_vec(&("day2-restore-approval-grant-ed25519-v1", &statement))?;
    let signature = URL_SAFE_NO_PAD.encode(key.sign(&frame).as_ref());
    Ok((
        SignedApprovalRecord {
            statement,
            signature,
        },
        selection(key.public_key().as_ref().try_into()?)?,
    ))
}

#[test]
fn signed_record_roundtrips_and_verifies_the_complete_fixed_purpose_frame() -> Result<()> {
    let statement = statement()?;
    let (record, public) = signed(statement.clone())?;
    let decoded = SignedApprovalRecord::decode(&serde_json::to_vec(&record)?)?;
    decoded.verify_signature_data(&statement, &public)?;
    assert_eq!(decoded, record);
    assert_eq!(
        statement.signature_input_data()?,
        serde_json::to_vec(&("day2-restore-approval-grant-ed25519-v1", &statement))?
    );
    // The policy permits the same person to approve and execute. This codec
    // imposes no two-person rule; real current membership remains owner work.
    let mut same_admin = statement;
    same_admin.approver = same_admin.request.executor.clone();
    let (record, public) = signed(same_admin.clone())?;
    record.verify_signature_data(&same_admin, &public)?;
    Ok(())
}

#[test]
fn every_binding_field_is_signed_and_compared_including_both_admin_identities() -> Result<()> {
    let original = statement()?;
    let (record, public) = signed(original.clone())?;
    let foreign = json!(Digest::new(b"foreign"));
    let changes = [
        ("/request/grant_id", foreign.clone()),
        ("/request/full_archive_digest", foreign.clone()),
        (
            "/request/target/scope/installation",
            json!("another-instance"),
        ),
        (
            "/request/target/scope/environment",
            json!("another-environment"),
        ),
        ("/request/target/scope/app", json!("another-app")),
        ("/request/target/binding_generation", json!(4)),
        ("/request/target/authority", foreign.clone()),
        ("/request/target/selection", foreign.clone()),
        ("/request/target/incarnation", foreign.clone()),
        ("/request/target/security_epoch", json!(3)),
        ("/request/target/artifact", foreign.clone()),
        ("/request/target/schema", foreign.clone()),
        (
            "/request/executor/email",
            json!("other-executor@example.org"),
        ),
        (
            "/request/executor/subject",
            json!("another-executor-subject"),
        ),
        ("/request/custody/id", json!("another-vault")),
        ("/request/custody/revision", foreign.clone()),
        ("/approver/email", json!("another-approver@example.org")),
        ("/approver/subject", json!("another-approver-subject")),
        ("/registry", foreign.clone()),
        ("/credential", foreign.clone()),
        ("/assertion", foreign.clone()),
        ("/signing_key", foreign),
    ];
    for (path, replacement) in changes {
        let mut value = serde_json::to_value(&original)?;
        *value.pointer_mut(path).expect("explicit field") = replacement;
        let changed: ApprovalStatement = serde_json::from_value(value)?;
        changed.validate()?;
        // Both a changed expected identity and a modified transported payload
        // refuse. The latter also refuses when its own expectation is changed,
        // so complete equality alone cannot masquerade as signature checking.
        assert!(
            record.verify_signature_data(&changed, &public).is_err(),
            "{path}"
        );
        let mut tampered = record.clone();
        tampered.statement = changed.clone();
        assert!(
            tampered.verify_signature_data(&original, &public).is_err(),
            "{path}"
        );
        assert!(
            tampered.verify_signature_data(&changed, &public).is_err(),
            "{path}"
        );
    }
    let mut renewed = record.clone();
    renewed.statement.request.approved_at += 1;
    renewed.statement.request.expires_at += 1;
    renewed.statement.validate()?;
    assert!(
        record
            .verify_signature_data(&renewed.statement, &public)
            .is_err()
    );
    assert!(
        renewed
            .verify_signature_data(&renewed.statement, &public)
            .is_err()
    );
    for (approved_at, expires_at) in [(99, 3700), (100, 3701), (101, 3700)] {
        let mut wrong = record.clone();
        wrong.statement.request.approved_at = approved_at;
        wrong.statement.request.expires_at = expires_at;
        assert!(
            wrong
                .verify_signature_data(&wrong.statement, &public)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn another_key_another_purpose_or_unsigned_record_cannot_verify() -> Result<()> {
    let statement = statement()?;
    let (record, public) = signed(statement.clone())?;
    let another = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).expect("other fixture key");
    let another_public = selection(another.public_key().as_ref().try_into()?)?;
    assert!(
        record
            .verify_signature_data(&statement, &another_public)
            .is_err()
    );
    let mut substituted = record.clone();
    substituted.statement.signing_key = another_public.commitment()?;
    assert!(
        substituted
            .verify_signature_data(&substituted.statement, &another_public)
            .is_err()
    );
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("fixed fixture key");
    for wrong_frame in [
        serde_json::to_vec(&statement)?,
        serde_json::to_vec(&("day2-restore-approval-request-v1", &statement))?,
        serde_json::to_vec(&("day2-native-enrollment-v1", "issuer-birth", &statement))?,
    ] {
        let mut wrong = record.clone();
        wrong.signature = URL_SAFE_NO_PAD.encode(key.sign(&wrong_frame).as_ref());
        assert!(wrong.verify_signature_data(&statement, &public).is_err());
    }
    let mut unsigned = record;
    unsigned.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    // Decoding is explicitly structural DATA admission, not authentication.
    let decoded = SignedApprovalRecord::decode(&serde_json::to_vec(&unsigned)?)?;
    assert!(decoded.verify_signature_data(&statement, &public).is_err());
    Ok(())
}

#[test]
fn the_same_public_material_at_another_exact_version_cannot_verify() -> Result<()> {
    let statement = statement()?;
    let (record, selected) = signed(statement.clone())?;
    let mut reimported = selected.clone();
    reimported.version = reimported
        .version
        .as_str()
        .replace("Versions/7", "Versions/8")
        .try_into()?;
    assert_eq!(reimported.public_key, selected.public_key);
    reimported.validate()?;
    assert_ne!(reimported.commitment()?, selected.commitment()?);
    assert!(
        record
            .verify_signature_data(&statement, &reimported)
            .is_err()
    );
    let mut substituted = record.clone();
    substituted.statement.signing_key = reimported.commitment()?;
    assert!(
        substituted
            .verify_signature_data(&substituted.statement, &reimported)
            .is_err()
    );
    assert!(
        substituted
            .verify_signature_data(&statement, &selected)
            .is_err()
    );
    Ok(())
}

#[test]
fn closed_record_encoding_rejects_unknown_duplicate_noncanonical_and_large_inputs() -> Result<()> {
    let (record, _) = signed(statement()?)?;
    for path in [
        "",
        "/statement",
        "/statement/request",
        "/statement/request/target",
        "/statement/approver",
    ] {
        let mut value = serde_json::to_value(&record)?;
        value
            .pointer_mut(path)
            .and_then(Value::as_object_mut)
            .expect("object")
            .insert("approved".into(), json!(true));
        assert!(SignedApprovalRecord::decode(&serde_json::to_vec(&value)?).is_err());
    }
    for signature in [
        String::new(),
        "A".repeat(85),
        "A".repeat(87),
        "=".repeat(86),
        format!("{}=", record.signature),
    ] {
        let mut value = record.clone();
        value.signature = signature;
        assert!(SignedApprovalRecord::decode(&serde_json::to_vec(&value)?).is_err());
    }
    let encoded = serde_json::to_string(&record)?;
    let duplicate = encoded.replacen("{", "{\"signature\":\"untrusted\",", 1);
    assert!(SignedApprovalRecord::decode(duplicate.as_bytes()).is_err());
    assert!(SignedApprovalRecord::decode(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn pending_intent_has_no_time_and_completion_binds_exactly_one_hour_without_renewal() -> Result<()>
{
    let request = statement()?.request;
    let intent = request.intent();
    let decoded = super::super::ApprovalIntent::decode(&serde_json::to_vec(&intent)?)?;
    assert_eq!(decoded, intent);
    let fixed = decoded.request_data(100)?;
    assert_eq!(fixed, request);
    decoded.require_request(&fixed)?;
    let later = decoded.request_data(200)?;
    assert_eq!(later.approved_at, 200);
    assert_eq!(later.expires_at, 3800);
    assert_eq!(later.intent(), fixed.intent());
    assert_ne!(later.commitment()?, fixed.commitment()?);
    assert!(fixed.require_exact(&later).is_err());
    assert_ne!(intent.commitment()?, fixed.commitment()?);
    assert!(decoded.request_data(-1).is_err());
    assert!(decoded.request_data(i64::MAX - 3599).is_err());
    assert_eq!(decoded.request_data(i64::MAX - 3600)?.expires_at, i64::MAX);
    let mut invalid = serde_json::to_value(&intent)?;
    invalid
        .as_object_mut()
        .expect("intent")
        .insert("approved_at".into(), json!(100));
    assert!(super::super::ApprovalIntent::decode(&serde_json::to_vec(&invalid)?).is_err());
    let mut changed = fixed.clone();
    changed.target.security_epoch += 1;
    assert!(decoded.require_request(&changed).is_err());
    Ok(())
}
