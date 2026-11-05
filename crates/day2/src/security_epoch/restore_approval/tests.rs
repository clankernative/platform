use super::*;
use day2_capabilities::Name;
use serde_json::{Value, json};

fn request() -> Result<ApprovalRequest> {
    let digest = |label: &str| Digest::new(label.as_bytes());
    Ok(ApprovalRequest {
        grant_id: digest("one-server-grant"),
        full_archive_digest: digest("complete-captured-archive-bytes-and-inventory"),
        target: TargetBinding {
            scope: AuthorityScope {
                installation: Name::try_from("one-instance".to_owned())?,
                environment: Name::try_from("test".to_owned())?,
                app: Name::try_from("one-app".to_owned())?,
            },
            binding_generation: 3,
            authority: digest("selected-external-authority"),
            selection: digest("complete-selected-store-and-profile"),
            incarnation: digest("fresh-target-incarnation"),
            security_epoch: 2,
            artifact: digest("actual-artifact"),
            schema: digest("admitted-schema"),
        },
        executor: AdminIdentity {
            email: "admin@example.org".into(),
            subject: "one-stable-subject".into(),
        },
        custody: BindingRef {
            id: Name::try_from("existing-vault".to_owned())?,
            revision: digest("existing-vault-revision"),
        },
        approved_at: 100,
        expires_at: 3700,
    })
}

#[test]
fn canonical_request_roundtrips_without_creating_an_authentication_type() -> Result<()> {
    let expected = request()?;
    let bytes = serde_json::to_vec(&expected)?;
    let actual = ApprovalRequest::decode(&bytes)?;
    actual.require_exact(&expected)?;
    assert_eq!(actual.commitment()?, expected.commitment()?);
    assert_ne!(
        actual.commitment()?,
        Digest::of(&("another-approval-purpose", &actual))?
    );
    // Preserve opaque verified identity bytes; this DATA layer must not turn
    // distinct Unicode principals/subjects into one normalized identity.
    let mut unicode = expected;
    unicode.executor.email = "álîce@example.org".into();
    unicode.executor.subject = "opaque-主体".into();
    let decoded = ApprovalRequest::decode(&serde_json::to_vec(&unicode)?)?;
    decoded.require_exact(&unicode)?;
    // Passkey verification is required for the approver. Executor DATA must
    // not add a human-only policy; the real owner still has to authenticate
    // this exact workload and prove current admin membership independently.
    let mut workload = unicode;
    workload.executor.email = "operator@one.gserviceaccount.com".into();
    workload.executor.subject = "actual-workload-subject".into();
    ApprovalRequest::decode(&serde_json::to_vec(&workload)?)?.require_exact(&workload)?;
    Ok(())
}

#[test]
fn every_selected_field_is_compared_and_committed_independently() -> Result<()> {
    let expected = request()?;
    let foreign = json!(Digest::new(b"foreign"));
    // The paths are an independent complete list of this version's binding.
    // Every change is well shaped, so a shape-only or hash-only substitution
    // cannot masquerade as complete equality with the actual selected request.
    let changes = [
        ("/grant_id", foreign.clone()),
        ("/full_archive_digest", foreign.clone()),
        ("/target/scope/installation", json!("other-instance")),
        ("/target/scope/environment", json!("other-environment")),
        ("/target/scope/app", json!("other-app")),
        ("/target/binding_generation", json!(4)),
        ("/target/authority", foreign.clone()),
        ("/target/selection", foreign.clone()),
        ("/target/incarnation", foreign.clone()),
        ("/target/security_epoch", json!(3)),
        ("/target/artifact", foreign.clone()),
        ("/target/schema", foreign.clone()),
        ("/executor/email", json!("other@example.org")),
        ("/executor/subject", json!("other-stable-subject")),
        ("/custody/id", json!("foreign-vault")),
        ("/custody/revision", foreign),
    ];
    let original = serde_json::to_value(&expected)?;
    for (path, replacement) in changes {
        let mut value = original.clone();
        *value.pointer_mut(path).expect("declared request field") = replacement;
        let changed = ApprovalRequest::decode(&serde_json::to_vec(&value)?)?;
        assert!(changed.require_exact(&expected).is_err(), "{path}");
        assert_ne!(changed.commitment()?, expected.commitment()?, "{path}");
    }
    let mut renewed = expected.clone();
    renewed.approved_at += 1;
    renewed.expires_at += 1;
    renewed.validate()?;
    assert!(renewed.require_exact(&expected).is_err());
    assert_ne!(renewed.commitment()?, expected.commitment()?);
    Ok(())
}

#[test]
fn fixed_one_hour_is_exact_and_overflow_or_alternate_spans_refuse() -> Result<()> {
    assert_eq!(RESTORE_APPROVAL_LIFETIME_SECONDS, 3600);
    let original = request()?;
    for (approved_at, expires_at) in [
        (-1, 3599),
        (100, 100),
        (100, 99),
        (100, 3699),
        (100, 3701),
        (i64::MAX, i64::MIN),
        (i64::MAX - 3599, i64::MAX),
    ] {
        let mut invalid = original.clone();
        invalid.approved_at = approved_at;
        invalid.expires_at = expires_at;
        assert!(invalid.validate().is_err());
        assert!(invalid.commitment().is_err());
        assert!(ApprovalRequest::decode(&serde_json::to_vec(&invalid)?).is_err());
    }
    let mut boundary = original;
    boundary.approved_at = i64::MAX - 3600;
    boundary.expires_at = i64::MAX;
    boundary.validate()?;
    Ok(())
}

#[test]
fn unknown_fields_malformed_identities_and_oversized_inputs_refuse() -> Result<()> {
    let original = serde_json::to_value(request()?)?;
    for path in ["", "/target", "/target/scope", "/executor", "/custody"] {
        let mut value = original.clone();
        value
            .pointer_mut(path)
            .and_then(Value::as_object_mut)
            .expect("declared object")
            .insert("approved".into(), json!(true));
        assert!(ApprovalRequest::decode(&serde_json::to_vec(&value)?).is_err());
    }
    for (path, replacement) in [
        ("/grant_id", json!("not-a-digest")),
        ("/target/binding_generation", json!(0)),
        ("/target/security_epoch", json!(0)),
        ("/executor/email", json!("Admin@example.org")),
        ("/executor/email", json!("admin@example.org ")),
        ("/executor/email", json!("@example.org")),
        ("/executor/email", json!("admin@")),
        ("/executor/email", json!("admin@@example.org")),
        ("/executor/subject", json!("")),
        ("/executor/subject", json!("untrusted\nsubject")),
        ("/executor/subject", json!("x".repeat(1025))),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).expect("declared request field") = replacement;
        assert!(ApprovalRequest::decode(&serde_json::to_vec(&value)?).is_err());
    }
    assert!(ApprovalRequest::decode(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
    Ok(())
}
