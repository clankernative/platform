use super::*;
use serde_json::json;

fn intent() -> Result<ApprovalIntent> {
    let request = super::super::tests::request()?;
    Ok(ApprovalIntent {
        grant_id: request.grant_id,
        full_archive_digest: request.full_archive_digest,
        target: request.target,
        executor: request.executor,
        custody: request.custody,
    })
}

#[test]
fn request_and_bounded_decoder_share_the_exact_challenge_intent() -> Result<()> {
    let original = intent()?;
    let request = original.request_data(100)?;
    let from_request = request.intent();
    let decoded = super::super::ApprovalIntent::decode(&serde_json::to_vec(&from_request)?)?;
    decoded.require_exact(&original)?;
    decoded.require_request(&request)?;
    assert_eq!(decoded.commitment()?, original.commitment()?);
    let mut changed = decoded.clone();
    changed.executor.subject.push_str("-changed");
    assert!(decoded.require_exact(&changed).is_err());
    assert!(changed.require_request(&request).is_err());
    let mut oversized = serde_json::to_vec(&original)?;
    oversized.resize(MAX_REQUEST_BYTES + 1, b' ');
    assert!(super::super::ApprovalIntent::decode(&oversized).is_err());
    Ok(())
}

#[test]
fn challenge_has_no_premature_approval_clock_and_final_request_keeps_fixed_hour() -> Result<()> {
    let intent = intent()?;
    let before = intent.commitment()?;
    for completed_at in [0, 100, 100_000] {
        let request = intent.request_data(completed_at)?;
        intent.require_request(&request)?;
        assert_eq!(request.approved_at, completed_at);
        assert_eq!(request.expires_at, completed_at + 3600);
        assert_eq!(intent.commitment()?, before);
        assert_ne!(request.commitment()?, before);
    }
    assert!(intent.request_data(-1).is_err());
    assert!(intent.request_data(i64::MAX).is_err());
    let mut shortened = intent.request_data(100)?;
    shortened.expires_at -= 1;
    assert!(intent.require_request(&shortened).is_err());
    assert!(serde_json::to_value(&intent)?.get("approved_at").is_none());
    Ok(())
}

#[test]
fn every_independently_enumerated_intent_field_changes_challenge_and_final_binding() -> Result<()> {
    let original = intent()?;
    let baseline = original.commitment()?;
    let finalized = original.request_data(100)?;
    let foreign = json!(Digest::new(b"foreign intent field"));
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
        ("/executor/subject", json!("other-subject")),
        ("/custody/id", json!("other-vault")),
        ("/custody/revision", foreign),
    ];
    fn leaves(value: &serde_json::Value, prefix: &str, out: &mut Vec<String>) {
        if let serde_json::Value::Object(fields) = value {
            for (name, value) in fields {
                leaves(value, &format!("{prefix}/{name}"), out);
            }
        } else {
            out.push(prefix.to_owned());
        }
    }
    let mut actual_paths = Vec::new();
    leaves(&serde_json::to_value(&original)?, "", &mut actual_paths);
    actual_paths.sort();
    let mut independently_expected = changes
        .iter()
        .map(|(path, _)| path.to_string())
        .collect::<Vec<_>>();
    independently_expected.sort();
    assert_eq!(actual_paths, independently_expected);
    for (path, value) in changes {
        let mut value_record = serde_json::to_value(&original)?;
        *value_record.pointer_mut(path).unwrap() = value;
        let changed: ApprovalIntent = serde_json::from_value(value_record)?;
        assert_ne!(changed.commitment()?, baseline, "{path}");
        assert!(original.require_exact(&changed).is_err(), "{path}");
        assert!(changed.require_request(&finalized).is_err(), "{path}");
    }
    let mut premature_clock = serde_json::to_value(&original)?;
    premature_clock["approved_at"] = json!(100);
    assert!(serde_json::from_value::<ApprovalIntent>(premature_clock).is_err());
    Ok(())
}
