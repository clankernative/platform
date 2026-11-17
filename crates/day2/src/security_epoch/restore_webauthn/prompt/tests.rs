use super::*;
use crate::security_epoch::restore_approval::{fixture_request_data, signed::ApprovalStatement};
use serde_json::Value;

fn intent() -> Result<ApprovalIntent> {
    Ok(fixture_request_data()?.intent())
}

fn record() -> Result<SignedApprovalRecord> {
    let request = fixture_request_data()?;
    // Shape-only public transport DATA. This synthetic signature is never
    // promoted to an approval, registry source or authenticated executor.
    Ok(SignedApprovalRecord {
        statement: ApprovalStatement {
            approver: request.executor.clone(),
            request,
            registry: Digest::new(b"fixture registry"),
            credential: Digest::new(b"fixture credential"),
            assertion: Digest::new(b"fixture assertion digest"),
            signing_key: Digest::new(b"fixture exact signing selection"),
        },
        signature: URL_SAFE_NO_PAD.encode([0; 64]),
    })
}

#[test]
fn approval_options_bind_the_actual_challenge_and_exact_registry_selection() -> Result<()> {
    let fixture = super::super::tests::fixture();
    let mut challenge = fixture.challenge.clone();
    let expected = intent()?;
    challenge.request = expected.commitment()?;
    let encoded = challenge.encoded()?;
    let prompt = approval(&fixture.key.record, &challenge, encoded.clone(), &expected)?;
    let bytes = prompt.encode()?;
    let data: Value = crate::json::decode(&bytes)?;
    assert_eq!(data["purpose"], "day2_restore_approval_v1");
    assert_eq!(data["intent"], serde_json::to_value(&expected)?);
    assert_eq!(
        data["approver"],
        serde_json::to_value(&fixture.key.record.principal)?
    );
    assert_ne!(fixture.key.record.principal, expected.executor);
    assert_eq!(data["request"], serde_json::to_value(&challenge.request)?);
    assert_eq!(data["origin"], fixture.key.record.origin);
    assert_eq!(data["public_key"]["rpId"], fixture.key.record.rp_id);
    assert_eq!(data["public_key"]["challenge"], encoded);
    let independently_encoded = URL_SAFE_NO_PAD.encode(
        ring::digest::digest(
            &ring::digest::SHA256,
            &serde_json::to_vec(&(
                "day2-restore-webauthn-challenge-v1",
                &challenge.request,
                &challenge.nonce,
                &challenge.enrollment,
            ))?,
        )
        .as_ref(),
    );
    assert_eq!(data["public_key"]["challenge"], independently_encoded);
    assert_eq!(data["public_key"]["userVerification"], "required");
    assert_eq!(
        data["public_key"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        data["public_key"]["allowCredentials"][0]["type"],
        "public-key"
    );
    assert_eq!(
        data["public_key"]["allowCredentials"][0]["id"],
        URL_SAFE_NO_PAD.encode(&fixture.key.record.credential_id)
    );
    assert!(data.get("approval").is_none());
    assert!(data.get("operation").is_none());
    let text = String::from_utf8(bytes)?;
    for private in [
        fixture.key.record.public_key.as_slice(),
        fixture.key.record.user_handle.as_slice(),
        challenge.nonce.as_slice(),
    ] {
        assert!(!text.contains(&URL_SAFE_NO_PAD.encode(private)));
    }
    Ok(())
}

#[test]
fn prompt_challenges_require_uv_and_cannot_reuse_the_approval_assertion_for_execution() -> Result<()>
{
    // Only the existing synthetic authenticator signs these test inputs. Both
    // purposes use the same fixture key to cover the allowed same-admin case.
    let mut fixture = super::super::tests::fixture();
    let expected = intent()?;
    fixture.challenge.request = expected.commitment()?;
    let approval_challenge = fixture.challenge.clone();
    let prompt = approval(
        &fixture.key.record,
        &approval_challenge,
        approval_challenge.encoded()?,
        &expected,
    )?;
    let data: Value = crate::json::decode(&prompt.encode()?)?;
    let assertion = fixture.assertion(3, 0x0d);
    let client: Value = crate::json::decode(&assertion.client_data_json)?;
    assert_eq!(data["public_key"]["challenge"], client["challenge"]);
    let verify = |challenge: &Challenge, counter, assertion: &super::super::Assertion| {
        super::super::verify(
            &fixture.key,
            challenge,
            &challenge.request,
            counter,
            assertion,
        )
    };
    assert_eq!(verify(&approval_challenge, 2, &assertion)?.counter, 3);
    assert!(verify(&approval_challenge, 2, &fixture.assertion(3, 0x09)).is_err());

    let signed = record()?;
    let operation = Digest::new(b"same admin actual execution operation");
    let mut executor_challenge = approval_challenge.clone();
    executor_challenge.request = execution_request(&signed, &operation)?;
    let executor_prompt = execution(
        &fixture.key.record,
        &executor_challenge,
        executor_challenge.encoded()?,
        &signed,
        &operation,
    )?;
    let executor_data: Value = crate::json::decode(&executor_prompt.encode()?)?;
    assert_ne!(
        data["public_key"]["challenge"],
        executor_data["public_key"]["challenge"]
    );
    assert!(verify(&executor_challenge, 2, &assertion).is_err());
    // No native executor or approval is constructed from either DATA result.
    fixture.challenge = executor_challenge;
    let executor_assertion = fixture.assertion(4, 0x0d);
    assert_eq!(
        super::super::verify(
            &fixture.key,
            &fixture.challenge,
            &fixture.challenge.request,
            3,
            &executor_assertion,
        )?
        .counter,
        4
    );
    assert!(
        super::super::verify(
            &fixture.key,
            &approval_challenge,
            &approval_challenge.request,
            3,
            &executor_assertion,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn approval_options_refuse_another_intent_key_or_server_challenge() -> Result<()> {
    let fixture = super::super::tests::fixture();
    let expected = intent()?;
    let mut challenge = fixture.challenge.clone();
    challenge.request = expected.commitment()?;
    let encoded = challenge.encoded()?;
    let mut variants = Vec::new();
    let mut other = expected.clone();
    other.grant_id = Digest::new(b"other grant");
    variants.push(other);
    let mut other = expected.clone();
    other.full_archive_digest = Digest::new(b"other complete archive");
    variants.push(other);
    let mut other = expected.clone();
    other.target.security_epoch += 1;
    variants.push(other);
    let mut other = expected.clone();
    other.target.incarnation = Digest::new(b"other target");
    variants.push(other);
    let mut other = expected.clone();
    other.executor.subject = "another subject".to_owned();
    variants.push(other);
    let mut other = expected.clone();
    other.custody.revision = Digest::new(b"other vault revision");
    variants.push(other);
    for other in variants {
        assert!(approval(&fixture.key.record, &challenge, encoded.clone(), &other).is_err());
    }
    for change in 0..11 {
        let mut key = fixture.key.record.clone();
        match change {
            0 => key.credential_id.push(1),
            1 => key.rp_id = "other.example.test".into(),
            2 => key.origin = "https://other.example.test".into(),
            3 => key.registry = Digest::new(b"removed or replaced registry key"),
            4 => key.revision += 1,
            5 => key.admin = Digest::new(b"another registry admin"),
            6 => key.public_key[1] ^= 1,
            7 => key.user_handle.push(1),
            8 => key.backup_eligible = !key.backup_eligible,
            9 => key.principal.email = "other-approver@example.test".into(),
            _ => key.principal.subject = "another-selected-subject".into(),
        }
        assert!(approval(&key, &challenge, encoded.clone(), &expected).is_err());
    }
    let mut other = challenge.clone();
    other.nonce[0] ^= 1;
    assert!(approval(&fixture.key.record, &other, encoded.clone(), &expected).is_err());
    assert!(
        approval(
            &fixture.key.record,
            &challenge,
            "caller challenge".into(),
            &expected
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn execution_options_bind_the_complete_signed_grant_and_operation_in_a_separate_purpose()
-> Result<()> {
    let fixture = super::super::tests::fixture();
    let signed = record()?;
    let operation = Digest::new(b"exact accepting operation");
    let mut challenge = fixture.challenge.clone();
    challenge.request = execution_request(&signed, &operation)?;
    let encoded = challenge.encoded()?;
    let prompt = execution(
        &fixture.key.record,
        &challenge,
        encoded.clone(),
        &signed,
        &operation,
    )?;
    let data: Value = crate::json::decode(&prompt.encode()?)?;
    assert_eq!(data["purpose"], "day2_restore_execution_v1");
    assert_eq!(data["approval"], serde_json::to_value(&signed)?);
    assert_eq!(data["operation"], serde_json::to_value(&operation)?);
    assert_eq!(data["public_key"]["challenge"], encoded);
    assert_eq!(data["public_key"]["userVerification"], "required");
    assert!(data.get("intent").is_none());
    assert!(
        approval(
            &fixture.key.record,
            &challenge,
            encoded.clone(),
            &signed.statement.request.intent()
        )
        .is_err()
    );
    assert!(
        execution(
            &fixture.key.record,
            &challenge,
            encoded.clone(),
            &signed,
            &Digest::new(b"other operation")
        )
        .is_err()
    );
    let mut other = signed.clone();
    other.statement.request.expires_at += 1;
    assert!(
        execution(
            &fixture.key.record,
            &challenge,
            encoded.clone(),
            &other,
            &operation
        )
        .is_err()
    );
    let mut other = signed.clone();
    other.statement.approver.subject = "another approver".into();
    assert!(
        execution(
            &fixture.key.record,
            &challenge,
            encoded.clone(),
            &other,
            &operation
        )
        .is_err()
    );
    let mut other = signed.clone();
    other.signature = URL_SAFE_NO_PAD.encode([1; 64]);
    assert!(execution(&fixture.key.record, &challenge, encoded, &other, &operation).is_err());
    assert_eq!(
        signed.statement.request.expires_at - signed.statement.request.approved_at,
        3600
    );
    Ok(())
}

#[test]
fn protected_prompt_encoding_refuses_oversize_and_exposes_no_caller_policy_flags() -> Result<()> {
    let fixture = super::super::tests::fixture();
    let expected = intent()?;
    let mut original = fixture.challenge.clone();
    original.request = expected.commitment()?;
    let positive = approval(
        &fixture.key.record,
        &original,
        original.encoded()?,
        &expected,
    )?;
    let data: Value = crate::json::decode(&positive.encode()?)?;
    let mut fields = data["public_key"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["allowCredentials", "challenge", "rpId", "userVerification"]
    );
    let mut key = fixture.key.record.clone();
    key.origin = "x".repeat(MAX_BYTES);
    let mut challenge = fixture.challenge.clone();
    challenge.request = expected.commitment()?;
    challenge.enrollment = key.binding_data()?;
    assert!(approval(&key, &challenge, challenge.encoded()?, &expected).is_err());
    let mut key = fixture.key.record.clone();
    key.credential_id = vec![1; MAX_CREDENTIAL_ID + 1];
    challenge.enrollment = key.binding_data()?;
    assert!(approval(&key, &challenge, challenge.encoded()?, &expected).is_err());
    Ok(())
}
