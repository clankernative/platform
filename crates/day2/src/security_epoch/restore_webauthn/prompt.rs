//! Protected-command presentation DATA from the actual retained ceremony.
//! It cannot decode into a pending ceremony, key source, signed approval or
//! authenticated executor. The existing durable verifier remains mandatory.
use super::{Challenge, KeyRecord, MAX_CREDENTIAL_ID, execution_request};
use crate::security_epoch::restore_approval::{ApprovalIntent, signed::SignedApprovalRecord};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use serde::Serialize;

const MAX_BYTES: usize = 32_768;

/// Only the bounded encoder crosses the protected command response boundary.
/// No Deserialize, public fields or scalar-to-ceremony conversion is supplied.
pub(in crate::security_epoch) struct RestorePasskeyPrompt {
    data: Prompt,
}

/// Public comparison DATA from two inert authenticator fixtures. The actual
/// encoder remains the only source of the approval/execution wire format.
#[cfg(test)]
pub(crate) struct RestorePromptFixtureData {
    pub(crate) approval: Vec<u8>,
    pub(crate) execution: Vec<u8>,
    pub(crate) approval_credential_id: Vec<u8>,
    pub(crate) executor_credential_id: Vec<u8>,
    pub(crate) origin: String,
    pub(crate) rp_id: String,
}

#[cfg(test)]
pub(super) fn fixture_data(
    intent: &ApprovalIntent,
    approver: &crate::security_epoch::restore_approval::AdminIdentity,
    record: &SignedApprovalRecord,
    operation: &Digest,
) -> Result<RestorePromptFixtureData> {
    intent.require_request(&record.statement.request)?;
    ensure!(
        record.statement.approver == *approver,
        "restore_prompt_fixture_approver_changed"
    );
    // Existing synthetic fixture material only. Distinct principals use
    // distinct public credential IDs, as two real registry rows would require.
    let mut approval_fixture = super::tests::fixture();
    approval_fixture.key.record.principal = approver.clone();
    approval_fixture.key.record.credential_id = b"fixture-approval-credential".to_vec();
    approval_fixture.challenge.request = intent.commitment()?;
    approval_fixture.challenge.enrollment = approval_fixture.key.record.binding_data()?;
    let approval_bytes = approval(
        &approval_fixture.key.record,
        &approval_fixture.challenge,
        approval_fixture.challenge.encoded()?,
        intent,
    )?
    .encode()?;

    let mut execution_fixture = super::tests::fixture();
    execution_fixture.key.record.principal = record.statement.request.executor.clone();
    execution_fixture.key.record.credential_id = b"fixture-executor-credential".to_vec();
    execution_fixture.challenge.request = execution_request(record, operation)?;
    execution_fixture.challenge.enrollment = execution_fixture.key.record.binding_data()?;
    let execution_bytes = execution(
        &execution_fixture.key.record,
        &execution_fixture.challenge,
        execution_fixture.challenge.encoded()?,
        record,
        operation,
    )?
    .encode()?;
    ensure!(
        approval_fixture.key.record.origin == execution_fixture.key.record.origin
            && approval_fixture.key.record.rp_id == execution_fixture.key.record.rp_id,
        "restore_prompt_fixture_origin_changed"
    );
    Ok(RestorePromptFixtureData {
        approval: approval_bytes,
        execution: execution_bytes,
        approval_credential_id: approval_fixture.key.record.credential_id.clone(),
        executor_credential_id: execution_fixture.key.record.credential_id.clone(),
        origin: approval_fixture.key.record.origin.clone(),
        rp_id: approval_fixture.key.record.rp_id.clone(),
    })
}

#[derive(Serialize)]
#[serde(tag = "purpose")]
enum Prompt {
    #[serde(rename = "day2_restore_approval_v1")]
    Approval {
        intent: Box<ApprovalIntent>,
        approver: crate::security_epoch::restore_approval::AdminIdentity,
        request: Digest,
        origin: String,
        public_key: PublicKeyRequest,
    },
    #[serde(rename = "day2_restore_execution_v1")]
    Execution {
        approval: Box<SignedApprovalRecord>,
        operation: Digest,
        request: Digest,
        origin: String,
        public_key: PublicKeyRequest,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyRequest {
    challenge: String,
    rp_id: String,
    allow_credentials: [Credential; 1],
    user_verification: UserVerification,
}

#[derive(Serialize)]
struct Credential {
    r#type: CredentialType,
    id: String,
}

#[derive(Serialize)]
enum CredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Serialize)]
enum UserVerification {
    #[serde(rename = "required")]
    Required,
}

fn public_key(
    record: &KeyRecord,
    challenge: &Challenge,
    encoded: String,
) -> Result<PublicKeyRequest> {
    ensure!(
        (1..=MAX_CREDENTIAL_ID).contains(&record.credential_id.len())
            && challenge.enrollment == record.binding_data()?
            && encoded == challenge.encoded()?,
        "restore_prompt_ceremony_binding_changed"
    );
    Ok(PublicKeyRequest {
        challenge: encoded,
        rp_id: record.rp_id.clone(),
        allow_credentials: [Credential {
            r#type: CredentialType::PublicKey,
            id: URL_SAFE_NO_PAD.encode(&record.credential_id),
        }],
        user_verification: UserVerification::Required,
    })
}

pub(in crate::security_epoch::restore_webauthn) fn approval(
    record: &KeyRecord,
    challenge: &Challenge,
    encoded: String,
    intent: &ApprovalIntent,
) -> Result<RestorePasskeyPrompt> {
    ensure!(
        challenge.request == intent.commitment()?,
        "restore_prompt_approval_intent_changed"
    );
    let prompt = RestorePasskeyPrompt {
        data: Prompt::Approval {
            intent: Box::new(intent.clone()),
            approver: record.principal.clone(),
            request: challenge.request.clone(),
            origin: record.origin.clone(),
            public_key: public_key(record, challenge, encoded)?,
        },
    };
    prompt.encode()?;
    Ok(prompt)
}

pub(in crate::security_epoch::restore_webauthn) fn execution(
    record: &KeyRecord,
    challenge: &Challenge,
    encoded: String,
    approval: &SignedApprovalRecord,
    operation: &Digest,
) -> Result<RestorePasskeyPrompt> {
    ensure!(
        challenge.request == execution_request(approval, operation)?,
        "restore_prompt_execution_binding_changed"
    );
    let prompt = RestorePasskeyPrompt {
        data: Prompt::Execution {
            approval: Box::new(approval.clone()),
            operation: operation.clone(),
            request: challenge.request.clone(),
            origin: record.origin.clone(),
            public_key: public_key(record, challenge, encoded)?,
        },
    };
    prompt.encode()?;
    Ok(prompt)
}

impl RestorePasskeyPrompt {
    pub(in crate::security_epoch) fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&self.data)?;
        ensure!(bytes.len() <= MAX_BYTES, "restore_prompt_bound");
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
