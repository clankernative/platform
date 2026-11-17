//! Browser presentation DATA decoded from a genuine protected-channel reply.
//! This does not verify a passkey, approve restore, authenticate an executor,
//! lend a native owner or supply a final-success response. The routing caller
//! must first authenticate IAP and retain its process-local ceremony binding.
use crate::iap;
use crate::security_epoch::{
    ProtectedRestoreCommandData,
    restore_approval::{AdminIdentity, ApprovalIntent, signed::SignedApprovalRecord},
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

const MAX_PROMPT_BYTES: usize = 32_768;

#[derive(Serialize, Deserialize)]
#[serde(tag = "purpose", deny_unknown_fields)]
enum Prompt {
    #[serde(rename = "day2_restore_approval_v1")]
    Approval {
        intent: Box<ApprovalIntent>,
        approver: AdminIdentity,
        request: Digest,
        origin: String,
        public_key: PublicKey,
    },
    #[serde(rename = "day2_restore_execution_v1")]
    Execution {
        approval: Box<SignedApprovalRecord>,
        operation: Digest,
        request: Digest,
        origin: String,
        public_key: PublicKey,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicKey {
    challenge: String,
    rp_id: String,
    allow_credentials: [Credential; 1],
    user_verification: UserVerification,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    r#type: CredentialType,
    id: String,
}

#[derive(Serialize, Deserialize)]
enum CredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
}

#[derive(Serialize, Deserialize)]
enum UserVerification {
    #[serde(rename = "required")]
    Required,
}

fn decode(bytes: &[u8]) -> Result<Prompt> {
    ensure!(
        bytes.len() <= MAX_PROMPT_BYTES,
        "restore_browser_prompt_bound"
    );
    let value: serde_json::Value = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("restore_browser_prompt_encoding"))?;
    let prompt: Prompt = serde_json::from_value(value.clone())
        .map_err(|_| anyhow::anyhow!("restore_browser_prompt_encoding"))?;
    // Reject sequence aliases and enum-map alternatives at EVERY nested DTO,
    // including reused intent/record DATA. Only the producer's object/string
    // shape may cross this presentation boundary; duplicate keys were already
    // refused by the common bounded decoder above.
    ensure!(
        serde_json::to_value(&prompt)? == value,
        "restore_browser_prompt_shape"
    );
    Ok(prompt)
}

fn require_identity(actual: &AdminIdentity, identity: &iap::Verified) -> Result<()> {
    ensure!(
        actual.email == identity.email && actual.subject == identity.subject,
        "restore_browser_principal_changed"
    );
    Ok(())
}

impl PublicKey {
    fn require_selected(&self, credential: &[u8], origin: &str) -> Result<()> {
        let selected =
            url::Url::parse(origin).map_err(|_| anyhow::anyhow!("restore_browser_origin"))?;
        ensure!(
            selected.scheme() == "https"
                && selected.origin().ascii_serialization() == origin
                && selected.username().is_empty()
                && selected.password().is_none()
                && selected.host_str() == Some(self.rp_id.as_str()),
            "restore_browser_origin"
        );
        // The reviewed registry validator binds each RP ID to this exact
        // security origin (including an explicit non-default port). These are
        // comparisons to configured origin DATA, not permission from a prompt.
        ensure!(
            (1..=1023).contains(&credential.len())
                && self.allow_credentials[0].id == URL_SAFE_NO_PAD.encode(credential),
            "restore_browser_credential_changed"
        );
        let challenge = URL_SAFE_NO_PAD
            .decode(&self.challenge)
            .map_err(|_| anyhow::anyhow!("restore_browser_challenge"))?;
        // The genuine producer emits exactly the SHA-256 challenge commitment.
        ensure!(
            challenge.len() == 32 && URL_SAFE_NO_PAD.encode(&challenge) == self.challenge,
            "restore_browser_challenge"
        );
        Ok(())
    }
}

/// Validate the complete actual approval prompt BEFORE returning challenge
/// DATA to the same IAP email+subject. A declared email alone is insufficient.
/// `id` is only correlation; it never recreates a server-held pending ceremony.
pub(super) fn approval(
    bytes: &[u8],
    id: &Digest,
    command: &ProtectedRestoreCommandData,
    identity: &iap::Verified,
    origin: &str,
) -> Result<AdminIdentity> {
    ensure!(id == &command.id, "restore_browser_command_changed");
    let Prompt::Approval {
        intent,
        approver,
        request,
        origin: actual_origin,
        public_key,
    } = decode(bytes)?
    else {
        anyhow::bail!("restore_browser_purpose_changed");
    };
    command.intent.require_exact(&intent)?;
    require_identity(&approver, identity)?;
    ensure!(
        approver.email == command.approver_email
            && request == command.intent.commitment()?
            && actual_origin == origin,
        "restore_browser_approval_changed"
    );
    public_key.require_selected(&command.approver_credential, origin)?;
    Ok(approver)
}

/// Validate the later distinct executor ceremony against the SAME retained
/// command, approval result and selected approver. The two humans may differ.
/// No clock is begun or extended here; the genuine native verifier retains its
/// original fixed challenge and single-use grant lifetime independently.
pub(super) fn execution(
    bytes: &[u8],
    id: &Digest,
    command: &ProtectedRestoreCommandData,
    recorded: &Digest,
    approved_by: &AdminIdentity,
    identity: &iap::Verified,
    origin: &str,
) -> Result<Digest> {
    ensure!(id == &command.id, "restore_browser_command_changed");
    let Prompt::Execution {
        approval,
        operation,
        request,
        origin: actual_origin,
        public_key,
    } = decode(bytes)?
    else {
        anyhow::bail!("restore_browser_purpose_changed");
    };
    command
        .intent
        .require_request(&approval.statement.request)?;
    require_identity(&approval.statement.request.executor, identity)?;
    ensure!(
        Digest::of(approval.as_ref())? == *recorded
            && approval.statement.approver == *approved_by
            && operation == command.operation
            && request
                == crate::security_epoch::restore_execution_request_data(&approval, &operation)?
            && actual_origin == origin,
        "restore_browser_execution_changed"
    );
    public_key.require_selected(&command.executor_credential, origin)?;
    // Only correlation DATA from this already-validated SAME public record.
    // ApprovalRecorded commits the entire signed record; terminal native output
    // commits the contained request instead. Do not confuse those two hashes.
    approval.statement.request.commitment()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    struct World {
        command: ProtectedRestoreCommandData,
        record: SignedApprovalRecord,
        approver: AdminIdentity,
        approval: Vec<u8>,
        execution: Vec<u8>,
        origin: String,
    }

    fn world() -> Result<World> {
        // Synthetic PUBLIC signed-record DATA only. No signature, passkey,
        // native owner or authenticated execution is qualified by this fixture.
        let mut record = crate::security_epoch::restore_public_record_fixture_data()?;
        let approver = AdminIdentity {
            email: "approver@example.com".into(),
            subject: "approver-subject".into(),
        };
        record.statement.approver = approver.clone();
        record.statement.request.executor = AdminIdentity {
            email: "executor@example.com".into(),
            subject: "executor-subject".into(),
        };
        let intent = record.statement.request.intent();
        let operation = Digest::new(b"exact executor operation DATA");
        // Actual production prompt factories and encoder, with inert fixture
        // key material supplied only inside the verifier's own cfgtest module.
        let data = crate::security_epoch::restore_prompt_fixture_data(
            &intent, &approver, &record, &operation,
        )?;
        assert_ne!(data.approval_credential_id, data.executor_credential_id);
        assert_eq!(
            url::Url::parse(&data.origin)?.host_str(),
            Some(data.rp_id.as_str())
        );
        Ok(World {
            command: ProtectedRestoreCommandData {
                id: Digest::new(b"complete selected command DATA"),
                intent,
                operation,
                approver_email: approver.email.clone(),
                approver_credential: data.approval_credential_id,
                executor_credential: data.executor_credential_id,
            },
            record,
            approver,
            approval: data.approval,
            execution: data.execution,
            origin: data.origin,
        })
    }

    fn identity(data: &AdminIdentity) -> iap::Verified {
        iap::Verified {
            email: data.email.clone(),
            subject: data.subject.clone(),
        }
    }

    #[test]
    fn actual_encoder_prompts_keep_distinct_approver_and_executor_principals_and_phases()
    -> Result<()> {
        let world = world()?;
        let approver = identity(&world.approver);
        let executor = identity(&world.command.intent.executor);
        assert_eq!(
            approval(
                &world.approval,
                &world.command.id,
                &world.command,
                &approver,
                &world.origin
            )?,
            world.approver
        );
        let recorded = Digest::of(&world.record)?;
        let approval_request = execution(
            &world.execution,
            &world.command.id,
            &world.command,
            &recorded,
            &world.approver,
            &executor,
            &world.origin,
        )?;
        assert_eq!(
            approval_request,
            world.record.statement.request.commitment()?
        );
        assert_ne!(approval_request, recorded);
        assert!(
            approval(
                &world.approval,
                &world.command.id,
                &world.command,
                &executor,
                &world.origin
            )
            .is_err()
        );
        assert!(
            execution(
                &world.execution,
                &world.command.id,
                &world.command,
                &recorded,
                &world.approver,
                &approver,
                &world.origin
            )
            .is_err()
        );
        for wrong in [
            iap::Verified {
                subject: "another-subject".into(),
                ..approver
            },
            iap::Verified {
                email: "another@example.com".into(),
                ..identity(&world.approver)
            },
        ] {
            assert!(
                approval(
                    &world.approval,
                    &world.command.id,
                    &world.command,
                    &wrong,
                    &world.origin
                )
                .is_err()
            );
        }
        assert!(
            approval(
                &world.execution,
                &world.command.id,
                &world.command,
                &identity(&world.approver),
                &world.origin
            )
            .is_err()
        );
        assert!(
            execution(
                &world.approval,
                &world.command.id,
                &world.command,
                &recorded,
                &world.approver,
                &executor,
                &world.origin
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn immutable_command_record_operation_origin_and_public_key_joins_refuse_substitution()
    -> Result<()> {
        let world = world()?;
        let approver = identity(&world.approver);
        let executor = identity(&world.command.intent.executor);
        let recorded = Digest::of(&world.record)?;
        let other = Digest::new(b"foreign DATA");
        assert!(
            approval(
                &world.approval,
                &other,
                &world.command,
                &approver,
                &world.origin
            )
            .is_err()
        );
        assert!(
            execution(
                &world.execution,
                &world.command.id,
                &world.command,
                &other,
                &world.approver,
                &executor,
                &world.origin
            )
            .is_err()
        );
        for (is_approval, raw, paths) in [
            (
                true,
                &world.approval,
                vec![
                    "/request",
                    "/origin",
                    "/approver/subject",
                    "/public_key/rpId",
                    "/public_key/challenge",
                    "/public_key/allowCredentials/0/id",
                ],
            ),
            (
                false,
                &world.execution,
                vec![
                    "/request",
                    "/origin",
                    "/operation",
                    "/approval/statement/approver/subject",
                    "/public_key/rpId",
                    "/public_key/challenge",
                    "/public_key/allowCredentials/0/id",
                ],
            ),
        ] {
            for path in paths {
                let mut changed: Value = crate::json::decode(raw)?;
                *changed.pointer_mut(path).unwrap() = match path {
                    "/request" | "/operation" => json!(other),
                    "/public_key/challenge" => json!(URL_SAFE_NO_PAD.encode([7u8; 31])),
                    "/public_key/allowCredentials/0/id" => {
                        json!(URL_SAFE_NO_PAD.encode(b"foreign-public-credential"))
                    }
                    "/origin" => json!("https://another.example.com"),
                    "/public_key/rpId" => json!("another.example.com"),
                    _ => json!("foreign-subject"),
                };
                let changed = serde_json::to_vec(&changed)?;
                if is_approval {
                    assert!(
                        approval(
                            &changed,
                            &world.command.id,
                            &world.command,
                            &approver,
                            &world.origin
                        )
                        .is_err(),
                        "{path}"
                    );
                } else {
                    assert!(
                        execution(
                            &changed,
                            &world.command.id,
                            &world.command,
                            &recorded,
                            &world.approver,
                            &executor,
                            &world.origin
                        )
                        .is_err(),
                        "{path}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn displayed_intent_and_retained_execution_intent_cannot_diverge_from_the_exact_command()
    -> Result<()> {
        let mut world = world()?;
        let approver = identity(&world.approver);
        for path in [
            "/intent/target/security_epoch",
            "/intent/full_archive_digest",
        ] {
            let mut prompt: Value = crate::json::decode(&world.approval)?;
            *prompt.pointer_mut(path).unwrap() = if path.ends_with("security_epoch") {
                json!(world.command.intent.target.security_epoch + 1)
            } else {
                json!(Digest::new(b"another full archive DATA"))
            };
            // Keep the original command id, request digest, real fixture IAP,
            // origin and public key EXACT. Only displayed consent is changed.
            // Removing require_exact must make this actual regression fail.
            assert!(
                approval(
                    &serde_json::to_vec(&prompt)?,
                    &world.command.id,
                    &world.command,
                    &approver,
                    &world.origin
                )
                .is_err(),
                "{path}"
            );
        }
        let executor = identity(&world.record.statement.request.executor);
        let recorded = Digest::of(&world.record)?;
        execution(
            &world.execution,
            &world.command.id,
            &world.command,
            &recorded,
            &world.approver,
            &executor,
            &world.origin,
        )?;
        // Corrupt ONLY the retained intent DATA: no new locator, operation,
        // record, hash, prompt request or expected actor is supplied. Removing
        // require_request would accept this inconsistent composition.
        world.command.intent.target.security_epoch += 1;
        assert!(
            execution(
                &world.execution,
                &world.command.id,
                &world.command,
                &recorded,
                &world.approver,
                &executor,
                &world.origin
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn nested_derived_sequence_and_enum_map_aliases_never_normalize_into_browser_prompts()
    -> Result<()> {
        let world = world()?;
        for raw in [&world.approval, &world.execution] {
            let value: Value = crate::json::decode(raw)?;
            for path in [
                "/public_key",
                "/public_key/allowCredentials/0",
                "/public_key/userVerification",
                "/public_key/allowCredentials/0/type",
            ] {
                let mut changed = value.clone();
                let current = changed.pointer(path).unwrap();
                let alias = match path {
                    "/public_key" => json!([
                        current["challenge"],
                        current["rpId"],
                        current["allowCredentials"],
                        current["userVerification"]
                    ]),
                    "/public_key/allowCredentials/0" => json!([current["type"], current["id"]]),
                    "/public_key/userVerification" => json!({"required":null}),
                    _ => json!({"public-key":null}),
                };
                *changed.pointer_mut(path).unwrap() = alias;
                // Prove this is an alias the derive would actually normalize,
                // rather than a fixture rejected for an unrelated wrong type.
                let normalized: Prompt = serde_json::from_value(changed.clone())?;
                assert_ne!(serde_json::to_value(normalized)?, changed);
                assert!(decode(&serde_json::to_vec(&changed)?).is_err(), "{path}");
            }
            let mut extra = value.clone();
            extra["current_owner"] = json!(true);
            assert!(decode(&serde_json::to_vec(&extra)?).is_err());
            let raw = std::str::from_utf8(raw)?;
            let duplicate = format!("{{\"purpose\":{},{}", value["purpose"], &raw[1..]);
            assert!(decode(duplicate.as_bytes()).is_err());
        }
        assert!(decode(&vec![b' '; MAX_PROMPT_BYTES + 1]).is_err());
        Ok(())
    }
}
