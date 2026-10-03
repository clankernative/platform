//! Checked input intent and current-policy guards for local lifecycle commands.
use super::{
    issuance::{Confirmation, ReadyKeys},
    store,
};
use crate::{app_contract::CredentialAccess, authority_state::ActiveCredentialFamily, protocol};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{
        LineageRef, ManagedProfile, ManagementPredicate, ManagementSnapshot, ManagementState,
        ManifestFamily, RotationProfile, VersionRef,
    },
    oauth::GrantCeiling,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Intent {
    Issue {
        label: String,
    },
    Rotate {
        lineage: String,
        head: String,
        revision: u64,
    },
    Revoke {
        lineage: String,
    },
}

impl Intent {
    pub(crate) fn action(&self) -> &str {
        match self {
            Self::Issue { .. } => "issue",
            Self::Rotate { .. } => "rotate",
            Self::Revoke { .. } => "revoke",
        }
    }

    pub(super) fn instruction(&self, registration: &str, invocation: &str) -> Value {
        let mut value = serde_json::to_value(self).expect("string-only intent");
        let object = value.as_object_mut().expect("intent record");
        object.remove("action");
        object.insert("registration".into(), registration.into());
        object.insert("invocation".into(), invocation.into());
        value
    }
}

pub(super) fn intent(access: &CredentialAccess, input: &Value) -> Result<Intent> {
    let text = |path: &str| -> Result<String> {
        Ok(input
            .get(path)
            .and_then(Value::as_str)
            .context("credential canonical input path missing")?
            .into())
    };
    Ok(
        match access
            .mutation()
            .context("credential mutation declaration missing")?
            .0
        {
            "issue" => {
                let label = text(&access.issue_label)?;
                ensure!(
                    !label.trim().is_empty()
                        && label.len() <= 128
                        && !label.chars().any(char::is_control),
                    "invalid credential label"
                );
                Intent::Issue { label }
            }
            "rotate" => {
                let head = text(&access.rotation_head)?;
                let revision = input
                    .get(&access.rotation_revision)
                    .and_then(Value::as_u64)
                    .context("credential rotation revision missing")?;
                ensure!(
                    revision > 0
                        && revision <= i64::MAX as u64
                        && !head.is_empty()
                        && head.len() <= 160
                        && head
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                    "invalid credential rotation precondition"
                );
                Intent::Rotate {
                    lineage: text(&access.management_lineage)?,
                    head,
                    revision,
                }
            }
            "revoke" => Intent::Revoke {
                lineage: text(&access.management_lineage)?,
            },
            _ => anyhow::bail!("unsupported credential action"),
        },
    )
}

pub(super) fn stage(
    tx: &Transaction<'_>,
    request: &protocol::Request,
    proof: &Confirmation,
    family: &ManifestFamily,
    selected: &ActiveCredentialFamily,
    ready: &ReadyKeys,
) -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let (raw, predicate) = match &proof.intent {
        Intent::Rotate { lineage, .. } => (lineage, &selected.management.rotate),
        Intent::Revoke { lineage } => (lineage, &selected.management.revoke),
        _ => anyhow::bail!("credential lifecycle action required"),
    };
    // Group predicates require an admitted current group resolver, not guessed membership.
    ensure!(
        matches!(predicate, ManagementPredicate::Creator),
        "credential management policy unavailable"
    );
    let prefix = format!("cr1_{}_", family.registration.as_str());
    ensure!(raw.len() <= 2048, "invalid credential lineage");
    let lineage: LineageRef = crate::json::decode(
        &URL_SAFE_NO_PAD.decode(
            raw.strip_prefix(&prefix)
                .context("credential family reference mismatch")?,
        )?,
    )?;
    ensure!(
        lineage.namespace == selected.binding.namespace
            && lineage.family == family.id
            && super::encode_ref(family.registration.as_str(), &lineage)? == *raw,
        "credential lineage outside selected family"
    );
    let namespace = Digest::of(&("credential-namespace-v1", &lineage.namespace))?;
    let (principal, label, grant_json, grant_digest, grant_until, epoch, creator): (String, String, String, String, i64, i64, String) = tx.query_row(
        "SELECT principal,label,grant_json,grant_digest,grant_valid_until,security_epoch,creator
         FROM day2_credential_lineages WHERE id=?1 AND namespace=?2 AND family=?3 AND family_contract=?4",
        params![lineage.id,namespace.as_str(),family.id.as_str(),family.contract.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    ).optional()?.context("credential lineage unavailable")?;
    ensure!(creator == proof.actor, "credential management denied");
    let slot = u32::try_from(request.observations.len())?;
    match &proof.intent {
        Intent::Rotate { head, revision, .. } => {
            ensure!(
                matches!(selected.binding.rotation, RotationProfile::AtomicReplace),
                "credential rotation profile unavailable"
            );
            ensure!(
                family.profile != ManagedProfile::Personal || principal == proof.subject,
                "personal rotation requires its fixed human subject"
            );
            ensure!(
                u64::try_from(epoch)? == ready.security_epoch,
                "credential lineage security epoch retired"
            );
            let ceiling: GrantCeiling = crate::json::decode(grant_json.as_bytes())?;
            ceiling.verify()?;
            ensure!(
                ceiling.digest.as_str() == grant_digest
                    && ceiling.subject == principal
                    && ceiling.client == selected.binding.approved_authority
                    && ceiling.audience == selected.binding.audience,
                "credential stored authority changed"
            );
            for root in ceiling.roots.values() {
                ensure!(
                    family.roots.get(&root.operation) == Some(root),
                    "credential predecessor grant no longer admitted"
                );
            }
            let expires_at = proof
                .approved_at
                .checked_add(i64::try_from(family.lifetime_seconds)?)
                .context("credential lifetime overflow")?
                .min(grant_until)
                .min(ready.valid_until);
            if expires_at <= proof.approved_at {
                return Ok(
                    json!({"conflict":true,"lineage":"","version":"","label":"","expires_at":0})
                        .to_string(),
                );
            }
            let expected = ManagementSnapshot {
                lineage: lineage.clone(),
                head: VersionRef {
                    lineage: lineage.clone(),
                    id: head.clone(),
                },
                revision: *revision,
                state: ManagementState::Active,
            };
            let result = store::stage_rotation(
                tx,
                &ready.keys,
                &expected,
                store::RotationIntent {
                    invocation: &proof.invocation,
                    instruction_slot: slot,
                    recipient: &proof.actor,
                    session: &proof.session,
                    issued_at: proof.approved_at,
                    expires_at,
                    reveal_until: proof
                        .approved_at
                        .checked_add(i64::from(selected.binding.reveal_window_seconds))
                        .context("credential reveal overflow")?
                        .min(expires_at),
                },
            )?;
            Ok(match result {
                store::RotationResult::Conflict => json!({"conflict":true,"lineage":"","version":"","label":"","expires_at":0}),
                store::RotationResult::Rotated(pending) => json!({"conflict":false,"lineage":raw,"version":pending.public_identity().version,"label":label,"expires_at":expires_at}),
            }.to_string())
        }
        Intent::Revoke { .. } => {
            // Retain the exact public outcome independently of later lineage revisions.
            let digest = Digest::of(&(
                "credential-revocation-intent-v1",
                &proof.intent,
                &proof.actor,
                &proof.subject,
                &proof.session,
            ))?;
            let previous: Option<(String,String)> = tx.query_row("SELECT request_digest,outcome FROM day2_credential_revocations WHERE namespace=?1 AND invocation=?2 AND instruction_slot=?3",
                params![namespace.as_str(),proof.invocation,slot], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
            if let Some((prior, outcome)) = previous {
                ensure!(
                    prior == digest.as_str(),
                    "credential revocation identity reused"
                );
                return Ok(outcome);
            }
            let changed = store::stage_revoke(tx, &lineage.namespace, &lineage.id)?;
            let revision: i64 = tx.query_row(
                "SELECT revision FROM day2_credential_lineages WHERE id=?1",
                [&lineage.id],
                |row| row.get(0),
            )?;
            let outcome =
                json!({"already_revoked":!changed,"lineage":raw,"revision":revision}).to_string();
            tx.execute(
                "INSERT INTO day2_credential_receipts VALUES (?1,?2,?3,?4,?5,'revoke',?6,NULL)",
                params![
                    namespace.as_str(),
                    proof.invocation,
                    slot,
                    family.contract.as_str(),
                    digest.as_str(),
                    lineage.id
                ],
            )?;
            tx.execute(
                "INSERT INTO day2_credential_revocations VALUES (?1,?2,?3,?4,?5)",
                params![
                    namespace.as_str(),
                    proof.invocation,
                    slot,
                    digest.as_str(),
                    outcome
                ],
            )?;
            Ok(outcome)
        }
        _ => anyhow::bail!("credential lifecycle action required"),
    }
}
