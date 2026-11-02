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
        GrantMode, GrantSelection, IssuanceGrant, LineageRef, ManagedProfile, ManagementPredicate,
        ManagementSnapshot, ManagementState, ManifestFamily, RotationGrant, RotationProfile,
        VersionRef,
    },
    oauth::GrantCeiling,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum IssueGrant {
    Fixed {},
    Selected { selection: GrantSelection },
}

impl IssueGrant {
    pub(crate) fn request(&self) -> IssuanceGrant<'_> {
        match self {
            Self::Fixed {} => IssuanceGrant::Fixed,
            Self::Selected { selection } => IssuanceGrant::Selected(selection),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RotationWire", into = "RotationWire")]
pub(crate) enum RotateGrant {
    Fixed,
    KeepExisting,
    Narrow(GrantSelection),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RotationMode {
    Fixed,
    KeepExisting,
    Narrow,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationWire {
    mode: RotationMode,
    selections: Vec<GrantSelection>,
}

impl TryFrom<RotationWire> for RotateGrant {
    type Error = anyhow::Error;

    fn try_from(wire: RotationWire) -> Result<Self> {
        match (wire.mode, wire.selections.as_slice()) {
            (RotationMode::Fixed, []) => Ok(Self::Fixed),
            (RotationMode::KeepExisting, []) => Ok(Self::KeepExisting),
            (RotationMode::Narrow, [selection]) => Ok(Self::Narrow(selection.clone())),
            _ => anyhow::bail!("invalid closed credential rotation choice"),
        }
    }
}

impl From<RotateGrant> for RotationWire {
    fn from(choice: RotateGrant) -> Self {
        match choice {
            RotateGrant::Fixed => Self {
                mode: RotationMode::Fixed,
                selections: vec![],
            },
            RotateGrant::KeepExisting => Self {
                mode: RotationMode::KeepExisting,
                selections: vec![],
            },
            RotateGrant::Narrow(selection) => Self {
                mode: RotationMode::Narrow,
                selections: vec![selection],
            },
        }
    }
}

impl RotateGrant {
    pub(super) fn request(&self, family: &ManifestFamily) -> Result<RotationGrant<'_>> {
        match (self, &family.grant) {
            (Self::Fixed, GrantMode::Fixed) | (Self::KeepExisting, GrantMode::Selectable) => {
                Ok(RotationGrant::KeepExisting)
            }
            (Self::Narrow(selection), GrantMode::Selectable) => {
                validate_selection(selection)?;
                family.issuance_roots(IssuanceGrant::Selected(selection))?;
                Ok(RotationGrant::Narrow(selection))
            }
            _ => anyhow::bail!("credential rotation grant mode mismatch"),
        }
    }
}

/// Frozen consent DATA only. Current policy, original and actual predecessor
/// are checked again under the publishing transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotationPreview {
    pub digest: Digest,
    pub roots: Vec<String>,
}

pub(super) fn validate_selection(selection: &GrantSelection) -> Result<()> {
    ensure!(
        (1..=64).contains(&selection.roots().len())
            && selection.roots().windows(2).all(|pair| pair[0] < pair[1]),
        "credential selection root budget or order"
    );
    for root in selection.roots() {
        store::validate_id(root)?;
    }
    Ok(())
}

pub(super) fn validate_preview(intent: &Intent, preview: &Option<RotationPreview>) -> Result<()> {
    ensure!(
        matches!(intent, Intent::Rotate { .. }) == preview.is_some(),
        "credential rotation preview missing or unexpected"
    );
    if let Some(preview) = preview {
        ensure!(
            (1..=64).contains(&preview.roots.len())
                && preview.roots.windows(2).all(|pair| pair[0] < pair[1]),
            "credential rotation preview root budget or order"
        );
        for root in &preview.roots {
            store::validate_id(root)?;
        }
    }
    Ok(())
}

fn lineage_ref(
    raw: &str,
    family: &ManifestFamily,
    selected: &ActiveCredentialFamily,
) -> Result<LineageRef> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    ensure!(raw.len() <= 2048, "invalid credential lineage");
    let prefix = format!("cr1_{}_", family.registration.as_str());
    let lineage: LineageRef = crate::json::decode(
        &URL_SAFE_NO_PAD.decode(
            raw.strip_prefix(&prefix)
                .context("credential family reference mismatch")?,
        )?,
    )?;
    ensure!(
        lineage.namespace == selected.binding.namespace
            && lineage.family == family.id
            && super::encode_ref(family.registration.as_str(), &lineage)? == raw,
        "credential lineage outside selected family"
    );
    Ok(lineage)
}

pub(super) fn rotation_preview(
    db: &Connection,
    family: &ManifestFamily,
    selected: &ActiveCredentialFamily,
    actor: &str,
    intent: &Intent,
) -> Result<Option<RotationPreview>> {
    let Intent::Rotate {
        lineage,
        head,
        grant,
        ..
    } = intent
    else {
        return Ok(None);
    };
    ensure!(
        matches!(selected.management.rotate, ManagementPredicate::Creator),
        "credential management policy unavailable"
    );
    let lineage = lineage_ref(lineage, family, selected)?;
    let creator:String=db.query_row(
        "SELECT creator FROM day2_credential_lineages WHERE id=?1 AND namespace=?2 AND family=?3 AND family_contract=?4",
        params![lineage.id,Digest::of(&("credential-namespace-v1",&lineage.namespace))?.as_str(),family.id.as_str(),family.contract.as_str()],|r|r.get(0),
    )?;
    ensure!(creator == actor, "credential management denied");
    let predecessor = store::version_grant(db, &lineage, head)?;
    let successor = family.rotation_ceiling(&predecessor, grant.request(family)?)?;
    Ok(Some(RotationPreview {
        digest: successor.digest,
        roots: successor.roots.into_keys().collect(),
    }))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Intent {
    Issue {
        label: String,
        grant: IssueGrant,
    },
    Rotate {
        lineage: String,
        head: String,
        revision: u64,
        grant: RotateGrant,
    },
    Revoke {
        lineage: String,
    },
}

impl Intent {
    pub(super) fn check_family(&self, family: &ManifestFamily) -> Result<()> {
        if let Self::Issue { grant, .. } = self {
            family.issuance_roots(grant.request())?;
        } else if let Self::Rotate { grant, .. } = self {
            grant.request(family)?;
        }
        Ok(())
    }

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
                let grant = if access.issue_grant.is_empty() {
                    IssueGrant::Fixed {}
                } else {
                    let raw = text(&access.issue_grant)?;
                    ensure!(raw.len() <= 8192, "credential selection byte budget");
                    IssueGrant::Selected {
                        selection: crate::json::decode(raw.as_bytes())?,
                    }
                };
                Intent::Issue { label, grant }
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
                    grant: if access.rotation_grant.is_empty() {
                        RotateGrant::Fixed
                    } else {
                        let raw = text(&access.rotation_grant)?;
                        ensure!(raw.len() <= 16384, "credential rotation choice byte budget");
                        let grant: RotateGrant = crate::json::decode(raw.as_bytes())?;
                        ensure!(
                            serde_json::to_string(&grant)? == raw,
                            "noncanonical credential rotation choice"
                        );
                        grant
                    },
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
    let lineage = lineage_ref(raw, family, selected)?;
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
        Intent::Rotate {
            head,
            revision,
            grant: choice,
            ..
        } => {
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
            ensure!(
                ceiling.digest.as_str() == grant_digest
                    && ceiling.subject == principal
                    && ceiling.client == selected.binding.approved_authority
                    && ceiling.audience == selected.binding.audience,
                "credential stored authority changed"
            );
            let predecessor = store::version_grant(tx, &lineage, head)?;
            let grant = family.rotation_ceiling(&predecessor, choice.request(family)?)?;
            ensure!(
                proof.rotation_grant.as_ref() == Some(&grant.digest),
                "credential rotation grant changed after confirmation"
            );
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
                    grant: &grant,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_choice_is_closed_canonical_and_never_defaults_to_a_grant() -> Result<()> {
        let keep = RotateGrant::KeepExisting;
        assert_eq!(
            serde_json::to_string(&keep)?,
            r#"{"mode":"keep_existing","selections":[]}"#
        );
        let selection: GrantSelection = serde_json::from_value(json!({
            "family_contract":Digest::new(b"rotation choice family"),"roots":["app.read"]
        }))?;
        let narrow = RotateGrant::Narrow(selection);
        let encoded = serde_json::to_string(&narrow)?;
        assert_eq!(
            crate::json::decode::<RotateGrant>(encoded.as_bytes())?,
            narrow
        );
        for value in [
            json!(null),
            json!("keep_existing"),
            json!({}),
            json!({"mode":"keep_existing"}),
            json!({"mode":"keep_existing","selections":[],"extra":true}),
            json!({"mode":"unknown","selections":[]}),
            json!({"mode":"narrow","selections":[]}),
            json!({"mode":"keep_existing","selections":[json!({"family_contract":Digest::new(b"family"),"roots":["app.read"]})]}),
            json!({"mode":"narrow","selections":[json!({"family_contract":Digest::new(b"family"),"roots":["app.read"]}),json!({"family_contract":Digest::new(b"family"),"roots":["app.write"]})]}),
        ] {
            assert!(
                crate::json::decode::<RotateGrant>(value.to_string().as_bytes()).is_err(),
                "accepted {value}"
            );
        }
        for roots in [
            vec![],
            vec!["app.read", "app.read"],
            vec!["app.write", "app.read"],
            vec!["invalid root"],
        ] {
            let selection: GrantSelection = serde_json::from_value(
                json!({"family_contract":Digest::new(b"family"),"roots":roots}),
            )?;
            assert!(validate_selection(&selection).is_err());
        }
        let duplicate = r#"{"mode":"keep_existing","mode":"narrow","selections":[]}"#;
        assert!(crate::json::decode::<RotateGrant>(duplicate.as_bytes()).is_err());
        Ok(())
    }
}
