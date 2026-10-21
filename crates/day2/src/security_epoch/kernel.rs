//! Pure initial bootstrap transitions and exact-request reconciliation. The
//! external epoch is independent of OAuth slot epochs and local authority stamps.
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{AuthorityScope, EpochProvider, EpochStore, SecurityEpoch},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub activation: Digest,
    pub database_incarnation: Digest,
    pub provider_volume_uid: String,
    pub mount_binding: Digest,
    pub schema: Digest,
    pub marker: Digest,
    pub artifact: Digest,
    pub app_workload: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bootstrap {
    pub authority: Digest,
    pub scope: AuthorityScope,
    // Firestore's signed integer format cannot represent the complete u64 domain.
    // Both numeric identities and epochs use canonical decimal strings on wire.
    pub project_number: String,
    pub database_uid: String,
    pub record_incarnation: Digest,
    pub key_set: Digest,
    pub policy: Digest,
    pub controller_role: Digest,
    pub create_operation: Digest,
    pub manifest: Manifest,
}

impl Bootstrap {
    pub(super) fn validate_selection(&self, selection: &EpochStore) -> Result<()> {
        selection.validate()?;
        let EpochProvider::FirestoreNativeV1 {
            project_number,
            database_uid,
            ..
        } = &selection.provider;
        ensure!(
            self.authority == selection.authority_key()?
                && self.scope == selection.scope
                && self.project_number == project_number.to_string()
                && self.database_uid == *database_uid
                && self.key_set == selection.key_set,
            "security_epoch_selection_mismatch"
        );
        ensure!(
            !self.manifest.provider_volume_uid.is_empty()
                && self.manifest.provider_volume_uid.len() <= 512
                && self
                    .manifest
                    .provider_volume_uid
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic()),
            "security_epoch_volume_identity"
        );
        Ok(())
    }
}

/// This describes a candidate. Its process incarnation is data received from a
/// different process, never a reconstruction of that process's native handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Holder {
    pub principal: Digest,
    pub pod_uid: String,
    pub process_incarnation: Digest,
    pub ephemeral_key: Digest,
}

impl Holder {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.pod_uid.len() == 36
                && self.pod_uid.bytes().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                }),
            "security_epoch_holder_identity"
        );
        Ok(())
    }
}

/// Provider timestamps are conditional-version tokens, not host clock samples.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct UpdateTime(String);

impl TryFrom<String> for UpdateTime {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let parsed =
            time::OffsetDateTime::parse(&value, &time::format_description::well_known::Rfc3339)?;
        ensure!(
            value.ends_with('Z') && parsed.nanosecond().is_multiple_of(1_000),
            "security_epoch_provider_version"
        );
        Ok(Self(value))
    }
}

impl From<UpdateTime> for String {
    fn from(value: UpdateTime) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Versions {
    pub root: UpdateTime,
    pub sentinel: UpdateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    CreateInitialAuthority {
        bootstrap: Bootstrap,
    },
    CompleteInitialFirstActivation {
        bootstrap: Bootstrap,
        operation: Digest,
        parent_receipt: Digest,
        before: Versions,
        holder: Holder,
    },
}

impl Request {
    pub(super) fn bootstrap(&self) -> &Bootstrap {
        match self {
            Self::CreateInitialAuthority { bootstrap }
            | Self::CompleteInitialFirstActivation { bootstrap, .. } => bootstrap,
        }
    }

    pub(super) fn operation(&self) -> &Digest {
        match self {
            Self::CreateInitialAuthority { bootstrap } => &bootstrap.create_operation,
            Self::CompleteInitialFirstActivation { operation, .. } => operation,
        }
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-external-epoch-request-v1", self))
    }

    pub(super) fn validate(&self, selection: &EpochStore) -> Result<()> {
        self.bootstrap().validate_selection(selection)?;
        if let Self::CompleteInitialFirstActivation {
            bootstrap,
            operation,
            parent_receipt,
            holder,
            ..
        } = self
        {
            ensure!(
                operation != &bootstrap.create_operation,
                "security_epoch_operation_reused"
            );
            let create = Self::CreateInitialAuthority {
                bootstrap: bootstrap.clone(),
            };
            ensure!(
                parent_receipt == &create.receipt()?.digest()?,
                "security_epoch_parent_receipt_mismatch"
            );
            holder.validate()?;
        }
        Ok(())
    }

    pub(super) fn records(&self) -> Result<(AuthorityRecord, SentinelRecord)> {
        let phase = match self {
            Self::CreateInitialAuthority { .. } => Phase::PendingFirstHolder,
            Self::CompleteInitialFirstActivation {
                operation,
                parent_receipt,
                before,
                holder,
                ..
            } => Phase::ActiveFirstHolder {
                completion: Box::new(Completion {
                    operation: operation.clone(),
                    request: self.digest()?,
                    parent_receipt: parent_receipt.clone(),
                    before: before.clone(),
                    holder: holder.clone(),
                }),
            },
        };
        let bootstrap = self.bootstrap().clone();
        let epoch = SecurityEpoch::try_from(1)?;
        Ok((
            AuthorityRecord {
                format: AuthorityFormat::Day2CredentialAuthorityV1,
                bootstrap: bootstrap.clone(),
                epoch,
                phase: phase.clone(),
            },
            SentinelRecord {
                format: SentinelFormat::Day2CredentialBootstrapV1,
                bootstrap,
                initial_epoch: epoch,
                phase,
            },
        ))
    }

    pub(super) fn receipt(&self) -> Result<Receipt> {
        let (root, sentinel) = self.records()?;
        Ok(Receipt {
            format: ReceiptFormat::Day2CredentialEpochReceiptV1,
            request: self.clone(),
            request_digest: self.digest()?,
            after_root: Digest::of(&root)?,
            after_sentinel: Digest::of(&sentinel)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Completion {
    pub operation: Digest,
    pub request: Digest,
    pub parent_receipt: Digest,
    pub before: Versions,
    pub holder: Holder,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Phase {
    PendingFirstHolder,
    ActiveFirstHolder { completion: Box<Completion> },
}

impl<'de> Deserialize<'de> for Phase {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Serde's internally tagged UNIT visitor ignores extras. Also require a
        // map here: a sequence must not become another spelling of a state.
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Phase;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a closed external epoch phase map")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Phase, A::Error> {
                use serde::de::Error;
                let mut phase = None;
                let mut completion = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "phase" => {
                            if phase.is_some() {
                                return Err(A::Error::duplicate_field("phase"));
                            }
                            phase = Some(map.next_value::<String>()?);
                        }
                        "completion" => {
                            if completion.is_some() {
                                return Err(A::Error::duplicate_field("completion"));
                            }
                            completion = Some(map.next_value::<serde_json::Value>()?);
                        }
                        _ => return Err(A::Error::unknown_field(&key, &["phase", "completion"])),
                    }
                }
                match (phase.as_deref(), completion) {
                    (Some("pending_first_holder"), None) => Ok(Phase::PendingFirstHolder),
                    (Some("active_first_holder"), Some(value)) if value.is_object() => {
                        Ok(Phase::ActiveFirstHolder {
                            completion: serde_json::from_value(value).map_err(A::Error::custom)?,
                        })
                    }
                    _ => Err(A::Error::custom("invalid closed external epoch phase")),
                }
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AuthorityFormat {
    Day2CredentialAuthorityV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SentinelFormat {
    Day2CredentialBootstrapV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReceiptFormat {
    Day2CredentialEpochReceiptV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityRecord {
    format: AuthorityFormat,
    pub bootstrap: Bootstrap,
    #[serde(with = "epoch_decimal")]
    pub epoch: SecurityEpoch,
    pub phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SentinelRecord {
    format: SentinelFormat,
    pub bootstrap: Bootstrap,
    #[serde(with = "epoch_decimal")]
    pub initial_epoch: SecurityEpoch,
    pub phase: Phase,
}

mod epoch_decimal {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(
        value: &SecurityEpoch,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.value().to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SecurityEpoch, D::Error> {
        let value = String::deserialize(deserializer)?;
        let epoch = value
            .parse::<u64>()
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(D::Error::custom)?;
        if value != SecurityEpoch::value(epoch).to_string() {
            return Err(D::Error::custom("noncanonical security epoch"));
        }
        Ok(epoch)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    format: ReceiptFormat,
    pub request: Request,
    pub request_digest: Digest,
    pub after_root: Digest,
    pub after_sentinel: Digest,
}

impl Receipt {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-external-epoch-receipt-v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Versioned<T> {
    pub value: T,
    pub version: UpdateTime,
}

/// Only a coherent provider read may supply this data. Even then it is not
/// current execution authority; dispatch needs a separate native stage context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub root: Option<Versioned<AuthorityRecord>>,
    pub sentinel: Option<Versioned<SentinelRecord>>,
    pub create: Option<Versioned<Receipt>>,
    pub activate: Option<Versioned<Receipt>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    NotApplied,
    Applied(Box<Receipt>),
}

/// Reconciliation does not authorize another send. A caller must re-acquire the
/// exact stage's native context and consume a new journal dispatch guard. Only
/// the identical conditional request can be retried after an ambiguous send.
pub(super) fn reconcile(
    selection: &EpochStore,
    request: &Request,
    snapshot: &Snapshot,
) -> Result<Outcome> {
    request.validate(selection)?;
    let create = Request::CreateInitialAuthority {
        bootstrap: request.bootstrap().clone(),
    };
    let all_absent = snapshot.root.is_none()
        && snapshot.sentinel.is_none()
        && snapshot.create.is_none()
        && snapshot.activate.is_none();
    if all_absent {
        ensure!(
            matches!(request, Request::CreateInitialAuthority { .. }),
            "security_epoch_initial_authority_missing"
        );
        return Ok(Outcome::NotApplied);
    }
    let root = snapshot
        .root
        .as_ref()
        .context("security_epoch_partial_state")?;
    let sentinel = snapshot
        .sentinel
        .as_ref()
        .context("security_epoch_partial_state")?;
    let create_receipt = snapshot
        .create
        .as_ref()
        .context("security_epoch_partial_state")?;
    ensure!(
        create_receipt.value == create.receipt()?,
        "security_epoch_create_receipt_mismatch"
    );
    let state_request = match &root.value.phase {
        Phase::PendingFirstHolder => {
            ensure!(snapshot.activate.is_none(), "security_epoch_partial_state");
            create.clone()
        }
        Phase::ActiveFirstHolder { .. } => {
            let receipt = &snapshot
                .activate
                .as_ref()
                .context("security_epoch_activation_receipt_missing")?
                .value;
            ensure!(
                matches!(
                    receipt.request,
                    Request::CompleteInitialFirstActivation { .. }
                ) && receipt.request.bootstrap() == create.bootstrap(),
                "security_epoch_activation_receipt_mismatch"
            );
            receipt.request.validate(selection)?;
            ensure!(
                receipt == &receipt.request.receipt()?,
                "security_epoch_activation_receipt_mismatch"
            );
            receipt.request.clone()
        }
    };
    let (expected_root, expected_sentinel) = state_request.records()?;
    ensure!(
        root.value == expected_root && sentinel.value == expected_sentinel,
        "security_epoch_root_sentinel_mismatch"
    );
    match request {
        Request::CreateInitialAuthority { .. } => {
            Ok(Outcome::Applied(Box::new(create_receipt.value.clone())))
        }
        Request::CompleteInitialFirstActivation { before, .. } => match root.value.phase {
            Phase::PendingFirstHolder => {
                ensure!(
                    before.root == root.version && before.sentinel == sentinel.version,
                    "security_epoch_conditional_version_changed"
                );
                Ok(Outcome::NotApplied)
            }
            Phase::ActiveFirstHolder { .. } => {
                ensure!(
                    state_request == *request,
                    "security_epoch_conflicting_holder"
                );
                Ok(Outcome::Applied(Box::new(request.receipt()?)))
            }
        },
    }
}
