use crate::security_epoch::native_enrollment::{
    NativeRole,
    policy::{EnrollmentPolicy, decode_key},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc};

pub(super) const MAX_PACKET: usize = 8192;

/// Historical process binding, never an owning process handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessData {
    pub process: u32,
    pub start_ticks: u64,
    pub code: Digest,
    pub boot: String,
    pub namespaces: BTreeMap<String, (u64, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerData {
    pub policy: Digest,
    pub root_version: String,
    pub nonce: Digest,
    pub public_key: String,
    pub process: ProcessData,
    pub provisioner: ProcessData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerCertificate {
    pub data: IssuerData,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageData {
    pub issuer: Digest,
    pub policy: Digest,
    pub role: NativeRole,
    pub purpose: StagePurpose,
    pub public_key: String,
    pub challenge: Digest,
    pub request: Digest,
    pub process: ProcessData,
    pub runtime: RuntimeBinding,
    pub origin_ns: u64,
    pub deadline_ns: u64,
}

/// Signed closed stage purpose. Each producer and consumer requires its exact
/// purpose; a longer bootstrap/observation interval is never ordinary Current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum StagePurpose {
    CurrentRole,
    InitialFirstHolder,
    StorageBootstrap,
    StorageMetadataObservation,
}

impl StagePurpose {
    pub(super) fn limit(self) -> std::time::Duration {
        match self {
            Self::CurrentRole => std::time::Duration::from_secs(5),
            Self::InitialFirstHolder => {
                crate::security_epoch::native_clock::INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT
            }
            Self::StorageBootstrap => crate::security_epoch::native_clock::STORAGE_BOOTSTRAP_LIMIT,
            Self::StorageMetadataObservation => {
                crate::security_epoch::native_clock::STORAGE_METADATA_OBSERVATION_LIMIT
            }
        }
    }

    pub(super) fn require_role(self, role: NativeRole) -> Result<()> {
        let allowed = match self {
            Self::CurrentRole => true,
            Self::InitialFirstHolder | Self::StorageBootstrap => {
                matches!(role, NativeRole::EpochController | NativeRole::AppHost)
            }
            Self::StorageMetadataObservation => role == NativeRole::EpochController,
        };
        ensure!(allowed, "native_enrollment_stage_purpose_role");
        Ok(())
    }

    /// DATA comparison used by the actual native stage gate. Success here
    /// neither constructs nor checks a native stage, clock or permission.
    pub(super) fn require_exact(self, expected: Self) -> Result<()> {
        ensure!(self == expected, "native_enrollment_stage_purpose_changed");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeBinding {
    pub container: crate::security_epoch::runtime_profile::ContainerFacts,
    pub node_uid: String,
    pub boot: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedStage {
    pub data: StageData,
    pub signature: String,
}

/// Selection DATA for one irreversible issuer-closure attempt. The real
/// requester still needs its retained role key, native message process and
/// original. A signed statement alone is NOT business-rights Stop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FreezeSelection {
    pub admin_binding: Digest,
    pub operation: Digest,
    pub fenced_root: Digest,
    pub app: super::storage_peer_wire::StageStatement,
    pub controller: super::storage_peer_wire::StageStatement,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenIssuance {
    pub selection: FreezeSelection,
    pub policy: Digest,
    pub issuer: Digest,
    pub cohort: Digest,
    pub request: Digest,
    pub challenge: Digest,
}

impl FreezeSelection {
    pub(super) fn history_digest(&self) -> Result<Digest> {
        let mut members = [&self.app, &self.controller];
        members.sort_by_key(|s| {
            (
                s.stage.data.process.process,
                s.stage.data.process.start_ticks,
                s.stage.data.role,
            )
        });
        Digest::of(&(
            "day2-native-issuer-cohort-v1",
            members.map(|s| {
                (
                    &s.stage.data.public_key,
                    &s.stage.data.process,
                    &s.stage.data.runtime,
                    s.stage.data.role,
                )
            }),
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Packet {
    BirthChallenge {
        policy: Digest,
        nonce: Digest,
    },
    BirthKey {
        nonce: Digest,
        public_key: String,
        signature: String,
    },
    BirthGrant {
        certificate: IssuerCertificate,
    },
    FreezeHello {
        selection: Box<FreezeSelection>,
        request: Digest,
    },
    FreezeNonce {
        request: Digest,
        challenge: Digest,
    },
    FreezeBind {
        selection: Box<FreezeSelection>,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    FreezeGrant {
        statement: Box<FrozenIssuance>,
        signature: String,
    },
    StageHello {
        policy: Digest,
        role: NativeRole,
        purpose: StagePurpose,
        public_key: String,
        request: Digest,
    },
    StageNonce {
        request: Digest,
        challenge: Digest,
    },
    StageBind {
        policy: Digest,
        role: NativeRole,
        purpose: StagePurpose,
        public_key: String,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    StageGrant {
        certificate: IssuerCertificate,
        stage: Box<SignedStage>,
    },
}

#[cfg(target_os = "linux")]
impl Packet {
    pub(super) fn frame(&self) -> Option<super::handshake::Frame> {
        use super::handshake::{Frame, Protocol, Step};
        let step = match self {
            Self::StageHello { .. } | Self::FreezeHello { .. } => Step::Hello,
            Self::StageNonce { .. } | Self::FreezeNonce { .. } => Step::Challenge,
            Self::StageBind { .. } | Self::FreezeBind { .. } => Step::Bind,
            Self::StageGrant { .. } | Self::FreezeGrant { .. } => Step::Grant,
            Self::BirthChallenge { .. } | Self::BirthKey { .. } | Self::BirthGrant { .. } => {
                return None;
            }
        };
        Some(Frame {
            protocol: Protocol::Enrollment,
            step,
            sequence: None,
        })
    }
}

/// Key possession belongs to one native executor. It is never a wire value.
pub(super) struct KeyOwner {
    key: Ed25519KeyPair,
    local: PhantomData<Rc<()>>,
}

impl KeyOwner {
    pub(super) fn generate() -> Result<Self> {
        let mut seed = zeroize::Zeroizing::new([0_u8; 32]);
        crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, seed.as_mut())?;
        let key = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| anyhow::anyhow!("native_enrollment_key_generation"))?;
        Ok(Self {
            key,
            local: PhantomData,
        })
    }

    pub(super) fn public(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref())
    }

    pub(super) fn sign<T: Serialize>(&self, purpose: &str, value: &T) -> Result<String> {
        let bytes = frame(purpose, value)?;
        Ok(URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).as_ref()))
    }
}

fn frame<T: Serialize>(purpose: &str, value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&("day2-native-enrollment-v1", purpose, value))?;
    ensure!(bytes.len() <= MAX_PACKET, "native_enrollment_frame_bound");
    Ok(bytes)
}

pub(super) fn issuer_birth_frame(data: &IssuerData) -> Result<Vec<u8>> {
    frame("issuer-birth", data)
}

pub(super) fn verify<T: Serialize>(
    key: &str,
    purpose: &str,
    value: &T,
    encoded: &str,
) -> Result<()> {
    let key = decode_key(key)?;
    ensure!(encoded.len() == 86, "native_enrollment_signature_encoding");
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    ensure!(
        bytes.len() == 64 && URL_SAFE_NO_PAD.encode(&bytes) == encoded,
        "native_enrollment_signature_encoding"
    );
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&frame(purpose, value)?, &bytes)
        .map_err(|_| anyhow::anyhow!("native_enrollment_signature_refused"))
}

impl IssuerCertificate {
    pub(super) fn verify(&self, policy: &EnrollmentPolicy) -> Result<()> {
        ensure!(
            self.data.policy == policy.digest()?
                && self.data.root_version == policy.root.version
                && self.data.process.code == policy.issuer_code
                && self.data.provisioner.code == policy.provisioner_code,
            "native_enrollment_issuer_selection"
        );
        decode_key(&self.data.public_key)?;
        verify(
            &policy.root.public_key,
            "issuer-birth",
            &self.data,
            &self.signature,
        )
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-native-issuer-certificate-v1", self))
    }
}

pub(super) fn nonce(purpose: &str) -> Result<Digest> {
    let mut bytes = [0_u8; 32];
    crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, &mut bytes)?;
    Digest::of(&("day2-native-enrollment-nonce-v1", purpose, bytes))
}

pub(super) fn decode(bytes: &[u8]) -> Result<Packet> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PACKET,
        "native_enrollment_packet_bound"
    );
    let value: serde_json::Value = crate::json::decode(bytes)?;
    ensure!(
        value.is_object(),
        "native_enrollment_packet_object_required"
    );
    let selection = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("freeze_hello" | "freeze_bind") => Some("/selection"),
        Some("freeze_grant") => {
            ensure!(
                value
                    .pointer("/statement")
                    .is_some_and(serde_json::Value::is_object),
                "native_enrollment_freeze_object_required"
            );
            Some("/statement/selection")
        }
        _ => None,
    };
    if let Some(path) = selection {
        ensure!(
            value
                .pointer(path)
                .is_some_and(serde_json::Value::is_object),
            "native_enrollment_freeze_object_required"
        );
        for role in ["app", "controller"] {
            super::storage_peer_wire::require_stage_objects(&value, &format!("{path}/{role}"))?;
        }
    }
    Ok(serde_json::from_value(value)?)
}
