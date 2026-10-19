use crate::security_epoch::native_enrollment::policy::{EnrollmentPolicy, NativeRole, decode_key};
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
    pub public_key: String,
    pub challenge: Digest,
    pub request: Digest,
    pub process: ProcessData,
    pub runtime: RuntimeBinding,
    pub origin_ns: u64,
    pub deadline_ns: u64,
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
    StageHello {
        policy: Digest,
        role: NativeRole,
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
        public_key: String,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    StageGrant {
        certificate: IssuerCertificate,
        stage: SignedStage,
    },
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

    pub(super) fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|_| anyhow::anyhow!("native_enrollment_root_key"))?;
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
                && self.data.root_version == policy.root_version
                && self.data.process.code == policy.issuer_code
                && self.data.provisioner.code == policy.provisioner_code,
            "native_enrollment_issuer_selection"
        );
        decode_key(&self.data.public_key)?;
        verify(
            &policy.root_public_key,
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
    crate::json::decode(bytes)
}
