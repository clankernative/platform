//! Host-only signed query envelope for a separate application workload.
//!
//! The signature authenticates a key bound by the host to one source workload;
//! it does not authorize the inherited actor. Only the native caller host may
//! construct requests, and the receiving app still checks its own policy.

use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_WIRE_BYTES: usize = 131_072;
const MAX_PAYLOAD_BYTES: usize = 70_000;
const DOMAIN: &[u8] = b"day2-app-query-v1\0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub installation: String,
    pub environment: String,
    pub app: String,
}

impl Scope {
    pub fn from_runtime(runtime: &crate::store::Runtime) -> Result<Self> {
        let instance = crate::artifact::Instance::load(runtime.instance_path())?;
        Ok(Self {
            installation: instance.installation,
            environment: instance.environment,
            app: runtime.app().to_owned(),
        })
    }

    pub fn same_installation(&self, other: &Self) -> bool {
        self.installation == other.installation && self.environment == other.environment
    }

    pub fn runtime_scope(&self) -> String {
        format!("{}/{}/{}", self.installation, self.environment, self.app)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub version: u32,
    pub source: Scope,
    pub target: Scope,
    pub operation: String,
    pub schema_digest: String,
    pub contract_digest: Option<String>,
    pub input: Value,
    pub actor: String,
    pub origin: String,
    pub step: String,
    pub chain: String,
    pub now: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub activation: Digest,
    pub generation: u64,
    /// The provider observation fenced around dispatch. The receiver's control
    /// adapter must decode and compare this with its own fresh observation.
    pub serving: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    key_id: String,
    payload: String,
    signature: String,
}

pub struct Signer {
    key_id: String,
    key: signature::Ed25519KeyPair,
}

impl Signer {
    pub fn from_pkcs8(key_id: &str, pkcs8: &[u8]) -> Result<Self> {
        valid_key_id(key_id)?;
        let key = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| anyhow::anyhow!("invalid_app_call_signing_key"))?;
        Ok(Self {
            key_id: key_id.to_owned(),
            key,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }

    pub fn sign(&self, query: &Query) -> Result<Vec<u8>> {
        let payload = serde_json::to_vec(query)?;
        ensure!(
            payload.len() <= MAX_PAYLOAD_BYTES,
            "app_call_payload_too_large"
        );
        let mut signed = Vec::with_capacity(DOMAIN.len() + payload.len());
        signed.extend_from_slice(DOMAIN);
        signed.extend_from_slice(&payload);
        let signature = self.key.sign(&signed);
        Ok(serde_json::to_vec(&Signed {
            key_id: self.key_id.clone(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(signature.as_ref()),
        })?)
    }
}

pub struct TrustedKey {
    pub source: Scope,
    pub public_key: Vec<u8>,
}

pub struct Verifier {
    keys: BTreeMap<String, TrustedKey>,
}

pub struct VerifiedQuery(Query);

impl VerifiedQuery {
    pub fn query(&self) -> &Query {
        &self.0
    }
}

impl Verifier {
    pub fn new(keys: BTreeMap<String, TrustedKey>) -> Result<Self> {
        ensure!(
            !keys.is_empty() && keys.len() <= 64,
            "invalid_app_call_key_set"
        );
        for (key_id, key) in &keys {
            valid_key_id(key_id)?;
            ensure!(key.public_key.len() == 32, "invalid_app_call_public_key");
            ensure!(
                !key.source.installation.is_empty()
                    && !key.source.environment.is_empty()
                    && !key.source.app.is_empty(),
                "invalid_app_call_source"
            );
        }
        Ok(Self { keys })
    }

    pub fn verify(&self, wire: &[u8], at: i64) -> Result<VerifiedQuery> {
        ensure!(wire.len() <= MAX_WIRE_BYTES, "invalid_app_call_proof");
        let signed: Signed = crate::json::decode(wire)?;
        valid_key_id(&signed.key_id)?;
        let trusted = self
            .keys
            .get(&signed.key_id)
            .ok_or_else(|| anyhow::anyhow!("invalid_app_call_proof"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(&signed.payload)
            .map_err(|_| anyhow::anyhow!("invalid_app_call_proof"))?;
        ensure!(payload.len() <= MAX_PAYLOAD_BYTES, "invalid_app_call_proof");
        let signature = URL_SAFE_NO_PAD
            .decode(&signed.signature)
            .map_err(|_| anyhow::anyhow!("invalid_app_call_proof"))?;
        let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, &trusted.public_key)
            .verify(&message, &signature)
            .map_err(|_| anyhow::anyhow!("invalid_app_call_proof"))?;
        let query: Query = crate::json::decode(&payload)?;
        ensure!(
            query.version == 1
                && query.source == trusted.source
                && query.source.same_installation(&query.target)
                && query.source.app != query.target.app
                && query.issued_at <= at
                && at < query.expires_at
                && query
                    .expires_at
                    .checked_sub(query.issued_at)
                    .is_some_and(|lifetime| lifetime <= 60)
                && !query.origin.is_empty()
                && !query.step.is_empty(),
            "invalid_app_call_proof"
        );
        crate::authority::valid_actor(&query.actor)?;
        crate::delegation::extend(&query.chain, &query.source.app, &query.target.app)?;
        Ok(VerifiedQuery(query))
    }
}

fn valid_key_id(value: &str) -> Result<()> {
    ensure!(
        (1..=80).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
        "invalid_app_call_key_id"
    );
    Ok(())
}
