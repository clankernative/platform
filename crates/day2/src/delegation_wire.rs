//! Host-only signed query envelope for a separate application workload.
//!
//! A workload signature binds the request to one calling app. A separate
//! platform issuer proof binds its exact bytes to verified origin evidence;
//! neither signature replaces the receiving app's own policy check.

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
const ISSUER_DOMAIN: &[u8] = b"day2-app-issuer-v1\0";
const MAX_ISSUED_WIRE_BYTES: usize = 200_000;

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub version: u32,
    pub purpose: crate::delegation::Purpose,
    pub source_epoch: String,
    pub budget: u32,
    pub delivery: Option<crate::delegation_commands::Delivery>,
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

pub struct VerifiedQuery(Query, Option<IssuerClaims>);

impl VerifiedQuery {
    pub fn query(&self) -> &Query {
        &self.0
    }

    pub(crate) fn origin(&self) -> Result<&IssuerClaims> {
        self.1
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("delegated_origin_evidence_missing"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerClaims {
    pub version: u32,
    pub issuer: String,
    pub key_id: String,
    pub source: Scope,
    pub target: Scope,
    pub root: String,
    pub principal: String,
    pub subject_digest: String,
    pub workload_email: String,
    pub workload_subject_digest: String,
    pub actor: String,
    pub origin: String,
    pub query_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedIssuer {
    key_id: String,
    payload: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuedQuery {
    workload: String,
    issuer: String,
}

/// Untrusted routing hint only. The selected receiver must still verify the
/// exact raw envelope, IAP identity and both signatures before admission.
pub fn claimed_source(wire: &[u8]) -> Result<Scope> {
    Ok(claimed_query(wire)?.source)
}

/// Scheduling hint only. Verification uses these same exact signed bytes;
/// selecting the reserved read pool never grants authority or changes purpose.
pub(crate) fn claimed_purpose(wire: &[u8]) -> Result<crate::delegation::Purpose> {
    Ok(claimed_query(wire)?.purpose)
}

fn claimed_query(wire: &[u8]) -> Result<Query> {
    ensure!(
        wire.len() <= MAX_ISSUED_WIRE_BYTES,
        "app_call_wire_too_large"
    );
    let issued: IssuedQuery = crate::json::decode(wire)?;
    let signed: Signed = crate::json::decode(&URL_SAFE_NO_PAD.decode(issued.workload)?)?;
    let query: Query = crate::json::decode(&URL_SAFE_NO_PAD.decode(signed.payload)?)?;
    Ok(query)
}

pub struct IssuerSigner {
    issuer: String,
    key_id: String,
    key: signature::Ed25519KeyPair,
}

impl IssuerSigner {
    pub fn from_pkcs8(issuer: &str, key_id: &str, pkcs8: &[u8]) -> Result<Self> {
        valid_key_id(issuer)?;
        valid_key_id(key_id)?;
        let key = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| anyhow::anyhow!("invalid_app_issuer_signing_key"))?;
        Ok(Self {
            issuer: issuer.to_owned(),
            key_id: key_id.to_owned(),
            key,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }

    pub fn sign(&self, claims: &IssuerClaims) -> Result<Vec<u8>> {
        ensure!(
            claims.issuer == self.issuer && claims.key_id == self.key_id,
            "app_issuer_identity_changed"
        );
        let payload = serde_json::to_vec(claims)?;
        ensure!(payload.len() <= 16_384, "app_issuer_proof_too_large");
        let mut signed = Vec::with_capacity(ISSUER_DOMAIN.len() + payload.len());
        signed.extend_from_slice(ISSUER_DOMAIN);
        signed.extend_from_slice(&payload);
        Ok(serde_json::to_vec(&SignedIssuer {
            key_id: self.key_id.clone(),
            payload: URL_SAFE_NO_PAD.encode(payload),
            signature: URL_SAFE_NO_PAD.encode(self.key.sign(&signed).as_ref()),
        })?)
    }
}

pub fn issued_query(workload: &[u8], issuer: &[u8]) -> Result<Vec<u8>> {
    let wire = serde_json::to_vec(&IssuedQuery {
        workload: URL_SAFE_NO_PAD.encode(workload),
        issuer: URL_SAFE_NO_PAD.encode(issuer),
    })?;
    ensure!(
        wire.len() <= MAX_ISSUED_WIRE_BYTES,
        "app_call_wire_too_large"
    );
    Ok(wire)
}

pub struct IssuerVerifier {
    issuer: String,
    keys: BTreeMap<String, Vec<u8>>,
    target_audience: String,
}

impl IssuerVerifier {
    pub fn new(
        issuer: &str,
        keys: BTreeMap<String, Vec<u8>>,
        target_audience: &str,
    ) -> Result<Self> {
        valid_key_id(issuer)?;
        ensure!(
            !keys.is_empty() && keys.len() <= 64 && !target_audience.is_empty(),
            "invalid_app_issuer_key_set"
        );
        for (key_id, key) in &keys {
            valid_key_id(key_id)?;
            ensure!(key.len() == 32, "invalid_app_issuer_public_key");
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            keys,
            target_audience: target_audience.to_owned(),
        })
    }

    pub fn verify(
        &self,
        wire: &[u8],
        at: i64,
        gate: &crate::iap::Workload,
        workload_verifier: &Verifier,
    ) -> Result<VerifiedQuery> {
        ensure!(
            wire.len() <= MAX_ISSUED_WIRE_BYTES,
            "invalid_app_issuer_proof"
        );
        let issued: IssuedQuery = crate::json::decode(wire)?;
        let workload = URL_SAFE_NO_PAD.decode(&issued.workload)?;
        let issuer = URL_SAFE_NO_PAD.decode(&issued.issuer)?;
        let verified = workload_verifier.verify(&workload, at)?;
        let signed: SignedIssuer = crate::json::decode(&issuer)?;
        valid_key_id(&signed.key_id)?;
        let key = self
            .keys
            .get(&signed.key_id)
            .ok_or_else(|| anyhow::anyhow!("invalid_app_issuer_proof"))?;
        let payload = URL_SAFE_NO_PAD.decode(&signed.payload)?;
        ensure!(payload.len() <= 16_384, "invalid_app_issuer_proof");
        let signature = URL_SAFE_NO_PAD.decode(&signed.signature)?;
        let mut message = Vec::with_capacity(ISSUER_DOMAIN.len() + payload.len());
        message.extend_from_slice(ISSUER_DOMAIN);
        message.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(&message, &signature)
            .map_err(|_| anyhow::anyhow!("invalid_app_issuer_proof"))?;
        let claims: IssuerClaims = crate::json::decode(&payload)?;
        let query = verified.query();
        ensure!(
            claims.version == 1
                && claims.issuer == self.issuer
                && claims.key_id == signed.key_id
                && claims.source == query.source
                && claims.target == query.target
                && claims.actor == query.actor
                && claims.origin == query.origin
                && !claims.root.is_empty()
                && !claims.principal.is_empty()
                && claims.subject_digest.starts_with("sha256:")
                && claims.query_digest == crate::digest(&workload)
                && claims.issued_at <= at
                && at < claims.expires_at
                && claims.expires_at <= query.expires_at
                && claims.issued_at >= query.issued_at
                && gate.audience() == self.target_audience
                && gate.email() == claims.workload_email
                && crate::digest(gate.subject().as_bytes()) == claims.workload_subject_digest,
            "invalid_app_issuer_proof"
        );
        Ok(VerifiedQuery(verified.0, Some(claims)))
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
        Ok(VerifiedQuery(query, None))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_key_overlap_retires_old_proofs_without_widening_scope() -> Result<()> {
        let source = Scope {
            installation: "alpha".into(),
            environment: "test".into(),
            app: "middle".into(),
        };
        let target = Scope {
            app: "stock".into(),
            ..source.clone()
        };
        let query = Query {
            version: 1,
            purpose: crate::delegation::Purpose::Query,
            source_epoch: crate::digest(b"epoch"),
            budget: 14,
            delivery: None,
            source: source.clone(),
            target,
            operation: "stock.available".into(),
            schema_digest: crate::digest(b"schema"),
            contract_digest: Some(crate::digest(b"contract")),
            input: serde_json::json!({}),
            actor: "alice@example.com".into(),
            origin: "middle-root".into(),
            step: "ob_middle_0".into(),
            chain: "entry".into(),
            now: 100,
            issued_at: 100,
            expires_at: 130,
            activation: Digest::new(b"active"),
            generation: 1,
            serving: Value::Null,
        };
        let old = signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("test key"))?;
        let new = signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("test key"))?;
        let old = Signer::from_pkcs8("old", old.as_ref())?;
        let new = Signer::from_pkcs8("new", new.as_ref())?;
        let verifier = |include_old: bool| -> Result<Verifier> {
            let mut keys = BTreeMap::from([(
                "new".into(),
                TrustedKey {
                    source: source.clone(),
                    public_key: new.public_key(),
                },
            )]);
            if include_old {
                keys.insert(
                    "old".into(),
                    TrustedKey {
                        source: source.clone(),
                        public_key: old.public_key(),
                    },
                );
            }
            Verifier::new(keys)
        };
        let old_wire = old.sign(&query)?;
        let new_wire = new.sign(&query)?;
        let overlap = verifier(true)?;
        assert!(overlap.verify(&old_wire, 101).is_ok());
        assert!(overlap.verify(&new_wire, 101).is_ok());
        let retired = verifier(false)?;
        assert!(retired.verify(&old_wire, 101).is_err());
        assert!(retired.verify(&new_wire, 101).is_ok());
        assert!(retired.verify(&new_wire, 130).is_err());
        let mut substituted = query;
        substituted.source.app = "entry".into();
        assert!(retired.verify(&new.sign(&substituted)?, 101).is_err());
        Ok(())
    }
}
