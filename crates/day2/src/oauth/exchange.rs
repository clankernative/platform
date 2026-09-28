//! Private outbound authorization-code exchange. The durable dispatch fence is
//! committed before a consuming permit reaches the reviewed transport adapter.
//! The adapter receives one bound request and cannot choose a different profile,
//! registration, callback or token endpoint through this API.

use super::account::{MappedHumanEvidence, ProviderAccount, VerifiedMappedAccount};
use super::connect::{self, CallbackBinding, ConnectIntent};
use super::custody::{self, PreparedTokenMaterial, PreparedVerifier};
use super::profiles::{AccountBindingEvidence, OutboundQualification, ValidatedTokenResponse};
use anyhow::{Result, ensure};
use day2_capabilities::oauth::{ProviderCallbackRef, ProviderIssuerRef};
use day2_capabilities::{BindingRef, Digest};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExchangeBinding {
    pub(super) instance: BindingRef,
    pub(super) profile: BindingRef,
    pub(super) adapter: BindingRef,
    pub(super) issuer: ProviderIssuerRef,
    pub(super) issuer_url: String,
    pub(super) registration: BindingRef,
    pub(super) callback: ProviderCallbackRef,
    pub(super) callback_url: String,
    pub(super) token_endpoint: String,
    pub(super) client_credential: BindingRef,
    pub(super) custody: BindingRef,
    #[serde(default)]
    pub(super) account_evidence: Option<Digest>,
    pub(super) code_ref: String,
    pub(super) verifier_ref: String,
    pub(super) token_slot_ref: String,
    pub(super) code_challenge: String,
}

impl ExchangeBinding {
    fn derive(input: &OutboundQualification<'_>, code_challenge: &str) -> Result<Self> {
        ensure!(
            code_challenge.len() == 43
                && code_challenge
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "invalid PKCE S256 challenge"
        );
        let registration = &input.instance.registration;
        let code_ref = Digest::of(&(
            "oauth-private-code-ref-v1",
            &input.intent.attempt,
            &input.intent.slot,
            input.binding.state_hash(),
        ))?;
        let verifier_ref = Digest::of(&(
            "oauth-private-pkce-ref-v1",
            &input.intent.attempt,
            &input.permission.profile,
            &registration.registration,
            input.binding.state_hash(),
        ))?;
        let token_slot_ref = Digest::of(&(
            "oauth-private-token-slot-v1",
            &input.intent.slot,
            input.intent.proposed_generation,
            &input.instance.custody,
        ))?;
        Ok(Self {
            instance: input.instance.instance.clone(),
            profile: input.permission.profile.clone(),
            adapter: input.reviewed.adapter.clone(),
            issuer: input.reviewed.issuer.clone(),
            issuer_url: input.reviewed.issuer_url.clone(),
            registration: registration.registration.clone(),
            callback: registration.callback.clone(),
            callback_url: registration.callback_url.clone(),
            token_endpoint: input.reviewed.token_endpoint.clone(),
            client_credential: registration.client_credential.clone(),
            custody: input.instance.custody.clone(),
            account_evidence: match &input.instance.account {
                AccountBindingEvidence::MappedHuman { .. } => None,
                _ => Some(Digest::of(&input.instance.account)?),
            },
            code_ref: code_ref.as_str().to_owned(),
            verifier_ref: verifier_ref.as_str().to_owned(),
            token_slot_ref: token_slot_ref.as_str().to_owned(),
            code_challenge: code_challenge.to_owned(),
        })
    }

    pub(super) fn matches_current(&self, input: &OutboundQualification<'_>) -> Result<bool> {
        Ok(self == &Self::derive(input, &self.code_challenge)?)
    }

    pub(super) fn verifier_ref(&self) -> &str {
        &self.verifier_ref
    }

    pub(super) fn token_slot_ref(&self) -> &str {
        &self.token_slot_ref
    }

    pub(super) fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

/// Encryption is completed before `begin`; the verifier ciphertext and both
/// durable bindings then enter one SQLite transaction.
pub(crate) struct PreparedAuthorization {
    qualified: super::profiles::QualifiedOutboundConnect,
    binding: ExchangeBinding,
    verifier: PreparedVerifier,
}

impl PreparedAuthorization {
    pub fn code_challenge(&self) -> &str {
        self.binding.code_challenge()
    }

    pub fn code_ref(&self) -> &str {
        &self.binding.code_ref
    }

    pub fn begin(self, db: &mut Connection, now: i64) -> Result<bool> {
        connect::begin_prepared(db, self, now)
    }

    pub(super) fn parts(
        &self,
    ) -> (
        &ConnectIntent,
        &CallbackBinding,
        &ExchangeBinding,
        &PreparedVerifier,
    ) {
        (
            self.qualified.intent(),
            self.qualified.binding(),
            &self.binding,
            &self.verifier,
        )
    }
}

pub(crate) fn prepare_authorization(
    input: OutboundQualification<'_>,
    key: &crate::managed_credentials::crypto::KeyLease,
    verifier: &str,
) -> Result<PreparedAuthorization> {
    let qualified = super::profiles::qualify_outbound_connect(
        input.intent,
        input.binding,
        input.requirement,
        input.permission,
        input.reviewed,
        input.instance,
    )?;
    let challenge = custody::pkce_challenge(verifier)?;
    let binding = ExchangeBinding::derive(&input, &challenge)?;
    let verifier = custody::prepare_verifier(key, qualified.intent(), &binding, verifier)?;
    Ok(PreparedAuthorization {
        qualified,
        binding,
        verifier,
    })
}

pub(super) fn install_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS oauth_exchange_schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS oauth_exchange_bindings (
            attempt TEXT PRIMARY KEY REFERENCES oauth_connect_attempts(attempt),
            binding TEXT NOT NULL
        );",
    )?;
    let mut versions = db.prepare("SELECT version FROM oauth_exchange_schema_version")?;
    let known = versions
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        known.is_empty() || known == [1],
        "unsupported OAuth exchange schema version"
    );
    if known.is_empty() {
        db.execute("INSERT INTO oauth_exchange_schema_version VALUES (1)", [])?;
    }
    Ok(())
}

pub(super) fn store_binding(
    tx: &rusqlite::Transaction<'_>,
    attempt: &str,
    binding: &ExchangeBinding,
) -> Result<()> {
    tx.execute(
        "INSERT INTO oauth_exchange_bindings (attempt, binding) VALUES (?1, ?2)",
        params![attempt, serde_json::to_string(binding)?],
    )?;
    Ok(())
}

pub(super) fn load_binding(db: &Connection, attempt: &str) -> Result<Option<ExchangeBinding>> {
    let encoded: Option<String> = db
        .query_row(
            "SELECT binding FROM oauth_exchange_bindings WHERE attempt = ?1",
            [attempt],
            |row| row.get(0),
        )
        .optional()?;
    encoded
        .map(|encoded| serde_json::from_str(&encoded).map_err(Into::into))
        .transpose()
}

/// One-use permit produced only after the exchange-may-have-been-sent CAS
/// commits. It cannot be cloned, serialized, or recovered after a crash.
pub struct ExchangeDispatchPermit {
    intent: ConnectIntent,
    binding: ExchangeBinding,
    code_ref: String,
}

pub struct ExchangeRequest<'a> {
    permit: &'a ExchangeDispatchPermit,
}

impl ExchangeRequest<'_> {
    pub fn attempt(&self) -> &str {
        &self.permit.intent.attempt
    }

    pub fn token_endpoint(&self) -> &str {
        &self.permit.binding.token_endpoint
    }

    pub fn code_ref(&self) -> &str {
        &self.permit.code_ref
    }

    pub(crate) fn load_code(
        &self,
        db: &Connection,
        key: &crate::managed_credentials::crypto::KeyLease,
    ) -> Result<String> {
        custody::load_code(db, key, &self.permit.intent, &self.permit.binding)
    }

    pub fn verifier_ref(&self) -> &str {
        self.permit.binding.verifier_ref()
    }

    pub(crate) fn load_verifier(
        &self,
        db: &Connection,
        key: &crate::managed_credentials::crypto::KeyLease,
    ) -> Result<String> {
        custody::load_verifier(db, key, &self.permit.intent, &self.permit.binding)
    }

    pub fn client_credential(&self) -> &BindingRef {
        &self.permit.binding.client_credential
    }

    pub fn callback_url(&self) -> &str {
        &self.permit.binding.callback_url
    }

    pub fn registration(&self) -> &BindingRef {
        &self.permit.binding.registration
    }

    pub fn profile(&self) -> &BindingRef {
        &self.permit.binding.profile
    }
}

pub struct TokenHttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

pub enum ExchangeObservation {
    Response(Box<PrivateExchangeResponse>),
    Uncertain(ExchangeUncertain),
}

pub struct ExchangeUncertain {
    attempt: String,
}

impl ExchangeUncertain {
    pub fn record(self, db: &Connection) -> Result<bool> {
        connect::mark_uncertain(db, &self.attempt)
    }
}

pub struct PrivateExchangeResponse {
    pub(super) intent: ConnectIntent,
    pub(super) binding: ExchangeBinding,
    pub(super) http: TokenHttpResponse,
}

impl ExchangeDispatchPermit {
    pub fn send(
        self,
        transport: impl FnOnce(&ExchangeRequest<'_>) -> Result<TokenHttpResponse>,
    ) -> ExchangeObservation {
        let result = transport(&ExchangeRequest { permit: &self });
        match result {
            Ok(http) => ExchangeObservation::Response(Box::new(PrivateExchangeResponse {
                intent: self.intent,
                binding: self.binding,
                http,
            })),
            Err(_) => ExchangeObservation::Uncertain(ExchangeUncertain {
                attempt: self.intent.attempt,
            }),
        }
    }
}

pub fn authorize_and_commit_qualified_exchange(
    db: &mut Connection,
    input: OutboundQualification<'_>,
    now: i64,
) -> Result<Option<ExchangeDispatchPermit>> {
    let qualified = super::profiles::qualify_outbound_connect(
        input.intent,
        input.binding,
        input.requirement,
        input.permission,
        input.reviewed,
        input.instance,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(ConnectIntent, String, String, String)> = tx
        .query_row(
            "SELECT a.slot, a.expected_generation, a.expected_epoch,
                    a.proposed_generation, a.owner, a.profile, a.registration,
                    a.callback, a.consent, a.expires_at, a.code_ref,
                    c.binding, e.binding
             FROM oauth_connect_attempts a
             JOIN oauth_callback_bindings c ON c.attempt = a.attempt
             JOIN oauth_exchange_bindings e ON e.attempt = a.attempt
             WHERE a.attempt = ?1 AND a.state = 'exchange_ready' AND a.expires_at > ?2",
            params![input.intent.attempt, now],
            |row| {
                Ok((
                    ConnectIntent {
                        attempt: input.intent.attempt.clone(),
                        slot: row.get(0)?,
                        expected_generation: row.get(1)?,
                        expected_epoch: row.get(2)?,
                        proposed_generation: row.get(3)?,
                        owner: row.get(4)?,
                        profile: row.get(5)?,
                        registration: row.get(6)?,
                        callback: row.get(7)?,
                        consent: row.get(8)?,
                        expires_at: row.get(9)?,
                    },
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_intent, code_ref, callback_json, exchange_json)) = row else {
        return Ok(None);
    };
    if stored_intent != *qualified.intent() || !connect::slot_matches(&tx, &stored_intent)? {
        return Ok(None);
    }
    let stored_callback: CallbackBinding = serde_json::from_str(&callback_json)?;
    let stored_exchange: ExchangeBinding = serde_json::from_str(&exchange_json)?;
    if &stored_callback != qualified.binding()
        || !stored_exchange.matches_current(&input)?
        || !custody::verifier_exists(&tx, &stored_intent, &stored_exchange)?
        || !custody::code_exists(&tx, &stored_intent, &stored_exchange)?
        || code_ref != stored_exchange.code_ref
    {
        return Ok(None);
    }
    let changed = tx.execute(
        "UPDATE oauth_connect_attempts SET state = 'exchange_may_have_been_sent'
         WHERE attempt = ?1 AND state = 'exchange_ready' AND expires_at > ?2",
        params![input.intent.attempt, now],
    )?;
    ensure!(changed == 1, "qualified exchange dispatch fence lost");
    tx.commit()?;
    Ok(Some(ExchangeDispatchPermit {
        intent: stored_intent,
        binding: stored_exchange,
        code_ref,
    }))
}

/// The callback parser owns the one-time claim; the code is encrypted in its
/// transaction using the current qualified attempt and exact exchange binding.
pub(crate) fn handle_qualified_callback(
    db: &mut Connection,
    input: OutboundQualification<'_>,
    ingress: super::outbound::CallbackIngress<'_>,
    key: &crate::managed_credentials::crypto::KeyLease,
) -> Result<super::outbound::CallbackOutcome> {
    let qualified = super::profiles::qualify_outbound_connect(
        input.intent,
        input.binding,
        input.requirement,
        input.permission,
        input.reviewed,
        input.instance,
    )?;
    ensure!(
        ingress.attempt == qualified.intent().attempt,
        "callback attempt mismatch"
    );
    let callback_code_ref = ingress.code_ref;
    super::outbound::handle_callback(db, ingress, |tx, code| {
        let binding = load_binding(tx, &qualified.intent().attempt)?
            .ok_or_else(|| anyhow::anyhow!("private exchange binding missing"))?;
        ensure!(
            binding.matches_current(&input)?,
            "callback exchange binding changed"
        );
        ensure!(
            callback_code_ref == binding.code_ref,
            "callback code reference mismatch"
        );
        let prepared = custody::prepare_code(key, qualified.intent(), &binding, code)?;
        custody::publish_code(tx, prepared)
    })
}

pub struct VerifiedMappedExchange {
    verified: VerifiedMappedAccount,
    binding: ExchangeBinding,
    tokens: ValidatedTokenResponse,
}

impl PrivateExchangeResponse {
    pub fn validate_mapped(
        self,
        input: OutboundQualification<'_>,
        mapping: &MappedHumanEvidence,
        observed: &ProviderAccount,
    ) -> Result<VerifiedMappedExchange> {
        let qualified = super::profiles::qualify_outbound_connect(
            input.intent,
            input.binding,
            input.requirement,
            input.permission,
            input.reviewed,
            input.instance,
        )?;
        ensure!(
            self.intent == *qualified.intent()
                && self.binding.matches_current(&input)?
                && observed.issuer == self.binding.issuer_url,
            "exchange response does not match the qualified account binding"
        );
        ensure!(
            self.http.status == 200 && self.http.content_type == "application/json",
            "unsupported provider token response status or content type"
        );
        let tokens = input
            .reviewed
            .protocol
            .validate_token_response(&self.http.body, input.permission)?;
        let verified = VerifiedMappedAccount::verify(
            &self.intent,
            input.requirement,
            input.permission,
            mapping,
            observed,
            &tokens,
        )?;
        Ok(VerifiedMappedExchange {
            verified,
            binding: self.binding,
            tokens,
        })
    }
}

pub struct PreparedMappedSettlement {
    verified: VerifiedMappedAccount,
    binding: ExchangeBinding,
    material: PreparedTokenMaterial,
}

impl VerifiedMappedExchange {
    pub(crate) fn prepare_tokens(
        self,
        key: &crate::managed_credentials::crypto::KeyLease,
    ) -> Result<PreparedMappedSettlement> {
        let material = custody::prepare_tokens(
            key,
            self.verified.intent(),
            self.verified.account(),
            &self.binding,
            self.tokens,
        )?;
        Ok(PreparedMappedSettlement {
            verified: self.verified,
            binding: self.binding,
            material,
        })
    }
}

pub fn settle_mapped(
    db: &mut Connection,
    prepared: PreparedMappedSettlement,
    current: OutboundQualification<'_>,
    current_mapping_revision: &Digest,
    now: i64,
) -> Result<bool> {
    let qualified = super::profiles::qualify_outbound_connect(
        current.intent,
        current.binding,
        current.requirement,
        current.permission,
        current.reviewed,
        current.instance,
    )?;
    if prepared.verified.intent() != qualified.intent()
        || !prepared.binding.matches_current(&current)?
    {
        return Ok(false);
    }
    connect::activate_mapped_bound(
        db,
        &prepared.verified,
        &prepared.binding,
        current_mapping_revision,
        now,
        |tx| custody::publish_tokens(tx, prepared.material),
    )
}
