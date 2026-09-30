//! Durable outbound authorization-code attempt state. The protocol adapter
//! validates callback parameters, identity and scopes before calling these CAS
//! transitions. Code and token bytes are held only by private custody.

use anyhow::{Result, ensure};
use day2_capabilities::BindingRef;
use day2_capabilities::Digest;
use day2_capabilities::oauth::{
    ProductReturnRef, ProviderCallbackRef, ProviderIssuerRef, SecurityOriginRef,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

const MAX_CONNECT_SECONDS: i64 = 900;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectIntent {
    pub attempt: String,
    pub slot: String,
    pub expected_generation: Option<i64>,
    pub expected_epoch: i64,
    pub proposed_generation: i64,
    pub owner: String,
    pub profile: String,
    pub registration: String,
    pub callback: String,
    pub consent: String,
    pub expires_at: i64,
}

/// Host-owned evidence for one authorization redirect. The raw state and
/// security session credential never enter SQLite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackBinding {
    state_hash: Digest,
    issuer: ProviderIssuerRef,
    issuer_url: String,
    security_origin: SecurityOriginRef,
    profile: BindingRef,
    callback: ProviderCallbackRef,
    binding_namespace: String,
    session: Digest,
    product_return: ProductReturnRef,
}

pub struct CallbackBindingSpec {
    pub issuer: ProviderIssuerRef,
    pub issuer_url: String,
    pub security_origin: SecurityOriginRef,
    pub profile: BindingRef,
    pub callback: ProviderCallbackRef,
    pub binding_namespace: String,
    pub session: Digest,
    pub product_return: ProductReturnRef,
}

impl CallbackBinding {
    pub fn from_secret_state(state: &[u8], spec: CallbackBindingSpec) -> Result<Self> {
        Ok(Self {
            state_hash: callback_state_hash(state)?,
            issuer: spec.issuer,
            issuer_url: spec.issuer_url,
            security_origin: spec.security_origin,
            profile: spec.profile,
            callback: spec.callback,
            binding_namespace: spec.binding_namespace,
            session: spec.session,
            product_return: spec.product_return,
        })
    }

    pub(super) fn verify(&self, intent: &ConnectIntent) -> Result<()> {
        let issuer = url::Url::parse(&self.issuer_url)?;
        ensure!(
            issuer.scheme() == "https"
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && issuer.as_str() == self.issuer_url
                && self.issuer_url.len() <= 512,
            "invalid reviewed provider issuer"
        );
        ensure!(
            self.profile.id.as_str() == intent.profile
                && Digest::of(&self.callback)?.as_str() == intent.callback,
            "callback binding does not match connect intent"
        );
        self.callback.verify_derived(
            &self.security_origin,
            &self.profile,
            &self.binding_namespace,
        )?;
        identifier(&self.binding_namespace)?;
        Ok(())
    }

    pub(super) fn state_hash(&self) -> &Digest {
        &self.state_hash
    }

    pub(super) fn issuer(&self) -> &ProviderIssuerRef {
        &self.issuer
    }

    pub(super) fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    pub(super) fn security_origin(&self) -> &SecurityOriginRef {
        &self.security_origin
    }

    pub(super) fn profile(&self) -> &BindingRef {
        &self.profile
    }

    pub(super) fn binding_namespace(&self) -> &str {
        &self.binding_namespace
    }

    pub(super) fn callback(&self) -> &ProviderCallbackRef {
        &self.callback
    }

    pub(super) fn session(&self) -> &Digest {
        &self.session
    }

    pub(super) fn product_return(&self) -> &ProductReturnRef {
        &self.product_return
    }
}

pub(super) fn callback_state_hash(state: &[u8]) -> Result<Digest> {
    ensure!(
        (32..=512).contains(&state.len()),
        "invalid provider state length"
    );
    Digest::of(&("oauth-outbound-state-v1", state))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectState {
    AwaitingProviderAuthorization,
    ExchangeReady,
    ExchangeMayHaveBeenSent,
    AwaitingAccountApproval,
    Activated { generation: i64, account: String },
    Denied,
    Cancelled,
    Expired,
    ExchangeUncertain,
    ActivationRejected,
}

/// A single process-local authorization-code dispatch permit. No re-creation
/// from a durable fenced attempt is possible after a crash.
pub(super) struct LegacyExchangeDispatchPermit {
    attempt: String,
    code_ref: String,
}

impl LegacyExchangeDispatchPermit {
    pub fn send<T>(self, transport: impl FnOnce(&str, &str) -> T) -> T {
        transport(&self.attempt, &self.code_ref)
    }
}

pub fn install_schema(db: &Connection) -> Result<()> {
    super::store::install_schema(db)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS oauth_connect_schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS oauth_callback_schema_version (
            version INTEGER PRIMARY KEY
        );
        CREATE TABLE IF NOT EXISTS oauth_connect_attempts (
            attempt TEXT PRIMARY KEY,
            slot TEXT NOT NULL,
            expected_generation INTEGER,
            expected_epoch INTEGER NOT NULL CHECK(expected_epoch > 0),
            proposed_generation INTEGER NOT NULL CHECK(proposed_generation > 0),
            owner TEXT NOT NULL,
            profile TEXT NOT NULL,
            registration TEXT NOT NULL,
            callback TEXT NOT NULL,
            consent TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'awaiting_provider_authorization', 'exchange_ready',
                'exchange_may_have_been_sent', 'awaiting_account_approval',
                'activated', 'denied', 'cancelled', 'expired',
                'exchange_uncertain', 'activation_rejected'
            )),
            code_ref TEXT,
            account TEXT,
            scope_evidence TEXT,
            CHECK((state IN ('exchange_ready', 'exchange_may_have_been_sent',
                  'exchange_uncertain')) = (code_ref IS NOT NULL)),
            CHECK((state IN ('awaiting_account_approval', 'activated')) =
                  (account IS NOT NULL AND scope_evidence IS NOT NULL))
        );
        CREATE TABLE IF NOT EXISTS oauth_callback_bindings (
            attempt TEXT PRIMARY KEY REFERENCES oauth_connect_attempts(attempt),
            binding TEXT NOT NULL
        );",
    )?;
    let mut versions = db.prepare("SELECT version FROM oauth_connect_schema_version")?;
    let known = versions
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        known.is_empty() || known == [1],
        "unsupported outbound OAuth schema version"
    );
    if known.is_empty() {
        db.execute("INSERT INTO oauth_connect_schema_version VALUES (1)", [])?;
    }
    let mut versions = db.prepare("SELECT version FROM oauth_callback_schema_version")?;
    let known = versions
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        known.is_empty() || known == [1],
        "unsupported OAuth callback schema version"
    );
    if known.is_empty() {
        db.execute("INSERT INTO oauth_callback_schema_version VALUES (1)", [])?;
    }
    super::exchange::install_schema(db)?;
    super::custody::install_schema(db)?;
    Ok(())
}

/// Records an already authorized interactive intent. The exact active pointer
/// and security epoch are captured before redirecting to the provider.
pub(super) fn begin(db: &mut Connection, intent: &ConnectIntent, now: i64) -> Result<bool> {
    begin_inner(db, intent, None, None, now)
}

/// The legacy kernel path checks exact provider and instance qualification.
/// Production exchange setup also prepares encrypted PKCE custody.
pub(super) fn begin_qualified(
    db: &mut Connection,
    input: super::profiles::OutboundQualification<'_>,
    now: i64,
) -> Result<bool> {
    let qualified = super::profiles::qualify_outbound_connect(
        input.intent,
        input.binding,
        input.requirement,
        input.permission,
        input.reviewed,
        input.instance,
    )?;
    begin_bound(db, qualified.intent(), qualified.binding(), now)
}

/// Internal protocol tests may record a callback binding directly. Production
/// callers use `begin_qualified` so registration evidence is checked first.
pub(super) fn begin_bound(
    db: &mut Connection,
    intent: &ConnectIntent,
    binding: &CallbackBinding,
    now: i64,
) -> Result<bool> {
    binding.verify(intent)?;
    begin_inner(db, intent, Some(binding), None, now)
}

pub(super) fn begin_prepared(
    db: &mut Connection,
    prepared: super::exchange::PreparedAuthorization,
    now: i64,
) -> Result<bool> {
    let (intent, callback, exchange, verifier) = prepared.parts();
    callback.verify(intent)?;
    begin_inner(db, intent, Some(callback), Some((exchange, verifier)), now)
}

fn begin_inner(
    db: &mut Connection,
    intent: &ConnectIntent,
    binding: Option<&CallbackBinding>,
    private: Option<(
        &super::exchange::ExchangeBinding,
        &super::custody::PreparedVerifier,
    )>,
    now: i64,
) -> Result<bool> {
    validate(intent)?;
    ensure!(
        intent
            .expires_at
            .checked_sub(now)
            .is_some_and(|lifetime| lifetime > 0 && lifetime <= MAX_CONNECT_SECONDS),
        "invalid connect attempt lifetime"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !slot_matches(&tx, intent)? {
        return Ok(false);
    }
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO oauth_connect_attempts
         (attempt, slot, expected_generation, expected_epoch, proposed_generation,
          owner, profile, registration, callback, consent, expires_at, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 'awaiting_provider_authorization')",
        params![
            intent.attempt,
            intent.slot,
            intent.expected_generation,
            intent.expected_epoch,
            intent.proposed_generation,
            intent.owner,
            intent.profile,
            intent.registration,
            intent.callback,
            intent.consent,
            intent.expires_at
        ],
    )?;
    if inserted == 1
        && let Some(binding) = binding
    {
        tx.execute(
            "INSERT INTO oauth_callback_bindings (attempt, binding) VALUES (?1, ?2)",
            params![intent.attempt, serde_json::to_string(binding)?],
        )?;
    }
    if inserted == 1
        && let Some((exchange, verifier)) = private
    {
        super::exchange::store_binding(&tx, &intent.attempt, exchange)?;
        super::custody::publish_verifier(&tx, verifier)?;
    }
    tx.commit()?;
    Ok(inserted == 1)
}

/// `code_ref` names quarantined private custody, never a raw authorization code.
/// A duplicate callback cannot move the attempt back to ExchangeReady.
pub(super) fn claim_callback(
    db: &mut Connection,
    attempt: &str,
    code_ref: &str,
    now: i64,
    custody_write: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    identifier(attempt)?;
    identifier(code_ref)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let eligible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM oauth_connect_attempts
         WHERE attempt = ?1 AND state = 'awaiting_provider_authorization' AND expires_at > ?2)",
        params![attempt, now],
        |row| row.get(0),
    )?;
    if !eligible {
        return Ok(false);
    }
    custody_write(&tx)?;
    let changed = tx.execute(
        "UPDATE oauth_connect_attempts SET state = 'exchange_ready', code_ref = ?2
         WHERE attempt = ?1 AND state = 'awaiting_provider_authorization'
           AND expires_at > ?3",
        params![attempt, code_ref, now],
    )?;
    tx.commit()?;
    Ok(changed == 1)
}

pub(super) fn authorize_and_commit_exchange(
    db: &mut Connection,
    attempt: &str,
    now: i64,
) -> Result<Option<LegacyExchangeDispatchPermit>> {
    identifier(attempt)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(ConnectIntent, String)> = tx
        .query_row(
            "SELECT slot, expected_generation, expected_epoch, proposed_generation, owner,
                profile, registration, callback, consent, expires_at, code_ref
             FROM oauth_connect_attempts
         WHERE attempt = ?1 AND state = 'exchange_ready' AND expires_at > ?2",
            params![attempt, now],
            |row| {
                Ok((
                    ConnectIntent {
                        attempt: attempt.into(),
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
                ))
            },
        )
        .optional()?;
    let Some((intent, code_ref)) = row else {
        return Ok(None);
    };
    if !slot_matches(&tx, &intent)? {
        return Ok(None);
    }
    let changed = tx.execute(
        "UPDATE oauth_connect_attempts SET state = 'exchange_may_have_been_sent'
         WHERE attempt = ?1 AND state = 'exchange_ready'",
        [attempt],
    )?;
    ensure!(changed == 1, "exchange dispatch fence lost");
    tx.commit()?;
    Ok(Some(LegacyExchangeDispatchPermit {
        attempt: attempt.into(),
        code_ref,
    }))
}

pub fn mark_uncertain(db: &Connection, attempt: &str) -> Result<bool> {
    identifier(attempt)?;
    Ok(db.execute(
        "UPDATE oauth_connect_attempts SET state = 'exchange_uncertain'
         WHERE attempt = ?1 AND state = 'exchange_may_have_been_sent'",
        [attempt],
    )? == 1)
}

/// A validated provider denial consumes only an awaiting attempt. The parser's
/// provider description is discarded before this durable transition.
pub fn record_denial(db: &Connection, attempt: &str, now: i64) -> Result<bool> {
    identifier(attempt)?;
    Ok(db.execute(
        "UPDATE oauth_connect_attempts SET state = 'denied'
         WHERE attempt = ?1 AND state = 'awaiting_provider_authorization'
           AND expires_at > ?2",
        params![attempt, now],
    )? == 1)
}

/// The cleanup closure removes quarantined private material in the same
/// transaction. Cancellation never returns an exchange dispatch permit.
pub fn cancel(
    db: &mut Connection,
    attempt: &str,
    custody_cleanup: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    finish_blocked(db, attempt, None, "cancelled", custody_cleanup)
}

pub fn expire(
    db: &mut Connection,
    attempt: &str,
    now: i64,
    custody_cleanup: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    finish_blocked(db, attempt, Some(now), "expired", custody_cleanup)
}

fn finish_blocked(
    db: &mut Connection,
    attempt: &str,
    now: Option<i64>,
    outcome: &str,
    custody_cleanup: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    identifier(attempt)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let eligible: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM oauth_connect_attempts
         WHERE attempt = ?1 AND state IN (
           'awaiting_provider_authorization', 'exchange_ready',
           'exchange_may_have_been_sent', 'exchange_uncertain',
           'awaiting_account_approval')
           AND (?2 IS NULL OR expires_at <= ?2))",
        params![attempt, now],
        |row| row.get(0),
    )?;
    if !eligible {
        return Ok(false);
    }
    custody_cleanup(&tx)?;
    super::custody::delete_attempt_material(&tx, attempt)?;
    let changed = tx.execute(
        "UPDATE oauth_connect_attempts SET state = ?2, code_ref = NULL,
         account = NULL, scope_evidence = NULL WHERE attempt = ?1",
        params![attempt, outcome],
    )?;
    ensure!(changed == 1, "connect terminal transition lost");
    tx.commit()?;
    Ok(true)
}

/// For explicit-account policy the verified response is encrypted in private
/// quarantine in the same transaction as the approval state. The caller supplies
/// stable verified account and scope evidence, never display email selection.
pub(super) fn await_account_approval(
    db: &mut Connection,
    attempt: &str,
    account: &str,
    scope_evidence: &str,
    now: i64,
    custody_write: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    identifier(attempt)?;
    identifier(account)?;
    identifier(scope_evidence)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state: Option<String> = tx
        .query_row(
            "SELECT state FROM oauth_connect_attempts WHERE attempt = ?1 AND expires_at > ?2",
            params![attempt, now],
            |row| row.get(0),
        )
        .optional()?;
    if !matches!(
        state.as_deref(),
        Some("exchange_may_have_been_sent" | "exchange_uncertain")
    ) {
        return Ok(false);
    }
    custody_write(&tx)?;
    let changed = tx.execute(
        "UPDATE oauth_connect_attempts SET state = 'awaiting_account_approval',
         account = ?2, scope_evidence = ?3, code_ref = NULL
         WHERE attempt = ?1 AND state IN ('exchange_may_have_been_sent', 'exchange_uncertain')
           AND expires_at > ?4",
        params![attempt, account, scope_evidence, now],
    )?;
    ensure!(changed == 1, "approval quarantine fence lost");
    tx.commit()?;
    Ok(true)
}

pub(super) fn quarantine_external_bound(
    db: &mut Connection,
    verified: &super::account::VerifiedExternalAccount,
    exchange: &super::exchange::ExchangeBinding,
    now: i64,
    custody_write: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    let intent = verified.intent();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored: Option<(ConnectIntent, String)> = tx
        .query_row(
            "SELECT slot, expected_generation, expected_epoch, proposed_generation, owner,
                profile, registration, callback, consent, expires_at, state
         FROM oauth_connect_attempts WHERE attempt = ?1",
            [&intent.attempt],
            |row| {
                Ok((
                    ConnectIntent {
                        attempt: intent.attempt.clone(),
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
                ))
            },
        )
        .optional()?;
    let Some((stored_intent, state)) = stored else {
        return Ok(false);
    };
    if stored_intent != *intent
        || state != "exchange_may_have_been_sent"
        || now >= intent.expires_at
        || !slot_matches(&tx, intent)?
        || super::exchange::load_binding(&tx, &intent.attempt)?.as_ref() != Some(exchange)
    {
        return Ok(false);
    }
    custody_write(&tx)?;
    super::custody::delete_code(&tx, intent, exchange)?;
    super::custody::delete_verifier(&tx, intent, exchange)?;
    let changed = tx.execute(
        "UPDATE oauth_connect_attempts SET state = 'awaiting_account_approval',
         account = ?2, scope_evidence = ?3, code_ref = NULL
         WHERE attempt = ?1 AND state = 'exchange_may_have_been_sent' AND expires_at > ?4",
        params![
            intent.attempt,
            verified.account(),
            verified.scope_evidence(),
            now
        ],
    )?;
    ensure!(changed == 1, "external approval quarantine fence lost");
    tx.commit()?;
    Ok(true)
}

/// Kernel activation is one transaction with caller-supplied custody
/// publication. The qualified exchange path also checks its sealed binding.
pub(super) fn activate_mapped(
    db: &mut Connection,
    verified: &super::account::VerifiedMappedAccount,
    current_mapping_revision: &Digest,
    now: i64,
    custody_publish: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    activate_mapped_inner(
        db,
        verified,
        None,
        current_mapping_revision,
        now,
        custody_publish,
    )
}

pub(super) fn activate_mapped_bound(
    db: &mut Connection,
    verified: &super::account::VerifiedMappedAccount,
    binding: &super::exchange::ExchangeBinding,
    current_mapping_revision: &Digest,
    now: i64,
    custody_publish: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    activate_mapped_inner(
        db,
        verified,
        Some(binding),
        current_mapping_revision,
        now,
        custody_publish,
    )
}

fn activate_mapped_inner(
    db: &mut Connection,
    verified: &super::account::VerifiedMappedAccount,
    exchange: Option<&super::exchange::ExchangeBinding>,
    current_mapping_revision: &Digest,
    now: i64,
    custody_publish: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    let intent: Option<ConnectIntent> = db
        .query_row(
            "SELECT slot, expected_generation, expected_epoch, proposed_generation, owner,
                profile, registration, callback, consent, expires_at
         FROM oauth_connect_attempts WHERE attempt = ?1",
            [verified.attempt()],
            |row| {
                Ok(ConnectIntent {
                    attempt: verified.attempt().into(),
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
                })
            },
        )
        .optional()?;
    if !verified.matches_current_mapping(current_mapping_revision)
        || !intent.is_some_and(|intent| verified.matches_attempt(&intent))
    {
        return Ok(false);
    }
    activate_bound(
        db,
        verified.attempt(),
        (verified.account(), verified.scope_evidence()),
        ActivationGuard {
            expected_intent: Some(verified.intent()),
            approved_account: None,
            exchange,
        },
        now,
        custody_publish,
    )
}

#[cfg(test)]
fn activate(
    db: &mut Connection,
    attempt: &str,
    account: &str,
    scope_evidence: &str,
    approved_account: Option<&str>,
    now: i64,
    custody_publish: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    activate_bound(
        db,
        attempt,
        (account, scope_evidence),
        ActivationGuard {
            expected_intent: None,
            approved_account,
            exchange: None,
        },
        now,
        custody_publish,
    )
}

struct ActivationGuard<'a> {
    expected_intent: Option<&'a ConnectIntent>,
    approved_account: Option<&'a str>,
    exchange: Option<&'a super::exchange::ExchangeBinding>,
}

pub(super) fn activate_external_bound(
    db: &mut Connection,
    intent: &ConnectIntent,
    exchange: &super::exchange::ExchangeBinding,
    account: &str,
    scope_evidence: &str,
    now: i64,
    custody_publish: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    activate_bound(
        db,
        &intent.attempt,
        (account, scope_evidence),
        ActivationGuard {
            expected_intent: Some(intent),
            approved_account: Some(account),
            exchange: Some(exchange),
        },
        now,
        custody_publish,
    )
}

fn activate_bound(
    db: &mut Connection,
    attempt: &str,
    account_scope: (&str, &str),
    guard: ActivationGuard<'_>,
    now: i64,
    custody_publish: impl FnOnce(&Transaction<'_>) -> Result<()>,
) -> Result<bool> {
    let (account, scope_evidence) = account_scope;
    identifier(attempt)?;
    identifier(account)?;
    identifier(scope_evidence)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(ConnectIntent, String, Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT slot, expected_generation, expected_epoch, proposed_generation, owner,
                profile, registration, callback, consent, expires_at, state, account, scope_evidence
         FROM oauth_connect_attempts WHERE attempt = ?1",
            [attempt],
            |row| {
                Ok((
                    ConnectIntent {
                        attempt: attempt.into(),
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
    let Some((intent, state, stored_account, stored_scope)) = row else {
        return Ok(false);
    };
    if guard
        .expected_intent
        .is_some_and(|expected| expected != &intent)
    {
        return Ok(false);
    }
    if let Some(exchange) = guard.exchange {
        let stored = super::exchange::load_binding(&tx, attempt)?;
        if stored.as_ref() != Some(exchange) {
            return Ok(false);
        }
    }
    let approved = match state.as_str() {
        "awaiting_account_approval" => {
            guard.approved_account == Some(account)
                && stored_account.as_deref() == Some(account)
                && stored_scope.as_deref() == Some(scope_evidence)
        }
        "exchange_may_have_been_sent" | "exchange_uncertain" => guard.approved_account.is_none(),
        _ => false,
    };
    if !approved {
        return Ok(false);
    }
    if now >= intent.expires_at || !slot_matches(&tx, &intent)? {
        super::custody::delete_attempt_material(&tx, attempt)?;
        tx.execute(
            "UPDATE oauth_connect_attempts SET state = 'activation_rejected',
            code_ref = NULL, account = NULL, scope_evidence = NULL WHERE attempt = ?1",
            [attempt],
        )?;
        tx.commit()?;
        return Ok(false);
    }
    let affinity = Digest::of(&(
        "oauth-connection-affinity-v1",
        &intent.owner,
        &intent.profile,
        &intent.registration,
        &intent.callback,
        &intent.consent,
        account,
        scope_evidence,
        intent.proposed_generation,
        intent.expected_epoch,
    ))?;
    custody_publish(&tx)?;
    if let Some(exchange) = guard.exchange
        && state != "awaiting_account_approval"
    {
        super::custody::delete_code(&tx, &intent, exchange)?;
        super::custody::delete_verifier(&tx, &intent, exchange)?;
    }
    if let Some(previous) = intent.expected_generation {
        let changed = tx.execute(
            "UPDATE oauth_connection_slots SET generation = ?2, token_version = 1,
             profile = ?3, account = ?4, affinity = ?5, status = 'active'
             WHERE slot = ?1 AND generation = ?6 AND security_epoch = ?7",
            params![
                intent.slot,
                intent.proposed_generation,
                intent.profile,
                account,
                affinity.as_str(),
                previous,
                intent.expected_epoch
            ],
        )?;
        ensure!(changed == 1, "connection replacement CAS lost");
    } else {
        tx.execute(
            "INSERT INTO oauth_connection_slots
             (slot, generation, token_version, security_epoch, profile, account, affinity, status)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, 'active')",
            params![
                intent.slot,
                intent.proposed_generation,
                intent.expected_epoch,
                intent.profile,
                account,
                affinity.as_str()
            ],
        )?;
    }
    tx.execute(
        "UPDATE oauth_connect_attempts SET state = 'activated', account = ?2,
         scope_evidence = ?3, code_ref = NULL WHERE attempt = ?1",
        params![attempt, account, scope_evidence],
    )?;
    tx.commit()?;
    Ok(true)
}

pub fn state(db: &Connection, attempt: &str) -> Result<Option<ConnectState>> {
    identifier(attempt)?;
    let row: Option<(String, Option<String>, Option<i64>)> = db.query_row(
        "SELECT state, account, proposed_generation FROM oauth_connect_attempts WHERE attempt = ?1",
        [attempt], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    row.map(|(state, account, generation)| match state.as_str() {
        "awaiting_provider_authorization" => Ok(ConnectState::AwaitingProviderAuthorization),
        "exchange_ready" => Ok(ConnectState::ExchangeReady),
        "exchange_may_have_been_sent" => Ok(ConnectState::ExchangeMayHaveBeenSent),
        "awaiting_account_approval" => {
            ensure!(account.is_some(), "missing verified account");
            Ok(ConnectState::AwaitingAccountApproval)
        }
        "activated" => Ok(ConnectState::Activated {
            generation: generation.ok_or_else(|| anyhow::anyhow!("missing generation"))?,
            account: account.ok_or_else(|| anyhow::anyhow!("missing active account"))?,
        }),
        "denied" => Ok(ConnectState::Denied),
        "cancelled" => Ok(ConnectState::Cancelled),
        "expired" => Ok(ConnectState::Expired),
        "exchange_uncertain" => Ok(ConnectState::ExchangeUncertain),
        "activation_rejected" => Ok(ConnectState::ActivationRejected),
        _ => anyhow::bail!("unknown connect attempt state"),
    })
    .transpose()
}

/// Read the durable attempt and callback evidence for a pending external
/// approval. A request path supplies only the opaque attempt identifier; the
/// provider, registration, account and original session come from SQLite.
pub(super) fn pending_approval(
    db: &Connection,
    attempt: &str,
    now: i64,
) -> Result<Option<(ConnectIntent, CallbackBinding)>> {
    identifier(attempt)?;
    let row: Option<(ConnectIntent, Option<String>)> = db
        .query_row(
            "SELECT a.slot, a.expected_generation, a.expected_epoch,
                    a.proposed_generation, a.owner, a.profile,
                    a.registration, a.callback, a.consent, a.expires_at,
                    b.binding
             FROM oauth_connect_attempts AS a
             LEFT JOIN oauth_callback_bindings AS b ON b.attempt = a.attempt
             WHERE a.attempt = ?1 AND a.state = 'awaiting_account_approval'
                   AND a.expires_at > ?2",
            params![attempt, now],
            |row| {
                Ok((
                    ConnectIntent {
                        attempt: attempt.to_owned(),
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
                ))
            },
        )
        .optional()?;
    let Some((intent, binding)) = row else {
        return Ok(None);
    };
    validate(&intent)?;
    let binding: CallbackBinding = serde_json::from_str(
        &binding.ok_or_else(|| anyhow::anyhow!("pending approval missing callback binding"))?,
    )?;
    binding.verify(&intent)?;
    Ok(Some((intent, binding)))
}

pub(super) fn slot_matches(tx: &Transaction<'_>, intent: &ConnectIntent) -> Result<bool> {
    let row: Option<(i64, i64, String)> = tx
        .query_row(
            "SELECT generation, security_epoch, status FROM oauth_connection_slots WHERE slot = ?1",
            [&intent.slot],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(match (row, intent.expected_generation) {
        (None, None) => intent.expected_epoch == 1 && intent.proposed_generation == 1,
        (Some((generation, epoch, status)), Some(expected)) => {
            generation == expected
                && epoch == intent.expected_epoch
                && status == "active"
                && intent.proposed_generation == expected + 1
        }
        _ => false,
    })
}

fn validate(intent: &ConnectIntent) -> Result<()> {
    for field in [
        &intent.attempt,
        &intent.slot,
        &intent.owner,
        &intent.profile,
        &intent.registration,
        &intent.callback,
        &intent.consent,
    ] {
        identifier(field)?;
    }
    ensure!(
        intent.expected_epoch > 0
            && intent.proposed_generation > 0
            && intent
                .expected_generation
                .is_none_or(|generation| generation > 0),
        "invalid connect generation or epoch"
    );
    Ok(())
}

pub(super) fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 160
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte)),
        "invalid private OAuth identifier"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn intent(attempt: &str) -> ConnectIntent {
        ConnectIntent {
            attempt: attempt.into(),
            slot: "installation.env.workspace.calendar.human_1".into(),
            expected_generation: None,
            expected_epoch: 1,
            proposed_generation: 1,
            owner: "human_1".into(),
            profile: "google_calendar_v1".into(),
            registration: "google_registration_v1".into(),
            callback: "security_callback_v1".into(),
            consent: "consent_v1".into(),
            expires_at: 100,
        }
    }

    #[test]
    fn callback_replay_and_unsent_fence_survive_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("connect.sqlite");
        let mut first = Connection::open(&path).unwrap();
        install_schema(&first).unwrap();
        assert!(begin(&mut first, &intent("attempt_1"), 1).unwrap());
        assert!(!begin(&mut first, &intent("attempt_1"), 1).unwrap());
        assert!(claim_callback(&mut first, "attempt_1", "private_code_1", 2, |_| Ok(())).unwrap());
        assert!(!claim_callback(&mut first, "attempt_1", "private_code_2", 2, |_| Ok(())).unwrap());
        let permit = authorize_and_commit_exchange(&mut first, "attempt_1", 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            permit.send(|attempt, code| (attempt.into(), code.into())),
            ("attempt_1".to_owned(), "private_code_1".to_owned())
        );
        drop(first);
        let mut reopened = Connection::open(&path).unwrap();
        install_schema(&reopened).unwrap();
        assert!(
            authorize_and_commit_exchange(&mut reopened, "attempt_1", 4)
                .unwrap()
                .is_none()
        );
        assert!(mark_uncertain(&reopened, "attempt_1").unwrap());
        assert_eq!(
            state(&reopened, "attempt_1").unwrap(),
            Some(ConnectState::ExchangeUncertain)
        );
    }

    #[test]
    fn terminal_outcomes_fence_late_exchange_and_activation() {
        let mut db = Connection::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        begin(&mut db, &intent("denied"), 1).unwrap();
        assert!(record_denial(&db, "denied", 2).unwrap());
        assert!(!record_denial(&db, "denied", 2).unwrap());
        assert!(!claim_callback(&mut db, "denied", "late_code", 3, |_| Ok(())).unwrap());
        assert_eq!(state(&db, "denied").unwrap(), Some(ConnectState::Denied));

        begin(&mut db, &intent("cancelled"), 1).unwrap();
        db.execute_batch("CREATE TABLE private_codes (id TEXT PRIMARY KEY)")
            .unwrap();
        claim_callback(&mut db, "cancelled", "code_ref", 2, |tx| {
            tx.execute("INSERT INTO private_codes VALUES ('code_ref')", [])?;
            Ok(())
        })
        .unwrap();
        assert!(
            cancel(&mut db, "cancelled", |tx| {
                tx.execute("DELETE FROM private_codes WHERE id = 'code_ref'", [])?;
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(
            state(&db, "cancelled").unwrap(),
            Some(ConnectState::Cancelled)
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM private_codes", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            authorize_and_commit_exchange(&mut db, "cancelled", 3)
                .unwrap()
                .is_none()
        );

        begin(&mut db, &intent("expired"), 1).unwrap();
        assert!(!expire(&mut db, "expired", 99, |_| Ok(())).unwrap());
        assert!(expire(&mut db, "expired", 100, |_| Ok(())).unwrap());
        assert!(!claim_callback(&mut db, "expired", "late_code", 101, |_| Ok(())).unwrap());
        assert_eq!(state(&db, "expired").unwrap(), Some(ConnectState::Expired));
    }

    #[test]
    fn two_sqlite_hosts_claim_callback_once() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("callback-race.sqlite");
        let mut first = Connection::open(&path).unwrap();
        install_schema(&first).unwrap();
        assert!(begin(&mut first, &intent("attempt_1"), 1).unwrap());
        drop(first);
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|scope| {
            let jobs = (1..=2)
                .map(|index| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let mut db = Connection::open(path).unwrap();
                        db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                        barrier.wait();
                        claim_callback(
                            &mut db,
                            "attempt_1",
                            &format!("private_code_{index}"),
                            2,
                            |_| Ok(()),
                        )
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.into_iter().filter(|claimed| *claimed).count(), 1);
        let mut reopened = Connection::open(&path).unwrap();
        assert_eq!(
            state(&reopened, "attempt_1").unwrap(),
            Some(ConnectState::ExchangeReady)
        );
        assert!(
            authorize_and_commit_exchange(&mut reopened, "attempt_1", 3)
                .unwrap()
                .is_some()
        );
        assert!(
            authorize_and_commit_exchange(&mut reopened, "attempt_1", 3)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn approval_binds_exact_account_and_only_one_generation_activates() {
        let mut db = Connection::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        assert!(begin(&mut db, &intent("attempt_1"), 1).unwrap());
        assert!(begin(&mut db, &intent("attempt_2"), 1).unwrap());
        for attempt in ["attempt_1", "attempt_2"] {
            assert!(
                claim_callback(&mut db, attempt, &format!("code_{attempt}"), 2, |_| Ok(()))
                    .unwrap()
            );
            authorize_and_commit_exchange(&mut db, attempt, 3)
                .unwrap()
                .unwrap()
                .send(|_, _| ());
            assert!(
                await_account_approval(
                    &mut db,
                    attempt,
                    "issuer:subject_1",
                    "scope_v1",
                    4,
                    |_| Ok(())
                )
                .unwrap()
            );
        }
        assert!(
            !activate(
                &mut db,
                "attempt_1",
                "issuer:subject_2",
                "scope_v1",
                Some("issuer:subject_2"),
                4,
                |_| Ok(())
            )
            .unwrap()
        );
        assert_eq!(
            state(&db, "attempt_1").unwrap(),
            Some(ConnectState::AwaitingAccountApproval)
        );
        assert!(
            !activate(
                &mut db,
                "attempt_1",
                "issuer:subject_1",
                "scope_v1",
                None,
                4,
                |_| Ok(())
            )
            .unwrap()
        );
        assert!(
            activate(
                &mut db,
                "attempt_1",
                "issuer:subject_1",
                "scope_v1",
                Some("issuer:subject_1"),
                4,
                |_| Ok(())
            )
            .unwrap()
        );
        assert!(
            !activate(
                &mut db,
                "attempt_2",
                "issuer:subject_1",
                "scope_v1",
                Some("issuer:subject_1"),
                4,
                |_| Ok(())
            )
            .unwrap()
        );
        assert_eq!(
            state(&db, "attempt_2").unwrap(),
            Some(ConnectState::ActivationRejected)
        );
        let selected: (i64, String) = db
            .query_row(
                "SELECT generation, account FROM oauth_connection_slots",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(selected, (1, "issuer:subject_1".into()));
    }

    #[test]
    fn failed_custody_write_rolls_back_callback_and_activation() {
        let mut db = Connection::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        begin(&mut db, &intent("attempt_1"), 1).unwrap();
        assert!(
            claim_callback(&mut db, "attempt_1", "code_1", 2, |_| {
                anyhow::bail!("custody unavailable")
            })
            .is_err()
        );
        assert_eq!(
            state(&db, "attempt_1").unwrap(),
            Some(ConnectState::AwaitingProviderAuthorization)
        );
        claim_callback(&mut db, "attempt_1", "code_1", 2, |_| Ok(())).unwrap();
        authorize_and_commit_exchange(&mut db, "attempt_1", 3)
            .unwrap()
            .unwrap()
            .send(|_, _| ());
        assert!(
            activate(
                &mut db,
                "attempt_1",
                "issuer:subject_1",
                "scope_v1",
                None,
                4,
                |_| anyhow::bail!("custody unavailable")
            )
            .is_err()
        );
        assert_eq!(
            state(&db, "attempt_1").unwrap(),
            Some(ConnectState::ExchangeMayHaveBeenSent)
        );
        assert!(
            db.query_row("SELECT COUNT(*) FROM oauth_connection_slots", [], |row| row
                .get::<_, i64>(0))
                .unwrap()
                == 0
        );
    }

    #[test]
    fn unknown_connect_schema_version_fails_closed() {
        let db = Connection::open_in_memory().unwrap();
        install_schema(&db).unwrap();
        db.execute("UPDATE oauth_connect_schema_version SET version = 2", [])
            .unwrap();
        assert!(install_schema(&db).is_err());
    }
}
