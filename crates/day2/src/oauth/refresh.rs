//! Private, demand-driven Google refresh. The worker can request a connection;
//! only this host path chooses current custody and consumes a durable send permit.
use super::{custody, effects, google, store, usage};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::{BindingRef, Digest};
use rusqlite::Connection;
use std::{io::Read as _, time::Duration};

const RENEW_SECONDS: i64 = 60;
const BUDGET: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 64 * 1024;

/// Produced only by the selected native secret reader. No Debug, Clone,
/// serialization or application-visible secret access is available.
pub(crate) struct ClientCredential {
    client: String,
    secret: String,
    reference: BindingRef,
}

impl ClientCredential {
    pub(super) fn new(client: String, secret: String, reference: BindingRef) -> Result<Self> {
        ensure!(!client.is_empty() && client.len() <= 512 && client.bytes().all(|b| b.is_ascii_graphic()), "invalid OAuth refresh client");
        ensure!(!secret.is_empty() && secret.len() <= 8192 && secret.bytes().all(|b| b.is_ascii_graphic()), "invalid OAuth refresh credential");
        Ok(Self { client, secret, reference })
    }
}

/// Its constructor remains in this module, after response/account verification.
/// Kernel callers cannot choose another slot, material or replacement version.
pub(super) struct PreparedReplacement {
    attempt: String,
    next: i64,
    receipt: String,
    base_reference: String,
    material: custody::PreparedTokenMaterial,
}

impl PreparedReplacement {
    pub(super) fn into_parts(self) -> (String, i64, String, String, custody::PreparedTokenMaterial) {
        (self.attempt, self.next, self.receipt, self.base_reference, self.material)
    }
}

fn clock_refusal(db: &Connection, context: &usage::RefreshContext) -> Result<()> {
    let expected = context.eligibility();
    custody::refuse_access(db, &expected.slot, expected.generation, expected.base_version,
        expected.security_epoch, &expected.profile, &expected.account)
}

fn local_matches(
    db: &Connection,
    runtime: &crate::store::Runtime,
    request: &crate::protocol::Request,
    registration: &str,
    subject: &str,
    selection: &usage::Selection,
    context: &usage::RefreshContext,
    now: i64,
) -> Result<bool> {
    Ok(usage::refresh_context(db, runtime, request, registration, subject, selection, now)?
        .is_some_and(|current| current.pin() == context.pin()))
}

/// Called before resolve publishes its immutable invocation-affine Use. An
/// already committed expiry/clock refusal is never cleared by refresh.
pub(super) fn ensure_current(
    runtime: &crate::store::Runtime,
    request: &crate::protocol::Request,
    registration: &str,
    subject: &str,
    selection: &usage::Selection,
    started_at: i64,
) -> Result<Option<&'static str>> {
    let authority = runtime.connections.as_deref().context("OAuth refresh authority missing")?;
    let mut db = crate::store::open(runtime.db())?;
    let snapshot = db.transaction()?;
    let context = usage::refresh_context(&snapshot, runtime, request, registration, subject, selection, started_at);
    snapshot.commit()?;
    let context = match context {
        Ok(Some(context)) => context,
        Ok(None) => return Ok(None),
        Err(_) => return Ok(Some("ReauthRequired")),
    };
    let selected = selection.identity()?;
    let Some(key) = authority.custody(runtime.app(), registration, &request.context.actor, &selected, started_at)? else {
        return Ok(Some("BindingUnavailable"));
    };
    let now = effects::wall_time()?;
    if now < started_at {
        clock_refusal(&db, &context)?;
        return Ok(Some("ReauthRequired"));
    }
    let snapshot = crate::write_queue::immediate(&mut db)?;
    ensure!(local_matches(&snapshot, runtime, request, registration, subject, selection, &context, now)?, "refresh authority changed during key retrieval");
    let expected = context.eligibility();
    let source = custody::load_refresh(&snapshot, &key, context.intent(), context.binding(), &expected.account, expected.base_version, now)?;
    snapshot.commit()?;
    let Some(source) = source else { return Ok(Some("ReauthRequired")); };
    let unresolved: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM oauth_refresh_attempts WHERE slot=?1 AND generation=?2 AND base_version=?3
         AND state IN ('may_have_been_sent','uncertain'))",
        rusqlite::params![expected.slot, expected.generation, expected.base_version], |row| row.get(0),
    )?;
    if unresolved { return Ok(Some("ReauthRequired")); }
    if source.expires_at > now.saturating_add(RENEW_SECONDS) {
        return Ok(None);
    }
    ensure!(selection.requirement.capability == google::CAPABILITY
        && super::catalog::Adapter::selected(&selection.reviewed)? == super::catalog::Adapter::GoogleCalendar,
        "product refresh adapter unavailable");
    let Some(client) = authority.refresh_client(runtime.app(), registration, &request.context.actor, &selected, now)? else {
        return Ok(Some("BindingUnavailable"));
    };
    ensure!(client.reference == selection.instance.registration.client_credential, "refresh credential binding changed");
    let dispatch_at = effects::wall_time()?;
    if dispatch_at < now || dispatch_at < source.issued_at {
        clock_refusal(&db, &context)?;
        return Ok(Some("ReauthRequired"));
    }
    let next = expected.base_version.checked_add(1).context("OAuth material version overflow")?;
    let attempt = Digest::of(&("oauth-product-refresh-attempt-v1", expected))?.as_str().to_owned();
    let mut permit = None;
    let admitted = authority.with_current(runtime.app(), registration, &request.context.actor, dispatch_at, &mut |current| {
        if current.identity()? != selected { return Ok(false); }
        if !local_matches(&db, runtime, request, registration, subject, current, &context, dispatch_at)? { return Ok(false); }
        // Reclaiming an unsent Ready attempt is safe; the durable CAS still
        // returns at most one process-local permit across processes/restarts.
        store::claim_refresh(&mut db, &attempt, expected)?;
        permit = store::authorize_checked_dispatch(&mut db, &attempt, |tx| {
            let at = effects::wall_time()?;
            ensure!(at >= dispatch_at, "refresh dispatch clock rewound");
            local_matches(tx, runtime, request, registration, subject, current, &context, at)
        })?;
        Ok(permit.is_some())
    });
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            if effects::wall_time()? < dispatch_at { clock_refusal(&db, &context)?; }
            return Err(error);
        }
    };
    if !admitted { return Ok(Some("CapacityDeferred")); }
    let permit = permit.context("refresh dispatch permit missing")?;
    let sent_at = effects::wall_time()?;
    if sent_at < dispatch_at {
        store::mark_uncertain(&db, &attempt)?;
        clock_refusal(&db, &context)?;
        return Ok(Some("ReauthRequired"));
    }
    let monotonic = effects::Instant::now();
    let mut last_clock = sent_at;
    let mut clock_failed = false;
    let result = permit.send(|bound| -> Result<Option<super::profiles::ValidatedTokenResponse>> {
        ensure!(bound == expected, "refresh dispatch material changed");
        let wire = Wire::new()?;
        let response = wire.client.post(google::TOKEN).form(&[
            ("grant_type", "refresh_token"), ("refresh_token", source.token()),
            ("client_id", client.client.as_str()), ("client_secret", client.secret.as_str()),
        ]).send().map_err(|_| anyhow::anyhow!("OAuth refresh response unavailable; do not retry"))?;
        let status = response.status().as_u16();
        let bytes = body(response)?;
        if status == 400 {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Rejection { error: String, error_description: Option<String> }
            let rejection: Rejection = crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("invalid OAuth refresh rejection"))?;
            ensure!(rejection.error == "invalid_grant"
                && rejection.error_description.as_ref().is_none_or(|text| text.len() <= 4096), "unclassified OAuth refresh rejection");
            return Ok(None);
        }
        ensure!(status == 200, "unclassified OAuth refresh response");
        let tokens = google::refresh_tokens(&bytes, &selection.reviewed, &selection.permission, source.token())?;
        let expiry = dispatch_at.checked_add(i64::try_from(tokens.lifetime())?).context("OAuth refresh expiry overflow")?;
        let at = effects::wall_time()?;
        if at < last_clock || at >= expiry { clock_failed = true; anyhow::bail!("OAuth refresh response clock fence changed"); }
        last_clock = at;
        let current = authority.current(runtime.app(), registration, &request.context.actor, at)?.context("OAuth refresh readiness unavailable")?;
        ensure!(current.identity()? == selected, "OAuth refresh selection changed before account read");
        let at = effects::wall_time()?;
        if at < last_clock || at >= expiry { clock_failed = true; anyhow::bail!("OAuth refresh account dispatch clock fence changed"); }
        last_clock = at;
        let snapshot = db.transaction()?;
        ensure!(local_matches(&snapshot, runtime, request, registration, subject, &current, &context, at)?, "OAuth refresh authority changed before account read");
        snapshot.commit()?;
        ensure!(monotonic.elapsed() <= BUDGET, "OAuth refresh account dispatch elapsed budget exceeded");
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", tokens.refresh_access()))?;
        authorization.set_sensitive(true);
        let response = wire.client.get(google::USERINFO).header(reqwest::header::AUTHORIZATION, authorization)
            .send().map_err(|_| anyhow::anyhow!("OAuth refresh account unavailable; do not retry"))?;
        ensure!(response.status().as_u16() == 200, "OAuth refresh account refused");
        let observed = google::observe_account(&body(response)?)?;
        ensure!(super::account::provider_account_digest(&observed)?.as_str() == expected.account,
            "OAuth refreshed account changed");
        ensure!(monotonic.elapsed() <= BUDGET, "OAuth refresh elapsed budget exceeded");
        Ok(Some(tokens))
    });
    let tokens = match result {
        Ok(Some(tokens)) => tokens,
        Ok(None) => { store::mark_definitive_rejection(&mut db, &attempt)?; return Ok(Some("ReauthRequired")); }
        Err(_) => {
            store::mark_uncertain(&db, &attempt)?;
            if clock_failed { clock_refusal(&db, &context)?; }
            return Ok(Some("ReauthRequired"));
        }
    };
    // Lifetime begins at the earliest dispatch fence, never at settlement.
    let expires_at = dispatch_at.checked_add(i64::try_from(tokens.lifetime())?).context("OAuth refresh expiry overflow")?;
    let observed_at = effects::wall_time()?;
    if observed_at < last_clock || observed_at >= expires_at || monotonic.elapsed() > BUDGET {
        store::mark_uncertain(&db, &attempt)?;
        clock_refusal(&db, &context)?;
        return Ok(Some("ReauthRequired"));
    }
    let material = custody::prepare_replacement_tokens(&key, context.intent(), context.binding(), &expected.account, next, tokens, dispatch_at)?;
    let receipt = Digest::of(&("oauth-product-refresh-committed-v1", &attempt, context.pin(), next))?.as_str().to_owned();
    let mut prepared = Some(PreparedReplacement { attempt: attempt.clone(), next, receipt,
        base_reference: custody::token_reference(context.binding(), expected.base_version)?, material });
    let publication = authority.with_current(runtime.app(), registration, &request.context.actor, observed_at, &mut |current| {
        if current.identity()? != selected { return Ok(false); }
        Ok(store::publish_replacement(&mut db, prepared.take().context("refresh settlement already consumed")?, |tx| {
            let at = effects::wall_time()?;
            ensure!(at >= observed_at && at < expires_at && monotonic.elapsed() <= BUDGET, "refresh publication clock or elapsed fence changed");
            local_matches(tx, runtime, request, registration, subject, current, &context, at)
        })?.is_some())
    });
    match publication {
        Ok(true) => Ok(None),
        _ => {
            store::mark_uncertain(&db, &attempt)?;
            let at = effects::wall_time()?;
            if at < observed_at || at >= expires_at { clock_refusal(&db, &context)?; }
            Ok(Some("ReauthRequired"))
        }
    }
}

struct Wire { client: effects::Client }

impl Wire {
    fn new() -> Result<Self> {
        Ok(Self { client: effects::Client::builder().no_proxy()
            .redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(3)).timeout(Duration::from_secs(4)).build()? })
    }
}

fn body(response: effects::Response) -> Result<Vec<u8>> {
    ensure!(response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.split(';').next() == Some("application/json")), "invalid OAuth refresh content type");
    ensure!(response.content_length().is_none_or(|n| n <= MAX_RESPONSE as u64), "OAuth refresh response too large");
    let mut bytes = Vec::new();
    response.take(MAX_RESPONSE as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("OAuth refresh body unavailable; do not retry"))?;
    ensure!(bytes.len() <= MAX_RESPONSE, "OAuth refresh response too large");
    Ok(bytes)
}
