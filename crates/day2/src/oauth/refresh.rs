//! Private, demand-driven Google refresh. The worker can request a connection;
//! only this host path chooses current custody and consumes a durable send permit.
use super::{admission::SubjectReader, custody, effects, google, store, usage};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::{BindingRef, Digest};
use rusqlite::Connection;
use std::{io::Read as _, time::Duration};

const RENEW_SECONDS: i64 = 60;
const BUDGET: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 64 * 1024;

/// A native producer observed a rewind even if a subsequent clock read has
/// already recovered. Generic secret/network failures do not carry this fact.
#[derive(Debug)]
pub(super) struct ClockRefusal;

impl std::fmt::Display for ClockRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuth refresh clock fence refused")
    }
}

impl std::error::Error for ClockRefusal {}

/// Carries the freshest observed clock and exact current material all the way
/// into the transaction that mints the immutable Use.
pub(crate) struct Resolution {
    problem: Option<&'static str>,
    fence: Option<MaterialFence>,
    clock: i64,
}

struct MaterialFence {
    expected: store::RefreshEligibility,
    reference: String,
}

impl Resolution {
    fn unavailable(problem: &'static str) -> Self {
        Self {
            problem: Some(problem),
            fence: None,
            clock: 0,
        }
    }

    fn ready(context: &usage::RefreshContext, version: i64, clock: i64) -> Result<Self> {
        let mut expected = context.eligibility().clone();
        expected.base_version = version;
        Ok(Self {
            problem: None,
            clock,
            fence: Some(MaterialFence {
                expected,
                reference: custody::token_reference(context.binding(), version)?,
            }),
        })
    }

    pub(super) fn problem(&self) -> Option<&'static str> {
        self.problem
    }

    /// The caller commits even a refused result so an observed rewind cannot
    /// disappear when the product decision subsequently fails.
    pub(super) fn validate(&self, db: &Connection, now: i64) -> Result<bool> {
        if now < self.clock {
            if let Some(fence) = &self.fence {
                let expected = &fence.expected;
                custody::refuse_access(
                    db,
                    &expected.slot,
                    expected.generation,
                    expected.base_version,
                    expected.security_epoch,
                    &expected.profile,
                    &expected.account,
                )?;
            }
            return Ok(false);
        }
        let Some(fence) = &self.fence else {
            return Ok(true);
        };
        let expected = &fence.expected;
        Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM oauth_connection_slots s JOIN oauth_private_tokens t
            ON t.slot=s.slot AND t.generation=s.generation AND t.account=s.account
            WHERE s.slot=?1 AND s.generation=?2 AND s.token_version=?3 AND s.security_epoch=?4
            AND s.profile=?5 AND s.account=?6 AND s.affinity=?7 AND s.status='active' AND t.reference=?8)",
            rusqlite::params![expected.slot, expected.generation, expected.base_version, expected.security_epoch,
                expected.profile, expected.account, expected.affinity, fence.reference], |row| row.get(0))?)
    }
}

/// Produced only by the selected native secret reader. No Debug, Clone,
/// serialization or application-visible secret access is available.
pub(crate) struct ClientCredential {
    client: String,
    secret: String,
    reference: BindingRef,
    checked_at: i64,
}

pub(in crate::oauth) struct InitialExchange<'a> {
    pub key: &'a crate::managed_credentials::crypto::KeyLease,
    pub selection: &'a usage::Selection,
    pub subject: &'a str,
    pub now: i64,
    pub guard: &'a super::management::app::FinishGuard<'a>,
}

impl ClientCredential {
    /// Consumes the durable code-exchange permit. Credentials, provider code,
    /// PKCE verifier and tokens never leave the fixed native adapter.
    pub(in crate::oauth) fn initial_exchange(
        self,
        permit: super::exchange::ExchangeDispatchPermit,
        input: InitialExchange<'_>,
    ) -> Result<(
        super::exchange::ExchangeObservation,
        Option<super::account::ProviderAccount>,
    )> {
        let InitialExchange {
            key,
            selection,
            subject,
            now,
            guard,
        } = input;
        ensure!(
            now >= self.checked_at && selection.reviewed.token_endpoint == google::TOKEN,
            "OAuth initial credential expired or changed"
        );
        let wire = Wire::new()?;
        let started = effects::Instant::now();
        let mut account = None;
        let outcome = permit.send(|request| {
            ensure!(
                request.token_endpoint() == google::TOKEN
                    && request.client_credential() == &self.reference
                    && request.profile() == &selection.permission.profile
                    && request.registration() == &selection.instance.registration.registration,
                "OAuth initial credential binding changed"
            );
            let raw = guard.send(
                now,
                |db| {
                    let code = request.load_code(db, key)?;
                    let verifier = request.load_verifier(db, key)?;
                    Ok((code, verifier))
                },
                |(code, verifier)| {
                    let response = wire
                        .client
                        .post(google::TOKEN)
                        .timeout(
                            BUDGET
                                .checked_sub(started.elapsed())
                                .context("OAuth initial deadline reached")?,
                        )
                        .form(&[
                            ("grant_type", "authorization_code"),
                            ("client_id", self.client.as_str()),
                            ("client_secret", self.secret.as_str()),
                            ("code", code.as_str()),
                            ("code_verifier", verifier.as_str()),
                            ("redirect_uri", request.callback_url()),
                        ])
                        .send()
                        .map_err(|_| anyhow::anyhow!("OAuth initial exchange outcome unknown"))?;
                    ensure!(
                        response.status().as_u16() == 200,
                        "OAuth initial exchange refused"
                    );
                    body(response)
                },
            )?;
            let (normalized, tokens) = google::normalized_tokens(
                &raw,
                super::catalog::TokenContext {
                    reviewed: &selection.reviewed,
                    permission: &selection.permission,
                    client_id: &self.client,
                    subject,
                },
                false,
            )?;
            let mut authorization =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", tokens.access))?;
            authorization.set_sensitive(true);
            let observed_account = guard.send(
                now,
                |_| Ok(()),
                |()| {
                    let response = wire
                        .client
                        .get(google::USERINFO)
                        .header(reqwest::header::AUTHORIZATION, authorization)
                        .timeout(
                            BUDGET
                                .checked_sub(started.elapsed())
                                .context("OAuth initial deadline reached")?,
                        )
                        .send()
                        .map_err(|_| anyhow::anyhow!("OAuth initial account outcome unknown"))?;
                    ensure!(
                        response.status().as_u16() == 200,
                        "OAuth initial account refused"
                    );
                    google::observe_account(&body(response)?)
                },
            )?;
            account = Some(observed_account);
            Ok(super::exchange::TokenHttpResponse {
                status: 200,
                content_type: "application/json".into(),
                body: normalized,
            })
        });
        Ok((outcome, account))
    }

    pub(super) fn new(
        client: String,
        secret: String,
        reference: BindingRef,
        checked_at: i64,
    ) -> Result<Self> {
        ensure!(checked_at >= 0, "invalid OAuth refresh credential clock");
        ensure!(
            !client.is_empty()
                && client.len() <= 512
                && client.bytes().all(|b| b.is_ascii_graphic()),
            "invalid OAuth refresh client"
        );
        ensure!(
            !secret.is_empty()
                && secret.len() <= 8192
                && secret.bytes().all(|b| b.is_ascii_graphic()),
            "invalid OAuth refresh credential"
        );
        Ok(Self {
            client,
            secret,
            reference,
            checked_at,
        })
    }
}

/// Its constructor remains in this module, after response/account verification.
/// Kernel callers cannot choose another slot, material or replacement version.
pub(crate) struct PreparedReplacement {
    attempt: String,
    next: i64,
    receipt: String,
    base_reference: String,
    material: custody::PreparedTokenMaterial,
}

impl PreparedReplacement {
    pub(super) fn into_parts(
        self,
    ) -> (String, i64, String, String, custody::PreparedTokenMaterial) {
        (
            self.attempt,
            self.next,
            self.receipt,
            self.base_reference,
            self.material,
        )
    }
}

fn clock_refusal(db: &Connection, context: &usage::RefreshContext) -> Result<()> {
    let expected = context.eligibility();
    custody::refuse_access(
        db,
        &expected.slot,
        expected.generation,
        expected.base_version,
        expected.security_epoch,
        &expected.profile,
        &expected.account,
    )
}

fn current_clock_refusal(
    runtime: &crate::store::Runtime,
    serving: &mut super::native_management::RuntimeConsumer<'_, '_>,
    context: &usage::RefreshContext,
) -> Result<()> {
    serving.sql_write(runtime, |tx| {
        clock_refusal(tx, context)?;
        Ok(crate::store::SqlDecision::Commit(()))
    })
}

fn current_uncertain(
    runtime: &crate::store::Runtime,
    serving: &mut super::native_management::RuntimeConsumer<'_, '_>,
    attempt: &str,
) -> Result<()> {
    serving.sql_write(runtime, |tx| {
        store::mark_uncertain(tx, attempt)?;
        Ok(crate::store::SqlDecision::Commit(()))
    })
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
    serving: &mut super::native_management::RuntimeConsumer<'_, '_>,
) -> Result<Resolution> {
    serving.require_runtime(runtime)?;
    let authority = runtime
        .connections
        .as_deref()
        .context("OAuth refresh authority missing")?;
    let context = serving.sql_read(runtime, |snapshot| {
        Ok(usage::refresh_context(
            &snapshot,
            runtime,
            request,
            registration,
            subject,
            selection,
            started_at,
        ))
    })?;
    let context = match context {
        Ok(Some(context)) => context,
        Ok(None) => {
            return Ok(Resolution {
                problem: None,
                fence: None,
                clock: started_at,
            });
        }
        Err(_) => return Ok(Resolution::unavailable("ReauthRequired")),
    };
    let local_matches = |db: &Connection, current: &usage::Selection, at: i64| -> Result<bool> {
        Ok(
            usage::refresh_context(db, runtime, request, registration, subject, current, at)?
                .is_some_and(|current| current.pin() == context.pin()),
        )
    };
    let selected = selection.identity()?;
    serving.check()?;
    let Some(key) = authority.custody(
        runtime.app(),
        registration,
        &request.context.actor,
        &selected,
        started_at,
        &mut SubjectReader::runtime(runtime, serving),
    )?
    else {
        return Ok(Resolution::unavailable("BindingUnavailable"));
    };
    let now = effects::wall_time()?;
    if now < started_at {
        current_clock_refusal(runtime, serving, &context)?;
        return Ok(Resolution::unavailable("ReauthRequired"));
    }
    let expected = context.eligibility();
    let source = serving.sql_write(runtime, |snapshot| {
        ensure!(
            local_matches(&snapshot, selection, now)?,
            "refresh authority changed during key retrieval"
        );
        let source = custody::load_refresh(
            &snapshot,
            &key,
            context.intent(),
            context.binding(),
            &expected.account,
            expected.base_version,
            now,
        )?;
        Ok(crate::store::SqlDecision::Commit(source))
    })?;
    let Some(source) = source else {
        return Ok(Resolution::unavailable("ReauthRequired"));
    };
    let unresolved: bool = serving.sql_read(runtime, |db| Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM oauth_refresh_attempts WHERE slot=?1 AND generation=?2 AND base_version=?3
         AND state IN ('may_have_been_sent','uncertain'))",
        rusqlite::params![expected.slot, expected.generation, expected.base_version], |row| row.get(0),
    )?))?;
    if unresolved {
        return Ok(Resolution::unavailable("ReauthRequired"));
    }
    if source.expires_at > now.saturating_add(RENEW_SECONDS) {
        return Resolution::ready(&context, expected.base_version, now);
    }
    ensure!(
        selection.requirement.capability == google::CAPABILITY
            && super::catalog::Adapter::selected(&selection.reviewed)?
                == super::catalog::Adapter::GoogleCalendar,
        "product refresh adapter unavailable"
    );
    serving.check()?;
    let client = authority.refresh_client(
        runtime.app(),
        registration,
        &request.context.actor,
        &selected,
        now,
        &mut SubjectReader::runtime(runtime, serving),
    );
    let client = match client {
        Err(error) if error.downcast_ref::<ClockRefusal>().is_some() => {
            current_clock_refusal(runtime, serving, &context)?;
            return Ok(Resolution::unavailable("ReauthRequired"));
        }
        Err(error) => return Err(error),
        Ok(None) => return Ok(Resolution::unavailable("BindingUnavailable")),
        Ok(Some(client)) => client,
    };
    ensure!(
        client.reference == selection.instance.registration.client_credential,
        "refresh credential binding changed"
    );
    let dispatch_at = effects::wall_time()?;
    if dispatch_at < now || dispatch_at < source.issued_at || dispatch_at < client.checked_at {
        current_clock_refusal(runtime, serving, &context)?;
        return Ok(Resolution::unavailable("ReauthRequired"));
    }
    let next = expected
        .base_version
        .checked_add(1)
        .context("OAuth material version overflow")?;
    let attempt = Digest::of(&("oauth-product-refresh-attempt-v1", expected))?
        .as_str()
        .to_owned();
    let mut permit = None;
    let mut checked_dispatch = dispatch_at;
    let admitted = authority.with_current(
        runtime.app(),
        registration,
        &request.context.actor,
        dispatch_at,
        &mut SubjectReader::runtime(runtime, serving),
        &mut |current, subjects| {
            subjects.with_runtime(|serving| {
                if current.identity()? != selected {
                    return Ok(false);
                }
                let eligible = serving.sql_read(runtime, |snapshot| {
                    local_matches(snapshot, current, dispatch_at)
                })?;
                if !eligible {
                    return Ok(false);
                }
                // Reclaiming an unsent Ready attempt is safe; the durable CAS still
                // returns at most one process-local permit across processes/restarts.
                serving.check()?;
                store::claim_current_refresh(runtime, serving, &attempt, expected)?;
                permit = store::authorize_checked_dispatch(runtime, serving, &attempt, |tx| {
                    let at = effects::wall_time()?;
                    if at < dispatch_at {
                        return Err(ClockRefusal.into());
                    }
                    checked_dispatch = at;
                    local_matches(tx, current, at)
                })?;
                Ok(permit.is_some())
            })
        },
    );
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            if error.downcast_ref::<ClockRefusal>().is_some()
                || effects::wall_time()? < checked_dispatch
            {
                current_clock_refusal(runtime, serving, &context)?;
                return Ok(Resolution::unavailable("ReauthRequired"));
            }
            return Err(error);
        }
    };
    let sent_at = effects::wall_time()?;
    if sent_at < checked_dispatch {
        current_clock_refusal(runtime, serving, &context)?;
        current_uncertain(runtime, serving, &attempt)?;
        return Ok(Resolution::unavailable("ReauthRequired"));
    }
    if !admitted {
        return Ok(Resolution::unavailable("CapacityDeferred"));
    }
    let permit = permit.context("refresh dispatch permit missing")?;
    let monotonic = effects::Instant::now();
    let mut last_clock = sent_at;
    let result = permit.send(
        |bound| -> Result<Option<super::profiles::ValidatedTokenResponse>> {
            ensure!(bound == expected, "refresh dispatch material changed");
            serving.check()?;
            let wire = Wire::new()?;
            let response = wire
                .client
                .post(google::TOKEN)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", source.token()),
                    ("client_id", client.client.as_str()),
                    ("client_secret", client.secret.as_str()),
                ])
                .send()
                .map_err(|_| anyhow::anyhow!("OAuth refresh response unavailable; do not retry"))?;
            serving.check()?;
            let status = response.status().as_u16();
            let bytes = body(response)?;
            serving.check()?;
            if status == 400 {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Rejection {
                    error: String,
                    error_description: Option<String>,
                }
                let rejection: Rejection = crate::json::decode(&bytes)
                    .map_err(|_| anyhow::anyhow!("invalid OAuth refresh rejection"))?;
                ensure!(
                    rejection.error == "invalid_grant"
                        && rejection
                            .error_description
                            .as_ref()
                            .is_none_or(|text| text.len() <= 4096),
                    "unclassified OAuth refresh rejection"
                );
                return Ok(None);
            }
            ensure!(status == 200, "unclassified OAuth refresh response");
            let tokens = google::refresh_tokens(
                &bytes,
                &selection.reviewed,
                &selection.permission,
                source.token(),
            )?;
            let expiry = dispatch_at
                .checked_add(i64::try_from(tokens.lifetime())?)
                .context("OAuth refresh expiry overflow")?;
            let at = effects::wall_time()?;
            if at < last_clock || at >= expiry {
                anyhow::bail!("OAuth refresh response clock fence changed");
            }
            last_clock = at;
            let current = authority
                .current(
                    runtime.app(),
                    registration,
                    &request.context.actor,
                    at,
                    &mut SubjectReader::runtime(runtime, serving),
                )?
                .context("OAuth refresh readiness unavailable")?;
            ensure!(
                current.identity()? == selected,
                "OAuth refresh selection changed before account read"
            );
            let at = effects::wall_time()?;
            if at < last_clock || at >= expiry {
                anyhow::bail!("OAuth refresh account dispatch clock fence changed");
            }
            last_clock = at;
            serving.sql_read(runtime, |snapshot| {
                ensure!(
                    local_matches(&snapshot, &current, at)?,
                    "OAuth refresh authority changed before account read"
                );
                Ok(())
            })?;
            ensure!(
                monotonic.elapsed() <= BUDGET,
                "OAuth refresh account dispatch elapsed budget exceeded"
            );
            let mut authorization = reqwest::header::HeaderValue::from_str(&format!(
                "Bearer {}",
                tokens.refresh_access()
            ))?;
            authorization.set_sensitive(true);
            serving.check()?;
            let response = wire
                .client
                .get(google::USERINFO)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .send()
                .map_err(|_| anyhow::anyhow!("OAuth refresh account unavailable; do not retry"))?;
            ensure!(
                response.status().as_u16() == 200,
                "OAuth refresh account refused"
            );
            serving.check()?;
            let account = body(response)?;
            serving.check()?;
            let observed = google::observe_account(&account)?;
            ensure!(
                super::account::provider_account_digest(&observed)?.as_str() == expected.account,
                "OAuth refreshed account changed"
            );
            ensure!(
                monotonic.elapsed() <= BUDGET,
                "OAuth refresh elapsed budget exceeded"
            );
            Ok(Some(tokens))
        },
    );
    let tokens = match result {
        Ok(Some(tokens)) => tokens,
        Ok(None) => {
            serving.check()?;
            store::reject_current_refresh(runtime, serving, &attempt)?;
            serving.check()?;
            return Ok(Resolution::unavailable("ReauthRequired"));
        }
        Err(_) => {
            serving.refuse();
            // Dispatch already durably fenced this exact attempt. Once its
            // owner is refused, even relabeling that row is new SQL authority.
            // Keep may_have_been_sent: it already blocks use and redispatch.
            return Ok(Resolution::unavailable("ReauthRequired"));
        }
    };
    // Lifetime begins at the earliest dispatch fence, never at settlement.
    let expires_at = dispatch_at
        .checked_add(i64::try_from(tokens.lifetime())?)
        .context("OAuth refresh expiry overflow")?;
    let observed_at = effects::wall_time()?;
    if observed_at < last_clock || observed_at >= expires_at || monotonic.elapsed() > BUDGET {
        current_clock_refusal(runtime, serving, &context)?;
        current_uncertain(runtime, serving, &attempt)?;
        return Ok(Resolution::unavailable("ReauthRequired"));
    }
    let material = custody::prepare_replacement_tokens(
        &key,
        context.intent(),
        context.binding(),
        &expected.account,
        next,
        tokens,
        dispatch_at,
    )?;
    let base_reference = custody::token_reference(context.binding(), expected.base_version)?;
    let next_reference = custody::token_reference(context.binding(), next)?;
    let receipt = Digest::of(&(
        "oauth-product-refresh-committed-v1",
        &attempt,
        context.pin(),
        next,
        &base_reference,
        &next_reference,
    ))?
    .as_str()
    .to_owned();
    let mut prepared = Some(PreparedReplacement {
        attempt: attempt.clone(),
        next,
        receipt,
        base_reference,
        material,
    });
    let mut freshest = observed_at;
    let mut publication_clock_refused = false;
    serving.check()?;
    let publication = authority.with_current(
        runtime.app(),
        registration,
        &request.context.actor,
        observed_at,
        &mut SubjectReader::runtime(runtime, serving),
        &mut |current, subjects| {
            subjects.with_runtime(|serving| {
                if current.identity()? != selected {
                    return Ok(false);
                }
                Ok(store::publish_replacement(
                    runtime,
                    serving,
                    prepared
                        .take()
                        .context("refresh settlement already consumed")?,
                    |tx| {
                        let at = effects::wall_time()?;
                        if at < observed_at || at >= expires_at {
                            publication_clock_refused = true;
                            return Err(ClockRefusal.into());
                        }
                        ensure!(
                            monotonic.elapsed() <= BUDGET,
                            "refresh publication elapsed fence changed"
                        );
                        freshest = at;
                        local_matches(tx, current, at)
                    },
                )?
                .is_some())
            })
        },
    );
    serving.check()?;
    match publication {
        Ok(true) => Resolution::ready(&context, next, freshest),
        _ => {
            if publication_clock_refused {
                current_clock_refusal(runtime, serving, &context)?;
                current_uncertain(runtime, serving, &attempt)?;
            } else {
                current_uncertain(runtime, serving, &attempt)?;
                let at = effects::wall_time()?;
                if at < freshest || at >= expires_at {
                    current_clock_refusal(runtime, serving, &context)?;
                }
            }
            Ok(Resolution::unavailable("ReauthRequired"))
        }
    }
}

struct Wire {
    client: effects::Client,
}

impl Wire {
    fn new() -> Result<Self> {
        Ok(Self {
            client: effects::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(4))
                .build()?,
        })
    }
}

fn body(response: effects::Response) -> Result<Vec<u8>> {
    ensure!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|value| value.split(';').next() == Some("application/json")),
        "invalid OAuth refresh content type"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_RESPONSE as u64),
        "OAuth refresh response too large"
    );
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("OAuth refresh body unavailable; do not retry"))?;
    ensure!(
        bytes.len() <= MAX_RESPONSE,
        "OAuth refresh response too large"
    );
    Ok(bytes)
}
