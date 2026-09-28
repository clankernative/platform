//! Signed webhook ingress: establishing that a request really came from a provider.
//!
//! Hold-gate scope. This verifies a signature over the bytes as received and
//! derives the invocation identity a delivery carries. It deliberately does not
//! declare endpoints, admit them, or route anything: the question it answers first
//! is whether a delivery can be refused before the application exists, and whether
//! a repeated delivery resolves to one identity.
//!
//! Verification lives in the host because the signing secret must never reach
//! application code, and because the signature covers the exact bytes received. A
//! body that has been parsed and re-serialised produces a different signature even
//! when it is semantically identical, so only the host — which holds the original
//! bytes — can check it.

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeMap;

/// Why a delivery was refused. Every refusal is typed: a webhook endpoint that
/// silently drops a delivery is indistinguishable from one that is working, and
/// the provider will simply retry into the same silence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The provider's timestamp header was absent or not an integer.
    Timestamp,
    /// The signature header was absent, or not `v0=` followed by hex.
    Signature,
    /// The timestamp is outside the replay tolerance.
    Stale,
    /// The signature does not match the body under this secret.
    Untrusted,
    /// The delivery carries no identifier and the endpoint supplies no derivation,
    /// so the delivery cannot be made exactly-once.
    Unidentified,
    /// The delivery verified but could not be recorded within [`ACCEPT_WAIT`];
    /// nothing was recorded, and the provider may redeliver it.
    Busy,
}

impl Refused {
    /// A short, non-revealing reason for the audit stream. It never says which
    /// part of a signature failed, because that answers an attacker's question.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timestamp => "ingress_timestamp",
            Self::Signature => "ingress_signature",
            Self::Stale => "ingress_stale",
            Self::Untrusted => "ingress_untrusted",
            Self::Unidentified => "ingress_unidentified",
            Self::Busy => "ingress_busy",
        }
    }
}

/// Ingress providers the host can verify deliveries for. An endpoint naming
/// anything else is refused at admission: the provider owns the signature scheme,
/// the envelope shape and the rule that identifies one delivery, so an unregistered
/// name has nobody to answer those.
/// Longest a verified delivery waits, for an execution permit and again for its
/// write turn, before the host answers busy. Twice this stays inside GitHub's
/// ten-second delivery timeout.
pub const ACCEPT_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

pub const PROVIDERS: &[&str] = &[
    "slack.events.v1",
    "slack.interactivity.v1",
    "github.webhook.v1",
    "gitea.actions.v1",
];

/// How a provider signs a delivery.
///
/// Signature schemes are not interchangeable, and the differences are not
/// cosmetic: they change what is signed. Slack signs `v0:{timestamp}:{body}` and
/// GitHub signs the body alone, so a verifier that assumed one shape rejects every
/// delivery from the other — with `Untrusted`, the refusal that looks like an
/// attack rather than like a bug.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// HMAC-SHA256 over `v0:{timestamp}:{body}`, hex, prefixed `v0=`.
    SlackV0,
    /// HMAC-SHA256 over the body alone, hex, prefixed `sha256=`.
    ///
    /// GitHub signs no timestamp, so there is no signed instant to measure
    /// staleness against and a captured delivery stays verifiable indefinitely.
    /// What bounds replay here is identity, not time: the delivery GUID is stable
    /// across GitHub's redeliveries, so a replay resolves to the invocation that
    /// already ran and is a reuse rather than a second invocation. That is a
    /// stronger guarantee than a tolerance window, and it is the same mechanism
    /// that makes Slack's own retries safe — but it holds only while the
    /// invocation record survives, where Slack's window holds unconditionally.
    GitHubSha256,
    /// Gitea signs the body with HMAC-SHA256, hex without a prefix.
    GiteaSha256,
}

/// Where the parts of a signature live on the wire, and how they combine.
///
/// The header names belong to the provider rather than to the route. A route that
/// named them itself would read Slack's headers for a GitHub delivery, find
/// nothing, and refuse every delivery from a correctly configured endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signing {
    pub scheme: Scheme,
    pub signature_header: &'static str,
    /// `None` for a provider that signs no timestamp.
    pub timestamp_header: Option<&'static str>,
}

/// How a registered provider signs. Host-owned, for the same reason identity is.
pub fn signing(provider: &str) -> anyhow::Result<Signing> {
    match provider {
        "slack.events.v1" | "slack.interactivity.v1" => Ok(Signing {
            scheme: Scheme::SlackV0,
            signature_header: "x-slack-signature",
            timestamp_header: Some("x-slack-request-timestamp"),
        }),
        "github.webhook.v1" => Ok(Signing {
            scheme: Scheme::GitHubSha256,
            signature_header: "x-hub-signature-256",
            timestamp_header: None,
        }),
        "gitea.actions.v1" => Ok(Signing {
            scheme: Scheme::GiteaSha256,
            signature_header: "x-gitea-signature",
            timestamp_header: None,
        }),
        other => anyhow::bail!("unregistered ingress provider: {other}"),
    }
}

/// Fail during configuration loading when the endpoint and credential profile disagree.
pub(crate) fn validate_connection(
    provider: &str,
    connection: &day2_capabilities::integrations::LiveConnection,
) -> anyhow::Result<()> {
    use day2_capabilities::integrations::LiveConnection;
    let compatible = matches!(
        (provider, connection),
        ("gitea.actions.v1", LiveConnection::GiteaActions { .. })
            | (
                "slack.events.v1" | "slack.interactivity.v1",
                LiveConnection::Slack { .. }
            )
            | ("github.webhook.v1", LiveConnection::GitHubActions { .. })
    );
    anyhow::ensure!(compatible, "endpoint_connection_provider_mismatch");
    connection.validate()?;
    anyhow::ensure!(
        connection.verification_ref().is_some(),
        "endpoint_connection_signing_secret_missing"
    );
    Ok(())
}

impl Scheme {
    /// Verify a signature over the bytes as received.
    ///
    /// `timestamp` is whatever the provider's timestamp header carried, and is
    /// `None` when it declares none. A scheme that signs a timestamp refuses a
    /// delivery without one rather than verifying a shorter basestring.
    pub fn verify(
        self,
        secret: &str,
        timestamp: Option<&str>,
        signature: &str,
        body: &[u8],
        now_seconds: i64,
    ) -> Result<(), Refused> {
        let (prefix, signed_timestamp) = match self {
            Self::SlackV0 => {
                let timestamp = timestamp.ok_or(Refused::Timestamp)?;
                let sent: i64 = timestamp.parse().map_err(|_| Refused::Timestamp)?;
                // Both directions: a timestamp far in the future is as suspect as a
                // stale one, and accepting it would widen the replay window
                // arbitrarily.
                if now_seconds.saturating_sub(sent).abs() > SLACK_TOLERANCE_SECONDS {
                    return Err(Refused::Stale);
                }
                ("v0=", Some(timestamp))
            }
            Self::GitHubSha256 => ("sha256=", None),
            Self::GiteaSha256 => ("", None),
        };
        let offered = signature.strip_prefix(prefix).ok_or(Refused::Signature)?;
        let offered = decode_hex(offered).ok_or(Refused::Signature)?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| Refused::Untrusted)?;
        if let Some(timestamp) = signed_timestamp {
            mac.update(b"v0:");
            mac.update(timestamp.as_bytes());
            mac.update(b":");
        }
        mac.update(body);
        // Constant time: verify_slice compares without an early exit, so a wrong
        // signature costs the same as a right one.
        mac.verify_slice(&offered).map_err(|_| Refused::Untrusted)
    }
}

/// Every endpoint is reached under this prefix, followed by its declared name.
pub const ROUTE_PREFIX: &str = "/ingress/";

/// The fields that together identify one Slack interaction. No single one is
/// enough: a message carries many actions, an action many users, and a user may
/// act more than once on different messages.
const SLACK_INTERACTION: &[&str] = &[
    "team.id",
    "container.message_ts",
    "actions.0.action_id",
    "user.id",
];

/// How a registered provider identifies one delivery. Host-owned, because the
/// identity has to be known before the application is involved.
pub fn identity_source(provider: &str) -> anyhow::Result<IdentitySource> {
    match provider {
        // Slack guarantees event_id is stable across its three retries.
        "slack.events.v1" => Ok(IdentitySource::PayloadField("event_id")),
        // Interactivity carries nothing durable of its own.
        "slack.interactivity.v1" => Ok(IdentitySource::Composite(SLACK_INTERACTION)),
        // GitHub's delivery GUID is stable across a redelivery — the same GUID is
        // reused when a delivery is replayed from the UI or the API — which is what
        // lets a redelivered webhook resolve to the invocation that already ran.
        "github.webhook.v1" => Ok(IdentitySource::Header("x-github-delivery")),
        // Gitea identifies an attempt. A redelivery may have a new UUID, so
        // domain commands must also deduplicate the underlying run/job.
        "gitea.actions.v1" => Ok(IdentitySource::Header("x-gitea-delivery")),
        other => anyhow::bail!("unregistered ingress provider: {other}"),
    }
}

/// An application may declare at most this many endpoints.
pub const MAXIMUM_ENDPOINTS: usize = 16;

/// Slack verifies that the timestamp is within five minutes of local time.
pub const SLACK_TOLERANCE_SECONDS: i64 = 300;

/// Verify a Slack request signature.
///
/// The basestring is `v0:{timestamp}:{body}` and the digest is HMAC-SHA256 under
/// the signing secret, hex encoded, prefixed `v0=`. `body` must be the bytes as
/// received.
pub fn verify_slack(
    secret: &str,
    timestamp: &str,
    signature: &str,
    body: &[u8],
    now_seconds: i64,
) -> Result<(), Refused> {
    Scheme::SlackV0.verify(secret, Some(timestamp), signature, body, now_seconds)
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || value.is_empty() {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(value.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Where a delivery's identity comes from. Declared by the provider, never by the
/// application, and there is no way to declare "none".
///
/// It is not uniform across providers: Slack's Events API supplies `event_id` and
/// GitHub supplies a delivery GUID, but Slack's interactivity payloads supply
/// nothing durable — `trigger_id` expires in three seconds and is single use. That
/// case is `Composite`, not an absence, because the fields that identify an
/// interaction do exist; no single one of them is enough.
///
/// Identity belongs to the provider because extracting it must happen **before**
/// the application is involved. An application-supplied derivation would be
/// application code running ahead of deduplication — so a replayed delivery would
/// execute it every time, weakening the ordering the hold gate establishes exactly
/// where it matters most.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentitySource {
    /// A header on the request, such as `x-github-delivery`.
    Header(&'static str),
    /// A field of the decoded payload, such as Slack's `event_id`.
    PayloadField(&'static str),
    /// Several payload fields together, for a provider whose deliveries carry no
    /// single durable identifier. The fields are named by the provider pack, which
    /// knows its own payload shape; an application cannot get this wrong because it
    /// never states it.
    Composite(&'static [&'static str]),
}

impl IdentitySource {
    /// The delivery identifier this source names, or `None` when the delivery does
    /// not carry it. A missing identifier is a refusal, never a generated
    /// substitute: inventing one would make every retry a fresh delivery.
    pub fn extract(self, headers: &BTreeMap<String, String>, payload: &Value) -> Option<String> {
        let field = |name: &str| -> Option<&str> {
            name.split('.')
                .try_fold(payload, |value, part| match part.parse::<usize>() {
                    // A numeric segment indexes an array: Slack's interaction
                    // payloads put the action under `actions.0`.
                    Ok(index) if value.is_array() => value.get(index),
                    _ => value.get(part),
                })?
                .as_str()
        };
        match self {
            Self::Header(name) => headers.get(name).map(String::as_str).map(str::to_owned),
            Self::PayloadField(name) => field(name).map(str::to_owned),
            Self::Composite(names) => {
                // Every named field must be present. A composite missing one of its
                // parts is not a weaker identity, it is a different one, and two
                // deliveries could collide on it.
                let parts = names
                    .iter()
                    .map(|name| field(name))
                    .collect::<Option<Vec<_>>>()?;
                Some(parts.join("."))
            }
        }
    }
}

/// An endpoint as an application declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub app: String,
    pub name: String,
    pub operation: String,
    /// What the provider supplies. Not an application decision.
    pub provider_identity: IdentitySource,
    /// How the provider signs, and where the parts are. Also not an application
    /// decision, and paired with `provider_identity` so an endpoint cannot end up
    /// verifying as one provider while identifying as another.
    pub signing: Signing,
    /// The provider-owned command envelope, assembled only after verification.
    pub input: Input,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Payload,
    GiteaActions,
}

impl Input {
    pub fn for_provider(provider: &str) -> anyhow::Result<Self> {
        match provider {
            "slack.events.v1" | "slack.interactivity.v1" | "github.webhook.v1" => Ok(Self::Payload),
            "gitea.actions.v1" => Ok(Self::GiteaActions),
            other => anyhow::bail!("unregistered ingress provider: {other}"),
        }
    }

    pub fn validate(self, record: &crate::schema::Record) -> anyhow::Result<()> {
        if self == Self::GiteaActions {
            let expected = BTreeMap::from([
                ("delivery_id".to_owned(), crate::schema::Kind::Text),
                ("event_name".to_owned(), crate::schema::Kind::Text),
                ("owner".to_owned(), crate::schema::Kind::Text),
                ("repo".to_owned(), crate::schema::Kind::Text),
                ("action".to_owned(), crate::schema::Kind::Text),
                ("run_id".to_owned(), crate::schema::Kind::Integer),
                ("run_attempt".to_owned(), crate::schema::Kind::Integer),
            ]);
            anyhow::ensure!(
                record.fields == expected,
                "Gitea Actions input must contain delivery_id, event_name, owner, repo, action (Str), run_id and run_attempt (I64)"
            );
        }
        Ok(())
    }

    fn decode(
        self,
        delivery: &Delivery<'_>,
        payload: Value,
        identifier: &str,
    ) -> Result<Value, Refused> {
        match self {
            Self::Payload => Ok(payload),
            Self::GiteaActions => {
                let event = delivery
                    .headers
                    .get("x-gitea-event")
                    .ok_or(Refused::Unidentified)?;
                if event.is_empty()
                    || event.len() > 64
                    || !event.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
                    || identifier.is_empty()
                    || identifier.len() > 128
                    || !payload.is_object()
                {
                    return Err(Refused::Unidentified);
                }
                let (record, id_field) = match event.as_str() {
                    "workflow_run" => (payload.get("workflow_run"), "id"),
                    "workflow_job" => (payload.get("workflow_job"), "run_id"),
                    _ => return Err(Refused::Untrusted),
                };
                let record = record.ok_or(Refused::Untrusted)?;
                let run_id = record
                    .get(id_field)
                    .and_then(Value::as_i64)
                    .filter(|id| *id > 0)
                    .ok_or(Refused::Untrusted)?;
                let run_attempt = record
                    .get("run_attempt")
                    .and_then(Value::as_i64)
                    .filter(|id| *id >= 0)
                    .ok_or(Refused::Untrusted)?;
                let owner = payload
                    .pointer("/repository/owner/login")
                    .and_then(Value::as_str)
                    .ok_or(Refused::Untrusted)?;
                let repo = payload
                    .pointer("/repository/name")
                    .and_then(Value::as_str)
                    .ok_or(Refused::Untrusted)?;
                let action = payload
                    .get("action")
                    .and_then(Value::as_str)
                    .ok_or(Refused::Untrusted)?;
                if [owner, repo].iter().any(|v| {
                    v.is_empty()
                        || v.len() > 100
                        || *v == "."
                        || *v == ".."
                        || !v
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                }) || action.is_empty()
                    || action.len() > 64
                {
                    return Err(Refused::Untrusted);
                }
                // A webhook identifies what changed. The app reads authoritative
                // run/job state through its scoped Actions resource. Large user,
                // repository and step objects never become command input.
                Ok(serde_json::json!({
                    "delivery_id": identifier, "event_name": event, "owner": owner,
                    "repo": repo, "action": action, "run_id": run_id, "run_attempt": run_attempt,
                }))
            }
        }
    }
}

impl Endpoint {
    pub fn validate(&self) -> Result<(), String> {
        if self.app.is_empty() || self.name.is_empty() {
            return Err("an endpoint requires an application and a name".into());
        }
        // The name reaches the derived invocation identity, whose alphabet is
        // narrow; refuse it here rather than at the first delivery.
        for part in [&self.app, &self.name] {
            if !part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
            {
                return Err("endpoint names must use the invocation identifier alphabet".into());
            }
        }
        // Identity is no longer something an endpoint can get wrong: the source is
        // the provider's and `IdentitySource` has no "none" to choose. What the
        // provider does with a delivery that lacks its identifier is refuse it,
        // which `extract` expresses by returning None.
        Ok(())
    }

    /// The invocation identity a delivery resolves to. Derived rather than
    /// generated, so a provider's retry, a manual redelivery and a replay all
    /// resolve to the same identity and commit once.
    ///
    /// Delivery identifiers are provider-controlled input, so they are not trusted
    /// into the identity space unchecked: one that does not match the invocation
    /// alphabet is hashed, following the same rule as `audit::record_attempt`.
    pub fn identity(&self, delivery: &str) -> String {
        let safe = !delivery.is_empty()
            && delivery.len() <= 64
            && delivery
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte));
        let delivery = if safe {
            delivery.to_owned()
        } else {
            crate::digest(delivery.as_bytes())
                .trim_start_matches("sha256:")
                .chars()
                .take(32)
                .collect()
        };
        format!("ingress.{}.{}.{delivery}", self.app, self.name)
    }
}

/// Admit one verified delivery: check the signature over the bytes as received,
/// derive the identity the delivery resolves to, and hand it to the runtime.
///
/// This is the step a host route performs. It is written as a function so the hold
/// gate can drive it without an HTTP server, and so the order is explicit: nothing
/// reaches the runtime until the signature is established, which is what makes
/// "refused before the application exists" a property of the code rather than of
/// the route that happens to call it.
///
/// The command is admitted and left for the existing scheduler to drain. Providers
/// impose short response deadlines — Slack allows three seconds — so a delivery is
/// acknowledged by being accepted durably, never by being finished.
/// One delivery as received. The fields travel together because they are all the
/// same thing — the bytes and headers on the wire — and separating them invites
/// verifying one body while admitting another.
pub struct Delivery<'a> {
    /// The body exactly as received, before any parsing.
    pub body: &'a [u8],
    /// Request headers, lowercased.
    ///
    /// The signature and timestamp are read from here by the names the provider
    /// declares, rather than being picked out by the route and passed in. A route
    /// that chose them would have to know each provider's header names, and would
    /// read Slack's for a GitHub delivery — refusing every delivery from a
    /// correctly configured endpoint, as `Untrusted`.
    pub headers: &'a BTreeMap<String, String>,
}

/// What the instance bound to an endpoint: what it runs as, and the secret that
/// establishes the sender. An application chooses neither.
pub struct Binding<'a> {
    pub actor: &'a str,
    /// The signing secret. It never reaches application code.
    pub secret: &'a str,
}

/// Admit one verified delivery: check the signature over the bytes as received,
/// derive the identity the delivery resolves to, and hand it to the runtime.
///
/// The order is the point and is written out rather than left to the caller:
/// signature first, then identity, then the runtime. Nothing reaches the runtime
/// until the sender is established, which is what makes "refused before the
/// application exists" a property of this function rather than of whichever route
/// happens to call it.
///
/// The identity is extracted here, from the payload or headers, rather than
/// supplied. Letting an application derive it would be application code running
/// ahead of deduplication, so a replayed delivery would execute it on every
/// arrival — weakening the guarantee exactly where it matters most.
///
/// The command is admitted and left for the existing scheduler to drain. Providers
/// impose short response deadlines — Slack allows three seconds — so a delivery is
/// acknowledged by being accepted durably, never by being finished.
pub fn admit(
    runtime: &crate::store::Runtime,
    endpoint: &Endpoint,
    binding: &Binding<'_>,
    delivery: &Delivery<'_>,
    now_seconds: i64,
) -> Result<String, Refused> {
    endpoint.validate().map_err(|_| Refused::Unidentified)?;
    let header = |name: &str| delivery.headers.get(name).map(String::as_str);
    endpoint.signing.scheme.verify(
        binding.secret,
        endpoint.signing.timestamp_header.and_then(header),
        header(endpoint.signing.signature_header).unwrap_or_default(),
        delivery.body,
        now_seconds,
    )?;
    // Parsed only after the signature establishes the bytes are the provider's.
    let payload: Value = serde_json::from_slice(delivery.body).unwrap_or(Value::Null);
    let identifier = endpoint
        .provider_identity
        .extract(delivery.headers, &payload)
        .ok_or(Refused::Unidentified)?;
    let identity = endpoint.identity(&identifier);
    let input = endpoint.input.decode(delivery, payload, &identifier)?;
    // A repeated delivery resolves to the identity that already ran, so accepting
    // it again is a reuse rather than a second invocation.
    // Providers abandon a delivery after a short deadline (GitHub: ten seconds) and
    // do not retry on their own, so recording it may not wait out the full write
    // queue: a busy host answers 503 while the provider is still listening.
    crate::write_queue::bounded(ACCEPT_WAIT, || {
        runtime.accept_route(
            &endpoint.operation,
            binding.actor,
            &identity,
            &input,
            now_seconds,
            crate::audit::Trigger::Ingress,
        )
    })
    .map_err(|error| {
        if crate::error::classify(&error) == crate::error::Failure::StorageBusy {
            Refused::Busy
        } else {
            Refused::Untrusted
        }
    })?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The worked example published in Slack's request-verification guide.
    ///
    /// This is the one piece of evidence a signer written by the same hand as the
    /// verifier cannot supply. A signer built from the same misreading of the
    /// documentation — the wrong basestring order, or a re-serialised body — agrees
    /// with its verifier perfectly and fails against Slack. Only a vector produced
    /// by the provider settles it.
    const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    const TIMESTAMP: &str = "1531420618";
    const BODY: &str = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    const SIGNATURE: &str = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    /// Inside Slack's five-minute tolerance of the vector's timestamp.
    const NOW: i64 = 1_531_420_620;

    fn verify(signature: &str, body: &[u8], now: i64) -> Result<(), Refused> {
        verify_slack(SECRET, TIMESTAMP, signature, body, now)
    }

    #[test]
    fn the_published_slack_vector_verifies() {
        assert_eq!(verify(SIGNATURE, BODY.as_bytes(), NOW), Ok(()));
    }

    #[test]
    fn a_tampered_body_is_refused() {
        // One byte. The body still parses and still means almost the same thing.
        let tampered = BODY.replace("roadrunner", "roadrunnec");
        assert_eq!(
            verify(SIGNATURE, tampered.as_bytes(), NOW),
            Err(Refused::Untrusted)
        );
        // Truncation and extension are the same class.
        assert_eq!(
            verify(SIGNATURE, &BODY.as_bytes()[..BODY.len() - 1], NOW),
            Err(Refused::Untrusted)
        );
        assert_eq!(
            verify(SIGNATURE, format!("{BODY}&extra=1").as_bytes(), NOW),
            Err(Refused::Untrusted)
        );
    }

    #[test]
    fn a_body_that_was_parsed_and_rebuilt_is_refused() {
        // The mutation that catches the most likely implementation bug: reading the
        // body through a form parser and re-encoding it. Every field survives and
        // the request is semantically identical, but the bytes moved.
        let mut fields: Vec<&str> = BODY.split('&').collect();
        fields.sort();
        let rebuilt = fields.join("&");
        assert_ne!(rebuilt, BODY, "the fixture must not already be sorted");
        assert_eq!(
            verify(SIGNATURE, rebuilt.as_bytes(), NOW),
            Err(Refused::Untrusted)
        );
    }

    #[test]
    fn a_signature_from_another_secret_is_refused() {
        // A correctly formed signature, correctly computed — under the wrong key.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"another-workspaces-secret").unwrap();
        mac.update(format!("v0:{TIMESTAMP}:{BODY}").as_bytes());
        let forged = format!("v0={:x}", mac.finalize().into_bytes());
        assert_eq!(
            verify(&forged, BODY.as_bytes(), NOW),
            Err(Refused::Untrusted)
        );
    }

    #[test]
    fn a_stale_or_future_timestamp_is_refused_before_the_signature_is_checked() {
        // Replay protection does not depend on the signature being wrong: a
        // captured request carries a perfectly valid one. Offsets are measured from
        // the signed timestamp, not from an arbitrary "now".
        let signed: i64 = TIMESTAMP.parse().unwrap();
        for outside in [
            signed + SLACK_TOLERANCE_SECONDS + 1,
            signed - SLACK_TOLERANCE_SECONDS - 1,
        ] {
            assert_eq!(
                verify(SIGNATURE, BODY.as_bytes(), outside),
                Err(Refused::Stale),
                "now={outside}"
            );
        }
        // The boundary itself is inside the window, in both directions.
        for inside in [
            signed + SLACK_TOLERANCE_SECONDS,
            signed - SLACK_TOLERANCE_SECONDS,
        ] {
            assert_eq!(
                verify(SIGNATURE, BODY.as_bytes(), inside),
                Ok(()),
                "now={inside}"
            );
        }
    }

    #[test]
    fn a_malformed_signature_is_refused_without_being_mistaken_for_a_wrong_one() {
        for malformed in [
            "",
            "a2114d57", // no version prefix
            "v1=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
            "v0=", // empty digest
            "v0=zz114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
            "v0=a2114d5", // odd length
        ] {
            assert_eq!(
                verify(malformed, BODY.as_bytes(), NOW),
                Err(Refused::Signature),
                "{malformed:?}"
            );
        }
        for malformed in ["", "not-a-number", "1531420618.5"] {
            assert_eq!(
                verify_slack(SECRET, malformed, SIGNATURE, BODY.as_bytes(), NOW),
                Err(Refused::Timestamp),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn a_truncated_digest_does_not_verify_by_prefix() {
        // A verifier that compared only the bytes it was given would accept this.
        let short = &SIGNATURE[..SIGNATURE.len() - 2];
        assert_eq!(
            verify(short, BODY.as_bytes(), NOW),
            Err(Refused::Untrusted),
            "a prefix of a valid digest verified"
        );
    }

    /// The worked example published in GitHub's webhook-validation documentation.
    ///
    /// Same standard as the Slack vector above and for the same reason: a verifier
    /// and a signer written by one hand agree with each other about a wrong
    /// basestring. Only the provider's own vector settles what GitHub actually
    /// signs — here, the body alone, with no timestamp anywhere in it.
    const GITHUB_SECRET: &str = "It's a Secret to Everybody";
    const GITHUB_BODY: &str = "Hello, World!";
    const GITHUB_SIGNATURE: &str =
        "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    #[test]
    fn the_published_github_vector_verifies() {
        assert_eq!(
            Scheme::GitHubSha256.verify(
                GITHUB_SECRET,
                None,
                GITHUB_SIGNATURE,
                GITHUB_BODY.as_bytes(),
                0,
            ),
            Ok(())
        );
        // The body *alone* is what is signed, and that has to be pinned against a
        // timestamp being supplied rather than against one being absent. Every
        // call above passes None, so a scheme that quietly folded a timestamp into
        // its basestring would satisfy all of them — the mutation that proved this
        // test vacuous until it was added.
        assert_eq!(
            Scheme::GitHubSha256.verify(
                GITHUB_SECRET,
                Some("1531420618"),
                GITHUB_SIGNATURE,
                GITHUB_BODY.as_bytes(),
                0,
            ),
            Ok(()),
            "a supplied timestamp changed what GitHub's scheme signs"
        );
        // A tampered body is refused, so the vector is checking the signature
        // rather than the prefix.
        assert_eq!(
            Scheme::GitHubSha256.verify(GITHUB_SECRET, None, GITHUB_SIGNATURE, b"Hello, World?", 0),
            Err(Refused::Untrusted)
        );
    }

    #[test]
    fn a_scheme_does_not_verify_another_providers_signature() {
        // The failure this prevents is subtle: both schemes are HMAC-SHA256 over
        // the same secret and the same body, differing only in whether a timestamp
        // joins the basestring and in the prefix. A verifier that applied the wrong
        // one would refuse every delivery from a correctly configured endpoint, and
        // would report it as Untrusted — indistinguishable from an attack.
        assert_eq!(
            Scheme::SlackV0.verify(
                GITHUB_SECRET,
                Some("0"),
                GITHUB_SIGNATURE,
                GITHUB_BODY.as_bytes(),
                0,
            ),
            Err(Refused::Signature),
            "GitHub's prefix was accepted by Slack's scheme"
        );
        assert_eq!(
            Scheme::GitHubSha256.verify(SECRET, None, SIGNATURE, BODY.as_bytes(), NOW),
            Err(Refused::Signature),
            "Slack's prefix was accepted by GitHub's scheme"
        );
        // And with the prefix corrected, the digest still does not match, because
        // the basestrings genuinely differ.
        let restated = SIGNATURE.replace("v0=", "sha256=");
        assert_eq!(
            Scheme::GitHubSha256.verify(SECRET, None, &restated, BODY.as_bytes(), NOW),
            Err(Refused::Untrusted),
            "Slack's basestring verified under GitHub's scheme"
        );
    }

    #[test]
    fn a_scheme_that_signs_a_timestamp_refuses_a_delivery_without_one() {
        // Not a shorter basestring, and not a pass: dropping the timestamp header
        // must not quietly turn Slack's scheme into GitHub's.
        assert_eq!(
            Scheme::SlackV0.verify(SECRET, None, SIGNATURE, BODY.as_bytes(), NOW),
            Err(Refused::Timestamp)
        );
    }

    /// Every registered provider answers both host-owned questions.
    ///
    /// `PROVIDERS` is a hand-maintained list and the two answers are matches, so
    /// the list is what falls behind: a provider added here but not to `signing`
    /// admits an endpoint at artifact validation and then fails at the first
    /// delivery, in production, on someone else's webhook. Enumerating from the
    /// list rather than from a remembered set is the whole point.
    #[test]
    fn every_registered_provider_supplies_an_identity_and_a_signing_description() {
        for provider in PROVIDERS {
            let signing = signing(provider)
                .unwrap_or_else(|_| panic!("{provider} is registered but does not sign"));
            identity_source(provider)
                .unwrap_or_else(|_| panic!("{provider} is registered but identifies nothing"));
            // A scheme that signs a timestamp needs the header it is read from, or
            // it refuses every delivery with Timestamp.
            assert_eq!(
                matches!(signing.scheme, Scheme::SlackV0),
                signing.timestamp_header.is_some(),
                "{provider} disagrees with itself about signing a timestamp"
            );
            assert!(
                !signing.signature_header.is_empty()
                    && signing.signature_header.to_ascii_lowercase() == signing.signature_header,
                "{provider} names a signature header the route cannot find: {}",
                signing.signature_header
            );
        }
        // An unregistered name has nobody to answer either question.
        assert!(signing("github.webhook.v3").is_err());
        assert!(identity_source("github.webhook.v3").is_err());
    }

    #[test]
    fn endpoint_connection_configuration_fails_before_delivery() {
        use day2_capabilities::{integrations::LiveConnection, resources::VersionRef};
        let token = VersionRef {
            id: "gitea-token".into(),
            revision: 1,
        };
        let key = VersionRef {
            id: "gitea-signing".into(),
            revision: 1,
        };
        let connection = LiveConnection::GiteaActions {
            credential_ref: token.clone(),
            endpoint: "https://git.example.test".into(),
            signing_secret_ref: Some(key),
        };
        assert!(validate_connection("gitea.actions.v1", &connection).is_ok());
        assert!(
            validate_connection("slack.events.v1", &connection)
                .unwrap_err()
                .to_string()
                .contains("provider_mismatch")
        );
        assert!(validate_connection("github.webhook.v1", &connection).is_err());
        let missing_key = LiveConnection::GiteaActions {
            credential_ref: token,
            endpoint: "https://git.example.test".into(),
            signing_secret_ref: None,
        };
        assert!(
            validate_connection("gitea.actions.v1", &missing_key)
                .unwrap_err()
                .to_string()
                .contains("signing_secret_missing")
        );
    }

    #[test]
    fn gitea_verifies_unprefixed_hmac_and_projects_only_action_identifiers() {
        // The published GitHub vector uses the same HMAC basestring as Gitea.
        let digest = GITHUB_SIGNATURE.strip_prefix("sha256=").unwrap();
        assert_eq!(
            Scheme::GiteaSha256.verify(GITHUB_SECRET, None, digest, b"Hello, World!", 0),
            Ok(())
        );
        assert_eq!(
            Scheme::GiteaSha256.verify(GITHUB_SECRET, None, GITHUB_SIGNATURE, b"Hello, World!", 0),
            Err(Refused::Signature)
        );
        assert_eq!(
            Scheme::GiteaSha256.verify(GITHUB_SECRET, None, digest, b"changed", 0),
            Err(Refused::Untrusted)
        );
        let payload = json!({
            "action":"completed",
            "repository":{"owner":{"login":"example-org"},"name":"example-repo","description":"x".repeat(100_000)},
            "workflow_job":{"id":23,"run_id":7,"run_attempt":2}
        });
        let headers = BTreeMap::from([
            ("x-gitea-event".into(), "workflow_job".into()),
            ("x-gitea-delivery".into(), "attempt-one".into()),
        ]);
        let bytes = serde_json::to_vec(&payload).unwrap();
        let delivery = Delivery {
            body: &bytes,
            headers: &headers,
        };
        let envelope = Input::GiteaActions
            .decode(&delivery, payload.clone(), "attempt-one")
            .unwrap();
        assert_eq!(
            envelope,
            json!({
                "delivery_id":"attempt-one","event_name":"workflow_job","action":"completed",
                "owner":"example-org","repo":"example-repo","run_id":7,"run_attempt":2,
            })
        );
        assert!(envelope.to_string().len() < 1024);
        let mut malformed = payload;
        malformed["workflow_job"]["run_id"] = json!(0);
        assert_eq!(
            Input::GiteaActions.decode(&delivery, malformed, "attempt-one"),
            Err(Refused::Untrusted)
        );
    }

    #[test]
    fn a_github_delivery_is_identified_by_its_guid() {
        // GitHub reuses the GUID when a delivery is redelivered, which is what
        // makes a redelivery a reuse rather than a second invocation — and is the
        // only thing bounding replay, since GitHub signs no timestamp.
        let guid = "72d3162e-cc78-11e3-81ab-4c9367dc0958";
        let headers = BTreeMap::from([("x-github-delivery".to_owned(), guid.to_owned())]);
        assert_eq!(
            identity_source("github.webhook.v1")
                .expect("registered")
                .extract(&headers, &json!({})),
            Some(guid.to_owned())
        );
        // The GUID contains hyphens but no separators the identity space uses, so
        // it survives into the identity intact rather than being hashed.
        let endpoint = Endpoint {
            app: "ci".into(),
            name: "status".into(),
            operation: "ci.record".into(),
            provider_identity: identity_source("github.webhook.v1").expect("registered"),
            signing: signing("github.webhook.v1").expect("registered"),
            input: Input::Payload,
        };
        assert_eq!(endpoint.identity(guid), format!("ingress.ci.status.{guid}"));
    }

    fn endpoint(provider_identity: IdentitySource) -> Endpoint {
        Endpoint {
            app: "wsb".into(),
            name: "approvals".into(),
            operation: "slack.interactivity".into(),
            provider_identity,
            signing: signing("slack.interactivity.v1").expect("registered"),
            input: Input::Payload,
        }
    }

    /// The fields that identify one Slack interaction. No single one is enough:
    /// a message has many actions, an action has many users, and a user may act
    /// more than once on different messages.
    const INTERACTION: IdentitySource = IdentitySource::Composite(&[
        "team.id",
        "container.message_ts",
        "actions.0.action_id",
        "user.id",
    ]);

    #[test]
    fn a_provider_with_no_single_identifier_composes_one_from_the_payload() {
        // Slack's interactivity payloads carry nothing durable on their own. The
        // provider names the fields that together identify an interaction, so the
        // application never states an identity and cannot state a wrong one.
        let headers = BTreeMap::new();
        let interaction = |message: &str, action: &str, user: &str| {
            json!({
                "team": {"id": "T1DC2JH3J"},
                "container": {"message_ts": message},
                "actions": [{"action_id": action}],
                "user": {"id": user},
            })
        };

        let approve = interaction("1531420618.000100", "approve", "U2CERLKJA");
        let first = INTERACTION.extract(&headers, &approve).expect("identified");
        // The same interaction replayed is the same identity, which is the whole
        // reason a composite is needed rather than a timestamp.
        assert_eq!(INTERACTION.extract(&headers, &approve), Some(first.clone()));
        // Each field genuinely distinguishes: change any one and the identity moves.
        for other in [
            interaction("1531420618.000200", "approve", "U2CERLKJA"),
            interaction("1531420618.000100", "reject", "U2CERLKJA"),
            interaction("1531420618.000100", "approve", "UOTHERUSER"),
        ] {
            assert_ne!(INTERACTION.extract(&headers, &other), Some(first.clone()));
        }
        // A payload missing one part is refused rather than identified by the rest,
        // which would let two different interactions collide.
        let partial = json!({"team": {"id": "T1DC2JH3J"}, "user": {"id": "U2CERLKJA"}});
        assert_eq!(INTERACTION.extract(&headers, &partial), None);
    }

    #[test]
    fn a_header_or_payload_identifier_is_taken_as_it_is() {
        let payload = json!({"event_id": "Ev0PV52K21"});
        let headers = BTreeMap::from([(
            "x-github-delivery".to_owned(),
            "72d3162e-cc78-11e3-81ab-4c9367dc0958".to_owned(),
        )]);
        assert_eq!(
            IdentitySource::PayloadField("event_id").extract(&headers, &payload),
            Some("Ev0PV52K21".to_owned())
        );
        assert_eq!(
            IdentitySource::Header("x-github-delivery").extract(&headers, &payload),
            Some("72d3162e-cc78-11e3-81ab-4c9367dc0958".to_owned())
        );
        // Absent is a refusal, never a substitute: inventing an identifier would
        // make every retry a fresh delivery.
        assert_eq!(
            IdentitySource::PayloadField("missing").extract(&headers, &payload),
            None
        );
        assert_eq!(
            IdentitySource::Header("x-absent").extract(&headers, &payload),
            None
        );
    }

    #[test]
    fn an_endpoint_name_that_cannot_become_an_invocation_id_is_refused() {
        for name in ["", "slack approvals", "approvals:v2", "approvals/v2"] {
            let mut endpoint = endpoint(IdentitySource::PayloadField("event_id"));
            endpoint.name = name.into();
            assert!(endpoint.validate().is_err(), "{name:?}");
        }
    }

    #[test]
    fn one_delivery_resolves_to_one_identity_however_often_it_arrives() {
        let endpoint = endpoint(IdentitySource::PayloadField("event_id"));
        // Slack retries three times over six minutes with the same event_id; GitHub
        // reuses its GUID on redelivery for three days. Both must land on one id.
        let first = endpoint.identity("Ev0PV52K21");
        assert_eq!(first, endpoint.identity("Ev0PV52K21"));
        assert_ne!(first, endpoint.identity("Ev0PV52K22"));
        // And the result is usable as an invocation id.
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                && first.len() <= 128,
            "{first}"
        );
    }

    #[test]
    fn a_hostile_delivery_identifier_cannot_reach_the_identity_space() {
        let endpoint = endpoint(IdentitySource::Header("x-github-delivery"));
        // Provider-controlled input. A delivery id containing separators could
        // otherwise forge another endpoint's identity, or a schedule's.
        for hostile in [
            "../../schedule.reports.sweep.0001758067200000",
            "a.b.c",
            "with space",
            &"x".repeat(512),
            "",
        ] {
            let identity = endpoint.identity(hostile);
            assert!(
                identity
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                    && identity.len() <= 128,
                "{hostile:?} produced {identity}"
            );
            assert!(
                identity.starts_with("ingress.wsb.approvals."),
                "{hostile:?} escaped its endpoint"
            );
        }
        // Distinct hostile inputs stay distinct rather than colliding into one.
        assert_ne!(endpoint.identity("a.b.c"), endpoint.identity("a.b.d"));
    }
}
