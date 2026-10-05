//! Google IAP identity at the edge.
//!
//! IAP stands in front of every internal tool. It runs the Google sign-in, and
//! on every request it forwards to an application it attaches a signed JWT in
//! `x-goog-iap-jwt-assertion`. There is no login flow for the platform to run —
//! IAP already ran it — so the whole of the platform's job is to check the
//! signature and the claims, and to decide who the request is from.
//!
//! This follows the validator the existing fleet uses
//! (`GoLinks.Api/src/Middleware/IapAuthMiddleware.fs`) so that an application
//! accepts and refuses the same requests whichever generation serves it: the same
//! header, issuer, key set, audience source, required expiry, two-minute skew,
//! and the lowercased `email` claim as the principal. It is deliberately stricter
//! in four places, each of which is a way the old validator could be talked into
//! trusting something it should not:
//!
//! - **There is no way to turn verification off.** The old middleware honoured
//!   `ValidateJwt=false` and then believed a plain header. Here an instance
//!   either declares IAP and verifies every request, or does not declare it and
//!   serves only the local development sign-in.
//! - **Only ES256.** IAP signs with ES256 and publishes EC keys only. The old
//!   validator also accepted RS256, which no IAP assertion uses; accepting an
//!   algorithm nobody issues is surface without a purpose.
//! - **The hosted domain is checked**, from the installation rather than from
//!   each app. The old validator relied on the IAP access list alone.
//! - **An unknown key id refreshes the key set**, rather than waiting out an
//!   hour-long cache — so a rotation cannot produce an hour of refusals.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Mutex};

pub const ASSERTION_HEADER: &str = "x-goog-iap-jwt-assertion";
pub const ISSUER: &str = "https://cloud.google.com/iap";
pub const KEYS_URL: &str = "https://www.gstatic.com/iap/verify/public_key-jwk";

/// Tolerated disagreement between IAP's clock and ours. The old validator's.
const CLOCK_SKEW: i64 = 120;
/// How long a fetched key set is trusted without asking again.
const KEY_LIFETIME: i64 = 3_600;
/// The least time between two fetches, however many unknown key ids arrive. A
/// stream of assertions naming invented keys must not become a stream of
/// requests to Google on the forger's behalf.
const REFRESH_FLOOR: i64 = 60;
/// Real assertions are well under a kilobyte; this only bounds the parse.
const MAX_ASSERTION_BYTES: usize = 16_384;

/// Who a verified assertion says the request is from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The principal: the lowercased, trimmed `email` claim.
    pub email: String,
    /// Google's account id. Never reused, unlike the address — see
    /// `bind_subject`.
    pub subject: String,
}

/// A service account assertion verified for one IAP audience. This is kept
/// separate from a human principal: a workload never becomes an app actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    email: String,
    subject: String,
    audience: String,
}

impl Workload {
    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// Where the signing keys come from. Google in production; a fixed set in tests,
/// because a test that fetched real keys could only ever check real assertions.
pub trait KeySource: Send + Sync {
    fn fetch(&self) -> Result<String>;
}

pub struct GoogleKeys;

impl KeySource for GoogleKeys {
    fn fetch(&self) -> Result<String> {
        use std::io::Read;
        let response = crate::oauth::effects::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()?
            .get(KEYS_URL)
            .send()?
            .error_for_status()?;
        let mut bytes = Vec::new();
        response.take(65_537).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 65_536, "IAP key set too large");
        Ok(String::from_utf8(bytes)?)
    }
}

#[derive(Default)]
struct Cache {
    keys: BTreeMap<String, Vec<u8>>,
    fetched_at: Option<i64>,
    attempted_at: Option<i64>,
}

pub struct Verifier {
    audience: String,
    mode: Mode,
    source: Box<dyn KeySource>,
    cache: Mutex<Cache>,
}

enum Mode {
    Human { hosted_domain: String },
    Workload { email: String },
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    exp: i64,
    sub: String,
    email: String,
    #[serde(default)]
    hd: Option<String>,
}

#[derive(Deserialize)]
struct KeySet {
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct Key {
    kid: String,
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
}

fn refuse() -> anyhow::Error {
    anyhow::anyhow!(crate::error::Failure::InvalidIdentityAssertion)
}

impl Verifier {
    pub fn new(audience: &str, hosted_domain: &str, source: Box<dyn KeySource>) -> Result<Self> {
        ensure!(!audience.trim().is_empty(), "iap_audience_required");
        ensure!(!hosted_domain.trim().is_empty(), "hosted_domain_required");
        Ok(Self {
            audience: audience.to_owned(),
            mode: Mode::Human {
                hosted_domain: hosted_domain.to_ascii_lowercase(),
            },
            source,
            cache: Mutex::new(Cache::default()),
        })
    }

    pub fn for_workload(audience: &str, email: &str, source: Box<dyn KeySource>) -> Result<Self> {
        ensure!(!audience.trim().is_empty(), "iap_audience_required");
        let email = email.trim().to_ascii_lowercase();
        ensure!(
            email.ends_with(".gserviceaccount.com") && email.contains('@'),
            "iap_workload_email_required"
        );
        Ok(Self {
            audience: audience.to_owned(),
            mode: Mode::Workload { email },
            source,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// Check one assertion, as of `now`, and say who it is from.
    ///
    /// Every refusal is the same `invalid_identity_assertion`, so the edge
    /// tells a prober that it failed and not which check failed. The one
    /// exception is a key set that cannot be fetched, which is an outage on our
    /// side and reported as one.
    pub fn verify(&self, assertion: &str, now: i64) -> Result<Verified> {
        let Mode::Human { hosted_domain } = &self.mode else {
            return Err(refuse());
        };
        let claims = self.verify_claims(assertion, now)?;
        let email = claims.email.trim().to_ascii_lowercase();
        ensure!(!email.is_empty() && email.contains('@'), refuse());
        // A service account at the human front door has no person behind it.
        ensure!(
            !email.ends_with(".gserviceaccount.com"),
            crate::error::Failure::MachineCallerRequiresDelegation
        );
        ensure!(
            claims.hd.as_deref().map(str::to_ascii_lowercase).as_deref()
                == Some(hosted_domain.as_str())
                && email.ends_with(&format!("@{hosted_domain}")),
            refuse()
        );
        Ok(Verified {
            email,
            subject: claims.sub,
        })
    }

    pub fn verify_workload(&self, assertion: &str, now: i64) -> Result<Workload> {
        let Mode::Workload { email: expected } = &self.mode else {
            return Err(refuse());
        };
        let claims = self.verify_claims(assertion, now)?;
        let email = claims.email.trim().to_ascii_lowercase();
        ensure!(email == *expected, refuse());
        Ok(Workload {
            email,
            subject: claims.sub,
            audience: self.audience.clone(),
        })
    }

    fn verify_claims(&self, assertion: &str, now: i64) -> Result<Claims> {
        ensure!(assertion.len() <= MAX_ASSERTION_BYTES, refuse());
        let mut parts = assertion.split('.');
        let (Some(head), Some(body), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(refuse());
        };
        let header: Header =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(head).map_err(|_| refuse())?)
                .map_err(|_| refuse())?;
        ensure!(header.alg == "ES256", refuse());

        let key = self.key(&header.kid, now)?;
        let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| refuse())?;
        // The signed bytes are the two encoded segments exactly as they arrived,
        // never a re-encoding of what they decoded to.
        let signed = &assertion[..head.len() + 1 + body.len()];
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &key)
            .verify(signed.as_bytes(), &signature)
            .map_err(|_| refuse())?;

        // Claims are read only once the signature holds, so nothing below is
        // ever a decision made on an attacker's say-so.
        let claims: Claims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).map_err(|_| refuse())?)
                .map_err(|_| refuse())?;
        ensure!(claims.iss == ISSUER, refuse());
        // The audience is this application's backend service. An assertion
        // IAP issued for another application is valid, signed, and not for us.
        ensure!(claims.aud == self.audience, refuse());
        ensure!(now <= claims.exp + CLOCK_SKEW, refuse());
        ensure!(!claims.sub.trim().is_empty(), refuse());

        Ok(claims)
    }

    /// The public key a key id names, refreshing the set when it is stale or
    /// does not know the id — at most once per `REFRESH_FLOOR`.
    fn key(&self, kid: &str, now: i64) -> Result<Vec<u8>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!(crate::error::Failure::Internal))?;
        let fresh = cache
            .fetched_at
            .is_some_and(|at| now.saturating_sub(at) < KEY_LIFETIME);
        if fresh && let Some(key) = cache.keys.get(kid) {
            return Ok(key.clone());
        }
        let may_refresh = cache
            .attempted_at
            .is_none_or(|at| now.saturating_sub(at) >= REFRESH_FLOOR);
        if may_refresh {
            cache.attempted_at = Some(now);
            match self.source.fetch().and_then(|raw| parse_keys(&raw)) {
                Ok(keys) => {
                    cache.keys = keys;
                    cache.fetched_at = Some(now);
                }
                // Without any keys nothing can be verified, so an outage fails
                // closed. With stale keys, carry on: they still verify every
                // assertion signed by a key Google has not yet retired.
                Err(_) if cache.keys.is_empty() => {
                    return Err(anyhow::anyhow!(
                        crate::error::Failure::IdentityKeysUnavailable
                    ));
                }
                Err(_) => {}
            }
        }
        cache.keys.get(kid).cloned().ok_or_else(refuse)
    }
}

/// Hold an address to the account first seen with it.
///
/// An address is reassignable and a Google subject is not: when someone leaves
/// and their address is later given to someone else, IAP signs the newcomer's
/// assertions with the old address and a new subject. Admitting by address
/// alone would hand the newcomer everything recorded under the old owner —
/// their grants, their audit trail, their place in every reader and writer
/// list. So the first subject seen for an address is kept, and a different one
/// is refused until an operator decides the address has changed hands.
pub(crate) fn bind_subject(db: &rusqlite::Connection, verified: &Verified, now: i64) -> Result<()> {
    db.execute(
        "INSERT INTO day2_principals(email,subject,first_seen) VALUES(?1,?2,?3)
         ON CONFLICT(email) DO NOTHING",
        rusqlite::params![verified.email, verified.subject, now],
    )?;
    let bound: String = db.query_row(
        "SELECT subject FROM day2_principals WHERE email=?1",
        [&verified.email],
        |row| row.get(0),
    )?;
    ensure!(
        bound == verified.subject,
        crate::error::Failure::PrincipalSubjectChanged
    );
    Ok(())
}

/// The EC P-256 keys in a JWK set, as uncompressed points.
fn parse_keys(raw: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let set: KeySet = serde_json::from_str(raw).context("identity key set")?;
    let mut keys = BTreeMap::new();
    for key in set.keys {
        if key.kty != "EC" || key.crv != "P-256" {
            continue;
        }
        let x = URL_SAFE_NO_PAD.decode(&key.x)?;
        let y = URL_SAFE_NO_PAD.decode(&key.y)?;
        ensure!(x.len() == 32 && y.len() == 32, "identity key coordinates");
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        keys.insert(key.kid, point);
    }
    ensure!(!keys.is_empty(), "identity key set has no usable keys");
    Ok(keys)
}

#[cfg(test)]
#[path = "iap_tests.rs"]
mod tests;
