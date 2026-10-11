//! Google OIDC step-up for the OAuth security shell. IAP identifies every
//! incoming request; this separate code flow proves a new authentication event.

use super::{
    approval_keys::{GcpSecretReader, GcpSecretVersion},
    fresh_auth::FreshIntent,
    security_shell::{FreshAuthenticator, ReauthStart},
};
use crate::iap;
use crate::oauth::effects;
use anyhow::{Context, Result, ensure};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
    time::Duration,
};

const AUTHORIZATION_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const JWK_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUER: &str = "https://accounts.google.com";
const MAX_ATTEMPTS: usize = 1024;
const ATTEMPT_SECONDS: i64 = 300;

pub(crate) trait KeySource: Send + Sync {
    fn fetch(&self) -> Result<String>;
}

pub(crate) struct GoogleKeys;

impl KeySource for GoogleKeys {
    fn fetch(&self) -> Result<String> {
        use std::io::Read;
        let response = effects::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()?
            .get(JWK_URL)
            .send()?
            .error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= 65_536),
            "OIDC key set too large"
        );
        let mut bytes = Vec::new();
        response.take(65_537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65_536, "OIDC key set too large");
        String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("invalid OIDC key set"))
    }
}

pub(crate) trait CodeExchange: Send + Sync {
    fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        client_id: &str,
    ) -> Result<String>;
}

pub(crate) struct GoogleCodeExchange {
    reader: GcpSecretReader,
    version: GcpSecretVersion,
    client: effects::Client,
    endpoint: url::Url,
}

impl GoogleCodeExchange {
    pub(super) fn new(reader: GcpSecretReader, version: GcpSecretVersion) -> Result<Self> {
        version.validate()?;
        Ok(Self {
            reader,
            version,
            endpoint: url::Url::parse(TOKEN_URL)?,
            client: effects::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(8))
                .build()?,
        })
    }

    fn send(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        client_id: &str,
    ) -> Result<String> {
        use std::io::Read;
        let secret = super::clients::credential(self.reader.load(&self.version)?)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("client_secret", secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
            ])
            .send()?;
        ensure!(response.status().is_success(), "OIDC exchange rejected");
        ensure!(
            response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .is_some_and(|value| value
                    .to_str()
                    .is_ok_and(|value| value.split(';').next() == Some("application/json"))),
            "invalid OIDC token response type"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= 16_384),
            "OIDC token response too large"
        );
        let mut bytes = Vec::new();
        response.take(16_385).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16_384, "OIDC token response too large");
        let value: serde_json::Value = crate::json::decode(&bytes)?;
        let token = value
            .get("id_token")
            .and_then(serde_json::Value::as_str)
            .context("OIDC ID token missing")?;
        ensure!(
            !token.is_empty() && token.len() <= 16_384,
            "invalid OIDC ID token"
        );
        Ok(token.into())
    }
}

impl CodeExchange for GoogleCodeExchange {
    fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        client_id: &str,
    ) -> Result<String> {
        self.send(code, verifier, redirect_uri, client_id)
            .map_err(|_| {
                anyhow::anyhow!("OIDC code exchange unavailable; start a new authentication")
            })
    }
}

#[derive(Clone)]
struct Pending {
    intent: FreshIntent,
    iap_subject: String,
    iap_email: String,
    nonce: String,
    verifier: String,
    started_at: i64,
    started: effects::Instant,
    location: String,
}

pub(crate) struct Reauthenticated {
    intent: FreshIntent,
    human: String,
    subject: String,
    authenticated_at: i64,
    provider_expires_at: i64,
    started_at: i64,
    started: effects::Instant,
    lifetime: Mutex<Lifetime>,
    #[cfg(test)]
    isolated_fixture: bool,
}

struct Lifetime {
    wall: i64,
    observed: effects::Instant,
    refused: bool,
}

impl Reauthenticated {
    pub(in crate::oauth) fn intent(&self) -> &FreshIntent {
        &self.intent
    }

    pub(in crate::oauth) fn human(&self) -> &str {
        &self.human
    }

    pub(in crate::oauth) fn subject(&self) -> &str {
        &self.subject
    }

    pub(in crate::oauth) fn authenticated_at(&self) -> i64 {
        self.authenticated_at
    }

    pub(in crate::oauth) fn deadline(&self) -> Result<i64> {
        let deadline = self
            .authenticated_at
            .checked_add(ATTEMPT_SECONDS)
            .context("OIDC authentication time overflow")?
            .min(
                self.started_at
                    .checked_add(ATTEMPT_SECONDS)
                    .context("OIDC attempt time overflow")?,
            )
            .min(self.provider_expires_at);
        Ok(self
            .intent
            .deadline()
            .map_or(deadline, |pending| deadline.min(pending)))
    }

    pub(in crate::oauth) fn require_current(&self, now: i64) -> Result<()> {
        self.observe_current(now).map(|_| ())
    }

    pub(in crate::oauth) fn observe_current(&self, entry_now: i64) -> Result<i64> {
        let mut lifetime = self
            .lifetime
            .lock()
            .map_err(|_| anyhow::anyhow!("OIDC lifetime unavailable"))?;
        let result = (|| {
            ensure!(
                !lifetime.refused,
                "OIDC original lifetime permanently refused"
            );
            ensure!(
                entry_now >= self.authenticated_at,
                "OIDC request predates authentication"
            );
            #[cfg(test)]
            let now = if self.isolated_fixture {
                entry_now
            } else {
                effects::wall_time()?
            };
            #[cfg(not(test))]
            let now = effects::wall_time()?;
            // Existing OAuth Instant is a same-domain upper bound, not a suspend
            // clock or a mapping of Google's auth_time into a local clock domain.
            let observed = effects::Instant::now();
            ensure!(
                now >= lifetime.wall
                    && observed.checked_duration_since(lifetime.observed).is_some(),
                "OIDC original clock observation moved backwards or changed domain"
            );
            let elapsed = observed
                .checked_duration_since(self.started)
                .context("OIDC authentication clock changed")?;
            let budget = self
                .deadline()?
                .checked_sub(self.started_at)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .context("OIDC original lifetime invalid")?;
            ensure!(
                now >= entry_now
                    && self.authenticated_at >= self.started_at
                    && self.authenticated_at > self.intent.created_at()
                    && now >= self.authenticated_at
                    && now < self.deadline()?
                    && elapsed < Duration::from_secs(budget),
                "OIDC authentication expired or time changed"
            );
            Ok((now, observed))
        })();
        match result {
            Ok((now, observed)) => {
                lifetime.wall = now;
                lifetime.observed = observed;
                Ok(now)
            }
            Err(error) => {
                lifetime.refused = true;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(in crate::oauth) fn fixture(
        intent: FreshIntent,
        human: String,
        subject: String,
        authenticated_at: i64,
    ) -> Self {
        let started = effects::Instant::now();
        Self {
            intent,
            human,
            subject,
            authenticated_at,
            provider_expires_at: authenticated_at
                .checked_add(ATTEMPT_SECONDS)
                .expect("fixture lifetime overflow"),
            started_at: authenticated_at,
            started,
            lifetime: Mutex::new(Lifetime {
                wall: authenticated_at,
                observed: started,
                refused: false,
            }),
            isolated_fixture: true,
        }
    }
}

struct RsaKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Default)]
struct KeyCache {
    keys: BTreeMap<String, RsaKey>,
    fetched_at: Option<i64>,
    attempted_at: Option<i64>,
}

/// One shell OIDC client. Client credentials and key fetchers are host-owned;
/// neither the app nor a callback can choose issuer, audience, or redirect.
pub(crate) struct GoogleOidc {
    client_id: String,
    hosted_domain: String,
    redirect_uri: String,
    exchange: Box<dyn CodeExchange>,
    key_source: Box<dyn KeySource>,
    keys: Mutex<KeyCache>,
    pending: Mutex<HashMap<String, Pending>>,
}

/// Production shell adapter: a signed IAP assertion is required for every
/// request, and only the separate Google OIDC callback can create a fresh
/// authentication event for that same Google subject.
pub(crate) struct GoogleFreshAuthenticator {
    iap: iap::Verifier,
    oidc: GoogleOidc,
}

impl GoogleFreshAuthenticator {
    pub(crate) fn new(
        iap_audience: &str,
        hosted_domain: &str,
        shell_origin: &str,
        client_id: String,
        exchange: Box<dyn CodeExchange>,
    ) -> Result<Self> {
        Ok(Self {
            iap: iap::Verifier::new(iap_audience, hosted_domain, Box::new(iap::GoogleKeys))?,
            oidc: GoogleOidc::new(
                client_id,
                hosted_domain.to_owned(),
                shell_origin,
                exchange,
                Box::new(GoogleKeys),
            )?,
        })
    }
}

impl FreshAuthenticator for GoogleFreshAuthenticator {
    fn identify(&self, headers: &HeaderMap, now: i64) -> Result<iap::Verified> {
        let mut assertions = headers.get_all(iap::ASSERTION_HEADER).iter();
        let (Some(assertion), None) = (assertions.next(), assertions.next()) else {
            anyhow::bail!("security shell requires one IAP assertion");
        };
        self.iap.verify(assertion.to_str()?, now)
    }

    fn begin(
        &self,
        identity: &iap::Verified,
        intent: FreshIntent,
        now: i64,
    ) -> Result<ReauthStart> {
        Ok(ReauthStart::Redirect(
            self.oidc.begin(identity, intent, now)?,
        ))
    }

    fn complete(&self, query: &str, identity: &iap::Verified, now: i64) -> Result<Reauthenticated> {
        self.oidc.complete(query, identity, now)
    }
}

impl GoogleOidc {
    pub(crate) fn new(
        client_id: String,
        hosted_domain: String,
        shell_origin: &str,
        exchange: Box<dyn CodeExchange>,
        key_source: Box<dyn KeySource>,
    ) -> Result<Self> {
        let url = url::Url::parse(shell_origin)?;
        ensure!(
            url.scheme() == "https"
                && format!("{}/", url.origin().ascii_serialization()) == shell_origin,
            "OIDC shell origin must be canonical HTTPS"
        );
        ensure!(
            client_id.len() <= 255
                && client_id.ends_with(".apps.googleusercontent.com")
                && !hosted_domain.is_empty()
                && hosted_domain == hosted_domain.to_ascii_lowercase()
                && crate::artifact::dns_name(&hosted_domain),
            "invalid Google OIDC client or domain"
        );
        Ok(Self {
            client_id,
            hosted_domain,
            redirect_uri: format!("{shell_origin}_day2/reauth/callback"),
            exchange,
            key_source,
            keys: Mutex::new(KeyCache::default()),
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn callback_path() -> &'static str {
        "/_day2/reauth/callback"
    }

    /// Starts a new provider authentication after the account was quarantined.
    /// State, nonce and PKCE verifier never enter the app or provider callback URL.
    pub(crate) fn begin(
        &self,
        identity: &iap::Verified,
        intent: FreshIntent,
        now: i64,
    ) -> Result<String> {
        intent.require_identity(identity)?;
        let origin = url::Url::parse(&self.redirect_uri)?
            .origin()
            .ascii_serialization();
        intent.require_shell_origin(&origin)?;
        ensure!(
            intent.attempt().len() <= 128
                && !intent.attempt().is_empty()
                && now >= intent.created_at()
                && intent.deadline().is_none_or(|deadline| now < deadline),
            "invalid OIDC attempt"
        );
        let started = effects::Instant::now();
        let mut attempts = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("OIDC state unavailable"))?;
        attempts.retain(|_, pending| {
            now >= pending.started_at
                && now - pending.started_at <= ATTEMPT_SECONDS
                && started
                    .checked_duration_since(pending.started)
                    .is_some_and(|elapsed| elapsed <= Duration::from_secs(ATTEMPT_SECONDS as u64))
        });
        for pending in attempts.values() {
            if pending.intent.attempt() == intent.attempt() {
                ensure!(
                    pending.intent == intent,
                    "active Google pending purpose or context changed"
                );
                // Return the original state/nonce/PKCE link without resetting
                // either original lifetime or substituting a new intent.
                return Ok(pending.location.clone());
            }
        }
        ensure!(attempts.len() < MAX_ATTEMPTS, "OIDC state capacity reached");
        let state = effects::random()?;
        let nonce = effects::random()?;
        let verifier = effects::random()?;
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut url = url::Url::parse(AUTHORIZATION_URL)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("max_age", "0")
            .append_pair("claims", r#"{"id_token":{"auth_time":{"essential":true}}}"#)
            .append_pair("hd", &self.hosted_domain)
            .append_pair("login_hint", &identity.email);
        let location: String = url.into();
        attempts.insert(
            Digest::new(state.as_bytes()).as_str().to_owned(),
            Pending {
                intent,
                iap_subject: identity.subject.clone(),
                iap_email: identity.email.clone(),
                nonce,
                verifier,
                started_at: now,
                started,
                location: location.clone(),
            },
        );
        Ok(location)
    }

    /// Callback state is consumed before the code exchange. A failed exchange or
    /// verification cannot be retried with the same provider code or nonce.
    pub(crate) fn complete(
        &self,
        raw_query: &str,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Reauthenticated> {
        ensure!(raw_query.len() <= 4096, "OIDC callback too large");
        let mut fields = BTreeMap::new();
        for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
            ensure!(
                fields
                    .insert(key.into_owned(), value.into_owned())
                    .is_none(),
                "duplicate OIDC callback field"
            );
        }
        ensure!(
            fields.get("iss").map(String::as_str) == Some(ISSUER),
            "invalid OIDC callback issuer"
        );
        let state = fields.get("state").context("OIDC state missing")?;
        ensure!(token_shape(state), "invalid OIDC state");
        let code = fields.get("code").context("OIDC code missing")?;
        ensure!(!code.is_empty() && code.len() <= 2048, "invalid OIDC code");
        let pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("OIDC state unavailable"))?
            .remove(Digest::new(state.as_bytes()).as_str())
            .context("OIDC state expired or replayed")?;
        ensure!(
            now >= pending.started_at
                && now - pending.started_at <= ATTEMPT_SECONDS
                && effects::Instant::now()
                    .checked_duration_since(pending.started)
                    .is_some_and(|elapsed| elapsed <= Duration::from_secs(ATTEMPT_SECONDS as u64))
                && pending.iap_subject == identity.subject
                && pending.iap_email == identity.email,
            "OIDC identity or time changed"
        );
        let token =
            self.exchange
                .exchange(code, &pending.verifier, &self.redirect_uri, &self.client_id)?;
        let claims = self.verify_id_token(&token, &pending.nonce, identity, now)?;
        ensure!(
            claims.auth_time >= pending.started_at,
            "OIDC authentication predates shell challenge"
        );
        Ok(Reauthenticated {
            intent: pending.intent,
            human: pending.iap_email,
            subject: pending.iap_subject,
            authenticated_at: claims.auth_time,
            provider_expires_at: claims.exp,
            started_at: pending.started_at,
            started: pending.started,
            lifetime: Mutex::new(Lifetime {
                wall: now,
                observed: effects::Instant::now(),
                refused: false,
            }),
            #[cfg(test)]
            isolated_fixture: false,
        })
    }

    fn verify_id_token(
        &self,
        token: &str,
        nonce: &str,
        identity: &iap::Verified,
        now: i64,
    ) -> Result<Claims> {
        ensure!(token.len() <= 16_384, "OIDC ID token too large");
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            anyhow::bail!("invalid OIDC ID token");
        };
        let header: JwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?;
        ensure!(
            header.alg == "RS256" && !header.kid.is_empty() && header.kid.len() <= 128,
            "unsupported OIDC ID token signature"
        );
        let key = self.key(&header.kid, now)?;
        RsaPublicKeyComponents {
            n: &key.n,
            e: &key.e,
        }
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            &token.as_bytes()[..token.len() - signature.len() - 1],
            &URL_SAFE_NO_PAD.decode(signature)?,
        )
        .map_err(|_| anyhow::anyhow!("invalid OIDC ID token signature"))?;
        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
        ensure!(
            matches!(
                claims.iss.as_str(),
                "https://accounts.google.com" | "accounts.google.com"
            ) && claims.aud == self.client_id
                && claims.exp > now
                && claims.iat <= now + 30
                && now >= claims.iat
                && now - claims.iat <= ATTEMPT_SECONDS
                && claims.auth_time > 0
                && claims.auth_time <= now + 30
                && claims.auth_time <= claims.iat + 30
                && claims.nonce == nonce
                && claims.email_verified
                && claims.hd == self.hosted_domain
                && claims.email.to_ascii_lowercase() == identity.email
                && format!("accounts.google.com:{}", claims.sub) == identity.subject,
            "OIDC ID token does not prove this fresh IAP human"
        );
        Ok(claims)
    }

    fn key(&self, kid: &str, now: i64) -> Result<RsaKey> {
        let mut cache = self
            .keys
            .lock()
            .map_err(|_| anyhow::anyhow!("OIDC keys unavailable"))?;
        if cache
            .fetched_at
            .is_some_and(|at| now >= at && now - at < 3600)
            && let Some(key) = cache.keys.get(kid)
        {
            return Ok(RsaKey {
                n: key.n.clone(),
                e: key.e.clone(),
            });
        }
        if cache.attempted_at.is_none_or(|at| now >= at + 60) {
            cache.attempted_at = Some(now);
            let keys = parse_keys(&self.key_source.fetch()?)?;
            cache.keys = keys;
            cache.fetched_at = Some(now);
        }
        let key = cache.keys.get(kid).context("unknown OIDC signing key")?;
        Ok(RsaKey {
            n: key.n.clone(),
            e: key.e.clone(),
        })
    }
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    email: String,
    email_verified: bool,
    hd: String,
    exp: i64,
    iat: i64,
    nonce: String,
    auth_time: i64,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    alg: String,
    #[serde(default, rename = "use")]
    usage: String,
    n: String,
    e: String,
}

fn parse_keys(raw: &str) -> Result<BTreeMap<String, RsaKey>> {
    ensure!(raw.len() <= 65_536, "OIDC key set too large");
    let set: JwkSet = serde_json::from_str(raw)?;
    ensure!(
        !set.keys.is_empty() && set.keys.len() <= 16,
        "invalid OIDC key set"
    );
    let mut keys = BTreeMap::new();
    for key in set.keys {
        if key.kty != "RSA"
            || (!key.alg.is_empty() && key.alg != "RS256")
            || (!key.usage.is_empty() && key.usage != "sig")
        {
            continue;
        }
        ensure!(
            !key.kid.is_empty() && key.kid.len() <= 128,
            "invalid OIDC key id"
        );
        let n = URL_SAFE_NO_PAD.decode(key.n)?;
        let e = URL_SAFE_NO_PAD.decode(key.e)?;
        ensure!(
            (256..=1024).contains(&n.len()) && (1..=8).contains(&e.len()),
            "invalid OIDC RSA key"
        );
        ensure!(
            keys.insert(key.kid, RsaKey { n, e }).is_none(),
            "duplicate OIDC signing key"
        );
    }
    ensure!(!keys.is_empty(), "no supported OIDC signing key");
    Ok(keys)
}

fn token_shape(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
pub(in crate::oauth) use signed_fixtures::fixture_login;

#[cfg(test)]
pub(in crate::oauth) use signed_fixtures::{ReplayLogin, ReplayProviderCounts};

#[cfg(test)]
mod signed_fixtures {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
        },
    };
    use std::sync::Arc;

    // Public, test-only 2048-bit RSA fixture from the previously reviewed Google
    // parser control. It is not an enrollment, provider or production key.
    const TEST_PKCS8: &[u8] = &[
        0x30, 0x82, 0x04, 0xbe, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa8, 0x30, 0x82, 0x04, 0xa4,
        0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xe2, 0xf9, 0xc3, 0x04, 0x8c, 0x18, 0x57,
        0x1c, 0x40, 0x98, 0x5c, 0x58, 0x3b, 0xb0, 0x69, 0x1e, 0x3f, 0xb8, 0x03, 0xa7, 0x01, 0xc7,
        0xfd, 0x3a, 0x2e, 0x26, 0xbe, 0x33, 0x2f, 0xbf, 0xcb, 0xdb, 0x5b, 0x2e, 0x5f, 0x55, 0x42,
        0x16, 0x8e, 0x9c, 0x75, 0x91, 0x21, 0x95, 0x22, 0x04, 0xbe, 0xbf, 0x1e, 0x62, 0x67, 0xe9,
        0x1f, 0x67, 0x49, 0xce, 0x06, 0xad, 0x2c, 0x30, 0xdc, 0x9c, 0x03, 0xa3, 0x1b, 0x0c, 0x06,
        0xdd, 0x12, 0xd1, 0xbd, 0x68, 0x07, 0xca, 0x33, 0x1e, 0x86, 0xf8, 0x1d, 0x7e, 0x57, 0x2f,
        0x36, 0x95, 0x88, 0x02, 0xeb, 0x52, 0x17, 0xc8, 0x97, 0xdc, 0x29, 0xb5, 0xc5, 0x4f, 0x01,
        0xcd, 0x29, 0xd9, 0x2c, 0xf5, 0xc0, 0x66, 0x3f, 0x78, 0xe8, 0xa0, 0x0d, 0x56, 0xa3, 0x44,
        0x73, 0x28, 0x26, 0x26, 0x38, 0x37, 0x18, 0x4f, 0x8a, 0xe3, 0xa5, 0x60, 0x04, 0x93, 0xdf,
        0x32, 0x6f, 0xc3, 0xaa, 0xe9, 0x5a, 0xa3, 0x07, 0xc6, 0xcb, 0x5e, 0x5e, 0x8d, 0xec, 0x04,
        0x80, 0xa1, 0xff, 0x52, 0x3e, 0x48, 0xe6, 0x2a, 0xa3, 0xf2, 0x41, 0xde, 0xa7, 0xba, 0xc1,
        0x9c, 0x22, 0xb5, 0xff, 0xf3, 0x99, 0x6b, 0xda, 0x9b, 0xc5, 0xa7, 0xb8, 0x41, 0xad, 0x19,
        0xee, 0xe1, 0xc2, 0x07, 0x84, 0xb4, 0x1b, 0xac, 0xff, 0x3c, 0xa7, 0x03, 0x9d, 0x2a, 0x38,
        0x43, 0x7f, 0x44, 0xd2, 0x3e, 0xf6, 0xf2, 0xb6, 0xee, 0x44, 0x5d, 0xc1, 0xab, 0xa6, 0x28,
        0xda, 0xf7, 0x44, 0x93, 0xa2, 0x7f, 0xa0, 0xe4, 0x19, 0x26, 0x8f, 0xd0, 0x55, 0x9a, 0xe0,
        0xb8, 0xc4, 0x5a, 0x55, 0x5e, 0xbb, 0x91, 0x99, 0xe0, 0x81, 0xf4, 0xcc, 0x85, 0x57, 0xd4,
        0xcc, 0x41, 0xeb, 0x36, 0x4a, 0xc1, 0xb0, 0xfe, 0x5d, 0x85, 0x9b, 0xdf, 0x37, 0xc7, 0x09,
        0x50, 0x1f, 0xbf, 0xd1, 0x61, 0x60, 0xa3, 0x44, 0x85, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
        0x82, 0x01, 0x01, 0x00, 0x9f, 0x0a, 0x04, 0xf5, 0x0d, 0xb9, 0x0c, 0x68, 0xb6, 0x76, 0x4b,
        0xd6, 0x63, 0x54, 0x94, 0x03, 0x67, 0x00, 0x68, 0x46, 0xc0, 0x3f, 0xc2, 0x96, 0xde, 0xb9,
        0xb4, 0xf2, 0x26, 0xd6, 0x0c, 0x60, 0x92, 0x7e, 0x66, 0xbc, 0x55, 0xc7, 0x7a, 0x7b, 0xf5,
        0x01, 0x11, 0x77, 0xee, 0xd3, 0x46, 0x58, 0xa2, 0x50, 0xaf, 0xa0, 0xb0, 0xa9, 0x6e, 0x14,
        0x97, 0xa7, 0x05, 0xdc, 0xe2, 0xe7, 0xca, 0xc0, 0xa1, 0xf6, 0x06, 0x65, 0x27, 0x87, 0xa1,
        0x60, 0xe0, 0x7c, 0x74, 0xdf, 0x42, 0x11, 0x5e, 0x91, 0x25, 0x43, 0xe6, 0xca, 0x55, 0xf8,
        0x3d, 0xad, 0x53, 0x0e, 0xf2, 0x21, 0x89, 0x74, 0x5d, 0x61, 0xa3, 0xd0, 0x7f, 0x2f, 0x36,
        0x8a, 0xa8, 0x1a, 0xbd, 0x04, 0xda, 0x73, 0x33, 0x85, 0x6e, 0x77, 0x4a, 0xfd, 0x69, 0xe5,
        0xc3, 0xe4, 0x0e, 0xfb, 0xc5, 0x45, 0x07, 0x9e, 0xc4, 0xf6, 0x5c, 0x20, 0x28, 0x4b, 0x42,
        0x9f, 0x87, 0xc9, 0xab, 0xf2, 0xe8, 0xd1, 0x17, 0x98, 0xdc, 0xaa, 0x62, 0x66, 0x05, 0xf4,
        0xd1, 0x66, 0x4f, 0xee, 0x82, 0xa6, 0xfd, 0xf5, 0xeb, 0x62, 0x2b, 0xac, 0x1d, 0x0a, 0x1f,
        0xfe, 0xbf, 0xa8, 0xd3, 0x57, 0x0f, 0x26, 0x65, 0xbd, 0x23, 0x98, 0x7f, 0xd0, 0xca, 0x4a,
        0x2f, 0x64, 0xee, 0x3f, 0xba, 0x1d, 0x57, 0xea, 0xdc, 0xb2, 0x76, 0xbe, 0xc2, 0x62, 0x3f,
        0x46, 0x95, 0x42, 0x63, 0xe1, 0x11, 0xcd, 0x5d, 0x38, 0x91, 0x41, 0x8d, 0x54, 0x81, 0xa7,
        0x3f, 0x48, 0xcb, 0xa8, 0x07, 0x63, 0x77, 0x32, 0x0c, 0xec, 0xed, 0x5a, 0xc9, 0xbf, 0xd1,
        0xc5, 0xc5, 0xc3, 0x40, 0x9d, 0x09, 0x75, 0x15, 0xd0, 0x06, 0xee, 0x7a, 0x95, 0xcf, 0x4f,
        0x6e, 0x41, 0xd1, 0xa6, 0xe1, 0x82, 0xf3, 0xf5, 0xb6, 0xfd, 0x8e, 0xb4, 0xdb, 0xaf, 0x68,
        0xed, 0xb0, 0xb9, 0x6a, 0x8d, 0x02, 0x81, 0x81, 0x00, 0xf4, 0x49, 0x43, 0x31, 0xaa, 0x2d,
        0xc3, 0x8f, 0x92, 0xfa, 0xab, 0x4e, 0xb2, 0x5c, 0x2c, 0x7d, 0x04, 0xc4, 0x9f, 0x8d, 0x3b,
        0x83, 0xd8, 0xa8, 0x1e, 0xcb, 0x76, 0x22, 0x2e, 0xd7, 0xb6, 0xf6, 0x7f, 0x01, 0xe6, 0x5f,
        0x44, 0xcc, 0x99, 0x2d, 0x14, 0x9c, 0x3e, 0x00, 0xff, 0xde, 0xf4, 0xa2, 0xb7, 0x17, 0x58,
        0x92, 0xf5, 0x79, 0x23, 0x47, 0x7e, 0xa4, 0x3b, 0xed, 0x2a, 0xf4, 0x56, 0x99, 0x65, 0x27,
        0x83, 0xc2, 0xcc, 0xc6, 0x05, 0x19, 0xf0, 0xaf, 0x85, 0x97, 0x20, 0x88, 0xd2, 0x9a, 0x40,
        0x13, 0x40, 0xb0, 0x81, 0xb5, 0x96, 0x7f, 0x58, 0x1d, 0xfe, 0xd5, 0x13, 0xe7, 0xec, 0xc9,
        0xa6, 0xeb, 0xa3, 0xf7, 0xab, 0x72, 0x65, 0xa2, 0xaa, 0xec, 0xc1, 0xb0, 0x7a, 0x31, 0x0e,
        0xd6, 0x91, 0x08, 0xc2, 0xbb, 0x2a, 0xde, 0xc3, 0x29, 0xc4, 0x11, 0xeb, 0x1c, 0x8c, 0xa5,
        0xb0, 0x3b, 0x02, 0x81, 0x81, 0x00, 0xed, 0xdc, 0x00, 0xe4, 0x44, 0xc3, 0x5c, 0x0f, 0xb9,
        0x63, 0xde, 0xe5, 0xd9, 0x44, 0x9c, 0xae, 0x6d, 0xc6, 0x1c, 0xed, 0xcc, 0x82, 0x1b, 0xd4,
        0xd5, 0x9b, 0xb0, 0xca, 0x38, 0xda, 0xfe, 0xad, 0x0a, 0x2f, 0x60, 0x10, 0xb0, 0x30, 0x98,
        0x98, 0x11, 0xb6, 0x40, 0x52, 0x43, 0x33, 0x28, 0x50, 0x2c, 0x31, 0x91, 0x02, 0x2f, 0xe9,
        0x60, 0xde, 0x73, 0x71, 0x3e, 0xb8, 0x79, 0x0b, 0xf1, 0x5d, 0x70, 0x9b, 0x6f, 0x2e, 0x0b,
        0x63, 0xa0, 0xff, 0x23, 0xae, 0x6c, 0xae, 0xf5, 0x10, 0x99, 0x5c, 0xf8, 0x0c, 0xba, 0xce,
        0x5b, 0x46, 0x00, 0x2a, 0x5d, 0xd7, 0x89, 0x45, 0x37, 0x16, 0x0b, 0x08, 0x83, 0xa1, 0xc3,
        0x69, 0xbf, 0x36, 0xa7, 0x6f, 0x5f, 0x3a, 0x5b, 0xf3, 0x70, 0x97, 0xf2, 0xb3, 0xa4, 0x3a,
        0x3b, 0x7e, 0x3e, 0xc8, 0x90, 0xf8, 0xed, 0x4d, 0x70, 0xe6, 0xf7, 0x9e, 0x52, 0x3f, 0x02,
        0x81, 0x80, 0x0e, 0x93, 0xfc, 0xad, 0x8f, 0x11, 0x52, 0x15, 0x54, 0x59, 0x1f, 0x36, 0x00,
        0x10, 0xde, 0x1a, 0xcb, 0xd9, 0x0c, 0x08, 0x7a, 0x9f, 0xc0, 0xa3, 0x2f, 0xcb, 0x46, 0x8e,
        0x7d, 0xab, 0x23, 0xe1, 0x0b, 0xed, 0x4a, 0x19, 0x2f, 0x5a, 0xe2, 0x5d, 0x3d, 0x58, 0xa1,
        0x9e, 0x9f, 0xa6, 0x67, 0x84, 0xfa, 0x56, 0x2b, 0x54, 0x01, 0xd0, 0x2b, 0xd9, 0xcd, 0x65,
        0xf1, 0xa9, 0x92, 0xa1, 0xa8, 0x35, 0x59, 0x43, 0x05, 0x6a, 0xef, 0x9b, 0x75, 0x9c, 0x79,
        0xaf, 0x8f, 0xd2, 0x57, 0xff, 0xb2, 0x49, 0xc0, 0x3f, 0x25, 0xe2, 0x22, 0xab, 0x7a, 0x82,
        0xb8, 0xf8, 0x79, 0x47, 0xaf, 0xfb, 0x6c, 0x37, 0x10, 0x7e, 0x09, 0x77, 0xf3, 0x44, 0x4d,
        0x6a, 0x6a, 0xb6, 0xdc, 0x4c, 0x32, 0xce, 0x90, 0xab, 0x1f, 0x56, 0x9d, 0x80, 0x5b, 0xeb,
        0x95, 0x4b, 0xfd, 0xc6, 0x6f, 0xf8, 0x71, 0x30, 0x46, 0x17, 0x02, 0x81, 0x80, 0x4a, 0xe2,
        0x9d, 0xe1, 0x40, 0x08, 0xe5, 0x7e, 0x09, 0xd6, 0xf8, 0x81, 0x12, 0xc3, 0x38, 0x34, 0xee,
        0x58, 0x96, 0x19, 0x03, 0xee, 0xde, 0x86, 0x46, 0x6e, 0x0a, 0xdd, 0xcf, 0xc2, 0x9a, 0xb5,
        0xad, 0xe4, 0x36, 0x71, 0x6a, 0x97, 0x12, 0x23, 0xa6, 0x47, 0xe3, 0xbe, 0x42, 0x6b, 0xe3,
        0xc0, 0x41, 0xf9, 0xa4, 0xf6, 0xb4, 0x50, 0xdc, 0x6f, 0x8c, 0x96, 0xd5, 0xb1, 0x4c, 0x62,
        0xc7, 0x2d, 0xac, 0xdb, 0x32, 0xc8, 0xa3, 0x4b, 0x4d, 0x8f, 0xa6, 0x13, 0x2f, 0x22, 0x72,
        0x03, 0x34, 0xd5, 0x81, 0x3e, 0xb8, 0xbd, 0x69, 0x1d, 0x03, 0xc6, 0x52, 0xdf, 0x1d, 0xd7,
        0x8d, 0xbd, 0x41, 0xe1, 0xff, 0x57, 0x39, 0x67, 0x9c, 0x8c, 0xbf, 0x70, 0x1f, 0xe2, 0x06,
        0xbb, 0x00, 0xf2, 0xc5, 0xb5, 0x6a, 0xf9, 0xee, 0x6b, 0x13, 0xa7, 0x1f, 0x85, 0x4f, 0x68,
        0xb7, 0x27, 0xf0, 0x43, 0x87, 0x0f, 0x02, 0x81, 0x81, 0x00, 0xcc, 0x70, 0x22, 0xd0, 0x95,
        0xba, 0x27, 0xe5, 0x00, 0x0c, 0x8a, 0x76, 0xa9, 0x51, 0xdb, 0xb7, 0x66, 0x94, 0x1e, 0xac,
        0x7e, 0x14, 0x61, 0x5b, 0x8a, 0xe7, 0x38, 0xfc, 0x23, 0x51, 0xd3, 0xbd, 0x94, 0x4e, 0x7b,
        0xae, 0x6b, 0xd7, 0xe2, 0xcc, 0xa5, 0x77, 0xd7, 0xee, 0x0c, 0xcd, 0x85, 0x2c, 0xe1, 0xff,
        0xde, 0xea, 0x89, 0x4d, 0x19, 0xc7, 0xbf, 0x0c, 0x85, 0xbb, 0x90, 0x2e, 0xdb, 0x57, 0xa9,
        0x38, 0xe0, 0x3f, 0x28, 0x0a, 0x9a, 0x18, 0x55, 0x27, 0x32, 0x2c, 0x6d, 0x69, 0x6b, 0xbf,
        0xce, 0xcd, 0xb7, 0x14, 0xd2, 0xf8, 0xbb, 0x84, 0xa5, 0x4d, 0x42, 0xab, 0xa4, 0xf8, 0x75,
        0x02, 0x7c, 0x66, 0x4e, 0x34, 0x94, 0x83, 0x12, 0x58, 0xd1, 0x2d, 0x07, 0xfe, 0x30, 0x26,
        0xf9, 0x9a, 0x04, 0xdc, 0x3d, 0xb9, 0xea, 0x17, 0x74, 0x64, 0xe2, 0xd1, 0xdf, 0xc2, 0xb6,
        0xc1, 0x4c, 0x95,
    ];

    // Published ring 0.17.14 P-256 TEST vector, not company key material.
    // PKCS8 SHA256 d56f99994233d749d03315f5cb9797fad81d3e25f962d2cd543d4dfe7cdd1389.
    const REPLAY_IAP_PKCS8: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x57, 0x83, 0x29, 0xbf, 0xf0, 0x57, 0xbf, 0x48, 0xc8,
        0x4b, 0x9f, 0xc4, 0x62, 0x94, 0x0c, 0x57, 0xbb, 0x50, 0x9e, 0x77, 0xe4, 0x43, 0x22, 0x8d,
        0xbd, 0x62, 0x70, 0x54, 0xa1, 0xfc, 0xe2, 0x83, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xfc,
        0x11, 0x66, 0x98, 0xa3, 0xe3, 0x23, 0x65, 0x50, 0xc4, 0xc9, 0xef, 0xa9, 0xbd, 0x4d, 0x06,
        0x19, 0x60, 0x2a, 0x65, 0xd2, 0x93, 0x0e, 0x91, 0x50, 0xab, 0x33, 0xe8, 0x4d, 0xbc, 0x83,
        0xf8, 0xa6, 0xa6, 0xb9, 0x93, 0x3f, 0x35, 0xab, 0x59, 0x24, 0x5e, 0x5b, 0x5a, 0x7a, 0xf5,
        0xdc, 0xa7, 0x6b, 0x33, 0xcb, 0xe7, 0xae, 0xee, 0x59, 0x81, 0xb3, 0xca, 0x35, 0x0b, 0xeb,
        0xf5, 0x2e, 0xcd,
    ];
    const REPLAY_IAP_JWKS: &str = r#"{"keys":[{"alg":"ES256","crv":"P-256","kid":"owned-iap-replay-fixture","kty":"EC","use":"sig","x":"_BFmmKPjI2VQxMnvqb1NBhlgKmXSkw6RUKsz6E28g_g","y":"pqa5kz81q1kkXltaevXcp2szy-eu7lmBs8o1C-v1Ls0"}]}"#;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
    pub(in crate::oauth) struct ReplayProviderCounts {
        pub iap_keys: usize,
        pub google_keys: usize,
        pub exchanges: usize,
    }

    #[derive(Clone, PartialEq, Eq)]
    struct ReplayAuthorization {
        state: String,
        nonce: String,
        challenge: String,
        fields: BTreeMap<String, String>,
    }

    struct ReplayKeys {
        jwks: String,
        counts: Arc<Mutex<ReplayProviderCounts>>,
        iap: bool,
    }

    impl KeySource for ReplayKeys {
        fn fetch(&self) -> Result<String> {
            ensure!(!self.iap, "replay Google key role changed");
            self.counts.lock().unwrap().google_keys += 1;
            Ok(self.jwks.clone())
        }
    }

    impl iap::KeySource for ReplayKeys {
        fn fetch(&self) -> Result<String> {
            ensure!(self.iap, "replay IAP key role changed");
            self.counts.lock().unwrap().iap_keys += 1;
            Ok(self.jwks.clone())
        }
    }

    struct ReplayExchange {
        key: Arc<RsaKeyPair>,
        authorization: Arc<Mutex<Option<ReplayAuthorization>>>,
        counts: Arc<Mutex<ReplayProviderCounts>>,
        identity: iap::Verified,
        client: String,
        redirect: String,
        authenticated_at: i64,
        completed_at: i64,
        expires_at: i64,
    }

    impl CodeExchange for ReplayExchange {
        fn exchange(
            &self,
            code: &str,
            verifier: &str,
            redirect: &str,
            client: &str,
        ) -> Result<String> {
            ensure!(
                code == "signed-replay-code"
                    && token_shape(verifier)
                    && redirect == self.redirect
                    && client == self.client,
                "replay selected Google exchange changed"
            );
            let authorization = self
                .authorization
                .lock()
                .unwrap()
                .take()
                .context("replay authorization already consumed")?;
            ensure!(
                URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
                    == authorization.challenge,
                "replay original PKCE changed"
            );
            self.counts.lock().unwrap().exchanges += 1;
            let claims = serde_json::json!({
                "iss":ISSUER,"aud":client,
                "sub":self.identity.subject.strip_prefix("accounts.google.com:").context("replay Google subject")?,
                "email":self.identity.email,"email_verified":true,"hd":"example.com",
                "iat":self.completed_at,"exp":self.expires_at,
                "nonce":authorization.nonce,"auth_time":self.authenticated_at,
            });
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"owned-google-fixture"}"#),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
            );
            let mut signature = vec![0; self.key.public().modulus_len()];
            self.key
                .sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    signed.as_bytes(),
                    &mut signature,
                )
                .map_err(|_| anyhow::anyhow!("replay Google signature failed"))?;
            Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)))
        }
    }

    /// Fixed public keys and genuine signed parsers. The real mounted page must
    /// begin the authorization; this constructor creates no Pending or proof.
    pub(in crate::oauth) struct ReplayLogin {
        pub authenticator: Arc<GoogleFreshAuthenticator>,
        key: EcdsaKeyPair,
        audience: String,
        client: String,
        email: String,
        redirect: String,
        authorization: Arc<Mutex<Option<ReplayAuthorization>>>,
        original: Mutex<Option<ReplayAuthorization>>,
        counts: Arc<Mutex<ReplayProviderCounts>>,
        claim_identity: Digest,
        iap_claims: Mutex<Vec<Digest>>,
    }

    impl ReplayLogin {
        pub fn new(
            identity: &iap::Verified,
            audience: &str,
            client: &str,
            origin: &str,
            authenticated_at: i64,
            completed_at: i64,
            expires_at: i64,
        ) -> Result<Self> {
            let key = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                REPLAY_IAP_PKCS8,
                &SystemRandom::new(),
            )
            .map_err(|_| anyhow::anyhow!("published replay IAP vector invalid"))?;
            let point = key.public_key().as_ref();
            let expected: serde_json::Value = serde_json::from_str(REPLAY_IAP_JWKS)?;
            ensure!(
                point.len() == 65
                    && point[0] == 4
                    && Some(URL_SAFE_NO_PAD.encode(&point[1..33]).as_str())
                        == expected["keys"][0]["x"].as_str()
                    && Some(URL_SAFE_NO_PAD.encode(&point[33..65]).as_str())
                        == expected["keys"][0]["y"].as_str(),
                "published replay IAP public identity changed"
            );
            let rsa = Arc::new(
                RsaKeyPair::from_pkcs8(TEST_PKCS8)
                    .map_err(|_| anyhow::anyhow!("published replay Google vector invalid"))?,
            );
            let mut bytes = rsa.public_key().as_ref();
            let mut sequence = der(&mut bytes, 0x30)?;
            let modulus = der(&mut sequence, 0x02)?;
            let exponent = der(&mut sequence, 0x02)?;
            ensure!(
                bytes.is_empty() && sequence.is_empty(),
                "replay RSA extra fields"
            );
            let google_keys = serde_json::json!({"keys":[{"kid":"owned-google-fixture",
                "kty":"RSA","alg":"RS256","use":"sig",
                "n":URL_SAFE_NO_PAD.encode(modulus.strip_prefix(&[0]).unwrap_or(modulus)),
                "e":URL_SAFE_NO_PAD.encode(exponent)}]})
            .to_string();
            let counts = Arc::new(Mutex::new(ReplayProviderCounts::default()));
            let authorization = Arc::new(Mutex::new(None));
            let redirect = format!(
                "{}{}",
                url::Url::parse(origin)?.origin().ascii_serialization(),
                GoogleOidc::callback_path()
            );
            let oidc = GoogleOidc::new(
                client.into(),
                "example.com".into(),
                origin,
                Box::new(ReplayExchange {
                    key: rsa,
                    authorization: authorization.clone(),
                    counts: counts.clone(),
                    identity: identity.clone(),
                    client: client.into(),
                    redirect: redirect.clone(),
                    authenticated_at,
                    completed_at,
                    expires_at,
                }),
                Box::new(ReplayKeys {
                    jwks: google_keys,
                    counts: counts.clone(),
                    iap: false,
                }),
            )?;
            let authenticator = Arc::new(GoogleFreshAuthenticator {
                iap: iap::Verifier::new(
                    audience,
                    "example.com",
                    Box::new(ReplayKeys {
                        jwks: REPLAY_IAP_JWKS.into(),
                        counts: counts.clone(),
                        iap: true,
                    }),
                )?,
                oidc,
            });
            let claim_identity = Digest::of(&(
                "signed-replay-claim-inputs-v1",
                REPLAY_IAP_JWKS,
                Digest::new(TEST_PKCS8),
                identity.email.as_str(),
                identity.subject.as_str(),
                audience,
                client,
                redirect.as_str(),
                authenticated_at,
                completed_at,
                expires_at,
            ))?;
            Ok(Self {
                authenticator,
                key,
                audience: audience.into(),
                client: client.into(),
                email: identity.email.clone(),
                redirect,
                authorization,
                original: Mutex::new(None),
                counts,
                claim_identity,
                iap_claims: Mutex::new(Vec::new()),
            })
        }

        pub fn headers(&self, identity: &iap::Verified, now: i64) -> Result<HeaderMap> {
            let claims = serde_json::json!({"iss":"https://cloud.google.com/iap","aud":self.audience,
                "iat":now,"exp":now.checked_add(600).context("replay IAP expiry")?,
                "sub":identity.subject,"email":identity.email,"hd":"example.com"});
            let mut inputs = self.iap_claims.lock().unwrap();
            ensure!(inputs.len() < 16, "replay IAP input count budget");
            inputs.push(Digest::of(&("ES256", "owned-iap-replay-fixture", &claims))?);
            drop(inputs);
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"owned-iap-replay-fixture"}"#),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
            );
            let signature = self
                .key
                .sign(&SystemRandom::new(), signed.as_bytes())
                .map_err(|_| anyhow::anyhow!("replay IAP signature failed"))?;
            let mut headers = HeaderMap::new();
            headers.insert(
                iap::ASSERTION_HEADER,
                format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())).parse()?,
            );
            Ok(headers)
        }

        pub fn capture_authorization(&self, location: &str) -> Result<String> {
            let url = url::Url::parse(location)?;
            let expected = url::Url::parse(AUTHORIZATION_URL)?;
            ensure!(
                url.origin() == expected.origin()
                    && url.path() == expected.path()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "replay authorization origin/path"
            );
            let mut fields = BTreeMap::new();
            for (name, value) in url.query_pairs().into_owned() {
                ensure!(
                    fields.insert(name, value).is_none(),
                    "replay duplicate authorization field"
                );
            }
            ensure!(fields.len() == 12, "replay authorization field set");
            for (name, value) in [
                ("response_type", "code"),
                ("scope", "openid email"),
                ("client_id", self.client.as_str()),
                ("redirect_uri", self.redirect.as_str()),
                ("code_challenge_method", "S256"),
                ("max_age", "0"),
                ("claims", r#"{"id_token":{"auth_time":{"essential":true}}}"#),
                ("hd", "example.com"),
                ("login_hint", self.email.as_str()),
            ] {
                ensure!(
                    fields.get(name).map(String::as_str) == Some(value),
                    "replay original Google query changed"
                );
            }
            for name in ["state", "nonce", "code_challenge"] {
                ensure!(
                    fields.get(name).is_some_and(|value| token_shape(value)),
                    "replay original Google token shape"
                );
            }
            let current = ReplayAuthorization {
                state: fields.get("state").context("replay state")?.clone(),
                nonce: fields.get("nonce").context("replay nonce")?.clone(),
                challenge: fields.get("code_challenge").context("replay PKCE")?.clone(),
                fields,
            };
            let mut original = self.original.lock().unwrap();
            if let Some(previous) = original.as_ref() {
                ensure!(
                    *previous == current,
                    "replay original authorization replaced"
                );
            } else {
                *original = Some(current.clone());
                *self.authorization.lock().unwrap() = Some(current.clone());
            }
            Ok(url::form_urlencoded::Serializer::new(String::new())
                .append_pair("state", &current.state)
                .append_pair("code", "signed-replay-code")
                .append_pair("iss", ISSUER)
                .finish())
        }

        pub fn counts(&self) -> ReplayProviderCounts {
            *self.counts.lock().unwrap()
        }

        pub fn pending_count(&self) -> usize {
            self.authenticator.oidc.pending.lock().unwrap().len()
        }

        pub fn pending_intent(&self) -> Result<FreshIntent> {
            let pending = self.authenticator.oidc.pending.lock().unwrap();
            ensure!(
                pending.len() == 1,
                "replay needs exactly one original Google intent"
            );
            Ok(pending.values().next().unwrap().intent.clone())
        }

        /// Unsigned original claim inputs remain exact; random signatures and
        /// private wire strings never enter a public replay trace.
        pub fn authorization_identity(&self) -> Result<Digest> {
            let original = self.original.lock().unwrap();
            let original = original.as_ref().context("replay has no authorization")?;
            Digest::of(&(
                &self.claim_identity,
                &*self.iap_claims.lock().unwrap(),
                &self.client,
                &self.redirect,
                &original.fields,
            ))
        }
    }

    struct Keys(String);

    impl KeySource for Keys {
        fn fetch(&self) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    impl iap::KeySource for Keys {
        fn fetch(&self) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    struct Exchange {
        key: Arc<RsaKeyPair>,
        nonce: Arc<Mutex<Option<String>>>,
        identity: iap::Verified,
        authenticated_at: i64,
        completed_at: i64,
        expires_at: i64,
    }

    impl CodeExchange for Exchange {
        fn exchange(
            &self,
            code: &str,
            verifier: &str,
            redirect: &str,
            client: &str,
        ) -> Result<String> {
            ensure!(
                code == "signed-fixture-code"
                    && token_shape(verifier)
                    && redirect == "https://security.example.com/_day2/reauth/callback"
                    && client == "123.apps.googleusercontent.com",
                "fixture Google selection changed"
            );
            let nonce = self
                .nonce
                .lock()
                .unwrap()
                .take()
                .context("fixture nonce already consumed")?;
            let subject = self
                .identity
                .subject
                .strip_prefix("accounts.google.com:")
                .context("fixture Google subject missing")?;
            let claims = serde_json::json!({
                "iss": ISSUER, "aud": client, "sub": subject, "email": self.identity.email,
                "email_verified": true, "hd": "example.com",
                "iat": self.completed_at, "exp": self.expires_at,
                "nonce": nonce, "auth_time": self.authenticated_at,
            });
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"owned-google-fixture"}"#),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
            );
            let mut signature = vec![0; self.key.public().modulus_len()];
            self.key
                .sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    signed.as_bytes(),
                    &mut signature,
                )
                .map_err(|_| anyhow::anyhow!("fixture RSA signature failed"))?;
            Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)))
        }
    }

    fn der<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8]> {
        let (actual, rest) = input.split_first().context("fixture DER tag missing")?;
        ensure!(*actual == tag, "fixture DER tag mismatch");
        let (first, rest) = rest.split_first().context("fixture DER length missing")?;
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(*first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            ensure!(
                (1..=2).contains(&count) && rest.len() >= count,
                "fixture DER length budget"
            );
            (
                rest[..count]
                    .iter()
                    .fold(0usize, |size, byte| size * 256 + usize::from(*byte)),
                &rest[count..],
            )
        };
        ensure!(
            length <= 4096 && rest.len() >= length,
            "fixture DER content budget"
        );
        let (value, rest) = rest.split_at(length);
        *input = rest;
        Ok(value)
    }

    /// Uses the real IAP and Google signature parsers and the exact original
    /// begin/state/nonce/PKCE path. No test scalar proof enters the callback.
    /// Ephemeral IAP signing entropy makes these parser/conformance inputs
    /// nondeterministic; they are not seeded campaign or saved-replay evidence.
    pub(in crate::oauth) fn fixture_login(
        identity: &iap::Verified,
        intent: FreshIntent,
        started_at: i64,
        authenticated_at: i64,
        completed_at: i64,
    ) -> Result<(Arc<GoogleFreshAuthenticator>, HeaderMap, String)> {
        fixture_login_with_expiry(
            identity,
            intent,
            started_at,
            authenticated_at,
            completed_at,
            completed_at
                .checked_add(300)
                .context("fixture expiry overflow")?,
        )
    }

    pub(super) fn fixture_login_with_expiry(
        identity: &iap::Verified,
        intent: FreshIntent,
        started_at: i64,
        authenticated_at: i64,
        completed_at: i64,
        expires_at: i64,
    ) -> Result<(Arc<GoogleFreshAuthenticator>, HeaderMap, String)> {
        let key = Arc::new(
            RsaKeyPair::from_pkcs8(TEST_PKCS8)
                .map_err(|_| anyhow::anyhow!("public RSA fixture invalid"))?,
        );
        let mut bytes = key.public_key().as_ref();
        let mut sequence = der(&mut bytes, 0x30)?;
        ensure!(bytes.is_empty(), "fixture public key trailing bytes");
        let modulus = der(&mut sequence, 0x02)?;
        let exponent = der(&mut sequence, 0x02)?;
        ensure!(sequence.is_empty(), "fixture public key extra fields");
        let modulus = modulus.strip_prefix(&[0]).unwrap_or(modulus);
        let keys = serde_json::json!({"keys":[{
            "kid":"owned-google-fixture","kty":"RSA","alg":"RS256","use":"sig",
            "n":URL_SAFE_NO_PAD.encode(modulus),"e":URL_SAFE_NO_PAD.encode(exponent),
        }]})
        .to_string();
        let nonce = Arc::new(Mutex::new(None));
        let oidc = GoogleOidc::new(
            "123.apps.googleusercontent.com".into(),
            "example.com".into(),
            "https://security.example.com/",
            Box::new(Exchange {
                key,
                nonce: nonce.clone(),
                identity: identity.clone(),
                authenticated_at,
                completed_at,
                expires_at,
            }),
            Box::new(Keys(keys)),
        )?;
        let location = oidc.begin(identity, intent, started_at)?;
        let url = url::Url::parse(&location)?;
        let fields: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
        *nonce.lock().unwrap() = Some(fields["nonce"].clone());
        let callback = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("state", &fields["state"])
            .append_pair("code", "signed-fixture-code")
            .append_pair("iss", ISSUER)
            .finish();

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("fixture IAP key generation failed"))?;
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| anyhow::anyhow!("fixture IAP key invalid"))?;
        let point = pair.public_key().as_ref();
        let iap_keys = serde_json::json!({"keys":[{
            "kid":"owned-iap-fixture","kty":"EC","crv":"P-256","alg":"ES256","use":"sig",
            "x":URL_SAFE_NO_PAD.encode(&point[1..33]),"y":URL_SAFE_NO_PAD.encode(&point[33..65]),
        }]})
        .to_string();
        let audience = "/projects/123/global/backendServices/456";
        let claims = serde_json::json!({"iss":"https://cloud.google.com/iap","aud":audience,
            "iat":started_at,"exp":started_at.checked_add(600).context("fixture IAP expiry overflow")?,
            "sub":identity.subject,"email":identity.email,"hd":"example.com"});
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"owned-iap-fixture"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
        );
        let signature = pair
            .sign(&rng, signed.as_bytes())
            .map_err(|_| anyhow::anyhow!("fixture IAP signature failed"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            iap::ASSERTION_HEADER,
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())).parse()?,
        );
        let authenticator = Arc::new(GoogleFreshAuthenticator {
            iap: iap::Verifier::new(audience, "example.com", Box::new(Keys(iap_keys)))?,
            oidc,
        });
        Ok((authenticator, headers, callback))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_original_google_intent_reuse_completion_and_lifetime_are_owned() -> Result<()> {
        struct FixedClock {
            domain: u64,
            wall: i64,
            ticks: Duration,
        }
        impl effects::Hooks for FixedClock {
            fn domain(&self) -> u64 {
                self.domain
            }
            fn wall_time(&self) -> Result<i64> {
                Ok(self.wall)
            }
            fn monotonic(&self) -> Duration {
                self.ticks
            }
            fn fill(&self, _: &mut [u8]) -> Result<()> {
                anyhow::bail!("clock-only control has no entropy")
            }
            fn send(&self, _: reqwest::blocking::Request) -> Result<effects::Response> {
                anyhow::bail!("clock-only control has no HTTP provider")
            }
        }
        let clock = crate::oauth::simulation::World::new(901);
        clock.advance(95);
        effects::scope(clock.clone(), || {
            let identity = identity();
            let intent = FreshIntent::fixture_oauth(
                &identity,
                "original-purpose-attempt",
                &Digest::new(b"complete original challenge"),
                "https://security.example.com/",
            )?;
            let (authenticator, headers, callback) =
                fixture_login(&identity, intent.clone(), 100, 101, 101)?;
            let ReauthStart::Redirect(original) =
                authenticator.begin(&identity, intent.clone(), 100)?
            else {
                anyhow::bail!("Google begin bypassed actual authorization");
            };
            clock.advance(1);
            let ReauthStart::Redirect(reopened) =
                authenticator.begin(&identity, intent.clone(), 101)?
            else {
                anyhow::bail!("Google reuse bypassed actual authorization");
            };
            assert_eq!(original, reopened);
            let changed = FreshIntent::fixture_oauth(
                &identity,
                intent.attempt(),
                &Digest::new(b"changed complete original challenge"),
                "https://security.example.com/",
            )?;
            assert!(authenticator.begin(&identity, changed, 101).is_err());
            let verified = authenticator.identify(&headers, 101)?;
            let proof = super::super::fresh_auth::VerifiedAuthTime::from_google(
                authenticator.complete(&callback, &verified, 101)?,
            );
            proof.require_intent(&intent, &identity)?;
            proof.require_current(101)?;
            assert_eq!(proof.authenticated_at(), 101);
            assert_eq!(proof.subject(), identity.subject);
            assert_eq!(proof.deadline()?, 400); // Original begin, not completion +300.
            assert!(authenticator.complete(&callback, &verified, 101).is_err());
            let independent_proof = || -> Result<super::super::fresh_auth::VerifiedAuthTime> {
                let (authenticator, headers, callback) =
                    fixture_login(&identity, intent.clone(), 100, 101, 101)?;
                let verified = authenticator.identify(&headers, 101)?;
                Ok(super::super::fresh_auth::VerifiedAuthTime::from_google(
                    authenticator.complete(&callback, &verified, 101)?,
                ))
            };
            let predating_entry = independent_proof()?;
            assert!(predating_entry.require_current(100).is_err());
            let domain = effects::Hooks::domain(clock.as_ref());
            let ticks = effects::Hooks::monotonic(clock.as_ref());
            let healthy = std::sync::Arc::new(FixedClock {
                domain,
                wall: 101,
                ticks,
            });
            effects::scope(healthy, || proof.require_current(101))?;
            let expired = std::sync::Arc::new(FixedClock {
                domain,
                wall: 101,
                ticks: ticks
                    .checked_add(Duration::from_secs(300))
                    .context("clock control overflow")?,
            });
            let monotonic_proof = independent_proof()?;
            effects::scope(expired, || {
                assert!(monotonic_proof.require_current(101).is_err())
            });
            let other_domain = std::sync::Arc::new(FixedClock {
                domain: domain
                    .checked_add(1)
                    .context("clock domain control overflow")?,
                wall: 101,
                ticks,
            });
            let domain_proof = independent_proof()?;
            domain_proof.require_current(101)?;
            effects::scope(other_domain, || {
                assert!(domain_proof.require_current(101).is_err())
            });
            let expired_wall_proof = independent_proof()?;
            let forward = std::sync::Arc::new(FixedClock {
                domain,
                wall: 401,
                ticks,
            });
            effects::scope(forward, || {
                assert!(expired_wall_proof.require_current(101).is_err())
            });
            let rollback = std::sync::Arc::new(FixedClock {
                domain,
                wall: 102,
                ticks,
            });
            effects::scope(rollback, || {
                assert!(expired_wall_proof.require_current(101).is_err())
            });
            let rollback_proof = independent_proof()?;
            let later = std::sync::Arc::new(FixedClock {
                domain,
                wall: 103,
                ticks,
            });
            effects::scope(later, || {
                assert_eq!(rollback_proof.observe_current(101).unwrap(), 103)
            });
            let backwards = std::sync::Arc::new(FixedClock {
                domain,
                wall: 102,
                ticks,
            });
            effects::scope(backwards, || {
                assert!(rollback_proof.require_current(101).is_err())
            });
            let recovered_wall = std::sync::Arc::new(FixedClock {
                domain,
                wall: 104,
                ticks,
            });
            effects::scope(recovered_wall, || {
                assert!(rollback_proof.require_current(101).is_err())
            });
            Ok(())
        })
    }

    #[test]
    fn signed_google_callback_refuses_original_subject_substitution_and_expiry() -> Result<()> {
        for expired in [false, true] {
            let identity = identity();
            let intent = FreshIntent::fixture_oauth(
                &identity,
                "signed-current-owner",
                &Digest::new(b"signed current context"),
                "https://security.example.com/",
            )?;
            let (authenticator, _, callback) = fixture_login(&identity, intent, 100, 101, 101)?;
            let current = if expired {
                identity.clone()
            } else {
                iap::Verified {
                    email: identity.email.clone(),
                    subject: "accounts.google.com:replacement".into(),
                }
            };
            assert!(
                authenticator
                    .complete(&callback, &current, if expired { 401 } else { 101 })
                    .is_err()
            );
            assert!(authenticator.complete(&callback, &identity, 101).is_err());
        }
        Ok(())
    }

    #[test]
    fn signed_google_short_provider_expiry_bounds_original_session() -> Result<()> {
        let clock = crate::oauth::simulation::World::new(903);
        clock.advance(95);
        effects::scope(clock.clone(), || {
            let identity = identity();
            let intent = FreshIntent::fixture_oauth(
                &identity,
                "short-signed-proof",
                &Digest::new(b"short original proof"),
                "https://security.example.com/",
            )?;
            let (authenticator, headers, callback) = signed_fixtures::fixture_login_with_expiry(
                &identity,
                intent.clone(),
                100,
                101,
                101,
                103,
            )?;
            clock.advance(1);
            let identity = authenticator.identify(&headers, 101)?;
            let proof = super::super::fresh_auth::VerifiedAuthTime::from_google(
                authenticator.complete(&callback, &identity, 101)?,
            );
            proof.require_intent(&intent, &identity)?;
            assert_eq!(proof.deadline()?, 103);
            proof.require_current(101)?;
            clock.advance(1);
            assert_eq!(proof.observe_current(101)?, 102);
            clock.advance(1);
            assert!(proof.require_current(101).is_err()); // Stale entry time cannot bypass expiry.
            Ok(())
        })
    }

    #[test]
    fn oidc_reads_the_exact_credential_per_exchange_and_redacts_failures() -> Result<()> {
        use crate::oauth::registration::tests::{Server, TokensSource, secret_response};
        use std::sync::{Arc, atomic::AtomicUsize};
        let server = Server::new(vec![
            (200, secret_response().to_string()),
            (200, r#"{"id_token":"private-fixture-id-token"}"#.into()),
            (200, secret_response().to_string()),
            (
                400,
                r#"{"error_description":"private-fixture-client-canary"}"#.into(),
            ),
            (
                200,
                r#"{"name":"projects/12345/secrets/wrong/versions/7"}"#.into(),
            ),
        ])?;
        let reader = GcpSecretReader::fixture(
            &server.endpoint,
            Arc::new(TokensSource(AtomicUsize::new(0))),
        )?;
        let mut exchange = GoogleCodeExchange::new(
            reader,
            GcpSecretVersion {
                project_number: 12345,
                secret: "google_client_secret".into(),
                version: 7,
            },
        )?;
        exchange.endpoint = url::Url::parse(&server.endpoint)?.join("token")?;
        let client = "123-reauth.apps.googleusercontent.com";
        let callback = "https://security.example.com/_day2/reauth/callback";
        assert_eq!(
            exchange.exchange("private-code-1", &"v".repeat(43), callback, client)?,
            "private-fixture-id-token"
        );
        for code in ["private-code-2", "private-code-3"] {
            let error = exchange
                .exchange(code, &"v".repeat(43), callback, client)
                .unwrap_err();
            assert!(!format!("{error:#}").contains("private-fixture"));
        }
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 5);
        for request in [&requests[0], &requests[2], &requests[4]] {
            assert!(request.starts_with(
                "GET /v1/projects/12345/secrets/google_client_secret/versions/7:access "
            ));
        }
        for request in [&requests[1], &requests[3]] {
            let form: BTreeMap<_, _> =
                url::form_urlencoded::parse(request.split("\r\n\r\n").nth(1).unwrap().as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(form["client_id"], client);
            assert_eq!(form["redirect_uri"], callback);
            assert_eq!(form["client_secret"], "private-fixture-client-canary");
            assert_eq!(form["code_verifier"], "v".repeat(43));
        }
        Ok(())
    }

    const HEADER: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
    const PAYLOAD: &str = "eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiIxMjMuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTIyMzMiLCJlbWFpbCI6InBlcnNvbkBleGFtcGxlLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJoZCI6ImV4YW1wbGUuY29tIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDAsIm5vbmNlIjoiZml4dHVyZV9ub25jZSIsImF1dGhfdGltZSI6MTcwMDAwMDAwMH0";
    const SIGNATURE: &str = "m6swOxUdd_KfJM5l1uGZsRiiVRfU-ZWSgiOTzs-j6I8zKOMGpv0-fw5Op8lTW0ebM105OtGgAaezlJMZTOMGgjXzAbIdkVaDSH4rw6uakDwaqB5vW0wpPWqGfGYfDE3EY11zzMy974v7F2gCxX6W9DkGIjNCnlddLd0gsvqKtx2fmWx7M9Tsp1pCEIcLB7zF_JSdgEj3l5jpz7CLCJVQERlY9VO8fITrVtehQEhfCMUKSq-tEK4X5BHzJLrqOahh5TwoNUoZbrMJUazpYdlxMq2o2_WZndSLXimgTiSC2HJROYGJb2aDxJLxS4cuVK_rjfflDFbc2ZE2ujrS8P7eCQ";
    const MODULUS: &str = "uw1GEXK-BIhfQWMBg2vJPf5lzT9LBaKkObl1bRLPyem2EM__BjRCDQA_lwx5L1E3aAWUQ_LKyGvOZuvpAJUGjg6atUwrocl71fyepxY-E79wxwuGbtXoPqUbnNtz7nvTUnLT-rOySiEnAGyx4RdNK9UvWjd8kuu7wP8x3fAWdK2LKPq1lzrUgLtHnTeU5_s-q-99wD_BB80IbLY1YnDJPqadMDT-WrhGtX0F8sOeJTCjbBnjWzF5oN4FO0chv7W8oNISrT0UZJBaiqST0wlVZgHFQlrnxP1_9yJ4Y-E-N6bLMkvY0fbUsRw3pk0H9XgtY8IpujTGP2imuhW_WQwNpQ";

    struct FixedKeys;
    impl KeySource for FixedKeys {
        fn fetch(&self) -> Result<String> {
            Ok(serde_json::json!({"keys":[{"kid":"test-key","kty":"RSA","alg":"RS256","use":"sig","n":MODULUS,"e":"AQAB"}]}).to_string())
        }
    }

    struct NoExchange;
    impl CodeExchange for NoExchange {
        fn exchange(&self, _: &str, _: &str, _: &str, _: &str) -> Result<String> {
            anyhow::bail!("exchange should not run")
        }
    }

    fn oidc() -> GoogleOidc {
        GoogleOidc::new(
            "123.apps.googleusercontent.com".into(),
            "example.com".into(),
            "https://security.example/",
            Box::new(NoExchange),
            Box::new(FixedKeys),
        )
        .unwrap()
    }

    fn identity() -> iap::Verified {
        iap::Verified {
            email: "person@example.com".into(),
            subject: "accounts.google.com:112233".into(),
        }
    }

    #[test]
    fn native_oidc_secret_token_keys_and_one_use_callbacks_replay_without_network() -> Result<()> {
        use crate::oauth::{
            effects,
            registration::tests::{TokensSource, secret_response},
            simulation::World,
        };
        use std::sync::{Arc, atomic::AtomicUsize};
        for seed in 0..8 {
            for fault in [None, Some(0), Some(1)] {
                let run = || -> Result<_> {
                    let world = World::new(seed);
                    world.script(
                        vec![
                            (200, secret_response().to_string()),
                            (200, r#"{"id_token":"private-fixture-id-token"}"#.into()),
                        ],
                        fault,
                    );
                    effects::scope(world.clone(), || {
                        let reader =
                            GcpSecretReader::new(Arc::new(TokensSource(AtomicUsize::new(0))))?;
                        let exchange = GoogleCodeExchange::new(
                            reader,
                            GcpSecretVersion {
                                project_number: 12345,
                                secret: "google_client_secret".into(),
                                version: 7,
                            },
                        )?;
                        let token = exchange.exchange(
                            "private-code",
                            &"v".repeat(43),
                            "https://security.example.com/_day2/reauth/callback",
                            "123.apps.googleusercontent.com",
                        );
                        assert_eq!(token.is_ok(), fault.is_none());
                        if let Err(error) = &token {
                            assert!(!format!("{error:#}").contains("private-fixture"));
                        }
                        let oidc = oidc();
                        let location = oidc.begin(
                            &identity(),
                            FreshIntent::fixture_oauth(
                                &identity(),
                                "attempt",
                                &Digest::of(&"pending")?,
                                "https://security.example/",
                            )?,
                            5,
                        )?;
                        let url = url::Url::parse(&location)?;
                        let state = url
                            .query_pairs()
                            .find(|(name, _)| name == "state")
                            .unwrap()
                            .1
                            .into_owned();
                        world.advance(300);
                        let callback = format!(
                            "state={state}&code=private-code&iss=https%3A%2F%2Faccounts.google.com"
                        );
                        assert!(
                            oidc.complete(&callback, &identity(), effects::wall_time()?)
                                .is_err()
                        );
                        assert!(oidc.pending.lock().unwrap().is_empty());
                        assert!(oidc.complete(&callback, &identity(), 5).is_err());
                        Ok((token.is_ok(), Digest::of(&location)?, world.requests()))
                    })
                };
                assert_eq!(run()?, run()?);
            }
            let world = World::new(seed);
            world.script(vec![(200, FixedKeys.fetch()?)], None);
            effects::scope(world.clone(), || -> Result<()> {
                let oidc = GoogleOidc::new(
                    "123.apps.googleusercontent.com".into(),
                    "example.com".into(),
                    "https://security.example.com/",
                    Box::new(NoExchange),
                    Box::new(GoogleKeys),
                )?;
                let token = format!("{HEADER}.{PAYLOAD}.{SIGNATURE}");
                assert_eq!(
                    oidc.verify_id_token(&token, "fixture_nonce", &identity(), 1_700_000_001)?
                        .auth_time,
                    1_700_000_000
                );
                assert!(
                    oidc.verify_id_token(&token, "wrong_nonce", &identity(), 1_700_000_001)
                        .is_err()
                );
                assert_eq!(world.requests().len(), 1);
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn shell_requires_iap_assertion_before_starting_google_step_up() {
        let authenticator = GoogleFreshAuthenticator::new(
            "/projects/123/global/backendServices/456",
            "example.com",
            "https://security.example/",
            "123.apps.googleusercontent.com".into(),
            Box::new(NoExchange),
        )
        .unwrap();
        assert!(
            authenticator
                .identify(&HeaderMap::new(), 1_700_000_001)
                .is_err()
        );
    }

    #[test]
    fn signed_google_id_token_binds_nonce_subject_and_actual_authentication_time() {
        let oidc = oidc();
        let token = format!("{HEADER}.{PAYLOAD}.{SIGNATURE}");
        let claims = oidc
            .verify_id_token(&token, "fixture_nonce", &identity(), 1_700_000_001)
            .unwrap();
        assert_eq!(claims.auth_time, 1_700_000_000);
        assert!(
            oidc.verify_id_token(&token, "different_nonce", &identity(), 1_700_000_001)
                .is_err()
        );
        assert!(
            oidc.verify_id_token(
                &token,
                "fixture_nonce",
                &iap::Verified {
                    email: "person@example.com".into(),
                    subject: "accounts.google.com:other".into(),
                },
                1_700_000_001
            )
            .is_err()
        );
        assert!(
            oidc.verify_id_token(&token, "fixture_nonce", &identity(), 1_700_000_400)
                .is_err()
        );
        let tampered = format!("{HEADER}.{PAYLOAD}.{}", "a".repeat(SIGNATURE.len()));
        assert!(
            oidc.verify_id_token(&tampered, "fixture_nonce", &identity(), 1_700_000_001)
                .is_err()
        );
    }

    #[test]
    fn authorization_request_uses_one_use_nonce_pkce_and_fresh_authentication_request() {
        let oidc = oidc();
        let url = oidc
            .begin(
                &identity(),
                FreshIntent::fixture_oauth(
                    &identity(),
                    "attempt_1",
                    &Digest::of(&"pending").unwrap(),
                    "https://security.example/",
                )
                .unwrap(),
                1_700_000_000,
            )
            .unwrap();
        let url = url::Url::parse(&url).unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://accounts.google.com"
        );
        let params: BTreeMap<_, _> = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(params["max_age"], "0");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["redirect_uri"],
            "https://security.example/_day2/reauth/callback"
        );
        assert!(params["claims"].contains("auth_time"));
        assert!(!url.as_str().contains("attempt_1"));
        let callback = format!(
            "state={}&code=provider-code&iss=https%3A%2F%2Faccounts.google.com&scope=openid+email",
            params["state"]
        );
        assert!(
            oidc.complete(
                &callback,
                &iap::Verified {
                    email: "other@example.com".into(),
                    subject: "accounts.google.com:other".into(),
                },
                1_700_000_001
            )
            .is_err()
        );
        assert!(
            oidc.complete(&callback, &identity(), 1_700_000_001)
                .is_err()
        );
    }

    #[test]
    fn callback_accepts_google_scope_parameter_before_one_use_exchange() {
        let oidc = oidc();
        let url = oidc
            .begin(
                &identity(),
                FreshIntent::fixture_oauth(
                    &identity(),
                    "attempt_1",
                    &Digest::of(&"pending").unwrap(),
                    "https://security.example/",
                )
                .unwrap(),
                1_700_000_000,
            )
            .unwrap();
        let url = url::Url::parse(&url).unwrap();
        let state = url.query_pairs().find(|(key, _)| key == "state").unwrap().1;
        let callback = format!(
            "state={state}&code=provider-code&iss=https%3A%2F%2Faccounts.google.com&scope=openid+email"
        );
        assert!(
            oidc.complete(&callback, &identity(), 1_700_000_001)
                .err()
                .unwrap()
                .to_string()
                .contains("exchange should not run")
        );
        assert!(
            oidc.complete(&callback, &identity(), 1_700_000_001)
                .is_err()
        );
    }
}
