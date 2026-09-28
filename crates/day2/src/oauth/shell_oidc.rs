//! Google OIDC step-up for the OAuth security shell. IAP identifies every
//! incoming request; this separate code flow proves a new authentication event.

use super::security_shell::{FreshAuthenticator, ReauthStart};
use crate::{iap, web_security};
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
        Ok(reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?
            .get(JWK_URL)
            .send()?
            .error_for_status()?
            .text()?)
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
    client_secret: String,
}

impl GoogleCodeExchange {
    pub(crate) fn new(client_secret: String) -> Result<Self> {
        ensure!(
            !client_secret.is_empty() && client_secret.len() <= 4096,
            "invalid OIDC client secret"
        );
        Ok(Self { client_secret })
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
        #[derive(Deserialize)]
        struct TokenResponse {
            id_token: String,
        }
        let response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()?
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", redirect_uri),
                ("code_verifier", verifier),
            ])
            .send()?
            .error_for_status()?;
        ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= 16_384),
            "OIDC token response too large"
        );
        let bytes = response.bytes()?;
        ensure!(bytes.len() <= 16_384, "OIDC token response too large");
        Ok(serde_json::from_slice::<TokenResponse>(&bytes)?.id_token)
    }
}

#[derive(Clone)]
struct Pending {
    attempt: String,
    challenge: Digest,
    iap_subject: String,
    iap_email: String,
    nonce: String,
    verifier: String,
    started_at: i64,
}

pub(crate) struct Reauthenticated {
    pub attempt: String,
    pub challenge: Digest,
    pub human: String,
    pub authenticated_at: i64,
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
        client_secret: String,
    ) -> Result<Self> {
        Ok(Self {
            iap: iap::Verifier::new(iap_audience, hosted_domain, Box::new(iap::GoogleKeys))?,
            oidc: GoogleOidc::new(
                client_id,
                hosted_domain.to_owned(),
                shell_origin,
                Box::new(GoogleCodeExchange::new(client_secret)?),
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
        attempt: &str,
        challenge: &Digest,
        now: i64,
    ) -> Result<ReauthStart> {
        Ok(ReauthStart::Redirect(
            self.oidc.begin(identity, attempt, challenge, now)?,
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
        attempt: &str,
        challenge: &Digest,
        now: i64,
    ) -> Result<String> {
        ensure!(
            attempt.len() <= 128 && !attempt.is_empty(),
            "invalid OIDC attempt"
        );
        let state = web_security::random()?;
        let nonce = web_security::random()?;
        let verifier = web_security::random()?;
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let pending = Pending {
            attempt: attempt.to_owned(),
            challenge: challenge.clone(),
            iap_subject: identity.subject.clone(),
            iap_email: identity.email.clone(),
            nonce: nonce.clone(),
            verifier,
            started_at: now,
        };
        {
            let mut attempts = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("OIDC state unavailable"))?;
            attempts.retain(|_, pending| {
                now >= pending.started_at && now - pending.started_at <= ATTEMPT_SECONDS
            });
            ensure!(attempts.len() < MAX_ATTEMPTS, "OIDC state capacity reached");
            attempts.insert(Digest::new(state.as_bytes()).as_str().to_owned(), pending);
        }
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
        Ok(url.into())
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
            attempt: pending.attempt,
            challenge: pending.challenge,
            human: identity.email.clone(),
            authenticated_at: claims.auth_time,
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
mod tests {
    use super::*;

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
    fn shell_requires_iap_assertion_before_starting_google_step_up() {
        let authenticator = GoogleFreshAuthenticator::new(
            "/projects/123/global/backendServices/456",
            "example.com",
            "https://security.example/",
            "123.apps.googleusercontent.com".into(),
            "test-only-client-secret".into(),
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
                "attempt_1",
                &Digest::of(&"pending").unwrap(),
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
                "attempt_1",
                &Digest::of(&"pending").unwrap(),
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
