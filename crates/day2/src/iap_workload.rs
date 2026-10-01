//! Native host credentials for explicitly selected IAP receiver URLs. IAM
//! Credentials holds the signing key; this adapter never discovers credentials.

use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{blocking::Client, header::HeaderValue, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::{Host, Url};

const IAM_ORIGIN: &str = "https://iamcredentials.googleapis.com/";
const MAX_RESPONSE: u64 = 16_384;

pub trait AccessTokens: Send + Sync {
    fn authorization(&self) -> Result<HeaderValue>;
}

pub struct BearerToken(String);

impl BearerToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedJwt {
    key_id: String,
    signed_jwt: String,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

/// Immutable host-selected allowlist. Unselected audiences are refused before
/// acquiring an access token or contacting IAM. Each entry gets a fresh JWT.
pub struct Signer {
    service_account: String,
    audiences: BTreeSet<Url>,
    iam: Url,
    client: Client,
    tokens: Arc<dyn AccessTokens>,
}

impl Signer {
    pub fn new(
        service_account: &str,
        audiences: BTreeSet<Url>,
        tokens: Arc<dyn AccessTokens>,
    ) -> Result<Self> {
        Self::with_iam(service_account, audiences, tokens, IAM_ORIGIN, false)
    }

    /// Explicit native conformance fixture: only loopback HTTP can replace IAM
    /// or a protected receiver. Production construction has no override.
    pub fn transport_fixture(
        service_account: &str,
        audiences: BTreeSet<Url>,
        tokens: Arc<dyn AccessTokens>,
        iam_origin: &str,
    ) -> Result<Self> {
        Self::with_iam(service_account, audiences, tokens, iam_origin, true)
    }

    fn with_iam(
        service_account: &str,
        audiences: BTreeSet<Url>,
        tokens: Arc<dyn AccessTokens>,
        iam_origin: &str,
        fixture: bool,
    ) -> Result<Self> {
        day2_capabilities::oauth::ShellTransport {
            service_account: service_account.into(),
        }
        .validate()?;
        ensure!(
            !audiences.is_empty() && audiences.len() <= 128,
            "invalid_iap_audience_budget"
        );
        for url in &audiences {
            ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.as_str().len() <= 2048
                    && !url.path().contains('%')
                    && ((url.scheme() == "https"
                        && url.port().is_none()
                        && matches!(url.host(), Some(Host::Domain(_))))
                        || (fixture && loopback(url))),
                "invalid_iap_receiver_url"
            );
        }
        let iam = Url::parse(iam_origin)?;
        ensure!(
            if fixture {
                loopback(&iam) && iam.path() == "/"
            } else {
                iam.as_str() == IAM_ORIGIN
            },
            "invalid_iam_signing_origin"
        );
        Ok(Self {
            service_account: service_account.into(),
            audiences,
            iam,
            tokens,
            client: Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()?,
        })
    }

    pub fn sign_for(&self, audience: &Url) -> Result<BearerToken> {
        ensure!(
            self.audiences.contains(audience),
            "iap_receiver_not_selected"
        );
        let at = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let claims = Claims {
            iss: self.service_account.clone(),
            sub: self.service_account.clone(),
            aud: audience.as_str().into(),
            iat: at,
            exp: at
                .checked_add(300)
                .ok_or_else(|| anyhow::anyhow!("invalid_iap_credential_time"))?,
        };
        let mut endpoint = self.iam.clone();
        endpoint.set_path(&format!(
            "/v1/projects/-/serviceAccounts/{}:signJwt",
            self.service_account
        ));
        let mut authorization = self.tokens.authorization()?;
        ensure!(
            authorization
                .to_str()
                .is_ok_and(|value| value
                    .strip_prefix("Bearer ")
                    .is_some_and(|token| !token.is_empty()
                        && token.len() <= 8192
                        && token.bytes().all(|b| b.is_ascii_graphic()))),
            "invalid_iap_access_token"
        );
        authorization.set_sensitive(true);
        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(
                &serde_json::json!({"payload":serde_json::to_string(&claims)?}),
            )?)
            .send()
            .map_err(|_| anyhow::anyhow!("iam_sign_jwt_unavailable"))?;
        ensure!(response.status().is_success(), "iam_sign_jwt_refused");
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("iam_sign_jwt_unavailable"))?;
        ensure!(
            bytes.len() as u64 <= MAX_RESPONSE,
            "iam_sign_jwt_response_too_large"
        );
        let signed: SignedJwt =
            crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("invalid_iam_signed_jwt"))?;
        validate_signed(&signed, &claims).map_err(|_| anyhow::anyhow!("invalid_iam_signed_jwt"))?;
        Ok(BearerToken(signed.signed_jwt))
    }
}

fn validate_signed(signed: &SignedJwt, claims: &Claims) -> Result<()> {
    ensure!(
        !signed.key_id.is_empty() && signed.key_id.len() <= 256 && signed.signed_jwt.len() <= 8192,
        "invalid_iam_signed_jwt"
    );
    let parts: Vec<_> = signed.signed_jwt.split('.').collect();
    ensure!(parts.len() == 3, "invalid_iam_signed_jwt");
    let header: JwtHeader = crate::json::decode(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let returned: Claims = crate::json::decode(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    ensure!(
        header.alg == "RS256"
            && header.kid == signed.key_id
            && returned == *claims
            && URL_SAFE_NO_PAD.decode(parts[2])?.len() >= 64,
        "invalid_iam_signed_jwt"
    );
    Ok(())
}

fn loopback(url: &Url) -> bool {
    url.scheme() == "http"
        && matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Tokens(AtomicUsize);
    impl AccessTokens for Tokens {
        fn authorization(&self) -> Result<HeaderValue> {
            self.0.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("no token should be requested")
        }
    }

    #[test]
    fn unselected_receivers_are_rejected_before_credentials() -> Result<()> {
        let tokens = Arc::new(Tokens(AtomicUsize::new(0)));
        let url = Url::parse("https://app.example/_day2/oauth/approval")?;
        let signer = Signer::new(
            "shell@company.iam.gserviceaccount.com",
            [url].into(),
            tokens.clone(),
        )?;
        for raw in [
            "https://app.example/",
            "https://other.example/_day2/oauth/approval",
            "https://app.example/_day2/oauth/approval?next=x",
        ] {
            assert!(signer.sign_for(&Url::parse(raw)?).is_err());
        }
        assert_eq!(tokens.0.load(Ordering::SeqCst), 0);
        for raw in [
            "http://app.example/_day2/oauth/approval",
            "https://app.example:444/_day2/oauth/approval",
            "https://app.example/_day2/oauth/approval?next=x",
            "https://person@app.example/_day2/oauth/approval",
            "https://app.example/_day2/oauth/%61pproval",
        ] {
            assert!(
                Signer::new(
                    "shell@company.iam.gserviceaccount.com",
                    [Url::parse(raw)?].into(),
                    tokens.clone()
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn returned_jwt_cannot_substitute_claims_keys_or_duplicate_fields() -> Result<()> {
        let claims = Claims {
            iss: "shell@company.iam.gserviceaccount.com".into(),
            sub: "shell@company.iam.gserviceaccount.com".into(),
            aud: "https://app.example/_day2/oauth/approval".into(),
            iat: 10,
            exp: 310,
        };
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"fixture"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signature = URL_SAFE_NO_PAD.encode([0; 64]);
        let signed = SignedJwt {
            key_id: "fixture".into(),
            signed_jwt: format!("{head}.{body}.{signature}"),
        };
        validate_signed(&signed, &claims)?;
        let mut changed = claims.clone();
        changed.aud = "https://other.example/_day2/oauth/approval".into();
        assert!(validate_signed(&signed, &changed).is_err());
        changed = claims.clone();
        changed.exp += 1;
        assert!(validate_signed(&signed, &changed).is_err());
        for head in [
            br#"{"alg":"RS256","kid":"other"}"#.as_slice(),
            br#"{"alg":"none","kid":"fixture"}"#,
            br#"{"alg":"none","alg":"RS256","kid":"fixture"}"#,
        ] {
            let signed = SignedJwt {
                key_id: "fixture".into(),
                signed_jwt: format!("{}.{body}.{signature}", URL_SAFE_NO_PAD.encode(head)),
            };
            assert!(validate_signed(&signed, &claims).is_err());
        }
        assert!(
            crate::json::decode::<SignedJwt>(
                br#"{"keyId":"fixture","keyId":"other","signedJwt":"ignored"}"#
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn iam_signs_the_exact_oauth_receiver_with_a_five_minute_credential() -> Result<()> {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            thread,
        };
        struct Access;
        impl AccessTokens for Access {
            fn authorization(&self) -> Result<HeaderValue> {
                Ok(HeaderValue::from_static("Bearer fixture-access-token"))
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("http://{}/", listener.local_addr()?);
        let task = thread::spawn(move || -> Result<Claims> {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            ensure!(
                line.trim_end()
                    == "POST /v1/projects/-/serviceAccounts/security@company.iam.gserviceaccount.com:signJwt HTTP/1.1",
                "wrong IAM signing identity"
            );
            let mut length = None;
            let mut authorization = false;
            loop {
                line.clear();
                reader.read_line(&mut line)?;
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = Some(value.trim().parse::<usize>()?);
                }
                if line
                    .trim_end()
                    .eq_ignore_ascii_case("authorization: Bearer fixture-access-token")
                {
                    authorization = true;
                }
            }
            ensure!(authorization, "missing selected access token");
            let mut bytes = vec![0; length.context("missing request length")?];
            reader.read_exact(&mut bytes)?;
            let request: serde_json::Value = crate::json::decode(&bytes)?;
            let claims: Claims = crate::json::decode(
                request["payload"]
                    .as_str()
                    .context("missing payload")?
                    .as_bytes(),
            )?;
            let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"fixture"}"#);
            let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
            let signature = URL_SAFE_NO_PAD.encode([0; 64]);
            let response = serde_json::to_vec(
                &serde_json::json!({"keyId":"fixture", "signedJwt":format!("{head}.{body}.{signature}")}),
            )?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )?;
            stream.write_all(&response)?;
            Ok(claims)
        });
        let audience = Url::parse("https://app.example/_day2/oauth/approval")?;
        let signer = Signer::transport_fixture(
            "security@company.iam.gserviceaccount.com",
            [audience.clone()].into(),
            Arc::new(Access),
            &origin,
        )?;
        let signed = signer.sign_for(&audience)?;
        assert_eq!(format!("{signed:?}"), "BearerToken([REDACTED])");
        let claims = task.join().expect("IAM fixture panicked")?;
        assert_eq!(claims.aud, audience.as_str());
        assert_eq!(claims.iss, "security@company.iam.gserviceaccount.com");
        assert_eq!(claims.sub, claims.iss);
        assert_eq!(claims.exp - claims.iat, 300);
        Ok(())
    }
}
