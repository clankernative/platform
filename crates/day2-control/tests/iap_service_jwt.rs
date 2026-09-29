use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::any,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_control::iap_service_jwt::{Gate, GkeMetadataAccessTokens, IapServiceJwt};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex, mpsc},
    thread,
};
use tokio::sync::oneshot;

#[derive(Default)]
struct Seen {
    metadata_calls: usize,
    signed: Vec<Value>,
    tamper: bool,
    redirect: bool,
}

struct Server {
    origin: String,
    seen: Arc<Mutex<Seen>>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

async fn handle(
    State(seen): State<Arc<Mutex<Seen>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, String) {
    let metadata = "/computeMetadata/v1/instance/service-accounts/default/token";
    if method == Method::GET && uri.path() == metadata {
        if headers
            .get("Metadata-Flavor")
            .and_then(|value| value.to_str().ok())
            != Some("Google")
        {
            return (StatusCode::FORBIDDEN, String::new());
        }
        seen.lock().unwrap().metadata_calls += 1;
        return (
            StatusCode::OK,
            json!({"access_token":"metadata-access","token_type":"Bearer"}).to_string(),
        );
    }
    if method != Method::POST
        || uri.path()
            != "/v1/projects/-/serviceAccounts/caller@project.iam.gserviceaccount.com:signJwt"
        || headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer metadata-access")
    {
        return (StatusCode::FORBIDDEN, String::new());
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let Some(payload) = request.get("payload").and_then(Value::as_str) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let Ok(mut claims) = serde_json::from_str::<Value>(payload) else {
        return (StatusCode::BAD_REQUEST, String::new());
    };
    let (tamper, redirect) = {
        let mut state = seen.lock().unwrap();
        state.signed.push(claims.clone());
        (state.tamper, state.redirect)
    };
    if redirect {
        return (StatusCode::FOUND, String::new());
    }
    if tamper {
        claims["aud"] = json!("https://forged.example/_platform/app-query");
    }
    let jwt = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(json!({"alg":"RS256","kid":"managed-key"}).to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
        URL_SAFE_NO_PAD.encode([7_u8; 64])
    );
    (
        StatusCode::OK,
        json!({"keyId":"managed-key","signedJwt":jwt}).to_string(),
    )
}

impl Server {
    fn start() -> Result<Self> {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let server_seen = seen.clone();
        let (send, receive) = mpsc::channel();
        let (shutdown, done) = oneshot::channel();
        let thread = thread::spawn(move || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                send.send(format!("http://{}", listener.local_addr()?))?;
                let router = Router::new().fallback(any(handle)).with_state(server_seen);
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        let _ = done.await;
                    })
                    .await?;
                Ok(())
            })
        });
        Ok(Self {
            origin: receive.recv()?,
            seen,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn metadata_and_iam_mint_exact_fresh_credentials_for_each_iap_gate() -> Result<()> {
    let server = Server::start()?;
    let tokens = Arc::new(GkeMetadataAccessTokens::transport_fixture(&format!(
        "{}/computeMetadata/v1/instance/service-accounts/default/token",
        server.origin
    ))?);
    let issuer = format!("{}/_platform/app-issue", server.origin);
    let receiver = format!("{}/_platform/app-query", server.origin);
    let signer = IapServiceJwt::transport_fixture(
        "caller@project.iam.gserviceaccount.com",
        &issuer,
        &receiver,
        &format!("{}/", server.origin),
        tokens,
    )?;
    let first = signer.sign_for(Gate::Issuer)?;
    let second = signer.sign_for(Gate::Receiver)?;
    assert!(format!("{first:?}").contains("[REDACTED]"));
    let audience = |jwt: &str| -> Result<String> {
        let body = jwt.split('.').nth(1).unwrap();
        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body)?)?;
        Ok(claims["aud"].as_str().unwrap().to_owned())
    };
    assert_eq!(audience(first.as_str())?, issuer);
    assert_eq!(audience(second.as_str())?, receiver);
    let seen = server.seen.lock().unwrap();
    assert_eq!(
        seen.metadata_calls, 2,
        "access tokens are fetched per request"
    );
    assert_eq!(seen.signed.len(), 2, "IAM signs separately for each gate");
    for (claims, expected) in seen.signed.iter().zip([issuer, receiver]) {
        assert_eq!(claims["iss"], "caller@project.iam.gserviceaccount.com");
        assert_eq!(claims["sub"], claims["iss"]);
        assert_eq!(claims["aud"], expected);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            300
        );
    }
    drop(seen);
    server.seen.lock().unwrap().tamper = true;
    assert!(
        signer.sign_for(Gate::Receiver).is_err(),
        "IAM cannot return a different audience"
    );
    server.seen.lock().unwrap().tamper = false;
    server.seen.lock().unwrap().redirect = true;
    assert!(
        signer.sign_for(Gate::Issuer).is_err(),
        "IAM redirects are never followed"
    );
    Ok(())
}

#[test]
fn production_bindings_refuse_untrusted_urls() -> Result<()> {
    struct Tokens;
    impl day2_control::secrets::AccessTokenProvider for Tokens {
        fn access_token(
            &self,
        ) -> std::result::Result<
            day2_control::secrets::AccessToken,
            day2_control::source::SourceError,
        > {
            day2_control::secrets::AccessToken::new("unused".to_owned())
        }
    }
    let tokens = Arc::new(Tokens);
    let good_issuer = "https://issuer.example/_platform/app-issue";
    let good_receiver = "https://target.example/_platform/app-query";
    assert!(
        IapServiceJwt::new(
            "caller@project.iam.gserviceaccount.com",
            good_issuer,
            good_receiver,
            tokens.clone()
        )
        .is_ok()
    );
    assert!(
        IapServiceJwt::new(
            "person@example.com",
            good_issuer,
            good_receiver,
            tokens.clone()
        )
        .is_err()
    );
    assert!(
        IapServiceJwt::new(
            "caller@project.iam.gserviceaccount.com",
            "http://issuer.example/_platform/app-issue",
            good_receiver,
            tokens.clone()
        )
        .is_err()
    );
    assert!(
        IapServiceJwt::new(
            "caller@project.iam.gserviceaccount.com",
            "https://issuer.example/_platform/app-issue?next=x",
            good_receiver,
            tokens.clone()
        )
        .is_err()
    );
    assert!(
        IapServiceJwt::new(
            "caller@project.iam.gserviceaccount.com",
            good_issuer,
            "https://target.example/other",
            tokens
        )
        .is_err()
    );
    Ok(())
}
