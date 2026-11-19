use super::*;
use serde_json::{Value, json};
use std::collections::VecDeque;

fn connection() -> LiveConnection {
    LiveConnection::InternalTools {
        service_account: "home-reader@company.iam.gserviceaccount.com".into(),
        origin: "https://it.example.test".into(),
        iap_audience: "https://it.example.test/*".into(),
        target_app_id: "it".into(),
    }
}

fn plan() -> ReadPlan {
    ReadPlan::authorize(&connection(), "example.test", 1_700_000_000).unwrap()
}

fn json_reply(status: u16, value: Value) -> std::result::Result<Reply, TransportFailure> {
    Ok(Reply {
        status,
        json: true,
        body: value.to_string().into_bytes(),
    })
}

fn token() -> std::result::Result<Reply, TransportFailure> {
    json_reply(
        200,
        json!({"token_type":"Bearer","expires_in":300,"service_token":"fixture-service-token"}),
    )
}

fn page(page: u16, items: Vec<Value>, more: bool) -> std::result::Result<Reply, TransportFailure> {
    json_reply(
        200,
        json!({"items":items,"page":page,"pageSize":PAGE_SIZE,"hasNextPage":more}),
    )
}

fn entry(app_id: &str, name: &str, subdomain: &str) -> Value {
    json!({"appId":app_id,"displayName":name,"subdomain":subdomain,
        "owners":[{"email":"owner@private.test"}],"repositorySlug":"private/repo"})
}

/// Scripted wire replies, recording every request the pipeline makes.
struct FixturePort {
    credential: Option<Failure>,
    token: VecDeque<std::result::Result<Reply, TransportFailure>>,
    pages: VecDeque<std::result::Result<Reply, TransportFailure>>,
    requests: Vec<String>,
}

impl FixturePort {
    fn new(
        token: std::result::Result<Reply, TransportFailure>,
        pages: Vec<std::result::Result<Reply, TransportFailure>>,
    ) -> Self {
        Self {
            credential: None,
            token: VecDeque::from([token]),
            pages: pages.into(),
            requests: Vec::new(),
        }
    }
}

impl LibraryPort for FixturePort {
    fn credential(&mut self) -> std::result::Result<IapCredential, Failure> {
        self.requests.push("sign".into());
        match self.credential {
            Some(failure) => Err(failure),
            None => IapCredential::new("fixture-iap-credential".into()),
        }
    }

    fn service_token(
        &mut self,
        credential: &IapCredential,
        body: &[u8],
        _max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        assert_eq!(credential.bearer(), "fixture-iap-credential");
        self.requests
            .push(format!("token {}", String::from_utf8_lossy(body)));
        self.token.pop_front().expect("one token exchange")
    }

    fn page(
        &mut self,
        credential: &IapCredential,
        token: &ServiceToken,
        query: &str,
        max_bytes: usize,
    ) -> std::result::Result<Reply, TransportFailure> {
        assert_eq!(credential.bearer(), "fixture-iap-credential");
        assert_eq!(token.value(), "fixture-service-token");
        self.requests.push(format!("page {query}"));
        let mut reply = self.pages.pop_front().expect("scripted page");
        if let Ok(reply) = &mut reply {
            reply.body.truncate(max_bytes + 1);
        }
        reply
    }
}

fn run(port: &mut FixturePort) -> (std::result::Result<Library, String>, Meter) {
    let (result, meter) = collect(&plan(), port);
    (result.map_err(|error| error.to_string()), meter)
}

#[test]
fn the_plan_takes_every_selector_from_the_reviewed_connection_and_binding() {
    assert!(ReadPlan::authorize(&connection(), "example.test", 1).is_ok());
    assert!(ReadPlan::authorize(&connection(), "example.test/evil", 1).is_err());
    assert!(ReadPlan::authorize(&connection(), "example.test", -1).is_err());
    let mut foreign = connection();
    if let LiveConnection::InternalTools { iap_audience, .. } = &mut foreign {
        *iap_audience = "https://elsewhere.test/*".into();
    }
    assert!(ReadPlan::authorize(&foreign, "example.test", 1).is_err());
    let slack = LiveConnection::SlackWebhook {
        credential_ref: day2_capabilities::resources::VersionRef {
            id: "hook".into(),
            revision: 1,
        },
    };
    assert!(ReadPlan::authorize(&slack, "example.test", 1).is_err());
}

#[test]
fn the_projection_keeps_only_launch_facts_skips_undeployed_apps_and_orders_them() {
    let mut port = FixturePort::new(
        token(),
        vec![page(
            1,
            vec![
                entry("zeta", "zeta", "zeta"),
                entry("alpha", "Alpha", "alpha"),
                json!({"appId":"drafts","displayName":"Drafts"}),
                json!({"appId":"nulled","displayName":"Nulled","subdomain":null}),
                entry("empty", "Empty", ""),
                entry("beta", "beta", "b"),
                entry("alpha", "Alpha", "alpha"),
                entry("Alpha2", "Alpha", "alpha"),
            ],
            false,
        )],
    );
    let (result, _) = run(&mut port);
    // "Alpha2" is not a DNS label: the whole read fails instead of dropping it.
    assert_eq!(result.unwrap_err(), "internal_tools_response_invalid");

    let mut port = FixturePort::new(
        token(),
        vec![page(
            1,
            vec![
                entry("zeta", "zeta", "zeta"),
                entry("alpha", "Alpha", "alpha"),
                json!({"appId":"drafts","displayName":"Drafts"}),
                json!({"appId":"nulled","displayName":"Nulled","subdomain":null}),
                entry("empty", "Empty", ""),
                entry("beta", "beta", "b"),
                entry("alpha", "Alpha", "alpha"),
                entry("alpha-2", "alpha", "a2"),
            ],
            false,
        )],
    );
    let (result, _) = run(&mut port);
    let library = result.unwrap();
    assert_eq!(library.captured_at, 1_700_000_000);
    let summary: Vec<_> = library
        .apps
        .iter()
        .map(|app| (app.app_id.as_str(), app.name.as_str(), app.url.as_str()))
        .collect();
    assert_eq!(
        summary,
        [
            ("alpha", "Alpha", "https://alpha.example.test/"),
            ("alpha-2", "alpha", "https://a2.example.test/"),
            ("beta", "beta", "https://b.example.test/"),
            ("zeta", "zeta", "https://zeta.example.test/"),
        ]
    );
    let encoded = serde_json::to_string(&library).unwrap();
    assert!(!encoded.contains("owner@private.test") && !encoded.contains("private/repo"));
    assert_eq!(
        port.requests,
        [
            "sign".to_owned(),
            format!(
                "token {}",
                json!({"target_app_id":"it","scopes":[SERVICE_SCOPE]})
            ),
            "page Page=1&PageSize=100".to_owned(),
        ]
    );
}

#[test]
fn duplicates_resolve_the_same_way_whatever_order_the_provider_returns() {
    let entries = vec![
        entry("quoty", "Quoty", "quoty"),
        entry("quoty", "Quoty Old", "quoty-old"),
        entry("golinks", "Golinks", "go"),
    ];
    let mut reversed = entries.clone();
    reversed.reverse();
    let read = |items| {
        let mut port = FixturePort::new(token(), vec![page(1, items, false)]);
        run(&mut port).0.unwrap()
    };
    let first = read(entries);
    assert_eq!(first, read(reversed));
    assert_eq!(first.apps.len(), 2);
    assert_eq!(first.apps[1].url, "https://quoty.example.test/");
}

#[test]
fn every_malformed_entry_fails_the_read() {
    for bad in [
        entry("quoty", "Quoty", "evil.test"),
        entry("quoty", "Quoty", "-quoty"),
        entry("quoty", "Quoty", "QUOTY"),
        entry("quoty", "Quoty", &"q".repeat(64)),
        entry("", "Quoty", "quoty"),
        entry("quoty/x", "Quoty", "quoty"),
        entry("quoty", "", "quoty"),
        entry("quoty", "Line\nBreak", "quoty"),
        entry("quoty", &"n".repeat(MAX_NAME_BYTES + 1), "quoty"),
        json!({"displayName":"Quoty","subdomain":"quoty"}),
        json!({"appId":"quoty","displayName":7,"subdomain":"quoty"}),
        json!({"appId":"quoty","displayName":"Quoty","subdomain":["quoty"]}),
    ] {
        let mut port = FixturePort::new(token(), vec![page(1, vec![bad.clone()], false)]);
        assert_eq!(
            run(&mut port).0.unwrap_err(),
            "internal_tools_response_invalid",
            "{bad}"
        );
    }
}

#[test]
fn pagination_follows_the_control_plane_and_refuses_what_it_would_not_send() {
    let full = |offset: usize| {
        (0..PAGE_SIZE)
            .map(|index| {
                let id = format!("app-{:04}", offset + index);
                entry(&id, &id, &id)
            })
            .collect::<Vec<_>>()
    };
    let mut port = FixturePort::new(
        token(),
        vec![
            page(1, full(0), true),
            page(2, vec![entry("last", "Last", "last")], false),
        ],
    );
    let (result, meter) = run(&mut port);
    assert_eq!(result.unwrap().apps.len(), PAGE_SIZE + 1);
    assert_eq!(meter.calls, SIGNING_CALLS + 3);
    assert_eq!(port.requests.last().unwrap(), "page Page=2&PageSize=100");

    for (reply, code) in [
        // A different page than requested.
        (page(2, vec![], false), "internal_tools_pagination_invalid"),
        // A short page that claims more.
        (
            page(1, vec![entry("a", "A", "a")], true),
            "internal_tools_pagination_invalid",
        ),
        // An empty page that claims more.
        (page(1, vec![], true), "internal_tools_pagination_invalid"),
        (
            json_reply(
                200,
                json!({"items":[],"page":1,"pageSize":25,"hasNextPage":false}),
            ),
            "internal_tools_pagination_invalid",
        ),
        (
            json_reply(200, json!({"items":[],"page":1,"pageSize":100})),
            "internal_tools_response_invalid",
        ),
        (
            json_reply(200, json!([])),
            "internal_tools_response_invalid",
        ),
        (
            json_reply(
                200,
                json!({"items":full(0).into_iter().chain([entry("x","X","x")]).collect::<Vec<_>>(),
                    "page":1,"pageSize":100,"hasNextPage":false}),
            ),
            "internal_tools_pagination_invalid",
        ),
    ] {
        let mut port = FixturePort::new(token(), vec![reply]);
        assert_eq!(run(&mut port).0.unwrap_err(), code);
    }
}

#[test]
fn a_further_page_past_the_bound_fails_without_being_requested() {
    let pages = (1..=MAX_PAGES)
        .map(|number| {
            let items = (0..PAGE_SIZE)
                .map(|index| {
                    let id = format!("app-{number:02}-{index:03}");
                    entry(&id, &id, &id)
                })
                .collect();
            page(number, items, true)
        })
        .collect();
    let mut port = FixturePort::new(token(), pages);
    let (result, meter) = run(&mut port);
    assert_eq!(result.unwrap_err(), "internal_tools_app_budget");
    assert_eq!(meter.calls, PLANNED_CALLS);
    assert_eq!(port.requests.len(), 2 + usize::from(MAX_PAGES));
    assert!(port.pages.is_empty());
}

#[test]
fn statuses_are_classified_by_phase() {
    for (status, code) in [
        (400, "internal_tools_service_token_refused"),
        (401, "internal_tools_service_token_refused"),
        (403, "internal_tools_service_token_refused"),
        (404, "internal_tools_service_token_refused"),
        (429, "internal_tools_rate_limited"),
        (503, "internal_tools_unavailable"),
        (302, "internal_tools_response_invalid"),
    ] {
        let mut port = FixturePort::new(json_reply(status, json!({})), vec![]);
        let (result, meter) = run(&mut port);
        assert_eq!(result.unwrap_err(), code);
        assert_eq!(meter.last.unwrap().phase, Phase::ServiceToken);
        assert_eq!(meter.last.unwrap().http_status, Some(status));
    }
    for (status, code) in [
        (401, "internal_tools_authentication_failed"),
        (403, "internal_tools_scope_denied"),
        (404, "internal_tools_response_invalid"),
        (429, "internal_tools_rate_limited"),
        (500, "internal_tools_unavailable"),
    ] {
        let mut port = FixturePort::new(token(), vec![json_reply(status, json!({}))]);
        let (result, meter) = run(&mut port);
        assert_eq!(result.unwrap_err(), code);
        let last = meter.last.unwrap();
        assert_eq!(
            (last.phase, last.page, last.http_status),
            (Phase::Library, 1, Some(status))
        );
    }
}

#[test]
fn a_malformed_service_token_is_never_presented() {
    for body in [
        json!({"token_type":"Basic","expires_in":300,"service_token":"t"}),
        json!({"token_type":"Bearer","expires_in":0,"service_token":"t"}),
        json!({"token_type":"Bearer","expires_in":86_401,"service_token":"t"}),
        json!({"token_type":"Bearer","expires_in":300,"service_token":""}),
        json!({"token_type":"Bearer","expires_in":300,"service_token":"has space"}),
        json!({"token_type":"Bearer","expires_in":300}),
    ] {
        let mut port = FixturePort::new(json_reply(200, body), vec![]);
        assert_eq!(
            run(&mut port).0.unwrap_err(),
            "internal_tools_response_invalid"
        );
        assert!(
            port.requests
                .iter()
                .all(|request| !request.starts_with("page"))
        );
    }
    let mut port = FixturePort::new(
        Ok(Reply {
            status: 200,
            json: false,
            body: br#"{"token_type":"Bearer","expires_in":300,"service_token":"t"}"#.to_vec(),
        }),
        vec![],
    );
    assert_eq!(
        run(&mut port).0.unwrap_err(),
        "internal_tools_response_invalid"
    );
}

#[test]
fn failed_and_truncated_exchanges_are_metered() {
    // Signing that fails is still charged at its bound.
    let mut port = FixturePort::new(token(), vec![]);
    port.credential = Some(Failure::CredentialUnavailable);
    let (result, meter) = run(&mut port);
    assert_eq!(result.unwrap_err(), "internal_tools_credential_unavailable");
    assert_eq!(
        (meter.calls, meter.request_bytes, meter.response_bytes),
        (SIGNING_CALLS, SIGNING_REQUEST_BYTES, SIGNING_RESPONSE_BYTES)
    );

    // A body read that stops part way keeps the bytes it consumed.
    let mut port = FixturePort::new(
        token(),
        vec![Err(TransportFailure {
            failure: Failure::Unavailable,
            response_bytes: 777,
            http_status: Some(200),
        })],
    );
    let (result, meter) = run(&mut port);
    assert_eq!(result.unwrap_err(), "internal_tools_unavailable");
    let token_bytes = token().ok().unwrap().body.len() as u64;
    assert_eq!(
        meter.response_bytes,
        SIGNING_RESPONSE_BYTES + token_bytes + 777
    );
    assert_eq!(
        meter.request_bytes,
        SIGNING_REQUEST_BYTES + (service_token_request("it").len() + page_query(1).len()) as u64
    );

    // An oversized page is read only to the probe byte, and that is metered.
    let mut port = FixturePort::new(
        token(),
        vec![Ok(Reply {
            status: 200,
            json: true,
            body: vec![b' '; MAX_PAGE_RESPONSE_BYTES + 10],
        })],
    );
    let (result, meter) = run(&mut port);
    assert_eq!(result.unwrap_err(), "internal_tools_response_too_large");
    assert_eq!(
        meter.response_bytes,
        SIGNING_RESPONSE_BYTES + token_bytes + MAX_PAGE_RESPONSE_BYTES as u64 + 1
    );
    assert!(meter.response_bytes <= MAX_READ_RESPONSE_BYTES);
}

#[test]
fn the_aggregate_page_bound_shrinks_each_later_page() {
    // Three near-limit pages exhaust the aggregate; the fourth may read only
    // what is left, so the whole read stays within its reservation.
    let padding = "p".repeat(MAX_PAGE_RESPONSE_BYTES - 64 * 1024);
    let pages = (1..=4u16)
        .map(|number| {
            let mut items: Vec<Value> = (0..PAGE_SIZE)
                .map(|index| {
                    let id = format!("app-{number}-{index:03}");
                    entry(&id, &id, &id)
                })
                .collect();
            items[0]["padding"] = json!(padding);
            page(number, items, true)
        })
        .collect();
    let mut port = FixturePort::new(token(), pages);
    let (result, meter) = run(&mut port);
    assert_eq!(result.unwrap_err(), "internal_tools_response_too_large");
    assert!(meter.response_bytes <= MAX_READ_RESPONSE_BYTES);
}

mod transport {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::{
        io::Write as _,
        net::{TcpListener, TcpStream},
        thread,
    };

    /// One recorded request: its request line, header lines and body.
    type Recorded = (String, Vec<String>, Vec<u8>);

    struct Access;

    impl crate::iap_workload::AccessTokens for Access {
        fn authorization(&self) -> Result<reqwest::header::HeaderValue> {
            Ok(reqwest::header::HeaderValue::from_static(
                "Bearer fixture-workload-token",
            ))
        }
    }

    fn request(stream: &mut TcpStream) -> Result<Recorded> {
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte)?;
            bytes.push(byte[0]);
            ensure!(bytes.len() <= 32 * 1024, "fixture request too large");
        }
        let head = String::from_utf8(bytes)?;
        let mut lines = head.lines().map(str::to_owned);
        let first = lines.next().unwrap_or_default();
        let headers: Vec<String> = lines.filter(|line| !line.is_empty()).collect();
        let length = headers
            .iter()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        Ok((first, headers, body))
    }

    fn respond(stream: &mut TcpStream, body: &str) -> Result<()> {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        stream.flush()?;
        Ok(())
    }

    fn header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
        headers.iter().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
    }

    #[test]
    fn the_native_port_sends_exactly_the_reviewed_requests() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("http://{}", listener.local_addr()?);
        let audience = format!("{origin}/*");
        let server = thread::spawn(move || -> Result<Vec<Recorded>> {
            let mut seen = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                let (line, headers, body) = request(&mut stream)?;
                let reply = if line.contains(":signJwt") {
                    // Echo the requested claims as IAM would sign them.
                    let request: Value = serde_json::from_slice(&body)?;
                    let claims = request["payload"].as_str().unwrap_or_default().to_owned();
                    format!(
                        r#"{{"keyId":"fixture","signedJwt":"{}.{}.{}"}}"#,
                        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"fixture"}"#),
                        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
                        URL_SAFE_NO_PAD.encode([0; 64])
                    )
                } else if line.starts_with("POST ") {
                    json!({"token_type":"Bearer","expires_in":300,"service_token":"fixture-service-token"})
                        .to_string()
                } else {
                    json!({"items":[{"appId":"quoty","displayName":"Quoty","subdomain":"quoty",
                        "owners":[{"email":"owner@private.test"}]}],
                        "page":1,"pageSize":100,"hasNextPage":false})
                    .to_string()
                };
                respond(&mut stream, &reply)?;
                seen.push((line, headers, body));
            }
            Ok(seen)
        });
        let mut port = NativeLibraryPort::transport_fixture(
            &plan(),
            &origin,
            &format!("{origin}/"),
            Arc::new(Access),
            || Ok(1_700_000_000),
        )?;
        let (result, meter) = collect(&plan(), &mut port);
        let library = result?;
        assert_eq!(
            serde_json::to_value(&library)?,
            json!({"apps":[{"app_id":"quoty","name":"Quoty","url":"https://quoty.example.test/"}],
                "captured_at":1_700_000_000})
        );
        assert_eq!(meter.calls, SIGNING_CALLS + 2);
        let seen = server.join().expect("fixture server panicked")?;
        let [sign, token, page] = seen.as_slice() else {
            anyhow::bail!("exactly three requests")
        };
        assert_eq!(
            sign.0,
            "POST /v1/projects/-/serviceAccounts/home-reader@company.iam.gserviceaccount.com:signJwt HTTP/1.1"
        );
        assert_eq!(
            header(&sign.1, "authorization"),
            Some("Bearer fixture-workload-token")
        );
        let signed: Value = serde_json::from_slice(&sign.2)?;
        let claims: Value = serde_json::from_str(signed["payload"].as_str().unwrap_or_default())?;
        assert_eq!(claims["aud"], audience);
        assert_eq!(claims["iss"], "home-reader@company.iam.gserviceaccount.com");
        assert_eq!(claims["sub"], claims["iss"]);

        assert_eq!(token.0, "POST /api/internal-tools/service-tokens HTTP/1.1");
        let jwt = header(&token.1, "authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_owned();
        assert_eq!(jwt.split('.').count(), 3);
        assert_eq!(header(&token.1, "content-type"), Some("application/json"));
        assert_eq!(header(&token.1, SERVICE_HEADER), None);
        assert_eq!(token.2, service_token_request("it"));

        assert_eq!(page.0, "GET /api/app-library?Page=1&PageSize=100 HTTP/1.1");
        assert_eq!(
            header(&page.1, "authorization"),
            Some(format!("Bearer {jwt}").as_str())
        );
        assert_eq!(
            header(&page.1, SERVICE_HEADER),
            Some("fixture-service-token")
        );
        assert_eq!(header(&page.1, "accept-encoding"), Some("identity"));
        assert!(page.2.is_empty());
        Ok(())
    }

    #[test]
    fn an_expired_read_deadline_sends_nothing() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let origin = format!("http://{}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        static CALLS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
        // The first reading fixes the deadline; every later one is past it.
        let mut port = NativeLibraryPort::transport_fixture(
            &plan(),
            &origin,
            &format!("{origin}/"),
            Arc::new(Access),
            || Ok(CALLS.fetch_add(READ_DEADLINE_SECONDS, std::sync::atomic::Ordering::SeqCst)),
        )?;
        let (result, _) = collect(&plan(), &mut port);
        assert_eq!(
            result.unwrap_err().to_string(),
            "internal_tools_unavailable"
        );
        assert!(listener.accept().is_err(), "no connection was opened");
        Ok(())
    }
}
