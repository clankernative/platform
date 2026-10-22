use super::*;
use crate::carta_live::{MAX_PAGE_RESPONSE_BYTES, collect_complete};
use anyhow::{Context, ensure};
use day2_capabilities::{integrations::LiveConnection, resources::CartaChildren};
use serde_json::{Value, json};
use std::{
    io::Write,
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicI64, Ordering},
    thread,
};

const ISSUER: &str = "1234567";
const CLIENT: &str = "fixture-client";
const SECRET: &str = "SYNTHETIC_NEVER_EXPORT_CARTA_SECRET";
const TOKEN: &str = "SYNTHETIC_NEVER_EXPORT_ACCESS_TOKEN";

fn plan(pages: u16) -> CapturePlan {
    CapturePlan::authorize(
        "cartaco/test/equity",
        &day2_capabilities::resources::VersionRef {
            id: "carta-playground".into(),
            revision: 1,
        },
        &LiveConnection::Carta {
            credential_ref: day2_capabilities::resources::VersionRef {
                id: "carta-secret".into(),
                revision: 1,
            },
            client_id: CLIENT.into(),
            environment: CartaEnvironment::Playground,
            max_pages_per_collection: pages,
        },
        ISSUER,
        CartaChildren::Omit,
        false,
    )
    .unwrap()
}

fn fixed_clock() -> Result<i64> {
    Ok(1_700_000_000)
}

/// One exchange as the loopback server received it.
struct Received {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn receive(stream: &mut TcpStream) -> Result<Received> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        ensure!(bytes.len() <= 32 * 1024, "fixture request too large");
    }
    let head = String::from_utf8(bytes)?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().context("request line")?.split(' ');
    let method = request_line.next().context("method")?.to_owned();
    let target = request_line.next().context("target")?.to_owned();
    let headers: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(Ok(0), |(_, value)| value.parse::<usize>())?;
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(Received {
        method,
        target,
        headers,
        body: String::from_utf8(body)?,
    })
}

fn respond(stream: &mut TcpStream, status: &str, headers: &[&str], body: &[u8]) -> Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\n")?;
    for header in headers {
        write!(stream, "{header}\r\n")?;
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn json_reply(stream: &mut TcpStream, body: &Value) -> Result<()> {
    respond(
        stream,
        "200 OK",
        &["Content-Type: application/json; charset=utf-8"],
        body.to_string().as_bytes(),
    )
}

fn token_reply() -> Value {
    json!({"access_token":TOKEN,"token_type":"Bearer","expires_in":3600,
        "scope":"read_issuer_stakeholders read_issuer_securities"})
}

fn stakeholder(id: &str) -> Value {
    json!({"id":id,"issuerId":ISSUER,"fullName":id,"email":format!("{id}@example.test"),
        "relationship":"EMPLOYEE","entityType":"INDIVIDUAL"})
}

/// Serve `count` exchanges, answering each with `answer`, and return what the
/// adapter actually sent.
fn serve(
    count: usize,
    answer: impl Fn(usize, &Received, &mut TcpStream) -> Result<()> + Send + 'static,
) -> Result<(String, thread::JoinHandle<Result<Vec<Received>>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let origin = format!("http://{}", listener.local_addr()?);
    let server = thread::spawn(move || -> Result<Vec<Received>> {
        let mut received = Vec::new();
        for index in 0..count {
            let (mut stream, _) = listener.accept()?;
            let request = receive(&mut stream)?;
            answer(index, &request, &mut stream)?;
            received.push(request);
        }
        Ok(received)
    });
    Ok((origin, server))
}

fn port(origin: &str, pages: u16, clock: fn() -> Result<i64>) -> Result<NativeCartaPort> {
    NativeCartaPort::transport_fixture(
        &plan(pages),
        CLIENT,
        CartaClientSecret::new(SECRET.into()).map_err(anyhow::Error::from)?,
        [origin, origin],
        clock,
    )
}

#[test]
fn the_native_port_sends_exactly_the_reviewed_requests() -> Result<()> {
    let continuation = "next+page/=&1";
    let (origin, server) = serve(4, move |index, request, stream| match index {
        0 => json_reply(stream, &token_reply()),
        1 => json_reply(
            stream,
            &json!({"stakeholders":[stakeholder("s1")],"nextPageToken":continuation}),
        ),
        2 => json_reply(stream, &json!({"stakeholders":[stakeholder("s2")]})),
        _ => {
            ensure!(
                request.target.contains("optionGrants"),
                "unexpected request"
            );
            json_reply(stream, &json!({"optionGrants":[],"nextPageToken":""}))
        }
    })?;
    let mut native = port(&origin, 5, fixed_clock)?;
    let (capture, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    let received = server.join().expect("fixture server panicked")?;
    let capture = capture?;
    assert_eq!(capture.snapshot().stakeholder_count, 2);
    assert_eq!(meter.calls, 4);

    let token = &received[0];
    assert_eq!(
        (token.method.as_str(), token.target.as_str()),
        ("POST", "/o/access_token/")
    );
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT}:{SECRET}"));
    assert_eq!(
        token.header("authorization"),
        Some(format!("Basic {basic}").as_str())
    );
    assert_eq!(
        token.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        token.body,
        "grant_type=CLIENT_CREDENTIALS&scope=read_issuer_stakeholders+read_issuer_securities"
    );
    let pages = [
        format!("/v1alpha1/issuers/{ISSUER}/stakeholders"),
        format!("/v1alpha1/issuers/{ISSUER}/stakeholders?pageToken=next%2Bpage%2F%3D%261"),
        format!("/v1alpha1/issuers/{ISSUER}/optionGrants"),
    ];
    for (request, target) in received[1..].iter().zip(pages) {
        assert_eq!(
            (request.method.as_str(), request.target.as_str()),
            ("GET", target.as_str())
        );
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert!(request.body.is_empty());
    }
    for request in &received {
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("accept-encoding"), Some("identity"));
        assert!(request.header("cookie").is_none());
    }
    // The secret is Basic-only and never sent as a bearer; the token never
    // reaches the token endpoint.
    assert!(received[1..].iter().all(|request| {
        !request
            .headers
            .iter()
            .any(|(_, value)| value.contains(&basic))
    }));
    Ok(())
}

#[test]
fn redirects_are_refused_not_followed() -> Result<()> {
    let (origin, server) = serve(2, |index, _, stream| match index {
        0 => json_reply(stream, &token_reply()),
        _ => respond(
            stream,
            "302 Found",
            &["Location: /v1alpha1/issuers/7654321/stakeholders"],
            b"",
        ),
    })?;
    let mut native = port(&origin, 5, fixed_clock)?;
    let (result, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    let received = server.join().expect("fixture server panicked")?;
    assert_eq!(
        result.err().context("redirect")?.to_string(),
        "carta_response_invalid"
    );
    assert_eq!(received.len(), 2, "the redirect target was never requested");
    assert_eq!(meter.calls, 2);
    Ok(())
}

#[test]
fn responses_are_bounded_while_reading() -> Result<()> {
    // A declared oversize is refused from its header; an undeclared one is read
    // only to the probe byte.
    for declared in [true, false] {
        let (origin, server) = serve(2, move |index, _, stream| match index {
            0 => json_reply(stream, &token_reply()),
            _ => {
                let body = vec![b' '; 4096];
                if declared {
                    // The adapter refuses on the header and may close first.
                    let _ = respond(stream, "200 OK", &["Content-Type: application/json"], &body);
                    Ok(())
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                    )?;
                    let _ = stream.write_all(&body);
                    Ok(())
                }
            }
        })?;
        let mut native = port(&origin, 5, fixed_clock)?;
        let (result, meter) = collect_complete(&plan(5), &mut native, 1024);
        server.join().expect("fixture server panicked")?;
        assert_eq!(
            result.err().context("oversize")?.to_string(),
            "carta_response_too_large"
        );
        assert!(meter.response_bytes <= token_reply().to_string().len() as u64 + 1025);
        assert_eq!(
            meter.last.and_then(|last| last.http_status),
            Some(200),
            "a refusal keeps the status the response declared"
        );
    }
    Ok(())
}

#[test]
fn a_truncated_body_settles_the_bytes_it_consumed_and_its_metadata() -> Result<()> {
    // The response declares 4096 bytes, sends 1024 and closes.
    let (origin, server) = serve(2, |index, _, stream| match index {
        0 => json_reply(stream, &token_reply()),
        _ => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRetry-After: 9\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n"
            )?;
            stream.write_all(&[b' '; 1024])?;
            stream.flush()?;
            stream.shutdown(std::net::Shutdown::Both)?;
            Ok(())
        }
    })?;
    let mut native = port(&origin, 5, fixed_clock)?;
    let (result, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    server.join().expect("fixture server panicked")?;
    assert_eq!(
        result.err().context("truncated")?.to_string(),
        "carta_unavailable"
    );
    assert_eq!(meter.calls, 2);
    assert_eq!(
        meter.response_bytes,
        token_reply().to_string().len() as u64 + 1024,
        "the partial page is metered, not dropped"
    );
    assert_eq!(
        meter
            .last
            .map(|last| (last.page, last.http_status, last.retry_after_seconds)),
        Some((0, Some(200), Some(9)))
    );

    // A response refused from its headers keeps its status and Retry-After.
    let (origin, server) = serve(2, |index, _, stream| match index {
        0 => json_reply(stream, &token_reply()),
        _ => {
            // The adapter refuses on the header and may close first.
            let _ = respond(
                stream,
                "503 Service Unavailable",
                &[
                    "Content-Type: application/json",
                    "Content-Encoding: gzip",
                    "Retry-After: 4",
                ],
                b"{}",
            );
            Ok(())
        }
    })?;
    let mut native = port(&origin, 5, fixed_clock)?;
    let (result, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    server.join().expect("fixture server panicked")?;
    assert_eq!(
        result.err().context("encoded")?.to_string(),
        "carta_response_invalid"
    );
    assert_eq!(
        meter
            .last
            .map(|last| (last.http_status, last.retry_after_seconds)),
        Some((Some(503), Some(4)))
    );
    Ok(())
}

#[test]
fn provider_refusals_keep_stable_codes_and_never_echo_content() -> Result<()> {
    for (status, extra, expected) in [
        ("401 Unauthorized", None, "carta_authentication_failed"),
        ("403 Forbidden", None, "carta_scope_denied"),
        (
            "429 Too Many Requests",
            Some("Retry-After: 12"),
            "carta_rate_limited",
        ),
        ("503 Service Unavailable", None, "carta_unavailable"),
    ] {
        let (origin, server) = serve(2, move |index, _, stream| match index {
            0 => json_reply(stream, &token_reply()),
            _ => respond(
                stream,
                status,
                &[
                    "Content-Type: application/json",
                    extra.unwrap_or("X-Fixture: none"),
                ],
                format!(r#"{{"detail":"{SECRET} {TOKEN}"}}"#).as_bytes(),
            ),
        })?;
        let mut native = port(&origin, 5, fixed_clock)?;
        let (result, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
        server.join().expect("fixture server panicked")?;
        let error = result.err().context("refusal")?;
        assert_eq!(error.to_string(), expected);
        let rendered = format!("{error:?} {:?}", meter.last);
        assert!(!rendered.contains(SECRET) && !rendered.contains(TOKEN));
        assert_eq!(
            meter.last.and_then(|last| last.retry_after_seconds),
            extra.map(|_| 12)
        );
    }
    let (origin, server) = serve(1, |_, _, stream| {
        respond(
            stream,
            "400 Bad Request",
            &["Content-Type: application/json"],
            br#"{"error":"invalid_client"}"#,
        )
    })?;
    let mut native = port(&origin, 5, fixed_clock)?;
    let (result, _) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    server.join().expect("fixture server panicked")?;
    assert_eq!(
        result.err().context("bad client")?.to_string(),
        "carta_authentication_failed"
    );
    // A closed port is an unavailable provider.
    let closed = TcpListener::bind(("127.0.0.1", 0))?;
    let origin = format!("http://{}", closed.local_addr()?);
    drop(closed);
    let mut native = port(&origin, 5, fixed_clock)?;
    let (result, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    assert_eq!(
        result.err().context("closed")?.to_string(),
        "carta_unavailable"
    );
    assert_eq!(meter.calls, 1);
    Ok(())
}

static ELAPSED: AtomicI64 = AtomicI64::new(0);

fn advancing_clock() -> Result<i64> {
    Ok(1_700_000_000 + ELAPSED.fetch_add(100, Ordering::SeqCst))
}

#[test]
fn the_capture_deadline_stops_requests_before_they_are_sent() -> Result<()> {
    ELAPSED.store(0, Ordering::SeqCst);
    let (origin, server) = serve(1, |_, _, stream| json_reply(stream, &token_reply()))?;
    // Construction reads 0 s, the token request 100 s, and the first page would
    // start at 200 s, past the 180 s capture deadline.
    let mut native = port(&origin, 5, advancing_clock)?;
    let (result, meter) = collect_complete(&plan(5), &mut native, MAX_PAGE_RESPONSE_BYTES);
    let received = server.join().expect("fixture server panicked")?;
    assert_eq!(
        result.err().context("deadline")?.to_string(),
        "carta_unavailable"
    );
    assert_eq!(received.len(), 1, "no request is sent after the deadline");
    assert_eq!(
        meter.calls, 2,
        "the refused request is still metered as attempted"
    );
    Ok(())
}

#[test]
fn origins_are_fixed_per_environment_and_fixtures_are_loopback_only() {
    assert_eq!(
        origins(CartaEnvironment::Production),
        ("https://login.app.carta.com", "https://api.carta.com")
    );
    assert_eq!(
        origins(CartaEnvironment::Playground),
        (
            "https://login.playground.carta.team",
            "https://api.playground.carta.team"
        )
    );
    for origin in [
        "https://127.0.0.1:1",
        "http://example.test",
        "http://127.0.0.1:1/path",
        "http://user@127.0.0.1:1",
    ] {
        assert!(port(origin, 5, fixed_clock).is_err(), "{origin}");
    }
    assert!(CartaClientSecret::new(String::new()).is_err());
    assert!(CartaClientSecret::new("has space".into()).is_err());
}
