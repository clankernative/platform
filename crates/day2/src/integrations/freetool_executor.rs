use super::Credentials;
use anyhow::{Context, Result, ensure};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use std::io::Read;

const PATH: &str = "/v1/executor";
pub(crate) const MAX_EXECUTOR_WIRE_BYTES: u64 = 1_100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialAction {
    Status,
    Replace,
    Retain,
    Clear,
}

impl CredentialAction {
    fn path(self) -> &'static str {
        match self {
            Self::Status => "/v1/credentials/status",
            Self::Replace => "/v1/credentials/replace",
            Self::Retain => "/v1/credentials/retain",
            Self::Clear => "/v1/credentials/clear",
        }
    }
}

pub(crate) fn send(
    endpoint: &str,
    credential: &Credentials,
    body: &[u8],
    max_response_bytes: u64,
) -> super::FreetoolExecutorExchange {
    let mut usage = WireUsage {
        known: true,
        ..Default::default()
    };
    let response = send_to_path(
        endpoint,
        credential,
        PATH,
        body,
        Some(max_response_bytes),
        Some(&mut usage),
    );
    super::FreetoolExecutorExchange {
        response,
        request_bytes: usage.request_bytes,
        response_bytes: usage.response_bytes,
        known: usage.known,
        dispatched: usage.dispatched,
    }
}

#[derive(Default)]
struct WireUsage {
    request_bytes: u64,
    response_bytes: u64,
    known: bool,
    dispatched: bool,
}

pub(crate) fn send_credential(
    endpoint: &str,
    credential: &Credentials,
    action: CredentialAction,
    body: &[u8],
) -> Result<Vec<u8>> {
    send_to_path(endpoint, credential, action.path(), body, None, None)
}

fn send_to_path(
    endpoint: &str,
    credential: &Credentials,
    path: &str,
    body: &[u8],
    granted_response_bytes: Option<u64>,
    mut usage: Option<&mut WireUsage>,
) -> Result<Vec<u8>> {
    let maximum_request_bytes = if path == PATH {
        MAX_EXECUTOR_WIRE_BYTES as usize
    } else {
        16_384
    };
    let maximum_response_bytes = if path == PATH {
        granted_response_bytes
            .unwrap_or_default()
            .min(MAX_EXECUTOR_WIRE_BYTES)
    } else {
        16_384
    };
    ensure!(
        body.len() <= maximum_request_bytes,
        "freetool_service_request_budget"
    );
    if path == PATH {
        ensure!(
            maximum_response_bytes > 0,
            "freetool_service_response_budget"
        );
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let mut nonce_bytes = [0_u8; 24];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("freetool_nonce_unavailable"))?;
    let nonce = crate::hex(&nonce_bytes);
    let body_digest = crate::hex(digest(&SHA256, body).as_ref());
    let canonical = format!("POST\n{path}\n{timestamp}\n{nonce}\n{body_digest}");
    let signature = crate::hex(&credential.sign_executor_request(canonical.as_bytes())?);
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    if path == PATH {
        let usage = usage.as_deref_mut().expect("executor usage meter");
        usage.request_bytes = body.len() as u64;
        usage.dispatched = true;
        usage.known = false;
    }
    let response = client
        .post(format!("{}{path}", endpoint.trim_end_matches('/')))
        .header("content-type", "application/json")
        .header("x-freetool-timestamp", timestamp)
        .header("x-freetool-nonce", nonce)
        .header("x-freetool-body-sha256", body_digest)
        .header("x-freetool-signature", signature)
        .body(body.to_vec())
        .send()
        .context("freetool_service_unavailable")?;
    let status = response.status();
    if path != PATH && !status.is_success() {
        // Translate only the HTTP status, never a service error body that might
        // accidentally include submitted credential material.
        let failure = match response.status().as_u16() {
            400 => crate::error::Failure::InvalidForm,
            401 | 403 => crate::error::Failure::ResourceForbidden,
            409 => crate::error::Failure::VersionConflict,
            _ => crate::error::Failure::CredentialUnavailable,
        };
        anyhow::bail!(failure);
    }
    let json_content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        });
    if path != PATH {
        ensure!(status.is_success(), "freetool_service_rejected");
        ensure!(json_content_type, "freetool_service_response_invalid");
    }
    let mut bytes = Vec::new();
    let read_result = response
        .take(maximum_response_bytes.saturating_add(1))
        .read_to_end(&mut bytes);
    if path == PATH {
        let usage = usage.expect("executor usage meter");
        usage.response_bytes = bytes.len() as u64;
        usage.known = read_result.is_ok();
    }
    read_result.context("freetool_service_response_unavailable")?;
    ensure!(
        bytes.len() as u64 <= maximum_response_bytes,
        "freetool_service_response_budget"
    );
    if path == PATH {
        ensure!(status.is_success(), "freetool_service_rejected");
        ensure!(json_content_type, "freetool_service_response_invalid");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::hmac;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn read_request(stream: &mut std::net::TcpStream) -> Result<(String, Vec<u8>)> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let count = stream.read(&mut chunk)?;
            ensure!(count > 0, "loopback request ended before headers");
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            ensure!(bytes.len() <= 16 * 1024, "loopback headers exceeded limit");
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec())?;
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .context("missing content length")?;
        while bytes.len() - header_end < length {
            let count = stream.read(&mut chunk)?;
            ensure!(count > 0, "loopback request body truncated");
            bytes.extend_from_slice(&chunk[..count]);
        }
        Ok((headers, bytes[header_end..header_end + length].to_vec()))
    }

    #[test]
    fn loopback_transport_authenticates_exact_body_and_trusted_route() -> Result<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let key = vec![0x5a; 32];
        let key_hex = crate::hex(&key);
        let expected_body = br#"{"operation":"status","identity":{"installation":"i/e","application":"freetool","actor":"alice","artifact":"a","operation":"freetool.run","resource_id":"r","configuration_id":"c","immutable_version":1,"configuration_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","run_id":"run","arguments_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#.to_vec();
        let expected = expected_body.clone();
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let (headers, body) = read_request(&mut stream)?;
            ensure!(
                headers.starts_with("POST /v1/executor HTTP/1.1\r\n"),
                "unexpected route"
            );
            ensure!(body == expected, "the signed bytes changed in transit");
            let header = |name: &str| -> Result<String> {
                headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case(name)
                            .then(|| value.trim().to_owned())
                    })
                    .context("missing executor auth header")
            };
            let timestamp = header("x-freetool-timestamp")?;
            let nonce = header("x-freetool-nonce")?;
            let supplied_digest = header("x-freetool-body-sha256")?;
            let signature = header("x-freetool-signature")?;
            ensure!(nonce.len() == 48, "nonce is not 24 random bytes");
            ensure!(
                supplied_digest == crate::hex(digest(&SHA256, &body).as_ref()),
                "body digest mismatch"
            );
            let canonical = format!("POST\n/v1/executor\n{timestamp}\n{nonce}\n{supplied_digest}");
            let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
            let signature = decode_hex(&signature).context("bad signature hex")?;
            hmac::verify(&signing_key, canonical.as_bytes(), &signature)
                .map_err(|_| anyhow::anyhow!("bad signature"))?;
            let response = br#"{"state":"status","receipt":null}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            )?;
            stream.write_all(response)?;
            Ok(())
        });
        let credential = Credentials::bearer(key_hex)?;
        let exchange = send(
            &endpoint,
            &credential,
            &expected_body,
            MAX_EXECUTOR_WIRE_BYTES,
        );
        assert_eq!(exchange.request_bytes, expected_body.len() as u64);
        assert!(exchange.dispatched);
        let response = exchange.response?;
        assert_eq!(exchange.response_bytes, response.len() as u64);
        assert!(exchange.known);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("loopback server panicked"))??;
        let parsed: crate::freetool_executor::ServiceResponse = serde_json::from_slice(&response)?;
        ensure!(
            matches!(
                parsed,
                crate::freetool_executor::ServiceResponse::Status { receipt: None }
            ),
            "unexpected loopback response"
        );
        Ok(())
    }

    #[test]
    fn executor_transport_enforces_and_meters_granted_wire_response_limit() -> Result<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let response_body = vec![b'x'; 1024];
        let server_body = response_body.clone();
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let _ = read_request(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                server_body.len()
            )?;
            stream.write_all(&server_body)?;
            Ok(())
        });
        let body = br#"{"operation":"status"}"#;
        let credential = Credentials::bearer(crate::hex(&[0x31; 32]))?;
        let response_limit = 128;
        let exchange = send(&endpoint, &credential, body, response_limit);
        assert!(exchange.response.is_err());
        assert_eq!(exchange.request_bytes, body.len() as u64);
        assert_eq!(exchange.response_bytes, response_limit + 1);
        assert!(exchange.known && exchange.dispatched);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("loopback thread panicked"))??;
        Ok(())
    }

    #[test]
    fn executor_transport_meters_http_failure_body_bytes() -> Result<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let response_body = vec![b'e'; 4096];
        let server_body = response_body.clone();
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let _ = read_request(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 502 Bad Gateway\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                server_body.len()
            )?;
            stream.write_all(&server_body)?;
            Ok(())
        });
        let body = br#"{"operation":"status"}"#;
        let credential = Credentials::bearer(crate::hex(&[0x31; 32]))?;
        let exchange = send(&endpoint, &credential, body, 8192);
        assert!(exchange.response.is_err());
        assert_eq!(exchange.request_bytes, body.len() as u64);
        assert_eq!(exchange.response_bytes, response_body.len() as u64);
        assert!(exchange.known && exchange.dispatched);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("loopback thread panicked"))??;
        Ok(())
    }

    #[test]
    fn executor_transport_charges_error_body_bytes_not_normalized_observation() -> Result<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let wire_response = serde_json::to_vec(&serde_json::json!({
            "state": "error",
            "code": "synthetic_private_token_".to_owned() + &"A".repeat(4096),
        }))?;
        let server_body = wire_response.clone();
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let _ = read_request(&mut stream)?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                server_body.len()
            )?;
            stream.write_all(&server_body)?;
            Ok(())
        });
        let body = br#"{"operation":"status"}"#;
        let credential = Credentials::bearer(crate::hex(&[0x31; 32]))?;
        let exchange = send(&endpoint, &credential, body, 8192);
        let response = exchange.response?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("loopback thread panicked"))??;
        assert_eq!(exchange.request_bytes, body.len() as u64);
        assert_eq!(exchange.response_bytes, wire_response.len() as u64);
        assert!(exchange.known && exchange.dispatched);
        let decoded: crate::freetool_executor::ServiceResponse = serde_json::from_slice(&response)?;
        let normalized = crate::freetool_executor::response_json(decoded)?;
        assert!(normalized.len() < exchange.response_bytes as usize);
        Ok(())
    }

    #[test]
    fn credential_transport_redacts_rejections_and_preserves_conflict() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let _ = read_request(&mut stream)?;
            let leaked = b"a-provider-must-never-echo-this-secret";
            write!(
                stream,
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                leaked.len()
            )?;
            stream.write_all(leaked)?;
            Ok(())
        });
        let credential = Credentials::bearer(crate::hex(&[0x31; 32]))?;
        let error =
            send_credential(&endpoint, &credential, CredentialAction::Replace, b"{}").unwrap_err();
        assert_eq!(
            crate::error::classify(&error),
            crate::error::Failure::VersionConflict
        );
        assert!(!format!("{error:?}").contains("echo-this-secret"));
        server.join().expect("loopback thread")?;
        Ok(())
    }

    #[test]
    fn credential_transport_signs_only_allowlisted_private_routes() -> Result<()> {
        for (action, path) in [
            (CredentialAction::Status, "/v1/credentials/status"),
            (CredentialAction::Replace, "/v1/credentials/replace"),
            (CredentialAction::Retain, "/v1/credentials/retain"),
            (CredentialAction::Clear, "/v1/credentials/clear"),
        ] {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let endpoint = format!("http://{}", listener.local_addr()?);
            let key = vec![0x42; 32];
            let key_hex = crate::hex(&key);
            let server = thread::spawn(move || -> Result<()> {
                let (mut stream, _) = listener.accept()?;
                let (headers, body) = read_request(&mut stream)?;
                ensure!(
                    headers.starts_with(&format!("POST {path} HTTP/1.1\r\n")),
                    "credential route mismatch"
                );
                ensure!(
                    body == br#"{"identity":{}}"#,
                    "credential request body changed"
                );
                let header = |name: &str| -> Result<String> {
                    headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case(name)
                                .then(|| value.trim().to_owned())
                        })
                        .context("missing credential auth header")
                };
                let timestamp = header("x-freetool-timestamp")?;
                let nonce = header("x-freetool-nonce")?;
                let supplied_digest = header("x-freetool-body-sha256")?;
                let signature = header("x-freetool-signature")?;
                ensure!(nonce.len() == 48, "nonce is not 24 random bytes");
                ensure!(
                    supplied_digest == crate::hex(digest(&SHA256, &body).as_ref()),
                    "credential digest mismatch"
                );
                let canonical = format!("POST\n{path}\n{timestamp}\n{nonce}\n{supplied_digest}");
                let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
                let signature = decode_hex(&signature).context("bad signature hex")?;
                hmac::verify(&signing_key, canonical.as_bytes(), &signature)
                    .map_err(|_| anyhow::anyhow!("bad credential signature"))?;
                let response = br#"{"status":"absent","credential_id":null,"version":0}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.len()
                )?;
                stream.write_all(response)?;
                Ok(())
            });
            let credential = Credentials::bearer(key_hex)?;
            let body = br#"{"identity":{}}"#;
            let response = send_credential(&endpoint, &credential, action, body);
            server
                .join()
                .map_err(|_| anyhow::anyhow!("loopback server panicked"))??;
            response?;
        }
        Ok(())
    }

    #[test]
    fn loopback_transport_does_not_follow_redirects() -> Result<()> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let server = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let _ = read_request(&mut stream)?;
            stream.write_all(b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")?;
            Ok(())
        });
        let credential = Credentials::bearer(crate::hex(&[0x31; 32]))?;
        let exchange = send(&endpoint, &credential, b"{}", MAX_EXECUTOR_WIRE_BYTES);
        assert!(exchange.response.is_err());
        assert_eq!(exchange.request_bytes, 2);
        assert!(exchange.dispatched);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("loopback server panicked"))??;
        Ok(())
    }

    fn decode_hex(value: &str) -> Option<Vec<u8>> {
        if !value.len().is_multiple_of(2) {
            return None;
        }
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let digit = |byte: u8| match byte {
                    b'0'..=b'9' => Some(byte - b'0'),
                    b'a'..=b'f' => Some(byte - b'a' + 10),
                    _ => None,
                };
                Some(digit(pair[0])? * 16 + digit(pair[1])?)
            })
            .collect()
    }
}
