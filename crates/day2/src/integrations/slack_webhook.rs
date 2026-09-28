//! https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/
//! A pinned destination, secret URL, and one non-retried write.

use super::{AdapterError, PreparedCall, ResponseProfile, WireRequest, WireResponse};
use day2_capabilities::integrations::LiveConnection;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostRequest {
    handle: String,
    text: String,
}

pub(super) fn validate_url(url: &str, expected: &str) -> Result<(), AdapterError> {
    let tail = url
        .strip_prefix("https://hooks.slack.com/services/")
        .ok_or(AdapterError::CredentialUnavailable)?;
    let segments: Vec<_> = tail.split('/').collect();
    if url.len() > 1024
        || segments.len() != 3
        || segments.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        || format!("{:x}", Sha256::digest(url.as_bytes())) != expected
    {
        return Err(AdapterError::CredentialUnavailable);
    }
    Ok(())
}

pub(super) fn prepare(
    connection: &LiveConnection,
    endpoint_sha256: &str,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let input: PostRequest =
        serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
    if input.handle.is_empty()
        || input.text.trim().is_empty()
        || input.text.chars().count() > 3000
        || input
            .text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(AdapterError::InvalidRequest);
    }
    let fallback = input
        .text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let body = json!({"text":fallback,"mrkdwn":false,"link_names":false,"parse":"none",
        "unfurl_links":false,"unfurl_media":false,
        "blocks":[{"type":"section","text":{"type":"plain_text","text":input.text,"emoji":false}}]});
    Ok(PreparedCall {
        connection: connection.clone(),
        // Filled only after secret resolution and digest validation. This value is
        // never transmitted and neither the secret nor a URL enters the receipt.
        request: WireRequest::json("", body.to_string().into_bytes()),
        response: ResponseProfile::SlackWebhook {
            endpoint_sha256: endpoint_sha256.into(),
        },
        response_limit: 0,
        reserved_monetary_microusd: Some(0),
    })
}

pub(super) fn response(response: &WireResponse) -> (Result<Value, AdapterError>, bool) {
    if response.status == 200 && response.body == b"ok" {
        return (Ok(json!({"status":"accepted"})), false);
    }
    match response.status {
        400 | 401 | 403 | 404 | 410 => (Err(AdapterError::ProviderDenied), false),
        429 => (Err(AdapterError::RateLimited), false),
        _ => (Err(AdapterError::ResponseInvalid), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::{
        self, Authorization, CredentialResolver, Credentials, Transport, TransportError,
    };
    use day2_capabilities::resources::{Action, ResourceTarget, VersionRef};
    use std::sync::Mutex;

    const URL: &str = "https://hooks.slack.com/services/TEXAMPLE/BEXAMPLE/fake-secret";

    struct Secret(&'static str);
    impl CredentialResolver for Secret {
        fn resolve(&self, _: &LiveConnection) -> Result<Credentials, AdapterError> {
            Credentials::bearer(self.0.into())
        }
    }

    struct Socket {
        calls: Mutex<u64>,
        status: u16,
        body: &'static [u8],
        lose_reply: bool,
    }
    impl Transport for Socket {
        fn send(
            &self,
            request: &WireRequest,
            authorization: Authorization<'_>,
            _: u64,
        ) -> Result<WireResponse, TransportError> {
            *self.calls.lock().unwrap() += 1;
            assert!(matches!(authorization, Authorization::Webhook));
            assert_eq!(request.url, URL);
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            assert!(body.get("channel").is_none());
            assert_eq!(body["blocks"][0]["text"]["type"], "plain_text");
            assert_eq!(body["text"], "CI &lt;!channel&gt; &amp; test");
            if self.lose_reply {
                return Err(TransportError {
                    kind: AdapterError::TransportUnavailable,
                    response_bytes: 0,
                    http_status: None,
                    request_id: None,
                });
            }
            Ok(WireResponse {
                status: self.status,
                json_content_type: false,
                body: self.body.into(),
                request_id: None,
                metadata: vec![],
            })
        }
    }

    fn call() -> PreparedCall {
        integrations::prepare(
            &Action::SlackWebhookPost,
            &LiveConnection::SlackWebhook {
                credential_ref: VersionRef {
                    id: "webhook".into(),
                    revision: 1,
                },
            },
            &ResourceTarget::SlackWebhookDestination {
                endpoint_sha256: format!("{:x}", Sha256::digest(URL.as_bytes())),
            },
            &json!({"handle":"opaque","text":"CI <!channel> & test"}).to_string(),
            65536,
            1024,
        )
        .unwrap()
    }

    #[test]
    fn exact_secret_destination_is_required_before_dispatch() {
        let digest = format!("{:x}", Sha256::digest(URL.as_bytes()));
        assert!(validate_url(URL, &digest).is_ok());
        for url in [
            "https://evil.example/services/T/B/secret",
            "http://hooks.slack.com/services/T/B/secret",
            "https://hooks.slack.com/services/T/B/secret?x=1",
            "https://hooks.slack.com/services/T/B/secret#x",
            "https://hooks.slack.com/services/T/B/../secret",
            "https://hooks.slack.com/services/T/B/%61",
        ] {
            assert!(validate_url(url, &format!("{:x}", Sha256::digest(url.as_bytes()))).is_err());
        }
        let socket = Socket {
            calls: Mutex::new(0),
            status: 200,
            body: b"ok",
            lose_reply: false,
        };
        let outcome = integrations::execute(
            &call(),
            &Secret("https://hooks.slack.com/services/TOTHER/BOTHER/other-secret"),
            &socket,
            "attempt",
        );
        assert_eq!(outcome.result, Err(AdapterError::CredentialUnavailable));
        assert!(!outcome.dispatched);
        assert_eq!(*socket.calls.lock().unwrap(), 0);
    }

    #[test]
    fn plain_success_receipt_has_no_url_or_invented_message_identity() {
        let call = call();
        assert_eq!(call.max_calls(), 1);
        let socket = Socket {
            calls: Mutex::new(0),
            status: 200,
            body: b"ok",
            lose_reply: false,
        };
        let outcome = integrations::execute(&call, &Secret(URL), &socket, "attempt");
        assert_eq!(outcome.result.unwrap(), r#"{"status":"accepted"}"#);
        assert!(!outcome.outcome_unknown);
        assert_eq!(outcome.calls, 1);
    }

    #[test]
    fn lost_or_unrecognized_replies_are_unknown_and_never_retried() {
        for (status, body, lose, unknown) in [
            (200, b"ok".as_slice(), true, true),
            (500, b"error", false, true),
            (200, b"unexpected", false, true),
            (302, b"redirect", false, true),
            (403, b"action_prohibited", false, false),
            (429, b"rate_limited", false, false),
        ] {
            let socket = Socket {
                calls: Mutex::new(0),
                status,
                body,
                lose_reply: lose,
            };
            let outcome = integrations::execute(&call(), &Secret(URL), &socket, "attempt");
            assert!(outcome.result.is_err());
            assert_eq!(outcome.outcome_unknown, unknown);
            assert_eq!(*socket.calls.lock().unwrap(), 1);
        }
    }

    #[test]
    fn app_cannot_supply_a_url_channel_or_oversized_message() {
        let connection = LiveConnection::SlackWebhook {
            credential_ref: VersionRef {
                id: "webhook".into(),
                revision: 1,
            },
        };
        for request in [
            json!({"handle":"opaque","text":"message","url":URL}),
            json!({"handle":"opaque","text":"message","channel":"COTHER"}),
            json!({"handle":"opaque","text":"x".repeat(3001)}),
            json!({"handle":"opaque","text":"\u{0000}"}),
        ] {
            assert!(prepare(&connection, "digest", &request.to_string()).is_err());
        }
    }
}
