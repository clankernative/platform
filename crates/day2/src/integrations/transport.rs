use super::AdapterError;
use day2_capabilities::integrations::LiveConnection;
use reqwest::{
    blocking::Client,
    header::{HeaderName, HeaderValue},
    redirect::Policy,
};
use std::{io::Read, time::Duration};

/// No Debug/Serialize implementation: credential bytes cannot enter receipts.
pub(crate) struct Credentials(String);

impl Credentials {
    pub(super) fn slack_webhook_url(&self, digest: &str) -> Result<&str, AdapterError> {
        super::slack_webhook::validate_url(&self.0, digest)?;
        Ok(&self.0)
    }

    pub(crate) fn bearer(value: String) -> Result<Self, AdapterError> {
        Self::validate(&value)?;
        Ok(Self(value))
    }

    pub(crate) fn validate(value: &str) -> Result<(), AdapterError> {
        if value.is_empty() || value.len() > 16_384 || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(AdapterError::CredentialUnavailable);
        }
        Ok(())
    }
}

/// Secret material used *locally* and never transmitted.
///
/// Two uses share this type because they share the property that matters: an
/// inbound signature is verified against it, and an outbound presigned URL is
/// derived from it, and in neither case does the secret itself leave the process.
/// A bearer token is the opposite — it goes in a header, on the wire, into any log
/// that records a request.
///
/// Deliberately not `Credentials`, and deliberately without a `bearer`
/// constructor. A bot token is transmitted to the provider on every call; a
/// signing secret is never transmitted at all. Sharing one type would make both
/// dangerous confusions representable — a signing secret leaked outbound in an
/// Authorization header, or a bot token accepted as a verification key so that
/// anyone holding it could forge deliveries. Separate types make neither
/// expressible rather than merely discouraged.
///
/// No Debug or Serialize, for the same reason as `Credentials`.
// REMOVE WITH THE INGRESS ROUTE: the key is read only when verifying a
// delivery, and nothing verifies one yet.
#[allow(dead_code)]
pub struct LocalSecret(String);

impl LocalSecret {
    pub(crate) fn new(value: String) -> Result<Self, AdapterError> {
        if value.is_empty() || value.len() > 16_384 || !value.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(AdapterError::CredentialUnavailable);
        }
        Ok(Self(value))
    }

    /// The only way out, and it is not a header value: verification computes an
    /// HMAC locally and the key never leaves the process.
    #[allow(dead_code)] // REMOVE WITH THE INGRESS ROUTE.
    pub(crate) fn as_hmac_key(&self) -> &str {
        &self.0
    }
}

/// The HTTP method a reviewed request uses.
///
/// An enum rather than a boolean because the set is now open past GET and POST:
/// an object store answers existence with HEAD and reclaims storage with DELETE,
/// and a boolean cannot say which.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
    Head,
    Delete,
}

impl Method {
    /// Only a POST carries one; everything else states its request in the URL.
    fn carries_a_body(self) -> bool {
        matches!(self, Self::Post)
    }
}

/// How a request proves it is allowed.
///
/// The two arms are not interchangeable and must not be defaultable. A bearer
/// token is transmitted to the provider in a header. A presigned request carries
/// its authorization in the URL's signature, and the secret it was derived from —
/// a [`LocalSecret`] — must never be transmitted at all.
///
/// Making this an explicit argument is what keeps that invariant structural rather
/// than remembered. `Presigned` holds no credential, so there is nothing for the
/// transport to attach; and because `LocalSecret` has no `bearer` constructor, an
/// object store's secret cannot become a `Credentials` in the first place. A
/// transport that took `&Credentials` unconditionally would have forced one of
/// those two rules to be broken to send a HEAD at all.
#[derive(Clone, Copy)]
pub(crate) enum Authorization<'a> {
    Bearer(&'a Credentials),
    Presigned,
    /// The secret URL is already validated and pinned; attach JSON headers only.
    Webhook,
}

/// Object metadata worth reading off a response, and nothing else.
///
/// An allowlist rather than the whole header map: response headers carry vendor
/// identifiers, request ids and timing that have no business reaching an
/// application or a receipt, and copying them wholesale is how provider data leaks
/// into places it was never reviewed for.
pub(crate) const OBJECT_METADATA: &[&str] = &[
    "content-length",
    "etag",
    "last-modified",
    // Where a redirect points. The client follows no redirects — `Policy::none`
    // — because following one strips the Authorization header across an origin
    // change and lands the response somewhere nobody reviewed. A provider that
    // answers with a signed URL is answering *with the URL*, so the location is
    // the result rather than a step on the way to it.
    "location",
];

pub(crate) trait CredentialResolver: Send + Sync {
    fn resolve(&self, connection: &LiveConnection) -> Result<Credentials, AdapterError>;
}

/// A closed request built only by this module's reviewed provider builders.
/// Deliberately lacks Debug to keep prompts, filters and message content private.
#[derive(Clone)]
pub(crate) struct WireRequest {
    pub(super) url: String,
    pub(super) body: Vec<u8>,
    pub(super) headers: Vec<(&'static str, String)>,
    pub(super) method: Method,
}

impl WireRequest {
    #[cfg(test)]
    pub(crate) fn client_request_id(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| *name == "x-client-request-id")
            .map(|(_, value)| value.as_str())
    }

    pub(super) fn json(url: &str, body: Vec<u8>) -> Self {
        Self {
            url: url.into(),
            body,
            headers: vec![],
            method: Method::Post,
        }
    }

    pub(super) fn payload_bytes(&self) -> u64 {
        if self.method.carries_a_body() {
            self.body.len() as u64
        } else {
            self.url
                .split_once('?')
                .map_or(0, |(_, query)| query.len() as u64)
        }
    }
}

pub(crate) struct WireResponse {
    pub(crate) status: u16,
    pub(crate) json_content_type: bool,
    pub(crate) body: Vec<u8>,
    pub(crate) request_id: Option<String>,
    /// Allowlisted object metadata. Empty for every provider but the object store,
    /// whose HEAD answers entirely in headers and carries no body at all.
    pub(crate) metadata: Vec<(&'static str, String)>,
}

pub(crate) struct TransportError {
    pub(crate) kind: AdapterError,
    pub(crate) response_bytes: u64,
    pub(crate) http_status: Option<u16>,
    pub(crate) request_id: Option<String>,
}

pub(crate) trait Transport: Send + Sync {
    fn send(
        &self,
        request: &WireRequest,
        authorization: Authorization<'_>,
        max_response_bytes: u64,
    ) -> Result<WireResponse, TransportError>;
}

pub(crate) struct HttpTransport(Client);

impl HttpTransport {
    pub(crate) fn new() -> Result<Self, AdapterError> {
        Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            // No cookie_store/provider is installed (default disabled).
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(0)
            .user_agent("day2-reviewed-integrations/1")
            .build()
            .map(Self)
            .map_err(|_| AdapterError::TransportUnavailable)
    }
}

impl Transport for HttpTransport {
    fn send(
        &self,
        request: &WireRequest,
        authorization: Authorization<'_>,
        max_response_bytes: u64,
    ) -> Result<WireResponse, TransportError> {
        let failure = |kind| TransportError {
            kind,
            response_bytes: 0,
            http_status: None,
            request_id: None,
        };
        let mut builder = match request.method {
            Method::Get => self.0.get(&request.url),
            Method::Post => self.0.post(&request.url).body(request.body.clone()),
            Method::Head => self.0.head(&request.url),
            Method::Delete => self.0.delete(&request.url),
        };
        builder = builder.header("accept-encoding", "identity");
        match authorization {
            Authorization::Bearer(credential) => {
                let mut value = HeaderValue::from_str(&format!("Bearer {}", credential.0))
                    .map_err(|_| failure(AdapterError::CredentialUnavailable))?;
                value.set_sensitive(true);
                builder = builder
                    .header("authorization", value)
                    .header("accept", "application/json")
                    .header("content-type", "application/json; charset=utf-8");
            }
            // Nothing is attached. The URL's signature is the authorization, and
            // attaching the secret it was derived from would hand the store the
            // key to every other object in the bucket.
            Authorization::Presigned => {}
            Authorization::Webhook => {
                builder = builder.header("content-type", "application/json; charset=utf-8");
            }
        }
        for (name, value) in &request.headers {
            let value =
                HeaderValue::from_str(value).map_err(|_| failure(AdapterError::InvalidProfile))?;
            builder = builder.header(HeaderName::from_static(name), value);
        }
        let response = builder
            .send()
            .map_err(|_| failure(AdapterError::TransportUnavailable))?;
        let status = response.status().as_u16();
        let request_id = if request.url == "https://api.openai.com/v1/responses" {
            response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .and_then(super::correlation_identifier)
        } else {
            None
        };
        let response_failure = |kind, response_bytes| TransportError {
            kind,
            response_bytes,
            http_status: Some(status),
            request_id: request_id.clone(),
        };
        let json_content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
            });
        if response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
        {
            return Err(response_failure(AdapterError::ResponseInvalid, 0));
        }
        if response
            .content_length()
            .is_some_and(|size| size > max_response_bytes)
        {
            return Err(response_failure(AdapterError::ResponseTooLarge, 0));
        }
        let metadata = OBJECT_METADATA
            .iter()
            .filter_map(|name| {
                let value = response.headers().get(*name)?.to_str().ok()?;
                // Bounded and printable: these reach an application.
                (value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic()))
                    .then(|| (*name, value.to_owned()))
            })
            .collect();
        let mut body = Vec::new();
        let mut reader = response.take(max_response_bytes.saturating_add(1));
        if reader.read_to_end(&mut body).is_err() {
            return Err(response_failure(
                AdapterError::TransportUnavailable,
                body.len() as u64,
            ));
        }
        if body.len() as u64 > max_response_bytes {
            return Err(response_failure(
                AdapterError::ResponseTooLarge,
                body.len() as u64,
            ));
        }
        Ok(WireResponse {
            status,
            json_content_type,
            body,
            request_id,
            metadata,
        })
    }
}
