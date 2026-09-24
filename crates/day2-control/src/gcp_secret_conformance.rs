//! Metadata-only sandbox probes, not a qualified runtime retirement adapter.
//! GCP ETags are opaque and metadata reads are eventually consistent. Neither a
//! missing response nor an enabled readback proves a disable cannot apply later.

use crate::{
    Digest,
    secrets::{AccessTokenProvider, SecretVersion},
};
use reqwest::{
    blocking::{Client, Response},
    header::AUTHORIZATION,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    sync::Arc,
    time::Duration,
};
use url::{Host, Url};

const MAX_RESPONSE_BYTES: usize = 32 * 1024;
const OWNERSHIP_LABEL: &str = "day2-conformance-run";
type Result<T> = std::result::Result<T, GcpError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpError {
    InvalidConfiguration,
    InvalidReference,
    NotAllowlisted,
    CredentialsUnavailable,
    TransportUnknown,
    Unauthorized,
    NotFound,
    RateLimited,
    RemoteRejected,
    RedirectForbidden,
    InvalidResponse,
    ResponseBudget,
    OwnershipMismatch,
    FixtureNotEnabled,
    IncarnationChanged,
    PreconditionChanged,
}
impl fmt::Display for GcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GCP conformance: {self:?}")
    }
}
impl std::error::Error for GcpError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OpaqueEtag(String);
impl OpaqueEtag {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for OpaqueEtag {
    type Error = GcpError;
    fn try_from(value: String) -> Result<Self> {
        if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(GcpError::InvalidResponse);
        }
        Ok(Self(value))
    }
}
impl From<OpaqueEtag> for String {
    fn from(value: OpaqueEtag) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VersionState {
    Enabled,
    Disabled,
    Destroyed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMetadata {
    pub project_number: u64,
    pub secret: String,
    pub create_time: String,
    pub etag: OpaqueEtag,
    pub run_marker: String,
    pub version_aliases: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionMetadata {
    pub version: SecretVersion,
    pub create_time: String,
    pub state: VersionState,
    pub etag: OpaqueEtag,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub secret: SecretMetadata,
    pub first: VersionMetadata,
    pub second: VersionMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AliasResolution {
    pub alias: String,
    pub parent: SecretMetadata,
    pub version: VersionMetadata,
}

/// The session must durably reserve exactly one dispatch of this request. Its
/// ETag is never refreshed: a later request needs separate operator authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableAttempt {
    pub effect: Digest,
    pub version: SecretVersion,
    pub expected_etag: OpaqueEtag,
    pub expected_create_time: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDelivery {
    Deliver,
    LoseAck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisableRejection {
    PreconditionFailed,
    Unauthorized,
    NotFound,
    RateLimited,
    RedirectForbidden,
    RemoteRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisableOutcome {
    Acknowledged { metadata: VersionMetadata },
    Uncertain {},
    Rejected { reason: DisableRejection },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationReason {
    NotDisabled,
    Destroyed,
    NotFound,
    TransportUnknown,
    RateLimited,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisabledObservation {
    DisabledObservation {
        metadata: VersionMetadata,
    },
    Inconclusive {
        reason: ObservationReason,
        metadata: Option<VersionMetadata>,
    },
}

pub struct GcpSandboxClient {
    client: Client,
    endpoint: Url,
    project_number: u64,
    allowed_secrets: BTreeSet<String>,
    run_marker: String,
    tokens: Arc<dyn AccessTokenProvider>,
}

impl GcpSandboxClient {
    pub fn new(
        project_number: u64,
        allowed_secrets: BTreeSet<String>,
        run_marker: String,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        Self::with_endpoint(
            "https://secretmanager.googleapis.com/",
            project_number,
            allowed_secrets,
            run_marker,
            tokens,
        )
    }

    /// Loopback HTTP is only a protocol-test transport; it is not cloud evidence.
    pub fn with_endpoint(
        endpoint: &str,
        project_number: u64,
        allowed_secrets: BTreeSet<String>,
        run_marker: String,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).map_err(|_| GcpError::InvalidConfiguration)?;
        let loopback = match endpoint.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            Some(Host::Domain("localhost")) => true,
            _ => false,
        };
        let google = endpoint.scheme() == "https"
            && endpoint.host_str() == Some("secretmanager.googleapis.com")
            && endpoint.port().is_none();
        if !(google || (endpoint.scheme() == "http" && loopback))
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || project_number == 0
            || allowed_secrets.is_empty()
            || allowed_secrets.len() > 8
            || run_marker.is_empty()
            || run_marker.len() > 63
            || !run_marker
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err(GcpError::InvalidConfiguration);
        }
        for secret in &allowed_secrets {
            SecretVersion {
                project_number,
                secret: secret.clone(),
                version: 1,
            }
            .validate()
            .map_err(|_| GcpError::InvalidConfiguration)?;
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .user_agent("day2-gcp-conformance/0.1")
            .build()
            .map_err(|_| GcpError::InvalidConfiguration)?;
        Ok(Self {
            client,
            endpoint,
            project_number,
            allowed_secrets,
            run_marker,
            tokens,
        })
    }

    pub fn validate_fixture(&self, secret: &str, versions: [u64; 2]) -> Result<Fixture> {
        if versions[0] == 0 || versions[1] == 0 || versions[0] == versions[1] {
            return Err(GcpError::InvalidReference);
        }
        let parent = self.parent_metadata(secret)?;
        let first = self.metadata(&self.version(secret, versions[0]))?;
        let second = self.metadata(&self.version(secret, versions[1]))?;
        if first.state != VersionState::Enabled || second.state != VersionState::Enabled {
            return Err(GcpError::FixtureNotEnabled);
        }
        Ok(Fixture {
            secret: parent,
            first,
            second,
        })
    }

    pub fn resolve_alias(&self, secret: &str, alias: &str) -> Result<AliasResolution> {
        if !valid_alias(alias) {
            return Err(GcpError::InvalidReference);
        }
        let parent = self.parent_metadata(secret)?;
        let version = *parent
            .version_aliases
            .get(alias)
            .ok_or(GcpError::NotFound)?;
        let metadata = self.metadata(&self.version(secret, version))?;
        Ok(AliasResolution {
            alias: alias.to_owned(),
            parent,
            version: metadata,
        })
    }

    pub fn metadata(&self, version: &SecretVersion) -> Result<VersionMetadata> {
        self.require_version(version)?;
        let response = self.get(&version.resource_name())?;
        version_metadata(decode_response(response)?, version)
    }

    pub fn parent_metadata(&self, secret: &str) -> Result<SecretMetadata> {
        self.require_version(&self.version(secret, 1))?;
        let name = format!("projects/{}/secrets/{secret}", self.project_number);
        let response: ApiSecret = decode_response(self.get(&name)?)?;
        if response.name != name || !valid_creation_time(&response.create_time) {
            return Err(GcpError::InvalidResponse);
        }
        if response.labels.get(OWNERSHIP_LABEL) != Some(&self.run_marker) {
            return Err(GcpError::OwnershipMismatch);
        }
        if response.version_aliases.len() > 50 {
            return Err(GcpError::InvalidResponse);
        }
        let mut aliases = BTreeMap::new();
        for (alias, version) in response.version_aliases {
            let number: u64 = version.parse().map_err(|_| GcpError::InvalidResponse)?;
            if !valid_alias(&alias) || number == 0 || number.to_string() != version {
                return Err(GcpError::InvalidResponse);
            }
            aliases.insert(alias, number);
        }
        Ok(SecretMetadata {
            project_number: self.project_number,
            secret: secret.to_owned(),
            create_time: response.create_time,
            etag: response.etag,
            run_marker: self.run_marker.clone(),
            version_aliases: aliases,
        })
    }

    /// Sends at most one conditional POST. This does not deduplicate calls made
    /// by its caller; the durable session owns dispatch authorization and fencing.
    pub fn disable_once(
        &self,
        attempt: &DisableAttempt,
        delivery: ResponseDelivery,
    ) -> Result<DisableOutcome> {
        self.require_version(&attempt.version)?;
        if !valid_creation_time(&attempt.expected_create_time) {
            return Err(GcpError::InvalidReference);
        }
        self.parent_metadata(&attempt.version.secret)?;
        let before = self.metadata(&attempt.version)?;
        if before.create_time != attempt.expected_create_time {
            return Err(GcpError::IncarnationChanged);
        }
        if before.etag != attempt.expected_etag || before.state != VersionState::Enabled {
            return Err(GcpError::PreconditionChanged);
        }
        let url = self.url(&format!("{}:disable", attempt.version.resource_name()))?;
        let response = self
            .client
            .post(url)
            .header(AUTHORIZATION, self.authorization()?)
            .json(&DisableBody {
                etag: &attempt.expected_etag,
            })
            .send();
        let response = match response {
            Ok(response) => response,
            Err(_) => return Ok(DisableOutcome::Uncertain {}),
        };
        if delivery == ResponseDelivery::LoseAck {
            return Ok(DisableOutcome::Uncertain {});
        }
        let status = response.status().as_u16();
        if status == 200 {
            // Invalid or incomplete success bodies cannot establish whether the
            // mutation applied. They must not turn into permission to retry.
            let parsed = decode_body::<ApiVersion>(response)
                .and_then(|body| version_metadata(body, &attempt.version));
            return Ok(match parsed {
                Ok(metadata)
                    if metadata.state == VersionState::Disabled
                        && metadata.create_time == attempt.expected_create_time
                        && metadata.etag != attempt.expected_etag =>
                {
                    DisableOutcome::Acknowledged { metadata }
                }
                _ => DisableOutcome::Uncertain {},
            });
        }
        if status == 408 || status >= 500 {
            return Ok(DisableOutcome::Uncertain {});
        }
        let reason = match status {
            400 => match decode_body::<ApiErrorResponse>(response) {
                Ok(body) if body.error.status == "FAILED_PRECONDITION" => {
                    DisableRejection::PreconditionFailed
                }
                _ => DisableRejection::RemoteRejected,
            },
            401 | 403 => DisableRejection::Unauthorized,
            404 => DisableRejection::NotFound,
            429 => DisableRejection::RateLimited,
            300..=399 => DisableRejection::RedirectForbidden,
            _ => DisableRejection::RemoteRejected,
        };
        Ok(DisableOutcome::Rejected { reason })
    }

    pub fn observe_disabled(
        &self,
        version: &SecretVersion,
        expected_create_time: &str,
    ) -> Result<DisabledObservation> {
        if !valid_creation_time(expected_create_time) {
            return Err(GcpError::InvalidReference);
        }
        let metadata = match self.metadata(version) {
            Ok(value) => value,
            Err(error) => {
                let reason = match error {
                    GcpError::NotFound => ObservationReason::NotFound,
                    GcpError::TransportUnknown => ObservationReason::TransportUnknown,
                    GcpError::RateLimited => ObservationReason::RateLimited,
                    _ => return Err(error),
                };
                return Ok(DisabledObservation::Inconclusive {
                    reason,
                    metadata: None,
                });
            }
        };
        if metadata.create_time != expected_create_time {
            return Err(GcpError::IncarnationChanged);
        }
        Ok(match metadata.state {
            VersionState::Disabled => DisabledObservation::DisabledObservation { metadata },
            VersionState::Enabled => DisabledObservation::Inconclusive {
                reason: ObservationReason::NotDisabled,
                metadata: Some(metadata),
            },
            VersionState::Destroyed => DisabledObservation::Inconclusive {
                reason: ObservationReason::Destroyed,
                metadata: Some(metadata),
            },
        })
    }

    fn version(&self, secret: &str, version: u64) -> SecretVersion {
        SecretVersion {
            project_number: self.project_number,
            secret: secret.to_owned(),
            version,
        }
    }

    fn require_version(&self, version: &SecretVersion) -> Result<()> {
        version.validate().map_err(|_| GcpError::InvalidReference)?;
        if version.project_number != self.project_number
            || !self.allowed_secrets.contains(&version.secret)
        {
            return Err(GcpError::NotAllowlisted);
        }
        Ok(())
    }

    fn authorization(&self) -> Result<reqwest::header::HeaderValue> {
        self.tokens
            .access_token()
            .and_then(|token| token.authorization_header())
            .map_err(|_| GcpError::CredentialsUnavailable)
    }

    fn url(&self, resource: &str) -> Result<Url> {
        self.endpoint
            .join(&format!("v1/{resource}"))
            .map_err(|_| GcpError::InvalidReference)
    }

    fn get(&self, resource: &str) -> Result<Response> {
        self.client
            .get(self.url(resource)?)
            .header(AUTHORIZATION, self.authorization()?)
            .header("accept", "application/json")
            .send()
            .map_err(|_| GcpError::TransportUnknown)
    }
}

fn valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        && !value.eq_ignore_ascii_case("latest")
        && !value.eq_ignore_ascii_case("new")
}

fn valid_creation_time(value: &str) -> bool {
    // Retained as opaque identity evidence, never interpreted as a revision clock.
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_graphic())
}

fn version_metadata(response: ApiVersion, version: &SecretVersion) -> Result<VersionMetadata> {
    if response.name != version.resource_name() || !valid_creation_time(&response.create_time) {
        return Err(GcpError::InvalidResponse);
    }
    Ok(VersionMetadata {
        version: version.clone(),
        create_time: response.create_time,
        state: response.state,
        etag: response.etag,
    })
}

fn decode_response<T: DeserializeOwned>(response: Response) -> Result<T> {
    match response.status().as_u16() {
        200 => decode_body(response),
        401 | 403 => Err(GcpError::Unauthorized),
        404 => Err(GcpError::NotFound),
        429 => Err(GcpError::RateLimited),
        408 | 500..=599 => Err(GcpError::TransportUnknown),
        300..=399 => Err(GcpError::RedirectForbidden),
        _ => Err(GcpError::RemoteRejected),
    }
}

fn decode_body<T: DeserializeOwned>(response: Response) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(GcpError::ResponseBudget);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GcpError::TransportUnknown)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(GcpError::ResponseBudget);
    }
    serde_json::from_slice(&bytes).map_err(|_| GcpError::InvalidResponse)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiSecret {
    name: String,
    create_time: String,
    etag: OpaqueEtag,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    version_aliases: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiVersion {
    name: String,
    create_time: String,
    state: VersionState,
    etag: OpaqueEtag,
}

#[derive(Serialize)]
struct DisableBody<'a> {
    etag: &'a OpaqueEtag,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: ApiError,
}
#[derive(Deserialize)]
struct ApiError {
    status: String,
}
