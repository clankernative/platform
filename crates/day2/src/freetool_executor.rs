//! Private adapter for the typed Freetool executor capability pack.
//!
//! The SDK's typed contracts are translated here into the executor service's
//! wire DTOs. Trusted dispatch facts are supplied by Runtime; Roc may supply only
//! the already-authorized business execution identity and complete plan.
use anyhow::{Context, Result, ensure};
use day2_capabilities::{integrations::LiveConnection, resources::VersionRef};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

pub const MAX_RESULT_PAGE_BYTES: u32 = 12_000;
pub const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
pub(crate) const CREDENTIALS_PATH_PREFIX: &str = "/__freetool/credentials/";

pub(crate) fn credential_management_path(resource: &str) -> Result<String> {
    ensure!(
        crate::identity::valid_for(resource, "res"),
        "invalid_freetool_credential_resource"
    );
    Ok(format!("{CREDENTIALS_PATH_PREFIX}{resource}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunClaims {
    pub resource_id: String,
    pub configuration_id: String,
    pub immutable_version: u64,
    pub configuration_digest: String,
    pub run_id: String,
    pub arguments_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionIdentity {
    pub installation: String,
    pub application: String,
    pub actor: String,
    pub artifact: String,
    pub operation: String,
    pub resource_id: String,
    pub configuration_id: String,
    pub immutable_version: u64,
    pub configuration_digest: String,
    pub run_id: String,
    pub arguments_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExecutionPlan {
    Http {
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Postgres {
        resource_binding_id: String,
        statement: String,
        parameters: Vec<SqlValue>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum SqlValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Decimal(String),
    Text(String),
    Bytes(Vec<u8>),
    Date(String),
    Timestamp(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ServiceRequest {
    Register {
        identity: ExecutionIdentity,
        plan: ExecutionPlan,
    },
    Execute {
        identity: ExecutionIdentity,
    },
    Status {
        identity: ExecutionIdentity,
    },
    ResultPage {
        identity: ExecutionIdentity,
        offset: u64,
        limit: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ServiceResponse {
    Registered {
        manifest_digest: String,
    },
    Executed {
        outcome: Outcome,
    },
    Status {
        receipt: Option<Box<ReceiptSnapshot>>,
    },
    ResultPage {
        result_id: String,
        digest: String,
        total_bytes: u64,
        offset: u64,
        bytes: Vec<u8>,
    },
    Error {
        code: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "outcome",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum ReceiptState {
    Dispatching,
    Settled(Outcome),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptSnapshot {
    pub identity: ExecutionIdentity,
    pub state: ReceiptState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Outcome {
    Succeeded {
        result_id: String,
        digest: String,
        byte_count: u64,
    },
    Rejected {
        code: String,
    },
    Failed {
        code: String,
    },
    Unknown {
        code: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FingerprintInput {
    configuration_document: String,
    arguments_document: String,
    handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityInput {
    run: RunClaims,
    #[serde(default)]
    plan: Option<ExecutionPlan>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    limit: Option<u32>,
    handle: String,
}

pub(crate) fn identity(
    runtime: &crate::store::Runtime,
    request: &crate::protocol::Request,
    claims: RunClaims,
) -> Result<ExecutionIdentity> {
    let operation = runtime.artifact().route(&request.operation)?;
    let (installation, _environment, app) = runtime
        .scope()
        .split_once('/')
        .and_then(|(a, rest)| rest.split_once('/').map(|(b, c)| (a, b, c)))
        .context("invalid_runtime_scope")?;
    ensure!(
        app == "freetool",
        crate::error::Failure::CapabilityForbidden
    );
    trusted_identity(
        &format!("{installation}/{_environment}"),
        &request.context.actor,
        runtime.artifact().id(),
        &operation.name,
        claims,
    )
}

fn authorize_resource_scope(
    scope: &day2_capabilities::resources::FreetoolResourceScope,
    resource_id: &str,
) -> Result<()> {
    ensure!(
        scope.authorizes(resource_id),
        crate::error::Failure::ResourceForbidden
    );
    Ok(())
}

fn authorize_input(
    runtime: &crate::store::Runtime,
    request: &crate::protocol::Request,
    instruction: &crate::protocol::Instruction,
    grant: &crate::resources::ResourceUse,
) -> Result<(CapabilityInput, ExecutionIdentity)> {
    let input: CapabilityInput = serde_json::from_str(&instruction.data)?;
    ensure!(
        input.handle == grant.handle,
        crate::error::Failure::ResourceForbidden
    );
    let day2_capabilities::resources::ResourceTarget::FreetoolExecutor { scope, .. } =
        &grant.grant.target
    else {
        anyhow::bail!(crate::error::Failure::ResourceForbidden)
    };
    authorize_resource_scope(scope, &input.run.resource_id)?;
    ensure!(
        input.run.immutable_version > 0,
        "invalid_freetool_configuration_version"
    );
    let identity = identity(runtime, request, input.run.clone())?;
    Ok((input, identity))
}

pub(crate) fn trusted_request(
    runtime: &crate::store::Runtime,
    request: &crate::protocol::Request,
    instruction: &crate::protocol::Instruction,
    grant: &crate::resources::ResourceUse,
) -> Result<(ServiceRequest, String)> {
    let (input, identity) = authorize_input(runtime, request, instruction, grant)?;
    let request = match instruction.model.as_str() {
        "freetool.register.v1" => {
            let plan = input.plan.context("freetool_plan_missing")?;
            validate_plan(&plan)?;
            ServiceRequest::Register { identity, plan }
        }
        "freetool.execute.v1" => ServiceRequest::Execute { identity },
        "freetool.status.v1" => ServiceRequest::Status { identity },
        "freetool.result_page.v1" => {
            let limit = input.limit.context("freetool_result_limit_missing")?;
            ensure!(
                (1..=MAX_RESULT_PAGE_BYTES).contains(&limit),
                "freetool_result_page_limit"
            );
            ServiceRequest::ResultPage {
                identity,
                offset: input.offset.unwrap_or(0),
                limit,
            }
        }
        _ => anyhow::bail!("unknown_freetool_executor_capability"),
    };
    Ok((request, instruction.data.clone()))
}

pub(crate) fn fingerprint(
    instruction: &crate::protocol::Instruction,
    grant: &crate::resources::ResourceUse,
) -> Result<String> {
    let input: FingerprintInput = serde_json::from_str(&instruction.data)?;
    ensure!(
        input.handle == grant.handle,
        crate::error::Failure::ResourceForbidden
    );
    let configuration = input.configuration_document;
    let arguments = input.arguments_document;
    ensure!(
        configuration.len() <= 24 * 1024 && arguments.len() <= 24 * 1024,
        "freetool_fingerprint_input_budget"
    );
    let configuration_digest = sha256(configuration.as_bytes());
    let arguments_digest = sha256(arguments.as_bytes());
    Ok(
        json!({"configuration_digest":configuration_digest,"arguments_digest":arguments_digest})
            .to_string(),
    )
}

pub(crate) fn trusted_identity(
    installation: &str,
    actor: &str,
    artifact: &str,
    operation: &str,
    claims: RunClaims,
) -> Result<ExecutionIdentity> {
    ensure!(
        !installation.is_empty()
            && !actor.is_empty()
            && !artifact.is_empty()
            && !operation.is_empty(),
        "freetool_dispatch_identity_missing"
    );
    Ok(ExecutionIdentity {
        installation: installation.into(),
        application: "freetool".into(),
        actor: actor.into(),
        artifact: artifact.into(),
        operation: operation.into(),
        resource_id: claims.resource_id,
        configuration_id: claims.configuration_id,
        immutable_version: claims.immutable_version,
        configuration_digest: claims.configuration_digest,
        run_id: claims.run_id,
        arguments_digest: claims.arguments_digest,
    })
}

fn validate_plan(plan: &ExecutionPlan) -> Result<()> {
    let serialized = serde_json::to_vec(plan)?;
    ensure!(serialized.len() <= 1_048_576, "freetool_plan_budget");
    match plan {
        ExecutionPlan::Http {
            method,
            url,
            headers,
            body,
        } => {
            ensure!(
                matches!(
                    method.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
                ),
                "freetool_http_method_invalid"
            );
            let parsed = url::Url::parse(url).context("freetool_http_url_invalid")?;
            ensure!(
                matches!(parsed.scheme(), "http" | "https")
                    && parsed.host_str().is_some()
                    && parsed.username().is_empty()
                    && parsed.password().is_none(),
                "freetool_http_url_invalid"
            );
            ensure!(
                headers.len() <= 64 && body.len() <= 262_144,
                "freetool_http_plan_budget"
            );
            for (name, value) in headers {
                ensure!(
                    !name.is_empty() && name.len() <= 256 && value.len() <= 8192,
                    "freetool_http_header_invalid"
                );
                ensure!(
                    name.bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                        && !value.bytes().any(|byte| byte == b'\r' || byte == b'\n'),
                    "freetool_http_header_invalid"
                );
                ensure!(
                    ![
                        "host",
                        "content-length",
                        "authorization",
                        "proxy-authorization",
                        "cookie",
                        "set-cookie",
                        "x-api-key",
                        "api-key",
                        "x-auth-token"
                    ]
                    .iter()
                    .any(|blocked| name.eq_ignore_ascii_case(blocked)),
                    "freetool_http_header_restricted"
                );
            }
        }
        ExecutionPlan::Postgres {
            resource_binding_id,
            statement,
            parameters,
        } => {
            ensure!(
                !resource_binding_id.is_empty()
                    && resource_binding_id.len() <= 256
                    && !statement.is_empty()
                    && statement.len() <= 65_536
                    && parameters.len() <= 256,
                "freetool_postgres_plan_invalid"
            );
        }
    }
    Ok(())
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn response_json(response: ServiceResponse) -> Result<String> {
    let output = match response {
        ServiceResponse::Registered { manifest_digest } => {
            json!({"state":"registered","code":"","result_id":"","digest":manifest_digest,"byte_count":0})
        }
        ServiceResponse::Executed { outcome } => outcome_json(outcome),
        ServiceResponse::Status { receipt: None } => {
            json!({"state":"not_found","code":"","result_id":"","digest":"","byte_count":0})
        }
        ServiceResponse::Status {
            receipt: Some(receipt),
        } => match receipt.state {
            ReceiptState::Dispatching => {
                json!({"state":"dispatching","code":"","result_id":"","digest":"","byte_count":0})
            }
            ReceiptState::Settled(outcome) => outcome_json(outcome),
        },
        ServiceResponse::ResultPage {
            result_id,
            digest,
            total_bytes,
            offset,
            bytes,
        } => {
            json!({"result_id":result_id,"digest":digest,"total_bytes":total_bytes,"offset":offset,"bytes":bytes})
        }
        ServiceResponse::Error { code } => {
            json!({"state":"error","code":safe_code(&code),"result_id":"","digest":"","byte_count":0})
        }
    };
    let encoded = serde_json::to_string(&output)?;
    ensure!(
        encoded.len() <= MAX_OBSERVATION_BYTES,
        "freetool_observation_budget"
    );
    Ok(encoded)
}

fn outcome_json(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Succeeded {
            result_id,
            digest,
            byte_count,
        } => {
            json!({"state":"succeeded","code":"","result_id":result_id,"digest":digest,"byte_count":byte_count})
        }
        Outcome::Rejected { code } => {
            json!({"state":"rejected","code":safe_code(&code),"result_id":"","digest":"","byte_count":0})
        }
        Outcome::Failed { code } => {
            json!({"state":"failed","code":safe_code(&code),"result_id":"","digest":"","byte_count":0})
        }
        Outcome::Unknown { code } => {
            json!({"state":"unknown","code":safe_code(&code),"result_id":"","digest":"","byte_count":0})
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutorErrorCode {
    InvalidRequest,
    Unauthorized,
    InvalidIdentity,
    CallerNotAuthorized,
    InvalidTarget,
    ResourceNotAuthorized,
    TargetNotAuthorized,
    ManifestConflict,
    RegistryFailure,
    ReceiptUnavailable,
    InvalidPage,
    ResultUnavailable,
    NotRegistered,
    ExecutionInProgress,
    IdentityConflict,
    ReceiptFailure,
    ResultPersistenceUncertain,
    ReceiptPersistenceUncertain,
    DnsFailure,
    DnsRejected,
    EgressDenied,
    HttpSetupFailure,
    InvalidMethod,
    CredentialTargetMismatch,
    CredentialUnavailable,
    CredentialHeaderConflict,
    CredentialTypeUnsupported,
    ProviderTimeout,
    ProviderConnectFailure,
    ProviderTransportFailure,
    RedirectDenied,
    ResponseTooLarge,
    ProviderResponseFailure,
    ProviderHttpError,
    QueryRejected,
    ProviderQueryFailure,
    InvalidParameters,
    ResultTooLarge,
    ResultEncodingFailure,
    DeliveryUncertain,
    InvalidPlan,
    PlanTooLarge,
    InvalidUrl,
    RequestTooLarge,
    InvalidHeader,
    RestrictedHeader,
    InvalidQuery,
}

impl ExecutorErrorCode {
    const REVIEWED: &'static [Self] = &[
        Self::InvalidRequest,
        Self::Unauthorized,
        Self::InvalidIdentity,
        Self::CallerNotAuthorized,
        Self::InvalidTarget,
        Self::ResourceNotAuthorized,
        Self::TargetNotAuthorized,
        Self::ManifestConflict,
        Self::RegistryFailure,
        Self::ReceiptUnavailable,
        Self::InvalidPage,
        Self::ResultUnavailable,
        Self::NotRegistered,
        Self::ExecutionInProgress,
        Self::IdentityConflict,
        Self::ReceiptFailure,
        Self::ResultPersistenceUncertain,
        Self::ReceiptPersistenceUncertain,
        Self::DnsFailure,
        Self::DnsRejected,
        Self::EgressDenied,
        Self::HttpSetupFailure,
        Self::InvalidMethod,
        Self::CredentialTargetMismatch,
        Self::CredentialUnavailable,
        Self::CredentialHeaderConflict,
        Self::CredentialTypeUnsupported,
        Self::ProviderTimeout,
        Self::ProviderConnectFailure,
        Self::ProviderTransportFailure,
        Self::RedirectDenied,
        Self::ResponseTooLarge,
        Self::ProviderResponseFailure,
        Self::ProviderHttpError,
        Self::QueryRejected,
        Self::ProviderQueryFailure,
        Self::InvalidParameters,
        Self::ResultTooLarge,
        Self::ResultEncodingFailure,
        Self::DeliveryUncertain,
        Self::InvalidPlan,
        Self::PlanTooLarge,
        Self::InvalidUrl,
        Self::RequestTooLarge,
        Self::InvalidHeader,
        Self::RestrictedHeader,
        Self::InvalidQuery,
    ];

    fn decode(value: &str) -> Option<Self> {
        Self::REVIEWED
            .iter()
            .copied()
            .find(|code| code.as_str() == value)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::InvalidIdentity => "invalid_identity",
            Self::CallerNotAuthorized => "caller_not_authorized",
            Self::InvalidTarget => "invalid_target",
            Self::ResourceNotAuthorized => "resource_not_authorized",
            Self::TargetNotAuthorized => "target_not_authorized",
            Self::ManifestConflict => "manifest_conflict",
            Self::RegistryFailure => "registry_failure",
            Self::ReceiptUnavailable => "receipt_unavailable",
            Self::InvalidPage => "invalid_page",
            Self::ResultUnavailable => "result_unavailable",
            Self::NotRegistered => "not_registered",
            Self::ExecutionInProgress => "execution_in_progress",
            Self::IdentityConflict => "identity_conflict",
            Self::ReceiptFailure => "receipt_failure",
            Self::ResultPersistenceUncertain => "result_persistence_uncertain",
            Self::ReceiptPersistenceUncertain => "receipt_persistence_uncertain",
            Self::DnsFailure => "dns_failure",
            Self::DnsRejected => "dns_rejected",
            Self::EgressDenied => "egress_denied",
            Self::HttpSetupFailure => "http_setup_failure",
            Self::InvalidMethod => "invalid_method",
            Self::CredentialTargetMismatch => "credential_target_mismatch",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::CredentialHeaderConflict => "credential_header_conflict",
            Self::CredentialTypeUnsupported => "credential_type_unsupported",
            Self::ProviderTimeout => "provider_timeout",
            Self::ProviderConnectFailure => "provider_connect_failure",
            Self::ProviderTransportFailure => "provider_transport_failure",
            Self::RedirectDenied => "redirect_denied",
            Self::ResponseTooLarge => "response_too_large",
            Self::ProviderResponseFailure => "provider_response_failure",
            Self::ProviderHttpError => "provider_http_error",
            Self::QueryRejected => "query_rejected",
            Self::ProviderQueryFailure => "provider_query_failure",
            Self::InvalidParameters => "invalid_parameters",
            Self::ResultTooLarge => "result_too_large",
            Self::ResultEncodingFailure => "result_encoding_failure",
            Self::DeliveryUncertain => "delivery_uncertain",
            Self::InvalidPlan => "invalid_plan",
            Self::PlanTooLarge => "plan_too_large",
            Self::InvalidUrl => "invalid_url",
            Self::RequestTooLarge => "request_too_large",
            Self::InvalidHeader => "invalid_header",
            Self::RestrictedHeader => "restricted_header",
            Self::InvalidQuery => "invalid_query",
        }
    }
}

fn safe_code(value: &str) -> &'static str {
    ExecutorErrorCode::decode(value)
        .map(ExecutorErrorCode::as_str)
        .unwrap_or("executor_error")
}

pub(crate) struct CallOutcome {
    pub result: Result<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub known: bool,
    pub dispatched: bool,
}

pub(crate) fn request_wire_bytes(request: &ServiceRequest) -> Result<u64> {
    let bytes = serde_json::to_vec(request)?;
    ensure!(
        bytes.len() as u64 <= crate::integrations::MAX_FREETOOL_EXECUTOR_WIRE_BYTES,
        "freetool_service_request_budget"
    );
    Ok(bytes.len() as u64)
}

pub(crate) fn call(
    runtime: &crate::store::Runtime,
    resource: &crate::resources::ResourceUse,
    request: ServiceRequest,
) -> CallOutcome {
    let is_result_page = matches!(&request, ServiceRequest::ResultPage { .. });
    let Some(connection) = resource.grant.live.as_ref() else {
        return CallOutcome {
            result: Err(anyhow::anyhow!("freetool_executor_connection_missing")),
            request_bytes: 0,
            response_bytes: 0,
            known: true,
            dispatched: false,
        };
    };
    let exchange = runtime.integrations().freetool_request(
        runtime.db(),
        &resource.grant.connection,
        connection,
        request,
        resource.grant.limits.max_response_bytes,
    );
    let crate::integrations::FreetoolExecutorExchange {
        response,
        request_bytes,
        response_bytes,
        known,
        dispatched,
    } = exchange;
    let result = response.and_then(|bytes| {
        let response: ServiceResponse =
            serde_json::from_slice(&bytes).context("freetool_service_response_invalid")?;
        match response {
            ServiceResponse::Error { code } if is_result_page => {
                anyhow::bail!(safe_code(&code))
            }
            ServiceResponse::Error { code } => response_json(ServiceResponse::Error { code }),
            response => response_json(response),
        }
    });
    CallOutcome {
        result,
        request_bytes,
        response_bytes,
        known,
        dispatched,
    }
}

/// SQLite-backed deterministic adapter used by simulations; it preserves sealed
/// registrations and service receipts without opening a socket.
fn simulated_record_key(
    connection_id: &VersionRef,
    connection: &LiveConnection,
    identity: &ExecutionIdentity,
) -> Result<String> {
    ensure!(
        matches!(connection, LiveConnection::FreetoolExecutor { .. }),
        "freetool_executor_connection_mismatch"
    );
    Ok(sha256(&serde_json::to_vec(&(
        connection_id,
        connection,
        identity,
    ))?))
}

pub(crate) fn simulated_call(
    database: &Path,
    connection_id: &VersionRef,
    connection: &LiveConnection,
    request: ServiceRequest,
) -> Result<ServiceResponse> {
    use rusqlite::{Connection, OptionalExtension, params};
    connection.validate()?;
    let mut db = Connection::open(database)?;
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS freetool_executor_records(identity TEXT PRIMARY KEY, plan TEXT NOT NULL, outcome TEXT, result_id TEXT, result_digest TEXT, result_body BLOB);")?;
    match request {
        ServiceRequest::Register { identity, plan } => {
            let key = simulated_record_key(connection_id, connection, &identity)?;
            let plan_json = serde_json::to_string(&plan)?;
            let existing: Option<String> = db
                .query_row(
                    "SELECT plan FROM freetool_executor_records WHERE identity=?1",
                    [&key],
                    |row| row.get(0),
                )
                .optional()?;
            if existing
                .as_deref()
                .is_some_and(|current| current != plan_json)
            {
                return Ok(ServiceResponse::Error {
                    code: "manifest_conflict".into(),
                });
            }
            if existing.is_none() {
                db.execute(
                    "INSERT INTO freetool_executor_records(identity,plan) VALUES(?1,?2)",
                    params![key, plan_json],
                )?;
            }
            Ok(ServiceResponse::Registered {
                manifest_digest: sha256(plan_json.as_bytes()),
            })
        }
        ServiceRequest::Execute { identity } => {
            let key = simulated_record_key(connection_id, connection, &identity)?;
            let transaction = db.transaction()?;
            let record: Option<(String, Option<String>)> = transaction
                .query_row(
                    "SELECT plan,outcome FROM freetool_executor_records WHERE identity=?1",
                    [&key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((_plan, existing)) = record else {
                transaction.rollback()?;
                return Ok(ServiceResponse::Error {
                    code: "not_registered".into(),
                });
            };
            if let Some(existing) = existing {
                let outcome: Outcome = serde_json::from_str(&existing)?;
                transaction.commit()?;
                return Ok(ServiceResponse::Executed { outcome });
            }
            let body = b"simulated executor result".to_vec();
            let result_id = format!("sim_{}", &sha256(key.as_bytes())[..24]);
            let digest = sha256(&body);
            let outcome = Outcome::Succeeded {
                result_id: result_id.clone(),
                digest: digest.clone(),
                byte_count: body.len() as u64,
            };
            transaction.execute(
                "UPDATE freetool_executor_records SET outcome=?1,result_id=?2,result_digest=?3,result_body=?4 WHERE identity=?5 AND outcome IS NULL",
                params![serde_json::to_string(&outcome)?, result_id, digest, body, key],
            )?;
            transaction.commit()?;
            Ok(ServiceResponse::Executed { outcome })
        }
        ServiceRequest::Status { identity } => {
            let key = simulated_record_key(connection_id, connection, &identity)?;
            let outcome: Option<String> = db
                .query_row(
                    "SELECT outcome FROM freetool_executor_records WHERE identity=?1",
                    [&key],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            let receipt = outcome
                .map(|raw| -> Result<ReceiptSnapshot> {
                    Ok(ReceiptSnapshot {
                        identity,
                        state: ReceiptState::Settled(serde_json::from_str(&raw)?),
                    })
                })
                .transpose()?;
            Ok(ServiceResponse::Status {
                receipt: receipt.map(Box::new),
            })
        }
        ServiceRequest::ResultPage {
            identity,
            offset,
            limit,
        } => {
            if limit == 0 || limit > MAX_RESULT_PAGE_BYTES {
                return Ok(ServiceResponse::Error {
                    code: "invalid_page".into(),
                });
            }
            let key = simulated_record_key(connection_id, connection, &identity)?;
            let result: Option<(String, String, Vec<u8>)> = db.query_row(
                "SELECT result_id,result_digest,result_body FROM freetool_executor_records WHERE identity=?1 AND outcome IS NOT NULL AND result_id IS NOT NULL",
                [&key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let Some((result_id, digest, body)) = result else {
                return Ok(ServiceResponse::Error {
                    code: "result_unavailable".into(),
                });
            };
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(body.len());
            let end = start.saturating_add(limit as usize).min(body.len());
            Ok(ServiceResponse::ResultPage {
                result_id,
                digest,
                total_bytes: body.len() as u64,
                offset,
                bytes: body[start..end].to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simulated_connection() -> (VersionRef, LiveConnection) {
        (
            VersionRef {
                id: "executor_test".into(),
                revision: 1,
            },
            LiveConnection::FreetoolExecutor {
                credential_ref: VersionRef {
                    id: "executor_key_test".into(),
                    revision: 1,
                },
                endpoint: "http://127.0.0.1:43210".into(),
            },
        )
    }

    fn identity() -> ExecutionIdentity {
        ExecutionIdentity {
            installation: "test/dev".into(),
            application: "freetool".into(),
            actor: "alice".into(),
            artifact: "artifact-1".into(),
            operation: "freetool.run".into(),
            resource_id: "resource-1".into(),
            configuration_id: "config-1".into(),
            immutable_version: 1,
            configuration_digest: "a".repeat(64),
            run_id: "run-1".into(),
            arguments_digest: "b".repeat(64),
        }
    }

    #[test]
    fn executor_request_meter_uses_the_exact_serialized_wire_body() -> Result<()> {
        let request = ServiceRequest::Status {
            identity: identity(),
        };
        let encoded = serde_json::to_vec(&request)?;
        assert_eq!(request_wire_bytes(&request)?, encoded.len() as u64);
        Ok(())
    }

    #[test]
    fn simulated_world_seals_manifest_and_reuses_receipt_and_scoped_pages() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("executor.sqlite");
        let (connection_id, connection) = simulated_connection();
        let identity = identity();
        let plan = ExecutionPlan::Http {
            method: "GET".into(),
            url: "https://api.example.test/items".into(),
            headers: vec![("accept".into(), "application/json".into())],
            body: Vec::new(),
        };
        let registered = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::Register {
                identity: identity.clone(),
                plan: plan.clone(),
            },
        )?;
        assert!(matches!(registered, ServiceResponse::Registered { .. }));
        let duplicate = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::Register {
                identity: identity.clone(),
                plan: plan.clone(),
            },
        )?;
        assert_eq!(duplicate, registered);
        let conflict = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::Register {
                identity: identity.clone(),
                plan: ExecutionPlan::Http {
                    method: "GET".into(),
                    url: "https://api.example.test/other".into(),
                    headers: vec![],
                    body: vec![],
                },
            },
        )?;
        assert!(matches!(conflict, ServiceResponse::Error { code } if code == "manifest_conflict"));

        let first = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::Execute {
                identity: identity.clone(),
            },
        )?;
        let second = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::Execute {
                identity: identity.clone(),
            },
        )?;
        assert_eq!(
            first, second,
            "duplicate execute must reuse the recorded receipt"
        );
        let ServiceResponse::Executed {
            outcome:
                Outcome::Succeeded {
                    result_id,
                    digest,
                    byte_count,
                },
        } = first
        else {
            panic!("expected successful simulated execution");
        };
        let status = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::Status {
                identity: identity.clone(),
            },
        )?;
        assert!(matches!(
            status,
            ServiceResponse::Status {
                receipt: Some(receipt)
            } if matches!(receipt.state, ReceiptState::Settled(Outcome::Succeeded { .. }))
        ));
        let page = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::ResultPage {
                identity: identity.clone(),
                offset: 0,
                limit: MAX_RESULT_PAGE_BYTES,
            },
        )?;
        assert!(
            matches!(page, ServiceResponse::ResultPage { result_id: actual, digest: actual_digest, total_bytes, bytes, .. }
            if actual == result_id && actual_digest == digest && total_bytes == byte_count && bytes == b"simulated executor result")
        );
        let denied = simulated_call(
            &database,
            &connection_id,
            &connection,
            ServiceRequest::ResultPage {
                identity: ExecutionIdentity {
                    actor: "bob".into(),
                    ..identity
                },
                offset: 0,
                limit: 100,
            },
        )?;
        assert!(matches!(denied, ServiceResponse::Error { code } if code == "result_unavailable"));
        Ok(())
    }

    #[test]
    fn resource_scope_is_enforced_before_dispatch() -> Result<()> {
        use day2_capabilities::resources::FreetoolResourceScope;

        let explicit = FreetoolResourceScope::Explicit {
            allowed_resources: std::collections::BTreeSet::from(["resource-1".into()]),
        };
        authorize_resource_scope(&explicit, "resource-1")?;
        assert!(authorize_resource_scope(&explicit, "resource-2").is_err());

        authorize_resource_scope(&FreetoolResourceScope::AnyAppResource, "resource-2")?;
        Ok(())
    }

    #[test]
    fn caller_cannot_forge_host_identity_facts() -> Result<()> {
        let claims = RunClaims {
            resource_id: "business-resource".into(),
            configuration_id: "config-7".into(),
            immutable_version: 7,
            configuration_digest: "a".repeat(64),
            run_id: "run-9".into(),
            arguments_digest: "b".repeat(64),
        };
        let identity = trusted_identity(
            "install/env",
            "verified-actor",
            "pinned-artifact",
            "freetool.run",
            claims,
        )?;
        assert_eq!(identity.installation, "install/env");
        assert_eq!(identity.actor, "verified-actor");
        assert_eq!(identity.artifact, "pinned-artifact");
        assert_eq!(identity.operation, "freetool.run");
        assert_eq!(identity.application, "freetool");
        assert_eq!(identity.resource_id, "business-resource");
        assert_eq!(identity.immutable_version, 7);
        Ok(())
    }

    #[test]
    fn protocol_plan_dtos_match_the_service_tagged_wire_shape() -> Result<()> {
        let http: ExecutionPlan = serde_json::from_str(
            r#"{"kind":"http","method":"POST","url":"https://api.example.test/items","headers":[["content-type","application/json"]],"body":[123,125]}"#,
        )?;
        assert_eq!(
            http,
            ExecutionPlan::Http {
                method: "POST".into(),
                url: "https://api.example.test/items".into(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: b"{}".to_vec(),
            }
        );
        let sql: ExecutionPlan = serde_json::from_str(
            r#"{"kind":"postgres","resource_binding_id":"db-reporting","statement":"SELECT $1","parameters":[{"type":"integer","value":4},{"type":"null"}]}"#,
        )?;
        assert_eq!(
            sql,
            ExecutionPlan::Postgres {
                resource_binding_id: "db-reporting".into(),
                statement: "SELECT $1".into(),
                parameters: vec![SqlValue::Integer(4), SqlValue::Null],
            }
        );
        assert!(serde_json::from_str::<ExecutionPlan>(r#"{"kind":"http","method":"GET","url":"https://example.test","headers":[],"body":[],"endpoint":"forged"}"#).is_err());
        Ok(())
    }

    #[test]
    fn fingerprints_are_sha256_of_exact_utf8_documents_only() {
        assert_eq!(
            sha256("é".as_bytes()),
            "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c"
        );
        assert_ne!(sha256(b"{}"), sha256(b"{ }"));
    }

    #[test]
    fn provider_error_codes_are_allowlisted_and_redacted() -> Result<()> {
        for code in ExecutorErrorCode::REVIEWED {
            assert_eq!(safe_code(code.as_str()), code.as_str());
        }

        let private_token = "synthetic_private_token_ABC123";
        assert_eq!(safe_code(private_token), "executor_error");
        let error = response_json(ServiceResponse::Error {
            code: private_token.into(),
        })?;
        let error: serde_json::Value = serde_json::from_str(&error)?;
        assert_eq!(error["code"], "executor_error");

        for outcome in [
            Outcome::Rejected {
                code: private_token.into(),
            },
            Outcome::Failed {
                code: private_token.into(),
            },
            Outcome::Unknown {
                code: private_token.into(),
            },
        ] {
            assert_eq!(outcome_json(outcome)["code"], "executor_error");
        }
        assert_eq!(
            outcome_json(Outcome::Failed {
                code: "provider_timeout".into(),
            })["code"],
            "provider_timeout"
        );
        Ok(())
    }
}
