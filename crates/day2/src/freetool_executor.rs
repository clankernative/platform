//! Private adapter for the typed Freetool executor capability pack.
//!
//! The SDK's nominal contracts are translated here into the executor service's
//! wire DTOs. Trusted dispatch facts are supplied by Runtime; Roc may supply only
//! the already-authorized business execution identity and complete plan.
use anyhow::{Context, Result, ensure};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

pub const MAX_RESULT_PAGE_BYTES: u32 = 12_000;
pub const MAX_OBSERVATION_BYTES: usize = 64 * 1024;

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
        receipt: Option<ReceiptSnapshot>,
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
    let day2_capabilities::resources::ResourceTarget::FreetoolExecutor {
        allowed_resources, ..
    } = &grant.grant.target
    else {
        anyhow::bail!(crate::error::Failure::ResourceForbidden)
    };
    ensure!(
        allowed_resources.contains(&input.run.resource_id),
        crate::error::Failure::ResourceForbidden
    );
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

fn safe_code(value: &str) -> String {
    if !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        value.to_owned()
    } else {
        "executor_error".into()
    }
}

pub(crate) fn call(
    runtime: &crate::store::Runtime,
    resource: &crate::resources::ResourceUse,
    request: ServiceRequest,
) -> Result<String> {
    let is_result_page = matches!(&request, ServiceRequest::ResultPage { .. });
    let connection = resource
        .grant
        .live
        .as_ref()
        .context("freetool_executor_connection_missing")?;
    let response = runtime
        .integrations()
        .freetool_request(runtime.db(), connection, request)?;
    match response {
        ServiceResponse::Error { code } if is_result_page => anyhow::bail!(safe_code(&code)),
        ServiceResponse::Error { code } => response_json(ServiceResponse::Error { code }),
        response => response_json(response),
    }
}

/// SQLite-backed deterministic adapter used by simulations; it preserves sealed
/// registrations and service receipts without opening a socket.
pub(crate) fn simulated_call(database: &Path, request: ServiceRequest) -> Result<ServiceResponse> {
    use rusqlite::{Connection, OptionalExtension, params};
    let mut db = Connection::open(database)?;
    db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS freetool_executor_records(identity TEXT PRIMARY KEY, plan TEXT NOT NULL, outcome TEXT, result_id TEXT, result_digest TEXT, result_body BLOB);")?;
    match request {
        ServiceRequest::Register { identity, plan } => {
            let key = serde_json::to_string(&identity)?;
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
            let key = serde_json::to_string(&identity)?;
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
            let key = serde_json::to_string(&identity)?;
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
            Ok(ServiceResponse::Status { receipt })
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
            let key = serde_json::to_string(&identity)?;
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
    fn simulated_world_seals_manifest_and_reuses_receipt_and_scoped_pages() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("executor.sqlite");
        let identity = identity();
        let plan = ExecutionPlan::Http {
            method: "GET".into(),
            url: "https://api.example.test/items".into(),
            headers: vec![("accept".into(), "application/json".into())],
            body: Vec::new(),
        };
        let registered = simulated_call(
            &database,
            ServiceRequest::Register {
                identity: identity.clone(),
                plan: plan.clone(),
            },
        )?;
        assert!(matches!(registered, ServiceResponse::Registered { .. }));
        let duplicate = simulated_call(
            &database,
            ServiceRequest::Register {
                identity: identity.clone(),
                plan: plan.clone(),
            },
        )?;
        assert_eq!(duplicate, registered);
        let conflict = simulated_call(
            &database,
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
            ServiceRequest::Execute {
                identity: identity.clone(),
            },
        )?;
        let second = simulated_call(
            &database,
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
            ServiceRequest::Status {
                identity: identity.clone(),
            },
        )?;
        assert!(matches!(
            status,
            ServiceResponse::Status {
                receipt: Some(ReceiptSnapshot {
                    state: ReceiptState::Settled(Outcome::Succeeded { .. }),
                    ..
                })
            }
        ));
        let page = simulated_call(
            &database,
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
    fn provider_error_codes_are_bounded_and_redacted() {
        assert_eq!(
            safe_code("resource_not_authorized"),
            "resource_not_authorized"
        );
        assert_eq!(safe_code("contains secret value"), "executor_error");
        assert_eq!(safe_code(&"x".repeat(129)), "executor_error");
    }
}
