//! OpenAPI projection of the shared, admitted operation catalog.
use crate::{
    artifact::Artifact,
    schema::{Kind, Record},
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const SPEC_PATH: &str = "/openapi.json";
pub const DOCS_PATH: &str = "/docs";
pub const API_PREFIX: &str = "/api/";
pub const SESSION_PATH: &str = "/api/session";
pub const AUDIT_PATH: &str = "/api/audit";
pub const AUDIT_EVENTS_PATH: &str = "/api/audit/events";
pub const RESERVED: &[&str] = &["api", "docs", "openapi.json", "mcp"];

pub use crate::operation_catalog::{
    Catalog, Endpoint, input_example, input_schema, output_schema, record_schema,
};

fn acting_parameters(include_csrf: bool) -> Vec<Value> {
    let mut parameters = vec![
        json!({"name":"X-Day2-Act-As","in":"header","required":false,
        "description":"Request-scoped effective actor, never authentication. Requires a session, exact Origin, X-CSRF-Token and a current operator delegation rule for the request path. Does not change the session. Omit for a direct request.",
        "schema":{"type":"string","minLength":1,"maxLength":512}}),
    ];
    if include_csrf {
        parameters.extend([
            json!({"name":"Origin","in":"header","required":false,"description":"Exact app origin; required when X-Day2-Act-As is present, including on GET.","schema":{"type":"string","format":"uri"}}),
            json!({"name":"X-CSRF-Token","in":"header","required":false,"description":"Token from GET /api/session; required when X-Day2-Act-As is present, including on GET.","schema":{"type":"string"}}),
        ]);
    }
    parameters
}

impl Catalog {
    pub fn document(
        &self,
        artifact: &Artifact,
        app: &str,
        artifact_id: &str,
        cookie_name: &str,
        origin: &str,
    ) -> Value {
        let mut schemas = BTreeMap::from([
            (
                "Error".to_string(),
                json!({"type":"object","required":["error"],"additionalProperties":false,
                "properties":{"error":{"type":"object","required":["code","message"],"additionalProperties":false,
                    "properties":{"code":{"type":"string"},"message":{"type":"string"}}}}}),
            ),
            (
                "Session".to_string(),
                json!({"type":"object","required":["actor","csrf_token"],"additionalProperties":false,
                "properties":{"actor":{"type":"string"},"csrf_token":{"type":"string","description":"Pass as X-CSRF-Token on commands and all X-Day2-Act-As requests, including queries. Valid only for the current session."}}}),
            ),
        ]);
        let mut paths = BTreeMap::new();
        for endpoint in self.endpoints.values() {
            let op = &endpoint.operation;
            let input = &artifact.schema.inputs[&op.input_type];
            let input_name = format!("Input_{}", op.name);
            let output_name = format!("Output_{}", op.name);
            let input_shape = endpoint.input_schema.clone();
            let output_shape = endpoint.output_schema.clone();
            let request_example = &endpoint.request_example;
            let mut operation = json!({
                "operationId":op.name,"summary":endpoint.summary,"tags":[op.kind],
                "description":endpoint.description,"deprecated":endpoint.deprecated,
                "x-day2-execution-description":endpoint.execution_description,
                "responses":responses(Some(&output_name)),
                "x-day2-input-schema":format!("#/components/schemas/{input_name}"),
                "x-day2-request-example":request_example,
                "x-day2-response-example-source":endpoint.response_example_source,
            });
            operation["responses"]["200"]["description"] = json!(endpoint.response_description);
            operation["responses"]["200"]["content"]["application/json"]["example"] =
                endpoint.response_example.clone();
            if let Some(metadata) = &endpoint.metadata {
                operation["x-day2-operation-contract"] = json!(metadata);
            }
            if let Some(definition) = &artifact.app_contract {
                operation["x-day2-application-errors"] = json!(
                    definition.operations[&op.name]
                        .errors
                        .iter()
                        .map(|code| application_error(&definition.errors[code], &op.name))
                        .collect::<Vec<_>>()
                );
                operation["x-day2-execution"] = json!(definition.operations[&op.name].execution);
                operation["x-day2-required-all-rows"] =
                    json!(definition.operations[&op.name].required_all_rows);
            }
            if op.kind == "query" {
                operation["parameters"] = Value::Array(input.fields.iter().map(|(name, kind)| {
                    let mut parameter = json!({"name":name,"in":"query","required":true});
                    let field_schema = input_shape["properties"][name].clone();
                    if let Some(description) = field_schema.get("description") { parameter["description"] = description.clone(); }
                    if matches!(kind, Kind::OptionalText | Kind::InputShape { .. }) {
                        parameter["content"] = json!({"application/json":{"schema":field_schema,"example":request_example[name]}});
                        parameter["description"] = json!(format!("{} JSON-encode this query parameter. Optional text uses quotes for the None string; structured inputs use JSON objects or arrays.", parameter["description"].as_str().unwrap_or_default()));
                    } else {
                        parameter["schema"] = field_schema;
                        parameter["example"] = request_example[name].clone();
                    }
                    parameter
                }).collect());
            } else {
                operation["parameters"] = json!([
                    {"name":"Prefer","in":"header","required":false,"description":"Use respond-async to wait only for durable acceptance.","schema":{"type":"string","enum":["respond-async"]}},
                    {"name":"Idempotency-Key","in":"header","required":true,"description":"Caller-generated key, scoped to the authenticated requester and app. Preserve key, effective actor, operation and input on retry; use a new key for a new command.",
                        "schema":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_-]+$"}},
                    {"name":"X-CSRF-Token","in":"header","required":true,"description":"Obtain from GET /api/session.","schema":{"type":"string"}},
                    {"name":"Origin","in":"header","required":true,"description":"The exact app origin. Browsers send it automatically; other clients must supply it.","schema":{"type":"string","format":"uri"}}
                ]);
                operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{input_name}")},"example":request_example}}});
                operation["responses"]["202"] = json!({"description":"Durably accepted; execution continues. Follow Location for status.","headers":{"Location":{"schema":{"type":"string"}}},"content":{"application/json":{"schema":{"type":"object","required":["invocation_id","status","status_url"],"properties":{"invocation_id":{"type":"string"},"status":{"const":"pending"},"status_url":{"type":"string"}}}}}});
            }
            operation["parameters"]
                .as_array_mut()
                .expect("operation parameters")
                .extend(acting_parameters(op.kind == "query"));
            schemas.insert(input_name, input_shape);
            schemas.insert(output_name, output_shape);
            paths.insert(
                endpoint.path(),
                json!({endpoint.method().to_ascii_lowercase():operation}),
            );
        }
        paths.insert(SESSION_PATH.into(), json!({"get":{"operationId":"platform.session","summary":"Current API session","tags":["platform"],
            "description":"Returns the authenticated session actor and a session-bound CSRF token for commands and request-scoped X-Day2-Act-As requests.","responses":responses(Some("Session"))}}));
        paths.get_mut(SESSION_PATH).expect("session path")["get"]["responses"]["200"]["content"]
            ["application/json"]["example"] =
            json!({"actor":"developer","csrf_token":"SESSION_BOUND_CSRF_TOKEN"});
        let id_components: BTreeMap<_, _> = artifact
            .schema
            .models
            .values()
            .filter_map(|record| record.identity.as_ref())
            .map(|identity| (identity.prefix.clone(), format!("Id_{}", identity.prefix)))
            .collect();
        schemas.insert("Invocation".into(), json!({
            "type":"object","additionalProperties":false,
            "required":["invocation_id","operation","status","result","error","children"],
            "properties":{
                "invocation_id":{"type":"string"},"operation":{"type":"string"},
                "status":{"type":"string","enum":["pending","success","failure","blocked"]},
                "result":{"description":"The operation's final typed result, or null while pending, failed or blocked."},
                "error":{"type":"string"},
                "children":{"type":"array","maxItems":8,"items":{
                    "type":"object","additionalProperties":false,"required":["id","parent","operation","status"],
                    "properties":{"id":{"type":"string"},"parent":{"type":"string"},
                        "operation":{"type":"string"},"status":{"type":"string","enum":["pending","success","failure","blocked"]}}
                }}
            }
        }));
        let mut invocation = json!({
            "operationId":"platform.invocation","summary":"Command invocation status","tags":["platform"],
            "description":"Read your invocation and child statuses under current authority. On-behalf-of status reads require the original authenticated requester, effective actor and currently authorized request delegation rule. This does not run application code.",
            "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","maxLength":128},"example":"INVOCATION_ID"}],
            "responses":responses(Some("Invocation"))
        });
        invocation["parameters"]
            .as_array_mut()
            .expect("invocation parameters")
            .extend(acting_parameters(true));
        invocation["responses"]["200"]["content"]["application/json"]["example"] = json!({
            "invocation_id":"INVOCATION_ID","operation":"COMMAND_NAME","status":"pending","result":null,"error":"","children":[]
        });
        paths.insert("/api/invocations/{id}".into(), json!({"get":invocation}));
        audit_document(&mut schemas, &mut paths);
        for schema in schemas.values_mut() {
            reference_id_schemas(schema, &id_components);
        }
        for path in paths.values_mut() {
            reference_id_schemas(path, &id_components);
        }
        for (prefix, name) in &id_components {
            schemas.insert(name.clone(), crate::identity::json_schema(prefix));
        }
        let mut document = json!({"openapi":"3.1.1","info":{"title":format!("{app} API"),"version":artifact_id,
            "description":"Generated by Day2 from the admitted app's typed command and query contracts. Browser pages, Datastar transports, verification and internal commands are excluded. Authenticate using the app's existing session cookie. Responses are not cached. The local host uses its one-time sign-in flow; it does not issue production API credentials."},
            "servers":[{"url":origin}],"security":[{"AppSession":[]}],
            "tags":[{"name":"query","description":"Read-only operations"},{"name":"command","description":"Transactional writes"},{"name":"platform","description":"Platform API support"}],
            "paths":paths,"components":{"schemas":schemas,"securitySchemes":{"AppSession":{"type":"apiKey","in":"cookie","name":cookie_name}}}});
        crate::api_examples::populate(&mut document);
        document
    }
}

fn application_error(error: &crate::app_contract::Failure, operation: &str) -> Value {
    let current = error
        .targets()
        .find(|target| target.operation == operation)
        .expect("checked operation failure case");
    json!({
        "code":error.code, "description":error.description, "recovery":error.recovery,
        "operation":current, "operations":error.targets().collect::<Vec<_>>()
    })
}

fn audit_document(schemas: &mut BTreeMap<String, Value>, paths: &mut BTreeMap<String, Value>) {
    schemas.insert("AuditChange".into(), json!({
        "type":"object","additionalProperties":false,
        "required":["model","record_id","before_version","after_version","fields"],
        "properties":{
            "model":{"type":"string"},"record_id":{"type":"string"},
            "before_version":{"type":["integer","null"],"description":"Null for a newly created row."},
            "after_version":{"type":"integer"},
            "fields":{"type":"array","items":{"type":"string"},"description":"Changed field names only. No old or new field values."}
        }
    }));
    schemas.insert("AuditEntry".into(), json!({
        "type":"object","additionalProperties":false,
        "required":["sequence","invocation","actor","operation","status","at","artifact","changes"],
        "properties":{
            "sequence":{"type":"integer"},"invocation":{"type":"string"},"actor":{"type":"string"},
            "operation":{"type":"string"},"status":{"type":"string","enum":["success","failure"]},
            "at":{"type":"integer","description":"Accepted invocation time, in Unix seconds."},
            "artifact":{"type":"string"},"changes":{"type":"array","items":{"$ref":"#/components/schemas/AuditChange"}}
        }
    }));
    // Descriptive siblings keep nested fields visible in the native docs while
    // retaining reusable OpenAPI component identities (allowed by OpenAPI 3.1).
    let mut change = schemas["AuditChange"].clone();
    change["$ref"] = json!("#/components/schemas/AuditChange");
    schemas.get_mut("AuditEntry").expect("audit entry")["properties"]["changes"]["items"] = change;
    schemas.insert("AuditEvent".into(), json!({
        "type":"object","additionalProperties":false,
        "required":["sequence","scope","kind","identity","actor","initiator","operation","outcome","at_ms","artifact","reason"],
        "properties":{
            "sequence":{"type":"integer"},"scope":{"type":"string"},
            "kind":{"type":"string","enum":["admission","execution_attempt","invocation","web"]},
            "identity":{"type":"string"},"actor":{"type":["string","null"]},
            "initiator":{"type":["string","null"],"description":"Original requesting actor, when known."},
            "operation":{"type":["string","null"]},"outcome":{"type":"string"},
            "at_ms":{"type":"integer","description":"Event time, in Unix milliseconds. Receipt events preserve accepted invocation time; interruptions use observed host time."},
            "artifact":{"type":["string","null"]},
            "reason":{"type":["string","null"],"maxLength":100,"description":"Bounded host reason/category code. Never raw errors, request bodies, query strings or credentials."}
        }
    }));
    for (name, item) in [
        ("AuditPage", "AuditEntry"),
        ("AuditEventPage", "AuditEvent"),
    ] {
        let mut item_shape = schemas[item].clone();
        item_shape["$ref"] = json!(format!("#/components/schemas/{item}"));
        schemas.insert(name.into(), json!({
            "type":"object","additionalProperties":false,"required":["items","next_cursor"],
            "properties":{
                "items":{"type":"array","maxItems":50,"items":item_shape},
                "next_cursor":{"type":"string","pattern":"^(|aud1_[0-9a-f]{64})$","description":"Opaque continuation; empty when no older matches remain. Reuse with the same filters, limit and actor within 24 hours."}
            }
        }));
    }
    for (path, id, title, description, schema, filters) in [
        (
            AUDIT_PATH,
            "platform.audit",
            "Platform audit log",
            "Mandatory host-owned audit of completed commands and queries. Requires current auditor membership. Successful row changes and the completion receipt commit atomically; applications cannot disable capture. Filter by model and record_id for a record's revision timeline. A matching entry includes all changes in its transaction. Field values, request inputs/results and deletion reasons are excluded, so this is not a reconstruction of historical business values. Legacy invocations may predate row-change capture.",
            "AuditPage",
            &["actor", "operation", "status", "model", "record_id"][..],
        ),
        (
            AUDIT_EVENTS_PATH,
            "platform.audit_events",
            "Platform audit lifecycle events",
            "Mandatory host-owned admission, reuse, rejection, interruption, completion and HTTP events. Requires current auditor membership. Use identity to follow all attempts for one invocation. HTTP events have their own identities and omit query strings and bodies. Each attempt is retained; a completed invocation still has only one completion receipt. This read does not execute application code.",
            "AuditEventPage",
            &["actor", "operation", "kind", "identity", "outcome"][..],
        ),
    ] {
        let mut parameters = vec![
            json!({"name":"cursor","in":"query","required":false,"schema":{"type":"string","default":"","pattern":"^(|aud1_[0-9a-f]{64})$"},"example":"","description":"Empty or omitted for the newest page. Copy next_cursor to read older matches; opaque and bound to this app, artifact, actor, view, filters and limit. Expires after 24 hours. Current auditor permission is rechecked on every page."}),
            json!({"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":50,"default":50},"example":50,"description":"Maximum returned items. Results are in descending append-only sequence; new events do not shift older page boundaries."}),
        ];
        for name in filters {
            let (description, maximum) = match *name {
                "actor" => (
                    "Exact authenticated actor. Empty or omitted matches all.",
                    512,
                ),
                "operation" => ("Exact operation name. Empty or omitted matches all.", 160),
                "status" => (
                    "Completion status: success or failure. Empty or omitted matches all.",
                    16,
                ),
                "model" => (
                    "Exact model name from a change. Empty or omitted matches all models.",
                    160,
                ),
                "record_id" => (
                    "Exact record identity; requires model. Empty or omitted matches all records in the model.",
                    160,
                ),
                "kind" => (
                    "Event kind: admission, execution_attempt, invocation or web. Empty or omitted matches all.",
                    32,
                ),
                "identity" => (
                    "Exact invocation or HTTP event identity. Empty or omitted matches all.",
                    160,
                ),
                "outcome" => (
                    "Event outcome: accepted, reused, rejected, interrupted, success, failure, received or response. Empty or omitted matches all.",
                    32,
                ),
                _ => unreachable!(),
            };
            parameters.push(json!({"name":name,"in":"query","required":false,"schema":{"type":"string","maxLength":maximum},"example":"","description":description}));
        }
        let mut operation = json!({"operationId":id,"summary":title,"description":description,"tags":["platform"],"parameters":parameters,"responses":responses(Some(schema))});
        operation["responses"]["200"]["content"]["application/json"]["example"] =
            json!({"items":[],"next_cursor":""});
        operation["responses"]["200"]
            .as_object_mut()
            .expect("audit success response")
            .remove("headers");
        paths.insert(path.into(), json!({"get":operation}));
    }
}

fn reference_id_schemas(value: &mut Value, components: &BTreeMap<String, String>) {
    match value {
        Value::Object(fields) => {
            if let Some(name) = fields
                .get("x-day2-id-prefix")
                .and_then(Value::as_str)
                .and_then(|prefix| components.get(prefix))
            {
                // Keep descriptive siblings for renderers; OpenAPI 3.1 permits them.
                fields.insert("$ref".into(), json!(format!("#/components/schemas/{name}")));
            }
            for child in fields.values_mut() {
                reference_id_schemas(child, components);
            }
        }
        Value::Array(items) => {
            for item in items {
                reference_id_schemas(item, components);
            }
        }
        _ => (),
    }
}

fn responses(output: Option<&str>) -> Value {
    let mut responses = serde_json::Map::new();
    if let Some(output) = output {
        responses.insert("200".into(), json!({"description":"Successful result.","headers":{"X-Day2-Invocation":{"description":"Durable invocation identity for business operations.","schema":{"type":"string"}}},
            "content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{output}")}}}}));
    }
    for (code, description) in [
        ("400", "Malformed request or invalid input shape."),
        ("401", "A valid app session is required."),
        ("403", "The operation or request is not authorized."),
        ("404", "Unknown operation or resource."),
        ("405", "HTTP method does not match the operation."),
        ("408", "Request body timed out."),
        (
            "409",
            "Stale version, idempotency conflict or changed installation binding.",
        ),
        ("413", "Request body is too large."),
        ("415", "Commands require application/json."),
        ("422", "The application rejected the operation."),
        ("500", "The operation could not be completed."),
        (
            "503",
            "The server is unavailable. Retry commands with the same idempotency key.",
        ),
    ] {
        let error = match code {
            "400" => "invalid_input",
            "401" => "sign_in_required",
            "403" => "forbidden",
            "404" => "unknown_operation",
            "405" => "unsupported_method",
            "408" => "request_timeout",
            "409" => "idempotency_key_conflict",
            "413" => "body_too_large",
            "415" => "unsupported_content_type",
            "422" => "application_rejected",
            "503" => "unavailable",
            _ => "internal_error",
        };
        responses.insert(
            code.into(),
            json!({
                "description":description,
                "content":{"application/json":{
                    "schema":{"$ref":"#/components/schemas/Error"},
                    "example":{"error":{"code":error,"message":description}}
                }}
            }),
        );
    }
    responses.into()
}

/// Optional text and structured inputs carry JSON within one URL parameter.
pub(crate) fn query_input(record: &Record, raw: &str) -> Result<Value> {
    let mut object = serde_json::Map::new();
    for (name, raw) in crate::routing::query_fields(raw)? {
        let kind = record.fields.get(&name).context("unknown query field")?;
        let value = if matches!(kind, Kind::OptionalText | Kind::InputShape { .. }) {
            crate::json::decode(raw.as_bytes())?
        } else {
            crate::web_security::field_value(kind, &raw)?
        };
        object.insert(name, value);
    }
    let input = Value::Object(object);
    record.validate_input(&input)?;
    Ok(input)
}

#[cfg(test)]
mod structured_query_tests {
    use super::*;
    use crate::output_schema::Type;
    use std::collections::BTreeMap;

    #[test]
    fn shared_error_documentation_lists_every_target_and_binds_current_endpoint() -> Result<()> {
        let error: crate::app_contract::Failure = serde_json::from_value(json!({
            "code":"app:people.invalid_input", "description":"Invalid input.", "recovery":"Correct it.",
            "operation":{"operation":"people.upsert","input_type":"upsert_input","output_type":"rollout"},
            "additional_operations":[{"operation":"people.effective","input_type":"path_input","output_type":"policy"}]
        }))?;
        let document = application_error(&error, "people.effective");
        assert_eq!(document["operation"]["operation"], "people.effective");
        assert_eq!(document["operation"]["input_type"], "path_input");
        assert_eq!(document["operations"].as_array().unwrap().len(), 2);
        assert_eq!(document["operations"][0]["operation"], "people.upsert");
        assert_eq!(document["operations"][1]["operation"], "people.effective");
        Ok(())
    }

    #[test]
    fn structured_query_parameter_is_typed_json_with_unique_nested_keys() -> Result<()> {
        let shape = Type::List(Box::new(Type::Record(BTreeMap::from([
            ("key".into(), Type::String),
            ("enabled".into(), Type::Boolean),
        ]))));
        let record = Record {
            fields: BTreeMap::from([(
                "filters".into(),
                Kind::InputShape {
                    roc_type: shape.annotation(),
                    shape,
                },
            )]),
            roc_type: Some("SearchTypes.Input".into()),
            identity: None,
        };
        let encoded = |raw: &str| {
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("filters", raw)
                .finish()
        };
        assert_eq!(
            query_input(&record, &encoded(r#"[{"key":"role","enabled":true}]"#))?,
            json!({"filters":[{"key":"role","enabled":true}]})
        );
        for raw in [
            r#"[{"key":"a","key":"b","enabled":true}]"#,
            r#"[{"key":"a","enabled":"true"}]"#,
            r#"[{"key":"a","enabled":true,"extra":0}]"#,
            r#"{"key":"a","enabled":true}"#,
        ] {
            assert!(query_input(&record, &encoded(raw)).is_err(), "{raw}");
        }
        assert!(query_input(&record, "filters=%5B%5D&filters=%5B%5D").is_err());
        assert!(crate::web_security::field_value(&record.fields["filters"], "[]").is_err());
        Ok(())
    }
}
