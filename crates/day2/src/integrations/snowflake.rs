//! https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests
//! https://docs.snowflake.com/en/developer-guide/sql-api/reference

use super::{AdapterError, PreparedCall, ResponseProfile, transport::WireRequest};
use day2_capabilities::integrations::{LiveConnection, SnowflakeScalar, SnowflakeView};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    handle: String,
    parameters: Vec<Parameter>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameter {
    name: String,
    kind: String,
    value: String,
}

pub(super) fn prepare(
    connection: &LiveConnection,
    query: &SnowflakeView,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let LiveConnection::Snowflake {
        account,
        role,
        warehouse,
        ..
    } = connection
    else {
        return Err(AdapterError::InvalidProfile);
    };
    let input: ReadRequest =
        serde_json::from_str(input).map_err(|_| AdapterError::InvalidRequest)?;
    if input.handle.is_empty() || input.parameters.len() != query.filters.len() {
        return Err(AdapterError::InvalidRequest);
    }
    let mut parameters = BTreeMap::new();
    for parameter in input.parameters {
        let value = match parameter.kind.as_str() {
            "text" => SnowflakeScalar::Text(parameter.value),
            "integer" => {
                let integer: i64 = parameter
                    .value
                    .parse()
                    .map_err(|_| AdapterError::InvalidRequest)?;
                if integer.to_string() != parameter.value {
                    return Err(AdapterError::InvalidRequest);
                }
                SnowflakeScalar::Integer(integer)
            }
            "boolean" => match parameter.value.as_str() {
                "true" => SnowflakeScalar::Boolean(true),
                "false" => SnowflakeScalar::Boolean(false),
                _ => return Err(AdapterError::InvalidRequest),
            },
            _ => return Err(AdapterError::InvalidRequest),
        };
        if parameters.insert(parameter.name, value).is_some() {
            return Err(AdapterError::InvalidRequest);
        }
    }
    let mut statement = format!(
        "SELECT {} FROM {}.{}.{}",
        query
            .columns
            .iter()
            .map(|name| quoted(name))
            .collect::<Vec<_>>()
            .join(", "),
        quoted(&query.database),
        quoted(&query.schema),
        quoted(&query.view)
    );
    let mut predicates = Vec::new();
    let mut bindings = Map::new();
    for (index, (column, kind)) in query.filters.iter().enumerate() {
        let value = parameters.get(column).ok_or(AdapterError::InvalidRequest)?;
        if value.scalar_type() != *kind {
            return Err(AdapterError::InvalidRequest);
        }
        let (kind, value) = match value {
            SnowflakeScalar::Text(value) => {
                if value.len() > 16_384 || value.contains('\0') {
                    return Err(AdapterError::InvalidRequest);
                }
                ("TEXT", value.clone())
            }
            SnowflakeScalar::Integer(value) => ("FIXED", value.to_string()),
            SnowflakeScalar::Boolean(value) => ("BOOLEAN", value.to_string()),
        };
        predicates.push(format!("{} = ?", quoted(column)));
        bindings.insert((index + 1).to_string(), json!({"type":kind,"value":value}));
    }
    if !predicates.is_empty() {
        statement.push_str(&format!(" WHERE {}", predicates.join(" AND ")));
    }
    // One extra row detects an incomplete result instead of silently truncating.
    statement.push_str(&format!(" LIMIT {}", query.max_rows + 1));
    let body = json!({"statement":statement,"timeout":20,"database":query.database,"schema":query.schema,
        "warehouse":warehouse,"role":role,"bindings":bindings,"parameters":{"MULTI_STATEMENT_COUNT":"1"}});
    Ok(PreparedCall {
        connection: connection.clone(),
        request: WireRequest::json(
            &format!("https://{account}.snowflakecomputing.com/api/v2/statements"),
            body.to_string().into_bytes(),
        ),
        response: ResponseProfile::Snowflake {
            columns: query.columns.clone(),
            max_rows: query.max_rows,
        },
        response_limit: 0,
        reserved_monetary_microusd: None,
    })
}

fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

pub(super) fn response(
    json: &Value,
    columns: &[String],
    max_rows: u32,
) -> Result<Value, AdapterError> {
    if json.get("code").and_then(Value::as_str) != Some("090001")
        && json.get("code").and_then(Value::as_str) != Some("0")
    {
        return Err(AdapterError::ResponseInvalid);
    }
    if json.get("statementHandles").is_some() {
        return Err(AdapterError::ResponseInvalid);
    }
    let meta = json
        .get("resultSetMetaData")
        .ok_or(AdapterError::ResponseInvalid)?;
    let count = meta
        .get("numRows")
        .and_then(Value::as_u64)
        .ok_or(AdapterError::ResponseInvalid)?;
    if count > u64::from(max_rows) {
        return Err(AdapterError::ResponseTooLarge);
    }
    if meta.get("format").and_then(Value::as_str) != Some("jsonv2") {
        return Err(AdapterError::ResponseInvalid);
    }
    let row_type = meta
        .get("rowType")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if row_type.len() != columns.len()
        || !row_type
            .iter()
            .zip(columns)
            .all(|(actual, expected)| actual.get("name").and_then(Value::as_str) == Some(expected))
    {
        return Err(AdapterError::ResponseInvalid);
    }
    let partitions = meta
        .get("partitionInfo")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if partitions.len() != 1 || partitions[0].get("rowCount").and_then(Value::as_u64) != Some(count)
    {
        return Err(AdapterError::Incomplete);
    }
    let rows = json
        .get("data")
        .and_then(Value::as_array)
        .ok_or(AdapterError::ResponseInvalid)?;
    if rows.len() as u64 != count
        || rows.iter().any(|row| {
            row.as_array().is_none_or(|cells| {
                cells.len() != columns.len()
                    || cells
                        .iter()
                        .any(|cell| !cell.is_null() && !cell.is_string())
            })
        })
    {
        return Err(AdapterError::ResponseInvalid);
    }
    // No status URLs, partition links or SQL echoed to the caller. A synchronous
    // incomplete result is a failure, never an implicit unbounded follow-up.
    let rows: Vec<Vec<Value>> =
        rows.iter()
            .map(|row| {
                row.as_array().expect("validated row").iter()
        .map(|cell| json!({"is_null":cell.is_null(),"value":cell.as_str().unwrap_or("")})).collect()
            })
            .collect();
    Ok(json!({"columns":columns,"rows":rows}))
}
