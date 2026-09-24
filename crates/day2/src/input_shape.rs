//! Closed structural operation inputs. Persistent model fields keep their own
//! scalar/reference codecs; these shapes never become SQLite blob columns.
use crate::{output_schema::Type, schema::Kind};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

pub const MAX_DEPTH: usize = 8;
pub const MAX_SCHEMA_NODES: usize = 256;
pub const MAX_VALUE_NODES: usize = 4096;
pub const MAX_FIELDS: usize = 32;
pub const MAX_LIST_ITEMS: usize = 100;
pub const MAX_JSON_BYTES: usize = 65_535;

pub(crate) fn validate_schema(shape: &Type, depth: usize, nodes: &mut usize) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "input schema depth budget");
    *nodes += 1;
    ensure!(*nodes <= MAX_SCHEMA_NODES, "input schema node budget");
    match shape {
        Type::Record(fields) => {
            ensure!(fields.len() <= MAX_FIELDS, "input record field budget");
            for (name, field) in fields {
                crate::schema::identifier(name)?;
                validate_schema(field, depth + 1, nodes)?;
            }
        }
        Type::List(item) => validate_schema(item, depth + 1, nodes)?,
        // A keyed collection admits one level: scalar values, or a list of scalars.
        // Deeper nesting would need an encoding grammar whose invalid states the
        // schema cannot express, so it fails closed instead.
        Type::Map(value) => {
            ensure!(
                matches!(
                    **value,
                    Type::String | Type::Integer | Type::Unsigned(_) | Type::Boolean
                ) || matches!(&**value, Type::List(item)
                    if matches!(**item, Type::String | Type::Integer | Type::Unsigned(_) | Type::Boolean)),
                "map values admit one level: a scalar or a list of scalars"
            );
            validate_schema(value, depth + 1, nodes)?
        }
        Type::Set => {}
        Type::String | Type::Integer | Type::Unsigned(_) | Type::Boolean | Type::OptionalText => {}
        _ => bail!("structured inputs require builtin scalars, structural records or lists"),
    }
    Ok(())
}

pub(crate) fn validate_kind(shape: &Type, roc_type: &str) -> Result<()> {
    ensure!(
        matches!(
            shape,
            Type::Record(_) | Type::List(_) | Type::Map(_) | Type::Set
        ),
        "structured input must start with a record, list, map or set"
    );
    validate_schema(shape, 1, &mut 0)?;
    ensure!(
        roc_type == shape.annotation(),
        "structured input annotation differs from checked shape"
    );
    Ok(())
}

pub(crate) fn validate_value(shape: &Type, value: &Value) -> Result<()> {
    validate_schema(shape, 1, &mut 0)?;
    validate_at(shape, value, 1, &mut 0)?;
    ensure!(
        serde_json::to_vec(value)?.len() <= MAX_JSON_BYTES,
        "input byte budget"
    );
    Ok(())
}

pub(crate) fn validate_at(
    shape: &Type,
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "input value depth budget");
    *nodes += 1;
    ensure!(*nodes <= MAX_VALUE_NODES, "input value node budget");
    match shape {
        Type::Record(fields) => {
            let record = value
                .as_object()
                .context("expected structured input record")?;
            ensure!(record.len() == fields.len(), "input record field mismatch");
            for (name, shape) in fields {
                validate_at(
                    shape,
                    record.get(name).context("missing structured input field")?,
                    depth + 1,
                    nodes,
                )
                .with_context(|| format!("input field {name}"))?;
            }
        }
        Type::List(item) => {
            let items = value.as_array().context("expected structured input list")?;
            ensure!(items.len() <= MAX_LIST_ITEMS, "input list item budget");
            for (index, value) in items.iter().enumerate() {
                validate_at(item, value, depth + 1, nodes)
                    .with_context(|| format!("input item {index}"))?;
            }
        }
        // Inbound values are checked for the same invariants the constructors
        // guarantee, so a caller that bypasses Roc cannot introduce a duplicate
        // key or a second encoding of one value.
        Type::Map(item) => {
            let entries = payload(value, "entries", "map")?;
            ensure!(entries.len() <= MAX_LIST_ITEMS, "input map entry budget");
            let mut keys: Vec<&str> = Vec::with_capacity(entries.len());
            for (index, entry) in entries.iter().enumerate() {
                let object = entry.as_object().context("expected map entry")?;
                ensure!(object.len() == 2, "map entry requires key and value");
                let key = object
                    .get("key")
                    .and_then(Value::as_str)
                    .context("map entry key missing")?;
                ensure!(!key.trim().is_empty(), "map key must not be blank");
                ensure!(!keys.contains(&key), "map keys must be unique");
                ensure!(
                    keys.last().is_none_or(|last| *last < key),
                    "map entries must be ordered by key"
                );
                keys.push(key);
                validate_at(
                    item,
                    object.get("value").context("map entry value missing")?,
                    depth + 1,
                    nodes,
                )
                .with_context(|| format!("input map entry {index}"))?;
            }
        }
        Type::Set => {
            let members = payload(value, "members", "set")?;
            ensure!(members.len() <= MAX_LIST_ITEMS, "input set member budget");
            let mut seen: Vec<&str> = Vec::with_capacity(members.len());
            for member in members {
                let member = member.as_str().context("expected set member text")?;
                ensure!(!member.trim().is_empty(), "set member must not be blank");
                ensure!(!seen.contains(&member), "set members must be unique");
                ensure!(
                    seen.last().is_none_or(|last| *last < member),
                    "set members must be ordered"
                );
                seen.push(member);
            }
        }
        Type::String => ensure!(Kind::Text.valid(value), "expected bounded input text"),
        Type::Integer => ensure!(Kind::Integer.valid(value), "expected i64 input"),
        Type::Unsigned(width) => ensure!(width.valid(value), "invalid unsigned input"),
        Type::Boolean => ensure!(value.is_boolean(), "expected boolean input"),
        Type::OptionalText => ensure!(
            Kind::OptionalText.valid(value),
            "invalid optional input text"
        ),
        _ => bail!("unsupported structured input shape"),
    }
    Ok(())
}

pub(crate) fn json_schema(shape: &Type) -> Value {
    match shape {
        Type::Record(fields) => json!({
            "type":"object", "required":fields.keys().collect::<Vec<_>>(), "additionalProperties":false,
            "properties":fields.iter().map(|(name, shape)| (name.clone(), json_schema(shape))).collect::<serde_json::Map<_, _>>()
        }),
        Type::List(item) => {
            json!({"type":"array", "maxItems":MAX_LIST_ITEMS, "items":json_schema(item)})
        }
        _ => crate::operation_catalog::output_schema(shape),
    }
}

pub(crate) fn example(shape: &Type) -> Value {
    match shape {
        Type::Record(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, shape)| (name.clone(), example(shape)))
                .collect(),
        ),
        Type::List(_) => json!([]),
        Type::Integer | Type::Unsigned(_) => json!(0),
        Type::Boolean => json!(false),
        Type::OptionalText => json!("None"),
        _ => json!("example"),
    }
}

/// The single payload list a nominal collection wrapper carries on the wire.
fn payload<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a Vec<Value>> {
    let object = value
        .as_object()
        .with_context(|| format!("expected {label} input"))?;
    ensure!(
        object.len() == 1,
        "{label} input requires one {field} field"
    );
    object
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("{label} input requires {field} list"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn attributes() -> Type {
        Type::List(Box::new(Type::Record(BTreeMap::from([
            ("key".into(), Type::String),
            ("value".into(), Type::String),
        ]))))
    }

    #[test]
    fn structural_lists_preserve_objects_and_reject_unknown_nested_fields() -> Result<()> {
        let shape = attributes();
        validate_kind(&shape, "List({ key : Str, value : Str })")?;
        validate_value(&shape, &json!([{"key":"role","value":"reader"}]))?;
        for value in [
            json!([{"key":"role","value":"reader","unknown":true}]),
            json!([{"key":"role"}]),
            json!([{"key":"role","value":1}]),
            json!("[{\"key\":\"role\",\"value\":\"reader\"}]"),
        ] {
            assert!(validate_value(&shape, &value).is_err());
        }
        assert!(validate_kind(&shape, "List(Trusted.Unchecked)").is_err());
        let schema = json_schema(&shape);
        assert_eq!(schema["maxItems"], 100);
        assert_eq!(schema["items"]["additionalProperties"], false);
        Ok(())
    }

    #[test]
    fn nested_inputs_enforce_collection_depth_node_and_string_budgets() -> Result<()> {
        validate_value(
            &attributes(),
            &json!(vec![json!({"key":"k","value":"v"}); 100]),
        )?;
        assert!(
            validate_value(
                &attributes(),
                &json!(vec![json!({"key":"k","value":"v"}); 101])
            )
            .is_err()
        );
        assert!(
            validate_value(
                &attributes(),
                &json!([{"key":"k","value":"v".repeat(16_385)}])
            )
            .is_err()
        );
        let mut deep = Type::String;
        for _ in 0..MAX_DEPTH {
            deep = Type::List(Box::new(deep));
        }
        assert!(validate_schema(&deep, 1, &mut 0).is_err());
        let wide = Type::Record(
            (0..MAX_FIELDS)
                .map(|index| (format!("field_{index}"), attributes()))
                .collect(),
        );
        assert!(validate_schema(&wide, 1, &mut (MAX_SCHEMA_NODES - 1)).is_err());
        let many_lists = Type::List(Box::new(Type::List(Box::new(Type::Integer))));
        assert!(validate_value(&many_lists, &json!(vec![vec![0; 100]; 100])).is_err());
        Ok(())
    }

    #[test]
    fn input_shape_rejects_nominal_wrappers_and_lossy_numbers() -> Result<()> {
        for unsupported in [
            Type::ModelReference {
                roc_type: "Models.Employee".into(),
                prefix: "emp".into(),
            },
            Type::StandardText {
                domain: "Name".into(),
            },
            Type::RowVersion,
            Type::IdPage(Box::new(Type::String)),
            Type::PageSize,
        ] {
            assert!(validate_schema(&Type::List(Box::new(unsupported)), 1, &mut 0).is_err());
        }
        let shape = Type::List(Box::new(Type::Unsigned(crate::numeric::Unsigned::U64)));
        validate_value(&shape, &json!([u64::MAX]))?;
        assert!(validate_value(&shape, &json!([1.5])).is_err());
        assert!(validate_value(&shape, &json!([-1])).is_err());
        Ok(())
    }
}
