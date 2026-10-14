//! Structural wire types for the private workflow port. Unsupported Rust types
//! have no Wire implementation, so they cannot silently become a Roc contract.
use std::collections::BTreeMap;

pub enum Schema {
    Primitive(&'static str),
    List(Box<Schema>),
    Record {
        name: &'static str,
        fields: Vec<(&'static str, Schema)>,
    },
}

pub trait Wire {
    fn schema() -> Schema;
}

fn matches_shape(schema: &Schema, value: &serde_json::Value) -> bool {
    match schema {
        Schema::Primitive("Str") => value.is_string(),
        Schema::Primitive("Bool") => value.is_boolean(),
        Schema::Primitive("U32") => value.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
        Schema::Primitive("U64") => value.as_u64().is_some(),
        Schema::Primitive(_) => false,
        Schema::List(item) => value
            .as_array()
            .is_some_and(|values| values.iter().all(|value| matches_shape(item, value))),
        Schema::Record { fields, .. } => value.as_object().is_some_and(|values| {
            values.len() == fields.len()
                && fields.iter().all(|(name, schema)| {
                    values
                        .get(*name)
                        .is_some_and(|value| matches_shape(schema, value))
                })
        }),
    }
}

/// Serde also accepts positional arrays for records, including [] for an empty
/// struct. Validate the actual wire shape before invoking a native handler.
pub fn decode<T: Wire + serde::de::DeserializeOwned>(
    request: &super::Request,
) -> anyhow::Result<T> {
    let value: serde_json::Value = request.decode()?;
    anyhow::ensure!(
        matches_shape(&T::schema(), &value),
        "workflow input does not match its declared contract"
    );
    Ok(serde_json::from_value(value)?)
}

impl Wire for String {
    fn schema() -> Schema {
        Schema::Primitive("Str")
    }
}

impl Wire for bool {
    fn schema() -> Schema {
        Schema::Primitive("Bool")
    }
}

impl Wire for u32 {
    fn schema() -> Schema {
        Schema::Primitive("U32")
    }
}

impl Wire for u64 {
    fn schema() -> Schema {
        Schema::Primitive("U64")
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn schema() -> Schema {
        Schema::List(Box::new(T::schema()))
    }
}

/// Terminal receipts are serialized for CLI presentation, never inspected for
/// recipe decisions. Keep their native domain type checked without inventing a
/// second Roc definition of an artifact format (which may contain reserved keys).
pub struct JsonReceipt<T>(pub T);

impl<T: serde::Serialize> serde::Serialize for JsonReceipt<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};
        let json = serde_json::to_string(&self.0).map_err(S::Error::custom)?;
        let mut record = serializer.serialize_struct("JsonReceipt", 1)?;
        record.serialize_field("json", &json)?;
        record.end()
    }
}

impl<T: serde::Serialize> Wire for JsonReceipt<T> {
    fn schema() -> Schema {
        Schema::Record {
            name: "JsonReceipt",
            fields: vec![("json", String::schema())],
        }
    }
}

pub struct Operation {
    pub method: &'static str,
    pub action: &'static str,
    pub input: Schema,
    pub output: Schema,
}

pub struct Host {
    pub name: &'static str,
    pub constructor: &'static str,
    pub operations: Vec<Operation>,
}

fn type_name(schema: &Schema, definitions: &mut BTreeMap<&'static str, String>) -> String {
    match schema {
        Schema::Primitive(name) => (*name).into(),
        Schema::List(item) => format!("List({})", type_name(item, definitions)),
        Schema::Record { name, fields } => {
            let body = if fields.is_empty() {
                "{}".into()
            } else {
                let fields = fields
                    .iter()
                    .map(|(field, schema)| {
                        format!("\t\t{field} : {},\n", type_name(schema, definitions))
                    })
                    .collect::<String>();
                format!("{{\n{fields}\t}}")
            };
            let definition = format!("\t{name} : {body}\n");
            if let Some(existing) = definitions.insert(name, definition.clone()) {
                assert_eq!(existing, definition, "conflicting wire record name");
            }
            (*name).into()
        }
    }
}

/// Deterministic generated sources are checked into the private workflow package
/// and checked for freshness before compiling or reusing its executable.
pub fn roc_sources(hosts: &[Host]) -> Vec<(&'static str, String)> {
    let mut definitions = BTreeMap::new();
    let mut host_types = String::new();
    let mut transport = String::from(
        "# Generated from the native workflow contract; edit its Rust definitions.\nimport UiCapability\n\nUiTransport :: [].{\n",
    );
    for host in hosts {
        host_types.push_str(&format!("\t{} : {{\n", host.name));
        transport.push_str(&format!(
            "\t{} : (Str => Try(Str, Str)) -> UiCapability.{}\n\t{} = |send!| {{\n",
            host.constructor, host.name, host.constructor
        ));
        for operation in &host.operations {
            let input = type_name(&operation.input, &mut definitions);
            let output = type_name(&operation.output, &mut definitions);
            host_types.push_str(&format!(
                "\t\t{}! : {} => Try({}, Str),\n",
                operation.method, input, output
            ));
            transport.push_str(&format!("\t\t{}!: |input| {{\n\t\t\traw = send!(Json.to_str({{ protocol: 1.U32, action: \"{}\", input: Json.to_str(input) }}))?\n\t\t\tresult : UiCapability.{}\n\t\t\tresult = Json.parse(raw).map_err(|_| \"invalid {} response\")?\n\t\t\tOk(result)\n\t\t}},\n", operation.method, operation.action, output, operation.action));
        }
        host_types.push_str("\t}\n\n");
        transport.push_str("\t}\n\n");
    }
    let records = definitions.into_values().collect::<Vec<_>>().join("\n");
    let api = format!(
        "# Generated from the native workflow contract; edit its Rust definitions.\nUiCapability :: [].{{\n{records}\n{host_types}}}\n"
    );
    transport.push_str("}\n");
    vec![
        ("ops/UiCapability.roc", api),
        ("ops/UiTransport.roc", transport),
    ]
}

/// A record's Rust type, Serde codec and Roc field names come from this one
/// definition. Wire field names are explicit because existing receipts use camelCase.
#[macro_export]
macro_rules! workflow_record {
    ($name:ident { $($field:ident : $ty:ty => $wire:literal),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            $(#[serde(rename = $wire)] pub $field: $ty,)*
        }

        impl $crate::automation::contract::Wire for $name {
            fn schema() -> $crate::automation::contract::Schema {
                $crate::automation::contract::Schema::Record {
                    name: stringify!($name),
                    fields: vec![$(($wire, <$ty as $crate::automation::contract::Wire>::schema())),*],
                }
            }
        }
    };
}

/// No default handlers: adding an operation makes every implementation of its
/// host trait incomplete until the corresponding typed native method exists.
#[macro_export]
macro_rules! workflow_host {
    ($name:ident, $constructor:literal, $schema:ident, $dispatch:ident {
        $($method:ident ($action:literal, $input:ty) -> $output:ty),* $(,)?
    }) => {
        pub trait $name {
            $(fn $method(&mut self, input: $input) -> anyhow::Result<$output>;)*
        }

        pub fn $schema() -> $crate::automation::contract::Host {
            use $crate::automation::contract::{Host, Operation, Wire};
            Host {
                name: stringify!($name),
                constructor: $constructor,
                operations: vec![$(Operation {
                    method: stringify!($method), action: $action,
                    input: <$input>::schema(), output: <$output>::schema(),
                }),*],
            }
        }

        pub fn $dispatch(host: &mut impl $name, request: &$crate::automation::Request)
            -> anyhow::Result<Option<serde_json::Value>>
        {
            match request.action.as_str() {
                $($action => {
                    let input: $input = $crate::automation::contract::decode(request)?;
                    let output: $output = host.$method(input)?;
                    Ok(Some(serde_json::to_value(output)?))
                }),*
                _ => Ok(None),
            }
        }
    };
}
