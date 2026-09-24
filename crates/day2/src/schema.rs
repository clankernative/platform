use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Kind {
    Integer,
    Unsigned(crate::numeric::Unsigned),
    RowVersion,
    Text,
    Boolean,
    OptionalText,
    Reference {
        target: String,
    },
    ModelReference {
        target: String,
        prefix: String,
    },
    TextDomain {
        roc_type: String,
    },
    StandardText {
        domain: String,
    },
    WebUrl,
    Cursor,
    IdCursor,
    PageSize,
    InputShape {
        shape: crate::output_schema::Type,
        roc_type: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub fields: BTreeMap<String, Kind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roc_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<crate::identity::ModelIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForeignKey {
    pub model: String,
    pub field: String,
    pub target: String,
}

/// A declared equality key. Field order is canonical, independent of Roc record
/// layout; uniqueness applies to the complete tuple, never to its row ID.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Index {
    pub model: String,
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    pub models: BTreeMap<String, Record>,
    pub inputs: BTreeMap<String, Record>,
    pub foreign_keys: Vec<ForeignKey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indexes: Vec<Index>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub domains: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Table {
    entries: Vec<Entry>,
    types: Vec<Node>,
}
#[derive(Deserialize)]
struct Entry {
    symbol: String,
    type_id: usize,
}
#[derive(Deserialize)]
struct Field {
    name: String,
    type_id: usize,
}
#[derive(Deserialize)]
struct Tag {
    name: String,
    payload: Vec<usize>,
}
#[derive(Deserialize)]
struct Node {
    kind: String,
    name: String,
    item: usize,
    fields: Vec<Field>,
    args: Vec<usize>,
    ret: usize,
    tags: Vec<Tag>,
}

pub fn identifier(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 48,
        "invalid identifier length"
    );
    ensure!(
        name.as_bytes()[0].is_ascii_lowercase(),
        "identifier must start with a-z: {name}"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "invalid identifier: {name}"
    );
    ensure!(
        !name.starts_with("day2_") && !name.starts_with("sqlite_"),
        "reserved identifier: {name}"
    );
    Ok(())
}

impl Table {
    /// Keys come from each model's attached `table`, reflected through the
    /// platform-generated storage witness. Every key column must be a column of
    /// its own model with the same kind; the SDK has no other way to name one.
    fn indexes(
        &self,
        models: &BTreeMap<String, Record>,
        model_types: &BTreeMap<String, String>,
    ) -> Result<Vec<Index>> {
        let entries = self
            .entries
            .iter()
            .filter(|entry| entry.symbol == "day2_storage")
            .collect::<Vec<_>>();
        ensure!(entries.len() <= 1, "duplicate storage witness");
        let Some(entry) = entries.first() else {
            return Ok(Vec::new());
        };
        let function = self.node(entry.type_id)?;
        ensure!(
            function.kind == "function" && function.args.len() == 1,
            "invalid storage witness"
        );
        let storage = self.node(function.ret)?;
        ensure!(
            storage.kind == "record",
            "storage definition must be a record"
        );
        let declaration = storage
            .fields
            .iter()
            .find(|field| field.name == "tables")
            .context("storage witness requires generated tables")?;
        let tables = self.node(declaration.type_id)?;
        ensure!(
            tables.kind == "record" && tables.fields.len() == models.len(),
            "storage tables must match registered models"
        );
        let witness = |node: &Node, name: &str| -> Result<usize> {
            let field = node
                .fields
                .iter()
                .find(|field| field.name == name)
                .with_context(|| format!("table witness requires {name}"))?;
            let list = self.node(field.type_id)?;
            ensure!(list.kind == "list", "invalid table witness {name}");
            Ok(list.item)
        };
        let mut indexes = Vec::new();
        for declared in &tables.fields {
            let model = models
                .get(&declared.name)
                .with_context(|| format!("unregistered storage table {}", declared.name))?;
            let table = self.node(declared.type_id)?;
            ensure!(
                table.kind == "record" && table.name == "Table" && table.fields.len() == 2,
                "storage tables require Table witnesses"
            );
            let row = self.node(witness(table, "row_witness")?)?;
            ensure!(
                row.kind == "record" && Some(&row.name) == model.roc_type.as_ref(),
                "table {} must declare keys over its own model",
                declared.name
            );
            let keys = self.node(witness(table, "key_witness")?)?;
            if keys.kind == "unit" || (keys.kind == "record" && keys.fields.is_empty()) {
                continue;
            }
            ensure!(keys.kind == "record", "table keys must be a record");
            for definition in &keys.fields {
                let key = self.node(definition.type_id)?;
                ensure!(
                    key.kind == "union" && key.tags.len() == 1,
                    "a key requires Table.unique or Table.non_unique"
                );
                let tag = &key.tags[0];
                ensure!(
                    matches!(tag.name.as_str(), "Unique" | "NonUnique") && tag.payload.len() == 1,
                    "a key requires Table.unique or Table.non_unique"
                );
                let list = self.node(tag.payload[0])?;
                ensure!(list.kind == "list", "invalid key witness");
                let columns = self.node(list.item)?;
                ensure!(
                    columns.kind == "record"
                        && columns.name.starts_with("__")
                        && !columns.fields.is_empty(),
                    "key {}.{} must select a record of columns, such as {{ date: row.date }}",
                    declared.name,
                    definition.name
                );
                let mut fields = Vec::new();
                for column in &columns.fields {
                    let expected = model.fields.get(&column.name).with_context(|| {
                        format!(
                            "key {}.{} names {}, which is not a column of {}",
                            declared.name, definition.name, column.name, row.name
                        )
                    })?;
                    ensure!(
                        &self.kind(column.type_id, model_types)? == expected,
                        "key {}.{} column {} does not read the model's {} column",
                        declared.name,
                        definition.name,
                        column.name,
                        column.name
                    );
                    fields.push(column.name.clone());
                }
                fields.sort();
                indexes.push(Index {
                    model: declared.name.clone(),
                    name: definition.name.clone(),
                    fields,
                    unique: tag.name == "Unique",
                });
            }
        }
        indexes.sort_by(|left, right| (&left.model, &left.name).cmp(&(&right.model, &right.name)));
        Ok(indexes)
    }

    fn domains(&self) -> Result<BTreeMap<String, String>> {
        let mut domains = BTreeMap::new();
        let entries = self
            .entries
            .iter()
            .filter(|entry| entry.symbol == "day2_domains")
            .collect::<Vec<_>>();
        ensure!(entries.len() <= 1, "duplicate domain witness");
        if let Some(entry) = entries.first() {
            let function = self.node(entry.type_id)?;
            ensure!(
                function.kind == "function" && function.args.len() == 1,
                "invalid domain witness"
            );
            let root = self.node(function.ret)?;
            ensure!(
                matches!(root.kind.as_str(), "record" | "unit"),
                "domain definitions must be a record"
            );
            for field in &root.fields {
                identifier(&field.name)?;
                let definition = self.node(field.type_id)?;
                ensure!(
                    definition.kind == "record" && definition.name == "TextSpec",
                    "domain definitions require TextSpec"
                );
                let witness = definition
                    .fields
                    .iter()
                    .find(|field| field.name == "witness")
                    .context("domain tag witness required")?;
                let witness = self.node(witness.type_id)?;
                ensure!(witness.kind == "list", "invalid domain tag witness");
                let domain = self.node(witness.item)?.name.clone();
                roc_type_name(&domain)?;
                ensure!(
                    domains.insert(field.name.clone(), domain).is_none(),
                    "duplicate domain key"
                );
            }
        }
        Ok(domains)
    }
    fn node(&self, id: usize) -> Result<&Node> {
        self.types
            .get(id)
            .context("invalid compiler type reference")
    }
    fn root(&self, name: &str) -> Result<&Node> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| entry.symbol == name)
            .collect();
        ensure!(entries.len() == 1, "expected one checked {name} entrypoint");
        let function = self.node(entries[0].type_id)?;
        ensure!(
            function.kind == "function"
                && function.args.len() == 1
                && function.args[0] == function.ret,
            "invalid schema witness"
        );
        let root = self.node(function.ret)?;
        ensure!(root.kind == "record", "registered types must form a record");
        Ok(root)
    }
    fn kind(&self, id: usize, models: &BTreeMap<String, String>) -> Result<Kind> {
        let node = self.node(id)?;
        match node.kind.as_str() {
            "integer" => Ok(Kind::Integer),
            "unsigned" => Ok(Kind::Unsigned(
                crate::numeric::Unsigned::from_roc(&node.name)
                    .context("unsupported unsigned integer width")?,
            )),
            "text" => Ok(Kind::Text),
            "boolean" => Ok(Kind::Boolean),
            "record" if matches!(node.name.as_str(), "Cursor" | "PageSize" | "RowVersion") => {
                ensure!(
                    node.fields.len() == 1
                        && node.fields[0].name == "value"
                        && if node.name == "RowVersion" {
                            let value = self.node(node.fields[0].type_id)?;
                            // Older admitted artifacts used I64 with the same positive bounds.
                            value.kind == "integer"
                                || (value.kind == "unsigned" && value.name == "U64")
                        } else if node.name == "Cursor" {
                            matches!(
                                self.node(node.fields[0].type_id)?.kind.as_str(),
                                "integer" | "text"
                            )
                        } else {
                            self.node(node.fields[0].type_id)?.kind == "integer"
                        },
                    "invalid bounded numeric type shape"
                );
                Ok(if node.name == "Cursor" {
                    if self.node(node.fields[0].type_id)?.kind == "text" {
                        Kind::IdCursor
                    } else {
                        Kind::Cursor
                    }
                } else if node.name == "PageSize" {
                    Kind::PageSize
                } else {
                    Kind::RowVersion
                })
            }
            "record" if node.name == "Ref" => {
                ensure!(node.fields.len() == 2, "invalid reference shape");
                let field = |name: &str| -> Result<&Node> {
                    self.node(
                        node.fields
                            .iter()
                            .find(|f| f.name == name)
                            .context("invalid reference shape")?
                            .type_id,
                    )
                };
                ensure!(
                    matches!(field("value")?.kind.as_str(), "integer" | "text"),
                    "invalid reference value"
                );
                let witness = field("witness")?;
                ensure!(witness.kind == "list", "invalid reference witness");
                let target = models
                    .get(&self.node(witness.item)?.name)
                    .context("reference target must be a registered nominal model")?;
                Ok(Kind::Reference {
                    target: target.clone(),
                })
            }
            "record" if node.name == "Text" => {
                ensure!(node.fields.len() == 2, "invalid standard text shape");
                let value = node
                    .fields
                    .iter()
                    .find(|field| field.name == "value")
                    .context("text value missing")?;
                ensure!(
                    self.node(value.type_id)?.kind == "text",
                    "invalid text value"
                );
                let witness = node
                    .fields
                    .iter()
                    .find(|field| field.name == "witness")
                    .context("text witness missing")?;
                let witness = self.node(witness.type_id)?;
                ensure!(
                    witness.kind == "list",
                    "text requires nominal domain witness"
                );
                let domain = self.node(witness.item)?.name.clone();
                roc_type_name(&domain)?;
                Ok(Kind::StandardText { domain })
            }
            "record" if !node.name.starts_with("__") => {
                roc_type_name(&node.name)?;
                ensure!(
                    !models.contains_key(&node.name),
                    "nested model must use Ref"
                );
                ensure!(
                    node.fields.len() == 1
                        && node.fields[0].name == "value"
                        && self.node(node.fields[0].type_id)?.kind == "text",
                    "domain codecs currently require a nominal {{ value : Str }} wrapper"
                );
                if node.name == "WebUrl" {
                    return Ok(Kind::WebUrl);
                }
                Ok(Kind::TextDomain {
                    roc_type: node.name.clone(),
                })
            }
            "union" if node.tags.len() == 2 => {
                let none = node
                    .tags
                    .iter()
                    .find(|tag| tag.name == "None" && tag.payload.is_empty());
                let some = node
                    .tags
                    .iter()
                    .find(|tag| tag.name == "Some" && tag.payload.len() == 1);
                ensure!(none.is_some(), "unsupported nullable representation");
                let some = some.context("unsupported nullable representation")?;
                ensure!(
                    self.node(some.payload[0])?.kind == "text",
                    "only optional text supported in this spike"
                );
                Ok(Kind::OptionalText)
            }
            _ => bail!("unsupported persistent/input type: {}", node.kind),
        }
    }
    /// The single payload field of a nominal SDK collection. These types wrap one
    /// list because the reflection has no map or set kind; the wrapper name carries
    /// the contract.
    fn nominal_payload(&self, node: &Node, field: &str) -> Result<&Node> {
        ensure!(
            node.fields.len() == 1 && node.fields[0].name == field,
            "nominal collection requires exactly one {field} field"
        );
        self.node(node.fields[0].type_id)
    }

    fn input_shape(
        &self,
        id: usize,
        active: &mut std::collections::BTreeSet<usize>,
        count: &mut usize,
    ) -> Result<crate::output_schema::Type> {
        use crate::output_schema::Type;
        ensure!(
            active.len() < crate::input_shape::MAX_DEPTH,
            "input schema depth budget"
        );
        ensure!(active.insert(id), "recursive structured input unsupported");
        *count += 1;
        ensure!(
            *count <= crate::input_shape::MAX_SCHEMA_NODES,
            "input schema node budget"
        );
        let node = self.node(id)?;
        let builtin = node.name.is_empty() || node.name.starts_with("__");
        let shape = match node.kind.as_str() {
            "text" if builtin => Type::String,
            "integer" if builtin => Type::Integer,
            "boolean" if builtin => Type::Boolean,
            "unsigned" => Type::Unsigned(
                crate::numeric::Unsigned::from_roc(&node.name)
                    .context("unsupported unsigned input width")?,
            ),
            "unit" if node.name.is_empty() => {
                ensure!(
                    node.fields.is_empty()
                        && node.tags.is_empty()
                        && node.args.is_empty()
                        && node.item == 0
                        && node.ret == 0,
                    "invalid structured unit input"
                );
                Type::Record(BTreeMap::new())
            }
            // Nominal keyed and unique collections. The reflection exposes records
            // and lists only, so the contract is carried by the SDK type name the
            // same way Text, Ref and Cursor are recognised above.
            "record" if node.name == "TextMap" => {
                let entries = self.nominal_payload(node, "entries")?;
                let entry = self.node(entries.item)?;
                ensure!(
                    entries.kind == "list" && entry.kind == "record" && entry.fields.len() == 2,
                    "map requires a list of key/value entries"
                );
                let key = entry
                    .fields
                    .iter()
                    .find(|field| field.name == "key")
                    .context("map entry key missing")?;
                ensure!(
                    self.node(key.type_id)?.kind == "text",
                    "map keys must be text"
                );
                let value = entry
                    .fields
                    .iter()
                    .find(|field| field.name == "value")
                    .context("map entry value missing")?;
                Type::Map(Box::new(self.input_shape(value.type_id, active, count)?))
            }
            "record" if node.name == "TextSet" => {
                let members = self.nominal_payload(node, "members")?;
                ensure!(members.kind == "list", "set requires a list of members");
                ensure!(
                    self.node(members.item)?.kind == "text",
                    "set members must be text"
                );
                Type::Set
            }
            "record" if node.name.starts_with("__") => {
                ensure!(
                    node.fields.len() <= crate::input_shape::MAX_FIELDS,
                    "input record field budget"
                );
                let mut fields = BTreeMap::new();
                for field in &node.fields {
                    identifier(&field.name)?;
                    ensure!(
                        fields
                            .insert(
                                field.name.clone(),
                                self.input_shape(field.type_id, active, count)?
                            )
                            .is_none(),
                        "duplicate structured input field"
                    );
                }
                Type::Record(fields)
            }
            "list" if builtin => Type::List(Box::new(self.input_shape(node.item, active, count)?)),
            // Native reflection gives the structural optional union this
            // synthesized name; user-defined nominal wrappers retain theirs.
            "union" if builtin || node.name == "NoneOrSome" => {
                ensure!(
                    node.tags.len() == 2
                        && node.fields.is_empty()
                        && node.args.is_empty()
                        && node.item == 0
                        && node.ret == 0,
                    "unsupported structured input union"
                );
                ensure!(
                    node.tags
                        .iter()
                        .any(|tag| tag.name == "None" && tag.payload.is_empty()),
                    "optional input requires None"
                );
                let some = node
                    .tags
                    .iter()
                    .find(|tag| tag.name == "Some" && tag.payload.len() == 1)
                    .context("optional input requires one Some payload")?;
                ensure!(
                    self.input_shape(some.payload[0], active, count)? == Type::String,
                    "only optional text is supported inside structured inputs"
                );
                Type::OptionalText
            }
            _ => bail!(
                "structured inputs require builtin scalars, structural records or lists; unsupported {} {}",
                node.kind,
                node.name
            ),
        };
        active.remove(&id);
        Ok(shape)
    }

    fn input_kind(&self, id: usize, models: &BTreeMap<String, String>) -> Result<Kind> {
        let node = self.node(id)?;
        // Structural shapes route to the input-shape compiler, and so do the two
        // nominal collection wrappers: their name carries a contract the bare
        // record shape cannot express, so they are not domain text wrappers.
        if node.kind == "list"
            || node.kind == "unit"
            || (node.kind == "record"
                && (node.name.starts_with("__")
                    || node.name == "TextMap"
                    || node.name == "TextSet"))
        {
            let shape = self.input_shape(id, &mut std::collections::BTreeSet::new(), &mut 0)?;
            let roc_type = shape.annotation();
            crate::input_shape::validate_kind(&shape, &roc_type)?;
            Ok(Kind::InputShape { shape, roc_type })
        } else {
            self.kind(id, models)
        }
    }

    fn record(
        &self,
        id: usize,
        persistent: bool,
        models: &BTreeMap<String, String>,
    ) -> Result<Record> {
        let node = self.node(id)?;
        // Native reflection represents an empty operation input as unit and
        // erases its name. Admit only the exact structural {} shape here;
        // persistent model registration retains its nominal record checks.
        if !persistent && node.kind == "unit" {
            ensure!(
                node.name.is_empty()
                    && node.fields.is_empty()
                    && node.args.is_empty()
                    && node.tags.is_empty()
                    && node.item == 0
                    && node.ret == 0,
                "invalid empty input metadata"
            );
            return Ok(Record {
                fields: BTreeMap::new(),
                roc_type: None,
                identity: None,
            });
        }
        ensure!(
            node.kind == "record" && node.fields.len() <= 32,
            "expected bounded flat record"
        );
        let mut fields = BTreeMap::new();
        for field in &node.fields {
            identifier(&field.name)?;
            if persistent {
                ensure!(
                    !["id", "version", "created_at", "deleted_at"].contains(&field.name.as_str()),
                    "platform-managed column"
                );
                ensure!(
                    !matches!(
                        self.kind(field.type_id, models)?,
                        Kind::Cursor | Kind::IdCursor | Kind::PageSize
                    ),
                    "pagination types cannot be persistent model fields"
                );
            }
            ensure!(
                fields
                    .insert(
                        field.name.clone(),
                        if persistent {
                            self.kind(field.type_id, models)?
                        } else {
                            self.input_kind(field.type_id, models)?
                        }
                    )
                    .is_none(),
                "duplicate field"
            );
        }
        let roc_type = (!node.name.starts_with("__")).then(|| node.name.clone());
        if let Some(name) = &roc_type {
            roc_type_name(name)?;
        }
        ensure!(
            !persistent || roc_type.is_some(),
            "models must be nominal records (:=)"
        );
        Ok(Record {
            fields,
            roc_type,
            identity: None,
        })
    }
}

impl Schema {
    pub fn bind_identities(&mut self, registry: &crate::identity::Registry) -> Result<()> {
        registry.validate()?;
        let identities: BTreeMap<_, _> = self
            .models
            .iter()
            .map(|(name, record)| {
                Ok((
                    name.clone(),
                    registry
                        .identity(
                            name,
                            record
                                .roc_type
                                .as_deref()
                                .context("nominal_model_required")?,
                        )?
                        .clone(),
                ))
            })
            .collect::<Result<_>>()?;
        ensure!(
            registry.models.iter().filter(|m| !m.retired).count() == self.models.len(),
            "unbound_model_identity"
        );
        for (name, record) in &mut self.models {
            record.identity = Some(identities[name].clone());
        }
        for record in self.models.values_mut().chain(self.inputs.values_mut()) {
            for kind in record.fields.values_mut() {
                if let Kind::Reference { target } = kind {
                    *kind = Kind::ModelReference {
                        target: target.clone(),
                        prefix: identities[target].prefix.clone(),
                    };
                }
            }
        }
        self.validate_typed()
    }

    pub fn from_checked_types(json: &[u8]) -> Result<Self> {
        let normalized = crate::registry::codec_witnesses(json)?;
        let tables: Vec<Table> = serde_json::from_slice(&normalized)?;
        ensure!(tables.len() == 1, "ambiguous compiler metadata");
        let table = &tables[0];
        let mut model_types = BTreeMap::new();
        for field in &table.root("day2_schema")?.fields {
            let list = table.node(field.type_id)?;
            ensure!(
                list.kind == "list",
                "model registration must be List(record)"
            );
            let model = table.node(list.item)?;
            ensure!(
                model.kind == "record" && !model.name.starts_with("__"),
                "models must be nominal records (:=)"
            );
            roc_type_name(&model.name)?;
            ensure!(
                model_types
                    .insert(model.name.clone(), field.name.clone())
                    .is_none(),
                "one nominal model cannot register as multiple tables"
            );
        }
        let mut models = BTreeMap::new();
        for field in &table.root("day2_schema")?.fields {
            identifier(&field.name)?;
            let list = table.node(field.type_id)?;
            ensure!(
                list.kind == "list",
                "model registration must be List(record)"
            );
            ensure!(
                models
                    .insert(
                        field.name.clone(),
                        table.record(list.item, true, &model_types)?
                    )
                    .is_none(),
                "duplicate model"
            );
        }
        ensure!(
            !models.is_empty() && models.len() <= 32,
            "invalid model count"
        );
        let mut inputs = BTreeMap::new();
        let input_fields = if table
            .entries
            .iter()
            .any(|entry| entry.symbol == "day2_inputs")
        {
            table.root("day2_inputs")?.fields.as_slice()
        } else {
            &[]
        };
        for field in input_fields {
            identifier(&field.name)?;
            ensure!(
                inputs
                    .insert(
                        field.name.clone(),
                        table.record(field.type_id, false, &model_types)?
                    )
                    .is_none(),
                "duplicate input"
            );
        }
        let foreign_keys = models
            .iter()
            .flat_map(|(model, record)| {
                record
                    .fields
                    .iter()
                    .filter_map(move |(field, kind)| match kind {
                        Kind::Reference { target } => Some(ForeignKey {
                            model: model.clone(),
                            field: field.clone(),
                            target: target.clone(),
                        }),
                        _ => None,
                    })
            })
            .collect();
        let indexes = table.indexes(&models, &model_types)?;
        let schema = Self {
            models,
            inputs,
            foreign_keys,
            indexes,
            domains: table.domains()?,
        };
        schema.validate_typed()?;
        Ok(schema)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.indexes.len() <= 128, "index count budget");
        let mut index_names = std::collections::BTreeSet::new();
        let mut sql_index_names = std::collections::BTreeSet::new();
        for index in &self.indexes {
            identifier(&index.model)?;
            identifier(&index.name)?;
            ensure!(
                index_names.insert((&index.model, &index.name)),
                "duplicate index declaration"
            );
            ensure!(
                sql_index_names.insert(format!("{}_{}", index.model, index.name)),
                "generated SQL index name collision"
            );
            let model = self
                .models
                .get(&index.model)
                .context("index references unknown model")?;
            ensure!(
                !index.fields.is_empty() && index.fields.len() <= 8,
                "index field count budget"
            );
            ensure!(
                index.fields.windows(2).all(|pair| pair[0] < pair[1]),
                "index fields must be distinct and sorted"
            );
            for field in &index.fields {
                identifier(field)?;
                ensure!(
                    model.fields.contains_key(field),
                    "index references unknown model field: {}.{field}",
                    index.model
                );
            }
        }
        ensure!(self.domains.len() <= 64, "domain count budget");
        let mut tags = std::collections::BTreeSet::new();
        for (name, domain) in &self.domains {
            identifier(name)?;
            roc_type_name(domain)?;
            ensure!(tags.insert(domain), "duplicate nominal domain definition");
        }
        for record in self.models.values().chain(self.inputs.values()) {
            for kind in record.fields.values() {
                if let Kind::StandardText { domain } = kind {
                    ensure!(
                        tags.contains(domain),
                        "unregistered standard text domain: {domain}"
                    );
                }
            }
        }
        ensure!(
            !self.models.is_empty() && self.models.len() <= 32,
            "invalid models"
        );
        for (name, record) in &self.models {
            identifier(name)?;
            ensure!(
                !record.fields.is_empty() && record.fields.len() <= 32,
                "invalid model field count"
            );
            for field in record.fields.keys() {
                identifier(field)?;
                ensure!(
                    !["id", "version", "created_at", "deleted_at"].contains(&field.as_str()),
                    "reserved field"
                );
                ensure!(
                    !Self::names_secret_material(field),
                    "secret material in a model: {field}"
                );
            }
            ensure!(
                record.fields.values().all(|kind| !matches!(
                    kind,
                    Kind::Cursor | Kind::IdCursor | Kind::PageSize | Kind::InputShape { .. }
                )),
                "pagination and structured input types cannot be persistent model fields"
            );
        }
        let mut model_types = std::collections::BTreeSet::new();
        for record in self.models.values() {
            if let Some(name) = &record.roc_type {
                roc_type_name(name)?;
                ensure!(model_types.insert(name), "duplicate nominal model identity");
            }
        }
        for record in self.models.values().chain(self.inputs.values()) {
            if let Some(name) = &record.roc_type {
                roc_type_name(name)?;
            }
            for kind in record.fields.values() {
                if let Kind::ModelReference { target, prefix } = kind {
                    ensure!(
                        self.models
                            .get(target)
                            .and_then(|record| record.identity.as_ref())
                            .is_some_and(|identity| &identity.prefix == prefix),
                        "reference_prefix_differs_from_model"
                    );
                }
                match kind {
                    Kind::Reference { target } | Kind::ModelReference { target, .. } => ensure!(
                        self.models
                            .get(target)
                            .is_some_and(|r| r.roc_type.is_some()),
                        "unknown reference target"
                    ),
                    Kind::TextDomain { roc_type } => {
                        roc_type_name(roc_type)?;
                    }
                    Kind::InputShape { shape, roc_type } => {
                        crate::input_shape::validate_kind(shape, roc_type)?;
                    }
                    _ => {}
                }
            }
        }
        ensure!(self.inputs.len() <= 128, "invalid input registration count");
        for (name, record) in &self.inputs {
            identifier(name)?;
            ensure!(record.fields.len() <= 32, "too many input fields");
            let mut nodes = 1;
            for (field, kind) in &record.fields {
                identifier(field)?;
                if let Kind::InputShape { shape, .. } = kind {
                    crate::input_shape::validate_schema(shape, 1, &mut nodes)?;
                } else {
                    nodes += 1;
                }
            }
            ensure!(
                nodes <= crate::input_shape::MAX_SCHEMA_NODES,
                "input schema node budget"
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for fk in &self.foreign_keys {
            ensure!(
                self.models.contains_key(&fk.target),
                "unknown foreign key target"
            );
            let kind = self
                .models
                .get(&fk.model)
                .and_then(|m| m.fields.get(&fk.field));
            ensure!(
                kind == Some(&Kind::Integer)
                    || matches!(kind, Some(Kind::ModelReference { target, .. }) if target == &fk.target)
                    || kind
                        == Some(&Kind::Reference {
                            target: fk.target.clone()
                        }),
                "foreign key must match its typed reference"
            );
            ensure!(seen.insert((&fk.model, &fk.field)), "ambiguous foreign key");
        }
        for (model, record) in &self.models {
            for (field, kind) in &record.fields {
                if let Kind::Reference { target } | Kind::ModelReference { target, .. } = kind {
                    ensure!(
                        self.foreign_keys.contains(&ForeignKey {
                            model: model.clone(),
                            field: field.clone(),
                            target: target.clone()
                        }),
                        "missing derived foreign key"
                    );
                }
            }
        }
        let mut handles = std::collections::BTreeSet::new();
        for (input, record) in &self.inputs {
            ensure!(
                handles.insert(input.clone()),
                "generated Inputs name collision"
            );
            for field in record.fields.keys() {
                ensure!(
                    handles.insert(format!("{input}_{field}")),
                    "generated Inputs name collision"
                );
            }
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String> {
        Ok(crate::digest(&serde_json::to_vec(
            &serde_json::json!({"models":self.models,"foreign_keys":self.foreign_keys}),
        )?))
    }
    pub fn validate_typed(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.models.values().all(|record| record.roc_type.is_some()),
            "typed artifacts require nominal models"
        );
        ensure!(
            self.foreign_keys.iter().all(|fk| matches!(
                self.models[&fk.model].fields[&fk.field],
                Kind::Reference { .. } | Kind::ModelReference { .. }
            )),
            "typed artifacts require reference-derived relationships"
        );
        let mut handles = std::collections::BTreeSet::from(["snapshot".to_string()]);
        for (model, record) in &self.models {
            ensure!(
                handles.insert(model.clone()) && handles.insert(format!("all_{model}")),
                "generated Data name collision: {model}"
            );
            for (field, kind) in &record.fields {
                for suffix in ["equal", "asc", "desc"] {
                    ensure!(
                        handles.insert(format!("{model}_{field}_{suffix}")),
                        "generated Data name collision: {model}.{field}"
                    );
                }
                if matches!(
                    kind,
                    Kind::Text
                        | Kind::OptionalText
                        | Kind::TextDomain { .. }
                        | Kind::StandardText { .. }
                        | Kind::WebUrl
                ) {
                    ensure!(
                        handles.insert(format!("{model}_{field}_like")),
                        "generated Data name collision: {model}.{field}"
                    );
                }
                if matches!(kind, Kind::Reference { .. } | Kind::ModelReference { .. }) {
                    ensure!(
                        handles.insert(format!("{model}_by_{field}")),
                        "generated Data name collision: {model}.{field}"
                    );
                }
            }
            for field in ["id", "version", "created_at", "deleted_at"] {
                for suffix in ["equal", "asc", "desc"] {
                    ensure!(
                        handles.insert(format!("{model}_{field}_{suffix}")),
                        "generated Data name collision: {model}.{field}"
                    );
                }
            }
        }
        Ok(())
    }
    /// Whether a field name says it holds secret material.
    ///
    /// Rows are never removed from this platform, so a secret written into one is
    /// a secret that cannot be taken back: soft deletion leaves the value in place,
    /// and the operator retention policy that eventually removes the row is not a
    /// revocation path anyone should rely on. Secret material belongs in the
    /// credential capability, which can be rotated and revoked.
    ///
    /// **This is a name heuristic and cannot be sound.** A field called `notes` can
    /// hold a password and nothing here will notice. It catches the common accident
    /// — a column literally called `api_key` — and is deliberately narrow, because
    /// a check that fires on `token_count` would be turned off within a week.
    fn names_secret_material(field: &str) -> bool {
        let name = field.to_ascii_lowercase();
        // Counts and limits are measurements, not material. LLM token counts are
        // the case that makes a blanket `token` ban unusable.
        if ["_count", "_limit", "_total", "_used", "_remaining"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        {
            return false;
        }
        const EXACT: &[&str] = &[
            "token",
            "secret",
            "password",
            "passwd",
            "credential",
            "credentials",
            "private_key",
            "api_key",
            "apikey",
            "access_key",
            "secret_key",
            "client_secret",
            "access_token",
            "refresh_token",
            "auth_token",
            "bearer_token",
            "session_token",
        ];
        EXACT.contains(&name.as_str())
            || name.ends_with("_secret")
            || name.ends_with("_password")
            || name.ends_with("_api_key")
            || name.ends_with("_private_key")
    }

    pub fn ddl(&self) -> Result<Vec<String>> {
        self.ddl_with_tables(&BTreeMap::new(), true)
    }

    pub(crate) fn ddl_with_tables(
        &self,
        tables: &BTreeMap<String, String>,
        indexes: bool,
    ) -> Result<Vec<String>> {
        self.validate()?;
        let mut statements = Vec::new();
        for (name, record) in &self.models {
            let mut fields = vec![
                if record.identity.is_some() {
                    "id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16)".to_string()
                } else {
                    "id INTEGER PRIMARY KEY CHECK(id > 0)".to_string()
                },
                "version INTEGER NOT NULL CHECK(version > 0)".to_string(),
                "created_at INTEGER NOT NULL".to_string(),
                // Every model is soft-deletable, with no way to opt out.
                //
                // Not a per-model choice, because the choice is the hazard: an
                // author who forgets to ask for it gets a table whose rows can
                // be lost, and nothing about the declaration says so. Universal
                // means a row is never removed by application code anywhere in
                // the fleet, and that "was this deleted?" is always answerable.
                //
                // Zero is live. A timestamp would be ambiguous at the epoch, and
                // a nullable column would make "deleted" and "unknown" the same
                // shape in every query that forgot to handle NULL.
                "deleted_at INTEGER NOT NULL DEFAULT 0 CHECK(deleted_at >= 0)".to_string(),
            ];
            for (field, kind) in &record.fields {
                let mut definition = format!("\"{field}\" {}", kind.ddl()?);
                if *kind == Kind::Boolean {
                    definition.push_str(&format!(" CHECK(\"{field}\" IN (0,1))"));
                }
                if let Kind::Unsigned(unsigned) = kind {
                    if *unsigned == crate::numeric::Unsigned::U64 {
                        definition.push_str(&format!(" CHECK(length(\"{field}\") = 8)"));
                    } else {
                        definition.push_str(&format!(
                            " CHECK(\"{field}\" >= 0 AND \"{field}\" <= {})",
                            unsigned.maximum()
                        ));
                    }
                }
                if *kind == Kind::RowVersion {
                    definition.push_str(&format!(" CHECK(\"{field}\" >= 1)"));
                }
                if matches!(kind, Kind::ModelReference { .. }) {
                    definition.push_str(&format!(" CHECK(length(\"{field}\") = 16)"));
                }
                fields.push(definition);
            }
            for fk in self.foreign_keys.iter().filter(|fk| fk.model == *name) {
                fields.push(format!(
                    "FOREIGN KEY(\"{}\") REFERENCES \"{}\"(id) ON DELETE RESTRICT",
                    fk.field,
                    tables.get(&fk.target).unwrap_or(&fk.target)
                ));
            }
            let table = tables.get(name).unwrap_or(name);
            statements.push(format!(
                "CREATE TABLE \"{table}\" ({}) STRICT",
                fields.join(", ")
            ));
        }
        for fk in self.foreign_keys.iter().filter(|_| indexes) {
            statements.push(format!(
                "CREATE INDEX \"day2_idx_{}_{}\" ON \"{}\"(\"{}\",id)",
                fk.model, fk.field, fk.model, fk.field
            ));
        }
        if indexes {
            for index in &self.indexes {
                statements.push(index.ddl());
            }
        }
        Ok(statements)
    }
}

impl Index {
    pub(crate) fn ddl(&self) -> String {
        let mut fields = self
            .fields
            .iter()
            .map(|field| format!("\"{field}\""))
            .collect::<Vec<_>>();
        if !self.unique {
            fields.push("id".into());
        }
        format!(
            "CREATE {}INDEX \"day2_decl_{}_{}\" ON \"{}\"({})",
            if self.unique { "UNIQUE " } else { "" },
            self.model,
            self.name,
            self.model,
            fields.join(",")
        )
    }
}

impl Kind {
    pub fn ddl(&self) -> Result<&'static str> {
        Ok(match self {
            Self::Unsigned(crate::numeric::Unsigned::U64) | Self::ModelReference { .. } => {
                "BLOB NOT NULL"
            }
            Self::Integer
            | Self::Unsigned(_)
            | Self::RowVersion
            | Self::Boolean
            | Self::Reference { .. }
            | Self::PageSize => "INTEGER NOT NULL",
            Self::Text
            | Self::TextDomain { .. }
            | Self::StandardText { .. }
            | Self::WebUrl
            | Self::Cursor
            | Self::IdCursor => "TEXT NOT NULL",
            Self::OptionalText => "TEXT",
            Self::InputShape { .. } => bail!("structured inputs have no persistent column codec"),
        })
    }
    pub(crate) fn wire_type(&self, input: bool) -> &str {
        match self {
            Self::Integer | Self::PageSize => "I64",
            Self::RowVersion => "U64",
            Self::Unsigned(unsigned) => unsigned.roc_type(),
            Self::Boolean => "Bool",
            Self::Text => "Str",
            Self::OptionalText => "[None, Some(Str)]",
            Self::Reference { .. } => {
                if input {
                    "Str"
                } else {
                    "I64"
                }
            }
            Self::TextDomain { .. }
            | Self::StandardText { .. }
            | Self::WebUrl
            | Self::Cursor
            | Self::IdCursor
            | Self::ModelReference { .. } => "Str",
            Self::InputShape { roc_type, .. } => roc_type,
        }
    }
    pub fn valid(&self, value: &Value) -> bool {
        match self {
            Self::Integer => value.as_i64().is_some(),
            Self::Unsigned(unsigned) => unsigned.valid(value),
            Self::RowVersion => crate::numeric::valid_row_version(value),
            Self::Cursor => value.as_str().is_some_and(|raw| {
                raw.parse::<i64>()
                    .is_ok_and(|number| number >= 0 && number.to_string() == raw)
            }),
            Self::IdCursor => value.as_str().is_some_and(|raw| {
                raw.is_empty()
                    || crate::identity::parse(raw).is_ok()
                    || crate::protocol::valid_selection_cursor(raw)
            }),
            Self::ModelReference { prefix, .. } => value
                .as_str()
                .is_some_and(|raw| crate::identity::valid_for(raw, prefix)),
            Self::PageSize => value
                .as_i64()
                .is_some_and(|number| (1..=100).contains(&number)),
            Self::Text | Self::TextDomain { .. } | Self::StandardText { .. } => {
                value.as_str().is_some_and(|s| s.len() <= 16_384)
            }
            Self::Boolean => value.is_boolean(),
            Self::WebUrl => value.as_str().is_some_and(|s| web_url(s).is_ok()),
            Self::Reference { .. } => value.as_i64().is_some_and(|id| id > 0),
            Self::OptionalText => {
                value == "None"
                    || value.as_object().is_some_and(|o| {
                        o.len() == 1
                            && o.get("Some")
                                .is_some_and(|v| v.as_str().is_some_and(|s| s.len() <= 16_384))
                    })
            }
            Self::InputShape { shape, roc_type } => {
                crate::input_shape::validate_kind(shape, roc_type).is_ok()
                    && crate::input_shape::validate_value(shape, value).is_ok()
            }
        }
    }
}

pub fn web_url(value: &str) -> Result<url::Url> {
    ensure!(
        value.len() <= 2048
            && !value
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '\\'),
        "invalid_url"
    );
    let url = url::Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "invalid_url"
    );
    Ok(url)
}

impl Record {
    pub(crate) fn input_type(&self) -> Result<&str> {
        if let Some(name) = self.roc_type.as_deref() {
            roc_type_name(name)?;
            return Ok(name);
        }
        ensure!(
            self.fields.is_empty() && self.identity.is_none(),
            "registered inputs require nominal types declared with :=; only an empty input may use structural {{}}"
        );
        Ok("{}")
    }

    pub fn validate_value(&self, value: &Value) -> Result<()> {
        self.validate_fields(value, false)
    }
    pub fn validate_input(&self, value: &Value) -> Result<()> {
        self.validate_fields(value, true)
    }
    fn validate_fields(&self, value: &Value, input: bool) -> Result<()> {
        let object = value.as_object().context("input must be a JSON object")?;
        ensure!(
            object.len() == self.fields.len(),
            "missing or unknown fields"
        );
        let mut input_nodes = 1;
        for (name, kind) in &self.fields {
            if let Kind::InputShape { shape, roc_type } = kind {
                ensure!(input, "structured inputs are not persistent fields");
                crate::input_shape::validate_kind(shape, roc_type)?;
                crate::input_shape::validate_at(
                    shape,
                    object
                        .get(name)
                        .with_context(|| format!("missing input field {name}"))?,
                    1,
                    &mut input_nodes,
                )
                .with_context(|| format!("invalid field: {name}"))?;
                continue;
            }
            input_nodes += 1;
            ensure!(
                object.get(name).is_some_and(|v| {
                    if input && matches!(kind, Kind::Reference { .. }) {
                        v.as_str().is_some_and(|raw| {
                            raw.parse::<i64>()
                                .is_ok_and(|id| id > 0 && id.to_string() == raw)
                        })
                    } else {
                        kind.valid(v)
                    }
                }),
                "invalid field: {name}"
            );
        }
        if input {
            ensure!(
                input_nodes <= crate::input_shape::MAX_VALUE_NODES,
                "input value node budget"
            );
            ensure!(
                serde_json::to_vec(value)?.len() <= crate::input_shape::MAX_JSON_BYTES,
                "input byte budget"
            );
        }
        Ok(())
    }
}

pub(crate) fn roc_type_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 128
            && name.split('.').all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }),
        "unsupported qualified Roc type name: {name}"
    );
    Ok(())
}

#[cfg(test)]
mod empty_input_tests {
    use super::*;
    use serde_json::json;

    fn unit() -> Value {
        json!({"kind":"unit", "name":"", "item":0, "ret":0,
            "fields":[], "args":[], "tags":[]})
    }

    fn input(node: Value) -> Result<Record> {
        let table: Table = serde_json::from_value(json!({"entries":[],"types":[node]}))?;
        table.record(0, false, &BTreeMap::new())
    }

    #[test]
    fn empty_operation_input_is_exact_json_object_and_not_a_persistent_model() -> Result<()> {
        let record = input(unit())?;
        assert_eq!(record.input_type()?, "{}");
        assert!(record.roc_type.is_none());
        assert!(record.fields.is_empty());
        record.validate_input(&json!({}))?;
        for invalid in [json!({"unexpected":0}), json!([]), json!(null), json!("")] {
            assert!(record.validate_input(&invalid).is_err());
        }
        let table: Table = serde_json::from_value(json!({"entries":[],"types":[unit()]}))?;
        assert!(table.record(0, true, &BTreeMap::new()).is_err());
        let nonempty = Record {
            fields: BTreeMap::from([("name".into(), Kind::Text)]),
            roc_type: None,
            identity: None,
        };
        assert!(nonempty.input_type().is_err());
        Ok(())
    }

    #[test]
    fn unit_input_rejects_corrupted_reflection_payloads() {
        for (field, value) in [
            ("name", json!("Guessed.Input")),
            ("item", json!(1)),
            ("ret", json!(1)),
            ("args", json!([0])),
            ("tags", json!([{"name":"Some","payload":[]} ])),
            ("fields", json!([{"name":"hidden","type_id":0}])),
        ] {
            let mut node = unit();
            node[field] = value;
            assert!(input(node).is_err(), "unit payload {field}");
        }
    }

    #[test]
    fn empty_input_generates_normal_and_restricted_codecs() -> Result<()> {
        let schema = Schema {
            models: BTreeMap::from([(
                "rows".into(),
                Record {
                    fields: BTreeMap::from([("name".into(), Kind::Text)]),
                    roc_type: Some("Models.Row".into()),
                    identity: None,
                },
            )]),
            inputs: BTreeMap::from([("empty".into(), input(unit())?)]),
            foreign_keys: vec![],
            indexes: vec![],
            domains: BTreeMap::new(),
        };
        let normal = schema.inputs_module()?;
        let restricted = schema.admission_inputs_module()?;
        assert!(normal.contains("empty : Input({  })"));
        assert!(normal.contains("_day2_value = day2_dto.map_err"));
        assert!(normal.contains("|_value| Json.to_str({  })"));
        assert_eq!(
            restricted,
            normal.replace("Input.define(", "Input.admission_define(")
        );
        Ok(())
    }
}

#[cfg(test)]
mod structured_input_tests {
    use super::*;
    use serde_json::json;

    fn node(kind: &str, name: &str) -> Value {
        json!({"kind":kind, "name":name, "item":0, "ret":0,
            "fields":[], "args":[], "tags":[]})
    }

    fn table() -> Result<Table> {
        let mut root = node("record", "UpdateTypes.Input");
        root["fields"] = json!([{"name":"attributes","type_id":1},{"name":"groups","type_id":4}]);
        let mut attributes = node("list", "");
        attributes["item"] = json!(2);
        let mut attribute = node("record", "__AnonStruct_attributes");
        attribute["fields"] = json!([{"name":"key","type_id":3},{"name":"value","type_id":3}]);
        let mut groups = node("list", "");
        groups["item"] = json!(3);
        Ok(serde_json::from_value(
            json!({"entries":[],"types":[root,attributes,attribute,node("text", ""),groups]}),
        )?)
    }

    fn schema(record: Record) -> Schema {
        Schema {
            models: BTreeMap::from([(
                "rows".into(),
                Record {
                    fields: BTreeMap::from([("name".into(), Kind::Text)]),
                    roc_type: Some("Models.Row".into()),
                    identity: None,
                },
            )]),
            inputs: BTreeMap::from([("update".into(), record)]),
            foreign_keys: vec![],
            indexes: vec![],
            domains: BTreeMap::new(),
        }
    }

    #[test]
    fn checked_structured_inputs_generate_typed_codecs_and_json_contracts() -> Result<()> {
        let record = table()?.record(0, false, &BTreeMap::new())?;
        assert_eq!(record.input_type()?, "UpdateTypes.Input");
        assert_eq!(
            record.fields["attributes"].wire_type(true),
            "List({ key : Str, value : Str })"
        );
        let value = json!({"attributes":[{"key":"role","value":"reader"}],"groups":["engineering@example.test"]});
        record.validate_input(&value)?;
        assert!(record.validate_value(&value).is_err());
        let contract = crate::operation_catalog::record_schema(&record);
        assert_eq!(
            contract["properties"]["attributes"]["items"]["properties"]["key"]["type"],
            "string"
        );
        let example = crate::operation_catalog::input_example(&record);
        record.validate_input(&example)?;
        assert!(example["attributes"].is_array());
        let schema = schema(record);
        let normal = schema.inputs_module()?;
        assert!(normal.contains("attributes : List({ key : Str, value : Str })"));
        assert!(normal.contains("attributes = day2_value.attributes"));
        assert!(normal.contains("attributes: value.attributes"));
        assert_eq!(
            schema.admission_inputs_module()?,
            normal
                .replace("Input.define(", "Input.admission_define(")
                .replace("Field.define(", "Field.admission_define(")
        );
        Ok(())
    }

    #[test]
    fn checked_nested_nominals_references_recursion_and_duplicates_fail_closed() -> Result<()> {
        for name in ["Models.Attribute", "Ref", "Text", "Cursor"] {
            let mut table = table()?;
            table.types[2].name = name.into();
            assert!(
                table.record(0, false, &BTreeMap::new()).is_err(),
                "nested {name}"
            );
        }
        let mut recursive = table()?;
        recursive.types[1].item = 1;
        assert!(recursive.record(0, false, &BTreeMap::new()).is_err());
        let mut duplicate = table()?;
        duplicate.types[2].fields[1].name = "key".into();
        assert!(duplicate.record(0, false, &BTreeMap::new()).is_err());
        assert!(table()?.record(0, true, &BTreeMap::new()).is_err());
        Ok(())
    }

    #[test]
    fn native_optional_union_name_is_structural_but_nominal_union_names_are_not() -> Result<()> {
        for (name, accepted) in [("NoneOrSome", true), ("Contracts.Optional", false)] {
            let mut reflected = table()?;
            reflected.types[2].fields.push(Field {
                name: "note".into(),
                type_id: 5,
            });
            let mut optional = node("union", name);
            optional["tags"] = json!([{"name":"None","payload":[]},{"name":"Some","payload":[3]}]);
            reflected.types.push(serde_json::from_value(optional)?);
            assert_eq!(
                reflected.record(0, false, &BTreeMap::new()).is_ok(),
                accepted,
                "optional union {name}"
            );
        }
        Ok(())
    }

    #[test]
    fn serialized_shapes_cannot_inject_roc_types_or_become_model_columns() -> Result<()> {
        let record = table()?.record(0, false, &BTreeMap::new())?;
        let mut schema = schema(record.clone());
        schema
            .models
            .get_mut("rows")
            .unwrap()
            .fields
            .insert("payload".into(), record.fields["attributes"].clone());
        assert!(schema.validate().is_err());
        assert!(schema.ddl().is_err());
        let mut schema = super::structured_input_tests::schema(record);
        if let Kind::InputShape { roc_type, .. } = schema
            .inputs
            .get_mut("update")
            .unwrap()
            .fields
            .get_mut("groups")
            .unwrap()
        {
            *roc_type = "List(Trusted.Bypass)".into();
        }
        assert!(schema.validate_typed().is_err());
        assert!(schema.inputs_module().is_err());
        Ok(())
    }

    #[test]
    fn structured_input_budgets_are_shared_across_fields() -> Result<()> {
        use crate::output_schema::Type;
        let shape = Type::List(Box::new(Type::List(Box::new(Type::Integer))));
        let kind = Kind::InputShape {
            roc_type: shape.annotation(),
            shape,
        };
        let record = Record {
            fields: BTreeMap::from([("left".into(), kind.clone()), ("right".into(), kind)]),
            roc_type: Some("Input.Input".into()),
            identity: None,
        };
        let chunk = json!(vec![vec![0; 100]; 25]);
        assert!(record.fields["left"].valid(&chunk));
        assert!(
            record
                .validate_input(&json!({"left":chunk,"right":chunk}))
                .is_err()
        );
        let mut schema = schema(table()?.record(0, false, &BTreeMap::new())?);
        let shape = Type::Record(
            (0..32)
                .map(|i| (format!("field_{i}"), Type::String))
                .collect(),
        );
        schema.inputs.get_mut("update").unwrap().fields = (0..8)
            .map(|i| {
                (
                    format!("field_{i}"),
                    Kind::InputShape {
                        roc_type: shape.annotation(),
                        shape: shape.clone(),
                    },
                )
            })
            .collect();
        assert!(schema.validate().is_err());
        Ok(())
    }
}

/// The two rules that make "nothing is ever removed" safe to rely on.
///
/// Both are platform invariants rather than app conventions, so both are
/// checked here rather than left to reviewers.
#[cfg(test)]
mod deletion_invariants {
    use super::*;
    use serde_json::json;

    fn schema_with(fields: Value) -> Result<Schema> {
        Ok(serde_json::from_value(json!({
            "models": {"rows": {"roc_type": "Models.Row", "fields": fields}},
            "inputs": {},
            "foreign_keys": [],
        }))?)
    }

    /// **Rule 1: uniqueness spans soft-deleted rows.**
    ///
    /// A declared unique index must keep conflicting with a row that has been
    /// deleted. golinks already depends on this — deleting a link does not
    /// release its name — and the reverse would be worse than inconvenient: a
    /// name freed by deletion can be re-registered by someone else, and
    /// restoring the original would then be impossible or would collide.
    ///
    /// The index is generated without any reference to `deleted_at`, and this
    /// pins that. Adding `WHERE deleted_at = 0` to the generated DDL is the
    /// specific mistake it exists to catch.
    #[test]
    fn a_unique_index_still_covers_rows_that_were_soft_deleted() -> Result<()> {
        let mut schema = schema_with(json!({"name": "text"}))?;
        schema.indexes.push(Index {
            model: "rows".into(),
            name: "by_name".into(),
            fields: vec!["name".into()],
            unique: true,
        });
        let ddl = schema.ddl()?;
        let index = ddl
            .iter()
            .find(|statement| statement.contains("UNIQUE INDEX"))
            .context("a unique index is generated")?;
        assert!(
            !index.to_lowercase().contains("deleted_at"),
            "the unique index is scoped by deletion state, so a deleted row \
             releases its unique value: {index}"
        );
        // And the column exists to be excluded from, so the assertion above is
        // about a real choice rather than a column that does not exist yet.
        assert!(
            ddl.iter().any(|statement| statement.contains("deleted_at")),
            "every table carries deleted_at"
        );
        Ok(())
    }

    /// **Rule 2: secret material never lives in a row.**
    ///
    /// A row is never removed, so a secret written into one cannot be taken
    /// back — soft deletion leaves the value in place, and an operator
    /// retention policy is not a revocation path. Secrets belong in the
    /// credential capability, which rotates and revokes.
    #[test]
    fn a_model_field_that_names_secret_material_is_refused() {
        for field in [
            "token",
            "secret",
            "password",
            "api_key",
            "apikey",
            "private_key",
            "client_secret",
            "access_token",
            "refresh_token",
            "slack_secret",
            "user_password",
            "github_api_key",
        ] {
            assert!(
                schema_with(json!({ field: "text" }))
                    .and_then(|schema| schema.validate())
                    .is_err(),
                "{field} was admitted into a model"
            );
        }
    }

    /// The gate has to stay narrow enough to survive contact with real models.
    ///
    /// A check that fired on `token_count` would be switched off within a week,
    /// and then it would catch nothing at all. LLM token counts are the case
    /// that makes a blanket ban on `token` unusable — pinalysis sums them.
    #[test]
    fn measurements_and_ordinary_fields_are_not_mistaken_for_secrets() -> Result<()> {
        for field in [
            "token_count",
            "tokens_used",
            "input_token_count",
            "secret_count",
            "key",
            "keyword",
            "public_key_fingerprint",
            "name",
            "credential_count",
        ] {
            schema_with(json!({ field: "text" }))?
                .validate()
                .with_context(|| format!("{field} was refused as secret material"))?;
        }
        Ok(())
    }
}
