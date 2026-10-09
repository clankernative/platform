use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_DEPTH: usize = 16;
pub const MAX_LIST_ITEMS: usize = 1_000;
pub const MAX_PAGE_ITEMS: usize = 100;
// Nested envelopes count their outer items as well as their children.
pub const MAX_TOTAL_COLLECTION_ITEMS: usize = 1_024;
pub const MAX_JSON_BYTES: usize = 512 * 1_024;
const MAX_SCHEMA_NODES: usize = 1_024;
const MAX_VALUE_NODES: usize = 16_384;
const MAX_FIELDS: usize = 64;
const MAX_STRING_BYTES: usize = 16 * 1_024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Type {
    String,
    OptionalText,
    StandardText {
        domain: String,
    },
    Integer,
    Unsigned(day2_contracts::numeric::Unsigned),
    RowVersion,
    ModelReference {
        roc_type: String,
        prefix: String,
    },
    Boolean,
    Record(BTreeMap<String, Type>),
    List(Box<Type>),
    /// Keyed collection with unique text keys, canonically ordered by key.
    Map(Box<Type>),
    /// Unique text members, canonically ordered.
    Set,
    CollectionPage(Box<Type>),
    IdPage(Box<Type>),
    Cursor,
    IdCursor,
    PageSize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub shape: Type,
    pub roc_type: String,
}

pub type Catalog = BTreeMap<String, Contract>;

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
struct Node {
    kind: String,
    name: String,
    item: usize,
    fields: Vec<Field>,
    args: Vec<usize>,
    ret: usize,
    #[serde(default)]
    tags: Vec<Tag>,
}
#[derive(Deserialize)]
struct Tag {
    name: String,
    payload: Vec<usize>,
}

impl Table {
    fn node(&self, id: usize) -> Result<&Node> {
        self.types
            .get(id)
            .context("invalid output compiler type reference")
    }

    fn contract(
        &self,
        id: usize,
        active: &mut BTreeSet<usize>,
        nodes: &mut usize,
    ) -> Result<Contract> {
        ensure!(active.len() < MAX_DEPTH, "output schema depth budget");
        ensure!(active.insert(id), "recursive page output type unsupported");
        *nodes += 1;
        ensure!(*nodes <= MAX_SCHEMA_NODES, "output schema node budget");
        let node = self.node(id)?;
        let (shape, roc_type) = match node.kind.as_str() {
            "text" => (Type::String, "Str".into()),
            "integer" => (Type::Integer, "I64".into()),
            "unsigned" => (
                Type::Unsigned(
                    day2_contracts::numeric::Unsigned::from_roc(&node.name)
                        .context("unsupported unsigned integer width")?,
                ),
                node.name.clone(),
            ),
            "boolean" => (Type::Boolean, "Bool".into()),
            "union" => {
                ensure!(
                    node.tags.len() == 2
                        && node.fields.is_empty()
                        && node.args.is_empty()
                        && node.item == 0
                        && node.ret == 0,
                    "unsupported optional output representation"
                );
                ensure!(
                    node.tags
                        .iter()
                        .any(|tag| tag.name == "None" && tag.payload.is_empty()),
                    "optional output requires None without a payload"
                );
                let some = node
                    .tags
                    .iter()
                    .find(|tag| tag.name == "Some" && tag.payload.len() == 1)
                    .context("optional output requires one Some payload")?;
                ensure!(
                    self.node(some.payload[0])?.kind == "text",
                    "only optional text outputs are supported"
                );
                (Type::OptionalText, "[None, Some(Str)]".into())
            }
            "record" if node.name == "Text" => {
                ensure!(node.fields.len() == 2, "invalid text output shape");
                let witness = node
                    .fields
                    .iter()
                    .find(|field| field.name == "witness")
                    .context("text output witness")?;
                let witness = self.node(witness.type_id)?;
                ensure!(
                    witness.kind == "list",
                    "text output witness requires a nominal tag"
                );
                let domain = self.node(witness.item)?.name.clone();
                crate::schema::roc_type_name(&domain)?;
                (
                    Type::StandardText {
                        domain: domain.clone(),
                    },
                    format!("Text({domain})"),
                )
            }
            "record" if node.name == "Ref" => {
                ensure!(node.fields.len() == 2, "invalid output reference");
                let value = node
                    .fields
                    .iter()
                    .find(|field| field.name == "value")
                    .context("invalid output reference")?;
                let witness = node
                    .fields
                    .iter()
                    .find(|field| field.name == "witness")
                    .context("invalid output reference")?;
                let witness = self.node(witness.type_id)?;
                ensure!(
                    self.node(value.type_id)?.kind == "text" && witness.kind == "list",
                    "invalid output reference"
                );
                let target = self.node(witness.item)?;
                crate::schema::roc_type_name(&target.name)?;
                (
                    Type::ModelReference {
                        roc_type: target.name.clone(),
                        prefix: String::new(),
                    },
                    format!("Ref({})", target.name),
                )
            }
            "list" => {
                bail!("API collections require CollectionPage; bare List outputs are forbidden")
            }
            "record" if node.name == "CollectionPage" => {
                ensure!(node.fields.len() == 3, "invalid CollectionPage shape");
                let field = |name: &str| -> Result<&Node> {
                    self.node(
                        node.fields
                            .iter()
                            .find(|field| field.name == name)
                            .context("invalid CollectionPage fields")?
                            .type_id,
                    )
                };
                let items = field("items")?;
                let cursor = field("next_after")?;
                ensure!(
                    items.kind == "list"
                        && field("has_more")?.kind == "boolean"
                        && cursor.kind == "record"
                        && cursor.name == "Cursor"
                        && cursor.fields.len() == 1
                        && cursor.fields[0].name == "value"
                        && matches!(
                            self.node(cursor.fields[0].type_id)?.kind.as_str(),
                            "integer" | "text"
                        ),
                    "invalid CollectionPage shape"
                );
                let item = self.contract(items.item, active, nodes)?;
                (
                    if self.node(cursor.fields[0].type_id)?.kind == "text" {
                        Type::IdPage(Box::new(item.shape))
                    } else {
                        Type::CollectionPage(Box::new(item.shape))
                    },
                    format!("CollectionPage({})", item.roc_type),
                )
            }
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
                (
                    if node.name == "Cursor" {
                        if self.node(node.fields[0].type_id)?.kind == "text" {
                            Type::IdCursor
                        } else {
                            Type::Cursor
                        }
                    } else if node.name == "PageSize" {
                        Type::PageSize
                    } else {
                        Type::RowVersion
                    },
                    node.name.clone(),
                )
            }
            "record" | "unit" => {
                ensure!(node.fields.len() <= MAX_FIELDS, "output field count budget");
                ensure!(
                    node.kind != "unit" || node.fields.is_empty(),
                    "invalid output unit"
                );
                let mut fields = BTreeMap::new();
                let mut annotations = BTreeMap::new();
                for field in &node.fields {
                    day2_contracts::names::identifier(&field.name)?;
                    let contract = self
                        .contract(field.type_id, active, nodes)
                        .with_context(|| format!("output field {}", field.name))?;
                    ensure!(
                        fields.insert(field.name.clone(), contract.shape).is_none(),
                        "duplicate output field"
                    );
                    annotations.insert(field.name.clone(), contract.roc_type);
                }
                let annotation = if node.kind == "record" && !node.name.starts_with("__") {
                    crate::schema::roc_type_name(&node.name)?;
                    node.name.clone()
                } else {
                    let fields = annotations
                        .iter()
                        .map(|(key, ty)| format!("{key} : {ty}"))
                        .collect::<Vec<_>>();
                    format!("{{ {} }}", fields.join(", "))
                };
                (Type::Record(fields), annotation)
            }
            _ => bail!("unsupported page output type: {}", node.kind),
        };
        active.remove(&id);
        Ok(Contract { shape, roc_type })
    }
}

pub fn from_checked_types(bytes: &[u8]) -> Result<Catalog> {
    ensure!(
        bytes.len() <= 4 * 1_024 * 1_024,
        "compiler output metadata byte budget"
    );
    let normalized = crate::registry::codec_witnesses(bytes)?;
    let tables: Vec<Table> = serde_json::from_slice(&normalized)?;
    ensure!(tables.len() <= 16, "compiler output table budget");
    let mut witness = None;
    for table in &tables {
        ensure!(
            table.types.len() <= 4_096 && table.entries.len() <= 512,
            "compiler output graph budget"
        );
        for entry in &table.entries {
            if entry.symbol == "day2_outputs" {
                ensure!(
                    witness.replace((table, entry)).is_none(),
                    "duplicate day2_outputs witness"
                );
            }
        }
    }
    let Some((table, entry)) = witness else {
        ensure!(
            tables.len() == 1
                && tables[0]
                    .entries
                    .iter()
                    .any(|entry| entry.symbol == "day2_schema"),
            "missing checked output/model witnesses"
        );
        return Ok(Catalog::new());
    };
    let function = table.node(entry.type_id)?;
    ensure!(
        function.kind == "function" && function.args.len() == 1 && function.args[0] == function.ret,
        "invalid page output witness"
    );
    let root = table.node(function.ret)?;
    ensure!(
        matches!(root.kind.as_str(), "record" | "unit"),
        "registered outputs must form a record"
    );
    ensure!(root.fields.len() <= 128, "output registration count budget");
    ensure!(
        root.kind != "unit" || root.fields.is_empty(),
        "invalid output registration unit"
    );
    let mut catalog = Catalog::new();
    let mut nodes = 0;
    for field in &root.fields {
        day2_contracts::names::identifier(&field.name)?;
        let contract = table.contract(field.type_id, &mut BTreeSet::new(), &mut nodes)?;
        ensure!(
            catalog.insert(field.name.clone(), contract).is_none(),
            "duplicate registered page output"
        );
    }
    validate_api(&catalog)?;
    Ok(catalog)
}

pub(crate) fn annotation_imports(annotation: &str) -> Result<BTreeSet<&str>> {
    ensure!(
        !annotation.is_empty() && annotation.len() <= 32_768,
        "output type annotation budget"
    );
    ensure!(
        annotation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_ .:{},()[]".contains(&byte)),
        "unsafe output type annotation"
    );
    let mut imports = BTreeSet::new();
    for token in annotation
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .filter(|token| !token.is_empty())
    {
        if token.as_bytes()[0].is_ascii_uppercase() {
            crate::schema::roc_type_name(token)?;
            if ![
                "Str", "I64", "U8", "U16", "U32", "U64", "Bool", "List", "None", "Some",
            ]
            .contains(&token)
            {
                let module = token.split('.').next().context("output module")?;
                ensure!(
                    !["Output", "Outputs", "Json"].contains(&module),
                    "reserved output module"
                );
                imports.insert(module);
            }
        } else {
            day2_contracts::names::identifier(token)?;
        }
    }
    Ok(imports)
}

pub fn validate(catalog: &Catalog) -> Result<()> {
    ensure!(catalog.len() <= 64, "output registration count budget");
    let mut nodes = 0;
    for (name, contract) in catalog {
        day2_contracts::names::identifier(name)?;
        contract.shape.validate_schema(0, &mut nodes)?;
        annotation_imports(&contract.roc_type)?;
    }
    Ok(())
}

/// New API contracts cannot expose an unpaginated collection at any nesting depth.
pub fn validate_api(catalog: &Catalog) -> Result<()> {
    validate(catalog)?;
    for contract in catalog.values() {
        contract.shape.validate_api()?;
    }
    Ok(())
}

pub fn roc_module(catalog: &Catalog) -> Result<String> {
    roc_module_profile(catalog, false)
}

pub(crate) fn admission_roc_module(catalog: &Catalog) -> Result<String> {
    roc_module_profile(catalog, true)
}

fn roc_module_profile(catalog: &Catalog, admission: bool) -> Result<String> {
    validate_api(catalog)?;
    let prefix = if admission { "admission_" } else { "" };
    if catalog.is_empty() {
        return Ok("Outputs :: [].{}\n".into());
    }
    let mut imports = BTreeSet::new();
    for contract in catalog.values() {
        imports.extend(annotation_imports(&contract.roc_type)?);
    }
    let mut source = String::from(
        "import pf.Output\nimport pf.CollectionPage\nimport pf.Cursor\nimport pf.PageSize\nimport pf.Ref\n",
    );
    if catalog
        .values()
        .any(|output| output.shape.has_standard_text())
    {
        source.push_str("import Domains\n");
    }
    if catalog
        .values()
        .any(|contract| contract.shape.uses_row_version())
    {
        source.push_str("import pf.RowVersion\n");
    }
    for module in imports {
        if module == "Ref" {
            continue;
        }
        if module == "Text" {
            source.push_str(&format!("import pf.{module}\n"));
        } else if !["CollectionPage", "Cursor", "PageSize", "RowVersion"].contains(&module) {
            source.push_str(&format!("import {module}\n"));
        }
    }
    source.push_str("\nOutputs :: [].{\n");
    for (name, contract) in catalog {
        let encoded = contract.shape.roc_wire("data", 0);
        let body = format!("Output.{prefix}define(\"{name}\", |data| Json.to_str({encoded}))");
        source.push_str(&format!(
            "    {name} : Output({})\n    {name} = {body}\n",
            contract.roc_type
        ));
        source.push_str(&format!("    decode_{name} : Str -> Try({}, Str)\n    decode_{name} = |raw| {{\n        parsed : Try({}, _)\n        parsed = Json.parse(raw)\n        value = parsed.map_err(|_| \"invalid_verification_output\")?\n        {}\n    }}\n", contract.roc_type, contract.shape.wire_annotation(), contract.shape.roc_decode("value", 0)));
    }
    source.push_str("}\n");
    Ok(source)
}

impl Type {
    fn has_standard_text(&self) -> bool {
        match self {
            Self::StandardText { .. } => true,
            Self::Record(fields) => fields.values().any(Self::has_standard_text),
            Self::List(item) | Self::CollectionPage(item) | Self::IdPage(item) => {
                item.has_standard_text()
            }
            _ => false,
        }
    }
    pub(crate) fn annotation(&self) -> String {
        match self {
            Self::StandardText { domain } => format!("Text({domain})"),
            Self::ModelReference { roc_type, .. } => format!("Ref({roc_type})"),
            Self::RowVersion => "RowVersion".into(),
            Self::IdCursor | Self::Cursor => "Cursor".into(),
            Self::PageSize => "PageSize".into(),
            Self::Record(fields) => format!(
                "{{ {} }}",
                fields
                    .iter()
                    .map(|(key, shape)| format!("{key} : {}", shape.annotation()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::List(item) => format!("List({})", item.annotation()),
            Self::Map(value) => format!("TextMap({})", value.annotation()),
            Self::Set => "TextSet".into(),
            Self::IdPage(item) | Self::CollectionPage(item) => {
                format!("CollectionPage({})", item.annotation())
            }
            _ => self.wire_annotation(),
        }
    }

    pub(crate) fn wire_annotation(&self) -> String {
        match self {
            Self::OptionalText => "[None, Some(Str)]".into(),
            Self::String
            | Self::StandardText { .. }
            | Self::ModelReference { .. }
            | Self::Cursor
            | Self::IdCursor => "Str".into(),
            Self::Integer | Self::PageSize => "I64".into(),
            Self::Map(value) => format!(
                "{{ entries : List({{ key : Str, value : {} }}) }}",
                value.wire_annotation()
            ),
            Self::Set => "{ members : List(Str) }".into(),
            Self::Unsigned(width) => width.roc_type().into(),
            Self::RowVersion => "U64".into(),
            Self::Boolean => "Bool".into(),
            Self::Record(fields) => format!(
                "{{ {} }}",
                fields
                    .iter()
                    .map(|(key, shape)| format!("{key} : {}", shape.wire_annotation()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::List(item) => format!("List({})", item.wire_annotation()),
            Self::IdPage(item) | Self::CollectionPage(item) => format!(
                "{{ items : List({}), has_more : Bool, next_after : Str }}",
                item.wire_annotation()
            ),
        }
    }

    fn roc_decode(&self, expression: &str, depth: usize) -> String {
        match self {
            Self::StandardText { domain } => {
                format!("Domains.{}({expression})", crate::domain::decoder(domain))
            }
            Self::ModelReference { prefix, .. } => format!(
                "Ref.for_model(\"{prefix}\", {expression}).map_err(|_| \"invalid_reference\")"
            ),
            Self::RowVersion => {
                format!("RowVersion.from_u64({expression}).map_err(|_| \"invalid_row_version\")")
            }
            Self::Cursor | Self::IdCursor => {
                format!("Cursor.from_str({expression}).map_err(|_| \"invalid_cursor\")")
            }
            Self::PageSize => {
                format!("PageSize.from_i64({expression}).map_err(|_| \"invalid_page_size\")")
            }
            Self::Record(fields) => format!(
                "Ok({{ {} }})",
                fields
                    .iter()
                    .map(|(key, field)| format!(
                        "{key}: ({})?",
                        field.roc_decode(&format!("{expression}.{key}"), depth + 1)
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::List(item) => format!(
                "{expression}.map_try(|item_{depth}| {})",
                item.roc_decode(&format!("item_{depth}"), depth + 1)
            ),
            Self::IdPage(item) | Self::CollectionPage(item) => format!(
                "CollectionPage.from_parts({expression}.items.map_try(|item_{depth}| {})?, {expression}.has_more, Cursor.from_str({expression}.next_after).map_err(|_| \"invalid_cursor\")?)",
                item.roc_decode(&format!("item_{depth}"), depth + 1)
            ),
            _ => format!("Ok({expression})"),
        }
    }

    pub fn bind_identities(&mut self, schema: &crate::schema::Schema) -> Result<()> {
        match self {
            Self::ModelReference { roc_type, prefix } => {
                *prefix = schema
                    .models
                    .values()
                    .find(|record| record.roc_type.as_ref() == Some(roc_type))
                    .and_then(|record| record.identity.as_ref())
                    .context("unregistered_output_reference")?
                    .prefix
                    .clone();
            }
            Self::Record(fields) => {
                for field in fields.values_mut() {
                    field.bind_identities(schema)?;
                }
            }
            Self::IdPage(item) | Self::CollectionPage(item) | Self::List(item) => {
                item.bind_identities(schema)?
            }
            _ => (),
        }
        Ok(())
    }
    pub(crate) fn uses_row_version(&self) -> bool {
        match self {
            Self::RowVersion => true,
            Self::Record(fields) => fields.values().any(Self::uses_row_version),
            Self::IdPage(item) | Self::CollectionPage(item) | Self::List(item) => {
                item.uses_row_version()
            }
            _ => false,
        }
    }

    /// Whether a nominal collection appears anywhere in this shape, so generated
    /// code can import exactly the modules its decoders construct.
    pub fn mentions_map(&self) -> bool {
        match self {
            Self::Map(_) => true,
            Self::Record(fields) => fields.values().any(Self::mentions_map),
            Self::List(item) | Self::IdPage(item) | Self::CollectionPage(item) => {
                item.mentions_map()
            }
            _ => false,
        }
    }

    pub fn mentions_set(&self) -> bool {
        match self {
            Self::Set => true,
            Self::Record(fields) => fields.values().any(Self::mentions_set),
            Self::List(item) | Self::IdPage(item) | Self::CollectionPage(item) => {
                item.mentions_set()
            }
            Self::Map(value) => value.mentions_set(),
            _ => false,
        }
    }

    pub fn validate_api(&self) -> Result<()> {
        match self {
            Self::List(_) => {
                bail!("API collections require CollectionPage; bare List outputs are forbidden")
            }
            Self::IdPage(item) | Self::CollectionPage(item) => item.validate_api()?,
            Self::Record(fields) => {
                for field in fields.values() {
                    field.validate_api()?;
                }
            }
            _ => (),
        }
        Ok(())
    }

    /// Templates see the checked wire envelope, never the opaque Roc representation.
    pub fn template_shape(&self) -> Self {
        match self {
            Self::IdPage(item) | Self::CollectionPage(item) => Self::Record(BTreeMap::from([
                ("items".into(), Self::List(Box::new(item.template_shape()))),
                ("has_more".into(), Self::Boolean),
                ("next_after".into(), Self::String),
            ])),
            Self::ModelReference { prefix, .. } => Self::ModelReference {
                roc_type: String::new(),
                prefix: prefix.clone(),
            },
            Self::IdCursor | Self::Cursor => Self::String,
            Self::PageSize | Self::Unsigned(_) => Self::Integer,
            Self::Record(fields) => Self::Record(
                fields
                    .iter()
                    .map(|(name, field)| (name.clone(), field.template_shape()))
                    .collect(),
            ),
            Self::List(item) => Self::List(Box::new(item.template_shape())),
            _ => self.clone(),
        }
    }

    fn roc_wire(&self, expression: &str, depth: usize) -> String {
        match self {
            Self::StandardText { .. } => format!("{expression}.to_str()"),
            Self::IdPage(item) | Self::CollectionPage(item) => {
                let variable = format!("day2_item_{depth}");
                format!(
                    "{{ items: CollectionPage.items({expression}).map(|{variable}| {}), has_more: CollectionPage.has_more({expression}), next_after: Cursor.to_str(CollectionPage.next_after({expression})) }}",
                    item.roc_wire(&variable, depth + 1)
                )
            }
            Self::IdCursor | Self::Cursor => format!("Cursor.to_str({expression})"),
            Self::ModelReference { .. } => format!("({expression}).to_str()"),
            Self::PageSize => format!("PageSize.to_i64({expression})"),
            Self::RowVersion => format!("RowVersion.to_u64({expression})"),
            Self::Record(fields) => format!(
                "{{ {} }}",
                fields
                    .iter()
                    .map(|(name, field)| format!(
                        "{name}: {}",
                        field.roc_wire(&format!("{expression}.{name}"), depth + 1)
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => expression.into(),
        }
    }
    fn validate_schema(&self, depth: usize, nodes: &mut usize) -> Result<()> {
        ensure!(depth < MAX_DEPTH, "output schema depth budget");
        *nodes += 1;
        ensure!(*nodes <= MAX_SCHEMA_NODES, "output schema node budget");
        match self {
            Self::Record(fields) => {
                ensure!(fields.len() <= MAX_FIELDS, "output field count budget");
                for (name, field) in fields {
                    day2_contracts::names::identifier(name)?;
                    field.validate_schema(depth + 1, nodes)?;
                }
            }
            Self::IdPage(item) | Self::List(item) | Self::CollectionPage(item) => {
                item.validate_schema(depth + 1, nodes)?
            }
            Self::Map(value) => value.validate_schema(depth + 1, nodes)?,
            Self::Set => {}
            Self::String
            | Self::OptionalText
            | Self::StandardText { .. }
            | Self::Integer
            | Self::Unsigned(_)
            | Self::RowVersion
            | Self::Boolean
            | Self::Cursor
            | Self::IdCursor
            | Self::ModelReference { .. }
            | Self::PageSize => (),
        }
        Ok(())
    }

    pub fn validate_value(&self, value: &Value) -> Result<()> {
        self.validate_schema(0, &mut 0)?;
        self.validate_at(value, 0, &mut 0, &mut 0)?;
        ensure!(
            serde_json::to_vec(value)?.len() <= MAX_JSON_BYTES,
            "page output byte budget"
        );
        Ok(())
    }

    fn validate_at(
        &self,
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        collection_items: &mut usize,
    ) -> Result<()> {
        ensure!(depth < MAX_DEPTH, "page output depth budget");
        *nodes += 1;
        ensure!(*nodes <= MAX_VALUE_NODES, "page output node budget");
        match self {
            Self::OptionalText => {
                if value != "None" {
                    let object = value.as_object().context("expected optional text output")?;
                    ensure!(
                        object.len() == 1,
                        "optional text output requires one Some field"
                    );
                    Self::String.validate_at(
                        object
                            .get("Some")
                            .context("optional text output requires Some")?,
                        depth + 1,
                        nodes,
                        collection_items,
                    )?;
                }
            }
            Self::String | Self::StandardText { .. } => ensure!(
                value
                    .as_str()
                    .is_some_and(|text| text.len() <= MAX_STRING_BYTES),
                "expected bounded output string"
            ),
            Self::Integer => ensure!(value.as_i64().is_some(), "expected i64 page output"),
            Self::Unsigned(unsigned) => ensure!(unsigned.valid(value), "invalid unsigned output"),
            Self::RowVersion => ensure!(
                day2_contracts::numeric::valid_row_version(value),
                "invalid row version output"
            ),
            Self::Boolean => ensure!(value.is_boolean(), "expected boolean page output"),
            Self::Cursor => ensure!(
                crate::schema::Kind::Cursor.valid(value),
                "invalid output cursor"
            ),
            Self::IdCursor => ensure!(
                crate::schema::Kind::IdCursor.valid(value),
                "invalid output cursor"
            ),
            Self::ModelReference { prefix, .. } => ensure!(
                value
                    .as_str()
                    .is_some_and(|raw| crate::identity::valid_for(raw, prefix)),
                "invalid output reference"
            ),
            Self::PageSize => ensure!(
                crate::schema::Kind::PageSize.valid(value),
                "invalid output page size"
            ),
            Self::IdPage(item) | Self::CollectionPage(item) => {
                let record = value
                    .as_object()
                    .context("expected collection page envelope")?;
                ensure!(
                    record.len() == 3,
                    "collection page envelope fields mismatch"
                );
                let items = record
                    .get("items")
                    .and_then(Value::as_array)
                    .context("collection page items missing")?;
                let more = record
                    .get("has_more")
                    .and_then(Value::as_bool)
                    .context("collection page has_more missing")?;
                let cursor = record
                    .get("next_after")
                    .context("collection page cursor missing")?;
                ensure!(
                    if matches!(self, Self::IdPage(_)) {
                        crate::schema::Kind::IdCursor.valid(cursor)
                    } else {
                        crate::schema::Kind::Cursor.valid(cursor)
                    },
                    "invalid collection page cursor"
                );
                ensure!(
                    items.len() <= MAX_PAGE_ITEMS,
                    "collection page item budget exceeded"
                );
                *collection_items += items.len();
                ensure!(
                    *collection_items <= MAX_TOTAL_COLLECTION_ITEMS,
                    "total collection item budget exceeded"
                );
                ensure!(
                    !more || (!items.is_empty() && cursor != "0" && cursor != ""),
                    "invalid collection page continuation"
                );
                for (index, value) in items.iter().enumerate() {
                    item.validate_at(value, depth + 1, nodes, collection_items)
                        .with_context(|| format!("collection page item {index}"))?;
                }
            }
            Self::Record(fields) => {
                let record = value.as_object().context("expected page output record")?;
                ensure!(record.len() == fields.len(), "page output field mismatch");
                for (name, ty) in fields {
                    ty.validate_at(
                        record
                            .get(name)
                            .with_context(|| format!("missing page output field {name}"))?,
                        depth + 1,
                        nodes,
                        collection_items,
                    )
                    .with_context(|| format!("output field {name}"))?;
                }
            }
            Self::List(item) => {
                let items = value.as_array().context("expected page output list")?;
                ensure!(items.len() <= MAX_LIST_ITEMS, "page output list budget");
                for (index, value) in items.iter().enumerate() {
                    item.validate_at(value, depth + 1, nodes, collection_items)
                        .with_context(|| format!("output item {index}"))?;
                }
            }
            // The nominal wrappers travel as their structural payload. Uniqueness
            // and canonical order are constructor invariants, so they are checked
            // here rather than assumed.
            Self::Map(item) => {
                let entries = nominal_entries(value, "entries", "map")?;
                ensure!(entries.len() <= MAX_LIST_ITEMS, "map entry budget");
                let mut keys: Vec<&str> = Vec::with_capacity(entries.len());
                for (index, entry) in entries.iter().enumerate() {
                    let object = entry.as_object().context("expected map entry")?;
                    ensure!(object.len() == 2, "map entry requires key and value");
                    let key = object
                        .get("key")
                        .and_then(serde_json::Value::as_str)
                        .context("map entry key missing")?;
                    ensure!(!key.trim().is_empty(), "map key must not be blank");
                    ensure!(!keys.contains(&key), "map keys must be unique");
                    ensure!(
                        keys.last().is_none_or(|last| *last < key),
                        "map entries must be ordered by key"
                    );
                    keys.push(key);
                    item.validate_at(
                        object.get("value").context("map entry value missing")?,
                        depth + 1,
                        nodes,
                        collection_items,
                    )
                    .with_context(|| format!("map entry {index}"))?;
                }
            }
            Self::Set => {
                let members = nominal_entries(value, "members", "set")?;
                ensure!(members.len() <= MAX_LIST_ITEMS, "set member budget");
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
        }
        Ok(())
    }
}

/// The single payload list a nominal collection wrapper carries on the wire.
fn nominal_entries<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<&'a Vec<serde_json::Value>> {
    let object = value
        .as_object()
        .with_context(|| format!("expected {label} output"))?;
    ensure!(
        object.len() == 1,
        "{label} output requires one {field} field"
    );
    object
        .get(field)
        .and_then(serde_json::Value::as_array)
        .with_context(|| format!("{label} output requires {field} list"))
}
