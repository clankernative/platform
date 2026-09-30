use crate::{artifact::Artifact, output_schema, schema::Schema};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unified: bool,
    pub commands: BTreeMap<String, Operation>,
    pub queries: BTreeMap<String, Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schedules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub input: String,
    pub output: String,
}

pub fn entrypoint(admission: bool) -> String {
    let method = if admission { "admission_step" } else { "step" };
    format!(
        "app [step] {{ pf: platform \"../sdk/main.roc\" }}\nimport Registry\nimport App\nstep : Str -> Str\nstep = |raw| Registry.{method}(App.definition, raw)\n"
    )
}

#[derive(Deserialize, Serialize)]
struct Table {
    entries: Vec<Entry>,
    types: Vec<Node>,
}
#[derive(Deserialize, Serialize)]
struct Entry {
    symbol: String,
    type_id: usize,
}
#[derive(Deserialize, Serialize)]
struct Field {
    name: String,
    type_id: usize,
}
#[derive(Deserialize, Serialize)]
struct Tag {
    name: String,
    payload: Vec<usize>,
}
#[derive(Deserialize, Serialize)]
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

fn checked_tables(bytes: &[u8]) -> Result<(Vec<Table>, bool)> {
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "compiler metadata byte budget"
    );
    let mut tables: Vec<Table> = serde_json::from_slice(bytes)?;
    ensure!(tables.len() <= 16, "compiler metadata table budget");
    let mut normalized = false;
    for table in &mut tables {
        ensure!(
            table.types.len() <= 4096 && table.entries.len() <= 512,
            "compiler metadata graph budget"
        );
        normalized |= table.normalize_boxes()?;
    }
    Ok((tables, normalized))
}

impl Table {
    // RocBox is a compiler layout indirection, not a new domain type. Rewrite
    // graph edges to the original payload IDs so every structural reader shares
    // the same identity and recursion checks; ABI generation keeps the raw graph.
    fn normalize_boxes(&mut self) -> Result<bool> {
        if !self.types.iter().any(|node| node.kind == "box") {
            return Ok(false);
        }
        let mut resolved = self
            .types
            .iter()
            .enumerate()
            .map(|(id, node)| (node.kind != "box").then_some(id))
            .collect::<Vec<_>>();
        let mut visiting = vec![false; self.types.len()];
        for start in 0..self.types.len() {
            let mut path = Vec::new();
            let mut current = start;
            let payload = loop {
                if let Some(payload) = *resolved
                    .get(current)
                    .context("invalid boxed compiler type reference")?
                {
                    break payload;
                }
                ensure!(!visiting[current], "cyclic compiler box chain");
                visiting[current] = true;
                let node = &self.types[current];
                ensure!(
                    node.name.is_empty()
                        && node.fields.is_empty()
                        && node.args.is_empty()
                        && node.ret == 0
                        && node.tags.is_empty(),
                    "box metadata must contain only its payload reference"
                );
                path.push(current);
                current = node.item;
            };
            for id in path {
                resolved[id] = Some(payload);
            }
        }
        let canonical = |id: usize| -> Result<usize> {
            resolved
                .get(id)
                .copied()
                .flatten()
                .context("invalid compiler type reference")
        };
        for entry in &mut self.entries {
            entry.type_id = canonical(entry.type_id)?;
        }
        for node in &mut self.types {
            for field in &mut node.fields {
                field.type_id = canonical(field.type_id)?;
            }
            for arg in &mut node.args {
                *arg = canonical(*arg)?;
            }
            for tag in &mut node.tags {
                for payload in &mut tag.payload {
                    *payload = canonical(*payload)?;
                }
            }
            if node.kind == "function" {
                node.ret = canonical(node.ret)?;
            }
            if matches!(node.kind.as_str(), "list" | "box") {
                node.item = canonical(node.item)?;
            }
        }
        Ok(true)
    }

    fn entry(&self, symbol: &str) -> Result<&Node> {
        let entries = self
            .entries
            .iter()
            .filter(|entry| entry.symbol == symbol)
            .collect::<Vec<_>>();
        ensure!(entries.len() == 1, "missing or duplicated {symbol} witness");
        self.node(entries[0].type_id)
    }

    fn identity(&self, symbol: &str) -> Result<usize> {
        let function = self.entry(symbol)?;
        ensure!(
            function.kind == "function"
                && function.args.len() == 1
                && function.args[0] == function.ret,
            "invalid {symbol} identity witness"
        );
        self.node(function.ret)?;
        Ok(function.ret)
    }

    fn node(&self, id: usize) -> Result<&Node> {
        self.types
            .get(id)
            .context("invalid registry type reference")
    }
    fn fields(&self, symbol: &str) -> Result<&[Field]> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| entry.symbol == symbol)
            .collect();
        ensure!(
            entries.len() == 1,
            "missing or duplicated {symbol} declaration"
        );
        let function = self.node(entries[0].type_id)?;
        ensure!(
            function.kind == "function"
                && function.args.len() == 1
                && function.args[0] == function.ret,
            "invalid {symbol} witness"
        );
        let record = self.node(function.ret)?;
        ensure!(
            matches!(record.kind.as_str(), "record" | "unit") && record.fields.len() <= 128,
            "invalid declaration record"
        );
        Ok(&record.fields)
    }
    fn witness_type(&self, node: &Node, name: &str) -> Result<&Node> {
        let fields: Vec<_> = node
            .fields
            .iter()
            .filter(|field| field.name == name)
            .collect();
        ensure!(fields.len() == 1, "missing typed handle witness");
        self.node(fields[0].type_id)
    }
    fn witness(&self, node: &Node, name: &str) -> Result<usize> {
        let list = self.witness_type(node, name)?;
        ensure!(list.kind == "list", "invalid typed handle witness");
        Ok(list.item)
    }
    fn registered(&self, fields: &[Field], ty: usize, models: bool) -> Result<String> {
        let mut matches = Vec::new();
        for field in fields {
            let registered = if models {
                self.node(field.type_id)?.item
            } else {
                field.type_id
            };
            if self.same_type(registered, ty, &mut BTreeSet::new())? {
                matches.push(field.name.clone());
            }
        }
        ensure!(
            matches.len() == 1,
            "registry type must have exactly one registered codec/model"
        );
        Ok(matches[0].clone())
    }

    // The compiler repeats equivalent nodes across monomorphized witnesses.
    // Compare the checked graph, retaining nominal names and recursive edges.
    fn same_type(
        &self,
        left: usize,
        right: usize,
        seen: &mut BTreeSet<(usize, usize)>,
    ) -> Result<bool> {
        let a = self.node(left)?;
        let b = self.node(right)?;
        if a.kind != b.kind || a.name != b.name {
            return Ok(false);
        }
        ensure!(seen.len() <= 4096, "registry equivalence budget");
        if !seen.insert((left, right)) {
            return Ok(true);
        }
        match a.kind.as_str() {
            "integer" | "text" | "boolean" | "unit" => Ok(true),
            "unsigned" => {
                ensure!(
                    crate::numeric::Unsigned::from_roc(&a.name).is_some(),
                    "unsupported unsigned declaration width"
                );
                Ok(true)
            }
            "list" => self.same_type(a.item, b.item, seen),
            "record" => {
                if a.fields.len() != b.fields.len() {
                    return Ok(false);
                }
                for field in &a.fields {
                    let matches: Vec<_> = b
                        .fields
                        .iter()
                        .filter(|other| other.name == field.name)
                        .collect();
                    if matches.len() != 1
                        || !self.same_type(field.type_id, matches[0].type_id, seen)?
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            "union" => {
                for node in [a, b] {
                    let none = node.tags.iter().find(|tag| tag.name == "None");
                    let some = node.tags.iter().find(|tag| tag.name == "Some");
                    ensure!(
                        node.tags.len() == 2
                            && none.is_some_and(|tag| tag.payload.is_empty())
                            && some.is_some_and(|tag| tag.payload.len() == 1),
                        "unsupported declaration tag union"
                    );
                    ensure!(
                        self.node(some.context("optional payload")?.payload[0])?
                            .kind
                            == "text",
                        "only optional text supported in declaration codecs"
                    );
                }
                let left = a
                    .tags
                    .iter()
                    .find(|tag| tag.name == "Some")
                    .context("optional payload")?;
                let right = b
                    .tags
                    .iter()
                    .find(|tag| tag.name == "Some")
                    .context("optional payload")?;
                self.same_type(left.payload[0], right.payload[0], seen)
            }
            _ => anyhow::bail!(
                "unsupported declaration codec shape: {} ({})",
                a.kind,
                a.name
            ),
        }
    }
}

pub fn from_checked_types(bytes: &[u8]) -> Result<Catalog> {
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "registry compiler metadata budget"
    );
    let normalized = codec_witnesses(bytes)?;
    let tables: Vec<Table> = serde_json::from_slice(&normalized)?;
    if tables
        .iter()
        .any(|table| table.entries.iter().any(|entry| entry.symbol == "day2_app"))
    {
        return inferred_catalog(app_table(&tables)?);
    }
    let tables: Vec<_> = tables
        .iter()
        .filter(|table| {
            table
                .entries
                .iter()
                .any(|entry| entry.symbol == "day2_commands")
        })
        .collect();
    ensure!(
        tables.len() == 1,
        "one checked declaration catalog required"
    );
    let table = tables[0];
    ensure!(
        table.types.len() <= 4096 && table.entries.len() <= 128,
        "registry graph budget"
    );
    let inputs = table.fields("day2_inputs")?;
    let outputs = table.fields("day2_outputs")?;
    let mut catalog = Catalog::default();
    let mut names = BTreeSet::new();
    for (symbol, expected, target) in [
        (
            "day2_commands",
            "Declaration.Command",
            &mut catalog.commands,
        ),
        ("day2_queries", "Declaration.Query", &mut catalog.queries),
    ] {
        for field in table.fields(symbol)? {
            crate::schema::identifier(&field.name)?;
            ensure!(
                names.insert(field.name.clone()),
                "command/query names must not conflict"
            );
            let handle = table.node(field.type_id)?;
            ensure!(
                handle.kind == "record" && handle.name == expected,
                "registry category requires {expected} handles"
            );
            let input = table.registered(inputs, table.witness(handle, "input_witness")?, false)?;
            let output =
                table.registered(outputs, table.witness(handle, "output_witness")?, false)?;
            ensure!(
                target
                    .insert(field.name.clone(), Operation { input, output })
                    .is_none(),
                "duplicate declaration"
            );
        }
    }
    ensure!(
        catalog.commands.len() + catalog.queries.len() <= 128,
        "declaration count budget"
    );
    Ok(catalog)
}

/// Synthesize codec inventories from compiler-proven callback witnesses. These
/// records are a deterministic projection, never additional compiler evidence.
/// Artifact loading repeats this projection from the retained original bytes.
pub fn codec_witnesses(bytes: &[u8]) -> Result<Vec<u8>> {
    let (mut tables, normalized) = checked_tables(bytes)?;
    let unchanged = |tables: &[Table]| -> Result<Vec<u8>> {
        if normalized {
            Ok(serde_json::to_vec(tables)?)
        } else {
            Ok(bytes.to_vec())
        }
    };
    if tables.len() != 1
        || !tables[0]
            .entries
            .iter()
            .any(|entry| entry.symbol == "day2_app")
    {
        return unchanged(&tables);
    }
    let table = &mut tables[0];
    if table
        .entries
        .iter()
        .any(|entry| entry.symbol == "day2_inputs")
    {
        return unchanged(&tables);
    }
    let shape = AppShape::from_table(table)?;
    if !shape.unified {
        return unchanged(&tables);
    }
    let product = table.node(table.entry("day2_app")?.ret)?;
    let mut derived = Vec::new();
    for (symbol, helper, callback) in shape.witnesses() {
        let (_category, role) = helper.split_once('_').context("witness role")?;
        let group = "operations";
        let name = callback.rsplit('.').next().context("witness operation")?;
        let group = product
            .fields
            .iter()
            .find(|field| field.name == group)
            .context("witness group")?;
        let field = table
            .node(group.type_id)?
            .fields
            .iter()
            .find(|field| field.name == name)
            .context("witness operation missing")?;
        let definition = table.node(field.type_id)?;
        let witness_name = format!("{role}_witness");
        let has_nested_witness = definition
            .fields
            .iter()
            .any(|field| field.name == witness_name);
        let function_witness = !has_nested_witness
            || table.witness_type(definition, &witness_name)?.kind == "function";
        if function_witness {
            // Native glue erases nested closure signatures. A generated exported
            // identity function is checked against this exact registered definition,
            // forcing its input/output type into compiler evidence.
            table.identity(&symbol)?;
        } else {
            // Older command/query handles retain List witnesses.
            let id = table.witness(definition, &witness_name)?;
            if table.entries.iter().any(|entry| entry.symbol == symbol) {
                ensure!(
                    table.same_type(id, table.identity(&symbol)?, &mut BTreeSet::new())?,
                    "callback and definition witnesses disagree"
                );
            } else {
                derived.push((symbol, id));
            }
        }
    }
    for (symbol, id) in derived {
        let type_id = table.types.len();
        table.types.push(Node {
            kind: "function".into(),
            name: String::new(),
            item: 0,
            fields: vec![],
            args: vec![id],
            ret: id,
            tags: vec![],
        });
        table.entries.push(Entry { symbol, type_id });
    }
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for (symbol, _, _) in shape.witnesses() {
        let target = if symbol.starts_with("day2_command_output_")
            || symbol.starts_with("day2_query_output_")
        {
            &mut outputs
        } else {
            &mut inputs
        };
        let id = table.identity(&symbol)?;
        let mut found = false;
        for other in target.iter() {
            if table.same_type(*other, id, &mut BTreeSet::new())? {
                found = true;
                break;
            }
        }
        if !found {
            target.push(id);
        }
    }
    for (symbol, prefix, types) in [
        ("day2_inputs", "input", inputs),
        ("day2_outputs", "output", outputs),
    ] {
        let root = table.types.len();
        table.types.push(Node {
            kind: "record".into(),
            name: String::new(),
            item: 0,
            fields: types
                .into_iter()
                .enumerate()
                .map(|(index, type_id)| Field {
                    name: format!("{prefix}_{index}"),
                    type_id,
                })
                .collect(),
            args: vec![],
            ret: 0,
            tags: vec![],
        });
        let function = table.types.len();
        table.types.push(Node {
            kind: "function".into(),
            name: String::new(),
            item: 0,
            fields: vec![],
            args: vec![root],
            ret: root,
            tags: vec![],
        });
        table.entries.push(Entry {
            symbol: symbol.into(),
            type_id: function,
        });
    }
    Ok(serde_json::to_vec(&tables)?)
}

/// Names come from the compiler's checked App.definition record, never source text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppShape {
    pub unified: bool,
    pub commands: Vec<String>,
    pub queries: Vec<String>,
    pub pages: Vec<String>,
    pub properties: Vec<String>,
    pub errors: Vec<String>,
    pub schedules: Vec<String>,
    pub ingress: Vec<String>,
    pub redirects: Vec<String>,
    pub credentials: BTreeMap<String, String>,
}

fn app_table(tables: &[Table]) -> Result<&Table> {
    let matching = tables
        .iter()
        .filter(|table| table.entries.iter().any(|entry| entry.symbol == "day2_app"))
        .collect::<Vec<_>>();
    ensure!(matching.len() == 1, "one checked App.definition required");
    let table = matching[0];
    ensure!(
        table.types.len() <= 4096 && table.entries.len() <= 512,
        "app reflection budget"
    );
    Ok(table)
}

impl AppShape {
    pub fn from_checked_types(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 4 * 1024 * 1024, "app reflection byte budget");
        let (tables, _) = checked_tables(bytes)?;
        Self::from_table(app_table(&tables)?)
    }

    fn from_table(table: &Table) -> Result<Self> {
        let function = table.entry("day2_app")?;
        ensure!(
            function.kind == "function" && function.args.len() == 1,
            "invalid App.definition witness"
        );
        let product = table.node(function.ret)?;
        let unified = product
            .fields
            .iter()
            .any(|field| field.name == "operations");
        let expected = if unified {
            BTreeSet::from(["namespace", "operations", "pages", "properties", "errors"])
        } else {
            BTreeSet::from(["namespace", "commands", "queries"])
        };
        let declared = product
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<BTreeSet<_>>();
        // `schedules` is optional: an application that declares none omits the
        // field entirely, so existing applications keep their exact shape.
        let optional = if unified {
            BTreeSet::from(["schedules", "ingress", "redirects", "credentials"])
        } else {
            BTreeSet::new()
        };
        ensure!(
            product.kind == "record"
                && product.fields.len() == declared.len()
                && expected.is_subset(&declared)
                && declared
                    .iter()
                    .all(|name| expected.contains(name) || optional.contains(name)),
            "App.definition requires namespace and complete command/query operations"
        );
        let category = |name: &str| -> Result<Vec<String>> {
            let field = product
                .fields
                .iter()
                .find(|field| field.name == name)
                .context("app category missing")?;
            let record = table.node(field.type_id)?;
            ensure!(
                matches!(record.kind.as_str(), "record" | "unit"),
                "App.definition.{name} must be a record"
            );
            let mut names = BTreeSet::new();
            for field in &record.fields {
                crate::schema::identifier(&field.name)?;
                ensure!(
                    names.insert(field.name.clone()),
                    "duplicate App.definition operation"
                );
            }
            Ok(names.into_iter().collect())
        };
        let namespace = product
            .fields
            .iter()
            .find(|field| field.name == "namespace")
            .expect("namespace field");
        ensure!(
            table.node(namespace.type_id)?.kind == "text",
            "App.definition.namespace must be a string"
        );
        let (commands, queries) = if unified {
            let operations = product
                .fields
                .iter()
                .find(|field| field.name == "operations")
                .context("operations missing")?;
            let mut commands = Vec::new();
            let mut queries = Vec::new();
            category("operations")?;
            for field in &table.node(operations.type_id)?.fields {
                let definition = table.node(field.type_id)?;
                ensure!(
                    definition.kind == "record",
                    "App.definition operations require nominal definition records"
                );
                match definition.name.as_str() {
                    "Api.CommandDef" => commands.push(field.name.clone()),
                    "Api.QueryDef" => queries.push(field.name.clone()),
                    _ => anyhow::bail!(
                        "App.definition.operations.{} requires Api.command or Api.query with a complete contract",
                        field.name
                    ),
                }
            }
            commands.sort();
            queries.sort();
            (commands, queries)
        } else {
            (category("commands")?, category("queries")?)
        };
        let credentials = if unified && declared.contains("credentials") {
            category("credentials")?;
            let registration = product
                .fields
                .iter()
                .find(|field| field.name == "credentials")
                .context("credential registrations missing")?;
            let mut profiles = BTreeMap::new();
            for field in &table.node(registration.type_id)?.fields {
                let family = table.node(field.type_id)?;
                ensure!(family.kind == "record", "credential family must be nominal");
                let profile = match family.name.as_str() {
                    "Credential.ClientFamily" => "client",
                    "Credential.PersonalFamily" => "personal",
                    _ => anyhow::bail!(
                        "App.definition.credentials.{} requires a supported Credential family",
                        field.name
                    ),
                };
                profiles.insert(field.name.clone(), profile.to_owned());
            }
            ensure!(
                profiles.len() <= 64,
                "credential family registration budget"
            );
            profiles
        } else {
            BTreeMap::new()
        };
        let shape = Self {
            unified,
            commands,
            queries,
            pages: if unified {
                category("pages")?
            } else {
                Vec::new()
            },
            properties: if unified {
                category("properties")?
            } else {
                Vec::new()
            },
            errors: if unified {
                category("errors")?
            } else {
                Vec::new()
            },
            schedules: if unified && declared.contains("schedules") {
                category("schedules")?
            } else {
                Vec::new()
            },
            ingress: if unified && declared.contains("ingress") {
                category("ingress")?
            } else {
                Vec::new()
            },
            redirects: if unified && declared.contains("redirects") {
                category("redirects")?
            } else {
                Vec::new()
            },
            credentials,
        };
        ensure!(
            !shape.commands.is_empty() || !shape.queries.is_empty(),
            "public operations required"
        );
        ensure!(
            shape.commands.len() + shape.queries.len() <= 128,
            "app operation count budget"
        );
        ensure!(
            shape
                .commands
                .iter()
                .all(|name| !shape.queries.contains(name)),
            "command/query names must not conflict"
        );
        Ok(shape)
    }

    fn witnesses(&self) -> Vec<(String, String, String)> {
        let mut witnesses = Vec::new();
        for (category, plural, names, roles) in [
            (
                "command",
                "commands",
                &self.commands,
                &["input", "output"][..],
            ),
            ("query", "queries", &self.queries, &["input", "output"][..]),
        ] {
            for name in names {
                for role in roles {
                    witnesses.push((
                        format!("day2_{category}_{role}_{name}"),
                        format!("{category}_{role}"),
                        format!(
                            "App.definition.{}.{name}",
                            if self.unified { "operations" } else { plural }
                        ),
                    ));
                }
            }
        }
        witnesses
    }
}

pub fn app_platform(shape: Option<&AppShape>) -> String {
    app_platform_for(shape, Projection::default())
}

/// The optional App.definition categories whose names the app-shape reflection
/// must see. Each is projected only for an application that declares it, so an
/// application with none keeps exactly the shape it has today.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Projection {
    pub schedules: bool,
    pub ingress: bool,
    pub redirects: bool,
    pub credentials: bool,
}

impl Projection {
    /// Read from App.roc, because no type table exists yet to ask.
    pub fn declared(app_source: &str) -> Result<Self> {
        Ok(Self {
            schedules: crate::app_inference::declares_schedules(app_source)?,
            ingress: crate::app_inference::declares_ingress(app_source)?,
            redirects: crate::app_inference::declares_redirects(app_source)?,
            credentials: crate::app_inference::declares_credentials(app_source)?,
        })
    }
}

pub fn app_platform_for(shape: Option<&AppShape>, projection: Projection) -> String {
    let mut source = include_str!("../../../tools/app-platform.roc").to_string();
    for (declared, category) in [
        (projection.schedules, "schedules"),
        (projection.ingress, "ingress"),
        (projection.redirects, "redirects"),
        (projection.credentials, "credentials"),
    ] {
        if declared {
            source = source.replacen(
                "\t\tpages: App.definition.pages,",
                &format!(
                    "\t\tpages: App.definition.pages,\n\t\t{category}: App.definition.{category},"
                ),
                1,
            );
        }
    }
    if let Some(shape) = shape {
        let mut provides = "\"day2_app\": app_shape".to_string();
        for (symbol, helper, callback) in shape.witnesses() {
            provides.push_str(&format!(", \"{symbol}\": {symbol}"));
            source.push_str(&format!(
                "\n{symbol} = |value| {helper}({callback}, value)\n"
            ));
        }
        source = source.replacen("\"day2_app\": app_shape", &provides, 1);
    }
    source
}

fn inferred_catalog(table: &Table) -> Result<Catalog> {
    let shape = AppShape::from_table(table)?;
    let mut expected = shape
        .witnesses()
        .into_iter()
        .map(|(symbol, _, _)| symbol)
        .chain(["day2_schema", "day2_inputs", "day2_outputs", "day2_app"].map(str::to_string))
        .collect::<BTreeSet<_>>();
    if shape.unified {
        expected.insert("day2_domains".into());
        // Older checked artifacts predate the complete storage witness.
        if table
            .entries
            .iter()
            .any(|entry| entry.symbol == "day2_storage")
        {
            expected.insert("day2_storage".into());
        }
    }
    ensure!(
        table.entries.len() == expected.len()
            && table
                .entries
                .iter()
                .map(|entry| entry.symbol.clone())
                .collect::<BTreeSet<_>>()
                == expected,
        "inferred operation witnesses must exactly cover App.definition"
    );
    let inputs = table.fields("day2_inputs")?;
    let outputs = table.fields("day2_outputs")?;
    let models = table.fields("day2_schema")?;
    if shape.unified {
        ensure!(
            shape.properties.iter().collect::<BTreeSet<_>>()
                == models.iter().map(|field| &field.name).collect(),
            "every registered model requires a root invariant"
        );
    }
    let mut catalog = Catalog {
        unified: shape.unified,
        pages: shape.pages.clone(),
        schedules: shape.schedules.clone(),
        ingress: shape.ingress.clone(),
        redirects: shape.redirects.clone(),
        credentials: shape.credentials.clone(),
        errors: shape.errors.clone(),
        ..Catalog::default()
    };
    for (category, names, target) in [
        ("command", &shape.commands, &mut catalog.commands),
        ("query", &shape.queries, &mut catalog.queries),
    ] {
        for name in names {
            let input = table.identity(&format!("day2_{category}_input_{name}"))?;
            let output = table.identity(&format!("day2_{category}_output_{name}"))?;
            target.insert(
                name.clone(),
                Operation {
                    input: table.registered(inputs, input, false)?,
                    output: table.registered(outputs, output, false)?,
                },
            );
        }
    }
    Ok(catalog)
}

impl Catalog {
    pub fn modules(
        &self,
        schema: &Schema,
        outputs: &output_schema::Catalog,
        admission: bool,
    ) -> Result<BTreeMap<String, String>> {
        let prefix = if admission { "admission_" } else { "" };
        let input_type = |key: &str| -> Result<String> {
            Ok(schema
                .inputs
                .get(key)
                .with_context(|| format!("registered codec {key} missing"))?
                .input_type()?
                .to_owned())
        };
        let output_type = |key: &str| -> Result<String> {
            Ok(outputs
                .get(key)
                .context("registry output missing")?
                .roc_type
                .clone())
        };
        let mut modules = BTreeMap::new();
        modules.insert(
            crate::credential_codegen::MODULE.into(),
            crate::credential_codegen::module(
                self.credentials.keys().map(String::as_str),
                admission,
            )?,
        );
        let mut imports = "import pf.Write\nimport pf.Read\nimport pf.Model\nimport pf.Input\nimport pf.Output\nimport pf.Context\nimport pf.Tx\nimport pf.Query\nimport pf.CollectionPage\nimport pf.Cursor\nimport pf.PageSize\nimport AppIdentity\nimport Data\nimport Inputs\nimport Outputs\n".to_string();
        if outputs
            .values()
            .any(|contract| contract.shape.uses_row_version())
        {
            imports.push_str("import pf.RowVersion\n");
        }
        let mut modules_used = BTreeSet::new();
        for record in schema.inputs.values().chain(schema.models.values()) {
            if let Some(annotation) = &record.roc_type {
                modules_used.extend(output_schema::annotation_imports(annotation)?);
            }
        }
        for output in outputs.values() {
            modules_used.extend(output_schema::annotation_imports(&output.roc_type)?);
        }
        for module in modules_used {
            if !["CollectionPage", "Cursor", "PageSize", "RowVersion"].contains(&module) {
                if ["Ref", "Text"].contains(&module) {
                    imports.push_str(&format!("import pf.{module}\n"));
                } else {
                    imports.push_str(&format!("import {module}\n"));
                }
            }
        }
        for (name, constructor, fields) in [
            ("Commands", "Write", &self.commands),
            ("Reads", "Read", &self.queries),
        ] {
            let mut source = format!("{imports}\n{name} :: [].{{\n");
            for (key, definition) in fields {
                source.push_str(&format!("\t{key} : {constructor}({}, {})\n\t{key} = {constructor}.{prefix}define(AppIdentity.namespace.concat(\".{key}\"), Inputs.{}, Outputs.{})\n", input_type(&definition.input)?, output_type(&definition.output)?, definition.input, definition.output));
            }
            source.push_str("}\n");
            modules.insert(format!("{name}.roc"), source);
        }
        if self.unified {
            modules.extend(crate::app_contract::modules(
                self, schema, outputs, &imports, admission,
            )?);
            return Ok(modules);
        }
        let mut contract =
            format!("{imports}import pf.PageBinding\nimport pf.Property\n\nAppContract :: [].{{\n");
        for (name, effect, definitions) in [
            ("Commands", "Tx", &self.commands),
            ("Queries", "Query", &self.queries),
        ] {
            let fields = definitions
                .iter()
                .map(|(key, definition)| {
                    Ok(format!(
                        "{key} : (Context, {} -> {effect}({}))",
                        input_type(&definition.input)?,
                        output_type(&definition.output)?
                    ))
                })
                .collect::<Result<Vec<_>>>()?
                .join(", ");
            contract.push_str(&format!("\t{name} : {{ {fields} }}\n"));
        }
        contract.push_str("\tProduct : { namespace : Str, commands : Commands, queries : Queries, pages : List(PageBinding), properties : List(Property) }\n}\n");
        modules.insert("AppContract.roc".into(), contract);
        let mut registry = "import pf.Product\nimport pf.CommandBinding\nimport pf.QueryBinding\nimport AppContract\nimport Commands\nimport Reads\n\nRegistry :: [].{\n".to_owned();
        let commands = self
            .commands
            .keys()
            .map(|key| {
                format!("CommandBinding.{prefix}define(Commands.{key}, product.commands.{key})")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let queries = self
            .queries
            .keys()
            .map(|key| format!("QueryBinding.{prefix}define(Reads.{key}, product.queries.{key})"))
            .collect::<Vec<_>>()
            .join(", ");
        registry.push_str(&format!("\t{prefix}step : AppContract.Product, Str -> Str\n\t{prefix}step = |product, raw| Product.{prefix}step({{ namespace: product.namespace, commands: [{commands}], queries: [{queries}], pages: product.pages, properties: product.properties, schedules: [], ingress: [], redirects: [] }}, raw)\n}}\n"));
        modules.insert("Registry.roc".into(), registry);
        Ok(modules)
    }

    pub fn validate_artifact(&self, artifact: &Artifact) -> Result<()> {
        crate::schema::identifier(&artifact.namespace)?;
        let mut expected = BTreeMap::new();
        for (kind, entries) in [("command", &self.commands), ("query", &self.queries)] {
            for (name, declaration) in entries {
                crate::schema::identifier(name)?;
                ensure!(
                    expected
                        .insert(
                            format!("{}.{name}", artifact.namespace),
                            (
                                kind,
                                declaration.input.as_str(),
                                declaration.output.as_str()
                            )
                        )
                        .is_none(),
                    "duplicate declared operation"
                );
            }
        }
        ensure!(
            artifact.operations.len() == expected.len(),
            "declaration registry completeness mismatch"
        );
        for operation in &artifact.operations {
            ensure!(
                expected.get(&operation.name)
                    == Some(&(
                        operation.kind.as_str(),
                        operation.input_type.as_str(),
                        operation.output_type.as_str()
                    )),
                "registered operation differs from checked declaration"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn optional_trigger_categories_survive_app_shape_projection() -> Result<()> {
        for fields in [
            "",
            "ingress: { gitea: notice },",
            "schedules: { poll: timer }, ingress: { gitea: notice }, redirects: { go: route },",
        ] {
            let app = format!(
                "App :: [].{{ definition = {{ namespace: \"test\", operations: {{}}, pages: {{}}, properties: {{}}, errors: {{}}, {fields} }} }}"
            );
            let generated = app_platform_for(None, Projection::declared(&app)?);
            for category in ["schedules", "ingress", "redirects"] {
                assert_eq!(
                    generated.contains(&format!("{category}: App.definition.{category},")),
                    fields.contains(&format!("{category}:")),
                    "app shape lost or invented {category}: {fields}",
                );
            }
        }
        Ok(())
    }

    use super::*;
    use serde_json::{Value, json};

    fn checked() -> Value {
        let node = |kind: &str, name: &str, item: usize, fields: Value, args: Value, ret: usize| json!({"kind":kind,"name":name,"item":item,"fields":fields,"args":args,"ret":ret});
        json!([{"entries": [
            {"symbol":"day2_schema","type_id":13},
            {"symbol":"day2_inputs","type_id":10},
            {"symbol":"day2_outputs","type_id":12},
            {"symbol":"day2_commands","type_id":8},
            {"symbol":"day2_queries","type_id":13}
        ],"types":[
            node("unit","",0,json!([]),json!([]),0),
            node("record","Contracts.Input",0,json!([{"name":"text","type_id":2}]),json!([]),0),
            node("text","",0,json!([]),json!([]),0),
            node("record","__AnonStruct_output",0,json!([{"name":"value","type_id":2}]),json!([]),0),
            node("list","",1,json!([]),json!([]),0),
            node("list","",3,json!([]),json!([]),0),
            node("record","Declaration.Command",0,json!([{"name":"input_witness","type_id":4},{"name":"output_witness","type_id":5}]),json!([]),0),
            node("record","",0,json!([{"name":"save","type_id":6}]),json!([]),0),
            node("function","",0,json!([]),json!([7]),7),
            node("record","",0,json!([{"name":"input","type_id":1}]),json!([]),0),
            node("function","",0,json!([]),json!([9]),9),
            node("record","",0,json!([{"name":"output","type_id":3}]),json!([]),0),
            node("function","",0,json!([]),json!([11]),11),
            node("function","",0,json!([]),json!([0]),0)
        ]}])
    }

    fn boxed(document: &mut Value, payload: usize) -> usize {
        let types = document[0]["types"].as_array_mut().unwrap();
        let id = types.len();
        types.push(json!({
            "kind":"box", "name":"", "item":payload,
            "fields":[], "args":[], "ret":0, "tags":[]
        }));
        id
    }

    #[test]
    fn compiler_boxes_preserve_nominal_identity_and_exported_witnesses() {
        let original = checked();
        let expected = from_checked_types(&serde_json::to_vec(&original).unwrap()).unwrap();
        let mut document = original.clone();
        let first = boxed(&mut document, 6);
        let second = boxed(&mut document, first);
        document[0]["types"][7]["fields"][0]["type_id"] = json!(second);
        let input = boxed(&mut document, 1);
        document[0]["types"][4]["item"] = json!(input);
        let root = boxed(&mut document, 9);
        document[0]["types"][10]["args"][0] = json!(root);
        let entry = boxed(&mut document, 8);
        document[0]["entries"][3]["type_id"] = json!(entry);
        let bytes = serde_json::to_vec(&document).unwrap();
        assert_eq!(from_checked_types(&bytes).unwrap(), expected);
        let normalized = codec_witnesses(&bytes).unwrap();
        assert_eq!(codec_witnesses(&normalized).unwrap(), normalized);
        assert_eq!(
            codec_witnesses(&serde_json::to_vec(&original).unwrap()).unwrap(),
            serde_json::to_vec(&original).unwrap(),
            "unboxed historical compiler evidence remains byte-for-byte unchanged"
        );

        let mut other = document[0]["types"][1].clone();
        other["name"] = json!("Contracts.Other");
        let types = document[0]["types"].as_array_mut().unwrap();
        let other_id = types.len();
        types.push(other);
        document[0]["types"][input]["item"] = json!(other_id);
        assert!(from_checked_types(&serde_json::to_vec(&document).unwrap()).is_err());
    }

    #[test]
    fn app_shape_resolves_boxed_definitions_without_changing_categories() {
        let mut document = checked();
        document[0]["types"][6]["name"] = json!("Api.CommandDef");
        let definition = boxed(&mut document, 6);
        document[0]["types"][7]["fields"][0]["type_id"] = json!(definition);
        let types = document[0]["types"].as_array_mut().unwrap();
        let root = types.len();
        types.push(json!({
            "kind":"record", "name":"", "item":0, "args":[], "ret":0,
            "fields":[
                {"name":"namespace","type_id":2},
                {"name":"operations","type_id":7},
                {"name":"pages","type_id":0},
                {"name":"properties","type_id":0},
                {"name":"errors","type_id":0}
            ]
        }));
        let function = types.len();
        types.push(json!({
            "kind":"function", "name":"", "item":0, "fields":[],
            "args":[0], "ret":root
        }));
        document[0]["entries"] = json!([{"symbol":"day2_app","type_id":function}]);
        let parse =
            |document: &Value| AppShape::from_checked_types(&serde_json::to_vec(document).unwrap());
        let shape = parse(&document).unwrap();
        assert!(shape.unified);
        assert_eq!(shape.commands, ["save"]);
        assert!(shape.queries.is_empty());
        document[0]["types"][6]["name"] = json!("Api.QueryDef");
        let shape = parse(&document).unwrap();
        assert!(shape.commands.is_empty());
        assert_eq!(shape.queries, ["save"]);
        document[0]["types"][6]["kind"] = json!("text");
        assert!(parse(&document).is_err());
        document[0]["types"][6]["kind"] = json!("record");
        document[0]["types"][6]["name"] = json!("Impostor.CommandDef");
        assert!(parse(&document).is_err());
    }

    #[test]
    fn compiler_boxes_reject_malformed_or_cyclic_graphs_before_projection() {
        let mut original = checked();
        let wrapper = boxed(&mut original, 6);
        original[0]["types"][7]["fields"][0]["type_id"] = json!(wrapper);
        for (field, value) in [
            ("item", json!(99_999)),
            ("item", json!(wrapper)),
            ("name", json!("Api.CommandDef")),
            ("fields", json!([{"name":"value","type_id":2}])),
            ("args", json!([2])),
            ("ret", json!(2)),
            ("tags", json!([{"name":"Some","payload":[2]}])),
        ] {
            let mut document = original.clone();
            document[0]["types"][wrapper][field] = value;
            let bytes = serde_json::to_vec(&document).unwrap();
            assert!(codec_witnesses(&bytes).is_err(), "malformed box {field}");
            assert!(AppShape::from_checked_types(&bytes).is_err());
        }
        let second = boxed(&mut original, wrapper);
        original[0]["types"][wrapper]["item"] = json!(second);
        assert!(codec_witnesses(&serde_json::to_vec(&original).unwrap()).is_err());

        let mut unreachable = checked();
        let id = unreachable[0]["types"].as_array().unwrap().len();
        boxed(&mut unreachable, id);
        assert!(
            codec_witnesses(&serde_json::to_vec(&unreachable).unwrap()).is_err(),
            "unreferenced malformed compiler boxes are not admitted"
        );

        let mut bounded = checked();
        let mut target = 6;
        while bounded[0]["types"].as_array().unwrap().len() < 4096 {
            target = boxed(&mut bounded, target);
        }
        bounded[0]["types"][7]["fields"][0]["type_id"] = json!(target);
        assert!(from_checked_types(&serde_json::to_vec(&bounded).unwrap()).is_ok());
        boxed(&mut bounded, target);
        assert!(codec_witnesses(&serde_json::to_vec(&bounded).unwrap()).is_err());
    }

    #[test]
    fn compiler_catalog_retains_category_and_nominal_codec_identity() {
        let base = checked();
        let parse = |value: &Value| from_checked_types(&serde_json::to_vec(value).unwrap());
        assert_eq!(
            parse(&base).unwrap().commands["save"],
            Operation {
                input: "input".into(),
                output: "output".into()
            }
        );
        let mut duplicated = base.clone();
        let copy = duplicated[0]["types"][1].clone();
        duplicated[0]["types"].as_array_mut().unwrap().push(copy);
        duplicated[0]["types"][4]["item"] = json!(14);
        assert!(
            parse(&duplicated).is_ok(),
            "equivalent monomorphized nodes are legitimate"
        );
        duplicated[0]["types"][14]["name"] = json!("Contracts.Other");
        assert!(
            parse(&duplicated).is_err(),
            "structural shape does not erase nominal identity"
        );
        for (path, replacement) in [
            ("/0/types/6/name", json!("Declaration.Query")),
            ("/0/types/6/fields", json!([])),
            ("/0/types/7/fields/0/name", json!("bad.name")),
            ("/0/types/9/fields", json!([])),
            (
                "/0/types/9/fields",
                json!([{"name":"input","type_id":1},{"name":"alias","type_id":1}]),
            ),
            ("/0/types/8/ret", json!(0)),
            ("/0/types/4/item", json!(99999)),
            ("/0/entries/4/symbol", json!("missing_queries")),
        ] {
            let mut value = base.clone();
            *value.pointer_mut(path).unwrap() = replacement;
            assert!(
                parse(&value).is_err(),
                "invalid checked declaration admitted: {path}"
            );
        }
    }

    #[test]
    fn unsigned_declaration_identity_preserves_width_and_signedness() {
        let mut value = checked();
        value[0]["types"][2]["kind"] = json!("unsigned");
        value[0]["types"][2]["name"] = json!("U32");
        let mut other = value[0]["types"][2].clone();
        other["name"] = json!("U64");
        let mut signed = other.clone();
        signed["kind"] = json!("integer");
        signed["name"] = json!("");
        value[0]["types"]
            .as_array_mut()
            .unwrap()
            .extend([other, signed]);
        let table: Table = serde_json::from_value(value[0].clone()).unwrap();
        assert!(table.same_type(2, 2, &mut BTreeSet::new()).unwrap());
        assert!(!table.same_type(2, 14, &mut BTreeSet::new()).unwrap());
        assert!(!table.same_type(2, 15, &mut BTreeSet::new()).unwrap());
        assert!(from_checked_types(&serde_json::to_vec(&value).unwrap()).is_ok());
        value[0]["types"][2]["name"] = json!("U128");
        assert!(from_checked_types(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn compiler_catalog_compares_optional_text_through_nominal_graphs() {
        let mut value = checked();
        value[0]["types"][1]["fields"][0]["type_id"] = json!(14);
        let mut input_copy = value[0]["types"][1].clone();
        input_copy["fields"][0]["type_id"] = json!(16);
        let union = json!({"kind":"union","name":"OptionalText","item":0,"fields":[],"args":[],"ret":0,"tags":[{"name":"None","payload":[]},{"name":"Some","payload":[2]}]});
        let mut union_copy = union.clone();
        union_copy["tags"].as_array_mut().unwrap().reverse();
        value[0]["types"]
            .as_array_mut()
            .unwrap()
            .extend([union, input_copy, union_copy]);
        let text = boxed(&mut value, 2);
        value[0]["types"][14]["tags"][1]["payload"][0] = json!(text);
        value[0]["types"][4]["item"] = json!(15);
        let parse = |metadata: &Value| from_checked_types(&serde_json::to_vec(metadata).unwrap());
        assert_eq!(parse(&value).unwrap().commands["save"].input, "input");
        for tags in [
            json!([]),
            json!([{"name":"None","payload":[]}]),
            json!([{"name":"None","payload":[]},{"name":"Other","payload":[2]}]),
            json!([{"name":"None","payload":[2]},{"name":"Some","payload":[2]}]),
            json!([{"name":"None","payload":[]},{"name":"Some","payload":[2,2]}]),
            json!([{"name":"None","payload":[]},{"name":"Some","payload":[0]}]),
            json!([{"name":"None","payload":[]},{"name":"Some","payload":[9999]}]),
        ] {
            let mut invalid = value.clone();
            invalid[0]["types"][16]["tags"] = tags;
            assert!(
                parse(&invalid).is_err(),
                "malformed optional metadata admitted"
            );
        }
    }
}
