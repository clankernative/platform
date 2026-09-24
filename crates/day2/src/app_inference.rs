//! Temporary compiler inputs for checking App before its exact handles exist.
//! Only the static namespace is read from source. Operation membership and every
//! type come from compiler witnesses. Provisional handles are never executable
//! build inputs: binding replaces them before both admission profiles and linking.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token<'a> {
    Word(&'a str),
    String(&'a str),
    Punct(u8),
}

fn tokens(source: &str) -> Result<Vec<Token<'_>>> {
    ensure!(source.len() <= 128_000, "app source byte budget");
    let bytes = source.as_bytes();
    let mut at = 0;
    let mut result = Vec::new();
    while at < bytes.len() {
        let start = at;
        match bytes[at] {
            b'#' => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'"' => {
                let triple = bytes[at..].starts_with(b"\"\"\"");
                let width = if triple { 3 } else { 1 };
                at += width;
                loop {
                    ensure!(at < bytes.len(), "unterminated app string");
                    if bytes[at] == b'\\' {
                        at += 2;
                        continue;
                    }
                    if bytes[at..].starts_with(if triple { b"\"\"\"" } else { b"\"" }) {
                        at += width;
                        break;
                    }
                    at += 1;
                }
                result.push(Token::String(&source[start..at]));
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                at += 1;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                result.push(Token::Word(&source[start..at]));
            }
            byte => {
                at += 1;
                if !byte.is_ascii_whitespace() {
                    result.push(Token::Punct(byte));
                }
            }
        }
    }
    Ok(result)
}

/// Read the top-level module declaration, not a guessed filename or import.
/// The compiler subsequently checks the unmodified source and every reference.
pub(crate) fn module_name(source: &str) -> Result<String> {
    let tokens = tokens(source)?;
    let mut depth = 0_i32;
    let mut name = None;
    for (at, token) in tokens.iter().enumerate() {
        if depth == 0
            && let Token::Word(candidate) = token
            && matches!(
                tokens.get(at + 1..at + 3),
                Some([Token::Punct(b':'), Token::Punct(b':' | b'=')])
            )
        {
            crate::schema::roc_type_name(candidate)?;
            ensure!(
                name.replace((*candidate).to_owned()).is_none(),
                "one module declaration required"
            );
        }
        match token {
            Token::Punct(b'{' | b'[' | b'(') => depth += 1,
            Token::Punct(b'}' | b']' | b')') => depth -= 1,
            _ => (),
        }
        ensure!(depth >= 0, "unbalanced app module");
    }
    ensure!(depth == 0, "unbalanced app module");
    name.context("a named module declaration such as SubmitReport :: [].{ ... } is required")
}

/// App.definition is an ordinary record; its namespace is one static literal.
/// Copying this constant into a generated module breaks the App -> handlers ->
/// handles dependency cycle. The final worker manifest checks the actual value.
pub fn namespace(source: &str) -> Result<String> {
    let tokens = tokens(source)?;
    let starts = tokens
        .windows(3)
        .enumerate()
        .filter_map(|(index, window)| {
            (window
                == [
                    Token::Word("definition"),
                    Token::Punct(b'='),
                    Token::Punct(b'{'),
                ])
            .then_some(index + 3)
        })
        .collect::<Vec<_>>();
    ensure!(
        starts.len() == 1,
        "App.definition must be a record literal with a namespace field"
    );
    let mut depth = 1;
    let mut namespace = None;
    for at in starts[0]..tokens.len() {
        match tokens[at] {
            Token::Punct(b'{') => depth += 1,
            Token::Punct(b'}') => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Token::Word("namespace")
                if depth == 1 && (at == starts[0] || tokens[at - 1] == Token::Punct(b',')) =>
            {
                ensure!(namespace.is_none(), "duplicate App.definition namespace");
                let Some(
                    [
                        Token::Punct(b':'),
                        Token::String(literal),
                        Token::Punct(b',' | b'}'),
                    ],
                ) = tokens.get(at + 1..at + 4)
                else {
                    anyhow::bail!(
                        "App.definition.namespace must be a literal string, such as \"reports\""
                    );
                };
                let value: String =
                    serde_json::from_str(literal).context("invalid namespace literal")?;
                crate::schema::identifier(&value)?;
                namespace = Some(value);
            }
            _ => {}
        }
    }
    ensure!(depth == 0, "unclosed App.definition record");
    namespace.context("App.definition requires namespace, such as namespace: \"reports\"")
}

/// Whether App.definition declares a `schedules` field, read from the source the
/// same way the namespace is. The witness platform that produces the type table is
/// written before any type table exists, so whether to project this field cannot
/// be answered from the table itself. A wrong answer is loud in both directions: a
/// missed field fails to type-check against the generated Product, and a spurious
/// one fails on a `schedules` that does not exist.
pub fn declares_schedules(source: &str) -> Result<bool> {
    declares_category(source, "schedules")
}

/// Whether App.definition declares a top-level field with this name.
fn declares_category(source: &str, category: &str) -> Result<bool> {
    let tokens = tokens(source)?;
    let starts = tokens
        .windows(3)
        .enumerate()
        .filter_map(|(index, window)| {
            (window
                == [
                    Token::Word("definition"),
                    Token::Punct(b'='),
                    Token::Punct(b'{'),
                ])
            .then_some(index + 3)
        })
        .collect::<Vec<_>>();
    ensure!(
        starts.len() == 1,
        "App.definition must be a record literal with a namespace field"
    );
    let mut depth = 1;
    let mut declared = false;
    for at in starts[0]..tokens.len() {
        match tokens[at] {
            Token::Punct(b'{') => depth += 1,
            Token::Punct(b'}') => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            // Only a top-level field counts, and only where a field may begin, so
            // a nested record or a comment cannot introduce one.
            Token::Word(word)
                if word == category
                    && depth == 1
                    && (at == starts[0] || tokens[at - 1] == Token::Punct(b','))
                    && tokens.get(at + 1) == Some(&Token::Punct(b':')) =>
            {
                ensure!(!declared, "duplicate App.definition {category}");
                declared = true;
            }
            _ => {}
        }
    }
    ensure!(depth == 0, "unclosed App.definition record");
    Ok(declared)
}

/// Whether App.definition declares an `ingress` field, read from the source for the
/// same reason `declares_schedules` is: the witness platform that produces the type
/// table is written before any type table exists.
pub fn declares_ingress(source: &str) -> Result<bool> {
    declares_category(source, "ingress")
}

pub fn identity_module(namespace: &str) -> Result<String> {
    crate::schema::identifier(namespace)?;
    Ok(format!(
        "AppIdentity :: [].{{\n\tnamespace : Str\n\tnamespace = \"{namespace}\"\n}}\n"
    ))
}

/// App.definition no longer carries storage. A leftover field would fail to type
/// check against the generated Product; name the migration instead.
pub fn reject_storage_declaration(source: &str) -> Result<()> {
    ensure!(
        !declares_category(source, "storage")?,
        "App.definition.storage was removed: every model is a table. Delete the \
         storage field and Storage.roc, and declare business keys on the model as \
         `table = Table.keyed(...)`"
    );
    Ok(())
}

/// The module whose nominal records are the application's tables.
pub const MODELS_MODULE: &str = "Models";

/// One nominal model declared in the models module, with its attached `table`.
#[derive(Debug)]
struct DeclaredModel {
    name: String,
    keyed: bool,
}

fn closing(tokens: &[Token<'_>], open: usize) -> Result<usize> {
    let mut depth = 0_i32;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token {
            Token::Punct(b'{' | b'[' | b'(') => depth += 1,
            Token::Punct(b'}' | b']' | b')') => {
                depth -= 1;
                if depth == 0 {
                    return Ok(at);
                }
            }
            _ => (),
        }
    }
    anyhow::bail!("unbalanced models module")
}

/// Read model declarations from syntax. Every nominal record declared directly in
/// the models module is a table; the compiler checks each one and the registry
/// comparison rejects anything that is not registered.
fn declared_models(source: &str) -> Result<Vec<DeclaredModel>> {
    let tokens = tokens(source)?;
    let header = tokens
        .windows(3)
        .position(|window| {
            window
                == [
                    Token::Word(MODELS_MODULE),
                    Token::Punct(b':'),
                    Token::Punct(b':'),
                ]
        })
        .context("Models.roc must declare Models :: [].{ ... }")?;
    let open = (header..tokens.len())
        .find(|&at| {
            tokens[at] == Token::Punct(b'.') && tokens.get(at + 1) == Some(&Token::Punct(b'{'))
        })
        .context("Models must attach its model declarations: Models :: [].{ ... }")?
        + 1;
    let end = closing(&tokens, open)?;
    let mut models = Vec::new();
    let mut at = open + 1;
    while at < end {
        match (&tokens[at], tokens.get(at + 1), tokens.get(at + 2)) {
            (Token::Word(name), Some(Token::Punct(b':')), Some(Token::Punct(b'=' | b':')))
                if name.as_bytes()[0].is_ascii_uppercase() =>
            {
                crate::schema::roc_type_name(name)?;
                let body = at + 3;
                let body_end = match tokens.get(body) {
                    Some(Token::Punct(b'{' | b'[' | b'(')) => closing(&tokens, body)?,
                    _ => body,
                };
                let mut next = body_end + 1;
                let mut keyed = false;
                if tokens.get(next) == Some(&Token::Punct(b'.'))
                    && tokens.get(next + 1) == Some(&Token::Punct(b'{'))
                {
                    let block_end = closing(&tokens, next + 1)?;
                    keyed = table_declaration(name, &tokens[next + 2..block_end])?;
                    next = block_end + 1;
                }
                models.push(DeclaredModel {
                    name: (*name).to_owned(),
                    keyed,
                });
                at = next;
            }
            (Token::Punct(b'{' | b'[' | b'('), _, _) => at = closing(&tokens, at)? + 1,
            _ => at += 1,
        }
    }
    Ok(models)
}

/// Check a model's attached block for `table`. The annotation keeps key errors on
/// the model; the key lint rejects a label that reads a different column, which
/// types alone cannot see when both columns share a type.
fn table_declaration(model: &str, block: &[Token<'_>]) -> Result<bool> {
    let mut depth = 0_i32;
    let (mut annotated, mut defined) = (false, None);
    for (at, token) in block.iter().enumerate() {
        match token {
            Token::Punct(b'{' | b'[' | b'(') => depth += 1,
            Token::Punct(b'}' | b']' | b')') => depth -= 1,
            Token::Word("table") if depth == 0 => match block.get(at + 1) {
                Some(Token::Punct(b':')) => {
                    ensure!(
                        block.get(at + 2..at + 8)
                            == Some(&[
                                Token::Word("Table"),
                                Token::Punct(b'('),
                                Token::Word(model),
                                Token::Punct(b','),
                                Token::Word("_"),
                                Token::Punct(b')'),
                            ]),
                        "{model}.table must be annotated `table : Table({model}, _)`"
                    );
                    annotated = true;
                }
                Some(Token::Punct(b'=')) => defined = Some(at + 2),
                _ => (),
            },
            _ => (),
        }
    }
    let Some(start) = defined else {
        ensure!(!annotated, "{model}.table is annotated but not defined");
        return Ok(false);
    };
    ensure!(
        annotated,
        "{model}.table needs the annotation `table : Table({model}, _)` so key errors point at the model"
    );
    let parameter = match block.get(start..start + 6) {
        Some(
            [
                Token::Word("Table"),
                Token::Punct(b'.'),
                Token::Word("keyed"),
                Token::Punct(b'('),
                Token::Punct(b'|'),
                Token::Word(parameter),
            ],
        ) => Some(*parameter),
        Some(
            [
                Token::Word("Table"),
                Token::Punct(b'.'),
                Token::Word("plain"),
                ..,
            ],
        ) => None,
        _ => anyhow::bail!("{model}.table must be `Table.keyed(|row| {{ ... }})`"),
    };
    let mut at = start;
    while at < block.len() {
        if let (
            Token::Word("Table"),
            Some(Token::Punct(b'.')),
            Some(Token::Word(kind)),
            Some(Token::Punct(b'(')),
            Some(Token::Punct(b'{')),
        ) = (
            &block[at],
            block.get(at + 1),
            block.get(at + 2),
            block.get(at + 3),
            block.get(at + 4),
        ) {
            ensure!(
                matches!(*kind, "unique" | "non_unique"),
                "{model}.table: unknown key kind Table.{kind}"
            );
            let open = at + 4;
            let end = closing(block, open)?;
            key_columns(model, parameter, &block[open + 1..end])?;
            at = end;
        }
        at += 1;
    }
    Ok(true)
}

fn key_columns(model: &str, parameter: Option<&str>, columns: &[Token<'_>]) -> Result<()> {
    ensure!(
        !columns.is_empty(),
        "{model}.table: a key selects at least one column"
    );
    for entry in columns.split(|token| *token == Token::Punct(b',')) {
        match entry {
            [] => (),
            [Token::Word(_)] => (),
            [
                Token::Word(label),
                Token::Punct(b':'),
                Token::Word(read),
                Token::Punct(b'.'),
                Token::Word(column),
            ] if Some(*read) == parameter => {
                ensure!(
                    label == column,
                    "{model}.table: key column `{label}` reads `{read}.{column}`; a key label must name the column it reads"
                );
            }
            [Token::Word(label), Token::Punct(b':'), Token::Word(column)] => ensure!(
                label == column,
                "{model}.table: key column `{label}` reads `{column}`; a key label must name the column it reads"
            ),
            _ => anyhow::bail!("{model}.table: write each key column as `column: row.column`"),
        }
    }
    Ok(())
}

/// Text domain types the application uses as `Text(Domain)`, each with its rules.
fn text_domains(sources: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let (mut specified, mut used) = (BTreeSet::new(), BTreeSet::new());
    for source in sources.values() {
        let tokens = tokens(source)?;
        for window in tokens.windows(6) {
            if let [
                Token::Word("rules"),
                Token::Punct(b':'),
                Token::Word("TextSpec"),
                Token::Punct(b'('),
                Token::Word(domain),
                Token::Punct(b')'),
            ] = window
            {
                specified.insert((*domain).to_owned());
            }
        }
        for window in tokens.windows(4) {
            if let [
                Token::Word("Text"),
                Token::Punct(b'('),
                Token::Word(domain),
                Token::Punct(b')' | b'.'),
            ] = window
            {
                ensure!(
                    window[3] == Token::Punct(b')'),
                    "text domain types are top-level modules: Text({domain}) must not be qualified"
                );
                used.insert((*domain).to_owned());
            }
        }
    }
    let mut domains = BTreeMap::new();
    for domain in used {
        ensure!(
            specified.contains(&domain),
            "Text({domain}) needs `rules : TextSpec({domain})` on the {domain} type"
        );
        crate::schema::roc_type_name(&domain)?;
        let mut name = String::new();
        for (index, ch) in domain.chars().enumerate() {
            if ch.is_ascii_uppercase() && index > 0 {
                name.push('_');
            }
            name.push(ch.to_ascii_lowercase());
        }
        crate::schema::identifier(&name)?;
        ensure!(
            domains.insert(name, domain).is_none(),
            "duplicate text domain name"
        );
    }
    Ok(domains)
}

/// Generate `SchemaSource.roc` for a staged application package: its identity
/// ledger plus every staged app module, keyed by module name.
pub fn staged_schema_source(
    app: &std::path::Path,
    modules: &BTreeMap<String, std::path::PathBuf>,
) -> Result<String> {
    reject_storage_declaration(&std::fs::read_to_string(app.join("App.roc"))?)?;
    let registry = std::fs::read_to_string(app.join(crate::identity::REGISTRY_FILE))
        .context("model-identities.json is required")?;
    let sources = modules
        .keys()
        .map(|name| {
            Ok((
                name.clone(),
                std::fs::read_to_string(app.join(format!("{name}.roc")))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    schema_source(&registry, &sources)
}

/// Generate the storage schema from the committed identity ledger and the models
/// module. Applications declare no storage object: every model is a table named by
/// the ledger, keys come from each model's `table`, and text domains from their use.
/// `sources` maps staged module names to their source text.
pub fn schema_source(registry: &str, sources: &BTreeMap<String, String>) -> Result<String> {
    let registry: crate::identity::Registry =
        serde_json::from_str(registry).context("invalid model identity ledger")?;
    registry.validate()?;
    let models = declared_models(
        sources
            .get(MODELS_MODULE)
            .context("Models.roc is required: every nominal record it declares is a table")?,
    )?;
    let mut tables = BTreeMap::new();
    for model in &models {
        let roc_type = format!("{MODELS_MODULE}.{}", model.name);
        let registered = registry
            .models
            .iter()
            .find(|entry| !entry.retired && entry.roc_type == roc_type)
            .with_context(|| {
                format!(
                    "{roc_type} is not registered: run `xtask register-model APP TABLE {roc_type}` \
                     (or `xtask rename-model` if it was renamed) and commit model-identities.json"
                )
            })?;
        ensure!(
            tables
                .insert(registered.table.clone(), (roc_type, model.keyed))
                .is_none(),
            "duplicate model table"
        );
    }
    for entry in registry.models.iter().filter(|entry| !entry.retired) {
        ensure!(
            tables.contains_key(&entry.table),
            "registered model {} (table {}) is not declared in Models.roc: run `xtask retire-model APP {}` \
             or `xtask rename-model`",
            entry.roc_type,
            entry.table,
            entry.table
        );
    }
    ensure!(
        !tables.is_empty(),
        "Models.roc must declare at least one model"
    );
    let domains = text_domains(sources)?;
    let mut source = format!("import {MODELS_MODULE}\nimport pf.Table\n");
    for domain in domains.values() {
        source.push_str(&format!("import {domain}\n"));
    }
    source.push_str("SchemaSource :: [].{\n");
    let list = |format: &dyn Fn(&str, &str, bool) -> String| {
        tables
            .iter()
            .map(|(table, (roc_type, keyed))| format(table, roc_type, *keyed))
            .collect::<Vec<_>>()
            .join(", ")
    };
    source.push_str(&format!(
        "    Tables : {{ {} }}\n",
        list(&|table, roc_type, _| format!("{table} : List({roc_type})"))
    ));
    source.push_str("    schema : Tables -> Tables\n    schema = |tables| tables\n");
    source.push_str(&format!(
        "    domains = {{{}}}\n",
        domains
            .iter()
            .map(|(name, domain)| format!(" {name}: {domain}.rules"))
            .collect::<Vec<_>>()
            .join(",")
            + if domains.is_empty() { "" } else { " " }
    ));
    source.push_str(&format!(
        "    tables : {{ {} }}\n",
        list(&|table, roc_type, keyed| format!(
            "{table} : Table({roc_type}, {})",
            if keyed { "_" } else { "{}" }
        ))
    ));
    source.push_str(&format!(
        "    tables = {{ {} }}\n",
        list(&|table, roc_type, keyed| if keyed {
            format!("{table}: {roc_type}.table")
        } else {
            format!("{table}: Table.plain")
        })
    ));
    source.push_str(&format!(
        "    identities = \"{}\"\n    storage = {{ schema, tables, domains, identities }}\n}}\n",
        crate::identity::REGISTRY_FILE
    ));
    Ok(source)
}

/// Seed only potential member references, including aliases and exposing imports.
/// These names have no authority: AppShape subsequently discovers the actual
/// catalog, all three modules are replaced, and undeclared references must fail.
pub fn provisional_modules(sources: &[String]) -> Result<BTreeMap<String, String>> {
    let mut names = BTreeSet::new();
    for source in sources {
        let tokens = tokens(source)?;
        let mut exposed = false;
        for (at, token) in tokens.iter().enumerate() {
            if *token == Token::Word("exposing") {
                exposed = true;
            }
            if *token == Token::Punct(b']') {
                exposed = false;
            }
            if let Token::Word(name) = token
                && (exposed || at > 0 && tokens[at - 1] == Token::Punct(b'.'))
                && crate::schema::identifier(name).is_ok()
                && *name != "exposing"
                && *name != "as"
            {
                names.insert(*name);
            }
        }
    }
    ensure!(names.len() <= 4096, "provisional handle name budget");
    let mut modules = BTreeMap::new();
    for (module, kind, parameters) in [
        ("Commands", "Write", "input, output"),
        ("Reads", "Read", "input, output"),
    ] {
        let mut source = format!(
            "import pf.{kind}\nimport pf.Input\nimport pf.Output\nimport pf.Model\nimport AppIdentity\n\n{module} :: [].{{\n"
        );
        for name in &names {
            let input =
                "Input.define(\"inference_only\", |_raw| Err(\"inference_only\"), |_value| \"\")";
            let codecs = format!("{input}, Output.define(\"inference_only\", |_value| \"\")");
            source.push_str(&format!("\t{name} : {kind}({parameters})\n\t{name} = {kind}.define(AppIdentity.namespace.concat(\".{name}\"), {codecs})\n\n"));
        }
        source.push_str("}\n");
        modules.insert(format!("{module}.roc"), source);
    }
    let mut paths = String::from("import pf.Path\nSelectors :: [].{\n");
    for name in &names {
        paths.push_str(&format!(
            "    {name} : Path(root, value)\n    {name} = Path.define(\"inference_only\")\n"
        ));
    }
    paths.push_str("}\n");
    modules.insert("Selectors.roc".into(), paths);
    let mut failures = String::from("import pf.Failure\nimport AppIdentity\nErrors :: [].{\n");
    for name in &names {
        failures.push_str(&format!(
            "    {name} = Failure.define(AppIdentity.namespace.concat(\".{name}\"))\n"
        ));
    }
    failures.push_str("}\n");
    modules.insert("Errors.roc".into(), failures);
    Ok(modules)
}

/// Unbound phantom types have no native List element layout. Identity callbacks
/// preserve their signatures during discovery; callers restore the sealed bytes
/// before binding and checking either executable profile.
pub fn provisional_sdk(module: &str, source: &str) -> Result<String> {
    let replacements = match module {
        "Path.roc" => [
            (
                "root_witness : List(root), value_witness : List(value)",
                "witness : (root, value -> {})",
            ),
            (
                "root_witness: [], value_witness: []",
                "witness: |_root, _value| {}",
            ),
        ],
        "Read.roc" | "Write.roc" => [
            (
                "input_witness : List(a), output_witness : List(b)",
                "input_witness : (a -> a), output_witness : (b -> b)",
            ),
            (
                "input_witness: [], output_witness: []",
                "input_witness: |value| value, output_witness: |value| value",
            ),
        ],
        _ => anyhow::bail!("unknown provisional SDK module"),
    };
    let mut result = source.to_owned();
    for (from, to) in replacements {
        ensure!(
            result.matches(from).count() == 1,
            "provisional SDK interface changed in {module}"
        );
        result = result.replacen(from, to, 1);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_static_and_comments_and_nested_fields_cannot_override_it() -> Result<()> {
        assert_eq!(
            namespace(
                "# definition = { namespace: \"fake\" }\nApp :: [].{ definition = { namespace: \"reports\", commands: { namespace: handler }, queries: {} } }"
            )?,
            "reports"
        );
        for source in [
            "definition = { namespace: other, }",
            "definition = { namespace: \"a\".concat(\"b\"), }",
            "definition = { namespace: \"a\", namespace: \"b\", }",
            "definition = { commands: { namespace: \"a\", } }",
            "definition = { namespace: \"bad.name\", }",
            "definition = { namespace: \"reports\", ",
        ] {
            assert!(namespace(source).is_err(), "{source}");
        }
        Ok(())
    }

    #[test]
    fn provisional_handles_support_aliases_without_declaring_operations() -> Result<()> {
        let sources = vec!["import Commands as Work\nimport Reads exposing [detail]\nWork.analyze\nCommands.submit\n# Commands.fake\n\"Commands.fake\"".into()];
        let modules = provisional_modules(&sources)?;
        assert!(modules["Commands.roc"].contains("analyze : Write(input, output)"));
        assert!(modules["Reads.roc"].contains("detail : Read(input, output)"));
        assert!(!modules["Commands.roc"].contains("fake"));
        Ok(())
    }

    const LEDGER: &str = r#"{"format": 1, "models": [
        {"identity": {"key": "b41c7d2e8a95f60312ad4e7b9c06f158", "prefix": "cmp"},
         "table": "campaigns", "roc_type": "Models.Campaign", "retired": false},
        {"identity": {"key": "f70a1b6c93de5827401c8fa3b6e29d5f", "prefix": "add"},
         "table": "ad_days", "roc_type": "Models.AdDay", "retired": false},
        {"identity": {"key": "0123456789abcdef0123456789abcdef", "prefix": "old"},
         "table": "olds", "roc_type": "Models.Old", "retired": true}
    ]}"#;

    const MODELS: &str = "import pf.Ref\nimport pf.Table\nimport Title\n\nModels :: [].{\n\t# Campaign := { fake : Str } in a comment is not a model.\n\tCampaign := { name : Text(Title), created_time : I64 }\n\n\tAdDay := {\n\t\tcampaign : Ref(Campaign),\n\t\tdate : Str,\n\t}.{\n\t\ttable : Table(AdDay, _)\n\t\ttable = Table.keyed(|row| {\n\t\t\tby_date: Table.unique({ campaign: row.campaign, date: row.date }),\n\t\t})\n\n\t\tis_eq : AdDay, AdDay -> Bool\n\t\tis_eq = |left, right| left.date == right.date\n\t}\n}\n";

    const TITLE: &str = "import pf.TextSpec\n\nTitle := { marker : Bool }.{\n\trules : TextSpec(Title)\n\trules = TextSpec.define({ maximum_bytes: 200, nonblank: Bool.True, description: \"A title.\" })\n}\n";

    fn sources(models: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("Models".to_owned(), models.to_owned()),
            ("Title".to_owned(), TITLE.to_owned()),
            (
                "App".to_owned(),
                "App :: [].{ definition = { namespace: \"ads\" } }".to_owned(),
            ),
        ])
    }

    fn failure(ledger: &str, models: &str) -> String {
        schema_source(ledger, &sources(models))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn every_model_is_a_table_named_by_the_ledger_with_keys_and_domains_derived() -> Result<()> {
        assert_eq!(
            schema_source(LEDGER, &sources(MODELS))?,
            "import Models\nimport pf.Table\nimport Title\nSchemaSource :: [].{\n    Tables : { ad_days : List(Models.AdDay), campaigns : List(Models.Campaign) }\n    schema : Tables -> Tables\n    schema = |tables| tables\n    domains = { title: Title.rules }\n    tables : { ad_days : Table(Models.AdDay, _), campaigns : Table(Models.Campaign, {}) }\n    tables = { ad_days: Models.AdDay.table, campaigns: Table.plain }\n    identities = \"model-identities.json\"\n    storage = { schema, tables, domains, identities }\n}\n"
        );
        Ok(())
    }

    #[test]
    fn models_and_the_ledger_must_agree_with_an_actionable_step() {
        let unregistered = MODELS.replace("\n}\n", "\n\n\tFresh := { name : Str }\n}\n");
        assert!(
            failure(LEDGER, &unregistered)
                .contains("Models.Fresh is not registered: run `xtask register-model")
        );
        let missing = MODELS.replace(
            "\tCampaign := { name : Text(Title), created_time : I64 }\n",
            "",
        );
        let missing = missing.replace("Ref(Campaign)", "Str");
        assert!(failure(LEDGER, &missing).contains("xtask retire-model APP campaigns"));
    }

    #[test]
    fn a_table_is_annotated_and_each_key_label_names_the_column_it_reads() {
        let unannotated = MODELS.replace("\t\ttable : Table(AdDay, _)\n", "");
        assert!(
            failure(LEDGER, &unannotated)
                .contains("needs the annotation `table : Table(AdDay, _)`")
        );
        let foreign = MODELS.replace("table : Table(AdDay, _)", "table : Table(Campaign, _)");
        assert!(failure(LEDGER, &foreign).contains("must be annotated `table : Table(AdDay, _)`"));
        let swapped = MODELS.replace("date: row.date", "date: row.campaign");
        assert!(failure(LEDGER, &swapped).contains("key column `date` reads `row.campaign`"));
        let computed = MODELS.replace("date: row.date", "date: Str.concat(row.date, \"x\")");
        assert!(
            failure(LEDGER, &computed).contains("write each key column as `column: row.column`")
        );
    }

    #[test]
    fn text_domains_need_rules_and_storage_is_no_longer_an_app_field() {
        let mut unspecified = sources(MODELS);
        unspecified.remove("Title");
        assert!(
            schema_source(LEDGER, &unspecified)
                .unwrap_err()
                .to_string()
                .contains("Text(Title) needs `rules : TextSpec(Title)`")
        );
        assert!(
            reject_storage_declaration(
                "App :: [].{ definition = { namespace: \"ads\", storage: Storage.definition } }"
            )
            .unwrap_err()
            .to_string()
            .contains("App.definition.storage was removed")
        );
        assert!(
            reject_storage_declaration("App :: [].{ definition = { namespace: \"ads\" } }").is_ok()
        );
    }
}
