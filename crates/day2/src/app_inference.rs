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

/// Resolve the explicit storage dependency, never a conventional module name.
/// Only this reference is read from syntax. The compiler checks its schema and
/// the final AppContract requires App.definition.storage to have that exact type.
pub fn schema_source(source: &str) -> Result<String> {
    let tokens = tokens(source)?;
    let start = tokens
        .windows(3)
        .position(|window| {
            window
                == [
                    Token::Word("definition"),
                    Token::Punct(b'='),
                    Token::Punct(b'{'),
                ]
        })
        .context("App.definition record required")?
        + 3;
    let mut depth = 1;
    let mut dependency = None;
    for at in start..tokens.len() {
        match tokens[at] {
            Token::Punct(b'{') => depth += 1,
            Token::Punct(b'}') => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Token::Word("storage")
                if depth == 1 && (at == start || tokens[at - 1] == Token::Punct(b',')) =>
            {
                let Some(
                    [
                        Token::Punct(b':'),
                        Token::Word(module),
                        Token::Punct(b'.'),
                        Token::Word(member),
                        Token::Punct(b',' | b'}'),
                    ],
                ) = tokens.get(at + 1..at + 6)
                else {
                    anyhow::bail!(
                        "App.definition.storage must reference an imported definition, such as Storage.definition"
                    );
                };
                crate::schema::roc_type_name(module)?;
                crate::schema::identifier(member)?;
                ensure!(
                    dependency.replace((*module, *member)).is_none(),
                    "duplicate storage definition"
                );
            }
            _ => (),
        }
    }
    let (module, member) = dependency.context("App.definition requires a storage dependency")?;
    let mut imports = Vec::new();
    for at in 0..tokens.len() {
        if tokens[at] == Token::Word("import") {
            if tokens.get(at + 1) == Some(&Token::Word(module)) {
                imports.push(format!("import {module}"));
            } else if let Some([Token::Word(original), Token::Word("as"), Token::Word(alias)]) =
                tokens.get(at + 1..at + 4)
                && *alias == module
            {
                crate::schema::roc_type_name(original)?;
                imports.push(format!("import {original} as {module}"));
            }
        }
    }
    ensure!(
        imports.len() == 1,
        "storage requires one explicit app module import"
    );
    Ok(format!(
        "{}\nSchemaSource :: [].{{\n    schema = {module}.{member}.schema\n    domains = {module}.{member}.domains\n    storage = {module}.{member}\n}}\n",
        imports[0]
    ))
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
}
