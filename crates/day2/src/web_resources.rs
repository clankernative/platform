use crate::{assets, digest};
use anyhow::{Context, Result, bail, ensure};
use cssparser::{ParseError, Parser, ParserInput, Token};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ExportAllDeclaration, ExportFromDeclaration, Expression, ImportDeclaration, ImportExpression,
};
use oxc_ast_visit::{Visit, walk};
use oxc_span::SourceType;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 128;
const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

pub type Catalog = BTreeMap<String, Resource>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub digest: String,
    pub media_type: String,
    pub bytes: u64,
}

fn component(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 80
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')),
        "ui_resource_path: expected an ASCII filename, not a URL or traversal"
    );
    Ok(())
}

fn media_type(path: &str) -> Result<&'static str> {
    ensure!(
        path.len() <= 512 && path.split('/').count() <= 8,
        "ui_resource_path_budget"
    );
    for part in path.split('/') {
        component(part)?;
    }
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("js") => Ok(JS),
        Some("css") => Ok(CSS),
        _ => bail!("ui_resource_type: ui/ accepts only native .js modules and .css stylesheets"),
    }
}

pub fn validate(catalog: &Catalog) -> Result<()> {
    ensure!(catalog.len() <= MAX_FILES, "ui_resource_count_budget");
    let mut total = 0;
    for (path, resource) in catalog {
        ensure!(
            resource.media_type == media_type(path)?,
            "ui_resource_media_type_mismatch: {path}"
        );
        assets::hash_part(&resource.digest)?;
        ensure!(resource.bytes <= MAX_FILE_BYTES, "ui_resource_file_budget");
        total += resource.bytes;
    }
    ensure!(total <= MAX_PACK_BYTES, "ui_resource_pack_budget");
    Ok(())
}

fn blob_name(resource: &Resource) -> Result<String> {
    let extension = match resource.media_type.as_str() {
        JS => "js",
        CSS => "css",
        _ => bail!("ui_resource_media_type"),
    };
    Ok(format!(
        "{}.{extension}",
        assets::hash_part(&resource.digest)?
    ))
}

pub fn read_blob(directory: &Path, resource: &Resource) -> Result<Vec<u8>> {
    let directory = directory.join("web_resources");
    ensure!(
        fs::symlink_metadata(&directory)?.file_type().is_dir(),
        "ui_resource_directory_type"
    );
    let bytes = assets::read_regular(&directory.join(blob_name(resource)?), MAX_FILE_BYTES)?;
    ensure!(
        bytes.len() as u64 == resource.bytes && digest(&bytes) == resource.digest,
        "ui_resource_digest_mismatch"
    );
    Ok(bytes)
}

pub fn validate_blobs(directory: &Path, catalog: &Catalog) -> Result<()> {
    validate(catalog)?;
    for (path, resource) in catalog {
        validate_source(path, &read_blob(directory, resource)?, catalog)?;
    }
    Ok(())
}

/// Keep the source path in the catalog, not in the filesystem blob name. The
/// browser's artifact-scoped URL then preserves ordinary relative imports.
pub fn package(source: &Path, target: &Path) -> Result<Catalog> {
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Catalog::new()),
        metadata => ensure!(metadata?.file_type().is_dir(), "ui_resource_directory_type"),
    }
    let mut sources = BTreeMap::new();
    let mut total = 0;
    collect(source, "", &mut sources, &mut total)?;
    let catalog: Catalog = sources
        .iter()
        .map(|(path, bytes)| {
            Ok((
                path.clone(),
                Resource {
                    digest: digest(bytes),
                    media_type: media_type(path)?.into(),
                    bytes: bytes.len() as u64,
                },
            ))
        })
        .collect::<Result<_>>()?;
    validate(&catalog)?;
    for (path, bytes) in &sources {
        validate_source(path, bytes, &catalog)?;
    }
    if !catalog.is_empty() {
        fs::create_dir_all(target.join("web_resources"))?;
        for (path, resource) in &catalog {
            fs::write(
                target.join("web_resources").join(blob_name(resource)?),
                &sources[path],
            )?;
        }
    }
    Ok(catalog)
}

fn collect(
    directory: &Path,
    prefix: &str,
    sources: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
) -> Result<()> {
    ensure!(
        prefix.split('/').count() <= 8 && fs::symlink_metadata(directory)?.file_type().is_dir(),
        "ui_resource_directory_type_or_depth"
    );
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= MAX_FILES, "ui_resource_directory_budget");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("ui_resource_filename"))?;
        component(&name)?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "ui_resource_symlink_forbidden");
        let path = format!("{prefix}{name}");
        if kind.is_dir() {
            collect(&entry.path(), &format!("{path}/"), sources, total)?;
        } else {
            ensure!(kind.is_file(), "ui_resource_special_file_forbidden");
            if name.ends_with(".md") || name.ends_with(".html") {
                continue;
            }
            media_type(&path).with_context(|| format!("ui/{path}"))?;
            ensure!(sources.len() < MAX_FILES, "ui_resource_count_budget");
            let bytes = assets::read_regular(&entry.path(), MAX_FILE_BYTES)?;
            *total += bytes.len() as u64;
            ensure!(*total <= MAX_PACK_BYTES, "ui_resource_pack_budget");
            sources.insert(path, bytes);
        }
    }
    Ok(())
}

pub fn copy_blobs(source: &Path, target: &Path, catalog: &Catalog) -> Result<()> {
    validate_blobs(source, catalog)?;
    if !catalog.is_empty() {
        fs::create_dir_all(target.join("web_resources"))?;
        for resource in catalog.values() {
            fs::write(
                target.join("web_resources").join(blob_name(resource)?),
                read_blob(source, resource)?,
            )?;
        }
    }
    Ok(())
}

fn validate_source(path: &str, bytes: &[u8], catalog: &Catalog) -> Result<()> {
    let source =
        std::str::from_utf8(bytes).with_context(|| format!("ui/{path}: expected UTF-8"))?;
    match media_type(path)? {
        JS => validate_javascript(source, path, catalog),
        CSS => validate_css(source),
        _ => unreachable!(),
    }
    .with_context(|| format!("ui/{path}"))
}

fn resolve_import(path: &str, specifier: &str, catalog: &Catalog) -> Result<()> {
    ensure!(
        (specifier.starts_with("./") || specifier.starts_with("../"))
            && !specifier.contains(['\\', '%', '?', '#']),
        "ui_import_not_admitted: {specifier:?}; use a relative .js module in ui/. External package catalogs are not implemented"
    );
    let base = url::Url::parse(&format!("https://ui.invalid/_admitted/{path}"))?;
    let resolved = base.join(specifier)?;
    let relative = resolved
        .path()
        .strip_prefix("/_admitted/")
        .context("ui_import_path_escape")?;
    ensure!(
        media_type(relative)? == JS && catalog.contains_key(relative),
        "ui_import_unresolved: {specifier:?} from {path}; expected an admitted .js module"
    );
    Ok(())
}

struct Imports<'s> {
    imports: Vec<String>,
    error: Option<&'static str>,
    source: &'s str,
}

impl<'a> Visit<'a> for Imports<'_> {
    fn visit_import_declaration(&mut self, node: &ImportDeclaration<'a>) {
        if node.with_clause.is_some() || node.phase.is_some() {
            self.error = Some(
                "ui_import_attributes_unsupported: only native JavaScript modules are admitted",
            );
        }
        self.imports.push(node.source.value.to_string());
    }

    fn visit_export_from_declaration(&mut self, node: &ExportFromDeclaration<'a>) {
        if node.with_clause.is_some() {
            self.error = Some("ui_import_attributes_unsupported");
        }
        self.imports.push(node.source.value.to_string());
    }

    fn visit_export_all_declaration(&mut self, node: &ExportAllDeclaration<'a>) {
        if node.with_clause.is_some() {
            self.error = Some("ui_import_attributes_unsupported");
        }
        self.imports.push(node.source.value.to_string());
    }

    fn visit_import_expression(&mut self, node: &ImportExpression<'a>) {
        if node.options.is_some() || node.phase.is_some() {
            self.error = Some("ui_import_attributes_unsupported");
        }
        match &node.source {
            Expression::StringLiteral(value) => self.imports.push(value.value.to_string()),
            _ => {
                self.error =
                    Some("ui_import_computed: import() requires a literal relative .js module path")
            }
        }
        walk::walk_import_expression(self, node);
    }

    fn visit_program(&mut self, node: &oxc_ast::ast::Program<'a>) {
        if node.hashbang.is_some() || self.source.starts_with("#!") {
            self.error =
                Some("ui_browser_module_required: executable scripts are not browser modules");
        }
        walk::walk_program(self, node);
    }
}

fn validate_javascript(source: &str, path: &str, catalog: &Catalog) -> Result<()> {
    let allocator = Allocator::default();
    let parsed = oxc_parser::Parser::new(&allocator, source, SourceType::mjs()).parse();
    ensure!(
        !parsed.panicked && parsed.diagnostics.is_empty(),
        "ui_javascript_parse: {}",
        parsed
            .diagnostics
            .first()
            .map_or_else(|| "parser failed".into(), ToString::to_string)
    );
    let mut imports = Imports {
        imports: vec![],
        error: None,
        source,
    };
    imports.visit_program(&parsed.program);
    if let Some(error) = imports.error {
        bail!(error);
    }
    for specifier in imports.imports {
        resolve_import(path, &specifier, catalog)?;
    }
    Ok(())
}

pub fn validate_inline_style(source: &str) -> Result<()> {
    ensure!(source.len() <= 16_384, "ui_inline_style_budget");
    validate_css(source)
}

fn validate_css(source: &str) -> Result<()> {
    let mut input = ParserInput::new(source);
    let mut parser = Parser::new(&mut input);
    let mut remaining = 131_072;
    css_tokens(&mut parser, 0, &mut remaining)
        .map_err(|error| anyhow::anyhow!("ui_css_policy: {error:?}"))
}

fn fragment_url(value: &str) -> bool {
    value.strip_prefix('#').is_some_and(|id| {
        !id.is_empty()
            && id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    })
}

// Resource-loading tokens are checked after CSS escape decoding, including
// custom properties and nested rules. This is source admission, not a JS sandbox.
fn css_tokens<'i>(
    parser: &mut Parser<'i, '_>,
    depth: usize,
    remaining: &mut usize,
) -> std::result::Result<(), ParseError<'i, &'static str>> {
    if depth > 64 {
        return Err(parser.new_custom_error("CSS nesting budget"));
    }
    while !parser.is_exhausted() {
        if *remaining == 0 {
            return Err(parser.new_custom_error("CSS token budget"));
        }
        *remaining -= 1;
        let token = parser.next_including_whitespace_and_comments()?.clone();
        if token.is_parse_error() {
            return Err(parser.new_unexpected_token_error(token));
        }
        match token {
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("import") => {
                return Err(
                    parser.new_custom_error("@import is not admitted; keep styles in ui/app.css")
                );
            }
            Token::UnquotedUrl(value) if !fragment_url(&value) => {
                return Err(parser.new_custom_error(
                    "CSS resource URLs are not admitted; use app image assets in HTML",
                ));
            }
            Token::Function(name) if name.eq_ignore_ascii_case("url") => {
                parser.parse_nested_block(|nested| {
                    let value = nested.expect_string()?.clone();
                    if !fragment_url(&value) {
                        return Err(nested.new_custom_error("CSS resource URLs are not admitted"));
                    }
                    nested.expect_exhausted()?;
                    Ok(())
                })?;
            }
            Token::Function(name)
                if ["image", "image-set", "-webkit-image-set", "src"]
                    .iter()
                    .any(|item| name.eq_ignore_ascii_case(item)) =>
            {
                return Err(parser.new_custom_error("CSS image/source functions are not admitted"));
            }
            Token::Function(_)
            | Token::ParenthesisBlock
            | Token::SquareBracketBlock
            | Token::CurlyBracketBlock => {
                parser.parse_nested_block(|nested| css_tokens(nested, depth + 1, remaining))?;
            }
            _ => {}
        }
    }
    Ok(())
}
