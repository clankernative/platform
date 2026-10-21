use crate::digest;
use anyhow::{Context, Result, bail, ensure};
use cssparser::{ParseError, Parser, ParserInput, Token};
use day2_assets as assets;
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
const WOFF2: &str = "font/woff2";
const WOFF2_HEADER_BYTES: usize = 48;
pub const COMPONENT_ENTRYPOINT: &str = "ui-package.js";
const COMPONENT_RECEIPT: &str = "ui-assembly/receipt-v1";
const COMPONENT_MODULE_PREFIX: &str = "ui-assembly/module/";
pub const GENERATED_MODULE_PREFIX: &str = "ui-assembly/generated-module/";

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
        Some("woff2") if path.starts_with("fonts/") && path.matches('/').count() == 1 => Ok(WOFF2),
        _ => bail!(
            "ui_resource_type: ui/ accepts only native .js modules, .css stylesheets, and fonts/*.woff2"
        ),
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
        WOFF2 => "woff2",
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
            // The Native UI builder validates this build-only lock before packaging;
            // it is an app input, not a browser resource.
            if path == "ui.lock.json"
                || path == "presentation.json"
                || name.ends_with(".md")
                || name.ends_with(".html")
            {
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
    match media_type(path)? {
        WOFF2 => validate_woff2(bytes),
        kind => {
            let source =
                std::str::from_utf8(bytes).with_context(|| format!("ui/{path}: expected UTF-8"))?;
            match kind {
                JS => validate_javascript(source, path, catalog),
                CSS => validate_stylesheet(source, path, catalog),
                _ => unreachable!(),
            }
        }
    }
    .with_context(|| format!("ui/{path}"))
}

fn validate_woff2(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= WOFF2_HEADER_BYTES,
        "ui_woff2_header_truncated"
    );
    ensure!(&bytes[..4] == b"wOF2", "ui_woff2_magic");
    let declared_length = u32::from_be_bytes(bytes[8..12].try_into()?);
    ensure!(
        declared_length as usize == bytes.len(),
        "ui_woff2_length_mismatch"
    );
    let tables = u16::from_be_bytes(bytes[12..14].try_into()?);
    let sfnt_size = u32::from_be_bytes(bytes[16..20].try_into()?);
    let compressed_size = u32::from_be_bytes(bytes[20..24].try_into()?);
    ensure!(
        tables > 0 && tables <= 4096 && sfnt_size > 0 && compressed_size > 0,
        "ui_woff2_header_invalid"
    );
    ensure!(
        sfnt_size as u64 <= MAX_PACK_BYTES,
        "ui_woff2_sfnt_size_budget"
    );
    ensure!(
        compressed_size as usize <= bytes.len() - WOFF2_HEADER_BYTES,
        "ui_woff2_compressed_length_invalid"
    );
    Ok(())
}

fn resolve_import(path: &str, specifier: &str, catalog: &Catalog) -> Result<()> {
    // One closed host module, served from embedded platform bytes. This does
    // not admit arbitrary absolute URLs or external dependency graphs.
    if specifier == "/assets/platform/navigation.js" {
        return Ok(());
    }
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

fn javascript_imports(source: &str) -> Result<Vec<String>> {
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
    Ok(imports.imports)
}

fn validate_javascript(source: &str, path: &str, catalog: &Catalog) -> Result<()> {
    for specifier in javascript_imports(source)? {
        resolve_import(path, &specifier, catalog)?;
    }
    Ok(())
}

/// Resolve the complete module closure rooted at the host-generated component
/// entrypoint. This is build-time admission, not a sandbox for browser code.
pub fn component_closure(directory: &Path, catalog: &Catalog) -> Result<BTreeMap<String, String>> {
    ensure!(
        catalog
            .get(COMPONENT_ENTRYPOINT)
            .is_some_and(|resource| resource.media_type == JS),
        "ui_component_entrypoint_missing"
    );
    let mut pending = vec![COMPONENT_ENTRYPOINT.to_owned()];
    let mut closure = BTreeMap::new();
    while let Some(path) = pending.pop() {
        if closure.contains_key(&path) {
            continue;
        }
        let resource = catalog.get(&path).context("ui_component_module_missing")?;
        ensure!(resource.media_type == JS, "ui_component_module_type");
        let source = String::from_utf8(read_blob(directory, resource)?)?;
        for specifier in javascript_imports(&source)? {
            if specifier == "/assets/platform/navigation.js" {
                continue;
            }
            let resolved = resolve_module_path(&path, &specifier, catalog)?;
            pending.push(resolved);
        }
        closure.insert(path, resource.digest.clone());
    }
    Ok(closure)
}

fn resolve_module_path(path: &str, specifier: &str, catalog: &Catalog) -> Result<String> {
    ensure!(
        (specifier.starts_with("./") || specifier.starts_with("../"))
            && !specifier.contains(['\\', '%', '?', '#']),
        "ui_import_not_admitted: {specifier:?}"
    );
    let base = url::Url::parse(&format!("https://ui.invalid/_admitted/{path}"))?;
    let resolved = base.join(specifier)?;
    let relative = resolved
        .path()
        .strip_prefix("/_admitted/")
        .context("ui_import_path_escape")?;
    ensure!(
        media_type(relative)? == JS && catalog.contains_key(relative),
        "ui_import_unresolved: {specifier:?} from {path}"
    );
    Ok(relative.to_owned())
}

/// Select only executable resources actually emitted by the pinned provider.
/// Package metadata may be JavaScript without an autoload entrypoint. Neither a
/// reserved filename nor another app-authored file becomes trusted transitively.
pub fn generated_component_modules(
    directory: &Path,
    catalog: &Catalog,
    sources: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let modules: BTreeMap<_, _> = sources
        .iter()
        .filter_map(|(key, hash)| {
            key.strip_prefix(GENERATED_MODULE_PREFIX)
                .map(|path| (path.to_owned(), hash.clone()))
        })
        .collect();
    ensure!(
        modules.iter().all(|(path, hash)| {
            catalog
                .get(path)
                .is_some_and(|resource| resource.media_type == JS && resource.digest == *hash)
                && sources.get(&format!("app/ui/{path}")) == Some(hash)
        }),
        "ui_component_provider_output_mismatch"
    );
    if modules.contains_key(COMPONENT_ENTRYPOINT) {
        let closure = component_closure(directory, catalog)?;
        ensure!(
            closure
                .iter()
                .all(|(path, hash)| modules.get(path) == Some(hash)),
            "ui_component_import_not_generated_by_pinned_provider"
        );
    }
    Ok(modules)
}

/// Host build receipt binding the managed package/provider and exact generated
/// executable set. The native build source manifest seals these entries.
fn component_authority(sources: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut authority = BTreeMap::new();
    for key in [
        "ui-provider/executable",
        "ui/package",
        "ui-provider/input-lock",
    ] {
        authority.insert(
            key.to_owned(),
            sources
                .get(key)
                .context("ui_component_authority_missing")?
                .clone(),
        );
    }
    for (key, value) in sources {
        if key.starts_with("ui-source/app/ui/") || key.starts_with(GENERATED_MODULE_PREFIX) {
            authority.insert(key.clone(), value.clone());
        }
    }
    Ok(authority)
}

pub fn component_receipt(
    namespace: &str,
    closure: &BTreeMap<String, String>,
    sources: &BTreeMap<String, String>,
) -> Result<String> {
    ensure!(!closure.is_empty(), "ui_component_closure_empty");
    ensure!(
        closure.iter().all(|(path, hash)| {
            sources.get(&format!("{GENERATED_MODULE_PREFIX}{path}")) == Some(hash)
        }),
        "ui_component_module_not_generated_by_pinned_provider"
    );
    let authority = component_authority(sources)?;
    Ok(digest(&serde_json::to_vec(&(
        namespace,
        COMPONENT_ENTRYPOINT,
        authority,
        closure,
    ))?))
}

pub fn bind_component_receipt(
    namespace: &str,
    closure: &BTreeMap<String, String>,
    sources: &mut BTreeMap<String, String>,
) -> Result<()> {
    let receipt = component_receipt(namespace, closure, sources)?;
    sources.retain(|key, _| !key.starts_with(COMPONENT_MODULE_PREFIX));
    for (path, hash) in closure {
        sources.insert(format!("{COMPONENT_MODULE_PREFIX}{path}"), hash.clone());
    }
    sources.insert(COMPONENT_RECEIPT.into(), receipt);
    Ok(())
}

/// Validate app JavaScript admission using exact named legacy exceptions and
/// the host-produced component closure receipt; no path-prefix grants exist.
pub fn validate_executable_policy(
    namespace: &str,
    script_entrypoint: &str,
    catalog: &Catalog,
    sources: &BTreeMap<String, String>,
) -> Result<()> {
    let javascript = catalog
        .iter()
        .filter(|(_, resource)| resource.media_type == JS)
        .collect::<BTreeMap<_, _>>();
    if script_entrypoint.is_empty() && javascript.is_empty() {
        ensure!(
            !sources.contains_key(COMPONENT_RECEIPT),
            "ui_component_receipt_without_modules"
        );
        return Ok(());
    }
    let mut approved = BTreeMap::new();
    for (path, resource) in &javascript {
        if approved_legacy_module(namespace, path, &resource.digest) {
            approved.insert((*path).clone(), resource.digest.clone());
        }
    }
    let expected_legacy = match (namespace, script_entrypoint) {
        ("notifications", "notifications.js") => vec!["notifications.js"],
        ("chart-live", "app.js") => vec!["app.js", "chart-navigation.js"],
        _ => Vec::new(),
    };
    ensure!(
        approved
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == expected_legacy.iter().copied().collect(),
        "legacy_app_javascript_exception_set_mismatch"
    );
    let has_component = sources.contains_key(COMPONENT_RECEIPT);
    if has_component {
        let closure = sources
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix(COMPONENT_MODULE_PREFIX)
                    .map(|path| (path.to_owned(), value.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        ensure!(
            !closure.is_empty()
                && closure.iter().all(|(path, hash)| {
                    javascript
                        .get(path)
                        .is_some_and(|resource| resource.digest == *hash)
                        && sources.get(&format!("app/ui/{path}")) == Some(hash)
                }),
            "ui_component_module_receipt_mismatch"
        );
        ensure!(
            component_receipt(namespace, &closure, sources)? == sources[COMPONENT_RECEIPT],
            "ui_component_receipt_invalid"
        );
        approved.extend(closure);
    }
    ensure!(
        javascript.keys().all(|path| approved.contains_key(*path)),
        "unapproved_app_executable_resource"
    );
    ensure!(
        script_entrypoint.is_empty()
            || catalog.get(script_entrypoint).is_some_and(|resource| {
                approved_legacy_module(namespace, script_entrypoint, &resource.digest)
            }),
        "application JavaScript entrypoint is not an approved unchanged module"
    );
    Ok(())
}

fn approved_legacy_module(namespace: &str, path: &str, hash: &str) -> bool {
    matches!(
        (namespace, path, hash),
        (
            "notifications",
            "notifications.js",
            "sha256:4ae41088b340a78bf3ba53e56d5163805448b5d330330401c8e267cc3820857e"
        ) | (
            "chart-live",
            "app.js",
            "sha256:a200c72e74c8d38d888829979b8619b36cb145a6aaa315578d63a97da09d7aca"
        ) | (
            "chart-live",
            "chart-navigation.js",
            "sha256:156b19235681b17e1bc4f36628435c2d2b12b58e38ad75e1889bba824f96115f"
        )
    )
}

pub fn validate_inline_style(source: &str) -> Result<()> {
    ensure!(source.len() <= 16_384, "ui_inline_style_budget");
    validate_css(source, None)
}

fn validate_stylesheet(source: &str, path: &str, catalog: &Catalog) -> Result<()> {
    validate_css(source, Some((path, catalog)))
}

fn validate_css(source: &str, stylesheet: Option<(&str, &Catalog)>) -> Result<()> {
    let mut input = ParserInput::new(source);
    let mut parser = Parser::new(&mut input);
    let mut remaining = 131_072;
    css_tokens(&mut parser, 0, &mut remaining, false, false, stylesheet)
        .map_err(|error| anyhow::anyhow!("ui_css_policy: {error:?}"))
}

fn resolve_font(path: &str, value: &str, catalog: &Catalog) -> Result<()> {
    ensure!(
        !value.starts_with('/')
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/')
            })
            && !value.split('/').any(|part| part.is_empty() || part == ".."),
        "ui_css_font_url_not_relative"
    );
    let base = url::Url::parse(&format!("https://ui.invalid/_admitted/{path}"))?;
    let resolved = base.join(value)?;
    ensure!(
        resolved.origin() == base.origin(),
        "ui_css_font_url_external"
    );
    let relative = resolved
        .path()
        .strip_prefix("/_admitted/")
        .context("ui_css_font_path_escape")?;
    ensure!(
        media_type(relative)? == WOFF2 && catalog.contains_key(relative),
        "ui_css_font_unresolved: {value:?} from {path}; expected an admitted fonts/*.woff2 resource"
    );
    Ok(())
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
    in_font_face: bool,
    in_font_src: bool,
    stylesheet: Option<(&str, &Catalog)>,
) -> std::result::Result<(), ParseError<'i, &'static str>> {
    if depth > 64 {
        return Err(parser.new_custom_error("CSS nesting budget"));
    }
    let mut next_block_is_font_face = false;
    let mut next_ident_is_src = false;
    let mut font_src_value = in_font_src;
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
            Token::AtKeyword(name) => {
                next_block_is_font_face = name.eq_ignore_ascii_case("font-face");
            }
            Token::Ident(name) if in_font_face => {
                next_ident_is_src = name.eq_ignore_ascii_case("src");
            }
            Token::Colon if in_font_face => {
                font_src_value = next_ident_is_src;
                next_ident_is_src = false;
            }
            Token::Semicolon if in_font_face => {
                font_src_value = false;
                next_ident_is_src = false;
            }
            Token::UnquotedUrl(value) if !fragment_url(&value) => {
                if !in_font_face || !font_src_value || !validate_font_url(stylesheet, &value) {
                    return Err(parser.new_custom_error(
                        "CSS resource URLs are not admitted; only catalog WOFF2 URLs in source @font-face are admitted",
                    ));
                }
            }
            Token::Function(name) if name.eq_ignore_ascii_case("url") => {
                parser.parse_nested_block(|nested| {
                    let value = nested.expect_string()?.clone();
                    if !fragment_url(&value)
                        && (!in_font_face
                            || !font_src_value
                            || !validate_font_url(stylesheet, &value))
                    {
                        return Err(nested.new_custom_error(
                            "CSS resource URLs are not admitted; only catalog WOFF2 URLs in source @font-face are admitted",
                        ));
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
            Token::Function(_) | Token::ParenthesisBlock | Token::SquareBracketBlock => {
                next_block_is_font_face = false;
                parser.parse_nested_block(|nested| {
                    css_tokens(
                        nested,
                        depth + 1,
                        remaining,
                        in_font_face,
                        font_src_value,
                        stylesheet,
                    )
                })?;
            }
            Token::CurlyBracketBlock => {
                let font_face = in_font_face || next_block_is_font_face;
                next_block_is_font_face = false;
                parser.parse_nested_block(|nested| {
                    css_tokens(nested, depth + 1, remaining, font_face, false, stylesheet)
                })?;
            }
            Token::WhiteSpace(_) | Token::Comment(_) => {}
            _ => next_block_is_font_face = false,
        }
    }
    Ok(())
}

fn validate_font_url(stylesheet: Option<(&str, &Catalog)>, value: &str) -> bool {
    stylesheet.is_some_and(|(path, catalog)| resolve_font(path, value, catalog).is_ok())
}

#[cfg(test)]
mod executable_policy_tests {
    use super::*;
    use tempfile::tempdir;

    fn js(digest: &str) -> Resource {
        Resource {
            digest: digest.to_owned(),
            media_type: JS.into(),
            bytes: 1,
        }
    }

    #[test]
    fn retained_legacy_modules_are_exact_namespace_path_digest_approvals() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        for (app, path, expected) in [
            (
                "notifications",
                "ui/notifications.js",
                "sha256:4ae41088b340a78bf3ba53e56d5163805448b5d330330401c8e267cc3820857e",
            ),
            (
                "chart-live",
                "ui/app.js",
                "sha256:a200c72e74c8d38d888829979b8619b36cb145a6aaa315578d63a97da09d7aca",
            ),
            (
                "chart-live",
                "ui/chart-navigation.js",
                "sha256:156b19235681b17e1bc4f36628435c2d2b12b58e38ad75e1889bba824f96115f",
            ),
        ] {
            assert_eq!(
                digest(&std::fs::read(examples.join(app).join(path)).unwrap()),
                expected
            );
        }
        let notifications = BTreeMap::from([(
            "notifications.js".into(),
            js("sha256:4ae41088b340a78bf3ba53e56d5163805448b5d330330401c8e267cc3820857e"),
        )]);
        let sources = BTreeMap::new();
        assert!(
            validate_executable_policy(
                "notifications",
                "notifications.js",
                &notifications,
                &sources
            )
            .is_ok()
        );
        assert!(
            validate_executable_policy("other-app", "notifications.js", &notifications, &sources)
                .is_err()
        );
        let changed = BTreeMap::from([(
            "notifications.js".into(),
            js("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )]);
        assert!(
            validate_executable_policy("notifications", "notifications.js", &changed, &sources)
                .is_err()
        );
        let extra = BTreeMap::from([
            (
                "notifications.js".into(),
                notifications["notifications.js"].clone(),
            ),
            (
                "unused.js".into(),
                js("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ),
        ]);
        assert!(
            validate_executable_policy("notifications", "notifications.js", &extra, &sources)
                .is_err()
        );
        assert!(
            validate_executable_policy("notifications", "unused.js", &notifications, &sources)
                .is_err()
        );
        let chart = BTreeMap::from([
            (
                "app.js".into(),
                js("sha256:a200c72e74c8d38d888829979b8619b36cb145a6aaa315578d63a97da09d7aca"),
            ),
            (
                "chart-navigation.js".into(),
                js("sha256:156b19235681b17e1bc4f36628435c2d2b12b58e38ad75e1889bba824f96115f"),
            ),
        ]);
        assert!(validate_executable_policy("chart-live", "app.js", &chart, &sources).is_ok());
        assert!(validate_executable_policy("chart-live", "", &chart, &sources).is_err());
    }

    #[test]
    fn component_receipt_binds_entrypoint_closure_and_managed_authority() -> Result<()> {
        let temp = tempdir()?;
        let ui = temp.path().join("source");
        std::fs::create_dir_all(&ui)?;
        std::fs::write(ui.join("ui-package.js"), "import './component.js';")?;
        std::fs::write(ui.join("component.js"), "export const ready = true;")?;
        let blob_root = temp.path().join("artifact");
        let catalog = package(&ui, &blob_root)?;
        let closure = component_closure(&blob_root, &catalog)?;
        assert_eq!(
            closure.keys().cloned().collect::<Vec<_>>(),
            vec!["component.js", "ui-package.js"]
        );

        let mut sources = BTreeMap::from([
            (
                "ui-provider/executable".into(),
                digest(b"reviewed provider"),
            ),
            ("ui/package".into(), digest(b"reviewed package")),
            ("ui-provider/input-lock".into(), digest(b"captured lock")),
        ]);
        for (path, hash) in &closure {
            sources.insert(format!("app/ui/{path}"), hash.clone());
        }
        // Authority-looking package keys plus an app-authored entrypoint are
        // insufficient: every executable must have a host-recorded provider output.
        assert!(bind_component_receipt("example", &closure, &mut sources).is_err());
        for (path, hash) in &closure {
            sources.insert(format!("{GENERATED_MODULE_PREFIX}{path}"), hash.clone());
        }
        bind_component_receipt("example", &closure, &mut sources)?;
        validate_executable_policy("example", "", &catalog, &sources)?;
        let mut with_unused = catalog.clone();
        with_unused.insert(
            "unused.js".into(),
            Resource {
                digest: digest(b"unused module"),
                media_type: JS.into(),
                bytes: b"unused module".len() as u64,
            },
        );
        assert!(validate_executable_policy("example", "", &with_unused, &sources).is_err());

        let mut forged_source = sources.clone();
        forged_source.remove(&format!("{GENERATED_MODULE_PREFIX}component.js"));
        assert!(validate_executable_policy("example", "", &catalog, &forged_source).is_err());
        forged_source.insert(
            format!("{GENERATED_MODULE_PREFIX}component.js"),
            digest(b"different provider output"),
        );
        assert!(validate_executable_policy("example", "", &catalog, &forged_source).is_err());
        let mut fake = BTreeMap::from([("ui-provider/executable".into(), digest(b"self claimed"))]);
        assert!(validate_executable_policy("example", "", &catalog, &fake).is_err());
        fake = sources.clone();
        fake.insert("ui-assembly/receipt-v1".into(), digest(b"fake receipt"));
        assert!(validate_executable_policy("example", "", &catalog, &fake).is_err());
        fake = sources.clone();
        fake.insert(
            "ui-assembly/module/component.js".into(),
            digest(b"changed module"),
        );
        assert!(validate_executable_policy("example", "", &catalog, &fake).is_err());
        fake = sources.clone();
        fake.remove("ui-assembly/module/ui-package.js");
        fake.insert(
            "ui-assembly/module/components/ui-package.js".into(),
            digest(b"fake entrypoint"),
        );
        assert!(validate_executable_policy("example", "", &catalog, &fake).is_err());
        fake = sources.clone();
        fake.insert("ui/package".into(), digest(b"different reviewed package"));
        assert!(validate_executable_policy("example", "", &catalog, &fake).is_err());
        fake = sources.clone();
        fake.remove("ui-assembly/receipt-v1");
        fake.insert(
            "ui-provider/executable".into(),
            digest(b"self claimed provider"),
        );
        assert!(validate_executable_policy("example", "", &catalog, &fake).is_err());
        Ok(())
    }

    #[test]
    fn actual_provider_metadata_is_admitted_without_granting_an_app_script_entrypoint() -> Result<()>
    {
        let temp = tempdir()?;
        let hash = digest(b"export const catalog = {};");
        let catalog = BTreeMap::from([("clanker-properties.js".into(), js(&hash))]);
        let mut sources = BTreeMap::from([
            (
                "ui-provider/executable".into(),
                digest(b"reviewed provider"),
            ),
            ("ui/package".into(), digest(b"reviewed package")),
            ("ui-provider/input-lock".into(), digest(b"captured lock")),
            ("app/ui/clanker-properties.js".into(), hash.clone()),
            (
                format!("{GENERATED_MODULE_PREFIX}clanker-properties.js"),
                hash,
            ),
        ]);
        let modules = generated_component_modules(temp.path(), &catalog, &sources)?;
        bind_component_receipt("example", &modules, &mut sources)?;
        validate_executable_policy("example", "", &catalog, &sources)?;
        assert!(
            validate_executable_policy("example", "clanker-properties.js", &catalog, &sources)
                .is_err()
        );
        let mut forged = catalog;
        forged.insert(
            "ui-package.js".into(),
            js(&digest(b"app-authored entrypoint")),
        );
        assert!(validate_executable_policy("example", "", &forged, &sources).is_err());
        Ok(())
    }

    #[test]
    fn component_imports_must_resolve_before_receipt_creation() -> Result<()> {
        let temp = tempdir()?;
        let ui = temp.path().join("source");
        std::fs::create_dir_all(&ui)?;
        std::fs::write(ui.join("ui-package.js"), "import './missing.js';")?;
        assert!(package(&ui, &temp.path().join("artifact")).is_err());
        Ok(())
    }
}
