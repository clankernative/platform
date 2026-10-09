use crate::{digest, output_schema::Type};
use anyhow::{Context, Result, bail, ensure};
use day2_assets as assets;
use html5gum::{DefaultEmitter, Token, Tokenizer};
use minijinja::{AutoEscape, Environment, UndefinedBehavior, machinery::ast};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Write},
    path::Path,
    sync::{Arc, Mutex},
};

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_PACK_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILES: usize = 128;
const MAX_HTML_BYTES: usize = 512 * 1024;
const MAX_VARIANTS: usize = 256;
const MARKER: &str = "day2templatevalue";
const VOID: &[&str] = &["area", "br", "col", "hr", "img", "input", "wbr"];

pub type Catalog = BTreeMap<String, Template>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub digest: String,
    pub bytes: u64,
}

fn path_name(path: &str) -> Result<()> {
    ensure!(
        path.len() <= 512
            && path.ends_with(".html")
            && path.split('/').count() <= 8
            && path.split('/').all(|part| {
                !part.is_empty()
                    && part.len() <= 80
                    && !part.starts_with('.')
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
            }),
        "template_path: expected a relative .html path inside ui/"
    );
    ensure!(
        path.starts_with("pages/") || path.starts_with("components/"),
        "template_path: place templates in ui/pages/ or ui/components/"
    );
    Ok(())
}

pub fn validate(catalog: &Catalog) -> Result<()> {
    ensure!(catalog.len() <= MAX_FILES, "template_count_budget");
    let mut total = 0;
    for (path, template) in catalog {
        path_name(path)?;
        assets::hash_part(&template.digest)?;
        ensure!(template.bytes <= MAX_FILE_BYTES, "template_file_budget");
        total += template.bytes;
    }
    ensure!(total <= MAX_PACK_BYTES, "template_pack_budget");
    Ok(())
}

fn blob_name(template: &Template) -> Result<String> {
    Ok(format!("{}.html", assets::hash_part(&template.digest)?))
}

pub fn read_blob(directory: &Path, template: &Template) -> Result<String> {
    let directory = directory.join("web_templates");
    ensure!(
        fs::symlink_metadata(&directory)?.file_type().is_dir(),
        "template_directory_type"
    );
    let bytes = assets::read_regular(&directory.join(blob_name(template)?), MAX_FILE_BYTES)?;
    ensure!(
        bytes.len() as u64 == template.bytes && digest(&bytes) == template.digest,
        "template_digest_mismatch"
    );
    String::from_utf8(bytes).context("template_utf8")
}

fn sources(directory: &Path, catalog: &Catalog) -> Result<BTreeMap<String, String>> {
    validate(catalog)?;
    catalog
        .iter()
        .map(|(path, template)| Ok((path.clone(), read_blob(directory, template)?)))
        .collect()
}

pub fn validate_blobs(directory: &Path, catalog: &Catalog) -> Result<()> {
    for (path, source) in sources(directory, catalog)? {
        parse(&source, &path)?;
    }
    Ok(())
}

pub fn package(source: &Path, target: &Path) -> Result<Catalog> {
    match fs::symlink_metadata(source) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Catalog::new()),
        metadata => ensure!(metadata?.file_type().is_dir(), "template_source_directory"),
    }
    let mut sources = BTreeMap::new();
    collect(source, "", &mut sources)?;
    let catalog: Catalog = sources
        .iter()
        .map(|(path, source)| {
            (
                path.clone(),
                Template {
                    digest: digest(source.as_bytes()),
                    bytes: source.len() as u64,
                },
            )
        })
        .collect();
    validate(&catalog)?;
    for (path, source) in &sources {
        parse(source, path)?;
    }
    if !catalog.is_empty() {
        fs::create_dir_all(target.join("web_templates"))?;
        for (path, template) in &catalog {
            fs::write(
                target.join("web_templates").join(blob_name(template)?),
                &sources[path],
            )?;
        }
    }
    Ok(catalog)
}

fn collect(directory: &Path, prefix: &str, output: &mut BTreeMap<String, String>) -> Result<()> {
    ensure!(
        prefix.split('/').count() <= 8 && fs::symlink_metadata(directory)?.file_type().is_dir(),
        "template_directory_depth_or_type"
    );
    let mut entries = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= MAX_FILES, "template_directory_budget");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("template_filename"))?;
        let path = format!("{prefix}{name}");
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "template_symlink_forbidden");
        if kind.is_dir() {
            collect(&entry.path(), &format!("{path}/"), output)?;
        } else {
            ensure!(kind.is_file(), "template_special_file_forbidden");
            if !name.ends_with(".html") {
                continue;
            }
            path_name(&path)?;
            ensure!(output.len() < MAX_FILES, "template_count_budget");
            let source = String::from_utf8(assets::read_regular(&entry.path(), MAX_FILE_BYTES)?)?;
            ensure!(
                output.values().map(String::len).sum::<usize>() + source.len()
                    <= MAX_PACK_BYTES as usize,
                "template_pack_budget"
            );
            output.insert(path, source);
        }
    }
    Ok(())
}

pub fn copy_blobs(source: &Path, target: &Path, catalog: &Catalog) -> Result<()> {
    validate_blobs(source, catalog)?;
    if !catalog.is_empty() {
        fs::create_dir_all(target.join("web_templates"))?;
        for template in catalog.values() {
            fs::write(
                target.join("web_templates").join(blob_name(template)?),
                read_blob(source, template)?,
            )?;
        }
    }
    Ok(())
}

fn handles(catalog: &Catalog) -> Result<BTreeMap<String, String>> {
    validate(catalog)?;
    let mut handles = BTreeMap::new();
    for path in catalog.keys().filter(|path| path.starts_with("pages/")) {
        let stem = path
            .strip_prefix("pages/")
            .and_then(|path| path.strip_suffix(".html"))
            .context("template_handle_path")?;
        for part in stem.split('/') {
            day2_contracts::names::identifier(part)
                .context("template_handle_requires_snake_case_page_path")?;
        }
        let handle = stem.replace('/', "_");
        day2_contracts::names::identifier(&handle)?;
        ensure!(
            handle != "path" && handles.insert(handle.clone(), path.clone()).is_none(),
            "template_handle_collision_or_reserved: {handle}"
        );
    }
    Ok(handles)
}

pub fn validate_handles(catalog: &Catalog) -> Result<()> {
    handles(catalog)?;
    Ok(())
}

pub fn roc_module(catalog: &Catalog) -> Result<String> {
    let mut code = "import pf.Template\n\nTemplates :: [].{\n".to_owned();
    for handle in handles(catalog)?.keys() {
        code.push_str(&format!(
            "    {handle} : Template\n    {handle} = Template.{handle}\n"
        ));
    }
    code.push_str("}\n");
    Ok(code)
}

pub fn roc_sdk_module(catalog: &Catalog) -> Result<String> {
    let mut code =
        "Template :: { file : Str }.{\n    path : Template -> Str\n    path = |template| template.file\n"
            .to_owned();
    for (handle, path) in handles(catalog)? {
        code.push_str(&format!(
            "    {handle} : Template\n    {handle} = {{ file: {} }}\n",
            serde_json::to_string(&path)?
        ));
    }
    code.push_str("}\n");
    Ok(code)
}

fn parse<'a>(source: &'a str, path: &'a str) -> Result<ast::Stmt<'a>> {
    ensure!(!source.contains(MARKER), "template_reserved_marker");
    minijinja::machinery::parse(source, path, Default::default(), Default::default())
        .with_context(|| format!("ui/{path}: template syntax"))
}

#[derive(Clone)]
struct Dynamic {
    shape: Type,
    asset: bool,
    navigation: bool,
    literal: Option<String>,
}

struct Analysis<'a> {
    sources: &'a BTreeMap<String, String>,
    assets: &'a assets::Catalog,
    stack: Vec<String>,
    dynamic: BTreeMap<String, Dynamic>,
    routes: Option<&'a crate::routing::Catalog>,
    repeated_live_regions: bool,
    repeated_live_forms: bool,
}

fn scalar(shape: &Type) -> bool {
    matches!(
        shape,
        Type::String
            | Type::Integer
            | Type::Boolean
            | Type::ModelReference { .. }
            | Type::RowVersion
            | Type::StandardText { .. }
    )
}

impl Analysis<'_> {
    fn navigation(&self, expr: &ast::Expr<'_>, context: &Type) -> Result<bool> {
        let ast::Expr::Call(call) = expr else {
            return Ok(false);
        };
        let ast::Expr::GetAttr(method) = &call.expr else {
            return Ok(false);
        };
        let ast::Expr::Var(namespace) = &method.expr else {
            return Ok(false);
        };
        if !["routes", "platform"].contains(&namespace.id) {
            return Ok(false);
        }
        let catalog = self
            .routes
            .context("template_routes_require_explicit_routing")?;
        if namespace.id == "platform" {
            ensure!(
                ["audit", "docs", "openapi"].contains(&method.name) && call.args.is_empty(),
                "template_unknown_platform_navigation"
            );
            return Ok(true);
        }
        let route = catalog
            .navigation_input(method.name)
            .with_context(|| format!("template_unknown_route: {}", method.name))?;
        let mut supplied = BTreeSet::new();
        for argument in &call.args {
            let ast::CallArg::Kwarg(name, value) = argument else {
                bail!("template_route_keyword_arguments_required")
            };
            ensure!(
                supplied.insert(*name),
                "template_duplicate_route_argument: {name}"
            );
            let kind = route.input.fields.get(*name).with_context(|| {
                format!("template_unknown_route_argument: {}.{name}", method.name)
            })?;
            ensure!(
                self.expression(value, context)? == input_type(kind)?,
                "template_route_argument_type: {}.{name}",
                method.name
            );
        }
        for name in route.required {
            ensure!(
                supplied.contains(name),
                "template_missing_route_argument: {}.{name}",
                method.name
            );
        }
        Ok(true)
    }

    fn expression(&self, expr: &ast::Expr<'_>, context: &Type) -> Result<Type> {
        use ast::{BinOpKind as B, Expr as E, UnaryOpKind as U};
        match expr {
            E::Var(var) => match context {
                Type::Record(fields) => fields
                    .get(var.id)
                    .cloned()
                    .with_context(|| format!("template_unknown_field: {}", var.id)),
                _ => bail!("template_context_record_required"),
            },
            E::GetAttr(attr) => match self.expression(&attr.expr, context)? {
                Type::Record(fields) => fields
                    .get(attr.name)
                    .cloned()
                    .with_context(|| format!("template_unknown_field: {}", attr.name)),
                _ => bail!("template_field_access_requires_record: {}", attr.name),
            },
            E::Const(value) if value.value.as_str().is_some() => Ok(Type::String),
            E::Const(value) if value.value.kind() == minijinja::value::ValueKind::Bool => {
                Ok(Type::Boolean)
            }
            E::Const(value) if value.value.as_i64().is_some() => Ok(Type::Integer),
            E::Call(call) => {
                ensure!(
                    matches!(&call.expr, E::Var(var) if var.id == "asset"),
                    "template_function_not_admitted"
                );
                let [ast::CallArg::Pos(E::Const(key))] = call.args.as_slice() else {
                    bail!("template_asset_literal_required");
                };
                let key = key
                    .value
                    .as_str()
                    .context("template_asset_literal_required")?;
                ensure!(
                    self.assets.contains_key(key),
                    "template_unknown_asset: {key}"
                );
                Ok(Type::String)
            }
            E::Filter(filter) => {
                ensure!(
                    filter.name == "length" && filter.args.is_empty(),
                    "template_filter_not_admitted: {}",
                    filter.name
                );
                let shape = self.expression(
                    filter.expr.as_ref().context("template_filter_value")?,
                    context,
                )?;
                ensure!(
                    matches!(shape, Type::String | Type::List(_)),
                    "template_length_requires_list_or_string"
                );
                Ok(Type::Integer)
            }
            E::UnaryOp(op) => {
                let shape = self.expression(&op.expr, context)?;
                match op.op {
                    U::Not => {
                        ensure!(shape == Type::Boolean, "template_not_requires_boolean");
                        Ok(Type::Boolean)
                    }
                    U::Neg => {
                        ensure!(shape == Type::Integer, "template_neg_requires_integer");
                        Ok(Type::Integer)
                    }
                }
            }
            E::BinOp(op) => {
                let left = self.expression(&op.left, context)?;
                let right = self.expression(&op.right, context)?;
                ensure!(
                    left == right && scalar(&left),
                    "template_operator_type_mismatch"
                );
                match op.op {
                    B::Eq | B::Ne => Ok(Type::Boolean),
                    B::Lt | B::Lte | B::Gt | B::Gte => {
                        ensure!(
                            matches!(left, Type::String | Type::Integer),
                            "template_comparison_type"
                        );
                        Ok(Type::Boolean)
                    }
                    B::ScAnd | B::ScOr => {
                        ensure!(left == Type::Boolean, "template_boolean_operator_type");
                        Ok(Type::Boolean)
                    }
                    B::Add | B::Sub | B::Mul | B::FloorDiv | B::Rem => {
                        ensure!(
                            left == Type::Integer,
                            "template_arithmetic_requires_integer"
                        );
                        Ok(Type::Integer)
                    }
                    _ => bail!("template_operator_not_admitted"),
                }
            }
            E::IfExpr(branch) => {
                ensure!(
                    self.expression(&branch.test_expr, context)? == Type::Boolean,
                    "template_condition_requires_boolean"
                );
                let yes = self.expression(&branch.true_expr, context)?;
                let no = self.expression(
                    branch
                        .false_expr
                        .as_ref()
                        .context("template_expression_else_required")?,
                    context,
                )?;
                ensure!(yes == no && scalar(&yes), "template_branch_type_mismatch");
                Ok(yes)
            }
            _ => bail!("template_expression_not_admitted: {}", expr.description()),
        }
    }

    fn template(&mut self, path: &str, context: &Type) -> Result<Vec<String>> {
        path_name(path)?;
        ensure!(
            self.stack.len() < 16 && !self.stack.iter().any(|name| name == path),
            "template_include_cycle_or_depth: {path}"
        );
        let source = self
            .sources
            .get(path)
            .with_context(|| format!("template_include_not_found: {path}"))?;
        let ast = parse(source, path)?;
        self.stack.push(path.into());
        let result = self
            .statement(&ast, context)
            .with_context(|| format!("ui/{path}"));
        self.stack.pop();
        result
    }

    fn statements(&mut self, statements: &[ast::Stmt<'_>], context: &Type) -> Result<Vec<String>> {
        let mut variants = vec![String::new()];
        for statement in statements {
            variants = combine(variants, self.statement(statement, context)?)?;
        }
        Ok(variants)
    }

    fn statement(&mut self, statement: &ast::Stmt<'_>, context: &Type) -> Result<Vec<String>> {
        use ast::{Expr as E, Stmt as S};
        match statement {
            S::Template(template) => self.statements(&template.children, context),
            S::EmitRaw(raw) => Ok(vec![raw.raw.into()]),
            S::EmitExpr(emit) => {
                let navigation = self.navigation(&emit.expr, context)?;
                let shape = if navigation {
                    Type::String
                } else {
                    self.expression(&emit.expr, context)?
                };
                ensure!(scalar(&shape), "template_output_requires_scalar");
                ensure!(self.dynamic.len() < 4096, "template_expression_budget");
                let marker = format!("{MARKER}{:06}end", self.dynamic.len());
                self.dynamic.insert(
                    marker.clone(),
                    Dynamic {
                        shape,
                        asset: !navigation && matches!(&emit.expr, E::Call(_)),
                        navigation,
                        literal: match &emit.expr {
                            E::Const(value) => value.value.as_str().map(str::to_owned),
                            _ => None,
                        },
                    },
                );
                Ok(vec![marker])
            }
            S::IfCond(branch) => {
                ensure!(
                    self.expression(&branch.expr, context)? == Type::Boolean,
                    "template_condition_requires_boolean"
                );
                let mut variants = self.statements(&branch.true_body, context)?;
                variants.extend(self.statements(&branch.false_body, context)?);
                ensure!(variants.len() <= MAX_VARIANTS, "template_branch_budget");
                Ok(variants)
            }
            S::ForLoop(loop_) => {
                ensure!(
                    !loop_.recursive && loop_.filter_expr.is_none(),
                    "template_recursive_or_filtered_loop_not_admitted"
                );
                let Type::List(item) = self.expression(&loop_.iter, context)? else {
                    bail!("template_loop_requires_list")
                };
                let E::Var(target) = &loop_.target else {
                    bail!("template_loop_variable_required")
                };
                let Type::Record(mut fields) = context.clone() else {
                    bail!("template_context_record_required")
                };
                ensure!(
                    !["loop", "asset"].contains(&target.id)
                        && (self.routes.is_none() || !["routes", "platform"].contains(&target.id))
                        && !fields.contains_key(target.id),
                    "template_loop_variable_shadowing"
                );
                fields.insert(target.id.into(), *item);
                fields.insert(
                    "loop".into(),
                    Type::Record(BTreeMap::from([
                        ("index".into(), Type::Integer),
                        ("index0".into(), Type::Integer),
                        ("first".into(), Type::Boolean),
                        ("last".into(), Type::Boolean),
                        ("length".into(), Type::Integer),
                    ])),
                );
                let mut variants = self.statements(&loop_.body, &Type::Record(fields))?;
                // A repeated body must return to the same HTML element stack.
                // Checking this independently makes the invariant hold for every iteration.
                for variant in &variants {
                    balanced(variant)?;
                    let html = Html::parse_fragment(variant);
                    if html
                        .select(&Selector::parse("[data-live]").expect("static selector"))
                        .next()
                        .is_some()
                    {
                        self.repeated_live_regions = true;
                    }
                    if html
                        .select(&Selector::parse("form[data-command]").expect("static selector"))
                        .next()
                        .is_some()
                    {
                        self.repeated_live_forms = true;
                    }
                }
                variants.extend(self.statements(&loop_.else_body, context)?);
                ensure!(variants.len() <= MAX_VARIANTS, "template_branch_budget");
                Ok(variants)
            }
            S::Include(include) => {
                ensure!(
                    !include.ignore_missing,
                    "template_optional_include_not_admitted"
                );
                let E::Const(name) = &include.name else {
                    bail!("template_include_literal_required")
                };
                self.template(
                    name.value
                        .as_str()
                        .context("template_include_literal_required")?,
                    context,
                )
            }
            _ => bail!(
                "template_statement_not_admitted: use interpolation, if, for and literal include"
            ),
        }
    }
}

fn combine(left: Vec<String>, right: Vec<String>) -> Result<Vec<String>> {
    ensure!(
        left.len().saturating_mul(right.len()) <= MAX_VARIANTS,
        "template_branch_budget: simplify independently conditional HTML (maximum {MAX_VARIANTS} structural variants)"
    );
    let mut variants = Vec::new();
    for a in &left {
        for b in &right {
            ensure!(
                a.len() + b.len() <= MAX_HTML_BYTES,
                "template_markup_budget"
            );
            variants.push(format!("{a}{b}"));
        }
    }
    Ok(variants)
}

fn analyze<'a>(
    sources: &'a BTreeMap<String, String>,
    path: &str,
    context: &Type,
    assets: &'a assets::Catalog,
    routes: Option<&'a crate::routing::Catalog>,
) -> Result<(Analysis<'a>, Vec<String>)> {
    if routes.is_some() {
        let Type::Record(fields) = context else {
            bail!("template_context_record_required")
        };
        ensure!(
            !["asset", "routes", "platform"]
                .iter()
                .any(|name| fields.contains_key(*name)),
            "template_reserved_context_name"
        );
    }
    let mut analysis = Analysis {
        sources,
        assets,
        stack: Vec::new(),
        dynamic: BTreeMap::new(),
        routes,
        repeated_live_regions: false,
        repeated_live_forms: false,
    };
    let variants = analysis.template(path, context)?;
    for markup in &variants {
        check_html_policy(markup, Some(&analysis.dynamic), routes.is_some())?;
    }
    Ok((analysis, variants))
}

pub fn validate_page(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: &Type,
    assets: &assets::Catalog,
) -> Result<()> {
    analyze(&sources(directory, catalog)?, path, context, assets, None)?;
    Ok(())
}

pub fn validate_routed_page(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: &Type,
    assets: &assets::Catalog,
    routes: &crate::routing::Catalog,
) -> Result<()> {
    analyze(
        &sources(directory, catalog)?,
        path,
        context,
        assets,
        Some(routes),
    )?;
    Ok(())
}

/// Live regions keep the same targets in every admitted template branch. Their
/// contents may change, but form drafts and their original versions stay outside.
pub fn validate_live_page(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: &Type,
    assets: &assets::Catalog,
    routes: Option<&crate::routing::Catalog>,
) -> Result<()> {
    let sources = sources(directory, catalog)?;
    let (analysis, variants) = analyze(&sources, path, context, assets, routes)?;
    validate_live_variants(&analysis, &variants)
}

fn validate_live_variants(analysis: &Analysis<'_>, variants: &[String]) -> Result<()> {
    ensure!(
        !analysis.repeated_live_regions,
        "template_live_region_in_loop: place data-live outside the loop"
    );
    ensure!(
        !analysis.repeated_live_forms,
        "template_live_form_in_loop: place command forms outside the loop"
    );
    let mut expected = None;
    let mut expected_forms = None;
    for markup in variants {
        let html = check_html_policy(markup, Some(&analysis.dynamic), analysis.routes.is_some())?;
        let regions = checked_live_regions(&html)?;
        let ids: BTreeSet<_> = regions.keys().cloned().collect();
        ensure!(
            ids.iter().all(|id| !id.contains(MARKER)),
            "template_live_region_id_must_be_literal"
        );
        if let Some(expected) = &expected {
            ensure!(
                &ids == expected,
                "template_live_regions_must_exist_in_every_branch"
            );
        } else {
            expected = Some(ids);
        }
        let mut forms = BTreeMap::new();
        for form in html.select(&Selector::parse("form[data-command]").expect("static selector")) {
            let id = form
                .value()
                .attr("id")
                .context("template_live_form_id_required")?;
            ensure!(
                !id.contains(MARKER),
                "template_live_form_id_must_be_literal"
            );
            ensure!(
                literal_html_id(id),
                "template_live_form_id: expected a literal HTML identifier"
            );
            ensure!(
                html.select(&Selector::parse("[id]").expect("static selector"))
                    .filter(|element| element.value().attr("id") == Some(id))
                    .count()
                    == 1,
                "template_live_form_id_not_unique: {id}"
            );
            forms.insert(
                id.to_owned(),
                form.value().attr("data-command").unwrap().to_owned(),
            );
        }
        if let Some(expected) = &expected_forms {
            ensure!(
                &forms == expected,
                "template_live_forms_must_exist_in_every_branch"
            );
        } else {
            expected_forms = Some(forms);
        }
    }
    Ok(())
}

/// Extract admitted, rendered application regions, including after platform form
/// binding. Only the regions are rechecked against app HTML policy: the surrounding
/// page can contain the platform's generated form attributes and reserved IDs.
pub fn live_regions(markup: &str) -> Result<BTreeMap<String, String>> {
    ensure!(markup.len() <= MAX_HTML_BYTES, "template_markup_budget");
    balanced(markup)?;
    let html = Html::parse_fragment(markup);
    ensure!(html.errors.is_empty(), "template_live_html_parse_error");
    ensure!(
        html.tree.nodes().count() <= 8192,
        "template_html_node_budget"
    );
    let regions = checked_live_regions(&html)?;
    for region in regions.values() {
        parse_checked(region)?;
    }
    Ok(regions)
}

fn literal_html_id(id: &str) -> bool {
    id.len() <= 128
        && id.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn checked_live_regions(html: &Html) -> Result<BTreeMap<String, String>> {
    let live = Selector::parse("[data-live]").expect("static selector");
    let editable =
        Selector::parse("form,input,textarea,select,button,option,optgroup,[contenteditable]")
            .expect("static selector");
    let mut all_ids = BTreeMap::<_, usize>::new();
    for element in html.select(&Selector::parse("[id]").expect("static selector")) {
        *all_ids
            .entry(element.value().attr("id").unwrap())
            .or_default() += 1;
    }
    let mut regions = BTreeMap::new();
    for region in html.select(&live) {
        let element = region.value();
        ensure!(
            element.attr("data-live") == Some(""),
            "template_live_marker_must_be_empty: use data-live"
        );
        let id = element
            .attr("id")
            .context("template_live_region_id_required")?;
        ensure!(
            literal_html_id(id),
            "template_live_region_id: expected a literal HTML identifier"
        );
        ensure!(
            all_ids.get(id) == Some(&1),
            "template_live_region_id_not_unique: {id}"
        );
        ensure!(
            !editable.matches(&region) && region.select(&editable).next().is_none(),
            "template_live_region_contains_editable: {id}"
        );
        for ancestor in region.ancestors().filter_map(scraper::ElementRef::wrap) {
            ensure!(
                ancestor.value().attr("data-live").is_none(),
                "template_live_regions_must_not_nest: {id}"
            );
            ensure!(
                ancestor.value().name() != "form"
                    && ancestor.value().attr("contenteditable").is_none(),
                "template_live_region_inside_editable: {id}"
            );
        }
        regions.insert(id.to_owned(), region.html());
    }
    ensure!(!regions.is_empty(), "template_live_region_required");
    ensure!(regions.len() <= 32, "template_live_region_budget");
    Ok(regions)
}

fn input_type(kind: &crate::schema::Kind) -> Result<Type> {
    Ok(match kind {
        crate::schema::Kind::Integer
        | crate::schema::Kind::PageSize
        | crate::schema::Kind::Unsigned(_) => Type::Integer,
        crate::schema::Kind::RowVersion => Type::RowVersion,
        crate::schema::Kind::StandardText { domain } => Type::StandardText {
            domain: domain.clone(),
        },
        crate::schema::Kind::ModelReference { prefix, .. } => Type::ModelReference {
            roc_type: String::new(),
            prefix: prefix.clone(),
        },
        crate::schema::Kind::Boolean => Type::Boolean,
        crate::schema::Kind::OptionalText => {
            bail!("template_optional_route_argument_not_supported")
        }
        crate::schema::Kind::InputShape { .. } => {
            bail!("template_structured_route_argument_not_supported")
        }
        _ => Type::String,
    })
}

fn tokenizer(
    markup: &str,
) -> impl Iterator<Item = Result<Token<usize>, std::convert::Infallible>> + '_ {
    let mut emitter = DefaultEmitter::<usize>::new_with_span();
    emitter.naively_switch_states(true);
    Tokenizer::new_with_emitter(markup, emitter)
}

fn name(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).context("template_html_utf8")
}

fn balanced(markup: &str) -> Result<()> {
    let mut stack = Vec::new();
    for token in tokenizer(markup) {
        match token? {
            Token::StartTag(tag) => {
                let tag_name = name(&tag.name)?;
                ensure!(
                    !tag.self_closing
                        || VOID.contains(&tag_name)
                        || stack.iter().any(|tag| tag == "svg"),
                    "template_html_self_closing: {tag_name}"
                );
                if !VOID.contains(&tag_name) && !tag.self_closing {
                    stack.push(tag_name.to_owned());
                }
                ensure!(stack.len() <= 48, "template_html_depth_budget");
            }
            Token::EndTag(tag) => {
                let tag_name = name(&tag.name)?;
                ensure!(
                    stack.pop().as_deref() == Some(tag_name),
                    "template_html_unbalanced: {tag_name}"
                );
            }
            Token::Error(error) => bail!("template_html_token_error: {:?}", error.value),
            _ => {}
        }
    }
    ensure!(stack.is_empty(), "template_html_unclosed_element");
    Ok(())
}

fn executable_attribute(name: &str) -> bool {
    // These are the plugins in the pinned Datastar 1.0.1 release. Ordinary
    // app data attributes remain data, not executable expression contexts.
    [
        "attr",
        "bind",
        "class",
        "computed",
        "effect",
        "indicator",
        "init",
        "json-signals",
        "on",
        "ref",
        "show",
        "signals",
        "style",
        "text",
    ]
    .iter()
    .any(|plugin| {
        name.strip_prefix(&format!("data-{plugin}"))
            .is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix.starts_with(':')
                    || suffix.starts_with('-')
                    || suffix.starts_with("__")
            })
    })
}

fn check_html(markup: &str, dynamic: Option<&BTreeMap<String, Dynamic>>) -> Result<Html> {
    check_html_policy(markup, dynamic, false)
}

fn check_html_policy(
    markup: &str,
    dynamic: Option<&BTreeMap<String, Dynamic>>,
    routed: bool,
) -> Result<Html> {
    ensure!(markup.len() <= MAX_HTML_BYTES, "template_markup_budget");
    balanced(markup)?;
    let mut seen = BTreeSet::new();
    for token in tokenizer(markup) {
        match token? {
            Token::StartTag(tag) => {
                let tag_name = name(&tag.name)?;
                validate_tag(tag_name)?;
                ensure!(tag.attributes.len() <= 64, "template_attribute_budget");
                for (attr, value) in &tag.attributes {
                    let attr = name(attr)?;
                    let value_text = name(value)?;
                    let markers: Vec<_> = dynamic
                        .into_iter()
                        .flat_map(BTreeMap::iter)
                        .filter(|(marker, _)| value_text.contains(marker.as_str()))
                        .collect();
                    if attr == "src" && dynamic.is_some() {
                        ensure!(
                            markers.len() == 1 && markers[0].1.asset && value_text == markers[0].0,
                            "template_image_src_requires_asset_helper"
                        );
                    }
                    if routed
                        && (attr == "href" || attr == "xlink:href")
                        && ["a", "area"].contains(&tag_name)
                    {
                        if markers.is_empty() {
                            ensure!(
                                value_text.starts_with('#') || absolute_web_url(value_text).is_ok(),
                                "template_internal_href_requires_route_helper"
                            );
                        } else {
                            ensure!(
                                markers.len() == 1
                                    && value_text == markers[0].0
                                    && markers[0].1.shape == Type::String
                                    && !markers[0].1.asset,
                                "template_href_requires_whole_url: use routes.page(arguments) or a complete external URL value"
                            );
                            if let Some(literal) = &markers[0].1.literal {
                                absolute_web_url(literal)
                                    .context("template_internal_href_requires_route_helper")?;
                            }
                        }
                    }
                    for (marker, binding) in &markers {
                        if binding.navigation {
                            ensure!(
                                routed
                                    && ["a", "area"].contains(&tag_name)
                                    && attr == "href"
                                    && value_text == marker.as_str(),
                                "template_route_helper_requires_exact_href"
                            );
                        }
                        let raw = markup
                            .get(value.span.start..value.span.end)
                            .context("template_attribute_span")?;
                        let suffix = raw
                            .get(attr.len()..)
                            .context("template_attribute_span")?
                            .trim_start();
                        let suffix = suffix
                            .strip_prefix('=')
                            .context("template_interpolation_requires_quoted_attribute")?
                            .trim_start();
                        ensure!(
                            suffix.starts_with(['\'', '"']),
                            "template_interpolation_requires_quoted_attribute: {attr}"
                        );
                        ensure!(
                            !executable_attribute(attr)
                                && !attr.starts_with("on")
                                && ![
                                    "style",
                                    "data-command",
                                    "data-platform",
                                    "name",
                                    "type",
                                    "form",
                                    "action",
                                    "method",
                                    "srcset",
                                    "fill",
                                    "stroke",
                                    "filter",
                                    "clip-path",
                                    "mask",
                                    "cursor",
                                    "marker",
                                    "marker-start",
                                    "marker-mid",
                                    "marker-end"
                                ]
                                .contains(&attr),
                            "template_interpolation_context_forbidden: {attr}"
                        );
                        if attr == "src" {
                            ensure!(
                                binding.asset && value_text == marker.as_str(),
                                "template_image_src_requires_asset_helper"
                            );
                        }
                        seen.insert(marker.to_string());
                    }
                    validate_attribute(tag_name, attr, value_text, !markers.is_empty())?;
                }
            }
            Token::String(value) => {
                if let Some(dynamic) = dynamic {
                    let value = name(&value)?;
                    for marker in dynamic
                        .keys()
                        .filter(|marker| value.contains(marker.as_str()))
                    {
                        ensure!(
                            !dynamic[marker].navigation,
                            "template_route_helper_requires_exact_href"
                        );
                        seen.insert(marker.clone());
                    }
                }
            }
            Token::Doctype(_) => bail!("template_body_fragment_required"),
            Token::Error(error) => bail!("template_html_token_error: {:?}", error.value),
            _ => {}
        }
    }
    if let Some(dynamic) = dynamic {
        for marker in dynamic
            .keys()
            .filter(|marker| markup.contains(marker.as_str()))
        {
            ensure!(
                seen.contains(marker),
                "template_interpolation_context_forbidden: tags, attribute names and comments must be literal"
            );
        }
    }
    let html = Html::parse_fragment(markup);
    ensure!(
        html.errors.is_empty(),
        "template_html_parse_error: {:?}",
        html.errors
    );
    ensure!(
        html.tree.nodes().count() <= 8192,
        "template_html_node_budget"
    );
    Ok(html)
}

fn validate_tag(tag: &str) -> Result<()> {
    ensure!(
        tag.len() <= 80
            && tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "template_html_tag_name"
    );
    ensure!(
        ![
            "script",
            "style",
            "link",
            "meta",
            "base",
            "iframe",
            "frame",
            "frameset",
            "object",
            "embed",
            "html",
            "head",
            "body",
            "foreignobject",
            "animate",
            "animatemotion",
            "animatetransform",
            "set",
            "math",
            "noscript",
            "plaintext",
            "xmp",
            "listing"
        ]
        .contains(&tag),
        "template_html_tag_not_admitted: {tag}"
    );
    Ok(())
}

fn validate_attribute(tag: &str, attr: &str, value: &str, interpolated: bool) -> Result<()> {
    ensure!(
        attr.len() <= 128 && value.len() <= 16_384,
        "template_attribute_budget"
    );
    ensure!(
        !attr.starts_with("on")
            && ![
                "srcset",
                "imagesrcset",
                "imagesizes",
                "poster",
                "srcdoc",
                "data",
                "background",
                "ping",
                "formaction",
                "formmethod",
                "formenctype",
                "formtarget",
                "action",
                "method",
                "form",
                "http-equiv",
                "xmlns:xlink",
                "xml:base",
                "nonce",
                "integrity",
                "is"
            ]
            .contains(&attr),
        "template_html_attribute_not_admitted: {attr}"
    );
    if tag == "form" {
        ensure!(
            !["enctype", "target"].contains(&attr)
                && !attr.starts_with("data-on:submit")
                && !attr.starts_with("data-on-submit")
                && !attr.starts_with("data-day2-")
                && !attr.starts_with("data-attr:action")
                && !attr.starts_with("data-attr:method"),
            "template_reserved_form_transport_attribute"
        );
    }
    if attr == "src" {
        ensure!(
            tag == "img"
                && (interpolated
                    || value.starts_with("/assets/app/")
                    || value.starts_with("/assets/instance/")),
            "template_image_src_requires_asset_helper"
        );
    }
    if attr == "href" || attr == "xlink:href" {
        if tag == "a" || tag == "area" {
            if !interpolated {
                validate_href(value)?;
            }
        } else {
            ensure!(
                value.starts_with('#') && !interpolated,
                "template_resource_href_forbidden"
            );
        }
    }
    if attr == "style" {
        crate::web_resources::validate_inline_style(value)?;
    }
    if [
        "fill",
        "stroke",
        "filter",
        "clip-path",
        "mask",
        "cursor",
        "marker",
        "marker-start",
        "marker-mid",
        "marker-end",
    ]
    .contains(&attr)
    {
        crate::web_resources::validate_inline_style(&format!("{attr}:{value}"))?;
    }
    if attr == "xmlns" {
        ensure!(
            tag == "svg" && value == "http://www.w3.org/2000/svg",
            "template_namespace_not_admitted"
        );
    }
    if attr == "id" {
        ensure!(!value.starts_with("day2-"), "template_reserved_id");
    }
    Ok(())
}

fn validate_href(value: &str) -> Result<()> {
    ensure!(
        !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
            && !value.contains('\\'),
        "template_invalid_href"
    );
    if value.starts_with('#') || (value.starts_with('/') && !value.starts_with("//")) {
        return Ok(());
    }
    absolute_web_url(value)?;
    Ok(())
}

fn absolute_web_url(value: &str) -> Result<url::Url> {
    ensure!(
        !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
            && !value.contains('\\'),
        "template_invalid_href"
    );
    let url = url::Url::parse(value).context("template_invalid_href")?;
    ensure!(
        matches!(url.scheme(), "https" | "http")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "template_invalid_href"
    );
    Ok(url)
}

pub fn parse_checked(markup: &str) -> Result<Html> {
    check_html(markup, None)
}

pub fn validate_bindings(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: &Type,
    assets: &assets::Catalog,
    operations: &[crate::artifact::Operation],
    schema: &crate::schema::Schema,
) -> Result<()> {
    let sources = sources(directory, catalog)?;
    let (analysis, variants) = analyze(&sources, path, context, assets, None)?;
    validate_forms(&analysis, &variants, operations, schema)
}

pub fn validate_routed_bindings(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: &Type,
    assets: &assets::Catalog,
    routes: &crate::routing::Catalog,
    artifact: &crate::artifact::Artifact,
) -> Result<()> {
    let sources = sources(directory, catalog)?;
    let (analysis, variants) = analyze(&sources, path, context, assets, Some(routes))?;
    validate_forms(&analysis, &variants, &artifact.operations, &artifact.schema)
}

fn validate_forms(
    analysis: &Analysis<'_>,
    variants: &[String],
    operations: &[crate::artifact::Operation],
    schema: &crate::schema::Schema,
) -> Result<()> {
    let forms = Selector::parse("form").expect("static selector");
    for markup in variants {
        let html = check_html_policy(markup, Some(&analysis.dynamic), analysis.routes.is_some())?;
        for form in html.select(&forms) {
            let controls = crate::web_forms::controls(form)?;
            if form.value().attr("data-platform") == Some("sign-out") {
                ensure!(
                    form.value().attr("data-command").is_none() && controls.is_empty(),
                    "template_sign_out_binding"
                );
                continue;
            }
            let command = form
                .value()
                .attr("data-command")
                .context("template_form_command_required")?;
            ensure!(
                form.value().attr("data-platform").is_none(),
                "template_unknown_platform_form"
            );
            let operation = operations
                .iter()
                .find(|op| op.kind == "command" && op.name == command)
                .with_context(|| format!("template_unknown_command: {command}"))?;
            let input = schema
                .inputs
                .get(&operation.input_type)
                .context("template_unknown_input_contract")?;
            let mut names = BTreeSet::new();
            let mut keyed = BTreeSet::new();
            for control in &controls {
                let (field, key) = crate::web_forms::split_control(&control.name);
                let kind = input.fields.get(field).with_context(|| {
                    format!("template_unknown_command_field: {command}.{field}")
                })?;
                let carried = crate::web_forms::carrier(kind);
                // A declared collection may contribute several controls; every other
                // field keeps the one-control rule, so a repeated name cannot
                // silently become a collection.
                match carried {
                    crate::web_forms::Carrier::Scalar => ensure!(
                        names.insert(field),
                        "template_duplicate_form_field: {field}"
                    ),
                    crate::web_forms::Carrier::Map => {
                        let key = key.with_context(|| {
                            format!("template_map_form_field_requires_key: {command}.{field}")
                        })?;
                        day2_contracts::names::identifier(key)?;
                        ensure!(
                            keyed.insert((field, key)),
                            "template_duplicate_form_field: {field}.{key}"
                        );
                        names.insert(field);
                    }
                    _ => {
                        names.insert(field);
                    }
                }
                ensure!(
                    carried == crate::web_forms::Carrier::Map || key.is_none(),
                    "template_unexpected_form_field_key: {field}"
                );
                ensure!(
                    !matches!(kind, crate::schema::Kind::OptionalText)
                        && (!matches!(kind, crate::schema::Kind::InputShape { .. })
                            || carried != crate::web_forms::Carrier::Scalar),
                    "template_optional_or_structured_form_field_unsupported"
                );
                // A collection is authored as editable controls; a hidden row binding
                // is moved into the signed ticket, which carries one value per field.
                ensure!(
                    carried == crate::web_forms::Carrier::Scalar || !control.hidden,
                    "template_hidden_collection_form_field_unsupported"
                );
                if control.hidden {
                    let value = control.value.as_str();
                    let bindings: Vec<_> = analysis
                        .dynamic
                        .iter()
                        .filter(|(marker, _)| value.contains(marker.as_str()))
                        .collect();
                    if !bindings.is_empty() {
                        let expected = input_type(kind)?;
                        for (_, binding) in &bindings {
                            ensure!(
                                binding.shape == expected,
                                "template_hidden_binding_type: {command}.{field}"
                            );
                        }
                        ensure!(
                            expected == Type::String
                                || (bindings.len() == 1 && value == bindings[0].0),
                            "template_hidden_binding_scalar_required: {field}"
                        );
                    } else {
                        let value = crate::web_security::field_value(kind, value)?;
                        crate::schema::Record {
                            fields: BTreeMap::from([(field.to_owned(), kind.clone())]),
                            roc_type: None,
                            identity: None,
                        }
                        .validate_input(&serde_json::json!({field: value}))?;
                    }
                }
            }
            ensure!(
                names == input.fields.keys().map(String::as_str).collect(),
                "template_incomplete_command_fields: {command}"
            );
        }
    }
    Ok(())
}

#[derive(Default)]
struct Emissions {
    bytes: usize,
    values: Vec<Emission>,
}

struct Emission {
    start: usize,
    end: usize,
    navigation: bool,
}

struct BoundedOutput(Vec<u8>, Option<Arc<Mutex<Emissions>>>);

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_HTML_BYTES {
            return Err(io::Error::other("template_render_budget"));
        }
        self.0.extend_from_slice(bytes);
        if let Some(emissions) = &self.1 {
            emissions
                .lock()
                .map_err(|_| io::Error::other("template_emission_state"))?
                .bytes = self.0.len();
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn render(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: serde_json::Value,
    asset_urls: BTreeMap<String, String>,
) -> Result<String> {
    let sources = sources(directory, catalog)?;
    let environment = environment(&sources, asset_urls)?;
    let mut output = BoundedOutput(Vec::new(), None);
    environment
        .get_template(path)?
        .render_to_write(context, &mut output)?;
    let markup = String::from_utf8(output.0)?;
    parse_checked(&markup)?;
    Ok(markup)
}

fn environment<'a>(
    sources: &'a BTreeMap<String, String>,
    asset_urls: BTreeMap<String, String>,
) -> Result<Environment<'a>> {
    let mut environment = Environment::empty();
    environment.set_auto_escape_callback(|_| AutoEscape::Html);
    environment.set_undefined_behavior(UndefinedBehavior::Strict);
    environment.set_fuel(Some(200_000));
    environment.set_recursion_limit(32);
    environment.add_filter("length", |value: minijinja::Value| {
        value.len().ok_or_else(|| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "length requires a list or string",
            )
        })
    });
    environment.add_function("asset", move |key: String| {
        asset_urls.get(&key).cloned().ok_or_else(|| {
            minijinja::Error::new(
                minijinja::ErrorKind::InvalidOperation,
                "asset is not admitted",
            )
        })
    });
    for (name, source) in sources {
        environment.add_template(name, source)?;
    }
    Ok(environment)
}

#[derive(Debug)]
struct Navigation(String);
impl minijinja::value::Object for Navigation {}

#[derive(Debug)]
struct Routes(crate::routing::Catalog);

fn template_error(error: impl std::fmt::Display) -> minijinja::Error {
    minijinja::Error::new(minijinja::ErrorKind::InvalidOperation, error.to_string())
}

impl minijinja::value::Object for Routes {
    fn call_method(
        self: &Arc<Self>,
        _state: &minijinja::State<'_, '_>,
        method: &str,
        args: &[minijinja::Value],
    ) -> std::result::Result<minijinja::Value, minijinja::Error> {
        let (kwargs,): (minijinja::value::Kwargs,) = minijinja::value::from_args(args)?;
        let mut input = serde_json::Map::new();
        for name in kwargs.args() {
            let value: minijinja::Value = kwargs.get(name)?;
            input.insert(
                name.into(),
                serde_json::to_value(value).map_err(template_error)?,
            );
        }
        kwargs.assert_all_used()?;
        let url = self
            .0
            .build_url(method, &serde_json::Value::Object(input))
            .map_err(template_error)?;
        Ok(minijinja::Value::from_object(Navigation(url)))
    }
}

#[derive(Debug)]
struct Platform;

impl minijinja::value::Object for Platform {
    fn call_method(
        self: &Arc<Self>,
        _state: &minijinja::State<'_, '_>,
        method: &str,
        args: &[minijinja::Value],
    ) -> std::result::Result<minijinja::Value, minijinja::Error> {
        if !args.is_empty() {
            return Err(template_error("template_unknown_platform_navigation"));
        }
        let path = match method {
            "audit" => "/audit",
            "docs" => crate::openapi::DOCS_PATH,
            "openapi" => crate::openapi::SPEC_PATH,
            _ => return Err(template_error("template_unknown_platform_navigation")),
        };
        Ok(minijinja::Value::from_object(Navigation(path.into())))
    }
}

pub fn render_routed(
    directory: &Path,
    catalog: &Catalog,
    path: &str,
    context: serde_json::Value,
    asset_urls: BTreeMap<String, String>,
    routes: &crate::routing::Catalog,
    origin: &str,
) -> Result<String> {
    let sources = sources(directory, catalog)?;
    let fields = context
        .as_object()
        .context("template_context_record_required")?;
    ensure!(
        !["asset", "routes", "platform"]
            .iter()
            .any(|name| fields.contains_key(*name)),
        "template_reserved_context_name"
    );
    let mut environment = environment(&sources, asset_urls)?;
    environment.add_global(
        "routes",
        minijinja::Value::from_object(Routes(routes.clone())),
    );
    environment.add_global("platform", minijinja::Value::from_object(Platform));
    let emissions = Arc::new(Mutex::new(Emissions::default()));
    let output_emissions = emissions.clone();
    // Record actual formatter output positions, not guessable marker strings or
    // URL membership. JSON data cannot manufacture the host's Navigation type.
    environment.set_formatter(move |output, state, value| {
        let start = output_emissions.lock().map_err(template_error)?.bytes;
        let navigation = value.downcast_object_ref::<Navigation>();
        if let Some(navigation) = navigation {
            minijinja::escape_formatter(
                output,
                state,
                &minijinja::Value::from(navigation.0.as_str()),
            )?;
        } else {
            minijinja::escape_formatter(output, state, value)?;
        }
        let mut emissions = output_emissions.lock().map_err(template_error)?;
        if emissions.values.len() >= 8192 {
            return Err(template_error("template_emission_budget"));
        }
        let end = emissions.bytes;
        emissions.values.push(Emission {
            start,
            end,
            navigation: navigation.is_some(),
        });
        Ok(())
    });
    let mut output = BoundedOutput(Vec::new(), Some(emissions.clone()));
    environment
        .get_template(path)?
        .render_to_write(context, &mut output)?;
    let markup = String::from_utf8(output.0)?;
    let html = parse_checked(&markup)?;
    check_navigation(
        &markup,
        &html,
        &emissions
            .lock()
            .map_err(|_| anyhow::anyhow!("template_emission_state"))?
            .values,
        origin,
    )?;
    Ok(markup)
}

fn quoted_value_span(
    markup: &str,
    attr: &str,
    span: html5gum::Span<usize>,
) -> Result<Option<std::ops::Range<usize>>> {
    let raw = markup
        .get(span.start..span.end)
        .context("template_attribute_span")?;
    let suffix = raw
        .get(attr.len()..)
        .context("template_attribute_span")?
        .trim_start();
    let Some(suffix) = suffix.strip_prefix('=') else {
        return Ok(None);
    };
    let suffix = suffix.trim_start();
    let Some(quote @ (b'\'' | b'"')) = suffix.as_bytes().first().copied() else {
        return Ok(None);
    };
    let start = span.end - suffix.len() + 1;
    let length = markup[start..span.end]
        .find(char::from(quote))
        .context("template_attribute_quote")?;
    Ok(Some(start..start + length))
}

fn check_navigation(markup: &str, html: &Html, emissions: &[Emission], origin: &str) -> Result<()> {
    let origin = absolute_web_url(origin)?.origin();
    let mut used = BTreeSet::new();
    for token in tokenizer(markup) {
        let Token::StartTag(tag) = token? else {
            continue;
        };
        if !["a", "area"].contains(&name(&tag.name)?) {
            continue;
        }
        for (attribute, value) in &tag.attributes {
            let attribute = name(attribute)?;
            if attribute != "href" && attribute != "xlink:href" {
                continue;
            }
            let value_text = name(value)?;
            let relevant: Vec<_> = emissions
                .iter()
                .enumerate()
                .filter(|(_, emission)| {
                    emission.start >= value.span.start && emission.end <= value.span.end
                })
                .collect();
            if let [(index, emission)] = relevant.as_slice()
                && emission.navigation
                && quoted_value_span(markup, attribute, value.span)?
                    == Some(emission.start..emission.end)
            {
                used.insert(*index);
                continue;
            }
            ensure!(
                !relevant.iter().any(|(_, emission)| emission.navigation),
                "template_route_helper_requires_exact_href"
            );
            if value_text.starts_with('#') {
                ensure!(
                    relevant.is_empty(),
                    "template_dynamic_internal_href_requires_route_helper"
                );
            } else {
                let destination = absolute_web_url(value_text)
                    .context("template_internal_href_requires_route_helper")?;
                ensure!(
                    destination.origin() != origin,
                    "template_same_origin_href_requires_route_helper"
                );
            }
        }
    }
    ensure!(
        emissions
            .iter()
            .enumerate()
            .all(|(index, emission)| !emission.navigation || used.contains(&index)),
        "template_route_helper_requires_exact_href"
    );
    validate_fragments(html)
}

pub(crate) fn validate_fragments(html: &Html) -> Result<()> {
    let ids: BTreeSet<_> = html
        .select(&Selector::parse("[id]").expect("static selector"))
        .filter_map(|element| element.value().attr("id"))
        .collect();
    for element in html.select(&Selector::parse("a,area").expect("static selector")) {
        for attribute in ["href", "xlink:href"] {
            let Some(fragment) = element
                .value()
                .attr(attribute)
                .and_then(|value| value.strip_prefix('#'))
            else {
                continue;
            };
            let target = percent_encoding::percent_decode_str(fragment).decode_utf8()?;
            ensure!(
                target.is_empty() || target == "day2-main" || ids.contains(target.as_ref()),
                "template_fragment_target_missing: {fragment}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit_live(source: &str) -> Result<()> {
        let sources = BTreeMap::from([("pages/live.html".into(), source.into())]);
        let context = Type::Record(BTreeMap::from([
            ("ready".into(), Type::Boolean),
            ("title".into(), Type::String),
            ("items".into(), Type::List(Box::new(Type::String))),
        ]));
        let assets = assets::Catalog::new();
        let (analysis, variants) = analyze(&sources, "pages/live.html", &context, &assets, None)?;
        validate_live_variants(&analysis, &variants)
    }

    #[test]
    fn live_regions_admit_empty_lists_and_conditional_contents_with_stable_targets() {
        admit_live(
            "<section id=\"results\" data-live>{% for item in items %}<p>{{ item }}</p>{% else %}<p>Empty</p>{% endfor %}</section><div id=\"status\" data-live>{% if ready %}Ready{% else %}Pending{% endif %}</div><form id=\"revise\" data-command=\"reports.revise\"><textarea name=\"text\">{{ title }}</textarea></form>",
        ).unwrap();
    }

    #[test]
    fn live_region_admission_rejects_unstable_targets() {
        for (source, error) in [
            ("<p>No regions</p>", "template_live_region_required"),
            (
                "<p data-live>Missing ID</p>",
                "template_live_region_id_required",
            ),
            (
                "<p id=\"{{ title }}\" data-live>Dynamic ID</p>",
                "template_live_region_id_must_be_literal",
            ),
            (
                "<p id=\"result\" data-live=\"true\">Invalid marker</p>",
                "template_live_marker_must_be_empty",
            ),
            (
                "<p id=\"result\" data-live>Result</p><p id=\"result\">Duplicate ID</p>",
                "template_live_region_id_not_unique",
            ),
            (
                "{% if ready %}<p id=\"ready\" data-live>Ready</p>{% else %}<p id=\"pending\" data-live>Pending</p>{% endif %}",
                "template_live_regions_must_exist_in_every_branch",
            ),
            (
                "{% for item in items %}<p id=\"result\" data-live>{{ item }}</p>{% else %}<p id=\"result\" data-live>Empty</p>{% endfor %}",
                "template_live_region_in_loop",
            ),
            (
                "<section id=\"outer\" data-live><p id=\"inner\" data-live>Nested</p></section>",
                "template_live_regions_must_not_nest",
            ),
        ] {
            let failure = admit_live(source).expect_err(source);
            assert!(
                format!("{failure:#}").contains(error),
                "{source}: {failure:#}"
            );
        }
    }

    #[test]
    fn live_regions_cannot_replace_drafts_or_their_expected_versions() {
        for contents in [
            "<form data-command=\"reports.revise\"></form>",
            "<input type=\"hidden\" name=\"expected_version\" value=\"1\">",
            "<input name=\"title\">",
            "<textarea name=\"text\">Draft</textarea>",
            "<select name=\"choice\"><option>First</option></select>",
            "<button type=\"button\">Act</button>",
            "<p contenteditable=\"true\">Draft</p>",
        ] {
            let source = format!("<section id=\"result\" data-live>{contents}</section>");
            assert!(
                format!("{:#}", admit_live(&source).unwrap_err())
                    .contains("template_live_region_contains_editable")
            );
            assert!(live_regions(&source).is_err());
        }
        for source in [
            "<textarea id=\"draft\" data-live>Draft</textarea>",
            "<form data-command=\"reports.revise\"><p id=\"result\" data-live>Result</p></form>",
            "<section contenteditable=\"true\"><p id=\"result\" data-live>Draft</p></section>",
        ] {
            assert!(admit_live(source).is_err(), "{source}");
            assert!(live_regions(source).is_err(), "{source}");
        }
    }

    #[test]
    fn live_command_forms_require_stable_unique_literal_ids() {
        for (form, error) in [
            (
                "<form data-command=\"reports.submit\"></form>",
                "template_live_form_id_required",
            ),
            (
                "<form id=\"{{ title }}\" data-command=\"reports.submit\"></form>",
                "template_live_form_id_must_be_literal",
            ),
            (
                "<form id=\"submit\" data-command=\"reports.submit\"></form><p id=\"submit\">Collision</p>",
                "template_live_form_id_not_unique",
            ),
            (
                "{% if ready %}<form id=\"submit\" data-command=\"reports.submit\"></form>{% endif %}",
                "template_live_forms_must_exist_in_every_branch",
            ),
            (
                "{% if ready %}<form id=\"submit\" data-command=\"reports.submit\"></form>{% else %}<form id=\"submit\" data-command=\"reports.revise\"></form>{% endif %}",
                "template_live_forms_must_exist_in_every_branch",
            ),
            (
                "{% for item in items %}<form id=\"submit\" data-command=\"reports.submit\"></form>{% endfor %}",
                "template_live_form_in_loop",
            ),
        ] {
            let source = format!("<p id=\"result\" data-live>Result</p>{form}");
            let failure = admit_live(&source).unwrap_err();
            assert!(
                format!("{failure:#}").contains(error),
                "{source}: {failure:#}"
            );
        }
    }

    #[test]
    fn live_extraction_rechecks_region_ids_and_preserves_platform_form_boundaries() {
        let markup = "<main id=\"day2-main\"><p id=\"result\" data-live>Ready &amp; current</p><form id=\"day2-form-revise\" method=\"post\" action=\"/_command\"><textarea name=\"text\">Draft</textarea><input type=\"hidden\" name=\"_ticket\" value=\"private\"></form></main>";
        let regions = live_regions(markup).unwrap();
        assert_eq!(regions.len(), 1);
        let fragment = parse_checked(&regions["result"]).unwrap();
        let result = fragment
            .select(&Selector::parse("#result[data-live]").unwrap())
            .next()
            .unwrap();
        assert_eq!(result.text().collect::<String>(), "Ready & current");
        assert!(!regions["result"].contains("Draft"));
        assert!(!regions["result"].contains("private"));
        assert!(
            live_regions(
                "<p id=\"result\" data-live>Result</p><p id=\"result\">Runtime collision</p>"
            )
            .is_err()
        );
    }

    #[test]
    fn image_catalog_reference_cannot_be_bypassed_by_literal_platform_url() {
        let markup = "<img src=\"/assets/app/typo\" alt=\"Logo\">";
        assert!(check_html(markup, Some(&BTreeMap::new())).is_err());
        assert!(parse_checked(markup).is_ok());
    }

    #[test]
    fn loop_variable_cannot_shadow_asset_helper() {
        let sources = BTreeMap::from([(
            "pages/links.html".into(),
            "{% for asset in items %}<p>{{ asset }}</p>{% endfor %}".into(),
        )]);
        let context = Type::Record(BTreeMap::from([(
            "items".into(),
            Type::List(Box::new(Type::String)),
        )]));
        let error = analyze(
            &sources,
            "pages/links.html",
            &context,
            &assets::Catalog::new(),
            None,
        )
        .err()
        .expect("asset must remain the platform helper");
        assert!(format!("{error:#}").contains("template_loop_variable_shadowing"));
    }

    #[test]
    fn submitters_cannot_override_platform_form_transport() {
        for (attribute, value) in [
            ("formaction", "/other"),
            ("formmethod", "get"),
            ("formenctype", "text/plain"),
            ("formtarget", "_blank"),
        ] {
            let markup = format!(
                "<form data-command=\"links.create\"><button type=\"submit\" {attribute}=\"{value}\">Create</button></form>"
            );
            assert!(check_html(&markup, Some(&BTreeMap::new())).is_err());
            assert!(parse_checked(&markup).is_err());
        }
    }

    #[test]
    fn fragment_targets_are_rechecked_after_form_suppression() {
        let mut html =
            Html::parse_fragment("<a href=\"#create\">Create</a><form id=\"create\"></form>");
        validate_fragments(&html).unwrap();
        let form = html
            .select(&Selector::parse("form").unwrap())
            .next()
            .unwrap()
            .id();
        html.tree.get_mut(form).unwrap().detach();
        assert!(validate_fragments(&html).is_err());
    }
}
