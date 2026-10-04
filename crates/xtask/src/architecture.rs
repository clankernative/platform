//! A reviewed ratchet for ambient platform effects. This is a syntax boundary,
//! not Rust type resolution: it deliberately inventories imports, indirection,
//! and suppression points that require review alongside concrete effect paths.

use anyhow::{Context, Result, bail, ensure};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use syn::{
    Attribute, Expr, Item, Meta, Pat, Type, UseTree,
    visit::{self, Visit},
};

const RULES_FILE: &str = "architecture-rules.json";
const VERSION: u32 = 1;
const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCES: usize = 4096;
const MAX_FINDINGS: usize = 100_000;
const MAX_DIRECTORY_DEPTH: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub source: String,
    pub kind: String,
    pub target: String,
    pub context: String,
    pub fingerprint: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Inventory {
    pub version: u32,
    pub sources: Vec<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Allowance {
    source: String,
    kind: String,
    target: String,
    context: String,
    fingerprint: String,
    count: usize,
    reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Rules {
    version: u32,
    sources: Vec<String>,
    allowances: Vec<Allowance>,
}

impl Allowance {
    fn finding(&self) -> Finding {
        Finding {
            source: self.source.clone(),
            kind: self.kind.clone(),
            target: self.target.clone(),
            context: self.context.clone(),
            fingerprint: self.fingerprint.clone(),
            count: self.count,
        }
    }
}

/// Read-only inventory. Callers may print this for review; there is intentionally
/// no API that updates, expands, or repairs the reviewed allowance file.
pub fn inventory(root: &Path) -> Result<Inventory> {
    let mut paths = Vec::new();
    collect_sources(root, &root.join("crates"), &mut paths, 0)?;
    if root.join("cli/checks").exists() {
        collect_sources(root, &root.join("cli/checks"), &mut paths, 0)?;
    }
    if root.join("build.rs").exists() {
        paths.push("build.rs".to_owned());
    }
    paths.sort();
    ensure!(
        paths.len() <= MAX_SOURCES,
        "architecture source limit exceeded"
    );
    let mut parsed = BTreeMap::new();
    for path in &paths {
        if integration_or_generated(path) {
            continue;
        }
        let bytes = read_regular(&root.join(path), MAX_SOURCE_BYTES)?;
        let source = std::str::from_utf8(&bytes).with_context(|| format!("UTF-8 {path}"))?;
        let syntax =
            syn::parse_file(source).with_context(|| format!("parse architecture source {path}"))?;
        parsed.insert(path.clone(), syntax);
    }
    // A file reached solely through test-only module declarations is a test
    // source. Orphan files remain inspected, so moving code out of the module
    // graph cannot make it disappear from the ratchet.
    let test_only = test_only_sources(&parsed);
    let mut findings = BTreeMap::new();
    for (source, syntax) in &parsed {
        if test_only.contains(source) || definitely_test_only(&syntax.attrs) {
            continue;
        }
        let mut scanner = Scanner::new(source, &mut findings);
        scanner.visit_file(syntax);
        ensure!(
            findings.len() <= MAX_FINDINGS,
            "architecture finding limit exceeded"
        );
    }
    Ok(Inventory {
        version: VERSION,
        sources: paths,
        findings: findings.into_values().collect(),
    })
}

pub fn check(root: &Path) -> Result<()> {
    let bytes = read_regular(&root.join(RULES_FILE), MAX_CONFIG_BYTES)?;
    let rules: Rules =
        day2::json::decode_evidence(&bytes).context("parse architecture-rules.json")?;
    let actual = inventory(root)?;
    validate(&rules, &actual)?;
    println!(
        "platform architecture: {} sources, {} reviewed effect sites ({} occurrences)",
        actual.sources.len(),
        actual.findings.len(),
        actual
            .findings
            .iter()
            .map(|finding| finding.count)
            .sum::<usize>()
    );
    Ok(())
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "architecture input must be a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= limit as u64,
        "architecture input exceeds byte limit: {}",
        path.display()
    );
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "architecture input exceeds byte limit: {}",
        path.display()
    );
    Ok(bytes)
}

fn integration_or_generated(path: &str) -> bool {
    let components: Vec<_> = path.split('/').collect();
    // Integration harnesses and the pinned worker ABI are catalogued, but they
    // are not production decision logic. A src/tests/ or generated/ directory
    // elsewhere receives no naming-based exemption.
    components.first() == Some(&"crates") && components.get(2) == Some(&"tests")
        || path.starts_with("cli/checks/tests/")
        || path.starts_with("crates/worker/generated/")
}

fn validate(rules: &Rules, actual: &Inventory) -> Result<()> {
    ensure!(
        rules.version == VERSION,
        "unsupported architecture rules version {}",
        rules.version
    );
    ensure!(
        rules.sources.windows(2).all(|pair| pair[0] < pair[1]),
        "architecture sources must be sorted and unique"
    );
    let expected_sources: BTreeSet<_> = rules.sources.iter().collect();
    let actual_sources: BTreeSet<_> = actual.sources.iter().collect();
    ensure!(
        expected_sources == actual_sources,
        "architecture source inventory changed; unreviewed: {:?}; stale: {:?}",
        actual_sources
            .difference(&expected_sources)
            .collect::<Vec<_>>(),
        expected_sources
            .difference(&actual_sources)
            .collect::<Vec<_>>()
    );
    let mut expected = BTreeMap::new();
    for allowance in &rules.allowances {
        ensure!(
            !allowance.reason.trim().is_empty(),
            "architecture allowance needs a review reason: {}",
            allowance.target
        );
        ensure!(
            allowance.count > 0,
            "architecture allowance count must be positive: {}",
            allowance.target
        );
        ensure!(
            allowance.fingerprint.len() == 64
                && allowance
                    .fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid architecture fingerprint: {}",
            allowance.fingerprint
        );
        let finding = allowance.finding();
        let key = finding_key(&finding);
        ensure!(
            expected.insert(key, finding).is_none(),
            "duplicate architecture allowance: {} {}",
            allowance.source,
            allowance.target
        );
    }
    let observed: BTreeMap<_, _> = actual
        .findings
        .iter()
        .cloned()
        .map(|finding| (finding_key(&finding), finding))
        .collect();
    let mut violations = Vec::new();
    for (key, finding) in &observed {
        match expected.get(key) {
            None => violations.push(format!(
                "unreviewed {}: {} {} [{}]",
                finding.kind, finding.source, finding.target, finding.fingerprint
            )),
            Some(allowance) if allowance.count != finding.count => violations.push(format!(
                "changed occurrence count: {} {} (reviewed {}, actual {})",
                finding.source, finding.target, allowance.count, finding.count
            )),
            Some(_) => {}
        }
    }
    for (key, finding) in &expected {
        if !observed.contains_key(key) {
            violations.push(format!(
                "stale allowance: {} {} [{}]",
                finding.source, finding.target, finding.fingerprint
            ));
        }
    }
    if !violations.is_empty() {
        bail!(
            "platform architecture review required:\n{}",
            violations.join("\n")
        );
    }
    Ok(())
}

type FindingKey = (String, String, String, String, String);

fn finding_key(finding: &Finding) -> FindingKey {
    (
        finding.source.clone(),
        finding.kind.clone(),
        finding.target.clone(),
        finding.context.clone(),
        finding.fingerprint.clone(),
    )
}

fn collect_sources(
    root: &Path,
    directory: &Path,
    output: &mut Vec<String>,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= MAX_DIRECTORY_DEPTH,
        "architecture source directory depth limit exceeded: {}",
        directory.display()
    );
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("stat source directory {}", directory.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "architecture source root must be a regular directory: {}",
        directory.display()
    );
    for entry in fs::read_dir(directory).with_context(|| format!("list {}", directory.display()))? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        let path = entry.path();
        ensure!(
            !metadata.is_symlink(),
            "architecture source symlink requires an explicit policy: {}",
            path.display()
        );
        if metadata.is_dir() {
            collect_sources(root, &path, output, depth + 1)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(
                path.strip_prefix(root)?
                    .to_str()
                    .context("non-UTF-8 architecture path")?
                    .replace('\\', "/"),
            );
            ensure!(
                output.len() <= MAX_SOURCES,
                "architecture source limit exceeded"
            );
        }
    }
    Ok(())
}

fn test_only_sources(parsed: &BTreeMap<String, syn::File>) -> BTreeSet<String> {
    let mut edges = Vec::new();
    for (source, syntax) in parsed {
        let source_path = Path::new(source);
        let parent = source_path.parent().unwrap_or(Path::new(""));
        let directory = if matches!(
            source_path.file_stem().and_then(|value| value.to_str()),
            Some("lib" | "main" | "mod")
        ) {
            parent.to_path_buf()
        } else {
            parent.join(source_path.file_stem().unwrap_or_default())
        };
        module_edges(
            source,
            &syntax.items,
            &directory,
            definitely_test_only(&syntax.attrs),
            parsed,
            &mut edges,
        );
        struct Includes<'a> {
            source: &'a str,
            parsed: &'a BTreeMap<String, syn::File>,
            edges: &'a mut Vec<(String, String, bool)>,
            test: bool,
        }
        impl<'ast> Visit<'ast> for Includes<'_> {
            fn visit_item(&mut self, item: &'ast Item) {
                let previous = self.test;
                self.test |= definitely_test_only(item_attributes(item));
                visit::visit_item(self, item);
                self.test = previous;
            }

            fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                if invocation.path.is_ident("include")
                    && let Ok(literal) = invocation.parse_body::<syn::LitStr>()
                {
                    let candidate = normalize_source_path(
                        &Path::new(self.source)
                            .parent()
                            .unwrap_or(Path::new(""))
                            .join(literal.value()),
                    );
                    if self.parsed.contains_key(&candidate) {
                        self.edges
                            .push((self.source.to_owned(), candidate, self.test));
                    }
                }
            }
        }
        Includes {
            source,
            parsed,
            edges: &mut edges,
            test: definitely_test_only(&syntax.attrs),
        }
        .visit_file(syntax);
    }
    let mut tests: BTreeSet<String> = parsed
        .iter()
        .filter(|(_, file)| definitely_test_only(&file.attrs))
        .map(|(path, _)| path.clone())
        .collect();
    // Repeated propagation handles descendants of an external test module.
    loop {
        let mut incoming: BTreeMap<String, (bool, bool)> = BTreeMap::new();
        for (parent, child, test) in &edges {
            let flags = incoming.entry(child.clone()).or_default();
            if *test || tests.contains(parent) {
                flags.0 = true;
            } else {
                flags.1 = true;
            }
        }
        let next: BTreeSet<_> = incoming
            .into_iter()
            .filter(|(_, flags)| flags.0 && !flags.1)
            .map(|(path, _)| path)
            .chain(
                parsed
                    .iter()
                    .filter(|(_, file)| definitely_test_only(&file.attrs))
                    .map(|(path, _)| path.clone()),
            )
            .collect();
        if next == tests {
            return tests;
        }
        // Cyclic module graphs are invalid Rust, but avoid an unbounded checker
        // loop even when inspecting a work in progress.
        if !tests.is_subset(&next) {
            return BTreeSet::new();
        }
        tests = next;
    }
}

fn module_edges(
    source: &str,
    items: &[Item],
    directory: &Path,
    inherited_test: bool,
    parsed: &BTreeMap<String, syn::File>,
    edges: &mut Vec<(String, String, bool)>,
) {
    for item in items {
        let Item::Mod(module) = item else { continue };
        let test = inherited_test || definitely_test_only(&module.attrs);
        if let Some((_, items)) = &module.content {
            module_edges(
                source,
                items,
                &directory.join(module.ident.to_string()),
                test,
                parsed,
                edges,
            );
        } else {
            let explicit = module.attrs.iter().find_map(|attribute| {
                if !attribute.path().is_ident("path") {
                    return None;
                }
                let Meta::NameValue(value) = &attribute.meta else {
                    return None;
                };
                let Expr::Lit(literal) = &value.value else {
                    return None;
                };
                let syn::Lit::Str(path) = &literal.lit else {
                    return None;
                };
                Some(path.value())
            });
            let candidates = if let Some(path) = explicit {
                // #[path] is relative to the containing source for an external
                // module; the common module-directory case is also recognized.
                vec![
                    Path::new(source).parent().unwrap_or(directory).join(&path),
                    directory.join(path),
                ]
            } else {
                vec![
                    directory.join(format!("{}.rs", module.ident)),
                    directory.join(module.ident.to_string()).join("mod.rs"),
                ]
            };
            for candidate in candidates {
                let candidate = normalize_source_path(&candidate);
                if parsed.contains_key(&candidate) {
                    edges.push((source.to_owned(), candidate, test));
                }
            }
        }
    }
}

fn normalize_source_path(path: &Path) -> String {
    let mut normalized = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized.to_string_lossy().replace('\\', "/")
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

// Tri-state cfg evaluation: unknown production features/targets are inspected.
// A false result must hold with test disabled for every unknown configuration.
fn cfg_value(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::List(list) => {
            let nested = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )
                .ok()?;
            let values: Vec<_> = nested.iter().map(cfg_value).collect();
            if list.path.is_ident("all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|value| *value == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if list.path.is_ident("any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|value| *value == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else if list.path.is_ident("not") && values.len() == 1 {
                values[0].map(|value| !value)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn definitely_test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if attribute.path().is_ident("cfg") {
            attribute
                .parse_args::<Meta>()
                .ok()
                .is_some_and(|meta| cfg_value(&meta) == Some(false))
        } else if attribute.path().is_ident("cfg_attr") {
            attribute
                .parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )
                .ok()
                .is_some_and(|nested| {
                    let mut values = nested.iter();
                    values
                        .next()
                        .is_some_and(|condition| cfg_value(condition) == Some(true))
                        && values.any(|meta| {
                            let Meta::List(list) = meta else { return false };
                            list.path.is_ident("cfg")
                                && list
                                    .parse_args::<Meta>()
                                    .ok()
                                    .is_some_and(|meta| cfg_value(&meta) == Some(false))
                        })
                })
        } else {
            false
        }
    })
}

struct Scanner<'a> {
    source: &'a str,
    findings: &'a mut BTreeMap<FindingKey, Finding>,
    context: Vec<String>,
    aliases: Vec<BTreeMap<String, String>>,
    values: Vec<BTreeMap<String, String>>,
    fields: BTreeMap<String, BTreeMap<String, String>>,
    self_type: Option<String>,
    call_callee: bool,
}

impl<'a> Scanner<'a> {
    fn new(source: &'a str, findings: &'a mut BTreeMap<FindingKey, Finding>) -> Self {
        let mut scanner = Self {
            source,
            findings,
            context: Vec::new(),
            aliases: vec![BTreeMap::new()],
            values: vec![BTreeMap::new()],
            fields: BTreeMap::new(),
            self_type: None,
            call_callee: false,
        };
        if source == "crates/day2/src/web_security.rs" {
            scanner.aliases[0].insert("random".to_owned(), "day2::web_security::random".to_owned());
        }
        if source == "crates/day2/src/resource_admin.rs" {
            scanner.aliases[0].insert(
                "now_ms".to_owned(),
                "day2::resource_admin::now_ms".to_owned(),
            );
        }
        scanner
    }

    fn record(&mut self, kind: &str, target: &str, tokens: impl ToTokens) {
        let context = if self.context.is_empty() {
            "<module>".to_owned()
        } else {
            self.context.join("::")
        };
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                format!("{kind}\n{target}\n{context}\n{}", tokens.to_token_stream()).as_bytes()
            )
        );
        let finding = Finding {
            source: self.source.to_owned(),
            kind: kind.to_owned(),
            target: target.to_owned(),
            context,
            fingerprint,
            count: 1,
        };
        let entry = self
            .findings
            .entry(finding_key(&finding))
            .or_insert_with(|| {
                let mut finding = finding.clone();
                finding.count = 0;
                finding
            });
        entry.count += 1;
    }

    fn resolve(&self, path: &syn::Path) -> String {
        let names: Vec<_> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.resolve_name(&names.join("::"))
    }

    fn resolve_name(&self, name: &str) -> String {
        let mut current = name.to_owned();
        while let Some(ancestor) = current.strip_prefix("super::") {
            current = ancestor.to_owned();
        }
        if let Some(local) = current.strip_prefix("self::") {
            current = local.to_owned();
        }
        if let Some(root) = current.strip_prefix("crate::") {
            let (first, rest) = root.split_once("::").unwrap_or((root, ""));
            if let Some(alias) = self.aliases.first().and_then(|scope| scope.get(first)) {
                current = if rest.is_empty() {
                    alias.clone()
                } else {
                    format!("{alias}::{rest}")
                };
            }
        }
        let mut seen = BTreeSet::new();
        for _ in 0..32 {
            if !seen.insert(current.clone()) {
                break;
            }
            let (first, rest) = current.split_once("::").unwrap_or((&current, ""));
            let alias = self.aliases.iter().rev().find_map(|scope| scope.get(first));
            let Some(alias) = alias else { break };
            current = if rest.is_empty() {
                alias.clone()
            } else {
                format!("{alias}::{rest}")
            };
        }
        current
    }

    fn use_tree(&mut self, tree: &UseTree, prefix: &str, review: bool) {
        let join = |name: &str| {
            if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}::{name}")
            }
        };
        match tree {
            UseTree::Path(path) => {
                self.use_tree(&path.tree, &join(&path.ident.to_string()), review)
            }
            UseTree::Name(name) => {
                let target = if name.ident == "self" {
                    prefix.to_owned()
                } else {
                    join(&name.ident.to_string())
                };
                let alias = if name.ident == "self" {
                    prefix.rsplit("::").next().unwrap_or(prefix).to_owned()
                } else {
                    name.ident.to_string()
                };
                let target = self.resolve_name(&target);
                self.bind_alias(alias, target.clone(), tree);
                if review && dangerous_namespace(&target) {
                    self.record("effect-reexport", &target, tree);
                }
            }
            UseTree::Rename(rename) => {
                let target = self.resolve_name(&if rename.ident == "self" {
                    prefix.to_owned()
                } else {
                    join(&rename.ident.to_string())
                });
                self.bind_alias(rename.rename.to_string(), target.clone(), tree);
                if review && dangerous_namespace(&target) {
                    self.record("effect-reexport", &target, tree);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.use_tree(item, prefix, review);
                }
            }
            UseTree::Glob(_) => {
                let prefix = self.resolve_name(prefix);
                let names: &[&str] = match prefix.as_str() {
                    "std" => &["time", "env", "fs", "thread", "process", "net"],
                    "std::time" => &["SystemTime", "Instant"],
                    "std::env" => &[
                        "var",
                        "var_os",
                        "vars",
                        "vars_os",
                        "args",
                        "args_os",
                        "current_dir",
                        "current_exe",
                        "set_current_dir",
                        "set_var",
                        "remove_var",
                        "temp_dir",
                    ],
                    "std::fs" => &[
                        "File",
                        "OpenOptions",
                        "read",
                        "read_to_string",
                        "write",
                        "copy",
                        "rename",
                        "remove_file",
                        "remove_dir",
                        "remove_dir_all",
                        "create_dir",
                        "create_dir_all",
                        "read_dir",
                        "metadata",
                        "symlink_metadata",
                        "canonicalize",
                        "set_permissions",
                        "hard_link",
                    ],
                    "std::thread" => &[
                        "sleep",
                        "spawn",
                        "scope",
                        "park",
                        "park_timeout",
                        "yield_now",
                        "current",
                        "Builder",
                    ],
                    "std::process" => &["Command", "id", "exit", "abort"],
                    "std::net" => &["TcpStream", "TcpListener", "UdpSocket"],
                    "getrandom" => &["fill", "u32", "u64"],
                    "rand" => &["rng", "random", "random_iter", "thread_rng"],
                    "reqwest" | "reqwest::blocking" => &["Client", "get"],
                    "chrono" => &["Utc", "Local"],
                    "uuid" => &["Uuid"],
                    _ => &[],
                };
                for name in names {
                    self.bind_alias((*name).to_owned(), format!("{prefix}::{name}"), tree);
                }
            }
        }
    }

    fn bind_alias(&mut self, alias: String, target: String, tokens: impl ToTokens) {
        let mut selected = target.clone();
        if let Some(previous) = self.aliases.last().unwrap().get(&alias).cloned()
            && previous != target
            && (dangerous_namespace(&previous) || dangerous_namespace(&target))
        {
            let alternatives = BTreeSet::from([previous.clone(), target.clone()]);
            self.record(
                "effect-alias-conflict",
                &format!(
                    "{alias}: {}",
                    alternatives.into_iter().collect::<Vec<_>>().join(" | ")
                ),
                tokens,
            );
            if dangerous_namespace(&previous) && !dangerous_namespace(&target) {
                selected = previous;
            }
        }
        self.aliases.last_mut().unwrap().insert(alias, selected);
    }

    fn collect_fields(&mut self, structure: &syn::ItemStruct) {
        let mut fields = BTreeMap::new();
        for (index, field) in structure.fields.iter().enumerate() {
            if let Some(origin) = self.type_origin(&field.ty) {
                fields.insert(
                    field
                        .ident
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| index.to_string()),
                    origin,
                );
            }
        }
        let name = structure.ident.to_string();
        if let Some(previous) = self.fields.get(&name).cloned()
            && previous != fields
            && previous
                .values()
                .chain(fields.values())
                .any(|origin| dangerous_namespace(origin))
        {
            self.record("effect-field-conflict", &name, structure);
            // Preserve known hazardous field origins when an alternate
            // platform declaration uses a pure field with the same name.
            for (name, origin) in previous {
                if dangerous_namespace(&origin) {
                    fields.insert(name, origin);
                }
            }
        }
        self.fields.insert(name, fields);
    }

    fn type_origin(&self, ty: &Type) -> Option<String> {
        match ty {
            Type::Path(path) => {
                let last = path.path.segments.last()?;
                if matches!(
                    last.ident.to_string().as_str(),
                    "Option" | "Result" | "Box" | "Arc" | "Rc" | "Mutex" | "RwLock"
                ) && let syn::PathArguments::AngleBracketed(arguments) = &last.arguments
                    && let Some(syn::GenericArgument::Type(inner)) = arguments.args.first()
                {
                    return self.type_origin(inner);
                }
                Some(self.resolve(&path.path))
            }
            Type::Reference(reference) => self.type_origin(&reference.elem),
            Type::Paren(paren) => self.type_origin(&paren.elem),
            _ => None,
        }
    }

    fn origin(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Path(path) => {
                if path.path.is_ident("self") {
                    return self.self_type.clone();
                }
                let name = self.resolve(&path.path);
                self.values
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(&name))
                    .cloned()
                    .or(Some(name))
            }
            Expr::Call(call) => self.origin(&call.func).map(|origin| {
                if origin.ends_with("::new")
                    || origin.ends_with("::builder")
                    || origin.ends_with("::open")
                    || origin.ends_with("::create")
                    || origin.ends_with("::now")
                {
                    origin.rsplit_once("::").unwrap().0.to_owned()
                } else {
                    origin
                }
            }),
            Expr::MethodCall(call) => self.origin(&call.receiver),
            Expr::Field(field) => {
                let origin = self.origin(&field.base)?;
                let name = field.member.to_token_stream().to_string();
                self.fields
                    .get(&origin)
                    .and_then(|fields| fields.get(&name))
                    .cloned()
            }
            Expr::Try(value) => self.origin(&value.expr),
            Expr::Await(value) => self.origin(&value.base),
            Expr::Paren(value) => self.origin(&value.expr),
            Expr::Reference(value) => self.origin(&value.expr),
            Expr::Cast(value) => self.type_origin(&value.ty),
            _ => None,
        }
    }

    fn parameters(&mut self, signature: &syn::Signature) {
        for argument in &signature.inputs {
            if let syn::FnArg::Typed(argument) = argument
                && let Some(origin) = self.type_origin(&argument.ty)
            {
                self.bind_pattern(&argument.pat, &origin);
            }
        }
    }

    fn bind_pattern(&mut self, pattern: &Pat, origin: &str) {
        match pattern {
            Pat::Ident(pattern) => {
                self.values
                    .last_mut()
                    .unwrap()
                    .insert(pattern.ident.to_string(), origin.to_owned());
            }
            Pat::Type(pattern) => {
                let origin = self.type_origin(&pattern.ty).unwrap_or(origin.to_owned());
                self.bind_pattern(&pattern.pat, &origin);
            }
            Pat::Reference(pattern) => self.bind_pattern(&pattern.pat, origin),
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        // Imports are independent of textual declaration order in Rust.
        for item in &file.items {
            if let Item::ExternCrate(item) = item
                && !definitely_test_only(&item.attrs)
                && let Some((_, alias)) = &item.rename
            {
                self.bind_alias(alias.to_string(), item.ident.to_string(), item);
            }
        }
        for item in &file.items {
            if let Item::Use(import) = item
                && !definitely_test_only(&import.attrs)
            {
                self.use_tree(&import.tree, "", false);
            }
        }
        for item in &file.items {
            if let Item::Struct(structure) = item
                && !definitely_test_only(&structure.attrs)
            {
                self.collect_fields(structure);
            }
        }
        visit::visit_file(self, file);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if definitely_test_only(item_attributes(item)) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        self.context.push(module.ident.to_string());
        self.aliases.push(BTreeMap::new());
        if let Some((_, items)) = &module.content {
            for item in items {
                if let Item::ExternCrate(item) = item
                    && !definitely_test_only(&item.attrs)
                    && let Some((_, alias)) = &item.rename
                {
                    self.bind_alias(alias.to_string(), item.ident.to_string(), item);
                }
            }
            for item in items {
                if let Item::Use(import) = item
                    && !definitely_test_only(&import.attrs)
                {
                    self.use_tree(&import.tree, "", false);
                }
            }
            for item in items {
                if let Item::Struct(structure) = item
                    && !definitely_test_only(&structure.attrs)
                {
                    self.collect_fields(structure);
                }
            }
        }
        visit::visit_item_mod(self, module);
        self.aliases.pop();
        self.context.pop();
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.context.push(function.sig.ident.to_string());
        self.values.push(BTreeMap::new());
        self.parameters(&function.sig);
        visit::visit_item_fn(self, function);
        self.values.pop();
        self.context.pop();
    }

    fn visit_item_const(&mut self, constant: &'ast syn::ItemConst) {
        if let Some(origin) = self.origin(&constant.expr) {
            self.values
                .last_mut()
                .unwrap()
                .insert(constant.ident.to_string(), origin);
        }
        self.context.push(constant.ident.to_string());
        visit::visit_item_const(self, constant);
        self.context.pop();
    }

    fn visit_item_static(&mut self, constant: &'ast syn::ItemStatic) {
        if let Some(origin) = self.origin(&constant.expr) {
            self.values
                .last_mut()
                .unwrap()
                .insert(constant.ident.to_string(), origin);
        }
        self.context.push(constant.ident.to_string());
        visit::visit_item_static(self, constant);
        self.context.pop();
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.values.push(BTreeMap::new());
        for input in &closure.inputs {
            if let Pat::Type(pattern) = input
                && let Some(origin) = self.type_origin(&pattern.ty)
            {
                self.bind_pattern(&pattern.pat, &origin);
            }
        }
        visit::visit_expr_closure(self, closure);
        self.values.pop();
    }

    fn visit_item_impl(&mut self, implementation: &'ast syn::ItemImpl) {
        let previous = self.self_type.take();
        self.self_type = self.type_origin(&implementation.self_ty);
        self.context
            .push(implementation.self_ty.to_token_stream().to_string());
        visit::visit_item_impl(self, implementation);
        self.context.pop();
        self.self_type = previous;
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if definitely_test_only(&function.attrs) {
            return;
        }
        self.context.push(function.sig.ident.to_string());
        self.values.push(BTreeMap::new());
        self.parameters(&function.sig);
        visit::visit_impl_item_fn(self, function);
        self.values.pop();
        self.context.pop();
    }

    fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
        if definitely_test_only(&function.attrs) {
            return;
        }
        self.context.push(function.sig.ident.to_string());
        self.values.push(BTreeMap::new());
        self.parameters(&function.sig);
        visit::visit_trait_item_fn(self, function);
        self.values.pop();
        self.context.pop();
    }

    fn visit_item_struct(&mut self, structure: &'ast syn::ItemStruct) {
        visit::visit_item_struct(self, structure);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.aliases.push(BTreeMap::new());
        self.values.push(BTreeMap::new());
        for statement in &block.stmts {
            if let syn::Stmt::Item(Item::Use(import)) = statement
                && !definitely_test_only(&import.attrs)
            {
                self.use_tree(&import.tree, "", false);
            }
        }
        visit::visit_block(self, block);
        self.values.pop();
        self.aliases.pop();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if definitely_test_only(&local.attrs) {
            return;
        }
        if let Some(initializer) = &local.init {
            if let Some(origin) = self.origin(&initializer.expr) {
                self.bind_pattern(&local.pat, &origin);
            }
        } else if let Pat::Type(pattern) = &local.pat
            && let Some(origin) = self.type_origin(&pattern.ty)
        {
            self.bind_pattern(&pattern.pat, &origin);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr(&mut self, expression: &'ast Expr) {
        // Attributes are available on all ordinary expressions through their
        // concrete variants; the common effect-bearing forms are handled here.
        let attrs = match expression {
            Expr::Call(expr) => &expr.attrs,
            Expr::MethodCall(expr) => &expr.attrs,
            Expr::Block(expr) => &expr.attrs,
            Expr::Macro(expr) => &expr.attrs,
            Expr::Path(expr) => &expr.attrs,
            Expr::If(expr) => &expr.attrs,
            Expr::Match(expr) => &expr.attrs,
            Expr::Closure(expr) => &expr.attrs,
            _ => return visit::visit_expr(self, expression),
        };
        if !definitely_test_only(attrs) {
            visit::visit_expr(self, expression);
        }
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let target = self.resolve(&expression.path);
        if !self.call_callee
            && let Some(kind) = hazard(&target)
        {
            self.record(kind, &target, expression);
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some(target) = self.origin(&call.func)
            && let Some(kind) = hazard(&target)
        {
            self.record(kind, &target, call);
        }
        for attribute in &call.attrs {
            self.visit_attribute(attribute);
        }
        let previous = self.call_callee;
        self.call_callee = true;
        self.visit_expr(&call.func);
        self.call_callee = previous;
        for argument in &call.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if let Some(origin) = self.origin(&call.receiver) {
            let target = format!("{origin}::{method}");
            if let Some(kind) = method_hazard(&origin, &method) {
                self.record(kind, &target, call);
            }
        }
        if matches!(
            method.as_str(),
            "execute" | "execute_batch" | "prepare" | "prepare_cached" | "query_row" | "query_map"
        ) && let Some(Expr::Lit(literal)) = call.args.first()
            && let syn::Lit::Str(sql) = &literal.lit
        {
            // SQL-shaped literals are visited below. This handles only
            // expression fragments, avoiding duplicate findings.
            let shaped = sql_hazards(&sql.value(), true);
            for target in sql_hazards(&sql.value(), false).difference(&shaped) {
                self.record("sql-ambient", target, sql);
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_item_use(&mut self, import: &'ast syn::ItemUse) {
        self.use_tree(
            &import.tree,
            "",
            !matches!(import.vis, syn::Visibility::Inherited),
        );
        // All hazardous globs require review, including private imports.
        fn globs(tree: &UseTree, prefix: String, output: &mut Vec<String>) {
            match tree {
                UseTree::Path(path) => globs(
                    &path.tree,
                    if prefix.is_empty() {
                        path.ident.to_string()
                    } else {
                        format!("{prefix}::{}", path.ident)
                    },
                    output,
                ),
                UseTree::Group(group) => {
                    for tree in &group.items {
                        globs(tree, prefix.clone(), output);
                    }
                }
                UseTree::Glob(_) => output.push(prefix),
                _ => {}
            }
        }
        let mut prefixes = Vec::new();
        globs(&import.tree, String::new(), &mut prefixes);
        for prefix in prefixes {
            let prefix = self.resolve_name(&prefix);
            if dangerous_namespace(&prefix) {
                self.record("effect-glob", &prefix, import);
            }
        }
        visit::visit_item_use(self, import);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if let Some((_, alias)) = &item.rename {
            self.aliases
                .last_mut()
                .unwrap()
                .insert(alias.to_string(), item.ident.to_string());
        }
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        let target = self.resolve(attribute.path());
        if matches!(target.as_str(), "tokio::main" | "tokio::test") {
            self.record("scheduling-attribute", &target, attribute);
        }
        if attribute.path().is_ident("path") {
            self.record("source-indirection", "module-path", attribute);
        }
        if attribute.path().is_ident("allow") || attribute.path().is_ident("expect") {
            self.record(
                "lint-suppression",
                &attribute.path().to_token_stream().to_string(),
                attribute,
            );
        }
        if attribute.path().is_ident("cfg_attr")
            && let Ok(metas) = attribute.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )
        {
            for meta in metas.iter().skip(1).filter(|_| {
                metas
                    .first()
                    .is_none_or(|condition| cfg_value(condition) != Some(false))
            }) {
                if meta.path().is_ident("allow") || meta.path().is_ident("expect") {
                    self.record(
                        "lint-suppression",
                        &meta.path().to_token_stream().to_string(),
                        meta,
                    );
                }
            }
        }
        visit::visit_attribute(self, attribute);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        let target = self.resolve(&invocation.path);
        if matches!(target.as_str(), "env" | "option_env") {
            self.record("environment-macro", &target, invocation);
        } else if matches!(target.as_str(), "include" | "include_str" | "include_bytes") {
            self.record("source-indirection", &target, invocation);
        } else if matches!(
            target.as_str(),
            "tokio::select" | "tokio::join" | "tokio::try_join"
        ) {
            self.record("scheduling-macro", &target, invocation);
        }
        // Parse ordinary macro arguments as expressions. For macro-specific
        // token grammars, inspect syntactic path tokens separately: literals
        // and comments cannot masquerade as a clock call.
        if let Ok(expressions) = invocation
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        {
            for expression in &expressions {
                self.visit_expr(expression);
            }
        } else {
            self.macro_tokens(invocation.tokens.clone());
        }
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        for target in sql_hazards(&literal.value(), true) {
            self.record("sql-ambient", &target, literal);
        }
    }
}

impl Scanner<'_> {
    fn macro_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if let proc_macro2::TokenTree::Group(group) = &tokens[index] {
                self.macro_tokens(group.stream());
            }
            if let proc_macro2::TokenTree::Ident(first) = &tokens[index] {
                let mut name = first.to_string();
                let mut end = index + 1;
                while end + 2 < tokens.len() {
                    let (
                        proc_macro2::TokenTree::Punct(first),
                        proc_macro2::TokenTree::Punct(second),
                        proc_macro2::TokenTree::Ident(next),
                    ) = (&tokens[end], &tokens[end + 1], &tokens[end + 2])
                    else {
                        break;
                    };
                    if first.as_char() != ':' || second.as_char() != ':' {
                        break;
                    }
                    name.push_str("::");
                    name.push_str(&next.to_string());
                    end += 3;
                }
                let target = self.resolve_name(&name);
                if let Some(kind) = hazard(&target) {
                    let call_end = if matches!(tokens.get(end), Some(proc_macro2::TokenTree::Group(group)) if group.delimiter() == proc_macro2::Delimiter::Parenthesis)
                    {
                        end + 1
                    } else {
                        end
                    };
                    let syntax: proc_macro2::TokenStream =
                        tokens[index..call_end].iter().cloned().collect();
                    self.record(kind, &target, syntax);
                }
                if matches!(tokens.get(end), Some(proc_macro2::TokenTree::Punct(punctuation)) if punctuation.as_char() == '!')
                {
                    let kind = match target.as_str() {
                        "env" | "option_env" => Some("environment-macro"),
                        "include" | "include_str" | "include_bytes" => Some("source-indirection"),
                        "tokio::select" | "tokio::join" | "tokio::try_join" => {
                            Some("scheduling-macro")
                        }
                        _ => None,
                    };
                    if let Some(kind) = kind {
                        let syntax: proc_macro2::TokenStream = tokens
                            [index..(end + 2).min(tokens.len())]
                            .iter()
                            .cloned()
                            .collect();
                        self.record(kind, &target, syntax);
                    }
                }
                index = end;
            } else {
                index += 1;
            }
        }
    }
}

fn dangerous_namespace(target: &str) -> bool {
    matches!(target, "std" | "tokio" | "chrono" | "uuid" | "libc")
        || [
            "std::time",
            "std::env",
            "std::fs",
            "std::thread",
            "std::process",
            "std::net",
            "tokio::time",
            "tokio::task",
            "tokio::fs",
            "tokio::net",
            "tokio::process",
            "getrandom",
            "rand",
            "rand_core",
            "fastrand",
            "reqwest",
            "ureq",
            "socket2",
        ]
        .iter()
        .any(|prefix| target == *prefix || target.starts_with(&format!("{prefix}::")))
}

fn hazard(target: &str) -> Option<&'static str> {
    if matches!(
        target,
        "web_security::random" | "crate::web_security::random" | "day2::web_security::random"
    ) {
        return Some("entropy");
    }
    if matches!(
        target,
        "resource_admin::now_ms" | "crate::resource_admin::now_ms" | "day2::resource_admin::now_ms"
    ) {
        return Some("clock");
    }
    if matches!(
        target,
        "std::time::SystemTime::now"
            | "std::time::SystemTime::elapsed"
            | "std::time::Instant::now"
            | "std::time::Instant::elapsed"
            | "tokio::time::Instant::now"
            | "tokio::time::Instant::elapsed"
            | "chrono::Utc::now"
            | "chrono::Local::now"
    ) {
        return Some("clock");
    }
    if target.starts_with("tokio::time::")
        && matches!(
            target.rsplit("::").next(),
            Some("sleep" | "sleep_until" | "interval" | "interval_at" | "timeout" | "timeout_at")
        )
    {
        return Some("timer");
    }
    if target.starts_with("getrandom::")
        || matches!(
            target,
            "rand::random"
                | "rand::random_iter"
                | "rand::thread_rng"
                | "rand::rng"
                | "rand::rngs::OsRng"
                | "rand_core::OsRng"
        )
        || (target.starts_with("rand::") || target.starts_with("rand_core::"))
            && matches!(
                target.rsplit("::").next(),
                Some("from_entropy" | "from_os_rng" | "try_from_os_rng")
            )
        || target.starts_with("fastrand::")
        || matches!(
            target,
            "uuid::Uuid::new_v4" | "uuid::Uuid::now_v7" | "uuid::Uuid::new_v7"
        )
    {
        return Some("entropy");
    }
    if target.starts_with("std::env::")
        && !target.starts_with("std::env::consts::")
        && !matches!(target, "std::env::split_paths" | "std::env::join_paths")
    {
        return Some("environment");
    }
    if target.starts_with("dotenv::") || target.starts_with("dotenvy::") {
        return Some("environment");
    }
    if target.starts_with("std::fs::") || target.starts_with("tokio::fs::") {
        return Some("filesystem");
    }
    if matches!(
        target,
        "tempfile::tempdir"
            | "tempfile::tempdir_in"
            | "tempfile::tempfile"
            | "tempfile::tempfile_in"
            | "tempfile::NamedTempFile::new"
            | "tempfile::NamedTempFile::new_in"
    ) {
        return Some("filesystem");
    }
    if target.starts_with("std::process::")
        && matches!(
            target.rsplit("::").next(),
            Some("new" | "id" | "exit" | "abort")
        )
        || target.starts_with("tokio::process::Command::")
    {
        return Some("process");
    }
    if target.starts_with("std::thread::")
        && matches!(
            target.rsplit("::").next(),
            Some("sleep" | "spawn" | "scope" | "park" | "park_timeout" | "yield_now" | "current")
        )
        || matches!(
            target,
            "tokio::spawn"
                | "tokio::task::spawn"
                | "tokio::task::spawn_blocking"
                | "tokio::task::block_in_place"
                | "tokio::task::yield_now"
                | "tokio::task::spawn_local"
                | "tokio::runtime::Runtime::new"
                | "tokio::runtime::Builder::new_current_thread"
                | "tokio::runtime::Builder::new_multi_thread"
        )
    {
        return Some("scheduling");
    }
    if target.starts_with("std::net::")
        && matches!(
            target.rsplit("::").next(),
            Some("bind" | "connect" | "connect_timeout")
        )
        || target.starts_with("tokio::net::")
            && matches!(target.rsplit("::").next(), Some("bind" | "connect"))
        || matches!(
            target,
            "reqwest::get"
                | "reqwest::blocking::get"
                | "reqwest::Client::new"
                | "reqwest::Client::builder"
                | "reqwest::blocking::Client::new"
                | "reqwest::blocking::Client::builder"
                | "socket2::Socket::new"
        )
        || target.starts_with("ureq::")
            && matches!(
                target.rsplit("::").next(),
                Some("get" | "post" | "put" | "delete" | "head" | "patch" | "request")
            )
    {
        return Some("network");
    }
    if target.starts_with("libc::") {
        return match target.rsplit("::").next().unwrap_or("") {
            "getrandom" | "arc4random" | "arc4random_buf" | "rand" | "random" => Some("entropy"),
            "clock_gettime" | "gettimeofday" | "time" => Some("clock"),
            "nanosleep" | "sleep" | "usleep" => Some("timer"),
            "getenv" | "setenv" | "unsetenv" => Some("environment"),
            "fork" | "execve" | "execv" | "execvp" | "posix_spawn" | "system" => Some("process"),
            "open" | "openat" | "fopen" | "read" | "write" | "unlink" | "mkdir" | "stat" => {
                Some("filesystem")
            }
            "socket" | "connect" | "bind" | "listen" | "accept" => Some("network"),
            "pthread_create" => Some("scheduling"),
            "syscall" => Some("foreign-syscall"),
            _ => None,
        };
    }
    None
}

fn method_hazard(origin: &str, method: &str) -> Option<&'static str> {
    if matches!(
        origin,
        "std::time::SystemTime" | "std::time::Instant" | "tokio::time::Instant"
    ) && method == "elapsed"
    {
        return Some("clock");
    }
    if (origin.starts_with("reqwest::") || origin.starts_with("ureq::"))
        && matches!(
            method,
            "send" | "call" | "execute" | "send_json" | "send_string" | "send_bytes" | "send_form"
        )
    {
        return Some("network");
    }
    if (origin.starts_with("std::process::Command")
        || origin.starts_with("tokio::process::Command"))
        && matches!(method, "spawn" | "status" | "output" | "exec")
    {
        return Some("process");
    }
    if origin.starts_with("std::thread::") && method == "spawn" {
        return Some("scheduling");
    }
    if (origin.starts_with("getrandom::")
        || origin.starts_with("rand::")
        || origin.starts_with("rand_core::"))
        && matches!(
            method,
            "fill_bytes"
                | "try_fill_bytes"
                | "random"
                | "random_range"
                | "gen"
                | "gen_range"
                | "next_u32"
                | "next_u64"
        )
    {
        return Some("entropy");
    }
    if (origin.starts_with("std::fs::") || origin.starts_with("tokio::fs::"))
        && matches!(
            method,
            "open"
                | "metadata"
                | "read"
                | "read_exact"
                | "read_to_end"
                | "read_to_string"
                | "write"
                | "write_all"
                | "sync_all"
                | "sync_data"
                | "set_len"
                | "set_permissions"
        )
    {
        return Some("filesystem");
    }
    if (origin.starts_with("std::net::") || origin.starts_with("tokio::net::"))
        && matches!(
            method,
            "accept"
                | "send"
                | "send_to"
                | "recv"
                | "recv_from"
                | "read"
                | "read_exact"
                | "write"
                | "write_all"
                | "shutdown"
        )
    {
        return Some("network");
    }
    None
}

#[derive(Debug)]
enum SqlToken {
    Word(String),
    String(String),
    Symbol(char),
}

fn sql_tokens(sql: &str) -> Vec<SqlToken> {
    let chars: Vec<_> = sql.chars().collect();
    let mut output = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }
        if ch == '-' && chars.get(index + 1) == Some(&'-') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == '/' && chars.get(index + 1) == Some(&'*') {
            index += 2;
            while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                index += 1;
            }
            index = (index + 2).min(chars.len());
            continue;
        }
        if matches!(ch, '\'' | '"' | '`' | '[') {
            let end = if ch == '[' { ']' } else { ch };
            index += 1;
            let mut value = String::new();
            while index < chars.len() {
                if chars[index] == end {
                    index += 1;
                    if chars.get(index) == Some(&end) && ch != '[' {
                        value.push(end);
                        index += 1;
                        continue;
                    }
                    break;
                }
                value.push(chars[index]);
                index += 1;
            }
            if ch == '\'' {
                output.push(SqlToken::String(value.to_ascii_lowercase()));
            } else {
                output.push(SqlToken::Symbol('?'));
            }
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            output.push(SqlToken::Word(
                chars[start..index]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase(),
            ));
        } else {
            output.push(SqlToken::Symbol(ch));
            index += 1;
        }
    }
    output
}

fn sql_hazards(sql: &str, require_sql_shape: bool) -> BTreeSet<String> {
    let tokens = sql_tokens(sql);
    if require_sql_shape
        && !matches!(tokens.first(), Some(SqlToken::Word(word)) if matches!(word.as_str(), "select" | "with" | "insert" | "update" | "delete" | "create" | "alter" | "replace" | "pragma"))
    {
        return BTreeSet::new();
    }
    let mut output = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Word(word) = token else {
            continue;
        };
        if matches!(
            word.as_str(),
            "current_time" | "current_date" | "current_timestamp"
        ) {
            output.insert(format!("sqlite::{word}"));
        }
        if !matches!(tokens.get(index + 1), Some(SqlToken::Symbol('('))) {
            continue;
        }
        if matches!(word.as_str(), "random" | "randomblob") {
            output.insert(format!("sqlite::{word}"));
        }
        if matches!(
            word.as_str(),
            "date" | "time" | "datetime" | "julianday" | "unixepoch" | "strftime"
        ) {
            let mut depth = 1;
            let mut arguments = Vec::new();
            for token in tokens.iter().skip(index + 2) {
                match token {
                    SqlToken::Symbol('(') => depth += 1,
                    SqlToken::Symbol(')') => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                arguments.push(token);
            }
            if arguments.is_empty() || arguments.iter().any(|token| matches!(token, SqlToken::String(value) if matches!(value.as_str(), "now" | "localtime" | "subsec" | "subsecond"))) ||
                word == "strftime" && arguments.len() == 1 {
                output.insert(format!("sqlite::{word}"));
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(source: &str) -> Vec<Finding> {
        let syntax = syn::parse_file(source).unwrap();
        let mut findings = BTreeMap::new();
        Scanner::new("crates/fixture/src/lib.rs", &mut findings).visit_file(&syntax);
        findings.into_values().collect()
    }

    fn fixture(source: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("crates/fixture/src")).unwrap();
        fs::write(directory.path().join("crates/fixture/src/lib.rs"), source).unwrap();
        directory
    }

    fn reviewed(inventory: &Inventory) -> Rules {
        Rules {
            version: VERSION,
            sources: inventory.sources.clone(),
            allowances: inventory
                .findings
                .iter()
                .map(|finding| Allowance {
                    source: finding.source.clone(),
                    kind: finding.kind.clone(),
                    target: finding.target.clone(),
                    context: finding.context.clone(),
                    fingerprint: finding.fingerprint.clone(),
                    count: finding.count,
                    reason: "fixture owner: adapter; remove when fixture extraction lands"
                        .to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn imported_aliases_and_indirect_bindings_are_inventory_sites() {
        let findings = scan(
            r#"
            use std::{time::SystemTime as Wall, env as environment};
            use getrandom::fill as secure_bytes;
            fn sample() {
                let now = Wall::now;
                let _ = now();
                let _ = environment::var("TOKEN");
                secure_bytes(&mut [0; 32]);
            }
        "#,
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.kind == "clock")
                .count(),
            2
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.target == "std::env::var")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.target == "getrandom::fill")
        );
    }

    #[test]
    fn renamed_self_modules_and_out_of_order_extern_aliases_are_resolved() {
        let findings = scan(
            r#"
            use std::time::{self as clocks, Duration};
            use crate::web_security::{self as security, Ticket};
            fn sample() { clocks::SystemTime::now(); security::random(); entropy::fill(&mut [0; 8]); }
            extern crate getrandom as entropy;
        "#,
        );
        for target in [
            "std::time::SystemTime::now",
            "crate::web_security::random",
            "getrandom::fill",
        ] {
            assert!(
                findings.iter().any(|finding| finding.target == target),
                "missing {target}: {findings:?}"
            );
        }
    }

    #[test]
    fn helper_wrappers_and_method_receivers_do_not_hide_effects() {
        let findings = scan(
            r#"
            use reqwest::blocking::Client as Http;
            use std::time::Instant as Tick;
            fn wrapper() { let _ = std::time::SystemTime::now(); }
            fn request(client: &Http, started: Tick) {
                client.get("https://example.test").send();
                started.elapsed();
                let mut child = std::process::Command::new("true");
                child.output();
            }
        "#,
        );
        for target in [
            "std::time::SystemTime::now",
            "reqwest::blocking::Client::send",
            "std::time::Instant::elapsed",
            "std::process::Command::new",
            "std::process::Command::output",
        ] {
            assert!(
                findings.iter().any(|finding| finding.target == target),
                "missing {target}: {findings:?}"
            );
        }
    }

    #[test]
    fn struct_fields_are_resolved_before_impls_and_through_wrappers() {
        let findings = scan(
            r#"
            use reqwest::blocking::Client as Http;
            impl Adapter { fn dispatch(&self) { self.client.as_ref().unwrap().post("https://example.test").send(); } }
            struct Adapter { client: Option<std::sync::Arc<Http>> }
            mod nested {
                use super::Http;
                impl Shell { fn dispatch(&self) { self.client.get("https://example.test").send(); } }
                struct Shell { client: Http }
            }
        "#,
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.target == "reqwest::blocking::Client::send")
                .count(),
            2,
            "{findings:?}"
        );
    }

    #[test]
    fn alternate_target_imports_cannot_silently_overwrite_effect_aliases() {
        let findings = scan(
            r#"
            #[cfg(target_os = "linux")] use std::time::SystemTime as Clock;
            #[cfg(target_os = "macos")] use deterministic::Clock;
            fn sample() { Clock::now(); }
        "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "effect-alias-conflict"),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.target == "std::time::SystemTime::now"),
            "{findings:?}"
        );
    }

    #[test]
    fn comments_literals_and_zeroization_are_not_fake_effects() {
        let findings = scan(
            r#"
            // std::time::SystemTime::now(); getrandom::fill(&mut bytes);
            fn clean() {
                let example = "std::time::SystemTime::now()";
                let mut bytes = [7_u8; 8];
                bytes.fill(0);
                let description = "Consider SQL random() and datetime('now')";
            }
        "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn known_platform_ambient_helpers_require_caller_review() {
        let findings = scan(
            r#"
            use crate::web_security::random as nonce;
            use day2::resource_admin as resource;
            fn helper_callers() { nonce(); resource::now_ms(); }
        "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.target == "crate::web_security::random")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.target == "day2::resource_admin::now_ms")
        );
    }

    #[test]
    fn sql_tokens_ignore_quoted_names_strings_and_comments() {
        assert!(sql_hazards("SELECT 'random()', \"CURRENT_TIMESTAMP\", [current_time], `CURRENT_DATE` -- randomblob(1)\n/* datetime('now') */", true).is_empty());
        assert!(
            sql_hazards(
                "SELECT datetime('2026-01-01'), strftime('%s', '2026-01-01'), date(?1)",
                true
            )
            .is_empty()
        );
        assert_eq!(
            sql_hazards(
                "CREATE TABLE t (at DEFAULT CURRENT_TIMESTAMP, id DEFAULT (randomblob(8)), day DEFAULT (date()))",
                true
            ),
            BTreeSet::from([
                "sqlite::current_timestamp".to_owned(),
                "sqlite::date".to_owned(),
                "sqlite::randomblob".to_owned()
            ])
        );
        assert!(
            sql_hazards(
                "SELECT strftime('%s'), unixepoch('subsec'), datetime('2020-01-01','localtime')",
                true
            )
            .contains("sqlite::datetime")
        );
    }

    #[test]
    fn sql_constants_and_executed_fragments_are_checked_once() {
        let findings = scan(
            r#"
            const SQL: &str = "SELECT random(), datetime('now')";
            fn query(db: Db) { db.execute_batch(SQL); db.prepare("CURRENT_TIMESTAMP"); }
        "#,
        );
        assert_eq!(findings.len(), 3, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.kind == "sql-ambient" && finding.count == 1)
        );
    }

    #[test]
    fn test_only_scopes_skip_but_unknown_platform_scopes_remain() {
        let findings = scan(
            r#"
            #[cfg(test)] mod tests { fn f() { std::time::Instant::now(); } }
            #[cfg(all(test, feature = "fixture"))] fn test_only() { std::env::var("TEST"); }
            #[cfg(any(test, target_os = "linux"))] fn production() { std::time::Instant::now(); }
            #[cfg(not(test))] fn ordinary() { std::time::Instant::now(); }
            #[cfg_attr(not(test), cfg(test))] fn suppressed() { std::time::Instant::now(); }
            struct Adapter;
            impl Adapter { #[cfg(test)] fn f() { std::time::Instant::now(); } }
        "#,
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.context == "production")
        );
        assert!(findings.iter().any(|finding| finding.context == "ordinary"));
    }

    #[test]
    fn external_test_modules_are_catalogued_but_not_inspected() {
        let directory =
            fixture("#[cfg(test)] mod fixtures; fn live() { std::time::Instant::now(); }");
        fs::write(
            directory.path().join("crates/fixture/src/fixtures.rs"),
            "mod child; fn fixture() { std::env::var(\"TEST\"); }",
        )
        .unwrap();
        fs::create_dir(directory.path().join("crates/fixture/src/fixtures")).unwrap();
        fs::write(
            directory
                .path()
                .join("crates/fixture/src/fixtures/child.rs"),
            "fn fixture() { std::env::var(\"TEST\"); }",
        )
        .unwrap();
        let result = inventory(directory.path()).unwrap();
        assert_eq!(result.sources.len(), 3);
        assert_eq!(result.findings.len(), 1, "{:?}", result.findings);
    }

    #[test]
    fn a_production_include_keeps_shared_test_source_in_the_scan() {
        let directory = fixture("#[cfg(test)] mod fixture; include!(\"./fixture.rs\");");
        fs::write(
            directory.path().join("crates/fixture/src/fixture.rs"),
            "fn clock() { std::time::Instant::now(); }",
        )
        .unwrap();
        let result = inventory(directory.path()).unwrap();
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.source == "crates/fixture/src/fixture.rs"
                    && finding.kind == "clock"),
            "{:?}",
            result.findings
        );
    }

    #[test]
    fn harmless_new_source_and_stale_source_require_review() {
        let directory = fixture("fn pure() {}");
        let original = inventory(directory.path()).unwrap();
        let rules = reviewed(&original);
        assert!(validate(&rules, &original).is_ok());
        fs::write(
            directory.path().join("crates/fixture/src/new.rs"),
            "fn pure() {}",
        )
        .unwrap();
        assert!(
            validate(&rules, &inventory(directory.path()).unwrap())
                .unwrap_err()
                .to_string()
                .contains("unreviewed")
        );
        let mut changed = original.clone();
        changed.sources.clear();
        assert!(
            validate(&rules, &changed)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }

    #[test]
    fn all_declared_roots_build_scripts_and_integration_paths_are_catalogued() {
        let directory = fixture("fn pure() {}");
        fs::create_dir_all(directory.path().join("cli/checks/src")).unwrap();
        fs::write(
            directory.path().join("cli/checks/src/lib.rs"),
            "fn fixture() { std::env::var(\"INPUT\"); }",
        )
        .unwrap();
        fs::write(
            directory.path().join("build.rs"),
            "fn main() { std::env::var(\"BUILD\"); }",
        )
        .unwrap();
        fs::create_dir_all(directory.path().join("crates/fixture/tests")).unwrap();
        fs::write(
            directory.path().join("crates/fixture/tests/runtime.rs"),
            "fn test() { std::env::var(\"TEST\"); }",
        )
        .unwrap();
        fs::create_dir_all(directory.path().join("crates/fixture/src/tests")).unwrap();
        fs::write(
            directory.path().join("crates/fixture/src/tests/bypass.rs"),
            "fn bypass() { std::env::var(\"BYPASS\"); }",
        )
        .unwrap();
        let result = inventory(directory.path()).unwrap();
        assert_eq!(result.sources.len(), 5);
        assert_eq!(result.findings.len(), 3, "{:?}", result.findings);
        assert!(
            result
                .sources
                .contains(&"crates/fixture/tests/runtime.rs".to_owned())
        );
    }

    #[test]
    fn new_stale_duplicate_and_excess_call_allowances_fail() {
        let actual = Inventory {
            version: VERSION,
            sources: vec!["crates/fixture/src/lib.rs".to_owned()],
            findings: scan("fn clock() { std::time::Instant::now(); }"),
        };
        let mut rules = reviewed(&actual);
        assert!(validate(&rules, &actual).is_ok());
        rules.allowances[0].count += 1;
        assert!(
            validate(&rules, &actual)
                .unwrap_err()
                .to_string()
                .contains("changed occurrence count")
        );
        rules.allowances[0].count = 1;
        let mut additional = actual.clone();
        additional.findings[0].count += 1;
        assert!(validate(&rules, &additional).is_err());
        let mut removed = actual.clone();
        removed.findings.clear();
        assert!(
            validate(&rules, &removed)
                .unwrap_err()
                .to_string()
                .contains("stale allowance")
        );
        let duplicate: Allowance =
            serde_json::from_value(serde_json::to_value(&rules.allowances[0]).unwrap()).unwrap();
        rules.allowances.push(duplicate);
        assert!(
            validate(&rules, &actual)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        rules.allowances.clear();
        assert!(
            validate(&rules, &actual)
                .unwrap_err()
                .to_string()
                .contains("unreviewed clock")
        );
    }

    #[test]
    fn fingerprints_survive_formatting_but_bind_arguments_and_context() {
        assert_eq!(
            scan("fn f(){std::env::var(\"A\");}"),
            scan("\n\n fn f() {\n std::env::var( \"A\" );\n }")
        );
        assert_ne!(
            scan("fn f(){std::env::var(\"A\");}"),
            scan("fn f(){std::env::var(\"B\");}")
        );
        assert_ne!(
            scan("fn f(){std::env::var(\"A\");}"),
            scan("fn g(){std::env::var(\"A\");}")
        );
    }

    #[test]
    fn macros_globs_reexports_and_suppression_points_need_review() {
        let findings = scan(
            r#"
            use std::time::*;
            pub use std::time::SystemTime as Wall;
            #[allow(clippy::disallowed_methods)]
            fn f() {
                let _ = option_env!("TOKEN");
                let _ = env!("TOKEN");
                tracing::info!(at = std::time::SystemTime::now(), "message");
                opaque!(otherwise => std::time::Instant::now());
            }
        "#,
        );
        for kind in [
            "effect-glob",
            "effect-reexport",
            "lint-suppression",
            "environment-macro",
            "clock",
        ] {
            assert!(
                findings.iter().any(|finding| finding.kind == kind),
                "missing {kind}: {findings:?}"
            );
        }
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.kind == "clock")
                .count(),
            2
        );
    }

    #[test]
    fn malformed_unknown_and_unbounded_policy_values_fail_closed() {
        assert!(
            serde_json::from_str::<Rules>(
                r#"{"version":1,"sources":[],"allowances":[],"permit_all":true}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<Rules>("{}").is_err());
        let actual = Inventory {
            version: VERSION,
            sources: vec![],
            findings: vec![],
        };
        let mut rules = reviewed(&actual);
        rules.version = 2;
        assert!(validate(&rules, &actual).is_err());
        rules.version = VERSION;
        rules.sources = vec!["b".to_owned(), "a".to_owned()];
        assert!(
            validate(&rules, &actual)
                .unwrap_err()
                .to_string()
                .contains("sorted")
        );
        let actual = Inventory {
            version: VERSION,
            sources: vec!["crates/fixture/src/lib.rs".to_owned()],
            findings: scan("fn f() { std::time::Instant::now(); }"),
        };
        let mut rules = reviewed(&actual);
        rules.allowances[0].reason.clear();
        assert!(
            validate(&rules, &actual)
                .unwrap_err()
                .to_string()
                .contains("review reason")
        );
        rules.allowances[0].reason = "review".to_owned();
        rules.allowances[0].count = 0;
        assert!(
            validate(&rules, &actual)
                .unwrap_err()
                .to_string()
                .contains("positive")
        );
    }

    #[test]
    fn public_checker_rejects_duplicate_json_keys_and_symlink_inputs() {
        let directory = fixture("fn pure() {}");
        fs::write(
            directory.path().join(RULES_FILE),
            r#"{"version":1,"version":1,"sources":[],"allowances":[]}"#,
        )
        .unwrap();
        assert!(
            check(directory.path())
                .unwrap_err()
                .chain()
                .any(|error| error.to_string().contains("duplicate"))
        );
        #[cfg(unix)]
        {
            let target = directory.path().join("reviewed.json");
            fs::write(&target, "{}").unwrap();
            let link = directory.path().join("linked.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                read_regular(&link, MAX_CONFIG_BYTES)
                    .unwrap_err()
                    .to_string()
                    .contains("regular file")
            );
            std::os::unix::fs::symlink(
                directory.path().join("crates/fixture/src/lib.rs"),
                directory.path().join("crates/fixture/src/link.rs"),
            )
            .unwrap();
            assert!(
                inventory(directory.path())
                    .unwrap_err()
                    .to_string()
                    .contains("symlink")
            );
        }
    }
}
