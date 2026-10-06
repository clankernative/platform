//! A reviewed ratchet for ambient platform effects. This is a syntax boundary,
//! not Rust type resolution: it deliberately inventories imports, indirection,
//! and suppression points that require review alongside concrete effect paths.
//! Parent/local globs cannot supply known ambient names without a canonical
//! same-source import. The conservative name set includes production import
//! aliases across scanned sources; it does not guess module parents. Explicit
//! crate wrapper imports retain their existing port review, and arbitrary
//! external reexports, type aliases and macro expansion remain limitations.
//! Only unconditional imports/declarations disambiguate inherited names across
//! alternate targets. These refusals cannot be authorized by effect allowances.
//! Known ReadDir acquisition/parameter lineage has a finite consumer/adaptor
//! boundary. Unmodeled explicit calls receiving it refuse; only exact standard
//! Result/Option acquisition projections are pure. Syntactically explicit
//! unsupported generic/tuple/array/slice containers retain a refusal marker;
//! hidden containment, per-entry values, callback captures and arbitrary return
//! types are not a containment or general Rust output-resolution claim. Lazy
//! RHS transfers require a modeled native first iterator even in canonical
//! Iterator UFCS; a custom implementation could otherwise advance immediately.

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
const MAX_ALIAS_ROUNDS: usize = 32;
const MAX_PARENT_EFFECT_DIAGNOSTICS: usize = 32;
const READ_DIR_HANDLE: &str = "std::fs::ReadDir";
const READ_DIR_RESULT: &str = "std::io::Result<std::fs::ReadDir>";
const READ_DIR_OPTION: &str = "std::option::Option<std::fs::ReadDir>";
// A refusal marker for a syntactically known native handle in an unsupported
// container, never a fourth admitted wrapper kind or a guessed concrete type.
const READ_DIR_UNMODELED: &str = "<unmodeled ReadDir container>";

fn identifier_name(identifier: &syn::Ident) -> String {
    use syn::ext::IdentExt;
    // r# is Rust lexical quoting, not a distinct identifier. Normalize only
    // semantic keys/targets; original AST tokens still fingerprint the source.
    identifier.unraw().to_string()
}

fn path_name(path: &syn::Path) -> String {
    path.segments.iter().map(|segment| identifier_name(&segment.ident)).collect::<Vec<_>>().join("::")
}

fn path_is_ident(path: &syn::Path, expected: &str) -> bool {
    path.get_ident().is_some_and(|identifier| identifier_name(identifier) == expected)
}

fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(identifier) => identifier_name(identifier),
        syn::Member::Unnamed(index) => index.index.to_string(),
    }
}

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
    require_canonical_html_crate(&parsed, &test_only)?;
    let ambient_names = ambient_import_names(&parsed, &test_only)?;
    let mut findings = BTreeMap::new();
    for (source, syntax) in &parsed {
        if test_only.contains(source) || definitely_test_only(&syntax.attrs) {
            continue;
        }
        let mut scanner = Scanner::new(source, &mut findings, &ambient_names);
        scanner.visit_file(syntax);
        scanner.require_resolved_parent_effects()?;
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

fn require_canonical_html_crate(parsed: &BTreeMap<String, syn::File>, test_only: &BTreeSet<String>) -> Result<()> {
    // Absolute paths use Rust's extern prelude, including crate-root aliases
    // inherited by child files. Reject a conflicting binding across the same
    // already bounded authored-source inventory; do not resolve module graphs.
    struct CrateBindings { invalid: bool }
    impl<'ast> Visit<'ast> for CrateBindings {
        fn visit_item(&mut self, item: &'ast Item) {
            if !definitely_test_only(item_attributes(item)) { visit::visit_item(self, item); }
        }
        fn visit_expr(&mut self, expression: &'ast Expr) {
            if !definitely_test_only(expression_attributes(expression)) { visit::visit_expr(self, expression); }
        }
        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if !definitely_test_only(&function.attrs) { visit::visit_impl_item_fn(self, function); }
        }
        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if !definitely_test_only(&function.attrs) { visit::visit_trait_item_fn(self, function); }
        }
        fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
            use syn::ext::IdentExt;
            let binding = item.rename.as_ref().map(|(_, name)| name).unwrap_or(&item.ident);
            if binding.unraw() == "maud" && (item.ident.unraw() != "maud" || !unconditional_scope(&item.attrs)) {
                self.invalid = true;
            }
        }
    }
    for (source, syntax) in parsed {
        if test_only.contains(source) || definitely_test_only(&syntax.attrs) { continue; }
        let mut bindings = CrateBindings { invalid: false };
        bindings.visit_file(syntax);
        ensure!(!bindings.invalid, "noncanonical Maud extern-crate binding in {}", source.chars().take(256).collect::<String>());
    }
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
    let entries: fs::ReadDir = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => return Err(error).with_context(|| format!("list {}", directory.display())),
    };
    for entry in entries {
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
                if path_is_ident(&invocation.path, "include")
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
                &directory.join(identifier_name(&module.ident)),
                test,
                parsed,
                edges,
            );
        } else {
            let explicit = module.attrs.iter().find_map(|attribute| {
                if !path_is_ident(attribute.path(), "path") {
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
                    directory.join(format!("{}.rs", identifier_name(&module.ident))),
                    directory.join(identifier_name(&module.ident)).join("mod.rs"),
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
        Meta::Path(path) if path_is_ident(path, "test") => Some(false),
        Meta::List(list) => {
            let nested = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )
                .ok()?;
            let values: Vec<_> = nested.iter().map(cfg_value).collect();
            if path_is_ident(&list.path, "all") {
                if values.contains(&Some(false)) {
                    Some(false)
                } else if values.iter().all(|value| *value == Some(true)) {
                    Some(true)
                } else {
                    None
                }
            } else if path_is_ident(&list.path, "any") {
                if values.contains(&Some(true)) {
                    Some(true)
                } else if values.iter().all(|value| *value == Some(false)) {
                    Some(false)
                } else {
                    None
                }
            } else if path_is_ident(&list.path, "not") && values.len() == 1 {
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
        if path_is_ident(attribute.path(), "cfg") {
            attribute
                .parse_args::<Meta>()
                .ok()
                .is_some_and(|meta| cfg_value(&meta) == Some(false))
        } else if path_is_ident(attribute.path(), "cfg_attr") {
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
                            path_is_ident(&list.path, "cfg")
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

fn glob_names(prefix: &str) -> &'static [&'static str] {
    match prefix {
        "std" => &["time", "env", "fs", "path", "thread", "process", "net"],
        "std::time" => &["SystemTime", "Instant"],
        "std::path" => &["Path", "PathBuf", "Components", "Iter", "absolute"],
        "time" => &["OffsetDateTime", "UtcDateTime"],
        "rustix" => &["time", "fs"],
        "rustix::fs" => &["open"],
        "rustix::time" => &[
            "clock_gettime",
            "clock_gettime_dynamic",
            "clock_getres",
            "clock_settime",
            "clock_nanosleep_absolute",
            "clock_nanosleep_relative",
            "nanosleep",
            "ClockId",
        ],
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
    }
}

fn import_names(tree: &UseTree, prefix: &str, output: &mut Vec<(String, String)>) {
    let join = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}::{name}")
        }
    };
    match tree {
        UseTree::Path(path) => import_names(&path.tree, &join(&identifier_name(&path.ident)), output),
        UseTree::Name(name) => {
            let target = if name.ident == "self" {
                prefix.to_owned()
            } else {
                join(&identifier_name(&name.ident))
            };
            let alias = if name.ident == "self" {
                prefix.rsplit("::").next().unwrap_or(prefix).to_owned()
            } else {
                identifier_name(&name.ident)
            };
            output.push((alias, target));
        }
        UseTree::Rename(rename) => output.push((
            identifier_name(&rename.rename),
            if rename.ident == "self" {
                prefix.to_owned()
            } else {
                join(&identifier_name(&rename.ident))
            },
        )),
        UseTree::Group(group) => {
            for tree in &group.items {
                import_names(tree, prefix, output);
            }
        }
        UseTree::Glob(_) => {
            for name in glob_names(prefix) {
                output.push(((*name).to_owned(), join(name)));
            }
        }
    }
}

fn relative_name(mut name: &str) -> &str {
    while let Some(rest) = name.strip_prefix("super::") {
        name = rest;
    }
    name.strip_prefix("self::").unwrap_or(name)
}

fn parent_import(name: &str) -> bool {
    name == "super" || name.starts_with("super::")
}

fn local_glob(name: &str) -> bool {
    parent_import(name)
        || name == "self"
        || name.starts_with("self::")
        || name == "crate"
        || name.starts_with("crate::")
}

/// Import aliases are a conservative workspace name set, not an assertion that
/// a particular file is a module's parent. An explicit local binding disambiguates
/// ordinary domain names; unresolved inherited ambient names require source fixes.
fn ambient_import_names(
    parsed: &BTreeMap<String, syn::File>,
    test_only: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    fn alias_type(ty: &Type) -> Option<String> {
        match ty {
            Type::BareFn(_) => Some(String::new()),
            Type::Reference(ty) => alias_type(&ty.elem),
            Type::Paren(ty) => alias_type(&ty.elem),
            Type::Group(ty) => alias_type(&ty.elem),
            Type::Path(ty) => {
                let last = ty.path.segments.last()?;
                if matches!(
                    identifier_name(&last.ident).as_str(),
                    "Option" | "Result" | "Box" | "Arc" | "Rc" | "Mutex" | "RwLock"
                ) && let syn::PathArguments::AngleBracketed(arguments) = &last.arguments
                    && let Some(syn::GenericArgument::Type(inner)) = arguments.args.first()
                {
                    return alias_type(inner);
                }
                let target = ty
                    .path
                    .segments
                    .iter()
                    .map(|segment| identifier_name(&segment.ident))
                    .collect::<Vec<_>>()
                    .join("::");
                ambient_receiver_type(&target).then_some(target)
            }
            _ => None,
        }
    }

    fn reference_paths(expression: &Expr) -> Vec<String> {
        match expression {
            Expr::Path(path) => vec![
                path.path
                    .segments
                    .iter()
                    .map(|segment| identifier_name(&segment.ident))
                    .collect::<Vec<_>>()
                    .join("::"),
            ],
            Expr::Paren(expression) => reference_paths(&expression.expr),
            Expr::Group(expression) => reference_paths(&expression.expr),
            Expr::Reference(expression) => reference_paths(&expression.expr),
            Expr::Cast(expression) => reference_paths(&expression.expr),
            Expr::Try(expression) => reference_paths(&expression.expr),
            Expr::Unary(expression) if matches!(expression.op, syn::UnOp::Deref(_)) => {
                reference_paths(&expression.expr)
            }
            Expr::Call(expression)
                if expression.args.len() == 1
                    && matches!(reference_paths(&expression.func).as_slice(), [target] if value_wrapper_target(target)) =>
            {
                reference_paths(&expression.args[0])
            }
            Expr::Block(expression) => block_references(&expression.block),
            Expr::If(expression) => {
                let mut paths = block_references(&expression.then_branch);
                if let Some((_, alternative)) = &expression.else_branch {
                    paths.extend(reference_paths(alternative));
                }
                paths
            }
            Expr::Match(expression) => expression
                .arms
                .iter()
                .flat_map(|arm| reference_paths(&arm.body))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn block_references(block: &syn::Block) -> Vec<String> {
        match block.stmts.last() {
            Some(syn::Stmt::Expr(expression, None)) => reference_paths(expression),
            _ => Vec::new(),
        }
    }

    fn callback_type(ty: &Type, aliases: &BTreeSet<String>) -> bool {
        match ty {
            Type::BareFn(_) => true,
            Type::Reference(ty) => callback_type(&ty.elem, aliases),
            Type::Paren(ty) => callback_type(&ty.elem, aliases),
            Type::Group(ty) => callback_type(&ty.elem, aliases),
            Type::Path(ty) => {
                let Some(last) = ty.path.segments.last() else {
                    return false;
                };
                if matches!(
                    identifier_name(&last.ident).as_str(),
                    "Option" | "Result" | "Box" | "Arc" | "Rc" | "Mutex" | "RwLock"
                ) && let syn::PathArguments::AngleBracketed(arguments) = &last.arguments
                {
                    return arguments.args.iter().any(|argument| match argument {
                        syn::GenericArgument::Type(inner) => callback_type(inner, aliases),
                        _ => false,
                    });
                }
                aliases.contains(&identifier_name(&last.ident))
            }
            _ => false,
        }
    }

    fn unknown_callback_initializer(expression: &Expr) -> bool {
        match expression {
            Expr::Path(_) => false,
            Expr::Paren(expression) => unknown_callback_initializer(&expression.expr),
            Expr::Group(expression) => unknown_callback_initializer(&expression.expr),
            Expr::Reference(expression) => unknown_callback_initializer(&expression.expr),
            Expr::Cast(expression) => unknown_callback_initializer(&expression.expr),
            Expr::Try(expression) => unknown_callback_initializer(&expression.expr),
            Expr::Unary(expression) if matches!(expression.op, syn::UnOp::Deref(_)) => {
                unknown_callback_initializer(&expression.expr)
            }
            Expr::Call(expression)
                if expression.args.len() == 1
                    && matches!(reference_paths(&expression.func).as_slice(), [target] if value_wrapper_target(target)) =>
            {
                unknown_callback_initializer(&expression.args[0])
            }
            Expr::Block(expression) => unknown_callback_block(&expression.block),
            Expr::If(expression) => {
                unknown_callback_block(&expression.then_branch)
                    || expression
                        .else_branch
                        .as_ref()
                        .is_some_and(|(_, branch)| unknown_callback_initializer(branch))
            }
            Expr::Match(expression) => expression
                .arms
                .iter()
                .any(|arm| unknown_callback_initializer(&arm.body)),
            _ => true,
        }
    }

    fn unknown_callback_block(block: &syn::Block) -> bool {
        struct Names(BTreeSet<String>);
        impl<'ast> Visit<'ast> for Names {
            fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
                self.0.insert(identifier_name(&pattern.ident));
                visit::visit_pat_ident(self, pattern);
            }
        }
        let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() else {
            return true;
        };
        let mut locals = Names(BTreeSet::new());
        for statement in &block.stmts {
            if let syn::Stmt::Local(local) = statement {
                locals.visit_pat(&local.pat);
            }
        }
        reference_paths(tail).iter().any(|target| {
            locals
                .0
                .contains(target.split("::").next().unwrap_or_default())
        }) || unknown_callback_initializer(tail)
    }

    struct CallbackAliases(Vec<(String, Type)>);
    impl<'ast> Visit<'ast> for CallbackAliases {
        fn visit_item(&mut self, item: &'ast Item) {
            if !definitely_test_only(item_attributes(item)) {
                visit::visit_item(self, item);
            }
        }

        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            self.0.push((identifier_name(&item.ident), (*item.ty).clone()));
        }

        fn visit_expr(&mut self, expression: &'ast Expr) {
            if !definitely_test_only(expression_attributes(expression)) {
                visit::visit_expr(self, expression);
            }
        }
    }

    struct Imports(
        Vec<(String, String)>,
        Vec<(String, String)>,
        BTreeSet<String>,
        BTreeSet<String>,
    );
    impl Imports {
        fn value_alias(&mut self, name: &syn::Ident, ty: &Type, expression: &Expr) {
            // A declared callback with an unsupported initializer is not proven
            // effect-free. Parent imports must refuse it; no factory or local
            // return-flow resolution is inferred from its signature.
            if callback_type(ty, &self.2) && unknown_callback_initializer(expression) {
                self.3.insert(identifier_name(name));
            }
            // Keep reference edges until import and constant aliases have been
            // composed. A nominal type does not prove DATA, but a DATA terminal
            // must not become ambient merely because its import name is broad.
            match alias_type(ty) {
                Some(declared) if !declared.is_empty() => self.0.push((identifier_name(name), declared)),
                _ => {
                    for target in reference_paths(expression) {
                        self.1.push((identifier_name(name), target));
                    }
                }
            }
        }
    }
    impl<'ast> Visit<'ast> for Imports {
        fn visit_item(&mut self, item: &'ast Item) {
            if !definitely_test_only(item_attributes(item)) {
                visit::visit_item(self, item);
            }
        }

        fn visit_expr(&mut self, expression: &'ast Expr) {
            if !definitely_test_only(expression_attributes(expression)) {
                visit::visit_expr(self, expression);
            }
        }

        fn visit_item_use(&mut self, import: &'ast syn::ItemUse) {
            import_names(&import.tree, "", &mut self.0);
        }

        fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
            if let Some((_, alias)) = &item.rename {
                self.0.push((identifier_name(alias), identifier_name(&item.ident)));
            }
        }

        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.value_alias(&item.ident, &item.ty, &item.expr);
            visit::visit_item_const(self, item);
        }

        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            self.value_alias(&item.ident, &item.ty, &item.expr);
            visit::visit_item_static(self, item);
        }
    }
    let mut imports = Imports(Vec::new(), Vec::new(), BTreeSet::new(), BTreeSet::new());
    for (source, syntax) in parsed {
        if !test_only.contains(source) && !definitely_test_only(&syntax.attrs) {
            let mut aliases = CallbackAliases(Vec::new());
            aliases.visit_file(syntax);
            ensure!(
                aliases.0.len() <= MAX_FINDINGS,
                "architecture callback-type count limit exceeded"
            );
            imports.2.clear();
            for _ in 0..MAX_ALIAS_ROUNDS {
                let additions: BTreeSet<_> = aliases
                    .0
                    .iter()
                    .filter(|(_, ty)| callback_type(ty, &imports.2))
                    .map(|(name, _)| name.clone())
                    .collect();
                if additions.is_subset(&imports.2) {
                    break;
                }
                imports.2.extend(additions);
            }
            ensure!(
                aliases
                    .0
                    .iter()
                    .all(|(name, ty)| imports.2.contains(name) || !callback_type(ty, &imports.2)),
                "architecture callback-type chain limit exceeded"
            );
            imports.visit_file(syntax);
            ensure!(
                imports.0.len() + imports.1.len() + imports.3.len() <= MAX_FINDINGS,
                "architecture import-name limit exceeded"
            );
        }
    }
    // This composes only collected syntactic import/reference prefixes. It
    // neither resolves compiler modules/types nor infers arbitrary call output.
    // Parent/self prefixes are workspace name candidates, as in the existing
    // name closure; collisions retain every possible terminal conservatively.
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut origin_bytes = 0usize;
    let mut origin_count = 0usize;
    for (name, target) in imports.0.iter().chain(&imports.1) {
        let target = relative_name(target);
        if edges
            .get(name)
            .is_some_and(|targets| targets.contains(target))
        {
            continue;
        }
        origin_bytes += name.len() + target.len();
        origin_count += 1;
        ensure!(
            origin_bytes <= MAX_CONFIG_BYTES,
            "architecture reference-alias space limit exceeded"
        );
        edges
            .entry(name.clone())
            .or_default()
            .insert(target.to_owned());
    }
    // Expand only reference candidates, rather than unrelated namespace paths.
    let mut origins: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (name, target) in &imports.1 {
        origins
            .entry(name.clone())
            .or_default()
            .insert(relative_name(target).to_owned());
    }
    let mut attempts = 0usize;
    let mut converged = false;
    for _ in 0..MAX_ALIAS_ROUNDS {
        let mut additions = Vec::new();
        let mut addition_bytes = 0usize;
        for (name, targets) in &origins {
            for target in targets {
                let (first, suffix) = target.split_once("::").unwrap_or((target, ""));
                if let Some(prefixes) = edges.get(first) {
                    for prefix in prefixes {
                        attempts += 1;
                        ensure!(
                            attempts <= MAX_FINDINGS * MAX_ALIAS_ROUNDS,
                            "architecture reference-alias work limit exceeded"
                        );
                        let length =
                            prefix.len() + suffix.len() + if suffix.is_empty() { 0 } else { 2 };
                        ensure!(
                            length <= MAX_CONFIG_BYTES,
                            "architecture reference-alias path limit exceeded"
                        );
                        addition_bytes += name.len() + length;
                        ensure!(
                            addition_bytes <= MAX_CONFIG_BYTES,
                            "architecture reference-alias expansion space limit exceeded"
                        );
                        let combined = if suffix.is_empty() {
                            prefix.clone()
                        } else {
                            format!("{prefix}::{suffix}")
                        };
                        if !targets.contains(&combined) {
                            additions.push((name.clone(), combined));
                            ensure!(
                                additions.len() <= MAX_FINDINGS,
                                "architecture reference-alias count limit exceeded"
                            );
                        }
                    }
                }
            }
        }
        let mut changed = false;
        for (name, target) in additions {
            let bytes = name.len() + target.len();
            if origins.entry(name).or_default().insert(target.clone()) {
                origin_bytes += bytes;
                origin_count += 1;
                ensure!(
                    origin_bytes <= MAX_CONFIG_BYTES && origin_count <= MAX_FINDINGS,
                    "architecture reference-alias space/count limit exceeded"
                );
                changed = true;
            }
        }
        if !changed {
            converged = true;
            break;
        }
    }
    ensure!(
        converged,
        "architecture reference-alias chain limit exceeded"
    );
    let mut names = BTreeSet::from(["DirBuilder".to_owned()]);
    names.extend(imports.3.iter().cloned());
    names.extend(imports.1.iter().filter_map(|(name, _)| {
        origins
            .get(name)
            .is_some_and(|targets| {
                targets.iter().any(|target| {
                    hazard(target).is_some()
                        || ambient_receiver_type(target)
                        || imports.3.contains(target)
                })
            })
            .then(|| name.clone())
    }));
    for prefix in [
        "std",
        "std::time",
        "std::env",
        "std::fs",
        "std::thread",
        "std::process",
        "std::net",
    ] {
        names.extend(glob_names(prefix).iter().map(|name| (*name).to_owned()));
    }
    for _ in 0..MAX_ALIAS_ROUNDS {
        let additions: BTreeSet<_> = imports
            .0
            .iter()
            .filter(|(_, target)| ambient_import_target(target, &names))
            .map(|(name, _)| name.clone())
            .collect();
        if additions.is_subset(&names) {
            return Ok(names);
        }
        names.extend(additions);
    }
    ensure!(
        imports
            .0
            .iter()
            .all(|(name, target)| names.contains(name) || !ambient_import_target(target, &names)),
        "architecture ambient import-alias chain limit exceeded"
    );
    Ok(names)
}

fn expression_attributes(expression: &Expr) -> &[Attribute] {
    match expression {
        Expr::Call(expr) => &expr.attrs,
        Expr::MethodCall(expr) => &expr.attrs,
        Expr::Block(expr) => &expr.attrs,
        Expr::Macro(expr) => &expr.attrs,
        Expr::Path(expr) => &expr.attrs,
        Expr::If(expr) => &expr.attrs,
        Expr::Match(expr) => &expr.attrs,
        Expr::Closure(expr) => &expr.attrs,
        _ => &[],
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DeclarationNamespace {
    Type,
    Value,
    Both,
}

#[derive(Clone, Copy)]
enum PathNamespace {
    Any,
    Type,
    Value,
}

impl DeclarationNamespace {
    fn includes(self, namespace: PathNamespace) -> bool {
        match namespace {
            PathNamespace::Any => true,
            PathNamespace::Type => matches!(self, Self::Type | Self::Both),
            PathNamespace::Value => matches!(self, Self::Value | Self::Both),
        }
    }
}

fn canonical_import_namespace(target: &str) -> Option<DeclarationNamespace> {
    // Only the already-known canonical effect vocabulary supplies import
    // namespaces. Unknown external exports are not guessed from their names.
    if matches!(
        target,
        "chrono::Utc" | "chrono::Local" | "rand::rngs::OsRng" | "rand_core::OsRng"
    ) {
        Some(DeclarationNamespace::Both)
    } else if ambient_receiver_type(target)
        || matches!(
            target,
            "uuid::Uuid"
                | "time::OffsetDateTime"
                | "time::UtcDateTime"
                | "std"
                | "std::time"
                | "std::env"
                | "std::fs"
                | "std::path"
                | "std::iter"
                | "core::iter"
                | "std::iter::Iterator"
                | "core::iter::Iterator"
                | "std::iter::IntoIterator"
                | "core::iter::IntoIterator"
                | "std::thread"
                | "std::process"
                | "std::net"
                | "tokio"
                | "tokio::time"
                | "tokio::fs"
                | "tokio::process"
                | "tokio::net"
                | "tokio::runtime"
                | "tokio::task"
                | "rand"
                | "rand::rngs"
                | "rand_core"
                | "reqwest"
                | "reqwest::blocking"
                | "ureq"
                | "socket2"
                | "chrono"
                | "uuid"
                | "time"
                | "getrandom"
                | "fastrand"
                | "libc"
                | "rustix"
                | "rustix::time"
                | "rustix::fs"
        )
    {
        Some(DeclarationNamespace::Type)
    } else if value_wrapper_target(target)
        || hazard(target).is_some() && {
            // Broad effect prefixes include exports whose namespace is not
            // known here. Only their existing finite free-function catalog is
            // a namespace proof; other exports conservatively remain unknown.
            let (prefix, name) = target.rsplit_once("::").unwrap_or(("", target));
            let broad = [
                "std::fs::",
                "tokio::fs::",
                "std::env::",
                "getrandom::",
                "fastrand::",
                "dotenv::",
                "dotenvy::",
            ]
            .iter()
            .any(|prefix| target.starts_with(prefix));
            !broad
                || glob_names(if prefix == "tokio::fs" {
                    "std::fs"
                } else {
                    prefix
                })
                .contains(&name)
        }
    {
        Some(DeclarationNamespace::Value)
    } else {
        None
    }
}

fn declarations<'a>(
    items: impl IntoIterator<Item = &'a Item>,
) -> BTreeMap<String, DeclarationNamespace> {
    items
        .into_iter()
        .filter(|item| unconditional_scope(item_attributes(item)))
        .filter_map(|item| {
            let (ident, namespace) = match item {
                Item::Const(item) => (&item.ident, DeclarationNamespace::Value),
                Item::Enum(item) => (&item.ident, DeclarationNamespace::Type),
                Item::Fn(item) => (&item.sig.ident, DeclarationNamespace::Value),
                Item::Mod(item) => (&item.ident, DeclarationNamespace::Type),
                Item::Static(item) => (&item.ident, DeclarationNamespace::Value),
                Item::Struct(item) => (
                    &item.ident,
                    if matches!(&item.fields, syn::Fields::Unit | syn::Fields::Unnamed(_)) {
                        DeclarationNamespace::Both
                    } else {
                        DeclarationNamespace::Type
                    },
                ),
                Item::Trait(item) => (&item.ident, DeclarationNamespace::Type),
                Item::TraitAlias(item) => (&item.ident, DeclarationNamespace::Type),
                Item::Type(item) => (&item.ident, DeclarationNamespace::Type),
                Item::Union(item) => (&item.ident, DeclarationNamespace::Type),
                _ => return None,
            };
            // A named-field struct, type alias, trait or module does not
            // shadow an imported value with the same spelling in Rust.
            Some((identifier_name(ident), namespace))
        })
        .fold(BTreeMap::new(), |mut names, (name, declared)| {
            // A type-only declaration may coexist with a genuine value
            // declaration. Neither source order removes that value shadow.
            names
                .entry(name)
                .and_modify(|namespace| {
                    if *namespace != declared {
                        *namespace = DeclarationNamespace::Both;
                    }
                })
                .or_insert(declared);
            names
        })
}

fn unconditional_scope(attributes: &[Attribute]) -> bool {
    attributes.iter().all(|attribute| {
        if path_is_ident(attribute.path(), "cfg") {
            attribute
                .parse_args::<Meta>()
                .ok()
                .is_some_and(|meta| cfg_value(&meta) == Some(true))
        } else {
            !path_is_ident(attribute.path(), "cfg_attr")
        }
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ValueKind {
    Data,
    Reference,
    Receiver,
}

struct Scanner<'a> {
    source: &'a str,
    findings: &'a mut BTreeMap<FindingKey, Finding>,
    context: Vec<String>,
    aliases: Vec<BTreeMap<String, String>>,
    named_imports: Vec<BTreeMap<String, String>>,
    parent_aliases: Vec<BTreeSet<String>>,
    conditional_aliases: Vec<BTreeSet<String>>,
    alias_dependencies: Vec<BTreeMap<String, BTreeSet<String>>>,
    parent_globs: Vec<bool>,
    declarations: Vec<BTreeMap<String, DeclarationNamespace>>,
    // Parent declarations do not disambiguate names imported by a child.
    // Blocks still see ordinary declarations in their own enclosing module.
    declaration_floors: Vec<usize>,
    ambient_names: &'a BTreeSet<String>,
    unresolved_parent_effects: BTreeSet<String>,
    conditional_effect_bindings: BTreeSet<String>,
    read_dir_ambiguities: BTreeSet<String>,
    values: Vec<BTreeMap<String, String>>,
    bindings: Vec<BTreeSet<String>>,
    // Receiver provenance can survive a call result (File/Command methods),
    // but reading that returned value does not reference the creating function.
    value_kinds: Vec<BTreeMap<String, ValueKind>>,
    // Value frames can be finer than import frames (parameters/branches).
    // This records the existing lexical import frame owning each value frame.
    value_scopes: Vec<usize>,
    // Modules do not inherit unqualified value bindings from their parent.
    // Their imports still follow the existing conservative alias rules.
    value_floors: Vec<usize>,
    fields: BTreeMap<String, BTreeMap<String, String>>,
    self_type: Option<String>,
}

impl<'a> Scanner<'a> {
    fn new(
        source: &'a str,
        findings: &'a mut BTreeMap<FindingKey, Finding>,
        ambient_names: &'a BTreeSet<String>,
    ) -> Self {
        let mut scanner = Self {
            source,
            findings,
            context: Vec::new(),
            aliases: vec![BTreeMap::new()],
            named_imports: vec![BTreeMap::new()],
            parent_aliases: vec![BTreeSet::new()],
            conditional_aliases: vec![BTreeSet::new()],
            alias_dependencies: vec![BTreeMap::new()],
            parent_globs: vec![false],
            declarations: vec![BTreeMap::new()],
            declaration_floors: vec![0],
            ambient_names,
            unresolved_parent_effects: BTreeSet::new(),
            conditional_effect_bindings: BTreeSet::new(),
            read_dir_ambiguities: BTreeSet::new(),
            values: vec![BTreeMap::new()],
            bindings: vec![BTreeSet::new()],
            value_kinds: vec![BTreeMap::new()],
            value_scopes: vec![0],
            value_floors: vec![0],
            fields: BTreeMap::new(),
            self_type: None,
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

    fn require_resolved_parent_effects(&self) -> Result<()> {
        ensure!(
            self.unresolved_parent_effects.is_empty(),
            "unresolved parent ambient imports in {} (canonical same-source imports required): {}",
            self.source,
            self.unresolved_parent_effects
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
        ensure!(
            self.conditional_effect_bindings.is_empty(),
            "conditional ambient local bindings in {} (an unconditional typed owner is required): {}",
            self.source,
            self.conditional_effect_bindings
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
        ensure!(
            self.read_dir_ambiguities.is_empty(),
            "unresolved ReadDir handoffs or iterator calls in {} (a supported canonical operation is required): {}",
            self.source,
            self.read_dir_ambiguities.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        Ok(())
    }

    fn parent_effect_path(&mut self, name: &str) {
        self.parent_effect_path_checked(name, false, PathNamespace::Any);
    }

    fn parent_effect_path_checked(
        &mut self,
        name: &str,
        unknown_callable: bool,
        namespace: PathNamespace,
    ) {
        self.require_known_alias_namespace(name, namespace);
        if matches!(namespace, PathNamespace::Value) && !name.contains("::") {
            self.require_known_value_import_precedence(name, false);
        }
        if !unknown_callable && (canonical_binding(name) || hazard(name).is_some()) {
            return;
        }
        let relative = relative_name(name);
        let first = relative.split("::").next().unwrap_or_default();
        if !self.ambient_names.contains(first)
            || !unknown_callable
                && !parent_import(name)
                && self.declaration_exempts(first, namespace)
            || !parent_import(name)
                && !relative.contains("::")
                && !unknown_callable
                && !matches!(namespace, PathNamespace::Type)
                && self
                    .value_origin(first)
                    .is_some_and(|origin| origin.as_deref() != Some(first))
        {
            return;
        }
        let inherited = self.alias_has_flag(
            first,
            &self.parent_aliases,
            &mut BTreeSet::new(),
            MAX_ALIAS_ROUNDS,
        );
        let parent_context =
            parent_import(name) || self.parent_globs.iter().any(|active| *active) || inherited;
        let conditional = parent_context
            && self.alias_has_flag(
                first,
                &self.conditional_aliases,
                &mut BTreeSet::new(),
                MAX_ALIAS_ROUNDS,
            );
        let import = self.aliases.iter().rev().find_map(|scope| scope.get(first));
        // A parent reentry is deliberately not a canonical local binding,
        // even if another scope happens to give the spelling an origin.
        if let Some(target) = import
            && !unknown_callable
            && !parent_import(name)
            && !inherited
            && !conditional
            && (canonical_binding(&self.resolve_name(target))
                || target.starts_with("crate::")
                || self.explicit_namespace_shadow(first))
        {
            return;
        }
        if parent_context && self.unresolved_parent_effects.len() < MAX_PARENT_EFFECT_DIAGNOSTICS {
            let context = if self.context.is_empty() {
                "<module>".to_owned()
            } else {
                self.context.join("::")
            };
            self.unresolved_parent_effects.insert(format!(
                "{context}: {}",
                name.chars().take(256).collect::<String>()
            ));
        }
    }

    fn declaration_exempts(&self, name: &str, namespace: PathNamespace) -> bool {
        self.declaration_scope(name, namespace).is_some()
    }

    fn declaration_scope(&self, name: &str, namespace: PathNamespace) -> Option<usize> {
        for index in (*self.declaration_floors.last().unwrap()..self.declarations.len()).rev() {
            if self.declarations[index]
                .get(name)
                .is_some_and(|declared| declared.includes(namespace))
            {
                return Some(index);
            }
            if let Some(target) = self.named_imports[index].get(name)
                && canonical_import_namespace(&self.resolve_name(target))
                    .is_none_or(|kind| kind.includes(namespace))
            {
                // A closer explicit import outranks an outer declaration.
                // Unknown imported namespaces conservatively form a barrier.
                return None;
            }
        }
        None
    }

    fn value_declaration_shadows_alias(&self, name: &str) -> bool {
        let Some(declaration) = self.declaration_scope(name, PathNamespace::Value) else {
            return false;
        };
        let alias = self
            .aliases
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, aliases)| {
                let target = aliases.get(name)?;
                canonical_import_namespace(&self.resolve_name(target))
                    .is_none_or(|kind| kind.includes(PathNamespace::Value))
                    .then_some(index)
            });
        // Equal-frame injected platform helper origins stay reviewed origins.
        alias.is_none_or(|alias| declaration > alias)
    }

    fn require_known_alias_namespace(&mut self, name: &str, namespace: PathNamespace) {
        if matches!(namespace, PathNamespace::Any) {
            return;
        }
        let first = relative_name(name).split("::").next().unwrap_or_default();
        if self.declaration_exempts(first, namespace) && !parent_import(name) {
            return;
        }
        let mut masked = false;
        for (index, imports) in self.named_imports.iter().enumerate().rev() {
            let Some(target) = imports.get(first) else {
                continue;
            };
            let origin = self.resolve_name(target);
            let kind = canonical_import_namespace(&origin);
            if !masked {
                if kind.is_some_and(|kind| kind.includes(namespace)) {
                    return;
                }
                masked = true;
                continue;
            }
            if kind.is_some_and(|kind| kind.includes(namespace))
                && (hazard(&origin).is_some() || ambient_binding(&origin))
            {
                if matches!(namespace, PathNamespace::Value)
                    && self
                        .visible_value_index(first)
                        .is_some_and(|binding| self.value_scopes[binding] >= index)
                {
                    return;
                }
                if self.unresolved_parent_effects.len() < MAX_PARENT_EFFECT_DIAGNOSTICS {
                    let context = if self.context.is_empty() {
                        "<module>".to_owned()
                    } else {
                        self.context.join("::")
                    };
                    self.unresolved_parent_effects.insert(format!(
                        "{context}: {} (ambiguous imported namespace precedence)",
                        name.chars().take(256).collect::<String>()
                    ));
                }
                return;
            }
        }
    }

    fn value_import_barrier(&self, name: &str) -> Option<(usize, bool)> {
        self.named_imports
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, imports)| {
                let target = imports.get(name)?;
                let namespace = canonical_import_namespace(&self.resolve_name(target));
                namespace
                    .is_none_or(|kind| kind.includes(PathNamespace::Value))
                    .then_some((index, namespace.is_none()))
            })
    }

    fn raw_value_index(&self, name: &str) -> Option<usize> {
        (*self.value_floors.last().unwrap()..self.values.len())
            .rev()
            .find(|index| {
                self.bindings[*index].contains(name) || self.values[*index].contains_key(name)
            })
    }

    fn visible_value_index(&self, name: &str) -> Option<usize> {
        let index = self.raw_value_index(name)?;
        (self
            .value_import_barrier(name)
            .is_none_or(|(barrier, _)| self.value_scopes[index] >= barrier)
            && self
                .declaration_scope(name, PathNamespace::Value)
                .is_none_or(|declaration| self.value_scopes[index] >= declaration))
        .then_some(index)
    }

    fn require_known_value_import_precedence(&mut self, name: &str, callable: bool) {
        let Some((barrier, true)) = self.value_import_barrier(name) else {
            return;
        };
        if self
            .declaration_scope(name, PathNamespace::Value)
            .is_some_and(|declaration| declaration >= barrier)
        {
            // A genuine nearer value declaration, unlike a type-only name,
            // owns the callee instead of either the import or hidden binding.
            return;
        }
        let Some(index) = self.raw_value_index(name) else {
            return;
        };
        if self.value_scopes[index] >= barrier {
            return;
        }
        let kind = self.value_kinds[index]
            .get(name)
            .copied()
            .unwrap_or(ValueKind::Data);
        let Some(origin) = self.values[index].get(name) else {
            return;
        };
        // A computed value can retain a known function origin through an
        // unmodeled method such as unwrap. Only actual callable traversal
        // narrows that retained origin; ordinary DATA references stay DATA.
        if ((kind == ValueKind::Reference || callable) && hazard(origin).is_some()
            || kind == ValueKind::Receiver && ambient_receiver_type(origin))
            && self.unresolved_parent_effects.len() < MAX_PARENT_EFFECT_DIAGNOSTICS
        {
            let context = if self.context.is_empty() {
                "<module>".to_owned()
            } else {
                self.context.join("::")
            };
            self.unresolved_parent_effects.insert(format!(
                "{context}: {} (unknown imported value namespace)",
                name.chars().take(256).collect::<String>()
            ));
        }
    }

    fn import_provenance(&mut self, alias: &str, target: &str) {
        self.named_imports
            .last_mut()
            .unwrap()
            .insert(alias.to_owned(), target.to_owned());
        if parent_import(target) {
            self.parent_aliases
                .last_mut()
                .unwrap()
                .insert(alias.to_owned());
        } else if !canonical_binding(target) && !target.starts_with("crate::") {
            self.alias_dependencies
                .last_mut()
                .unwrap()
                .entry(alias.to_owned())
                .or_default()
                .insert(
                    relative_name(target)
                        .split("::")
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                );
        }
    }

    fn explicit_namespace_shadow(&self, name: &str) -> bool {
        let Some(index) = self
            .aliases
            .iter()
            .rposition(|scope| scope.contains_key(name))
        else {
            return false;
        };
        let Some(target) = self.named_imports[index].get(name) else {
            return false;
        };
        let Some((root, _)) = target.split_once("::") else {
            return false;
        };
        // Named opaque imports lexically shadow a parent glob even when their
        // reexported type is outside the effect vocabulary (e.g. Axum Response).
        // A known ambient alias root still requires canonical resolution. This
        // is a syntactic namespace distinction, not external wrapper analysis.
        !matches!(root, "super" | "self" | "crate") && !self.ambient_names.contains(root)
    }

    fn alias_has_flag(
        &self,
        name: &str,
        flags: &[BTreeSet<String>],
        seen: &mut BTreeSet<String>,
        remaining: usize,
    ) -> bool {
        let Some(index) = self
            .aliases
            .iter()
            .rposition(|scope| scope.contains_key(name))
        else {
            return false;
        };
        if flags[index].contains(name) {
            return true;
        }
        if !seen.insert(name.to_owned()) {
            return false;
        }
        let dependencies = self.alias_dependencies[index].get(name);
        if let Some(dependencies) = dependencies {
            if remaining == 0 {
                return !dependencies.is_empty();
            }
            for dependency in dependencies {
                if self.alias_has_flag(dependency, flags, seen, remaining - 1) {
                    return true;
                }
            }
        }
        false
    }

    fn import_use(&mut self, import: &syn::ItemUse, review: bool) {
        if !unconditional_scope(&import.attrs) {
            let mut names = Vec::new();
            import_names(&import.tree, "", &mut names);
            self.conditional_aliases
                .last_mut()
                .unwrap()
                .extend(names.into_iter().map(|(name, _)| name));
        }
        self.use_tree(&import.tree, "", review);
    }

    fn canonical_html_macro(&self, invocation: &syn::Macro) -> bool {
        let path = &invocation.path;
        let name = path.segments.iter().map(|segment| identifier_name(&segment.ident)).collect::<Vec<_>>().join("::");
        // Absolute qualified invocation avoids Rust's inherited textual macro
        // precedence. Inventory separately refuses conflicting extern bindings.
        path.leading_colon.is_some() && name == "maud::html"
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
            .map(|segment| identifier_name(&segment.ident))
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
                self.use_tree(&path.tree, &join(&identifier_name(&path.ident)), review)
            }
            UseTree::Name(name) => {
                let target = if name.ident == "self" {
                    prefix.to_owned()
                } else {
                    join(&identifier_name(&name.ident))
                };
                let alias = if name.ident == "self" {
                    prefix.rsplit("::").next().unwrap_or(prefix).to_owned()
                } else {
                    identifier_name(&name.ident)
                };
                self.import_provenance(&alias, &target);
                let target = self.resolve_name(&target);
                self.bind_alias(alias, target.clone(), tree);
                if review && ambient_binding(&target) {
                    self.record("effect-reexport", &target, tree);
                }
            }
            UseTree::Rename(rename) => {
                let raw_target = if rename.ident == "self" {
                    prefix.to_owned()
                } else {
                    join(&identifier_name(&rename.ident))
                };
                self.import_provenance(&identifier_name(&rename.rename), &raw_target);
                let target = self.resolve_name(&raw_target);
                self.bind_alias(identifier_name(&rename.rename), target.clone(), tree);
                if review && ambient_binding(&target) {
                    self.record("effect-reexport", &target, tree);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.use_tree(item, prefix, review);
                }
            }
            UseTree::Glob(_) => {
                if local_glob(prefix) {
                    *self.parent_globs.last_mut().unwrap() = true;
                }
                let prefix = self.resolve_name(prefix);
                for name in glob_names(&prefix) {
                    self.bind_alias((*name).to_owned(), format!("{prefix}::{name}"), tree);
                }
            }
        }
    }

    fn bind_alias(&mut self, alias: String, target: String, tokens: impl ToTokens) {
        let mut selected = target.clone();
        if let Some(previous) = self.aliases.last().unwrap().get(&alias).cloned()
            && previous != target
            && (ambient_binding(&previous) || ambient_binding(&target))
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
            if ambient_binding(&previous) && !ambient_binding(&target) {
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
                        .map(identifier_name)
                        .unwrap_or_else(|| index.to_string()),
                    origin,
                );
            }
        }
        let name = identifier_name(&structure.ident);
        if let Some(previous) = self.fields.get(&name).cloned()
            && previous != fields
            && previous
                .values()
                .chain(fields.values())
                .any(|origin| ambient_binding(origin))
        {
            self.record("effect-field-conflict", &name, structure);
            // Preserve known hazardous field origins when an alternate
            // platform declaration uses a pure field with the same name.
            for (name, origin) in previous {
                if ambient_binding(&origin) {
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
                let resolved = self.resolve(&path.path);
                if let syn::PathArguments::AngleBracketed(arguments) = &last.arguments {
                    let types = arguments.args.iter().filter_map(|argument| {
                        if let syn::GenericArgument::Type(ty) = argument { Some(self.type_origin(ty)) } else { None }
                    }).collect::<Vec<_>>();
                    let native_count = types.iter().filter(|origin| origin.as_deref().is_some_and(read_dir_lineage)).count();
                    let inner = types.first().cloned().flatten();
                    if native_count != 0 {
                        return Some(if native_count == 1 && inner.as_deref() == Some(READ_DIR_HANDLE) {
                            let first = identifier_name(&path.path.segments.first()?.ident);
                            if self.declaration_scope(&first, PathNamespace::Type).is_some()
                                || self.alias_has_flag(&first, &self.parent_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
                                || self.alias_has_flag(&first, &self.conditional_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
                            {
                                READ_DIR_UNMODELED
                            } else {
                                match resolved.as_str() {
                                    "std::result::Result" | "core::result::Result" | "std::io::Result" => READ_DIR_RESULT,
                                    "std::option::Option" | "core::option::Option" => READ_DIR_OPTION,
                                    _ => READ_DIR_UNMODELED,
                                }
                            }
                        } else {
                            READ_DIR_UNMODELED
                        }.to_owned());
                    }
                    if matches!(identifier_name(&last.ident).as_str(), "Option" | "Result" | "Box" | "Arc" | "Rc" | "Mutex" | "RwLock")
                        || matches!(resolved.as_str(), "std::result::Result" | "core::result::Result" | "std::io::Result" | "std::option::Option" | "core::option::Option") {
                        return inner;
                    }
                }
                Some(resolved)
            }
            Type::Tuple(tuple) => tuple.elems.iter().any(|ty| self.type_origin(ty).as_deref().is_some_and(read_dir_lineage)).then(|| READ_DIR_UNMODELED.to_owned()),
            Type::Array(array) => self.type_origin(&array.elem).as_deref().is_some_and(read_dir_lineage).then(|| READ_DIR_UNMODELED.to_owned()),
            Type::Slice(slice) => self.type_origin(&slice.elem).as_deref().is_some_and(read_dir_lineage).then(|| READ_DIR_UNMODELED.to_owned()),
            Type::Reference(reference) => self.type_origin(&reference.elem),
            Type::Paren(paren) => self.type_origin(&paren.elem),
            _ => None,
        }
    }

    fn origin(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Path(path) => {
                if path_is_ident(&path.path, "self") {
                    return self.self_type.clone();
                }
                if path.path.segments.len() == 1
                    && let Some(origin) =
                        self.value_origin(&identifier_name(&path.path.segments[0].ident))
                {
                    return origin;
                }
                if path.path.segments.len() == 1
                    && self
                        .value_declaration_shadows_alias(&identifier_name(&path.path.segments[0].ident))
                {
                    return Some(identifier_name(&path.path.segments[0].ident));
                }
                let name = self.resolve(&path.path);
                self.values
                    .iter()
                    .skip(*self.value_floors.last().unwrap())
                    .rev()
                    .find_map(|scope| scope.get(&name))
                    .cloned()
                    .or(Some(name))
            }
            Expr::Call(call) => {
                if let Some(method) = self.read_dir_call_method(call) {
                    return if read_dir_lazy_method(&method) {
                        Some("std::fs::ReadDir".to_owned())
                    } else {
                        None
                    };
                }
                self.origin(&call.func).and_then(|origin| {
                if call.args.len() == 1 && value_wrapper_target(&origin) {
                    let inner = self.origin(&call.args[0]);
                    if inner.as_deref().is_some_and(read_dir_lineage) {
                        return Some(if inner.as_deref() == Some(READ_DIR_HANDLE) {
                            if origin.rsplit("::").next() == Some("Some") { READ_DIR_OPTION } else { READ_DIR_RESULT }
                        } else { READ_DIR_UNMODELED }.to_owned());
                    }
                    return inner;
                }
                // The selected free function has an actual PathBuf result;
                // current-directory access is still inventoried at this call.
                if origin == "std::path::absolute" {
                    return Some("std::path::PathBuf".to_owned());
                }
                if origin == "std::fs::read_dir" {
                    return Some(READ_DIR_RESULT.to_owned());
                }
                if let Some((owner, method)) = origin.rsplit_once("::") {
                    if let Some(result) = path_method_result(owner, method) {
                        return Some(result.to_owned());
                    }
                }
                if origin.ends_with("::new")
                    || origin.ends_with("::builder")
                    || origin.ends_with("::open")
                    || origin.ends_with("::create")
                    || origin.ends_with("::now")
                    || origin == "std::path::PathBuf::from"
                {
                    Some(origin.rsplit_once("::").unwrap().0.to_owned())
                } else {
                    Some(origin)
                }
                })
            },
            Expr::MethodCall(call) => {
                let method = identifier_name(&call.method);
                if let Some(result) = self.origin(&call.receiver).and_then(|owner| read_dir_projection_result(&owner, &method)) {
                    return Some(result.to_owned());
                }
                if self.read_dir_method_lineage(call) {
                    // This provenance denotes the known underlying directory
                    // iterator, not the concrete Rust type of an adaptor.
                    return if read_dir_lazy_method(&method) {
                        Some("std::fs::ReadDir".to_owned())
                    } else if read_dir_consuming_method(&method) || method == "size_hint" {
                        None
                    } else {
                        self.origin(&call.receiver)
                    };
                }
                self.origin(&call.receiver).map(|origin| {
                path_method_result(&origin, &identifier_name(&call.method))
                    .map(str::to_owned)
                    .unwrap_or(origin)
                })
            },
            Expr::Field(field) => {
                let origin = self.origin(&field.base)?;
                let name = member_name(&field.member);
                self.fields
                    .get(&origin)
                    .and_then(|fields| fields.get(&name))
                    .cloned()
                    .or_else(|| read_dir_unmodeled_projection(Some(&origin)).map(str::to_owned))
            }
            Expr::Index(index) => read_dir_unmodeled_projection(self.origin(&index.expr).as_deref()).map(str::to_owned),
            Expr::Try(value) => self.origin(&value.expr).map(|origin| {
                if matches!(origin.as_str(), READ_DIR_RESULT | READ_DIR_OPTION) {
                    READ_DIR_HANDLE.to_owned()
                } else { origin }
            }),
            Expr::Await(value) => self.origin(&value.base),
            Expr::Paren(value) => self.origin(&value.expr),
            Expr::Group(value) => self.origin(&value.expr),
            Expr::Reference(value) => self.origin(&value.expr),
            Expr::Unary(value) if matches!(value.op, syn::UnOp::Deref(_)) => {
                self.origin(&value.expr)
            }
            // A bare function-pointer type has no nominal origin. Preserve a
            // known operand's provenance instead of erasing its exact target.
            Expr::Cast(value) => self
                .type_origin(&value.ty)
                .or_else(|| self.origin(&value.expr)),
            _ => None,
        }
    }

    fn read_dir_method_lineage(&self, call: &syn::ExprMethodCall) -> bool {
        // A custom chain/zip/comparison may consume its argument immediately.
        // Unknown left receivers must use canonical Iterator UFCS; only an
        // already retained bare native iterator proves the dot-method lineage.
        self.origin(&call.receiver).as_deref() == Some(READ_DIR_HANDLE)
    }

    fn read_dir_call_candidate(&self, call: &syn::ExprCall) -> Option<(String, String)> {
        let target = self.origin(&call.func)?;
        let (owner, method) = target.rsplit_once("::")?;
        if (read_dir_consuming_method(method) || read_dir_lazy_method(method) || method == "size_hint")
            && (call.args.first().is_some_and(|argument| {
                self.origin(argument).as_deref() == Some(READ_DIR_HANDLE)
            }) || read_dir_second_iterator_method(method)
                && call.args.iter().nth(1).is_some_and(|argument| {
                    self.origin(argument).as_deref() == Some(READ_DIR_HANDLE)
                }))
        {
            Some((owner.to_owned(), method.to_owned()))
        } else {
            None
        }
    }

    fn refuse_read_dir_handoff(&mut self, target: &str) {
        if self.read_dir_ambiguities.len() == MAX_PARENT_EFFECT_DIAGNOSTICS {
            return;
        }
        let context = if self.context.is_empty() { "<module>".to_owned() } else { self.context.join("::") };
        self.read_dir_ambiguities.insert(format!("{context}: {}", target.chars().take(256).collect::<String>()));
    }

    fn read_dir_call_method(&self, call: &syn::ExprCall) -> Option<String> {
        let (owner, method) = self.read_dir_call_candidate(call)?;
        if call.args.iter().enumerate().any(|(index, argument)| {
            let origin = self.origin(argument);
            origin.as_deref().is_some_and(read_dir_lineage)
                && !(origin.as_deref() == Some(READ_DIR_HANDLE)
                    && (index == 0 || index == 1 && read_dir_second_iterator_method(&method)))
        }) {
            return None;
        }
        // Even canonical Iterator UFCS can select a custom override. Lazy
        // transfers from an unknown first iterator cannot be called pure just
        // because the second argument is native. Modeled native/adaptor owners
        // remain supported; completed consumer sites are reviewed effects.
        if read_dir_lazy_method(&method)
            && call.args.first().and_then(|argument| self.origin(argument)).as_deref() != Some(READ_DIR_HANDLE)
        { return None; }
        let selected = match owner.as_str() {
            "std::fs::ReadDir" => call.args.first().is_some_and(|argument| self.origin(argument).as_deref() == Some(READ_DIR_HANDLE)),
            "std::iter::Iterator" | "core::iter::Iterator" => {
                !read_dir_peek_method(&method) && method != "into_iter"
            }
            "std::iter::IntoIterator" | "core::iter::IntoIterator" => method == "into_iter",
            "std::iter::Peekable" | "core::iter::Peekable" => read_dir_peek_method(&method),
            _ => false,
        };
        // A stored generic trait-function reference does not retain the lexical
        // import provenance of its producer. Require a directly qualified path
        // or an unconditional same-source canonical named trait alias instead.
        let Expr::Path(path) = call.func.as_ref() else { return None; };
        let first = identifier_name(&path.path.segments.first()?.ident);
        let exact = owner == "std::fs::ReadDir" || path.path.segments.len() > 1;
        if selected && exact
            && !parent_import(&path_name(&path.path))
            && self.declaration_scope(&first, PathNamespace::Type).is_none()
            && !self.alias_has_flag(&first, &self.parent_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
            && !self.alias_has_flag(&first, &self.conditional_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
        {
            Some(method)
        } else {
            None
        }
    }

    fn read_dir_constructor(&self, call: &syn::ExprCall) -> bool {
        if call.args.len() != 1 || self.origin(&call.args[0]).as_deref() != Some(READ_DIR_HANDLE) {
            return false;
        }
        let Some(target) = self.origin(&call.func) else { return false; };
        if !matches!(target.as_str(),
            "std::option::Option::Some" | "core::option::Option::Some"
                | "std::result::Result::Ok" | "core::result::Result::Ok") {
            return false;
        }
        let Expr::Path(path) = call.func.as_ref() else { return false; };
        let Some(first) = path.path.segments.first() else { return false; };
        let first = identifier_name(&first.ident);
        path.path.segments.len() > 1 && !parent_import(&path_name(&path.path))
            && self.declaration_scope(&first, PathNamespace::Type).is_none()
            && !self.alias_has_flag(&first, &self.parent_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
            && !self.alias_has_flag(&first, &self.conditional_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
    }

    fn read_dir_pattern_projection(&self, pattern: &syn::PatTupleStruct, origin: Option<&str>) -> Option<(Option<&'static str>, ValueKind)> {
        if pattern.elems.len() != 1 { return None; }
        let first = identifier_name(&pattern.path.segments.first()?.ident);
        let namespace = if pattern.path.segments.len() == 1 { PathNamespace::Value } else { PathNamespace::Type };
        if self.declaration_scope(&first, namespace).is_some()
            || parent_import(&path_name(&pattern.path))
            || self.alias_has_flag(&first, &self.parent_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
            || self.alias_has_flag(&first, &self.conditional_aliases, &mut BTreeSet::new(), MAX_ALIAS_ROUNDS)
        { return None; }
        // The exact standard acquisition shape proves its success payload is
        // the handle and its error is ordinary DATA. Unknown/nested containers
        // never get promoted by a variant's spelling or a custom constructor.
        match (origin, self.resolve(&pattern.path).as_str()) {
            (Some(READ_DIR_RESULT), "Ok" | "std::result::Result::Ok" | "core::result::Result::Ok")
                | (Some(READ_DIR_OPTION), "Some" | "std::option::Option::Some" | "core::option::Option::Some") =>
                Some((Some(READ_DIR_HANDLE), ValueKind::Receiver)),
            (Some(READ_DIR_RESULT), "Err" | "std::result::Result::Err" | "core::result::Result::Err") =>
                Some((None, ValueKind::Data)),
            _ => None,
        }
    }

    fn parameters(&mut self, signature: &syn::Signature) {
        for argument in &signature.inputs {
            if let syn::FnArg::Typed(argument) = argument {
                let origin = self.type_origin(&argument.ty);
                let kind = if origin.as_deref().is_some_and(ambient_receiver_type) {
                    ValueKind::Receiver
                } else {
                    ValueKind::Data
                };
                self.bind_value(&argument.pat, origin.as_deref(), kind);
            }
        }
    }

    fn value_origin(&self, name: &str) -> Option<Option<String>> {
        self.visible_value_index(name)
            .map(|index| self.values[index].get(name).cloned())
    }

    fn value_kind(&self, name: &str) -> Option<ValueKind> {
        self.visible_value_index(name).map(|index| {
            self.value_kinds[index]
                .get(name)
                .copied()
                .unwrap_or(ValueKind::Data)
        })
    }

    fn reference_target(&self, name: &str) -> Option<String> {
        if !name.contains("::") {
            match self.value_kind(name) {
                Some(ValueKind::Data | ValueKind::Receiver) => return None,
                Some(ValueKind::Reference) => return self.value_origin(name).flatten(),
                None => {}
            }
            if self.value_declaration_shadows_alias(name) {
                return Some(name.to_owned());
            }
        }
        Some(self.resolve_name(name))
    }

    fn expression_kind(&self, expression: &Expr) -> ValueKind {
        match expression {
            Expr::Path(path) if path.path.segments.len() == 1 => self
                .value_kind(&identifier_name(&path.path.segments[0].ident))
                .unwrap_or(ValueKind::Reference),
            Expr::Path(_) => ValueKind::Reference,
            Expr::Paren(wrapper) => self.expression_kind(&wrapper.expr),
            Expr::Group(wrapper) => self.expression_kind(&wrapper.expr),
            Expr::Reference(wrapper) => self.expression_kind(&wrapper.expr),
            Expr::Unary(wrapper) if matches!(wrapper.op, syn::UnOp::Deref(_)) => {
                self.expression_kind(&wrapper.expr)
            }
            Expr::Cast(wrapper) => {
                if self
                    .type_origin(&wrapper.ty)
                    .as_deref()
                    .is_some_and(ambient_receiver_type)
                {
                    ValueKind::Receiver
                } else {
                    self.expression_kind(&wrapper.expr)
                }
            }
            Expr::Try(wrapper) => self.expression_kind(&wrapper.expr),
            Expr::Await(wrapper) => self.expression_kind(&wrapper.base),
            Expr::Call(call)
                if call.args.len() == 1
                    && self
                        .origin(&call.func)
                        .is_some_and(|target| value_wrapper_target(&target)) =>
            {
                self.expression_kind(&call.args[0])
            }
            Expr::Call(call)
                if self.read_dir_call_method(call).is_some_and(|method| read_dir_lazy_method(&method)) =>
            {
                ValueKind::Receiver
            }
            Expr::MethodCall(call)
                if self.read_dir_method_lineage(call)
                    && read_dir_lazy_method(&identifier_name(&call.method)) =>
            {
                ValueKind::Receiver
            }
            Expr::Call(call)
                if self.origin(&call.func).is_some_and(|target| {
                    matches!(target.as_str(), "rand::rng" | "rand::thread_rng")
                        || target == "std::path::absolute"
                        || target == "std::fs::read_dir"
                        || target.starts_with("ureq::")
                            && matches!(
                                target.rsplit("::").next(),
                                Some(
                                    "get"
                                        | "post"
                                        | "put"
                                        | "delete"
                                        | "head"
                                        | "patch"
                                        | "request"
                                )
                            )
                        || target.rsplit_once("::").is_some_and(|(owner, method)| {
                            ambient_receiver_type(owner) && !receiver_returns_data(owner, method)
                        })
                }) =>
            {
                ValueKind::Receiver
            }
            Expr::MethodCall(call)
                if self.expression_kind(&call.receiver) == ValueKind::Receiver
                    && self.origin(&call.receiver).is_some_and(|origin| {
                        !receiver_returns_data(&origin, &identifier_name(&call.method))
                    }) =>
            {
                ValueKind::Receiver
            }
            Expr::Field(_)
                if self
                    .origin(expression)
                    .as_deref()
                    .is_some_and(ambient_receiver_type) =>
            {
                ValueKind::Receiver
            }
            // An arbitrary function/method's result is not a function reference.
            // Its nominal receiver origin remains available separately; this
            // does not infer an output type or authorize a returned callback.
            _ => ValueKind::Data,
        }
    }

    fn reject_conditional_effect_binding(&mut self, local: &syn::Local) {
        if !pattern_binds(&local.pat) {
            return;
        }
        let mut bindings = Vec::new();
        if let Some(initializer) = &local.init {
            self.expression_bindings(&local.pat, &initializer.expr, &mut bindings);
        } else {
            bindings.push((&local.pat, None, ValueKind::Data));
        }
        let mut resolved = Vec::new();
        for (pattern, origin, kind) in bindings {
            self.reject_conditional_tuple_rest(pattern, origin.as_deref());
            self.pattern_bindings(pattern, origin.as_deref(), kind, &mut resolved);
        }
        for (_, origin, kind) in resolved {
            self.reject_conditional_origin(origin.as_deref(), kind);
        }
    }

    fn reject_conditional_origin(&mut self, origin: Option<&str>, kind: ValueKind) {
        let Some(origin) = origin else {
            return;
        };
        if kind != ValueKind::Receiver
            && (kind != ValueKind::Reference
                || !ambient_binding(origin) && hazard(origin).is_none())
        {
            return;
        }
        if self.conditional_effect_bindings.len() == MAX_PARENT_EFFECT_DIAGNOSTICS {
            return;
        }
        let context = if self.context.is_empty() {
            "<module>".to_owned()
        } else {
            self.context.join("::")
        };
        self.conditional_effect_bindings.insert(format!(
            "{context}: {}",
            origin.chars().take(256).collect::<String>(),
        ));
    }

    fn reject_conditional_tuple_rest(&mut self, pattern: &Pat, origin: Option<&str>) {
        match pattern {
            Pat::Type(pattern) => {
                let typed = self.type_origin(&pattern.ty);
                self.reject_conditional_tuple_rest(&pattern.pat, typed.as_deref().or(origin));
            }
            Pat::Paren(pattern) => self.reject_conditional_tuple_rest(&pattern.pat, origin),
            Pat::Reference(pattern) => self.reject_conditional_tuple_rest(&pattern.pat, origin),
            Pat::Struct(pattern) => {
                for field in &pattern.fields {
                    let field_origin = origin
                        .and_then(|origin| self.fields.get(origin))
                        .and_then(|fields| fields.get(&member_name(&field.member)))
                        .cloned();
                    self.reject_conditional_tuple_rest(&field.pat, field_origin.as_deref());
                }
            }
            Pat::TupleStruct(pattern)
                if pattern
                    .elems
                    .iter()
                    .any(|element| matches!(element, Pat::Rest(_))) =>
            {
                // The field map does not retain total arity for unknown types.
                // Do not guess trailing numeric fields across `..` when an
                // explicitly known handle field could be selected.
                let handles: Vec<_> = origin
                    .and_then(|origin| self.fields.get(origin))
                    .into_iter()
                    .flat_map(|fields| fields.values())
                    .filter(|origin| ambient_receiver_type(origin))
                    .cloned()
                    .collect();
                for handle in handles {
                    self.reject_conditional_origin(Some(&handle), ValueKind::Receiver);
                }
            }
            _ => {}
        }
    }

    fn push_values(&mut self) {
        self.values.push(BTreeMap::new());
        self.bindings.push(BTreeSet::new());
        self.value_kinds.push(BTreeMap::new());
        self.value_scopes.push(self.aliases.len() - 1);
    }

    fn pop_values(&mut self) {
        self.values.pop();
        self.bindings.pop();
        self.value_kinds.pop();
        self.value_scopes.pop();
    }

    fn bind_value(&mut self, pattern: &Pat, origin: Option<&str>, kind: ValueKind) {
        let mut resolved = Vec::new();
        self.pattern_bindings(pattern, origin, kind, &mut resolved);
        for (ident, origin, kind) in resolved {
            let name = identifier_name(ident);
            self.bindings.last_mut().unwrap().insert(name.clone());
            self.values.last_mut().unwrap().remove(&name);
            self.value_kinds
                .last_mut()
                .unwrap()
                .insert(name.clone(), kind);
            if let Some(origin) = origin {
                self.values.last_mut().unwrap().insert(name, origin);
            }
        }
    }

    fn pattern_bindings<'p>(
        &self,
        pattern: &'p Pat,
        origin: Option<&str>,
        kind: ValueKind,
        output: &mut Vec<(&'p syn::Ident, Option<String>, ValueKind)>,
    ) {
        match pattern {
            Pat::Ident(pattern) => {
                output.push((&pattern.ident, origin.map(str::to_owned), kind));
                if let Some((_, subpattern)) = &pattern.subpat {
                    self.pattern_bindings(subpattern, origin, kind, output);
                }
            }
            Pat::Type(pattern) => {
                let typed = self.type_origin(&pattern.ty);
                let kind = if typed.as_deref().is_some_and(ambient_receiver_type) {
                    ValueKind::Receiver
                } else {
                    kind
                };
                self.pattern_bindings(&pattern.pat, typed.as_deref().or(origin), kind, output);
            }
            Pat::Reference(pattern) => self.pattern_bindings(&pattern.pat, origin, kind, output),
            Pat::Paren(pattern) => self.pattern_bindings(&pattern.pat, origin, kind, output),
            Pat::Tuple(pattern) => {
                for element in &pattern.elems {
                    self.pattern_bindings(element, origin, kind, output);
                }
            }
            Pat::TupleStruct(pattern) => {
                if let Some((origin, kind)) = self.read_dir_pattern_projection(pattern, origin) {
                    for element in &pattern.elems { self.pattern_bindings(element, origin, kind, output); }
                    return;
                }
                let fields = origin.and_then(|origin| self.fields.get(origin));
                let mut trailing_unknown = false;
                for (index, element) in pattern.elems.iter().enumerate() {
                    trailing_unknown |= matches!(element, Pat::Rest(_));
                    if let Some(fields) = fields {
                        let field_origin = (!trailing_unknown)
                            .then(|| fields.get(&index.to_string()))
                            .flatten();
                        let field_kind =
                            if field_origin.is_some_and(|origin| ambient_receiver_type(origin)) {
                                ValueKind::Receiver
                            } else {
                                ValueKind::Data
                            };
                        self.pattern_bindings(
                            element,
                            field_origin.map(String::as_str),
                            field_kind,
                            output,
                        );
                    } else {
                        let projected = read_dir_unmodeled_projection(origin);
                        let kind = if projected.is_some() { ValueKind::Receiver } else { kind };
                        self.pattern_bindings(element, projected.or(origin), kind, output);
                    }
                }
            }
            Pat::Struct(pattern) => {
                for field in &pattern.fields {
                    let field_origin = origin
                        .and_then(|origin| self.fields.get(origin))
                        .and_then(|fields| fields.get(&member_name(&field.member)))
                        .cloned()
                        .or_else(|| read_dir_unmodeled_projection(origin).map(str::to_owned));
                    let kind = if field_origin.as_deref().is_some_and(ambient_receiver_type) {
                        ValueKind::Receiver
                    } else {
                        ValueKind::Data
                    };
                    self.pattern_bindings(&field.pat, field_origin.as_deref(), kind, output);
                }
            }
            Pat::Slice(pattern) => {
                for element in &pattern.elems {
                    self.pattern_bindings(element, origin, kind, output);
                }
            }
            Pat::Or(pattern) => {
                for case in &pattern.cases {
                    self.pattern_bindings(case, origin, kind, output);
                }
            }
            _ => {}
        }
    }

    fn bind_expression(&mut self, pattern: &Pat, expression: &Expr) {
        // Resolve every component against the old scope before installing any
        // binding: `(metadata, current) = (read, metadata)` must not read the
        // newly bound `metadata` while resolving the second initializer.
        let mut bindings = Vec::new();
        self.expression_bindings(pattern, expression, &mut bindings);
        for (pattern, origin, kind) in bindings {
            self.bind_value(pattern, origin.as_deref(), kind);
        }
    }

    fn expression_bindings<'p>(
        &self,
        pattern: &'p Pat,
        expression: &Expr,
        output: &mut Vec<(&'p Pat, Option<String>, ValueKind)>,
    ) {
        match expression {
            Expr::Paren(expression) => {
                return self.expression_bindings(pattern, &expression.expr, output);
            }
            Expr::Group(expression) => {
                return self.expression_bindings(pattern, &expression.expr, output);
            }
            Expr::Reference(expression) => {
                return self.expression_bindings(pattern, &expression.expr, output);
            }
            _ => {}
        }
        match (pattern, expression) {
            (Pat::Paren(pattern), expression) => {
                self.expression_bindings(&pattern.pat, expression, output)
            }
            (Pat::Reference(pattern), expression) => {
                self.expression_bindings(&pattern.pat, expression, output)
            }
            (Pat::Type(pattern), expression) if self.type_origin(&pattern.ty).is_none() => {
                self.expression_bindings(&pattern.pat, expression, output)
            }
            (Pat::Tuple(pattern), Expr::Tuple(expression))
                if pattern.elems.len() == expression.elems.len()
                    && !pattern
                        .elems
                        .iter()
                        .any(|pattern| matches!(pattern, Pat::Rest(_))) =>
            {
                for (pattern, expression) in pattern.elems.iter().zip(&expression.elems) {
                    self.expression_bindings(pattern, expression, output);
                }
            }
            (Pat::Slice(pattern), Expr::Array(expression))
                if pattern.elems.len() == expression.elems.len()
                    && !pattern
                        .elems
                        .iter()
                        .any(|pattern| matches!(pattern, Pat::Rest(_))) =>
            {
                for (pattern, expression) in pattern.elems.iter().zip(&expression.elems) {
                    self.expression_bindings(pattern, expression, output);
                }
            }
            (Pat::Slice(pattern), Expr::Repeat(expression)) => {
                for pattern in &pattern.elems {
                    self.expression_bindings(pattern, &expression.expr, output);
                }
            }
            (Pat::TupleStruct(pattern), Expr::Call(expression))
                if pattern.elems.len() == 1
                    && expression.args.len() == 1
                    && self.origin(&expression.func).is_some_and(|name| {
                        matches!(
                            name.as_str(),
                            "Some"
                                | "Option::Some"
                                | "std::option::Option::Some"
                                | "core::option::Option::Some"
                                | "Ok"
                                | "Result::Ok"
                                | "std::result::Result::Ok"
                                | "core::result::Result::Ok"
                        )
                    }) =>
            {
                self.expression_bindings(&pattern.elems[0], &expression.args[0], output);
            }
            // An opaque aggregate's origin does not describe each component.
            // It also cannot prove extracted native container fields are DATA.
            // Keep only a refusal marker, without guessing element types.
            (Pat::Tuple(_) | Pat::Slice(_), _) => {
                let origin = read_dir_unmodeled_projection(self.origin(expression).as_deref()).map(str::to_owned);
                let kind = if origin.is_some() { ValueKind::Receiver } else { ValueKind::Data };
                output.push((pattern, origin, kind));
            }
            _ => output.push((
                pattern,
                self.origin(expression),
                self.expression_kind(expression),
            )),
        }
    }

    fn condition(&mut self, expression: &Expr) {
        match expression {
            Expr::Let(expression) => {
                visit::visit_expr_let(self, expression);
                self.bind_expression(&expression.pat, &expression.expr);
            }
            Expr::Binary(expression) if matches!(expression.op, syn::BinOp::And(_)) => {
                for attribute in &expression.attrs {
                    self.visit_attribute(attribute);
                }
                self.condition(&expression.left);
                self.condition(&expression.right);
            }
            Expr::Paren(expression) => {
                for attribute in &expression.attrs {
                    self.visit_attribute(attribute);
                }
                self.condition(&expression.expr);
            }
            expression => self.visit_expr(expression),
        }
    }

    fn block(&mut self, block: &syn::Block, callable_tail: bool) {
        self.aliases.push(BTreeMap::new());
        self.named_imports.push(BTreeMap::new());
        self.parent_aliases.push(BTreeSet::new());
        self.conditional_aliases.push(BTreeSet::new());
        self.alias_dependencies.push(BTreeMap::new());
        self.parent_globs.push(false);
        self.declarations
            .push(declarations(block.stmts.iter().filter_map(|statement| {
                if let syn::Stmt::Item(item) = statement {
                    Some(item)
                } else {
                    None
                }
            })));
        self.push_values();
        for statement in &block.stmts {
            if let syn::Stmt::Item(Item::Use(import)) = statement
                && !definitely_test_only(&import.attrs)
            {
                self.import_use(import, false);
            }
        }
        for (index, statement) in block.stmts.iter().enumerate() {
            if callable_tail
                && index + 1 == block.stmts.len()
                && let syn::Stmt::Expr(expression, None) = statement
            {
                self.callable_expression(expression, false);
            } else {
                self.visit_stmt(statement);
            }
        }
        self.pop_values();
        self.aliases.pop();
        self.named_imports.pop();
        self.parent_aliases.pop();
        self.conditional_aliases.pop();
        self.alias_dependencies.pop();
        self.parent_globs.pop();
        self.declarations.pop();
    }

    fn if_expression(&mut self, expression: &syn::ExprIf, callable: bool) {
        for attribute in &expression.attrs {
            self.visit_attribute(attribute);
        }
        self.push_values();
        self.condition(&expression.cond);
        self.block(&expression.then_branch, callable);
        self.pop_values();
        if let Some((_, alternative)) = &expression.else_branch {
            if callable {
                self.callable_expression(alternative, false);
            } else {
                self.visit_expr(alternative);
            }
        }
    }

    fn match_expression(&mut self, expression: &syn::ExprMatch, callable: bool) {
        for attribute in &expression.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_expr(&expression.expr);
        for arm in &expression.arms {
            self.push_values();
            self.visit_pat(&arm.pat);
            self.bind_expression(&arm.pat, &expression.expr);
            for attribute in &arm.attrs {
                self.visit_attribute(attribute);
            }
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            if callable {
                self.callable_expression(&arm.body, false);
            } else {
                self.visit_expr(&arm.body);
            }
            self.pop_values();
        }
    }

    fn callable_expression(&mut self, expression: &Expr, suppress_direct_reference: bool) {
        if definitely_test_only(expression_attributes(expression)) {
            return;
        }
        match expression {
            Expr::Path(path) => {
                let name = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| identifier_name(&segment.ident))
                    .collect::<Vec<_>>()
                    .join("::");
                if path.path.segments.len() == 1 {
                    self.require_known_value_import_precedence(&name, true);
                }
                self.parent_effect_path_checked(
                    &name,
                    false,
                    if path.path.segments.len() == 1 {
                        PathNamespace::Value
                    } else {
                        PathNamespace::Type
                    },
                );
                if path.path.segments.len() == 1
                    && self.value_origin(&identifier_name(&path.path.segments[0].ident)) == Some(None)
                {
                    self.parent_effect_path_checked(
                        &identifier_name(&path.path.segments[0].ident),
                        true,
                        PathNamespace::Value,
                    );
                }
                if suppress_direct_reference {
                    for attribute in &path.attrs {
                        self.visit_attribute(attribute);
                    }
                    self.visit_path(&path.path);
                } else {
                    self.visit_expr_path(path);
                }
            }
            Expr::Paren(wrapper) => {
                for attribute in &wrapper.attrs {
                    self.visit_attribute(attribute);
                }
                self.callable_expression(&wrapper.expr, suppress_direct_reference);
            }
            Expr::Group(wrapper) => {
                for attribute in &wrapper.attrs {
                    self.visit_attribute(attribute);
                }
                self.callable_expression(&wrapper.expr, suppress_direct_reference);
            }
            Expr::Reference(wrapper) => {
                for attribute in &wrapper.attrs {
                    self.visit_attribute(attribute);
                }
                self.callable_expression(&wrapper.expr, suppress_direct_reference);
            }
            Expr::Unary(wrapper) => {
                for attribute in &wrapper.attrs {
                    self.visit_attribute(attribute);
                }
                self.callable_expression(&wrapper.expr, suppress_direct_reference);
            }
            Expr::Cast(wrapper) => {
                for attribute in &wrapper.attrs {
                    self.visit_attribute(attribute);
                }
                self.callable_expression(&wrapper.expr, suppress_direct_reference);
                self.visit_type(&wrapper.ty);
            }
            Expr::Try(wrapper) => {
                for attribute in &wrapper.attrs {
                    self.visit_attribute(attribute);
                }
                self.callable_expression(&wrapper.expr, suppress_direct_reference);
            }
            Expr::Call(call)
                if call.args.len() == 1
                    && self
                        .origin(&call.func)
                        .is_some_and(|target| value_wrapper_target(&target)) =>
            {
                for attribute in &call.attrs {
                    self.visit_attribute(attribute);
                }
                self.visit_expr(&call.func);
                // These exact constructors already preserve the inner origin.
                // Their argument becomes the selected callable after `?`, so
                // unknown lexical callbacks must retain that context too.
                // Keep the ordinary argument reference: the constructor is a
                // value operation, not the direct callee path of the outer call.
                self.callable_expression(&call.args[0], false);
            }
            Expr::Block(expression) => {
                for attribute in &expression.attrs {
                    self.visit_attribute(attribute);
                }
                self.block(&expression.block, true);
            }
            Expr::If(expression) => self.if_expression(expression, true),
            Expr::Match(expression) => self.match_expression(expression, true),
            Expr::Field(field) => {
                if self.origin(expression).is_none() {
                    if let syn::Member::Named(member) = &field.member {
                        self.parent_effect_path_checked(
                            &identifier_name(member),
                            true,
                            PathNamespace::Value,
                        );
                    }
                    for attribute in &field.attrs {
                        self.visit_attribute(attribute);
                    }
                    self.callable_expression(&field.base, false);
                    self.visit_member(&field.member);
                } else {
                    self.visit_expr(expression);
                }
            }
            Expr::Index(index) => {
                if self.origin(expression).is_none() {
                    self.callable_expression(&index.expr, false);
                    self.visit_expr(&index.index);
                    for attribute in &index.attrs {
                        self.visit_attribute(attribute);
                    }
                } else {
                    self.visit_expr(expression);
                }
            }
            _ => self.visit_expr(expression),
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        *self.declarations.last_mut().unwrap() = declarations(&file.items);
        // Imports are independent of textual declaration order in Rust.
        for item in &file.items {
            if let Item::ExternCrate(item) = item
                && !definitely_test_only(&item.attrs)
                && let Some((_, alias)) = &item.rename
            {
                self.bind_alias(identifier_name(alias), identifier_name(&item.ident), item);
            }
        }
        for item in &file.items {
            if let Item::Use(import) = item
                && !definitely_test_only(&import.attrs)
            {
                self.import_use(import, false);
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
        self.named_imports.push(BTreeMap::new());
        self.parent_aliases.push(BTreeSet::new());
        self.conditional_aliases.push(BTreeSet::new());
        self.alias_dependencies.push(BTreeMap::new());
        self.parent_globs.push(false);
        self.declarations.push(
            module
                .content
                .as_ref()
                .map(|(_, items)| declarations(items))
                .unwrap_or_default(),
        );
        self.push_values();
        self.value_floors.push(self.values.len() - 1);
        self.declaration_floors.push(self.declarations.len() - 1);
        if let Some((_, items)) = &module.content {
            for item in items {
                if let Item::ExternCrate(item) = item
                    && !definitely_test_only(&item.attrs)
                    && let Some((_, alias)) = &item.rename
                {
                    self.bind_alias(identifier_name(alias), identifier_name(&item.ident), item);
                }
            }
            for item in items {
                if let Item::Use(import) = item
                    && !definitely_test_only(&import.attrs)
                {
                    self.import_use(import, false);
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
        self.named_imports.pop();
        self.parent_aliases.pop();
        self.conditional_aliases.pop();
        self.alias_dependencies.pop();
        self.parent_globs.pop();
        self.declaration_floors.pop();
        self.declarations.pop();
        self.value_floors.pop();
        self.pop_values();
        self.context.pop();
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.context.push(function.sig.ident.to_string());
        self.push_values();
        self.parameters(&function.sig);
        visit::visit_item_fn(self, function);
        self.pop_values();
        self.context.pop();
    }

    fn visit_item_const(&mut self, constant: &'ast syn::ItemConst) {
        let name = identifier_name(&constant.ident);
        let declared = self
            .type_origin(&constant.ty)
            .filter(|origin| ambient_receiver_type(origin));
        let kind = if declared.is_some() {
            ValueKind::Receiver
        } else {
            self.expression_kind(&constant.expr)
        };
        let origin = declared.or_else(|| self.origin(&constant.expr));
        if unconditional_scope(&constant.attrs) {
            self.bindings.last_mut().unwrap().insert(name.clone());
            self.values.last_mut().unwrap().remove(&name);
            self.value_kinds
                .last_mut()
                .unwrap()
                .insert(name.clone(), kind);
            if let Some(origin) = origin {
                self.values.last_mut().unwrap().insert(name, origin);
            }
        } else {
            self.reject_conditional_origin(origin.as_deref(), kind);
        }
        self.context.push(constant.ident.to_string());
        visit::visit_item_const(self, constant);
        self.context.pop();
    }

    fn visit_item_static(&mut self, constant: &'ast syn::ItemStatic) {
        let name = identifier_name(&constant.ident);
        let declared = self
            .type_origin(&constant.ty)
            .filter(|origin| ambient_receiver_type(origin));
        let kind = if declared.is_some() {
            ValueKind::Receiver
        } else {
            self.expression_kind(&constant.expr)
        };
        let origin = declared.or_else(|| self.origin(&constant.expr));
        if unconditional_scope(&constant.attrs) {
            self.bindings.last_mut().unwrap().insert(name.clone());
            self.values.last_mut().unwrap().remove(&name);
            self.value_kinds
                .last_mut()
                .unwrap()
                .insert(name.clone(), kind);
            if let Some(origin) = origin {
                self.values.last_mut().unwrap().insert(name, origin);
            }
        } else {
            self.reject_conditional_origin(origin.as_deref(), kind);
        }
        self.context.push(constant.ident.to_string());
        visit::visit_item_static(self, constant);
        self.context.pop();
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.push_values();
        for input in &closure.inputs {
            self.bind_value(input, None, ValueKind::Data);
        }
        visit::visit_expr_closure(self, closure);
        self.pop_values();
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
        self.push_values();
        self.parameters(&function.sig);
        visit::visit_impl_item_fn(self, function);
        self.pop_values();
        self.context.pop();
    }

    fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
        if definitely_test_only(&function.attrs) {
            return;
        }
        self.context.push(function.sig.ident.to_string());
        self.push_values();
        self.parameters(&function.sig);
        visit::visit_trait_item_fn(self, function);
        self.pop_values();
        self.context.pop();
    }

    fn visit_item_struct(&mut self, structure: &'ast syn::ItemStruct) {
        visit::visit_item_struct(self, structure);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.block(block, false);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if definitely_test_only(&local.attrs) {
            return;
        }
        // The new binding cannot shadow its own initializer or let-else branch.
        visit::visit_local(self, local);
        // Alternate-platform bindings cannot erase another branch's origin.
        // Silently skipping a known ambient receiver would also erase later
        // methods. Require one unconditional typed owner around its cfg-selected
        // initializer instead; arbitrary Rust output types remain unmodeled.
        if unconditional_scope(&local.attrs) {
            if let Some(initializer) = &local.init {
                self.bind_expression(&local.pat, &initializer.expr);
            } else {
                self.bind_value(&local.pat, None, ValueKind::Data);
            }
        } else {
            self.reject_conditional_effect_binding(local);
        }
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.if_expression(expression, false);
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        for attribute in &expression.attrs {
            self.visit_attribute(attribute);
        }
        self.push_values();
        self.condition(&expression.cond);
        self.visit_block(&expression.body);
        self.pop_values();
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        for attribute in &expression.attrs {
            self.visit_attribute(attribute);
        }
        let origin = self.origin(&expression.expr);
        if origin.as_deref() == Some(READ_DIR_HANDLE) {
            // One authored implicit consumption site, not an iteration count.
            self.record("filesystem", "std::fs::ReadDir::next", expression);
        } else if origin.as_deref().is_some_and(read_dir_lineage) {
            self.refuse_read_dir_handoff("for-loop over an unextracted native container");
        }
        self.visit_expr(&expression.expr);
        self.visit_pat(&expression.pat);
        self.push_values();
        self.bind_value(&expression.pat, None, ValueKind::Data);
        self.visit_block(&expression.body);
        self.pop_values();
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.match_expression(expression, false);
    }

    fn visit_expr(&mut self, expression: &'ast Expr) {
        // Attributes are available on all ordinary expressions through their
        // concrete variants; the common effect-bearing forms are handled here.
        if !definitely_test_only(expression_attributes(expression)) {
            visit::visit_expr(self, expression);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.parent_effect_path(
            &path
                .segments
                .iter()
                .map(|segment| identifier_name(&segment.ident))
                .collect::<Vec<_>>()
                .join("::"),
        );
        visit::visit_path(self, path);
    }

    fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
        let name = ty
            .path
            .segments
            .iter()
            .map(|segment| identifier_name(&segment.ident))
            .collect::<Vec<_>>()
            .join("::");
        self.parent_effect_path_checked(&name, false, PathNamespace::Type);
        visit::visit_type_path(self, ty);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let name = expression
            .path
            .segments
            .iter()
            .map(|segment| identifier_name(&segment.ident))
            .collect::<Vec<_>>()
            .join("::");
        self.parent_effect_path_checked(
            &name,
            false,
            if expression.path.segments.len() == 1 {
                PathNamespace::Value
            } else {
                PathNamespace::Type
            },
        );
        let target = self.reference_target(&name);
        if let Some(target) = target
            && let Some(kind) = hazard(&target)
        {
            self.record(kind, &target, expression);
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let mut suppress_direct_reference = false;
        if call.args.iter().any(|argument| self.origin(argument).as_deref().is_some_and(read_dir_lineage))
            && self.read_dir_call_method(call).is_none()
            && !self.read_dir_constructor(call)
        {
            let target = self.origin(&call.func).unwrap_or_else(|| "<computed callee>".to_owned());
            self.refuse_read_dir_handoff(&target);
        }
        if let Some(method) = self.read_dir_call_method(call)
            && read_dir_consuming_method(&method)
        {
            self.record("filesystem", &format!("std::fs::ReadDir::{method}"), call);
            suppress_direct_reference = true;
        } else if let Some(target) = self.origin(&call.func)
            && let Some(kind) = hazard(&target)
        {
            self.record(kind, &target, call);
            suppress_direct_reference = true;
        }
        for attribute in &call.attrs {
            self.visit_attribute(attribute);
        }
        // Suppress only a direct callee reference already represented by this
        // call. Computed callees retain references in all statements, branches,
        // guards and nested arguments; they do not acquire an inferred origin.
        self.callable_expression(&call.func, suppress_direct_reference);
        for argument in &call.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = identifier_name(&call.method);
        let receiver = self.origin(&call.receiver);
        if call.args.iter().enumerate().any(|(index, argument)| {
            let origin = self.origin(argument);
            origin.as_deref().is_some_and(read_dir_lineage)
                && !(origin.as_deref() == Some(READ_DIR_HANDLE)
                    && index == 0 && read_dir_second_iterator_method(&method))
        }) {
            self.refuse_read_dir_handoff(&format!("{method} (unmodeled native argument role)"));
        }
        if receiver.as_deref().and_then(|owner| read_dir_projection_result(owner, &method)).is_some() {
            // Only an actual known acquisition wrapper gets this pure projection.
        } else if self.read_dir_method_lineage(call) {
            if read_dir_consuming_method(&method) {
                self.record("filesystem", &format!("std::fs::ReadDir::{method}"), call);
            } else if !read_dir_lazy_method(&method) && method != "size_hint" {
                self.refuse_read_dir_handoff(&method);
            }
        } else if receiver.as_deref().is_some_and(read_dir_lineage)
            || call.args.iter().any(|argument| self.origin(argument).as_deref().is_some_and(read_dir_lineage)) {
            self.refuse_read_dir_handoff(&method);
        } else if let Some(origin) = self.origin(&call.receiver) {
            if let Some(kind) = method_hazard(&origin, &method) {
                // PathBuf reaches these actual Path methods through Deref.
                // Preserve the authored call AST while naming the canonical
                // operation, without inferring arbitrary method output types.
                let owner = if path_receiver_type(&origin) {
                    "std::path::Path"
                } else {
                    &origin
                };
                let target = format!("{owner}::{method}");
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
        self.import_use(import, !matches!(import.vis, syn::Visibility::Inherited));
        // All hazardous globs require review, including private imports.
        fn globs(tree: &UseTree, prefix: String, output: &mut Vec<String>) {
            match tree {
                UseTree::Path(path) => globs(
                    &path.tree,
                    if prefix.is_empty() {
                        identifier_name(&path.ident)
                    } else {
                        format!("{prefix}::{}", identifier_name(&path.ident))
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
            if ambient_binding(&prefix) {
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
                .insert(identifier_name(alias), identifier_name(&item.ident));
        }
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        let target = self.resolve(attribute.path());
        if matches!(target.as_str(), "tokio::main" | "tokio::test") {
            self.record("scheduling-attribute", &target, attribute);
        }
        if path_is_ident(attribute.path(), "path") {
            self.record("source-indirection", "module-path", attribute);
        }
        if path_is_ident(attribute.path(), "allow") || path_is_ident(attribute.path(), "expect") {
            self.record(
                "lint-suppression",
                &path_name(attribute.path()),
                attribute,
            );
        }
        if path_is_ident(attribute.path(), "cfg_attr")
            && let Ok(metas) = attribute.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )
        {
            for meta in metas.iter().skip(1).filter(|_| {
                metas
                    .first()
                    .is_none_or(|condition| cfg_value(condition) != Some(false))
            }) {
                if path_is_ident(meta.path(), "allow") || path_is_ident(meta.path(), "expect") {
                    self.record(
                        "lint-suppression",
                        &path_name(meta.path()),
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
        // The pinned Maud parser emits named attribute HtmlName as literal
        // text. Only an absolute qualified invocation and recognized bounded
        // element grammar may remove that lhs; values stay ordinary tokens.
        if self.canonical_html_macro(invocation)
            && let Ok(markup) = syn::parse2::<HtmlAttributeLabels>(invocation.tokens.clone())
        {
            self.macro_tokens(markup.0);
            return;
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
        fn call_expression_end(tokens: &[proc_macro2::TokenTree], mut end: usize) -> Option<usize> {
            let parenthesis = |index: usize| {
                matches!(tokens.get(index), Some(proc_macro2::TokenTree::Group(group))
                    if group.delimiter() == proc_macro2::Delimiter::Parenthesis)
            };
            let mut call = false;
            let mut member = false;
            if parenthesis(end) {
                end += 1;
                call = true;
            }
            for _ in 0..MAX_ALIAS_ROUNDS {
                if matches!(tokens.get(end), Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == '?')
                {
                    end += 1;
                } else if matches!(tokens.get(end), Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == '.')
                    && matches!(tokens.get(end + 1), Some(proc_macro2::TokenTree::Ident(_)))
                {
                    end += 2;
                    member = true;
                    if parenthesis(end) {
                        end += 1;
                        call = true;
                    }
                } else {
                    return (call || member).then_some(end);
                }
            }
            None
        }
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if let proc_macro2::TokenTree::Group(group) = &tokens[index] {
                if let Some(end) = call_expression_end(&tokens, index + 1)
                    && let Ok(expression) =
                        syn::parse2::<Expr>(tokens[index..end].iter().cloned().collect())
                {
                    self.visit_expr(&expression);
                    index = end;
                    continue;
                }
                // A whole valid Rust group carries real lexical scopes (e.g.
                // a JSON value block with local DATA shadowing an imported fn).
                // Invalid macro-specific groups retain conservative token scans.
                if let Ok(expression) =
                    syn::parse2::<Expr>(std::iter::once(tokens[index].clone()).collect())
                {
                    self.visit_expr(&expression);
                    index += 1;
                    continue;
                }
                self.macro_tokens(group.stream());
            }
            if let proc_macro2::TokenTree::Ident(first) = &tokens[index] {
                let mut name = identifier_name(first);
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
                    name.push_str(&identifier_name(next));
                    end += 3;
                }
                // Recover bounded call/postfix expressions inside JSON and
                // other token grammars. A member name is not a free function;
                // the normal AST visitor retains its receiver's provenance.
                if let Some(expression_end) = call_expression_end(&tokens, end)
                    && let Ok(expression) =
                        syn::parse2::<Expr>(tokens[index..expression_end].iter().cloned().collect())
                {
                    self.visit_expr(&expression);
                    index = expression_end;
                    continue;
                }
                let target = self.reference_target(&name);
                // A fallback bare identifier may be a value reference even
                // without a call (e.g. a function pointer in a JSON value).
                // A type-only declaration cannot qualify that inherited value.
                self.parent_effect_path_checked(
                    &name,
                    false,
                    if name.contains("::") {
                        PathNamespace::Type
                    } else {
                        PathNamespace::Value
                    },
                );
                if let Some(target) = &target
                    && let Some(kind) = hazard(target)
                {
                    let call_end = if matches!(tokens.get(end), Some(proc_macro2::TokenTree::Group(group)) if group.delimiter() == proc_macro2::Delimiter::Parenthesis)
                    {
                        end + 1
                    } else {
                        end
                    };
                    let syntax: proc_macro2::TokenStream =
                        tokens[index..call_end].iter().cloned().collect();
                    self.record(kind, target, syntax);
                }
                if matches!(tokens.get(end), Some(proc_macro2::TokenTree::Punct(punctuation)) if punctuation.as_char() == '!')
                {
                    let macro_target = self.resolve_name(&name);
                    let kind = match macro_target.as_str() {
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
                        self.record(kind, &macro_target, syntax);
                    }
                }
                index = end;
            } else {
                index += 1;
            }
        }
    }
}

// Supported subset of the locked maud_macros 0.27.0 ast.rs grammar:
// static element heads/names, named/class/id attributes, literal/splice/block
// values and togglers. @control flow and any unsupported form retain the
// unchanged conservative scanner. This is not macro expansion resolution.
struct HtmlAttributeLabels(proc_macro2::TokenStream);

impl syn::parse::Parse for HtmlAttributeLabels {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        use syn::ext::IdentExt;
        type Stream = proc_macro2::TokenStream;
        type Tree = proc_macro2::TokenTree;

        fn debit(input: syn::parse::ParseStream<'_>, work: &mut usize) -> syn::Result<()> {
            *work += 1;
            if *work > MAX_ALIAS_ROUNDS * MAX_ALIAS_ROUNDS {
                return Err(input.error("bounded Maud attribute grammar exceeded"));
            }
            Ok(())
        }

        fn name(input: syn::parse::ParseStream<'_>, work: &mut usize) -> syn::Result<Stream> {
            fn fragment(input: syn::parse::ParseStream<'_>) -> syn::Result<Stream> {
                if input.peek(syn::Ident::peek_any) {
                    Ok(input.call(syn::Ident::parse_any)?.into_token_stream())
                } else {
                    let literal: syn::Lit = input.parse()?;
                    if !matches!(literal, syn::Lit::Str(_) | syn::Lit::Int(_)) {
                        return Err(input.error("unsupported Maud name fragment"));
                    }
                    Ok(literal.into_token_stream())
                }
            }
            debit(input, work)?;
            let mut output = fragment(input)?;
            while input.peek(syn::Token![-]) || input.peek(syn::Token![:]) {
                debit(input, work)?;
                output.extend(std::iter::once(input.parse::<Tree>()?));
                output.extend(fragment(input)?);
            }
            Ok(output)
        }

        fn expression_group(input: syn::parse::ParseStream<'_>) -> syn::Result<Tree> {
            let token: Tree = input.parse()?;
            let Tree::Group(group) = &token else { return Err(input.error("expected Maud expression group")); };
            syn::parse2::<Expr>(group.stream())?;
            // Keep the exact original RHS group, including its tokens/span.
            Ok(token)
        }

        fn group(input: syn::parse::ParseStream<'_>, depth: usize, work: &mut usize, elements: bool) -> syn::Result<Tree> {
            let token: Tree = input.parse()?;
            let Tree::Group(original) = token else { return Err(input.error("expected Maud markup group")); };
            let parser = |input: syn::parse::ParseStream<'_>| markup(input, depth + 1, work, elements);
            let content = syn::parse::Parser::parse2(parser, original.stream())?;
            let mut output = proc_macro2::Group::new(original.delimiter(), content);
            output.set_span(original.span());
            Ok(Tree::Group(output))
        }

        fn value(input: syn::parse::ParseStream<'_>, depth: usize, work: &mut usize) -> syn::Result<Tree> {
            if input.peek(syn::token::Paren) || input.peek(syn::token::Bracket) {
                expression_group(input)
            } else if input.peek(syn::token::Brace) {
                group(input, depth, work, false)
            } else {
                let token: Tree = input.parse()?;
                syn::parse2::<syn::LitStr>(std::iter::once(token.clone()).collect())?;
                Ok(token)
            }
        }

        fn element(input: syn::parse::ParseStream<'_>, depth: usize, work: &mut usize) -> syn::Result<Stream> {
            let mut output = Stream::new();
            if input.peek(syn::Ident::peek_any) {
                output.extend(name(input, work)?);
            }
            while input.peek(syn::Ident::peek_any) || input.peek(syn::Lit) || input.peek(syn::Token![.]) || input.peek(syn::Token![#]) {
                debit(input, work)?;
                if input.peek(syn::Token![.]) || input.peek(syn::Token![#]) {
                    let punctuation: Tree = input.parse()?;
                    let class = matches!(&punctuation, Tree::Punct(punctuation) if punctuation.as_char() == '.');
                    output.extend(std::iter::once(punctuation));
                    if input.peek(syn::token::Paren) || input.peek(syn::token::Brace) {
                        output.extend(std::iter::once(value(input, depth, work)?));
                    } else {
                        output.extend(name(input, work)?);
                    }
                    if class && input.peek(syn::token::Bracket) {
                        output.extend(std::iter::once(expression_group(input)?));
                    }
                    continue;
                }
                let label = name(input, work)?;
                let optional = if input.peek(syn::Token![?]) { Some(input.parse::<Tree>()?) } else { None };
                if input.peek(syn::Token![=]) {
                    let equality: Tree = input.parse()?;
                    if input.peek(syn::Token![=]) || input.peek(syn::Token![>]) {
                        return Err(input.error("expected one Maud attribute equals sign"));
                    }
                    // A checked named-attribute lhs is literal output, not a
                    // value reference. Only this complete HtmlName is removed.
                    output.extend(std::iter::once(equality));
                    output.extend(std::iter::once(value(input, depth, work)?));
                } else {
                    output.extend(label);
                    output.extend(optional);
                    if input.peek(syn::token::Bracket) {
                        output.extend(std::iter::once(expression_group(input)?));
                    }
                }
            }
            if input.peek(syn::token::Brace) {
                output.extend(std::iter::once(group(input, depth, work, true)?));
            } else {
                output.extend(input.parse::<syn::Token![;]>()?.into_token_stream());
            }
            Ok(output)
        }

        fn markup(input: syn::parse::ParseStream<'_>, depth: usize, work: &mut usize, elements: bool) -> syn::Result<Stream> {
            if depth > MAX_ALIAS_ROUNDS {
                return Err(input.error("bounded Maud markup depth exceeded"));
            }
            let mut output = Stream::new();
            while !input.is_empty() {
                debit(input, work)?;
                if input.peek(syn::token::Paren) {
                    output.extend(std::iter::once(expression_group(input)?));
                } else if input.peek(syn::token::Brace) {
                    output.extend(std::iter::once(group(input, depth, work, elements)?));
                } else if input.peek(syn::Lit) {
                    let literal: syn::LitStr = input.parse()?;
                    output.extend(literal.into_token_stream());
                } else if input.peek(syn::Token![;]) {
                    output.extend(input.parse::<syn::Token![;]>()?.into_token_stream());
                } else if elements && (input.peek(syn::Ident::peek_any) || input.peek(syn::Token![.]) || input.peek(syn::Token![#])) {
                    output.extend(element(input, depth, work)?);
                } else {
                    return Err(input.error("unsupported Maud markup grammar"));
                }
            }
            Ok(output)
        }

        Ok(Self(markup(input, 0, &mut 0, true)?))
    }
}

fn path_receiver_type(target: &str) -> bool {
    matches!(target, "std::path::Path" | "std::path::PathBuf")
}

fn path_projection_type(target: &str) -> bool {
    matches!(target, "std::path::Components" | "std::path::Iter")
}

fn path_filesystem_method(method: &str) -> bool {
    matches!(method,
        "exists" | "try_exists" | "is_file" | "is_dir" | "is_symlink"
            | "metadata" | "symlink_metadata" | "canonicalize" | "read_link" | "read_dir")
}

fn path_method_result(owner: &str, method: &str) -> Option<&'static str> {
    match method {
        "canonicalize" | "read_link" if path_receiver_type(owner) => Some("std::path::PathBuf"),
        "metadata" | "symlink_metadata" if path_receiver_type(owner) => Some("std::fs::Metadata"),
        "read_dir" if path_receiver_type(owner) => Some(READ_DIR_RESULT),
        "components" if path_receiver_type(owner) => Some("std::path::Components"),
        "iter" if path_receiver_type(owner) => Some("std::path::Iter"),
        "as_path" if path_projection_type(owner) => Some("std::path::Path"),
        _ => None,
    }
}

fn read_dir_peek_method(method: &str) -> bool {
    matches!(method, "peek" | "peek_mut" | "next_if" | "next_if_eq" | "next_if_map" | "next_if_map_mut")
}

fn read_dir_consuming_method(method: &str) -> bool {
    // Stable Iterator consumers in the pinned standard library. The fact is
    // emitted only for retained ReadDir lineage, never arbitrary iterators.
    read_dir_peek_method(method) || matches!(method,
        "next" | "nth" | "last" | "count" | "collect" | "fold" | "try_fold"
            | "for_each" | "try_for_each" | "find" | "find_map" | "position"
            | "all" | "any" | "reduce" | "min" | "max" | "min_by" | "max_by"
            | "min_by_key" | "max_by_key" | "partition" | "unzip" | "sum" | "product"
            | "cmp" | "partial_cmp" | "eq" | "ne" | "lt" | "le" | "gt" | "ge"
            | "is_sorted" | "is_sorted_by" | "is_sorted_by_key")
}

fn read_dir_lazy_method(method: &str) -> bool {
    // These construct/borrow adaptors without requesting the next entry.
    // Their lineage is only the known underlying ReadDir; no concrete generic
    // adaptor type or captured callback/per-entry output is inferred.
    matches!(method,
        "into_iter" | "by_ref" | "step_by" | "chain" | "zip" | "map" | "filter"
            | "filter_map" | "enumerate" | "peekable" | "skip_while" | "take_while"
            | "map_while" | "skip" | "take" | "scan" | "flat_map" | "flatten"
            | "fuse" | "inspect" | "copied" | "cloned" | "cycle")
}

fn read_dir_lineage(origin: &str) -> bool {
    matches!(origin, READ_DIR_HANDLE | READ_DIR_RESULT | READ_DIR_OPTION | READ_DIR_UNMODELED)
}

fn read_dir_unmodeled_projection(origin: Option<&str>) -> Option<&'static str> {
    // Without an exact registered field or supported variant projection, a
    // known native container cannot produce a fresh DATA exemption. This is
    // retained uncertainty, not generic substitution or element inference.
    origin.filter(|origin| read_dir_lineage(origin)).map(|_| READ_DIR_UNMODELED)
}

fn read_dir_projection_result(owner: &str, method: &str) -> Option<&'static str> {
    // Only the exact known wrapper shape gets a standard projection. A bare
    // ReadDir extension trait with the same method spelling is still refused.
    if matches!(owner, READ_DIR_RESULT | READ_DIR_OPTION) {
        match method {
            "unwrap" | "expect" => Some(READ_DIR_HANDLE),
            "as_ref" | "as_mut" => Some(if owner == READ_DIR_RESULT { READ_DIR_RESULT } else { READ_DIR_OPTION }),
            _ => None,
        }
    } else { None }
}

fn read_dir_second_iterator_method(method: &str) -> bool {
    matches!(method, "chain" | "zip" | "cmp" | "partial_cmp" | "eq" | "ne" | "lt" | "le" | "gt" | "ge")
}

fn ambient_receiver_type(target: &str) -> bool {
    // Known receivers only, including pure paths with filesystem methods:
    // Metadata, read buffers, PIDs, UUIDs and raw clock samples are not receivers
    // merely because their factory is ambient. This is not general Rust
    // output-type or wrapper resolution.
    path_receiver_type(target) || path_projection_type(target) || read_dir_lineage(target) || matches!(
        target,
        "std::fs::File"
            | "std::fs::OpenOptions"
            | "tokio::fs::File"
            | "tokio::fs::OpenOptions"
            | "std::process::Command"
            | "tokio::process::Command"
            | "std::time::Instant"
            | "std::time::SystemTime"
            | "tokio::time::Instant"
            | "std::net::TcpStream"
            | "std::net::TcpListener"
            | "std::net::UdpSocket"
            | "tokio::net::TcpStream"
            | "tokio::net::TcpListener"
            | "tokio::net::UdpSocket"
            | "socket2::Socket"
            | "reqwest::Client"
            | "reqwest::ClientBuilder"
            | "reqwest::RequestBuilder"
            | "reqwest::blocking::Client"
            | "reqwest::blocking::ClientBuilder"
            | "reqwest::blocking::RequestBuilder"
            | "rand::rngs::OsRng"
            | "rand::rngs::ThreadRng"
            | "rand::rngs::SmallRng"
            | "rand::rngs::StdRng"
            | "rand_core::OsRng"
            | "tokio::runtime::Runtime"
            | "tokio::runtime::Builder"
            | "std::thread::Builder"
            | "ureq::Agent"
            | "ureq::AgentBuilder"
            | "ureq::Request"
    )
}

fn receiver_returns_data(origin: &str, method: &str) -> bool {
    // Known scalar/metadata/completed-response results terminate receiver
    // propagation. Other methods of an already known handle conservatively
    // retain it: this includes builders, open/clone and unmodeled transforms,
    // and is not a claim that every such result has the same Rust output type.
    // Only exact known return carriers retain receiver provenance. Completed
    // Metadata/bool values must not inherit Path's filesystem predicates.
    if path_method_result(origin, method).is_some_and(ambient_receiver_type) {
        return false;
    }
    if read_dir_projection_result(origin, method).is_some() {
        return false;
    }
    if origin == READ_DIR_HANDLE {
        if read_dir_lazy_method(method) {
            return false;
        }
        if read_dir_consuming_method(method) || method == "size_hint" {
            return true;
        }
    }
    // These exact Path projections return pure scalar/string DATA,
    // not another path. Conditional DATA bindings must not be mistaken for
    // conditional receiver origins. Unknown transforms still retain the
    // known receiver conservatively; this is a finite standard API boundary.
    if path_receiver_type(origin) && matches!(method,
        "is_absolute" | "is_relative" | "has_root" | "starts_with" | "ends_with"
            | "as_os_str" | "to_str" | "to_string_lossy"
            | "display" | "file_name" | "file_stem" | "extension")
    {
        return true;
    }
    // Components/Iter retain a path through as_path; only their exact scalar
    // and element outputs are DATA. Arbitrary iterator transforms are not an
    // output-type resolver and retain the known receiver conservatively.
    if path_projection_type(origin) && matches!(method, "next" | "nth" | "last" | "count" | "size_hint") {
        return true;
    }
    if matches!(origin, "std::fs::OpenOptions" | "tokio::fs::OpenOptions")
        && matches!(method, "read" | "write")
    {
        return false;
    }
    if matches!(
        method,
        "new"
            | "builder"
            | "open"
            | "create"
            | "from"
            | "try_clone"
            | "spawn"
            | "accept"
            | "bind"
            | "connect"
            | "connect_timeout"
            | "now"
            | "from_os_rng"
            | "try_from_os_rng"
    ) {
        return false;
    }
    if matches!(
        origin,
        "std::time::SystemTime" | "std::time::Instant" | "tokio::time::Instant"
    ) && matches!(method, "duration_since" | "checked_duration_since")
        || (origin.starts_with("std::process::Command")
            || origin.starts_with("tokio::process::Command"))
            && matches!(
                method,
                "get_program" | "get_args" | "get_envs" | "get_current_dir"
            )
    {
        return true;
    }
    method_hazard(origin, method).is_some()
}

fn pattern_binds(pattern: &Pat) -> bool {
    match pattern {
        Pat::Ident(_) => true,
        Pat::Type(pattern) => pattern_binds(&pattern.pat),
        Pat::Reference(pattern) => pattern_binds(&pattern.pat),
        Pat::Paren(pattern) => pattern_binds(&pattern.pat),
        Pat::Tuple(pattern) => pattern.elems.iter().any(pattern_binds),
        Pat::TupleStruct(pattern) => pattern.elems.iter().any(pattern_binds),
        Pat::Struct(pattern) => pattern.fields.iter().any(|field| pattern_binds(&field.pat)),
        Pat::Slice(pattern) => pattern.elems.iter().any(pattern_binds),
        Pat::Or(pattern) => pattern.cases.iter().any(pattern_binds),
        _ => false,
    }
}

fn value_wrapper_target(target: &str) -> bool {
    matches!(
        target,
        "Some"
            | "Option::Some"
            | "std::option::Option::Some"
            | "core::option::Option::Some"
            | "Ok"
            | "Result::Ok"
            | "std::result::Result::Ok"
            | "core::result::Result::Ok"
    )
}

fn dangerous_namespace(target: &str) -> bool {
    matches!(
        target,
        "std" | "tokio" | "chrono" | "uuid" | "libc" | "rustix"
    ) || [
        "std::time",
        "rustix::time",
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

/// These exact types expose listed ambient constructors. This predicate governs
/// import provenance and conservative alternate-target alias retention; concrete
/// call findings still use the exact hazard list, rather than every type method.
fn ambient_binding(target: &str) -> bool {
    read_dir_lineage(target) || dangerous_namespace(target)
        || matches!(
            target,
            "time"
                | "time::OffsetDateTime"
                | "time::UtcDateTime"
                | "chrono::Utc"
                | "chrono::Local"
                | "uuid::Uuid"
                | "std::path"
                | "std::path::Path"
                | "std::path::PathBuf"
                | "std::path::Components"
                | "std::path::Iter"
                | "std::path::absolute"
                | "rustix::fs"
                | "rustix::fs::open"
        )
}

fn canonical_library_path(target: &str) -> bool {
    ["time::", "chrono::", "uuid::"]
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

fn canonical_binding(target: &str) -> bool {
    ambient_binding(target) || canonical_library_path(target)
}

fn ambient_import_target(target: &str, names: &BTreeSet<String>) -> bool {
    ambient_binding(target)
        // In particular, the std `time` name must not turn the external
        // crate's Date/RFC3339 imports into ambient type aliases.
        || !canonical_library_path(target)
            && names.contains(relative_name(target).split("::").next().unwrap_or_default())
}

fn hazard(target: &str) -> Option<&'static str> {
    if let Some(method) = target.strip_prefix("std::fs::ReadDir::")
        && (read_dir_lazy_method(method) || method == "size_hint")
    {
        // The old std::fs namespace rule is conservative, but these exact
        // methods only construct adaptors or query a bound, not OS entries.
        return None;
    }
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
            | "time::OffsetDateTime::now_utc"
            | "time::OffsetDateTime::now_local"
            | "time::UtcDateTime::now"
            | "rustix::time::clock_gettime"
            | "rustix::time::clock_gettime_dynamic"
            | "rustix::time::clock_getres"
            | "rustix::time::clock_settime"
    ) {
        return Some("clock");
    }
    if target.starts_with("rustix::time::")
        && matches!(
            target.rsplit("::").next(),
            Some("clock_nanosleep_absolute" | "clock_nanosleep_relative" | "nanosleep")
        )
    {
        return Some("timer");
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
    if target == "rustix::fs::open"
        || target.rsplit_once("::").is_some_and(|(owner, method)| owner == "std::path::Path" && path_filesystem_method(method)) {
        return Some("filesystem");
    }
    if target == "std::path::absolute" {
        return Some("environment");
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
    if path_receiver_type(origin) && path_filesystem_method(method) {
        return Some("filesystem");
    }
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
        scan_syntax(syn::parse_file(source).unwrap())
    }

    #[test]
    fn path_and_rustix_calls_keep_exact_targets_and_authored_fingerprints() {
        let findings = scan(r#"
            use std::path::{Path as InputPath, PathBuf as OwnedPath};
            fn direct(path: &std::path::Path) {
                std::path::Path::exists(path);
                std::path::Path::canonicalize(path);
            }
            fn typed(path: &InputPath, buffer: OwnedPath) {
                path.exists(); buffer.canonicalize();
            }
            fn constructed(value: &str) {
                let path = InputPath::new(value); path.exists();
                let owned = OwnedPath::from(value); owned.canonicalize();
                let next = owned.canonicalize().unwrap(); next.exists();
            }
            fn callbacks(path: &InputPath) {
                let check = InputPath::exists; check(path); check(path);
            }
            fn ufcs_return(path: &InputPath) {
                let next = InputPath::canonicalize(path).unwrap(); next.exists();
            }
            struct Holder { path: OwnedPath }
            fn field(holder: Holder) { holder.path.exists(); }
            fn unix(value: &str) {
                rustix::fs::open(value, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty());
            }
            fn nested(value: &str) {
                std::fs::File::from(rustix::fs::open(value,
                    rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()).unwrap());
            }
        "#);
        let mut actual = BTreeMap::new();
        for finding in &findings {
            assert_eq!(finding.kind, "filesystem", "{findings:?}");
            *actual.entry((finding.context.as_str(), finding.target.as_str())).or_insert(0usize) += finding.count;
        }
        assert_eq!(actual, BTreeMap::from([
            (("direct", "std::path::Path::exists"), 1),
            (("direct", "std::path::Path::canonicalize"), 1),
            (("typed", "std::path::Path::exists"), 1),
            (("typed", "std::path::Path::canonicalize"), 1),
            (("constructed", "std::path::Path::exists"), 2),
            (("constructed", "std::path::Path::canonicalize"), 2),
            (("callbacks", "std::path::Path::exists"), 3),
            (("ufcs_return", "std::path::Path::canonicalize"), 1),
            (("ufcs_return", "std::path::Path::exists"), 1),
            (("field", "std::path::Path::exists"), 1),
            (("unix", "rustix::fs::open"), 1),
            (("nested", "rustix::fs::open"), 1),
            (("nested", "std::fs::File::from"), 1),
        ]), "{findings:?}");

        let normal = scan("fn f(path: &std::path::Path) { path.exists(); }");
        let spaced = scan("fn f(path: &std::path::Path) { /* same call */ path . exists ( ) ; }");
        let raw = scan("fn f(path: &r#std::path::r#Path) { path.r#exists(); }");
        assert_eq!(normal.len(), 1, "{normal:?}");
        assert_eq!(spaced.len(), 1, "{spaced:?}");
        assert_eq!(raw.len(), 1, "{raw:?}");
        assert_eq!(normal[0].target, raw[0].target);
        assert_eq!(normal[0].fingerprint, spaced[0].fingerprint);
        assert_ne!(normal[0].fingerprint, raw[0].fingerprint);
        let normal = scan("fn f() { rustix::fs::open(\"a\", flags(), mode()); }");
        let raw = scan("fn f() { r#rustix::r#fs::r#open(\"a\", flags(), mode()); }");
        assert_eq!(normal.len(), 1, "{normal:?}");
        assert_eq!(raw.len(), 1, "{raw:?}");
        assert_eq!(normal[0].target, raw[0].target);
        assert_ne!(normal[0].fingerprint, raw[0].fingerprint);
        for source in [
            "fn f(path: &std::path::Path) { let next = std::path::Path::canonicalize(path).unwrap(); next.exists(); }",
            "use std::path::Path as Location; fn f(path: &Location) { let next = Location::canonicalize(path).unwrap(); next.exists(); }",
            "fn f(path: &r#std::path::r#Path) { let next = r#std::path::r#Path::r#canonicalize(path).unwrap(); next.r#exists(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 2, "{source}: {findings:?}");
            assert!(findings.iter().all(|finding| finding.count == 1 && finding.kind == "filesystem"), "{source}: {findings:?}");
            assert_eq!(findings.iter().map(|finding| finding.target.as_str()).collect::<BTreeSet<_>>(), BTreeSet::from(["std::path::Path::canonicalize", "std::path::Path::exists"]), "{source}: {findings:?}");
        }
        let findings = scan("fn f(path: &std::path::Path) { let resolve = std::path::Path::canonicalize; let next = resolve(path).unwrap(); next.exists(); }");
        assert_eq!(findings.iter().filter(|finding| finding.target == "std::path::Path::canonicalize").map(|finding| finding.count).sum::<usize>(), 2, "{findings:?}");
        assert_eq!(findings.iter().filter(|finding| finding.target == "std::path::Path::exists").map(|finding| finding.count).sum::<usize>(), 1, "{findings:?}");
        // Literal expected vocabulary is independent of the production helper.
        // Rust1.98.1 path.rs forwards each method to a real filesystem read.
        for method in ["exists", "try_exists", "is_file", "is_dir", "is_symlink",
            "metadata", "symlink_metadata", "canonicalize", "read_link", "read_dir"] {
            let target = format!("std::path::Path::{method}");
            for source in [
                format!("fn f(path: &std::path::Path) {{ std::path::Path::{method}(path); }}"),
                format!("use std::path::Path as Location; fn f(path: &Location) {{ path.{method}(); }}"),
                format!("fn f(path: &r#std::r#path::r#Path) {{ path.r#{method}(); }}"),
                format!("fn f() {{ std::path::PathBuf::from(\"a\").{method}(); }}"),
            ] {
                let findings = scan(&source);
                assert_eq!(findings.len(), 1, "{source}: {findings:?}");
                assert_eq!(findings[0].target, target, "{source}: {findings:?}");
                assert_eq!(findings[0].kind, "filesystem");
                assert_eq!(findings[0].count, 1);
            }
        }
        for source in [
            "fn f(path: &std::path::Path) { let next = path.read_link().unwrap(); next.exists(); }",
            "fn f(path: &std::path::Path) { let next = std::path::Path::read_link(path).unwrap(); next.exists(); }",
            "use std::path::Path as Location; fn f(path: &Location) { let next = Location::read_link(path).unwrap(); next.exists(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 2, "{source}: {findings:?}");
            assert!(findings.iter().all(|finding| finding.count == 1), "{source}: {findings:?}");
            assert_eq!(findings.iter().map(|finding| finding.target.as_str()).collect::<BTreeSet<_>>(), BTreeSet::from(["std::path::Path::read_link", "std::path::Path::exists"]), "{source}: {findings:?}");
        }
        for source in [
            "fn f() { let next = std::path::absolute(\"relative\").unwrap(); next.exists(); }",
            "use std::path::absolute as resolve; fn f() { let next = resolve(\"relative\").unwrap(); next.exists(); }",
            "fn f() { let next = r#std::r#path::r#absolute(\"relative\").unwrap(); next.r#exists(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 2, "{source}: {findings:?}");
            assert!(findings.iter().any(|finding| finding.target == "std::path::absolute" && finding.kind == "environment" && finding.count == 1), "{source}: {findings:?}");
            assert!(findings.iter().any(|finding| finding.target == "std::path::Path::exists" && finding.kind == "filesystem" && finding.count == 1), "{source}: {findings:?}");
        }
        for source in [
            "fn f(path: &std::path::Path) { path.components().as_path().exists(); }",
            "fn f(path: &std::path::Path) { std::path::Path::components(path).as_path().exists(); }",
            "use std::path::{Path as Location, Components as Parts}; fn f(path: &Location) { let parts = Location::components(path); Parts::as_path(&parts).exists(); }",
            "fn f(path: &r#std::path::r#Path) { r#std::path::r#Path::r#iter(path).r#as_path().r#exists(); }",
            "fn f(parts: &std::path::Iter<'_>) { std::path::Iter::as_path(parts).exists(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 1, "{source}: {findings:?}");
            assert_eq!(findings[0].target, "std::path::Path::exists", "{source}: {findings:?}");
            assert_eq!(findings[0].count, 1, "{source}: {findings:?}");
        }
    }

    #[test]
    fn path_and_rustix_aliases_preserve_closed_provenance() {
        for source in [
            "use std::path::*; fn f(path: &Path) { path.exists(); }",
            "use std::path as paths; fn f(path: &paths::Path) { path.exists(); }",
            "use std::path::r#Path as r#Location; fn f(path: &Location) { path.r#exists(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.iter().filter(|finding| finding.target == "std::path::Path::exists").map(|finding| finding.count).sum::<usize>(), 1, "{source}: {findings:?}");
        }
        for source in [
            "use rustix::fs::open as read_input; fn f() { read_input(\"a\", flags(), mode()); }",
            "use rustix::fs::*; fn f() { open(\"a\", flags(), mode()); }",
            "use rustix::fs as disk; fn f() { disk::open(\"a\", flags(), mode()); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.iter().filter(|finding| finding.target == "rustix::fs::open").map(|finding| finding.count).sum::<usize>(), 1, "{source}: {findings:?}");
        }
        for child in [
            "use super::*; fn f(path: &Location) { path.exists(); }",
            "use super::Location; fn f(path: &Location) { path.canonicalize(); }",
            "fn f(path: &std::path::Path) { super::Location::exists(path); }",
            "use super::read_input; fn f() { read_input(\"a\", flags(), mode()); }",
            "use super::resolve; fn f() { resolve(\"relative\"); }",
        ] {
            let directory = fixture("use std::path::Path as Location; use std::path::absolute as resolve; use rustix::fs::open as read_input; mod child;");
            fs::write(directory.path().join("crates/fixture/src/child.rs"), child).unwrap();
            let error = inventory(directory.path()).unwrap_err().to_string();
            assert!(error.contains("unresolved parent ambient imports"), "{child}: {error}");
        }
        let findings = scan("#[cfg(unix)] use std::path::Path as Location;
            #[cfg(windows)] use fixture::Pure as Location;
            fn f(path: &Location) { path.exists(); }");
        assert!(findings.iter().any(|finding| finding.kind == "effect-alias-conflict"), "{findings:?}");
        assert!(findings.iter().any(|finding| finding.target == "std::path::Path::exists"), "{findings:?}");
        for source in [
            "fn f() { #[cfg(unix)] let path = std::path::Path::new(\"a\"); path.exists(); }",
            "fn f() { #[cfg(unix)] let path: std::path::PathBuf = std::path::PathBuf::from(\"a\"); path.exists(); }",
            "fn f() { #[cfg(unix)] let path = std::path::Path::new(\"a\").canonicalize().unwrap(); path.exists(); }",
            "fn f(path: &std::path::Path) { #[cfg(unix)] let parts = path.components(); parts.as_path().exists(); }",
            "fn f(path: &std::path::Path) { #[cfg(unix)] let parts = std::path::Path::iter(path); parts.as_path().exists(); }",
            "fn f() { #[cfg(unix)] let path = std::path::absolute(\"relative\").unwrap(); path.exists(); }",
            "fn f(path: &std::path::Path) { #[cfg(unix)] let entries = path.read_dir().unwrap(); entries.next(); }",
        ] {
            let error = inventory(fixture(source).path()).unwrap_err().to_string();
            assert!(error.contains("conditional ambient local bindings"), "{source}: {error}");
        }
    }

    #[test]
    fn pure_paths_and_completed_path_data_remain_effect_free() {
        let findings = scan(r#"
            use std::path::{Path, PathBuf};
            fn pure(value: &str, path: &Path, owned: PathBuf) {
                Path::new(value).is_absolute(); path.components(); path.join("child");
                path.to_str(); owned.as_path(); PathBuf::from(value).file_name();
                let path = PathBuf::new(); path.as_os_str();
                rustix::fs::Mode::empty();
            }
            fn conditional_data(path: &Path) {
                #[cfg(unix)] let absolute = path.is_absolute();
                #[cfg(unix)] let count = path.components().count();
                #[cfg(unix)] let hint = path.iter().size_hint();
                #[cfg(unix)] let text = path.to_str();
                #[cfg(unix)] let name = path.file_name();
                #[cfg(unix)] let label = path.display();
            }
            struct Data { exists: bool, canonicalize: String }
            fn metadata(data: Data) { json!({"exists": data.exists, "canonicalize": data.canonicalize}); }
            #[cfg(test)] fn only_fixture(path: &Path) { path.exists(); path.canonicalize(); }
        "#);
        assert!(findings.is_empty(), "{findings:?}");
        let findings = scan(r#"
            fn f(path: &std::path::Path) {
                #[cfg(unix)] let exists = path.exists();
                let exists = path.exists(); json!({"exists": exists});
                exists.then_some(7);
                let path: std::path::PathBuf = {
                    #[cfg(unix)] { std::path::PathBuf::from("a") }
                    #[cfg(not(unix))] { std::path::PathBuf::new() }
                };
                path.exists();
            }
        "#);
        assert!(findings.iter().all(|finding| finding.target == "std::path::Path::exists"), "{findings:?}");
        assert_eq!(findings.iter().map(|finding| finding.count).sum::<usize>(), 3, "{findings:?}");
        let findings = scan(r#"
            fn f(path: &std::path::Path) {
                let parts: std::path::Components<'_> = {
                    #[cfg(unix)] { path.components() }
                    #[cfg(not(unix))] { path.components() }
                };
                parts.as_path().exists();
            }
        "#);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].target, "std::path::Path::exists");
        assert_eq!(findings[0].count, 1);
        for method in ["metadata", "symlink_metadata"] {
            for source in [
                format!("fn f(path: &std::path::Path) {{ let facts = path.{method}().unwrap(); facts.is_file(); facts.is_dir(); facts.is_symlink(); }}"),
                format!("fn f(path: &std::path::Path) {{ let facts = std::path::Path::{method}(path).unwrap(); facts.is_file(); facts.is_dir(); facts.is_symlink(); }}"),
                format!("fn f(path: &std::path::Path) {{ #[cfg(unix)] let facts = path.{method}().unwrap(); facts.is_file(); }}"),
            ] {
                let findings = scan(&source);
                assert_eq!(findings.len(), 1, "{source}: {findings:?}");
                assert_eq!(findings[0].target, format!("std::path::Path::{method}"), "{source}: {findings:?}");
                assert_eq!(findings[0].count, 1);
            }
        }
        // ReadDir is a known non-Path output, not a guessed Path receiver.
        // This does not model arbitrary Iterator adapters or per-entry returns.
        for source in [
            "fn f(path: &std::path::Path) { let entries = path.read_dir().unwrap(); entries.size_hint(); }",
            "fn f(path: &std::path::Path) { let entries = std::path::Path::read_dir(path).unwrap(); entries.size_hint(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 1, "{source}: {findings:?}");
            assert_eq!(findings[0].target, "std::path::Path::read_dir");
            assert_eq!(findings[0].count, 1);
        }
    }

    #[test]
    fn known_read_dir_consumption_keeps_io_and_lazy_path_iterators_stay_pure() {
        // Source controls, not a compiler claim about arbitrary Iterator bounds.
        // Comparisons/order consumers use mapped integer entries where needed.
        for (operation, expression) in [
            ("next", "entries.next()"), ("nth", "entries.nth(1)"),
            ("last", "entries.last()"), ("count", "entries.count()"),
            ("collect", "entries.collect::<Vec<_>>()"),
            ("fold", "entries.fold(0, |n, _| n + 1)"),
            ("try_fold", "entries.try_fold(0, |n, _| Ok::<_, ()>(n + 1))"),
            ("for_each", "entries.for_each(|_| {})"),
            ("try_for_each", "entries.try_for_each(|_| Ok::<_, ()>(()))"),
            ("find", "entries.find(|_| true)"),
            ("find_map", "entries.find_map(|_| Some(0))"),
            ("position", "entries.position(|_| true)"),
            ("all", "entries.all(|_| true)"), ("any", "entries.any(|_| true)"),
            ("reduce", "entries.reduce(|first, _| first)"),
            ("min", "entries.map(|_| 0).min()"), ("max", "entries.map(|_| 0).max()"),
            ("min_by", "entries.min_by(|_, _| std::cmp::Ordering::Equal)"),
            ("max_by", "entries.max_by(|_, _| std::cmp::Ordering::Equal)"),
            ("min_by_key", "entries.min_by_key(|_| 0)"),
            ("max_by_key", "entries.max_by_key(|_| 0)"),
            ("partition", "entries.partition::<Vec<_>, _>(|_| true)"),
            ("unzip", "entries.map(|_| (0, 0)).unzip::<_, _, Vec<_>, Vec<_>>()"),
            ("sum", "entries.map(|_| 0u32).sum::<u32>()"),
            ("product", "entries.map(|_| 1u32).product::<u32>()"),
            ("cmp", "entries.map(|_| 0).cmp([0])"),
            ("partial_cmp", "entries.map(|_| 0).partial_cmp([0])"),
            ("eq", "entries.map(|_| 0).eq([0])"), ("ne", "entries.map(|_| 0).ne([0])"),
            ("lt", "entries.map(|_| 0).lt([0])"), ("le", "entries.map(|_| 0).le([0])"),
            ("gt", "entries.map(|_| 0).gt([0])"), ("ge", "entries.map(|_| 0).ge([0])"),
            ("is_sorted", "entries.map(|_| 0).is_sorted()"),
            ("is_sorted_by", "entries.is_sorted_by(|_, _| true)"),
            ("is_sorted_by_key", "entries.is_sorted_by_key(|_| 0)"),
            ("peek", "entries.peekable().peek()"),
            ("peek_mut", "entries.peekable().peek_mut()"),
            ("next_if", "entries.peekable().next_if(|_| true)"),
            ("next_if_eq", "entries.map(|_| 0).peekable().next_if_eq(&0)"),
            ("next_if_map", "entries.peekable().next_if_map(|entry| Ok::<_, std::io::Result<std::fs::DirEntry>>(entry))"),
            ("next_if_map_mut", "entries.peekable().next_if_map_mut(|_| Some(0))"),
        ] {
            let source = format!("fn f(path: &std::path::Path) {{ let mut entries = path.read_dir().unwrap(); {expression}; }}");
            let findings = scan(&source);
            let counts = findings.iter().map(|finding| (finding.target.clone(), finding.count)).collect::<BTreeMap<_, _>>();
            assert_eq!(counts, BTreeMap::from([("std::path::Path::read_dir".to_owned(), 1), (format!("std::fs::ReadDir::{operation}"), 1)]), "{source}: {findings:?}");
        }
        for source in [
            "fn f() { let mut entries = std::fs::read_dir(\".\").unwrap(); entries.next(); }",
            "use std::fs::read_dir as selected; fn f() { let mut entries = selected(\".\").unwrap(); entries.next(); }",
            "use r#std::r#fs::r#read_dir as r#selected; fn f() { let mut r#entries = r#selected(\".\").unwrap(); r#entries.r#next(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 2, "{source}: {findings:?}");
            assert!(findings.iter().any(|finding| finding.target == "std::fs::read_dir" && finding.count == 1));
            assert!(findings.iter().any(|finding| finding.target == "std::fs::ReadDir::next" && finding.count == 1));
        }
        for source in [
            "fn f(mut entries: std::fs::ReadDir) { core::iter::Iterator::next(&mut entries); }",
            "use std::iter::Iterator as Advance; fn f(mut entries: std::fs::ReadDir) { Advance::next(&mut entries); }",
            "fn f(mut entries: std::fs::ReadDir) { <std::fs::ReadDir as core::iter::Iterator>::next(&mut entries); }",
            "fn f(mut entries: std::fs::ReadDir) { std::fs::ReadDir::next(&mut entries); }",
            "fn f(mut entries: r#std::r#fs::r#ReadDir) { r#core::r#iter::r#Iterator::r#next(&mut entries); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::IntoIterator::into_iter(entries).next(); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::Iterator::map(entries, |entry| entry).next(); }",
            "fn f(first: std::fs::ReadDir, second: std::fs::ReadDir) { core::iter::Iterator::chain(first, second).next(); }",
            "fn f(first: std::fs::ReadDir, second: std::fs::ReadDir) { core::iter::Iterator::zip(first, second).next(); }",
            "fn f(mut entries: std::fs::ReadDir) { entries.by_ref().filter(|_| true).take(1).next(); }",
            "fn f(entries: std::io::Result<std::fs::ReadDir>) { entries.unwrap().next(); }",
            "fn f(entries: core::option::Option<std::fs::ReadDir>) { entries.expect(\"directory\").next(); }",
            "fn f(mut entries: std::io::Result<std::fs::ReadDir>) { entries.as_mut().unwrap().next(); }",
            "use std::io::Result as Outcome; fn f(entries: Outcome<std::fs::ReadDir>) { entries.unwrap().next(); }",
            "fn f(entries: std::fs::ReadDir) { let wrapped = core::option::Option::Some(entries); wrapped.unwrap().next(); }",
            "fn f(entries: std::fs::ReadDir) { let wrapped: core::result::Result<_, ()> = core::result::Result::Ok(entries); wrapped.unwrap().next(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 1, "{source}: {findings:?}");
            assert_eq!(findings[0].target, "std::fs::ReadDir::next", "{source}: {findings:?}");
            assert_eq!(findings[0].count, 1);
        }
        for source in [
            "fn f(entries: std::fs::ReadDir) { for entry in entries {} }",
            "fn f(entries: std::fs::ReadDir) { for entry in entries.filter(|_| true) {} }",
            "fn f(first: std::fs::ReadDir, second: std::fs::ReadDir) { for entry in core::iter::Iterator::chain(first, second) {} }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 1, "{source}: {findings:?}");
            assert_eq!(findings[0].target, "std::fs::ReadDir::next");
            assert_eq!(findings[0].count, 1);
        }
        for source in [
            "fn f(entries: std::fs::ReadDir) { entries.map(|entry| entry); }",
            "fn f(entries: std::fs::ReadDir) { entries.size_hint(); }",
            "fn f(entries: std::io::Result<std::fs::ReadDir>) { entries.as_ref().unwrap().size_hint(); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::Iterator::size_hint(&entries); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::IntoIterator::into_iter(entries); }",
            "fn f(mut entries: std::fs::ReadDir) { entries.next().into_iter().count(); }",
            "fn f(entries: std::fs::ReadDir) { entries.collect::<Vec<_>>().into_iter().count(); }",
        ] {
            let findings = scan(source);
            let expected = if source.contains("entries.next()") || source.contains("entries.collect") { 1 } else { 0 };
            assert_eq!(findings.len(), expected, "{source}: {findings:?}");
            if expected == 1 { assert_eq!(findings[0].count, 1); }
        }
        for source in [
            "fn f(path: &std::path::Path) { path.components().count(); path.iter().next(); for part in path.components() {} }",
            "fn f() { core::iter::Iterator::next(&mut [0].iter()); for value in [0] {} }",
            "fn f(mut entries: std::fs::ReadDir) { entries.next().unwrap().unwrap().file_name(); }",
        ] {
            let findings = scan(source);
            let expected = usize::from(source.contains("entries.next()"));
            assert_eq!(findings.len(), expected, "{source}: {findings:?}");
        }
        let normal = scan("fn f(mut entries: std::fs::ReadDir) { entries.next(); }");
        let raw = scan("fn f(mut r#entries: r#std::r#fs::r#ReadDir) { r#entries.r#next(); }");
        assert_eq!(normal[0].target, raw[0].target);
        assert_ne!(normal[0].fingerprint, raw[0].fingerprint);
        for source in [
            "fn f(entries: &mut std::fs::ReadDir) { Iterator::next(entries); }",
            "fn f(entries: std::fs::ReadDir) { for entry in IntoIterator::into_iter(entries) {} }",
            "fn f(mut entries: std::fs::ReadDir) { let advance = core::iter::Iterator::next; advance(&mut entries); }",
            "use super::Iterator; fn f(entries: &mut std::fs::ReadDir) { Iterator::next(entries); }",
            "#[cfg(unix)] use core::iter::Iterator as Selected; fn f(entries: &mut std::fs::ReadDir) { Selected::next(entries); }",
            "trait Iterator { fn next(entries: &mut std::fs::ReadDir); } fn f(entries: &mut std::fs::ReadDir) { Iterator::next(entries); }",
            "use core::iter::Iterator as Selected; fn f(entries: &mut std::fs::ReadDir) { trait Selected { fn next(entries: &mut std::fs::ReadDir); } Selected::next(entries); }",
            "fn f(entries: std::fs::ReadDir) { consume(entries); }",
            "fn f(entries: std::fs::ReadDir) { Vec::<_>::from_iter(entries); }",
            "fn f(entries: std::fs::ReadDir) { std::vec::Vec::<_>::from_iter(entries); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::FromIterator::from_iter(entries); }",
            "fn f(entries: std::fs::ReadDir) { let mut data = Vec::new(); data.extend(entries); }",
            "fn f(entries: std::fs::ReadDir) { entries.custom_operation(); }",
            "fn f(entries: std::fs::ReadDir) { (|value: std::fs::ReadDir| value)(entries); }",
            "fn f(entries: std::fs::ReadDir) { custom(entries.map(|entry| entry)); }",
            "trait Access { fn unwrap(self) -> usize; } impl Access for std::fs::ReadDir { fn unwrap(self) -> usize { self.count() } } fn f(entries: std::fs::ReadDir) { entries.unwrap(); }",
            "trait Access { fn expect(self, message: &str) -> usize; } impl Access for std::fs::ReadDir { fn expect(self, message: &str) -> usize { self.count() } } fn f(entries: std::fs::ReadDir) { entries.expect(\"x\"); }",
            "trait Access { fn as_ref(&mut self) -> bool; } impl Access for std::fs::ReadDir { fn as_ref(&mut self) -> bool { self.next().is_some() } } fn f(mut entries: std::fs::ReadDir) { entries.as_ref(); }",
            "trait Access { fn as_mut(&mut self) -> bool; } impl Access for std::fs::ReadDir { fn as_mut(&mut self) -> bool { self.next().is_some() } } fn f(mut entries: std::fs::ReadDir) { entries.as_mut(); }",
            "struct Result<T> { inner: T } impl<T> Result<T> { fn unwrap(self) -> T { self.inner } } fn f(entries: Result<std::fs::ReadDir>) { entries.unwrap(); }",
            "fn f(entries: std::io::Result<std::fs::ReadDir>) { for entry in entries {} }",
            "fn f(entries: std::io::Result<core::option::Option<std::fs::ReadDir>>) { entries.unwrap().unwrap().next(); }",
            "fn f(entries: std::fs::ReadDir) { Some(entries); }",
            "fn f(entries: std::fs::ReadDir) { Ok::<_, ()>(entries); }",
            "fn Some(entries: std::fs::ReadDir) -> usize { entries.count() } fn f(entries: std::fs::ReadDir) { Some(entries); }",
        ] {
            let directory = fixture(source);
            let error = inventory(directory.path()).unwrap_err().to_string();
            assert!(error.contains("unresolved ReadDir handoffs or iterator calls"), "{source}: {error}");
        }
        assert!(scan("trait Iterator { fn next(value: u32); } fn f() { Iterator::next(7); }").is_empty());
        for source in [
            "fn f() -> std::io::Result<()> { let mut entries = std::fs::read_dir(\".\")?; entries.next(); Ok(()) }",
            "fn f(path: &std::path::Path) { let mut entries = path.read_dir().expect(\"directory\"); entries.next(); }",
            "fn f(path: &std::path::Path) { if let Ok(entries) = std::fs::read_dir(path) { for entry in entries.flatten() {} } }",
            "fn f(path: &std::path::Path) { if let core::result::Result::Ok(mut entries) = path.read_dir() { entries.next(); } }",
            "use core::result::Result::Ok as Accepted; fn f(path: &std::path::Path) { if let Accepted(mut entries) = path.read_dir() { entries.next(); } }",
            "fn f(path: &std::path::Path) -> std::io::Result<()> { let mut entries: std::fs::ReadDir = match std::fs::read_dir(path) { Ok(entries) => entries, Err(error) => return Err(error).context(\"list source\"), }; entries.next(); Ok(()) }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 2, "{source}: {findings:?}");
            assert!(findings.iter().any(|finding| finding.target == "std::fs::ReadDir::next" && finding.count == 1));
        }
        for source in [
            "fn f(entries: core::option::Option<std::fs::ReadDir>) { if let Some(mut entries) = entries { entries.next(); } }",
            "fn f(entries: core::option::Option<std::fs::ReadDir>) { if let core::option::Option::Some(entries) = entries { for entry in entries {} } }",
            "fn f(entries: std::io::Result<std::fs::ReadDir>) { if let Err(error) = entries { helper(error); } }",
        ] {
            let findings = scan(source);
            let expected = usize::from(!source.contains("if let Err"));
            assert_eq!(findings.len(), expected, "{source}: {findings:?}");
            if expected == 1 { assert_eq!(findings[0].target, "std::fs::ReadDir::next"); }
        }
        // Use the actual owning source function rather than a second template
        // for its IO/error path. Only its real canonical imports are scaffolded.
        let actual = syn::parse_file(include_str!("architecture.rs")).unwrap();
        let collector = actual.items.into_iter().find(|item| {
            matches!(item, Item::Fn(function) if function.sig.ident == "collect_sources")
        }).unwrap();
        let mut owning = syn::parse_file("use std::{fs, path::Path}; use anyhow::{Context, Result, ensure};").unwrap();
        owning.items.push(collector);
        let findings = scan_syntax(owning);
        let counts = findings.iter().map(|finding| (finding.target.as_str(), finding.count)).collect::<BTreeMap<_, _>>();
        assert_eq!(counts, BTreeMap::from([
            ("std::fs::symlink_metadata", 1usize), ("std::fs::read_dir", 1), ("std::fs::ReadDir::next", 1),
        ]), "{findings:?}");
        // Alternate target field definitions cannot erase a known wrapper or
        // unsupported-container marker before the supported Unix operation.
        for (native_type, operation) in [
            ("std::io::Result<std::fs::ReadDir>", "holder.entries.as_mut().unwrap().next()"),
            ("core::option::Option<std::fs::ReadDir>", "holder.entries.as_mut().unwrap().next()"),
        ] {
            for native_first in [false, true] {
                let native = format!("#[cfg(unix)] struct Holder {{ entries: {native_type} }}");
                let pure = "#[cfg(not(unix))] struct Holder { entries: u32 }";
                let definitions = if native_first { format!("{native} {pure}") } else { format!("{pure} {native}") };
                let source = format!("{definitions} fn f(mut holder: Holder) {{ #[cfg(unix)] {operation}; }}");
                let findings = scan(&source);
                assert_eq!(findings.len(), 2, "{source}: {findings:?}");
                assert!(findings.iter().any(|finding| finding.kind == "effect-field-conflict" && finding.target == "Holder"));
                assert!(findings.iter().any(|finding| finding.target == "std::fs::ReadDir::next" && finding.count == 1));
            }
        }
        for source in [
            "struct Wrap<T> { inner: T } fn f(entries: Wrap<std::fs::ReadDir>) { entries.drain(); }",
            "struct Wrap<T> { inner: T } fn f(value: Wrap<std::fs::ReadDir>) { let Wrap { inner: mut entries } = value; entries.next(); }",
            "struct Wrap<T> { inner: T } fn f(Wrap { inner: mut entries }: Wrap<std::fs::ReadDir>) { entries.next(); }",
            "struct Wrap<T> { inner: T } fn f(value: Wrap<std::fs::ReadDir>) { let Wrap { inner } = value; helper(inner); }",
            "struct Wrap<T> { inner: T } fn f(mut value: Wrap<std::fs::ReadDir>) { let Wrap { ref mut inner } = value; inner.next(); }",
            "struct Wrap<T> { inner: T, flag: bool } fn f(value: Wrap<std::fs::ReadDir>) { let Wrap { inner, .. } = value; helper(inner); }",
            "struct Wrap<T> { inner: T } fn f(mut value: Wrap<std::fs::ReadDir>) { value.inner.next(); }",
            "struct Wrap<T> { inner: T } fn f(value: Wrap<std::fs::ReadDir>) { helper(value.inner); }",
            "fn f(entries: [std::fs::ReadDir; 1]) { drain(entries); }",
            "fn f(entries: (std::fs::ReadDir,)) { drain(entries); }",
            "fn f(entries: &[std::fs::ReadDir]) { drain(entries); }",
            "fn f(value: (std::fs::ReadDir,)) { let (mut entries,) = value; entries.next(); }",
            "fn f(value: (std::fs::ReadDir, u32)) { let (mut entries, _) = value; entries.next(); }",
            "fn f((mut entries, _): (std::fs::ReadDir, u32)) { entries.next(); }",
            "fn f(value: [std::fs::ReadDir; 1]) { let [mut entries] = value; entries.next(); }",
            "fn f([mut entries]: [std::fs::ReadDir; 1]) { entries.next(); }",
            "fn f(value: &mut [std::fs::ReadDir]) { if let [entries] = value { entries.next(); } }",
            "fn f(value: &mut [std::fs::ReadDir; 1]) { value[0].next(); }",
            "fn f(value: &mut (std::fs::ReadDir, u32)) { value.0.next(); }",
            "fn f(entries: core::result::Result<(), std::fs::ReadDir>) { if let Err(mut entries) = entries { entries.next(); } }",
            "fn f(a: std::fs::ReadDir, b: std::fs::ReadDir) { let mut out = a.fold(b, |acc, _| acc); out.next(); }",
            "fn f(a: std::fs::ReadDir, b: std::fs::ReadDir) { let mut out = core::iter::Iterator::fold(a, b, |acc, _| acc); out.next(); }",
            "fn f(a: std::fs::ReadDir, b: std::fs::ReadDir) { a.custom_operation(b); }",
            "fn f(result: std::io::Result<std::fs::ReadDir>, entries: std::fs::ReadDir) { result.chain(entries); }",
            "fn f(result: std::io::Result<std::fs::ReadDir>, entries: std::fs::ReadDir) { core::iter::Iterator::chain(result, entries); }",
            "struct Sink; impl Sink { fn chain(&self, entries: std::fs::ReadDir) -> usize { entries.count() } } fn f(entries: std::fs::ReadDir) { Sink.chain(entries); }",
            "struct Sink; fn f(sink: Sink, entries: std::fs::ReadDir) { sink.zip(entries); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::empty().chain(entries).next(); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::repeat(()).zip(entries).next(); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::Iterator::chain(core::iter::empty(), entries).next(); }",
            "fn f(entries: std::fs::ReadDir) { core::iter::Iterator::zip(core::iter::repeat(()), entries).next(); }",
            "struct Sink; impl Iterator for Sink { type Item = std::io::Result<std::fs::DirEntry>; fn next(&mut self) -> Option<Self::Item> { None } fn chain<U>(self, other: U) -> std::iter::Chain<Self, U::IntoIter> where Self: Sized, U: IntoIterator<Item = Self::Item> { other.into_iter().count(); panic!(\"advanced\") } } fn f(entries: std::fs::ReadDir) { core::iter::Iterator::chain(Sink, entries); }",
            "fn f(entries: std::fs::ReadDir) { std::fs::ReadDir::chain(core::iter::empty(), entries).next(); }",
            "struct Ok(std::fs::ReadDir); fn f(entries: std::io::Result<std::fs::ReadDir>) { if let Ok(mut entries) = entries { entries.next(); } }",
            "#[cfg(unix)] use core::result::Result::Ok; fn f(entries: std::io::Result<std::fs::ReadDir>) { if let Ok(mut entries) = entries { entries.next(); } }",
            "use super::Ok; fn f(entries: std::io::Result<std::fs::ReadDir>) { if let Ok(mut entries) = entries { entries.next(); } }",
            "#[cfg(unix)] struct Holder { entries: Wrap<std::fs::ReadDir> } #[cfg(not(unix))] struct Holder { entries: u32 } fn f(holder: Holder) { #[cfg(unix)] holder.entries.drain(); }",
            "#[cfg(unix)] struct Holder { entries: [std::fs::ReadDir; 1] } #[cfg(not(unix))] struct Holder { entries: u32 } fn f(holder: Holder) { #[cfg(unix)] drain(holder.entries); }",
        ] {
            let directory = fixture(source);
            let error = inventory(directory.path()).unwrap_err().to_string();
            assert!(error.contains("unresolved ReadDir handoffs or iterator calls"), "{source}: {error}");
        }
        for source in [
            "struct Wrap<T> { inner: T } fn f(entries: Wrap<u32>) { entries.drain(); }",
            "struct Wrap<T> { inner: T } fn f(value: Wrap<u32>) { let Wrap { inner: number } = value; helper(number); }",
            "struct Wrap<T> { inner: T } fn f(Wrap { inner: number }: Wrap<u32>) { helper(number); }",
            "struct Wrap<T> { inner: T } fn f(mut value: Wrap<u32>) { let Wrap { ref mut inner } = value; helper(inner); }",
            "struct Wrap<T> { inner: T, flag: bool } fn f(value: Wrap<u32>) { let Wrap { inner, .. } = value; helper(inner); }",
            "struct Wrap<T> { inner: T } fn f(value: Wrap<u32>) { helper(value.inner); }",
            "fn f(entries: [u32; 1], tuple: (u32,), slice: &[u32]) { helper(entries); helper(tuple); helper(slice); }",
            "fn f(value: (u32, u32)) { let (number, _) = value; helper(number); }",
            "fn f(value: [u32; 1]) { let [number] = value; helper(number); }",
            "fn f(value: &[u32]) { if let [number] = value { helper(number); } }",
            "fn f(value: &mut [u32; 1]) { helper(value[0]); }",
            "struct Sink; fn f(sink: Sink) { sink.chain([0]); sink.zip([0]); }",
            "fn f(entries: std::fs::ReadDir) { std::fs::ReadDir::size_hint(&entries); }",
        ] {
            assert!(scan(source).is_empty(), "{source}");
        }
        for source in [
            "struct Holder { entries: std::fs::ReadDir, count: u32 } fn f(value: Holder) { let Holder { entries: mut selected, count } = value; selected.next(); helper(count); }",
            "struct Holder { entries: std::fs::ReadDir } fn f(Holder { entries: mut selected }: Holder) { selected.next(); }",
            "struct Holder { entries: std::fs::ReadDir } fn f(mut value: Holder) { let Holder { ref mut entries } = value; entries.next(); }",
        ] {
            let findings = scan(source);
            assert_eq!(findings.len(), 1, "{source}: {findings:?}");
            assert_eq!(findings[0].target, "std::fs::ReadDir::next", "{source}: {findings:?}");
            assert_eq!(findings[0].count, 1);
        }
        for source in [
            "fn f(path: &std::path::Path) { helper(path.components()); helper(path.iter()); }",
            "fn f(mut entries: std::fs::ReadDir) { helper(entries.next()); }",
            "fn f(entries: std::fs::ReadDir) { helper(entries.count()); }",
            "fn f(entries: std::fs::ReadDir) { let data = entries.collect::<Vec<_>>(); helper(data); }",
            "fn f(entries: std::fs::ReadDir) { let hint = entries.size_hint(); helper(hint); }",
        ] {
            let findings = scan(source);
            let expected = usize::from(source.contains("entries.next()") || source.contains("entries.count()") || source.contains("entries.collect"));
            assert_eq!(findings.len(), expected, "{source}: {findings:?}");
        }
        let directory = fixture("pub fn f(entries: std::fs::ReadDir) { for entry in entries {} }");
        let error = check(directory.path()).unwrap_err().to_string();
        assert!(error.contains("unreviewed filesystem") && error.contains("std::fs::ReadDir::next"), "{error}");
    }

    #[test]
    fn new_path_effects_refuse_an_empty_reviewed_contract_surface() {
        // These are the actual strict-contract counterexample source shapes.
        // The strict dependency guard rejects any collected finding; this
        // fixture additionally proves ordinary reviewed-empty source admission
        // refuses them. It does not replace an actual compiler/Clippy canary.
        for (source, target) in [
            ("pub fn path_present(value: &str) -> bool { std::path::Path::new(value).exists() }", "std::path::Path::exists"),
            ("pub fn resolve(value: &str) -> std::io::Result<std::path::PathBuf> { std::path::Path::new(value).canonicalize() }", "std::path::Path::canonicalize"),
            ("pub fn open_input(value: &str) -> rustix::io::Result<rustix::fd::OwnedFd> { rustix::fs::open(value, rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty()) }", "rustix::fs::open"),
        ] {
            let directory = fixture("pub fn pure(value: &str) -> usize { value.len() }");
            let rules = reviewed(&inventory(directory.path()).unwrap());
            assert!(rules.allowances.is_empty());
            fs::write(directory.path().join(RULES_FILE), serde_json::to_vec(&rules).unwrap()).unwrap();
            fs::write(directory.path().join("crates/fixture/src/lib.rs"), source).unwrap();
            let actual = inventory(directory.path()).unwrap();
            assert_eq!(actual.findings.len(), 1, "{source}: {actual:?}");
            assert_eq!(actual.findings[0].target, target, "{source}: {actual:?}");
            let error = check(directory.path()).unwrap_err().to_string();
            assert!(error.contains("unreviewed filesystem") && error.contains(target), "{source}: {error}");
        }
        for method in ["exists", "try_exists", "is_file", "is_dir", "is_symlink",
            "metadata", "symlink_metadata", "canonicalize", "read_link", "read_dir"] {
            let directory = fixture("pub fn pure(value: &str) -> usize { value.len() }");
            let rules = reviewed(&inventory(directory.path()).unwrap());
            fs::write(directory.path().join(RULES_FILE), serde_json::to_vec(&rules).unwrap()).unwrap();
            let source = format!("pub fn filesystem_fact(path: &std::path::Path) {{ path.{method}(); }}");
            fs::write(directory.path().join("crates/fixture/src/lib.rs"), &source).unwrap();
            let error = check(directory.path()).unwrap_err().to_string();
            assert!(error.contains("unreviewed filesystem") && error.contains(&format!("std::path::Path::{method}")), "{source}: {error}");
        }
        let directory = fixture("pub fn pure(value: &str) -> usize { value.len() }");
        let rules = reviewed(&inventory(directory.path()).unwrap());
        fs::write(directory.path().join(RULES_FILE), serde_json::to_vec(&rules).unwrap()).unwrap();
        fs::write(directory.path().join("crates/fixture/src/lib.rs"), "pub fn current_directory_fact() { std::path::absolute(\"relative\"); }").unwrap();
        let error = check(directory.path()).unwrap_err().to_string();
        assert!(error.contains("unreviewed environment") && error.contains("std::path::absolute"), "{error}");
    }

    fn scan_syntax(syntax: syn::File) -> Vec<Finding> {
        let parsed = BTreeMap::from([("crates/fixture/src/lib.rs".to_owned(), syntax)]);
        require_canonical_html_crate(&parsed, &BTreeSet::new()).unwrap();
        let ambient_names = ambient_import_names(&parsed, &BTreeSet::new()).unwrap();
        let mut findings = BTreeMap::new();
        let mut scanner = Scanner::new("crates/fixture/src/lib.rs", &mut findings, &ambient_names);
        scanner.visit_file(&parsed["crates/fixture/src/lib.rs"]);
        scanner.require_resolved_parent_effects().unwrap();
        findings.into_values().collect()
    }

    fn fixture(source: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("crates/fixture/src")).unwrap();
        fs::write(directory.path().join("crates/fixture/src/lib.rs"), source).unwrap();
        directory
    }

    #[test]
    fn raw_paths_keep_canonical_targets_and_authored_fingerprints() {
        let findings = scan(r#"
            fn f() {
                std::time::Instant::r#now();
                r#std::r#time::r#Instant::now();
                r#tokio::time::r#sleep(std::time::Duration::ZERO);
                time::OffsetDateTime::r#now_utc();
                chrono::r#Utc::r#now();
                uuid::r#Uuid::r#new_v4();
                r#std::r#process::r#id();
            }
        "#);
        let mut actual = BTreeMap::new();
        for finding in &findings {
            *actual.entry((finding.kind.as_str(), finding.target.as_str())).or_insert(0usize) += finding.count;
        }
        assert_eq!(actual, BTreeMap::from([
            (("clock", "std::time::Instant::now"), 2usize),
            (("timer", "tokio::time::sleep"), 1),
            (("clock", "time::OffsetDateTime::now_utc"), 1),
            (("clock", "chrono::Utc::now"), 1),
            (("entropy", "uuid::Uuid::new_v4"), 1),
            (("process", "std::process::id"), 1),
        ]), "{findings:?}");

        let ordinary = scan("fn f() { std::time::Instant::now(); }");
        let quoted = scan("fn f() { std::time::Instant::r#now(); }");
        assert_eq!(ordinary.len(), 1);
        assert_eq!(quoted.len(), 1);
        assert_eq!(ordinary[0].target, quoted[0].target);
        assert_eq!(ordinary[0].kind, quoted[0].kind);
        assert_eq!(ordinary[0].count, quoted[0].count);
        assert_ne!(ordinary[0].fingerprint, quoted[0].fingerprint);

        let findings = scan(r#"fn f() {
            opaque!(value => r#std::r#process::r#id());
            json!({"when": r#std::time::Instant::r#now()});
        }"#);
        let actual: BTreeMap<_, _> = findings.iter().map(|finding| (finding.target.as_str(), finding.count)).collect();
        assert_eq!(actual, BTreeMap::from([("std::process::id", 1usize), ("std::time::Instant::now", 1)]), "{findings:?}");

        let findings = scan(r#"use super::*; fn f() {
            ::r#maud::r#html! { div id="literal" data-id=(std::process::r#id()) {} }
        }"#);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].target, "std::process::id");
        assert_eq!(findings[0].count, 1);
    }

    #[test]
    fn raw_imports_bindings_and_members_share_rust_identity() {
        let findings = scan(r#"
            use r#std::{r#time::r#Instant as r#Clock, r#fs::r#File as r#Disk};
            struct r#Holder { r#file: Disk }
            fn f(holder: &Holder) {
                Clock::r#now();
                holder.file.r#metadata();
                let r#read = r#std::fs::r#read;
                read("a"); r#read("b");
            }
        "#);
        let mut actual = BTreeMap::new();
        for finding in &findings {
            *actual.entry(finding.target.as_str()).or_insert(0usize) += finding.count;
        }
        assert_eq!(actual, BTreeMap::from([
            ("std::time::Instant::now", 1usize),
            ("std::fs::File::metadata", 1),
            ("std::fs::read", 3),
        ]), "{findings:?}");

        let findings = scan("extern crate r#getrandom as r#entropy;
            fn f() { entropy::r#fill(&mut [0; 8]); }");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].target, "getrandom::fill");
        assert_eq!(findings[0].count, 1);

        let findings = scan("const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
            mod child { use super::*; fn r#CLOCK() {} type CLOCK = u32; fn f() { CLOCK(); } }");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].target, "std::time::Instant::now");
        assert_eq!(findings[0].context, "CLOCK");

        for source in [
            r#"use std::fs::read;
                fn f() -> Result<(), E> {
                    let r#read = std::fs::r#read("a")?;
                    json!({"a": read, "b": r#read}); Ok(())
                }"#,
            r#"use std::process::r#id;
                fn f() {
                    let r#id = 7;
                    { use std::process::id; id(); }
                    json!({"id": id});
                }"#,
            r#"fn f() {
                    let r#Client = std::time::Instant::r#now;
                    { use reqwest::r#Client; Client(); }
                }"#,
        ] {
            let findings = scan(source);
            let (target, expected) = if source.contains("fs::") {
                ("std::fs::read", 1usize)
            } else if source.contains("process::") {
                ("std::process::id", 1)
            } else {
                ("std::time::Instant::now", 2)
            };
            assert_eq!(findings.iter().map(|finding| finding.count).sum::<usize>(), expected, "{source}: {findings:?}");
            assert!(findings.iter().all(|finding| finding.target == target), "{source}: {findings:?}");
        }

        for source in [
            r#"use std::fs::metadata as r#metadata;
                struct r#Data { r#random: u8, r#metadata: u8 }
                fn f(d: Data) {
                    json!({"a": d.random, "b": d.r#metadata});
                    let r#id = 7; json!({"id": id});
                }"#,
            r#"fn f(input: &str) {
                time::r#Date::r#parse(input, FORMAT);
                time::OffsetDateTime::r#parse(input, &time::format_description::well_known::Rfc3339);
            }"#,
        ] {
            assert!(scan(source).is_empty(), "{source}");
        }
    }

    #[test]
    fn raw_parent_and_conditional_names_preserve_closed_refusal() {
        for source in [
            "use super::*; fn f() { r#id(); }",
            "use super::*; fn f() { let (r#id, _) = helper(); opaque!(value => id()); }",
            "use super::*; #[r#cfg(unix)] use std::time::Instant as r#CLOCK;
                #[cfg(not(unix))] use crate::pure::CLOCK; fn f() { CLOCK::r#now(); }",
        ] {
            let error = match inventory(fixture(source).path()) {
                Err(error) => error.to_string(),
                Ok(actual) => panic!("raw identifier bypassed closed parent checks: {source}: {actual:?}"),
            };
            assert!(error.contains("unresolved parent ambient imports"), "{source}: {error}");
        }
        for source in [
            "fn f() { super::r#id(); }",
            "use super::r#CLOCK; fn f() { CLOCK::r#now(); }",
            "use super::r#CLOCK; fn r#CLOCK() {} fn f() { CLOCK::r#now(); }",
        ] {
            let directory = fixture("use std::time::Instant as r#CLOCK; mod child;");
            fs::write(directory.path().join("crates/fixture/src/child.rs"), source).unwrap();
            let error = match inventory(directory.path()) {
                Err(error) => error.to_string(),
                Ok(actual) => panic!("raw parent alias bypassed closed checks: {source}: {actual:?}"),
            };
            assert!(error.contains("unresolved parent ambient imports"), "{source}: {error}");
        }
        let source = "use super::r#CLOCK; fn f() { CLOCK(); }";
        let directory = fixture("type r#Clock = fn() -> std::time::Instant;
            const r#FIRST: Clock = std::time::Instant::r#now;
            const CLOCK: r#Clock = FIRST; mod child;");
        fs::write(directory.path().join("crates/fixture/src/child.rs"), source).unwrap();
        let error = match inventory(directory.path()) {
            Err(error) => error.to_string(),
            Ok(actual) => panic!("raw constant alias bypassed closed checks: {source}: {actual:?}"),
        };
        assert!(error.contains("unresolved parent ambient imports"), "{source}: {error}");
        for source in [
            "fn f() -> Result<(), E> {
                #[r#cfg(unix)] let r#file = std::fs::r#File::r#open(\"a\")?;
                file.r#metadata(); Ok(())
            }",
            "fn f() {
                #[r#cfg_attr(unix, r#allow(dead_code))]
                let r#spawn = std::process::r#Command::r#new(\"a\");
                spawn.r#spawn();
            }",
        ] {
            let error = match inventory(fixture(source).path()) {
                Err(error) => error.to_string(),
                Ok(actual) => panic!("raw conditional owner bypassed refusal: {source}: {actual:?}"),
            };
            assert!(error.contains("conditional ambient local bindings"), "{source}: {error}");
        }
    }

    #[test]
    fn raw_cfg_and_module_names_preserve_the_production_graph() {
        let directory = fixture("#[r#cfg(r#test)] mod r#tests; fn production() {}");
        fs::write(directory.path().join("crates/fixture/src/tests.rs"),
            "extern crate custom as maud; fn fixture() { std::time::Instant::now(); }").unwrap();
        let actual = inventory(directory.path()).unwrap();
        assert_eq!(actual.sources, vec!["crates/fixture/src/lib.rs", "crates/fixture/src/tests.rs"]);
        assert!(actual.findings.is_empty(), "{actual:?}");

        let findings = scan(r#"
            #[r#cfg(r#test)] fn fixture() { std::time::Instant::r#now(); }
            #[r#cfg_attr(r#not(r#test), r#cfg(r#test))]
            fn also_fixture() { std::process::r#id(); }
            fn production() {
                #[r#cfg(r#test)] { std::time::Instant::r#now(); }
            }
        "#);
        assert!(findings.is_empty(), "{findings:?}");

        let findings = scan(r#"
            #[r#allow(dead_code)] fn first() {}
            #[r#cfg_attr(r#not(r#test), r#expect(dead_code))] fn second() {}
        "#);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(findings.iter().all(|finding| finding.kind == "lint-suppression" && finding.count == 1), "{findings:?}");
        assert_eq!(findings.iter().map(|finding| finding.target.as_str()).collect::<BTreeSet<_>>(), BTreeSet::from(["allow", "expect"]));
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

    fn parent_fixture(child: &str) -> tempfile::TempDir {
        let directory = fixture(
            "use std::{fs, fs as disk, fs::File, process::Command, process::Command as Spawn}; mod child;",
        );
        fs::write(directory.path().join("crates/fixture/src/child.rs"), child).unwrap();
        directory
    }

    #[test]
    fn parent_globs_reject_hidden_filesystem_and_process_names() {
        for child in [
            "use super::*; fn f() { fs::read(\"input\"); }",
            "use super::*; fn f() { Command::new(\"tool\"); }",
            "use super::*; struct Holder { file: File }",
        ] {
            let directory = parent_fixture(child);
            let error = inventory(directory.path()).unwrap_err().to_string();
            assert!(
                error.contains("unresolved parent ambient imports"),
                "{error}"
            );
            assert!(error.contains("crates/fixture/src/child.rs"), "{error}");
        }
        let directory = fixture("use std::fs::*; mod child;");
        fs::write(
            directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { read(\"input\"); }",
        )
        .unwrap();
        assert!(
            inventory(directory.path())
                .unwrap_err()
                .to_string()
                .contains("unresolved parent ambient imports")
        );
        fs::write(
            directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { let read = read; read(\"input\"); }",
        )
        .unwrap();
        assert!(
            inventory(directory.path())
                .unwrap_err()
                .to_string()
                .contains("unresolved parent ambient imports")
        );
    }

    #[test]
    fn renamed_parent_effects_and_reentry_require_canonical_imports() {
        for child in [
            "use super::*; fn f() { disk::read(\"input\"); }",
            "use super::*; fn f() { Spawn::new(\"tool\"); }",
            "use super::disk as files; fn f() { files::read(\"input\"); }",
            "use super::Spawn as Run; fn f() { Run::new(\"tool\"); }",
            "use files as Local; use super::disk as files; fn f() { Local::read(\"input\"); }",
            "fn f() { super::Spawn::new(\"tool\"); }",
            "struct Spawn; fn f() { super::Spawn::new(\"tool\"); }",
            "use std::process::Command as Spawn; fn f() { super::Spawn::new(\"tool\"); }",
            "fn f() { use super::*; let call = disk::read; call(\"input\"); }",
            "use super::*; fn f() { opaque!(otherwise => disk::read(\"input\")); }",
        ] {
            let directory = parent_fixture(child);
            let error = inventory(directory.path()).unwrap_err().to_string();
            assert!(
                error.contains("unresolved parent ambient imports"),
                "{child}: {error}"
            );
        }
    }

    #[test]
    fn explicit_ambient_imports_keep_globs_and_effect_review() {
        let directory = parent_fixture(
            "use super::*; use std::{fs as disk, process::Command as Spawn};
             fn f() { disk::read(\"input\"); Spawn::new(\"tool\"); }",
        );
        let actual = inventory(directory.path()).unwrap();
        for target in ["std::fs::read", "std::process::Command::new"] {
            assert!(actual.findings.iter().any(|finding|
                finding.source.ends_with("child.rs") && finding.target == target), "{target}");
        }
        let rules = reviewed(&actual);
        validate(&rules, &actual).unwrap();
        fs::write(
            directory.path().join(RULES_FILE),
            serde_json::to_vec(&rules).unwrap(),
        )
        .unwrap();
        // Existing allowances cannot bless an unresolved imported effect.
        fs::write(
            directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { disk::read(\"input\"); Spawn::new(\"tool\"); }",
        )
        .unwrap();
        assert!(
            check(directory.path())
                .unwrap_err()
                .to_string()
                .contains("unresolved parent ambient imports")
        );

        for child in [
            "use super::*; fn f() { std::fs::read(\"input\"); std::process::Command::new(\"tool\"); }",
            "use super::*; #[cfg(not(test))] use std::fs as disk; fn f() { disk::read(\"input\"); }",
            "#[cfg(unix)] use std::fs as disk; fn f() { disk::read(\"input\"); }",
        ] {
            let directory = parent_fixture(child);
            assert!(
                inventory(directory.path())
                    .unwrap()
                    .findings
                    .iter()
                    .any(|finding| finding.source.ends_with("child.rs")
                        && finding.target == "std::fs::read")
            );
        }
    }

    #[test]
    fn benign_parent_globs_local_declarations_and_wrappers_remain_inventoryable() {
        let directory = fixture(
            "struct Domain; mod ports { pub struct Command; impl Command { pub fn new() {} } pub fn read() {} }
             mod child;",
        );
        fs::write(directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; use crate::ports::{self as fs, Command};
             struct File; struct Instant; fn read() {}
             fn f(_: Domain, _: File, _: Instant) { read(); fs::read(); Command::new(); let _ = \"disk::read\"; }").unwrap();
        let actual = inventory(directory.path()).unwrap();
        assert!(actual.findings.is_empty(), "{:?}", actual.findings);
    }

    fn http_name_fixture(child: &str) -> tempfile::TempDir {
        let directory = fixture(
            "use reqwest::{Body, Response, Response as Reply, StatusCode, header::{self, HeaderMap}};
             use std::fs as disk; mod child;",
        );
        fs::write(directory.path().join("crates/fixture/src/child.rs"), child).unwrap();
        directory
    }

    #[test]
    fn explicit_opaque_named_imports_shadow_parent_http_names() {
        for child in [
            "use super::*;
             use axum::{body::Body, http::{HeaderMap, StatusCode, header}, response::Response};
             fn f(_: Body, _: HeaderMap, _: StatusCode, _: Response) { let _ = header::LOCATION; }",
            "use super::*; use axum::response::Response as Reply;
             fn f(_: Reply) {}",
            "use super::*; fn f(_: Response) {} use axum::response::Response;",
            "use super::*; fn f() {
                 use axum::response::Response; let value: Option<Response> = None;
             }",
        ] {
            let actual = inventory(http_name_fixture(child).path()).unwrap();
            assert!(actual.findings.is_empty(), "{child}: {:?}", actual.findings);
        }
    }

    #[test]
    fn removing_or_globbing_opaque_imports_keeps_parent_refusal() {
        for child in [
            "use super::*; fn f(_: Body) {}",
            "use super::*; fn f(_: HeaderMap) {}",
            "use super::*; fn f(_: StatusCode) {}",
            "use super::*; fn f(_: Response) {}",
            "use super::*; fn f() { let _ = header::LOCATION; }",
            "use super::*; use axum::http::*; fn f(_: HeaderMap) {}",
            "use super::*; fn f() { { use axum::response::Response; } let _: Option<Response> = None; }",
        ] {
            let error = inventory(http_name_fixture(child).path())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("unresolved parent ambient imports"),
                "{child}: {error}"
            );
        }
    }

    #[test]
    fn opaque_named_imports_do_not_bless_parent_or_conditional_aliases() {
        for child in [
            "use super::Response; fn f(_: Response) {}",
            "use super::Response as Reply; fn f(_: Reply) {}",
            "use super::*; use axum::response::Response; fn f(_: super::Response) {}",
            "use super::*; use self::Response as Reply; fn f(_: Reply) {}",
            "use super::*; use disk::metadata as Response; fn f() { Response(\"input\"); }",
            "use super::*; #[cfg(unix)] use axum::response::Response; fn f(_: Response) {}",
            "use super::*; #[cfg(unix)] use axum::response::Response;
             #[cfg(windows)] use other::Response; fn f(_: Response) {}",
            "use super::*; use external::response::Response;
             #[cfg(unix)] use axum as external; fn f(_: Response) {}",
            "use super::disk as external; use external::metadata as Response;
             fn f() { Response(\"input\"); }",
            "use super::*; use axum::response::Response;
             fn f() { let (Response, _) = helper(); Response(); }",
        ] {
            let error = inventory(http_name_fixture(child).path())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("unresolved parent ambient imports"),
                "{child}: {error}"
            );
        }
    }

    #[test]
    fn opaque_namespace_shadows_keep_exact_ambient_call_findings() {
        let actual = inventory(
            http_name_fixture(
                "use super::*;
             use axum::response::Response;
             use std::{fs as disk, time::Instant};
             use time::OffsetDateTime; use getrandom::fill; use reqwest::blocking::Client;
             fn f(_: Response, bytes: &mut [u8]) {
                 disk::metadata(\"input\"); Instant::now(); OffsetDateTime::now_utc();
                 fill(bytes); Client::new().get(\"https://example.invalid\").send();
             }",
            )
            .path(),
        )
        .unwrap();
        // Compare semantic calls in f, not import metadata or AST fingerprints.
        // In particular, both Client construction and its eventual send count.
        let mut calls = BTreeMap::new();
        for finding in actual
            .findings
            .iter()
            .filter(|finding| finding.source.ends_with("child.rs") && finding.context == "f")
        {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        let expected = BTreeMap::from([
            (("filesystem", "std::fs::metadata"), 1usize),
            (("clock", "std::time::Instant::now"), 1),
            (("clock", "time::OffsetDateTime::now_utc"), 1),
            (("entropy", "getrandom::fill"), 1),
            (("network", "reqwest::blocking::Client::new"), 1),
            (("network", "reqwest::blocking::Client::send"), 1),
        ]);
        assert_eq!(calls, expected, "{:?}", actual.findings);
    }

    #[test]
    fn macro_members_retain_loaded_artifact_receivers() {
        for load in [
            "LoadedArtifact::load",
            "day2::artifact::LoadedArtifact::load",
        ] {
            let directory = fixture(&format!(
                "use super::*; use day2::artifact::LoadedArtifact;
                 fn execute(path: &std::path::Path) {{
                     let loaded = {load}(path)?; let existing = {load}(path)?;
                     json!({{\"artifact\":loaded.id(), \"same\":existing.id() == loaded.id(),
                         \"short\":loaded.id().trim_start_matches(\"sha256:\")}});
                 }}",
            ));
            assert!(inventory(directory.path()).unwrap().findings.is_empty());
        }
    }

    #[test]
    fn macro_call_islands_record_nested_ambient_origins_once() {
        let findings = scan(
            "use super::*;
             use std::{fs::File, process::Command, time::Instant};
             use reqwest::blocking::Client as Http;
             struct Holder { file: File }
             fn f(command: &mut Command, holder: &Holder, http: &Http) {
                 opaque!(branch => {\"id\":std::process::id(), \"spawn\":command.spawn(),
                     \"metadata\":holder.file.metadata(),
                     \"nested\":accept(Instant::now(), http.get(\"https://example.invalid\").send())});
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in findings.iter().filter(|finding| finding.context == "f") {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("process", "std::process::id"), 1usize),
                (("process", "std::process::Command::spawn"), 1),
                (("filesystem", "std::fs::File::metadata"), 1),
                (("clock", "std::time::Instant::now"), 1),
                (("network", "reqwest::blocking::Client::send"), 1),
            ]),
            "{findings:?}"
        );
    }

    #[test]
    fn macro_call_islands_keep_parent_and_unknown_callable_refusal() {
        for source in [
            "use super::*; fn f() { opaque!(branch => id()); }",
            "fn f() { opaque!(branch => super::id()); }",
            "use super::*; fn f() { let (id, _) = helper(); opaque!(branch => id()); }",
            "use super::*; fn f() { let (id, _) = helper(); opaque!(branch => (id)()); }",
            "use super::*; struct Data { id: fn() }
             fn f(value: Data) { opaque!(branch => (value.id)()); }",
        ] {
            let error = inventory(fixture(source).path()).unwrap_err().to_string();
            assert!(
                error.contains("unresolved parent ambient imports"),
                "{source}: {error}"
            );
        }
        // Only an absolute qualified external Maud macro may distinguish
        // literal attribute labels from executable Rust input.
        for source in [
            "use super::*; fn f() {
                 ::maud::html! { div id=\"x\" data-id=\"y\" xml:id=\"z\" { div id=\"inner\" {} } }
             }",
            "use super::*; fn f() { ::maud::html! { div id=\"x\" {} } }",
            "use super::*; macro_rules! html { () => {} }
             fn f() { ::maud::html! { div id=\"x\" {} } }",
            "use super::*; extern crate maud; fn f() { ::maud::html! { div id=\"x\" {} } }",
            "use super::*; extern crate r#maud; fn f() { ::maud::html! { div id=\"x\" {} } }",
            "use super::*; #[cfg(test)] extern crate custom as maud;
             fn f() { ::maud::html! { div id=\"x\" {} } }",
            "use super::*; struct Holder; impl Holder {
                 #[cfg(test)] fn fixture() { extern crate custom as maud; }
             } fn f() { ::maud::html! { div id=\"x\" {} } }",
            "use super::*; trait Holder {
                 #[cfg(test)] fn fixture() { extern crate custom as maud; }
             } fn f() { ::maud::html! { div id=\"x\" {} } }",
        ] {
            let actual = inventory(fixture(source).path()).unwrap_or_else(|error| panic!("{source}: {error}"));
            assert!(actual.findings.is_empty(), "{source}: {:?}", actual.findings);
        }
        for source in [
            "use super::*; fn f() { opaque! { div id=\"x\" {} } }",
            "use super::*; use maud::html; fn f() { html! { div id=\"x\" {} } }",
            "use super::*; use ::maud::html; fn f() { html! { div id=\"x\" {} } }",
            "use super::*; use ::maud::html as render; fn f() { render! { div id=\"x\" {} } }",
            "use super::*; use ::maud::html; fn f() { use crate::custom::html;
                 html! { div id=\"x\" {} } }",
            "use super::*; #[cfg(unix)] use ::maud::html; fn f() { html! { div id=\"x\" {} } }",
            "use super::*; #[cfg(unix)] use crate::custom::html; #[cfg(not(unix))] use ::maud::html;
                 fn f() { html! { div id=\"x\" {} } }",
            "use super::*; use ::maud::html; fn f() {
                 macro_rules! html { ($($tokens:tt)*) => { () } }
                 html! { div id=\"x\" {} } }",
            "use super::*; mod maud { pub use crate::custom::html; }
                 fn f() { maud::html! { div id=\"x\" {} } }",
            "use super::*; fn f() { ::maud::html! { div id=(id()) {} } }",
            "use super::*; fn f() { ::maud::html! { div id=(super::id()) {} } }",
            "use super::*; fn f() {
                 ::maud::html! { div id=(({ let (id, _) = helper(); id })()) {} } }",
            "use super::*; fn f() {
                 ::maud::html! { div id=(opaque!(branch => id())) {} } }",
            "use super::*; fn f() {
                 ::maud::html! { @if ready { div id=\"x\" {} } } }",
            "use super::*; fn f() { ::maud::html! { div id==\"x\" {} } }",
            "use super::*; fn f() { ::maud::html! { div id=>\"x\" {} } }",
        ] {
            let error = match inventory(fixture(source).path()) {
                Err(error) => error.to_string(),
                Ok(actual) => panic!("unsupported/shadowed markup lost its conservative checks: {source}: {actual:?}"),
            };
            assert!(error.contains("unresolved parent ambient imports"), "{source}: {error}");
        }
        for (source, expected) in [
            ("use super::*; fn f() {
                 ::maud::html! { div id=(std::process::id()) data-id=\"x\" xml:id=\"y\"
                     data-value=[Some(std::process::id())] checked[std::process::id() != 0] {
                         (std::time::Instant::now())
                     }
                 }
             }", BTreeMap::from([("std::process::id", 3usize), ("std::time::Instant::now", 1)])),
            ("use super::*; fn f() {
                 ::maud::html! { div id=({ let callback = std::process::id; callback() }) {} }
             }", BTreeMap::from([("std::process::id", 2)])),
        ] {
            let actual = inventory(fixture(source).path()).unwrap_or_else(|error| panic!("{source}: {error}"));
            let mut calls = BTreeMap::new();
            for finding in &actual.findings {
                *calls.entry(finding.target.as_str()).or_insert(0usize) += finding.count;
            }
            assert_eq!(calls, expected, "markup values must retain exact call/reference counts: {source}: {:?}", actual.findings);
        }
        let direct = scan("fn f() { std::process::id(); }");
        let markup = scan("fn f() { ::maud::html! { div id=(std::process::id()) {} } }");
        assert_eq!(markup, direct, "attribute interpolation keeps the original effect AST/fingerprint");

        for root in ["extern crate custom as maud; mod child;", "extern crate self as maud; mod child;",
            "extern crate custom as r#maud; mod child;", "extern crate self as r#maud; mod child;",
            "#[cfg(unix)] extern crate maud; mod child;", "#[cfg(unix)] extern crate custom as maud; mod child;"] {
            for child in ["use super::*; fn f() { ::maud::html! { div id=\"x\" {} } }",
                "use super::*; use ::maud::html; fn f() { html! { div id=\"x\" {} } }"] {
                let directory = fixture(root);
                fs::write(directory.path().join("crates/fixture/src/child.rs"), child).unwrap();
                let error = inventory(directory.path()).unwrap_err().to_string();
                assert!(error.contains("noncanonical Maud extern-crate binding"), "{root}: {child}: {error}");
            }
        }
        let directory = fixture("macro_rules! html { ($($tokens:tt)*) => { () } } mod child;");
        fs::write(directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; use ::maud::html; fn f() { html! { div id=\"x\" {} } }").unwrap();
        assert!(inventory(directory.path()).unwrap_err().to_string().contains("unresolved parent ambient imports"));
        fs::write(directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { ::maud::html! { div id=\"x\" {} } }").unwrap();
        assert!(inventory(directory.path()).unwrap().findings.is_empty());

        let excluded = fixture("#[cfg(test)] mod tests; mod child;");
        fs::write(excluded.path().join("crates/fixture/src/tests.rs"), "extern crate custom as maud;").unwrap();
        fs::write(excluded.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { ::maud::html! { div id=\"x\" {} } }").unwrap();
        assert!(inventory(excluded.path()).unwrap().findings.is_empty());

        let mut depth = quote::quote! { "literal" };
        for _ in 0..=MAX_ALIAS_ROUNDS { depth = quote::quote! { { #depth } }; }
        assert!(syn::parse2::<HtmlAttributeLabels>(depth).is_err());
        let mut work = proc_macro2::TokenStream::new();
        for _ in 0..MAX_ALIAS_ROUNDS * MAX_ALIAS_ROUNDS {
            work.extend(quote::quote! { div id="x" {} });
        }
        assert!(syn::parse2::<HtmlAttributeLabels>(work).is_err());
    }

    #[test]
    fn macro_function_aliases_and_callable_fields_do_not_erase_provenance() {
        let findings = scan(
            "use super::*; fn f() {
                 let id = std::process::id;
                 opaque!(branch => {\"direct\":id(), \"wrapped\":(id)()});
             }",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.target == "std::process::id")
                .map(|finding| finding.count)
                .sum::<usize>(),
            3,
            "{findings:?}"
        );
        let source = "use super::*; struct Data { id: fn() }
            fn f(value: Data) { (value.id)(); }";
        assert!(
            inventory(fixture(source).path())
                .unwrap_err()
                .to_string()
                .contains("unresolved parent ambient imports")
        );
    }

    #[test]
    fn computed_macro_callees_keep_ambient_value_references() {
        for (callee, count) in [
            ("({std::process::id})", 1),
            ("(if flag {std::process::id} else {std::process::id})", 2),
            (
                "(match flag {true => std::process::id, false => std::process::id})",
                2,
            ),
            ("({consume(std::process::id); callback})", 1),
            ("(choose(std::process::id))", 1),
        ] {
            for expression in [
                format!("json!({{\"pid\":{callee}()}});"),
                format!("{callee}();"),
            ] {
                let findings = scan(&format!(
                    "use super::*; fn f(flag: bool, callback: fn()) {{ {expression} }}",
                ));
                assert_eq!(
                    findings
                        .iter()
                        .filter(|finding| finding.target == "std::process::id")
                        .map(|finding| finding.count)
                        .sum::<usize>(),
                    count,
                    "computed callee must retain every source reference: {expression}: {findings:?}"
                );
            }
        }
    }

    #[test]
    fn returned_unknown_callables_keep_lexical_refusal() {
        for callee in [
            "({id})",
            "({let (id, _) = helper(); id})",
            "(if flag {id} else {id})",
            "(match flag {true => id, false => id})",
            "(match pair {(id, _) => id})",
            "({let (metadata, _) = helper(); metadata.callback})",
        ] {
            for expression in [
                format!("json!({{\"pid\":{callee}()}});"),
                format!("{callee}();"),
            ] {
                let directory = fixture(&format!(
                    "use super::*; fn f(flag: bool) {{ let (id, _) = helper(); let pair = helper(); {expression} }}",
                ));
                let error = inventory(directory.path()).unwrap_err().to_string();
                assert!(
                    error.contains("unresolved parent ambient imports"),
                    "{expression}: {error}"
                );
            }
        }
    }

    #[test]
    fn callable_branch_traversal_preserves_scope_and_unrelated_data() {
        let directory = fixture(
            "use super::*; fn pure() {} fn f(flag: bool, metadata: usize) {
                 json!({\"a\":({let id = pure; id})(),
                     \"b\":(if flag {pure} else {pure})(),
                     \"c\":(match flag {true => pure, false => pure})(),
                     \"d\":({let _ = metadata; pure})()});
             }
             #[cfg(test)] fn excluded() { json!({\"pid\":({let (id, _) = helper(); id})()}); }",
        );
        assert!(inventory(directory.path()).unwrap().findings.is_empty());
    }

    #[test]
    fn result_and_option_callables_keep_unknown_lexical_refusal() {
        for (callee, result, completed) in [
            ("(Ok::<_, ()>(id)?)", "Result<(), ()>", "Ok(())"),
            (
                "(std::result::Result::<_, ()>::Ok(id)?)",
                "Result<(), ()>",
                "Ok(())",
            ),
            ("(Keep::<_, ()>(id)?)", "Result<(), ()>", "Ok(())"),
            ("({Ok::<_, ()>(id)?})", "Result<(), ()>", "Ok(())"),
            (
                "({let (id, _) = helper(); Ok::<_, ()>(id)?})",
                "Result<(), ()>",
                "Ok(())",
            ),
            (
                "({let (metadata, _) = helper(); Ok::<_, ()>(metadata.callback)?})",
                "Result<(), ()>",
                "Ok(())",
            ),
            (
                "(if flag {Ok::<_, ()>(id)?} else {Ok::<_, ()>(id)?})",
                "Result<(), ()>",
                "Ok(())",
            ),
            (
                "(match flag {true => Ok::<_, ()>(id)?, false => Ok::<_, ()>(id)?})",
                "Result<(), ()>",
                "Ok(())",
            ),
            ("(Some(id)?)", "Option<()>", "Some(())"),
            (
                "(core::option::Option::Some(id)?)",
                "Option<()>",
                "Some(())",
            ),
            ("({Some(id)?})", "Option<()>", "Some(())"),
        ] {
            for expression in [
                format!("json!({{\"pid\":{callee}()}});"),
                format!("{callee}();"),
            ] {
                let directory = fixture(&format!(
                    "use super::*; use core::result::Result::Ok as Keep;
                     fn f(flag: bool) -> {result} {{ let (id, _) = helper(); {expression} {completed} }}",
                ));
                let error = inventory(directory.path()).unwrap_err().to_string();
                assert!(
                    error.contains("unresolved parent ambient imports"),
                    "{expression}: {error}"
                );
            }
        }
    }

    #[test]
    fn wrapped_callables_preserve_exact_known_references() {
        for (callee, count) in [
            ("(Ok::<_, ()>(std::process::id)?)", 2),
            ("(core::result::Result::<_, ()>::Ok(std::process::id)?)", 2),
            ("({Ok::<_, ()>(std::process::id)?})", 1),
            (
                "(if flag {Ok::<_, ()>(std::process::id)?} else {Ok::<_, ()>(std::process::id)?})",
                2,
            ),
        ] {
            for expression in [
                format!("json!({{\"pid\":{callee}()}});"),
                format!("{callee}();"),
            ] {
                let findings = scan(&format!(
                    "use super::*; fn f(flag: bool) -> Result<(), ()> {{ {expression} Ok(()) }}",
                ));
                assert_eq!(
                    findings
                        .iter()
                        .filter(|finding| finding.target == "std::process::id")
                        .map(|finding| finding.count)
                        .sum::<usize>(),
                    count,
                    "wrapper must retain its reference and any known outer call: {expression}: {findings:?}"
                );
            }
        }
    }

    #[test]
    fn wrapper_data_and_pure_callables_remain_ordinary() {
        let directory = fixture(
            "use super::*; fn pure() {} fn f(metadata: usize) -> Result<(), ()> {
                 let _ = Ok::<_, ()>(metadata)?;
                 json!({\"a\":(Ok::<_, ()>(pure)?)(),
                     \"b\":({let id = pure; Ok::<_, ()>(id)?})()});
                 Ok(())
             }
             fn optional() -> Option<()> { (Some(pure)?)(); Some(()) }
             #[cfg(test)] fn excluded() -> Result<(), ()> {
                 let (id, _) = helper(); (Ok::<_, ()>(id)?)(); Ok(())
             }",
        );
        assert!(inventory(directory.path()).unwrap().findings.is_empty());
    }

    #[test]
    fn returned_bytes_and_metadata_do_not_repeat_ambient_calls() {
        let findings = scan(
            "use super::*; use std::fs;
             fn f() -> Result<(), Error> {
                 let bytes = fs::read(\"worker\")?;
                 let copied = bytes;
                 ensure!(copied.len() >= 4 && copied[..4] == [0, 1, 2, 3]);
                 json!({\"size\":copied.len(), \"prefix\":copied[0]});
                 let metadata = fs::symlink_metadata(\"worker\")?;
                 ensure!(metadata.is_file() && metadata.len() <= 256);
                 Ok(())
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("filesystem", "std::fs::read"), 1usize),
                (("filesystem", "std::fs::symlink_metadata"), 1),
            ]),
            "returned data must not acquire creating-function reference sites: {findings:?}"
        );
    }

    #[test]
    fn returned_tempdir_paths_do_not_repeat_creation() {
        let findings = scan(
            "use super::*; fn f(root: &Path) -> Result<(), Error> {
                 let temporary = tempfile::tempdir_in(root)?;
                 let archive = temporary.path().join(\"roc.tar.gz\");
                 let extracted = temporary.path().join(\"extracted\");
                 inspect(&archive, &extracted, temporary.path());
                 ensure!(archive.starts_with(temporary.path()));
                 std::fs::write(&archive, b\"bounded\")?;
                 Ok(())
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("filesystem", "tempfile::tempdir_in"), 1usize),
                (("filesystem", "std::fs::write"), 1),
            ]),
            "returned paths must not repeat TempDir construction: {findings:?}"
        );
    }

    #[test]
    fn returned_file_and_command_receivers_keep_actual_method_effects() {
        let findings = scan(
            "use super::*; use std::{fs::File, process::Command};
             fn f(input: &File) -> Result<(), Error> {
                 let mut file = File::open(\"worker\")?;
                 let _ = file.metadata()?;
                 let mut bytes = Vec::new();
                 file.read_to_end(&mut bytes)?;
                 input.sync_all()?;
                 let mut command = Command::new(\"tool\");
                 command.env(\"EXPLICIT\", \"value\"); command.spawn()?;
                 Ok(())
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("filesystem", "std::fs::File::open"), 1usize),
                (("filesystem", "std::fs::File::metadata"), 1),
                (("filesystem", "std::fs::File::read_to_end"), 1),
                (("filesystem", "std::fs::File::sync_all"), 1),
                (("process", "std::process::Command::new"), 1),
                (("process", "std::process::Command::spawn"), 1),
            ]),
            "receiver provenance must remain separate from value references: {findings:?}"
        );
    }

    #[test]
    fn returned_data_shadow_preserves_real_function_references() {
        let findings = scan(
            "use super::*; fn f() -> Result<(), Error> {
                 let read = std::fs::read;
                 { let read = std::fs::read(\"worker\")?; inspect(&read, read.len()); }
                 read(\"a\")?; read(\"b\")?; Ok(())
             }
             const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
             fn clock() { let copied = CLOCK; copied(); copied(); }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("filesystem", "std::fs::read"), 4usize),
                (("clock", "std::time::Instant::now"), 4),
            ]),
            "scoped data shadows must not erase function references: {findings:?}"
        );
    }

    #[test]
    fn unconditional_typed_file_retains_conditional_constructor_receivers() {
        let findings = scan(
            "use super::*; use std::fs::File;
             fn bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, Error> {
                 let file: File = {
                     #[cfg(unix)] { File::from(rustix::fs::open(path, flags(), mode())?) }
                     #[cfg(not(unix))] { File::open(path)? }
                 };
                 let admitted = file.metadata()?;
                 ensure!(admitted.is_file() && admitted.len() <= maximum);
                 let mut bytes = Vec::new();
                 file.take(maximum + 1).read_to_end(&mut bytes)?;
                 Ok(bytes)
             }",
        );
        for target in ["std::fs::File::metadata", "std::fs::File::read_to_end"] {
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.target == target)
                    .map(|finding| finding.count)
                    .sum::<usize>(),
                1,
                "typed owning receiver must retain its real method effect: {target}: {findings:?}"
            );
        }
        assert!(
            !findings
                .iter()
                .any(|finding| finding.target == "std::fs::File"),
            "ordinary File/Metadata references must not become ambient calls: {findings:?}"
        );
    }

    #[test]
    fn conditional_known_ambient_local_bindings_fail_closed() {
        for source in [
            "use std::fs::File; fn f(path: &Path) {
                 #[cfg(unix)] let file = File::from(open_native(path));
                 #[cfg(not(unix))] let file = File::open(path).unwrap();
                 file.metadata(); file.read_to_end(&mut Vec::new());
             }",
            "use std::fs::File as Input; fn f() {
                 #[cfg(feature = \"native\")] let file: Input = choose_file();
                 file.metadata();
             }",
            "fn f() { #[cfg(unix)] let (read, _) = (std::fs::read, 0); read(\"a\"); }",
            "fn f() { #[cfg(unix)] let [current] = [std::time::Instant::now]; current(); }",
            "fn f() { #[cfg_attr(feature = \"native\", allow(dead_code))]
                 let command = std::process::Command::new(\"tool\"); command.spawn(); }",
            "use reqwest::blocking::Client; fn f() {
                 #[cfg(unix)] let client: Client; client.get(\"https://example.invalid\").send();
             }",
        ] {
            let error = inventory(fixture(source).path()).unwrap_err().to_string();
            assert!(
                error.contains("conditional ambient local bindings"),
                "{source}: {error}"
            );
        }
    }

    #[test]
    fn conditional_pure_data_and_provable_test_bindings_stay_exempt() {
        let findings = scan(
            "fn f() {
                 #[cfg(unix)] let count = 1;
                 #[cfg(not(unix))] let count = 2;
                 inspect(count);
                 #[cfg(test)] let file = std::fs::File::open(\"test\");
                 #[cfg(any())] let hidden = std::time::Instant::now;
                 #[cfg(not(test))] let current = std::time::Instant::now;
                 current();
             }",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.target == "std::time::Instant::now")
                .map(|finding| finding.count)
                .sum::<usize>(),
            2,
            "{findings:?}"
        );
        assert!(
            !findings.iter().any(|finding| finding.kind == "filesystem"),
            "{findings:?}"
        );
    }

    #[test]
    fn conditional_discarded_effect_results_remain_actual_effects() {
        let findings = scan(
            "fn f() {
                 #[cfg(unix)] let _ = std::process::Command::new(\"tool\").status();
                 #[cfg(not(unix))] let (_, _) = (std::fs::read(\"a\"), std::fs::read(\"b\"));
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("process", "std::process::Command::new"), 1usize),
                (("process", "std::process::Command::status"), 1),
                (("filesystem", "std::fs::read"), 2),
            ]),
            "discarded results do not create an untracked receiver: {findings:?}"
        );
    }

    #[test]
    fn conditional_values_from_ambient_calls_are_data() {
        let findings = scan(
            "use std::fs::{File, Metadata};
             fn f() -> Result<(), Error> {
                 #[cfg(unix)] let bytes = std::fs::read(\"worker\")?;
                 #[cfg(unix)] inspect(&bytes, bytes.len());
                 #[cfg(unix)] let pid = std::process::id();
                 #[cfg(unix)] inspect(pid);
                 #[cfg(unix)] let named = std::fs::symlink_metadata(\"worker\")?;
                 #[cfg(unix)] inspect(named.len());
                 #[cfg(unix)] let opened: Metadata = File::open(\"worker\")?.metadata()?;
                 #[cfg(unix)] inspect(opened.len());
                 Ok(())
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("filesystem", "std::fs::read"), 1usize),
                (("filesystem", "std::fs::symlink_metadata"), 1),
                (("filesystem", "std::fs::File::open"), 1),
                (("filesystem", "std::fs::File::metadata"), 1),
                (("process", "std::process::id"), 1),
            ]),
            "conditional returned DATA must retain only actual calls: {findings:?}"
        );
    }

    #[test]
    fn conditional_data_never_erases_other_target_references() {
        let findings = scan(
            "use std::process::id;
             fn f() -> Result<(), Error> {
                 #[cfg(unix)] let id = std::fs::read(\"worker\")?;
                 #[cfg(not(unix))] let actual = id();
                 #[cfg(not(unix))] opaque!({\"reference\":id});
                 Ok(())
             }",
        );
        let mut calls = BTreeMap::new();
        for finding in &findings {
            *calls
                .entry((finding.kind.as_str(), finding.target.as_str()))
                .or_insert(0usize) += finding.count;
        }
        assert_eq!(
            calls,
            BTreeMap::from([
                (("filesystem", "std::fs::read"), 1usize),
                (("process", "std::process::id"), 2),
            ]),
            "a conditional DATA local cannot shadow another target's callable: {findings:?}"
        );
    }

    #[test]
    fn conditional_owned_struct_fields_preserve_handle_roles() {
        for source in [
            "struct Holder { file: std::fs::File }
             fn f(holder: Holder) {
                 #[cfg(unix)] let Holder { file } = holder;
                 #[cfg(unix)] file.metadata();
             }",
            "struct Holder { command: std::process::Command }
             fn f(holder: Holder) {
                 #[cfg(unix)] let Holder { command: selected } = holder;
                 #[cfg(unix)] selected.spawn();
             }",
            "struct Holder(std::fs::File);
             fn f(holder: Holder) {
                 #[cfg(unix)] let Holder(file) = holder;
                 #[cfg(unix)] file.metadata();
             }",
            "struct Holder(u8, std::fs::File);
             fn f(holder: Holder) {
                 #[cfg(unix)] let Holder(.., file) = holder;
                 #[cfg(unix)] file.metadata();
             }",
            "struct Holder(u8, std::fs::File); struct Outer { inner: Holder }
             fn f(outer: Outer) {
                 #[cfg(unix)] let Outer { inner: Holder(.., file) } = outer;
                 #[cfg(unix)] file.metadata();
             }",
        ] {
            let error = inventory(fixture(source).path()).unwrap_err().to_string();
            assert!(
                error.contains("conditional ambient local bindings"),
                "{source}: {error}"
            );
        }
        let findings = scan(
            "struct Holder { metadata: std::fs::Metadata }
             fn f(holder: Holder) {
                 #[cfg(unix)] let Holder { metadata } = holder;
                 #[cfg(unix)] inspect(metadata.len());
             }",
        );
        assert!(
            findings.is_empty(),
            "known ordinary fields are not ambient receivers: {findings:?}"
        );
    }

    #[test]
    fn already_supported_handle_factories_and_transforms_cannot_be_conditional_data() {
        for source in [
            "use std::fs::File; fn f(file: &File) {
                 #[cfg(unix)] let selected = File::try_clone(file).unwrap(); selected.metadata();
             }",
            "use std::fs::OpenOptions; fn f(path: &Path) {
                 #[cfg(unix)] let selected = OpenOptions::new().read(true).open(path).unwrap();
                 selected.metadata();
             }",
            "async fn f(path: &Path) {
                 #[cfg(unix)] let selected = tokio::fs::File::open(path).await?;
                 selected.read_to_end(&mut Vec::new()).await?;
             }",
            "use reqwest::blocking::Client; fn f(client: &Client) {
                 #[cfg(unix)] let selected = Client::get(client, \"https://example.invalid\"); selected.send();
             }",
            "fn f() { #[cfg(unix)] let selected = ureq::get(\"https://example.invalid\"); selected.call(); }",
            "fn f() { #[cfg(unix)] let selected = std::thread::Builder::new(); selected.spawn(callback); }",
            "fn f() { #[cfg(unix)] let selected = rand::rng(); selected.random::<u8>(); }",
            "fn f() { #[cfg(unix)] let selected = std::net::TcpListener::bind(\"127.0.0.1:0\").unwrap(); selected.accept(); }",
            "fn f() { #[cfg(unix)] let selected = std::time::Instant::now(); selected.elapsed(); }",
            "fn f() { #[cfg(unix)] let selected = std::process::Command::new(\"worker\").env(\"PATH\", \"\"); selected.spawn(); }",
            "fn f() { #[cfg(unix)] let selected = tokio::runtime::Builder::new_current_thread(); selected.build(); }",
        ] {
            let error = inventory(fixture(source).path()).unwrap_err().to_string();
            assert!(error.contains("conditional ambient local bindings"), "{source}: {error}");
        }
    }

    #[test]
    fn conditional_const_and_static_never_install_cross_target_shadows() {
        for declaration in ["const id: u32 = 7;", "static id: u32 = 7;"] {
            let findings = scan(&format!(
                "use std::process::id; fn f() {{
                     #[cfg(unix)] {declaration}
                     #[cfg(unix)] inspect(id);
                     #[cfg(not(unix))] let actual = id();
                 }}",
            ));
            // The ordinary reference is conservatively visible on alternate
            // targets, but the actual nonUnix call must never be erased.
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.target == "std::process::id")
                    .map(|finding| finding.count)
                    .sum::<usize>(),
                2,
                "{declaration}: {findings:?}"
            );
        }
        for declaration in [
            "#[cfg(unix)] const current: fn() -> std::time::Instant = std::time::Instant::now;",
            "#[cfg(unix)] static current: fn() -> std::time::Instant = std::time::Instant::now;",
            "#[cfg(unix)] static selected: reqwest::blocking::Client = supplied_client();",
        ] {
            let error = inventory(fixture(declaration).path())
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("conditional ambient local bindings"),
                "{declaration}: {error}"
            );
        }
        let findings = scan(
            "#[cfg(test)] const current: fn() -> std::time::Instant = std::time::Instant::now;",
        );
        assert!(
            findings.is_empty(),
            "provably test-only items remain excluded: {findings:?}"
        );
    }

    #[test]
    fn parent_const_and_static_callables_require_closed_imports() {
        for declaration in ["const", "static"] {
            for (definition, imported, call) in [
                (format!("{declaration} CLOCK: fn() -> std::time::Instant = std::time::Instant::now;"), "CLOCK", "CLOCK"),
                (format!("{declaration} CLOCK: fn() -> std::time::Instant = std::time::Instant::now;"), "CLOCK as Current", "Current"),
                (format!("use std::time::Instant as Current; {declaration} CLOCK: fn() -> Current = Current::now;"), "CLOCK", "CLOCK"),
                (format!("{declaration} FIRST: fn() -> std::time::Instant = std::time::Instant::now;
                    {declaration} CLOCK: fn() -> std::time::Instant = FIRST;"), "CLOCK", "CLOCK"),
                (format!("{declaration} CLOCK: Option<fn() -> std::time::Instant> = Some(std::time::Instant::now);"), "CLOCK", "CLOCK.unwrap()"),
                (format!("{declaration} CLOCK: fn() -> std::time::Instant = {{ std::time::Instant::now }};"), "CLOCK", "CLOCK"),
                (format!("{declaration} CLOCK: fn() -> std::time::Instant = if true {{ std::time::Instant::now }} else {{ std::time::Instant::now }};"), "CLOCK", "CLOCK"),
                (format!("{declaration} CLOCK: fn() -> std::time::Instant = match true {{ true => std::time::Instant::now, false => std::time::Instant::now }};"), "CLOCK", "CLOCK"),
                (format!("type Clock = fn() -> std::time::Instant; {declaration} CLOCK: Clock = std::time::Instant::now;"), "CLOCK", "CLOCK"),
                (format!("use std::time::Instant as Current; type Clock = fn() -> Current;
                    {declaration} CLOCK: Clock = Current::now;"), "CLOCK", "CLOCK"),
                (format!("type Clock = fn() -> std::time::Instant;
                    {declaration} FIRST: Clock = std::time::Instant::now;
                    {declaration} CLOCK: Clock = FIRST;"), "CLOCK", "CLOCK"),
                (format!("{declaration} CLOCK: fn() -> std::time::Instant = {{ let f = std::time::Instant::now; f }};"), "CLOCK", "CLOCK"),
                (format!("use core::option::Option::Some as Keep; type Clock = fn() -> std::time::Instant;
                    {declaration} CLOCK: Option<Clock> = Keep(std::time::Instant::now);"), "CLOCK", "CLOCK.unwrap()"),
                (format!("use core::option::Option::Some as Keep; type Clock = fn() -> std::time::Instant;
                    {declaration} FIRST: Option<Clock> = Keep(std::time::Instant::now);
                    {declaration} CLOCK: Option<Clock> = FIRST;"), "CLOCK", "CLOCK.unwrap()"),
                (format!("const fn factory() -> fn() -> std::time::Instant {{ std::time::Instant::now }}
                    {declaration} FIRST: fn() -> std::time::Instant = factory();
                    {declaration} CLOCK: fn() -> std::time::Instant = FIRST;"), "CLOCK", "CLOCK"),
                (format!("{declaration} CLOCK: Result<(), fn() -> std::time::Instant> = Err(std::time::Instant::now);"), "CLOCK", "CLOCK.unwrap_err()"),
            ] {
                // Collection is item-order independent, including a constant
                // declared after the importing child module.
                for source in [
                    format!("{definition} mod child {{ use super::{imported}; fn f() {{ {call}(); }} }}"),
                    format!("mod child {{ use super::{imported}; fn f() {{ {call}(); }} }} {definition}"),
                ] {
                    let error = match inventory(fixture(&source).path()) {
                        Err(error) => error.to_string(),
                        Ok(inventory) => panic!("parent callback was accepted: {source}: {inventory:?}"),
                    };
                    assert!(error.contains("unresolved parent ambient imports"), "{source}: {error}");
                }
            }
        }
        for declarations in [
            "fn CLOCK() {} type CLOCK = u32;",
            "type CLOCK = u32; fn CLOCK() {}",
        ] {
            for source in [
                format!(
                    "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
                    mod child {{ use super::*; {declarations} fn f() {{ CLOCK(); }} }}"
                ),
                format!(
                    "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
                    mod child {{ use super::*; fn f() {{ {declarations} CLOCK(); }} }}"
                ),
            ] {
                let findings = match inventory(fixture(&source).path()) {
                    Ok(inventory) => inventory.findings,
                    Err(error) => panic!(
                        "coexisting namespaces refused a real value shadow: {source}: {error}"
                    ),
                };
                assert_eq!(
                    findings
                        .iter()
                        .map(|finding| (finding.target.as_str(), finding.count))
                        .collect::<Vec<_>>(),
                    vec![("std::time::Instant::now", 1)],
                    "coexisting type/value declarations preserve the real value shadow in either order: {source}: {findings:?}"
                );
            }
        }
        for body in [
            "CLOCK::now();",
            "json!({\"now\":CLOCK::now()});",
            "let _: Option<CLOCK> = None;",
            "let CLOCK = 7; let _: Option<CLOCK> = None;",
        ] {
            for source in [
                format!(
                    "use std::time::Instant as CLOCK;
                    mod child {{ use super::CLOCK; fn CLOCK() {{}} fn f() {{ {body} }} }}"
                ),
                format!(
                    "use std::time::Instant as CLOCK;
                    mod child {{ use super::CLOCK; fn f() {{ fn CLOCK() {{}} {body} }} }}"
                ),
            ] {
                let error = match inventory(fixture(&source).path()) {
                    Err(error) => error.to_string(),
                    Ok(inventory) => panic!(
                        "value-only declaration qualified an inherited type: {source}: {inventory:?}"
                    ),
                };
                assert!(
                    error.contains("unresolved parent ambient imports"),
                    "{source}: {error}"
                );
            }
        }
        for source in [
            "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
             mod child { fn CLOCK() {} fn f() { { use super::CLOCK; CLOCK(); } } }",
            "use std::time::Instant as CLOCK;
             mod child { type CLOCK = u32; fn f() { { use super::CLOCK; CLOCK::now(); } } }",
            "use std::time::Instant as CLOCK;
             fn f() { use std::process::id as CLOCK; CLOCK::now(); }",
            "use std::process::id as CLOCK;
             fn f() { use reqwest::blocking::Client as CLOCK; CLOCK(); }",
            "fn f() { let CLOCK = std::time::Instant::now;
                 { use opaque::Client as CLOCK; CLOCK(); } }",
            "fn f() { let file = std::fs::File::open(\"a\")?;
                 { use opaque::File as file; file.metadata(); } }",
            "use std::process::id as CLOCK;
             fn f() { use opaque::Client as CLOCK; CLOCK(); }",
            "fn f() { let p = Some(std::time::Instant::now); let CLOCK = p.unwrap();
                 { use opaque::Client as CLOCK; CLOCK(); } }",
            "fn f() { let p = Some(std::time::Instant::now); let CLOCK = p.unwrap();
                 { use opaque::Client as CLOCK; json!({\"clock\":({CLOCK})()}); } }",
        ] {
            let error = match inventory(fixture(source).path()) {
                Err(error) => error.to_string(),
                Ok(inventory) => {
                    panic!("closer import lost ambient provenance: {source}: {inventory:?}")
                }
            };
            assert!(
                error.contains("unresolved parent ambient imports"),
                "{source}: {error}"
            );
        }
        for (source, expected) in [
            (
                "fn f() { let id = 7; { use std::process::id; id(); } }",
                BTreeMap::from([("std::process::id", 1usize)]),
            ),
            (
                "use std::process::id; fn f() { let id = 7; json!({\"n\":id});
                { use std::process::id; id(); } json!({\"n\":id}); }",
                BTreeMap::from([("std::process::id", 1)]),
            ),
            (
                "fn f() { let Client = std::time::Instant::now;
                { use reqwest::Client; Client(); } }",
                BTreeMap::from([("std::time::Instant::now", 2)]),
            ),
            (
                "fn f() { let file = std::fs::File::open(\"a\")?;
                { use reqwest::Client as file; file.metadata(); } }",
                BTreeMap::from([("std::fs::File::open", 1), ("std::fs::File::metadata", 1)]),
            ),
            (
                "fn f() { let CLOCK = std::time::Instant::now;
                { fn CLOCK() {} CLOCK(); } CLOCK(); }",
                BTreeMap::from([("std::time::Instant::now", 2)]),
            ),
            (
                "use std::process::id; fn f() { { fn id() {} id(); } id(); }",
                BTreeMap::from([("std::process::id", 1)]),
            ),
            (
                "fn f() { let bytes = std::fs::read(\"a\")?;
                { use opaque::Client as bytes; json!({\"bytes\":bytes}); } }",
                BTreeMap::from([("std::fs::read", 1)]),
            ),
            (
                "fn f() { let CLOCK = std::time::Instant::now;
                { use opaque::Client as CLOCK; { fn CLOCK() {} CLOCK(); } } }",
                BTreeMap::from([("std::time::Instant::now", 1)]),
            ),
        ] {
            let findings = match inventory(fixture(source).path()) {
                Ok(inventory) => inventory.findings,
                Err(error) => {
                    panic!("real lexical shadow or canonical call refused: {source}: {error}")
                }
            };
            let mut actual = BTreeMap::new();
            for finding in &findings {
                *actual.entry(finding.target.as_str()).or_insert(0usize) += finding.count;
            }
            assert_eq!(
                actual, expected,
                "lexical precedence must retain exact actual effects: {source}: {findings:?}"
            );
        }
        let findings = scan(
            "fn pure() {} const CLOCK: fn() = pure;
             mod child { use super::CLOCK; fn f() { CLOCK(); } }
             mod shadow { use super::CLOCK; fn pure() {} fn f() { let CLOCK = pure; CLOCK(); } }
             const NUMBER: u32 = std::u32::MAX;
             mod data { use super::NUMBER; fn f() { json!({\"n\":NUMBER}); } }
             use std::env::consts::OS as Platform; type Text = &'static str;
             const PLATFORM: Text = Platform;
             mod platform { use super::PLATFORM; fn f() { json!({\"os\":PLATFORM}); } }
             const PURE: fn() = { let metadata = 7; pure };
             mod pure_block { use super::PURE; fn f() { PURE(); } }
             fn test_block() { #[cfg(test)] { type Clock = fn() -> std::time::Instant; } }
             type Clock = u32; const fn seven() -> Clock { 7 }
             const COUNT: Clock = seven();
             mod count { use super::COUNT; fn f() { json!({\"n\":COUNT}); } }
             const DATA: Result<(), u32> = Err(7);
             static STATIC_DATA: Result<(), u32> = Err(8);
             mod result_data { use super::{DATA, STATIC_DATA};
                 fn f() { json!({\"n\":DATA.unwrap_err(),\"m\":STATIC_DATA.unwrap_err()}); } }",
        );
        assert!(
            findings.is_empty(),
            "pure pointers and DATA constant paths remain ordinary: {findings:?}"
        );
        let findings = scan(
            "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
             mod child { use super::CLOCK; fn pure() {} fn f() { let CLOCK = pure; CLOCK(); } }",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.target == "std::time::Instant::now")
                .map(|finding| finding.count)
                .sum::<usize>(),
            1,
            "a genuine local pure shadow remains lexical: {findings:?}"
        );
        let source = "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
            mod child { use super::*; fn f() { CLOCK(); } }";
        let error = match inventory(fixture(source).path()) {
            Err(error) => error.to_string(),
            Ok(inventory) => {
                panic!("a parent declaration cannot qualify a child glob: {source}: {inventory:?}")
            }
        };
        assert!(
            error.contains("unresolved parent ambient imports"),
            "{source}: {error}"
        );
        for declaration in [
            "type CLOCK = u32;",
            "struct CLOCK { value: u32 }",
            "trait CLOCK {}",
            "mod CLOCK {}",
            "enum CLOCK { Value }",
            "union CLOCK { value: u32 }",
        ] {
            for expression in [
                "CLOCK();",
                "json!({\"now\":CLOCK()});",
                "let _ = CLOCK;",
                "json!({\"callback\":CLOCK});",
            ] {
                for source in [
                    format!(
                        "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
                        mod child {{ use super::CLOCK; {declaration} fn f() {{ {expression} }} }}"
                    ),
                    format!(
                        "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
                        mod child {{ use super::CLOCK; fn f() {{ {declaration} {expression} }} }}"
                    ),
                ] {
                    let error = match inventory(fixture(&source).path()) {
                        Err(error) => error.to_string(),
                        Ok(inventory) => panic!(
                            "type-only declaration qualified an inherited value: {source}: {inventory:?}"
                        ),
                    };
                    assert!(
                        error.contains("unresolved parent ambient imports"),
                        "{source}: {error}"
                    );
                }
            }
        }
        let findings = scan(
            "const CLOCK: fn() -> std::time::Instant = std::time::Instant::now;
             mod sibling { use super::*; fn CLOCK() {} fn f() { CLOCK(); } }
             mod nested { use super::*; fn f() { fn CLOCK() {} CLOCK(); } }
             mod type_position { use super::CLOCK; type CLOCK = u32; fn f(value: CLOCK) {} }
             mod type_shadow { use super::CLOCK; struct CLOCK { value: u32 }
                 impl CLOCK { fn now() {} } fn f() { CLOCK::now(); } }
             mod constructors { use super::*;
                 fn unit() { struct CLOCK; let _ = CLOCK; }
                 fn tuple() { struct CLOCK(u8); CLOCK(7); } }
             fn metadata() {} fn outer() { use crate::*; metadata(); }",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.target == "std::time::Instant::now")
                .map(|finding| finding.count)
                .sum::<usize>(),
            1,
            "same-module/block pure declarations and the outer declaration floor remain visible: {findings:?}"
        );
    }

    #[test]
    fn macro_bare_values_and_blocks_share_lexical_provenance() {
        for (source, count) in [
            (
                "use std::fs::read; fn f() -> Result<(), Error> {
                 let read = read(\"worker\")?; json!({\"bytes\":read}); Ok(())
             }",
                1,
            ),
            (
                "use std::fs::read; fn f() -> Result<(), Error> {
                 json!({\"bytes\":{ let read = std::fs::read(\"worker\")?; read }});
                 Ok(())
             }",
                1,
            ),
            (
                "use std::fs::read; fn f() -> Result<(), Error> {
                 opaque!({\"data\":{ let read = read(\"worker\")?; read },
                     \"alias\":{ let read = read; read }, \"outside\":read}); Ok(())
             }",
                4,
            ),
            (
                "use std::fs::read; fn f() -> Result<(), Error> {
                 let (read, callback) = (read(\"worker\")?, read);
                 opaque!({\"bytes\":read, \"reference\":callback});
                 callback(\"a\")?; Ok(())
             }",
                4,
            ),
            (
                "use std::fs::read; struct Data { read: u8 }
             fn f() { let data = Data { read: 7 }; json!({\"n\":data.read}); }",
                0,
            ),
            (
                "use std::fs::read;
             fn f() { json!({\"n\":{ const read: u8 = 7; read }}); }",
                0,
            ),
            (
                "use std::fs::read;
             mod first { const read: u8 = 7; fn f() { json!({\"n\":read}); } }
             mod second { use std::fs::read; fn f() { json!({\"reference\":read}); } }
             fn f() { json!({\"reference\":read}); }",
                2,
            ),
            (
                "const read: u8 = 7;
             mod child { use std::fs::read; fn f() { json!({\"reference\":read}); } }
             fn f() { json!({\"n\":read}); }",
                1,
            ),
        ] {
            let findings = scan(source);
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.target == "std::fs::read")
                    .map(|finding| finding.count)
                    .sum::<usize>(),
                count,
                "macro fallback must use actual lexical reference roles: {source}: {findings:?}"
            );
        }
    }

    #[test]
    fn test_only_parent_globs_are_catalogued_without_ambient_refusal() {
        let directory =
            fixture("use std::{fs as disk, process::Command as Spawn}; #[cfg(test)] mod child;");
        fs::write(
            directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { disk::read(\"input\"); Spawn::new(\"tool\"); }",
        )
        .unwrap();
        let actual = inventory(directory.path()).unwrap();
        assert!(
            actual
                .sources
                .iter()
                .any(|source| source.ends_with("child.rs"))
        );
        assert!(
            !actual
                .findings
                .iter()
                .any(|finding| finding.source.ends_with("child.rs"))
        );

        let directory = parent_fixture(
            "#[cfg(test)] fn f() { use super::*; disk::read(\"input\"); }
             #[cfg(test)] mod nested { use super::*; fn f() { Spawn::new(\"tool\"); } }",
        );
        assert!(inventory(directory.path()).unwrap().findings.is_empty());
    }

    #[test]
    fn conditional_parent_aliases_cannot_be_overwritten_by_canonical_imports() {
        for child in [
            "#[cfg(unix)] use super::Spawn as Run;
             #[cfg(windows)] use std::process::Command as Run;
             fn f() { Run::new(\"tool\"); }",
            "use super::*; #[cfg(windows)] use std::process::Command as Spawn;
             fn f() { Spawn::new(\"tool\"); }",
            "use super::*; #[cfg(windows)] struct Spawn; fn f() { Spawn::new(\"tool\"); }",
        ] {
            let directory = parent_fixture(child);
            assert!(
                inventory(directory.path())
                    .unwrap_err()
                    .to_string()
                    .contains("unresolved parent ambient imports"),
                "{child}"
            );
        }
    }

    #[test]
    fn ambient_import_alias_collection_has_a_closed_chain_bound() {
        let mut admitted = "use std::fs as alias0;\n".to_owned();
        for index in 1..MAX_ALIAS_ROUNDS {
            admitted.push_str(&format!("use alias{} as alias{index};\n", index - 1));
        }
        inventory(fixture(&admitted).path()).unwrap();
        let mut source = "use std::fs as alias0;\n".to_owned();
        for index in 1..=MAX_ALIAS_ROUNDS {
            source.push_str(&format!("use alias{} as alias{index};\n", index - 1));
        }
        let directory = fixture(&source);
        assert!(
            inventory(directory.path())
                .unwrap_err()
                .to_string()
                .contains("import-alias chain limit")
        );
    }

    #[test]
    fn pinned_time_clock_apis_require_review_through_aliases_and_globs() {
        let findings = scan(
            r#"
            use time::{OffsetDateTime as Wall, UtcDateTime as UtcWall};
            use time as clocks;
            fn qualified() {
                time::OffsetDateTime::now_utc();
                time::OffsetDateTime::now_local();
                time::UtcDateTime::now();
            }
            fn renamed() { Wall::now_utc(); Wall::now_local(); UtcWall::now(); }
            fn module_alias() { clocks::OffsetDateTime::now_utc(); }
            fn wildcard() { use time::*; OffsetDateTime::now_utc(); OffsetDateTime::now_local(); UtcDateTime::now(); }
            fn indirect() { let clock = Wall::now_utc; clock(); }
            #[cfg(test)] fn fixture_only() { time::UtcDateTime::now(); }
        "#,
        );
        for context in ["qualified", "renamed", "wildcard"] {
            for target in [
                "time::OffsetDateTime::now_utc",
                "time::OffsetDateTime::now_local",
                "time::UtcDateTime::now",
            ] {
                assert!(
                    findings.iter().any(|finding| finding.kind == "clock"
                        && finding.context == context
                        && finding.target == target),
                    "{context}: {target}"
                );
            }
        }
        for context in ["module_alias", "indirect"] {
            assert!(findings.iter().any(|finding| finding.kind == "clock"
                && finding.context == context
                && finding.target == "time::OffsetDateTime::now_utc"));
        }
        assert!(
            !findings
                .iter()
                .any(|finding| finding.context == "fixture_only")
        );
    }

    #[test]
    fn protected_library_parent_aliases_cannot_hide_clocks_or_entropy() {
        for child in [
            "use super::*; fn f() { Wall::now_utc(); }",
            "use super::*; fn f() { Wall::now_local(); }",
            "use super::*; fn f() { UtcWall::now(); }",
            "use super::Wall as Clock; fn f() { Clock::now_utc(); }",
            "fn f() { super::UtcWall::now(); }",
            "use super::*; fn f() { Universal::now(); }",
            "use super::*; fn f() { LocalWall::now(); }",
            "use super::Universal as Clock; fn f() { Clock::now(); }",
            "fn f() { super::LocalWall::now(); }",
            "use super::*; fn f() { Id::new_v4(); }",
            "use super::Id as FreshId; fn f() { FreshId::now_v7(); }",
            "fn f() { super::Id::new_v7(); }",
        ] {
            let directory = fixture(
                "use time::{OffsetDateTime as Wall, UtcDateTime as UtcWall};
                 use chrono::{Utc as Universal, Local as LocalWall};
                 use uuid::Uuid as Id; mod child;",
            );
            fs::write(directory.path().join("crates/fixture/src/child.rs"), child).unwrap();
            assert!(
                inventory(directory.path())
                    .unwrap_err()
                    .to_string()
                    .contains("unresolved parent ambient imports"),
                "{child}"
            );
        }
        let findings = scan(
            "use chrono::*; use uuid::*; fn f() { Utc::now(); Local::now(); Uuid::new_v4(); }",
        );
        for target in [
            "chrono::Utc::now",
            "chrono::Local::now",
            "uuid::Uuid::new_v4",
        ] {
            assert!(
                findings.iter().any(|finding| finding.target == target),
                "{target}"
            );
        }
    }

    #[test]
    fn conditional_library_aliases_retain_their_ambient_origin() {
        for (import, call, target) in [
            (
                "time::OffsetDateTime",
                "now_utc",
                "time::OffsetDateTime::now_utc",
            ),
            ("time::UtcDateTime", "now", "time::UtcDateTime::now"),
            ("chrono::Utc", "now", "chrono::Utc::now"),
            ("chrono::Local", "now", "chrono::Local::now"),
            ("uuid::Uuid", "new_v4", "uuid::Uuid::new_v4"),
        ] {
            let findings = scan(&format!(
                "#[cfg(unix)] use {import} as Ambient;
                 #[cfg(windows)] use fixture::Pure as Ambient;
                 fn f() {{ Ambient::{call}(); }}",
            ));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.kind == "effect-alias-conflict"),
                "{import}"
            );
            assert!(
                findings.iter().any(|finding| finding.target == target),
                "{target}"
            );
        }
    }

    #[test]
    fn canonical_date_and_rfc3339_parsing_are_not_ambient_effects() {
        let findings = scan(
            r#"
            use super::*;
            use time::{Date as Day, OffsetDateTime as Stamp, UtcOffset,
                format_description::well_known::Rfc3339 as Wire};
            use time as dates;
            use dates::Date as DayAlias;
            use chrono::NaiveDate as CalendarDay;
            use uuid::Uuid as Id;
            fn parse() {
                Day::parse("2026-10-05", &time::format_description::parse_borrowed::<1>("[year]-[month]-[day]").unwrap());
                DayAlias::from_calendar_date(2026, time::Month::October, 5);
                let value = Stamp::parse("2026-10-05T00:00:10Z", &Wire).unwrap();
                value.format(&Wire); value.checked_to_offset(UtcOffset::UTC);
                Stamp::from_unix_timestamp(1); time::UtcDateTime::from_unix_timestamp(1);
                CalendarDay::parse_from_str("2026-10-05", "%Y-%m-%d");
                Id::parse_str("00000000-0000-0000-0000-000000000000");
            }
        "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
        let directory = fixture(
            "use time::{Date as Day, format_description::well_known::Rfc3339 as Wire}; mod child;",
        );
        fs::write(
            directory.path().join("crates/fixture/src/child.rs"),
            "use super::*; fn f() { Day::parse(\"2026-10-05\", &Wire); }",
        )
        .unwrap();
        assert!(inventory(directory.path()).unwrap().findings.is_empty());
    }

    #[test]
    fn lexical_provider_data_bindings_do_not_become_parent_effects() {
        let findings = scan(
            r#"
            use super::*;
            struct Data { metadata: String }
            fn f(current: (), data: Data) {
                let metadata = data.metadata.clone(); metadata.len();
                let current = (current, metadata); let _ = current.0;
                if let Some(current) = Some(data) { current.metadata.len(); }
                let closure = |metadata| metadata; closure(1);
                for current in [1, 2] { let _ = current; }
                match Some(1) { Some(current) => { let _ = current; }, _ => {} }
            }
        "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn lexical_binding_initializers_and_branch_exits_keep_parent_refusal() {
        for source in [
            "use super::*; fn f() { let metadata = metadata(\"input\"); }",
            "use super::*; fn f() { let metadata = metadata; metadata(\"input\"); }",
            "use super::*; fn f() { if let Some(metadata) = Some(1) {} else { metadata(\"input\"); } }",
            "use super::*; fn f() { if let Some(current) = Some(1) {} current(); }",
            "use super::*; fn f() { let closure = |metadata| metadata; metadata(\"input\"); }",
            "use super::*; fn f(metadata: ()) { super::metadata(\"input\"); }",
            "use super::*; fn f() { #[cfg(unix)] let metadata = std::fs::read; #[cfg(windows)] let metadata = 1; metadata(\"input\"); }",
        ] {
            let directory = fixture(source);
            assert!(
                inventory(directory.path())
                    .unwrap_err()
                    .to_string()
                    .contains("unresolved parent ambient imports"),
                "{source}"
            );
        }
    }

    #[test]
    fn lexical_function_aliases_keep_exact_effect_origins() {
        let findings = scan(
            r#"
            use super::*;
            use std::fs::metadata;
            fn f() {
                let metadata = std::fs::read; metadata("input");
                let current = std::thread::current; current();
                if let Some(metadata) = Some(std::fs::metadata) { metadata("input"); }
                let call = |metadata: std::fs::File| { metadata.metadata(); };
            }
        "#,
        );
        for target in [
            "std::fs::read",
            "std::thread::current",
            "std::fs::metadata",
            "std::fs::File::metadata",
        ] {
            assert!(
                findings.iter().any(|finding| finding.target == target),
                "{target}: {findings:?}"
            );
        }
        assert!(
            findings
                .iter()
                .filter(|finding| finding.target == "std::fs::metadata")
                .map(|finding| finding.count)
                .sum::<usize>()
                >= 2,
            "both the wrapped function reference and its branch-local call must remain inventoried: {findings:?}"
        );
    }

    #[test]
    fn aggregate_destructuring_keeps_function_references_and_calls() {
        for (source, target) in [
            (
                r#"use super::*; use std::fs; fn f() {
                let (metadata, _) = (std::fs::metadata, 0);
                metadata("a"); metadata("b");
            }"#,
                "std::fs::metadata",
            ),
            (
                r#"use super::*; fn f() {
                let [current] = [std::time::Instant::now]; current(); current();
            }"#,
                "std::time::Instant::now",
            ),
            (
                r#"use super::*; fn f() {
                let [metadata, _] = [std::fs::metadata; 2]; metadata("a"); metadata("b");
            }"#,
                "std::fs::metadata",
            ),
            (
                r#"use super::*; fn f() {
                if let Some((metadata, _)) = Some((std::fs::metadata, 0)) {
                    metadata("a"); metadata("b");
                }
            }"#,
                "std::fs::metadata",
            ),
        ] {
            let findings = scan(source);
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.target == target)
                    .map(|finding| finding.count)
                    .sum::<usize>(),
                3,
                "reference and both calls must remain inventoried: {source}: {findings:?}"
            );
        }
    }

    #[test]
    fn aggregate_initializers_resolve_all_components_before_binding() {
        let findings = scan(
            r#"use super::*; use std::fs::metadata; fn f() {
            let (metadata, current) = (std::fs::read, metadata);
            current("old"); metadata("new");
        }"#,
        );
        for target in ["std::fs::read", "std::fs::metadata"] {
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.target == target)
                    .map(|finding| finding.count)
                    .sum::<usize>(),
                2,
                "initializer must use the old import, not the new tuple component: {target}: {findings:?}"
            );
        }
    }

    #[test]
    fn unknown_destructured_ambient_callees_fail_closed() {
        for source in [
            "use super::*; fn f() { let (metadata, _) = helper(); metadata(\"a\"); }",
            "use super::*; use std::fs::metadata; fn f() { let (metadata, _) = helper(); metadata(\"a\"); }",
            "use super::*; fn f() { let [current, ..] = helpers(); (current)(); }",
            "use super::*; fn f() { let (metadata, ..) = (std::fs::metadata, 0); metadata(\"a\"); }",
            "use super::*; fn f((metadata, _): (fn(&str), usize)) { metadata(\"a\"); }",
            "use super::*; fn f() { let (time, _) = helper(); time(); }",
        ] {
            let directory = fixture(source);
            assert!(
                inventory(directory.path())
                    .unwrap_err()
                    .to_string()
                    .contains("unresolved parent ambient imports"),
                "{source}"
            );
        }
    }

    #[test]
    fn dereferenced_and_cast_function_aliases_keep_reference_and_calls() {
        for source in [
            r#"use super::*; fn f() {
                let (metadata, _) = (&std::fs::metadata, 0);
                (*metadata)("a"); (*metadata)("b");
            }"#,
            r#"use super::*; fn f() {
                let metadata = std::fs::metadata as fn(&str) -> _;
                metadata("a"); metadata("b");
            }"#,
            r#"use super::*; fn f() {
                let metadata = &(std::fs::metadata as fn(&str) -> _);
                (*metadata)("a"); (*metadata)("b");
            }"#,
        ] {
            let findings = scan(source);
            assert_eq!(
                findings
                    .iter()
                    .filter(|finding| finding.target == "std::fs::metadata")
                    .map(|finding| finding.count)
                    .sum::<usize>(),
                3,
                "wrapper must preserve reference and both calls: {source}: {findings:?}"
            );
        }
    }

    #[test]
    fn invisible_expression_groups_preserve_function_call_origins() {
        let mut syntax = syn::parse_file(
            r#"use super::*; fn f() {
            let metadata = std::fs::metadata; metadata("a"); metadata("b");
        }"#,
        )
        .unwrap();
        let Item::Fn(function) = &mut syntax.items[1] else {
            panic!("fixture function missing")
        };
        for statement in &mut function.block.stmts {
            if let syn::Stmt::Expr(Expr::Call(call), _) = statement {
                call.func = Box::new(Expr::Group(syn::ExprGroup {
                    attrs: Vec::new(),
                    group_token: Default::default(),
                    expr: call.func.clone(),
                }));
            }
        }
        let findings = scan_syntax(syntax);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.target == "std::fs::metadata")
                .map(|finding| finding.count)
                .sum::<usize>(),
            3,
            "none-delimited call wrapper must preserve reference and both calls: {findings:?}"
        );
    }

    #[test]
    fn ordinary_data_references_and_type_wrappers_remain_pure() {
        let findings = scan(
            r#"use super::*;
            struct Data { metadata: usize }
            fn f(data: &(Data), current: &()) {
                let metadata = &data.metadata;
                let copied = *metadata as i64;
                let _ = (-copied, !copied, *current);
            }
        "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
        let directory = fixture(
            r#"use super::*;
            fn f((metadata, _): (fn(&str), usize)) {
                let metadata = metadata as fn(&str); (*&metadata)("a");
            }
        "#,
        );
        assert!(
            inventory(directory.path())
                .unwrap_err()
                .to_string()
                .contains("unresolved parent ambient imports")
        );
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
    fn continuous_clock_calls_cannot_escape_review_through_aliases_or_globs() {
        let findings = scan(
            r#"
            use rustix::time::{self as ticks, clock_gettime as read_clock};
            fn qualified() { ticks::clock_gettime(ticks::ClockId::Boottime); }
            fn renamed() { read_clock(ticks::ClockId::Boottime); }
            fn wildcard() { use rustix::time::*; clock_gettime(ClockId::Boottime); }
            fn escaped() { let read = read_clock; read(ticks::ClockId::Boottime); }
            #[cfg(test)] fn synthetic() { rustix::time::clock_gettime(ticks::ClockId::Boottime); }
        "#,
        );
        for scope in ["qualified", "renamed", "wildcard", "escaped"] {
            assert!(findings.iter().any(|finding| finding.kind == "clock"
                && finding.target == "rustix::time::clock_gettime"
                && finding.context.contains(scope)));
        }
        assert!(
            !findings
                .iter()
                .any(|finding| finding.context.contains("synthetic"))
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
                use reqwest::blocking::Client as Http;
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
