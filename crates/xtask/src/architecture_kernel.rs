//! Compiler-backed restrictions for policy-selected contract and kernel crates.
//! The callback check is deliberately syntactic: arbitrary Serialize impls,
//! macro expansion, and transitive dependency effects still require review.

use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};
use syn::{
    Attribute, Item, Meta, PathArguments, Token, TypeParamBound, UseTree,
    punctuated::Punctuated,
    visit::{self, Visit},
};

const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCES: usize = 4096;
const MAX_DEPTH: usize = 32;
const MAX_COMPILER_OUTPUT_BYTES: usize = 1024 * 1024;
const COMPILER_TIMEOUT: Duration = Duration::from_secs(600);
const REQUIRED_FORBIDS: [&str; 4] = [
    "unsafe_code",
    "clippy::disallowed_methods",
    "clippy::disallowed_types",
    "clippy::disallowed_macros",
];

/// Names and actual library target sources come from the verified dependency
/// policy, never a guessed src/lib.rs or an independently maintained inventory.
pub struct StrictCrate<'a> {
    pub name: &'a str,
    pub source: &'a str,
    pub kernel: bool,
}

pub fn check(root: &Path, packages: &[StrictCrate<'_>]) -> Result<()> {
    ensure!(
        !packages.is_empty() && packages.len() <= 128,
        "strict crate inventory budget"
    );
    let mut names = BTreeSet::new();
    for package in packages {
        ensure!(
            !package.name.is_empty()
                && package.name.len() <= 128
                && package
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                && !package.name.starts_with('-')
                && names.insert(package.name),
            "strict crate names must be bounded and unique"
        );
        let source = confined_source(root, package.source)?;
        let syntax = parse_source(&source)?;
        required_attributes(&syntax, package.kernel)
            .with_context(|| format!("strict crate {}", package.name))?;
        if package.kernel {
            let mut sources = Vec::new();
            collect_sources(
                source.parent().context("kernel source directory")?,
                &mut sources,
                0,
            )?;
            for source in sources {
                callbacks(&parse_source(&source)?)
                    .with_context(|| format!("kernel source {}", source.display()))?;
            }
        }
    }
    let config = root.join("architecture");
    let metadata = fs::symlink_metadata(&config)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "regular Clippy configuration directory required"
    );
    read_regular(&config.join("clippy.toml"))?;
    let directory = tempfile::tempdir().context("strict compiler log directory")?;
    let log = directory.path().join("clippy.log");
    let outcome = day2_ops::process::run(
        &mut clippy_command(root, packages)?,
        root,
        &log,
        COMPILER_TIMEOUT,
    );
    // The supervisor has reaped the process group before this bounded read.
    let metadata = fs::symlink_metadata(&log)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= MAX_COMPILER_OUTPUT_BYTES as u64,
        "strict compiler diagnostic budget"
    );
    let diagnostic = read_regular(&log)?;
    ensure!(
        diagnostic.len() <= MAX_COMPILER_OUTPUT_BYTES,
        "strict compiler diagnostic budget"
    );
    outcome.with_context(|| {
        format!(
            "strict platform crate Clippy rejected production code: {}",
            String::from_utf8_lossy(&diagnostic)
        )
    })?;
    admit_clippy_diagnostic(&diagnostic)?;
    println!(
        "platform kernel compiler boundary: {} strict crates",
        packages.len()
    );
    Ok(())
}

fn admit_clippy_diagnostic(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_COMPILER_OUTPUT_BYTES,
        "strict compiler diagnostic budget"
    );
    let diagnostic = String::from_utf8_lossy(bytes);
    // Clippy emits invalid configured paths as diagnostics outside its lint
    // machinery. Neither forbid nor -Dwarnings promotes those to errors; admit
    // no compiler warning, so a misspelled restriction cannot silently weaken
    // the boundary. Optional absent third-party paths use allow-invalid=true.
    ensure!(
        !diagnostic.lines().any(|line| line.starts_with("warning:")),
        "strict platform Clippy emitted a warning: {diagnostic}"
    );
    Ok(())
}

fn clippy_command(root: &Path, packages: &[StrictCrate<'_>]) -> Result<Command> {
    let config = root.join("architecture").canonicalize()?;
    let mut command = Command::new("cargo");
    command.current_dir(root).env("CLIPPY_CONF_DIR", config);
    command.args([
        "clippy",
        "--offline",
        "--locked",
        "--jobs=2",
        "--color=never",
        "--lib",
        "--no-deps",
    ]);
    for package in packages {
        command.args(["-p", package.name]);
    }
    pin_lint_flags(&mut command);
    command.args(["--", "--cap-lints=forbid", "-Dwarnings"]);
    Ok(command)
}

fn pin_lint_flags(command: &mut Command) {
    // Cargo's encoded flags replace raw/environment/configured rustflags. An
    // additional cap alone cannot raise an inherited --cap-lints=allow.
    command
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", "--cap-lints=forbid");
}

fn confined_source(root: &Path, source: &str) -> Result<PathBuf> {
    let relative = Path::new(source);
    ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            && relative
                .extension()
                .is_some_and(|extension| extension == "rs"),
        "strict crate source must be a relative Rust path"
    );
    let mut path = root.to_path_buf();
    ensure!(
        fs::symlink_metadata(&path)?.is_dir(),
        "strict platform root must be a directory"
    );
    for component in relative.components() {
        path.push(component);
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "symlink in strict crate source"
        );
    }
    Ok(path)
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular kernel input required"
    );
    ensure!(
        metadata.len() <= MAX_SOURCE_BYTES as u64,
        "kernel input byte budget"
    );
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= MAX_SOURCE_BYTES, "kernel input byte budget");
    Ok(bytes)
}

fn parse_source(path: &Path) -> Result<syn::File> {
    let bytes = read_regular(path)?;
    syn::parse_file(std::str::from_utf8(&bytes)?)
        .with_context(|| format!("parse {}", path.display()))
}

fn collect_sources(path: &Path, sources: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "kernel source depth budget");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "symlink in kernel source tree"
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_sources(&entry?.path(), sources, depth + 1)?;
        }
    } else if path.extension().is_some_and(|extension| extension == "rs") {
        ensure!(metadata.is_file(), "regular kernel Rust source required");
        sources.push(path.to_path_buf());
        ensure!(sources.len() <= MAX_SOURCES, "kernel source count budget");
    }
    Ok(())
}

fn path_name(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn required_attributes(syntax: &syn::File, kernel: bool) -> Result<()> {
    let mut forbids = BTreeSet::new();
    let mut no_std = false;
    for attribute in &syntax.attrs {
        if !matches!(attribute.style, syn::AttrStyle::Inner(_)) {
            continue;
        }
        if matches!(&attribute.meta, Meta::Path(path) if path.is_ident("no_std")) {
            no_std = true;
        }
        if let Meta::List(list) = &attribute.meta
            && list.path.is_ident("forbid")
        {
            for meta in list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)? {
                if let Meta::Path(path) = meta {
                    forbids.insert(path_name(&path));
                }
            }
        }
    }
    for required in REQUIRED_FORBIDS {
        ensure!(
            forbids.contains(required),
            "missing unconditional crate forbid({required})"
        );
    }
    ensure!(
        !kernel || no_std,
        "kernel requires unconditional crate no_std"
    );
    Ok(())
}

fn test_only(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        let Meta::List(list) = &attribute.meta else {
            return false;
        };
        list.path.is_ident("cfg")
            && list
                .parse_args::<Meta>()
                .is_ok_and(|meta| requires_test(&meta))
    })
}

fn requires_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let Ok(parts) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return false;
            };
            if list.path.is_ident("all") {
                parts.iter().any(requires_test)
            } else if list.path.is_ident("any") {
                !parts.is_empty() && parts.iter().all(requires_test)
            } else {
                false
            }
        }
        _ => false,
    }
}

#[derive(Default)]
struct Scope {
    imports: BTreeMap<String, Vec<String>>,
    shadows: BTreeSet<String>,
}

fn imports(tree: &UseTree, prefix: &[String], scope: &mut Scope) {
    match tree {
        UseTree::Path(path) => {
            let mut prefix = prefix.to_vec();
            prefix.push(path.ident.to_string());
            imports(&path.tree, &prefix, scope);
        }
        UseTree::Name(name) => {
            let mut path = prefix.to_vec();
            path.push(name.ident.to_string());
            scope.imports.insert(name.ident.to_string(), path);
        }
        UseTree::Rename(rename) => {
            let mut path = prefix.to_vec();
            path.push(rename.ident.to_string());
            scope.imports.insert(rename.rename.to_string(), path);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                imports(item, prefix, scope);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn scope(items: &[Item]) -> Scope {
    let mut scope = Scope::default();
    for item in items {
        if test_only(item_attributes(item)) {
            continue;
        }
        match item {
            Item::Use(item) if !test_only(&item.attrs) => imports(&item.tree, &[], &mut scope),
            Item::Trait(item) => {
                scope.shadows.insert(item.ident.to_string());
            }
            Item::TraitAlias(item) => {
                scope.shadows.insert(item.ident.to_string());
            }
            _ => {}
        }
    }
    scope
}

struct CallbackCheck {
    scopes: Vec<Scope>,
    violations: BTreeSet<&'static str>,
}

impl CallbackCheck {
    fn callback_trait(&self, bound: &syn::TraitBound) -> bool {
        let mut path: Vec<_> = bound
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let function_syntax =
            bound.path.segments.last().is_some_and(|segment| {
                matches!(segment.arguments, PathArguments::Parenthesized(_))
            });
        // Stable Rust's parenthesized trait arguments denote the Fn family,
        // including reexports whose local names differ from Fn/FnMut/FnOnce.
        if function_syntax {
            return true;
        }
        for _ in 0..MAX_DEPTH {
            let Some(first) = path.first() else {
                return false;
            };
            let binding = self.scopes.iter().rev().find_map(|scope| {
                if scope.shadows.contains(first) {
                    Some(None)
                } else {
                    scope.imports.get(first).map(Some)
                }
            });
            match binding {
                Some(Some(import)) if import != &path => {
                    path = import.iter().chain(path.iter().skip(1)).cloned().collect();
                }
                Some(None) => return false,
                _ => break,
            }
        }
        let Some(last) = path.last().map(String::as_str) else {
            return false;
        };
        let native =
            path.len() == 1 || matches!(path.first().map(String::as_str), Some("std" | "core"));
        native && matches!(last, "Future" | "IntoFuture")
    }
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

impl<'ast> Visit<'ast> for CallbackCheck {
    fn visit_file(&mut self, syntax: &'ast syn::File) {
        if test_only(&syntax.attrs) {
            return;
        }
        self.scopes.push(scope(&syntax.items));
        visit::visit_file(self, syntax);
        self.scopes.pop();
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if test_only(item_attributes(item)) {
            return;
        }
        if let Item::Mod(module) = item
            && module
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("path"))
        {
            self.violations.insert("module path override");
        }
        visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if let Some((_, items)) = &module.content {
            self.scopes.push(scope(items));
            for item in items {
                self.visit_item(item);
            }
            self.scopes.pop();
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attributes: &[Attribute] = match item {
            syn::ImplItem::Const(item) => &item.attrs,
            syn::ImplItem::Fn(item) => &item.attrs,
            syn::ImplItem::Type(item) => &item.attrs,
            syn::ImplItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if !test_only(attributes) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attributes: &[Attribute] = match item {
            syn::TraitItem::Const(item) => &item.attrs,
            syn::TraitItem::Fn(item) => &item.attrs,
            syn::TraitItem::Type(item) => &item.attrs,
            syn::TraitItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if !test_only(attributes) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_type_bare_fn(&mut self, function: &'ast syn::TypeBareFn) {
        self.violations.insert("function pointer");
        visit::visit_type_bare_fn(self, function);
    }

    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if signature.asyncness.is_some() {
            self.violations.insert("async function");
        }
        visit::visit_signature(self, signature);
    }

    fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
        self.violations.insert("async block");
        visit::visit_expr_async(self, expression);
    }

    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        if expression.asyncness.is_some() {
            self.violations.insert("async closure");
        }
        visit::visit_expr_closure(self, expression);
    }

    fn visit_type_param_bound(&mut self, bound: &'ast TypeParamBound) {
        if let TypeParamBound::Trait(bound) = bound
            && self.callback_trait(bound)
        {
            self.violations.insert("callback or future trait");
        }
        visit::visit_type_param_bound(self, bound);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if item.ident == "std" {
            self.violations.insert("explicit std linkage");
        }
    }
}

fn callbacks(syntax: &syn::File) -> Result<()> {
    let mut checker = CallbackCheck {
        scopes: Vec::new(),
        violations: BTreeSet::new(),
    };
    checker.visit_file(syntax);
    if !checker.violations.is_empty() {
        bail!(
            "kernel callback interfaces forbidden: {:?}",
            checker.violations
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admit_clippy_output(output: &std::process::Output) -> Result<()> {
        ensure!(
            output.status.success(),
            "compiler fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        admit_clippy_diagnostic(&output.stderr)
    }

    const ATTRIBUTES: &str = "#![forbid(unsafe_code, clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]\n";
    const CONFIG: &str = include_str!("../../../architecture/clippy.toml");

    fn syntax(body: &str) -> syn::File {
        syn::parse_file(body).unwrap()
    }

    #[test]
    fn requires_literal_unconditional_crate_attributes() {
        assert!(required_attributes(&syntax(ATTRIBUTES), false).is_ok());
        assert!(required_attributes(&syntax(&format!("#![no_std]\n{ATTRIBUTES}")), true).is_ok());
        for required in REQUIRED_FORBIDS {
            let missing = ATTRIBUTES.replace(required, "unused_variables");
            assert!(required_attributes(&syntax(&missing), false).is_err());
        }
        for fake in [
            "// #![no_std]\n",
            "#![cfg_attr(any(), no_std)]\n",
            "#![cfg_attr(all(), no_std)]\n",
        ] {
            assert!(required_attributes(&syntax(&format!("{fake}{ATTRIBUTES}")), true).is_err());
        }
        let conditional = "#![cfg_attr(any(), forbid(unsafe_code, clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros))]";
        assert!(required_attributes(&syntax(conditional), false).is_err());
    }

    #[test]
    fn rejects_callback_shapes_and_imported_trait_aliases() {
        for body in [
            "pub fn apply(callback: fn(u64) -> u64) {}",
            "pub struct State { callback: fn() }",
            "pub fn apply<F: FnOnce()>(callback: F) {}",
            "use core::ops::FnMut as Callback; pub fn apply<F: Callback()>(callback: F) {}",
            "use other::ExportedCallback as Callback; pub fn apply<F: Callback()>(callback: F) {}",
            "pub fn apply<F: core::future::Future>(future: F) {}",
            "use core::future::Future as Work; pub fn apply<F: Work>(future: F) {}",
            "use core::future as jobs; pub fn apply<F: jobs::Future>(future: F) {}",
            "pub fn apply<F: IntoFuture>(future: F) {}",
            "pub async fn apply() {}",
            "pub fn apply() { let _ = async { 1 }; }",
            "pub fn apply() { let _ = async || 1; }",
            "extern crate std;",
            "#[path = \"../../other.rs\"] mod escaped;",
            "#[cfg(test)] trait Future {} pub fn apply<F: Future>(future: F) {}",
        ] {
            assert!(callbacks(&syntax(body)).is_err(), "accepted {body}");
        }
    }

    #[test]
    fn permits_serde_bounds_pure_closures_and_test_only_callbacks() {
        for body in [
            "pub fn fingerprint<T: serde::Serialize>(value: &T) {}",
            "pub fn checked(value: Option<u64>) -> u64 { value.map(|x| x + 1).unwrap_or(0) }",
            "#[cfg(test)] mod tests { pub async fn test() {} }",
            "#[cfg(all(test, feature = \"campaign\"))] fn test(callback: fn()) {}",
            "pub trait Future {} pub fn pure<T: Future>(value: T) {}",
            "mod tests { #[cfg(test)] fn apply(callback: fn()) {} }",
        ] {
            assert!(callbacks(&syntax(body)).is_ok(), "rejected {body}");
        }
        assert!(
            callbacks(&syntax(
                "#[cfg(any(test, feature = \"production\"))] pub async fn apply() {}"
            ))
            .is_err()
        );
    }

    fn fixture() -> Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        fs::create_dir(directory.path().join("src"))?;
        fs::create_dir(directory.path().join("architecture"))?;
        fs::write(directory.path().join("architecture/clippy.toml"), CONFIG)?;
        fs::write(
            directory.path().join("rust-toolchain.toml"),
            include_str!("../../../rust-toolchain.toml"),
        )?;
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname = \"boundary-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n",
        )?;
        fs::write(
            directory.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"boundary-fixture\"\nversion = \"0.0.0\"\n",
        )?;
        Ok(directory)
    }

    fn path_contract_fixture() -> Result<tempfile::TempDir> {
        let directory = fixture()?;
        fs::create_dir(directory.path().join("contract"))?;
        fs::create_dir(directory.path().join("contract/src"))?;
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname = \"boundary-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\nmembers = [\"contract\"]\n[dependencies]\nboundary-contract = { path = \"contract\" }\n",
        )?;
        fs::write(
            directory.path().join("contract/Cargo.toml"),
            "[package]\nname = \"boundary-contract\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        fs::write(
            directory.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"boundary-contract\"\nversion = \"0.0.0\"\n\n[[package]]\nname = \"boundary-fixture\"\nversion = \"0.0.0\"\ndependencies = [\"boundary-contract\"]\n",
        )?;
        // The kernel really compiles as no_std while linking a reviewed strict
        // std contract. Source no_std alone cannot prevent dependency effects.
        fs::write(
            directory.path().join("src/lib.rs"),
            format!(
                "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::pure() }}"
            ),
        )?;
        Ok(directory)
    }

    #[test]
    fn real_clippy_rejects_typed_path_effects_through_strict_contract_dependency() -> Result<()> {
        let fixture = path_contract_fixture()?;
        let packages = [
            StrictCrate {
                name: "boundary-fixture",
                source: "src/lib.rs",
                kernel: true,
            },
            StrictCrate {
                name: "boundary-contract",
                source: "contract/src/lib.rs",
                kernel: false,
            },
        ];
        // Stable standard APIs available before the pinned Rust 1.98.1. PathBuf
        // reaches the same Path definitions through Deref; only lexical path
        // operations remain outside this effect-method vocabulary.
        const METHODS: [(&str, &str); 10] = [
            ("exists", ""),
            ("try_exists", ".is_ok()"),
            ("is_file", ""),
            ("is_dir", ""),
            ("is_symlink", ""),
            ("metadata", ".is_ok()"),
            ("symlink_metadata", ".is_ok()"),
            ("canonicalize", ".is_ok()"),
            ("read_link", ".is_ok()"),
            ("read_dir", ".is_ok()"),
        ];
        let contract = fixture.path().join("contract/src/lib.rs");
        let pure = "pub fn pure() -> bool { let joined = std::path::Path::new(\"data\").join(\"child\"); joined.is_absolute() || joined.components().count() == 2 }";
        fs::write(&contract, format!("{ATTRIBUTES}{pure}"))?;
        check(fixture.path(), &packages)?;
        for (method, result) in METHODS {
            for body in [
                format!(
                    "pub fn pure() -> bool {{ std::path::Path::new(\".\").{method}(){result} }}"
                ),
                format!(
                    "use std::path::Path as Selected; pub fn pure() -> bool {{ Selected::new(\".\").{method}(){result} }}"
                ),
                format!(
                    "use r#std::r#path::r#Path as r#Selected; pub fn pure() -> bool {{ r#Selected::r#new(\".\").r#{method}(){result} }}"
                ),
                format!(
                    "pub fn pure() -> bool {{ std::path::PathBuf::from(\".\").{method}(){result} }}"
                ),
                format!(
                    "fn selected() -> &'static std::path::Path {{ std::path::Path::new(\".\") }} pub fn pure() -> bool {{ selected().{method}(){result} }}"
                ),
                format!(
                    "fn selected() -> std::path::PathBuf {{ std::path::PathBuf::from(\".\") }} pub fn pure() -> bool {{ selected().{method}(){result} }}"
                ),
            ] {
                fs::write(&contract, format!("{ATTRIBUTES}{body}"))?;
                let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
                ensure!(
                    rejection.contains("clippy::disallowed_methods")
                        && rejection.contains(&format!("std::path::Path::{method}")),
                    "wrong typed-path rejection for {body}: {rejection}"
                );
            }
        }
        // absolute is lexical with respect to file entries, but can consult
        // ambient cwd. It is a free standard function, not a Path method.
        for body in [
            "pub fn pure() -> bool { std::path::absolute(\".\").is_ok() }",
            "use std::path::absolute as selected; pub fn pure() -> bool { selected(\".\").is_ok() }",
            "use r#std::r#path::r#absolute as r#selected; pub fn pure() -> bool { r#selected(\".\").is_ok() }",
            "pub fn pure() -> bool { std::path::absolute(std::path::PathBuf::from(\".\")).is_ok() }",
            "fn selected() -> &'static std::path::Path { std::path::Path::new(\".\") } pub fn pure() -> bool { std::path::absolute(selected()).is_ok() }",
            "fn selected() -> std::path::PathBuf { std::path::PathBuf::from(\".\") } pub fn pure() -> bool { std::path::absolute(selected()).is_ok() }",
        ] {
            fs::write(&contract, format!("{ATTRIBUTES}{body}"))?;
            let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
            ensure!(
                rejection.contains("clippy::disallowed_methods")
                    && rejection.contains("std::path::absolute"),
                "wrong absolute-path rejection for {body}: {rejection}"
            );
        }
        // An allowed dependency can return path DATA into an actual no_std
        // caller. Inferred methods there still require compiler enforcement.
        for producer in [
            "pub fn selected() -> &'static std::path::Path { std::path::Path::new(\".\") }",
            "pub fn selected() -> std::path::PathBuf { std::path::PathBuf::from(\".\") }",
        ] {
            fs::write(&contract, format!("{ATTRIBUTES}{producer}"))?;
            for (method, result) in METHODS {
                fs::write(
                    fixture.path().join("src/lib.rs"),
                    format!(
                        "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::selected().{method}(){result} }}"
                    ),
                )?;
                let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
                ensure!(
                    rejection.contains("clippy::disallowed_methods")
                        && rejection.contains(&format!("std::path::Path::{method}")),
                    "wrong no_std returned-path rejection: {rejection}"
                );
            }
            fs::write(
                &contract,
                format!("{ATTRIBUTES}pub use std::path::absolute; {producer}"),
            )?;
            fs::write(
                fixture.path().join("src/lib.rs"),
                format!(
                    "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::absolute(boundary_contract::selected()).is_ok() }}"
                ),
            )?;
            let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
            ensure!(
                rejection.contains("clippy::disallowed_methods")
                    && rejection.contains("std::path::absolute"),
                "wrong no_std absolute-path rejection: {rejection}"
            );
        }
        fs::write(
            fixture.path().join("src/lib.rs"),
            format!(
                "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::pure() }}"
            ),
        )?;
        // ReadDir is an OS iterator, unlike pure Path/Components/Iter data.
        // The type lint covers explicit signatures and named reexports; it
        // does not inspect every inferred local expression's type.
        for body in [
            "pub fn advance(entries: &mut std::fs::ReadDir) -> bool { entries.next().is_some() }",
            "use std::fs::ReadDir as Directory; pub fn advance(entries: &mut Directory) -> bool { entries.next().is_some() }",
            "use r#std::r#fs::r#ReadDir as r#Directory; pub fn advance(entries: &mut r#Directory) -> bool { entries.r#next().is_some() }",
            "pub use std::fs::ReadDir;",
            "pub use std::fs::ReadDir as Directory;",
            "pub type Directory = std::fs::ReadDir;",
        ] {
            fs::write(&contract, format!("{ATTRIBUTES}{pure}\n{body}"))?;
            let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
            ensure!(
                rejection.contains("clippy::disallowed_types")
                    && rejection.contains("std::fs::ReadDir"),
                "wrong directory-iterator type rejection for {body}: {rejection}"
            );
        }
        fs::write(
            &contract,
            format!("{ATTRIBUTES}{pure}\npub use std::fs::ReadDir as Directory;"),
        )?;
        for body in [
            "pub fn advance(entries: &mut boundary_contract::Directory) -> bool { entries.next().is_some() }",
            "use boundary_contract::Directory as Entries; pub fn advance(entries: &mut Entries) -> bool { entries.next().is_some() }",
            "pub fn advance(entries: &mut boundary_contract::r#Directory) -> bool { entries.r#next().is_some() }",
            "pub fn advance(entries: &mut boundary_contract::Directory) -> bool { core::iter::Iterator::next(entries).is_some() }",
            "pub fn advance(entries: boundary_contract::Directory) -> usize { entries.count() }",
            "pub fn advance(entries: boundary_contract::Directory) -> usize { let mut count = 0; for _ in entries { count += 1; } count }",
        ] {
            fs::write(
                fixture.path().join("src/lib.rs"),
                format!(
                    "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::pure() }}\n{body}"
                ),
            )?;
            // Only the actual no_std caller is a lint target in this phase.
            // The contract is compiled as a dependency, so its reexport cannot
            // substitute for a caller's semantic ReadDir type diagnostic.
            let rejection = check(fixture.path(), &packages[..1])
                .unwrap_err()
                .to_string();
            ensure!(
                rejection.contains("clippy::disallowed_types")
                    && rejection.contains("std::fs::ReadDir")
                    && rejection.contains(" --> src/lib.rs:"),
                "wrong no_std supplied-directory rejection for {body}: {rejection}"
            );
        }
        // Selecting the entire strict graph also refuses the contract's native
        // handle exposure, independently of whether a caller advances it.
        fs::write(
            fixture.path().join("src/lib.rs"),
            format!(
                "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::pure() }}"
            ),
        )?;
        let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
        ensure!(
            rejection.contains("clippy::disallowed_types")
                && rejection.contains("std::fs::ReadDir"),
            "strict contract exported a directory iterator: {rejection}"
        );
        // A wholly inferred handle acquired via a reexport is rejected at its
        // already-banned acquisition. This is a method-lint control, not an
        // inferred-type guarantee; known advancement is also source-scanned.
        fs::write(
            &contract,
            format!("{ATTRIBUTES}{pure}\npub use std::fs::read_dir as selected;"),
        )?;
        for body in [
            "pub fn advance() -> bool { let mut entries = boundary_contract::selected(\".\").unwrap(); entries.next().is_some() }",
            "pub fn advance() -> usize { let entries = boundary_contract::selected(\".\").unwrap(); let mut count = 0; for _ in entries { count += 1; } count }",
        ] {
            fs::write(
                fixture.path().join("src/lib.rs"),
                format!(
                    "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::pure() }}\n{body}"
                ),
            )?;
            let rejection = check(fixture.path(), &packages[..1])
                .unwrap_err()
                .to_string();
            ensure!(
                rejection.contains("clippy::disallowed_methods")
                    && rejection.contains("std::fs::read_dir")
                    && rejection.contains(" --> src/lib.rs:"),
                "wrong inferred-directory acquisition rejection for {body}: {rejection}"
            );
        }
        fs::write(
            fixture.path().join("src/lib.rs"),
            format!(
                "#![no_std]\n{ATTRIBUTES}pub fn pure() -> bool {{ boundary_contract::pure() }}"
            ),
        )?;
        for level in ["allow", "expect"] {
            fs::write(
                &contract,
                format!(
                    "{ATTRIBUTES}{pure}\n#[{level}(clippy::disallowed_types)] pub fn advance(entries: &mut std::fs::ReadDir) -> bool {{ entries.next().is_some() }}"
                ),
            )?;
            let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
            ensure!(
                rejection.contains("E0453"),
                "strict contract suppressed its type forbid: {rejection}"
            );
        }
        for level in ["allow", "expect"] {
            fs::write(
                &contract,
                format!(
                    "{ATTRIBUTES}#[{level}(clippy::disallowed_methods)] pub fn pure() -> bool {{ std::path::Path::new(\".\").exists() }}"
                ),
            )?;
            let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
            ensure!(
                rejection.contains("E0453"),
                "strict contract suppressed a forbid: {rejection}"
            );
        }
        // Both policy-selected targets retain forbid and the same pinned
        // compiler flags. Restoring data-only paths must still compile.
        fs::write(&contract, format!("{ATTRIBUTES}{pure}"))?;
        check(fixture.path(), &packages)?;
        Ok(())
    }

    #[test]
    fn rejects_escaped_paths_and_oversized_or_deep_sources() -> Result<()> {
        let fixture = fixture()?;
        fs::write(fixture.path().join("src/lib.rs"), ATTRIBUTES)?;
        assert!(confined_source(fixture.path(), "../src/lib.rs").is_err());
        fs::write(
            fixture.path().join("src/large.rs"),
            vec![b' '; MAX_SOURCE_BYTES + 1],
        )?;
        assert!(parse_source(&fixture.path().join("src/large.rs")).is_err());
        let mut path = fixture.path().join("src");
        for _ in 0..=MAX_DEPTH {
            path = path.join("nested");
            fs::create_dir(&path)?;
        }
        assert!(collect_sources(&fixture.path().join("src"), &mut Vec::new(), 0).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_source_files_and_configuration() -> Result<()> {
        let fixture = fixture()?;
        fs::write(fixture.path().join("src/lib.rs"), ATTRIBUTES)?;
        std::os::unix::fs::symlink("lib.rs", fixture.path().join("src/linked.rs"))?;
        assert!(confined_source(fixture.path(), "src/linked.rs").is_err());
        assert!(collect_sources(&fixture.path().join("src"), &mut Vec::new(), 0).is_err());
        std::os::unix::fs::symlink(
            "clippy.toml",
            fixture.path().join("architecture/linked.toml"),
        )?;
        assert!(read_regular(&fixture.path().join("architecture/linked.toml")).is_err());
        Ok(())
    }

    #[test]
    fn real_clippy_resolves_clock_aliases_and_forbid_rejects_suppression() -> Result<()> {
        let fixture = fixture()?;
        let packages = [StrictCrate {
            name: "boundary-fixture",
            source: "src/lib.rs",
            kernel: false,
        }];
        fs::write(
            fixture.path().join("src/lib.rs"),
            format!("{ATTRIBUTES}pub fn pure(value: u64) -> u64 {{ value }}"),
        )?;
        check(fixture.path(), &packages)?;
        for body in [
            "use std::time::SystemTime as Clock; pub fn ambient() { let _ = Clock::now(); }",
            "use std::time as clock; pub fn ambient() { let _ = clock::SystemTime::now(); }",
        ] {
            fs::write(
                fixture.path().join("src/lib.rs"),
                format!("{ATTRIBUTES}{body}"),
            )?;
            let output = clippy_command(fixture.path(), &packages)?.output()?;
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "compiler accepted aliased clock");
            assert!(
                diagnostic.contains("clippy::disallowed_methods"),
                "wrong rejection: {diagnostic}"
            );
        }
        for (body, expected) in [
            (
                "use std::process::Command as Process; pub struct Effect { pub process: Process }",
                "clippy::disallowed_types",
            ),
            (
                "pub const NAME: &str = env!(\"CARGO_PKG_NAME\");",
                "clippy::disallowed_macros",
            ),
        ] {
            fs::write(
                fixture.path().join("src/lib.rs"),
                format!("{ATTRIBUTES}{body}"),
            )?;
            let output = clippy_command(fixture.path(), &packages)?.output()?;
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success(),
                "compiler accepted forbidden primitive"
            );
            assert!(
                diagnostic.contains(expected),
                "wrong rejection: {diagnostic}"
            );
        }
        fs::write(
            fixture.path().join("src/lib.rs"),
            format!(
                "{ATTRIBUTES}use std::time::SystemTime as Clock; pub fn ambient() {{ let _ = Clock::now(); }}"
            ),
        )?;
        let mut command = clippy_command(fixture.path(), &packages)?;
        command
            .env("RUSTFLAGS", "--cap-lints=allow")
            .env("CARGO_ENCODED_RUSTFLAGS", "--cap-lints=allow");
        pin_lint_flags(&mut command);
        let output = command.output()?;
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "inherited lint cap disabled enforcement"
        );
        assert!(
            diagnostic.contains("clippy::disallowed_methods"),
            "wrong rejection: {diagnostic}"
        );
        for (level, lint) in [
            ("allow", "unsafe_code"),
            ("allow", "clippy::disallowed_methods"),
            ("expect", "unsafe_code"),
            ("expect", "clippy::disallowed_methods"),
        ] {
            fs::write(
                fixture.path().join("src/lib.rs"),
                format!(
                    "{ATTRIBUTES}#[{level}({lint})] pub fn pure(value: u64) -> u64 {{ value }}"
                ),
            )?;
            let output = clippy_command(fixture.path(), &packages)?.output()?;
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "compiler accepted suppression");
            assert!(
                diagnostic.contains("E0453"),
                "wrong rejection: {diagnostic}"
            );
        }
        fs::write(
            fixture.path().join("src/lib.rs"),
            format!("{ATTRIBUTES}pub fn pure(value: u64) -> u64 {{ value }}"),
        )?;
        fs::write(
            fixture.path().join("architecture/clippy.toml"),
            "disallowed-methods = [{ path = \"std::time::SystemTime::misspelled_now\", reason = \"invalid policy must fail\" }]",
        )?;
        let output = clippy_command(fixture.path(), &packages)?.output()?;
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(
            admit_clippy_output(&output).is_err(),
            "guard accepted an invalid policy path: {diagnostic}"
        );
        assert!(
            diagnostic.contains("misspelled_now"),
            "wrong rejection: {diagnostic}"
        );
        let rejection = check(fixture.path(), &packages).unwrap_err().to_string();
        assert!(
            rejection.contains("misspelled_now"),
            "wrong supervised rejection: {rejection}"
        );
        Ok(())
    }
}
