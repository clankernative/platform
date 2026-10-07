//! Test-only accidental-drift guard; the central architecture/compiler guards
//! remain complementary. This scanner resolves explicit imports, not arbitrary
//! dependency macros or type-directed method dispatch.

use std::collections::{BTreeMap, BTreeSet};
use syn::visit::{self, Visit};

#[derive(Default)]
struct Guard {
    aliases: BTreeMap<String, String>,
    function: String,
    crypto: bool,
    violations: Vec<String>,
}

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && matches!(&attribute.meta, syn::Meta::List(meta) if meta.tokens.to_string() == "test")
    })
}

fn imported(tree: &syn::UseTree, prefix: String, aliases: &mut BTreeMap<String, String>) {
    match tree {
        syn::UseTree::Path(path) => {
            imported(&path.tree, format!("{prefix}{}::", path.ident), aliases)
        }
        syn::UseTree::Name(name) => {
            let target = if name.ident == "self" {
                prefix.trim_end_matches("::").into()
            } else {
                format!("{prefix}{}", name.ident)
            };
            let alias = target.rsplit("::").next().unwrap().to_owned();
            if aliases
                .get(&alias)
                .is_some_and(|previous| previous != &target)
            {
                // Conflicting conditional imports cannot overwrite an effect
                // alias with an apparently innocent target.
                aliases.insert(alias, "forbidden-alias-conflict".into());
            } else {
                aliases.insert(alias, target);
            }
        }
        syn::UseTree::Rename(rename) => {
            let alias = rename.rename.to_string();
            let target = format!("{prefix}{}", rename.ident);
            if aliases
                .get(&alias)
                .is_some_and(|previous| previous != &target)
            {
                aliases.insert(alias, "forbidden-alias-conflict".into());
            } else {
                aliases.insert(alias, target);
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                imported(item, prefix.clone(), aliases);
            }
        }
        syn::UseTree::Glob(_) => {
            aliases.insert("*".into(), prefix);
        }
    }
}

fn ambient(target: &str) -> bool {
    target.starts_with("getrandom::")
        || target.starts_with("rand::")
        || target.starts_with("rand_core::")
        || target.starts_with("fastrand::")
        || target.starts_with("std::time::SystemTime")
        || target.starts_with("std::time::Instant")
        || target.starts_with("tokio::time::")
        || target.starts_with("chrono::")
        || target.starts_with("uuid::Uuid::new_")
        || matches!(
            target,
            "std::thread::sleep"
                | "std::thread::spawn"
                | "tokio::spawn"
                | "tokio::task::spawn_blocking"
                | "crate::web_security::random"
                | "web_security::random"
        )
        || target == "forbidden-alias-conflict"
}

impl Guard {
    fn resolved(&self, path: &syn::Path) -> String {
        let mut segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string());
        let Some(first) = segments.next() else {
            return String::new();
        };
        let mut target = self.aliases.get(&first).cloned().unwrap_or(first);
        // A conflicting origin stays forbidden for every associated path;
        // appending a member must not turn this marker into an innocent name.
        if target == "forbidden-alias-conflict" {
            return target;
        }
        for segment in segments {
            target.push_str("::");
            target.push_str(&segment);
        }
        target
    }

    fn scan(mut self, source: &str) -> Vec<String> {
        let file = syn::parse_file(source).unwrap();
        self.visit_file(&file);
        self.violations
    }
}

impl<'ast> Visit<'ast> for Guard {
    fn visit_file(&mut self, file: &'ast syn::File) {
        // Rust imports apply throughout their lexical module, even if written
        // after the function that invokes them.
        for item in &file.items {
            if let syn::Item::Use(import) = item {
                self.visit_item_use(import);
            }
        }
        visit::visit_file(self, file);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !test_only(&item.attrs) {
            imported(&item.tree, String::new(), &mut self.aliases);
            if self.aliases.get("*").is_some_and(|target| ambient(target)) {
                self.violations.push("ambient glob import".into());
            }
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !test_only(&item.attrs) {
            let saved = self.aliases.clone();
            if let Some((_, items)) = &item.content {
                for child in items {
                    if let syn::Item::Use(import) = child {
                        self.visit_item_use(import);
                    }
                }
            }
            visit::visit_item_mod(self, item);
            self.aliases = saved;
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            let saved_function = std::mem::replace(&mut self.function, item.sig.ident.to_string());
            let saved_aliases = self.aliases.clone();
            visit::visit_item_fn(self, item);
            self.function = saved_function;
            self.aliases = saved_aliases;
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !test_only(&item.attrs) {
            let saved = std::mem::replace(&mut self.function, item.sig.ident.to_string());
            visit::visit_impl_item_fn(self, item);
            self.function = saved;
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let target = self.resolved(path);
        let oauth_entropy = target.ends_with("oauth::effects::fill");
        if ambient(&target) || (oauth_entropy && !(self.crypto && self.function == "seal_oauth")) {
            self.violations.push(target);
        }
        visit::visit_path(self, path);
    }
}

const REVIEWED_SOURCES: &[&str] = &[
    "authority.rs",
    "browser.rs",
    "crypto.rs",
    "effects.rs",
    "effects_guard.rs",
    "ingress.rs",
    "issuance.rs",
    "lifecycle.rs",
    "mod.rs",
    "simulation.rs",
    "store.rs",
    "verification.rs",
];

fn reviewed_sources_match(sources: impl IntoIterator<Item = String>) -> bool {
    sources.into_iter().collect::<BTreeSet<_>>()
        == REVIEWED_SOURCES
            .iter()
            .map(|source| (*source).to_owned())
            .collect()
}

#[test]
fn extra_credential_sources_cannot_bypass_the_effect_guard() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/managed_credentials");
    let sources = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            assert!(
                entry.file_type().unwrap().is_file(),
                "credential source must be a regular file"
            );
            entry.file_name().into_string().unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        reviewed_sources_match(sources.clone()),
        "unreviewed credential source inventory: {sources:?}"
    );
    let mut extra = sources;
    extra.push("ambient_escape.rs".into());
    assert!(!reviewed_sources_match(extra));
}

#[test]
fn managed_credential_ambient_effects_are_confined_to_the_reviewed_adapter() {
    for (name, source) in [
        ("mod", include_str!("mod.rs")),
        ("authority", include_str!("authority.rs")),
        ("browser", include_str!("browser.rs")),
        ("crypto", include_str!("crypto.rs")),
        ("ingress", include_str!("ingress.rs")),
        ("issuance", include_str!("issuance.rs")),
        ("lifecycle", include_str!("lifecycle.rs")),
        ("store", include_str!("store.rs")),
        ("verification", include_str!("verification.rs")),
    ] {
        let violations = Guard {
            crypto: name == "crypto",
            ..Guard::default()
        }
        .scan(source);
        assert!(
            violations.is_empty(),
            "credential ambient effects escaped in {name}: {violations:?}"
        );
    }
}

#[test]
fn the_source_guard_rejects_aliased_clock_entropy_and_scheduling() {
    for source in [
        "use std::time::SystemTime as Clock; fn f() { Clock::now(); }",
        "use std::time as time; fn f() { time::Instant::now(); }",
        "use getrandom::fill as entropy; fn f() { entropy(&mut [0; 32]); }",
        "fn f() { entropy(&mut [0; 32]); } use getrandom::fill as entropy;",
        "use crate::web_security as security; fn f() { security::random(); }",
        "use tokio::task::spawn_blocking as spawn; fn f() { spawn(|| ()); }",
        "fn f() { tokio::time::sleep(std::time::Duration::ZERO); }",
        "fn f() { crate::oauth::effects::fill(&mut [0; 32]); }",
        "#[cfg(unix)] use std::time::SystemTime as Clock; #[cfg(windows)] use fixture::Clock; fn f() { Clock::now(); }",
    ] {
        assert!(
            !Guard::default().scan(source).is_empty(),
            "guard accepted {source}"
        );
    }
    assert!(
        Guard::default()
            .scan(
                "fn f() { super::effects::wall_time(); super::effects::fill_secret(&mut [0; 32]); }"
            )
            .is_empty()
    );
    assert!(
        Guard {
            crypto: true,
            ..Guard::default()
        }
        .scan("impl Lease { fn seal_oauth() { crate::oauth::effects::fill(&mut [0; 12]); } }")
        .is_empty()
    );
    assert!(
        !Guard {
            crypto: true,
            ..Guard::default()
        }
        .scan("fn prepare_managed() { crate::oauth::effects::fill(&mut [0; 32]); }")
        .is_empty()
    );
}

#[test]
fn conditional_alias_conflicts_remain_forbidden_through_path_suffixes() {
    for source in [
        "#[cfg(windows)] use fixture::Clock; #[cfg(unix)] use std::time::SystemTime as Clock; fn f() { Clock::now(); }",
        "#[cfg(unix)] use std::time as clock; #[cfg(windows)] use fixture::clock; fn f() { clock::Instant::now(); }",
        "#[cfg(unix)] use std::time::{Instant as Clock}; #[cfg(windows)] use fixture::{Clock}; fn f() { Clock::now(); }",
        "fn f() { #[cfg(unix)] use std::time::Instant as Clock; #[cfg(windows)] use fixture::Clock; Clock::now(); }",
    ] {
        let violations = Guard::default().scan(source);
        assert!(
            violations
                .iter()
                .any(|target| target == "forbidden-alias-conflict"),
            "conflict lost through path suffix: {source}: {violations:?}"
        );
    }
    for source in [
        "use std::time::Duration as Clock; fn f() { Clock::from_secs(1); }",
        "mod fixture { pub struct Clock; impl Clock { pub fn now() {} } } use fixture::Clock as forbidden_alias_conflict; fn f() { forbidden_alias_conflict::now(); }",
        "mod fixture { pub mod forbidden_alias_conflict { pub fn now() {} } } use fixture::forbidden_alias_conflict as Clock; fn f() { Clock::now(); }",
        "mod fixture { pub struct Clock; impl Clock { pub fn now() {} } } #[cfg(unix)] use fixture::Clock; #[cfg(windows)] use fixture::Clock; fn f() { Clock::now(); }",
    ] {
        let violations = Guard::default().scan(source);
        assert!(
            violations.is_empty(),
            "guard refused a pure alias: {source}: {violations:?}"
        );
    }
}
