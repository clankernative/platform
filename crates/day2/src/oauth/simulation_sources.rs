//! Compiled source identities and an AST guard against ambient OAuth effects.
//! New modules must join this catalog; test fixtures remain adapter conformance.
use anyhow::{Result, ensure};
use syn::visit::Visit;

pub(super) const SOURCES: &[(&str, &str)] = &[
    ("account.rs", include_str!("account.rs")),
    ("admission", ""),
    ("admission.rs", include_str!("admission.rs")),
    (
        "admission/desired_epochs.rs",
        include_str!("admission/desired_epochs.rs"),
    ),
    ("approval_keys.rs", include_str!("approval_keys.rs")),
    ("approval_registry.rs", include_str!("approval_registry.rs")),
    ("calendar.rs", include_str!("calendar.rs")),
    ("catalog.rs", include_str!("catalog.rs")),
    ("clients.rs", include_str!("clients.rs")),
    ("connect.rs", include_str!("connect.rs")),
    ("custody.rs", include_str!("custody.rs")),
    ("declaration.rs", include_str!("declaration.rs")),
    ("effects.rs", include_str!("effects.rs")),
    ("exchange.rs", include_str!("exchange.rs")),
    ("external.rs", include_str!("external.rs")),
    ("fresh_auth.rs", include_str!("fresh_auth.rs")),
    ("fresh_owner.rs", include_str!("fresh_owner.rs")),
    ("gitlab.rs", include_str!("gitlab.rs")),
    ("google.rs", include_str!("google.rs")),
    ("google_begin.rs", include_str!("google_begin.rs")),
    ("host.rs", include_str!("host.rs")),
    ("inbound.rs", include_str!("inbound.rs")),
    ("live_readiness.rs", include_str!("live_readiness.rs")),
    ("management", ""),
    ("management.rs", include_str!("management.rs")),
    ("management/app.rs", include_str!("management/app.rs")),
    (
        "management/app_native_lifecycle.rs",
        include_str!("management/app_native_lifecycle.rs"),
    ),
    ("management/shell.rs", include_str!("management/shell.rs")),
    ("mod.rs", include_str!("mod.rs")),
    ("native_http", ""),
    ("native_http.rs", include_str!("native_http.rs")),
    (
        "native_http/response_io.rs",
        include_str!("native_http/response_io.rs"),
    ),
    ("native_management", ""),
    ("native_management.rs", include_str!("native_management.rs")),
    (
        "native_management/response.rs",
        include_str!("native_management/response.rs"),
    ),
    ("native_original.rs", include_str!("native_original.rs")),
    ("outbound.rs", include_str!("outbound.rs")),
    ("profiles.rs", include_str!("profiles.rs")),
    ("protocol.rs", include_str!("protocol.rs")),
    (
        "qualification_shell.rs",
        include_str!("qualification_shell.rs"),
    ),
    ("refresh.rs", include_str!("refresh.rs")),
    ("refresh_tests.rs", include_str!("refresh_tests.rs")),
    ("registration.rs", include_str!("registration.rs")),
    (
        "registration_publication.rs",
        include_str!("registration_publication.rs"),
    ),
    (
        "registration_tests.rs",
        include_str!("registration_tests.rs"),
    ),
    ("schema.rs", include_str!("schema.rs")),
    ("security_shell.rs", include_str!("security_shell.rs")),
    ("shell_oidc.rs", include_str!("shell_oidc.rs")),
    ("shell_transport.rs", include_str!("shell_transport.rs")),
    (
        "shell_transport_tests.rs",
        include_str!("shell_transport_tests.rs"),
    ),
    ("simulation.rs", include_str!("simulation.rs")),
    (
        "simulation_inbound.rs",
        include_str!("simulation_inbound.rs"),
    ),
    (
        "simulation_sources.rs",
        include_str!("simulation_sources.rs"),
    ),
    ("store.rs", include_str!("store.rs")),
    ("usage.rs", include_str!("usage.rs")),
    ("workload.rs", include_str!("workload.rs")),
    ("../iap.rs", include_str!("../iap.rs")),
    ("../iap_workload.rs", include_str!("../iap_workload.rs")),
    (
        "../managed_credentials/crypto.rs",
        include_str!("../managed_credentials/crypto.rs"),
    ),
    (
        "../../../day2-capabilities/src/oauth.rs",
        include_str!("../../../day2-capabilities/src/oauth.rs"),
    ),
    ("ops/Verify.roc", include_str!("../../../../ops/Verify.roc")),
    (
        "ops/OAuthRegistration.roc",
        include_str!("../../../../ops/OAuthRegistration.roc"),
    ),
    (
        "sdk/Connection.roc",
        include_str!("../../../../sdk/contracts/Connection.roc"),
    ),
    (
        "sdk/ConnectionAccess.roc",
        include_str!("../../../../sdk/contracts/ConnectionAccess.roc"),
    ),
    (
        "sdk/GoogleCalendar.roc",
        include_str!("../../../../sdk/contracts/GoogleCalendar.roc"),
    ),
    (
        "sdk/GitlabProjects.roc",
        include_str!("../../../../sdk/contracts/GitlabProjects.roc"),
    ),
    ("build/Cargo.lock", include_str!("../../../../Cargo.lock")),
    ("build/Cargo.toml", include_str!("../../../../Cargo.toml")),
    ("build/day2-Cargo.toml", include_str!("../../Cargo.toml")),
    (
        "build/rust-toolchain.toml",
        include_str!("../../../../rust-toolchain.toml"),
    ),
];

#[derive(Default)]
struct Guard {
    violations: Vec<String>,
    native: NativeBoundary,
}

#[derive(Clone, Copy, Default)]
enum NativeBoundary {
    #[default]
    None,
    Original,
    Http,
}

impl Guard {
    fn check(&mut self, segments: &[String]) {
        let path = segments.join("::");
        // Only native owner identity and fixed HTTP executor plumbing. This
        // does not admit a module alias, arbitrary thread work, entropy, time
        // sampling or provider HTTP outside the controlled effect boundary.
        if !matches!(self.native, NativeBoundary::None)
            && matches!(
                path.as_str(),
                "std::thread::ThreadId" | "std::thread::current"
            )
        {
            return;
        }
        if matches!(self.native, NativeBoundary::Http)
            && matches!(
                path.as_str(),
                "std::thread::Builder::new" | "tokio::time::timeout"
            )
        {
            return;
        }
        if segments.iter().any(|segment| {
            matches!(
                segment.as_str(),
                "SystemTime" | "UNIX_EPOCH" | "getrandom" | "SystemRandom" | "OsRng" | "thread_rng"
            )
        }) || path == "std"
            || path == "std::time"
            || path.starts_with("std::time::Instant")
            || path.starts_with("std::thread")
            || path.starts_with("reqwest::blocking")
            || path == "reqwest"
            || path == "tokio"
            || path == "reqwest::Client"
            || path.starts_with("tokio::time")
            || path.starts_with("tokio::task::spawn")
            || path == "tokio::spawn"
            || path == "tokio::task"
            || path == "web_security::random"
            || path.ends_with("::web_security::random")
        {
            self.violations.push(path);
        }
    }

    fn tokens(&mut self, tokens: proc_macro2::TokenStream) {
        use proc_macro2::TokenTree;
        let tokens = tokens.into_iter().collect::<Vec<_>>();
        for (index, token) in tokens.iter().enumerate() {
            match token {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    let mut path = vec![ident.to_string()];
                    let mut cursor = index + 1;
                    while let [
                        TokenTree::Punct(first),
                        TokenTree::Punct(second),
                        TokenTree::Ident(segment),
                        ..,
                    ] = &tokens[cursor..]
                    {
                        if first.as_char() != ':' || second.as_char() != ':' {
                            break;
                        }
                        path.push(segment.to_string());
                        cursor += 3;
                    }
                    self.check(&path);
                }
                _ => (),
            }
        }
    }

    fn imports(&mut self, prefix: &mut Vec<String>, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.imports(prefix, &path.tree);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                self.check(prefix);
                prefix.pop();
            }
            syn::UseTree::Rename(name) => {
                prefix.push(name.ident.to_string());
                self.check(prefix);
                prefix.pop();
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.imports(prefix, item);
                }
            }
            syn::UseTree::Glob(_) => {
                self.check(prefix);
                self.violations.push("unreviewed glob import".into());
            }
        }
    }
}

impl<'ast> Visit<'ast> for Guard {
    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        // Hyper's Timer trait supplies a deadline of this type. Naming that
        // input type neither samples a clock nor admits an Instant constructor.
        if matches!(self.native, NativeBoundary::Http)
            && path.qself.is_none()
            && path
                .path
                .segments
                .iter()
                .map(|part| part.ident.to_string())
                .eq(["std", "time", "Instant"].map(String::from))
        {
            return;
        }
        syn::visit::visit_type_path(self, path);
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        use syn::Item::*;
        let attributes: &[syn::Attribute] = match item {
            Const(i) => &i.attrs,
            Enum(i) => &i.attrs,
            ExternCrate(i) => &i.attrs,
            Fn(i) => &i.attrs,
            ForeignMod(i) => &i.attrs,
            Impl(i) => &i.attrs,
            Macro(i) => &i.attrs,
            Mod(i) => &i.attrs,
            Static(i) => &i.attrs,
            Struct(i) => &i.attrs,
            Trait(i) => &i.attrs,
            TraitAlias(i) => &i.attrs,
            Type(i) => &i.attrs,
            Union(i) => &i.attrs,
            Use(i) => &i.attrs,
            _ => &[],
        };
        if test_only(attributes) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.check(
            &path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>(),
        );
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.imports(&mut Vec::new(), &item.tree);
    }

    fn visit_macro(&mut self, macro_: &'ast syn::Macro) {
        self.tokens(macro_.tokens.clone());
        syn::visit::visit_macro(self, macro_);
    }

    fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
        if !test_only(&method.attrs) {
            syn::visit::visit_impl_item_fn(self, method);
        }
    }
}

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| matches!(&attribute.meta, syn::Meta::List(list) if list.path.is_ident("cfg") && list.tokens.to_string() == "test"))
}

#[test]
fn ambient_macro_effects_and_namespace_aliases_cannot_bypass_the_guard() -> Result<()> {
    for source in [
        "fn f() { ensure!(std::time::Instant::now() < limit); }",
        "use std::time as clock; fn f() { clock::Instant::now(); }",
        "fn f() { format!(\"{}\", getrandom::fill(&mut bytes)); }",
        "use reqwest::blocking as wire; fn f() { wire::Client::new(); }",
        "fn f() { crate::web_security::random(); }",
        "use crate::web_security::random as nonce; fn f() { nonce(); }",
    ] {
        let mut guard = Guard::default();
        guard.visit_file(&syn::parse_file(source)?);
        ensure!(
            !guard.violations.is_empty(),
            "ambient effect guard was bypassed"
        );
    }
    let mut guard = Guard::default();
    guard.visit_file(&syn::parse_file(
        "#[cfg(test)] mod tests { fn f() { std::time::SystemTime::now(); } }",
    )?);
    ensure!(
        guard.violations.is_empty(),
        "native test fixtures are not production effects"
    );
    for boundary in [NativeBoundary::Original, NativeBoundary::Http] {
        for source in [
            "use std::thread as worker; fn f() { worker::sleep(delay); }",
            "fn f() { std::thread::sleep(delay); }",
            "fn f() { tokio::spawn(work); }",
            "fn f() { reqwest::blocking::Client::new(); }",
            "fn f() { std::time::SystemTime::now(); }",
            "fn f() { std::time::Instant::now(); }",
            "use std::time::Instant as Clock; fn f() { Clock::now(); }",
        ] {
            let mut guard = Guard {
                native: boundary,
                ..Guard::default()
            };
            guard.visit_file(&syn::parse_file(source)?);
            ensure!(
                !guard.violations.is_empty(),
                "native owner exception escaped its fixed ports"
            );
        }
    }
    let mut timer = Guard {
        native: NativeBoundary::Http,
        ..Guard::default()
    };
    timer.visit_file(&syn::parse_file(
        "fn timer(deadline: std::time::Instant) {}",
    )?);
    ensure!(
        timer.violations.is_empty(),
        "Hyper deadline input type refused"
    );
    Ok(())
}

#[test]
fn every_oauth_module_uses_the_controlled_effect_boundary() -> Result<()> {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/oauth");
    let mut files = std::fs::read_dir(&directory)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 OAuth source"))
        })
        .collect::<Result<Vec<_>>>()?;
    files.sort();
    let expected = SOURCES
        .iter()
        .filter(|(name, _)| !name.contains('/'))
        .map(|(name, _)| name.to_string())
        .collect::<Vec<_>>();
    ensure!(
        files == expected,
        "OAuth source catalog changed; add effect guard and replay identity coverage"
    );
    for (name, expected) in [
        ("admission", &["desired_epochs.rs"][..]),
        (
            "management",
            &["app.rs", "app_native_lifecycle.rs", "shell.rs"][..],
        ),
        ("native_http", &["response_io.rs"][..]),
        ("native_management", &["response.rs"][..]),
    ] {
        let mut children = std::fs::read_dir(directory.join(name))?
            .map(|entry| {
                entry?
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF8 {name} source"))
            })
            .collect::<Result<Vec<_>>>()?;
        children.sort();
        ensure!(
            children
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied()),
            "OAuth {name} source catalog changed"
        );
    }
    for &(name, source) in SOURCES {
        if matches!(
            name,
            "effects.rs"
                | "simulation.rs"
                | "simulation_sources.rs"
                | "simulation_inbound.rs"
                | "refresh_tests.rs"
                | "registration_tests.rs"
                | "shell_transport_tests.rs"
                | "management/app_native_lifecycle.rs"
        ) || name.contains("day2-capabilities")
            || !name.ends_with(".rs")
        {
            continue;
        }
        let parsed = syn::parse_file(source)?;
        let mut guard = Guard {
            native: match name {
                "native_http.rs" => NativeBoundary::Http,
                "native_original.rs" | "native_http/response_io.rs" => NativeBoundary::Original,
                _ => NativeBoundary::None,
            },
            ..Guard::default()
        };
        if name.ends_with("managed_credentials/crypto.rs") {
            // Shared credential crypto has unrelated operations. OAuth's
            // sealing function is the covered boundary, including its nonce.
            let method = parsed
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Impl(block) => Some(block),
                    _ => None,
                })
                .flat_map(|block| block.items.iter())
                .find_map(|item| match item {
                    syn::ImplItem::Fn(function) if function.sig.ident == "seal_oauth" => {
                        Some(function)
                    }
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!("OAuth sealing boundary missing"))?;
            guard.visit_impl_item_fn(method);
        } else {
            guard.visit_file(&parsed);
        }
        ensure!(
            guard.violations.is_empty(),
            "ambient OAuth effects in {name}: {:?}",
            guard.violations
        );
    }
    Ok(())
}
