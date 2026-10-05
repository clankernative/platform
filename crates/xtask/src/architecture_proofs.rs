//! Reviewed owning-module APIs, private fields and consuming receivers prevent
//! accidental authority-handle construction and wire/clone escapes. Known direct
//! construction sites and proof-returning factory signatures require admission.
//! Compiler trait assertions complement this syntax guard. It does not establish
//! authorization semantics inside admitted factories or expand macros/resolve
//! arbitrary external aliases; protected operations still validate current facts.

use anyhow::{Context, Result, ensure};
use quote::{ToTokens, quote};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::Path};
use syn::{Item, Type, Visibility, punctuated::Punctuated, token::Comma, visit::Visit};

const POLICY: &str = "architecture-proofs.json";
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Readiness,
    Consuming,
    SecretPermit,
}

impl Kind {
    fn permits_derive(self, name: &str) -> bool {
        match self {
            Self::Readiness => ["Clone", "Debug", "PartialEq", "Eq"].contains(&name),
            Self::Consuming => ["Debug"].contains(&name),
            Self::SecretPermit => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    source: String,
    type_name: String,
    kind: Kind,
    consuming_methods: Vec<String>,
    methods: Vec<String>,
    factories: Vec<Factory>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Factory {
    owner: Option<String>,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    proofs: Vec<Proof>,
    #[serde(default)]
    trait_checks: Vec<TraitCheck>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum TraitScope {
    Module,
    Const,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TraitCheck {
    source: String,
    scope: TraitScope,
    fingerprint: String,
    registration: Option<Registration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    source: String,
    module: String,
}

#[derive(Serialize)]
pub struct TraitCheckFinding {
    source: String,
    scope: TraitScope,
    fingerprint: String,
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular proof input required"
    );
    ensure!(
        metadata.len() <= MAX_BYTES as u64,
        "proof input byte budget"
    );
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= MAX_BYTES, "proof input byte budget");
    Ok(bytes)
}

fn source_path(root: &Path, source: &str) -> Result<std::path::PathBuf> {
    let mut path = root.to_path_buf();
    let relative = Path::new(source);
    for component in relative.components() {
        path.push(component);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "proof source symlink forbidden"
        );
        if path != root.join(relative) {
            ensure!(metadata.is_dir(), "proof source parent must be a directory");
        }
    }
    Ok(path)
}

fn validate_policy(policy: &Policy) -> Result<()> {
    ensure!(policy.version == 1, "unsupported proof policy version");
    ensure!(
        !policy.proofs.is_empty() && policy.proofs.len() <= 128,
        "proof policy entry budget"
    );
    let mut identities = BTreeSet::new();
    for proof in &policy.proofs {
        let path = Path::new(&proof.source);
        ensure!(
            path.starts_with("crates")
                && path.extension().is_some_and(|value| value == "rs")
                && path
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_))),
            "invalid proof source"
        );
        ensure!(
            syn::parse_str::<syn::Ident>(&proof.type_name).is_ok(),
            "invalid proof type name"
        );
        ensure!(
            identities.insert((&proof.source, &proof.type_name)),
            "duplicate proof policy entry"
        );
        ensure!(proof.consuming_methods.len() <= 16, "proof method budget");
        ensure!(
            proof
                .consuming_methods
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "proof methods must be unique and sorted"
        );
        ensure!(
            proof
                .consuming_methods
                .iter()
                .all(|name| syn::parse_str::<syn::Ident>(name).is_ok()),
            "invalid consuming method name"
        );
        ensure!(
            matches!(proof.kind, Kind::Readiness) || !proof.consuming_methods.is_empty(),
            "consuming proof must identify its consuming sink"
        );
        ensure!(
            proof.methods.len() <= 32 && proof.factories.len() <= 32,
            "proof API budget"
        );
        let methods = reviewed_methods(proof)?;
        ensure!(
            proof
                .consuming_methods
                .iter()
                .all(|name| methods.contains_key(name)),
            "consuming sink must be a reviewed method"
        );
        reviewed_factories(proof)?;
    }
    ensure!(
        policy.trait_checks.len() <= 16,
        "trait check catalog budget"
    );
    let mut sources = BTreeSet::new();
    for check in &policy.trait_checks {
        ensure!(
            sources.insert(&check.source),
            "duplicate trait check source"
        );
        ensure!(
            check.fingerprint.starts_with("sha256:")
                && check.fingerprint.len() == 71
                && check.fingerprint[7..]
                    .bytes()
                    .all(|value| value.is_ascii_hexdigit()),
            "invalid trait check fingerprint"
        );
        if let Some(registration) = &check.registration {
            syn::parse_str::<syn::Ident>(&registration.module)?;
        }
    }
    Ok(())
}

fn parse_source(root: &Path, source: &str) -> Result<syn::File> {
    let relative = Path::new(source);
    ensure!(
        relative.starts_with("crates")
            && relative
                .extension()
                .is_some_and(|extension| extension == "rs")
            && relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "invalid trait check source"
    );
    let path = source_path(root, source)?;
    ensure!(
        path.canonicalize()?.starts_with(root),
        "trait source leaves platform root"
    );
    let bytes = read_regular(&path)?;
    Ok(syn::parse_file(std::str::from_utf8(&bytes)?)?)
}

fn trait_check_finding(root: &Path, check: &TraitCheck) -> Result<TraitCheckFinding> {
    let syntax = parse_source(root, &check.source)?;
    ensure!(
        syntax
            .attrs
            .iter()
            .all(|attribute| attribute.path().is_ident("doc")),
        "trait check source must compile unconditionally"
    );
    if let Some(registration) = &check.registration {
        let library = parse_source(root, &registration.source)?;
        let registrations: Vec<_> = library
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(module) if module.ident == registration.module => Some(module),
                _ => None,
            })
            .collect();
        ensure!(
            registrations.len() == 1
                && registrations[0].attrs.is_empty()
                && registrations[0].content.is_none()
                && matches!(registrations[0].vis, Visibility::Inherited),
            "selected trait module requires unconditional private registration"
        );
        ensure!(
            Path::new(&registration.source)
                .parent()
                .map(|parent| parent.join(format!("{}.rs", registration.module)))
                .as_deref()
                == Some(Path::new(&check.source)),
            "trait module registration must name its exact source"
        );
    }
    let tokens = match check.scope {
        TraitScope::Module => {
            ensure!(
                syntax.items.iter().all(|item| match item {
                    Item::Macro(item) => item.attrs.is_empty(),
                    Item::Const(item) => item.attrs.is_empty(),
                    _ => false,
                }),
                "selected trait module must contain unconditional macros and const checks"
            );
            ensure!(
                syntax
                    .items
                    .iter()
                    .any(|item| matches!(item, Item::Const(_))),
                "selected trait module requires const checks"
            );
            let items = &syntax.items;
            quote!(#(#items)*)
        }
        TraitScope::Const => {
            let checks: Vec<_> = syntax.items.iter().filter_map(|item| {
                let Item::Const(item) = item else { return None; };
                let syn::Expr::Block(block) = item.expr.as_ref() else { return None; };
                block.block.stmts.iter().any(|statement| matches!(statement,
                    syn::Stmt::Item(Item::Macro(definition)) if definition.ident.as_ref().is_some_and(|name| name == "assert_not_impl")
                )).then_some(item)
            }).collect();
            ensure!(
                checks.len() == 1 && checks[0].attrs.is_empty(),
                "selected trait const must compile unconditionally"
            );
            checks[0].to_token_stream()
        }
    };
    Ok(TraitCheckFinding {
        source: check.source.clone(),
        scope: check.scope,
        fingerprint: day2::digest(tokens.to_string().as_bytes()),
    })
}

/// Read-only normalized assertion facts for explicit policy review.
pub fn trait_check_inventory(root: &Path) -> Result<Vec<TraitCheckFinding>> {
    let root = root.canonicalize()?;
    let policy: Policy = day2::json::decode_evidence(&read_regular(&root.join(POLICY))?)?;
    validate_policy(&policy)?;
    policy
        .trait_checks
        .iter()
        .map(|check| trait_check_finding(&root, check))
        .collect()
}

fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Reference(reference) => return type_name(&reference.elem),
        Type::Paren(parenthesized) => return type_name(&parenthesized.elem),
        Type::Group(group) => return type_name(&group.elem),
        _ => {}
    }
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn signature(visibility: &Visibility, signature: &syn::Signature) -> String {
    let mut signature = signature.clone();
    // Rustfmt's trailing parameter commas do not change the admitted API.
    signature.inputs = signature.inputs.into_iter().collect();
    signature.generics.params = signature.generics.params.into_iter().collect();
    quote!(#visibility #signature).to_string()
}

fn parse_signature(source: &str) -> Result<syn::ImplItemFn> {
    ensure!(source.len() <= 4096, "proof signature byte budget");
    let method: syn::ImplItemFn = syn::parse_str(&format!("{source} {{}}"))?;
    ensure!(
        method.attrs.is_empty(),
        "proof signatures cannot contain conditional attributes"
    );
    Ok(method)
}

fn reviewed_methods(proof: &Proof) -> Result<std::collections::BTreeMap<String, String>> {
    let mut methods = std::collections::BTreeMap::new();
    for reviewed in &proof.methods {
        let method = parse_signature(reviewed)?;
        ensure!(
            methods
                .insert(
                    method.sig.ident.to_string(),
                    signature(&method.vis, &method.sig)
                )
                .is_none(),
            "duplicate reviewed proof method"
        );
    }
    Ok(methods)
}

fn reviewed_factories(proof: &Proof) -> Result<BTreeSet<(Option<String>, String)>> {
    let mut factories = BTreeSet::new();
    for reviewed in &proof.factories {
        if let Some(owner) = &reviewed.owner {
            syn::parse_str::<Type>(owner).context("invalid proof factory owner")?;
        }
        let method = parse_signature(&reviewed.signature)?;
        ensure!(
            factories.insert((reviewed.owner.clone(), signature(&method.vis, &method.sig))),
            "duplicate reviewed proof factory"
        );
    }
    Ok(factories)
}

fn contains_proof(ty: &Type, proof: &str, self_is_proof: bool) -> bool {
    struct Finder<'a> {
        proof: &'a str,
        self_is_proof: bool,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
            if ty.path.segments.last().is_some_and(|segment| {
                segment.ident == self.proof || (self.self_is_proof && segment.ident == "Self")
            }) {
                self.found = true;
            }
            syn::visit::visit_type_path(self, ty);
        }
    }
    let mut finder = Finder {
        proof,
        self_is_proof,
        found: false,
    };
    finder.visit_type(ty);
    finder.found
}

fn constructs_proof(block: &syn::Block, proof: &str, self_is_proof: bool, tuple: bool) -> bool {
    struct Finder<'a> {
        proof: &'a str,
        self_is_proof: bool,
        tuple: bool,
        found: bool,
    }
    impl Finder<'_> {
        fn matches(&self, path: &syn::Path) -> bool {
            path.segments.last().is_some_and(|segment| {
                segment.ident == self.proof || (self.self_is_proof && segment.ident == "Self")
            })
        }
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
            self.found |= self.matches(&value.path);
            syn::visit::visit_expr_struct(self, value);
        }
        fn visit_expr_path(&mut self, value: &'ast syn::ExprPath) {
            self.found |= self.tuple && self.matches(&value.path);
            syn::visit::visit_expr_path(self, value);
        }
    }
    let mut finder = Finder {
        proof,
        self_is_proof,
        tuple,
        found: false,
    };
    finder.visit_block(block);
    finder.found
}

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute.meta.to_token_stream().to_string() == "cfg (test)"
    })
}

fn uses_proof_alias(tree: &syn::UseTree, proof: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => uses_proof_alias(&path.tree, proof),
        syn::UseTree::Rename(rename) => rename.ident == proof,
        syn::UseTree::Group(group) => group.items.iter().any(|item| uses_proof_alias(item, proof)),
        _ => false,
    }
}

fn inspect_factories(
    proof: &Proof,
    items: &[Item],
    nested: bool,
    tuple: bool,
    reviewed: &BTreeSet<(Option<String>, String)>,
    found: &mut BTreeSet<(Option<String>, String)>,
) -> Result<()> {
    let inspect_function = |owner: Option<String>,
                            visibility: &Visibility,
                            sig: &syn::Signature,
                            body: &syn::Block,
                            found: &mut BTreeSet<_>|
     -> Result<()> {
        let self_is_proof = owner.as_deref() == Some(&proof.type_name);
        let returns_proof = match &sig.output {
            syn::ReturnType::Default => false,
            syn::ReturnType::Type(_, ty) => contains_proof(ty, &proof.type_name, self_is_proof),
        };
        if !returns_proof && !constructs_proof(body, &proof.type_name, self_is_proof, tuple) {
            return Ok(());
        }
        ensure!(
            !nested,
            "proof factories must remain in the reviewed owning module"
        );
        let identity = (owner, signature(visibility, sig));
        ensure!(
            reviewed.contains(&identity),
            "unreviewed proof factory {}::{}, signature {}",
            proof.type_name,
            sig.ident,
            identity.1
        );
        ensure!(found.insert(identity), "ambiguous proof factory");
        Ok(())
    };
    for item in items {
        match item {
            Item::Type(alias) if contains_proof(&alias.ty, &proof.type_name, false) => {
                anyhow::bail!("proof aliases require an explicit boundary review");
            }
            Item::Use(import) if uses_proof_alias(&import.tree, &proof.type_name) => {
                anyhow::bail!("proof import aliases require an explicit boundary review");
            }
            Item::Const(value) if !test_only(&value.attrs) => {
                let expression = &value.expr;
                let block: syn::Block = syn::parse_quote!({ #expression });
                ensure!(
                    !contains_proof(&value.ty, &proof.type_name, false)
                        && !constructs_proof(&block, &proof.type_name, false, tuple),
                    "proof values require a reviewed function factory"
                );
            }
            Item::Static(value) if !test_only(&value.attrs) => {
                let expression = &value.expr;
                let block: syn::Block = syn::parse_quote!({ #expression });
                ensure!(
                    !contains_proof(&value.ty, &proof.type_name, false)
                        && !constructs_proof(&block, &proof.type_name, false, tuple),
                    "proof values require a reviewed function factory"
                );
            }
            Item::Fn(function) if !test_only(&function.attrs) => {
                inspect_function(None, &function.vis, &function.sig, &function.block, found)?;
            }
            Item::Impl(implementation) if !test_only(&implementation.attrs) => {
                let owner = implementation.self_ty.to_token_stream().to_string();
                for member in &implementation.items {
                    if let syn::ImplItem::Fn(function) = member
                        && !test_only(&function.attrs)
                    {
                        inspect_function(
                            Some(owner.clone()),
                            &function.vis,
                            &function.sig,
                            &function.block,
                            found,
                        )?;
                    }
                }
            }
            Item::Mod(module) if !test_only(&module.attrs) => {
                if let Some((_, items)) = &module.content {
                    inspect_factories(proof, items, true, tuple, reviewed, found)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn inspect(proof: &Proof, items: &[Item]) -> Result<()> {
    // The configured definition lives at its owning module's top level. Moving
    // it behind a macro, alias or conditional wrapper requires explicit review.
    let declarations: Vec<_> = items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(value) if value.ident == proof.type_name => Some(value),
            _ => None,
        })
        .collect();
    ensure!(
        declarations.len() == 1,
        "configured proof {} must have one explicit owning definition",
        proof.type_name
    );
    let definition = declarations[0];
    ensure!(
        !definition.fields.is_empty(),
        "proof {} cannot become a freely constructible unit type",
        proof.type_name
    );
    ensure!(
        definition
            .fields
            .iter()
            .all(|field| matches!(field.vis, Visibility::Inherited)),
        "proof {} fields must be private to their owning module",
        proof.type_name
    );
    for attribute in &definition.attrs {
        ensure!(
            !attribute.path().is_ident("cfg_attr"),
            "proof attributes cannot hide conditional derives"
        );
        if attribute.path().is_ident("derive") {
            let derives =
                attribute.parse_args_with(Punctuated::<syn::Path, Comma>::parse_terminated)?;
            for derive in derives {
                let name = derive
                    .segments
                    .last()
                    .context("proof derive name")?
                    .ident
                    .to_string();
                ensure!(
                    proof.kind.permits_derive(&name),
                    "proof {} cannot derive {name}",
                    proof.type_name
                );
            }
        }
    }
    let mut found_methods = BTreeSet::new();
    let methods = reviewed_methods(proof)?;
    for item in items {
        let Item::Impl(implementation) = item else {
            continue;
        };
        if type_name(&implementation.self_ty).as_deref() != Some(&proof.type_name) {
            continue;
        }
        ensure!(
            implementation.trait_.is_none(),
            "proof {} cannot gain a manual trait implementation",
            proof.type_name
        );
        for item in &implementation.items {
            let syn::ImplItem::Fn(function) = item else {
                continue;
            };
            let name = function.sig.ident.to_string();
            ensure!(
                methods.get(&name) == Some(&signature(&function.vis, &function.sig)),
                "unreviewed proof method {}::{name}",
                proof.type_name
            );
            ensure!(
                found_methods.insert(name.clone()),
                "ambiguous proof method {name}"
            );
            if !proof.consuming_methods.contains(&name) {
                continue;
            }
            let receiver = function
                .sig
                .receiver()
                .context("proof sink requires self")?;
            ensure!(
                receiver.reference.is_none() && receiver.colon_token.is_none(),
                "proof sink {}::{name} must consume self by value",
                proof.type_name
            );
            ensure!(
                function.sig.asyncness.is_none(),
                "proof consumption occurs before asynchronous transport"
            );
        }
    }
    ensure!(
        methods.keys().all(|name| found_methods.contains(name)),
        "reviewed proof method missing from {}",
        proof.type_name
    );
    let reviewed = reviewed_factories(proof)?;
    let mut found = BTreeSet::new();
    inspect_factories(
        proof,
        items,
        false,
        matches!(definition.fields, syn::Fields::Unnamed(_)),
        &reviewed,
        &mut found,
    )?;
    ensure!(
        found == reviewed,
        "reviewed proof factory missing from {}",
        proof.type_name
    );
    Ok(())
}

pub fn check(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let policy: Policy = day2::json::decode_evidence(&read_regular(&root.join(POLICY))?)?;
    validate_policy(&policy)?;
    for check in &policy.trait_checks {
        ensure!(
            trait_check_finding(&root, check)?.fingerprint == check.fingerprint,
            "reviewed production trait checks changed: {}",
            check.source
        );
    }
    for proof in &policy.proofs {
        let path = source_path(&root, &proof.source)?;
        ensure!(
            path.canonicalize()?.starts_with(&root),
            "proof source leaves platform root"
        );
        let bytes = read_regular(&path)?;
        let syntax = syn::parse_file(std::str::from_utf8(&bytes)?)?;
        inspect(proof, &syntax.items)
            .with_context(|| format!("proof boundary {}::{}", proof.source, proof.type_name))?;
    }
    println!(
        "Authority proof boundaries checked: {} handles",
        policy.proofs.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(kind: Kind) -> Proof {
        Proof {
            source: "crates/example/src/proofs.rs".into(),
            type_name: "Permit".into(),
            kind,
            consuming_methods: vec!["send".into()],
            methods: vec!["pub fn send(self)".into()],
            factories: vec![],
        }
    }

    fn check_source(source: &str) -> Result<()> {
        inspect(&proof(Kind::Consuming), &syn::parse_file(source)?.items)
    }

    #[test]
    fn consuming_proof_accepts_private_fields_and_by_value_sink() {
        check_source("pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }")
            .unwrap();
    }

    #[test]
    fn consuming_proof_rejects_constructor_and_receiver_escapes() {
        for source in [
            "pub struct Permit { pub claim: Claim } impl Permit { pub fn send(self) {} }",
            "pub struct Permit { pub(crate) claim: Claim } impl Permit { pub fn send(self) {} }",
            "pub struct Permit { pub(super) claim: Claim } impl Permit { pub fn send(self) {} }",
            "pub struct Permit; impl Permit { pub fn send(self) {} }",
            "pub struct Permit {} impl Permit { pub fn send(self) {} }",
            "pub struct Permit { claim: Claim } impl Permit { pub fn send(&self) {} }",
            "pub struct Permit { claim: Claim } impl Permit { pub fn send(&mut self) {} }",
            "pub struct Permit { claim: Claim } impl Permit { pub async fn send(self) {} }",
            "pub type Permit = Claim; impl Permit { pub fn send(self) {} }",
            "pub struct Permit { claim: Claim }",
        ] {
            assert!(check_source(source).is_err(), "{source}");
        }
        let mut reviewed = proof(Kind::Consuming);
        reviewed.methods = vec!["pub fn send(&self)".into()];
        let borrowed = syn::parse_file(
            "pub struct Permit { claim: Claim } impl Permit { pub fn send(&self) {} }",
        )
        .unwrap();
        assert!(
            inspect(&reviewed, &borrowed.items)
                .unwrap_err()
                .to_string()
                .contains("must consume self")
        );
    }

    #[test]
    fn reviewed_factories_accept_exact_admission_and_reject_forgery_exports() -> Result<()> {
        let mut reviewed = proof(Kind::Consuming);
        reviewed.factories.push(Factory {
            owner: None,
            signature: "pub fn admit(claim: Claim) -> Option<Permit>".into(),
        });
        let source = "pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} } pub fn admit(claim: Claim) -> Option<Permit> { Some(Permit { claim }) }";
        inspect(&reviewed, &syn::parse_file(source)?.items)?;
        let changed = source.replace("claim: Claim) ->", "claim: OtherClaim) ->");
        ensure!(
            inspect(&reviewed, &syn::parse_file(&changed)?.items)
                .unwrap_err()
                .to_string()
                .contains("unreviewed proof factory"),
            "factory signature drift must fail"
        );

        let base = "pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }";
        for export in [
            "impl Permit { pub fn forge(claim: Claim) -> Self { Self { claim } } }",
            "pub fn forge(claim: Claim) -> Result<Option<Permit>> { Ok(Some(Permit { claim })) }",
            "impl Journal { pub fn forge(claim: Claim) -> Permit { Permit { claim } } }",
            "pub fn forge() -> impl FnOnce() -> Permit { || Permit { claim: claim() } }",
            "pub mod child { pub fn forge(claim: Claim) -> super::Permit { super::Permit { claim } } }",
            "use self::Permit as P; pub fn forge(claim: Claim) -> P { P { claim } }",
            "type Alias = Permit; pub fn forge(claim: Claim) -> Result<Alias> { Ok(Alias { claim }) }",
            "pub static FORGE: fn() -> Permit = || Permit { claim: claim() };",
        ] {
            ensure!(
                check_source(&format!("{base} {export}")).is_err(),
                "unreviewed export accepted: {export}"
            );
        }
        Ok(())
    }

    #[test]
    fn consuming_proof_rejects_wire_clone_and_default_traits() {
        for derive in [
            "Clone",
            "Copy",
            "Default",
            "Deserialize",
            "serde::Deserialize",
            "Serialize",
            "RenamedDerive",
        ] {
            let source = format!(
                "#[derive({derive})] pub struct Permit {{ claim: Claim }} impl Permit {{ pub fn send(self) {{}} }}"
            );
            assert!(check_source(&source).is_err(), "{derive}");
        }
        for source in [
            "#[cfg_attr(feature = \"wire\", derive(Deserialize))] pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }",
            "pub struct Permit { claim: Claim } impl Clone for Permit {} impl Permit { pub fn send(self) {} }",
            "pub struct Permit { claim: Claim } impl Debug for &Permit {} impl Permit { pub fn send(self) {} }",
            "pub struct Permit { claim: Claim } impl Serialize for &mut (Permit) {} impl Permit { pub fn send(self) {} }",
        ] {
            assert!(check_source(source).is_err());
        }
        check_source("pub struct Permit { claim: Claim } struct Ordinary; impl Debug for &Ordinary {} impl Permit { pub fn send(self) {} }").unwrap();
        let grouped = Type::Group(syn::TypeGroup {
            group_token: Default::default(),
            elem: Box::new(syn::parse_quote!(&Permit)),
        });
        assert_eq!(type_name(&grouped).as_deref(), Some("Permit"));
    }

    #[test]
    fn readiness_can_clone_identity_without_becoming_wire_authority() {
        let mut proof = proof(Kind::Readiness);
        proof.consuming_methods.clear();
        proof.methods.clear();
        let source =
            syn::parse_file("#[derive(Clone, Debug)] pub struct Permit { id: Digest }").unwrap();
        inspect(&proof, &source.items).unwrap();
        let source =
            syn::parse_file("#[derive(Deserialize)] pub struct Permit { id: Digest }").unwrap();
        assert!(inspect(&proof, &source.items).is_err());
    }

    #[test]
    fn secret_permit_has_no_debug_projection() {
        let source = syn::parse_file("#[derive(Debug)] pub struct Permit { secret: Secret } impl Permit { pub fn send(self) {} }").unwrap();
        assert!(inspect(&proof(Kind::SecretPermit), &source.items).is_err());
    }

    #[test]
    fn malformed_duplicate_and_unbounded_policies_fail_closed() {
        assert!(
            serde_json::from_str::<Policy>(r#"{"version":1,"proofs":[],"disable":true}"#).is_err()
        );
        assert!(serde_json::from_str::<Kind>("\"unsafe\"").is_err());
        let mut policy = Policy {
            version: 1,
            proofs: vec![proof(Kind::Consuming)],
            trait_checks: vec![],
        };
        validate_policy(&policy).unwrap();
        policy.proofs.push(proof(Kind::Consuming));
        assert!(validate_policy(&policy).is_err());
        policy.proofs.truncate(1);
        policy.proofs[0].source = "../outside.rs".into();
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn public_checker_rejects_duplicate_keys_deep_policies_and_symlink_parents() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        let duplicate = br#"{"version":1,"proofs":[{"source":"crates/example/src/proofs.rs","type_name":"Permit","kind":"consuming","\u006bind":"readiness","consuming_methods":["send"]}]}"#;
        fs::write(root.join(POLICY), duplicate)?;
        ensure!(
            check(root)
                .unwrap_err()
                .to_string()
                .contains("duplicate JSON key"),
            "duplicate policy keys must fail in strict decoding"
        );
        let deep = format!(
            "{{\"version\":1,\"proofs\":{}0{}}}",
            "[".repeat(33),
            "]".repeat(33)
        );
        fs::write(root.join(POLICY), deep)?;
        ensure!(
            check(root).unwrap_err().to_string() == "JSON structure budget",
            "deep policy must fail before typed policy validation"
        );

        let policy = r#"{"version":1,"proofs":[{"source":"crates/example/src/proofs.rs","type_name":"Permit","kind":"consuming","consuming_methods":["send"],"methods":["pub fn send(self)"],"factories":[]}]}"#;
        fs::write(root.join(POLICY), policy)?;
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        let source = "pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }";
        fs::write(owner.join("proofs.rs"), source)?;
        check(root)?;
        #[cfg(unix)]
        {
            let alias = root.join("alias");
            fs::create_dir_all(&alias)?;
            fs::write(alias.join("proofs.rs"), source)?;
            fs::remove_file(owner.join("proofs.rs"))?;
            fs::remove_dir(&owner)?;
            std::os::unix::fs::symlink(&alias, &owner)?;
            ensure!(
                check(root).unwrap_err().to_string() == "proof source symlink forbidden",
                "in-root symlink parents must not be accepted as owning sources"
            );
        }
        Ok(())
    }

    #[test]
    fn production_trait_catalog_rejects_removal_and_conditional_compilation() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        let source =
            "macro_rules! assert_not_impl { () => {} } const _: () = { assert_not_impl!(); };";
        fs::write(owner.join("assertions.rs"), source)?;
        fs::write(owner.join("lib.rs"), "mod assertions;")?;
        let mut reviewed = TraitCheck {
            source: "crates/example/src/assertions.rs".into(),
            scope: TraitScope::Module,
            fingerprint: String::new(),
            registration: Some(Registration {
                source: "crates/example/src/lib.rs".into(),
                module: "assertions".into(),
            }),
        };
        reviewed.fingerprint = trait_check_finding(&root, &reviewed)?.fingerprint;
        let checked = |reviewed: &TraitCheck| -> Result<()> {
            ensure!(
                trait_check_finding(&root, reviewed)?.fingerprint == reviewed.fingerprint,
                "trait catalog drift"
            );
            Ok(())
        };
        checked(&reviewed)?;
        for registration in [
            "",
            "#[cfg(test)] mod assertions;",
            "pub mod assertions;",
            "#[path = \"assertions.rs\"] mod assertions;",
        ] {
            fs::write(owner.join("lib.rs"), registration)?;
            assert!(checked(&reviewed).is_err(), "{registration}");
        }
        fs::write(owner.join("lib.rs"), "mod assertions;")?;
        for changed in [
            "#![cfg(test)] macro_rules! assert_not_impl { () => {} } const _: () = { assert_not_impl!(); };",
            "macro_rules! assert_not_impl { () => {} } #[cfg(test)] const _: () = { assert_not_impl!(); };",
            "macro_rules! assert_not_impl { () => {} }",
            "macro_rules! assert_not_impl { () => {} } const _: () = {};",
        ] {
            fs::write(owner.join("assertions.rs"), changed)?;
            assert!(checked(&reviewed).is_err(), "{changed}");
        }
        let ready =
            "const _: () = { macro_rules! assert_not_impl { () => {} } assert_not_impl!(); };";
        fs::write(owner.join("assertions.rs"), ready)?;
        reviewed.scope = TraitScope::Const;
        reviewed.registration = None;
        reviewed.fingerprint = trait_check_finding(&root, &reviewed)?.fingerprint;
        checked(&reviewed)?;
        for changed in [
            "",
            "#[cfg(test)] const _: () = { macro_rules! assert_not_impl { () => {} } assert_not_impl!(); };",
            "const _: () = { macro_rules! assert_not_impl { () => {} } }; ",
        ] {
            fs::write(owner.join("assertions.rs"), changed)?;
            assert!(checked(&reviewed).is_err(), "{changed}");
        }
        Ok(())
    }

    #[test]
    fn compiler_negative_assertion_detects_traits_implemented_outside_the_owner() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let source = fixture.path().join("proof.rs");
        struct ActualMacro(Option<syn::ItemMacro>);
        impl<'ast> Visit<'ast> for ActualMacro {
            fn visit_item_macro(&mut self, definition: &'ast syn::ItemMacro) {
                if definition
                    .ident
                    .as_ref()
                    .is_some_and(|name| name == "assert_not_impl")
                {
                    self.0 = Some(definition.clone());
                }
            }
        }
        for actual_source in [
            include_str!("../../day2/src/structural_proofs.rs"),
            include_str!("../../day2-control/src/release.rs"),
        ] {
            let actual = syn::parse_file(actual_source)?;
            let mut extractor = ActualMacro(None);
            extractor.visit_file(&actual);
            let definition = extractor
                .0
                .context("actual production negative trait macro")?;
            ensure!(
                definition.attrs.is_empty(),
                "production trait macro must be unconditional"
            );
            let assertion = format!(
                "mod owner {{ pub struct Permit; }} {} const _: () = {{ assert_not_impl!(owner::Permit, Clone); }}; fn main() {{}}",
                definition.to_token_stream()
            );
            let production_only = "#[cfg(not(test))] impl Clone for owner::Permit { fn clone(&self) -> Self { Self } }";
            for (implementation, test_build, expected_success) in [
                ("", false, true),
                (
                    "impl Clone for owner::Permit { fn clone(&self) -> Self { Self } }",
                    false,
                    false,
                ),
                (production_only, true, true),
                (production_only, false, false),
            ] {
                fs::write(&source, format!("{assertion}\n{implementation}"))?;
                let mut compiler = std::process::Command::new("rustc");
                compiler.args(["--edition=2024", "--emit=metadata"]);
                if test_build {
                    compiler.args(["--cfg", "test"]);
                }
                let output = compiler
                    .arg(&source)
                    .arg("--out-dir")
                    .arg(fixture.path())
                    .output()?;
                let diagnostic = String::from_utf8_lossy(&output.stderr);
                if expected_success {
                    ensure!(
                        output.status.success(),
                        "valid proof trait assertion failed: {diagnostic}"
                    );
                } else {
                    ensure!(
                        !output.status.success() && diagnostic.contains("E0283"),
                        "cloneable proof must fail with trait inference ambiguity: {diagnostic}"
                    );
                }
            }
        }
        Ok(())
    }
}
