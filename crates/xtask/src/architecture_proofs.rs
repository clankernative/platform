//! Reviewed owning-module APIs, private fields and consuming receivers prevent
//! accidental authority-handle construction and wire/clone escapes. Known direct
//! construction sites and proof-returning factory signatures require admission.
//! A destructor requires an exact owning-impl AST pin; other manual trait impls
//! remain forbidden. Compiler trait assertions complement this syntax guard. It does not establish
//! authorization semantics inside admitted factories or expand macros/resolve
//! arbitrary external aliases; protected operations still validate current facts.
//! Inventory covers owning and inline module AST by default. Opt-in explicit
//! owning-child catalogs additionally close over every production child of the
//! selected module and aggregate its canonical, unaliased owning APIs. This is
//! a bounded source convention, not a general Rust name resolver, erasure proof
//! or hostile-code containment.
//! Nonmaterial proof inputs have a separate exact-use catalog, excluding their
//! already reviewed inherent APIs and factories. Explicit block-local aliases
//! and macro-generated inherent APIs are refused; arbitrary macro expansion,
//! transitive aliases and uncataloged out-of-line sources remain outside the
//! default inventory; opt-in catalogs refuse additional production children.
//! Parsed wire buffers use a separate catalog: their entire owning struct AST
//! and destructor are pinned, with only reviewed Serde derives permitted. They
//! do not represent opaque authority. This guards reviewed erasure-code drift,
//! not every plaintext copy, macro expansion or out-of-line use of the buffer.

use anyhow::{Context, Result, ensure};
use quote::{ToTokens, quote};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};
use syn::{
    Item, Type, Visibility, ext::IdentExt, punctuated::Punctuated, token::Comma, visit::Visit,
};

const POLICY: &str = "architecture-proofs.json";
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROOFS: usize = 128;
const MAX_TRAIT_SOURCES: usize = 32;
const MAX_BUFFER_DESTRUCTORS: usize = 128;
const MAX_OWNING_CHILDREN: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Readiness,
    Consuming,
    SecretPermit,
    PrivateMaterial,
}

impl Kind {
    fn permits_derive(self, name: &str) -> bool {
        match self {
            Self::Readiness => ["Clone", "Debug", "PartialEq", "Eq"].contains(&name),
            Self::Consuming => ["Debug"].contains(&name),
            Self::SecretPermit | Self::PrivateMaterial => false,
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
    #[serde(default)]
    material_uses: Vec<Factory>,
    #[serde(default)]
    proof_uses: Vec<Factory>,
    #[serde(default)]
    destructor: Option<String>,
    #[serde(default, deserialize_with = "deserialize_owning_children")]
    owning_children: Option<Vec<OwningChild>>,
}

#[derive(Deserialize, Serialize)]
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
    #[serde(default)]
    buffer_destructors: Vec<BufferDestructor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BufferDestructor {
    source: String,
    type_name: String,
    definition_fingerprint: String,
    destructor_fingerprint: String,
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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    source: String,
    module: String,
}

/// Explicit source edges, never inferred from references to a proof name.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwningChild {
    source: String,
    registration: Registration,
}

fn deserialize_owning_children<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<OwningChild>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Omission preserves legacy scope; an explicitly supplied catalog must be
    // an array. In particular null cannot silently turn closed scope back off.
    Vec::<OwningChild>::deserialize(deserializer).map(Some)
}

/// Select source facts for review without supplying any admission pins.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateDescriptor {
    version: u32,
    trait_checks: Vec<CandidateTraitCheck>,
    destructors: Vec<CandidateDestructor>,
    #[serde(default)]
    buffer_destructors: Vec<CandidateDestructor>,
    #[serde(default)]
    proof_uses: Vec<CandidateDestructor>,
    #[serde(default)]
    owning_apis: Vec<CandidateOwningApi>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateOwningApi {
    source: String,
    type_name: String,
    kind: Kind,
    owning_children: Vec<OwningChild>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateTraitCheck {
    source: String,
    scope: TraitScope,
    registration: Option<Registration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateDestructor {
    source: String,
    type_name: String,
}

#[derive(Serialize)]
pub struct TraitCheckFinding {
    source: String,
    scope: TraitScope,
    fingerprint: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct DestructorFinding {
    source: String,
    type_name: String,
    fingerprint: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct BufferDestructorFinding {
    source: String,
    type_name: String,
    definition_fingerprint: String,
    destructor_fingerprint: String,
}

#[derive(Serialize)]
pub struct ProofInventory {
    trait_checks: Vec<TraitCheckFinding>,
    destructors: Vec<DestructorFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    buffer_destructors: Vec<BufferDestructorFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    proof_uses: Vec<ProofUseFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    owning_apis: Vec<OwningApiFinding>,
}

#[derive(Serialize)]
pub struct OwningApiFinding {
    source: String,
    type_name: String,
    owning_children: Vec<OwningChild>,
    methods: Vec<String>,
    factories: Vec<Factory>,
    material_uses: Vec<Factory>,
    proof_uses: Vec<Factory>,
}

#[derive(Serialize)]
pub struct ProofUseFinding {
    source: String,
    type_name: String,
    uses: Vec<Factory>,
}

fn valid_fingerprint(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == 71
        && value[7..].bytes().all(|value| value.is_ascii_hexdigit())
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
    let file = fs::File::open(path)?;
    ensure!(file.metadata()?.is_file(), "regular proof input required");
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
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
        !policy.proofs.is_empty() && policy.proofs.len() <= MAX_PROOFS,
        "proof policy entry budget"
    );
    let mut identities = BTreeSet::new();
    for proof in &policy.proofs {
        if let Some(children) = &proof.owning_children {
            validate_owning_children(&proof.source, children)?;
        }
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
            identities.insert((&proof.source, semantic_name(&proof.type_name))),
            "duplicate proof policy entry"
        );
        ensure!(proof.consuming_methods.len() <= 16, "proof method budget");
        ensure!(
            proof
                .consuming_methods
                .windows(2)
                .all(|pair| semantic_name(&pair[0]) < semantic_name(&pair[1])),
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
            matches!(proof.kind, Kind::Readiness | Kind::PrivateMaterial)
                || !proof.consuming_methods.is_empty(),
            "consuming proof must identify its consuming sink"
        );
        ensure!(
            proof.methods.len() <= 32
                && proof.factories.len() <= 32
                && proof.material_uses.len() <= 32
                && proof.proof_uses.len() <= 32,
            "proof API budget"
        );
        ensure!(
            matches!(proof.kind, Kind::PrivateMaterial) || proof.material_uses.is_empty(),
            "material uses require the private_material kind"
        );
        ensure!(
            !matches!(proof.kind, Kind::PrivateMaterial) || proof.proof_uses.is_empty(),
            "nonmaterial proof uses cannot replace private material uses"
        );
        let methods = reviewed_methods(proof)?;
        ensure!(
            proof
                .consuming_methods
                .iter()
                .all(|name| methods.contains_key(semantic_name(name))),
            "consuming sink must be a reviewed method"
        );
        reviewed_factories(proof)?;
        reviewed_material_uses(proof)?;
        reviewed_signatures(&proof.proof_uses)?;
        if let Some(fingerprint) = &proof.destructor {
            ensure!(
                valid_fingerprint(fingerprint),
                "invalid proof destructor fingerprint"
            );
        }
    }
    ensure!(
        policy.trait_checks.len() <= MAX_TRAIT_SOURCES,
        "trait check catalog budget"
    );
    let mut sources = BTreeSet::new();
    for check in &policy.trait_checks {
        ensure!(
            sources.insert(&check.source),
            "duplicate trait check source"
        );
        ensure!(
            valid_fingerprint(&check.fingerprint),
            "invalid trait check fingerprint"
        );
        if let Some(registration) = &check.registration {
            syn::parse_str::<syn::Ident>(&registration.module)?;
        }
    }
    ensure!(
        policy.buffer_destructors.len() <= MAX_BUFFER_DESTRUCTORS,
        "buffer destructor catalog budget"
    );
    for buffer in &policy.buffer_destructors {
        validate_candidate_source(&buffer.source)?;
        ensure!(
            buffer.type_name.len() <= 128
                && syn::parse_str::<syn::Ident>(&buffer.type_name).is_ok(),
            "invalid buffer destructor type"
        );
        ensure!(
            identities.insert((&buffer.source, semantic_name(&buffer.type_name))),
            "duplicate buffer destructor or overlapping proof entry"
        );
        ensure!(
            valid_fingerprint(&buffer.definition_fingerprint)
                && valid_fingerprint(&buffer.destructor_fingerprint),
            "invalid buffer destructor fingerprint"
        );
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

fn validate_owning_children(owner: &str, children: &[OwningChild]) -> Result<()> {
    ensure!(
        children.len() <= MAX_OWNING_CHILDREN,
        "owning child catalog budget"
    );
    validate_candidate_source(owner)?;
    if children.is_empty() {
        return Ok(());
    }
    ensure!(
        children
            .windows(2)
            .all(|pair| pair[0].source < pair[1].source),
        "owning child sources must be unique and sorted"
    );
    let mut edges = BTreeSet::new();
    for child in children {
        validate_candidate_source(&child.source)?;
        validate_candidate_source(&child.registration.source)?;
        ensure!(
            child.source != owner,
            "owning child cannot replace its owner"
        );
        ensure!(
            child.registration.module.len() <= 128
                && syn::parse_str::<syn::Ident>(&child.registration.module).is_ok(),
            "invalid owning child module"
        );
        ensure!(
            edges.insert((
                &child.registration.source,
                semantic_name(&child.registration.module),
            )),
            "duplicate owning child registration"
        );
        let mut source = child.source.as_str();
        let mut seen = BTreeSet::new();
        while source != owner {
            ensure!(seen.insert(source), "cyclic owning child graph");
            source = children
                .iter()
                .find(|edge| edge.source == source)
                .context("owning child parent must be explicitly selected")?
                .registration
                .source
                .as_str();
        }
    }
    Ok(())
}

fn child_depth(owner: &str, source: &str, children: &[OwningChild]) -> usize {
    let mut source = source;
    let mut depth = 0;
    while source != owner {
        // validate_owning_children has already established a bounded rooted graph.
        source = &children
            .iter()
            .find(|edge| edge.source == source)
            .expect("validated child graph")
            .registration
            .source;
        depth += 1;
    }
    depth
}

fn registration_matches(source: &str, module: &syn::ItemMod, child: &str) -> Result<()> {
    ensure!(
        matches!(module.vis, Visibility::Inherited),
        "owning child registration must remain private"
    );
    let mut explicit = None;
    for attr in &module.attrs {
        if path_is_ident(attr.path(), "doc") {
            continue;
        }
        ensure!(
            path_is_ident(attr.path(), "path") && explicit.is_none(),
            "owning child registration must be unconditional with one exact path"
        );
        let syn::Meta::NameValue(value) = &attr.meta else {
            anyhow::bail!("owning child path must be a literal");
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) = &value.value
        else {
            anyhow::bail!("owning child path must be a literal");
        };
        let value = value.value();
        ensure!(
            value.len() <= 4096
                && value.ends_with(".rs")
                && !value.contains('\\')
                && value
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
                && Path::new(&value)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "owning child path must remain relative and bounded"
        );
        explicit = Some(value);
    }
    let parent = Path::new(source)
        .parent()
        .context("owning child source parent")?;
    if let Some(path) = explicit {
        ensure!(
            parent.join(path) == Path::new(child),
            "owning child registration substituted its source"
        );
    } else {
        let stem = Path::new(source)
            .file_stem()
            .context("owning child source stem")?;
        let base = if ["mod", "lib", "main"].iter().any(|name| stem == *name) {
            parent.to_path_buf()
        } else {
            parent.join(stem)
        };
        ensure!(
            base.join(format!("{}.rs", semantic_ident(&module.ident))) == Path::new(child)
                || base.join(semantic_ident(&module.ident)).join("mod.rs") == Path::new(child),
            "owning child registration must name its exact Rust source"
        );
    }
    Ok(())
}

/// Only selected files are opened. Every production edge in those files must
/// occur in the catalog; this does not discover or resolve arbitrary modules.
fn owning_items(
    root: &Path,
    owner: &str,
    selected: &str,
    children: Option<&[OwningChild]>,
) -> Result<Vec<Item>> {
    if let Some(children) = children {
        validate_owning_children(owner, children)?;
    }
    let syntax = parse_source(root, owner)?;
    let Some(children) = children else {
        return Ok(syntax.items);
    };
    let mut sources = BTreeMap::new();
    sources.insert(owner.to_owned(), syntax);
    for child in children {
        sources.insert(child.source.clone(), parse_source(root, &child.source)?);
    }
    let mut registered = BTreeSet::new();
    for (source, syntax) in &sources {
        ensure!(
            syntax
                .attrs
                .iter()
                .all(|attr| path_is_ident(attr.path(), "doc")),
            "owning sources must compile unconditionally"
        );
        // Out-of-line modules nested in an inline/local scope are deliberately
        // unsupported. They need a reviewed explicit source edge convention.
        struct Modules<'a> {
            source: &'a str,
            children: &'a [OwningChild],
            depth: usize,
            registered: &'a mut BTreeSet<String>,
            failure: Option<anyhow::Error>,
        }
        impl<'ast> Visit<'ast> for Modules<'_> {
            fn visit_block(&mut self, block: &'ast syn::Block) {
                self.depth += 1;
                syn::visit::visit_block(self, block);
                self.depth -= 1;
            }
            fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
                if self.failure.is_some() || test_only(&module.attrs) {
                    return;
                }
                if module.content.is_none() {
                    let result = (|| -> Result<()> {
                        ensure!(
                            self.depth == 0,
                            "owning child must have a direct module registration"
                        );
                        let child = self
                            .children
                            .iter()
                            .find(|child| {
                                child.registration.source == self.source
                                    && ident_is(&module.ident, &child.registration.module)
                            })
                            .context("uncataloged production owning child")?;
                        registration_matches(self.source, module, &child.source)?;
                        ensure!(
                            self.registered.insert(child.source.clone()),
                            "duplicate owning child registration"
                        );
                        Ok(())
                    })();
                    self.failure = result.err();
                    return;
                }
                self.depth += 1;
                syn::visit::visit_item_mod(self, module);
                self.depth -= 1;
            }
            fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
                if !test_only(&function.attrs) {
                    self.depth += 1;
                    syn::visit::visit_item_fn(self, function);
                    self.depth -= 1;
                }
            }
            fn visit_item_impl(&mut self, implementation: &'ast syn::ItemImpl) {
                if !test_only(&implementation.attrs) {
                    self.depth += 1;
                    syn::visit::visit_item_impl(self, implementation);
                    self.depth -= 1;
                }
            }
            fn visit_item_trait(&mut self, definition: &'ast syn::ItemTrait) {
                if !test_only(&definition.attrs) {
                    self.depth += 1;
                    syn::visit::visit_item_trait(self, definition);
                    self.depth -= 1;
                }
            }
            fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
                if !test_only(&function.attrs) {
                    syn::visit::visit_impl_item_fn(self, function);
                }
            }
            fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
                if !test_only(&function.attrs) {
                    syn::visit::visit_trait_item_fn(self, function);
                }
            }
        }
        let mut modules = Modules {
            source,
            children,
            depth: 0,
            registered: &mut registered,
            failure: None,
        };
        modules.visit_file(syntax);
        if let Some(failure) = modules.failure {
            return Err(failure);
        }
        canonical_owning_bindings(
            selected,
            &syntax.items,
            child_depth(owner, source, children),
        )?;
    }
    ensure!(
        registered.len() == children.len(),
        "selected owning child registration missing"
    );
    // The owning definition and permitted destructor remain in the owner;
    // validated child APIs are inspected as exact additional owning scopes.
    let mut items = sources
        .remove(owner)
        .context("owning source missing")?
        .items;
    for child in children {
        items.extend(
            sources
                .remove(&child.source)
                .context("owning child source missing")?
                .items,
        );
    }
    Ok(items)
}

fn canonical_owning_bindings(selected: &str, items: &[Item], ancestor_depth: usize) -> Result<()> {
    struct Bindings<'a> {
        selected: &'a str,
        ancestor_depth: usize,
        canonical_imports: usize,
        referenced: bool,
        item_depth: usize,
        self_is_proof: bool,
        non_doc_ancestor: bool,
        failure: Option<&'static str>,
    }
    impl Bindings<'_> {
        fn import(
            &mut self,
            tree: &syn::UseTree,
            prefix: &mut Vec<String>,
            attrs: &[syn::Attribute],
        ) {
            match tree {
                syn::UseTree::Path(path) => {
                    if ident_is(&path.ident, self.selected) {
                        // `Type::{self as Alias}` also binds the owning type;
                        // terminal-name checks alone would miss that alias.
                        self.failure =
                            Some("proof child cannot import through its owning type namespace");
                        return;
                    }
                    prefix.push(semantic_ident(&path.ident));
                    self.import(&path.tree, prefix, attrs);
                    prefix.pop();
                }
                syn::UseTree::Group(group) => {
                    for tree in &group.items {
                        self.import(tree, prefix, attrs);
                    }
                }
                syn::UseTree::Name(name) if ident_is(&name.ident, self.selected) => {
                    if self.ancestor_depth == 0
                        || self.item_depth != 0
                        || self.non_doc_ancestor
                        || prefix.len() != self.ancestor_depth
                        || prefix.iter().any(|segment| segment != "super")
                        || attrs.iter().any(|attr| !path_is_ident(attr.path(), "doc"))
                    {
                        self.failure =
                            Some("proof child requires an unconditional canonical ancestor import");
                    }
                    self.canonical_imports += 1;
                }
                syn::UseTree::Rename(rename)
                    if ident_is(&rename.ident, self.selected)
                        || ident_is(&rename.rename, self.selected) =>
                {
                    self.failure = Some("proof child cannot alias its owning type");
                }
                syn::UseTree::Glob(_) => {
                    self.failure = Some("owning scopes cannot gain production wildcard imports");
                }
                _ => {}
            }
        }
    }
    impl<'ast> Visit<'ast> for Bindings<'_> {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            self.item_depth += 1;
            syn::visit::visit_block(self, block);
            self.item_depth -= 1;
        }
        fn visit_item(&mut self, item: &'ast Item) {
            let attrs: &[syn::Attribute] = match item {
                Item::Const(item) => &item.attrs,
                Item::Enum(item) => &item.attrs,
                Item::Fn(item) => &item.attrs,
                Item::Impl(item) => &item.attrs,
                Item::Macro(item) => &item.attrs,
                Item::Mod(item) => &item.attrs,
                Item::Static(item) => &item.attrs,
                Item::Struct(item) => &item.attrs,
                Item::Trait(item) => &item.attrs,
                Item::Type(item) => &item.attrs,
                Item::Union(item) => &item.attrs,
                Item::Use(item) => &item.attrs,
                _ => &[],
            };
            if self.failure.is_some() || test_only(attrs) {
                return;
            }
            let previous_ancestor = self.non_doc_ancestor;
            // Selected definition derives remain governed by its existing kind
            // rules. For users/factories, attributes on any enclosing item may
            // change whether the reviewed signature actually compiles.
            self.non_doc_ancestor |= !matches!(item, Item::Struct(item) if ident_is(&item.ident, self.selected))
                && attrs.iter().any(|attr| !path_is_ident(attr.path(), "doc"));
            match item {
                Item::Use(item) => {
                    if item.leading_colon.is_some() && import_binds(&item.tree, None, self.selected)
                    {
                        self.failure = Some("proof child import must be relative to its owner");
                    }
                    self.import(&item.tree, &mut Vec::new(), attrs);
                }
                Item::Struct(item) if ident_is(&item.ident, self.selected) => {
                    if self.ancestor_depth != 0 || self.item_depth != 0 {
                        self.failure = Some("proof child cannot substitute an owning definition");
                    } else if attrs.iter().any(|attr| {
                        path_is_ident(attr.path(), "cfg") || path_is_ident(attr.path(), "cfg_attr")
                    }) {
                        self.failure = Some("owning proof definition must be unconditional");
                    }
                    syn::visit::visit_item_struct(self, item);
                }
                Item::Enum(item) if ident_is(&item.ident, self.selected) => {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::Type(item) if ident_is(&item.ident, self.selected) => {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::Union(item) if ident_is(&item.ident, self.selected) => {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::Trait(item) if ident_is(&item.ident, self.selected) => {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::TraitAlias(item) if ident_is(&item.ident, self.selected) => {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::ExternCrate(item)
                    if ident_is(&item.ident, self.selected)
                        || item
                            .rename
                            .as_ref()
                            .is_some_and(|(_, rename)| ident_is(rename, self.selected)) =>
                {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::Mod(item) if ident_is(&item.ident, self.selected) => {
                    self.failure = Some("proof type cannot be shadowed")
                }
                Item::Impl(item) => {
                    let own =
                        type_name(&item.self_ty).as_deref() == Some(semantic_name(self.selected));
                    if own
                        && (self.item_depth != 0
                            || !matches!(item.self_ty.as_ref(), Type::Path(ty)
                            if ty.qself.is_none() && ty.path.leading_colon.is_none()
                                && ty.path.segments.len() == 1 && ident_is(&ty.path.segments[0].ident, self.selected))
                            || attrs.iter().any(|attr| !path_is_ident(attr.path(), "doc"))
                            || (self.ancestor_depth != 0 && item.trait_.is_some()))
                    {
                        self.failure = Some(
                            "proof child impl must be direct and unconditional; traits remain owning-only",
                        );
                        return;
                    }
                    let previous = std::mem::replace(&mut self.self_is_proof, own);
                    syn::visit::visit_item_impl(self, item);
                    self.self_is_proof = previous;
                }
                Item::Mod(item) => {
                    self.item_depth += 1;
                    syn::visit::visit_item_mod(self, item);
                    self.item_depth -= 1;
                }
                Item::Fn(item) => {
                    let references = item.sig.inputs.iter().any(|arg| match arg {
                        syn::FnArg::Typed(arg) => contains_proof(&arg.ty, self.selected, false),
                        syn::FnArg::Receiver(_) => false,
                    }) || matches!(&item.sig.output, syn::ReturnType::Type(_, ty) if contains_proof(ty, self.selected, false))
                        || constructs_proof(&item.block, self.selected, false, true);
                    if references && attrs.iter().any(|attr| !path_is_ident(attr.path(), "doc")) {
                        self.failure =
                            Some("proof owning users and factories must be unconditional");
                    }
                    self.item_depth += 1;
                    syn::visit::visit_item_fn(self, item);
                    self.item_depth -= 1;
                }
                _ => syn::visit::visit_item(self, item),
            }
            self.non_doc_ancestor = previous_ancestor;
        }
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if path
                .segments
                .last()
                .is_some_and(|segment| ident_is(&segment.ident, self.selected))
            {
                self.referenced = true;
                if self.non_doc_ancestor {
                    self.failure = Some("proof owning users and factories must be unconditional");
                }
                if path.leading_colon.is_some() || path.segments.len() != 1 {
                    self.failure = Some("proof owning uses require the canonical unqualified type");
                }
            }
            syn::visit::visit_path(self, path);
        }
        fn visit_type_param(&mut self, param: &'ast syn::TypeParam) {
            if ident_is(&param.ident, self.selected) {
                self.failure = Some("proof type cannot be shadowed by a generic parameter");
            }
            syn::visit::visit_type_param(self, param);
        }
        fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
            if invocation
                .path
                .segments
                .last()
                .is_some_and(|segment| ident_is(&segment.ident, "include"))
            {
                self.failure = Some("owning sources cannot load production Rust through include!");
                return;
            }
            syn::visit::visit_macro(self, invocation);
        }
        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if test_only(&function.attrs) {
                return;
            }
            let previous_ancestor = self.non_doc_ancestor;
            self.non_doc_ancestor |= function
                .attrs
                .iter()
                .any(|attr| !path_is_ident(attr.path(), "doc"));
            let references = self.self_is_proof
                || function.sig.inputs.iter().any(|arg| match arg {
                    syn::FnArg::Typed(arg) => contains_proof(&arg.ty, self.selected, false),
                    syn::FnArg::Receiver(_) => false,
                })
                || matches!(&function.sig.output, syn::ReturnType::Type(_, ty) if contains_proof(ty, self.selected, false))
                || constructs_proof(&function.block, self.selected, self.self_is_proof, true);
            if references
                && function
                    .attrs
                    .iter()
                    .any(|attr| !path_is_ident(attr.path(), "doc"))
            {
                self.failure = Some("proof owning methods must be unconditional");
            }
            self.item_depth += 1;
            syn::visit::visit_impl_item_fn(self, function);
            self.item_depth -= 1;
            self.non_doc_ancestor = previous_ancestor;
        }
        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if test_only(&function.attrs) {
                return;
            }
            let previous_ancestor = self.non_doc_ancestor;
            self.non_doc_ancestor |= function
                .attrs
                .iter()
                .any(|attr| !path_is_ident(attr.path(), "doc"));
            syn::visit::visit_trait_item_fn(self, function);
            self.non_doc_ancestor = previous_ancestor;
        }
    }
    let mut visitor = Bindings {
        selected,
        ancestor_depth,
        canonical_imports: 0,
        referenced: false,
        item_depth: 0,
        self_is_proof: false,
        non_doc_ancestor: false,
        failure: None,
    };
    for item in items {
        visitor.visit_item(item);
    }
    if let Some(failure) = visitor.failure {
        anyhow::bail!(failure);
    }
    ensure!(
        visitor.canonical_imports <= 1,
        "duplicate owning type import"
    );
    ensure!(
        ancestor_depth == 0 || !visitor.referenced || visitor.canonical_imports == 1,
        "proof child must import its actual ancestor type"
    );
    Ok(())
}

fn trait_check_finding(root: &Path, check: &TraitCheck) -> Result<TraitCheckFinding> {
    trait_source_finding(
        root,
        &check.source,
        check.scope,
        check.registration.as_ref(),
    )
}

fn trait_source_finding(
    root: &Path,
    source: &str,
    scope: TraitScope,
    registration: Option<&Registration>,
) -> Result<TraitCheckFinding> {
    let syntax = parse_source(root, source)?;
    ensure!(
        syntax
            .attrs
            .iter()
            .all(|attribute| path_is_ident(attribute.path(), "doc")),
        "trait check source must compile unconditionally"
    );
    if let Some(registration) = registration {
        let library = parse_source(root, &registration.source)?;
        let registrations: Vec<_> = library
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Mod(module) if ident_is(&module.ident, &registration.module) => Some(module),
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
                == Some(Path::new(source)),
            "trait module registration must name its exact source"
        );
    }
    let tokens = match scope {
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
                    syn::Stmt::Item(Item::Macro(definition)) if definition.ident.as_ref().is_some_and(|name| ident_is(name, "assert_not_impl"))
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
        source: source.to_owned(),
        scope,
        fingerprint: day2::digest(tokens.to_string().as_bytes()),
    })
}

/// Read-only normalized assertion, destructor and parsed-buffer definition facts for explicit
/// policy review. This never copies a policy pin into the emitted source facts.
pub fn trait_check_inventory(root: &Path) -> Result<ProofInventory> {
    let root = root.canonicalize()?;
    let policy: Policy = day2::json::decode_evidence(&read_regular(&root.join(POLICY))?)?;
    validate_policy(&policy)?;
    let trait_checks = policy
        .trait_checks
        .iter()
        .map(|check| trait_check_finding(&root, check))
        .collect::<Result<Vec<_>>>()?;
    let mut destructors = Vec::new();
    for proof in &policy.proofs {
        let syntax = parse_source(&root, &proof.source)?;
        if let Some(fingerprint) = destructor_fingerprint(proof, &syntax.items)? {
            destructors.push(DestructorFinding {
                source: proof.source.clone(),
                type_name: proof.type_name.clone(),
                fingerprint,
            });
        }
    }
    destructors.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    let buffer_destructors = buffer_inventory(
        &root,
        policy
            .buffer_destructors
            .iter()
            .map(|buffer| (buffer.source.as_str(), buffer.type_name.as_str())),
    )?;
    let mut proof_uses = Vec::new();
    let mut owning_apis = Vec::new();
    for proof in &policy.proofs {
        if !matches!(proof.kind, Kind::PrivateMaterial) {
            let items = owning_items(
                &root,
                &proof.source,
                &proof.type_name,
                proof.owning_children.as_deref(),
            )?;
            let definition = proof_definition(&proof.type_name, &items)?;
            inspect_proof_syntax(&proof.type_name, &items)?;
            proof_uses.push(ProofUseFinding {
                source: proof.source.clone(),
                type_name: proof.type_name.clone(),
                uses: collect_proof_uses(
                    &proof.type_name,
                    &items,
                    matches!(definition.fields, syn::Fields::Unnamed(_)),
                )?
                .into_iter()
                .map(|(owner, signature)| Factory { owner, signature })
                .collect(),
            });
        }
        if proof.owning_children.is_some() {
            owning_apis.push(owning_api_finding(&root, proof)?);
        }
    }
    proof_uses.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    owning_apis.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    Ok(ProofInventory {
        trait_checks,
        destructors,
        buffer_destructors,
        proof_uses,
        owning_apis,
    })
}

fn validate_candidate_source(source: &str) -> Result<()> {
    ensure!(
        source.len() <= 4096
            && source.starts_with("crates/")
            && source.ends_with(".rs")
            && !source.contains('\\')
            && source
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && Path::new(source)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "invalid candidate source path"
    );
    Ok(())
}

fn validate_candidate(descriptor: &CandidateDescriptor) -> Result<()> {
    ensure!(
        descriptor.version == 1,
        "unsupported proof candidate version"
    );
    ensure!(
        !descriptor.trait_checks.is_empty()
            || !descriptor.destructors.is_empty()
            || !descriptor.buffer_destructors.is_empty()
            || !descriptor.proof_uses.is_empty()
            || !descriptor.owning_apis.is_empty(),
        "proof candidate requires explicit source selections"
    );
    ensure!(
        descriptor.trait_checks.len() <= MAX_TRAIT_SOURCES,
        "trait check catalog budget"
    );
    ensure!(
        descriptor.destructors.len() <= MAX_PROOFS,
        "proof candidate destructor budget"
    );
    ensure!(
        descriptor.buffer_destructors.len() <= MAX_BUFFER_DESTRUCTORS,
        "buffer destructor catalog budget"
    );
    ensure!(
        descriptor.proof_uses.len() <= MAX_PROOFS,
        "proof candidate use selector budget"
    );
    let mut trait_sources = BTreeSet::new();
    for check in &descriptor.trait_checks {
        validate_candidate_source(&check.source)?;
        ensure!(
            trait_sources.insert(&check.source),
            "duplicate candidate trait source"
        );
        match (check.scope, &check.registration) {
            (TraitScope::Module, Some(registration)) => {
                validate_candidate_source(&registration.source)?;
                ensure!(
                    registration.module.len() <= 128
                        && syn::parse_str::<syn::Ident>(&registration.module).is_ok(),
                    "invalid candidate registration module"
                );
            }
            (TraitScope::Const, None) => {}
            _ => anyhow::bail!(
                "candidate trait scope requires exact module registration or an unregistered const"
            ),
        }
    }
    let mut destructors = BTreeSet::new();
    for destructor in descriptor
        .destructors
        .iter()
        .chain(&descriptor.buffer_destructors)
    {
        validate_candidate_source(&destructor.source)?;
        ensure!(
            destructor.type_name.len() <= 128
                && syn::parse_str::<syn::Ident>(&destructor.type_name).is_ok(),
            "invalid candidate destructor type"
        );
        ensure!(
            destructors.insert((&destructor.source, semantic_name(&destructor.type_name))),
            "duplicate candidate destructor"
        );
    }
    let mut proof_uses = BTreeSet::new();
    for selected in &descriptor.proof_uses {
        validate_candidate_source(&selected.source)?;
        ensure!(
            selected.type_name.len() <= 128
                && syn::parse_str::<syn::Ident>(&selected.type_name).is_ok(),
            "invalid candidate proof use type"
        );
        ensure!(
            proof_uses.insert((&selected.source, semantic_name(&selected.type_name))),
            "duplicate candidate proof use selector"
        );
    }
    ensure!(
        descriptor.owning_apis.len() <= MAX_PROOFS,
        "owning API selector budget"
    );
    let mut owning_apis = BTreeSet::new();
    for selected in &descriptor.owning_apis {
        validate_candidate_source(&selected.source)?;
        ensure!(
            selected.type_name.len() <= 128
                && syn::parse_str::<syn::Ident>(&selected.type_name).is_ok(),
            "invalid candidate owning API type"
        );
        validate_owning_children(&selected.source, &selected.owning_children)?;
        ensure!(
            owning_apis.insert((&selected.source, semantic_name(&selected.type_name))),
            "duplicate candidate owning API selection"
        );
    }
    Ok(())
}

/// Derive actual normalized AST facts from bounded, pin-free source selections.
/// This does not load or write admission policy, establish proof API safety,
/// expand macros or follow unselected children, or produce a passing receipt.
pub fn candidate_inventory(root: &Path, descriptor: &Path) -> Result<ProofInventory> {
    let root = root.canonicalize()?;
    let descriptor: CandidateDescriptor = day2::json::decode_evidence(&read_regular(descriptor)?)?;
    validate_candidate(&descriptor)?;
    let mut trait_checks = descriptor
        .trait_checks
        .iter()
        .map(|check| {
            trait_source_finding(
                &root,
                &check.source,
                check.scope,
                check.registration.as_ref(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    trait_checks.sort_by(|left, right| left.source.cmp(&right.source));
    let mut destructors = Vec::new();
    for selected in &descriptor.destructors {
        let syntax = parse_source(&root, &selected.source)?;
        let declarations = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(definition) if ident_is(&definition.ident, &selected.type_name) => {
                    Some(definition)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        ensure!(
            declarations.len() == 1,
            "candidate destructor requires one explicit owning struct"
        );
        ensure!(
            syntax
                .attrs
                .iter()
                .chain(&declarations[0].attrs)
                .all(|attribute| !path_is_ident(attribute.path(), "cfg")
                    && !path_is_ident(attribute.path(), "cfg_attr"))
                && declarations[0].generics.params.is_empty()
                && declarations[0].generics.where_clause.is_none(),
            "candidate destructor definition must be unconditional and nongeneric"
        );
        let fingerprint = destructor_source_fingerprint(&selected.type_name, &syntax.items)?
            .context("candidate destructor missing from selected owning type")?;
        destructors.push(DestructorFinding {
            source: selected.source.clone(),
            type_name: selected.type_name.clone(),
            fingerprint,
        });
    }
    destructors.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    let buffer_destructors = buffer_inventory(
        &root,
        descriptor
            .buffer_destructors
            .iter()
            .map(|buffer| (buffer.source.as_str(), buffer.type_name.as_str())),
    )?;
    let proof_uses = proof_use_inventory(
        &root,
        descriptor
            .proof_uses
            .iter()
            .map(|selected| (selected.source.as_str(), selected.type_name.as_str())),
    )?;
    let mut owning_apis = descriptor
        .owning_apis
        .iter()
        .map(|selected| {
            let proof = Proof {
                source: selected.source.clone(),
                type_name: selected.type_name.clone(),
                kind: selected.kind,
                consuming_methods: Vec::new(),
                methods: Vec::new(),
                factories: Vec::new(),
                material_uses: Vec::new(),
                proof_uses: Vec::new(),
                destructor: None,
                owning_children: Some(selected.owning_children.clone()),
            };
            owning_api_finding(&root, &proof)
        })
        .collect::<Result<Vec<_>>>()?;
    owning_apis.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    Ok(ProofInventory {
        trait_checks,
        destructors,
        buffer_destructors,
        proof_uses,
        owning_apis,
    })
}

/// Pin-free API facts share the exact source convention used by admission.
/// The signatures are review data, never a declaration that a factory is safe.
fn owning_api_finding(root: &Path, proof: &Proof) -> Result<OwningApiFinding> {
    let items = owning_items(
        root,
        &proof.source,
        &proof.type_name,
        proof.owning_children.as_deref(),
    )?;
    let definition = proof_definition(&proof.type_name, &items)?;
    inspect_proof_syntax(&proof.type_name, &items)?;
    let mut methods = BTreeMap::new();
    for item in &items {
        if let Item::Impl(implementation) = item
            && implementation.trait_.is_none()
            && type_name(&implementation.self_ty).as_deref()
                == Some(semantic_name(&proof.type_name))
        {
            for item in &implementation.items {
                if let syn::ImplItem::Fn(function) = item {
                    ensure!(
                        methods
                            .insert(
                                semantic_ident(&function.sig.ident),
                                signature(&function.vis, &function.sig)
                            )
                            .is_none(),
                        "ambiguous owning API method"
                    );
                }
            }
        }
    }
    let tuple = matches!(definition.fields, syn::Fields::Unnamed(_));
    let factories = |found: BTreeSet<(Option<String>, String)>| {
        found
            .into_iter()
            .map(|(owner, signature)| Factory { owner, signature })
            .collect()
    };
    let mut found = BTreeSet::new();
    inspect_factories(proof, &items, false, tuple, None, &mut found)?;
    let actual_factories = factories(found);
    let (material_uses, proof_uses) = if matches!(proof.kind, Kind::PrivateMaterial) {
        let mut found = BTreeSet::new();
        inspect_material_uses(proof, &items, None, &mut found)?;
        (factories(found), Vec::new())
    } else {
        (
            Vec::new(),
            factories(collect_proof_uses(&proof.type_name, &items, tuple)?),
        )
    };
    Ok(OwningApiFinding {
        source: proof.source.clone(),
        type_name: proof.type_name.clone(),
        owning_children: proof.owning_children.clone().unwrap_or_default(),
        methods: methods.into_values().collect(),
        factories: actual_factories,
        material_uses,
        proof_uses,
    })
}

fn proof_use_inventory<'a>(
    root: &Path,
    selections: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<ProofUseFinding>> {
    let mut findings = selections
        .map(|(source, selected)| {
            let syntax = parse_source(root, source)?;
            let definition = proof_definition(selected, &syntax.items)?;
            inspect_proof_syntax(selected, &syntax.items)?;
            let uses = collect_proof_uses(
                selected,
                &syntax.items,
                matches!(definition.fields, syn::Fields::Unnamed(_)),
            )?;
            Ok(ProofUseFinding {
                source: source.to_owned(),
                type_name: selected.to_owned(),
                uses: uses
                    .into_iter()
                    .map(|(owner, signature)| Factory { owner, signature })
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    findings.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    Ok(findings)
}

fn buffer_inventory<'a>(
    root: &Path,
    selections: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<Vec<BufferDestructorFinding>> {
    let mut findings = selections
        .map(|(source, type_name)| {
            buffer_source_finding(source, type_name, &parse_source(root, source)?)
        })
        .collect::<Result<Vec<_>>>()?;
    findings.sort_by(|left, right| {
        (&left.source, &left.type_name).cmp(&(&right.source, &right.type_name))
    });
    Ok(findings)
}

/// Review a parsed wire buffer's explicit owning definition independently of
/// authority proofs. The full struct AST includes field types and codec attrs;
/// macros, arbitrary aliases and out-of-line children are not expanded here.
fn buffer_source_finding(
    source: &str,
    selected: &str,
    syntax: &syn::File,
) -> Result<BufferDestructorFinding> {
    ensure!(
        syntax
            .attrs
            .iter()
            .all(|attribute| path_is_ident(attribute.path(), "doc")),
        "buffer source must compile unconditionally"
    );
    let definitions = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(definition) if ident_is(&definition.ident, selected) => Some(definition),
            _ => None,
        })
        .collect::<Vec<_>>();
    ensure!(
        definitions.len() == 1,
        "buffer requires one explicit owning struct"
    );
    let definition = definitions[0];
    ensure!(
        definition.generics.params.is_empty() && definition.generics.where_clause.is_none(),
        "buffer definition must be nongeneric"
    );
    ensure!(
        matches!(definition.vis, Visibility::Inherited)
            || matches!(&definition.vis, Visibility::Restricted(visibility)
            if visibility.in_token.is_none() && path_is_ident(&visibility.path, "super")),
        "buffer type must remain private or parent-visible"
    );
    ensure!(
        !definition.fields.is_empty()
            && definition
                .fields
                .iter()
                .all(|field| matches!(field.vis, Visibility::Inherited)),
        "buffer fields must remain nonempty and private"
    );
    let mut derives = BTreeSet::new();
    for attribute in &definition.attrs {
        ensure!(
            path_is_ident(attribute.path(), "doc")
                || path_is_ident(attribute.path(), "serde")
                || path_is_ident(attribute.path(), "derive"),
            "buffer definition attributes require explicit review"
        );
        if path_is_ident(attribute.path(), "derive") {
            for derive in
                attribute.parse_args_with(Punctuated::<syn::Path, Comma>::parse_terminated)?
            {
                let name = derive.to_token_stream().to_string();
                ensure!(
                    [
                        "Serialize",
                        "Deserialize",
                        "serde :: Serialize",
                        "serde :: Deserialize",
                        ":: serde :: Serialize",
                        ":: serde :: Deserialize"
                    ]
                    .contains(&name.as_str()),
                    "buffer cannot derive {name}"
                );
                let terminal = derive
                    .segments
                    .last()
                    .context("buffer derive name")?
                    .ident
                    .unraw()
                    .to_string();
                ensure!(derives.insert(terminal), "duplicate buffer codec derive");
            }
        }
    }
    ensure!(
        !derives.is_empty(),
        "buffer requires an explicit reviewed Serde codec"
    );
    ensure!(
        definition
            .fields
            .iter()
            .all(|field| field.attrs.iter().all(|attribute| path_is_ident(
                attribute.path(),
                "doc"
            ) || path_is_ident(
                attribute.path(),
                "serde"
            ))),
        "buffer field attributes require explicit review"
    );
    let destructor_fingerprint = destructor_source_fingerprint(selected, &syntax.items)?
        .context("buffer requires an explicit owning destructor")?;
    Ok(BufferDestructorFinding {
        source: source.to_owned(),
        type_name: selected.to_owned(),
        definition_fingerprint: day2::digest(definition.to_token_stream().to_string().as_bytes()),
        destructor_fingerprint,
    })
}

fn inspect_buffer(root: &Path, reviewed: &BufferDestructor) -> Result<()> {
    let finding = buffer_source_finding(
        &reviewed.source,
        &reviewed.type_name,
        &parse_source(root, &reviewed.source)?,
    )?;
    ensure!(
        finding.definition_fingerprint == reviewed.definition_fingerprint,
        "reviewed buffer definition changed: {}::{}",
        reviewed.source,
        reviewed.type_name
    );
    ensure!(
        finding.destructor_fingerprint == reviewed.destructor_fingerprint,
        "reviewed buffer destructor changed: {}::{}",
        reviewed.source,
        reviewed.type_name
    );
    Ok(())
}

// Raw identifiers have the same Rust identity as their ordinary spelling.
// Normalize recognition only; exact quoted signatures and AST pins stay intact.
fn semantic_name(name: &str) -> &str {
    name.strip_prefix("r#").unwrap_or(name)
}

fn semantic_ident(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

fn ident_is(ident: &syn::Ident, expected: &str) -> bool {
    ident.unraw() == semantic_name(expected)
}

fn path_is_ident(path: &syn::Path, expected: &str) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 1
        && matches!(path.segments[0].arguments, syn::PathArguments::None)
        && ident_is(&path.segments[0].ident, expected)
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
        .map(|segment| semantic_ident(&segment.ident))
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
                    semantic_ident(&method.sig.ident),
                    signature(&method.vis, &method.sig)
                )
                .is_none(),
            "duplicate reviewed proof method"
        );
    }
    Ok(methods)
}

fn reviewed_factories(proof: &Proof) -> Result<BTreeSet<(Option<String>, String)>> {
    reviewed_signatures(&proof.factories)
}

fn reviewed_material_uses(proof: &Proof) -> Result<BTreeSet<(Option<String>, String)>> {
    reviewed_signatures(&proof.material_uses)
}

fn reviewed_signatures(reviewed: &[Factory]) -> Result<BTreeSet<(Option<String>, String)>> {
    let mut factories = BTreeSet::new();
    for reviewed in reviewed {
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

fn import_binds(tree: &syn::UseTree, prefix: Option<&syn::Ident>, name: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => import_binds(&path.tree, Some(&path.ident), name),
        syn::UseTree::Name(import) => {
            if ident_is(&import.ident, "self") {
                prefix.is_some_and(|prefix| ident_is(prefix, name))
            } else {
                ident_is(&import.ident, name)
            }
        }
        syn::UseTree::Rename(import) => ident_is(&import.rename, name),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| import_binds(tree, prefix, name)),
        // A wildcard may shadow the prelude trait or standard-library namespace.
        syn::UseTree::Glob(_) => true,
    }
}

fn shadows_destructor_path(items: &[Item], name: &str) -> bool {
    items.iter().any(|item| match item {
        Item::Use(import) => import_binds(&import.tree, None, name),
        Item::Trait(value) => ident_is(&value.ident, name),
        Item::TraitAlias(value) => ident_is(&value.ident, name),
        Item::Type(value) => ident_is(&value.ident, name),
        Item::Struct(value) => ident_is(&value.ident, name),
        Item::Enum(value) => ident_is(&value.ident, name),
        Item::Union(value) => ident_is(&value.ident, name),
        Item::Mod(value) => ident_is(&value.ident, name),
        Item::ExternCrate(value) => {
            value
                .rename
                .as_ref()
                .is_some_and(|(_, alias)| ident_is(alias, name))
                || (ident_is(&value.ident, name) && !matches!(name, "std" | "core"))
        }
        _ => false,
    })
}

fn proof_trait_impls<'a>(
    type_name_selected: &str,
    items: &'a [Item],
    root: bool,
    found: &mut Vec<&'a syn::ItemImpl>,
) -> Result<()> {
    for item in items {
        match item {
            Item::Impl(implementation)
                if implementation.trait_.is_some()
                    && type_name(&implementation.self_ty).as_deref()
                        == Some(semantic_name(type_name_selected)) =>
            {
                ensure!(
                    root,
                    "proof trait implementations require the explicit owning scope"
                );
                found.push(implementation);
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    proof_trait_impls(type_name_selected, nested, false, found)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Only one direct, unconditional destructor is eligible for explicit review.
/// Its complete normalized impl, including body and trait path, is pinned.
fn destructor_fingerprint(proof: &Proof, items: &[Item]) -> Result<Option<String>> {
    destructor_source_fingerprint(&proof.type_name, items)
}

fn destructor_source_fingerprint(
    type_name_selected: &str,
    items: &[Item],
) -> Result<Option<String>> {
    let mut implementations = Vec::new();
    proof_trait_impls(type_name_selected, items, true, &mut implementations)?;
    let mut fingerprint = None;
    for implementation in implementations {
        let (polarity, path, _) = implementation.trait_.as_ref().context("proof trait impl")?;
        let destructor_path = path
            .segments
            .iter()
            .map(|segment| semantic_ident(&segment.ident))
            .collect::<Vec<_>>()
            .join("::");
        ensure!(
            path.segments
                .iter()
                .all(|segment| matches!(segment.arguments, syn::PathArguments::None)),
            "proof destructor trait path cannot gain generic arguments"
        );
        let namespace = match destructor_path.as_str() {
            "Drop" if path.leading_colon.is_none() => "Drop",
            "std::ops::Drop" => "std",
            "core::ops::Drop" => "core",
            _ => anyhow::bail!(
                "proof {} cannot gain a manual trait implementation",
                type_name_selected
            ),
        };
        ensure!(
            !shadows_destructor_path(items, namespace),
            "proof destructor trait path cannot be shadowed or imported through an alias"
        );
        ensure!(
            polarity.is_none()
                && implementation.attrs.is_empty()
                && implementation.defaultness.is_none()
                && implementation.unsafety.is_none()
                && implementation.generics.params.is_empty()
                && implementation.generics.where_clause.is_none()
                && matches!(implementation.self_ty.as_ref(), Type::Path(ty)
                    if ty.qself.is_none() && path_is_ident(&ty.path, type_name_selected))
                && implementation.items.len() == 1,
            "proof destructor must be direct, unconditional and nongeneric"
        );
        let syn::ImplItem::Fn(destructor) = &implementation.items[0] else {
            anyhow::bail!("proof destructor requires exactly fn drop(&mut self)");
        };
        let expected = parse_signature("fn drop(&mut self)")?;
        let mut destructor_shape = destructor.sig.clone();
        destructor_shape.ident = destructor_shape.ident.unraw();
        ensure!(
            destructor.attrs.is_empty()
                && destructor.defaultness.is_none()
                && signature(&destructor.vis, &destructor_shape)
                    == signature(&expected.vis, &expected.sig),
            "proof destructor requires exactly fn drop(&mut self)"
        );
        ensure!(
            fingerprint.is_none(),
            "duplicate proof destructor implementation"
        );
        fingerprint = Some(day2::digest(
            implementation.to_token_stream().to_string().as_bytes(),
        ));
    }
    Ok(fingerprint)
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
                ident_is(&segment.ident, self.proof)
                    || (self.self_is_proof && ident_is(&segment.ident, "Self"))
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
                ident_is(&segment.ident, self.proof)
                    || (self.self_is_proof && ident_is(&segment.ident, "Self"))
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
        path_is_ident(attribute.path(), "cfg")
            && attribute
                .parse_args::<syn::Path>()
                .ok()
                .is_some_and(|path| path_is_ident(&path, "test"))
    })
}

fn uses_proof_alias(tree: &syn::UseTree, proof: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => uses_proof_alias(&path.tree, proof),
        syn::UseTree::Rename(rename) => ident_is(&rename.ident, proof),
        syn::UseTree::Group(group) => group.items.iter().any(|item| uses_proof_alias(item, proof)),
        _ => false,
    }
}

fn inspect_factories(
    proof: &Proof,
    items: &[Item],
    nested: bool,
    tuple: bool,
    reviewed: Option<&BTreeSet<(Option<String>, String)>>,
    found: &mut BTreeSet<(Option<String>, String)>,
) -> Result<()> {
    let inspect_function = |owner: Option<String>,
                            self_is_proof: bool,
                            visibility: &Visibility,
                            sig: &syn::Signature,
                            body: &syn::Block,
                            found: &mut BTreeSet<_>|
     -> Result<()> {
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
            reviewed.is_none_or(|reviewed| reviewed.contains(&identity)),
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
                inspect_function(
                    None,
                    false,
                    &function.vis,
                    &function.sig,
                    &function.block,
                    found,
                )?;
            }
            Item::Impl(implementation) if !test_only(&implementation.attrs) => {
                let owner = implementation.self_ty.to_token_stream().to_string();
                for member in &implementation.items {
                    if let syn::ImplItem::Fn(function) = member
                        && !test_only(&function.attrs)
                    {
                        inspect_function(
                            Some(owner.clone()),
                            type_name(&implementation.self_ty).as_deref()
                                == Some(semantic_name(&proof.type_name)),
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

/// Review syntactically visible material users as well as constructors. Inherent
/// receivers count as material inputs. External aliases and expanded macro bodies
/// are not resolved. Out-of-line sinks participate only through an explicit,
/// closed owning-child selection; other sinks require independent admission.
fn inspect_material_uses(
    proof: &Proof,
    items: &[Item],
    reviewed: Option<&BTreeSet<(Option<String>, String)>>,
    found: &mut BTreeSet<(Option<String>, String)>,
) -> Result<()> {
    let inspect_function = |owner: Option<String>,
                            self_is_material: bool,
                            visibility: &Visibility,
                            sig: &syn::Signature,
                            found: &mut BTreeSet<_>|
     -> Result<()> {
        if !sig.inputs.iter().any(|argument| match argument {
            syn::FnArg::Typed(argument) => {
                contains_proof(&argument.ty, &proof.type_name, self_is_material)
            }
            syn::FnArg::Receiver(receiver) => {
                contains_proof(&receiver.ty, &proof.type_name, self_is_material)
            }
        }) {
            return Ok(());
        }
        let identity = (owner, signature(visibility, sig));
        ensure!(
            reviewed.is_none_or(|reviewed| reviewed.contains(&identity)),
            "unreviewed private material use {}::{}, signature {}",
            proof.type_name,
            sig.ident,
            identity.1
        );
        ensure!(found.insert(identity), "ambiguous private material use");
        Ok(())
    };
    for item in items {
        match item {
            Item::Fn(function) if !test_only(&function.attrs) => {
                inspect_function(None, false, &function.vis, &function.sig, found)?;
            }
            Item::Impl(implementation) if !test_only(&implementation.attrs) => {
                let owner = implementation.self_ty.to_token_stream().to_string();
                let self_is_material = type_name(&implementation.self_ty).as_deref()
                    == Some(semantic_name(&proof.type_name));
                // The only admitted material trait impl is an exactly pinned
                // destructor; inventory other owners' trait methods normally.
                if implementation.trait_.is_some() && self_is_material {
                    continue;
                }
                for member in &implementation.items {
                    if let syn::ImplItem::Fn(function) = member
                        && !test_only(&function.attrs)
                    {
                        inspect_function(
                            Some(owner.clone()),
                            self_is_material,
                            &function.vis,
                            &function.sig,
                            found,
                        )?;
                    }
                }
            }
            Item::Trait(definition) if !test_only(&definition.attrs) => {
                for member in &definition.items {
                    if let syn::TraitItem::Fn(function) = member
                        && !test_only(&function.attrs)
                    {
                        inspect_function(
                            Some(definition.ident.to_string()),
                            false,
                            &Visibility::Inherited,
                            &function.sig,
                            found,
                        )?;
                    }
                }
            }
            Item::Mod(module) if !test_only(&module.attrs) => {
                if let Some((_, items)) = &module.content {
                    inspect_material_uses(proof, items, reviewed, found)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn proof_definition<'a>(selected: &str, items: &'a [Item]) -> Result<&'a syn::ItemStruct> {
    let declarations: Vec<_> = items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(value) if ident_is(&value.ident, selected) => Some(value),
            _ => None,
        })
        .collect();
    ensure!(
        declarations.len() == 1,
        "configured proof {} must have one explicit owning definition",
        selected
    );
    Ok(declarations[0])
}

// Visit blocks as well as module items: local aliases can otherwise conceal a
// constructor under an erased return type. Refusal needs no alias resolution.
fn inspect_proof_syntax(selected: &str, items: &[Item]) -> Result<()> {
    struct Syntax<'a> {
        selected: &'a str,
        failure: Option<&'static str>,
    }
    impl<'ast> Visit<'ast> for Syntax<'_> {
        fn visit_item(&mut self, item: &'ast Item) {
            let attributes: &[syn::Attribute] = match item {
                Item::Const(value) => &value.attrs,
                Item::Fn(value) => &value.attrs,
                Item::Impl(value) => &value.attrs,
                Item::Mod(value) => &value.attrs,
                Item::Static(value) => &value.attrs,
                Item::Trait(value) => &value.attrs,
                Item::Type(value) => &value.attrs,
                Item::Use(value) => &value.attrs,
                _ => &[],
            };
            if self.failure.is_some() || test_only(attributes) {
                return;
            }
            match item {
                Item::Type(alias) if contains_proof(&alias.ty, self.selected, false) => {
                    self.failure = Some("proof aliases require an explicit boundary review");
                }
                Item::Use(import) if uses_proof_alias(&import.tree, self.selected) => {
                    self.failure = Some("proof import aliases require an explicit boundary review");
                }
                Item::Impl(implementation)
                    if implementation.trait_.is_none()
                        && type_name(&implementation.self_ty).as_deref()
                            == Some(semantic_name(self.selected))
                        && implementation.items.iter().any(|item| {
                            matches!(item, syn::ImplItem::Macro(invocation)
                                if !test_only(&invocation.attrs))
                        }) =>
                {
                    self.failure = Some("proof inherent APIs cannot be generated by macros");
                }
                _ => syn::visit::visit_item(self, item),
            }
        }

        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if !test_only(&function.attrs) {
                syn::visit::visit_impl_item_fn(self, function);
            }
        }

        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if !test_only(&function.attrs) {
                syn::visit::visit_trait_item_fn(self, function);
            }
        }
    }
    let mut syntax = Syntax {
        selected,
        failure: None,
    };
    for item in items {
        syntax.visit_item(item);
    }
    if let Some(failure) = syntax.failure {
        anyhow::bail!(failure);
    }
    Ok(())
}

/// Exact explicit inputs for nonmaterial proofs, including owned values and
/// shared borrows with interior mutability. Existing inherent APIs and factories
/// are reviewed separately. This visits local functions and inline children,
/// not closure bindings, transitive aliases or expanded/out-of-line source.
fn collect_proof_uses(
    selected: &str,
    items: &[Item],
    tuple: bool,
) -> Result<BTreeSet<(Option<String>, String)>> {
    struct Uses<'a> {
        selected: &'a str,
        tuple: bool,
        owner: Option<String>,
        protected_owner: bool,
        self_is_proof: bool,
        function_depth: usize,
        module_depth: usize,
        found: BTreeSet<(Option<String>, String)>,
        failure: Option<anyhow::Error>,
    }
    impl Uses<'_> {
        fn function(
            &mut self,
            visibility: &Visibility,
            function: &syn::Signature,
            body: Option<&syn::Block>,
            factory_context: bool,
        ) {
            if self.failure.is_some() || self.protected_owner {
                return;
            }
            let typed_input = function.inputs.iter().any(|argument| match argument {
                syn::FnArg::Typed(argument) => {
                    contains_proof(&argument.ty, self.selected, self.self_is_proof)
                }
                syn::FnArg::Receiver(receiver) => {
                    contains_proof(&receiver.ty, self.selected, self.self_is_proof)
                }
            });
            // A generic input can carry the proof through an explicit bound,
            // e.g. T: AsMut<Permit>, without naming it in the parameter's type.
            struct Bound<'a> {
                selected: &'a str,
                found: bool,
            }
            impl<'ast> Visit<'ast> for Bound<'_> {
                fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
                    self.found |= path
                        .path
                        .segments
                        .last()
                        .is_some_and(|segment| ident_is(&segment.ident, self.selected));
                    syn::visit::visit_type_path(self, path);
                }
            }
            let mut bound = Bound {
                selected: self.selected,
                found: false,
            };
            bound.visit_generics(&function.generics);
            if !typed_input && !bound.found {
                return;
            }
            let returns_proof = matches!(&function.output, syn::ReturnType::Type(_, ty)
                if contains_proof(ty, self.selected, self.self_is_proof));
            if factory_context
                && (returns_proof
                    || body.is_some_and(|body| {
                        constructs_proof(body, self.selected, self.self_is_proof, self.tuple)
                    }))
            {
                return;
            }
            let identity = (self.owner.clone(), signature(visibility, function));
            if !self.found.insert(identity) {
                self.failure = Some(anyhow::anyhow!("ambiguous nonmaterial proof use"));
            } else if self.found.len() > 32 {
                self.failure = Some(anyhow::anyhow!("proof use API budget"));
            }
        }
    }
    impl<'ast> Visit<'ast> for Uses<'_> {
        fn visit_item(&mut self, item: &'ast Item) {
            let attributes: &[syn::Attribute] = match item {
                Item::Fn(value) => &value.attrs,
                Item::Impl(value) => &value.attrs,
                Item::Mod(value) => &value.attrs,
                Item::Trait(value) => &value.attrs,
                Item::Const(value) => &value.attrs,
                Item::Static(value) => &value.attrs,
                _ => &[],
            };
            if self.failure.is_none() && !test_only(attributes) {
                syn::visit::visit_item(self, item);
            }
        }

        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            let owner = self.owner.take();
            let protected = std::mem::replace(&mut self.protected_owner, false);
            let self_is_proof = std::mem::replace(&mut self.self_is_proof, false);
            self.function(
                &function.vis,
                &function.sig,
                Some(&function.block),
                self.function_depth == 0,
            );
            self.function_depth += 1;
            syn::visit::visit_item_fn(self, function);
            self.function_depth -= 1;
            self.owner = owner;
            self.protected_owner = protected;
            self.self_is_proof = self_is_proof;
        }

        fn visit_item_impl(&mut self, implementation: &'ast syn::ItemImpl) {
            let owner = self
                .owner
                .replace(implementation.self_ty.to_token_stream().to_string());
            let self_is_proof = std::mem::replace(
                &mut self.self_is_proof,
                type_name(&implementation.self_ty).as_deref() == Some(semantic_name(self.selected)),
            );
            let protected = std::mem::replace(
                &mut self.protected_owner,
                self.self_is_proof && self.module_depth == 0 && self.function_depth == 0,
            );
            syn::visit::visit_item_impl(self, implementation);
            self.owner = owner;
            self.protected_owner = protected;
            self.self_is_proof = self_is_proof;
        }

        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if !test_only(&function.attrs) {
                self.function(
                    &function.vis,
                    &function.sig,
                    Some(&function.block),
                    self.function_depth == 0,
                );
                self.function_depth += 1;
                syn::visit::visit_impl_item_fn(self, function);
                self.function_depth -= 1;
            }
        }

        fn visit_item_trait(&mut self, definition: &'ast syn::ItemTrait) {
            let owner = self.owner.replace(definition.ident.to_string());
            let protected = std::mem::replace(&mut self.protected_owner, false);
            let self_is_proof = std::mem::replace(&mut self.self_is_proof, false);
            syn::visit::visit_item_trait(self, definition);
            self.owner = owner;
            self.protected_owner = protected;
            self.self_is_proof = self_is_proof;
        }

        fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
            if !test_only(&function.attrs) {
                self.function(
                    &Visibility::Inherited,
                    &function.sig,
                    function.default.as_ref(),
                    false,
                );
                self.function_depth += 1;
                syn::visit::visit_trait_item_fn(self, function);
                self.function_depth -= 1;
            }
        }

        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            self.module_depth += 1;
            syn::visit::visit_item_mod(self, module);
            self.module_depth -= 1;
        }
    }
    let mut uses = Uses {
        selected,
        tuple,
        owner: None,
        protected_owner: false,
        self_is_proof: false,
        function_depth: 0,
        module_depth: 0,
        found: BTreeSet::new(),
        failure: None,
    };
    for item in items {
        uses.visit_item(item);
    }
    if let Some(failure) = uses.failure {
        return Err(failure);
    }
    Ok(uses.found)
}

fn inspect(proof: &Proof, items: &[Item]) -> Result<()> {
    // The configured definition lives at its owning module's top level. Moving
    // it behind a macro, alias or conditional wrapper requires explicit review.
    let definition = proof_definition(&proof.type_name, items)?;
    inspect_proof_syntax(&proof.type_name, items)?;
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
            !path_is_ident(attribute.path(), "cfg_attr"),
            "proof attributes cannot hide conditional derives"
        );
        if path_is_ident(attribute.path(), "derive") {
            let derives =
                attribute.parse_args_with(Punctuated::<syn::Path, Comma>::parse_terminated)?;
            for derive in derives {
                let name = derive
                    .segments
                    .last()
                    .context("proof derive name")?
                    .ident
                    .unraw()
                    .to_string();
                ensure!(
                    proof.kind.permits_derive(&name),
                    "proof {} cannot derive {name}",
                    proof.type_name
                );
            }
        }
    }
    ensure!(
        destructor_fingerprint(proof, items)? == proof.destructor,
        "reviewed proof destructor changed or missing from {}",
        proof.type_name
    );
    let mut found_methods = BTreeSet::new();
    let methods = reviewed_methods(proof)?;
    for item in items {
        let Item::Impl(implementation) = item else {
            continue;
        };
        if type_name(&implementation.self_ty).as_deref() != Some(semantic_name(&proof.type_name)) {
            continue;
        }
        if implementation.trait_.is_some() {
            continue;
        }
        for item in &implementation.items {
            let syn::ImplItem::Fn(function) = item else {
                continue;
            };
            let name = semantic_ident(&function.sig.ident);
            ensure!(
                methods.get(&name) == Some(&signature(&function.vis, &function.sig)),
                "unreviewed proof method {}::{name}",
                proof.type_name
            );
            ensure!(
                found_methods.insert(name.clone()),
                "ambiguous proof method {name}"
            );
            if !proof
                .consuming_methods
                .iter()
                .any(|method| semantic_name(method) == name)
            {
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
        Some(&reviewed),
        &mut found,
    )?;
    ensure!(
        found == reviewed,
        "reviewed proof factory missing from {}",
        proof.type_name
    );
    if matches!(proof.kind, Kind::PrivateMaterial) {
        let reviewed = reviewed_material_uses(proof)?;
        let mut found = BTreeSet::new();
        inspect_material_uses(proof, items, Some(&reviewed), &mut found)?;
        ensure!(
            found == reviewed,
            "reviewed private material use missing from {}",
            proof.type_name
        );
    } else {
        let reviewed = reviewed_signatures(&proof.proof_uses)?;
        let found = collect_proof_uses(
            &proof.type_name,
            items,
            matches!(definition.fields, syn::Fields::Unnamed(_)),
        )?;
        if let Some((owner, signature)) = found.difference(&reviewed).next() {
            anyhow::bail!(
                "unreviewed nonmaterial proof use {}::{}, signature {}",
                proof.type_name,
                owner.as_deref().unwrap_or("<free>"),
                signature
            );
        }
        ensure!(
            found == reviewed,
            "reviewed nonmaterial proof use missing from {}",
            proof.type_name
        );
    }
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
        let items = owning_items(
            &root,
            &proof.source,
            &proof.type_name,
            proof.owning_children.as_deref(),
        )?;
        inspect(proof, &items)
            .with_context(|| format!("proof boundary {}::{}", proof.source, proof.type_name))?;
    }
    for buffer in &policy.buffer_destructors {
        inspect_buffer(&root, buffer)?;
    }
    println!(
        "Authority proof boundaries checked: {} handles; {} parsed buffer destructors",
        policy.proofs.len(),
        policy.buffer_destructors.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn proof(kind: Kind) -> Proof {
        Proof {
            source: "crates/example/src/proofs.rs".into(),
            type_name: "Permit".into(),
            kind,
            consuming_methods: vec!["send".into()],
            methods: vec!["pub fn send(self)".into()],
            factories: vec![],
            material_uses: vec![],
            proof_uses: vec![],
            destructor: None,
            owning_children: None,
        }
    }

    fn check_source(source: &str) -> Result<()> {
        inspect(&proof(Kind::Consuming), &syn::parse_file(source)?.items)
    }

    #[test]
    fn raw_proof_owners_factories_inputs_aliases_and_traits_cannot_escape_review() -> Result<()> {
        let base =
            "struct Claim; pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }";
        inspect(&proof(Kind::Consuming), &syn::parse_file(base)?.items)?;
        for owner in ["Permit", "r#Permit"] {
            for (addition, category) in [
                (
                    format!("impl {owner} {{ pub fn raw(&self) -> &Claim {{ &self.claim }} }}"),
                    "unreviewed proof method",
                ),
                (
                    format!("fn forge(claim: Claim) -> {owner} {{ {owner} {{ claim }} }}"),
                    "unreviewed proof factory",
                ),
                (
                    format!(
                        "fn erased(claim: Claim) -> Box<dyn std::any::Any> {{ Box::new({owner} {{ claim }}) }}"
                    ),
                    "unreviewed proof factory",
                ),
                (
                    format!("fn borrowed(permit: &{owner}) {{}}"),
                    "unreviewed nonmaterial proof use",
                ),
                (
                    format!("fn bounded<T: AsRef<{owner}>>(permit: T) {{}}"),
                    "unreviewed nonmaterial proof use",
                ),
                (
                    format!(
                        "impl std::ops::Deref for {owner} {{ type Target = Claim; fn deref(&self) -> &Claim {{ &self.claim }} }}"
                    ),
                    "cannot gain a manual trait implementation",
                ),
                (format!("type Alias = {owner};"), "proof aliases require"),
                (
                    format!("use self::{owner} as Alias;"),
                    "proof import aliases require",
                ),
            ] {
                let source = syn::parse_file(&format!("{base} {addition}"))?;
                let error = inspect(&proof(Kind::Consuming), &source.items)
                    .unwrap_err()
                    .to_string();
                ensure!(error.contains(category), "{addition}: {error}");
            }
        }
        // The inherent signature is deliberately reviewed so this control
        // reaches factory admission rather than stopping at method admission.
        let mut reviewed = proof(Kind::Consuming);
        reviewed
            .methods
            .push("pub fn forge(claim: Claim) -> Self".into());
        for owner in ["Permit", "r#Permit"] {
            let source = syn::parse_file(&format!(
                "{base} impl {owner} {{ pub fn forge(claim: Claim) -> Self {{ Self {{ claim }} }} }}"
            ))?;
            ensure!(
                inspect(&reviewed, &source.items)
                    .unwrap_err()
                    .to_string()
                    .contains("unreviewed proof factory")
            );
        }

        let mut material = proof(Kind::PrivateMaterial);
        material.material_uses.push(Factory {
            owner: Some("Permit".into()),
            signature: material.methods[0].clone(),
        });
        inspect(&material, &syn::parse_file(base)?.items)?;
        for owner in ["Permit", "r#Permit"] {
            let source = syn::parse_file(&format!("{base} fn borrowed(material: &{owner}) {{}}"))?;
            ensure!(
                inspect(&material, &source.items)
                    .unwrap_err()
                    .to_string()
                    .contains("unreviewed private material use")
            );
        }
        Ok(())
    }

    #[test]
    fn raw_identity_recognition_preserves_exact_reviewed_signatures_and_data() -> Result<()> {
        let source = syn::parse_file(
            "struct Claim; struct r#Data { r#claim: Claim } impl r#Data { fn new(claim: Claim) -> Self { Self { claim } } } pub struct r#Permit { r#claim: Claim } impl r#Permit { pub fn r#send(self) {} pub fn prepare(claim: Claim) -> Self { Self { claim } } }",
        )?;
        let mut reviewed = proof(Kind::Consuming);
        reviewed.methods = vec![
            "pub fn r#send(self)".into(),
            "pub fn prepare(claim: Claim) -> Self".into(),
        ];
        reviewed.factories.push(Factory {
            owner: Some("r#Permit".into()),
            signature: reviewed.methods[1].clone(),
        });
        inspect(&reviewed, &source.items)?;
        // Semantic identity does not erase the raw owner or member spelling
        // from the exact source API catalog.
        reviewed.factories[0].owner = Some("Permit".into());
        ensure!(
            inspect(&reviewed, &source.items)
                .unwrap_err()
                .to_string()
                .contains("unreviewed proof factory")
        );
        reviewed.factories[0].owner = Some("r#Permit".into());
        reviewed.methods[0] = "pub fn send(self)".into();
        ensure!(
            inspect(&reviewed, &source.items)
                .unwrap_err()
                .to_string()
                .contains("unreviewed proof method")
        );
        let mut duplicate = proof(Kind::Consuming);
        duplicate.methods.push("pub fn r#send(self)".into());
        ensure!(
            reviewed_methods(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate reviewed proof method")
        );
        Ok(())
    }

    #[test]
    fn raw_destructor_shadow_refuses_byte_identical_reviewed_impl() -> Result<()> {
        let reviewed = drop_proof();
        let baseline = syn::parse_file(&format!("{DROP_BASE} {REVIEWED_DROP}"))?;
        inspect(&reviewed, &baseline.items)?;
        for alias in [
            "trait LocalDrop { fn drop(&mut self); } use LocalDrop as r#Drop;",
            "trait r#Drop { fn drop(&mut self); }",
        ] {
            let source = syn::parse_file(&format!("{DROP_BASE} {alias} {REVIEWED_DROP}"))?;
            let actual = source
                .items
                .iter()
                .find_map(|item| match item {
                    Item::Impl(item) if item.trait_.is_some() => {
                        Some(item.to_token_stream().to_string())
                    }
                    _ => None,
                })
                .context("fixture destructor")?;
            ensure!(
                actual
                    == syn::parse_str::<syn::ItemImpl>(REVIEWED_DROP)?
                        .to_token_stream()
                        .to_string()
            );
            let error = destructor_fingerprint(&reviewed, &source.items)
                .unwrap_err()
                .to_string();
            ensure!(error.contains("cannot be shadowed"), "{alias}: {error}");
        }
        for source in [
            "use fake as r#std; impl std::ops::Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "mod r#core { pub mod ops { pub trait Drop { fn drop(&mut self); } } } impl core::ops::Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
        ] {
            let parsed = syn::parse_file(&format!("{DROP_BASE} {source}"))?;
            ensure!(
                destructor_fingerprint(&reviewed, &parsed.items)
                    .unwrap_err()
                    .to_string()
                    .contains("cannot be shadowed")
            );
        }
        Ok(())
    }

    #[test]
    fn genuine_raw_standard_destructor_retains_exact_ast_pin() -> Result<()> {
        let source = syn::parse_file(
            "pub struct r#Permit { claim: Vec<u8> } impl r#Permit { pub fn send(self) {} } impl ::r#std::ops::r#Drop for r#Permit { fn r#drop(&mut self) { self.claim.fill(0); } }",
        )?;
        let mut reviewed = proof(Kind::Consuming);
        let actual =
            destructor_fingerprint(&reviewed, &source.items)?.context("raw native destructor")?;
        ensure!(actual != drop_proof().destructor.context("normal fixture pin")?);
        reviewed.destructor = Some(actual);
        inspect(&reviewed, &source.items)?;
        let mut normal_pin = proof(Kind::Consuming);
        normal_pin.destructor = drop_proof().destructor;
        ensure!(
            inspect(&normal_pin, &source.items)
                .unwrap_err()
                .to_string()
                .contains("destructor changed")
        );
        Ok(())
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

    const NONMATERIAL: &str =
        "pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }";

    #[test]
    fn nonmaterial_proof_inputs_require_exact_owned_shared_and_mutable_uses() -> Result<()> {
        for kind in [Kind::Readiness, Kind::Consuming, Kind::SecretPermit] {
            for (input, body) in [
                ("mut value: Permit", "value.claim = replacement();"),
                ("value: &Permit", "value.claim.reset();"),
                ("value: &mut Permit", "value.claim = replacement();"),
                ("value: Option<Box<crate::owner::Permit>>", "drop(value);"),
            ] {
                let signature = format!("pub(crate) fn retarget({input}) -> bool");
                let source =
                    syn::parse_file(&format!("{NONMATERIAL} {signature} {{ {body} true }}"))?;
                let mut reviewed = proof(kind);
                let refusal = inspect(&reviewed, &source.items)
                    .err()
                    .context("unreviewed proof input admitted")?;
                ensure!(
                    refusal
                        .to_string()
                        .contains("unreviewed nonmaterial proof use"),
                    "wrong rejection: {refusal}"
                );
                reviewed.proof_uses.push(Factory {
                    owner: None,
                    signature,
                });
                inspect(&reviewed, &source.items)?;
                ensure!(reviewed.factories.is_empty() && reviewed.material_uses.is_empty());
            }
        }
        for signature in [
            "fn retarget<T: AsMut<Permit>>(mut value: T) -> bool",
            "fn retarget<T>(mut value: T) -> bool where T: AsMut<crate::owner::Permit>",
        ] {
            let syntax = syn::parse_file(&format!(
                "{NONMATERIAL} {signature} {{ value.as_mut().claim = replacement(); true }}"
            ))?;
            let mut reviewed = proof(Kind::Consuming);
            ensure!(inspect(&reviewed, &syntax.items).is_err());
            reviewed.proof_uses.push(Factory {
                owner: None,
                signature: signature.into(),
            });
            inspect(&reviewed, &syntax.items)?;
        }
        Ok(())
    }

    #[test]
    fn proof_use_catalog_includes_other_owners_inline_traits_and_local_functions() -> Result<()> {
        for (addition, owner, signature) in [
            (
                "impl Other { fn retarget(&self, value: &mut Permit) { value.claim = replacement(); } }",
                Some("Other"),
                "fn retarget(&self, value: &mut Permit)",
            ),
            (
                "mod child { pub(super) fn retarget(value: &mut super::Permit) { value.claim = replacement(); } }",
                None,
                "pub(super) fn retarget(value: &mut super::Permit)",
            ),
            (
                "mod child { impl super::Permit { fn retarget(&mut self) { self.claim = replacement(); } } }",
                Some("super :: Permit"),
                "fn retarget(&mut self)",
            ),
            (
                "trait Observer { fn inspect(&self, value: &Permit); }",
                Some("Observer"),
                "fn inspect(&self, value: &Permit)",
            ),
            (
                "fn outer() { fn retarget(mut value: Permit) -> bool { value.claim = replacement(); true } }",
                None,
                "fn retarget(mut value: Permit) -> bool",
            ),
            (
                "fn outer() { fn retarget(value: &Permit) -> &Permit { value } }",
                None,
                "fn retarget(value: &Permit) -> &Permit",
            ),
            (
                "trait Observer { fn inspect(&self, value: &Permit) -> &Permit { value } }",
                Some("Observer"),
                "fn inspect(&self, value: &Permit) -> &Permit",
            ),
        ] {
            let source = syn::parse_file(&format!("{NONMATERIAL} {addition}"))?;
            let mut reviewed = proof(Kind::Consuming);
            ensure!(inspect(&reviewed, &source.items).is_err());
            reviewed.proof_uses.push(Factory {
                owner: owner.map(str::to_owned),
                signature: signature.into(),
            });
            inspect(&reviewed, &source.items)?;
        }
        let mut source = syn::parse_file(NONMATERIAL)?;
        let Item::Impl(implementation) = &mut source.items[1] else {
            anyhow::bail!("fixture inherent impl");
        };
        let syn::ImplItem::Fn(function) = &mut implementation.items[0] else {
            anyhow::bail!("fixture consuming method");
        };
        function.block = syn::parse_quote!({
            fn retarget(value: &mut Permit) {
                value.claim = replacement();
            }
        });
        ensure!(
            inspect(&proof(Kind::Consuming), &source.items)
                .err()
                .context("local function hidden in reviewed method admitted")?
                .to_string()
                .contains("unreviewed nonmaterial proof use")
        );
        Ok(())
    }

    #[test]
    fn proof_uses_do_not_duplicate_factories_or_inherent_apis() -> Result<()> {
        let mut reviewed = proof(Kind::Consuming);
        reviewed.factories.push(Factory {
            owner: None,
            signature: "fn renew(value: Permit) -> Permit".into(),
        });
        let syntax = syn::parse_file(&format!(
            "{NONMATERIAL} fn renew(value: Permit) -> Permit {{ value }}"
        ))?;
        inspect(&reviewed, &syntax.items)?;
        ensure!(collect_proof_uses("Permit", &syntax.items, false)?.is_empty());
        for addition in [
            "#[cfg(test)] fn retarget(value: &mut Permit) {}",
            "#[cfg(test)] mod child { fn retarget(value: &mut super::Permit) {} }",
            "impl Other { #[cfg(test)] fn retarget(&self, value: &mut Permit) {} }",
            "#[cfg(test)] impl Other { fn retarget(&self, value: &mut Permit) {} }",
            "fn ordinary(value: &mut Ordinary) {}",
        ] {
            let syntax = syn::parse_file(&format!("{NONMATERIAL} {addition}"))?;
            inspect(&proof(Kind::Consuming), &syntax.items)?;
        }
        for conditional in ["not(test)", "unix", "windows"] {
            let syntax = syn::parse_file(&format!(
                "{NONMATERIAL} #[cfg({conditional})] fn retarget(value: &mut Permit) {{}}"
            ))?;
            ensure!(inspect(&proof(Kind::Consuming), &syntax.items).is_err());
        }
        Ok(())
    }

    #[test]
    fn proof_uses_refuse_stale_duplicate_excess_and_material_reclassification() -> Result<()> {
        let signature = "fn inspect(value: &Permit)";
        let mut reviewed = proof(Kind::Readiness);
        reviewed.proof_uses.push(Factory {
            owner: None,
            signature: signature.into(),
        });
        ensure!(
            inspect(&reviewed, &syn::parse_file(NONMATERIAL)?.items)
                .err()
                .context("stale proof use admitted")?
                .to_string()
                .contains("reviewed nonmaterial proof use missing")
        );
        let source = syn::parse_file(&format!(
            "{NONMATERIAL} {signature} {{}} mod child {{ {signature} {{}} }}"
        ))?;
        ensure!(
            inspect(&reviewed, &source.items)
                .err()
                .context("duplicate use identity admitted")?
                .to_string()
                .contains("ambiguous nonmaterial proof use")
        );
        reviewed.proof_uses.push(Factory {
            owner: None,
            signature: signature.into(),
        });
        ensure!(reviewed_signatures(&reviewed.proof_uses).is_err());
        let mut at_limit = proof(Kind::Readiness);
        let mut source = NONMATERIAL.to_owned();
        for index in 0..32 {
            let signature = format!("fn inspect_{index}(value: &Permit)");
            source.push_str(&format!(" {signature} {{}}"));
            at_limit.proof_uses.push(Factory {
                owner: None,
                signature,
            });
        }
        inspect(&at_limit, &syn::parse_file(&source)?.items)?;
        validate_policy(&Policy {
            version: 1,
            proofs: vec![at_limit],
            trait_checks: vec![],
            buffer_destructors: vec![],
        })?;
        source.push_str(" fn inspect_32(value: &Permit) {}");
        ensure!(
            collect_proof_uses("Permit", &syn::parse_file(&source)?.items, false)
                .err()
                .context("33 uses admitted")?
                .to_string()
                == "proof use API budget"
        );
        let mut excess = proof(Kind::Readiness);
        excess.proof_uses = (0..33)
            .map(|index| Factory {
                owner: None,
                signature: format!("fn inspect_{index}(value: &Permit)"),
            })
            .collect();
        ensure!(
            validate_policy(&Policy {
                version: 1,
                proofs: vec![excess],
                trait_checks: vec![],
                buffer_destructors: vec![],
            })
            .err()
            .context("33 reviewed proof uses admitted")?
            .to_string()
                == "proof API budget"
        );
        let mut material = private_material();
        material.proof_uses.push(Factory {
            owner: None,
            signature: signature.into(),
        });
        ensure!(
            validate_policy(&Policy {
                version: 1,
                proofs: vec![material],
                trait_checks: vec![],
                buffer_destructors: vec![],
            })
            .err()
            .context("material uses replaced by proof uses")?
            .to_string()
            .contains("cannot replace private material uses")
        );
        Ok(())
    }

    #[test]
    fn block_local_aliases_cannot_hide_erased_proof_factories_or_inputs() -> Result<()> {
        for alias in ["type Hidden = Permit;", "use self::Permit as Hidden;"] {
            for addition in [
                format!("fn forge() -> impl Send {{ {alias} Hidden {{ claim: claim() }} }}"),
                format!("fn outer() {{ {alias} fn retarget(value: &mut Hidden) {{}} }}"),
                format!(
                    "impl Other {{ fn forge() -> impl Send {{ {alias} Hidden {{ claim: claim() }} }} }}"
                ),
            ] {
                let syntax = syn::parse_file(&format!("{NONMATERIAL} {addition}"))?;
                ensure!(
                    inspect(&proof(Kind::Consuming), &syntax.items)
                        .err()
                        .context("block-local alias hid proof boundary")?
                        .to_string()
                        .contains("aliases require an explicit boundary review")
                );
            }
            let syntax = syn::parse_file(&format!(
                "{NONMATERIAL} #[cfg(test)] fn fixture() {{ {alias} }}"
            ))?;
            inspect(&proof(Kind::Consuming), &syntax.items)?;
        }
        Ok(())
    }

    #[test]
    fn protected_inherent_apis_refuse_macros_without_expanding_general_code() -> Result<()> {
        for addition in [
            "impl Permit { generated_api!(); }",
            "mod child { impl super::Permit { generated_api!(); } }",
            "#[cfg(not(test))] impl Permit { generated_api!(); }",
        ] {
            let syntax = syn::parse_file(&format!("{NONMATERIAL} {addition}"))?;
            ensure!(
                inspect(&proof(Kind::Consuming), &syntax.items)
                    .err()
                    .context("macro-generated protected API admitted")?
                    .to_string()
                    .contains("inherent APIs cannot be generated by macros")
            );
        }
        for addition in [
            "impl Other { ordinary_api!(); }",
            "impl Permit { #[cfg(test)] fixture_api!(); }",
            "#[cfg(test)] mod child { impl super::Permit { fixture_api!(); } }",
        ] {
            let syntax = syn::parse_file(&format!("{NONMATERIAL} {addition}"))?;
            inspect(&proof(Kind::Consuming), &syntax.items)?;
        }
        Ok(())
    }

    #[test]
    fn candidate_proof_uses_are_pin_free_sorted_bounded_actual_facts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        let source =
            format!("{NONMATERIAL} fn zeta(value: &Permit) {{}} fn alpha(mut value: Permit) {{}}");
        fs::write(owner.join("proofs.rs"), &source)?;
        let descriptor = serde_json::json!({
            "version": 1,
            "trait_checks": [],
            "destructors": [],
            "proof_uses": [{
                "source": "crates/example/src/proofs.rs",
                "type_name": "Permit"
            }]
        });
        let path = root.join("candidates.json");
        fs::write(&path, serde_json::to_vec(&descriptor)?)?;
        let facts = candidate_inventory(root, &path)?;
        ensure!(facts.proof_uses.len() == 1 && facts.proof_uses[0].uses.len() == 2);
        ensure!(
            facts.proof_uses[0].uses[0].signature == "fn alpha (mut value : Permit)"
                && facts.proof_uses[0].uses[1].signature == "fn zeta (value : & Permit)"
        );
        ensure!(
            !root.join(POLICY).exists() && fs::read_to_string(owner.join("proofs.rs"))? == source,
            "candidate inventory mutated or required policy"
        );
        for (field, value) in [
            ("fingerprint", serde_json::json!("sha256:forged")),
            ("uses", serde_json::json!([])),
        ] {
            let mut forged = descriptor.clone();
            forged["proof_uses"][0][field] = value;
            ensure!(
                serde_json::from_value::<CandidateDescriptor>(forged).is_err(),
                "candidate supplied admission values instead of selectors"
            );
        }
        let mut invalid = descriptor.clone();
        invalid["proof_uses"][0]["source"] = "crates/../escape.rs".into();
        ensure!(validate_candidate(&serde_json::from_value(invalid)?).is_err());
        let mut duplicate = descriptor.clone();
        duplicate["proof_uses"] =
            serde_json::json!([descriptor["proof_uses"][0], descriptor["proof_uses"][0]]);
        ensure!(
            validate_candidate(&serde_json::from_value(duplicate)?)
                .err()
                .context("duplicate candidate proof use selector admitted")?
                .to_string()
                == "duplicate candidate proof use selector"
        );
        let mut selectors = descriptor.clone();
        selectors["proof_uses"] = (0..128)
            .map(|index| {
                serde_json::json!({
                    "source": "crates/example/src/proofs.rs", "type_name": format!("Permit_{index}")
                })
            })
            .collect::<Vec<_>>()
            .into();
        validate_candidate(&serde_json::from_value(selectors.clone())?)?;
        selectors["proof_uses"]
            .as_array_mut()
            .context("proof use selectors")?
            .push(serde_json::json!({
                "source": "crates/example/src/proofs.rs", "type_name": "Permit_128"
            }));
        ensure!(
            validate_candidate(&serde_json::from_value(selectors)?)
                .err()
                .context("129 candidate proof use selectors admitted")?
                .to_string()
                == "proof candidate use selector budget"
        );
        let mut changed = descriptor;
        changed["proof_uses"][0]["type_name"] = "Missing".into();
        fs::write(&path, serde_json::to_vec(&changed)?)?;
        ensure!(candidate_inventory(root, &path).is_err());
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

    const DROP_BASE: &str =
        "pub struct Permit { claim: Vec<u8> } impl Permit { pub fn send(self) {} }";
    const REVIEWED_DROP: &str =
        "impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }";

    fn drop_proof() -> Proof {
        let mut reviewed = proof(Kind::Consuming);
        reviewed.destructor =
            destructor_fingerprint(&reviewed, &syn::parse_file(REVIEWED_DROP).unwrap().items)
                .unwrap();
        reviewed
    }

    #[test]
    fn consuming_proof_requires_exact_explicit_destructor_review() -> Result<()> {
        let reviewed = drop_proof();
        let source = format!("{DROP_BASE} {REVIEWED_DROP}");
        let parsed = syn::parse_file(&source)?;
        inspect(&reviewed, &parsed.items)?;
        ensure!(
            check_source(&source).is_err(),
            "unreviewed Drop must remain forbidden"
        );
        ensure!(
            inspect(&reviewed, &syn::parse_file(DROP_BASE)?.items).is_err(),
            "removing a reviewed destructor must fail"
        );
        let spaced = format!(
            "{DROP_BASE}\nimpl Drop for Permit {{\n fn drop( &mut self ) {{\n self.claim.fill( 0 );\n }}\n}}"
        );
        inspect(&reviewed, &syn::parse_file(&spaced)?.items)?;
        for path in [
            "std::ops::Drop",
            "core::ops::Drop",
            "::std::ops::Drop",
            "::core::ops::Drop",
        ] {
            let source = format!(
                "{DROP_BASE} {}",
                REVIEWED_DROP.replace("impl Drop", &format!("impl {path}"))
            );
            let syntax = syn::parse_file(&source)?;
            ensure!(
                inspect(&reviewed, &syntax.items).is_err(),
                "trait path is part of the exact pin"
            );
            let mut pinned = proof(Kind::Consuming);
            pinned.destructor = destructor_fingerprint(&pinned, &syntax.items)?;
            inspect(&pinned, &syntax.items)?;
        }
        Ok(())
    }

    #[test]
    fn reviewed_destructor_rejects_changed_body_members_other_traits_and_duplicates() -> Result<()>
    {
        let reviewed = drop_proof();
        for implementation in [
            "impl Drop for Permit { fn drop(&mut self) {} }",
            "impl Drop for Permit { fn drop(&mut self) { self.claim.fill(1); } }",
            "impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } fn leak(&self) {} }",
            "struct Other { claim: Vec<u8> } impl Drop for Other { fn drop(&mut self) { self.claim.fill(0); } }",
            "impl Clone for Permit { fn clone(&self) -> Self { Self { claim: self.claim.clone() } } }",
            "impl Drop for &mut Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "#[cfg(not(test))] impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "impl Drop for Permit { #[cfg(not(test))] fn drop(&mut self) { self.claim.fill(0); } }",
            "mod nested { use super::Permit; impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } } }",
        ] {
            let source = format!("{DROP_BASE} {implementation}");
            ensure!(
                inspect(&reviewed, &syn::parse_file(&source)?.items).is_err(),
                "accepted {implementation}"
            );
        }
        for suffix in [
            REVIEWED_DROP,
            "impl std::ops::Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "impl Clone for Permit { fn clone(&self) -> Self { Self { claim: self.claim.clone() } } }",
            "impl Permit { pub fn leak(&self) -> &[u8] { &self.claim } }",
            "mod nested { impl std::fmt::Debug for super::Permit {} }",
        ] {
            let source = format!("{DROP_BASE} {REVIEWED_DROP} {suffix}");
            ensure!(
                inspect(&reviewed, &syn::parse_file(&source)?.items).is_err(),
                "accepted {suffix}"
            );
        }
        let generic = syn::parse_file(
            "pub struct Permit<T> { claim: T } impl<T> Permit<T> { pub fn send(self) {} } impl<T> Drop for Permit<T> { fn drop(&mut self) {} }",
        )?;
        ensure!(
            inspect(&reviewed, &generic.items).is_err(),
            "generic destructor must fail"
        );
        Ok(())
    }

    #[test]
    fn destructor_trait_aliases_and_shadowed_standard_paths_cannot_supply_a_pin() -> Result<()> {
        let reviewed = drop_proof();
        for alias in [
            "use std::ops::Drop as Destructor; impl Destructor for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "trait Drop { fn drop(&mut self); } impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "#[cfg(unix)] use fake::Drop; impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "use fake::*; impl Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "use fake as std; impl std::ops::Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
            "mod core { pub mod ops { pub trait Drop { fn drop(&mut self); } } } impl core::ops::Drop for Permit { fn drop(&mut self) { self.claim.fill(0); } }",
        ] {
            let source = syn::parse_file(&format!("{DROP_BASE} {alias}"))?;
            ensure!(
                destructor_fingerprint(&reviewed, &source.items).is_err(),
                "accepted {alias}"
            );
        }
        Ok(())
    }

    #[test]
    fn destructor_inventory_reports_actual_source_sorted_without_refreshing_policy() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        let source = format!("{DROP_BASE} {REVIEWED_DROP}");
        fs::write(owner.join("proofs.rs"), &source)?;
        fs::write(owner.join("other.rs"), &source)?;
        let entries = ["proofs.rs", "other.rs"].map(|file| {
            serde_json::json!({
                "source": format!("crates/example/src/{file}"), "type_name": "Permit",
                "kind": "consuming", "consuming_methods": ["send"],
                "methods": ["pub fn send(self)"], "factories": [],
                "destructor": format!("sha256:{}", "0".repeat(64)),
            })
        });
        let policy = serde_json::json!({
            "version": 1,
            "proofs": entries,
        });
        let before = serde_json::to_vec(&policy)?;
        fs::write(root.join(POLICY), &before)?;
        let first = trait_check_inventory(root)?;
        let second = trait_check_inventory(root)?;
        ensure!(
            first.destructors == second.destructors && first.destructors.len() == 2,
            "inventory facts must be deterministic"
        );
        ensure!(
            first.destructors[0].source.ends_with("other.rs"),
            "destructor facts must be sorted"
        );
        ensure!(
            first.destructors[0].fingerprint == drop_proof().destructor.unwrap(),
            "inventory must derive the source impl, never repeat the policy pin"
        );
        ensure!(
            check(root).is_err(),
            "stale destructor pin must not admit the source"
        );
        fs::write(
            owner.join("proofs.rs"),
            source.replace("fill(0)", "fill(1)"),
        )?;
        let changed = trait_check_inventory(root)?;
        ensure!(
            changed.destructors[1].fingerprint != first.destructors[1].fingerprint,
            "changed destructor body must change the source fact"
        );
        ensure!(
            fs::read(root.join(POLICY))? == before,
            "inventory must never rewrite policy"
        );
        Ok(())
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

    const PRIVATE_MATERIAL: &str = "pub(crate) struct Permit { claim: Vec<u8> } mod sink;";

    fn private_material() -> Proof {
        let mut proof = proof(Kind::PrivateMaterial);
        proof.consuming_methods.clear();
        proof.methods.clear();
        proof
    }

    #[test]
    fn private_material_does_not_manufacture_an_inherent_consuming_method() -> Result<()> {
        let reviewed = private_material();
        inspect(&reviewed, &syn::parse_file(PRIVATE_MATERIAL)?.items)?;
        validate_policy(&Policy {
            version: 1,
            proofs: vec![reviewed],
            trait_checks: vec![],
            buffer_destructors: vec![],
        })?;
        assert!(matches!(
            serde_json::from_str::<Kind>("\"private_material\"")?,
            Kind::PrivateMaterial
        ));
        for kind in [Kind::Consuming, Kind::SecretPermit] {
            let mut proof = proof(kind);
            proof.consuming_methods.clear();
            proof.methods.clear();
            ensure!(
                validate_policy(&Policy {
                    version: 1,
                    proofs: vec![proof],
                    trait_checks: vec![],
                    buffer_destructors: vec![]
                })
                .is_err(),
                "existing consuming kinds must still require their inherent sink"
            );
        }
        Ok(())
    }

    #[test]
    fn private_material_requires_private_fields_no_traits_and_exact_owning_api() -> Result<()> {
        let reviewed = private_material();
        for derive in [
            "Debug",
            "Clone",
            "Copy",
            "Default",
            "Serialize",
            "Deserialize",
            "PartialEq",
            "Eq",
            "OtherDerive",
        ] {
            ensure!(
                inspect(
                    &reviewed,
                    &syn::parse_file(&format!("#[derive({derive})] {PRIVATE_MATERIAL}"))?.items
                )
                .is_err(),
                "private material cannot derive {derive}"
            );
        }
        for source in [
            "pub(crate) struct Permit { pub claim: Vec<u8> } mod sink;",
            "pub(crate) struct Permit { pub(crate) claim: Vec<u8> } mod sink;",
            "pub(crate) struct Permit { pub(super) claim: Vec<u8> } mod sink;",
            "pub(crate) struct Permit; mod sink;",
            "#[cfg_attr(feature = \"wire\", derive(Serialize))] pub(crate) struct Permit { claim: Vec<u8> } mod sink;",
        ] {
            ensure!(
                inspect(&reviewed, &syn::parse_file(source)?.items).is_err(),
                "accepted {source}"
            );
        }
        for escape in [
            "impl Debug for Permit {}",
            "impl Clone for Permit {}",
            "impl Serialize for Permit {}",
            "impl Deserialize<'static> for Permit {}",
            "impl AsRef<[u8]> for Permit {}",
            "impl Permit { pub fn from_bytes(claim: Vec<u8>) -> Self { Self { claim } } }",
            "pub fn forge(claim: Vec<u8>) -> Permit { Permit { claim } }",
            "impl Permit { pub fn bytes(&self) -> &[u8] { &self.claim } }",
            "impl Permit { pub fn into_bytes(self) -> Vec<u8> { self.claim } }",
            "pub fn bytes(value: &Permit) -> &[u8] { &value.claim }",
            "pub fn into_bytes(value: Permit) -> Vec<u8> { value.claim }",
            "impl Other { pub fn bytes(&self, value: &Permit) -> &[u8] { &value.claim } }",
            "trait Leak { fn bytes(value: &Permit) -> &[u8] { &value.claim } }",
            "impl Leak for Other { fn bytes(value: &Permit) -> &[u8] { &value.claim } }",
            "pub fn nested(value: Option<&Permit>) -> &[u8] { &value.unwrap().claim }",
            "mod child { impl super::Permit { pub fn bytes(&self) -> &[u8] { &self.claim } } }",
            "type Alias = Permit; pub fn bytes(value: &Alias) -> &[u8] { &value.claim }",
            "use self::Permit as Alias; pub fn bytes(value: &Alias) -> &[u8] { &value.claim }",
        ] {
            ensure!(
                inspect(
                    &reviewed,
                    &syn::parse_file(&format!("{PRIVATE_MATERIAL} {escape}"))?.items
                )
                .is_err(),
                "unreviewed private-material escape accepted: {escape}"
            );
        }
        Ok(())
    }

    #[test]
    fn private_material_keeps_exact_factories_and_optional_consuming_receiver_checks() -> Result<()>
    {
        let mut reviewed = private_material();
        reviewed.factories.push(Factory {
            owner: None,
            signature: "fn admit(claim: Vec<u8>) -> Permit".into(),
        });
        let source = format!(
            "{PRIVATE_MATERIAL} fn admit(claim: Vec<u8>) -> Permit {{ Permit {{ claim }} }}"
        );
        inspect(&reviewed, &syn::parse_file(&source)?.items)?;
        for changed in [
            source.replace("fn admit", "pub fn admit"),
            source.replace("fn admit", "fn forge"),
            PRIVATE_MATERIAL.into(),
        ] {
            ensure!(
                inspect(&reviewed, &syn::parse_file(&changed)?.items).is_err(),
                "factory drift accepted"
            );
        }
        for receiver in ["&self", "&mut self", "self: Box<Self>"] {
            let mut reviewed = private_material();
            reviewed.methods.push(format!("fn deliver({receiver})"));
            reviewed.consuming_methods.push("deliver".into());
            let source =
                format!("{PRIVATE_MATERIAL} impl Permit {{ fn deliver({receiver}) {{}} }}");
            ensure!(
                inspect(&reviewed, &syn::parse_file(&source)?.items).is_err(),
                "nonconsuming receiver {receiver}"
            );
        }
        let mut reviewed = private_material();
        reviewed.methods.push("fn deliver(self)".into());
        reviewed.consuming_methods.push("deliver".into());
        reviewed.material_uses.push(Factory {
            owner: Some("Permit".into()),
            signature: "fn deliver(self)".into(),
        });
        inspect(
            &reviewed,
            &syn::parse_file(&format!(
                "{PRIVATE_MATERIAL} impl Permit {{ fn deliver(self) {{}} }}"
            ))?
            .items,
        )?;
        reviewed.methods[0] = "async fn deliver(self)".into();
        reviewed.material_uses[0].signature = "async fn deliver(self)".into();
        ensure!(
            inspect(
                &reviewed,
                &syn::parse_file(&format!(
                    "{PRIVATE_MATERIAL} impl Permit {{ async fn deliver(self) {{}} }}"
                ))?
                .items
            )
            .is_err(),
            "asynchronous consumption must remain forbidden"
        );
        Ok(())
    }

    #[test]
    fn private_material_users_require_exact_separate_review_without_becoming_factories()
    -> Result<()> {
        let mut reviewed = private_material();
        reviewed.material_uses.push(Factory {
            owner: None,
            signature: "fn publish(value: Permit)".into(),
        });
        let source =
            format!("{PRIVATE_MATERIAL} fn publish(value: Permit) {{ sink::respond(value); }}");
        ensure!(
            inspect(&private_material(), &syn::parse_file(&source)?.items).is_err(),
            "material users require review"
        );
        inspect(&reviewed, &syn::parse_file(&source)?.items)?;
        validate_policy(&Policy {
            version: 1,
            proofs: vec![reviewed],
            trait_checks: vec![],
            buffer_destructors: vec![],
        })?;
        for changed in [
            source.replace("fn publish", "pub fn publish"),
            source.replace("value: Permit", "value: &Permit"),
            PRIVATE_MATERIAL.into(),
            format!("{source} fn publish(value: Permit) {{ sink::respond(value); }}"),
        ] {
            let mut reviewed = private_material();
            reviewed.material_uses.push(Factory {
                owner: None,
                signature: "fn publish(value: Permit)".into(),
            });
            ensure!(
                inspect(&reviewed, &syn::parse_file(&changed)?.items).is_err(),
                "material user drift accepted"
            );
        }
        let source = format!(
            "{PRIVATE_MATERIAL} mod inline {{ pub(super) fn publish(value: super::Permit) {{ super::sink::respond(value); }} }}"
        );
        ensure!(
            inspect(&private_material(), &syn::parse_file(&source)?.items).is_err(),
            "inline users require review"
        );
        let mut reviewed = private_material();
        reviewed.material_uses.push(Factory {
            owner: None,
            signature: "pub(super) fn publish(value: super::Permit)".into(),
        });
        inspect(&reviewed, &syn::parse_file(&source)?.items)?;
        let mut wrong = private_material();
        wrong.factories.push(Factory {
            owner: None,
            signature: "fn publish(value: Permit)".into(),
        });
        ensure!(
            inspect(&wrong, &syn::parse_file(&source)?.items).is_err(),
            "factory review cannot replace material-use review"
        );
        for kind in [Kind::Readiness, Kind::Consuming, Kind::SecretPermit] {
            let mut wrong = proof(kind);
            wrong.material_uses.push(Factory {
                owner: None,
                signature: "fn publish(value: Permit)".into(),
            });
            ensure!(
                validate_policy(&Policy {
                    version: 1,
                    proofs: vec![wrong],
                    trait_checks: vec![],
                    buffer_destructors: vec![]
                })
                .is_err(),
                "existing proof kinds cannot accept material-use policies"
            );
        }
        Ok(())
    }

    #[test]
    fn private_material_inherits_exact_destructor_pin_and_trait_refusal() -> Result<()> {
        let mut reviewed = private_material();
        let source = syn::parse_file(&format!("{PRIVATE_MATERIAL} {REVIEWED_DROP}"))?;
        ensure!(
            inspect(&reviewed, &source.items).is_err(),
            "unreviewed Drop must fail"
        );
        reviewed.destructor = destructor_fingerprint(&reviewed, &source.items)?;
        inspect(&reviewed, &source.items)?;
        for change in [
            PRIVATE_MATERIAL.into(),
            format!(
                "{PRIVATE_MATERIAL} {}",
                REVIEWED_DROP.replace("fill(0)", "clear()")
            ),
            format!("{PRIVATE_MATERIAL} {REVIEWED_DROP} {REVIEWED_DROP}"),
            format!("{PRIVATE_MATERIAL} {REVIEWED_DROP} impl Debug for Permit {{}}"),
        ] {
            ensure!(
                inspect(&reviewed, &syn::parse_file(&change)?.items).is_err(),
                "destructor/trait drift accepted"
            );
        }
        Ok(())
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
            buffer_destructors: vec![],
        };
        validate_policy(&policy).unwrap();
        for fingerprint in [
            "",
            "sha256:short",
            "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            policy.proofs[0].destructor = Some(fingerprint.into());
            assert!(
                validate_policy(&policy).is_err(),
                "invalid destructor pin {fingerprint}"
            );
        }
        policy.proofs[0].destructor = drop_proof().destructor;
        validate_policy(&policy).unwrap();
        policy.proofs[0].destructor = None;
        policy.proofs.push(proof(Kind::Consuming));
        assert!(validate_policy(&policy).is_err());
        policy.proofs.truncate(1);
        policy.proofs[0].source = "../outside.rs".into();
        assert!(validate_policy(&policy).is_err());
    }

    const BUFFER_SOURCE: &str = r#"
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(super) struct WireBuffer {
            body: Vec<u8>,
            #[serde(default)] refresh_token: Option<String>,
        }
        impl Drop for WireBuffer {
            fn drop(&mut self) {
                self.body.fill(0);
                if let Some(token) = &mut self.refresh_token { token.zeroize(); }
            }
        }
    "#;

    fn buffer_fixture(root: &Path) -> Result<serde_json::Value> {
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        fs::write(owner.join("proofs.rs"), DROP_BASE)?;
        fs::write(owner.join("buffers.rs"), BUFFER_SOURCE)?;
        let buffer = buffer_source_finding(
            "crates/example/src/buffers.rs",
            "WireBuffer",
            &syn::parse_file(BUFFER_SOURCE)?,
        )?;
        Ok(serde_json::json!({ "version": 1, "proofs": [{
            "source": "crates/example/src/proofs.rs", "type_name": "Permit", "kind": "consuming",
            "consuming_methods": ["send"], "methods": ["pub fn send(self)"], "factories": []
        }], "buffer_destructors": [buffer] }))
    }

    #[test]
    fn buffer_catalog_pins_wire_layout_and_destructor_without_authority_methods() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let policy = buffer_fixture(&root)?;
        fs::write(root.join(POLICY), serde_json::to_vec(&policy)?)?;
        check(&root)?;
        let facts = trait_check_inventory(&root)?;
        ensure!(
            facts.destructors.is_empty() && facts.buffer_destructors.len() == 1,
            "parsed buffers must remain separate from authority proof destructors"
        );
        ensure!(
            serde_json::to_value(&facts.buffer_destructors)? == policy["buffer_destructors"],
            "native buffer inventory must derive the admitted source facts"
        );
        let changed_spacing =
            BUFFER_SOURCE.replace("self.body.fill(0);", "self . body . fill ( 0 );");
        fs::write(root.join("crates/example/src/buffers.rs"), changed_spacing)?;
        check(&root)?;
        ensure!(
            fs::read(root.join(POLICY))? == serde_json::to_vec(&policy)?,
            "inventory or check wrote policy"
        );
        for visibility in ["", "pub(super) "] {
            let source = BUFFER_SOURCE.replace("pub(super) ", visibility);
            buffer_source_finding(
                "crates/example/src/buffers.rs",
                "WireBuffer",
                &syn::parse_file(&source)?,
            )?;
        }
        for codec in [
            "Serialize",
            "Deserialize",
            "serde::Serialize",
            "::serde::Deserialize",
        ] {
            let source = BUFFER_SOURCE.replace("serde::Serialize, serde::Deserialize", codec);
            buffer_source_finding(
                "crates/example/src/buffers.rs",
                "WireBuffer",
                &syn::parse_file(&source)?,
            )?;
        }
        Ok(())
    }

    #[test]
    fn buffer_catalog_rejects_field_codec_and_destructor_drift_without_repinning() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let policy = buffer_fixture(&root)?;
        fs::write(root.join(POLICY), serde_json::to_vec(&policy)?)?;
        let original = trait_check_inventory(&root)?.buffer_destructors.remove(0);
        for changed in [
            BUFFER_SOURCE.replace("body: Vec<u8>,", "body: Vec<u8>, access_token: String,"),
            BUFFER_SOURCE.replace("body: Vec<u8>,", "body: String,"),
            BUFFER_SOURCE.replace("body: Vec<u8>,", "payload: Vec<u8>,"),
            BUFFER_SOURCE.replace(
                "#[serde(default)]",
                "#[serde(default, rename = \"refresh\")]",
            ),
            BUFFER_SOURCE.replace("pub(super) ", ""),
            BUFFER_SOURCE.replace("self.body.fill(0);", "self.body.clear();"),
        ] {
            fs::write(root.join("crates/example/src/buffers.rs"), changed)?;
            ensure!(
                check(&root).is_err(),
                "buffer layout or destructor changed without explicit review"
            );
            let actual = trait_check_inventory(&root)?.buffer_destructors.remove(0);
            ensure!(
                actual != original,
                "native buffer facts copied a stale policy pin"
            );
            ensure!(
                fs::read(root.join(POLICY))? == serde_json::to_vec(&policy)?,
                "inventory refreshed buffer policy"
            );
        }
        Ok(())
    }

    #[test]
    fn buffer_shapes_forbid_public_fields_conditional_layouts_and_noncodec_derives() -> Result<()> {
        for derive in [
            "Debug",
            "Clone",
            "Copy",
            "Default",
            "PartialEq",
            "Eq",
            "RenamedCodec",
            "other::Deserialize",
        ] {
            let source = BUFFER_SOURCE.replace(
                "serde::Serialize, serde::Deserialize",
                &format!("serde::Deserialize, {derive}"),
            );
            let error = buffer_source_finding(
                "crates/example/src/buffers.rs",
                "WireBuffer",
                &syn::parse_file(&source)?,
            )
            .err()
            .context("forbidden buffer derive accepted")?;
            ensure!(
                error.to_string().starts_with("buffer cannot derive"),
                "derive restriction relied only on a stale pin"
            );
        }
        for source in [
            BUFFER_SOURCE.replace("body: Vec<u8>,", "pub body: Vec<u8>,"),
            BUFFER_SOURCE.replace("body: Vec<u8>,", "pub(crate) body: Vec<u8>,"),
            BUFFER_SOURCE.replace("body: Vec<u8>,", "pub(super) body: Vec<u8>,"),
            BUFFER_SOURCE.replace("pub(super) ", "pub "),
            BUFFER_SOURCE.replace("pub(super) ", "pub(crate) "),
            BUFFER_SOURCE.replace("struct WireBuffer", "struct WireBuffer<T>"),
            BUFFER_SOURCE.replace("pub(super) struct", "#[cfg(not(test))] pub(super) struct"),
            BUFFER_SOURCE.replace(
                "pub(super) struct",
                "#[cfg_attr(test, derive(Debug))] pub(super) struct",
            ),
            BUFFER_SOURCE.replace(
                "body: Vec<u8>,",
                "#[cfg(feature = \"body\")] body: Vec<u8>,",
            ),
            BUFFER_SOURCE.replace(
                "body: Vec<u8>,",
                "#[cfg_attr(test, serde(skip))] body: Vec<u8>,",
            ),
            format!("#![cfg(not(test))] {BUFFER_SOURCE}"),
            BUFFER_SOURCE.replace("#[derive(serde::Serialize, serde::Deserialize)]", ""),
            BUFFER_SOURCE.replace(
                "serde::Serialize, serde::Deserialize",
                "Deserialize, serde::Deserialize",
            ),
            BUFFER_SOURCE.replace(
                "body: Vec<u8>,\n            #[serde(default)] refresh_token: Option<String>,",
                "",
            ),
            format!("{BUFFER_SOURCE} #[derive(Deserialize)] struct WireBuffer {{ body: Vec<u8> }}"),
        ] {
            ensure!(
                buffer_source_finding(
                    "crates/example/src/buffers.rs",
                    "WireBuffer",
                    &syn::parse_file(&source)?
                )
                .is_err(),
                "unsafe or ambiguous buffer shape accepted: {source}"
            );
        }
        Ok(())
    }

    #[test]
    fn buffer_destructors_retain_exact_drop_and_all_manual_trait_restrictions() -> Result<()> {
        let syntax = syn::parse_file(BUFFER_SOURCE)?;
        let definition = syntax.items[0].to_token_stream().to_string();
        let destructor = syntax.items[1].to_token_stream().to_string();
        for source in [
            definition.clone(),
            format!("{BUFFER_SOURCE} {destructor}"),
            format!("{definition} #[cfg(not(test))] {destructor}"),
            format!(
                "{definition} {}",
                destructor.replace("for WireBuffer", "for Other")
            ),
            format!("{definition} mod child {{ {destructor} }}"),
            format!("{BUFFER_SOURCE} impl Debug for WireBuffer {{}}"),
            format!("{BUFFER_SOURCE} impl Clone for &WireBuffer {{}}"),
            format!("{BUFFER_SOURCE} impl Serialize for WireBuffer {{}}"),
            format!("{definition} use other::Drop; {destructor}"),
        ] {
            ensure!(
                buffer_source_finding(
                    "crates/example/src/buffers.rs",
                    "WireBuffer",
                    &syn::parse_file(&source)?
                )
                .is_err(),
                "unconditional exact owning Drop or manual trait restriction weakened"
            );
        }
        Ok(())
    }

    #[test]
    fn buffer_policy_refuses_unknown_pins_duplicates_overlap_and_129_entries() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let policy = buffer_fixture(&root)?;
        let path = root.join(POLICY);
        for (field, value) in [
            ("definition_fingerprint", "NATIVE_INVENTORY_PENDING"),
            ("destructor_fingerprint", "sha256:short"),
            ("fingerprint", "unreviewed"),
        ] {
            let mut invalid = policy.clone();
            invalid["buffer_destructors"][0][field] = value.into();
            fs::write(&path, serde_json::to_vec(&invalid)?)?;
            ensure!(
                check(&root).is_err(),
                "invalid buffer pin or unknown field accepted"
            );
        }
        for (source, name) in [
            ("../buffers.rs", "WireBuffer"),
            ("crates/example/src/buffers.rs", "WireBuffer<T>"),
        ] {
            let mut invalid = policy.clone();
            invalid["buffer_destructors"][0]["source"] = source.into();
            invalid["buffer_destructors"][0]["type_name"] = name.into();
            ensure!(
                validate_policy(&serde_json::from_value(invalid)?).is_err(),
                "invalid buffer selection accepted"
            );
        }
        let mut duplicate = policy.clone();
        let buffer = duplicate["buffer_destructors"][0].clone();
        duplicate["buffer_destructors"]
            .as_array_mut()
            .context("buffer catalog")?
            .push(buffer);
        ensure!(
            validate_policy(&serde_json::from_value(duplicate)?).is_err(),
            "duplicate buffer catalog entry accepted"
        );
        let mut overlap = policy.clone();
        overlap["buffer_destructors"][0]["source"] = "crates/example/src/proofs.rs".into();
        overlap["buffer_destructors"][0]["type_name"] = "Permit".into();
        ensure!(
            validate_policy(&serde_json::from_value(overlap)?).is_err(),
            "buffer relabeled an authority proof"
        );
        let mut at_limit = policy;
        let template = at_limit["buffer_destructors"][0].clone();
        at_limit["buffer_destructors"] = (0..128)
            .map(|index| {
                let mut buffer = template.clone();
                buffer["type_name"] = format!("WireBuffer_{index}").into();
                buffer
            })
            .collect::<Vec<_>>()
            .into();
        validate_policy(&serde_json::from_value(at_limit.clone())?)?;
        fs::write(
            root.join("crates/example/src/buffers.rs"),
            (0..128)
                .map(|index| BUFFER_SOURCE.replace("WireBuffer", &format!("WireBuffer_{index}")))
                .collect::<Vec<_>>()
                .join("\n"),
        )?;
        let mut admitted = at_limit.clone();
        admitted["buffer_destructors"] = buffer_inventory(
            &root,
            at_limit["buffer_destructors"]
                .as_array()
                .context("buffer catalog")?
                .iter()
                .map(|entry| {
                    (
                        entry["source"].as_str().unwrap(),
                        entry["type_name"].as_str().unwrap(),
                    )
                }),
        )?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?
        .into();
        fs::write(&path, serde_json::to_vec(&admitted)?)?;
        check(&root)?;
        ensure!(
            trait_check_inventory(&root)?.buffer_destructors.len() == 128,
            "128 actual buffer definitions must remain admitted by the public guard"
        );
        let mut overflow = at_limit;
        let mut last = overflow["buffer_destructors"][0].clone();
        last["type_name"] = "WireBuffer_128".into();
        overflow["buffer_destructors"]
            .as_array_mut()
            .context("buffer catalog")?
            .push(last);
        fs::write(&path, serde_json::to_vec(&overflow)?)?;
        ensure!(
            check(&root).unwrap_err().to_string() == "buffer destructor catalog budget",
            "buffer entry bound changed"
        );
        Ok(())
    }

    #[test]
    fn candidate_buffer_layout_facts_are_pin_free_separate_and_deterministic() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        buffer_fixture(&root)?;
        let path = root.join("candidate.json");
        let descriptor = serde_json::json!({ "version": 1, "trait_checks": [], "destructors": [],
            "buffer_destructors": [{ "source": "crates/example/src/buffers.rs", "type_name": "WireBuffer" }] });
        fs::write(&path, serde_json::to_vec(&descriptor)?)?;
        let facts = candidate_inventory(&root, &path)?;
        ensure!(
            facts.destructors.is_empty() && facts.buffer_destructors.len() == 1,
            "candidate buffer descriptor was classified as an authority proof"
        );
        ensure!(
            !root.join(POLICY).exists(),
            "candidate buffer inventory wrote policy"
        );
        for pin in [
            "fingerprint",
            "definition_fingerprint",
            "destructor_fingerprint",
        ] {
            let mut forged = descriptor.clone();
            forged["buffer_destructors"][0][pin] = "unreviewed".into();
            fs::write(&path, serde_json::to_vec(&forged)?)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "candidate accepted a buffer pin"
            );
        }
        for (field, value) in [
            ("source", "../buffers.rs"),
            ("type_name", "WireBuffer<T>"),
            ("type_name", "MissingBuffer"),
        ] {
            let mut invalid = descriptor.clone();
            invalid["buffer_destructors"][0][field] = value.into();
            fs::write(&path, serde_json::to_vec(&invalid)?)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "candidate accepted invalid buffer selection"
            );
        }
        let mut duplicate = descriptor.clone();
        duplicate["destructors"] = duplicate["buffer_destructors"].clone();
        fs::write(&path, serde_json::to_vec(&duplicate)?)?;
        ensure!(
            candidate_inventory(&root, &path).is_err(),
            "candidate accepted overlapping destructor classifications"
        );
        let mut duplicate = descriptor.clone();
        let selected = duplicate["buffer_destructors"][0].clone();
        duplicate["buffer_destructors"]
            .as_array_mut()
            .context("candidate buffers")?
            .push(selected);
        fs::write(&path, serde_json::to_vec(&duplicate)?)?;
        ensure!(
            candidate_inventory(&root, &path).is_err(),
            "candidate accepted duplicate buffer selections"
        );
        let mut ordered = descriptor.clone();
        let mut second = ordered["buffer_destructors"][0].clone();
        second["type_name"] = "AnotherBuffer".into();
        ordered["buffer_destructors"]
            .as_array_mut()
            .context("candidate buffers")?
            .push(second);
        fs::write(
            root.join("crates/example/src/buffers.rs"),
            format!(
                "{BUFFER_SOURCE}\n{}",
                BUFFER_SOURCE.replace("WireBuffer", "AnotherBuffer")
            ),
        )?;
        fs::write(&path, serde_json::to_vec(&ordered)?)?;
        let ordered_facts = candidate_inventory(&root, &path)?;
        ensure!(
            ordered_facts.buffer_destructors[0].type_name == "AnotherBuffer",
            "buffer facts must sort by source and type"
        );
        ordered["buffer_destructors"]
            .as_array_mut()
            .context("candidate buffers")?
            .reverse();
        fs::write(&path, serde_json::to_vec(&ordered)?)?;
        ensure!(
            serde_json::to_value(candidate_inventory(&root, &path)?)?
                == serde_json::to_value(&ordered_facts)?,
            "candidate buffer facts depend on selector order"
        );
        fs::write(
            root.join("crates/example/src/buffers.rs"),
            BUFFER_SOURCE.replace("body: Vec<u8>,", "body: Vec<u8>, code: String,"),
        )?;
        fs::write(&path, serde_json::to_vec(&descriptor)?)?;
        let changed = candidate_inventory(&root, &path)?;
        ensure!(
            changed.buffer_destructors[0].definition_fingerprint
                != facts.buffer_destructors[0].definition_fingerprint
                && changed.buffer_destructors[0].destructor_fingerprint
                    == facts.buffer_destructors[0].destructor_fingerprint,
            "native layout facts must reflect added unadmitted plaintext fields independently of Drop"
        );
        let mut at_limit = descriptor;
        at_limit["buffer_destructors"] = (0..128).map(|index| serde_json::json!({
            "source": "crates/example/src/buffers.rs", "type_name": format!("WireBuffer_{index}")
        })).collect::<Vec<_>>().into();
        validate_candidate(&serde_json::from_value(at_limit.clone())?)?;
        at_limit["buffer_destructors"]
            .as_array_mut()
            .context("candidate buffers")?
            .push(serde_json::json!({
                "source": "crates/example/src/buffers.rs", "type_name": "WireBuffer_128"
            }));
        fs::write(&path, serde_json::to_vec(&at_limit)?)?;
        ensure!(
            candidate_inventory(&root, &path)
                .err()
                .context("129 candidate buffers accepted")?
                .to_string()
                == "buffer destructor catalog budget",
            "candidate buffer bound changed"
        );
        Ok(())
    }

    fn candidate_fixture(root: &Path) -> Result<serde_json::Value> {
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        fs::write(owner.join("lib.rs"), "mod assertions;")?;
        fs::write(
            owner.join("assertions.rs"),
            "macro_rules! assert_not_impl { () => {} } const _: () = { assert_not_impl!(); };",
        )?;
        fs::write(
            owner.join("proofs.rs"),
            format!("{DROP_BASE} {REVIEWED_DROP}"),
        )?;
        fs::write(
            owner.join("const_assertions.rs"),
            "const _: () = { macro_rules! assert_not_impl { () => {} } assert_not_impl!(); };",
        )?;
        Ok(serde_json::json!({ "version": 1, "trait_checks": [
            { "source": "crates/example/src/const_assertions.rs", "scope": "const", "registration": null },
            { "source": "crates/example/src/assertions.rs", "scope": "module",
                "registration": { "source": "crates/example/src/lib.rs", "module": "assertions" } }
        ], "destructors": [{ "source": "crates/example/src/proofs.rs", "type_name": "Permit" }] }))
    }

    #[test]
    fn candidate_inventory_derives_facts_without_admitting_or_mutating_policy() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let mut descriptor = candidate_fixture(&root)?;
        let path = root.join("candidate.json");
        fs::write(&path, serde_json::to_vec(&descriptor)?)?;
        // Candidate extraction works before any policy exists.
        let facts = candidate_inventory(&root, &path)?;
        ensure!(
            !root.join(POLICY).exists(),
            "candidate inventory wrote admission policy"
        );
        ensure!(
            serde_json::to_value(&facts)?
                .get("buffer_destructors")
                .is_none(),
            "existing empty-buffer inventories must retain their JSON shape"
        );
        ensure!(
            facts.trait_checks.len() == 2 && facts.destructors.len() == 1,
            "candidate inventory omitted selected AST facts"
        );
        ensure!(
            facts.trait_checks[0].source == "crates/example/src/assertions.rs",
            "source facts must have deterministic ordering"
        );
        ensure!(
            facts.destructors[0].fingerprint
                == drop_proof().destructor.context("reviewed fixture pin")?,
            "destructor facts must use the existing normalized AST pin"
        );
        descriptor["trait_checks"]
            .as_array_mut()
            .context("fixture trait descriptors")?
            .reverse();
        fs::write(&path, serde_json::to_vec(&descriptor)?)?;
        ensure!(
            serde_json::to_value(candidate_inventory(&root, &path)?)?
                == serde_json::to_value(&facts)?,
            "descriptor order changed source facts"
        );
        let rejected = br#"{"version":1,"proofs":[]}"#;
        fs::write(root.join(POLICY), rejected)?;
        ensure!(
            check(&root).is_err(),
            "invalid policy unexpectedly admitted"
        );
        candidate_inventory(&root, &path)?;
        ensure!(
            fs::read(root.join(POLICY))? == rejected.as_slice(),
            "candidate inventory repaired admission policy"
        );
        fs::write(
            root.join("crates/example/src/proofs.rs"),
            format!(
                "{DROP_BASE} {}",
                REVIEWED_DROP.replace("fill(0)", "clear()")
            ),
        )?;
        let changed = candidate_inventory(&root, &path)?;
        ensure!(
            changed.destructors[0].fingerprint != facts.destructors[0].fingerprint,
            "candidate destructor facts copied a stale pin"
        );
        ensure!(check(&root).is_err(), "source facts became a policy pass");
        Ok(())
    }

    #[test]
    fn candidate_descriptors_refuse_pins_unknown_fields_and_duplicate_keys() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let descriptor = candidate_fixture(&root)?;
        let path = root.join("candidate.json");
        for (field, target) in [
            ("fingerprint", "/trait_checks/0"),
            ("fingerprint", "/destructors/0"),
            ("fingerprint", "/trait_checks/1/registration"),
            ("proofs", ""),
        ] {
            let mut forged = descriptor.clone();
            forged
                .pointer_mut(target)
                .context("fixture descriptor target")?[field] = "unreviewed".into();
            fs::write(&path, serde_json::to_vec(&forged)?)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "candidate accepted {target}/{field}"
            );
        }
        let duplicate =
            br#"{"version":1,"trait_checks":[],"trait_\u0063hecks":[],"destructors":[]}"#;
        fs::write(&path, duplicate)?;
        ensure!(
            candidate_inventory(&root, &path)
                .err()
                .context("duplicate descriptor accepted")?
                .to_string()
                .contains("duplicate JSON key"),
            "candidate must use strict duplicate-key decoding"
        );
        let deep = format!(
            "{{\"version\":1,\"trait_checks\":{}0{},\"destructors\":[]}}",
            "[".repeat(33),
            "]".repeat(33)
        );
        fs::write(&path, deep)?;
        ensure!(
            candidate_inventory(&root, &path)
                .err()
                .context("deep descriptor accepted")?
                .to_string()
                == "JSON structure budget",
            "candidate must bound descriptor parsing"
        );
        fs::write(&path, vec![b' '; MAX_BYTES + 1])?;
        ensure!(
            candidate_inventory(&root, &path)
                .err()
                .context("oversized descriptor accepted")?
                .to_string()
                == "proof input byte budget",
            "candidate must bound descriptor bytes"
        );
        Ok(())
    }

    #[test]
    fn candidate_descriptors_reject_invalid_paths_scopes_types_and_duplicates() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let descriptor = candidate_fixture(&root)?;
        let path = root.join("candidate.json");
        for invalid in [
            "../outside.rs",
            "/crates/example/src/assertions.rs",
            "crates/example/../assertions.rs",
            "crates/example/src//assertions.rs",
            "crates/example/src/./assertions.rs",
            "crates/example/src\\assertions.rs",
            "crates/example/src/assertions.txt",
        ] {
            let mut changed = descriptor.clone();
            changed["trait_checks"][0]["source"] = invalid.into();
            fs::write(&path, serde_json::to_vec(&changed)?)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "candidate accepted path {invalid}"
            );
        }
        let mut changes = Vec::new();
        let mut changed = descriptor.clone();
        changed["version"] = 2.into();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["trait_checks"][0]["scope"] = "unknown".into();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["trait_checks"][1]["registration"] = serde_json::Value::Null;
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["trait_checks"][0]["registration"] =
            descriptor["trait_checks"][1]["registration"].clone();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["trait_checks"][1]["registration"]["source"] = "../lib.rs".into();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["trait_checks"][1]["registration"]["module"] = "wrong::module".into();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["destructors"][0]["type_name"] = "Permit<T>".into();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["destructors"][0]["type_name"] = "Missing".into();
        changes.push(changed);
        let mut changed = descriptor.clone();
        changed["trait_checks"][1]["source"] = changed["trait_checks"][0]["source"].clone();
        changes.push(changed);
        let mut changed = descriptor.clone();
        let duplicate = changed["destructors"][0].clone();
        changed["destructors"]
            .as_array_mut()
            .context("fixture destructor descriptors")?
            .push(duplicate);
        changes.push(changed);
        changes.push(serde_json::json!({ "version": 1, "trait_checks": [], "destructors": [] }));
        for changed in changes {
            fs::write(&path, serde_json::to_vec(&changed)?)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "invalid candidate descriptor accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn candidate_descriptors_keep_existing_32_source_and_128_destructor_bounds() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let path = root.join("candidate.json");
        let traits = (0..32).map(|index| serde_json::json!({
            "source": format!("crates/example/src/assertions_{index}.rs"), "scope": "const", "registration": null
        })).collect::<Vec<_>>();
        let destructors = (0..128)
            .map(|index| {
                serde_json::json!({
                    "source": "crates/example/src/proofs.rs", "type_name": format!("Permit_{index}")
                })
            })
            .collect::<Vec<_>>();
        let at_limit =
            serde_json::json!({ "version": 1, "trait_checks": traits, "destructors": destructors });
        validate_candidate(&serde_json::from_value(at_limit.clone())?)?;
        let mut overflow = at_limit.clone();
        overflow["trait_checks"].as_array_mut().context("fixture trait descriptors")?.push(serde_json::json!({
            "source": "crates/example/src/assertions_32.rs", "scope": "const", "registration": null
        }));
        fs::write(&path, serde_json::to_vec(&overflow)?)?;
        ensure!(
            candidate_inventory(&root, &path)
                .err()
                .context("33 candidate trait sources accepted")?
                .to_string()
                == "trait check catalog budget",
            "candidate source bound changed"
        );
        let mut overflow = at_limit;
        overflow["destructors"]
            .as_array_mut()
            .context("fixture destructor descriptors")?
            .push(serde_json::json!({
                "source": "crates/example/src/proofs.rs", "type_name": "Permit_128"
            }));
        fs::write(&path, serde_json::to_vec(&overflow)?)?;
        ensure!(
            candidate_inventory(&root, &path)
                .err()
                .context("129 candidate destructors accepted")?
                .to_string()
                == "proof candidate destructor budget",
            "candidate destructor bound changed"
        );
        Ok(())
    }

    #[test]
    fn candidate_inventory_rejects_missing_conditional_and_ambiguous_source_facts() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let descriptor = candidate_fixture(&root)?;
        let path = root.join("candidate.json");
        fs::write(&path, serde_json::to_vec(&descriptor)?)?;
        let owner = root.join("crates/example/src");
        for registration in ["", "pub mod assertions;", "#[cfg(test)] mod assertions;"] {
            fs::write(owner.join("lib.rs"), registration)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "uncompiled candidate assertion accepted"
            );
        }
        fs::write(owner.join("lib.rs"), "mod assertions;")?;
        for source in [
            DROP_BASE.into(),
            format!("{DROP_BASE} {REVIEWED_DROP} {REVIEWED_DROP}"),
            format!("{DROP_BASE} #[cfg(test)] {REVIEWED_DROP}"),
            format!("#![cfg(test)] {DROP_BASE} {REVIEWED_DROP}"),
            format!("#[cfg(test)] {DROP_BASE} {REVIEWED_DROP}"),
            format!(
                "{} {REVIEWED_DROP}",
                DROP_BASE.replace("struct Permit", "struct Permit<T>")
            ),
            format!("{DROP_BASE} impl Clone for Permit {{}}"),
            format!(
                "{DROP_BASE} {}",
                REVIEWED_DROP.replace("for Permit", "for Other")
            ),
        ] {
            fs::write(owner.join("proofs.rs"), source)?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "missing or unreviewable candidate destructor accepted"
            );
        }
        fs::write(
            owner.join("proofs.rs"),
            format!("{DROP_BASE} {REVIEWED_DROP}"),
        )?;
        #[cfg(unix)]
        {
            let alias = root.join("alias");
            fs::create_dir_all(&alias)?;
            fs::write(
                alias.join("proofs.rs"),
                format!("{DROP_BASE} {REVIEWED_DROP}"),
            )?;
            fs::remove_file(owner.join("proofs.rs"))?;
            std::os::unix::fs::symlink(alias.join("proofs.rs"), owner.join("proofs.rs"))?;
            ensure!(
                candidate_inventory(&root, &path).is_err(),
                "symlink candidate source accepted"
            );
        }
        Ok(())
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

    fn trait_catalog_policy(root: &Path, count: usize) -> Result<serde_json::Value> {
        let owner = root.join("crates/example/src");
        fs::create_dir_all(&owner)?;
        fs::write(
            owner.join("proofs.rs"),
            "pub struct Permit { claim: Claim } impl Permit { pub fn send(self) {} }",
        )?;
        let source =
            "const _: () = { macro_rules! assert_not_impl { () => {} } assert_not_impl!(); };";
        let mut trait_checks = Vec::new();
        for index in 0..count {
            let source_path = format!("crates/example/src/assertions_{index}.rs");
            fs::write(root.join(&source_path), source)?;
            let mut reviewed = TraitCheck {
                source: source_path,
                scope: TraitScope::Const,
                fingerprint: String::new(),
                registration: None,
            };
            reviewed.fingerprint = trait_check_finding(root, &reviewed)?.fingerprint;
            trait_checks.push(
                serde_json::json!({ "source": reviewed.source, "scope": reviewed.scope,
                "fingerprint": reviewed.fingerprint, "registration": null }),
            );
        }
        Ok(serde_json::json!({ "version": 1, "proofs": [{
            "source": "crates/example/src/proofs.rs", "type_name": "Permit", "kind": "consuming",
            "consuming_methods": ["send"], "methods": ["pub fn send(self)"], "factories": []
        }], "trait_checks": trait_checks }))
    }

    #[test]
    fn production_trait_catalog_admits_exactly_32_reviewed_sources() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let policy = trait_catalog_policy(&root, 32)?;
        fs::write(root.join(POLICY), serde_json::to_vec(&policy)?)?;
        check(&root)?;
        ensure!(
            trait_check_inventory(&root)?.trait_checks.len() == 32,
            "inventory must retain every admitted assertion source"
        );
        // At the capacity boundary each source still has its own exact pin.
        fs::write(
            root.join("crates/example/src/assertions_31.rs"),
            "const _: () = {};",
        )?;
        ensure!(
            check(&root).is_err(),
            "capacity must not bypass source admission"
        );
        Ok(())
    }

    #[test]
    fn production_trait_catalog_rejects_33_reviewed_sources() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        let policy = trait_catalog_policy(&root, 33)?;
        fs::write(root.join(POLICY), serde_json::to_vec(&policy)?)?;
        ensure!(
            check(&root).unwrap_err().to_string() == "trait check catalog budget",
            "the 33rd otherwise valid assertion source must exceed admission capacity"
        );
        ensure!(
            trait_check_inventory(&root)
                .err()
                .context("oversized inventory accepted")?
                .to_string()
                == "trait check catalog budget",
            "inventory and mandatory checking must share the source bound"
        );
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

// Generic source fixtures exercise closed ownership without depending on
// future native runtime producers or their application artifacts.
#[cfg(test)]
mod owning_children_tests {
    use super::*;

    fn child(source: &str, parent: &str, module: &str) -> OwningChild {
        OwningChild {
            source: source.into(),
            registration: Registration {
                source: parent.into(),
                module: module.into(),
            },
        }
    }

    fn write_source(root: &Path, source: &str, bytes: &str) -> Result<()> {
        let path = root.join(source);
        fs::create_dir_all(path.parent().context("fixture parent")?)?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn inspect_owned(root: &Path, proof: &Proof) -> Result<()> {
        let root = root.canonicalize()?;
        inspect(
            proof,
            &owning_items(
                &root,
                &proof.source,
                &proof.type_name,
                proof.owning_children.as_deref(),
            )?,
        )
    }

    #[test]
    fn nested_explicit_parent_import_is_supported_but_alias_and_inline_registration_are_not()
    -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let owner = "crates/example/src/proofs.rs";
        let first = "crates/example/src/proofs/first.rs";
        let second = "crates/example/src/proofs/second.rs";
        let mut proof = tests::proof(Kind::Consuming);
        proof.owning_children = Some(vec![
            child(first, owner, "first"),
            child(second, first, "second"),
        ]);
        write_source(
            fixture.path(),
            owner,
            "struct Permit { value: u8 } mod first;",
        )?;
        write_source(fixture.path(), first, "#[path = \"second.rs\"] mod second;")?;
        write_source(
            fixture.path(),
            second,
            "use super::super::Permit; impl Permit { pub fn send(self) {} }",
        )?;
        inspect_owned(fixture.path(), &proof)?;
        for source in [
            "use super::Permit; impl Permit { pub fn send(self) {} }",
            "use super::super::Permit as Permit; impl Permit { pub fn send(self) {} }",
            "use super::super::*; impl Permit { pub fn send(self) {} }",
            "use crate::Permit; impl Permit { pub fn send(self) {} }",
        ] {
            write_source(fixture.path(), second, source)?;
            ensure!(inspect_owned(fixture.path(), &proof).is_err());
        }
        write_source(
            fixture.path(),
            second,
            "use super::super::Permit; impl Permit { pub fn send(self) {} }",
        )?;
        write_source(
            fixture.path(),
            first,
            "mod inline { #[path = \"second.rs\"] mod second; }",
        )?;
        ensure!(inspect_owned(fixture.path(), &proof).is_err());
        Ok(())
    }

    #[test]
    fn generic_self_factory_is_inventory_visible_and_requires_exact_review() -> Result<()> {
        let source = "pub struct Permit<'a> { claim: &'a Claim } impl<'a> Permit<'a> { pub fn send(self) {} pub fn prepare(claim: &'a Claim) -> Self { Self { claim } } }";
        let mut proof = tests::proof(Kind::Consuming);
        proof
            .methods
            .push("pub fn prepare(claim: &'a Claim) -> Self".into());
        proof.factories.push(Factory {
            owner: Some("Permit < 'a >".into()),
            signature: "pub fn prepare(claim: &'a Claim) -> Self".into(),
        });
        inspect(&proof, &syn::parse_file(source)?.items)?;
        proof.factories.clear();
        ensure!(
            inspect(&proof, &syn::parse_file(source)?.items)
                .unwrap_err()
                .to_string()
                .contains("unreviewed proof factory")
        );
        let mut observed = BTreeSet::new();
        inspect_factories(
            &proof,
            &syn::parse_file(source)?.items,
            false,
            false,
            None,
            &mut observed,
        )?;
        ensure!(
            observed.len() == 1
                && observed
                    .iter()
                    .next()
                    .context("generic factory")?
                    .0
                    .as_deref()
                    == Some("Permit < 'a >")
        );
        Ok(())
    }

    #[test]
    fn owning_catalog_refuses_cycles_unrelated_parents_duplicates_and_budget_overflow() -> Result<()>
    {
        let owner = "crates/example/src/proofs.rs";
        let first = "crates/example/src/proofs/first.rs";
        let second = "crates/example/src/proofs/second.rs";
        let valid = vec![child(first, owner, "first"), child(second, first, "second")];
        validate_owning_children(owner, &valid)?;
        for children in [
            vec![
                child(first, second, "first"),
                child(second, first, "second"),
            ],
            vec![child(first, "crates/unrelated/src/lib.rs", "first")],
            vec![child(first, owner, "first"), child(second, owner, "first")],
            vec![
                child(first, owner, "first"),
                child(first, owner, "duplicate"),
            ],
            vec![child("crates/example/src/../outside.rs", owner, "first")],
        ] {
            ensure!(validate_owning_children(owner, &children).is_err());
        }
        let excessive = (0..=MAX_OWNING_CHILDREN)
            .map(|index| {
                child(
                    &format!("crates/example/src/proofs/child{index}.rs"),
                    owner,
                    &format!("child{index}"),
                )
            })
            .collect::<Vec<_>>();
        ensure!(validate_owning_children(owner, &excessive).is_err());
        Ok(())
    }

    #[test]
    fn native_policy_check_uses_opt_in_catalog_and_rejects_new_child_api() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let owner = "crates/example/src/proofs.rs";
        let implementation = "crates/example/src/proofs/implementation.rs";
        write_source(
            fixture.path(),
            owner,
            "struct Permit { value: u8 } mod implementation;",
        )?;
        write_source(
            fixture.path(),
            implementation,
            "use super::Permit; impl Permit { pub fn send(self) {} }",
        )?;
        let policy = serde_json::json!({"version":1,"proofs":[{
            "source":owner,"type_name":"Permit","kind":"consuming",
            "consuming_methods":["send"],"methods":["pub fn send(self)"],"factories":[],
            "owning_children":[{"source":implementation,"registration":{"source":owner,"module":"implementation"}}]
        }]});
        fs::write(fixture.path().join(POLICY), serde_json::to_vec(&policy)?)?;
        check(fixture.path())?;
        write_source(
            fixture.path(),
            implementation,
            "use super::Permit; impl Permit { pub fn send(self) {} pub fn raw(&self)->u8 { self.value } }",
        )?;
        ensure!(check(fixture.path()).is_err());
        let facts = trait_check_inventory(fixture.path())?;
        ensure!(
            facts.owning_apis.len() == 1 && facts.owning_apis[0].methods.len() == 2,
            "inventory copied stale admitted signatures"
        );
        Ok(())
    }

    #[test]
    fn omitted_catalog_is_legacy_explicit_empty_is_closed_and_null_refuses() -> Result<()> {
        let mut value = serde_json::json!({
            "source":"crates/example/src/proofs.rs", "type_name":"Permit", "kind":"consuming",
            "consuming_methods":["send"], "methods":["pub fn send(self)"], "factories":[]
        });
        let legacy: Proof = serde_json::from_value(value.clone())?;
        ensure!(legacy.owning_children.is_none());
        value["owning_children"] = serde_json::json!([]);
        let closed: Proof = serde_json::from_value(value.clone())?;
        ensure!(
            closed
                .owning_children
                .as_deref()
                .is_some_and(|children| children.is_empty())
        );
        value["owning_children"] = serde_json::Value::Null;
        ensure!(serde_json::from_value::<Proof>(value).is_err());
        let fixture = tempfile::tempdir()?;
        write_source(
            fixture.path(),
            &legacy.source,
            "struct Permit { value: u8 } impl Permit { pub fn send(self) {} }",
        )?;
        inspect_owned(fixture.path(), &legacy)?;
        inspect_owned(fixture.path(), &closed)?;
        write_source(
            fixture.path(),
            &legacy.source,
            "struct Permit { value: u8 } impl Permit { pub fn send(self) {} } mod added;",
        )?;
        inspect_owned(fixture.path(), &legacy)?;
        ensure!(
            inspect_owned(fixture.path(), &closed)
                .unwrap_err()
                .to_string()
                .contains("uncataloged production owning child")
        );
        Ok(())
    }
}
