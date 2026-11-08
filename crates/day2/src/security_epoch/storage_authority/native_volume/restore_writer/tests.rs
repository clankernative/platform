use super::*;
use quote::ToTokens as _;
use syn::{
    parse::Parser as _,
    visit::{self, Visit},
};

fn root_source() -> &'static str {
    let source = include_str!("../../native_volume.rs");
    let start = source
        .find("/// The actual root remains owned from BEFORE")
        .unwrap();
    let end = start + source[start..].find("#[cfg(test)]").unwrap();
    &source[start..end]
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.0.push(call.to_token_stream().to_string());
        visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.to_token_stream().to_string());
        visit::visit_expr_method_call(self, call);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("ensure") {
            let args = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(mac.tokens.clone())
                .unwrap();
            let mut nested = Calls::default();
            for arg in &args {
                nested.visit_expr(arg);
            }
            self.0.extend(nested.0);
        } else {
            visit::visit_macro(self, mac);
        }
    }
}

fn call(source: &str) -> String {
    syn::parse_str::<syn::Expr>(source)
        .unwrap()
        .to_token_stream()
        .to_string()
}

fn admitted_order(source: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    let methods: Vec<_> = file.items.iter().filter_map(|item| {
        let syn::Item::Impl(item) = item else { return None; };
        if !matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|s| s.ident == "CurrentVolumePhase")) { return None; }
        item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(f) if f.sig.ident == "admit_restore_creator_root" => Some(f),
            _ => None,
        })
    }).collect();
    if methods.len() != 1 {
        return false;
    }
    let mut calls = Calls::default();
    calls.visit_block(&methods[0].block);
    let sequence = [
        "self.reader.stage.require_purpose(StagePurpose::CurrentRole)",
        "self.check_directory(held_root, anchor)",
        "current.exchange_current_views(&mut self.reader.acquisition)",
        "self.reader.acquire_material()",
        "self.check_durability_profile()",
        "self.check_directory(held_root, anchor)",
        "original.exchange_current_views(&mut self.reader.acquisition)",
        "self.resources.directory.try_clone()",
        "restore_pin_directory(&volume)",
        "restore_private_directory(&directory)",
        "restore_private_directory(held_root)",
        "root.check(held_root)",
        "self.check_directory(held_root, anchor)",
    ];
    let mut cursor = 0;
    for expected in sequence {
        let expected = call(expected);
        let Some(relative) = calls.0[cursor..].iter().position(|c| c == &expected) else {
            return false;
        };
        cursor += relative + 1;
    }
    [
        ("self.check_directory(held_root, anchor)", 3),
        (
            "self.reader.stage.narrow_io_acquisition(self.reader.store.max_lease_seconds)",
            2,
        ),
        ("self.reader.acquire_material()", 1),
        ("self.check_durability_profile()", 1),
        ("self.resources.directory.try_clone()", 1),
        ("root.check(held_root)", 1),
    ]
    .into_iter()
    .all(|(name, count)| calls.0.iter().filter(|c| *c == &call(name)).count() == count)
}

#[test]
fn actual_root_admission_meets_before_provider_and_uses_the_retained_volume() {
    let source = root_source();
    assert!(admitted_order(source));
    for (before, after) in [
        (
            "current.exchange_current_views(&mut self.reader.acquisition)?;",
            "Ok::<(), anyhow::Error>(())?;",
        ),
        (
            "self.check_durability_profile()?;",
            "Ok::<(), anyhow::Error>(())?;",
        ),
        (
            "self.resources.directory.try_clone()?",
            "held_root.try_clone()?",
        ),
        ("root.check(held_root)?;", "Ok::<(), anyhow::Error>(())?;"),
    ] {
        assert_eq!(source.matches(before).count(), 1);
        assert!(!admitted_order(&source.replacen(before, after, 1)));
    }
    let before = "current.exchange_current_views(&mut self.reader.acquisition)?;";
    let material = "let material = self.reader.acquire_material()?;";
    let late =
        source
            .replacen(before, "", 1)
            .replacen(material, &format!("{material} {before}"), 1);
    assert!(!admitted_order(&late));
    let last = "self.check_directory(held_root, anchor)?;";
    assert_eq!(source.matches(last).count(), 3);
    let position = source.rfind(last).unwrap();
    let mut missing_post = source.to_owned();
    missing_post.replace_range(position..position + last.len(), "");
    assert!(!admitted_order(&missing_post));
}

#[test]
fn root_material_has_only_fixed_check_and_unconditional_loss_refusal() {
    let file = syn::parse_file(include_str!("../../native_volume.rs")).unwrap();
    let root = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(s) if s.ident == "RestoreCreatorRoot" => Some(s),
            _ => None,
        })
        .unwrap();
    assert!(matches!(root.vis, syn::Visibility::Restricted(_)));
    assert!(root.attrs.iter().all(|a| a.path().is_ident("doc")));
    assert_eq!(root.fields.len(), 5);
    assert!(
        root.fields
            .iter()
            .all(|f| matches!(f.vis, syn::Visibility::Inherited))
    );
    let mut checks = 0;
    let mut drops = 0;
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        if !matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("RestoreCreatorRoot"))
        {
            continue;
        }
        match &item.trait_ {
            None => {
                assert_eq!(item.items.len(), 1);
                assert!(matches!(&item.items[0], syn::ImplItem::Fn(f) if f.sig.ident == "check"));
                checks += 1;
            }
            Some((_, ty, _)) => {
                assert!(ty.is_ident("Drop"));
                assert!(item.generics.params.is_empty());
                assert_eq!(item.items.len(), 1);
                let syn::ImplItem::Fn(f) = &item.items[0] else {
                    panic!("drop method required");
                };
                let expected: syn::Block = syn::parse_quote!({
                    self.original.refuse();
                });
                assert_eq!(
                    f.block.to_token_stream().to_string(),
                    expected.to_token_stream().to_string()
                );
                drops += 1;
            }
        }
    }
    assert_eq!((checks, drops), (1, 1));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn portable_directory_metadata_cannot_become_native_admission() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let held = File::open(directory.path())?;
    assert!(restore_private_directory(&held).is_err());
    assert!(restore_pin_directory(&held).is_err());
    Ok(())
}

fn closed_construction(source: &str) -> bool {
    struct Constructors {
        phase: bool,
        factory: bool,
        count: usize,
        closed: bool,
    }
    impl<'ast> Visit<'ast> for Constructors {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && matches!(&a.meta, syn::Meta::List(l) if l.tokens.to_string() == "test")
            }) {
                return;
            }
            visit::visit_item_mod(self, item);
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let previous = self.phase;
            self.phase = item.trait_.is_none()
                && matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|s| s.ident == "CurrentVolumePhase"));
            visit::visit_item_impl(self, item);
            self.phase = previous;
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = self.factory;
            self.factory = self.phase && item.sig.ident == "admit_restore_creator_root";
            visit::visit_impl_item_fn(self, item);
            self.factory = previous;
        }
        fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
            if item.path.is_ident("RestoreCreatorRoot") {
                self.count += 1;
                self.closed &= self.factory;
            }
            visit::visit_expr_struct(self, item);
        }
    }
    let mut seen = Constructors {
        phase: false,
        factory: false,
        count: 0,
        closed: true,
    };
    seen.visit_file(&syn::parse_file(source).unwrap());
    seen.count == 1 && seen.closed
}

#[test]
fn data_and_another_impl_cannot_add_a_root_constructor() {
    let source = include_str!("../../native_volume.rs");
    assert!(closed_construction(source));
    let body =
        "RestoreCreatorRoot { volume, directory, volume_identity, directory_identity, original }";
    assert!(!closed_construction(&format!(
        "{source} fn from_data() {{ let value = {body}; }}"
    )));
    assert!(!closed_construction(&format!(
        "{source} impl OtherPhase {{ fn admit_restore_creator_root() {{ let value = {body}; }} }}"
    )));
    assert!(!closed_construction(&source.replacen(
        "fn admit_restore_creator_root(",
        "fn from_metadata(",
        1
    )));
}

#[test]
fn physical_root_check_is_closed_local_work_and_keeps_named_replacement_refusal() {
    fn local(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let methods: Vec<_> = file.items.iter().filter_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if item.trait_.is_some() || !matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("RestoreCreatorRoot")) { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "check" => Some(method), _ => None,
            })
        }).collect();
        if methods.len() != 1 {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            let result = (|| {
                self.original.remaining()?;
                ensure!(
                    directory_identity(&self.volume)? == self.volume_identity
                        && restore_private_directory(&self.directory)? == self.directory_identity
                        && restore_private_directory(held_root)? == self.directory_identity,
                    "restore_writer_root_changed"
                );
                let named = restore_pin_directory(&self.volume)?;
                ensure!(
                    restore_private_directory(&named)? == self.directory_identity,
                    "restore_writer_named_root_changed"
                );
                self.original.remaining()?;
                Ok(())
            })();
            if result.is_err() {
                self.original.refuse();
            }
            result
        });
        methods[0].block.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }
    let source = root_source();
    assert!(local(source));
    for (old, new) in [
        (
            "let named = restore_pin_directory(&self.volume)?;",
            "let named = self.directory.try_clone()?;",
        ),
        (
            "self.original.remaining()?;",
            "self.original.check_current()?;",
        ),
        (
            "restore_private_directory(held_root)? == self.directory_identity",
            "true",
        ),
        ("self.original.refuse();", "self.original.remaining().ok();"),
    ] {
        assert!(source.contains(old));
        assert!(!local(&source.replacen(old, new, 1)));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pinned_root_helper_exposes_named_replacement_and_refuses_symlinks_and_foreign_modes()
-> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Real Linux FD/identity negatives only; this never constructs a native
    // RestoreCreatorRoot, current role, approval or writer from fixture DATA.
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join(super::PRIVATE_DIRECTORY);
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    let volume = File::open(temporary.path())?;
    let held = restore_pin_directory(&volume)?;
    let original = restore_private_directory(&held)?;
    std::fs::rename(&path, temporary.path().join("old-root"))?;
    std::fs::create_dir(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    assert_ne!(
        restore_private_directory(&restore_pin_directory(&volume)?)?,
        original
    );
    assert_eq!(restore_private_directory(&held)?, original);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    assert!(restore_private_directory(&restore_pin_directory(&volume)?).is_err());
    std::fs::remove_dir(&path)?;
    std::os::unix::fs::symlink("old-root", &path)?;
    assert!(restore_pin_directory(&volume).is_err());
    Ok(())
}
