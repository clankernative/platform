//! Mechanical scheduled-backup completion DATA, never native authority.
//!
//! The only unsafe boundary is private `linux.rs`. No runtime consumer is wired
//! to this component. A received page, even one saying Known, does not prove its
//! creator, current original, completed posts, immutable image or upload grant.
#![deny(unsafe_code)]

/// Fixed page and envelope ABI. Nothing selects a larger or arbitrary mapping.
pub const PAGE_BYTES: usize = 4096;
pub const FRAME_BYTES: usize = 368;
#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
const HEADER_BYTES: usize = 352;
#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
const STATE_OFFSET: u64 = (PAGE_BYTES - 1) as u64;
#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
const MAGIC: &[u8; 16] = b"DAY2COMPLETEPAGE";
#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
const PENDING: u8 = 0;
#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
const KNOWN: u8 = 1;
#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
const REFUSED: u8 = 2;

/// Public commitments only. The caller must derive these from its actual
/// authenticated context and full `native_archive_commitment`, not a Manifest.
/// Constructing or comparing this DATA grants no authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub controller: [u8; 32],
    pub requester: [u8; 32],
    pub connection: [u8; 32],
    pub requester_nonce: [u8; 32],
    pub controller_nonce: [u8; 32],
    pub original: [u8; 32],
    pub operation: [u8; 32],
    pub intent: [u8; 32],
    pub image: [u8; 32],
    pub destination: [u8; 32],
}

#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
impl Binding {
    fn header(self) -> [u8; HEADER_BYTES] {
        let mut bytes = [0; HEADER_BYTES];
        bytes[..16].copy_from_slice(MAGIC);
        bytes[16] = 1;
        for (slot, digest) in bytes[32..].as_chunks_mut::<32>().0.iter_mut().zip([
            self.controller,
            self.requester,
            self.connection,
            self.requester_nonce,
            self.controller_nonce,
            self.original,
            self.operation,
            self.intent,
            self.image,
            self.destination,
        ]) {
            slot.copy_from_slice(&digest);
        }
        bytes
    }
}

/// Observed bytes only. Known is not an authenticated completion constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateData {
    Pending,
    Known,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    File,
    Mapping,
    Frame,
    Socket,
    Send,
    Read,
    State,
    Process,
}

/// Closed local failure: never a pathname, foreign message or provider value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: FailureKind,
    pub errno: Option<i32>,
}

impl Error {
    #[cfg(any(
        test,
        all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
    ))]
    const fn invalid(kind: FailureKind) -> Self {
        Self { kind, errno: None }
    }
}

#[cfg(any(
    test,
    all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8")
))]
fn state_data(byte: u8) -> Result<StateData, Error> {
    match byte {
        PENDING => Ok(StateData::Pending),
        KNOWN => Ok(StateData::Known),
        REFUSED => Ok(StateData::Refused),
        _ => Err(Error::invalid(FailureKind::State)),
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "completion_page_{:?} errno={:?}", self.kind, self.errno)
    }
}
impl std::error::Error for Error {}

/// Later resource cleanup, not a native post or acceptance condition. A failed
/// unmap retains ownership for the caller; a close is never blindly retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleanupData {
    pub unmapped: bool,
    pub descriptor_released: bool,
    pub unmap_errno: Option<i32>,
    pub close_errno: Option<i32>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8"))]
mod linux;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_has_atomic = "8"))]
pub use linux::{
    FreshPage, LocalRefusalData, PendingPublication, Publication, PublishedData, ReadyPublication,
    ReceivedData, validate_received_data,
};

// The explicit Bazel kernel target disables libtest. Its fixed main cannot
// silently select zero cases; no argument chooses or skips a qualification case.
#[cfg(all(
    test,
    feature = "kernel-qualification",
    target_os = "linux",
    target_arch = "x86_64",
    target_has_atomic = "8"
))]
fn main() {
    linux::run_kernel_qualification();
}

#[cfg(all(test, not(feature = "kernel-qualification")))]
mod tests {
    use super::*;

    #[test]
    fn actual_selected_build_script_flags_are_a_declared_compiler_input() {
        // Exercise the real compile-data path on every host; this is not a
        // macOS claim about either Linux backend.
        let flags = include_str!(env!("COMPLETION_RUSTIX_FLAGS"));
        assert!(
            flags
                .lines()
                .any(|line| line == "--cfg=libc" || line == "--cfg=linux_raw")
        );
    }

    #[test]
    fn fixed_header_has_exact_fields_no_rust_padding_or_state_overlap() {
        let binding = Binding {
            controller: [1; 32],
            requester: [2; 32],
            connection: [3; 32],
            requester_nonce: [4; 32],
            controller_nonce: [5; 32],
            original: [6; 32],
            operation: [7; 32],
            intent: [8; 32],
            image: [9; 32],
            destination: [10; 32],
        };
        let header = binding.header();
        assert_eq!(header.len(), 352);
        assert_eq!(&header[..16], MAGIC);
        assert_eq!(header[16], 1);
        assert_eq!(&header[17..32], &[0; 15]);
        for (i, field) in header[32..].as_chunks::<32>().0.iter().enumerate() {
            assert!(field.iter().all(|b| *b == i as u8 + 1));
        }
        assert!(HEADER_BYTES < STATE_OFFSET as usize);
        assert_eq!(FRAME_BYTES, HEADER_BYTES + 16);
    }

    #[test]
    fn only_three_explicit_state_bytes_decode_and_unknown_never_normalizes() {
        for byte in 0..=u8::MAX {
            assert_eq!(state_data(byte).is_ok(), byte <= 2);
        }
        assert_eq!(state_data(0), Ok(StateData::Pending));
        assert_eq!(state_data(1), Ok(StateData::Known));
        assert_eq!(state_data(2), Ok(StateData::Refused));
    }

    fn root_api_closed(source: &str) -> bool {
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut exports = Vec::new();
        let mut names = Vec::new();
        for item in &file.items {
            match item {
                syn::Item::Use(item) if !matches!(item.vis, syn::Visibility::Inherited) => {
                    let syn::UseTree::Path(prefix) = &item.tree else {
                        return false;
                    };
                    if prefix.ident != "linux" {
                        return false;
                    }
                    let syn::UseTree::Group(group) = prefix.tree.as_ref() else {
                        return false;
                    };
                    for item in &group.items {
                        let syn::UseTree::Name(name) = item else {
                            return false;
                        };
                        exports.push(name.ident.to_string());
                    }
                }
                syn::Item::Const(c) if !matches!(c.vis, syn::Visibility::Inherited) => {
                    names.push(c.ident.to_string())
                }
                syn::Item::Struct(s) if !matches!(s.vis, syn::Visibility::Inherited) => {
                    names.push(s.ident.to_string())
                }
                syn::Item::Enum(e) if !matches!(e.vis, syn::Visibility::Inherited) => {
                    names.push(e.ident.to_string())
                }
                syn::Item::Fn(f) if !matches!(f.vis, syn::Visibility::Inherited) => return false,
                syn::Item::Mod(m) if !matches!(m.vis, syn::Visibility::Inherited) => return false,
                syn::Item::Type(a) if !matches!(a.vis, syn::Visibility::Inherited) => return false,
                syn::Item::Trait(a) if !matches!(a.vis, syn::Visibility::Inherited) => {
                    return false;
                }
                syn::Item::Macro(_) => return false,
                _ => {}
            }
        }
        names.sort();
        exports.sort();
        names
            == [
                "Binding",
                "CleanupData",
                "Error",
                "FRAME_BYTES",
                "FailureKind",
                "PAGE_BYTES",
                "StateData",
            ]
            && exports
                == [
                    "FreshPage",
                    "LocalRefusalData",
                    "PendingPublication",
                    "Publication",
                    "PublishedData",
                    "ReadyPublication",
                    "ReceivedData",
                    "validate_received_data",
                ]
    }

    #[test]
    fn actual_safe_root_cannot_reexport_an_unsafe_mapping_or_add_an_authority_factory() {
        let source = include_str!("lib.rs");
        assert!(root_api_closed(source));
        for extra in [
            "pub use rustix::mm::mmap;",
            "pub fn native_owner() {}",
            "pub mod escape {}",
            "pub type RawMapping=usize;",
        ] {
            assert!(!root_api_closed(&format!("{source}\n{extra}")));
        }
    }

    fn api_closed(source: &str) -> bool {
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut functions = Vec::new();
        for item in file.items {
            match item {
                syn::Item::Mod(module) if module.ident == "tests" && module.content.is_some() => {}
                syn::Item::Mod(_) => return false,
                syn::Item::Impl(item) => {
                    let syn::Type::Path(owner) = *item.self_ty else {
                        return false;
                    };
                    let name = owner.path.segments.last().unwrap().ident.to_string();
                    if let Some((_, trait_path, _)) = &item.trait_
                        && !(trait_path.is_ident("Drop")
                            && [
                                "Backing",
                                "FreshPage",
                                "PendingPublication",
                                "ReadyPublication",
                            ]
                            .contains(&name.as_str()))
                    {
                        return false;
                    }
                    for member in item.items {
                        if let syn::ImplItem::Fn(f) = member
                            && matches!(f.vis, syn::Visibility::Public(_))
                        {
                            if f.sig.unsafety.is_some() || !f.sig.generics.params.is_empty() {
                                return false;
                            }
                            functions.push(format!("{name}::{}", f.sig.ident));
                        }
                    }
                }
                syn::Item::Struct(s) if matches!(s.vis, syn::Visibility::Public(_)) => {
                    if s.fields
                        .iter()
                        .any(|f| !matches!(f.vis, syn::Visibility::Inherited))
                        || s.attrs.iter().any(|a| a.path().is_ident("derive"))
                    {
                        return false;
                    }
                }
                syn::Item::Enum(e) if !matches!(e.vis, syn::Visibility::Inherited) => {
                    if e.ident != "Publication" || !e.attrs.is_empty() || e.variants.len() != 2 {
                        return false;
                    }
                    for (variant, (name, owner)) in e
                        .variants
                        .iter()
                        .zip([("Known", "PublishedData"), ("Refused", "LocalRefusalData")])
                    {
                        if variant.ident != name
                            || variant.fields.len() != 1
                            || !variant.attrs.is_empty()
                        {
                            return false;
                        }
                        if !matches!(&variant.fields.iter().next().unwrap().ty,syn::Type::Path(p) if p.path.is_ident(owner))
                        {
                            return false;
                        }
                    }
                }
                syn::Item::Use(u) if !matches!(u.vis, syn::Visibility::Inherited) => return false,
                syn::Item::Type(a) if !matches!(a.vis, syn::Visibility::Inherited) => return false,
                syn::Item::Fn(f) if matches!(f.vis, syn::Visibility::Public(_)) => {
                    if f.sig.unsafety.is_some() || !f.sig.generics.params.is_empty() {
                        return false;
                    }
                    functions.push(f.sig.ident.to_string());
                }
                _ => {}
            }
        }
        functions.sort();
        functions
            == [
                "FreshPage::create",
                "FreshPage::send_pending",
                "LocalRefusalData::dispose",
                "PendingPublication::prepare",
                "PublishedData::dispose",
                "ReadyPublication::publish",
                "ReceivedData::state_data",
                "validate_received_data",
            ]
    }

    #[test]
    fn actual_component_has_no_raw_getter_callback_mapping_or_native_constructor() {
        let source = include_str!("linux.rs");
        assert!(api_closed(source));
        for extra in [
            "impl FreshPage { pub fn raw(&self)->usize {0} }",
            "pub fn map_other(fd:usize) {}",
            "mod extra;",
            "pub struct Escaped { pub fd:usize }",
            "impl ReceivedData { pub fn complete_native(&self) {} }",
            "impl AsFd for ReceivedData {fn as_fd(&self)->BorrowedFd<'_> {self.descriptor.as_fd()}}",
            "pub use rustix::mm::mmap;",
            "pub type Export = Backing;",
            "#[derive(Clone)] pub struct CloneOwner {inner:Backing}",
        ] {
            assert!(!api_closed(&format!("{source}\n{extra}")));
        }
        let root = include_str!("lib.rs");
        assert!(root.starts_with("//!"));
        let parsed = syn::parse_file(root).unwrap();
        assert!(parsed.attrs.iter().any(|a| {
            a.path().is_ident("deny")
                && a.parse_args::<syn::Path>()
                    .is_ok_and(|p| p.is_ident("unsafe_code"))
        }));
    }

    fn publication_shape(file: &syn::File) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls {
            names: Vec<String>,
            cas: usize,
            release: bool,
        }
        impl<'a> Visit<'a> for Calls {
            fn visit_expr_call(&mut self, node: &'a syn::ExprCall) {
                if let syn::Expr::Path(p) = node.func.as_ref() {
                    self.names.push(
                        p.path
                            .segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::"),
                    );
                }
                syn::visit::visit_expr_call(self, node);
            }
            fn visit_expr_method_call(&mut self, node: &'a syn::ExprMethodCall) {
                self.names.push(node.method.to_string());
                if node.method == "compare_exchange" {
                    self.cas += 1;
                    let paths = node
                        .args
                        .iter()
                        .filter_map(|arg| match arg {
                            syn::Expr::Path(p) => Some(
                                p.path
                                    .segments
                                    .iter()
                                    .map(|s| s.ident.to_string())
                                    .collect::<Vec<_>>()
                                    .join("::"),
                            ),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    self.release =
                        paths == ["PENDING", "KNOWN", "Ordering::Release", "Ordering::Relaxed"];
                }
                syn::visit::visit_expr_method_call(self, node);
            }
        }
        for item in &file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let syn::Type::Path(owner) = item.self_ty.as_ref() else {
                continue;
            };
            if !owner.path.is_ident("ReadyPublication") {
                continue;
            }
            for member in &item.items {
                let syn::ImplItem::Fn(f) = member else {
                    continue;
                };
                if f.sig.ident != "publish" {
                    continue;
                }
                let mut calls = Calls::default();
                calls.visit_block(&f.block);
                return calls.names
                    == [
                        "expect",
                        "take",
                        "is_ok",
                        "compare_exchange",
                        "state",
                        "Publication::Known",
                        "Publication::Refused",
                    ]
                    && f.block.stmts.len() == 3
                    && calls.cas == 1
                    && calls.release;
            }
        }
        false
    }

    fn publish_block(file: &mut syn::File) -> &mut syn::Block {
        for item in &mut file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let syn::Type::Path(owner) = item.self_ty.as_ref() else {
                continue;
            };
            if !owner.path.is_ident("ReadyPublication") {
                continue;
            }
            for member in &mut item.items {
                if let syn::ImplItem::Fn(f) = member
                    && f.sig.ident == "publish"
                {
                    return &mut f.block;
                }
            }
        }
        panic!("actual terminal method absent");
    }

    #[test]
    fn actual_terminal_site_performs_only_one_release_cas_and_owning_moves() {
        let file = syn::parse_file(include_str!("linux.rs")).unwrap();
        assert!(publication_shape(&file));
        for changed in [
            syn::parse_quote! {if known {inner.dispose(); Publication::Known(PublishedData {inner})} else {Publication::Refused(LocalRefusalData {inner})}},
            syn::parse_quote! {if known {native_post(); Publication::Known(PublishedData {inner})} else {Publication::Refused(LocalRefusalData {inner})}},
        ] {
            let mut mutant = file.clone();
            *publish_block(&mut mutant).stmts.last_mut().unwrap() = changed;
            assert!(!publication_shape(&mutant));
        }
        let mut mutant = file.clone();
        publish_block(&mut mutant).stmts[1] = syn::parse_quote! {let known=inner.state().compare_exchange(PENDING,KNOWN,Ordering::Relaxed,Ordering::Relaxed).is_ok();};
        assert!(!publication_shape(&mutant));
        let mut mutant = file.clone();
        publish_block(&mut mutant)
            .stmts
            .insert(2, syn::parse_quote! {native_post();});
        assert!(!publication_shape(&mutant));
    }
    fn qualification_entry_shape(file: &syn::File) -> bool {
        for item in &file.items {
            let syn::Item::Fn(f) = item else {
                continue;
            };
            if f.sig.ident != "run_kernel_qualification" {
                continue;
            }
            let Some(syn::Stmt::Expr(syn::Expr::Match(m), _)) = f.block.stmts.last() else {
                return false;
            };
            let Some(normal) = m.arms.first() else {
                return false;
            };
            if !matches!(&normal.pat,syn::Pat::Slice(p) if p.elems.is_empty()) {
                return false;
            }
            let syn::Expr::Block(body) = normal.body.as_ref() else {
                return false;
            };
            let calls = body
                .block
                .stmts
                .iter()
                .filter_map(|stmt| match stmt {
                    syn::Stmt::Expr(syn::Expr::Call(c), _) => match c.func.as_ref() {
                        syn::Expr::Path(p) => Some(
                            p.path
                                .segments
                                .iter()
                                .map(|s| s.ident.to_string())
                                .collect::<Vec<_>>()
                                .join("::"),
                        ),
                        _ => None,
                    },
                    _ => None,
                })
                .collect::<Vec<_>>();
            return body.block.stmts.len() == 2
                && calls
                    == [
                        "tests::actual_kernel_qualification",
                        "tests::verify_kernel_qualification",
                    ];
        }
        false
    }

    #[test]
    fn actual_custom_harness_requires_execution_and_complete_receipt_not_libtest_filter() {
        let file = syn::parse_file(include_str!("linux.rs")).unwrap();
        assert!(qualification_entry_shape(&file));
        for remove in [0, 1] {
            let mut mutant = file.clone();
            for item in &mut mutant.items {
                if let syn::Item::Fn(f) = item
                    && f.sig.ident == "run_kernel_qualification"
                {
                    let syn::Stmt::Expr(syn::Expr::Match(m), _) = f.block.stmts.last_mut().unwrap()
                    else {
                        panic!("actual matcher")
                    };
                    let syn::Expr::Block(body) = m.arms[0].body.as_mut() else {
                        panic!("actual normal entry")
                    };
                    body.block.stmts.remove(remove);
                }
            }
            assert!(!qualification_entry_shape(&mutant));
        }
    }
}
