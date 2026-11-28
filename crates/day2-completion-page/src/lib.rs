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
    FailedPublication, FreshPage, LocalRefusalData, PendingPublication, Publication, PublishedData,
    ReadyPublication, ReceivedData, validate_received_data,
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
                    "FailedPublication",
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
                "FailedPublication::dispose",
                "FailedPublication::error_data",
                "FreshPage::create",
                "FreshPage::into_pending_attempt",
                "LocalRefusalData::dispose",
                "PendingPublication::into_ready",
                "PendingPublication::prepare",
                "PendingPublication::send_pending",
                "PublishedData::dispose",
                "ReadyPublication::publish",
                "ReceivedData::state_data",
                "validate_received_data",
            ]
    }

    fn borrowed_attempt_operation(source: &str, name: &str, expected: &str, next: &str) -> bool {
        use syn::visit::Visit;
        fn ident(expr: &syn::Expr, name: &str) -> bool {
            matches!(expr,syn::Expr::Path(path) if path.path.is_ident(name))
        }
        fn phase(expr: &syn::Expr, name: &str) -> bool {
            matches!(expr,syn::Expr::Path(path) if path.path.segments.len()==2 && path.path.segments[0].ident=="AttemptState" && path.path.segments[1].ident==name)
        }
        fn path(expr: &syn::Expr, parts: &[&str]) -> bool {
            matches!(expr,syn::Expr::Path(path) if path.path.segments.iter().map(|p|p.ident.to_string()).eq(parts.iter().map(|p|(*p).to_owned())))
        }
        let file = syn::parse_file(source).unwrap();
        let methods=file.items.into_iter().filter_map(|item|match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty,syn::Type::Path(p) if p.path.is_ident("PendingPublication"))=>Some(item),_=>None,
        }).flat_map(|item|item.items).filter_map(|item|match item {syn::ImplItem::Fn(f) if f.sig.ident==name=>Some(f),_=>None}).collect::<Vec<_>>();
        let [method] = methods.as_slice() else {
            return false;
        };
        let Some(syn::FnArg::Receiver(receiver)) = method.sig.inputs.first() else {
            return false;
        };
        if receiver.mutability.is_none()
            || !receiver
                .reference
                .as_ref()
                .is_some_and(|(_, lifetime)| lifetime.is_none())
            || method.sig.inputs.len() != if name == "send_pending" { 2 } else { 1 }
            || !method.sig.generics.params.is_empty()
            || method.sig.unsafety.is_some()
            || method.sig.asyncness.is_some()
        {
            return false;
        }
        let [
            syn::Stmt::Expr(syn::Expr::Try(spent), _),
            syn::Stmt::Local(local),
            syn::Stmt::Expr(syn::Expr::MethodCall(settle), None),
        ] = method.block.stmts.as_slice()
        else {
            return false;
        };
        let syn::Expr::MethodCall(spend) = &*spent.expr else {
            return false;
        };
        if !ident(&spend.receiver, "self")
            || spend.method != "spend"
            || spend.args.len() != 1
            || !phase(&spend.args[0], expected)
            || !ident(&settle.receiver, "self")
            || settle.method != "settle_attempt"
            || settle.args.len() != 2
            || !ident(&settle.args[0], "requested")
            || !phase(&settle.args[1], next)
            || !matches!(&local.pat,syn::Pat::Ident(p) if p.ident=="requested")
        {
            return false;
        }
        let Some(init) = &local.init else {
            return false;
        };
        let syn::Expr::Call(catch) = &*init.expr else {
            return false;
        };
        if !path(&catch.func, &["std", "panic", "catch_unwind"]) || catch.args.len() != 1 {
            return false;
        }
        let syn::Expr::Call(safe) = &catch.args[0] else {
            return false;
        };
        if !path(&safe.func, &["std", "panic", "AssertUnwindSafe"]) || safe.args.len() != 1 {
            return false;
        }
        let syn::Expr::Closure(body) = &safe.args[0] else {
            return false;
        };
        if !body.inputs.is_empty() || body.capture.is_some() || body.asyncness.is_some() {
            return false;
        }
        #[derive(Default)]
        struct Moves(bool);
        impl<'a> Visit<'a> for Moves {
            fn visit_expr_assign(&mut self, _: &'a syn::ExprAssign) {
                self.0 = true;
            }
            fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
                if [
                    "take",
                    "replace",
                    "dispose",
                    "into_ready",
                    "publish",
                    "into_raw_fd",
                ]
                .iter()
                .any(|n| call.method == *n)
                {
                    self.0 = true;
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
                if matches!(&*call.func,syn::Expr::Path(p) if p.path.segments.last().is_some_and(|p|["take","replace","drop","forget","munmap","try_close"].iter().any(|n|p.ident==*n)))
                {
                    self.0 = true;
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut moved = Moves::default();
        moved.visit_expr(&body.body);
        !moved.0
    }

    #[test]
    fn actual_fallible_operations_borrow_the_preinstalled_spent_owner_through_unwind() {
        let source = include_str!("linux.rs");
        for (name, before, after) in [
            ("send_pending", "Fresh", "Sent"),
            ("prepare", "Sent", "Prepared"),
        ] {
            assert!(borrowed_attempt_operation(source, name, before, after));
            for (old, new) in [
                ("self.spend(AttemptState::", "self.bypass(AttemptState::"),
                ("std::panic::catch_unwind", "std::panic::bypass"),
                ("self.settle_attempt(requested", "self.bypass(requested"),
            ] {
                assert!(source.contains(old));
                let mutant = source.replace(old, new);
                assert!(!borrowed_attempt_operation(&mutant, name, before, after));
            }
            assert!(!borrowed_attempt_operation(source, name, after, before));
            // Mutate the ACTUAL caught bodies. A direct field assignment could
            // otherwise drop Backing before the external native posts, even
            // though no forbidden ownership method was called.
            let boundary = "std::panic::AssertUnwindSafe(|| {";
            assert!(source.contains(boundary));
            let changed = source.replace(
                boundary,
                "std::panic::AssertUnwindSafe(|| { self.inner = None;",
            );
            assert!(!borrowed_attempt_operation(&changed, name, before, after));
        }
    }

    fn retained_allocation(source: &str) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Allocation {
            constructors: usize,
            unboxed: bool,
        }
        impl<'a> Visit<'a> for Allocation {
            fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func
                    && path.path.segments.iter().any(|p| p.ident == "Box")
                {
                    if path.path.segments.last().is_some_and(|p| p.ident == "new") {
                        self.constructors += 1;
                    } else {
                        self.unboxed = true;
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_unary(&mut self, unary: &'a syn::ExprUnary) {
                if matches!(unary.op, syn::UnOp::Deref(_))
                    && matches!(&*unary.expr, syn::Expr::Path(p) if p.path.is_ident("inner"))
                {
                    self.unboxed = true;
                }
                syn::visit::visit_expr_unary(self, unary);
            }
        }
        fn container(ty: &syn::Type, name: &str) -> Option<syn::Type> {
            let syn::Type::Path(path) = ty else {
                return None;
            };
            if path.path.segments.len() != 1 {
                return None;
            }
            let segment = path.path.segments.first()?;
            if segment.ident != name {
                return None;
            }
            let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
                return None;
            };
            if args.args.len() != 1 {
                return None;
            }
            let syn::GenericArgument::Type(inner) = args.args.first()? else {
                return None;
            };
            Some(inner.clone())
        }
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut allocations = Vec::new();
        let mut owners = Vec::new();
        for item in &file.items {
            if let syn::Item::Struct(item) = item {
                let name = item.ident.to_string();
                let optional = ["FreshPage", "PendingPublication", "ReadyPublication"]
                    .contains(&name.as_str());
                if optional
                    || ["FailedPublication", "PublishedData", "LocalRefusalData"]
                        .contains(&name.as_str())
                {
                    let fields = item
                        .fields
                        .iter()
                        .filter(|f| f.ident.as_ref().is_some_and(|i| i == "inner"))
                        .collect::<Vec<_>>();
                    let [field] = fields.as_slice() else {
                        return false;
                    };
                    let ty = if optional {
                        container(&field.ty, "Option")
                    } else {
                        Some(field.ty.clone())
                    };
                    if !ty.and_then(|ty| container(&ty, "Box")).is_some_and(
                        |ty| matches!(ty,syn::Type::Path(p) if p.path.is_ident("Backing")),
                    ) {
                        return false;
                    }
                    owners.push(name);
                }
            }
            if let syn::Item::Impl(item) = item {
                let syn::Type::Path(owner) = &*item.self_ty else {
                    return false;
                };
                for member in &item.items {
                    if let syn::ImplItem::Fn(method) = member {
                        let mut observed = Allocation::default();
                        observed.visit_block(&method.block);
                        if observed.unboxed {
                            return false;
                        }
                        if observed.constructors != 0 {
                            allocations.push((
                                owner.path.is_ident("FreshPage"),
                                method.sig.ident == "create",
                                observed.constructors,
                            ));
                        }
                    }
                }
            }
        }
        owners.sort();
        allocations == [(true, true, 1)]
            && owners
                == [
                    "FailedPublication",
                    "FreshPage",
                    "LocalRefusalData",
                    "PendingPublication",
                    "PublishedData",
                    "ReadyPublication",
                ]
    }

    #[test]
    fn actual_backing_is_boxed_only_at_creation_and_never_unboxed_in_transitions() {
        let source = include_str!("linux.rs");
        assert!(retained_allocation(source));
        for (old, new) in [
            (
                "Some(Box::new(backing))",
                "Some(Box::new(*Box::new(backing)))",
            ),
            (
                "PublishedData { inner }",
                "PublishedData { inner: Box::new(*inner) }",
            ),
            (
                "LocalRefusalData { inner }",
                "LocalRefusalData { inner: *inner }",
            ),
            (
                "inner,\n                error:",
                "inner: Box::new(*inner),\n                error:",
            ),
            (
                "PublishedData { inner }",
                "PublishedData { inner: Box::into_inner(inner) }",
            ),
            (
                "pub struct FailedPublication {\n    inner: Box<Backing>",
                "pub struct FailedPublication {\n    inner: Backing",
            ),
        ] {
            assert_eq!(source.matches(old).count(), 1);
            assert!(!retained_allocation(&source.replacen(old, new, 1)));
        }
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
