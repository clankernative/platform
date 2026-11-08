use super::*;
use crate::security_epoch::restore_fencing::tests as drain;
use std::sync::Arc;
use std::{fs::OpenOptions, io::Write};

#[derive(Debug)]
struct Unknown(Arc<()>);
impl std::fmt::Display for Unknown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("controlled_writer_unknown")
    }
}
impl std::error::Error for Unknown {}

struct Model {
    refused: bool,
    calls: usize,
    checks: usize,
    root: Digest,
    wrong: Option<Target>,
    unknown: bool,
    expire: bool,
    panic: bool,
    cause: Arc<()>,
}
impl Model {
    fn new() -> Self {
        Self {
            refused: false,
            calls: 0,
            checks: 0,
            root: Digest::new(b"settled-current-root"),
            wrong: None,
            unknown: false,
            expire: false,
            panic: false,
            cause: Arc::new(()),
        }
    }
}
impl sealed::Source for Model {}
impl Source<drain::Model> for Model {
    fn admit(
        &mut self,
        session: &mut Session<'_, '_, drain::Model>,
        target: &Target,
        _: &File,
    ) -> Result<Admission> {
        self.calls += 1;
        ensure!(
            !self.refused && self.calls == 1,
            "controlled_writer_reissued"
        );
        if self.expire {
            drain::at(session, 99, 100);
        }
        if self.unknown {
            return Err(anyhow::Error::new(Unknown(self.cause.clone())));
        }
        Ok(Admission {
            origin: AdmissionOrigin::UnqualifiedModel,
            target: self.wrong.take().unwrap_or_else(|| target.clone()),
        })
    }
    fn check(
        &mut self,
        _: &mut Session<'_, '_, drain::Model>,
        admission: &Admission,
        creator: &File,
    ) -> Result<()> {
        self.checks += 1;
        assert!(!self.panic, "controlled_writer_check_panic");
        ensure!(
            !self.refused && self.root == admission.target.settled_root,
            "controlled_root_or_writer_changed"
        );
        let held = creator.metadata()?;
        ensure!(
            (held.dev(), held.ino()) == admission.target.creator,
            "controlled_creator_changed"
        );
        Ok(())
    }
    fn refuse(&mut self) {
        self.refused = true;
    }
}
fn binding(owner: &mut impl Checks) -> Binding {
    let s = owner.state();
    Binding {
        scope: day2_capabilities::security_epoch::AuthorityScope {
            installation: s.input.namespace.installation.clone(),
            environment: s.input.namespace.environment.clone(),
            app: s.input.namespace.app.clone(),
        },
        selection: Digest::new(b"exact-selected-instance"),
        incumbent_root: Digest::new(b"incumbent-root"),
        incumbent_holder: Digest::new(b"all-incumbents-cohort"),
        intent: Digest::new(b"one-approved-intent"),
        operation: s.input.operation.clone(),
        binding_generation: s.input.namespace.binding_generation,
        source_epoch: s.input.source_epoch,
        target_epoch: s.input.source_epoch + 1,
        target_incarnation: s.input.target_incarnation.clone(),
    }
}

#[test]
fn same_creator_reset_image_and_actual_session_remain_borrowed_and_drop_refuses_all() -> Result<()>
{
    let mut world = super::super::tests::world()?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    stage(&mut world.owner, &mut session, &binding)?;
    let mut source = Model::new();
    let root = source.root.clone();
    {
        let mut candidate = Candidate::admit(
            &mut world.owner,
            &mut session,
            &mut source,
            binding.clone(),
            root.clone(),
        )?;
        candidate.check()?;
        candidate.check()?;
        assert_eq!(candidate.source.calls, 1);
        assert!(candidate.source.checks > 2);
    }
    assert!(source.refused && world.owner.state().refused);
    assert!(session.require_drained().is_err());
    // Even a different intact approval/source cannot re-admit the spent owner.
    let (mut a2, mut stop2) = drain::configured(binding.clone());
    let mut session2 = Session::begin(&mut a2, &mut stop2)?;
    let mut source2 = Model::new();
    assert!(
        Candidate::admit(&mut world.owner, &mut session2, &mut source2, binding, root).is_err()
    );
    assert_eq!(source2.calls, 0);
    let source_path = world.source_path()?;
    let state = world.owner.state();
    let mut reopened = super::super::tests::fixture_owner(
        source_path,
        state.root_path.clone(),
        state.input.database.clone(),
    )?;
    assert!(execute(&mut reopened).is_err());
    assert!(reopened.state().refused);
    Ok(())
}

#[test]
fn same_inode_same_length_overwrite_cannot_reuse_a_previous_positive_check() -> Result<()> {
    let mut world = super::super::tests::world()?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    stage(&mut world.owner, &mut session, &binding)?;
    let mut external = world.owner.state().creator.as_ref().unwrap().try_clone()?;
    external.seek(SeekFrom::Start(120))?;
    let mut saved = [0u8; 1];
    external.read_exact(&mut saved)?;
    let mut source = Model::new();
    let root = source.root.clone();
    let mut candidate =
        Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root)?;
    candidate.check()?;
    external.seek(SeekFrom::Start(120))?;
    external.write_all(&[saved[0] ^ 1])?;
    external.sync_all()?;
    assert!(candidate.check().is_err());
    external.seek(SeekFrom::Start(120))?;
    external.write_all(&saved)?;
    external.sync_all()?;
    assert!(candidate.check().is_err());
    assert!(candidate.source.refused && candidate.owner.state().refused);
    assert!(candidate.session.require_drained().is_err());
    Ok(())
}

#[test]
fn replacing_creator_with_byte_equal_named_file_cannot_replace_first_creator_identity() -> Result<()>
{
    let mut world = super::super::tests::world()?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    stage(&mut world.owner, &mut session, &binding)?;
    let path = world.owner.state().target_path()?;
    let bytes = std::fs::read(&path)?;
    let mut source = Model::new();
    let root = source.root.clone();
    let mut candidate =
        Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root)?;
    std::fs::rename(&path, path.with_extension("old"))?;
    std::fs::write(&path, bytes)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    candidate.owner.state().creator = Some(OpenOptions::new().read(true).write(true).open(&path)?);
    assert!(candidate.check().is_err());
    assert!(candidate.source.refused && candidate.owner.state().refused);
    Ok(())
}

#[test]
fn identical_binding_under_another_original_or_foreign_root_never_joins() -> Result<()> {
    for change in 0..5 {
        let mut world = super::super::tests::world()?;
        let binding = binding(&mut world.owner);
        let (mut a, mut stop) = drain::configured(binding.clone());
        let mut session = Session::begin(&mut a, &mut stop)?;
        stage(&mut world.owner, &mut session, &binding)?;
        let (mut a2, mut stop2) = drain::configured(binding.clone());
        let other = Session::begin(&mut a2, &mut stop2)?;
        let state = world.owner.state();
        let mut wrong = Target {
            binding: binding.clone(),
            original: session.identity(),
            settled_root: Digest::new(b"settled-current-root"),
            image: state.frozen_image.clone().unwrap(),
            creator: state.creator_identity.unwrap(),
        };
        match change {
            0 => wrong.original = other.identity(),
            1 => wrong.binding.operation = Digest::new(b"other-operation"),
            2 => wrong.binding.target_epoch += 1,
            3 => wrong.settled_root = Digest::new(b"old-unsettled-root"),
            _ => wrong.image.0 = Digest::new(b"different-reset-image"),
        }
        let mut source = Model::new();
        source.wrong = Some(wrong);
        let root = source.root.clone();
        assert!(
            Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root).is_err()
        );
        assert!(world.owner.state().refused && source.refused);
        assert!(session.require_drained().is_err());
    }
    Ok(())
}

#[test]
fn unknown_admission_keeps_primary_and_postchecks_the_same_original_before_refusing() -> Result<()>
{
    let mut world = super::super::tests::world()?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    stage(&mut world.owner, &mut session, &binding)?;
    let mut source = Model::new();
    source.unknown = true;
    source.expire = true;
    let root = source.root.clone();
    let cause = source.cause.clone();
    let error = match Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root) {
        Ok(_) => panic!("unknown writer admitted"),
        Err(error) => error,
    };
    assert!(Arc::ptr_eq(
        &error.downcast_ref::<Unknown>().unwrap().0,
        &cause
    ));
    assert_eq!(source.calls, 1);
    assert!(world.owner.state().refused && source.refused);
    assert!(session.require_drained().is_err());
    Ok(())
}

#[test]
fn caught_check_unwind_and_expiry_poison_actual_owners_not_only_candidate() -> Result<()> {
    for panic in [false, true] {
        let mut world = super::super::tests::world()?;
        let binding = binding(&mut world.owner);
        let (mut a, mut stop) = drain::configured(binding.clone());
        let mut session = Session::begin(&mut a, &mut stop)?;
        stage(&mut world.owner, &mut session, &binding)?;
        let mut source = Model::new();
        let root = source.root.clone();
        let mut candidate =
            Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root)?;
        if panic {
            candidate.source.panic = true;
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| candidate.check()))
                    .is_err()
            );
            candidate.source.panic = false;
        } else {
            drain::at(candidate.session, 99, 100);
            assert!(candidate.check().is_err());
            drain::at(candidate.session, 10, 10);
        }
        assert!(candidate.check().is_err());
        assert!(candidate.owner.state().refused && candidate.source.refused);
        assert!(candidate.session.require_drained().is_err());
    }
    Ok(())
}

#[test]
fn closed_source_has_no_production_origin_impl_default_or_escaping_candidate_api() {
    use quote::ToTokens as _;
    fn normalize_type(ty: &mut syn::Type) {
        match ty {
            syn::Type::Path(path) => {
                for segment in &mut path.path.segments {
                    if let syn::PathArguments::AngleBracketed(args) = &mut segment.arguments {
                        args.args.pop_punct();
                        for arg in &mut args.args {
                            if let syn::GenericArgument::Type(ty) = arg {
                                normalize_type(ty);
                            }
                        }
                    }
                }
            }
            syn::Type::Reference(reference) => normalize_type(&mut reference.elem),
            syn::Type::Tuple(tuple) => {
                for elem in &mut tuple.elems {
                    normalize_type(elem);
                }
            }
            syn::Type::Paren(paren) => normalize_type(&mut paren.elem),
            syn::Type::Group(group) => normalize_type(&mut group.elem),
            _ => {}
        }
    }
    fn signature(signature: &syn::Signature) -> String {
        let mut signature = signature.clone();
        // Optional generic/parameter commas change no nominal type or borrow.
        // Tuple punctuation remains exact because a one-tuple is a real type.
        for input in &mut signature.inputs {
            if let syn::FnArg::Typed(input) = input {
                normalize_type(&mut input.ty);
            }
        }
        if let syn::ReturnType::Type(_, ty) = &mut signature.output {
            normalize_type(ty);
        }
        signature.inputs.pop_punct();
        signature.to_token_stream().to_string()
    }
    fn native_target_type(ty: &syn::Type) -> bool {
        let syn::Type::Path(path) = ty else {
            return false;
        };
        if path.qself.is_some()
            || path.path.leading_colon.is_some()
            || path.path.segments.len() != 1
        {
            return false;
        }
        let segment = &path.path.segments[0];
        if segment.ident != "NativeStagedTarget" {
            return false;
        }
        let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return false;
        };
        arguments.colon2_token.is_none() && arguments.args.len()==2
            && arguments.args.iter().all(|argument|matches!(argument,syn::GenericArgument::Lifetime(lifetime) if lifetime.ident=="_"))
    }
    fn closed(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let mut origins = 0;
        let mut restore_consumers = 0;
        for item in file.items {
            match item {
                syn::Item::Enum(item) if item.ident == "AdmissionOrigin" => {
                    origins += 1;
                    if !item.variants.iter().all(|v| v.attrs.iter().any(|a| matches!(&a.meta,
                        syn::Meta::List(m) if m.path.is_ident("cfg") && m.tokens.to_string() == "test"))) {
                        return false;
                    }
                }
                syn::Item::Impl(item) => {
                    if item.trait_.as_ref().is_some_and(|(_, p, _)| {
                        p.segments.last().is_some_and(|s| s.ident == "Source")
                    }) {
                        return false;
                    }
                    let context = matches!(&*item.self_ty, syn::Type::Path(ty)
                        if ty.path.segments.last().is_some_and(|part| part.ident == "StagingContext"));
                    let target = item.trait_.is_none() && native_target_type(&item.self_ty);
                    let restore = item.trait_.is_none()
                        && item.self_ty.to_token_stream().to_string()
                            == syn::parse_str::<syn::Type>(
                                "NativeRestore<'metadata, 'storage, 'role, 'selection>",
                            )
                            .unwrap()
                            .to_token_stream()
                            .to_string();
                    let cohort = item.trait_.is_none()
                        && matches!(&*item.self_ty,syn::Type::Path(path)
                        if path.qself.is_none() && path.path.leading_colon.is_none()
                            && path.path.segments.len()==1 && path.path.segments[0].ident=="RestoreControllerCohort"
                            && matches!(path.path.segments[0].arguments,syn::PathArguments::None));
                    for member in item.items {
                        if let syn::ImplItem::Fn(f) = member
                            && !matches!(f.vis, syn::Visibility::Inherited)
                        {
                            let context_method = context
                                && matches!(&f.vis, syn::Visibility::Restricted(v)
                                    if v.in_token.is_none() && v.path.is_ident("super"))
                                && [
                                    "portable",
                                    "state",
                                    "current",
                                    "local_sql",
                                    "application",
                                    "refuse",
                                ]
                                .iter()
                                .any(|name| f.sig.ident == *name);
                            // Only the exact concrete nonescaping target operations
                            // are admitted, with their exact types/visibility.
                            // No descriptor, constructor or generic callback is
                            // made available by this new private-material borrow.
                            let target_method = target
                                && matches!(&f.vis, syn::Visibility::Restricted(v)
                                    if v.in_token.is_some()
                                        && v.path.to_token_stream().to_string() == "crate :: security_epoch")
                                && [
                                    "fn refuse(&mut self)",
                                    "fn validate(&mut self, check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>) -> Result<crate::security_epoch::kernel::restore::completion::TargetReport>",
                                    "fn creator_data(&mut self, check:&mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_ ,'_ ,'_ ,'_ ,'_>)->Result<crate::security_epoch::native_enrollment::RestoreCreatorData>",
                                    "fn sync_for_receiver(&mut self, check:&mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>, receiver:&mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>)->Result<()>",
                                    "fn check_active_identity(&mut self, check:&mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>, creator:&crate::security_epoch::native_enrollment::RestoreCreatorData, report:&crate::security_epoch::kernel::restore::completion::TargetReport)->Result<()>",
                                    "fn pin_active_cohort(&mut self, check:&mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>, creator:&crate::security_epoch::native_enrollment::RestoreCreatorData, report:&crate::security_epoch::kernel::restore::completion::TargetReport)->Result<RestoreControllerCohort>",
                                ].into_iter().any(|expected|
                                    signature(&syn::parse_str::<syn::Signature>(expected).unwrap())
                                        == signature(&f.sig));
                            let restore_consumer = restore
                                && matches!(&f.vis, syn::Visibility::Restricted(v) if v.in_token.is_none() && v.path.is_ident("super"))
                                && signature(&f.sig) == signature(&syn::parse_str::<syn::Signature>("fn consume(mut auth: crate::security_epoch::bootstrap::AuthenticatedRestoreExecution<'metadata, 'storage, 'role>, intent: &crate::security_epoch::kernel::restore::Intent, state: State, selection: super::application::Selection<'selection>, artifact: super::archive::CapturedRestoreArtifact<'selection>) -> Result<Self>").unwrap());
                            let cohort_method=cohort
                                && matches!(&f.vis,syn::Visibility::Restricted(v) if v.in_token.is_some()
                                    && v.path.to_token_stream().to_string()=="crate :: security_epoch")
                                && signature(&f.sig)==signature(&syn::parse_str::<syn::Signature>("fn check(&mut self,target:&mut NativeStagedTarget<'_,'_>,creator:&crate::security_epoch::native_enrollment::RestoreCreatorData,report:&crate::security_epoch::kernel::restore::completion::TargetReport)->Result<crate::security_epoch::native_enrollment::SqliteCohort>").unwrap());
                            restore_consumers += usize::from(restore_consumer);
                            if !context_method
                                && !target_method
                                && !restore_consumer
                                && !cohort_method
                            {
                                return false;
                            }
                        }
                    }
                }
                syn::Item::Trait(item)
                    if item
                        .items
                        .iter()
                        .any(|i| matches!(i, syn::TraitItem::Fn(f) if f.default.is_some())) =>
                {
                    return false;
                }
                _ => {}
            }
        }
        origins == 1 && restore_consumers == 1
    }
    let source = include_str!("../writer.rs");
    assert!(closed(source));
    let mut compact = syn::parse_file(source).unwrap();
    let mut normalized = 0;
    for item in &mut compact.items {
        if let syn::Item::Impl(item) = item
            && matches!(&*item.self_ty, syn::Type::Path(ty)
                if ty.path.segments.last().is_some_and(|part|part.ident == "NativeStagedTarget"))
        {
            for method in &mut item.items {
                if let syn::ImplItem::Fn(method) = method
                    && method.sig.ident == "validate"
                {
                    assert!(method.sig.inputs.trailing_punct());
                    method.sig.inputs.pop_punct();
                    normalized += 1;
                }
            }
        }
    }
    assert_eq!(normalized, 1, "one actual target validation signature");
    assert!(closed(&compact.to_token_stream().to_string()));
    assert!(!closed(&source.replacen(
        "enum AdmissionOrigin {",
        "enum AdmissionOrigin { UntrustedReceipt,",
        1
    )));
    assert!(!closed(
        &(source.to_owned() + "\nimpl Source<UntrustedClock> for UntrustedData {}")
    ));
    assert!(!closed(&source.replacen(
        "    fn check(&mut self)",
        "    pub fn check(&mut self)",
        1
    )));
    for (name, expose) in [("refuse", true), ("validate", false)] {
        let mut changed = syn::parse_file(source).unwrap();
        let mut selected = 0;
        for item in &mut changed.items {
            if let syn::Item::Impl(item) = item
                && native_target_type(&item.self_ty)
            {
                for item in &mut item.items {
                    if let syn::ImplItem::Fn(method) = item
                        && method.sig.ident == name
                    {
                        selected += 1;
                        if expose {
                            method.vis = syn::parse_quote!(pub);
                        } else {
                            method.sig.output = syn::parse_quote!(->Result<std::fs::File>);
                        }
                    }
                }
            }
        }
        assert_eq!(selected, 1, "one actual public target method: {name}");
        assert!(!closed(&changed.to_token_stream().to_string()));
    }
    assert!(!closed(
        &(source.to_owned()
            + "\nimpl NativeStagedTarget<'_, '_> { pub(in crate::security_epoch) fn creator(&self) -> &std::fs::File { unreachable!() } }")
    ));
    let consume_start = source.find("pub(super) fn consume(").unwrap();
    let (before_consume, tail) = source.split_at(consume_start);
    let consume_end = tail.find("\n    fn begin(").unwrap();
    let (consume, after_consume) = tail.split_at(consume_end);
    for (from, to) in [
        ("pub(super) fn consume(", "pub(crate) fn consume("),
        (
            "mut auth: crate::security_epoch::bootstrap::AuthenticatedRestoreExecution<",
            "mut auth: UntrustedData<",
        ),
        ("state: State,", "state: std::fs::File,"),
        (
            "selection: super::application::Selection<'selection>,",
            "selection: Receipt,",
        ),
    ] {
        assert_eq!(
            consume.matches(from).count(),
            1,
            "exact production consumer target: {from}"
        );
        assert!(!closed(&format!(
            "{before_consume}{}{after_consume}",
            consume.replacen(from, to, 1)
        )));
    }
    for extra in [
        "impl NativeRestore<'static,'static,'static,'static> { pub(super) fn owner(&mut self) -> &mut UntrustedData { unreachable!() } }",
        "impl foreign::NativeRestore<'metadata,'storage,'role,'selection> { pub(super) fn consume(mut auth: crate::security_epoch::bootstrap::AuthenticatedRestoreExecution<'metadata,'storage,'role>, intent: &crate::security_epoch::kernel::restore::Intent, state: State, selection: super::application::Selection<'selection>, artifact: super::archive::CapturedRestoreArtifact<'selection>) -> Result<Self> { unreachable!() } }",
    ] {
        assert!(!closed(&(source.to_owned() + extra)));
    }
    for method_name in ["creator_data", "check_active_identity", "pin_active_cohort"] {
        for cut in 0..3 {
            let mut changed = syn::parse_file(source).unwrap();
            let mut selected = 0;
            for item in &mut changed.items {
                if let syn::Item::Impl(implementation) = item
                    && implementation.trait_.is_none()
                    && native_target_type(&implementation.self_ty)
                {
                    for item in &mut implementation.items {
                        if let syn::ImplItem::Fn(method) = item
                            && method.sig.ident == method_name
                        {
                            selected += 1;
                            match cut {
                                0 => method.vis = syn::parse_quote!(pub),
                                1 => method.sig.output = syn::parse_quote!(->Result<std::fs::File>),
                                _ => {
                                    let syn::FnArg::Typed(argument) =
                                        method.sig.inputs.last_mut().unwrap()
                                    else {
                                        panic!("actual check input");
                                    };
                                    *argument.ty = syn::parse_quote!(&mut UntrustedData);
                                }
                            }
                        }
                    }
                }
            }
            assert_eq!(selected, 1);
            assert!(
                !closed(&changed.to_token_stream().to_string()),
                "exact target API cut {cut}"
            );
        }
    }
    assert!(!closed(
        &(source.to_owned()
            + "\nimpl NativeStagedTarget<'_, '_> {pub(in crate::security_epoch) fn raw_creator(&self)->&std::fs::File{unreachable!()}}")
    ));
    for extra in [
        "impl RestoreControllerCohort {pub(in crate::security_epoch) fn raw(&self)->&std::fs::File{unreachable!()}}",
        "impl foreign::RestoreControllerCohort {pub(in crate::security_epoch) fn check(&mut self,target:&mut NativeStagedTarget<'_,'_>,creator:&crate::security_epoch::native_enrollment::RestoreCreatorData,report:&crate::security_epoch::kernel::restore::completion::TargetReport)->Result<crate::security_epoch::native_enrollment::SqliteCohort>{unreachable!()}}",
    ] {
        assert!(!closed(&(source.to_owned() + extra)));
    }
    for cut in 0..3 {
        let mut changed = syn::parse_file(source).unwrap();
        let mut selected = 0;
        for item in &mut changed.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("RestoreControllerCohort"))
            {
                for item in &mut item.items {
                    if let syn::ImplItem::Fn(method) = item
                        && method.sig.ident == "check"
                    {
                        selected += 1;
                        match cut {
                            0 => method.vis = syn::parse_quote!(pub),
                            1 => method.sig.output = syn::parse_quote!(->Result<std::fs::File>),
                            _ => {
                                let syn::FnArg::Typed(input) =
                                    method.sig.inputs.iter_mut().nth(1).unwrap()
                                else {
                                    panic!("actual target input")
                                };
                                *input.ty = syn::parse_quote!(&mut UntrustedData);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(selected, 1);
        assert!(!closed(&changed.to_token_stream().to_string()));
    }
}

#[test]
fn actual_concrete_context_keeps_native_checks_and_portable_models_separate() -> Result<()> {
    use quote::ToTokens as _;
    fn closed(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let expected = [
            ("native", "Self { source: StagingSource::Native(parent) }"),
            (
                "portable",
                "Self { source: StagingSource::Portable(owner) }",
            ),
            (
                "state",
                "match &mut self.source { StagingSource::Native(parent) => parent.state(), StagingSource::Portable(owner) => owner.state(), }",
            ),
            (
                "current",
                "match &mut self.source { StagingSource::Native(parent) => parent.current(), StagingSource::Portable(owner) => owner.current(), }",
            ),
            (
                "local_sql",
                "match &mut self.source { StagingSource::Native(parent) => parent.local_sql(), StagingSource::Portable(owner) => owner.local_sql(), }",
            ),
            (
                "application",
                "match &mut self.source { StagingSource::Native(parent) => parent.application(source), StagingSource::Portable(owner) => owner.application(source), }",
            ),
            (
                "refuse",
                "match &mut self.source { StagingSource::Native(parent) => parent.refuse(), StagingSource::Portable(owner) => owner.refuse(), }",
            ),
        ];
        let mut seen = 0;
        let mut variants = 0;
        for item in file.items {
            if let syn::Item::Enum(item) = &item
                && item.ident == "StagingSource"
            {
                variants += 1;
                if item.variants.len() != 2
                    || item.variants[0].ident != "Native"
                    || item.variants[1].ident != "Portable"
                {
                    return Ok(false);
                }
            }
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|part| part.ident == "StagingContext"))
            {
                if item.trait_.is_some() || item.items.len() != expected.len() {
                    return Ok(false);
                }
                for member in item.items {
                    let syn::ImplItem::Fn(method) = member else {
                        return Ok(false);
                    };
                    let Some((name, body)) =
                        expected.iter().find(|(name, _)| method.sig.ident == *name)
                    else {
                        return Ok(false);
                    };
                    if *name == "native" || *name == "portable" {
                        let [syn::Stmt::Expr(syn::Expr::Struct(value), None)] =
                            method.block.stmts.as_slice()
                        else {
                            return Ok(false);
                        };
                        if !value.path.is_ident("Self")
                            || value.rest.is_some()
                            || value.fields.len() != 1
                        {
                            return Ok(false);
                        }
                        let field = &value.fields[0];
                        if !matches!(&field.member, syn::Member::Named(name) if name == "source") {
                            return Ok(false);
                        }
                        let syn::Expr::Call(call) = &field.expr else {
                            return Ok(false);
                        };
                        let expected: syn::Expr = syn::parse_str(if *name == "native" {
                            "StagingSource::Native(parent)"
                        } else {
                            "StagingSource::Portable(owner)"
                        })?;
                        if call.to_token_stream().to_string()
                            != expected.to_token_stream().to_string()
                        {
                            return Ok(false);
                        }
                    } else {
                        let wanted = syn::parse_str::<syn::Block>(&format!("{{{body}}}"))?;
                        if method.block.to_token_stream().to_string()
                            != wanted.to_token_stream().to_string()
                        {
                            return Ok(false);
                        }
                    }
                    if *name == "native" && !matches!(method.vis, syn::Visibility::Inherited) {
                        return Ok(false);
                    }
                    seen += 1;
                }
            }
        }
        Ok(seen == expected.len() && variants == 1)
    }
    let source = include_str!("../writer.rs");
    assert!(closed(source)?);
    for (old, new) in [
        (
            "StagingSource::Native(parent) => parent.current(),",
            "StagingSource::Native(parent) => parent.local_sql(),",
        ),
        (
            "StagingSource::Native(parent) => parent.local_sql(),",
            "StagingSource::Native(parent) => parent.current(),",
        ),
        ("    fn native(", "    pub(super) fn native("),
    ] {
        assert_eq!(
            source.matches(old).count(),
            1,
            "actual native-context mutation target"
        );
        assert!(!closed(&source.replacen(old, new, 1))?);
    }
    assert!(!closed(&source.replacen(
        "    Native(&'owner",
        "    Forged, Native(&'owner",
        1
    ))?);
    Ok(())
}

#[test]
fn candidate_and_admission_are_not_copyable_serialized_transferable_permissions() {
    type Borrowed =
        Candidate<'static, 'static, 'static, super::super::tests::Fixture, drain::Model, Model>;
    macro_rules! opaque {
        ($ty:ty, $bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$ty as Ambiguous<_>>::check;
        }};
    }
    opaque!(Borrowed, Clone);
    opaque!(Borrowed, Default);
    opaque!(Borrowed, serde::Serialize);
    opaque!(Borrowed, serde::Deserialize<'static>);
    opaque!(Borrowed, Send);
    opaque!(Borrowed, Sync);
    opaque!(Admission, Clone);
    opaque!(Admission, Default);
    opaque!(Admission, serde::Serialize);
    opaque!(Admission, serde::Deserialize<'static>);
    opaque!(Admission, Send);
    opaque!(Admission, Sync);
    type Native = NativeParent<'static, 'static, 'static, 'static, 'static>;
    opaque!(Native, Clone);
    opaque!(Native, Copy);
    opaque!(Native, Default);
    opaque!(Native, std::fmt::Debug);
    opaque!(Native, serde::Serialize);
    opaque!(Native, serde::Deserialize<'static>);
    opaque!(Native, Send);
    opaque!(Native, Sync);
    type Context = StagingContext<'static, 'static, 'static, 'static, 'static, 'static>;
    opaque!(Context, Clone);
    opaque!(Context, Copy);
    opaque!(Context, Default);
    opaque!(Context, std::fmt::Debug);
    opaque!(Context, serde::Serialize);
    opaque!(Context, serde::Deserialize<'static>);
    opaque!(Context, Send);
    opaque!(Context, Sync);
}

#[test]
fn creator_born_under_original_a_cannot_join_identical_original_b() -> Result<()> {
    let mut world = super::super::tests::world()?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut first = Session::begin(&mut a, &mut stop)?;
    let first_id = first.identity();
    stage(&mut world.owner, &mut first, &binding)?;
    assert!(
        world
            .owner
            .state()
            .birth_original
            .as_ref()
            .unwrap()
            .same(&first_id)
    );
    let (mut b, mut other_stop) = drain::configured(binding.clone());
    let mut other = Session::begin(&mut b, &mut other_stop)?;
    assert!(!first_id.same(&other.identity()));
    let mut source = Model::new();
    let root = source.root.clone();
    assert!(Candidate::admit(&mut world.owner, &mut other, &mut source, binding, root).is_err());
    assert_eq!(source.calls, 0);
    assert!(
        world
            .owner
            .state()
            .birth_original
            .as_ref()
            .unwrap()
            .same(&first_id)
    );
    assert!(world.owner.state().refused && source.refused);
    assert!(other.require_drained().is_err());
    Ok(())
}

#[test]
fn raw_mechanical_staging_cannot_be_stamped_later_or_create_a_candidate() -> Result<()> {
    for later_stage in [false, true] {
        let mut world = super::super::tests::world()?;
        execute(&mut world.owner)?;
        assert!(world.owner.state().birth_original.is_none());
        let binding = binding(&mut world.owner);
        let (mut a, mut stop) = drain::configured(binding.clone());
        let mut session = Session::begin(&mut a, &mut stop)?;
        let mut source = Model::new();
        let root = source.root.clone();
        if later_stage {
            assert!(stage(&mut world.owner, &mut session, &binding).is_err());
        }
        assert!(
            Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root).is_err()
        );
        assert!(world.owner.state().birth_original.is_none());
        assert_eq!(source.calls, 0);
        assert!(world.owner.state().refused && source.refused);
    }
    Ok(())
}

#[test]
fn expiry_during_owner_metadata_work_prevents_the_next_creator_io_and_admission() -> Result<()> {
    let mut world = super::super::tests::world()?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    stage(&mut world.owner, &mut session, &binding)?;
    let mut observed = world.owner.state().creator.as_ref().unwrap().try_clone()?;
    observed.seek(SeekFrom::Start(37))?;
    world.owner.expire_current = Some(drain::clock_handle(&mut session));
    let mut source = Model::new();
    let root = source.root.clone();
    assert!(Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root).is_err());
    assert_eq!(observed.stream_position()?, 37); // even first seek was forbidden
    assert_eq!(source.calls, 0);
    assert!(world.owner.state().refused && source.refused);
    drain::at(&mut session, 10, 10);
    assert!(session.require_drained().is_err());
    Ok(())
}

#[test]
fn native_parent_keeps_the_actual_root_and_brackets_local_checks_without_provider_work()
-> Result<()> {
    use quote::ToTokens as _;
    fn joined(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let expected_current: syn::Block = syn::parse_quote!({
            let checked = (|| {
                self.loan.check_current()?;
                let requested = self.root.check(&self.state.root);
                let artifact = match self.installed.as_mut() {
                    Some(artifact) => artifact.check(&self.state),
                    None => Ok(()),
                };
                let post = self.loan.check_current();
                requested?;
                artifact?;
                post.map(|_| ())
            })();
            if checked.is_err() {
                self.refuse();
            }
            checked
        });
        let expected_local: syn::Block = syn::parse_quote!({
            let checked = (|| {
                self.loan.check_local()?;
                let requested = self.root.check(&self.state.root);
                let artifact = match self.installed.as_mut() {
                    Some(artifact) => artifact.check(&self.state),
                    None => Ok(()),
                };
                let post = self.loan.check_local();
                requested?;
                artifact?;
                post
            })();
            if checked.is_err() {
                self.refuse();
            }
            checked
        });
        let root_type = syn::parse_str::<syn::Type>(
            "crate::security_epoch::storage_authority::RestoreCreatorRoot",
        )?
        .to_token_stream()
        .to_string();
        let mut root = false;
        let mut methods = 0;
        for item in &file.items {
            if let syn::Item::Struct(item) = item
                && item.ident == "NativeParent"
            {
                root = item.fields.iter().any(|field| {
                    field.ident.as_ref().is_some_and(|id| id == "root")
                        && matches!(field.vis, syn::Visibility::Inherited)
                        && field.ty.to_token_stream().to_string() == root_type
                });
            }
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if item.trait_.is_some()
                || !matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|part| part.ident == "NativeParent"))
            {
                continue;
            }
            for method in &item.items {
                let syn::ImplItem::Fn(method) = method else {
                    continue;
                };
                let expected = if method.sig.ident == "current" {
                    &expected_current
                } else if method.sig.ident == "local_sql" {
                    &expected_local
                } else {
                    continue;
                };
                if method.block.to_token_stream().to_string()
                    != expected.to_token_stream().to_string()
                {
                    return Ok(false);
                }
                methods += 1;
            }
        }
        Ok(root && methods == 2)
    }
    let source = include_str!("../writer.rs");
    assert!(joined(source)?);
    for (old, new) in [
        (
            "root: crate::security_epoch::storage_authority::RestoreCreatorRoot,",
            "root: File,",
        ),
        (
            "let requested = self.root.check(&self.state.root);",
            "let requested = Ok(());",
        ),
        ("let post = self.loan.check_local();", "let post = Ok(());"),
        ("self.loan.check_local()?;", "self.loan.check_current()?;"),
        (
            "requested?;\n            artifact?;\n            post",
            "post?;\n            artifact?;\n            requested",
        ),
    ] {
        assert!(
            source.contains(old),
            "actual native-root join mutant target"
        );
        let changed = if old == "requested?;\n            artifact?;\n            post" {
            let start = source.find("    fn local_sql(").unwrap();
            format!(
                "{}{}",
                &source[..start],
                source[start..].replacen(old, new, 1)
            )
        } else {
            source.replacen(old, new, 1)
        };
        assert!(!joined(&changed)?);
    }
    Ok(())
}

#[test]
fn native_transition_bridge_keeps_actual_creator_original_postchecks_and_no_data_grant()
-> Result<()> {
    use quote::ToTokens as _;
    fn fixed(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let methods:Vec<_>=file.items.iter().filter_map(|item|match item {
            syn::Item::Impl(owner) if owner.trait_.is_none() && matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident=="RestoredWriterCandidate"))=>Some(owner),_=>None,
        }).flat_map(|owner|owner.items.iter()).filter_map(|item|match item {
            syn::ImplItem::Fn(method) if method.sig.ident=="confirm"=>Some(method),_=>None,
        }).collect();
        let [actual] = methods.as_slice() else {
            return Ok(false);
        };
        let [syn::Stmt::Expr(syn::Expr::MethodCall(call), None)] = actual.block.stmts.as_slice()
        else {
            return Ok(false);
        };
        let expected: syn::Expr =
            syn::parse_quote!(loan.confirm_writer(self.target, &mut self.peer));
        let syn::Expr::MethodCall(expected) = expected else {
            unreachable!()
        };
        let mut call = call.clone();
        call.args.pop_punct();
        Ok(
            matches!(&actual.vis,syn::Visibility::Restricted(visibility) if visibility.path.to_token_stream().to_string()=="crate :: security_epoch")
                && call.to_token_stream().to_string() == expected.to_token_stream().to_string(),
        )
    }
    // Replace the old raw holder/creator bridge in place. The actual candidate
    // now lends its SAME target and peer; there is no caller holder argument.
    let source = include_str!("receiver.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    assert!(fixed(source)?);
    for (from, to) in [
        (
            "loan.confirm_writer(self.target, &mut self.peer)",
            "loan.confirm_writer(other_target, &mut self.peer)",
        ),
        (
            "loan.confirm_writer(self.target, &mut self.peer)",
            "loan.confirm_writer(self.target, &mut other_peer)",
        ),
        (
            "loan.confirm_writer(self.target, &mut self.peer)",
            "loan.confirm_writer(self.target, holder_data)",
        ),
        (
            "loan.confirm_writer(self.target, &mut self.peer)",
            "Ok(receipt_data)",
        ),
    ] {
        assert_eq!(source.matches(from).count(), 1);
        assert!(!fixed(&source.replacen(from, to, 1))?);
    }
    Ok(())
}

#[test]
fn native_entry_binds_actual_loan_before_root_and_report_follows_real_reset() -> Result<()> {
    use quote::ToTokens as _;
    use syn::visit::{self, Visit};
    fn canonical(expr: &syn::Expr) -> String {
        let mut expr = expr.clone();
        if let syn::Expr::MethodCall(call) = &mut expr
            && call.args.trailing_punct()
        {
            call.args.pop_punct();
        }
        expr.to_token_stream().to_string()
    }
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(canonical(&syn::Expr::MethodCall(call.clone())));
            visit::visit_expr_method_call(self, call);
        }
    }
    fn flow(source: &str, owner: &str, method: &str) -> Result<Vec<String>> {
        let file = syn::parse_file(source)?;
        let mut found = Vec::new();
        for item in &file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if item.trait_.is_some()
                || !matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.segments.last().is_some_and(|part| part.ident == owner))
            {
                continue;
            }
            for item in &item.items {
                if let syn::ImplItem::Fn(item) = item
                    && item.sig.ident == method
                {
                    let mut calls = Calls::default();
                    calls.visit_block(&item.block);
                    found.push(calls.0);
                }
            }
        }
        ensure!(found.len() == 1, "one actual native entry method");
        Ok(found.remove(0))
    }
    fn required(source: &str) -> Result<bool> {
        let calls = flow(source, "NativeParent", "admit")?;
        let sequence = [
            "loan.require_staging_input(intent, &state.input.namespace)",
            "state.require_unstarted()",
            "selection.require_native_input(&state.input, intent)",
            "loan.admit_creator_root(&state.root)",
            "loan.check_current()",
            "parent.current()",
        ];
        let mut cursor = 0;
        for expected in sequence {
            let expected = canonical(&syn::parse_str::<syn::Expr>(expected)?);
            let Some(relative) = calls[cursor..].iter().position(|call| call == &expected) else {
                return Ok(false);
            };
            cursor += relative + 1;
        }
        let calls = flow(source, "NativeParent", "stage_and_settle")?;
        let expected = [
            "self.selection.require_native_input(&self.state.input, intent)",
            "self.execute_staging()",
            "self.artifact.install(&mut self.loan, &mut self.root, &mut self.state, intent)",
            "self.current()",
            "self.selection.reborrow()",
            "self.installed.as_mut().context(\"restore_artifact_not_installed\")",
            "self.installed.as_mut()",
            "self.loan.settle_target(&mut target)",
            "self.current()",
            "result.is_err()",
            "self.refuse()",
        ]
        .into_iter()
        .map(|value| syn::parse_str::<syn::Expr>(value).map(|e| canonical(&e)))
        .collect::<std::result::Result<Vec<_>, _>>()?;
        if calls != expected {
            return Ok(false);
        }
        let consumed = flow(source, "NativeRestore", "consume")?;
        let actual_stop = canonical(&syn::parse_str::<syn::Expr>(
            "auth.stop_for_restore(intent)",
        )?);
        if consumed.iter().filter(|call| **call == actual_stop).count() != 1 {
            return Ok(false);
        }
        let calls = flow(source, "NativeRestore", "begin")?;
        let borrowed = canonical(&syn::parse_str::<syn::Expr>("self.owner.borrow_write()")?);
        Ok(calls.first() == Some(&borrowed)
            && calls.iter().filter(|call| **call == borrowed).count() == 1)
    }
    let source = include_str!("../writer.rs");
    assert!(required(source)?);
    // Mutate parsed tokens, so native line folding and optional call commas
    // cannot silently lose the actual production target.
    fn fragment(text: &str) -> Result<String> {
        let block: syn::Block = syn::parse_str(&format!("{{{text}}}"))?;
        ensure!(block.stmts.len() == 1, "one actual source fragment");
        Ok(block.stmts[0]
            .to_token_stream()
            .to_string()
            .replace(", )", " )")
            .replace(",)", ")"))
    }
    let parsed = syn::parse_file(source)?
        .to_token_stream()
        .to_string()
        .replace(", )", " )")
        .replace(",)", ")");
    assert!(required(&parsed)?);
    for (before, after) in [
        (
            "loan.require_staging_input(intent, &state.input.namespace)?;",
            "Ok::<(),anyhow::Error>(())?;",
        ),
        (
            "loan.admit_creator_root(&state.root)",
            "loan.admit_creator_root(&other_root)",
        ),
        ("parent.current()?;", "Ok::<(),anyhow::Error>(())?;"),
        (
            "let projection = self.execute_staging()?;",
            "let projection = cached_projection;",
        ),
        (
            "self.loan.settle_target(&mut target)",
            "self.loan.settle_other(&mut target)",
        ),
        ("self.owner.borrow_write()?", "self.owner.borrow_other()?"),
        ("auth.stop_for_restore(intent)?", "auth.other_stop(intent)?"),
    ] {
        let before = fragment(before)?;
        let after = fragment(after)?;
        assert_eq!(
            parsed.matches(&before).count(),
            1,
            "actual native entry mutation target"
        );
        assert!(!required(&parsed.replacen(&before, &after, 1))?);
    }
    Ok(())
}
