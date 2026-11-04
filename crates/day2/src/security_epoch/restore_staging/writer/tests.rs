use super::*;
use crate::security_epoch::restore_fencing::tests as drain;
use std::sync::Arc;

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
        Self { refused: false, calls: 0, checks: 0, root: Digest::new(b"settled-current-root"),
            wrong: None, unknown: false, expire: false, panic: false, cause: Arc::new(()) }
    }
}
impl sealed::Source for Model {}
impl Source<drain::Model> for Model {
    fn admit(&mut self, session: &mut Session<'_, drain::Model>, target: &Target, _: &File) -> Result<Admission> {
        self.calls += 1;
        ensure!(!self.refused && self.calls == 1, "controlled_writer_reissued");
        if self.expire { drain::at(session, 99, 100); }
        if self.unknown { return Err(anyhow::Error::new(Unknown(self.cause.clone()))); }
        Ok(Admission { origin: AdmissionOrigin::UnqualifiedModel,
            target: self.wrong.take().unwrap_or_else(|| target.clone()) })
    }
    fn check(&mut self, _: &mut Session<'_, drain::Model>, admission: &Admission, creator: &File) -> Result<()> {
        self.checks += 1;
        assert!(!self.panic, "controlled_writer_check_panic");
        ensure!(!self.refused && self.root == admission.target.settled_root, "controlled_root_or_writer_changed");
        let held = creator.metadata()?;
        ensure!((held.dev(), held.ino()) == admission.target.creator, "controlled_creator_changed");
        Ok(())
    }
    fn refuse(&mut self) { self.refused = true; }
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
fn same_creator_reset_image_and_actual_session_remain_borrowed_and_drop_refuses_all() -> Result<()> {
    let mut world = super::super::tests::world()?;
    execute(&mut world.owner)?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    let mut source = Model::new();
    let root = source.root.clone();
    {
        let mut candidate = Candidate::admit(&mut world.owner, &mut session, &mut source, binding.clone(), root.clone())?;
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
    assert!(Candidate::admit(&mut world.owner, &mut session2, &mut source2, binding, root).is_err());
    assert_eq!(source2.calls, 0);
    Ok(())
}

#[test]
fn same_inode_same_length_overwrite_cannot_reuse_a_previous_positive_check() -> Result<()> {
    let mut world = super::super::tests::world()?;
    execute(&mut world.owner)?;
    let binding = binding(&mut world.owner);
    let mut external = world.owner.state().creator.as_ref().unwrap().try_clone()?;
    external.seek(SeekFrom::Start(120))?;
    let mut saved = [0u8; 1]; external.read_exact(&mut saved)?;
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    let mut source = Model::new(); let root = source.root.clone();
    let mut candidate = Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root)?;
    candidate.check()?;
    external.seek(SeekFrom::Start(120))?;
    external.write_all(&[saved[0] ^ 1])?; external.sync_all()?;
    assert!(candidate.check().is_err());
    external.seek(SeekFrom::Start(120))?; external.write_all(&saved)?; external.sync_all()?;
    assert!(candidate.check().is_err());
    assert!(candidate.source.refused && candidate.owner.state().refused);
    assert!(candidate.session.require_drained().is_err());
    Ok(())
}

#[test]
fn replacing_creator_with_byte_equal_named_file_cannot_replace_first_creator_identity() -> Result<()> {
    let mut world = super::super::tests::world()?;
    execute(&mut world.owner)?;
    let binding = binding(&mut world.owner);
    let path = world.owner.state().target_path()?;
    let bytes = std::fs::read(&path)?;
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    let mut source = Model::new(); let root = source.root.clone();
    let mut candidate = Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root)?;
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
        execute(&mut world.owner)?;
        let binding = binding(&mut world.owner);
        let (mut a, mut stop) = drain::configured(binding.clone());
        let mut session = Session::begin(&mut a, &mut stop)?;
        let (mut a2, mut stop2) = drain::configured(binding.clone());
        let other = Session::begin(&mut a2, &mut stop2)?;
        let state = world.owner.state();
        let mut wrong = Target { binding: binding.clone(), original: session.identity(),
            settled_root: Digest::new(b"settled-current-root"), image: state.frozen_image.clone().unwrap(),
            creator: state.creator_identity.unwrap() };
        match change {
            0 => wrong.original = other.identity(),
            1 => wrong.binding.operation = Digest::new(b"other-operation"),
            2 => wrong.binding.target_epoch += 1,
            3 => wrong.settled_root = Digest::new(b"old-unsettled-root"),
            _ => wrong.image.0 = Digest::new(b"different-reset-image"),
        }
        let mut source = Model::new(); source.wrong = Some(wrong);
        let root = source.root.clone();
        assert!(Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root).is_err());
        assert!(world.owner.state().refused && source.refused);
        assert!(session.require_drained().is_err());
    }
    Ok(())
}

#[test]
fn unknown_admission_keeps_primary_and_postchecks_the_same_original_before_refusing() -> Result<()> {
    let mut world = super::super::tests::world()?;
    execute(&mut world.owner)?;
    let binding = binding(&mut world.owner);
    let (mut a, mut stop) = drain::configured(binding.clone());
    let mut session = Session::begin(&mut a, &mut stop)?;
    let mut source = Model::new(); source.unknown = true; source.expire = true;
    let root = source.root.clone(); let cause = source.cause.clone();
    let error = match Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root) {
        Ok(_) => panic!("unknown writer admitted"), Err(error) => error,
    };
    assert!(Arc::ptr_eq(&error.downcast_ref::<Unknown>().unwrap().0, &cause));
    assert_eq!(source.calls, 1);
    assert!(world.owner.state().refused && source.refused);
    assert!(session.require_drained().is_err());
    Ok(())
}

#[test]
fn caught_check_unwind_and_expiry_poison_actual_owners_not_only_candidate() -> Result<()> {
    for panic in [false, true] {
        let mut world = super::super::tests::world()?;
        execute(&mut world.owner)?;
        let binding = binding(&mut world.owner);
        let (mut a, mut stop) = drain::configured(binding.clone());
        let mut session = Session::begin(&mut a, &mut stop)?;
        let mut source = Model::new(); let root = source.root.clone();
        let mut candidate = Candidate::admit(&mut world.owner, &mut session, &mut source, binding, root)?;
        if panic {
            candidate.source.panic = true;
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| candidate.check())).is_err());
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
    let source = include_str!("../writer.rs");
    let file = syn::parse_file(source).unwrap();
    let origin = file.items.iter().find_map(|item| match item {
        syn::Item::Enum(item) if item.ident == "AdmissionOrigin" => Some(item), _ => None,
    }).unwrap();
    assert!(origin.variants.iter().all(|v| v.attrs.iter().any(|a| matches!(&a.meta,
        syn::Meta::List(m) if m.path.is_ident("cfg") && m.tokens.to_string() == "test"))));
    for item in file.items {
        if let syn::Item::Impl(item) = item {
            assert!(item.trait_.as_ref().is_none_or(|(_, p, _)| !p.is_ident("Source")));
            for member in item.items {
                if let syn::ImplItem::Fn(f) = member {
                    assert!(matches!(f.vis, syn::Visibility::Inherited));
                }
            }
        }
    }
    // No genuine owner or filesystem object can be recovered from Candidate.

}
