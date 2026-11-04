use super::*;

fn digest(label: &str) -> Digest {
    Digest::new(label.as_bytes())
}
fn binding() -> Binding {
    Binding {
        scope: AuthorityScope {
            installation: "company".to_owned().try_into().unwrap(),
            environment: "test".to_owned().try_into().unwrap(),
            app: "one-app".to_owned().try_into().unwrap(),
        },
        selection: digest("selected-store"),
        incumbent_root: digest("root"),
        incumbent_holder: digest("holder"),
        intent: digest("exact-intent"),
        operation: digest("one-staging-op"),
        binding_generation: 3,
        source_epoch: 7,
        target_epoch: 8,
        target_incarnation: digest("fresh-target"),
    }
}
fn lease(kind: Kind, tag: &str, end: u64) -> Outstanding {
    Outstanding {
        identity: Identity {
            holder: digest("holder"),
            executor: digest(tag),
            stage: digest("actual-stage"),
            grant: digest("one-grant"),
            kind,
        },
        expires_upper: end,
    }
}
fn approval(expires: u64) -> Approval {
    Approval {
        origin: ApprovalOrigin::UnqualifiedModel,
        binding: binding(),
        domain: digest("qualified-clock"),
        issued_at: 10,
        expires_at: expires,
        last: None,
        state: Cell::new(Disposition::Fresh),
        identity: Rc::new(()),
        local: PhantomData,
    }
}
#[derive(Debug)]
struct StopFailure(std::sync::Arc<()>);
impl std::fmt::Display for StopFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("controlled_stop_unknown")
    }
}
impl std::error::Error for StopFailure {}
pub(in crate::security_epoch) struct Model {
    binding: Binding,
    domain: Digest,
    lower: u64,
    upper: u64,
    identity: Rc<()>,
    leases: Vec<Outstanding>,
    gate_closed: bool,
    refused: bool,
    complete: bool,
    stop_calls: usize,
    samples: usize,
    unknown: bool,
    post_error: bool,
    panic_sample: Option<usize>,
    panic_stopped: bool,
    cause: std::sync::Arc<()>,
}
impl Model {
    fn new(mut leases: Vec<Outstanding>) -> Self {
        leases.sort_by(|a, b| a.identity.cmp(&b.identity));
        Self {
            binding: binding(),
            domain: digest("qualified-clock"),
            lower: 10,
            upper: 10,
            identity: Rc::new(()),
            leases,
            gate_closed: false,
            refused: false,
            complete: true,
            stop_calls: 0,
            samples: 0,
            unknown: false,
            post_error: false,
            panic_sample: None,
            panic_stopped: false,
            cause: std::sync::Arc::new(()),
        }
    }
    pub(in crate::security_epoch) fn at(&mut self, lower: u64, upper: u64) {
        self.lower = lower;
        self.upper = upper;
    }
}
impl sealed::Source for Model {}
impl Source for Model {
    fn current(&mut self, _: &Approval) -> Result<Clock> {
        self.samples += 1;
        assert!(
            self.panic_sample != Some(self.samples),
            "controlled_current_panic"
        );
        ensure!(!self.refused, "controlled_source_refused");
        ensure!(
            !(self.post_error && self.stop_calls > 0),
            "controlled_postcheck_failure"
        );
        Ok(Clock {
            binding: self.binding.clone(),
            domain: self.domain.clone(),
            lower: self.lower,
            upper: self.upper,
        })
    }
    fn stop(&mut self, _: &Approval) -> Result<Stopped> {
        ensure!(
            !self.refused && !self.gate_closed,
            "controlled_stop_repeated"
        );
        self.stop_calls += 1;
        self.gate_closed = true;
        if self.unknown {
            return Err(anyhow::Error::new(StopFailure(self.cause.clone())));
        }
        ensure!(self.complete, "controlled_inventory_not_complete");
        Ok(Stopped {
            origin: StopOrigin::UnqualifiedModel,
            binding: self.binding.clone(),
            domain: self.domain.clone(),
            source: self.identity.clone(),
            stop_upper: self.upper,
            outstanding: self.leases.clone(),
        })
    }
    fn check_stopped(&mut self, _: &Approval, cut: &Stopped) -> Result<()> {
        assert!(!self.panic_stopped, "controlled_stop_check_panic");
        ensure!(
            !self.refused
                && self.gate_closed
                && self.complete
                && Rc::ptr_eq(&self.identity, &cut.source)
                && self.binding == cut.binding
                && self.domain == cut.domain
                && self.leases == cut.outstanding,
            "controlled_exclusion_changed"
        );
        Ok(())
    }
    fn refuse(&mut self) {
        self.refused = true;
    }
}

#[test]
fn every_final_permit_and_clock_uncertainty_must_drain_inside_one_original() -> Result<()> {
    let mut a = approval(100);
    let mut source = Model::new(vec![
        lease(Kind::Lease, "app", 20),
        lease(Kind::FinalPermit, "paused-winner", 40),
    ]);
    let mut session = Session::begin(&mut a, &mut source)?;
    assert_eq!(session.poll()?, WaitStatus::Pending { not_before: 40 });
    session.source.at(39, 41);
    assert_eq!(session.poll()?, WaitStatus::Pending { not_before: 40 });
    session.source.at(40, 41);
    session.require_drained()?;
    assert_eq!(session.approval.expires_at, 100);
    assert_eq!(session.source.stop_calls, 1);
    // Cached Drained DATA cannot outlive the same original or renew it.
    session.source.at(99, 100);
    assert!(session.require_drained().is_err());
    session.source.at(40, 41);
    assert!(session.require_drained().is_err());
    assert_eq!(session.source.stop_calls, 1);
    Ok(())
}

#[test]
fn missing_inventory_and_original_too_short_refuse_without_waiting_or_retry() {
    for incomplete in [false, true] {
        let mut a = approval(40);
        let mut source = Model::new(vec![lease(Kind::FinalPermit, "late", 40)]);
        source.complete = !incomplete;
        assert!(Session::begin(&mut a, &mut source).is_err());
        assert!(source.gate_closed && source.refused);
        assert_eq!(a.state.get(), Disposition::Refused);
        assert!(Session::begin(&mut a, &mut source).is_err());
        assert_eq!(source.stop_calls, 1);
    }
}

#[test]
fn unknown_stop_keeps_primary_cause_runs_postcheck_and_never_reissues() {
    let mut a = approval(100);
    let mut source = Model::new(vec![]);
    source.unknown = true;
    source.post_error = true;
    let cause = source.cause.clone();
    let error = match Session::begin(&mut a, &mut source) {
        Ok(_) => panic!("unknown stop admitted"),
        Err(error) => error,
    };
    assert!(std::sync::Arc::ptr_eq(
        &error.downcast_ref::<StopFailure>().unwrap().0,
        &cause
    ));
    assert_eq!(source.samples, 2);
    assert!(source.refused && source.gate_closed);
    assert!(Session::begin(&mut a, &mut source).is_err());
    assert_eq!(source.stop_calls, 1);
}

#[test]
fn changed_scope_selection_root_holder_intent_target_or_source_cannot_consume_a_cut() -> Result<()>
{
    for change in 0..9 {
        let mut a = approval(100);
        let mut source = Model::new(vec![]);
        let mut session = Session::begin(&mut a, &mut source)?;
        match change {
            0 => session.source.binding.scope.app = "foreign".to_owned().try_into()?,
            1 => session.source.binding.selection = digest("foreign"),
            2 => session.source.binding.incumbent_root = digest("foreign"),
            3 => session.source.binding.incumbent_holder = digest("foreign"),
            4 => session.source.binding.intent = digest("foreign"),
            5 => session.source.binding.target_incarnation = digest("foreign"),
            6 => session.source.domain = digest("foreign"),
            7 => session.source.identity = Rc::new(()),
            _ => session.source.gate_closed = false,
        }
        assert!(session.require_drained().is_err());
        assert!(session.source.refused);
    }
    Ok(())
}

#[test]
fn duplicate_or_unbounded_inventory_and_late_new_rights_refuse() -> Result<()> {
    for fault in 0..3 {
        let mut a = approval(100);
        let item = lease(Kind::Lease, "one", 20);
        let mut source = Model::new(match fault {
            0 => vec![item.clone(), item],
            1 => (0..=MAX_OUTSTANDING)
                .map(|i| lease(Kind::Lease, &format!("holder-{i}"), 20))
                .collect(),
            _ => vec![item],
        });
        if fault < 2 {
            assert!(Session::begin(&mut a, &mut source).is_err());
        } else {
            let mut session = Session::begin(&mut a, &mut source)?;
            session
                .source
                .leases
                .push(lease(Kind::FinalPermit, "late-right", 20));
            session.source.at(20, 20);
            assert!(session.require_drained().is_err());
        }
        assert!(source.refused);
    }
    Ok(())
}

#[test]
fn rewind_invalid_interval_and_drop_permanently_refuse_without_resume() -> Result<()> {
    for fault in 0..4 {
        let mut a = approval(100);
        let mut source = Model::new(vec![lease(Kind::Lease, "one", 20)]);
        {
            let mut session = Session::begin(&mut a, &mut source)?;
            match fault {
                0 => session.source.at(9, 10),
                1 => session.source.at(15, 14),
                2 => session.source.at(99, 100),
                _ => {}
            }
            if fault < 3 {
                assert!(session.poll().is_err());
            }
        }
        assert!(source.refused && source.gate_closed);
        assert!(Session::begin(&mut a, &mut source).is_err());
        assert_eq!(source.stop_calls, 1);
    }
    Ok(())
}

// Independent math oracle, with no production transition/check/helper call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Pending,
    Drained,
    Refused,
}
#[test]
fn generated_lease_and_permit_histories_replay_twice_against_independent_bounds() -> Result<()> {
    for seed in 0u64..64 {
        let ceiling = 20 + seed % 17;
        let end = ceiling + 1 + seed % 7;
        let schedule = [
            (10, 10),
            (ceiling - 1, ceiling + 1),
            (ceiling, ceiling + 1),
            (end - 1, end),
            (ceiling, ceiling),
        ];
        let mut replays = Vec::new();
        for _ in 0..2 {
            let mut a = approval(end);
            let mut source = Model::new(vec![
                lease(Kind::Lease, "app", ceiling - 1),
                lease(Kind::FinalPermit, "own-final", ceiling),
            ]);
            let mut session = Session::begin(&mut a, &mut source)?;
            let mut observations = Vec::new();
            let mut terminal = false;
            for (lower, upper) in schedule {
                let expected = if terminal || upper >= end {
                    terminal = true;
                    Expected::Refused
                } else if lower < ceiling {
                    Expected::Pending
                } else {
                    Expected::Drained
                };
                session.source.at(lower, upper);
                let observed = match session.poll() {
                    Ok(WaitStatus::Pending { .. }) => Expected::Pending,
                    Ok(WaitStatus::Drained) => Expected::Drained,
                    Err(_) => Expected::Refused,
                };
                assert_eq!(observed, expected, "seed {seed} bounds ({lower},{upper})");
                observations.push(observed);
            }
            assert_eq!(session.source.stop_calls, 1);
            replays.push(observations);
        }
        assert_eq!(replays[0], replays[1]);
    }
    Ok(())
}

#[test]
fn production_approval_stop_proofs_and_sources_have_no_construction_or_default_path() {
    use syn::visit::{self, Visit};
    #[derive(Default)]
    struct Audit {
        approval: usize,
        stop: usize,
        impls: usize,
        defaults: usize,
    }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && matches!(&a.meta,syn::Meta::List(v) if v.tokens.to_string()=="test")
            }) {
                return;
            }
            visit::visit_item_mod(self, item)
        }
        fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
            let n = item
                .variants
                .iter()
                .filter(|v| {
                    !v.attrs.iter().any(|a| {
                        a.path().is_ident("cfg")
                            && matches!(&a.meta,syn::Meta::List(v) if v.tokens.to_string()=="test")
                    })
                })
                .count();
            if item.ident == "ApprovalOrigin" {
                self.approval += n;
            }
            if item.ident == "StopOrigin" {
                self.stop += n;
            }
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            if item
                .trait_
                .as_ref()
                .is_some_and(|(_, p, _)| p.segments.last().is_some_and(|s| s.ident == "Source"))
            {
                self.impls += 1;
            }
            visit::visit_item_impl(self, item)
        }
        fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
            self.defaults += item
                .items
                .iter()
                .filter(|item| matches!(item,syn::TraitItem::Fn(f) if f.default.is_some()))
                .count();
        }
    }
    fn closed(source: &str) -> bool {
        let mut audit = Audit::default();
        audit.visit_file(&syn::parse_file(source).unwrap());
        audit.approval == 0 && audit.stop == 0 && audit.impls == 0 && audit.defaults == 0
    }
    let source = include_str!("../restore_fencing.rs");
    assert!(closed(source));
    assert!(!closed(&source.replacen(
        "enum ApprovalOrigin {",
        "enum ApprovalOrigin { UntrustedData,",
        1
    )));
    assert!(!closed(&source.replacen(
        "enum StopOrigin {",
        "enum StopOrigin { Receipt,",
        1
    )));
    assert!(!closed(
        &(source.to_owned() + "\nimpl Source for UntrustedData {}")
    ));
    macro_rules! opaque {
        ($ty:ty,$bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$ty as Ambiguous<_>>::check;
        }};
    }
    opaque!(Approval, Clone);
    opaque!(Approval, Default);
    opaque!(Approval, serde::Serialize);
    opaque!(Approval, serde::Deserialize<'static>);
    opaque!(Approval, Send);
    opaque!(Approval, Sync);
    opaque!(Stopped, Clone);
    opaque!(Stopped, Default);
    opaque!(Stopped, serde::Serialize);
    opaque!(Stopped, serde::Deserialize<'static>);
    opaque!(Stopped, Send);
    opaque!(Stopped, Sync);
}

#[test]
fn caught_poll_panics_poison_the_retained_session_at_every_supplier_cut() -> Result<()> {
    for site in 0..3 {
        let mut a = approval(100);
        let mut source = Model::new(vec![lease(Kind::FinalPermit, "held", 20)]);
        let mut session = Session::begin(&mut a, &mut source)?;
        match site {
            0 => session.source.panic_sample = Some(session.source.samples + 1),
            1 => session.source.panic_stopped = true,
            _ => session.source.panic_sample = Some(session.source.samples + 2),
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| session.poll()));
        assert!(result.is_err());
        session.source.panic_sample = None;
        session.source.panic_stopped = false;
        session.source.at(20, 20);
        assert_eq!(session.approval.state.get(), Disposition::Refused);
        assert!(session.source.refused);
        assert!(session.require_drained().is_err());
        assert_eq!(session.source.stop_calls, 1);
    }
    Ok(())
}

#[test]
fn continuity_data_never_replaces_the_same_fresh_session_or_target() -> Result<()> {
    let mut a = approval(100);
    let mut source = Model::new(vec![]);
    let mut first = Session::begin(&mut a, &mut source)?;
    let id = first.identity();
    first.require_join(&binding(), &id)?;
    let copied = id.clone();
    first.require_join(&binding(), &copied)?;
    let mut other_a = approval(100);
    let mut other_source = Model::new(vec![]);
    let mut second = Session::begin(&mut other_a, &mut other_source)?;
    assert!(!id.same(&second.identity()));
    assert!(second.require_join(&binding(), &id).is_err());
    assert!(second.source.refused);
    first.source.at(99, 100);
    assert!(first.require_join(&binding(), &copied).is_err());
    first.source.at(10, 10);
    assert!(first.require_join(&binding(), &copied).is_err());
    for cut in 0..5 {
        let mut a = approval(100);
        let mut source = Model::new(vec![]);
        let mut session = Session::begin(&mut a, &mut source)?;
        let id = session.identity();
        let mut expected = binding();
        match cut {
            0 => expected.operation = digest("different-operation"),
            1 => expected.binding_generation += 1,
            2 => expected.source_epoch += 1,
            3 => expected.target_epoch += 1,
            _ => expected.target_incarnation = digest("different-target"),
        }
        assert!(session.require_join(&expected, &id).is_err());
        assert!(session.source.refused);
    }
    Ok(())
}

// Controlled model ONLY; no native or production supplier is exposed.
pub(in crate::security_epoch) fn configured(binding: Binding) -> (Approval, Model) {
    let mut original = approval(100);
    original.binding = binding.clone();
    let mut source = Model::new(vec![]);
    source.binding = binding;
    (original, source)
}
