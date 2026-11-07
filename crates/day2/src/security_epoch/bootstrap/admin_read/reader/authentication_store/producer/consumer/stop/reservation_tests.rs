use super::*;
use quote::ToTokens as _;
use syn::{parse::Parser, visit::Visit};

fn method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
    syn::parse_file(source).unwrap().items.into_iter().find_map(|item| {
            let syn::Item::Impl(item)=item else {return None};
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|p|p.ident==owner)) {return None;}
            item.items.into_iter().find_map(|item|match item {syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(method),_=>None})
        }).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("ensure") {
            let args = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(mac.tokens.clone())
                .unwrap();
            for argument in &args {
                self.visit_expr(argument);
            }
        }
        syn::visit::visit_macro(self, mac);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        syn::visit::visit_expr_call(self, call);
        if let syn::Expr::Path(path) = &*call.func {
            if path.path.segments.len() > 1 {
                self.0.push(
                    path.path
                        .segments
                        .iter()
                        .map(|p| p.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                );
            }
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        syn::visit::visit_expr_method_call(self, call);
        self.0.push(call.method.to_string());
    }
    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        syn::visit::visit_expr_struct(self, node);
        self.0
            .push(node.path.segments.last().unwrap().ident.to_string());
    }
}

fn ordered(method: &syn::ImplItemFn, required: &[&str]) -> bool {
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    let mut at = 0;
    for name in required {
        let Some(index) = calls.0[at..].iter().position(|call| call == name) else {
            return false;
        };
        at += index + 1;
    }
    true
}

#[test]
fn actual_reservation_factory_commits_marker_before_packets_and_waits_for_known_peer() {
    let source = include_str!("../stop.rs");
    let stop = method(source, "AuthenticatedRestoreExecution", "stop_for_restore");
    let send = method(source, "NativeReservation", "reserve");
    let expected_stop = [
        "begin_restore_attempt",
        "check",
        "freeze_restore_issuer",
        "announce_restore_stop",
        "await_restore_stopped",
        "require_historical_keys",
        "NativeReservation",
        "reserve",
    ];
    let expected_send = [
        "check",
        "reserve_restore",
        "check",
        "announce_restore_fence",
        "check",
        "await_restore_fence_confirmed",
        "check",
        "require_restore_stopped",
        "FencedRestoreContinuation",
        "check_current",
    ];
    assert!(ordered(&stop, &expected_stop));
    assert!(ordered(&send, &expected_send));
    for (original, required) in [(&stop, &expected_stop[..]), (&send, &expected_send[..])] {
        let rendered = original.block.to_token_stream().to_string();
        for name in required
            .iter()
            .copied()
            .filter(|name| !matches!(*name, "check" | "reserve"))
        {
            assert_eq!(rendered.matches(name).count(), 1, "{name}");
            let mut parsed = original.clone();
            parsed.block = syn::parse_str(&rendered.replacen(name, "unchecked_data", 1)).unwrap();
            assert!(!ordered(&parsed, required), "{name}");
        }
    }
    // The supplied plan/clock cannot replace actual original acquisition.
    for forbidden in [
        "begin_current_stage",
        "begin_current_request",
        "enroll_current_thread",
        "NativeAcquisition :: begin",
    ] {
        assert!(!stop.to_token_stream().to_string().contains(forbidden));
        assert!(!send.to_token_stream().to_string().contains(forbidden));
    }
}

fn version(value: u64) -> kernel::UpdateTime {
    format!("2026-11-04T00:00:00.{value:06}Z")
        .try_into()
        .unwrap()
}

fn fixture(seed: u64) -> Result<(ReservationView, Vec<Snapshot>)> {
    let (before, plan) = kernel::restore::reservation_observation_fixture(seed)?;
    let mut after = before.clone();
    after.root = Some(kernel::Versioned {
        value: plan.reservation.advance.root.clone(),
        version: version(3),
    });
    after.sentinel = Some(kernel::Versioned {
        value: plan.reservation.advance.sentinel.clone(),
        version: version(3),
    });
    let mut rewritten = after.clone();
    rewritten.root.as_mut().unwrap().version = version(4);
    rewritten.sentinel.as_mut().unwrap().version = version(4);
    let mut history = after.clone();
    history.create.as_mut().unwrap().version = version(4);
    let mut partial = before.clone();
    partial.root = after.root.clone();
    let (_, foreign) = kernel::restore::reservation_observation_fixture(seed + 1)?;
    let mut other = after.clone();
    other.root.as_mut().unwrap().value = foreign.reservation.advance.root;
    Ok((
        ReservationView {
            before: before.clone(),
            root: plan.reservation.advance.root,
            sentinel: plan.reservation.advance.sentinel,
            phase: std::cell::RefCell::new(ObservationPhase::Created),
        },
        vec![before, after, rewritten, history, partial, other],
    ))
}

fn act(view: &mut ReservationView, observations: &[Snapshot], action: u64) -> bool {
    match action {
        0 => view.begin().is_ok(),
        1 => view.arm_commit().is_ok(),
        2..=7 => view.check(&observations[(action - 2) as usize]).is_ok(),
        8 => view.known(observations[1].clone()).is_ok(),
        9 => view.known(observations[2].clone()).is_ok(),
        10 => {
            view.refuse();
            true
        }
        _ => view.known(observations[0].clone()).is_ok(),
    }
}

#[test]
fn private_self_cas_observations_match_an_independent_replayable_model() -> Result<()> {
    for seed in 1_u64..=512 {
        let mut runs = Vec::new();
        for _ in 0..2 {
            let (mut actual, observations) = fixture(seed)?;
            // Independent states:0created,1reading,2uncertain interval,
            //3known-v3,4known-v4,5refused. No implementation discriminant,
            // equality predicate or native owner is used by this oracle.
            let mut expected = 0;
            let mut random = seed;
            let mut outcomes = Vec::new();
            for index in 0..48 {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                // Deterministically include the entire positive path before
                // generated refusal/rewrite/re-entry histories take over.
                let action = if seed % 2 == 0 && index < 7 {
                    [0, 1, 2, 3, 8, 3, 2][index]
                } else {
                    random % 12
                };
                let wanted = match action {
                    0 => {
                        let ok = expected == 0;
                        expected = if ok { 1 } else { 5 };
                        ok
                    }
                    1 => {
                        let ok = expected == 1;
                        expected = if ok { 2 } else { 5 };
                        ok
                    }
                    2 => matches!(expected, 0..=2),
                    3 => matches!(expected, 2 | 3),
                    4 => matches!(expected, 2 | 4),
                    5..=7 => false,
                    8 => {
                        let ok = expected == 2;
                        expected = if ok { 3 } else { 5 };
                        ok
                    }
                    9 => {
                        let ok = expected == 2;
                        expected = if ok { 4 } else { 5 };
                        ok
                    }
                    10 => {
                        expected = 5;
                        true
                    }
                    _ => false,
                };
                if !wanted {
                    expected = 5;
                }
                let observed = act(&mut actual, &observations, action);
                outcomes.push((action, observed));
                assert_eq!(observed, wanted, "seed={seed} prefix={outcomes:?}");
            }
            runs.push(outcomes);
        }
        assert_eq!(runs[0], runs[1], "seed={seed}");
    }
    Ok(())
}

#[test]
fn known_reservation_never_regresses_or_adopts_a_rewritten_or_partial_snapshot() -> Result<()> {
    let (mut actual, observations) = fixture(900)?;
    actual.begin()?;
    actual.arm_commit()?;
    actual.check(&observations[0])?;
    actual.check(&observations[1])?;
    actual.known(observations[1].clone())?;
    actual.check(&observations[1])?;
    assert!(actual.check(&observations[2]).is_err());
    assert!(actual.check(&observations[1]).is_err()); // repair never revives
    for index in [0, 3, 4, 5] {
        let (mut actual, observations) = fixture(901)?;
        actual.begin()?;
        actual.arm_commit()?;
        assert!(actual.known(observations[index].clone()).is_err());
        assert!(actual.known(observations[1].clone()).is_err());
    }
    Ok(())
}

#[test]
fn captured_readiness_survives_cas_peer_ack_and_handoff_without_clock_repair() -> Result<()> {
    // Independent effect-prefix model. These labels are not actual native
    // packets/SQL; the source controls below join the real checker sites.
    for cut in 0..3 {
        let captured = Readiness::new(1000, 1005)?;
        let original = (captured.observed_at, captured.ready_until);
        let mut released = Vec::new();
        for (index, effect) in [
            "reservation_send",
            "peer_confirmation",
            "fenced_sql_release",
        ]
        .into_iter()
        .enumerate()
        {
            let at = if index == cut { 1005 } else { 1004 };
            let checked = captured.check(at);
            assert_eq!(checked.is_ok(), index < cut, "cut={cut} effect={effect}");
            if checked.is_ok() {
                released.push(effect);
            }
            assert_eq!((captured.observed_at, captured.ready_until), original);
        }
        assert_eq!(released.len(), cut);
        assert!(captured.check(1004).is_err());
    }
    let captured = Readiness::new(1000, 1005)?;
    assert!(captured.check(999).is_err());
    assert!(captured.check(1001).is_err());
    Ok(())
}

#[test]
fn actual_fenced_local_and_current_checks_keep_the_same_captured_readiness() {
    let source = include_str!("../stop.rs");
    let guarded = |actual: &syn::ImplItemFn| {
        ordered(actual, &["current_fenced_time", "approval_window", "check"])
            && actual
                .block
                .to_token_stream()
                .to_string()
                .matches("self . readiness . check")
                .count()
                == 1
    };
    for name in ["check_local_inner", "check_current_inner"] {
        let actual = method(source, "FencedRestoreContinuation", name);
        assert!(guarded(&actual), "{name}");
        let rendered = actual.block.to_token_stream().to_string();
        let target = "self . readiness . check";
        assert_eq!(rendered.matches(target).count(), 1);
        let changed = rendered.replacen(target, "self . readiness . unchecked", 1);
        let mut parsed = actual.clone();
        parsed.block = syn::parse_str(&changed).unwrap();
        assert!(!guarded(&parsed));
    }
    let actual = method(include_str!("../stop.rs"), "NativeReservation", "reserve");
    assert!(
        actual
            .block
            .to_token_stream()
            .to_string()
            .contains("readiness : self . readiness")
    );
    let capture = method(
        include_str!("../stop.rs"),
        "AuthenticatedRestoreExecution",
        "stop_for_restore",
    );
    assert!(ordered(
        &capture,
        &["Readiness::new", "NativeReservation", "reserve"]
    ));
}

#[test]
fn native_reservation_checks_substitution_first_and_keeps_actual_send_error_primary() {
    let source =
        include_str!("../../../../../../../storage_authority/native_volume/restore_approval.rs");
    let actual = method(source, "NativeApprovalSource", "reserve_restore");
    assert!(ordered(
        &actual,
        &[
            "require_dispatch_data",
            "begin",
            "check",
            "call",
            "arm_commit",
            "commit_and_readback",
            "known",
            "check"
        ]
    ));
    let mut calls = Calls::default();
    calls.visit_block(&actual.block);
    assert_eq!(
        calls.0.first().map(String::as_str),
        Some("require_dispatch_data")
    );
    assert_eq!(
        calls
            .0
            .iter()
            .filter(|name| name.as_str() == "commit_and_readback")
            .count(),
        1
    );
    let dispatch = method(
        include_str!("../stop.rs"),
        "ReservationSourceLoan",
        "require_dispatch_data",
    );
    let rendered = dispatch.block.to_token_stream().to_string();
    for pointer in ["self . source", "self . plan", "self . current"] {
        assert!(rendered.contains(pointer), "{pointer}");
    }
    let post = method(source, "ReservationPort", "post");
    let rendered = post.block.to_token_stream().to_string();
    let sent = rendered.find("let sent =").unwrap();
    let checked = rendered.find("let checked =").unwrap();
    let primary = rendered.find("let bytes = sent ?").unwrap();
    let post_result = rendered.find("checked ?").unwrap();
    assert!(sent < checked && checked < primary && primary < post_result);
    let moved = rendered.replacen("let checked = self . loan . check (self . source) ;", "", 1);
    assert_ne!(moved, rendered);
    assert!(!moved.contains("let checked ="));
}
