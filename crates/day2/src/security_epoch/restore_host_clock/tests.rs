use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn actual_observation_intervals_enclose_the_independent_host_clock() -> Result<()> {
    // The independent world is an exact one-million-second offset. Measurements
    // can land anywhere within each before/after bracket; return checks spend
    // more time. Expected UTC is computed from that world, never Tracker state.
    for seed in 0..128_u64 {
        let mut tracker = Tracker::default();
        let offset = Duration::from_secs(1_000_000);
        let mut boot = ms(1000);
        let mut state = seed + 1;
        for _ in 0..32 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let before = boot;
            let measured = before + ms(state % 10);
            let after = measured + ms((state >> 8) % 10);
            let end = after + ms((state >> 16) % 10);
            let utc = offset + measured;
            let (lower, upper) = tracker.observe(before, utc, after, end)?;
            let actual_at_return = offset + end;
            assert!(
                lower <= actual_at_return && actual_at_return <= upper,
                "seed {seed}"
            );
            assert!(upper - lower <= MAX_UNCERTAINTY);
            boot = end + ms(1 + (state >> 24) % 20);
        }
    }
    Ok(())
}

#[test]
fn nonzero_clock_rates_remain_valid_across_varying_postcheck_durations() -> Result<()> {
    for rate in [-1000_i128, -500, 500, 1000] {
        for seed in 0..64_u64 {
            let utc_at = |boot: Duration| -> Duration {
                let nanos = 1_000_000_000_000_000_i128
                    + i128::try_from(boot.as_nanos()).expect("small world") * (1_000_000 + rate)
                        / 1_000_000;
                Duration::new(
                    (nanos / 1_000_000_000).try_into().expect("positive world"),
                    (nanos % 1_000_000_000).try_into().expect("nanos"),
                )
            };
            let mut tracker = Tracker::default();
            let mut boot = ms(1000);
            let mut state = seed + 1;
            for _ in 0..32 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let before = boot;
                let measured = before + ms(state % 10);
                let after = measured + ms((state >> 8) % 10);
                let end = after + ms((state >> 16) % 900);
                let (low, high) = tracker.observe(before, utc_at(measured), after, end)?;
                assert!(
                    low <= utc_at(end) && utc_at(end) <= high,
                    "rate {rate} seed {seed}"
                );
                boot = end + ms(1 + (state >> 24) % 20);
            }
        }
    }
    // Exact review counterexample: the prior read was at 1s, while its
    // postcheck completed at 2s. Zero time between returns is not zero time
    // between actual REALTIME reads.
    for utc in [
        Duration::from_micros(102_000_500),
        Duration::from_micros(101_999_500),
    ] {
        let mut tracker = Tracker::default();
        tracker.observe(ms(1000), ms(101_000), ms(1000), ms(2000))?;
        let (low, high) = tracker.observe(ms(2000), utc, ms(2000), ms(2000))?;
        assert!(low <= utc && utc <= high);
    }
    Ok(())
}

#[test]
fn steps_rewinds_uncertainty_and_overflow_are_terminal_even_after_clock_repair() -> Result<()> {
    for fault in 0..6 {
        let mut tracker = Tracker::default();
        tracker.observe(ms(1000), ms(101_005), ms(1010), ms(1020))?;
        let (before, utc, after, end) = match fault {
            0 => (ms(2000), ms(104_005), ms(2010), ms(2020)), // forward step
            1 => (ms(2000), ms(101_005), ms(2010), ms(2020)), // offset backstep without UTC reversal
            2 => (ms(2000), ms(100_000), ms(2010), ms(2020)), // UTC reversal
            3 => (ms(1019), ms(101_025), ms(1030), ms(1040)), // BOOTTIME rewind
            4 => (ms(2000), ms(102_005), ms(2010), ms(4000)), // excessive uncertainty
            _ => (ms(2000), ms(102_005), ms(1999), ms(2020)), // inverted bracket
        };
        assert!(
            tracker.observe(before, utc, after, end).is_err(),
            "fault {fault}"
        );
        assert!(
            tracker
                .observe(ms(3000), ms(103_005), ms(3010), ms(3020))
                .is_err(),
            "repair {fault}"
        );
    }
    let mut overflow = Tracker::default();
    assert!(
        overflow
            .observe(
                Duration::ZERO,
                Duration::MAX,
                Duration::from_nanos(1),
                Duration::from_nanos(2)
            )
            .is_err()
    );
    assert!(
        overflow
            .observe(ms(1000), ms(101_005), ms(1010), ms(1020))
            .is_err()
    );
    Ok(())
}

#[test]
fn actual_clock_views_keep_foreign_shorter_and_refused_originals_distinct() -> Result<()> {
    use crate::security_epoch::native_clock::NativeAcquisition;
    // These are the existing lower clock fixtures, never enrolled-stage or
    // approval factories. They exercise the exact view meet used by the sampler.
    let id = Digest::new(b"one actual original");
    let mut parent = NativeAcquisition::fixture(
        id.clone(),
        std::process::id(),
        ms(1000),
        Duration::from_secs(5),
    );
    let mut child = parent.narrow(5, ms(2000))?;
    parent.exchange_current_views(&mut child)?;
    assert_eq!(parent.remaining()?, ms(1000));
    assert_eq!(child.remaining()?, ms(1000));
    // A later, still-shorter legitimate child also meets back into the first
    // view; returning to that view cannot widen the parent's ceiling.
    let mut shorter = parent.narrow(5, ms(1500))?;
    parent.exchange_current_views(&mut shorter)?;
    parent.exchange_current_views(&mut child)?;
    assert_eq!(parent.remaining()?, ms(500));
    assert_eq!(child.remaining()?, ms(500));
    let mut parent = NativeAcquisition::fixture(
        id.clone(),
        std::process::id(),
        ms(1000),
        Duration::from_secs(5),
    );
    let mut foreign =
        NativeAcquisition::fixture(id, std::process::id(), ms(1000), Duration::from_secs(5));
    assert!(parent.exchange_current_views(&mut foreign).is_err());
    assert!(parent.sample().is_err());
    assert!(foreign.sample().is_err());
    for refuse_parent in [false, true] {
        let mut parent = NativeAcquisition::fixture(
            Digest::new(b"refusal"),
            std::process::id(),
            ms(1000),
            Duration::from_secs(5),
        );
        let mut child = parent.narrow(5, ms(4000))?;
        if refuse_parent {
            parent.refuse();
        } else {
            child.refuse();
        }
        assert!(parent.exchange_current_views(&mut child).is_err());
        assert!(parent.sample().is_err());
        assert!(child.sample().is_err());
    }
    Ok(())
}

fn self_field(expr: &syn::Expr, name: &str) -> bool {
    matches!(expr,syn::Expr::Field(f) if matches!(&f.member,syn::Member::Named(n) if n==name)
        && matches!(&*f.base,syn::Expr::Path(p) if p.path.is_ident("self")))
}

fn unparen(mut value: &syn::Expr) -> &syn::Expr {
    while let syn::Expr::Paren(p) = value {
        value = &p.expr;
    }
    value
}

fn result_body(method: &syn::ImplItemFn) -> Option<&syn::Block> {
    let syn::Stmt::Local(local) = method.block.stmts.first()? else {
        return None;
    };
    if !matches!(&local.pat,syn::Pat::Ident(p) if p.ident=="result") {
        return None;
    }
    let syn::Expr::Call(call) = unparen(&local.init.as_ref()?.expr) else {
        return None;
    };
    let syn::Expr::Closure(closure) = unparen(&call.func) else {
        return None;
    };
    let syn::Expr::Block(block) = &*closure.body else {
        return None;
    };
    Some(&block.block)
}

fn bound<'a>(body: &'a syn::Block, name: &str) -> Option<&'a syn::Expr> {
    fn selected(pat: &syn::Pat, name: &str) -> bool {
        match pat {
            syn::Pat::Ident(p) => p.ident == name,
            syn::Pat::Type(p) => selected(&p.pat, name),
            _ => false,
        }
    }
    let values: Vec<_> = body
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            syn::Stmt::Local(l) if selected(&l.pat, name) => l.init.as_ref().map(|i| &*i.expr),
            _ => None,
        })
        .collect();
    (values.len() == 1).then(|| values[0])
}

fn checked_flow(method: &syn::ImplItemFn) -> bool {
    let Some(body) = result_body(method) else {
        return false;
    };
    let Some(syn::Expr::Try(utc)) = bound(body, "utc") else {
        return false;
    };
    if !matches!(&*utc.expr,syn::Expr::Call(c) if c.args.is_empty()
        && matches!(&*c.func,syn::Expr::Path(p) if p.path.is_ident("realtime")))
    {
        return false;
    }
    for name in ["before", "after", "end"] {
        if !matches!(bound(body,name),Some(syn::Expr::Field(f))
            if matches!(&f.member,syn::Member::Named(n) if n=="elapsed")
            && matches!(&*f.base,syn::Expr::Try(t) if matches!(&*t.expr,syn::Expr::MethodCall(c)
                if c.method=="sample" && c.args.is_empty() && self_field(&c.receiver,"acquisition"))))
        {
            return false;
        }
    }
    let tuples: Vec<_> = body
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            syn::Stmt::Local(l)
                if matches!(&l.pat,syn::Pat::Tuple(p) if p.elems.len()==2
            && matches!(&p.elems[0],syn::Pat::Ident(i) if i.ident=="lower")
            && matches!(&p.elems[1],syn::Pat::Ident(i) if i.ident=="upper")) =>
            {
                Some(l)
            }
            _ => None,
        })
        .collect();
    if tuples.len() != 1 {
        return false;
    }
    let Some(init) = &tuples[0].init else {
        return false;
    };
    let syn::Expr::Try(t) = &*init.expr else {
        return false;
    };
    let syn::Expr::MethodCall(c) = &*t.expr else {
        return false;
    };
    if c.method != "observe" || !self_field(&c.receiver, "tracker") || c.args.len() != 4 {
        return false;
    }
    for (arg, name) in c.args.iter().zip(["before", "utc", "after", "end"]) {
        if !matches!(arg,syn::Expr::Path(p) if p.path.is_ident(name)) {
            return false;
        }
    }
    let Some(syn::Stmt::Expr(syn::Expr::Call(output), None)) = body.stmts.last() else {
        return false;
    };
    if !matches!(&*output.func,syn::Expr::Path(p) if p.path.is_ident("Ok"))
        || output.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Struct(data)) = output.args.first() else {
        return false;
    };
    if !data.path.is_ident("HostTimeData") || data.rest.is_some() {
        return false;
    }
    for (field, value) in [
        ("lower", "lower"),
        ("upper", "upper"),
        ("observed_at", "end"),
    ] {
        let fields: Vec<_> = data
            .fields
            .iter()
            .filter(|f| matches!(&f.member,syn::Member::Named(n) if n==field))
            .collect();
        if fields.len() != 1
            || !matches!(&fields[0].expr,syn::Expr::Path(p) if p.path.is_ident(value))
        {
            return false;
        }
    }
    matches!(method.block.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Path(p),None)) if p.path.is_ident("result"))
}

fn wiring(file: &syn::File) -> bool {
    use syn::visit::Visit;
    #[derive(Default)]
    struct Calls {
        ordered: Vec<String>,
        forbidden: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
            match &*node.expr {
                syn::Expr::MethodCall(call) if call.method == "meet_current_read_view" => {
                    if !self_field(&call.receiver, "same")
                        || call.args.len() != 2
                        || !matches!(call.args.first(),Some(syn::Expr::Path(p)) if p.path.is_ident("stage"))
                        || !matches!(call.args.last(),Some(syn::Expr::Reference(r)) if r.mutability.is_some() && self_field(&r.expr,"acquisition"))
                    {
                        self.forbidden = true;
                    }
                    self.ordered.push("meet".into());
                }
                syn::Expr::MethodCall(call) if call.method == "sample" => {
                    self.ordered.push("sample".into())
                }
                syn::Expr::Call(call) if matches!(&*call.func,syn::Expr::Path(p) if p.path.is_ident("realtime")) => {
                    self.ordered.push("realtime".into())
                }
                _ => {}
            }
            syn::visit::visit_expr_try(self, node);
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if matches!(&*node.func,syn::Expr::Path(p) if p.path.segments.iter().any(|s|s.ident=="begin"||s.ident=="begin_current"||s.ident=="fixture"))
            {
                self.forbidden = true;
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut methods = std::collections::BTreeMap::new();
    for item in &file.items {
        if let syn::Item::Impl(i) = item {
            if !matches!(&*i.self_ty,syn::Type::Path(p) if p.path.is_ident("UnfencedHostClock")) {
                continue;
            }
            for item in &i.items {
                if let syn::ImplItem::Fn(f) = item {
                    methods.insert(f.sig.ident.to_string(), f);
                }
            }
        }
    }
    let Some(observe) = methods.get("observe") else {
        return false;
    };
    let Some(capture) = methods.get("capture") else {
        return false;
    };
    let Some(shared_capture) = methods.get("capture_checked_current") else {
        return false;
    };
    let mut calls = Calls::default();
    calls.visit_block(&observe.block);
    let mut factory = Calls::default();
    factory.visit_block(&capture.block);
    factory.visit_block(&shared_capture.block);
    checked_flow(observe)
        && !calls.forbidden
        && !factory.forbidden
        && matches!(shared_capture.vis, syn::Visibility::Inherited)
        && calls.ordered == ["meet", "sample", "realtime", "sample", "meet", "sample"]
        && matches!(capture.block.stmts.first(),Some(syn::Stmt::Expr(syn::Expr::Try(t),Some(_)))
            if matches!(&*t.expr,syn::Expr::MethodCall(c) if c.method=="check_for"))
}

fn controller_method<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ImplItemFn> {
    file.items.iter().find_map(|item| {
        let syn::Item::Impl(item) = item else { return None; };
        if !matches!(&*item.self_ty, syn::Type::Path(p) if p.path.is_ident("UnfencedControllerClock")) { return None; }
        item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(f) if f.sig.ident == name => Some(f),
            _ => None,
        })
    })
}

fn is_name(value: &syn::Expr, name: &str) -> bool {
    matches!(unparen(value), syn::Expr::Path(p) if p.path.is_ident(name))
}

fn tried(value: &syn::Expr) -> Option<&syn::Expr> {
    match unparen(value) {
        syn::Expr::Try(t) => Some(&t.expr),
        _ => None,
    }
}

fn named_closure<'a>(body: &'a syn::Block, name: &str) -> Option<&'a syn::Expr> {
    let syn::Expr::Call(call) = unparen(bound(body, name)?) else {
        return None;
    };
    let syn::Expr::Closure(closure) = unparen(&call.func) else {
        return None;
    };
    Some(unparen(&closure.body))
}

fn phase_call(value: &syn::Expr, name: &str) -> bool {
    matches!(unparen(value),syn::Expr::MethodCall(c) if c.method==name && c.args.is_empty() && is_name(&c.receiver,"phase"))
}

fn returned_name(body: &syn::Block, name: &str) -> bool {
    matches!(body.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Call(c),None))
        if matches!(&*c.func,syn::Expr::Path(p) if p.path.is_ident("Ok"))
        && c.args.len()==1 && c.args.first().is_some_and(|e|is_name(e,name)))
}

fn final_refusal(method: &syn::ImplItemFn, target: &str, argument: bool) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::If(failed), None)) = method.block.stmts.iter().rev().nth(1)
    else {
        return false;
    };
    if !matches!(&*failed.cond,syn::Expr::MethodCall(c) if c.method=="is_err" && c.args.is_empty() && is_name(&c.receiver,"result"))
    {
        return false;
    }
    let Some(syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_))) =
        failed.then_branch.stmts.first()
    else {
        return false;
    };
    call.method == "refuse"
        && is_name(&call.receiver, target)
        && if argument {
            call.args.len() == 1 && call.args.first().is_some_and(|e| is_name(e, "phase"))
        } else {
            call.args.is_empty()
        }
}

fn controller_wiring(file: &syn::File) -> bool {
    let Some(capture) = controller_method(file, "capture") else {
        return false;
    };
    let Some(observe) = controller_method(file, "observe") else {
        return false;
    };
    // Each public fixed entry requires the actual physical Controller phase,
    // never a role enum, bare stage, cached scalar or caller-selected source.
    for method in [capture, observe] {
        let typed: Vec<_> = method
            .sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(arg) => Some(arg),
                _ => None,
            })
            .collect();
        let Some(arg) = typed.first() else {
            return false;
        };
        if !matches!(&*arg.pat,syn::Pat::Ident(p) if p.ident=="phase")
            || !matches!(&*arg.ty,syn::Type::Reference(r) if r.mutability.is_some()
                && matches!(&*r.elem,syn::Type::Path(p) if p.path.segments.last().is_some_and(|s|s.ident=="CurrentControllerStoragePhase")))
            || typed.len() != if method.sig.ident == "capture" { 2 } else { 1 }
        {
            return false;
        }
        if !bound(&method.block, "checked").is_some_and(|e| phase_call(e, "check")) {
            return false;
        }
        if !matches!(method.block.stmts.last(),Some(syn::Stmt::Expr(e,None)) if is_name(e,"result"))
        {
            return false;
        }
    }
    let Some(syn::Expr::Block(captured)) = named_closure(&capture.block, "captured") else {
        return false;
    };
    let Some(stage) = bound(&captured.block, "stage").and_then(tried) else {
        return false;
    };
    if !phase_call(stage, "controller_stage") {
        return false;
    }
    let Some(syn::Stmt::Expr(syn::Expr::Try(role), Some(_))) = captured.block.stmts.get(1) else {
        return false;
    };
    if !matches!(&*role.expr,syn::Expr::MethodCall(c) if c.method=="check_for"
        && is_name(&c.receiver,"stage") && c.args.len()==2
        && c.args.first().is_some_and(|e|is_name(e,"scope"))
        && matches!(c.args.last(),Some(syn::Expr::Path(p)) if p.path.segments.len()==2 && p.path.segments[0].ident=="NativeRole" && p.path.segments[1].ident=="EpochController"))
    {
        return false;
    }
    let Some(syn::Expr::Call(factory)) = bound(&captured.block, "clock").and_then(tried) else {
        return false;
    };
    if !matches!(&*factory.func,syn::Expr::Path(p) if p.path.segments.len()==2
        && p.path.segments[0].ident=="UnfencedHostClock" && p.path.segments[1].ident=="capture_checked_current")
        || factory.args.len() != 1
        || !factory.args.first().is_some_and(|e| is_name(e, "stage"))
    {
        return false;
    }
    let Some(syn::Stmt::Expr(syn::Expr::Call(output), None)) = captured.block.stmts.last() else {
        return false;
    };
    if !matches!(&*output.func,syn::Expr::Path(p) if p.path.is_ident("Ok"))
        || output.args.len() != 1
        || !matches!(output.args.first(),Some(syn::Expr::Struct(s)) if s.path.is_ident("Self") && s.rest.is_none() && s.fields.len()==1
            && s.fields.first().is_some_and(|f|matches!(&f.member,syn::Member::Named(n) if n=="clock") && is_name(&f.expr,"clock")))
    {
        return false;
    }
    let Some(syn::Expr::Block(result)) = named_closure(&capture.block, "result") else {
        return false;
    };
    if !bound(&result.block, "value")
        .and_then(tried)
        .is_some_and(|e| is_name(e, "captured"))
        || !returned_name(&result.block, "value")
    {
        return false;
    }
    let Some(syn::Stmt::Expr(syn::Expr::If(failed), None)) = result.block.stmts.get(1) else {
        return false;
    };
    if !matches!(&*failed.cond,syn::Expr::Let(l) if is_name(&l.expr,"checked")
        && matches!(&*l.pat,syn::Pat::TupleStruct(p) if p.path.is_ident("Err")))
    {
        return false;
    }
    if !matches!(failed.then_branch.stmts.first(),Some(syn::Stmt::Expr(syn::Expr::MethodCall(c),Some(_)))
        if c.method=="refuse" && c.args.is_empty()
        && matches!(&*c.receiver,syn::Expr::Field(f) if matches!(&f.member,syn::Member::Named(n) if n=="clock") && is_name(&f.base,"value")))
    {
        return false;
    }
    if !matches!(failed.then_branch.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Return(r),Some(_)))
        if matches!(r.expr.as_deref(),Some(syn::Expr::Call(c)) if matches!(&*c.func,syn::Expr::Path(p) if p.path.is_ident("Err")) && c.args.len()==1 && c.args.first().is_some_and(|e|is_name(e,"error"))))
    {
        return false;
    }
    let Some(syn::Expr::MethodCall(sample)) = named_closure(&observe.block, "observed") else {
        return false;
    };
    if sample.method != "observe"
        || !self_field(&sample.receiver, "clock")
        || sample.args.len() != 1
        || !sample
            .args
            .first()
            .and_then(tried)
            .is_some_and(|e| phase_call(e, "controller_stage"))
    {
        return false;
    }
    let Some(syn::Expr::Block(result)) = named_closure(&observe.block, "result") else {
        return false;
    };
    if !bound(&result.block, "value")
        .and_then(tried)
        .is_some_and(|e| is_name(e, "observed"))
        || !matches!(result.block.stmts.get(1),Some(syn::Stmt::Expr(syn::Expr::Try(t),Some(_))) if is_name(&t.expr,"checked"))
        || !returned_name(&result.block, "value")
    {
        return false;
    }
    // Both calls must execute before either Result is propagated. Moving the
    // physical check into the result closure would skip it on sample refusal.
    final_refusal(capture, "phase", false)
        && final_refusal(observe, "self", true)
        && local_index(&capture.block, "captured") < local_index(&capture.block, "checked")
        && local_index(&capture.block, "checked") < local_index(&capture.block, "result")
        && local_index(&observe.block, "observed") < local_index(&observe.block, "checked")
        && local_index(&observe.block, "checked") < local_index(&observe.block, "result")
}

#[test]
fn actual_controller_factory_retains_its_physical_phase_and_actual_sample_results() -> Result<()> {
    let source = include_str!("../restore_host_clock.rs");
    assert!(controller_wiring(&syn::parse_file(source)?));
    for (from, to) in [
        (
            "stage.check_for(scope, NativeRole::EpochController)?;",
            "stage.check_for(scope, NativeRole::AppHost)?;",
        ),
        (
            "let stage = phase.controller_stage()?;",
            "let stage = phase.controller_stage();",
        ),
        (
            "UnfencedHostClock::capture_checked_current(stage)?",
            "UnfencedHostClock::capture(stage, scope)?",
        ),
        (
            "self.clock.observe(phase.controller_stage()?)",
            "self.clock.observe(phase.controller_stage())",
        ),
        (
            "let value = observed?;",
            "let value = observed.unwrap_or(HostTimeData { domain: Digest::new(b\"forged\"), lower: Duration::ZERO, upper: Duration::ZERO, observed_at: Duration::ZERO });",
        ),
    ] {
        assert_eq!(source.matches(from).count(), 1, "actual mutation target");
        assert!(
            !controller_wiring(&syn::parse_file(&source.replacen(from, to, 1))?),
            "{from}"
        );
    }
    assert_eq!(source.matches("let checked = phase.check();").count(), 2);
    for selected in 0..2 {
        let positions: Vec<_> = source
            .match_indices("let checked = phase.check();")
            .map(|p| p.0)
            .collect();
        let mut changed = source.to_owned();
        let start = positions[selected];
        changed.replace_range(
            start..start + "let checked = phase.check();".len(),
            "let checked = Ok::<(), anyhow::Error>(());",
        );
        assert!(!controller_wiring(&syn::parse_file(&changed)?));
    }
    Ok(())
}

fn unparen_mut(value: &mut syn::Expr) -> &mut syn::Expr {
    match value {
        syn::Expr::Paren(p) => unparen_mut(&mut p.expr),
        _ => value,
    }
}

fn observed_body_mut(file: &mut syn::File) -> &mut syn::Block {
    for item in &mut file.items {
        let syn::Item::Impl(i) = item else {
            continue;
        };
        if !matches!(&*i.self_ty,syn::Type::Path(p) if p.path.is_ident("UnfencedHostClock")) {
            continue;
        }
        for member in &mut i.items {
            let syn::ImplItem::Fn(method) = member else {
                continue;
            };
            if method.sig.ident != "observe" {
                continue;
            }
            let syn::Stmt::Local(local) = method.block.stmts.first_mut().expect("result") else {
                panic!("result local");
            };
            let syn::Expr::Call(call) =
                unparen_mut(&mut local.init.as_mut().expect("result init").expr)
            else {
                panic!("actual closure call");
            };
            let syn::Expr::Closure(closure) = unparen_mut(&mut call.func) else {
                panic!("actual closure");
            };
            let syn::Expr::Block(body) = &mut *closure.body else {
                panic!("actual body");
            };
            return &mut body.block;
        }
    }
    panic!("actual production observe method missing");
}

fn local_index(body: &syn::Block, name: &str) -> usize {
    let indexes: Vec<_> = body.stmts.iter().enumerate().filter_map(|(index,stmt)| {
        matches!(stmt,syn::Stmt::Local(l) if matches!(&l.pat,syn::Pat::Ident(p) if p.ident==name)).then_some(index)
    }).collect();
    assert_eq!(indexes.len(), 1, "one actual binding {name}");
    indexes[0]
}

#[test]
fn production_sampler_uses_actual_same_original_and_actual_clock_results() -> Result<()> {
    let file = syn::parse_file(include_str!("../restore_host_clock.rs"))?;
    assert!(wiring(&file));
    for target in [0, 1] {
        let mut mutant = file.clone();
        let body = observed_body_mut(&mut mutant);
        let indexes:Vec<_>=body.stmts.iter().enumerate().filter_map(|(index,stmt)| {
            matches!(stmt,syn::Stmt::Expr(syn::Expr::Try(t),Some(_)) if matches!(&*t.expr,syn::Expr::MethodCall(c) if c.method=="meet_current_read_view")).then_some(index)
        }).collect();
        assert_eq!(indexes.len(), 2);
        body.stmts[indexes[target]] = syn::parse_quote!(self.acquisition.sample()?;);
        assert!(!wiring(&mutant));
    }
    let mut mutant = file;
    let body = observed_body_mut(&mut mutant);
    let index = local_index(body, "utc");
    let syn::Stmt::Local(local) = &mut body.stmts[index] else {
        panic!("actual utc local");
    };
    *local.init.as_mut().expect("actual UTC init").expr =
        syn::parse_quote!(Duration::from_secs(123));
    assert!(!wiring(&mutant));
    Ok(())
}

#[test]
fn production_guard_rejects_discarded_real_reads_and_checked_results() -> Result<()> {
    let file = syn::parse_file(include_str!("../restore_host_clock.rs"))?;
    for kind in 0..3 {
        let mut mutant = file.clone();
        let body = observed_body_mut(&mut mutant);
        let (index, replacements): (_, Vec<syn::Stmt>) = match kind {
            0 => (
                local_index(body, "utc"),
                vec![
                    syn::parse_quote!(let _observed = realtime()?;),
                    syn::parse_quote!(let utc = Duration::from_secs(123);),
                ],
            ),
            1 => (
                local_index(body, "before"),
                vec![
                    syn::parse_quote!(let _observed = self.acquisition.sample()?.elapsed;),
                    syn::parse_quote!(let before = Duration::ZERO;),
                ],
            ),
            _ => {
                let indexes:Vec<_>=body.stmts.iter().enumerate().filter_map(|(index,stmt)| {
                    matches!(stmt,syn::Stmt::Local(l) if matches!(&l.pat,syn::Pat::Tuple(p) if p.elems.len()==2
                        && matches!(&p.elems[0],syn::Pat::Ident(i) if i.ident=="lower")
                        && matches!(&p.elems[1],syn::Pat::Ident(i) if i.ident=="upper"))).then_some(index)
                }).collect();
                assert_eq!(indexes.len(), 1);
                (
                    indexes[0],
                    vec![
                        syn::parse_quote!(let _checked = self.tracker.observe(before,utc,after,end)?;),
                        syn::parse_quote!(let (lower,upper) = (Duration::ZERO,Duration::ZERO);),
                    ],
                )
            }
        };
        body.stmts.splice(index..=index, replacements);
        assert!(!wiring(&mutant), "discard {kind}");
    }
    let mut mutant = file;
    let body = observed_body_mut(&mut mutant);
    let syn::Stmt::Expr(syn::Expr::Call(output), None) =
        body.stmts.last_mut().expect("actual return")
    else {
        panic!("actual Ok");
    };
    let Some(syn::Expr::Struct(data)) = output.args.first_mut() else {
        panic!("actual returned data");
    };
    assert!(data.path.is_ident("HostTimeData"));
    let mut changed = 0;
    for field in &mut data.fields {
        if matches!(&field.member,syn::Member::Named(n) if n=="lower") {
            field.expr = syn::parse_quote!(Duration::ZERO);
            changed += 1;
        }
    }
    assert_eq!(changed, 1);
    assert!(!wiring(&mutant));
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_never_substitutes_wall_or_replay_time() {
    assert!(realtime().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_leaf_reads_real_kernel_realtime_without_claiming_an_enrolled_owner() -> Result<()> {
    let value = realtime()?;
    assert!(value.as_secs() > 0);
    Ok(())
}
