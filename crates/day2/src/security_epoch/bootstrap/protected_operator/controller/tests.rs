//! No native peer/role/action fixture is constructed by these controls.
use super::*;
use quote::ToTokens;

fn method(name: &str) -> syn::ImplItemFn {
    let file = syn::parse_file(include_str!("../controller.rs")).unwrap();
    file.items.iter().find_map(|item| {
        let syn::Item::Impl(item) = item else { return None; };
        if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("ProtectedRestoreSession")) { return None; }
        item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item.clone()),
            _ => None,
        })
    }).unwrap()
}

fn expression(actual: &syn::Expr, expected: &str) -> bool {
    let expected: syn::Expr = syn::parse_str(expected).unwrap();
    fn same(left: &syn::Expr, right: &syn::Expr) -> bool {
        fn unblocked(value: &syn::Expr) -> &syn::Expr {
            if let syn::Expr::Block(value) = value
                && value.attrs.is_empty()
                && value.label.is_none()
                && let [syn::Stmt::Expr(expression, None)] = value.block.stmts.as_slice()
            {
                return expression;
            }
            value
        }
        let (left, right) = (unblocked(left), unblocked(right));
        // Only typed argument/field separators may have a trailing comma.
        // Opaque macros and every operator retain exact token jointness.
        match (left, right) {
            (syn::Expr::Try(left), syn::Expr::Try(right))
                if left.attrs.is_empty() && right.attrs.is_empty() =>
            {
                same(&left.expr, &right.expr)
            }
            (syn::Expr::Call(left), syn::Expr::Call(right))
                if left.attrs.is_empty() && right.attrs.is_empty() =>
            {
                same(&left.func, &right.func)
                    && left.args.len() == right.args.len()
                    && left
                        .args
                        .iter()
                        .zip(&right.args)
                        .all(|(left, right)| same(left, right))
            }
            (syn::Expr::MethodCall(left), syn::Expr::MethodCall(right))
                if left.attrs.is_empty() && right.attrs.is_empty() =>
            {
                same(&left.receiver, &right.receiver)
                    && left.method == right.method
                    && left.turbofish.to_token_stream().to_string()
                        == right.turbofish.to_token_stream().to_string()
                    && left.args.len() == right.args.len()
                    && left
                        .args
                        .iter()
                        .zip(&right.args)
                        .all(|(left, right)| same(left, right))
            }
            (syn::Expr::Struct(left), syn::Expr::Struct(right))
                if left.attrs.is_empty()
                    && right.attrs.is_empty()
                    && left.rest.is_none()
                    && right.rest.is_none() =>
            {
                left.qself.is_none()
                    && right.qself.is_none()
                    && left.path.to_token_stream().to_string()
                        == right.path.to_token_stream().to_string()
                    && left.fields.len() == right.fields.len()
                    && left.fields.iter().zip(&right.fields).all(|(left, right)| {
                        left.attrs.is_empty()
                            && right.attrs.is_empty()
                            && left.member.to_token_stream().to_string()
                                == right.member.to_token_stream().to_string()
                            && same(&left.expr, &right.expr)
                    })
            }
            (syn::Expr::Assign(left), syn::Expr::Assign(right))
                if left.attrs.is_empty() && right.attrs.is_empty() =>
            {
                same(&left.left, &right.left) && same(&left.right, &right.right)
            }
            (syn::Expr::Tuple(left), syn::Expr::Tuple(right))
                if left.attrs.is_empty() && right.attrs.is_empty() =>
            {
                left.elems.len() == right.elems.len()
                    && left
                        .elems
                        .iter()
                        .zip(&right.elems)
                        .all(|(left, right)| same(left, right))
            }
            (syn::Expr::Closure(left), syn::Expr::Closure(right)) => {
                let mut a = left.clone();
                let mut b = right.clone();
                *a.body = syn::parse_quote!(());
                *b.body = syn::parse_quote!(());
                a.to_token_stream().to_string() == b.to_token_stream().to_string()
                    && same(&left.body, &right.body)
            }
            _ => left.to_token_stream().to_string() == right.to_token_stream().to_string(),
        }
    }
    same(actual, &expected)
}

fn current_turn_is_retained(body: &syn::Block) -> bool {
    let [
        syn::Stmt::Local(data),
        syn::Stmt::Expr(terminal, Some(_)),
        syn::Stmt::Local(request),
        syn::Stmt::Local(stage),
        syn::Stmt::Local(local),
        syn::Stmt::Expr(syn::Expr::Return(returned), Some(_)),
    ] = body.stmts.as_slice()
    else {
        return false;
    };
    if data.pat.to_token_stream().to_string() != "(id , assertion)"
        || data.init.as_ref().is_none_or(|init| !expression(&init.expr, "(id.clone(), assertion.clone())"))
        || !expression(terminal, "self.terminal = true")
        || request.pat.to_token_stream().to_string() != "request"
        || request.init.as_ref().is_none_or(|init| !expression(&init.expr, "self.request.take().expect(\"same saved request\")"))
        || stage.pat.to_token_stream().to_string() != "stage"
        || stage.init.as_ref().is_none_or(|init| !expression(&init.expr, "turn.take_accepting_stage(request, role)?"))
        || local.pat.to_token_stream().to_string() != "archive"
        || local.init.as_ref().is_none_or(|init| init.diverge.is_some() || !expression(&init.expr, "self.commands.authenticate_archive(&id, &assertion, active, stage, metadata, trace)?")) { return false; }
    returned.expr.as_ref().is_some_and(|value| {
        expression(
            value,
            "Ok(Some(PreparedProtectedRestore { archive, turn, attempt }))",
        )
    })
}

#[test]
fn actual_acceptance_keeps_the_genuine_peer_and_a_new_empty_registry_in_one_session() {
    let source = syn::parse_file(include_str!("../controller.rs")).unwrap();
    let item = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "ProtectedRestoreSession" => Some(item),
            _ => None,
        })
        .unwrap();
    let fields = item
        .fields
        .iter()
        .map(|field| {
            assert!(matches!(field.vis, syn::Visibility::Inherited));
            (
                field.ident.as_ref().unwrap().to_string(),
                field.ty.to_token_stream().to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [
            ("peer".into(), "ProtectedRestorePeer".into()),
            ("request".into(), "Option < EnrolledCurrentRequest >".into()),
            ("terminal".into(), "bool".into()),
            ("commands".into(), "ProtectedRestoreCommands".into())
        ]
    );
    let actual = method("try_accept");
    let expected: syn::Block = syn::parse_quote!({
        if !listener.pending()? {
            return Ok(None);
        }
        let peer = listener.accept(role)?;
        Ok(Some(Self {
            peer,
            request: None,
            terminal: false,
            commands: ProtectedRestoreCommands::new(),
        }))
    });
    let guarded = |body: &syn::Block| {
        body.to_token_stream().to_string() == expected.to_token_stream().to_string()
    };
    assert!(guarded(&actual.block));
    let expected_type: syn::ReturnType = syn::parse_quote!(-> Result<Option<Self>>);
    assert_eq!(
        actual.sig.output.to_token_stream().to_string(),
        expected_type.to_token_stream().to_string()
    );
    for index in 0..expected.stmts.len() {
        let mut removed = actual.block.clone();
        removed.stmts.remove(index);
        assert!(!guarded(&removed));
    }
    let mut early_action = actual.block.clone();
    early_action.stmts.swap(0, 1);
    assert!(!guarded(&early_action));
    let mut readiness_as_owner = actual.block.clone();
    readiness_as_owner.stmts[1] = syn::parse_quote!(let peer = listener.pending()?;);
    assert!(!guarded(&readiness_as_owner));
    let mut foreign = actual.block.clone();
    foreign.stmts[1] = syn::parse_quote!(let peer = other.accept(role)?;);
    assert!(!guarded(&foreign));
}

fn poll_guarded(body: &syn::Block) -> bool {
    use syn::visit::Visit;
    #[derive(Default)]
    struct Calls {
        methods: Vec<syn::ExprMethodCall>,
        functions: Vec<syn::ExprCall>,
        settled_writes: usize,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_assign(&mut self, item: &'ast syn::ExprAssign) {
            if expression(&item.left, "attempt.settled") {
                self.settled_writes += 1;
            }
            syn::visit::visit_expr_assign(self, item);
        }
        fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
            syn::visit::visit_expr_method_call(self, item);
            self.methods.push(item.clone());
        }
        fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
            syn::visit::visit_expr_call(self, item);
            self.functions.push(item.clone());
        }
    }
    let mut calls = Calls::default();
    calls.visit_block(body);
    let exact_method = |text: &str| {
        calls
            .methods
            .iter()
            .filter(|item| expression(&syn::Expr::MethodCall((*item).clone()), text))
            .count()
    };
    if calls.settled_writes != 1
        || exact_method("self.peer.retained_refusal()") != 1
        || exact_method("self.peer.require_owner(role)") != 1
        || exact_method("self.peer.pending()") != 1
        || exact_method("role.begin_current_request()") != 1
        || exact_method("self.request.as_ref().expect(\"actual saved request\").consumer_origin()")
            != 1
        || exact_method("self.peer.try_receive(&mut stage)") != 1
        || exact_method("role.borrow_current_request(request)") != 1
        || exact_method(
            "role.borrow_current_request(self.request.as_mut().expect(\"same saved request\"))",
        ) != 3
        || calls
            .methods
            .iter()
            .any(|call| call.method == "begin_current_stage")
    {
        return false;
    }
    let index = |method: &str| {
        calls
            .methods
            .iter()
            .position(|call| call.method == method)
            .unwrap()
    };
    if !(index("retained_refusal") < index("require_owner")
        && index("require_owner") < index("pending")
        && index("pending") < index("begin_current_request")
        && index("begin_current_request") < index("consumer_origin")
        && index("consumer_origin") < index("try_receive"))
    {
        return false;
    }
    let Some(syn::Stmt::Local(first)) = body.stmts.first() else {
        return false;
    };
    if first.pat.to_token_stream().to_string() != "mut attempt"
        || first.init.as_ref().is_none_or(|init| {
            !expression(
                &init.expr,
                "Attempt { peer: self.peer.retained_refusal(), original: None, settled: false }",
            )
        })
    {
        return false;
    }
    let top_assignment = |text: &str| {
        body.stmts.iter().position(|statement| matches!(statement, syn::Stmt::Expr(actual, Some(_)) if expression(actual, text)))
    };
    let Some(captured) = top_assignment("self.request = Some(role.begin_current_request()?)")
    else {
        return false;
    };
    let Some(negative) = top_assignment(
        "attempt.original = Some(self.request.as_ref().expect(\"actual saved request\").consumer_origin())",
    ) else {
        return false;
    };
    let Some(receive) = body.stmts.iter().position(|statement| matches!(statement, syn::Stmt::Local(local) if local.pat.to_token_stream().to_string() == "mut turn")) else { return false; };
    if !(captured < negative
        && negative < receive
        && index("consumer_origin") < index("borrow_current_request"))
    {
        return false;
    }
    let Some(terminal_index) = body.stmts.iter().position(|statement| matches!(statement, syn::Stmt::Expr(syn::Expr::If(branch), _) if expression(&branch.cond, "self.terminal"))) else { return false; };
    let Some(capture_index) = top_assignment("self.request = Some(role.begin_current_request()?)")
    else {
        return false;
    };
    if terminal_index >= capture_index {
        return false;
    }
    let Some((preflight_index, preflight)) =
        body.stmts
            .iter()
            .enumerate()
            .find_map(|(index, statement)| match statement {
                syn::Stmt::Expr(syn::Expr::If(item), None)
                    if expression(
                        &item.cond,
                        "!matches_pending(&self.commands, turn.request_data())",
                    ) =>
                {
                    Some((index, item))
                }
                _ => None,
            })
    else {
        return false;
    };
    let Some((dispatch_index, dispatch)) =
        body.stmts
            .iter()
            .enumerate()
            .find_map(|(index, statement)| {
                let syn::Stmt::Local(local) = statement else {
                    return None;
                };
                let syn::Expr::Match(item) = &*local.init.as_ref()?.expr else {
                    return None;
                };
                Some((index, item))
            })
    else {
        return false;
    };
    let Some((accept_index, accepted)) =
        body.stmts
            .iter()
            .enumerate()
            .find_map(|(index, statement)| {
                let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
                    return None;
                };
                let syn::Expr::Let(selected) = &*branch.cond else {
                    return None;
                };
                let syn::Pat::Struct(pattern) = &*selected.pat else {
                    return None;
                };
                if pattern.path.segments.last()?.ident != "Authenticate"
                    || !expression(&selected.expr, "turn.request_data()")
                {
                    return None;
                }
                Some((index, &branch.then_branch))
            })
    else {
        return false;
    };
    if !(preflight_index < accept_index && accept_index < dispatch_index)
        || !current_turn_is_retained(accepted)
        || preflight.else_branch.is_some()
        || !expression(&dispatch.expr, "turn.request_data()")
        || dispatch.arms.len() != 5
    {
        return false;
    }
    for (arm, name) in dispatch.arms.iter().zip([
        "BeginApproval",
        "Approve",
        "BeginExecution",
        "Authenticate",
        "Abandon",
    ]) {
        let syn::Pat::Struct(pattern) = &arm.pat else {
            return false;
        };
        if pattern
            .path
            .segments
            .last()
            .is_none_or(|last| last.ident != name)
            || arm.guard.is_some()
        {
            return false;
        }
        if name == "Authenticate"
            && !expression(&arm.body, "unreachable!(\"terminal branch returned\")")
        {
            return false;
        }
    }
    let idle = body.stmts.iter().find_map(|statement| match statement {
        syn::Stmt::Expr(syn::Expr::If(branch), _)
            if expression(&branch.cond, "!self.peer.pending()?") =>
        {
            Some(branch)
        }
        _ => None,
    });
    let Some(idle) = idle else {
        return false;
    };
    let idle_expected: syn::Block =
        syn::parse_str("{ attempt.settled = true; return Ok(None); }").unwrap();
    if idle.else_branch.is_some()
        || idle.then_branch.to_token_stream().to_string()
            != idle_expected.to_token_stream().to_string()
    {
        return false;
    }
    let free = |name: &str| {
        calls
            .functions
            .iter()
            .filter(|call| matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident(name)))
            .collect::<Vec<_>>()
    };
    let replies = free("reply");
    let finishes = free("finish");
    replies.len() == 2
        && finishes.len() == 2
        && expression(
            &syn::Expr::Call(replies[0].clone()),
            "reply(turn, stage, ProtectedRestoreReply::Refused)",
        )
        && expression(
            &syn::Expr::Call(replies[1].clone()),
            "reply(turn, stage, data)",
        )
        && finishes.iter().all(|call| {
            expression(
                &syn::Expr::Call((*call).clone()),
                "finish(&mut self.request, role, &mut attempt)",
            )
        })
}

#[test]
fn actual_poll_keeps_one_saved_original_and_retains_the_whole_accepting_turn() {
    let actual = method("poll");
    assert!(poll_guarded(&actual.block));
    for (from, to) in [
        ("role.begin_current_request()", "role.begin_current_stage()"),
        (
            "self.request.as_ref().expect(\"actual saved request\").consumer_origin()",
            "other.consumer_origin()",
        ),
        (
            "self.peer.try_receive(&mut stage)",
            "self.peer.try_receive(&mut other)",
        ),
        (
            "self.commands.authenticate_archive(&id, &assertion, active, stage, metadata, trace)",
            "self.commands.authenticate_archive(&id, &assertion, active, role.begin_current_stage()?, metadata, trace)",
        ),
    ] {
        use syn::visit::Visit;
        struct Target<'a> {
            expected: &'a str,
            matches: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Target<'_> {
            fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
                if expression(&syn::Expr::MethodCall(item.clone()), self.expected) {
                    self.matches.push(item.to_token_stream().to_string());
                }
                syn::visit::visit_expr_method_call(self, item);
            }
        }
        let mut target = Target {
            expected: from,
            matches: Vec::new(),
        };
        target.visit_block(&actual.block);
        assert_eq!(target.matches.len(), 1, "actual mutation target {from}");
        let source = actual.block.to_token_stream().to_string();
        let replacement: syn::Expr = syn::parse_str(to).unwrap();
        let changed = syn::parse_str(&source.replacen(
            &target.matches[0],
            &replacement.to_token_stream().to_string(),
            1,
        ))
        .unwrap();
        assert!(!poll_guarded(&changed), "accepted {from}");
    }
    for to in [
        "archive , turn : other_turn , attempt",
        "archive , turn , attempt : other_attempt",
    ] {
        let source = actual.block.to_token_stream().to_string();
        assert_eq!(source.matches("archive , turn , attempt").count(), 1);
        let changed = syn::parse_str(&source.replacen("archive , turn , attempt", to, 1)).unwrap();
        assert!(!poll_guarded(&changed));
    }
    let mut renewed = actual.block.clone();
    renewed
        .stmts
        .insert(0, syn::parse_quote!(let _ = role.begin_current_request()?;));
    assert!(!poll_guarded(&renewed));
    for index in [1, actual.block.stmts.len() - 2] {
        let mut disarmed = actual.block.clone();
        disarmed
            .stmts
            .insert(index, syn::parse_quote!(attempt.settled = true;));
        assert!(!poll_guarded(&disarmed), "early disarm at {index}");
    }
}

#[test]
fn expression_oracle_ignores_only_typed_separators_and_keeps_opaque_compound_operators() {
    let actual: syn::Expr = syn::parse_str("owner.check(a, b,)").unwrap();
    assert!(expression(&actual, "owner.check(a, b)"));
    assert!(!expression(&actual, "other.check(a, b)"));
    assert!(!expression(&actual, "owner.check(b, a)"));
    assert!(expression(
        &syn::parse_str("sink = Some(owner.check(a,),)").unwrap(),
        "sink = Some(owner.check(a))"
    ));
    assert!(expression(
        &syn::parse_str("|| { owner.check(a,) }").unwrap(),
        "|| owner.check(a)"
    ));
    assert!(!expression(
        &syn::parse_str("|| { side_effect(); owner.check(a) }").unwrap(),
        "|| owner.check(a)"
    ));
    assert!(!expression(&syn::parse_str("(a,)").unwrap(), "(a)"));
    assert!(!expression(&syn::parse_str("(a,b)").unwrap(), "(a,b,c)"));
    let compound: syn::Expr = syn::parse_str("ensure!(true&&true, \"profile\")").unwrap();
    assert!(!expression(&compound, "ensure!(true & &true, \"profile\")"));
}

#[test]
fn already_observed_reply_errors_and_panics_keep_the_actual_primary() {
    struct Primary;
    impl std::fmt::Debug for Primary {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign Debug")
        }
    }
    impl std::fmt::Display for Primary {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign Display")
        }
    }
    impl std::error::Error for Primary {}
    let error = anyhow::Error::new(Primary);
    let actual = error.downcast_ref::<Primary>().unwrap() as *const Primary;
    let refused = observed(Ok(Err(error)), Ok(Err(anyhow::anyhow!("post refused"))));
    assert_eq!(
        refused.unwrap_err().downcast_ref::<Primary>().unwrap() as *const Primary,
        actual
    );
    assert!(observed(Ok(Ok(())), Ok(Err(anyhow::anyhow!("post refused")))).is_err());
    assert!(observed(Ok(Ok(())), Ok(Ok(()))).is_ok());
    let panic = std::panic::catch_unwind(|| observed(Err(Box::new(17u8)), Err(Box::new(29u8))));
    assert_eq!(*panic.unwrap_err().downcast::<u8>().unwrap(), 17);
    let panic = std::panic::catch_unwind(|| observed(Ok(Ok(())), Err(Box::new(29u8))));
    assert_eq!(*panic.unwrap_err().downcast::<u8>().unwrap(), 29);
}

#[test]
fn actual_attempt_drop_poison_is_armed_for_errors_unwind_and_unfinished_accepting_work() {
    let source = syn::parse_file(include_str!("../controller.rs")).unwrap();
    let actual = source
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Attempt"))
                || item
                    .trait_
                    .as_ref()
                    .is_none_or(|(_, path, _)| !path.is_ident("Drop"))
            {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "drop" => Some(item),
                _ => None,
            })
        })
        .unwrap();
    let expected: syn::Block = syn::parse_str("{ if !self.settled { self.peer.refuse(); if let Some(original) = &self.original { original.refuse(); } } }").unwrap();
    let guarded = |body: &syn::Block| {
        body.to_token_stream().to_string() == expected.to_token_stream().to_string()
    };
    assert!(guarded(&actual.block));
    assert!(!guarded(&syn::parse_quote!({})));
    for source in [
        "{ if !self.settled { if let Some(original) = &self.original { original.refuse(); } } }",
        "{ if !self.settled { self.peer.refuse(); } }",
        "{ if self.settled { self.peer.refuse(); if let Some(original) = &self.original { original.refuse(); } } }",
        "{ if !self.settled { other_peer.refuse(); if let Some(original) = &self.original { original.refuse(); } } }",
    ] {
        assert!(!guarded(&syn::parse_str(source).unwrap()));
    }
    // This is actual-source/refusal wiring evidence, not a scalar fake native
    // owner. The poll oracle requires an EXECUTED top-level original assignment
    // before first receive, and retains Attempt in the accepting return; the
    // finish oracle allows disarm only after genuine request.finish succeeds.
    let actual = method("poll");
    assert!(poll_guarded(&actual.block));
    let source = actual.block.to_token_stream().to_string();
    let index = actual.block.stmts.iter().position(|statement| matches!(statement, syn::Stmt::Expr(syn::Expr::Assign(item), Some(_)) if expression(&item.left, "attempt.original"))).unwrap();
    let mut missing = actual.block.clone();
    missing.stmts.remove(index);
    assert!(!poll_guarded(&missing));
    let mut dead = actual.block.clone();
    let assignment = &actual.block.stmts[index];
    dead.stmts[index] = syn::parse_quote!(let _unused = || { #assignment };);
    assert!(!poll_guarded(&dead));
    assert_eq!(source.matches("archive , turn , attempt").count(), 1);
}

#[test]
fn fixed_reply_observes_post_even_on_failure_and_only_actual_finish_disarms_the_attempt() {
    let source = syn::parse_file(include_str!("../controller.rs")).unwrap();
    let function = |name: &str| {
        source
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
            .unwrap()
    };
    let actual = function("reply");
    let guarded = |body: &syn::Block| {
        let [
            syn::Stmt::Local(requested),
            syn::Stmt::Local(post),
            syn::Stmt::Expr(tail, None),
        ] = body.stmts.as_slice()
        else {
            return false;
        };
        requested.pat.to_token_stream().to_string() == "requested"
            && requested.init.as_ref().is_some_and(|init| expression(&init.expr, "std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| turn.reply(&mut stage, data)))"))
            && post.pat.to_token_stream().to_string() == "post"
            && post.init.as_ref().is_some_and(|init| expression(&init.expr, "std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()))"))
            && expression(tail, "observed(requested, post)")
    };
    assert!(guarded(&actual.block));
    for index in 0..actual.block.stmts.len() {
        let mut removed = actual.block.clone();
        removed.stmts.remove(index);
        assert!(!guarded(&removed));
    }
    let mut short_circuit = actual.block.clone();
    short_circuit.stmts[0] = syn::parse_quote!(let requested = turn.reply(&mut stage, data)?;);
    assert!(!guarded(&short_circuit));
    let actual = function("finish");
    let guarded = |body: &syn::Block| {
        let [
            syn::Stmt::Expr(finished, Some(_)),
            syn::Stmt::Expr(settled, Some(_)),
            syn::Stmt::Expr(tail, None),
        ] = body.stmts.as_slice()
        else {
            return false;
        };
        expression(
            finished,
            "request.take().context(\"protected_restore_saved_request_missing\")?.finish(role)?",
        ) && expression(settled, "attempt.settled = true")
            && expression(tail, "Ok(())")
    };
    assert!(guarded(&actual.block));
    let mut early = actual.block.clone();
    early.stmts.swap(0, 1);
    assert!(!guarded(&early));
    for index in 0..2 {
        let mut removed = actual.block.clone();
        removed.stmts.remove(index);
        assert!(!guarded(&removed));
    }
}

#[test]
fn missing_and_malformed_data_never_select_a_native_action_or_create_pending_material() {
    let commands = ProtectedRestoreCommands::new();
    let id = day2_capabilities::Digest::new(b"unknown locator DATA");
    for request in [
        ProtectedRestoreRequest::BeginApproval {
            input: b"{\"approved\":true}".to_vec(),
        },
        ProtectedRestoreRequest::Approve {
            id: id.clone(),
            assertion: vec![0],
        },
        ProtectedRestoreRequest::BeginExecution { id: id.clone() },
        ProtectedRestoreRequest::Authenticate {
            id: id.clone(),
            assertion: vec![0],
        },
        ProtectedRestoreRequest::Abandon { id },
    ] {
        assert!(!matches_pending(&commands, &request));
        assert!(commands.slot.current.is_none());
        assert!(commands.slot.seen.is_empty());
    }
}

#[test]
fn actual_accepting_carrier_consumes_archive_turn_and_attempt_without_a_callback_or_parts() {
    let file = syn::parse_file(include_str!("../controller.rs")).unwrap();
    let selected = |owner: &str, name: &str| {
        let all=file.items.iter().filter_map(|item|{
            let syn::Item::Impl(item)=item else{return None;};
            if item.trait_.is_some() || !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|s|s.ident==owner)){return None;}
            item.items.iter().find_map(|item|match item{syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(method.clone()),_=>None})
        }).collect::<Vec<_>>();
        assert_eq!(all.len(), 1);
        all.into_iter().next().unwrap()
    };
    let run = selected("PreparedProtectedRestore", "run");
    assert_eq!(run.sig.inputs.len(), 1);
    assert!(
        matches!(&run.sig.inputs[0],syn::FnArg::Receiver(receiver) if receiver.reference.is_none())
    );
    // Only a named-field pattern's optional trailing comma is irrelevant.
    // Preserve its path/qself, attributes, field order/bindings and rest marker.
    fn carrier_pattern(pattern: &syn::Pat) -> bool {
        let syn::Pat::Struct(mut actual) = pattern.clone() else {
            return false;
        };
        actual.fields.pop_punct();
        let expected: syn::Pat = syn::parse_quote!(Self {
            archive,
            turn,
            attempt
        });
        actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }
    assert!(carrier_pattern(&syn::parse_quote!(Self {
        archive,
        turn,
        attempt
    })));
    assert!(carrier_pattern(&syn::parse_quote!(Self {
        archive,
        turn,
        attempt,
    })));
    for pattern in [
        syn::parse_quote!(Other {
            archive,
            turn,
            attempt
        }),
        syn::parse_quote!(Self {
            archive,
            turn,
            attempt,
            ..
        }),
        syn::parse_quote!(Self {
            archive,
            turn,
            attempt,
            extra
        }),
        syn::parse_quote!(Self { archive, turn }),
        syn::parse_quote!(Self {
            archive: foreign,
            turn,
            attempt
        }),
        syn::parse_quote!(Self { ref archive, turn, attempt }),
        syn::parse_quote!(Self {
            turn,
            archive,
            attempt
        }),
        syn::parse_quote!(Self {
            #[cfg(any())]
            archive,
            turn,
            attempt
        }),
        syn::parse_quote!((archive, turn, attempt)),
    ] {
        assert!(!carrier_pattern(&pattern));
    }
    let guarded = |body: &syn::Block| {
        let [syn::Stmt::Local(parts), syn::Stmt::Expr(tail, None)] = body.stmts.as_slice() else {
            return false;
        };
        carrier_pattern(&parts.pat)
            && parts
                .init
                .as_ref()
                .is_some_and(|init| init.diverge.is_none() && expression(&init.expr, "self"))
            && expression(tail, "archive.run_protected(turn,attempt)")
    };
    assert!(guarded(&run.block));
    for changed in [
        syn::parse_quote!({
            let Self {
                archive,
                turn,
                attempt,
            } = self;
            archive.run_protected(other_turn, attempt)
        }),
        syn::parse_quote!({
            let Self {
                archive,
                turn,
                attempt,
            } = self;
            archive.run_protected(turn, other_attempt)
        }),
        syn::parse_quote!({
            let Self {
                archive,
                turn,
                attempt,
            } = self;
            Ok(())
        }),
        syn::parse_quote!({
            let Self {
                archive,
                turn,
                attempt,
            } = self;
            attempt.settled = true;
            archive.run_protected(turn, attempt)
        }),
    ] {
        assert!(!guarded(&changed));
    }
    let serve = selected("Attempt", "serve_installed");
    assert_eq!(serve.sig.inputs.len(), 2);
    assert!(
        matches!(&serve.sig.inputs[0],syn::FnArg::Receiver(receiver) if receiver.reference.is_none() && receiver.mutability.is_some())
    );
    let syn::FnArg::Typed(installation) = &serve.sig.inputs[1] else {
        panic!("whole actual retired carrier");
    };
    let syn::Type::Path(path) = &*installation.ty else {
        panic!("whole owner type");
    };
    assert_eq!(
        path.path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>(),
        [
            "crate",
            "security_epoch",
            "bootstrap",
            "RetiredControllerCurrentInstallation"
        ]
    );
    let syn::PathArguments::AngleBracketed(args) = &path.path.segments.last().unwrap().arguments
    else {
        panic!("all seven lifetimes");
    };
    assert_eq!(args.args.len(), 7);
    assert!(
        args.args
            .iter()
            .all(|arg| matches!(arg, syn::GenericArgument::Lifetime(_)))
    );
    let settle = |body: &syn::Block| {
        let [syn::Stmt::Expr(mark, Some(_)), syn::Stmt::Expr(tail, None)] = body.stmts.as_slice()
        else {
            return false;
        };
        expression(mark, "self.settled=true")
            && expression(tail, "installation.serve_app_currents()")
    };
    assert!(settle(&serve.block));
    for changed in [
        syn::parse_quote!({
            self.settled = true;
            Ok(())
        }),
        syn::parse_quote!({
            self.settled = true;
            other.serve_app_currents()
        }),
        syn::parse_quote!({
            self.settled = true;
            installation.check()?;
            installation.serve_app_currents()
        }),
        syn::parse_quote!({
            installation.serve_app_currents()?;
            self.settled = true;
            Ok(())
        }),
    ] {
        assert!(!settle(&changed));
    }
}
