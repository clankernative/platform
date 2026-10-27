use super::{
    policy::decode_key,
    protocol::{self, KeyOwner},
};
use super::{
    policy::{EnrollmentPolicy, RuntimeSelection},
    protocol::{IssuerCertificate, IssuerData, ProcessData},
};
use day2_capabilities::Digest;

fn actual_policy_file_wiring(birth: &str, owner: &str) -> bool {
    use syn::visit::Visit;
    fn fields(expression: &syn::Expr, expected: &[&str]) -> bool {
        match (expression, expected.split_last()) {
            (syn::Expr::Path(path), Some((name, []))) => path.path.is_ident(name),
            (syn::Expr::Field(field), Some((name, rest))) => {
                matches!(&field.member, syn::Member::Named(actual) if actual == name)
                    && fields(&field.base, rest)
            }
            _ => false,
        }
    }

    fn linux(statement: &syn::Stmt) -> Option<&syn::Block> {
        let syn::Stmt::Expr(syn::Expr::Block(block), _) = statement else {
            return None;
        };
        (block.attrs.len() == 1
            && matches!(&block.attrs[0].meta, syn::Meta::List(meta)
            if meta.path.is_ident("cfg") && meta.tokens.to_string() == "target_os = \"linux\""))
        .then_some(&block.block)
    }

    fn result_body(body: &syn::Block) -> Option<&syn::Block> {
        for statement in &body.stmts {
            if let Some(nested) = linux(statement)
                && let Some(result) = result_body(nested)
            {
                return Some(result);
            }
            if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result")
                && let Some(initializer) = &local.init
                && let syn::Expr::Call(call) = &*initializer.expr
                && let syn::Expr::Paren(parenthesized) = &*call.func
                && let syn::Expr::Closure(closure) = &*parenthesized.expr
                && let syn::Expr::Block(block) = &*closure.body
            {
                return Some(&block.block);
            }
        }
        None
    }

    fn direct_check(body: &syn::Block, receiver: &[&str], clock: &[&str]) -> usize {
        fn actual_clock(expression: &syn::Expr, clock: &[&str]) -> bool {
            if clock == ["self", "acquisition"] {
                matches!(expression, syn::Expr::MethodCall(call)
                    if call.method == "as_mut" && call.args.is_empty()
                    && fields(&call.receiver, clock))
            } else {
                matches!(expression, syn::Expr::Reference(reference)
                    if reference.mutability.is_some() && fields(&reference.expr, clock))
            }
        }
        body.stmts.iter().map(|statement| {
            if let Some(body) = linux(statement) { return direct_check(body, receiver, clock); }
            usize::from(matches!(statement, syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_))
                if matches!(&*attempt.expr, syn::Expr::MethodCall(call)
                    if call.method == "check" && fields(&call.receiver, receiver) && call.args.len() == 1
                    && actual_clock(&call.args[0], clock))))
        }).sum()
    }

    fn method(source: &syn::File, owner: &str, name: &str) -> Option<syn::ImplItemFn> {
        source.items.iter().find_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|name| name.ident == owner))
            {
                return None;
            }
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function.clone()),
                _ => None,
            })
        })
    }

    fn stamp_local(body: &syn::Block, name: &str, input: &[&str]) -> bool {
        body.stmts.iter().any(|statement| {
            let syn::Stmt::Local(local) = statement else { return false; };
            if !matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == name) { return false; }
            let Some(initializer) = &local.init else { return false; };
            let syn::Expr::Try(attempt) = &*initializer.expr else { return false; };
            let syn::Expr::Call(call) = &*attempt.expr else { return false; };
            matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("policy_file_stamp"))
                && call.args.len() == 2
                && matches!(&call.args[0], syn::Expr::Reference(reference) if fields(&reference.expr, input))
                && fields(&call.args[1], &["acquisition"])
        })
    }

    let cold_source = birth.split("#[cfg(test)]").next().unwrap();
    let visible_cold_read =
        cold_source.matches("File::read(").count() == 1 && !cold_source.contains("read_to_end(");
    let owner = syn::parse_file(owner).unwrap();
    let birth = syn::parse_file(birth).unwrap();
    let Some(enroll) = method(&owner, "EnrolledProcessRoleOwner", "enroll_current_thread") else {
        return false;
    };
    let Some(enroll) = enroll.block.stmts.iter().find_map(linux) else {
        return false;
    };
    let captured = enroll.stmts.iter().any(|statement| {
        let syn::Stmt::Local(local) = statement else { return false; };
        let syn::Pat::Tuple(tuple) = &local.pat else { return false; };
        if tuple.elems.len() != 2
            || !matches!(&tuple.elems[0], syn::Pat::Ident(binding) if binding.ident == "policy")
            || !matches!(&tuple.elems[1], syn::Pat::Ident(binding) if binding.ident == "policy_file" && binding.mutability.is_some()) { return false; }
        let Some(initializer) = &local.init else { return false; };
        let syn::Expr::Try(attempt) = &*initializer.expr else { return false; };
        let syn::Expr::Call(call) = &*attempt.expr else { return false; };
        matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>() == ["super", "birth", "admit_policy"])
            && call.args.len() == 1
            && matches!(&call.args[0], syn::Expr::Reference(reference)
                if reference.mutability.is_some() && fields(&reference.expr, &["acquisition"]))
    });
    let retained = matches!(enroll.stmts.last(), Some(syn::Stmt::Expr(syn::Expr::Call(call), None))
        if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("Ok")) && call.args.len() == 1
        && matches!(&call.args[0], syn::Expr::Struct(value)
            if value.path.is_ident("Self") && value.fields.iter().any(|field|
                matches!(&field.member, syn::Member::Named(name) if name == "policy_file")
                && fields(&field.expr, &["policy_file"]))));
    let Some(begin) = method(&owner, "EnrolledProcessRoleOwner", "begin_stage") else {
        return false;
    };
    let Some(stage) = method(&owner, "EnrolledRoleStage", "check") else {
        return false;
    };
    let Some(begin) = result_body(&begin.block) else {
        return false;
    };
    let Some(stage) = result_body(&stage.block) else {
        return false;
    };
    let Some(check) = method(&birth, "PolicyFileOwner", "check_file") else {
        return false;
    };
    let Some(check) = result_body(&check.block) else {
        return false;
    };
    #[derive(Default)]
    struct FullRead(bool);
    impl<'ast> Visit<'ast> for FullRead {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.0 |= path.path.segments.last().is_some_and(|name| {
                    name.ident.to_string().starts_with("read")
                        || [
                            "load_policy",
                            "admit_policy",
                            "admit_policy_file",
                            "decode",
                            "begin",
                        ]
                        .iter()
                        .any(|candidate| name.ident == candidate)
                });
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0 |= call.method.to_string().starts_with("read") || call.method == "seek";
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut full = FullRead::default();
    full.visit_block(check);
    full.visit_block(begin);
    full.visit_block(stage);
    let joins = check.stmts.iter().any(|statement| matches!(statement, syn::Stmt::Macro(statement)
        if statement.mac.path.is_ident("ensure")
        && statement.mac.tokens.to_string().replace(' ', "").starts_with("held==self.stamp&&current==self.stamp,")));
    let same_clock = check.stmts.iter().filter(|statement| matches!(statement,
        syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_))
        if matches!(&*attempt.expr, syn::Expr::MethodCall(call)
            if call.method == "remaining" && fields(&call.receiver, &["acquisition"]) && call.args.is_empty()))).count();
    visible_cold_read
        && captured
        && retained
        && !full.0
        && direct_check(enroll, &["policy_file"], &["acquisition"]) == 1
        && direct_check(begin, &["self", "policy_file"], &["acquisition"]) == 1
        && direct_check(
            stage,
            &["self", "owner", "policy_file"],
            &["self", "acquisition"],
        ) == 1
        && stamp_local(check, "held", &["self", "file"])
        && stamp_local(check, "current", &["named"])
        && joins
        && same_clock == 2
}

#[test]
fn actual_enrolled_checks_borrow_the_admitted_policy_file_and_original_clock() {
    assert!(actual_policy_file_wiring(
        include_str!("birth.rs"),
        include_str!("owner.rs")
    ));
    let source = include_str!("birth.rs");
    assert_eq!(
        source
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .matches("File::read(")
            .count(),
        1
    );
    assert!(!include_str!("policy.rs").contains("PolicyInterpretation"));
}

#[test]
fn policy_file_guard_rejects_conditional_checks_and_substituted_actual_handles() {
    let birth = include_str!("birth.rs");
    let owner = include_str!("owner.rs");
    for call in [
        "self.policy_file.check(&mut acquisition)?;",
        "self.owner.policy_file.check(self.acquisition.as_mut())?;",
    ] {
        for replacement in [
            format!("if false {{ {call} }}"),
            call.replace("?;", ";"),
            call.replace("&mut acquisition", "&mut unrelated"),
            call.replace("self.acquisition.as_mut()", "unrelated.as_mut()"),
        ] {
            if replacement == call {
                continue;
            }
            let changed = owner.replacen(call, &replacement, 1);
            assert_ne!(changed, owner);
            assert!(!actual_policy_file_wiring(birth, &changed));
        }
    }
    for (before, after) in [
        (
            "super::birth::admit_policy(&mut acquisition)?",
            "super::birth::metadata_only_policy(&mut acquisition)?",
        ),
        (
            "                policy_file,",
            "                policy_file: unrelated,",
        ),
    ] {
        let changed = owner.replacen(before, after, 1);
        assert_ne!(changed, owner);
        assert!(!actual_policy_file_wiring(birth, &changed));
    }
    for (before, after) in [
        (
            "let held = policy_file_stamp(&self.file, acquisition)?;",
            "let held = if false { policy_file_stamp(&self.file, acquisition)? } else { unrelated };",
        ),
        (
            "policy_file_stamp(&self.file, acquisition)?",
            "policy_file_stamp(&foreign, acquisition)?",
        ),
        (
            "policy_file_stamp(&named, acquisition)?",
            "policy_file_stamp(&self.file, acquisition)?",
        ),
        ("held == self.stamp && current == self.stamp", "true"),
        ("File::read(", "std::io::Read::read("),
        (
            "let named = open_policy_file(path, acquisition)?;",
            "let _ = admit_policy_file(path, acquisition)?; let named = open_policy_file(path, acquisition)?;",
        ),
    ] {
        let changed = birth.replacen(before, after, 1);
        assert_ne!(changed, birth);
        assert!(!actual_policy_file_wiring(&changed, owner));
    }
}

fn enrolled_self_reborrow_shape(source: &str) -> bool {
    use syn::visit::Visit;

    fn fields(expression: &syn::Expr, expected: &[&str]) -> bool {
        match (expression, expected.split_last()) {
            (syn::Expr::Path(path), Some((last, []))) => path.path.is_ident(last),
            (syn::Expr::Field(field), Some((last, rest))) => {
                matches!(&field.member, syn::Member::Named(name) if name == last)
                    && fields(&field.base, rest)
            }
            _ => false,
        }
    }

    fn linux_body(statement: &syn::Stmt) -> Option<&syn::Block> {
        let syn::Stmt::Expr(syn::Expr::Block(block), _) = statement else {
            return None;
        };
        (block.label.is_none()
            && block.attrs.len() == 1
            && matches!(&block.attrs[0].meta, syn::Meta::List(meta)
                if meta.path.is_ident("cfg") && meta.tokens.to_string() == "target_os = \"linux\""))
        .then_some(&block.block)
    }

    // Follow only the actual result closure and unconditional Linux blocks.
    // A counted call hidden under an impossible runtime condition is not a
    // production check, and dropping its error is not a successful check.
    fn result_body(body: &syn::Block) -> Option<&syn::Block> {
        for statement in &body.stmts {
            if let Some(body) = linux_body(statement) {
                if let Some(result) = result_body(body) {
                    return Some(result);
                }
            } else if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result")
                && let Some(initializer) = &local.init
                && let syn::Expr::Call(call) = &*initializer.expr
                && let syn::Expr::Paren(parenthesized) = &*call.func
                && let syn::Expr::Closure(closure) = &*parenthesized.expr
                && let syn::Expr::Block(result) = &*closure.body
            {
                return Some(&result.block);
            }
        }
        None
    }

    fn direct_retained_check(body: &syn::Block, owner: &[&str], clock: &[&str]) -> usize {
        body.stmts
            .iter()
            .map(|statement| {
                if let Some(body) = linux_body(statement) {
                    return direct_retained_check(body, owner, clock);
                }
                let syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_)) = statement else {
                    return 0;
                };
                let syn::Expr::MethodCall(call) = &*attempt.expr else {
                    return 0;
                };
                usize::from(
                    call.method == "check"
                        && fields(&call.receiver, owner)
                        && call.args.len() == 1
                        && if clock.len() == 1 {
                            matches!(&call.args[0], syn::Expr::Reference(reference)
                                if reference.mutability.is_some() && fields(&reference.expr, clock))
                        } else {
                            matches!(&call.args[0], syn::Expr::MethodCall(borrow)
                                if borrow.method == "as_mut" && borrow.args.is_empty()
                                && fields(&borrow.receiver, clock))
                        },
                )
            })
            .sum()
    }

    fn retained_check_runs(function: &syn::ImplItemFn, owner: &[&str], clock: &[&str]) -> bool {
        #[derive(Default)]
        struct EarlyReturn(bool);
        impl<'ast> Visit<'ast> for EarlyReturn {
            fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
                self.0 = true;
            }
        }
        let Some(body) = result_body(&function.block) else {
            return false;
        };
        let mut early = EarlyReturn::default();
        early.visit_block(body);
        !early.0 && direct_retained_check(body, owner, clock) == 1
    }

    #[derive(Default)]
    struct Calls {
        captures: usize,
        clocks: usize,
        owner_checks: usize,
        stage_checks: usize,
    }

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let path = path.path.segments.iter().collect::<Vec<_>>();
                self.captures += usize::from(
                    path.len() == 2
                        && path[0].ident == "SelfSnapshot"
                        && path[1].ident == "acquire",
                );
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.clocks += usize::from(call.method == "into_connection_clock");
            self.owner_checks +=
                usize::from(call.method == "check" && fields(&call.receiver, &["self", "current"]));
            self.stage_checks += usize::from(
                call.method == "check" && fields(&call.receiver, &["self", "owner", "current"]),
            );
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let source = syn::parse_file(source).unwrap();
    let mut enrollment = None;
    let mut begin = None;
    let mut check = None;
    let mut begin_runs = false;
    let mut check_runs = false;
    for item in source.items {
        let syn::Item::Impl(implementation) = item else {
            continue;
        };
        let syn::Type::Path(owner) = &*implementation.self_ty else {
            continue;
        };
        let owner = owner.path.segments.last().unwrap().ident.to_string();
        for item in implementation.items {
            let syn::ImplItem::Fn(function) = item else {
                continue;
            };
            let mut calls = Calls::default();
            calls.visit_block(&function.block);
            if owner == "EnrolledProcessRoleOwner" && function.sig.ident == "enroll_current_thread"
            {
                assert!(enrollment.replace(calls).is_none());
            } else if owner == "EnrolledProcessRoleOwner" && function.sig.ident == "begin_stage" {
                begin_runs = retained_check_runs(&function, &["self", "current"], &["acquisition"]);
                assert!(begin.replace(calls).is_none());
            } else if owner == "EnrolledRoleStage" && function.sig.ident == "check" {
                check_runs = retained_check_runs(
                    &function,
                    &["self", "owner", "current"],
                    &["self", "acquisition"],
                );
                assert!(check.replace(calls).is_none());
            }
        }
    }
    matches!(
        enrollment,
        Some(Calls {
            captures: 1,
            clocks: 1,
            ..
        })
    ) && begin_runs
        && check_runs
        && matches!(
            begin,
            Some(Calls {
                captures: 0,
                owner_checks: 1,
                ..
            })
        )
        && matches!(
            check,
            Some(Calls {
                captures: 0,
                stage_checks: 1,
                ..
            })
        )
}

#[test]
fn actual_enrolled_owner_retains_self_resources_for_request_checks() {
    assert!(enrolled_self_reborrow_shape(include_str!("owner.rs")));
}

#[test]
fn enrolled_self_guard_rejects_recapture_or_omitted_retained_checks() {
    let source = include_str!("owner.rs");
    for (before, after) in [
        ("SelfSnapshot::acquire(", "SelfSnapshot::metadata_only("),
        (
            "acquisition.into_connection_clock()?",
            "acquisition.discard_clock()?",
        ),
        (
            "self.current.check(&mut acquisition)?",
            "SelfSnapshot::acquire(&mut acquisition)?",
        ),
        (
            "self.owner.current.check(self.acquisition.as_mut())?",
            "self.owner.current.skip(self.acquisition.as_mut())?",
        ),
    ] {
        let mutated = source.replacen(before, after, 1);
        assert_ne!(mutated, source);
        assert!(!enrolled_self_reborrow_shape(&mutated));
    }
}

#[test]
fn enrolled_self_guard_requires_unconditional_fallible_checks_of_the_actual_request() {
    let source = include_str!("owner.rs");
    for call in [
        "self.current.check(&mut acquisition)?;",
        "self.owner.current.check(self.acquisition.as_mut())?;",
    ] {
        for replacement in [
            format!("if false {{ {call} }}"),
            call.replace("?;", ";"),
            call.replace("&mut acquisition", "&mut unrelated"),
            call.replace("&mut self.acquisition", "&mut unrelated"),
            call.replace("self.acquisition.as_mut()", "unrelated.as_mut()"),
        ] {
            if replacement == call {
                continue;
            }
            let changed = source.replacen(call, &replacement, 1);
            assert_ne!(changed, source);
            assert!(!enrolled_self_reborrow_shape(&changed));
        }
    }
}

fn owned_request_borrow_shape(source: &str) -> bool {
    fn field(expression: &syn::Expr, member: &str) -> bool {
        matches!(expression, syn::Expr::Field(value)
            if matches!(&value.member, syn::Member::Named(name) if name == member)
            && matches!(&*value.base, syn::Expr::Path(path) if path.path.is_ident("request")))
    }

    fn path(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.path.is_ident(name))
    }

    let source = syn::parse_file(source).unwrap();
    let functions = source.items.iter().filter_map(|item| {
        let syn::Item::Impl(owner) = item else { return None; };
        if !matches!(&*owner.self_ty, syn::Type::Path(path) if path.path.is_ident("EnrolledProcessRoleOwner")) {
            return None;
        }
        owner.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "borrow_current_request" => Some(function),
            _ => None,
        })
    }).collect::<Vec<_>>();
    let [function] = functions.as_slice() else {
        return false;
    };
    let inputs = function.sig.inputs.iter().collect::<Vec<_>>();
    let [syn::FnArg::Receiver(owner), syn::FnArg::Typed(request)] = inputs.as_slice() else {
        return false;
    };
    if !matches!(&owner.reference, Some((_, Some(lifetime))) if lifetime.ident == "request")
        || owner.mutability.is_none()
        || !matches!(&*request.pat, syn::Pat::Ident(binding) if binding.ident == "request")
        || !matches!(&*request.ty, syn::Type::Reference(reference)
            if reference.mutability.is_some()
            && reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "request")
            && matches!(&*reference.elem, syn::Type::Path(path) if path.path.is_ident("EnrolledCurrentRequest")))
    {
        return false;
    }
    let syn::ReturnType::Type(_, output) = &function.sig.output else {
        return false;
    };
    let syn::Type::Path(output) = &**output else {
        return false;
    };
    let Some(result) = output.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(result_args) = &result.arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(syn::Type::Path(stage))) = result_args.args.first() else {
        return false;
    };
    let Some(stage) = stage.path.segments.last() else {
        return false;
    };
    if stage.ident != "EnrolledRoleStage"
        || !matches!(&stage.arguments, syn::PathArguments::AngleBracketed(args)
            if matches!(args.args.first(), Some(syn::GenericArgument::Lifetime(lifetime)) if lifetime.ident == "request"))
    {
        return false;
    }
    let Some(result_body) = function.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        if !matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result") {
            return None;
        }
        let syn::Expr::Call(call) = &*local.init.as_ref()?.expr else {
            return None;
        };
        let syn::Expr::Paren(parenthesized) = &*call.func else {
            return None;
        };
        let syn::Expr::Closure(closure) = &*parenthesized.expr else {
            return None;
        };
        let syn::Expr::Block(block) = &*closure.body else {
            return None;
        };
        Some(&block.block)
    }) else {
        return false;
    };
    let original_interval = result_body.stmts.iter().filter(|statement| {
        let syn::Stmt::Local(local) = statement else { return false; };
        let syn::Pat::Tuple(tuple) = &local.pat else { return false; };
        if tuple.elems.len() != 2
            || !matches!(&tuple.elems[0], syn::Pat::Wild(_))
            || !matches!(&tuple.elems[1], syn::Pat::Ident(binding) if binding.ident == "deadline") { return false; }
        let Some(initializer) = &local.init else { return false; };
        let syn::Expr::Try(attempt) = &*initializer.expr else { return false; };
        let syn::Expr::MethodCall(call) = &*attempt.expr else { return false; };
        call.method == "interval_data" && field(&call.receiver, "acquisition") && call.args.is_empty()
    }).count();
    let actual_owner = result_body.stmts.iter().any(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return false;
        };
        if !matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "original") {
            return false;
        }
        let Some(initializer) = &local.init else {
            return false;
        };
        let syn::Expr::Try(attempt) = &*initializer.expr else {
            return false;
        };
        let syn::Expr::MethodCall(error) = &*attempt.expr else {
            return false;
        };
        let syn::Expr::MethodCall(upgrade) = &*error.receiver else {
            return false;
        };
        error.method == "ok_or_else"
            && upgrade.method == "upgrade"
            && upgrade.args.is_empty()
            && field(&upgrade.receiver, "identity")
    });
    let bound_owner = result_body.stmts.iter().any(|statement| {
        matches!(statement, syn::Stmt::Macro(statement)
            if statement.mac.path.is_ident("ensure")
            && statement.mac.tokens.to_string().replace(' ', "").starts_with(
                "Rc::ptr_eq(&original,&self.identity)&&request.incarnation==self.incarnation&&request.role==self.role&&request.process==std::process::id()&&request.thread==std::thread::current().id(),"))
    });
    let actual_borrow = function.block.stmts.iter().any(|statement| {
        let syn::Stmt::Local(local) = statement else { return false; };
        if !matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "stage") { return false; }
        let Some(initializer) = &local.init else { return false; };
        let syn::Expr::Struct(stage) = &*initializer.expr else { return false; };
        stage.path.is_ident("EnrolledRoleStage") && stage.fields.iter().any(|value| {
            if !matches!(&value.member, syn::Member::Named(name) if name == "acquisition") { return false; }
            let syn::Expr::Call(call) = &value.expr else { return false; };
            matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.iter().map(|part| part.ident.to_string()).collect::<Vec<_>>() == ["StageAcquisition", "borrowed"])
                && call.args.len() == 1
                && matches!(&call.args[0], syn::Expr::Reference(reference)
                    if reference.mutability.is_some() && field(&reference.expr, "acquisition"))
        })
    });
    #[derive(Default)]
    struct CopiedOriginal(bool);
    impl<'ast> syn::visit::Visit<'ast> for CopiedOriginal {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.0 |= matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "begin" || part.ident == "begin_bounded"));
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0 |= [
                "narrow",
                "begin_stage",
                "begin_current_stage",
                "begin_current",
            ]
            .iter()
            .any(|name| call.method == name);
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut copied = CopiedOriginal::default();
    syn::visit::Visit::visit_block(&mut copied, &function.block);
    let stage_check = function
        .block
        .stmts
        .iter()
        .filter(|statement| {
            matches!(statement, syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_))
            if matches!(&*attempt.expr, syn::Expr::MethodCall(call)
                if call.method == "check" && path(&call.receiver, "stage") && call.args.is_empty()))
        })
        .count();
    original_interval == 1
        && actual_owner
        && bound_owner
        && actual_borrow
        && !copied.0
        && stage_check == 1
}

#[test]
fn actual_http_request_borrow_keeps_both_owners_borrowed_and_the_same_original() {
    assert!(owned_request_borrow_shape(include_str!("owner.rs")));
}

#[test]
fn http_request_guard_rejects_new_clocks_weaker_lifetimes_and_skipped_postchecks() {
    let source = include_str!("owner.rs");
    for (before, after) in [
        (
            "&'request mut EnrolledCurrentRequest",
            "&mut EnrolledCurrentRequest",
        ),
        (
            "request.acquisition.interval_data()?",
            "NativeAcquisition::begin(5)?.interval_data()?",
        ),
        (
            "StageAcquisition::borrowed(&mut request.acquisition)",
            "StageAcquisition::owned(request.acquisition.narrow(5, deadline)?)",
        ),
        (
            "StageAcquisition::borrowed(&mut request.acquisition)",
            "StageAcquisition::borrowed(&mut unrelated)",
        ),
        (
            "request.acquisition.interval_data()?",
            "request.unrelated.interval_data()?",
        ),
        ("Rc::ptr_eq(&original, &self.identity)", "true"),
        ("request.incarnation == self.incarnation", "true"),
        ("request.role == self.role", "true"),
        ("request.process == std::process::id()", "true"),
        ("request.thread == std::thread::current().id()", "true"),
    ] {
        let changed = source.replacen(before, after, 1);
        assert_ne!(changed, source);
        assert!(!owned_request_borrow_shape(&changed));
    }
    // Pin this mutation to the actual borrow method rather than a different
    // caller's identically named check earlier in the production source.
    let (prefix, body) = source
        .split_once("pub(crate) fn borrow_current_request")
        .unwrap();
    for replacement in ["if false { stage.check()?; }", "let _ = stage.check();"] {
        let changed = format!(
            "{prefix}pub(crate) fn borrow_current_request{}",
            body.replacen("stage.check()?;", replacement, 1)
        );
        assert!(!owned_request_borrow_shape(&changed));
    }
}

fn actual_read_cap_handoff(source: &str) -> bool {
    fn is_path(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.path.is_ident(expected))
    }
    fn is_field(expression: &syn::Expr, owner: &str, member: &str) -> bool {
        matches!(expression, syn::Expr::Field(field)
            if is_path(&field.base, owner) && matches!(&field.member, syn::Member::Named(name) if name == member))
    }
    let syntax = syn::parse_file(source).unwrap();
    let Some(function) = syntax.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("SameEnrolledOwner")) { return None; }
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "meet_current_read_view" => Some(function),
            _ => None,
        })
    }) else { return false; };
    let Some(syn::Stmt::Local(result)) = function.block.stmts.first() else {
        return false;
    };
    let Some(initializer) = &result.init else {
        return false;
    };
    let syn::Expr::Call(invocation) = &*initializer.expr else {
        return false;
    };
    let syn::Expr::Paren(parenthesized) = &*invocation.func else {
        return false;
    };
    let syn::Expr::Closure(closure) = &*parenthesized.expr else {
        return false;
    };
    let syn::Expr::Block(body) = &*closure.body else {
        return false;
    };
    if body.block.stmts.len() != 4 {
        return false;
    }
    for (index, method, receiver, argument) in [
        (0, "check", "self", Some("stage")),
        (1, "require_current_role", "stage", None),
        (2, "exchange_current_views", "acquisition", Some("actual")),
        (3, "check", "stage", None),
    ] {
        let syn::Stmt::Expr(expression, semicolon) = &body.block.stmts[index] else {
            return false;
        };
        let expression = if index < 3 {
            let syn::Expr::Try(attempt) = expression else {
                return false;
            };
            if semicolon.is_none() {
                return false;
            }
            &*attempt.expr
        } else {
            if semicolon.is_some() {
                return false;
            }
            expression
        };
        let syn::Expr::MethodCall(call) = expression else {
            return false;
        };
        let correct_receiver = if index == 2 {
            matches!(&*call.receiver, syn::Expr::MethodCall(borrow)
                if borrow.method == "as_mut" && borrow.args.is_empty()
                && is_field(&borrow.receiver, "stage", "acquisition"))
        } else {
            is_path(&call.receiver, receiver)
        };
        if call.method != method
            || !correct_receiver
            || match argument {
                Some(argument) => call.args.len() != 1 || !is_path(&call.args[0], argument),
                None => !call.args.is_empty(),
            }
        {
            return false;
        }
    }
    let Some(syn::Stmt::Expr(syn::Expr::If(failed), _)) = function.block.stmts.get(1) else {
        return false;
    };
    matches!(&*failed.cond, syn::Expr::MethodCall(call) if call.method == "is_err" && is_path(&call.receiver, "result"))
        && failed.then_branch.stmts.iter().any(|statement| {
            matches!(statement,
            syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_))
            if call.method == "refuse" && is_path(&call.receiver, "actual") && call.args.is_empty())
        })
}

#[test]
fn actual_read_handoff_meets_the_real_child_into_the_release_stage_without_a_scalar_clock() {
    assert!(actual_read_cap_handoff(include_str!("owner.rs")));
}

#[test]
fn read_cap_handoff_guard_rejects_skipped_meets_wrong_views_and_lost_refusal() {
    let source = include_str!("owner.rs");
    let (prefix, body) = source.split_once("fn meet_current_read_view").unwrap();
    for (before, after) in [
        ("self.check(stage)?;", "let _ = self.check(stage);"),
        ("stage.require_current_role()?;", "stage.check()?;"),
        (
            "stage.acquisition.as_mut().exchange_current_views(actual)?;",
            "if false { stage.acquisition.as_mut().exchange_current_views(actual)?; }",
        ),
        (
            "stage.acquisition.as_mut().exchange_current_views(actual)?;",
            "let _ = stage.acquisition.as_mut().exchange_current_views(actual);",
        ),
        (
            "stage.acquisition.as_mut().exchange_current_views(actual)?;",
            "stage.acquisition.as_mut().exchange_current_views(unrelated)?;",
        ),
        ("stage.check()", "Ok(())"),
        ("actual.refuse();", ""),
    ] {
        let changed = body.replacen(before, after, 1);
        assert_ne!(changed, body);
        assert!(!actual_read_cap_handoff(&format!(
            "{prefix}fn meet_current_read_view{changed}"
        )));
    }
}

fn actual_current_read_cap_caller(source: &str) -> bool {
    fn path(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.path.is_ident(expected))
    }
    fn field(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Field(value) if path(&value.base, "self")
            && matches!(&value.member, syn::Member::Named(name) if name == expected))
    }
    fn call(statement: &syn::Stmt) -> Option<&syn::ExprMethodCall> {
        let syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_)) = statement else {
            return None;
        };
        match &*attempt.expr {
            syn::Expr::MethodCall(call) => Some(call),
            _ => None,
        }
    }
    fn actual_view(expression: &syn::Expr) -> bool {
        matches!(expression, syn::Expr::Reference(reference)
            if reference.mutability.is_some() && field(&reference.expr, "acquisition"))
    }
    let syntax = syn::parse_file(source).unwrap();
    let Some(sample) = syntax.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("RetainedEpochReads")) { return None; }
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "sample" => Some(function),
            _ => None,
        })
    }) else { return false; };
    let Some(body) = sample.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        if !matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result") {
            return None;
        }
        let init = local.init.as_ref()?;
        let syn::Expr::MethodCall(measure) = &*init.expr else {
            return None;
        };
        if measure.method != "measure" || !path(&measure.receiver, "timings") {
            return None;
        }
        let Some(syn::Expr::Closure(closure)) = measure.args.last() else {
            return None;
        };
        let syn::Expr::Block(body) = &*closure.body else {
            return None;
        };
        Some(&body.block)
    }) else {
        return false;
    };
    let Some(joined) = body.stmts.iter().position(|statement| {
        call(statement).is_some_and(|call| {
            call.method == "join"
                && field(&call.receiver, "scope")
                && call.args.len() == 2
                && actual_view(&call.args[0])
                && path(&call.args[1], "same_stage")
        })
    }) else {
        return false;
    };
    let Some(syn::Stmt::Expr(syn::Expr::If(current), _)) = body.stmts.get(joined + 1) else {
        return false;
    };
    if current.else_branch.is_some()
        || current.then_branch.stmts.len() != 1
        || !matches!(&*current.cond, syn::Expr::Binary(condition)
            if matches!(condition.op, syn::BinOp::Eq(_)) && field(&condition.left, "scope")
                && matches!(&*condition.right, syn::Expr::Path(path)
                    if path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>() == ["ReadScope", "Current"]))
    {
        return false;
    }
    let Some(meet) = call(&current.then_branch.stmts[0]) else {
        return false;
    };
    let Some(process) = body.stmts.get(joined + 2).and_then(call) else {
        return false;
    };
    meet.method == "meet_current_read_view"
        && field(&meet.receiver, "owner")
        && meet.args.len() == 2
        && path(&meet.args[0], "stage")
        && actual_view(&meet.args[1])
        && process.method == "check"
        && field(&process.receiver, "process")
        && process.args.len() == 1
        && actual_view(&process.args[0])
}

#[test]
fn actual_retained_current_sample_meets_its_joined_view_into_the_release_stage() {
    let source = include_str!("../authenticated_reads/retained.rs");
    assert!(actual_current_read_cap_caller(source));
    let actual =
        "self.owner\n                    .meet_current_read_view(stage, &mut self.acquisition)?;";
    assert_eq!(source.matches(actual).count(), 1, "unique actual cap meet");
    for (before, after) in [
        (actual, ""),
        (
            actual,
            "let _ = self.owner.meet_current_read_view(stage, &mut self.acquisition);",
        ),
        (
            actual,
            "self.owner.meet_current_read_view(stage, &mut unrelated)?;",
        ),
        (
            actual,
            "unrelated.meet_current_read_view(stage, &mut self.acquisition)?;",
        ),
        ("if self.scope == ReadScope::Current {", "if false {"),
        (
            "if self.scope == ReadScope::Current {",
            "if self.scope == ReadScope::StorageBootstrap {",
        ),
    ] {
        let changed = source.replacen(before, after, 1);
        assert!(changed != source, "ineffective cap mutant: {before}");
        assert!(!actual_current_read_cap_caller(&changed));
    }
}

pub(super) fn policy(root: &KeyOwner) -> EnrollmentPolicy {
    let store = crate::security_epoch::tests::selection();
    let bootstrap = crate::security_epoch::control_slot_tests::policy(&store);
    EnrollmentPolicy {
        bootstrap,
        store,
        root: super::root_kms::KmsRootSelection {
            version: "projects/test-project/locations/us-central1/keyRings/enrollment/cryptoKeys/root/cryptoKeyVersions/1".into(),
            public_key: root.public(),
        },
        provisioner_code: Digest::new(b"provisioner"),
        issuer_code: Digest::new(b"issuer"),
        runtime: RuntimeSelection {
            containerd_code: Digest::new(b"containerd"),
            containerd_version: "v2.2.0".into(),
            containerd_revision: "selected-revision".into(),
            cri_version: "v1".into(),
            node_name: "node-one".into(),
            node_uid: "node-uid".into(),
            kernel_release: "6.12.0".into(),
            architecture: "arm64".into(),
        },
    }
}

fn process(code: Digest) -> ProcessData {
    ProcessData {
        process: 71,
        start_ticks: 123,
        code,
        boot: "boot-one".into(),
        namespaces: ["time", "time_for_children", "pid", "mnt", "user", "cgroup"]
            .into_iter()
            .map(|name| (name.to_owned(), (7, 9)))
            .collect(),
    }
}

#[test]
fn runtime_revision_may_be_explicitly_empty_but_cannot_be_omitted_or_normalized() {
    let root = KeyOwner::generate().unwrap();
    let mut selected = policy(&root);
    selected.runtime.containerd_version = "2.1.5-0ubuntu0~24.04.1~gke1".into();
    selected.runtime.containerd_revision.clear();
    selected.validate().unwrap();
    let empty_revision = selected.digest().unwrap();
    let mut encoded = serde_json::to_value(&selected).unwrap();
    let decoded: EnrollmentPolicy =
        crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert_eq!(decoded, selected);
    encoded["runtime"]
        .as_object_mut()
        .unwrap()
        .remove("containerd_revision");
    assert!(
        crate::json::decode::<EnrollmentPolicy>(&serde_json::to_vec(&encoded).unwrap()).is_err()
    );

    selected.runtime.containerd_revision = "selected-revision".into();
    assert_ne!(selected.digest().unwrap(), empty_revision);
    for revision in [" ".to_owned(), "\n".to_owned(), "x".repeat(254)] {
        selected.runtime.containerd_revision = revision;
        assert!(selected.validate().is_err());
    }
    selected.runtime.containerd_revision.clear();
    selected.runtime.containerd_version.clear();
    assert!(selected.validate().is_err());
}

#[test]
fn signatures_are_purpose_and_value_bound_and_canonical() {
    let key = KeyOwner::generate().unwrap();
    let signature = key.sign("birth", &"one").unwrap();
    protocol::verify(&key.public(), "birth", &"one", &signature).unwrap();
    assert!(protocol::verify(&key.public(), "stage", &"one", &signature).is_err());
    assert!(protocol::verify(&key.public(), "birth", &"two", &signature).is_err());
    assert!(decode_key(&(key.public() + "=")).is_err());
    assert!(protocol::verify(&key.public(), "birth", &"one", &(signature + "=")).is_err());
}

#[test]
fn packet_parser_refuses_duplicate_unknown_and_oversized_fields() {
    assert!(
        protocol::decode(br#"{"kind":"birth_challenge","policy":"x","policy":"y","nonce":"z"}"#)
            .is_err()
    );
    assert!(protocol::decode(br#"{"kind":"birth_grant","unexpected":true}"#).is_err());
    assert!(protocol::decode(&vec![b' '; protocol::MAX_PACKET + 1]).is_err());
}

#[test]
fn issuer_certificate_requires_selected_root_generation_code_and_company() {
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let selected = policy(&root);
    let data = IssuerData {
        policy: selected.digest().unwrap(),
        root_version: selected.root.version.clone(),
        nonce: Digest::new(b"original-birth"),
        public_key: issuer.public(),
        process: process(selected.issuer_code.clone()),
        provisioner: process(selected.provisioner_code.clone()),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    };
    certificate.verify(&selected).unwrap();
    for changed in ["root", "version", "scope", "code", "profile"] {
        let mut policy = selected.clone();
        match changed {
            "root" => policy.root.public_key = KeyOwner::generate().unwrap().public(),
            "version" => policy.root.version = policy.root.version.replace("/1", "/2"),
            "scope" => policy.bootstrap.scope.app = serde_json::from_str("\"other\"").unwrap(),
            "code" => policy.issuer_code = Digest::new(b"replacement"),
            "profile" => {
                policy.bootstrap.runtime_profile.manifest = Digest::new(b"replacement-profile")
            }
            _ => unreachable!(),
        }
        assert!(certificate.verify(&policy).is_err(), "{changed}");
    }
    let mut changed = certificate.clone();
    changed.data.nonce = Digest::new(b"different-birth");
    assert!(changed.verify(&selected).is_err());
    let mut changed = certificate;
    changed.data.process.start_ticks += 1;
    assert!(changed.verify(&selected).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_never_installs_a_role_or_replaces_the_clock() {
    let scope = crate::security_epoch::tests::selection().scope;
    assert!(
        super::EnrolledProcessRoleOwner::enroll_current_thread(&scope, super::NativeRole::AppHost)
            .is_err()
    );
    assert!(super::run(false).is_err());
}

#[test]
fn role_bind_signature_and_packet_require_the_exact_closed_stage_purpose() {
    use super::{
        NativeRole,
        protocol::{Packet, StagePurpose},
    };
    let key = KeyOwner::generate().unwrap();
    let policy = Digest::new(b"policy");
    let request = Digest::new(b"request");
    let challenge = Digest::new(b"challenge");
    let public = key.public();
    let binding = (
        &policy,
        NativeRole::AppHost,
        StagePurpose::InitialFirstHolder,
        &public,
        &request,
        &challenge,
    );
    let signature = key.sign("role-bind", &binding).unwrap();
    protocol::verify(&public, "role-bind", &binding, &signature).unwrap();
    let other = (
        &policy,
        NativeRole::AppHost,
        StagePurpose::CurrentRole,
        &public,
        &request,
        &challenge,
    );
    assert!(protocol::verify(&public, "role-bind", &other, &signature).is_err());
    let packet = Packet::StageHello {
        policy,
        role: NativeRole::AppHost,
        purpose: StagePurpose::InitialFirstHolder,
        public_key: public,
        request,
    };
    let bytes = serde_json::to_vec(&packet).unwrap();
    assert!(protocol::decode(&bytes).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("purpose");
    assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["purpose"] = serde_json::json!("any_stage");
    assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn storage_stage_purposes_are_closed_and_role_restricted_independent_of_duration() {
    use super::{NativeRole, protocol::StagePurpose};
    for purpose in [
        StagePurpose::CurrentRole,
        StagePurpose::InitialFirstHolder,
        StagePurpose::StorageBootstrap,
        StagePurpose::StorageMetadataObservation,
    ] {
        for role in [
            NativeRole::AppHost,
            NativeRole::EpochController,
            NativeRole::SecurityShell,
        ] {
            let expected = match purpose {
                StagePurpose::CurrentRole => true,
                StagePurpose::InitialFirstHolder | StagePurpose::StorageBootstrap => {
                    role != NativeRole::SecurityShell
                }
                StagePurpose::StorageMetadataObservation => role == NativeRole::EpochController,
            };
            assert_eq!(purpose.require_role(role).is_ok(), expected);
        }
    }
    assert_eq!(
        StagePurpose::CurrentRole.limit(),
        std::time::Duration::from_secs(5)
    );
    assert_eq!(
        StagePurpose::InitialFirstHolder.limit(),
        std::time::Duration::from_secs(10)
    );
    assert_eq!(
        StagePurpose::StorageBootstrap.limit(),
        std::time::Duration::from_secs(60)
    );
    assert_eq!(
        StagePurpose::StorageMetadataObservation.limit(),
        std::time::Duration::from_secs(10)
    );
}

#[test]
fn validly_signed_short_bootstrap_and_metadata_grants_fail_the_ordinary_current_purpose_gate() {
    // Cryptographic DATA only. This is the exact comparison used by the real
    // EnrolledRoleStage::require_current_role gate, not a native-stage fixture.
    use super::{
        NativeRole,
        protocol::{RuntimeBinding, SignedStage, StageData, StagePurpose},
    };
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let key = KeyOwner::generate().unwrap();
    let selected = policy(&root);
    let issuer_data = IssuerData {
        policy: selected.digest().unwrap(),
        root_version: selected.root.version.clone(),
        nonce: Digest::new(b"purpose-test-issuer"),
        public_key: issuer.public(),
        process: process(selected.issuer_code.clone()),
        provisioner: process(selected.provisioner_code.clone()),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &issuer_data).unwrap(),
        data: issuer_data,
    };
    certificate.verify(&selected).unwrap();
    for (purpose, role) in [
        (StagePurpose::CurrentRole, NativeRole::AppHost),
        (StagePurpose::CurrentRole, NativeRole::EpochController),
        (StagePurpose::InitialFirstHolder, NativeRole::AppHost),
        (
            StagePurpose::InitialFirstHolder,
            NativeRole::EpochController,
        ),
        (StagePurpose::StorageBootstrap, NativeRole::AppHost),
        (StagePurpose::StorageBootstrap, NativeRole::EpochController),
        (
            StagePurpose::StorageMetadataObservation,
            NativeRole::EpochController,
        ),
    ] {
        for seconds in [1_u64, 5] {
            purpose.require_role(role).unwrap();
            let workload = selected.workload(role);
            let data = StageData {
                issuer: certificate.digest().unwrap(),
                policy: selected.digest().unwrap(),
                role,
                purpose,
                public_key: key.public(),
                challenge: Digest::new(b"purpose-challenge"),
                request: Digest::new(b"purpose-request"),
                process: process(selected.code(role).clone()),
                runtime: RuntimeBinding {
                    container: crate::security_epoch::runtime_profile::ContainerFacts {
                        pod_name: workload.workload.name.clone(),
                        pod_uid: format!("purpose-test-{role:?}"),
                        node_name: selected.runtime.node_name.clone(),
                        container_name: workload.container.name.clone(),
                        container_id: "a".repeat(64),
                        image: workload.container.image.clone(),
                        restart_count: 0,
                    },
                    node_uid: "node-uid".into(),
                    boot: "boot-one".into(),
                },
                origin_ns: 100_000_000_000,
                deadline_ns: 100_000_000_000 + seconds * 1_000_000_000,
            };
            let stage = SignedStage {
                signature: issuer.sign("role-stage", &data).unwrap(),
                data,
            };
            protocol::verify(
                &certificate.data.public_key,
                "role-stage",
                &stage.data,
                &stage.signature,
            )
            .unwrap();
            assert_eq!(
                stage
                    .data
                    .purpose
                    .require_exact(StagePurpose::CurrentRole)
                    .is_ok(),
                purpose == StagePurpose::CurrentRole
            );
            for expected in [
                StagePurpose::CurrentRole,
                StagePurpose::InitialFirstHolder,
                StagePurpose::StorageBootstrap,
                StagePurpose::StorageMetadataObservation,
            ] {
                assert_eq!(
                    stage.data.purpose.require_exact(expected).is_ok(),
                    purpose == expected
                );
                if expected != purpose {
                    let mut substituted = stage.clone();
                    substituted.data.purpose = expected;
                    assert!(
                        protocol::verify(
                            &certificate.data.public_key,
                            "role-stage",
                            &substituted.data,
                            &substituted.signature
                        )
                        .is_err()
                    );
                }
            }
        }
    }
}

#[test]
fn hello_bind_and_grant_signature_never_substitute_a_storage_stage_purpose() {
    use super::{
        NativeRole,
        protocol::{Packet, StagePurpose},
    };
    let key = KeyOwner::generate().unwrap();
    let policy = Digest::new(b"purpose-policy");
    let request = Digest::new(b"purpose-request");
    let challenge = Digest::new(b"purpose-challenge");
    let public = key.public();
    for purpose in [
        StagePurpose::CurrentRole,
        StagePurpose::InitialFirstHolder,
        StagePurpose::StorageBootstrap,
        StagePurpose::StorageMetadataObservation,
    ] {
        let role = NativeRole::EpochController;
        let binding = (&policy, role, purpose, &public, &request, &challenge);
        let signature = key.sign("role-bind", &binding).unwrap();
        protocol::verify(&public, "role-bind", &binding, &signature).unwrap();
        for other in [
            StagePurpose::CurrentRole,
            StagePurpose::InitialFirstHolder,
            StagePurpose::StorageBootstrap,
            StagePurpose::StorageMetadataObservation,
        ] {
            if other != purpose {
                let changed = (&policy, role, other, &public, &request, &challenge);
                assert!(protocol::verify(&public, "role-bind", &changed, &signature).is_err());
            }
        }
        for packet in [
            Packet::StageHello {
                policy: policy.clone(),
                role,
                purpose,
                public_key: public.clone(),
                request: request.clone(),
            },
            Packet::StageBind {
                policy: policy.clone(),
                role,
                purpose,
                public_key: public.clone(),
                request: request.clone(),
                challenge: challenge.clone(),
                signature: signature.clone(),
            },
        ] {
            let mut value = serde_json::to_value(&packet).unwrap();
            assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_ok());
            value.as_object_mut().unwrap().remove("purpose");
            assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
            value["purpose"] = serde_json::json!("any_storage");
            assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
}
// Production wiring controls: no fixture constructs an admitted native peer.
fn cold_peer_admission_wiring(owner: &str, storage: &str, serving: &str) -> bool {
    use syn::visit::Visit;

    fn method(source: &syn::File, owner: &str, name: &str) -> Option<syn::ImplItemFn> {
        source.items.iter().find_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == owner))
            {
                return None;
            }
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function.clone()),
                _ => None,
            })
        })
    }

    #[derive(Default)]
    struct Calls {
        admission: usize,
        exchange: usize,
        authentication: usize,
        completed: usize,
        boundary: bool,
        returns: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.exchange += usize::from(path.path.is_ident("exchange"));
                self.boundary |= path.path.is_ident("handshake");
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.admission += usize::from(call.method == "admit_peer_connection");
            self.authentication += usize::from(call.method == "narrow_authentication");
            self.completed += usize::from(call.method == "complete_authentication");
            self.boundary |= [
                "accept",
                "receive_storage",
                "storage_statement",
                "serving_statement",
                "narrow_io_acquisition",
                "initial_first_holder_acquisition",
            ]
            .iter()
            .any(|name| call.method == name);
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.returns = true;
        }
    }

    fn flatten<'a>(body: &'a syn::Block, statements: &mut Vec<&'a syn::Stmt>) {
        for statement in &body.stmts {
            if let syn::Stmt::Expr(syn::Expr::Block(block), _) = statement
                && block.attrs.len() == 1
                && matches!(&block.attrs[0].meta, syn::Meta::List(meta)
                    if meta.path.is_ident("cfg") && meta.tokens.to_string() == "target_os = \"linux\"")
            {
                flatten(&block.block, statements);
            } else if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result")
                && let Some(initializer) = &local.init
                && let syn::Expr::Call(call) = &*initializer.expr
                && call.args.is_empty()
                && let syn::Expr::Paren(parenthesized) = &*call.func
                && let syn::Expr::Closure(closure) = &*parenthesized.expr
                && let syn::Expr::Block(block) = &*closure.body
            {
                flatten(&block.block, statements);
            } else {
                statements.push(statement);
            }
        }
    }

    let owner = syn::parse_file(owner).unwrap();
    let storage = syn::parse_file(storage).unwrap();
    let serving = syn::parse_file(serving).unwrap();
    for (source, owner, name) in [
        (&storage, "InitialHolderListener", "prepare"),
        (&storage, "AuthenticatedInitialHolderOffer", "receive"),
        (&serving, "ShellServingConnection", "receive"),
        (&serving, "ControllerServingListener", "accept"),
    ] {
        let Some(function) = method(source, owner, name) else {
            return false;
        };
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        if calls.admission != 1 || calls.returns {
            return false;
        }
        let mut statements = Vec::new();
        flatten(&function.block, &mut statements);
        let admission = statements.iter().position(|statement| {
            matches!(statement,
            syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_))
            if matches!(&*attempt.expr, syn::Expr::MethodCall(call)
                if call.method == "admit_peer_connection" && call.args.is_empty()
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("stage"))))
        });
        let boundary = statements.iter().position(|statement| {
            let mut calls = Calls::default();
            calls.visit_stmt(statement);
            calls.boundary
        });
        if !matches!((admission, boundary), (Some(admission), Some(boundary)) if admission < boundary)
        {
            return false;
        }
    }
    for name in ["begin_stage", "borrow_current_request"] {
        let Some(function) = method(&owner, "EnrolledProcessRoleOwner", name) else {
            return false;
        };
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        if calls.exchange != 0 || calls.admission != 0 || calls.authentication != 0 {
            return false;
        }
    }
    let Some(cold) = method(&owner, "EnrolledRoleStage", "admit_peer_connection") else {
        return false;
    };
    let mut calls = Calls::default();
    calls.visit_block(&cold.block);
    calls.exchange == 1 && calls.authentication == 1 && calls.completed == 1
}

#[test]
fn every_real_cold_peer_factory_admits_before_handshake_and_warm_borrows_do_not_enroll() {
    assert!(cold_peer_admission_wiring(
        include_str!("owner.rs"),
        include_str!("storage_peer.rs"),
        include_str!("serving_peer.rs")
    ));
}

#[test]
fn cold_peer_guard_rejects_omitted_conditional_swallowed_or_unrelated_admission() {
    let owner = include_str!("owner.rs");
    let storage = include_str!("storage_peer.rs");
    let serving = include_str!("serving_peer.rs");
    let call = "stage.admit_peer_connection()?;";
    for (source, is_storage) in [(storage, true), (serving, false)] {
        assert_eq!(source.matches(call).count(), 2);
        for (position, _) in source.match_indices(call) {
            for replacement in [
                "",
                "if false { stage.admit_peer_connection()?; }",
                "let _ = stage.admit_peer_connection();",
                "unrelated.admit_peer_connection()?;",
            ] {
                let changed = format!(
                    "{}{replacement}{}",
                    &source[..position],
                    &source[position + call.len()..]
                );
                let (storage, serving) = if is_storage {
                    (changed.as_str(), serving)
                } else {
                    (storage, changed.as_str())
                };
                assert!(!cold_peer_admission_wiring(owner, storage, serving));
            }
        }
    }
}

#[test]
fn cold_peer_guard_rejects_reenrollment_in_a_warm_original_and_skipped_cold_exchange() {
    let source = include_str!("owner.rs");
    let storage = include_str!("storage_peer.rs");
    let serving = include_str!("serving_peer.rs");
    let signature =
        "fn begin_stage(&mut self, purpose: StagePurpose) -> Result<EnrolledRoleStage<'_>> {";
    let changed = source.replacen(signature, &format!("{signature}\nexchange();"), 1);
    assert_ne!(changed, source);
    assert!(!cold_peer_admission_wiring(&changed, storage, serving));
    let (prefix, cold) = source.split_once("fn admit_peer_connection").unwrap();
    for (before, after) in [
        ("= exchange(", "= skipped_exchange("),
        (
            ".narrow_authentication()?",
            ".begin_authentication_again()?",
        ),
        (
            ".complete_authentication(authentication)?",
            ".discard_authentication(authentication)?",
        ),
    ] {
        let changed = cold.replacen(before, after, 1);
        assert_ne!(changed, cold);
        assert!(!cold_peer_admission_wiring(
            &format!("{prefix}fn admit_peer_connection{changed}"),
            storage,
            serving
        ));
    }
}
fn actual_read_cap_handoff(source: &str) -> bool {
    fn is_path(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.path.is_ident(expected))
    }
    fn is_field(expression: &syn::Expr, owner: &str, member: &str) -> bool {
        matches!(expression, syn::Expr::Field(field)
            if is_path(&field.base, owner) && matches!(&field.member, syn::Member::Named(name) if name == member))
    }
    let syntax = syn::parse_file(source).unwrap();
    let Some(function) = syntax.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("SameEnrolledOwner")) { return None; }
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "meet_current_read_view" => Some(function),
            _ => None,
        })
    }) else { return false; };
    let Some(syn::Stmt::Local(result)) = function.block.stmts.first() else {
        return false;
    };
    let Some(initializer) = &result.init else {
        return false;
    };
    let syn::Expr::Call(invocation) = &*initializer.expr else {
        return false;
    };
    let syn::Expr::Paren(parenthesized) = &*invocation.func else {
        return false;
    };
    let syn::Expr::Closure(closure) = &*parenthesized.expr else {
        return false;
    };
    let syn::Expr::Block(body) = &*closure.body else {
        return false;
    };
    if body.block.stmts.len() != 4 {
        return false;
    }
    for (index, method, receiver, argument) in [
        (0, "check", "self", Some("stage")),
        (1, "require_current_role", "stage", None),
        (2, "exchange_current_views", "acquisition", Some("actual")),
        (3, "check", "stage", None),
    ] {
        let syn::Stmt::Expr(expression, semicolon) = &body.block.stmts[index] else {
            return false;
        };
        let expression = if index < 3 {
            let syn::Expr::Try(attempt) = expression else {
                return false;
            };
            if semicolon.is_none() {
                return false;
            }
            &*attempt.expr
        } else {
            if semicolon.is_some() {
                return false;
            }
            expression
        };
        let syn::Expr::MethodCall(call) = expression else {
            return false;
        };
        let correct_receiver = if index == 2 {
            matches!(&*call.receiver, syn::Expr::MethodCall(borrow)
                if borrow.method == "as_mut" && borrow.args.is_empty()
                    && is_field(&borrow.receiver, "stage", "acquisition"))
        } else {
            is_path(&call.receiver, receiver)
        };
        if call.method != method
            || !correct_receiver
            || match argument {
                Some("CURRENT_PURPOSE") => {
                    call.args.len() != 1
                        || !matches!(&call.args[0], syn::Expr::Path(path)
                    if path.path.segments.iter().map(|segment|segment.ident.to_string()).collect::<Vec<_>>() == ["StagePurpose", "CurrentRole"])
                }
                Some(argument) => call.args.len() != 1 || !is_path(&call.args[0], argument),
                None => !call.args.is_empty(),
            }
        {
            return false;
        }
    }
    let Some(syn::Stmt::Expr(syn::Expr::If(failed), _)) = function.block.stmts.get(1) else {
        return false;
    };
    fn field_path(expression: &syn::Expr, names: &[&str]) -> bool {
        match (expression, names.split_last()) {
            (syn::Expr::Path(path), Some((name, []))) => path.path.is_ident(name),
            (syn::Expr::Field(field), Some((name, parent))) => {
                matches!(&field.member, syn::Member::Named(actual) if actual == name)
                    && field_path(&field.base, parent)
            }
            _ => false,
        }
    }
    fn latch(statement: &syn::Stmt, names: &[&str]) -> bool {
        matches!(statement, syn::Stmt::Expr(syn::Expr::Assign(assign), Some(_))
            if field_path(&assign.left,names)
            && matches!(&*assign.right,syn::Expr::Lit(value) if matches!(value.lit,syn::Lit::Bool(syn::LitBool{value:true,..}))))
    }
    fn refuse(statement: &syn::Stmt, names: &[&str]) -> bool {
        matches!(statement,syn::Stmt::Expr(syn::Expr::MethodCall(call),Some(_))
            if call.method=="refuse" && call.args.is_empty()
                && if names == ["stage", "acquisition"] {
                    matches!(&*call.receiver, syn::Expr::MethodCall(borrow)
                        if borrow.method == "as_mut" && borrow.args.is_empty()
                            && field_path(&borrow.receiver,names))
                } else { field_path(&call.receiver,names) })
    }
    function.block.stmts.len() == 3
        && matches!(function.block.stmts.last(),Some(syn::Stmt::Expr(value,None)) if is_path(value,"result"))
        && matches!(&*failed.cond, syn::Expr::MethodCall(call) if call.method == "is_err" && is_path(&call.receiver, "result"))
        && failed.then_branch.stmts.len() == 4
        && latch(&failed.then_branch.stmts[0], &["self", "refused"])
        && latch(&failed.then_branch.stmts[1], &["stage", "owner", "refused"])
        && refuse(&failed.then_branch.stmts[2], &["stage", "acquisition"])
        && refuse(&failed.then_branch.stmts[3], &["actual"])
}

#[test]
fn actual_read_handoff_meets_the_real_child_into_the_release_stage_without_a_scalar_clock() {
    assert!(actual_read_cap_handoff(include_str!("owner.rs")));
}

#[test]
fn read_cap_handoff_guard_rejects_skipped_meets_wrong_views_and_lost_refusal() {
    let source = include_str!("owner.rs");
    let (prefix, body) = source.split_once("fn meet_current_read_view").unwrap();
    for (before, after) in [
        ("self.check(stage)?;", "let _ = self.check(stage);"),
        (
            "stage.require_current_role()?;",
            "stage.check()?;",
        ),
        (
            "stage.acquisition.as_mut().exchange_current_views(actual)?;",
            "if false { stage.acquisition.as_mut().exchange_current_views(actual)?; }",
        ),
        (
            "stage.acquisition.as_mut().exchange_current_views(actual)?;",
            "let _ = stage.acquisition.as_mut().exchange_current_views(actual);",
        ),
        (
            "stage.acquisition.as_mut().exchange_current_views(actual)?;",
            "stage.acquisition.as_mut().exchange_current_views(unrelated)?;",
        ),
        ("stage.check()", "Ok(())"),
        ("self.refused = true;", "self.refused = false;"),
        (
            "stage.owner.refused = true;",
            "stage.owner.refused = false;",
        ),
        ("stage.acquisition.as_mut().refuse();", ""),
        ("actual.refuse();", ""),
    ] {
        let changed = body.replacen(before, after, 1);
        assert_ne!(changed, body);
        assert!(!actual_read_cap_handoff(&format!(
            "{prefix}fn meet_current_read_view{changed}"
        )));
    }
}
