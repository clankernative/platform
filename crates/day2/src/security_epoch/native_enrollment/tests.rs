use super::{
    policy::decode_key,
    protocol::{self, KeyOwner},
};
use super::{
    policy::{EnrollmentPolicy, RuntimeSelection},
    protocol::{IssuerCertificate, IssuerData, ProcessData},
};
use day2_capabilities::Digest;

// Count only the exact fallible short borrow of the retained native field.
// RefCell reentry is an error on the same checked path, never a recapture or
// a panicking borrow hidden inside a successful-looking source control.
fn shared_native_check_receiver(expression: &syn::Expr, expected: &[&str]) -> bool {
    use quote::ToTokens;
    let receiver = format!(
        "{}.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?",
        expected.join("."),
    );
    let expected: syn::Expr = syn::parse_str(&receiver).unwrap();
    expression.to_token_stream().to_string() == expected.to_token_stream().to_string()
}

fn native_source_tokens(source: &str) -> String {
    // Lexer fragments can join `?;` or `,&`, while syn emits those separators
    // separately. Keep their exact operations equal
    // without dropping commas, delimiters or any control tokens.
    fn normalize(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
        stream
            .into_iter()
            .map(|token| match token {
                proc_macro2::TokenTree::Punct(punct) if matches!(punct.as_char(), '?' | ',') => {
                    proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                        punct.as_char(),
                        proc_macro2::Spacing::Alone,
                    ))
                }
                proc_macro2::TokenTree::Group(group) => proc_macro2::TokenTree::Group(
                    proc_macro2::Group::new(group.delimiter(), normalize(group.stream())),
                ),
                token => token,
            })
            .collect()
    }
    normalize(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
}

#[test]
fn native_source_tokens_match_actual_fallible_statements_and_preserve_tuple_commas() {
    use quote::ToTokens;
    let actual: syn::Stmt = syn::parse_str("attempt.owner.check()?;").unwrap();
    assert_eq!(
        native_source_tokens("attempt.owner.check()?;"),
        actual.to_token_stream().to_string()
    );
    let call: syn::Expr =
        syn::parse_str("make(selection,&projection,&activation,&holder)").unwrap();
    assert_eq!(
        native_source_tokens("make(selection,&projection,&activation,&holder)"),
        call.to_token_stream().to_string()
    );
    assert_ne!(
        native_source_tokens("(value)"),
        native_source_tokens("(value,)")
    );
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
                        && shared_native_check_receiver(&call.receiver, owner)
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
            self.owner_checks += usize::from(
                call.method == "check"
                    && shared_native_check_receiver(&call.receiver, &["self", "current"]),
            );
            self.stage_checks += usize::from(
                call.method == "check"
                    && shared_native_check_receiver(&call.receiver, &["self", "owner", "current"]),
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
    let source = native_source_tokens(include_str!("owner.rs"));
    for (before, after) in [
        ("SelfSnapshot::acquire", "SelfSnapshot::metadata_only"),
        (
            "acquisition.into_connection_clock()?",
            "acquisition.discard_clock()?",
        ),
        (
            "self.current.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?.check(&mut acquisition)?",
            "SelfSnapshot::acquire(&mut acquisition)?",
        ),
        (
            "self.owner.current.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?.check(self.acquisition.as_mut())?",
            "self.owner.current.skip(self.acquisition.as_mut())?",
        ),
    ] {
        let mutated = source.replacen(
            &native_source_tokens(before),
            &native_source_tokens(after),
            1,
        );
        assert_ne!(mutated, source);
        assert!(!enrolled_self_reborrow_shape(&mutated));
    }
}

#[test]
fn enrolled_self_guard_requires_unconditional_fallible_checks_of_the_actual_request() {
    let source = native_source_tokens(include_str!("owner.rs"));
    for call in [
        "self.current.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?.check(&mut acquisition)?;",
        "self.owner.current.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?.check(self.acquisition.as_mut())?;",
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
            let changed = source.replacen(
                &native_source_tokens(call),
                &native_source_tokens(&replacement),
                1,
            );
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
                    if call.method == "check" && (if receiver == ["policy_file"] { fields(&call.receiver, receiver) } else { shared_native_check_receiver(&call.receiver, receiver) }) && call.args.len() == 1
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
                && { use quote::ToTokens; field.expr.to_token_stream().to_string() == native_source_tokens("Rc::new(RefCell::new(policy_file))") })));
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
    let owner = native_source_tokens(include_str!("owner.rs"));
    for call in [
        "self.policy_file.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?.check(&mut acquisition)?;",
        "self.owner.policy_file.try_borrow_mut().map_err(|_| anyhow::anyhow!(\"native_enrollment_resource_busy\"))?.check(self.acquisition.as_mut())?;",
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
            let changed = owner.replacen(
                &native_source_tokens(call),
                &native_source_tokens(&replacement),
                1,
            );
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
            "policy_file: Rc::new(RefCell::new(policy_file)),",
            "                policy_file: unrelated,",
        ),
    ] {
        let changed = owner.replacen(
            &native_source_tokens(before),
            &native_source_tokens(after),
            1,
        );
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
        assert!(!actual_policy_file_wiring(&changed, &owner));
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

fn enrollment_call_tokens(expression: &syn::Expr) -> String {
    use quote::ToTokens as _;
    fn normalize(value: &mut syn::Expr) {
        match value {
            syn::Expr::Call(call) => {
                normalize(&mut call.func);
                for argument in &mut call.args {
                    normalize(argument);
                }
                call.args.pop_punct();
            }
            syn::Expr::MethodCall(call) => {
                normalize(&mut call.receiver);
                for argument in &mut call.args {
                    normalize(argument);
                }
                call.args.pop_punct();
            }
            syn::Expr::Array(array) => {
                for element in &mut array.elems {
                    normalize(element);
                }
                array.elems.pop_punct();
            }
            syn::Expr::Reference(value) => normalize(&mut value.expr),
            syn::Expr::Try(value) => normalize(&mut value.expr),
            _ => {}
        }
    }
    let mut expression = expression.clone();
    normalize(&mut expression);
    expression.to_token_stream().to_string()
}

fn enrollment_statement_tokens(statement: &syn::Stmt) -> String {
    use quote::ToTokens as _;
    let mut statement = statement.clone();
    if let syn::Stmt::Local(local) = &mut statement
        && let Some(init) = &mut local.init
    {
        *init.expr = syn::parse_str(&enrollment_call_tokens(&init.expr)).unwrap();
    }
    statement.to_token_stream().to_string()
}

// The Linux issuer path is inspected on every host without constructing a fake
// native issuer. Kernel/message-origin qualification remains Linux-only.
fn frozen_publication_source(source: &str) -> anyhow::Result<bool> {
    use quote::ToTokens as _;
    let file = syn::parse_file(source)?;
    let methods: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "freeze" => Some(item),
            _ => None,
        })
        .collect();
    if methods.len() != 1 {
        return Ok(false);
    }
    #[derive(Default)]
    struct Freshness {
        flag_references: usize,
        current_bindings: usize,
        snapshot_acquisitions: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for Freshness {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.flag_references += usize::from(path.path.is_ident("issuance"));
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_pat_ident(&mut self, binding: &'ast syn::PatIdent) {
            self.current_bindings += usize::from(binding.ident == "current");
            syn::visit::visit_pat_ident(self, binding);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.snapshot_acquisitions += usize::from(matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.iter().any(|s|s.ident=="SelfSnapshot")
                    && path.path.segments.last().is_some_and(|s|s.ident=="acquire")));
            syn::visit::visit_expr_call(self, call);
        }
    }
    use syn::visit::Visit as _;
    let mut freshness = Freshness::default();
    freshness.visit_block(&methods[0].block);
    if freshness.flag_references != 2
        || freshness.current_bindings != 1
        || freshness.snapshot_acquisitions != 0
    {
        return Ok(false);
    }
    let body = &methods[0].block.stmts;
    let retained: syn::Stmt = syn::parse_str("let (costs, current, peer) = observations;")?;
    // The concrete mutable entry snapshot is only destructured from the
    // actual observation borrow; no local constructor or shadow may replace it.
    if !body
        .get(2)
        .is_some_and(|s| s.to_token_stream().to_string() == retained.to_token_stream().to_string())
    {
        return Ok(false);
    }
    if body.len() < 10 {
        return Ok(false);
    }
    let tail = body[body.len() - 9..]
        .iter()
        .map(enrollment_statement_tokens)
        .collect::<Vec<_>>();
    let expected: syn::Block = syn::parse_str(
        r#"{
        issuer.certificate.verify(&issuer.policy)?;
        issuer.parent.check_identity(acquisition, &costs.hashes(Subject::ParentBefore))?;
        current.check(acquisition)?;
        acquisition.remaining()?;
        let sent = channel.send(
            &Packet::FreezeGrant {
                statement: Box::new(statement.clone()),
                signature: signature.clone(),
            },
            acquisition,
        );
        let retained = FrozenCohort::capture(statement, signature, &issuer.certificate, peer, &mut bound, acquisition, costs);
        sent?;
        let cohort = retained?;
        closing.retain_frozen(cohort)
    }"#,
    )?;
    if tail
        != expected
            .stmts
            .iter()
            .map(enrollment_statement_tokens)
            .collect::<Vec<_>>()
    {
        return Ok(false);
    }
    let closed: syn::Stmt = syn::parse_str("let closing = issuance.close()?;")?;
    let closed = closed.to_token_stream().to_string();
    let closes: Vec<_> = body
        .iter()
        .enumerate()
        .filter(|(_, s)| s.to_token_stream().to_string() == closed)
        .map(|(i, _)| i)
        .collect();
    if closes.len() != 1 {
        return Ok(false);
    }
    let cutoff = closes[0];
    let bound: syn::Stmt =
        syn::parse_str(r#"ensure!(enrolled.len() == 2, "native_restore_unclosed_role_cohort");"#)?;
    Ok(body
        .get(cutoff + 1)
        .is_some_and(|s| s.to_token_stream().to_string() == bound.to_token_stream().to_string())
        && cutoff < body.len() - 9
        && methods[0].sig.inputs.iter().any(|arg| {
            matches!(arg, syn::FnArg::Typed(arg)
            if matches!(&*arg.pat, syn::Pat::Ident(p) if p.ident=="observations")
                && arg.ty.to_token_stream().to_string() == syn::parse_str::<syn::Type>("(&Costs, &mut SelfSnapshot, &mut MessageProcess)").unwrap().to_token_stream().to_string())
        }))
}

fn issuer_loop_keeps_the_same_closure(source: &str) -> anyhow::Result<bool> {
    use quote::ToTokens as _;
    use syn::visit::Visit as _;
    let file = syn::parse_file(source)?;
    let runs: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "run" => Some(item),
            _ => None,
        })
        .collect();
    if runs.len() != 1 {
        return Ok(false);
    }
    let expected: syn::Stmt = syn::parse_str("let mut issuance = Issuance::Open;")?;
    let declarations: Vec<_> = runs[0]
        .block
        .stmts
        .iter()
        .enumerate()
        .filter(|(_, stmt)| {
            stmt.to_token_stream().to_string() == expected.to_token_stream().to_string()
        })
        .map(|(i, _)| i)
        .collect();
    if declarations.len() != 1 {
        return Ok(false);
    }
    let Some(syn::Stmt::Expr(syn::Expr::Loop(_), _)) = runs[0].block.stmts.last() else {
        return Ok(false);
    };
    if declarations[0] >= runs[0].block.stmts.len() - 1 {
        return Ok(false);
    }
    #[derive(Default)]
    struct Uses {
        bindings: usize,
        references: usize,
        forwarded: usize,
    }
    impl<'a> syn::visit::Visit<'a> for Uses {
        fn visit_pat_ident(&mut self, p: &'a syn::PatIdent) {
            self.bindings += usize::from(p.ident == "issuance");
            syn::visit::visit_pat_ident(self, p);
        }
        fn visit_expr_path(&mut self, p: &'a syn::ExprPath) {
            self.references += usize::from(p.path.is_ident("issuance"));
            syn::visit::visit_expr_path(self, p);
        }
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if matches!(&*call.func,syn::Expr::Path(path) if path.path.is_ident("serve"))
                && call.args.len() == 6
                && matches!(&call.args[2],syn::Expr::Reference(r) if r.mutability.is_some() && matches!(&*r.expr,syn::Expr::Path(p) if p.path.is_ident("issuance")))
            {
                self.forwarded += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut uses = Uses::default();
    uses.visit_block(&runs[0].block);
    Ok(uses.bindings == 1 && uses.references == 1 && uses.forwarded == 1)
}

#[test]
fn actual_issuer_loop_does_not_reconstruct_closure_on_each_request() -> anyhow::Result<()> {
    use quote::ToTokens as _;
    let source = include_str!("service.rs");
    assert!(issuer_loop_keeps_the_same_closure(source)?);
    for mutation in 0..2 {
        let mut file = syn::parse_file(source)?;
        let run = file
            .items
            .iter_mut()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "run" => Some(item),
                _ => None,
            })
            .unwrap();
        let syn::Stmt::Expr(syn::Expr::Loop(body), _) = run.block.stmts.last_mut().unwrap() else {
            unreachable!()
        };
        body.body.stmts.insert(
            0,
            if mutation == 0 {
                syn::parse_str("let mut issuance = Issuance::Open;")?
            } else {
                syn::parse_str("issuance = Issuance::Open;")?
            },
        );
        assert!(!issuer_loop_keeps_the_same_closure(
            &file.to_token_stream().to_string()
        )?);
    }
    Ok(())
}

#[test]
fn issuer_freeze_keeps_same_snapshot_publication_guards_and_irreversible_cut() -> anyhow::Result<()>
{
    let source = include_str!("service.rs");
    assert!(frozen_publication_source(source)?);
    use quote::ToTokens as _;
    for mutation in 0..8 {
        let mut changed = syn::parse_file(source)?;
        let function = changed
            .items
            .iter_mut()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "freeze" => Some(item),
                _ => None,
            })
            .unwrap();
        let count = function.block.stmts.len();
        match mutation {
            0 => {
                function.block.stmts.remove(count - 7);
            }
            1 => {
                function.block.stmts.remove(count - 9);
            }
            2 | 3 => {
                let arm: syn::Stmt = syn::parse_quote! { let closing = issuance.close()?; };
                let matches: Vec<_> = function
                    .block
                    .stmts
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| {
                        s.to_token_stream().to_string() == arm.to_token_stream().to_string()
                    })
                    .map(|(i, _)| i)
                    .collect();
                assert_eq!(matches.len(), 1);
                let index = matches[0];
                if mutation == 2 {
                    function.block.stmts[index] =
                        syn::parse_quote! { let closing = issuance.require_open()?; };
                } else {
                    function.block.stmts[index + 1] = syn::parse_quote! { ensure!(enrolled.len() <= 2, "native_restore_unclosed_role_cohort"); };
                }
            }
            4 => {
                let mut modified = 0;
                for argument in &mut function.sig.inputs {
                    if let syn::FnArg::Typed(argument) = argument
                        && matches!(&*argument.pat,syn::Pat::Ident(p) if p.ident=="observations")
                        && let syn::Type::Tuple(tuple) = &mut *argument.ty
                        && let syn::Type::Reference(reference) = &mut tuple.elems[1]
                    {
                        assert!(reference.mutability.take().is_some());
                        modified += 1;
                    }
                }
                assert_eq!(modified, 1);
            }
            5 => {
                // Move the actual current check AFTER send, keeping valid Rust
                // and its returned Result. Merely swapping the semicolon-free
                // return into the middle would only test a syntax error.
                let current = function.block.stmts.remove(count - 7);
                // Keep valid Rust: move the actual native check after the
                // real send local and before its consuming retained tail.
                function.block.stmts.insert(count - 5, current);
            }
            6 => function
                .block
                .stmts
                .insert(count - 9, syn::parse_str("issuance = Issuance::Open;")?),
            7 => function.block.stmts.insert(
                count - 9,
                syn::parse_str(
                    "let mut current = SelfSnapshot::acquire(replacement, acquisition, costs)?;",
                )?,
            ),
            _ => unreachable!(),
        }
        assert!(
            !frozen_publication_source(&changed.to_token_stream().to_string())?,
            "must refuse mutation {mutation}"
        );
    }
    Ok(())
}

// Source-only checks on the actual Linux supplier. No native owner or received
// process is constructed from synthetic DATA on portable hosts.
fn retained_frozen_generation_source(source: &str) -> anyhow::Result<bool> {
    use quote::ToTokens as _;
    let file = syn::parse_file(source)?;
    let method = |owner: &str, name: &str| -> anyhow::Result<syn::Block> {
        let methods: Vec<_> = file.items.iter().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(p)
                if p.qself.is_none() && p.path.segments.len() == 1 && p.path.segments[0].ident == owner) => Some(item),
            _ => None,
        }).flat_map(|item| &item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method), _ => None,
        }).collect();
        anyhow::ensure!(methods.len() == 1, "one actual frozen-generation method");
        Ok(methods[0].block.clone())
    };
    fn required_calls(block: &syn::Block) -> Vec<String> {
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'a> syn::visit::Visit<'a> for Calls {
            fn visit_expr_try(&mut self, expression: &'a syn::ExprTry) {
                self.0
                    .push(enrollment_call_tokens(&syn::Expr::Try(expression.clone())));
                syn::visit::visit_expr_try(self, expression);
            }
        }
        let mut calls = Calls::default();
        syn::visit::Visit::visit_block(&mut calls, block);
        calls.0
    }
    let token = |text: &str| enrollment_call_tokens(&syn::parse_str::<syn::Expr>(text).unwrap());
    let capture_body = method("FrozenCohort", "capture")?;
    let capture = required_calls(&capture_body);
    let ceiling: syn::Stmt = syn::parse_quote! {
        let ceiling = statement.selection.current_deadline_data(acquisition.sample()?.elapsed)?;
    };
    if capture_body
        .stmts
        .iter()
        .filter(|statement| {
            statement.to_token_stream().to_string() == ceiling.to_token_stream().to_string()
        })
        .count()
        != 1
    {
        return Ok(false);
    }
    let operations = [
        "statement.selection.current_deadline_data(acquisition.sample()?.elapsed)?",
        "acquisition.narrow(5, ceiling)?",
        "peer.retain_message_anchor(&mut original, &costs.hashes(Subject::Requester))?",
        "bound.retain_message_anchor(&mut original, &costs.hashes(Subject::Requester))?",
        "cohort.check(costs)?",
        "acquisition.remaining()?",
    ]
    .map(token);
    let positions: Vec<_> = operations
        .iter()
        .filter(|op| capture.iter().filter(|call| *call == *op).count() == 1)
        .map(|op| capture.iter().position(|call| call == op).unwrap())
        .collect();
    if positions.len() != operations.len() || !positions.windows(2).all(|pair| pair[0] < pair[1]) {
        return Ok(false);
    }
    let check = required_calls(&method("FrozenCohort", "check")?);
    let signature = token(
        r#"protocol::verify(&self.certificate.data.public_key, "restore-issuer-frozen", &self.statement, &self.signature)?"#,
    );
    let peers = token(
        "MessageProcess::check_same_actor(&mut [&mut self.controller, &mut self.bound], &mut self.original, &costs.hashes(Subject::Requester))?",
    );
    let close = method("Issuance", "close")?.to_token_stream().to_string();
    let finish = method("ClosingFreeze", "retain_frozen")?
        .to_token_stream()
        .to_string();
    Ok(check.iter().filter(|call| **call == signature).count() == 1
        && check.iter().filter(|call| **call == peers).count() == 1
        && close.contains("* self = Self :: Refused")
        && close.contains("ClosingFreeze { issuance : self }")
        && !close.contains("Frozen (")
        && finish.contains("* self . issuance = Issuance :: Frozen")
        && !finish.contains("Issuance :: Open"))
}

#[test]
fn frozen_generation_keeps_real_controller_anchors_and_original_without_data_reconstruction()
-> anyhow::Result<()> {
    use quote::ToTokens as _;
    let source = include_str!("service.rs");
    assert!(retained_frozen_generation_source(source)?);
    for mutation in 0..6 {
        let mut parsed = syn::parse_file(source)?;
        let (owner, method) = match mutation {
            0..=2 => ("FrozenCohort", "capture"),
            3 => ("FrozenCohort", "check"),
            4 => ("Issuance", "close"),
            _ => ("ClosingFreeze", "retain_frozen"),
        };
        let methods: Vec<_> = parsed
            .items
            .iter_mut()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty,syn::Type::Path(p)
                if p.path.segments.len()==1 && p.path.segments[0].ident==owner) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| &mut item.items)
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == method => Some(&mut item.block),
                _ => None,
            })
            .collect();
        assert_eq!(methods.len(), 1);
        let body = methods.into_iter().next().unwrap();
        match mutation {
            0 | 1 => {
                let name = if mutation == 0 {
                    "original"
                } else {
                    "controller"
                };
                let local=body.stmts.iter_mut().find_map(|statement|match statement {
                    syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(p)if p.ident==name)=>Some(local),_=>None,
                }).unwrap();
                *local.init.as_mut().unwrap().expr =
                    if mutation == 0 {
                        syn::parse_quote!(NativeAcquisition::begin(5)?)
                    } else {
                        syn::parse_quote!(bound.retain_message_anchor(
                            &mut original,
                            &costs.hashes(Subject::Requester)
                        )?)
                    };
            }
            2 => {
                let target=body.stmts.iter_mut().find(|statement|matches!(statement,
                    syn::Stmt::Expr(syn::Expr::Try(value),_) if enrollment_call_tokens(&value.expr)=="cohort . check (costs)"
                )).unwrap();
                *target = syn::parse_quote!(let _ = cohort.check(costs););
            }
            3 => {
                let syn::Stmt::Local(local) = &mut body.stmts[0] else {
                    unreachable!()
                };
                let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
                    unreachable!()
                };
                let syn::Expr::Paren(paren) = &mut *call.func else {
                    unreachable!()
                };
                let syn::Expr::Closure(closure) = &mut *paren.expr else {
                    unreachable!()
                };
                let syn::Expr::Block(block) = &mut *closure.body else {
                    unreachable!()
                };
                let target=block.block.stmts.iter_mut().find(|statement|matches!(statement,
                    syn::Stmt::Expr(syn::Expr::Try(value),_) if matches!(&*value.expr,syn::Expr::Call(call)
                        if matches!(&*call.func,syn::Expr::Path(path) if path.path.segments.last().is_some_and(|name|name.ident=="verify")))
                )).unwrap();
                *target = syn::parse_quote!(let _unchecked_signature=(););
            }
            4 => body.stmts[1] = syn::parse_quote!(*self=Self::Open;),
            _ => body.stmts[1] = syn::parse_quote!(*self.issuance=Issuance::Open;),
        }
        assert!(
            !retained_frozen_generation_source(&parsed.to_token_stream().to_string())?,
            "mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn frozen_capture_refuses_cold_deadline_substitution_or_fresh_clock_replacement()
-> anyhow::Result<()> {
    use quote::ToTokens as _;
    let source = include_str!("service.rs");
    assert!(retained_frozen_generation_source(source)?);
    let original =
        "let ceiling = statement.selection.current_deadline_data(acquisition.sample()?.elapsed)?;";
    for replacement in [
        "let ceiling = std::time::Duration::from_nanos(statement.selection.controller.stage.data.deadline_ns.min(statement.selection.app.stage.data.deadline_ns));",
        "let ceiling = std::time::Duration::MAX;",
        "let ceiling = statement.selection.current_deadline_data(acquisition.sample()?.elapsed).unwrap_or(std::time::Duration::MAX);",
    ] {
        let mut parsed = syn::parse_file(source)?;
        let mut replaced = 0;
        for item in &mut parsed.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if !matches!(&*item.self_ty, syn::Type::Path(p) if p.path.is_ident("FrozenCohort")) {
                continue;
            }
            for method in &mut item.items {
                let syn::ImplItem::Fn(method) = method else {
                    continue;
                };
                if method.sig.ident != "capture" {
                    continue;
                }
                let expected = syn::parse_str::<syn::Stmt>(original)?
                    .to_token_stream()
                    .to_string();
                for statement in &mut method.block.stmts {
                    if statement.to_token_stream().to_string() == expected {
                        *statement = syn::parse_str(replacement)?;
                        replaced += 1;
                    }
                }
            }
        }
        assert_eq!(replaced, 1);
        assert!(!retained_frozen_generation_source(
            &parsed.to_token_stream().to_string()
        )?);
    }
    Ok(())
}

fn actual_restore_role_method(source: &str, owner: &str, method: &str) -> String {
    use quote::ToTokens;
    let source = syn::parse_file(source).unwrap();
    let methods = source
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == owner) {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == method => Some(item),
                _ => None,
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(methods.len(), 1);
    methods[0].block.to_token_stream().to_string()
}

fn restore_role_factory_order(body: &str) -> bool {
    let mut tail = body;
    for expected in [
        "self.pending.installation_attempted=true;",
        "self.check()?;",
        "receiver.original.interval_data()?",
        "receiver.original.narrow(5,deadline)?",
        "receiver.original.narrow(5,deadline)?.into_connection_clock()?",
        "Rc::clone(&receiver.key)",
        "Rc::clone(&receiver.policy_file)",
        "Rc::clone(&receiver.current)",
        "Rc::clone(&process.grant_peer)",
        "Rc::clone(&process.nonce_peer)",
        "Rc::clone(&process.channel)",
        "let checked=self.check();",
        "requested.is_err() || checked.is_err()",
        "self.pending.refuse();",
        "requested?;",
        "checked?;",
        "history:self",
        "PendingRestoredEnrollment::from_restore(port)",
    ] {
        let expected = native_source_tokens(expected);
        let Some(at) = tail.find(&expected) else {
            return false;
        };
        tail = &tail[at + expected.len()..];
    }
    ![
        "NativeAcquisition::begin",
        "KeyOwner::generate",
        "enroll_current_thread",
        "store::open",
        "begin_current_request",
        "begin_current_stage",
    ]
    .iter()
    .any(|forbidden| body.contains(&native_source_tokens(forbidden)))
}

#[test]
fn actual_pending_restore_spends_before_shared_resources_and_preserves_native_posts() {
    let source = include_str!("restored/activation.rs");
    let body = actual_restore_role_method(source, "AcceptedRestoredApp", "prepare_ordinary_role");
    assert!(restore_role_factory_order(&body));
    for (from, to) in [
        ("self.pending.installation_attempted=true;", ""),
        ("Rc::clone(&receiver.key)", "Rc::clone(&other.key)"),
        (
            "let original=receiver.original.narrow(5,deadline)?;",
            "let original=NativeAcquisition::begin(5)?;",
        ),
        (
            "let checked=self.check();",
            "let checked=Ok::<(),anyhow::Error>(());",
        ),
        ("history:self", "history:other"),
    ] {
        let from = native_source_tokens(from);
        assert_eq!(body.matches(&from).count(), 1);
        let changed = body.replacen(&from, &native_source_tokens(to), 1);
        assert!(!restore_role_factory_order(&changed));
    }
}

#[test]
fn actual_pending_restore_checks_borrow_old_original_and_always_check_old_history() {
    let source = include_str!("owner.rs");
    let body = actual_restore_role_method(source, "PendingRestoredEnrollment", "check");
    let expected = [
        "self.history.check()?;",
        "self.original.interval_data()?",
        "StageAcquisition::borrowed(&mut self.original)",
        "stage.check()",
        "let checked=self.history.check();",
        "requested.is_err() || checked.is_err()",
        "self.original.refuse();",
        "self.owner.refused=true;",
        "self.history.refuse();",
        "requested?;checked",
    ];
    let ordered = |body: &str| {
        let mut rest = body;
        for part in &expected {
            let part = native_source_tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        true
    };
    assert!(ordered(&body));
    for part in &expected {
        let target = native_source_tokens(part);
        assert_eq!(body.matches(&target).count(), 1);
        assert!(!ordered(&body.replacen(&target, "", 1)));
    }
    for forbidden in [
        "begin_current",
        "NativeAcquisition::begin",
        "KeyOwner::generate",
        "into_owner",
        "finish_known",
        "Runtime::",
        "store::open",
    ] {
        assert!(!body.contains(&native_source_tokens(forbidden)));
    }
    let factory = actual_restore_role_method(source, "PendingRestoredEnrollment", "from_restore");
    for flag in [
        "initial_holder_attempted:true",
        "initial_handshake_attempted:true",
        "serving_attempted:true",
    ] {
        assert!(factory.contains(&native_source_tokens(flag)));
    }
}

#[test]
fn pending_restore_drop_poisons_actual_original_without_borrowing_shared_resources() {
    let body = actual_restore_role_method(
        include_str!("owner.rs"),
        "PendingRestoredEnrollment",
        "drop",
    );
    assert!(body.contains(&native_source_tokens("self.original.refuse();")));
    assert!(body.contains(&native_source_tokens("self.owner.refused=true;")));
    assert!(body.contains(&native_source_tokens("self.history.refuse();")));
    for forbidden in [
        "borrow",
        "try_borrow",
        "catch_unwind",
        "if self.complete",
        "Ok(",
    ] {
        assert!(!body.contains(forbidden));
    }
}

#[test]
fn actual_restored_runtime_build_never_reopens_or_initializes_the_first_keeper() {
    fn factory_closed(body: &str) -> bool {
        let required = [
            "birth.check()?;",
            "birth.runtime_inputs_data()?",
            "InitialStoreMetadata::admit",
            "native_database:Some(NativeDatabaseSelection {path:db})",
            "let checked=birth.reobserve();",
            "requested.is_err() || checked.is_err()",
            "birth.refuse();",
            "let runtime=requested?;",
            "checked?;",
            "Ok(runtime)",
        ];
        let mut tail = body;
        for part in required {
            let part = native_source_tokens(part);
            let Some(at) = tail.find(&part) else {
                return false;
            };
            tail = &tail[at + part.len()..];
        }
        ![
            "open_existing",
            "Connection::open",
            "SQLITE_OPEN_CREATE",
            "DATABASE",
            "initialize",
            "finish_known",
            "finish_scope",
            "NativeAcquisition::begin",
        ]
        .iter()
        .any(|term| body.contains(&native_source_tokens(term)))
    }
    let body = actual_restore_role_method(
        include_str!("../../store/native_storage.rs"),
        "Runtime",
        "load_restored_storage",
    );
    assert!(factory_closed(&body));
    for (from, to) in [
        ("birth.runtime_inputs_data()?", "supplied_metadata"),
        (
            "native_database:Some(NativeDatabaseSelection {path:db})",
            "native_database:None",
        ),
        (
            "let checked=birth.reobserve();",
            "let checked=Ok::<(),anyhow::Error>(());",
        ),
        ("checked?;", ""),
        (
            "Ok(runtime)",
            "{let _=open_existing(&runtime.db)?;Ok(runtime)}",
        ),
    ] {
        let from = native_source_tokens(from);
        assert_eq!(body.matches(&from).count(), 1);
        assert!(!factory_closed(&body.replacen(
            &from,
            &native_source_tokens(to),
            1
        )));
    }
}

#[test]
fn restored_runtime_is_prepared_only_inside_the_consumed_pending_factory() {
    use syn::visit::Visit;
    let source = include_str!("restored/activation.rs");
    let body = actual_restore_role_method(source, "AcceptedRestoredApp", "prepare_ordinary_role");
    let runtime = native_source_tokens("let runtime=self.prepare_runtime()?;");
    let port = native_source_tokens("let port=super::super::RestoredRoleInstallPort");
    assert!(body.find(&runtime).unwrap() < body.find(&port).unwrap());
    let prepared = actual_restore_role_method(source, "AcceptedRestoredApp", "prepare_runtime");
    assert!(prepared.contains(&native_source_tokens("keeper: &mut input.received.keeper")));
    assert!(prepared.contains(&native_source_tokens("let checked=birth.check();")));
    assert!(prepared.contains(&native_source_tokens("birth.completed=true;")));
    struct Origins {
        current: Option<String>,
        owners: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Origins {
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let prior = self.current.replace(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
            self.current = prior;
        }
        fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
            if item
                .path
                .segments
                .last()
                .is_some_and(|name| name.ident == "RestoredRuntimeBirth")
            {
                self.owners.push(self.current.clone().unwrap_or_default());
            }
            syn::visit::visit_expr_struct(self, item);
        }
    }
    let mut origins = Origins {
        current: None,
        owners: Vec::new(),
    };
    origins.visit_file(&syn::parse_file(source).unwrap());
    assert_eq!(origins.owners, ["prepare_runtime"]);
    let pending = actual_restore_role_method(
        include_str!("owner.rs"),
        "PendingRestoredEnrollment",
        "from_restore",
    );
    let stable_runtime = |body: &str| {
        body.matches(&native_source_tokens(
            "runtime:std::sync::Arc::new(port.runtime)",
        ))
        .count()
            == 1
            && !["port.runtime.clone()", "Arc::make_mut", "Arc::try_unwrap"]
                .iter()
                .any(|term| body.contains(&native_source_tokens(term)))
    };
    assert!(stable_runtime(&pending));
    for replacement in [
        "runtime:port.runtime",
        "runtime:std::sync::Arc::new(port.runtime.clone())",
        "runtime:std::sync::Arc::new(other.runtime)",
    ] {
        assert!(!stable_runtime(&pending.replacen(
            &native_source_tokens("runtime:std::sync::Arc::new(port.runtime)"),
            &native_source_tokens(replacement),
            1,
        )));
    }
    use quote::ToTokens;
    let owner = syn::parse_file(include_str!("owner.rs")).unwrap();
    let runtime = owner
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "PendingRestoredEnrollment" => item
                .fields
                .iter()
                .find(|field| field.ident.as_ref().is_some_and(|name| name == "runtime")),
            _ => None,
        })
        .unwrap();
    assert!(matches!(runtime.vis, syn::Visibility::Inherited));
    let expected: syn::Type = syn::parse_quote!(std::sync::Arc<crate::store::Runtime>);
    assert_eq!(
        runtime.ty.to_token_stream().to_string(),
        expected.to_token_stream().to_string()
    );
}

#[test]
fn actual_pending_reader_spans_error_and_unwind_without_exporting_an_observation() {
    fn ordered(body: &str) -> bool {
        let mut tail = body;
        for part in [
            "let mut attempt=PendingReaderAttempt {owner:self,completed:false,};",
            "attempt.owner.check()?;",
            "attempt.owner.history.restored_reader_data(selection)",
            "let checked=attempt.owner.check();",
            "requested.is_err() || checked.is_err()",
            "attempt.owner.refuse();",
            "let reader=requested?;",
            "checked?;",
            "attempt.completed=true;",
            "Ok(reader)",
        ] {
            let part = native_source_tokens(part);
            let Some(at) = tail.find(&part) else {
                eprintln!("missing required body fragment: {part}");
                return false;
            };
            tail = &tail[at + part.len()..];
        }
        true
    }
    let body = actual_restore_role_method(
        include_str!("owner.rs"),
        "PendingRestoredEnrollment",
        "checked_restored_reader_data",
    );
    assert!(ordered(&body));
    for (part, replacement) in [
        ("owner:self,completed:false", "owner:self,completed:true"),
        (
            "let checked=attempt.owner.check();",
            "let checked=Ok::<(),anyhow::Error>(());",
        ),
        ("checked?;", ""),
        ("attempt.owner.refuse();", ""),
    ] {
        let part = native_source_tokens(part);
        assert_eq!(body.matches(&part).count(), 1);
        assert!(!ordered(&body.replacen(
            &part,
            &native_source_tokens(replacement),
            1
        )));
    }
    for forbidden in [
        "NativeAcquisition::begin",
        "Budget::from",
        "RestoredEpochObservation",
        "begin_current_request",
        "CounterRequest",
        "finish_known",
    ] {
        assert!(!body.contains(&native_source_tokens(forbidden)));
    }
    let drop = actual_restore_role_method(include_str!("owner.rs"), "PendingReaderAttempt", "drop");
    assert!(drop.contains(&native_source_tokens(
        "if !self.completed {self.owner.refuse();}"
    )));
    assert!(!drop.contains("borrow"));
    let data = actual_restore_role_method(
        include_str!("restored/activation.rs"),
        "AcceptedRestoredApp",
        "restored_reader_data",
    );
    for part in [
        "&peer.process.receiver.policy.store==selection",
        "peer.local.holder_data()?",
        "selection,&peer.projection,&actual.activation,&holder",
    ] {
        let part = native_source_tokens(part);
        assert_eq!(data.matches(&part).count(), 1, "{part}");
    }
}

#[test]
fn actual_pending_counter_pairs_before_admission_and_reads_only_under_old_original() {
    fn ordered(body: &str) -> bool {
        let mut tail = body;
        for part in [
            "PendingReaderAttempt",
            "attempt.owner.check()?;",
            "attempt.owner.history.restored_reader_data(&selected)?",
            "lineage.require_restored_reader_data(&expected)?",
            "attempt.owner.original.interval_data()?",
            "StageAcquisition::borrowed(&mut attempt.owner.original)",
            "attempt.owner.counter.admit",
            "attempt.owner.counter.request",
            "lineage.read(&selected,&mut reads,&mut stage)?",
            "lineage.check(&selected,&mut reads,&mut stage,&mut observed)?",
            "reads.finish(&mut stage)?",
            "let checked=attempt.owner.check();",
            "requested.is_err() || checked.is_err()",
            "attempt.owner.refuse();",
            "let observed=requested?;",
            "checked?;",
            "attempt.completed=true;",
            "Ok(observed)",
        ] {
            let part = native_source_tokens(part);
            let Some(at) = tail.find(&part) else {
                return false;
            };
            tail = &tail[at + part.len()..];
        }
        true
    }
    let body = actual_restore_role_method(
        include_str!("owner.rs"),
        "PendingRestoredEnrollment",
        "admit_current",
    );
    assert!(ordered(&body));
    for (from, to) in [
        ("lineage.require_restored_reader_data(&expected)?;", ""),
        (
            "StageAcquisition::borrowed(&mut attempt.owner.original)",
            "StageAcquisition::owned(NativeAcquisition::begin(5)?)",
        ),
        (
            "lineage.read(&selected,&mut reads,&mut stage)?",
            "cached_observation",
        ),
        ("reads.finish(&mut stage)?;", ""),
        (
            "let checked=attempt.owner.check();",
            "let checked=Ok::<(),anyhow::Error>(());",
        ),
    ] {
        let from = native_source_tokens(from);
        assert_eq!(body.matches(&from).count(), 1);
        assert!(!ordered(&body.replacen(
            &from,
            &native_source_tokens(to),
            1
        )));
    }
    for forbidden in [
        "NativeAcquisition::begin",
        "begin_current_request",
        "RestoredEpochObservation",
        "into_connection_clock",
        "store::open",
        "Runtime::",
        "finish_known",
    ] {
        assert!(!body.contains(&native_source_tokens(forbidden)));
    }
}

// These controls inspect actual production bodies, not an alternate native
// owner. Linux keeper/peer conformance remains a separate qualification gate.
fn restored_history_method(source: &str, owner: &str, name: &str) -> String {
    use quote::ToTokens;
    let file = syn::parse_file(source).unwrap();
    let mut methods = file.items.into_iter().filter_map(|item| {
        let syn::Item::Impl(item) = item else {
            return None;
        };
        let syn::Type::Path(path) = &*item.self_ty else {
            return None;
        };
        if !path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == owner)
        {
            return None;
        }
        item.items.into_iter().find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == name => {
                use syn::visit::Visit;
                // Normalize only optional terminal separators on actual call
                // arguments and named struct fields. Tuple commas remain real.
                struct OptionalSeparators {
                    replacements: Vec<(String, String)>,
                }
                impl<'ast> Visit<'ast> for OptionalSeparators {
                    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
                        if item.args.trailing_punct() {
                            let mut normalized = item.clone();
                            normalized.args.pop_punct();
                            self.replacements.push((
                                native_source_tokens(&item.to_token_stream().to_string()),
                                native_source_tokens(&normalized.to_token_stream().to_string()),
                            ));
                        }
                        syn::visit::visit_expr_call(self, item);
                    }
                    fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
                        if item.args.trailing_punct() {
                            let mut normalized = item.clone();
                            normalized.args.pop_punct();
                            self.replacements.push((
                                native_source_tokens(&item.to_token_stream().to_string()),
                                native_source_tokens(&normalized.to_token_stream().to_string()),
                            ));
                        }
                        syn::visit::visit_expr_method_call(self, item);
                    }
                    fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                        if item.rest.is_none() && item.fields.trailing_punct() {
                            let mut normalized = item.clone();
                            normalized.fields.pop_punct();
                            self.replacements.push((
                                native_source_tokens(&item.to_token_stream().to_string()),
                                native_source_tokens(&normalized.to_token_stream().to_string()),
                            ));
                        }
                        syn::visit::visit_expr_struct(self, item);
                    }
                }
                let mut separators = OptionalSeparators {
                    replacements: Vec::new(),
                };
                separators.visit_block(&item.block);
                let mut body = native_source_tokens(&item.block.into_token_stream().to_string());
                for (before, after) in separators.replacements {
                    body = body.replace(&before, &after);
                }
                Some(body)
            }
            _ => None,
        })
    });
    let method = methods.next().unwrap();
    assert!(methods.next().is_none());
    method
}

#[test]
fn restored_history_source_controls_preserve_tuple_shape_and_normalize_only_optional_separators() {
    let source = "impl Controls {fn a(){call(1,);let x=Input {v:1,};take((x,));}fn b(){call(1);let x=Input {v:1};take((x,));}fn c(){call(1);let x=Input {v:1};take((x));}}";
    assert_eq!(
        restored_history_method(source, "Controls", "a"),
        restored_history_method(source, "Controls", "b")
    );
    assert_ne!(
        restored_history_method(source, "Controls", "b"),
        restored_history_method(source, "Controls", "c")
    );
    let update = "impl Controls {fn update(){let x=Input {v:1,..base};}fn range(){let x=Input {v:1..base};}}";
    assert_ne!(
        restored_history_method(update, "Controls", "update"),
        restored_history_method(update, "Controls", "range")
    );
}

fn restored_history_order(body: &str, expected: &[&str]) -> bool {
    let mut tail = body;
    for part in expected {
        let part = native_source_tokens(part);
        let Some(at) = tail.find(&part) else {
            return false;
        };
        tail = &tail[at + part.len()..];
    }
    true
}

#[test]
fn actual_history_slot_owns_whole_keeper_before_wait_and_restores_before_positive_result() {
    let source = include_str!("restored/activation.rs");
    let take = restored_history_method(source, "RestoredHistoryLoan", "take");
    let take_order = [
        "!root.refused.get()",
        "!root.channel_refusal.get()",
        "root.retained.take()",
        "history:Some(history)",
        "if requested.is_err() {root.refuse();}",
    ];
    let take_flow = |body: &str| {
        if !restored_history_order(body, &take_order) {
            return false;
        }
        let Ok(block) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        matches!(block.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Path(path),None)) if path.path.is_ident("requested"))
    };
    assert!(take_flow(&take));
    let mut wrong_return = syn::parse_str::<syn::Block>(&take).unwrap();
    *wrong_return.stmts.last_mut().unwrap() = syn::Stmt::Expr(syn::parse_quote!(unchecked), None);
    use quote::ToTokens;
    assert!(!take_flow(&native_source_tokens(
        &wrong_return.to_token_stream().to_string()
    )));
    let check = restored_history_method(source, "RestoredAppHistory", "check");
    let check_order = [
        "RestoredHistoryLoan::take(self)?",
        "let requested=loan.history.as_mut()",
        ".check();",
        "if requested.is_err() {self.refuse();}",
        "let checked=loan.finish();",
        "requested?;checked",
    ];
    assert!(restored_history_order(&check, &check_order));
    for part in take_order {
        let part = native_source_tokens(part);
        assert_eq!(take.matches(&part).count(), 1);
        assert!(!take_flow(&take.replacen(&part, "", 1)));
    }
    for part in check_order {
        let part = native_source_tokens(part);
        assert_eq!(check.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &check.replacen(&part, "", 1),
            &check_order
        ));
    }
    let finish = restored_history_method(source, "RestoredHistoryLoan", "finish");
    let finish_order = [
        "self.history.take()",
        "self.root.retained.replace(Some(history))",
        "self.root.refuse();",
        "restore_history_slot_changed",
        "!self.root.refused.get()",
        "self.completed=true;",
        "Ok(())",
    ];
    assert!(restored_history_order(&finish, &finish_order));
    for part in finish_order {
        let part = native_source_tokens(part);
        assert_eq!(finish.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &finish.replacen(&part, "", 1),
            &finish_order
        ));
    }
    for body in [&take, &check, &finish] {
        for forbidden in [
            "borrow_mut",
            "try_borrow",
            "callback",
            "NativeAcquisition::begin",
            "finish_known",
        ] {
            assert!(!body.contains(&native_source_tokens(forbidden)));
        }
    }
}

#[test]
fn actual_shared_history_negative_teardown_never_borrows_or_checks_expired_originals() {
    let source = include_str!("restored/activation.rs");
    let refuse = restored_history_method(source, "RestoredAppHistory", "refuse");
    for part in [
        "self.refused.set(true);",
        "self.receiver_refusal.refuse();",
        "self.reader_refusal.refuse();",
        "self.channel_refusal.set(true);",
    ] {
        assert_eq!(refuse.matches(&native_source_tokens(part)).count(), 1);
    }
    for forbidden in [
        "retained",
        "borrow",
        "remaining",
        "check",
        "sample",
        "catch_unwind",
        "wait",
    ] {
        assert!(!refuse.contains(forbidden));
    }
    let drop = restored_history_method(include_str!("restored.rs"), "RestoredHistoryLoan", "drop");
    assert!(restored_history_order(
        &drop,
        &[
            "if !self.completed {self.root.refuse();}",
            "self.history.take()",
            "self.root.retained.replace(Some(history))",
            "self.root.refuse();",
            "drop(unexpected);"
        ]
    ));
    let factory = restored_history_method(source, "AcceptedRestoredApp", "retain_history");
    let expected = [
        "self.check()?;",
        "actual.captured.peer.process.receiver.original.retained_refusal()",
        "actual.original.retained_refusal()",
        "std::rc::Rc::clone(&actual.captured.peer.channel.refused)",
        "let checked=self.check();",
        "requested.is_err() || checked.is_err()",
        "self.refuse();",
        "requested?;",
        "checked?;",
        "Cell::new(Some(self))",
    ];
    assert!(restored_history_order(&factory, &expected));
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(factory.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &factory.replacen(&part, "", 1),
            &expected
        ));
    }
}

#[test]
fn actual_restored_file_continuity_uses_current_stage_and_same_first_keeper_only() {
    let source = include_str!("restored/activation.rs");
    let wrapper = restored_history_method(source, "RestoredAppHistory", "check_current_resources");
    let wrapper_expected = [
        "RestoredHistoryLoan::take(self)?",
        "loan.history.as_mut()",
        ".and_then(|accepted|accepted.check_current_keeper(stage))",
        "let checked=stage.check();",
        "requested.is_err() || checked.is_err()",
        "self.refuse();",
        "let restored=loan.finish();",
        "requested?;checked?;restored",
    ];
    assert!(restored_history_order(&wrapper, &wrapper_expected));
    for part in wrapper_expected {
        let target = native_source_tokens(part);
        assert_eq!(wrapper.matches(&target).count(), 1);
        assert!(!restored_history_order(
            &wrapper.replacen(&target, "", 1),
            &wrapper_expected
        ));
    }
    let actual = restored_history_method(source, "AcceptedRestoredApp", "check_current_keeper");
    let expected = [
        "let keeper = &mut input.received.keeper;",
        "stage.require_current_role()?;",
        "stage.check_selection(&policy.bootstrap,&policy.store,super::super::NativeRole::AppHost)?;",
        "keeper.input.owner.captured.check_anchors()?;",
        "keeper.keeper.check(&keeper.input.owner.captured.directory,&keeper.input.owner.captured.file)",
    ];
    assert!(restored_history_order(&actual, &expected));
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(actual.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &actual.replacen(&part, "", 1),
            &expected
        ));
    }
    let forbidden = [
        "receiver.original",
        "remaining",
        "reobserve",
        "transcript",
        "receiver.check",
        "history.check",
        "self.check()",
        "NativeAcquisition::begin",
        "try_clone",
        "Connection::open",
        "receive_restore",
        "send_restore",
    ];
    let safe = |body: &str| {
        forbidden
            .iter()
            .all(|part| !body.contains(&native_source_tokens(part)))
    };
    assert!(safe(&wrapper));
    assert!(safe(&actual));
    for injection in [
        "let _renewed=NativeAcquisition::begin(5)?;",
        "keeper.input.owner.captured.peer.process.receiver.original.remaining()?;",
    ] {
        let mut changed = syn::parse_str::<syn::Block>(&actual).unwrap();
        let syn::Stmt::Expr(syn::Expr::Block(linux), _) = changed.stmts.last_mut().unwrap() else {
            panic!("actual native helper body");
        };
        linux
            .block
            .stmts
            .insert(0, syn::parse_str(injection).unwrap());
        let changed = restored_history_method(
            &format!(
                "impl Injected {{fn check() {}}}",
                quote::ToTokens::to_token_stream(&changed)
            ),
            "Injected",
            "check",
        );
        assert!(!safe(&changed), "{injection}");
    }
    let current = restored_history_method(
        include_str!("owner.rs"),
        "RestoredAppFileContinuity",
        "check_current",
    );
    assert!(restored_history_order(
        &current,
        &[
            "stage.require_current_role()?;",
            "self.same.check(stage)?;",
            "self.history.check_current_resources(stage)",
            "let checked=self.same.check(stage);",
            "self.history.refuse();",
            "requested?;checked"
        ]
    ));
}

#[test]
fn actual_restored_file_factory_spends_before_check_and_retains_both_old_posts() {
    let actual = restored_history_method(
        include_str!("owner.rs"),
        "PendingRestoredEnrollment",
        "prepare_file_continuity",
    );
    let expected = [
        "PendingReaderAttempt {owner:self,completed:false}",
        "!attempt.owner.file_continuity_attempted",
        "attempt.owner.file_continuity_attempted=true;",
        "attempt.owner.check()?;",
        "attempt.owner.original.interval_data()?",
        "StageAcquisition::borrowed(&mut attempt.owner.original)",
        "stage.capture_same_owner()?",
        "Rc::clone(&attempt.owner.history)",
        "file.check_current(&mut stage)?;",
        "let checked=attempt.owner.check();",
        "requested.is_err() || checked.is_err()",
        "attempt.owner.refuse();",
        "let file=requested?;",
        "checked?;",
        "attempt.completed=true;",
    ];
    let factory_flow = |body: &str| {
        if !restored_history_order(body, &expected) {
            return false;
        }
        let Ok(block) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        use quote::ToTokens;
        matches!(block.stmts.last(),Some(syn::Stmt::Expr(expression,None)) if native_source_tokens(&expression.to_token_stream().to_string()) == native_source_tokens("Ok(file)"))
    };
    assert!(factory_flow(&actual));
    use quote::ToTokens;
    let mut wrong_return = syn::parse_str::<syn::Block>(&actual).unwrap();
    *wrong_return.stmts.last_mut().unwrap() =
        syn::Stmt::Expr(syn::parse_quote!(Ok(other_file)), None);
    assert!(!factory_flow(&native_source_tokens(
        &wrong_return.to_token_stream().to_string()
    )));
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(actual.matches(&part).count(), 1);
        assert!(!factory_flow(&actual.replacen(&part, "", 1)));
    }
    for forbidden in [
        "NativeAcquisition::begin",
        "begin_current",
        "store::open",
        "finish_known",
        "Runtime::",
    ] {
        assert!(!actual.contains(&native_source_tokens(forbidden)));
    }
}

#[test]
fn actual_restored_file_continuity_can_only_be_built_by_its_genuine_pending_owner() {
    use quote::ToTokens;
    use syn::visit::Visit;
    fn closed(sources: &[&str]) -> bool {
        struct Origins {
            owner: Option<String>,
            method: Option<String>,
            constructed: usize,
            closed: bool,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                if item.attrs.iter().any(|attr|matches!(&attr.meta,syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string()=="test")) {return;}
                syn::visit::visit_item_mod(self, item);
            }
            fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                let old = self.owner.take();
                self.owner = match &*item.self_ty {
                    syn::Type::Path(path) => {
                        path.path.segments.last().map(|part| part.ident.to_string())
                    }
                    _ => None,
                };
                syn::visit::visit_item_impl(self, item);
                self.owner = old;
            }
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let old = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = old;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                let name = item.path.segments.last().map(|part| part.ident.to_string());
                if name.as_deref() == Some("RestoredAppFileContinuity")
                    || (name.as_deref() == Some("Self")
                        && self.owner.as_deref() == Some("RestoredAppFileContinuity"))
                {
                    self.constructed += 1;
                    self.closed &= self.owner.as_deref()==Some("PendingRestoredEnrollment")
                        && self.method.as_deref()==Some("prepare_file_continuity") && item.rest.is_none() && item.fields.len()==2
                        && item.fields.iter().all(|field|match &field.member {
                            syn::Member::Named(name) if name=="history"=>native_source_tokens(&field.expr.to_token_stream().to_string())==native_source_tokens("Rc::clone(&attempt.owner.history)"),
                            syn::Member::Named(name) if name=="same"=>matches!(&field.expr,syn::Expr::Path(path) if path.path.is_ident("same")),
                            _=>false,
                        });
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let mut origins = Origins {
            owner: None,
            method: None,
            constructed: 0,
            closed: true,
        };
        for source in sources {
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            origins.visit_file(&file);
        }
        origins.closed && origins.constructed == 1
    }
    let source = include_str!("owner.rs");
    let children = [
        include_str!("owner/restore.rs"),
        include_str!("owner/restore_receiver.rs"),
        include_str!("owner/serving.rs"),
        include_str!("owner/storage.rs"),
    ];
    let all = |root: &str| closed(&[root, children[0], children[1], children[2], children[3]]);
    assert!(all(source));
    let fake = "impl RestoredAppFileContinuity {fn adopt(history:Rc<RestoredAppHistory>,same:SameEnrolledOwner)->Self {Self {history,same}}}";
    assert!(!all(&(source.to_owned() + fake)));
    // The peer-continuity constructor legitimately clones this same history
    // too. Mutate only the actual file factory, never a whole-file occurrence.
    let mut changed = syn::parse_file(source).unwrap();
    let mut selected = 0;
    for item in &mut changed.items {
        if let syn::Item::Impl(item) = item
            && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("PendingRestoredEnrollment"))
        {
            for item in &mut item.items {
                if let syn::ImplItem::Fn(item) = item
                    && item.sig.ident == "prepare_file_continuity"
                {
                    let body = item.block.to_token_stream().to_string();
                    let target = native_source_tokens("history: Rc::clone(&attempt.owner.history)");
                    assert_eq!(body.matches(&target).count(), 1);
                    item.block = syn::parse_str(&body.replacen(
                        &target,
                        &native_source_tokens("history: Rc::clone(&other.history)"),
                        1,
                    ))
                    .unwrap();
                    selected += 1;
                }
            }
        }
    }
    assert_eq!(selected, 1);
    assert!(!all(&changed.to_token_stream().to_string()));
    assert!(!include_str!("restored/activation.rs").contains("fn from_pending("));
}

#[test]
fn actual_restored_current_peer_checks_retain_whole_history_and_independent_fresh_post() {
    use quote::ToTokens;
    let actual = restored_history_method(
        include_str!("restored/activation.rs"),
        "RestoredAppHistory",
        "check_current_peer_anchors",
    );
    let closed = |body: &str| {
        let Ok(block) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        let expected: syn::Block = syn::parse_quote!({
            let mut loan = RestoredHistoryLoan::take(self)?;
            let requested: Result<()> = (|| {})();
            let checked = stage
                .storage()
                .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let restored = loan.finish();
            requested?;
            checked?;
            restored
        });
        block.stmts.len() == expected.stmts.len()
            && block.stmts[0].to_token_stream().to_string()
                == expected.stmts[0].to_token_stream().to_string()
            && block.stmts[2..]
                .iter()
                .map(|item| item.to_token_stream().to_string())
                .collect::<Vec<_>>()
                == expected.stmts[2..]
                    .iter()
                    .map(|item| item.to_token_stream().to_string())
                    .collect::<Vec<_>>()
    };
    assert!(closed(&actual));
    let wrapper_expected = [
        "loan.history.as_mut()",
        ".and_then(|accepted|accepted.check_current_peer_anchors(stage,acquisition))",
    ];
    assert!(restored_history_order(&actual, &wrapper_expected));
    for part in wrapper_expected {
        let target = native_source_tokens(part);
        assert_eq!(actual.matches(&target).count(), 1);
        assert!(!restored_history_order(
            &actual.replacen(&target, "", 1),
            &wrapper_expected
        ));
    }
    let helper = restored_history_method(
        include_str!("restored/activation.rs"),
        "AcceptedRestoredApp",
        "check_current_peer_anchors",
    );
    let expected = [
        "let peer = &mut input.received.keeper.input.owner.captured.peer;",
        "stage.require_current_role()?;",
        "stage.check_selection(&peer.process.receiver.policy.bootstrap, &peer.process.receiver.policy.store, super::super::NativeRole::AppHost)?;",
        "!peer.refused && (2..=5).contains(&peer.receipts.len())",
        "for receipt in &mut peer.receipts",
        "receipt.check_current_anchor(&peer.controller, stage, acquisition)?;",
        "peer.channel.check_current_anchor(stage, acquisition)",
    ];
    assert!(restored_history_order(&helper, &expected));
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(helper.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &helper.replacen(&part, "", 1),
            &expected
        ));
    }
    let mut conditional = syn::parse_str::<syn::Block>(&actual).unwrap();
    conditional.stmts[2] = syn::parse_quote!(let checked = Ok::<(),anyhow::Error>(()););
    assert!(!closed(&native_source_tokens(
        &conditional.to_token_stream().to_string()
    )));
    let mut wrong_return = syn::parse_str::<syn::Block>(&actual).unwrap();
    *wrong_return.stmts.last_mut().unwrap() = syn::Stmt::Expr(syn::parse_quote!(Ok(())), None);
    assert!(!closed(&native_source_tokens(
        &wrong_return.to_token_stream().to_string()
    )));
    let forbidden = [
        "receiver.original",
        "accepted.check()",
        "history.check",
        "transcript",
        "begin_current",
        "send_restore",
        "receive_restore",
        "try_clone",
        "NativeAcquisition::begin",
    ];
    let safe = |body: &str| {
        forbidden
            .iter()
            .all(|part| !body.contains(&native_source_tokens(part)))
    };
    assert!(safe(&actual));
    assert!(safe(&helper));
    for injection in [
        "let _renewed=NativeAcquisition::begin(5)?;",
        "peer.process.receiver.original.remaining()?;",
    ] {
        let mut changed = syn::parse_str::<syn::Block>(&helper).unwrap();
        let syn::Stmt::Expr(syn::Expr::Block(linux), _) = changed.stmts.last_mut().unwrap() else {
            panic!("actual native helper body");
        };
        linux
            .block
            .stmts
            .insert(0, syn::parse_str(injection).unwrap());
        let changed = restored_history_method(
            &format!(
                "impl Injected {{fn check() {}}}",
                quote::ToTokens::to_token_stream(&changed)
            ),
            "Injected",
            "check",
        );
        assert!(!safe(&changed), "{injection}");
    }
}

#[test]
fn actual_restored_current_peer_anchor_checks_use_actual_pidfds_socket_and_fresh_acquisition() {
    use quote::ToTokens;
    let source = include_str!("restored/transport.rs");
    for owner in ["RestoredControllerReceipt", "RestoreTransport"] {
        let actual = restored_history_method(source, owner, "check_current_anchor");
        let block = syn::parse_str::<syn::Block>(&actual).unwrap();
        let expected: syn::Block = if owner == "RestoredControllerReceipt" {
            syn::parse_quote!({
                let requested: Result<()> = (|| {})();
                let checked = stage
                    .storage()
                    .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
                if requested.is_err() || checked.is_err() {
                    #[cfg(target_os = "linux")]
                    {
                        self.refused = true;
                    }
                    acquisition.refuse();
                }
                requested?;
                checked
            })
        } else {
            syn::parse_quote!({
                let requested: Result<()> = (|| {})();
                let checked = stage
                    .storage()
                    .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
                if requested.is_err() || checked.is_err() {
                    self.refuse();
                    acquisition.refuse();
                }
                requested?;
                checked
            })
        };
        let outer = |block: &syn::Block| {
            block.stmts.len() == expected.stmts.len()
                && block.stmts[1..]
                    .iter()
                    .map(|item| item.to_token_stream().to_string())
                    .collect::<Vec<_>>()
                    == expected.stmts[1..]
                        .iter()
                        .map(|item| item.to_token_stream().to_string())
                        .collect::<Vec<_>>()
        };
        assert!(outer(&block));
        let mut missing_post = block.clone();
        missing_post.stmts[1] = syn::parse_quote!(let checked = Ok::<(),anyhow::Error>(()););
        assert!(!outer(&missing_post));
        let parts: &[&str] = if owner == "RestoredControllerReceipt" {
            &[
                "!self.refused",
                "self.process == std::process::id()",
                "self.thread == std::thread::current().id()",
                "stage.storage()?.check_storage_acquisition(acquisition)?;",
                "stage.storage()?.storage_statement()?",
                "self.statement.as_ref() == Some(&statement.digest()?)",
                "statement.certificate == local.certificate",
                "statement.stage.data.policy == local.stage.data.policy",
                "statement.stage.data.role == NativeRole::EpochController",
                "local.stage.data.role == NativeRole::AppHost",
                "statement.stage.data.process.process == self.sender",
                "process::live(&self.pidfd, acquisition)",
            ]
        } else {
            &[
                "!self.refused.get()",
                "stage.storage()?.check_storage_acquisition(acquisition)?;",
                "super::super::channel::require_connected(&self.socket, acquisition)",
            ]
        };
        assert!(restored_history_order(&actual, parts));
        for part in parts {
            let part = native_source_tokens(part);
            assert_eq!(actual.matches(&part).count(), 1);
            assert!(!restored_history_order(
                &actual.replacen(&part, "", 1),
                parts
            ));
        }
        for forbidden in [
            "receiver.original",
            "app.check",
            "begin_current",
            "transcript",
            "try_clone",
            "File::from",
            "NativeAcquisition::begin",
        ] {
            assert!(!actual.contains(&native_source_tokens(forbidden)));
        }
    }
}

#[test]
fn actual_restored_peer_factory_spends_before_checks_and_preserves_outer_old_posts() {
    use quote::ToTokens;
    let actual = restored_history_method(
        include_str!("owner.rs"),
        "PendingRestoredEnrollment",
        "prepare_peer_continuity",
    );
    let outer = |body: &str| {
        let Ok(block) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        let expected: syn::Block = syn::parse_quote!({
            let mut attempt = PendingReaderAttempt {
                owner: self,
                completed: false,
            };
            let requested: Result<_> = (|| {})();
            let checked = attempt.owner.check();
            if requested.is_err() || checked.is_err() {
                attempt.owner.refuse();
            }
            let peer = requested?;
            checked?;
            attempt.completed = true;
            Ok(peer)
        });
        let expected = restored_history_method(
            &format!("impl Expected {{fn body() {}}}", expected.to_token_stream()),
            "Expected",
            "body",
        );
        let expected = syn::parse_str::<syn::Block>(&expected).unwrap();
        block.stmts.len() == expected.stmts.len()
            && block.stmts[0].to_token_stream().to_string()
                == expected.stmts[0].to_token_stream().to_string()
            && block.stmts[2..]
                .iter()
                .map(|item| item.to_token_stream().to_string())
                .collect::<Vec<_>>()
                == expected.stmts[2..]
                    .iter()
                    .map(|item| item.to_token_stream().to_string())
                    .collect::<Vec<_>>()
    };
    assert!(outer(&actual));
    let expected = [
        "!attempt.owner.peer_continuity_attempted",
        "attempt.owner.peer_continuity_attempted=true;",
        "attempt.owner.check()?;",
        "attempt.owner.original.interval_data()?",
        "StageAcquisition::borrowed(&mut attempt.owner.original)",
        "let same = stage.capture_same_owner()?;",
        "RestoredAppPeerContinuity {history:Rc::clone(&attempt.owner.history),same}",
        "let mut acquisition = stage.narrow_io_acquisition(5)?;",
        "peer.check_anchors(&mut stage,&mut acquisition)?;",
    ];
    assert!(restored_history_order(&actual, &expected));
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(actual.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &actual.replacen(&part, "", 1),
            &expected
        ));
    }
    let mut no_post = syn::parse_str::<syn::Block>(&actual).unwrap();
    no_post.stmts[2] = syn::parse_quote!(let checked=Ok::<(),anyhow::Error>(()););
    assert!(!outer(&native_source_tokens(
        &no_post.to_token_stream().to_string()
    )));
    let wrong_root = native_source_tokens("Rc::clone(&attempt.owner.history)");
    assert_eq!(actual.matches(&wrong_root).count(), 1);
    assert!(!restored_history_order(
        &actual.replacen(
            &wrong_root,
            &native_source_tokens("Rc::clone(&other.history)"),
            1
        ),
        &expected
    ));
    for forbidden in [
        "NativeAcquisition::begin",
        "begin_current",
        "Transcript",
        "Channel::",
        "try_clone",
        "finish_known",
        "Runtime::",
        "store::open",
    ] {
        assert!(!actual.contains(&native_source_tokens(forbidden)));
    }
}

#[test]
fn actual_restored_peer_continuity_checks_same_owner_before_native_anchors_and_after_errors() {
    use quote::ToTokens;
    let actual = restored_history_method(
        include_str!("owner.rs"),
        "RestoredAppPeerContinuity",
        "check_anchors",
    );
    let expected = [
        "RestoredPeerAnchorAttempt {history: &self.history,acquisition,completed:false}",
        "stage.require_current_role()?;",
        "self.same.check(stage)?;",
        "self.history.check_current_peer_anchors(stage,attempt.acquisition)",
        "let checked = self.same.check(stage);",
        "self.history.refuse();",
        "attempt.acquisition.refuse();",
        "requested?;checked?;attempt.completed=true;Ok(())",
    ];
    assert!(restored_history_order(&actual, &expected));
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(actual.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &actual.replacen(&part, "", 1),
            &expected
        ));
    }
    let block = syn::parse_str::<syn::Block>(&actual).unwrap();
    let post: syn::Stmt = syn::parse_quote!(let checked=self.same.check(stage););
    assert_eq!(
        block.stmts[2].to_token_stream().to_string(),
        post.to_token_stream().to_string()
    );
    for forbidden in [
        "begin_current",
        "receiver.original",
        "history.check()",
        "send",
        "receive",
        "callback",
        "try_clone",
    ] {
        assert!(!actual.contains(&native_source_tokens(forbidden)));
    }
}

#[test]
fn actual_restored_peer_abandonment_refuses_without_borrow_or_clock_and_fields_stay_private() {
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    for (owner, expected) in [
        (
            "RestoredAppPeerContinuity",
            syn::parse_quote!({
                self.history.refuse();
            }),
        ),
        (
            "RestoredPeerAnchorAttempt",
            syn::parse_quote!({
                if !self.completed {
                    self.history.refuse();
                    self.acquisition.refuse();
                }
            }),
        ),
    ] {
        let actual =
            syn::parse_str::<syn::Block>(&restored_history_method(source, owner, "drop")).unwrap();
        let expected: syn::Block = expected;
        assert_eq!(
            actual.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }
    let file = syn::parse_file(source).unwrap();
    fn docs_only(attributes: &[syn::Attribute]) -> bool {
        attributes.iter().all(|attribute| matches!(&attribute.meta,
            syn::Meta::NameValue(value) if value.path.is_ident("doc")
                && matches!(&value.value,syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Str(_)))))
    }
    for name in ["RestoredAppPeerContinuity", "RestoredPeerAnchorAttempt"] {
        let entries = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item) if item.ident == name => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        );
        assert!(docs_only(&entries[0].attrs));
        for forbidden in [
            syn::parse_quote!(#[derive(Clone)]),
            syn::parse_quote!(#[cfg(test)]),
            syn::parse_quote!(#[allow(dead_code)]),
        ] {
            let mut changed = entries[0].attrs.clone();
            changed.push(forbidden);
            assert!(!docs_only(&changed));
        }
    }
}

#[test]
fn actual_controller_native_retirement_consumes_stage_and_moves_same_owner_only_after_retirement() {
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    let actual = restored_history_method(source, "EnrolledRoleStage", "retire_controller_native");
    let expected = [
        "ControllerNativeRetirement {stage:Some(self),completed:false}",
        "attempt.stage.as_mut()",
        "stage.require_current_role()?;",
        "stage.owner.role == NativeRole::EpochController",
        "stage.acquisition.retire_owned(&mut stage.owner.clock)",
        "let refusal = requested?;",
        "attempt.stage.take()",
        "RetainedControllerNative {owner:stage.owner,refusal}",
        "attempt.completed=true;",
        "Ok(retained)",
    ];
    assert!(restored_history_order(&actual, &expected));
    fn requested_body(block: &syn::Block) -> Option<&syn::Block> {
        let syn::Stmt::Local(local) = block.stmts.get(1)? else {
            return None;
        };
        let init = local.init.as_ref()?;
        let syn::Expr::Call(call) = &*init.expr else {
            return None;
        };
        if !call.args.is_empty() {
            return None;
        }
        let mut function = &*call.func;
        while let syn::Expr::Paren(paren) = function {
            function = &paren.expr;
        }
        let syn::Expr::Closure(closure) = function else {
            return None;
        };
        if !closure.inputs.is_empty() || closure.asyncness.is_some() {
            return None;
        }
        let syn::Expr::Block(body) = &*closure.body else {
            return None;
        };
        Some(&body.block)
    }
    fn live_guards(block: &syn::Block) -> bool {
        use syn::parse::Parser;
        let Some(body) = requested_body(block) else {
            return false;
        };
        if body.stmts.len() < 3 {
            return false;
        }
        let binding: syn::Stmt = syn::parse_quote!(let stage=attempt.stage.as_mut().ok_or_else(||anyhow::anyhow!("native_controller_retirement_stage_missing"))?;);
        let purpose: syn::Stmt = syn::parse_quote!(stage.require_current_role()?;);
        if body.stmts[0].to_token_stream().to_string() != binding.to_token_stream().to_string()
            || body.stmts[1].to_token_stream().to_string() != purpose.to_token_stream().to_string()
        {
            return false;
        }
        let syn::Stmt::Macro(guard) = &body.stmts[2] else {
            return false;
        };
        if !guard.attrs.is_empty()
            || !guard.mac.path.is_ident("ensure")
            || guard.semi_token.is_none()
        {
            return false;
        }
        let Ok(args) = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
            .parse2(guard.mac.tokens.clone())
        else {
            return false;
        };
        let required: syn::Expr =
            syn::parse_quote!(stage.owner.role == NativeRole::EpochController);
        args.len() == 2
            && args[0].to_token_stream().to_string() == required.to_token_stream().to_string()
            && matches!(&args[1],syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Str(value) if value.value()=="native_controller_retirement_role_changed"))
    }
    let block = syn::parse_str::<syn::Block>(&actual).unwrap();
    assert!(live_guards(&block));
    // Each counterexample preserves the old ordered/count witnesses while
    // removing a real unconditional purpose or Controller-role guard.
    for mutation in 0..4 {
        let mut changed = block.clone();
        let mut inner = requested_body(&changed).unwrap().clone();
        let index = if mutation == 0 { 1 } else { 2 };
        let old = inner.stmts[index].clone();
        inner.stmts[index] = if mutation == 3 {
            let syn::Stmt::Macro(mut guard) = old else {
                unreachable!();
            };
            guard.attrs.push(syn::parse_quote!(#[cfg(any())]));
            syn::Stmt::Macro(guard)
        } else if mutation == 2 {
            syn::parse_quote!(let _=stage.owner.role==NativeRole::EpochController;)
        } else {
            syn::parse_quote!(if false {#old})
        };
        let syn::Stmt::Local(local) = &mut changed.stmts[1] else {
            unreachable!();
        };
        *local.init.as_mut().unwrap().expr = syn::parse_quote!((|| #inner)());
        let text = native_source_tokens(&changed.to_token_stream().to_string());
        assert!(restored_history_order(&text, &expected));
        for guard in [
            "stage.require_current_role()",
            "stage.owner.role == NativeRole::EpochController",
        ] {
            let guard = native_source_tokens(guard);
            assert_eq!(text.matches(&guard).count(), actual.matches(&guard).count());
        }
        assert!(!live_guards(&changed));
    }
    for part in expected {
        let part = native_source_tokens(part);
        assert_eq!(actual.matches(&part).count(), 1);
        assert!(!restored_history_order(
            &actual.replacen(&part, "", 1),
            &expected
        ));
    }
    for forbidden in [
        "NativeAcquisition::begin",
        "into_connection_clock",
        "begin_current",
        "StageAcquisition::owned",
        "capture_same_owner",
        "callback",
        "try_clone",
        "finish_known",
    ] {
        assert!(!actual.contains(&native_source_tokens(forbidden)));
    }
    let file = syn::parse_file(source).unwrap();
    let mut methods=file.items.iter().filter_map(|item| {
        let syn::Item::Impl(item)=item else{return None;};
        if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|s|s.ident=="EnrolledRoleStage")) {return None;}
        item.items.iter().find_map(|item|match item {syn::ImplItem::Fn(item) if item.sig.ident=="retire_controller_native"=>Some(item),_=>None})
    });
    let method = methods.next().unwrap();
    assert!(methods.next().is_none());
    assert_eq!(method.sig.inputs.len(), 1);
    assert!(
        matches!(method.sig.inputs.first(),Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none() && receiver.colon_token.is_none())
    );
    let syn::ReturnType::Type(_, output) = &method.sig.output else {
        panic!("fixed output missing");
    };
    let syn::Type::Path(result) = &**output else {
        panic!("fixed Result missing");
    };
    let args = &result.path.segments.last().unwrap().arguments;
    let syn::PathArguments::AngleBracketed(args) = args else {
        panic!("fixed output argument missing");
    };
    assert_eq!(args.args.len(), 1);
    let Some(syn::GenericArgument::Type(syn::Type::Path(retained))) = args.args.first() else {
        panic!("fixed retained output missing");
    };
    let retained = retained.path.segments.last().unwrap();
    assert_eq!(retained.ident, "RetainedControllerNative");
    let syn::PathArguments::AngleBracketed(args) = &retained.arguments else {
        panic!("real role lifetime missing");
    };
    assert_eq!(args.args.len(), 1);
    assert!(
        matches!(args.args.first(),Some(syn::GenericArgument::Lifetime(lifetime)) if lifetime.ident=="role")
    );
    let fresh = restored_history_method(source, "RetainedControllerNative", "begin_current_stage");
    let expected: syn::Block = syn::parse_quote!({ self.owner.begin_current_stage() });
    assert_eq!(
        fresh,
        native_source_tokens(&expected.to_token_stream().to_string())
    );
}

#[test]
fn actual_retained_controller_native_and_attempt_drop_are_only_negative_and_fields_remain_private()
{
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    for (owner, expected) in [
        (
            "RetainedControllerNative",
            syn::parse_quote!({
                self.owner.refused = true;
                self.refusal.refuse();
            }),
        ),
        (
            "ControllerNativeRetirement",
            syn::parse_quote!({
                if !self.completed
                    && let Some(stage) = &mut self.stage
                {
                    stage.owner.refused = true;
                    stage.acquisition.as_mut().refuse();
                }
            }),
        ),
    ] {
        let expected: syn::Block = expected;
        let actual =
            syn::parse_str::<syn::Block>(&restored_history_method(source, owner, "drop")).unwrap();
        assert_eq!(
            actual.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }
    let file = syn::parse_file(source).unwrap();
    for name in ["RetainedControllerNative", "ControllerNativeRetirement"] {
        let entries = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item) if item.ident == name => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        );
        assert!(entries[0].attrs.iter().all(|a|matches!(&a.meta,syn::Meta::NameValue(value) if value.path.is_ident("doc") && matches!(&value.value,syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Str(_))))));
    }
}

#[test]
fn actual_app_native_preparation_retains_whole_pending_and_original_for_genuine_ack() {
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    let actual = restored_history_method(
        source,
        "PendingRestoredEnrollment",
        "prepare_current_native",
    );
    let actual: syn::Block = syn::parse_str(&actual).unwrap();
    let linux = |body: &syn::Block| -> Option<syn::Block> {
        let syn::Stmt::Expr(syn::Expr::Block(linux), None) = body.stmts.last()? else {
            return None;
        };
        if linux.attrs.len() != 1
            || !matches!(&linux.attrs[0].meta,syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string()=="target_os = \"linux\"")
        {
            return None;
        }
        Some(linux.block.clone())
    };
    let expected: syn::Block = syn::parse_quote!({
        let _ = self.admit_current(&lineage)?;
        let file = self.prepare_file_continuity()?;
        let peer = self.prepare_peer_continuity()?;
        self.check()?;
        Ok(PreparedRestoredAppNative {
            pending: self,
            file,
            peer,
            lineage,
        })
    });
    let normalized = |body: &syn::Block| {
        restored_history_method(
            &format!(
                "impl AppPreparationShape {{fn capture() {}}}",
                body.to_token_stream()
            ),
            "AppPreparationShape",
            "capture",
        )
    };
    let guarded = |body: &syn::Block| {
        linux(body).is_some_and(|body| normalized(&body) == normalized(&expected))
    };
    assert!(guarded(&actual));
    assert!(
        !actual
            .to_token_stream()
            .to_string()
            .contains("retire_checked")
    );
    assert!(
        !actual
            .to_token_stream()
            .to_string()
            .contains("into_connection_clock")
    );
    for index in 0..expected.stmts.len() {
        let mut changed = actual.clone();
        let syn::Stmt::Expr(syn::Expr::Block(body), None) = changed.stmts.last_mut().unwrap()
        else {
            unreachable!();
        };
        body.block.stmts.remove(index);
        assert!(!guarded(&changed));
    }
    let mut late = actual.clone();
    let syn::Stmt::Expr(syn::Expr::Block(body), None) = late.stmts.last_mut().unwrap() else {
        unreachable!();
    };
    body.block.stmts.swap(2, 3);
    assert!(!guarded(&late));
    let mut premature = actual.clone();
    let syn::Stmt::Expr(syn::Expr::Block(body), None) = premature.stmts.last_mut().unwrap() else {
        unreachable!();
    };
    body.block.stmts.insert(
        4,
        syn::parse_quote!(self.owner.clock.retire_checked(&mut self.original)?;),
    );
    assert!(!guarded(&premature));
    let mut copied = actual.clone();
    let syn::Stmt::Expr(syn::Expr::Block(body), None) = copied.stmts.last_mut().unwrap() else {
        unreachable!();
    };
    body.block.stmts[4] = syn::Stmt::Expr(
        syn::parse_quote!(Ok(PreparedRestoredAppNative {
            pending: other,
            file,
            peer,
            lineage
        })),
        None,
    );
    assert!(!guarded(&copied));
    let negative = restored_history_method(source, "PreparedRestoredAppNative", "drop");
    let expected: syn::Block = syn::parse_quote!({
        self.pending.refuse();
    });
    assert_eq!(
        negative,
        native_source_tokens(&expected.to_token_stream().to_string())
    );
    let file = syn::parse_file(source).unwrap();
    let owner = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "PreparedRestoredAppNative" => Some(item),
            _ => None,
        })
        .unwrap();
    let expected_fields = [
        ("pending", syn::parse_quote!(PendingRestoredEnrollment)),
        ("file", syn::parse_quote!(RestoredAppFileContinuity)),
        ("peer", syn::parse_quote!(RestoredAppPeerContinuity)),
        (
            "lineage",
            syn::parse_quote!(crate::security_epoch::bootstrap::ActiveLineage),
        ),
    ];
    let whole_fields = |owner: &syn::ItemStruct| {
        owner.fields.len() == expected_fields.len()
            && owner
                .fields
                .iter()
                .zip(&expected_fields)
                .all(|(field, (name, ty))| {
                    let ty: &syn::Type = ty;
                    matches!(field.vis, syn::Visibility::Inherited)
                        && field.attrs.is_empty()
                        && field.ident.as_ref().is_some_and(|id| id == name)
                        && field.ty.to_token_stream().to_string()
                            == ty.to_token_stream().to_string()
                })
    };
    assert!(whole_fields(owner));
    for index in 0..expected_fields.len() {
        let mut changed = owner.clone();
        changed.fields.iter_mut().nth(index).unwrap().ty = syn::parse_quote!(UntrustedData);
        assert!(!whole_fields(&changed));
    }
    for item in &file.items {
        if let syn::Item::Impl(item) = item
            && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("PreparedRestoredAppNative"))
        {
            if let Some((_, path, _)) = &item.trait_ {
                assert!(path.is_ident("Drop"));
            } else {
                let names = item
                    .items
                    .iter()
                    .filter_map(|i| match i {
                        syn::ImplItem::Fn(f) => Some(f.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(names, ["confirm_installed"]);
            }
        }
    }
}

#[test]
fn app_installed_owner_retains_whole_prepared_input_and_all_independent_posts() {
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    let actual = restored_history_method(source, "PreparedRestoredAppNative", "confirm_installed");
    let expected: syn::Block = syn::parse_quote!({
        let requested: Result<()> = (|| {
            self.pending.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let (_, deadline) = self.pending.original.interval_data()?;
                let mut stage = EnrolledRoleStage {
                    owner: &mut self.pending.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut self.pending.original),
                    deadline,
                };
                self.file.check_current(&mut stage)?;
                let mut acquisition = stage.narrow_io_acquisition(5)?;
                self.peer.check_anchors(&mut stage, &mut acquisition)?;
                let requested = self.pending.history.confirm_installation(&mut stage);
                let peer_post = self.peer.check_anchors(&mut stage, &mut acquisition);
                let file_post = self.file.check_current(&mut stage);
                let native_post = stage.check();
                requested?;
                peer_post?;
                file_post?;
                native_post
            }
        })();
        let checked = self.pending.check();
        if requested.is_err() || checked.is_err() {
            self.pending.refuse();
        }
        requested?;
        checked?;
        Ok(InstalledRestoredAppNative { prepared: self })
    });
    let normalize = |block: &syn::Block| {
        restored_history_method(
            &format!(
                "impl InstalledShape {{fn check() {}}}",
                block.to_token_stream()
            ),
            "InstalledShape",
            "check",
        )
    };
    assert_eq!(actual, normalize(&expected));
    for index in 0..expected.stmts.len() {
        let mut changed = expected.clone();
        changed.stmts.remove(index);
        assert_ne!(actual, normalize(&changed));
    }
    let mut copied = expected.clone();
    *copied.stmts.last_mut().unwrap() = syn::Stmt::Expr(
        syn::parse_quote!(Ok(InstalledRestoredAppNative { prepared: other })),
        None,
    );
    assert_ne!(actual, normalize(&copied));
    for forbidden in [
        "NativeAcquisition :: begin",
        "retire_checked",
        "into_connection_clock",
        "Runtime ::",
    ] {
        assert!(!actual.contains(forbidden));
    }
    let file = syn::parse_file(source).unwrap();
    let owner = file
        .items
        .iter()
        .find_map(|i| match i {
            syn::Item::Struct(i) if i.ident == "InstalledRestoredAppNative" => Some(i),
            _ => None,
        })
        .unwrap();
    assert_eq!(owner.fields.len(), 1);
    let field = owner.fields.iter().next().unwrap();
    assert!(matches!(field.vis, syn::Visibility::Inherited));
    assert_eq!(field.ident.as_ref().unwrap(), "prepared");
    let ty: syn::Type = syn::parse_quote!(PreparedRestoredAppNative);
    assert_eq!(
        field.ty.to_token_stream().to_string(),
        ty.to_token_stream().to_string()
    );
    assert!(
        restored_history_method(source, "InstalledRestoredAppNative", "drop").contains("refuse")
    );
}

#[test]
fn restored_request_capture_holds_the_real_parent_before_native_work_and_keeps_negative_drop() {
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    let actual = restored_history_method(source, "RetiredRestoredAppNative", "capture_request");
    let expected: syn::Block = syn::parse_quote!({
        let mut captured = CapturedRestoredAppRequest {
            refusal: RestoredCaptureRefusal::new(&self.request_state),
            history: Rc::clone(&self.installed.prepared.pending.history),
            request: None,
            scope_settled: false,
        };
        captured.refusal.gate.capture()?;
        let pending = &mut self.installed.prepared.pending;
        captured.request = Some(pending.owner.begin_current_request()?);
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("native_restore_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            let fresh = captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_capture_missing"))?;
            pending
                .original
                .require_retired_predecessor(&mut fresh.acquisition)?;
            pending.owner.borrow_current_request(fresh)?.check()?;
            Ok(captured)
        }
    });
    let normalize = |body: &syn::Block| {
        restored_history_method(
            &format!(
                "impl CaptureShape {{fn capture() {}}}",
                body.to_token_stream()
            ),
            "CaptureShape",
            "capture",
        )
    };
    assert_eq!(actual, normalize(&expected));
    let mut premature = expected.clone();
    let syn::Stmt::Local(local) = &mut premature.stmts[0] else {
        panic!("actual capture initializer");
    };
    let syn::Expr::Struct(value) = local.init.as_mut().unwrap().expr.as_mut() else {
        panic!("actual captured native request");
    };
    let fields = value
        .fields
        .iter_mut()
        .filter(|field| matches!(&field.member,syn::Member::Named(name) if name=="scope_settled"))
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 1);
    fields.into_iter().next().unwrap().expr = syn::parse_quote!(true);
    assert_ne!(actual, normalize(&premature));
    let mut missing = expected.clone();
    let syn::Stmt::Local(local) = &mut missing.stmts[0] else {
        unreachable!();
    };
    let syn::Expr::Struct(value) = local.init.as_mut().unwrap().expr.as_mut() else {
        unreachable!();
    };
    let before = value.fields.len();
    value.fields = value
        .fields
        .clone()
        .into_iter()
        .filter(|field| !matches!(&field.member,syn::Member::Named(name) if name=="scope_settled"))
        .collect();
    assert_eq!(value.fields.len() + 1, before);
    assert_ne!(actual, normalize(&missing));
    for cut in 0..expected.stmts.len() {
        let mut changed = expected.clone();
        changed.stmts.remove(cut);
        assert_ne!(actual, normalize(&changed), "outer cut{cut}");
    }
    let mut late = expected.clone();
    late.stmts.swap(1, 3);
    assert_ne!(actual, normalize(&late));
    let syn::Stmt::Expr(syn::Expr::Block(linux), None) = expected.stmts.last().unwrap() else {
        panic!("Linux");
    };
    for cut in 0..linux.block.stmts.len() {
        let mut changed = expected.clone();
        let syn::Stmt::Expr(syn::Expr::Block(linux), None) = changed.stmts.last_mut().unwrap()
        else {
            unreachable!();
        };
        linux.block.stmts.remove(cut);
        assert_ne!(actual, normalize(&changed), "native cut{cut}");
    }
    let drop = restored_history_method(source, "CapturedRestoredAppRequest", "drop");
    for required in [
        "self.refusal.refuse()",
        "self.history.refuse()",
        "request.refuse()",
    ] {
        let target: syn::Block = syn::parse_str(&format!("{{{required};}}")).unwrap();
        let normalized = normalize(&target);
        // Compare the actual call's tokens, excluding only the enclosing braces.
        let required = normalized
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();
        assert!(drop.contains(required));
    }
}

#[test]
fn app_keeper_handoff_retires_actual_original_last_and_never_discards_negative_guards() {
    use quote::ToTokens;
    let source = include_str!("owner.rs");
    let actual = restored_history_method(
        source,
        "InstalledRestoredAppNative",
        "retire_current_native",
    );
    let expected: syn::Block = syn::parse_quote!({
        let requested = self.prepared.pending.history.check_installed();
        let checked = self.prepared.pending.check();
        if requested.is_err() || checked.is_err() {
            self.prepared.pending.refuse();
        }
        requested?;
        checked?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested: Result<()> = (|| {
                let (_, deadline) = self.prepared.pending.original.interval_data()?;
                let mut stage = EnrolledRoleStage {
                    owner: &mut self.prepared.pending.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut self.prepared.pending.original),
                    deadline,
                };
                let mut acquisition = stage.narrow_io_acquisition(5)?;
                let file = self.prepared.file.check_current(&mut stage);
                let peer = self
                    .prepared
                    .peer
                    .check_anchors(&mut stage, &mut acquisition);
                let native = stage.check();
                finish_restored_app_posts(file, peer, native)
            })();
            let checked = self.prepared.pending.check();
            if requested.is_err() || checked.is_err() {
                self.prepared.pending.refuse();
            }
            requested?;
            checked?;
            self.prepared
                .pending
                .owner
                .clock
                .retire_checked(&mut self.prepared.pending.original)?;
            Ok(RetiredRestoredAppNative {
                installed: self,
                request_state: Rc::new(RestoredRequestGate::new()),
                current_peer: None,
            })
        }
    });
    let normalize = |block: &syn::Block| {
        restored_history_method(
            &format!(
                "impl HandoffShape {{fn check() {}}}",
                block.to_token_stream()
            ),
            "HandoffShape",
            "check",
        )
    };
    assert_eq!(actual, normalize(&expected));
    let syn::Stmt::Expr(syn::Expr::Block(linux), None) = expected.stmts.last().unwrap() else {
        panic!("Linux body");
    };
    for index in 0..linux.block.stmts.len() {
        let mut changed = expected.clone();
        let syn::Stmt::Expr(syn::Expr::Block(linux), None) = changed.stmts.last_mut().unwrap()
        else {
            unreachable!();
        };
        linux.block.stmts.remove(index);
        assert_ne!(actual, normalize(&changed));
    }
    fn posts(block: &mut syn::Block) -> &mut syn::Block {
        let syn::Stmt::Expr(syn::Expr::Block(linux), None) = block.stmts.last_mut().unwrap() else {
            panic!("Linux body");
        };
        let syn::Stmt::Local(local) = linux.block.stmts.first_mut().unwrap() else {
            panic!("request local");
        };
        let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
            panic!("closed call");
        };
        let syn::Expr::Paren(paren) = &mut *call.func else {
            panic!("closed parentheses");
        };
        let syn::Expr::Closure(closure) = &mut *paren.expr else {
            panic!("closed body");
        };
        let syn::Expr::Block(body) = &mut *closure.body else {
            panic!("closed block");
        };
        &mut body.block
    }
    fn one_local(block: &syn::Block, name: &str) -> usize {
        let positions=block.stmts.iter().enumerate().filter_map(|(index,stmt)|
            matches!(stmt,syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(id) if id.ident==name)).then_some(index)
        ).collect::<Vec<_>>();
        assert_eq!(positions.len(), 1, "{name}");
        positions[0]
    }
    let mut short = expected.clone();
    let body = posts(&mut short);
    let file = one_local(body, "file");
    body.stmts.insert(file + 1, syn::parse_quote!(file?;));
    assert_ne!(actual, normalize(&short));
    let mut masked = expected.clone();
    let body = posts(&mut masked);
    let file = one_local(body, "file");
    let acquisition = one_local(body, "acquisition");
    assert!(acquisition < file);
    body.stmts.swap(file, acquisition);
    assert_ne!(actual, normalize(&masked));
    let mut late = expected.clone();
    let syn::Stmt::Expr(syn::Expr::Block(linux), None) = late.stmts.last_mut().unwrap() else {
        unreachable!();
    };
    linux.block.stmts.insert(
        linux.block.stmts.len() - 1,
        syn::parse_quote!(self.prepared.pending.check()?;),
    );
    assert_ne!(actual, normalize(&late));
    let mut copied = expected.clone();
    let syn::Stmt::Expr(syn::Expr::Block(linux), None) = copied.stmts.last_mut().unwrap() else {
        unreachable!();
    };
    *linux.block.stmts.last_mut().unwrap() = syn::Stmt::Expr(
        syn::parse_quote!(Ok(RetiredRestoredAppNative {
            installed: other,
            request_state: RestoredRequestState::Vacant
        })),
        None,
    );
    assert_ne!(actual, normalize(&copied));
    let file = syn::parse_file(source).unwrap();
    let owner = file
        .items
        .iter()
        .find_map(|i| match i {
            syn::Item::Struct(i) if i.ident == "RetiredRestoredAppNative" => Some(i),
            _ => None,
        })
        .unwrap();
    assert_eq!(owner.fields.len(), 3);
    for (field, (name, expected)) in owner.fields.iter().zip([
        ("installed", syn::parse_quote!(InstalledRestoredAppNative)),
        ("request_state", syn::parse_quote!(Rc<RestoredRequestGate>)),
        (
            "current_peer",
            syn::parse_quote!(Option<super::RestoredPeerConnection<'static>>),
        ),
    ]) {
        assert!(matches!(field.vis, syn::Visibility::Inherited));
        assert_eq!(field.ident.as_ref().unwrap(), name);
        let expected: syn::Type = expected;
        assert_eq!(
            field.ty.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }
    fn retired_methods_admitted(file: &syn::File) -> bool {
        let mut methods = std::collections::BTreeSet::new();
        let mut inherent = 0;
        let mut drops = 0;
        for item in &file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("RetiredRestoredAppNative"))
            {
                if let Some((_, path, _)) = &item.trait_ {
                    if !path.is_ident("Drop") {
                        return false;
                    }
                    drops += 1;
                } else {
                    inherent += 1;
                    for item in &item.items {
                        let syn::ImplItem::Fn(method) = item else {
                            return false;
                        };
                        if !methods.insert(method.sig.ident.to_string()) {
                            return false;
                        }
                    }
                }
            }
        }
        inherent == 1
            && drops == 1
            && methods
                == ["capture_request", "install_host", "prepare_host_native"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<std::collections::BTreeSet<_>>()
    }
    assert!(retired_methods_admitted(&file));
    let actual_impl = file.items.iter().position(|item| {
        matches!(item, syn::Item::Impl(item) if item.trait_.is_none()
            && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("RetiredRestoredAppNative")))
    }).unwrap();
    let mut getter = file.clone();
    let syn::Item::Impl(item) = &mut getter.items[actual_impl] else {
        unreachable!();
    };
    item.items.push(syn::parse_quote!(
        fn runtime(&self) -> &crate::store::Runtime {
            self.installed.prepared.pending.runtime.as_ref()
        }
    ));
    assert!(!retired_methods_admitted(&getter));
    let mut missing_setup = file.clone();
    let syn::Item::Impl(item) = &mut missing_setup.items[actual_impl] else {
        unreachable!();
    };
    let before = item.items.len();
    item.items.retain(|item| {
        !matches!(item, syn::ImplItem::Fn(method) if method.sig.ident == "prepare_host_native")
    });
    assert_eq!(item.items.len() + 1, before);
    assert!(!retired_methods_admitted(&missing_setup));
    let mut duplicate_capture = file.clone();
    let syn::Item::Impl(item) = &mut duplicate_capture.items[actual_impl] else {
        unreachable!();
    };
    let capture = item.items.iter().find(|item| {
        matches!(item, syn::ImplItem::Fn(method) if method.sig.ident == "capture_request")
    }).unwrap().clone();
    item.items.push(capture);
    assert!(!retired_methods_admitted(&duplicate_capture));
    assert!(restored_history_method(source, "RetiredRestoredAppNative", "drop").contains("refuse"));
    for forbidden in [
        "NativeAcquisition :: begin",
        "into_connection_clock",
        "finished = true",
        "Runtime ::",
    ] {
        assert!(!actual.contains(forbidden));
    }
}

#[test]
fn actual_app_post_selector_preserves_primary_identity_with_simultaneous_refusals() {
    use std::sync::Arc;
    #[derive(Debug)]
    struct Failure {
        identity: Arc<()>,
        index: usize,
    }
    impl std::fmt::Display for Failure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("closed_app_post_fixture")
        }
    }
    impl std::error::Error for Failure {}
    for faults in 0..8u8 {
        let identities = [Arc::new(()), Arc::new(()), Arc::new(())];
        let calls = std::cell::RefCell::new(Vec::new());
        let post = |index: usize| -> anyhow::Result<()> {
            calls.borrow_mut().push(index);
            if faults & (1 << index) == 0 {
                Ok(())
            } else {
                Err(Failure {
                    identity: Arc::clone(&identities[index]),
                    index,
                }
                .into())
            }
        };
        let result = super::owner::finish_restored_app_posts(post(0), post(1), post(2));
        assert_eq!(*calls.borrow(), [0, 1, 2]);
        let expected = (0..3usize).find(|index| faults & (1 << index) != 0);
        match expected {
            None => assert!(result.is_ok()),
            Some(index) => {
                let error = result.unwrap_err();
                let marker = error.downcast_ref::<Failure>().unwrap();
                assert_eq!(marker.index, index);
                assert!(Arc::ptr_eq(&marker.identity, &identities[index]));
            }
        }
    }
}
