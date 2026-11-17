//! Portable production-source controls, not fabricated native owners or
//! substitute kernel qualification. Parse actual Linux bodies on every host.
use quote::ToTokens;

#[derive(Default)]
struct Calls(Vec<syn::ExprMethodCall>);

impl<'ast> syn::visit::Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.clone());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn text(value: &impl ToTokens) -> String {
    value.to_token_stream().to_string()
}

fn calls(body: &syn::Block) -> Calls {
    let mut calls = Calls::default();
    syn::visit::Visit::visit_block(&mut calls, body);
    calls
}

fn selected<'a>(
    calls: &'a Calls,
    receiver: &str,
    method: &str,
    args: &[&str],
) -> Vec<(usize, &'a syn::ExprMethodCall)> {
    let receiver: syn::Expr = syn::parse_str(receiver).unwrap();
    let args: Vec<syn::Expr> = args
        .iter()
        .map(|arg| syn::parse_str(arg).unwrap())
        .collect();
    calls
        .0
        .iter()
        .enumerate()
        .filter(|(_, call)| {
            text(&call.receiver) == text(&receiver)
                && call.method == method
                && call.args.len() == args.len()
                && call
                    .args
                    .iter()
                    .zip(&args)
                    .all(|(actual, expected)| text(actual) == text(expected))
        })
        .collect()
}

fn function(name: &str) -> syn::ItemFn {
    let mut found: Vec<_> = syn::parse_file(include_str!("native.rs"))
        .unwrap()
        .items
        .into_iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1);
    let mut function = found.pop().unwrap();
    // The owning factory and imports are unconditional; only its actual
    // platform body is selected. The other branch permanently refuses.
    let linux: syn::Attribute = syn::parse_quote!(#[cfg(target_os = "linux")]);
    let blocks: Vec<_> = function
        .block
        .stmts
        .iter()
        .filter_map(|stmt| match stmt {
            syn::Stmt::Expr(syn::Expr::Block(block), _)
                if block.attrs.len() == 1 && text(&block.attrs[0]) == text(&linux) =>
            {
                Some(block.block.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(blocks.len(), 1);
    function.block = Box::new(blocks[0].clone());
    function
}

fn independent_post(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Local(local) = statement else {
        return false;
    };
    if !matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "checked") {
        return false;
    }
    let Some(init) = &local.init else {
        return false;
    };
    let syn::Expr::Call(catch) = &*init.expr else {
        return false;
    };
    let path: syn::Expr = syn::parse_quote!(std::panic::catch_unwind);
    if text(&catch.func) != text(&path) || catch.args.len() != 1 {
        return false;
    }
    let syn::Expr::Call(assert) = &catch.args[0] else {
        return false;
    };
    let path: syn::Expr = syn::parse_quote!(std::panic::AssertUnwindSafe);
    if text(&assert.func) != text(&path) || assert.args.len() != 1 {
        return false;
    }
    let syn::Expr::Closure(closure) = &assert.args[0] else {
        return false;
    };
    if !closure.inputs.is_empty() {
        return false;
    }
    let body = match &*closure.body {
        syn::Expr::Block(body) if body.block.stmts.len() == 1 => match &body.block.stmts[0] {
            syn::Stmt::Expr(expr, None) => expr,
            _ => return false,
        },
        body => body,
    };
    let syn::Expr::MethodCall(call) = body else {
        return false;
    };
    let calls = Calls(vec![call.clone()]);
    selected(&calls, "attempt", "check", &["stage", "&mut acquisition"]).len() == 1
}

fn guarded(body: &syn::Block, controller: bool) -> bool {
    let calls = calls(body);
    let crypto = selected(
        &calls,
        if controller { "proof" } else { "hello" },
        "verify_data",
        &["&remote"],
    );
    let late_crypto = selected(
        &calls,
        if controller { "confirm" } else { "accept" },
        "verify_data",
        &["&remote"],
    );
    let meet = selected(
        &calls,
        "attempt",
        "meet_received",
        &["&mut same", "stage", "&mut acquisition"],
    );
    let receive = calls
        .0
        .iter()
        .enumerate()
        .filter(|(_, call)| call.method == "receive_protected_admission")
        .collect::<Vec<_>>();
    let send = calls
        .0
        .iter()
        .enumerate()
        .filter(|(_, call)| call.method == "send_protected_admission")
        .collect::<Vec<_>>();
    let retained = selected(&calls, "attempt.senders", "push", &["sender"]);
    if crypto.len() != 1
        || late_crypto.len() != 1
        || meet.len() != 2
        || receive.len() != 2
        || send.len() != 2
        || retained.len() != 2
    {
        return false;
    }
    let exact = if controller {
        selected(
            &calls,
            "connection",
            "require_initial",
            &["&remote", "&local", "&nonce"],
        )
    } else {
        selected(
            &calls,
            "hello",
            "require_hello",
            &["&remote", "&controller_nonce"],
        )
    };
    let late_exact = if controller {
        selected(&calls, "confirm", "require_confirm", &["&connection"])
    } else {
        selected(&calls, "accept", "require_accept", &["&connection"])
    };
    let checks = selected(&calls, "attempt", "check", &["stage", "&mut acquisition"]);
    let before = |a: usize, b: usize| checks.iter().any(|(i, _)| a < *i && *i < b);
    if exact.len() != 1
        || late_exact.len() != 1
        || !(receive[0].0 < retained[0].0
            && retained[0].0 < crypto[0].0
            && crypto[0].0 < exact[0].0
            && exact[0].0 < meet[0].0
            && receive[1].0 < retained[1].0
            && retained[1].0 < late_crypto[0].0
            && late_crypto[0].0 < late_exact[0].0
            && late_exact[0].0 < meet[1].0
            && before(retained[0].0, crypto[0].0)
            && before(retained[1].0, late_crypto[0].0))
    {
        return false;
    }
    let local = selected(&calls, "stage", "protected_restore_statement", &[]);
    if local.len() != 1
        || (controller && local[0].0 >= send[0].0)
        || (!controller && !(meet[0].0 < local[0].0 && local[0].0 < send[0].0))
    {
        return false;
    }
    let refused: syn::Stmt = syn::parse_quote! {
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            attempt.refuse(); stage.refuse_serving(); acquisition.refuse();
        }
    };
    if body
        .stmts
        .iter()
        .filter(|stmt| independent_post(stmt))
        .count()
        != 1
        || body
            .stmts
            .iter()
            .filter(|stmt| text(stmt) == text(&refused))
            .count()
            != 1
    {
        return false;
    }
    let body = text(body);
    ![
        "NativeAcquisition :: begin",
        "begin_current",
        "ServingPeer",
        "bind_admitted",
        "validate_request",
    ]
    .iter()
    .any(|forbidden| body.contains(forbidden))
}

#[test]
fn actual_initial_factories_authenticate_retained_senders_before_meeting_the_saved_request() {
    for controller in [true, false] {
        let actual = function(if controller { "accept" } else { "connect" });
        assert!(guarded(&actual.block, controller));
        let calls = calls(&actual.block);
        for (receiver, method, args) in [
            (
                if controller { "proof" } else { "hello" },
                "verify_data",
                vec!["&remote"],
            ),
            (
                if controller { "confirm" } else { "accept" },
                "verify_data",
                vec!["&remote"],
            ),
            ("attempt.senders", "push", vec!["sender"]),
        ] {
            let selected = selected(&calls, receiver, method, &args);
            assert_eq!(selected.len(), if method == "push" { 2 } else { 1 });
            let needle = text(selected[0].1);
            assert_eq!(text(&actual.block).matches(&needle).count(), selected.len());
            let changed =
                syn::parse_str(&text(&actual.block).replacen(&needle, "Ok(())", 1)).unwrap();
            assert!(!guarded(&changed, controller));
        }
        let crypto = selected(
            &calls,
            if controller { "proof" } else { "hello" },
            "verify_data",
            &["&remote"],
        );
        let meet = selected(
            &calls,
            "attempt",
            "meet_received",
            &["&mut same", "stage", "&mut acquisition"],
        );
        let crypto = text(crypto[0].1);
        let meet = text(meet[0].1);
        let changed = text(&actual.block)
            .replacen(&crypto, "__SOURCE_SWAP__", 1)
            .replacen(&meet, &crypto, 1)
            .replacen("__SOURCE_SWAP__", &meet, 1);
        assert!(!guarded(&syn::parse_str(&changed).unwrap(), controller));
        for name in ["checked", "refused"] {
            let mut changed = actual.block.clone();
            let original = changed.stmts.len();
            changed.stmts.retain(|stmt| match (name, stmt) {
                ("checked", syn::Stmt::Local(local)) => {
                    !matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "checked")
                }
                ("refused", syn::Stmt::Expr(syn::Expr::If(_), _)) => false,
                _ => true,
            });
            assert_eq!(changed.stmts.len() + 1, original);
            assert!(!guarded(&changed, controller));
        }
    }
}

#[test]
fn actual_outer_admission_uses_one_saved_request_and_spends_issuer_attempt_before_native_io() {
    let file = syn::parse_file(include_str!("../protected_restore.rs")).unwrap();
    for (owner, name) in [
        ("ProtectedRestoreListener", "accept"),
        ("ProtectedRestoreShell", "connect"),
    ] {
        let mut methods = Vec::new();
        for item in &file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident(owner))
            {
                methods.extend(item.items.iter().filter_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                }));
            }
        }
        assert_eq!(methods.len(), 1);
        let calls = calls(&methods[0].block);
        let attempt = calls
            .0
            .iter()
            .position(|call| call.method == "begin_protected_restore_attempt")
            .unwrap();
        assert_eq!(
            calls
                .0
                .iter()
                .filter(|call| call.method == "begin_protected_restore_attempt")
                .count(),
            1
        );
        if name == "accept" {
            let begin = selected(&calls, "role", "begin_current_request", &[]);
            let borrowed = selected(&calls, "role", "borrow_current_request", &["&mut request"]);
            let finish = selected(&calls, "request", "finish", &["role"]);
            assert_eq!((begin.len(), borrowed.len(), finish.len()), (1, 1, 1));
            assert!(begin[0].0 < borrowed[0].0 && borrowed[0].0 < attempt && attempt < finish[0].0);
        } else {
            assert!(!text(&methods[0].block).contains("begin_current"));
        }
        assert_eq!(selected(&calls, "stage", "check", &[]).len(), 1);
        assert_eq!(selected(&calls, "stage", "refuse_serving", &[]).len(), 1);
    }
}
