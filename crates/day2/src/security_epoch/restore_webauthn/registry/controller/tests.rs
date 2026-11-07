//! DATA and actual-source controls only. No portable native reader is invented.
use super::super::tests::configuration;
use super::*;
use quote::ToTokens;
use syn::parse::Parser;
use syn::visit::Visit;

fn context(instance: &Instance) -> Result<ControllerRegistryData> {
    Ok(ControllerRegistryData {
        selector: "/reviewed/instance.json".into(),
        instance: Digest::of(instance)?,
        scope: instance.scope("app")?,
        app: "app".into(),
        artifact: "artifact".into(),
        authority: crate::authority_state::AuthorityStamp {
            epoch: Digest::new(b"epoch").as_str().to_owned(),
            revision: 7,
        },
        operation: Digest::new(b"complete restore approval intent"),
        approver: "álîce@example.test".into(),
        executor: "executor@example.test".into(),
    })
}

#[test]
fn controller_record_binds_exact_operation_instance_scope_and_approver() -> Result<()> {
    let instance = configuration();
    let captured = context(&instance)?;
    let request = captured.operation.clone();
    let selected = controller_record(
        &instance,
        &captured,
        Digest::new(b"held file"),
        &[1, 2, 3],
        &request,
    )?;
    // These are record DATA, not a key origin or an approval.
    assert_eq!(selected.revision, 7);
    assert_eq!(selected.credential_id, [1, 2, 3]);
    for change in 0..5 {
        let mut altered = context(&instance)?;
        match change {
            0 => altered.operation = Digest::new(b"another operation"),
            1 => altered.instance = Digest::new(b"another instance"),
            2 => altered.scope = "another/canary/app".into(),
            3 => altered.app = "another-app".into(),
            _ => altered.approver = altered.executor.clone(),
        }
        assert!(
            controller_record(
                &instance,
                &altered,
                Digest::new(b"held file"),
                &[1, 2, 3],
                &request
            )
            .is_err()
        );
    }
    assert!(
        controller_record(
            &instance,
            &captured,
            Digest::new(b"held file"),
            &[9],
            &request
        )
        .is_err()
    );
    let mut removed = configuration();
    removed
        .control
        .as_mut()
        .unwrap()
        .restore_passkeys
        .as_mut()
        .unwrap()
        .keys
        .clear();
    let removed_context = context(&removed)?;
    assert!(
        controller_record(
            &removed,
            &removed_context,
            Digest::new(b"held file"),
            &[1, 2, 3],
            &request
        )
        .is_err()
    );
    Ok(())
}

fn method<'a>(file: &'a syn::File, owner: &str, name: &str) -> &'a syn::ImplItemFn {
    file.items.iter().filter_map(|item| match item {syn::Item::Impl(item)=>Some(item),_=>None})
        .filter(|item| matches!(item.self_ty.as_ref(),syn::Type::Path(path) if path.path.segments.last().unwrap().ident == owner))
        .flat_map(|item| &item.items).find_map(|item| match item {syn::ImplItem::Fn(item) if item.sig.ident == name=>Some(item),_=>None}).unwrap()
}
fn calls(block: &syn::Block) -> Vec<String> {
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("ensure") {
                let arguments =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(node.tokens.clone())
                        .expect("actual ensure arguments must parse");
                let mut nested = Calls(Vec::new());
                for expression in &arguments {
                    nested.visit_expr(expression);
                }
                self.0.extend(nested.0);
            }
            syn::visit::visit_macro(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            syn::visit::visit_expr_method_call(self, node);
            self.0.push(node.method.to_string());
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            syn::visit::visit_expr_call(self, node);
            if let syn::Expr::Path(path) = node.func.as_ref() {
                self.0
                    .push(path.path.segments.last().unwrap().ident.to_string());
            }
        }
    }
    let mut visitor = Calls(Vec::new());
    visitor.visit_block(block);
    visitor.0
}

#[test]
fn call_collector_visits_statement_and_expression_ensure_exactly_once() {
    let block: syn::Block = syn::parse_str(
        r#"{
            ensure!(statement_check()?, "statement");
            let _value = ensure!(expression_check()?, "expression");
        }"#,
    )
    .unwrap();
    assert!(matches!(&block.stmts[0], syn::Stmt::Macro(_)));
    assert!(matches!(&block.stmts[1], syn::Stmt::Local(_)));
    assert_eq!(calls(&block), ["statement_check", "expression_check"]);
}
fn before(calls: &[String], a: &str, b: &str) -> bool {
    matches!((calls.iter().position(|c|c==a),calls.iter().position(|c|c==b)),(Some(a),Some(b)) if a<b)
}
fn current(source: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    let capture = calls(&method(&file, "RegistryCeremony", "capture_controller").block);
    let verify = calls(&method(&file, "RegistryCeremony", "verify_current_controller").block);
    let local = calls(&method(&file, "ControllerBorrow", "check_local").block);
    before(&capture, "registry_data", "open")
        && before(&capture, "open", "fill")
        && capture.iter().filter(|c| *c == "selected").count() == 2
        && before(&verify, "begin_attempt", "verify")
        && verify.iter().filter(|c| *c == "observe_controller").count() == 2
        && before(&verify, "observe_controller", "verify")
        && verify.iter().rposition(|c| c == "observe_controller")
            > verify.iter().position(|c| c == "verify")
        && local
            .iter()
            .filter(|c| *c == "check_registry_local")
            .count()
            == 2
        && before(&local, "check_registry_local", "check_local")
        && local.iter().rposition(|c| c == "check_registry_local")
            > local.iter().position(|c| c == "check_local")
        && !["begin_current_stage", "run", "arm", "finish_checked"]
            .iter()
            .any(|forbidden| verify.iter().any(|call| call == forbidden))
}

#[test]
fn actual_controller_key_loan_keeps_the_native_reader_and_postchecks() {
    let source = include_str!("../controller.rs");
    assert!(current(source));
    for (old, new) in [
        ("self.begin_attempt()?;", ""),
        (
            "let checked = self.observe_controller(reader);",
            "let checked = Ok(());",
        ),
        (
            "let checked = self.reader.check_registry_local();",
            "let checked = Ok(());",
        ),
    ] {
        assert_eq!(source.matches(old).count(), 1);
        let changed = source.replace(old, new);
        syn::parse_file(&changed).unwrap();
        assert!(!current(&changed));
    }
}

fn registry_local(source: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    let local = method(&file, "ControllerAdminReader", "check_registry_local");
    let trace = calls(&local.block);
    if trace.iter().filter(|call| *call == "check_local").count() != 2
        || !before(&trace, "check_local", "check_handles")
        || trace.iter().rposition(|call| call == "check_local")
            <= trace.iter().position(|call| call == "check_handles")
    {
        return false;
    }
    for forbidden in [
        "registry_data",
        "check_action",
        "read",
        "refresh",
        "begin_sql",
        "transaction",
        "begin_current_stage",
    ] {
        if trace.iter().any(|call| call == forbidden) {
            return false;
        }
    }
    let captured = method(&file, "ControllerAdminReader", "registry_data")
        .to_token_stream()
        .to_string();
    captured.contains("self . check (self . metadata")
}

#[test]
fn actual_registry_local_loan_brackets_handles_without_sql_or_provider_work() {
    let source = include_str!("../../../bootstrap/admin_read/reader.rs");
    assert!(registry_local(source));
    let omitted = source.replacen(
        "let checked = self.loan.check_local();",
        "let checked = Ok(());",
        1,
    );
    assert_ne!(omitted, source);
    assert!(!registry_local(&omitted));
    let old = "let requested = self.sqlite.check_handles();\n        let checked = self.loan.check_local();";
    let early = "let checked = self.loan.check_local();\n        let requested = self.sqlite.check_handles();";
    assert_eq!(source.matches(old).count(), 1);
    assert!(!registry_local(&source.replacen(old, early, 1)));
}
