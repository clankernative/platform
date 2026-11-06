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
        &captured.executor,
    )?;
    // These are record DATA, not a key origin or an approval.
    assert_eq!(selected.revision, 7);
    assert_eq!(selected.credential_id, [1, 2, 3]);
    for change in 0..6 {
        let mut altered = context(&instance)?;
        match change {
            0 => altered.operation = Digest::new(b"another operation"),
            1 => altered.instance = Digest::new(b"another instance"),
            2 => altered.scope = "another/canary/app".into(),
            3 => altered.app = "another-app".into(),
            4 => altered.approver = altered.executor.clone(),
            _ => altered.executor = "another-executor@example.test".into(),
        }
        assert!(
            controller_record(
                &instance,
                &altered,
                Digest::new(b"held file"),
                &[1, 2, 3],
                &request,
                &captured.executor,
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
            &request,
            &captured.executor,
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
            &request,
            &captured.executor,
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
            "let checked = self.observe_controller(reader, executor);",
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

fn typed_intent_wiring(source: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    let capture = method(&file, "ControllerCeremony", "capture");
    let verify = method(&file, "ControllerCeremony", "verify_current");
    let trace = calls(&verify.block);
    capture
        .sig
        .to_token_stream()
        .to_string()
        .contains("intent : ApprovalIntent")
        && capture
            .block
            .to_token_stream()
            .to_string()
            .contains("& intent . executor . email")
        && verify
            .block
            .to_token_stream()
            .to_string()
            .contains("self . intent . require_exact (expected) ?")
        && verify
            .block
            .to_token_stream()
            .to_string()
            .contains("& self . intent . executor . email")
        && before(&trace, "require_exact", "verify_current_controller")
        && matches!(
            method(&file, "RegistryCeremony", "capture_controller").vis,
            syn::Visibility::Inherited
        )
        && matches!(
            method(&file, "RegistryCeremony", "verify_current_controller").vis,
            syn::Visibility::Inherited
        )
}

#[test]
fn actual_controller_entry_requires_complete_intent_before_crypto_and_hides_digest_helpers() {
    let source = include_str!("../controller.rs");
    assert!(typed_intent_wiring(source));
    for (old, new) in [
        ("self.intent.require_exact(expected)?;", ""),
        ("&intent.executor.email", "&String::new()"),
        ("&self.intent.executor.email", "&String::new()"),
        (
            "fn capture_controller(",
            "pub(crate) fn capture_controller(",
        ),
        (
            "fn verify_current_controller(",
            "pub(crate) fn verify_current_controller(",
        ),
    ] {
        assert_eq!(source.matches(old).count(), 1);
        let mutant = source.replace(old, new);
        assert!(!typed_intent_wiring(&mutant));
    }
}

#[derive(Debug)]
struct NativePostFailure;
impl std::fmt::Display for NativePostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("test native postcheck")
    }
}
impl std::error::Error for NativePostFailure {}

#[test]
fn known_assertion_denial_requires_successful_postcheck_and_unknown_errors_remain_errors() {
    use super::super::super::AssertionDenied;
    let denial = || anyhow::Error::new(AssertionDenied::Signature).context("opaque context");
    assert_eq!(settle_verification(Err(denial()), Ok(())).unwrap(), None);
    let post = settle_verification(Err(denial()), Err(NativePostFailure.into())).unwrap_err();
    assert!(post.is::<NativePostFailure>());
    assert!(!post.is::<AssertionDenied>());
    let unknown = settle_verification(
        Err(anyhow::anyhow!("restore_passkey_signature_invalid")),
        Ok(()),
    )
    .unwrap_err();
    assert!(!unknown.is::<AssertionDenied>());
    // Two actual source failures retain the original source cause, while the
    // caller's error branch still refuses the reader. No native owner is faked.
    let primary = settle_verification(
        Err(NativePostFailure.into()),
        Err(anyhow::anyhow!("second source fault")),
    )
    .unwrap_err();
    assert!(primary.is::<NativePostFailure>());
    let facts = || AssertionFacts {
        counter: 8,
        backed_up: false,
    };
    assert_eq!(
        settle_verification(Ok(facts()), Ok(())).unwrap(),
        Some(facts())
    );
    assert!(
        settle_verification(Ok(facts()), Err(NativePostFailure.into()))
            .unwrap_err()
            .is::<NativePostFailure>()
    );
}

fn denial_wiring(source: &str) -> bool {
    let file = syn::parse_file(source).unwrap();
    let verify = method(&file, "RegistryCeremony", "verify_current_controller");
    let locals = verify.block.to_token_stream().to_string();
    let trace = calls(&verify.block);
    let helper = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "settle_verification" => Some(item),
            _ => None,
        })
        .unwrap()
        .block
        .to_token_stream()
        .to_string();
    before(&trace, "verify", "settle_verification")
        && trace.iter().rposition(|c| c == "observe_controller") < trace.iter().position(|c| c == "settle_verification")
        && locals.contains("let checked = self . observe_controller (reader , executor) ;")
        && locals.contains("settle_verification (requested , checked)")
        && !locals.contains("} ? ; let checked")
        && locals.contains("self . refused . set (true)")
        && locals.contains("reader . refuse ()")
        && locals.contains("else if matches ! (& result , Ok (None)) { self . refused . set (true) ; }")
        && helper.contains("Err (error) if error . is :: < super :: super :: AssertionDenied > () => { checked ? ; Ok (None) }")
        && helper.contains("Err (error) => Err (error)")
        && !helper.contains("to_string")
}

#[test]
fn actual_controller_denial_conversion_happens_only_after_the_mandatory_postcheck() {
    let source = include_str!("../controller.rs");
    assert!(denial_wiring(source));
    for (old, new) in [
        (
            "let checked = self.observe_controller(reader, executor);",
            "let checked = Ok(());",
        ),
        (
            "settle_verification(requested, checked)",
            "settle_verification(requested, Ok(()))",
        ),
        ("checked?;\n            Ok(None)", "Ok(None)"),
        (
            "error.is::<super::super::AssertionDenied>()",
            "error.to_string() == \"restore_passkey_signature_invalid\"",
        ),
        (
            "} else if matches!(&result, Ok(None)) {",
            "} else if false {",
        ),
    ] {
        assert_eq!(source.matches(old).count(), 1);
        let mutant = source.replace(old, new);
        syn::parse_file(&mutant).unwrap();
        assert!(!denial_wiring(&mutant));
    }
}
