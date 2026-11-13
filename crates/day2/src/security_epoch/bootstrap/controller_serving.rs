#[cfg(test)]
mod observation_boundary_tests {
    use quote::ToTokens;
    use syn::visit::Visit;

    fn lineage_check(node: &syn::ExprMethodCall) -> bool {
        node.method == "check"
            && matches!(&*node.receiver, syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "lineage")
                && matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("self")))
    }

    fn observations(method: &str) -> usize {
        if method == "serve_shell_current" {
            3
        } else {
            2
        }
    }

    // Inspect the actual fixed native callers. A helper fixture cannot catch
    // a repeated full check added at one of these call sites. This supplies
    // no native role, phase or permission and does not replace Linux tests.
    fn native_observation_shape(source: &str, method_name: &str) -> (usize, usize, usize) {
        #[derive(Default)]
        struct Calls {
            standalone_physical_checks: usize,
            observation_checks: usize,
            checked_observation_stages: usize,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
                if node.method == "check"
                    && matches!(&*node.receiver, syn::Expr::Path(path) if path.path.is_ident("physical"))
                {
                    self.standalone_physical_checks += 1;
                }
                if lineage_check(node) {
                    self.observation_checks += 1;
                    self.checked_observation_stages += usize::from(matches!(
                        node.args.iter().nth(2),
                        Some(syn::Expr::Try(guard)) if matches!(&*guard.expr,
                            syn::Expr::MethodCall(stage) if stage.method == "controller_stage"
                            && matches!(&*stage.receiver, syn::Expr::Path(path) if path.path.is_ident("physical")))
                    ));
                }
                syn::visit::visit_expr_method_call(self, node);
            }
        }
        let file = syn::parse_file(source).unwrap();
        let method = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("ActiveControllerStorageContinuity")) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| &item.items)
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == method_name => Some(method),
                _ => None,
            })
            .expect("actual fixed native serving method");
        let mut calls = Calls::default();
        calls.visit_block(&method.block);
        (
            calls.standalone_physical_checks,
            calls.observation_checks,
            calls.checked_observation_stages,
        )
    }

    #[test]
    fn app_and_shell_observation_consumers_keep_one_full_boundary_check() {
        for method in ["serve_app_current", "serve_shell_current"] {
            // Both reads retain their full checked getter. Shell also checks
            // its OLD observation after waiting and before the new read.
            assert_eq!(
                native_observation_shape(include_str!("../bootstrap.rs"), method),
                (
                    usize::from(method == "serve_shell_current"),
                    observations(method),
                    observations(method)
                )
            );
        }
    }

    fn observation_consumer(source: &str, method: &str) -> (String, syn::ExprMethodCall) {
        let file = syn::parse_file(source).unwrap();
        let actual = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("ActiveControllerStorageContinuity")) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| &item.items)
            .find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == method => Some(item),
                _ => None,
            })
            .expect("exact actual Controller method");
        struct Selected(Vec<syn::ExprMethodCall>);
        impl<'ast> Visit<'ast> for Selected {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if lineage_check(call) {
                    self.0.push(call.clone());
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut selected = Selected(Vec::new());
        selected.visit_block(&actual.block);
        assert_eq!(selected.0.len(), observations(method));
        (
            format!(
                "impl ActiveControllerStorageContinuity {{ {} }}",
                actual.to_token_stream()
            ),
            selected.0.remove(0),
        )
    }

    #[test]
    fn each_native_caller_rejects_restoring_the_immediate_physical_repeat() {
        let source = include_str!("../bootstrap.rs");
        for method in ["serve_app_current", "serve_shell_current"] {
            let (actual, consumer) = observation_consumer(source, method);
            let call = consumer.to_token_stream().to_string();
            assert!(actual.contains(&call));
            let repeated = actual.replacen(&call, &format!("{{ physical.check()?; {call} }}"), 1);
            assert_eq!(
                native_observation_shape(&repeated, method),
                (
                    usize::from(method == "serve_shell_current") + 1,
                    observations(method),
                    observations(method)
                )
            );
        }
    }

    #[test]
    fn each_observation_still_requires_the_full_checked_stage_getter() {
        let source = include_str!("../bootstrap.rs");
        for method in ["serve_app_current", "serve_shell_current"] {
            let (actual, consumer) = observation_consumer(source, method);
            let checked = consumer.to_token_stream().to_string();
            let mut unchecked = consumer.clone();
            unchecked.args[2] = syn::parse_quote!(unchecked_stage);
            assert!(actual.contains(&checked));
            let mutated = actual.replacen(&checked, &unchecked.to_token_stream().to_string(), 1);
            assert_ne!(
                native_observation_shape(&mutated, method),
                (
                    usize::from(method == "serve_shell_current"),
                    observations(method),
                    observations(method)
                )
            );
        }
    }

    #[test]
    fn shell_checks_the_old_observation_after_consumed_and_before_reread() {
        fn flow(source: &str) -> Vec<String> {
            struct Flow(Vec<String>);
            impl<'ast> Visit<'ast> for Flow {
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    let receiver = call.receiver.to_token_stream().to_string();
                    if receiver == "self . lineage"
                        && (call.method == "read" || call.method == "check")
                    {
                        self.0.push(call.method.to_string());
                    }
                    if receiver == "shell" && call.method == "await_consumed" {
                        self.0.push("consumed".into());
                    }
                    syn::visit::visit_expr_method_call(self, call);
                }
            }
            let file = syn::parse_file(source).unwrap();
            let mut found = Flow(Vec::new());
            found.visit_file(&file);
            found.0
        }
        let (source, _) =
            observation_consumer(include_str!("../bootstrap.rs"), "serve_shell_current");
        let expected = ["read", "check", "consumed", "check", "read", "check"];
        assert_eq!(flow(&source), expected);
        let file = syn::parse_file(&source).unwrap();
        struct Checks(Vec<String>);
        impl<'ast> Visit<'ast> for Checks {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if lineage_check(call) {
                    self.0.push(call.to_token_stream().to_string());
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut checks = Checks(Vec::new());
        checks.visit_file(&file);
        assert_eq!(checks.0.len(), 3);
        let call = &checks.0[1];
        assert!(checks.0.iter().all(|actual| actual == call));
        let first = source.find(call).unwrap();
        let second = first + call.len() + source[first + call.len()..].find(call).unwrap();
        let mut removed = source.clone();
        removed.replace_range(second..second + call.len(), "Ok::<(),anyhow::Error>(())");
        assert_ne!(flow(&removed), expected);
    }

    #[test]
    fn app_wait_read_receives_the_same_lineage_and_old_observation() {
        fn calls(source: &str) -> Vec<syn::ExprMethodCall> {
            struct Calls(Vec<syn::ExprMethodCall>);
            impl<'ast> Visit<'ast> for Calls {
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    if call.method == "announce_and_read_app_consumed" {
                        self.0.push(call.clone());
                    }
                    syn::visit::visit_expr_method_call(self, call);
                }
            }
            let file = syn::parse_file(source).unwrap();
            let mut found = Calls(Vec::new());
            found.visit_file(&file);
            found.0
        }
        let (source, _) =
            observation_consumer(include_str!("../bootstrap.rs"), "serve_app_current");
        let calls = calls(&source);
        let [call] = calls.as_slice() else {
            panic!("one actual closed wait/read");
        };
        let expected = [
            "& mut reads",
            "& self . store",
            "& self . lineage",
            "& mut observed",
            "trace",
        ];
        assert_eq!(call.receiver.to_token_stream().to_string(), "physical");
        assert_eq!(
            call.args
                .iter()
                .map(|arg| arg.to_token_stream().to_string())
                .collect::<Vec<_>>(),
            expected
        );
        let mut other = call.clone();
        other.args[3] = syn::parse_quote!(&mut other_observed);
        assert_ne!(
            other
                .args
                .iter()
                .map(|arg| arg.to_token_stream().to_string())
                .collect::<Vec<_>>(),
            expected
        );
    }
}
