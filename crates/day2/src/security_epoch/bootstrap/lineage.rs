#[cfg(test)]
mod tests {
    use super::super::*;
    use quote::ToTokens;
    use syn::visit::Visit;

    fn method(source: &str, name: &str) -> syn::Block {
        let file = syn::parse_file(source).unwrap();
        file.items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("ActiveLineage")) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| &item.items)
            .find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item.block.clone()),
                _ => None,
            })
            .expect("actual fixed lineage method")
    }

    fn expression(mut value: &syn::Expr) -> &syn::Expr {
        while let syn::Expr::Block(block) = value {
            if !block.attrs.is_empty() || block.label.is_some() {
                break;
            }
            let [syn::Stmt::Expr(inner, None)] = block.block.stmts.as_slice() else {
                break;
            };
            value = inner;
        }
        value
    }

    fn calls(block: &syn::Block) -> Vec<String> {
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if [
                    "require_selection_data",
                    "binding_data",
                    "require_pair_data",
                    "read",
                    "read_restored",
                    "check_observation",
                    "check_restored_observation",
                    "refuse",
                ]
                .iter()
                .any(|name| call.method == *name)
                {
                    self.0.push(format!(
                        "{}.{}({})",
                        call.receiver.to_token_stream(),
                        call.method,
                        call.args
                            .iter()
                            .map(|arg| arg.to_token_stream().to_string())
                            .collect::<Vec<_>>()
                            .join(";")
                    ));
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("request_names") || path.path.is_ident("check_active_snapshot"))
                {
                    self.0.push(format!(
                        "{}({})",
                        call.func.to_token_stream(),
                        call.args
                            .iter()
                            .map(|arg| arg.to_token_stream().to_string())
                            .collect::<Vec<_>>()
                            .join(";")
                    ));
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut found = Calls(Vec::new());
        found.visit_block(block);
        found.0
    }

    fn initial_arm(block: &syn::Block) -> Option<syn::Block> {
        struct Initial(Vec<syn::Block>);
        impl<'ast> Visit<'ast> for Initial {
            fn visit_expr_match(&mut self, expr: &'ast syn::ExprMatch) {
                for arm in &expr.arms {
                    if let syn::Pat::Tuple(pattern) = &arm.pat
                        && pattern
                            .elems
                            .iter()
                            .map(|p| p.to_token_stream().to_string())
                            .collect::<Vec<_>>()
                            == [
                                "LineageKind :: Initial (initial)",
                                "ObservationKind :: Initial (observed)",
                            ]
                        && let syn::Expr::Block(body) = &*arm.body
                    {
                        self.0.push(body.block.clone());
                    }
                }
                syn::visit::visit_expr_match(self, expr);
            }
        }
        let mut initial = Initial(Vec::new());
        initial.visit_block(block);
        let [body] = initial.0.as_slice() else {
            return None;
        };
        Some(body.clone())
    }

    fn initial_check_is_native_first(block: &syn::Block) -> bool {
        let Some(body) = initial_arm(block) else {
            return false;
        };
        let [
            syn::Stmt::Expr(syn::Expr::Try(native), Some(_)),
            syn::Stmt::Expr(syn::Expr::Call(snapshot), None),
        ] = body.stmts.as_slice()
        else {
            return false;
        };
        matches!(&*native.expr, syn::Expr::MethodCall(call)
            if call.method == "check_observation"
            && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("reads")))
            && matches!(&*snapshot.func, syn::Expr::Path(path) if path.path.is_ident("check_active_snapshot"))
    }

    #[test]
    fn restored_reader_pairing_compares_both_bindings_and_refuses_initial() {
        use syn::parse::Parser;
        fn binding(expr: &syn::Expr, owner: &str) -> bool {
            matches!(expr, syn::Expr::Try(value)
                if matches!(&*value.expr, syn::Expr::MethodCall(call)
                    if call.method == "binding_data" && call.args.is_empty()
                    && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident(owner))))
        }
        fn closed(body: &syn::Block) -> bool {
            let [syn::Stmt::Expr(syn::Expr::Match(branch), None)] = body.stmts.as_slice() else {
                return false;
            };
            if branch.expr.to_token_stream().to_string() != "& self . kind" {
                return false;
            }
            let [restored, initial] = branch.arms.as_slice() else {
                return false;
            };
            if restored.pat.to_token_stream().to_string() != "LineageKind :: Restored (reader)"
                || initial.pat.to_token_stream().to_string() != "LineageKind :: Initial (_)"
                || !matches!(expression(&initial.body), syn::Expr::Macro(mac)
                    if mac.mac.path.to_token_stream().to_string() == "anyhow :: bail")
            {
                return false;
            }
            let syn::Expr::Block(restored) = &*restored.body else {
                return false;
            };
            let [
                syn::Stmt::Macro(guard),
                syn::Stmt::Expr(syn::Expr::Call(done), None),
            ] = restored.block.stmts.as_slice()
            else {
                return false;
            };
            if !guard.mac.path.is_ident("ensure") {
                return false;
            }
            let Ok(args) =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(guard.mac.tokens.clone())
            else {
                return false;
            };
            let Some(syn::Expr::Binary(pair)) = args.first() else {
                return false;
            };
            args.len() == 2
                && matches!(pair.op, syn::BinOp::Eq(_))
                && binding(&pair.left, "reader")
                && binding(&pair.right, "expected")
                && matches!(&*done.func, syn::Expr::Path(path) if path.path.is_ident("Ok"))
                && done.args.len() == 1
                && matches!(done.args.first(), Some(syn::Expr::Tuple(unit)) if unit.elems.is_empty())
        }
        let actual = method(
            include_str!("../bootstrap.rs"),
            "require_restored_reader_data",
        );
        assert!(closed(&actual));
        let body = actual.to_token_stream().to_string();
        for (from, to) in [
            ("reader . binding_data ()", "expected . binding_data ()"),
            ("expected . binding_data ()", "reader . binding_data ()"),
            ("==", "!="),
            (
                "anyhow :: bail ! (\"active_lineage_restored_required\")",
                "Ok (())",
            ),
        ] {
            assert_eq!(body.matches(from).count(), 1, "{from}");
            let mutant = syn::parse_str::<syn::Block>(&body.replacen(from, to, 1)).unwrap();
            assert!(!closed(&mutant), "{from}");
        }
    }

    #[test]
    fn restored_lineage_metadata_requires_the_actual_pending_app_only() {
        fn closed(source: &str) -> bool {
            struct Factory {
                method: Option<String>,
                restored: Vec<Option<String>>,
            }
            impl<'ast> Visit<'ast> for Factory {
                fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                    if item.attrs.iter().any(|attr| {
                        matches!(&attr.meta, syn::Meta::List(list)
                        if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
                    }) {
                        return;
                    }
                    syn::visit::visit_item_mod(self, item);
                }
                fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                    let previous = self.method.replace(item.sig.ident.to_string());
                    syn::visit::visit_impl_item_fn(self, item);
                    self.method = previous;
                }
                fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                    let mut parts = path.path.segments.iter().rev();
                    if parts.next().is_some_and(|part| part.ident == "Restored")
                        && parts.next().is_some_and(|part| part.ident == "LineageKind")
                    {
                        self.restored.push(self.method.clone());
                    }
                    syn::visit::visit_expr_path(self, path);
                }
            }
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            let Some(actual) = file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("ActiveLineage")) {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "from_app_install" => Some(item),
                    _ => None,
                })
            }) else { return false; };
            let expected: syn::Block = syn::parse_quote!({
                let reader = pending.checked_restored_reader_data(selection)?;
                Ok(Self {
                    kind: LineageKind::Restored(Box::new(reader)),
                })
            });
            let mut factory = Factory {
                method: None,
                restored: Vec::new(),
            };
            factory.visit_file(&file);
            matches!(actual.vis, syn::Visibility::Inherited)
                && actual.sig.generics.params.is_empty()
                && actual.sig.asyncness.is_none()
                && actual.sig.output.to_token_stream().to_string() == "-> Result < Self >"
                && actual
                    .sig
                    .inputs
                    .iter()
                    .map(|arg| arg.to_token_stream().to_string())
                    .collect::<Vec<_>>()
                    == [
                        "pending : & mut crate :: security_epoch :: native_enrollment :: PendingRestoredEnrollment",
                        "selection : & EpochStore",
                    ]
                && actual.block.to_token_stream().to_string()
                    == expected.to_token_stream().to_string()
                && factory.restored == [Some("from_app_install".to_owned())]
        }
        let actual = syn::parse_file(include_str!("../bootstrap.rs")).unwrap();
        let items = actual
            .items
            .into_iter()
            .filter(|item| {
                let attrs = match item {
                    syn::Item::Mod(item) => &item.attrs,
                    syn::Item::Fn(item) => &item.attrs,
                    _ => return true,
                };
                !attrs.iter().any(|attr| {
                    matches!(&attr.meta, syn::Meta::List(list)
                if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
                })
            })
            .collect::<Vec<_>>();
        let production = quote::quote!(#(#items)*).to_string();
        let source = production.as_str();
        assert!(closed(source));
        for (from, to) in [
            (
                "pending : & mut crate :: security_epoch :: native_enrollment :: PendingRestoredEnrollment",
                "pending : & mut crate :: security_epoch :: firestore :: RestoreWriterPeerRead",
            ),
            (
                "pending . checked_restored_reader_data (selection) ?",
                "other . checked_restored_reader_data (selection) ?",
            ),
            (
                "pending . checked_restored_reader_data (selection) ?",
                "pending . checked_restored_reader_data (other_selection) ?",
            ),
            (
                "pending . checked_restored_reader_data (selection) ?",
                "pending . checked_restored_reader_data (selection)",
            ),
            (
                "LineageKind :: Restored (Box :: new (reader))",
                "LineageKind :: Restored (Box :: new (cached_reader))",
            ),
        ] {
            assert_eq!(source.matches(from).count(), 1, "{from}");
            assert!(!closed(&source.replacen(from, to, 1)), "{from}");
        }
        for extra in [
            "fn unchecked() {let _ = LineageKind::Restored(Box::new(data));}",
            "fn unchecked() {let _ = self::LineageKind::Restored(Box::new(data));}",
            "fn unchecked() {let _ = crate::security_epoch::bootstrap::LineageKind::Restored(Box::new(data));}",
            "fn unchecked() {let constructor = self::LineageKind::Restored; let _ = constructor(Box::new(data));}",
        ] {
            assert!(!closed(&format!("{source}\n{extra}")), "{extra}");
        }
    }

    #[test]
    fn fixed_read_dispatch_uses_the_actual_request_and_one_correct_lineage() {
        let actual = method(include_str!("../bootstrap.rs"), "read");
        let expected = [
            "self.require_selection_data(selection)",
            "self.binding_data()",
            "request_names(selection;& initial . completion)",
            "reads.read(stage;selection;& names)",
            "check_active_snapshot(selection;& initial . completion;& initial . activation;observed . snapshot ())",
            "observed.refuse()",
            "reads.read_restored(stage;selection;reader)",
            "reads.refuse()",
        ];
        assert_eq!(calls(&actual), expected);
        let body = actual.to_token_stream().to_string();
        for (from, to) in [
            (
                "self . require_selection_data",
                "other . require_selection_data",
            ),
            ("reads . read_restored", "other_reads . read_restored"),
            ("reads . read (", "other_reads . read ("),
            ("observed . refuse", "unrelated . refuse"),
            ("reads . refuse", "unrelated . refuse"),
        ] {
            assert_eq!(body.matches(from).count(), 1, "{from}");
            assert_ne!(
                calls(&syn::parse_str::<syn::Block>(&body.replacen(from, to, 1)).unwrap()),
                expected
            );
        }
    }

    #[test]
    fn fixed_check_pairs_before_use_and_keeps_native_precedence_and_both_refusals() {
        let actual = method(include_str!("../bootstrap.rs"), "check");
        let expected = [
            "self.require_selection_data(selection)",
            "self.require_pair_data(observed)",
            "reads.check_observation(stage;observed)",
            "check_active_snapshot(selection;& initial . completion;& initial . activation;observed . snapshot ())",
            "reads.check_restored_observation(stage;reader;observed)",
            "observed.refuse()",
            "reads.refuse()",
        ];
        assert_eq!(calls(&actual), expected);
        assert!(initial_check_is_native_first(&actual));
        let body = actual.to_token_stream().to_string();
        for (from, to) in [
            ("self . require_pair_data", "other . require_pair_data"),
            (
                "reads . check_restored_observation",
                "other_reads . check_restored_observation",
            ),
            ("observed . refuse", "unrelated . refuse"),
            ("reads . refuse", "unrelated . refuse"),
        ] {
            assert_eq!(body.matches(from).count(), 1, "{from}");
            assert_ne!(
                calls(&syn::parse_str::<syn::Block>(&body.replacen(from, to, 1)).unwrap()),
                expected
            );
        }
        let arm = initial_arm(&actual).unwrap();
        let [
            syn::Stmt::Expr(syn::Expr::Try(native), Some(_)),
            syn::Stmt::Expr(syn::Expr::Call(snapshot), None),
        ] = arm.stmts.as_slice()
        else {
            panic!("actual initial arm");
        };
        let native = &native.expr;
        let reversed: syn::Block = syn::parse_quote!({ #snapshot?; #native });
        let from = arm.to_token_stream().to_string();
        assert_eq!(body.matches(&from).count(), 1);
        let reversed = syn::parse_str::<syn::Block>(&body.replacen(
            &from,
            &reversed.to_token_stream().to_string(),
            1,
        ))
        .unwrap();
        assert!(!initial_check_is_native_first(&reversed));
    }

    #[test]
    fn initial_lineage_keeps_both_existing_binding_domains() -> Result<()> {
        let create = crate::security_epoch::tests::create();
        let completion = Request::CompleteInitialFirstActivation {
            bootstrap: create.bootstrap().clone(),
            operation: Digest::new(b"completion"),
            parent_receipt: create.receipt()?.digest()?,
            before: crate::security_epoch::kernel::Versions {
                root: "2026-11-04T00:00:00.000001Z".to_owned().try_into()?,
                sentinel: "2026-11-04T00:00:00.000001Z".to_owned().try_into()?,
            },
            holder: crate::security_epoch::kernel::Holder {
                principal: Digest::new(b"principal"),
                pod_uid: "a6b27e63-16d8-4b99-92f6-2437e5b20f43".into(),
                process_incarnation: Digest::new(b"incarnation"),
                ephemeral_key: Digest::new(b"key"),
            },
        };
        let lineage =
            ActiveLineage::initial(completion.clone(), Digest::new(b"full-initial-snapshot"));
        let operation = Digest::new(b"actual-request-binding");
        assert_eq!(
            lineage.serving_binding(&operation)?,
            Digest::of(&(
                "day2-current-active-app-storage-v1",
                completion.digest()?,
                &operation,
            ))?
        );
        assert_eq!(
            lineage.admin_binding(&operation)?,
            Digest::of(&(
                "day2-current-admin-read-v1",
                completion.digest()?,
                &operation,
            ))?
        );
        assert_ne!(
            lineage.serving_binding(&operation)?,
            lineage.admin_binding(&operation)?
        );
        Ok(())
    }

    #[test]
    fn actual_observation_has_private_fields_and_only_the_real_read_factory() {
        struct Origins(usize);
        impl<'ast> Visit<'ast> for Origins {
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if value
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "ActiveObservation")
                {
                    self.0 += 1;
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let source = include_str!("../bootstrap.rs");
        let file = syn::parse_file(source).unwrap();
        let mut found = Origins(0);
        found.visit_file(&file);
        assert_eq!(found.0, 1);
        let read = method(source, "read");
        let mut factory = Origins(0);
        factory.visit_block(&read);
        assert_eq!(factory.0, 1);
        let extra = format!(
            "{source}\nfn unrelated() {{ let _ = self::ActiveObservation {{binding: data, kind: data}}; }}"
        );
        let mut duplicate = Origins(0);
        duplicate.visit_file(&syn::parse_file(&extra).unwrap());
        assert_eq!(duplicate.0, 2);
        let wrapper = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "ActiveObservation" => Some(item),
                _ => None,
            })
            .unwrap();
        assert_eq!(wrapper.fields.len(), 2);
        assert!(
            wrapper
                .fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        );
    }

    #[test]
    fn first_restore_snapshot_selection_never_casts_restored_history() {
        fn closed(body: &syn::Block) -> bool {
            let [
                syn::Stmt::Expr(syn::Expr::Try(pair), Some(_)),
                syn::Stmt::Expr(syn::Expr::Match(selected), None),
            ] = body.stmts.as_slice()
            else {
                return false;
            };
            if !matches!(&*pair.expr, syn::Expr::MethodCall(call)
                if call.method == "require_pair_data"
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("self"))
                && call.args.len() == 1
                && matches!(call.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident("observed")))
                || selected.expr.to_token_stream().to_string() != "& observed . kind"
            {
                return false;
            }
            let [initial, restored] = selected.arms.as_slice() else {
                return false;
            };
            let syn::Pat::TupleStruct(initial_pattern) = &initial.pat else {
                return false;
            };
            let syn::Pat::TupleStruct(restored_pattern) = &restored.pat else {
                return false;
            };
            initial_pattern.path.to_token_stream().to_string() == "ObservationKind :: Initial"
                && restored_pattern.path.to_token_stream().to_string()
                    == "ObservationKind :: Restored"
                && matches!(expression(&restored.body), syn::Expr::Macro(mac)
                    if mac.mac.path.to_token_stream().to_string() == "anyhow :: bail")
        }
        let actual = method(
            include_str!("../bootstrap.rs"),
            "initial_restore_snapshot_data",
        );
        assert!(closed(&actual));
        let body = actual.to_token_stream().to_string();
        let from = "anyhow :: bail ! (\"initial_restore_lineage_required\")";
        assert_eq!(body.matches(from).count(), 1);
        assert!(!closed(
            &syn::parse_str::<syn::Block>(&body.replacen(from, "Ok (cached_snapshot)", 1)).unwrap()
        ));
    }

    #[test]
    fn initial_restore_adapters_keep_selection_and_exact_arguments() {
        fn selected(body: &syn::Block) -> Option<String> {
            let [
                syn::Stmt::Expr(syn::Expr::Try(selection), Some(_)),
                syn::Stmt::Expr(syn::Expr::Match(branch), None),
            ] = body.stmts.as_slice()
            else {
                return None;
            };
            if selection.expr.to_token_stream().to_string()
                != "self . require_selection_data (selection)"
                || branch.expr.to_token_stream().to_string() != "& self . kind"
            {
                return None;
            }
            let [initial, _] = branch.arms.as_slice() else {
                return None;
            };
            if initial.pat.to_token_stream().to_string() != "LineageKind :: Initial (initial)" {
                return None;
            }
            let syn::Expr::Call(call) = expression(&initial.body) else {
                return None;
            };
            Some(format!(
                "{}({})",
                call.func.to_token_stream(),
                call.args
                    .iter()
                    .map(|arg| arg.to_token_stream().to_string())
                    .collect::<Vec<_>>()
                    .join(";")
            ))
        }
        let source = include_str!("../bootstrap.rs");
        for (name, expected) in [
            (
                "initial_restore_names_data",
                "request_names(selection;& initial . completion)",
            ),
            (
                "initial_restore_stop_selection_data",
                "crate :: security_epoch :: kernel :: restore :: StopSelection :: new(selection;intent;& initial . completion;before)",
            ),
        ] {
            let actual = method(source, name);
            assert_eq!(selected(&actual).as_deref(), Some(expected));
            let body = actual.to_token_stream().to_string();
            for (from, to) in [
                (
                    "self . require_selection_data (selection)",
                    "self . require_selection_data (other_selection)",
                ),
                ("& initial . completion", "& cached_completion"),
            ] {
                assert_eq!(body.matches(from).count(), 1, "{name}: {from}");
                let mutant = syn::parse_str::<syn::Block>(&body.replacen(from, to, 1)).unwrap();
                assert_ne!(selected(&mutant).as_deref(), Some(expected));
            }
        }
    }

    #[test]
    fn first_restore_leaf_callers_use_only_closed_initial_adapters() {
        fn closed(source: &str) -> bool {
            struct Calls {
                names: usize,
                stop: usize,
                snapshot: usize,
                invalid: bool,
            }
            impl<'ast> Visit<'ast> for Calls {
                fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                    if item.attrs.iter().any(|attr| {
                        matches!(&attr.meta, syn::Meta::List(list)
                        if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
                    }) {
                        return;
                    }
                    syn::visit::visit_item_mod(self, item);
                }
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    let receiver = call.receiver.to_token_stream().to_string();
                    let args = call
                        .args
                        .iter()
                        .map(|arg| arg.to_token_stream().to_string())
                        .collect::<Vec<_>>();
                    if call.method == "initial_restore_names_data" {
                        self.names += 1;
                        let loan = receiver.strip_suffix(" . lineage");
                        self.invalid |= !loan.is_some_and(|loan| {
                            [
                                "self . loan",
                                "self . auth . action . reader . loan",
                                "self . executor . action . reader . loan",
                            ]
                            .contains(&loan)
                                && args == [format!("& {loan} . selection")]
                        });
                    } else if call.method == "initial_restore_stop_selection_data" {
                        self.stop += 1;
                        self.invalid |= receiver != "auth . action . reader . loan . lineage"
                            || args != ["& selection", "intent", "& before"];
                    } else if call.method == "initial_restore_snapshot_data" {
                        self.snapshot += 1;
                        self.invalid |=
                            receiver != "auth . action . reader . loan" || !args.is_empty();
                    }
                    syn::visit::visit_expr_method_call(self, call);
                }
                fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                    let base = field.base.to_token_stream().to_string();
                    self.invalid |= field.member.to_token_stream().to_string() == "completion"
                        && base.ends_with(" . loan");
                    syn::visit::visit_expr_field(self, field);
                }
            }
            let mut calls = Calls {
                names: 0,
                stop: 0,
                snapshot: 0,
                invalid: false,
            };
            calls.visit_file(&syn::parse_file(source).unwrap());
            !calls.invalid && (calls.names, calls.stop, calls.snapshot) == (6, 1, 1)
        }
        let source =
            include_str!("admin_read/reader/authentication_store/producer/consumer/stop.rs");
        assert!(closed(source));
        for (from, to) in [
            (".initial_restore_names_data", ".unchecked_names"),
            (".initial_restore_stop_selection_data", ".unchecked_stop"),
            (".initial_restore_snapshot_data", ".unchecked_snapshot"),
        ] {
            assert!(source.contains(from));
            assert!(!closed(&source.replacen(from, to, 1)));
        }
    }

    #[test]
    fn initial_birth_stop_and_confirmation_metadata_all_refuse_restored_lineage() {
        fn refuses(body: &syn::Block) -> bool {
            let Some(syn::Stmt::Expr(syn::Expr::Match(selected), None)) = body.stmts.last() else {
                return false;
            };
            if selected.expr.to_token_stream().to_string() != "& self . kind" {
                return false;
            }
            let [_, restored] = selected.arms.as_slice() else {
                return false;
            };
            matches!(&restored.pat, syn::Pat::TupleStruct(pattern)
                if pattern.path.to_token_stream().to_string() == "LineageKind :: Restored")
                && matches!(expression(&restored.body), syn::Expr::Macro(mac)
                    if mac.mac.path.to_token_stream().to_string() == "anyhow :: bail")
        }
        let source = include_str!("../bootstrap.rs");
        for name in [
            "initial_runtime_artifact_data",
            "initial_restore_names_data",
            "initial_restore_stop_selection_data",
            "check_initial_restore_stop_data",
            "initial_restore_confirmation_data",
        ] {
            let actual = method(source, name);
            assert!(refuses(&actual), "{name}");
            let body = actual.to_token_stream().to_string();
            let from = "anyhow :: bail ! (\"initial_restore_lineage_required\")";
            assert_eq!(body.matches(from).count(), 1);
            let bypass =
                syn::parse_str::<syn::Block>(&body.replacen(from, "Ok (cached_initial_data)", 1))
                    .unwrap();
            assert!(!refuses(&bypass), "{name}");
        }
    }

    #[test]
    fn initial_factory_is_confined_to_the_fixed_successful_bootstrap_sites() {
        fn sites(source: &str) -> Option<Vec<(Option<String>, String)>> {
            struct Sites {
                owner: Option<String>,
                method: Option<String>,
                found: Vec<(Option<String>, String)>,
                invalid: bool,
            }
            impl<'ast> Visit<'ast> for Sites {
                fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                    if item.attrs.iter().any(|attr| {
                        matches!(&attr.meta, syn::Meta::List(list)
                        if list.path.is_ident("cfg") && list.tokens.to_string() == "test")
                    }) {
                        return;
                    }
                    syn::visit::visit_item_mod(self, item);
                }
                fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                    let owner = self.owner.take();
                    self.owner = match &*item.self_ty {
                        syn::Type::Path(path) => {
                            path.path.segments.last().map(|part| part.ident.to_string())
                        }
                        _ => None,
                    };
                    syn::visit::visit_item_impl(self, item);
                    self.owner = owner;
                }
                fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                    let previous = self.method.replace(item.sig.ident.to_string());
                    syn::visit::visit_impl_item_fn(self, item);
                    self.method = previous;
                }
                fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                    let previous = self.method.replace(item.sig.ident.to_string());
                    syn::visit::visit_item_fn(self, item);
                    self.method = previous;
                }
                fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                    if matches!(&*call.func, syn::Expr::Path(path) if path.path.segments.len() >= 2
                        && path.path.segments[path.path.segments.len()-2].ident == "ActiveLineage"
                        && path.path.segments.last().is_some_and(|part| part.ident == "initial"))
                    {
                        self.invalid |= call.args.len() != 2 || !call.args.iter().zip(["completion", "activation"])
                            .all(|(arg,name)| matches!(arg, syn::Expr::Path(path) if path.path.is_ident(name)));
                        self.found
                            .push((self.owner.clone(), self.method.clone().unwrap_or_default()));
                    }
                    syn::visit::visit_expr_call(self, call);
                }
            }
            let file = syn::parse_file(source).ok()?;
            let mut sites = Sites {
                owner: None,
                method: None,
                found: Vec::new(),
                invalid: false,
            };
            sites.visit_file(&file);
            let expected = vec![
                (
                    Some("AppStorageBootstrap".to_owned()),
                    "into_active".to_owned(),
                ),
                (None, "activate_controller".to_owned()),
            ];
            (!sites.invalid && sites.found == expected).then_some(sites.found)
        }
        let source = include_str!("../bootstrap.rs");
        assert!(sites(source).is_some());
        let third = format!(
            "{source}\nfn unrelated() {{ let _ = self::ActiveLineage::initial(completion, activation); }}"
        );
        assert!(sites(&third).is_none());
        let wrong = source.replacen(
            "ActiveLineage::initial(completion, activation)",
            "ActiveLineage::initial(other_completion, activation)",
            1,
        );
        assert_ne!(source, wrong);
        assert!(sites(&wrong).is_none());
    }
}
