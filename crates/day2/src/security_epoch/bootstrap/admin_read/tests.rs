use super::*;
use syn::visit::Visit;

#[test]
fn actor_errors_never_export_the_claimed_identity() {
    let marker = "domain:private-admin-marker";
    let error = validate_actor(marker).unwrap_err();
    assert_eq!(error.to_string(), "controller_admin_actor_shape");
    assert!(!format!("{error:#}").contains(marker));
    validate_actor("alice@example.com").unwrap();
}

// The model knows only open/excluded/terminal, not the implementation enum.
// Seed and event history are printed on a mismatch for exact replay. This
// exercises the production local reducer, not invented native stage owners.
#[test]
fn seeded_sql_lifetime_histories_match_an_independent_model() {
    for seed in 1_u64..=512 {
        let mut random = seed;
        let mut actual = ReadDisposition::new();
        let (mut live, mut sql) = (true, false);
        let mut history = Vec::new();
        for _ in 0..64 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let action = random % 7;
            history.push(action);
            let expected = match action {
                0 => {
                    let allowed = live && !sql;
                    if allowed {
                        sql = true;
                    } else {
                        live = false;
                    }
                    allowed
                }
                1 | 2 => {
                    let allowed = live && sql && action == 1;
                    if allowed {
                        sql = false;
                    } else {
                        live = false;
                    }
                    allowed
                }
                3 => live,
                4 => live && !sql,
                5 => {
                    let allowed = live && !sql;
                    live = false;
                    allowed
                }
                _ => {
                    live = false;
                    true
                }
            };
            let observed = match action {
                0 => actual.begin_sql().is_ok(),
                1 | 2 => actual.end_sql(action == 1).is_ok(),
                3 => actual.check().is_ok(),
                4 => actual.require_closed().is_ok(),
                5 => actual.finish().is_ok(),
                _ => {
                    actual.refuse();
                    true
                }
            };
            assert_eq!(observed, expected, "seed={seed} events={history:?}");
        }
    }
}

#[test]
fn open_sql_never_allows_provider_or_release_and_unknown_close_is_permanent() {
    let mut state = ReadDisposition::new();
    state.begin_sql().unwrap();
    // Local identity checks remain possible throughout the entire unit.
    state.check().unwrap();
    assert!(state.require_closed().is_err());
    assert!(state.end_sql(false).is_err());
    assert!(state.end_sql(true).is_err());
    assert!(state.begin_sql().is_err());
    assert!(state.finish().is_err());
    assert!(state.check().is_err());
}

// An independently tracked connection lifetime is deliberately different from
// the transaction lifetime. Neither autocommit nor a successful unit may release
// the peer while the actual reader remains open.
#[test]
fn retained_reader_units_match_independent_connection_and_transaction_histories() {
    for seed in 1_u64..=512 {
        let mut random = seed;
        let mut actual = ReadDisposition::new();
        let (mut live, mut connection, mut transaction) = (true, false, false);
        let mut history = Vec::new();
        for _ in 0..64 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let action = random % 8;
            history.push(action);
            let expected = match action {
                0 => {
                    let yes = live && !connection && !transaction;
                    if yes {
                        connection = true;
                    }
                    yes
                }
                1 => {
                    let yes = live && !transaction;
                    if yes {
                        transaction = true;
                    } else {
                        live = false;
                    }
                    yes
                }
                2 => {
                    let yes = live && connection && transaction;
                    if yes {
                        transaction = false;
                    } else {
                        live = false;
                    }
                    yes
                }
                3 => {
                    let yes = live && connection && !transaction;
                    if yes {
                        connection = false;
                    }
                    yes
                }
                4 => {
                    let yes = live && !connection && transaction;
                    if yes {
                        transaction = false;
                    } else {
                        live = false;
                    }
                    yes
                }
                5 => live && !transaction,
                6 => {
                    let yes = live && !connection && !transaction;
                    live = false;
                    yes
                }
                _ => {
                    live = false;
                    true
                }
            };
            let observed = match action {
                0 => actual.retain_reader().is_ok(),
                1 => {
                    if connection {
                        actual.begin_retained_sql().is_ok()
                    } else {
                        actual.begin_sql().is_ok()
                    }
                }
                2 => actual.end_retained_sql(true).is_ok(),
                3 => actual.close_reader().is_ok(),
                4 => actual.end_sql(true).is_ok(),
                5 => actual.require_closed().is_ok(),
                6 => actual.finish().is_ok(),
                _ => {
                    actual.refuse();
                    true
                }
            };
            assert_eq!(observed, expected, "seed={seed} events={history:?}");
        }
    }
}

#[test]
fn successful_reader_unit_is_not_connection_close_or_peer_release() {
    let mut state = ReadDisposition::new();
    state.retain_reader().unwrap();
    state.begin_retained_sql().unwrap();
    assert!(state.require_closed().is_err());
    state.end_retained_sql(true).unwrap();
    state.require_closed().unwrap();
    assert!(state.require_released().is_err());
    state.close_reader().unwrap();
    state.finish().unwrap();

    let mut state = ReadDisposition::new();
    state.retain_reader().unwrap();
    state.begin_retained_sql().unwrap();
    assert!(state.end_sql(true).is_err());
    assert!(state.end_retained_sql(true).is_err());
    assert!(state.close_reader().is_err());
    assert!(state.finish().is_err());

    let mut state = ReadDisposition::new();
    state.retain_reader().unwrap();
    state.begin_retained_sql().unwrap();
    assert!(state.end_retained_sql(false).is_err());
    assert!(state.end_retained_sql(true).is_err());
    assert!(state.close_reader().is_err());
    assert!(state.finish().is_err());

    // The one-shot projection cannot open a second connection inside the
    // retained session. It refuses BEFORE the fixed adapter's SQLite open.
    let mut state = ReadDisposition::new();
    state.retain_reader().unwrap();
    assert!(state.begin_sql().is_err());
    assert!(state.begin_retained_sql().is_err());
}

fn method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
    syn::parse_file(source)
        .unwrap()
        .items
        .into_iter()
        .filter_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            let syn::Type::Path(path) = &*item.self_ty else {
                return None;
            };
            path.path
                .segments
                .last()
                .is_some_and(|part| part.ident == owner)
                .then_some(item)
        })
        .flat_map(|item| item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        })
        .expect("actual production method")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.len() == 2
            && node.path.segments[0].ident == "Connection"
            && node.path.segments[1].ident == "close"
        {
            self.0.push("close".to_owned());
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        // Receiver/arguments execute before the method result is consumed.
        syn::visit::visit_expr_method_call(self, node);
        self.0.push(node.method.to_string());
    }
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        syn::visit::visit_expr_call(self, node);
        if let syn::Expr::Path(path) = &*node.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
    }
}
fn calls(source: &str, owner: &str, name: &str) -> Vec<String> {
    let mut visitor = Calls::default();
    visitor.visit_block(&method(source, owner, name).block);
    visitor.0
}
fn before(calls: &[String], first: &str, second: &str) -> bool {
    matches!((calls.iter().position(|x| x == first), calls.iter().position(|x| x == second)), (Some(a), Some(b)) if a < b)
}

fn app_two_phase_stop(method: &syn::ImplItemFn) -> bool {
    use quote::ToTokens as _;
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    let selected: Vec<&str> = calls
        .0
        .iter()
        .map(String::as_str)
        .filter(|name| {
            matches!(
                *name,
                "seal"
                    | "check_initial_restore_stop_data"
                    | "check_drained"
                    | "acknowledge_restore_stop"
                    | "await_restore_fence"
                    | "confirm_restore_reservation"
                    | "acknowledge_restore_fence"
                    | "await_restore_release"
                    | "finish_restore_stopped"
            )
        })
        .collect();
    #[derive(Default)]
    struct CapturedOperation {
        count: usize,
        valid: bool,
        captures: usize,
        captured: bool,
    }
    impl<'ast> Visit<'ast> for CapturedOperation {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "check_initial_restore_stop_data" {
                self.count += 1;
                self.valid = call.receiver.to_token_stream().to_string() == "self . lineage"
                    && call.args.len() == 4
                    && call.args[0].to_token_stream().to_string() == "& self . store"
                    && matches!(call.args.get(1),Some(syn::Expr::Path(path)) if path.path.is_ident("restore_operation"))
                    && call.args[2].to_token_stream().to_string() == "& stopped . selection"
                    && call.args[3].to_token_stream().to_string() == "& before";
            }
            if call.method == "restore_operation_data" {
                self.captures += 1;
                self.captured = matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("operation"))
                    && call.args.is_empty();
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut operation = CapturedOperation::default();
    operation.visit_block(&method.block);
    selected
        == [
            "seal",
            "check_initial_restore_stop_data",
            "check_drained",
            "acknowledge_restore_stop",
            "await_restore_fence",
            "check_drained",
            "confirm_restore_reservation",
            "check_drained",
            "acknowledge_restore_fence",
            "await_restore_release",
            "check_drained",
            "finish_restore_stopped",
        ]
        && operation.count == 1
        && operation.valid
        && operation.captures == 1
        && operation.captured
        && !calls.0.iter().any(|name| name == "check_fenced_initial")
}

#[test]
fn actual_app_stop_drains_active_then_confirms_known_fence_on_the_same_original() {
    use quote::ToTokens as _;
    let actual = method(
        include_str!("../admin_read.rs"),
        "ActiveAppStorageContinuity",
        "admin_read",
    );
    assert!(app_two_phase_stop(&actual));
    let rendered = actual.to_token_stream().to_string();
    let parse = |rendered: &str| {
        method(
            &format!("impl Dummy {{ {rendered} }}"),
            "Dummy",
            "admin_read",
        )
    };
    for target in [
        "check_initial_restore_stop_data",
        "acknowledge_restore_stop",
        "await_restore_fence",
        "confirm_restore_reservation",
        "acknowledge_restore_fence",
        "await_restore_release",
    ] {
        assert_eq!(rendered.matches(target).count(), 1, "{target}");
        assert!(
            !app_two_phase_stop(&parse(&rendered.replacen(target, "unchecked_data", 1))),
            "{target}"
        );
    }
    #[derive(Default)]
    struct SelectedCall(Vec<syn::ExprMethodCall>);
    impl<'ast> Visit<'ast> for SelectedCall {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "check_initial_restore_stop_data" {
                self.0.push(call.clone());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut selected = SelectedCall::default();
    selected.visit_block(&actual.block);
    assert_eq!(selected.0.len(), 1);
    let mut changed = selected.0.pop().unwrap();
    let original = changed.to_token_stream().to_string();
    assert_eq!(rendered.matches(&original).count(), 1);
    let mut wrong_lineage = changed.clone();
    *wrong_lineage.receiver = syn::parse_quote!(unrelated.lineage);
    assert!(!app_two_phase_stop(&parse(&rendered.replacen(
        &original,
        &wrong_lineage.to_token_stream().to_string(),
        1
    ))));
    changed.args[1] = syn::parse_quote!(&stopped.selection.restore_operation);
    assert!(!app_two_phase_stop(&parse(&rendered.replacen(
        &original,
        &changed.to_token_stream().to_string(),
        1
    ))));
    let captured = "restore_operation_data";
    assert_eq!(rendered.matches(captured).count(), 1);
    assert!(!app_two_phase_stop(&parse(&rendered.replacen(
        captured,
        "unchecked_data",
        1
    ))));
    let controller = calls(
        include_str!("../admin_read.rs"),
        "ActiveControllerStorageContinuity",
        "begin_admin_read",
    );
    assert_eq!(
        controller
            .iter()
            .filter(|name| *name == "require_admin_operation_data")
            .count(),
        1
    );
    assert!(before(&controller, "require_admin_operation_data", "read"));
    let freeze = calls(
        include_str!("../../native_enrollment/storage_peer/continuation.rs"),
        "CurrentStoragePeerPhase",
        "freeze_restore_issuer",
    );
    assert_eq!(
        freeze
            .iter()
            .filter(|name| *name == "require_restore_operation_data")
            .count(),
        1
    );
    assert!(before(
        &freeze,
        "require_restore_operation_data",
        "capture_restore"
    ));
}

fn ordered(source: &str) -> bool {
    let read = calls(source, "InitialStoreMetadata", "controller_admin_data");
    [
        "begin_sql",
        "open_readonly",
        "transaction",
        "check_database",
        "project",
        "commit",
        "close",
        "end_sql",
        "check_metadata",
    ]
    .windows(2)
    .all(|pair| {
        // The first metadata check precedes SQL; compare final postcheck.
        if pair[1] == "check_metadata" {
            read.iter().position(|x| x == "end_sql")
                < read.iter().rposition(|x| x == "check_metadata")
        } else {
            before(&read, pair[0], pair[1])
        }
    })
}

#[test]
fn real_reader_wiring_closes_sql_before_reobservation_and_acceptance() {
    let source = include_str!("../../../store/native_storage/controller_admins.rs");
    assert!(ordered(source));
    for (old, new) in [
        ("loan.begin_sql()?;", ""),
        ("loan.check_database(&tx)?;", ""),
        (
            "let checked = loan.check_metadata(self);",
            "let checked = Ok(());",
        ),
        ("let ended = loan.end_sql(&closed);", "let ended = Ok(());"),
        ("Connection::close", "Connection::is_autocommit"),
    ] {
        let mutated = source.replace(old, new);
        assert_ne!(source, mutated, "one actual target {old}");
        assert!(!ordered(&mutated), "guard must reject {old}");
    }
}

fn opened_before_configuration(loan: &str, single: &str, retained: &str) -> bool {
    let bind = calls(loan, "ControllerAdminReadLoan", "retain_reader");
    let single = calls(single, "InitialStoreMetadata", "controller_admin_data");
    let retained = calls(retained, "ControllerAdminSqlite", "open");
    before(&bind, "check_opened_database", "retain_reader")
        && before(&single, "check_opened_database", "configure_connection")
        && before(&retained, "retain_reader", "configure_connection")
}

#[test]
fn both_actual_reader_entries_check_opened_members_before_configuration() {
    let loan = include_str!("../admin_read.rs");
    let single = include_str!("../../../store/native_storage/controller_admins.rs");
    let retained = include_str!("../../../store/native_storage/controller_admins/reader.rs");
    assert!(opened_before_configuration(loan, single, retained));
    let changed = loan.replacen("self.check_opened_database(db)?;", "", 1);
    assert_ne!(loan, changed);
    assert!(!opened_before_configuration(&changed, single, retained));
    let changed = single.replacen("loan.check_opened_database(db)?;", "", 1);
    assert_ne!(single, changed);
    assert!(!opened_before_configuration(loan, &changed, retained));
    let read = calls(single, "InitialStoreMetadata", "controller_admin_data");
    assert!(before(&read, "check_database", "project"));
    assert!(
        read.iter().rposition(|call| call == "check_database")
            > read.iter().position(|call| call == "project")
    );
}

fn final_order(source: &str) -> bool {
    let finish = calls(source, "ControllerAdminReadLoan", "finish_checked");
    let refresh = calls(source, "ControllerAdminReadLoan", "refresh");
    before(&refresh, "require_closed", "read")
        && before(&finish, "refresh", "announce_and_read_app_consumed")
        && before(&finish, "announce_and_read_app_consumed", "finish")
        && before(&finish, "finish", "finish_app_known")
        && !before(&finish, "finish_app_known", "finish")
        && finish.iter().filter(|call| *call == "finish").count() == 2
}

#[test]
fn real_loan_retains_originals_and_only_known_final_path_restores_continuations() {
    let source = include_str!("../admin_read.rs");
    assert!(final_order(source));
    for (old, new) in [
        ("self.disposition.require_closed()?;", ""),
        ("self.reads.finish(physical.controller_stage()?)?;", ""),
        (".finish_app_known()?", ".check()?"),
    ] {
        let changed = source.replace(old, new);
        assert_ne!(source, changed);
        assert!(!final_order(&changed));
    }
    let file = syn::parse_file(source).unwrap();
    assert!(!file.items.iter().any(|item| matches!(item, syn::Item::Impl(item) if item.trait_.as_ref().is_some_and(|(_, path, _)| path.is_ident("Drop")))));
    // Actual field guards, not a generic unsupported Drop or simulated Native.
    let counter = include_str!("../../authenticated_reads/connection.rs");
    assert!(counter.contains("impl Drop for CounterUseGuard"));
    assert!(counter.contains("if !self.completed {\n            self.refuse();"));
    let physical = include_str!("../../storage_authority/preparation/continuity.rs");
    assert!(physical.contains("*continuation = false;"));
    assert!(physical.contains("*self.continuation = true;"));
    let initial = include_str!("../../storage_authority/initial.rs");
    let app = calls(initial, "AppInitialStorageContinuity", "begin_admin_read");
    assert!(before(&app, "begin", "sqlite_cohort"));
    assert!(before(&app, "sqlite_cohort", "begin_current"));
    let app_operation = method(source, "ActiveAppStorageContinuity", "admin_read");
    fn closed_app_admin(method: &syn::ImplItemFn) -> bool {
        use quote::ToTokens as _;
        let expected: syn::Type =
            syn::parse_quote!(&mut crate::oauth::native_management::AppAuthorityStop<'_>);
        method.sig.inputs.len() == 4
            && method.sig.generics.params.is_empty()
            && matches!(method.sig.inputs.last(), Some(syn::FnArg::Typed(argument))
                if argument.ty.to_token_stream().to_string() == expected.to_token_stream().to_string())
    }
    assert!(
        closed_app_admin(&app_operation),
        "fixed operation borrows the actual cohort, never a callback"
    );
    for substituted in [
        syn::parse_quote!(cohort: &mut dyn FnMut() -> anyhow::Result<()>),
        syn::parse_quote!(cohort: bool),
        syn::parse_quote!(cohort: &mut crate::oauth::native_management::AppAuthorityStop<'static>),
    ] {
        let mut mutant = app_operation.clone();
        mutant.sig.inputs.pop();
        mutant.sig.inputs.push(substituted);
        assert!(!closed_app_admin(&mutant));
    }
}

#[test]
fn controller_refresh_checks_the_old_lineage_before_its_replacement() {
    use quote::ToTokens;
    use syn::visit::Visit;
    struct Lineage(Vec<syn::ExprMethodCall>);
    impl<'ast> Visit<'ast> for Lineage {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.receiver.to_token_stream().to_string() == "self . lineage"
                && (call.method == "check" || call.method == "read")
            {
                self.0.push(call.clone());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let source = include_str!("../admin_read.rs");
    let actual = method(source, "ControllerAdminReadLoan", "refresh");
    let mut selected = Lineage(Vec::new());
    selected.visit_block(&actual.block);
    let shapes = |selected: &Lineage| {
        selected
            .0
            .iter()
            .map(|call| {
                (
                    call.method.to_string(),
                    call.args
                        .iter()
                        .map(|arg| arg.to_token_stream().to_string())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = vec![
        (
            "check".to_owned(),
            vec![
                "& self . selection",
                "& mut self . reads",
                "physical . controller_stage () ?",
                "& mut self . observed",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ),
        (
            "read".to_owned(),
            vec![
                "& self . selection",
                "& mut self . reads",
                "physical . controller_stage () ?",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ),
        (
            "check".to_owned(),
            vec![
                "& self . selection",
                "& mut self . reads",
                "physical . controller_stage () ?",
                "& mut observed",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ),
    ];
    assert_eq!(shapes(&selected), expected);
    let flow = calls(source, "ControllerAdminReadLoan", "refresh");
    assert!(before(&flow, "require_closed", "check"));
    let body = actual.block.to_token_stream().to_string();
    let first = selected.0[0].to_token_stream().to_string();
    assert_eq!(body.matches(&first).count(), 1);
    let changed =
        syn::parse_str::<syn::Block>(&body.replacen(&first, "Ok::<(),anyhow::Error>(())", 1))
            .unwrap();
    let mut removed = Lineage(Vec::new());
    removed.visit_block(&changed);
    assert_ne!(shapes(&removed), expected);
}

#[test]
fn final_admin_read_passes_the_same_old_observation_into_the_closed_wait_read() {
    use quote::ToTokens;
    use syn::visit::Visit;
    struct Consumed(Vec<syn::ExprMethodCall>);
    impl<'ast> Visit<'ast> for Consumed {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "announce_and_read_app_consumed" {
                self.0.push(call.clone());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let actual = method(
        include_str!("../admin_read.rs"),
        "ControllerAdminReadLoan",
        "finish_checked",
    );
    let mut consumed = Consumed(Vec::new());
    consumed.visit_block(&actual.block);
    let [call] = consumed.0.as_slice() else {
        panic!("one actual fixed consumed-read call");
    };
    let expected = [
        "& mut self . reads",
        "& self . selection",
        "self . lineage",
        "& mut self . observed",
        "self . trace",
    ];
    assert_eq!(call.receiver.to_token_stream().to_string(), "physical");
    assert_eq!(
        call.args
            .iter()
            .map(|arg| arg.to_token_stream().to_string())
            .collect::<Vec<_>>(),
        expected
    );
    let mut different = call.clone();
    different.args[3] = syn::parse_quote!(&mut other_observed);
    assert_ne!(
        different
            .args
            .iter()
            .map(|arg| arg.to_token_stream().to_string())
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn first_restore_snapshot_selector_is_a_fixed_negative_loan_facade() {
    use quote::ToTokens;
    fn closed(source: &str) -> bool {
        let actual = method(
            source,
            "ControllerAdminReadLoan",
            "initial_restore_snapshot_data",
        );
        let body = actual.block.to_token_stream().to_string();
        actual.sig.inputs.len() == 1
            && matches!(actual.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
                if receiver.reference.is_some() && receiver.mutability.is_some())
            && calls(
                source,
                "ControllerAdminReadLoan",
                "initial_restore_snapshot_data",
            ) == ["initial_restore_snapshot_data", "is_err", "refuse"]
            && body.contains("self . lineage . initial_restore_snapshot_data (& self . observed)")
            && body.matches("self . refuse ()").count() == 1
    }
    let source = include_str!("../admin_read.rs");
    assert!(closed(source));
    let actual = method(
        source,
        "ControllerAdminReadLoan",
        "initial_restore_snapshot_data",
    );
    let method = actual.to_token_stream().to_string();
    let wrapped = format!("impl ControllerAdminReadLoan {{ {method} }}");
    assert!(closed(&wrapped));
    assert!(!closed(&wrapped.replacen(
        "self . refuse ()",
        "unrelated . refuse ()",
        1
    )));
}
