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
                1 => actual.begin_sql().is_ok(),
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
    state.begin_sql().unwrap();
    assert!(state.require_closed().is_err());
    state.end_retained_sql(true).unwrap();
    state.require_closed().unwrap();
    assert!(state.require_released().is_err());
    state.close_reader().unwrap();
    state.finish().unwrap();

    let mut state = ReadDisposition::new();
    state.retain_reader().unwrap();
    state.begin_sql().unwrap();
    assert!(state.end_sql(true).is_err());
    assert!(state.end_retained_sql(true).is_err());
    assert!(state.close_reader().is_err());
    assert!(state.finish().is_err());

    let mut state = ReadDisposition::new();
    state.retain_reader().unwrap();
    state.begin_sql().unwrap();
    assert!(state.end_retained_sql(false).is_err());
    assert!(state.end_retained_sql(true).is_err());
    assert!(state.close_reader().is_err());
    assert!(state.finish().is_err());
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
    assert_eq!(
        app_operation.sig.inputs.len(),
        3,
        "fixed operation has no consumer callback"
    );
}
