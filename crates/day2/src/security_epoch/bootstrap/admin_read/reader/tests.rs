use super::*;
use syn::visit::Visit;

fn data(revision: u64, members: &[&str]) -> ControllerAdminData {
    ControllerAdminData {
        authority: crate::authority_state::AuthorityStamp {
            epoch: "epoch".into(),
            revision,
        },
        members: members.iter().map(|actor| (*actor).to_owned()).collect(),
    }
}

#[test]
fn exact_policy_selection_checks_both_principals_and_never_adopts_a_new_stamp() -> Result<()> {
    let actors = ["approver@example.test", "executor@example.test"];
    let current = data(7, &actors);
    let operation = Digest::new(b"exact accepting action");
    let selected = AdminSelection::capture(&current, &operation, actors[0], actors[1])?;
    selected.check(&current)?;
    // The same admin may approve and execute. There is no two-person rule.
    AdminSelection::capture(&current, &operation, actors[0], actors[0])?;
    for changed in [
        data(8, &actors),
        data(7, &actors[..1]),
        data(7, &actors[1..]),
        data(0, &actors),
    ] {
        assert!(selected.check(&changed).is_err());
    }
    let mut changed = data(7, &actors);
    changed.authority.epoch = "another epoch".into();
    assert!(selected.check(&changed).is_err());
    assert!(
        AdminSelection::capture(&current, &operation, "domain:private-identity", actors[1])
            .is_err()
    );
    Ok(())
}

fn calls(source: &str, owner: &str, name: &str) -> Vec<String> {
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
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
    let file = syn::parse_file(source).unwrap();
    let method = file.items.iter().filter_map(|item| match item { syn::Item::Impl(value) => Some(value), _ => None })
        .filter(|value| matches!(value.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().unwrap().ident == owner))
        .flat_map(|value| &value.items).find_map(|item| match item { syn::ImplItem::Fn(value) if value.sig.ident == name => Some(value), _ => None }).unwrap();
    let mut visitor = Calls(Vec::new());
    visitor.visit_block(&method.block);
    visitor.0
}
fn before(calls: &[String], first: &str, last: &str) -> bool {
    matches!((calls.iter().position(|x| x == first), calls.iter().position(|x| x == last)), (Some(a), Some(b)) if a < b)
}
fn wired(reader: &str, resource: &str, loan: &str) -> bool {
    let accept = calls(reader, "ControllerAdminReader", "capture");
    let open = calls(resource, "ControllerAdminSqlite", "open");
    let read = calls(resource, "ControllerAdminSqlite", "read");
    let finish = calls(reader, "ControllerAdminReader", "finish_checked");
    let forward_close = calls(resource, "ControllerAdminSqlite", "close");
    let close = calls(loan, "ControllerAdminReadLoan", "close_reader");
    let final_peer = calls(loan, "ControllerAdminReadLoan", "finish_checked");
    before(&accept, "check_action", "open")
        && before(&open, "retain_reader", "configure_connection")
        && before(&read, "begin_retained_sql", "transaction")
        && before(&read, "check_database", "project")
        && before(&read, "commit", "end_retained_sql")
        && read.iter().rposition(|x| x == "check_metadata")
            > read.iter().position(|x| x == "end_retained_sql")
        && before(&finish, "check", "close")
        && before(&finish, "close", "finish_checked")
        && before(&forward_close, "take", "close_reader")
        && forward_close
            .iter()
            .filter(|call| *call == "close_reader")
            .count()
            == 1
        && before(&close, "close", "close_reader")
        && before(
            &final_peer,
            "require_released",
            "announce_and_read_app_consumed",
        )
}

#[test]
fn production_reader_never_releases_peer_from_autocommit_or_unclosed_sql() {
    let reader = include_str!("../reader.rs");
    let resource = include_str!("../../../../store/native_storage/controller_admins/reader.rs");
    let loan = include_str!("../../admin_read.rs");
    assert!(wired(reader, resource, loan));
    for (old, new) in [
        ("loan.check_action(metadata, operation)?;", ""),
        (
            "let closed = self.sqlite.close(&mut self.loan);",
            "let closed = Ok(());",
        ),
    ] {
        let changed = reader.replace(old, new);
        assert_ne!(reader, changed, "actual owner target {old}");
        assert!(!wired(&changed, resource, loan), "must reject {old}");
    }
    for (old, new) in [
        ("loan.retain_reader(&connection)?;", ""),
        ("loan.begin_retained_sql(", "loan.end_retained_sql("),
        ("loan.check_database(&tx)?;", ""),
        (
            "loan.end_retained_sql(db, &completed)",
            "loan.end_sql(&completed)",
        ),
        ("loan.close_reader(connection)", "loan.end_sql(&Ok(()))"),
    ] {
        let changed = resource.replace(old, new);
        assert_ne!(resource, changed, "actual SQL target {old}");
        assert!(!wired(reader, &changed, loan), "must reject {old}");
    }
    let changed = loan.replace(
        "self.disposition.require_released()",
        "self.disposition.require_closed()",
    );
    assert_ne!(loan, changed);
    assert!(!wired(reader, resource, &changed));
}

#[test]
fn abandoning_reader_drops_actual_sqlite_before_the_native_loan() {
    let file = syn::parse_file(include_str!("../reader.rs")).unwrap();
    let fields = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "ControllerAdminReader" => Some(&item.fields),
            _ => None,
        })
        .unwrap();
    let names: Vec<_> = fields
        .iter()
        .map(|field| field.ident.as_ref().unwrap().to_string())
        .collect();
    assert_eq!(names, ["sqlite", "loan", "metadata", "selected"]);
    assert!(
        fields
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited))
    );
    let mut wrong = names.clone();
    wrong.swap(0, 1);
    assert_ne!(wrong, ["sqlite", "loan", "metadata", "selected"]);
}
