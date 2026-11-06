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
    let selected = AdminSelection::capture(&current, &operation, actors[0], actors[1])?.unwrap();
    selected.check(&current)?;
    // The same admin may approve and execute. There is no two-person rule.
    assert!(AdminSelection::capture(&current, &operation, actors[0], actors[0])?.is_some());
    for nonmember in [data(7, &actors[..1]), data(7, &actors[1..]), data(7, &[])] {
        assert!(AdminSelection::capture(&nonmember, &operation, actors[0], actors[1])?.is_none());
    }
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

#[test]
fn actual_durable_authority_changes_cannot_rebind_the_captured_selection() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut db = rusqlite::Connection::open(directory.path().join("authority.sqlite"))?;
    crate::authority_state::upgrade(&db)?;
    let document = crate::authority_state::AuthorityDocument {
        security: None,
        enabled: true,
        hosted_domain: None,
        readers: Default::default(),
        writers: Default::default(),
        policy: Some(crate::authority::Policy {
            version: 1,
            admins: [
                "approver@example.test".to_owned(),
                "executor@example.test".to_owned(),
            ]
            .into(),
            operations: Default::default(),
            constraints: Default::default(),
            delegations: Default::default(),
        }),
        resources: Default::default(),
        credentials: Default::default(),
    };
    db.execute(
        "INSERT INTO day2_authority VALUES(1,?1,1,?2,'fixture-artifact','fixture-path')",
        rusqlite::params![
            Digest::new(b"durable authority epoch").as_str(),
            serde_json::to_string(&document)?
        ],
    )?;
    let read = |db: &rusqlite::Connection| -> Result<ControllerAdminData> {
        let active = crate::authority_state::current(db)?;
        Ok(ControllerAdminData {
            members: active.policy()?.admins.clone(),
            authority: active.stamp,
        })
    };
    let selected = AdminSelection::capture(
        &read(&db)?,
        &Digest::new(b"action"),
        "approver@example.test",
        "executor@example.test",
    )?
    .unwrap();
    let tx = db.transaction()?;
    tx.execute("UPDATE day2_authority SET revision=2", [])?;
    tx.commit()?;
    // A known later revision still refuses even with identical current admins.
    assert!(selected.check(&read(&db)?).is_err());
    let mut removed = document;
    removed
        .policy
        .as_mut()
        .unwrap()
        .admins
        .remove("executor@example.test");
    db.execute(
        "UPDATE day2_authority SET revision=3,document=?1",
        [serde_json::to_string(&removed)?],
    )?;
    assert!(selected.check(&read(&db)?).is_err());
    drop(db);
    let reopened = rusqlite::Connection::open(directory.path().join("authority.sqlite"))?;
    assert!(selected.check(&read(&reopened)?).is_err());
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
        // Change the first actual constructor statement, not the substring
        // inside a later self.loan call (which would leave invalid `self.`).
        let changed = reader.replacen(old, new, 1);
        assert_ne!(reader, changed, "actual owner target {old}");
        syn::parse_file(&changed).expect("valid owner counterexample");
        assert!(!wired(&changed, resource, loan), "must reject {old}");
    }
    for (old, new) in [
        ("loan.retain_reader(&connection)?;", ""),
        (
            "loan.begin_retained_sql(\n            self.connection\n                .as_ref()\n                .context(\"controller_admin_reader_closed\")?,\n        )?;",
            "loan.begin_sql()?;",
        ),
        ("loan.check_database(&tx)?;", ""),
        (
            "loan.end_retained_sql(db, &completed)",
            "loan.end_sql(&completed)",
        ),
        ("loan.close_reader(connection)", "loan.end_sql(&Ok(()))"),
    ] {
        let changed = resource.replacen(old, new, 1);
        assert_ne!(resource, changed, "actual SQL target {old}");
        syn::parse_file(&changed).expect("valid SQL counterexample");
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

fn denied_settles(source: &str) -> bool {
    use quote::ToTokens;
    struct Denial(Option<syn::Expr>);
    impl<'ast> Visit<'ast> for Denial {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if matches!(&node.pat, syn::Pat::TupleStruct(pattern) if pattern.path.is_ident("Some"))
            {
                self.0 = node
                    .init
                    .as_ref()
                    .and_then(|init| init.diverge.as_ref())
                    .map(|(_, expr)| *expr.clone());
            }
            syn::visit::visit_local(self, node);
        }
    }
    let file = syn::parse_file(source).unwrap();
    let mut denial = Denial(None);
    denial.visit_file(&file);
    let Some(syn::Expr::Block(body)) = denial.0 else {
        return false;
    };
    let wrapper = format!(
        "impl Guard {{ fn denied() {} }}",
        body.block.to_token_stream()
    );
    let trace = calls(&wrapper, "Guard", "denied");
    let expected: syn::Stmt = syn::parse_quote!(return Ok(None););
    before(&trace, "close", "check_local")
        && before(&trace, "check_local", "finish_checked")
        && body.block.stmts.last().is_some_and(|last| {
            last.to_token_stream().to_string() == expected.to_token_stream().to_string()
        })
}

#[test]
fn known_initial_denial_settles_the_same_reader_before_returning_data() {
    let source = include_str!("../reader.rs");
    assert!(denied_settles(source));
    for (old, new) in [
        (
            "let closed = sqlite.close(&mut loan);",
            "let closed = Ok(());",
        ),
        ("loan.finish_checked()?;", ""),
    ] {
        assert_eq!(source.matches(old).count(), 1);
        assert!(!denied_settles(&source.replace(old, new)));
    }
}

// Actual source interval: the dedicated restore original is captured before
// the existing reader can open/recover/read SQLite, never after its result.
fn execution_reader_interval(source: &str) -> Result<bool> {
    use quote::ToTokens as _;
    use syn::visit::Visit as _;
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*expression.func {
                self.0
                    .push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, expression);
        }
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            self.0.push(expression.method.to_string());
            syn::visit::visit_expr_method_call(self, expression);
        }
    }
    let file = syn::parse_file(source)?;
    let methods: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item.items.iter().filter_map(|method| match method {
                syn::ImplItem::Fn(method)
                    if method.sig.ident == "begin_restore_execution_reader" =>
                {
                    Some(method)
                }
                _ => None,
            })),
            _ => None,
        })
        .flatten()
        .collect();
    if methods.len() != 1
        || methods[0].block.stmts.len() != 6
        || methods[0].block.stmts[0].to_token_stream().to_string()
            != "record . encode () ? ;"
    {
        return Ok(false);
    }
    let mut calls = Calls::default();
    calls.visit_block(&methods[0].block);
    let selected: Vec<_> = calls
        .0
        .iter()
        .filter(|call| {
            matches!(
                call.as_str(),
                "capture" | "begin_accepting_admin_reader" | "check_execution_original"
            )
        })
        .map(String::as_str)
        .collect();
    Ok(selected
        == [
            "capture",
            "begin_accepting_admin_reader",
            "check_execution_original",
        ])
}

#[test]
fn restore_execution_original_precedes_the_actual_accepting_reader() -> Result<()> {
    let source = include_str!("../reader.rs");
    assert!(execution_reader_interval(source)?);
    let changed = source.replacen(
        "RestoreOriginalGuard::capture(",
        "RestoreOriginalGuard::from_data(",
        1,
    );
    assert_ne!(source, changed);
    assert!(!execution_reader_interval(&changed)?);
    let changed = source.replacen(
        "reader.check_execution_original(&mut original, record, operation)?;",
        "",
        1,
    );
    assert_ne!(source, changed);
    assert!(!execution_reader_interval(&changed)?);
    let start = source.find("        let mut original = crate::security_epoch::restore_original::RestoreOriginalGuard::capture(").unwrap();
    let end = source[start..].find("        let intent =").unwrap() + start;
    let capture = &source[start..end];
    let removed = source.replacen(capture, "", 1);
    let marker = "        reader.check_execution_original(&mut original, record, operation)?;";
    let moved = removed.replacen(marker, &format!("{capture}{marker}"), 1);
    syn::parse_file(&moved)?;
    assert!(!execution_reader_interval(&moved)?);
    let waited = source.replacen(
        "        record.encode()?;",
        "        std::thread::yield_now();\n        record.encode()?;",
        1,
    );
    assert_ne!(source, waited);
    syn::parse_file(&waited)?;
    assert!(!execution_reader_interval(&waited)?);
    Ok(())
}
