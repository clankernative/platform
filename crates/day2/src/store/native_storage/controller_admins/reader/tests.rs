use super::*;
use std::collections::BTreeSet;
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

fn fixture() -> Result<(
    tempfile::TempDir,
    std::path::PathBuf,
    Connection,
    ReaderConnection,
)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().canonicalize()?.join("reader.sqlite");
    let keeper = Connection::open(&path)?;
    keeper.pragma_update(None, "journal_mode", "WAL")?;
    keeper.execute_batch("CREATE TABLE current_admin(actor TEXT PRIMARY KEY); INSERT INTO current_admin VALUES('approver@example.test'),('executor@example.test')")?;
    let mut connection = Box::new(open_readonly(&path)?);
    configure_connection(&mut connection)?;
    connection.pragma_update(None, "query_only", true)?;
    let tx = connection.transaction()?;
    let files = opened_files::snapshot(&tx)?;
    tx.commit()?;
    Ok((
        directory,
        path,
        keeper,
        ReaderConnection {
            connection: Some(connection),
            files: Some(files),
        },
    ))
}

#[test]
fn actual_connection_retains_all_auxiliary_handles_between_closed_units() -> Result<()> {
    let (_directory, _path, keeper, mut reader) = fixture()?;
    for _ in 0..4 {
        reader.check_handles()?;
        let tx = reader.connection.as_mut().unwrap().transaction()?;
        let actual: BTreeSet<String> = tx
            .prepare("SELECT actor FROM current_admin")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        assert_eq!(
            actual,
            BTreeSet::from([
                "approver@example.test".into(),
                "executor@example.test".into()
            ])
        );
        assert!(tx.execute("DELETE FROM current_admin", []).is_err());
        tx.commit()?;
        reader.check_handles()?;
        assert!(reader.connection.as_ref().unwrap().is_autocommit());
    }
    // A new real transaction sees a later writer; no old read snapshot is held
    // over external work. This fixture does NOT model native writer exclusion.
    keeper.execute(
        "DELETE FROM current_admin WHERE actor=?1",
        ["approver@example.test"],
    )?;
    let tx = reader.connection.as_mut().unwrap().transaction()?;
    assert_eq!(
        tx.query_row("SELECT count(*) FROM current_admin", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    tx.rollback()?;
    reader.check_handles()?;
    Ok(())
}

#[test]
fn same_cohort_second_connection_is_not_the_retained_reader() -> Result<()> {
    let (_directory, path, _keeper, mut reader) = fixture()?;
    let mut substituted = Box::new(open_readonly(&path)?);
    let tx = substituted.transaction()?;
    let files = opened_files::snapshot(&tx)?;
    assert!(opened_files::cohort(&files)? == opened_files::cohort(reader.files.as_ref().unwrap())?);
    tx.rollback()?;
    // Keep the original open: foreign descriptor numbers cannot accidentally
    // be reused by this negative control's new connection.
    let _original = reader.connection.replace(substituted).unwrap();
    assert!(reader.check_handles().is_err());
    Ok(())
}

#[test]
fn open_transaction_and_replaced_auxiliary_handles_refuse() -> Result<()> {
    let (_directory, path, _keeper, reader) = fixture()?;
    let db = reader.connection.as_ref().unwrap();
    db.execute_batch("BEGIN")?;
    assert!(reader.check_handles().is_err());
    db.execute_batch("ROLLBACK")?;
    reader.check_handles()?;
    let mut files = opened_files::held(db)?;
    files.journal.as_mut().unwrap().inode ^= 1;
    let changed = ReaderConnection {
        connection: reader.connection,
        files: Some(files),
    };
    assert!(changed.check_handles().is_err());
    assert!(path.exists());
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
fn wired(reader: &str, loan: &str) -> bool {
    let accept = calls(reader, "InitialStoreMetadata", "accept_admin_reader");
    let open = calls(reader, "ReaderConnection", "open");
    let read = calls(reader, "ReaderConnection", "read");
    let finish = calls(reader, "ControllerAdminReader", "finish_checked");
    let close = calls(loan, "ControllerAdminReadLoan", "close_reader");
    let final_peer = calls(loan, "ControllerAdminReadLoan", "finish_checked");
    before(&accept, "check_action", "open")
        && before(&open, "retain_reader", "configure_connection")
        && before(&read, "begin_sql", "transaction")
        && before(&read, "check_database", "project")
        && before(&read, "commit", "end_retained_sql")
        && read.iter().rposition(|x| x == "check_metadata")
            > read.iter().position(|x| x == "end_retained_sql")
        && before(&finish, "check", "close")
        && before(&finish, "close", "finish_checked")
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
    let loan = include_str!("../../../../security_epoch/bootstrap/admin_read.rs");
    assert!(wired(reader, loan));
    for (old, new) in [
        ("loan.check_action(self, operation)?;", ""),
        ("loan.retain_reader(&connection)?;", ""),
        ("loan.begin_sql()?;", ""),
        ("loan.check_database(&tx)?;", ""),
        (
            "loan.end_retained_sql(db, &completed)",
            "loan.end_sql(&completed)",
        ),
        (
            "let closed = self.sqlite.close(&mut self.loan);",
            "let closed = Ok(());",
        ),
    ] {
        let changed = reader.replace(old, new);
        assert_ne!(reader, changed, "actual source target {old}");
        assert!(!wired(&changed, loan), "must reject {old}");
    }
    let changed = loan.replace(
        "self.disposition.require_released()",
        "self.disposition.require_closed()",
    );
    assert_ne!(loan, changed);
    assert!(!wired(reader, &changed));
}
