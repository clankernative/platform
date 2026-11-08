//! Real SQLite/crypto adapters and an independent expected denial cut. These
//! fixtures never construct a native owner, passkey approval or writer.
use super::{Kind, Profile, Snapshot, close_in, install, require_no_history, require_open};
use crate::oauth::{connect, custody, exchange, inbound, outbound, profiles, protocol, store};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, TransactionBehavior, params};
use std::{collections::BTreeSet, path::Path};

mod empty_historical_unit {
    use super::*;

    fn historical() -> Result<Connection> {
        let db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch(super::super::EMPTY_HISTORICAL_UNIT)?;
        db.execute_batch("CREATE TABLE app_rows(value TEXT); INSERT INTO app_rows VALUES('keep')")?;
        Ok(db)
    }

    fn schema(db: &Connection) -> Result<Vec<(String, String, Option<String>)>> {
        Ok(db
            .prepare("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }

    #[test]
    fn exact_empty_restore_unit_is_replaced_without_changing_app_rows() -> Result<()> {
        let db = historical()?;
        install(&db)?;
        assert_eq!(
            db.query_row(
                "SELECT version FROM oauth_restore_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            db.query_row("SELECT value FROM app_rows", [], |row| row
                .get::<_, String>(0))?,
            "keep"
        );
        let current = Connection::open_in_memory()?;
        install(&current)?;
        current.execute_batch("CREATE TABLE app_rows(value TEXT)")?;
        assert_eq!(schema(&db)?, schema(&current)?);
        let before = schema(&db)?;
        install(&db)?;
        assert_eq!(schema(&db)?, before);
        Ok(())
    }

    #[test]
    fn historical_restore_history_is_refused_and_retained() -> Result<()> {
        let db = historical()?;
        let cut = Digest::new(b"historical restore cut DATA");
        let inventory = Digest::new(b"historical restore inventory DATA");
        db.execute(
            "INSERT INTO oauth_restore_cuts(digest,binding,inventory) VALUES(?1,'{}',?2)",
            params![cut.as_str(), inventory.as_str()],
        )?;
        db.execute(
            "INSERT INTO oauth_restore_closed(kind,id,cut) VALUES('fresh','closed-original',?1)",
            [cut.as_str()],
        )?;
        let before = schema(&db)?;
        let error = format!("{:#}", install(&db).unwrap_err());
        assert!(error.contains("holds security history"), "{error}");
        assert_eq!(schema(&db)?, before);
        assert_eq!(
            db.query_row("SELECT digest FROM oauth_restore_cuts", [], |row| row
                .get::<_, String>(0))?,
            cut.as_str()
        );
        assert_eq!(
            db.query_row("SELECT id FROM oauth_restore_closed", [], |row| row
                .get::<_, String>(0))?,
            "closed-original"
        );
        Ok(())
    }

    #[test]
    fn changed_or_incomplete_restore_units_are_refused_without_mutation() -> Result<()> {
        for change in [
            "CREATE TABLE oauth_restore_unknown(value TEXT)",
            "CREATE INDEX oauth_restore_extra ON oauth_restore_cuts(binding)",
            "CREATE TABLE OAUTH_RESTORE_ALIAS(value TEXT)",
            "DROP TABLE oauth_restore_schema_version",
            "DELETE FROM oauth_restore_schema_version",
            "UPDATE oauth_restore_schema_version SET version=2",
            "UPDATE oauth_restore_schema_version SET version=3",
            "DROP TABLE oauth_restore_closed",
            "DROP TRIGGER oauth_restore_cut_no_delete",
            "DROP TRIGGER oauth_restore_cuts_shape_INSERT_v1",
            "DROP TRIGGER oauth_restore_cut_no_delete; CREATE TRIGGER oauth_restore_cut_no_delete BEFORE DELETE ON oauth_restore_cuts BEGIN SELECT 1; END",
            "ALTER TABLE oauth_restore_cuts ADD COLUMN unknown TEXT",
        ] {
            let db = historical()?;
            db.execute_batch(change)?;
            let before = schema(&db)?;
            assert!(install(&db).is_err(), "{change}");
            assert_eq!(schema(&db)?, before, "{change}");
        }
        Ok(())
    }

    #[test]
    fn empty_restore_replacement_rolls_back_with_later_admission_refusal() -> Result<()> {
        let db = historical()?;
        let before = schema(&db)?;
        let result = crate::oauth::schema::admit(&db, |db| -> Result<()> {
            install(db)?;
            anyhow::bail!("later admission refused")
        });
        assert!(result.is_err());
        assert_eq!(schema(&db)?, before);
        assert_eq!(
            db.query_row(
                "SELECT version FROM oauth_restore_schema_version",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        Ok(())
    }

    #[test]
    fn empty_restore_replacement_preserves_the_shared_admission_budget() -> Result<()> {
        let db = historical()?;
        let before = schema(&db)?;
        let result =
            crate::oauth::schema::admit_with_limits(&db, 1_000_000, 1, 8 * 1_048_576, install);
        assert!(format!("{:#}", result.unwrap_err()).contains("budget"));
        assert_eq!(schema(&db)?, before);
        install(&db)?;
        Ok(())
    }
}

#[test]
fn current_use_admits_its_connect_dependency_once_through_the_actual_owner() -> Result<()> {
    use syn::visit::{self, Visit};
    fn call(expression: &syn::Expr, target: &str) -> bool {
        let syn::Expr::Try(tried) = expression else {
            return false;
        };
        let syn::Expr::Call(call) = &*tried.expr else {
            return false;
        };
        let syn::Expr::Path(path) = &*call.func else {
            return false;
        };
        path.path
            .segments
            .iter()
            .map(|p| p.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
            == target
            && call.args.len() == 1
            && matches!(call.args.first(),Some(syn::Expr::Path(p)) if p.path.is_ident("db"))
    }
    fn present(expression: &syn::Expr, name: &str) -> bool {
        let syn::Expr::Call(call) = expression else {
            return false;
        };
        matches!(&*call.func,syn::Expr::Path(p) if p.path.is_ident("present"))
            && call.args.len() == 1
            && matches!(call.args.first(),Some(syn::Expr::Lit(l)) if matches!(&l.lit,syn::Lit::Str(s) if s.value()==name))
    }
    #[derive(Default)]
    struct Calls {
        guards: Vec<u8>,
        connect: usize,
        usage: usize,
        valid: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
            let guard = if present(&node.cond, "oauth_connect_schema_version") {
                1
            } else if matches!(&*node.cond,syn::Expr::Unary(u) if matches!(u.op,syn::UnOp::Not(_)) && present(&u.expr,"oauth_use_schema_version"))
            {
                2
            } else if present(&node.cond, "oauth_use_schema_version") {
                3
            } else {
                0
            };
            self.visit_expr(&node.cond);
            self.guards.push(guard);
            self.visit_block(&node.then_branch);
            self.guards.pop();
            if let Some((_, otherwise)) = &node.else_branch {
                self.visit_expr(otherwise);
            }
        }
        fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
            let expression = syn::Expr::Try(node.clone());
            if call(&expression, "super::connect::install_schema") {
                self.connect += 1;
                self.valid &= self.guards.last() == Some(&2) && self.guards.contains(&1);
            }
            if call(&expression, "super::usage::install") {
                self.usage += 1;
                self.valid &= self.guards.last() == Some(&3);
            }
            visit::visit_expr_try(self, node);
        }
    }
    fn valid(source: &str, usage: &str) -> Result<bool> {
        let syntax = syn::parse_file(source)?;
        let captures: Vec<_> = syntax
            .items
            .iter()
            .filter_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                matches!(&*item.self_ty,syn::Type::Path(p) if p.path.is_ident("Snapshot"))
                    .then_some(item)
            })
            .flat_map(|item| item.items.iter())
            .filter_map(|item| match item {
                syn::ImplItem::Fn(f) if f.sig.ident == "capture" => Some(&f.block),
                _ => None,
            })
            .collect();
        ensure!(captures.len() == 1, "test_snapshot_capture_target");
        let mut calls = Calls {
            valid: true,
            ..Default::default()
        };
        calls.visit_block(captures[0]);
        let syntax = syn::parse_file(usage)?;
        let installs: Vec<_> = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(f) if f.sig.ident == "install" => Some(&f.block),
                _ => None,
            })
            .collect();
        ensure!(installs.len() == 1, "test_use_install_target");
        let first = matches!(installs[0].stmts.first(),Some(syn::Stmt::Expr(e,_)) if call(e,"super::connect::install_schema"));
        let mut dependency = Calls {
            valid: true,
            ..Default::default()
        };
        dependency.visit_block(installs[0]);
        Ok(calls.valid
            && calls.connect == 1
            && calls.usage == 1
            && first
            && dependency.connect == 1)
    }
    let source = include_str!("restore.rs");
    let usage = include_str!("usage.rs");
    assert!(valid(source, usage)?);
    let direct = "super::connect::install_schema(db)?;";
    let use_call = "super::usage::install(db)?;";
    let condition = "if !present(\"oauth_use_schema_version\")";
    assert_eq!(source.matches(direct).count(), 1);
    assert_eq!(source.matches(use_call).count(), 1);
    assert_eq!(source.matches(condition).count(), 1);
    assert!(!valid(&source.replace(condition, "if true"), usage)?);
    assert!(!valid(&source.replace(direct, "();"), usage)?);
    assert!(!valid(
        &source.replace(direct, &format!("{direct}{direct}")),
        usage
    )?);
    assert!(!valid(&source.replace(use_call, "();"), usage)?);
    assert_eq!(usage.matches(direct).count(), 1);
    assert!(!valid(source, &usage.replace(direct, "();"))?);
    assert!(!valid(
        source,
        &usage.replace(direct, &format!("let _ = ();{direct}"))
    )?);
    Ok(())
}

#[test]
fn current_connect_and_use_corruption_keep_first_refusal_and_the_absent_use_route() -> Result<()> {
    fn rows(db: &Connection, sql: &str) -> Result<Vec<Vec<rusqlite::types::Value>>> {
        Ok(db
            .prepare(sql)?
            .query_map([], |r| {
                (0..r.as_ref().column_count())
                    .map(|i| r.get(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
    fn corrupt(db: &Connection, sql: &str) -> Result<()> {
        let guards = db
            .prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger'")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        db.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA ignore_check_constraints=ON")?;
        for (name, _) in &guards {
            db.execute_batch(&format!("DROP TRIGGER {name}"))?;
        }
        db.execute_batch(sql)?;
        for (_, ddl) in guards {
            db.execute_batch(&ddl)?;
        }
        db.execute_batch("PRAGMA ignore_check_constraints=OFF; PRAGMA foreign_keys=ON")?;
        Ok(())
    }
    for (with_use, bad_connect, bad_use) in [
        (false, false, false),
        (false, true, false),
        (true, true, true),
        (true, false, true),
    ] {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch(crate::store::PLATFORM_DDL)?;
        db.execute(
            "INSERT INTO day2_meta VALUES('scope','company/canary/calendar')",
            [],
        )?;
        db.execute(
            "INSERT INTO day2_meta VALUES('schema',?1)",
            [Digest::new(b"schema").as_str()],
        )?;
        if with_use {
            crate::oauth::usage::install(&db)?;
        } else {
            connect::install_schema(&db)?;
        }
        db.execute("INSERT INTO oauth_connection_slots VALUES('slot',1,1,1,'profile','account','affinity','active')",[])?;
        if bad_use {
            db.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES('old','query','alice@example.com','{}',?1,1,'pending')",[Digest::new(b"artifact").as_str()])?;
            db.execute(
                "INSERT INTO oauth_use_handles VALUES(?1,'old','{}')",
                ["x".repeat(43)],
            )?;
        }
        if bad_connect {
            corrupt(&db, "UPDATE oauth_connection_slots SET generation=0")?;
        }
        if bad_use {
            corrupt(&db, "UPDATE oauth_use_handles SET claims='null'")?;
        }
        let before = rows(&db, "SELECT * FROM oauth_connection_slots ORDER BY slot")?;
        let profile = Profile::prepare()?;
        let tx = db.transaction()?;
        let result = Snapshot::capture(&tx, &profile);
        if bad_connect || bad_use {
            let error = result
                .err()
                .ok_or_else(|| anyhow::anyhow!("test_expected_corruption_refusal"))?;
            let table = if bad_connect {
                "oauth_connection_slots"
            } else {
                "oauth_use_handles"
            };
            assert!(
                error.chain().any(|e| e.to_string().contains(table)),
                "wrong canonical dependency refusal"
            );
        } else {
            result?;
        }
        tx.rollback()?;
        assert!(before == rows(&db, "SELECT * FROM oauth_connection_slots ORDER BY slot")?);
        let present:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='oauth_use_handles')",[],|row|row.get(0))?;
        assert_eq!(present, with_use);
    }
    Ok(())
}

pub(in crate::oauth) fn database(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.pragma_update(None, "foreign_keys", true)?;
    db.execute_batch(crate::store::PLATFORM_DDL)?;
    db.execute(
        "INSERT INTO day2_meta VALUES('scope','company/canary/calendar')",
        [],
    )?;
    db.execute(
        "INSERT INTO day2_meta VALUES('schema',?1)",
        [Digest::new(b"schema").as_str()],
    )?;
    crate::oauth::usage::install(&db)?;
    inbound::install_schema(&db)?;
    Ok(db)
}

fn intent(id: &str) -> connect::ConnectIntent {
    connect::ConnectIntent {
        attempt: id.into(),
        slot: format!("slot_{id}"),
        expected_generation: None,
        expected_epoch: 1,
        proposed_generation: 1,
        generation_floor: 0,
        owner: "human_1".into(),
        profile: "google_calendar_v1".into(),
        registration: "registration_1".into(),
        callback: "callback_1".into(),
        consent: "consent_1".into(),
        expires_at: 100,
    }
}

fn seed(db: &mut Connection) -> Result<()> {
    assert!(connect::begin(db, &intent("pending"), 1)?);
    assert!(connect::begin(db, &intent("sent"), 1)?);
    assert!(connect::claim_callback(
        db,
        "sent",
        "retained_code",
        2,
        |_| Ok(())
    )?);
    let _may = connect::authorize_and_commit_exchange(db, "sent", 3)?.unwrap();
    for (index, state) in [
        "ready",
        "may_have_been_sent",
        "uncertain",
        "replacement_committed",
    ]
    .into_iter()
    .enumerate()
    {
        let slot = format!("refresh_slot_{index}");
        db.execute("INSERT INTO oauth_connection_slots VALUES(?1,1,1,1,'profile','account','affinity','active')",[&slot])?;
        db.execute("INSERT INTO oauth_refresh_attempts VALUES(?1,?2,1,1,1,'profile','account','affinity',?3,?4,?5)",
            params![format!("refresh_{index}"),slot,state,if index==3 {Some(2)} else {None},if index==3 {Some("known_receipt")} else {None}])?;
    }
    inbound::record_grant(db, "old_grant", &inbound::tests::ceiling(), 1)?;
    Ok(())
}

fn cut(db: &mut Connection, profile: &Profile, seed: u64) -> Result<usize> {
    let mut tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before = Snapshot::capture(&tx, profile)?;
    let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), seed)?;
    let count = close_in(&mut tx, before, &cut, profile)?;
    tx.commit()?;
    Ok(count)
}

pub(in crate::oauth) fn apply_for_storage(db: &mut Connection, seed: u64) -> Result<usize> {
    let scope: String = db.query_row(
        "SELECT value FROM main.day2_meta WHERE key='scope'",
        [],
        |r| r.get(0),
    )?;
    let schema: String = db.query_row(
        "SELECT value FROM main.day2_meta WHERE key='schema'",
        [],
        |r| r.get(0),
    )?;
    let profile = Profile::prepare()?;
    let mut tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before = Snapshot::capture(&tx, &profile)?;
    let cut = crate::security_epoch::restore_cut::fixture_for_storage(
        before.digest().clone(),
        seed,
        &scope,
        schema.try_into()?,
    )?;
    let count = close_in(&mut tx, before, &cut, &profile)?;
    tx.commit()?;
    Ok(count)
}

type ConnectHistory = Vec<(String, String, Option<String>)>;
type RefreshHistory = Vec<(String, String, Option<i64>, Option<String>)>;

fn histories(db: &Connection) -> Result<(ConnectHistory, RefreshHistory)> {
    let mut q = db.prepare(
        "SELECT attempt,state,code_ref FROM main.oauth_connect_attempts ORDER BY attempt",
    )?;
    let connects = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut q=db.prepare("SELECT attempt,state,next_version,receipt FROM main.oauth_refresh_attempts ORDER BY attempt")?;
    let refresh = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok((connects, refresh))
}

#[test]
fn restored_generation_floors_preserve_pending_history_and_refuse_raw_adoption() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("generation-floors.sqlite");
    let mut db = database(&path)?;
    seed(&mut db)?;
    assert_eq!(super::generation_floor(&db, "refresh_slot_0")?, None);
    let mut higher = intent("higher_pending");
    higher.slot = "refresh_slot_0".into();
    higher.expected_generation = Some(1);
    higher.proposed_generation = 2;
    assert!(connect::begin(&mut db, &higher, 1)?);
    let history = histories(&db)?;
    assert_eq!(cut(&mut db, &Profile::prepare()?, 93)?, 8);
    drop(db);
    for _ in 0..2 {
        let mut db = Connection::open(&path)?;
        db.pragma_update(None, "foreign_keys", true)?;
        assert_eq!(histories(&db)?, history);
        for (slot, expected) in [
            ("refresh_slot_0", 2),
            ("refresh_slot_1", 1),
            ("slot_pending", 1),
            ("slot_sent", 1),
        ] {
            assert_eq!(super::generation_floor(&db, slot)?, Some(expected));
        }
        assert_eq!(super::generation_floor(&db, "unused_slot")?, None);
        // Historical rows retain their captured floor; current schema admission
        // must not reinterpret them against the newly published floor.
        connect::install_schema(&db)?;
        assert_eq!(db.query_row("SELECT generation_floor,proposed_generation FROM oauth_connect_attempts WHERE attempt='higher_pending'",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?)))?,(0,2));
        let mut copied = higher.clone();
        copied.attempt = "raw_new_id".into();
        copied.expected_epoch = 2;
        copied.generation_floor = 2;
        copied.proposed_generation = 3;
        assert!(!connect::begin(&mut db, &copied, 4)?);
        assert!(connect::state(&db, &copied.attempt)?.is_none());
        for statement in [
            "UPDATE oauth_restore_slot_floors SET generation=3 WHERE slot='refresh_slot_0'",
            "DELETE FROM oauth_restore_slot_floors WHERE slot='refresh_slot_0'",
            "INSERT OR REPLACE INTO oauth_restore_slot_floors SELECT slot,3,cut FROM oauth_restore_slot_floors WHERE slot='refresh_slot_0'",
            "INSERT OR REPLACE INTO oauth_restore_cuts SELECT digest,binding,inventory FROM oauth_restore_cuts",
            "INSERT OR REPLACE INTO oauth_restore_closed SELECT kind,id,cut FROM oauth_restore_closed WHERE kind='connect' AND id='higher_pending'",
        ] {
            assert!(db.execute(statement, []).is_err(), "{statement}");
        }
        assert_eq!(super::generation_floor(&db, "refresh_slot_0")?, Some(2));
        assert!(require_open(&db, Kind::Connect, "higher_pending").is_err());
        assert_eq!(histories(&db)?, history);
    }
    assert_eq!(super::next_generation(Some(1), 2)?, 3);
    assert_eq!(super::next_generation(None, 9)?, 10);
    for (current, floor) in [
        (Some(0), 0),
        (Some(-1), 0),
        (None, -1),
        (None, i64::MAX),
        (Some(i64::MAX), 0),
        (None, i64::MAX - 1),
    ] {
        assert!(super::next_generation(current, floor).is_err());
    }
    Ok(())
}

#[test]
fn each_imported_generation_source_contributes_its_own_conservative_floor() -> Result<()> {
    // Imported bounded DATA may be undecipherable or inconsistent with a live
    // slot. It is not a valid provider credential, grant or publication proof.
    // It must still reserve its generation so fresh authorization cannot adopt
    // it or collide with old material. Expected values are independent literals.
    for (source, slot, expected) in [
        ("slot", "refresh_slot_0", 9),
        ("refresh", "refresh_slot_0", 10),
        ("pending", "slot_pending", 11),
        ("token", "opaque_token_slot", 12),
        ("quarantine", "opaque_quarantine_slot", 13),
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("source.sqlite");
        let mut db = database(&path)?;
        seed(&mut db)?;
        match source {
            "slot" => {
                db.execute(
                    "UPDATE oauth_connection_slots SET generation=9 WHERE slot='refresh_slot_0'",
                    [],
                )?;
            }
            "refresh" => {
                db.execute(
                    "UPDATE oauth_refresh_attempts SET generation=10 WHERE attempt='refresh_0'",
                    [],
                )?;
            }
            "pending" => {
                db.execute("UPDATE oauth_connect_attempts SET expected_generation=10,proposed_generation=11 WHERE attempt='pending'",[])?;
            }
            "token" => {
                db.execute("INSERT INTO oauth_private_tokens VALUES('opaque_reference','opaque_token_slot',12,'account','opaque_digest','version',zeroblob(12),zeroblob(16))",[])?;
            }
            "quarantine" => {
                db.execute("INSERT INTO oauth_external_quarantine VALUES('pending','opaque_quarantine_slot',13,'account','scope','challenge',1,'reference','token_digest','version',zeroblob(12),zeroblob(16),'identity_digest','version',zeroblob(12),zeroblob(16))",[])?;
            }
            _ => unreachable!(),
        }
        cut(&mut db, &Profile::prepare()?, 98)?;
        drop(db);
        for _ in 0..2 {
            let db = Connection::open(&path)?;
            assert_eq!(
                super::generation_floor(&db, slot)?,
                Some(expected),
                "{source}"
            );
            assert_eq!(super::next_generation(None, expected)?, expected + 1);
            if source == "token" {
                assert_eq!(db.query_row("SELECT generation,hex(ciphertext) FROM oauth_private_tokens WHERE reference='opaque_reference'",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?)))?,(12,"00".repeat(16)));
            }
            if source == "quarantine" {
                assert_eq!(db.query_row("SELECT generation,hex(token_ciphertext) FROM oauth_external_quarantine WHERE attempt='pending'",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?)))?,(13,"00".repeat(16)));
            }
        }
    }
    Ok(())
}

#[test]
fn allocation_floor_requires_the_whole_current_unit_without_repair() -> Result<()> {
    for damaged in [
        "UPDATE oauth_restore_schema_version SET version=1",
        "DROP TABLE oauth_restore_slot_floors",
        "DROP TABLE oauth_restore_closed",
        "DROP TABLE oauth_restore_cuts",
    ] {
        let dir = tempfile::tempdir()?;
        let db = database(&dir.path().join("partial.sqlite"))?;
        db.execute_batch(damaged)?;
        let before:String=db.query_row("SELECT group_concat(name||':'||coalesce(sql,''),'|') FROM (SELECT name,sql FROM sqlite_master ORDER BY name)",[],|r|r.get(0))?;
        assert!(
            super::generation_floor(&db, "unknown_slot").is_err(),
            "{damaged}"
        );
        assert_eq!(db.query_row("SELECT group_concat(name||':'||coalesce(sql,''),'|') FROM (SELECT name,sql FROM sqlite_master ORDER BY name)",[],|r|r.get::<_,String>(0))?,before);
    }
    Ok(())
}

#[test]
fn applied_cut_rejects_another_real_connection_even_with_that_connections_owned_scope() -> Result<()>
{
    let a_dir = tempfile::tempdir()?;
    let b_dir = tempfile::tempdir()?;
    let mut a = database(&a_dir.path().join("a.sqlite"))?;
    let mut b = database(&b_dir.path().join("b.sqlite"))?;
    let profile = Profile::prepare()?;
    let a_tx = a.transaction()?;
    let b_tx = b.transaction()?;
    let before = Snapshot::capture(&a_tx, &profile)?;
    let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), 1234)?;
    // Private helper access is confined to this child test. The production
    // whole-reset entry returns counts and cannot export this transaction loan.
    let applied =
        crate::oauth::schema::admit(&a_tx, |_| super::apply_in(&a_tx, before, &cut, &profile))?;
    assert!(
        applied.require_connection(&a_tx).is_err(),
        "no live admission scope remains"
    );
    crate::oauth::schema::admit(&b_tx, |db| {
        crate::oauth::schema::require_admission(db)?;
        assert!(
            applied.require_connection(&b_tx).is_err(),
            "foreign metadata is not this loan"
        );
        Ok(())
    })?;
    crate::oauth::schema::admit(&a_tx, |_| applied.require_connection(&a_tx))?;
    a_tx.rollback()?;
    b_tx.rollback()?;
    Ok(())
}

#[test]
fn complete_cut_preserves_unknown_and_known_histories_and_reopens_as_denial() -> Result<()> {
    let profile = Profile::prepare()?;
    for seed_number in [3, 17, 81] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("app.sqlite");
        let mut db = database(&path)?;
        seed(&mut db)?;
        if seed_number == 17 {
            assert!(connect::mark_uncertain(&db, "sent")?);
        }
        let history = histories(&db)?;
        assert_eq!(cut(&mut db, &profile, seed_number)?, 7); // 2 connect + 4 refresh + 1 grant.
        drop(db);
        for _ in 0..2 {
            let mut db = Connection::open(&path)?;
            db.pragma_update(None, "foreign_keys", true)?;
            assert_eq!(histories(&db)?, history);
            assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status='reauth_required' AND security_epoch=2 AND generation=1 AND token_version=1",[],|r|r.get::<_,i64>(0))?,4);
            assert_eq!(
                db.query_row(
                    "SELECT status,epoch FROM main.oauth_inbound_grants WHERE id='old_grant'",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                )?,
                ("revoked".into(), 2)
            );
            assert!(store::authorize_and_commit_dispatch(&mut db, "refresh_0").is_err());
            assert!(
                connect::claim_callback(&mut db, "pending", "late_code", 5, |_| panic!(
                    "closed callback entered custody"
                ))
                .is_err()
            );
            assert!(
                connect::await_account_approval(
                    &mut db,
                    "sent",
                    "account",
                    "scope",
                    5,
                    |_| panic!("closed response entered custody")
                )
                .is_err()
            );
            assert!(connect::begin(&mut db, &intent("pending"), 5).is_err());
            assert!(connect::record_denial(&db, "pending", 5).is_err());
            for attempt in ["refresh_1", "refresh_2"] {
                assert!(store::mark_definitive_rejection(&mut db, attempt).is_err());
            }
            for attempt in ["pending", "sent"] {
                assert!(
                    connect::cancel(&mut db, attempt, |_| panic!(
                        "closed cancellation entered custody"
                    ))
                    .is_err()
                );
                assert!(
                    connect::expire(&mut db, attempt, 1000, |_| panic!(
                        "closed expiry entered custody"
                    ))
                    .is_err()
                );
            }
            assert!(require_open(&db, Kind::Inbound, "old_grant").is_err());
            assert!(require_no_history(&db).is_err());
            assert!(
                db.execute("DELETE FROM main.oauth_restore_closed", [])
                    .is_err()
            );
            assert!(
                db.execute("UPDATE main.oauth_restore_cuts SET inventory=inventory", [])
                    .is_err()
            );
            assert_eq!(histories(&db)?, history);
        }
    }
    Ok(())
}

#[test]
fn late_prepared_code_and_tokens_cannot_publish_or_decrypt_after_cut() -> Result<()> {
    crate::oauth::effects::scope(crate::oauth::simulation::World::new(9721), || {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        let fixture = profiles::tests::external_fixture();
        let key = profiles::tests::exchange_key();
        let authorization = exchange::prepare_authorization(
            fixture.input(),
            &key,
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )?;
        let binding = authorization.parts().2.clone();
        assert!(authorization.begin(&mut db, 1)?);
        let code = custody::prepare_code(&key, &fixture.intent, &binding, "fixture_code")?;
        let raw=br#"{"access_token":"fixture_access","token_type":"Bearer","expires_in":300,"scope":"calendar.read"}"#;
        let tokens = fixture
            .reviewed
            .protocol
            .validate_token_response(raw, &fixture.permission)?;
        let held =
            custody::prepare_tokens(&key, &fixture.intent, "account_1", &binding, tokens, 2)?;
        let before: Vec<u8> = db.query_row(
            "SELECT ciphertext FROM main.oauth_private_verifiers",
            [],
            |r| r.get(0),
        )?;
        cut(&mut db, &profile, 19)?;
        let tx = db.transaction()?;
        assert!(custody::publish_code(&tx, code).is_err());
        assert!(custody::publish_tokens(&tx, held).is_err());
        assert!(custody::load_verifier(&tx, &key, &fixture.intent, &binding).is_err());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_private_codes", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_private_tokens", [], |r| {
                r.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(
            tx.query_row(
                "SELECT ciphertext FROM main.oauth_private_verifiers",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )?,
            before
        );
        tx.commit()?;
        Ok(())
    })
}

#[test]
fn actual_code_and_provider_denial_callbacks_cannot_change_cut_closed_rows_or_material()
-> Result<()> {
    fn rows(db: &Connection, sql: &str) -> Result<Vec<Vec<rusqlite::types::Value>>> {
        let mut query = db.prepare(sql)?;
        let result = query
            .query_map([], |row| {
                (0..row.as_ref().column_count())
                    .map(|i| row.get(i))
                    .collect()
            })?
            .collect::<rusqlite::Result<_>>()?;
        Ok(result)
    }
    crate::oauth::effects::scope(crate::oauth::simulation::World::new(9722), || {
        for denied in [false, true] {
            for restored in [false, true] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("callback.sqlite");
                let mut db = database(&path)?;
                let fixture = profiles::tests::external_fixture();
                let key = profiles::tests::exchange_key();
                let authorization = exchange::prepare_authorization(
                    fixture.input(),
                    &key,
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
                )?;
                let code_ref = authorization.code_ref().to_owned();
                assert!(authorization.begin(&mut db, 1)?);
                let raw: &[u8] = if denied {
                    b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&error=access_denied&iss=https%3A%2F%2Fissuer.example%2Ftenant"
                } else {
                    b"state=0123456789abcdefghijklmnopqrstuvwxyzABCDEF&code=fixture_code&iss=https%3A%2F%2Fissuer.example%2Ftenant"
                };
                let ingress = || outbound::CallbackIngress {
                    attempt: &fixture.intent.attempt,
                    raw_query: raw,
                    route: &fixture.instance.registration.callback,
                    session: fixture.binding.session(),
                    issuer_binding: &fixture.reviewed.issuer,
                    code_ref: &code_ref,
                    now: 2,
                };
                if !restored {
                    let outcome = exchange::handle_qualified_callback(
                        &mut db,
                        fixture.input(),
                        ingress(),
                        &key,
                    )?;
                    assert!(if denied {
                        matches!(outcome, outbound::CallbackOutcome::Denied { .. })
                    } else {
                        matches!(outcome, outbound::CallbackOutcome::CodeAccepted { .. })
                    });
                    continue;
                }
                let original = rows(&db, "SELECT * FROM oauth_connect_attempts ORDER BY attempt")?;
                let verifier = rows(
                    &db,
                    "SELECT * FROM oauth_private_verifiers ORDER BY reference",
                )?;
                assert!(!verifier.is_empty());
                cut(&mut db, &Profile::prepare()?, 92)?;
                for _ in 0..2 {
                    drop(db);
                    db = Connection::open(&path)?;
                    assert!(
                        outbound::handle_callback_profile(
                            &mut db,
                            ingress(),
                            &protocol::CallbackParameters {
                                require_issuer: true,
                                allowed_extras: BTreeSet::new()
                            },
                            |_, _| panic!("closed real callback entered custody")
                        )
                        .is_err()
                    );
                    assert_eq!(
                        rows(&db, "SELECT * FROM oauth_connect_attempts ORDER BY attempt")?,
                        original
                    );
                    assert_eq!(
                        rows(
                            &db,
                            "SELECT * FROM oauth_private_verifiers ORDER BY reference"
                        )?,
                        verifier
                    );
                    assert!(
                        rows(&db, "SELECT * FROM oauth_private_codes ORDER BY reference")?
                            .is_empty()
                    );
                }
            }
        }
        Ok(())
    })
}

#[test]
fn old_slot_cannot_be_adopted_but_fresh_scope_still_needs_new_authorization() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut db = database(&dir.path().join("app.sqlite"))?;
    let profile = Profile::prepare()?;
    seed(&mut db)?;
    cut(&mut db, &profile, 20)?;
    let mut adoption = intent("new_attempt");
    adoption.slot = "refresh_slot_0".into();
    assert!(!connect::begin(&mut db, &adoption, 5)?);
    adoption.expected_generation = Some(1);
    adoption.proposed_generation = 2;
    adoption.expected_epoch = 2;
    assert!(!connect::begin(&mut db, &adoption, 5)?); // No implicit restored-slot replacement profile.
    let fresh = intent("new_scoped_authorization");
    assert!(connect::begin(&mut db, &fresh, 5)?); // Navigation only, never a provider or native permit.
    assert_eq!(
        connect::state(&db, &fresh.attempt)?,
        Some(connect::ConnectState::AwaitingProviderAuthorization)
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM main.oauth_connection_slots WHERE status='active'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn changed_row_or_identity_inventory_refuses_without_repair() -> Result<()> {
    for mutation in 0..4 {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        seed(&mut db)?;
        let mut tx = db.transaction()?;
        let before = Snapshot::capture(&tx, &profile)?;
        let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), 21)?;
        match mutation {
            0 => {
                tx.execute("UPDATE main.oauth_connection_slots SET affinity='changed' WHERE slot='refresh_slot_0'",[])?;
            }
            1 => {
                tx.execute("UPDATE main.oauth_connect_attempts SET consent='changed' WHERE attempt='pending'",[])?;
            }
            2 => {
                tx.execute(
                    "UPDATE main.day2_meta SET value='foreign/scope/app' WHERE key='scope'",
                    [],
                )?;
            }
            _ => {
                tx.execute("INSERT INTO main.oauth_connect_attempts SELECT 'new_identity',slot,expected_generation,expected_epoch,proposed_generation,owner,profile,registration,callback,consent,expires_at,state,code_ref,account,scope_evidence,generation_floor FROM main.oauth_connect_attempts WHERE attempt='pending'",[])?;
            }
        }
        assert!(close_in(&mut tx, before, &cut, &profile).is_err());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn late_failure_rolls_back_cut_and_all_local_revocations_even_if_caller_catches_it() -> Result<()> {
    for failure in ["slot", "inbound"] {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        seed(&mut db)?;
        let before_history = histories(&db)?;
        // Valid but exhausted inputs are refused, never clamped or wrapped.
        let table = if failure == "slot" {
            "oauth_connection_slots"
        } else {
            "oauth_inbound_grants"
        };
        let column = if failure == "slot" {
            "security_epoch"
        } else {
            "epoch"
        };
        db.execute(
            &format!("UPDATE {table} SET {column}=9223372036854775807"),
            [],
        )?;
        let mut tx = db.transaction()?;
        let snapshot = Snapshot::capture(&tx, &profile)?;
        let cut = crate::security_epoch::restore_cut::fixture(snapshot.digest().clone(), 22)?;
        assert!(close_in(&mut tx, snapshot, &cut, &profile).is_err());
        tx.commit()?; // Catching the failure must not persist a prefix.
        assert_eq!(
            db.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM main.oauth_restore_closed", [], |r| {
                r.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(histories(&db)?, before_history);
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM main.oauth_connection_slots WHERE status='active'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            4
        );
    }
    Ok(())
}

#[test]
fn missing_partial_shadow_and_unknown_units_refuse_before_any_cut() -> Result<()> {
    for mutation in 0..6 {
        let dir = tempfile::tempdir()?;
        let mut db = database(&dir.path().join("app.sqlite"))?;
        let profile = Profile::prepare()?;
        match mutation {
            0 => db.execute_batch("CREATE TEMP TABLE oauth_connect_attempts(untrusted TEXT)")?,
            1 => db.execute_batch("CREATE TABLE oauth_unreviewed_callback(untrusted TEXT)")?,
            2 => db.execute_batch("DROP TABLE oauth_use_handles")?,
            3 => db.execute_batch("CREATE TEMP TABLE day2_meta(key TEXT,value TEXT)")?,
            4 => db.execute_batch("ATTACH ':memory:' AS foreign_state")?,
            _ => {
                db.execute("INSERT INTO oauth_connect_attempts(attempt,slot,expected_generation,expected_epoch,proposed_generation,owner,profile,registration,callback,consent,expires_at,state,generation_floor) VALUES(?1,'slot',NULL,1,1,'human','profile','registration','callback','consent',100,'awaiting_provider_authorization',0)",["invalid\noriginal"])?;
            }
        }
        let tx = db.transaction()?;
        assert!(Snapshot::capture(&tx, &profile).is_err());
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn ordinary_restore_allows_only_empty_current_cut_metadata() -> Result<()> {
    let mut db = Connection::open_in_memory()?;
    {
        let tx = db.transaction()?;
        require_no_history(&tx)?;
        tx.commit()?;
    }
    install(&db)?;
    {
        let tx = db.transaction()?;
        require_no_history(&tx)?;
        tx.commit()?;
    }
    db.execute("DELETE FROM oauth_restore_schema_version", [])?;
    let tx = db.transaction()?;
    assert!(require_no_history(&tx).is_err());
    tx.rollback()?;
    Ok(())
}

#[test]
fn ordinary_preflight_refuses_retained_oauth_after_selection_removal_and_readonly_reopen()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("archive.sqlite");
    let mut db = database(&path)?;
    {
        let tx = db.transaction()?;
        crate::store::require_no_managed_credential_restore_state(&tx)?;
        tx.commit()?;
    }
    seed(&mut db)?;
    let original = histories(&db)?;
    // No credential family or desired OAuth selection participates in this
    // actual ordinary preflight. Empty restore-cut tables cannot hide history.
    drop(db);
    for _ in 0..2 {
        let mut db =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = db.transaction()?;
        assert!(crate::store::require_no_managed_credential_restore_state(&tx).is_err());
        assert_eq!(histories(&tx)?, original);
        assert_eq!(
            tx.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        tx.rollback()?;
    }
    Ok(())
}

#[test]
fn ordinary_preflight_preserves_the_callers_actual_progress_hook_on_success_and_refusal()
-> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    };
    for occupied in [false, true] {
        let directory = tempfile::tempdir()?;
        let mut db = database(&directory.path().join("archive.sqlite"))?;
        if occupied {
            seed(&mut db)?;
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let interrupt = Arc::new(AtomicBool::new(false));
        let counter = calls.clone();
        let stop = interrupt.clone();
        db.progress_handler(
            1,
            Some(move || {
                counter.fetch_add(1, SeqCst);
                stop.load(SeqCst)
            }),
        )?;
        let tx = db.transaction()?;
        assert_eq!(
            crate::store::require_no_managed_credential_restore_state(&tx).is_err(),
            occupied
        );
        tx.rollback()?;
        let before = calls.load(SeqCst);
        let _:i64=db.query_row("WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<100) SELECT sum(i) FROM n",[],|r|r.get(0))?;
        assert!(
            calls.load(SeqCst) > before,
            "preflight replaced the caller's hook"
        );
        interrupt.store(true, SeqCst);
        assert!(
            db.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                .is_err()
        );
        db.progress_handler(0, None::<fn() -> bool>)?;
    }
    Ok(())
}

const CHILD: &str = "oauth::restore::tests::restore_cut_process_child";

#[test]
fn actual_process_loss_before_and_after_outer_commit_has_one_replayable_cut() -> Result<()> {
    for stage in 0..3 {
        let directory = tempfile::tempdir()?;
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                CHILD,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("G1_RESTORE_CUT_ROOT", directory.path())
            .env("G1_RESTORE_CUT_STAGE", stage.to_string())
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(70 + stage),
            "child did not reach its controlled loss point"
        );
        for _ in 0..2 {
            let db = Connection::open(directory.path().join("app.sqlite"))?;
            let applied = stage == 2; // Independent expected durable boundary.
            assert_eq!(
                db.query_row("SELECT count(*) FROM main.oauth_restore_cuts", [], |r| r
                    .get::<_, i64>(0))?,
                i64::from(applied)
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM main.oauth_restore_closed", [], |r| {
                    r.get::<_, i64>(0)
                })?,
                if applied { 7 } else { 0 }
            );
            assert_eq!(db.query_row("SELECT count(*) FROM main.oauth_connection_slots WHERE status=?1 AND security_epoch=?2",params![if applied {"reauth_required"} else {"active"},if applied {2} else {1}],|r|r.get::<_,i64>(0))?,4);
            assert_eq!(
                db.query_row(
                    "SELECT state,code_ref FROM main.oauth_connect_attempts WHERE attempt='sent'",
                    [],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                )?,
                ("exchange_may_have_been_sent".into(), "retained_code".into())
            );
            assert_eq!(
                db.query_row(
                    "SELECT receipt FROM main.oauth_refresh_attempts WHERE attempt='refresh_3'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "known_receipt"
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "singleton subprocess invoked by the mandatory process-loss parent"]
fn restore_cut_process_child() -> Result<()> {
    let root = std::path::PathBuf::from(
        std::env::var_os("G1_RESTORE_CUT_ROOT")
            .ok_or_else(|| anyhow::anyhow!("owned child root required"))?,
    );
    let stage: i32 = std::env::var("G1_RESTORE_CUT_STAGE")?.parse()?;
    assert!((0..3).contains(&stage));
    let mut db = database(&root.join("app.sqlite"))?;
    seed(&mut db)?;
    let profile = Profile::prepare()?;
    let mut tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let before = Snapshot::capture(&tx, &profile)?;
    let cut = crate::security_epoch::restore_cut::fixture(before.digest().clone(), 101)?;
    if stage == 0 {
        std::process::exit(70);
    }
    close_in(&mut tx, before, &cut, &profile)?;
    if stage == 1 {
        std::process::exit(71);
    }
    tx.commit()?;
    std::process::exit(72)
}

#[test]
fn actual_continuation_gates_cannot_drop_retarget_duplicate_or_delay_the_cut_check() -> Result<()> {
    use syn::visit::Visit;
    // Deliberately closed to the simple expressions used by these prefixes.
    // Compare parsed structure, without adding a token-printing dependency or
    // treating unrecognised expressions/macros as equivalent source.
    fn expression(value: &syn::Expr) -> Option<String> {
        let arguments = |args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>| {
            args.iter().map(expression).collect::<Option<Vec<_>>>()
        };
        Some(match value {
            syn::Expr::Path(path) if path.qself.is_none() && path.attrs.is_empty() => {
                let parts = path
                    .path
                    .segments
                    .iter()
                    .map(|part| {
                        matches!(part.arguments, syn::PathArguments::None)
                            .then(|| part.ident.to_string())
                    })
                    .collect::<Option<Vec<_>>>()?;
                format!("path:{:?}:{parts:?}", path.path.leading_colon.is_some())
            }
            syn::Expr::Call(call) if call.attrs.is_empty() => {
                format!(
                    "call:{:?}:{:?}",
                    expression(&call.func)?,
                    arguments(&call.args)?
                )
            }
            syn::Expr::MethodCall(call) if call.attrs.is_empty() && call.turbofish.is_none() => {
                format!(
                    "method:{:?}:{}:{:?}",
                    expression(&call.receiver)?,
                    call.method,
                    arguments(&call.args)?
                )
            }
            syn::Expr::Reference(reference) if reference.attrs.is_empty() => {
                format!(
                    "reference:{}:{:?}",
                    reference.mutability.is_some(),
                    expression(&reference.expr)?
                )
            }
            syn::Expr::Field(field) if field.attrs.is_empty() => {
                let member = match &field.member {
                    syn::Member::Named(name) => format!("named:{name}"),
                    syn::Member::Unnamed(index) => format!("index:{}", index.index),
                };
                format!("field:{:?}:{member}", expression(&field.base)?)
            }
            syn::Expr::Try(attempt) if attempt.attrs.is_empty() => {
                format!("try:{:?}", expression(&attempt.expr)?)
            }
            syn::Expr::Lit(literal) if literal.attrs.is_empty() => match &literal.lit {
                syn::Lit::Str(text) => format!("string:{:?}", text.value()),
                _ => return None,
            },
            _ => return None,
        })
    }
    fn statement(value: &syn::Stmt) -> Option<String> {
        match value {
            syn::Stmt::Expr(expr, semicolon) => Some(format!(
                "expr:{}:{:?}",
                semicolon.is_some(),
                expression(expr)?
            )),
            syn::Stmt::Local(local) if local.attrs.is_empty() => {
                let typed = matches!(&local.pat, syn::Pat::Type(_));
                let binding = match &local.pat {
                    syn::Pat::Ident(binding)
                        if binding.attrs.is_empty() && binding.subpat.is_none() =>
                    {
                        binding
                    }
                    syn::Pat::Type(typed) if typed.attrs.is_empty() => {
                        let syn::Pat::Ident(binding) = typed.pat.as_ref() else {
                            return None;
                        };
                        let syn::Type::Path(path) = typed.ty.as_ref() else {
                            return None;
                        };
                        if !path.path.is_ident("Claims") || path.qself.is_some() {
                            return None;
                        }
                        binding
                    }
                    _ => return None,
                };
                if !binding.attrs.is_empty() || binding.subpat.is_some() {
                    return None;
                }
                let init = local.init.as_ref()?;
                if init.diverge.is_some() {
                    return None;
                }
                Some(format!(
                    "let:{}:{}:{}:{}:{:?}",
                    binding.ident,
                    binding.by_ref.is_some(),
                    binding.mutability.is_some(),
                    typed,
                    expression(&init.expr)?
                ))
            }
            _ => None,
        }
    }
    struct Calls(usize);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "require_open")
            {
                self.0 += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    fn body(source: &str, name: &str, owner: Option<&str>) -> Result<syn::Block> {
        let syntax = syn::parse_file(source)?;
        let mut selected = Vec::new();
        for item in syntax.items {
            match item {
                syn::Item::Fn(function) if owner.is_none() && function.sig.ident == name => {
                    selected.push(*function.block)
                }
                syn::Item::Impl(implementation)
                    if owner.is_some_and(|owner| {
                        matches!(implementation.self_ty.as_ref(),syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident(owner))
                    }) =>
                {
                    for item in implementation.items {
                        if let syn::ImplItem::Fn(function) = item
                            && function.sig.ident == name
                        {
                            selected.push(function.block);
                        }
                    }
                }
                _ => {}
            }
        }
        ensure!(selected.len() == 1, "actual_cut_gate_selector_count");
        Ok(selected.remove(0))
    }
    fn accepts(block: &syn::Block, prefix: &str, guard: &str, count: usize) -> Result<bool> {
        let expected: syn::Block = syn::parse_str(&format!("{{{prefix}{guard}}}"))?;
        let prefix: Vec<_> = expected.stmts.iter().map(statement).collect();
        ensure!(
            prefix.iter().all(Option::is_some),
            "closed_guard_prefix_shape"
        );
        let actual: Vec<_> = block
            .stmts
            .iter()
            .take(prefix.len())
            .map(statement)
            .collect();
        let mut calls = Calls(0);
        calls.visit_block(block);
        Ok(actual == prefix && calls.0 == count)
    }
    let connect = include_str!("connect.rs");
    let custody = include_str!("custody.rs");
    let exchange = include_str!("exchange.rs");
    let refresh = include_str!("store.rs");
    let fresh = include_str!("fresh_owner.rs");
    let management = include_str!("management/app.rs");
    let usage = include_str!("usage.rs");
    let inbound = include_str!("inbound.rs");
    let outbound = include_str!("outbound.rs");
    let mut specs = Vec::new();
    for name in ["begin_in", "slot_matches"] {
        specs.push((connect, name, None, "", "Connect", "tx", "&intent.attempt"));
    }
    specs.push((connect, "activate_in", None, "", "Connect", "tx", "attempt"));
    specs.push((
        connect,
        "activate_mapped_in",
        None,
        "",
        "Connect",
        "tx",
        "verified.attempt()",
    ));
    specs.push((
        connect,
        "pending_approval",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((connect,"claim_callback",None,"identifier(attempt)?;identifier(code_ref)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"authorize_and_commit_exchange",None,"identifier(attempt)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"await_account_approval",None,"identifier(attempt)?;identifier(account)?;identifier(scope_evidence)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((connect,"quarantine_external_bound",None,"let intent=verified.intent();let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","&intent.attempt"));
    specs.push((connect,"finish_blocked",None,"identifier(attempt)?;let tx=db.transaction_with_behavior(TransactionBehavior::Immediate)?;","Connect","&tx","attempt"));
    specs.push((
        outbound,
        "handle_callback_in",
        None,
        "",
        "Connect",
        "tx",
        "ingress.attempt",
    ));
    specs.push((
        connect,
        "record_denial",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((
        refresh,
        "definitive_rejection_in",
        None,
        "",
        "Refresh",
        "tx",
        "attempt",
    ));
    specs.push((
        exchange,
        "load_binding",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((
        exchange,
        "authorize_in",
        None,
        "",
        "Connect",
        "tx",
        "&input.intent.attempt",
    ));
    for name in [
        "claim_refresh_in",
        "checked_dispatch_in",
        "commit_replacement_in",
    ] {
        specs.push((refresh, name, None, "", "Refresh", "tx", "attempt"));
    }
    for name in [
        "claim",
        "publish",
        "consume_in_current_app_transaction",
        "terminal_history",
    ] {
        specs.push((
            fresh,
            name,
            None,
            "",
            "Fresh",
            "db",
            "intent.commitment()?.as_str()",
        ));
    }
    for name in ["code_exists", "verifier_exists"] {
        specs.push((custody, name, None, "", "Connect", "tx", "&intent.attempt"));
    }
    specs.push((
        custody,
        "delete_attempt_material",
        None,
        "",
        "Connect",
        "tx",
        "attempt",
    ));
    for name in ["load_code", "load_verifier", "load_bundle"] {
        specs.push((custody, name, None, "", "Connect", "db", "&intent.attempt"));
    }
    for name in [
        "publish_code",
        "publish_verifier",
        "publish_tokens",
        "replace_tokens",
        "publish_external_quarantine",
    ] {
        specs.push((
            custody,
            name,
            None,
            "",
            "Connect",
            "tx",
            "&prepared.attempt",
        ));
    }
    specs.push((
        custody,
        "quarantine_row",
        None,
        "",
        "Connect",
        "db",
        "attempt",
    ));
    specs.push((usage, "load", None, "", "Use", "db", "reference"));
    specs.push((inbound, "active_grant", None, "", "Inbound", "db", "id"));
    specs.push((inbound, "record_grant", None, "", "Inbound", "db", "id"));
    for (name, id) in [("load", "id"), ("check_in", "&view.id")] {
        specs.push((
            management,
            name,
            Some("Manager"),
            "",
            "Management",
            "db",
            id,
        ));
    }
    assert_eq!(specs.len(), 39);
    for (source, name, owner, prefix, kind, db, id) in specs {
        let root = if owner.is_some() {
            "crate::oauth::restore"
        } else {
            "super::restore"
        };
        let guard = format!("{root}::require_open({db},{root}::Kind::{kind},{id})?;");
        let block = body(source, name, owner)?;
        let count = if kind == "Use" { 2 } else { 1 };
        assert!(accepts(&block, prefix, &guard, count)?, "{name}");
        if kind == "Use" {
            let decoded: syn::Stmt =
                syn::parse_str("let claims:Claims=crate::json::decode(encoded.as_bytes())?;")?;
            ensure!(
                statement(&decoded).is_some(),
                "closed_decode_statement_shape"
            );
            let positions: Vec<_> = block
                .stmts
                .iter()
                .enumerate()
                .filter(|(_, actual_statement)| statement(actual_statement) == statement(&decoded))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(positions.len(), 1);
            let check: syn::Stmt = syn::parse_str(
                "super::restore::require_open(db,super::restore::Kind::UseOriginal,claim_identity(&claims)?.as_str())?;",
            )?;
            ensure!(statement(&check).is_some(), "closed_original_guard_shape");
            assert_eq!(statement(&block.stmts[positions[0] + 1]), statement(&check));
            let mut omitted = block.clone();
            omitted.stmts.remove(positions[0] + 1);
            assert!(!accepts(&omitted, prefix, &guard, count)?);
        }
        let expected: syn::Block = syn::parse_str(&format!("{{{prefix}{guard}}}"))?;
        let index = expected.stmts.len() - 1;
        let mut deleted = block.clone();
        deleted.stmts.remove(index);
        assert!(!accepts(&deleted, prefix, &guard, count)?, "deleted {name}");
        let mut delayed = block.clone();
        let check = delayed.stmts.remove(index);
        let commit: syn::Stmt = syn::parse_str("tx.commit()?;")?;
        let commits: Vec<_> = delayed
            .stmts
            .iter()
            .enumerate()
            .filter(|(_, value)| statement(value) == statement(&commit))
            .map(|(i, _)| i)
            .collect();
        assert!(commits.len() <= 1);
        if let Some(position) = commits.first() {
            // Move after real work but before consuming the owned transaction.
            delayed.stmts.insert(*position, check);
        } else {
            let last = delayed
                .stmts
                .pop()
                .ok_or_else(|| anyhow::anyhow!("guard_tail_missing"))?;
            let syn::Stmt::Expr(value, None) = last else {
                anyhow::bail!("guard_tail_shape")
            };
            let mut saved: syn::Stmt = syn::parse_str("let restore_guard_delayed_result=();")?;
            let syn::Stmt::Local(local) = &mut saved else {
                unreachable!()
            };
            *local.init.as_mut().unwrap().expr = value;
            delayed.stmts.push(saved);
            delayed.stmts.push(check);
            let tail: syn::Block = syn::parse_str("{restore_guard_delayed_result}")?;
            delayed.stmts.extend(tail.stmts);
        }
        assert!(!accepts(&delayed, prefix, &guard, count)?, "delayed {name}");
        let mut duplicate = block.clone();
        duplicate.stmts.insert(index, expected.stmts[index].clone());
        assert!(
            !accepts(&duplicate, prefix, &guard, count)?,
            "duplicate {name}"
        );
        let mut wrong = block.clone();
        wrong.stmts[index] = syn::parse_str(&guard.replace(id, "\"different_original\""))?;
        assert!(
            !accepts(&wrong, prefix, &guard, count)?,
            "retargeted {name}"
        );
    }
    Ok(())
}
