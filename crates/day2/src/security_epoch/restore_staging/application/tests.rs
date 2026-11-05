use super::*;
use crate::{
    authority_state, budget,
    managed_credentials::{effects, simulation, store as credentials},
};
use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope};
use rusqlite::types::Value;
use std::collections::BTreeMap;

struct Fixture {
    db: Connection,
    namespace: Namespace,
    previous: authority_state::ActiveAuthority,
    fence: restore_authority::PreparedRestoreFence,
    authority_schema: restore_authority::RestoreFenceSchema,
    oauth_schema: crate::oauth::restore::Profile,
    cut: restore_cut::Cut,
    peers: (String, String),
    token: zeroize::Zeroizing<String>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        db.pragma_update(None, "journal_mode", "MEMORY")?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch(crate::store::PLATFORM_DDL)?;
        let namespace = credentials::tests::namespace();
        let scope = format!(
            "{}/{}/{}",
            namespace.installation.as_str(),
            namespace.environment.as_str(),
            namespace.app.as_str()
        );
        db.execute("INSERT INTO day2_meta VALUES('scope',?1)", [&scope])?;
        db.execute(
            "INSERT INTO day2_meta VALUES('schema',?1)",
            [Digest::new(b"schema").as_str()],
        )?;
        let previous = authority_state::ActiveAuthority {
            stamp: authority_state::AuthorityStamp {
                epoch: Digest::new(b"old-application-authority").as_str().into(),
                revision: 1,
            },
            document: authority_state::AuthorityDocument {
                security: None,
                hosted_domain: None,
                resources: Default::default(),
                credentials: Default::default(),
                enabled: true,
                readers: Default::default(),
                writers: Default::default(),
                policy: None,
            },
            artifact_id: Digest::new(b"artifact").as_str().into(),
            artifact_path: "/admitted/source".into(),
        };
        {
            let tx = db.transaction()?;
            crate::audit::upgrade(&tx)?;
            authority_state::upgrade(&tx)?;
            budget::initialize_in(&tx, &previous.stamp.epoch)?;
            crate::delegation_commands::upgrade(&tx)?;
            authority_state::store_record_in(&tx, &previous, "fixture", "source")?;
            tx.commit()?;
        }
        // Match ordinary initialization: complete host/audit setup before any
        // private OAuth tables exist. The host's business-row upgrade must not
        // add model columns to an already installed private identity unit.
        credentials::install_schema(&db)?;
        crate::managed_credentials::issuance::install(&db)?;
        crate::oauth::usage::install(&db)?;
        crate::oauth::inbound::install_schema(&db)?;
        let (_, token) = credentials::restore::seed_first_epoch_for_tests(&mut db)?;
        let peers = credentials::restore::seed_historical_peers_for_tests(
            &db,
            &scope,
            &previous.stamp,
            &previous.artifact_id,
            1,
        )?;
        db.execute(
            "INSERT INTO day2_web_sessions VALUES(?1,'alice@example.com',200)",
            [crate::digest("a".repeat(43).as_bytes())],
        )?;
        db.execute("INSERT INTO day2_web_secret VALUES(1,?1)", [&[7u8; 32][..]])?;
        db.execute("INSERT INTO oauth_connection_slots VALUES('old-slot',1,1,1,'profile','account','affinity','active')",[])?;
        db.execute("INSERT INTO oauth_refresh_attempts VALUES('old-refresh','old-slot',1,1,1,'profile','account','affinity','uncertain',NULL,NULL)",[])?;
        {
            let tx = db.transaction()?;
            tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES('old-work','submit','alice@example.com','{}',?1,100,'pending')",[&previous.artifact_id])?;
            authority_state::pin_invocation(&tx, "old-work", &previous.stamp)?;
            let outgoing = serde_json::to_string(&crate::delegation_commands::Delivery {
                first_at: 90,
                incarnation: "source-incarnation".into(),
            })?;
            tx.execute("INSERT INTO day2_app_outgoing VALUES('unknown-send','exact-fingerprint',?1,'old-work')",[&outgoing])?;
            let mut request = budget::ReservationRequest {
                id: "known".into(),
                binding: "fixture-exact-input".into(),
                context: budget::BudgetContext {
                    app: namespace.app.as_str().into(),
                    actor: "alice@example.com".into(),
                    connection: "mailbox".into(),
                    invocation_root: "old-work".into(),
                    now: 100,
                },
                budgets: BTreeMap::from([(
                    "app".into(),
                    BudgetDefinition {
                        revision: 1,
                        scope: BudgetScope::App,
                        period_seconds: 60,
                        limits: BudgetLimits {
                            calls: Some(100),
                            ..Default::default()
                        },
                    },
                )]),
                quote: budget::Consumption {
                    calls: 3,
                    ..Default::default()
                },
            };
            let known = budget::reserve_in(&tx, &request)?;
            budget::settle_in(
                &tx,
                &known,
                &budget::Settlement::Known {
                    actual: budget::Consumption {
                        calls: 2,
                        ..Default::default()
                    },
                },
            )?;
            request.id = "unknown".into();
            let unknown = budget::reserve_in(&tx, &request)?;
            budget::settle_in(&tx, &unknown, &budget::Settlement::Unknown)?;
            tx.commit()?;
        }
        let authority_schema = restore_authority::RestoreFenceSchema::prepare()?;
        let oauth_schema = crate::oauth::restore::Profile::prepare()?;
        let cut = {
            let tx = db.transaction()?;
            let snapshot = crate::oauth::restore::Snapshot::capture(&tx, &oauth_schema)?;
            let cut = restore_cut::fixture_for_storage_epoch(
                snapshot.digest().clone(),
                909,
                &scope,
                Digest::new(b"schema"),
                1,
            )?;
            tx.rollback()?;
            cut
        };
        let fence = restore_authority::PreparedRestoreFence::new(
            previous.clone(),
            std::path::Path::new("/unpublished/target"),
            Digest::new(b"fresh-application-authority"),
            200,
        )?;
        Ok(Self {
            db,
            namespace,
            previous,
            fence,
            authority_schema,
            oauth_schema,
            cut,
            peers,
            token,
        })
    }

    fn selection(&self) -> Selection<'_> {
        Selection {
            namespace: &self.namespace,
            source_epoch: 1,
            fence: &self.fence,
            authority_schema: &self.authority_schema,
            oauth_schema: &self.oauth_schema,
            cut: &self.cut,
        }
    }
}

fn rows(db: &Connection, table: &str) -> Result<Vec<Vec<Value>>> {
    ensure!(
        table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "test_table_identifier"
    );
    let mut statement = db.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let values = statement
        .query_map([], |row| {
            (0..row.as_ref().column_count())
                .map(|i| row.get(i))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<Vec<Value>>>>()?;
    Ok(values)
}

fn snapshot(db: &Connection) -> Result<BTreeMap<String, Vec<Vec<Value>>>> {
    let mut statement=db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    tables
        .into_iter()
        .map(|table| Ok((table.clone(), rows(db, &table)?)))
        .collect()
}

fn ledger(db: &Connection) -> Result<budget::LedgerStatus> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Deferred)?;
    let value = budget::inspect_in(&tx)?;
    tx.commit()?;
    Ok(value)
}

#[test]
fn complete_reset_revokes_and_closes_without_erasing_history_or_budget_debt() -> Result<()> {
    effects::scope(simulation::World::new(98311), || {
        let fixture = Fixture::new()?;
        assert!(credentials::restore::first_epoch_ingress_for_tests(
            &fixture.db,
            &fixture.token,
            1
        )?);
        let material = rows(&fixture.db, "day2_credential_material")?;
        let receipts = rows(&fixture.db, "day2_credential_receipts")?;
        let outgoing = rows(&fixture.db, "day2_app_outgoing")?;
        let before_budget = ledger(&fixture.db)?;
        assert_eq!(before_budget.known_usage.calls, 2);
        assert_eq!(before_budget.unknown_usage.len(), 1);
        crate::web_security::session_for_token_in(&fixture.db, &"a".repeat(43), 100)?;
        let summary = reset(&fixture.db, &fixture.selection())?;
        assert_eq!(
            (
                summary.credentials.lineages,
                summary.credentials.newly_revoked,
                summary.credentials.versions,
                summary.closed_oauth_originals
            ),
            (1, 1, 1, 1)
        );
        let bytes = fixture.db.serialize(MAIN_DB)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("unpublished.sqlite");
        std::fs::write(&path, &*bytes)?;
        for _ in 0..2 {
            let db = Connection::open(&path)?;
            let active = authority_state::current(&db)?;
            assert!(!active.document.enabled);
            assert_ne!(active.stamp.epoch, fixture.previous.stamp.epoch);
            assert_eq!(active.stamp.revision, 2);
            assert_eq!(
                db.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                    .get::<_, String>(
                    0
                ))?,
                "revoked"
            );
            assert_eq!(
                db.query_row("SELECT state FROM day2_credential_versions", [], |r| r
                    .get::<_, String>(
                    0
                ))?,
                "revoked"
            );
            for current_epoch in [1, 2] {
                assert!(!credentials::restore::first_epoch_ingress_for_tests(
                    &db,
                    &fixture.token,
                    current_epoch
                )?);
            }
            assert_eq!(
                db.query_row("SELECT state FROM day2_credential_deliveries", [], |r| {
                    r.get::<_, String>(0)
                })?,
                "closed"
            );
            assert!(material == rows(&db, "day2_credential_material")?);
            assert!(receipts == rows(&db, "day2_credential_receipts")?);
            assert!(outgoing == rows(&db, "day2_app_outgoing")?);
            assert_eq!(
                db.query_row("SELECT intent FROM day2_credential_browser", [], |r| r
                    .get::<_, String>(
                    0
                ))?,
                fixture.peers.0
            );
            assert_eq!(
                db.query_row(
                    "SELECT confirmation FROM day2_credential_confirmations",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                fixture.peers.1
            );
            assert_eq!(
                db.query_row(
                    "SELECT state FROM oauth_refresh_attempts WHERE attempt='old-refresh'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "uncertain"
            );
            assert_eq!(db.query_row("SELECT status,security_epoch,generation FROM oauth_connection_slots WHERE slot='old-slot'",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?)))?,("reauth_required".into(),2,1));
            assert!(crate::web_security::session_for_token_in(&db, &"a".repeat(43), 100).is_err());
            assert_eq!(
                db.query_row("SELECT count(*) FROM day2_web_secret", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            let after = ledger(&db)?;
            assert!(after.frozen_after_restore);
            assert_eq!(after.ledger_id, before_budget.ledger_id);
            assert_eq!(after.accounts, before_budget.accounts);
            assert_eq!(after.known_usage, before_budget.known_usage);
            assert_eq!(after.unknown_usage, before_budget.unknown_usage);
            assert_eq!(
                after.outstanding_attempts,
                before_budget.outstanding_attempts
            );
            assert!(authority_state::is_blocked(&db, "old-work")?);
        }
        Ok(())
    })
}

#[test]
fn cut_binding_failure_after_fence_rolls_back_even_when_caller_catches_and_commits() -> Result<()> {
    effects::scope(simulation::World::new(98312), || {
        for after_cut in [false, true] {
            let fixture = Fixture::new()?;
            let before = snapshot(&fixture.db)?;
            let wrong = restore_cut::fixture_for_storage_epoch(
                Digest::new(b"wrong-inventory"),
                910,
                "wonderly/dev/transcriber",
                Digest::new(b"schema"),
                1,
            )?;
            let tx = Transaction::new_unchecked(&fixture.db, TransactionBehavior::Immediate)?;
            assert!(
                crate::oauth::restore::reset_application_in(
                    &tx,
                    &fixture.fence,
                    &fixture.authority_schema,
                    &fixture.oauth_schema,
                    if after_cut { &fixture.cut } else { &wrong },
                    &fixture.namespace,
                    if after_cut { 8 } else { 1 }
                )
                .is_err()
            );
            tx.commit()?;
            assert!(fixture.db.is_autocommit());
            assert!(
                before == snapshot(&fixture.db)?,
                "partial denial escaped the owning rollback scope"
            );
        }
        Ok(())
    })
}

#[test]
fn credential_only_profile_still_refuses_closed_peer_history_and_nested_budget_cannot_renew()
-> Result<()> {
    effects::scope(simulation::World::new(98313), || {
        let fixture = Fixture::new()?;
        let before = snapshot(&fixture.db)?;
        let tx = Transaction::new_unchecked(&fixture.db, TransactionBehavior::Immediate)?;
        assert!(credentials::restore::stage_reset(&tx, &fixture.namespace, 1).is_err());
        crate::oauth::schema::admit(&tx, |db| {
            assert!(crate::oauth::schema::admit_memory_transaction(&tx, |_| Ok(())).is_err());
            crate::oauth::schema::require_admission(db)
        })?;
        tx.commit()?;
        assert!(before == snapshot(&fixture.db)?);
        Ok(())
    })
}

#[test]
fn first_restore_selection_refuses_noninitial_source_epochs() -> Result<()> {
    for source_epoch in [7, 8] {
        assert!(
            restore_cut::fixture_for_storage_epoch(
                Digest::new(b"inventory"),
                911,
                "wonderly/dev/transcriber",
                Digest::new(b"schema"),
                source_epoch,
            )
            .is_err()
        );
    }
    Ok(())
}
