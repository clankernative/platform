use super::*;
use crate::{
    authority_state, budget,
    managed_credentials::{effects, simulation, store as credentials},
};
use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope};
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(in crate::security_epoch::restore_staging) struct Fixture {
    pub(in crate::security_epoch::restore_staging) db: Connection,
    namespace: Namespace,
    artifact: crate::artifact::LoadedArtifact,
    previous: authority_state::ActiveAuthority,
    fence: restore_authority::PreparedRestoreFence,
    authority_schema: restore_authority::RestoreFenceSchema,
    oauth_schema: crate::oauth::restore::Profile,
    cut: restore_cut::Cut,
    peers: (String, String),
    token: zeroize::Zeroizing<String>,
}

impl Fixture {
    pub(in crate::security_epoch::restore_staging) fn new() -> Result<Self> {
        let schema:crate::schema::Schema=serde_json::from_value(serde_json::json!({"models":{"fixture_business":{"fields":{"value":"text"}}},"inputs":{},"foreign_keys":[]}))?;
        let schema_digest=schema.hash()?;
        // Actual host tests lend a typed immutable contract without running a
        // compiler. This cfg(test) constructor is not native artifact admission.
        let contract:crate::artifact::Artifact=serde_json::from_value(serde_json::json!({
            "format":crate::artifact::CURRENT_FORMAT,"roc_version":"restore-model-fixture",
            "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "worker_digest":"restore-model-fixture","schema_digest":schema_digest,"schema":schema,
            "operations":[],"sources":{},"admission":"local-spike-only"
        }))?;
        let artifact=crate::artifact::LoadedArtifact::from_contract_for_tests(Digest::new(b"artifact").as_str().into(),PathBuf::new(),contract);
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        db.pragma_update(None, "journal_mode", "MEMORY")?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.execute_batch(crate::store::PLATFORM_DDL)?;
        for ddl in artifact.contract().schema.ddl()? {db.execute_batch(&ddl)?;}
        db.execute("INSERT INTO fixture_business(id,version,created_at,value) VALUES(1,1,100,'keep-data')",[])?;
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
            [&artifact.contract().schema_digest],
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
        credentials::install_schema(&db).context("fixture_credential_schema")?;
        crate::managed_credentials::issuance::install(&db)
            .context("fixture_confirmation_schema")?;
        crate::oauth::usage::install(&db).context("fixture_oauth_schema")?;
        crate::oauth::inbound::install_schema(&db).context("fixture_inbound_schema")?;
        let (_, token) = credentials::restore::seed_first_epoch_for_tests(&mut db)
            .context("fixture_epoch_one_issue")?;
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
        let authority_schema = restore_authority::RestoreFenceSchema::prepare()
            .context("fixture_authority_reference")?;
        let oauth_schema =
            crate::oauth::restore::Profile::prepare().context("fixture_oauth_reference")?;
        let cut = {
            let tx = db.transaction()?;
            let snapshot = crate::oauth::restore::Snapshot::capture(&tx, &oauth_schema)
                .context("fixture_source_snapshot")?;
            let cut = restore_cut::fixture_for_storage_epoch(
                snapshot.digest().clone(),
                909,
                &scope,
                artifact.contract().schema_digest.clone().try_into()?,
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
            artifact,
            previous,
            fence,
            authority_schema,
            oauth_schema,
            cut,
            peers,
            token,
        })
    }

    pub(in crate::security_epoch::restore_staging) fn selection(&self) -> Selection<'_> {
        Selection {
            namespace: &self.namespace,
            source_epoch: 1,
            artifact: &self.artifact,
            fence: &self.fence,
            authority_schema: &self.authority_schema,
            oauth_schema: &self.oauth_schema,
            cut: &self.cut,
        }
    }

    pub(in crate::security_epoch::restore_staging) fn require_image(
        &self,
        db: &Connection,
        reset: bool,
    ) -> Result<()> {
        assert_eq!(observation(db, &self.token)?, expected(reset));
        for table in ["day2_credential_material", "day2_credential_receipts", "day2_app_outgoing"] {
            assert!(rows(db, table)? == rows(&self.db, table)?, "restore_history_changed");
        }
        let before = ledger(&self.db)?;
        let after = ledger(db)?;
        assert_eq!(after.ledger_id, before.ledger_id);
        assert_eq!(after.accounts, before.accounts);
        assert_eq!(after.known_usage, before.known_usage);
        assert_eq!(after.unknown_usage, before.unknown_usage);
        assert_eq!(after.outstanding_attempts, before.outstanding_attempts);
        Ok(())
    }
}

// Test-only outer transaction for the standalone denial conformance histories.
// Production staging always owns its own outer unit in prepare_image.
fn reset(db: &Connection, selected: &Selection<'_>) -> Result<Summary> {
    ensure!(db.is_autocommit(), "test_restore_transaction_already_open");
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let result = reset_in(&tx, selected, selected.namespace, selected.source_epoch)?;
    tx.commit()?;
    Ok(result)
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
        assert!(
            credentials::restore::first_epoch_ingress_for_tests(&fixture.db, &fixture.token, 1)
                .context("fixture_pre_reset_ingress")?
        );
        let material = rows(&fixture.db, "day2_credential_material")?;
        let receipts = rows(&fixture.db, "day2_credential_receipts")?;
        let outgoing = rows(&fixture.db, "day2_app_outgoing")?;
        let before_budget = ledger(&fixture.db)?;
        assert_eq!(before_budget.known_usage.calls, 2);
        assert_eq!(before_budget.unknown_usage.len(), 1);
        crate::web_security::session_for_token_in(&fixture.db, &"a".repeat(43), 100)?;
        let summary = reset(&fixture.db, &fixture.selection()).context("actual_complete_reset")?;
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
fn reset_selection_cannot_substitute_the_staging_namespace_or_source_epoch() -> Result<()> {
    effects::scope(simulation::World::new(98314), || {
        for wrong_epoch in [false,true] {
            let fixture=Fixture::new()?;
            let before=snapshot(&fixture.db)?;
            let mut namespace=fixture.namespace.clone();
            if !wrong_epoch {namespace.binding_generation+=1;}
            let tx=Transaction::new_unchecked(&fixture.db,TransactionBehavior::Immediate)?;
            assert!(reset_in(&tx,&fixture.selection(),&namespace,if wrong_epoch {2} else {1}).is_err());
            tx.commit()?;
            assert!(before==snapshot(&fixture.db)?);
        }
        Ok(())
    })
}

#[test]
fn cut_rejects_a_foreign_artifact_or_schema_before_any_denial_write() -> Result<()> {
    effects::scope(simulation::World::new(98315), || {
        for wrong_schema in [false,true] {
            let fixture=Fixture::new()?;
            let mut contract=fixture.artifact.contract().clone();
            let id=if wrong_schema {
                contract.schema_digest=Digest::new(b"foreign-contract-schema").as_str().into();
                fixture.artifact.id().to_owned()
            } else {Digest::new(b"foreign-artifact").as_str().into()};
            let foreign=crate::artifact::LoadedArtifact::from_contract_for_tests(id,PathBuf::new(),contract);
            fixture.cut.require_artifact(&fixture.artifact)?;
            assert!(fixture.cut.require_artifact(&foreign).is_err());
            let selected=Selection{artifact:&foreign,..fixture.selection()};
            let before=snapshot(&fixture.db)?;
            let tx=Transaction::new_unchecked(&fixture.db,TransactionBehavior::Immediate)?;
            assert!(reset_in(&tx,&selected,&fixture.namespace,1).is_err());
            tx.commit()?;
            assert!(before==snapshot(&fixture.db)?);
        }
        Ok(())
    })
}

#[test]
fn actual_complete_reset_checks_exact_artifact_then_canonical_model_storage_before_cuts() {
    use quote::ToTokens as _;
    let file=syn::parse_file(include_str!("../application.rs")).unwrap();
    let functions:Vec<_>=file.items.into_iter().filter_map(|i|match i {syn::Item::Fn(f) if f.sig.ident=="reset_in"=>Some(f),_=>None}).collect();
    assert_eq!(functions.len(),1);
    let actual=&functions[0];
    let tail:syn::Block=syn::parse_quote!({
        selected.cut.require_artifact(selected.artifact)?;
        ensure!(crate::authority_state::current(tx)?.artifact_id == selected.artifact.id(),"complete_restore_source_artifact_changed");
        let scope=format!("{}/{}/{}",namespace.installation.as_str(),namespace.environment.as_str(),namespace.app.as_str());
        crate::store::validate_storage_in(tx,selected.artifact,&scope)?;
        crate::oauth::restore::reset_application_in(tx,selected.fence,selected.authority_schema,selected.oauth_schema,selected.cut,selected.namespace,selected.source_epoch)
    });
    let valid=|f:&syn::ItemFn| f.block.stmts.len()>=tail.stmts.len() && f.block.stmts.iter().rev().take(tail.stmts.len()).zip(tail.stmts.iter().rev()).all(|(a,b)|a.to_token_stream().to_string()==b.to_token_stream().to_string());
    assert!(valid(actual));
    let start=actual.block.stmts.len()-tail.stmts.len();
    for index in 0..tail.stmts.len() {
        let mut removed=actual.clone();removed.block.stmts.remove(start+index);assert!(!valid(&removed));
    }
    let mut late_validation=actual.clone();late_validation.block.stmts.swap(start+3,start+4);assert!(!valid(&late_validation));
    let mut foreign=actual.clone();foreign.block.stmts[start+3]=syn::parse_quote!(crate::store::validate_storage_in(tx,foreign_artifact,&scope)?;);assert!(!valid(&foreign));
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
                fixture.artifact.contract().schema_digest.clone().try_into()?,
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

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Inspect,
    DropReset,
    WrongEpoch,
    Commit,
    Reopen,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    enabled: bool,
    old_authority: bool,
    frozen_debt: bool,
    revoked_versions: i64,
    open_deliveries: i64,
    sessions: i64,
    secrets: i64,
    reauthorization_required: bool,
    old_token_accepted: bool,
}

fn observation(db: &Connection, token: &str) -> Result<Observation> {
    let authority = authority_state::current(db)?;
    let budget = ledger(db)?;
    ensure!(
        budget.known_usage.calls == 2 && budget.unknown_usage.len() == 1,
        "test_debt_changed"
    );
    let unknown: String = db.query_row(
        "SELECT state FROM oauth_refresh_attempts WHERE attempt='old-refresh'",
        [],
        |row| row.get(0),
    )?;
    ensure!(unknown == "uncertain", "test_unknown_refresh_erased");
    Ok(Observation {
        enabled: authority.document.enabled,
        old_authority: authority.stamp.epoch == Digest::new(b"old-application-authority").as_str(),
        frozen_debt: budget.frozen_after_restore,
        revoked_versions: db.query_row("SELECT count(*) FROM day2_credential_versions WHERE state='revoked'", [], |row| row.get(0))?,
        open_deliveries: db.query_row("SELECT count(*) FROM day2_credential_deliveries WHERE state!='closed'", [], |row| row.get(0))?,
        sessions: db.query_row("SELECT count(*) FROM day2_web_sessions", [], |row| row.get(0))?,
        secrets: db.query_row("SELECT count(*) FROM day2_web_secret", [], |row| row.get(0))?,
        reauthorization_required: db.query_row("SELECT status='reauth_required' AND security_epoch=2 FROM oauth_connection_slots WHERE slot='old-slot'", [], |row| row.get(0))?,
        old_token_accepted: credentials::restore::first_epoch_ingress_for_tests(db, token, 1)?,
    })
}

fn expected(reset: bool) -> Observation {
    // This oracle knows only the two allowed terminal states. It never reads
    // reset counts, cut rows, production transitions or a returned authority.
    if reset {
        Observation {
            enabled: false,
            old_authority: false,
            frozen_debt: true,
            revoked_versions: 1,
            open_deliveries: 0,
            sessions: 0,
            secrets: 0,
            reauthorization_required: true,
            old_token_accepted: false,
        }
    } else {
        Observation {
            enabled: true,
            old_authority: true,
            frozen_debt: false,
            revoked_versions: 0,
            open_deliveries: 1,
            sessions: 1,
            secrets: 1,
            reauthorization_required: false,
            old_token_accepted: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryFailure {
    ReturnedError,
    Panic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRun {
    step: Option<usize>,
    actual: Vec<Observation>,
    failure: Option<HistoryFailure>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordingCut {
    Ordinary,
    AfterFirstObservation,
}

fn history(
    seed: u64,
    actions: &[Action],
    recording: RecordingCut,
    captured: &mut HistoryRun,
) -> Result<()> {
    effects::scope(simulation::World::new(seed), || {
        let fixture = Fixture::new()?;
        let material = rows(&fixture.db, "day2_credential_material")?;
        let receipts = rows(&fixture.db, "day2_credential_receipts")?;
        let mut reset_committed = false;
        for (index, action) in actions.iter().enumerate() {
            captured.step = Some(index);
            match action {
                Action::Inspect => {}
                Action::DropReset | Action::WrongEpoch => {
                    let before = snapshot(&fixture.db)?;
                    let tx =
                        Transaction::new_unchecked(&fixture.db, TransactionBehavior::Immediate)?;
                    let result = crate::oauth::restore::reset_application_in(
                        &tx,
                        &fixture.fence,
                        &fixture.authority_schema,
                        &fixture.oauth_schema,
                        &fixture.cut,
                        &fixture.namespace,
                        if matches!(action, Action::WrongEpoch) {
                            8
                        } else {
                            1
                        },
                    );
                    assert_eq!(
                        result.is_ok(),
                        matches!(action, Action::DropReset) && !reset_committed
                    );
                    if matches!(action, Action::WrongEpoch) {
                        // Even a caller that catches the error and commits the
                        // surrounding transaction cannot retain a partial cut.
                        tx.commit()?;
                    } else {
                        // A real complete reset ran, but the actual outer
                        // transaction drops before its commit or image copy.
                        drop(tx);
                    }
                    assert!(before == snapshot(&fixture.db)?);
                }
                Action::Commit => {
                    let result = reset(&fixture.db, &fixture.selection());
                    assert_eq!(result.is_ok(), !reset_committed);
                    reset_committed = true;
                }
                Action::Reopen => {
                    let before = snapshot(&fixture.db)?;
                    let image = fixture.db.serialize(MAIN_DB)?;
                    let directory = tempfile::tempdir()?;
                    let path = directory.path().join("observation.sqlite");
                    std::fs::write(&path, &*image)?;
                    for _ in 0..2 {
                        let reopened = Connection::open(&path)?;
                        assert!(before == snapshot(&reopened)?);
                        assert_eq!(
                            observation(&reopened, &fixture.token)?,
                            expected(reset_committed)
                        );
                    }
                }
            }
            let observed = observation(&fixture.db, &fixture.token)?;
            captured.actual.push(observed.clone());
            if recording == RecordingCut::AfterFirstObservation && index == 0 {
                anyhow::bail!("test_only_recorder_cut");
            }
            assert_eq!(observed, expected(reset_committed));
            assert!(material == rows(&fixture.db, "day2_credential_material")?);
            assert!(receipts == rows(&fixture.db, "day2_credential_receipts")?);
        }
        Ok(())
    })
}

fn run_history(seed: u64, actions: &[Action], recording: RecordingCut) -> HistoryRun {
    let mut captured = HistoryRun {
        step: None,
        actual: Vec::new(),
        failure: None,
    };
    // Keep the completed prefix even when setup returns Err or an assertion
    // panics. Never inspect, serialize or format the foreign error/payload.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        history(seed, actions, recording, &mut captured)
    })) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => captured.failure = Some(HistoryFailure::ReturnedError),
        Err(_) => captured.failure = Some(HistoryFailure::Panic),
    }
    captured
}

fn expected_sequence(actions: &[Action]) -> Vec<Observation> {
    let mut committed = false;
    actions
        .iter()
        .map(|action| {
            committed |= matches!(action, Action::Commit);
            expected(committed)
        })
        .collect()
}

fn implementation() -> Result<Digest> {
    Digest::of(&(
        "offline-restore-sql-histories-v1",
        std::env::consts::OS,
        std::env::consts::ARCH,
        [
            include_str!("../application.rs"),
            include_str!("tests.rs"),
            include_str!("../../restore_authority.rs"),
            include_str!("../../restore_cut.rs"),
            include_str!("../../../oauth/restore.rs"),
            include_str!("../../../oauth/schema.rs"),
            include_str!("../../../managed_credentials/restore.rs"),
            include_str!("../../../managed_credentials/store.rs"),
            include_str!("../../../managed_credentials/crypto.rs"),
            include_str!("../../../store.rs"),
            include_str!("../../../authority_state.rs"),
            include_str!("../../../budget.rs"),
            include_str!("../../../budget_reduction.rs"),
            include_str!("../../../delegation_commands.rs"),
            include_str!("../../../web_security.rs"),
            include_str!("../../../oauth/store.rs"),
            include_str!("../../../oauth/connect.rs"),
            include_str!("../../../oauth/usage.rs"),
            include_str!("../../../oauth/inbound.rs"),
            include_str!("../../kernel/restore.rs"),
            include_str!("../../../json.rs"),
            include_str!("../../../../../day2-capabilities/src/credentials.rs"),
            include_str!("../../../../../day2-capabilities/src/security_epoch.rs"),
            include_str!("../../../../../../Cargo.lock"),
            include_str!("../../../../../../Cargo.toml"),
            include_str!("../../../../../../toolchain.json"),
            include_str!("../../../../../../MODULE.bazel"),
            include_str!("../../../../../../.bazelrc"),
            include_str!("../../../../Cargo.toml"),
            include_str!("../../../../BUILD.bazel"),
            include_str!("../../../../../day2-capabilities/Cargo.toml"),
            include_str!("../../../../../day2-capabilities/BUILD.bazel"),
        ],
    ))
}

const MAX_HISTORY_BYTES: usize = 32768;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryBundle {
    format: u8,
    source: Digest,
    seed: u64,
    recording: RecordingCut,
    actions: Vec<Action>,
    expected: Vec<Observation>,
    first: HistoryRun,
    second: HistoryRun,
}

fn successful(bundle: &HistoryBundle) -> bool {
    bundle.first.failure.is_none()
        && bundle.second.failure.is_none()
        && bundle.first.actual == bundle.expected
        && bundle.second.actual == bundle.expected
        && bundle.first == bundle.second
}

fn write_history_file(path: &std::path::Path, bundle: &HistoryBundle) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = serde_json::to_vec(bundle)?;
    ensure!(
        bytes.len() <= MAX_HISTORY_BYTES,
        "offline_restore_evidence_bound"
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn private_history_directory(root: &std::path::Path) -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    Ok(tempfile::Builder::new()
        .prefix("failure-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root)?)
}

fn save_history(bundle: &HistoryBundle) -> Result<std::path::PathBuf> {
    ensure!(
        bundle.recording == RecordingCut::Ordinary,
        "recorder_control_not_campaign_evidence"
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/credential-restore-application-histories");
    std::fs::create_dir_all(&root)?;
    let directory = private_history_directory(&root)?;
    let path = directory.path().join("failure.json");
    write_history_file(&path, bundle)?;
    let _retained = directory.keep();
    Ok(path)
}

fn check_history(seed: u64, actions: &[Action]) -> Result<()> {
    ensure!(
        !actions.is_empty() && actions.len() <= 16,
        "offline_restore_action_bound"
    );
    let bundle = HistoryBundle {
        format: 1,
        source: implementation()?,
        seed,
        recording: RecordingCut::Ordinary,
        actions: actions.to_vec(),
        expected: expected_sequence(actions),
        first: run_history(seed, actions, RecordingCut::Ordinary),
        second: run_history(seed, actions, RecordingCut::Ordinary),
    };
    if !successful(&bundle) {
        let path = save_history(&bundle)?;
        anyhow::bail!(
            "offline restore history failed; seed {seed}; evidence: {}",
            path.display()
        );
    }
    Ok(())
}

fn decode_history(bytes: &[u8]) -> Result<HistoryBundle> {
    (|| -> Result<HistoryBundle> {
        ensure!(bytes.len() <= MAX_HISTORY_BYTES, "bound");
        let bundle: HistoryBundle = crate::json::decode(bytes)?;
        ensure!(
            bundle.format == 1 && bundle.source == implementation()?,
            "source"
        );
        ensure!(
            !bundle.actions.is_empty() && bundle.actions.len() <= 16,
            "actions"
        );
        ensure!(
            bundle.expected == expected_sequence(&bundle.actions),
            "oracle"
        );
        for run in [&bundle.first, &bundle.second] {
            match run.step {
                None => ensure!(
                    run.actual.is_empty() && run.failure.is_some(),
                    "setup_prefix"
                ),
                Some(i) => ensure!(
                    i < bundle.actions.len()
                        && (run.actual.len() == i || run.actual.len() == i + 1),
                    "step_prefix"
                ),
            }
            if run.failure.is_none() {
                ensure!(
                    run.actual.len() == bundle.actions.len()
                        && run.step == Some(bundle.actions.len() - 1),
                    "complete_prefix"
                );
            }
        }
        ensure!(!successful(&bundle), "not_counterexample");
        Ok(bundle)
    })()
    .map_err(|_| anyhow::anyhow!("offline_restore_replay_refused"))
}

#[derive(Debug, PartialEq, Eq)]
enum ReplayDisposition {
    FailureReproduced,
}

fn replay_history_file(path: &std::path::Path) -> Result<ReplayDisposition> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "offline_restore_replay_not_regular"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_HISTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let bundle = decode_history(&bytes)?;
    let first = run_history(bundle.seed, &bundle.actions, bundle.recording);
    let second = run_history(bundle.seed, &bundle.actions, bundle.recording);
    ensure!(
        first == bundle.first && second == bundle.second,
        "offline_restore_replay_prefix_changed"
    );
    // Exact failure reproduction is DATA, never a passing model campaign.
    Ok(ReplayDisposition::FailureReproduced)
}

fn require_requested_replay(path: &std::path::Path) -> Result<()> {
    let ReplayDisposition::FailureReproduced = replay_history_file(path)?;
    anyhow::bail!("offline_restore_requested_failure_reproduced")
}

#[test]
fn generated_offline_reset_histories_replay_twice_with_independent_terminal_expectations()
-> Result<()> {
    // These are SQL-denial histories, not retries of native effects or consumed
    // approvals. Reopen observes copied DATA; it never adopts a target/writer.
    for seed in 0..12u64 {
        let mut actions = vec![
            Action::Inspect,
            Action::DropReset,
            Action::WrongEpoch,
            Action::Reopen,
        ];
        for index in 0..8 {
            actions.push(match seed.rotate_left(index) % 5 {
                0 => Action::Inspect,
                1 => Action::DropReset,
                2 => Action::WrongEpoch,
                3 => Action::Commit,
                _ => Action::Reopen,
            });
        }
        actions.extend([Action::Commit, Action::Reopen]);
        check_history(seed, &actions)?;
    }
    // An explicitly requested replay is additional; it never skips the twelve
    // mandatory schedules. Records contain only bounded typed synthetic DATA.
    if let Some(path) = std::env::var_os("DAY2_OFFLINE_RESTORE_REPLAY") {
        require_requested_replay(std::path::Path::new(&path))?;
    }
    Ok(())
}

#[test]
fn failed_history_bundle_preserves_both_prefixes_with_strict_private_data_only() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Synthetic recorder controls only. These records are not claimed to be
    // observations of a failing reset, native owner or application artifact.
    let actions = vec![Action::Inspect; 16];
    let first = HistoryRun {
        step: Some(4),
        actual: vec![expected(false); 4],
        failure: Some(HistoryFailure::ReturnedError),
    };
    let second = HistoryRun {
        step: Some(9),
        actual: vec![expected(false); 9],
        failure: Some(HistoryFailure::Panic),
    };
    let mut bundle = HistoryBundle {
        format: 1,
        source: implementation()?,
        seed: 17,
        recording: RecordingCut::Ordinary,
        expected: expected_sequence(&actions),
        actions,
        first,
        second,
    };
    let root = tempfile::tempdir()?;
    let directory = private_history_directory(root.path())?;
    let path = directory.path().join("recorder-control.json");
    write_history_file(&path, &bundle)?;
    assert_eq!(path.metadata()?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        path.parent().unwrap().metadata()?.permissions().mode() & 0o777,
        0o700
    );
    let bytes = std::fs::read(&path)?;
    let decoded = decode_history(&bytes)?;
    assert_eq!(decoded.first, bundle.first);
    assert_eq!(decoded.second, bundle.second);
    assert!(bytes.len() <= MAX_HISTORY_BYTES);
    let marker = "OFFLINE_RESTORE_FOREIGN_PRIVATE_VALUE";
    let mut changed = serde_json::to_value(&bundle)?;
    changed
        .as_object_mut()
        .unwrap()
        .insert(marker.into(), serde_json::json!(marker));
    let refused = decode_history(&serde_json::to_vec(&changed)?)
        .err()
        .ok_or_else(|| anyhow::anyhow!("test_missing_replay_refusal"))?;
    assert_eq!(refused.to_string(), "offline_restore_replay_refused");
    let mut maximum = expected(false);
    maximum.revoked_versions = i64::MAX;
    maximum.open_deliveries = i64::MAX;
    maximum.sessions = i64::MAX;
    maximum.secrets = i64::MAX;
    bundle.first.step = Some(15);
    bundle.second.step = Some(15);
    bundle.first.actual = vec![maximum.clone(); 16];
    bundle.second.actual = vec![maximum; 16];
    let largest = serde_json::to_vec(&bundle)?;
    assert!(largest.len() <= MAX_HISTORY_BYTES);
    assert!(decode_history(&largest).is_ok());
    bundle.source = Digest::new(b"different-implementation");
    assert!(decode_history(&serde_json::to_vec(&bundle)?).is_err());
    assert!(decode_history(&vec![b' '; MAX_HISTORY_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn exact_file_replay_reports_a_real_recorder_cut_without_exporting_control_evidence() -> Result<()>
{
    let actions = vec![Action::Inspect, Action::Commit];
    let recording = RecordingCut::AfterFirstObservation;
    let first = run_history(9214, &actions, recording);
    let second = run_history(9214, &actions, recording);
    assert_eq!(first.failure, Some(HistoryFailure::ReturnedError));
    assert_eq!(first.step, Some(0));
    assert_eq!(first.actual, vec![expected(false)]);
    assert_eq!(first, second);
    let mut bundle = HistoryBundle {
        format: 1,
        source: implementation()?,
        seed: 9214,
        recording,
        expected: expected_sequence(&actions),
        actions,
        first,
        second,
    };
    assert!(save_history(&bundle).is_err());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("actual-recorder-cut.json");
    write_history_file(&path, &bundle)?;
    assert_eq!(
        replay_history_file(&path)?,
        ReplayDisposition::FailureReproduced
    );
    assert_eq!(
        require_requested_replay(&path)
            .expect_err("a reproduced failure cannot pass the campaign")
            .to_string(),
        "offline_restore_requested_failure_reproduced"
    );
    bundle.second.actual.clear();
    let altered = directory.path().join("changed-prefix.json");
    write_history_file(&altered, &bundle)?;
    assert!(replay_history_file(&altered).is_err());
    Ok(())
}
