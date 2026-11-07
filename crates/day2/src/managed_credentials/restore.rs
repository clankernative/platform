//! Atomic reset of a separately owned, unpublished restore target. This is a
//! private SQL primitive, not maintenance authority, copy permission, target
//! admission, a Runtime opener or an ordinary-restore exception.
use super::{
    CREDENTIAL_PEER_TABLES, CREDENTIAL_TABLES, install_schema, namespace_key, stage_revoke,
};
use crate::oauth::schema;
use anyhow::{Result, ensure};
use day2_capabilities::credentials::Namespace;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

const MAX_LINEAGES: usize = 1024;
const MAX_VERSIONS: i64 = 4096;

/// Counts only. No credential, material, key, permit or native owner escapes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResetSummary {
    pub lineages: usize,
    pub newly_revoked: usize,
    pub versions: u64,
}

/// Only the future restore owner may call this on its private offline target.
/// This resets only the credential unit. The staging caller must separately
/// refuse unsupported OAuth/callback/provider/companion state BEFORE copying;
/// these counts are not a complete reset report or target-admission proof.
/// The caller retains its transaction, rollback-on-error, commit/close barriers
/// and actual creator FD. This routine neither commits nor authorizes those
/// effects. Existing live Runtime hooks must never be replaced by this adapter.
pub(crate) fn stage_reset(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    source_epoch: u64,
) -> Result<ResetSummary> {
    ensure!(!tx.is_autocommit(), "restore_reset_requires_transaction");
    ensure!(
        tx.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?,
        "restore_reset_requires_foreign_keys"
    );
    namespace.validate()?;
    ensure!(source_epoch > 0, "restore_reset_source_epoch");
    let source_epoch = i64::try_from(source_epoch)?;
    let selected = namespace_key(namespace)?;
    // This adapter owns the temporary hook only on an offline target. Nested
    // schema calls share the same cumulative debit rather than renewing it.
    schema::admit(tx, |_| reset_in(tx, namespace, &selected, source_epoch))
}

fn inspect_in(
    tx: &Transaction<'_>,
    selected: &str,
    epoch: i64,
) -> Result<(Vec<String>, usize, i64)> {
    // Require a complete EXISTING unit. The installer below validates it; it
    // must never turn an absent/partial imported unit into current state.
    for table in CREDENTIAL_TABLES {
        let present: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |r| r.get(0),
        )?;
        ensure!(present, "restore_reset_existing_unit_required");
    }
    install_schema(tx)?;
    // This first profile refuses all peer history, even terminal entries. A
    // later owner-reviewed reset must invalidate pending intents explicitly.
    for table in CREDENTIAL_PEER_TABLES {
        let present: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |r| r.get(0),
        )?;
        if present {
            let occupied: bool = tx.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM main.{table})"),
                [],
                |r| r.get(0),
            )?;
            ensure!(!occupied, "restore_reset_peer_history_unsupported");
        }
    }
    let mut query = tx.prepare(
        "SELECT id,namespace,security_epoch,state FROM day2_credential_lineages ORDER BY id",
    )?;
    let mut rows = query.query([])?;
    let mut active = Vec::new();
    let mut lineages = 0usize;
    while let Some(row) = rows.next()? {
        schema::materialize(row)?;
        lineages += 1;
        ensure!(lineages <= MAX_LINEAGES, "restore_reset_lineage_bound");
        ensure!(
            row.get_ref(1)?.as_str()? == selected && row.get::<_, i64>(2)? == epoch,
            "restore_reset_namespace_or_epoch_changed"
        );
        if row.get_ref(3)?.as_str()? == "active" {
            active.push(row.get::<_, String>(0)?);
        }
    }
    drop(rows);
    drop(query);
    let versions: i64 = tx.query_row("SELECT count(*) FROM day2_credential_versions", [], |r| {
        r.get(0)
    })?;
    ensure!(
        (0..=MAX_VERSIONS).contains(&versions),
        "restore_reset_version_bound"
    );
    let wrong_versions:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_credential_versions v JOIN day2_credential_lineages l ON l.id=v.lineage WHERE v.security_epoch!=?1 OR l.namespace!=?2)",params![epoch,selected],|r|r.get(0))?;
    ensure!(!wrong_versions, "restore_reset_version_binding_changed");
    Ok((active, lineages, versions))
}

/// Read-only qualification of the actual archive BEFORE any target creation.
/// No permission, key readiness or native witness is returned. Admission is
/// validation-only for a complete existing unit, including on read-only SQLite.
pub(crate) fn inspect_source(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    source_epoch: u64,
) -> Result<()> {
    namespace.validate()?;
    ensure!(
        !tx.is_autocommit() && source_epoch > 0,
        "restore_source_snapshot_required"
    );
    ensure!(
        tx.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))?,
        "restore_reset_requires_foreign_keys"
    );
    let selected = namespace_key(namespace)?;
    let epoch = i64::try_from(source_epoch)?;
    schema::admit(tx, |_| {
        inspect_in(tx, &selected, epoch)?;
        Ok(())
    })
}

fn reset_in(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    selected: &str,
    epoch: i64,
) -> Result<ResetSummary> {
    let (active, lineages, versions) = inspect_in(tx, selected, epoch)?;
    // No epoch, grant, selector, verifier, custody envelope, receipt or origin
    // is rewritten. Reuse the canonical active->revoked transition exactly.
    for lineage in &active {
        ensure!(
            stage_revoke(tx, namespace, lineage)?,
            "restore_reset_lineage_changed"
        );
    }
    install_schema(tx)?;
    let unreset:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_credential_lineages WHERE state!='revoked') OR EXISTS(SELECT 1 FROM day2_credential_versions WHERE state!='revoked') OR EXISTS(SELECT 1 FROM day2_credential_deliveries WHERE state!='closed')",[],|r|r.get(0))?;
    ensure!(!unreset, "restore_reset_terminal_postcondition");
    Ok(ResetSummary {
        lineages,
        newly_revoked: active.len(),
        versions: versions.try_into()?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests as fixture;
    use super::super::*;
    use super::*;
    use rusqlite::{Connection, TransactionBehavior};

    fn database() -> Result<(tempfile::TempDir, Connection, PublicReceipt)> {
        let (dir, mut db) = fixture::database()?;
        db.pragma_update(None, "foreign_keys", true)?;
        let receipt = fixture::committed_issue(&mut db)?;
        Ok((dir, db, receipt))
    }

    #[test]
    fn real_reset_revokes_once_without_retagging_or_committing() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1904),
            || {
                let (dir, mut db, receipt) = database()?;
                let before: (String, Vec<u8>, Vec<u8>) = db.query_row(
                    "SELECT identity_json,nonce,ciphertext FROM day2_credential_material",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let first = stage_reset(&tx, &fixture::namespace(), 7)?;
                assert_eq!(
                    first,
                    ResetSummary {
                        lineages: 1,
                        newly_revoked: 1,
                        versions: 1
                    }
                );
                assert!(!tx.is_autocommit());
                assert_eq!(stage_reset(&tx, &fixture::namespace(), 7)?.newly_revoked, 0);
                assert_eq!(
                    tx.query_row("SELECT revision FROM day2_credential_lineages", [], |r| r
                        .get::<_, i64>(
                        0
                    ))?,
                    2
                );
                tx.commit()?;
                drop(db);
                let db = Connection::open(dir.path().join("app.sqlite"))?;
                let after: (String, Vec<u8>, Vec<u8>) = db.query_row(
                    "SELECT identity_json,nonce,ciphertext FROM day2_credential_material",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                assert!(before == after, "restore reset changed custody bytes");
                assert_eq!(
                    db.query_row(
                        "SELECT security_epoch FROM day2_credential_versions",
                        [],
                        |r| r.get::<_, i64>(0)
                    )?,
                    7
                );
                assert_eq!(
                    db.query_row("SELECT state FROM day2_credential_versions", [], |r| r
                        .get::<_, String>(
                        0
                    ))?,
                    "revoked"
                );
                assert!(crate::store::require_no_managed_credential_restore_state(&db).is_err());
                assert!(!receipt.lineage.is_empty());
                Ok(())
            },
        )
    }

    #[test]
    fn wrong_scope_or_epoch_refuses_before_any_row_change() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1905),
            || {
                for foreign in [false, true] {
                    let (_dir, mut db, _) = database()?;
                    let mut ns = fixture::namespace();
                    if foreign {
                        ns.binding_generation += 1;
                    }
                    let tx = db.transaction()?;
                    assert!(stage_reset(&tx, &ns, if foreign { 7 } else { 8 }).is_err());
                    assert_eq!(
                        tx.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                            .get::<_, String>(
                            0
                        ))?,
                        "active"
                    );
                    assert_eq!(
                        tx.query_row("SELECT revision FROM day2_credential_lineages", [], |r| r
                            .get::<_, i64>(
                            0
                        ))?,
                        1
                    );
                    tx.rollback()?;
                }
                Ok(())
            },
        )
    }

    #[test]
    fn drop_rolls_back_the_real_reset_and_absent_schema_is_not_installed() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1906),
            || {
                let (_dir, mut db, _) = database()?;
                {
                    let tx = db.transaction()?;
                    stage_reset(&tx, &fixture::namespace(), 7)?;
                }
                assert_eq!(
                    db.query_row("SELECT state FROM day2_credential_lineages", [], |r| r
                        .get::<_, String>(
                        0
                    ))?,
                    "active"
                );
                let mut empty = Connection::open_in_memory()?;
                empty.pragma_update(None, "foreign_keys", true)?;
                let tx = empty.transaction()?;
                assert!(stage_reset(&tx, &fixture::namespace(), 7).is_err());
                assert_eq!(
                    tx.query_row("SELECT count(*) FROM sqlite_master", [], |r| r
                        .get::<_, i64>(0))?,
                    0
                );
                Ok(())
            },
        )
    }

    fn reveal(
        db: &mut Connection,
        version: &str,
        attempt: &str,
    ) -> Result<zeroize::Zeroizing<String>> {
        let post = VerifiedHumanPost {
            namespace: fixture::namespace(),
            version: version.into(),
            recipient: "issuer/human-1".into(),
            session: "session-1".into(),
            attempt: attempt.into(),
            now: 1100,
            security_epoch: 7,
        };
        Ok(zeroize::Zeroizing::new(
            authorize_reveal(db, post)?
                .ok_or_else(|| anyhow::anyhow!("fixture_delivery_missing"))?
                .into_response_body(&fixture::lease())?,
        ))
    }

    #[test]
    fn actual_rotated_tokens_and_reveal_stay_refused_after_reset_and_reopen() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1910),
            || {
                let (dir, mut db, first) = database()?;
                let old = reveal(&mut db, first.version.as_ref().unwrap(), "restore-old")?;
                let grant = fixture::issue("unused").ceiling;
                let ns = fixture::namespace();
                let family = fixture::family();
                let operation = &grant.roots["SubmitTranscription"];
                let accepts = |db: &Connection, token: &str| -> Result<bool> {
                    Ok(verify_ingress(
                        db,
                        &fixture::lease(),
                        IngressVerification {
                            namespace: &ns,
                            family: family.id.as_str(),
                            family_contract: &family.contract,
                            security_epoch: 7,
                            now: 1100,
                            operation,
                        },
                        token,
                    )?
                    .is_some())
                };
                assert!(accepts(&db, &old)?);
                let tx = db.transaction()?;
                let current = match stage_rotation(
                    &tx,
                    &fixture::lease(),
                    &fixture::snapshot(&first),
                    RotationIntent {
                        invocation: "restore-rotation",
                        instruction_slot: 0,
                        recipient: "issuer/human-1",
                        session: "session-1",
                        issued_at: 1100,
                        expires_at: 2100,
                        reveal_until: 1400,
                        grant: &grant,
                    },
                )? {
                    RotationResult::Rotated(pending) => pending.public_identity().clone(),
                    RotationResult::Conflict => anyhow::bail!("fixture_rotation_conflict"),
                };
                tx.commit()?;
                let current_token = reveal(
                    &mut db,
                    current.version.as_ref().unwrap(),
                    "restore-current",
                )?;
                assert!(!accepts(&db, &old)?);
                assert!(accepts(&db, &current_token)?);
                let tx = db.transaction()?;
                assert_eq!(stage_reset(&tx, &ns, 7)?.versions, 2);
                tx.commit()?;
                drop(db);
                let mut db = Connection::open(dir.path().join("app.sqlite"))?;
                assert!(!accepts(&db, &old)?);
                assert!(!accepts(&db, &current_token)?);
                let post = VerifiedHumanPost {
                    namespace: ns.clone(),
                    version: current.version.unwrap(),
                    recipient: "issuer/human-1".into(),
                    session: "session-1".into(),
                    attempt: "after-reset".into(),
                    now: 1100,
                    security_epoch: 7,
                };
                assert!(authorize_reveal(&mut db, post)?.is_none());
                assert_eq!(db.query_row("SELECT count(*) FROM day2_credential_versions WHERE state='revoked' AND security_epoch=7",[],|r|r.get::<_,i64>(0))?,2);
                Ok(())
            },
        )
    }

    #[test]
    fn existing_terminal_history_is_byte_exact_and_business_rows_survive() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1911),
            || {
                let (_dir, mut db, first) = database()?;
                db.execute_batch("CREATE TABLE restore_business(value TEXT) STRICT; INSERT INTO restore_business VALUES('keep-business-data');")?;
                let tx = db.transaction()?;
                assert!(stage_revoke(&tx, &fixture::namespace(), &first.lineage)?);
                tx.commit()?;
                let before = fixture::database_snapshot(&db)?;
                let tx = db.transaction()?;
                assert_eq!(stage_reset(&tx, &fixture::namespace(), 7)?.newly_revoked, 0);
                tx.commit()?;
                assert!(
                    before == fixture::database_snapshot(&db)?,
                    "terminal reset changed retained history"
                );
                Ok(())
            },
        )
    }

    #[test]
    fn occupied_peers_incomplete_schema_and_disabled_foreign_keys_refuse_unchanged() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1912),
            || {
                for fault in 0..4 {
                    let (_directory, mut db) = if fault == 0 {
                        (None, fixture::restored_peer_database()?)
                    } else {
                        let (dir, db) = fixture::database()?;
                        (Some(dir), db)
                    };
                    if fault == 1 {
                        db.execute_batch("PRAGMA foreign_keys=OFF;")?;
                    } else {
                        db.pragma_update(None, "foreign_keys", true)?;
                    }
                    if fault == 2 {
                        db.execute_batch("DROP TRIGGER day2_credential_versions_shape_UPDATE_v2;")?;
                    }
                    if fault == 3 {
                        db.execute_batch("UPDATE day2_credential_schema_version SET version=99;")?;
                    }
                    let before = fixture::database_snapshot(&db)?;
                    let tx = db.transaction()?;
                    assert!(stage_reset(&tx, &fixture::namespace(), 7).is_err());
                    tx.rollback()?;
                    assert!(
                        before == fixture::database_snapshot(&db)?,
                        "refusal modified imported state"
                    );
                }
                Ok(())
            },
        )
    }

    #[test]
    fn caller_sql_constraint_after_reset_rolls_back_the_complete_unit() -> Result<()> {
        super::super::super::effects::scope(
            super::super::super::simulation::World::new(1913),
            || {
                let (_dir, mut db, _) = database()?;
                db.execute_batch("CREATE TABLE restore_cut(value INTEGER UNIQUE); INSERT INTO restore_cut VALUES(1);")?;
                let before = fixture::database_snapshot(&db)?;
                let tx = db.transaction()?;
                stage_reset(&tx, &fixture::namespace(), 7)?;
                let failure = tx
                    .execute("INSERT INTO restore_cut VALUES(1)", [])
                    .unwrap_err();
                assert_eq!(
                    failure.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::ConstraintViolation)
                );
                tx.rollback()?;
                assert!(
                    before == fixture::database_snapshot(&db)?,
                    "post-reset failure committed partial state"
                );
                Ok(())
            },
        )
    }
}
