//! Atomic reset of a separately owned, unpublished restore target. This is a
//! private SQL primitive, not maintenance authority, copy permission, target
//! admission, a Runtime opener or an ordinary-restore exception.
use super::{
    CREDENTIAL_PEER_TABLES, CREDENTIAL_TABLES, install_schema, namespace_key, stage_revoke,
};
#[cfg(test)]
use super::{
    IngressVerification, PublicReceipt, VerifiedHumanPost, authorize_reveal, prepare_issue,
    stage_issue, verify_ingress,
};
use crate::oauth::schema;
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::credentials::Namespace;
#[cfg(test)]
use rusqlite::Connection;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};

const MAX_LINEAGES: usize = 1024;
const MAX_VERSIONS: i64 = 4096;

enum PeerAdmission<'proof, 'db> {
    Empty,
    Closed(&'proof crate::security_epoch::restore_authority::ClosedCredentialPeers<'db>),
}

impl PeerAdmission<'_, '_> {
    fn require(&self, tx: &Transaction<'_>, namespace: &Namespace, epoch: i64) -> Result<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Closed(context) => context.require(tx, namespace, u64::try_from(epoch)?),
        }
    }
}

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
    stage_with_peers(tx, namespace, source_epoch, PeerAdmission::Empty)
}

/// Complete-application denial profile only. Unlike the credential-only entry,
/// historical peers may remain after the same transaction's authority and
/// OAuth cuts. No pending record is reissued, migrated or used as permission.
pub(crate) fn stage_closed_reset(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    source_epoch: u64,
    peers: &crate::security_epoch::restore_authority::ClosedCredentialPeers<'_>,
) -> Result<ResetSummary> {
    stage_with_peers(tx, namespace, source_epoch, PeerAdmission::Closed(peers))
}

fn stage_with_peers(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    source_epoch: u64,
    peers: PeerAdmission<'_, '_>,
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
    schema::admit(tx, |_| {
        reset_in(tx, namespace, &selected, source_epoch, &peers)
    })
}

fn inspect_in(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    selected: &str,
    epoch: i64,
    peers: &PeerAdmission<'_, '_>,
) -> Result<(Vec<String>, usize, i64)> {
    peers.require(tx, namespace, epoch)?;
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
    #[cfg(test)]
    note_work(tx, "credential_pre_before");
    let installed = install_schema(tx);
    #[cfg(test)]
    note_work(tx, "credential_pre_after");
    installed.context("restore_credential_pre_admission")?;
    // The credential-only profile still refuses all peer history. The complete
    // profile has already proved both cuts on this same transaction; the actual
    // installer above still validates every retained peer row and relationship.
    if matches!(peers, PeerAdmission::Empty) {
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
        inspect_in(tx, namespace, &selected, epoch, &PeerAdmission::Empty)?;
        Ok(())
    })
}

fn reset_in(
    tx: &Transaction<'_>,
    namespace: &Namespace,
    selected: &str,
    epoch: i64,
    peers: &PeerAdmission<'_, '_>,
) -> Result<ResetSummary> {
    let (active, lineages, versions) = inspect_in(tx, namespace, selected, epoch, peers)?;
    // No epoch, grant, selector, verifier, custody envelope, receipt or origin
    // is rewritten. Reuse the canonical active->revoked transition exactly.
    #[cfg(test)]
    note_work(tx, "credential_revoke_before");
    for lineage in &active {
        ensure!(
            stage_revoke(tx, namespace, lineage)?,
            "restore_reset_lineage_changed"
        );
    }
    #[cfg(test)]
    note_work(tx, "credential_revoke_after");
    let installed = install_schema(tx);
    #[cfg(test)]
    note_work(tx, "credential_post_after");
    installed.context("restore_credential_post_admission")?;
    let unreset:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM day2_credential_lineages WHERE state!='revoked') OR EXISTS(SELECT 1 FROM day2_credential_versions WHERE state!='revoked') OR EXISTS(SELECT 1 FROM day2_credential_deliveries WHERE state!='closed')",[],|r|r.get(0))?;
    ensure!(!unreset, "restore_reset_terminal_postcondition");
    peers.require(tx, namespace, epoch)?;
    Ok(ResetSummary {
        lineages,
        newly_revoked: active.len(),
        versions: versions.try_into()?,
    })
}

#[cfg(test)]
fn note_work(db: &Connection, step: &'static str) {
    eprintln!(
        "restore_test_work step={step} remaining={:?}",
        schema::remaining_work_for_tests(db)
    );
}

/// Create genuine encrypted epoch-one material through the ordinary store
/// functions. The test selection is synthetic, not native or human authority.
#[cfg(test)]
pub(crate) fn seed_first_epoch_for_tests(
    db: &mut dyn crate::write_queue::ConnectionOwner,
) -> Result<(PublicReceipt, zeroize::Zeroizing<String>)> {
    let mut intent = super::tests::issue("invocation-1");
    intent.security_epoch = 1;
    let prepared = prepare_issue(&super::tests::lease(), &super::tests::family(), intent)?;
    let tx = db.transaction()?;
    let receipt = stage_issue(&tx, prepared)?.public_identity().clone();
    tx.commit()?;
    let post = VerifiedHumanPost {
        namespace: super::tests::namespace(),
        version: receipt.version.clone().context("fixture_version")?,
        recipient: "issuer/human-1".into(),
        session: "session-1".into(),
        attempt: "before-restore".into(),
        now: 1100,
        security_epoch: 1,
    };
    let token = authorize_reveal(db, post)?
        .context("fixture_delivery_missing")?
        .into_response_body(&super::tests::lease())?;
    Ok((receipt, zeroize::Zeroizing::new(token)))
}

#[cfg(test)]
pub(crate) fn first_epoch_ingress_for_tests(
    db: &Connection,
    token: &str,
    current_epoch: u64,
) -> Result<bool> {
    let grant = super::tests::issue("unused").ceiling;
    let family = super::tests::family();
    Ok(verify_ingress(
        db,
        &super::tests::lease(),
        IngressVerification {
            namespace: &super::tests::namespace(),
            family: family.id.as_str(),
            family_contract: &family.contract,
            security_epoch: current_epoch,
            now: 1100,
            operation: &grant.roots["SubmitTranscription"],
        },
        token,
    )?
    .is_some())
}

/// Canonical stored-record conformance DATA only. This seed contains no
/// authentication signature and cannot construct a native or human owner.
#[cfg(test)]
pub(crate) fn seed_historical_peers_for_tests(
    db: &rusqlite::Connection,
    scope: &str,
    authority: &crate::authority_state::AuthorityStamp,
    artifact: &str,
    source_epoch: u64,
) -> Result<(String, String)> {
    let source = super::tests::restored_peer_database()?;
    let raw: String =
        source.query_row("SELECT intent FROM day2_credential_browser", [], |row| {
            row.get(0)
        })?;
    let mut pending: super::super::browser::Pending = crate::json::decode(raw.as_bytes())?;
    pending.authority = authority.clone();
    pending.artifact = artifact.into();
    let raw: String = source.query_row(
        "SELECT confirmation FROM day2_credential_confirmations",
        [],
        |row| row.get(0),
    )?;
    let record = super::super::issuance::decode_record(&pending.invocation, raw.as_bytes())?;
    let mut confirmation = record.confirmation;
    confirmation.authority = authority.clone();
    confirmation.artifact = artifact.into();
    confirmation.security_epoch = source_epoch;
    let super::super::issuance::ConfirmationOrigin::Credential(mut original) = record.original
    else {
        anyhow::bail!("test_expected_credential_history")
    };
    original.scope = scope.into();
    original.app = scope
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow::anyhow!("test_scope"))?
        .into();
    original.artifact = artifact.into();
    original.pending_challenge = pending.challenge()?;
    let pending_json = serde_json::to_string(&pending)?;
    let confirmation_json = super::super::issuance::encode_record(
        confirmation,
        super::super::issuance::ConfirmationOrigin::Credential(original),
    )?;
    super::super::issuance::install(db)?;
    db.execute(
        "INSERT INTO day2_credential_browser VALUES(?1,?2,?3,?4)",
        params![
            pending.invocation,
            pending.attempt,
            pending_json,
            pending.expires_at
        ],
    )?;
    db.execute(
        "INSERT INTO day2_credential_confirmations VALUES(?1,?2)",
        params![pending.invocation, confirmation_json],
    )?;
    Ok((pending_json, confirmation_json))
}

#[cfg(test)]
mod tests {
    use super::super::tests as fixture;
    use super::super::*;
    use super::*;
    use rusqlite::{Connection, TransactionBehavior};

    fn database() -> Result<(
        tempfile::TempDir,
        crate::oauth::schema::RawAdmissionDatabase,
        PublicReceipt,
    )> {
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
                let db = crate::oauth::schema::RawAdmissionDatabase::open(
                    dir.path().join("app.sqlite"),
                )?;
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
                let mut empty = crate::oauth::schema::RawAdmissionDatabase::open_in_memory()?;
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
        db: &mut dyn crate::write_queue::ConnectionOwner,
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
                let mut db = crate::oauth::schema::RawAdmissionDatabase::open(
                    dir.path().join("app.sqlite"),
                )?;
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
