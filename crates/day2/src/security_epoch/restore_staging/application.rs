//! One atomic offline denial transaction. This does not admit an archive,
//! authorize restore/copy, create a native original or return a writer.
use super::*;
use crate::security_epoch::{restore_authority, restore_cut};

/// All selection/entropy/reference preparation precedes this SQL-only unit.
/// The future accepting caller separately retains actual approval/exclusion,
/// complete artifact/model admission and the same creator-file owner.
struct Selection<'a> {
    namespace: &'a Namespace,
    source_epoch: u64,
    fence: &'a restore_authority::PreparedRestoreFence,
    authority_schema: &'a restore_authority::RestoreFenceSchema,
    oauth_schema: &'a crate::oauth::restore::Profile,
    cut: &'a restore_cut::Cut,
}

struct Summary {
    credentials: ResetSummary,
    closed_oauth_originals: usize,
}

fn reset(db: &Connection, selected: &Selection<'_>) -> Result<Summary> {
    ensure!(
        db.is_autocommit(),
        "complete_restore_requires_owned_transaction"
    );
    memory_shape(db, None)?;
    ensure!(
        db.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?
            && db.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?
                == "memory",
        "complete_restore_memory_configuration_required"
    );
    // A single cumulative admission covers every canonical validator and
    // revocation. No imported schema is initialized, upgraded or repaired.
    crate::oauth::schema::admit(db, |db| {
        // The outer borrow deliberately owns the admission scope. SQLite
        // checks transaction exclusivity; this value owns rollback on error.
        let mut tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        let before = crate::oauth::restore::Snapshot::capture(&tx, selected.oauth_schema)?;
        selected.fence.apply_in(&tx, selected.authority_schema)?;
        let applied =
            crate::oauth::restore::apply_in(&mut tx, before, selected.cut, selected.oauth_schema)?;
        let credentials = applied.stage_closed_credentials(
            selected.fence,
            selected.namespace,
            selected.source_epoch,
        )?;
        let closed_oauth_originals = applied.closed_count();
        // End the actual transaction loan before its sole outer commit.
        drop(applied);
        tx.commit()?;
        Ok(Summary {
            credentials,
            closed_oauth_originals,
        })
    })
}
