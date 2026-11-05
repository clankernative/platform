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

type Summary = crate::oauth::restore::ApplicationResetSummary;

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
    // Begin outside admission: its SAVEPOINT belongs inside this outer TX.
    // The called concrete operation owns one cumulative rollback scope and
    // cannot return an applied-cut loan or a raw connection.
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let summary = crate::oauth::restore::reset_application_in(
        &tx,
        selected.fence,
        selected.authority_schema,
        selected.oauth_schema,
        selected.cut,
        selected.namespace,
        selected.source_epoch,
    )?;
    tx.commit()?;
    Ok(summary)
}

#[cfg(test)]
mod tests;
