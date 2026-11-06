//! Complete offline denial inside the staging-owned transaction. This does not admit an archive,
//! authorize restore/copy, create a native original or return a writer.
use super::*;
use crate::security_epoch::{restore_authority, restore_cut};

/// All selection/entropy/reference preparation precedes this SQL-only unit.
/// The future accepting caller separately retains actual approval/exclusion,
/// complete artifact/model admission and the same creator-file owner.
pub(super) struct Selection<'a> {
    namespace: &'a Namespace,
    source_epoch: u64,
    artifact: &'a crate::artifact::LoadedArtifact,
    fence: &'a restore_authority::PreparedRestoreFence,
    authority_schema: &'a restore_authority::RestoreFenceSchema,
    oauth_schema: &'a crate::oauth::restore::Profile,
    cut: &'a restore_cut::Cut,
}

pub(super) type Summary = crate::oauth::restore::ApplicationResetSummary;

pub(super) fn reset_in(
    tx: &Transaction<'_>,
    selected: &Selection<'_>,
    namespace: &Namespace,
    source_epoch: u64,
) -> Result<Summary> {
    ensure!(
        !tx.is_autocommit(),
        "complete_restore_requires_owned_transaction"
    );
    ensure!(
        selected.namespace == namespace && selected.source_epoch == source_epoch,
        "complete_restore_staging_input_changed"
    );
    memory_shape(tx, None)?;
    ensure!(
        tx.pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))?
            && tx.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?
                == "memory",
        "complete_restore_memory_configuration_required"
    );
    selected.cut.require_artifact(selected.artifact)?;
    ensure!(
        crate::authority_state::current(tx)?.artifact_id == selected.artifact.id(),
        "complete_restore_source_artifact_changed"
    );
    let scope = format!("{}/{}/{}",namespace.installation.as_str(),namespace.environment.as_str(),namespace.app.as_str());
    crate::store::validate_storage_in(tx,selected.artifact,&scope)?;
    // The canonical operation's cumulative admission SAVEPOINT belongs inside
    // this same outer transaction. Only prepare_image commits, serializes and
    // closes it; no applied-cut loan or raw connection can escape this call.
    crate::oauth::restore::reset_application_in(
        tx,
        selected.fence,
        selected.authority_schema,
        selected.oauth_schema,
        selected.cut,
        selected.namespace,
        selected.source_epoch,
    )
}

#[cfg(test)]
pub(super) mod tests;
