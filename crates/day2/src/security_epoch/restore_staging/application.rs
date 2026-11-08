//! Complete offline denial inside the staging-owned transaction. This does not admit an archive,
//! authorize restore/copy, create a native original or return a writer.
use super::{MemoryHook, memory_shape};
use crate::security_epoch::{restore_authority, restore_cut};
use anyhow::{Result, ensure};
use day2_capabilities::credentials::Namespace;
use rusqlite::Transaction;

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

impl<'a> Selection<'a> {
    /// Immutable denial preparation only. This neither returns a file nor
    /// constructs a NativeRestore. That private entry separately consumes the
    /// actual authenticated executor and checks this exact input again.
    pub(super) fn prepared(
        namespace: &'a Namespace,
        source_epoch: u64,
        artifact: &'a crate::artifact::LoadedArtifact,
        fence: &'a restore_authority::PreparedRestoreFence,
        authority_schema: &'a restore_authority::RestoreFenceSchema,
        oauth_schema: &'a crate::oauth::restore::Profile,
        cut: &'a restore_cut::Cut,
    ) -> Result<Self> {
        artifact.require_current_api()?;
        cut.require_artifact(artifact)?;
        cut.require_credential_binding(namespace, source_epoch)?;
        Ok(Self {
            namespace,
            source_epoch,
            artifact,
            fence,
            authority_schema,
            oauth_schema,
            cut,
        })
    }

    // This compares retained immutable preparation DATA. It never supplies
    // the native owner, full-archive reader or current namespace generation.
    pub(super) fn require_native_input(
        &self,
        input: &super::Input,
        intent: &crate::security_epoch::kernel::restore::Intent,
    ) -> Result<()> {
        input.require_intent(intent)?;
        ensure!(
            self.namespace == &input.namespace && self.source_epoch == input.source_epoch,
            "native_restore_preparation_changed"
        );
        self.artifact.require_current_api()?;
        self.cut.require_artifact(self.artifact)?;
        self.cut
            .require_credential_binding(self.namespace, self.source_epoch)?;
        self.cut.require_intent(intent)?;
        Ok(())
    }

    pub(super) fn native_report(
        &self,
        input: &super::Input,
        intent: &crate::security_epoch::kernel::restore::Intent,
        projection: &super::Projection,
    ) -> Result<crate::security_epoch::kernel::restore::completion::TargetReport> {
        self.require_native_input(input, intent)?;
        ensure!(
            projection.target_incarnation == input.target_incarnation,
            "native_restore_projection_changed"
        );
        let reset_observation = day2_capabilities::Digest::of(&(
            "day2-native-complete-reset-observation-v1",
            self.cut.digest(),
            self.cut.inventory(),
            &intent.archive.full_archive_digest,
            &projection.image,
            projection.bytes,
            &projection.target_incarnation,
            &projection.reset.credentials,
            projection.reset.closed_oauth_originals,
        ))?;
        Ok(
            crate::security_epoch::kernel::restore::completion::TargetReport {
                intent: self.cut.require_intent(intent)?,
                // This existing kernel field denotes the source SQLite image,
                // while the signed approval and cut also bind the full archive.
                archive: input.database.clone(),
                target_incarnation: projection.target_incarnation.clone(),
                target_epoch: self
                    .source_epoch
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("restore_epoch_exhausted"))?,
                image: projection.image.clone(),
                schema: self.artifact.contract().schema_digest.clone().try_into()?,
                artifact: self.artifact.id().to_owned().try_into()?,
                reset_observation,
            },
        )
    }

    /// Lend only the same already-retained immutable selection; this is not a
    /// constructor from a record and supplies no native authority.
    pub(super) fn reborrow(&self) -> Selection<'_> {
        Selection {
            namespace: self.namespace,
            source_epoch: self.source_epoch,
            artifact: self.artifact,
            fence: self.fence,
            authority_schema: self.authority_schema,
            oauth_schema: self.oauth_schema,
            cut: self.cut,
        }
    }
}

pub(super) type Summary = crate::oauth::restore::ApplicationResetSummary;

pub(super) fn reset_in(
    tx: &Transaction<'_>,
    hook: &MemoryHook<'_>,
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
    selected.artifact.require_current_api()?;
    selected.cut.require_artifact(selected.artifact)?;
    ensure!(
        crate::authority_state::current(tx)?.artifact_id == selected.artifact.id(),
        "complete_restore_source_artifact_changed"
    );
    let scope = format!(
        "{}/{}/{}",
        namespace.installation.as_str(),
        namespace.environment.as_str(),
        namespace.app.as_str()
    );
    crate::store::validate_storage_in(tx, selected.artifact, &scope)?;
    // The canonical operation's cumulative admission SAVEPOINT belongs inside
    // this same outer transaction. Only prepare_image commits, serializes and
    // closes it; no applied-cut loan or raw connection can escape this call.
    crate::oauth::restore::reset_application_in(
        (tx, hook),
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
