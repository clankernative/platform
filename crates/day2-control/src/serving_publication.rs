//! Activation's durable publication intent. Remote writes remain outside SQLite.
use crate::{Digest, journal::Journal, release::ReleaseTarget, serving_snapshot::ServingSnapshot};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};

pub struct Publication {
    pub revision: u64,
    pub digest: Digest,
    pub snapshot: ServingSnapshot,
    scope: String,
}

fn scope(target: &ReleaseTarget) -> Result<String> {
    Ok(serde_json::to_string(&(
        &target.company,
        &target.environment,
    ))?)
}

impl Publication {
    pub fn require_scope(&self, target: &ReleaseTarget) -> Result<()> {
        ensure!(self.scope == scope(target)?, "publication_scope_changed");
        Ok(())
    }
}

pub(crate) fn enqueue_in(tx: &Transaction<'_>, target: &ReleaseTarget) -> Result<()> {
    tx.execute(
        "INSERT INTO release_serving_publications(scope,revision) VALUES(?1,1)
         ON CONFLICT(scope) DO UPDATE SET revision=revision+1",
        [scope(target)?],
    )?;
    Ok(())
}

impl Journal {
    pub fn serving_publication_is_current(&self, publication: &Publication) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT revision=?2 FROM release_serving_publications WHERE scope=?1",
            params![publication.scope, i64::try_from(publication.revision)?],
            |row| row.get(0),
        )?)
    }

    pub fn serving_publication(&self, targets: &[ReleaseTarget]) -> Result<Publication> {
        let first = targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("publication_targets_missing"))?;
        let scope = scope(first)?;
        ensure!(
            targets
                .iter()
                .all(|target| target.company == first.company
                    && target.environment == first.environment),
            "publication_scope_changed"
        );
        let tx = self.connection.unchecked_transaction()?;
        let revision: i64 = tx.query_row(
            "SELECT revision FROM release_serving_publications WHERE scope=?1",
            [&scope],
            |row| row.get(0),
        )?;
        let snapshot = self.serving_snapshot_in(&tx, targets)?;
        let digest = Digest::of(&snapshot)?;
        tx.commit()?;
        Ok(Publication {
            revision: u64::try_from(revision)?,
            digest,
            snapshot,
            scope,
        })
    }

    /// A stale acknowledgment cannot erase a newer activation's publication.
    pub fn acknowledge_serving_publication(&mut self, publication: &Publication) -> Result<bool> {
        Ok(self.connection.execute(
            "UPDATE release_serving_publications SET published_revision=?2,published_digest=?3
             WHERE scope=?1 AND revision=?2",
            params![
                publication.scope,
                i64::try_from(publication.revision)?,
                publication.digest.as_str()
            ],
        )? == 1)
    }

    pub fn serving_publication_pending(&self, target: &ReleaseTarget) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT revision>published_revision FROM release_serving_publications WHERE scope=?1",
            [scope(target)?], |row| row.get::<_, bool>(0),
        ).optional()?.unwrap_or(false))
    }
}
