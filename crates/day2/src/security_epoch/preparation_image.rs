//! Frozen initial SQLite image DATA for the original-descriptor preparation
//! protocol. These bytes carry no file, controller, durability or P3 authority.
//! The native creator must keep its actual original file, authorize every I/O,
//! persist this exact image and read it back before using the decoder below.

use super::native_clock::NativeAcquisition;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use rusqlite::{Connection, MAIN_DB};

const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCHEMA_DEFINITIONS: usize = 4096;
const MAX_SCHEMA_BYTES: usize = 8 * 1024 * 1024;

/// An owned, immutable copy: a SQLite NOCOPY view cannot outlive this snapshot
/// or change after a later write to the source connection. No native authority
/// can be reconstructed from an image or its schema digest.
pub(super) struct FrozenPreparationImage {
    bytes: Vec<u8>,
    schema: Digest,
}

impl FrozenPreparationImage {
    /// The caller must have initialized the complete admitted framework/app
    /// schema and seed/marker in one committed transaction. This function only
    /// freezes DATA; it does not admit that schema or authorize file creation.
    pub(super) fn freeze(
        connection: &Connection,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
        acquisition.remaining()?;
        ensure!(connection.is_autocommit(), "epoch_preparation_uncommitted_image");
        ensure!(
            connection.path().is_none_or(str::is_empty),
            "epoch_preparation_memory_image_required"
        );
        let mut databases = connection.prepare("PRAGMA database_list")?;
        let mut rows = databases.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            let file: String = row.get(2)?;
            ensure!(
                matches!(name.as_str(), "main" | "temp") && file.is_empty(),
                "epoch_preparation_attached_database_refused"
            );
        }
        let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        ensure!(mode == "memory", "epoch_preparation_initial_journal_mode");
        let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        ensure!(pages > 0 && page_size > 0, "epoch_preparation_empty_image");
        let expected = usize::try_from(pages)?
            .checked_mul(usize::try_from(page_size)?)
            .ok_or_else(|| anyhow::anyhow!("epoch_preparation_image_bound"))?;
        ensure!(expected <= MAX_IMAGE_BYTES, "epoch_preparation_image_bound");
        let schema = schema_contract(connection)?;
        acquisition.remaining()?;
        let data = connection.serialize(MAIN_DB)?;
        ensure!(data.len() == expected, "epoch_preparation_image_length");
        ensure!(
            data.len() >= 100
                && &data[..16] == b"SQLite format 3\0"
                && data[18] == 1
                && data[19] == 1,
            "epoch_preparation_initial_image_format"
        );
        let bytes = data.to_vec();
        drop(data);
        acquisition.remaining()?;
        Ok(Self { bytes, schema })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn schema(&self) -> &Digest {
        &self.schema
    }

    /// Parse only complete, immutable bytes already proven equal to the trusted
    /// generated image. The caller remains responsible for reading through the
    /// held original descriptor, native rechecks and exact seed/marker binding.
    pub(super) fn decode_exact_readback(
        &self,
        readback: &[u8],
        acquisition: &mut NativeAcquisition,
    ) -> Result<Connection> {
        let result = (|| {
        acquisition.remaining()?;
        ensure!(readback == self.bytes, "epoch_preparation_image_readback_mismatch");
        let mut decoded = Connection::open_in_memory()?;
        decoded.pragma_update(None, "temp_store", "MEMORY")?;
        // Safe pinned API over an already verified, complete immutable slice;
        // never a live descriptor, uncertain input or WAL-header repair.
        decoded.deserialize_read_exact(MAIN_DB, readback, readback.len(), true)?;
        ensure!(
            schema_contract(&decoded)? == self.schema,
            "epoch_preparation_schema_readback_mismatch"
        );
        let integrity: String = decoded.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "epoch_preparation_image_integrity");
        acquisition.remaining()?;
        Ok(decoded)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }
}

/// Hash schema definitions, excluding all database values and generated IDs.
/// The selected contract must be derived from the admitted initialization path;
/// hashing an arbitrary existing database never makes its schema admitted.
pub(super) fn schema_contract(connection: &Connection) -> Result<Digest> {
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name",
    )?;
    let mut rows = statement.query([])?;
    let mut definitions = Vec::new();
    let mut size = 0_usize;
    while let Some(row) = rows.next()? {
        ensure!(
            definitions.len() < MAX_SCHEMA_DEFINITIONS,
            "epoch_preparation_schema_bound"
        );
        let definition: (String, String, String, Option<String>) =
            (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
        for value in [
            Some(definition.0.as_str()),
            Some(definition.1.as_str()),
            Some(definition.2.as_str()),
            definition.3.as_deref(),
        ].into_iter().flatten() {
            size = size.checked_add(value.len())
                .ok_or_else(|| anyhow::anyhow!("epoch_preparation_schema_bound"))?;
        }
        ensure!(size <= MAX_SCHEMA_BYTES, "epoch_preparation_schema_bound");
        definitions.push(definition);
    }
    ensure!(!definitions.is_empty(), "epoch_preparation_empty_schema");
    Digest::of(&("day2-initial-framework-schema-v1", definitions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn acquisition() -> NativeAcquisition {
        NativeAcquisition::fixture(
            Digest::new(b"image-test-clock"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        )
    }

    fn database() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE initial_marker(seed TEXT PRIMARY KEY); INSERT INTO initial_marker VALUES('original');").unwrap();
        db
    }

    #[test]
    fn frozen_image_survives_source_mutation_and_readback_is_read_only() {
        let db = database();
        let image = FrozenPreparationImage::freeze(&db, &mut acquisition()).unwrap();
        db.execute("UPDATE initial_marker SET seed='replacement'", []).unwrap();
        drop(db);
        let restored = image.decode_exact_readback(image.bytes(), &mut acquisition()).unwrap();
        let seed: String = restored.query_row("SELECT seed FROM initial_marker", [], |row| row.get(0)).unwrap();
        assert_eq!(seed, "original");
        assert!(restored.execute("UPDATE initial_marker SET seed='wrong'", []).is_err());
        let mut corrupt = image.bytes().to_vec();
        corrupt[18] = 2;
        assert!(image.decode_exact_readback(&corrupt, &mut acquisition()).is_err());
    }

    #[test]
    fn schema_contract_excludes_values_and_changes_with_definitions() {
        let db = database();
        let original = schema_contract(&db).unwrap();
        db.execute("UPDATE initial_marker SET seed='another-incarnation'", []).unwrap();
        assert_eq!(schema_contract(&db).unwrap(), original);
        db.execute_batch("CREATE TABLE other_definition(value INTEGER NOT NULL)").unwrap();
        assert_ne!(schema_contract(&db).unwrap(), original);
    }

    #[test]
    fn uncommitted_or_attached_or_expired_images_refuse() {
        let mut db = database();
        let tx = db.transaction().unwrap();
        assert!(FrozenPreparationImage::freeze(&tx, &mut acquisition()).is_err());
        tx.rollback().unwrap();
        db.execute_batch("ATTACH ':memory:' AS other").unwrap();
        assert!(FrozenPreparationImage::freeze(&db, &mut acquisition()).is_err());
        let db = database();
        let mut expired = NativeAcquisition::fixture(
            Digest::new(b"expired-image-clock"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::ZERO,
        );
        assert!(FrozenPreparationImage::freeze(&db, &mut expired).is_err());
    }
}
