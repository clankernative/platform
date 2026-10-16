//! Frozen initial SQLite image DATA for the original-descriptor preparation
//! protocol. These bytes carry no file, controller, durability or P3 authority.
//! The native creator must keep its actual original file, authorize every I/O,
//! persist this exact image and read it back before using the decoder below.

use super::{
    native_clock::NativeAcquisition,
    seed_core::{Incarnations, InitialMarker, OriginalSeedCore},
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use rusqlite::{Connection, MAIN_DB, TransactionBehavior, params};

const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCHEMA_DEFINITIONS: usize = 4096;
const MAX_SCHEMA_BYTES: usize = 8 * 1024 * 1024;

const INITIAL_SEED_SCHEMA: &str = "CREATE TABLE day2_initial_security_seed (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    store BLOB NOT NULL,
    core BLOB NOT NULL,
    marker BLOB NOT NULL
) STRICT";

/// Provenance comes from the actual memory-only constructor, not a filename or
/// database_list result (which also describe anonymous temporary databases).
/// There is no adopt, pathname or raw-Connection constructor.
struct FreshMemoryDatabase {
    connection: Connection,
}

impl FreshMemoryDatabase {
    fn empty(acquisition: &mut NativeAcquisition) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            let connection = Connection::open_in_memory()?;
            // Set this before any initializer or schema sorting SQL. Bundled
            // SQLite's default does not itself guarantee memory-only temp data.
            connection.pragma_update(None, "temp_store", "MEMORY")?;
            ensure!(
                connection.pragma_query_value(None, "temp_store", |row| row.get::<_, i64>(0))? == 2,
                "epoch_preparation_temp_store_required"
            );
            crate::store::configure_connection(&connection)?;
            acquisition.remaining()?;
            Ok(Self { connection })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    fn freeze(self, acquisition: &mut NativeAcquisition) -> Result<FrozenPreparationImage> {
        FrozenPreparationImage::freeze(&self.connection, acquisition)
    }
}

/// The complete initial framework/app schema, selected store and canonical
/// seed/marker committed together IN MEMORY. This is DATA, not a durable file,
/// original creator, P3 acknowledgment or current bootstrap execution permit.
pub(super) struct InitialPreparationImage {
    image: FrozenPreparationImage,
    store: EpochStore,
    core: OriginalSeedCore,
    marker: InitialMarker,
}

impl InitialPreparationImage {
    pub(super) fn prepare(
        runtime: &crate::store::Runtime,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        incarnations: Incarnations,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            let core = OriginalSeedCore::new(policy, store, incarnations)?;
            ensure!(
                runtime.scope()
                    == format!(
                        "{}/{}/{}",
                        core.scope.installation.as_str(),
                        core.scope.environment.as_str(),
                        core.scope.app.as_str()
                    )
                    && runtime.app() == core.scope.app.as_str()
                    && runtime.artifact().id() == core.artifact.as_str(),
                "epoch_preparation_runtime_selection_mismatch"
            );
            let marker = core.marker()?;
            let mut memory = FreshMemoryDatabase::empty(acquisition)?;
            let tx = memory
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            runtime.initialize_in_transaction(&tx)?;
            tx.execute_batch(INITIAL_SEED_SCHEMA)?;
            ensure!(
                schema_contract(&tx)? == core.schema_contract,
                "epoch_preparation_admitted_schema_mismatch"
            );
            tx.execute(
                "INSERT INTO day2_initial_security_seed VALUES(1,?1,?2,?3)",
                params![
                    serde_json::to_vec(store)?,
                    serde_json::to_vec(&core)?,
                    serde_json::to_vec(&marker)?
                ],
            )?;
            acquisition.remaining()?;
            tx.commit()?;
            let image = memory.freeze(acquisition)?;
            ensure!(
                image.schema == core.schema_contract,
                "epoch_preparation_schema_changed"
            );
            acquisition.remaining()?;
            Ok(Self {
                image,
                store: store.clone(),
                core,
                marker,
            })
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    pub(super) fn bytes(&self) -> &[u8] {
        self.image.bytes()
    }

    pub(super) fn store(&self) -> &EpochStore {
        &self.store
    }

    pub(super) fn core(&self) -> &OriginalSeedCore {
        &self.core
    }

    pub(super) fn marker(&self) -> &InitialMarker {
        &self.marker
    }

    /// Semantic readback remains DATA. The future native owner must separately
    /// prove the read came through its surviving original descriptor, completed
    /// the physical sync protocol and still has current role/file authority.
    pub(super) fn decode_exact_readback(
        &self,
        readback: &[u8],
        acquisition: &mut NativeAcquisition,
    ) -> Result<Connection> {
        let result = (|| {
            let decoded = self.image.decode_exact_readback(readback, acquisition)?;
            let count: i64 = decoded.query_row(
                "SELECT count(*) FROM day2_initial_security_seed",
                [],
                |row| row.get(0),
            )?;
            ensure!(count == 1, "epoch_preparation_seed_cardinality");
            let (store, core, marker): (Vec<u8>, Vec<u8>, Vec<u8>) = decoded.query_row(
                "SELECT store,core,marker FROM day2_initial_security_seed WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            ensure!(
                store == serde_json::to_vec(&self.store)?
                    && core == serde_json::to_vec(&self.core)?
                    && marker == serde_json::to_vec(&self.marker)?
                    && self.core.marker()? == self.marker
                    && self.image.schema() == &self.core.schema_contract,
                "epoch_preparation_seed_marker_readback_mismatch"
            );
            acquisition.remaining()?;
            Ok(decoded)
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }
}

/// An owned, immutable copy: a SQLite NOCOPY view cannot outlive this snapshot
/// or change after a later write to the source connection. No native authority
/// can be reconstructed from an image or its schema digest.
struct FrozenPreparationImage {
    bytes: Vec<u8>,
    schema: Digest,
}

impl FrozenPreparationImage {
    /// The caller must have initialized the complete admitted framework/app
    /// schema and seed/marker in one committed transaction. This function only
    /// freezes DATA; it does not admit that schema or authorize file creation.
    fn freeze(connection: &Connection, acquisition: &mut NativeAcquisition) -> Result<Self> {
        let result = (|| {
            acquisition.remaining()?;
            ensure!(
                connection.pragma_query_value(None, "temp_store", |row| row.get::<_, i64>(0))? == 2,
                "epoch_preparation_temp_store_required"
            );
            ensure!(
                connection.is_autocommit(),
                "epoch_preparation_uncommitted_image"
            );
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
            let mode: String =
                connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
            ensure!(mode == "memory", "epoch_preparation_initial_journal_mode");
            let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
            let page_size: i64 =
                connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
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

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn schema(&self) -> &Digest {
        &self.schema
    }

    /// Parse only complete, immutable bytes already proven equal to the trusted
    /// generated image. The caller remains responsible for reading through the
    /// held original descriptor, native rechecks and exact seed/marker binding.
    fn decode_exact_readback(
        &self,
        readback: &[u8],
        acquisition: &mut NativeAcquisition,
    ) -> Result<Connection> {
        let result = (|| {
            acquisition.remaining()?;
            ensure!(
                readback == self.bytes,
                "epoch_preparation_image_readback_mismatch"
            );
            let mut memory = FreshMemoryDatabase::empty(acquisition)?;
            // Safe pinned API over an already verified, complete immutable slice;
            // never a live descriptor, uncertain input or WAL-header repair.
            memory
                .connection
                .deserialize_read_exact(MAIN_DB, readback, readback.len(), true)?;
            let decoded = memory.connection;
            ensure!(
                schema_contract(&decoded)? == self.schema,
                "epoch_preparation_schema_readback_mismatch"
            );
            let integrity: String =
                decoded.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
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
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")?;
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
        ]
        .into_iter()
        .flatten()
        {
            size = size
                .checked_add(value.len())
                .ok_or_else(|| anyhow::anyhow!("epoch_preparation_schema_bound"))?;
        }
        ensure!(size <= MAX_SCHEMA_BYTES, "epoch_preparation_schema_bound");
        definitions.push(definition);
    }
    ensure!(!definitions.is_empty(), "epoch_preparation_empty_schema");
    Digest::of(&("day2-initial-framework-schema-v1", definitions))
}

#[cfg(test)]
pub(super) mod tests {
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
        let db = FreshMemoryDatabase::empty(&mut acquisition())
            .unwrap()
            .connection;
        db.execute_batch("CREATE TABLE initial_marker(seed TEXT PRIMARY KEY); INSERT INTO initial_marker VALUES('original');").unwrap();
        db
    }

    #[test]
    fn frozen_image_survives_source_mutation_and_readback_is_read_only() {
        let db = database();
        let image = FrozenPreparationImage::freeze(&db, &mut acquisition()).unwrap();
        db.execute("UPDATE initial_marker SET seed='replacement'", [])
            .unwrap();
        drop(db);
        let restored = image
            .decode_exact_readback(image.bytes(), &mut acquisition())
            .unwrap();
        let seed: String = restored
            .query_row("SELECT seed FROM initial_marker", [], |row| row.get(0))
            .unwrap();
        assert_eq!(seed, "original");
        assert!(
            restored
                .execute("UPDATE initial_marker SET seed='wrong'", [])
                .is_err()
        );
        let mut corrupt = image.bytes().to_vec();
        corrupt[18] = 2;
        let mut interval = acquisition();
        assert!(
            image
                .decode_exact_readback(&corrupt, &mut interval)
                .is_err()
        );
        assert!(interval.remaining().is_err());
    }

    #[test]
    fn schema_contract_excludes_values_and_changes_with_definitions() {
        let db = database();
        let original = schema_contract(&db).unwrap();
        db.execute("UPDATE initial_marker SET seed='another-incarnation'", [])
            .unwrap();
        assert_eq!(schema_contract(&db).unwrap(), original);
        db.execute_batch("CREATE TABLE other_definition(value INTEGER NOT NULL)")
            .unwrap();
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

    #[test]
    fn changed_temp_storage_refuses_before_schema_sorting() {
        let db = database();
        db.pragma_update(None, "temp_store", "FILE").unwrap();
        let mut interval = acquisition();
        assert!(FrozenPreparationImage::freeze(&db, &mut interval).is_err());
        assert!(interval.remaining().is_err());
    }

    // Synthetic host-boundary contract DATA; no compiler/artifact admission,
    // actual native role, file ownership or Linux volume qualification.
    pub(in crate::security_epoch) fn runtime() -> (tempfile::TempDir, crate::store::Runtime) {
        let directory = tempfile::tempdir().unwrap();
        let instance_path = directory.path().join("instance.json");
        std::fs::write(
            &instance_path,
            serde_json::to_vec(&serde_json::json!({
                "installation":"company","environment":"canary",
                "apps":{"calendar":{"artifact":"unused","readers":[],"writers":[]}}
            }))
            .unwrap(),
        )
        .unwrap();
        let contract: crate::artifact::Artifact = serde_json::from_value(serde_json::json!({
            "format":crate::artifact::CURRENT_FORMAT,"roc_version":"image-test",
            "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "worker_digest":"image-test","schema_digest":"image-test",
            "schema":{"models":{"items":{"fields":{"value":"text"}}},"inputs":{},"foreign_keys":[]},
            "operations":[],"sources":{},"admission":"local-spike-only"
        }))
        .unwrap();
        let artifact = crate::artifact::LoadedArtifact::from_contract_for_tests(
            Digest::new(b"initial-image-artifact").as_str().to_owned(),
            directory.path().into(),
            contract,
        );
        let runtime = crate::store::Runtime::from_artifact_for_tests(
            instance_path,
            "calendar".into(),
            directory.path().join("must-not-create.sqlite"),
            artifact,
        )
        .unwrap();
        (directory, runtime)
    }

    pub(in crate::security_epoch) fn incarnations() -> Incarnations {
        Incarnations {
            record: Digest::new(b"record"),
            database: Digest::new(b"database"),
            activation: Digest::new(b"activation"),
        }
    }

    pub(in crate::security_epoch) fn policy(
        runtime: &crate::store::Runtime,
        store: &EpochStore,
    ) -> InitialBootstrapPolicy {
        let mut memory = FreshMemoryDatabase::empty(&mut acquisition()).unwrap();
        let tx = memory.connection.transaction().unwrap();
        runtime.initialize_in_transaction(&tx).unwrap();
        tx.execute_batch(INITIAL_SEED_SCHEMA).unwrap();
        let schema = schema_contract(&tx).unwrap();
        tx.rollback().unwrap();
        let epoch = serde_json::json!({"id":"epoch","revision":Digest::of(store).unwrap()});
        let day2_capabilities::security_epoch::EpochProvider::FirestoreNativeV1 {
            iam_source, ..
        } = &store.provider;
        let role = |account: serde_json::Value, name: &str| {
            serde_json::json!({
                "namespace":{"name":"native","uid":"namespace-uid"},
                "kubernetes_service_account":{"name":name,"uid":format!("{name}-ksa-uid")},
                "google_service_account":account,"workload_kind":if name=="app" { "stateful_set_v1" } else { "deployment_v1" },
                "workload":{"name":name,"uid":format!("{name}-workload-uid")},
                "token_review_audience":"https://kubernetes.default.svc"
            })
        };
        serde_json::from_value(serde_json::json!({
            "scope":store.scope,"epoch_store":epoch,
            "cluster":{"project":"project-seven","location":"us-central1","name":"native","uid":"cluster-uid",
                "api_origin":"https://10.0.0.1:443","certificate_authority":Digest::new(b"ca")},
            "controller":role(serde_json::json!({"kind":"gke_workload_identity_v1",
                "service_account":"controller@project-seven.iam.gserviceaccount.com",
                "service_account_uid":"200000000000000000007"}),"controller"),
            "app":role(serde_json::to_value(iam_source).unwrap(),"app"),
            "control_store":{"kind":"firestore_authority_database_v1","epoch_store":epoch},
            "runtime_profile":{"kind":"gke_linux_trusted_native_v1","manifest":Digest::new(b"profile"),
                "controller_code":Digest::new(b"code"),"app_artifact":runtime.artifact().id()},
            "fresh_storage":{"provider_volume_uid":"provider-volume-uid","mount_binding":Digest::new(b"mount"),
                "schema_contract":schema,"marker_format":"initial-v1"}
        })).unwrap()
    }

    #[test]
    fn complete_framework_and_seed_marker_share_the_callers_transaction() {
        let (_directory, runtime) = runtime();
        let mut memory = FreshMemoryDatabase::empty(&mut acquisition()).unwrap();
        let tx = memory.connection.transaction().unwrap();
        runtime.initialize_in_transaction(&tx).unwrap();
        tx.execute_batch(INITIAL_SEED_SCHEMA).unwrap();
        for name in [
            "items",
            "day2_meta",
            "day2_authority",
            "day2_initial_security_seed",
        ] {
            let count: i64 = tx
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name=?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing complete initial definition: {name}");
        }
        tx.rollback().unwrap();
        let tables: i64 = memory
            .connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            tables, 0,
            "initializer committed outside the callers transaction"
        );
        assert!(!runtime.db().exists());
    }

    #[test]
    fn complete_image_binds_canonical_store_seed_marker_and_read_only_app_schema() {
        let (_directory, runtime) = runtime();
        let store = super::super::tests::selection();
        let policy = policy(&runtime, &store);
        let image = InitialPreparationImage::prepare(
            &runtime,
            &policy,
            &store,
            incarnations(),
            &mut acquisition(),
        )
        .unwrap();
        let decoded = image
            .decode_exact_readback(image.bytes(), &mut acquisition())
            .unwrap();
        let row: (Vec<u8>, Vec<u8>, Vec<u8>) = decoded
            .query_row(
                "SELECT store,core,marker FROM day2_initial_security_seed WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row.0, serde_json::to_vec(image.store()).unwrap());
        assert_eq!(row.1, serde_json::to_vec(image.core()).unwrap());
        assert_eq!(row.2, serde_json::to_vec(image.marker()).unwrap());
        assert_eq!(image.core().marker().unwrap(), *image.marker());
        let scope: String = decoded
            .query_row("SELECT value FROM day2_meta WHERE key='scope'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(scope, runtime.scope());
        let items: i64 = decoded
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(items, 0);
        assert!(
            decoded
                .execute(
                    "INSERT INTO items(id,version,created_at,value) VALUES(1,1,0,'forbidden')",
                    []
                )
                .is_err()
        );
        assert!(!runtime.db().exists());
    }

    #[test]
    fn wrong_schema_or_artifact_cannot_publish_an_initial_image() {
        let (_directory, runtime) = runtime();
        let store = super::super::tests::selection();
        let good = policy(&runtime, &store);
        let mut bad_schema = good.clone();
        bad_schema.fresh_storage.schema_contract = Digest::new(b"not-complete-framework-schema");
        let mut interval = acquisition();
        assert!(
            InitialPreparationImage::prepare(
                &runtime,
                &bad_schema,
                &store,
                incarnations(),
                &mut interval
            )
            .is_err()
        );
        assert!(interval.remaining().is_err());
        let mut bad_artifact = good;
        bad_artifact.runtime_profile.app_artifact = Digest::new(b"different-artifact");
        assert!(
            InitialPreparationImage::prepare(
                &runtime,
                &bad_artifact,
                &store,
                incarnations(),
                &mut acquisition()
            )
            .is_err()
        );
        assert!(!runtime.db().exists());
    }
}
