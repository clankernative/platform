//! Private prepared denial portion of secure restore. No production approval,
//! incumbent exclusion, Runtime opener or restored-writer supplier exists here.
use crate::authority_state::{self, ActiveAuthority};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rusqlite::Connection;
use std::path::Path;

fn require_transaction(db: &Connection) -> Result<()> {
    ensure!(!db.is_autocommit(), "authority_requires_transaction");
    Ok(())
}

/// Prepared denial DATA, never maintenance approval, a clock witness, native
/// exclusion, a Runtime opener or a new writer. The secure owner must derive
/// the fresh epoch and qualified delegation cutoff outside its SQL loan, bind
/// the actual admitted artifact and retain those same owners through commit.
/// The ordinary restore wrapper still performs its existing history refusal.
pub(crate) struct PreparedRestoreFence {
    previous: ActiveAuthority,
    disabled: ActiveAuthority,
    not_before: i64,
}

impl PreparedRestoreFence {
    pub(crate) fn new(
        previous: ActiveAuthority,
        relocated: &Path,
        fresh_epoch: Digest,
        not_before: i64,
    ) -> Result<Self> {
        ensure!(not_before >= 0, "restore_delegation_clock_invalid");
        ensure!(
            fresh_epoch.as_str() != previous.stamp.epoch,
            "restore_authority_epoch_reused"
        );
        let mut disabled = previous.clone();
        disabled.stamp.epoch = fresh_epoch.as_str().into();
        disabled.stamp.revision = previous
            .stamp
            .revision
            .checked_add(1)
            .context("authority_revision_exhausted")?;
        i64::try_from(disabled.stamp.revision).context("authority_revision_exhausted")?;
        disabled.document.enabled = false;
        disabled.artifact_path = relocated.to_string_lossy().into_owned();
        Ok(Self {
            previous,
            disabled,
            not_before,
        })
    }

    pub(crate) fn into_disabled(self) -> ActiveAuthority {
        self.disabled
    }

    fn require_applied_in(&self, connection: &Connection) -> Result<()> {
        require_transaction(connection)?;
        crate::oauth::schema::require_admission(connection)?;
        ensure!(
            authority_state::current(connection)? == self.disabled
                && !self.disabled.document.enabled
                && self.disabled.stamp.epoch != self.previous.stamp.epoch,
            "restore_disabled_authority_changed"
        );
        Ok(())
    }

    /// Nonescaping SQL-denial context for the complete reset, minted only after
    /// both actual local cuts. It is not approval, exclusion or IO authority.
    pub(crate) fn closed_credential_peers<'db>(
        &'db self,
        connection: &'db rusqlite::Transaction<'_>,
        applied: &'db crate::oauth::restore::AppliedCut<'_, '_, '_>,
        namespace: &day2_capabilities::credentials::Namespace,
        source_epoch: u64,
    ) -> Result<ClosedCredentialPeers<'db>> {
        applied.require_connection(connection)?;
        let context = ClosedCredentialPeers {
            connection,
            fence: self,
            cut: applied.cut(),
            namespace: namespace.clone(),
            source_epoch,
        };
        context.require(connection, namespace, source_epoch)?;
        Ok(context)
    }

    /// SQL only. No clock, entropy, artifact/provider IO, outer commit or
    /// readiness is produced. The enclosing complete reset owns rollback.
    pub(crate) fn apply_in(
        &self,
        connection: &Connection,
        schema: &RestoreFenceSchema,
    ) -> Result<()> {
        require_transaction(connection)?;
        crate::oauth::schema::require_admission(connection)?;
        require_single_restore_database(connection)?;
        schema.require_current_in(connection)?;
        ensure!(
            authority_state::current(connection)? == self.previous,
            "restore_authority_snapshot_changed"
        );
        let reused: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM day2_authority_history WHERE epoch=?1)",
            [&self.disabled.stamp.epoch],
            |row| row.get(0),
        )?;
        ensure!(!reused, "restore_authority_epoch_reused");
        crate::budget::freeze_current_restore_in(connection)?;
        crate::delegation_commands::fence_current_restore_in(connection, self.not_before)?;
        authority_state::store_record_in(
            connection,
            &self.disabled,
            "platform-restore",
            "restore-fence",
        )?;
        authority_state::discard_restored_sessions_in(connection)
    }
}

/// Permission to retain already admitted peer rows as historical DATA while
/// revoking the credential unit in this exact transaction. This has no native
/// factory, serialization or ability to authorize issue/reveal/serving.
pub(crate) struct ClosedCredentialPeers<'db> {
    connection: &'db Connection,
    fence: &'db PreparedRestoreFence,
    cut: &'db super::restore_cut::Cut,
    namespace: day2_capabilities::credentials::Namespace,
    source_epoch: u64,
}

const _: () = {
    macro_rules! not_impl {
        ($bound:path) => {{
            trait AmbiguousIfImpl<A> { fn check() {} }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $bound> AmbiguousIfImpl<u8> for T {}
            let _ = <ClosedCredentialPeers<'static> as AmbiguousIfImpl<_>>::check;
        }};
    }
    not_impl!(Clone);not_impl!(Copy);not_impl!(Default);not_impl!(std::fmt::Debug);
    not_impl!(serde::Serialize);not_impl!(serde::Deserialize<'static>);
    not_impl!(Send);not_impl!(Sync);not_impl!(std::ops::Deref);
    not_impl!(AsRef<Connection>);not_impl!(std::borrow::Borrow<Connection>);
};

impl ClosedCredentialPeers<'_> {
    pub(crate) fn require(
        &self,
        connection: &Connection,
        namespace: &day2_capabilities::credentials::Namespace,
        source_epoch: u64,
    ) -> Result<()> {
        ensure!(
            std::ptr::eq(connection, self.connection)
                && namespace == &self.namespace
                && source_epoch == self.source_epoch,
            "restore_closed_peer_owner_changed"
        );
        self.fence.require_applied_in(connection)?;
        self.cut
            .require_credential_binding(namespace, source_epoch)?;
        self.cut.require_applied_in(connection)
    }
}

/// Canonical schema reference for the denial leaf only. Prepared on a trusted
/// empty memory database before the restore loan; never installs on imported
/// state and is not whole-application admission, approval or native exclusion.
pub(crate) struct RestoreFenceSchema {
    reference: Connection,
}

impl RestoreFenceSchema {
    pub(crate) fn prepare() -> Result<Self> {
        let mut reference = Connection::open_in_memory()?;
        reference.pragma_update(None, "foreign_keys", true)?;
        reference.execute_batch(crate::store::PLATFORM_DDL)?;
        {
            let tx = reference.transaction()?;
            crate::audit::upgrade(&tx)?;
            authority_state::upgrade(&tx)?;
            crate::budget::initialize_in(&tx, "restore-schema-reference")?;
            crate::delegation_commands::upgrade(&tx)?;
            tx.commit()?;
        }
        Ok(Self { reference })
    }

    /// The enclosing adapter owns an active cumulative scope on this connection:
    /// a raw offline target owns its temporary hook, while Runtime retains its
    /// permanent hook. This leaf never installs, removes or assumes a hook.
    /// Complete reset must independently admit every other app/private unit.
    fn require_current_in(&self, connection: &Connection) -> Result<()> {
        require_transaction(connection)?;
        require_single_restore_database(connection)?;
        crate::oauth::schema::require_admission(connection)?;
        let db = connection;
        {
            let expected = Self::objects(&self.reference)?;
            ensure!(
                Self::objects(db)? == expected,
                "restore_denial_schema_changed"
            );
            for (kind, name, _) in expected {
                match kind.as_str() {
                    "table" => {
                        crate::oauth::schema::exact_layout(db, &self.reference, &name)?;
                        // Partial integrity check covers only this admitted
                        // table and its indexes, not unadmitted app/private units.
                        let mut statement =
                            db.prepare(&format!("PRAGMA integrity_check({name})"))?;
                        let mut rows = statement.query([])?;
                        let first = rows.next()?.context("restore_integrity_result_missing")?;
                        crate::oauth::schema::materialize(first)?;
                        ensure!(
                            first.get_ref(0)?.as_str()? == "ok" && rows.next()?.is_none(),
                            "restore_integrity_refused"
                        );
                    }
                    "trigger" => ensure!(
                        crate::oauth::schema::schema_sql(db, "trigger", &name)?
                            == crate::oauth::schema::schema_sql(&self.reference, "trigger", &name)?,
                        "restore_denial_guard_changed"
                    ),
                    "index" => {}
                    _ => anyhow::bail!("restore_denial_schema_changed"),
                }
            }
            // The upgrade routines are deliberately absent from the mutation
            // path. In particular an empty/old budget marker cannot mint a new
            // lineage or restamp the pool-return protocol.
            let (ledger, restored, version): (String, i64, i64) = db.query_row(
                "SELECT ledger_id,restored,pool_return_version FROM day2_budget_meta WHERE singleton=1",
                [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            Digest::try_from(ledger)?;
            ensure!(restored == 0 && version == 1, "restore_budget_not_current");
            // This is structural denial admission. Semantic validation of all
            // serialized receipts/history remains the complete owner's duty;
            // do not traverse optional resource-provider units from here.
            Ok(())
        }
    }

    fn owns(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        name.starts_with("day2_authority")
            || name.starts_with("day2_budget_")
            || name.starts_with("day2_app_")
            || name == "day2_invocation_authority"
            || name.starts_with("day2_invocations")
            || name == "day2_inherited_origins"
            || name == "day2_web_sessions"
            || name == "day2_web_secret"
    }

    fn objects(db: &Connection) -> Result<Vec<(String, String, String)>> {
        let mut statement = db.prepare(
            "SELECT type,name,tbl_name FROM main.sqlite_master ORDER BY type,name,tbl_name",
        )?;
        let mut rows = statement.query([])?;
        let mut objects = Vec::new();
        while let Some(row) = rows.next()? {
            crate::oauth::schema::materialize(row)?;
            let name = row.get_ref(1)?.as_str()?;
            let table = row.get_ref(2)?.as_str()?;
            if Self::owns(name) || Self::owns(table) {
                objects.push((row.get(0)?, row.get(1)?, row.get(2)?));
            }
        }
        Ok(objects)
    }
}

fn require_single_restore_database(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        ensure!(
            count <= 2 && ["main", "temp"].contains(&row.get_ref(1)?.as_str()?),
            "restore_attached_database_refused"
        );
    }
    let temporary: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_master)",
        [],
        |row| row.get(0),
    )?;
    ensure!(!temporary, "restore_temporary_schema_refused");
    Ok(())
}
