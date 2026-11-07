//! One-way offline restore denial. This is not approval, native exclusion,
//! provider rollback, a restored writer or a way to recover an old permit.
//! Existing outcomes/material stay intact; exact old continuations are fenced.
use crate::security_epoch::restore_cut::Cut;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use ring::digest::{Context as Hash, SHA256};
use rusqlite::{Connection, Transaction, params, types::ValueRef};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Connect,
    Refresh,
    Management,
    Use,
    UseOriginal,
    Fresh,
    Inbound,
}
impl Kind {
    fn text(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Refresh => "refresh",
            Self::Management => "management",
            Self::Use => "use",
            Self::UseOriginal => "use_original",
            Self::Fresh => "fresh",
            Self::Inbound => "inbound",
        }
    }
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    super::schema::install_current(db, "oauth_restore_schema_version", 1,
        "CREATE TABLE IF NOT EXISTS oauth_restore_schema_version(version INTEGER PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS oauth_restore_cuts(
             digest TEXT PRIMARY KEY, binding TEXT NOT NULL, inventory TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS oauth_restore_closed(
             kind TEXT NOT NULL, id TEXT NOT NULL,
             cut TEXT NOT NULL REFERENCES oauth_restore_cuts(digest), PRIMARY KEY(kind,id)
         );
         CREATE TRIGGER IF NOT EXISTS oauth_restore_cut_no_update BEFORE UPDATE ON oauth_restore_cuts
             BEGIN SELECT RAISE(ABORT,'immutable restore cut'); END;
         CREATE TRIGGER IF NOT EXISTS oauth_restore_cut_no_delete BEFORE DELETE ON oauth_restore_cuts
             BEGIN SELECT RAISE(ABORT,'restore cut retained'); END;
         CREATE TRIGGER IF NOT EXISTS oauth_restore_closed_no_update BEFORE UPDATE ON oauth_restore_closed
             BEGIN SELECT RAISE(ABORT,'immutable restore closure'); END;
         CREATE TRIGGER IF NOT EXISTS oauth_restore_closed_no_delete BEFORE DELETE ON oauth_restore_closed
             BEGIN SELECT RAISE(ABORT,'restore closure retained'); END;",
        &[super::schema::Invariant { table: "oauth_restore_cuts", predicate:
            "length(digest)=71 AND substr(digest,1,7)='sha256:' AND substr(digest,8) NOT GLOB '*[^0-9a-f]*'
             AND length(binding) BETWEEN 1 AND 32768 AND json_valid(binding) AND json_type(binding)='object'
             AND length(inventory)=71 AND substr(inventory,1,7)='sha256:' AND substr(inventory,8) NOT GLOB '*[^0-9a-f]*'" },
          super::schema::Invariant { table: "oauth_restore_closed", predicate:
            "kind IN ('connect','refresh','management','use','use_original','fresh','inbound')
             AND length(id) BETWEEN 1 AND 256 AND length(cut)=71
             AND EXISTS(SELECT 1 FROM oauth_restore_cuts c WHERE c.digest=cut)" }])
}

fn validate_id(id: &str) -> Result<()> {
    ensure!(
        (1..=256).contains(&id.len())
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte)),
        "restore_continuation_identity_bound"
    );
    Ok(())
}

/// Absence in a CURRENT installed unit is only absence of this denial. All
/// existing authentication, current epoch, purpose and owner checks still run.
/// A missing/partial unit is an error, never an implicit pre-restore fallback.
pub(crate) fn require_open(db: &Connection, kind: Kind, id: &str) -> Result<()> {
    validate_id(id)?;
    let current: bool = db.query_row(
        "SELECT count(*)=1 AND min(version)=1 FROM main.oauth_restore_schema_version",
        [],
        |row| row.get(0),
    )?;
    ensure!(current, "restore_current_cut_unit_required");
    let closed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.oauth_restore_closed c LEFT JOIN main.oauth_restore_cuts k ON k.digest=c.cut WHERE c.kind=?1 AND c.id=?2)",
        params![kind.text(), id], |row| row.get(0))?;
    ensure!(!closed, "pre_restore_authority_closed");
    Ok(())
}

// Identity-bearing tables are explicitly classified. DDL is always obtained
// from the real installers below, never copied into a second schema definition.
const UNITS: &[(&str, &[&str])] = &[
    (
        "oauth_schema_version",
        &["oauth_connection_slots", "oauth_refresh_attempts"],
    ),
    ("oauth_connect_schema_version", &["oauth_connect_attempts"]),
    (
        "oauth_callback_schema_version",
        &["oauth_callback_bindings"],
    ),
    (
        "oauth_exchange_schema_version",
        &["oauth_exchange_bindings"],
    ),
    (
        "oauth_custody_schema_version",
        &[
            "oauth_private_verifiers",
            "oauth_private_codes",
            "oauth_private_tokens",
            "oauth_external_quarantine",
        ],
    ),
    (
        "oauth_management_schema_version",
        &[
            "oauth_management_intents",
            "oauth_management_dispatch_slots",
        ],
    ),
    ("native_fresh_schema_version", &["native_fresh_owners"]),
    ("oauth_use_schema_version", &["oauth_use_handles"]),
    (
        "oauth_inbound_schema_version",
        &[
            "oauth_inbound_grants",
            "oauth_inbound_codes",
            "oauth_inbound_refresh",
            "oauth_inbound_access",
        ],
    ),
    (
        "oauth_restore_schema_version",
        &["oauth_restore_cuts", "oauth_restore_closed"],
    ),
];

type Schema = BTreeMap<(String, String), (String, Option<String>)>;

fn sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("oauth_") || lower.starts_with("native_fresh_")
}

fn schema(db: &Connection, database: &'static str) -> Result<Schema> {
    let mut result = BTreeMap::new();
    let mut statement = db.prepare(&format!(
        "SELECT type,name,tbl_name,sql FROM {database}.sqlite_master ORDER BY type,name"
    ))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        super::schema::materialize(row)?;
        let name = row.get_ref(1)?.as_str()?;
        let table = row.get_ref(2)?.as_str()?;
        if sensitive(name) || sensitive(table) {
            ensure!(result.len() < 256, "restore_schema_object_bound");
            result.insert((row.get(0)?, name.into()), (table.into(), row.get(3)?));
        }
    }
    Ok(result)
}

fn canonical() -> Result<(Connection, Schema)> {
    let db = Connection::open_in_memory()?;
    db.execute_batch(crate::store::PLATFORM_DDL)?;
    // These are the canonical product installers, including their full current
    // dependency units. Nothing is installed or repaired on the imported DB.
    super::usage::install(&db)?;
    super::inbound::install_schema(&db)?;
    let expected = super::schema::admit(&db, |db| schema(db, "main"))?;
    ensure!(
        expected.values().all(|(table, _)| UNITS
            .iter()
            .any(|(version, tables)| table == version || tables.contains(&table.as_str()))),
        "restore_unclassified_oauth_schema"
    );
    Ok((db, expected))
}

/// The ordinary restore path has no external fence. Empty current metadata may
/// be copied, but retained denial history cannot be laundered by removing the
/// credential family or OAuth declarations from desired configuration.
pub(crate) fn require_no_history(db: &Connection) -> Result<()> {
    // Never install/admit on this connection: archive preflight already owns
    // its VM-step hook. Bound borrowed metadata without replacing that hook.
    let mut databases = db.prepare("PRAGMA database_list")?;
    let mut attached = databases.query([])?;
    let mut database_count = 0usize;
    while let Some(row) = attached.next()? {
        database_count += 1;
        ensure!(
            database_count <= 2 && ["main", "temp"].contains(&row.get_ref(1)?.as_str()?),
            "security_restore_preflight_required"
        );
    }
    let mut rows_seen = 0usize;
    let mut bytes_seen = 0usize;
    let actual = absence_schema(db, "main", &mut rows_seen, &mut bytes_seen)?;
    ensure!(
        absence_schema(db, "temp", &mut rows_seen, &mut bytes_seen)?.is_empty(),
        "security_restore_preflight_required"
    );
    if actual.is_empty() {
        return Ok(());
    }
    let profile = Profile::prepare()?;
    ensure!(
        actual
            .iter()
            .all(|(key, value)| profile.expected.get(key) == Some(value)),
        "security_restore_preflight_required"
    );
    for (version, tables) in UNITS {
        let owned = |table: &str| table == *version || tables.contains(&table);
        if !actual.values().any(|(table, _)| owned(table)) {
            continue;
        }
        ensure!(
            profile
                .expected
                .iter()
                .filter(|(_, (table, _))| owned(table))
                .all(|(key, value)| actual.get(key) == Some(value)),
            "security_restore_preflight_required"
        );
        let query = format!("SELECT version FROM main.{version}");
        let read = |connection: &Connection| -> Result<Vec<i64>> {
            let mut q = connection.prepare(&query)?;
            let mut rows = q.query([])?;
            let mut values = Vec::new();
            while let Some(row) = rows.next()? {
                ensure!(values.len() < 2, "security_restore_preflight_required");
                values.push(row.get(0)?);
            }
            Ok(values)
        };
        ensure!(
            read(db)? == read(&profile.reference)?,
            "security_restore_preflight_required"
        );
        for table in *tables {
            let occupied: bool = db.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM main.{table})"),
                [],
                |row| row.get(0),
            )?;
            ensure!(!occupied, "security_restore_preflight_required");
        }
    }
    Ok(())
}

fn absence_schema(
    db: &Connection,
    database: &'static str,
    rows_seen: &mut usize,
    bytes_seen: &mut usize,
) -> Result<Schema> {
    let mut result = BTreeMap::new();
    let mut q = db.prepare(&format!(
        "SELECT type,name,tbl_name,sql FROM {database}.sqlite_master"
    ))?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        *rows_seen = rows_seen
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("security_restore_preflight_required"))?;
        ensure!(*rows_seen <= 4096, "security_restore_preflight_required");
        for i in 0..4 {
            let bytes = match row.get_ref(i)? {
                ValueRef::Text(bytes) => bytes.len(),
                ValueRef::Null => 0,
                _ => anyhow::bail!("security_restore_preflight_required"),
            };
            ensure!(bytes <= 32768, "security_restore_preflight_required");
            *bytes_seen = bytes_seen
                .checked_add(bytes)
                .ok_or_else(|| anyhow::anyhow!("security_restore_preflight_required"))?;
            ensure!(
                *bytes_seen <= 8 * 1048576,
                "security_restore_preflight_required"
            );
        }
        let name = row.get_ref(1)?.as_str()?;
        let table = row.get_ref(2)?.as_str()?;
        if sensitive(name) || sensitive(table) {
            ensure!(result.len() < 256, "security_restore_preflight_required");
            result.insert((row.get(0)?, name.into()), (table.into(), row.get(3)?));
        }
    }
    Ok(result)
}

/// Trusted reference preparation stays outside the imported SQL/admission
/// scope. It contains no imported values, keys or native permission.
pub(crate) struct Profile {
    reference: Connection,
    expected: Schema,
}
impl Profile {
    pub(crate) fn prepare() -> Result<Self> {
        let (reference, expected) = canonical()?;
        Ok(Self {
            reference,
            expected,
        })
    }
}

fn identities(table: &str) -> Result<Option<(Kind, usize)>> {
    Ok(match table {
        "oauth_connect_attempts"
        | "oauth_callback_bindings"
        | "oauth_exchange_bindings"
        | "oauth_external_quarantine" => Some((Kind::Connect, 0)),
        "oauth_private_codes" | "oauth_private_verifiers" => Some((Kind::Connect, 1)),
        "oauth_refresh_attempts" => Some((Kind::Refresh, 0)),
        "oauth_management_intents" => Some((Kind::Management, 0)),
        "oauth_management_dispatch_slots" => Some((Kind::Management, 1)),
        "oauth_use_handles" => Some((Kind::Use, 0)),
        "native_fresh_owners" => Some((Kind::Fresh, 0)),
        "oauth_inbound_grants" => Some((Kind::Inbound, 0)),
        "oauth_inbound_codes" | "oauth_inbound_access" => Some((Kind::Inbound, 1)),
        "oauth_inbound_refresh" => Some((Kind::Inbound, 3)),
        "oauth_connection_slots"
        | "oauth_private_tokens"
        | "oauth_restore_cuts"
        | "oauth_restore_closed" => None,
        value if UNITS.iter().any(|(version, _)| value == *version) => None,
        _ => anyhow::bail!("restore_unclassified_oauth_table"),
    })
}

fn hash_value(hash: &mut Hash, value: ValueRef<'_>) {
    let (tag, bytes): (u8, &[u8]) = match value {
        ValueRef::Null => (0, &[]),
        ValueRef::Integer(value) => {
            hash.update(&[1]);
            hash.update(&value.to_be_bytes());
            return;
        }
        ValueRef::Real(value) => {
            hash.update(&[2]);
            hash.update(&value.to_bits().to_be_bytes());
            return;
        }
        ValueRef::Text(bytes) => (3, bytes),
        ValueRef::Blob(bytes) => (4, bytes),
    };
    hash.update(&[tag]);
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// Complete bounded row/schema commitment. It is DATA, not source admission or
/// a native snapshot. The offline owner retains the actual held archive/target.
pub(crate) struct Snapshot {
    digest: Digest,
    identities: BTreeSet<(Kind, String)>,
    tables: BTreeSet<String>,
}
impl Snapshot {
    pub(crate) fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn capture(db: &Connection, profile: &Profile) -> Result<Self> {
        ensure!(!db.is_autocommit(), "restore_snapshot_transaction_required");
        let Profile {
            reference,
            expected,
        } = profile;
        super::schema::admit(db, |db| {
            let mut databases = db.prepare("PRAGMA database_list")?;
            let mut rows = databases.query([])?;
            while let Some(row) = rows.next()? {
                super::schema::materialize(row)?;
                ensure!(
                    ["main", "temp"].contains(&row.get_ref(1)?.as_str()?),
                    "restore_attached_database_refused"
                );
            }
            ensure!(
                schema(db, "temp")?.is_empty(),
                "restore_shadow_schema_refused"
            );
            let meta_shadow:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM temp.sqlite_master WHERE lower(name)='day2_meta' OR lower(tbl_name)='day2_meta')",[],|r|r.get(0))?;
            ensure!(!meta_shadow, "restore_shadow_schema_refused");
            super::schema::exact_layout(db, reference, "day2_meta")?;
            let actual = schema(db, "main")?;
            ensure!(
                actual
                    .iter()
                    .all(|(key, value)| expected.get(key) == Some(value)),
                "restore_oauth_schema_changed"
            );
            for (version, tables) in UNITS {
                let unit: Schema = expected
                    .iter()
                    .filter(|(_, (table, _))| table == version || tables.contains(&table.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if actual
                    .values()
                    .any(|(table, _)| table == version || tables.contains(&table.as_str()))
                {
                    ensure!(
                        unit.iter()
                            .all(|(key, value)| actual.get(key) == Some(value)),
                        "restore_oauth_partial_unit"
                    );
                    let query = format!("SELECT version FROM main.{version} ORDER BY version");
                    let read = |connection: &Connection| -> Result<Vec<i64>> {
                        let mut q = connection.prepare(&query)?;
                        let mut rows = q.query([])?;
                        let mut result = Vec::new();
                        while let Some(row) = rows.next()? {
                            super::schema::materialize(row)?;
                            ensure!(result.len() < 2, "restore_version_row_bound");
                            result.push(row.get(0)?);
                        }
                        Ok(result)
                    };
                    ensure!(
                        read(db)? == read(reference)?,
                        "restore_oauth_version_changed"
                    );
                }
            }
            ensure!(
                actual.keys().any(|(_, name)| name == "oauth_restore_cuts"),
                "restore_current_cut_unit_required"
            );
            let present = |name: &str| {
                actual
                    .keys()
                    .any(|(kind, table)| kind == "table" && table == name)
            };
            // Validation uses canonical row predicates. Dependencies must
            // already exist, so these calls cannot fill an imported gap.
            if present("oauth_connect_schema_version") {
                ensure!(
                    [
                        "oauth_schema_version",
                        "oauth_callback_schema_version",
                        "oauth_exchange_schema_version",
                        "oauth_custody_schema_version",
                        "oauth_management_schema_version",
                        "native_fresh_schema_version"
                    ]
                    .iter()
                    .all(|name| present(name)),
                    "restore_oauth_dependency_missing"
                );
                super::connect::install_schema(db)?;
            } else {
                ensure!(
                    ![
                        "oauth_callback_schema_version",
                        "oauth_exchange_schema_version",
                        "oauth_custody_schema_version"
                    ]
                    .iter()
                    .any(|name| present(name)),
                    "restore_oauth_dependency_missing"
                );
                if present("oauth_schema_version") {
                    super::store::install_schema(db)?;
                }
                if present("oauth_management_schema_version") {
                    super::management::app::install(db)?;
                }
                if present("native_fresh_schema_version") {
                    super::fresh_owner::install(db)?;
                }
            }
            if present("oauth_use_schema_version") {
                ensure!(
                    present("oauth_connect_schema_version"),
                    "restore_oauth_dependency_missing"
                );
                super::usage::install(db)?;
            }
            if present("oauth_inbound_schema_version") {
                super::inbound::install_schema(db)?;
            }
            install(db)?;
            ensure!(
                schema(db, "main")? == actual,
                "restore_schema_changed_during_validation"
            );
            let mut foreign = db.prepare("PRAGMA main.foreign_key_check")?;
            ensure!(
                foreign.query([])?.next()?.is_none(),
                "restore_oauth_foreign_key"
            );
            let tables: BTreeSet<_> = actual
                .iter()
                .filter(|((kind, _), _)| kind == "table")
                .map(|((_, name), _)| name.clone())
                .collect();
            let mut hash = Hash::new(&SHA256);
            hash.update(b"day2-complete-oauth-reset-snapshot-v1");
            hash.update(&serde_json::to_vec(&actual.iter().collect::<Vec<_>>())?);
            let mut meta = db.prepare("SELECT key,value FROM main.day2_meta ORDER BY key")?;
            let mut meta_rows = meta.query([])?;
            while let Some(row) = meta_rows.next()? {
                super::schema::materialize(row)?;
                hash.update(&[253]);
                hash_value(&mut hash, row.get_ref(0)?);
                hash_value(&mut hash, row.get_ref(1)?);
            }
            let mut identities_set = BTreeSet::new();
            for table in &tables {
                let selector = identities(table)?;
                hash.update(&(table.len() as u64).to_be_bytes());
                hash.update(table.as_bytes());
                let mut statement =
                    db.prepare(&format!("SELECT * FROM main.{table} ORDER BY rowid"))?;
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    super::schema::materialize(row)?;
                    hash.update(&[255]);
                    hash.update(&(row.as_ref().column_count() as u64).to_be_bytes());
                    for index in 0..row.as_ref().column_count() {
                        hash_value(&mut hash, row.get_ref(index)?);
                    }
                    if let Some((kind, index)) = selector {
                        let id = row.get_ref(index)?.as_str()?;
                        validate_id(id)?;
                        identities_set.insert((kind, id.into()));
                        if table == "oauth_use_handles" {
                            let identity = super::usage::restore_identity(
                                row.get_ref(2)?.as_str()?,
                                row.get_ref(1)?.as_str()?,
                            )?;
                            identities_set.insert((Kind::UseOriginal, identity.as_str().into()));
                        }
                        ensure!(identities_set.len() <= 8192, "restore_identity_count_bound");
                    }
                    if table == "oauth_restore_cuts" {
                        Cut::validate_record(row.get_ref(1)?.as_str()?, row.get_ref(0)?.as_str()?)?;
                    }
                }
                hash.update(&[254]);
            }
            let digest =
                Digest::try_from(format!("sha256:{}", crate::hex(hash.finish().as_ref())))?;
            Ok(Self {
                digest,
                identities: identities_set,
                tables,
            })
        })
    }
}

/// Atomic denial phase inside the private reset transaction. The caller must
/// already own genuine exclusion and the unpublished target. No outer commit,
/// external request, secret deletion, custody change or owner is produced.
pub(crate) fn close_in(
    tx: &mut Transaction<'_>,
    before: Snapshot,
    cut: &Cut,
    profile: &Profile,
) -> Result<usize> {
    cut.check_storage_metadata(tx)?;
    ensure!(
        tx.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))?,
        "restore_foreign_keys_required"
    );
    ensure!(
        cut.inventory() == before.digest(),
        "restore_cut_inventory_changed"
    );
    let fresh = Snapshot::capture(tx, profile)?;
    ensure!(fresh.digest == before.digest, "restore_snapshot_changed");
    let savepoint = tx.savepoint()?;
    let occupied: bool = savepoint.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.oauth_restore_cuts)",
        [],
        |r| r.get(0),
    )?;
    ensure!(!occupied, "restore_cut_already_present");
    savepoint.execute(
        "INSERT INTO main.oauth_restore_cuts(digest,binding,inventory) VALUES(?1,?2,?3)",
        params![
            cut.digest().as_str(),
            cut.encoded()?,
            cut.inventory().as_str()
        ],
    )?;
    for (kind, id) in &before.identities {
        savepoint.execute(
            "INSERT INTO main.oauth_restore_closed(kind,id,cut) VALUES(?1,?2,?3)",
            params![kind.text(), id, cut.digest().as_str()],
        )?;
    }
    if before.tables.contains("oauth_connection_slots") {
        let exhausted:bool=savepoint.query_row("SELECT EXISTS(SELECT 1 FROM main.oauth_connection_slots WHERE security_epoch=9223372036854775807)",[],|r|r.get(0))?;
        ensure!(!exhausted, "restore_local_epoch_exhausted");
        savepoint.execute("UPDATE main.oauth_connection_slots SET status='reauth_required',security_epoch=security_epoch+1",[])?;
    }
    if before.tables.contains("oauth_inbound_grants") {
        let exhausted:bool=savepoint.query_row("SELECT EXISTS(SELECT 1 FROM main.oauth_inbound_grants WHERE epoch=9223372036854775807)",[],|r|r.get(0))?;
        ensure!(!exhausted, "restore_inbound_epoch_exhausted");
        savepoint.execute("UPDATE main.oauth_inbound_grants SET status='revoked',epoch=epoch+1 WHERE status='active'",[])?;
        savepoint.execute(
            "UPDATE main.oauth_inbound_refresh SET state='revoked' WHERE state='active'",
            [],
        )?;
    }
    if before.tables.contains("native_fresh_owners") {
        savepoint.execute("UPDATE main.native_fresh_owners SET stage='refused' WHERE stage IN ('allocated','offered')",[])?;
    }
    let count = before.identities.len();
    savepoint.commit()?;
    Ok(count)
}

#[cfg(test)]
#[path = "restore_tests.rs"]
pub(super) mod tests;
