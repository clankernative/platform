//! Append-only provenance for authored resource versions. This is not desired
//! configuration and is never consulted to authorize app execution. A version
//! is reserved before replacing instance.json so failed saves cannot reuse it
//! for different bytes or reset a budget's accounting lineage.

use anyhow::{Result, ensure};
use day2_capabilities::resources::{BudgetDefinition, Catalog};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{collections::BTreeMap, fs, path::Path};

/// The caller holds the installation's exclusive resource-authoring lock until
/// after atomic file replacement. Repeating an interrupted save with the same
/// definitions is safe; a reserved newer revision cannot be rolled backward.
pub(crate) fn validate_and_record(
    parent: &Path,
    installation: &str,
    environment: &str,
    old: Option<&Catalog>,
    next: Option<&Catalog>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(catalog) = old {
        catalog.validate()?;
    }
    if let Some(catalog) = next {
        catalog.validate()?;
    }
    if let (Some(old), Some(next)) = (old, next) {
        old.validate_successor(next)?;
    }
    let state = parent.join(".state");
    fs::create_dir_all(&state)?;
    ensure!(
        !fs::symlink_metadata(&state)?.file_type().is_symlink(),
        "resource_history_directory_symlink"
    );
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))?;
    let path = state.join("resource-authoring.sqlite");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "resource_history_file_invalid"
        );
    }
    let mut db = crate::store::open(&path)?;
    let tx = crate::write_queue::immediate(&mut db)?;
    upgrade(&tx)?;
    let identity = serde_json::to_string(&(installation, environment))?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT identity FROM resource_catalog_scope WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match previous {
        Some(previous) => ensure!(previous == identity, "resource_history_scope_mismatch"),
        None => {
            tx.execute(
                "INSERT INTO resource_catalog_scope VALUES(1,?1)",
                [&identity],
            )?;
        }
    }
    // A failed file replacement can leave the previous desired version behind.
    // Its already-recorded bytes are checked without treating that seed as a
    // request to roll back the newly reserved version.
    if let Some(catalog) = old {
        record(&tx, catalog, true)?;
    }
    if let Some(catalog) = next {
        record(&tx, catalog, false)?;
    }
    tx.commit()?;
    fs::File::open(&state)?.sync_all()?;
    Ok(())
}

fn upgrade(db: &Connection) -> Result<()> {
    let existing: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='resource_catalog_versions')",
        [],
        |row| row.get(0),
    )?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS resource_catalog_scope(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS resource_catalog_versions(
        kind TEXT NOT NULL CHECK(kind IN ('connection','resource','policy','budget')),
        id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), definition TEXT NOT NULL,
        PRIMARY KEY(kind,id,revision)
    ) STRICT;",
    )?;
    for (table, key) in [
        ("resource_catalog_scope", "singleton=NEW.singleton"),
        (
            "resource_catalog_versions",
            "kind=NEW.kind AND id=NEW.id AND revision=NEW.revision",
        ),
    ] {
        for (suffix, action) in [
            ("no_update", format!("BEFORE UPDATE ON {table}")),
            ("no_delete", format!("BEFORE DELETE ON {table}")),
            (
                "no_replace",
                format!("BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE {key})"),
            ),
        ] {
            let name = format!("{table}_{suffix}");
            let sql = format!(
                "CREATE TRIGGER {name} {action} BEGIN SELECT RAISE(ABORT,'append_only_resource_catalog'); END"
            );
            if !existing {
                db.execute_batch(&sql)?;
            }
            crate::audit::validate_trigger(db, &name, &sql)?;
        }
    }
    Ok(())
}

fn record(db: &Connection, catalog: &Catalog, seed: bool) -> Result<()> {
    record_kind(
        db,
        "connection",
        &catalog.connections,
        |value| value.revision,
        seed,
    )?;
    record_kind(
        db,
        "resource",
        &catalog.resources,
        |value| value.revision,
        seed,
    )?;
    record_kind(
        db,
        "policy",
        &catalog.policies,
        |value| value.revision,
        seed,
    )?;
    for (id, definition) in &catalog.budgets {
        let prior: Option<String> = db.query_row("SELECT definition FROM resource_catalog_versions WHERE kind='budget' AND id=?1 ORDER BY revision LIMIT 1", [id], |row| row.get(0)).optional()?;
        if let Some(prior) = prior {
            let prior: BudgetDefinition = crate::json::decode(prior.as_bytes())?;
            ensure!(
                definition.scope == prior.scope
                    && definition.period_seconds == prior.period_seconds,
                "budget_lineage_is_immutable"
            );
        }
    }
    record_kind(db, "budget", &catalog.budgets, |value| value.revision, seed)
}

fn record_kind<T: Serialize>(
    db: &Connection,
    kind: &str,
    definitions: &BTreeMap<String, T>,
    revision: impl Fn(&T) -> u64,
    seed: bool,
) -> Result<()> {
    for (id, definition) in definitions {
        let revision = i64::try_from(revision(definition))?;
        let bytes = serde_json::to_string(definition)?;
        let previous: Option<String> = db.query_row("SELECT definition FROM resource_catalog_versions WHERE kind=?1 AND id=?2 AND revision=?3", params![kind,id,revision], |row| row.get(0)).optional()?;
        if let Some(previous) = &previous {
            ensure!(
                previous == &bytes,
                "resource_version_bytes_changed: {kind}/{id}/{revision}"
            );
        }
        let maximum: Option<i64> = db.query_row(
            "SELECT max(revision) FROM resource_catalog_versions WHERE kind=?1 AND id=?2",
            params![kind, id],
            |row| row.get(0),
        )?;
        ensure!(
            maximum.is_none_or(|maximum| revision >= maximum) || (seed && previous.is_some()),
            "resource_version_rollback: {kind}/{id}/{revision}"
        );
        if previous.is_none() {
            db.execute(
                "INSERT INTO resource_catalog_versions VALUES(?1,?2,?3,?4)",
                params![kind, id, revision, bytes],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::resources::{BudgetLimits, BudgetScope};

    fn catalog(revision: u64, calls: u64) -> Catalog {
        Catalog {
            version: 1,
            connections: BTreeMap::new(),
            resources: BTreeMap::new(),
            policies: BTreeMap::new(),
            budgets: BTreeMap::from([(
                "shared".into(),
                BudgetDefinition {
                    revision,
                    scope: BudgetScope::Installation,
                    period_seconds: 3600,
                    limits: BudgetLimits {
                        calls: Some(calls),
                        ..Default::default()
                    },
                },
            )]),
        }
    }

    #[test]
    fn deletion_and_whole_catalog_removal_never_free_version_or_budget_identity() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = catalog(1, 10);
        validate_and_record(dir.path(), "company", "prod", None, Some(&first))?;
        validate_and_record(dir.path(), "company", "prod", Some(&first), None)?;
        validate_and_record(dir.path(), "company", "prod", None, Some(&first))?;
        assert!(
            validate_and_record(dir.path(), "company", "prod", None, Some(&catalog(1, 20)))
                .is_err()
        );
        let second = catalog(2, 20);
        validate_and_record(dir.path(), "company", "prod", None, Some(&second))?;
        assert!(validate_and_record(dir.path(), "company", "prod", None, Some(&first)).is_err());
        let mut changed = catalog(3, 20);
        changed.budgets.get_mut("shared").unwrap().period_seconds = 60;
        assert!(validate_and_record(dir.path(), "company", "prod", None, Some(&changed)).is_err());
        changed.budgets.get_mut("shared").unwrap().period_seconds = 3600;
        changed.budgets.get_mut("shared").unwrap().scope = BudgetScope::Actor;
        assert!(validate_and_record(dir.path(), "company", "prod", None, Some(&changed)).is_err());
        assert!(validate_and_record(dir.path(), "other", "prod", None, Some(&second)).is_err());
        Ok(())
    }

    #[test]
    fn interrupted_file_replacement_retries_exact_reserved_bytes_and_guards_are_checked()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = catalog(1, 10);
        let second = catalog(2, 20);
        validate_and_record(dir.path(), "company", "prod", Some(&first), Some(&second))?;
        // The file is still first after a failed rename. Retry with same second.
        validate_and_record(dir.path(), "company", "prod", Some(&first), Some(&second))?;
        assert!(
            validate_and_record(
                dir.path(),
                "company",
                "prod",
                Some(&first),
                Some(&catalog(2, 30))
            )
            .is_err()
        );
        let db = crate::store::open(&dir.path().join(".state/resource-authoring.sqlite"))?;
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM resource_catalog_versions",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert!(
            db.execute("UPDATE resource_catalog_versions SET definition='{}'", [])
                .is_err()
        );
        assert!(
            db.execute("DELETE FROM resource_catalog_versions", [])
                .is_err()
        );
        assert!(db.execute("INSERT OR REPLACE INTO resource_catalog_versions SELECT * FROM resource_catalog_versions",[]).is_err());
        db.execute_batch("DROP TRIGGER resource_catalog_versions_no_update")?;
        assert!(
            validate_and_record(dir.path(), "company", "prod", Some(&first), Some(&second))
                .is_err()
        );
        Ok(())
    }
}
