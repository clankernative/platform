use crate::{
    artifact::LoadedArtifact,
    digest,
    schema::Kind,
    store::{Runtime, open},
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddColumn {
    pub model: String,
    pub field: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub format: u32,
    pub scope: String,
    pub source_artifact: String,
    pub target_artifact: String,
    pub source_schema: String,
    pub target_schema: String,
    pub add_nullable_text: Vec<AddColumn>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add_indexes: Vec<crate::schema::Index>,
    /// Explicitly retired models remain physically present and read-only. Their
    /// rows, indexes, identities and historical receipts are never discarded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retire_models: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub convert_ids: bool,
}
impl Plan {
    pub fn id(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
}

pub fn plan(runtime: &Runtime, target: &LoadedArtifact) -> Result<Plan> {
    plan_contracts(
        runtime.scope(),
        runtime.artifact().id(),
        runtime.artifact().contract(),
        target.id(),
        target.contract(),
    )
}

fn plan_contracts(
    scope: &str,
    source_id: &str,
    source_contract: &crate::artifact::Artifact,
    target_id: &str,
    target: &crate::artifact::Artifact,
) -> Result<Plan> {
    source_contract
        .identities
        .check_successor(&target.identities)?;
    let source = &source_contract.schema;
    let next = &target.schema;
    source.validate()?;
    ensure!(
        next.models
            .keys()
            .all(|name| source.models.contains_key(name)),
        "table additions need a future migration protocol"
    );
    let retire_models: Vec<String> = source
        .models
        .keys()
        .filter(|name| !next.models.contains_key(*name))
        .cloned()
        .collect();
    for name in &retire_models {
        let old = &source.models[name];
        ensure!(
            old.identity.as_ref().is_some_and(|identity| {
                target.identities.models.iter().any(|registered| {
                    registered.retired
                        && registered.table == *name
                        && old.roc_type.as_ref() == Some(&registered.roc_type)
                        && registered.identity == *identity
                })
            }),
            "table removal requires explicit model retirement: {name}"
        );
    }
    for old in &source.indexes {
        ensure!(
            retire_models.contains(&old.model) || next.indexes.contains(old),
            "index removal or redefinition requires explicit migration: {}.{}",
            old.model,
            old.name
        );
    }
    let add_indexes = next
        .indexes
        .iter()
        .filter(|index| !source.indexes.contains(index))
        .cloned()
        .collect();
    let retained_foreign_keys: Vec<_> = source
        .foreign_keys
        .iter()
        .filter(|key| !retire_models.contains(&key.model))
        .cloned()
        .collect();
    ensure!(
        retained_foreign_keys == next.foreign_keys,
        "relationship changes require explicit migration"
    );
    let mut additions = Vec::new();
    let convert_ids = source
        .models
        .values()
        .any(|record| record.identity.is_none())
        && next.models.values().any(|record| record.identity.is_some());
    if convert_ids {
        ensure!(
            retire_models.is_empty(),
            "model retirement and ID conversion require separate migrations"
        );
        ensure!(
            source.models.values().all(|r| r.identity.is_none())
                && next.models.values().all(|r| r.identity.is_some()),
            "mixed_id_migration_unsupported"
        );
    }
    for (name, old) in &source.models {
        if retire_models.contains(name) {
            continue;
        }
        let new = &next.models[name];
        ensure!(
            convert_ids || old.identity == new.identity,
            "model_identity_is_immutable: {name}"
        );
        ensure!(
            old.roc_type == new.roc_type,
            "nominal model identity change requires explicit migration: {name}"
        );
        for (field, kind) in &old.fields {
            let converted_reference = matches!((kind, new.fields.get(field)),
                (Kind::Reference { target }, Some(Kind::ModelReference { target: new_target, .. }))
                if convert_ids && target == new_target);
            ensure!(
                new.fields.get(field) == Some(kind) || converted_reference,
                "destructive or renamed field: {name}.{field}"
            );
        }
        for (field, kind) in &new.fields {
            if !old.fields.contains_key(field) {
                ensure!(
                    *kind == Kind::OptionalText,
                    "new required field needs an explicit backfill"
                );
                additions.push(AddColumn {
                    model: name.clone(),
                    field: field.clone(),
                });
            }
        }
    }
    next.validate()?;
    Ok(Plan {
        format: 1,
        scope: scope.to_owned(),
        source_artifact: source_id.to_owned(),
        target_artifact: target_id.to_owned(),
        source_schema: source_contract.schema_digest.clone(),
        target_schema: target.schema_digest.clone(),
        add_nullable_text: additions,
        add_indexes,
        retire_models,
        convert_ids,
    })
}

pub fn apply(runtime: &Runtime, target: &LoadedArtifact, supplied: &Plan) -> Result<()> {
    // Never execute SQL supplied by an operator or app. Recompute the checked transition.
    apply_plan(
        runtime.db(),
        &runtime.artifact().contract().schema,
        &target.contract().schema,
        supplied,
        &plan(runtime, target)?,
    )
}

fn apply_plan(
    path: &std::path::Path,
    source: &crate::schema::Schema,
    target: &crate::schema::Schema,
    supplied: &Plan,
    expected: &Plan,
) -> Result<()> {
    ensure!(supplied == expected, "migration_plan_mismatch");
    let id = supplied.id()?;
    let mut connection = open(path)?;
    // SQLite table replacement requires disabling automatic FK actions before
    // BEGIN. Explicit checks bracket the entire atomic rewrite instead.
    if supplied.convert_ids {
        connection.pragma_update(None, "foreign_keys", false)?;
    }
    let tx = crate::write_queue::immediate(&mut connection)?;
    let scope: String = tx.query_row("SELECT value FROM day2_meta WHERE key='scope'", [], |r| {
        r.get(0)
    })?;
    ensure!(scope == supplied.scope, "migration_scope_mismatch");
    let pending = runnable_pending(&tx)?;
    ensure!(pending == 0, "migration_requires_drained_invocations");
    let current: String =
        tx.query_row("SELECT value FROM day2_meta WHERE key='schema'", [], |r| {
            r.get(0)
        })?;
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT source,target FROM day2_migrations WHERE id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((source, target)) = existing {
        ensure!(
            source == supplied.source_schema
                && target == supplied.target_schema
                && current == target,
            "migration_journal_mismatch"
        );
        return Ok(());
    }
    ensure!(current == supplied.source_schema, "stale_migration_plan");
    if supplied.convert_ids {
        convert_ids(&tx, source, target)?;
    }
    for column in supplied
        .add_nullable_text
        .iter()
        .filter(|_| !supplied.convert_ids)
    {
        tx.execute_batch(&format!(
            "ALTER TABLE \"{}\" ADD COLUMN \"{}\" TEXT",
            column.model, column.field
        ))?;
    }
    // A UNIQUE index checks existing rows before the same transaction publishes
    // schema metadata. Duplicate data rolls back added columns and indexes too.
    for index in supplied
        .add_indexes
        .iter()
        .filter(|_| !supplied.convert_ids)
    {
        tx.execute_batch(&index.ddl())?;
    }
    // Retirement removes the model from admitted app handles, not from storage.
    // Keep its data and outgoing foreign keys intact, and reject accidental
    // writes even from tooling still referring to the former physical table.
    for model in &supplied.retire_models {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            let trigger = format!("day2_retired_{model}_{}", action.to_ascii_lowercase());
            tx.execute_batch(&format!(
                "CREATE TRIGGER \"{trigger}\" BEFORE {action} ON \"{model}\" BEGIN SELECT RAISE(ABORT,'retired_model'); END"
            ))?;
        }
    }
    tx.execute(
        "UPDATE day2_meta SET value=?1 WHERE key='schema'",
        [&supplied.target_schema],
    )?;
    tx.execute(
        "UPDATE day2_meta SET value=?1 WHERE key='schema_json'",
        [serde_json::to_string(target)?],
    )?;
    tx.execute(
        "INSERT INTO day2_migrations VALUES(?1,?2,?3)",
        params![id, supplied.source_schema, supplied.target_schema],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn activate(runtime: &Runtime, target: &LoadedArtifact) -> Result<()> {
    let expected = crate::authority_state::current(&open(runtime.db())?)?.stamp;
    let request_id = digest(&serde_json::to_vec(&(
        runtime.scope(),
        &expected,
        target.id(),
    ))?)
    .replace(':', "-");
    activate_checked(
        runtime,
        target,
        &crate::authority_state::LocalOperator::assert_local("local-platform-operator")?,
        &expected,
        &request_id,
    )?;
    Ok(())
}

/// Publish the artifact binding and compatible company authority together.
/// The instance document is desired configuration; this commit activates it.
pub fn activate_checked(
    runtime: &Runtime,
    target: &LoadedArtifact,
    operator: &crate::authority_state::LocalOperator,
    expected: &crate::authority_state::AuthorityStamp,
    request_id: &str,
) -> Result<crate::authority_state::AuthorityReceipt> {
    target.require_current_api()?;
    let instance = crate::artifact::Instance::load(runtime.instance_path())?;
    ensure!(
        instance.scope(runtime.app())? == runtime.scope(),
        crate::error::Failure::InstallationChanged
    );
    let source = crate::authority_state::desired_fingerprint(
        &instance,
        runtime.app(),
        operator,
        &Some(expected.clone()),
        Some(target),
    )?;
    let mut connection = open(runtime.db())?;
    let connection = crate::write_queue::immediate(&mut connection)?;
    crate::authority_state::upgrade(&connection)?;
    let scope: String =
        connection.query_row("SELECT value FROM day2_meta WHERE key='scope'", [], |r| {
            r.get(0)
        })?;
    ensure!(
        scope == runtime.scope(),
        crate::error::Failure::InstallationChanged
    );
    if let Some(receipt) =
        crate::authority_state::cached_desired_receipt_in(&connection, request_id, &source)?
    {
        return Ok(receipt);
    }
    let change = crate::authority_state::ApplyAuthority {
        request_id: request_id.into(),
        expected: Some(expected.clone()),
        document: crate::authority_state::AuthorityDocument::resolve_at(
            &instance,
            runtime.app(),
            target,
            runtime.host().now_ms()?,
        )?,
    };
    if let Some(receipt) =
        crate::authority_state::activation_receipt_in(&connection, target, operator, &change)?
    {
        crate::authority_state::pin_desired_receipt_in(&connection, request_id, &source, &receipt)?;
        connection.commit()?;
        return Ok(receipt);
    }
    runtime
        .artifact()
        .contract()
        .identities
        .check_successor(&target.contract().identities)?;
    let schema: String =
        connection.query_row("SELECT value FROM day2_meta WHERE key='schema'", [], |r| {
            r.get(0)
        })?;
    let pending = runnable_pending(&connection)?;
    ensure!(
        scope == runtime.scope() && schema == target.contract().schema_digest && pending == 0,
        "activation_precondition_failed"
    );
    crate::deferrals::check_compatible(&connection, target)?;
    if let Some(contract) = &target.contract().app_contract {
        crate::domain::validate_storage(&connection, &target.contract().schema, &contract.domains)?;
    }
    let receipt =
        crate::authority_state::apply_binding_in(&connection, runtime, target, operator, &change)?;
    crate::authority_state::pin_desired_receipt_in(&connection, request_id, &source, &receipt)?;
    connection.commit()?;
    Ok(receipt)
}

/// Revoked work cannot run business phases again and does not prevent an
/// upgrade. Its admitted external attempts may only settle immutable evidence,
/// independently of the newly active artifact and business schema.
fn runnable_pending(connection: &Connection) -> Result<i64> {
    let blocks: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_authority_blocks')",
        [],
        |row| row.get(0),
    )?;
    let query = if blocks {
        "SELECT count(*) FROM day2_invocations i WHERE status='pending'
         AND NOT EXISTS(SELECT 1 FROM day2_authority_blocks b WHERE b.invocation=i.id)"
    } else {
        "SELECT count(*) FROM day2_invocations WHERE status='pending'"
    };
    Ok(connection.query_row(query, [], |row| row.get(0))?)
}

fn foreign_keys_valid(connection: &Connection) -> Result<()> {
    let mut check = connection.prepare("PRAGMA foreign_key_check")?;
    ensure!(
        check.query([])?.next()?.is_none(),
        "migration_foreign_key_violation"
    );
    Ok(())
}

/// Rewrite primary and foreign keys together. The caller owns an IMMEDIATE
/// transaction with FK actions disabled; any failure rolls back every change.
fn convert_ids(
    connection: &Connection,
    source: &crate::schema::Schema,
    target: &crate::schema::Schema,
) -> Result<()> {
    use anyhow::Context;
    use std::collections::BTreeMap;
    foreign_keys_valid(connection)?;
    connection.execute_batch(
        "CREATE TABLE day2_id_mappings (
            model TEXT NOT NULL, legacy_id INTEGER NOT NULL CHECK(legacy_id > 0),
            id BLOB NOT NULL CHECK(length(id) = 16),
            PRIMARY KEY(model,legacy_id), UNIQUE(model,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS day2_id_seeds (
            invocation TEXT PRIMARY KEY REFERENCES day2_invocations(id),
            seed BLOB NOT NULL CHECK(length(seed)=32)
        ) STRICT;",
    )?;
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|error| anyhow::anyhow!("migration entropy: {error}"))?;
    for (name, record) in &target.models {
        let identity = record.identity.as_ref().context("missing_model_identity")?;
        let mut statement =
            connection.prepare(&format!("SELECT id,created_at FROM \"{name}\" ORDER BY id"))?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let old: i64 = row.get(0)?;
            let created_at: i64 = row.get(1)?;
            let millis = u64::try_from(created_at)?
                .checked_mul(1000)
                .context("invalid_uuid_clock")?;
            let bytes =
                crate::identity::generate(&seed, millis, &identity.key, u64::try_from(old)?)?;
            connection.execute(
                "INSERT INTO day2_id_mappings VALUES(?1,?2,?3)",
                params![identity.key, old, bytes.as_slice()],
            )?;
        }
    }
    let tables: BTreeMap<String, String> = target
        .models
        .keys()
        .map(|name| (name.clone(), format!("day2_uuid_{name}")))
        .collect();
    for ddl in target.ddl_with_tables(&tables, false)? {
        connection.execute_batch(&ddl)?;
    }
    for (name, record) in &target.models {
        let identity = record.identity.as_ref().context("missing_model_identity")?;
        // Registry keys are validated lowercase hex; identifiers come from the
        // checked schema. No supplied migration SQL reaches this statement.
        let lookup = |key: &str, field: &str| {
            format!(
                "(SELECT id FROM day2_id_mappings WHERE model='{key}' AND legacy_id=old.\"{field}\")"
            )
        };
        let mut fields = vec![
            "\"id\"".to_string(),
            "\"version\"".into(),
            "\"created_at\"".into(),
        ];
        let mut values = vec![
            lookup(&identity.key, "id"),
            "old.version".into(),
            "old.created_at".into(),
        ];
        for (field, kind) in &record.fields {
            fields.push(format!("\"{field}\""));
            values.push(if !source.models[name].fields.contains_key(field) {
                "NULL".into()
            } else if let Kind::ModelReference {
                target: referenced, ..
            } = kind
            {
                lookup(
                    &target.models[referenced]
                        .identity
                        .as_ref()
                        .context("missing_model_identity")?
                        .key,
                    field,
                )
            } else {
                format!("old.\"{field}\"")
            });
        }
        connection.execute_batch(&format!(
            "INSERT INTO \"{}\" ({}) SELECT {} FROM \"{name}\" AS old",
            tables[name],
            fields.join(","),
            values.join(",")
        ))?;
    }
    for name in source.models.keys() {
        connection.execute_batch(&format!("DROP TABLE \"{name}\""))?;
    }
    for (name, temporary) in &tables {
        connection.execute_batch(&format!("ALTER TABLE \"{temporary}\" RENAME TO \"{name}\""))?;
    }
    for ddl in target.ddl()?.into_iter().skip(target.models.len()) {
        connection.execute_batch(&ddl)?;
    }
    foreign_keys_valid(connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::TransactionBehavior;

    #[test]
    fn explicit_retirement_preserves_rows_audit_and_indexes_and_freezes_archived_models()
    -> Result<()> {
        use serde_json::json;
        let (_, mut schema) = id_schemas()?;
        schema
            .models
            .get_mut("parents")
            .unwrap()
            .fields
            .remove("note");
        schema.indexes.push(crate::schema::Index {
            model: "children".into(),
            name: "by_title".into(),
            fields: vec!["title".into()],
            unique: true,
        });
        let registry = crate::identity::Registry {
            format: 1,
            models: schema
                .models
                .iter()
                .map(|(table, record)| crate::identity::Registration {
                    identity: record.identity.clone().unwrap(),
                    table: table.clone(),
                    roc_type: record.roc_type.clone().unwrap(),
                    retired: false,
                })
                .collect(),
        };
        let source: crate::artifact::Artifact = serde_json::from_value(json!({
            "format":12,"roc_version":"test","worker_digest":"test",
            "schema_digest":schema.hash()?, "schema":schema,"identities":registry,
            "operations":[],"sources":{},"admission":"local-spike-only"
        }))?;
        let mut target = source.clone();
        target.schema.models.remove("children");
        target.schema.foreign_keys.clear();
        target
            .schema
            .indexes
            .retain(|index| index.model != "children");
        target
            .schema
            .models
            .get_mut("parents")
            .unwrap()
            .fields
            .insert("note".into(), Kind::OptionalText);
        target.schema_digest = target.schema.hash()?;
        let make_plan = |target: &crate::artifact::Artifact| {
            plan_contracts("test/local/retirement", "source", &source, "target", target)
        };
        assert!(
            make_plan(&target)
                .unwrap_err()
                .to_string()
                .contains("explicit model retirement")
        );
        target
            .identities
            .models
            .iter_mut()
            .find(|model| model.table == "children")
            .unwrap()
            .retired = true;
        let expected = make_plan(&target)?;
        assert_eq!(expected.retire_models, ["children"]);
        assert!(!expected.convert_ids);
        let mut rewritten = target.clone();
        rewritten
            .identities
            .models
            .iter_mut()
            .find(|model| model.table == "children")
            .unwrap()
            .roc_type = "Models.Forged".into();
        assert!(make_plan(&rewritten).is_err());
        let mut active_reference = source.clone();
        active_reference.schema.models.remove("parents");
        active_reference
            .identities
            .models
            .iter_mut()
            .find(|model| model.table == "parents")
            .unwrap()
            .retired = true;
        assert!(make_plan(&active_reference).is_err());

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("retirement.sqlite");
        let connection = open(&path)?;
        for ddl in source.schema.ddl()? {
            connection.execute_batch(&ddl)?;
        }
        connection.execute_batch(
            "CREATE TABLE day2_meta(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE day2_migrations(id TEXT PRIMARY KEY,source TEXT,target TEXT);
            CREATE TABLE day2_invocations(id TEXT PRIMARY KEY,status TEXT);
            CREATE TABLE day2_audit(invocation TEXT PRIMARY KEY,actor TEXT);
            INSERT INTO day2_audit VALUES('historic','alice');
            INSERT INTO parents(id,version,created_at,title) VALUES(x'01800000000070008000000000000001',3,100,'Parent');
            INSERT INTO children(id,version,created_at,parent_id,title) VALUES(x'01800000000070008000000000000002',4,101,x'01800000000070008000000000000001','Historic event');"
        )?;
        for (key, value) in [
            ("scope", "test/local/retirement".into()),
            ("schema", source.schema.hash()?),
            ("schema_json", serde_json::to_string(&source.schema)?),
        ] {
            connection.execute("INSERT INTO day2_meta VALUES(?1,?2)", params![key, value])?;
        }
        let apply =
            |plan: &Plan| apply_plan(&path, &source.schema, &target.schema, plan, &expected);
        let mut forged = expected.clone();
        forged.retire_models.clear();
        assert_eq!(
            apply(&forged).unwrap_err().to_string(),
            "migration_plan_mismatch"
        );
        connection.execute(
            "INSERT INTO day2_invocations VALUES('pending','pending')",
            [],
        )?;
        assert_eq!(
            apply(&expected).unwrap_err().to_string(),
            "migration_requires_drained_invocations"
        );
        connection.execute("UPDATE day2_invocations SET status='success'", [])?;
        connection.execute_batch("CREATE TRIGGER day2_retired_children_insert BEFORE UPDATE ON parents BEGIN SELECT 1; END")?;
        assert!(apply(&expected).is_err());
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM pragma_table_info('parents') WHERE name='note'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT value FROM day2_meta WHERE key='schema'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            source.schema.hash()?
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_migrations", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        connection.execute_batch("DROP TRIGGER day2_retired_children_insert")?;
        apply(&expected)?;
        apply(&expected)?;
        assert_eq!(
            connection.query_row("SELECT version,created_at,title FROM children", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?,
            (4, 101, "Historic event".into())
        );
        assert_eq!(
            connection.query_row(
                "SELECT actor FROM day2_audit WHERE invocation='historic'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "alice"
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_migrations", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        for sql in [
            "UPDATE children SET title='changed'",
            "DELETE FROM children",
            "INSERT INTO children SELECT * FROM children",
            "INSERT OR REPLACE INTO children SELECT * FROM children",
        ] {
            assert!(
                connection
                    .execute(sql, [])
                    .unwrap_err()
                    .to_string()
                    .contains("retired_model")
            );
        }
        connection.execute("UPDATE parents SET note='still active'", [])?;
        foreign_keys_valid(&connection)?;
        let indexes: i64 = connection.query_row("SELECT count(*) FROM sqlite_master WHERE type='index' AND tbl_name='children' AND sql LIKE '%UNIQUE%'", [], |row| row.get(0))?;
        assert_eq!(indexes, 1);
        Ok(())
    }

    fn id_schemas() -> Result<(crate::schema::Schema, crate::schema::Schema)> {
        let old: crate::schema::Schema = serde_json::from_value(serde_json::json!({
            "models": {
                "parents": {"roc_type":"Models.Parent", "fields":{"title":"text"}},
                "children": {"roc_type":"Models.Child", "fields":{"parent_id":{"reference":{"target":"parents"}},"title":"text"}}
            }, "inputs":{"create":{"roc_type":"Contracts.Create","fields":{"title":"text"}}},
            "foreign_keys":[{"model":"children","field":"parent_id","target":"parents"}]
        }))?;
        let mut new = old.clone();
        let mut registry = crate::identity::Registry::default();
        registry.synchronize(&old.models)?;
        new.bind_identities(&registry)?;
        new.models
            .get_mut("parents")
            .unwrap()
            .fields
            .insert("note".into(), Kind::OptionalText);
        new.indexes.push(crate::schema::Index {
            model: "parents".into(),
            name: "by_title".into(),
            fields: vec!["title".into()],
            unique: true,
        });
        Ok((old, new))
    }

    #[test]
    fn integer_migration_preserves_rows_revisions_and_remaps_foreign_keys_atomically() -> Result<()>
    {
        let (old, new) = id_schemas()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("data.sqlite");
        {
            let mut connection = Connection::open(&path)?;
            connection.pragma_update(None, "foreign_keys", false)?;
            for ddl in old.ddl()? {
                connection.execute_batch(&ddl)?;
            }
            connection.execute_batch(
                "CREATE TABLE day2_invocations(id TEXT PRIMARY KEY);
                INSERT INTO parents(id,version,created_at,title) VALUES(1,3,100,'Parent');
                INSERT INTO parents(id,version,created_at,title) VALUES(9223372036854775807,1,101,'Large legacy ID');
                INSERT INTO children(id,version,created_at,parent_id,title) VALUES(2,4,102,1,'Child');",
            )?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            convert_ids(&tx, &old, &new)?;
            tx.commit()?;
        }
        let connection = open(&path)?;
        foreign_keys_valid(&connection)?;
        let (parent, child, foreign, version, created, title, note) = connection.query_row(
            "SELECT p.id,c.id,c.parent_id,c.version,c.created_at,c.title,p.note FROM children c JOIN parents p ON p.id=c.parent_id", [],
            |r| Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,r.get::<_,String>(5)?,r.get::<_,Option<String>>(6)?))
        )?;
        assert_eq!(parent.len(), 16);
        assert_eq!(child.len(), 16);
        assert_eq!(parent, foreign);
        assert_eq!(
            (version, created, title.as_str(), note),
            (4, 102, "Child", None)
        );
        let parent_id = crate::identity::Id::from_uuid("par", parent.clone().try_into().unwrap())?;
        assert!(parent_id.to_string().starts_with("par_"));
        assert_eq!(parent_id.bytes_for("par")?.as_slice(), parent.as_slice());
        let count: i64 =
            connection.query_row("SELECT count(*) FROM day2_id_mappings", [], |r| r.get(0))?;
        assert_eq!(count, 3);
        assert!(
            connection
                .execute("DELETE FROM parents WHERE id=?1", [parent])
                .is_err()
        );
        assert!(
            connection
                .execute("UPDATE children SET parent_id=?1", [vec![0_u8; 16]])
                .is_err()
        );
        assert!(
            connection
                .execute("UPDATE children SET id=?1", [vec![0_u8; 8]])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn failed_id_migration_leaves_original_tables_and_no_partial_mappings() -> Result<()> {
        let (old, new) = id_schemas()?;
        for poison in [
            "INSERT INTO children(id,version,created_at,parent_id,title) VALUES(2,1,100,999,'Orphan')",
            "INSERT INTO parents(id,version,created_at,title) VALUES(1,1,-1,'Bad timestamp')",
            "INSERT INTO parents(id,version,created_at,title) VALUES(1,1,100,'Duplicate'),(2,1,100,'Duplicate')",
        ] {
            let mut connection = Connection::open_in_memory()?;
            connection.pragma_update(None, "foreign_keys", false)?;
            for ddl in old.ddl()? {
                connection.execute_batch(&ddl)?;
            }
            connection.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY)")?;
            connection.execute_batch(poison)?;
            {
                let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert!(convert_ids(&tx, &old, &new).is_err());
            }
            let mappings: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='day2_id_mappings')",
                [],
                |r| r.get(0),
            )?;
            assert!(!mappings);
            let kind: String = connection.query_row(
                "SELECT type FROM pragma_table_info('parents') WHERE name='id'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(kind, "INTEGER");
        }
        Ok(())
    }

    #[test]
    fn id_migration_plan_requires_drain_is_idempotent_and_protects_registered_prefixes()
    -> Result<()> {
        use serde_json::json;
        let (old, new) = id_schemas()?;
        let mut registry = crate::identity::Registry::default();
        for (table, record) in &new.models {
            registry.models.push(crate::identity::Registration {
                identity: record.identity.clone().unwrap(),
                table: table.clone(),
                roc_type: record.roc_type.clone().unwrap(),
                retired: false,
            });
        }
        let artifact = |schema: &crate::schema::Schema,
                        format,
                        identities: &crate::identity::Registry|
         -> Result<crate::artifact::Artifact> {
            let value = json!({"format":format,"roc_version":"test","worker_digest":"test", "schema_digest":schema.hash()?,
                "schema":schema,"identities":identities,"operations":[],"sources":{},"admission":"local-spike-only"});
            Ok(serde_json::from_value(value)?)
        };
        let directory = tempfile::tempdir()?;
        let db = directory.path().join("data.sqlite");
        let source = artifact(&old, 10, &crate::identity::Registry::default())?;
        let target = artifact(&new, 11, &registry)?;
        let make_plan = |source: &crate::artifact::Artifact, target: &crate::artifact::Artifact| {
            plan_contracts(
                "example/local/test",
                &digest(&serde_json::to_vec(source)?),
                source,
                &digest(&serde_json::to_vec(target)?),
                target,
            )
        };
        let apply = |supplied: &Plan| -> Result<()> {
            apply_plan(
                &db,
                &source.schema,
                &target.schema,
                supplied,
                &make_plan(&source, &target)?,
            )
        };
        let connection = open(&db)?;
        for ddl in old.ddl()? {
            connection.execute_batch(&ddl)?;
        }
        connection.execute_batch(
            "CREATE TABLE day2_meta(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE day2_migrations(id TEXT PRIMARY KEY,source TEXT,target TEXT);
            CREATE TABLE day2_invocations(id TEXT PRIMARY KEY,status TEXT);
            INSERT INTO parents(id,version,created_at,title) VALUES(1,2,100,'Parent');
            INSERT INTO children(id,version,created_at,parent_id,title) VALUES(3,4,101,1,'Child');
            INSERT INTO day2_invocations VALUES('pending','pending');",
        )?;
        for (key, value) in [
            ("scope", "example/local/test".to_owned()),
            ("schema", old.hash()?),
            ("schema_json", serde_json::to_string(&old)?),
        ] {
            connection.execute("INSERT INTO day2_meta VALUES(?1,?2)", params![key, value])?;
        }
        let transition = make_plan(&source, &target)?;
        let mut destructive = target.clone();
        let field = source.schema.models["parents"]
            .fields
            .keys()
            .next()
            .unwrap()
            .clone();
        destructive
            .schema
            .models
            .get_mut("parents")
            .unwrap()
            .fields
            .remove(&field);
        assert!(
            make_plan(&source, &destructive)
                .unwrap_err()
                .to_string()
                .contains("destructive")
        );
        assert!(transition.convert_ids);
        assert_eq!(
            apply(&transition).unwrap_err().to_string(),
            "migration_requires_drained_invocations"
        );
        connection.execute("UPDATE day2_invocations SET status='success'", [])?;
        let mut forged = transition.clone();
        forged.convert_ids = false;
        assert_eq!(
            apply(&forged).unwrap_err().to_string(),
            "migration_plan_mismatch"
        );
        apply(&transition)?;
        let id: Vec<u8> = connection.query_row("SELECT id FROM parents", [], |r| r.get(0))?;
        apply(&transition)?;
        assert_eq!(
            connection.query_row("SELECT id FROM parents", [], |r| r.get::<_, Vec<u8>>(0))?,
            id
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_migrations", [], |r| r
                .get::<_, i64>(0))?,
            1
        );
        foreign_keys_valid(&connection)?;
        let mut changed = target.clone();
        changed.identities.models[0].identity.prefix = "changed".into();
        assert!(make_plan(&target, &changed).is_err());
        assert!(
            target
                .identities
                .check_successor(&changed.identities)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn unique_index_migration_rejects_existing_duplicates_without_publishing_or_partial_ddl()
    -> Result<()> {
        use serde_json::json;
        let source_schema: crate::schema::Schema = serde_json::from_value(json!({
            "models":{"entries":{"roc_type":"Models.Entry","fields":{"account":"text","name":"text"}}},
            "inputs":{}, "foreign_keys":[]
        }))?;
        let mut target_schema = source_schema.clone();
        target_schema
            .models
            .get_mut("entries")
            .unwrap()
            .fields
            .insert("note".into(), Kind::OptionalText);
        target_schema.indexes = vec![
            crate::schema::Index {
                model: "entries".into(),
                name: "by_account".into(),
                fields: vec!["account".into()],
                unique: false,
            },
            crate::schema::Index {
                model: "entries".into(),
                name: "by_account_name".into(),
                fields: vec!["account".into(), "name".into()],
                unique: true,
            },
        ];
        let artifact = |schema: &crate::schema::Schema| -> Result<crate::artifact::Artifact> {
            Ok(serde_json::from_value(
                json!({"format":10,"roc_version":"test","worker_digest":"test",
                "schema_digest":schema.hash()?, "schema":schema,"operations":[],"sources":{},"admission":"local-spike-only"}),
            )?)
        };
        let source = artifact(&source_schema)?;
        let target = artifact(&target_schema)?;
        let expected = plan_contracts("test/local/indexes", "source", &source, "target", &target)?;
        assert_eq!(expected.add_indexes, target_schema.indexes);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("indexes.sqlite");
        let connection = open(&path)?;
        for ddl in source_schema.ddl()? {
            connection.execute_batch(&ddl)?;
        }
        connection.execute_batch(
            "CREATE TABLE day2_meta(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE day2_migrations(id TEXT PRIMARY KEY,source TEXT,target TEXT);
            CREATE TABLE day2_invocations(id TEXT PRIMARY KEY,status TEXT);
            INSERT INTO entries(id,version,created_at,account,name) VALUES(1,1,0,'a','home'),(2,1,0,'a','home');",
        )?;
        for (key, value) in [
            ("scope", "test/local/indexes".into()),
            ("schema", source_schema.hash()?),
            ("schema_json", serde_json::to_string(&source_schema)?),
        ] {
            connection.execute("INSERT INTO day2_meta VALUES(?1,?2)", params![key, value])?;
        }
        let error =
            apply_plan(&path, &source_schema, &target_schema, &expected, &expected).unwrap_err();
        assert!(
            error.to_string().contains("UNIQUE constraint failed"),
            "{error:#}"
        );
        assert_eq!(
            connection.query_row(
                "SELECT value FROM day2_meta WHERE key='schema'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            source_schema.hash()?
        );
        assert_eq!(
            connection.query_row(
                "SELECT value FROM day2_meta WHERE key='schema_json'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            serde_json::to_string(&source_schema)?
        );
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM pragma_table_info('entries') WHERE name='note'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'day2_decl_%'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_migrations", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        connection.execute("UPDATE entries SET account='b' WHERE id=2", [])?;
        apply_plan(&path, &source_schema, &target_schema, &expected, &expected)?;
        apply_plan(&path, &source_schema, &target_schema, &expected, &expected)?;
        assert_eq!(
            connection.query_row(
                "SELECT value FROM day2_meta WHERE key='schema'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            target_schema.hash()?
        );
        assert_eq!(
            connection.query_row("SELECT count(*) FROM day2_migrations", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert!(
            connection
                .execute("UPDATE entries SET account='a' WHERE id=2", [])
                .is_err()
        );
        let mut dropped = target.clone();
        dropped.schema.indexes.pop();
        assert!(
            plan_contracts("test/local/indexes", "target", &target, "dropped", &dropped)
                .unwrap_err()
                .to_string()
                .contains("index removal")
        );
        let mut redefined = target.clone();
        redefined.schema.indexes[1].unique = false;
        assert!(
            plan_contracts(
                "test/local/indexes",
                "target",
                &target,
                "redefined",
                &redefined
            )
            .unwrap_err()
            .to_string()
            .contains("index removal")
        );
        Ok(())
    }
}
