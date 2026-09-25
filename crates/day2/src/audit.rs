use crate::{
    protocol::{Request, Row},
    store::{Runtime, open},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

// Host schema upgrades are independent of app model migrations. Existing business
// tables and old receipts are untouched; legacy receipts have no fabricated diff.
pub(crate) const PRINCIPALS_DDL: &str = "CREATE TABLE IF NOT EXISTS day2_principals(
    email TEXT PRIMARY KEY CHECK(length(email) BETWEEN 3 AND 320),
    subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 255),
    first_seen INTEGER NOT NULL) STRICT";

pub(crate) fn upgrade(db: &Connection) -> Result<()> {
    let version: Option<String> = db
        .query_row(
            "SELECT value FROM day2_meta WHERE key='host_schema'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        !db.is_autocommit(),
        "audit schema upgrade requires transaction"
    );
    if let Some(version) = &version {
        ensure!(
            ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"].contains(&version.as_str()),
            "unknown_host_schema"
        );
    }
    if version.is_none() {
        db.execute_batch("
        CREATE TABLE day2_audit_changes(
            invocation TEXT NOT NULL REFERENCES day2_invocations(id), ordinal INTEGER NOT NULL,
            model TEXT NOT NULL, record_id TEXT NOT NULL, before_version INTEGER,
            after_version INTEGER NOT NULL, fields TEXT NOT NULL,
            PRIMARY KEY(invocation,ordinal)) STRICT;
        CREATE INDEX day2_audit_record ON day2_audit_changes(model,record_id);
        CREATE TABLE day2_web_events(
            sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT,
            category TEXT NOT NULL, status INTEGER NOT NULL) STRICT;
        CREATE TABLE day2_web_sessions(
            hash TEXT PRIMARY KEY, actor TEXT NOT NULL, expires INTEGER NOT NULL) STRICT;
        CREATE TABLE day2_web_secret(id INTEGER PRIMARY KEY CHECK(id=1), secret BLOB NOT NULL) STRICT;
        CREATE TRIGGER day2_audit_no_update BEFORE UPDATE ON day2_audit BEGIN SELECT RAISE(ABORT,'append_only_audit'); END;
        CREATE TRIGGER day2_audit_no_delete BEFORE DELETE ON day2_audit BEGIN SELECT RAISE(ABORT,'append_only_audit'); END;
        CREATE TRIGGER day2_changes_no_update BEFORE UPDATE ON day2_audit_changes BEGIN SELECT RAISE(ABORT,'append_only_audit'); END;
        CREATE TRIGGER day2_changes_no_delete BEFORE DELETE ON day2_audit_changes BEGIN SELECT RAISE(ABORT,'append_only_audit'); END;
        CREATE TRIGGER day2_events_no_update BEFORE UPDATE ON day2_web_events BEGIN SELECT RAISE(ABORT,'append_only_audit'); END;
        CREATE TRIGGER day2_events_no_delete BEFORE DELETE ON day2_web_events BEGIN SELECT RAISE(ABORT,'append_only_audit'); END;
        INSERT INTO day2_meta VALUES('host_schema','9');
    ")?;
    }
    ensure_event_stream(db)?;
    // Steps run when the database is *below* a version, not when it differs from
    // one. Gating on inequality meant every added version silently re-ran an
    // earlier step, which is how schema 4 first tried to recreate schema 2's
    // triggers on a database that already had them.
    let at: u32 = version.as_deref().unwrap_or("1").parse().unwrap_or(1);
    if at < 2 {
        for (_, sql) in RECEIPT_TRIGGERS {
            db.execute_batch(sql)?;
        }
        db.execute("UPDATE day2_meta SET value='2' WHERE key='host_schema'", [])?;
    }
    // Schema 3 records what caused an invocation. Existing rows are requests: an
    // actor asked for them, because nothing else could create one before this.
    if at < 3 {
        let columns: i64 = db.query_row(
            "SELECT count(*) FROM pragma_table_info('day2_invocations') WHERE name='trigger'",
            [],
            |row| row.get(0),
        )?;
        if columns == 0 {
            db.execute_batch(
                "ALTER TABLE day2_invocations ADD COLUMN trigger TEXT NOT NULL DEFAULT 'request'
                 CHECK(length(trigger) BETWEEN 1 AND 32)",
            )?;
        }
        // The receipt trigger now projects the cause, so it must be replaced rather
        // than left at its earlier definition.
        db.execute_batch("DROP TRIGGER IF EXISTS day2_receipt_event")?;
        for (name, sql) in RECEIPT_TRIGGERS {
            if *name == "day2_receipt_event" {
                db.execute_batch(sql)?;
            }
        }
        db.execute("UPDATE day2_meta SET value='3' WHERE key='host_schema'", [])?;
    }
    // Schema 4 widens the trigger constraint from an enumeration of causes to a
    // shape. Enumerating them made each new cause a schema migration, which is the
    // wrong cost for a list that RADICAL expects to grow — schedules, events and
    // webhook triggers. The Rust `Trigger` enum remains the authority for which
    // causes exist; the column only refuses nonsense.
    if at < 4 {
        widen_trigger(db, "day2_invocations")?;
        db.execute("UPDATE day2_meta SET value='4' WHERE key='host_schema'", [])?;
    }
    // Schema 5 gives every application table a deleted_at column.
    //
    // The platform has no hard delete: application code marks a row deleted and
    // nothing removes it. Existing instances were created before the column
    // existed, so their tables are altered in place rather than rebuilt —
    // ALTER TABLE ADD COLUMN with a default is a metadata-only change in SQLite,
    // so this is cheap even on large tables.
    //
    // Discovered from sqlite_master rather than from the app's declared schema:
    // the column belongs to every model table whatever the artifact currently
    // says, and an instance mid-migration may hold tables the current schema no
    // longer names. Platform tables are excluded by prefix; they are host state
    // and are never soft-deleted.
    if at < 5 {
        let tables: Vec<String> = db
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' \
                 AND name NOT LIKE 'day2_%' AND name NOT LIKE 'sqlite_%'",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for table in tables {
            let present: i64 = db.query_row(
                "SELECT count(*) FROM pragma_table_info(?1) WHERE name='deleted_at'",
                [&table],
                |row| row.get(0),
            )?;
            if present == 0 {
                db.execute_batch(&format!(
                    "ALTER TABLE \"{table}\" ADD COLUMN deleted_at INTEGER NOT NULL \
                     DEFAULT 0 CHECK(deleted_at >= 0)"
                ))?;
            }
        }
        db.execute("UPDATE day2_meta SET value='5' WHERE key='host_schema'", [])?;
    }
    // Schema 6 records removals.
    //
    // Retention is the only thing in the platform that destroys anything, so it
    // is the one act whose record has to outlive what it acted on. The row is
    // gone; this says it existed, when it was created, when it was deleted, who
    // removed it and under which policy. Append-only like the rest of the audit,
    // and carrying no field values — a record of a removal that quoted the row
    // would keep the data the removal was for.
    if at < 6 {
        // Guarded on the table rather than on the version, because the version
        // is not the only thing that says whether this step has run: a database
        // whose `host_schema` was reset — a repeatability test, a recovery —
        // arrives here with the table already present, and re-creating it would
        // fail the upgrade and take the audit down with it.
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
             AND name='day2_retention_removals')",
            [],
            |row| row.get(0),
        )?;
        if !exists {
            db.execute_batch(REMOVALS_DDL)?;
            for (_, sql) in REMOVAL_TRIGGERS {
                db.execute_batch(sql)?;
            }
        }
        db.execute("UPDATE day2_meta SET value='6' WHERE key='host_schema'", [])?;
    }
    // Schema 7 records which applications an invocation passed through.
    //
    // Empty for everything that entered from outside the instance, which is
    // every invocation that predates delegation and most of them afterwards. A
    // delegated call records the chain so that "who asked for this" is
    // answerable from the record rather than reconstructed by joining two apps'
    // audit logs on a timestamp, and so that a cycle is refusable before it is
    // a loop rather than after it is a bill.
    if at < 7 {
        let present: i64 = db.query_row(
            "SELECT count(*) FROM pragma_table_info('day2_invocations') WHERE name='caller'",
            [],
            |row| row.get(0),
        )?;
        if present == 0 {
            db.execute_batch(
                "ALTER TABLE day2_invocations ADD COLUMN caller TEXT NOT NULL DEFAULT ''
                 CHECK(length(caller) <= 512)",
            )?;
        }
        db.execute("UPDATE day2_meta SET value='7' WHERE key='host_schema'", [])?;
    }
    // Schema 8 separates who authenticated from whom the work is for.
    //
    // Equal for every invocation that predates impersonation and for most of
    // them afterwards, which is why `authenticated` is empty by default and read
    // as "the same principal". They differ when a service acts for a human or an
    // administrator acts for a customer, and then both have to survive: an audit
    // holding only the effective principal attributes an administrator's action
    // to the customer, and one holding only the authenticated principal cannot
    // say what was done or to whom. The rule that permitted it is recorded
    // beside them, so a removed rule does not erase which rule applied.
    if at < 8 {
        for (column, definition) in [
            (
                "authenticated",
                "TEXT NOT NULL DEFAULT '' CHECK(length(authenticated) <= 512)",
            ),
            (
                "delegation_rule",
                "TEXT NOT NULL DEFAULT '' CHECK(length(delegation_rule) <= 160)",
            ),
        ] {
            let present: i64 = db.query_row(
                "SELECT count(*) FROM pragma_table_info('day2_invocations') WHERE name=?1",
                [column],
                |row| row.get(0),
            )?;
            if present == 0 {
                db.execute_batch(&format!(
                    "ALTER TABLE day2_invocations ADD COLUMN {column} {definition}"
                ))?;
            }
        }
        // The receipt trigger now reads the authenticated principal into the
        // stream's `initiator`. Its text is pinned and re-validated below, so an
        // existing database has to be moved to the new definition here rather
        // than failing later as a changed guard — which is what a silently
        // edited audit guard should look like, and this is not one.
        for (name, sql) in RECEIPT_TRIGGERS
            .iter()
            .filter(|(name, _)| *name == "day2_receipt_event")
        {
            db.execute_batch(&format!("DROP TRIGGER IF EXISTS {name}"))?;
            db.execute_batch(sql)?;
        }
        db.execute("UPDATE day2_meta SET value='8' WHERE key='host_schema'", [])?;
    }
    // Schema 9 binds each person's address to the account behind it.
    //
    // The edge admits people by the address in their identity assertion, and
    // an address is not a person: an account deleted and recreated under the
    // same name — a departed employee's address given to a new hire — is a
    // different account with the same address. Google's subject id is never
    // reused, so the first subject seen for an address is recorded and every
    // later request must present it. See `crate::iap`.
    if at < 9 {
        db.execute_batch(PRINCIPALS_DDL)?;
        db.execute("UPDATE day2_meta SET value='9' WHERE key='host_schema'", [])?;
    }
    // Schema 10 lets a completed invocation keep a receipt in place of its input
    // and trace. See `crate::journal`.
    if at < 10 {
        let columns: i64 = db.query_row(
            "SELECT count(*) FROM pragma_table_info('day2_invocations') WHERE name='receipt'",
            [],
            |row| row.get(0),
        )?;
        if columns == 0 {
            db.execute_batch("ALTER TABLE day2_invocations ADD COLUMN receipt TEXT")?;
        }
        // Compaction looks for the oldest completed invocations that still carry a
        // trace; once compacted a row leaves this index, so it stays small.
        db.execute_batch(
            "CREATE INDEX IF NOT EXISTS day2_invocations_uncompacted ON day2_invocations(now)
             WHERE trace IS NOT NULL AND status IN ('success','failure')",
        )?;
        db.execute(
            "UPDATE day2_meta SET value='10' WHERE key='host_schema'",
            [],
        )?;
    }
    for (name, sql) in APPEND_TRIGGERS
        .iter()
        .chain(RECEIPT_TRIGGERS)
        .chain(REMOVAL_TRIGGERS)
    {
        validate_trigger(db, name, sql)?;
    }
    crate::live::upgrade(db)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS day2_audit_cursors(
        token TEXT PRIMARY KEY CHECK(length(token)=69), binding TEXT NOT NULL,
        before_sequence INTEGER NOT NULL CHECK(before_sequence>0), expires_at INTEGER NOT NULL,
        UNIQUE(binding,before_sequence)) STRICT;
        CREATE INDEX IF NOT EXISTS day2_audit_cursors_expiry ON day2_audit_cursors(expires_at);",
    )?;
    Ok(())
}

/// Replace the `trigger` column with one whose constraint checks shape rather than
/// enumerating values, preserving what every existing row recorded.
///
/// SQLite cannot alter a CHECK in place, but it can drop a column whose only CHECK
/// refers to itself, so this is a column swap rather than a table rebuild — no
/// foreign key pointing at `day2_invocations` is disturbed.
fn widen_trigger(db: &Connection, table: &str) -> Result<()> {
    let enumerated: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name=?1 AND sql LIKE '%trigger IN (%')",
        [table],
        |row| row.get(0),
    )?;
    if !enumerated {
        return Ok(());
    }
    db.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN trigger_widened TEXT NOT NULL DEFAULT 'request'
             CHECK(length(trigger_widened) BETWEEN 1 AND 32);
         UPDATE {table} SET trigger_widened = trigger;
         ALTER TABLE {table} DROP COLUMN trigger;
         ALTER TABLE {table} RENAME COLUMN trigger_widened TO trigger;"
    ))?;
    Ok(())
}

/// Where a removal is recorded, with the guards that keep it append-only.
///
/// A fresh database walks every migration step, so this runs from exactly one
/// place and the pinned trigger text in `APPEND_TRIGGERS` is what it creates.
const REMOVALS_DDL: &str = "
    CREATE TABLE day2_retention_removals(
        sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL CHECK(at >= 0),
        operator TEXT NOT NULL CHECK(length(operator) BETWEEN 1 AND 512),
        model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 160),
        record_id TEXT NOT NULL CHECK(length(record_id) BETWEEN 1 AND 160),
        created_at INTEGER NOT NULL CHECK(created_at >= 0),
        deleted_at INTEGER NOT NULL CHECK(deleted_at > 0),
        after_days INTEGER NOT NULL CHECK(after_days >= 1),
        reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 200)) STRICT;
    CREATE INDEX day2_removals_record ON day2_retention_removals(model,record_id);";

/// Replace the event stream's enumerated `kind` with a shape, preserving rows.
///
/// The same in-place column swap `widen_trigger` performs, and for the same
/// reason: an enumeration in a CHECK makes every new kind of auditable act a
/// schema migration, which is the wrong price for a list that keeps growing.
/// The Rust side remains the authority for which kinds exist; the column only
/// refuses nonsense.
fn widen_kind(db: &Connection) -> Result<()> {
    db.execute_batch(
        "ALTER TABLE day2_audit_events ADD COLUMN kind_widened TEXT NOT NULL DEFAULT 'invocation'
            CHECK(length(kind_widened) BETWEEN 1 AND 32);
         UPDATE day2_audit_events SET kind_widened = kind;
         ALTER TABLE day2_audit_events DROP COLUMN kind;
         ALTER TABLE day2_audit_events RENAME COLUMN kind_widened TO kind;",
    )?;
    Ok(())
}

const APPEND_TRIGGERS: &[(&str, &str)] = &[
    (
        "day2_audit_no_update",
        "CREATE TRIGGER day2_audit_no_update BEFORE UPDATE ON day2_audit BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_audit_no_delete",
        "CREATE TRIGGER day2_audit_no_delete BEFORE DELETE ON day2_audit BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_changes_no_update",
        "CREATE TRIGGER day2_changes_no_update BEFORE UPDATE ON day2_audit_changes BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_changes_no_delete",
        "CREATE TRIGGER day2_changes_no_delete BEFORE DELETE ON day2_audit_changes BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_events_no_update",
        "CREATE TRIGGER day2_events_no_update BEFORE UPDATE ON day2_web_events BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_events_no_delete",
        "CREATE TRIGGER day2_events_no_delete BEFORE DELETE ON day2_web_events BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
];
/// The guards on the removal record, and the stream entry it raises.
///
/// A removal record that could be edited or dropped would make the removal
/// itself deniable, which is the one thing this table exists to prevent. The
/// third trigger puts every removal into the one feed an operator reads, beside
/// the invocations and web requests — an act that destroys data is the last
/// thing that should require knowing which table to look in.
const REMOVAL_TRIGGERS: &[(&str, &str)] = &[
    (
        "day2_removals_no_update",
        "CREATE TRIGGER day2_removals_no_update BEFORE UPDATE ON day2_retention_removals BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_removals_no_delete",
        "CREATE TRIGGER day2_removals_no_delete BEFORE DELETE ON day2_retention_removals BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_removal_event",
        "CREATE TRIGGER day2_removal_event AFTER INSERT ON day2_retention_removals BEGIN INSERT INTO day2_audit_events(scope,kind,identity,actor,initiator,operation,outcome,at_ms,artifact,reason,trigger) VALUES((SELECT value FROM day2_meta WHERE key='scope'),'retention','removal_'||NEW.sequence,NEW.operator,NEW.operator,NULL,'removed',NEW.at*1000,NULL,substr(NEW.model||':'||NEW.record_id,1,100),'retention'); END",
    ),
];
const RECEIPT_TRIGGERS: &[(&str, &str)] = &[
    (
        "day2_audit_no_replace",
        "CREATE TRIGGER day2_audit_no_replace BEFORE INSERT ON day2_audit WHEN EXISTS(SELECT 1 FROM day2_audit WHERE invocation=NEW.invocation) BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_changes_no_replace",
        "CREATE TRIGGER day2_changes_no_replace BEFORE INSERT ON day2_audit_changes WHEN EXISTS(SELECT 1 FROM day2_audit_changes WHERE invocation=NEW.invocation AND ordinal=NEW.ordinal) BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_events_no_replace",
        "CREATE TRIGGER day2_events_no_replace BEFORE INSERT ON day2_web_events WHEN EXISTS(SELECT 1 FROM day2_web_events WHERE sequence=NEW.sequence) BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_receipt_event",
        // `initiator` is who authenticated; `actor` is who the work was for. They
        // are the same for almost every invocation, and the pair is the whole
        // point when they are not: an audit holding only one of them either
        // attributes an administrator's action to the customer or cannot say
        // what was done and to whom.
        "CREATE TRIGGER day2_receipt_event AFTER INSERT ON day2_audit BEGIN INSERT INTO day2_audit_events(scope,kind,identity,actor,initiator,operation,outcome,at_ms,artifact,reason,trigger) VALUES((SELECT value FROM day2_meta WHERE key='scope'),'invocation',NEW.invocation,NEW.actor,COALESCE(NULLIF((SELECT authenticated FROM day2_invocations WHERE id=NEW.invocation),''),NEW.actor),NEW.operation,NEW.status,NEW.at*1000,(SELECT artifact FROM day2_invocations WHERE id=NEW.invocation),(SELECT NULLIF(delegation_rule,'') FROM day2_invocations WHERE id=NEW.invocation),COALESCE((SELECT trigger FROM day2_invocations WHERE id=NEW.invocation),'request')); END",
    ),
    (
        "day2_web_audit_event",
        "CREATE TRIGGER day2_web_audit_event AFTER INSERT ON day2_web_events BEGIN INSERT INTO day2_audit_events(scope,kind,identity,actor,initiator,operation,outcome,at_ms,artifact,reason) VALUES((SELECT value FROM day2_meta WHERE key='scope'),'web','web_'||NEW.sequence,NEW.actor,NEW.actor,NULL,CASE WHEN NEW.status=102 THEN 'received' ELSE 'response' END,NEW.at*1000,NULL,NEW.category||':'||NEW.status); END",
    ),
];
const STREAM_TRIGGERS: &[(&str, &str)] = &[
    (
        "day2_stream_no_replace",
        "CREATE TRIGGER day2_stream_no_replace BEFORE INSERT ON day2_audit_events WHEN EXISTS(SELECT 1 FROM day2_audit_events WHERE sequence=NEW.sequence) BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_stream_no_update",
        "CREATE TRIGGER day2_stream_no_update BEFORE UPDATE ON day2_audit_events BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
    (
        "day2_stream_no_delete",
        "CREATE TRIGGER day2_stream_no_delete BEFORE DELETE ON day2_audit_events BEGIN SELECT RAISE(ABORT,'append_only_audit'); END",
    ),
];

// Once installed by migration, a changed guard is corruption, not a missing
// default: silently repairing it could hide an interval of mutable audit history.
pub(crate) fn validate_trigger(db: &Connection, name: &str, expected: &str) -> Result<()> {
    let actual: Option<String> = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    let normalize = |sql: &str| {
        sql.trim()
            .trim_end_matches(';')
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    ensure!(
        actual
            .as_deref()
            .is_some_and(|actual| normalize(actual) == normalize(expected)),
        "audit_guard_missing_or_changed"
    );
    Ok(())
}

pub(crate) fn ensure_event_stream(db: &Connection) -> Result<()> {
    ensure!(
        !db.is_autocommit(),
        "audit stream upgrade requires transaction"
    );
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='day2_audit_events_meta')", [], |row| row.get(0))?;
    if !exists {
        db.execute_batch("CREATE TABLE day2_audit_events_meta(version INTEGER PRIMARY KEY CHECK(version IN (1,2,3,4))) STRICT;
            INSERT INTO day2_audit_events_meta VALUES(4);
            CREATE TABLE day2_audit_events(
                sequence INTEGER PRIMARY KEY, scope TEXT NOT NULL CHECK(length(scope) BETWEEN 1 AND 512),
                kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 32),
                identity TEXT NOT NULL CHECK(length(identity) BETWEEN 1 AND 160), actor TEXT, initiator TEXT,
                operation TEXT, outcome TEXT NOT NULL, at_ms INTEGER NOT NULL CHECK(at_ms>=0), artifact TEXT, reason TEXT,
                trigger TEXT NOT NULL DEFAULT 'request' CHECK(length(trigger) BETWEEN 1 AND 32),
                CHECK(actor IS NULL OR length(actor) BETWEEN 1 AND 512), CHECK(initiator IS NULL OR length(initiator) BETWEEN 1 AND 512),
                CHECK(operation IS NULL OR length(operation) BETWEEN 1 AND 160), CHECK(reason IS NULL OR length(reason)<=100)) STRICT;
            CREATE INDEX day2_audit_events_scope ON day2_audit_events(scope,sequence);")?;
        for (_, sql) in STREAM_TRIGGERS {
            db.execute_batch(sql)?;
        }
    }
    // Stream version 2 records what caused each event. An existing stream predates
    // schedules, so everything already in it was caused by a request.
    let stream: i64 = db.query_row(
        "SELECT count(*) FROM pragma_table_info('day2_audit_events') WHERE name='trigger'",
        [],
        |row| row.get(0),
    )?;
    if stream == 0 {
        db.execute_batch(
            "ALTER TABLE day2_audit_events ADD COLUMN trigger TEXT NOT NULL DEFAULT 'request'
             CHECK(length(trigger) BETWEEN 1 AND 32);
             DELETE FROM day2_audit_events_meta;
             INSERT INTO day2_audit_events_meta VALUES(3)",
        )?;
    }
    // Stream 3 widens the same constraint on the event stream. Copying the recorded
    // causes requires an UPDATE, which the append-only guards refuse, so they are
    // dropped and restored within this migration's transaction: the table is never
    // mutable to anyone outside it, and `validate_event_stream` re-checks the
    // restored guards against their pinned definitions immediately afterwards.
    let stream_version: i64 = db.query_row(
        "SELECT max(version) FROM day2_audit_events_meta",
        [],
        |row| row.get(0),
    )?;
    if stream_version < 3 {
        for (name, _) in STREAM_TRIGGERS {
            db.execute_batch(&format!("DROP TRIGGER IF EXISTS {name}"))?;
        }
        widen_trigger(db, "day2_audit_events")?;
        for (_, sql) in STREAM_TRIGGERS {
            db.execute_batch(sql)?;
        }
        db.execute_batch(
            "DELETE FROM day2_audit_events_meta; INSERT INTO day2_audit_events_meta VALUES(3)",
        )?;
    }
    // Stream 4 widens `kind` the same way and for the same reason: it was an
    // enumeration, so every new kind of thing worth auditing was a schema
    // migration. Retention removals are the fourth kind, and they will not be
    // the last. The meta table's own CHECK is widened first, since a database
    // that predates this cannot record the version that follows it.
    if stream_version < 4 {
        for (name, _) in STREAM_TRIGGERS {
            db.execute_batch(&format!("DROP TRIGGER IF EXISTS {name}"))?;
        }
        widen_kind(db)?;
        for (_, sql) in STREAM_TRIGGERS {
            db.execute_batch(sql)?;
        }
        db.execute_batch(
            "ALTER TABLE day2_audit_events_meta RENAME TO day2_audit_events_meta_old;
             CREATE TABLE day2_audit_events_meta(version INTEGER PRIMARY KEY CHECK(version IN (1,2,3,4))) STRICT;
             DROP TABLE day2_audit_events_meta_old;
             INSERT INTO day2_audit_events_meta VALUES(4)",
        )?;
    }
    validate_event_stream(db)
}

pub(crate) fn validate_event_stream(db: &Connection) -> Result<()> {
    let versions: Vec<i64> = db
        .prepare("SELECT version FROM day2_audit_events_meta")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    ensure!(versions == [4], "unsupported_audit_stream_version");
    for (name, sql) in STREAM_TRIGGERS {
        validate_trigger(db, name, sql)?;
    }
    Ok(())
}

/// What caused an invocation to exist. Recorded rather than inferred: a scheduled
/// run was previously distinguishable only by the shape of its identity, which is
/// legible to a person reading one but not a thing a query or a policy can rely on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// An actor asked for it: HTTP, MCP, a form or the CLI.
    Request,
    /// An occurrence of a declared schedule. No actor asked; the instance bound one.
    Schedule,
    /// Another command requested it inside its own transaction.
    CommandRequest,
    /// A deferred command became due and was admitted afresh.
    Deferral,
    /// A verified inbound delivery from a provider: a webhook. No actor asked;
    /// the instance bound one, and the signature established the sender.
    Ingress,
    /// Another application in this instance asked, on behalf of the same actor.
    /// The caller chain on the invocation says which, and through what.
    Delegated,
    /// A blocked invocation was admitted afresh by a local operator.
    Recovery,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Schedule => "schedule",
            Self::CommandRequest => "command_request",
            Self::Deferral => "deferral",
            Self::Ingress => "ingress",
            Self::Delegated => "delegated",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptKind {
    Admission,
    ExecutionAttempt,
    Recovery,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    Accepted,
    Reused,
    Rejected,
    Interrupted,
    Abandoned,
    Reissued,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptReason {
    OperatorRecovery,
    ArtifactRejected,
    UnknownOperation,
    InvalidIdentity,
    InvalidClock,
    InvalidInput,
    AuthorizationRejected,
    StorageRejected,
    IdempotencyConflict,
    ExecutionInterrupted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub sequence: i64,
    pub scope: String,
    pub kind: String,
    pub identity: String,
    pub actor: Option<String>,
    pub initiator: Option<String>,
    pub operation: Option<String>,
    pub outcome: String,
    pub at_ms: i64,
    pub artifact: Option<String>,
    pub reason: Option<String>,
    #[serde(default = "requested")]
    pub trigger: String,
}

fn requested() -> String {
    Trigger::Request.as_str().to_owned()
}

pub(crate) struct Attempt<'a> {
    pub kind: AttemptKind,
    pub trigger: Trigger,
    pub identity: &'a str,
    pub actor: &'a str,
    pub initiator: &'a str,
    pub operation: &'a str,
    pub outcome: AttemptOutcome,
    pub reason: Option<AttemptReason>,
    pub at_ms: i64,
}

pub(crate) fn record_recovery(
    db: &Connection,
    runtime: &Runtime,
    operator: &str,
    invocation: &str,
    resolution: &str,
    _reason: &str,
    at_ms: i64,
) -> Result<()> {
    ensure!(!db.is_autocommit(), "recovery audit requires transaction");
    let operation: String = db.query_row(
        "SELECT operation FROM day2_invocations WHERE id=?1",
        [invocation],
        |row| row.get(0),
    )?;
    let outcome = match resolution {
        "abandoned" => AttemptOutcome::Abandoned,
        "reissued" => AttemptOutcome::Reissued,
        _ => anyhow::bail!("invalid_recovery_resolution"),
    };
    record_attempt(
        db,
        runtime,
        Attempt {
            kind: AttemptKind::Recovery,
            trigger: Trigger::Recovery,
            identity: invocation,
            actor: operator,
            initiator: operator,
            operation: &operation,
            outcome,
            reason: Some(AttemptReason::OperatorRecovery),
            at_ms,
        },
    )?;
    // The append-only recovery row holds the bounded operator reason and evidence;
    // the event stream exposes resolution and redacted metadata.
    Ok(())
}

pub(crate) fn record_attempt(
    db: &Connection,
    runtime: &Runtime,
    attempt: Attempt<'_>,
) -> Result<()> {
    ensure!(!db.is_autocommit(), "audit attempt requires transaction");
    validate_event_stream(db)?;
    let actor = (!attempt.actor.is_empty()
        && attempt.actor.len() <= 512
        && !attempt.actor.chars().any(char::is_control))
    .then_some(attempt.actor);
    let initiator = (!attempt.initiator.is_empty()
        && attempt.initiator.len() <= 512
        && !attempt.initiator.chars().any(char::is_control))
    .then_some(attempt.initiator);
    let operation = runtime
        .artifact()
        .route(attempt.operation)
        .ok()
        .map(|operation| operation.name.as_str());
    let identity = if !attempt.identity.is_empty()
        && attempt.identity.len() <= 128
        && attempt
            .identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.$".contains(&byte))
    {
        attempt.identity.to_owned()
    } else {
        crate::digest(attempt.identity.as_bytes())
    };
    let tag = |value: serde_json::Value| -> Result<String> {
        Ok(value.as_str().context("audit tag")?.to_owned())
    };
    db.execute("INSERT INTO day2_audit_events(scope,kind,identity,actor,initiator,operation,outcome,at_ms,artifact,reason,trigger) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![runtime.scope(),tag(serde_json::to_value(attempt.kind)?)?,identity,actor,initiator,operation,tag(serde_json::to_value(attempt.outcome)?)?,attempt.at_ms,runtime.artifact().id(),attempt.reason.map(|reason| tag(serde_json::to_value(reason)?)).transpose()?,attempt.trigger.as_str()])?;
    Ok(())
}

// Authority comes from the native append-only journal in the current installation
// database. Worker observations, row versions and timestamps cannot prove origin.
pub(crate) fn created_by_invocation(
    db: &Connection,
    invocation: &str,
    model: &str,
    id: crate::identity::Id,
) -> Result<bool> {
    ensure!(!db.is_autocommit(), "creation proof requires transaction");
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_audit_changes
         WHERE invocation=?1 AND model=?2 AND record_id=?3
         AND before_version IS NULL AND after_version=1)",
        params![invocation, model, id.to_string()],
        |row| row.get(0),
    )?)
}

pub(crate) fn record_change(
    db: &Connection,
    request: &Request,
    model: &str,
    before: Option<&Row>,
    after: &Row,
) -> Result<()> {
    let old: serde_json::Value = before
        .map(|row| serde_json::from_str(&row.data))
        .transpose()?
        .unwrap_or(serde_json::Value::Null);
    let new: serde_json::Value = serde_json::from_str(&after.data)?;
    let fields: Vec<_> = new
        .as_object()
        .context("row object")?
        .iter()
        .filter(|(name, value)| old.get(name.as_str()) != Some(value))
        .map(|(name, _)| name)
        .collect();
    db.execute(
        "INSERT INTO day2_audit_changes VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            request.context.invocation_id,
            i64::try_from(request.observations.len())?,
            model,
            after.id.to_string(),
            before.map(|row| row.version),
            after.version,
            serde_json::to_string(&fields)?
        ],
    )?;
    crate::live::changed(db)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Change {
    pub model: String,
    pub record_id: String,
    pub before_version: Option<i64>,
    pub after_version: i64,
    pub fields: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Entry {
    pub sequence: i64,
    pub invocation: String,
    pub actor: String,
    pub operation: String,
    pub status: String,
    pub at: i64,
    pub artifact: String,
    pub changes: Vec<Change>,
}
#[derive(Default)]
pub struct Filter {
    pub before: i64,
    pub actor: Option<String>,
    pub operation: Option<String>,
    pub status: Option<String>,
}

/// A bounded platform audit read. Empty filters and cursor mean the first page.
/// Receipt pages accept status/model/record_id; lifecycle pages accept kind,
/// identity/outcome. The host rejects filters belonging to the other view.
#[derive(Clone, Debug, Serialize)]
pub struct PageRequest {
    pub cursor: String,
    pub limit: u32,
    pub actor: Option<String>,
    pub operation: Option<String>,
    pub status: Option<String>,
    pub model: Option<String>,
    pub record_id: Option<String>,
    pub kind: Option<String>,
    pub identity: Option<String>,
    pub outcome: Option<String>,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            cursor: String::new(),
            limit: 50,
            actor: None,
            operation: None,
            status: None,
            model: None,
            record_id: None,
            kind: None,
            identity: None,
            outcome: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Empty when this append-only history has no older matching items.
    pub next_cursor: String,
}

impl PageRequest {
    pub(crate) fn from_query(raw: &str, events: bool) -> Result<Self> {
        let mut fields =
            crate::routing::query_fields(raw).context(crate::error::Failure::InvalidInput)?;
        let mut request = Self {
            cursor: fields.remove("cursor").unwrap_or_default(),
            limit: fields
                .remove("limit")
                .map(|value| value.parse())
                .transpose()
                .context(crate::error::Failure::InvalidInput)?
                .unwrap_or(50),
            ..Self::default()
        };
        for (name, slot) in [
            ("actor", &mut request.actor),
            ("operation", &mut request.operation),
            ("status", &mut request.status),
            ("model", &mut request.model),
            ("record_id", &mut request.record_id),
            ("kind", &mut request.kind),
            ("identity", &mut request.identity),
            ("outcome", &mut request.outcome),
        ] {
            *slot = fields.remove(name).filter(|value| !value.is_empty());
        }
        ensure!(fields.is_empty(), crate::error::Failure::InvalidInput);
        request.validate(events)?;
        Ok(request)
    }

    fn validate(&self, events: bool) -> Result<()> {
        use crate::error::Failure::InvalidInput;
        ensure!((1..=50).contains(&self.limit), InvalidInput);
        ensure!(
            self.cursor.is_empty()
                || self
                    .cursor
                    .strip_prefix("aud1_")
                    .is_some_and(|value| value.len() == 64
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
            crate::error::Failure::InvalidCursor
        );
        for (value, max) in [
            (&self.actor, 512),
            (&self.operation, 160),
            (&self.status, 16),
            (&self.model, 160),
            (&self.record_id, 160),
            (&self.kind, 32),
            (&self.identity, 160),
            (&self.outcome, 32),
        ] {
            ensure!(
                value.as_ref().is_none_or(|value| !value.is_empty()
                    && value.len() <= max
                    && !value.chars().any(char::is_control)),
                InvalidInput
            );
        }
        if events {
            ensure!(
                self.status.is_none() && self.model.is_none() && self.record_id.is_none(),
                InvalidInput
            );
            ensure!(
                self.kind.as_deref().is_none_or(|value| [
                    "admission",
                    "execution_attempt",
                    "invocation",
                    "web"
                ]
                .contains(&value)),
                InvalidInput
            );
            ensure!(
                self.outcome.as_deref().is_none_or(|value| [
                    "accepted",
                    "reused",
                    "rejected",
                    "interrupted",
                    "success",
                    "failure",
                    "received",
                    "response"
                ]
                .contains(&value)),
                InvalidInput
            );
        } else {
            ensure!(
                self.kind.is_none() && self.identity.is_none() && self.outcome.is_none(),
                InvalidInput
            );
            ensure!(
                self.record_id.is_none() || self.model.is_some(),
                InvalidInput
            );
            ensure!(
                self.status
                    .as_deref()
                    .is_none_or(|value| ["success", "failure"].contains(&value)),
                InvalidInput
            );
        }
        Ok(())
    }

    fn binding(&self, runtime: &Runtime, actor: &str, events: bool) -> Result<String> {
        let mut filter = self.clone();
        filter.cursor.clear();
        Ok(crate::digest(&serde_json::to_vec(&(
            "platform-audit-v1",
            runtime.scope(),
            runtime.artifact().id(),
            actor,
            events,
            filter,
        ))?))
    }
}

fn page_boundary(db: &Connection, request: &PageRequest, binding: &str, now: i64) -> Result<i64> {
    use crate::error::Failure::InvalidCursor;
    if request.cursor.is_empty() {
        return Ok(0);
    }
    ensure!(
        request
            .cursor
            .strip_prefix("aud1_")
            .is_some_and(|value| value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
        InvalidCursor
    );
    db.query_row(
        "SELECT before_sequence FROM day2_audit_cursors WHERE token=?1 AND binding=?2 AND expires_at>?3",
        params![request.cursor, binding, now],
        |row| row.get(0),
    ).optional()?.context(InvalidCursor)
}

fn next_page_cursor(db: &Connection, binding: &str, before: i64, now: i64) -> Result<String> {
    db.execute("DELETE FROM day2_audit_cursors WHERE expires_at<=?1", [now])?;
    if let Some(token) = db
        .query_row(
            "SELECT token FROM day2_audit_cursors WHERE binding=?1 AND before_sequence=?2",
            params![binding, before],
            |row| row.get(0),
        )
        .optional()?
    {
        return Ok(token);
    }
    let count: i64 = db.query_row("SELECT count(*) FROM day2_audit_cursors", [], |row| {
        row.get(0)
    })?;
    ensure!(count < 10_000, "audit_cursor_capacity");
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("audit_cursor_entropy"))?;
    let token = format!(
        "aud1_{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let expires = now
        .checked_add(86_400)
        .context("invalid_audit_cursor_clock")?;
    db.execute(
        "INSERT INTO day2_audit_cursors(token,binding,before_sequence,expires_at) VALUES(?1,?2,?3,?4)",
        params![token, binding, before, expires],
    )?;
    Ok(token)
}

impl Runtime {
    /// Read completed invocations and their redacted row changes under current
    /// app owner authority. Record filters match changes in the same transaction;
    /// the returned entry retains every change in that invocation.
    pub fn audit_page(&self, actor: &str, request: &PageRequest) -> Result<Page<Entry>> {
        request.validate(false)?;
        let mut db = open(self.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        self.authorize_audit_in(&tx, actor)?;
        let now = self.host().now_ms()?.div_euclid(1000);
        let binding = request.binding(self, actor, false)?;
        let before = page_boundary(&tx, request, &binding, now)?;
        let mut items = tx.prepare("SELECT a.rowid,a.invocation,a.actor,a.operation,a.status,a.at,i.artifact
            FROM day2_audit a JOIN day2_invocations i ON a.invocation=i.id
            WHERE (?1=0 OR a.rowid<?1) AND (?2 IS NULL OR a.actor=?2)
            AND (?3 IS NULL OR a.operation=?3) AND (?4 IS NULL OR a.status=?4)
            AND (?5 IS NULL OR EXISTS(SELECT 1 FROM day2_audit_changes c WHERE c.invocation=a.invocation
                AND c.model=?5 AND (?6 IS NULL OR c.record_id=?6)))
            ORDER BY a.rowid DESC LIMIT ?7")?
            .query_map(params![before, request.actor, request.operation, request.status,
                request.model, request.record_id, request.limit + 1], |row| Ok(Entry {
                sequence: row.get(0)?, invocation: row.get(1)?, actor: row.get(2)?,
                operation: row.get(3)?, status: row.get(4)?, at: row.get(5)?,
                artifact: row.get(6)?, changes: vec![],
            }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let more = items.len() > request.limit as usize;
        items.truncate(request.limit as usize);
        for entry in &mut items {
            entry.changes = read_changes(&tx, &entry.invocation)?;
        }
        let next_cursor = if more {
            next_page_cursor(
                &tx,
                &binding,
                items.last().context("audit page boundary")?.sequence,
                now,
            )?
        } else {
            String::new()
        };
        tx.commit()?;
        Ok(Page { items, next_cursor })
    }

    /// Read the common admission, execution, completion and HTTP event stream.
    pub fn audit_event_page(&self, actor: &str, request: &PageRequest) -> Result<Page<Event>> {
        request.validate(true)?;
        let mut db = open(self.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        self.authorize_audit_in(&tx, actor)?;
        validate_event_stream(&tx)?;
        let now = self.host().now_ms()?.div_euclid(1000);
        let binding = request.binding(self, actor, true)?;
        let before = page_boundary(&tx, request, &binding, now)?;
        let mut items = tx.prepare("SELECT sequence,scope,kind,identity,actor,initiator,operation,outcome,at_ms,artifact,reason,trigger
            FROM day2_audit_events WHERE scope=?1 AND (?2=0 OR sequence<?2)
            AND (?3 IS NULL OR actor=?3) AND (?4 IS NULL OR operation=?4) AND (?5 IS NULL OR kind=?5)
            AND (?6 IS NULL OR identity=?6) AND (?7 IS NULL OR outcome=?7) ORDER BY sequence DESC LIMIT ?8")?
            .query_map(params![self.scope(), before, request.actor, request.operation, request.kind,
                request.identity, request.outcome, request.limit + 1], |row| Ok(Event {
                sequence: row.get(0)?, scope: row.get(1)?, kind: row.get(2)?, identity: row.get(3)?,
                actor: row.get(4)?, initiator: row.get(5)?, operation: row.get(6)?, outcome: row.get(7)?,
                at_ms: row.get(8)?, artifact: row.get(9)?, reason: row.get(10)?, trigger: row.get(11)?,
            }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let more = items.len() > request.limit as usize;
        items.truncate(request.limit as usize);
        let next_cursor = if more {
            next_page_cursor(
                &tx,
                &binding,
                items.last().context("audit page boundary")?.sequence,
                now,
            )?
        } else {
            String::new()
        };
        tx.commit()?;
        Ok(Page { items, next_cursor })
    }

    pub(crate) fn audit_rejection(
        &self,
        operation: &str,
        actor: &str,
        identity: &str,
        now: i64,
        reason: AttemptReason,
        trigger: Trigger,
    ) -> Result<()> {
        self.audit_admission_rejection(operation, (actor, actor), identity, now, reason, trigger)
    }

    pub(crate) fn audit_admission_rejection(
        &self,
        operation: &str,
        (actor, initiator): (&str, &str),
        identity: &str,
        now: i64,
        reason: AttemptReason,
        trigger: Trigger,
    ) -> Result<()> {
        let at_ms = if (0..=253_402_300_799).contains(&now) {
            now.checked_mul(1000).context("audit clock overflow")?
        } else {
            self.host().now_ms()?
        };
        let mut connection = open(self.db())?;
        let transaction = crate::write_queue::immediate(&mut connection)?;
        self.check_binding(&transaction)?;
        upgrade(&transaction)?;
        record_attempt(
            &transaction,
            self,
            Attempt {
                kind: AttemptKind::Admission,
                trigger,
                identity,
                actor,
                initiator,
                operation,
                outcome: AttemptOutcome::Rejected,
                reason: Some(reason),
                at_ms,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn audit_execution_interruption(&self, identity: &str) -> Result<()> {
        let mut connection = open(self.db())?;
        let transaction = crate::write_queue::immediate(&mut connection)?;
        self.check_binding(&transaction)?;
        upgrade(&transaction)?;
        let metadata: Option<(String, String, String)> = transaction
            .query_row(
                "SELECT COALESCE(NULLIF(authenticated,''),actor),operation,trigger
                 FROM day2_invocations WHERE id=?1",
                [identity],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (initiator, operation, cause) = metadata.unwrap_or_else(|| {
            (
                String::new(),
                String::new(),
                Trigger::Request.as_str().into(),
            )
        });
        // The cause is the invocation's own, recorded when it was admitted.
        let trigger = match cause.as_str() {
            "schedule" => Trigger::Schedule,
            "command_request" => Trigger::CommandRequest,
            "deferral" => Trigger::Deferral,
            "ingress" => Trigger::Ingress,
            "delegated" => Trigger::Delegated,
            "recovery" => Trigger::Recovery,
            _ => Trigger::Request,
        };
        record_attempt(
            &transaction,
            self,
            Attempt {
                kind: AttemptKind::ExecutionAttempt,
                trigger,
                identity,
                actor: "",
                initiator: &initiator,
                operation: &operation,
                outcome: AttemptOutcome::Interrupted,
                reason: Some(AttemptReason::ExecutionInterrupted),
                at_ms: self.host().now_ms()?,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn audit_events(&self, actor: &str, before: i64) -> Result<Vec<Event>> {
        ensure!(before >= 0, crate::error::Failure::InvalidCursor);
        let mut db = open(self.db())?;
        let tx = db.transaction()?;
        self.authorize_audit_in(&tx, actor)?;
        validate_event_stream(&tx)?;
        let events = tx.prepare("SELECT sequence,scope,kind,identity,actor,initiator,operation,outcome,at_ms,artifact,reason,trigger FROM day2_audit_events WHERE scope=?1 AND (?2=0 OR sequence<?2) ORDER BY sequence DESC LIMIT 51")?.query_map(params![self.scope(),before], |row| Ok(Event {sequence:row.get(0)?,scope:row.get(1)?,kind:row.get(2)?,identity:row.get(3)?,actor:row.get(4)?,initiator:row.get(5)?,operation:row.get(6)?,outcome:row.get(7)?,at_ms:row.get(8)?,artifact:row.get(9)?,reason:row.get(10)?,trigger:row.get(11)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(events)
    }
    pub fn authorize_audit(&self, actor: &str) -> Result<()> {
        let mut db = open(self.db())?;
        let tx = db.transaction()?;
        self.authorize_audit_in(&tx, actor)
    }
    fn authorize_audit_in(&self, db: &Connection, actor: &str) -> Result<()> {
        self.check_binding(db)?;
        let active = crate::authority_state::current(db)?;
        active.document.validate(self.artifact())?;
        if let Some(requirements) = &active.document.security {
            requirements.require_runtime()?;
        }
        active.document.authorize_audit(actor)
    }
    pub fn audit_entries(&self, actor: &str, filter: &Filter) -> Result<Vec<Entry>> {
        ensure!(filter.before >= 0, crate::error::Failure::InvalidCursor);
        let mut db = open(self.db())?;
        let tx = db.transaction()?;
        self.authorize_audit_in(&tx, actor)?;
        let mut statement = tx.prepare("SELECT a.rowid,a.invocation,a.actor,a.operation,a.status,a.at,i.artifact FROM day2_audit a JOIN day2_invocations i ON a.invocation=i.id WHERE (?1=0 OR a.rowid<?1) AND (?2 IS NULL OR a.actor=?2) AND (?3 IS NULL OR a.operation=?3) AND (?4 IS NULL OR a.status=?4) ORDER BY a.rowid DESC LIMIT 51")?;
        let mut entries = statement
            .query_map(
                params![filter.before, filter.actor, filter.operation, filter.status],
                |row| {
                    Ok(Entry {
                        sequence: row.get(0)?,
                        invocation: row.get(1)?,
                        actor: row.get(2)?,
                        operation: row.get(3)?,
                        status: row.get(4)?,
                        at: row.get(5)?,
                        artifact: row.get(6)?,
                        changes: vec![],
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for entry in &mut entries {
            entry.changes = read_changes(&tx, &entry.invocation)?;
        }
        Ok(entries)
    }
    pub(crate) fn web_event(
        &self,
        at: i64,
        actor: Option<&str>,
        category: &str,
        status: u16,
    ) -> Result<()> {
        ensure!(
            (100..=599).contains(&status) && at >= 0 && category.len() <= 80,
            "invalid_web_audit_metadata"
        );
        let mut db = open(self.db())?;
        let tx = crate::write_queue::immediate(&mut db)?;
        self.check_binding(&tx)?;
        upgrade(&tx)?;
        tx.execute(
            "INSERT INTO day2_web_events(at,actor,category,status) VALUES(?1,?2,?3,?4)",
            params![at, actor, category, status],
        )?;
        tx.commit()?;
        Ok(())
    }
}

/// The observation an application uses to read its own history.
///
/// Granted per operation in the authority policy's `observations`, like any
/// other read, and refused to every operation that is not granted it.
pub const HISTORY: &str = "audit.history.v1";

/// Most entries one history page may return. The same bound as the platform
/// audit pages, so neither view can be made to read more than the other.
const HISTORY_PAGE: i64 = 50;
/// Most operation names one history read may filter by.
const HISTORY_OPERATIONS: usize = 64;
/// Most row changes listed on one entry. `change_count` always states the total,
/// so an abbreviated list is visible as one rather than passing for complete.
const HISTORY_CHANGES: usize = 20;
/// Encoded bytes a page may occupy. An observation is journaled as an escaped
/// string inside a 64-KiB record, so the page stops early, lawfully, with a
/// continuation, rather than growing past what the journal will hold.
const HISTORY_BYTES: usize = 40_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRequest {
    operations: Vec<String>,
    after: String,
    limit: i64,
}

/// One completed invocation of this application, as the application sees it.
#[derive(Serialize)]
struct HistoryEntry {
    sequence: i64,
    operation: String,
    actor: String,
    initiator: String,
    trigger: String,
    outcome: String,
    at: i64,
    changes: Vec<HistoryChange>,
    change_count: u64,
}

#[derive(Serialize)]
struct HistoryChange {
    model: String,
    record_id: String,
    /// Zero when the change created the row.
    before_version: i64,
    after_version: i64,
    fields: Vec<String>,
}

#[derive(Serialize)]
struct HistoryPage {
    items: Vec<HistoryEntry>,
    has_more: bool,
    next_after: String,
}

/// Refuse `audit.history` to an operation its current policy does not grant it.
pub(crate) fn require_history(
    policy: &crate::authority::Policy,
    runtime: &Runtime,
    operation: &str,
) -> Result<()> {
    let operation = &runtime.artifact().route(operation)?.name;
    ensure!(
        policy
            .operations
            .get(operation)
            .is_some_and(|grant| grant.observations.contains(HISTORY)),
        crate::error::Failure::CapabilityForbidden
    );
    Ok(())
}

/// Read one page of this application's own completed history.
///
/// Scoped by construction rather than by filter: each application has its own
/// database, and this reads only its receipts and row changes — never another
/// application's, never the admission, rejection, interruption, web or
/// retention events of the platform log, and never inputs, results, tokens or
/// bodies, none of which the receipt holds. Row changes name the record and the
/// fields that changed but carry no values, because the platform records none:
/// an append-only copy of business values would outlive the deletion and
/// retention of the rows they came from. An application that wants a value
/// reads the row through its own granted query.
///
/// Newest first. The continuation is an ordinary selection cursor, bound to
/// this actor, this operation and this filter, and expiring like any other.
/// The caller holds the write lock; the only write is that cursor.
pub(crate) fn history(
    db: &Connection,
    runtime: &Runtime,
    request: &Request,
    instruction: &crate::protocol::Instruction,
) -> Result<String> {
    use crate::error::Failure::InvalidInput;
    let read: HistoryRequest =
        crate::json::decode(instruction.data.as_bytes()).context(InvalidInput)?;
    ensure!((1..=HISTORY_PAGE).contains(&read.limit), InvalidInput);
    ensure!(read.operations.len() <= HISTORY_OPERATIONS, InvalidInput);
    for operation in &read.operations {
        ensure!(
            !operation.is_empty()
                && operation.len() <= 160
                && !operation.chars().any(char::is_control),
            InvalidInput
        );
    }
    let operations: std::collections::BTreeSet<&str> =
        read.operations.iter().map(String::as_str).collect();
    let registered = &runtime.artifact().route(&request.operation)?.name;
    let binding = crate::digest(&serde_json::to_vec(&(
        "day2.audit_history.v1",
        runtime.scope(),
        &request.context.actor,
        registered,
        &operations,
    ))?);
    history_page(
        db,
        &read,
        &binding,
        &request.context.invocation_id,
        request.context.now,
    )
}

fn history_page(
    db: &Connection,
    read: &HistoryRequest,
    binding: &str,
    invocation_id: &str,
    now: i64,
) -> Result<String> {
    use crate::error::Failure::InvalidCursor;
    crate::store::upgrade_selection_cursors(db)?;
    let before = if read.after.is_empty() {
        0
    } else {
        let cursor = crate::store::decode_selection_cursor(db, &read.after, now)?;
        ensure!(
            cursor.binding == binding && cursor.values.len() == 1,
            InvalidCursor
        );
        crate::store::pin_selection_cursor(db, &read.after, invocation_id)?;
        cursor.values[0]
            .as_i64()
            .filter(|sequence| *sequence > 0)
            .context(InvalidCursor)?
    };
    let rows = db
        .prepare(
            "SELECT a.rowid,a.invocation,a.operation,a.actor,
                COALESCE(NULLIF(i.authenticated,''),a.actor),i.trigger,a.status,a.at
            FROM day2_audit a JOIN day2_invocations i ON a.invocation=i.id
            WHERE i.status IN ('success','failure') AND a.status=i.status
            AND (?1=0 OR a.rowid<?1)
            AND (?2='[]' OR a.operation IN (SELECT value FROM json_each(?2)))
            ORDER BY a.rowid DESC LIMIT ?3",
        )?
        .query_map(
            params![
                before,
                serde_json::to_string(&read.operations)?,
                read.limit + 1
            ],
            |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    HistoryEntry {
                        sequence: row.get(0)?,
                        operation: row.get(2)?,
                        actor: row.get(3)?,
                        initiator: row.get(4)?,
                        trigger: row.get(5)?,
                        outcome: row.get(6)?,
                        at: row.get(7)?,
                        changes: Vec::new(),
                        change_count: 0,
                    },
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut has_more = rows.len() > read.limit as usize;
    let mut items = Vec::new();
    let mut spent = 64;
    for (invocation, mut entry) in rows.into_iter().take(read.limit as usize) {
        entry.change_count = u64::try_from(db.query_row(
            "SELECT count(*) FROM day2_audit_changes WHERE invocation=?1",
            [&invocation],
            |row| row.get::<_, i64>(0),
        )?)?;
        entry.changes = db.prepare(
            "SELECT model,record_id,before_version,after_version,fields FROM day2_audit_changes WHERE invocation=?1 ORDER BY ordinal LIMIT ?2",
        )?.query_map(params![invocation, HISTORY_CHANGES as i64], |row| {
            let fields: String = row.get(4)?;
            Ok((HistoryChange {
                model: row.get(0)?, record_id: row.get(1)?, before_version: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                after_version: row.get(3)?, fields: Vec::new(),
            }, fields))
        })?.collect::<rusqlite::Result<Vec<_>>>()?.into_iter().map(|(mut change, fields)| {
            change.fields = serde_json::from_str(&fields)?;
            Ok(change)
        }).collect::<Result<Vec<_>>>()?;
        let mut cost = escaped_len(&entry)?;
        if cost > HISTORY_BYTES / 2 {
            // Only a pathological entry reaches this: its change list is dropped,
            // and `change_count` still says how many there were.
            entry.changes.clear();
            cost = escaped_len(&entry)?;
        }
        if !items.is_empty() && spent + cost > HISTORY_BYTES {
            has_more = true;
            break;
        }
        spent += cost;
        items.push(entry);
    }
    let next_after = match items.last() {
        Some(last) if has_more => {
            let token = crate::store::encode_selection_cursor(
                db,
                &crate::store::SelectionCursor {
                    binding: binding.into(),
                    values: vec![serde_json::json!(last.sequence)],
                },
                now,
            )?;
            crate::store::pin_selection_cursor(db, &token, invocation_id)?;
            token
        }
        _ => {
            has_more = false;
            String::new()
        }
    };
    Ok(serde_json::to_string(&HistoryPage {
        items,
        has_more,
        next_after,
    })?)
}

/// What an entry costs inside the journaled observation, where the page is an
/// escaped JSON string.
fn escaped_len(entry: &HistoryEntry) -> Result<usize> {
    Ok(serde_json::to_string(&serde_json::to_string(entry)?)?.len() + 1)
}

fn read_changes(db: &Connection, invocation: &str) -> Result<Vec<Change>> {
    let mut statement = db.prepare("SELECT model,record_id,before_version,after_version,fields FROM day2_audit_changes WHERE invocation=?1 ORDER BY ordinal")?;
    let changes = statement.query_map([invocation], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    changes
        .map(|change| {
            let (model, record_id, before_version, after_version, fields) = change?;
            Ok(Change {
                model,
                record_id,
                before_version,
                after_version,
                fields: serde_json::from_str(&fields)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use serde_json::{Value, json};

    fn database() -> Result<Connection> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE day2_invocations(id TEXT PRIMARY KEY, authenticated TEXT, trigger TEXT, status TEXT);
            CREATE TABLE day2_audit(invocation TEXT PRIMARY KEY, operation TEXT, actor TEXT, status TEXT, at INTEGER);
            CREATE TABLE day2_audit_changes(invocation TEXT, ordinal INTEGER, model TEXT, record_id TEXT,
                before_version INTEGER, after_version INTEGER, fields TEXT);")?;
        Ok(db)
    }

    fn receipt(
        db: &Connection,
        id: &str,
        operation: &str,
        changes: usize,
        field: &str,
    ) -> Result<()> {
        db.execute(
            "INSERT INTO day2_invocations VALUES(?1,'support','request','success')",
            [id],
        )?;
        db.execute(
            "INSERT INTO day2_audit VALUES(?1,?2,'customer','success',100)",
            params![id, operation],
        )?;
        for ordinal in 0..changes {
            db.execute(
                "INSERT INTO day2_audit_changes VALUES(?1,?2,'entries',?3,NULL,1,?4)",
                params![
                    id,
                    ordinal as i64,
                    format!("record-{ordinal}"),
                    json!([field]).to_string()
                ],
            )?;
        }
        Ok(())
    }

    fn page(
        db: &Connection,
        operations: &[&str],
        after: &str,
        limit: i64,
        binding: &str,
    ) -> Result<Value> {
        Ok(serde_json::from_str(&history_page(
            db,
            &HistoryRequest {
                operations: operations.iter().map(|name| (*name).into()).collect(),
                after: after.into(),
                limit,
            },
            binding,
            "",
            100,
        )?)?)
    }

    #[test]
    fn bounded_changes_report_the_total_and_large_entries_preserve_continuations() -> Result<()> {
        let db = database()?;
        receipt(&db, "old", "retired.write", 25, "note")?;
        let first = page(&db, &[], "", 50, "scope")?;
        assert_eq!(first["items"][0]["change_count"], 25);
        assert_eq!(
            first["items"][0]["changes"].as_array().unwrap().len(),
            HISTORY_CHANGES
        );
        assert_eq!(first["items"][0]["changes"][0]["before_version"], 0);
        // Each row is within the entry budget but the collection needs more
        // than one page. Quotes exercise escaped observation/journal size.
        for index in 0..12 {
            receipt(
                &db,
                &format!("wide-{index}"),
                "retired.write",
                1,
                &"\"".repeat(1_500),
            )?;
        }
        let mut cursor = String::new();
        let mut sequences = std::collections::BTreeSet::new();
        let mut pages = 0;
        loop {
            let result = page(&db, &[], &cursor, 50, "scope")?;
            assert!(serde_json::to_string(&result.to_string())?.len() < HISTORY_BYTES + 256);
            pages += 1;
            for entry in result["items"].as_array().unwrap() {
                assert!(sequences.insert(entry["sequence"].as_i64().unwrap()));
            }
            if result["has_more"] == false {
                break;
            }
            cursor = result["next_after"].as_str().unwrap().into();
        }
        assert!(pages > 1);
        assert_eq!(sequences.len(), 13);
        receipt(&db, "huge", "retired.write", 1, &"\"".repeat(HISTORY_BYTES))?;
        let huge = page(&db, &[], "", 1, "scope")?;
        assert_eq!(huge["items"][0]["changes"], json!([]));
        assert_eq!(huge["items"][0]["change_count"], 1);
        assert_eq!(huge["has_more"], true);
        Ok(())
    }

    #[test]
    fn exact_operation_filters_and_cursor_binding_cannot_widen_history() -> Result<()> {
        let db = database()?;
        receipt(&db, "old", "retired.write", 0, "")?;
        receipt(&db, "query", "app.read", 0, "")?;
        receipt(&db, "new", "retired.write", 0, "")?;
        db.execute(
            "INSERT INTO day2_invocations VALUES('pending','support','request','pending')",
            [],
        )?;
        db.execute(
            "INSERT INTO day2_invocations VALUES('aborted','support','request','failure')",
            [],
        )?;
        let first = page(&db, &["retired.write"], "", 1, "bound-filter")?;
        let cursor = first["next_after"].as_str().unwrap();
        assert!(page(&db, &[], cursor, 1, "different-filter").is_err());
        assert!(page(&db, &["retired.write"], "sel1_forged", 1, "bound-filter").is_err());
        receipt(&db, "newer", "retired.write", 0, "")?;
        let older = page(&db, &["retired.write"], cursor, 1, "bound-filter")?;
        assert_eq!(older["items"][0]["sequence"], 1);
        assert_eq!(older["has_more"], false);
        assert_eq!(
            page(&db, &["retired"], "", 50, "other")?["items"],
            json!([])
        );
        assert_eq!(
            page(&db, &[], "", 50, "all")?["items"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        db.execute(
            "UPDATE day2_selection_cursors SET expires_at=100 WHERE token=?1",
            [cursor],
        )?;
        assert!(page(&db, &["retired.write"], cursor, 1, "bound-filter").is_err());
        Ok(())
    }
}
