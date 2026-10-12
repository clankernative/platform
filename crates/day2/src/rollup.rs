//! Totals the platform keeps for an application.
//!
//! A model declares a rollup beside its keys:
//!
//! ```roc
//! daily_outcomes: Table.rollup(
//!     { created_time: Table.day(row.created_time), repo: row.repo, conclusion: row.conclusion },
//!     { runs: Table.count, duration: Table.sum(row.duration) },
//! )
//! ```
//!
//! The host keeps one row per group in a table of its own, maintained by SQLite
//! triggers on the source table, so every create, update, soft delete and
//! restore adjusts the totals inside the transaction that made it. Nothing an
//! application writes can leave them stale, and no repair job exists.
//!
//! The vocabulary is deliberately small. A group is a set of the model's columns,
//! an integer column optionally bucketed to its UTC hour, day or week. A measure
//! counts rows or sums an integer column. Both measures can be undone exactly when
//! a row changes group or is deleted, which is what keeps the totals exact; min,
//! max and distinct counts cannot, so they are not offered. A soft-deleted row is
//! outside every total, and a group whose last row leaves disappears.
//!
//! Reads go through the same selections as a model: a rollup is served as a
//! read-only table whose rows carry a synthetic id, version 1 and no creation
//! time. Changing a rollup changes the schema, and migration rebuilds new or changed rollups
//! from their source rows.
use crate::schema::{Kind, Record};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    Hour,
    Day,
    Week,
}

impl Bucket {
    pub(crate) fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "Hour" => Some(Self::Hour),
            "Day" => Some(Self::Day),
            "Week" => Some(Self::Week),
            _ => None,
        }
    }
    /// The start of the UTC period containing `column`, in the same unit. Weeks
    /// start on Monday; the epoch was a Thursday, three days after one.
    fn sql(self, column: &str) -> String {
        let (period, offset) = match self {
            Self::Hour => (3_600, 0),
            Self::Day => (86_400, 0),
            Self::Week => (604_800, 259_200),
        };
        format!(
            "({column} - ((({column} % {period} + {offset}) % {period} + {period}) % {period}))"
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<Bucket>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Measure {
    Count,
    /// Sums the model column of the measure's own name.
    Sum,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    pub name: String,
    pub measure: Measure,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rollup {
    pub model: String,
    pub name: String,
    /// Sorted by field name, as reflection presents a record.
    pub group: Vec<Group>,
    /// Sorted by name.
    pub measures: Vec<Aggregate>,
}

impl Rollup {
    /// The table the totals live in, and the name reads use.
    pub fn table(&self) -> String {
        format!("{}_{}", self.model, self.name)
    }

    pub fn prefix(&self) -> String {
        let digest = crate::digest(&serde_json::to_vec(self).expect("rollup is serializable"));
        let letters: String = digest
            .bytes()
            .skip(7)
            .take(20)
            .map(|b| (b'a' + if b <= b'9' { b - b'0' } else { b - b'a' + 10 }) as char)
            .collect();
        format!("rollup{letters}")
    }

    pub(crate) fn validate(&self, source: &Record) -> Result<()> {
        day2_contracts::names::identifier(&self.name)?;
        day2_contracts::names::identifier(&self.table())?;
        ensure!(
            !self.group.is_empty() && self.group.len() <= 8,
            "rollup {} needs one to eight group columns",
            self.table()
        );
        ensure!(
            !self.measures.is_empty() && self.measures.len() <= 8,
            "rollup {} needs one to eight measures",
            self.table()
        );
        ensure!(
            self.group
                .windows(2)
                .all(|pair| pair[0].field < pair[1].field)
                && self
                    .measures
                    .windows(2)
                    .all(|pair| pair[0].name < pair[1].name),
            "rollup columns must be distinct and sorted"
        );
        for group in &self.group {
            let kind = source.fields.get(&group.field).with_context(|| {
                format!(
                    "rollup {} groups by {}, which is not a column of {}",
                    self.table(),
                    group.field,
                    self.model
                )
            })?;
            ensure!(
                matches!(
                    kind,
                    Kind::Integer
                        | Kind::Boolean
                        | Kind::Text
                        | Kind::TextDomain { .. }
                        | Kind::StandardText { .. }
                ),
                "rollup {} cannot group by {}: groups use integer, boolean or text columns",
                self.table(),
                group.field
            );
            ensure!(
                group.bucket.is_none() || *kind == Kind::Integer,
                "rollup {} can bucket only an integer time column",
                self.table()
            );
        }
        for aggregate in &self.measures {
            day2_contracts::names::identifier(&aggregate.name)?;
            ensure!(
                !self.group.iter().any(|group| group.field == aggregate.name)
                    && !matches!(
                        aggregate.name.as_str(),
                        "id" | "version" | "created_at" | "deleted_at"
                    ),
                "rollup {} measure {} collides with a column",
                self.table(),
                aggregate.name
            );
            if aggregate.measure == Measure::Sum {
                ensure!(
                    source.fields.get(&aggregate.name) == Some(&Kind::Integer),
                    "rollup {} sums {}, which is not an integer column of {}",
                    self.table(),
                    aggregate.name,
                    self.model
                );
            }
        }
        Ok(())
    }

    /// How reads see the rollup: its group columns, bucketed ones as integers,
    /// and its measures.
    pub fn record(&self, source: &Record) -> Record {
        let mut fields = std::collections::BTreeMap::new();
        for group in &self.group {
            let kind = if group.bucket.is_some() {
                Kind::Integer
            } else {
                source.fields[&group.field].clone()
            };
            fields.insert(group.field.clone(), kind);
        }
        for aggregate in &self.measures {
            fields.insert(aggregate.name.clone(), Kind::Integer);
        }
        Record {
            fields,
            // Rows decode as a structural record, so no type is generated for them.
            roc_type: None,
            identity: Some(day2_contracts::identity::ModelIdentity {
                key: source
                    .identity
                    .as_ref()
                    .map_or_else(|| "0".repeat(32), |identity| identity.key.clone()),
                prefix: self.prefix(),
            }),
        }
    }

    /// Group columns in index order: plain columns, then bucketed times, so an
    /// equality filter on the former can walk the latter in order.
    fn index_columns(&self) -> Vec<&Group> {
        let mut columns: Vec<_> = self.group.iter().filter(|g| g.bucket.is_none()).collect();
        columns.extend(self.group.iter().filter(|g| g.bucket.is_some()));
        columns
    }

    fn group_value(group: &Group, row: &str) -> String {
        let column = format!("{row}\"{}\"", group.field);
        group
            .bucket
            .map_or(column.clone(), |bucket| bucket.sql(&column))
    }

    fn measure_value(aggregate: &Aggregate, row: &str) -> String {
        match aggregate.measure {
            Measure::Count => "1".into(),
            Measure::Sum => format!("{row}\"{}\"", aggregate.name),
        }
    }

    fn quoted<'a>(names: impl Iterator<Item = &'a str>) -> String {
        names
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// A deterministic, never-reused sequence in the UUID payload. These are
    /// transient read handles, not identities for persisted foreign keys.
    fn id_sql(sequence: &str) -> String {
        format!("unhex('00000000000070008000' || printf('%012x', {sequence}))")
    }

    /// Adds the row visible as `row` (`NEW.`) to its group.
    fn add(&self, row: &str) -> String {
        let table = self.table();
        let groups = Self::quoted(self.group.iter().map(|g| g.field.as_str()));
        let measures = Self::quoted(self.measures.iter().map(|a| a.name.as_str()));
        let group_values = self
            .group
            .iter()
            .map(|g| Self::group_value(g, row))
            .collect::<Vec<_>>()
            .join(",");
        let measure_values = self
            .measures
            .iter()
            .map(|a| Self::measure_value(a, row))
            .collect::<Vec<_>>()
            .join(",");
        let conflict = Self::quoted(self.index_columns().into_iter().map(|g| g.field.as_str()));
        let updates = self
            .measures
            .iter()
            .map(|a| format!("\"{0}\"=\"{0}\"+excluded.\"{0}\"", a.name))
            .chain(std::iter::once("day2_rows=day2_rows+1".to_owned()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "UPDATE \"day2_rollup_sequence_{table}\" SET value=value+1 WHERE {row}deleted_at=0; \
             INSERT INTO \"{table}\"(id,{groups},{measures},day2_rows) \
             SELECT {},{group_values},{measure_values},1 \
             WHERE {row}deleted_at = 0 \
             ON CONFLICT({conflict}) DO UPDATE SET {updates};",
            Self::id_sql(&format!(
                "(SELECT value FROM \"day2_rollup_sequence_{table}\")"
            ))
        )
    }

    /// Removes the row visible as `row` (`OLD.`) from its group, and the group
    /// with it when it was the last.
    fn remove(&self, row: &str) -> String {
        let table = self.table();
        let matches = self
            .group
            .iter()
            .map(|g| format!("\"{}\" = {}", g.field, Self::group_value(g, row)))
            .collect::<Vec<_>>()
            .join(" AND ");
        let updates = self
            .measures
            .iter()
            .map(|a| format!("\"{0}\"=\"{0}\"-{1}", a.name, Self::measure_value(a, row)))
            .chain(std::iter::once("day2_rows=day2_rows-1".to_owned()))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "DELETE FROM \"{table}\" WHERE {matches} AND {row}deleted_at = 0 AND day2_rows = 1; \
             UPDATE \"{table}\" SET {updates} WHERE {matches} AND {row}deleted_at = 0;"
        )
    }

    fn trigger(&self, event: &str) -> String {
        format!("day2_rollup_{}_{event}", self.table())
    }

    /// The table, its group index and the triggers that maintain it.
    pub(crate) fn ddl(&self, source: &Record) -> Result<Vec<String>> {
        let table = self.table();
        let mut columns = vec![
            "id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16)".to_owned(),
            "version INTEGER NOT NULL DEFAULT 1 CHECK(version = 1)".to_owned(),
            "created_at INTEGER NOT NULL DEFAULT 0".to_owned(),
            "deleted_at INTEGER NOT NULL DEFAULT 0 CHECK(deleted_at = 0)".to_owned(),
        ];
        for (field, kind) in &self.record(source).fields {
            columns.push(format!("\"{field}\" {}", kind.ddl()?));
        }
        columns.push("day2_rows INTEGER NOT NULL CHECK(day2_rows > 0)".to_owned());
        let model = &self.model;
        // Only a change the totals can see fires the update trigger.
        let changed = std::iter::once("OLD.deleted_at IS NOT NEW.deleted_at".to_owned())
            .chain(
                self.group
                    .iter()
                    .map(|g| g.field.as_str())
                    .chain(
                        self.measures
                            .iter()
                            .filter(|a| a.measure == Measure::Sum)
                            .map(|a| a.name.as_str()),
                    )
                    .map(|field| format!("OLD.\"{field}\" IS NOT NEW.\"{field}\"")),
            )
            .collect::<Vec<_>>()
            .join(" OR ");
        let mut statements = vec![
            format!(
                "CREATE TABLE IF NOT EXISTS \"day2_rollup_sequence_{table}\"(singleton INTEGER PRIMARY KEY CHECK(singleton=1), value INTEGER NOT NULL CHECK(value BETWEEN 0 AND 281474976710655)) STRICT"
            ),
            format!("INSERT OR IGNORE INTO \"day2_rollup_sequence_{table}\" VALUES(1,0)"),
            format!(
                "CREATE TABLE IF NOT EXISTS \"{table}\" ({}) STRICT",
                columns.join(", ")
            ),
            format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS \"day2_rollup_group_{table}\" ON \"{table}\"({})",
                Self::quoted(self.index_columns().into_iter().map(|g| g.field.as_str()))
            ),
            format!(
                "CREATE TRIGGER IF NOT EXISTS \"{}\" AFTER INSERT ON \"{model}\" \
                 WHEN NEW.deleted_at = 0 BEGIN {} END",
                self.trigger("insert"),
                self.add("NEW.")
            ),
            // Subtract before adding to avoid doubling a large sum transiently.
            format!(
                "CREATE TRIGGER IF NOT EXISTS \"{}\" AFTER UPDATE ON \"{model}\" \
                 WHEN {changed} BEGIN {} {} END",
                self.trigger("update"),
                self.remove("OLD."),
                self.add("NEW.")
            ),
            // Retention removes only rows that were already deleted, so this is a
            // no-op for them; it exists so no removal path can leave a stale total.
            format!(
                "CREATE TRIGGER IF NOT EXISTS \"{}\" AFTER DELETE ON \"{model}\" \
                 WHEN OLD.deleted_at = 0 BEGIN {} END",
                self.trigger("delete"),
                self.remove("OLD.")
            ),
        ];
        // Separate object categories and use a numeric field suffix so table
        // and field names containing underscores cannot alias another index.
        for (ordinal, field) in self.record(source).fields.keys().enumerate() {
            statements.push(format!("CREATE INDEX IF NOT EXISTS \"day2_rollup_column_{table}_{ordinal}\" ON \"{table}\"(\"{field}\",id)"));
        }
        Ok(statements)
    }

    /// Drops the table and its triggers.
    pub(crate) fn drop_sql(&self) -> String {
        format!(
            "DROP TRIGGER IF EXISTS \"{}\"; DROP TRIGGER IF EXISTS \"{}\"; \
             DROP TRIGGER IF EXISTS \"{}\"; DROP TABLE IF EXISTS \"{}\"; DROP TABLE IF EXISTS \"day2_rollup_sequence_{}\";",
            self.trigger("insert"),
            self.trigger("update"),
            self.trigger("delete"),
            self.table(),
            self.table()
        )
    }

    fn recount_select(&self) -> String {
        let group_values = self
            .group
            .iter()
            .map(|g| Self::group_value(g, ""))
            .collect::<Vec<_>>();
        let measures = self
            .measures
            .iter()
            .map(|a| match a.measure {
                Measure::Count => "count(*)".to_owned(),
                Measure::Sum => format!("sum(\"{}\")", a.name),
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "SELECT {},{measures},count(*) FROM \"{}\" WHERE deleted_at = 0 GROUP BY {}",
            group_values.join(","),
            self.model,
            group_values.join(",")
        )
    }

    /// Recomputes every total from the source rows.
    pub(crate) fn rebuild(&self, connection: &rusqlite::Connection) -> Result<()> {
        let table = self.table();
        let groups = Self::quoted(self.group.iter().map(|g| g.field.as_str()));
        let measures = Self::quoted(self.measures.iter().map(|a| a.name.as_str()));
        connection.execute_batch(&format!(
            "DELETE FROM \"{table}\";
             INSERT INTO \"{table}\"(id,{groups},{measures},day2_rows)
             SELECT {},* FROM ({}) ;
             UPDATE \"day2_rollup_sequence_{table}\" SET value=value+(SELECT count(*) FROM \"{table}\");",
            Self::id_sql(&format!("(SELECT value FROM \"day2_rollup_sequence_{table}\") + row_number() OVER (ORDER BY {groups})")),
            self.recount_select()
        ))?;
        Ok(())
    }

    /// Groups whose stored totals differ from a recount of the source rows, in
    /// either direction. Zero for a correctly maintained rollup.
    pub fn mismatches(&self, connection: &rusqlite::Connection) -> Result<i64> {
        let columns = Self::quoted(
            self.group
                .iter()
                .map(|g| g.field.as_str())
                .chain(self.measures.iter().map(|a| a.name.as_str())),
        );
        let stored = format!("SELECT {columns},day2_rows FROM \"{}\"", self.table());
        let recount = self.recount_select();
        Ok(connection.query_row(
            &format!(
                "SELECT (SELECT count(*) FROM ({stored} EXCEPT {recount})) + \
                 (SELECT count(*) FROM ({recount} EXCEPT {stored}))"
            ),
            [],
            |row| row.get(0),
        )?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;
    use rusqlite::{Connection, params};

    pub(crate) fn fixture() -> Result<(Connection, crate::schema::Schema)> {
        let schema: crate::schema::Schema = serde_json::from_value(serde_json::json!({
            "models":{"events":{"fields":{"owner":"text","time":"integer","amount":"integer"}}},
            "inputs":{},"foreign_keys":[],
            "rollups":[{"model":"events","name":"daily","group":[{"field":"owner"},{"field":"time","bucket":"day"}],
                "measures":[{"name":"amount","measure":{"kind":"sum"}},{"name":"count","measure":{"kind":"count"}}]}]
        }))?;
        schema.validate()?;
        let connection = Connection::open_in_memory()?;
        for sql in schema.ddl()? {
            connection.execute_batch(&sql)?;
        }
        Ok((connection, schema))
    }

    #[test]
    fn overlapping_names_keep_all_indexes_and_sequences_distinct() -> Result<()> {
        let (_, mut schema) = fixture()?;
        schema.models.insert(
            "sequence_events".to_owned(),
            schema.models["events"].clone(),
        );
        let mut count_suffix = schema.rollups[0].clone();
        count_suffix.name = "daily_count".to_owned();
        let mut sequence_prefix = schema.rollups[0].clone();
        sequence_prefix.model = "sequence_events".to_owned();
        schema.rollups.extend([count_suffix, sequence_prefix]);
        schema.validate()?;
        let db = Connection::open_in_memory()?;
        for sql in schema.ddl()? {
            db.execute_batch(&sql)?;
        }
        for model in ["events", "sequence_events"] {
            db.execute_batch(&format!(
                "INSERT INTO {model}(id,version,created_at,owner,time,amount) VALUES(1,1,0,'alice',1,7),(2,1,0,'alice',2,3)"
            ))?;
        }
        for rollup in &schema.rollups {
            assert_eq!(rollup.mismatches(&db)?, 0);
            let indexes: i64 = db.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='index' AND tbl_name=?1 AND name LIKE 'day2_rollup_%'",
                [rollup.table()],
                |row| row.get(0),
            )?;
            assert_eq!(
                indexes,
                1 + rollup.record(&schema.models[&rollup.model]).fields.len() as i64
            );
        }
        Ok(())
    }

    #[test]
    fn lifecycle_recount_rebuild_and_overflow_are_atomic() -> Result<()> {
        let (db, schema) = fixture()?;
        let rollup = &schema.rollups[0];
        db.execute_batch("INSERT INTO events(id,version,created_at,owner,time,amount) VALUES(1,1,0,'alice',1,7),(2,1,0,'alice',2,-7),(3,1,0,'bob',-1,9)")?;
        assert_eq!(rollup.mismatches(&db)?, 0);
        assert_eq!(
            db.query_row(
                "SELECT amount FROM events_daily WHERE owner='alice'",
                [],
                |r| r.get::<_, i64>(0)
            )?,
            0
        );
        for sql in [
            "UPDATE events SET amount=10 WHERE id=1",
            "UPDATE events SET owner='bob',time=90000 WHERE id=1",
            "UPDATE events SET deleted_at=1 WHERE id=2",
            "UPDATE events SET deleted_at=0 WHERE id=2",
            "DELETE FROM events WHERE id=3",
        ] {
            db.execute_batch(sql)?;
            assert_eq!(rollup.mismatches(&db)?, 0, "{sql}");
        }
        rollup.rebuild(&db)?;
        assert_eq!(rollup.mismatches(&db)?, 0);
        db.execute_batch("UPDATE events SET amount=9223372036854775807 WHERE id=1")?;
        assert!(db.execute_batch("INSERT INTO events(id,version,created_at,owner,time,amount) VALUES(4,1,0,'bob',90000,1)").is_err());
        assert_eq!(rollup.mismatches(&db)?, 0);
        assert_eq!(
            db.query_row("SELECT count(*) FROM events WHERE id=4", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        db.execute_batch("DELETE FROM events")?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM events_daily", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }

    #[test]
    fn utc_buckets_floor_before_epoch_and_week_starts_monday() -> Result<()> {
        let db = Connection::open_in_memory()?;
        for (bucket, time, expected) in [
            (Bucket::Hour, -1, -3600),
            (Bucket::Day, -1, -86400),
            (Bucket::Week, 0, -259200),
            (Bucket::Week, 345600, 345600),
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT {}", bucket.sql("?1")), [time], |r| r
                    .get::<_, i64>(0))?,
                expected
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_reclassifications_equal_independent_recounts(changes in prop::collection::vec((0i64..12, -200000i64..200000, -1000i64..1000, any::<bool>(), any::<bool>()), 1..80)) {
            let (db, schema) = fixture().unwrap();
            for (id,time,amount,bob,deleted) in changes {
                db.execute("INSERT INTO events(id,version,created_at,owner,time,amount,deleted_at) VALUES(?1,1,0,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,time=excluded.time,amount=excluded.amount,deleted_at=excluded.deleted_at",
                    params![id+1, if bob {"bob"} else {"alice"},time,amount,i64::from(deleted)]).unwrap();
                prop_assert_eq!(schema.rollups[0].mismatches(&db).unwrap(),0);
            }
        }
    }
}
