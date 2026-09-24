//! A typed, read-only Carta transport with explicitly seeded synthetic captures.
//! This is not a live Carta client. Operators and verification hosts may install
//! immutable captures; applications can only read their runtime's scoped capture.
//! The adapter preserves provider records and duplicates. Import decisions,
//! employee mapping, publication and financial calculations remain application code.
use crate::{protocol::Instruction, store::Runtime};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

pub const MAX_RECORDS: usize = 10_000;
pub const MAX_RECORD_BYTES: usize = 12_288;
const MAX_CAPTURE_BYTES: usize = 32 * 1_048_576;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum OptionalText {
    #[default]
    None,
    Some(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub id: String,
    pub issuer_id: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Stakeholder {
    pub id: String,
    pub issuer_id: String,
    pub full_name: String,
    pub email: String,
    pub employee_id: OptionalText,
    pub relationship: String,
    pub group: OptionalText,
    pub entity_type: String,
    pub address_country: OptionalText,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub issuer_id: String,
    pub stakeholder_id: String,
    pub equity_incentive_plan_name: String,
    pub issue_date: String,
    pub vesting_start_date: String,
    pub board_approval_date: String,
    pub stakeholder_acceptance_date: OptionalText,
    pub grant_expiration_date: String,
    pub iso_nso_split: bool,
    pub stock_option_type: String,
    pub quantity: String,
    pub outstanding_quantity: String,
    pub vested_quantity: String,
    pub exercised_quantity: String,
    pub exercise_price_currency: String,
    pub exercise_price_amount: String,
    pub security_label: String,
    pub early_exercisable: bool,
    pub vesting_schedule_name: String,
    pub vesting_schedule_last_modified_date: String,
    pub vesting_schedule_start_date: String,
    pub vesting_schedule_end_date: String,
    pub last_modified_datetime: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VestingEvent {
    pub id: String,
    pub grant_id: String,
    pub vest_date: String,
    pub quantity: String,
    pub iso_quantity: String,
    pub nso_quantity: String,
    pub performance_condition: bool,
    pub vested: bool,
    pub max_quantity: String,
    pub target_quantity: String,
    pub vested_quantity: OptionalText,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exercise {
    pub grant_id: String,
    pub exercise_id: String,
    pub quantity: String,
    pub fair_market_value_as_of_date: OptionalText,
    pub exercise_date: String,
    pub status: String,
    pub certificate_id: String,
    pub exercise_type: String,
    pub qualified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Record {
    Stakeholder(Stakeholder),
    Grant(Box<Grant>),
    VestingEvent(VestingEvent),
    Exercise(Exercise),
}

impl Record {
    fn envelope(&self) -> Result<String> {
        let record = serde_json::to_value(self)?;
        let data = serde_json::to_string(&record["data"])?;
        ensure!(data.len() <= MAX_RECORD_BYTES, "carta_record_byte_budget");
        Ok(json!({"kind":record["kind"],"data":data}).to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyntheticSnapshot {
    pub issuer_id: String,
    pub records: Vec<Record>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntheticFailure {
    Unavailable,
}

impl std::fmt::Display for SyntheticFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("carta_unavailable")
    }
}

impl std::error::Error for SyntheticFailure {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {
    #[serde(rename = "handle")]
    _handle: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Next {
    snapshot_id: String,
    cursor: u64,
    #[serde(rename = "handle")]
    _handle: String,
}

pub(crate) enum Read {
    Begin {
        scope: String,
        issuer_id: String,
    },
    Next {
        scope: String,
        snapshot_id: String,
        cursor: u64,
        issuer_id: String,
    },
}

pub(crate) fn authorized(
    runtime: &Runtime,
    instruction: &Instruction,
    issuer_id: &str,
) -> Result<Read> {
    match instruction.model.as_str() {
        "carta.snapshot.v1" => {
            let _: Empty = crate::json::decode(instruction.data.as_bytes())?;
            Ok(Read::Begin {
                scope: runtime.scope().into(),
                issuer_id: issuer_id.into(),
            })
        }
        "carta.record.v1" => {
            let next: Next = crate::json::decode(instruction.data.as_bytes())?;
            ensure!(
                next.snapshot_id.len() == 70
                    && next.snapshot_id.starts_with("carta_")
                    && next.snapshot_id[6..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    && next.cursor <= MAX_RECORDS as u64,
                "invalid_carta_cursor"
            );
            Ok(Read::Next {
                scope: runtime.scope().into(),
                snapshot_id: next.snapshot_id,
                cursor: next.cursor,
                issuer_id: issuer_id.into(),
            })
        }
        _ => anyhow::bail!("unknown_carta_capability"),
    }
}

fn upgrade(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS carta_snapshots (
            scope TEXT NOT NULL, id TEXT NOT NULL, issuer_id TEXT NOT NULL,
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            PRIMARY KEY(scope,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS carta_records (
            scope TEXT NOT NULL, snapshot TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
            envelope TEXT NOT NULL, PRIMARY KEY(scope,snapshot,ordinal),
            FOREIGN KEY(scope,snapshot) REFERENCES carta_snapshots(scope,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS carta_active (
            scope TEXT PRIMARY KEY, snapshot TEXT NOT NULL,
            FOREIGN KEY(scope,snapshot) REFERENCES carta_snapshots(scope,id)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS carta_failures (
            scope TEXT NOT NULL, snapshot TEXT NOT NULL, ordinal INTEGER NOT NULL,
            remaining INTEGER NOT NULL CHECK(remaining >= 0),
            PRIMARY KEY(scope,snapshot,ordinal),
            FOREIGN KEY(scope,snapshot) REFERENCES carta_snapshots(scope,id)
        ) STRICT;"
    )?;
    for table in ["carta_snapshots", "carta_records"] {
        for (action, suffix) in [("UPDATE", "update"), ("DELETE", "delete")] {
            connection.execute_batch(&format!(
                "CREATE TRIGGER IF NOT EXISTS {table}_no_{suffix} BEFORE {action} ON {table}
                 BEGIN SELECT RAISE(ABORT,'immutable_carta_snapshot'); END;"
            ))?;
        }
        let key = if table == "carta_snapshots" {
            "scope=NEW.scope AND id=NEW.id"
        } else {
            "scope=NEW.scope AND snapshot=NEW.snapshot AND ordinal=NEW.ordinal"
        };
        connection.execute_batch(&format!(
            "CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table}
             WHEN EXISTS(SELECT 1 FROM {table} WHERE {key})
             BEGIN SELECT RAISE(ABORT,'immutable_carta_snapshot'); END;"
        ))?;
    }
    Ok(())
}

fn seed(path: &Path, scope: &str, capture: &SyntheticSnapshot) -> Result<Snapshot> {
    seed_with_mode(path, scope, capture, false)
}

fn seed_with_mode(
    path: &Path,
    scope: &str,
    capture: &SyntheticSnapshot,
    only_unconfigured: bool,
) -> Result<Snapshot> {
    ensure!(
        !scope.is_empty() && scope.len() <= 1024,
        "invalid_carta_scope"
    );
    ensure!(
        !capture.issuer_id.is_empty() && capture.issuer_id.len() <= 128,
        "invalid_carta_issuer"
    );
    ensure!(
        capture.records.len() <= MAX_RECORDS,
        "carta_record_count_budget"
    );
    let mut envelopes = Vec::with_capacity(capture.records.len());
    let mut bytes = 0_usize;
    for record in &capture.records {
        let record_issuer = match record {
            Record::Stakeholder(record) => Some(&record.issuer_id),
            Record::Grant(record) => Some(&record.issuer_id),
            Record::VestingEvent(_) | Record::Exercise(_) => None,
        };
        if let Some(issuer_id) = record_issuer {
            ensure!(
                issuer_id == &capture.issuer_id,
                "carta_issuer_scope_mismatch"
            );
        }
        let envelope = record.envelope()?;
        bytes = bytes
            .checked_add(envelope.len())
            .context("carta_capture_byte_budget")?;
        ensure!(bytes <= MAX_CAPTURE_BYTES, "carta_capture_byte_budget");
        envelopes.push(envelope);
    }
    let identity = crate::digest(&serde_json::to_vec(&(
        "carta-synthetic-v1",
        scope,
        capture,
    ))?);
    let snapshot = Snapshot {
        id: format!("carta_{}", &identity[7..]),
        issuer_id: capture.issuer_id.clone(),
    };
    let mut connection = crate::store::open(path)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    upgrade(&tx)?;
    if only_unconfigured {
        let existing = tx.query_row(
            "SELECT s.id,s.issuer_id FROM carta_active a JOIN carta_snapshots s ON s.scope=a.scope AND s.id=a.snapshot WHERE a.scope=?1",
            [scope], |row| Ok(Snapshot { id: row.get(0)?, issuer_id: row.get(1)? }),
        ).optional()?;
        if let Some(existing) = existing {
            tx.commit()?;
            return Ok(existing);
        }
    }
    let present: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM carta_snapshots WHERE scope=?1 AND id=?2)",
        params![scope, snapshot.id],
        |row| row.get(0),
    )?;
    if !present {
        tx.execute(
            "INSERT INTO carta_snapshots VALUES(?1,?2,?3,?4)",
            params![
                scope,
                snapshot.id,
                snapshot.issuer_id,
                i64::try_from(envelopes.len())?
            ],
        )?;
        for (ordinal, envelope) in envelopes.iter().enumerate() {
            tx.execute(
                "INSERT INTO carta_records VALUES(?1,?2,?3,?4)",
                params![scope, snapshot.id, i64::try_from(ordinal)?, envelope],
            )?;
        }
    }
    tx.execute("INSERT INTO carta_active VALUES(?1,?2) ON CONFLICT(scope) DO UPDATE SET snapshot=excluded.snapshot", params![scope, snapshot.id])?;
    tx.commit()?;
    Ok(snapshot)
}

/// Explicit operator/test setup, never called by ordinary runtime loading or by
/// a Roc operation. Repeating an identical capture is idempotent; selecting a new
/// capture leaves all previously issued snapshot identities readable unchanged.
pub fn seed_synthetic(runtime: &Runtime, capture: &SyntheticSnapshot) -> Result<Snapshot> {
    seed(
        &runtime.db().with_file_name("carta.synthetic.sqlite"),
        runtime.scope(),
        capture,
    )
}

/// A shared, visibly synthetic provider model for disposable verification.
/// This function only constructs data; installing it always requires an explicit
/// native setup call. No application operation or ordinary runtime load calls it.
pub fn synthetic_example() -> SyntheticSnapshot {
    let issuer_id = "synthetic-issuer-1";
    let mut records = Vec::new();
    for name in ["alice", "bob"] {
        records.push(Record::Stakeholder(Stakeholder {
            id: format!("holder-{name}"),
            issuer_id: issuer_id.into(),
            full_name: format!("Synthetic {name}"),
            email: format!("{name}@example.test"),
            employee_id: OptionalText::Some(format!("employee-{name}")),
            relationship: "EMPLOYEE".into(),
            group: OptionalText::Some("Synthetic fixture".into()),
            entity_type: "INDIVIDUAL".into(),
            address_country: OptionalText::Some("US".into()),
        }));
    }
    for name in ["alice", "bob"] {
        let grant_id = format!("grant-{name}-1");
        records.push(Record::Grant(Box::new(Grant {
            id: grant_id.clone(),
            issuer_id: issuer_id.into(),
            stakeholder_id: format!("holder-{name}"),
            equity_incentive_plan_name: "Synthetic equity plan".into(),
            issue_date: "2024-01-01".into(),
            vesting_start_date: "2024-01-01".into(),
            board_approval_date: "2023-12-15".into(),
            stakeholder_acceptance_date: OptionalText::Some("2024-01-02".into()),
            grant_expiration_date: "2034-01-01".into(),
            iso_nso_split: false,
            stock_option_type: "ISO".into(),
            quantity: "1000".into(),
            outstanding_quantity: "900".into(),
            vested_quantity: "500".into(),
            exercised_quantity: "100".into(),
            exercise_price_currency: "USD".into(),
            exercise_price_amount: "0.25".into(),
            security_label: format!("SYNTHETIC-{name}"),
            early_exercisable: false,
            vesting_schedule_name: "Synthetic four-year schedule".into(),
            vesting_schedule_last_modified_date: "2024-01-01".into(),
            vesting_schedule_start_date: "2024-01-01".into(),
            vesting_schedule_end_date: "2028-01-01".into(),
            last_modified_datetime: "2026-01-01T00:00:00Z".into(),
        })));
        records.push(Record::VestingEvent(VestingEvent {
            id: format!("vesting-{name}-1"),
            grant_id: grant_id.clone(),
            vest_date: "2026-01-01".into(),
            quantity: "500".into(),
            iso_quantity: "500".into(),
            nso_quantity: "0".into(),
            performance_condition: false,
            vested: true,
            max_quantity: "500".into(),
            target_quantity: "500".into(),
            vested_quantity: OptionalText::Some("500".into()),
        }));
        records.push(Record::Exercise(Exercise {
            grant_id,
            exercise_id: format!("exercise-{name}-1"),
            quantity: "100".into(),
            fair_market_value_as_of_date: OptionalText::Some("2026-01-15".into()),
            exercise_date: "2026-01-15".into(),
            status: "COMPLETED".into(),
            certificate_id: format!("certificate-{name}-1"),
            exercise_type: "CASH".into(),
            qualified: true,
        }));
    }
    SyntheticSnapshot {
        issuer_id: issuer_id.into(),
        records,
    }
}

/// Verification campaigns deliberately supply the shared synthetic provider
/// model. An independently seeded campaign keeps its own world unchanged.
pub(crate) fn seed_verification_if_unconfigured(runtime: &Runtime) -> Result<()> {
    seed_with_mode(
        &runtime.db().with_file_name("carta.synthetic.sqlite"),
        runtime.scope(),
        &synthetic_example(),
        true,
    )?;
    Ok(())
}

/// A host-only deterministic failure schedule. The current runtime records an
/// observation error as terminal; a new business attempt can resume at this cursor.
pub fn fail_reads(runtime: &Runtime, snapshot_id: &str, cursor: u64, count: u32) -> Result<()> {
    ensure!(
        count <= 100 && cursor <= MAX_RECORDS as u64,
        "invalid_carta_failure_schedule"
    );
    let connection = crate::store::open(&runtime.db().with_file_name("carta.synthetic.sqlite"))?;
    connection.execute("INSERT INTO carta_failures VALUES(?1,?2,?3,?4) ON CONFLICT(scope,snapshot,ordinal) DO UPDATE SET remaining=excluded.remaining", params![runtime.scope(), snapshot_id, i64::try_from(cursor)?, i64::from(count)])?;
    Ok(())
}

pub(crate) fn observe(runtime: &Runtime, read: Read) -> Result<String> {
    read_at(&runtime.db().with_file_name("carta.synthetic.sqlite"), read)
}

fn read_at(path: &Path, read: Read) -> Result<String> {
    ensure!(path.is_file(), "carta_unconfigured");
    // OPEN_CREATE is intentionally absent: an unconfigured provider never creates
    // a plausible empty capture or silently supplies demonstration data.
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(std::time::Duration::from_secs(2))?;
    match read {
        Read::Begin { scope, issuer_id } => {
            let snapshot: Option<Snapshot> = connection.query_row(
                "SELECT s.id,s.issuer_id FROM carta_active a JOIN carta_snapshots s ON s.scope=a.scope AND s.id=a.snapshot WHERE a.scope=?1 AND s.issuer_id=?2",
                params![scope,issuer_id], |row| Ok(Snapshot { id: row.get(0)?, issuer_id: row.get(1)? }),
            ).optional()?;
            Ok(serde_json::to_string(
                &snapshot.context("carta_unconfigured")?,
            )?)
        }
        Read::Next {
            scope,
            snapshot_id,
            cursor,
            issuer_id,
        } => {
            let cursor = i64::try_from(cursor)?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let count: Option<i64> = tx
                .query_row(
                    "SELECT record_count FROM carta_snapshots WHERE scope=?1 AND id=?2 AND issuer_id=?3",
                    params![scope, snapshot_id,issuer_id],
                    |row| row.get(0),
                )
                .optional()?;
            let count = count.context("carta_snapshot_unavailable")?;
            ensure!(
                (0..=MAX_RECORDS as i64).contains(&count),
                "carta_record_count_budget"
            );
            ensure!(cursor <= count, "invalid_carta_cursor");
            let failed = tx.execute("UPDATE carta_failures SET remaining=remaining-1 WHERE scope=?1 AND snapshot=?2 AND ordinal=?3 AND remaining>0", params![scope, snapshot_id, cursor])?;
            if failed != 0 {
                tx.commit()?;
                return Err(SyntheticFailure::Unavailable.into());
            }
            let result = if cursor == count {
                json!({"kind":"done","data":"{}"}).to_string()
            } else {
                tx.query_row("SELECT envelope FROM carta_records WHERE scope=?1 AND snapshot=?2 AND ordinal=?3", params![scope, snapshot_id, cursor], |row| row.get::<_, String>(0))?
            };
            ensure!(
                result.len() <= MAX_RECORD_BYTES * 2 + 128,
                "carta_record_byte_budget"
            );
            tx.commit()?;
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture() -> SyntheticSnapshot {
        SyntheticSnapshot {
            issuer_id: "synthetic-issuer".into(),
            records: vec![Record::Stakeholder(Stakeholder {
                id: "holder-1".into(),
                issuer_id: "synthetic-issuer".into(),
                full_name: "Synthetic Holder".into(),
                employee_id: OptionalText::Some(String::new()),
                ..Stakeholder::default()
            })],
        }
    }

    fn next(scope: &str, id: &str, cursor: u64) -> Read {
        Read::Next {
            scope: scope.into(),
            snapshot_id: id.into(),
            cursor,
            issuer_id: "synthetic-issuer".into(),
        }
    }

    #[test]
    fn unconfigured_scope_and_substituted_snapshot_are_refused() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sqlite");
        assert!(
            read_at(
                &path,
                Read::Begin {
                    scope: "first".into(),
                    issuer_id: "synthetic-issuer".into(),
                }
            )
            .is_err()
        );
        assert!(!path.exists());
        let snapshot = seed(&path, "first", &capture())?;
        assert!(
            read_at(
                &path,
                Read::Begin {
                    scope: "second".into(),
                    issuer_id: "synthetic-issuer".into(),
                }
            )
            .is_err()
        );
        assert!(read_at(&path, next("second", &snapshot.id, 0)).is_err());
        assert!(
            read_at(
                &path,
                Read::Begin {
                    scope: "first".into(),
                    issuer_id: "another-issuer".into()
                }
            )
            .is_err(),
            "a configured scope does not authorize every issuer"
        );
        assert!(
            read_at(
                &path,
                Read::Next {
                    scope: "first".into(),
                    snapshot_id: snapshot.id.clone(),
                    cursor: 0,
                    issuer_id: "another-issuer".into()
                }
            )
            .is_err(),
            "a snapshot ID cannot substitute for issuer authority"
        );
        assert!(read_at(&path, next("first", "unknown", 0)).is_err());
        assert!(read_at(&path, next("first", &snapshot.id, 2)).is_err());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read_at(
                &path,
                next("first", &snapshot.id, 1)
            )?)?["kind"],
            "done"
        );
        Ok(())
    }

    #[test]
    fn immutable_captures_preserve_duplicates_options_and_old_reads() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sqlite");
        let first = capture();
        let snapshot = seed(&path, "first", &first)?;
        assert_eq!(seed(&path, "first", &first)?, snapshot);
        let original = read_at(&path, next("first", &snapshot.id, 0))?;
        let mut replacement = first.clone();
        replacement.records.push(first.records[0].clone());
        let newer = seed(&path, "first", &replacement)?;
        assert_ne!(newer.id, snapshot.id);
        assert_eq!(original, read_at(&path, next("first", &snapshot.id, 0))?);
        assert_eq!(
            read_at(&path, next("first", &newer.id, 0))?,
            read_at(&path, next("first", &newer.id, 1))?
        );
        let envelope: serde_json::Value = serde_json::from_str(&original)?;
        let data: serde_json::Value = serde_json::from_str(envelope["data"].as_str().unwrap())?;
        assert_eq!(data["employee_id"], json!({"Some":""}));
        assert_eq!(data["group"], "None");
        let connection = Connection::open(&path)?;
        assert!(
            connection
                .execute("UPDATE carta_records SET envelope='{}'", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM carta_snapshots", [])
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT OR REPLACE INTO carta_records SELECT * FROM carta_records LIMIT 1",
                    []
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn issuer_and_byte_budgets_fail_before_any_capture_is_published() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sqlite");
        let mut invalid = capture();
        invalid.issuer_id = "other".into();
        assert!(seed(&path, "first", &invalid).is_err());
        assert!(!path.exists());
        let mut oversized = capture();
        let Record::Stakeholder(holder) = &mut oversized.records[0] else {
            unreachable!()
        };
        holder.full_name = "x".repeat(MAX_RECORD_BYTES);
        assert!(seed(&path, "first", &oversized).is_err());
        assert!(!path.exists());
        let mut many = capture();
        many.records = vec![many.records[0].clone(); MAX_RECORDS + 1];
        assert!(seed(&path, "first", &many).is_err());
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn scheduled_read_failure_is_typed_and_never_changes_snapshot_data() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sqlite");
        let snapshot = seed(&path, "first", &capture())?;
        let original = read_at(&path, next("first", &snapshot.id, 0))?;
        Connection::open(&path)?.execute(
            "INSERT INTO carta_failures VALUES('first',?1,0,1)",
            [&snapshot.id],
        )?;
        let error = read_at(&path, next("first", &snapshot.id, 0)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<SyntheticFailure>(),
            Some(&SyntheticFailure::Unavailable)
        );
        assert_eq!(original, read_at(&path, next("first", &snapshot.id, 0))?);
        Ok(())
    }

    #[test]
    fn verification_seed_does_not_replace_a_configured_world() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("provider.sqlite");
        let existing = seed(&path, "first", &capture())?;
        assert_eq!(
            seed_with_mode(&path, "first", &synthetic_example(), true)?,
            existing
        );
        let fixture = seed_with_mode(&path, "second", &synthetic_example(), true)?;
        assert_eq!(fixture.issuer_id, "synthetic-issuer-1");
        assert_eq!(synthetic_example().records.len(), 8);
        Ok(())
    }
}
