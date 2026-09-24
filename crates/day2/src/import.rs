//! Carrying records from a previous system into an application.
//!
//! There is no bulk write. Each record is one invocation of a command the
//! application declares for the purpose, so everything an ordinary write goes
//! through — the operation's authority, input validation, the application's own
//! rules, the transaction, the mutation audit — an imported record goes through
//! too. The platform contributes three things only:
//!
//! - **Invocation identity from the source record.** A record's key and its
//!   exact input become its invocation id. Importing the same file again replays
//!   what was already done instead of doing it twice, so an interrupted import is
//!   resumed by running it again. A record corrected after a refusal has
//!   different input, so it runs afresh rather than replaying the refusal; a
//!   second copy of something already imported is the application's to refuse,
//!   as it would refuse any duplicate.
//! - **One refusal does not stop the rest.** A record the application refuses is
//!   reported with its code and the import moves on, so one bad record costs one
//!   record rather than the run.
//! - **A report, line for line.** Each input line produces one output line naming
//!   its key and either the new record's id or why it was refused. That report is
//!   the mapping from the old system's identifiers to the new ones.
//!
//! Each record is imported *for* someone. The operator running the import
//! authenticates as themselves and acts for the record's `actor` under an
//! instance delegation rule, exactly as any on-behalf-of request does. So a
//! record's owner is whoever the invocation acts for — the platform's rule that
//! a row is owned by the actor who created it holds for imported rows too — and
//! the audit names the operator as initiator beside them.
//!
//! The source format is JSON lines:
//! `{"key": "<source id>", "actor": "<who it is for>", "input": {...}}`.

use crate::store::{Fault, Runtime};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};

/// The most lines one import will read. Far above any current source and low
/// enough that a runaway file is refused rather than read to exhaustion.
const MAX_LINES: usize = 1_000_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    key: String,
    actor: String,
    input: Value,
}

/// What became of one source record.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Imported {
    pub line: usize,
    pub key: String,
    /// `imported`, or `refused` with a code.
    pub outcome: &'static str,
    /// The new record's id, when the command returned one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Summary {
    pub imported: usize,
    pub refused: usize,
}

/// The invocation id a source record is imported under.
///
/// Keys are restricted to what an invocation id may hold rather than encoded,
/// so the id in the audit log begins with the source record's own identifier.
/// The digest after it is of the exact actor and input, which is what the host
/// binds an invocation id to.
pub fn invocation_id(operation: &str, key: &str, actor: &str, input: &Value) -> Result<String> {
    ensure!(
        !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "invalid_import_key"
    );
    let digest = crate::digest(serde_json::to_string(&(actor, input))?.as_bytes());
    let id = format!(
        "import-{operation}-{key}-{}",
        &crate::assets::hash_part(&digest)?[..16]
    );
    ensure!(id.len() <= 128, "invalid_import_key");
    Ok(id)
}

/// Import every line of `source` through `operation`, authenticated as
/// `operator` and acting for each line's actor, writing one report line per
/// source line to `report`.
///
/// A malformed line is refused like a refused record, so the report stays line
/// for line. So is a record the host could not run at all — an outage reads as
/// `internal_error` on each line it touched — because running the same source
/// again is always safe: imported records replay, refused ones are tried again.
/// Only a source that cannot be read or a report that cannot be written stops
/// the import.
pub fn run(
    runtime: &Runtime,
    operation: &str,
    operator: &str,
    source: impl BufRead,
    now: i64,
    mut report: impl Write,
) -> Result<Summary> {
    runtime.artifact().route(operation)?;
    let mut summary = Summary::default();
    for (index, raw) in source.lines().enumerate() {
        ensure!(index < MAX_LINES, "import_too_large");
        let raw = raw.context("import source unreadable")?;
        let line = index + 1;
        let imported = match serde_json::from_str::<Line>(&raw) {
            Err(_) => refused(line, String::new(), "invalid_import_line"),
            Ok(record) => one(runtime, operation, operator, line, record, now),
        };
        if imported.outcome == "imported" {
            summary.imported += 1;
        } else {
            summary.refused += 1;
        }
        serde_json::to_writer(&mut report, &imported)?;
        report.write_all(b"\n")?;
    }
    report.flush()?;
    Ok(summary)
}

fn refused(line: usize, key: String, error: &str) -> Imported {
    Imported {
        line,
        key,
        outcome: "refused",
        id: None,
        error: error.to_owned(),
    }
}

fn one(
    runtime: &Runtime,
    operation: &str,
    operator: &str,
    line: usize,
    record: Line,
    now: i64,
) -> Imported {
    let id = match invocation_id(operation, &record.key, &record.actor, &record.input) {
        Ok(id) => id,
        Err(_) => return refused(line, record.key, "invalid_import_key"),
    };
    let accepted = runtime.accept_on_behalf_of(
        operation,
        crate::store::ActingAs {
            authenticated: operator,
            actor: &record.actor,
            trigger: crate::audit::Trigger::Request,
        },
        &id,
        &record.input,
        now,
    );
    match accepted.and_then(|()| runtime.execute(&id, Fault::None)) {
        Ok(outcome) if outcome.status == "success" => Imported {
            line,
            id: outcome.result["id"].as_str().map(str::to_owned),
            key: record.key,
            outcome: "imported",
            error: String::new(),
        },
        Ok(outcome) => refused(
            line,
            record.key,
            if outcome.error.is_empty() {
                &outcome.status
            } else {
                &outcome.error
            },
        ),
        Err(error) => refused(line, record.key, crate::error::classify(&error).code()),
    }
}
