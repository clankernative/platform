use crate::{
    artifact::LoadedArtifact,
    protocol::{Context as InvocationContext, Instruction, Request, Response, Row},
    worker::Worker,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};

pub const MAX_ROWS_PER_MODEL: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub format: u32,
    pub artifact: String,
    pub snapshot: Value,
    pub checks: Vec<Check>,
}

pub fn validate_catalog(names: &[String]) -> Result<()> {
    ensure!(
        !names.is_empty() && names.len() <= 64,
        "invalid property count"
    );
    let mut unique = BTreeSet::new();
    for name in names {
        day2_contracts::names::identifier(name)?;
        ensure!(unique.insert(name), "duplicate property name");
    }
    Ok(())
}

pub fn evaluate(artifact: &LoadedArtifact, snapshot: &Value) -> Result<Evidence> {
    ensure!(
        artifact.contract().format >= 2,
        "artifact has no property contract"
    );
    validate_catalog(&artifact.contract().properties)?;
    let models = &artifact.contract().schema.models;
    let tables = snapshot.as_object().context("snapshot must be an object")?;
    ensure!(
        tables.len() == models.len(),
        "incomplete or unknown snapshot tables"
    );
    for (name, model) in models {
        let rows = tables
            .get(name)
            .and_then(Value::as_array)
            .context("missing snapshot table")?;
        ensure!(rows.len() <= MAX_ROWS_PER_MODEL, "snapshot row budget");
        let mut ids = BTreeSet::new();
        for value in rows {
            let row: Row = serde_json::from_value(value.clone())?;
            ensure!(
                row.id.valid() && row.version > 0 && ids.insert(row.id),
                "invalid snapshot row identity"
            );
            model.validate_value(&serde_json::from_str(&row.data)?)?;
        }
    }
    // Properties have no observations or effect interpreter. They can only
    // evaluate the complete, bounded snapshot supplied by the verifier.
    let executable = artifact.materialize_worker()?;
    let mut worker = Worker::start(&executable)?;
    let request = Request {
        operation: "$properties".into(),
        input: serde_json::to_string(snapshot)?,
        context: InvocationContext {
            invocation_id: "properties".into(),
            actor: "verifier".into(),
            now: 0,
            // A property check is not an invocation: nothing authenticated it,
            // nothing scheduled it, and it reaches no data beyond the snapshot
            // it is handed. It says so rather than borrowing a cause it lacks.
            authentication: "verification".into(),
            caller: Vec::new(),
            authenticated: String::new(),
            delegation_rule: String::new(),
        },
        observations: Vec::new(),
    };
    let response: Response =
        serde_json::from_slice(&worker.exchange(&serde_json::to_vec(&request)?)?)?;
    ensure!(
        response.kind == "done"
            && response.consumed == 0
            && response.error.is_empty()
            && response.instruction == Instruction::default(),
        "invalid property response"
    );
    let checks: Vec<Check> = serde_json::from_str(&response.result)?;
    ensure!(
        checks
            .iter()
            .map(|check| &check.name)
            .eq(artifact.contract().properties.iter()),
        "property catalog mismatch"
    );
    ensure!(
        checks
            .iter()
            .all(|check| !check.passed || check.error.is_empty()),
        "property cannot pass with a decoding error"
    );
    Ok(Evidence {
        format: 1,
        artifact: artifact.id().to_owned(),
        snapshot: snapshot.clone(),
        checks,
    })
}

pub fn require(
    artifact: &LoadedArtifact,
    snapshot: &Value,
    evidence_dir: &Path,
) -> Result<Evidence> {
    let evidence = evaluate(artifact, snapshot)?;
    let failures: Vec<_> = evidence
        .checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| check.name.as_str())
        .collect();
    if !failures.is_empty() {
        let bytes = serde_json::to_vec_pretty(&evidence)?;
        let hash = crate::digest(&bytes);
        fs::create_dir_all(evidence_dir)?;
        let path = evidence_dir.join(format!("{}.json", hash.trim_start_matches("sha256:")));
        fs::write(&path, bytes)?;
        bail!(
            "properties failed: {}; evidence: {}",
            failures.join(", "),
            path.display()
        );
    }
    Ok(evidence)
}

pub fn replay(artifact: &LoadedArtifact, evidence: &Evidence) -> Result<Evidence> {
    ensure!(
        evidence.format == 1 && evidence.artifact == artifact.id(),
        "property evidence identity mismatch"
    );
    let actual = evaluate(artifact, &evidence.snapshot)?;
    ensure!(&actual == evidence, "property replay diverged");
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_catalog_is_nonempty_bounded_unique_and_closed() {
        assert!(validate_catalog(&["consistent".into()]).is_ok());
        for names in [
            vec![],
            vec!["duplicate".into(); 2],
            vec!["x".into(); 65],
            vec!["$properties".into()],
            vec!["".into()],
            vec!["day2_reserved".into()],
        ] {
            assert!(validate_catalog(&names).is_err());
        }
    }
}
