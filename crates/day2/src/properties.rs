use crate::{
    artifact::LoadedArtifact,
    protocol::{Context as InvocationContext, Instruction, Request, Response, Row},
    store::Runtime,
    worker::Worker,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet, fs, io::Read, os::unix::fs::OpenOptionsExt, path::Path, time::Duration,
};

pub const MAX_PROPERTY_FRAME: usize = crate::worker::PROPERTY_MAX_FRAME;
const EVIDENCE_METADATA_BUDGET: usize = 64 * 1024;

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

fn validate_snapshot_budget(
    snapshot: &Value,
    limits: &crate::artifact::VerificationLimits,
) -> Result<Vec<u8>> {
    let tables = snapshot.as_object().context("snapshot must be an object")?;
    let mut facts = 0usize;
    for rows in tables.values() {
        let rows = rows.as_array().context("snapshot table must be an array")?;
        ensure!(rows.len() <= limits.rows_per_model, "snapshot row budget");
        facts = facts.saturating_add(rows.len());
    }
    ensure!(facts <= limits.total_facts, "snapshot fact budget");
    let bytes = serde_json::to_vec(snapshot)?;
    ensure!(
        bytes.len() <= limits.snapshot_bytes,
        "verification snapshot byte budget"
    );
    Ok(bytes)
}

fn start_property_worker(
    executable: &Path,
    limits: &crate::artifact::VerificationLimits,
) -> Result<Worker> {
    #[cfg(target_os = "linux")]
    {
        Worker::start_verification(
            executable,
            limits.worker_memory_bytes,
            Duration::from_millis(limits.evaluation_timeout_ms),
            MAX_PROPERTY_FRAME,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (executable, limits);
        bail!("qualified property worker memory limit unavailable on this platform")
    }
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
    artifact.require_current_api()?;
    validate_catalog(&artifact.contract().properties)?;
    let models = &artifact.contract().schema.models;
    let tables = snapshot.as_object().context("snapshot must be an object")?;
    ensure!(
        tables.len() == models.len(),
        "incomplete or unknown snapshot tables"
    );
    let limits = artifact
        .contract()
        .verification_limits
        .as_ref()
        .context("artifact verification limits missing")?;
    limits.validate()?;
    let snapshot_bytes = validate_snapshot_budget(snapshot, limits)?;
    for (name, model) in models {
        let rows = tables
            .get(name)
            .and_then(Value::as_array)
            .context("missing snapshot table")?;
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
    let mut worker = start_property_worker(&executable, limits)?;
    let request = Request {
        operation: "$properties".into(),
        input: String::from_utf8(snapshot_bytes)?,
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
    let request_bytes = serde_json::to_vec(&request)?;
    ensure!(
        request_bytes.len() < MAX_PROPERTY_FRAME,
        "property request frame budget"
    );
    let response_bytes = worker.exchange_bounded(
        &request_bytes,
        MAX_PROPERTY_FRAME,
        Duration::from_millis(limits.evaluation_timeout_ms),
    )?;
    let response: Response = serde_json::from_slice(&response_bytes)?;
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

/// Ordinary property checks capture their live snapshot through Runtime.
/// Explicit JSON snapshots are reserved for probes and saved-evidence replay.
pub fn require(runtime: &Runtime, evidence_dir: &Path) -> Result<Evidence> {
    let snapshot = runtime.application_snapshot()?;
    evaluate(runtime.artifact(), snapshot.as_value())?.require(evidence_dir)
}

impl Evidence {
    pub fn require(self, evidence_dir: &Path) -> Result<Self> {
        let failures: Vec<_> = self
            .checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| check.name.as_str())
            .collect();
        if !failures.is_empty() {
            let bytes = serde_json::to_vec_pretty(&self)?;
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
        Ok(self)
    }
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

fn evidence_byte_limit(limits: &crate::artifact::VerificationLimits) -> Result<u64> {
    limits.validate()?;
    let maximum = limits
        .snapshot_bytes
        .checked_add(MAX_PROPERTY_FRAME)
        .and_then(|bytes| bytes.checked_add(EVIDENCE_METADATA_BUDGET))
        .context("property evidence byte limit overflow")?;
    u64::try_from(maximum).context("property evidence byte limit overflow")
}

fn read_evidence_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    ensure!(
        path_metadata.file_type().is_file() && path_metadata.len() <= maximum,
        "property evidence file type or byte budget"
    );
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .context("property evidence file unavailable")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum,
        "property evidence file type or byte budget"
    );
    let read_limit = maximum
        .checked_add(1)
        .context("property evidence byte limit overflow")?;
    let mut bytes = Vec::new();
    file.take(read_limit).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= maximum,
        "property evidence byte budget"
    );
    Ok(bytes)
}

/// Read bounded saved evidence without following links, then replay it offline.
pub fn replay_file(artifact: &LoadedArtifact, path: &Path) -> Result<Evidence> {
    artifact.require_current_api()?;
    let limits = artifact
        .contract()
        .verification_limits
        .as_ref()
        .context("artifact verification limits missing")?;
    let bytes = read_evidence_file(path, evidence_byte_limit(limits)?)?;
    let evidence: Evidence = serde_json::from_slice(&bytes).context("decode property evidence")?;
    replay(artifact, &evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn replay_artifact() -> Result<LoadedArtifact> {
        let contract: crate::artifact::Artifact = serde_json::from_value(json!({
            "format": crate::artifact::CURRENT_FORMAT,
            "verification_limits": crate::artifact::VerificationLimits::QUALIFIED,
            "roc_version": "test",
            "worker_digest": "test",
            "schema_digest": "test",
            "schema": {"models": {}, "inputs": {}, "foreign_keys": []},
            "operations": [],
            "sources": {},
            "admission": "local-spike-only"
        }))?;
        Ok(LoadedArtifact::from_contract_for_tests(
            "expected-artifact".into(),
            std::path::PathBuf::new(),
            contract,
        ))
    }

    #[test]
    fn qualified_snapshot_limits_accept_exact_capacity_and_fail_closed_at_plus_one() -> Result<()> {
        let limits = crate::artifact::VerificationLimits::QUALIFIED;
        let home_like = |id: usize| {
            json!({
                "id": id.to_string(),
                "version": 1,
                "created_at": 1_758_067_230_000_i64,
                "data": json!({
                    "title": format!("Home \"favorite\" #{id}"),
                    "url": format!("https://example.test/items/{id}?q=one\\two"),
                    "description": "A row with UTF-8: café and a newline\\n; JSON escaping must survive",
                    "favorite": id.is_multiple_of(2),
                    "tags": ["personal", "work"]
                }).to_string()
            })
        };
        let exact_row_limit =
            json!({"items": (0..limits.rows_per_model).map(home_like).collect::<Vec<_>>()});
        assert!(validate_snapshot_budget(&exact_row_limit, &limits).is_ok());
        let row_overflow =
            json!({"items": (0..=limits.rows_per_model).map(home_like).collect::<Vec<_>>()});
        assert!(validate_snapshot_budget(&row_overflow, &limits).is_err());

        let split = limits.total_facts / 2;
        let exact_cross_model_limit = json!({
            "folders": (0..split).map(home_like).collect::<Vec<_>>(),
            "items": (split..limits.total_facts).map(home_like).collect::<Vec<_>>()
        });
        assert!(validate_snapshot_budget(&exact_cross_model_limit, &limits).is_ok());
        let cross_model_overflow = json!({
            "folders": (0..split).map(home_like).collect::<Vec<_>>(),
            "items": (split..=limits.total_facts).map(home_like).collect::<Vec<_>>()
        });
        assert!(validate_snapshot_budget(&cross_model_overflow, &limits).is_err());

        let exact_bytes = serde_json::to_vec(&exact_cross_model_limit)?;
        let byte_limit = crate::artifact::VerificationLimits {
            snapshot_bytes: exact_bytes.len(),
            ..limits.clone()
        };
        assert!(validate_snapshot_budget(&exact_cross_model_limit, &byte_limit).is_ok());
        let one_byte_short = crate::artifact::VerificationLimits {
            snapshot_bytes: exact_bytes.len() - 1,
            ..limits
        };
        assert!(validate_snapshot_budget(&exact_cross_model_limit, &one_byte_short).is_err());
        Ok(())
    }

    #[test]
    fn replay_rejects_evidence_from_another_artifact_before_evaluation() -> Result<()> {
        let contract: crate::artifact::Artifact = serde_json::from_value(json!({
            "format": 2,
            "roc_version": "test",
            "worker_digest": "test",
            "schema_digest": "test",
            "schema": {"models": {}, "inputs": {}, "foreign_keys": []},
            "operations": [],
            "sources": {},
            "admission": "local-spike-only"
        }))?;
        let artifact = LoadedArtifact::from_contract_for_tests(
            "expected-artifact".into(),
            std::path::PathBuf::new(),
            contract,
        );
        let evidence = Evidence {
            format: 1,
            artifact: "different-artifact".into(),
            snapshot: json!({}),
            checks: Vec::new(),
        };
        assert!(replay(&artifact, &evidence).is_err());
        Ok(())
    }

    #[test]
    fn saved_evidence_reader_rejects_oversized_and_nonregular_files_without_mutation() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let oversized = directory.path().join("oversized.json");
        fs::write(&oversized, b"12345")?;
        let original = fs::read(&oversized)?;
        assert!(read_evidence_file(&oversized, 4).is_err());
        assert_eq!(fs::read(&oversized)?, original);
        assert!(read_evidence_file(directory.path(), 1024).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = directory.path().join("target.json");
            let link = directory.path().join("link.json");
            fs::write(&target, b"{}")?;
            symlink(&target, &link)?;
            assert!(read_evidence_file(&link, 1024).is_err());
            assert_eq!(fs::read(&target)?, b"{}");
        }
        Ok(())
    }

    #[test]
    fn replay_file_rejects_wrong_artifact_without_changing_saved_evidence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("evidence.json");
        let evidence = Evidence {
            format: 1,
            artifact: "different-artifact".into(),
            snapshot: json!({}),
            checks: Vec::new(),
        };
        let bytes = serde_json::to_vec(&evidence)?;
        fs::write(&path, &bytes)?;
        let error = replay_file(&replay_artifact()?, &path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("property evidence identity mismatch")
        );
        assert_eq!(fs::read(&path)?, bytes);
        Ok(())
    }

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
