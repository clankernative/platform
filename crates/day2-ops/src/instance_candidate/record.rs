//! The instance's deployment candidate records, byte for byte as its earlier
//! Python controller wrote and validated them, so a record either one wrote
//! serves the other: the candidate record, the checked-inputs record (the same
//! shape), the reuse proof and the paths of all three and of the build log.
//!
//! Bytes are `json.dumps(value, sort_keys=True)` with the default separators
//! and a final newline; a binding's digest is the sha256 of the same encoding
//! without the newline. Only the shape the live path writes is accepted: a
//! qualified SDK release and a checked main artifact.
use crate::instance_source::{
    self, BINDING_FIELDS, app_image, contract, hash, identifier, int, object_with,
    verification_profile,
};
use anyhow::{Result, anyhow, ensure};
use day2::python_json::{self, Layout};
use day2::sdk_release::MANIFEST_LIMIT;
use serde_json::{Value, json};

/// Where the records live in the instance's state bucket.
pub const STATE: &str = "day2/app-releases";

/// The most a record may hold, as for all deployment metadata.
pub const RECORD_LIMIT: u64 = 1_048_576;

/// Every field of a candidate record: the base fields, the qualified SDK's
/// admission and inputs, and the checked main artifact's provenance.
pub const FIELDS: [&str; 10] = [
    "version",
    "binding",
    "source_commit",
    "image",
    "artifact_id",
    "build_log",
    "security_requirements",
    "source_inputs",
    "checked_commit",
    "ci_artifact",
];

/// `gs://<bucket>/day2/app-releases`.
pub fn state(bucket: &str) -> String {
    format!("gs://{bucket}/{STATE}")
}

/// A binding's digest: the sha256 hex of its default-separator,
/// sorted-key encoding.
pub fn binding_digest(binding: &Value) -> Result<String> {
    let digest = day2::digest(&python_json::dumps(binding, Layout::Default)?);
    Ok(digest["sha256:".len()..].to_owned())
}

/// The candidate record for a binding and a source commit.
pub fn candidate_uri(bucket: &str, app: &str, digest: &str, commit: &str) -> String {
    format!("{}/{app}/candidates/{digest}/{commit}.json", state(bucket))
}

/// The checked-inputs record for a binding and the checked source inputs.
pub fn inputs_uri(bucket: &str, app: &str, digest: &str, inputs: &str) -> String {
    let hex = inputs.strip_prefix("sha256:").unwrap_or(inputs);
    format!("{}/{app}/checked-inputs/{digest}/{hex}.json", state(bucket))
}

/// The build log (or reuse proof) for a binding and a source commit.
pub fn log_uri(bucket: &str, app: &str, digest: &str, commit: &str) -> String {
    format!("{}/{app}/builds/{digest}/{commit}.log", state(bucket))
}

/// A record's bytes: the sorted-key, default-separator encoding and a
/// newline.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = python_json::dumps(value, Layout::Default)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Deployment metadata: at most 1 MiB, and no duplicate key at any depth.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() as u64 <= RECORD_LIMIT,
        "deployment metadata exceeds byte limit"
    );
    day2::json::decode_with_limits(bytes, RECORD_LIMIT as usize, RECORD_LIMIT as usize).map_err(
        |error| {
            if format!("{error:#}").contains("duplicate JSON key") {
                anyhow!("duplicate JSON field")
            } else {
                anyhow!("invalid deployment metadata JSON")
            }
        },
    )
}

/// The candidate shapes of the earlier controller that this one does not
/// write: without a qualified SDK release, or without a checked main artifact.
fn unported(value: &Value) -> Result<()> {
    ensure!(
        !object_with(value, &FIELDS[..6]) && !object_with(value, &FIELDS[..9]),
        "deployment candidates without a qualified SDK release and a checked main artifact are not \
         supported"
    );
    Ok(())
}

/// A string field, or the empty string.
fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_default()
}

/// A candidate record's validation, for `app`, in the earlier controller's
/// order and with its messages: the
/// record's fields, its binding, its native admission and checked main
/// artifact, its app-local images and its private build log under `bucket`.
pub fn check(value: &Value, app: &str, registry: &str, bucket: &str) -> Result<()> {
    unported(value)?;
    ensure!(
        object_with(value, &FIELDS),
        "invalid deployment candidate fields"
    );
    ensure!(
        int(&value["version"]) == Some(1),
        "unsupported deployment candidate version"
    );
    let binding = &value["binding"];
    instance_source::unported_binding(binding)?;
    ensure!(
        object_with(binding, &BINDING_FIELDS),
        "invalid candidate build binding"
    );
    instance_source::blob(&binding["qualified_release"], MANIFEST_LIMIT)?;
    verification_profile(&binding["verification"])?;
    ensure!(
        value["source_inputs"].as_str().is_some_and(hash)
            && value["checked_commit"]
                .as_str()
                .is_some_and(instance_source::commit),
        "invalid checked app inputs"
    );
    let requirements = &value["security_requirements"];
    ensure!(
        requirements.is_object()
            && int(&requirements["version"]) == Some(1)
            && requirements["artifact"].as_str()
                == Some(format!("sha256:{}", text(value, "artifact_id")).as_str())
            && requirements["containment"]["kind"] == "linux_qualified_v1",
        "candidate native admission belongs to another artifact"
    );
    contract(&binding["ci_artifact"])?;
    instance_source::proof(
        &value["ci_artifact"],
        binding,
        text(value, "checked_commit"),
        text(value, "source_inputs"),
    )?;
    ensure!(
        value["artifact_id"] == value["ci_artifact"]["receipt"]["artifact_id"],
        "candidate differs from its checked main artifact"
    );
    ensure!(binding["app"] == app, "release belongs to another app");
    instance_source::identity(&binding["source"])?;
    ensure!(
        binding["source"]["repository"] == binding["repository"],
        "release source mismatch"
    );
    ensure!(
        app_image(text(value, "image"), registry, app, true)
            && app_image(text(binding, "tooling_image"), registry, app, true)
            && app_image(text(binding, "runtime_image"), registry, app, true),
        "release images must be pinned and app-local"
    );
    ensure!(
        value["image"]
            .as_str()
            .and_then(|image| image.split('@').next())
            == binding["image_repository"].as_str(),
        "release image mismatch"
    );
    ensure!(
        value["source_commit"]
            .as_str()
            .is_some_and(instance_source::commit),
        "invalid release source commit"
    );
    ensure!(
        value["artifact_id"]
            .as_str()
            .is_some_and(|id| instance_source::lower_hex(id, 64)),
        "invalid release artifact"
    );
    let log = log_uri(
        bucket,
        app,
        &binding_digest(binding)?,
        text(value, "source_commit"),
    );
    ensure!(
        value["build_log"] == log,
        "release evidence must remain in private app release state"
    );
    Ok(())
}

/// The checks the earlier build host made of the binding it received, for a
/// binding under `registry`: its shape, its app, its pinned app-local images,
/// its image repository and its source directory.
pub fn native_binding(binding: &Value, registry: &str) -> Result<String> {
    instance_source::unported_binding(binding)?;
    ensure!(
        object_with(binding, &BINDING_FIELDS),
        "invalid candidate build binding"
    );
    let app = text(binding, "app");
    ensure!(identifier(app), "invalid deployment app ID");
    ensure!(
        app_image(text(binding, "runtime_image"), registry, app, true)
            && app_image(text(binding, "tooling_image"), registry, app, true),
        "builder requires pinned app-local images"
    );
    ensure!(
        app_image(text(binding, "image_repository"), registry, app, false),
        "builder image repository mismatch"
    );
    ensure!(
        binding["directory"]
            .as_str()
            .is_some_and(instance_source::directory),
        "invalid source subdirectory"
    );
    instance_source::blob(&binding["qualified_release"], MANIFEST_LIMIT)?;
    verification_profile(&binding["verification"])?;
    contract(&binding["ci_artifact"])?;
    instance_source::identity(&binding["source"])?;
    Ok(app.to_owned())
}

/// The proof that `commit` reuses the cached checked result.
pub fn reuse_proof(digest: &str, commit: &str, inputs: &str, cached: &Value) -> Value {
    json!({
        "version": 1,
        "kind": "checked-input-reuse",
        "binding": digest,
        "source_commit": commit,
        "source_inputs": inputs,
        "checked_commit": cached["checked_commit"],
        "checked_log": cached["build_log"],
        "image": cached["image"],
        "artifact_id": cached["artifact_id"],
    })
}

/// The cached record for another commit: its source commit and build log,
/// everything else unchanged.
pub fn reused(cached: &Value, commit: &str, log: &str) -> Value {
    let mut value = cached.clone();
    value["source_commit"] = json!(commit);
    value["build_log"] = json!(log);
    value
}
