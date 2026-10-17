use super::*;
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

fn artifact() -> Result<LoadedArtifact> {
    let contract: crate::artifact::Artifact = serde_json::from_value(json!({
        "format": crate::artifact::CURRENT_FORMAT,
        "verification_limits": crate::artifact::VerificationLimits::QUALIFIED,
        "roc_version": "test",
        "worker_digest": "test-worker",
        "schema_digest": "test-schema",
        "schema": {
            "models": {},
            "inputs": {"Input": {"fields": {"name": "text"}}},
            "foreign_keys": []
        },
        "operations": [{"name":"app.create","kind":"command","input_type":"Input","output_type":"Text"}],
        "sources": {},
        "admission": "local-spike-only"
    }))?;
    Ok(LoadedArtifact::from_contract_for_tests(
        "test-artifact".into(),
        Path::new("/test/artifact").into(),
        contract,
    ))
}

fn request(action: VerificationAction) -> VerificationRequest {
    let invocation = VerificationInvocation {
        actor: "reviewer-7",
        input: r#"{"name":"Ada"}"#,
        seed: 9182,
    };
    verification_request(
        "check",
        "app.create",
        &json!({"version":3}),
        &json!({"rows":[{"id":"before"}]}),
        &json!({"created":true}),
        &invocation,
    )
    .map(|mut request| {
        request.action = action;
        request
    })
    .unwrap()
}

fn reply(value: &str, error: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"value":value,"error":error})).unwrap()
}

fn failure_record(
    artifact: &LoadedArtifact,
    request: VerificationRequest,
    stage: VerificationStage,
    callback: impl FnMut() -> Result<Vec<u8>>,
) -> VerificationFailure {
    let (result, responses, generated_input) =
        observe_verification(artifact, &request, stage, callback);
    VerificationFailure {
        format: 1,
        artifact: artifact.id().into(),
        request,
        stage,
        responses,
        error: format!("{:#}", result.unwrap_err()),
        generated_input,
    }
}

fn replay(
    dir: &Path,
    artifact: &LoadedArtifact,
    record: &VerificationFailure,
    callback: impl FnMut(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    let path = save_verification_failure(dir, record)?;
    replay_verification_with(artifact, &path, callback)
}

#[test]
fn saved_check_failure_retains_complete_context_and_replays_the_exact_request() -> Result<()> {
    let artifact = artifact()?;
    let request = request(VerificationAction::Check);
    let record = failure_record(
        &artifact,
        request.clone(),
        VerificationStage::Callback,
        || Ok(reply("", "post-check rejected")),
    );
    let dir = tempfile::tempdir()?;
    let path = save_verification_failure(dir.path(), &record)?;
    let original = fs::read(&path)?;
    let mut observed = Vec::new();
    replay_verification_with(&artifact, &path, |frame| {
        observed.push(std::str::from_utf8(frame)?.to_owned());
        Ok(reply("", "post-check rejected"))
    })?;
    assert_eq!(
        observed,
        vec![format!("verify:{}", serde_json::to_string(&request)?); 2]
    );
    assert_eq!(fs::read(path)?, original, "replay must not mutate evidence");
    let context: Value = serde_json::from_str(&request.snapshot)?;
    assert_eq!(context["verification"]["actor"], "reviewer-7");
    assert_eq!(context["verification"]["input"], r#"{"name":"Ada"}"#);
    assert_eq!(request.seed, 9182);
    assert!(request.before.contains("before"));
    assert_eq!(request.output, r#"{"created":true}"#);
    Ok(())
}

#[test]
fn saved_input_preparation_failure_replays_the_recorded_context() -> Result<()> {
    let artifact = artifact()?;
    let request = request(VerificationAction::Input);
    let record = failure_record(
        &artifact,
        request.clone(),
        VerificationStage::Callback,
        || Ok(reply("", "input preparation rejected")),
    );
    let dir = tempfile::tempdir()?;
    let path = save_verification_failure(dir.path(), &record)?;
    let mut observed = Vec::new();
    replay_verification_with(&artifact, &path, |frame| {
        observed.push(std::str::from_utf8(frame)?.to_owned());
        Ok(reply("", "input preparation rejected"))
    })?;
    assert_eq!(
        observed,
        vec![format!("verify:{}", serde_json::to_string(&request)?); 2]
    );
    assert_eq!(request.seed, 9182);
    assert!(request.snapshot.contains("reviewer-7"));
    assert!(request.before.contains("before"));
    assert!(request.output.contains("created"));
    Ok(())
}

#[test]
fn malformed_generated_input_is_saved_with_actual_produced_value_and_replayed() -> Result<()> {
    let artifact = artifact()?;
    let request = request(VerificationAction::Input);
    let produced = "{\"unexpected\":true}".to_owned();
    let record = failure_record(
        &artifact,
        request,
        VerificationStage::GeneratedInput,
        || Ok(reply(&produced, "")),
    );
    assert!(record.error.contains("unknown field") || record.error.contains("name"));
    assert_eq!(record.generated_input.as_deref(), Some(produced.as_str()));
    assert_eq!(record.responses.len(), 2);
    let dir = tempfile::tempdir()?;
    let path = save_verification_failure(dir.path(), &record)?;
    replay_verification_with(&artifact, &path, |_| Ok(reply(&produced, "")))?;
    Ok(())
}

#[test]
fn callback_operational_failures_and_nondeterminism_preserve_only_observed_fingerprints()
-> Result<()> {
    let artifact = artifact()?;
    let req = request(VerificationAction::Check);
    let zero = failure_record(&artifact, req.clone(), VerificationStage::Callback, || {
        anyhow::bail!("worker unavailable")
    });
    assert!(zero.responses.is_empty());
    let dir = tempfile::tempdir()?;
    replay(dir.path(), &artifact, &zero, |_| {
        anyhow::bail!("worker unavailable")
    })?;

    let mut calls = 0;
    let one = failure_record(&artifact, req.clone(), VerificationStage::Callback, || {
        calls += 1;
        if calls == 1 {
            Ok(reply("", ""))
        } else {
            anyhow::bail!("worker disconnected")
        }
    });
    assert_eq!(
        one.responses.len(),
        1,
        "the first reply was observed before operational failure"
    );
    let dir = tempfile::tempdir()?;
    let mut replay_calls = 0;
    replay(dir.path(), &artifact, &one, |_| {
        replay_calls += 1;
        if replay_calls == 1 {
            Ok(reply("", ""))
        } else {
            anyhow::bail!("worker disconnected")
        }
    })?;

    let mut calls = 0;
    let nondeterministic = failure_record(&artifact, req, VerificationStage::Callback, || {
        calls += 1;
        Ok(reply(if calls == 1 { "a" } else { "b" }, ""))
    });
    assert_eq!(nondeterministic.responses.len(), 2);
    assert!(nondeterministic.error.contains("not deterministic"));
    let dir = tempfile::tempdir()?;
    replay(dir.path(), &artifact, &nondeterministic, {
        let mut calls: usize = 0;
        move |_| {
            calls += 1;
            Ok(reply(if calls == 2 { "b" } else { "a" }, ""))
        }
    })?;
    Ok(())
}

#[test]
fn replay_rejects_success_drift_error_fingerprint_and_generated_input_tampering() -> Result<()> {
    let artifact = artifact()?;
    let record = failure_record(
        &artifact,
        request(VerificationAction::Check),
        VerificationStage::Callback,
        || Ok(reply("", "expected failure")),
    );
    for kind in 0..3 {
        let dir = tempfile::tempdir()?;
        let path = save_verification_failure(dir.path(), &record)?;
        let mut count = 0;
        let result = replay_verification_with(&artifact, &path, |_| {
            count += 1;
            Ok(match kind {
                0 => reply("ok", ""),
                1 => reply("", "other failure"),
                _ => reply(
                    if count == 2 { "different" } else { "" },
                    "expected failure",
                ),
            })
        });
        assert!(result.is_err(), "tampering variant {kind}");
    }
    let generated = failure_record(
        &artifact,
        request(VerificationAction::Input),
        VerificationStage::GeneratedInput,
        || Ok(reply("{\"unknown\":1}", "")),
    );
    let dir = tempfile::tempdir()?;
    let path = save_verification_failure(dir.path(), &generated)?;
    let mut tampered = generated;
    tampered.generated_input = Some("tampered".into());
    fs::write(&path, serde_json::to_vec(&tampered)?)?;
    assert!(
        replay_verification_with(&artifact, &path, |_| Ok(reply("{\"unknown\":1}", ""))).is_err()
    );
    Ok(())
}

#[test]
fn invalid_identity_context_action_operation_and_format_reject_before_callback() -> Result<()> {
    let artifact = artifact()?;
    let valid = failure_record(
        &artifact,
        request(VerificationAction::Check),
        VerificationStage::Callback,
        || Ok(reply("", "failure")),
    );
    let variants = [
        {
            let mut v = valid.clone();
            v.artifact = "other".into();
            v
        },
        {
            let mut v = valid.clone();
            v.format = 2;
            v
        },
        {
            let mut v = valid.clone();
            v.request.action = VerificationAction::ErrorInput;
            v
        },
        {
            let mut v = valid.clone();
            v.request.operation = "app.missing".into();
            v
        },
        {
            let mut v = valid.clone();
            v.request.snapshot = r#"{"verification":{"actor":"","input":"x"}}"#.into();
            v
        },
        {
            let mut v = valid.clone();
            v.request.before = r#"{"verification":{"actor":"different","input":"x"}}"#.into();
            v
        },
    ];
    let mut variants = variants
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut unknown_action = serde_json::to_value(&valid)?;
    unknown_action["request"]["action"] = json!("unknown-action");
    variants.push(unknown_action);
    for invalid in variants {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("evidence.json");
        fs::write(&path, serde_json::to_vec(&invalid)?)?;
        let mut called = false;
        assert!(
            replay_verification_with(&artifact, &path, |_| {
                called = true;
                Ok(reply("", "failure"))
            })
            .is_err()
        );
        assert!(!called, "invalid evidence must be rejected before callback");
    }
    Ok(())
}

#[test]
fn evidence_reader_rejects_sparse_oversize_and_non_regular_paths_without_blocking() -> Result<()> {
    let artifact = artifact()?;
    let dir = tempfile::tempdir()?;
    let reject = |path: &Path| -> Result<()> {
        let error = replay_verification_with(&artifact, path, |_| {
            panic!("unsafe evidence path reached callback")
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("verification evidence file type or byte budget"),
            "{error:#}"
        );
        Ok(())
    };
    let sparse = dir.path().join("sparse.json");
    let file = fs::File::create(&sparse)?;
    file.set_len((VERIFICATION_EVIDENCE_BYTES + 1) as u64)?;
    drop(file);
    reject(&sparse)?;
    let directory = dir.path().join("directory");
    fs::create_dir(&directory)?;
    reject(&directory)?;
    let target = dir.path().join("target");
    fs::write(&target, b"{}")?;
    let symlink = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &symlink)?;
    reject(&symlink)?;
    let fifo = dir.path().join("fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    assert!(status.success(), "FIFO fixture creation failed");
    reject(&fifo)?;
    Ok(())
}

#[test]
fn admitted_reports_worker_failure_is_saved_and_replayed_when_configured() -> Result<()> {
    let Ok(path) = std::env::var("DAY2_TEST_REPORTS_ARTIFACT") else {
        eprintln!(
            "skipping native Reports replay; set DAY2_TEST_REPORTS_ARTIFACT to an admitted Reports artifact directory"
        );
        return Ok(());
    };
    let artifact = LoadedArtifact::load(Path::new(&path))?;
    let dir = tempfile::tempdir()?;
    let invocation = VerificationInvocation {
        actor: "developer",
        input: "{}",
        seed: 42,
    };
    let request = verification_request(
        "check",
        "reports.detail",
        &json!({"reports": []}),
        &json!({"reports": []}),
        &json!({"intentionally_invalid": true}),
        &invocation,
    )?;
    let result = verification_captured(
        &artifact,
        request,
        Some(dir.path()),
        VerificationStage::Callback,
    );
    assert!(
        result.is_err(),
        "the deliberately invalid Reports check should fail"
    );
    let evidence = dir.path().join("verification-failure.json");
    assert!(
        evidence.is_file(),
        "native callback failure should create replay evidence"
    );
    let original = fs::read(&evidence)?;
    let failure: VerificationFailure = serde_json::from_slice(&original)?;
    assert_eq!(
        failure.responses.len(),
        2,
        "both real worker replies required"
    );
    assert!(
        failure
            .error
            .contains("reports.detail check verification failed")
    );
    replay_verification_file(&artifact, &evidence)?;
    assert_eq!(fs::read(&evidence)?, original);
    Ok(())
}

#[test]
fn creation_is_exclusive_private_and_does_not_overwrite_existing_evidence() -> Result<()> {
    let artifact = artifact()?;
    let record = failure_record(
        &artifact,
        request(VerificationAction::Check),
        VerificationStage::Callback,
        || Ok(reply("", "failure")),
    );
    let dir = tempfile::tempdir()?;
    let path = save_verification_failure(dir.path(), &record)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    let inode = fs::metadata(&path)?.ino();
    assert!(save_verification_failure(dir.path(), &record).is_err());
    assert_eq!(fs::metadata(&path)?.ino(), inode);
    Ok(())
}
