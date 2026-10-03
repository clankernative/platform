//! Explicit local operator adoption of an actual native qualification. This
//! verifies preserved source, artifacts and evidence; it is not forge authentication.
use crate::{
    BindingRef, BuildPlan, Digest,
    build::PlatformInputs,
    contracts::BuildProfile,
    engine::{Capabilities, EffectResult, ExecutionHost, check_publication},
    gke_release_driver::Configuration,
    journal::{Journal, Lease},
    kernel::{CredentialPresence, EffectKind, Observation, State, VerificationEvidence},
};
use anyhow::{Context, Result, ensure};
use day2::{artifact::LoadedArtifact, automation};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "qualified_build_input_budget"
    );
    Ok(fs::read(path)?)
}

pub fn check_receipt(
    value: &Value,
    artifact: &Digest,
    worker: &str,
    architecture: &str,
) -> Result<()> {
    ensure!(
        value["format"] == 1
            && value["status"] == "passed"
            && value["scope"] == "linux_sqlite_single_v1"
            && value["environment"]["architecture"] == architecture,
        "qualified_build_profile_changed"
    );
    let required: std::collections::BTreeSet<_> = [
        "linux-build-check",
        "linux-build-delegation",
        "linux-build-delegation-business",
        "linux-build-owned",
        "linux-build-probe",
        "linux-build-runtime",
        "linux-build-tooling",
        "linux-capture",
        "linux-runtime-forced-restart",
        "linux-runtime-graceful-restart",
        "linux-runtime-isolation",
        "linux-runtime-package",
        "linux-runtime-read-write",
        "linux-runtime-restore",
        "linux-runtime-revoke",
        "linux-runtime-start",
        "linux-runtime-stop",
        "linux-start-tooling",
        "linux-stop-tooling",
        "linux-test-delegation",
        "test-backup",
        "test-http",
        "test-sandbox",
        "test-worker",
    ]
    .into_iter()
    .collect();
    let checks = value["checks"]
        .as_array()
        .context("qualified_build_checks_missing")?;
    let actual: std::collections::BTreeSet<_> = checks
        .iter()
        .map(|s| s.as_str().context("qualified_build_check_invalid"))
        .collect::<Result<_>>()?;
    ensure!(
        checks.len() == required.len() && actual == required,
        "qualified_build_checks_incomplete"
    );
    ensure!(
        value["applications"]
            .as_object()
            .context("qualified_build_apps_missing")?
            .values()
            .any(|v| v["artifact"] == artifact.as_str() && v["worker"] == worker),
        "qualified_build_artifact_unselected"
    );
    Ok(())
}

struct Provider {
    plan: BuildPlan,
    evidence: VerificationEvidence,
}
impl Capabilities for Provider {
    fn validate(&self, plan: &BuildPlan) -> Result<()> {
        ensure!(plan == &self.plan, "qualified_build_plan_changed");
        Ok(())
    }
    fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        self.validate(&lease.execution.plan)?;
        Ok(EffectResult::Completed(match lease.kind {
            EffectKind::FetchSource => Observation::Source {
                source: self.evidence.source.clone(),
            },
            EffectKind::VerifyArtifact => Observation::Verified {
                evidence: self.evidence.clone(),
            },
            EffectKind::PublishCheck => {
                let publication = check_publication(lease)?;
                Observation::Published {
                    evidence: publication.evidence.clone(),
                    publication: Digest::of(&publication)?,
                }
            }
        }))
    }
}

/// Native admission runs where these workers can be executed. Candidate artifacts
/// must be in the preserved qualification, and the entire original source pin
/// and each preserved log must still match. No passing result is synthesized.
pub fn prepare(
    mut configuration: Configuration,
    source: &Path,
    toolchains: &Path,
    qualified: &Path,
) -> Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "qualified_build_requires_native_linux"
    );
    configuration.validate()?;
    let bytes = bounded(&qualified.join("qualification.json"), 1_048_576)?;
    let receipt: Value = day2::json::decode(&bytes)?;
    let receipt_digest = Digest::new(&bytes);
    ensure!(
        PlatformInputs::capture(source, toolchains)?
            .digest()
            .as_str()
            == receipt["platform"]
                .as_str()
                .context("qualified_build_platform_missing")?,
        "qualified_build_source_changed"
    );
    ensure!(
        Digest::new(&bounded(
            &source.join(format!("toolchains/linux-{}.json", std::env::consts::ARCH)),
            1_048_576
        )?)
        .as_str()
            == receipt["toolchain"]
                .as_str()
                .context("qualified_build_toolchain_missing")?,
        "qualified_build_toolchain_changed"
    );
    let logs = receipt["evidence"]
        .as_object()
        .context("qualified_build_evidence_missing")?;
    ensure!(
        !logs.is_empty() && logs.len() <= 128,
        "qualified_build_evidence_budget"
    );
    for (name, digest) in logs {
        ensure!(
            name.ends_with(".log")
                && !name.contains('/')
                && !name.contains('\\')
                && !name.starts_with('.'),
            "qualified_build_evidence_name"
        );
        ensure!(
            Digest::new(&bounded(&qualified.join(name), 16 * 1024 * 1024)?).as_str()
                == digest
                    .as_str()
                    .context("qualified_build_evidence_digest_missing")?,
            "qualified_build_evidence_changed"
        );
    }
    let mut hosts = Vec::new();
    for candidate in &mut configuration.candidates {
        let artifact = LoadedArtifact::load(
            &configuration.artifact_store.join(
                candidate
                    .approval
                    .artifact
                    .as_str()
                    .trim_start_matches("sha256:"),
            ),
        )?;
        let preserved = LoadedArtifact::load(
            &qualified.join("artifacts").join(
                candidate
                    .approval
                    .artifact
                    .as_str()
                    .trim_start_matches("sha256:"),
            ),
        )?;
        ensure!(
            artifact.id() == preserved.id()
                && artifact.contract().namespace == candidate.approval.target.app.as_str(),
            "qualified_build_namespace_changed"
        );
        check_receipt(
            &receipt,
            &candidate.approval.artifact,
            &artifact.contract().worker_digest,
            std::env::consts::ARCH,
        )?;
        ensure!(
            artifact.contract().credential_declarations.is_empty()
                && artifact.contract().connection_declarations.is_empty(),
            "qualified_build_profile_unsupported"
        );
        let plan = BuildPlan {
            version: 1,
            company: candidate.approval.target.company.clone(),
            app: candidate.approval.target.app.clone(),
            request: candidate.approval.request.clone(),
            commit: candidate.approval.git.commit.clone(),
            profile: BuildProfile {
                source: candidate.approval.git.source.clone(),
                builder: BindingRef::pin(
                    "native_qualification".to_owned().try_into()?,
                    &receipt_digest,
                )?,
                durability: configuration.durability.clone(),
                platform: receipt["platform"]
                    .as_str()
                    .context("qualified_build_platform_missing")?
                    .to_owned()
                    .try_into()?,
                recipe: Digest::new(include_bytes!("qualified_release_build.rs")),
            },
        };
        let evidence = VerificationEvidence {
            plan: plan.fingerprint()?,
            source: plan.profile.platform.clone(),
            platform: plan.profile.platform.clone(),
            recipe: plan.profile.recipe.clone(),
            builder: plan.profile.builder.clone(),
            artifact: candidate.approval.artifact.clone(),
            checks: receipt_digest.clone(),
            credential_presence: CredentialPresence::Absent,
        };
        let host = ExecutionHost::new(
            configuration.journal.clone(),
            plan.company.clone(),
            configuration.owner.clone(),
            configuration.durability.clone(),
            Arc::new(Provider {
                plan: plan.clone(),
                evidence,
            }),
        );
        let id = host.accept_as(&plan, "local_operator:native_qualification")?;
        candidate.approval.build_execution = id.clone();
        hosts.push((id, host));
    }
    automation::run(
        &automation::runner()?,
        &["gke-release-build"],
        |request| match request.action.as_str() {
            "gke-build-open" => {
                Ok(json!({"executions":hosts.iter().map(|(id,_)|id).collect::<Vec<_>>()}))
            }
            "gke-build-advance" => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    execution: Digest,
                }
                let input: Input = request.decode()?;
                let (_, host) = hosts
                    .iter()
                    .find(|(id, _)| id == &input.execution)
                    .context("qualified_build_unselected")?;
                host.advance_with_clock(&input.execution, || {
                    Ok(u64::try_from(
                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                    )?)
                })?;
                let state = Journal::open(&configuration.journal)?
                    .get(&input.execution)?
                    .state;
                Ok(
                    json!({"state":match state {State::Succeeded {..}=>"active",State::Failed {..}=>"failed",_=>"pending"},"wait_millis":0}),
                )
            }
            "gke-release-wait" => Ok(json!({})),
            "gke-build-finish" => {
                let journal = Journal::open(&configuration.journal)?;
                for candidate in &mut configuration.candidates {
                    let State::Succeeded { evidence, .. } =
                        journal.get(&candidate.approval.build_execution)?.state
                    else {
                        anyhow::bail!("qualified_build_not_complete");
                    };
                    candidate.approval.evidence = evidence;
                }
                Ok(serde_json::to_value(&configuration)?)
            }
            _ => anyhow::bail!("unknown_qualified_build_capability"),
        },
    )
}
