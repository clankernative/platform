//! Trusted host composition. Only execution identities and redacted progress cross
//! into Temporal. Every provider call happens outside the journal transaction.
use crate::{
    BindingRef, BuildPlan, Digest, Name,
    build::{BuildRequest, PlatformInputs, TrustedRunner},
    journal::{
        Claim, CompletionRejection, HostFault, Journal, Lease, RecoveryMode, RetryDisposition,
    },
    kernel::{BuildFailureEvidence, EffectKind, FailureCode, Observation, State},
    source::{
        CheckConclusion, CheckObservation, CheckPublication, CheckPublishError, FailureClass,
        GithubBinding, GithubSource, SecretResolver, SourceSnapshot,
    },
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use durable_temporal::{AdvanceBackend, BackendError, StepOutcome, TemporalAdapter};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub enum EffectResult {
    Completed(Observation),
    RetryNotApplied,
    Ambiguous,
}

pub trait Capabilities: Send + Sync + 'static {
    fn validate(&self, plan: &BuildPlan) -> Result<()>;
    fn perform(&self, lease: &Lease) -> Result<EffectResult>;
}

pub struct ExecutionHost {
    journal: PathBuf,
    company: Name,
    owner: Name,
    durability: BindingRef,
    capabilities: Arc<dyn Capabilities>,
}

impl ExecutionHost {
    pub fn new(
        journal: PathBuf,
        company: Name,
        owner: Name,
        durability: BindingRef,
        capabilities: Arc<dyn Capabilities>,
    ) -> Self {
        Self {
            journal,
            company,
            owner,
            durability,
            capabilities,
        }
    }

    pub fn accept(&self, plan: &BuildPlan) -> Result<Digest> {
        self.validate_acceptance(plan)?;
        Ok(Journal::open(&self.journal)?.accept(plan)?.id)
    }

    pub fn accept_as(&self, plan: &BuildPlan, actor: &str) -> Result<Digest> {
        self.validate_acceptance(plan)?;
        Ok(Journal::open(&self.journal)?.accept_as(plan, actor)?.id)
    }

    fn validate_acceptance(&self, plan: &BuildPlan) -> Result<()> {
        ensure!(plan.company == self.company, "company authority mismatch");
        ensure!(
            plan.profile.durability == self.durability,
            "durable runtime binding mismatch"
        );
        self.capabilities.validate(plan)?;
        Ok(())
    }

    pub async fn dispatch(&self, adapter: &TemporalAdapter) -> Result<usize> {
        self.durability.verify(adapter.binding_configuration())?;
        let pending =
            Journal::open(&self.journal)?.pending_for(&self.company, &self.durability, 64)?;
        let mut count = 0;
        for id in pending {
            let execution = Journal::open(&self.journal)?.get(&id)?;
            ensure!(
                execution.plan.profile.durability == self.durability,
                "outbox runtime binding mismatch"
            );
            if execution.state.next_effect().is_none() {
                continue;
            }
            let receipt = adapter.ensure_started(id.as_str()).await?;
            Journal::open(&self.journal)?.dispatched(&id, &receipt.workflow_id, &receipt.run_id)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn advance_at(&self, id: &Digest, now: u64) -> Result<StepOutcome> {
        self.advance_with_clock(id, || Ok(now))
    }

    pub fn advance_with_clock(
        &self,
        id: &Digest,
        clock: impl Fn() -> Result<u64>,
    ) -> Result<StepOutcome> {
        let (claim, now) = self.claim_with_clock(id, &clock)?;
        let lease = match claim {
            Claim::Busy => return Ok(StepOutcome::Continue),
            Claim::Terminal(state) => return Ok(progress(&state)),
            Claim::Acquired(lease) => lease,
        };
        let outcome = self.perform(&lease)?;
        let finished = clock()
            .map_err(|_| self.fault(id, HostFault::Clock))?
            .max(now);
        self.settle_at(&lease, outcome, finished)
    }

    /// One durable boundary, shared by the live driver and deterministic scheduler.
    /// A lease fences journal writes; it cannot retract an already sent provider call.
    pub fn claim_at(&self, id: &Digest, now: u64) -> Result<Claim> {
        self.claim_with_clock(id, || Ok(now))
            .map(|(claim, _)| claim)
    }

    fn claim_with_clock(
        &self,
        id: &Digest,
        clock: impl FnOnce() -> Result<u64>,
    ) -> Result<(Claim, u64)> {
        let execution = Journal::open(&self.journal)
            .and_then(|journal| journal.get(id))
            .map_err(|_| HostFault::JournalRead)?;
        self.validate_scope(&execution.plan)?;
        self.capabilities
            .validate(&execution.plan)
            .map_err(|_| self.fault(id, HostFault::CapabilityBinding))?;
        let now = clock().map_err(|_| self.fault(id, HostFault::Clock))?;
        Journal::open(&self.journal)
            .and_then(|mut journal| journal.claim(id, self.owner.clone(), now, 20 * 60 * 1000))
            .map(|claim| (claim, now))
            .map_err(|_| self.fault(id, HostFault::Claim))
    }

    fn validate_scope(&self, plan: &BuildPlan) -> Result<()> {
        ensure!(plan.company == self.company, "company authority mismatch");
        ensure!(
            plan.profile.durability == self.durability,
            "execution runtime binding mismatch"
        );
        Ok(())
    }

    /// Provider I/O is deliberately outside any journal transaction. The adapter
    /// must reconcile uncertain effects by stable identity before another mutation.
    pub fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        self.validate_scope(&lease.execution.plan)?;
        self.capabilities
            .validate(&lease.execution.plan)
            .map_err(|_| self.fault(&lease.execution.id, HostFault::CapabilityBinding))?;
        self.capabilities
            .perform(lease)
            .map_err(|_| self.fault(&lease.execution.id, HostFault::Capability))
    }

    /// Atomically records an observed provider outcome and advances the real kernel.
    /// Keep completion possible after authority revocation: an in-flight external
    /// effect still needs a durable outcome, never an invented non-application.
    pub fn settle_at(
        &self,
        lease: &Lease,
        outcome: EffectResult,
        finished: u64,
    ) -> Result<StepOutcome> {
        let id = &lease.execution.id;
        self.validate_scope(&lease.execution.plan)?;
        match outcome {
            EffectResult::Completed(observation) => {
                let state = Journal::open(&self.journal)
                    .and_then(|mut journal| journal.complete(lease, &observation, finished))
                    .map_err(|error| self.completion_fault(id, error))?;
                Ok(progress(&state))
            }
            EffectResult::RetryNotApplied => {
                Journal::open(&self.journal)
                    .and_then(|mut journal| {
                        journal.defer(lease, RetryDisposition::NotApplied, finished)
                    })
                    .map_err(|error| self.completion_fault(id, error))?;
                Ok(StepOutcome::Continue)
            }
            EffectResult::Ambiguous => {
                Journal::open(&self.journal)
                    .and_then(|mut journal| {
                        journal.defer(lease, RetryDisposition::Ambiguous, finished)
                    })
                    .map_err(|error| self.completion_fault(id, error))?;
                Ok(StepOutcome::Continue)
            }
        }
    }

    fn fault(&self, id: &Digest, code: HostFault) -> anyhow::Error {
        // If storage itself is unavailable, diagnostics cannot be made durable.
        // The error still remains redacted and never clears the uncertain effect.
        let _ = Journal::open(&self.journal).and_then(|mut journal| journal.record_fault(id, code));
        code.into()
    }

    fn completion_fault(&self, id: &Digest, error: anyhow::Error) -> anyhow::Error {
        let fault = self.fault(id, HostFault::Completion);
        match error.downcast_ref::<CompletionRejection>() {
            Some(reason) => anyhow::Error::new(*reason).context(HostFault::Completion),
            None => fault,
        }
    }
}

impl AdvanceBackend for ExecutionHost {
    fn advance(
        &self,
        execution_id: &str,
        runtime: &durable_temporal::RuntimeConfig,
    ) -> std::result::Result<StepOutcome, BackendError> {
        self.durability
            .verify(runtime)
            .map_err(|_| BackendError::Rejected)?;
        let id = Digest::try_from(execution_id.to_owned()).map_err(|_| BackendError::Rejected)?;
        self.advance_with_clock(&id, || {
            Ok(u64::try_from(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            )?)
        })
        .map_err(|error| match error.downcast_ref::<HostFault>() {
            Some(HostFault::CapabilityBinding) | None => BackendError::Rejected,
            Some(_) => BackendError::Retryable,
        })
    }
}

fn progress(state: &State) -> StepOutcome {
    match state {
        State::Succeeded { .. } => StepOutcome::Succeeded,
        State::Failed { .. } | State::Cancelled => StepOutcome::Failed,
        _ => StepOutcome::Continue,
    }
}

pub struct GithubBuildCapabilities {
    pub source: GithubSource,
    pub binding: GithubBinding,
    pub source_binding: BindingRef,
    pub secrets: Arc<dyn SecretResolver + Send + Sync>,
    pub runner: TrustedRunner,
    pub platform: PlatformInputs,
    pub objects: PathBuf,
}

impl Capabilities for GithubBuildCapabilities {
    fn validate(&self, plan: &BuildPlan) -> Result<()> {
        plan.validate()?;
        self.binding.validate()?;
        ensure!(
            self.source_binding.revision
                == self
                    .source
                    .binding_revision(&self.binding, self.secrets.as_ref())?,
            "source endpoint or credential binding changed"
        );
        ensure!(
            self.source_binding == plan.profile.source,
            "source provider binding changed"
        );
        ensure!(
            self.runner.binding()? == plan.profile.builder,
            "builder binding changed"
        );
        ensure!(
            self.platform.digest() == &plan.profile.platform,
            "platform revision changed"
        );
        ensure!(
            crate::build::recipe_digest() == plan.profile.recipe,
            "unsupported verification recipe"
        );
        ensure!(
            self.binding.checks.is_some(),
            "check publication binding is required"
        );
        Ok(())
    }

    fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        self.validate(&lease.execution.plan)?;
        let plan = &lease.execution.plan;
        match lease.kind {
            EffectKind::FetchSource => {
                match self
                    .source
                    .fetch(&self.binding, &plan.commit, self.secrets.as_ref())
                {
                    Ok(snapshot) => {
                        save_source(&self.objects, &snapshot)?;
                        Ok(EffectResult::Completed(Observation::Source {
                            source: snapshot.digest().clone(),
                        }))
                    }
                    Err(error) if error.retryable() => Ok(EffectResult::RetryNotApplied),
                    Err(error) => Ok(EffectResult::Completed(Observation::Rejected {
                        code: source_failure(error.class),
                    })),
                }
            }
            EffectKind::VerifyArtifact => {
                let State::SourceReady { source } = &lease.execution.state else {
                    anyhow::bail!("invalid build state");
                };
                let snapshot = load_source(&self.objects, source, &plan.commit)?;
                let evidence = self.runner.execute(
                    &BuildRequest {
                        plan: plan.clone(),
                        source: snapshot,
                    },
                    &self.platform,
                    &self.objects.join("builds"),
                )?;
                match evidence.verification_evidence() {
                    Ok(evidence) => Ok(EffectResult::Completed(Observation::Verified { evidence })),
                    Err(_) => Ok(EffectResult::Completed(Observation::BuildRejected {
                        evidence: BuildFailureEvidence {
                            plan: plan.fingerprint()?,
                            source: source.clone(),
                            platform: plan.profile.platform.clone(),
                            recipe: plan.profile.recipe.clone(),
                            builder: plan.profile.builder.clone(),
                            checks: evidence.digest()?,
                            code: FailureCode::Contract,
                        },
                    })),
                }
            }
            EffectKind::PublishCheck => {
                let publication = check_publication(lease)?;
                match self
                    .source
                    .observe_check(&self.binding, &publication, self.secrets.as_ref())
                {
                    Ok(CheckObservation::Found(receipt)) => {
                        return Ok(EffectResult::Completed(Observation::Published {
                            evidence: publication.evidence.clone(),
                            publication: Digest::of(&receipt)?,
                        }));
                    }
                    Ok(CheckObservation::Missing) => {}
                    Err(error) if error.retryable() => {
                        return Ok(if lease.recovery == RecoveryMode::Reconcile {
                            EffectResult::Ambiguous
                        } else {
                            EffectResult::RetryNotApplied
                        });
                    }
                    Err(error) => {
                        return Ok(if lease.recovery == RecoveryMode::Reconcile {
                            EffectResult::Ambiguous
                        } else {
                            EffectResult::Completed(Observation::Rejected {
                                code: source_failure(error.class),
                            })
                        });
                    }
                }
                if lease.recovery == RecoveryMode::Reconcile {
                    return Ok(EffectResult::Ambiguous);
                }
                match self.source.publish_check_once(
                    &self.binding,
                    &publication,
                    self.secrets.as_ref(),
                ) {
                    Ok(receipt) => Ok(EffectResult::Completed(Observation::Published {
                        evidence: publication.evidence.clone(),
                        publication: Digest::of(&receipt)?,
                    })),
                    Err(CheckPublishError::Ambiguous(_)) => Ok(EffectResult::Ambiguous),
                    Err(CheckPublishError::Rejected(error)) if error.retryable() => {
                        Ok(EffectResult::RetryNotApplied)
                    }
                    Err(CheckPublishError::Rejected(error)) => {
                        Ok(EffectResult::Completed(Observation::Rejected {
                            code: source_failure(error.class),
                        }))
                    }
                }
            }
        }
    }
}

/// Both successful and failed verification publish only their admitted evidence
/// identity. Provider-specific code cannot choose a different conclusion.
pub fn check_publication(lease: &Lease) -> Result<CheckPublication> {
    ensure!(
        lease.kind == EffectKind::PublishCheck,
        "invalid publication effect"
    );
    let (evidence, conclusion) = match &lease.execution.state {
        State::Verified { evidence, .. } => (evidence, CheckConclusion::Success),
        State::VerificationFailed { evidence, .. } => (evidence, CheckConclusion::Failure),
        _ => anyhow::bail!("invalid publication state"),
    };
    Ok(CheckPublication {
        commit: lease.execution.plan.commit.clone(),
        effect_id: lease.effect.clone(),
        evidence: evidence.clone(),
        conclusion,
    })
}

fn source_failure(class: FailureClass) -> FailureCode {
    match class {
        FailureClass::Unauthorized => FailureCode::Denied,
        FailureClass::Limit => FailureCode::Budget,
        FailureClass::NotFound => FailureCode::Permanent,
        _ => FailureCode::Contract,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSource {
    files: BTreeMap<String, String>,
}

pub fn save_source(root: &Path, snapshot: &SourceSnapshot) -> Result<()> {
    let directory = root.join("sources");
    fs::create_dir_all(&directory)?;
    ensure!(
        !fs::symlink_metadata(&directory)?.file_type().is_symlink(),
        "source cache symlink"
    );
    let target = directory.join(snapshot.digest().as_str().trim_start_matches("sha256:"));
    let encoded = SavedSource {
        files: snapshot
            .files()
            .iter()
            .map(|(name, bytes)| (name.clone(), STANDARD.encode(bytes)))
            .collect(),
    };
    let bytes = serde_json::to_vec(&encoded)?;
    if target.exists() {
        ensure!(
            fs::read(&target)? == bytes,
            "immutable source cache conflict"
        );
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(&target) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => ensure!(
            fs::read(&target)? == bytes,
            "concurrent source cache conflict"
        ),
        Err(error) => return Err(error.error.into()),
    }
    fs::File::open(&directory)?.sync_all()?;
    Ok(())
}

pub fn load_source(root: &Path, digest: &Digest, commit: &crate::GitOid) -> Result<SourceSnapshot> {
    let target = root
        .join("sources")
        .join(digest.as_str().trim_start_matches("sha256:"));
    let metadata = fs::symlink_metadata(&target)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 24 * 1024 * 1024,
        "invalid source cache object"
    );
    let saved: SavedSource = serde_json::from_slice(&fs::read(&target)?)?;
    let files = saved
        .files
        .into_iter()
        .map(|(name, encoded)| Ok((name, STANDARD.decode(encoded)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let snapshot = SourceSnapshot::from_files(commit.clone(), files)?;
    ensure!(snapshot.digest() == digest, "source cache digest mismatch");
    Ok(snapshot)
}
