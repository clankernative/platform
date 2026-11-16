//! Candidate-only execution and bounded recovery of the original source. A
//! selection describes operator-observed deployment facts; only matching live
//! journal admission and actual measured code admit a process. No image or pod
//! attestation is inferred from these facts.
use super::*;
use crate::{runtime_generation, security_admission::HostCode};
use rusqlite::Connection;
use std::{fs::File, path::Path, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorRole {
    Source,
    Candidate,
}

/// Host/operator selection DATA, not application-supplied execution authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub release: String,
    pub role: ExecutorRole,
    pub placement: rollout::Placement,
    pub image: String,
}

impl Selection {
    pub fn load(path: &Path) -> Result<Self> {
        use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
        let mut input: File = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)?;
        ensure!(
            input.metadata()?.is_file(),
            "runtime_pair_selection_regular_file_required"
        );
        let mut bytes = Vec::new();
        input.by_ref().take(1_048_577).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "runtime_pair_selection_budget");
        crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("runtime_pair_selection_invalid"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCheck {
    pub generation: String,
    pub attempt: u64,
    pub snapshot: String,
    pub checks: String,
}

/// Required closed field: an old journal cannot silently become admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Execution {
    Unadmitted,
    Admitted {
        source: String,
        candidate: String,
        attempt: u64,
        check: Option<CandidateCheck>,
    },
}

impl Execution {
    pub(crate) fn validate(&self, release: &Release) -> Result<()> {
        if let Self::Admitted {
            source,
            candidate,
            attempt,
            check,
        } = self
        {
            ensure!(
                release.placement.is_some(),
                "runtime_pair_placement_required"
            );
            ensure!(
                *source
                    == runtime_generation::expected_id(&release.scope, &release.source.runtime)?
                    && *candidate
                        == runtime_generation::expected_id(
                            &release.scope,
                            &release.target.runtime
                        )?,
                "runtime_pair_generation_changed"
            );
            release
                .source
                .runtime
                .require_image(&release.source.image)?;
            release
                .target
                .runtime
                .require_image(&release.target.image)?;
            if let Some(check) = check {
                ensure!(
                    check.generation == *candidate && check.attempt == *attempt && *attempt > 0,
                    "runtime_pair_check_changed"
                );
                day2_assets::hash_part(&check.snapshot)?;
                day2_assets::hash_part(&check.checks)?;
            }
        }
        Ok(())
    }
}

fn bound(runtime: &Runtime, db: &Connection, source: bool) -> Result<Release> {
    ensure!(
        runtime.rolling() && !runtime.uses_native_storage(),
        "ordinary_rolling_profile_required"
    );
    runtime.check_binding(db)?;
    let release = rollout::state(db)?.context("runtime_pair_not_prepared")?;
    ensure!(
        matches!(release.kind, ReleaseKind::RuntimePair { .. })
            && (release.phase == Phase::Prepared || (source && release.phase == Phase::Aborted))
            && release.scope == runtime.scope()
            && release.source.artifact == runtime.artifact().id()
            && release.source.instance_digest == runtime.instance_digest()
            && release.target.instance_digest == runtime.instance_digest(),
        "runtime_pair_binding_changed"
    );
    let active = authority_state::current(db)?;
    ensure!(
        active.stamp == release.authority && active.artifact_id == release.source.artifact,
        "runtime_pair_authority_changed"
    );
    Ok(release)
}

fn prepared(runtime: &Runtime, db: &Connection) -> Result<Release> {
    bound(runtime, db, false)
}

fn admit_in(runtime: &Runtime, db: &Connection, id: &str) -> Result<Release> {
    let mut release = prepared(runtime, db)?;
    ensure!(release.id == id, "runtime_pair_binding_changed");
    ensure!(
        release.placement.is_some(),
        "runtime_pair_placement_required"
    );
    release
        .source
        .runtime
        .require_image(&release.source.image)?;
    release
        .target
        .runtime
        .require_image(&release.target.image)?;
    let source = runtime_generation::expected_id(runtime.scope(), &release.source.runtime)?;
    runtime_generation::require_expected(db, runtime.scope(), &source, &release.source.runtime)?;
    runtime_generation::require_active(db, &source)?;
    let candidate =
        runtime_generation::register_expected(db, runtime.scope(), &release.target.runtime)?;
    let ReleaseKind::RuntimePair { execution, .. } = &mut release.kind else {
        unreachable!()
    };
    match execution {
        Execution::Unadmitted => {
            *execution = Execution::Admitted {
                source,
                candidate,
                attempt: 0,
                check: None,
            }
        }
        Execution::Admitted {
            source: previous_source,
            candidate: previous_candidate,
            ..
        } => {
            ensure!(
                *previous_source == source && *previous_candidate == candidate,
                "runtime_pair_generation_changed"
            );
        }
    }
    rollout::write(db, &release)?;
    Ok(release)
}

/// Bind the two expected executors after the existing placement operation.
/// This changes no active runtime, authority document, replica or serving phase.
pub fn admit(runtime: &Runtime, id: &str, operator: &LocalOperator) -> Result<Release> {
    rollout::operator(runtime, operator)?;
    let _operation = crate::deployment::operation::OperationLease::acquire(
        runtime.db().parent().context("state root")?,
        runtime.app(),
    )?;
    let _release = rollout::release_lock(runtime)?;
    super::local_stores(runtime)?;
    let expected = super::expected_storage(runtime)?;
    runtime.sql_write(|tx| {
        ensure!(
            runtime.operators()?.contains(operator.name())
                || authority_state::current(tx)?
                    .policy()?
                    .admins
                    .contains(operator.name()),
            "rollout_operator_required"
        );
        ensure!(
            rollout::storage_shape(runtime, tx)? == expected.shape,
            "runtime_pair_store_shape_changed"
        );
        crate::store::require_no_managed_credential_restore_state(tx)?;
        let release = prepared(runtime, tx)?;
        let ReleaseKind::RuntimePair { admission, .. } = &release.kind else {
            unreachable!()
        };
        ensure!(
            admission.receipt.source.protocols == expected.protocols,
            "runtime_pair_protocol_changed"
        );
        admit_in(runtime, tx, id)
    })
}

fn require_executor(
    runtime: &Runtime,
    db: &Connection,
    selection: &Selection,
    measured: &HostCode,
) -> Result<(Release, String)> {
    let release = bound(runtime, db, selection.role == ExecutorRole::Source)?;
    ensure!(
        release.id == selection.release && release.placement.as_ref() == Some(&selection.placement),
        "runtime_pair_placement_changed"
    );
    let ReleaseKind::RuntimePair { execution, .. } = &release.kind else {
        unreachable!()
    };
    let Execution::Admitted {
        source, candidate, ..
    } = execution
    else {
        anyhow::bail!("runtime_pair_executor_not_admitted")
    };
    runtime_generation::require_active(db, source)?;
    let (generation, software) = match selection.role {
        ExecutorRole::Source => (source, &release.source),
        ExecutorRole::Candidate => (candidate, &release.target),
    };
    ensure!(
        selection.image == software.image,
        "runtime_pair_image_changed"
    );
    software.runtime.require_image(&selection.image)?;
    ensure!(
        *measured == software.runtime.code()?,
        "runtime_pair_executor_code_changed"
    );
    runtime_generation::require_expected(db, runtime.scope(), generation, &software.runtime)?;
    Ok((release.clone(), generation.clone()))
}

fn begin_check(
    runtime: &Runtime,
    db: &Connection,
    selection: &Selection,
    code: &HostCode,
) -> Result<(Release, String, u64)> {
    ensure!(
        selection.role == ExecutorRole::Candidate,
        "runtime_pair_candidate_role_required"
    );
    let (mut release, generation) = require_executor(runtime, db, selection, code)?;
    let ReleaseKind::RuntimePair {
        execution: Execution::Admitted { attempt, check, .. },
        ..
    } = &mut release.kind
    else {
        anyhow::bail!("runtime_pair_executor_not_admitted")
    };
    *attempt = attempt
        .checked_add(1)
        .context("runtime_pair_check_attempt_exhausted")?;
    *check = None;
    let selected_attempt = *attempt;
    rollout::write(db, &release)?;
    Ok((release, generation, selected_attempt))
}

fn finish_check(
    runtime: &Runtime,
    db: &Connection,
    selection: &Selection,
    code: &HostCode,
    expected: &Release,
    check: &CandidateCheck,
) -> Result<()> {
    let (mut current, generation) = require_executor(runtime, db, selection, code)?;
    ensure!(
        check.generation == generation,
        "runtime_pair_changed_during_check"
    );
    // A lost successful response may repeat the exact finalization. Compare the
    // whole original admission after removing only that completed observation.
    let mut pending = current.clone();
    if let ReleaseKind::RuntimePair {
        execution: Execution::Admitted { check: stored, .. },
        ..
    } = &mut pending.kind
        && stored.as_ref() == Some(check)
    {
        *stored = None;
        ensure!(pending == *expected, "runtime_pair_changed_during_check");
        return Ok(());
    }
    ensure!(current == *expected, "runtime_pair_changed_during_check");
    let ReleaseKind::RuntimePair {
        execution:
            Execution::Admitted {
                attempt,
                check: stored,
                ..
            },
        ..
    } = &mut current.kind
    else {
        anyhow::bail!("runtime_pair_executor_not_admitted")
    };
    ensure!(
        *attempt == check.attempt && *attempt > 0,
        "runtime_pair_check_changed"
    );
    *stored = Some(check.clone());
    rollout::write(db, &current)
}

fn private_evidence_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "runtime_pair_private_evidence_directory_required"
    );
    Ok(())
}

/// A candidate owns no business admission or public Runtime handle. Its only
/// executable app callback evaluates complete bounded snapshot properties.
pub struct Candidate {
    runtime: Runtime,
    selection: Selection,
    _serving: File,
    health_capacity: Arc<tokio::sync::Semaphore>,
}

impl Candidate {
    pub fn open(instance: &Path, app: &str, selection: Selection) -> Result<Self> {
        ensure!(
            selection.role == ExecutorRole::Candidate,
            "runtime_pair_candidate_role_required"
        );
        let serving = crate::deployment::pair_executor_lease(instance, app)?;
        let runtime = Runtime::load(instance, app)?;
        runtime.sql_read(|db| {
            require_executor(
                &runtime,
                db,
                &selection,
                &crate::security_admission::host_code()?,
            )?;
            rollout::verify_storage_shape(&runtime, db)
        })?;
        Ok(Self {
            runtime,
            selection,
            _serving: serving,
            health_capacity: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }

    pub fn check(&self, evidence_directory: &Path) -> Result<CandidateCheck> {
        // Re-check clears the old positive before evaluation. A crash, failure
        // or a losing concurrent attempt can never publish stale readiness.
        let (release, generation, attempt) = self.runtime.sql_write(|db| {
            begin_check(
                &self.runtime,
                db,
                &self.selection,
                &crate::security_admission::host_code()?,
            )
        })?;
        private_evidence_directory(evidence_directory)?;
        let snapshot = self.runtime.sql_read(|db| {
            let (current, _) = require_executor(
                &self.runtime,
                db,
                &self.selection,
                &crate::security_admission::host_code()?,
            )?;
            ensure!(current == release, "runtime_pair_changed_during_check");
            self.runtime.application_snapshot_in(db)
        })?;
        // The pure worker and evidence publication hold no business lock.
        let evidence = crate::properties::evaluate(self.runtime.artifact(), snapshot.as_value())?
            .require(evidence_directory)?;
        let check = CandidateCheck {
            generation,
            attempt,
            snapshot: crate::digest(&serde_json::to_vec(snapshot.as_value())?),
            checks: crate::digest(&serde_json::to_vec(&evidence.checks)?),
        };
        self.runtime.sql_write(|db| {
            finish_check(
                &self.runtime,
                db,
                &self.selection,
                &crate::security_admission::host_code()?,
                &release,
                &check,
            )
        })?;
        Ok(check)
    }

    fn ready(&self) -> Result<bool> {
        self.runtime.sql_read(|db| {
            let (release, generation) = require_executor(
                &self.runtime,
                db,
                &self.selection,
                &crate::security_admission::host_code()?,
            )?;
            Ok(matches!(release.kind, ReleaseKind::RuntimePair {
                execution: Execution::Admitted { check: Some(ref check), .. }, ..
            } if check.generation == generation))
        })
    }

    /// A standby listener exposes only health. Public readiness and every
    /// application route remain closed even after a successful candidate check.
    pub async fn serve(self, evidence_directory: &Path) -> Result<()> {
        let directory = evidence_directory.to_path_buf();
        let candidate = tokio::task::spawn_blocking(move || -> Result<Self> {
            self.check(&directory)?;
            Ok(self)
        })
        .await??;
        let router = candidate_router(Arc::new(candidate));
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 8080)).await?;
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = crate::deployment::termination().await;
            })
            .await?;
        Ok(())
    }
}

fn candidate_router(candidate: Arc<Candidate>) -> axum::Router {
    axum::Router::new()
        .route(
            "/health/live",
            axum::routing::get(|| async { axum::http::StatusCode::OK }),
        )
        .route("/health/candidate", axum::routing::get(candidate_health))
        .fallback(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE })
        .with_state(candidate)
}

async fn candidate_health(
    axum::extract::State(candidate): axum::extract::State<Arc<Candidate>>,
) -> axum::http::StatusCode {
    let Ok(permit) = candidate.health_capacity.clone().try_acquire_owned() else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE;
    };
    let ready = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        candidate.ready()
    })
    .await;
    if matches!(ready, Ok(Ok(true))) {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    }
}

/// One bounded headless source tick, under the same serving/kernel exclusion
/// as HTTP. It cannot accept a new root request or authorize a target runtime.
pub fn source_drain(
    instance: &Path,
    app: &str,
    selection: &Selection,
    budget: usize,
) -> Result<Vec<crate::invocations::Invocation>> {
    ensure!(
        selection.role == ExecutorRole::Source,
        "runtime_pair_source_role_required"
    );
    ensure!(budget <= 1000, "invocation_drain_budget");
    let _serving = crate::deployment::pair_executor_lease(instance, app)?;
    let runtime = Runtime::load(instance, app)?;
    runtime.sql_read(|db| {
        let (_, generation) = require_executor(
            &runtime,
            db,
            selection,
            &crate::security_admission::host_code()?,
        )?;
        ensure!(
            runtime_generation::selected(&runtime, db)? == generation,
            "runtime_pair_executor_code_changed"
        );
        rollout::verify_storage_shape(&runtime, db)
    })?;
    crate::invocations::drain(&runtime, budget)
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
