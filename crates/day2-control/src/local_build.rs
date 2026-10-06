//! Concrete local provider composition for the installation control API.
use crate::{
    BindingRef, BuildPlan, Digest, Name,
    build::{BuildRequest, PlatformInputs, TrustedRunner, recipe_digest},
    contracts::BuildProfile,
    engine::{
        Capabilities, EffectResult, ExecutionHost, check_publication, load_source, save_source,
    },
    journal::Lease,
    kernel::{BuildFailureEvidence, EffectKind, FailureCode, Observation, State},
    local_source::{SourceControl, private_directory},
    service::{AppHandle, Service},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{BuildProvider, DurabilityProvider};
use durable_temporal::{RuntimeConfig, TemporalAdapter};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

pub struct PreparedBuild {
    runner: TrustedRunner,
    platform: PlatformInputs,
    runtime: RuntimeConfig,
    profile: BuildProfile,
}
impl PreparedBuild {
    pub fn capture(
        service: &Service,
        app: &AppHandle,
        builder: &Name,
        runtime: &Name,
    ) -> Result<Self> {
        service.check(app)?;
        let configuration = service.configuration();
        let app_binding = configuration
            .apps
            .get(app.name())
            .context("unknown control app")?;
        let source = BindingRef::pin(
            app_binding.source.clone(),
            configuration
                .sources
                .get(&app_binding.source)
                .context("unknown source binding")?,
        )?;
        let BuildProvider::LocalMacos {
            platform_root,
            toolchains,
            xtask,
            rust,
            registry,
            ui_assembly,
        } = configuration
            .builders
            .get(builder)
            .context("unknown build provider")?;
        let runner = TrustedRunner::capture(
            builder.clone(),
            Path::new(xtask),
            Path::new(rust),
            Path::new(registry),
        )?;
        let runner = if let Some(ui_assembly) = ui_assembly {
            runner.with_ui_assembly(ui_assembly)?
        } else {
            runner
        };
        let platform = PlatformInputs::capture(Path::new(platform_root), Path::new(toolchains))?;
        let DurabilityProvider::TemporalLocal {
            endpoint,
            namespace,
            task_queue,
        } = configuration
            .runtimes
            .get(runtime)
            .context("unknown durable runtime")?;
        let runtime_configuration = RuntimeConfig::local(endpoint.parse()?, namespace, task_queue)?;
        let profile = BuildProfile {
            source,
            builder: runner.binding()?,
            durability: BindingRef::pin(runtime.clone(), &runtime_configuration)?,
            platform: platform.digest().clone(),
            recipe: recipe_digest(),
        };
        Ok(Self {
            runner,
            platform,
            runtime: runtime_configuration,
            profile,
        })
    }
    pub fn profile(&self) -> &BuildProfile {
        &self.profile
    }
    pub fn activate(self, service: &Service, app: &AppHandle) -> Result<BuildRuntime> {
        ensure!(
            service
                .configuration()
                .apps
                .get(app.name())
                .and_then(|app| app.build.as_ref())
                == Some(&self.profile),
            "operator must approve the exact generated build profile before submission"
        );
        let objects = PathBuf::from(&service.configuration().state_directory)
            .join("objects")
            .join(app.name().as_str());
        private_directory(&objects)?;
        let capabilities = LocalBuildCapabilities {
            source: service.source(app)?,
            source_binding: self.profile.source.clone(),
            runner: self.runner,
            platform: self.platform,
            objects,
        };
        let host = Arc::new(ExecutionHost::new(
            service.build_journal(),
            service.scope().company()?,
            Name::try_from("installation-worker".to_owned())?,
            self.profile.durability,
            Arc::new(capabilities),
        ));
        Ok(BuildRuntime {
            host,
            runtime: self.runtime,
        })
    }
}

pub struct BuildRuntime {
    pub host: Arc<ExecutionHost>,
    runtime: RuntimeConfig,
}
impl BuildRuntime {
    pub fn open(service: &Service, app: &AppHandle) -> Result<Self> {
        let profile = service
            .configuration()
            .apps
            .get(app.name())
            .and_then(|app| app.build.as_ref())
            .context("app_has_no_build_capability")?;
        PreparedBuild::capture(service, app, &profile.builder.id, &profile.durability.id)?
            .activate(service, app)
    }
    pub async fn run(&self, id: &Digest) -> Result<durable_temporal::StepOutcome> {
        let address = self
            .runtime
            .endpoint
            .strip_prefix("http://")
            .context("local Temporal endpoint")?
            .parse()?;
        let adapter = TemporalAdapter::connect_local(
            address,
            &self.runtime.namespace,
            &self.runtime.task_queue,
        )
        .await?;
        ensure!(
            adapter.binding_configuration() == &self.runtime,
            "durable runtime changed"
        );
        let mut worker = adapter.worker(self.host.clone())?;
        self.host.dispatch(&adapter).await?;
        let shutdown = worker.shutdown_handle();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let task = tokio::task::spawn_local(async move { worker.run().await });
                let result = adapter.result(id.as_str()).await;
                shutdown();
                task.await??;
                result
            })
            .await
    }
}

struct LocalBuildCapabilities {
    source: Box<dyn SourceControl>,
    source_binding: BindingRef,
    runner: TrustedRunner,
    platform: PlatformInputs,
    objects: PathBuf,
}
impl Capabilities for LocalBuildCapabilities {
    fn validate(&self, plan: &BuildPlan) -> Result<()> {
        plan.validate()?;
        ensure!(
            plan.profile.source == self.source_binding
                && plan.profile.builder == self.runner.binding()?
                && &plan.profile.platform == self.platform.digest()
                && plan.profile.recipe == recipe_digest(),
            "local build capability binding mismatch"
        );
        Ok(())
    }
    fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        self.validate(&lease.execution.plan)?;
        let plan = &lease.execution.plan;
        let observation = match lease.kind {
            EffectKind::FetchSource => {
                let snapshot = self.source.snapshot(&plan.commit)?;
                save_source(&self.objects, &snapshot)?;
                Observation::Source {
                    source: snapshot.digest().clone(),
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
                    Ok(evidence) => Observation::Verified { evidence },
                    Err(_) => Observation::BuildRejected {
                        evidence: BuildFailureEvidence {
                            plan: plan.fingerprint()?,
                            source: source.clone(),
                            platform: plan.profile.platform.clone(),
                            recipe: plan.profile.recipe.clone(),
                            builder: plan.profile.builder.clone(),
                            checks: evidence.digest()?,
                            code: FailureCode::Contract,
                        },
                    },
                }
            }
            EffectKind::PublishCheck => {
                let publication = check_publication(lease)?;
                let bytes = serde_json::to_vec(&publication)?;
                let root = self.objects.join("checks");
                private_directory(&root)?;
                let target = root.join(&lease.effect.as_str()[7..]);
                if target.exists() {
                    ensure!(fs::read(&target)? == bytes, "local check receipt conflict");
                } else {
                    let mut temporary = tempfile::NamedTempFile::new_in(&root)?;
                    temporary.write_all(&bytes)?;
                    temporary.as_file().sync_all()?;
                    if let Err(error) = temporary.persist_noclobber(&target) {
                        ensure!(
                            error.error.kind() == std::io::ErrorKind::AlreadyExists
                                && fs::read(&target)? == bytes,
                            "local check publication failed"
                        );
                    }
                    fs::File::open(&root)?.sync_all()?;
                }
                Observation::Published {
                    evidence: publication.evidence,
                    publication: Digest::new(&bytes),
                }
            }
        };
        Ok(EffectResult::Completed(observation))
    }
}
