//! Native entrypoint to the same Roc release workflow. Approvals consume actual
//! successful build records; the CLI's operator assertion is not forge authentication.
use crate::{
    BindingRef, Digest, Name,
    gke_release::{Deployment, GkeReleaseProvider, publish_scope},
    journal::Journal,
    release::{ReleaseApproval, ReleaseAuthority, ReleaseTarget},
    release_execution::{ReleaseExecutionHost, ReleaseExecutionPlan, ReleaseTerminal},
    release_recipe::CompiledReleaseRecipe,
    runtime_secret::ProviderResource,
    secrets::AccessTokenProvider,
};
use anyhow::{Context, Result, ensure};
use day2::automation;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub approval: ReleaseApproval,
    pub deployment: Deployment,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub version: u32,
    pub journal: PathBuf,
    pub artifact_store: PathBuf,
    pub instance: PathBuf,
    pub owner: Name,
    pub durability: BindingRef,
    pub authority: ReleaseAuthority,
    pub candidates: Vec<Candidate>,
}

impl Configuration {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(path)?.file_type().is_file(),
            "release_configuration_not_regular"
        );
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(4_194_305)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4_194_304, "release_configuration_budget");
        let value: Self = day2::json::decode(&bytes)?;
        value.validate()?;
        Ok(value)
    }

    /// Returns the release scope: every app the catalog instance binds in the
    /// candidates' installation and environment. The published snapshot
    /// selects each of them that has an active release.
    pub fn validate(&self) -> Result<Vec<ReleaseTarget>> {
        ensure!(
            self.version == 1 && !self.candidates.is_empty() && self.candidates.len() <= 32,
            "release_configuration_scope"
        );
        let scope = &self.candidates[0].approval.target;
        let public_instance: Value = day2::json::decode(&fs::read(&self.instance)?)?;
        let mut targets = std::collections::BTreeSet::new();
        for candidate in &self.candidates {
            candidate
                .deployment
                .validate(&candidate.approval.artifact)?;
            let target = &candidate.approval.target;
            ensure!(
                public_instance["installation"] == candidate.deployment.instance["installation"]
                    && public_instance["environment"]
                        == candidate.deployment.instance["environment"]
                    && public_instance["identity"] == candidate.deployment.instance["identity"]
                    && public_instance["apps"][target.app.as_str()]
                        == candidate.deployment.instance["apps"][target.app.as_str()]
                    && public_instance["resources"] == candidate.deployment.instance["resources"],
                "release_instance_differs_from_qualified_catalog"
            );
            ensure!(
                target == &candidate.deployment.serving.target
                    && target.company == scope.company
                    && target.environment == scope.environment
                    && targets.insert(target.app.clone()),
                "release_candidate_scope_changed"
            );
            ensure!(
                candidate.approval.git.source == self.authority.source
                    && candidate.approval.git.policy == self.authority.policy,
                "release_source_authority_changed"
            );
        }
        ensure!(
            self.artifact_store.is_dir() && self.instance.is_file(),
            "release_catalog_inputs_missing"
        );
        release_scope(&public_instance, scope)
    }

    /// Explicit operator approval. No source check or successful build is fabricated.
    pub fn approve(&self) -> Result<Value> {
        self.validate()?;
        let mut journal = Journal::open(&self.journal)?;
        let mut releases = Vec::new();
        for candidate in &self.candidates {
            let approval = &candidate.approval;
            let authority = crate::release::read_observation::<ReleaseAuthority>(
                &journal.connection,
                &approval.target,
                "authority",
                "current",
            )?;
            if let Some((_, existing)) = authority {
                ensure!(
                    existing == self.authority,
                    "release_authority_requires_explicit_update"
                );
            } else {
                journal.observe_release_authority(
                    &approval.target,
                    &"gke-installation".to_owned().try_into()?,
                    0,
                    &self.authority,
                )?;
            }
            journal.register_runtime_secret(
                &approval.target,
                &approval.secret,
                &ProviderResource {
                    provider: "gcp-secret-manager".to_owned().try_into()?,
                    account: candidate
                        .deployment
                        .serving
                        .project_number
                        .to_string()
                        .try_into()?,
                    secret: approval.secret.secret.clone(),
                },
                &self.authority.actor,
            )?;
            releases.push(journal.approve_release(approval)?.id().clone());
        }
        Ok(json!({"version":1,"approval_origin":"explicit_operator","releases":releases}))
    }
}

struct Execution {
    id: Digest,
    host: ReleaseExecutionHost,
}

pub struct Session {
    configuration: Configuration,
    scope: Vec<ReleaseTarget>,
    executions: Vec<Execution>,
    tokens: Arc<dyn AccessTokenProvider>,
}

impl Session {
    pub fn open(
        configuration: Configuration,
        tokens: Arc<dyn AccessTokenProvider>,
    ) -> Result<Self> {
        let scope = configuration.validate()?;
        let recipe = Arc::new(CompiledReleaseRecipe::installed()?);
        let mut executions = Vec::new();
        for candidate in &configuration.candidates {
            let release = Digest::of(&(
                "day2-release-v1",
                &candidate.approval.target,
                &candidate.approval.request,
            ))?;
            let journal = Journal::open_readonly(&configuration.journal)?;
            ensure!(
                crate::release::read_approval(&journal.connection, &release)?.approval
                    == candidate.approval,
                "release_approval_changed"
            );
            let plan = ReleaseExecutionPlan {
                release,
                recipe: recipe.identity()?,
                durability: configuration.durability.clone(),
                resources: candidate.approval.secret.binding.clone(),
                deployment: candidate.deployment.serving.deployment.clone(),
                deployment_input: Some(Digest::of(&candidate.deployment)?),
            };
            let provider = Arc::new(GkeReleaseProvider::new(
                configuration.journal.clone(),
                candidate.deployment.clone(),
                tokens.clone(),
            )?);
            let host = ReleaseExecutionHost::new(
                configuration.journal.clone(),
                candidate.approval.target.company.clone(),
                configuration.owner.clone(),
                configuration.durability.clone(),
                provider.clone(),
                recipe.clone(),
            )
            .with_catalog_store(configuration.artifact_store.clone())?
            .with_catalog_instance(configuration.instance.clone())?;
            let id = provider.accept(&host, &plan)?;
            executions.push(Execution { id, host });
        }
        Ok(Self {
            configuration,
            scope,
            executions,
            tokens,
        })
    }

    pub fn capability(&mut self, request: &automation::Request) -> Result<Value> {
        match request.action.as_str() {
            "gke-release-open" => Ok(
                json!({"executions":self.executions.iter().map(|execution| &execution.id).collect::<Vec<_>>()}),
            ),
            "gke-release-advance" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    execution: Digest,
                }
                let input: Input = request.decode()?;
                let execution = self
                    .executions
                    .iter()
                    .find(|execution| execution.id == input.execution)
                    .context("release_execution_not_selected")?;
                execution.host.advance_with_clock(&execution.id, || {
                    Ok(u64::try_from(
                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                    )?)
                })?;
                let snapshot = execution.host.inspect(&execution.id)?;
                let state = match snapshot.terminal {
                    Some(ReleaseTerminal::Activated) => "active",
                    Some(ReleaseTerminal::AuthorityLost) => "authority_lost",
                    Some(ReleaseTerminal::Intervention) => "intervention",
                    None => "pending",
                };
                eprintln!(
                    "release {}: {:?}",
                    snapshot.target.app.as_str(),
                    snapshot.phase
                );
                Ok(
                    json!({"state":state,"wait_millis":if snapshot.terminal.is_none() {1000} else {0}}),
                )
            }
            "gke-release-wait" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Input {
                    millis: u64,
                }
                let input: Input = request.decode()?;
                ensure!(input.millis <= 1000, "release_wait_budget");
                std::thread::sleep(Duration::from_millis(input.millis));
                Ok(json!({}))
            }
            "gke-release-publish" => {
                // Every active app of the scope gets the selections of every
                // other one, not only this run's candidates.
                let journal = &self.configuration.journal;
                let publication = publish_scope(journal, &self.scope, |deployment| {
                    GkeReleaseProvider::new(journal.clone(), deployment, self.tokens.clone())
                })?;
                Ok(
                    json!({"version":1,"status":"activated_and_published","origin":"live_gke","revision":publication.revision,"snapshot":publication.digest,"executions":self.executions.iter().map(|execution| &execution.id).collect::<Vec<_>>()}),
                )
            }
            _ => anyhow::bail!("unknown_gke_release_capability"),
        }
    }
}

/// The release targets of every app `instance` binds, in `scope`'s
/// installation and environment.
pub fn release_scope(instance: &Value, scope: &ReleaseTarget) -> Result<Vec<ReleaseTarget>> {
    let apps = instance["apps"]
        .as_object()
        .context("release_instance_apps_missing")?;
    ensure!(!apps.is_empty() && apps.len() <= 32, "release_scope_budget");
    apps.keys()
        .map(|app| {
            Ok(ReleaseTarget {
                company: scope.company.clone(),
                environment: scope.environment.clone(),
                app: app.clone().try_into()?,
            })
        })
        .collect()
}

pub fn run(configuration: Configuration, tokens: Arc<dyn AccessTokenProvider>) -> Result<Value> {
    let mut session = Session::open(configuration, tokens)?;
    automation::run(&automation::runner()?, &["gke-release"], |request| {
        session.capability(&request)
    })
}
