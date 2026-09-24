use super::{Action, BUILD_COUNT, TARGET_BUILDS, name};
use crate::{
    BindingRef, BuildPlan, Digest,
    journal::{Journal, OperatorActor},
    kernel::State,
    provider_evidence::{ReadBarrier, RevisionToken, StateEvidence},
    release::{
        ActivationReceipt, ApprovedRelease, GitApproval, ImmutableSecretRef, ReadyRelease,
        ReleaseApproval, ReleaseAuthority, ReleaseState, ReleaseTarget, SecretObservation,
    },
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    path::Path,
};

#[derive(Default)]
pub struct Releases {
    approved: [Option<ApprovedRelease>; BUILD_COUNT],
    ready: [Option<ReadyRelease>; BUILD_COUNT],
    approvals: BTreeMap<Digest, ReleaseApproval>,
    observed: BTreeMap<Digest, SecretObservation>,
    revisions: BTreeMap<Digest, u64>,
    authority_revision: [u64; 2],
    approval_authority: BTreeMap<Digest, u64>,
    readiness: BTreeMap<Digest, (Digest, u64, u64)>,
    activations: Vec<ActivationReceipt>,
    revoked: BTreeSet<Digest>,
    cancelled_builds: BTreeSet<Digest>,
    retiring: BTreeSet<Digest>,
}

pub(super) fn target(plan: &BuildPlan) -> Result<ReleaseTarget> {
    Ok(ReleaseTarget {
        company: plan.company.clone(),
        environment: name("production")?,
        app: plan.app.clone(),
    })
}
fn actor() -> Result<OperatorActor> {
    OperatorActor::try_from("simulation_operator".to_owned())
}
pub(super) fn secret(plan: &BuildPlan, index: usize) -> Result<ImmutableSecretRef> {
    Ok(ImmutableSecretRef {
        binding: BindingRef::pin(
            name(if plan.app.as_str() == "spend" {
                "shared_secrets"
            } else {
                "secrets"
            })?,
            &(plan.company.as_str(), "vault"),
        )?,
        secret: name("database_password")?,
        version: NonZeroU64::new([1, 2, 3, 1, 2, 3][index]).context("secret version")?,
    })
}

pub(super) fn resource(plan: &BuildPlan) -> Result<crate::runtime_secret::ProviderResource> {
    Ok(crate::runtime_secret::ProviderResource {
        provider: name("simulation")?,
        account: plan.company.clone(),
        secret: name("shared_database_password")?,
    })
}

impl Releases {
    pub fn approvals(&self) -> &BTreeMap<Digest, ReleaseApproval> {
        &self.approvals
    }

    pub fn activations(&self) -> &[ActivationReceipt] {
        &self.activations
    }

    pub fn cancel_build(&mut self, build: Digest) {
        self.cancelled_builds.insert(build);
    }

    pub fn retire(&mut self, plans: &[BuildPlan], version: u8) -> Result<()> {
        for (index, plan) in plans.iter().enumerate() {
            let reference = secret(plan, index)?;
            if plan.company.as_str() == "alpha" && reference.version.get() == u64::from(version) {
                self.retiring.insert(Digest::of(&reference)?);
            }
        }
        Ok(())
    }

    pub fn eligible(&self, release: &Digest) -> Result<bool> {
        let approval = self
            .approvals
            .get(release)
            .context("unknown approval in eligibility oracle")?;
        let latest = self
            .approvals
            .values()
            .filter(|other| other.target == approval.target)
            .map(|other| other.expected_generation)
            .max();
        let tenant = usize::from(approval.target.company.as_str() == "beta");
        Ok(latest == Some(approval.expected_generation)
            && !self.revoked.contains(release)
            && !self.cancelled_builds.contains(&approval.build_execution)
            && !self.retiring.contains(&Digest::of(&approval.secret)?)
            && self.approval_authority.get(release) == Some(&self.authority_revision[tenant]))
    }

    pub fn approval(&self, build: usize) -> Option<(Digest, ReleaseApproval)> {
        let approved = self.approved[build].as_ref()?;
        Some((
            approved.id().to_owned(),
            self.approvals.get(approved.id())?.clone(),
        ))
    }

    pub fn restart(&mut self, path: &Path) -> Result<()> {
        let identities: Vec<_> = self
            .approved
            .iter()
            .map(|value| value.as_ref().map(|value| value.id().to_owned()))
            .collect();
        self.approved = std::array::from_fn(|_| None);
        self.ready = std::array::from_fn(|_| None);
        let journal = Journal::open(path)?;
        for (index, id) in identities.into_iter().enumerate() {
            if let Some(id) = id {
                self.approved[index] = Some(journal.load_approved_release(&id)?);
            }
        }
        Ok(())
    }

    pub fn record_workflow_activation(&mut self, receipt: &ActivationReceipt) -> Result<()> {
        if self.activations.contains(receipt) {
            return Ok(());
        }
        let approval = self
            .approvals
            .get(&receipt.release)
            .context("workflow activation without independent Git approval")?;
        let tenant = usize::from(receipt.target.company.as_str() == "beta");
        ensure!(
            receipt.target == approval.target
                && receipt.artifact == approval.artifact
                && receipt.secret == approval.secret
                && receipt.generation == approval.expected_generation + 1
                && self.approval_authority.get(&receipt.release)
                    == Some(&self.authority_revision[tenant]),
            "workflow activation without current scoped Git approval"
        );
        self.activations.push(receipt.clone());
        Ok(())
    }

    pub fn initialize(&mut self, path: &Path, plans: &[BuildPlan]) -> Result<()> {
        for index in TARGET_BUILDS {
            let plan = &plans[index];
            let tenant = usize::from(plan.company.as_str() == "beta");
            self.authority_revision[tenant] = Journal::open(path)?.observe_release_authority(
                &target(plan)?,
                &name("initial_authority")?,
                0,
                &ReleaseAuthority {
                    source: plan.profile.source.clone(),
                    policy: Digest::new(b"review-policy-v1"),
                    actor: actor()?,
                },
            )?;
        }
        for (index, plan) in plans.iter().enumerate() {
            Journal::open(path)?.register_runtime_secret(
                &target(plan)?,
                &secret(plan, index)?,
                &resource(plan)?,
                &actor()?,
            )?;
        }
        Ok(())
    }

    pub fn states(&self, path: &Path, plans: &[BuildPlan]) -> Result<Vec<ReleaseState>> {
        let journal = Journal::open(path)?;
        TARGET_BUILDS
            .into_iter()
            .map(|index| journal.release_state(&target(&plans[index])?))
            .collect()
    }

    pub fn perform(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        action: &Action,
        sequence: usize,
    ) -> Result<String> {
        let before = self.states(path, plans)?;
        let result = self.apply(path, plans, action, sequence);
        let after = self.states(path, plans)?;
        if result.is_err() && before != after {
            return Ok("isolation_bypass".into());
        }
        // Approval, readiness and secret/authority changes cannot replace an incumbent.
        if !matches!(action, Action::Activate { .. })
            && before
                .iter()
                .map(|state| &state.active)
                .ne(after.iter().map(|state| &state.active))
        {
            return Ok("isolation_bypass".into());
        }
        match result {
            Ok(()) => Ok("release_accepted".into()),
            Err(error) if expected_denial(&error) => Ok("release_refused".into()),
            Err(error) => Err(error),
        }
    }

    fn apply(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        action: &Action,
        sequence: usize,
    ) -> Result<()> {
        let mut journal = Journal::open(path)?;
        match *action {
            Action::Approve {
                build,
                wrong_commit,
                wrong_tenant,
            } => {
                let index = build as usize;
                let plan = &plans[index];
                let state = journal.get(&plan.execution_id()?)?;
                let State::Succeeded {
                    artifact, evidence, ..
                } = state.state
                else {
                    anyhow::bail!("build_not_verified")
                };
                let mut release_target = target(plan)?;
                if wrong_tenant {
                    release_target.company = name(if plan.company.as_str() == "alpha" {
                        "beta"
                    } else {
                        "alpha"
                    })?;
                }
                let current = journal.release_state(&release_target)?;
                let approval = ReleaseApproval {
                    target: release_target,
                    request: name(&format!("approval_{sequence}"))?,
                    expected_generation: current.generation,
                    build_execution: state.id,
                    artifact,
                    evidence,
                    git: GitApproval {
                        source: plan.profile.source.clone(),
                        commit: if wrong_commit {
                            plans[(index + 1) % plans.len()].commit.clone()
                        } else {
                            plan.commit.clone()
                        },
                        policy: Digest::new(b"review-policy-v1"),
                        receipt: Digest::of(&("git-approved", plan.fingerprint()?, sequence))?,
                        actor: actor()?,
                    },
                    secret: secret(plan, index)?,
                };
                let approved = journal.approve_release(&approval)?;
                ensure!(!wrong_commit && !wrong_tenant, "invalid approval accepted");
                self.approval_authority.insert(
                    approved.id().to_owned(),
                    self.authority_revision[usize::from(plan.company.as_str() == "beta")],
                );
                self.approvals.insert(approved.id().to_owned(), approval);
                self.approved[index] = Some(approved);
            }
            Action::Secret {
                build,
                enabled,
                access,
                ready,
            } => {
                let plan = &plans[build as usize];
                let reference = secret(plan, build as usize)?;
                let key = Digest::of(&(target(plan)?, &reference))?;
                let current = self.revisions.get(&key).copied().unwrap_or(0);
                let observation = SecretObservation {
                    provider_state: StateEvidence::Qualified {
                        revision: RevisionToken::Ordered {
                            stream: Digest::of(&reference)?,
                            sequence: NonZeroU64::new(current + 1).context("provider revision")?,
                        },
                        barrier: ReadBarrier {
                            authority: reference.binding.clone(),
                            resource: Digest::of(&reference)?,
                            after_effect: None,
                            receipt: Digest::of(&("secret-provider-event", &key, sequence))?,
                        },
                    },
                    reference,
                    evidence: Digest::of(&("secret-provider-event", &key, sequence))?,
                    enabled,
                    access_granted: access,
                    projection_ready: ready,
                };
                let receipt = journal.observe_release_secret(
                    &target(plan)?,
                    &name(&format!("secret_{sequence}"))?,
                    current,
                    &observation,
                )?;
                self.revisions.insert(key.clone(), receipt.revision);
                self.observed.insert(key, observation);
            }
            Action::Prepare { build } => {
                let approved = self.approved[build as usize]
                    .as_ref()
                    .context("approval missing")?;
                let ready = journal.prepare_release(approved)?;
                let approval = self
                    .approvals
                    .get(approved.id())
                    .context("approval fact missing")?;
                let secret_revision = *self
                    .revisions
                    .get(&Digest::of(&(&approval.target, &approval.secret))?)
                    .context("readiness without provider metadata")?;
                let authority = *self
                    .approval_authority
                    .get(approved.id())
                    .context("approval authority missing")?;
                self.readiness.insert(
                    ready.id().to_owned(),
                    (approved.id().to_owned(), secret_revision, authority),
                );
                self.ready[build as usize] = Some(ready);
            }
            Action::Activate { build } => {
                let before = self.states(path, plans)?;
                let receipt = journal.activate_release(
                    self.ready[build as usize]
                        .as_ref()
                        .context("readiness missing")?,
                )?;
                if self.activations.contains(&receipt) {
                    // A historical receipt is not a new activation or restored authority.
                    ensure!(
                        before == self.states(path, plans)?,
                        "historical receipt changed active authority"
                    );
                    return Ok(());
                }
                let approval = self
                    .approvals
                    .get(&receipt.release)
                    .context("activation without recorded Git approval")?;
                ensure!(
                    receipt.artifact == approval.artifact
                        && receipt.target == approval.target
                        && receipt.secret == approval.secret,
                    "activation receipt mismatch"
                );
                let observed = self
                    .observed
                    .get(&Digest::of(&(&receipt.target, &receipt.secret))?)
                    .context("secret provider observation missing")?;
                ensure!(
                    observed.enabled && observed.access_granted && observed.projection_ready,
                    "activation without provider readiness"
                );
                let tenant = usize::from(approval.target.company.as_str() == "beta");
                let target_index = TARGET_BUILDS
                    .iter()
                    .position(|index| {
                        target(&plans[*index]).is_ok_and(|value| value == approval.target)
                    })
                    .context("release target catalog")?;
                let current = &before[target_index];
                let (release, secret_revision, authority) = self
                    .readiness
                    .get(&receipt.readiness)
                    .context("unrecorded readiness proof")?;
                ensure!(
                    current.desired.as_ref() == Some(&receipt.release)
                        && current.generation == receipt.generation
                        && *release == receipt.release
                        && *authority == self.authority_revision[tenant]
                        && self
                            .revisions
                            .get(&Digest::of(&(&receipt.target, &receipt.secret))?)
                            == Some(secret_revision),
                    "activation without current authority and secret revision"
                );
                self.activations.push(receipt);
            }
            Action::RevokeRelease { build } | Action::ReleaseCancel { build } => {
                let approved = self.approved[build as usize]
                    .as_ref()
                    .context("approval missing")?;
                if matches!(action, Action::ReleaseCancel { .. }) {
                    journal.cancel_release(approved, &actor()?)?;
                } else {
                    journal.revoke_release(approved, &actor()?)?;
                }
                self.revoked.insert(approved.id().to_owned());
            }
            Action::RevokeAuthority { tenant } => {
                let expected = self.authority_revision[tenant as usize];
                for index in TARGET_BUILDS {
                    let plan = &plans[index];
                    if usize::from(plan.company.as_str() == "beta") != tenant as usize {
                        continue;
                    }
                    self.authority_revision[tenant as usize] = journal.observe_release_authority(
                        &target(plan)?,
                        &name(&format!("authority_{sequence}"))?,
                        expected,
                        &ReleaseAuthority {
                            source: plan.profile.source.clone(),
                            policy: Digest::of(&("revised-policy", sequence))?,
                            actor: actor()?,
                        },
                    )?;
                }
            }
            _ => anyhow::bail!("not a release action"),
        }
        Ok(())
    }

    pub fn invariant(&self, path: &Path, plans: &[BuildPlan]) -> Result<Option<&'static str>> {
        let journal = Journal::open(path)?;
        for (index, state) in self.states(path, plans)?.into_iter().enumerate() {
            if let Some(active) = state.active {
                let Some(approval) = self.approvals.get(&active.release) else {
                    return Ok(Some("activation_without_git_approval"));
                };
                let build = journal.get(&approval.build_execution)?;
                if !matches!(build.state,State::Succeeded {ref artifact,ref evidence,..} if *artifact==active.artifact && *evidence==approval.evidence)
                    || active.target != target(&plans[TARGET_BUILDS[index]])?
                    || !self.activations.contains(&active)
                {
                    return Ok(Some("unverified_or_cross_tenant_activation"));
                }
            }
        }
        Ok(None)
    }
}

pub(super) fn expected_denial(error: &anyhow::Error) -> bool {
    if error
        .downcast_ref::<crate::release::ReleaseNotReady>()
        .is_some()
    {
        return true;
    }
    if matches!(
        error.downcast_ref::<crate::runtime_secret::RuntimeSecretRejection>(),
        Some(
            crate::runtime_secret::RuntimeSecretRejection::VersionUnavailable
                | crate::runtime_secret::RuntimeSecretRejection::Unregistered
                | crate::runtime_secret::RuntimeSecretRejection::WrongOwner
        )
    ) {
        return true;
    }
    matches!(
        error.to_string().as_str(),
        "build_not_verified"
            | "approval missing"
            | "readiness missing"
            | "release is no longer pending"
            | "release is not approved and pending"
            | "stale secret readiness"
            | "release already activated with different readiness"
            | "stale desired generation"
            | "release has been superseded"
            | "release approval authority is stale"
            | "Git approval does not match current installation authority"
            | "build belongs to another release target"
            | "Git approval does not match exact build source"
            | "release requires exact succeeded build artifact and evidence"
            | "build cancellation invalidates release"
    )
}
