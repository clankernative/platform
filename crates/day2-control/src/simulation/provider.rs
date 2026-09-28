use super::{Fault, plans};
use crate::{
    BindingRef, BuildPlan, Digest,
    engine::{Capabilities, EffectResult, check_publication},
    journal::{Lease, RecoveryMode},
    kernel::{
        BuildFailureEvidence, EffectKind, FailureCode, Observation, State, VerificationEvidence,
    },
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub company: String,
    pub app: String,
    pub commit: String,
    pub binding: BindingRef,
    pub effect: Digest,
    pub kind: EffectKind,
    pub observation: Observation,
    pub visible_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub effect: Digest,
    pub company: String,
    pub commit: String,
    pub receipt: Digest,
}

#[derive(Default)]
struct StateData {
    now: u64,
    fault: Fault,
    revoked: [bool; 2],
    records: BTreeMap<Digest, Record>,
    mutations: Vec<Mutation>,
}

/// Stateful external service model, deliberately independent of journal storage.
/// Receipts and delayed visibility survive host restart; no cloud APIs are called.
#[derive(Default)]
pub struct Provider {
    data: Mutex<StateData>,
}

#[derive(Debug)]
pub(super) struct RevokedBinding;

impl std::fmt::Display for RevokedBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("provider_binding_revoked")
    }
}

impl std::error::Error for RevokedBinding {}

impl Provider {
    pub fn configure(&self, now: u64, fault: Fault) -> Result<()> {
        let mut state = self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?;
        state.now = now;
        state.fault = fault;
        Ok(())
    }

    pub fn revoke(&self, tenant: usize, revoked: bool) -> Result<()> {
        self.data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?
            .revoked[tenant] = revoked;
        Ok(())
    }

    pub fn binding_revoked(&self, plan: &BuildPlan) -> Result<bool> {
        Ok(self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?
            .revoked[usize::from(plan.company.as_str() == "beta")])
    }

    pub fn records(&self) -> Result<Vec<Record>> {
        Ok(self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?
            .records
            .values()
            .cloned()
            .collect())
    }

    pub fn mutations(&self) -> Result<Vec<Mutation>> {
        Ok(self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?
            .mutations
            .clone())
    }

    pub fn source(plan: &BuildPlan) -> Result<Digest> {
        Digest::of(&(
            "simulation-source-v1",
            &plan.company,
            &plan.profile.source,
            &plan.commit,
        ))
    }

    pub fn artifact(plan: &BuildPlan) -> Result<Digest> {
        Digest::of(&(
            "simulation-artifact-v1",
            Self::source(plan)?,
            &plan.profile.platform,
            &plan.profile.recipe,
            &plan.profile.builder,
        ))
    }

    fn observation(lease: &Lease, reject: bool) -> Result<Observation> {
        let plan = &lease.execution.plan;
        match lease.kind {
            EffectKind::FetchSource => Ok(if reject {
                Observation::Rejected {
                    code: FailureCode::Denied,
                }
            } else {
                Observation::Source {
                    source: Self::source(plan)?,
                }
            }),
            EffectKind::VerifyArtifact => {
                ensure!(
                    matches!(&lease.execution.state, State::SourceReady { source } if *source == Self::source(plan)?),
                    "provider_source_identity"
                );
                let checks = Digest::of(&("simulation-checks-v1", plan.fingerprint()?, reject))?;
                Ok(if reject {
                    Observation::BuildRejected {
                        evidence: BuildFailureEvidence {
                            plan: plan.fingerprint()?,
                            source: Self::source(plan)?,
                            platform: plan.profile.platform.clone(),
                            recipe: plan.profile.recipe.clone(),
                            builder: plan.profile.builder.clone(),
                            checks,
                            code: FailureCode::Contract,
                        },
                    }
                } else {
                    Observation::Verified {
                        evidence: VerificationEvidence {
                            plan: plan.fingerprint()?,
                            source: Self::source(plan)?,
                            platform: plan.profile.platform.clone(),
                            recipe: plan.profile.recipe.clone(),
                            builder: plan.profile.builder.clone(),
                            artifact: Self::artifact(plan)?,
                            checks,
                            credential_presence: crate::kernel::CredentialPresence::Absent,
                        },
                    }
                })
            }
            EffectKind::PublishCheck => {
                if reject {
                    return Ok(Observation::Rejected {
                        code: FailureCode::Denied,
                    });
                }
                let publication = check_publication(lease)?;
                Ok(Observation::Published {
                    evidence: publication.evidence.clone(),
                    publication: Digest::of(&(
                        "simulation-check-receipt-v1",
                        &plan.company,
                        &plan.profile.source,
                        publication,
                    ))?,
                })
            }
        }
    }
}

impl Capabilities for Provider {
    fn validate(&self, plan: &BuildPlan) -> Result<()> {
        let expected = plans()?;
        ensure!(
            expected.iter().any(|expected| expected == plan),
            "provider_unapproved_plan"
        );
        let tenant = usize::from(plan.company.as_str() == "beta");
        if self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?
            .revoked[tenant]
        {
            return Err(RevokedBinding.into());
        }
        Ok(())
    }

    fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        self.validate(&lease.execution.plan)?;
        ensure!(
            lease.effect == crate::kernel::effect_id(&lease.execution.plan, lease.kind)?,
            "provider_effect_identity"
        );
        let mut state = self
            .data
            .lock()
            .map_err(|_| anyhow::anyhow!("provider_lock"))?;
        let fault = state.fault;
        if fault == Fault::Unavailable {
            return Ok(EffectResult::Ambiguous);
        }
        if let Some(record) = state.records.get(&lease.effect) {
            ensure!(
                record.company == lease.execution.plan.company.as_str()
                    && record.commit == lease.execution.plan.commit.as_str(),
                "provider_receipt_scope"
            );
            return Ok(if state.now < record.visible_at {
                EffectResult::Ambiguous
            } else {
                EffectResult::Completed(record.observation.clone())
            });
        }
        // Missing after an uncertain publish is not evidence of non-application.
        // Preserve this limitation rather than inventing an exactly-once provider.
        if lease.recovery == RecoveryMode::Reconcile && lease.kind == EffectKind::PublishCheck {
            return Ok(EffectResult::Ambiguous);
        }
        if fault == Fault::NotApplied {
            return Ok(EffectResult::RetryNotApplied);
        }
        let observation = Self::observation(lease, fault == Fault::Reject)?;
        if let Observation::Published {
            evidence: expected, ..
        } = &observation
        {
            ensure!(
                state.records.values().any(|record| record.company
                    == lease.execution.plan.company.as_str()
                    && record.commit == lease.execution.plan.commit.as_str()
                    && match &record.observation {
                        Observation::Verified { evidence } =>
                            Digest::of(evidence).is_ok_and(|value| value == *expected),
                        Observation::BuildRejected { evidence } =>
                            Digest::of(evidence).is_ok_and(|value| value == *expected),
                        _ => false,
                    }),
                "publication_without_verified_provider_evidence"
            );
            state.mutations.push(Mutation {
                effect: lease.effect.clone(),
                company: lease.execution.plan.company.as_str().into(),
                commit: lease.execution.plan.commit.as_str().into(),
                receipt: Digest::of(&observation)?,
            });
        }
        let plan = &lease.execution.plan;
        let visible_at = state
            .now
            .checked_add(if fault == Fault::Delayed {
                super::LEASE_TICK * 2
            } else {
                0
            })
            .ok_or_else(|| anyhow::anyhow!("provider_clock_overflow"))?;
        state.records.insert(
            lease.effect.clone(),
            Record {
                company: plan.company.as_str().into(),
                app: plan.app.as_str().into(),
                commit: plan.commit.as_str().into(),
                binding: if lease.kind == EffectKind::VerifyArtifact {
                    plan.profile.builder.clone()
                } else {
                    plan.profile.source.clone()
                },
                effect: lease.effect.clone(),
                kind: lease.kind,
                observation: observation.clone(),
                visible_at,
            },
        );
        Ok(if matches!(fault, Fault::LostAck | Fault::Delayed) {
            EffectResult::Ambiguous
        } else {
            EffectResult::Completed(observation)
        })
    }
}
