use crate::{BuildPlan, Digest};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FetchSource,
    VerifyArtifact,
    PublishCheck,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum State {
    Accepted,
    SourceReady {
        source: Digest,
    },
    Verified {
        source: Digest,
        artifact: Digest,
        evidence: Digest,
    },
    VerificationFailed {
        source: Digest,
        evidence: Digest,
        code: FailureCode,
    },
    Succeeded {
        artifact: Digest,
        evidence: Digest,
        publication: Digest,
    },
    Failed {
        code: FailureCode,
    },
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Denied,
    Contract,
    Permanent,
    Budget,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Source {
        source: Digest,
    },
    Verified {
        evidence: VerificationEvidence,
    },
    BuildRejected {
        evidence: BuildFailureEvidence,
    },
    Published {
        evidence: Digest,
        publication: Digest,
    },
    Rejected {
        code: FailureCode,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvidence {
    pub plan: Digest,
    pub source: Digest,
    pub platform: Digest,
    pub recipe: Digest,
    pub builder: crate::BindingRef,
    pub artifact: Digest,
    pub checks: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildFailureEvidence {
    pub plan: Digest,
    pub source: Digest,
    pub platform: Digest,
    pub recipe: Digest,
    pub builder: crate::BindingRef,
    pub checks: Digest,
    pub code: FailureCode,
}

fn validate_verification_binding(
    plan: &BuildPlan,
    source: &Digest,
    evidence_plan: &Digest,
    evidence_source: &Digest,
    platform: &Digest,
    recipe: &Digest,
    builder: &crate::BindingRef,
) -> Result<()> {
    ensure!(
        *evidence_plan == plan.fingerprint()?,
        "evidence belongs to another plan"
    );
    ensure!(
        evidence_source == source,
        "evidence belongs to another source snapshot"
    );
    ensure!(
        *platform == plan.profile.platform,
        "platform revision mismatch"
    );
    ensure!(
        *recipe == plan.profile.recipe,
        "verification recipe mismatch"
    );
    ensure!(
        *builder == plan.profile.builder,
        "untrusted builder binding"
    );
    Ok(())
}

impl State {
    pub fn next_effect(&self) -> Option<EffectKind> {
        match self {
            Self::Accepted => Some(EffectKind::FetchSource),
            Self::SourceReady { .. } => Some(EffectKind::VerifyArtifact),
            Self::Verified { .. } | Self::VerificationFailed { .. } => {
                Some(EffectKind::PublishCheck)
            }
            Self::Succeeded { .. } | Self::Failed { .. } | Self::Cancelled => None,
        }
    }

    pub fn observe(&self, plan: &BuildPlan, observation: &Observation) -> Result<Self> {
        ensure!(
            self.next_effect().is_some(),
            "terminal execution cannot advance"
        );
        match (self, observation) {
            (_, Observation::Rejected { code }) => Ok(Self::Failed { code: *code }),
            (Self::Accepted, Observation::Source { source }) => Ok(Self::SourceReady {
                source: source.clone(),
            }),
            (Self::SourceReady { source }, Observation::Verified { evidence }) => {
                validate_verification_binding(
                    plan,
                    source,
                    &evidence.plan,
                    &evidence.source,
                    &evidence.platform,
                    &evidence.recipe,
                    &evidence.builder,
                )?;
                Ok(Self::Verified {
                    source: source.clone(),
                    artifact: evidence.artifact.clone(),
                    evidence: Digest::of(evidence)?,
                })
            }
            (Self::SourceReady { source }, Observation::BuildRejected { evidence }) => {
                validate_verification_binding(
                    plan,
                    source,
                    &evidence.plan,
                    &evidence.source,
                    &evidence.platform,
                    &evidence.recipe,
                    &evidence.builder,
                )?;
                Ok(Self::VerificationFailed {
                    source: source.clone(),
                    evidence: Digest::of(evidence)?,
                    code: evidence.code,
                })
            }
            (
                Self::Verified {
                    artifact, evidence, ..
                },
                Observation::Published {
                    evidence: published,
                    publication,
                },
            ) => {
                ensure!(
                    evidence == published,
                    "publication belongs to different evidence"
                );
                Ok(Self::Succeeded {
                    artifact: artifact.clone(),
                    evidence: evidence.clone(),
                    publication: publication.clone(),
                })
            }
            (
                Self::VerificationFailed { evidence, code, .. },
                Observation::Published {
                    evidence: published,
                    ..
                },
            ) => {
                ensure!(
                    evidence == published,
                    "publication belongs to different failed evidence"
                );
                Ok(Self::Failed { code: *code })
            }
            _ => anyhow::bail!("observation does not match the required effect"),
        }
    }
}

pub fn effect_id(plan: &BuildPlan, effect: EffectKind) -> Result<Digest> {
    Digest::of(&(
        "day2-effect-v1",
        plan.execution_id()?,
        plan.fingerprint()?,
        effect,
    ))
}
