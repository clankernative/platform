//! One checked Roc decision implementation is used by live and simulated hosts.
use crate::{
    Digest,
    secret_retirement::{Recipe, RetirementPhase, RetirementSnapshot, RetirementStepRequest},
};
use anyhow::{Result, bail, ensure};
use day2::automation;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct CompiledSecretRetirementRecipe {
    executable: PathBuf,
    pin: Digest,
}

#[derive(Serialize)]
struct DecisionInput {
    phase: RetirementPhase,
    next_step: u64,
}

impl CompiledSecretRetirementRecipe {
    pub fn installed() -> Result<Self> {
        Self::new(&automation::runner()?)
    }
    pub fn new(executable: &Path) -> Result<Self> {
        let executable = automation::checked_runner(executable)?;
        let pin = revision(&executable)?;
        Ok(Self { executable, pin })
    }
    pub fn identity(&self) -> Result<Digest> {
        self.revision()
    }
    fn select(&self, phase: RetirementPhase, next_step: u64) -> Result<RetirementStepRequest> {
        self.revision()?;
        let input = serde_json::to_string(&DecisionInput { phase, next_step })?;
        let value = automation::run(
            &self.executable,
            &["secret-retirement-step", &input],
            |_| bail!("pure retirement recipe requested a native capability"),
        )?;
        Ok(serde_json::from_value(value)?)
    }
}
impl Recipe for CompiledSecretRetirementRecipe {
    fn revision(&self) -> Result<Digest> {
        ensure!(
            revision(&self.executable)? == self.pin,
            "retirement recipe changed after construction"
        );
        Ok(self.pin.clone())
    }
    fn choose(&self, snapshot: &RetirementSnapshot) -> Result<RetirementStepRequest> {
        self.select(snapshot.phase, snapshot.next_step)
    }
}
fn revision(executable: &Path) -> Result<Digest> {
    let executable = automation::checked_runner(executable)?;
    Digest::of(&(
        "day2-secret-retirement-recipe-v1",
        automation::source_digest(),
        Digest::new(&std::fs::read(executable)?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_retirement::RetirementOperation;
    #[test]
    fn compiled_retirement_recipe_selects_steps_and_refuses_terminal_phases() -> Result<()> {
        let recipe = CompiledSecretRetirementRecipe::installed()?;
        for (phase, operation, name) in [
            (
                RetirementPhase::WaitingConsumers,
                RetirementOperation::WaitConsumers,
                "wait_consumers",
            ),
            (
                RetirementPhase::Eligible,
                RetirementOperation::DisableVersion,
                "disable_version",
            ),
            (
                RetirementPhase::WaitingDisabled,
                RetirementOperation::ObserveDisabled,
                "observe_disabled",
            ),
            (
                RetirementPhase::Disabled,
                RetirementOperation::Complete,
                "complete",
            ),
        ] {
            for ordinal in [0, 9] {
                let step = recipe.select(phase, ordinal)?;
                assert_eq!(step.operation, operation);
                assert_eq!(step.name.as_str(), name);
                assert_eq!(step.ordinal, ordinal);
            }
        }
        for phase in [RetirementPhase::Complete, RetirementPhase::Stopped] {
            assert!(recipe.select(phase, 0).is_err());
        }
        for raw in [
            r#"{"phase":"future","next_step":0}"#,
            r#"{"phase":"waiting_consumers","next_step":-1}"#,
        ] {
            assert!(
                automation::run(
                    &recipe.executable,
                    &["secret-retirement-step", raw],
                    |_| bail!("unexpected capability")
                )
                .is_err()
            );
        }
        Ok(())
    }
}
