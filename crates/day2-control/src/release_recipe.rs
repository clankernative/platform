//! The live driver and simulation execute the same pinned, pure Roc decision.
//! Only phase and logical occurrence cross this boundary, never provider inputs.
use crate::{
    Digest,
    release_execution::{Recipe, ReleasePhase, ReleaseSnapshot, StepRequest},
};
use anyhow::{Result, bail, ensure};
use day2::automation;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct CompiledReleaseRecipe {
    executable: PathBuf,
    pin: Digest,
}

#[derive(Serialize)]
struct DecisionInput {
    phase: ReleasePhase,
    next_step: u64,
}

impl CompiledReleaseRecipe {
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

    fn select(&self, phase: ReleasePhase, next_step: u64) -> Result<StepRequest> {
        self.revision()?;
        let input = serde_json::to_string(&DecisionInput { phase, next_step })?;
        let value = automation::run(&self.executable, &["release-step", &input], |_| {
            bail!("pure release recipe requested a native capability")
        })?;
        Ok(serde_json::from_value(value)?)
    }
}

impl Recipe for CompiledReleaseRecipe {
    fn revision(&self) -> Result<Digest> {
        ensure!(
            revision(&self.executable)? == self.pin,
            "release recipe changed after construction"
        );
        Ok(self.pin.clone())
    }

    fn choose(&self, snapshot: &ReleaseSnapshot) -> Result<StepRequest> {
        self.select(snapshot.phase, snapshot.next_step)
    }
}

fn revision(executable: &Path) -> Result<Digest> {
    let executable = automation::checked_runner(executable)?;
    Digest::of(&(
        "day2-release-recipe-v1",
        automation::source_digest(),
        Digest::new(&std::fs::read(executable)?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_execution::ReleaseOperation;

    #[test]
    fn compiled_roc_selects_each_release_step_and_preserves_logical_occurrence() -> Result<()> {
        let recipe = CompiledReleaseRecipe::installed()?;
        for (phase, name, operation) in [
            (
                ReleasePhase::Accepted,
                "prepare_dependency",
                ReleaseOperation::PrepareDependency,
            ),
            (
                ReleasePhase::WaitingSecret,
                "observe_secret",
                ReleaseOperation::ObserveSecret,
            ),
            (
                ReleasePhase::SecretReady,
                "prepare_deployment",
                ReleaseOperation::PrepareDeployment,
            ),
            (
                ReleasePhase::WaitingDeployment,
                "observe_deployment",
                ReleaseOperation::ObserveDeployment,
            ),
            (
                ReleasePhase::DeploymentReady,
                "activate",
                ReleaseOperation::Activate,
            ),
        ] {
            for ordinal in [0, 1, 91] {
                let step = recipe.select(phase, ordinal)?;
                assert_eq!(step.name.as_str(), name);
                assert_eq!(step.ordinal, ordinal);
                assert_eq!(step.operation, operation);
            }
        }
        Ok(())
    }

    #[test]
    fn compiled_roc_refuses_terminal_and_unknown_phases() -> Result<()> {
        let recipe = CompiledReleaseRecipe::installed()?;
        for phase in [ReleasePhase::Active, ReleasePhase::Stopped] {
            assert!(recipe.select(phase, 0).is_err());
        }
        for raw in [
            r#"{"phase":"future","next_step":0}"#,
            r#"{"phase":"accepted","next_step":-1}"#,
            r#"{"phase":"accepted"}"#,
        ] {
            assert!(
                automation::run(&recipe.executable, &["release-step", raw], |_| {
                    bail!("pure decision invoked a capability")
                })
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn recipe_rechecks_distribution_after_construction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let original = automation::runner()?;
        let executable = directory.path().join("release-runner");
        std::fs::copy(&original, &executable)?;
        let metadata = executable.with_extension("json");
        std::fs::copy(original.with_extension("json"), &metadata)?;
        let recipe = CompiledReleaseRecipe::new(&executable)?;
        std::fs::write(metadata, b"{}")?;
        assert!(recipe.identity().is_err());
        assert!(recipe.select(ReleasePhase::Accepted, 0).is_err());
        Ok(())
    }
}
