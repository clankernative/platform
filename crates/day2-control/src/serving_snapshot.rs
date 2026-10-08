//! Operator-published active selections, separate from fresh provider evidence.
use crate::{
    release::ReleaseTarget,
    release_execution::{SelectedServing, ServingProbe},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingSnapshot {
    version: u32,
    selections: Vec<SelectedServing>,
}

impl ServingSnapshot {
    pub fn new(selections: Vec<SelectedServing>) -> Result<Self> {
        let value = Self {
            version: 1,
            selections,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && !self.selections.is_empty() && self.selections.len() <= 32,
            "serving_snapshot_budget"
        );
        let mut targets = std::collections::BTreeSet::new();
        let scope = &self.selections[0].binding.target;
        for selected in &self.selections {
            let target = &selected.binding.target;
            ensure!(
                targets.insert(serde_json::to_string(target)?)
                    && target.company == scope.company
                    && target.environment == scope.environment
                    && selected.generation > 0,
                "serving_snapshot_scope_changed"
            );
            selected.binding.incarnation.validate()?;
        }
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(1_048_577)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "serving_snapshot_byte_budget");
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 1_048_576, "serving_snapshot_byte_budget");
        let snapshot: Self = day2::json::decode(bytes)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn require_scope(&self, target: &ReleaseTarget) -> Result<()> {
        self.validate()?;
        let scope = &self.selections[0].binding.target;
        ensure!(
            scope.company == target.company && scope.environment == target.environment,
            "serving_snapshot_scope_changed"
        );
        Ok(())
    }

    pub fn selected(&self, target: &ReleaseTarget) -> Result<&SelectedServing> {
        self.selections
            .iter()
            .find(|entry| &entry.binding.target == target)
            .ok_or_else(|| anyhow::anyhow!("serving_target_unselected"))
    }

    pub fn with_selection<T>(
        path: &Path,
        target: &ReleaseTarget,
        probe: &dyn ServingProbe,
        call: impl FnOnce(&SelectedServing) -> Result<T>,
    ) -> Result<T> {
        let snapshot = Self::read(path)?;
        let selected = snapshot.selected(target)?;
        let observed = probe.observe(target)?;
        ensure!(observed == selected.binding, "serving_binding_changed");
        let result = call(selected);
        let current = Self::read(path)?;
        ensure!(
            current.selected(target)? == selected && probe.observe(target)? == observed,
            "serving_binding_changed"
        );
        result
    }
}
