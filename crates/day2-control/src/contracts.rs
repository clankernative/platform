use anyhow::{Result, ensure};
pub use day2_kernel::contracts::{BindingRef, BuildPlan, BuildProfile, Digest, GitOid, Name};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub version: u32,
    pub company: Name,
    pub build_profiles: BTreeMap<Name, BuildProfile>,
}

impl Instance {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported instance contract version");
        ensure!(
            !self.build_profiles.is_empty() && self.build_profiles.len() <= 1024,
            "build profile budget"
        );
        for profile in self.build_profiles.values() {
            ensure!(
                profile.source.id != profile.builder.id
                    && profile.source.id != profile.durability.id
                    && profile.builder.id != profile.durability.id,
                "capabilities need distinct binding identities"
            );
        }
        Ok(())
    }

    pub fn plan(
        &self,
        profile: &Name,
        app: Name,
        request: Name,
        commit: GitOid,
    ) -> Result<BuildPlan> {
        self.validate()?;
        let profile = self
            .build_profiles
            .get(profile)
            .ok_or_else(|| anyhow::anyhow!("unknown build profile"))?;
        Ok(BuildPlan {
            version: 1,
            company: self.company.clone(),
            app,
            request,
            commit,
            profile: profile.clone(),
        })
    }
}
