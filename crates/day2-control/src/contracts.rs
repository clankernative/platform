use anyhow::{Result, ensure};
pub use day2_capabilities::{BindingRef, BuildProfile, Digest, GitOid, Name};
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildPlan {
    pub version: u32,
    pub company: Name,
    pub app: Name,
    pub request: Name,
    pub commit: GitOid,
    pub profile: BuildProfile,
}

impl BuildPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported build contract version");
        ensure!(
            self.profile.source.id != self.profile.builder.id
                && self.profile.source.id != self.profile.durability.id
                && self.profile.builder.id != self.profile.durability.id,
            "duplicate capability binding identity"
        );
        Ok(())
    }

    pub fn execution_id(&self) -> Result<Digest> {
        Digest::of(&("day2-build-v1", &self.company, &self.app, &self.request))
    }

    pub fn fingerprint(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(self)
    }
}
