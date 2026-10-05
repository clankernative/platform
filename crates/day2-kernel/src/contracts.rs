use anyhow::{Result, ensure};
pub use day2_capabilities::{BindingRef, BuildProfile, Digest, GitOid, Name};
use serde::{Deserialize, Serialize};

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
