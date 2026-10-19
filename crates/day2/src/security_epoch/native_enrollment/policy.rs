use crate::security_epoch::runtime_profile::ContainerSelection;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{
    Digest,
    security_epoch::{
        AuthorityScope, EpochStore,
        bootstrap::{GkeClusterSelection, GkeRoleSelection},
    },
};
use serde::{Deserialize, Serialize};

/// Closed native roles. These do not identify a human, app worker or provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeRole {
    AppHost,
    SecurityShell,
    EpochController,
}

/// Operator selections, not proof that any selected process currently exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentPolicy {
    pub scope: AuthorityScope,
    pub root_version: String,
    pub root_public_key: String,
    pub provisioner_code: Digest,
    pub issuer_code: Digest,
    pub app_host_code: Digest,
    pub security_shell_code: Digest,
    pub controller_code: Digest,
    pub profile: Digest,
    pub runtime: RuntimeSelection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeSelection {
    pub cluster: GkeClusterSelection,
    /// Used only for authenticated project/cluster route selection. No epoch
    /// read or already-created authority is needed to enroll a native role.
    pub store: EpochStore,
    pub app: GkeRoleSelection,
    pub app_container: ContainerSelection,
    pub shell: GkeRoleSelection,
    pub shell_container: ContainerSelection,
    pub controller: GkeRoleSelection,
    pub controller_container: ContainerSelection,
    pub containerd_code: Digest,
    pub containerd_version: String,
    pub containerd_revision: String,
    pub cri_version: String,
    pub node_name: String,
    pub node_uid: String,
    pub kernel_release: String,
    pub architecture: String,
}

impl EnrollmentPolicy {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            !self.root_version.is_empty()
                && self.root_version.len() <= 128
                && self
                    .root_version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "native_enrollment_root_version"
        );
        self.root_key()?;
        self.runtime.cluster.validate()?;
        self.runtime.store.validate()?;
        self.runtime.app.validate()?;
        self.runtime.shell.validate()?;
        self.runtime.controller.validate()?;
        ensure!(
            self.runtime.store.scope == self.scope,
            "native_enrollment_scope_selection"
        );
        for value in [
            &self.runtime.containerd_version,
            &self.runtime.containerd_revision,
            &self.runtime.cri_version,
            &self.runtime.node_name,
            &self.runtime.node_uid,
            &self.runtime.kernel_release,
            &self.runtime.architecture,
        ] {
            ensure!(
                !value.is_empty()
                    && value.len() <= 253
                    && !value.chars().any(|c| c.is_control() || c.is_whitespace()),
                "native_enrollment_runtime_selection"
            );
        }
        Ok(())
    }

    pub(super) fn root_key(&self) -> Result<[u8; 32]> {
        decode_key(&self.root_public_key)
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-native-enrollment-policy-v1", self))
    }

    pub(super) fn code(&self, role: NativeRole) -> &Digest {
        match role {
            NativeRole::AppHost => &self.app_host_code,
            NativeRole::SecurityShell => &self.security_shell_code,
            NativeRole::EpochController => &self.controller_code,
        }
    }

    pub(super) fn workload(&self, role: NativeRole) -> (&GkeRoleSelection, &ContainerSelection) {
        match role {
            NativeRole::AppHost => (&self.runtime.app, &self.runtime.app_container),
            NativeRole::SecurityShell => (&self.runtime.shell, &self.runtime.shell_container),
            NativeRole::EpochController => {
                (&self.runtime.controller, &self.runtime.controller_container)
            }
        }
    }
}

pub(super) fn decode_key(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 43, "native_enrollment_key_encoding");
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&bytes) == value,
        "native_enrollment_key_encoding"
    );
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("native_enrollment_key_length"))
}
