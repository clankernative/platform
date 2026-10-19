use super::NativeRole;
use super::root_kms::KmsRootSelection;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{GkeRoleSelection, InitialBootstrapPolicy},
    },
};
use serde::{Deserialize, Serialize};

/// Operator selections only. Role, workload, container, code and profile have
/// one canonical source in the shared initial-bootstrap contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentPolicy {
    pub bootstrap: InitialBootstrapPolicy,
    /// Routing/identity DATA; enrollment does not read or require an epoch.
    pub store: EpochStore,
    pub root: KmsRootSelection,
    pub provisioner_code: Digest,
    pub issuer_code: Digest,
    pub runtime: RuntimeSelection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeSelection {
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
        self.bootstrap
            .validate(&std::collections::BTreeMap::from([(
                self.bootstrap.epoch_store.id.clone(),
                self.store.clone(),
            )]))?;
        self.root.validate()?;
        self.root_key()?;
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
        decode_key(&self.root.public_key)
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-native-enrollment-policy-v1", self))
    }

    pub(super) fn code(&self, role: NativeRole) -> &Digest {
        self.bootstrap.native_role(role).code
    }

    pub(super) fn workload(&self, role: NativeRole) -> &GkeRoleSelection {
        self.bootstrap.native_role(role).workload
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
