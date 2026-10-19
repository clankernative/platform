//! Fixed GKE zonal Persistent Disk selection and response joins. These values
//! are DATA: only the native owner may combine authenticated replies with the
//! current process mount and its retained original descriptor.

use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest, Name,
    security_epoch::bootstrap::{InitialBootstrapPolicy, KubernetesObjectSelection},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PersistentDiskSelection {
    pub claim: KubernetesObjectSelection,
    pub volume: KubernetesObjectSelection,
    pub zone: Name,
    pub disk: Name,
    /// Immutable Compute resource ID, not the disk name or CSI handle.
    pub disk_id: String,
    pub node: KubernetesObjectSelection,
    pub instance: Name,
    pub instance_id: String,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn numeric_id(value: &str) -> bool {
    !value.starts_with('0')
        && value.parse::<u64>().is_ok_and(|id| id != 0)
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .context("storage_provider_reply_field")
}

fn kubernetes(
    value: &Value,
    kind: &str,
    selected: &KubernetesObjectSelection,
    namespace: Option<&str>,
) -> Result<()> {
    ensure!(
        text(value, "/apiVersion")? == "v1"
            && text(value, "/kind")? == kind
            && text(value, "/metadata/name")? == selected.name
            && text(value, "/metadata/uid")? == selected.uid
            && value
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(Value::is_null)
            && namespace
                .is_none_or(
                    |ns| value.pointer("/metadata/namespace").and_then(Value::as_str) == Some(ns)
                ),
        "storage_provider_kubernetes_identity"
    );
    Ok(())
}

impl PersistentDiskSelection {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-gke-zonal-persistent-disk-v1", self))
    }

    pub(super) fn validate(&self, policy: &InitialBootstrapPolicy) -> Result<()> {
        for object in [&self.claim, &self.volume, &self.node] {
            ensure!(
                identifier(&object.name) && identifier(&object.uid),
                "storage_provider_object_selection"
            );
        }
        ensure!(
            numeric_id(&self.disk_id)
                && numeric_id(&self.instance_id)
                && self.disk_id == policy.fresh_storage.provider_volume_uid
                && self.digest()? == policy.fresh_storage.mount_binding,
            "storage_provider_selection_mismatch"
        );
        Ok(())
    }

    pub(super) fn disk_path(&self, policy: &InitialBootstrapPolicy) -> String {
        format!(
            "projects/{}/zones/{}/disks/{}",
            policy.cluster.project.as_str(),
            self.zone.as_str(),
            self.disk.as_str()
        )
    }

    fn instance_path(&self, policy: &InitialBootstrapPolicy) -> String {
        format!(
            "projects/{}/zones/{}/instances/{}",
            policy.cluster.project.as_str(),
            self.zone.as_str(),
            self.instance.as_str()
        )
    }

    pub(super) fn claim(&self, policy: &InitialBootstrapPolicy, value: &Value) -> Result<()> {
        self.validate(policy)?;
        kubernetes(
            value,
            "PersistentVolumeClaim",
            &self.claim,
            Some(&policy.app.namespace.name),
        )?;
        ensure!(
            text(value, "/status/phase")? == "Bound"
                && text(value, "/spec/volumeName")? == self.volume.name
                && text(value, "/spec/volumeMode")? == "Filesystem"
                && value.pointer("/spec/accessModes")
                    == Some(&serde_json::json!(["ReadWriteOnce"]))
                && value.pointer("/status/accessModes")
                    == Some(&serde_json::json!(["ReadWriteOnce"])),
            "storage_provider_claim_binding"
        );
        // ReadWriteOnce permits multiple Pods on one node. It is never a sole
        // writer proof; native first-holder/current-writer ownership is separate.
        Ok(())
    }

    pub(super) fn volume(&self, policy: &InitialBootstrapPolicy, value: &Value) -> Result<()> {
        self.validate(policy)?;
        kubernetes(value, "PersistentVolume", &self.volume, None)?;
        ensure!(
            text(value, "/status/phase")? == "Bound"
                && text(value, "/spec/claimRef/apiVersion")? == "v1"
                && text(value, "/spec/claimRef/kind")? == "PersistentVolumeClaim"
                && text(value, "/spec/claimRef/name")? == self.claim.name
                && text(value, "/spec/claimRef/uid")? == self.claim.uid
                && text(value, "/spec/claimRef/namespace")? == policy.app.namespace.name
                && text(value, "/spec/volumeMode")? == "Filesystem"
                && value.pointer("/spec/accessModes")
                    == Some(&serde_json::json!(["ReadWriteOnce"]))
                && text(value, "/spec/csi/driver")? == "pd.csi.storage.gke.io"
                && text(value, "/spec/csi/fsType")? == "ext4"
                && text(value, "/spec/csi/volumeHandle")? == self.disk_path(policy)
                && value
                    .pointer("/spec/csi/readOnly")
                    .is_none_or(|v| v == false),
            "storage_provider_volume_binding"
        );
        Ok(())
    }

    /// The actual native boot observation is supplied by the owning adapter,
    /// never a configured boot ID. This function itself returns no authority.
    pub(super) fn node(
        &self,
        policy: &InitialBootstrapPolicy,
        boot: &str,
        value: &Value,
    ) -> Result<()> {
        self.validate(policy)?;
        kubernetes(value, "Node", &self.node, None)?;
        ensure!(
            text(value, "/spec/providerID")?
                == format!(
                    "gce://{}/{}/{}",
                    policy.cluster.project.as_str(),
                    self.zone.as_str(),
                    self.instance.as_str()
                )
                && text(value, "/status/nodeInfo/bootID")? == boot,
            "storage_provider_node_binding"
        );
        Ok(())
    }

    pub(super) fn disk(&self, policy: &InitialBootstrapPolicy, value: &Value) -> Result<()> {
        self.validate(policy)?;
        ensure!(
            text(value, "/id")? == self.disk_id
                && text(value, "/name")? == self.disk.as_str()
                && text(value, "/selfLink")?
                    == format!(
                        "https://www.googleapis.com/compute/v1/{}",
                        self.disk_path(policy)
                    )
                && text(value, "/zone")?
                    == format!(
                        "https://www.googleapis.com/compute/v1/projects/{}/zones/{}",
                        policy.cluster.project.as_str(),
                        self.zone.as_str()
                    )
                && text(value, "/type")?
                    == format!(
                        "https://www.googleapis.com/compute/v1/projects/{}/zones/{}/diskTypes/pd-balanced",
                        policy.cluster.project.as_str(),
                        self.zone.as_str()
                    )
                && text(value, "/status")? == "READY"
                && value.get("users")
                    == Some(&serde_json::json!([format!(
                        "https://www.googleapis.com/compute/v1/{}",
                        self.instance_path(policy)
                    )])),
            "storage_provider_disk_binding"
        );
        Ok(())
    }

    /// Returns the selected attachment's device name, still DATA. The native
    /// adapter must join its actual block device to the retained directory;
    /// a symlink spelling or an attachment row alone is insufficient.
    pub(super) fn instance(
        &self,
        policy: &InitialBootstrapPolicy,
        value: &Value,
    ) -> Result<String> {
        self.validate(policy)?;
        ensure!(
            text(value, "/id")? == self.instance_id
                && text(value, "/name")? == self.instance.as_str()
                && text(value, "/selfLink")?
                    == format!(
                        "https://www.googleapis.com/compute/v1/{}",
                        self.instance_path(policy)
                    )
                && text(value, "/status")? == "RUNNING",
            "storage_provider_instance_binding"
        );
        let disks = value
            .get("disks")
            .and_then(Value::as_array)
            .context("storage_provider_attachment_list")?;
        ensure!(
            !disks.is_empty() && disks.len() <= 32,
            "storage_provider_attachment_bound"
        );
        let source = format!(
            "https://www.googleapis.com/compute/v1/{}",
            self.disk_path(policy)
        );
        let mut matches = disks
            .iter()
            .filter(|disk| disk.get("source").and_then(Value::as_str) == Some(source.as_str()));
        let disk = matches
            .next()
            .context("storage_provider_attachment_missing")?;
        ensure!(
            matches.next().is_none(),
            "storage_provider_attachment_ambiguous"
        );
        let name = text(disk, "/deviceName")?;
        ensure!(
            text(disk, "/type")? == "PERSISTENT"
                && text(disk, "/mode")? == "READ_WRITE"
                && disk.get("boot") == Some(&Value::Bool(false))
                && identifier(name)
                && !name.contains('.'),
            "storage_provider_attachment_binding"
        );
        Ok(name.to_owned())
    }
}

#[cfg(test)]
mod tests;
