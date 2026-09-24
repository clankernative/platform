//! Operator-owned deployment profiles; application code cannot choose topology.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU16, NonZeroU32};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeProfile {
    LinuxSqliteSingleV1 { resources: Resources },
}

impl RuntimeProfile {
    pub fn resources(&self) -> &Resources {
        match self {
            Self::LinuxSqliteSingleV1 { resources } => resources,
        }
    }

    pub fn replicas(&self) -> u8 {
        1
    }

    pub fn state_directory(&self) -> &'static str {
        ".state"
    }

    pub fn validate(&self) -> Result<()> {
        self.resources().validate()
    }
}

/// What holds the process bound in place.
///
/// The container checks its own cgroup at start and refuses to serve when a
/// bound exceeds the profile. Docker can bound a container's processes, so the
/// default is that the bound is observed there. Kubernetes cannot: it bounds a
/// pod's processes in a cgroup above the container's, which a container in its
/// own cgroup namespace cannot see. `Pod` is the operator declaring that the
/// orchestrator holds this profile's `process_limit` for the whole pod. The
/// container then does not hold its own cgroup's process bound to the profile:
/// it may be unbounded, or a looser value the container runtime wrote itself
/// (containerd 2 on GKE writes a node-derived one). It is a declaration, not an
/// observation, and qualification records it as one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLimitEnforcement {
    #[default]
    Container,
    Pod,
}

impl ProcessLimitEnforcement {
    fn is_container(&self) -> bool {
        *self == Self::Container
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ResourceWire")]
pub struct Resources {
    memory_mib: NonZeroU32,
    cpu_millis: NonZeroU32,
    process_limit: NonZeroU16,
    #[serde(default, skip_serializing_if = "ProcessLimitEnforcement::is_container")]
    process_limit_enforced_by: ProcessLimitEnforcement,
    http_concurrency: NonZeroU16,
    shutdown_seconds: NonZeroU16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceWire {
    memory_mib: NonZeroU32,
    cpu_millis: NonZeroU32,
    process_limit: NonZeroU16,
    #[serde(default)]
    process_limit_enforced_by: ProcessLimitEnforcement,
    http_concurrency: NonZeroU16,
    shutdown_seconds: NonZeroU16,
}

impl TryFrom<ResourceWire> for Resources {
    type Error = anyhow::Error;

    fn try_from(wire: ResourceWire) -> Result<Self> {
        let resources = Self {
            memory_mib: wire.memory_mib,
            cpu_millis: wire.cpu_millis,
            process_limit: wire.process_limit,
            process_limit_enforced_by: wire.process_limit_enforced_by,
            http_concurrency: wire.http_concurrency,
            shutdown_seconds: wire.shutdown_seconds,
        };
        resources.validate()?;
        Ok(resources)
    }
}

impl Resources {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (64..=65_536).contains(&self.memory_mib.get()),
            "runtime memory must be 64..65536 MiB"
        );
        ensure!(
            (50..=64_000).contains(&self.cpu_millis.get()),
            "runtime CPU must be 50..64000 millicores"
        );
        ensure!(
            (16..=4096).contains(&self.process_limit.get()),
            "runtime process limit must be 16..4096"
        );
        ensure!(
            self.http_concurrency.get() <= 32,
            "runtime HTTP concurrency must be 1..32"
        );
        ensure!(
            (5..=300).contains(&self.shutdown_seconds.get()),
            "runtime shutdown must be 5..300 seconds"
        );
        Ok(())
    }

    pub fn memory_mib(&self) -> u32 {
        self.memory_mib.get()
    }

    pub fn cpu_millis(&self) -> u32 {
        self.cpu_millis.get()
    }

    pub fn process_limit(&self) -> u16 {
        self.process_limit.get()
    }

    pub fn process_limit_enforced_by(&self) -> ProcessLimitEnforcement {
        self.process_limit_enforced_by
    }

    pub fn http_concurrency(&self) -> u16 {
        self.http_concurrency.get()
    }

    pub fn shutdown_seconds(&self) -> u16 {
        self.shutdown_seconds.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn profile() -> Value {
        json!({"kind":"linux_sqlite_single_v1","resources":{
            "memory_mib":512,"cpu_millis":1000,"process_limit":64,
            "http_concurrency":4,"shutdown_seconds":30
        }})
    }

    #[test]
    fn single_node_profile_roundtrips_without_optional_topology() -> Result<()> {
        let input = profile();
        let decoded: RuntimeProfile = serde_json::from_value(input.clone())?;
        assert_eq!(decoded.replicas(), 1);
        assert_eq!(decoded.state_directory(), ".state");
        assert_eq!(decoded.resources().http_concurrency(), 4);
        assert_eq!(serde_json::to_value(decoded)?, input);
        Ok(())
    }

    #[test]
    fn process_limit_enforcement_defaults_to_the_container_and_only_pod_is_declarable() -> Result<()>
    {
        let decoded: RuntimeProfile = serde_json::from_value(profile())?;
        assert_eq!(
            decoded.resources().process_limit_enforced_by(),
            ProcessLimitEnforcement::Container
        );
        let mut input = profile();
        input["resources"]["process_limit_enforced_by"] = json!("pod");
        let decoded: RuntimeProfile = serde_json::from_value(input.clone())?;
        assert_eq!(
            decoded.resources().process_limit_enforced_by(),
            ProcessLimitEnforcement::Pod
        );
        assert_eq!(serde_json::to_value(decoded)?, input);
        for invalid in [json!("node"), json!("none"), json!(true), json!(null)] {
            input["resources"]["process_limit_enforced_by"] = invalid;
            assert!(serde_json::from_value::<RuntimeProfile>(input.clone()).is_err());
        }
        Ok(())
    }

    #[test]
    fn invalid_bounds_unknown_fields_and_topology_overrides_fail_closed() {
        for field in ["replicas", "storage", "origin", "command"] {
            let mut input = profile();
            input[field] = json!(2);
            assert!(serde_json::from_value::<RuntimeProfile>(input).is_err());
        }
        for (field, invalid) in [
            ("memory_mib", 0),
            ("memory_mib", 63),
            ("memory_mib", 65_537),
            ("cpu_millis", 49),
            ("cpu_millis", 64_001),
            ("process_limit", 15),
            ("process_limit", 4097),
            ("http_concurrency", 0),
            ("http_concurrency", 33),
            ("shutdown_seconds", 4),
            ("shutdown_seconds", 301),
            ("unapproved", 1),
        ] {
            let mut input = profile();
            input["resources"][field] = json!(invalid);
            assert!(serde_json::from_value::<RuntimeProfile>(input).is_err());
        }
        for invalid in [json!(null), json!("512"), json!(512.5), json!(-1)] {
            let mut input = profile();
            input["resources"]["memory_mib"] = invalid;
            assert!(serde_json::from_value::<RuntimeProfile>(input).is_err());
        }
        let mut input = profile();
        input["kind"] = "postgres_ha".into();
        assert!(serde_json::from_value::<RuntimeProfile>(input).is_err());
    }
}
