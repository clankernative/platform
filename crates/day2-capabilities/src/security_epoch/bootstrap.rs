//! Desired initial-bootstrap selections. Every value here is DATA.
//! Validation checks configuration joins; it grants no provider or file authority.

use super::{AuthorityScope, EpochIam, EpochProvider, EpochStore};
use crate::{BindingRef, Digest, Name};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesObjectSelection {
    pub name: String,
    pub uid: String,
}

impl KubernetesObjectSelection {
    fn validate(&self) -> Result<()> {
        ensure!(dns_label(&self.name), "invalid_bootstrap_kubernetes_name");
        bounded_identifier(&self.uid, 128)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GkeClusterSelection {
    pub project: Name,
    pub location: Name,
    pub name: Name,
    pub uid: String,
    pub api_origin: String,
    pub certificate_authority: Digest,
}

impl GkeClusterSelection {
    pub fn validate(&self) -> Result<()> {
        bounded_identifier(&self.uid, 128)?;
        let origin = self.api_origin.strip_prefix("https://");
        ensure!(
            origin.is_some_and(|authority| {
                let (host, port) = authority
                    .split_once(':')
                    .map_or((authority, None), |(host, port)| (host, Some(port)));
                !host.is_empty()
                    && host.len() <= 253
                    && host.split('.').all(dns_label)
                    && port.is_none_or(|port| {
                        port.parse::<u16>().is_ok_and(|value| value != 0)
                            && port.bytes().all(|byte| byte.is_ascii_digit())
                    })
            }),
            "invalid_bootstrap_kubernetes_api_origin"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadKind {
    DeploymentV1,
    StatefulSetV1,
}

/// The selected native process role. This label cannot enroll a process or
/// authorize an action; a native owner must prove its current selected role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeRole {
    AppHost,
    SecurityShell,
    EpochController,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSelection {
    pub name: String,
    /// Immutable image digest, independently selected from executable bytes.
    pub image: Digest,
}

impl ContainerSelection {
    pub fn validate(&self) -> Result<()> {
        ensure!(dns_label(&self.name), "epoch_native_container_selection");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GkeRoleSelection {
    pub namespace: KubernetesObjectSelection,
    pub kubernetes_service_account: KubernetesObjectSelection,
    pub google_service_account: EpochIam,
    pub workload_kind: WorkloadKind,
    pub workload: KubernetesObjectSelection,
    pub container: ContainerSelection,
    /// Subject-token audience. The native API transport authenticates separately.
    pub token_review_audience: String,
}

impl GkeRoleSelection {
    pub fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        self.kubernetes_service_account.validate()?;
        self.workload.validate()?;
        self.container.validate()?;
        self.google_service_account.validate()?;
        bounded_identifier(&self.token_review_audience, 2048)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStoreKind {
    FirestoreAuthorityDatabaseV1,
}

/// Permanent control-intent slots use fixed document names in the SAME selected
/// authority database. There is no configurable namespace or per-Pod journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlStoreSelection {
    pub kind: ControlStoreKind,
    pub epoch_store: BindingRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfileKind {
    GkeLinuxTrustedNativeV1,
}

/// Immutable manifests select the supported code, dependency, continuous-clock,
/// storage and channel profile. Their hashes cannot qualify those producers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRuntimeProfile {
    pub kind: RuntimeProfileKind,
    pub manifest: Digest,
    /// SHA-256 of the exact native controller executable bytes, observed from
    /// its retained self-executable descriptor. This is an executable selection,
    /// not a whole image, dependency or runtime qualification proof.
    pub controller_code: Digest,
    /// Exact native AppHost executable, observed through the retained executable
    /// descriptor. Neither the Roc artifact nor the image digest replaces it.
    pub app_host_code: Digest,
    /// Exact native SecurityShell executable. Code may be shared with AppHost;
    /// its separate workload/container and enrolled role must still be proved.
    pub security_shell_code: Digest,
    /// Roc artifact admitted by the AppHost, not its native executable.
    pub app_artifact: Digest,
}

/// Borrowed desired selections, never an enrollment, runtime or role witness.
pub struct NativeRoleSelection<'a> {
    pub role: NativeRole,
    pub workload: &'a GkeRoleSelection,
    pub code: &'a Digest,
    /// The exact runtime/enrollment profile manifest. TCB, root and runtime
    /// admission remain the native producer's responsibility.
    pub profile: &'a Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshStorageSelection {
    pub provider_volume_uid: String,
    pub mount_binding: Digest,
    pub schema_contract: Digest,
    /// The marker FORMAT; generated seed and actual marker hash are excluded.
    pub marker_format: Name,
}

/// Only CreateInitialAuthority and CompleteInitialFirstActivation belong to
/// this policy. There is no advance, restore, takeover or adoption selector.
/// Generated incarnations, request IDs, holders, clocks and receipts cannot be
/// inserted into its policy hash or supplied as configuration proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialBootstrapPolicy {
    pub scope: AuthorityScope,
    pub epoch_store: BindingRef,
    pub cluster: GkeClusterSelection,
    pub controller: GkeRoleSelection,
    pub app: GkeRoleSelection,
    pub shell: GkeRoleSelection,
    pub control_store: ControlStoreSelection,
    pub runtime_profile: BootstrapRuntimeProfile,
    pub fresh_storage: FreshStorageSelection,
}

impl InitialBootstrapPolicy {
    pub fn validate(&self, stores: &BTreeMap<Name, EpochStore>) -> Result<()> {
        self.cluster.validate()?;
        self.controller.validate()?;
        self.app.validate()?;
        self.shell.validate()?;
        bounded_identifier(&self.fresh_storage.provider_volume_uid, 512)?;
        let store = stores
            .get(&self.epoch_store.id)
            .ok_or_else(|| anyhow::anyhow!("bootstrap_epoch_store_missing"))?;
        store.validate()?;
        ensure!(
            self.epoch_store.revision == Digest::of(store)?
                && self.control_store.epoch_store == self.epoch_store
                && self.scope == store.scope,
            "bootstrap_epoch_store_selection_mismatch"
        );
        let EpochProvider::FirestoreNativeV1 {
            project,
            iam_source,
            ..
        } = &store.provider;
        ensure!(
            self.cluster.project == *project && self.app.google_service_account == *iam_source,
            "bootstrap_app_reader_selection_mismatch"
        );
        for (left, right) in [
            (&self.controller, &self.app),
            (&self.controller, &self.shell),
            (&self.app, &self.shell),
        ] {
            distinct_roles(left, right)?;
        }
        Ok(())
    }

    pub fn native_role(&self, role: NativeRole) -> NativeRoleSelection<'_> {
        let (workload, code) = match role {
            NativeRole::AppHost => (&self.app, &self.runtime_profile.app_host_code),
            NativeRole::SecurityShell => (&self.shell, &self.runtime_profile.security_shell_code),
            NativeRole::EpochController => {
                (&self.controller, &self.runtime_profile.controller_code)
            }
        };
        NativeRoleSelection {
            role,
            workload,
            code,
            profile: &self.runtime_profile.manifest,
        }
    }

    pub fn digest(&self, stores: &BTreeMap<Name, EpochStore>) -> Result<Digest> {
        self.validate(stores)?;
        Digest::of(&("day2-initial-bootstrap-policy-v1", self))
    }
}

fn distinct_roles(left: &GkeRoleSelection, right: &GkeRoleSelection) -> Result<()> {
    let EpochIam::GkeWorkloadIdentityV1 {
        service_account: left_email,
        service_account_uid: left_uid,
    } = &left.google_service_account;
    let EpochIam::GkeWorkloadIdentityV1 {
        service_account: right_email,
        service_account_uid: right_uid,
    } = &right.google_service_account;
    ensure!(
        left_email != right_email && left_uid != right_uid,
        "bootstrap_native_role_accounts_must_be_distinct"
    );
    ensure!(
        (left.namespace.name == right.namespace.name)
            == (left.namespace.uid == right.namespace.uid)
            && left.kubernetes_service_account.uid != right.kubernetes_service_account.uid
            && left.workload.uid != right.workload.uid
            && (left.namespace.name != right.namespace.name
                || (left.kubernetes_service_account.name != right.kubernetes_service_account.name
                    && left.workload.name != right.workload.name)),
        "bootstrap_native_role_workloads_must_be_distinct"
    );
    Ok(())
}

fn dns_label(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn bounded_identifier(value: &str, limit: usize) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= limit
            && !value.chars().any(char::is_whitespace)
            && !value.chars().any(char::is_control),
        "invalid_bootstrap_identifier"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn selection(store: &EpochStore, alias: &str) -> InitialBootstrapPolicy {
        let EpochProvider::FirestoreNativeV1 {
            project,
            iam_source,
            ..
        } = &store.provider;
        let epoch = BindingRef {
            id: alias.to_owned().try_into().unwrap(),
            revision: Digest::of(store).unwrap(),
        };
        let mut controller = iam_source.clone();
        let EpochIam::GkeWorkloadIdentityV1 {
            service_account,
            service_account_uid,
        } = &mut controller;
        *service_account = format!("controller@{}.iam.gserviceaccount.com", project.as_str());
        *service_account_uid = "200000000000000000007".to_owned().try_into().unwrap();
        let shell = EpochIam::GkeWorkloadIdentityV1 {
            service_account: format!("shell@{}.iam.gserviceaccount.com", project.as_str()),
            service_account_uid: "300000000000000000007".to_owned().try_into().unwrap(),
        };
        let role = |account: EpochIam, name: &str| {
            json!({
                "namespace":{"name":"native","uid":"namespace-uid"},
                "kubernetes_service_account":{"name":name,"uid":format!("{name}-ksa-uid")},
                "google_service_account":account,"workload_kind":if name == "app" { "stateful_set_v1" } else { "deployment_v1" },
                "workload":{"name":name,"uid":format!("{name}-workload-uid")},
                "container":{"name":name,"image":Digest::new(format!("{name}-image").as_bytes())},
                "token_review_audience":"https://kubernetes.default.svc"
            })
        };
        serde_json::from_value(json!({
            "scope":store.scope,"epoch_store":epoch,
            "cluster":{"project":project,"location":"us-central1","name":"native","uid":"cluster-uid",
                "api_origin":"https://10.0.0.1:443","certificate_authority":Digest::new(b"ca")},
            "controller":role(controller,"controller"),"app":role(iam_source.clone(),"app"),
            "shell":role(shell,"shell"),
            "control_store":{"kind":"firestore_authority_database_v1","epoch_store":epoch},
            "runtime_profile":{"kind":"gke_linux_trusted_native_v1","manifest":Digest::new(b"profile"),
                "controller_code":Digest::new(b"code"),"app_host_code":Digest::new(b"app-host-code"),
                "security_shell_code":Digest::new(b"shell-code"),"app_artifact":Digest::new(b"artifact")},
            "fresh_storage":{"provider_volume_uid":"provider-volume-uid","mount_binding":Digest::new(b"mount"),
                "schema_contract":Digest::new(b"schema"),"marker_format":"initial-v1"}
        })).unwrap()
    }

    #[test]
    fn bootstrap_requires_exact_store_scope_reader_and_distinct_roles() {
        let store = super::super::tests::selection();
        let stores = BTreeMap::from([("epoch".to_owned().try_into().unwrap(), store.clone())]);
        let good = selection(&store, "epoch");
        good.validate(&stores).unwrap();
        let mut cases = Vec::new();
        let mut bad = good.clone();
        bad.epoch_store.revision = Digest::new(b"other");
        cases.push(bad);
        let mut bad = good.clone();
        bad.control_store.epoch_store.id = "other".to_owned().try_into().unwrap();
        cases.push(bad);
        let mut bad = good.clone();
        bad.scope.app = "other".to_owned().try_into().unwrap();
        cases.push(bad);
        let mut bad = good.clone();
        bad.app.google_service_account = good.controller.google_service_account.clone();
        cases.push(bad);
        let mut bad = good.clone();
        bad.controller.google_service_account = good.app.google_service_account.clone();
        cases.push(bad);
        let mut bad = good.clone();
        bad.controller.kubernetes_service_account = good.app.kubernetes_service_account.clone();
        cases.push(bad);
        for other in [&good.controller, &good.app] {
            let mut bad = good.clone();
            bad.shell.google_service_account = other.google_service_account.clone();
            cases.push(bad);
            let mut bad = good.clone();
            bad.shell.kubernetes_service_account = other.kubernetes_service_account.clone();
            cases.push(bad);
            let mut bad = good.clone();
            bad.shell.workload = other.workload.clone();
            cases.push(bad);
        }
        let mut bad = good.clone();
        bad.shell.namespace.uid = "recreated-namespace".into();
        cases.push(bad);
        let mut bad = good.clone();
        bad.shell.namespace.name = "different-namespace".into();
        cases.push(bad);
        for bad in cases {
            assert!(bad.validate(&stores).is_err());
        }
        let before = good.digest(&stores).unwrap();
        let mut changed = good.clone();
        changed.runtime_profile.controller_code = Digest::new(b"other-code");
        assert_ne!(before, changed.digest(&stores).unwrap());
        let mut changed = good.clone();
        changed.runtime_profile.app_host_code = Digest::new(b"other-app-host-code");
        assert_ne!(before, changed.digest(&stores).unwrap());
        let mut changed = good.clone();
        changed.runtime_profile.security_shell_code = Digest::new(b"other-shell-code");
        assert_ne!(before, changed.digest(&stores).unwrap());
        let mut changed = good.clone();
        changed.runtime_profile.app_artifact = Digest::new(b"other-artifact");
        assert_ne!(before, changed.digest(&stores).unwrap());
        let mut changed = good.clone();
        changed.runtime_profile.manifest = Digest::new(b"other-profile");
        assert_ne!(before, changed.digest(&stores).unwrap());
        let mut changed = good.clone();
        changed.shell.container.image = Digest::new(b"other-shell-image");
        assert_ne!(before, changed.digest(&stores).unwrap());
        let mut changed = good.clone();
        changed.shell.container.name = "other-container".into();
        assert_ne!(before, changed.digest(&stores).unwrap());
        assert!(good.validate(&BTreeMap::new()).is_err());
    }

    #[test]
    fn native_role_selects_its_exact_workload_executable_and_profile() {
        let mut policy = selection(&super::super::tests::selection(), "epoch");
        for (role, workload, code, wire) in [
            (
                NativeRole::AppHost,
                &policy.app,
                &policy.runtime_profile.app_host_code,
                "app_host",
            ),
            (
                NativeRole::SecurityShell,
                &policy.shell,
                &policy.runtime_profile.security_shell_code,
                "security_shell",
            ),
            (
                NativeRole::EpochController,
                &policy.controller,
                &policy.runtime_profile.controller_code,
                "epoch_controller",
            ),
        ] {
            let selected = policy.native_role(role);
            assert_eq!(selected.role, role);
            assert_eq!(selected.workload, workload);
            assert_eq!(selected.code, code);
            assert_ne!(selected.code, &policy.runtime_profile.app_artifact);
            assert_eq!(selected.profile, &policy.runtime_profile.manifest);
            assert_eq!(serde_json::to_value(role).unwrap(), json!(wire));
        }
        assert!(serde_json::from_value::<NativeRole>(json!("app")).is_err());
        // Both native modes may use the same executable. Code equality cannot
        // replace the distinct selected workload/container or enrolled role.
        policy.runtime_profile.security_shell_code = policy.runtime_profile.app_host_code.clone();
        let app = policy.native_role(NativeRole::AppHost);
        let shell = policy.native_role(NativeRole::SecurityShell);
        assert_eq!(app.code, shell.code);
        assert_ne!(app.role, shell.role);
        assert_ne!(app.workload, shell.workload);
    }

    #[test]
    fn desired_contract_rejects_generated_proof_and_unsupported_profiles() {
        let good =
            serde_json::to_value(selection(&super::super::tests::selection(), "epoch")).unwrap();
        for pointer in [
            "/shell",
            "/app/container",
            "/shell/container",
            "/controller/container",
            "/runtime_profile/controller_code",
            "/runtime_profile/app_host_code",
            "/runtime_profile/security_shell_code",
            "/runtime_profile/app_artifact",
            "/runtime_profile/manifest",
        ] {
            let mut bad = good.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                serde_json::from_value::<InitialBootstrapPolicy>(bad).is_err(),
                "{pointer}"
            );
        }
        for (pointer, value) in [
            ("/ready", json!(true)),
            ("/process_incarnation", json!("process")),
            ("/runtime_profile/deadline", json!(5)),
            ("/runtime_profile/kind", json!("local_sqlite")),
            ("/shell/enrolled", json!(true)),
            ("/control_store/namespace", json!("replacement-slots")),
            (
                "/fresh_storage/marker",
                json!(Digest::new(b"generated-marker")),
            ),
        ] {
            let mut bad = good.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), value);
            assert!(
                serde_json::from_value::<InitialBootstrapPolicy>(bad).is_err(),
                "{pointer}"
            );
        }
        for name in ["", "-shell", "shell-", "Shell", "shell.other"] {
            let mut bad: InitialBootstrapPolicy = serde_json::from_value(good.clone()).unwrap();
            bad.shell.container.name = name.into();
            assert!(bad.shell.validate().is_err(), "{name}");
        }
        for origin in [
            "http://10.0.0.1",
            "https://user@host",
            "https://host/path",
            "https://host?query",
            "https://host:0",
        ] {
            let mut bad: InitialBootstrapPolicy = serde_json::from_value(good.clone()).unwrap();
            bad.cluster.api_origin = origin.into();
            assert!(bad.cluster.validate().is_err(), "{origin}");
        }
    }
}
