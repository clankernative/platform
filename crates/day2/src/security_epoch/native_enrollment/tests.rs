use super::{
    policy::decode_key,
    protocol::{self, KeyOwner},
};
use super::{
    policy::{EnrollmentPolicy, RuntimeSelection},
    protocol::{IssuerCertificate, IssuerData, ProcessData},
};
use day2_capabilities::Digest;

fn policy(root: &KeyOwner) -> EnrollmentPolicy {
    let store = crate::security_epoch::tests::selection();
    let role: day2_capabilities::security_epoch::bootstrap::GkeRoleSelection = serde_json::from_value(serde_json::json!({"namespace":{"name":"native","uid":"namespace-uid"},"kubernetes_service_account":{"name":"host","uid":"ksa-uid"},"google_service_account":{"kind":"gke_workload_identity_v1","service_account":"host@project-seven.iam.gserviceaccount.com","service_account_uid":"100000000000000000007"},"workload_kind":"deployment_v1","workload":{"name":"host","uid":"deployment-uid"},"token_review_audience":"native-role"})).unwrap();
    EnrollmentPolicy {scope: store.scope.clone(), root_version: "root-one".into(), root_public_key: root.public(), provisioner_code: Digest::new(b"provisioner"), issuer_code: Digest::new(b"issuer"), app_host_code: Digest::new(b"app"), security_shell_code: Digest::new(b"shell"), controller_code: Digest::new(b"controller"), profile: Digest::new(b"profile"), runtime: RuntimeSelection {
        cluster: serde_json::from_value(serde_json::json!({"project":"project-seven","location":"us-central1","name":"native","uid":"cluster-uid","api_origin":"https://127.0.0.1","certificate_authority":Digest::new(b"ca")})).unwrap(),
        store, controller: role.clone(), controller_container: crate::security_epoch::runtime_profile::ContainerSelection {name: "controller".into(), image: Digest::new(b"controller-image")}, app: role, app_container: crate::security_epoch::runtime_profile::ContainerSelection {name: "app".into(), image: Digest::new(b"image")},
        shell: serde_json::from_value(serde_json::json!({"namespace":{"name":"shell","uid":"shell-ns"},"kubernetes_service_account":{"name":"shell","uid":"shell-ksa"},"google_service_account":{"kind":"gke_workload_identity_v1","service_account":"shell@project-seven.iam.gserviceaccount.com","service_account_uid":"100000000000000000008"},"workload_kind":"deployment_v1","workload":{"name":"shell","uid":"shell-workload"},"token_review_audience":"native-shell"})).unwrap(),
        shell_container: crate::security_epoch::runtime_profile::ContainerSelection {name: "shell".into(), image: Digest::new(b"shell-image")}, containerd_code: Digest::new(b"containerd"), containerd_version: "v2.2.0".into(), containerd_revision: "selected-revision".into(), cri_version: "v1".into(), node_name: "node-one".into(), node_uid: "node-uid".into(), kernel_release: "6.12.0".into(), architecture: "arm64".into(),
    }}
}

fn process(code: Digest) -> ProcessData {
    ProcessData {
        process: 71,
        start_ticks: 123,
        code,
        boot: "boot-one".into(),
        namespaces: ["time", "time_for_children", "pid", "mnt", "user", "cgroup"]
            .into_iter()
            .map(|name| (name.to_owned(), (7, 9)))
            .collect(),
    }
}

#[test]
fn signatures_are_purpose_and_value_bound_and_canonical() {
    let key = KeyOwner::generate().unwrap();
    let signature = key.sign("birth", &"one").unwrap();
    protocol::verify(&key.public(), "birth", &"one", &signature).unwrap();
    assert!(protocol::verify(&key.public(), "stage", &"one", &signature).is_err());
    assert!(protocol::verify(&key.public(), "birth", &"two", &signature).is_err());
    assert!(decode_key(&(key.public() + "=")).is_err());
    assert!(protocol::verify(&key.public(), "birth", &"one", &(signature + "=")).is_err());
}

#[test]
fn packet_parser_refuses_duplicate_unknown_and_oversized_fields() {
    assert!(
        protocol::decode(br#"{"kind":"birth_challenge","policy":"x","policy":"y","nonce":"z"}"#)
            .is_err()
    );
    assert!(protocol::decode(br#"{"kind":"birth_grant","unexpected":true}"#).is_err());
    assert!(protocol::decode(&vec![b' '; protocol::MAX_PACKET + 1]).is_err());
}

#[test]
fn issuer_certificate_requires_selected_root_generation_code_and_company() {
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let selected = policy(&root);
    let data = IssuerData {
        policy: selected.digest().unwrap(),
        root_version: selected.root_version.clone(),
        nonce: Digest::new(b"original-birth"),
        public_key: issuer.public(),
        process: process(selected.issuer_code.clone()),
        provisioner: process(selected.provisioner_code.clone()),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    };
    certificate.verify(&selected).unwrap();
    for changed in ["root", "version", "scope", "code", "profile"] {
        let mut policy = selected.clone();
        match changed {
            "root" => policy.root_public_key = KeyOwner::generate().unwrap().public(),
            "version" => policy.root_version = "root-two".into(),
            "scope" => policy.scope.app = serde_json::from_str("\"other\"").unwrap(),
            "code" => policy.issuer_code = Digest::new(b"replacement"),
            "profile" => policy.profile = Digest::new(b"replacement-profile"),
            _ => unreachable!(),
        }
        assert!(certificate.verify(&policy).is_err(), "{changed}");
    }
    let mut changed = certificate.clone();
    changed.data.nonce = Digest::new(b"different-birth");
    assert!(changed.verify(&selected).is_err());
    let mut changed = certificate;
    changed.data.process.start_ticks += 1;
    assert!(changed.verify(&selected).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_never_installs_a_role_or_replaces_the_clock() {
    let scope = crate::security_epoch::tests::selection().scope;
    assert!(
        super::EnrolledProcessRoleOwner::enroll_current_thread(&scope, super::NativeRole::AppHost)
            .is_err()
    );
    assert!(super::run(false).is_err());
}
