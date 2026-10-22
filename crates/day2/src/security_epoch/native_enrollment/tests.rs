use super::{
    policy::decode_key,
    protocol::{self, KeyOwner},
};
use super::{
    policy::{EnrollmentPolicy, RuntimeSelection},
    protocol::{IssuerCertificate, IssuerData, ProcessData},
};
use day2_capabilities::Digest;

pub(super) fn policy(root: &KeyOwner) -> EnrollmentPolicy {
    let store = crate::security_epoch::tests::selection();
    let bootstrap = crate::security_epoch::control_slot_tests::policy(&store);
    EnrollmentPolicy {
        bootstrap,
        store,
        root: super::root_kms::KmsRootSelection {
            version: "projects/test-project/locations/us-central1/keyRings/enrollment/cryptoKeys/root/cryptoKeyVersions/1".into(),
            public_key: root.public(),
        },
        provisioner_code: Digest::new(b"provisioner"),
        issuer_code: Digest::new(b"issuer"),
        runtime: RuntimeSelection {
            containerd_code: Digest::new(b"containerd"),
            containerd_version: "v2.2.0".into(),
            containerd_revision: "selected-revision".into(),
            cri_version: "v1".into(),
            node_name: "node-one".into(),
            node_uid: "node-uid".into(),
            kernel_release: "6.12.0".into(),
            architecture: "arm64".into(),
        },
    }
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
fn runtime_revision_may_be_explicitly_empty_but_cannot_be_omitted_or_normalized() {
    let root = KeyOwner::generate().unwrap();
    let mut selected = policy(&root);
    selected.runtime.containerd_version = "2.1.5-0ubuntu0~24.04.1~gke1".into();
    selected.runtime.containerd_revision.clear();
    selected.validate().unwrap();
    let empty_revision = selected.digest().unwrap();
    let mut encoded = serde_json::to_value(&selected).unwrap();
    let decoded: EnrollmentPolicy =
        crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert_eq!(decoded, selected);
    encoded["runtime"]
        .as_object_mut()
        .unwrap()
        .remove("containerd_revision");
    assert!(
        crate::json::decode::<EnrollmentPolicy>(&serde_json::to_vec(&encoded).unwrap()).is_err()
    );

    selected.runtime.containerd_revision = "selected-revision".into();
    assert_ne!(selected.digest().unwrap(), empty_revision);
    for revision in [" ".to_owned(), "\n".to_owned(), "x".repeat(254)] {
        selected.runtime.containerd_revision = revision;
        assert!(selected.validate().is_err());
    }
    selected.runtime.containerd_revision.clear();
    selected.runtime.containerd_version.clear();
    assert!(selected.validate().is_err());
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
        root_version: selected.root.version.clone(),
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
            "root" => policy.root.public_key = KeyOwner::generate().unwrap().public(),
            "version" => policy.root.version = policy.root.version.replace("/1", "/2"),
            "scope" => policy.bootstrap.scope.app = serde_json::from_str("\"other\"").unwrap(),
            "code" => policy.issuer_code = Digest::new(b"replacement"),
            "profile" => {
                policy.bootstrap.runtime_profile.manifest = Digest::new(b"replacement-profile")
            }
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

#[test]
fn role_bind_signature_and_packet_require_the_exact_closed_stage_purpose() {
    use super::{
        NativeRole,
        protocol::{Packet, StagePurpose},
    };
    let key = KeyOwner::generate().unwrap();
    let policy = Digest::new(b"policy");
    let request = Digest::new(b"request");
    let challenge = Digest::new(b"challenge");
    let public = key.public();
    let binding = (
        &policy,
        NativeRole::AppHost,
        StagePurpose::InitialFirstHolder,
        &public,
        &request,
        &challenge,
    );
    let signature = key.sign("role-bind", &binding).unwrap();
    protocol::verify(&public, "role-bind", &binding, &signature).unwrap();
    let other = (
        &policy,
        NativeRole::AppHost,
        StagePurpose::CurrentRole,
        &public,
        &request,
        &challenge,
    );
    assert!(protocol::verify(&public, "role-bind", &other, &signature).is_err());
    let packet = Packet::StageHello {
        policy,
        role: NativeRole::AppHost,
        purpose: StagePurpose::InitialFirstHolder,
        public_key: public,
        request,
    };
    let bytes = serde_json::to_vec(&packet).unwrap();
    assert!(protocol::decode(&bytes).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("purpose");
    assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["purpose"] = serde_json::json!("any_stage");
    assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}
