//! Generated cryptographic DATA controls only. No real native process, stage,
//! message pidfd, original file, P3 or first-holder owner is constructed here.

use super::*;
use crate::security_epoch::{
    native_enrollment::{
        protocol::{IssuerData, KeyOwner, RuntimeBinding, StageData},
        tests::policy,
    },
    runtime_profile::ContainerFacts,
};
use std::collections::BTreeMap;

fn process(code: Digest, process: u32) -> ProcessData {
    ProcessData {
        process,
        start_ticks: u64::from(process) + 100,
        code,
        boot: "fixture-boot".into(),
        namespaces: BTreeMap::from([("time".into(), (7, 9))]),
    }
}

fn fixture(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner) {
    let (policy, statement, key, _issuer) = fixture_with_issuer(role);
    (policy, statement, key)
}

fn fixture_with_issuer(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner, KeyOwner) {
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let key = KeyOwner::generate().unwrap();
    let policy = policy(&root);
    let data = IssuerData {
        policy: policy.digest().unwrap(),
        root_version: policy.root.version.clone(),
        nonce: Digest::new(b"fixture-issuer-generation"),
        public_key: issuer.public(),
        process: process(policy.issuer_code.clone(), 70),
        provisioner: process(policy.provisioner_code.clone(), 71),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    };
    let data = StageData {
        issuer: certificate.digest().unwrap(),
        policy: policy.digest().unwrap(),
        role,
        public_key: key.public(),
        challenge: Digest::new(b"fixture-role-challenge"),
        request: Digest::new(b"fixture-role-request"),
        process: process(policy.code(role).clone(), 80),
        runtime: RuntimeBinding {
            container: ContainerFacts {
                pod_name: "app".into(),
                pod_uid: "pod-uid".into(),
                node_name: "node-one".into(),
                container_name: "app".into(),
                container_id: "a".repeat(64),
                image: Digest::new(b"app-image"),
                restart_count: 0,
            },
            node_uid: "node-uid".into(),
            boot: "fixture-boot".into(),
        },
        origin_ns: 100_000_000_000,
        deadline_ns: 105_000_000_000,
    };
    let stage = SignedStage {
        signature: issuer.sign("role-stage", &data).unwrap(),
        data,
    };
    (
        policy,
        StageStatement {
            certificate,
            stage,
            original: OriginalInterval {
                domain: Digest::new(b"actual-domain-would-come-from-native-stage"),
                origin_ns: 100_000_000_000,
                deadline_ns: 105_000_000_000,
            },
        },
        key,
        issuer,
    )
}

fn signed(statement: &StageStatement, key: &KeyOwner, body: Body) -> Message {
    let sender = statement.digest().unwrap();
    let signature = key
        .sign("initial-storage-message", &(&sender, &body))
        .unwrap();
    Message {
        sender,
        body,
        signature,
    }
}

#[test]
fn stage_data_requires_the_same_issuer_role_process_and_live_original_interval() {
    let (policy, stage, _key) = fixture(NativeRole::AppHost);
    let now = Duration::from_secs(102);
    stage
        .validate(
            &policy,
            &stage.certificate,
            NativeRole::AppHost,
            &stage.stage.data.process,
            now,
        )
        .unwrap();
    for role in [NativeRole::EpochController, NativeRole::SecurityShell] {
        assert!(
            stage
                .validate(
                    &policy,
                    &stage.certificate,
                    role,
                    &stage.stage.data.process,
                    now
                )
                .is_err()
        );
    }
    let mut process = stage.stage.data.process.clone();
    process.start_ticks += 1;
    assert!(
        stage
            .validate(
                &policy,
                &stage.certificate,
                NativeRole::AppHost,
                &process,
                now
            )
            .is_err()
    );
    let mut issuer = stage.certificate.clone();
    issuer.data.nonce = Digest::new(b"replacement-issuer");
    assert!(
        stage
            .validate(
                &policy,
                &issuer,
                NativeRole::AppHost,
                &stage.stage.data.process,
                now
            )
            .is_err()
    );
    for time in [Duration::from_secs(99), Duration::from_secs(105)] {
        assert!(
            stage
                .validate(
                    &policy,
                    &stage.certificate,
                    NativeRole::AppHost,
                    &stage.stage.data.process,
                    time
                )
                .is_err()
        );
    }
    let mut changed = stage.clone();
    changed.original.deadline_ns += 1;
    assert!(
        changed
            .validate(
                &policy,
                &stage.certificate,
                NativeRole::AppHost,
                &stage.stage.data.process,
                now
            )
            .is_err()
    );
    let mut changed = stage.clone();
    changed.stage.data.public_key = KeyOwner::generate().unwrap().public();
    assert!(
        changed
            .validate(
                &policy,
                &stage.certificate,
                NativeRole::AppHost,
                &stage.stage.data.process,
                now
            )
            .is_err()
    );
}

#[test]
fn storage_messages_bind_original_stage_nonce_step_and_projection() {
    let (_policy, stage, key) = fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::Hello {
            app: Box::new(stage.clone()),
            nonce: Digest::new(b"app-nonce"),
        },
    );
    hello.verify(&stage).unwrap();
    let mut encoded = serde_json::to_value(&hello).unwrap();
    encoded["body"]["nonce"] = serde_json::to_value(Digest::new(b"other-nonce")).unwrap();
    let changed: Message = crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed.verify(&stage).is_err());
    let mut original = stage.clone();
    original.original.domain = Digest::new(b"replacement-acquisition");
    assert!(hello.verify(&original).is_err());
    let confirm = signed(
        &stage,
        &key,
        Body::Confirm {
            exchange: Digest::new(b"exchange"),
            projection: Digest::new(b"actual-file"),
        },
    );
    confirm.verify(&stage).unwrap();
    let mut encoded = serde_json::to_value(&confirm).unwrap();
    encoded["body"]["projection"] = serde_json::to_value(Digest::new(b"foreign-file")).unwrap();
    let changed: Message = crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed.verify(&stage).is_err());
    let wrong_role = signed(
        &stage,
        &key,
        Body::Complete {
            exchange: Digest::new(b"exchange"),
        },
    );
    assert!(wrong_role.verify(&stage).is_err());
    let mut encoded = serde_json::to_value(&confirm).unwrap();
    encoded["body"] = serde_json::json!({"step":"accepted","exchange":Digest::new(b"exchange")});
    let changed: Message = crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed.verify(&stage).is_err());
}

#[test]
fn transcript_changes_do_not_alias_another_exchange() {
    let exchange = Exchange {
        app_stage: Digest::new(b"app"),
        controller_stage: Digest::new(b"controller"),
        app_nonce: Digest::new(b"app-nonce"),
        controller_nonce: Digest::new(b"controller-nonce"),
        projection: Digest::new(b"projection"),
    };
    for field in [
        "app_stage",
        "controller_stage",
        "app_nonce",
        "controller_nonce",
        "projection",
    ] {
        let mut value = serde_json::to_value(&exchange).unwrap();
        value[field] = serde_json::to_value(Digest::new(b"different")).unwrap();
        let changed: Exchange = crate::json::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_ne!(exchange.digest().unwrap(), changed.digest().unwrap());
    }
}

#[test]
fn storage_wire_refuses_duplicate_unknown_array_and_oversized_records() {
    let (_policy, stage, key) = fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::Hello {
            app: Box::new(stage.clone()),
            nonce: Digest::new(b"nonce"),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    decode(&encoded).unwrap().verify(&stage).unwrap();
    assert!(decode(br#"{"sender":"x","sender":"y","body":{},"signature":"x"}"#).is_err());
    assert!(decode(&vec![b' '; protocol::MAX_PACKET + 1]).is_err());
    let original = serde_json::to_value(&hello).unwrap();
    for path in [
        "/body",
        "/body/app",
        "/body/app/certificate",
        "/body/app/certificate/data",
        "/body/app/stage",
        "/body/app/stage/data",
        "/body/app/stage/data/runtime",
        "/body/app/original",
    ] {
        let mut changed = original.clone();
        let record = changed.pointer(path).unwrap().as_object().unwrap();
        let sequence = record.values().cloned().collect::<Vec<_>>();
        *changed.pointer_mut(path).unwrap() = serde_json::Value::Array(sequence);
        assert!(
            decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted sequence at {path}"
        );
    }
    let mut changed = original;
    changed["body"]["app"]["original"]["unexpected"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
}

#[test]
fn privileged_controller_attestation_is_role_and_actual_kernel_sender_bound_data() {
    let (policy, controller, key) = fixture(NativeRole::EpochController);
    let now = Duration::from_secs(102);
    controller
        .validate_attested_controller(
            &policy,
            &controller.certificate,
            controller.stage.data.process.process,
            now,
        )
        .unwrap();
    assert!(
        controller
            .validate_attested_controller(
                &policy,
                &controller.certificate,
                controller.stage.data.process.process + 1,
                now
            )
            .is_err()
    );
    let complete = signed(
        &controller,
        &key,
        Body::Complete {
            exchange: Digest::new(b"exchange"),
        },
    );
    complete.verify(&controller).unwrap();
    let (policy, app, _key) = fixture(NativeRole::AppHost);
    assert!(
        app.validate_attested_controller(
            &policy,
            &app.certificate,
            app.stage.data.process.process,
            now
        )
        .is_err()
    );
}

#[test]
fn retained_identity_data_does_not_make_an_expired_grant_current() {
    let (policy, old, key, issuer) = fixture_with_issuer(NativeRole::AppHost);
    let mut fresh = old.clone();
    fresh.stage.data.origin_ns += 10_000_000_000;
    fresh.stage.data.deadline_ns += 10_000_000_000;
    fresh.stage.data.challenge = Digest::new(b"fresh-current-issuer-challenge");
    fresh.stage.data.request = Digest::new(b"fresh-current-role-request");
    fresh.stage.signature = issuer.sign("role-stage", &fresh.stage.data).unwrap();
    fresh.original.origin_ns += 10_000_000_000;
    fresh.original.deadline_ns += 10_000_000_000;
    fresh.original.domain = Digest::new(b"new-original-acquisition");
    assert!(old.same_enrollment(&fresh));
    let now = Duration::from_secs(112);
    assert!(
        old.validate(
            &policy,
            &old.certificate,
            NativeRole::AppHost,
            &old.stage.data.process,
            now
        )
        .is_err()
    );
    fresh
        .validate(
            &policy,
            &old.certificate,
            NativeRole::AppHost,
            &old.stage.data.process,
            now,
        )
        .unwrap();
    let hello = signed(
        &fresh,
        &key,
        Body::CurrentHello {
            app: Box::new(fresh.clone()),
            initial: Digest::new(b"original-known-exchange"),
            sequence: 1,
            request: StoragePeerRequest {
                purpose: StoragePeerPurpose::BootstrapCreate,
                binding: Digest::new(b"exact-request"),
            },
            nonce: Digest::new(b"fresh-app-nonce"),
        },
    );
    hello.verify(&fresh).unwrap();
    assert!(hello.verify(&old).is_err());
    for path in [
        "/certificate/data/nonce",
        "/stage/data/public_key",
        "/stage/data/process/code",
        "/stage/data/runtime/container/image",
    ] {
        let mut changed = serde_json::to_value(&fresh).unwrap();
        *changed.pointer_mut(path).unwrap() =
            serde_json::to_value(Digest::new(b"changed")).unwrap();
        if path.ends_with("public_key") {
            *changed.pointer_mut(path).unwrap() =
                serde_json::json!(KeyOwner::generate().unwrap().public());
        }
        let changed: StageStatement =
            crate::json::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(!old.same_enrollment(&changed), "identity changed at {path}");
    }
}

#[test]
fn current_exchange_binds_sequence_purpose_request_and_both_fresh_grants() {
    let exchange = CurrentExchange {
        initial: Digest::new(b"initial"),
        sequence: 1,
        request: StoragePeerRequest {
            purpose: StoragePeerPurpose::CurrentServing,
            binding: Digest::new(b"intent-action-body"),
        },
        app_stage: Digest::new(b"current-app-stage"),
        controller_stage: Digest::new(b"current-controller-stage"),
        app_nonce: Digest::new(b"current-app-nonce"),
        controller_nonce: Digest::new(b"current-controller-nonce"),
    };
    for path in [
        "/initial",
        "/app_stage",
        "/controller_stage",
        "/app_nonce",
        "/controller_nonce",
        "/request/binding",
        "/request/purpose",
        "/sequence",
    ] {
        let mut changed = serde_json::to_value(&exchange).unwrap();
        *changed.pointer_mut(path).unwrap() = match path {
            "/sequence" => serde_json::json!(2),
            "/request/purpose" => serde_json::json!("bootstrap_complete"),
            _ => serde_json::to_value(Digest::new(b"changed")).unwrap(),
        };
        let changed: CurrentExchange =
            crate::json::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_ne!(
            exchange.digest().unwrap(),
            changed.digest().unwrap(),
            "unbound {path}"
        );
    }
}

#[test]
fn current_wire_stays_closed_and_rejects_nested_arrays_and_unknown_fields() {
    let (_policy, stage, key) = fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::CurrentHello {
            app: Box::new(stage.clone()),
            initial: Digest::new(b"initial"),
            sequence: 1,
            request: StoragePeerRequest {
                purpose: StoragePeerPurpose::BootstrapCreate,
                binding: Digest::new(b"request"),
            },
            nonce: Digest::new(b"nonce"),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    decode(&encoded).unwrap().verify(&stage).unwrap();
    for path in [
        "/body/request",
        "/body/app/stage/data",
        "/body/app/original",
    ] {
        let mut changed = serde_json::to_value(&hello).unwrap();
        let values = changed
            .pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        *changed.pointer_mut(path).unwrap() = serde_json::Value::Array(values);
        assert!(
            decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted array {path}"
        );
    }
    let mut changed = serde_json::to_value(&hello).unwrap();
    changed["body"]["request"]["extra"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = serde_json::to_value(&hello).unwrap();
    changed["body"]["sequence"] = serde_json::json!("1");
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
}
