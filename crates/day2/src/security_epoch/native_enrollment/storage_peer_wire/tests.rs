//! Generated cryptographic DATA controls only. No real native process, stage,
//! message pidfd, original file, P3 or first-holder owner is constructed here.

use super::*;

#[test]
fn current_hello_selects_the_queued_ready_and_exact_request_even_when_validly_signed() {
    let (_, app, key) = fixture(NativeRole::AppHost);
    let initial = Digest::new(b"one retained peer");
    let ready_nonce = Digest::new(b"one controller ready");
    let request = StoragePeerRequest {
        purpose: StoragePeerPurpose::CurrentServing,
        binding: Digest::new(b"actual consumer"),
    };
    let hello = signed(
        &app,
        &key,
        Body::CurrentHello {
            app: Box::new(app.clone()),
            initial: initial.clone(),
            sequence: 1,
            request: request.clone(),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: ready_nonce.clone(),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    let decoded = decode(&encoded).unwrap();
    decoded.verify(&app).unwrap();
    decoded
        .current_hello(&initial, 1, &ready_nonce, None)
        .unwrap();
    decoded
        .current_hello(&initial, 1, &ready_nonce, Some(&request))
        .unwrap();
    assert!(
        decoded
            .current_hello(&initial, 1, &Digest::new(b"other ready"), None)
            .is_err()
    );
    assert!(
        decoded
            .current_hello(&initial, 2, &ready_nonce, None)
            .is_err()
    );
    assert!(
        decoded
            .current_hello(&Digest::new(b"other original"), 1, &ready_nonce, None)
            .is_err()
    );
    let foreign = StoragePeerRequest {
        purpose: request.purpose,
        binding: Digest::new(b"another consumer"),
    };
    assert!(
        decoded
            .current_hello(&initial, 1, &ready_nonce, Some(&foreign))
            .is_err()
    );
    let bootstrap = StoragePeerRequest {
        purpose: StoragePeerPurpose::BootstrapCreate,
        binding: request.binding.clone(),
    };
    let wrong_purpose = signed(
        &app,
        &key,
        Body::CurrentHello {
            app: Box::new(app.clone()),
            initial: initial.clone(),
            sequence: 1,
            request: bootstrap.clone(),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: ready_nonce.clone(),
        },
    );
    assert!(wrong_purpose.verify(&app).is_err());
    assert!(
        wrong_purpose
            .current_hello(&initial, 1, &ready_nonce, None)
            .is_err()
    );
    assert!(
        wrong_purpose
            .current_hello(&initial, 1, &ready_nonce, Some(&bootstrap))
            .is_err()
    );
    let mut missing = serde_json::to_value(&hello).unwrap();
    missing["body"]
        .as_object_mut()
        .unwrap()
        .remove("controller_nonce");
    assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
}

#[test]
fn current_begin_ready_cannot_be_replaced_by_a_later_grant_clock_or_nonce() {
    let (_, controller, key, issuer) = fixture_with_issuer(NativeRole::EpochController);
    let nonce = Digest::new(b"one current ready");
    let initial = Digest::new(b"original peer");
    let ready = signed(
        &controller,
        &key,
        Body::CurrentBeginReady {
            controller: Box::new(controller.clone()),
            initial: initial.clone(),
            sequence: 1,
            nonce: nonce.clone(),
        },
    );
    let bytes = serde_json::to_vec(&ready).unwrap();
    decode(&bytes).unwrap().verify(&controller).unwrap();
    let exchange = CurrentExchange {
        initial,
        sequence: 1,
        request: StoragePeerRequest {
            purpose: StoragePeerPurpose::CurrentServing,
            binding: Digest::new(b"consumer"),
        },
        app_stage: Digest::new(b"fresh app stage"),
        controller_stage: controller.digest().unwrap(),
        app_nonce: Digest::new(b"fresh app nonce"),
        controller_nonce: nonce.clone(),
    };
    exchange
        .require_begin_ready(&controller, &nonce, &controller)
        .unwrap();
    let mut replacement = controller.clone();
    replacement.stage.data.challenge = Digest::new(b"later role grant");
    replacement.stage.signature = issuer.sign("role-stage", &replacement.stage.data).unwrap();
    assert!(replacement.same_enrollment(&controller));
    assert!(
        exchange
            .require_begin_ready(&controller, &nonce, &replacement)
            .is_err()
    );
    let mut replacement = controller.clone();
    replacement.original.origin_ns += 1;
    assert!(
        exchange
            .require_begin_ready(&controller, &nonce, &replacement)
            .is_err()
    );
    assert!(
        exchange
            .require_begin_ready(&controller, &Digest::new(b"different ready"), &controller)
            .is_err()
    );
    assert!(
        controller
            .require_new_grant(&controller.grant_digest().unwrap())
            .is_err()
    );
    let original = serde_json::to_value(&ready).unwrap();
    for path in [
        "/body/controller",
        "/body/controller/stage",
        "/body/controller/original",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = serde_json::json!([]);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    for field in ["initial", "sequence", "nonce"] {
        let mut changed = original.clone();
        changed["body"].as_object_mut().unwrap().remove(field);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1");
    assert!(decode(duplicate.as_bytes()).is_err());
}
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

#[test]
fn app_holder_candidate_keeps_pod_process_and_key_identities_separate() {
    let (_, mut statement, _) = fixture(NativeRole::AppHost);
    assert!(statement.app_holder().is_err()); // fixture's non-UUID Pod is not admitted
    statement.stage.data.runtime.container.pod_uid = "a6b27e63-16d8-4b99-92f6-2437e5b20f43".into();
    let original = statement.app_holder().unwrap();
    let mut changed = statement.clone();
    changed.stage.data.challenge = Digest::new(b"another-grant-challenge");
    assert_eq!(changed.app_holder().unwrap(), original);
    changed.stage.data.process.start_ticks += 1;
    let process = changed.app_holder().unwrap();
    assert_ne!(process.process_incarnation, original.process_incarnation);
    assert_eq!(process.principal, original.principal);
    assert_eq!(process.ephemeral_key, original.ephemeral_key);
    let mut changed = statement.clone();
    changed.stage.data.public_key = KeyOwner::generate().unwrap().public();
    let key = changed.app_holder().unwrap();
    assert_ne!(key.ephemeral_key, original.ephemeral_key);
    assert_eq!(key.principal, original.principal);
    let mut changed = statement.clone();
    changed.stage.data.runtime.container.pod_uid = "b6b27e63-16d8-4b99-92f6-2437e5b20f43".into();
    let pod = changed.app_holder().unwrap();
    assert_ne!(pod.principal, original.principal);
    assert_ne!(pod.process_incarnation, original.process_incarnation);
    statement.stage.data.role = NativeRole::EpochController;
    assert!(statement.app_holder().is_err());
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
        purpose: StagePurpose::CurrentRole,
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
            StagePurpose::CurrentRole,
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
                    now,
                    StagePurpose::CurrentRole,
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
                now,
                StagePurpose::CurrentRole,
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
                now,
                StagePurpose::CurrentRole,
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
                    time,
                    StagePurpose::CurrentRole,
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
                now,
                StagePurpose::CurrentRole,
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
                now,
                StagePurpose::CurrentRole,
            )
            .is_err()
    );
}

#[test]
fn storage_messages_bind_original_stage_nonce_step_and_projection() {
    let (_policy, stage, key) = initial_fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::Hello {
            app: Box::new(stage.clone()),
            nonce: Digest::new(b"app-nonce"),
            controller_nonce: Digest::new(b"controller-ready-nonce"),
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
fn initial_ready_requires_a_controller_signature_and_closed_record_shape() {
    let (_, controller, key) = initial_fixture(NativeRole::EpochController);
    let (_, app, _) = initial_fixture(NativeRole::AppHost);
    let ready = signed(
        &controller,
        &key,
        Body::InitialReady {
            controller: Box::new(controller.clone()),
            nonce: Digest::new(b"one ready nonce"),
        },
    );
    let encoded = serde_json::to_vec(&ready).unwrap();
    decode(&encoded).unwrap().verify(&controller).unwrap();
    assert!(decode(&encoded).unwrap().verify(&app).is_err());
    let original = serde_json::to_value(&ready).unwrap();
    for path in [
        "/body/controller",
        "/body/controller/stage",
        "/body/controller/original",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = serde_json::json!([]);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    for replacement in [serde_json::Value::Null, serde_json::json!([])] {
        let mut changed = original.clone();
        changed["body"]["nonce"] = replacement;
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut changed = original.clone();
    changed["body"].as_object_mut().unwrap().remove("nonce");
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = original.clone();
    changed["body"]["unknown"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = original;
    changed["body"]["nonce"] = serde_json::to_value(Digest::new(b"tampered ready")).unwrap();
    assert!(
        decode(&serde_json::to_vec(&changed).unwrap())
            .unwrap()
            .verify(&controller)
            .is_err()
    );
    let duplicate = String::from_utf8(encoded).unwrap().replace(
        "\"step\":\"initial_ready\"",
        &format!(
            "\"step\":\"initial_ready\",\"nonce\":{}",
            serde_json::to_string(&Digest::new(b"duplicate")).unwrap()
        ),
    );
    assert!(decode(duplicate.as_bytes()).is_err());
}

#[test]
fn initial_hello_must_echo_the_ready_nonce_even_with_a_valid_app_signature() {
    let (_, app, key) = initial_fixture(NativeRole::AppHost);
    let nonce = Digest::new(b"controller ready");
    let hello = signed(
        &app,
        &key,
        Body::Hello {
            app: Box::new(app.clone()),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: nonce.clone(),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    let decoded = decode(&encoded).unwrap();
    decoded.verify(&app).unwrap();
    let (selected, _) = decoded.initial_hello(&nonce).unwrap();
    assert!(*selected == app);
    assert!(
        decoded
            .initial_hello(&Digest::new(b"different ready"))
            .is_err()
    );
    let wrong = signed(
        &app,
        &key,
        Body::Hello {
            app: Box::new(app.clone()),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: Digest::new(b"other controller ready"),
        },
    );
    wrong.verify(&app).unwrap();
    assert!(wrong.initial_hello(&nonce).is_err());
    let mut missing = serde_json::to_value(&hello).unwrap();
    missing["body"]
        .as_object_mut()
        .unwrap()
        .remove("controller_nonce");
    assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    let other = signed(
        &app,
        &key,
        Body::Confirm {
            exchange: Digest::new(b"not hello"),
            projection: Digest::new(b"no projection"),
        },
    );
    assert!(other.initial_hello(&nonce).is_err());
}

#[test]
fn first_offer_cannot_replace_the_ready_stage_clock_or_nonce() {
    let (_, ready, _, issuer) = initial_fixture_with_issuer(NativeRole::EpochController);
    let nonce = Digest::new(b"controller ready nonce");
    let exchange = Exchange {
        app_stage: Digest::new(b"app stage"),
        controller_stage: ready.digest().unwrap(),
        app_nonce: Digest::new(b"app nonce"),
        controller_nonce: nonce.clone(),
        projection: Digest::new(b"initial image"),
    };
    exchange
        .require_initial_ready(&ready, &nonce, &ready)
        .unwrap();
    let mut replacement = ready.clone();
    replacement.stage.data.challenge = Digest::new(b"later issuer grant");
    replacement.stage.signature = issuer.sign("role-stage", &replacement.stage.data).unwrap();
    assert!(ready.same_enrollment(&replacement));
    assert!(
        exchange
            .require_initial_ready(&ready, &nonce, &replacement)
            .is_err()
    );
    let mut changed_clock = ready.clone();
    changed_clock.original.origin_ns += 1;
    assert!(
        exchange
            .require_initial_ready(&ready, &nonce, &changed_clock)
            .is_err()
    );
    let mut changed = exchange.clone();
    changed.controller_nonce = Digest::new(b"other ready nonce");
    assert!(
        changed
            .require_initial_ready(&ready, &nonce, &ready)
            .is_err()
    );
    let mut changed = exchange;
    changed.controller_stage = replacement.digest().unwrap();
    assert!(
        changed
            .require_initial_ready(&ready, &nonce, &ready)
            .is_err()
    );
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
    let (_policy, stage, key) = initial_fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::Hello {
            app: Box::new(stage.clone()),
            nonce: Digest::new(b"nonce"),
            controller_nonce: Digest::new(b"controller-ready-nonce"),
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
    let (policy, controller, key) = initial_fixture(NativeRole::EpochController);
    let now = Duration::from_secs(102);
    controller
        .validate_attested_controller(
            &policy,
            &controller.certificate,
            controller.stage.data.process.process,
            now,
            StagePurpose::InitialFirstHolder,
        )
        .unwrap();
    assert!(
        controller
            .validate_attested_controller(
                &policy,
                &controller.certificate,
                controller.stage.data.process.process + 1,
                now,
                StagePurpose::InitialFirstHolder,
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
    let (policy, app, _key) = initial_fixture(NativeRole::AppHost);
    assert!(
        app.validate_attested_controller(
            &policy,
            &app.certificate,
            app.stage.data.process.process,
            now,
            StagePurpose::InitialFirstHolder,
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
    // A fresh envelope/nonce alone is not a new issuer role grant.
    let mut rewrapped = old.clone();
    rewrapped.original.domain = Digest::new(b"different-envelope-only");
    assert_ne!(old.digest().unwrap(), rewrapped.digest().unwrap());
    assert_eq!(
        old.grant_digest().unwrap(),
        rewrapped.grant_digest().unwrap()
    );
    assert_ne!(old.grant_digest().unwrap(), fresh.grant_digest().unwrap());
    let previous = old.grant_digest().unwrap();
    assert!(old.require_new_grant(&previous).is_err());
    assert!(rewrapped.require_new_grant(&previous).is_err());
    fresh.require_new_grant(&previous).unwrap();
    assert!(
        fresh
            .require_new_grant(&fresh.grant_digest().unwrap())
            .is_err()
    );
    let now = Duration::from_secs(112);
    assert!(
        old.validate(
            &policy,
            &old.certificate,
            NativeRole::AppHost,
            &old.stage.data.process,
            now,
            StagePurpose::CurrentRole,
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
            StagePurpose::CurrentRole,
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
                purpose: StoragePeerPurpose::CurrentServing,
                binding: Digest::new(b"exact-request"),
            },
            nonce: Digest::new(b"fresh-app-nonce"),
            controller_nonce: Digest::new(b"controller-ready"),
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
    let (_policy, stage, key) = bootstrap_fixture(NativeRole::AppHost);
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
            controller_nonce: Digest::new(b"controller-ready"),
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

#[test]
fn phase_result_consumption_and_release_require_the_exact_signed_transcript() {
    let (_, controller, controller_key) = fixture(NativeRole::EpochController);
    let (_, app, app_key) = fixture(NativeRole::AppHost);
    let exchange = Digest::new(b"this-exact-current-native-exchange");
    let foreign = Digest::new(b"other-executor-or-exchange");
    let cases = [
        (
            Body::CurrentResult {
                exchange: exchange.clone(),
            },
            CompletionKind::Result,
            &controller,
            &controller_key,
        ),
        (
            Body::CurrentConsumed {
                exchange: exchange.clone(),
            },
            CompletionKind::Consumed,
            &app,
            &app_key,
        ),
        (
            Body::CurrentReleased {
                exchange: exchange.clone(),
            },
            CompletionKind::Released,
            &controller,
            &controller_key,
        ),
    ];
    for (body, kind, sender, key) in cases {
        let message = signed(sender, key, body);
        let encoded = serde_json::to_vec(&message).unwrap();
        let mut message = decode(&encoded).unwrap();
        message.verify(sender).unwrap();
        assert!(message.body.matches_completion(&exchange, kind));
        assert!(!message.body.matches_completion(&foreign, kind));
        for other in [
            CompletionKind::Result,
            CompletionKind::Consumed,
            CompletionKind::Released,
        ] {
            let expected = matches!(
                (&message.body, other),
                (Body::CurrentResult { .. }, CompletionKind::Result)
                    | (Body::CurrentConsumed { .. }, CompletionKind::Consumed)
                    | (Body::CurrentReleased { .. }, CompletionKind::Released)
            );
            assert_eq!(message.body.matches_completion(&exchange, other), expected);
        }
        for (field, value) in [
            ("unexpected", serde_json::json!(true)),
            ("exchange", serde_json::Value::Null),
            ("step", serde_json::json!("current_unknown")),
        ] {
            let mut changed = serde_json::to_value(&message).unwrap();
            changed["body"][field] = value;
            assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut missing = serde_json::to_value(&message).unwrap();
        missing["body"].as_object_mut().unwrap().remove("exchange");
        assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        let exchange_json = serde_json::to_string(&exchange).unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        let duplicate = encoded.replacen(
            &format!("\"exchange\":{exchange_json}"),
            &format!("\"exchange\":{exchange_json},\"exchange\":{exchange_json}"),
            1,
        );
        assert_ne!(duplicate, encoded);
        assert!(decode(duplicate.as_bytes()).is_err());
        match &mut message.body {
            Body::CurrentResult { exchange }
            | Body::CurrentConsumed { exchange }
            | Body::CurrentReleased { exchange } => *exchange = foreign.clone(),
            _ => unreachable!(),
        }
        assert!(message.verify(sender).is_err());
    }
    let handshake = Body::CurrentReady {
        exchange: exchange.clone(),
    };
    for kind in [
        CompletionKind::Result,
        CompletionKind::Consumed,
        CompletionKind::Released,
    ] {
        assert!(!handshake.matches_completion(&exchange, kind));
    }
    assert!(
        signed(
            &app,
            &app_key,
            Body::CurrentResult {
                exchange: exchange.clone()
            }
        )
        .verify(&app)
        .is_err()
    );
    assert!(
        signed(
            &controller,
            &controller_key,
            Body::CurrentConsumed { exchange }
        )
        .verify(&controller)
        .is_err()
    );
}

fn bootstrap_fixture(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner) {
    let (policy, mut statement, key, issuer) = fixture_with_issuer(role);
    statement.stage.data.purpose = StagePurpose::StorageBootstrap;
    statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
    (policy, statement, key)
}

#[test]
fn bootstrap_request_rejects_valid_ordinary_grant_even_when_both_are_short() {
    for purpose in [
        StoragePeerPurpose::BootstrapCreate,
        StoragePeerPurpose::BootstrapComplete,
    ] {
        let (policy, current, key, issuer) = fixture_with_issuer(NativeRole::AppHost);
        let mut bootstrap = current.clone();
        bootstrap.stage.data.purpose = StagePurpose::StorageBootstrap;
        bootstrap.stage.signature = issuer.sign("role-stage", &bootstrap.stage.data).unwrap();
        bootstrap
            .validate(
                &policy,
                &bootstrap.certificate,
                NativeRole::AppHost,
                &bootstrap.stage.data.process,
                Duration::from_secs(102),
                StagePurpose::StorageBootstrap,
            )
            .unwrap();
        let request = StoragePeerRequest {
            purpose,
            binding: Digest::new(b"fixed-bootstrap-request"),
        };
        let nonce = Digest::new(b"ready");
        let initial = Digest::new(b"initial-peer");
        let body = |statement: &StageStatement| Body::CurrentHello {
            app: Box::new(statement.clone()),
            initial: initial.clone(),
            sequence: 1,
            request: request.clone(),
            nonce: Digest::new(b"app"),
            controller_nonce: nonce.clone(),
        };
        let correct = signed(&bootstrap, &key, body(&bootstrap));
        correct.verify(&bootstrap).unwrap();
        correct
            .current_hello(&initial, 1, &nonce, Some(&request))
            .unwrap();
        assert!(correct.verify(&current).is_err());
        let wrong = signed(&current, &key, body(&current));
        assert!(wrong.verify(&current).is_err());
        assert!(
            wrong
                .current_hello(&initial, 1, &nonce, Some(&request))
                .is_err()
        );
    }
}

#[test]
fn every_current_completion_binds_actual_stage_purpose_and_excludes_metadata() {
    for (role, completion) in [
        (NativeRole::EpochController, CompletionKind::Result),
        (NativeRole::AppHost, CompletionKind::Consumed),
        (NativeRole::EpochController, CompletionKind::Released),
    ] {
        let (_, ordinary, key, issuer) = fixture_with_issuer(role);
        for purpose in [
            StagePurpose::CurrentRole,
            StagePurpose::StorageBootstrap,
            StagePurpose::InitialFirstHolder,
            StagePurpose::StorageMetadataObservation,
        ] {
            let mut statement = ordinary.clone();
            statement.stage.data.purpose = purpose;
            statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
            let exchange = Digest::new(b"exact-purpose-exchange");
            let body = match completion {
                CompletionKind::Result => Body::CurrentResult {
                    exchange: exchange.clone(),
                },
                CompletionKind::Consumed => Body::CurrentConsumed {
                    exchange: exchange.clone(),
                },
                CompletionKind::Released => Body::CurrentReleased {
                    exchange: exchange.clone(),
                },
            };
            let message = signed(&statement, &key, body);
            let permitted = matches!(
                purpose,
                StagePurpose::CurrentRole | StagePurpose::StorageBootstrap
            );
            assert_eq!(message.verify(&statement).is_ok(), permitted);
            if permitted {
                let mut replacement = statement.clone();
                replacement.stage.data.purpose = if purpose == StagePurpose::CurrentRole {
                    StagePurpose::StorageBootstrap
                } else {
                    StagePurpose::CurrentRole
                };
                replacement.stage.signature =
                    issuer.sign("role-stage", &replacement.stage.data).unwrap();
                assert!(message.verify(&replacement).is_err());
                assert!(message.body.matches_completion(&exchange, completion));
            }
        }
    }
}

#[test]
fn metadata_statement_is_not_storage_peer_evidence_even_with_a_valid_short_grant() {
    let (policy, mut statement, _key, issuer) = fixture_with_issuer(NativeRole::EpochController);
    statement.stage.data.purpose = StagePurpose::StorageMetadataObservation;
    statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
    assert!(
        statement
            .validate_attested_controller(
                &policy,
                &statement.certificate,
                statement.stage.data.process.process,
                Duration::from_secs(102),
                StagePurpose::StorageMetadataObservation,
            )
            .is_err()
    );
}

fn initial_fixture(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner) {
    let (policy, statement, key, _) = initial_fixture_with_issuer(role);
    (policy, statement, key)
}

fn initial_fixture_with_issuer(
    role: NativeRole,
) -> (EnrollmentPolicy, StageStatement, KeyOwner, KeyOwner) {
    let (policy, mut statement, key, issuer) = fixture_with_issuer(role);
    statement.stage.data.purpose = StagePurpose::InitialFirstHolder;
    statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
    (policy, statement, key, issuer)
}

#[test]
fn initial_ten_second_grants_never_authorize_current_or_serving_work() {
    use crate::security_epoch::native_clock::INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT;
    use crate::security_epoch::native_enrollment::serving_peer_wire::Statement;
    assert_eq!(StagePurpose::CurrentRole.limit(), Duration::from_secs(5));
    assert_eq!(
        StagePurpose::InitialFirstHolder.limit(),
        INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT
    );
    assert!(
        StagePurpose::InitialFirstHolder
            .require_role(NativeRole::SecurityShell)
            .is_err()
    );
    for role in [NativeRole::AppHost, NativeRole::EpochController] {
        let (policy, mut statement, _, issuer) = initial_fixture_with_issuer(role);
        let deadline = Duration::from_nanos(statement.stage.data.origin_ns)
            + INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT;
        statement.stage.data.deadline_ns = deadline.as_nanos().try_into().unwrap();
        statement.original.deadline_ns = statement.stage.data.deadline_ns;
        statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
        let check = |statement: &StageStatement, now, purpose| {
            statement.validate(
                &policy,
                &statement.certificate,
                role,
                &statement.stage.data.process,
                now,
                purpose,
            )
        };
        check(
            &statement,
            Duration::from_millis(106_300),
            StagePurpose::InitialFirstHolder,
        )
        .unwrap();
        assert!(
            check(
                &statement,
                Duration::from_secs(110),
                StagePurpose::InitialFirstHolder
            )
            .is_err()
        );
        assert!(
            check(
                &statement,
                Duration::from_secs(99),
                StagePurpose::InitialFirstHolder
            )
            .is_err()
        );
        assert!(
            check(
                &statement,
                Duration::from_secs(102),
                StagePurpose::CurrentRole
            )
            .is_err()
        );
        let serving = Statement {
            certificate: statement.certificate.clone(),
            stage: statement.stage.clone(),
            original: statement.original.clone(),
        };
        assert!(
            serving
                .validate(
                    &policy,
                    &statement.certificate,
                    role,
                    statement.stage.data.process.process,
                    Some(&statement.stage.data.process),
                    Duration::from_secs(102)
                )
                .is_err()
        );
        // Even a correctly signed CurrentRole cannot acquire a ten-second span.
        let mut ordinary = statement.clone();
        ordinary.stage.data.purpose = StagePurpose::CurrentRole;
        ordinary.stage.signature = issuer.sign("role-stage", &ordinary.stage.data).unwrap();
        assert!(
            check(
                &ordinary,
                Duration::from_secs(102),
                StagePurpose::CurrentRole
            )
            .is_err()
        );
        let mut over = statement.clone();
        over.stage.data.deadline_ns += 1;
        over.original.deadline_ns += 1;
        over.stage.signature = issuer.sign("role-stage", &over.stage.data).unwrap();
        assert!(
            check(
                &over,
                Duration::from_secs(102),
                StagePurpose::InitialFirstHolder
            )
            .is_err()
        );
        let mut changed = statement.clone();
        changed.stage.data.purpose = StagePurpose::CurrentRole;
        changed.stage.data.deadline_ns = 105_000_000_000;
        changed.original.deadline_ns = 105_000_000_000;
        assert!(
            check(
                &changed,
                Duration::from_secs(102),
                StagePurpose::CurrentRole
            )
            .is_err()
        );
        // A short initial grant still cannot be replayed as ordinary authority.
        let mut short = statement.clone();
        short.stage.data.deadline_ns = 105_000_000_000;
        short.original.deadline_ns = 105_000_000_000;
        short.stage.signature = issuer.sign("role-stage", &short.stage.data).unwrap();
        check(
            &short,
            Duration::from_secs(102),
            StagePurpose::InitialFirstHolder,
        )
        .unwrap();
        assert!(check(&short, Duration::from_secs(102), StagePurpose::CurrentRole).is_err());
    }
}

#[test]
fn signed_storage_messages_cannot_cross_initial_and_current_purposes() {
    let (_, initial, key) = initial_fixture(NativeRole::AppHost);
    let message = signed(
        &initial,
        &key,
        Body::CurrentAck {
            exchange: Digest::new(b"current"),
        },
    );
    assert!(message.verify(&initial).is_err());
    let (_, current, key) = fixture(NativeRole::AppHost);
    let message = signed(
        &current,
        &key,
        Body::Hello {
            app: Box::new(current.clone()),
            nonce: Digest::new(b"app"),
            controller_nonce: Digest::new(b"controller"),
        },
    );
    assert!(message.verify(&current).is_err());
}
