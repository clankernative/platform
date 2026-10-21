//! Cryptographic DATA controls; no native owner, role or storage permission.
use super::*;

#[test]
fn ready_packets_are_controller_signed_closed_data_before_any_serving_scope() {
    let (_, controller, key, _) = fixture_with_issuer(NativeRole::EpochController);
    let (_, shell, _, _) = fixture_with_issuer(NativeRole::SecurityShell);
    for body in [
        Body::InitialBeginReady {
            controller: Box::new(controller.clone()),
            nonce: Digest::new(b"ready"),
        },
        Body::CurrentBeginReady {
            controller: Box::new(controller.clone()),
            initial: Digest::new(b"original"),
            sequence: 1,
            nonce: Digest::new(b"ready"),
        },
    ] {
        let ready = signed(&controller, &key, body);
        let bytes = serde_json::to_vec(&ready).unwrap();
        decode(&bytes).unwrap().verify(&controller).unwrap();
        assert!(decode(&bytes).unwrap().verify(&shell).is_err());
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
        let mut changed = original.clone();
        changed["body"]["role"] = serde_json::json!("epoch_controller");
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        let mut missing = original;
        missing["body"].as_object_mut().unwrap().remove("nonce");
        assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        let nonce = serde_json::to_string(&Digest::new(b"ready")).unwrap();
        let duplicate = String::from_utf8(bytes).unwrap().replace(
            &format!("\"nonce\":{nonce}"),
            &format!("\"nonce\":{nonce},\"nonce\":{nonce}"),
        );
        assert!(decode(duplicate.as_bytes()).is_err());
    }
}

#[test]
fn shell_hello_cannot_change_ready_nonce_original_or_sequence_even_with_valid_signature() {
    let (_, shell, key, _) = fixture_with_issuer(NativeRole::SecurityShell);
    let nonce = Digest::new(b"controller readiness");
    let initial = Digest::new(b"original peer");
    for (body, expected_initial, sequence) in [
        (
            Body::Hello {
                shell: Box::new(shell.clone()),
                nonce: Digest::new(b"shell nonce"),
                controller_nonce: nonce.clone(),
            },
            None,
            0,
        ),
        (
            Body::CurrentHello {
                shell: Box::new(shell.clone()),
                initial: initial.clone(),
                sequence: 1,
                binding: Digest::new(b"actual consumer"),
                nonce: Digest::new(b"shell nonce"),
                controller_nonce: nonce.clone(),
            },
            Some(initial.clone()),
            1,
        ),
    ] {
        let hello = signed(&shell, &key, body);
        let bytes = serde_json::to_vec(&hello).unwrap();
        let decoded = decode(&bytes).unwrap();
        decoded.verify(&shell).unwrap();
        decoded
            .hello(expected_initial.as_ref(), sequence, &nonce)
            .unwrap();
        assert!(
            decoded
                .hello(
                    expected_initial.as_ref(),
                    sequence,
                    &Digest::new(b"different ready")
                )
                .is_err()
        );
        assert!(
            decoded
                .hello(expected_initial.as_ref(), sequence + 1, &nonce)
                .is_err()
        );
        assert!(
            decoded
                .hello(Some(&Digest::new(b"foreign original")), sequence, &nonce)
                .is_err()
        );
        let mut missing = serde_json::to_value(&hello).unwrap();
        missing["body"]
            .as_object_mut()
            .unwrap()
            .remove("controller_nonce");
        assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
}

#[test]
fn shell_offer_cannot_renew_or_replace_the_ready_stage_or_nonce() {
    let (_, ready, _, issuer) = fixture_with_issuer(NativeRole::EpochController);
    let nonce = Digest::new(b"controller ready");
    let exchange = Exchange {
        initial: Some(Digest::new(b"retained peer")),
        sequence: 1,
        binding: Some(Digest::new(b"consumer")),
        shell_stage: Digest::new(b"shell stage"),
        controller_stage: ready.digest().unwrap(),
        shell_nonce: Digest::new(b"shell nonce"),
        controller_nonce: nonce.clone(),
    };
    exchange
        .require_begin_ready(&ready, &nonce, &ready)
        .unwrap();
    let mut later = ready.clone();
    later.stage.data.challenge = Digest::new(b"later actual grant data");
    later.stage.signature = issuer.sign("role-stage", &later.stage.data).unwrap();
    assert!(ready.same_enrollment(&later));
    assert!(
        exchange
            .require_begin_ready(&ready, &nonce, &later)
            .is_err()
    );
    let mut clock = ready.clone();
    clock.original.origin_ns += 1;
    assert!(
        exchange
            .require_begin_ready(&ready, &nonce, &clock)
            .is_err()
    );
    assert!(
        exchange
            .require_begin_ready(&ready, &Digest::new(b"different ready"), &ready)
            .is_err()
    );
    assert!(ready.require_fresh(&ready).is_err());
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

fn fixture_with_issuer(role: NativeRole) -> (EnrollmentPolicy, Statement, KeyOwner, KeyOwner) {
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
        Statement {
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

fn signed(statement: &Statement, key: &KeyOwner, body: Body) -> Message {
    let sender = statement.digest().unwrap();
    let signature = key.sign(DOMAIN, &(&sender, &body)).unwrap();
    Message {
        sender,
        body,
        signature,
    }
}

#[test]
fn statement_data_binds_same_issuer_full_policy_role_process_and_original_budget() {
    let (policy, statement, _, _) = fixture_with_issuer(NativeRole::SecurityShell);
    let pid = statement.stage.data.process.process;
    let now = Duration::from_secs(102);
    let check = |value: &Statement, expected: NativeRole, pid, now| {
        value.validate(
            &policy,
            &statement.certificate,
            expected,
            pid,
            Some(&statement.stage.data.process),
            now,
        )
    };
    check(&statement, NativeRole::SecurityShell, pid, now).unwrap();
    for role in [NativeRole::AppHost, NativeRole::EpochController] {
        assert!(check(&statement, role, pid, now).is_err());
    }
    assert!(check(&statement, NativeRole::SecurityShell, pid + 1, now).is_err());
    for now in [Duration::from_secs(99), Duration::from_secs(105)] {
        assert!(check(&statement, NativeRole::SecurityShell, pid, now).is_err());
    }
    let mut changed = statement.clone();
    changed.original.deadline_ns += 1;
    assert!(check(&changed, NativeRole::SecurityShell, pid, now).is_err());
    let mut changed = statement.clone();
    changed.original.origin_ns += 1;
    assert!(check(&changed, NativeRole::SecurityShell, pid, now).is_err());
    let mut changed = statement.clone();
    changed.stage.data.process.start_ticks += 1;
    assert!(check(&changed, NativeRole::SecurityShell, pid, now).is_err());
    let (_, other, _, _) = fixture_with_issuer(NativeRole::SecurityShell);
    assert!(
        statement
            .validate(
                &policy,
                &other.certificate,
                NativeRole::SecurityShell,
                pid,
                None,
                now
            )
            .is_err()
    );
    let mut selected = policy.clone();
    selected.bootstrap.scope.environment =
        day2_capabilities::Name::try_from("changed-environment".to_owned()).unwrap();
    assert!(
        statement
            .validate(
                &selected,
                &statement.certificate,
                NativeRole::SecurityShell,
                pid,
                None,
                now
            )
            .is_err()
    );
}

#[test]
fn current_phase_needs_a_later_distinct_signed_grant_not_rewrapped_data() {
    let (policy, statement, _, issuer) = fixture_with_issuer(NativeRole::SecurityShell);
    assert!(statement.require_fresh(&statement).is_err());
    let mut wrapped = statement.clone();
    wrapped.original.domain = Digest::new(b"different-envelope-domain");
    assert!(wrapped.require_fresh(&statement).is_err());
    wrapped.original.origin_ns -= 1;
    assert!(wrapped.require_fresh(&statement).is_err());
    let mut wrapped = statement.clone();
    wrapped.stage.signature.push('x');
    assert!(wrapped.require_fresh(&statement).is_err());
    let mut fresh = statement.clone();
    // Acquisition domains are per-origin random nonces, not the shared kernel
    // clock namespace. Fresh peer acquisitions must not equal the local one.
    fresh.original.domain = Digest::new(b"fresh-native-acquisition");
    fresh.original.origin_ns += 1;
    fresh.stage.data.origin_ns += 1;
    fresh.stage.data.request = Digest::new(b"fresh-role-request");
    fresh.stage.signature = issuer.sign("role-stage", &fresh.stage.data).unwrap();
    fresh.require_fresh(&statement).unwrap();
    fresh
        .validate(
            &policy,
            &statement.certificate,
            NativeRole::SecurityShell,
            fresh.stage.data.process.process,
            Some(&fresh.stage.data.process),
            Duration::from_secs(102),
        )
        .unwrap();
    assert!(statement.require_fresh(&fresh).is_err());
    fresh.stage.data.process.start_ticks += 1;
    assert!(fresh.require_fresh(&statement).is_err());
}

#[test]
fn message_key_possession_is_serving_domain_and_sender_role_bound() {
    let (_, statement, key, _) = fixture_with_issuer(NativeRole::SecurityShell);
    let body = Body::Hello {
        shell: Box::new(statement.clone()),
        nonce: Digest::new(b"hello"),
        controller_nonce: Digest::new(b"controller-ready"),
    };
    let mut message = signed(&statement, &key, body);
    message.verify(&statement).unwrap();
    message.signature = key
        .sign("initial-storage-message", &(&message.sender, &message.body))
        .unwrap();
    assert!(message.verify(&statement).is_err());
    let message = signed(
        &statement,
        &key,
        Body::Known {
            exchange: Digest::new(b"wrong-direction"),
        },
    );
    assert!(message.verify(&statement).is_err());
    let message = signed(
        &statement,
        &KeyOwner::generate().unwrap(),
        Body::Consumed {
            exchange: Digest::new(b"unknown-key"),
        },
    );
    assert!(message.verify(&statement).is_err());
}

#[test]
fn transcript_binds_connection_sequence_binding_both_stages_and_nonces() {
    let exchange = Exchange {
        initial: Some(Digest::new(b"initial")),
        sequence: 1,
        binding: Some(Digest::new(b"binding")),
        shell_stage: Digest::new(b"shell"),
        controller_stage: Digest::new(b"controller"),
        shell_nonce: Digest::new(b"shell-nonce"),
        controller_nonce: Digest::new(b"controller-nonce"),
    };
    let original = exchange.digest().unwrap();
    let value = serde_json::to_value(&exchange).unwrap();
    for field in [
        "initial",
        "binding",
        "shell_stage",
        "controller_stage",
        "shell_nonce",
        "controller_nonce",
    ] {
        let mut changed = value.clone();
        changed[field] =
            serde_json::to_value(Digest::new(format!("changed-{field}").as_bytes())).unwrap();
        let changed: Exchange = serde_json::from_value(changed).unwrap();
        assert_ne!(changed.digest().unwrap(), original);
    }
    let mut changed = exchange.clone();
    changed.sequence += 1;
    assert_ne!(changed.digest().unwrap(), original);
    changed.sequence = 0;
    assert!(changed.digest().is_err());
    changed = exchange.clone();
    changed.binding = None;
    assert!(changed.digest().is_err());
    changed = exchange.clone();
    changed.initial = None;
    assert!(changed.digest().is_err());
}

#[test]
fn closed_wire_refuses_duplicate_unknown_array_oversize_and_app_protocol_records() {
    let (_, statement, key, _) = fixture_with_issuer(NativeRole::SecurityShell);
    let message = signed(
        &statement,
        &key,
        Body::Hello {
            shell: Box::new(statement.clone()),
            nonce: Digest::new(b"hello"),
            controller_nonce: Digest::new(b"controller-ready"),
        },
    );
    let bytes = serde_json::to_vec(&message).unwrap();
    decode(&bytes).unwrap();
    let duplicate = String::from_utf8(bytes.clone())
        .unwrap()
        .replace("\"body\":", "\"body\":{},\"body\":");
    assert!(decode(duplicate.as_bytes()).is_err());
    let value = serde_json::to_value(&message).unwrap();
    let mut changed = value.clone();
    changed["extra"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = value.clone();
    changed["body"]["shell"]["stage"]["data"]["process"] = serde_json::json!([]);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = value.clone();
    changed["body"]["step"] = serde_json::json!("complete");
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    assert!(decode(&serde_json::to_vec(&serde_json::json!([value])).unwrap()).is_err());
    assert!(decode(&vec![b'x'; protocol::MAX_PACKET + 1]).is_err());
}
