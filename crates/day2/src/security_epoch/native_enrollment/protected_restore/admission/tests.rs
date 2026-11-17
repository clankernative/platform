//! Real signatures over DATA fixtures only. No native owner or kernel receipt
//! is constructed, and passing these cases does not qualify native admission.
use super::*;
use crate::security_epoch::{
    native_enrollment::{
        policy::EnrollmentPolicy,
        protocol::{
            IssuerCertificate, IssuerData, KeyOwner, ProcessData, RuntimeBinding, SignedStage,
            StageData,
        },
        storage_peer_wire::OriginalInterval,
        tests::policy,
    },
    runtime_profile::ContainerFacts,
};
use std::collections::BTreeMap;

struct Fixture {
    shell: Statement,
    controller: Statement,
    shell_key: KeyOwner,
    controller_key: KeyOwner,
    connection: ConnectionData,
}

fn process(code: Digest, process: u32) -> ProcessData {
    ProcessData {
        process,
        start_ticks: u64::from(process) + 100,
        code,
        boot: "protected-data-fixture-boot".into(),
        namespaces: ["mnt", "pid", "net", "user", "uts", "time"]
            .into_iter()
            .map(|name| (name.into(), (7, 9)))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn statement(
    policy: &EnrollmentPolicy,
    certificate: &IssuerCertificate,
    issuer: &KeyOwner,
    key: &KeyOwner,
    role: NativeRole,
    pid: u32,
) -> Statement {
    let data = StageData {
        issuer: certificate.digest().unwrap(),
        policy: policy.digest().unwrap(),
        role,
        purpose: StagePurpose::CurrentRole,
        public_key: key.public(),
        challenge: Digest::new(b"protected-data-fixture-challenge"),
        request: Digest::new(b"protected-data-fixture-request"),
        process: process(policy.code(role).clone(), pid),
        runtime: RuntimeBinding {
            container: ContainerFacts {
                pod_name: "protected-fixture".into(),
                pod_uid: "fixture-pod-uid".into(),
                node_name: "fixture-node".into(),
                container_name: "controller-or-shell".into(),
                container_id: "a".repeat(64),
                image: Digest::new(b"fixture-image"),
                restart_count: 0,
            },
            node_uid: "fixture-node-uid".into(),
            boot: "protected-data-fixture-boot".into(),
        },
        origin_ns: 100_000_000_000,
        deadline_ns: 105_000_000_000,
    };
    Statement {
        certificate: certificate.clone(),
        stage: SignedStage {
            signature: issuer.sign("role-stage", &data).unwrap(),
            data,
        },
        original: OriginalInterval {
            purpose: StagePurpose::CurrentRole,
            domain: Digest::new(b"fixture-not-an-actual-native-clock"),
            origin_ns: 100_000_000_000,
            deadline_ns: 105_000_000_000,
        },
    }
}

fn fixture() -> Fixture {
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let shell_key = KeyOwner::generate().unwrap();
    let controller_key = KeyOwner::generate().unwrap();
    let policy = policy(&root);
    let data = IssuerData {
        policy: policy.digest().unwrap(),
        root_version: policy.root.version.clone(),
        nonce: Digest::new(b"protected-data-fixture-issuer"),
        public_key: issuer.public(),
        process: process(policy.issuer_code.clone(), 70),
        provisioner: process(policy.provisioner_code.clone(), 71),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    };
    let shell = statement(
        &policy,
        &certificate,
        &issuer,
        &shell_key,
        NativeRole::SecurityShell,
        80,
    );
    let controller = statement(
        &policy,
        &certificate,
        &issuer,
        &controller_key,
        NativeRole::EpochController,
        81,
    );
    let connection = ConnectionData::bind(
        &shell,
        &controller,
        Digest::new(b"fresh-native-shell-nonce-would-be-required"),
        Digest::new(b"fresh-native-controller-nonce-would-be-required"),
    )
    .unwrap();
    Fixture {
        shell,
        controller,
        shell_key,
        controller_key,
        connection,
    }
}

fn signed(statement: &Statement, key: &KeyOwner, body: Body) -> Vec<u8> {
    let sender = enrollment(statement).unwrap();
    let signature = key
        .sign(DOMAIN, &Packet::commitment(&sender, &body).unwrap())
        .unwrap();
    Packet::encode(sender, body, signature).unwrap()
}

fn all_packets(f: &Fixture) -> [Vec<u8>; 4] {
    [
        signed(
            &f.controller,
            &f.controller_key,
            Body::ControllerHello {
                controller: Box::new(f.controller.clone()),
                nonce: f.connection.controller_nonce.clone(),
            },
        ),
        signed(
            &f.shell,
            &f.shell_key,
            Body::ShellProof {
                shell: Box::new(f.shell.clone()),
                connection: f.connection.clone(),
            },
        ),
        signed(
            &f.controller,
            &f.controller_key,
            Body::ControllerAccept {
                connection: f.connection.clone(),
            },
        ),
        signed(
            &f.shell,
            &f.shell_key,
            Body::ShellConfirm {
                connection: f.connection.clone(),
            },
        ),
    ]
}

#[test]
fn all_four_admission_steps_bind_full_statements_and_fit_the_unchanged_native_frame() {
    let f = fixture();
    let packets = all_packets(&f);
    for (index, bytes) in packets.iter().enumerate() {
        assert!(bytes.len() < MAX_PACKET_BYTES);
        let packet = Packet::decode(bytes).unwrap();
        packet
            .verify_data(if index % 2 == 0 {
                &f.controller
            } else {
                &f.shell
            })
            .unwrap();
    }
    Packet::decode(&packets[0])
        .unwrap()
        .require_hello(&f.controller, &f.connection.controller_nonce)
        .unwrap();
    Packet::decode(&packets[1])
        .unwrap()
        .require_proof(&f.shell, &f.connection)
        .unwrap();
    Packet::decode(&packets[2])
        .unwrap()
        .require_accept(&f.connection)
        .unwrap();
    Packet::decode(&packets[3])
        .unwrap()
        .require_confirm(&f.connection)
        .unwrap();
    assert_eq!(MAX_PACKET_BYTES, 8192);
    assert_eq!(super::super::wire::MAX_PACKET_BYTES, 48 * 1024);

    let mut oversized = f.controller.clone();
    oversized.stage.data.runtime.node_uid = "x".repeat(MAX_PACKET_BYTES);
    let sender = enrollment(&oversized).unwrap();
    let body = Body::ControllerHello {
        controller: Box::new(oversized),
        nonce: Digest::new(b"nonce"),
    };
    let signature = f
        .controller_key
        .sign(DOMAIN, &Packet::commitment(&sender, &body).unwrap())
        .unwrap();
    assert!(Packet::encode(sender, body, signature).is_err());
}

#[test]
fn full_field_signature_and_purpose_bindings_reject_tampering_and_serving_signatures() {
    let f = fixture();
    let packets = all_packets(&f);
    for (index, bytes) in packets.iter().enumerate() {
        let expected = if index % 2 == 0 {
            &f.controller
        } else {
            &f.shell
        };
        let foreign = if index % 2 == 0 {
            &f.shell
        } else {
            &f.controller
        };
        assert!(Packet::decode(bytes).unwrap().verify_data(foreign).is_err());
        let original: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        for field in ["sender", "signature"] {
            let mut changed = original.clone();
            changed[field] = if field == "sender" {
                serde_json::json!(Digest::new(b"other"))
            } else {
                serde_json::json!("A".repeat(86))
            };
            assert!(
                Packet::decode(&serde_json::to_vec(&changed).unwrap())
                    .and_then(|packet| packet.verify_data(expected))
                    .is_err()
            );
        }
    }
    let body = Body::ControllerAccept {
        connection: f.connection.clone(),
    };
    let sender = enrollment(&f.controller).unwrap();
    let digest = Packet::commitment(&sender, &body).unwrap();
    for domain in [
        "shell-controller-serving-message",
        super::super::wire::SIGNING_DOMAIN,
    ] {
        let signature = f.controller_key.sign(domain, &digest).unwrap();
        let bytes = Packet::encode(
            sender.clone(),
            Body::ControllerAccept {
                connection: f.connection.clone(),
            },
            signature,
        )
        .unwrap();
        assert!(
            Packet::decode(&bytes)
                .unwrap()
                .verify_data(&f.controller)
                .is_err()
        );
    }
    let mut changed: serde_json::Value = serde_json::from_slice(&packets[1]).unwrap();
    for field in ["controller", "shell_nonce", "controller_nonce"] {
        let original = changed["body"]["connection"][field].clone();
        changed["body"]["connection"][field] = serde_json::json!(Digest::new(b"tampered"));
        assert!(
            Packet::decode(&serde_json::to_vec(&changed).unwrap())
                .unwrap()
                .verify_data(&f.shell)
                .is_err()
        );
        changed["body"]["connection"][field] = original;
    }
}

#[test]
fn correctly_signed_foreign_connections_and_wrong_steps_cannot_match_the_selected_attempt() {
    let f = fixture();
    let packets = all_packets(&f);
    for cut in 0..4 {
        let mut shell = f.shell.clone();
        let mut controller = f.controller.clone();
        if cut == 0 {
            shell.original.origin_ns += 1;
        }
        if cut == 1 {
            controller.original.origin_ns += 1;
        }
        let connection = ConnectionData::bind(
            &shell,
            &controller,
            if cut == 2 {
                Digest::new(b"another-shell-nonce")
            } else {
                f.connection.shell_nonce.clone()
            },
            if cut == 3 {
                Digest::new(b"another-controller-nonce")
            } else {
                f.connection.controller_nonce.clone()
            },
        )
        .unwrap();
        assert_ne!(connection.digest().unwrap(), f.connection.digest().unwrap());
        let bytes = signed(
            &controller,
            &f.controller_key,
            Body::ControllerAccept { connection },
        );
        let packet = Packet::decode(&bytes).unwrap();
        packet.verify_data(&controller).unwrap();
        assert!(packet.require_accept(&f.connection).is_err());
    }
    for (index, bytes) in packets.iter().enumerate() {
        let packet = Packet::decode(bytes).unwrap();
        assert_eq!(
            packet
                .require_hello(&f.controller, &f.connection.controller_nonce)
                .is_ok(),
            index == 0
        );
        assert_eq!(
            packet.require_proof(&f.shell, &f.connection).is_ok(),
            index == 1
        );
        assert_eq!(packet.require_accept(&f.connection).is_ok(), index == 2);
        assert_eq!(packet.require_confirm(&f.connection).is_ok(), index == 3);
    }
    let hello = Packet::decode(&packets[0]).unwrap();
    assert!(
        hello
            .require_hello(&f.controller, &Digest::new(b"another-ready"))
            .is_err()
    );
    let mut later = f.controller.clone();
    later.original.origin_ns += 1;
    assert!(
        hello
            .require_hello(&later, &f.connection.controller_nonce)
            .is_err()
    );
    assert_ne!(
        enrollment(&later).unwrap(),
        enrollment(&f.controller).unwrap()
    );
}

#[test]
fn strict_admission_decoder_rejects_unknown_duplicate_array_and_alternate_version_shapes() {
    let f = fixture();
    for bytes in all_packets(&f) {
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for path in [
            "",
            "/body",
            "/body/connection",
            "/body/controller",
            "/body/shell",
        ] {
            if original.pointer(path).is_none() {
                continue;
            }
            let mut changed = original.clone();
            *changed.pointer_mut(path).unwrap() = serde_json::json!([]);
            assert!(Packet::from_value(changed).is_err());
        }
        let mut unknown = original.clone();
        unknown["permission"] = serde_json::json!(true);
        assert!(Packet::from_value(unknown).is_err());
        let mut unknown = original.clone();
        unknown["body"]["permission"] = serde_json::json!(true);
        assert!(Packet::from_value(unknown).is_err());
        let mut version = original.clone();
        version["format"] = serde_json::json!({"day2_protected_restore_admission_v1":null});
        assert!(Packet::from_value(version).is_err());
        let mut serving = original.clone();
        serving["format"] = serde_json::json!("shell-controller-serving-message");
        assert!(Packet::from_value(serving).is_err());
        let mut completed = original;
        completed["body"] = serde_json::json!({"step":"restore_completed"});
        assert!(Packet::from_value(completed).is_err());
        let text = String::from_utf8(bytes.clone()).unwrap();
        let duplicate = text.replacen(
            "\"sender\":",
            "\"format\":\"day2_protected_restore_admission_v1\",\"sender\":",
            1,
        );
        assert!(Packet::decode(duplicate.as_bytes()).is_err());
        for length in 0..bytes.len() {
            assert!(Packet::decode(&bytes[..length]).is_err());
        }
    }
    assert!(Packet::decode(&vec![b' '; MAX_PACKET_BYTES + 1]).is_err());
}

#[test]
fn connection_shape_refuses_wrong_roles_purposes_issuers_and_policies_without_claiming_native_admission()
 {
    let f = fixture();
    for cut in 0..4 {
        let mut shell = f.shell.clone();
        match cut {
            0 => shell.stage.data.role = NativeRole::AppHost,
            1 => shell.original.purpose = StagePurpose::InitialFirstHolder,
            2 => shell.stage.data.issuer = Digest::new(b"foreign-issuer"),
            3 => shell.stage.data.policy = Digest::new(b"foreign-policy"),
            _ => unreachable!(),
        }
        assert!(
            ConnectionData::bind(
                &shell,
                &f.controller,
                f.connection.shell_nonce.clone(),
                f.connection.controller_nonce.clone()
            )
            .is_err()
        );
    }
    assert!(
        ConnectionData::bind(
            &f.controller,
            &f.shell,
            f.connection.shell_nonce.clone(),
            f.connection.controller_nonce.clone()
        )
        .is_err()
    );
    assert!(
        ConnectionData::bind(
            &f.shell,
            &fixture().controller,
            f.connection.shell_nonce.clone(),
            f.connection.controller_nonce.clone()
        )
        .is_err()
    );
}

#[test]
fn fixed_signing_views_bind_real_message_data_without_exposing_a_key_or_native_owner() {
    use super::super::{
        ProtectedRestoreMessage, ProtectedRestoreReply, ProtectedRestoreRequest, wire,
    };
    let f = fixture();
    for (index, bytes) in all_packets(&f).iter().enumerate() {
        let packet = Packet::decode(bytes).unwrap();
        let (local, key, foreign) = if index % 2 == 0 {
            (&f.controller, &f.controller_key, &f.shell)
        } else {
            (&f.shell, &f.shell_key, &f.controller)
        };
        let view = ProtectedRestoreMessage::admission(&packet.body);
        assert_eq!(view.domain(), DOMAIN);
        assert_eq!(
            view.commitment_for(local).unwrap(),
            Packet::commitment(&enrollment(local).unwrap(), &packet.body).unwrap()
        );
        assert!(view.commitment_for(foreign).is_err());
        let signature = key
            .sign(view.domain(), &view.commitment_for(local).unwrap())
            .unwrap();
        let encoded = Packet::encode(enrollment(local).unwrap(), packet.body, signature).unwrap();
        Packet::decode(&encoded)
            .unwrap()
            .verify_data(local)
            .unwrap();
    }
    let connection = f.connection.digest().unwrap();
    let data = wire::Data::request(
        connection.clone(),
        enrollment(&f.shell).unwrap(),
        7,
        ProtectedRestoreRequest::Abandon {
            id: Digest::new(b"closed-command"),
        },
    )
    .unwrap();
    let view = ProtectedRestoreMessage::command(&data, &f.shell);
    assert_eq!(view.domain(), wire::SIGNING_DOMAIN);
    assert_eq!(
        view.commitment_for(&f.shell).unwrap(),
        data.commitment().unwrap()
    );
    assert!(view.commitment_for(&f.controller).is_err());
    let mut later = f.shell.clone();
    later.original.origin_ns += 1_000;
    later.original.deadline_ns += 1_000;
    // Historical identity may remain admitted across distinct requests. Only
    // the ACTUAL signing stage can establish the later original's validity.
    assert!(view.commitment_for(&later).is_ok());
    for cut in 0..4 {
        let mut changed = f.shell.clone();
        match cut {
            0 => changed.original.purpose = StagePurpose::InitialFirstHolder,
            1 => changed.stage.data.purpose = StagePurpose::StorageBootstrap,
            2 => changed.stage.data.process.code = Digest::new(b"changed-code"),
            _ => changed.stage.data.public_key = f.controller.stage.data.public_key.clone(),
        }
        assert!(view.commitment_for(&changed).is_err(), "cut {cut}");
    }
    let reply = wire::Data::reply(
        connection,
        enrollment(&f.controller).unwrap(),
        7,
        ProtectedRestoreReply::Refused,
    )
    .unwrap();
    let reply_view = ProtectedRestoreMessage::command(&reply, &f.controller);
    assert!(reply_view.commitment_for(&f.controller).is_ok());
    assert!(
        ProtectedRestoreMessage::command(&reply, &f.shell)
            .commitment_for(&f.shell)
            .is_err()
    );
}
