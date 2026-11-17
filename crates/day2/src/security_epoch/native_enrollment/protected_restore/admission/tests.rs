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

#[test]
fn initial_connection_requires_the_actual_controller_nonce_and_both_first_statements() {
    let fixture = fixture();
    let nonce = Digest::new(b"fresh-native-controller-nonce-would-be-required");
    fixture
        .connection
        .require_initial(&fixture.shell, &fixture.controller, &nonce)
        .unwrap();
    assert!(
        fixture
            .connection
            .require_initial(
                &fixture.shell,
                &fixture.controller,
                &Digest::new(b"another-controller-attempt")
            )
            .is_err()
    );
    for shell in [false, true] {
        for changed in 0..7 {
            let mut shell_statement = fixture.shell.clone();
            let mut controller_statement = fixture.controller.clone();
            let statement = if shell {
                &mut shell_statement
            } else {
                &mut controller_statement
            };
            match changed {
                0 => statement.original.domain = Digest::new(b"another-original"),
                1 => statement.original.origin_ns += 1,
                2 => statement.original.deadline_ns -= 1,
                3 => statement.original.purpose = StagePurpose::StorageBootstrap,
                4 => statement.stage.data.process.start_ticks += 1,
                5 => statement.stage.data.runtime.container.restart_count += 1,
                6 => statement.stage.signature.push('x'),
                _ => unreachable!(),
            }
            assert!(
                fixture
                    .connection
                    .require_initial(&shell_statement, &controller_statement, &nonce)
                    .is_err(),
                "side={shell}, mutation={changed}"
            );
        }
    }
    // The remote nonce is signed proof DATA, and is preserved exactly. The
    // Controller cannot turn a proof from its earlier local challenge into a
    // match merely by accepting the remote connection's saved nonce fields.
    let other = ConnectionData::bind(
        &fixture.shell,
        &fixture.controller,
        Digest::new(b"fresh-native-shell-nonce-would-be-required"),
        Digest::new(b"earlier-controller-attempt"),
    )
    .unwrap();
    assert!(
        other
            .require_initial(&fixture.shell, &fixture.controller, &nonce)
            .is_err()
    );
}

#[test]
fn admission_frames_have_their_own_four_step_protocol_and_no_request_sequence() {
    use crate::security_epoch::native_enrollment::handshake::{Frame, Protocol, Step};
    let fixture = fixture();
    let messages = [
        Body::ControllerHello {
            controller: Box::new(fixture.controller.clone()),
            nonce: Digest::new(b"hello-nonce-data"),
        },
        Body::ShellProof {
            shell: Box::new(fixture.shell.clone()),
            connection: fixture.connection.clone(),
        },
        Body::ControllerAccept {
            connection: fixture.connection.clone(),
        },
        Body::ShellConfirm {
            connection: fixture.connection,
        },
    ];
    for (message, step) in
        messages
            .into_iter()
            .zip([Step::Hello, Step::Bind, Step::Grant, Step::Confirm])
    {
        assert_eq!(
            message.frame(),
            Frame {
                protocol: Protocol::ProtectedRestoreAdmission,
                step,
                sequence: None,
            }
        );
    }
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

pub(super) fn fixture_statement_data(role: NativeRole) -> Statement {
    let fixture = fixture();
    match role {
        NativeRole::EpochController => fixture.controller,
        NativeRole::SecurityShell => fixture.shell,
        NativeRole::AppHost => panic!("protected transport DATA fixture has no App role"),
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
fn narrowed_later_steps_keep_the_enrollment_but_not_a_reconstructed_connection_or_live_grant() {
    use super::super::ProtectedRestoreMessage;
    let f = fixture();
    let mut shell = f.shell.clone();
    let mut controller = f.controller.clone();
    shell.original.deadline_ns -= 1_000_000_000;
    controller.original.deadline_ns -= 2_000_000_000;
    assert_eq!(enrollment(&shell).unwrap(), enrollment(&f.shell).unwrap());
    assert_eq!(
        enrollment(&controller).unwrap(),
        enrollment(&f.controller).unwrap()
    );
    let reconstructed = ConnectionData::bind(
        &shell,
        &controller,
        f.connection.shell_nonce.clone(),
        f.connection.controller_nonce.clone(),
    )
    .unwrap();
    assert_ne!(
        reconstructed.digest().unwrap(),
        f.connection.digest().unwrap()
    );
    for (statement, key, body) in [
        (
            &controller,
            &f.controller_key,
            Body::ControllerAccept {
                connection: f.connection.clone(),
            },
        ),
        (
            &shell,
            &f.shell_key,
            Body::ShellConfirm {
                connection: f.connection.clone(),
            },
        ),
    ] {
        let view = ProtectedRestoreMessage::admission(&body);
        let signature = key
            .sign(view.domain(), &view.commitment_for(statement).unwrap())
            .unwrap();
        let bytes = Packet::encode(enrollment(statement).unwrap(), body, signature).unwrap();
        let packet = Packet::decode(&bytes).unwrap();
        packet.verify_data(statement).unwrap();
        if statement.stage.data.role == NativeRole::EpochController {
            packet.require_accept(&f.connection).unwrap();
        } else {
            packet.require_confirm(&f.connection).unwrap();
        }
        // A valid DATA signature is not a clock/native grant. The shorter
        // interval still refuses equality; the real receiver must already
        // have met the authenticated bound into its retained acquisition.
        assert!(
            statement
                .original
                .validate_request(
                    std::time::Duration::from_nanos(statement.original.deadline_ns),
                    StagePurpose::CurrentRole
                )
                .is_err()
        );
    }
    let mut changed = controller;
    changed.stage.data.public_key = f.shell_key.public();
    assert_ne!(
        enrollment(&changed).unwrap(),
        enrollment(&f.controller).unwrap()
    );
}

#[test]
fn stable_enrollment_never_allows_hello_or_proof_to_substitute_the_actual_original() {
    use super::super::ProtectedRestoreMessage;
    let f = fixture();
    for (index, statement, key) in [
        (0, &f.shell, &f.shell_key),
        (1, &f.controller, &f.controller_key),
    ] {
        for field in 0..4 {
            let mut changed = statement.clone();
            match field {
                0 => changed.original.purpose = StagePurpose::StorageBootstrap,
                1 => changed.original.domain = Digest::new(b"another-original-domain"),
                2 => changed.original.origin_ns += 1,
                _ => changed.original.deadline_ns -= 1,
            }
            assert_eq!(
                enrollment(&changed).unwrap(),
                enrollment(statement).unwrap()
            );
            let body = if index == 0 {
                let mut connection = f.connection.clone();
                connection.shell_original = changed.original.clone();
                Body::ShellProof {
                    shell: Box::new(changed.clone()),
                    connection,
                }
            } else {
                Body::ControllerHello {
                    controller: Box::new(changed.clone()),
                    nonce: f.connection.controller_nonce.clone(),
                }
            };
            assert!(
                ProtectedRestoreMessage::admission(&body)
                    .commitment_for(statement)
                    .is_err()
            );
            // Deliberately sign hostile DATA with a fixture key. Production
            // never exposes its key, and the actual signing view above refused.
            let bytes = signed(&changed, key, body);
            assert!(
                Packet::decode(&bytes)
                    .unwrap()
                    .verify_data(statement)
                    .is_err()
            );
        }
    }
}

#[test]
fn late_steps_refuse_new_originals_and_widening_even_with_a_valid_packet_and_connection() {
    use super::super::ProtectedRestoreMessage;
    let f = fixture();
    let packets = all_packets(&f);
    for (index, statement) in [(2, &f.controller), (3, &f.shell)] {
        for field in 0..7 {
            let packet = Packet::decode(&packets[index]).unwrap();
            let mut changed = statement.clone();
            match field {
                0 => changed.original.purpose = StagePurpose::StorageBootstrap,
                1 => changed.original.domain = Digest::new(b"fresh-other-current-original"),
                2 => changed.original.origin_ns += 1,
                3 => changed.original.deadline_ns += 1,
                4 => changed.original.origin_ns -= 1,
                5 => changed.original.deadline_ns = changed.original.origin_ns,
                _ => changed.original.deadline_ns = changed.original.origin_ns - 1,
            }
            assert_eq!(
                enrollment(&changed).unwrap(),
                enrollment(statement).unwrap()
            );
            // Matching connection DATA and a valid old signature must not
            // authenticate a renewed original, changed purpose or wider cap.
            if index == 2 {
                packet.require_accept(&f.connection).unwrap();
            } else {
                packet.require_confirm(&f.connection).unwrap();
            }
            assert!(
                ProtectedRestoreMessage::admission(&packet.body)
                    .commitment_for(&changed)
                    .is_err(),
                "signer step {index}, field {field}"
            );
            assert!(
                packet.verify_data(&changed).is_err(),
                "receiver step {index}, field {field}"
            );
        }
    }
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
    for owner in ["shell_original", "controller_original"] {
        for field in ["purpose", "domain", "origin_ns", "deadline_ns"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&packets[1]).unwrap();
            let value = &mut changed["body"]["connection"][owner][field];
            *value = match field {
                "purpose" => serde_json::json!("storage_bootstrap"),
                "domain" => serde_json::json!(Digest::new(b"tampered-connection-original")),
                _ => serde_json::json!(value.as_u64().unwrap() + 1),
            };
            assert!(
                Packet::decode(&serde_json::to_vec(&changed).unwrap())
                    .and_then(|packet| packet.verify_data(&f.shell))
                    .is_err()
            );
        }
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
    assert_eq!(
        enrollment(&later).unwrap(),
        enrollment(&f.controller).unwrap()
    );
    let later_connection = ConnectionData::bind(
        &f.shell,
        &later,
        f.connection.shell_nonce.clone(),
        f.connection.controller_nonce.clone(),
    )
    .unwrap();
    assert_ne!(
        later_connection.digest().unwrap(),
        f.connection.digest().unwrap()
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
            "/body/connection/shell_original",
            "/body/connection/controller_original",
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
        f.shell.original.clone(),
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
    for cut in 0..4 {
        let mut changed = f.shell.clone();
        match cut {
            0 => changed.original.purpose = StagePurpose::InitialFirstHolder,
            1 => changed.original.domain = Digest::new(b"substituted-sender-domain"),
            2 => changed.original.origin_ns += 1,
            _ => changed.original.deadline_ns -= 1,
        }
        assert!(
            view.commitment_for(&changed).is_err(),
            "original field {cut}"
        );
    }
    let mut later = f.shell.clone();
    later.original.domain = Digest::new(b"later-distinct-sender-request");
    later.original.origin_ns += 1_000;
    later.original.deadline_ns += 1_000;
    // The historical enrollment remains admitted, but its packet cannot be
    // re-signed under a different actual request's original.
    assert!(later.same_enrollment(&f.shell));
    assert!(view.commitment_for(&later).is_err());
    let fresh_data = wire::Data::request(
        connection.clone(),
        enrollment(&f.shell).unwrap(),
        8,
        later.original.clone(),
        ProtectedRestoreRequest::Abandon {
            id: Digest::new(b"closed-command"),
        },
    )
    .unwrap();
    let fresh_view = ProtectedRestoreMessage::command(&fresh_data, &f.shell);
    assert!(fresh_view.commitment_for(&later).is_ok());
    assert!(fresh_view.commitment_for(&f.shell).is_err());
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
        f.controller.original.clone(),
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
