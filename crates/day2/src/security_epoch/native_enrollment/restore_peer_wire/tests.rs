//! Cryptographic protocol DATA only. These fixtures never create a native
//! stage, consumed approval, descriptor, P3, receiving keeper or writer.
use super::*;
use crate::security_epoch::native_enrollment::{
    handshake::{Actor, Direction, Frame, Observation, Protocol, Step, Transcript, Transport},
    protocol::KeyOwner,
    storage_peer_wire::{
        Body, Message, decode,
        tests::{fixture, fixture_with_issuer},
    },
};
use serde_json::{Value, json};
use std::time::Duration;

fn projection() -> Projection {
    let d = |value: &str| Digest::new(value.as_bytes());
    let policy = super::super::tests::policy(&KeyOwner::generate().unwrap());
    let selection = Selection {
        operation: d("restore-operation"),
        approval_request: d("exact-signed-request"),
        intent: d("intent"),
        full_archive: d("complete-captured-archive"),
        target: TargetBinding {
            scope: policy.bootstrap.scope.clone(),
            binding_generation: 1,
            authority: policy.store.authority_key().unwrap(),
            selection: Digest::of(&policy.store).unwrap(),
            incarnation: d("new-incarnation"),
            security_epoch: 2,
            artifact: d("artifact"),
            schema: d("schema"),
        },
    };
    Projection {
        report: TargetReport {
            intent: selection.intent.clone(),
            archive: d("source-image"),
            target_incarnation: selection.target.incarnation.clone(),
            target_epoch: 2,
            image: d("reset-image"),
            schema: selection.target.schema.clone(),
            artifact: selection.target.artifact.clone(),
            reset_observation: d("reset-observation"),
        },
        selection,
        creator: Creator {
            device_major: 8,
            device_minor: 1,
            inode: 123,
            length: 8192,
            user: 1000,
            group: 1000,
        },
        consumed_use: d("consumed-grant"),
        captured_records: d("all-eight-records"),
        ledger: LedgerKeys {
            initial_create: d("initial-create"),
            initial_activation: d("initial-activation"),
            advance: d("advance"),
            grant: d("grant"),
        },
    }
}

fn signed(statement: &StageStatement, key: &KeyOwner, payload: RestoreBody) -> Message {
    let body = Body::Restore { payload };
    let sender = statement.digest().unwrap();
    Message {
        signature: key
            .sign("initial-storage-message", &(&sender, &body))
            .unwrap(),
        sender,
        body,
    }
}

fn signed_app(statement: &RestoreAppStatement, key: &KeyOwner, payload: RestoreBody) -> Message {
    let body = Body::Restore { payload };
    let sender = statement.digest().unwrap();
    Message {
        signature: key
            .sign("restored-storage-message", &(&sender, &body))
            .unwrap(),
        sender,
        body,
    }
}

// Actual Ed25519 signatures over synthetic DATA only. No process, original,
// keeper, P3, native candidate or serving owner is manufactured here.
fn fixtures_with_issuer() -> Result<(
    super::super::policy::EnrollmentPolicy,
    RestoreAppStatement,
    KeyOwner,
    StageStatement,
    KeyOwner,
    KeyOwner,
)> {
    use super::super::protocol::{
        RestoreAdmissionStatement, RestoreAuthorizationData, RestoreAuthorizationStatement,
        SignedRestoreAdmission, SignedRestoreAuthorization, SignedStage,
    };
    let (policy, ordinary, app_key, issuer) = fixture_with_issuer(NativeRole::AppHost);
    let controller_key = KeyOwner::generate()?;
    let mut controller = ordinary.clone();
    let mut data = controller.stage.data.clone();
    data.role = NativeRole::EpochController;
    data.public_key = controller_key.public();
    data.process.process += 1;
    data.process.code = policy.code(NativeRole::EpochController).clone();
    let selected = policy.workload(NativeRole::EpochController);
    data.runtime.node_uid = policy.runtime.node_uid.clone();
    data.runtime.boot = data.process.boot.clone();
    data.runtime.container.node_name = policy.runtime.node_name.clone();
    data.runtime.container.pod_name = format!("{}-0", selected.workload.name);
    data.runtime.container.container_name = selected.container.name.clone();
    data.runtime.container.image = selected.container.image.clone();
    data.runtime.container.container_id = format!("containerd://{}", "b".repeat(64));
    controller.stage = SignedStage {
        signature: issuer.sign("role-stage", &data)?,
        data,
    };
    let p = projection();
    let data = RestoreAuthorizationData {
        issuer: ordinary.certificate.digest()?,
        policy: policy.digest()?,
        frozen: Digest::new(b"synthetic-frozen"),
        controller: controller.digest()?,
        operation: p.selection.operation.clone(),
        approval: p.selection.approval_request.clone(),
        grant: Digest::new(b"consumed-grant"),
        intent: p.selection.intent.clone(),
        full_archive: p.selection.full_archive.clone(),
        desired_instance: Digest::new(b"synthetic-admitted-current-instance"),
        target: p.selection.target.clone(),
        report: p.report,
        terminal: Digest::new(b"terminal"),
        terminal_version: "2026-11-05T00:00:00Z".to_owned().try_into()?,
        records: Digest::new(b"complete-ledger"),
        parent_clock: controller.original.domain.clone(),
        parent_origin_ns: 100_000_000_000,
        parent_deadline_ns: 105_000_000_000,
    };
    let statement = RestoreAuthorizationStatement {
        data,
        request: Digest::new(b"prepare-request"),
        challenge: Digest::new(b"prepare-challenge"),
        effective_deadline_ns: 104_000_000_000,
    };
    let authorization = SignedRestoreAuthorization {
        signature: issuer.sign("restore-controller-authorized-v1", &statement)?,
        statement,
    };
    let mut runtime = ordinary.stage.data.runtime.clone();
    let selected = policy.workload(NativeRole::AppHost);
    runtime.node_uid = policy.runtime.node_uid.clone();
    runtime.boot = ordinary.stage.data.process.boot.clone();
    runtime.container.node_name = policy.runtime.node_name.clone();
    runtime.container.pod_uid = "12345678-1234-1234-1234-123456789abc".to_owned();
    runtime.container.pod_name = format!("{}-7c4d9f6f7b-abc12", selected.workload.name);
    runtime.container.container_id = format!("containerd://{}", "a".repeat(64));
    runtime.container.container_name = selected.container.name.clone();
    runtime.container.image = selected.container.image.clone();
    let statement = RestoreAdmissionStatement {
        issuer: ordinary.certificate.digest()?,
        policy: policy.digest()?,
        authorization: authorization.digest_data()?,
        process: ordinary.stage.data.process.clone(),
        runtime,
        public_key: app_key.public(),
        request: Digest::new(b"new-app-request"),
        challenge: Digest::new(b"new-app-challenge"),
        receiver_clock: ordinary.original.domain.clone(),
        receiver_origin_ns: 100_000_000_000,
        receiver_deadline_ns: 105_000_000_000,
        effective_deadline_ns: 104_000_000_000,
    };
    let admission = SignedRestoreAdmission {
        signature: issuer.sign("restore-app-admission-v1", &statement)?,
        statement,
    };
    let app = RestoreAppStatement {
        certificate: ordinary.certificate,
        authorization,
        admission,
        original: RestoreOriginal {
            domain: ordinary.original.domain,
            origin_ns: 100_000_000_000,
            deadline_ns: 104_000_000_000,
        },
    };
    Ok((policy, app, app_key, controller, controller_key, issuer))
}

fn fixtures() -> Result<(
    super::super::policy::EnrollmentPolicy,
    RestoreAppStatement,
    KeyOwner,
    StageStatement,
    KeyOwner,
)> {
    let (policy, app, key, controller, controller_key, _) = fixtures_with_issuer()?;
    Ok((policy, app, key, controller, controller_key))
}

fn phases(app: &RestoreAppStatement, controller: &StageStatement) -> Vec<RestoreBody> {
    let p = projection();
    let app_nonce = Digest::new(b"app-nonce");
    let controller_nonce = Digest::new(b"controller-nonce");
    let exchange = Exchange {
        app_stage: app.digest().unwrap(),
        controller_stage: controller.digest().unwrap(),
        app_nonce: app_nonce.clone(),
        controller_nonce: controller_nonce.clone(),
        projection: p.digest().unwrap(),
    };
    let x = exchange.digest().unwrap();
    let pd = p.digest().unwrap();
    let activation = Activation {
        receipt: Digest::new(b"writer-receipt"),
        root: Digest::new(b"restored-root"),
        sentinel: Digest::new(b"restored-sentinel"),
        root_version: "2026-11-05T00:00:00Z".to_owned().try_into().unwrap(),
        sentinel_version: "2026-11-05T00:00:00Z".to_owned().try_into().unwrap(),
        receipt_version: "2026-11-05T00:00:00Z".to_owned().try_into().unwrap(),
        expectation: serde_json::from_value(json!({
            "records":std::array::from_fn::<_,10,_>(|index|Digest::new(format!("wire-record-{index}").as_bytes())),
            "versions":vec!["2026-11-05T00:00:00Z";10],
            "committed_at":"2026-11-05T00:00:00Z","read_floor":"2026-11-05T00:00:01Z"
        })).unwrap(),
    };
    let a = Digest::of(&activation).unwrap();
    vec![
        RestoreBody::Ready {
            controller: Box::new(controller.clone()),
            nonce: controller_nonce.clone(),
            selection: p.selection.clone(),
        },
        RestoreBody::Hello {
            app: Box::new(app.clone()),
            nonce: app_nonce,
            controller_nonce,
            selection: p.selection.clone(),
        },
        RestoreBody::Offer {
            controller: Box::new(controller.clone()),
            exchange,
            projection: Box::new(p),
        },
        RestoreBody::Confirm {
            exchange: x.clone(),
            projection: pd.clone(),
        },
        RestoreBody::Durable {
            exchange: x.clone(),
            projection: pd.clone(),
        },
        RestoreBody::Accepted {
            exchange: x.clone(),
            projection: pd,
        },
        RestoreBody::Activated {
            exchange: x.clone(),
            activation: Box::new(activation),
        },
        RestoreBody::ActivatedAck {
            exchange: x.clone(),
            activation: a.clone(),
            cohort: super::super::storage_peer_wire::SqliteCohort::from_identities(
                (9, 10),
                (9, 11),
                (9, 12),
            )
            .unwrap(),
        },
        RestoreBody::Released {
            exchange: x,
            activation: a,
        },
    ]
}

#[test]
fn nine_restore_phases_keep_controller_current_and_distinct_app_admission() -> Result<()> {
    let (_, app, app_key, controller, controller_key) = fixtures()?;
    let expected = [
        Step::BeginReady,
        Step::Hello,
        Step::Offer,
        Step::Confirm,
        Step::Complete,
        Step::Accepted,
        Step::Known,
        Step::Consumed,
        Step::Released,
    ];
    for (index, phase) in phases(&app, &controller).into_iter().enumerate() {
        let from_app = matches!(index, 1 | 3 | 5 | 7);
        let message = if from_app {
            signed_app(&app, &app_key, phase.clone())
        } else {
            signed(&controller, &controller_key, phase.clone())
        };
        let bytes = serde_json::to_vec(&message)?;
        let decoded = decode(&bytes)?;
        if from_app {
            decoded.verify_restored_app(&app)?;
            assert!(decoded.verify(&controller).is_err());
            let mut wrong = app.clone();
            wrong.original.domain = Digest::new(b"other-original");
            assert!(decoded.verify_restored_app(&wrong).is_err());
            let (_, ordinary, _) = fixture(NativeRole::AppHost);
            assert!(decoded.verify(&ordinary).is_err());
        } else {
            decoded.verify(&controller)?;
            assert!(decoded.verify_restored_app(&app).is_err());
        }
        assert_eq!(
            decoded.body.frame(),
            Frame {
                protocol: Protocol::RestoredStorage,
                step: expected[index],
                sequence: None
            }
        );
        assert!(
            decoded
                .body
                .require_stage_purpose(StagePurpose::InitialFirstHolder)
                .is_err()
        );
        assert!(
            decoded
                .body
                .require_stage_purpose(StagePurpose::StorageBootstrap)
                .is_err()
        );
        let mut changed: Value = crate::json::decode(&bytes)?;
        changed["body"]["payload"]["phase"] = json!(if index == 0 { "hello" } else { "ready" });
        assert!(decode(&serde_json::to_vec(&changed)?).is_err());
        let mut replacement = message;
        replacement.sender = Digest::new(b"different-signed-stage");
        if from_app {
            assert!(replacement.verify_restored_app(&app).is_err());
        } else {
            assert!(replacement.verify(&controller).is_err());
        }
    }
    Ok(())
}

#[test]
fn activation_with_all_ten_read_expectations_keeps_the_existing_packet_bound() -> Result<()> {
    let (_, app, _, controller, key) = fixtures()?;
    let mut phase = phases(&app, &controller).remove(6);
    let RestoreBody::Activated { activation, .. } = &mut phase else {
        unreachable!()
    };
    let at = "9999-12-31T23:59:59.999999000Z";
    let mut expectation = serde_json::to_value(&activation.expectation)?;
    expectation["versions"] = json!(vec![at; 10]);
    expectation["committed_at"] = json!(at);
    expectation["read_floor"] = json!(at);
    activation.expectation = serde_json::from_value(expectation)?;
    activation.root_version = at.to_owned().try_into()?;
    activation.sentinel_version = at.to_owned().try_into()?;
    activation.receipt_version = at.to_owned().try_into()?;
    let message = signed(&controller, &key, phase);
    let bytes = serde_json::to_vec(&message)?;
    assert!(bytes.len() <= crate::security_epoch::native_enrollment::protocol::MAX_PACKET);
    decode(&bytes)?.verify(&controller)?;
    let mut oversized = bytes;
    oversized.resize(
        crate::security_epoch::native_enrollment::protocol::MAX_PACKET + 1,
        b' ',
    );
    assert!(decode(&oversized).is_err());
    Ok(())
}

#[test]
fn real_selection_nonce_stage_and_projection_helpers_reject_substitution() -> Result<()> {
    let (_, app, _, controller, _) = fixtures()?;
    let phases = phases(&app, &controller);
    let p = projection();
    let (ready, nonce) = phases[0].ready(&p.selection)?;
    let (selected_app, app_nonce) = phases[1].hello(&p.selection, nonce)?;
    let (exchange, selected) =
        phases[2].offer(&p.selection, selected_app, ready, app_nonce, nonce)?;
    assert!(selected == &p);
    for field in 0..8 {
        let mut other = p.selection.clone();
        match field {
            0 => other.operation = Digest::new(b"other"),
            1 => other.approval_request = Digest::new(b"other"),
            2 => other.full_archive = Digest::new(b"other"),
            3 => other.intent = Digest::new(b"other"),
            4 => other.target.incarnation = Digest::new(b"other"),
            5 => other.target.security_epoch += 1,
            6 => other.target.binding_generation += 1,
            _ => other.target.scope.app = "foreign".to_owned().try_into().unwrap(),
        }
        assert!(phases[0].ready(&other).is_err());
        assert!(phases[1].hello(&other, nonce).is_err());
        assert!(
            phases[2]
                .offer(&other, selected_app, ready, app_nonce, nonce)
                .is_err()
        );
    }
    assert!(
        phases[1]
            .hello(&p.selection, &Digest::new(b"other-ready"))
            .is_err()
    );
    assert!(
        phases[2]
            .offer(
                &p.selection,
                selected_app,
                ready,
                &Digest::new(b"other-app-nonce"),
                nonce
            )
            .is_err()
    );
    assert!(
        phases[2]
            .offer(
                &p.selection,
                selected_app,
                ready,
                app_nonce,
                &Digest::new(b"other-ready")
            )
            .is_err()
    );
    let mut later = ready.clone();
    later.original.deadline_ns -= 1;
    assert!(
        phases[2]
            .offer(&p.selection, selected_app, &later, app_nonce, nonce)
            .is_err()
    );
    for (index, step) in [(3, Step::Confirm), (4, Step::Complete), (5, Step::Accepted)] {
        phases[index].require_file_echo(step, &exchange.digest()?, &p.digest()?)?;
        assert!(
            phases[index]
                .require_file_echo(Step::Hello, &exchange.digest()?, &p.digest()?)
                .is_err()
        );
        assert!(
            phases[index]
                .require_file_echo(step, &Digest::new(b"foreign"), &p.digest()?)
                .is_err()
        );
        assert!(
            phases[index]
                .require_file_echo(step, &exchange.digest()?, &Digest::new(b"foreign"))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn actual_decode_refuses_nested_array_unknown_duplicate_and_oversized_restore_data() -> Result<()> {
    let (_, app, _, controller, key) = fixtures()?;
    let phases = phases(&app, &controller);
    for (index, paths) in [
        (
            0,
            vec![
                "/body/payload",
                "/body/payload/selection",
                "/body/payload/selection/target",
                "/body/payload/selection/target/scope",
                "/body/payload/controller/stage/data/process",
            ],
        ),
        (
            2,
            vec![
                "/body/payload/exchange",
                "/body/payload/projection",
                "/body/payload/projection/creator",
                "/body/payload/projection/report",
                "/body/payload/projection/ledger",
            ],
        ),
    ] {
        let message = signed(&controller, &key, phases[index].clone());
        let raw = serde_json::to_vec(&message)?;
        let original: Value = crate::json::decode(&raw)?;
        for path in paths {
            let mut changed = original.clone();
            *changed.pointer_mut(path).unwrap() = json!([]);
            assert!(decode(&serde_json::to_vec(&changed)?).is_err(), "{path}");
        }
        let mut changed = original.clone();
        changed["body"]["payload"]["extra"] = json!("not-accepted");
        assert!(decode(&serde_json::to_vec(&changed)?).is_err());
        let raw = String::from_utf8(raw)?;
        let target = "\"phase\":";
        assert_eq!(raw.matches(target).count(), 1);
        let duplicate = raw.replacen(target, "\"phase\":\"ready\",\"phase\":", 1);
        assert!(decode(duplicate.as_bytes()).is_err());
    }
    assert!(decode(&vec![b' '; super::super::protocol::MAX_PACKET + 1]).is_err());
    Ok(())
}

#[test]
fn distinct_app_statement_binds_signed_authorization_process_original_and_controller() -> Result<()>
{
    let (policy, app, key, controller, _) = fixtures()?;
    let now = Duration::from_secs(101);
    let observed = app.admission.statement.process.clone();
    app.validate(&policy, &app.certificate, &observed, now)?;
    app.require_controller(&controller)?;
    app.require_selection(&projection().selection)?;
    app.holder_data()?.validate()?;
    for fault in 0..9 {
        let mut changed = app.clone();
        match fault {
            0 => changed.original.domain = Digest::new(b"foreign-domain"),
            1 => changed.original.origin_ns -= 1,
            2 => changed.original.deadline_ns += 1_000_000_000,
            3 => {
                changed.authorization.statement.data.full_archive =
                    Digest::new(b"foreign-full-archive")
            }
            4 => {
                changed.authorization.statement.data.target.incarnation =
                    Digest::new(b"foreign-target")
            }
            5 => changed.admission.statement.process.process += 1,
            6 => changed.admission.statement.public_key = KeyOwner::generate()?.public(),
            7 => {
                changed.admission.statement.receiver_clock = Digest::new(b"foreign-signed-original")
            }
            _ => changed.certificate.data.nonce = Digest::new(b"another-issuer"),
        }
        assert!(
            changed
                .validate(&policy, &app.certificate, &observed, now)
                .is_err(),
            "fault {fault}"
        );
    }
    assert!(
        app.validate(
            &policy,
            &app.certificate,
            &observed,
            Duration::from_secs(99)
        )
        .is_err()
    );
    assert!(
        app.validate(
            &policy,
            &app.certificate,
            &observed,
            Duration::from_secs(104)
        )
        .is_err()
    );
    let mut another_process = observed.clone();
    another_process.start_ticks += 1;
    assert!(
        app.validate(&policy, &app.certificate, &another_process, now)
            .is_err()
    );
    let mut changed_controller = controller.clone();
    changed_controller.original.domain = Digest::new(b"later-controller");
    assert!(app.require_controller(&changed_controller).is_err());
    let hello = phases(&app, &controller).remove(1);
    let message = signed_app(&app, &key, hello);
    message.verify_restored_app(&app)?;
    let (_, ordinary, _) = fixture(NativeRole::AppHost);
    assert!(message.verify(&ordinary).is_err());
    let mut encoded = serde_json::to_value(&message)?;
    encoded["body"]["payload"]["app"] = serde_json::to_value(ordinary)?;
    assert!(decode(&serde_json::to_vec(&encoded)?).is_err());
    Ok(())
}

#[test]
fn restored_hello_decoder_keeps_every_nested_signed_record_as_an_object() -> Result<()> {
    let (_, app, key, controller, _) = fixtures()?;
    let message = signed_app(&app, &key, phases(&app, &controller).remove(1));
    let raw = serde_json::to_vec(&message)?;
    let original: Value = crate::json::decode(&raw)?;
    for suffix in [
        "",
        "/certificate",
        "/certificate/data",
        "/certificate/data/process",
        "/certificate/data/process/namespaces",
        "/certificate/data/provisioner",
        "/certificate/data/provisioner/namespaces",
        "/authorization",
        "/authorization/statement",
        "/authorization/statement/data",
        "/authorization/statement/data/target",
        "/authorization/statement/data/target/scope",
        "/authorization/statement/data/report",
        "/admission",
        "/admission/statement",
        "/admission/statement/process",
        "/admission/statement/process/namespaces",
        "/admission/statement/runtime",
        "/admission/statement/runtime/container",
        "/original",
    ] {
        let path = format!("/body/payload/app{suffix}");
        let mut changed = original.clone();
        *changed.pointer_mut(&path).unwrap() = json!([]);
        assert!(decode(&serde_json::to_vec(&changed)?).is_err(), "{path}");
    }
    // Duplicate signed members cannot disappear through the Value shape pass.
    let raw = String::from_utf8(raw)?;
    let target = "\"full_archive\":";
    let (prefix, tail) = raw.split_once(target).unwrap();
    let duplicate = format!(
        "{prefix}{target}\"{}\",{target}{tail}",
        Digest::new(b"duplicate").as_str()
    );
    assert!(decode(duplicate.as_bytes()).is_err());
    Ok(())
}

fn observation(now: u64) -> Observation {
    Observation {
        domain: Digest::new(b"one-actual-domain-would-be-native"),
        origin: Duration::from_secs(100),
        deadline: Duration::from_secs(105),
        now: Duration::from_secs(now),
    }
}

#[test]
fn restored_transcript_spends_original_and_never_turns_partial_unknown_or_expired_into_current()
-> Result<()> {
    let expected = [
        Step::BeginReady,
        Step::Hello,
        Step::Offer,
        Step::Confirm,
        Step::Complete,
        Step::Accepted,
        Step::Known,
        Step::Consumed,
        Step::Released,
    ];
    for actor in [Actor::Controller, Actor::App] {
        for cut in 0..9 {
            let mut t = Transcript::new(Protocol::RestoredStorage, actor);
            for expected_step in expected.iter().take(cut) {
                let (direction, frame) = t.next().unwrap();
                assert_eq!(frame.step, *expected_step);
                t.begin(direction, observation(101))?;
                t.delivered(frame, observation(101))?;
            }
            assert!(t.begin_current(1, StagePurpose::CurrentRole).is_err());
            assert!(t.next().is_none());
        }
        let mut t = Transcript::new(Protocol::RestoredStorage, actor);
        for expected_step in expected {
            let (direction, frame) = t.next().unwrap();
            assert_eq!(frame.step, expected_step);
            t.begin(direction, observation(101))?;
            t.delivered(frame, observation(101))?;
        }
        assert!(t.complete());
        t.begin_current(1, StagePurpose::CurrentRole)?;
        assert!(matches!(
            t.next(),
            Some((
                _,
                Frame {
                    protocol: Protocol::CurrentStorage,
                    sequence: Some(1),
                    ..
                }
            ))
        ));
        let mut t = Transcript::new(Protocol::RestoredStorage, actor);
        let (direction, frame) = t.next().unwrap();
        t.begin(direction, observation(101))?;
        assert!(t.transport(Transport::Failed, observation(101)).is_err());
        assert!(t.delivered(frame, observation(101)).is_err());
        let mut t = Transcript::new(Protocol::RestoredStorage, actor);
        let (direction, _) = t.next().unwrap();
        assert!(t.begin(direction, observation(105)).is_err());
        assert!(t.next().is_none());
    }
    let mut shell = Transcript::new(Protocol::RestoredStorage, Actor::Shell);
    assert!(shell.begin(Direction::Receive, observation(101)).is_err());
    Ok(())
}

#[test]
fn signed_real_pod_shapes_pass_without_equating_pod_and_workload_names() -> Result<()> {
    let (policy, app, _, _, _, issuer) = fixtures_with_issuer()?;
    let now = Duration::from_secs(101);
    let observed = app.admission.statement.process.clone();
    let name = &policy.workload(NativeRole::AppHost).workload.name;
    for pod in [format!("{name}-7c4d9f6f7b-abc12"), format!("{name}-0")] {
        assert_ne!(&pod, name);
        let mut changed = app.clone();
        changed.admission.statement.runtime.container.pod_name = pod;
        changed.admission.signature =
            issuer.sign("restore-app-admission-v1", &changed.admission.statement)?;
        changed.validate(&policy, &changed.certificate, &observed, now)?;
    }
    for fault in 0..8 {
        let mut changed = app.clone();
        let runtime = &mut changed.admission.statement.runtime;
        match fault {
            0 => runtime.node_uid = "wrong-node-uid".into(),
            1 => runtime.boot = "another-boot".into(),
            2 => runtime.container.node_name = "wrong-node-name".into(),
            3 => runtime.container.container_name = "wrong-container".into(),
            4 => runtime.container.image = Digest::new(b"wrong-image"),
            5 => runtime.container.pod_name = "bad_name".into(),
            6 => runtime.container.container_id = "a".repeat(64),
            _ => runtime.container.container_id = format!("containerd://{}", "A".repeat(64)),
        }
        changed.admission.signature =
            issuer.sign("restore-app-admission-v1", &changed.admission.statement)?;
        // The signature and temporal binding really pass. The actual runtime
        // selection/shape check must reject this separately signed wrong world.
        changed.admission.verify_data(
            &policy,
            &changed.certificate,
            &changed.authorization,
            now,
        )?;
        assert!(
            changed
                .validate(&policy, &changed.certificate, &observed, now)
                .is_err(),
            "fault {fault}"
        );
    }
    Ok(())
}

#[test]
fn fresh_restore_controller_binding_does_not_turn_expired_cold_grants_into_permission() -> Result<()>
{
    let (policy, mut app, _, mut controller, _, issuer) = fixtures_with_issuer()?;
    fn bind(
        app: &mut RestoreAppStatement,
        controller: &StageStatement,
        issuer: &KeyOwner,
    ) -> Result<()> {
        app.authorization.statement.data.controller = controller.digest()?;
        app.authorization.signature = issuer.sign(
            "restore-controller-authorized-v1",
            &app.authorization.statement,
        )?;
        app.admission.statement.authorization = app.authorization.digest_data()?;
        app.admission.signature =
            issuer.sign("restore-app-admission-v1", &app.admission.statement)?;
        Ok(())
    }
    // The old connection admission is historical. A fresh signed restore
    // attests this exact Current request on its retained original instead.
    controller.stage.data.origin_ns = 94_000_000_000;
    controller.stage.data.deadline_ns = 99_000_000_000;
    controller.stage.signature = issuer.sign("role-stage", &controller.stage.data)?;
    bind(&mut app, &controller, &issuer)?;
    let now = Duration::from_secs(101);
    let sender = controller.stage.data.process.process;
    app.validate_controller_data(&policy, &controller, sender, now)?;
    assert!(
        controller
            .validate_attested_controller(
                &policy,
                &app.certificate,
                sender,
                now,
                StagePurpose::CurrentRole
            )
            .is_err()
    );
    assert!(
        app.validate_controller_data(&policy, &controller, sender + 1, now)
            .is_err()
    );
    for fault in 0..4 {
        let mut changed = controller.clone();
        match fault {
            0 => changed.original.domain = Digest::new(b"different-parent-original"),
            1 => changed.original.origin_ns += 1_000_000_000,
            2 => changed.original.deadline_ns = 101_000_000_000,
            _ => changed.original.deadline_ns = 106_000_000_000,
        }
        let mut rebound = app.clone();
        bind(&mut rebound, &changed, &issuer)?;
        rebound.admission.verify_data(
            &policy,
            &rebound.certificate,
            &rebound.authorization,
            now,
        )?;
        assert!(
            rebound
                .validate_controller_data(&policy, &changed, sender, now)
                .is_err(),
            "fault {fault}"
        );
    }
    assert!(
        app.validate_controller_data(&policy, &controller, sender, Duration::from_secs(104))
            .is_err()
    );
    Ok(())
}

#[test]
fn keeper_ack_requires_exact_exchange_activation_and_complete_cohort_without_granting_custody()
-> Result<()> {
    let (_, app, key, controller, _) = fixtures()?;
    let phases = phases(&app, &controller);
    let RestoreBody::Activated {
        exchange,
        activation,
    } = &phases[6]
    else {
        unreachable!();
    };
    let digest = Digest::of(activation)?;
    let cohort = phases[7].activation_ack(exchange, &digest)?;
    cohort.require_opened_members((9, 10), Some((9, 11)), Some((9, 12)))?;
    assert!(
        cohort
            .require_opened_members((9, 99), Some((9, 11)), Some((9, 12)))
            .is_err()
    );
    assert!(
        phases[7]
            .activation_ack(&Digest::new(b"other-exchange"), &digest)
            .is_err()
    );
    assert!(
        phases[7]
            .activation_ack(exchange, &Digest::new(b"other-activation"))
            .is_err()
    );
    assert!(phases[6].activation_ack(exchange, &digest).is_err());
    let message = signed_app(&app, &key, phases[7].clone());
    let original = serde_json::to_value(message)?;
    for fault in 0..3 {
        let mut changed = original.clone();
        match fault {
            0 => {
                changed["body"]["payload"]
                    .as_object_mut()
                    .unwrap()
                    .remove("cohort");
            }
            1 => changed["body"]["payload"]["cohort"] = json!([[9, 10], [9, 11], [9, 12]]),
            _ => changed["body"]["payload"]["cohort"]["extra"] = json!(true),
        }
        assert!(
            decode(&serde_json::to_vec(&changed)?).is_err(),
            "fault {fault}"
        );
    }
    let mut invalid = original;
    invalid["body"]["payload"]["cohort"]["shm"] = json!([9, 11]);
    let decoded = decode(&serde_json::to_vec(&invalid)?)?;
    let Body::Restore { payload } = decoded.body else {
        unreachable!();
    };
    assert!(payload.activation_ack(exchange, &digest).is_err());
    Ok(())
}

#[test]
fn writer_activation_only_selects_a_read_after_the_signed_phase_and_exact_exchange() -> Result<()> {
    let (_, app, _, controller, controller_key) = fixtures()?;
    let phases = phases(&app, &controller);
    let RestoreBody::Activated {
        exchange,
        activation,
    } = &phases[6]
    else {
        unreachable!();
    };
    let actual = signed(&controller, &controller_key, phases[6].clone());
    let decoded = decode(&serde_json::to_vec(&actual)?)?;
    decoded.verify(&controller)?;
    let Body::Restore { payload } = decoded.body else {
        unreachable!();
    };
    assert!(payload.writer_activation_data(exchange)? == activation.as_ref());
    assert!(
        payload
            .writer_activation_data(&Digest::new(b"different-completed-exchange"))
            .is_err()
    );
    for (index, other) in phases.iter().enumerate() {
        if index != 6 {
            assert!(other.writer_activation_data(exchange).is_err());
        }
    }
    // Even a correctly signed different-exchange message must not unblock
    // the receiving path. These are cryptographic DATA, never a native owner.
    let mut substituted = phases[6].clone();
    let RestoreBody::Activated {
        exchange: selected, ..
    } = &mut substituted
    else {
        unreachable!();
    };
    *selected = Digest::new(b"other-request");
    let wrong = signed(&controller, &controller_key, substituted);
    wrong.verify(&controller)?;
    let Body::Restore { payload } = wrong.body else {
        unreachable!();
    };
    assert!(payload.writer_activation_data(exchange).is_err());
    Ok(())
}

#[test]
fn role_ready_wire_has_a_distinct_purpose_and_exact_signed_completion_chain() -> Result<()> {
    use super::super::protocol::{
        RestoreIssuerCompletionData, RestoreIssuerCompletionStatement,
        SignedRestoreIssuerCompletion,
    };
    use anyhow::Context;
    let (policy, app, app_key, controller, controller_key, issuer) = fixtures_with_issuer()?;
    let old = phases(&app, &controller);
    let RestoreBody::ActivatedAck {
        exchange,
        activation,
        cohort,
    } = &old[7]
    else {
        unreachable!()
    };
    let expected = RestoreIssuerCompletionData {
        frozen: app.authorization.statement.data.frozen.clone(),
        authorization: app.authorization.digest_data()?,
        app: app.digest()?,
        activation: activation.clone(),
        cohort: cohort.clone(),
    };
    let statement = RestoreIssuerCompletionStatement {
        data: expected.clone(),
        request: Digest::new(b"finish-request"),
        challenge: Digest::new(b"finish-challenge"),
        effective_deadline_ns: app
            .original
            .deadline_ns
            .min(app.admission.statement.effective_deadline_ns),
    };
    let completion = SignedRestoreIssuerCompletion {
        signature: issuer.sign("restore-issuer-completed-v1", &statement)?,
        statement,
    };
    let payload = RestoreBody::RoleReady {
        exchange: exchange.clone(),
        completion: Box::new(completion.clone()),
    };
    let now = Duration::from_secs(101);
    payload.role_ready_data(exchange, &expected, &policy, &app.certificate, &app, now)?;
    let message = signed(&controller, &controller_key, payload.clone());
    let encoded = serde_json::to_vec(&message)?;
    ensure!(encoded.len() <= super::super::protocol::MAX_PACKET);
    let decoded = decode(&encoded)?;
    decoded.verify(&controller)?;
    assert!(decoded.verify_restored_app(&app).is_err());
    assert_eq!(
        decoded.body.frame(),
        Frame {
            protocol: Protocol::RestoredRole,
            step: Step::RoleReady,
            sequence: None
        }
    );
    let Body::Restore { payload: decoded } = decoded.body else {
        unreachable!()
    };
    decoded.role_ready_data(exchange, &expected, &policy, &app.certificate, &app, now)?;
    assert!(
        payload
            .role_ready_data(
                &Digest::new(b"foreign-exchange"),
                &expected,
                &policy,
                &app.certificate,
                &app,
                now
            )
            .is_err()
    );
    assert!(
        payload
            .role_ready_data(
                exchange,
                &expected,
                &policy,
                &app.certificate,
                &app,
                Duration::from_nanos(completion.statement.effective_deadline_ns)
            )
            .is_err()
    );
    assert!(
        signed_app(&app, &app_key, payload.clone())
            .verify(&controller)
            .is_err()
    );
    for field in ["frozen", "authorization", "app", "activation", "cohort"] {
        let mut changed = completion.clone();
        match field {
            "frozen" => changed.statement.data.frozen = Digest::new(b"foreign-frozen"),
            "authorization" => {
                changed.statement.data.authorization = Digest::new(b"foreign-authority")
            }
            "app" => changed.statement.data.app = Digest::new(b"foreign-app"),
            "activation" => changed.statement.data.activation = Digest::new(b"foreign-activation"),
            _ => {
                changed.statement.data.cohort =
                    super::super::storage_peer_wire::SqliteCohort::from_identities(
                        (9, 10),
                        (9, 11),
                        (9, 13),
                    )?
            }
        }
        changed.signature = issuer.sign("restore-issuer-completed-v1", &changed.statement)?;
        let payload = RestoreBody::RoleReady {
            exchange: exchange.clone(),
            completion: Box::new(changed),
        };
        let delivered = signed(&controller, &controller_key, payload.clone());
        // A valid outer Controller signature cannot substitute any current
        // completion identity, even with a synthetically re-signed issuer.
        delivered.verify(&controller)?;
        assert!(
            payload
                .role_ready_data(exchange, &expected, &policy, &app.certificate, &app, now)
                .is_err(),
            "{field}"
        );
    }
    assert!(
        old[8]
            .role_ready_data(exchange, &expected, &policy, &app.certificate, &app, now)
            .is_err()
    );
    let positional_records: &[(&str, &[&str])] = &[
        ("/body/payload/completion", &["statement", "signature"]),
        (
            "/body/payload/completion/statement",
            &["data", "request", "challenge", "effective_deadline_ns"],
        ),
        (
            "/body/payload/completion/statement/data",
            &["frozen", "authorization", "app", "activation", "cohort"],
        ),
        (
            "/body/payload/completion/statement/data/cohort",
            &["main", "wal", "shm"],
        ),
    ];
    for (path, fields) in positional_records {
        let mut malformed = serde_json::to_value(&message)?;
        let value = malformed
            .pointer_mut(path)
            .context("actual completion object")?;
        let record = value.as_object().context("closed map fixture")?;
        assert_eq!(record.len(), fields.len());
        let positional = Value::Array(fields.iter().map(|field| record[*field].clone()).collect());
        *value = positional;
        if *path == "/body/payload/completion" {
            // RoleReady already requires a map at this envelope. Prove the
            // standalone signed record is a complete Serde-valid sequence,
            // then distinguish that existing map-only Message boundary.
            assert!(
                serde_json::from_value::<SignedRestoreIssuerCompletion>(
                    malformed.pointer(path).unwrap().clone()
                )
                .is_ok()
            );
            assert!(serde_json::from_value::<Message>(malformed.clone()).is_err());
        } else {
            assert!(
                serde_json::from_value::<Message>(malformed.clone()).is_ok(),
                "complete declared-order sequence {path}"
            );
        }
        assert!(decode(&serde_json::to_vec(&malformed)?).is_err(), "{path}");
    }
    let bytes = String::from_utf8(encoded)?;
    let needle = "\"completion\":";
    ensure!(bytes.matches(needle).count() == 1);
    let duplicate = bytes.replacen(needle, &format!("{needle}null,{needle}"), 1);
    assert!(decode(duplicate.as_bytes()).is_err());
    Ok(())
}

struct RoleDecisionFixture {
    policy: super::super::policy::EnrollmentPolicy,
    app: RestoreAppStatement,
    app_key: KeyOwner,
    controller: StageStatement,
    controller_key: KeyOwner,
    issuer: KeyOwner,
    exchange: Digest,
    completion: super::super::protocol::SignedRestoreIssuerCompletion,
    decision: super::super::protocol::SignedRestoreRoleActivation,
}

fn role_decision_fixture() -> Result<RoleDecisionFixture> {
    use super::super::protocol::{
        RestoreIssuerCompletionData, RestoreIssuerCompletionStatement,
        RestoreRoleActivationStatement, SignedRestoreIssuerCompletion, SignedRestoreRoleActivation,
        SignedStage, StageData, StagePurpose,
    };
    let (policy, app, app_key, controller, controller_key, issuer) = fixtures_with_issuer()?;
    let old = phases(&app, &controller);
    let RestoreBody::ActivatedAck {
        exchange,
        activation,
        cohort,
    } = &old[7]
    else {
        unreachable!()
    };
    let data = RestoreIssuerCompletionData {
        frozen: app.authorization.statement.data.frozen.clone(),
        authorization: app.authorization.digest_data()?,
        app: app.digest()?,
        activation: activation.clone(),
        cohort: cohort.clone(),
    };
    let statement = RestoreIssuerCompletionStatement {
        data,
        request: Digest::new(b"decision-parent-request"),
        challenge: Digest::new(b"decision-parent-challenge"),
        effective_deadline_ns: 104_000_000_000,
    };
    let completion = SignedRestoreIssuerCompletion {
        signature: issuer.sign("restore-issuer-completed-v1", &statement)?,
        statement,
    };
    let request = Digest::new(b"decision-request");
    let challenge = Digest::new(b"decision-challenge");
    let data = StageData {
        issuer: app.certificate.digest()?,
        policy: policy.digest()?,
        role: NativeRole::AppHost,
        purpose: StagePurpose::CurrentRole,
        public_key: app.admission.statement.public_key.clone(),
        request: request.clone(),
        challenge: challenge.clone(),
        process: app.admission.statement.process.clone(),
        runtime: app.admission.statement.runtime.clone(),
        origin_ns: app.original.origin_ns,
        deadline_ns: 103_000_000_000,
    };
    let stage = SignedStage {
        signature: issuer.sign("role-stage", &data)?,
        data,
    };
    let statement = RestoreRoleActivationStatement {
        completion: completion.digest_data()?,
        stage,
        request,
        challenge,
        effective_deadline_ns: 103_000_000_000,
    };
    let decision = SignedRestoreRoleActivation {
        signature: issuer.sign("restore-app-role-activated-v1", &statement)?,
        statement,
    };
    Ok(RoleDecisionFixture {
        policy,
        app,
        app_key,
        controller,
        controller_key,
        issuer,
        exchange: exchange.clone(),
        completion,
        decision,
    })
}

#[test]
fn role_decision_wire_is_separate_exactly_bound_and_cannot_be_an_app_message() -> Result<()> {
    use super::super::protocol::SignedRestoreRoleActivation;
    let RoleDecisionFixture {
        policy,
        app,
        app_key,
        controller,
        controller_key,
        issuer,
        exchange,
        completion,
        decision,
    } = role_decision_fixture()?;
    let exchange = &exchange;
    let payload = RestoreBody::RoleDecision {
        exchange: exchange.clone(),
        decision: Box::new(decision.clone()),
    };
    let now = Duration::from_secs(101);
    payload.role_decision_data(exchange, &completion, &policy, &app.certificate, &app, now)?;
    let message = signed(&controller, &controller_key, payload.clone());
    let encoded = serde_json::to_vec(&message)?;
    ensure!(encoded.len() <= super::super::protocol::MAX_PACKET);
    let decoded = decode(&encoded)?;
    decoded.verify(&controller)?;
    ensure!(decoded.verify_restored_app(&app).is_err());
    ensure!(
        decoded.body.frame()
            == Frame {
                protocol: Protocol::RestoredDecision,
                step: Step::RoleDecision,
                sequence: None
            }
    );
    let wrong = signed_app(&app, &app_key, payload.clone());
    ensure!(wrong.verify_restored_app(&app).is_err());
    ensure!(
        payload
            .role_decision_data(
                &Digest::new(b"wrong-exchange"),
                &completion,
                &policy,
                &app.certificate,
                &app,
                now
            )
            .is_err()
    );
    ensure!(
        payload
            .role_decision_data(
                exchange,
                &completion,
                &policy,
                &app.certificate,
                &app,
                Duration::from_secs(103)
            )
            .is_err()
    );
    let mut foreign_completion = completion.clone();
    foreign_completion.statement.data.activation = Digest::new(b"foreign-activation");
    foreign_completion.signature =
        issuer.sign("restore-issuer-completed-v1", &foreign_completion.statement)?;
    ensure!(
        payload
            .role_decision_data(
                exchange,
                &foreign_completion,
                &policy,
                &app.certificate,
                &app,
                now
            )
            .is_err()
    );
    let mut changed = decision.clone();
    changed.statement.stage.data.public_key = KeyOwner::generate()?.public();
    changed.statement.stage.signature = issuer.sign("role-stage", &changed.statement.stage.data)?;
    changed.signature = issuer.sign("restore-app-role-activated-v1", &changed.statement)?;
    ensure!(
        RestoreBody::RoleDecision {
            exchange: exchange.clone(),
            decision: Box::new(changed)
        }
        .role_decision_data(exchange, &completion, &policy, &app.certificate, &app, now)
        .is_err()
    );
    let records: &[(&str, &[&str])] = &[
        ("/body/payload/decision", &["statement", "signature"]),
        (
            "/body/payload/decision/statement",
            &[
                "completion",
                "stage",
                "request",
                "challenge",
                "effective_deadline_ns",
            ],
        ),
        (
            "/body/payload/decision/statement/stage",
            &["data", "signature"],
        ),
        (
            "/body/payload/decision/statement/stage/data",
            &[
                "issuer",
                "policy",
                "role",
                "purpose",
                "public_key",
                "challenge",
                "request",
                "process",
                "runtime",
                "origin_ns",
                "deadline_ns",
            ],
        ),
        (
            "/body/payload/decision/statement/stage/data/process",
            &["process", "start_ticks", "code", "boot", "namespaces"],
        ),
        (
            "/body/payload/decision/statement/stage/data/runtime",
            &["container", "node_uid", "boot"],
        ),
        (
            "/body/payload/decision/statement/stage/data/runtime/container",
            &[
                "pod_name",
                "pod_uid",
                "node_name",
                "container_name",
                "container_id",
                "image",
                "restart_count",
            ],
        ),
    ];
    let value = serde_json::to_value(&message)?;
    for (path, fields) in records {
        let record = value.pointer(path).unwrap().as_object().unwrap();
        assert_eq!(record.len(), fields.len());
        let positional = Value::Array(fields.iter().map(|field| record[*field].clone()).collect());
        let mut changed = value.clone();
        *changed.pointer_mut(path).unwrap() = positional.clone();
        if *path == "/body/payload/decision" {
            ensure!(serde_json::from_value::<SignedRestoreRoleActivation>(positional).is_ok());
            ensure!(serde_json::from_value::<Message>(changed.clone()).is_err());
        } else {
            ensure!(
                serde_json::from_value::<Message>(changed.clone()).is_ok(),
                "complete declared-order role decision {path}"
            );
        }
        ensure!(
            decode(&serde_json::to_vec(&changed)?).is_err(),
            "actual object boundary {path}"
        );
    }
    let raw = String::from_utf8(encoded)?;
    let needle = "\"decision\":";
    ensure!(raw.matches(needle).count() == 1);
    let duplicate = raw.replacen(needle, &format!("{needle}null,{needle}"), 1);
    ensure!(decode(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn prepared_ack_and_acceptance_bind_exact_issuer_record_cohort_channel_and_sender() -> Result<()> {
    use super::super::protocol::{
        RestorePreparedConfirmationStatement, SignedRestorePreparedConfirmation,
    };
    let RoleDecisionFixture {
        policy,
        app,
        app_key,
        controller,
        controller_key,
        issuer,
        exchange,
        completion,
        decision,
    } = role_decision_fixture()?;
    let statement = RestorePreparedConfirmationStatement {
        issuer: app.certificate.digest()?,
        decision: decision.digest_data()?,
        completion: completion.digest_data()?,
        app: app.digest()?,
        request: Digest::new(b"actual-prepared-request"),
        challenge: Digest::new(b"actual-prepared-challenge"),
        effective_deadline_ns: 102_900_000_000,
    };
    let confirmation = SignedRestorePreparedConfirmation {
        signature: issuer.sign("restore-app-prepared-confirmed-v1", &statement)?,
        statement,
    };
    let cohort = completion.statement.data.cohort.clone();
    let payload = RestoreBody::AppPrepared {
        exchange: exchange.clone(),
        confirmation: Box::new(confirmation.clone()),
        cohort: cohort.clone(),
    };
    let now = Duration::from_secs(102);
    payload.prepared_confirmation_data(&exchange, (&decision, &completion), &policy, &app, now)?;
    let message = signed_app(&app, &app_key, payload.clone());
    let bytes = serde_json::to_vec(&message)?;
    let decoded = decode(&bytes)?;
    decoded.verify_restored_app(&app)?;
    ensure!(decoded.verify(&controller).is_err());
    ensure!(
        decoded.body.frame()
            == Frame {
                protocol: Protocol::RestoredConfirmation,
                step: Step::AppPrepared,
                sequence: None
            }
    );
    ensure!(
        payload
            .prepared_confirmation_data(
                &Digest::new(b"foreign-exchange"),
                (&decision, &completion),
                &policy,
                &app,
                now
            )
            .is_err()
    );
    ensure!(
        payload
            .prepared_confirmation_data(
                &exchange,
                (&decision, &completion),
                &policy,
                &app,
                Duration::from_nanos(102_900_000_000)
            )
            .is_err()
    );
    let mut wrong_cohort = serde_json::to_value(&cohort)?;
    wrong_cohort["main"][1] = Value::from(wrong_cohort["main"][1].as_u64().unwrap() + 1);
    let wrong_cohort: super::super::storage_peer_wire::SqliteCohort =
        serde_json::from_value(wrong_cohort)?;
    let changed = RestoreBody::AppPrepared {
        exchange: exchange.clone(),
        confirmation: Box::new(confirmation.clone()),
        cohort: wrong_cohort.clone(),
    };
    ensure!(
        changed
            .prepared_confirmation_data(&exchange, (&decision, &completion), &policy, &app, now)
            .is_err()
    );
    let mut wrong = confirmation.clone();
    wrong.statement.app = Digest::new(b"different-app");
    wrong.signature = issuer.sign("restore-app-prepared-confirmed-v1", &wrong.statement)?;
    ensure!(
        RestoreBody::AppPrepared {
            exchange: exchange.clone(),
            confirmation: Box::new(wrong),
            cohort: cohort.clone()
        }
        .prepared_confirmation_data(&exchange, (&decision, &completion), &policy, &app, now)
        .is_err()
    );
    let accepted = RestoreBody::PreparedAccepted {
        exchange: exchange.clone(),
        confirmation: confirmation.digest_data()?,
        cohort: Digest::of(&cohort)?,
        effective_deadline_ns: 102_800_000_000,
    };
    assert_eq!(
        accepted.prepared_acceptance_deadline_data(&exchange, &confirmation, &cohort, now)?,
        Duration::from_nanos(102_800_000_000)
    );
    let message = signed(&controller, &controller_key, accepted.clone());
    let decoded = decode(&serde_json::to_vec(&message)?)?;
    decoded.verify(&controller)?;
    ensure!(
        decoded.body.frame()
            == Frame {
                protocol: Protocol::RestoredConfirmation,
                step: Step::PreparedAccepted,
                sequence: None
            }
    );
    ensure!(
        signed_app(&app, &app_key, accepted.clone())
            .verify_restored_app(&app)
            .is_err()
    );
    ensure!(
        accepted
            .prepared_acceptance_deadline_data(
                &Digest::new(b"foreign-acceptance"),
                &confirmation,
                &cohort,
                now
            )
            .is_err()
    );
    ensure!(
        accepted
            .prepared_acceptance_deadline_data(&exchange, &confirmation, &wrong_cohort, now)
            .is_err()
    );
    for ceiling in [102_000_000_000, 102_900_000_001, 0] {
        let wrong = RestoreBody::PreparedAccepted {
            exchange: exchange.clone(),
            confirmation: confirmation.digest_data()?,
            cohort: Digest::of(&cohort)?,
            effective_deadline_ns: ceiling,
        };
        ensure!(
            wrong
                .prepared_acceptance_deadline_data(&exchange, &confirmation, &cohort, now)
                .is_err()
        );
    }
    ensure!(
        accepted
            .prepared_acceptance_deadline_data(
                &exchange,
                &confirmation,
                &cohort,
                Duration::from_nanos(102_800_000_000)
            )
            .is_err()
    );
    let mut other = confirmation.clone();
    other.statement.request = Digest::new(b"another-attempt");
    other.signature = issuer.sign("restore-app-prepared-confirmed-v1", &other.statement)?;
    ensure!(
        accepted
            .prepared_acceptance_deadline_data(&exchange, &other, &cohort, now)
            .is_err()
    );
    let value = serde_json::to_value(signed_app(&app, &app_key, payload))?;
    for (path, fields) in [
        ("/body/payload/confirmation", vec!["statement", "signature"]),
        (
            "/body/payload/confirmation/statement",
            vec![
                "issuer",
                "decision",
                "completion",
                "app",
                "request",
                "challenge",
                "effective_deadline_ns",
            ],
        ),
        ("/body/payload/cohort", vec!["main", "wal", "shm"]),
    ] {
        let record = value.pointer(path).unwrap().as_object().unwrap();
        assert_eq!(record.len(), fields.len());
        let mut changed = value.clone();
        *changed.pointer_mut(path).unwrap() =
            Value::Array(fields.iter().map(|field| record[*field].clone()).collect());
        if path.ends_with("statement") {
            ensure!(serde_json::from_value::<Message>(changed.clone()).is_ok());
        }
        if path.ends_with("cohort") {
            ensure!(
                serde_json::from_value::<super::super::storage_peer_wire::SqliteCohort>(
                    changed.pointer(path).unwrap().clone()
                )
                .is_ok()
            );
        }
        ensure!(decode(&serde_json::to_vec(&changed)?).is_err());
    }
    let raw = serde_json::to_string(&value)?;
    let needle = "\"confirmation\":";
    ensure!(raw.matches(needle).count() == 1);
    ensure!(
        decode(
            raw.replacen(needle, &format!("{needle}null,{needle}"), 1)
                .as_bytes()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn installed_ack_and_acceptance_bind_exact_prepared_cohort_role_and_original_data() -> Result<()> {
    use super::super::protocol::{
        RestorePreparedConfirmationStatement, SignedRestorePreparedConfirmation,
    };
    let RoleDecisionFixture {
        policy,
        app,
        app_key,
        controller,
        controller_key,
        issuer,
        exchange,
        completion,
        decision,
    } = role_decision_fixture()?;
    let statement = RestorePreparedConfirmationStatement {
        issuer: app.certificate.digest()?,
        decision: decision.digest_data()?,
        completion: completion.digest_data()?,
        app: app.digest()?,
        request: Digest::new(b"installed-prepared-request"),
        challenge: Digest::new(b"installed-prepared-challenge"),
        effective_deadline_ns: 102_900_000_000,
    };
    let confirmation = SignedRestorePreparedConfirmation {
        signature: issuer.sign("restore-app-prepared-confirmed-v1", &statement)?,
        statement,
    };
    let ordinary = StageStatement {
        certificate: app.certificate.clone(),
        stage: decision.statement.stage.clone(),
        original: super::super::storage_peer_wire::OriginalInterval {
            purpose: StagePurpose::CurrentRole,
            domain: app.original.domain.clone(),
            origin_ns: app.original.origin_ns,
            deadline_ns: confirmation.statement.effective_deadline_ns,
        },
    };
    let payload = RestoreBody::AppInstalled {
        exchange: exchange.clone(),
        prepared: confirmation.digest_data()?,
        cohort: completion.statement.data.cohort.clone(),
        app: Box::new(ordinary),
    };
    let now = Duration::from_secs(102);
    let validate = |payload: &RestoreBody, now| {
        payload
            .installed_confirmation_data(
                &exchange,
                (&confirmation, &decision, &completion),
                &policy,
                &app,
                now,
            )
            .map(|_| ())
    };
    validate(&payload, now)?;
    let message = signed_app(&app, &app_key, payload.clone());
    let encoded = serde_json::to_vec(&message)?;
    let decoded = decode(&encoded)?;
    decoded.verify_restored_app(&app)?;
    assert!(decoded.verify(&controller).is_err());
    assert_eq!(
        decoded.body.frame(),
        Frame {
            protocol: Protocol::RestoredInstallation,
            step: Step::AppInstalled,
            sequence: None
        }
    );
    for fault in 0..8 {
        let mut changed = payload.clone();
        let RestoreBody::AppInstalled {
            exchange,
            prepared,
            cohort,
            app,
        } = &mut changed
        else {
            unreachable!();
        };
        match fault {
            0 => *exchange = Digest::new(b"other-exchange"),
            1 => *prepared = Digest::new(b"other-prepared"),
            2 => {
                let mut data = serde_json::to_value(&*cohort)?;
                data["main"][1] = Value::from(data["main"][1].as_u64().unwrap() + 1);
                *cohort = serde_json::from_value(data)?;
            }
            3 => app.stage.data.public_key = "other-key".into(),
            4 => app.original.domain = Digest::new(b"other-original"),
            5 => app.original.origin_ns += 1,
            6 => app.original.deadline_ns = confirmation.statement.effective_deadline_ns + 1,
            _ => app.original.purpose = StagePurpose::StorageBootstrap,
        }
        assert!(validate(&changed, now).is_err(), "fault{fault}");
    }
    assert!(
        validate(
            &payload,
            Duration::from_nanos(confirmation.statement.effective_deadline_ns)
        )
        .is_err()
    );
    let accepted = RestoreBody::InstalledAccepted {
        exchange: exchange.clone(),
        installed: payload.installed_digest_data()?,
        cohort: Digest::of(&completion.statement.data.cohort)?,
        effective_deadline_ns: 102_800_000_000,
    };
    accepted.installed_acceptance_deadline_data(&exchange, &payload, now)?;
    let reply = signed(&controller, &controller_key, accepted.clone());
    let decoded = decode(&serde_json::to_vec(&reply)?)?;
    decoded.verify(&controller)?;
    assert_eq!(
        decoded.body.frame(),
        Frame {
            protocol: Protocol::RestoredInstallation,
            step: Step::InstalledAccepted,
            sequence: None
        }
    );
    for fault in 0..5 {
        let mut changed = accepted.clone();
        let RestoreBody::InstalledAccepted {
            exchange: actual_exchange,
            installed,
            cohort,
            effective_deadline_ns,
        } = &mut changed
        else {
            unreachable!();
        };
        match fault {
            0 => *actual_exchange = Digest::new(b"other-exchange"),
            1 => *installed = Digest::new(b"other-installed"),
            2 => *cohort = Digest::new(b"other-cohort"),
            3 => *effective_deadline_ns = confirmation.statement.effective_deadline_ns + 1,
            _ => *effective_deadline_ns = 102_000_000_000,
        }
        assert!(
            changed
                .installed_acceptance_deadline_data(&exchange, &payload, now)
                .is_err(),
            "acceptancefault{fault}"
        );
    }
    let mut positional = serde_json::to_value(&message)?;
    let record = positional
        .pointer("/body/payload/app")
        .unwrap()
        .as_object()
        .unwrap();
    let values = Value::Array(
        ["certificate", "stage", "original"]
            .iter()
            .map(|name| record[*name].clone())
            .collect(),
    );
    *positional.pointer_mut("/body/payload/app").unwrap() = values;
    assert!(decode(&serde_json::to_vec(&positional)?).is_err());
    let mut nested = serde_json::to_value(&message)?;
    let original = nested
        .pointer("/body/payload/app/original")
        .unwrap()
        .as_object()
        .unwrap();
    let positional = Value::Array(
        ["purpose", "domain", "origin_ns", "deadline_ns"]
            .iter()
            .map(|key| original[*key].clone())
            .collect(),
    );
    *nested.pointer_mut("/body/payload/app/original").unwrap() = positional;
    // Generic serde permits this complete declared-order record sequence;
    // the real packet decoder must still enforce the nested object graph.
    assert!(serde_json::from_value::<Message>(nested.clone()).is_ok());
    assert!(decode(&serde_json::to_vec(&nested)?).is_err());
    let raw = String::from_utf8(encoded)?;
    let needle = "\"prepared\":";
    assert_eq!(raw.matches(needle).count(), 1);
    assert!(
        decode(
            raw.replacen(needle, &format!("{needle}null,{needle}"), 1)
                .as_bytes()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn later_current_binding_is_exact_pair_identity_data_and_never_old_clock_permission() -> Result<()>
{
    let RoleDecisionFixture {
        app,
        decision,
        completion,
        exchange,
        ..
    } = role_decision_fixture()?;
    let installed = RestoreBody::AppInstalled {
        exchange: exchange.clone(),
        prepared: Digest::new(b"verified-record-would-be-retained-by-native-owner"),
        cohort: completion.statement.data.cohort,
        app: Box::new(StageStatement {
            certificate: app.certificate,
            stage: decision.statement.stage,
            original: super::super::storage_peer_wire::OriginalInterval {
                purpose: StagePurpose::CurrentRole,
                domain: app.original.domain,
                origin_ns: app.original.origin_ns,
                deadline_ns: app.original.deadline_ns,
            },
        }),
    };
    let acceptance = |installed: &RestoreBody| -> Result<RestoreBody> {
        let RestoreBody::AppInstalled {
            exchange,
            cohort,
            app,
            ..
        } = installed
        else {
            unreachable!();
        };
        Ok(RestoreBody::InstalledAccepted {
            exchange: exchange.clone(),
            installed: installed.installed_digest_data()?,
            cohort: Digest::of(cohort)?,
            effective_deadline_ns: app.original.deadline_ns - 1,
        })
    };
    let reply = acceptance(&installed)?;
    let binding = installed.current_connection_binding_data(&reply)?;
    let roundtrip: RestoreBody = crate::json::decode(&serde_json::to_vec(&installed)?)?;
    assert_eq!(roundtrip.current_connection_binding_data(&reply)?, binding);
    // No timestamp is supplied: expired historical packets remain identity
    // DATA. A native factory must still own their real completed history and
    // a later request must authenticate its own fresh interval and sender.
    let mut expected_worlds = std::collections::BTreeSet::new();
    expected_worlds.insert(binding.clone());
    for fault in 0..6 {
        let mut changed = installed.clone();
        let RestoreBody::AppInstalled {
            exchange,
            prepared,
            cohort,
            app,
        } = &mut changed
        else {
            unreachable!();
        };
        match fault {
            0 => *exchange = Digest::new(b"another-actual-exchange"),
            1 => *prepared = Digest::new(b"another-prepared-record"),
            2 => {
                let mut value = serde_json::to_value(&*cohort)?;
                for member in ["main", "wal", "shm"] {
                    value[member][1] = Value::from(value[member][1].as_u64().unwrap() + 1000);
                }
                *cohort = serde_json::from_value(value)?;
                cohort.validate()?;
            }
            3 => app.original.domain = Digest::new(b"another-historical-domain"),
            4 => app.original.origin_ns += 1,
            _ => app.original.deadline_ns -= 1,
        }
        let changed_reply = acceptance(&changed)?;
        assert!(
            installed
                .current_connection_binding_data(&changed_reply)
                .is_err()
        );
        let other = changed.current_connection_binding_data(&changed_reply)?;
        assert_ne!(other, binding, "fault{fault}");
        assert!(
            expected_worlds.insert(other),
            "constant-or-wrong-world result{fault}"
        );
    }
    for fault in 0..5 {
        let mut changed = reply.clone();
        let RestoreBody::InstalledAccepted {
            exchange,
            installed: echo,
            cohort,
            effective_deadline_ns,
        } = &mut changed
        else {
            unreachable!();
        };
        match fault {
            0 => *exchange = Digest::new(b"another-channel"),
            1 => *echo = Digest::new(b"another-packet"),
            2 => *cohort = Digest::new(b"another-cohort"),
            3 => *effective_deadline_ns = 0,
            _ => *effective_deadline_ns = u64::MAX,
        }
        assert!(installed.current_connection_binding_data(&changed).is_err());
    }
    let mut bootstrap = installed.clone();
    let RestoreBody::AppInstalled { app, .. } = &mut bootstrap else {
        unreachable!();
    };
    app.original.purpose = StagePurpose::StorageBootstrap;
    assert!(
        bootstrap
            .current_connection_binding_data(&acceptance(&bootstrap)?)
            .is_err()
    );
    assert!(reply.current_connection_binding_data(&installed).is_err());
    Ok(())
}
