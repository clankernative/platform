//! Cryptographic protocol DATA only. These fixtures never create a native
//! stage, consumed approval, descriptor, P3, receiving keeper or writer.
use super::*;
use crate::security_epoch::native_enrollment::{
    handshake::{Actor, Direction, Frame, Observation, Protocol, Step, Transcript, Transport},
    protocol::KeyOwner,
    storage_peer_wire::{Body, Message, decode, tests::fixture},
};
use serde_json::{Value, json};
use std::time::Duration;

fn projection() -> Projection {
    let d = |value: &str| Digest::new(value.as_bytes());
    let selection = Selection {
        operation: d("restore-operation"),
        approval_request: d("exact-signed-request"),
        intent: d("intent"),
        full_archive: d("complete-captured-archive"),
        target: TargetBinding {
            scope: day2_capabilities::security_epoch::AuthorityScope {
                installation: "installation".to_owned().try_into().unwrap(),
                environment: "production".to_owned().try_into().unwrap(),
                app: "app".to_owned().try_into().unwrap(),
            },
            binding_generation: 1,
            authority: d("authority"),
            selection: d("selection"),
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

fn phases(app: &StageStatement, controller: &StageStatement) -> Vec<RestoreBody> {
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
            activation,
        },
        RestoreBody::ActivatedAck {
            exchange: x.clone(),
            activation: a.clone(),
        },
        RestoreBody::Released {
            exchange: x,
            activation: a,
        },
    ]
}

#[test]
fn all_nine_signed_restore_phases_are_current_only_and_bind_actual_body() -> Result<()> {
    let (_, app, app_key) = fixture(NativeRole::AppHost);
    let (_, controller, controller_key) = fixture(NativeRole::EpochController);
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
        let (statement, key, wrong) = if matches!(index, 1 | 3 | 5 | 7) {
            (&app, &app_key, &controller)
        } else {
            (&controller, &controller_key, &app)
        };
        let message = signed(statement, key, phase.clone());
        let bytes = serde_json::to_vec(&message)?;
        let decoded = decode(&bytes)?;
        decoded.verify(statement)?;
        assert!(decoded.verify(wrong).is_err());
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
        let mut replacement = signed(statement, key, phase);
        replacement.sender = Digest::new(b"different-signed-stage");
        assert!(replacement.verify(statement).is_err());
    }
    Ok(())
}

#[test]
fn real_selection_nonce_stage_and_projection_helpers_reject_substitution() -> Result<()> {
    let (_, app, _) = fixture(NativeRole::AppHost);
    let (_, controller, _) = fixture(NativeRole::EpochController);
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
    let (_, app, _) = fixture(NativeRole::AppHost);
    let (_, controller, key) = fixture(NativeRole::EpochController);
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
