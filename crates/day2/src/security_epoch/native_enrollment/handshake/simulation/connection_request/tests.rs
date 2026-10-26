use super::*;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde_json::Value;

const MAX_BUNDLE: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    event: Event,
    expected: Option<Refusal>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    version: u8,
    seed: u64,
    steps: Vec<Step>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureKey {
    event: Event,
    expected: Option<Refusal>,
    actual: Option<Refusal>,
    active_before: Option<Request>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    key: FailureKey,
    index: usize,
    states: Vec<Oracle>,
}

fn replay(history: &History) -> Result<Result<Vec<Oracle>, Box<Failure>>> {
    ensure!(
        history.version == 1 && !history.steps.is_empty() && history.steps.len() <= MAX_EVENTS,
        "connection/request history version or event bound"
    );
    let mut oracle = Oracle::default();
    let mut states = Vec::new();
    for (index, step) in history.steps.iter().enumerate() {
        let active_before = oracle.active.as_ref().map(|a| a.request);
        let actual = oracle.observe(&step.event).err();
        states.push(oracle.clone());
        if actual != step.expected {
            return Ok(Err(Box::new(Failure {
                key: FailureKey {
                    event: step.event.clone(),
                    expected: step.expected,
                    actual,
                    active_before,
                },
                index,
                states,
            })));
        }
    }
    Ok(Ok(states))
}

fn reduced(history: &History, key: &FailureKey) -> Result<History> {
    let mut result = history.clone();
    let mut index = 0;
    let mut attempts = 0;
    while index < result.steps.len() && result.steps.len() > 1 && attempts < 128 {
        attempts += 1;
        let mut candidate = result.clone();
        candidate.steps.remove(index);
        if matches!(replay(&candidate)?, Err(ref error) if &error.key == key) {
            result = candidate;
        } else {
            index += 1;
        }
    }
    Ok(result)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u8,
    source: Digest,
    scope: String,
    original: History,
    reduced: History,
    failure: Option<FailureKey>,
    observations: Option<Captured>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Captured {
    original: Box<Failure>,
    reduced: Box<Failure>,
}

fn validate_bundle(bundle: &Bundle) -> Result<()> {
    ensure!(
        bundle.version == 1
            && bundle.scope == "reference_model_only"
            && bundle.source == super::super::implementation()
            && bundle.original.seed == bundle.reduced.seed,
        "connection/request replay source or scope differs"
    );
    ensure!(
        bundle.original.version == 1
            && bundle.reduced.version == 1
            && !bundle.original.steps.is_empty()
            && bundle.original.steps.len() <= MAX_EVENTS
            && !bundle.reduced.steps.is_empty()
            && bundle.reduced.steps.len() <= bundle.original.steps.len(),
        "replay history bound"
    );
    let mut rest = bundle.original.steps.as_slice();
    for step in &bundle.reduced.steps {
        let index = rest
            .iter()
            .position(|candidate| candidate == step)
            .ok_or_else(|| anyhow::anyhow!("reduction is not a deletion of the original"))?;
        rest = &rest[index + 1..];
    }
    match (&bundle.failure, &bundle.observations) {
        (Some(key), Some(captured)) => {
            ensure!(
                &captured.original.key == key && &captured.reduced.key == key,
                "counterexample category differs"
            );
            ensure!(
                replay(&bundle.original)? == Err(captured.original.clone())
                    && replay(&bundle.reduced)? == Err(captured.reduced.clone()),
                "saved complete observations differ"
            );
        }
        (None, None) => {}
        _ => anyhow::bail!("counterexample observations are incomplete"),
    }
    Ok(())
}

fn replay_file(path: &std::path::Path) -> Result<()> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_BUNDLE as u64,
        "bounded regular connection/request replay file required"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_BUNDLE as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BUNDLE, "replay byte bound");
    let wire: Value = crate::json::decode_evidence(&bytes)?;
    ensure!(
        wire.is_object() && wire["original"].is_object() && wire["reduced"].is_object(),
        "connection/request replay object shape"
    );
    let bundle: Bundle = serde_json::from_value(wire.clone())?;
    ensure!(
        wire == serde_json::to_value(&bundle)?,
        "connection/request replay discarded fields"
    );
    validate_bundle(&bundle)?;
    let first = replay(&bundle.reduced)?;
    let second = replay(&bundle.reduced)?;
    ensure!(
        first == second,
        "saved connection/request history is nondeterministic"
    );
    ensure!(
        first.is_ok(),
        "saved connection/request counterexample still fails"
    );
    Ok(())
}

#[test]
fn replay_saved_connection_request_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_CONNECTION_REQUEST_REPLAY") else {
        return Ok(());
    };
    replay_file(std::path::Path::new(&path))
}

fn checked(history: &History) -> Result<Vec<Value>> {
    let first = replay(history)?;
    let second = replay(history)?;
    ensure!(first == second, "reference history did not replay exactly");
    match first {
        Ok(states) => states
            .into_iter()
            .map(|state| serde_json::to_value(state).map_err(Into::into))
            .collect(),
        Err(failure) => {
            let small = reduced(history, &failure.key)?;
            let small_failure = replay(&small)?
                .err()
                .ok_or_else(|| anyhow::anyhow!("reduction lost failure"))?;
            let bundle = Bundle {
                version: 1,
                source: super::super::implementation(),
                scope: "reference_model_only".into(),
                original: history.clone(),
                reduced: small,
                failure: Some(failure.key.clone()),
                observations: Some(Captured {
                    original: failure,
                    reduced: small_failure,
                }),
            };
            validate_bundle(&bundle)?;
            let directory = evidence_root();
            std::fs::create_dir_all(&directory)?;
            let directory = tempfile::Builder::new()
                .prefix("failure-")
                .tempdir_in(directory)?;
            let path = directory.path().join("failure.json");
            let bytes = serde_json::to_vec_pretty(&bundle)?;
            ensure!(bytes.len() <= MAX_BUNDLE, "connection/request bundle bound");
            super::super::retain_failure_bytes(&path, &bytes)?;
            let retained = directory.keep();
            anyhow::bail!(
                "connection/request reference divergence: {}",
                retained.display()
            )
        }
    }
}

fn evidence_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/native-connection-request-simulation")
}

fn ok(event: Event) -> Step {
    Step {
        event,
        expected: None,
    }
}

fn request(sequence: u64, role: Role) -> Request {
    Request {
        connection: 1,
        selection: 0,
        role,
        sequence,
        id: u8::try_from(sequence).unwrap(),
        purpose: if role == Role::App {
            Purpose::Update
        } else {
            Purpose::Approve
        },
    }
}

fn begin(key: Request, now: u64) -> Event {
    Event::Begin {
        request: key,
        original: Original {
            id: key.id,
            domain: 1,
            origin: now,
            deadline: now + FIVE_SECONDS,
        },
        deadline: now + FIVE_SECONDS,
    }
}

fn fresh(steps: &mut Vec<Step>, key: Request, serial: &mut u64) {
    *serial += 1;
    steps.push(ok(Event::Authority { request: key }));
    steps.push(ok(Event::Counters {
        request: key,
        epoch: 1,
        writer: 1,
        version: 1,
        read: *serial,
    }));
}

fn unit(steps: &mut Vec<Step>, key: Request, serial: &mut u64, final_original: bool) {
    steps.push(ok(Event::ArmSql { request: key }));
    fresh(steps, key, serial);
    steps.push(ok(Event::OpenSql { request: key }));
    fresh(steps, key, serial);
    steps.push(ok(Event::CommitSql {
        request: key,
        final_original,
    }));
    steps.push(ok(Event::CloseSql { request: key }));
    fresh(steps, key, serial);
    steps.push(ok(Event::PostcheckSql { request: key }));
}

fn successful(seed: u64, role: Role) -> History {
    let mut steps = vec![ok(Event::Admit {
        connection: 1,
        role,
        checks: [true; 8],
        credential_deadline: 30 * FIVE_SECONDS,
    })];
    let mut serial = 0;
    let mut random = seed;
    let mut now = 0;
    for sequence in 1..=2 {
        let key = request(sequence, role);
        steps.push(ok(begin(key, now)));
        steps.push(ok(Event::Handles { request: key }));
        // An intermediate committed unit must not consume the human original.
        if super::super::next(&mut random).is_multiple_of(2) {
            unit(&mut steps, key, &mut serial, false);
        }
        unit(&mut steps, key, &mut serial, true);
        fresh(&mut steps, key, &mut serial);
        steps.push(ok(Event::Send {
            request: key,
            outcome: Effect::Known,
        }));
        fresh(&mut steps, key, &mut serial);
        steps.push(ok(Event::Release { request: key }));
        // The admission's old five-second interval is over; the next request
        // has its own interval, not a renewal of that admission or request.
        steps.push(ok(Event::Advance {
            nanos: 6_000_000_000,
        }));
        now += 6_000_000_000;
    }
    History {
        version: 1,
        seed,
        steps,
    }
}

fn one_unit() -> History {
    let key = request(1, Role::App);
    let mut steps = vec![
        ok(Event::Admit {
            connection: 1,
            role: Role::App,
            checks: [true; 8],
            credential_deadline: 30 * FIVE_SECONDS,
        }),
        ok(begin(key, 0)),
        ok(Event::Handles { request: key }),
    ];
    let mut serial = 0;
    unit(&mut steps, key, &mut serial, false);
    fresh(&mut steps, key, &mut serial);
    steps.push(ok(Event::Send {
        request: key,
        outcome: Effect::Known,
    }));
    fresh(&mut steps, key, &mut serial);
    steps.push(ok(Event::Release { request: key }));
    History {
        version: 1,
        seed: 0,
        steps,
    }
}

fn expected_suffix(steps: &mut [Step], reason: Refusal) {
    for step in steps {
        if !matches!(
            step.event,
            Event::Fault { .. }
                | Event::RestoreObservedFacts
                | Event::Advance { .. }
                | Event::Rewind { .. }
        ) {
            step.expected = Some(reason);
        }
    }
}

fn faulted(base: &History, cut: usize, fault: Event, reason: Refusal) -> History {
    let mut result = base.clone();
    result.steps.insert(cut, ok(fault));
    expected_suffix(&mut result.steps[cut + 1..], reason);
    result
}

#[test]
fn reference_connection_request_campaign() -> Result<()> {
    let mut histories = 0;
    let mut cases = std::collections::BTreeSet::new();
    for seed in 0..32 {
        for role in [Role::App, Role::Shell] {
            let base = successful(seed, role);
            let states = checked(&base)?;
            let last = states.last().unwrap();
            assert_eq!(last["counts"]["admissions"], 1);
            assert_eq!(last["counts"]["requests"], 2);
            assert_eq!(last["counts"]["sends"], 2);
            assert_eq!(last["counts"]["full_work"], serde_json::json!([0, 0, 0, 0]));
            assert!(last["refused"].is_null() && last["active"].is_null());
            histories += 1;
            cases.insert("two_fresh_requests_one_admission");
            for (index, step) in base.steps.iter().enumerate() {
                if !matches!(step.event, Event::Handles { .. }) {
                    continue;
                }
                for fault in [
                    Fault::PeerDeath,
                    Fault::ChannelClosure,
                    Fault::IssuerDeath,
                    Fault::Restart,
                    Fault::Sender,
                    Fault::Thread,
                    Fault::Namespace,
                    Fault::NamedFile,
                    Fault::Descriptor,
                ] {
                    let mut history =
                        faulted(&base, index, Event::Fault { fault }, Refusal::Handles);
                    history.steps.push(ok(Event::RestoreObservedFacts));
                    history.steps.push(Step {
                        event: begin(request(3, role), 12_000_000_000),
                        expected: Some(Refusal::Handles),
                    });
                    checked(&history)?;
                    histories += 1;
                }
                cases.insert("death_restart_sender_thread_namespace_path_fd_sticky_refusal");
                for fault in [
                    Fault::PeerDeath,
                    Fault::ChannelClosure,
                    Fault::IssuerDeath,
                    Fault::Restart,
                ] {
                    let mut history = base.clone();
                    history.steps.insert(index, ok(Event::Fault { fault }));
                    history
                        .steps
                        .insert(index + 1, ok(Event::RestoreObservedFacts));
                    expected_suffix(&mut history.steps[index + 2..], Refusal::Handles);
                    checked(&history)?;
                    histories += 1;
                }
                cases.insert("replacement_cannot_revive_retained_dead_handle_before_observation");
                checked(&faulted(
                    &base,
                    index,
                    Event::Fault {
                        fault: Fault::Authority,
                    },
                    Refusal::Authority,
                ))?;
                histories += 1;
                cases.insert("fresh_authority_refusal");
                for fault in [Fault::Epoch, Fault::Writer, Fault::Restore] {
                    // The next current-handle check can pass. The first fresh
                    // counter observation must fence the old admitted lineage.
                    let mut history = base.clone();
                    history.steps.insert(index, ok(Event::Fault { fault }));
                    let first_counter = history.steps[index + 1..]
                        .iter()
                        .position(|step| matches!(step.event, Event::Counters { .. }))
                        .unwrap()
                        + index
                        + 1;
                    expected_suffix(&mut history.steps[first_counter..], Refusal::Counter);
                    checked(&history)?;
                    histories += 1;
                }
                cases.insert("epoch_writer_restore_fencing");
                checked(&faulted(
                    &base,
                    index,
                    Event::Advance {
                        nanos: FIVE_SECONDS,
                    },
                    Refusal::Clock,
                ))?;
                histories += 1;
                cases.insert("deadline_equality_refuses");
            }
        }
    }
    cold_admission_rejections_are_not_replaced_by_warm_observations()?;
    cases.insert("cold_admission_and_shared_production_data_transcript");
    request_binding_loss_duplicates_and_consumed_originals_refuse()?;
    cases.insert("request_binding_duplicates_spent_original");
    sql_order_unknown_effect_and_known_result_drop_cannot_release()?;
    cases.insert("sql_order_failure_unknown_send_and_known_result_abandonment");
    cheap_content_assumption_does_not_hide_repeated_full_work()?;
    cases.insert("accepted_content_assumption_and_forbidden_warm_admission_work");
    shared_rewind_earlier_caps_and_observed_refusal_survive_new_requests()?;
    cases.insert("rewind_and_immutable_earlier_original_caps");
    omitted_barriers_rollback_and_counter_loss_refuse()?;
    cases.insert("arming_commit_close_postcheck_fresh_authority_and_counter_barriers");
    cases.insert("rollback_does_not_authorize_provider_send");
    let receipt = serde_json::json!({
        "format":1,"source":super::super::implementation(),"scope":"reference_model_only",
        "seeded_histories":histories,"cases":cases,"seeds":32,"roles":["app","shell"],
        "production_request_wiring_executed":false,"real_linux_owner_executed":false,
        "production_data_handshake_reducer_executed":true,
        "limits":{"events":MAX_EVENTS,"bundle_bytes":MAX_BUNDLE,"reduction_attempts":128},
        "warm_zero_scope":"synthetic_reference_histories_only",
    });
    let directory = evidence_root();
    std::fs::create_dir_all(&directory)?;
    let directory = tempfile::Builder::new()
        .prefix("campaign-")
        .tempdir_in(directory)?;
    super::super::retain_failure_bytes(
        &directory.path().join("receipt.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!(
        "Connection/request reference evidence: {}",
        directory.keep().display()
    );
    Ok(())
}

fn omitted_barriers_rollback_and_counter_loss_refuse() -> Result<()> {
    let base = one_unit();
    let key = request(1, Role::App);
    for cut in 0..5 {
        let mut history = base.clone();
        let removed = history
            .steps
            .iter()
            .position(|s| match cut {
                0 => matches!(s.event, Event::Authority { .. }),
                1 => matches!(s.event, Event::Counters { .. }),
                2 => matches!(s.event, Event::OpenSql { .. }),
                3 => matches!(s.event, Event::CloseSql { .. }),
                _ => matches!(s.event, Event::PostcheckSql { .. }),
            })
            .unwrap();
        history.steps.remove(removed);
        let failing = history
            .steps
            .iter()
            .position(|s| match cut {
                0 | 1 => matches!(s.event, Event::OpenSql { .. }),
                2 => matches!(s.event, Event::CommitSql { .. }),
                3 => matches!(s.event, Event::PostcheckSql { .. }),
                _ => matches!(s.event, Event::Send { .. }),
            })
            .unwrap();
        let reason = match cut {
            0 => Refusal::Authority,
            1 => Refusal::Counter,
            _ => Refusal::SqlOrder,
        };
        expected_suffix(&mut history.steps[failing..], reason);
        checked(&history)?;
    }
    let counter = base
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::Counters { .. }))
        .unwrap();
    let mut loss = base.clone();
    loss.steps[counter].event = Event::CounterFailure;
    expected_suffix(&mut loss.steps[counter..], Refusal::Counter);
    checked(&loss)?;
    let mut duplicate = base.clone();
    duplicate
        .steps
        .insert(counter + 1, duplicate.steps[counter].clone());
    expected_suffix(&mut duplicate.steps[counter + 1..], Refusal::Counter);
    checked(&duplicate)?;
    let mut foreign_request = base.clone();
    let handle = foreign_request
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::Handles { .. }))
        .unwrap();
    foreign_request.steps[handle].event = Event::Handles {
        request: Request {
            id: 99,
            ..request(1, Role::App)
        },
    };
    expected_suffix(&mut foreign_request.steps[handle..], Refusal::Binding);
    checked(&foreign_request)?;
    let commit = base
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::CommitSql { .. }))
        .unwrap();
    let mut rollback = base.clone();
    rollback.steps[commit].event = Event::RollbackSql { request: key };
    let send = rollback
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::Send { .. }))
        .unwrap();
    expected_suffix(&mut rollback.steps[send..], Refusal::SqlOrder);
    checked(&rollback)?;
    // A known rollback can close and finish a no-send read. It cannot grant a
    // provider write. A distinct Inspect request also needs fresh authority.
    rollback.steps.truncate(send);
    rollback.steps.push(ok(Event::Release { request: key }));
    checked(&rollback)?;
    let inspect = Request {
        purpose: Purpose::Inspect,
        ..request(1, Role::App)
    };
    let mut read = History {
        version: 1,
        seed: 0,
        steps: vec![
            base.steps[0].clone(),
            ok(begin(inspect, 0)),
            ok(Event::Handles { request: inspect }),
        ],
    };
    let mut serial = 0;
    fresh(&mut read.steps, inspect, &mut serial);
    read.steps.push(ok(Event::Release { request: inspect }));
    checked(&read)?;
    Ok(())
}

fn cold_admission_rejections_are_not_replaced_by_warm_observations() -> Result<()> {
    for missing in 0..8 {
        let mut checks = [true; 8];
        checks[missing] = false;
        let mut oracle = Oracle::default();
        assert_eq!(
            oracle.observe(&Event::Admit {
                connection: 1,
                role: Role::App,
                checks,
                credential_deadline: FIVE_SECONDS
            }),
            Err(Refusal::Admission)
        );
        oracle.observe(&Event::RestoreObservedFacts).unwrap();
        assert_eq!(
            oracle.observe(&Event::Admit {
                connection: 1,
                role: Role::App,
                checks: [true; 8],
                credential_deadline: FIVE_SECONDS
            }),
            Err(Refusal::Admission)
        );
    }
    // Reuse the real DATA reducer and independent wire-prefix oracle. Neither
    // successful transcript nor this reference acceptance is native admission.
    let mut transcript = super::super::LifecycleHandshake::enrollment(17)?;
    assert!(transcript.exchange(None)?);
    let mut killed = super::super::LifecycleHandshake::enrollment(17)?;
    assert!(!killed.exchange(Some(2))?);
    Ok(())
}

fn request_binding_loss_duplicates_and_consumed_originals_refuse() -> Result<()> {
    let base = successful(3, Role::App);
    let begin_index = base
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::Begin { .. }))
        .unwrap();
    for change in 0..6 {
        let mut history = base.clone();
        let Event::Begin { request, .. } = &mut history.steps[begin_index].event else {
            unreachable!()
        };
        match change {
            0 => request.connection += 1,
            1 => request.role = Role::Shell,
            2 => request.purpose = Purpose::Approve,
            3 => request.sequence += 1,
            4 => request.sequence = 0,
            _ => request.selection = 1,
        }
        expected_suffix(&mut history.steps[begin_index..], Refusal::Binding);
        checked(&history)?;
    }
    let mut duplicate = base.clone();
    duplicate
        .steps
        .insert(begin_index + 1, duplicate.steps[begin_index].clone());
    expected_suffix(&mut duplicate.steps[begin_index + 1..], Refusal::Binding);
    checked(&duplicate)?;
    let committed = base
        .steps
        .iter()
        .position(|s| {
            matches!(
                s.event,
                Event::CommitSql {
                    final_original: true,
                    ..
                }
            )
        })
        .unwrap();
    let postcheck = base.steps[committed + 1..]
        .iter()
        .position(|s| matches!(s.event, Event::PostcheckSql { .. }))
        .unwrap()
        + committed
        + 1;
    let mut spent = base.clone();
    spent.steps.insert(
        postcheck + 1,
        Step {
            event: Event::ArmSql {
                request: request(1, Role::App),
            },
            expected: Some(Refusal::SqlOrder),
        },
    );
    expected_suffix(&mut spent.steps[postcheck + 1..], Refusal::SqlOrder);
    let states = checked(&spent)?;
    assert_eq!(states.last().unwrap()["counts"]["sends"], 0);
    assert_eq!(
        states.last().unwrap()["counts"]["sql_opens"],
        base.steps[..=postcheck]
            .iter()
            .filter(|s| matches!(s.event, Event::OpenSql { .. }))
            .count()
    );
    let mut reused = one_unit();
    for step in &mut reused.steps {
        if let Event::CommitSql { final_original, .. } = &mut step.event {
            *final_original = true;
        }
    }
    let next = begin(request(2, Role::App), 0);
    let Event::Begin {
        request: next_request,
        mut original,
        deadline,
    } = next
    else {
        unreachable!()
    };
    original.id = 1;
    reused.steps.push(Step {
        event: Event::Begin {
            request: next_request,
            original,
            deadline,
        },
        expected: Some(Refusal::Binding),
    });
    checked(&reused)?;
    Ok(())
}

fn sql_order_unknown_effect_and_known_result_drop_cannot_release() -> Result<()> {
    let base = successful(4, Role::App);
    for cut in base.steps.iter().enumerate().filter_map(|(i, s)| {
        matches!(
            s.event,
            Event::OpenSql { .. }
                | Event::CommitSql { .. }
                | Event::CloseSql { .. }
                | Event::PostcheckSql { .. }
                | Event::Send { .. }
        )
        .then_some(i)
    }) {
        let mut failure = base.clone();
        failure.steps.insert(
            cut,
            Step {
                event: Event::SqlFailure,
                expected: Some(Refusal::Unknown),
            },
        );
        expected_suffix(&mut failure.steps[cut..], Refusal::Unknown);
        checked(&failure)?;
    }
    let send = base
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::Send { .. }))
        .unwrap();
    let mut unknown = base.clone();
    unknown.steps[send].event = Event::Send {
        request: request(1, Role::App),
        outcome: Effect::MayHaveBeenSent,
    };
    expected_suffix(&mut unknown.steps[send..], Refusal::Unknown);
    let state = checked(&unknown)?.pop().unwrap();
    assert_eq!(state["active"]["effect"], "may_have_been_sent");
    assert_eq!(state["counts"]["sends"], 1);
    for abandonment in [Event::Drop, Event::Cancel] {
        let mut dropped = base.clone();
        dropped.steps.insert(
            send + 1,
            Step {
                event: abandonment,
                expected: Some(Refusal::Abandoned),
            },
        );
        expected_suffix(&mut dropped.steps[send + 1..], Refusal::Abandoned);
        let state = checked(&dropped)?.pop().unwrap();
        assert_eq!(state["active"]["effect"], "known");
        assert_eq!(state["counts"]["sends"], 1);
    }
    Ok(())
}

fn cheap_content_assumption_does_not_hide_repeated_full_work() -> Result<()> {
    let base = successful(8, Role::App);
    let cut = base
        .steps
        .iter()
        .position(|s| matches!(s.event, Event::Handles { .. }))
        .unwrap();
    let mut drift = base.clone();
    drift.steps.insert(
        cut,
        ok(Event::Fault {
            fault: Fault::ContentDrift,
        }),
    );
    checked(&drift)?;
    for work in [
        FullWork::Executable,
        FullWork::PhysicalAttachment,
        FullWork::ProviderAuthentication,
        FullWork::IssuerEnrollment,
    ] {
        let mut history = base.clone();
        history.steps.insert(
            cut,
            Step {
                event: Event::FullWork { work },
                expected: Some(Refusal::RepeatedAdmission),
            },
        );
        expected_suffix(&mut history.steps[cut..], Refusal::RepeatedAdmission);
        let state = checked(&history)?.pop().unwrap();
        assert_eq!(
            state["counts"]["full_work"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap())
                .sum::<u64>(),
            1
        );
    }
    Ok(())
}

fn shared_rewind_earlier_caps_and_observed_refusal_survive_new_requests() -> Result<()> {
    let base = successful(11, Role::App);
    let second = base
        .steps
        .iter()
        .position(|s| {
            matches!(
                s.event,
                Event::Begin {
                    request: Request { sequence: 2, .. },
                    ..
                }
            )
        })
        .unwrap();
    // Sample the second request's genuinely later clock before rewinding.
    let mut rewind = base.clone();
    rewind
        .steps
        .insert(second + 1, ok(Event::Rewind { nanos: 1 }));
    expected_suffix(&mut rewind.steps[second + 2..], Refusal::Clock);
    checked(&rewind)?;
    let mut earlier = base.clone();
    let Event::Begin {
        original, deadline, ..
    } = &mut earlier.steps[second].event
    else {
        unreachable!()
    };
    original.origin = 0;
    original.deadline = FIVE_SECONDS;
    *deadline = FIVE_SECONDS;
    expected_suffix(&mut earlier.steps[second..], Refusal::Clock);
    checked(&earlier)?;
    let mut extended = base.clone();
    let Event::Begin {
        original, deadline, ..
    } = &mut extended.steps[second].event
    else {
        unreachable!()
    };
    original.deadline = 16_000_000_000;
    *deadline = 11_000_000_001;
    expected_suffix(&mut extended.steps[second..], Refusal::Clock);
    checked(&extended)?;
    let mut expired = base.clone();
    let Event::Admit {
        credential_deadline,
        ..
    } = &mut expired.steps[0].event
    else {
        unreachable!()
    };
    *credential_deadline = 6_000_000_000;
    expected_suffix(&mut expired.steps[second..], Refusal::Clock);
    checked(&expired)?;
    let mut renewed = one_unit();
    renewed.steps.push(ok(Event::Advance {
        nanos: 1_000_000_000,
    }));
    let Event::Begin {
        request,
        mut original,
        deadline,
    } = begin(request(2, Role::App), 1_000_000_000)
    else {
        unreachable!()
    };
    original.id = 1;
    renewed.steps.push(Step {
        event: Event::Begin {
            request,
            original,
            deadline,
        },
        expected: Some(Refusal::Clock),
    });
    checked(&renewed)?;
    Ok(())
}

#[test]
fn replay_identity_deletion_reduction_and_event_bounds_fail_closed() -> Result<()> {
    let mut history = successful(2, Role::App);
    history.steps.last_mut().unwrap().expected = Some(Refusal::Unknown);
    let failure = replay(&history)?.unwrap_err();
    let small = reduced(&history, &failure.key)?;
    assert!(small.steps.len() < history.steps.len());
    let small_failure = replay(&small)?.unwrap_err();
    let mut bundle = Bundle {
        version: 1,
        source: super::super::implementation(),
        scope: "reference_model_only".into(),
        original: history,
        reduced: small,
        failure: Some(failure.key.clone()),
        observations: Some(Captured {
            original: failure,
            reduced: small_failure,
        }),
    };
    validate_bundle(&bundle)?;
    let encoded = serde_json::to_vec(&bundle)?;
    let decoded: Bundle = crate::json::decode_evidence(&encoded)?;
    validate_bundle(&decoded)?;
    let path = tempfile::NamedTempFile::new()?;
    std::fs::write(path.path(), &encoded)?;
    assert!(replay_file(path.path()).is_err());
    let positive = successful(7, Role::Shell);
    let positive = Bundle {
        version: 1,
        source: super::super::implementation(),
        scope: "reference_model_only".into(),
        original: positive.clone(),
        reduced: positive,
        failure: None,
        observations: None,
    };
    std::fs::write(path.path(), serde_json::to_vec(&positive)?)?;
    replay_file(path.path())?;
    let duplicate = serde_json::to_string(&positive)?.replacen('{', "{\"version\":1,", 1);
    std::fs::write(path.path(), duplicate)?;
    assert!(replay_file(path.path()).is_err());
    let positional = serde_json::json!([
        positive.version,
        &positive.source,
        &positive.scope,
        &positive.original,
        &positive.reduced,
        &positive.failure,
        &positive.observations
    ]);
    std::fs::write(path.path(), serde_json::to_vec(&positional)?)?;
    assert!(replay_file(path.path()).is_err());
    path.as_file().set_len(MAX_BUNDLE as u64 + 1)?;
    assert!(replay_file(path.path()).is_err());
    let mut foreign = positive.clone();
    foreign.scope = "native_success".into();
    std::fs::write(path.path(), serde_json::to_vec(&foreign)?)?;
    assert!(replay_file(path.path()).is_err());
    let mut discarded = serde_json::to_value(&positive)?;
    discarded["original"]["steps"][0]["event"] =
        serde_json::json!({"event":"cancel","native_owner":true});
    std::fs::write(path.path(), serde_json::to_vec(&discarded)?)?;
    assert!(replay_file(path.path()).is_err());
    let mut unknown = serde_json::to_value(&positive)?;
    unknown["native_owner"] = serde_json::json!(true);
    std::fs::write(path.path(), serde_json::to_vec(&unknown)?)?;
    assert!(replay_file(path.path()).is_err());
    bundle.reduced.steps[0].event = Event::Advance { nanos: 123456 };
    assert!(validate_bundle(&bundle).is_err());
    bundle.source = Digest::new(b"foreign source");
    assert!(validate_bundle(&bundle).is_err());
    let mut oracle = Oracle::default();
    for _ in 0..MAX_EVENTS {
        oracle.observe(&Event::Advance { nanos: 0 }).unwrap();
    }
    assert_eq!(
        oracle.observe(&Event::RestoreObservedFacts),
        Err(Refusal::Bound)
    );
    let mut overflow = Oracle::default();
    overflow
        .observe(&Event::Advance { nanos: u64::MAX })
        .unwrap();
    assert_eq!(
        overflow.observe(&Event::Advance { nanos: 1 }),
        Err(Refusal::Bound)
    );
    overflow.observe(&Event::RestoreObservedFacts).unwrap();
    assert_eq!(
        overflow.observe(&Event::Admit {
            connection: 1,
            role: Role::App,
            checks: [true; 8],
            credential_deadline: 1
        }),
        Err(Refusal::Bound)
    );
    assert_eq!(
        oracle.observe(&Event::Admit {
            connection: 1,
            role: Role::App,
            checks: [true; 8],
            credential_deadline: 10
        }),
        Err(Refusal::Bound)
    );
    Ok(())
}
