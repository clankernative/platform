//! Multi-step histories of the real conditional-write decisions. Native role,
//! P3 and writer owners cannot be constructed here. The separate Linux fixture
//! adds actual original-file observations to these same schedules.
use super::*;
use crate::security_epoch::{
    bootstrap::check_active_snapshot, journal::snapshot_digest,
    native_enrollment::LifecycleHandshake, storage_authority::lifecycle_fixture,
    tests::lifecycle_provider as counter_fixture,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod model;

const MAX_EVENTS: usize = 96;
const MAX_BUNDLE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Reserve,
    Dispatch,
    Settle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Fault {
    None,
    LostSlotReply,
    MalformedSlotReply,
    ExpiredSlotReply,
    LostCounterBefore,
    LostCounterAfter,
    ExpiredCounterReply,
    AbandonClaim,
    ReplaceCandidate,
    RewriteSlot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum FileChange {
    Tamper,
    Replace,
    AppWrite,
    Restore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct FileState {
    pub named_original: bool,
    pub held_original: bool,
    pub image_exact: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    FirstHolder {
        death_cut: Option<usize>,
    },
    Bootstrap {
        stage: usize,
        operation: Operation,
        fault: Fault,
    },
    Current {
        death_cut: Option<usize>,
        rewrite_provider: bool,
    },
    Observe {
        stage: usize,
    },
    Reopen,
    RestoreClock,
    File {
        change: FileChange,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    seed: u64,
    physical: bool,
    events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    continuation: bool,
    first_holder: bool,
    current: usize,
    slot_posts: usize,
    counter_posts: usize,
    counter: Value,
    slots: Value,
    file: Option<FileState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Record {
    accepted: bool,
    state: State,
    // Complete bounded provider journals and handshake state, compared on
    // replay as well as checking the independently predicted complete rows.
    provider: Value,
    handshake: Value,
}

struct World {
    directory: tempfile::TempDir,
    port: SharedPort,
    selection: EpochStore,
    cores: [LogicalCore; 2],
    continuation: bool,
    first_holder: bool,
    current: usize,
    activation: Option<Digest>,
    handshake: LifecycleHandshake,
    #[cfg(target_os = "linux")]
    file: Option<crate::security_epoch::storage_authority::FileFixture>,
}

impl World {
    fn new(seed: u64, physical: bool) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        ensure!(!physical, "physical lifecycle requires Linux");
        let (selection, create) = fixture();
        let complete = completion(&create);
        let directory = tempfile::tempdir()?;
        let mut port = SharedPort::new();
        port.counter = counter_fixture::open(&directory.path().join("counter.sqlite"));
        port.slots = Provider::open(directory.path().join("slots.sqlite"));
        Ok(Self {
            directory,
            port,
            selection,
            cores: [create, complete],
            continuation: true,
            first_holder: false,
            current: 0,
            activation: None,
            handshake: LifecycleHandshake::new(seed)?,
            #[cfg(target_os = "linux")]
            file: if physical {
                Some(crate::security_epoch::storage_authority::FileFixture::new()?)
            } else {
                None
            },
        })
    }

    fn evidence(
        &mut self,
        core: &LogicalCore,
        purpose: Purpose,
    ) -> Result<(
        firestore::EpochObservation,
        guarded::SlotObservation,
        CurrentBootstrapExecution<'static, 'static>,
    )> {
        let counter = self.port.counter.observe(&core.counter)?;
        // Fixed original interval. Reopening SQLite never resets this to a
        // later sample and no constructor for a native owner is called.
        let context = CurrentBootstrapExecution::fixture(
            &self.selection,
            &core.counter,
            counter.snapshot(),
            purpose,
            Sample {
                domain: Digest::new(b"controller-process-clock"),
                elapsed: Duration::from_secs(100),
            },
        )?;
        let budget = Budget::for_context(self.port.sample()?, Duration::from_secs(105))?;
        let slot = guarded::read_with_budget(&self.selection, core, &mut self.port, budget)?;
        Ok((counter, slot, context))
    }

    fn bootstrap(&mut self, stage: usize, operation: Operation, fault: Fault) -> Result<()> {
        ensure!(
            self.first_holder,
            "fixture first-holder transcript incomplete"
        );
        let mut core = self.cores[stage].clone();
        if fault == Fault::ReplaceCandidate {
            // A well-formed different candidate for the SAME reserved stage.
            // Keep the original fixed request in self.cores for every later
            // readback; replacement never changes the retained candidate.
            if stage == 0 {
                core.seed.incarnations.record = Digest::new(b"replacement-record");
                core.counter = Request::CreateInitialAuthority {
                    bootstrap: core.seed.bootstrap()?,
                };
            } else {
                if let Request::CompleteInitialFirstActivation { holder, .. } = &mut core.counter {
                    holder.process_incarnation = Digest::new(b"replacement-holder");
                }
                let id = complete_operation(&core.counter, &core.seed.digest()?)?;
                if let Request::CompleteInitialFirstActivation { operation, .. } = &mut core.counter
                {
                    *operation = id;
                }
            }
            core = LogicalCore::new(&self.selection, core.policy, core.seed, &core.counter)?;
        }
        let purpose = if operation == Operation::Settle {
            Purpose::Reconcile
        } else {
            Purpose::Dispatch
        };
        let (counter, slot, context) = self.evidence(&core, purpose)?;
        self.port.claim_reply = match fault {
            Fault::LostSlotReply => ClaimReply::LostAfterCommit,
            Fault::MalformedSlotReply => ClaimReply::MalformedAfterCommit,
            Fault::ExpiredSlotReply => ClaimReply::ExpiredAfterCommit,
            _ => ClaimReply::Known,
        };
        match operation {
            Operation::Reserve => {
                let mutation = guarded::accept(
                    &self.selection,
                    core,
                    counter,
                    slot,
                    context,
                    &mut self.port,
                )?;
                mutation.send(&self.selection, &mut self.port)?;
            }
            Operation::Dispatch => {
                let expected = slot.data().context("missing slot")?.version.clone();
                let mutation = guarded::claim(
                    &self.selection,
                    core.clone(),
                    counter,
                    slot,
                    context,
                    attempt(
                        &core,
                        expected,
                        AttemptOrdinal::first(),
                        b"lifecycle-original",
                    ),
                    &mut self.port,
                )?;
                if fault == Fault::RewriteSlot {
                    let name = codec::name(&self.selection, &core)?;
                    self.port
                        .slots
                        .db
                        .execute("UPDATE slots SET version=version+1 WHERE name=?1", [name])?;
                }
                let claim = mutation.send(&self.selection, &mut self.port)?;
                ensure!(
                    fault != Fault::AbandonClaim,
                    "fixture abandoned known claim"
                );
                counter_fixture::lose_before(
                    &mut self.port.counter,
                    fault == Fault::LostCounterBefore,
                );
                self.port.lose_counter_reply = fault == Fault::LostCounterAfter;
                self.port.expire_after_counter_commit = fault == Fault::ExpiredCounterReply;
                claim.send(&self.selection, &mut self.port)?;
            }
            Operation::Settle => {
                let before = slot.data().context("missing slot")?;
                let SlotState::MayHaveBeenSent { attempt } = &before.slot.state else {
                    anyhow::bail!("not May");
                };
                let receipt = core.counter.receipt()?;
                let settlement = SettlementCore {
                    logical: core.digest()?,
                    expected: before.version.clone(),
                    control_attempt: attempt.id.clone(),
                    receipt: receipt.digest()?,
                };
                guarded::settle(
                    &self.selection,
                    core,
                    counter,
                    slot,
                    context,
                    settlement,
                    &mut self.port,
                )?
                .send(&self.selection, &mut self.port)?;
                if stage == 1 {
                    let snapshot = self
                        .port
                        .counter
                        .observe(&self.cores[1].counter)?
                        .into_data();
                    self.activation = Some(snapshot_digest(&snapshot)?);
                }
            }
        }
        Ok(())
    }

    fn current(&mut self, death_cut: Option<usize>, rewrite_provider: bool) -> Result<()> {
        let activation = self.activation.clone().context("activation not settled")?;
        let observed = self
            .port
            .counter
            .observe(&self.cores[1].counter)?
            .into_data();
        check_active_snapshot(
            &self.selection,
            &self.cores[1].counter,
            &activation,
            &observed,
        )?;
        ensure!(
            self.handshake.exchange(death_cut)?,
            "current exchange incomplete"
        );
        if rewrite_provider {
            counter_fixture::rewrite_root(&mut self.port.counter, &self.cores[1].counter);
        }
        let observed = self
            .port
            .counter
            .observe(&self.cores[1].counter)?
            .into_data();
        check_active_snapshot(
            &self.selection,
            &self.cores[1].counter,
            &activation,
            &observed,
        )?;
        self.current += 1;
        Ok(())
    }

    fn step(&mut self, event: Event) -> Result<Record> {
        let accepted = match event {
            Event::Reopen => {
                counter_fixture::reopen(
                    &mut self.port.counter,
                    &self.directory.path().join("counter.sqlite"),
                );
                self.port.slots = Provider::open(self.directory.path().join("slots.sqlite"));
                true
            }
            Event::RestoreClock => {
                self.port
                    .counter
                    .set_slot_fixture_time(Duration::from_secs(100));
                self.port.claim_reply = ClaimReply::Known;
                self.port.lose_counter_reply = false;
                self.port.expire_after_counter_commit = false;
                counter_fixture::lose_before(&mut self.port.counter, false);
                true
            }
            Event::File { change } => {
                #[cfg(target_os = "linux")]
                {
                    self.file
                        .as_mut()
                        .context("physical fixture required")?
                        .change(change)?;
                    true
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = change;
                    anyhow::bail!("physical lifecycle requires Linux");
                }
            }
            Event::Observe { stage } => self
                .port
                .counter
                .observe(&self.cores[stage].counter)
                .and_then(|observed| {
                    crate::security_epoch::kernel::reconcile(
                        &self.selection,
                        &self.cores[stage].counter,
                        observed.snapshot(),
                    )
                })
                .is_ok(),
            event => {
                // This drives the SAME production continuation decision, not a
                // second grant. The operation still uses only DATA contexts.
                let mut continuation = self.continuation;
                let result = lifecycle_fixture::phase(&mut continuation, || {
                    #[cfg(target_os = "linux")]
                    if let Some(file) = &mut self.file {
                        file.check(matches!(event, Event::Current { .. }))?;
                    }
                    match event {
                        Event::FirstHolder { death_cut } => {
                            ensure!(!self.first_holder, "first holder already fixed");
                            ensure!(
                                self.handshake.exchange(death_cut)?,
                                "first-holder exchange incomplete"
                            );
                            self.first_holder = true;
                            Ok(())
                        }
                        Event::Bootstrap {
                            stage,
                            operation,
                            fault,
                        } => self.bootstrap(stage, operation, fault),
                        Event::Current {
                            death_cut,
                            rewrite_provider,
                        } => self.current(death_cut, rewrite_provider),
                        _ => unreachable!(),
                    }?;
                    #[cfg(target_os = "linux")]
                    if let Some(file) = &mut self.file {
                        file.check(matches!(event, Event::Current { .. }))?;
                    }
                    Ok(())
                });
                self.continuation = continuation;
                result.is_ok()
            }
        };
        let counter = counter_fixture::snapshot(&self.port.counter);
        let provider = self.port.slots.replay();
        Ok(Record {
            accepted,
            state: State {
                continuation: self.continuation,
                first_holder: self.first_holder,
                current: self.current,
                slot_posts: self.port.slot_posts,
                counter_posts: self.port.counter_posts,
                counter: json!({"documents":counter["documents"],"sends":counter["sends"]}),
                slots: provider["final_rows"].clone(),
                #[cfg(target_os = "linux")]
                file: self.file.as_ref().map(|file| file.snapshot()).transpose()?,
                #[cfg(not(target_os = "linux"))]
                file: None,
            },
            provider: json!({"counter":counter,"slots":provider}),
            handshake: self.handshake.snapshot(),
        })
    }
}

#[derive(Debug, Serialize)]
struct Divergence {
    index: usize,
    category: &'static str,
    records: Vec<Record>,
    expected: Value,
}

fn run(program: &Program) -> Result<std::result::Result<Vec<Record>, Divergence>> {
    ensure!(
        program.version == 1 && !program.events.is_empty() && program.events.len() <= MAX_EVENTS,
        "lifecycle version/history bound"
    );
    ensure!(
        program.events.iter().all(|e| match e {
            Event::Bootstrap { stage, .. } | Event::Observe { stage } => *stage < 2,
            _ => true,
        }),
        "lifecycle stage bound"
    );
    ensure!(
        program.events.iter().all(|e| match e {
            Event::Bootstrap {
                operation: Operation::Reserve,
                fault,
                ..
            } => matches!(
                fault,
                Fault::None
                    | Fault::LostSlotReply
                    | Fault::MalformedSlotReply
                    | Fault::ExpiredSlotReply
            ),
            Event::Bootstrap {
                operation: Operation::Settle,
                fault,
                ..
            } => matches!(
                fault,
                Fault::None
                    | Fault::LostSlotReply
                    | Fault::MalformedSlotReply
                    | Fault::ExpiredSlotReply
                    | Fault::ReplaceCandidate
            ),
            _ => true,
        }),
        "lifecycle fault/operation bound"
    );
    let mut world = World::new(program.seed, program.physical)?;
    let mut model = model::Model::new(&world.cores, program.physical)?;
    let mut records = Vec::new();
    for (index, &event) in program.events.iter().enumerate() {
        let actual = world.step(event)?;
        let expected = model.step(event)?;
        records.push(actual.clone());
        if (actual.accepted, &actual.state) != (expected.0, &expected.1) {
            return Ok(Err(Divergence {
                index,
                category: "model",
                records,
                expected: serde_json::to_value(expected)?,
            }));
        }
    }
    Ok(Ok(records))
}

fn source() -> Digest {
    Digest::of(&[
        include_str!("lifecycle.rs"),
        include_str!("lifecycle/model.rs"),
        include_str!("../control_slot.rs"),
        include_str!("../control_slot_io.rs"),
        include_str!("../control_slot_firestore.rs"),
        include_str!("../kernel.rs"),
        include_str!("../firestore.rs"),
        include_str!("../journal.rs"),
        include_str!("../bootstrap.rs"),
        include_str!("../storage_authority/preparation/continuity.rs"),
        include_str!("../native_enrollment/handshake.rs"),
        include_str!("../native_enrollment/handshake/simulation.rs"),
        include_str!("../native_enrollment/handshake/simulation/model.rs"),
        include_str!("../native_enrollment/handshake/simulation/lifecycle.rs"),
        include_str!("../tests.rs"),
        include_str!("../tests/lifecycle_provider.rs"),
        include_str!("../control_slot_tests.rs"),
        include_str!("../storage_authority/preparation/tests/lifecycle_file.rs"),
        include_str!("../storage_authority/preparation/continuity/lifecycle_fixture.rs"),
        include_str!("../native_clock.rs"),
        include_str!("../storage_authority/preparation.rs"),
        include_str!("../storage_authority.rs"),
        include_str!("../storage_authority/native_volume.rs"),
        include_str!("../preparation_image.rs"),
        include_str!("../seed_core.rs"),
    ])
    .unwrap()
}

fn replayed(program: &Program) -> Result<std::result::Result<Vec<Record>, Divergence>> {
    let first = match run(program)? {
        Ok(records) => records,
        Err(e) => return Ok(Err(e)),
    };
    let second = match run(program)? {
        Ok(records) => records,
        Err(e) => return Ok(Err(e)),
    };
    if first != second {
        return Ok(Err(Divergence {
            index: 0,
            category: "replay",
            records: first,
            expected: serde_json::to_value(second)?,
        }));
    }
    Ok(Ok(first))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    source: Digest,
    program: Program,
    reduced: Program,
    failure: Value,
}

fn check(program: &Program) -> Result<Vec<Record>> {
    let failure = match replayed(program)? {
        Ok(records) => return Ok(records),
        Err(failure) => failure,
    };
    let mut reduced = program.clone();
    let mut attempts = 0;
    let mut index = 0;
    while index < reduced.events.len() && attempts < 96 && reduced.events.len() > 1 {
        let mut candidate = reduced.clone();
        candidate.events.remove(index);
        attempts += 1;
        if matches!(replayed(&candidate)?, Err(ref e) if e.category == failure.category) {
            reduced = candidate;
        } else {
            index += 1;
        }
    }
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/storage-lifecycle-simulation");
    std::fs::create_dir_all(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("failure-")
        .tempdir_in(root)?
        .keep();
    let bundle = Bundle {
        version: 1,
        source: source(),
        program: program.clone(),
        reduced,
        failure: serde_json::to_value(&failure)?,
    };
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    ensure!(
        bytes.len() as u64 <= MAX_BUNDLE,
        "lifecycle failure bundle bound"
    );
    std::fs::write(directory.join("failure.json"), bytes)?;
    anyhow::bail!(
        "storage lifecycle {} divergence at event {}; replay {}",
        failure.category,
        failure.index,
        directory.join("failure.json").display()
    )
}

fn next(random: &mut u64) -> u64 {
    *random = random.wrapping_add(0x9e3779b97f4a7c15);
    let mut n = *random;
    n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    n = (n ^ (n >> 27)).wrapping_mul(0x94d049bb133111eb);
    n ^ (n >> 31)
}

fn successful(seed: u64) -> Program {
    let mut random = seed;
    let mut events = vec![Event::FirstHolder { death_cut: None }];
    for stage in 0..2 {
        for operation in [Operation::Reserve, Operation::Dispatch, Operation::Settle] {
            if next(&mut random).is_multiple_of(2) {
                events.push(Event::Reopen);
            }
            events.push(Event::Bootstrap {
                stage,
                operation,
                fault: Fault::None,
            });
            events.push(Event::Observe { stage });
        }
    }
    for _ in 0..3 {
        events.push(Event::Current {
            death_cut: None,
            rewrite_provider: false,
        });
        if next(&mut random).is_multiple_of(2) {
            events.push(Event::Reopen);
        }
    }
    Program {
        version: 1,
        seed,
        physical: false,
        events,
    }
}

#[test]
fn seeded_storage_first_holder_activation_and_current_histories_replay() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..32 {
        let records = check(&successful(seed))?;
        let final_state = &records.last().unwrap().state;
        ensure!(
            final_state.current == 3 && final_state.continuation,
            "successful lifecycle missing current releases"
        );
        for record in &records {
            coverage.insert((
                record.state.slot_posts,
                record.state.counter_posts,
                record.state.current,
            ));
        }
    }
    ensure!(
        coverage.contains(&(6, 2, 3)),
        "lifecycle transition coverage"
    );
    Ok(())
}

#[test]
fn every_bootstrap_cut_keeps_unknown_completion_candidate_and_refusal_across_reopen() -> Result<()>
{
    let mut coverage = BTreeSet::new();
    for seed in 0..8 {
        let baseline = successful(seed);
        for (index, event) in baseline.events.iter().enumerate() {
            let Event::Bootstrap {
                stage, operation, ..
            } = *event
            else {
                continue;
            };
            let faults: &[Fault] = if operation == Operation::Dispatch {
                &[
                    Fault::LostSlotReply,
                    Fault::MalformedSlotReply,
                    Fault::ExpiredSlotReply,
                    Fault::LostCounterBefore,
                    Fault::LostCounterAfter,
                    Fault::ExpiredCounterReply,
                    Fault::AbandonClaim,
                    Fault::ReplaceCandidate,
                    Fault::RewriteSlot,
                ]
            } else if operation == Operation::Reserve {
                &[
                    Fault::LostSlotReply,
                    Fault::MalformedSlotReply,
                    Fault::ExpiredSlotReply,
                ]
            } else {
                &[
                    Fault::LostSlotReply,
                    Fault::MalformedSlotReply,
                    Fault::ExpiredSlotReply,
                    Fault::ReplaceCandidate,
                ]
            };
            for &fault in faults {
                let mut program = baseline.clone();
                program.events.truncate(index);
                program.events.push(Event::Bootstrap {
                    stage,
                    operation,
                    fault,
                });
                program.events.extend([
                    Event::Reopen,
                    Event::RestoreClock,
                    Event::Observe { stage },
                    Event::Bootstrap {
                        stage,
                        operation,
                        fault: Fault::None,
                    },
                    Event::Current {
                        death_cut: None,
                        rewrite_provider: false,
                    },
                ]);
                let records = check(&program)?;
                ensure!(
                    !records.last().unwrap().state.continuation,
                    "refused lifecycle resumed"
                );
                coverage.insert(format!("{stage}-{operation:?}-{fault:?}"));
            }
        }
    }
    ensure!(
        coverage.len() == 32,
        "fault cuts not actually observed: {}",
        coverage.len()
    );
    Ok(())
}

#[test]
fn generated_peer_death_and_provider_rewrite_cannot_rearm_current_continuity() -> Result<()> {
    for seed in 0..32 {
        let mut random = seed;
        let mut program = successful(seed);
        let current = program
            .events
            .iter()
            .position(|e| matches!(e, Event::Current { .. }))
            .unwrap();
        let cut = next(&mut random) as usize % current;
        if seed.is_multiple_of(3) {
            program.events[0] = Event::FirstHolder {
                death_cut: Some(cut),
            };
        } else {
            program.events[current] = Event::Current {
                death_cut: if seed.is_multiple_of(2) {
                    Some(cut)
                } else {
                    None
                },
                rewrite_provider: !seed.is_multiple_of(2),
            };
        }
        program.events.extend([
            Event::Reopen,
            Event::RestoreClock,
            Event::Current {
                death_cut: None,
                rewrite_provider: false,
            },
        ]);
        let records = check(&program)?;
        ensure!(
            !records.last().unwrap().accepted && !records.last().unwrap().state.continuation,
            "current refusal resurrected"
        );
    }
    Ok(())
}

#[test]
fn seeded_adversarial_multistep_histories_check_every_result_and_durable_row() -> Result<()> {
    for seed in 0..32 {
        let mut random = seed;
        let mut program = successful(seed);
        let prefix = next(&mut random) as usize % program.events.len();
        program.events.truncate(prefix);
        for _ in 0..40 {
            let stage = next(&mut random) as usize % 2;
            let event = match next(&mut random) % 8 {
                0 => Event::Reopen,
                1 => Event::RestoreClock,
                2 => Event::Observe { stage },
                3 => Event::FirstHolder { death_cut: None },
                4 => Event::Current {
                    death_cut: Some(next(&mut random) as usize % 100),
                    rewrite_provider: false,
                },
                5 => Event::Current {
                    death_cut: None,
                    rewrite_provider: next(&mut random).is_multiple_of(2),
                },
                n => Event::Bootstrap {
                    stage,
                    operation: [Operation::Reserve, Operation::Dispatch, Operation::Settle]
                        [next(&mut random) as usize % 3],
                    fault: if n == 6 {
                        Fault::None
                    } else {
                        Fault::LostSlotReply
                    },
                },
            };
            program.events.push(event);
        }
        check(&program)?;
    }
    Ok(())
}

#[test]
fn replay_saved_storage_lifecycle_history() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_STORAGE_LIFECYCLE_REPLAY") else {
        return Ok(());
    };
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_BUNDLE,
        "lifecycle replay byte bound"
    );
    let bundle: Bundle = serde_json::from_reader(file)?;
    ensure!(
        bundle.version == 1 && bundle.source == source(),
        "lifecycle replay source/version mismatch"
    );
    check(&bundle.program)?;
    check(&bundle.reduced)?;
    Ok(())
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(32))]
    #[test]
    fn arbitrary_reachable_prefixes_preserve_durable_rows_and_permanent_refusal(
        seed in proptest::prelude::any::<u64>(),
        choices in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..32),
    ) {
        let mut program = successful(seed);
        program.events.truncate(seed as usize % program.events.len());
        for choice in choices {
            program.events.push(match choice % 7 {
                0 => Event::Reopen,
                1 => Event::RestoreClock,
                2 => Event::Observe { stage: usize::from(choice % 2) },
                3 => Event::Current { death_cut: None, rewrite_provider: false },
                4 => Event::FirstHolder { death_cut: Some(usize::from(choice)) },
                _ => Event::Bootstrap {
                    stage: usize::from(choice % 2),
                    operation: [Operation::Reserve, Operation::Dispatch, Operation::Settle][usize::from(choice % 3)],
                    fault: Fault::None,
                },
            });
        }
        let result = check(&program);
        proptest::prop_assert!(result.is_ok(), "{}", result.err().unwrap());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn generated_real_file_histories_join_the_same_first_holder_and_writer_decisions() -> Result<()> {
    for seed in 0..4 {
        let mut baseline = successful(seed);
        baseline.physical = true;
        check(&baseline)?;
        for change in [FileChange::Tamper, FileChange::Replace] {
            let mut random = seed;
            let cuts = baseline
                .events
                .iter()
                .enumerate()
                .filter_map(|(i, e)| {
                    (matches!(e, Event::Bootstrap { .. })
                        || (change == FileChange::Replace && matches!(e, Event::Current { .. })))
                    .then_some(i)
                })
                .collect::<Vec<_>>();
            let index = if change == FileChange::Replace && seed.is_multiple_of(2) {
                *cuts
                    .iter()
                    .find(|&&i| matches!(baseline.events[i], Event::Current { .. }))
                    .unwrap()
            } else {
                cuts[next(&mut random) as usize % cuts.len()]
            };
            let mut program = baseline.clone();
            program.events.truncate(index);
            program.events.extend([
                Event::File { change },
                baseline.events[index],
                Event::File {
                    change: FileChange::Restore,
                },
                Event::Reopen,
                Event::RestoreClock,
                baseline.events[index],
            ]);
            let records = check(&program)?;
            ensure!(
                !records.last().unwrap().state.continuation,
                "restored real file revived continuation"
            );
        }
        // A legitimate same-inode SQLite mutation is accepted by current
        // physical checks, while initial-image admission stays exact.
        let mut current = baseline;
        let index = current
            .events
            .iter()
            .position(|e| matches!(e, Event::Current { .. }))
            .unwrap();
        current.events.insert(
            index,
            Event::File {
                change: FileChange::AppWrite,
            },
        );
        ensure!(
            check(&current)?.last().unwrap().state.current == 3,
            "physical current check rejected legitimate SQLite write"
        );
    }
    Ok(())
}
