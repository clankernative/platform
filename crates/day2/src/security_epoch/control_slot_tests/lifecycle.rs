//! Multi-step histories of the real conditional-write decisions. Native role,
//! P3 and writer owners cannot be constructed here. The separate Linux fixture
//! adds actual original-file observations to these same schedules.
use super::*;
use crate::security_epoch::{
    bootstrap::check_active_snapshot,
    journal::snapshot_digest,
    native_enrollment::{
        LifecycleHandshake, LifecycleModelError, LifecycleProgress, LifecycleReference,
    },
    storage_authority::lifecycle_fixture,
    tests::lifecycle_provider as counter_fixture,
};
use crate::simulation::coverage::{self as dst, Campaign, Transition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod model;
pub(in crate::security_epoch) mod preparation;
use preparation::{PreparationFiles, PreparationInput, PreparationObservation};

const MAX_EVENTS: usize = 96;
// The original ordinary history budget remains separate from one explicitly
// stepped bounded wire schedule; no native acquisition budget is changed.
const MAX_HANDSHAKE_ADVANCES: usize = 512;
const MAX_BUNDLE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Reserve,
    Dispatch,
    Settle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "work", rename_all = "snake_case", deny_unknown_fields)]
enum CompletionWork {
    Bootstrap {
        stage: usize,
        operation: Operation,
        fault: Fault,
    },
    Current {
        rewrite_provider: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompletionPhase {
    Wire,
    Mutation,
    AfterMutation,
    Release,
    Releasing,
    FinalFile,
    Complete,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionState {
    work: CompletionWork,
    phase: CompletionPhase,
    mutation_known: bool,
    consumed_checked: bool,
    peer_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Fault {
    None,
    LostSlotReply,
    MalformedSlotReply,
    ExpiredSlotReply,
    RewoundSlotClock,
    ForwardSlotClock,
    LostCounterBefore,
    LostCounterAfter,
    RolledBackCounterWrite,
    MalformedCounterReply,
    ExpiredCounterReply,
    RewoundCounterClock,
    ForwardCounterClock,
    AbandonClaim,
    ReplaceCandidate,
    RewriteSlot,
    FileTamperAfter,
    FileReplaceAfter,
    FileShortenAfter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CounterRecord {
    Authority,
    Sentinel,
    CreateReceipt,
    ActivationReceipt,
    OutsideSelection,
}

impl CounterRecord {
    const ALL: [Self; 5] = [
        Self::Authority,
        Self::Sentinel,
        Self::CreateReceipt,
        Self::ActivationReceipt,
        Self::OutsideSelection,
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum FileChange {
    Tamper,
    Replace,
    AppWrite,
    Shorten,
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
    PrepareOriginal {
        input: PreparationInput,
    },
    RestorePreparation {},
    FirstHolder {
        death_cut: Option<usize>,
    },
    StartFirstHolder {
        death_cut: Option<usize>,
    },
    AdvanceFirstHolder,
    ObserveFirstHolder {
        work_nanos: u64,
    },
    RetainFirstHolder {
        work_nanos: u64,
    },
    FileTime {
        nanos: u64,
    },
    FileRewind {
        nanos: u64,
    },
    StartCompletion {
        work: CompletionWork,
        death_cut: Option<usize>,
    },
    AdvanceCompletion,
    MutateCompletion,
    PrepareCompletionRelease,
    FinishCompletion,
    LosePacket {
        sender: usize,
    },
    WorkTime {
        wire_nanos: u64,
        provider_nanos: u64,
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
    CounterReplace {
        record: CounterRecord,
    },
    CounterRestore {
        record: CounterRecord,
    },
    File {
        change: FileChange,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HolderPhase {
    NotStarted,
    BeforeOffer,
    AppObservation,
    AfterAppObservation,
    ControllerRetention,
    Retained,
    Refused,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    seed: u64,
    // Complete immutable initial image DATA. Initializers contain real
    // authority entropy and temporary artifact paths, so replay must retain
    // the input bytes rather than initialize a different image each time.
    physical: Option<Vec<u8>>,
    events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    binding: Digest,
    continuation: bool,
    first_holder: bool,
    checked_accepted: bool,
    holder_phase: HolderPhase,
    completion: Option<CompletionState>,
    // Controlled environment tick in the independent provider fixture's
    // controller-process-clock domain, never a fresh native clock witness.
    provider_time: Duration,
    current: usize,
    slot_posts: usize,
    counter_posts: usize,
    counter_rollback_failures: usize,
    // Fixed primary budget category in the controlled port, not a native
    // clock witness. These schedules keep the domain unchanged.
    clock_order_failures: usize,
    // Actual primary counter acknowledgement codec failures, not native DATA
    // or a generic refusal. The model predicts this independently.
    counter_decode_failures: usize,
    counter: Value,
    slots: Value,
    file: Option<FileState>,
    preparation: Option<PreparationObservation>,
    preparation_files: Option<PreparationFiles>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Record {
    accepted: bool,
    state: State,
    // Complete bounded provider journals and handshake state, compared on
    // replay as well as checking the independently predicted complete rows.
    provider: Value,
    handshake: Value,
    reference: Option<Value>,
}

struct World {
    directory: tempfile::TempDir,
    port: SharedPort,
    selection: EpochStore,
    cores: [LogicalCore; 2],
    image_binding: Option<Digest>,
    continuation: bool,
    first_holder: bool,
    checked_accepted: bool,
    holder_phase: HolderPhase,
    completion: Option<CompletionState>,
    current: usize,
    activation: Option<Digest>,
    counter_rollback_failures: usize,
    clock_order_failures: usize,
    counter_decode_failures: usize,
    replaced: BTreeMap<CounterRecord, Option<Value>>,
    handshake: LifecycleHandshake,
    #[cfg(target_os = "linux")]
    file: Option<crate::security_epoch::storage_authority::FileFixture>,
}

fn is_primary_budget_order_failure(error: &anyhow::Error) -> bool {
    // Test-only closed classification of the actual budget producer. Never
    // serialize the formatted error or accept an outer context as its cause.
    error.root_cause().to_string() == "security_epoch_clock_domain_or_rewind"
}

fn is_fixture_mid_commit_failure(error: &anyhow::Error) -> bool {
    // Pinned anyhow stores the fixture's bare bail!("literal") as &'static str.
    // Refuse wrappers/lookalikes rather than formatting an unknown error or
    // mistaking an outer context label for the actual primary fixture cause.
    error.chain().count() == 1
        && error
            .downcast_ref::<&'static str>()
            .is_some_and(|message| *message == "scripted mid-commit failure")
}

fn checked_file_observation(
    handshake: &mut LifecycleHandshake,
    endpoint: usize,
    work_nanos: u64,
    observe: impl FnOnce() -> Result<()>,
) -> Result<()> {
    ensure!(
        handshake.check_file_boundary(endpoint)?,
        "first holder original precheck refused"
    );
    let requested = observe();
    let elapsed = if work_nanos == 0 {
        Ok(())
    } else {
        handshake.advance_file_time(work_nanos)
    };
    // Evaluate the postcheck even when file work failed. Preserve its original
    // primary error; the caller separately quarantines a model-execution error.
    let checked = handshake.check_file_boundary(endpoint);
    requested?;
    elapsed?;
    ensure!(checked?, "first holder original postcheck refused");
    Ok(())
}

#[test]
fn fixture_rollback_classification_never_formats_or_replaces_unknown_errors() {
    struct Opaque;
    impl std::fmt::Display for Opaque {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign Display must not run")
        }
    }
    impl std::fmt::Debug for Opaque {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign Debug must not run")
        }
    }
    impl std::error::Error for Opaque {}

    let fixed = anyhow::anyhow!("scripted mid-commit failure");
    let primary = fixed.root_cause();
    assert!(is_fixture_mid_commit_failure(&fixed));
    assert!(std::ptr::eq(primary, fixed.root_cause()));
    for unknown in [
        anyhow::anyhow!("another fixture failure"),
        anyhow::Error::msg("scripted mid-commit failure".to_owned()),
        anyhow::Error::new(Opaque),
        anyhow::Error::new(Opaque).context("scripted mid-commit failure"),
    ] {
        let primary = unknown.root_cause();
        assert!(!is_fixture_mid_commit_failure(&unknown));
        assert!(std::ptr::eq(primary, unknown.root_cause()));
    }
}

// Shared immutable fixture inputs only, never a transition or native owner.
fn consumer_completion_core(selection: &EpochStore, create: &LogicalCore) -> Result<LogicalCore> {
    let mut counter = Request::CompleteInitialFirstActivation {
        bootstrap: create.counter.bootstrap().clone(),
        operation: Digest::new(b"uncomputed"),
        parent_receipt: create.counter.receipt()?.digest()?,
        before: Versions {
            root: version(1),
            sentinel: version(1),
        },
        holder: Holder {
            principal: Digest::new(b"app-principal"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"original-app-process"),
            ephemeral_key: Digest::new(b"original-app-key"),
        },
    };
    let operation = complete_operation(&counter, &create.seed.digest()?)?;
    if let Request::CompleteInitialFirstActivation { operation: id, .. } = &mut counter {
        *id = operation;
    }
    LogicalCore::new(
        selection,
        create.policy.clone(),
        create.seed.clone(),
        &counter,
    )
}

impl World {
    fn new(seed: u64, physical: Option<&[u8]>) -> Result<Self> {
        Self::selected(seed, physical, None)
    }

    fn selected(
        seed: u64,
        physical: Option<&[u8]>,
        scope: Option<&day2_capabilities::security_epoch::AuthorityScope>,
    ) -> Result<Self> {
        ensure!(
            physical.is_none() || scope.is_none(),
            "physical fixture scope is fixed"
        );
        let portable = || {
            let mut selection = tests::selection();
            if let Some(scope) = scope {
                selection.scope = scope.clone();
            }
            fixture_for_store(selection)
        };
        #[cfg(not(target_os = "linux"))]
        ensure!(physical.is_none(), "physical lifecycle requires Linux");
        #[cfg(target_os = "linux")]
        let file = physical
            .map(crate::security_epoch::storage_authority::FileFixture::new)
            .transpose()?;
        #[cfg(target_os = "linux")]
        let (selection, create, image_binding) = if let Some(file) = &file {
            let (policy, store, original, image) = file.proposed_blueprint()?;
            let request = Request::CreateInitialAuthority {
                bootstrap: original.bootstrap()?,
            };
            let core = LogicalCore::new(&store, policy, original, &request)?;
            (store, core, Some(image))
        } else {
            let (store, core) = portable();
            (store, core, None)
        };
        #[cfg(not(target_os = "linux"))]
        let (selection, create) = portable();
        #[cfg(not(target_os = "linux"))]
        let image_binding = None;
        let mut expected_selection = tests::selection();
        if let Some(scope) = scope {
            expected_selection.scope = scope.clone();
        }
        ensure!(
            selection == expected_selection,
            "conditional fixture provider selection changed"
        );
        let complete = consumer_completion_core(&selection, &create)?;
        let directory = tempfile::tempdir()?;
        let mut port = SharedPort::new();
        port.counter = counter_fixture::open(&directory.path().join("counter.sqlite"));
        port.slots = Provider::open(directory.path().join("slots.sqlite"));
        Ok(Self {
            directory,
            port,
            selection,
            cores: [create, complete],
            image_binding,
            continuation: true,
            first_holder: false,
            checked_accepted: false,
            holder_phase: HolderPhase::NotStarted,
            completion: None,
            current: 0,
            activation: None,
            counter_rollback_failures: 0,
            clock_order_failures: 0,
            counter_decode_failures: 0,
            replaced: BTreeMap::new(),
            handshake: LifecycleHandshake::new(seed)?,
            #[cfg(target_os = "linux")]
            file,
        })
    }

    fn first_holder_step(&mut self, event: Event) -> Result<()> {
        match event {
            Event::StartFirstHolder { death_cut } => {
                ensure!(
                    self.holder_phase == HolderPhase::NotStarted && !self.first_holder,
                    "first holder already started"
                );
                #[cfg(target_os = "linux")]
                if let Some(file) = &mut self.file {
                    file.check(false)?;
                }
                self.handshake.begin_exchange(death_cut, 0)?;
                self.holder_phase = HolderPhase::BeforeOffer;
            }
            Event::AdvanceFirstHolder => {
                ensure!(
                    matches!(
                        self.holder_phase,
                        HolderPhase::BeforeOffer | HolderPhase::AfterAppObservation
                    ),
                    "first holder file obligation pending"
                );
                ensure!(
                    self.handshake.progress()? != LifecycleProgress::Refused,
                    "first holder peer refused"
                );
                self.handshake.advance_exchange()?;
                ensure!(
                    self.handshake.progress()? != LifecycleProgress::Refused,
                    "first holder peer refused"
                );
                if self.handshake.controller_accepted_checked()? {
                    self.checked_accepted = true;
                    ensure!(
                        self.holder_phase == HolderPhase::AfterAppObservation,
                        "first holder App observation missing"
                    );
                    self.holder_phase = HolderPhase::ControllerRetention;
                } else if self.holder_phase == HolderPhase::BeforeOffer
                    && self.handshake.app_observation_ready()?
                {
                    self.holder_phase = HolderPhase::AppObservation;
                }
            }
            Event::ObserveFirstHolder { work_nanos } => {
                ensure!(
                    self.holder_phase == HolderPhase::AppObservation
                        && self.handshake.app_observation_ready()?,
                    "first holder App observation order"
                );
                checked_file_observation(&mut self.handshake, 0, work_nanos, || {
                    #[cfg(target_os = "linux")]
                    if let Some(file) = &mut self.file {
                        file.check(false)?;
                    }
                    Ok(())
                })?;
                self.holder_phase = HolderPhase::AfterAppObservation;
            }
            Event::RetainFirstHolder { work_nanos } => {
                ensure!(
                    self.holder_phase == HolderPhase::ControllerRetention
                        && self.handshake.controller_accepted_checked()?,
                    "first holder Controller retention order"
                );
                checked_file_observation(&mut self.handshake, 1, work_nanos, || {
                    #[cfg(target_os = "linux")]
                    if let Some(file) = &mut self.file {
                        file.check(false)?;
                    }
                    Ok(())
                })?;
                self.first_holder = true;
                self.holder_phase = HolderPhase::Retained;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn complete_first_holder(&mut self, death_cut: Option<usize>) -> Result<()> {
        self.first_holder_step(Event::StartFirstHolder { death_cut })?;
        loop {
            let event = match self.holder_phase {
                HolderPhase::BeforeOffer | HolderPhase::AfterAppObservation => {
                    Event::AdvanceFirstHolder
                }
                HolderPhase::AppObservation => Event::ObserveFirstHolder { work_nanos: 0 },
                HolderPhase::ControllerRetention => Event::RetainFirstHolder { work_nanos: 0 },
                HolderPhase::Retained => return Ok(()),
                _ => anyhow::bail!("first holder incomplete"),
            };
            self.first_holder_step(event)?;
        }
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
        // Fixed original interval. Reopening SQLite never resets this to a
        // later sample and no constructor for a native owner is called.
        let budget = Budget::for_context(self.port.sample()?, Duration::from_secs(105))?;
        let (counter, slot) =
            guarded::read_for_action(&self.selection, core, &mut self.port, budget)?;
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
        Ok((counter, slot, context))
    }

    fn bootstrap_mutation(
        &mut self,
        stage: usize,
        operation: Operation,
        fault: Fault,
    ) -> Result<()> {
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
            Fault::ExpiredSlotReply => ClaimReply::ClockAfterCommit(Duration::from_secs(105)),
            Fault::RewoundSlotClock | Fault::ForwardSlotClock => {
                ClaimReply::ClockAfterCommit(Duration::from_secs(103))
            }
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
                Self::before_commit_clock(&mut self.port, fault);
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
                Self::before_commit_clock(&mut self.port, fault);
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
                self.port.counter_commit_time = match fault {
                    Fault::ExpiredCounterReply => Some(Duration::from_secs(105)),
                    Fault::RewoundCounterClock | Fault::ForwardCounterClock => {
                        Some(Duration::from_secs(103))
                    }
                    _ => None,
                };
                if fault == Fault::MalformedCounterReply {
                    counter_fixture::malformed_ack_after_commit(&mut self.port.counter);
                }
                if fault == Fault::RolledBackCounterWrite {
                    counter_fixture::fail_during_commit(&mut self.port.counter);
                }
                let result = claim.send(&self.selection, &mut self.port);
                if result.as_ref().err().is_some_and(|error| {
                    error
                        .root_cause()
                        .downcast_ref::<serde_json::Error>()
                        .is_some_and(serde_json::Error::is_data)
                }) {
                    self.counter_decode_failures += 1;
                }
                // Closed synthetic fixture cause only. Do not export or keep
                // formatted errors; a different refusal cannot satisfy this cut.
                if result
                    .as_ref()
                    .err()
                    .is_some_and(is_fixture_mid_commit_failure)
                {
                    self.counter_rollback_failures += 1;
                }
                result?;
                ensure!(
                    fault != Fault::ForwardCounterClock || self.port.counter_commit_time.is_none(),
                    "fixture counter reply clock hook was not consumed"
                );
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
                let mutation = guarded::settle(
                    &self.selection,
                    core,
                    counter,
                    slot,
                    context,
                    settlement,
                    &mut self.port,
                )?;
                Self::before_commit_clock(&mut self.port, fault);
                mutation.send(&self.selection, &mut self.port)?;
            }
        }
        // External file mutation after the real conditional write completed,
        // but before the enclosing phase's mandatory final file check. This
        // must not erase the durable write or turn its refusal into a retry.
        let change = match fault {
            Fault::FileTamperAfter => Some(FileChange::Tamper),
            Fault::FileReplaceAfter => Some(FileChange::Replace),
            Fault::FileShortenAfter => Some(FileChange::Shorten),
            _ => None,
        };
        if let Some(change) = change {
            ensure!(
                self.port.slots.db.is_autocommit()
                    && counter_fixture::transaction_closed(&self.port.counter),
                "post-write file cut encountered an open provider transaction"
            );
            #[cfg(target_os = "linux")]
            self.file
                .as_mut()
                .context("physical fixture required")?
                .change(change)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = change;
                anyhow::bail!("physical lifecycle requires Linux");
            }
        }
        // The real action's successful return is not its strong post-read.
        // Preserve native run_phase order; an actual mutation Err exits above
        // without starting new provider I/O on its refused port.
        let core = self.cores[stage].clone();
        let budget = Budget::for_context(self.port.sample()?, Duration::from_secs(105))?;
        let (observed, slot) =
            guarded::read_with_counter(&self.selection, &core, &mut self.port, budget)?;
        let action = match operation {
            Operation::Reserve => crate::security_epoch::bootstrap::Action::Reserve,
            Operation::Dispatch => crate::security_epoch::bootstrap::Action::Dispatch,
            Operation::Settle => crate::security_epoch::bootstrap::Action::Settle,
        };
        crate::security_epoch::bootstrap::validate_after_fixture(
            action,
            &self.selection,
            &core.counter,
            &core,
            observed.snapshot(),
            &slot,
        )?;
        self.port.sample()?;
        if stage == 1 && operation == Operation::Settle {
            self.activation = Some(snapshot_digest(observed.snapshot())?);
        }
        Ok(())
    }

    fn before_commit_clock(port: &mut SharedPort, fault: Fault) {
        // The observation, original context and mutation already exist with
        // the same 100..105 budget. Advance only this fixture's clock DATA
        // before the real send checks. Both replies end at 103: after 102 it
        // advances, after 104 it rewinds. No origin or limit is reconstructed.
        match fault {
            Fault::RewoundSlotClock | Fault::RewoundCounterClock => {
                port.counter.set_slot_fixture_time(Duration::from_secs(104));
            }
            Fault::ForwardSlotClock | Fault::ForwardCounterClock => {
                port.counter.set_slot_fixture_time(Duration::from_secs(102));
            }
            _ => {}
        }
    }

    fn check_current_before(&mut self) -> Result<()> {
        let activation = self.activation.clone().context("activation not settled")?;
        let observed = counter_fixture::observe_selected(
            &mut self.port.counter,
            &self.selection,
            &self.cores[1].counter,
        )?
        .into_data();
        check_active_snapshot(
            &self.selection,
            &self.cores[1].counter,
            &activation,
            &observed,
        )?;
        Ok(())
    }

    fn check_current_after(&mut self, rewrite_provider: bool) -> Result<()> {
        let activation = self.activation.clone().context("activation not settled")?;
        if rewrite_provider {
            counter_fixture::rewrite_selected_root(
                &mut self.port.counter,
                &self.selection,
                &self.cores[1].counter,
            );
        }
        let observed = counter_fixture::observe_selected(
            &mut self.port.counter,
            &self.selection,
            &self.cores[1].counter,
        )?
        .into_data();
        check_active_snapshot(
            &self.selection,
            &self.cores[1].counter,
            &activation,
            &observed,
        )?;
        Ok(())
    }

    fn completion_file(&mut self, physical: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(file) = &mut self.file {
            file.check(physical)?;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = physical;
        Ok(())
    }

    fn completion_step(&mut self, event: Event, endpoint: usize) -> Result<()> {
        match event {
            Event::StartCompletion { work, death_cut } => {
                ensure!(self.first_holder, "completion first holder missing");
                ensure!(
                    self.completion
                        .is_none_or(|state| state.phase == CompletionPhase::Complete),
                    "completion already pending or refused"
                );
                self.completion = Some(CompletionState {
                    work,
                    phase: CompletionPhase::Wire,
                    mutation_known: false,
                    consumed_checked: false,
                    peer_complete: false,
                });
                self.completion_file(matches!(work, CompletionWork::Current { .. }))?;
                ensure!(
                    self.port.slots.db.is_autocommit()
                        && counter_fixture::transaction_closed(&self.port.counter),
                    "completion holds provider transaction across wire"
                );
                match work {
                    CompletionWork::Bootstrap { .. } => self
                        .handshake
                        .begin_bootstrap_exchange(death_cut, endpoint)?,
                    CompletionWork::Current { .. } => {
                        self.check_current_before()?;
                        self.handshake.begin_exchange(death_cut, endpoint)?;
                    }
                }
            }
            Event::AdvanceCompletion => {
                let state = self.completion.context("completion not started")?;
                ensure!(
                    matches!(
                        state.phase,
                        CompletionPhase::Wire
                            | CompletionPhase::AfterMutation
                            | CompletionPhase::Releasing
                    ),
                    "completion callback obligation pending"
                );
                ensure!(
                    self.handshake.progress()? != LifecycleProgress::Refused,
                    "completion peer refused"
                );
                self.handshake.advance_exchange()?;
                ensure!(
                    self.handshake.progress()? != LifecycleProgress::Refused,
                    "completion peer refused"
                );
                let mut next = state;
                if matches!(state.work, CompletionWork::Bootstrap { .. })
                    && state.phase == CompletionPhase::Wire
                    && self.handshake.bootstrap_work_ready()?
                {
                    next.phase = CompletionPhase::Mutation;
                } else if state.phase != CompletionPhase::Releasing
                    && self.handshake.controller_consumed_checked()?
                {
                    ensure!(
                        !matches!(state.work, CompletionWork::Bootstrap { .. })
                            || state.mutation_known,
                        "completion mutation not known"
                    );
                    next.consumed_checked = true;
                    next.phase = CompletionPhase::Release;
                } else if self.handshake.progress()? == LifecycleProgress::ProtocolComplete {
                    ensure!(
                        state.phase == CompletionPhase::Releasing && state.consumed_checked,
                        "completion release not checked"
                    );
                    next.peer_complete = true;
                    next.phase = CompletionPhase::FinalFile;
                }
                self.completion = Some(next);
            }
            Event::MutateCompletion => {
                let state = self.completion.context("completion not started")?;
                ensure!(
                    state.phase == CompletionPhase::Mutation
                        && self.handshake.bootstrap_work_ready()?,
                    "completion mutation order"
                );
                let CompletionWork::Bootstrap {
                    stage,
                    operation,
                    fault,
                } = state.work
                else {
                    anyhow::bail!("current cannot mutate bootstrap");
                };
                ensure!(
                    self.handshake.check_file_boundary(1)?,
                    "completion original before mutation"
                );
                let requested = self.bootstrap_mutation(stage, operation, fault);
                let checked = self.handshake.check_file_boundary(1);
                requested?;
                ensure!(checked?, "completion original after mutation");
                ensure!(
                    self.port.slots.db.is_autocommit()
                        && counter_fixture::transaction_closed(&self.port.counter),
                    "completion mutation retained transaction"
                );
                self.completion_file(false)?;
                self.completion = Some(CompletionState {
                    phase: CompletionPhase::AfterMutation,
                    mutation_known: true,
                    ..state
                });
            }
            Event::PrepareCompletionRelease => {
                let state = self.completion.context("completion not started")?;
                ensure!(
                    state.phase == CompletionPhase::Release
                        && state.consumed_checked
                        && self.handshake.controller_consumed_checked()?,
                    "completion consumed not checked"
                );
                ensure!(
                    self.handshake.check_file_boundary(1)?,
                    "completion original before release"
                );
                // Activation still needs its last INITIAL-byte guard before
                // App release. Only the subsequent final guard is physical.
                let requested =
                    self.completion_file(matches!(state.work, CompletionWork::Current { .. }));
                let checked = self.handshake.check_file_boundary(1);
                requested?;
                ensure!(checked?, "completion original after release guard");
                self.completion = Some(CompletionState {
                    phase: CompletionPhase::Releasing,
                    ..state
                });
            }
            Event::FinishCompletion => {
                let state = self.completion.context("completion not started")?;
                ensure!(
                    state.phase == CompletionPhase::FinalFile
                        && state.peer_complete
                        && self.handshake.progress()? == LifecycleProgress::ProtocolComplete,
                    "completion peer unfinished"
                );
                ensure!(
                    self.handshake.check_file_boundary(1)?,
                    "completion original before final file"
                );
                let requested = (|| {
                    if let CompletionWork::Current { rewrite_provider } = state.work {
                        self.check_current_after(rewrite_provider)?;
                    }
                    let physical = matches!(
                        state.work,
                        CompletionWork::Current { .. }
                            | CompletionWork::Bootstrap {
                                stage: 1,
                                operation: Operation::Settle,
                                ..
                            }
                    );
                    self.completion_file(physical)
                })();
                let checked = self.handshake.check_file_boundary(1);
                requested?;
                ensure!(checked?, "completion original after final file");
                if matches!(state.work, CompletionWork::Current { .. }) {
                    self.current += 1;
                }
                self.completion = Some(CompletionState {
                    phase: CompletionPhase::Complete,
                    ..state
                });
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn complete_work(
        &mut self,
        work: CompletionWork,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<()> {
        self.completion_step(Event::StartCompletion { work, death_cut }, endpoint)?;
        loop {
            let state = self.completion.context("completion not started")?;
            let event = match state.phase {
                CompletionPhase::Wire
                | CompletionPhase::AfterMutation
                | CompletionPhase::Releasing => Event::AdvanceCompletion,
                CompletionPhase::Mutation => Event::MutateCompletion,
                CompletionPhase::Release => Event::PrepareCompletionRelease,
                CompletionPhase::FinalFile => Event::FinishCompletion,
                CompletionPhase::Complete => return Ok(()),
                CompletionPhase::Refused => anyhow::bail!("completion refused"),
            };
            self.completion_step(event, endpoint)?;
        }
    }

    fn counter_name(&self, record: CounterRecord) -> Result<String> {
        let Request::CompleteInitialFirstActivation { operation, .. } = &self.cores[1].counter
        else {
            unreachable!()
        };
        let names = crate::security_epoch::firestore::Names::new(
            &self.selection,
            self.cores[1].counter.bootstrap(),
            Some(operation),
        )?;
        Ok(match record {
            CounterRecord::Authority => names.root,
            CounterRecord::Sentinel => names.sentinel,
            CounterRecord::CreateReceipt => names.create,
            CounterRecord::ActivationReceipt => names.activate.unwrap(),
            // Outside every document in the selected coherent read, not just
            // a different field or a different selected receipt.
            CounterRecord::OutsideSelection => format!("{}/unrelated/record", names.root),
        })
    }

    fn replace_counter(&mut self, record: CounterRecord) -> Result<bool> {
        if self.replaced.contains_key(&record) {
            return Ok(false);
        }
        let name = self.counter_name(record)?;
        let snapshot = counter_fixture::snapshot(&self.port.counter);
        let rows = snapshot["documents"].as_array().unwrap();
        let original = rows.iter().find(|row| row["name"] == name).cloned();
        let source = if record == CounterRecord::OutsideSelection {
            rows.iter()
                .find(|row| row["name"] == self.counter_name(CounterRecord::Authority).unwrap())
        } else {
            original.as_ref()
        };
        let Some(mut replacement) = source.cloned() else {
            return Ok(false);
        };
        replacement["name"] = json!(name);
        let prefix = if matches!(
            record,
            CounterRecord::CreateReceipt | CounterRecord::ActivationReceipt
        ) {
            "/request/mapValue/fields"
        } else {
            ""
        };
        let pointer =
            format!("/fields{prefix}/bootstrap/mapValue/fields/record_incarnation/stringValue");
        let incarnation = replacement
            .pointer_mut(&pointer)
            .context("fixture bootstrap incarnation")?;
        ensure!(incarnation.is_string(), "fixture incarnation shape");
        let foreign = json!(Digest::new(b"external-provider-record-replacement"));
        ensure!(
            record == CounterRecord::OutsideSelection || *incarnation != foreign,
            "fixture replacement unchanged"
        );
        *incarnation = foreign;
        // Retain the version deliberately: a provider substituting canonical
        // DATA cannot evade the semantic check merely by retaining updateTime.
        counter_fixture::replace_document(&mut self.port.counter, &name, Some(&replacement))?;
        self.replaced.insert(record, original);
        Ok(true)
    }

    fn restore_counter(&mut self, record: CounterRecord) -> Result<bool> {
        let name = self.counter_name(record)?;
        let Some(original) = self.replaced.get(&record) else {
            return Ok(false);
        };
        counter_fixture::replace_document(&mut self.port.counter, &name, original.as_ref())?;
        self.replaced.remove(&record);
        Ok(true)
    }

    fn step(&mut self, event: Event) -> Result<Record> {
        self.step_peer(event, 0)
    }

    fn step_peer(&mut self, event: Event, endpoint: usize) -> Result<Record> {
        let accepted = match event {
            Event::RestorePreparation {} => {
                #[cfg(target_os = "linux")]
                {
                    self.file
                        .as_mut()
                        .context("physical preparation required")?
                        .restore_preparation()?;
                    true
                }
                #[cfg(not(target_os = "linux"))]
                {
                    anyhow::bail!("physical preparation requires Linux");
                }
            }
            Event::WorkTime {
                wire_nanos,
                provider_nanos,
            } => {
                self.handshake.advance_file_time(wire_nanos)?;
                counter_fixture::advance_clock(&mut self.port.counter, provider_nanos)?;
                true
            }
            Event::LosePacket { sender } => self.handshake.lose_packet(sender)?,
            Event::FileTime { nanos } => {
                self.handshake.advance_file_time(nanos)?;
                true
            }
            Event::FileRewind { nanos } => {
                self.handshake.rewind_file_time(nanos)?;
                true
            }
            Event::CounterReplace { record } => self.replace_counter(record)?,
            Event::CounterRestore { record } => self.restore_counter(record)?,
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
                self.port.counter_commit_time = None;
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
            Event::Observe { stage } => counter_fixture::observe_read_only(
                &self.directory.path().join("counter.sqlite"),
                &self.selection,
                &self.cores[stage].counter,
            )
            .and_then(|observed| {
                crate::security_epoch::kernel::reconcile(
                    &self.selection,
                    &self.cores[stage].counter,
                    &observed,
                )
            })
            .is_ok(),
            event => {
                // This drives the SAME production continuation decision, not a
                // second grant. The operation still uses only DATA contexts.
                let mut continuation = self.continuation;
                let result = lifecycle_fixture::phase(&mut continuation, || {
                    match event {
                        Event::PrepareOriginal { input } => {
                            #[cfg(target_os = "linux")]
                            {
                                ensure!(
                                    self.file
                                        .as_mut()
                                        .context("physical preparation required")?
                                        .prepare(input)?,
                                    "original preparation refused"
                                );
                                Ok(())
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                let _ = input;
                                anyhow::bail!("physical preparation requires Linux");
                            }
                        }
                        Event::FirstHolder { death_cut } => self.complete_first_holder(death_cut),
                        Event::StartFirstHolder { .. }
                        | Event::AdvanceFirstHolder
                        | Event::ObserveFirstHolder { .. }
                        | Event::RetainFirstHolder { .. } => self.first_holder_step(event),
                        Event::Bootstrap {
                            stage,
                            operation,
                            fault,
                        } => self.complete_work(
                            CompletionWork::Bootstrap {
                                stage,
                                operation,
                                fault,
                            },
                            None,
                            endpoint,
                        ),
                        Event::Current {
                            death_cut,
                            rewrite_provider,
                        } => self.complete_work(
                            CompletionWork::Current { rewrite_provider },
                            death_cut,
                            endpoint,
                        ),
                        Event::StartCompletion { .. }
                        | Event::AdvanceCompletion
                        | Event::MutateCompletion
                        | Event::PrepareCompletionRelease
                        | Event::FinishCompletion => self.completion_step(event, endpoint),
                        _ => unreachable!(),
                    }?;
                    Ok(())
                });
                self.continuation = continuation;
                if result.is_err()
                    && let Some(state) = self.completion.as_mut()
                    && state.phase != CompletionPhase::Complete
                {
                    state.phase = CompletionPhase::Refused;
                }
                match result {
                    Ok(()) => true,
                    Err(error)
                        if error.is::<LifecycleModelError>()
                            || self.handshake.progress().is_err() =>
                    {
                        return Err(error.context(LifecycleModelError));
                    }
                    Err(error) => {
                        if !self.first_holder {
                            self.holder_phase = HolderPhase::Refused;
                        }
                        // Fixed synthetic budget failure only. Do not retain
                        // or export any formatted error/provider value. The
                        // independent model must predict this primary cause,
                        // so an unrelated refusal cannot satisfy a rewind cut.
                        if is_primary_budget_order_failure(&error) {
                            self.clock_order_failures += 1;
                        }
                        false
                    }
                }
            }
        };
        let counter = counter_fixture::snapshot(&self.port.counter);
        self.record(accepted, counter)
    }

    fn record(&self, accepted: bool, counter: Value) -> Result<Record> {
        let provider = self.port.slots.replay();
        Ok(Record {
            accepted,
            state: State {
                binding: self.binding()?,
                continuation: self.continuation,
                first_holder: self.first_holder,
                checked_accepted: self.checked_accepted,
                holder_phase: self.holder_phase,
                completion: self.completion,
                provider_time: counter_fixture::clock_data(&self.port.counter),
                current: self.current,
                slot_posts: self.port.slot_posts,
                counter_posts: self.port.counter_posts,
                counter_rollback_failures: self.counter_rollback_failures,
                clock_order_failures: self.clock_order_failures,
                counter_decode_failures: self.counter_decode_failures,
                counter: json!({"documents":counter["documents"],"sends":counter["sends"]}),
                slots: provider["final_rows"].clone(),
                #[cfg(target_os = "linux")]
                file: self.file.as_ref().map(|file| file.snapshot()).transpose()?,
                #[cfg(not(target_os = "linux"))]
                file: None,
                #[cfg(target_os = "linux")]
                preparation: self
                    .file
                    .as_ref()
                    .and_then(|file| file.preparation_observation()),
                #[cfg(not(target_os = "linux"))]
                preparation: None,
                #[cfg(target_os = "linux")]
                preparation_files: self
                    .file
                    .as_ref()
                    .map(|file| file.preparation_files())
                    .transpose()?
                    .flatten(),
                #[cfg(not(target_os = "linux"))]
                preparation_files: None,
            },
            provider: json!({"counter":counter,"slots":provider}),
            handshake: self.handshake.snapshot(),
            reference: None,
        })
    }

    fn binding(&self) -> Result<Digest> {
        Digest::of(&(
            "day2-storage-lifecycle-fixture-v1",
            &self.cores,
            &self.image_binding,
        ))
    }
}

/// Test DATA composition, never a native role, permission or stage constructor.
/// Each step retains the complete provider/handshake records and checks the
/// existing independent model before exposing any observation to consumers.
pub(crate) struct ConsumerLifecycle {
    world: World,
    model: model::Model,
    steps: usize,
    shell: LifecycleHandshake,
    enrollment: [LifecycleHandshake; 3],
}

/// Closed test DATA. Neither progress nor the reference world is a role owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsumerHandshakeProgress {
    Pending,
    Completed,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsumerControllerAction {
    Reserve,
    Dispatch,
    Settle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsumerStorageFault {
    None,
    LostBefore,
    LostAfter,
    Rollback,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "storage", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ConsumerStorageEvent {
    BeginFirstHolder {
        death_cut: Option<usize>,
    },
    AdvanceFirstHolder {
        events: u8,
    },
    ObserveFirstHolder {
        work_nanos: u64,
    },
    RetainFirstHolder {
        work_nanos: u64,
    },
    BeginBootstrap {
        activation: bool,
        action: ConsumerControllerAction,
        fault: ConsumerStorageFault,
        death_cut: Option<usize>,
    },
    BeginCurrent {
        death_cut: Option<usize>,
        rewrite_provider: bool,
    },
    AdvanceCompletion {
        events: u8,
    },
    MutateCompletion,
    PrepareRelease,
    FinishCompletion,
    Controller {
        activation: bool,
        action: ConsumerControllerAction,
        fault: ConsumerStorageFault,
    },
    LosePacket {
        sender: usize,
    },
}

impl ConsumerControllerAction {
    fn operation(self) -> Operation {
        match self {
            Self::Reserve => Operation::Reserve,
            Self::Dispatch => Operation::Dispatch,
            Self::Settle => Operation::Settle,
        }
    }
}

impl ConsumerStorageFault {
    fn fault(self) -> Fault {
        match self {
            Self::None => Fault::None,
            Self::LostBefore => Fault::LostCounterBefore,
            Self::LostAfter => Fault::LostCounterAfter,
            Self::Rollback => Fault::RolledBackCounterWrite,
            Self::Malformed => Fault::MalformedCounterReply,
        }
    }
}

impl ConsumerStorageEvent {
    fn events(self) -> Result<Vec<Event>> {
        let (event, count) = match self {
            Self::BeginFirstHolder { death_cut } => (Event::StartFirstHolder { death_cut }, 1),
            Self::AdvanceFirstHolder { events } => (Event::AdvanceFirstHolder, events),
            Self::ObserveFirstHolder { work_nanos } => {
                (Event::ObserveFirstHolder { work_nanos }, 1)
            }
            Self::RetainFirstHolder { work_nanos } => (Event::RetainFirstHolder { work_nanos }, 1),
            Self::BeginBootstrap {
                activation,
                action,
                fault,
                death_cut,
            } => (
                Event::StartCompletion {
                    work: CompletionWork::Bootstrap {
                        stage: usize::from(activation),
                        operation: action.operation(),
                        fault: fault.fault(),
                    },
                    death_cut,
                },
                1,
            ),
            Self::BeginCurrent {
                death_cut,
                rewrite_provider,
            } => (
                Event::StartCompletion {
                    work: CompletionWork::Current { rewrite_provider },
                    death_cut,
                },
                1,
            ),
            Self::AdvanceCompletion { events } => (Event::AdvanceCompletion, events),
            Self::MutateCompletion => (Event::MutateCompletion, 1),
            Self::PrepareRelease => (Event::PrepareCompletionRelease, 1),
            Self::FinishCompletion => (Event::FinishCompletion, 1),
            Self::Controller {
                activation,
                action,
                fault,
            } => (
                Event::Bootstrap {
                    stage: usize::from(activation),
                    operation: action.operation(),
                    fault: fault.fault(),
                },
                1,
            ),
            Self::LosePacket { sender } => (Event::LosePacket { sender }, 1),
        };
        ensure!((1..=64).contains(&count), ConsumerModelError);
        Ok(vec![event; usize::from(count)])
    }
}

/// Reference-only storage state. Initial cores are controlled immutable DATA;
/// no actual world, provider, consumer result or SQLite read supplies decisions.
pub(crate) struct ConsumerStorageReference {
    model: model::Model,
}

impl ConsumerStorageReference {
    pub(crate) fn new(
        seed: u64,
        scope: &day2_capabilities::security_epoch::AuthorityScope,
    ) -> Result<Self> {
        let mut selection = tests::selection();
        selection.scope = scope.clone();
        let (selection, create) = fixture_for_store(selection);
        let complete = consumer_completion_core(&selection, &create)?;
        Ok(Self {
            model: model::Model::new(seed, &[create, complete], None, &None)?,
        })
    }

    pub(crate) fn step(&mut self, event: ConsumerEvent) -> Result<bool> {
        let (events, endpoint) = event.storage_events()?;
        for event in events {
            if !self.model.step_peer(event, endpoint)?.0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn current(&self) -> bool {
        self.model.consumer_current()
    }

    pub(crate) fn observation(&self) -> Value {
        json!({"state":self.model.observation(),"handshake":self.model.handshake_snapshot(),"current":self.current()})
    }

    pub(crate) fn next(&self) -> Result<Option<ConsumerStorageEvent>> {
        let state: State = serde_json::from_value(self.model.observation())?;
        if !state.continuation {
            return Ok(None);
        }
        Ok(match state.completion.map(|completion| completion.phase) {
            Some(
                CompletionPhase::Wire | CompletionPhase::AfterMutation | CompletionPhase::Releasing,
            ) => Some(ConsumerStorageEvent::AdvanceCompletion { events: 1 }),
            Some(CompletionPhase::Mutation) => Some(ConsumerStorageEvent::MutateCompletion),
            Some(CompletionPhase::Release) => Some(ConsumerStorageEvent::PrepareRelease),
            Some(CompletionPhase::FinalFile) => Some(ConsumerStorageEvent::FinishCompletion),
            Some(CompletionPhase::Complete | CompletionPhase::Refused) => None,
            None => match state.holder_phase {
                HolderPhase::BeforeOffer | HolderPhase::AfterAppObservation => {
                    Some(ConsumerStorageEvent::AdvanceFirstHolder { events: 1 })
                }
                HolderPhase::AppObservation => {
                    Some(ConsumerStorageEvent::ObserveFirstHolder { work_nanos: 0 })
                }
                HolderPhase::ControllerRetention => {
                    Some(ConsumerStorageEvent::RetainFirstHolder { work_nanos: 0 })
                }
                _ => None,
            },
        })
    }
}

impl From<LifecycleProgress> for ConsumerHandshakeProgress {
    fn from(progress: LifecycleProgress) -> Self {
        match progress {
            LifecycleProgress::Pending => Self::Pending,
            LifecycleProgress::ProtocolComplete => Self::Completed,
            LifecycleProgress::Refused => Self::Refused,
        }
    }
}

/// Independent serving model driven only by controlled seed/events. No access
/// to the consumer, provider, OAuth results, or production transcript decisions.
pub(crate) struct ConsumerShellReference {
    handshake: LifecycleReference,
}

impl ConsumerShellReference {
    pub(crate) fn new(seed: u64) -> Result<Self> {
        Ok(Self {
            handshake: LifecycleReference::serving(seed)?,
        })
    }

    pub(crate) fn begin(&mut self, death_cut: Option<usize>) -> Result<()> {
        self.handshake.begin_exchange(death_cut, 0)
    }

    pub(crate) fn advance(&mut self, events: u8) -> Result<()> {
        ensure!((1..=64).contains(&events), ConsumerModelError);
        for _ in 0..events {
            self.handshake.advance_exchange()?;
        }
        Ok(())
    }

    pub(crate) fn exchange(&mut self, death_cut: Option<usize>) -> Result<bool> {
        self.begin(death_cut)?;
        loop {
            if let Some(accepted) = self.handshake.advance_exchange()? {
                return Ok(accepted);
            }
        }
    }

    pub(crate) fn progress(&self) -> Result<ConsumerHandshakeProgress> {
        self.handshake.progress().map(Into::into)
    }

    pub(crate) fn observation(&self) -> Value {
        self.handshake.snapshot()
    }
}

#[derive(Debug)]
pub(crate) struct ConsumerModelError;
impl std::fmt::Display for ConsumerModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("composed native model divergence")
    }
}
impl std::error::Error for ConsumerModelError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ConsumerEvent {
    Storage {
        input: ConsumerStorageEvent,
    },
    FirstHolder {
        death_cut: Option<usize>,
    },
    Shell {
        death_cut: Option<usize>,
    },
    BeginShell {
        death_cut: Option<usize>,
    },
    AdvanceShell {
        events: u8,
    },
    Reserve {
        activation: bool,
    },
    Dispatch {
        activation: bool,
    },
    Settle {
        activation: bool,
    },
    Current {
        death_cut: Option<usize>,
        rewrite_provider: bool,
    },
    ControllerDeath {
        cut: usize,
    },
    Reopen,
    RestoreClock,
}

impl ConsumerEvent {
    fn storage_events(self) -> Result<(Vec<Event>, usize)> {
        let endpoint = usize::from(matches!(self, ConsumerEvent::ControllerDeath { .. }));
        let event = match self {
            ConsumerEvent::Storage { input } => return Ok((input.events()?, 0)),
            ConsumerEvent::FirstHolder { death_cut } => Event::FirstHolder { death_cut },
            ConsumerEvent::Shell { .. }
            | ConsumerEvent::BeginShell { .. }
            | ConsumerEvent::AdvanceShell { .. } => return Err(ConsumerModelError.into()),
            ConsumerEvent::Reserve { activation } => Event::Bootstrap {
                stage: usize::from(activation),
                operation: Operation::Reserve,
                fault: Fault::None,
            },
            ConsumerEvent::Dispatch { activation } => Event::Bootstrap {
                stage: usize::from(activation),
                operation: Operation::Dispatch,
                fault: Fault::None,
            },
            ConsumerEvent::Settle { activation } => Event::Bootstrap {
                stage: usize::from(activation),
                operation: Operation::Settle,
                fault: Fault::None,
            },
            ConsumerEvent::Current {
                death_cut,
                rewrite_provider,
            } => Event::Current {
                death_cut,
                rewrite_provider,
            },
            ConsumerEvent::ControllerDeath { cut } => Event::Current {
                death_cut: Some(cut),
                rewrite_provider: false,
            },
            ConsumerEvent::Reopen => Event::Reopen,
            ConsumerEvent::RestoreClock => Event::RestoreClock,
        };
        Ok((vec![event], endpoint))
    }
}

impl ConsumerLifecycle {
    pub(crate) fn new(
        seed: u64,
        scope: &day2_capabilities::security_epoch::AuthorityScope,
    ) -> Result<Self> {
        let world = World::selected(seed, None, Some(scope))?;
        let model = model::Model::new(seed, &world.cores, None, &world.image_binding)?;
        let mut enrollment = [
            LifecycleHandshake::enrollment(seed ^ 1)?,
            LifecycleHandshake::enrollment(seed ^ 2)?,
            LifecycleHandshake::enrollment(seed ^ 3)?,
        ];
        for role in &mut enrollment {
            ensure!(role.exchange(None)?, ConsumerModelError);
        }
        Ok(Self {
            world,
            model,
            steps: 0,
            shell: LifecycleHandshake::serving(seed)?,
            enrollment,
        })
    }

    pub(crate) fn source() -> Digest {
        Digest::of(&(source(), LifecycleHandshake::source())).unwrap()
    }

    /// Denied-only DATA harness control, never an enrolled-role constructor.
    pub(crate) fn corrupt_enrollment_reference_for_slot_control(&mut self) {
        self.enrollment[0].corrupt_reference_for_control();
    }

    pub(crate) fn corrupt_shell_reference_for_control(&mut self) {
        self.shell.corrupt_reference_for_control();
    }

    pub(crate) fn observation(&self) -> Result<Value> {
        Ok(
            json!({"storage":self.world.record(false, counter_fixture::snapshot(&self.world.port.counter))?,
            "expected":self.model.observation(),"expected_current":self.model.consumer_current(),"reference":self.model.handshake_snapshot(),"serving":self.shell.snapshot(),
            "serving_progress":ConsumerHandshakeProgress::from(self.shell.progress().map_err(|_| ConsumerModelError)?),
            "enrollment":self.enrollment.iter().map(LifecycleHandshake::snapshot).collect::<Vec<_>>()}),
        )
    }

    /// Reobserve the actual active counter, never turn a saved success into
    /// current permission. The independent model separately predicts refusal.
    pub(crate) fn check(
        &mut self,
        scope: &day2_capabilities::security_epoch::AuthorityScope,
        shell: bool,
    ) -> Result<()> {
        ensure!(
            &self.world.selection.scope == scope,
            "consumer native scope changed"
        );
        for role in &self.enrollment {
            ensure!(
                role.current().map_err(|_| ConsumerModelError)?,
                "consumer enrollment transcript refused"
            );
        }
        let actual = (|| {
            ensure!(
                self.world.continuation
                    && self.world.first_holder
                    && self
                        .world
                        .completion
                        .is_none_or(|state| state.phase == CompletionPhase::Complete),
                "consumer native continuation refused"
            );
            let activation = self
                .world
                .activation
                .as_ref()
                .context("consumer activation missing")?;
            let observed = counter_fixture::observe_selected(
                &mut self.world.port.counter,
                &self.world.selection,
                &self.world.cores[1].counter,
            )?
            .into_data();
            check_active_snapshot(
                &self.world.selection,
                &self.world.cores[1].counter,
                activation,
                &observed,
            )
        })();
        ensure!(
            actual.is_ok() == self.model.consumer_current(),
            ConsumerModelError
        );
        actual?;
        ensure!(
            !shell || self.shell.current().map_err(|_| ConsumerModelError)?,
            "consumer Shell transcript refused"
        );
        Ok(())
    }

    pub(crate) fn step(&mut self, event: ConsumerEvent) -> Result<serde_json::Value> {
        self.steps += 1;
        ensure!(self.steps <= MAX_EVENTS, "consumer lifecycle event bound");
        if matches!(
            event,
            ConsumerEvent::Shell { .. }
                | ConsumerEvent::BeginShell { .. }
                | ConsumerEvent::AdvanceShell { .. }
        ) {
            let accepted = match event {
                ConsumerEvent::Shell { death_cut } => self.shell.exchange(death_cut),
                ConsumerEvent::BeginShell { death_cut } => {
                    self.shell.begin_exchange(death_cut, 0).map(|()| true)
                }
                ConsumerEvent::AdvanceShell { events } => (|| {
                    ensure!((1..=64).contains(&events), ConsumerModelError);
                    for _ in 0..events {
                        self.shell.advance_exchange()?;
                    }
                    Ok(true)
                })(),
                _ => unreachable!(),
            }
            .map_err(|_| ConsumerModelError)?;
            let record = self.world.record(
                accepted,
                counter_fixture::snapshot(&self.world.port.counter),
            )?;
            return Ok(json!({"actual":record,"serving":self.shell.snapshot()}));
        }
        let (events, endpoint) = event.storage_events()?;
        let mut last = None;
        for event in events {
            let actual = self
                .world
                .step_peer(event, endpoint)
                .map_err(|_| ConsumerModelError)?;
            let (accepted, state) = self
                .model
                .step_peer(event, endpoint)
                .map_err(|_| ConsumerModelError)?;
            ensure!(
                (actual.accepted, &actual.state) == (accepted, &state),
                ConsumerModelError
            );
            last = Some(
                json!({"actual":actual,"expected":{"accepted":accepted,"state":state},"serving":self.shell.snapshot()}),
            );
            if !accepted {
                break;
            }
        }
        last.context(ConsumerModelError)
    }
}

#[test]
fn expected_peer_death_cannot_hide_a_handshake_oracle_error() -> Result<()> {
    fn active() -> Result<ConsumerLifecycle> {
        let mut consumer = ConsumerLifecycle::new(71, &tests::selection().scope)?;
        consumer.step(ConsumerEvent::FirstHolder { death_cut: None })?;
        for activation in [false, true] {
            consumer.step(ConsumerEvent::Reserve { activation })?;
            consumer.step(ConsumerEvent::Dispatch { activation })?;
            consumer.step(ConsumerEvent::Settle { activation })?;
        }
        consumer.step(ConsumerEvent::Current {
            death_cut: None,
            rewrite_provider: false,
        })?;
        Ok(consumer)
    }

    for event in [
        ConsumerEvent::Current {
            death_cut: Some(0),
            rewrite_provider: false,
        },
        ConsumerEvent::ControllerDeath { cut: 0 },
    ] {
        let mut ordinary = active()?;
        let refused = ordinary.step(event)?;
        assert_eq!(refused["actual"]["accepted"], false);
        assert_eq!(refused["expected"]["accepted"], false);
        assert_eq!(refused["actual"]["state"]["continuation"], false);

        let mut divergent = active()?;
        divergent.world.handshake.corrupt_reference_for_control();
        let error = divergent
            .step(event)
            .expect_err("oracle disagreement became an ordinary expected refusal");
        assert!(error.is::<ConsumerModelError>());
        assert!(!divergent.world.continuation);
        // Reproduce the masking condition: ordinary storage denial and the
        // complete outer State still agree. The transcript disagreement must
        // remain independently fatal rather than relying on that comparison.
        let expected = divergent.model.step(Event::Current {
            death_cut: Some(0),
            rewrite_provider: false,
        })?;
        let observed = divergent.world.record(
            false,
            counter_fixture::snapshot(&divergent.world.port.counter),
        )?;
        assert_eq!(
            (observed.accepted, &observed.state),
            (expected.0, &expected.1)
        );
        assert_ne!(observed.handshake["actual"], observed.handshake["oracle"]);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct Divergence {
    index: usize,
    category: &'static str,
    records: Vec<Record>,
    expected: Value,
}

fn reference_matches(actual: &Record, reference: &Value) -> bool {
    actual.handshake["oracle"] == reference["world"]
        && actual.handshake["schedule"] == reference["schedule"]
        && actual.handshake["failed"] == reference["failed"]
}

fn run(program: &Program) -> Result<std::result::Result<Vec<Record>, Divergence>> {
    ensure!(
        program.version == 1
            && !program.events.is_empty()
            && program.events.len() <= MAX_EVENTS + MAX_HANDSHAKE_ADVANCES
            && program
                .events
                .iter()
                .filter(|event| matches!(
                    event,
                    Event::AdvanceFirstHolder | Event::AdvanceCompletion
                ))
                .count()
                <= MAX_HANDSHAKE_ADVANCES
            && program
                .events
                .iter()
                .filter(|event| !matches!(
                    event,
                    Event::AdvanceFirstHolder | Event::AdvanceCompletion
                ))
                .count()
                <= MAX_EVENTS,
        "lifecycle version/history bound"
    );
    ensure!(
        program.events.iter().all(|e| match e {
            Event::Bootstrap { stage, .. }
            | Event::Observe { stage }
            | Event::StartCompletion {
                work: CompletionWork::Bootstrap { stage, .. },
                ..
            } => *stage < 2,
            Event::LosePacket { sender } => *sender < 2,
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
            }
            | Event::StartCompletion {
                work:
                    CompletionWork::Bootstrap {
                        operation: Operation::Reserve,
                        fault,
                        ..
                    },
                ..
            } => matches!(
                fault,
                Fault::None
                    | Fault::LostSlotReply
                    | Fault::MalformedSlotReply
                    | Fault::ExpiredSlotReply
                    | Fault::FileTamperAfter
                    | Fault::FileReplaceAfter
                    | Fault::FileShortenAfter
                    | Fault::RewoundSlotClock
                    | Fault::ForwardSlotClock
            ),
            Event::Bootstrap {
                operation: Operation::Settle,
                fault,
                ..
            }
            | Event::StartCompletion {
                work:
                    CompletionWork::Bootstrap {
                        operation: Operation::Settle,
                        fault,
                        ..
                    },
                ..
            } => matches!(
                fault,
                Fault::None
                    | Fault::LostSlotReply
                    | Fault::MalformedSlotReply
                    | Fault::ExpiredSlotReply
                    | Fault::ReplaceCandidate
                    | Fault::FileTamperAfter
                    | Fault::FileReplaceAfter
                    | Fault::FileShortenAfter
                    | Fault::RewoundSlotClock
                    | Fault::ForwardSlotClock
            ),
            _ => true,
        }),
        "lifecycle fault/operation bound"
    );
    ensure!(
        program.physical.is_some()
            || program.events.iter().all(|event| !matches!(
                event,
                Event::Bootstrap {
                    fault: Fault::FileTamperAfter
                        | Fault::FileReplaceAfter
                        | Fault::FileShortenAfter,
                    ..
                } | Event::StartCompletion {
                    work: CompletionWork::Bootstrap {
                        fault: Fault::FileTamperAfter
                            | Fault::FileReplaceAfter
                            | Fault::FileShortenAfter,
                        ..
                    },
                    ..
                }
            )),
        "lifecycle physical fault requires original image"
    );
    ensure!(
        program
            .physical
            .as_ref()
            .is_none_or(|image| (100..=16 * 1024 * 1024).contains(&image.len())),
        "lifecycle initial image byte bound"
    );
    ensure!(
        program.physical.is_some()
            || program.events.iter().all(|event| !matches!(
                event,
                Event::PrepareOriginal { .. } | Event::RestorePreparation {}
            )),
        "preparation event requires original image"
    );
    let mut world = World::new(program.seed, program.physical.as_deref())?;
    let mut model = model::Model::new(
        program.seed,
        &world.cores,
        program.physical.as_ref().map(Vec::len),
        &world.image_binding,
    )?;
    let mut records = Vec::new();
    for (index, &event) in program.events.iter().enumerate() {
        let mut actual = match world.step(event) {
            Ok(record) => record,
            Err(_) => {
                // Preserve the schedule even when a nested handshake oracle or
                // physical-fixture expectation fails before the outer model
                // comparison. Raw adapter errors never enter the bundle.
                let mut refused =
                    world.record(false, counter_fixture::snapshot(&world.port.counter))?;
                refused.reference = Some(model.handshake_snapshot());
                records.push(refused);
                return Ok(Err(Divergence {
                    index,
                    category: "adapter",
                    records,
                    expected: json!({"observation":"closed adapter and handshake model agreement"}),
                }));
            }
        };
        let expected = match model.step(event) {
            Ok(expected) => expected,
            Err(_) => {
                actual.reference = Some(model.handshake_snapshot());
                records.push(actual);
                return Ok(Err(Divergence {
                    index,
                    category: "oracle",
                    records,
                    expected: json!({"observation":"closed independent lifecycle execution"}),
                }));
            }
        };
        actual.reference = Some(model.handshake_snapshot());
        records.push(actual.clone());
        // Compare every retained wire world and original observation, including
        // bootstrap and ordinary Current. Equal aggregate status is insufficient.
        if !reference_matches(&actual, actual.reference.as_ref().unwrap()) {
            return Ok(Err(Divergence {
                index,
                category: "handshake-reference",
                records,
                expected: model.handshake_snapshot(),
            }));
        }
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
    Digest::of(&(
        std::env::consts::OS,
        std::env::consts::ARCH,
        [
            include_str!("lifecycle.rs"),
            include_str!("lifecycle/model.rs"),
            include_str!("lifecycle/preparation.rs"),
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
            include_str!("../storage_authority/preparation/tests.rs"),
            include_str!("../storage_authority/preparation/continuity/lifecycle_fixture.rs"),
            include_str!("../native_clock.rs"),
            include_str!("../storage_authority/preparation.rs"),
            include_str!("../storage_authority.rs"),
            include_str!("../storage_authority/native_volume.rs"),
            include_str!("../preparation_image.rs"),
            include_str!("../seed_core.rs"),
        ],
    ))
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
        let index = first
            .iter()
            .zip(&second)
            .position(|(a, b)| a != b)
            .unwrap_or(first.len().min(second.len()));
        return Ok(Err(Divergence {
            index,
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
    binding: Digest,
    program: Program,
    reduced: Program,
    failure: Value,
}

fn check(program: &Program) -> Result<Vec<Record>> {
    let failure = match replayed(program)? {
        Ok(records) => {
            record_history(program.seed, &records)?;
            return Ok(records);
        }
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
        binding: failure
            .records
            .first()
            .context("lifecycle failure snapshot absent")?
            .state
            .binding
            .clone(),
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
        physical: None,
        events,
    }
}

#[test]
fn independent_observation_after_semantic_refusal_never_revives_the_writer() -> Result<()> {
    let original = tests::selection().scope;
    let mut selected = original.clone();
    selected.installation = "scoped_company".to_owned().try_into()?;
    selected.environment = "production".to_owned().try_into()?;
    for scope in [original, selected] {
        let mut world = World::selected(71, None, Some(&scope))?;
        assert!(world.step(Event::FirstHolder { death_cut: None })?.accepted);
        for operation in [Operation::Reserve, Operation::Dispatch] {
            assert!(
                world
                    .step(Event::Bootstrap {
                        stage: 0,
                        operation,
                        fault: Fault::None
                    })?
                    .accepted
            );
        }
        assert!(
            !world
                .step(Event::Bootstrap {
                    stage: 0,
                    operation: Operation::Reserve,
                    fault: Fault::None
                })?
                .accepted
        );
        assert!(world.port.sample().is_err());
        let observed = world.step(Event::Observe { stage: 0 })?;
        assert!(observed.accepted);
        assert!(!observed.state.continuation);
        assert!(world.port.sample().is_err());
        let denied = world.step(Event::Bootstrap {
            stage: 0,
            operation: Operation::Settle,
            fault: Fault::None,
        })?;
        assert!(!denied.accepted);
        assert_eq!(denied.state.slot_posts, observed.state.slot_posts);
        assert_eq!(denied.state.counter_posts, observed.state.counter_posts);
    }
    Ok(())
}

fn record_history(seed: u64, records: &[Record]) -> Result<()> {
    dst::record(
        Campaign::StorageLifecycle,
        seed,
        [
            (
                Transition::StateChanged,
                records
                    .windows(2)
                    .filter(|w| w[0].state != w[1].state)
                    .count() as u64,
            ),
            (
                Transition::Accepted,
                records.iter().filter(|r| r.accepted).count() as u64,
            ),
            (
                Transition::Refused,
                records.iter().filter(|r| !r.accepted).count() as u64,
            ),
        ],
    )
}

// Generate only from the independent wire specification. The actual reducer
// and file fixture do not choose their own expected interleaving.
fn stepped_first_holder(seed: u64, death_cut: Option<usize>) -> Result<Program> {
    let mut reference = LifecycleReference::new(seed)?;
    reference.begin_exchange(death_cut, 0)?;
    let mut events = vec![Event::StartFirstHolder { death_cut }];
    let mut observed = false;
    loop {
        match reference.progress()? {
            LifecycleProgress::Refused => break,
            LifecycleProgress::ProtocolComplete => {
                events.push(Event::RetainFirstHolder { work_nanos: 0 });
                ensure!(
                    reference.check_file_boundary(1)? && reference.check_file_boundary(1)?,
                    "reference retention original refused"
                );
                break;
            }
            LifecycleProgress::Pending => {
                if !observed && reference.app_observation_ready()? {
                    events.push(Event::ObserveFirstHolder { work_nanos: 0 });
                    ensure!(
                        reference.check_file_boundary(0)? && reference.check_file_boundary(0)?,
                        "reference App original refused"
                    );
                    observed = true;
                } else {
                    events.push(Event::AdvanceFirstHolder);
                    reference.advance_exchange()?;
                }
            }
        }
    }
    Ok(Program {
        version: 1,
        seed,
        physical: None,
        events,
    })
}

#[test]
fn reference_comparison_observes_clocks_queues_and_endpoints_not_only_the_disposition() -> Result<()>
{
    let program = stepped_first_holder(17, None)?;
    let records = check(&program)?;
    let paused = records
        .iter()
        .find(|record| record.state.holder_phase == HolderPhase::AppObservation)
        .unwrap();
    let reference = paused.reference.as_ref().unwrap();
    assert!(reference_matches(paused, reference));
    for field in ["now", "queues", "endpoints"] {
        let mut changed = reference.clone();
        changed["world"][field] = Value::Null;
        assert!(!reference_matches(paused, &changed));
    }
    for field in ["schedule", "failed"] {
        let mut changed = reference.clone();
        changed[field] = Value::Null;
        assert!(!reference_matches(paused, &changed));
    }
    let mut bad = paused.clone();
    bad.handshake["oracle"]["now"] = Value::Null;
    assert!(!reference_matches(&bad, reference));
    Ok(())
}

#[test]
fn first_holder_advance_bound_is_independent_of_the_ordinary_event_allowance() -> Result<()> {
    let mut events = vec![Event::StartFirstHolder { death_cut: None }];
    events.extend(std::iter::repeat_n(
        Event::AdvanceFirstHolder,
        MAX_HANDSHAKE_ADVANCES + 1,
    ));
    assert!(events.len() < MAX_EVENTS + MAX_HANDSHAKE_ADVANCES);
    let program = Program {
        version: 1,
        seed: 17,
        physical: None,
        events,
    };
    assert!(run(&program).is_err());
    Ok(())
}

#[test]
fn stepped_first_holder_keeps_wire_completion_separate_from_file_retention() -> Result<()> {
    for seed in 0..8 {
        let mut program = stepped_first_holder(seed, None)?;
        let first = check(&program)?;
        let observe = program
            .events
            .iter()
            .position(|event| matches!(event, Event::ObserveFirstHolder { work_nanos: 0 }))
            .unwrap();
        let retain = program.events.len() - 1;
        assert_eq!(
            first[observe - 1].state.holder_phase,
            HolderPhase::AppObservation
        );
        assert_eq!(
            first[observe - 1].handshake["actual"]["endpoints"][0]["machine"]["position"],
            3
        );
        assert_eq!(
            first[retain - 1].state.holder_phase,
            HolderPhase::ControllerRetention
        );
        assert!(!first[retain - 1].state.first_holder);
        for endpoint in first[retain - 1].handshake["actual"]["endpoints"]
            .as_array()
            .unwrap()
        {
            assert_eq!(endpoint["machine"]["position"], 6);
            assert_eq!(endpoint["machine"]["busy"], false);
        }
        assert!(first[retain].state.first_holder && first[retain].state.continuation);
        assert_eq!(first[retain].state.holder_phase, HolderPhase::Retained);
        let complete = check(&Program {
            version: 1,
            seed,
            physical: None,
            events: vec![Event::FirstHolder { death_cut: None }],
        })?;
        assert_eq!(first.last(), complete.last());
        let baseline = successful(seed);
        program.events.extend_from_slice(&baseline.events[1..]);
        let records = check(&program)?;
        assert_eq!(records.last().unwrap().state.current, 3);
        assert_eq!(
            records.last().unwrap().state,
            check(&baseline)?.last().unwrap().state
        );
    }
    Ok(())
}

#[test]
fn pending_file_obligations_block_provider_work_and_never_rearm_after_reopen() -> Result<()> {
    for boundary in [
        Event::ObserveFirstHolder { work_nanos: 0 },
        Event::RetainFirstHolder { work_nanos: 0 },
    ] {
        let mut program = stepped_first_holder(17, None)?;
        let cut = program
            .events
            .iter()
            .position(|event| *event == boundary)
            .unwrap();
        program.events.truncate(cut);
        program.events.extend([
            Event::Bootstrap {
                stage: 0,
                operation: Operation::Reserve,
                fault: Fault::None,
            },
            Event::Reopen,
            Event::RestoreClock,
            boundary,
            Event::AdvanceFirstHolder,
            Event::FirstHolder { death_cut: None },
            Event::Current {
                death_cut: None,
                rewrite_provider: false,
            },
        ]);
        let records = check(&program)?;
        for record in &records[cut..] {
            assert!(!record.state.first_holder && !record.state.continuation);
            assert_eq!(record.state.holder_phase, HolderPhase::Refused);
            assert_eq!(
                (record.state.slot_posts, record.state.counter_posts),
                (0, 0)
            );
        }
        assert!(!records[cut].accepted && !records.last().unwrap().accepted);
    }
    Ok(())
}

#[test]
fn file_work_spends_the_original_interval_and_equality_refuses_even_after_wire_completion()
-> Result<()> {
    for seed in 0..4 {
        for boundary in [
            Event::ObserveFirstHolder { work_nanos: 0 },
            Event::RetainFirstHolder { work_nanos: 0 },
        ] {
            let mut program = stepped_first_holder(seed, None)?;
            let cut = program
                .events
                .iter()
                .position(|event| *event == boundary)
                .unwrap();
            let prefix = check(&Program {
                events: program.events[..cut].to_vec(),
                ..program.clone()
            })?;
            let snapshot = &prefix.last().unwrap().handshake["actual"];
            let now: Duration = serde_json::from_value(snapshot["now"].clone())?;
            for endpoint in snapshot["endpoints"].as_array().unwrap() {
                assert_eq!(
                    serde_json::from_value::<Duration>(endpoint["clock"]["origin"].clone())?,
                    Duration::from_secs(100)
                );
                assert_eq!(
                    serde_json::from_value::<Duration>(endpoint["clock"]["deadline"].clone())?,
                    Duration::from_secs(110)
                );
            }
            let equality = u64::try_from((Duration::from_secs(110) - now).as_nanos())?;
            program.events.truncate(cut);
            program.events.extend([
                Event::FileTime { nanos: equality },
                boundary,
                Event::Reopen,
                Event::RestoreClock,
                Event::FirstHolder { death_cut: None },
                Event::Bootstrap {
                    stage: 0,
                    operation: Operation::Reserve,
                    fault: Fault::None,
                },
            ]);
            let records = check(&program)?;
            assert!(records[cut].accepted);
            assert!(!records[cut + 1].accepted);
            for record in &records[cut + 1..] {
                assert!(!record.state.continuation && !record.state.first_holder);
                assert_eq!(
                    (record.state.slot_posts, record.state.counter_posts),
                    (0, 0)
                );
            }
            assert!(!records.last().unwrap().accepted);
        }
    }
    Ok(())
}

#[test]
fn file_observation_precheck_skips_work_and_postcheck_keeps_the_actual_file_primary() -> Result<()>
{
    struct Opaque;
    impl std::fmt::Display for Opaque {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign Display")
        }
    }
    impl std::fmt::Debug for Opaque {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("foreign Debug")
        }
    }
    impl std::error::Error for Opaque {}
    for boundary in [
        Event::ObserveFirstHolder { work_nanos: 0 },
        Event::RetainFirstHolder { work_nanos: 0 },
    ] {
        let program = stepped_first_holder(17, None)?;
        let cut = program
            .events
            .iter()
            .position(|event| *event == boundary)
            .unwrap();
        let endpoint = usize::from(matches!(boundary, Event::RetainFirstHolder { .. }));
        for precheck_failure in [false, true] {
            let mut world = World::new(17, None)?;
            for &event in &program.events[..cut] {
                assert!(world.step(event)?.accepted);
            }
            let snapshot = world.handshake.snapshot();
            let now: Duration = serde_json::from_value(snapshot["actual"]["now"].clone())?;
            let equality = u64::try_from((Duration::from_secs(110) - now).as_nanos())?;
            if precheck_failure {
                world.handshake.advance_file_time(equality)?;
            }
            let before = world.handshake.snapshot()["schedule"]["events"]
                .as_u64()
                .unwrap();
            let calls = std::cell::Cell::new(0);
            let error = anyhow::Error::new(Opaque);
            let primary = error.root_cause() as *const dyn std::error::Error;
            let mut continuation = world.continuation;
            let result = lifecycle_fixture::phase(&mut continuation, || {
                checked_file_observation(&mut world.handshake, endpoint, equality, || {
                    calls.set(calls.get() + 1);
                    Err(error)
                })
            });
            let refused = match result {
                Ok(()) => panic!("file observation accepted"),
                Err(error) => error,
            };
            assert!(!continuation);
            let after = world.handshake.snapshot();
            assert_eq!(after["actual"]["endpoints"][endpoint]["refused"], true);
            assert_eq!(
                world.checked_accepted,
                matches!(boundary, Event::RetainFirstHolder { .. })
            );
            if precheck_failure {
                assert_eq!(calls.get(), 0);
                assert_eq!(after["schedule"]["events"].as_u64().unwrap(), before + 1);
            } else {
                assert_eq!(calls.get(), 1);
                assert!(refused.is::<Opaque>());
                assert!(std::ptr::eq(primary, refused.root_cause()));
                assert_eq!(after["schedule"]["events"].as_u64().unwrap(), before + 3);
            }
        }
    }
    Ok(())
}

#[test]
fn time_spent_inside_the_file_action_refuses_retention_without_erasing_checked_accepted()
-> Result<()> {
    for boundary in [
        Event::ObserveFirstHolder { work_nanos: 0 },
        Event::RetainFirstHolder { work_nanos: 0 },
    ] {
        let mut program = stepped_first_holder(17, None)?;
        let cut = program
            .events
            .iter()
            .position(|event| *event == boundary)
            .unwrap();
        let prefix = check(&Program {
            events: program.events[..cut].to_vec(),
            ..program.clone()
        })?;
        let now: Duration =
            serde_json::from_value(prefix.last().unwrap().handshake["actual"]["now"].clone())?;
        let work_nanos = u64::try_from((Duration::from_secs(110) - now).as_nanos())?;
        let action = match boundary {
            Event::ObserveFirstHolder { .. } => Event::ObserveFirstHolder { work_nanos },
            Event::RetainFirstHolder { .. } => Event::RetainFirstHolder { work_nanos },
            _ => unreachable!(),
        };
        program.events.truncate(cut);
        program.events.extend([
            action,
            Event::Reopen,
            Event::RestoreClock,
            Event::RetainFirstHolder { work_nanos: 0 },
        ]);
        let records = check(&program)?;
        assert!(!records[cut].accepted);
        for record in &records[cut..] {
            assert!(!record.state.continuation && !record.state.first_holder);
            assert_eq!(
                record.state.checked_accepted,
                matches!(boundary, Event::RetainFirstHolder { .. })
            );
            assert_eq!(record.state.holder_phase, HolderPhase::Refused);
            assert_eq!(record.state.counter_posts, 0);
        }
    }
    Ok(())
}

#[test]
fn file_boundary_rewind_refuses_but_small_forward_work_keeps_the_same_original() -> Result<()> {
    for boundary in [
        Event::ObserveFirstHolder { work_nanos: 0 },
        Event::RetainFirstHolder { work_nanos: 0 },
    ] {
        for seed in 0..4 {
            let complete = stepped_first_holder(seed, None)?;
            let cut = complete
                .events
                .iter()
                .position(|event| *event == boundary)
                .unwrap();
            let mut rewind = complete.clone();
            rewind.events.truncate(cut);
            rewind.events.extend([
                Event::FileRewind {
                    nanos: 1_000_000_000,
                },
                boundary,
                Event::Reopen,
                Event::RestoreClock,
                Event::FirstHolder { death_cut: None },
            ]);
            let records = check(&rewind)?;
            assert!(records[cut].accepted && !records[cut + 1].accepted);
            assert!(
                records[cut + 1..]
                    .iter()
                    .all(|record| !record.state.first_holder && !record.state.continuation)
            );
            assert!(!records.last().unwrap().accepted);
            let mut forward = complete;
            forward.events[cut] = match boundary {
                Event::ObserveFirstHolder { .. } => Event::ObserveFirstHolder {
                    work_nanos: 1_000_000,
                },
                Event::RetainFirstHolder { .. } => Event::RetainFirstHolder {
                    work_nanos: 1_000_000,
                },
                _ => unreachable!(),
            };
            let records = check(&forward)?;
            assert!(records.iter().all(|record| record.accepted));
            assert!(records.last().unwrap().state.first_holder);
            for endpoint in records.last().unwrap().handshake["actual"]["endpoints"]
                .as_array()
                .unwrap()
            {
                assert_eq!(
                    serde_json::from_value::<Duration>(endpoint["clock"]["origin"].clone())?,
                    Duration::from_secs(100)
                );
                assert_eq!(
                    serde_json::from_value::<Duration>(endpoint["clock"]["deadline"].clone())?,
                    Duration::from_secs(110)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn stepwise_peer_death_is_observed_before_any_later_file_or_provider_action() -> Result<()> {
    let mut refused = 0;
    for seed in 0..8 {
        for cut in [0, 3, 21, 47, 79, 100] {
            let mut program = stepped_first_holder(seed, Some(cut))?;
            program.events.extend([
                Event::Reopen,
                Event::RestoreClock,
                Event::ObserveFirstHolder { work_nanos: 0 },
                Event::RetainFirstHolder { work_nanos: 0 },
                Event::Bootstrap {
                    stage: 0,
                    operation: Operation::Reserve,
                    fault: Fault::None,
                },
            ]);
            let records = check(&program)?;
            assert!(!records.last().unwrap().accepted);
            assert!(!records.last().unwrap().state.continuation);
            assert!(!records.last().unwrap().state.first_holder);
            assert_eq!(records.last().unwrap().state.counter_posts, 0);
            refused += usize::from(records.iter().any(|record| !record.accepted));
        }
    }
    assert_eq!(refused, 48);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn real_original_file_mutation_at_offer_and_after_accepted_never_becomes_retention() -> Result<()> {
    let mut cuts = BTreeSet::new();
    for seed in 0..2 {
        for boundary in [
            Event::ObserveFirstHolder { work_nanos: 0 },
            Event::RetainFirstHolder { work_nanos: 0 },
        ] {
            for change in [FileChange::Tamper, FileChange::Replace, FileChange::Shorten] {
                let mut program = stepped_first_holder(seed, None)?;
                program.physical =
                    Some(crate::security_epoch::storage_authority::FileFixture::initial_image());
                program.events.insert(
                    0,
                    Event::PrepareOriginal {
                        input: PreparationInput::SUCCESS,
                    },
                );
                let cut = program
                    .events
                    .iter()
                    .position(|event| *event == boundary)
                    .unwrap();
                program.events.truncate(cut);
                program.events.extend([
                    Event::File { change },
                    boundary,
                    Event::File {
                        change: FileChange::Restore,
                    },
                    Event::Reopen,
                    Event::RestoreClock,
                    Event::RetainFirstHolder { work_nanos: 0 },
                    Event::FirstHolder { death_cut: None },
                    Event::Bootstrap {
                        stage: 0,
                        operation: Operation::Reserve,
                        fault: Fault::None,
                    },
                ]);
                let records = check(&program)?;
                assert!(!records[cut + 1].accepted);
                if matches!(boundary, Event::RetainFirstHolder { .. }) {
                    assert_eq!(
                        records[cut].state.holder_phase,
                        HolderPhase::ControllerRetention
                    );
                    assert_eq!(
                        records[cut].handshake["actual"]["endpoints"][1]["machine"]["position"],
                        6
                    );
                }
                for record in &records[cut + 1..] {
                    assert!(!record.state.continuation && !record.state.first_holder);
                    assert_eq!(record.state.holder_phase, HolderPhase::Refused);
                    assert_eq!(
                        (record.state.slot_posts, record.state.counter_posts),
                        (0, 0)
                    );
                }
                assert!(!records.last().unwrap().accepted);
                cuts.insert(format!("{seed}/{boundary:?}/{change:?}"));
            }
        }
    }
    assert_eq!(cuts.len(), 12);
    Ok(())
}

fn stepped_completion(seed: u64, target: Event) -> Result<(Program, usize)> {
    let baseline = successful(seed);
    let index = baseline
        .events
        .iter()
        .position(|event| *event == target)
        .context("completion target absent")?;
    let input = World::new(seed, None)?;
    // Immutable fixture inputs only; no actual execution or observation selects
    // the expected schedule. All decisions below belong to the separate oracle.
    let mut reference = model::Model::new(seed, &input.cores, None, &input.image_binding)?;
    let mut events = baseline.events[..index].to_vec();
    for &event in &events {
        ensure!(reference.step(event)?.0, "reference prefix refused");
    }
    let (work, death_cut) = match target {
        Event::Bootstrap {
            stage,
            operation,
            fault,
        } => (
            CompletionWork::Bootstrap {
                stage,
                operation,
                fault,
            },
            None,
        ),
        Event::Current {
            death_cut,
            rewrite_provider,
        } => (CompletionWork::Current { rewrite_provider }, death_cut),
        _ => anyhow::bail!("unsupported completion target"),
    };
    let start = events.len();
    let begin = Event::StartCompletion { work, death_cut };
    ensure!(reference.step(begin)?.0, "reference start refused");
    events.push(begin);
    loop {
        let state: State = serde_json::from_value(reference.observation())?;
        let completion = state.completion.context("reference completion missing")?;
        let event = match completion.phase {
            CompletionPhase::Wire | CompletionPhase::AfterMutation | CompletionPhase::Releasing => {
                Event::AdvanceCompletion
            }
            CompletionPhase::Mutation => Event::MutateCompletion,
            CompletionPhase::Release => Event::PrepareCompletionRelease,
            CompletionPhase::FinalFile => Event::FinishCompletion,
            CompletionPhase::Complete => break,
            CompletionPhase::Refused => anyhow::bail!("reference completion refused"),
        };
        ensure!(reference.step(event)?.0, "reference event refused");
        events.push(event);
    }
    events.extend_from_slice(&baseline.events[index + 1..]);
    Ok((Program { events, ..baseline }, start))
}

fn completion_targets() -> Vec<Event> {
    let mut targets = Vec::new();
    for stage in 0..2 {
        for operation in [Operation::Reserve, Operation::Dispatch, Operation::Settle] {
            targets.push(Event::Bootstrap {
                stage,
                operation,
                fault: Fault::None,
            });
        }
    }
    targets.push(Event::Current {
        death_cut: None,
        rewrite_provider: false,
    });
    targets
}

#[test]
fn stepped_completions_keep_local_ready_separate_from_receipt_and_final_completion() -> Result<()> {
    for seed in 0..4 {
        for target in completion_targets() {
            let (program, start) = stepped_completion(seed, target)?;
            let records = check(&program)?;
            let finish = program
                .events
                .iter()
                .position(|event| matches!(event, Event::FinishCompletion))
                .unwrap();
            let pending = records[finish - 1].state.completion.unwrap();
            assert_eq!(pending.phase, CompletionPhase::FinalFile);
            assert!(pending.peer_complete && pending.consumed_checked);
            assert_eq!(
                records[finish].state.completion.unwrap().phase,
                CompletionPhase::Complete
            );
            if matches!(target, Event::Current { .. }) {
                assert_eq!(records[finish - 1].state.current, 0);
                assert_eq!(records[finish].state.current, 1);
            } else {
                let mutation = program
                    .events
                    .iter()
                    .position(|event| matches!(event, Event::MutateCompletion))
                    .unwrap();
                // The Controller's checked local Ready send permits its mutation;
                // App receipt is a separate later event, not an invented barrier.
                assert_eq!(
                    records[mutation - 1].handshake["actual"]["endpoints"][1]["machine"]["position"],
                    5
                );
                assert_eq!(
                    records[mutation - 1].handshake["actual"]["endpoints"][0]["machine"]["position"],
                    4
                );
                assert!(
                    !records[mutation - 1]
                        .state
                        .completion
                        .unwrap()
                        .mutation_known
                );
                assert!(records[mutation].state.completion.unwrap().mutation_known);
            }
            for record in &records[start..=finish] {
                assert!(record.accepted);
            }
            assert_eq!(
                records.last().unwrap().state,
                check(&successful(seed))?.last().unwrap().state
            );
            assert_eq!(
                records.last().unwrap().handshake,
                check(&successful(seed))?.last().unwrap().handshake
            );
        }
    }
    Ok(())
}

#[test]
fn pending_completion_cannot_start_another_scope_or_publish_current_even_with_active_rows()
-> Result<()> {
    for target in completion_targets() {
        for obligation in [
            Event::MutateCompletion,
            Event::PrepareCompletionRelease,
            Event::FinishCompletion,
        ] {
            let (mut program, _) = stepped_completion(17, target)?;
            let Some(cut) = program.events.iter().position(|event| *event == obligation) else {
                continue;
            };
            program.events.truncate(cut);
            program.events.extend([
                Event::Current {
                    death_cut: None,
                    rewrite_provider: false,
                },
                Event::Reopen,
                Event::RestoreClock,
                obligation,
                Event::FinishCompletion,
                Event::Bootstrap {
                    stage: 0,
                    operation: Operation::Reserve,
                    fault: Fault::None,
                },
            ]);
            let records = check(&program)?;
            let before = records[cut - 1].state.clone();
            for record in &records[cut..] {
                assert!(!record.state.continuation);
                assert_eq!(
                    record.state.completion.unwrap().phase,
                    CompletionPhase::Refused
                );
                assert_eq!(record.state.counter, before.counter);
                assert_eq!(record.state.slots, before.slots);
                assert_eq!(
                    (
                        record.state.counter_posts,
                        record.state.slot_posts,
                        record.state.current
                    ),
                    (before.counter_posts, before.slot_posts, before.current)
                );
            }
            assert!(!records[cut].accepted && !records.last().unwrap().accepted);
        }
    }
    Ok(())
}

#[test]
fn actual_consumer_with_active_rows_stays_blocked_until_its_pending_completion_finishes()
-> Result<()> {
    let scope = tests::selection().scope;
    let mut consumer = ConsumerLifecycle::new(17, &scope)?;
    let (program, _) = stepped_completion(
        17,
        Event::Bootstrap {
            stage: 1,
            operation: Operation::Settle,
            fault: Fault::None,
        },
    )?;
    let finish = program
        .events
        .iter()
        .position(|event| matches!(event, Event::FinishCompletion))
        .unwrap();
    for &event in &program.events[..finish] {
        let actual = consumer.world.step(event)?;
        let expected = consumer.model.step(event)?;
        assert_eq!((actual.accepted, &actual.state), (expected.0, &expected.1));
    }
    assert!(consumer.world.activation.is_some());
    assert_eq!(
        consumer.world.completion.unwrap().phase,
        CompletionPhase::FinalFile
    );
    assert!(!consumer.model.consumer_current());
    let before = counter_fixture::snapshot(&consumer.world.port.counter)["calls"].clone();
    assert!(consumer.check(&scope, false).is_err());
    assert_eq!(
        counter_fixture::snapshot(&consumer.world.port.counter)["calls"],
        before
    );
    let actual = consumer.world.step(Event::FinishCompletion)?;
    let expected = consumer.model.step(Event::FinishCompletion)?;
    assert_eq!((actual.accepted, &actual.state), (expected.0, &expected.1));
    assert!(actual.accepted);
    consumer.check(&scope, false)?;
    Ok(())
}

#[test]
fn unknown_counter_completion_keeps_may_and_applied_rows_without_known_or_reuse() -> Result<()> {
    for stage in 0..2 {
        for fault in [
            Fault::LostCounterAfter,
            Fault::MalformedCounterReply,
            Fault::RolledBackCounterWrite,
        ] {
            let (mut program, start) = stepped_completion(
                17,
                Event::Bootstrap {
                    stage,
                    operation: Operation::Dispatch,
                    fault: Fault::None,
                },
            )?;
            program.events[start] = Event::StartCompletion {
                work: CompletionWork::Bootstrap {
                    stage,
                    operation: Operation::Dispatch,
                    fault,
                },
                death_cut: None,
            };
            let cut = program
                .events
                .iter()
                .position(|event| matches!(event, Event::MutateCompletion))
                .unwrap();
            program.events.extend([
                Event::Reopen,
                Event::RestoreClock,
                Event::Observe { stage },
                Event::FinishCompletion,
                Event::Bootstrap {
                    stage,
                    operation: Operation::Settle,
                    fault: Fault::None,
                },
            ]);
            let records = check(&program)?;
            let failed = &records[cut];
            assert!(!failed.accepted && !failed.state.continuation);
            let completion = failed.state.completion.unwrap();
            assert!(!completion.mutation_known && !completion.peer_complete);
            assert_eq!(completion.phase, CompletionPhase::Refused);
            assert_eq!(failed.state.counter_posts, stage + 1);
            let before = &records[cut - 1].state.counter;
            if fault == Fault::RolledBackCounterWrite {
                assert_eq!(failed.state.counter["documents"], before["documents"]);
                assert_eq!(failed.state.counter_rollback_failures, 1);
            } else {
                assert_ne!(failed.state.counter["documents"], before["documents"]);
            }
            for record in &records[cut..] {
                assert_eq!(record.state.counter, failed.state.counter);
                assert_eq!(record.state.slots, failed.state.slots);
                assert_eq!(record.state.counter_posts, failed.state.counter_posts);
                assert!(!record.state.continuation);
            }
            assert!(!records.last().unwrap().accepted);
        }
    }
    Ok(())
}

#[test]
fn lost_known_consumed_and_released_packets_never_become_remote_receipts() -> Result<()> {
    let mut covered = BTreeSet::new();
    for target in completion_targets() {
        for (sender, packet) in [(1, "known"), (0, "consumed"), (1, "released")] {
            let (mut program, start) = stepped_completion(17, target)?;
            let input = World::new(17, None)?;
            let mut reference = model::Model::new(17, &input.cores, None, &input.image_binding)?;
            let mut found = None;
            for (index, &event) in program.events.iter().enumerate() {
                ensure!(reference.step(event)?.0, "loss prefix refused");
                if index >= start
                    && reference.handshake_snapshot()["world"]["queues"][sender][0]["frame"]["step"]
                        == packet
                {
                    found = Some(index + 1);
                    break;
                }
            }
            let cut = found.context("completion packet not actually queued")?;
            program.events.insert(cut, Event::LosePacket { sender });
            program.events.extend([
                Event::Reopen,
                Event::RestoreClock,
                Event::FinishCompletion,
                Event::Current {
                    death_cut: None,
                    rewrite_provider: false,
                },
            ]);
            let records = check(&program)?;
            assert!(records[cut].accepted);
            let known = &records[cut - 1].state;
            let refused = records[cut + 1..]
                .iter()
                .position(|record| !record.accepted)
                .context("lost packet did not refuse")?
                + cut
                + 1;
            for record in &records[refused..] {
                assert!(!record.state.continuation);
                assert!(!record.state.completion.unwrap().peer_complete);
                assert_eq!(record.state.counter, known.counter);
                assert_eq!(record.state.slots, known.slots);
                assert_eq!(record.state.current, known.current);
            }
            assert!(!records.last().unwrap().accepted);
            covered.insert(format!("{target:?}/{packet}"));
        }
    }
    assert_eq!(covered.len(), 21);
    Ok(())
}

#[test]
fn explicit_work_time_keeps_wire_and_provider_origins_separate_without_renewal() -> Result<()> {
    let target = Event::Bootstrap {
        stage: 0,
        operation: Operation::Reserve,
        fault: Fault::None,
    };
    let (mut program, _) = stepped_completion(17, target)?;
    let cut = program
        .events
        .iter()
        .position(|event| matches!(event, Event::MutateCompletion))
        .unwrap();
    let mut forward = program.clone();
    forward.events.insert(
        cut,
        Event::WorkTime {
            wire_nanos: 1_000_000,
            provider_nanos: 1_000_000,
        },
    );
    let forward_records = check(&forward)?;
    assert!(forward_records.iter().all(|record| record.accepted));
    assert_eq!(forward_records.last().unwrap().state.current, 3);
    assert_eq!(
        forward_records.last().unwrap().state.provider_time,
        Duration::from_secs(100) + Duration::from_millis(1)
    );
    program.events.insert(
        cut,
        Event::WorkTime {
            wire_nanos: 5_000_000_000,
            provider_nanos: 5_000_000_000,
        },
    );
    let records = check(&program)?;
    assert!(records[cut].accepted && !records[cut + 1].accepted);
    assert_eq!(records[cut].state.provider_time, Duration::from_secs(105));
    assert_eq!(
        (
            records[cut + 1].state.slot_posts,
            records[cut + 1].state.counter_posts
        ),
        (0, 0)
    );
    assert_eq!(
        records[cut].handshake["actual"]["endpoints"][1]["machine"]["purpose"],
        "storage_bootstrap"
    );
    let wire = &records[cut].handshake["actual"]["endpoints"][1]["clock"];
    let origin: Duration = serde_json::from_value(wire["origin"].clone())?;
    let deadline: Duration = serde_json::from_value(wire["deadline"].clone())?;
    assert_eq!(deadline - origin, Duration::from_secs(60));
    assert!(!records.last().unwrap().state.continuation);

    let (mut current, _) = stepped_completion(
        17,
        Event::Current {
            death_cut: None,
            rewrite_provider: false,
        },
    )?;
    let cut = current
        .events
        .iter()
        .position(|event| matches!(event, Event::PrepareCompletionRelease))
        .unwrap();
    let input = World::new(17, None)?;
    let mut reference = model::Model::new(17, &input.cores, None, &input.image_binding)?;
    for &event in &current.events[..cut] {
        assert!(reference.step(event)?.0);
    }
    let clock = reference.handshake_snapshot();
    let now: Duration = serde_json::from_value(clock["world"]["now"].clone())?;
    let deadline: Duration =
        serde_json::from_value(clock["world"]["endpoints"][1]["clock"]["deadline"].clone())?;
    let equality = u64::try_from((deadline - now).as_nanos())?;
    current.events.insert(
        cut,
        Event::WorkTime {
            wire_nanos: equality,
            provider_nanos: equality,
        },
    );
    let records = check(&current)?;
    assert!(records[cut].accepted && !records[cut + 1].accepted);
    assert_eq!(records.last().unwrap().state.current, 0);
    assert_eq!(
        records[cut].handshake["actual"]["endpoints"][1]["machine"]["purpose"],
        "current_role"
    );
    assert!(!records.last().unwrap().state.continuation);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn activation_checks_initial_bytes_before_release_then_physical_identity_after_peer_finish()
-> Result<()> {
    let target = Event::Bootstrap {
        stage: 1,
        operation: Operation::Settle,
        fault: Fault::None,
    };
    for (boundary, change, accepted) in [
        (Event::PrepareCompletionRelease, FileChange::AppWrite, false),
        (Event::FinishCompletion, FileChange::AppWrite, true),
        (Event::FinishCompletion, FileChange::Replace, false),
    ] {
        let (mut program, _) = stepped_completion(17, target)?;
        program.physical =
            Some(crate::security_epoch::storage_authority::FileFixture::initial_image());
        program.events.insert(
            0,
            Event::PrepareOriginal {
                input: PreparationInput::SUCCESS,
            },
        );
        let cut = program
            .events
            .iter()
            .position(|event| *event == boundary)
            .unwrap();
        if !accepted {
            program.events.truncate(cut);
        }
        program.events.insert(cut, Event::File { change });
        if !accepted {
            program.events.extend([
                boundary,
                Event::File {
                    change: FileChange::Restore,
                },
                Event::Reopen,
                Event::RestoreClock,
                Event::Current {
                    death_cut: None,
                    rewrite_provider: false,
                },
            ]);
        }
        let records = check(&program)?;
        assert_eq!(records[cut + 1].accepted, accepted);
        if accepted {
            assert_eq!(records.last().unwrap().state.current, 3);
        } else {
            assert!(!records[cut + 1].state.continuation);
            let state = records[cut + 1].state.completion.unwrap();
            assert!(state.consumed_checked);
            assert_eq!(
                state.peer_complete,
                matches!(boundary, Event::FinishCompletion)
            );
            for record in &records[cut + 1..] {
                assert!(!record.state.continuation);
                assert_eq!(record.state.counter, records[cut].state.counter);
            }
        }
    }
    Ok(())
}

#[test]
fn bootstrap_and_current_completion_helpers_keep_distinct_purpose_and_final_release() -> Result<()>
{
    let records = check(&successful(17))?;
    let final_record = records.last().unwrap();
    assert_eq!(final_record.state.current, 3);
    let completed = final_record.state.completion.unwrap();
    assert_eq!(completed.phase, CompletionPhase::Complete);
    assert!(completed.consumed_checked && completed.peer_complete);
    assert_eq!(final_record.state.provider_time, Duration::from_secs(100));
    for endpoint in final_record.handshake["actual"]["endpoints"]
        .as_array()
        .unwrap()
    {
        assert_eq!(endpoint["machine"]["sequence"], 9);
        assert_eq!(endpoint["machine"]["purpose"], "current_role");
    }
    assert!(reference_matches(
        final_record,
        final_record.reference.as_ref().unwrap()
    ));
    Ok(())
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
fn budget_order_observation_requires_the_actual_primary_error() -> Result<()> {
    let mut port = SharedPort::new();
    port.counter.set_slot_fixture_time(Duration::from_secs(100));
    let mut budget = Budget::for_context(port.sample()?, Duration::from_secs(105))?;
    port.counter.set_slot_fixture_time(Duration::from_secs(104));
    ensure!(
        budget.remaining(&mut port)? == Duration::from_secs(1),
        "original deadline changed"
    );
    port.counter.set_slot_fixture_time(Duration::from_secs(103));
    let rewound = budget
        .remaining(&mut port)
        .err()
        .context("rewound budget accepted")?;
    ensure!(
        is_primary_budget_order_failure(&rewound),
        "actual rewind cause missing"
    );
    ensure!(
        is_primary_budget_order_failure(&rewound.context("outer phase context")),
        "outer context erased actual rewind"
    );

    port.counter.set_slot_fixture_time(Duration::from_secs(100));
    let mut budget = Budget::for_context(port.sample()?, Duration::from_secs(105))?;
    port.counter.set_slot_fixture_time(Duration::from_secs(104));
    ensure!(
        budget.remaining(&mut port)? == Duration::from_secs(1),
        "original deadline changed"
    );
    port.counter.set_slot_fixture_time(Duration::from_secs(105));
    let expired = budget
        .remaining(&mut port)
        .err()
        .context("equality expiry accepted")?;
    ensure!(
        !is_primary_budget_order_failure(&expired),
        "expiry substituted for rewind"
    );
    ensure!(
        !is_primary_budget_order_failure(&expired.context("security_epoch_clock_domain_or_rewind")),
        "secondary label substituted for the actual primary"
    );
    Ok(())
}

#[test]
fn generated_post_commit_clock_rewinds_keep_durable_state_and_refuse_reuse() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..4 {
        let baseline = successful(seed);
        let reference = check(&baseline)?;
        for (index, event) in baseline.events.iter().enumerate() {
            let Event::Bootstrap {
                stage, operation, ..
            } = *event
            else {
                continue;
            };
            let mut pairs = vec![(Fault::RewoundSlotClock, Fault::ForwardSlotClock)];
            if operation == Operation::Dispatch {
                pairs.push((Fault::RewoundCounterClock, Fault::ForwardCounterClock));
            }
            for (rewound, forward) in pairs {
                let mut control = baseline.clone();
                control.events[index] = Event::Bootstrap {
                    stage,
                    operation,
                    fault: forward,
                };
                let control: Program = serde_json::from_slice(&serde_json::to_vec(&control)?)?;
                let positive = check(&control)?;
                let end = &positive.last().unwrap().state;
                // The controlled tick and selected fault are now retained
                // explicitly. They differ by design; every other field must
                // still equal the same successful untimed lifecycle.
                let mut expected = reference[index].state.clone();
                ensure!(
                    expected.provider_time == Duration::from_secs(100)
                        && expected.completion.is_some_and(|state| state.work
                            == CompletionWork::Bootstrap {
                                stage,
                                operation,
                                fault: Fault::None
                            }),
                    "baseline clock/control metadata changed"
                );
                expected.provider_time = Duration::from_secs(103);
                expected.completion.as_mut().unwrap().work = CompletionWork::Bootstrap {
                    stage,
                    operation,
                    fault: forward,
                };
                ensure!(
                    positive[index].accepted
                        && end.continuation
                        && end.current == 3
                        && end.clock_order_failures == 0
                        && positive[index].state == expected,
                    "forward clock control did not complete the same lifecycle"
                );

                let mut program = baseline.clone();
                program.events.truncate(index);
                program.events.push(Event::Bootstrap {
                    stage,
                    operation,
                    fault: rewound,
                });
                program.events.extend([
                    Event::RestoreClock,
                    Event::Observe { stage },
                    Event::Bootstrap {
                        stage,
                        operation,
                        fault: Fault::None,
                    },
                    Event::Reopen,
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
                let program: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
                let records = check(&program)?;
                let committed_slot = &reference[index].state;
                // A rewound claim reply is not a known claim: May is durable,
                // but no counter send is admitted. A counter-reply rewind
                // occurs after that counter write has actually committed.
                let committed_counter =
                    if operation == Operation::Dispatch && rewound == Fault::RewoundSlotClock {
                        &reference[index - 1].state
                    } else {
                        committed_slot
                    };
                ensure!(!records[index].accepted, "rewound reply was accepted");
                for record in &records[index..] {
                    ensure!(
                        !record.state.continuation
                            && record.state.clock_order_failures == 1
                            && record.state.counter == committed_counter.counter
                            && record.state.slots == committed_slot.slots
                            && record.state.slot_posts == committed_slot.slot_posts
                            && record.state.counter_posts == committed_counter.counter_posts,
                        "rewind cause, committed state or permanent refusal changed"
                    );
                }
                ensure!(
                    !records[index + 3].accepted
                        && !records[index + 5].accepted
                        && !records.last().unwrap().accepted,
                    "restored clock or reopened provider revived the actual continuation"
                );
                coverage.insert(format!("{stage}-{operation:?}-{rewound:?}"));
                coverage.insert(format!("{stage}-{operation:?}-{forward:?}"));
            }
        }
    }
    ensure!(
        coverage.len() == 16,
        "post-commit clock cut coverage incomplete"
    );
    Ok(())
}

#[test]
fn generated_malformed_counter_acknowledgements_keep_commits_and_refuse_reuse() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..4 {
        let baseline = successful(seed);
        let reference = check(&baseline)?;
        let end = &reference.last().unwrap().state;
        ensure!(
            end.continuation && end.current == 3 && end.counter_decode_failures == 0,
            "ordinary acknowledgement control did not complete"
        );
        for (index, event) in baseline.events.iter().enumerate() {
            let Event::Bootstrap {
                stage,
                operation: Operation::Dispatch,
                ..
            } = *event
            else {
                continue;
            };
            let mut program = baseline.clone();
            program.events.truncate(index);
            program.events.push(Event::Bootstrap {
                stage,
                operation: Operation::Dispatch,
                fault: Fault::MalformedCounterReply,
            });
            program.events.extend([
                Event::RestoreClock,
                Event::Observe { stage },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Settle,
                    fault: Fault::None,
                },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Dispatch,
                    fault: Fault::None,
                },
                Event::Reopen,
                Event::Observe { stage },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Dispatch,
                    fault: Fault::None,
                },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Settle,
                    fault: Fault::None,
                },
                Event::Current {
                    death_cut: None,
                    rewrite_provider: false,
                },
            ]);
            let program: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
            let records = check(&program)?;
            let committed = &reference[index].state;
            ensure!(
                !records[index].accepted,
                "malformed acknowledgement accepted"
            );
            for record in &records[index..] {
                ensure!(
                    !record.state.continuation
                        && record.state.counter_decode_failures == 1
                        && record.state.counter == committed.counter
                        && record.state.slots == committed.slots
                        && record.state.slot_posts == committed.slot_posts
                        && record.state.counter_posts == committed.counter_posts,
                    "decode cause, committed state or permanent refusal changed"
                );
            }
            for (event, record) in program.events.iter().zip(&records).skip(index + 1) {
                let historical_data = matches!(
                    event,
                    Event::RestoreClock | Event::Observe { .. } | Event::Reopen
                );
                ensure!(
                    record.accepted == historical_data,
                    "readback or attempted reuse changed"
                );
            }
            coverage.insert(stage);
        }
    }
    ensure!(
        coverage == BTreeSet::from([0, 1]),
        "counter acknowledgement stage coverage incomplete"
    );
    Ok(())
}

#[test]
fn generated_counter_transaction_rollbacks_keep_may_and_refuse_reuse() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..4 {
        let baseline = successful(seed);
        let reference = check(&baseline)?;
        let end = &reference.last().unwrap().state;
        ensure!(
            end.continuation && end.current == 3 && end.counter_rollback_failures == 0,
            "ordinary counter commit control did not complete"
        );
        for (index, event) in baseline.events.iter().enumerate() {
            let Event::Bootstrap {
                stage,
                operation: Operation::Dispatch,
                ..
            } = *event
            else {
                continue;
            };
            let mut program = baseline.clone();
            program.events.truncate(index);
            program.events.push(Event::Bootstrap {
                stage,
                operation: Operation::Dispatch,
                fault: Fault::RolledBackCounterWrite,
            });
            program.events.extend([
                Event::RestoreClock,
                Event::Observe { stage },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Dispatch,
                    fault: Fault::None,
                },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Settle,
                    fault: Fault::None,
                },
                Event::Reopen,
                Event::Observe { stage },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Settle,
                    fault: Fault::None,
                },
                Event::Bootstrap {
                    stage,
                    operation: Operation::Dispatch,
                    fault: Fault::None,
                },
                Event::Current {
                    death_cut: None,
                    rewrite_provider: false,
                },
            ]);
            let program: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
            let records = check(&program)?;
            let before = &reference[index - 1].state;
            let attempted = &reference[index].state;
            ensure!(
                !records[index].accepted,
                "partial counter transaction accepted"
            );
            for record in &records[index..] {
                ensure!(
                    !record.state.continuation
                        && record.state.counter_rollback_failures == 1
                        && record.state.counter["documents"] == before.counter["documents"]
                        && record.state.counter["sends"] == attempted.counter["sends"]
                        && record.state.slots == attempted.slots
                        && record.state.slot_posts == attempted.slot_posts
                        && record.state.counter_posts == attempted.counter_posts,
                    "rollback, durable May, attempted send or permanent refusal changed"
                );
            }
            for (event, record) in program.events.iter().zip(&records).skip(index + 1) {
                let historical_data = matches!(
                    event,
                    Event::RestoreClock | Event::Observe { .. } | Event::Reopen
                );
                ensure!(
                    record.accepted == historical_data,
                    "readback or attempted reuse changed"
                );
            }
            coverage.insert(stage);
        }
    }
    ensure!(
        coverage == BTreeSet::from([0, 1]),
        "counter rollback stage coverage incomplete"
    );
    Ok(())
}

#[test]
fn generated_canonical_provider_replacement_and_restore_preserve_observed_refusal() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..8 {
        let baseline = successful(seed);
        let currents = baseline
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, event)| matches!(event, Event::Current { .. }).then_some(i))
            .collect::<Vec<_>>();
        let mut random = seed;
        let prefix = currents[next(&mut random) as usize % currents.len()];
        for record in CounterRecord::ALL {
            for observed in [false, true] {
                let mut program = baseline.clone();
                program.events.truncate(prefix);
                if record != CounterRecord::OutsideSelection {
                    // A row outside every selected read input must survive
                    // the selected-row replacement and exact restoration.
                    program.events.push(Event::CounterReplace {
                        record: CounterRecord::OutsideSelection,
                    });
                }
                let before = program.events.len() - 1;
                let replace = program.events.len();
                program.events.push(Event::CounterReplace { record });
                program.events.push(Event::Reopen);
                let data_check = program.events.len();
                program.events.push(Event::Observe { stage: 1 });
                let first_check = program.events.len();
                if observed {
                    program.events.push(Event::Current {
                        death_cut: None,
                        rewrite_provider: false,
                    });
                }
                let restore = program.events.len();
                program.events.extend([
                    Event::CounterRestore { record },
                    Event::RestoreClock,
                    Event::Observe { stage: 1 },
                    Event::Current {
                        death_cut: None,
                        rewrite_provider: false,
                    },
                    Event::Reopen,
                    Event::Current {
                        death_cut: None,
                        rewrite_provider: false,
                    },
                ]);
                // The exact serialized program, including replacement target
                // and ordering, is the replay input; no test-only side channel.
                let program: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
                let records = check(&program)?;
                let prior = &records[before].state;
                let final_record = records.last().unwrap();
                let refused = observed && record != CounterRecord::OutsideSelection;
                ensure!(
                    records[replace].accepted && records[restore].accepted,
                    "external replacement/restore fixture did not complete"
                );
                ensure!(
                    records[data_check].accepted == (record == CounterRecord::OutsideSelection),
                    "independent DATA read did not check selected contents"
                );
                if observed {
                    ensure!(
                        records[first_check].accepted != refused,
                        "replacement observation not exercised"
                    );
                }
                ensure!(
                    records[restore + 2].accepted,
                    "restored DATA observation failed"
                );
                ensure!(
                    records[restore + 3].accepted != refused,
                    "restored same-port Current decision changed before reopen"
                );
                ensure!(
                    final_record.accepted != refused && final_record.state.continuation != refused,
                    "restoration changed the retained continuation decision"
                );
                ensure!(
                    final_record.state.counter == prior.counter
                        && final_record.state.slots == prior.slots,
                    "external restoration altered durable rows or send history"
                );
                ensure!(
                    final_record.state.slot_posts == prior.slot_posts
                        && final_record.state.counter_posts == prior.counter_posts,
                    "read-only replacement history dispatched a writer send"
                );
                let increments = if refused {
                    0
                } else {
                    2 + usize::from(observed)
                };
                ensure!(
                    final_record.state.current == prior.current + increments,
                    "replacement released an unexpected Current"
                );
                coverage.insert((record, observed));
            }
        }
    }
    ensure!(coverage.len() == 10, "replacement observation coverage");
    Ok(())
}

#[test]
fn generated_provider_replacements_fence_each_remaining_bootstrap_boundary() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..4 {
        let baseline = successful(seed);
        for (index, event) in baseline.events.iter().enumerate() {
            let Event::Bootstrap {
                stage, operation, ..
            } = *event
            else {
                continue;
            };
            // These are precisely the boundaries with an existing initial
            // authority; the activation receipt first exists before Settle1.
            if stage == 0 && operation != Operation::Settle {
                continue;
            }
            for record in CounterRecord::ALL {
                if record == CounterRecord::ActivationReceipt
                    && !(stage == 1 && operation == Operation::Settle)
                {
                    continue;
                }
                for observed in [false, true] {
                    let mut program = baseline.clone();
                    program.events.truncate(index);
                    let before = program.events.len() - 1;
                    let replace = program.events.len();
                    program.events.push(Event::CounterReplace { record });
                    let boundary = program.events.len();
                    if observed {
                        program.events.push(*event);
                    }
                    program.events.push(Event::CounterRestore { record });
                    program
                        .events
                        .extend_from_slice(&baseline.events[index + usize::from(observed)..]);
                    let program: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
                    let records = check(&program)?;
                    let refused = observed && record != CounterRecord::OutsideSelection;
                    ensure!(
                        records[replace].accepted,
                        "bootstrap replacement was not injected"
                    );
                    if observed {
                        ensure!(
                            records[boundary].accepted != refused,
                            "bootstrap replacement boundary not exercised"
                        );
                        if refused {
                            ensure!(
                                records[boundary].state.counter_posts
                                    == records[before].state.counter_posts
                                    && records[boundary].state.slot_posts
                                        == records[before].state.slot_posts,
                                "invalid selected state dispatched a bootstrap write"
                            );
                        }
                    }
                    let final_state = &records.last().unwrap().state;
                    ensure!(
                        final_state.continuation != refused
                            && final_state.current == if refused { 0 } else { 3 },
                        "bootstrap restoration revived refusal or blocked an unobserved edit"
                    );
                    coverage.insert(format!("{stage}-{operation:?}-{record:?}-{observed}"));
                }
            }
        }
    }
    ensure!(
        coverage.len() == 34,
        "bootstrap provider replacement coverage"
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
            let event = match next(&mut random) % 10 {
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
                n @ (6 | 7) => Event::Bootstrap {
                    stage,
                    operation: [Operation::Reserve, Operation::Dispatch, Operation::Settle]
                        [next(&mut random) as usize % 3],
                    fault: if n == 6 {
                        Fault::None
                    } else {
                        Fault::LostSlotReply
                    },
                },
                8 => Event::CounterReplace {
                    record: CounterRecord::ALL
                        [next(&mut random) as usize % CounterRecord::ALL.len()],
                },
                _ => Event::CounterRestore {
                    record: CounterRecord::ALL
                        [next(&mut random) as usize % CounterRecord::ALL.len()],
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
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_BUNDLE,
        "lifecycle replay byte bound"
    );
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BUNDLE,
        "lifecycle replay byte bound"
    );
    let bundle: Bundle = serde_json::from_slice(&bytes)?;
    ensure!(
        bundle.version == 1 && bundle.source == source(),
        "lifecycle replay source/version mismatch"
    );
    let fixture = World::new(bundle.program.seed, bundle.program.physical.as_deref())?;
    ensure!(
        fixture.binding()? == bundle.binding,
        "lifecycle replay immutable fixture inputs changed"
    );
    drop(fixture);
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
            program.events.push(match choice % 9 {
                0 => Event::Reopen,
                1 => Event::RestoreClock,
                2 => Event::Observe { stage: usize::from(choice % 2) },
                3 => Event::Current { death_cut: None, rewrite_provider: false },
                4 => Event::FirstHolder { death_cut: Some(usize::from(choice)) },
                5 | 6 => Event::Bootstrap {
                    stage: usize::from(choice % 2),
                    operation: [Operation::Reserve, Operation::Dispatch, Operation::Settle][usize::from(choice % 3)],
                    fault: Fault::None,
                },
                7 => Event::CounterReplace { record: CounterRecord::ALL[usize::from(choice) % CounterRecord::ALL.len()] },
                _ => Event::CounterRestore { record: CounterRecord::ALL[usize::from(choice) % CounterRecord::ALL.len()] },
            });
        }
        let result = check(&program);
        proptest::prop_assert!(result.is_ok(), "{}", result.err().unwrap());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn generated_post_write_file_refusals_preserve_commits_without_resend() -> Result<()> {
    let mut coverage = BTreeSet::new();
    for seed in 0..4 {
        let mut baseline = successful(seed);
        baseline.physical =
            Some(crate::security_epoch::storage_authority::FileFixture::initial_image());
        baseline.events.insert(
            0,
            Event::PrepareOriginal {
                input: PreparationInput::SUCCESS,
            },
        );
        let baseline: Program = serde_json::from_slice(&serde_json::to_vec(&baseline)?)?;
        let successful_records = check(&baseline)?;
        for (index, event) in baseline.events.iter().enumerate() {
            let Event::Bootstrap {
                stage, operation, ..
            } = *event
            else {
                continue;
            };
            for fault in [
                Fault::FileTamperAfter,
                Fault::FileReplaceAfter,
                Fault::FileShortenAfter,
            ] {
                let mut program = baseline.clone();
                program.events.truncate(index);
                program.events.push(Event::Bootstrap {
                    stage,
                    operation,
                    fault,
                });
                program.events.extend([
                    Event::Observe { stage },
                    Event::File {
                        change: FileChange::Restore,
                    },
                    Event::Reopen,
                    Event::RestoreClock,
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
                // The new cut itself must survive the same serialized input
                // and twice-replay path as a retained divergence bundle.
                let program: Program = serde_json::from_slice(&serde_json::to_vec(&program)?)?;
                let records = check(&program)?;
                let expected = &successful_records[index].state;
                ensure!(
                    successful_records[index].accepted,
                    "reference write did not complete"
                );
                ensure!(
                    !records[index].accepted,
                    "post-write file failure was accepted"
                );
                for record in &records[index..] {
                    ensure!(
                        !record.state.continuation
                            && record.state.counter == expected.counter
                            && record.state.slots == expected.slots
                            && record.state.slot_posts == expected.slot_posts
                            && record.state.counter_posts == expected.counter_posts,
                        "post-write refusal erased committed state or resent after restoration"
                    );
                }
                ensure!(
                    !records[records.len() - 2].accepted && !records.last().unwrap().accepted,
                    "restored post-write continuation resumed"
                );
                coverage.insert(format!("{stage}-{operation:?}-{fault:?}"));
            }
        }
    }
    ensure!(
        coverage.len() == 18,
        "post-write file cut coverage incomplete"
    );
    Ok(())
}

#[test]
fn post_write_file_faults_require_an_actual_original_image_before_execution() -> Result<()> {
    let baseline = successful(0);
    for (index, event) in baseline.events.iter().enumerate() {
        let Event::Bootstrap {
            stage, operation, ..
        } = *event
        else {
            continue;
        };
        for fault in [
            Fault::FileTamperAfter,
            Fault::FileReplaceAfter,
            Fault::FileShortenAfter,
        ] {
            let mut program = baseline.clone();
            program.events[index] = Event::Bootstrap {
                stage,
                operation,
                fault,
            };
            let error = run(&program)
                .err()
                .context("physical fault admitted without an image")?;
            ensure!(
                error.to_string() == "lifecycle physical fault requires original image",
                "physical fault was not refused at input admission"
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn generated_real_file_histories_join_the_same_first_holder_and_writer_decisions() -> Result<()> {
    for seed in 0..4 {
        let mut baseline = successful(seed);
        baseline.physical =
            Some(crate::security_epoch::storage_authority::FileFixture::initial_image());
        baseline.events.insert(
            0,
            Event::PrepareOriginal {
                input: PreparationInput::SUCCESS,
            },
        );
        // Persist/reload the actual image input before running. The complete
        // retained bytes, not a fresh initializer or a weaker logical digest,
        // must survive both executions and process-boundary replay.
        let baseline: Program = serde_json::from_slice(&serde_json::to_vec(&baseline)?)?;
        check(&baseline)?;
        for change in [FileChange::Tamper, FileChange::Replace, FileChange::Shorten] {
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
        for change in [FileChange::AppWrite, FileChange::Shorten] {
            let mut current = baseline.clone();
            let index = current
                .events
                .iter()
                .position(|e| matches!(e, Event::Current { .. }))
                .unwrap();
            current.events.insert(index, Event::File { change });
            ensure!(
                check(&current)?.last().unwrap().state.current == 3,
                "physical current check incorrectly required initial bytes/length"
            );
        }
    }
    Ok(())
}
