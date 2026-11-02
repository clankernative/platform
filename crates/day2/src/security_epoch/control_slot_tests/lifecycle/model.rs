//! Independent lifecycle rules and complete expected provider rows. No call to
//! Slot transitions, reconciliation, codecs, clock helpers or permission APIs.
//! Immutable fixture DATA and serde/hash primitives are shared, not decisions.
use super::*;
use crate::security_epoch::kernel::{AuthorityRecord, Receipt, SentinelRecord};
use std::collections::BTreeMap;

pub(super) struct Model {
    state: State,
    cores: [Value; 2],
    logical: [Digest; 2],
    requests: [Digest; 2],
    receipts: [Value; 2],
    records: [[Value; 2]; 2],
    names: [String; 4],
    slot_names: [String; 2],
    slots: [Option<Value>; 2],
    versions: [u64; 2],
    documents: BTreeMap<String, (Value, u64)>,
    replaced: BTreeMap<CounterRecord, Option<(Value, u64)>>,
    applied: usize,
    clock_invalid: bool,
    active: bool,
    file_refused: bool,
    handshake: LifecycleReference,
}

fn fields(value: &Value) -> Value {
    Value::Object(
        value
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| {
                let field = match value {
                    Value::String(_) => json!({"stringValue":value}),
                    Value::Object(_) => json!({"mapValue":{"fields":fields(value)}}),
                    _ => panic!("fixture record outside string/map specification"),
                };
                (key.clone(), field)
            })
            .collect(),
    )
}

fn digest<T: Serialize>(tag: &str, value: &T) -> Digest {
    Digest::of(&(tag, value)).unwrap()
}

impl Model {
    pub(super) fn observation(&self) -> Value {
        serde_json::to_value(&self.state).unwrap()
    }

    pub(super) fn handshake_snapshot(&self) -> Value {
        self.handshake.snapshot()
    }

    pub(super) fn consumer_current(&self) -> bool {
        self.active
            && self.state.first_holder
            && self.state.continuation
            && self
                .state
                .completion
                .is_none_or(|state| state.phase == CompletionPhase::Complete)
            && !self.clock_invalid
            && !self.file_refused
    }

    pub(super) fn new(
        seed: u64,
        cores: &[LogicalCore; 2],
        physical: bool,
        image_binding: &Option<Digest>,
    ) -> Result<Self> {
        let values = [
            serde_json::to_value(&cores[0])?,
            serde_json::to_value(&cores[1])?,
        ];
        let logical = [
            digest("day2-control-logical-core-v1", &cores[0]),
            digest("day2-control-logical-core-v1", &cores[1]),
        ];
        let requests = [
            digest("day2-external-epoch-request-v1", &cores[0].counter),
            digest("day2-external-epoch-request-v1", &cores[1].counter),
        ];
        let bootstrap = &values[0]["counter"]["bootstrap"];
        let authority = bootstrap["authority"]
            .as_str()
            .unwrap()
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned();
        let prefix = "projects/project-seven/databases/security/documents";
        let root = format!("{prefix}/day2_credential_authority_v1/{authority}");
        let sentinel = format!("{prefix}/day2_credential_bootstrap_v1/{authority}");
        let operation = |n: usize| {
            let counter = &values[n]["counter"];
            if n == 0 {
                counter["bootstrap"]["create_operation"].as_str().unwrap()
            } else {
                counter["operation"].as_str().unwrap()
            }
            .strip_prefix("sha256:")
            .unwrap()
            .to_owned()
        };
        let names = [
            root.clone(),
            sentinel,
            format!("{root}/operations/{}", operation(0)),
            format!("{root}/operations/{}", operation(1)),
        ];
        let records: [[Value; 2]; 2] = std::array::from_fn(|stage| {
            let request = &values[stage]["counter"];
            let phase = if stage == 0 {
                json!({"phase":"pending_first_holder"})
            } else {
                json!({"phase":"active_first_holder","completion":{
                    "operation":request["operation"],"request":requests[stage],"parent_receipt":request["parent_receipt"],
                    "before":request["before"],"holder":request["holder"]
                }})
            };
            [
                json!({"format":"day2_credential_authority_v1","bootstrap":bootstrap,"epoch":"1","phase":phase}),
                json!({"format":"day2_credential_bootstrap_v1","bootstrap":bootstrap,"initial_epoch":"1","phase":phase}),
            ]
        });
        let mut receipts = [Value::Null, Value::Null];
        for stage in 0..2 {
            // These immutable DTOs supply only their reviewed serialization
            // order. Expected phases, holders and receipt contents above/below
            // are specified independently; no production constructor is used.
            let root: AuthorityRecord = serde_json::from_value(records[stage][0].clone())?;
            let sentinel: SentinelRecord = serde_json::from_value(records[stage][1].clone())?;
            receipts[stage] = json!({"format":"day2_credential_epoch_receipt_v1","request":values[stage]["counter"],
                "request_digest":requests[stage],"after_root":Digest::of(&root)?,"after_sentinel":Digest::of(&sentinel)?});
        }
        Ok(Self {
            state: State {
                binding: Digest::of(&("day2-storage-lifecycle-fixture-v1", cores, image_binding))?,
                continuation: true,
                first_holder: false,
                checked_accepted: false,
                holder_phase: HolderPhase::NotStarted,
                completion: None,
                provider_time: Duration::from_secs(100),
                current: 0,
                slot_posts: 0,
                counter_posts: 0,
                counter_rollback_failures: 0,
                clock_order_failures: 0,
                counter_decode_failures: 0,
                counter: Value::Null,
                slots: Value::Null,
                file: physical.then_some(FileState {
                    named_original: true,
                    held_original: true,
                    image_exact: true,
                }),
            },
            cores: values,
            logical,
            requests,
            receipts,
            records,
            names,
            slot_names: [
                format!("{prefix}/day2_credential_control_v1/{authority}-create"),
                format!("{prefix}/day2_credential_control_v1/{authority}-complete"),
            ],
            slots: [None, None],
            versions: [0, 0],
            documents: BTreeMap::new(),
            replaced: BTreeMap::new(),
            applied: 0,
            clock_invalid: false,
            active: false,
            file_refused: false,
            handshake: LifecycleReference::new(seed)?,
        })
    }

    fn first_file_valid(&mut self) -> bool {
        let valid =
            !self.file_refused
                && self.state.file.as_ref().is_none_or(|file| {
                    file.named_original && file.held_original && file.image_exact
                });
        self.file_refused |= !valid;
        valid
    }

    fn first_holder_step(&mut self, event: Event) -> Result<bool> {
        if !self.state.continuation {
            return Ok(false);
        }
        let accepted = match event {
            Event::StartFirstHolder { death_cut } => {
                if self.state.holder_phase != HolderPhase::NotStarted
                    || self.state.first_holder
                    || !self.first_file_valid()
                {
                    false
                } else {
                    self.handshake.begin_exchange(death_cut, 0)?;
                    self.state.holder_phase = HolderPhase::BeforeOffer;
                    true
                }
            }
            Event::AdvanceFirstHolder => {
                if !matches!(
                    self.state.holder_phase,
                    HolderPhase::BeforeOffer | HolderPhase::AfterAppObservation
                ) || self.handshake.progress()? == LifecycleProgress::Refused
                {
                    false
                } else {
                    self.handshake.advance_exchange()?;
                    if self.handshake.progress()? == LifecycleProgress::Refused {
                        false
                    } else if self.handshake.controller_accepted_checked()? {
                        self.state.checked_accepted = true;
                        if self.state.holder_phase != HolderPhase::AfterAppObservation {
                            false
                        } else {
                            self.state.holder_phase = HolderPhase::ControllerRetention;
                            true
                        }
                    } else {
                        if self.state.holder_phase == HolderPhase::BeforeOffer
                            && self.handshake.app_observation_ready()?
                        {
                            self.state.holder_phase = HolderPhase::AppObservation;
                        }
                        true
                    }
                }
            }
            Event::ObserveFirstHolder { work_nanos } => {
                if self.state.holder_phase != HolderPhase::AppObservation
                    || !self.handshake.app_observation_ready()?
                    || !self.handshake.check_file_boundary(0)?
                {
                    false
                } else {
                    let requested = self.first_file_valid();
                    if work_nanos != 0 {
                        self.handshake.advance_file_time(work_nanos)?;
                    }
                    let checked = self.handshake.check_file_boundary(0)?;
                    if requested && checked {
                        self.state.holder_phase = HolderPhase::AfterAppObservation;
                        true
                    } else {
                        false
                    }
                }
            }
            Event::RetainFirstHolder { work_nanos } => {
                if self.state.holder_phase != HolderPhase::ControllerRetention
                    || !self.handshake.controller_accepted_checked()?
                    || !self.handshake.check_file_boundary(1)?
                {
                    false
                } else {
                    let requested = self.first_file_valid();
                    if work_nanos != 0 {
                        self.handshake.advance_file_time(work_nanos)?;
                    }
                    let checked = self.handshake.check_file_boundary(1)?;
                    if requested && checked {
                        self.state.first_holder = true;
                        self.state.holder_phase = HolderPhase::Retained;
                        true
                    } else {
                        false
                    }
                }
            }
            _ => unreachable!(),
        };
        if !accepted {
            self.state.continuation = false;
            if !self.state.first_holder {
                self.state.holder_phase = HolderPhase::Refused;
            }
        }
        Ok(accepted)
    }

    fn complete_first_holder(&mut self, death_cut: Option<usize>) -> Result<bool> {
        if !self.first_holder_step(Event::StartFirstHolder { death_cut })? {
            return Ok(false);
        }
        loop {
            let event = match self.state.holder_phase {
                HolderPhase::BeforeOffer | HolderPhase::AfterAppObservation => {
                    Event::AdvanceFirstHolder
                }
                HolderPhase::AppObservation => Event::ObserveFirstHolder { work_nanos: 0 },
                HolderPhase::ControllerRetention => Event::RetainFirstHolder { work_nanos: 0 },
                HolderPhase::Retained => return Ok(true),
                _ => return Ok(false),
            };
            if !self.first_holder_step(event)? {
                return Ok(false);
            }
        }
    }

    fn write_slot(&mut self, stage: usize, state: Value) {
        self.versions[stage] += 1;
        self.slots[stage] = Some(
            json!({"format":"day2_credential_control_slot_v1","logical":self.cores[stage],"state":state}),
        );
        self.state.slot_posts += 1;
    }

    fn fault_time(&mut self, fault: Fault) {
        match fault {
            Fault::ExpiredSlotReply | Fault::ExpiredCounterReply => {
                self.state.provider_time = Duration::from_secs(105)
            }
            Fault::RewoundSlotClock
            | Fault::ForwardSlotClock
            | Fault::RewoundCounterClock
            | Fault::ForwardCounterClock => self.state.provider_time = Duration::from_secs(103),
            _ => {}
        }
    }

    fn bootstrap(&mut self, stage: usize, operation: Operation, fault: Fault) -> bool {
        if !self.state.first_holder
            || self.clock_invalid
            || self.state.provider_time < Duration::from_secs(100)
            || self.state.provider_time >= Duration::from_secs(105)
            || fault == Fault::ReplaceCandidate
            || !self.observed_documents_match()
        {
            return false;
        }
        let current = self.slots[stage]
            .as_ref()
            .map(|slot| slot["state"]["state"].as_str().unwrap());
        match operation {
            Operation::Reserve => {
                if current.is_some() || self.applied != stage {
                    return false;
                }
                self.write_slot(stage, json!({"state":"prepared","next":"1"}));
            }
            Operation::Dispatch => {
                if current != Some("prepared") || self.applied != stage {
                    return false;
                }
                let core = AttemptCore {
                    logical: self.logical[stage].clone(),
                    request: self.requests[stage].clone(),
                    ordinal: AttemptOrdinal::try_from("1".to_owned()).unwrap(),
                    expected: version(self.versions[stage]),
                    controller_incarnation: Digest::new(b"controller-data"),
                    nonce: Digest::new(b"lifecycle-original"),
                };
                let attempt = json!({"core":core,"id":digest("day2-control-attempt-v1", &core)});
                if fault == Fault::RewriteSlot {
                    self.versions[stage] += 1;
                    self.state.slot_posts += 1; // rejected CAS is still a send
                    return false;
                }
                self.write_slot(
                    stage,
                    json!({"state":"may_have_been_sent","attempt":attempt}),
                );
                if matches!(
                    fault,
                    Fault::ExpiredSlotReply | Fault::RewoundSlotClock | Fault::ForwardSlotClock
                ) {
                    self.fault_time(fault);
                }
                if matches!(
                    fault,
                    Fault::LostSlotReply
                        | Fault::MalformedSlotReply
                        | Fault::ExpiredSlotReply
                        | Fault::RewoundSlotClock
                        | Fault::AbandonClaim
                ) {
                    self.clock_invalid =
                        matches!(fault, Fault::ExpiredSlotReply | Fault::RewoundSlotClock);
                    self.state.clock_order_failures +=
                        usize::from(fault == Fault::RewoundSlotClock);
                    return false;
                }
                self.state.counter_posts += 1;
                if !matches!(
                    fault,
                    Fault::LostCounterBefore | Fault::RolledBackCounterWrite
                ) {
                    let next = self.applied as u64 + 1;
                    self.documents.insert(
                        self.names[0].clone(),
                        (self.records[stage][0].clone(), next),
                    );
                    self.documents.insert(
                        self.names[1].clone(),
                        (self.records[stage][1].clone(), next),
                    );
                    self.documents.insert(
                        self.names[2 + stage].clone(),
                        (self.receipts[stage].clone(), next),
                    );
                    self.applied += 1;
                }
                self.fault_time(fault);
                self.clock_invalid = matches!(
                    fault,
                    Fault::ExpiredCounterReply | Fault::RewoundCounterClock
                );
                self.state.clock_order_failures += usize::from(fault == Fault::RewoundCounterClock);
                self.state.counter_decode_failures +=
                    usize::from(fault == Fault::MalformedCounterReply);
                self.state.counter_rollback_failures +=
                    usize::from(fault == Fault::RolledBackCounterWrite);
                return matches!(
                    fault,
                    Fault::None | Fault::ForwardSlotClock | Fault::ForwardCounterClock
                );
            }
            Operation::Settle => {
                if current != Some("may_have_been_sent") || self.applied <= stage {
                    return false;
                }
                let lineage = self.slots[stage].as_ref().unwrap()["state"]["attempt"].clone();
                let receipt: Receipt =
                    serde_json::from_value(self.receipts[stage].clone()).unwrap();
                let core = SettlementCore {
                    logical: self.logical[stage].clone(),
                    expected: version(self.versions[stage]),
                    control_attempt: serde_json::from_value(lineage["id"].clone()).unwrap(),
                    receipt: digest("day2-external-epoch-receipt-v1", &receipt),
                };
                self.write_slot(stage, json!({"state":"observed","control_lineage":lineage,"receipt":self.receipts[stage],
                    "settlement":{"id":digest("day2-control-settlement-v1", &core),"core":core}}));
                if stage == 1 && matches!(fault, Fault::None | Fault::ForwardSlotClock) {
                    self.active = true;
                }
            }
        }
        self.fault_time(fault);
        self.clock_invalid = matches!(fault, Fault::ExpiredSlotReply | Fault::RewoundSlotClock);
        self.state.clock_order_failures += usize::from(fault == Fault::RewoundSlotClock);
        matches!(fault, Fault::None | Fault::ForwardSlotClock)
    }

    fn completion_file_valid(&mut self, physical: bool) -> bool {
        let valid = !self.file_refused
            && self.state.file.as_ref().is_none_or(|file| {
                file.named_original && file.held_original && (physical || file.image_exact)
            });
        self.file_refused |= !valid;
        valid
    }

    fn completion_step(&mut self, event: Event, endpoint: usize) -> Result<bool> {
        if !self.state.continuation {
            return Ok(false);
        }
        let accepted = match event {
            Event::StartCompletion { work, death_cut } => {
                if !self.state.first_holder
                    || self
                        .state
                        .completion
                        .is_some_and(|state| state.phase != CompletionPhase::Complete)
                {
                    false
                } else {
                    self.state.completion = Some(CompletionState {
                        work,
                        phase: CompletionPhase::Wire,
                        mutation_known: false,
                        consumed_checked: false,
                        peer_complete: false,
                    });
                    if !self.completion_file_valid(matches!(work, CompletionWork::Current { .. })) {
                        false
                    } else {
                        match work {
                            CompletionWork::Bootstrap { .. } => {
                                self.handshake
                                    .begin_bootstrap_exchange(death_cut, endpoint)?;
                                true
                            }
                            CompletionWork::Current { .. } => {
                                if !self.active
                                    || self.clock_invalid
                                    || !self.active_documents_match()
                                {
                                    false
                                } else {
                                    self.handshake.begin_exchange(death_cut, endpoint)?;
                                    true
                                }
                            }
                        }
                    }
                }
            }
            Event::AdvanceCompletion => {
                if let Some(mut state) = self.state.completion {
                    if !matches!(
                        state.phase,
                        CompletionPhase::Wire
                            | CompletionPhase::AfterMutation
                            | CompletionPhase::Releasing
                    ) || self.handshake.progress()? == LifecycleProgress::Refused
                    {
                        false
                    } else {
                        self.handshake.advance_exchange()?;
                        if self.handshake.progress()? == LifecycleProgress::Refused {
                            false
                        } else {
                            let mut valid = true;
                            if matches!(state.work, CompletionWork::Bootstrap { .. })
                                && state.phase == CompletionPhase::Wire
                                && self.handshake.bootstrap_work_ready()?
                            {
                                state.phase = CompletionPhase::Mutation;
                            } else if state.phase != CompletionPhase::Releasing
                                && self.handshake.controller_consumed_checked()?
                            {
                                if matches!(state.work, CompletionWork::Bootstrap { .. })
                                    && !state.mutation_known
                                {
                                    valid = false;
                                } else {
                                    state.consumed_checked = true;
                                    state.phase = CompletionPhase::Release;
                                }
                            } else if self.handshake.progress()?
                                == LifecycleProgress::ProtocolComplete
                            {
                                if state.phase != CompletionPhase::Releasing
                                    || !state.consumed_checked
                                {
                                    valid = false;
                                } else {
                                    state.peer_complete = true;
                                    state.phase = CompletionPhase::FinalFile;
                                }
                            }
                            self.state.completion = Some(state);
                            valid
                        }
                    }
                } else {
                    false
                }
            }
            Event::MutateCompletion => {
                if let Some(mut state) = self.state.completion {
                    if state.phase != CompletionPhase::Mutation
                        || !self.handshake.bootstrap_work_ready()?
                    {
                        false
                    } else if let CompletionWork::Bootstrap {
                        stage,
                        operation,
                        fault,
                    } = state.work
                    {
                        if !self.handshake.check_file_boundary(1)? {
                            false
                        } else {
                            let counter_fault = match fault {
                                Fault::FileTamperAfter
                                | Fault::FileReplaceAfter
                                | Fault::FileShortenAfter => Fault::None,
                                _ => fault,
                            };
                            let requested = self.bootstrap(stage, operation, counter_fault);
                            if requested && let Some(file) = self.state.file.as_mut() {
                                match fault {
                                    Fault::FileReplaceAfter => file.named_original = false,
                                    Fault::FileTamperAfter | Fault::FileShortenAfter => {
                                        file.image_exact = false
                                    }
                                    _ => {}
                                }
                            }
                            let checked = self.handshake.check_file_boundary(1)?;
                            if requested
                                && checked
                                && self.completion_file_valid(false)
                                && self.observed_documents_match()
                            {
                                state.phase = CompletionPhase::AfterMutation;
                                state.mutation_known = true;
                                self.state.completion = Some(state);
                                true
                            } else {
                                false
                            }
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Event::PrepareCompletionRelease => {
                if let Some(mut state) = self.state.completion {
                    if state.phase != CompletionPhase::Release
                        || !state.consumed_checked
                        || !self.handshake.controller_consumed_checked()?
                        || !self.handshake.check_file_boundary(1)?
                    {
                        false
                    } else {
                        let requested = self.completion_file_valid(matches!(
                            state.work,
                            CompletionWork::Current { .. }
                        ));
                        let checked = self.handshake.check_file_boundary(1)?;
                        if requested && checked {
                            state.phase = CompletionPhase::Releasing;
                            self.state.completion = Some(state);
                            true
                        } else {
                            false
                        }
                    }
                } else {
                    false
                }
            }
            Event::FinishCompletion => {
                if let Some(mut state) = self.state.completion {
                    if state.phase != CompletionPhase::FinalFile
                        || !state.peer_complete
                        || self.handshake.progress()? != LifecycleProgress::ProtocolComplete
                        || !self.handshake.check_file_boundary(1)?
                    {
                        false
                    } else {
                        let requested = match state.work {
                            CompletionWork::Bootstrap {
                                stage, operation, ..
                            } => self.completion_file_valid(
                                stage == 1 && operation == Operation::Settle,
                            ),
                            CompletionWork::Current { rewrite_provider } => {
                                if rewrite_provider {
                                    self.documents.get_mut(&self.names[0]).unwrap().1 += 1;
                                }
                                self.active
                                    && !self.clock_invalid
                                    && self.active_documents_match()
                                    && self.completion_file_valid(true)
                            }
                        };
                        let checked = self.handshake.check_file_boundary(1)?;
                        if requested && checked {
                            if matches!(state.work, CompletionWork::Current { .. }) {
                                self.state.current += 1;
                            }
                            state.phase = CompletionPhase::Complete;
                            self.state.completion = Some(state);
                            true
                        } else {
                            false
                        }
                    }
                } else {
                    false
                }
            }
            _ => unreachable!(),
        };
        if !accepted {
            self.state.continuation = false;
            if let Some(state) = self.state.completion.as_mut()
                && state.phase != CompletionPhase::Complete
            {
                state.phase = CompletionPhase::Refused;
            }
        }
        Ok(accepted)
    }

    fn complete_work(
        &mut self,
        work: CompletionWork,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<bool> {
        if !self.completion_step(Event::StartCompletion { work, death_cut }, endpoint)? {
            return Ok(false);
        }
        loop {
            let state = self
                .state
                .completion
                .context("reference completion absent")?;
            let event = match state.phase {
                CompletionPhase::Wire
                | CompletionPhase::AfterMutation
                | CompletionPhase::Releasing => Event::AdvanceCompletion,
                CompletionPhase::Mutation => Event::MutateCompletion,
                CompletionPhase::Release => Event::PrepareCompletionRelease,
                CompletionPhase::FinalFile => Event::FinishCompletion,
                CompletionPhase::Complete => return Ok(true),
                CompletionPhase::Refused => return Ok(false),
            };
            if !self.completion_step(event, endpoint)? {
                return Ok(false);
            }
        }
    }

    fn counter_name(&self, record: CounterRecord) -> String {
        match record {
            CounterRecord::Authority => self.names[0].clone(),
            CounterRecord::Sentinel => self.names[1].clone(),
            CounterRecord::CreateReceipt => self.names[2].clone(),
            CounterRecord::ActivationReceipt => self.names[3].clone(),
            CounterRecord::OutsideSelection => format!("{}/unrelated/record", self.names[0]),
        }
    }

    fn replace_counter(&mut self, record: CounterRecord) -> bool {
        if self.replaced.contains_key(&record) {
            return false;
        }
        let name = self.counter_name(record);
        let original = self.documents.get(&name).cloned();
        let source = if record == CounterRecord::OutsideSelection {
            self.documents.get(&self.names[0])
        } else {
            original.as_ref()
        };
        let Some((mut value, version)) = source.cloned() else {
            return false;
        };
        let bootstrap = if matches!(
            record,
            CounterRecord::CreateReceipt | CounterRecord::ActivationReceipt
        ) {
            &mut value["request"]["bootstrap"]
        } else {
            &mut value["bootstrap"]
        };
        bootstrap["record_incarnation"] =
            json!(Digest::new(b"external-provider-record-replacement"));
        self.documents.insert(name, (value, version));
        self.replaced.insert(record, original);
        true
    }

    fn restore_counter(&mut self, record: CounterRecord) -> bool {
        let Some(original) = self.replaced.remove(&record) else {
            return false;
        };
        let name = self.counter_name(record);
        if let Some(original) = original {
            self.documents.insert(name, original);
        } else {
            self.documents.remove(&name);
        }
        true
    }

    fn active_documents_match(&self) -> bool {
        let expected = [
            (&self.records[1][0], 2),
            (&self.records[1][1], 2),
            (&self.receipts[0], 1),
            (&self.receipts[1], 2),
        ];
        self.names
            .iter()
            .zip(expected)
            .all(|(name, (value, version))| {
                self.documents
                    .get(name)
                    .is_some_and(|actual| actual.0 == *value && actual.1 == version)
            })
    }

    fn observed_documents_match(&self) -> bool {
        if self.applied == 0 {
            return self
                .names
                .iter()
                .all(|name| !self.documents.contains_key(name));
        }
        let stage = self.applied - 1;
        let expected = [
            Some(&self.records[stage][0]),
            Some(&self.records[stage][1]),
            Some(&self.receipts[0]),
            (stage == 1).then_some(&self.receipts[1]),
        ];
        self.names
            .iter()
            .zip(expected)
            .all(|(name, expected)| self.documents.get(name).map(|(value, _)| value) == expected)
    }

    pub(super) fn step(&mut self, event: Event) -> Result<(bool, State)> {
        self.step_peer(event, 0)
    }

    pub(super) fn step_peer(&mut self, event: Event, endpoint: usize) -> Result<(bool, State)> {
        let accepted = match event {
            Event::WorkTime {
                wire_nanos,
                provider_nanos,
            } => {
                self.handshake.advance_file_time(wire_nanos)?;
                self.state.provider_time = self
                    .state
                    .provider_time
                    .checked_add(Duration::from_nanos(provider_nanos))
                    .context("reference clock overflow")?;
                true
            }
            Event::LosePacket { sender } => self.handshake.lose_packet(sender)?,
            Event::StartCompletion { .. }
            | Event::AdvanceCompletion
            | Event::MutateCompletion
            | Event::PrepareCompletionRelease
            | Event::FinishCompletion => self.completion_step(event, endpoint)?,
            Event::FileTime { nanos } => {
                self.handshake.advance_file_time(nanos)?;
                true
            }
            Event::FileRewind { nanos } => {
                self.handshake.rewind_file_time(nanos)?;
                true
            }
            Event::StartFirstHolder { .. }
            | Event::AdvanceFirstHolder
            | Event::ObserveFirstHolder { .. }
            | Event::RetainFirstHolder { .. } => self.first_holder_step(event)?,
            Event::CounterReplace { record } => self.replace_counter(record),
            Event::CounterRestore { record } => self.restore_counter(record),
            Event::Reopen => true,
            Event::RestoreClock => {
                self.clock_invalid = false;
                self.state.provider_time = Duration::from_secs(100);
                true
            }
            // An independent read-only DATA observation may use a fresh read
            // budget. It is never a replacement execution/continuation owner.
            Event::Observe { stage } => {
                (stage == 0 || self.applied > 0) && self.observed_documents_match()
            }
            Event::File { change } => {
                let file = self
                    .state
                    .file
                    .as_mut()
                    .context("physical fixture required")?;
                match change {
                    FileChange::Tamper | FileChange::AppWrite | FileChange::Shorten => {
                        file.image_exact = false
                    }
                    FileChange::Replace => file.named_original = false,
                    FileChange::Restore => {
                        file.image_exact = true;
                        file.named_original = true;
                    }
                }
                true
            }
            event => {
                let file_valid = self.state.file.as_ref().is_none_or(|file| {
                    file.named_original
                        && (matches!(event, Event::Bootstrap { .. } | Event::Current { .. })
                            || file.image_exact)
                });
                if !self.state.continuation {
                    false
                } else if !matches!(event, Event::Bootstrap { .. } | Event::Current { .. })
                    && (self.file_refused || !file_valid)
                {
                    self.file_refused = true;
                    self.state.continuation = false;
                    if !self.state.first_holder {
                        self.state.holder_phase = HolderPhase::Refused;
                    }
                    false
                } else {
                    let accepted = match event {
                        Event::FirstHolder { death_cut } => {
                            self.complete_first_holder(death_cut)?
                        }
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
                        )?,
                        Event::Current {
                            death_cut,
                            rewrite_provider,
                        } => self.complete_work(
                            CompletionWork::Current { rewrite_provider },
                            death_cut,
                            endpoint,
                        )?,
                        _ => unreachable!(),
                    };
                    self.state.continuation = accepted;
                    if !accepted && !self.state.first_holder {
                        self.state.holder_phase = HolderPhase::Refused;
                    }
                    accepted
                }
            }
        };
        let documents = self.documents.iter().map(|(name, (value, version))| json!({"name":name,"fields":fields(value),"version":version})).collect::<Vec<_>>();
        self.state.counter = json!({"documents":documents,"sends":self.state.counter_posts});
        let mut slots = Vec::new();
        for stage in 0..2 {
            if let Some(value) = &self.slots[stage] {
                let slot: Slot = serde_json::from_value(value.clone())?;
                slots.push(json!({"name":self.slot_names[stage],"fields":{
                    "control_json":{"stringValue":serde_json::to_string(&slot)?},
                    "control_digest":{"stringValue":digest("day2-control-document-v1", &slot)}
                },"version":self.versions[stage]}));
            }
        }
        slots.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        self.state.slots = json!(slots);
        Ok((accepted, self.state.clone()))
    }
}
