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
    applied: usize,
    expired: bool,
    active: bool,
    file_refused: bool,
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
    pub(super) fn new(cores: &[LogicalCore; 2], physical: bool) -> Result<Self> {
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
                binding: Digest::of(cores)?,
                continuation: true,
                first_holder: false,
                current: 0,
                slot_posts: 0,
                counter_posts: 0,
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
            applied: 0,
            expired: false,
            active: false,
            file_refused: false,
        })
    }

    fn write_slot(&mut self, stage: usize, state: Value) {
        self.versions[stage] += 1;
        self.slots[stage] = Some(
            json!({"format":"day2_credential_control_slot_v1","logical":self.cores[stage],"state":state}),
        );
        self.state.slot_posts += 1;
    }

    fn bootstrap(&mut self, stage: usize, operation: Operation, fault: Fault) -> bool {
        if !self.state.first_holder || self.expired || fault == Fault::ReplaceCandidate {
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
                    Fault::LostSlotReply
                        | Fault::MalformedSlotReply
                        | Fault::ExpiredSlotReply
                        | Fault::AbandonClaim
                ) {
                    self.expired = fault == Fault::ExpiredSlotReply;
                    return false;
                }
                self.state.counter_posts += 1;
                if fault != Fault::LostCounterBefore {
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
                self.expired = fault == Fault::ExpiredCounterReply;
                return fault == Fault::None;
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
                if stage == 1 && fault == Fault::None {
                    self.active = true;
                }
            }
        }
        self.expired = fault == Fault::ExpiredSlotReply;
        fault == Fault::None
    }

    pub(super) fn step(&mut self, event: Event) -> Result<(bool, State)> {
        let accepted = match event {
            Event::Reopen => true,
            Event::RestoreClock => {
                self.expired = false;
                true
            }
            // An independent read-only DATA observation may use a fresh read
            // budget. It is never a replacement execution/continuation owner.
            Event::Observe { stage } => stage == 0 || self.applied > 0,
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
                        && (matches!(event, Event::Current { .. }) || file.image_exact)
                });
                if !self.state.continuation {
                    false
                } else if self.file_refused || !file_valid {
                    self.file_refused = true;
                    self.state.continuation = false;
                    false
                } else {
                    let accepted = match event {
                        Event::FirstHolder { death_cut } => {
                            if self.state.first_holder || death_cut.is_some() {
                                false
                            } else {
                                self.state.first_holder = true;
                                true
                            }
                        }
                        Event::Bootstrap {
                            stage,
                            operation,
                            fault,
                        } => self.bootstrap(stage, operation, fault),
                        Event::Current {
                            death_cut,
                            rewrite_provider,
                        } => {
                            if !self.active || self.expired {
                                false
                            } else {
                                if rewrite_provider && death_cut.is_none() {
                                    self.documents.get_mut(&self.names[0]).unwrap().1 += 1;
                                }
                                if death_cut.is_some() || rewrite_provider {
                                    false
                                } else {
                                    self.state.current += 1;
                                    true
                                }
                            }
                        }
                        _ => unreachable!(),
                    };
                    self.state.continuation = accepted;
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
