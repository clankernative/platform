//! Specification oracle for the approved admitted-connection contract.
//!
//! Every value here is synthetic DATA in the existing test harness. In
//! particular, accepting an admission record constructs no native owner.
//! Production request/transport hooks will supply observations after their
//! ports land; the reference histories alone do not qualify that wiring.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod tests;

const FIVE_SECONDS: u64 = 5_000_000_000;
const MAX_EVENTS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    App,
    Shell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Purpose {
    Inspect,
    Update,
    Approve,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    connection: u8,
    // Fixed synthetic selected app/artifact/policy/resource fixture versus a
    // foreign selection. This DATA is never a production selection owner.
    selection: u8,
    role: Role,
    sequence: u64,
    id: u8,
    purpose: Purpose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    id: u8,
    domain: u8,
    origin: u64,
    deadline: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Fault {
    PeerDeath,
    ChannelClosure,
    IssuerDeath,
    Restart,
    Sender,
    Thread,
    Namespace,
    NamedFile,
    Descriptor,
    Authority,
    Epoch,
    Writer,
    Restore,
    // This is the explicitly accepted loss of post-admission content proof.
    ContentDrift,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FullWork {
    Executable,
    PhysicalAttachment,
    ProviderAuthentication,
    IssuerEnrollment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Admit {
        connection: u8,
        role: Role,
        // Code, runtime/role, sender, namespace, storage, attachment, writer,
        // and original: independent controlled admission observations.
        checks: [bool; 8],
        credential_deadline: u64,
    },
    Begin {
        request: Request,
        original: Original,
        deadline: u64,
    },
    Authority {
        request: Request,
    },
    Counters {
        request: Request,
        epoch: u64,
        writer: u64,
        version: u64,
        read: u64,
    },
    Handles {
        request: Request,
    },
    ArmSql {
        request: Request,
    },
    OpenSql {
        request: Request,
    },
    CommitSql {
        request: Request,
        final_original: bool,
    },
    RollbackSql {
        request: Request,
    },
    CloseSql {
        request: Request,
    },
    PostcheckSql {
        request: Request,
    },
    Send {
        request: Request,
        outcome: Effect,
    },
    Release {
        request: Request,
    },
    SqlFailure,
    CounterFailure,
    Cancel,
    Drop,
    Fault {
        fault: Fault,
    },
    RestoreObservedFacts,
    Advance {
        nanos: u64,
    },
    Rewind {
        nanos: u64,
    },
    FullWork {
        work: FullWork,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Effect {
    #[default]
    NotAttempted,
    Excluded,
    Known,
    MayHaveBeenSent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Refusal {
    Admission,
    Binding,
    Authority,
    Counter,
    Clock,
    Handles,
    SqlOrder,
    Unknown,
    Abandoned,
    RepeatedAdmission,
    Bound,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Sql {
    #[default]
    Closed,
    Armed,
    Open,
    Committed,
    RolledBack,
    ClosedCommitted,
    ClosedRolledBack,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    admissions: u64,
    requests: u64,
    handles: u64,
    counters: u64,
    sql_opens: u64,
    sends: u64,
    full_work: [u64; 4],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    request: Request,
    original: Original,
    origin: u64,
    deadline: u64,
    authority: bool,
    fresh_counter: bool,
    sql: Sql,
    committed_and_postchecked: bool,
    effect: Effect,
}

/// Expected state is recomputed from observations, never from production's
/// success, native owner flags, transition helpers or positive witnesses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Oracle {
    events: usize,
    connection: Option<(u8, Role)>,
    refused: Option<Refusal>,
    active: Option<Active>,
    now: u64,
    latest: u64,
    credential_deadline: u64,
    sequence: u64,
    used_requests: BTreeSet<u8>,
    originals: BTreeMap<u8, Original>,
    spent_originals: BTreeSet<u8>,
    bad_handles: bool,
    dead_handles: bool,
    revoked: bool,
    epoch: u64,
    writer: u64,
    version: u64,
    last_read: u64,
    counts: Counts,
}

impl Oracle {
    fn observe(&mut self, event: &Event) -> Result<(), Refusal> {
        if self.events == MAX_EVENTS {
            return Err(*self.refused.get_or_insert(Refusal::Bound));
        }
        self.events += 1;
        // Environment restoration can happen after failure. It cannot clear
        // the affected owner's actual refusal or spent-original history.
        match event {
            Event::Fault { fault } => {
                match fault {
                    Fault::PeerDeath
                    | Fault::ChannelClosure
                    | Fault::IssuerDeath
                    | Fault::Restart => self.dead_handles = true,
                    Fault::Authority => self.revoked = true,
                    Fault::Epoch => self.epoch += 1,
                    Fault::Writer => self.writer += 1,
                    Fault::Restore => self.version += 1,
                    Fault::ContentDrift => {}
                    _ => self.bad_handles = true,
                }
                return Ok(());
            }
            Event::RestoreObservedFacts => {
                self.bad_handles = false;
                self.revoked = false;
                return Ok(());
            }
            Event::Advance { nanos } => {
                let Some(now) = self.now.checked_add(*nanos) else {
                    return Err(*self.refused.get_or_insert(Refusal::Bound));
                };
                self.now = now;
                return Ok(());
            }
            Event::Rewind { nanos } => {
                self.now = self.now.saturating_sub(*nanos);
                return Ok(());
            }
            _ => {}
        }
        if let Some(first) = self.refused {
            return Err(first);
        }
        let result = self.transition(event);
        if let Err(reason) = result {
            self.refused = Some(reason);
            if let Some(active) = &self.active {
                self.spent_originals.insert(active.original.id);
            }
        }
        result
    }

    fn clock(&mut self) -> Result<(), Refusal> {
        if self.now < self.latest || self.now >= self.credential_deadline {
            return Err(Refusal::Clock);
        }
        self.latest = self.now;
        if let Some(active) = &self.active
            && (self.now < active.origin
                || self.now >= active.deadline
                || self.now >= active.original.deadline)
        {
            return Err(Refusal::Clock);
        }
        Ok(())
    }

    fn current(&mut self, request: Request) -> Result<&mut Active, Refusal> {
        self.clock()?;
        if self.bad_handles || self.dead_handles {
            return Err(Refusal::Handles);
        }
        if self.revoked {
            return Err(Refusal::Authority);
        }
        let active = self.active.as_mut().ok_or(Refusal::Binding)?;
        if active.request != request {
            return Err(Refusal::Binding);
        }
        Ok(active)
    }

    fn protected(&mut self, request: Request) -> Result<&mut Active, Refusal> {
        let active = self.current(request)?;
        if !active.authority {
            return Err(Refusal::Authority);
        }
        if !active.fresh_counter {
            return Err(Refusal::Counter);
        }
        active.fresh_counter = false;
        active.authority = false;
        Ok(active)
    }

    fn transition(&mut self, event: &Event) -> Result<(), Refusal> {
        match *event {
            Event::Admit {
                connection,
                role,
                checks,
                credential_deadline,
            } => {
                if self.connection.is_some()
                    || !checks.into_iter().all(|good| good)
                    || credential_deadline <= self.now
                {
                    return Err(Refusal::Admission);
                }
                self.connection = Some((connection, role));
                self.credential_deadline = credential_deadline;
                self.latest = self.now;
                self.epoch = 1;
                self.writer = 1;
                self.version = 1;
                self.counts.admissions += 1;
            }
            Event::Begin {
                request,
                original,
                deadline,
            } => {
                self.clock()?;
                if self.bad_handles || self.dead_handles {
                    return Err(Refusal::Handles);
                }
                if self.revoked {
                    return Err(Refusal::Authority);
                }
                let allowed = matches!(
                    (request.role, request.purpose),
                    (Role::App, Purpose::Inspect | Purpose::Update)
                        | (Role::Shell, Purpose::Approve)
                );
                if self.active.is_some()
                    || self.connection != Some((request.connection, request.role))
                    || request.selection != 0
                    || !allowed
                    || self.sequence.checked_add(1) != Some(request.sequence)
                    || self.used_requests.contains(&request.id)
                    || self.spent_originals.contains(&original.id)
                {
                    return Err(Refusal::Binding);
                }
                if original.domain != 1
                    || original.origin > self.now
                    || original.deadline <= self.now
                    || deadline <= self.now
                    || deadline > original.deadline
                    || deadline > self.credential_deadline
                    || deadline - self.now > FIVE_SECONDS
                    || self
                        .originals
                        .get(&original.id)
                        .is_some_and(|old| *old != original)
                {
                    return Err(Refusal::Clock);
                }
                self.originals.insert(original.id, original);
                self.used_requests.insert(request.id);
                self.sequence = request.sequence;
                self.counts.requests += 1;
                self.active = Some(Active {
                    request,
                    original,
                    origin: self.now,
                    deadline,
                    authority: false,
                    fresh_counter: false,
                    sql: Sql::Closed,
                    committed_and_postchecked: false,
                    effect: Effect::NotAttempted,
                });
            }
            Event::Authority { request } => self.current(request)?.authority = true,
            Event::Counters {
                request,
                epoch,
                writer,
                version,
                read,
            } => {
                self.current(request)?;
                if (self.epoch, self.writer, self.version) != (1, 1, 1)
                    || (epoch, writer, version) != (self.epoch, self.writer, self.version)
                    || read <= self.last_read
                {
                    return Err(Refusal::Counter);
                }
                self.last_read = read;
                self.counts.counters += 1;
                self.current(request)?.fresh_counter = true;
            }
            Event::Handles { request } => {
                self.current(request)?;
                self.counts.handles += 1;
            }
            Event::ArmSql { request } => {
                let spent = self
                    .active
                    .as_ref()
                    .is_some_and(|a| self.spent_originals.contains(&a.original.id));
                let active = self.current(request)?;
                if active.sql != Sql::Closed || spent || active.effect != Effect::NotAttempted {
                    return Err(Refusal::SqlOrder);
                }
                active.sql = Sql::Armed;
                active.committed_and_postchecked = false;
            }
            Event::OpenSql { request } => {
                let active = self.protected(request)?;
                if active.sql != Sql::Armed {
                    return Err(Refusal::SqlOrder);
                }
                active.sql = Sql::Open;
                self.counts.sql_opens += 1;
            }
            Event::CommitSql {
                request,
                final_original,
            } => {
                let active = self.protected(request)?;
                if active.sql != Sql::Open {
                    return Err(Refusal::SqlOrder);
                }
                active.sql = Sql::Committed;
                let id = active.original.id;
                if final_original {
                    self.spent_originals.insert(id);
                }
            }
            Event::RollbackSql { request } => {
                let active = self.protected(request)?;
                if active.sql != Sql::Open {
                    return Err(Refusal::SqlOrder);
                }
                active.sql = Sql::RolledBack;
            }
            Event::CloseSql { request } => {
                let active = self.current(request)?;
                active.sql = match active.sql {
                    Sql::Committed => Sql::ClosedCommitted,
                    Sql::RolledBack => Sql::ClosedRolledBack,
                    _ => return Err(Refusal::SqlOrder),
                };
            }
            Event::PostcheckSql { request } => {
                let active = self.protected(request)?;
                active.committed_and_postchecked = match active.sql {
                    Sql::ClosedCommitted => true,
                    Sql::ClosedRolledBack => false,
                    _ => return Err(Refusal::SqlOrder),
                };
                active.sql = Sql::Closed;
            }
            Event::Send { request, outcome } => {
                let active = self.protected(request)?;
                if active.sql != Sql::Closed
                    || !active.committed_and_postchecked
                    || active.effect != Effect::NotAttempted
                    || outcome == Effect::NotAttempted
                {
                    return Err(Refusal::SqlOrder);
                }
                active.effect = outcome;
                if outcome != Effect::Excluded {
                    self.counts.sends += 1;
                }
                if outcome == Effect::MayHaveBeenSent {
                    return Err(Refusal::Unknown);
                }
            }
            Event::Release { request } => {
                let active = self.protected(request)?;
                if active.sql != Sql::Closed || active.effect == Effect::MayHaveBeenSent {
                    return Err(Refusal::SqlOrder);
                }
                self.active = None;
            }
            Event::SqlFailure => return Err(Refusal::Unknown),
            Event::CounterFailure => return Err(Refusal::Counter),
            Event::Cancel | Event::Drop => return Err(Refusal::Abandoned),
            Event::FullWork { work } => {
                let index = match work {
                    FullWork::Executable => 0,
                    FullWork::PhysicalAttachment => 1,
                    FullWork::ProviderAuthentication => 2,
                    FullWork::IssuerEnrollment => 3,
                };
                // Meter even the forbidden attempt. This is an oracle for an
                // observed call, not a promise that an adapter never made it.
                self.counts.full_work[index] += 1;
                return Err(Refusal::RepeatedAdmission);
            }
            _ => unreachable!("environment observations handled separately"),
        }
        Ok(())
    }
}
