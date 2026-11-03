//! The lifecycle campaign shares the original DATA scheduler and its oracle.
//! It never converts a completed transcript into native authority.
use super::*;

/// A simulator/model failure is never an ordinary native refusal. In particular,
/// it must survive the storage phase's pessimistic continuation handling.
#[derive(Debug)]
pub(in crate::security_epoch) struct LifecycleModelError;

impl std::fmt::Display for LifecycleModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("lifecycle handshake model execution failed")
    }
}

impl std::error::Error for LifecycleModelError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum LifecycleProgress {
    Pending,
    ProtocolComplete,
    Refused,
}

pub(in crate::security_epoch) struct LifecycleHandshake {
    actual: World<Transcript>,
    oracle: World<model::Model>,
    schedule: Schedule,
    failed: std::cell::Cell<bool>,
}

/// Controlled input order only. This contains no machine decisions or native
/// authority, and can drive a separate reference world without production state.
struct Schedule {
    seed: u64,
    sequence: u64,
    events: usize,
    initial: Protocol,
    purpose: StagePurpose,
    started: bool,
    pending: VecDeque<Event>,
}

impl Schedule {
    fn new(seed: u64, initial: Protocol) -> Self {
        Self {
            seed,
            sequence: 0,
            events: 0,
            initial,
            purpose: if initial == Protocol::InitialStorage {
                StagePurpose::InitialFirstHolder
            } else {
                StagePurpose::CurrentRole
            },
            started: false,
            pending: VecDeque::new(),
        }
    }

    fn begin(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
        purpose: StagePurpose,
    ) -> Result<()> {
        ensure!(endpoint < 2 && self.pending.is_empty(), LifecycleModelError);
        ensure!(
            matches!(
                (self.started, self.initial, purpose),
                (false, _, StagePurpose::CurrentRole)
                    | (
                        true,
                        Protocol::InitialStorage,
                        StagePurpose::CurrentRole | StagePurpose::StorageBootstrap,
                    )
                    | (true, Protocol::InitialServing, StagePurpose::CurrentRole)
            ),
            LifecycleModelError
        );
        let mut events = Vec::new();
        let sequence = if !self.started {
            0
        } else {
            self.sequence.checked_add(1).ok_or(LifecycleModelError)?
        };
        let protocol = if !self.started {
            self.initial
        } else {
            for endpoint in 0..2 {
                events.push(Event::BeginCurrent {
                    endpoint,
                    sequence,
                    purpose,
                });
            }
            match self.initial {
                Protocol::InitialStorage => Protocol::CurrentStorage,
                Protocol::InitialServing => Protocol::CurrentServing,
                _ => return Err(LifecycleModelError.into()),
            }
        };
        let mut random = self.seed ^ sequence;
        let wire = exchange(protocol, sequence, &mut random);
        let cut = death_cut.map(|n| n % wire.len());
        for (index, event) in wire.into_iter().enumerate() {
            if cut == Some(index) {
                events.push(Event::Kill { endpoint });
            }
            events.push(event);
        }
        ensure!(events.len() <= MAX_EVENTS, LifecycleModelError);
        ensure!(
            self.events <= 96 * MAX_EVENTS - events.len(),
            LifecycleModelError
        );
        self.sequence = sequence;
        if self.started {
            self.purpose = purpose;
        }
        self.started = true;
        self.pending = events.into();
        Ok(())
    }

    fn advance(&mut self) -> Result<Event> {
        let event = self.pending.front().cloned().ok_or(LifecycleModelError)?;
        self.external_observation()?;
        let _ = self.pending.pop_front();
        Ok(event)
    }

    fn external_observation(&mut self) -> Result<()> {
        ensure!(self.events < 96 * MAX_EVENTS, LifecycleModelError);
        self.events += 1;
        Ok(())
    }

    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"seed":self.seed,"sequence":self.sequence,
            "events":self.events,"initial":self.initial,"purpose":self.purpose,"started":self.started,"pending":self.pending})
    }
}

impl LifecycleHandshake {
    pub(in crate::security_epoch) fn source() -> Digest {
        implementation()
    }

    pub(in crate::security_epoch) fn new(seed: u64) -> Result<Self> {
        Self::selected(seed, Protocol::InitialStorage)
    }

    pub(in crate::security_epoch) fn serving(seed: u64) -> Result<Self> {
        Self::selected(seed, Protocol::InitialServing)
    }

    pub(in crate::security_epoch) fn enrollment(seed: u64) -> Result<Self> {
        Self::selected(seed, Protocol::Enrollment)
    }

    fn selected(seed: u64, initial: Protocol) -> Result<Self> {
        let program = Program {
            version: 1,
            seed,
            protocol: initial,
            events: vec![],
        };
        Ok(Self {
            actual: World::new(&program)?,
            oracle: World::new(&program)?,
            schedule: Schedule::new(seed, initial),
            failed: std::cell::Cell::new(false),
        })
    }

    /// Complete exchanges and durable-boundary pauses use the same stepper.
    pub(in crate::security_epoch) fn exchange(&mut self, death_cut: Option<usize>) -> Result<bool> {
        self.exchange_peer(death_cut, 0)
    }

    pub(in crate::security_epoch) fn exchange_peer(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<bool> {
        self.begin_exchange(death_cut, endpoint)?;
        loop {
            if let Some(complete) = self.advance_exchange()? {
                return Ok(complete);
            }
        }
    }

    pub(in crate::security_epoch) fn begin_exchange(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<()> {
        ensure!(!self.failed.get(), LifecycleModelError);
        self.schedule
            .begin(death_cut, endpoint, StagePurpose::CurrentRole)
    }

    pub(in crate::security_epoch) fn begin_bootstrap_exchange(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<()> {
        ensure!(!self.failed.get(), LifecycleModelError);
        self.schedule
            .begin(death_cut, endpoint, StagePurpose::StorageBootstrap)
    }

    /// Advance one actual/oracle event. Only the final event returns the known
    /// result; an intermediate pause is never a completed exchange or authority.
    pub(in crate::security_epoch) fn advance_exchange(&mut self) -> Result<Option<bool>> {
        ensure!(!self.failed.get(), LifecycleModelError);
        let event = match self.schedule.advance() {
            Ok(event) => event,
            Err(error) => {
                if !self.schedule.pending.is_empty() {
                    self.failed.set(true);
                }
                return Err(error);
            }
        };
        let result = (|| {
            let actual = self
                .actual
                .step(&event)
                .map_err(|error| error.context(LifecycleModelError))?;
            let expected = self
                .oracle
                .step(&event)
                .map_err(|error| error.context(LifecycleModelError))?;
            ensure!(actual == expected, LifecycleModelError);
            if self.schedule.pending.is_empty() {
                Ok(Some(self.current()?))
            } else {
                Ok(None)
            }
        })();
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub(in crate::security_epoch) fn current(&self) -> Result<bool> {
        Ok(self.progress()? == LifecycleProgress::ProtocolComplete)
    }

    pub(in crate::security_epoch) fn app_observation_ready(&self) -> Result<bool> {
        ensure!(!self.failed.get(), LifecycleModelError);
        if self.progress()? == LifecycleProgress::Refused {
            return Ok(false);
        }
        let observed = self.actual.endpoints[0].machine.next();
        let expected = self.oracle.endpoints[0].machine.next();
        if observed != expected {
            self.failed.set(true);
            return Err(LifecycleModelError.into());
        }
        Ok(self.progress()? != LifecycleProgress::Refused
            && matches!(self.actual.endpoints[0].attempt, Attempt::Idle)
            && observed
                == Some((
                    Direction::Send,
                    Frame {
                        protocol: Protocol::InitialStorage,
                        step: super::super::Step::Confirm,
                        sequence: None,
                    },
                )))
    }

    pub(in crate::security_epoch) fn controller_accepted_checked(&self) -> Result<bool> {
        if self.progress()? == LifecycleProgress::Refused {
            return Ok(false);
        }
        let actual = self.actual.endpoints[1].machine.complete()
            && matches!(self.actual.endpoints[1].attempt, Attempt::Idle);
        let expected = self.oracle.endpoints[1].machine.complete()
            && matches!(self.oracle.endpoints[1].attempt, Attempt::Idle);
        if actual != expected {
            self.failed.set(true);
            return Err(LifecycleModelError.into());
        }
        Ok(self.schedule.initial == Protocol::InitialStorage
            && self.schedule.sequence == 0
            && actual)
    }

    fn controller_next_is(&self, step: super::super::Step) -> Result<bool> {
        if self.progress()? == LifecycleProgress::Refused {
            return Ok(false);
        }
        let actual = (
            self.actual.endpoints[1].machine.next(),
            matches!(self.actual.endpoints[1].attempt, Attempt::Idle),
        );
        let expected = (
            self.oracle.endpoints[1].machine.next(),
            matches!(self.oracle.endpoints[1].attempt, Attempt::Idle),
        );
        if actual != expected {
            self.failed.set(true);
            return Err(LifecycleModelError.into());
        }
        Ok(self.schedule.sequence > 0
            && actual
                == (
                    Some((
                        Direction::Send,
                        Frame {
                            protocol: Protocol::CurrentStorage,
                            step,
                            sequence: None,
                        },
                    )),
                    true,
                ))
    }

    pub(in crate::security_epoch) fn bootstrap_work_ready(&self) -> Result<bool> {
        Ok(self.schedule.purpose == StagePurpose::StorageBootstrap
            && self.controller_next_is(super::super::Step::Known)?)
    }

    pub(in crate::security_epoch) fn controller_consumed_checked(&self) -> Result<bool> {
        self.controller_next_is(super::super::Step::Released)
    }

    pub(in crate::security_epoch) fn lose_packet(&mut self, sender: usize) -> Result<bool> {
        ensure!(!self.failed.get() && sender < 2, LifecycleModelError);
        self.observation_budget()?;
        let event = Event::Lose { sender };
        match (self.actual.step(&event), self.oracle.step(&event)) {
            (Ok(actual), Ok(expected)) if actual == expected => {
                Ok(actual.outcome == Outcome::Accepted)
            }
            _ => {
                self.failed.set(true);
                Err(LifecycleModelError.into())
            }
        }
    }

    fn observation_budget(&mut self) -> Result<()> {
        let result = self.schedule.external_observation();
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub(in crate::security_epoch) fn check_file_boundary(
        &mut self,
        endpoint: usize,
    ) -> Result<bool> {
        ensure!(!self.failed.get() && endpoint < 2, LifecycleModelError);
        self.observation_budget()?;
        let actual = self.actual.check_original(endpoint);
        let expected = self.oracle.check_original(endpoint);
        if actual != expected || self.actual.snapshot() != self.oracle.snapshot() {
            self.failed.set(true);
            return Err(LifecycleModelError.into());
        }
        Ok(actual)
    }

    pub(in crate::security_epoch) fn advance_file_time(&mut self, nanos: u64) -> Result<()> {
        self.file_time(Event::Advance { nanos })
    }

    pub(in crate::security_epoch) fn rewind_file_time(&mut self, nanos: u64) -> Result<()> {
        self.file_time(Event::Rewind { nanos })
    }

    fn file_time(&mut self, event: Event) -> Result<()> {
        ensure!(!self.failed.get(), LifecycleModelError);
        self.observation_budget()?;
        let actual = self.actual.step(&event);
        let expected = self.oracle.step(&event);
        match (actual, expected) {
            (Ok(actual), Ok(expected)) if actual == expected => Ok(()),
            _ => {
                self.failed.set(true);
                Err(LifecycleModelError.into())
            }
        }
    }

    /// Already-observed DATA only. Compare endpoint identities before reducing
    /// them to one disposition; no fresh native check or clock is sampled.
    pub(in crate::security_epoch) fn progress(&self) -> Result<LifecycleProgress> {
        ensure!(!self.failed.get(), LifecycleModelError);
        let actual: [(bool, bool, bool); 2] = std::array::from_fn(|index| {
            let endpoint = &self.actual.endpoints[index];
            (
                endpoint.alive,
                endpoint.refused,
                endpoint.machine.complete(),
            )
        });
        let expected: [(bool, bool, bool); 2] = std::array::from_fn(|index| {
            let endpoint = &self.oracle.endpoints[index];
            (
                endpoint.alive,
                endpoint.refused,
                endpoint.machine.complete(),
            )
        });
        if actual != expected {
            self.failed.set(true);
            return Err(LifecycleModelError.into());
        }
        Ok(
            if actual.iter().any(|(alive, refused, _)| !alive || *refused) {
                LifecycleProgress::Refused
            } else if self.schedule.pending.is_empty()
                && actual.iter().all(|(_, _, complete)| *complete)
            {
                LifecycleProgress::ProtocolComplete
            } else {
                LifecycleProgress::Pending
            },
        )
    }

    /// Negative-control input: alter only the reference endpoint, never the
    /// production reducer. This must fail even if peer death also refuses work.
    pub(in crate::security_epoch) fn corrupt_reference_for_control(&mut self) {
        self.oracle.endpoints[1].refused = true;
    }

    pub(in crate::security_epoch) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "actual":self.actual.snapshot(),"oracle":self.oracle.snapshot(),
            "schedule":self.schedule.snapshot(),"failed":self.failed.get(),
        })
    }
}

/// Reference-only lifecycle predictions for the outer durable-state oracle.
/// Sharing controlled input order does not share production machine decisions.
pub(in crate::security_epoch) struct LifecycleReference {
    world: World<model::Model>,
    schedule: Schedule,
    failed: std::cell::Cell<bool>,
}

impl LifecycleReference {
    pub(in crate::security_epoch) fn new(seed: u64) -> Result<Self> {
        Self::selected(seed, Protocol::InitialStorage)
    }

    pub(in crate::security_epoch) fn serving(seed: u64) -> Result<Self> {
        Self::selected(seed, Protocol::InitialServing)
    }

    fn selected(seed: u64, protocol: Protocol) -> Result<Self> {
        let program = Program {
            version: 1,
            seed,
            protocol,
            events: vec![],
        };
        Ok(Self {
            world: World::new(&program)?,
            schedule: Schedule::new(seed, protocol),
            failed: std::cell::Cell::new(false),
        })
    }

    pub(in crate::security_epoch) fn begin_exchange(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<()> {
        ensure!(!self.failed.get(), LifecycleModelError);
        self.schedule
            .begin(death_cut, endpoint, StagePurpose::CurrentRole)
    }

    pub(in crate::security_epoch) fn begin_bootstrap_exchange(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<()> {
        ensure!(!self.failed.get(), LifecycleModelError);
        self.schedule
            .begin(death_cut, endpoint, StagePurpose::StorageBootstrap)
    }

    pub(in crate::security_epoch) fn advance_exchange(&mut self) -> Result<Option<bool>> {
        ensure!(!self.failed.get(), LifecycleModelError);
        let event = match self.schedule.advance() {
            Ok(event) => event,
            Err(error) => {
                if !self.schedule.pending.is_empty() {
                    self.failed.set(true);
                }
                return Err(error);
            }
        };
        let result = (|| {
            self.world
                .step(&event)
                .map_err(|error| error.context(LifecycleModelError))?;
            if self.schedule.pending.is_empty() {
                Ok(Some(self.current()?))
            } else {
                Ok(None)
            }
        })();
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub(in crate::security_epoch) fn current(&self) -> Result<bool> {
        Ok(self.progress()? == LifecycleProgress::ProtocolComplete)
    }

    pub(in crate::security_epoch) fn app_observation_ready(&self) -> Result<bool> {
        Ok(self.progress()? != LifecycleProgress::Refused
            && matches!(self.world.endpoints[0].attempt, Attempt::Idle)
            && matches!(
                self.world.endpoints[0].machine.next(),
                Some((
                    Direction::Send,
                    Frame {
                        protocol: Protocol::InitialStorage,
                        step: super::super::Step::Confirm,
                        sequence: None,
                    }
                ))
            ))
    }

    pub(in crate::security_epoch) fn controller_accepted_checked(&self) -> Result<bool> {
        Ok(self.progress()? != LifecycleProgress::Refused
            && self.schedule.initial == Protocol::InitialStorage
            && self.schedule.sequence == 0
            && self.world.endpoints[1].machine.complete()
            && matches!(self.world.endpoints[1].attempt, Attempt::Idle))
    }

    fn controller_next_is(&self, step: super::super::Step) -> Result<bool> {
        Ok(self.progress()? != LifecycleProgress::Refused
            && self.schedule.sequence > 0
            && matches!(self.world.endpoints[1].attempt, Attempt::Idle)
            && self.world.endpoints[1].machine.next()
                == Some((
                    Direction::Send,
                    Frame {
                        protocol: Protocol::CurrentStorage,
                        step,
                        sequence: None,
                    },
                )))
    }

    pub(in crate::security_epoch) fn bootstrap_work_ready(&self) -> Result<bool> {
        Ok(self.schedule.purpose == StagePurpose::StorageBootstrap
            && self.controller_next_is(super::super::Step::Known)?)
    }

    pub(in crate::security_epoch) fn controller_consumed_checked(&self) -> Result<bool> {
        self.controller_next_is(super::super::Step::Released)
    }

    pub(in crate::security_epoch) fn lose_packet(&mut self, sender: usize) -> Result<bool> {
        ensure!(!self.failed.get() && sender < 2, LifecycleModelError);
        self.observation_budget()?;
        match self.world.step(&Event::Lose { sender }) {
            Ok(record) => Ok(record.outcome == Outcome::Accepted),
            Err(_) => {
                self.failed.set(true);
                Err(LifecycleModelError.into())
            }
        }
    }

    fn observation_budget(&mut self) -> Result<()> {
        let result = self.schedule.external_observation();
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub(in crate::security_epoch) fn check_file_boundary(
        &mut self,
        endpoint: usize,
    ) -> Result<bool> {
        ensure!(!self.failed.get() && endpoint < 2, LifecycleModelError);
        self.observation_budget()?;
        Ok(self.world.check_original(endpoint))
    }

    pub(in crate::security_epoch) fn advance_file_time(&mut self, nanos: u64) -> Result<()> {
        self.file_time(Event::Advance { nanos })
    }

    pub(in crate::security_epoch) fn rewind_file_time(&mut self, nanos: u64) -> Result<()> {
        self.file_time(Event::Rewind { nanos })
    }

    fn file_time(&mut self, event: Event) -> Result<()> {
        ensure!(!self.failed.get(), LifecycleModelError);
        self.observation_budget()?;
        if self.world.step(&event).is_err() {
            self.failed.set(true);
            return Err(LifecycleModelError.into());
        }
        Ok(())
    }

    pub(in crate::security_epoch) fn progress(&self) -> Result<LifecycleProgress> {
        ensure!(!self.failed.get(), LifecycleModelError);
        let endpoints: [(bool, bool, bool); 2] = std::array::from_fn(|index| {
            let endpoint = &self.world.endpoints[index];
            (
                endpoint.alive,
                endpoint.refused,
                endpoint.machine.complete(),
            )
        });
        Ok(
            if endpoints
                .iter()
                .any(|(alive, refused, _)| !alive || *refused)
            {
                LifecycleProgress::Refused
            } else if self.schedule.pending.is_empty()
                && endpoints.iter().all(|(_, _, complete)| *complete)
            {
                LifecycleProgress::ProtocolComplete
            } else {
                LifecycleProgress::Pending
            },
        )
    }

    pub(in crate::security_epoch) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"world":self.world.snapshot(),"schedule":self.schedule.snapshot(),"failed":self.failed.get()})
    }
}

#[test]
fn exhausted_file_observation_budget_quarantines_both_worlds_without_mutation() -> Result<()> {
    let mut actual = LifecycleHandshake::new(17)?;
    let mut reference = LifecycleReference::new(17)?;
    actual.begin_exchange(None, 0)?;
    reference.begin_exchange(None, 0)?;
    let pending = actual.schedule.pending.clone();
    actual.schedule.events = 96 * MAX_EVENTS;
    reference.schedule.events = 96 * MAX_EVENTS;
    let before = actual.actual.snapshot();
    let expected_before = reference.world.snapshot();
    assert!(
        actual
            .check_file_boundary(0)
            .unwrap_err()
            .is::<LifecycleModelError>()
    );
    assert!(
        reference
            .check_file_boundary(0)
            .unwrap_err()
            .is::<LifecycleModelError>()
    );
    assert!(actual.failed.get() && reference.failed.get());
    assert_eq!(actual.schedule.pending, pending);
    assert_eq!(reference.schedule.pending, pending);
    assert_eq!(actual.actual.snapshot(), before);
    assert_eq!(reference.world.snapshot(), expected_before);
    assert_eq!(actual.schedule.events, 96 * MAX_EVENTS);
    assert_eq!(reference.schedule.events, 96 * MAX_EVENTS);
    Ok(())
}

#[test]
fn queued_exchange_exhaustion_charges_file_work_before_popping_any_more_events() -> Result<()> {
    let mut actual = LifecycleHandshake::new(17)?;
    let mut reference = LifecycleReference::new(17)?;
    actual.begin_exchange(None, 0)?;
    reference.begin_exchange(None, 0)?;
    while !actual.app_observation_ready()? {
        assert_eq!(actual.advance_exchange()?, reference.advance_exchange()?);
    }
    assert!(reference.app_observation_ready()?);
    let pending = actual.schedule.pending.len();
    assert!(pending > 3);
    let cap = 96 * MAX_EVENTS;
    actual.schedule.events = cap - pending;
    reference.schedule.events = cap - pending;
    assert!(actual.check_file_boundary(0)? && reference.check_file_boundary(0)?);
    actual.advance_file_time(1)?;
    reference.advance_file_time(1)?;
    assert!(actual.check_file_boundary(0)? && reference.check_file_boundary(0)?);
    while actual.schedule.events < cap {
        assert_eq!(actual.advance_exchange()?, reference.advance_exchange()?);
    }
    assert_eq!(actual.schedule.pending.len(), 3);
    let queued = actual.schedule.pending.clone();
    assert!(
        actual
            .advance_exchange()
            .unwrap_err()
            .is::<LifecycleModelError>()
    );
    assert!(
        reference
            .advance_exchange()
            .unwrap_err()
            .is::<LifecycleModelError>()
    );
    assert_eq!(actual.schedule.events, cap);
    assert_eq!(reference.schedule.events, cap);
    assert_eq!(actual.schedule.pending, queued);
    assert_eq!(reference.schedule.pending, queued);
    assert!(actual.failed.get() && reference.failed.get());
    assert!(actual.current().is_err() && reference.current().is_err());
    assert!(actual.begin_exchange(None, 0).is_err() && reference.begin_exchange(None, 0).is_err());
    Ok(())
}

#[test]
fn checked_accepted_is_endpoint_history_not_a_global_empty_queue() -> Result<()> {
    let mut actual = LifecycleHandshake::new(17)?;
    let mut reference = LifecycleReference::new(17)?;
    actual.begin_exchange(None, 0)?;
    reference.begin_exchange(None, 0)?;
    while actual.schedule.pending.len() > 1 {
        assert!(!actual.controller_accepted_checked()?);
        assert!(!reference.controller_accepted_checked()?);
        assert_eq!(actual.advance_exchange()?, reference.advance_exchange()?);
    }
    assert!(matches!(
        actual.schedule.pending.front(),
        Some(Event::Postcheck { endpoint: 1 })
    ));
    actual
        .schedule
        .pending
        .push_back(Event::Advance { nanos: 0 });
    reference
        .schedule
        .pending
        .push_back(Event::Advance { nanos: 0 });
    assert_eq!(actual.advance_exchange()?, None);
    assert_eq!(reference.advance_exchange()?, None);
    assert_eq!(actual.progress()?, LifecycleProgress::Pending);
    assert_eq!(reference.progress()?, LifecycleProgress::Pending);
    assert!(actual.controller_accepted_checked()?);
    assert!(reference.controller_accepted_checked()?);
    assert!(!actual.schedule.pending.is_empty());
    assert_eq!(
        actual.check_file_boundary(1)?,
        reference.check_file_boundary(1)?
    );
    assert_eq!(actual.snapshot()["actual"], reference.snapshot()["world"]);
    Ok(())
}

#[test]
fn bootstrap_schedule_is_explicit_and_cannot_replace_initial_or_serving_purpose() -> Result<()> {
    let mut actual = LifecycleHandshake::new(17)?;
    let mut reference = LifecycleReference::new(17)?;
    let before = actual.snapshot();
    assert!(actual.begin_bootstrap_exchange(None, 0).is_err());
    assert!(reference.begin_bootstrap_exchange(None, 0).is_err());
    assert_eq!(actual.snapshot(), before);
    actual.begin_exchange(None, 0)?;
    reference.begin_exchange(None, 0)?;
    loop {
        let result = actual.advance_exchange()?;
        assert_eq!(result, reference.advance_exchange()?);
        if result.is_some() {
            break;
        }
    }
    actual.begin_bootstrap_exchange(None, 0)?;
    reference.begin_bootstrap_exchange(None, 0)?;
    assert_eq!(actual.advance_exchange()?, reference.advance_exchange()?);
    assert_eq!(actual.advance_exchange()?, reference.advance_exchange()?);
    for endpoint in actual.snapshot()["actual"]["endpoints"].as_array().unwrap() {
        assert_eq!(endpoint["machine"]["purpose"], "storage_bootstrap");
        let origin: Duration = serde_json::from_value(endpoint["clock"]["origin"].clone())?;
        let deadline: Duration = serde_json::from_value(endpoint["clock"]["deadline"].clone())?;
        assert_eq!(deadline - origin, Duration::from_secs(60));
    }
    let mut serving = LifecycleHandshake::serving(17)?;
    assert!(serving.exchange(None)?);
    let before = serving.snapshot();
    assert!(serving.begin_bootstrap_exchange(None, 0).is_err());
    assert_eq!(serving.snapshot(), before);
    Ok(())
}

#[test]
fn lifecycle_stepper_preserves_complete_exchanges_and_every_pause() -> Result<()> {
    for seed in 0..32 {
        for protocol in [
            Protocol::Enrollment,
            Protocol::InitialStorage,
            Protocol::InitialServing,
        ] {
            let mut complete = LifecycleHandshake::selected(seed, protocol)?;
            let mut stepped = LifecycleHandshake::selected(seed, protocol)?;
            let mut replay = LifecycleHandshake::selected(seed, protocol)?;
            let rounds = if protocol == Protocol::Enrollment {
                1
            } else {
                3
            };
            for _ in 0..rounds {
                assert!(complete.exchange(None)?);
                stepped.begin_exchange(None, 0)?;
                replay.begin_exchange(None, 0)?;
                assert!(!stepped.current()?);
                assert_eq!(stepped.snapshot(), replay.snapshot());
                let count = stepped.schedule.pending.len();
                assert!(count > 1 && count <= MAX_EVENTS);
                for index in 0..count {
                    let result = stepped.advance_exchange()?;
                    assert_eq!(result, replay.advance_exchange()?);
                    assert_eq!(stepped.snapshot(), replay.snapshot());
                    assert_eq!(result, (index + 1 == count).then_some(true));
                    assert_eq!(stepped.current()?, index + 1 == count);
                }
                assert_eq!(stepped.snapshot(), complete.snapshot());
            }
        }
    }
    Ok(())
}

#[test]
fn lifecycle_stepper_preserves_death_and_permanent_refusal_at_every_cut() -> Result<()> {
    for seed in 0..2 {
        for protocol in [Protocol::InitialStorage, Protocol::InitialServing] {
            for current in [false, true] {
                let mut successful = LifecycleHandshake::selected(seed, protocol)?;
                if current {
                    assert!(successful.exchange(None)?);
                }
                successful.begin_exchange(None, 0)?;
                let count = successful.schedule.pending.len();
                for cut in 0..count {
                    for endpoint in 0..2 {
                        let mut complete = LifecycleHandshake::selected(seed, protocol)?;
                        let mut stepped = LifecycleHandshake::selected(seed, protocol)?;
                        if current {
                            assert!(complete.exchange(None)?);
                            assert!(stepped.exchange(None)?);
                        }
                        assert!(!complete.exchange_peer(Some(cut), endpoint)?);
                        stepped.begin_exchange(Some(cut), endpoint)?;
                        loop {
                            if let Some(result) = stepped.advance_exchange()? {
                                assert!(!result);
                                break;
                            }
                            assert!(!stepped.current()?);
                        }
                        assert_eq!(stepped.snapshot(), complete.snapshot());
                        assert!(!stepped.exchange(None)?);
                        assert!(!complete.exchange(None)?);
                        assert_eq!(stepped.snapshot(), complete.snapshot());
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn lifecycle_stepper_rejects_overlap_exhaustion_bounds_and_oracle_divergence() -> Result<()> {
    let mut world = LifecycleHandshake::new(17)?;
    let before = world.snapshot();
    assert!(world.advance_exchange().is_err());
    assert!(world.begin_exchange(None, 2).is_err());
    assert_eq!(world.snapshot(), before);
    world.begin_exchange(None, 0)?;
    let queued = world.snapshot();
    assert!(!queued["schedule"]["pending"].as_array().unwrap().is_empty());
    assert!(world.begin_exchange(None, 0).is_err());
    assert_eq!(world.snapshot(), queued);
    world.advance_exchange()?;
    let paused = world.snapshot();
    assert_ne!(paused["schedule"]["pending"], queued["schedule"]["pending"]);
    assert!(world.exchange(None).is_err());
    assert_eq!(world.snapshot(), paused);
    world.corrupt_reference_for_control();
    let error = world.advance_exchange().unwrap_err();
    assert!(error.is::<LifecycleModelError>());
    let failed = world.snapshot();
    assert_eq!(failed["failed"], true);
    assert!(world.current().is_err());
    assert!(world.advance_exchange().is_err());
    assert!(world.begin_exchange(None, 0).is_err());
    assert_eq!(world.snapshot(), failed);

    let mut completed = LifecycleHandshake::new(17)?;
    assert!(completed.exchange(None)?);
    completed.corrupt_reference_for_control();
    assert!(completed.current().unwrap_err().is::<LifecycleModelError>());
    let failed = completed.snapshot();
    assert_eq!(failed["failed"], true);
    assert!(completed.begin_exchange(None, 0).is_err());
    assert!(completed.advance_exchange().is_err());
    assert!(completed.current().is_err());
    assert_eq!(completed.snapshot(), failed);

    let mut bounded = LifecycleHandshake::new(17)?;
    bounded.schedule.events = 96 * MAX_EVENTS;
    let before = bounded.snapshot();
    assert!(bounded.begin_exchange(None, 0).is_err());
    assert_eq!(bounded.snapshot(), before);

    let mut enrollment = LifecycleHandshake::enrollment(17)?;
    assert!(enrollment.exchange(None)?);
    let before = enrollment.snapshot();
    assert!(enrollment.begin_exchange(None, 0).is_err());
    assert_eq!(enrollment.snapshot(), before);
    Ok(())
}

#[test]
fn lifecycle_reference_predicts_each_pause_without_production_state() -> Result<()> {
    for seed in 0..8 {
        let mut actual = LifecycleHandshake::new(seed)?;
        let mut reference = LifecycleReference::new(seed)?;
        // A compile-time pin: the outer oracle owns only the independent model.
        let _: &World<model::Model> = &reference.world;
        for _ in 0..3 {
            actual.begin_exchange(None, 0)?;
            reference.begin_exchange(None, 0)?;
            assert!(!reference.current()?);
            loop {
                let outcome = actual.advance_exchange()?;
                assert_eq!(reference.advance_exchange()?, outcome);
                assert_eq!(reference.current()?, actual.current()?);
                let expected = reference.snapshot();
                let observed = actual.snapshot();
                assert_eq!(expected["world"], observed["oracle"]);
                assert_eq!(expected["schedule"], observed["schedule"]);
                if outcome.is_some() {
                    break;
                }
            }
        }
        reference.world.endpoints[1].refused = true;
        assert!(!reference.current()?);
        assert!(actual.current()?);
    }
    Ok(())
}

#[test]
fn lifecycle_reference_and_actual_require_the_final_postcheck_not_an_empty_queue() -> Result<()> {
    let mut actual = LifecycleHandshake::new(17)?;
    let mut reference = LifecycleReference::new(17)?;
    actual.begin_exchange(None, 0)?;
    reference.begin_exchange(None, 0)?;
    assert!(matches!(
        actual.schedule.pending.pop_back(),
        Some(Event::Postcheck { .. })
    ));
    assert!(matches!(
        reference.schedule.pending.pop_back(),
        Some(Event::Postcheck { .. })
    ));
    loop {
        let result = actual.advance_exchange()?;
        assert_eq!(reference.advance_exchange()?, result);
        if let Some(complete) = result {
            assert!(!complete);
            break;
        }
    }
    assert!(!actual.current()?);
    assert!(!reference.current()?);
    assert!(actual.schedule.pending.is_empty());
    assert!(reference.schedule.pending.is_empty());
    Ok(())
}

#[test]
fn lifecycle_progress_keeps_endpoint_identity_and_observed_death_before_completion() -> Result<()> {
    let mut world = LifecycleHandshake::new(17)?;
    world.begin_exchange(Some(0), 0)?;
    assert_eq!(world.advance_exchange()?, None); // the controlled death itself
    assert!(!world.actual.endpoints[0].refused);
    assert_eq!(world.progress()?, LifecycleProgress::Refused);
    assert!(!world.current()?);

    let mut wrong = LifecycleHandshake::new(17)?;
    wrong.actual.endpoints[0].refused = true;
    wrong.oracle.endpoints[1].refused = true;
    assert!(wrong.progress().unwrap_err().is::<LifecycleModelError>());
    let failed = wrong.snapshot();
    assert!(wrong.current().is_err());
    assert!(wrong.begin_exchange(None, 0).is_err());
    assert!(wrong.advance_exchange().is_err());
    assert_eq!(wrong.snapshot(), failed);
    Ok(())
}

#[test]
fn lifecycle_reference_preserves_typed_refusal_at_every_observed_prefix() -> Result<()> {
    let mut refused_prefixes = 0;
    for seed in 0..4 {
        let mut probe = LifecycleHandshake::new(seed)?;
        probe.begin_exchange(None, 0)?;
        let count = probe.schedule.pending.len();
        for cut in [0, count / 2, count - 1] {
            for endpoint in 0..2 {
                let mut actual = LifecycleHandshake::new(seed)?;
                let mut reference = LifecycleReference::new(seed)?;
                actual.begin_exchange(Some(cut), endpoint)?;
                reference.begin_exchange(Some(cut), endpoint)?;
                assert_eq!(reference.progress()?, LifecycleProgress::Pending);
                loop {
                    let result = actual.advance_exchange()?;
                    assert_eq!(reference.advance_exchange()?, result);
                    let progress = actual.progress()?;
                    assert_eq!(reference.progress()?, progress);
                    if progress == LifecycleProgress::Refused {
                        // A false current() alone cannot distinguish Pending.
                        assert_eq!(reference.progress()?, LifecycleProgress::Refused);
                        refused_prefixes += 1;
                    }
                    if let Some(complete) = result {
                        assert!(!complete);
                        assert_eq!(reference.progress()?, LifecycleProgress::Refused);
                        break;
                    }
                }
            }
        }
    }
    assert!(refused_prefixes > 0);
    Ok(())
}
