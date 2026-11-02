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

pub(in crate::security_epoch) struct LifecycleHandshake {
    actual: World<Transcript>,
    oracle: World<model::Model>,
    seed: u64,
    sequence: u64,
    events: usize,
    initial: Protocol,
    pending: VecDeque<Event>,
    failed: bool,
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
            seed,
            sequence: 0,
            events: 0,
            initial,
            pending: VecDeque::new(),
            failed: false,
        })
    }

    /// Drive the complete initial/current conversation, cutting a selected
    /// actual syscall return before its postcheck when requested. Peer death
    /// remains latched in both endpoint worlds for subsequent operations.
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

    /// Queue the same bounded DATA schedule without executing it. The outer
    /// lifecycle can interleave durable observations between individual events.
    /// An unfinished conversation cannot be replaced by another start.
    pub(in crate::security_epoch) fn begin_exchange(
        &mut self,
        death_cut: Option<usize>,
        endpoint: usize,
    ) -> Result<()> {
        ensure!(!self.failed && endpoint < 2 && self.pending.is_empty(), LifecycleModelError);
        let mut events = Vec::new();
        let sequence = if self.events == 0 {
            0
        } else {
            self.sequence.checked_add(1).ok_or(LifecycleModelError)?
        };
        let protocol = if self.events == 0 {
            self.initial
        } else {
            for endpoint in 0..2 {
                events.push(Event::BeginCurrent {
                    endpoint,
                    sequence,
                    purpose: StagePurpose::CurrentRole,
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
        ensure!(self.events <= 96 * MAX_EVENTS - events.len(), LifecycleModelError);
        self.sequence = sequence;
        self.pending = events.into();
        Ok(())
    }

    /// Advance one actual/oracle event. Only the final event returns the known
    /// result; an intermediate pause is never a completed exchange or authority.
    pub(in crate::security_epoch) fn advance_exchange(&mut self) -> Result<Option<bool>> {
        ensure!(!self.failed, LifecycleModelError);
        let event = self.pending.pop_front().ok_or(LifecycleModelError)?;
        self.events += 1;
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
            if self.pending.is_empty() {
                Ok(Some(self.current()?))
            } else {
                Ok(None)
            }
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(in crate::security_epoch) fn current(&self) -> Result<bool> {
        ensure!(!self.failed, LifecycleModelError);
        let actual = self
            .actual
            .endpoints
            .iter()
            .all(|e| !e.refused && e.alive && e.machine.complete());
        let expected = self
            .oracle
            .endpoints
            .iter()
            .all(|e| !e.refused && e.alive && e.machine.complete());
        ensure!(actual == expected, LifecycleModelError);
        Ok(self.pending.is_empty() && actual)
    }

    /// Negative-control input: alter only the reference endpoint, never the
    /// production reducer. This must fail even if peer death also refuses work.
    pub(in crate::security_epoch) fn corrupt_reference_for_control(&mut self) {
        self.oracle.endpoints[1].refused = true;
    }

    pub(in crate::security_epoch) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "actual":self.actual.snapshot(),"oracle":self.oracle.snapshot(),
            "seed":self.seed,"sequence":self.sequence,"events":self.events,
            "initial":self.initial,"pending":self.pending,"failed":self.failed,
        })
    }
}

#[test]
fn lifecycle_stepper_preserves_complete_exchanges_and_every_pause() -> Result<()> {
    for seed in 0..32 {
        for protocol in [Protocol::Enrollment, Protocol::InitialStorage, Protocol::InitialServing] {
            let mut complete = LifecycleHandshake::selected(seed, protocol)?;
            let mut stepped = LifecycleHandshake::selected(seed, protocol)?;
            let mut replay = LifecycleHandshake::selected(seed, protocol)?;
            let rounds = if protocol == Protocol::Enrollment { 1 } else { 3 };
            for _ in 0..rounds {
                assert!(complete.exchange(None)?);
                stepped.begin_exchange(None, 0)?;
                replay.begin_exchange(None, 0)?;
                assert!(!stepped.current()?);
                assert_eq!(stepped.snapshot(), replay.snapshot());
                let count = stepped.pending.len();
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
            let count = successful.pending.len();
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
    assert!(!queued["pending"].as_array().unwrap().is_empty());
    assert!(world.begin_exchange(None, 0).is_err());
    assert_eq!(world.snapshot(), queued);
    world.advance_exchange()?;
    let paused = world.snapshot();
    assert_ne!(paused["pending"], queued["pending"]);
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

    let mut bounded = LifecycleHandshake::new(17)?;
    bounded.events = 96 * MAX_EVENTS;
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
