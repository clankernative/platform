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
        ensure!(endpoint < 2, LifecycleModelError);
        let mut events = Vec::new();
        let protocol = if self.events == 0 {
            self.initial
        } else {
            self.sequence += 1;
            for endpoint in 0..2 {
                events.push(Event::BeginCurrent {
                    endpoint,
                    sequence: self.sequence,
                    purpose: if self.initial == Protocol::InitialStorage {
                        StagePurpose::AppServing
                    } else {
                        StagePurpose::CurrentRole
                    },
                });
            }
            match self.initial {
                Protocol::InitialStorage => Protocol::CurrentStorage,
                Protocol::InitialServing => Protocol::CurrentServing,
                _ => unreachable!("lifecycle starts at initial protocol"),
            }
        };
        let mut random = self.seed ^ self.sequence;
        let wire = exchange(protocol, self.sequence, &mut random);
        let cut = death_cut.map(|n| n % wire.len());
        for (index, event) in wire.into_iter().enumerate() {
            if cut == Some(index) {
                events.push(Event::Kill { endpoint });
            }
            events.push(event);
        }
        for event in events {
            self.events += 1;
            ensure!(self.events <= 96 * 512, LifecycleModelError);
            let actual = self
                .actual
                .step(&event)
                .map_err(|error| error.context(LifecycleModelError))?;
            let expected = self
                .oracle
                .step(&event)
                .map_err(|error| error.context(LifecycleModelError))?;
            ensure!(actual == expected, LifecycleModelError);
        }
        self.current()
    }

    pub(in crate::security_epoch) fn current(&self) -> Result<bool> {
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
        Ok(actual)
    }

    /// Negative-control input: alter only the reference endpoint, never the
    /// production reducer. This must fail even if peer death also refuses work.
    pub(in crate::security_epoch) fn corrupt_reference_for_control(&mut self) {
        self.oracle.endpoints[1].refused = true;
    }

    pub(in crate::security_epoch) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"actual":self.actual.snapshot(),"oracle":self.oracle.snapshot()})
    }
}
