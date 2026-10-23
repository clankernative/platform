//! The lifecycle campaign shares the original DATA scheduler and its oracle.
//! It never converts a completed transcript into native authority.
use super::*;

pub(in crate::security_epoch) struct LifecycleHandshake {
    actual: World<Transcript>,
    oracle: World<model::Model>,
    seed: u64,
    sequence: u64,
    events: usize,
}

impl LifecycleHandshake {
    pub(in crate::security_epoch) fn new(seed: u64) -> Result<Self> {
        let program = Program {
            version: 1,
            seed,
            protocol: Protocol::InitialStorage,
            events: vec![],
        };
        Ok(Self {
            actual: World::new(&program)?,
            oracle: World::new(&program)?,
            seed,
            sequence: 0,
            events: 0,
        })
    }

    /// Drive the complete initial/current conversation, cutting a selected
    /// actual syscall return before its postcheck when requested. Peer death
    /// remains latched in both endpoint worlds for subsequent operations.
    pub(in crate::security_epoch) fn exchange(&mut self, death_cut: Option<usize>) -> Result<bool> {
        let mut events = Vec::new();
        let protocol = if self.events == 0 {
            Protocol::InitialStorage
        } else {
            self.sequence += 1;
            for endpoint in 0..2 {
                events.push(Event::BeginCurrent {
                    endpoint,
                    sequence: self.sequence,
                });
            }
            Protocol::CurrentStorage
        };
        let mut random = self.seed ^ self.sequence;
        let wire = exchange(protocol, self.sequence, &mut random);
        let cut = death_cut.map(|n| n % wire.len());
        for (index, event) in wire.into_iter().enumerate() {
            if cut == Some(index) {
                events.push(Event::Kill { endpoint: 0 });
            }
            events.push(event);
        }
        for event in events {
            self.events += 1;
            ensure!(self.events <= 96 * 512, "lifecycle handshake event bound");
            let actual = self.actual.step(&event)?;
            let expected = self.oracle.step(&event)?;
            ensure!(actual == expected, "lifecycle handshake model divergence");
        }
        Ok(self
            .actual
            .endpoints
            .iter()
            .all(|e| !e.refused && e.alive && e.machine.complete()))
    }

    pub(in crate::security_epoch) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"actual":self.actual.snapshot(),"oracle":self.oracle.snapshot()})
    }
}
