//! One process-local original Google ceremony. Rows and publication digests are
//! DATA; this cache cannot be restored from them and creates no runtime role,
//! continuous-clock authority or fresh-human proof.

use super::{
    effects,
    fresh_auth::FreshIntent,
    shell_oidc::{GoogleBundle, GoogleFresh},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use std::{collections::BTreeMap, sync::Mutex};

const MAX_BEGINS: usize = 1024;

/// Immutable local observations only. The actual native original-lifetime
/// producer is separate and remains required for production acceptance.
#[derive(Clone)]
pub(super) struct Original {
    pub(super) intent: FreshIntent,
    pub(super) owner: Digest,
    pub(super) started_at: i64,
    pub(super) started: effects::Instant,
}

pub(super) enum Payload {
    Claim,
    Publication(Box<GoogleBundle>),
    Baseline(Box<GoogleBundle>),
    Manual(Box<GoogleFresh>),
    Fresh(Box<GoogleFresh>),
    BaselineCallback(Box<GoogleBundle>),
    FreshCallback(Box<GoogleFresh>),
}

enum Stage {
    Idle(Payload),
    Busy,
    Terminal,
}

struct Entry {
    original: Original,
    stage: Stage,
}

pub(super) struct Begins {
    entries: Mutex<BTreeMap<Digest, Entry>>,
}

impl Begins {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn reserve(&self, intent: &FreshIntent, now: i64) -> Result<Flight<'_>> {
        ensure!(
            now >= intent.created_at() && now < intent.deadline(),
            "original Google Begin expired"
        );
        let key = intent.commitment()?;
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Google Begin ownership unavailable"))?;
        let count = entries.len();
        if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(key.clone()) {
            ensure!(count < MAX_BEGINS, "Google Begin ownership capacity");
            // Capture before allocation naming entropy and before the Claim
            // RPC. Neither a lost reply nor reopening renews these observations.
            let started = effects::Instant::now();
            let owner = Digest::new(effects::random()?.as_bytes());
            slot.insert(Entry {
                original: Original {
                    intent: intent.clone(),
                    owner,
                    started_at: now,
                    started,
                },
                stage: Stage::Idle(Payload::Claim),
            });
        }
        let entry = entries
            .get_mut(&key)
            .context("Google Begin owner missing")?;
        ensure!(
            entry.original.intent == *intent,
            "Google Begin original context changed"
        );
        let stage = std::mem::replace(&mut entry.stage, Stage::Terminal);
        let payload = match stage {
            Stage::Idle(payload) => payload,
            Stage::Busy => {
                entry.stage = Stage::Busy;
                anyhow::bail!("Google Begin already in flight");
            }
            Stage::Terminal => anyhow::bail!("Google Begin already consumed or refused"),
        };
        entry.stage = Stage::Busy;
        Ok(Flight {
            begins: self,
            key,
            original: entry.original.clone(),
            payload: Some(payload),
            armed: true,
        })
    }

    /// State is an opaque callback index only. It never selects an app, current
    /// identity or profile. The original target remains the captured intent app.
    pub(super) fn callback(&self, state: &str) -> Result<Flight<'_>> {
        let state = Digest::new(state.as_bytes());
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Google Begin ownership unavailable"))?;
        let mut found = None;
        for (key, entry) in entries.iter() {
            let matches = match &entry.stage {
                Stage::Idle(Payload::Baseline(bundle)) => bundle.baseline_state() == &state,
                Stage::Idle(Payload::Fresh(fresh)) => fresh.state() == &state,
                _ => false,
            };
            if matches {
                ensure!(found.is_none(), "Google callback state collision");
                found = Some(key.clone());
            }
        }
        let key = found.context("Google callback expired, replayed or in flight")?;
        let entry = entries
            .get_mut(&key)
            .context("Google callback owner lost")?;
        let payload = match std::mem::replace(&mut entry.stage, Stage::Busy) {
            Stage::Idle(Payload::Baseline(bundle)) => Payload::BaselineCallback(bundle),
            Stage::Idle(Payload::Fresh(fresh)) => Payload::FreshCallback(fresh),
            _ => {
                entry.stage = Stage::Terminal;
                anyhow::bail!("Google callback phase changed");
            }
        };
        // Drop of either callback flight is TERMINAL, including an ambiguous
        // exchange or panic. No code, baseline, tuple or lifetime is retried.
        Ok(Flight {
            begins: self,
            key,
            original: entry.original.clone(),
            payload: Some(payload),
            armed: true,
        })
    }

    /// An opaque native UI index, never an app/URL selector or a fresh-human
    /// witness. Reserving it fences concurrent GET/POST without consuming the
    /// original phase on a wrong CSRF or an unavailable publication reply.
    pub(super) fn manual(&self, handle: &str) -> Result<Flight<'_>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Google Begin ownership unavailable"))?;
        let mut found = None;
        for (key, entry) in entries.iter() {
            let matches = match &entry.stage {
                Stage::Idle(Payload::Manual(fresh) | Payload::Fresh(fresh)) => {
                    fresh.manual_handle() == handle
                }
                _ => false,
            };
            if matches {
                ensure!(found.is_none(), "Google manual handle collision");
                found = Some(key.clone());
            }
        }
        let key = found.context("Google manual checkpoint expired, busy or consumed")?;
        let entry = entries.get_mut(&key).context("Google manual owner lost")?;
        let payload = match std::mem::replace(&mut entry.stage, Stage::Busy) {
            Stage::Idle(payload @ (Payload::Manual(_) | Payload::Fresh(_))) => payload,
            _ => {
                entry.stage = Stage::Terminal;
                anyhow::bail!("Google manual phase changed");
            }
        };
        Ok(Flight {
            begins: self,
            key,
            original: entry.original.clone(),
            payload: Some(payload),
            armed: true,
        })
    }
}

/// A bounded in-flight borrow, without holding a mutex or SQLite transaction
/// over RPC. Private tuple ownership moves with the flight; it is never cloned.
pub(super) struct Flight<'a> {
    begins: &'a Begins,
    key: Digest,
    pub(super) original: Original,
    payload: Option<Payload>,
    armed: bool,
}

impl Flight<'_> {
    pub(super) fn payload(&self) -> Result<&Payload> {
        self.payload
            .as_ref()
            .context("Google tuple generation or callback cannot repeat")
    }

    /// Call BEFORE any Google tuple entropy or callback exchange. A failure
    /// while the payload is absent permanently refuses this original owner.
    pub(super) fn take(&mut self) -> Result<Payload> {
        self.payload
            .take()
            .context("Google original phase already taken")
    }

    pub(super) fn retain_publication(&mut self, bundle: GoogleBundle) -> Result<()> {
        ensure!(self.payload.is_none(), "Google bundle cannot be replaced");
        self.payload = Some(Payload::Publication(Box::new(bundle)));
        Ok(())
    }

    pub(super) fn retain_manual(&mut self, fresh: GoogleFresh) -> Result<()> {
        ensure!(self.payload.is_none(), "Google baseline cannot be replaced");
        self.payload = Some(Payload::Manual(Box::new(fresh)));
        Ok(())
    }

    /// The concrete caller first verifies the same immutable app publication
    /// acknowledgement. Only then may it return the appropriate phase URL.
    pub(super) fn offered(mut self) -> Result<String> {
        let payload = self.take()?;
        let (payload, location) = match payload {
            Payload::Publication(bundle) | Payload::Baseline(bundle) => {
                let location = bundle.baseline_location().to_owned();
                (Payload::Baseline(bundle), location)
            }
            Payload::Manual(fresh) => {
                let location = fresh.manual_location();
                (Payload::Manual(fresh), location)
            }
            Payload::Fresh(fresh) => {
                let location = fresh.manual_location();
                (Payload::Fresh(fresh), location)
            }
            _ => anyhow::bail!("Google publication acknowledgement required"),
        };
        let mut entries = self
            .begins
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Google Begin ownership unavailable"))?;
        let entry = entries
            .get_mut(&self.key)
            .context("Google Begin owner lost")?;
        ensure!(
            entry.original.owner == self.original.owner && matches!(entry.stage, Stage::Busy),
            "Google Begin original lifecycle changed"
        );
        entry.stage = Stage::Idle(payload);
        self.armed = false;
        Ok(location)
    }

    /// Only a verified explicit same-origin manual POST and current app
    /// acknowledgement may call this. A lost 303 can reconcile only this same
    /// URL; no GET/Begin exposes it and no tuple/budget is replaced.
    pub(super) fn resumed(mut self) -> Result<String> {
        let fresh = match self.take()? {
            Payload::Manual(fresh) | Payload::Fresh(fresh) => fresh,
            _ => anyhow::bail!("Google manual resume phase required"),
        };
        let location = fresh.location().to_owned();
        let mut entries = self
            .begins
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Google Begin ownership unavailable"))?;
        let entry = entries
            .get_mut(&self.key)
            .context("Google manual owner lost")?;
        ensure!(
            entry.original.owner == self.original.owner && matches!(entry.stage, Stage::Busy),
            "Google manual original lifecycle changed"
        );
        entry.stage = Stage::Idle(Payload::Fresh(fresh));
        self.armed = false;
        Ok(location)
    }

    pub(super) fn terminal(mut self) -> Result<()> {
        let mut entries = self
            .begins
            .entries
            .lock()
            .map_err(|_| anyhow::anyhow!("Google Begin ownership unavailable"))?;
        let entry = entries
            .get_mut(&self.key)
            .context("Google Begin owner lost")?;
        ensure!(
            entry.original.owner == self.original.owner && matches!(entry.stage, Stage::Busy),
            "Google Begin original lifecycle changed"
        );
        entry.stage = Stage::Terminal;
        self.armed = false;
        Ok(())
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(mut entries) = self.begins.entries.lock() else {
            return;
        };
        let Some(entry) = entries.get_mut(&self.key) else {
            return;
        };
        if entry.original.owner != self.original.owner || !matches!(entry.stage, Stage::Busy) {
            return;
        }
        entry.stage = match self.payload.take() {
            // These RPC outcomes are DATA-only and may reconcile only the same
            // original claim or retained bundle. No automatic HTTP retry runs.
            Some(
                payload @ (Payload::Claim
                | Payload::Publication(_)
                | Payload::Baseline(_)
                | Payload::Manual(_)
                | Payload::Fresh(_)),
            ) => Stage::Idle(payload),
            // Both callback states and a taken native allocation are one-shot.
            _ => Stage::Terminal,
        };
    }
}
