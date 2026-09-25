//! Scheduled execution: deriving occurrences and offering them to the runtime.
//!
//! This derives *when* a schedule should run and *what identity* that run has, and
//! drives the occurrences an instance has bound an actor for. Declaring and
//! admitting schedules belongs to the artifact; this acts on what was admitted.
//!
//! The source keeps no state. What ran last and what is still running are both
//! questions about the invocation table, which is already durable, so there is no
//! scheduler checkpoint to recover, diverge or corrupt.
//!
//! Occurrences are derived from the clock rather than stored. There is no timer to
//! recover, so a process that restarts recomputes the same occurrences and, because
//! the identity is derived from the occurrence rather than generated per attempt,
//! re-offering one that already ran is a no-op rather than a second run.

use anyhow::{Context, Result, ensure};
use rusqlite::OptionalExtension;

/// Occurrences are zero-padded to this width so that identities sort
/// lexicographically in the same order as their occurrences. Invocation ids are
/// the primary key, so the occurrence source can find the most recent run of a
/// schedule with an index seek rather than a scan that grows with every
/// occurrence ever run. Sixteen digits covers millisecond timestamps past the
/// year 300000; `validate` refuses a schedule that could exceed it.
pub const OCCURRENCE_DIGITS: usize = 16;

/// A schedule may not run more often than this. Refused at admission rather than
/// at runtime: a one-second schedule would produce a durable invocation, a
/// transaction and an audit receipt every second.
pub const MINIMUM_INTERVAL_MS: i64 = 60_000;

/// An application may declare at most this many schedules. The interval bounds one
/// schedule; nothing otherwise bounds declaring hundreds.
pub const MAXIMUM_SCHEDULES: usize = 16;

/// What to do with occurrences that elapsed while nothing was running. There is no
/// default: after an outage, running every missed occurrence and silently dropping
/// them are both wrong, and which is correct is a property of the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missed {
    /// Run once for the most recent elapsed occurrence. Earlier ones are recorded
    /// as superseded rather than executed.
    Coalesce,
    /// Run each elapsed occurrence in order, up to a bound, then fail closed
    /// rather than growing without limit.
    RunEach { bound: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub app: String,
    pub name: String,
    pub interval_ms: i64,
    pub missed: Missed,
}

impl Schedule {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.interval_ms >= MINIMUM_INTERVAL_MS,
            "schedule interval must be at least {MINIMUM_INTERVAL_MS} ms"
        );
        ensure!(
            !self.app.is_empty() && !self.name.is_empty(),
            "schedule requires an application and a name"
        );
        // The identity becomes an invocation id, which accepts a narrow alphabet.
        for part in [&self.app, &self.name] {
            ensure!(
                part.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
                "schedule names must use the invocation identifier alphabet"
            );
        }
        ensure!(
            self.prefix().len() + OCCURRENCE_DIGITS <= 128,
            "schedule identity exceeds the invocation identifier bound"
        );
        if let Missed::RunEach { bound } = self.missed {
            ensure!(bound > 0 && bound <= 64, "missed-occurrence bound");
        }
        Ok(())
    }

    /// The occurrence covering an instant: the largest multiple of the interval at
    /// or before it. A pure function of the clock, so every process agrees without
    /// coordinating and a restart recomputes the same answer.
    pub fn occurrence_at(&self, now_ms: i64) -> i64 {
        now_ms.div_euclid(self.interval_ms) * self.interval_ms
    }

    /// The invocation identity for an occurrence. Derived, never generated: a
    /// duplicate tick, a retry after a lost response and a restart mid-run all
    /// resolve to the same identity, so the existing exactly-once guarantee applies
    /// with no new mechanism.
    ///
    /// Invocation identifiers accept only `[A-Za-z0-9_-.]` and at most 128 bytes,
    /// so the parts are joined with `.` rather than `:`. That constrains schedule
    /// and application names to the same alphabet, which `validate` enforces.
    pub fn identity(&self, occurrence_ms: i64) -> String {
        format!(
            "{}{occurrence_ms:0width$}",
            self.prefix(),
            width = OCCURRENCE_DIGITS
        )
    }

    /// Every identity this schedule can produce begins with this, and no other
    /// schedule's does. The occurrence source uses it to ask two questions of the
    /// invocation table -- what ran last, and is anything still running -- so the
    /// source keeps no state of its own.
    pub fn prefix(&self) -> String {
        format!("schedule.{}.{}.", self.app, self.name)
    }

    /// The occurrence an identity names, or `None` if it is not this schedule's.
    pub fn occurrence_of(&self, identity: &str) -> Option<i64> {
        identity.strip_prefix(&self.prefix())?.parse().ok()
    }

    /// Occurrences to offer, given the last one known to have been offered. The
    /// caller supplies `last_offered` from durable state; `None` means the schedule
    /// has never run, in which case only the current occurrence is offered rather
    /// than every occurrence since the epoch.
    pub fn due(&self, last_offered: Option<i64>, now_ms: i64) -> Result<Vec<i64>> {
        let current = self.occurrence_at(now_ms);
        let Some(last) = last_offered else {
            return Ok(vec![current]);
        };
        // A clock that moved backwards yields nothing new. The occurrence already
        // ran, and re-offering it would be a no-op anyway, but returning nothing
        // keeps the caller from logging a spurious attempt.
        if current <= last {
            return Ok(Vec::new());
        }
        match self.missed {
            Missed::Coalesce => Ok(vec![current]),
            Missed::RunEach { bound } => {
                let mut due = Vec::new();
                let mut at = last + self.interval_ms;
                while at <= current {
                    ensure!(
                        due.len() < bound,
                        "missed occurrences exceed the declared bound of {bound}"
                    );
                    due.push(at);
                    at += self.interval_ms;
                }
                Ok(due)
            }
        }
    }
}

/// Offer one occurrence to the runtime: derive its identity, accept it as an
/// internal route and run it. This is the single step an occurrence source
/// repeats; the loop that decides *when* to call it, the at-most-one-in-flight
/// rule and the missed-occurrence policy are not built yet.
///
/// Because the identity is derived, calling this twice for the same occurrence
/// commits once -- which is what the hold gate establishes. The actor is a
/// parameter because a schedule has no caller: the instance must bind one, and
/// that binding is also not built. Passing it here keeps the decision visible
/// rather than letting a default identity appear by accident.
///
/// A command whose effects are still outstanding returns `pending` rather than
/// completing here. That is not an error and needs no handling of its own: the
/// existing command scheduler already drains pending invocations durably, which is the reason a
/// schedule can be a trigger for an ordinary command rather than a new execution
/// kind.
pub fn offer(
    runtime: &crate::store::Runtime,
    schedule: &Schedule,
    actor: &str,
    operation: &str,
    input: &serde_json::Value,
    now_ms: i64,
) -> Result<crate::protocol::Outcome> {
    offer_occurrence(
        runtime,
        schedule,
        actor,
        operation,
        input,
        schedule.occurrence_at(now_ms),
    )
}

/// Offer one exact occurrence. The tick loop has already derived which occurrence
/// is due, and must not re-derive it from a clock that has moved since.
pub fn offer_occurrence(
    runtime: &crate::store::Runtime,
    schedule: &Schedule,
    actor: &str,
    operation: &str,
    input: &serde_json::Value,
    occurrence_ms: i64,
) -> Result<crate::protocol::Outcome> {
    schedule.validate()?;
    let identity = schedule.identity(occurrence_ms);
    // The occurrence is the run's logical time, not the wall clock that noticed it.
    // A tick that arrives late therefore produces the same invocation it would have
    // produced on time, which is what makes a delayed tick harmless.
    let seconds = occurrence_ms.div_euclid(1_000);
    // Accepting the same identity twice is already a reuse rather than a second
    // invocation, provided the operation, actor and input match -- which they do,
    // because all three are fixed by the declaration. No separate guard is needed.
    runtime.accept_route(
        operation,
        actor,
        &identity,
        input,
        seconds,
        crate::audit::Trigger::Schedule,
    )?;
    runtime.execute(&identity, crate::store::Fault::None)
}

/// Why an occurrence was not offered. A schedule that silently does nothing is
/// indistinguishable from one that is working, so every skip has a stated reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Skipped {
    /// The instance bound no actor. A schedule cannot choose its own identity, so
    /// this is the safe outcome rather than a default one.
    Unbound,
    /// Bound, but paused by the instance.
    Disabled,
    /// A previous occurrence is still running. Overlapping runs of the same
    /// schedule would race on the same rows.
    InFlight { since_ms: i64 },
    /// Nothing has elapsed since the last occurrence offered.
    NotDue,
    /// The backlog exceeded the declared catch-up bound, so the schedule failed
    /// closed. It stays failed until an operator resumes it; see SCHEDULES-PLAN.
    Backlog(String),
}

/// What one tick did to one schedule.
#[derive(Debug)]
pub struct Tick {
    pub schedule: String,
    pub offered: Vec<(i64, crate::protocol::Outcome)>,
    pub skipped: Option<Skipped>,
}

/// The most recent occurrence offered for this schedule, read from the invocation
/// table. Identities are the primary key and sort in occurrence order, so this is
/// a single index seek rather than a scan over every occurrence ever run.
fn last_offered(connection: &rusqlite::Connection, schedule: &Schedule) -> Result<Option<i64>> {
    let prefix = schedule.prefix();
    let identity: Option<String> = connection
        .query_row(
            "SELECT id FROM day2_invocations WHERE id >= ?1 AND id < ?2 ORDER BY id DESC LIMIT 1",
            rusqlite::params![prefix, format!("{prefix}~")],
            |row| row.get(0),
        )
        .optional()?;
    Ok(identity.and_then(|identity| schedule.occurrence_of(&identity)))
}

/// The occurrence of a run that has not finished, if any.
fn in_flight(connection: &rusqlite::Connection, schedule: &Schedule) -> Result<Option<i64>> {
    let prefix = schedule.prefix();
    let identity: Option<String> = connection
        .query_row(
            "SELECT id FROM day2_invocations WHERE id >= ?1 AND id < ?2 AND status='pending' ORDER BY id LIMIT 1",
            rusqlite::params![prefix, format!("{prefix}~")],
            |row| row.get(0),
        )
        .optional()?;
    Ok(identity.and_then(|identity| schedule.occurrence_of(&identity)))
}

/// Run one tick of the occurrence source for every schedule the artifact declares.
///
/// This is the whole loop body. Calling it more often than the shortest declared
/// interval is harmless -- occurrences are derived from the clock, so an extra tick
/// finds nothing due -- and calling it late only delays a run, never loses one,
/// because the occurrence that elapsed is still computed from the clock when the
/// next tick arrives. That is the property that makes a missed tick survivable and
/// a durable timer unnecessary.
pub fn tick(runtime: &crate::store::Runtime, now_ms: i64) -> Result<Vec<Tick>> {
    let instance = crate::artifact::Instance::load(runtime.instance_path())?;
    let app = runtime.app();
    let bindings = instance
        .apps
        .get(app)
        .context("app_not_installed")?
        .schedules
        .clone();
    let declared = runtime.artifact().contract().schedules.clone();
    let mut ticks = Vec::new();
    for declaration in &declared {
        let schedule = from_declaration(app, declaration)?;
        let mut tick = Tick {
            schedule: declaration.name.clone(),
            offered: Vec::new(),
            skipped: None,
        };
        let Some(binding) = bindings.get(&declaration.name) else {
            tick.skipped = Some(Skipped::Unbound);
            ticks.push(tick);
            continue;
        };
        if binding.disabled {
            tick.skipped = Some(Skipped::Disabled);
            ticks.push(tick);
            continue;
        }
        let connection = crate::store::open(runtime.db())?;
        if let Some(since_ms) = in_flight(&connection, &schedule)? {
            tick.skipped = Some(Skipped::InFlight { since_ms });
            ticks.push(tick);
            continue;
        }
        let last = last_offered(&connection, &schedule)?;
        drop(connection);
        let due = match schedule.due(last, now_ms) {
            Ok(due) => due,
            Err(error) => {
                tick.skipped = Some(Skipped::Backlog(format!("{error:#}")));
                ticks.push(tick);
                continue;
            }
        };
        if due.is_empty() {
            tick.skipped = Some(Skipped::NotDue);
        }
        for occurrence in due {
            let outcome = offer_occurrence(
                runtime,
                &schedule,
                &binding.actor,
                &declaration.operation,
                &serde_json::from_str(&declaration.input)?,
                occurrence,
            )?;
            tick.offered.push((occurrence, outcome));
        }
        ticks.push(tick);
    }
    Ok(ticks)
}

/// The schedule an admitted declaration describes.
pub fn from_declaration(app: &str, declaration: &crate::artifact::Schedule) -> Result<Schedule> {
    let schedule = Schedule {
        app: app.to_owned(),
        name: declaration.name.clone(),
        interval_ms: i64::try_from(declaration.interval_ms)?,
        missed: match declaration.missed.as_str() {
            "run_each" => Missed::RunEach {
                bound: usize::try_from(declaration.catch_up_bound)?,
            },
            "coalesce" => Missed::Coalesce,
            other => anyhow::bail!("unknown missed-occurrence policy {other}"),
        },
    };
    schedule.validate()?;
    Ok(schedule)
}

/// Remembers which refusals have already been reported.
///
/// A refusal is a condition, not an event: an unbound schedule is still unbound on
/// the next tick, and restating that every ten seconds buries the one time it
/// mattered. This reports a refusal when it starts and when it changes, and forgets
/// it once the schedule runs again -- so the next failure is reported afresh rather
/// than suppressed as a duplicate of an old one.
#[derive(Debug, Default)]
pub struct Refusals(std::collections::BTreeMap<String, Skipped>);

impl Refusals {
    pub fn should_report(&mut self, schedule: &str, skipped: Option<&Skipped>) -> bool {
        match skipped {
            // Running, or nothing to do. Both mean the schedule is healthy, so a
            // later refusal is news again.
            None | Some(Skipped::NotDue) => {
                self.0.remove(schedule);
                false
            }
            Some(reason) => {
                if self.0.get(schedule) == Some(reason) {
                    return false;
                }
                self.0.insert(schedule.to_owned(), reason.clone());
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_minute() -> Schedule {
        Schedule {
            app: "reports".into(),
            name: "sweep".into(),
            interval_ms: MINIMUM_INTERVAL_MS,
            missed: Missed::Coalesce,
        }
    }

    #[test]
    fn an_occurrence_is_a_pure_function_of_the_clock() -> Result<()> {
        let schedule = every_minute();
        // Every instant within one interval maps to the same occurrence, so two
        // processes reading slightly different clocks still agree.
        let base = 1_758_067_200_000;
        for offset in [0, 1, 17, 59_999] {
            assert_eq!(schedule.occurrence_at(base + offset), base);
        }
        assert_eq!(
            schedule.occurrence_at(base + MINIMUM_INTERVAL_MS),
            base + MINIMUM_INTERVAL_MS
        );
        Ok(())
    }

    #[test]
    fn identity_is_derived_so_a_restart_recomputes_it_exactly() -> Result<()> {
        let schedule = every_minute();
        let occurrence = schedule.occurrence_at(1_758_067_230_000);
        // A process that restarts derives the same identity from the same clock
        // reading; nothing about the identity depends on process state.
        let before = schedule.identity(occurrence);
        let after = every_minute().identity(every_minute().occurrence_at(1_758_067_259_999));
        assert_eq!(before, after);
        assert_eq!(before, "schedule.reports.sweep.0001758067200000");
        Ok(())
    }

    #[test]
    fn a_backwards_clock_offers_nothing_new() -> Result<()> {
        let schedule = every_minute();
        let last = schedule.occurrence_at(1_758_067_200_000);
        // Clock corrections move time backwards. The occurrence already ran, so
        // nothing is offered and no second run is possible.
        assert!(schedule.due(Some(last), 1_758_067_100_000)?.is_empty());
        assert!(schedule.due(Some(last), 1_758_067_200_000)?.is_empty());
        Ok(())
    }

    #[test]
    fn a_first_run_does_not_backfill_from_the_epoch() -> Result<()> {
        let schedule = every_minute();
        // Without durable state a schedule must not treat every occurrence since
        // 1970 as missed.
        assert_eq!(
            schedule.due(None, 1_758_067_230_000)?,
            vec![1_758_067_200_000]
        );
        Ok(())
    }

    #[test]
    fn coalescing_collapses_an_outage_to_one_occurrence() -> Result<()> {
        let schedule = every_minute();
        let last = 1_758_067_200_000;
        // Three days down at one occurrence a minute is 4,320 missed occurrences.
        let now = last + MINIMUM_INTERVAL_MS * 4_320;
        assert_eq!(schedule.due(Some(last), now)?, vec![now]);
        Ok(())
    }

    #[test]
    fn running_each_missed_occurrence_fails_closed_at_its_bound() -> Result<()> {
        let schedule = Schedule {
            missed: Missed::RunEach { bound: 10 },
            ..every_minute()
        };
        let last = 1_758_067_200_000;
        let due = schedule.due(Some(last), last + MINIMUM_INTERVAL_MS * 3)?;
        assert_eq!(due.len(), 3);
        assert_eq!(due[0], last + MINIMUM_INTERVAL_MS);
        // Beyond the declared bound it refuses rather than growing without limit.
        assert!(
            schedule
                .due(Some(last), last + MINIMUM_INTERVAL_MS * 99)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_persistent_refusal_is_reported_once_and_a_change_is_reported_again() {
        let mut refusals = Refusals::default();
        // Reported when it starts.
        assert!(refusals.should_report("sweep", Some(&Skipped::Unbound)));
        // Not restated on every tick for the next however-many hours.
        assert!(!refusals.should_report("sweep", Some(&Skipped::Unbound)));
        assert!(!refusals.should_report("sweep", Some(&Skipped::Unbound)));
        // A different reason is a different condition.
        assert!(refusals.should_report("sweep", Some(&Skipped::Disabled)));
        assert!(!refusals.should_report("sweep", Some(&Skipped::Disabled)));
        // Schedules are tracked independently.
        assert!(refusals.should_report("digest", Some(&Skipped::Disabled)));
        // Recovering clears the memory, so the next failure is reported rather than
        // silently swallowed as a repeat of the one before it.
        assert!(!refusals.should_report("sweep", None));
        assert!(refusals.should_report("sweep", Some(&Skipped::Disabled)));
        // Not due is ordinary and must not itself be reported.
        assert!(!refusals.should_report("digest", Some(&Skipped::NotDue)));
        assert!(refusals.should_report("digest", Some(&Skipped::Disabled)));
    }

    #[test]
    fn identities_sort_in_occurrence_order() -> Result<()> {
        let schedule = every_minute();
        // Invocation ids are the primary key, so the occurrence source finds the
        // most recent run with a range seek. That is only correct if string order
        // matches time order -- unpadded, "...9" would sort after "...10".
        let mut identities: Vec<String> = (0..64)
            .map(|step| schedule.identity(step * MINIMUM_INTERVAL_MS))
            .collect();
        let expected = identities.clone();
        identities.sort();
        assert_eq!(identities, expected);
        // And the occurrence survives the round trip, which is how the source
        // learns what ran last without storing it.
        for identity in &identities {
            let occurrence = schedule
                .occurrence_of(identity)
                .context("identity is this schedule's")?;
            assert_eq!(schedule.identity(occurrence), *identity);
        }
        // Another schedule's identity is not claimed.
        let other = Schedule {
            name: "digest".into(),
            ..every_minute()
        };
        assert!(other.occurrence_of(&identities[0]).is_none());
        Ok(())
    }

    #[test]
    fn an_identity_is_a_valid_invocation_identifier() -> Result<()> {
        let schedule = every_minute();
        let identity = schedule.identity(schedule.occurrence_at(1_758_067_230_000));
        // The runtime accepts only this alphabet for invocation identifiers.
        assert!(
            identity
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte)),
            "identity {identity} is not a valid invocation identifier"
        );
        assert!(identity.len() <= 128);
        // A name outside that alphabet is refused rather than producing an
        // identifier the runtime would reject at execution time.
        let bad = Schedule {
            name: "nightly sweep".into(),
            ..every_minute()
        };
        assert!(bad.validate().is_err());
        Ok(())
    }

    #[test]
    fn a_schedule_faster_than_the_minimum_is_refused() -> Result<()> {
        let schedule = Schedule {
            interval_ms: 1_000,
            ..every_minute()
        };
        assert!(schedule.validate().is_err());
        assert!(every_minute().validate().is_ok());
        Ok(())
    }
}
