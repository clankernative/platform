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

/// One hour, the unit a daily schedule's anchor is declared in.
pub const HOUR_MS: i64 = 60 * 60_000;

/// Schedules at least this long must be anchored to an hour of the UTC day, and
/// shorter ones cannot be. Admission enforces the same rule on the declaration.
pub const DAY_MS: i64 = 24 * HOUR_MS;

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
    /// The UTC hour a daily schedule fires at. Occurrences fall at
    /// `k * interval_ms + anchor_hour * HOUR_MS` since the epoch, so a schedule
    /// declared for 10:00 runs at 10:00 UTC rather than at midnight. `None` for
    /// schedules shorter than a day, whose occurrences are multiples of the interval.
    pub anchor_hour: Option<i64>,
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
        // The same rule admission applies to the declaration. An anchor is what
        // keeps a daily occurrence at a stable instant; on a shorter schedule it
        // would name an offset the interval cannot contain.
        ensure!(
            (self.interval_ms >= DAY_MS) == self.anchor_hour.is_some(),
            "a daily schedule requires a UTC anchor hour, and a shorter one cannot take it"
        );
        if let Some(hour) = self.anchor_hour {
            ensure!(
                (0..24).contains(&hour),
                "schedule anchor hour is outside the UTC day"
            );
        }
        Ok(())
    }

    /// How far past each multiple of the interval an occurrence falls.
    fn anchor_ms(&self) -> i64 {
        self.anchor_hour.map_or(0, |hour| hour * HOUR_MS)
    }

    /// The occurrence covering an instant: the latest anchored multiple of the
    /// interval at or before it, `k * interval_ms + anchor` since the epoch (UTC).
    /// A pure function of the clock, so every process agrees without coordinating
    /// and a restart recomputes the same answer.
    pub fn occurrence_at(&self, now_ms: i64) -> i64 {
        let anchor = self.anchor_ms();
        (now_ms - anchor).div_euclid(self.interval_ms) * self.interval_ms + anchor
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
    ///
    /// `last_offered` need not lie on this schedule's grid. A run recorded before
    /// the anchor applied -- every daily schedule used to fire at 00:00 UTC -- or
    /// under a different declared hour is read as the run of the anchored
    /// occurrence that covers it. Each anchored occurrence therefore still runs at
    /// most once and none after it is skipped: an installation whose last run was
    /// at 00:00 does not run again until the next anchor hour, then continues on the
    /// anchored grid rather than stepping on from the old one.
    pub fn due(&self, last_offered: Option<i64>, now_ms: i64) -> Result<Vec<i64>> {
        let current = self.occurrence_at(now_ms);
        let Some(last) = last_offered else {
            return Ok(vec![current]);
        };
        let last = self.occurrence_at(last);
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
/// A command with deferred effects returns `pending` rather than completing here.
/// That is not an error and needs no handling of its own: the existing command
/// scheduler already drains pending invocations durably, which is the reason a
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
        ticks.push(advance(
            runtime,
            &schedule,
            &binding.actor,
            &declaration.operation,
            &serde_json::from_str(&declaration.input)?,
            now_ms,
        )?);
    }
    Ok(ticks)
}

/// One tick of one bound, enabled schedule: refuse while a run is in flight,
/// otherwise offer whatever the invocation table and the clock say is due.
pub fn advance(
    runtime: &crate::store::Runtime,
    schedule: &Schedule,
    actor: &str,
    operation: &str,
    input: &serde_json::Value,
    now_ms: i64,
) -> Result<Tick> {
    let mut tick = Tick {
        schedule: schedule.name.clone(),
        offered: Vec::new(),
        skipped: None,
    };
    // Queue facts are DATA. The native SQL owner must close and settle before
    // accept/execute can enter their separate SQL and provider phases.
    let (in_flight, last) = runtime.sql_read(|connection| {
        runtime.check_binding(connection)?;
        let pending = in_flight(connection, schedule)?;
        let last = if pending.is_none() {
            last_offered(connection, schedule)?
        } else {
            None
        };
        Ok((pending, last))
    })?;
    if let Some(since_ms) = in_flight {
        tick.skipped = Some(Skipped::InFlight { since_ms });
        return Ok(tick);
    }
    let due = match schedule.due(last, now_ms) {
        Ok(due) => due,
        Err(error) => {
            tick.skipped = Some(Skipped::Backlog(format!("{error:#}")));
            return Ok(tick);
        }
    };
    if due.is_empty() {
        tick.skipped = Some(Skipped::NotDue);
    }
    for occurrence in due {
        let outcome = offer_occurrence(runtime, schedule, actor, operation, input, occurrence)?;
        tick.offered.push((occurrence, outcome));
    }
    Ok(tick)
}

/// The schedule an admitted declaration describes.
pub fn from_declaration(app: &str, declaration: &crate::artifact::Schedule) -> Result<Schedule> {
    let schedule = Schedule {
        app: app.to_owned(),
        name: declaration.name.clone(),
        interval_ms: i64::try_from(declaration.interval_ms)?,
        anchor_hour: (declaration.anchor_hour >= 0).then_some(declaration.anchor_hour),
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
            anchor_hour: None,
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

    /// 2025-09-17T00:00:00Z.
    const MIDNIGHT: i64 = 1_758_067_200_000;

    fn daily_at(hour: i64, missed: Missed) -> Schedule {
        Schedule {
            app: "equity".into(),
            name: "vesting".into(),
            interval_ms: DAY_MS,
            anchor_hour: Some(hour),
            missed,
        }
    }

    #[test]
    fn a_daily_schedule_fires_at_its_anchor_hour_in_utc() -> Result<()> {
        let schedule = daily_at(10, Missed::Coalesce);
        let ten = MIDNIGHT + 10 * HOUR_MS;
        // Every instant from 10:00 until the next 10:00 belongs to today's 10:00
        // occurrence -- not to midnight, which is where every daily schedule used
        // to fire whatever hour it declared.
        for at in [ten, ten + 1, ten + 13 * HOUR_MS, ten + DAY_MS - 1] {
            assert_eq!(schedule.occurrence_at(at), ten, "at {at}");
        }
        // Midnight and the rest of the morning still belong to yesterday's.
        for at in [MIDNIGHT, MIDNIGHT + 1, ten - 1] {
            assert_eq!(schedule.occurrence_at(at), ten - DAY_MS, "at {at}");
        }
        assert_eq!(schedule.occurrence_at(ten + DAY_MS), ten + DAY_MS);
        // The identity, and so Context.now inside the run, names 10:00.
        assert_eq!(
            schedule.identity(ten),
            format!("schedule.equity.vesting.{ten:016}")
        );
        Ok(())
    }

    #[test]
    fn a_daily_schedule_is_due_at_its_anchor_and_not_a_millisecond_before() -> Result<()> {
        let schedule = daily_at(10, Missed::Coalesce);
        let yesterday = MIDNIGHT - 14 * HOUR_MS;
        assert_eq!(yesterday, schedule.occurrence_at(yesterday));
        let ten = MIDNIGHT + 10 * HOUR_MS;
        for at in [MIDNIGHT, ten - 1] {
            assert!(schedule.due(Some(yesterday), at)?.is_empty(), "at {at}");
        }
        assert_eq!(schedule.due(Some(yesterday), ten)?, vec![ten]);
        assert_eq!(schedule.due(Some(yesterday), ten + 1)?, vec![ten]);
        // Once it ran, the rest of the day is not due.
        assert!(schedule.due(Some(ten), ten + DAY_MS - 1)?.is_empty());
        Ok(())
    }

    #[test]
    fn an_anchor_hour_of_zero_still_fires_at_midnight() -> Result<()> {
        let schedule = daily_at(0, Missed::Coalesce);
        assert_eq!(schedule.occurrence_at(MIDNIGHT + 23 * HOUR_MS), MIDNIGHT);
        assert_eq!(schedule.occurrence_at(MIDNIGHT - 1), MIDNIGHT - DAY_MS);
        Ok(())
    }

    #[test]
    fn a_multi_day_schedule_keeps_its_anchor_hour() -> Result<()> {
        let schedule = Schedule {
            interval_ms: 2 * DAY_MS,
            ..daily_at(3, Missed::Coalesce)
        };
        let occurrence = schedule.occurrence_at(MIDNIGHT);
        assert_eq!(occurrence.rem_euclid(DAY_MS), 3 * HOUR_MS);
        assert_eq!((occurrence - 3 * HOUR_MS).rem_euclid(2 * DAY_MS), 0);
        assert!(occurrence <= MIDNIGHT && MIDNIGHT < occurrence + 2 * DAY_MS);
        Ok(())
    }

    #[test]
    fn a_first_daily_run_offers_only_the_current_anchored_occurrence() -> Result<()> {
        let schedule = daily_at(10, Missed::RunEach { bound: 3 });
        // Installed at 05:00: the current occurrence is yesterday's 10:00, not
        // today's midnight and not a backfill from the epoch.
        assert_eq!(
            schedule.due(None, MIDNIGHT + 5 * HOUR_MS)?,
            vec![MIDNIGHT - 14 * HOUR_MS]
        );
        Ok(())
    }

    #[test]
    fn a_daily_outage_backlog_stays_on_the_anchor() -> Result<()> {
        let ten = MIDNIGHT + 10 * HOUR_MS;
        // Down from just after today's run until 15:00 three days later.
        let now = ten + 3 * DAY_MS + 5 * HOUR_MS;
        let coalesce = daily_at(10, Missed::Coalesce);
        assert_eq!(coalesce.due(Some(ten), now)?, vec![ten + 3 * DAY_MS]);
        let each = daily_at(10, Missed::RunEach { bound: 3 });
        assert_eq!(
            each.due(Some(ten), now)?,
            vec![ten + DAY_MS, ten + 2 * DAY_MS, ten + 3 * DAY_MS]
        );
        // One more day than the bound fails closed, as for any schedule.
        assert!(each.due(Some(ten), now + DAY_MS).is_err());
        Ok(())
    }

    #[test]
    fn a_run_recorded_before_the_anchor_applied_neither_repeats_nor_skips() -> Result<()> {
        // Before anchors were honoured every daily schedule fired at 00:00 UTC, so
        // an upgraded installation's last run is midnight. Midnight lies inside
        // yesterday's 10:00 occurrence, which is the one it is taken to have run.
        let legacy = MIDNIGHT;
        let ten = MIDNIGHT + 10 * HOUR_MS;
        for missed in [Missed::Coalesce, Missed::RunEach { bound: 3 }] {
            let schedule = daily_at(10, missed);
            // No second run on the morning of the upgrade.
            for at in [legacy, legacy + 1, ten - 1] {
                assert!(
                    schedule.due(Some(legacy), at)?.is_empty(),
                    "{missed:?} at {at}"
                );
            }
            // Today's 10:00 is not skipped.
            assert_eq!(schedule.due(Some(legacy), ten)?, vec![ten], "{missed:?}");
        }
        // A backlog that began before the upgrade is caught up on the anchored
        // grid, never at the old midnight occurrences.
        let each = daily_at(10, Missed::RunEach { bound: 3 });
        assert_eq!(
            each.due(Some(legacy), ten + 2 * DAY_MS)?,
            vec![ten, ten + DAY_MS, ten + 2 * DAY_MS]
        );
        // The same holds when an application moves its declared hour.
        let moved = daily_at(14, Missed::Coalesce);
        assert!(
            moved
                .due(Some(ten), MIDNIGHT + 14 * HOUR_MS - 1)?
                .is_empty()
        );
        assert_eq!(
            moved.due(Some(ten), MIDNIGHT + 14 * HOUR_MS)?,
            vec![MIDNIGHT + 14 * HOUR_MS]
        );
        Ok(())
    }

    #[test]
    fn an_unanchored_schedule_still_counts_from_the_epoch() -> Result<()> {
        let hourly = Schedule {
            interval_ms: HOUR_MS,
            ..every_minute()
        };
        assert_eq!(
            hourly.occurrence_at(MIDNIGHT + 10 * HOUR_MS + 1_800_000),
            MIDNIGHT + 10 * HOUR_MS
        );
        assert_eq!(
            hourly.due(Some(MIDNIGHT), MIDNIGHT + 3 * HOUR_MS + 1)?,
            vec![MIDNIGHT + 3 * HOUR_MS]
        );
        Ok(())
    }

    #[test]
    fn the_anchor_must_match_the_interval() -> Result<()> {
        assert!(daily_at(10, Missed::Coalesce).validate().is_ok());
        assert!(daily_at(23, Missed::Coalesce).validate().is_ok());
        assert!(daily_at(24, Missed::Coalesce).validate().is_err());
        assert!(daily_at(-1, Missed::Coalesce).validate().is_err());
        let unanchored = Schedule {
            anchor_hour: None,
            ..daily_at(10, Missed::Coalesce)
        };
        assert!(unanchored.validate().is_err());
        let anchored_minute = Schedule {
            anchor_hour: Some(3),
            ..every_minute()
        };
        assert!(anchored_minute.validate().is_err());
        Ok(())
    }

    #[test]
    fn a_declaration_carries_its_anchor_into_the_schedule() -> Result<()> {
        let declaration = crate::artifact::Schedule {
            name: "vesting".into(),
            operation: "equity.vest".into(),
            input: "{}".into(),
            input_type: "empty".into(),
            interval_ms: DAY_MS as u64,
            anchor_hour: 10,
            missed: "coalesce".into(),
            catch_up_bound: 0,
        };
        let schedule = from_declaration("equity", &declaration)?;
        assert_eq!(schedule.anchor_hour, Some(10));
        assert_eq!(
            schedule.occurrence_at(MIDNIGHT + 11 * HOUR_MS),
            MIDNIGHT + 10 * HOUR_MS
        );
        let sweep = crate::artifact::Schedule {
            name: "sweep".into(),
            interval_ms: 300_000,
            anchor_hour: -1,
            ..declaration
        };
        assert_eq!(from_declaration("equity", &sweep)?.anchor_hour, None);
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
