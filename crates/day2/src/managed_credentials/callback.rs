//! Single-acceptance callback reservation kernel. Every input, conditional plan
//! and receipt here is DATA, not a worker claim, command acceptance or permission.
//! No issuer, ingress, transport, store installer or native factory is supplied.
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, credentials::Namespace};
use serde::{Deserialize, Serialize};

/// The complete immutable launch/claim contract. Actual canonical target
/// extraction and genuine current-worker evidence belong to the future caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claim {
    pub namespace: Namespace,
    pub artifact: Digest,
    pub authority: Digest,
    pub worker: Digest,
    pub dispatch: Digest,
    pub claim: Digest,
    pub claim_epoch: u64,
    pub security_epoch: u64,
    pub resource: Digest,
    pub operation: Digest,
    pub ceiling: Digest,
}

impl Claim {
    fn validate(&self) -> Result<()> {
        self.namespace.validate()?;
        ensure!(
            self.claim_epoch > 0 && self.security_epoch > 0,
            "callback_invalid_epoch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub callback: Digest,
    pub credential_version: Digest,
    pub claim: Claim,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl Binding {
    fn validate(&self) -> Result<()> {
        self.claim.validate()?;
        ensure!(
            self.issued_at >= 0
                && self
                    .expires_at
                    .checked_sub(self.issued_at)
                    .is_some_and(|span| (1..=3600).contains(&span)),
            "callback_invalid_lifetime"
        );
        Ok(())
    }
}

/// A controlled-source observation, not native evidence. A future adapter must
/// freshly obtain this under the actual owner's original and refusal rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Current {
    pub claim: Claim,
    pub enabled: bool,
    pub observed_at: i64,
    pub ready_until: i64,
}

fn current(binding: &Binding, observed: &Current, at: i64) -> Result<()> {
    binding.validate()?;
    observed.claim.validate()?;
    ensure!(
        observed.enabled && observed.claim == binding.claim,
        "callback_claim_changed"
    );
    ensure!(
        observed.observed_at >= 0
            && observed.observed_at <= at
            && at < observed.ready_until
            && observed
                .ready_until
                .checked_sub(observed.observed_at)
                .is_some_and(|span| (1..=300).contains(&span))
            && binding.issued_at <= at
            && at < binding.expires_at,
        "callback_expired_or_clock_rewound"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Invocation {
    pub id: String,
    pub input: Digest,
}

impl Invocation {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
            "callback_invalid_invocation"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Use {
    Unspent {},
    Reserved {
        invocation: Invocation,
        reserved_at: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub binding: Binding,
    pub use_state: Use,
}

impl Record {
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if let Use::Reserved {
            invocation,
            reserved_at,
        } = &self.use_state
        {
            invocation.validate()?;
            ensure!(
                self.binding.issued_at <= *reserved_at && *reserved_at < self.binding.expires_at,
                "callback_invalid_reservation_time"
            );
        }
        Ok(())
    }
}

/// Provider version is an exact conditional token; equal-value rewrites cannot
/// make an old plan current. This integer is DATA, not an epoch or a clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub version: u64,
    pub record: Record,
}

impl Snapshot {
    fn validate(&self) -> Result<()> {
        ensure!(self.version > 0, "callback_invalid_conditional_version");
        self.record.validate()
    }
}

/// Historical one-use reservation only. It cannot be dispatched or converted
/// to a runtime command receipt, worker claim or execution permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    pub binding: Digest,
    pub callback: Digest,
    pub invocation: Invocation,
    pub reserved_at: i64,
}

fn reservation(record: &Record) -> Result<Reservation> {
    record.validate()?;
    let Use::Reserved {
        invocation,
        reserved_at,
    } = &record.use_state
    else {
        anyhow::bail!("callback_unspent");
    };
    Ok(Reservation {
        binding: Digest::of(&record.binding)?,
        callback: record.binding.callback.clone(),
        invocation: invocation.clone(),
        reserved_at: *reserved_at,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    before: Snapshot,
    after: Snapshot,
}

impl Plan {
    pub(crate) fn before(&self) -> &Snapshot {
        &self.before
    }

    pub(crate) fn after(&self) -> &Snapshot {
        &self.after
    }

    fn validate(&self) -> Result<()> {
        self.before.validate()?;
        self.after.validate()?;
        ensure!(
            matches!(self.before.record.use_state, Use::Unspent {})
                && matches!(self.after.record.use_state, Use::Reserved { .. })
                && self.before.record.binding == self.after.record.binding
                && self.before.version.checked_add(1) == Some(self.after.version),
            "callback_invalid_plan"
        );
        Ok(())
    }

    /// Recheck fresh source DATA and the original exact read immediately before
    /// a conditional adapter stages it. This is still no dispatch permission.
    pub(crate) fn revalidate(
        &self,
        observed: &Current,
        at: i64,
        snapshot: &Snapshot,
    ) -> Result<()> {
        self.validate()?;
        current(&self.before.record.binding, observed, at)?;
        let Use::Reserved { reserved_at, .. } = self.after.record.use_state else {
            unreachable!()
        };
        ensure!(
            at >= reserved_at && snapshot == &self.before,
            "callback_plan_became_stale"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Reserve(Box<Plan>),
    Existing(Reservation),
}

/// A caller must first authenticate the credential and decode its real target.
/// This DATA reducer does neither and is not installed on an ingress route.
pub(crate) fn decide(
    binding: &Binding,
    invocation: &Invocation,
    observed: &Current,
    at: i64,
    snapshot: &Snapshot,
) -> Result<Decision> {
    current(binding, observed, at)?;
    invocation.validate()?;
    snapshot.validate()?;
    ensure!(
        &snapshot.record.binding == binding,
        "callback_binding_changed"
    );
    match &snapshot.record.use_state {
        Use::Unspent {} => {
            let plan = Plan {
                before: snapshot.clone(),
                after: Snapshot {
                    version: snapshot
                        .version
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("callback_version_exhausted"))?,
                    record: Record {
                        binding: binding.clone(),
                        use_state: Use::Reserved {
                            invocation: invocation.clone(),
                            reserved_at: at,
                        },
                    },
                },
            };
            plan.validate()?;
            Ok(Decision::Reserve(Box::new(plan)))
        }
        Use::Reserved {
            invocation: accepted,
            reserved_at,
        } => {
            ensure!(
                accepted == invocation && at >= *reserved_at,
                "callback_already_reserved_or_clock_rewound"
            );
            Ok(Decision::Existing(reservation(&snapshot.record)?))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Applied(Reservation),
    NotApplied,
    Conflict,
}

/// Reconcile a stored effect even after authority changed. This reports DATA,
/// never permission to retry, poll a command, return a result or execute work.
pub(crate) fn reconcile(plan: &Plan, observed: &Snapshot) -> Result<Outcome> {
    plan.validate()?;
    observed.validate()?;
    Ok(if observed == &plan.after {
        Outcome::Applied(reservation(&observed.record)?)
    } else if observed == &plan.before {
        Outcome::NotApplied
    } else {
        Outcome::Conflict
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use day2_capabilities::Name;
    use rusqlite::{Connection, TransactionBehavior, params};
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };

    fn name(value: &str) -> Name {
        Name::try_from(value.to_owned()).unwrap()
    }

    fn binding() -> Binding {
        let d = |v: &str| Digest::new(v.as_bytes());
        Binding {
            callback: d("callback-one"),
            credential_version: d("credential-one"),
            claim: Claim {
                namespace: Namespace {
                    installation: name("fixture"),
                    environment: name("test"),
                    app: name("callback"),
                    binding_generation: 1,
                },
                artifact: d("artifact"),
                authority: d("authority"),
                worker: d("worker"),
                dispatch: d("dispatch"),
                claim: d("claim"),
                claim_epoch: 3,
                security_epoch: 7,
                resource: d("run-one"),
                operation: d("complete-run"),
                ceiling: d("ceiling"),
            },
            issued_at: 1000,
            expires_at: 1300,
        }
    }

    fn invocation(id: u8, input: u8) -> Invocation {
        Invocation {
            id: format!("invocation-{id}"),
            input: Digest::new(&[input]),
        }
    }

    fn source() -> Current {
        Current {
            claim: binding().claim,
            enabled: true,
            observed_at: 1000,
            ready_until: 1300,
        }
    }

    fn initial() -> Snapshot {
        Snapshot {
            version: 1,
            record: Record {
                binding: binding(),
                use_state: Use::Unspent {},
            },
        }
    }

    fn plan(id: u8, input: u8, observed: &Snapshot) -> Result<Plan> {
        match decide(
            &binding(),
            &invocation(id, input),
            &source(),
            1100,
            observed,
        )? {
            Decision::Reserve(plan) => Ok(*plan),
            Decision::Existing(_) => anyhow::bail!("fixture requires unspent callback"),
        }
    }

    /// Ordinary conditional SQLite adapter, only in this test module. These are
    /// reservation + acceptance-INTENT rows, never real runtime command rows.
    struct Provider {
        db: Connection,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Rows {
        callback: Snapshot,
        intents: BTreeMap<String, Reservation>,
    }

    impl Provider {
        fn create(path: &Path) -> Result<Self> {
            let db = Connection::open(path)?;
            db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
                CREATE TABLE callback(slot INTEGER PRIMARY KEY CHECK(slot=1),version TEXT NOT NULL,record TEXT NOT NULL) STRICT;
                CREATE TABLE intent(invocation TEXT PRIMARY KEY,record TEXT NOT NULL) STRICT;")?;
            let start = initial();
            db.execute(
                "INSERT INTO callback VALUES(1,?1,?2)",
                params![
                    start.version.to_string(),
                    serde_json::to_string(&start.record)?
                ],
            )?;
            Ok(Self { db })
        }

        fn open(path: &Path) -> Result<Self> {
            Ok(Self {
                db: Connection::open(path)?,
            })
        }

        fn rows(&self) -> Result<Rows> {
            let callback = read(&self.db)?;
            let mut query = self
                .db
                .prepare("SELECT invocation,record FROM intent ORDER BY invocation")?;
            let intents = query
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|(id, json)| Ok((id, crate::json::decode(json.as_bytes())?)))
                .collect::<Result<_>>()?;
            Ok(Rows { callback, intents })
        }

        fn apply(&mut self, plan: &Plan, observed: &Current, at: i64, cut: Cut) -> Result<()> {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            plan.revalidate(observed, at, &read(&tx)?)?;
            checkpoint(cut, Cut::BeforeWrite)?;
            let changed = tx.execute("UPDATE callback SET version=?1,record=?2 WHERE slot=1 AND version=?3 AND record=?4",
                params![plan.after.version.to_string(),serde_json::to_string(&plan.after.record)?,plan.before.version.to_string(),serde_json::to_string(&plan.before.record)?])?;
            ensure!(changed == 1, "fixture exact conditional refused");
            checkpoint(cut, Cut::AfterRecord)?;
            let reserved = reservation(&plan.after.record)?;
            tx.execute(
                "INSERT INTO intent VALUES(?1,?2)",
                params![reserved.invocation.id, serde_json::to_string(&reserved)?],
            )?;
            checkpoint(cut, Cut::AfterIntent)?;
            tx.commit()?;
            checkpoint(cut, Cut::AfterCommit)
        }
    }

    fn read(db: &Connection) -> Result<Snapshot> {
        let (version, record): (String, String) = db.query_row(
            "SELECT version,record FROM callback WHERE slot=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let snapshot = Snapshot {
            version: version.parse()?,
            record: crate::json::decode(record.as_bytes())?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Cut {
        Known,
        BeforeWrite,
        AfterRecord,
        AfterIntent,
        AfterCommit,
    }

    // Logical cuts drive generated histories; the child fixture below pauses
    // at these SAME adapter statements and is killed by the parent.
    fn checkpoint(selected: Cut, here: Cut) -> Result<()> {
        PHASES.with(|p| p.borrow_mut().push(here));
        #[cfg(unix)]
        if CHILD_CUT.with(|v| v.get() == Some(here)) {
            child_pause(here)?;
        }
        ensure!(selected != here, "fixture_uncertain_completion");
        Ok(())
    }

    #[test]
    fn one_reservation_rejects_new_identity_or_input_and_recovery_keeps_original_time() -> Result<()>
    {
        let first = plan(1, 1, &initial())?;
        let after = first.after().clone();
        assert!(
            matches!(decide(&binding(),&invocation(1,1),&source(),1110,&after)?,Decision::Existing(r) if r.reserved_at==1100)
        );
        for req in [invocation(2, 1), invocation(1, 2)] {
            assert!(decide(&binding(), &req, &source(), 1110, &after).is_err());
        }
        assert!(decide(&binding(), &invocation(1, 1), &source(), 1099, &after).is_err());
        assert!(decide(&binding(), &invocation(1, 1), &source(), 1300, &after).is_err());
        assert!(matches!(reconcile(&first, &after)?, Outcome::Applied(_)));
        assert_eq!(reconcile(&first, &initial())?, Outcome::NotApplied);
        Ok(())
    }

    #[test]
    fn source_scope_claim_and_epoch_changes_refuse_before_and_after_reservation() -> Result<()> {
        for fault in 0..14 {
            let mut observed = source();
            let other = Digest::new(b"other");
            match fault {
                0 => observed.claim.namespace.installation = name("other"),
                1 => observed.claim.namespace.environment = name("other"),
                2 => observed.claim.namespace.app = name("other"),
                3 => observed.claim.namespace.binding_generation += 1,
                4 => observed.claim.artifact = other,
                5 => observed.claim.authority = other,
                6 => observed.claim.worker = other,
                7 => observed.claim.dispatch = other,
                8 => observed.claim.claim = other,
                9 => observed.claim.claim_epoch += 1,
                10 => observed.claim.security_epoch += 1,
                11 => observed.claim.resource = other,
                12 => observed.claim.operation = other,
                13 => observed.claim.ceiling = other,
                _ => unreachable!(),
            }
            let first = plan(1, 1, &initial())?;
            assert!(decide(&binding(), &invocation(1, 1), &observed, 1100, &initial()).is_err());
            assert!(first.revalidate(&observed, 1100, &initial()).is_err());
            assert!(
                decide(
                    &binding(),
                    &invocation(1, 1),
                    &observed,
                    1100,
                    first.after()
                )
                .is_err()
            );
            // Historical effect reconciliation is not receipt-poll authority.
            assert!(matches!(
                reconcile(&first, first.after())?,
                Outcome::Applied(_)
            ));
        }
        Ok(())
    }

    #[test]
    fn exact_version_fences_equal_value_rewrite_and_exhaustion() -> Result<()> {
        let first = plan(1, 1, &initial())?;
        let mut rewritten = initial();
        rewritten.version += 1;
        assert!(first.revalidate(&source(), 1100, &rewritten).is_err());
        assert_eq!(reconcile(&first, &rewritten)?, Outcome::Conflict);
        rewritten.version = u64::MAX;
        assert!(plan(1, 1, &rewritten).is_err());
        let mut foreign = initial();
        foreign.record.binding.callback = Digest::new(b"other");
        assert!(decide(&binding(), &invocation(1, 1), &source(), 1100, &foreign).is_err());
        Ok(())
    }

    #[test]
    fn malformed_and_unready_data_never_creates_a_plan() -> Result<()> {
        for fault in 0..6 {
            let mut observed = source();
            match fault {
                0 => observed.enabled = false,
                1 => observed.observed_at = 1101,
                2 => observed.ready_until = 1100,
                3 => observed.ready_until = 1301,
                4 => observed.claim.claim_epoch = 0,
                5 => observed.observed_at = -1,
                _ => unreachable!(),
            }
            assert!(decide(&binding(), &invocation(1, 1), &observed, 1100, &initial()).is_err());
        }
        let mut req = invocation(1, 1);
        req.id = " ".into();
        assert!(decide(&binding(), &req, &source(), 1100, &initial()).is_err());
        let mut raw = serde_json::to_value(initial())?;
        raw["record"]["use_state"]["unknown"] = true.into();
        assert!(crate::json::decode::<Snapshot>(&serde_json::to_vec(&raw)?).is_err());
        let mut bad = first_plan_json()?;
        bad["after"]["version"] = 99.into();
        let decoded: Plan = crate::json::decode(&serde_json::to_vec(&bad)?)?;
        assert!(decoded.revalidate(&source(), 1100, &initial()).is_err());
        Ok(())
    }

    fn first_plan_json() -> Result<serde_json::Value> {
        Ok(serde_json::to_value(plan(1, 1, &initial())?)?)
    }

    #[test]
    fn competing_prepared_invocations_cannot_reserve_the_same_callback_twice() -> Result<()> {
        for winner in [1, 2] {
            let dir = tempfile::tempdir()?;
            let path = dir.path().join("race.sqlite");
            let mut first = Provider::create(&path)?;
            let mut second = Provider::open(&path)?;
            let a = plan(winner, 1, &first.rows()?.callback)?;
            let b = plan(3 - winner, 2, &second.rows()?.callback)?;
            first.apply(&a, &source(), 1100, Cut::Known)?;
            let committed = second.rows()?;
            assert!(second.apply(&b, &source(), 1100, Cut::Known).is_err());
            assert_eq!(second.rows()?, committed);
            assert_eq!(committed.intents.len(), 1);
            assert!(matches!(
                decide(
                    &binding(),
                    &invocation(winner, 1),
                    &source(),
                    1110,
                    &committed.callback
                )?,
                Decision::Existing(_)
            ));
            assert!(
                decide(
                    &binding(),
                    &invocation(3 - winner, 2),
                    &source(),
                    1110,
                    &committed.callback
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn sqlite_intent_collision_rolls_back_the_reservation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger.sqlite");
        let mut provider = Provider::create(&path)?;
        let fake = Reservation {
            binding: Digest::new(b"other"),
            callback: binding().callback,
            invocation: invocation(1, 9),
            reserved_at: 1000,
        };
        provider.db.execute(
            "INSERT INTO intent VALUES(?1,?2)",
            params![fake.invocation.id, serde_json::to_string(&fake)?],
        )?;
        assert!(
            provider
                .apply(&plan(1, 1, &initial())?, &source(), 1100, Cut::Known)
                .is_err()
        );
        assert_eq!(provider.rows()?.callback, initial());
        assert_eq!(provider.rows()?.intents.len(), 1);
        Ok(())
    }

    thread_local! { static PHASES: std::cell::RefCell<Vec<Cut>> = const { std::cell::RefCell::new(Vec::new()) }; }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
    enum Step {
        Prepare { id: u8, input: u8 },
        Apply { cut: Cut },
        Clock { at: i64 },
        Source { fault: u8 },
        Rewrite,
        Reopen,
        RestoreBefore,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Return {
        Prepared,
        Recovered,
        Refused,
        Applied,
        Uncertain,
        Changed,
        FixtureError,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct State {
        rows: Rows,
        pending: Option<Plan>,
        current: Current,
        at: i64,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Observation {
        actual: Option<State>,
        expected: State,
        returned: Return,
        expected_return: Return,
        phases: Vec<Cut>,
        expected_phases: Vec<Cut>,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Run {
        observations: Vec<Observation>,
        agrees: bool,
    }

    struct World {
        provider: Provider,
        path: PathBuf,
        before: PathBuf,
        pending: Option<Plan>,
        at: i64,
        fault: u8,
        epoch: u64,
        claim_epoch: u64,
    }
    impl World {
        fn current(&self) -> Current {
            let mut value = source();
            value.claim.security_epoch = self.epoch;
            value.claim.claim_epoch = self.claim_epoch;
            match self.fault {
                0 => {}
                1 => value.enabled = false,
                4 => value.claim.namespace.environment = name("other"),
                5 => value.claim.resource = Digest::new(b"run-two"),
                _ => unreachable!(),
            }
            value
        }
        fn step(&mut self, step: &Step) -> Result<Return> {
            PHASES.with(|p| p.borrow_mut().clear());
            Ok(match *step {
                Step::Prepare { id, input } => {
                    self.pending = None;
                    match decide(
                        &binding(),
                        &invocation(id, input),
                        &self.current(),
                        self.at,
                        &self.provider.rows()?.callback,
                    ) {
                        Ok(Decision::Reserve(p)) => {
                            self.pending = Some(*p);
                            Return::Prepared
                        }
                        Ok(Decision::Existing(_)) => Return::Recovered,
                        Err(_) => Return::Refused,
                    }
                }
                Step::Apply { cut } => {
                    if let Some(plan) = &self.pending {
                        let current = self.current();
                        if self.provider.apply(plan, &current, self.at, cut).is_ok() {
                            Return::Applied
                        } else if PHASES.with(|p| p.borrow().last() == Some(&cut))
                            && cut != Cut::Known
                        {
                            Return::Uncertain
                        } else {
                            Return::Refused
                        }
                    } else {
                        Return::Refused
                    }
                }
                Step::Clock { at } => {
                    self.at = at;
                    Return::Changed
                }
                Step::Source { fault } => {
                    match fault {
                        2 => {
                            self.epoch += 1;
                            self.fault = 0
                        }
                        3 => {
                            self.claim_epoch += 1;
                            self.fault = 0
                        }
                        _ => self.fault = fault,
                    };
                    Return::Changed
                }
                Step::Rewrite => {
                    let before = self.provider.rows()?.callback;
                    self.provider.db.execute(
                        "UPDATE callback SET version=?1 WHERE slot=1",
                        [before
                            .version
                            .checked_add(1)
                            .context("fixture version exhausted")?
                            .to_string()],
                    )?;
                    Return::Changed
                }
                Step::Reopen => {
                    self.provider = Provider::open(&self.path)?;
                    Return::Changed
                }
                Step::RestoreBefore => {
                    if self.epoch <= 7 {
                        return Ok(Return::Refused);
                    }
                    // SQLite backup API replaces the ledger, while the separately
                    // modelled current claim/epoch deliberately remains unchanged.
                    let mut replacement = Connection::open(&self.path)?;
                    let saved = Connection::open(&self.before)?;
                    let backup = rusqlite::backup::Backup::new(&saved, &mut replacement)?;
                    backup.run_to_completion(16, std::time::Duration::ZERO, None)?;
                    drop(backup);
                    self.provider = Provider::open(&self.path)?;
                    Return::Changed
                }
            })
        }
        fn state(&self) -> Result<State> {
            Ok(State {
                rows: self.provider.rows()?,
                pending: self.pending.clone(),
                current: self.current(),
                at: self.at,
            })
        }
    }

    /// Independent one-use state and planned version/time. This reference reads
    /// only the closed script, never the database, actual result or reducers.
    struct Model {
        version: u64,
        spent: Option<(u8, u8, i64)>,
        pending: Option<(u64, u8, u8, i64)>,
        at: i64,
        fault: u8,
        epoch: u64,
        claim_epoch: u64,
    }
    impl Model {
        fn new() -> Self {
            Self {
                version: 1,
                spent: None,
                pending: None,
                at: 1100,
                fault: 0,
                epoch: 7,
                claim_epoch: 3,
            }
        }
        fn fresh(&self) -> bool {
            self.fault == 0
                && self.epoch == 7
                && self.claim_epoch == 3
                && (1000..1300).contains(&self.at)
        }
        fn step(&mut self, step: &Step) -> (Return, Vec<Cut>) {
            let mut phases = vec![];
            let result = match *step {
                Step::Prepare { id, input } => {
                    self.pending = None;
                    if !self.fresh() {
                        Return::Refused
                    } else if let Some((accepted, data, at)) = self.spent {
                        if accepted == id && data == input && self.at >= at {
                            Return::Recovered
                        } else {
                            Return::Refused
                        }
                    } else {
                        self.pending = Some((self.version, id, input, self.at));
                        Return::Prepared
                    }
                }
                Step::Apply { cut } => {
                    if let Some((version, id, input, at)) = self.pending {
                        if self.fresh()
                            && self.at >= at
                            && self.version == version
                            && self.spent.is_none()
                        {
                            for phase in [
                                Cut::BeforeWrite,
                                Cut::AfterRecord,
                                Cut::AfterIntent,
                                Cut::AfterCommit,
                            ] {
                                phases.push(phase);
                                if phase == cut {
                                    break;
                                }
                            }
                            if matches!(cut, Cut::Known | Cut::AfterCommit) {
                                self.version += 1;
                                self.spent = Some((id, input, at));
                            }
                            if cut == Cut::Known {
                                Return::Applied
                            } else {
                                Return::Uncertain
                            }
                        } else {
                            Return::Refused
                        }
                    } else {
                        Return::Refused
                    }
                }
                Step::Clock { at } => {
                    self.at = at;
                    Return::Changed
                }
                Step::Source { fault } => {
                    match fault {
                        2 => {
                            self.epoch += 1;
                            self.fault = 0
                        }
                        3 => {
                            self.claim_epoch += 1;
                            self.fault = 0
                        }
                        _ => self.fault = fault,
                    };
                    Return::Changed
                }
                Step::Rewrite => {
                    self.version += 1;
                    Return::Changed
                }
                Step::Reopen => Return::Changed,
                Step::RestoreBefore => {
                    if self.epoch > 7 {
                        self.version = 1;
                        self.spent = None;
                        Return::Changed
                    } else {
                        Return::Refused
                    }
                }
            };
            (result, phases)
        }
        fn record(&self) -> Record {
            Record {
                binding: binding(),
                use_state: match self.spent {
                    None => Use::Unspent {},
                    Some((id, input, at)) => Use::Reserved {
                        invocation: invocation(id, input),
                        reserved_at: at,
                    },
                },
            }
        }
        fn state(&self) -> Result<State> {
            let mut intents = BTreeMap::new();
            if let Some((id, input, at)) = self.spent {
                let request = invocation(id, input);
                intents.insert(
                    request.id.clone(),
                    Reservation {
                        binding: Digest::of(&binding())?,
                        callback: binding().callback,
                        invocation: request,
                        reserved_at: at,
                    },
                );
            }
            let pending = self.pending.map(|(version, id, input, at)| Plan {
                before: Snapshot {
                    version,
                    record: Record {
                        binding: binding(),
                        use_state: Use::Unspent {},
                    },
                },
                after: Snapshot {
                    version: version + 1,
                    record: Record {
                        binding: binding(),
                        use_state: Use::Reserved {
                            invocation: invocation(id, input),
                            reserved_at: at,
                        },
                    },
                },
            });
            let mut current = source();
            current.claim.security_epoch = self.epoch;
            current.claim.claim_epoch = self.claim_epoch;
            match self.fault {
                0 => {}
                1 => current.enabled = false,
                4 => current.claim.namespace.environment = name("other"),
                5 => current.claim.resource = Digest::new(b"run-two"),
                _ => unreachable!(),
            }
            Ok(State {
                rows: Rows {
                    callback: Snapshot {
                        version: self.version,
                        record: self.record(),
                    },
                    intents,
                },
                pending,
                current,
                at: self.at,
            })
        }
    }

    fn validate_steps(steps: &[Step]) -> Result<()> {
        ensure!(
            !steps.is_empty() && steps.len() <= 64,
            "callback_history_bound"
        );
        for step in steps {
            match step {
                Step::Prepare { id, input } => ensure!(
                    (1..=4).contains(id) && (1..=4).contains(input),
                    "callback_history_request"
                ),
                Step::Clock { at } => ensure!((999..=1300).contains(at), "callback_history_clock"),
                Step::Source { fault } => ensure!(*fault <= 5, "callback_history_source"),
                _ => {}
            }
        }
        Ok(())
    }
    fn history(steps: &[Step], wrong_reference: bool) -> Result<Run> {
        validate_steps(steps)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger.sqlite");
        let before = dir.path().join("before.sqlite");
        let provider = Provider::create(&path)?;
        let mut backup = Connection::open(&before)?;
        rusqlite::backup::Backup::new(&provider.db, &mut backup)?.run_to_completion(
            16,
            std::time::Duration::ZERO,
            None,
        )?;
        drop(backup);
        let mut world = World {
            provider,
            path,
            before,
            pending: None,
            at: 1100,
            fault: 0,
            epoch: 7,
            claim_epoch: 3,
        };
        let mut model = Model::new();
        let mut observations = vec![];
        let mut agrees = true;
        for step in steps {
            let spent_before = model.spent;
            let (mut expected_return, expected_phases) = model.step(step);
            if wrong_reference
                && matches!(*step,Step::Prepare{id,..} if spent_before.is_some_and(|s|s.0!=id))
                && model.fresh()
            {
                expected_return = Return::Prepared;
            }
            let returned = world.step(step).unwrap_or(Return::FixtureError);
            let observation = Observation {
                actual: world.state().ok(),
                expected: model.state()?,
                returned,
                expected_return,
                phases: PHASES.with(|p| p.borrow().clone()),
                expected_phases,
            };
            agrees &= observation.actual.as_ref() == Some(&observation.expected)
                && returned == expected_return
                && observation.phases == observation.expected_phases;
            observations.push(observation);
            if !agrees {
                break;
            }
        }
        Ok(Run {
            observations,
            agrees,
        })
    }

    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Saved {
        format: u8,
        source: Digest,
        steps: Vec<Step>,
        wrong_reference: [bool; 2],
        runs: [Run; 2],
    }
    fn implementation() -> Result<Digest> {
        Digest::of(&(
            "day2-callback-reservation-ledger-v1",
            include_str!("callback.rs"),
            include_str!("../json.rs"),
            include_str!("../../../../Cargo.lock"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        ))
    }
    fn retain(steps: &[Step], wrong_reference: [bool; 2], runs: [Run; 2]) -> Result<PathBuf> {
        use std::io::Write;
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/credential-simulation");
        std::fs::create_dir_all(&root)?;
        let saved = Saved {
            format: 1,
            source: implementation()?,
            steps: steps.to_vec(),
            wrong_reference,
            runs,
        };
        let bytes = serde_json::to_vec(&saved)?;
        ensure!(bytes.len() <= 2 * 1024 * 1024, "callback_evidence_bound");
        let mut file = tempfile::Builder::new()
            .prefix("failure-callback-")
            .suffix(".json")
            .tempfile_in(root)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        Ok(file.keep()?.1)
    }
    fn replay(path: &Path) -> Result<()> {
        use std::io::Read;
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 2 * 1024 * 1024, "callback_evidence_bound");
        let saved: Saved =
            crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("callback_replay_decode"))?;
        ensure!(
            saved.format == 1 && saved.source == implementation()?,
            "callback_replay_source"
        );
        let actual = [
            history(&saved.steps, saved.wrong_reference[0])?,
            history(&saved.steps, saved.wrong_reference[1])?,
        ];
        ensure!(actual == saved.runs, "callback_replay_changed");
        Ok(())
    }
    #[test]
    fn seeded_histories_compare_complete_reservations_and_external_epoch_fences() -> Result<()> {
        for seed in 0u64..24 {
            let mut random = seed + 1;
            let initial_cut = [
                Cut::Known,
                Cut::BeforeWrite,
                Cut::AfterRecord,
                Cut::AfterIntent,
                Cut::AfterCommit,
            ][seed as usize % 5];
            let mut steps = vec![
                Step::Prepare { id: 1, input: 1 },
                Step::Apply { cut: initial_cut },
                Step::Reopen,
            ];
            let generated_start = steps.len();
            let mut generated_end = generated_start;
            for round in 0..40 {
                if round == 20 {
                    // Before irreversible fencing, ensure an initially rolled-back
                    // reservation actually enters a generated transaction. Clearing
                    // transient faults cannot lower the independent epoch.
                    steps.extend([
                        Step::Source { fault: 0 },
                        Step::Clock { at: 1100 },
                        Step::Prepare { id: 1, input: 1 },
                        Step::Apply {
                            cut: Cut::AfterRecord,
                        },
                    ]);
                    generated_end = steps.len();
                    steps.extend([
                        Step::Source { fault: 2 },
                        Step::RestoreBefore,
                        Step::Prepare { id: 1, input: 1 },
                    ]);
                }
                random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
                steps.push(match random % 7 {
                    0 => Step::Prepare {
                        id: 1 + ((random >> 32) % 4) as u8,
                        input: 1 + ((random >> 40) % 4) as u8,
                    },
                    1 => Step::Apply {
                        cut: [
                            Cut::Known,
                            Cut::BeforeWrite,
                            Cut::AfterRecord,
                            Cut::AfterIntent,
                            Cut::AfterCommit,
                        ][(random >> 32) as usize % 5],
                    },
                    2 => {
                        let fault = ((random >> 32) % 6) as u8;
                        Step::Source {
                            fault: if round < 20 && matches!(fault, 2 | 3) {
                                0
                            } else {
                                fault
                            },
                        }
                    }
                    3 => Step::Clock {
                        at: [999, 1099, 1100, 1150, 1299, 1300][(random >> 32) as usize % 6],
                    },
                    4 => Step::Rewrite,
                    5 => Step::Reopen,
                    _ => Step::RestoreBefore,
                });
            }
            let runs = [history(&steps, false)?, history(&steps, false)?];
            let needs_progress = matches!(
                initial_cut,
                Cut::BeforeWrite | Cut::AfterRecord | Cut::AfterIntent
            );
            let generated_progress = runs[0]
                .observations
                .get(generated_start..generated_end)
                .is_some_and(|window| window.iter().any(|o| o.phases.contains(&Cut::BeforeWrite)));
            if !runs[0].agrees
                || !runs[1].agrees
                || runs[0] != runs[1]
                || (needs_progress && !generated_progress)
            {
                let path = retain(&steps, [false, false], runs)?;
                anyhow::bail!("callback_history_divergence {}", path.display());
            }
        }
        Ok(())
    }
    #[test]
    fn fresh_identity_false_reference_is_retained_in_both_run_positions() -> Result<()> {
        let steps = vec![
            Step::Prepare { id: 1, input: 1 },
            Step::Apply { cut: Cut::Known },
            Step::Prepare { id: 2, input: 1 },
        ];
        for flags in [[true, false], [false, true], [true, true]] {
            let runs = [history(&steps, flags[0])?, history(&steps, flags[1])?];
            assert!(!runs[0].agrees || !runs[1].agrees);
            let path = retain(&steps, flags, runs)?;
            replay(&path)?;
            let original = std::fs::read(&path)?;
            let mut changed: serde_json::Value = crate::json::decode(&original)?;
            changed["runs"][1]["observations"][0]["returned"] = serde_json::json!("Recovered");
            std::fs::write(&path, serde_json::to_vec(&changed)?)?;
            assert!(replay(&path).is_err());
            std::fs::write(path, original)?;
        }
        Ok(())
    }
    #[test]
    fn saved_callback_reservation_replay() -> Result<()> {
        let Some(path) = std::env::var_os("DAY2_CALLBACK_LEDGER_REPLAY") else {
            return Ok(());
        };
        replay(Path::new(&path))
    }

    #[test]
    fn malformed_replay_values_cannot_enter_error_messages_or_causes() -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        use std::io::Write;
        for value in [
            b"PRIVATE_REPLAY_VALUE".as_slice(),
            br#"{"PRIVATE_REPLAY_VALUE":null}"#,
        ] {
            file.as_file_mut().set_len(0)?;
            std::io::Seek::rewind(file.as_file_mut())?;
            file.write_all(value)?;
            file.flush()?;
            let error = replay(file.path())
                .err()
                .context("malformed replay must refuse")?;
            ensure!(
                !error.to_string().contains("PRIVATE_REPLAY_VALUE")
                    && error.downcast_ref::<serde_json::Error>().is_none(),
                "callback_replay_private_error"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    thread_local! { static CHILD_CUT: std::cell::Cell<Option<Cut>> = const { std::cell::Cell::new(None) }; }
    #[cfg(unix)]
    const CHILD_ENV: &str = "DAY2_CALLBACK_LEDGER_CHILD";
    #[cfg(unix)]
    const CHILD_NAME: &str = "managed_credentials::callback::tests::callback_crash_child";
    #[cfg(unix)]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Child {
        format: u8,
        source: Digest,
        database: PathBuf,
        cut: Cut,
        behavior: ChildBehavior,
    }
    #[cfg(unix)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum ChildBehavior {
        Pause,
        Exit,
        Complete,
    }
    #[cfg(unix)]
    fn tag(cut: Cut) -> u8 {
        match cut {
            Cut::Known => 0,
            Cut::BeforeWrite => 1,
            Cut::AfterRecord => 2,
            Cut::AfterIntent => 3,
            Cut::AfterCommit => 4,
        }
    }
    #[cfg(unix)]
    fn marker(kind: u8, cut: Cut) -> [u8; 12] {
        let mut b = [0; 12];
        b[..8].copy_from_slice(b"D2CBUSE1");
        b[8] = kind;
        b[9] = tag(cut);
        b
    }
    #[cfg(unix)]
    fn child_pause(cut: Cut) -> Result<()> {
        use std::io::{Read, Write};
        std::io::stderr().write_all(&marker(1, cut))?;
        std::io::stderr().flush()?;
        if CHILD_EXIT.with(|v| v.get()) {
            std::process::exit(0)
        }
        let mut release = [0];
        std::io::stdin().read_exact(&mut release)?;
        anyhow::bail!("callback_child_released_without_death")
    }
    #[cfg(unix)]
    thread_local! { static CHILD_EXIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

    #[cfg(unix)]
    #[test]
    fn callback_crash_child() -> Result<()> {
        use std::io::{Read, Write};
        let Some(path) = std::env::var_os(CHILD_ENV) else {
            return Ok(());
        };
        let attempted = (|| -> Result<()> {
            let mut bytes = vec![];
            std::fs::File::open(path)?
                .take(4097)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 4096, "callback_child_input_bound");
            let child: Child = crate::json::decode(&bytes)?;
            ensure!(
                child.format == 1 && child.source == implementation()?,
                "callback_child_source"
            );
            let mut provider = Provider::open(&child.database)?;
            let requested = plan(1, 1, &provider.rows()?.callback)?;
            if !matches!(child.behavior, ChildBehavior::Complete) {
                CHILD_CUT.with(|v| v.set(Some(child.cut)));
            }
            CHILD_EXIT.with(|v| v.set(matches!(child.behavior, ChildBehavior::Exit)));
            provider.apply(&requested, &source(), 1100, Cut::Known)?;
            ensure!(
                matches!(child.behavior, ChildBehavior::Complete),
                "callback_checkpoint_missing"
            );
            std::io::stderr().write_all(&marker(2, Cut::Known))?;
            std::io::stderr().flush()?;
            Ok(())
        })();
        if attempted.is_err() {
            let _ = std::io::stderr().write_all(&marker(3, Cut::Known));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CrashObservation {
        cut: Cut,
        killed: bool,
        eof: bool,
        rows: Rows,
        expected: Rows,
        recovery: bool,
        fresh_identity: bool,
        newer_epoch: bool,
    }
    #[cfg(unix)]
    async fn crash(
        cut: Cut,
        behavior: ChildBehavior,
        trace: &mut CrashTrace,
    ) -> Result<CrashObservation> {
        use std::{io::Write, os::unix::process::ExitStatusExt, process::Stdio, time::Duration};
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger.sqlite");
        let provider = Provider::create(&path)?;
        drop(provider);
        let child = Child {
            format: 1,
            source: implementation()?,
            database: path.clone(),
            cut,
            behavior,
        };
        let mut config = tempfile::Builder::new()
            .prefix("child-")
            .tempfile_in(dir.path())?;
        config.write_all(&serde_json::to_vec(&child)?)?;
        config.as_file().sync_all()?;
        let mut process = tokio::process::Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, config.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        trace.progress.push(CrashStage::Spawned);
        let mut stderr = process.stderr.take().context("callback child stderr")?;
        let attempted: Result<CrashObservation> = async {
            let mut bytes = [0; 12];
            tokio::time::timeout(Duration::from_secs(30), stderr.read_exact(&mut bytes)).await??;
            let completion = matches!(behavior, ChildBehavior::Complete);
            ensure!(
                bytes
                    == marker(
                        if completion { 2 } else { 1 },
                        if completion { Cut::Known } else { cut }
                    ),
                "callback_child_marker"
            );
            trace.progress.push(CrashStage::MarkerVerified);
            // Only the parent-induced SIGKILL after an exact checkpoint counts.
            if matches!(behavior, ChildBehavior::Pause) {
                process.start_kill()?;
                trace.progress.push(CrashStage::KillSent);
            }
            let status = tokio::time::timeout(Duration::from_secs(30), process.wait()).await??;
            trace.exit = Some(ExitReport {
                success: status.success(),
                signal: status.signal(),
            });
            trace.progress.push(CrashStage::ChildClosed);
            let mut tail = vec![];
            tokio::time::timeout(
                Duration::from_secs(30),
                (&mut stderr).take(65).read_to_end(&mut tail),
            )
            .await??;
            ensure!(tail.is_empty(), "callback_child_trailing_output");
            trace.progress.push(CrashStage::PipeEof);
            let killed = status.signal() == Some(9);
            if completion {
                ensure!(status.success(), "callback_completion_child_failed");
            } else {
                ensure!(killed, "callback_child_not_killed_at_cut");
            }
            ensure!(tail.is_empty(), "callback_child_trailing_output");
            let reopened = Provider::open(&path)?;
            let rows = reopened.rows()?;
            trace.rows = Some(rows.clone());
            trace.progress.push(CrashStage::RowsRead);
            let committed = completion || cut == Cut::AfterCommit;
            let model = Model {
                version: if committed { 2 } else { 1 },
                spent: committed.then_some((1, 1, 1100)),
                pending: None,
                at: 1100,
                fault: 0,
                epoch: 7,
                claim_epoch: 3,
            };
            let expected = model.state()?.rows;
            let recovery = matches!(
                decide(
                    &binding(),
                    &invocation(1, 1),
                    &source(),
                    1110,
                    &rows.callback
                )?,
                Decision::Existing(_)
            );
            let fresh_identity = decide(
                &binding(),
                &invocation(2, 1),
                &source(),
                1110,
                &rows.callback,
            )
            .is_ok();
            let mut newer = source();
            newer.claim.security_epoch = 8;
            let newer_epoch =
                decide(&binding(), &invocation(1, 1), &newer, 1110, &rows.callback).is_ok();
            Ok(CrashObservation {
                cut,
                killed,
                eof: tail.is_empty(),
                rows,
                expected,
                recovery,
                fresh_identity,
                newer_epoch,
            })
        }
        .await;
        if attempted.is_err() {
            let _ = process.start_kill();
            trace.cleanup_closed = Some(
                tokio::time::timeout(Duration::from_secs(30), process.wait())
                    .await
                    .is_ok_and(|r| r.is_ok()),
            );
            if trace.rows.is_none() {
                trace.rows = Provider::open(&path).and_then(|p| p.rows()).ok();
            }
        }
        attempted
    }

    #[cfg(unix)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum CrashStage {
        Spawned,
        MarkerVerified,
        KillSent,
        ChildClosed,
        PipeEof,
        RowsRead,
    }
    #[cfg(unix)]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExitReport {
        success: bool,
        signal: Option<i32>,
    }
    #[cfg(unix)]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CrashTrace {
        progress: Vec<CrashStage>,
        exit: Option<ExitReport>,
        rows: Option<Rows>,
        cleanup_closed: Option<bool>,
    }
    #[cfg(unix)]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CrashRun {
        cut: Cut,
        behavior: ChildBehavior,
        trace: CrashTrace,
        observation: Option<CrashObservation>,
    }
    #[cfg(unix)]
    async fn capture_crash(cut: Cut, behavior: ChildBehavior) -> CrashRun {
        let mut trace = CrashTrace {
            progress: vec![],
            exit: None,
            rows: None,
            cleanup_closed: None,
        };
        let observation = crash(cut, behavior, &mut trace).await.ok();
        CrashRun {
            cut,
            behavior,
            trace,
            observation,
        }
    }
    #[cfg(unix)]
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CrashArchive {
        format: u8,
        source: Digest,
        runs: Vec<CrashRun>,
    }
    #[cfg(unix)]
    fn save_crash(runs: &[CrashRun]) -> Result<PathBuf> {
        use std::io::Write;
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/credential-simulation");
        std::fs::create_dir_all(&root)?;
        let mut file = tempfile::Builder::new()
            .prefix("failure-callback-crash-")
            .suffix(".json")
            .tempfile_in(root)?;
        let archive = CrashArchive {
            format: 1,
            source: implementation()?,
            runs: runs.to_vec(),
        };
        let bytes = serde_json::to_vec(&archive)?;
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "callback_crash_evidence_bound"
        );
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        Ok(file.keep()?.1)
    }
    #[cfg(unix)]
    async fn replay_crash(path: &Path) -> Result<()> {
        use std::io::Read;
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "callback_crash_evidence_bound"
        );
        let archive: CrashArchive = crate::json::decode(&bytes)
            .map_err(|_| anyhow::anyhow!("callback_crash_replay_decode"))?;
        ensure!(
            archive.format == 1
                && archive.source == implementation()?
                && (1..=2).contains(&archive.runs.len()),
            "callback_crash_replay_source"
        );
        for run in &archive.runs {
            ensure!(
                run.trace.progress.len() <= 6
                    && run.trace.cleanup_closed != Some(false)
                    && (!run.trace.progress.contains(&CrashStage::Spawned)
                        || run.observation.is_some()
                        || run.trace.cleanup_closed == Some(true)),
                "callback_crash_unresolved_cleanup"
            );
            ensure!(
                capture_crash(run.cut, run.behavior).await == *run,
                "callback_crash_replay_changed"
            );
        }
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn actual_child_death_cuts_reopen_as_one_atomic_reservation_and_intent() -> Result<()> {
        for cut in [
            Cut::BeforeWrite,
            Cut::AfterRecord,
            Cut::AfterIntent,
            Cut::AfterCommit,
        ] {
            let first = capture_crash(cut, ChildBehavior::Pause).await;
            let second = capture_crash(cut, ChildBehavior::Pause).await;
            let valid = first.observation.as_ref().is_some_and(|o| {
                o.rows == o.expected
                    && o.killed
                    && o.eof
                    && o.recovery == (cut == Cut::AfterCommit)
                    && o.fresh_identity != (cut == Cut::AfterCommit)
                    && !o.newer_epoch
            });
            if !valid || first != second {
                let path = save_crash(&[first, second])?;
                anyhow::bail!("callback_crash_divergence {}", path.display());
            }
        }
        let complete = capture_crash(Cut::Known, ChildBehavior::Complete).await;
        if !complete.observation.as_ref().is_some_and(|o| {
            o.rows == o.expected && o.recovery && !o.fresh_identity && !o.newer_epoch
        }) {
            let path = save_crash(&[complete])?;
            anyhow::bail!("callback_known_completion_failed {}", path.display());
        }
        let exit = capture_crash(Cut::AfterCommit, ChildBehavior::Exit).await;
        if !(exit.observation.is_none()
            && exit.trace.progress.contains(&CrashStage::MarkerVerified)
            && exit.trace.progress.contains(&CrashStage::PipeEof)
            && exit.trace.exit
                == Some(ExitReport {
                    success: true,
                    signal: None,
                })
            && exit.trace.cleanup_closed == Some(true))
        {
            let path = save_crash(&[exit])?;
            anyhow::bail!(
                "callback_normal_exit_cannot_count_as_crash {}",
                path.display()
            );
        }
        // Preserve/replay both full cut outcomes. This also exercises source and
        // evidence decoder on a real child cut, without claiming native proof.
        let pair = [
            capture_crash(Cut::AfterRecord, ChildBehavior::Pause).await,
            capture_crash(Cut::AfterRecord, ChildBehavior::Pause).await,
        ];
        let file = save_crash(&pair)?;
        replay_crash(&file).await?;
        let original = std::fs::read(&file)?;
        let mut wrong: serde_json::Value = crate::json::decode(&original)?;
        wrong["source"] = serde_json::json!(Digest::new(b"other source"));
        std::fs::write(&file, serde_json::to_vec(&wrong)?)?;
        assert!(replay_crash(&file).await.is_err());
        std::fs::write(file, original)?;
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn saved_callback_crash_replay() -> Result<()> {
        let Some(path) = std::env::var_os("DAY2_CALLBACK_LEDGER_CRASH_REPLAY") else {
            return Ok(());
        };
        replay_crash(Path::new(&path)).await
    }
}
