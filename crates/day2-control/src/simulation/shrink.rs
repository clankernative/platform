//! Bounded semantic reduction of typed histories, not a second property engine.
//! Proptest supplies histories and schedules. Only a reproducible, classified
//! failure enters this reducer; an unrelated failure is never an improvement.

use super::{
    Scenario, Trace,
    generation::{self, Program},
};
use crate::Digest;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureFingerprint {
    pub code: String,
    pub action: Option<String>,
}
impl FailureFingerprint {
    fn validate(&self) -> Result<()> {
        for value in std::iter::once(&self.code).chain(self.action.iter()) {
            ensure!(
                !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "invalid classified failure fingerprint"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ShrinkBudget(u32);
impl ShrinkBudget {
    pub fn new(evaluations: u32) -> Result<Self> {
        ensure!(
            (1..=4096).contains(&evaluations),
            "semantic shrink evaluation budget"
        );
        Ok(Self(evaluations))
    }
    pub fn evaluations(self) -> u32 {
        self.0
    }
}
impl Default for ShrinkBudget {
    fn default() -> Self {
        Self(64)
    }
}
impl TryFrom<u32> for ShrinkBudget {
    type Error = anyhow::Error;
    fn try_from(value: u32) -> Result<Self> {
        Self::new(value)
    }
}
impl From<ShrinkBudget> for u32 {
    fn from(value: ShrinkBudget) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShrinkReport {
    pub fingerprint: FailureFingerprint,
    pub program: Program,
    pub evaluations: u32,
    pub accepted: u32,
    /// Fixed point under the declared reductions, not a globally smallest trace.
    pub fixed_point: bool,
    pub budget_exhausted: bool,
}

/// The predicate must execute each candidate in isolated fresh state. Evaluation
/// errors are not counterexamples and abort reduction without changing its goal.
pub fn minimize(
    original: &Program,
    budget: ShrinkBudget,
    mut predicate: impl FnMut(&Program) -> Result<Option<FailureFingerprint>>,
) -> Result<ShrinkReport> {
    original.validate()?;
    generation::compile(original)?;
    let fingerprint = predicate(original)?
        .ok_or_else(|| anyhow::anyhow!("program has no classified counterexample"))?;
    fingerprint.validate()?;
    let mut report = ShrinkReport {
        fingerprint,
        program: original.clone(),
        evaluations: 1,
        accepted: 0,
        fixed_point: false,
        budget_exhausted: false,
    };
    let mut seen = BTreeSet::from([Digest::of(original)?]);
    'search: loop {
        if report.evaluations >= budget.0 {
            report.budget_exhausted = true;
            return Ok(report);
        }
        for history in [true, false] {
            let length = if history {
                report.program.intents.len()
            } else {
                report.program.schedule.len()
            };
            let mut width = length;
            while width > 0 {
                for start in (0..length).step_by(width) {
                    let end = (start + width).min(length);
                    let candidate = if history {
                        report.program.without_intents(start..end)?
                    } else {
                        let mut candidate = report.program.clone();
                        candidate.schedule.drain(start..end);
                        candidate
                    };
                    if try_candidate(candidate, &mut report, budget, &mut seen, &mut predicate)? {
                        continue 'search;
                    }
                    if report.budget_exhausted {
                        return Ok(report);
                    }
                }
                width /= 2;
            }
        }
        for index in 0..report.program.intents.len() {
            for simpler in report.program.intents[index].simplifications() {
                let mut candidate = report.program.clone();
                candidate.intents[index] = simpler;
                if try_candidate(candidate, &mut report, budget, &mut seen, &mut predicate)? {
                    continue 'search;
                }
                if report.budget_exhausted {
                    return Ok(report);
                }
            }
        }
        for index in 0..report.program.schedule.len() {
            for simpler in report.program.schedule[index].simplifications() {
                let mut candidate = report.program.clone();
                candidate.schedule[index] = simpler;
                if try_candidate(candidate, &mut report, budget, &mut seen, &mut predicate)? {
                    continue 'search;
                }
                if report.budget_exhausted {
                    return Ok(report);
                }
            }
        }
        report.fixed_point = true;
        return Ok(report);
    }
}

fn try_candidate(
    candidate: Program,
    report: &mut ShrinkReport,
    budget: ShrinkBudget,
    seen: &mut BTreeSet<Digest>,
    predicate: &mut impl FnMut(&Program) -> Result<Option<FailureFingerprint>>,
) -> Result<bool> {
    if candidate.validate().is_err()
        || generation::compile(&candidate).is_err()
        || !seen.insert(Digest::of(&candidate)?)
    {
        return Ok(false);
    }
    if report.evaluations >= budget.0 {
        report.budget_exhausted = true;
        return Ok(false);
    }
    report.evaluations += 1;
    if predicate(&candidate)?.as_ref() == Some(&report.fingerprint) {
        report.program = candidate;
        report.accepted += 1;
        return Ok(true);
    }
    Ok(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterexampleStatus {
    Invariant,
    Unclassified,
    ReplayDiverged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterexampleSummary {
    pub status: CounterexampleStatus,
    pub stage: FailureStage,
    pub fingerprint: Option<FailureFingerprint>,
    pub shrink: Option<ShrinkReport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    Compile,
    Execute,
    Replay,
    Classification,
    Shrink,
    MinimalReplay,
}

#[derive(Clone, Debug)]
pub struct PersistedCounterexample {
    pub directory: PathBuf,
    pub summary: CounterexampleSummary,
}

/// Runs the real simulator and exact replay. Failure bundles are private and
/// append-only by pathname: no existing regression file is overwritten. Raw host
/// error strings never enter the bundle; unavailable evidence stays unavailable.
pub fn check_and_persist(
    original: &Program,
    regression_root: &Path,
    budget: ShrinkBudget,
) -> Result<Option<PersistedCounterexample>> {
    let scenario = match generation::compile(original) {
        Ok(scenario) => scenario,
        Err(_) => {
            return persist(
                original,
                Evidence::default(),
                Evidence::default(),
                regression_root,
                summary(
                    CounterexampleStatus::Unclassified,
                    FailureStage::Compile,
                    None,
                    None,
                ),
            )
            .map(Some);
        }
    };
    let trace = match run_fresh(&scenario) {
        Ok(trace) => trace,
        Err(_) => {
            return persist(
                original,
                Evidence::scenario(&scenario),
                Evidence::default(),
                regression_root,
                summary(
                    CounterexampleStatus::Unclassified,
                    FailureStage::Execute,
                    None,
                    None,
                ),
            )
            .map(Some);
        }
    };
    let replay = run_fresh(&scenario);
    let evidence = Evidence {
        scenario: Some(&scenario),
        trace: Some(&trace),
        replay: replay.as_ref().ok(),
    };
    if !replay.as_ref().is_ok_and(|replay| replay == &trace) {
        return persist(
            original,
            evidence,
            Evidence::default(),
            regression_root,
            summary(
                CounterexampleStatus::ReplayDiverged,
                FailureStage::Replay,
                fingerprint(&trace)?,
                None,
            ),
        )
        .map(Some);
    }
    if trace.violation.is_none() {
        if trace.require_success().is_ok() {
            return Ok(None);
        }
        return persist(
            original,
            evidence,
            Evidence::default(),
            regression_root,
            summary(
                CounterexampleStatus::Unclassified,
                FailureStage::Classification,
                None,
                None,
            ),
        )
        .map(Some);
    }
    let Some(goal) = fingerprint(&trace)? else {
        return persist(
            original,
            evidence,
            Evidence::default(),
            regression_root,
            summary(
                CounterexampleStatus::Unclassified,
                FailureStage::Classification,
                None,
                None,
            ),
        )
        .map(Some);
    };
    let reduced = minimize(original, budget, |candidate| {
        let candidate_scenario = generation::compile(candidate)?;
        let trace = run_fresh(&candidate_scenario)?;
        fingerprint(&trace)
    });
    let report = match reduced {
        Ok(report) => report,
        Err(_) => {
            return persist(
                original,
                evidence,
                Evidence::default(),
                regression_root,
                summary(
                    CounterexampleStatus::Unclassified,
                    FailureStage::Shrink,
                    Some(goal),
                    None,
                ),
            )
            .map(Some);
        }
    };
    if report.fingerprint != goal {
        return persist(
            original,
            evidence,
            Evidence::default(),
            regression_root,
            summary(
                CounterexampleStatus::ReplayDiverged,
                FailureStage::Shrink,
                Some(goal),
                None,
            ),
        )
        .map(Some);
    }
    let minimal_scenario = generation::compile(&report.program)?;
    let minimal_trace = match run_fresh(&minimal_scenario) {
        Ok(trace) => trace,
        Err(_) => {
            return persist(
                original,
                evidence,
                Evidence::scenario(&minimal_scenario),
                regression_root,
                summary(
                    CounterexampleStatus::Unclassified,
                    FailureStage::MinimalReplay,
                    Some(goal),
                    Some(report),
                ),
            )
            .map(Some);
        }
    };
    let second = run_fresh(&minimal_scenario);
    let status = if !second.as_ref().is_ok_and(|second| second == &minimal_trace)
        || fingerprint(&minimal_trace)?.as_ref() != Some(&goal)
    {
        CounterexampleStatus::ReplayDiverged
    } else {
        CounterexampleStatus::Invariant
    };
    persist(
        original,
        evidence,
        Evidence {
            scenario: Some(&minimal_scenario),
            trace: Some(&minimal_trace),
            replay: second.as_ref().ok(),
        },
        regression_root,
        summary(
            status,
            FailureStage::MinimalReplay,
            Some(goal),
            Some(report),
        ),
    )
    .map(Some)
}

fn summary(
    status: CounterexampleStatus,
    stage: FailureStage,
    fingerprint: Option<FailureFingerprint>,
    shrink: Option<ShrinkReport>,
) -> CounterexampleSummary {
    CounterexampleSummary {
        status,
        stage,
        fingerprint,
        shrink,
    }
}

fn run_fresh(scenario: &Scenario) -> Result<Trace> {
    let directory = tempfile::tempdir()?;
    super::run(scenario, directory.path())
}

pub fn fingerprint(trace: &Trace) -> Result<Option<FailureFingerprint>> {
    classify(&trace.events, trace.violation.as_ref())
}

fn classify(
    events: &[super::Event],
    violation: Option<&super::Violation>,
) -> Result<Option<FailureFingerprint>> {
    let Some(violation) = violation else {
        return Ok(None);
    };
    // An action identifies where an unclassified host error occurred, not its
    // cause. Reducing such failures could silently replace the original defect.
    if violation.code == "unexpected_host_failure" {
        return Ok(None);
    }
    // Violation steps count completed events; event indices are zero-based.
    let action = violation
        .step
        .checked_sub(1)
        .and_then(|index| events.get(index as usize))
        .map(|event| serde_json::to_value(&event.action))
        .transpose()?
        .and_then(|value| {
            value
                .get("action")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    let fingerprint = FailureFingerprint {
        code: violation.code.clone(),
        action,
    };
    fingerprint.validate()?;
    Ok(Some(fingerprint))
}

#[derive(Clone, Copy, Default)]
struct Evidence<'a> {
    scenario: Option<&'a Scenario>,
    trace: Option<&'a Trace>,
    replay: Option<&'a Trace>,
}
impl<'a> Evidence<'a> {
    fn scenario(scenario: &'a Scenario) -> Self {
        Self {
            scenario: Some(scenario),
            ..Self::default()
        }
    }
}

fn persist(
    original: &Program,
    evidence: Evidence<'_>,
    minimal: Evidence<'_>,
    root: &Path,
    summary: CounterexampleSummary,
) -> Result<PersistedCounterexample> {
    fs::create_dir_all(root)?;
    let directory = tempfile::Builder::new()
        .prefix("counterexample-")
        .tempdir_in(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    }
    write_private(directory.path(), "original.program.json", original)?;
    if let Some(value) = evidence.scenario {
        write_private(directory.path(), "original.scenario.json", value)?;
    }
    if let Some(value) = evidence.trace {
        write_private(directory.path(), "original.trace.json", value)?;
    }
    if let Some(value) = evidence.replay {
        write_private(directory.path(), "original.replay.trace.json", value)?;
    }
    if let Some(value) = minimal.scenario {
        write_private(directory.path(), "minimal.scenario.json", value)?;
    }
    if let Some(value) = minimal.trace {
        write_private(directory.path(), "minimal.trace.json", value)?;
    }
    if let Some(value) = minimal.replay {
        write_private(directory.path(), "minimal.replay.trace.json", value)?;
    }
    if let Some(report) = &summary.shrink {
        write_private(directory.path(), "minimal.program.json", &report.program)?;
    }
    write_private(directory.path(), "summary.json", &summary)?;
    fs::File::open(directory.path())?.sync_all()?;
    Ok(PersistedCounterexample {
        directory: directory.keep(),
        summary,
    })
}

fn write_private(path: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= super::MAX_TRACE_BYTES * 2,
        "counterexample evidence byte budget"
    );
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path.join(name))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulation::{Action, Event, Violation};

    fn event(index: u32, action: Action) -> Event {
        Event {
            index,
            now: 0,
            action,
            outcome: "injected".into(),
            journal: Digest::new(b"journal"),
            provider: Digest::new(b"provider"),
            executions: Vec::new(),
            release_states: Vec::new(),
            release_executions: Vec::new(),
            release_mutations: 0,
            release_observations: 0,
            recovery: None,
            retirement: Default::default(),
        }
    }

    #[test]
    fn failure_steps_select_the_completed_event_not_the_following_event() -> Result<()> {
        let events = vec![event(0, Action::Restart {}), event(1, Action::Heal {})];
        for (step, action) in [(1, "restart"), (2, "heal")] {
            let classified = classify(
                &events,
                Some(&Violation {
                    step,
                    code: "fair_drain_exhausted".into(),
                }),
            )?;
            assert_eq!(classified.unwrap().action.as_deref(), Some(action));
        }
        for step in 0..=3 {
            assert_eq!(
                classify(
                    &events,
                    Some(&Violation {
                        step,
                        code: "unexpected_host_failure".into()
                    })
                )?,
                None
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_input_is_preserved_privately_without_fabricating_a_trace() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = Program {
            seed: 0,
            intents: Vec::new(),
            schedule: vec![generation::ScheduleChoice::Tick { millis: u32::MAX }],
        };
        let failure = check_and_persist(&program, root.path(), ShrinkBudget::new(1)?)?.unwrap();
        assert_eq!(failure.summary.status, CounterexampleStatus::Unclassified);
        assert_eq!(failure.summary.stage, FailureStage::Compile);
        assert!(!failure.directory.join("original.trace.json").exists());
        let input = failure.directory.join("original.program.json");
        assert_eq!(
            serde_json::from_slice::<Program>(&fs::read(&input)?)?,
            program
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&input)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                fs::metadata(&failure.directory)?.permissions().mode() & 0o777,
                0o700
            );
        }
        let second = check_and_persist(&program, root.path(), ShrinkBudget::new(1)?)?.unwrap();
        assert_ne!(failure.directory, second.directory);
        Ok(())
    }
}
