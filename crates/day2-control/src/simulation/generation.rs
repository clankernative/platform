//! Typed test inputs and scheduling guidance, not an alternative release recipe.
//!
//! The guidance model tracks submitted requests and attempted worker microsteps.
//! It never supplies expected host outcomes. The independent event oracle remains
//! responsible for safety and convergence. Entity identities are deliberately
//! bounded to six revisions across three applications in two companies.

use super::{Action, Fault, MAX_ACTIONS, ReadSelection, ReadStrength, Scenario};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, ops::Range};

pub const MAX_INTENTS: usize = 64;
const LEASE_MILLIS: u32 = 1_200_001;
// These are healthy-profile scheduling hints, never expected host outcomes.
// Actual transitions and activation must be witnessed by the independent oracle.
const BUILD_ATTEMPTS: u8 = 3;
const RELEASE_ATTEMPTS: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildId {
    First,
    Second,
    Independent,
    SecondAppFirst,
    SecondAppSecond,
    Third,
}

impl BuildId {
    pub const LEGACY: [Self; 3] = [Self::First, Self::Second, Self::Independent];
    pub const ALL: [Self; 6] = [
        Self::First,
        Self::Second,
        Self::Independent,
        Self::SecondAppFirst,
        Self::SecondAppSecond,
        Self::Third,
    ];

    pub fn index(self) -> u8 {
        match self {
            Self::First => 0,
            Self::Second => 1,
            Self::Independent => 2,
            Self::SecondAppFirst => 3,
            Self::SecondAppSecond => 4,
            Self::Third => 5,
        }
    }

    pub fn primary_version(self) -> Option<SecretVersionId> {
        match self {
            Self::First | Self::SecondAppFirst => Some(SecretVersionId::First),
            Self::Second | Self::SecondAppSecond => Some(SecretVersionId::Second),
            Self::Third => Some(SecretVersionId::Third),
            Self::Independent => None,
        }
    }

    fn predecessor(self) -> Option<Self> {
        match self {
            Self::Second => Some(Self::First),
            Self::SecondAppSecond => Some(Self::SecondAppFirst),
            Self::Third => Some(Self::Second),
            _ => None,
        }
    }

    fn supersedes(self, older: Self) -> bool {
        let mut predecessor = self.predecessor();
        while let Some(candidate) = predecessor {
            if candidate == older {
                return true;
            }
            predecessor = candidate.predecessor();
        }
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretVersionId {
    First,
    Second,
    Third,
}

impl SecretVersionId {
    pub const ALL: [Self; 3] = [Self::First, Self::Second, Self::Third];

    pub fn value(self) -> u8 {
        match self {
            Self::First => 1,
            Self::Second => 2,
            Self::Third => 3,
        }
    }

    fn index(self) -> usize {
        usize::from(self.value() - 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerId {
    First,
    Second,
    Third,
    Fourth,
}

impl WorkerId {
    pub const ALL: [Self; 4] = [Self::First, Self::Second, Self::Third, Self::Fourth];

    pub fn index(self) -> u8 {
        match self {
            Self::First => 0,
            Self::Second => 1,
            Self::Third => 2,
            Self::Fourth => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantId {
    Primary,
    Independent,
}

impl TenantId {
    fn index(self) -> u8 {
        match self {
            Self::Primary => 0,
            Self::Independent => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "attempt", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvalidAttempt {
    Isolation { build: BuildId, wrong_binding: bool },
    WrongApproval { build: BuildId, wrong_tenant: bool },
    PrematureStart { build: BuildId },
    PrematureRetirement { version: SecretVersionId },
    PrematureDrain { build: BuildId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
pub enum Intent {
    Submit {
        build: BuildId,
    },
    SubmitReplacement {
        build: BuildId,
    },
    Approve {
        build: BuildId,
    },
    StartRelease {
        build: BuildId,
    },
    Secret {
        build: BuildId,
        enabled: bool,
        access: bool,
        ready: bool,
        delay: u32,
    },
    DeliverSecret {
        build: BuildId,
    },
    CancelBuild {
        build: BuildId,
    },
    CancelRelease {
        build: BuildId,
    },
    RevokeRelease {
        build: BuildId,
    },
    RevokeAuthority {
        tenant: TenantId,
    },
    Binding {
        tenant: TenantId,
        revoked: bool,
    },
    Uncertain {
        build: BuildId,
        uncertain: bool,
    },
    Retire {
        version: SecretVersionId,
    },
    ReleaseRollback {
        build: BuildId,
    },
    Drain {
        build: BuildId,
    },
    Invalid {
        attempt: InvalidAttempt,
    },
}

impl Intent {
    fn build(&self) -> Option<BuildId> {
        match *self {
            Self::Submit { build }
            | Self::SubmitReplacement { build }
            | Self::Approve { build }
            | Self::StartRelease { build }
            | Self::Secret { build, .. }
            | Self::DeliverSecret { build }
            | Self::CancelBuild { build }
            | Self::CancelRelease { build }
            | Self::RevokeRelease { build }
            | Self::Uncertain { build, .. } => Some(build),
            Self::ReleaseRollback { build } | Self::Drain { build } => Some(build),
            _ => None,
        }
    }

    pub fn simplifications(&self) -> Vec<Self> {
        match *self {
            Self::Secret {
                build,
                enabled,
                access,
                ready,
                delay,
            } => {
                let mut result = Vec::new();
                if delay > 0 {
                    result.push(Self::Secret {
                        build,
                        enabled,
                        access,
                        ready,
                        delay: 0,
                    });
                }
                if !enabled {
                    result.push(Self::Secret {
                        build,
                        enabled: true,
                        access,
                        ready,
                        delay,
                    });
                }
                if !access {
                    result.push(Self::Secret {
                        build,
                        enabled,
                        access: true,
                        ready,
                        delay,
                    });
                }
                if !ready {
                    result.push(Self::Secret {
                        build,
                        enabled,
                        access,
                        ready: true,
                        delay,
                    });
                }
                result
            }
            Self::Uncertain {
                build,
                uncertain: true,
            } => {
                vec![Self::Uncertain {
                    build,
                    uncertain: false,
                }]
            }
            Self::Binding {
                tenant,
                revoked: true,
            } => {
                vec![Self::Binding {
                    tenant,
                    revoked: false,
                }]
            }
            Self::Invalid {
                attempt:
                    InvalidAttempt::Isolation {
                        build,
                        wrong_binding: true,
                    },
            } => {
                vec![Self::Invalid {
                    attempt: InvalidAttempt::Isolation {
                        build,
                        wrong_binding: false,
                    },
                }]
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "schedule", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScheduleChoice {
    Admit {
        selection: u8,
    },
    Work {
        worker: WorkerId,
        selection: u8,
        fault: Fault,
    },
    RetirementWork {
        version: SecretVersionId,
        worker: WorkerId,
        fault: Fault,
    },
    RetirementContend {
        version: SecretVersionId,
        worker: WorkerId,
    },
    QuiesceDeployment {
        build: BuildId,
        delay: u32,
    },
    SecretReadMode {
        version: SecretVersionId,
        selection: ReadSelection,
        strength: ReadStrength,
    },
    HoldRetirement {
        version: SecretVersionId,
    },
    DeliverRetirement {
        version: SecretVersionId,
    },
    ExternalSecretState {
        version: SecretVersionId,
        enabled: bool,
    },
    ObserveStoppedDeployment {
        build: BuildId,
    },
    ProbeDrain {
        build: BuildId,
    },
    RecreateDeployment {
        build: BuildId,
    },
    Contend {
        build: BuildId,
        worker: WorkerId,
    },
    DuplicateDelivery {
        worker: WorkerId,
    },
    Tick {
        millis: u32,
    },
    Restart {},
}

impl ScheduleChoice {
    pub fn simplifications(&self) -> Vec<Self> {
        match *self {
            Self::Admit { selection } if selection > 0 => vec![Self::Admit { selection: 0 }],
            Self::Work {
                worker,
                selection,
                fault,
            } => {
                let mut result = Vec::new();
                if fault != Fault::None {
                    result.push(Self::Work {
                        worker,
                        selection,
                        fault: Fault::None,
                    });
                }
                if selection > 0 {
                    result.push(Self::Work {
                        worker,
                        selection: 0,
                        fault,
                    });
                }
                if worker != WorkerId::First {
                    result.push(Self::Work {
                        worker: WorkerId::First,
                        selection,
                        fault,
                    });
                }
                result
            }
            Self::RetirementWork {
                version,
                worker,
                fault,
            } => {
                let mut result = Vec::new();
                if fault != Fault::None {
                    result.push(Self::RetirementWork {
                        version,
                        worker,
                        fault: Fault::None,
                    });
                }
                if worker != WorkerId::First {
                    result.push(Self::RetirementWork {
                        version,
                        worker: WorkerId::First,
                        fault,
                    });
                }
                result
            }
            Self::RetirementContend { version, worker } if worker != WorkerId::First => {
                vec![Self::RetirementContend {
                    version,
                    worker: WorkerId::First,
                }]
            }
            Self::Tick { millis } if millis > 0 => vec![Self::Tick { millis: 0 }],
            Self::QuiesceDeployment { build, delay } if delay > 0 => {
                vec![Self::QuiesceDeployment { build, delay: 0 }]
            }
            Self::SecretReadMode {
                version,
                selection,
                strength,
            } => {
                let mut result = Vec::new();
                if selection != ReadSelection::Current {
                    result.push(Self::SecretReadMode {
                        version,
                        selection: ReadSelection::Current,
                        strength,
                    });
                }
                if strength != ReadStrength::Qualified {
                    result.push(Self::SecretReadMode {
                        version,
                        selection,
                        strength: ReadStrength::Qualified,
                    });
                }
                result
            }
            Self::ExternalSecretState {
                version,
                enabled: false,
            } => vec![Self::ExternalSecretState {
                version,
                enabled: true,
            }],
            Self::Contend { build, worker } if worker != WorkerId::First => {
                vec![Self::Contend {
                    build,
                    worker: WorkerId::First,
                }]
            }
            Self::DuplicateDelivery { worker } if worker != WorkerId::First => {
                vec![Self::DuplicateDelivery {
                    worker: WorkerId::First,
                }]
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub seed: u64,
    pub intents: Vec<Intent>,
    pub schedule: Vec<ScheduleChoice>,
}

impl Program {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.intents.len() <= MAX_INTENTS,
            "generation intent budget"
        );
        ensure!(
            self.schedule.len() <= MAX_ACTIONS,
            "generation schedule budget"
        );
        ensure!(
            self.intents
                .iter()
                .filter(|intent| matches!(intent, Intent::Invalid { .. }))
                .count()
                <= 8,
            "generation negative lane budget"
        );
        for intent in &self.intents {
            if let Intent::SubmitReplacement { build } = intent {
                ensure!(
                    build.predecessor().is_some(),
                    "replacement generation requires an older revision"
                );
            }
            if let Intent::Secret { delay, .. } = intent {
                ensure!(*delay <= 4_000_000, "generation secret delay budget");
            }
        }
        for choice in &self.schedule {
            if let ScheduleChoice::QuiesceDeployment { delay, .. } = choice {
                ensure!(*delay <= 4_000_000, "generation quiescence delay budget");
            }
            if let ScheduleChoice::Tick { millis } = choice {
                ensure!(*millis <= 4_000_000, "generation clock budget");
            }
        }
        Ok(())
    }

    /// Stable entity references are never renumbered. Removing a positive
    /// prerequisite also removes its positive dependants, not explicit probes.
    pub fn without_intents(&self, range: Range<usize>) -> Result<Self> {
        ensure!(
            range.start <= range.end && range.end <= self.intents.len(),
            "generation removal range"
        );
        let mut result = self.clone();
        result.intents.drain(range);
        let submitted: BTreeSet<_> = result
            .intents
            .iter()
            .filter_map(|intent| {
                if let Intent::Submit { build } | Intent::SubmitReplacement { build } = intent {
                    Some(*build)
                } else {
                    None
                }
            })
            .collect();
        result.intents.retain(|intent| {
            intent
                .build()
                .is_none_or(|build| submitted.contains(&build))
        });
        loop {
            let declarations: BTreeSet<_> = result
                .intents
                .iter()
                .filter_map(|intent| match intent {
                    Intent::Submit { build } | Intent::SubmitReplacement { build } => Some(*build),
                    _ => None,
                })
                .collect();
            let before = result.intents.len();
            result.intents.retain(|intent| match intent {
                Intent::SubmitReplacement { build } => build
                    .predecessor()
                    .is_some_and(|previous| declarations.contains(&previous)),
                _ => intent
                    .build()
                    .is_none_or(|build| declarations.contains(&build)),
            });
            if before == result.intents.len() {
                break;
            }
        }
        let approved: BTreeSet<_> = result
            .intents
            .iter()
            .filter_map(|intent| {
                if let Intent::Approve { build } = intent {
                    Some(*build)
                } else {
                    None
                }
            })
            .collect();
        result.intents.retain(|intent| match intent {
            Intent::StartRelease { build }
            | Intent::Uncertain { build, .. }
            | Intent::CancelRelease { build }
            | Intent::RevokeRelease { build }
            | Intent::Drain { build }
            | Intent::ReleaseRollback { build } => approved.contains(build),
            _ => true,
        });
        let started: BTreeSet<_> = result
            .intents
            .iter()
            .filter_map(|intent| {
                if let Intent::StartRelease { build } = intent {
                    Some(*build)
                } else {
                    None
                }
            })
            .collect();
        let available: BTreeSet<_> = result
            .intents
            .iter()
            .filter_map(|intent| {
                if let Intent::Secret { build, .. } = intent {
                    build.primary_version()
                } else {
                    None
                }
            })
            .collect();
        result.intents.retain(|intent| match intent {
            Intent::Drain { build } | Intent::ReleaseRollback { build } => {
                started.contains(build)
                    && started.iter().any(|candidate| candidate.supersedes(*build))
            }
            Intent::Retire { version } => available.contains(version),
            _ => true,
        });
        let drained: BTreeSet<_> = result
            .intents
            .iter()
            .filter_map(|intent| {
                if let Intent::Drain { build } = intent {
                    Some(*build)
                } else {
                    None
                }
            })
            .collect();
        result.intents.retain(|intent| match intent {
            Intent::ReleaseRollback { build } => drained.contains(build),
            _ => true,
        });
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Request {
    declared: bool,
    release_declared: bool,
    submitted: bool,
    clean_build_rounds: u8,
    clean_release_rounds: u8,
    release_faulted: bool,
    approval_attempted: bool,
    release_attempted: bool,
    secret_available: bool,
    cancelled: bool,
    release_cancelled: bool,
    drain_attempted: bool,
    quiescence_attempted: bool,
    weak_stop_requested: bool,
    weak_stop_attempted: bool,
    weak_drain_attempted: bool,
    weak_recreate_attempted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Task {
    Build(BuildId),
    Release(BuildId),
    Retirement(SecretVersionId),
}

impl Task {
    fn build(self) -> Option<BuildId> {
        match self {
            Self::Build(build) | Self::Release(build) => Some(build),
            Self::Retirement(_) => None,
        }
    }

    fn claim(self, slot: u8) -> Action {
        match self {
            Self::Build(build) => Action::Claim {
                build: build.index(),
                slot,
            },
            Self::Release(build) => Action::ReleaseClaim {
                build: build.index(),
                slot,
            },
            Self::Retirement(version) => Action::RetirementClaim {
                version: version.value(),
                slot,
            },
        }
    }

    fn perform(self, slot: u8, fault: Fault) -> Action {
        match self {
            Self::Build(_) => Action::Perform { slot, fault },
            Self::Release(_) => Action::ReleasePerform { slot, fault },
            Self::Retirement(_) => Action::RetirementPerform { slot, fault },
        }
    }

    fn settle(self, slot: u8) -> Action {
        match self {
            Self::Build(_) => Action::Settle { slot },
            Self::Release(_) => Action::ReleaseSettle { slot },
            Self::Retirement(_) => Action::RetirementSettle { slot },
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Attempt {
    task: Task,
    performed: Option<Fault>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Version {
    declared_retirement: bool,
    available: bool,
    retirement_attempted: bool,
    clean_rounds: u8,
    hold_requested: bool,
    hold_attempted: bool,
    observed_read_requested: bool,
    opaque_read_requested: bool,
    read_stage: u8,
    read_round_started: u8,
    external_requested: bool,
    external_attempted: bool,
}

#[derive(Default)]
struct Guidance {
    requests: [Request; 6],
    versions: [Version; 3],
    workers: [Option<Attempt>; 4],
    completed: [Option<Task>; 4],
}

impl Guidance {
    fn new(program: &Program) -> Self {
        let mut model = Self::default();
        for intent in &program.intents {
            match intent {
                Intent::Submit { build } | Intent::SubmitReplacement { build } => {
                    model.requests[build.index() as usize].declared = true
                }
                Intent::Retire { version } => {
                    model.versions[version.index()].declared_retirement = true
                }
                Intent::StartRelease { build } => {
                    model.requests[build.index() as usize].release_declared = true
                }
                _ => {}
            }
        }
        for choice in &program.schedule {
            match choice {
                ScheduleChoice::HoldRetirement { version } => {
                    model.versions[version.index()].hold_requested = true
                }
                ScheduleChoice::SecretReadMode {
                    version, strength, ..
                } => {
                    let state = &mut model.versions[version.index()];
                    state.observed_read_requested |= strength == &ReadStrength::Observed;
                    state.opaque_read_requested |= strength == &ReadStrength::Opaque;
                }
                ScheduleChoice::ExternalSecretState { version, .. } => {
                    model.versions[version.index()].external_requested = true
                }
                ScheduleChoice::ObserveStoppedDeployment { build } => {
                    model.requests[build.index() as usize].weak_stop_requested = true
                }
                _ => {}
            }
        }
        model
    }

    fn replacement_attempted(&self, build: BuildId) -> bool {
        BuildId::ALL.into_iter().any(|candidate| {
            candidate.supersedes(build)
                && self.requests[candidate.index() as usize].clean_release_rounds
                    >= RELEASE_ATTEMPTS
        })
    }

    fn retirement_enabled(&self, version: SecretVersionId) -> bool {
        let state = self.versions[version.index()];
        state.available
            && (!state.hold_requested || state.hold_attempted)
            && (!state.observed_read_requested || state.read_stage > 0)
            && BuildId::ALL.into_iter().all(|build| {
                let request = self.requests[build.index() as usize];
                if !request.declared
                    || !request.release_declared
                    || build.primary_version() != Some(version)
                {
                    return true;
                }
                let successor_declared = BuildId::ALL.into_iter().any(|candidate| {
                    candidate.predecessor() == Some(build)
                        && self.requests[candidate.index() as usize].declared
                });
                if successor_declared {
                    self.replacement_attempted(build)
                } else {
                    request.clean_release_rounds >= RELEASE_ATTEMPTS
                }
            })
    }

    fn enabled(&self, intent: &Intent) -> bool {
        match *intent {
            Intent::Submit { build } => !self.requests[build.index() as usize].submitted,
            Intent::SubmitReplacement { build } => {
                !self.requests[build.index() as usize].submitted
                    && build.predecessor().is_some_and(|previous| {
                        let prior = self.requests[previous.index() as usize];
                        prior.declared && prior.clean_release_rounds >= RELEASE_ATTEMPTS
                    })
            }
            Intent::Approve { build } => {
                let request = self.requests[build.index() as usize];
                request.submitted
                    && request.clean_build_rounds >= BUILD_ATTEMPTS
                    && !request.cancelled
            }
            Intent::StartRelease { build }
            | Intent::Uncertain { build, .. }
            | Intent::CancelRelease { build }
            | Intent::RevokeRelease { build } => {
                self.requests[build.index() as usize].approval_attempted
            }
            Intent::Secret { build, .. } | Intent::CancelBuild { build } => {
                self.requests[build.index() as usize].submitted
            }
            Intent::DeliverSecret { build } => {
                self.requests[build.index() as usize].secret_available
            }
            Intent::Retire { version } => self.retirement_enabled(version),
            Intent::Drain { build } => {
                self.requests[build.index() as usize].release_attempted
                    && self.requests[build.index() as usize].quiescence_attempted
                    && self.replacement_attempted(build)
                    && build.primary_version().is_none_or(|version| {
                        let version = self.versions[version.index()];
                        !version.declared_retirement || version.clean_rounds > 0
                    })
            }
            Intent::ReleaseRollback { build } => {
                self.requests[build.index() as usize].drain_attempted
            }
            Intent::Invalid { ref attempt } => match *attempt {
                InvalidAttempt::Isolation { build, .. }
                | InvalidAttempt::WrongApproval { build, .. } => {
                    self.requests[build.index() as usize].submitted
                }
                InvalidAttempt::PrematureStart { .. } => true,
                InvalidAttempt::PrematureRetirement { version } => {
                    self.versions[version.index()].available
                }
                InvalidAttempt::PrematureDrain { build } => {
                    self.requests[build.index() as usize].approval_attempted
                }
            },
            Intent::RevokeAuthority { .. } | Intent::Binding { .. } => {
                self.requests.iter().any(|request| request.submitted)
            }
        }
    }

    fn admit(&mut self, intent: &Intent) -> Action {
        match *intent {
            Intent::Submit { build } | Intent::SubmitReplacement { build } => {
                self.requests[build.index() as usize].submitted = true;
                Action::Submit {
                    build: build.index(),
                }
            }
            Intent::Approve { build } => {
                self.requests[build.index() as usize].approval_attempted = true;
                Action::Approve {
                    build: build.index(),
                    wrong_commit: false,
                    wrong_tenant: false,
                }
            }
            Intent::StartRelease { build } => {
                self.requests[build.index() as usize].release_attempted = true;
                Action::ReleaseStart {
                    build: build.index(),
                }
            }
            Intent::Secret {
                build,
                enabled,
                access,
                ready,
                delay,
            } => {
                if let Some(version) = build.primary_version() {
                    self.versions[version.index()].available = true;
                    for alias in BuildId::ALL {
                        if alias.primary_version() == Some(version) {
                            self.requests[alias.index() as usize].secret_available = true;
                        }
                    }
                } else {
                    self.requests[build.index() as usize].secret_available = true;
                }
                Action::ReleaseSecret {
                    build: build.index(),
                    enabled,
                    access,
                    ready,
                    delay,
                }
            }
            Intent::DeliverSecret { build } => Action::ReleaseDeliverSecret {
                build: build.index(),
            },
            Intent::CancelBuild { build } => {
                self.requests[build.index() as usize].cancelled = true;
                Action::Cancel {
                    build: build.index(),
                }
            }
            Intent::CancelRelease { build } => {
                self.requests[build.index() as usize].release_cancelled = true;
                Action::ReleaseCancel {
                    build: build.index(),
                }
            }
            Intent::RevokeRelease { build } => {
                self.requests[build.index() as usize].release_cancelled = true;
                Action::RevokeRelease {
                    build: build.index(),
                }
            }
            Intent::RevokeAuthority { tenant } => Action::RevokeAuthority {
                tenant: tenant.index(),
            },
            Intent::Binding { tenant, revoked } => Action::Binding {
                tenant: tenant.index(),
                revoked,
            },
            Intent::Uncertain { build, uncertain } => Action::ReleaseUncertain {
                build: build.index(),
                uncertain,
            },
            Intent::Retire { version } => {
                self.versions[version.index()].retirement_attempted = true;
                Action::RetireSecret {
                    version: version.value(),
                }
            }
            Intent::Drain { build } => {
                self.requests[build.index() as usize].drain_attempted = true;
                Action::ReleaseDrain {
                    build: build.index(),
                }
            }
            Intent::ReleaseRollback { build } => Action::ReleaseRollback {
                build: build.index(),
            },
            Intent::Invalid { ref attempt } => match *attempt {
                InvalidAttempt::Isolation {
                    build,
                    wrong_binding,
                } => Action::ProbeIsolation {
                    build: build.index(),
                    wrong_binding,
                },
                InvalidAttempt::WrongApproval {
                    build,
                    wrong_tenant,
                } => Action::Approve {
                    build: build.index(),
                    wrong_commit: !wrong_tenant,
                    wrong_tenant,
                },
                InvalidAttempt::PrematureStart { build } => Action::ReleaseStart {
                    build: build.index(),
                },
                InvalidAttempt::PrematureRetirement { version } => {
                    self.versions[version.index()].retirement_attempted = true;
                    Action::RetireSecret {
                        version: version.value(),
                    }
                }
                InvalidAttempt::PrematureDrain { build } => Action::ReleaseDrain {
                    build: build.index(),
                },
            },
        }
    }

    fn work(&mut self, worker: WorkerId, selection: u8, fault: Fault) -> Option<Action> {
        let slot = worker.index();
        if let Some(attempt) = self.workers[slot as usize] {
            return Some(self.advance(slot, attempt, fault));
        }
        let candidates: Vec<_> = BuildId::ALL
            .into_iter()
            .filter_map(|build| {
                let request = self.requests[build.index() as usize];
                let task = if request.release_attempted
                    && !request.release_cancelled
                    && (request.clean_release_rounds <= RELEASE_ATTEMPTS || request.release_faulted)
                {
                    Some(Task::Release(build))
                } else if request.submitted
                    && !request.cancelled
                    && request.clean_build_rounds < BUILD_ATTEMPTS
                {
                    Some(Task::Build(build))
                } else {
                    None
                }?;
                (!self
                    .workers
                    .iter()
                    .flatten()
                    .any(|attempt| attempt.task == task))
                .then_some(task)
            })
            .collect();
        if !candidates.is_empty() {
            let task = candidates[selection as usize % candidates.len()];
            self.completed[slot as usize] = None;
            self.workers[slot as usize] = Some(Attempt {
                task,
                performed: None,
            });
            return Some(task.claim(slot));
        }
        let pending: Vec<_> = self
            .workers
            .iter()
            .enumerate()
            .filter_map(|(index, attempt)| attempt.map(|attempt| (index, attempt)))
            .collect();
        if pending.is_empty() {
            return None;
        }
        let (index, attempt) = pending[selection as usize % pending.len()];
        Some(self.advance(index as u8, attempt, fault))
    }

    fn advance(&mut self, slot: u8, attempt: Attempt, fault: Fault) -> Action {
        match attempt.performed {
            None => {
                self.workers[slot as usize] = Some(Attempt {
                    performed: Some(fault),
                    ..attempt
                });
                if fault != Fault::None
                    && let Task::Release(build) = attempt.task
                {
                    self.requests[build.index() as usize].release_faulted = true;
                }
                attempt.task.perform(slot, fault)
            }
            Some(previous) => {
                self.workers[slot as usize] = None;
                self.completed[slot as usize] = Some(attempt.task);
                if previous == Fault::None {
                    match attempt.task {
                        Task::Build(build) => {
                            let request = &mut self.requests[build.index() as usize];
                            request.clean_build_rounds =
                                request.clean_build_rounds.saturating_add(1);
                        }
                        Task::Release(build) => {
                            let request = &mut self.requests[build.index() as usize];
                            if request.secret_available {
                                request.clean_release_rounds =
                                    request.clean_release_rounds.saturating_add(1);
                            }
                        }
                        Task::Retirement(version) => {
                            let version = &mut self.versions[version.index()];
                            version.clean_rounds = version.clean_rounds.saturating_add(1);
                        }
                    }
                }
                attempt.task.settle(slot)
            }
        }
    }

    fn contend(&mut self, build: BuildId, worker: WorkerId) -> Option<Action> {
        let task = self
            .workers
            .iter()
            .flatten()
            .find(|attempt| attempt.task.build() == Some(build))?
            .task;
        self.contend_task(task, worker)
    }

    fn contend_task(&mut self, task: Task, worker: WorkerId) -> Option<Action> {
        if !self
            .workers
            .iter()
            .flatten()
            .any(|attempt| attempt.task == task)
        {
            return None;
        }
        let preferred = worker.index() as usize;
        let slot = if self.workers[preferred].is_none() {
            preferred
        } else {
            self.workers.iter().position(Option::is_none)?
        };
        self.completed[slot] = None;
        Some(task.claim(slot as u8))
    }

    fn retirement_work(
        &mut self,
        version: SecretVersionId,
        worker: WorkerId,
        fault: Fault,
    ) -> Option<Action> {
        if let Some((slot, attempt)) =
            self.workers.iter().enumerate().find_map(|(slot, attempt)| {
                attempt
                    .filter(|attempt| attempt.task == Task::Retirement(version))
                    .map(|attempt| (slot, attempt))
            })
        {
            return Some(self.advance(slot as u8, attempt, fault));
        }
        if !self.versions[version.index()].retirement_attempted {
            return None;
        }
        let preferred = worker.index() as usize;
        let slot = if self.workers[preferred].is_none() {
            preferred
        } else {
            self.workers.iter().position(Option::is_none)?
        };
        let task = Task::Retirement(version);
        self.completed[slot] = None;
        self.workers[slot] = Some(Attempt {
            task,
            performed: None,
        });
        Some(task.claim(slot as u8))
    }

    fn duplicate(&self, worker: WorkerId) -> Option<Action> {
        let slot = worker.index();
        self.completed[slot as usize].map(|task| task.settle(slot))
    }

    fn quiesce(&mut self, build: BuildId, delay: u32) -> Option<Action> {
        let request = self.requests[build.index() as usize];
        if !request.release_attempted
            || !self.replacement_attempted(build)
            || (request.weak_stop_requested && !request.weak_recreate_attempted)
        {
            return None;
        }
        // Guidance records attempts, not host acceptance. Retry after an early
        // refusal; the provider deduplicates an already-quiesced deployment.
        self.requests[build.index() as usize].quiescence_attempted = true;
        Some(Action::QuiesceDeployment {
            build: build.index(),
            delay,
        })
    }

    fn weak_choice(&mut self, choice: &ScheduleChoice) -> Option<Action> {
        match *choice {
            ScheduleChoice::SecretReadMode {
                version,
                selection,
                strength,
            } => {
                // Keep a fault installed for a complete attempt that begins
                // after installation; settling an older read is not exposure.
                if self
                    .workers
                    .iter()
                    .flatten()
                    .any(|attempt| attempt.task == Task::Retirement(version))
                {
                    return None;
                }
                let state = &mut self.versions[version.index()];
                if !state.available {
                    return None;
                }
                let stage = if strength == ReadStrength::Qualified {
                    3
                } else if strength == ReadStrength::Opaque {
                    2
                } else {
                    1
                };
                if stage <= state.read_stage
                    || (stage == 2
                        && state.observed_read_requested
                        && (state.read_stage != 1 || state.clean_rounds < 3))
                    || (stage == 3 && state.opaque_read_requested && state.read_stage != 2)
                    || (stage == 3
                        && (state.observed_read_requested || state.opaque_read_requested)
                        && (state.clean_rounds < 3
                            || state.clean_rounds <= state.read_round_started))
                {
                    return None;
                }
                state.read_stage = stage;
                state.read_round_started = state.clean_rounds;
                Some(Action::SecretReadMode {
                    version: version.value(),
                    selection,
                    strength,
                })
            }
            ScheduleChoice::HoldRetirement { version } => {
                let state = &mut self.versions[version.index()];
                if !state.available || state.hold_attempted {
                    return None;
                }
                state.hold_attempted = true;
                Some(Action::HoldRetirement {
                    version: version.value(),
                })
            }
            ScheduleChoice::DeliverRetirement { version } => {
                let state = self.versions[version.index()];
                if state.clean_rounds < 3 || (state.external_requested && !state.external_attempted)
                {
                    return None;
                }
                Some(Action::DeliverRetirement {
                    version: version.value(),
                })
            }
            ScheduleChoice::ExternalSecretState { version, enabled } => {
                let state = &mut self.versions[version.index()];
                if !state.retirement_attempted || state.clean_rounds < 3 || state.external_attempted
                {
                    return None;
                }
                state.external_attempted = true;
                Some(Action::ExternalSecretState {
                    version: version.value(),
                    enabled,
                })
            }
            ScheduleChoice::ObserveStoppedDeployment { build } => {
                let request = self.requests[build.index() as usize];
                if !request.release_attempted
                    || !self.replacement_attempted(build)
                    || request.weak_recreate_attempted
                {
                    return None;
                }
                self.requests[build.index() as usize].weak_stop_attempted = true;
                Some(Action::ObserveStoppedDeployment {
                    build: build.index(),
                })
            }
            ScheduleChoice::ProbeDrain { build } => {
                let request = &mut self.requests[build.index() as usize];
                if !request.weak_stop_attempted || request.weak_recreate_attempted {
                    return None;
                }
                request.weak_drain_attempted = true;
                Some(Action::ReleaseDrain {
                    build: build.index(),
                })
            }
            ScheduleChoice::RecreateDeployment { build } => {
                let request = &mut self.requests[build.index() as usize];
                if !request.weak_drain_attempted {
                    return None;
                }
                request.weak_recreate_attempted = true;
                Some(Action::RecreateDeployment {
                    build: build.index(),
                })
            }
            _ => None,
        }
    }
}

/// Compiles independent intent and worker streams without executing the host.
/// Guidance avoids empty workers; it is optimistic about acknowledged attempts,
/// so refusals and unknown results are still checked by the runtime oracle.
pub fn compile(program: &Program) -> Result<Scenario> {
    program.validate()?;
    let mut guidance = Guidance::new(program);
    let mut remaining: Vec<_> = program.intents.iter().collect();
    let mut actions = Vec::new();
    for choice in &program.schedule {
        let mut admit = |guidance: &mut Guidance, selection: u8| {
            let enabled: Vec<_> = remaining
                .iter()
                .enumerate()
                .filter_map(|(index, intent)| guidance.enabled(intent).then_some(index))
                .collect();
            if enabled.is_empty() {
                return None;
            }
            let selected = enabled[selection as usize % enabled.len()];
            let intent = remaining.remove(selected);
            Some(guidance.admit(intent))
        };
        let action = match *choice {
            ScheduleChoice::Admit { selection } => admit(&mut guidance, selection).or_else(|| {
                guidance.work(
                    WorkerId::ALL[selection as usize % 4],
                    selection,
                    Fault::None,
                )
            }),
            ScheduleChoice::Work {
                worker,
                selection,
                fault,
            } => guidance
                .work(worker, selection, fault)
                .or_else(|| admit(&mut guidance, selection)),
            ScheduleChoice::RetirementWork {
                version,
                worker,
                fault,
            } => guidance
                .retirement_work(version, worker, fault)
                .or_else(|| admit(&mut guidance, version.value()))
                .or_else(|| guidance.work(worker, version.value(), Fault::None)),
            ScheduleChoice::RetirementContend { version, worker } => {
                guidance.contend_task(Task::Retirement(version), worker)
            }
            ScheduleChoice::QuiesceDeployment { build, delay } => guidance.quiesce(build, delay),
            ScheduleChoice::SecretReadMode { version, .. }
            | ScheduleChoice::HoldRetirement { version }
            | ScheduleChoice::DeliverRetirement { version }
            | ScheduleChoice::ExternalSecretState { version, .. } => guidance
                .weak_choice(choice)
                .or_else(|| admit(&mut guidance, version.value()))
                .or_else(|| {
                    guidance.work(WorkerId::ALL[version.index()], version.value(), Fault::None)
                }),
            ScheduleChoice::ObserveStoppedDeployment { build }
            | ScheduleChoice::ProbeDrain { build }
            | ScheduleChoice::RecreateDeployment { build } => guidance
                .weak_choice(choice)
                // A not-yet-eligible fault is a chance to advance prerequisites,
                // not a discarded scheduler slot that starves its own rollout.
                .or_else(|| admit(&mut guidance, build.index()))
                .or_else(|| {
                    guidance.work(
                        WorkerId::ALL[build.index() as usize % 4],
                        build.index(),
                        Fault::None,
                    )
                }),
            ScheduleChoice::Contend { build, worker } => guidance.contend(build, worker),
            ScheduleChoice::DuplicateDelivery { worker } => guidance.duplicate(worker),
            ScheduleChoice::Tick { millis } => Some(Action::Tick { millis }),
            ScheduleChoice::Restart {} => {
                for request in &mut guidance.requests {
                    if request.release_attempted {
                        request.release_faulted = true;
                    }
                }
                guidance.workers = [None; 4];
                guidance.completed = [None; 4];
                Some(Action::Restart {})
            }
        };
        if let Some(action) = action {
            actions.push(action);
        }
    }
    let scenario = Scenario {
        format: 4,
        seed: program.seed,
        actions,
    };
    scenario.validate()?;
    Ok(scenario)
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }
}

fn weak_program(seed: u64, case: u32, mixed: u64) -> Result<Program> {
    let mut intents_random = Random(mixed ^ 0x81904b39dca17e21);
    let mut schedule_random = Random(mixed ^ 0x7cf29ed85a036bb4);
    let version = SecretVersionId::Third;
    // This unused immutable version isolates evidence weakness from consumer
    // availability. The controller profile also has a real competing rollout.
    let mut intents = vec![
        Intent::Submit {
            build: BuildId::Third,
        },
        Intent::Secret {
            build: BuildId::Third,
            enabled: true,
            access: true,
            ready: true,
            delay: 0,
        },
        Intent::Retire { version },
    ];
    if case % 8 == 6 {
        for build in [BuildId::First, BuildId::Second] {
            intents.extend([
                if build == BuildId::First {
                    Intent::Submit { build }
                } else {
                    Intent::SubmitReplacement { build }
                },
                Intent::Secret {
                    build,
                    enabled: true,
                    access: true,
                    ready: true,
                    delay: 0,
                },
                Intent::Approve { build },
                Intent::StartRelease { build },
            ]);
        }
        intents.extend([
            Intent::Drain {
                build: BuildId::First,
            },
            Intent::ReleaseRollback {
                build: BuildId::First,
            },
        ]);
    }
    for index in (1..intents.len()).rev() {
        intents.swap(index, (intents_random.next() % (index as u64 + 1)) as usize);
    }
    let mut schedule = Vec::new();
    for _ in 0..MAX_ACTIONS {
        let selection = schedule_random.next() as u8;
        let worker = WorkerId::ALL[schedule_random.next() as usize % 4];
        let draw = schedule_random.next() % 32;
        schedule.push(match draw {
            0..=4 => ScheduleChoice::Admit { selection },
            5..=8 => ScheduleChoice::Tick { millis: 100 },
            9..=12 => match case % 8 {
                2 => match selection % 3 {
                    0 => ScheduleChoice::SecretReadMode {
                        version,
                        selection: ReadSelection::Previous,
                        strength: ReadStrength::Observed,
                    },
                    1 => ScheduleChoice::SecretReadMode {
                        version,
                        selection: ReadSelection::Current,
                        strength: ReadStrength::Opaque,
                    },
                    _ => ScheduleChoice::SecretReadMode {
                        version,
                        selection: ReadSelection::Current,
                        strength: ReadStrength::Qualified,
                    },
                },
                _ => match selection % 3 {
                    0 => ScheduleChoice::HoldRetirement { version },
                    1 if case % 8 == 6 => ScheduleChoice::ExternalSecretState {
                        version,
                        enabled: false,
                    },
                    _ => ScheduleChoice::DeliverRetirement { version },
                },
            },
            13..=18 if case % 8 == 6 => match selection % 4 {
                0 => ScheduleChoice::ObserveStoppedDeployment {
                    build: BuildId::First,
                },
                1 => ScheduleChoice::ProbeDrain {
                    build: BuildId::First,
                },
                2 => ScheduleChoice::RecreateDeployment {
                    build: BuildId::First,
                },
                _ => ScheduleChoice::QuiesceDeployment {
                    build: BuildId::First,
                    delay: 0,
                },
            },
            19..=24 => ScheduleChoice::Work {
                worker,
                selection,
                fault: Fault::None,
            },
            _ => ScheduleChoice::RetirementWork {
                version,
                worker,
                fault: Fault::None,
            },
        });
    }
    let program = Program {
        seed,
        intents,
        schedule,
    };
    program.validate()?;
    Ok(program)
}

pub fn program(seed: u64, case: u32) -> Result<Program> {
    ensure!(case < 128, "simulation case budget");
    let mixed = seed ^ u64::from(case).wrapping_mul(0xd1342543de82ef95);
    if matches!(case % 8, 2 | 3 | 6) {
        return weak_program(seed, case, mixed);
    }
    let mut intents_random = Random(mixed ^ 0x81904b39dca17e21);
    let mut scheduler_random = Random(mixed ^ 0x7cf29ed85a036bb4);
    let rollover = case % 4 < 2;
    let healthy = case.is_multiple_of(4);
    let count = if rollover {
        5
    } else if case.is_multiple_of(2) {
        6
    } else {
        1 + (intents_random.next() % 6) as usize
    };
    let mut builds = if rollover {
        [
            BuildId::First,
            BuildId::SecondAppFirst,
            BuildId::Second,
            BuildId::SecondAppSecond,
            BuildId::Independent,
            BuildId::Third,
        ]
    } else {
        BuildId::ALL
    };
    for index in (1..count).rev() {
        builds.swap(index, (intents_random.next() % (index as u64 + 1)) as usize);
    }
    let mut intents = Vec::new();
    for (position, &build) in builds.iter().take(count).enumerate() {
        intents.extend([
            if rollover && build.predecessor().is_some() {
                Intent::SubmitReplacement { build }
            } else {
                Intent::Submit { build }
            },
            Intent::Approve { build },
            Intent::StartRelease { build },
            Intent::Secret {
                build,
                enabled: true,
                access: true,
                ready: true,
                delay: 0,
            },
            Intent::DeliverSecret { build },
        ]);
        if position < 3 {
            intents.push(Intent::Invalid {
                attempt: InvalidAttempt::Isolation {
                    build,
                    wrong_binding: intents_random.next().is_multiple_of(2),
                },
            });
        }
        if !rollover && position < 2 {
            intents.extend([
                Intent::Approve { build },
                Intent::StartRelease { build },
                Intent::Secret {
                    build,
                    enabled: intents_random.next().is_multiple_of(2),
                    access: intents_random.next().is_multiple_of(2),
                    ready: true,
                    delay: LEASE_MILLIS,
                },
                Intent::DeliverSecret { build },
            ]);
        }
    }
    if rollover {
        intents.extend([
            Intent::Retire {
                version: SecretVersionId::First,
            },
            Intent::Drain {
                build: BuildId::First,
            },
            Intent::Drain {
                build: BuildId::SecondAppFirst,
            },
            Intent::ReleaseRollback {
                build: BuildId::First,
            },
            Intent::ReleaseRollback {
                build: BuildId::SecondAppFirst,
            },
        ]);
    } else {
        let build = builds[0];
        intents.push(Intent::Invalid {
            attempt: InvalidAttempt::WrongApproval {
                build,
                wrong_tenant: intents_random.next().is_multiple_of(2),
            },
        });
        intents.push(Intent::Invalid {
            attempt: InvalidAttempt::PrematureStart { build },
        });
        intents.push(Intent::Invalid {
            attempt: InvalidAttempt::PrematureRetirement {
                version: SecretVersionId::ALL[(intents_random.next() % 3) as usize],
            },
        });
        intents.push(Intent::Invalid {
            attempt: InvalidAttempt::PrematureDrain { build },
        });
        intents.push(Intent::Retire {
            version: SecretVersionId::First,
        });
        for build in [BuildId::First, BuildId::SecondAppFirst, BuildId::Second] {
            if builds[..count].contains(&build) {
                intents.push(Intent::Drain { build });
                intents.push(Intent::ReleaseRollback { build });
            }
        }
        match case % 4 {
            2 => {
                intents.push(if intents_random.next().is_multiple_of(2) {
                    Intent::CancelRelease { build }
                } else {
                    Intent::RevokeRelease { build }
                });
                intents.push(Intent::CancelBuild { build: builds[1] });
            }
            _ => {
                intents.push(Intent::RevokeAuthority {
                    tenant: TenantId::Primary,
                });
                intents.push(Intent::Binding {
                    tenant: TenantId::Primary,
                    revoked: true,
                });
                intents.push(Intent::Binding {
                    tenant: TenantId::Primary,
                    revoked: false,
                });
            }
        }
    }
    let mut schedule = Vec::new();
    for _ in 0..MAX_ACTIONS {
        let selection = scheduler_random.next() as u8;
        let worker = WorkerId::ALL[(scheduler_random.next() % 4) as usize];
        let draw = scheduler_random.next() % 32;
        schedule.push(if draw < 8 {
            ScheduleChoice::Admit { selection }
        } else if !rollover && draw == 8 {
            ScheduleChoice::Restart {}
        } else if !rollover && draw < 11 {
            ScheduleChoice::Tick {
                millis: LEASE_MILLIS,
            }
        } else if !rollover && draw == 11 {
            ScheduleChoice::Contend {
                build: builds[selection as usize % count],
                worker,
            }
        } else if !rollover && draw == 12 {
            ScheduleChoice::DuplicateDelivery { worker }
        } else if draw < 20 {
            let version = if rollover {
                SecretVersionId::First
            } else {
                SecretVersionId::ALL[selection as usize % 3]
            };
            let fault = if healthy || !scheduler_random.next().is_multiple_of(3) {
                Fault::None
            } else {
                Fault::LostAck
            };
            ScheduleChoice::RetirementWork {
                version,
                worker,
                fault,
            }
        } else if !rollover && draw == 20 {
            ScheduleChoice::RetirementContend {
                version: SecretVersionId::ALL[selection as usize % 3],
                worker,
            }
        } else if draw < 25 {
            let build = if rollover {
                [BuildId::First, BuildId::SecondAppFirst][selection as usize % 2]
            } else {
                builds[selection as usize % count]
            };
            let delay = if rollover {
                0
            } else {
                scheduler_random.next() as u32 % 4_000_001
            };
            ScheduleChoice::QuiesceDeployment { build, delay }
        } else {
            let fault = if rollover || !scheduler_random.next().is_multiple_of(8) {
                Fault::None
            } else {
                [
                    Fault::NotApplied,
                    Fault::LostAck,
                    Fault::Delayed,
                    Fault::Unavailable,
                ][(scheduler_random.next() % 4) as usize]
            };
            ScheduleChoice::Work {
                worker,
                selection,
                fault,
            }
        });
    }
    let result = Program {
        seed,
        intents,
        schedule,
    };
    result.validate()?;
    Ok(result)
}

pub fn generated(seed: u64, case: u32) -> Result<Scenario> {
    compile(&program(seed, case)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_modes_cannot_be_skipped_or_replaced_during_an_older_attempt() {
        let version = SecretVersionId::Third;
        let opaque = ScheduleChoice::SecretReadMode {
            version,
            selection: ReadSelection::Current,
            strength: ReadStrength::Opaque,
        };
        let qualified = ScheduleChoice::SecretReadMode {
            version,
            selection: ReadSelection::Current,
            strength: ReadStrength::Qualified,
        };
        let mut guidance = Guidance::default();
        guidance.versions[version.index()] = Version {
            available: true,
            observed_read_requested: true,
            opaque_read_requested: true,
            read_stage: 1,
            clean_rounds: 8,
            ..Version::default()
        };
        assert!(
            guidance.weak_choice(&qualified).is_none(),
            "a high global round count cannot skip opaque mode"
        );
        guidance.workers[0] = Some(Attempt {
            task: Task::Retirement(version),
            performed: Some(Fault::None),
        });
        assert!(
            guidance.weak_choice(&opaque).is_none(),
            "an in-flight earlier read cannot count as opaque exposure"
        );
        guidance.workers[0] = None;
        assert!(guidance.weak_choice(&opaque).is_some());
        assert!(
            guidance.weak_choice(&qualified).is_none(),
            "installation alone is not a completed attempt"
        );
        guidance.workers[0] = Some(Attempt {
            task: Task::Retirement(version),
            performed: Some(Fault::None),
        });
        guidance.versions[version.index()].clean_rounds = 9;
        assert!(guidance.weak_choice(&qualified).is_none());
        guidance.workers[0] = None;
        assert!(guidance.weak_choice(&qualified).is_some());
    }

    #[test]
    fn removing_mode_choices_removes_their_guidance_prerequisites() {
        let version = SecretVersionId::Third;
        let qualified = ScheduleChoice::SecretReadMode {
            version,
            selection: ReadSelection::Current,
            strength: ReadStrength::Qualified,
        };
        let program = Program {
            seed: 1,
            intents: vec![],
            schedule: vec![qualified.clone()],
        };
        let mut guidance = Guidance::new(&program);
        guidance.versions[version.index()].available = true;
        assert!(!guidance.versions[version.index()].opaque_read_requested);
        assert!(!guidance.versions[version.index()].observed_read_requested);
        assert!(guidance.weak_choice(&qualified).is_some());
    }

    #[test]
    fn every_single_mode_selection_strength_pair_has_no_phantom_earlier_stage() {
        for selection in [
            ReadSelection::Current,
            ReadSelection::Previous,
            ReadSelection::Oldest,
        ] {
            for strength in [
                ReadStrength::Observed,
                ReadStrength::Opaque,
                ReadStrength::Qualified,
            ] {
                let version = SecretVersionId::Third;
                let choice = ScheduleChoice::SecretReadMode {
                    version,
                    selection,
                    strength,
                };
                let program = Program {
                    seed: 1,
                    intents: vec![],
                    schedule: vec![choice.clone()],
                };
                let mut guidance = Guidance::new(&program);
                guidance.versions[version.index()].available = true;
                assert_eq!(
                    guidance.versions[version.index()].observed_read_requested,
                    strength == ReadStrength::Observed
                );
                assert_eq!(
                    guidance.versions[version.index()].opaque_read_requested,
                    strength == ReadStrength::Opaque
                );
                assert_eq!(
                    guidance.weak_choice(&choice),
                    Some(Action::SecretReadMode {
                        version: version.value(),
                        selection,
                        strength
                    }),
                    "sole supplied mode {selection:?}/{strength:?} requires an absent earlier stage"
                );
            }
        }
    }

    #[test]
    fn ineligible_controller_choices_advance_their_request_prerequisites() -> Result<()> {
        let program = Program {
            seed: 1,
            intents: vec![Intent::Submit {
                build: BuildId::First,
            }],
            schedule: vec![ScheduleChoice::ObserveStoppedDeployment {
                build: BuildId::First,
            }],
        };
        assert_eq!(
            compile(&program)?.actions,
            vec![Action::Submit { build: 0 }]
        );
        Ok(())
    }

    #[test]
    fn weak_profiles_lower_typed_faults_without_admitting_release_authority() -> Result<()> {
        for case in [2, 3, 6] {
            let input = program(3664912422, case)?;
            assert!(!input.intents.iter().any(|intent| matches!(
                intent,
                Intent::Approve {
                    build: BuildId::Third
                } | Intent::StartRelease {
                    build: BuildId::Third
                }
            )));
            let scenario = compile(&input)?;
            assert!(
                scenario
                    .actions
                    .iter()
                    .any(|action| matches!(action, Action::RetireSecret { version: 3 }))
            );
            if case == 2 {
                assert!(scenario.actions.iter().any(|action| matches!(
                    action,
                    Action::SecretReadMode {
                        strength: ReadStrength::Observed,
                        ..
                    }
                )));
                assert!(scenario.actions.iter().any(|action| matches!(
                    action,
                    Action::SecretReadMode {
                        strength: ReadStrength::Opaque,
                        ..
                    }
                )));
            } else {
                assert!(
                    scenario
                        .actions
                        .iter()
                        .any(|action| matches!(action, Action::HoldRetirement { version: 3 }))
                );
                assert!(
                    scenario
                        .actions
                        .iter()
                        .any(|action| matches!(action, Action::DeliverRetirement { version: 3 }))
                );
            }
        }
        Ok(())
    }

    #[test]
    fn positive_retirement_can_target_version_without_a_release() {
        let mut guidance = Guidance::default();
        guidance.requests[BuildId::Third.index() as usize].declared = true;
        guidance.versions[SecretVersionId::Third.index()].available = true;
        assert!(guidance.retirement_enabled(SecretVersionId::Third));
        guidance.requests[BuildId::Third.index() as usize].release_declared = true;
        assert!(!guidance.retirement_enabled(SecretVersionId::Third));
    }

    #[test]
    fn optimistic_quiescence_attempts_remain_retryable() {
        let mut guidance = Guidance::default();
        assert!(guidance.quiesce(BuildId::First, 0).is_none());
        guidance.requests[BuildId::First.index() as usize].release_attempted = true;
        guidance.requests[BuildId::Second.index() as usize].clean_release_rounds = RELEASE_ATTEMPTS;
        let expected = Some(Action::QuiesceDeployment { build: 0, delay: 0 });
        assert_eq!(guidance.quiesce(BuildId::First, 0), expected);
        assert!(guidance.requests[BuildId::First.index() as usize].quiescence_attempted);
        assert_eq!(guidance.quiesce(BuildId::First, 0), expected);
    }

    #[test]
    fn programs_are_reproducible_bounded_and_have_no_preadmitted_requests() -> Result<()> {
        for case in 0..32 {
            let input = program(3664912422, case)?;
            assert_eq!(input, program(3664912422, case)?);
            let scenario = compile(&input)?;
            assert_eq!(scenario, compile(&input)?);
            assert_eq!(scenario.format, 4);
            assert!(scenario.actions.len() <= MAX_ACTIONS);
            let mut submitted = [false; 6];
            for action in scenario.actions {
                match action {
                    Action::Submit { build } => submitted[build as usize] = true,
                    Action::Claim { build, .. }
                    | Action::Cancel { build }
                    | Action::ProbeIsolation { build, .. }
                    | Action::Approve { build, .. } => assert!(submitted[build as usize]),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    #[test]
    fn generation_varies_submission_order_population_and_live_interleavings() -> Result<()> {
        let mut populations = BTreeSet::new();
        let mut orders = BTreeSet::new();
        let mut early = BTreeSet::new();
        for case in 0..32 {
            let scenario = generated(3664912422, case)?;
            let order: Vec<_> = scenario
                .actions
                .iter()
                .filter_map(|action| match action {
                    Action::Submit { build } => Some(*build),
                    _ => None,
                })
                .collect();
            populations.insert(order.len());
            orders.insert(order);
            early.insert(serde_json::to_string(
                &scenario.actions[..scenario.actions.len().min(12)],
            )?);
        }
        assert!(populations.len() >= 2);
        assert!(orders.len() >= 5);
        assert!(early.len() >= 24);
        Ok(())
    }

    #[test]
    fn healthy_guidance_schedules_intents_and_never_performs_an_empty_slot() -> Result<()> {
        for seed in [0, 1, 42, 3664912422] {
            let scenario = generated(seed, 0)?;
            let mut claimed = [[false; 4]; 3];
            let mut approvals = BTreeSet::new();
            let mut starts = BTreeSet::new();
            let mut retirement = false;
            let mut quiesced = BTreeSet::new();
            let mut drained = BTreeSet::new();
            let mut rollback_released = BTreeSet::new();
            for action in scenario.actions {
                match action {
                    Action::Claim { slot, .. } => claimed[0][slot as usize] = true,
                    Action::ReleaseClaim { slot, .. } => claimed[1][slot as usize] = true,
                    Action::RetirementClaim { slot, .. } => claimed[2][slot as usize] = true,
                    Action::Perform { slot, .. } => assert!(claimed[0][slot as usize]),
                    Action::ReleasePerform { slot, .. } => assert!(claimed[1][slot as usize]),
                    Action::RetirementPerform { slot, .. } => assert!(claimed[2][slot as usize]),
                    Action::Settle { slot } => {
                        assert!(claimed[0][slot as usize]);
                        claimed[0][slot as usize] = false;
                    }
                    Action::ReleaseSettle { slot } => {
                        assert!(claimed[1][slot as usize]);
                        claimed[1][slot as usize] = false;
                    }
                    Action::RetirementSettle { slot } => {
                        assert!(claimed[2][slot as usize]);
                        claimed[2][slot as usize] = false;
                    }
                    Action::RetireSecret { version: 1 } => retirement = true,
                    Action::QuiesceDeployment { build, .. } => {
                        quiesced.insert(build);
                    }
                    Action::ReleaseDrain { build } => {
                        assert!(retirement);
                        assert!(quiesced.contains(&build));
                        drained.insert(build);
                    }
                    Action::ReleaseRollback { build } => {
                        assert!(drained.contains(&build));
                        rollback_released.insert(build);
                    }
                    Action::Approve {
                        build,
                        wrong_commit: false,
                        wrong_tenant: false,
                    } => {
                        approvals.insert(build);
                    }
                    Action::ReleaseStart { build } => {
                        starts.insert(build);
                    }
                    _ => {}
                }
            }
            assert_eq!(approvals.len(), 5);
            assert_eq!(starts.len(), 5);
            assert!(retirement);
            assert_eq!(rollback_released, BTreeSet::from([0, 3]));
        }
        Ok(())
    }

    #[test]
    fn deleting_requests_preserves_explicit_negative_intent_identity() -> Result<()> {
        let mut input = program(9, 0)?;
        input.intents = vec![
            Intent::Submit {
                build: BuildId::Second,
            },
            Intent::Approve {
                build: BuildId::Second,
            },
            Intent::StartRelease {
                build: BuildId::Second,
            },
            Intent::Invalid {
                attempt: InvalidAttempt::PrematureStart {
                    build: BuildId::Second,
                },
            },
        ];
        let reduced = input.without_intents(0..1)?;
        assert_eq!(
            reduced.intents,
            vec![Intent::Invalid {
                attempt: InvalidAttempt::PrematureStart {
                    build: BuildId::Second
                }
            }]
        );
        assert!(
            compile(&reduced)?
                .actions
                .iter()
                .all(|action| matches!(action, Action::ReleaseStart { build: 1 }))
        );
        Ok(())
    }

    #[test]
    fn negative_scheduler_preserves_contending_claims_and_duplicate_delivery() -> Result<()> {
        let input = Program {
            seed: 0,
            intents: vec![Intent::Submit {
                build: BuildId::First,
            }],
            schedule: vec![
                ScheduleChoice::Admit { selection: 0 },
                ScheduleChoice::Work {
                    worker: WorkerId::First,
                    selection: 0,
                    fault: Fault::None,
                },
                ScheduleChoice::Contend {
                    build: BuildId::First,
                    worker: WorkerId::Second,
                },
                ScheduleChoice::Work {
                    worker: WorkerId::First,
                    selection: 0,
                    fault: Fault::None,
                },
                ScheduleChoice::Work {
                    worker: WorkerId::First,
                    selection: 0,
                    fault: Fault::None,
                },
                ScheduleChoice::DuplicateDelivery {
                    worker: WorkerId::First,
                },
                ScheduleChoice::Restart {},
                ScheduleChoice::DuplicateDelivery {
                    worker: WorkerId::First,
                },
            ],
        };
        assert_eq!(
            compile(&input)?.actions,
            vec![
                Action::Submit { build: 0 },
                Action::Claim { build: 0, slot: 0 },
                Action::Claim { build: 0, slot: 1 },
                Action::Perform {
                    slot: 0,
                    fault: Fault::None
                },
                Action::Settle { slot: 0 },
                Action::Settle { slot: 0 },
                Action::Restart {},
            ]
        );
        Ok(())
    }

    #[test]
    fn shared_versions_do_not_alias_the_independent_company() {
        assert_eq!(BuildId::LEGACY.map(BuildId::index), [0, 1, 2]);
        assert_eq!(BuildId::ALL.map(BuildId::index), [0, 1, 2, 3, 4, 5]);
        assert_eq!(
            BuildId::First.primary_version(),
            BuildId::SecondAppFirst.primary_version()
        );
        assert_eq!(
            BuildId::Second.primary_version(),
            BuildId::SecondAppSecond.primary_version()
        );
        assert_eq!(BuildId::Independent.primary_version(), None);
        assert_eq!(SecretVersionId::ALL.map(SecretVersionId::value), [1, 2, 3]);
    }

    #[test]
    fn competing_submissions_are_unconstrained_but_rollover_dependencies_are_explicit() -> Result<()>
    {
        let mut input = Program {
            seed: 0,
            intents: vec![
                Intent::Submit {
                    build: BuildId::Second,
                },
                Intent::Submit {
                    build: BuildId::Third,
                },
            ],
            schedule: vec![ScheduleChoice::Admit { selection: 1 }],
        };
        assert_eq!(compile(&input)?.actions, vec![Action::Submit { build: 5 }]);
        input.intents[1] = Intent::SubmitReplacement {
            build: BuildId::Third,
        };
        assert_eq!(compile(&input)?.actions, vec![Action::Submit { build: 1 }]);
        assert!(input.without_intents(0..1)?.intents.is_empty());
        Ok(())
    }

    #[test]
    fn retirement_and_cleanup_pruning_preserves_resource_and_successor_dependencies() -> Result<()>
    {
        let program = Program {
            seed: 0,
            intents: vec![
                Intent::Submit {
                    build: BuildId::First,
                },
                Intent::Approve {
                    build: BuildId::First,
                },
                Intent::StartRelease {
                    build: BuildId::First,
                },
                Intent::Secret {
                    build: BuildId::First,
                    enabled: true,
                    access: true,
                    ready: true,
                    delay: 0,
                },
                Intent::Submit {
                    build: BuildId::Second,
                },
                Intent::Approve {
                    build: BuildId::Second,
                },
                Intent::StartRelease {
                    build: BuildId::Second,
                },
                Intent::Retire {
                    version: SecretVersionId::First,
                },
                Intent::Drain {
                    build: BuildId::First,
                },
                Intent::ReleaseRollback {
                    build: BuildId::First,
                },
                Intent::Invalid {
                    attempt: InvalidAttempt::PrematureRetirement {
                        version: SecretVersionId::First,
                    },
                },
            ],
            schedule: Vec::new(),
        };
        let without_successor = program.without_intents(4..5)?;
        assert!(!without_successor.intents.iter().any(|intent| matches!(
            intent,
            Intent::Drain { .. } | Intent::ReleaseRollback { .. }
        )));
        let without_resource = program.without_intents(3..4)?;
        assert!(
            !without_resource
                .intents
                .iter()
                .any(|intent| matches!(intent, Intent::Retire { .. }))
        );
        assert!(without_resource.intents.iter().any(|intent| matches!(
            intent,
            Intent::Invalid {
                attempt: InvalidAttempt::PrematureRetirement {
                    version: SecretVersionId::First
                }
            }
        )));
        let without_drain = program.without_intents(8..9)?;
        assert!(
            !without_drain
                .intents
                .iter()
                .any(|intent| matches!(intent, Intent::ReleaseRollback { .. }))
        );
        Ok(())
    }

    #[test]
    fn retirement_uses_shared_worker_slots_and_keeps_competing_and_duplicate_attempts() -> Result<()>
    {
        let mut guidance = Guidance::default();
        guidance.versions[0].retirement_attempted = true;
        assert_eq!(
            guidance.retirement_work(SecretVersionId::First, WorkerId::First, Fault::None),
            Some(Action::RetirementClaim {
                version: 1,
                slot: 0
            })
        );
        assert_eq!(
            guidance.contend_task(Task::Retirement(SecretVersionId::First), WorkerId::Second),
            Some(Action::RetirementClaim {
                version: 1,
                slot: 1
            })
        );
        assert_eq!(
            guidance.retirement_work(SecretVersionId::First, WorkerId::First, Fault::LostAck),
            Some(Action::RetirementPerform {
                slot: 0,
                fault: Fault::LostAck
            })
        );
        assert_eq!(
            guidance.retirement_work(SecretVersionId::First, WorkerId::First, Fault::None),
            Some(Action::RetirementSettle { slot: 0 })
        );
        assert_eq!(
            guidance.duplicate(WorkerId::First),
            Some(Action::RetirementSettle { slot: 0 })
        );
        Ok(())
    }

    #[test]
    fn drain_observation_requires_independent_quiescence_but_negative_attempts_remain() {
        let mut guidance = Guidance::default();
        guidance.requests[0].release_attempted = true;
        guidance.requests[0].approval_attempted = true;
        guidance.requests[1].clean_release_rounds = RELEASE_ATTEMPTS;
        assert!(!guidance.enabled(&Intent::Drain {
            build: BuildId::First
        }));
        assert!(guidance.enabled(&Intent::Invalid {
            attempt: InvalidAttempt::PrematureDrain {
                build: BuildId::First
            }
        }));
        assert_eq!(
            guidance.quiesce(BuildId::First, 27),
            Some(Action::QuiesceDeployment {
                build: 0,
                delay: 27
            })
        );
        assert!(guidance.enabled(&Intent::Drain {
            build: BuildId::First
        }));
        assert_eq!(
            guidance.admit(&Intent::Drain {
                build: BuildId::First
            }),
            Action::ReleaseDrain { build: 0 }
        );
    }
}
