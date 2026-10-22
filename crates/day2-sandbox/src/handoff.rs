//! Scheduling DATA for one pre-exec handoff. This does not construct a worker,
//! admit bytes, grant access or replace any supervisor deadline.

use crate::LaunchProfile;
use std::time::{Duration, Instant};

const POLL_QUANTUM: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ready,
    Attempted,
    Waiting,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecFailure {
    TextBusy,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    InvalidTransition,
    ClockRewound,
    Deadline,
    OtherExecFailure,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransition => "worker exec handoff refused",
            Self::ClockRewound => "worker exec handoff clock rewound",
            Self::Deadline => "worker exec handoff deadline expired",
            Self::OtherExecFailure => "worker exec handoff failed",
        })
    }
}

impl std::error::Error for Refusal {}

pub(crate) struct ExecHandoff {
    latest: Instant,
    deadline: Instant,
    phase: Phase,
    reported_busy: bool,
}

impl ExecHandoff {
    pub(crate) fn new(profile: LaunchProfile, origin: Instant) -> Result<Self, Refusal> {
        Ok(Self {
            latest: origin,
            deadline: origin
                .checked_add(profile.handoff_wall_time())
                .ok_or(Refusal::Deadline)?,
            phase: Phase::Ready,
            reported_busy: false,
        })
    }

    fn observe(&mut self, now: Instant) -> Result<(), Refusal> {
        let refusal = if self.phase == Phase::Refused {
            Some(Refusal::InvalidTransition)
        } else if now < self.latest {
            Some(Refusal::ClockRewound)
        } else if now >= self.deadline {
            Some(Refusal::Deadline)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            self.phase = Phase::Refused;
            return Err(refusal);
        }
        self.latest = now;
        Ok(())
    }

    pub(crate) fn before_exec(&mut self, now: Instant) -> Result<(), Refusal> {
        self.observe(now)?;
        if !matches!(self.phase, Phase::Ready | Phase::Waiting) {
            self.phase = Phase::Refused;
            return Err(Refusal::InvalidTransition);
        }
        self.phase = Phase::Attempted;
        Ok(())
    }

    pub(crate) fn failed_exec(
        &mut self,
        failure: ExecFailure,
        now: Instant,
    ) -> Result<bool, Refusal> {
        self.observe(now)?;
        if self.phase != Phase::Attempted {
            self.phase = Phase::Refused;
            return Err(Refusal::InvalidTransition);
        }
        if failure != ExecFailure::TextBusy {
            self.phase = Phase::Refused;
            return Err(Refusal::OtherExecFailure);
        }
        self.phase = Phase::Waiting;
        let first = !self.reported_busy;
        self.reported_busy = true;
        Ok(first)
    }

    pub(crate) fn before_poll(&mut self, now: Instant) -> Result<Duration, Refusal> {
        self.observe(now)?;
        if self.phase != Phase::Waiting {
            self.phase = Phase::Refused;
            return Err(Refusal::InvalidTransition);
        }
        Ok((self.deadline - now).min(POLL_QUANTUM))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_handoffs_keep_the_original_ceiling_and_report_only_once() {
        for profile in [LaunchProfile::Ordinary, LaunchProfile::QualifiedProperty] {
            let origin = Instant::now();
            let mut handoff = ExecHandoff::new(profile, origin).unwrap();
            let deadline = handoff.deadline;
            for attempt in 0..8 {
                let now = origin + Duration::from_millis(attempt);
                handoff.before_exec(now).unwrap();
                let first = handoff.failed_exec(ExecFailure::TextBusy, now).unwrap();
                assert_eq!(first, attempt == 0);
                assert_eq!(handoff.before_poll(now).unwrap(), POLL_QUANTUM);
                assert_eq!(handoff.deadline, deadline);
            }
            let final_time = deadline - Duration::from_nanos(1);
            handoff.before_exec(final_time).unwrap();
            let first = handoff
                .failed_exec(ExecFailure::TextBusy, final_time)
                .unwrap();
            assert_eq!(
                handoff.before_poll(final_time).unwrap(),
                Duration::from_nanos(1)
            );
            assert!(!first);
            assert_eq!(handoff.before_exec(deadline), Err(Refusal::Deadline));
            assert!(handoff.before_exec(final_time).is_err());
        }
    }

    #[test]
    fn setup_and_first_attempt_spend_the_same_wall_interval() {
        for profile in [LaunchProfile::Ordinary, LaunchProfile::QualifiedProperty] {
            let origin = Instant::now();
            let mut handoff = ExecHandoff::new(profile, origin).unwrap();
            let deadline = handoff.deadline;
            assert_eq!(handoff.before_exec(deadline), Err(Refusal::Deadline));
            assert!(handoff.before_exec(origin).is_err());
        }
        assert_eq!(
            LaunchProfile::Ordinary.handoff_wall_time(),
            Duration::from_secs(3)
        );
        assert_eq!(crate::CPU_SECONDS, 5);
        assert_eq!(
            LaunchProfile::QualifiedProperty.handoff_wall_time(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn time_spent_before_poll_cannot_be_added_to_the_original_budget() {
        let origin = Instant::now();
        let mut handoff = ExecHandoff::new(LaunchProfile::Ordinary, origin).unwrap();
        let deadline = handoff.deadline;
        handoff.before_exec(origin).unwrap();
        assert!(handoff.failed_exec(ExecFailure::TextBusy, origin).unwrap());
        assert_eq!(
            handoff
                .before_poll(deadline - Duration::from_nanos(1))
                .unwrap(),
            Duration::from_nanos(1)
        );
        assert_eq!(handoff.before_poll(deadline), Err(Refusal::Deadline));
        assert!(handoff.before_exec(origin).is_err());
    }

    #[test]
    fn rewind_or_another_exec_error_cannot_resume_the_handoff() {
        let origin = Instant::now();
        let mut handoff = ExecHandoff::new(LaunchProfile::Ordinary, origin).unwrap();
        handoff
            .before_exec(origin + Duration::from_millis(2))
            .unwrap();
        assert!(matches!(
            handoff.failed_exec(ExecFailure::TextBusy, origin),
            Err(Refusal::ClockRewound)
        ));
        assert!(
            handoff
                .before_exec(origin + Duration::from_millis(3))
                .is_err()
        );

        let mut handoff = ExecHandoff::new(LaunchProfile::Ordinary, origin).unwrap();
        handoff.before_exec(origin).unwrap();
        assert!(matches!(
            handoff.failed_exec(ExecFailure::Other, origin),
            Err(Refusal::OtherExecFailure)
        ));
        assert!(
            handoff
                .before_exec(origin + Duration::from_millis(1))
                .is_err()
        );
    }

    #[test]
    fn an_attempt_needs_one_preceding_busy_failure_before_another_attempt() {
        let origin = Instant::now();
        let mut handoff = ExecHandoff::new(LaunchProfile::Ordinary, origin).unwrap();
        handoff.before_exec(origin).unwrap();
        assert_eq!(handoff.before_exec(origin), Err(Refusal::InvalidTransition));
        assert!(handoff.failed_exec(ExecFailure::TextBusy, origin).is_err());

        let mut handoff = ExecHandoff::new(LaunchProfile::Ordinary, origin).unwrap();
        assert!(matches!(
            handoff.failed_exec(ExecFailure::TextBusy, origin),
            Err(Refusal::InvalidTransition)
        ));
        assert!(handoff.before_exec(origin).is_err());
    }
}
