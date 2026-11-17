//! Process-local browser correlation DATA. Nothing here authenticates a
//! passkey or creates a native owner. A claimed phase is spent before native
//! work starts; missing replies, panics and lost cookies cannot reissue it.
use crate::security_epoch::restore_approval::AdminIdentity;
use crate::{iap, security_epoch::ProtectedRestoreCommandData};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::AuthorityScope};
use std::{collections::BTreeMap, sync::Arc};

const SESSION_SECONDS: i64 = 300;
const MAX_SESSIONS: usize = 1024;
const MAX_FLOWS: usize = 64;

struct Session {
    actor: AdminIdentity,
    csrf: String,
    created_at: i64,
    expires_at: i64,
    flow: Option<Digest>,
}

enum Phase {
    Busy,
    Refused,
    Approval {
        approver: AdminIdentity,
    },
    Approved {
        approver: AdminIdentity,
        recorded: Digest,
        handoff: String,
    },
    Execution {
        approval_request: Digest,
    },
    Completed,
    Abandoned,
}

struct Flow {
    scope: AuthorityScope,
    // Sharing immutable DATA never lends the genuine pending native ceremony.
    command: Arc<ProtectedRestoreCommandData>,
    phase: Phase,
}

pub(super) enum Step {
    Begin,
    Approve {
        approver: AdminIdentity,
    },
    Execute {
        approver: AdminIdentity,
        recorded: Digest,
    },
    Authenticate {
        approval_request: Digest,
    },
    Abandon,
}

/// A one-shot local routing value, not a capability or native continuation.
/// There is no constructor from a browser-supplied id, phase or public record.
pub(super) struct Claim {
    pub(super) scope: AuthorityScope,
    pub(super) command: Arc<ProtectedRestoreCommandData>,
    pub(super) step: Step,
}

#[derive(Default)]
pub(super) struct Store {
    sessions: BTreeMap<String, Session>,
    flows: BTreeMap<Digest, Flow>,
}

fn actor(identity: &iap::Verified) -> AdminIdentity {
    AdminIdentity {
        email: identity.email.clone(),
        subject: identity.subject.clone(),
    }
}

impl Store {
    pub(super) fn open(
        &mut self,
        token: String,
        csrf: String,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<()> {
        // Expired sessions can be forgotten, but flows and spent command ids
        // survive. Opening a new UI session never adopts or restarts a flow.
        self.sessions.retain(|_, session| at < session.expires_at);
        ensure!(
            self.sessions.len() < MAX_SESSIONS && !self.sessions.contains_key(&token),
            "restore_browser_capacity"
        );
        let expires_at = at
            .checked_add(SESSION_SECONDS)
            .context("restore_browser_clock")?;
        self.sessions.insert(
            token,
            Session {
                actor: actor(identity),
                csrf,
                created_at: at,
                expires_at,
                flow: None,
            },
        );
        Ok(())
    }

    pub(super) fn session(
        &self,
        token: &str,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<(&str, bool)> {
        let session = self
            .sessions
            .get(token)
            .context("restore_browser_session_missing")?;
        ensure!(
            session.actor == actor(identity) && at >= session.created_at && at < session.expires_at,
            "restore_browser_session_changed"
        );
        Ok((&session.csrf, session.flow.is_some()))
    }

    fn require_post(
        &self,
        token: &str,
        csrf: &str,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<()> {
        ensure!(
            self.session(token, identity, at)?.0 == csrf,
            "restore_browser_csrf"
        );
        Ok(())
    }

    pub(super) fn begin(
        &mut self,
        token: &str,
        csrf: &str,
        identity: &iap::Verified,
        at: i64,
        scope: AuthorityScope,
        command: ProtectedRestoreCommandData,
    ) -> Result<Claim> {
        self.require_post(token, csrf, identity, at)?;
        ensure!(
            self.sessions[token].flow.is_none() && command.approver_email == identity.email,
            "restore_browser_begin_changed"
        );
        ensure!(
            self.flows.len() < MAX_FLOWS && !self.flows.contains_key(&command.id),
            "restore_browser_command_spent"
        );
        ensure!(
            self.flows
                .values()
                .all(|flow| flow.scope != scope || matches!(flow.phase, Phase::Abandoned)),
            "restore_browser_flow_busy"
        );
        let id = command.id.clone();
        let command = Arc::new(command);
        self.flows.insert(
            id.clone(),
            Flow {
                scope: scope.clone(),
                command: command.clone(),
                phase: Phase::Busy,
            },
        );
        self.sessions
            .get_mut(token)
            .expect("validated session")
            .flow = Some(id);
        Ok(Claim {
            scope,
            command,
            step: Step::Begin,
        })
    }

    fn selected(&mut self, token: &str) -> Result<&mut Flow> {
        let id = self
            .sessions
            .get(token)
            .and_then(|session| session.flow.as_ref())
            .context("restore_browser_flow_missing")?;
        self.flows
            .get_mut(id)
            .context("restore_browser_flow_missing")
    }

    pub(super) fn approve(
        &mut self,
        token: &str,
        csrf: &str,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Claim> {
        self.require_post(token, csrf, identity, at)?;
        let flow = self.selected(token)?;
        let Phase::Approval { approver } = &flow.phase else {
            anyhow::bail!("restore_browser_phase_changed")
        };
        ensure!(
            *approver == actor(identity),
            "restore_browser_approver_changed"
        );
        let step = Step::Approve {
            approver: approver.clone(),
        };
        flow.phase = Phase::Busy;
        Ok(Claim {
            scope: flow.scope.clone(),
            command: flow.command.clone(),
            step,
        })
    }

    pub(super) fn execute(
        &mut self,
        token: &str,
        csrf: &str,
        handoff: &str,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Claim> {
        self.require_post(token, csrf, identity, at)?;
        let (id, flow) = self.flows.iter_mut().find(|(_, flow)| matches!(&flow.phase, Phase::Approved { handoff: actual, .. } if actual == handoff)).context("restore_browser_handoff_missing")?;
        ensure!(
            flow.command.intent.executor == actor(identity),
            "restore_browser_executor_changed"
        );
        let session = self.sessions.get_mut(token).expect("validated session");
        ensure!(
            session.flow.as_ref().is_none_or(|selected| selected == id),
            "restore_browser_session_busy"
        );
        let Phase::Approved {
            approver, recorded, ..
        } = &flow.phase
        else {
            unreachable!("selected phase")
        };
        let step = Step::Execute {
            approver: approver.clone(),
            recorded: recorded.clone(),
        };
        session.flow = Some(id.clone());
        // Consumes the handoff before native work, even for the same admin.
        flow.phase = Phase::Busy;
        Ok(Claim {
            scope: flow.scope.clone(),
            command: flow.command.clone(),
            step,
        })
    }

    pub(super) fn abandon(
        &mut self,
        token: &str,
        csrf: &str,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Claim> {
        self.require_post(token, csrf, identity, at)?;
        let flow = self.selected(token)?;
        let expected = match &flow.phase {
            Phase::Approval { approver } | Phase::Approved { approver, .. } => approver,
            Phase::Execution { .. } => &flow.command.intent.executor,
            Phase::Busy | Phase::Refused | Phase::Completed | Phase::Abandoned => {
                anyhow::bail!("restore_browser_phase_changed")
            }
        };
        ensure!(
            *expected == actor(identity),
            "restore_browser_abandon_actor_changed"
        );
        flow.phase = Phase::Busy;
        Ok(Claim {
            scope: flow.scope.clone(),
            command: flow.command.clone(),
            step: Step::Abandon,
        })
    }

    fn claimed(&mut self, claim: &Claim) -> Result<&mut Flow> {
        let flow = self
            .flows
            .get_mut(&claim.command.id)
            .context("restore_browser_flow_missing")?;
        ensure!(
            Arc::ptr_eq(&flow.command, &claim.command)
                && flow.scope == claim.scope
                && matches!(flow.phase, Phase::Busy),
            "restore_browser_claim_changed"
        );
        Ok(flow)
    }

    /// Negative only: an uncertain reply cannot leave a usable claim visible
    /// to a later request. An equal but separately constructed command cannot
    /// poison the actual flow selected by another private claim.
    pub(super) fn refuse_reply(
        &mut self,
        scope: &AuthorityScope,
        command: &Arc<ProtectedRestoreCommandData>,
    ) {
        if let Some(flow) = self.flows.get_mut(&command.id)
            && flow.scope == *scope
            && Arc::ptr_eq(&flow.command, command)
        {
            flow.phase = Phase::Refused;
        }
    }

    pub(super) fn approval_prompt(&mut self, claim: Claim, approver: AdminIdentity) -> Result<()> {
        ensure!(
            matches!(claim.step, Step::Begin),
            "restore_browser_phase_changed"
        );
        self.claimed(&claim)?.phase = Phase::Approval { approver };
        Ok(())
    }

    pub(super) fn recorded(
        &mut self,
        claim: Claim,
        recorded: Digest,
        handoff: String,
    ) -> Result<()> {
        ensure!(self.flows.values().all(|flow| !matches!(&flow.phase, Phase::Approved { handoff: actual, .. } if actual == &handoff)), "restore_browser_handoff_collision");
        let Step::Approve { approver } = &claim.step else {
            anyhow::bail!("restore_browser_phase_changed")
        };
        let approver = approver.clone();
        self.claimed(&claim)?.phase = Phase::Approved {
            approver,
            recorded,
            handoff,
        };
        Ok(())
    }

    pub(super) fn execution_prompt(
        &mut self,
        claim: Claim,
        approval_request: Digest,
    ) -> Result<()> {
        ensure!(
            matches!(claim.step, Step::Execute { .. }),
            "restore_browser_phase_changed"
        );
        self.claimed(&claim)?.phase = Phase::Execution { approval_request };
        Ok(())
    }

    pub(super) fn authenticate(
        &mut self,
        token: &str,
        csrf: &str,
        identity: &iap::Verified,
        at: i64,
    ) -> Result<Claim> {
        self.require_post(token, csrf, identity, at)?;
        let flow = self.selected(token)?;
        let Phase::Execution { approval_request } = &flow.phase else {
            anyhow::bail!("restore_browser_phase_changed");
        };
        ensure!(
            flow.command.intent.executor == actor(identity),
            "restore_browser_executor_changed"
        );
        let step = Step::Authenticate {
            approval_request: approval_request.clone(),
        };
        // Pessimistic terminal claim BEFORE any native send. Error/unwind/lost
        // reply stays Busy forever, never returns to Execution or reconnects.
        flow.phase = Phase::Busy;
        Ok(Claim {
            scope: flow.scope.clone(),
            command: flow.command.clone(),
            step,
        })
    }

    /// Delivery metadata only, reached solely after the actual native supplier
    /// and same-original courier posts return. This creates no native owner or
    /// future readiness. Unknown/foreign replies never restore a spent phase.
    pub(super) fn authenticated(
        &mut self,
        claim: Claim,
        data: &crate::security_epoch::native_enrollment::RestoreInstalledOutputData,
    ) -> Result<()> {
        let Step::Authenticate { approval_request } = &claim.step else {
            anyhow::bail!("restore_browser_phase_changed");
        };
        ensure!(
            data.approval == *approval_request
                && data.operation == claim.command.operation
                && data.full_archive == claim.command.intent.full_archive_digest
                && data.target == claim.command.intent.target
                && data.executor == claim.command.intent.executor,
            "restore_browser_installed_reply_changed"
        );
        // installed commits the actual held cohort/report and is not
        // reconstructible from command DATA. Its native validation belongs to
        // the genuine signed receiver; no browser supplied output is accepted.
        self.claimed(&claim)?.phase = Phase::Completed;
        Ok(())
    }

    pub(super) fn abandoned(&mut self, claim: Claim) -> Result<()> {
        ensure!(
            matches!(claim.step, Step::Abandon),
            "restore_browser_phase_changed"
        );
        self.claimed(&claim)?.phase = Phase::Abandoned;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn identity(email: &str, subject: &str) -> iap::Verified {
        iap::Verified {
            email: email.into(),
            subject: subject.into(),
        }
    }

    pub(super) fn command(n: u8) -> Result<(AuthorityScope, ProtectedRestoreCommandData)> {
        let record = crate::security_epoch::restore_public_record_fixture_data()?;
        let mut intent = record.statement.request.intent();
        intent.executor = actor(&identity("executor@example.com", "executor-subject"));
        let scope = intent.target.scope.clone();
        Ok((
            scope,
            ProtectedRestoreCommandData {
                id: Digest::new(&[n]),
                intent,
                operation: Digest::new(b"operation"),
                approver_email: "approver@example.com".into(),
                approver_credential: b"approver public id".to_vec(),
                executor_credential: b"executor public id".to_vec(),
            },
        ))
    }

    pub(super) fn opened() -> Result<Store> {
        let mut store = Store::default();
        store.open(
            "approver-cookie".into(),
            "approver-csrf".into(),
            &identity("approver@example.com", "approver-subject"),
            10,
        )?;
        store.open(
            "executor-cookie".into(),
            "executor-csrf".into(),
            &identity("executor@example.com", "executor-subject"),
            10,
        )?;
        Ok(store)
    }

    fn begin(store: &mut Store, n: u8) -> Result<Claim> {
        let (scope, command) = command(n)?;
        store.begin(
            "approver-cookie",
            "approver-csrf",
            &identity("approver@example.com", "approver-subject"),
            11,
            scope,
            command,
        )
    }

    pub(super) fn approved(store: &mut Store) -> Result<Digest> {
        let claim = begin(store, 1)?;
        store.approval_prompt(
            claim,
            actor(&identity("approver@example.com", "approver-subject")),
        )?;
        let claim = store.approve(
            "approver-cookie",
            "approver-csrf",
            &identity("approver@example.com", "approver-subject"),
            12,
        )?;
        let recorded = Digest::new(b"actual same-channel recorded DATA");
        store.recorded(claim, recorded.clone(), "one-use-handoff".into())?;
        Ok(recorded)
    }

    #[test]
    fn reply_uncertainty_refuses_the_actual_published_claim_without_poisoning_a_foreign_one()
    -> Result<()> {
        let mut store = opened()?;
        let claim = begin(&mut store, 1)?;
        let scope = claim.scope.clone();
        let actual = claim.command.clone();
        store.approval_prompt(
            claim,
            actor(&identity("approver@example.com", "approver-subject")),
        )?;
        let (_, equal_data) = command(1)?;
        store.refuse_reply(&scope, &Arc::new(equal_data));
        assert!(
            matches!(store.flows[&actual.id].phase, Phase::Approval { .. }),
            "equal DATA is not the actual claim"
        );
        let mut foreign = scope.clone();
        foreign.environment = "foreign".to_owned().try_into().unwrap();
        store.refuse_reply(&foreign, &actual);
        assert!(matches!(
            store.flows[&actual.id].phase,
            Phase::Approval { .. }
        ));
        store.refuse_reply(&scope, &actual);
        assert!(matches!(store.flows[&actual.id].phase, Phase::Refused));
        store.refuse_reply(&scope, &actual);
        assert!(
            store
                .approve(
                    "approver-cookie",
                    "approver-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    12
                )
                .is_err()
        );
        assert!(
            store
                .abandon(
                    "approver-cookie",
                    "approver-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    12
                )
                .is_err()
        );
        assert!(
            begin(&mut store, 2).is_err(),
            "a new request cannot rescue uncertainty in this scope"
        );
        let forged = Claim {
            scope,
            command: actual,
            step: Step::Begin,
        };
        assert!(
            store
                .approval_prompt(
                    forged,
                    actor(&identity("approver@example.com", "approver-subject"))
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn each_real_phase_claim_is_atomic_and_unknown_work_cannot_be_reissued_or_adopted() -> Result<()>
    {
        let mut store = opened()?;
        let claim = begin(&mut store, 1)?;
        assert!(begin(&mut store, 1).is_err());
        assert!(begin(&mut store, 2).is_err());
        assert!(
            store
                .approve(
                    "approver-cookie",
                    "approver-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    12
                )
                .is_err()
        );
        // Unknown transport outcome/panic: no completion is published. Drop
        // the SAME production claim, then try every supported restart path.
        drop(claim);
        store.open(
            "new-cookie".into(),
            "new-csrf".into(),
            &identity("approver@example.com", "approver-subject"),
            12,
        )?;
        for n in [1, 2] {
            let (scope, command) = command(n)?;
            assert!(
                store
                    .begin(
                        "new-cookie",
                        "new-csrf",
                        &identity("approver@example.com", "approver-subject"),
                        13,
                        scope,
                        command
                    )
                    .is_err()
            );
        }
        assert!(
            store
                .abandon(
                    "approver-cookie",
                    "approver-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    13
                )
                .is_err()
        );
        assert!(
            store
                .execute(
                    "executor-cookie",
                    "executor-csrf",
                    "one-use-handoff",
                    &identity("executor@example.com", "executor-subject"),
                    13
                )
                .is_err()
        );
        assert!(
            !store
                .session(
                    "new-cookie",
                    &identity("approver@example.com", "approver-subject"),
                    13
                )?
                .1
        );
        Ok(())
    }

    #[test]
    fn wrong_identity_csrf_session_and_phase_preserve_the_rightful_pending_ceremony() -> Result<()>
    {
        let mut store = opened()?;
        let claim = begin(&mut store, 1)?;
        store.approval_prompt(
            claim,
            actor(&identity("approver@example.com", "approver-subject")),
        )?;
        for (token, csrf, actual) in [
            (
                "approver-cookie",
                "wrong",
                identity("approver@example.com", "approver-subject"),
            ),
            (
                "approver-cookie",
                "approver-csrf",
                identity("approver@example.com", "different-subject"),
            ),
            (
                "approver-cookie",
                "approver-csrf",
                identity("different@example.com", "approver-subject"),
            ),
            (
                "executor-cookie",
                "executor-csrf",
                identity("executor@example.com", "executor-subject"),
            ),
            (
                "missing-cookie",
                "approver-csrf",
                identity("approver@example.com", "approver-subject"),
            ),
        ] {
            assert!(store.approve(token, csrf, &actual, 12).is_err());
        }
        assert!(
            store
                .execute(
                    "executor-cookie",
                    "executor-csrf",
                    "not-issued",
                    &identity("executor@example.com", "executor-subject"),
                    12
                )
                .is_err()
        );
        let claim = store.approve(
            "approver-cookie",
            "approver-csrf",
            &identity("approver@example.com", "approver-subject"),
            12,
        )?;
        assert!(matches!(claim.step, Step::Approve { .. }));
        assert!(
            store
                .approve(
                    "approver-cookie",
                    "approver-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    12
                )
                .is_err()
        );
        drop(claim);
        Ok(())
    }

    #[test]
    fn handoff_is_one_use_and_keeps_the_exact_command_record_and_two_actor_pairs() -> Result<()> {
        let mut store = opened()?;
        let recorded = approved(&mut store)?;
        for (token, csrf, actual) in [
            (
                "approver-cookie",
                "approver-csrf",
                identity("approver@example.com", "approver-subject"),
            ),
            (
                "executor-cookie",
                "executor-csrf",
                identity("executor@example.com", "different-subject"),
            ),
            (
                "executor-cookie",
                "executor-csrf",
                identity("different@example.com", "executor-subject"),
            ),
            (
                "executor-cookie",
                "wrong",
                identity("executor@example.com", "executor-subject"),
            ),
        ] {
            assert!(
                store
                    .execute(token, csrf, "one-use-handoff", &actual, 13)
                    .is_err()
            );
        }
        let claim = store.execute(
            "executor-cookie",
            "executor-csrf",
            "one-use-handoff",
            &identity("executor@example.com", "executor-subject"),
            13,
        )?;
        assert_eq!(claim.command.id, command(1)?.1.id);
        let Step::Execute {
            approver,
            recorded: actual,
        } = &claim.step
        else {
            panic!("wrong phase")
        };
        assert_eq!(
            *approver,
            actor(&identity("approver@example.com", "approver-subject"))
        );
        assert_eq!(*actual, recorded);
        assert!(
            store
                .execute(
                    "executor-cookie",
                    "executor-csrf",
                    "one-use-handoff",
                    &identity("executor@example.com", "executor-subject"),
                    13
                )
                .is_err()
        );
        store.execution_prompt(claim, Digest::new(b"public request commitment DATA"))?;
        assert!(
            store
                .abandon(
                    "approver-cookie",
                    "approver-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    14
                )
                .is_err()
        );
        assert!(
            store
                .execute(
                    "executor-cookie",
                    "executor-csrf",
                    "one-use-handoff",
                    &identity("executor@example.com", "executor-subject"),
                    13
                )
                .is_err()
        );
        let claim = store.abandon(
            "executor-cookie",
            "executor-csrf",
            &identity("executor@example.com", "executor-subject"),
            14,
        )?;
        store.abandoned(claim)?;
        // Confirmed abandon permits a DIFFERENT command from a new session,
        // but never reconstruction of the old id (or refresh of its clock).
        store.open(
            "later-cookie".into(),
            "later-csrf".into(),
            &identity("approver@example.com", "approver-subject"),
            14,
        )?;
        let (scope, old) = command(1)?;
        assert!(
            store
                .begin(
                    "later-cookie",
                    "later-csrf",
                    &identity("approver@example.com", "approver-subject"),
                    15,
                    scope,
                    old
                )
                .is_err()
        );
        let (scope, next) = command(2)?;
        drop(store.begin(
            "later-cookie",
            "later-csrf",
            &identity("approver@example.com", "approver-subject"),
            15,
            scope,
            next,
        )?);
        Ok(())
    }

    #[test]
    fn fixed_session_deadline_refuses_equality_rewind_and_new_session_adoption() -> Result<()> {
        let mut store = opened()?;
        approved(&mut store)?;
        let executor = identity("executor@example.com", "executor-subject");
        for at in [9, 310, 311] {
            assert!(
                store
                    .execute(
                        "executor-cookie",
                        "executor-csrf",
                        "one-use-handoff",
                        &executor,
                        at
                    )
                    .is_err()
            );
        }
        // A fresh UI session can consume a still-current native grant only
        // through the genuine one-use handoff. It cannot adopt by bare id.
        store.open("later-cookie".into(), "later-csrf".into(), &executor, 311)?;
        assert!(!store.session("later-cookie", &executor, 311)?.1);
        assert!(
            store
                .abandon("later-cookie", "later-csrf", &executor, 311)
                .is_err()
        );
        let claim = store.execute(
            "later-cookie",
            "later-csrf",
            "one-use-handoff",
            &executor,
            311,
        )?;
        drop(claim); // Actual native verifier still decides its ORIGINAL expiry.
        Ok(())
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::tests::{approved, command, identity, opened};
    use super::*;

    fn awaiting_authentication() -> Result<(Store, Digest)> {
        let mut store = opened()?;
        approved(&mut store)?;
        let claim = store.execute(
            "executor-cookie",
            "executor-csrf",
            "one-use-handoff",
            &identity("executor@example.com", "executor-subject"),
            13,
        )?;
        let expected = Digest::new(b"validated actual public approval request DATA");
        store.execution_prompt(claim, expected.clone())?;
        Ok((store, expected))
    }

    fn result_data(
        expected: Digest,
    ) -> Result<crate::security_epoch::native_enrollment::RestoreInstalledOutputData> {
        // Synthetic metadata only. No native owner, verified packet, writer,
        // passkey or final output is constructed or qualified by these values.
        let (_, command) = command(1)?;
        Ok(
            crate::security_epoch::native_enrollment::RestoreInstalledOutputData {
                approval: expected,
                operation: command.operation,
                full_archive: command.intent.full_archive_digest,
                target: command.intent.target,
                executor: command.intent.executor,
                installed: Digest::new(b"synthetic native-reported installed metadata"),
            },
        )
    }

    #[test]
    fn final_claim_is_spent_before_native_work_and_unknown_or_completed_work_never_restarts()
    -> Result<()> {
        for reply in [false, true] {
            let (mut store, expected) = awaiting_authentication()?;
            let claim = store.authenticate(
                "executor-cookie",
                "executor-csrf",
                &identity("executor@example.com", "executor-subject"),
                14,
            )?;
            assert!(
                store
                    .authenticate(
                        "executor-cookie",
                        "executor-csrf",
                        &identity("executor@example.com", "executor-subject"),
                        14
                    )
                    .is_err()
            );
            if reply {
                store.authenticated(claim, &result_data(expected)?)?;
            } else {
                drop(claim);
            }
            assert!(
                store
                    .authenticate(
                        "executor-cookie",
                        "executor-csrf",
                        &identity("executor@example.com", "executor-subject"),
                        15
                    )
                    .is_err()
            );
            assert!(
                store
                    .abandon(
                        "executor-cookie",
                        "executor-csrf",
                        &identity("executor@example.com", "executor-subject"),
                        15
                    )
                    .is_err()
            );
            assert!(
                store
                    .execute(
                        "executor-cookie",
                        "executor-csrf",
                        "one-use-handoff",
                        &identity("executor@example.com", "executor-subject"),
                        15
                    )
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn final_reply_must_match_request_hash_operation_archive_target_and_executor() -> Result<()> {
        for cut in 0..15 {
            let (mut store, expected) = awaiting_authentication()?;
            let claim = store.authenticate(
                "executor-cookie",
                "executor-csrf",
                &identity("executor@example.com", "executor-subject"),
                14,
            )?;
            let mut data = result_data(expected)?;
            match cut {
                0 => data.approval = Digest::new(b"whole signed record hash is not request hash"),
                1 => data.operation = Digest::new(b"foreign operation"),
                2 => data.full_archive = Digest::new(b"foreign archive"),
                3 => data.target.security_epoch += 1,
                4 => data.target.incarnation = Digest::new(b"foreign target"),
                5 => data.target.artifact = Digest::new(b"foreign artifact"),
                6 => data.executor.subject = "foreign subject".into(),
                7 => data.executor.email = "foreign@example.com".into(),
                8 => data.target.binding_generation += 1,
                9 => data.target.authority = Digest::new(b"foreign authority"),
                10 => data.target.selection = Digest::new(b"foreign selection"),
                11 => data.target.schema = Digest::new(b"foreign schema"),
                12 => {
                    data.target.scope.installation =
                        day2_capabilities::Name::try_from("foreign-installation".to_owned())?
                }
                13 => {
                    data.target.scope.environment =
                        day2_capabilities::Name::try_from("foreign-environment".to_owned())?
                }
                14 => {
                    data.target.scope.app =
                        day2_capabilities::Name::try_from("foreign-app".to_owned())?
                }
                _ => unreachable!(),
            }
            assert!(store.authenticated(claim, &data).is_err());
            assert!(
                store
                    .authenticate(
                        "executor-cookie",
                        "executor-csrf",
                        &identity("executor@example.com", "executor-subject"),
                        15
                    )
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn final_claim_keeps_csrf_actor_pair_and_fixed_ui_expiry_without_consuming_rightful_input()
    -> Result<()> {
        let (mut store, _) = awaiting_authentication()?;
        for (csrf, actor, at) in [
            (
                "wrong",
                identity("executor@example.com", "executor-subject"),
                14,
            ),
            (
                "executor-csrf",
                identity("executor@example.com", "foreign-subject"),
                14,
            ),
            (
                "executor-csrf",
                identity("foreign@example.com", "executor-subject"),
                14,
            ),
            (
                "executor-csrf",
                identity("executor@example.com", "executor-subject"),
                310,
            ),
        ] {
            assert!(
                store
                    .authenticate("executor-cookie", csrf, &actor, at)
                    .is_err()
            );
        }
        store.authenticate(
            "executor-cookie",
            "executor-csrf",
            &identity("executor@example.com", "executor-subject"),
            14,
        )?;
        Ok(())
    }
}
