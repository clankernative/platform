//! Genuine short-action approval composition. The human wait retains server
//! ceremony DATA only. Neither a row, scalar timestamp nor signature can enter
//! the private completed owner or recover an interrupted signing attempt.
use super::RestoreAuthenticationAction;
use crate::security_epoch::{
    kernel::Snapshot,
    restore_approval::{
        ApprovalIntent,
        signed::{ApprovalStatement, SignedApprovalRecord},
    },
    restore_host_clock::{HostTimeData, UnfencedControllerClock},
    restore_webauthn::{Assertion, ControllerCeremony, SigningUnit},
    storage_authority::NativeApprovalSource,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, restore_signing::KeySelection, security_epoch::EpochStore};
use std::time::Duration;

mod consumer;
pub(crate) use consumer::FencedReadUnit;
pub(in crate::security_epoch) use consumer::{
    ExecutionSourceLoan, FencedRegistryLoan, FencedRestoreContinuation, RestoreWriteLoan,
};

pub(in crate::security_epoch) struct PendingApproval {
    ceremony: ControllerCeremony,
    intent: ApprovalIntent,
    challenge: Digest,
    created_at: i64,
    expires_at: i64,
}

#[derive(PartialEq, Eq)]
enum SigningState {
    Prepared,
    MaySign,
    Published,
}

pub(in crate::security_epoch) struct CompletedCeremony<'metadata, 'storage, 'role> {
    action: Option<RestoreAuthenticationAction<'metadata, 'storage, 'role>>,
    ceremony: ControllerCeremony,
    assertion: Assertion,
    challenge: Digest,
    time_operation: Digest,
    statement: ApprovalStatement,
    signing: KeySelection,
    state: SigningState,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <CompletedCeremony<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <PendingApproval as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
};

fn operation(kind: &str, intent: &ApprovalIntent, challenge: &str) -> Result<Digest> {
    Digest::of(&(
        "day2-restore-approval-producer-v1",
        kind,
        intent.commitment()?,
        challenge,
    ))
}

fn seconds_ceiling(value: Duration) -> Result<i64> {
    Ok(i64::try_from(
        value
            .as_secs()
            .checked_add(u64::from(value.subsec_nanos() != 0))
            .context("restore_approval_clock_overflow")?,
    )?)
}

impl<'metadata, 'storage, 'role> RestoreAuthenticationAction<'metadata, 'storage, 'role> {
    pub(in crate::security_epoch) fn issue_approval(
        mut self,
        credential_id: &[u8],
    ) -> Result<PendingApproval> {
        let intent = self.intent.clone();
        self.check(&intent)?;
        let mut source = self.capture_source()?;
        let ceremony =
            ControllerCeremony::capture(&mut self.reader, credential_id, intent.clone())?;
        let encoded = ceremony.encoded_challenge()?;
        let time = source.qualify_time(&mut self, operation("issue", &intent, &encoded)?)?;
        let created_at = i64::try_from(time.lower.as_secs())?;
        let expires_at = created_at
            .checked_add(300)
            .context("restore_approval_clock_overflow")?;
        let sqlite = self.sqlite.as_mut().context("restore_auth_sqlite_closed")?;
        let requested = ceremony.issue_durable(
            &mut self.reader,
            (sqlite, &mut self.files),
            &intent,
            (created_at, expires_at),
        );
        let checked = self.check(&intent);
        let challenge = requested?;
        checked?;
        source.finish_checked(&mut self)?;
        self.finish_checked()?;
        Ok(PendingApproval {
            ceremony,
            intent,
            challenge,
            created_at,
            expires_at,
        })
    }

    fn capture_source(&mut self) -> Result<NativeApprovalSource> {
        let intent = self.intent.clone();
        self.check(&intent)?;
        let requested = self
            .reader
            .loan
            .physical
            .as_mut()
            .context("restore_auth_reader_closed")?
            .capture_approval_source(&self.reader.loan.selection.scope);
        let checked = self.check(&intent);
        let mut source = requested?;
        checked?;
        self.check_approval_source(&mut source)?;
        Ok(source)
    }

    /// Closed mutual check; exports no phase, stage, SQL or provider handle.
    pub(in crate::security_epoch) fn check_approval_source(
        &mut self,
        source: &mut NativeApprovalSource,
    ) -> Result<()> {
        let intent = self.intent.clone();
        self.check(&intent)?;
        let requested = source.check_phase(
            self.reader
                .loan
                .physical
                .as_mut()
                .context("restore_auth_reader_closed")?,
        );
        let checked = self.check(&intent);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn approval_clock_data(
        &mut self,
        clock: &mut UnfencedControllerClock,
    ) -> Result<HostTimeData> {
        let intent = self.intent.clone();
        self.check(&intent)?;
        let observed = clock.observe(
            self.reader
                .loan
                .physical
                .as_mut()
                .context("restore_auth_reader_closed")?,
        );
        let checked = self.check(&intent);
        if observed.is_err() || checked.is_err() {
            self.refuse();
        }
        let value = observed?;
        checked?;
        Ok(value)
    }

    pub(in crate::security_epoch) fn approval_snapshot_data(
        &mut self,
        source: &mut NativeApprovalSource,
    ) -> Result<(EpochStore, Snapshot)> {
        self.check_approval_source(source)?;
        Ok((
            self.reader.loan.selection.clone(),
            self.reader.loan.observed.snapshot().clone(),
        ))
    }
}

impl PendingApproval {
    pub(in crate::security_epoch) fn challenge_data(&self) -> Result<String> {
        self.ceremony.encoded_challenge()
    }

    pub(in crate::security_epoch) fn approve<'metadata, 'storage, 'role>(
        self,
        mut action: RestoreAuthenticationAction<'metadata, 'storage, 'role>,
        assertion: &Assertion,
    ) -> Result<Option<SignedApprovalRecord>> {
        self.intent.require_exact(&action.intent)?;
        let source = action.capture_source()?;
        let Some((mut completed, mut source)) =
            CompletedCeremony::prepare(self, action, assertion, source)?
        else {
            return Ok(None);
        };
        completed.mark_may()?;
        let record = source.sign_completed(&mut completed)?;
        source.publish_completed(&mut completed, &record)?;
        completed.record_publication(&record)?;
        let action = completed
            .action
            .as_mut()
            .context("restore_approval_action_closed")?;
        source.finish_checked(action)?;
        completed
            .action
            .take()
            .context("restore_approval_action_closed")?
            .finish_checked()?;
        Ok(Some(record))
    }
}

impl<'metadata, 'storage, 'role> CompletedCeremony<'metadata, 'storage, 'role> {
    fn prepare(
        pending: PendingApproval,
        mut action: RestoreAuthenticationAction<'metadata, 'storage, 'role>,
        assertion: &Assertion,
        mut source: NativeApprovalSource,
    ) -> Result<Option<(Self, NativeApprovalSource)>> {
        action.check(&pending.intent)?;
        let before = source.current_time(&mut action)?;
        let at = seconds_ceiling(before.upper)?;
        ensure!(
            pending.created_at <= at && at < pending.expires_at,
            "restore_approval_ceremony_expired_or_rewound"
        );
        let requested = pending.ceremony.complete_durable(
            &mut action.reader,
            (
                action
                    .sqlite
                    .as_mut()
                    .context("restore_auth_sqlite_closed")?,
                &mut action.files,
            ),
            &pending.challenge,
            (&pending.intent, at, assertion),
        );
        let checked = action.check(&pending.intent);
        let verified = requested?;
        checked?;
        let Some(facts) = verified else {
            source.finish_checked(&mut action)?;
            action.finish_checked()?;
            return Ok(None);
        };
        let time_operation = operation("approve", &pending.intent, pending.challenge.as_str())?;
        let frozen = source.qualify_time(&mut action, time_operation.clone())?;
        ensure!(
            seconds_ceiling(frozen.upper)? < pending.expires_at,
            "restore_approval_ceremony_expired"
        );
        let request = pending
            .intent
            .request_data(i64::try_from(frozen.lower.as_secs())?)?;
        let (statement, signing) =
            pending
                .ceremony
                .statement_data(&mut action.reader, &request, assertion)?;
        let requested = pending.ceremony.signing_unit(
            &mut action.reader,
            (
                action
                    .sqlite
                    .as_mut()
                    .context("restore_auth_sqlite_closed")?,
                &mut action.files,
            ),
            &pending.challenge,
            SigningUnit::Prepare {
                statement: &statement,
                counter: facts.counter_data(),
            },
        );
        let checked = action.check(&pending.intent);
        requested?;
        checked?;
        Ok(Some((
            Self {
                action: Some(action),
                ceremony: pending.ceremony,
                assertion: assertion.clone(),
                challenge: pending.challenge,
                time_operation,
                statement,
                signing,
                state: SigningState::Prepared,
            },
            source,
        )))
    }

    fn mark_may(&mut self) -> Result<()> {
        ensure!(
            self.state == SigningState::Prepared,
            "restore_approval_attempt_spent"
        );
        let action = self
            .action
            .as_mut()
            .context("restore_approval_action_closed")?;
        let requested = self.ceremony.signing_unit(
            &mut action.reader,
            (
                action
                    .sqlite
                    .as_mut()
                    .context("restore_auth_sqlite_closed")?,
                &mut action.files,
            ),
            &self.challenge,
            SigningUnit::MaySign {
                statement: &self.statement,
            },
        );
        let checked = action.check(&self.statement.request.intent());
        requested?;
        checked?;
        self.state = SigningState::MaySign;
        Ok(())
    }

    pub(in crate::security_epoch) fn check_signing_source(
        &mut self,
        source: &mut NativeApprovalSource,
    ) -> Result<()> {
        ensure!(
            self.state == SigningState::MaySign,
            "restore_approval_signing_phase_changed"
        );
        let action = self
            .action
            .as_mut()
            .context("restore_approval_action_closed")?;
        action.check_approval_source(source)?;
        source.require_qualified(&self.time_operation)?;
        let now = source.current_time(action)?;
        ensure!(
            Duration::from_secs(u64::try_from(self.statement.request.approved_at)?) <= now.lower
                && now.upper
                    < Duration::from_secs(u64::try_from(self.statement.request.expires_at)?),
            "restore_approval_expired_or_rewound"
        );
        let current = self.ceremony.statement_data(
            &mut action.reader,
            &self.statement.request,
            &self.assertion,
        )?;
        ensure!(
            current.0 == self.statement && current.1 == self.signing,
            "restore_approval_current_selection_changed"
        );
        let requested = self.ceremony.signing_unit(
            &mut action.reader,
            (
                action
                    .sqlite
                    .as_mut()
                    .context("restore_auth_sqlite_closed")?,
                &mut action.files,
            ),
            &self.challenge,
            SigningUnit::CheckMay {
                statement: &self.statement,
            },
        );
        let checked = action.check(&self.statement.request.intent());
        requested?;
        checked?;
        action.check_approval_source(source)
    }

    pub(in crate::security_epoch) fn signing_data(
        &self,
    ) -> Result<(KeySelection, ApprovalStatement)> {
        ensure!(
            self.state == SigningState::MaySign,
            "restore_approval_signing_phase_changed"
        );
        Ok((self.signing.clone(), self.statement.clone()))
    }

    pub(in crate::security_epoch) fn check_publication_source(
        &mut self,
        source: &mut NativeApprovalSource,
    ) -> Result<(EpochStore, Snapshot)> {
        self.check_signing_source(source)?;
        self.action
            .as_mut()
            .context("restore_approval_action_closed")?
            .approval_snapshot_data(source)
    }

    fn record_publication(&mut self, record: &SignedApprovalRecord) -> Result<()> {
        ensure!(
            record.statement == self.statement,
            "restore_approval_signed_statement_changed"
        );
        record.verify_signature_data(&self.statement, &self.signing)?;
        let action = self
            .action
            .as_mut()
            .context("restore_approval_action_closed")?;
        let requested = self.ceremony.signing_unit(
            &mut action.reader,
            (
                action
                    .sqlite
                    .as_mut()
                    .context("restore_auth_sqlite_closed")?,
                &mut action.files,
            ),
            &self.challenge,
            SigningUnit::Published { record },
        );
        let checked = action.check(&self.statement.request.intent());
        requested?;
        checked?;
        self.state = SigningState::Published;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use syn::{
        Expr, ImplItem, Item,
        visit::{self, Visit},
    };

    #[derive(Default)]
    struct Calls(Vec<String>);

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.0.push(node.method.to_string());
            visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Expr::Path(path) = node.func.as_ref()
                && let Some(last) = path.path.segments.last()
            {
                self.0.push(last.ident.to_string());
            }
            visit::visit_expr_call(self, node);
        }

        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            if node.path.is_ident("Self") {
                self.0.push("construct_self".into());
            }
            visit::visit_expr_struct(self, node);
        }
    }

    fn calls(source: &str, method: &str) -> Option<Vec<String>> {
        let file = syn::parse_file(source).ok()?;
        let functions = file
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Impl(item) => Some(item),
                _ => None,
            })
            .flat_map(|i| &i.items)
            .filter_map(|i| match i {
                ImplItem::Fn(f) if f.sig.ident == method => Some(f),
                _ => None,
            })
            .collect::<Vec<_>>();
        if functions.len() != 1 {
            return None;
        }
        let mut collected = Calls::default();
        collected.visit_block(&functions[0].block);
        Some(collected.0)
    }

    fn ordered(actual: &[String], required: &[&str]) -> bool {
        let mut tail = actual;
        for name in required {
            let Some(index) = tail.iter().position(|v| v == name) else {
                return false;
            };
            tail = &tail[index + 1..];
        }
        true
    }

    fn producer_wiring(source: &str) -> bool {
        let Some(prepare) = calls(source, "prepare") else {
            return false;
        };
        let Some(approve) = calls(source, "approve") else {
            return false;
        };
        let Some(check) = calls(source, "check_signing_source") else {
            return false;
        };
        let Some(issue) = calls(source, "issue_approval") else {
            return false;
        };
        ordered(
            &prepare,
            &[
                "complete_durable",
                "check",
                "qualify_time",
                "request_data",
                "statement_data",
                "signing_unit",
                "check",
                "construct_self",
            ],
        ) && ordered(
            &approve,
            &[
                "prepare",
                "mark_may",
                "sign_completed",
                "publish_completed",
                "record_publication",
                "finish_checked",
                "finish_checked",
            ],
        ) && ordered(
            &check,
            &[
                "check_approval_source",
                "require_qualified",
                "current_time",
                "statement_data",
                "signing_unit",
                "check",
                "check_approval_source",
            ],
        ) && ordered(
            &issue,
            &[
                "capture_source",
                "capture",
                "qualify_time",
                "issue_durable",
                "check",
                "finish_checked",
                "finish_checked",
            ],
        ) && prepare.iter().filter(|v| *v == "construct_self").count() == 1
            && approve.iter().filter(|v| *v == "sign_completed").count() == 1
    }

    #[test]
    fn actual_producer_requires_known_uv_time_and_attempt_commit_before_signing_and_terminal_close()
    {
        let source = include_str!("producer.rs");
        assert!(producer_wiring(source));
        // Each mutant edits an actual production call, leaving Rust parseable.
        for (from, to) in [
            (
                "pending.ceremony.complete_durable(",
                "pending.ceremony.verify_without_consumption(",
            ),
            (
                "source.qualify_time(&mut action, time_operation.clone())?",
                "source.unqualified_time(&mut action, time_operation.clone())?",
            ),
            ("completed.mark_may()?", "completed.skip_attempt_commit()?"),
            (
                "source.publish_completed(&mut completed, &record)?",
                "source.skip_publication(&mut completed, &record)?",
            ),
            (
                "source.finish_checked(action)?",
                "source.skip_final_source(action)?",
            ),
            (".statement_data(", ".stale_statement_data("),
        ] {
            assert!(source.contains(from), "mutation target {from}");
            assert!(
                !producer_wiring(&source.replacen(from, to, 1)),
                "accepted {from}"
            );
        }
        let prepare = calls(source, "prepare").unwrap();
        // No read/recovery method can create the only private completed owner.
        assert_eq!(prepare.iter().filter(|v| *v == "construct_self").count(), 1);
    }
}
