//! Fixed accepting-executor authentication. A human continuation contains only
//! ceremony DATA; the authenticated result retains its actual reader, auth-store
//! handles, qualified time and original. It is NOT a consumed grant, complete
//! rights stop, Fenced completion, staged creator or restored writer.
use super::super::super::RestoreExecutionReader;
use super::super::RestoreAuthenticationAction;
use super::seconds_ceiling;
use crate::security_epoch::{
    restore_approval::signed::SignedApprovalRecord,
    restore_host_clock::HostTimeData,
    restore_original::{RestoreObservation, RestoreOriginalGuard},
    restore_webauthn::{Assertion, ControllerExecutionCeremony, ExecutionCompletion},
    storage_authority::NativeApprovalSource,
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::Digest;
use std::time::Duration;

const EXECUTION_CHALLENGE_SECONDS: i64 = 300;

/// Server-owned one-attempt challenge, never current authority across the wait.
pub(in crate::security_epoch) struct PendingRestoreExecution {
    ceremony: ControllerExecutionCeremony,
    record: SignedApprovalRecord,
    operation: Digest,
    challenge: Digest,
    created_at: i64,
    expires_at: i64,
}

/// The genuine UV result owns, rather than projects, its actual three source
/// lifetimes. No boolean, signature, row or old receipt can create this type.
/// Abandonment drops the actual action/file lease, unfinished native source
/// and original guard; their existing terminal destructors remain responsible.
/// This carrier neither finishes them nor publishes a positive disposition.
pub(in crate::security_epoch) struct AuthenticatedRestoreExecution<'metadata, 'storage, 'role> {
    action: RestoreAuthenticationAction<'metadata, 'storage, 'role>,
    source: NativeApprovalSource,
    original: RestoreOriginalGuard,
    completion: ExecutionCompletion,
    record: SignedApprovalRecord,
    operation: Digest,
    time_operation: Digest,
    refused: bool,
}

fn time_operation(
    kind: &str,
    record: &SignedApprovalRecord,
    operation: &Digest,
    challenge: &str,
) -> Result<Digest> {
    Digest::of(&(
        "day2-restore-executor-time-v1",
        kind,
        record,
        operation,
        challenge,
    ))
}

fn approval_window(record: &SignedApprovalRecord, time: &HostTimeData) -> Result<i64> {
    record.statement.validate()?;
    let request = &record.statement.request;
    ensure!(
        time.lower <= time.upper
            && time.lower >= Duration::from_secs(request.approved_at.try_into()?)
            && time.upper < Duration::from_secs(request.expires_at.try_into()?),
        "restore_executor_approval_expired_or_rewound"
    );
    let at = seconds_ceiling(time.upper)?;
    ensure!(at < request.expires_at, "restore_executor_approval_expired");
    Ok(at)
}

impl RestoreAuthenticationAction<'_, '_, '_> {
    /// Issue a different purpose challenge; approver UV/signature cannot stand
    /// in for the executor's fresh one-use assertion. Same-person policy stays.
    pub(in crate::security_epoch) fn issue_execution(
        mut self,
        record: &SignedApprovalRecord,
        operation: &Digest,
        executor_credential_id: &[u8],
    ) -> Result<PendingRestoreExecution> {
        self.intent.require_request(&record.statement.request)?;
        let mut source = self.capture_source()?;
        let ceremony = ControllerExecutionCeremony::capture(
            &mut self.reader,
            executor_credential_id,
            record,
            operation,
        )?;
        let encoded = ceremony.encoded_challenge()?;
        let time = source.qualify_time(
            &mut self,
            time_operation("issue", record, operation, &encoded)?,
        )?;
        approval_window(record, &time)?;
        let created_at = i64::try_from(time.lower.as_secs())?;
        let expires_at = created_at
            .checked_add(EXECUTION_CHALLENGE_SECONDS)
            .context("restore_executor_clock_overflow")?
            .min(record.statement.request.expires_at);
        ensure!(
            seconds_ceiling(time.upper)? < expires_at,
            "restore_executor_challenge_expired"
        );
        let requested = ceremony.issue_durable(
            &mut self.reader,
            (
                self.sqlite.as_mut().context("restore_auth_sqlite_closed")?,
                &mut self.files,
            ),
            (created_at, expires_at),
        );
        let checked = self.check(&record.statement.request.intent());
        let challenge = requested?;
        checked?;
        source.finish_checked(&mut self)?;
        self.finish_checked()?;
        Ok(PendingRestoreExecution {
            ceremony,
            record: record.clone(),
            operation: operation.clone(),
            challenge,
            created_at,
            expires_at,
        })
    }

    // No stage/getter/callback: only check the pre-reader guard against this
    // action's existing physical phase and exact full request/operation.
    fn check_execution_original(
        &mut self,
        original: &mut RestoreOriginalGuard,
        record: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<RestoreObservation> {
        let intent = record.statement.request.intent();
        let requested = (|| {
            self.check(&intent)?;
            original.check_join(
                self.reader
                    .loan
                    .physical
                    .as_mut()
                    .context("restore_auth_reader_closed")?
                    .controller_stage()?,
                &record.statement.request,
                operation,
            )
        })();
        let checked = self.check(&intent);
        if requested.is_err() || checked.is_err() {
            original.refuse();
            self.refuse();
        }
        let observation = requested?;
        checked?;
        Ok(observation)
    }
}

impl PendingRestoreExecution {
    pub(in crate::security_epoch) fn challenge_data(&self) -> Result<String> {
        self.ceremony.encoded_challenge()
    }

    pub(in crate::security_epoch) fn authenticate<'metadata, 'storage, 'role>(
        self,
        mut input: RestoreExecutionReader<'metadata, 'storage, 'role>,
        assertion: &Assertion,
    ) -> Result<Option<AuthenticatedRestoreExecution<'metadata, 'storage, 'role>>> {
        ensure!(
            input.record == self.record && input.operation == self.operation,
            "restore_executor_input_changed"
        );
        input.reader.check_execution_original(
            &mut input.original,
            &self.record,
            &self.operation,
        )?;
        let mut action = input
            .reader
            .admit_restore_authentication(&self.record.statement.request.intent())?;
        action.check_execution_original(&mut input.original, &self.record, &self.operation)?;
        let mut source = action.capture_source()?;
        let before = source.current_time(&mut action)?;
        let at = approval_window(&self.record, &before)?;
        ensure!(
            self.created_at <= at && at < self.expires_at,
            "restore_executor_challenge_expired_or_rewound"
        );
        let verified = self.ceremony.complete_durable(
            &mut action.reader,
            (
                action
                    .sqlite
                    .as_mut()
                    .context("restore_auth_sqlite_closed")?,
                &mut action.files,
            ),
            &self.challenge,
            at,
            assertion,
        );
        let checked =
            action.check_execution_original(&mut input.original, &self.record, &self.operation);
        let verified = verified?;
        checked?;
        let Some(completion) = verified else {
            source.finish_checked(&mut action)?;
            action.finish_checked()?;
            return Ok(None);
        };
        let time_operation = time_operation(
            "authenticate",
            &self.record,
            &self.operation,
            self.challenge.as_str(),
        )?;
        let time = source.qualify_time(&mut action, time_operation.clone())?;
        let at = approval_window(&self.record, &time)?;
        ensure!(
            self.created_at <= at && at < self.expires_at,
            "restore_executor_challenge_expired_or_rewound"
        );
        let mut owner = AuthenticatedRestoreExecution {
            action,
            source,
            original: input.original,
            completion,
            record: self.record,
            operation: self.operation,
            time_operation,
            refused: false,
        };
        owner.check()?;
        Ok(Some(owner))
    }
}

impl AuthenticatedRestoreExecution<'_, '_, '_> {
    /// Fresh current registry, exact signer and executor, qualified original
    /// time/floor and physical checks; no renewal, reauthentication or replay.
    pub(in crate::security_epoch) fn check(&mut self) -> Result<RestoreObservation> {
        let requested = (|| {
            ensure!(!self.refused, "restore_executor_refused");
            self.action.check_execution_original(
                &mut self.original,
                &self.record,
                &self.operation,
            )?;
            self.completion.check_current(
                &mut self.action.reader,
                (
                    self.action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.action.files,
                ),
                &self.record,
                &self.operation,
            )?;
            self.source.require_qualified(&self.time_operation)?;
            let time = self.source.current_time(&mut self.action)?;
            approval_window(&self.record, &time)?;
            Ok(())
        })();
        // A primary verification/time failure does not bypass this SAME held
        // original's mandatory postcheck. Preserve the first failure.
        let checked =
            self.action
                .check_execution_original(&mut self.original, &self.record, &self.operation);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.original.refuse();
        self.action.refuse();
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ =
                <AuthenticatedRestoreExecution<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <PendingRestoreExecution as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use syn::visit::Visit as _;

    #[test]
    fn execution_never_renews_the_grant_hour_or_accepts_deadline_equality() -> Result<()> {
        let (_, record) = crate::security_epoch::restore_approval::fixture_publication_data()?;
        let start = record.statement.request.approved_at as u64;
        let end = record.statement.request.expires_at as u64;
        let sample = |lower, upper| HostTimeData {
            domain: Digest::new(b"controlled-time-data"),
            lower: Duration::from_secs(lower),
            upper: Duration::from_secs(upper),
            observed_at: Duration::from_secs(9),
        };
        assert_eq!(
            approval_window(&record, &sample(start, start))?,
            start as i64
        );
        assert_eq!(
            approval_window(&record, &sample(end - 1, end - 1))?,
            (end - 1) as i64
        );
        assert!(approval_window(&record, &sample(end - 1, end)).is_err());
        assert!(approval_window(&record, &sample(end, end)).is_err());
        assert!(approval_window(&record, &sample(start - 1, start)).is_err());
        assert!(approval_window(&record, &sample(start + 1, start)).is_err());
        let mut fractional = sample(end - 1, end - 1);
        fractional.upper += Duration::from_nanos(1);
        // SQLite ceremony time is conservatively rounded up; no sub-second
        // tail can turn equality into a fresh execution permission.
        assert!(approval_window(&record, &fractional).is_err());
        Ok(())
    }

    fn authenticating_source(source: &str) -> Result<bool> {
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'ast> syn::visit::Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
                self.0.push(expression.method.to_string());
                syn::visit::visit_expr_method_call(self, expression);
            }
        }
        let file = syn::parse_file(source)?;
        let methods: Vec<_> = file.items.iter().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(p) if p.path.is_ident("PendingRestoreExecution")) => Some(item),
            _ => None,
        }).flat_map(|item| item.items.iter()).filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "authenticate" => Some(item),
            _ => None,
        }).collect();
        if methods.len() != 1 {
            return Ok(false);
        }
        let method = methods[0];
        if !method
            .sig
            .to_token_stream()
            .to_string()
            .contains("RestoreExecutionReader")
        {
            return Ok(false);
        }
        let mut calls = Calls::default();
        calls.visit_block(&method.block);
        let sequence: Vec<_> = calls
            .0
            .iter()
            .filter(|call| {
                matches!(
                    call.as_str(),
                    "check_execution_original"
                        | "admit_restore_authentication"
                        | "capture_source"
                        | "current_time"
                        | "complete_durable"
                        | "qualify_time"
                        | "check"
                )
            })
            .map(String::as_str)
            .collect();
        let body = method.block.to_token_stream().to_string();
        Ok(sequence
            == [
                "check_execution_original",
                "admit_restore_authentication",
                "check_execution_original",
                "capture_source",
                "current_time",
                "complete_durable",
                "check_execution_original",
                "qualify_time",
                "check",
            ]
            && body.contains("let verified = verified ? ; checked ? ;")
            && body.contains("let Some (completion) = verified else")
            && body.contains("return Ok (None)"))
    }

    #[test]
    fn actual_accepting_path_requires_fresh_uv_and_preserves_postchecks_before_owner() -> Result<()>
    {
        let source = include_str!("consumer.rs");
        assert!(authenticating_source(source)?);
        for (from, to) in [
            (
                "RestoreExecutionReader<'metadata, 'storage, 'role>",
                "RestoreAuthenticationAction<'metadata, 'storage, 'role>",
            ),
            (
                "self.ceremony.complete_durable(",
                "self.ceremony.unverified(",
            ),
            ("let verified = verified?;", "let verified = Some(());"),
            (
                "        checked?;\n        let Some(completion) = verified",
                "        let Some(completion) = verified",
            ),
            (
                "source.qualify_time(&mut action, time_operation.clone())?",
                "source.current_time(&mut action)?",
            ),
        ] {
            let changed = source.replacen(from, to, 1);
            assert_ne!(source, changed, "actual target {from}");
            assert!(!authenticating_source(&changed)?, "must refuse {from}");
        }
        Ok(())
    }
}
