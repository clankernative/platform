//! One accepted operation original. Routing clones share the actual slot;
//! no selection DATA or later callback can replace its clock or native owner.

use super::{NativeSelection, OWNERS};
use crate::security_epoch::native_enrollment::{
    AdmissionWorkSnapshotData, EnrolledCurrentRequest, EnrolledProcessRoleOwner,
    EnrolledRequestDiagnosticData, EnrolledRoleStage, NativeRole, UnselectedShellRequest,
    cumulative_admission_work_data,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use serde::Serialize;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Entry {
    Http,
    Autonomous,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Boundary {
    Captured,
    ShellBound,
    CallbackBorrowed,
    CallbackReturned,
    ResponseLeased,
    ResponseBorrowed,
    Completed,
    Refused,
}

struct Diagnostic {
    entry: Entry,
    native: EnrolledRequestDiagnosticData,
    baseline: AdmissionWorkSnapshotData,
}

const JOIN_BYTES: usize = 8192;
static JOIN_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_join_sequence(sequence: &std::sync::atomic::AtomicU64) -> Option<u64> {
    use std::sync::atomic::Ordering;
    sequence
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
            previous.checked_add(1)
        })
        .ok()
        .and_then(|previous| previous.checked_add(1))
}

// Pure serialization also serves DATA-only tests. Only emit_join below supplies
// production material, obtained directly from the actual enrolled request/stage.
fn join_line(
    entry: Entry,
    boundary: Boundary,
    sequence: Option<u64>,
    native: &impl Serialize,
    before: &impl Serialize,
    now: &impl Serialize,
) -> Option<Vec<u8>> {
    #[derive(Serialize)]
    struct Record<'a, T, B, A> {
        format: &'static str,
        sequence: Option<u64>,
        entry: Entry,
        boundary: Boundary,
        native: &'a T,
        admission_before: &'a B,
        admission_now: &'a A,
    }
    let record = Record {
        format: "day2_native_request_join_v1",
        sequence,
        entry,
        boundary,
        native,
        admission_before: before,
        admission_now: now,
    };
    let json = serde_json::to_string(&record).ok()?;
    let line = format!("day2-native-request-join {json}\n");
    (line.len() <= JOIN_BYTES).then(|| line.into_bytes())
}

fn emit_join(
    entry: Entry,
    boundary: Boundary,
    native: Option<&EnrolledRequestDiagnosticData>,
    baseline: &AdmissionWorkSnapshotData,
) {
    use std::io::Write;
    let mut output = std::io::stderr().lock();
    let now = cumulative_admission_work_data();
    let sequence = next_join_sequence(&JOIN_SEQUENCE);
    let Some(line) = join_line(entry, boundary, sequence, &native, baseline, &now) else {
        return;
    };
    // Historical DATA, never a permission or successful-delivery oracle. Loss,
    // overflow, missing joins and null native fields remain UNKNOWN to readers.
    // Export does not check/sample authority, replace an original or alter its
    // result. No actor, HTTP path, provider value or token enters this record.
    let _ = output.write_all(&line);
}

// Capturing is already an attempt. Failure or unwind cannot return to Empty
// and obtain a later origin for the same accepted operation.
enum Slot<T> {
    Empty,
    Capturing,
    Live(T),
    Leased,
    Complete,
    Refused,
}

impl<T> Slot<T> {
    fn begin(&mut self) -> Result<()> {
        ensure!(
            matches!(self, Self::Empty),
            "native request already attempted"
        );
        *self = Self::Capturing;
        Ok(())
    }

    fn install(&mut self, value: T) -> Result<()> {
        ensure!(
            matches!(self, Self::Capturing),
            "native request capture refused"
        );
        *self = Self::Live(value);
        Ok(())
    }

    fn take(&mut self) -> Result<T> {
        ensure!(matches!(self, Self::Live(_)), "native request unavailable");
        let Self::Live(value) = std::mem::replace(self, Self::Leased) else {
            unreachable!("exclusive checked live slot")
        };
        Ok(value)
    }

    fn complete(&mut self) -> Result<()> {
        ensure!(
            matches!(self, Self::Leased),
            "native request completion refused"
        );
        *self = Self::Complete;
        Ok(())
    }

    fn refuse(&mut self) {
        if !matches!(self, Self::Complete) {
            *self = Self::Refused;
        }
    }
}

enum Original {
    Selected {
        scope: AuthorityScope,
        kind: NativeRole,
        entry: Entry,
        baseline: AdmissionWorkSnapshotData,
        current: EnrolledCurrentRequest,
    },
    Shell {
        start: UnselectedShellRequest,
        baseline: AdmissionWorkSnapshotData,
    },
    // A sealed literal producer supplies no application or native authority.
    LiteralHealth,
    // An explicitly non-native profile has no enrolled role to borrow. This
    // records transport lifetime only and can never bind or lease authority.
    NonNative,
    #[cfg(test)]
    Model(ModelOriginal),
}

impl Original {
    fn require(&self, scope: &AuthorityScope, kind: NativeRole) -> Result<()> {
        let Self::Selected {
            scope: selected,
            kind: actual,
            ..
        } = self
        else {
            anyhow::bail!("native request not bound")
        };
        ensure!(
            selected == scope && *actual == kind,
            "native request scope changed"
        );
        Ok(())
    }
}

fn refuse_with_evidence(slot: &mut Slot<Original>) {
    match std::mem::replace(slot, Slot::Refused) {
        Slot::Live(Original::Selected {
            entry,
            current,
            baseline,
            ..
        }) => {
            let native = current.historical_diagnostic_data();
            drop(current);
            emit_join(entry, Boundary::Refused, Some(&native), &baseline);
        }
        Slot::Complete => *slot = Slot::Complete,
        _ => {}
    }
}

/// A routing handle to one slot, never a clone of its actual native original.
/// A second callback cannot take an original held by the response lease.
pub(super) struct Request {
    slot: Rc<RefCell<Slot<Original>>>,
    refused: Rc<Cell<bool>>,
}

impl Clone for Request {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
            refused: self.refused.clone(),
        }
    }
}

impl Request {
    pub(super) fn new() -> Self {
        Self {
            slot: Rc::new(RefCell::new(Slot::Empty)),
            refused: Rc::new(Cell::new(false)),
        }
    }

    pub(super) fn capture_app(&self, scope: &AuthorityScope, entry: Entry) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        let baseline = cumulative_admission_work_data();
        let acquired = OWNERS.with(|owners| {
            let mut owners = owners.try_borrow_mut()?;
            let owners = owners
                .get_mut(scope.app.as_str())
                .context("native request App missing")?;
            ensure!(
                owners.kind == NativeRole::AppHost && owners.selection.scope() == scope,
                "native request App selection changed"
            );
            let mut role = owners.role.try_borrow_mut()?;
            role.begin_current_request()
        });
        match acquired {
            Ok(current) => {
                slot.install(Original::Selected {
                    scope: scope.clone(),
                    kind: NativeRole::AppHost,
                    entry,
                    baseline,
                    current,
                })?;
                let Slot::Live(Original::Selected {
                    current, baseline, ..
                }) = &*slot
                else {
                    unreachable!("exclusive installed request")
                };
                emit_join(
                    entry,
                    Boundary::Captured,
                    Some(&current.historical_diagnostic_data()),
                    baseline,
                );
                Ok(())
            }
            Err(error) => {
                slot.refuse();
                Err(error)
            }
        }
    }

    pub(super) fn capture_shell(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        let baseline = cumulative_admission_work_data();
        match UnselectedShellRequest::capture() {
            Ok(start) => slot.install(Original::Shell { start, baseline }),
            Err(error) => {
                slot.refuse();
                Err(error)
            }
        }
    }

    pub(super) fn capture_literal_health(
        &self,
        response: &crate::web::NativeResponse,
    ) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        ensure!(
            response.is_literal_health(),
            "native literal response required"
        );
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        slot.install(Original::LiteralHealth)
    }

    pub(super) fn capture_non_native(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        slot.install(Original::NonNative)
    }

    pub(super) fn with_stage<T>(
        &self,
        role: &mut EnrolledProcessRoleOwner,
        selection: &NativeSelection,
        kind: NativeRole,
        operation: impl FnOnce(EnrolledRoleStage<'_>) -> Result<T>,
    ) -> Result<T> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        if matches!(*slot, Slot::Live(Original::Shell { .. })) {
            ensure!(
                kind == NativeRole::SecurityShell,
                "native Shell request role changed"
            );
            let Original::Shell { start, baseline } = slot.take()? else {
                unreachable!("exclusive checked Shell original")
            };
            let current = match role.bind_shell_request(start) {
                Ok(current) => current,
                Err(error) => {
                    slot.refuse();
                    return Err(error);
                }
            };
            *slot = Slot::Live(Original::Selected {
                scope: selection.scope().clone(),
                kind,
                entry: Entry::Http,
                baseline,
                current,
            });
            if let Slot::Live(Original::Selected {
                current,
                entry,
                baseline,
                ..
            }) = &*slot
            {
                emit_join(
                    *entry,
                    Boundary::ShellBound,
                    Some(&current.historical_diagnostic_data()),
                    baseline,
                );
            }
        }
        let Slot::Live(original) = &mut *slot else {
            anyhow::bail!("native request unavailable")
        };
        // Exclude a foreign caller before observing or poisoning the winner.
        original.require(selection.scope(), kind)?;
        let Original::Selected {
            current,
            entry,
            baseline,
            ..
        } = original
        else {
            unreachable!("checked selected request")
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut stage = role.borrow_current_request(current)?;
            emit_join(
                *entry,
                Boundary::CallbackBorrowed,
                stage
                    .diagnostic_progress()
                    .historical_request_binding_data()
                    .ok()
                    .as_ref(),
                baseline,
            );
            stage.check_selection(&selection.policy, &selection.store, kind)?;
            let value = operation(stage)?;
            ensure!(
                !self.refused.get(),
                "native request refused during callback"
            );
            // Reborrow the SAME original for final identity/clock checks. The
            // prior callback's actual stage has ended; no new clock is begun.
            emit_join(
                *entry,
                Boundary::CallbackReturned,
                Some(&current.historical_diagnostic_data()),
                baseline,
            );
            role.borrow_current_request(current)?.check_selection(
                &selection.policy,
                &selection.store,
                kind,
            )?;
            Ok(value)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    refuse_with_evidence(&mut slot);
                }
                result
            }
            Err(panic) => {
                refuse_with_evidence(&mut slot);
                std::panic::resume_unwind(panic)
            }
        }
    }

    pub(super) fn take(&self, scope: &AuthorityScope, kind: NativeRole) -> Result<Lease> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        let Slot::Live(original) = &*slot else {
            anyhow::bail!("native request unavailable")
        };
        original.require(scope, kind)?;
        let Original::Selected {
            current,
            entry,
            baseline,
            ..
        } = slot.take()?
        else {
            unreachable!("checked selected request")
        };
        let native = current.historical_diagnostic_data();
        let lease = Lease {
            held: Held {
                slot: self.slot.clone(),
                refused: self.refused.clone(),
                current: Some(current),
                diagnostic: Some(Diagnostic {
                    entry,
                    native,
                    baseline,
                }),
            },
        };
        if let Some(data) = &lease.held.diagnostic {
            emit_join(
                data.entry,
                Boundary::ResponseLeased,
                Some(&data.native),
                &data.baseline,
            );
        }
        Ok(lease)
    }

    pub(super) fn finish(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let original = self.slot.try_borrow_mut()?.take()?;
        let (result, diagnostic) = match original {
            Original::LiteralHealth | Original::NonNative => (Ok(()), None),
            Original::Shell { start, .. } => (start.finish(), None),
            Original::Selected {
                scope,
                kind,
                entry,
                baseline,
                current,
            } => {
                let native = current.historical_diagnostic_data();
                let result = OWNERS.with(|owners| {
                    let mut owners = owners.try_borrow_mut()?;
                    let owners = owners
                        .get_mut(scope.app.as_str())
                        .context("native request owner missing")?;
                    ensure!(
                        owners.kind == kind && owners.selection.scope() == &scope,
                        "native request final owner changed"
                    );
                    let mut role = owners.role.try_borrow_mut()?;
                    current.finish(&mut role)
                });
                (
                    result,
                    Some(Diagnostic {
                        entry,
                        native,
                        baseline,
                    }),
                )
            }
            #[cfg(test)]
            Original::Model(mut model) => (model.check(), None),
        };
        let mut slot = self.slot.try_borrow_mut()?;
        if let Err(error) = result {
            if let Some(data) = &diagnostic {
                emit_join(
                    data.entry,
                    Boundary::Refused,
                    Some(&data.native),
                    &data.baseline,
                );
            }
            slot.refuse();
            return Err(error);
        }
        ensure!(
            !self.refused.get(),
            "native request refused during completion"
        );
        slot.complete()?;
        if let Some(data) = &diagnostic {
            emit_join(
                data.entry,
                Boundary::Completed,
                Some(&data.native),
                &data.baseline,
            );
        }
        Ok(())
    }

    pub(super) fn refuse(&self) {
        // This latch must work even while a synchronous consumer holds the
        // actual original's RefCell borrow and catches an inner abort error.
        self.refused.set(true);
        if let Ok(mut slot) = self.slot.try_borrow_mut() {
            refuse_with_evidence(&mut slot);
        }
    }

    #[cfg(test)]
    pub(super) fn has_started(&self) -> Result<bool> {
        Ok(!matches!(*self.slot.try_borrow()?, Slot::Empty))
    }

    /// DATA-only test port. It cannot be borrowed as an EnrolledRoleStage.
    #[cfg(test)]
    pub(super) fn capture_model(&self) -> Result<()> {
        ensure!(!self.refused.get(), "scripted request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        slot.install(Original::Model(ModelOriginal::new()))
    }

    #[cfg(test)]
    pub(super) fn model_origin(&self) -> Result<Option<std::time::Duration>> {
        ensure!(!self.refused.get(), "scripted request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        match &mut *slot {
            Slot::Live(Original::Model(model)) => {
                model.check()?;
                model.origin()
            }
            // Lower model tests need not claim an HTTP request. They still
            // cannot construct any actual enrolled role or original.
            Slot::Empty => Ok(None),
            _ => anyhow::bail!("scripted request unavailable"),
        }
    }
}

/// The response future owns this actual original alongside the actual role.
/// No RefCell borrow survives an await and cancellation drops this original.
pub(super) struct Lease {
    held: Held<Original, EnrolledCurrentRequest>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$type as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(super::response::QueryParent<'static, 'static>, Clone);
    assert_not_impl!(super::response::QueryParent<'static, 'static>, Copy);
    assert_not_impl!(super::response::QueryParent<'static, 'static>, Default);
    assert_not_impl!(
        super::response::QueryParent<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(super::response::QueryParent<'static, 'static>, Send);
    assert_not_impl!(super::response::QueryParent<'static, 'static>, Sync);
    assert_not_impl!(
        super::response::QueryParent<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        super::response::QueryParent<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(super::response::QueryLoan<'static, 'static>, Clone);
    assert_not_impl!(super::response::QueryLoan<'static, 'static>, Copy);
    assert_not_impl!(super::response::QueryLoan<'static, 'static>, Default);
    assert_not_impl!(
        super::response::QueryLoan<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(super::response::QueryLoan<'static, 'static>, Send);
    assert_not_impl!(super::response::QueryLoan<'static, 'static>, Sync);
    assert_not_impl!(
        super::response::QueryLoan<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        super::response::QueryLoan<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(super::response::HostRequestOwner<'static, 'static>, Clone);
    assert_not_impl!(super::response::HostRequestOwner<'static, 'static>, Copy);
    assert_not_impl!(super::response::HostRequestOwner<'static, 'static>, Default);
    assert_not_impl!(
        super::response::HostRequestOwner<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(super::response::HostRequestOwner<'static, 'static>, Send);
    assert_not_impl!(super::response::HostRequestOwner<'static, 'static>, Sync);
    assert_not_impl!(
        super::response::HostRequestOwner<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        super::response::HostRequestOwner<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(crate::store::ExecutionSql<'static, 'static, 'static>, Clone);
    assert_not_impl!(crate::store::ExecutionSql<'static, 'static, 'static>, Copy);
    assert_not_impl!(
        crate::store::ExecutionSql<'static, 'static, 'static>,
        Default
    );
    assert_not_impl!(
        crate::store::ExecutionSql<'static, 'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(crate::store::ExecutionSql<'static, 'static, 'static>, Send);
    assert_not_impl!(crate::store::ExecutionSql<'static, 'static, 'static>, Sync);
    assert_not_impl!(
        crate::store::ExecutionSql<'static, 'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        crate::store::ExecutionSql<'static, 'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(Lease, Clone);
    assert_not_impl!(Lease, Copy);
    assert_not_impl!(Lease, Default);
    assert_not_impl!(Lease, std::fmt::Debug);
    assert_not_impl!(Lease, Send);
    assert_not_impl!(Lease, Sync);
    assert_not_impl!(Lease, serde::Serialize);
    assert_not_impl!(Lease, serde::Deserialize<'static>);
    // Routing clones share the same actual value and terminal latch. They
    // cannot cross executors, serialize an original or manufacture a default.
    assert_not_impl!(Request, Default);
    assert_not_impl!(Request, std::fmt::Debug);
    assert_not_impl!(Request, Send);
    assert_not_impl!(Request, Sync);
    assert_not_impl!(Request, serde::Serialize);
    assert_not_impl!(Request, serde::Deserialize<'static>);
};

// Common move/cancellation code is tested with non-authority material. Only
// the native Lease wrapper can expose a stage, and only with a genuine role.
struct Held<S, T> {
    slot: Rc<RefCell<Slot<S>>>,
    refused: Rc<Cell<bool>>,
    current: Option<T>,
    diagnostic: Option<Diagnostic>,
}

impl<S, T> Held<S, T> {
    fn check(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request lease refused");
        ensure!(
            matches!(*self.slot.try_borrow()?, Slot::Leased),
            "native request lease refused"
        );
        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        self.check()?;
        ensure!(self.current.is_none(), "native request still owned");
        self.slot.try_borrow_mut()?.complete()
    }
}

impl Lease {
    /// Copy existing historical labels only, without a native sample/check.
    pub(super) fn historical_diagnostic_data(&self) -> Option<EnrolledRequestDiagnosticData> {
        self.held
            .diagnostic
            .as_ref()
            .map(|data| data.native.clone())
    }

    pub(super) fn borrow<'a>(
        &'a mut self,
        role: &'a mut EnrolledProcessRoleOwner,
    ) -> Result<EnrolledRoleStage<'a>> {
        self.held.check()?;
        let stage = role.borrow_current_request(
            self.held
                .current
                .as_mut()
                .context("native request consumed")?,
        )?;
        if let Some(data) = &self.held.diagnostic {
            emit_join(
                data.entry,
                Boundary::ResponseBorrowed,
                stage
                    .diagnostic_progress()
                    .historical_request_binding_data()
                    .ok()
                    .as_ref(),
                &data.baseline,
            );
        }
        Ok(stage)
    }

    pub(super) fn finish(mut self, role: &mut EnrolledProcessRoleOwner) -> Result<()> {
        self.held.check()?;
        self.held
            .current
            .take()
            .context("native request consumed")?
            .finish(role)?;
        self.held.complete()?;
        if let Some(data) = self.held.diagnostic.take() {
            emit_join(
                data.entry,
                Boundary::Completed,
                Some(&data.native),
                &data.baseline,
            );
        }
        Ok(())
    }
}

impl<S, T> Drop for Held<S, T> {
    fn drop(&mut self) {
        let mut incomplete = true;
        if let Ok(mut slot) = self.slot.try_borrow_mut() {
            incomplete = !matches!(*slot, Slot::Complete);
            if !matches!(*slot, Slot::Complete) {
                self.refused.set(true);
            }
            slot.refuse();
        } else {
            self.refused.set(true);
        }
        drop(self.current.take());
        if incomplete && let Some(data) = self.diagnostic.take() {
            emit_join(
                data.entry,
                Boundary::Refused,
                Some(&data.native),
                &data.baseline,
            );
        }
    }
}

#[cfg(test)]
struct ModelOriginal {
    origin: crate::oauth::effects::Instant,
    latest: crate::oauth::effects::Instant,
    thread: std::thread::ThreadId,
    refused: bool,
}

#[cfg(test)]
impl ModelOriginal {
    fn new() -> Self {
        let origin = crate::oauth::effects::Instant::now();
        Self {
            origin,
            latest: origin,
            thread: std::thread::current().id(),
            refused: false,
        }
    }

    fn check(&mut self) -> Result<()> {
        let now = crate::oauth::effects::Instant::now();
        let elapsed = now.checked_duration_since(self.origin);
        if self.refused
            || self.thread != std::thread::current().id()
            || now.checked_duration_since(self.latest).is_none()
            || elapsed.is_none_or(|elapsed| elapsed >= std::time::Duration::from_secs(5))
        {
            self.refused = true;
            anyhow::bail!("scripted HTTP original expired or changed")
        }
        self.latest = now;
        Ok(())
    }

    fn origin(&self) -> Result<Option<std::time::Duration>> {
        match self.origin {
            crate::oauth::effects::Instant::Simulated { ticks, .. } => Ok(Some(ticks)),
            crate::oauth::effects::Instant::Live(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::effects;
    use std::{
        cell::Cell,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    struct Time {
        domain: u64,
        millis: AtomicU64,
    }
    impl effects::Hooks for Time {
        fn domain(&self) -> u64 {
            self.domain
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(100)
        }
        fn monotonic(&self) -> Duration {
            Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
        fn fill(&self, _: &mut [u8]) -> Result<()> {
            anyhow::bail!("clock model has no entropy")
        }
        fn send(&self, _: reqwest::blocking::Request) -> Result<effects::Response> {
            anyhow::bail!("clock model has no network")
        }
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("clock model has no provider")
        }
    }

    #[test]
    fn diagnostic_sequence_never_wraps_or_turns_overflow_into_zero() {
        let sequence = std::sync::atomic::AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_join_sequence(&sequence), Some(u64::MAX));
        assert_eq!(next_join_sequence(&sequence), None);
        assert_eq!(next_join_sequence(&sequence), None);
        let line = join_line(
            Entry::Http,
            Boundary::Captured,
            None,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
        )
        .unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(line.strip_prefix(b"day2-native-request-join ").unwrap())
                .unwrap();
        assert!(record["sequence"].is_null());
        assert!(record["native"].is_null());
        assert!(record["admission_before"].is_null());
        assert!(record["admission_now"].is_null());
    }

    #[test]
    fn request_join_frames_are_bounded_data_and_preserve_unknown_fields_as_null() {
        // Serialization DATA cannot construct an enrolled request or stage.
        let native = serde_json::json!({"owner_ordinal": null, "request_ordinal": null});
        let before = serde_json::json!({"sequence": 2, "complete": false, "loss": true});
        let now = serde_json::json!({"sequence": 3, "complete": false, "loss": true});
        for (entry, expected) in [(Entry::Http, "http"), (Entry::Autonomous, "autonomous")] {
            let line =
                join_line(entry, Boundary::Refused, Some(17), &native, &before, &now).unwrap();
            let record: serde_json::Value =
                serde_json::from_slice(line.strip_prefix(b"day2-native-request-join ").unwrap())
                    .unwrap();
            assert_eq!(record["format"], "day2_native_request_join_v1");
            assert_eq!(record["entry"], expected);
            assert_eq!(record["boundary"], "refused");
            assert_eq!(record["sequence"], 17);
            assert_eq!(record["native"], native);
            assert_eq!(record["admission_before"], before);
            assert_eq!(record["admission_now"], now);
            assert_eq!(record.as_object().unwrap().len(), 7);
            assert!(line.len() <= JOIN_BYTES);
        }
        assert!(
            join_line(
                Entry::Http,
                Boundary::Captured,
                Some(1),
                &"x".repeat(JOIN_BYTES),
                &before,
                &now,
            )
            .is_none()
        );
    }

    #[test]
    fn maximal_actual_counter_and_identity_schemas_fit_without_truncation() {
        let native = EnrolledRequestDiagnosticData::maximal_fixture();
        let before = AdmissionWorkSnapshotData::maximal_fixture();
        let now = AdmissionWorkSnapshotData::maximal_fixture();
        let expected = serde_json::json!({
            "format": "day2_native_request_join_v1",
            "sequence": u64::MAX,
            "entry": "autonomous",
            "boundary": "completed",
            "native": &native,
            "admission_before": &before,
            "admission_now": &now,
        });
        let expected_bytes =
            b"day2-native-request-join ".len() + serde_json::to_vec(&expected).unwrap().len() + 1;
        let smallest_reviewed_bound = [8192, 12288]
            .into_iter()
            .find(|bound| *bound >= expected_bytes)
            .expect("diagnostic schema exceeds reviewed bounds");
        assert_eq!(
            JOIN_BYTES, smallest_reviewed_bound,
            "maximal actual frame is {expected_bytes} bytes"
        );
        let line = join_line(
            Entry::Autonomous,
            Boundary::Completed,
            Some(u64::MAX),
            &native,
            &before,
            &now,
        )
        .expect("complete actual counter schemas must not be truncated or silently omitted");
        assert_eq!(line.len(), expected_bytes);
        let record: serde_json::Value =
            serde_json::from_slice(line.strip_prefix(b"day2-native-request-join ").unwrap())
                .unwrap();
        assert_eq!(record, expected);
    }

    fn direct_join_uses_actual_getter(body: &syn::Block, boundary: &str, receiver: &str) -> bool {
        use syn::visit::Visit;
        struct Joins<'a> {
            boundary: &'a str,
            receiver: &'a str,
            count: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Joins<'_> {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("emit_join"))
                    && call.args.len() == 4
                    && matches!(&call.args[1], syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|part| part.ident == self.boundary))
                {
                    self.count += 1;
                    if self.receiver == "stage" {
                        let mut expression = &call.args[2];
                        for expected in [
                            "as_ref",
                            "ok",
                            "historical_request_binding_data",
                            "diagnostic_progress",
                        ] {
                            let syn::Expr::MethodCall(getter) = expression else {
                                self.valid = false;
                                return;
                            };
                            self.valid &= getter.method == expected && getter.args.is_empty();
                            expression = &getter.receiver;
                        }
                        self.valid &= matches!(expression, syn::Expr::Path(path) if path.path.is_ident("stage"));
                    } else {
                        self.valid &= matches!(&call.args[2], syn::Expr::Call(some)
                            if matches!(&*some.func, syn::Expr::Path(path) if path.path.is_ident("Some"))
                            && some.args.len() == 1
                            && matches!(&some.args[0], syn::Expr::Reference(reference)
                                if matches!(&*reference.expr, syn::Expr::MethodCall(getter)
                                    if getter.method == "historical_diagnostic_data" && getter.args.is_empty()
                                    && matches!(&*getter.receiver, syn::Expr::Path(path) if path.path.is_ident(self.receiver)))));
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut joins = Joins {
            boundary,
            receiver,
            count: 0,
            valid: true,
        };
        joins.visit_block(body);
        joins.count == 1 && joins.valid
    }

    #[test]
    fn capture_and_callback_joins_use_the_actual_current_request_and_stage() {
        let source = include_str!("request.rs");
        for (method, boundary, receiver) in [
            ("capture_app", "Captured", "current"),
            ("with_stage", "CallbackBorrowed", "stage"),
            ("with_stage", "CallbackReturned", "current"),
        ] {
            let body = selected_body(source, Some("Request"), method);
            assert!(direct_join_uses_actual_getter(&body, boundary, receiver));
            let rendered: proc_macro2::TokenStream = syn::parse_quote!(#body);
            let tokens = rendered.to_string();
            let getter = if receiver == "stage" {
                "diagnostic_progress"
            } else {
                "historical_diagnostic_data"
            };
            let wrong = tokens.replace(
                &format!("{receiver} . {getter}"),
                &format!("foreign . {getter}"),
            );
            assert_ne!(tokens, wrong);
            assert!(!direct_join_uses_actual_getter(
                &syn::parse_str(&wrong).unwrap(),
                boundary,
                receiver
            ));
            let removed = tokens.replace("emit_join", "ignore_join");
            assert_ne!(tokens, removed);
            assert!(!direct_join_uses_actual_getter(
                &syn::parse_str(&removed).unwrap(),
                boundary,
                receiver
            ));
        }
    }

    fn callback_check_order(body: &syn::Block) -> Vec<String> {
        use syn::visit::Visit;
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                // Runtime evaluates the receiver/arguments before the call.
                syn::visit::visit_expr_method_call(self, call);
                if matches!(
                    call.method.to_string().as_str(),
                    "borrow_current_request" | "check_selection"
                ) {
                    self.0.push(call.method.to_string());
                }
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                syn::visit::visit_expr_call(self, call);
                if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("operation")) {
                    self.0.push("operation".into());
                } else if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("emit_join"))
                    && let Some(syn::Expr::Path(path)) = call.args.iter().nth(1)
                    && let Some(name) = path.path.segments.last()
                    && matches!(
                        name.ident.to_string().as_str(),
                        "CallbackBorrowed" | "CallbackReturned"
                    )
                {
                    self.0.push(name.ident.to_string());
                }
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(body);
        calls.0
    }

    #[test]
    fn diagnostic_io_precedes_existing_checks_before_operation_and_return() {
        let body = selected_body(include_str!("request.rs"), Some("Request"), "with_stage");
        let expected = [
            "borrow_current_request",
            "CallbackBorrowed",
            "check_selection",
            "operation",
            "CallbackReturned",
            "borrow_current_request",
            "check_selection",
        ];
        assert_eq!(callback_check_order(&body), expected);
        use syn::visit::Visit;
        struct Pairs<'a> {
            boundary: &'a str,
            pairs: Vec<(syn::Stmt, syn::Stmt)>,
        }
        impl<'ast> Visit<'ast> for Pairs<'_> {
            fn visit_block(&mut self, block: &'ast syn::Block) {
                for pair in block.stmts.windows(2) {
                    if matches!(&pair[0], syn::Stmt::Expr(syn::Expr::Call(call), _)
                        if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("emit_join"))
                        && call.args.iter().nth(1).is_some_and(|argument|
                            matches!(argument, syn::Expr::Path(path)
                                if path.path.segments.last().is_some_and(|part| part.ident == self.boundary))))
                    {
                        self.pairs.push((pair[0].clone(), pair[1].clone()));
                    }
                }
                syn::visit::visit_block(self, block);
            }
        }
        for boundary in ["CallbackBorrowed", "CallbackReturned"] {
            let mut pairs = Pairs {
                boundary,
                pairs: Vec::new(),
            };
            pairs.visit_block(&body);
            assert_eq!(pairs.pairs.len(), 1);
            let (export, check) = pairs.pairs.pop().unwrap();
            let rendered: proc_macro2::TokenStream = syn::parse_quote!(#body);
            let before: proc_macro2::TokenStream = syn::parse_quote!(#export #check);
            let after: proc_macro2::TokenStream = syn::parse_quote!(#check #export);
            let tokens = rendered.to_string();
            let stale = tokens.replace(&before.to_string(), &after.to_string());
            assert_ne!(tokens, stale);
            assert_ne!(
                callback_check_order(&syn::parse_str(&stale).unwrap()),
                expected
            );
        }
    }

    fn response_owner_precedes_join(body: &syn::Block) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Order {
            owned: bool,
            joins: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Order {
            fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
                // The initializer must finish before its destructor protects
                // the actual moved request against diagnostic I/O/unwinding.
                syn::visit::visit_stmt(self, statement);
                if matches!(statement, syn::Stmt::Local(local)
                    if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "lease")
                    && local.init.as_ref().is_some_and(|init|
                        matches!(&*init.expr, syn::Expr::Struct(value) if value.path.is_ident("Lease"))))
                {
                    self.owned = true;
                }
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("emit_join"))
                    && call.args.len() == 4
                    && matches!(&call.args[1], syn::Expr::Path(path)
                        if path.path.segments.last().is_some_and(|part| part.ident == "ResponseLeased"))
                {
                    self.joins += 1;
                    self.valid &= self.owned;
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut order = Order {
            valid: true,
            ..Order::default()
        };
        order.visit_block(body);
        order.valid && order.joins == 1
    }

    #[test]
    fn response_lease_owns_cancellation_before_any_diagnostic_export() {
        let body = selected_body(include_str!("request.rs"), Some("Request"), "take");
        assert!(response_owner_precedes_join(&body));
        let rendered: proc_macro2::TokenStream = syn::parse_quote!(#body);
        let removed = rendered.to_string().replace("emit_join", "ignore_join");
        let mut early: syn::Block = syn::parse_str(&removed).unwrap();
        assert!(!response_owner_precedes_join(&early));
        let position = early
            .stmts
            .iter()
            .position(|statement| {
                matches!(statement, syn::Stmt::Local(local)
                if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "lease"))
            })
            .unwrap();
        early.stmts.insert(
            position,
            syn::parse_quote!(emit_join(entry, Boundary::ResponseLeased, &native, &baseline);),
        );
        assert!(!response_owner_precedes_join(&early));
    }

    fn evidence_order(body: &syn::Block) -> Vec<String> {
        use syn::visit::Visit;
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                syn::visit::visit_expr_method_call(self, call);
                if matches!(
                    call.method.to_string().as_str(),
                    "begin_current_request" | "finish" | "complete" | "write_all"
                ) {
                    self.0.push(call.method.to_string());
                }
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                syn::visit::visit_expr_call(self, call);
                let syn::Expr::Path(path) = &*call.func else {
                    return;
                };
                if path.path.is_ident("cumulative_admission_work_data") {
                    self.0.push("snapshot".into());
                } else if path.path.is_ident("join_line") {
                    let fresh = call.args.len() == 6
                        && matches!(&call.args[5], syn::Expr::Reference(reference)
                        if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("now")));
                    self.0
                        .push(if fresh { "fresh_frame" } else { "cached_frame" }.into());
                } else if path.path.is_ident("drop") {
                    self.0.push("drop".into());
                } else if path.path.is_ident("emit_join") {
                    if let Some(syn::Expr::Path(path)) = call.args.iter().nth(1)
                        && let Some(name) = path.path.segments.last()
                    {
                        self.0.push(format!("emit:{}", name.ident));
                    }
                } else if path
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect::<Vec<_>>()
                    == ["UnselectedShellRequest", "capture"]
                {
                    self.0.push("capture".into());
                }
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(body);
        calls.0
    }

    #[test]
    fn baseline_precedes_capture_and_terminal_frames_sample_after_actual_finish_or_drop() {
        let source = include_str!("request.rs");
        for (owner, method, expected) in [
            (
                Some("Request"),
                "capture_app",
                vec!["snapshot", "begin_current_request", "emit:Captured"],
            ),
            (
                Some("Request"),
                "capture_shell",
                vec!["snapshot", "capture"],
            ),
            (
                None,
                "emit_join",
                vec!["snapshot", "fresh_frame", "write_all"],
            ),
            (
                Some("Lease"),
                "finish",
                vec!["finish", "complete", "emit:Completed"],
            ),
            (Some("Held"), "drop", vec!["drop", "emit:Refused"]),
            (None, "refuse_with_evidence", vec!["drop", "emit:Refused"]),
        ] {
            assert_eq!(
                evidence_order(&selected_body(source, owner, method)),
                expected,
                "{method}"
            );
        }
        let mut late = selected_body(source, Some("Request"), "capture_app");
        let local = |body: &syn::Block, name: &str| {
            body.stmts
                .iter()
                .position(|statement| {
                    matches!(statement, syn::Stmt::Local(local)
                if matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == name))
                })
                .unwrap()
        };
        let before = local(&late, "baseline");
        let after = local(&late, "acquired");
        late.stmts.swap(before, after);
        assert_ne!(
            evidence_order(&late),
            ["snapshot", "begin_current_request", "emit:Captured"]
        );
        let emit = selected_body(source, None, "emit_join");
        let rendered: proc_macro2::TokenStream = syn::parse_quote!(#emit);
        let tokens = rendered.to_string();
        let cached = tokens.replace("& now", "baseline");
        assert_ne!(tokens, cached);
        assert_ne!(
            evidence_order(&syn::parse_str(&cached).unwrap()),
            ["snapshot", "fresh_frame", "write_all"]
        );
    }

    fn absent_scope() -> AuthorityScope {
        AuthorityScope {
            installation: "unenrolled-test".to_owned().try_into().unwrap(),
            environment: "test".to_owned().try_into().unwrap(),
            app: "no-native-owner".to_owned().try_into().unwrap(),
        }
    }

    #[test]
    fn non_native_transport_cannot_supply_or_reclassify_native_authority() -> Result<()> {
        for abort in [false, true] {
            let request = Request::new();
            request.capture_non_native()?;
            for role in [NativeRole::AppHost, NativeRole::SecurityShell] {
                assert!(request.take(&absent_scope(), role).is_err());
            }
            assert!(request.capture_app(&absent_scope(), Entry::Http).is_err());
            assert!(request.capture_shell().is_err());
            assert!(request.capture_model().is_err());
            if abort {
                request.refuse();
                assert!(request.finish().is_err());
            } else {
                request.finish()?;
                assert!(request.finish().is_err());
            }
            assert!(request.capture_non_native().is_err());
        }
        Ok(())
    }

    #[test]
    fn missing_native_supplier_cannot_downgrade_to_non_native_transport() {
        let request = Request::new();
        assert!(request.capture_app(&absent_scope(), Entry::Http).is_err());
        assert!(request.capture_non_native().is_err());
        assert!(request.capture_model().is_err());
        assert!(request.finish().is_err());
    }

    #[test]
    fn later_callbacks_spend_the_original_interval_and_exact_expiry_cannot_recover() -> Result<()> {
        let time = Arc::new(Time {
            domain: 71,
            millis: AtomicU64::new(10_000),
        });
        effects::scope(time.clone(), || -> Result<()> {
            let request = Request::new();
            request.capture_model()?;
            assert_eq!(request.model_origin()?, Some(Duration::from_secs(10)));
            time.millis.store(14_999, Ordering::SeqCst);
            assert_eq!(request.model_origin()?, Some(Duration::from_secs(10)));
            time.millis.store(15_000, Ordering::SeqCst);
            assert!(request.model_origin().is_err());
            time.millis.store(10_001, Ordering::SeqCst);
            assert!(request.model_origin().is_err());
            assert!(request.capture_model().is_err());
            assert!(request.finish().is_err());
            Ok(())
        })
    }

    #[test]
    fn rewind_or_foreign_domain_refuses_the_same_original_after_restoration() -> Result<()> {
        for foreign in [false, true] {
            let time = Arc::new(Time {
                domain: 72,
                millis: AtomicU64::new(10_000),
            });
            let other = Arc::new(Time {
                domain: 73,
                millis: AtomicU64::new(10_001),
            });
            effects::scope(time.clone(), || -> Result<()> {
                let request = Request::new();
                request.capture_model()?;
                time.millis.store(10_002, Ordering::SeqCst);
                request.model_origin()?;
                if foreign {
                    effects::scope(other, || assert!(request.model_origin().is_err()));
                } else {
                    time.millis.store(10_001, Ordering::SeqCst);
                    assert!(request.model_origin().is_err());
                }
                time.millis.store(10_003, Ordering::SeqCst);
                assert!(request.model_origin().is_err());
                assert!(request.finish().is_err());
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn abort_is_sticky_even_when_the_original_is_borrowed_and_the_error_is_caught() -> Result<()> {
        let request = Request::new();
        request.capture_model()?;
        let borrowed = request.slot.borrow_mut();
        request.clone().refuse();
        assert!(request.refused.get());
        drop(borrowed);
        assert!(request.model_origin().is_err());
        assert!(request.finish().is_err());
        assert!(request.capture_model().is_err());
        Ok(())
    }

    struct Material {
        identity: Rc<()>,
        refused: Rc<Cell<bool>>,
        complete: bool,
    }
    impl Material {
        fn finish(mut self) {
            self.complete = true;
        }
    }
    impl Drop for Material {
        fn drop(&mut self) {
            if !self.complete {
                self.refused.set(true);
            }
        }
    }

    #[test]
    fn suspension_moves_the_original_and_cancel_refuses_without_a_second_owner() {
        let slot = Rc::new(RefCell::new(Slot::Empty));
        let identity = Rc::new(());
        let refused = Rc::new(Cell::new(false));
        slot.borrow_mut().begin().unwrap();
        slot.borrow_mut()
            .install(Material {
                identity: identity.clone(),
                refused: refused.clone(),
                complete: false,
            })
            .unwrap();
        let actual = slot.borrow_mut().take().unwrap();
        let held = Held {
            slot: slot.clone(),
            refused: Rc::new(Cell::new(false)),
            current: Some(actual),
            diagnostic: None,
        };
        let mut pending = Box::pin(async move {
            held.check().unwrap();
            assert!(Rc::ptr_eq(
                &held.current.as_ref().unwrap().identity,
                &identity
            ));
            std::future::pending::<()>().await;
            drop(held);
        });
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(std::future::Future::poll(pending.as_mut(), &mut cx).is_pending());
        assert!(
            slot.try_borrow_mut().is_ok(),
            "no borrowed RefCell crosses suspension"
        );
        assert!(slot.borrow_mut().take().is_err());
        drop(pending);
        assert!(refused.get());
        assert!(slot.borrow_mut().begin().is_err());
        assert!(slot.borrow_mut().complete().is_err());
    }

    #[test]
    fn only_the_finished_actual_value_can_publish_completion() {
        let slot = Rc::new(RefCell::new(Slot::Empty));
        let refused = Rc::new(Cell::new(false));
        slot.borrow_mut().begin().unwrap();
        slot.borrow_mut()
            .install(Material {
                identity: Rc::new(()),
                refused: refused.clone(),
                complete: false,
            })
            .unwrap();
        let actual = slot.borrow_mut().take().unwrap();
        let mut held = Held {
            slot: slot.clone(),
            refused: Rc::new(Cell::new(false)),
            current: Some(actual),
            diagnostic: None,
        };
        assert!(held.complete().is_err());
        held.current.take().unwrap().finish();
        held.complete().unwrap();
        drop(held);
        assert!(!refused.get());
        assert!(matches!(*slot.borrow(), Slot::Complete));
        assert!(slot.borrow_mut().begin().is_err());
    }

    fn selected_body(source: &str, owner: Option<&str>, name: &str) -> syn::Block {
        let file = syn::parse_file(source).unwrap();
        let mut bodies = Vec::new();
        for item in file.items {
            match item {
                syn::Item::Fn(item) if owner.is_none() && item.sig.ident == name => bodies.push(*item.block),
                syn::Item::Impl(item) if owner.is_some_and(|owner| matches!(&*item.self_ty,
                    syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == owner))) => {
                    for item in item.items {
                        if let syn::ImplItem::Fn(item) = item && item.sig.ident == name { bodies.push(item.block); }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(
            bodies.len(),
            1,
            "exact production owner/method must remain unique"
        );
        bodies.pop().unwrap()
    }

    fn methods(body: &syn::Block) -> Vec<String> {
        use syn::visit::Visit;
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0.push(call.method.to_string());
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(body);
        calls.0
    }

    fn operation_capture_is_preserved(source: &str) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Service {
            checked: usize,
            valid: bool,
        }
        impl Service {
            fn tokens(&mut self, tokens: proc_macro2::TokenStream) {
                for token in tokens {
                    let proc_macro2::TokenTree::Group(group) = token else {
                        continue;
                    };
                    if group.delimiter() == proc_macro2::Delimiter::Brace {
                        let grouped = proc_macro2::TokenStream::from(
                            proc_macro2::TokenTree::Group(group.clone()),
                        );
                        if let Ok(block) = syn::parse2::<syn::Block>(grouped) {
                            self.visit_block(&block);
                            continue;
                        }
                    }
                    self.tokens(group.stream());
                }
            }
        }
        impl<'ast> Visit<'ast> for Service {
            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                // select! owns the real connection/service block. Descend its
                // syntax groups without pretending to expand arbitrary macros.
                self.tokens(mac.tokens.clone());
            }

            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if !matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("service_fn"))
                {
                    syn::visit::visit_expr_call(self, call);
                    return;
                }
                self.checked += 1;
                let Some(syn::Expr::Closure(closure)) = call.args.first() else {
                    return;
                };
                let syn::Expr::Block(block) = &*closure.body else {
                    return;
                };
                let mut captured = false;
                for statement in &block.block.stmts {
                    match statement {
                        syn::Stmt::Local(local) => {
                            let Some(init) = &local.init else {
                                return;
                            };
                            let syn::Expr::MethodCall(call) = &*init.expr else {
                                return;
                            };
                            if call.method == "capture_request" {
                                if captured
                                    || call.args.len() != 2
                                    || !matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("endpoint"))
                                    || !matches!(&call.args[0], syn::Expr::Reference(reference) if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("sink")))
                                    || !matches!(&call.args[1], syn::Expr::Reference(reference) if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("request")))
                                {
                                    return;
                                }
                                captured = true;
                            } else if call.method != "clone" {
                                return;
                            }
                        }
                        syn::Stmt::Expr(syn::Expr::Async(_), _) => {
                            self.valid = captured;
                            return;
                        }
                        _ => return,
                    }
                }
            }
        }
        let body = selected_body(source, None, "run");
        let mut service = Service::default();
        service.visit_block(&body);
        service.checked == 1 && service.valid
    }

    #[test]
    fn production_capture_precedes_async_dispatch_and_removal_or_delayed_capture_is_detected() {
        let source = include_str!("../native_http.rs");
        assert!(operation_capture_is_preserved(source));
        let removed = source.replacen(
            "let captured = endpoint.capture_request(&sink, &request);",
            "let captured = None;",
            1,
        );
        assert_ne!(removed, source);
        assert!(!operation_capture_is_preserved(&removed));
        let moved = source.replacen("let captured = endpoint.capture_request(&sink, &request);", "", 1)
            .replacen("let response = match captured", "let captured = endpoint.capture_request(&sink, &request); let response = match captured", 1);
        assert!(!operation_capture_is_preserved(&moved));
        let wrong = source.replacen(
            "endpoint.capture_request(&sink, &request)",
            "endpoint.capture_request(&other_sink, &request)",
            1,
        );
        assert!(!operation_capture_is_preserved(&wrong));
    }

    #[test]
    fn lexical_consumers_reborrow_the_actual_request_without_an_original_factory() {
        let source = include_str!("../native_management.rs");
        for (owner, name) in [
            (Some("EnrolledClock"), "sample"),
            (None, "with_app_participant"),
            (None, "with_current_for_role"),
            (None, "with_runtime_response"),
        ] {
            let body = selected_body(source, owner, name);
            let calls = methods(&body);
            assert!(!calls.iter().any(|name| name == "begin_current_stage"));
            assert_eq!(calls.iter().filter(|name| *name == "with_stage").count(), 1);
        }
        let source = include_str!("request.rs");
        let body = selected_body(source, Some("Request"), "with_stage");
        let calls = methods(&body);
        assert_eq!(
            calls
                .iter()
                .filter(|name| *name == "borrow_current_request")
                .count(),
            2
        );
        assert!(!calls.iter().any(|name| name == "begin_current_stage"));
        let restored = source.replacen(
            "role.borrow_current_request(current)?",
            "role.begin_current_stage()?",
            1,
        );
        let calls = methods(&selected_body(&restored, Some("Request"), "with_stage"));
        assert_eq!(
            calls
                .iter()
                .filter(|name| *name == "borrow_current_request")
                .count(),
            1
        );
        assert!(calls.iter().any(|name| name == "begin_current_stage"));
    }

    #[test]
    fn finite_response_moves_the_same_request_and_finishes_before_result_publication() {
        let source = include_str!("response.rs");
        let entries_use_one_shared_owner = |source: &str| {
            ["drive_response", "drive_host_request"]
                .into_iter()
                .all(|entry| {
                    let calls = methods(&selected_body(source, Some("Sink"), entry));
                    calls
                        .iter()
                        .filter(|name| *name == "drive_response_owner")
                        .count()
                        == 1
                        && !calls.iter().any(|name| {
                            matches!(name.as_str(), "borrow" | "prepare_current" | "finish")
                        })
                })
        };
        assert!(entries_use_one_shared_owner(source));
        let bypassed = source.replacen("self.drive_response_owner(", "self.drive_response(", 1);
        assert!(!entries_use_one_shared_owner(&bypassed));
        let calls = methods(&selected_body(source, Some("Sink"), "drive_response_owner"));
        assert!(!calls.iter().any(|name| name == "begin_current_stage"));
        let borrow = calls.iter().position(|name| name == "borrow").unwrap();
        let prepare = calls
            .iter()
            .position(|name| name == "prepare_current")
            .unwrap();
        assert!(borrow < prepare);
        let finish = calls.iter().rposition(|name| name == "finish").unwrap();
        let complete = calls.iter().rposition(|name| name == "complete").unwrap();
        assert!(finish < complete);
        assert_eq!(
            source
                .matches("request_owner.finish(role.owner())?;")
                .count(),
            1
        );
        let removed = source.replacen("request_owner.finish(role.owner())?;", "", 1);
        let calls = methods(&selected_body(
            &removed,
            Some("Sink"),
            "drive_response_owner",
        ));
        assert!(!calls.iter().any(|name| name == "finish"));
    }

    fn pump_entry_is_scoped(body: &syn::Block) -> bool {
        let Some(syn::Stmt::Local(local)) = body.stmts.first() else {
            return false;
        };
        let Some(init) = &local.init else {
            return false;
        };
        let syn::Expr::Call(call) = &*init.expr else {
            return false;
        };
        matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "with_runtime_operation"))
            && call.args.len() == 2
            && matches!(&call.args[1], syn::Expr::Closure(closure) if matches!(&*closure.body, syn::Expr::Match(_)))
    }

    #[test]
    fn all_pump_work_including_wall_time_starts_inside_the_one_operation_owner() {
        let source = include_str!("../../host_loop.rs");
        let actual = selected_body(source, Some("NativeWork"), "execute");
        assert!(pump_entry_is_scoped(&actual));
        let removed = source.replacen("with_runtime_operation", "unscoped_operation", 1);
        assert_ne!(source, removed);
        assert!(!pump_entry_is_scoped(&selected_body(
            &removed,
            Some("NativeWork"),
            "execute"
        )));
        let mut delayed = actual;
        delayed
            .stmts
            .insert(0, syn::parse_quote!(let _early = self.clock.wall_time();));
        assert!(!pump_entry_is_scoped(&delayed));
    }

    fn busy_exclusion_precedes_owner_lookup(body: &syn::Block) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct EarlyScope(bool);
        impl<'ast> Visit<'ast> for EarlyScope {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|part| part.ident == "runtime_response_scope"))
                {
                    self.0 = true;
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut early = EarlyScope::default();
        early.visit_block(body);
        let calls = methods(body);
        !early.0
            && calls
                .iter()
                .filter(|name| *name == "excludes_unstarted_operation")
                .count()
                == 1
            && matches!((calls.iter().position(|name| name == "excludes_unstarted_operation"),
                calls.iter().position(|name| name == "get")), (Some(exclude), Some(lookup)) if exclude < lookup)
    }

    #[test]
    fn a_leased_response_excludes_background_work_before_the_absent_owner_lookup() {
        let source = include_str!("../native_management.rs");
        let actual = selected_body(source, None, "with_runtime_operation");
        assert!(busy_exclusion_precedes_owner_lookup(&actual));
        let mut early = actual;
        early.stmts.insert(
            0,
            syn::parse_quote!(let _early = runtime_response_scope(runtime)?;),
        );
        assert!(!busy_exclusion_precedes_owner_lookup(&early));
        let removed = source.replacen(
            "owners.excludes_unstarted_operation(runtime.app())?",
            "false",
            1,
        );
        assert_ne!(source, removed);
        assert!(!busy_exclusion_precedes_owner_lookup(&selected_body(
            &removed,
            None,
            "with_runtime_operation"
        )));
    }

    fn startup_host_is_scoped(body: &syn::Block) -> bool {
        let Some(position) = body.stmts.iter().position(|statement| matches!(statement,
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "prepare_host"))) else {
            return false;
        };
        let syn::Stmt::Local(prepared) = &body.stmts[position] else {
            return false;
        };
        let Some(initializer) = &prepared.init else {
            return false;
        };
        let syn::Expr::Closure(closure) = &*initializer.expr else {
            return false;
        };
        let syn::Expr::Block(host) = &*closure.body else {
            return false;
        };
        let calls = methods(&host.block);
        fn propagated_call(statement: &syn::Stmt) -> Option<&syn::ExprCall> {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let initializer = local.init.as_ref()?;
            let syn::Expr::Try(result) = &*initializer.expr else {
                return None;
            };
            let syn::Expr::Call(call) = &*result.expr else {
                return None;
            };
            Some(call)
        }
        let directly_configures = host
            .block
            .stmts
            .iter()
            .filter_map(propagated_call)
            .any(|call| {
                let syn::Expr::Paren(function) = &*call.func else {
                    return false;
                };
                let syn::Expr::Field(field) = &*function.expr else {
                    return false;
                };
                matches!(&field.member, syn::Member::Named(name) if name == "configure")
                    && matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("self"))
            });
        let directly_binds = host
            .block
            .stmts
            .iter()
            .filter_map(propagated_call)
            .filter(|call| {
                matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "bind_edge_listener"))
            })
            .count();
        if !directly_configures
            || directly_binds != 1
            || !calls.iter().any(|name| name == "into_native_parts")
            || calls.iter().any(|name| name == "complete")
        {
            return false;
        }
        let [
            syn::Stmt::Local(parts),
            syn::Stmt::Expr(completed, Some(_)),
            syn::Stmt::Expr(_, None),
        ] = &body.stmts[position + 1..]
        else {
            return false;
        };
        let Some(initializer) = &parts.init else {
            return false;
        };
        let syn::Expr::Try(result) = &*initializer.expr else {
            return false;
        };
        let syn::Expr::If(branch) = &*result.expr else {
            return false;
        };
        if !matches!(&*branch.cond, syn::Expr::Path(path) if path.path.is_ident("native_initial")) {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::Call(call), None)) = branch.then_branch.stmts.last()
        else {
            return false;
        };
        matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "with_app_request"))
            && call.args.len() == 2
            && matches!(&call.args[0], syn::Expr::Path(path) if path.path.is_ident("scope"))
            && matches!(&call.args[1], syn::Expr::Path(path) if path.path.is_ident("prepare_host"))
            && matches!(completed, syn::Expr::MethodCall(call) if call.method == "complete"
                && call.args.is_empty()
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("observed")))
    }

    #[test]
    fn native_host_construction_shares_one_original_and_only_reports_completed_after_settlement() {
        let source = include_str!("../../deployment.rs");
        assert!(startup_host_is_scoped(&selected_body(
            source,
            Some("NativeAppStartup"),
            "prepare"
        )));
        for (before, after) in [
            (
                "crate::oauth::native_management::with_app_request(scope, prepare_host)",
                "prepare_host()",
            ),
            ("let parts = if native_initial {", "let parts = if false {"),
            (
                "        let parts = if native_initial {",
                "        observed.complete();\n        let parts = if native_initial {",
            ),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(source, changed);
            assert!(!startup_host_is_scoped(&selected_body(
                &changed,
                Some("NativeAppStartup"),
                "prepare"
            )));
        }
    }

    #[test]
    fn capture_failure_or_unwind_never_reopens_the_original() {
        for refuse in [false, true] {
            let mut slot: Slot<()> = Slot::Empty;
            slot.begin().unwrap();
            if refuse {
                slot.refuse();
            }
            assert!(slot.begin().is_err());
            if refuse {
                assert!(slot.install(()).is_err());
            }
        }
    }

    #[test]
    fn original_moves_once_and_refusal_cannot_restore_it() {
        let mut slot = Slot::Empty;
        let original = std::rc::Rc::new(());
        slot.begin().unwrap();
        slot.install(original.clone()).unwrap();
        assert!(slot.begin().is_err());
        let held = slot.take().unwrap();
        assert!(std::rc::Rc::ptr_eq(&held, &original));
        assert!(slot.take().is_err());
        slot.refuse();
        assert!(slot.complete().is_err());
        assert!(slot.install(held).is_err());
        assert!(slot.take().is_err());
    }

    #[test]
    fn only_the_taken_original_can_complete_and_completion_is_terminal() {
        let mut slot = Slot::Empty;
        assert!(slot.complete().is_err());
        assert!(slot.install(17).is_err());
        slot.begin().unwrap();
        slot.install(17).unwrap();
        assert!(slot.complete().is_err());
        assert_eq!(slot.take().unwrap(), 17);
        slot.complete().unwrap();
        slot.refuse();
        assert!(matches!(slot, Slot::Complete));
        assert!(slot.begin().is_err());
        assert!(slot.install(18).is_err());
        assert!(slot.take().is_err());
    }
}
