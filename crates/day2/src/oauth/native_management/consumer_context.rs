//! The actual consumer's original and selection retained inside one native
//! scope. Fixed factories require the actual captured request and, for human
//! work, the real bound original. None can construct a native scope or owner.

use super::request::ConsumerRequestOrigin;
use super::response::ConsumerLeaseOrigin;
use super::{EnrolledClock, OriginalPhase, Phase, Sink, SinkState, sql_runtime_scope};
use crate::oauth::fresh_auth::FreshIntent;
use crate::oauth::native_original::Original;
use crate::security_epoch::{
    native_enrollment::{
        EnrolledRoleStage, NativeConsumerCompletion, NativeConsumerOrigin, NativeRole,
        RestoredAppRequestSettlement,
    },
    serving::{NativeProviderUse, NativeSqlUse, RuntimeServingUse, ScopePurpose},
};
use crate::store::Runtime;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::rc::Rc;

/// Identity DATA for one concrete consumer context, distinct even when several
/// contexts borrow the same native HTTP original. No factory from scalar DATA
/// and no conversion into a context, native origin, scope or settlement exists.
#[derive(Clone)]
pub(crate) struct NativeConsumerAffinity {
    same: Rc<()>,
}

impl NativeConsumerAffinity {
    pub(crate) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.same, &other.same)
    }
}

/// No scalar/Runtime-only constructor, native getter or Human-to-Runtime
/// conversion. The final native owner must also retain its actual saved request,
/// peer, file, counter and negative roots; this context cannot replace them.
pub(crate) struct NativeConsumerContext<'request, 'original> {
    source: ConsumerOriginal<'request, 'original>,
    runtime: &'request Runtime,
    origin: ConsumerOrigin<'request>,
    binding: Digest,
    purpose: ScopePurpose,
    affinity: NativeConsumerAffinity,
    complete: bool,
}

/// Only the actual final request driver may construct this distinct context.
/// There is no conversion from a completed consumer/unit context. The genuine
/// saved request and this final original remain live until native settlement.
pub(crate) struct NativeRequestFinalContext<'request, 'original> {
    source: FinalOriginal<'request, 'original>,
    runtime: &'request Runtime,
    origin: ConsumerOrigin<'request>,
    affinity: NativeConsumerAffinity,
    complete: bool,
}

enum FinalOriginal<'request, 'original> {
    Bound(&'request mut OriginalPhase<'original>),
    Runtime,
}

enum ConsumerOriginal<'request, 'original> {
    Bound(&'request mut OriginalPhase<'original>),
    // The genuine AppCreator still owns this unbound original. A successful
    // current scope returns its borrow for the later CommittedCapture bind;
    // it does not complete the human operation or invent a FreshIntent.
    Captured(&'request mut Original<EnrolledClock>),
    Runtime,
}

/// These are actual negative roots, not an optional HTTP label. Startup and
/// background actions must carry their genuine captured native request; no
/// synthetic HTTP Sink or ResponseIdentity is needed or accepted for them.
enum ConsumerOrigin<'request> {
    Http {
        sink: &'request Sink,
        native: ConsumerRequestOrigin,
    },
    Response {
        sink: &'request Sink,
        native: ConsumerRequestOrigin,
        lease: ConsumerLeaseOrigin,
    },
    Autonomous(ConsumerRequestOrigin),
}

fn human_origin_matches(
    origin: &ConsumerOrigin<'_>,
    purpose: crate::security_epoch::serving::ServingUse,
) -> bool {
    use crate::security_epoch::serving::ServingUse;
    match origin {
        ConsumerOrigin::Http { .. } => human_http_purpose(purpose),
        ConsumerOrigin::Response { .. } => purpose == ServingUse::Response,
        ConsumerOrigin::Autonomous(_) => false,
    }
}

fn human_http_purpose(purpose: crate::security_epoch::serving::ServingUse) -> bool {
    use crate::security_epoch::serving::ServingUse;
    matches!(
        purpose,
        ServingUse::Pending
            | ServingUse::Claim
            | ServingUse::Publication
            | ServingUse::StartCommit
            | ServingUse::DispatchCommit
            | ServingUse::ProviderSend
            | ServingUse::FinishCommit
            | ServingUse::DisconnectCommit
            | ServingUse::Verification
            | ServingUse::Callback
    )
}

fn runtime_sql_write_allowed(purpose: ScopePurpose) -> bool {
    matches!(
        purpose,
        ScopePurpose::Runtime(
            RuntimeServingUse::Registration
                | RuntimeServingUse::Read
                | RuntimeServingUse::Refresh
                | RuntimeServingUse::SqlWrite
        )
    )
}

fn runtime_purpose_matches(actual: ScopePurpose, expected: RuntimeServingUse) -> bool {
    matches!(actual, ScopePurpose::Runtime(actual) if actual == expected)
        && matches!(
            expected,
            RuntimeServingUse::Registration
                | RuntimeServingUse::Read
                | RuntimeServingUse::Refresh
                | RuntimeServingUse::SqlRead
                | RuntimeServingUse::SqlWrite
        )
}

impl ConsumerOrigin<'_> {
    fn require_request(&self) -> Result<()> {
        match self {
            Self::Http { sink, native } | Self::Response { sink, native, .. } => {
                native.require_request(&sink.request)
            }
            Self::Autonomous(_) => Ok(()),
        }
    }

    fn check_current(&self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.require_request()?;
        match self {
            Self::Response {
                sink,
                native,
                lease,
            } => {
                let selected = native.check_current(stage);
                let live = lease.check(sink);
                if selected.is_err() || live.is_err() {
                    self.refuse();
                }
                selected?;
                live
            }
            Self::Http { sink, native } => {
                let selected = native.check_current(stage);
                if !sink.is_open() {
                    native.refuse();
                }
                selected?;
                ensure!(sink.is_open(), "native consumer HTTP origin refused");
                Ok(())
            }
            Self::Autonomous(native) => native.check_current(stage),
        }
    }

    fn require_same(&self, actual: &NativeConsumerOrigin) -> Result<()> {
        self.require_request()?;
        match self {
            Self::Response {
                sink,
                native,
                lease,
            } => {
                let selected = native.require_same(actual);
                let live = lease.check(sink);
                if selected.is_err() || live.is_err() {
                    self.refuse();
                    actual.refuse();
                }
                selected?;
                live
            }
            Self::Http { sink, native } => {
                let selected = native.require_same(actual);
                if !sink.is_open() {
                    native.refuse();
                    actual.refuse();
                }
                selected?;
                ensure!(sink.is_open(), "native consumer HTTP origin refused");
                Ok(())
            }
            Self::Autonomous(native) => native.require_same(actual),
        }
    }

    fn refuse(&self) {
        match self {
            Self::Response {
                sink,
                native,
                lease,
            } => {
                native.refuse();
                if native.same_request(&sink.request) {
                    lease.refuse_sink(sink);
                }
            }
            Self::Http { sink, native } => {
                native.refuse();
                if native.same_request(&sink.request) {
                    sink.state.set(SinkState::Refused);
                    sink.request.refuse();
                    sink.response_tickets.refuse();
                }
            }
            Self::Autonomous(native) => native.refuse(),
        }
    }
}

impl<'request, 'original> NativeConsumerContext<'request, 'original> {
    /// The actual bound original supplies phase and intent, never caller DATA.
    /// A response needs its separate sole lease root and cannot use this path.
    pub(super) fn human(
        runtime: &'request Runtime,
        original: &'request mut OriginalPhase<'original>,
        sink: &'request Sink,
        native: ConsumerRequestOrigin,
    ) -> Result<Self> {
        Self::bound(runtime, original, ConsumerOrigin::Http { sink, native })
    }

    pub(super) fn human_response(
        runtime: &'request Runtime,
        original: &'request mut OriginalPhase<'original>,
        sink: &'request Sink,
        native: ConsumerRequestOrigin,
        lease: ConsumerLeaseOrigin,
    ) -> Result<Self> {
        Self::bound(
            runtime,
            original,
            ConsumerOrigin::Response {
                sink,
                native,
                lease,
            },
        )
    }

    fn bound(
        runtime: &'request Runtime,
        original: &'request mut OriginalPhase<'original>,
        origin: ConsumerOrigin<'request>,
    ) -> Result<Self> {
        let selected = (|| {
            origin.require_request()?;
            ensure!(
                runtime.uses_native_storage(),
                "native human Runtime required"
            );
            ensure!(
                original.intent.app() == runtime.app(),
                "native human Runtime app changed"
            );
            original.intent.require_oauth_management()?;
            let purpose = super::serving_use(original.phase, NativeRole::AppHost)?;
            ensure!(
                human_origin_matches(&origin, purpose),
                "native human origin purpose changed"
            );
            if let ConsumerOrigin::Response { sink, lease, .. } = &origin {
                lease.require_human(sink, original.intent)?;
            }
            let commitment = original.intent.commitment()?;
            let binding = Digest::of(&("day2-native-human-serving-v1", &commitment, purpose))?;
            Ok((binding, purpose))
        })();
        let (binding, purpose) = match selected {
            Ok(selected) => selected,
            Err(error) => {
                original.refuse();
                origin.refuse();
                return Err(error);
            }
        };
        Ok(Self {
            source: ConsumerOriginal::Bound(original),
            runtime,
            origin,
            binding,
            purpose: ScopePurpose::Human(purpose),
            affinity: NativeConsumerAffinity { same: Rc::new(()) },
            complete: false,
        })
    }

    /// Pure selection/refusal only. Native constructors call this BEFORE
    /// borrowing the saved stage, which itself may observe identity and time.
    pub(crate) fn require_runtime(&mut self, runtime: &Runtime) -> Result<()> {
        if !std::ptr::eq(self.runtime, runtime) {
            self.refuse();
            anyhow::bail!("native consumer Runtime changed");
        }
        if !runtime.uses_native_storage() {
            self.refuse();
            anyhow::bail!("native consumer file selection missing");
        }
        if self.complete {
            self.refuse();
            anyhow::bail!("native consumer context unavailable");
        }
        Ok(())
    }

    /// Negative identity projection only, not a native/request/Runtime getter.
    /// The real scope retains it before any fallible consumer setup.
    pub(crate) fn affinity_data(&self) -> NativeConsumerAffinity {
        self.affinity.clone()
    }

    /// A RuntimeConsumer may borrow only an actual autonomous Runtime context,
    /// never relabel a human, captured creator or finite response scope. Pure
    /// pointer/purpose selection precedes any saved native-stage observation.
    pub(crate) fn require_runtime_purpose(
        &mut self,
        runtime: &Runtime,
        purpose: RuntimeServingUse,
    ) -> Result<()> {
        self.require_runtime(runtime)?;
        if !matches!(&self.source, ConsumerOriginal::Runtime)
            || !runtime_purpose_matches(self.purpose, purpose)
        {
            self.refuse();
            anyhow::bail!("native Runtime consumer original or purpose changed");
        }
        Ok(())
    }

    /// A finite response may borrow only its actual HTTP original. Neither a
    /// creator, autonomous action nor another human phase can become transport
    /// authority merely by reaching the response driver.
    pub(crate) fn require_response(&mut self, runtime: &Runtime) -> Result<()> {
        self.require_runtime(runtime)?;
        self.require_response_binding()?;
        let selected = match (&self.source, &self.origin, self.purpose) {
            (
                ConsumerOriginal::Bound(original),
                ConsumerOrigin::Response { .. },
                ScopePurpose::Human(crate::security_epoch::serving::ServingUse::Response),
            ) => original.phase == Phase::Response,
            (
                ConsumerOriginal::Runtime,
                ConsumerOrigin::Response { .. },
                ScopePurpose::Runtime(RuntimeServingUse::Response),
            ) => true,
            _ => false,
        };
        if !selected {
            self.refuse();
            anyhow::bail!("native response original or purpose changed");
        }
        Ok(())
    }

    pub(crate) fn require_affinity(&mut self, actual: &NativeConsumerAffinity) -> Result<()> {
        if !self.affinity.same(actual) {
            self.refuse();
            anyhow::bail!("native consumer scope context changed");
        }
        Ok(())
    }

    /// Exact negative original identity only, including after native finish.
    /// It supplies no clock sample, current authority or completion itself.
    pub(crate) fn require_origin(&mut self, actual: &NativeConsumerOrigin) -> Result<()> {
        self.require_response_binding()?;
        let result = self.origin.require_same(actual);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Local checks only: no counter read, provider operation or peer wait.
    /// The native owner passes its ACTUAL retained Runtime, never a caller's
    /// equal-valued replacement, before lending any consumer operation.
    pub(crate) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
    ) -> Result<()> {
        let result = (|| {
            self.require_runtime(runtime)?;
            self.require_response_binding()?;
            self.origin.check_current(stage)?;
            stage.check_for(&sql_runtime_scope(runtime)?, NativeRole::AppHost)?;
            ensure!(
                match (&self.source, &self.origin, self.purpose) {
                    (ConsumerOriginal::Bound(_), origin, ScopePurpose::Human(purpose)) =>
                        human_origin_matches(origin, purpose),
                    (
                        ConsumerOriginal::Captured(_),
                        ConsumerOrigin::Http { .. },
                        ScopePurpose::Runtime(RuntimeServingUse::PendingCapture),
                    ) => true,
                    (
                        ConsumerOriginal::Runtime,
                        ConsumerOrigin::Http { .. },
                        ScopePurpose::Runtime(
                            RuntimeServingUse::Registration
                            | RuntimeServingUse::Read
                            | RuntimeServingUse::Refresh
                            | RuntimeServingUse::SqlRead
                            | RuntimeServingUse::SqlWrite,
                        ),
                    ) => true,
                    (
                        ConsumerOriginal::Runtime,
                        ConsumerOrigin::Response { .. },
                        ScopePurpose::Runtime(
                            RuntimeServingUse::Response | RuntimeServingUse::ResponseComplete,
                        ),
                    ) => true,
                    (
                        ConsumerOriginal::Runtime,
                        ConsumerOrigin::Autonomous(_),
                        ScopePurpose::Runtime(
                            RuntimeServingUse::Registration
                            | RuntimeServingUse::Read
                            | RuntimeServingUse::Refresh
                            | RuntimeServingUse::SqlRead
                            | RuntimeServingUse::SqlWrite,
                        ),
                    ) => true,
                    _ => false,
                },
                "native consumer origin purpose changed"
            );
            ensure!(
                matches!(
                    (&self.source, self.purpose),
                    (ConsumerOriginal::Bound(_), ScopePurpose::Human(_))
                        | (
                            ConsumerOriginal::Captured(_),
                            ScopePurpose::Runtime(RuntimeServingUse::PendingCapture)
                        )
                        | (
                            ConsumerOriginal::Runtime,
                            ScopePurpose::Runtime(
                                RuntimeServingUse::Registration
                                    | RuntimeServingUse::Read
                                    | RuntimeServingUse::Refresh
                                    | RuntimeServingUse::SqlRead
                                    | RuntimeServingUse::SqlWrite
                                    | RuntimeServingUse::Response
                                    | RuntimeServingUse::ResponseComplete
                            )
                        )
                ),
                "native consumer original purpose changed"
            );
            match &mut self.source {
                ConsumerOriginal::Bound(original) => {
                    original.check_with_native(stage, original.wall)?;
                }
                ConsumerOriginal::Captured(original) => {
                    let sample = original.clock.clock.sample(stage);
                    original.check_capture_sample(sample)?;
                }
                ConsumerOriginal::Runtime => {}
            }
            self.origin.check_current(stage)?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn require_response_binding(&mut self) -> Result<()> {
        if let Err(error) = self.origin.require_request() {
            self.refuse();
            return Err(error);
        }
        let result = match (&self.source, &self.origin) {
            (ConsumerOriginal::Bound(original), ConsumerOrigin::Response { sink, lease, .. }) => {
                lease.require_human(sink, original.intent)
            }
            (ConsumerOriginal::Runtime, ConsumerOrigin::Response { sink, lease, .. }) => {
                lease.require_runtime(sink)
            }
            (_, ConsumerOrigin::Response { .. }) => {
                Err(anyhow::anyhow!("native response original source changed"))
            }
            _ => Ok(()),
        };
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Protocol DATA derived only by the fixed real-driver factory. The
    /// native supplier combines it with its actual retained lineage; callers
    /// cannot provide a replacement StoragePeerRequest to this consumer scope.
    pub(crate) fn checked_binding(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
    ) -> Result<(Digest, ScopePurpose)> {
        self.check(stage, runtime)?;
        Ok((self.binding.clone(), self.purpose))
    }

    pub(crate) fn check_sql(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
        access: NativeSqlUse,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage, runtime)?;
            if access == NativeSqlUse::Write {
                match &self.source {
                    ConsumerOriginal::Runtime => ensure!(
                        runtime_sql_write_allowed(self.purpose),
                        "native consumer SQL write purpose refused"
                    ),
                    ConsumerOriginal::Bound(_) | ConsumerOriginal::Captured(_) => {}
                }
            }
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn check_provider(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
        use_: NativeProviderUse,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage, runtime)?;
            ensure!(
                matches!(
                    (&self.source, self.purpose, use_),
                    (
                        ConsumerOriginal::Runtime,
                        ScopePurpose::Runtime(RuntimeServingUse::Read),
                        NativeProviderUse::Read
                    ) | (
                        ConsumerOriginal::Runtime,
                        ScopePurpose::Runtime(RuntimeServingUse::Refresh),
                        NativeProviderUse::Refresh
                    )
                ),
                "native consumer provider purpose refused"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn require_human(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
        intent: &FreshIntent,
        phase: Phase,
    ) -> Result<()> {
        let result = (|| {
            let ConsumerOriginal::Bound(original) = &self.source else {
                anyhow::bail!("native bound human context required");
            };
            ensure!(
                original.intent == intent && original.phase == phase,
                "native consumer original or phase changed"
            );
            self.check(stage, runtime)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Advance only the retained response's completion label, after the real
    /// response engine has returned its completed transport operation.
    pub(crate) fn response_complete(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage, runtime)?;
            match &mut self.source {
                ConsumerOriginal::Bound(original) => {
                    ensure!(
                        original.phase == Phase::Response,
                        "native response completion context changed"
                    );
                    original.phase = Phase::ResponseComplete;
                }
                ConsumerOriginal::Runtime => ensure!(
                    matches!(
                        self.purpose,
                        ScopePurpose::Runtime(RuntimeServingUse::Response)
                    ),
                    "native runtime response completion context changed"
                ),
                ConsumerOriginal::Captured(_) => {
                    anyhow::bail!("native creator cannot complete a response")
                }
            }
            self.check(stage, runtime)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Call after the native peer/counter/file posts while the same actual
    /// stage is still held. A scope does not finish the enclosing HTTP request.
    pub(crate) fn check_final(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
    ) -> Result<()> {
        self.check(stage, runtime)
    }

    /// The genuine S3 scope token still owns every negative native root. It
    /// checks this exact original AND context affinity before returning its
    /// borrowed request to Captured. It never finishes/rearms the HTTP request.
    pub(crate) fn complete_scope<'scope>(
        mut self,
        mut token: NativeConsumerCompletion<'scope, 'request, 'original>,
    ) -> Result<()> {
        token.check_context(&mut self)?;
        token.complete_native()?;
        self.complete = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        match &mut self.source {
            ConsumerOriginal::Bound(original) => original.refuse(),
            ConsumerOriginal::Captured(original) => original.refuse(),
            ConsumerOriginal::Runtime => {}
        }
        // Only direct negative roots here: no registry lookup, new owner,
        // provider action or counter read while a SQL transaction may be open.
        self.origin.refuse();
    }
}

impl<'request> NativeConsumerContext<'request, 'static> {
    /// Fixed startup SQL only. The closed input owns the real preconfiguration
    /// capture; no HTTP/human original, scalar timestamp or provider purpose
    /// can be supplied or reclassified by this constructor.
    pub(super) fn startup_sql(
        runtime: &'request Runtime,
        request: &super::request::StartupRequest,
    ) -> Result<Self> {
        let native = request.consumer_origin(runtime)?;
        let purpose = RuntimeServingUse::SqlWrite;
        Ok(Self {
            source: ConsumerOriginal::Runtime,
            runtime,
            origin: ConsumerOrigin::Autonomous(native),
            binding: Digest::of(&("day2-native-runtime-serving-v1", purpose))?,
            purpose: ScopePurpose::Runtime(purpose),
            affinity: NativeConsumerAffinity { same: Rc::new(()) },
            complete: false,
        })
    }
}

impl Drop for NativeConsumerContext<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.refuse();
        }
    }
}

impl<'request, 'original> NativeRequestFinalContext<'request, 'original> {
    fn require_response_binding(&mut self) -> Result<()> {
        if let Err(error) = self.origin.require_request() {
            self.refuse();
            return Err(error);
        }
        let result = match (&self.source, &self.origin) {
            (FinalOriginal::Bound(original), ConsumerOrigin::Response { sink, lease, .. }) => {
                lease.require_human(sink, original.intent)
            }
            (FinalOriginal::Runtime, ConsumerOrigin::Response { sink, lease, .. }) => {
                lease.require_runtime(sink)
            }
            _ => Ok(()),
        };
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Pure exact-object selection before any native stage/original borrow.
    /// This does not check a file, sample a clock or grant a final settlement.
    pub(crate) fn require_runtime(&mut self, runtime: &Runtime) -> Result<()> {
        if !std::ptr::eq(self.runtime, runtime) {
            self.refuse();
            anyhow::bail!("native final Runtime changed");
        }
        if !runtime.uses_native_storage() {
            self.refuse();
            anyhow::bail!("native final file selection missing");
        }
        if self.complete {
            self.refuse();
            anyhow::bail!("native final request context unavailable");
        }
        Ok(())
    }

    pub(crate) fn affinity_data(&self) -> NativeConsumerAffinity {
        self.affinity.clone()
    }

    pub(crate) fn require_affinity(&mut self, actual: &NativeConsumerAffinity) -> Result<()> {
        if !self.affinity.same(actual) {
            self.refuse();
            anyhow::bail!("native final request context changed");
        }
        Ok(())
    }

    /// Identity/negative checks only: this remains valid for the final owning
    /// settlement after native request.finish; it makes no fresh clock claim.
    pub(crate) fn require_origin(&mut self, actual: &NativeConsumerOrigin) -> Result<()> {
        self.require_response_binding()?;
        let result = self.origin.require_same(actual);
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// The native supplier calls this on its SAME saved stage after all
    /// peer/counter/file posts and immediately before native request.finish.
    /// A creator/unit context cannot be used as a final human context.
    pub(crate) fn check_final(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        runtime: &Runtime,
    ) -> Result<()> {
        let result = (|| {
            self.require_runtime(runtime)?;
            self.require_response_binding()?;
            self.origin.check_current(stage)?;
            stage.check_for(&sql_runtime_scope(runtime)?, NativeRole::AppHost)?;
            match (&mut self.source, &self.origin) {
                (FinalOriginal::Bound(original), ConsumerOrigin::Response { .. }) => {
                    ensure!(
                        original.phase == Phase::ResponseComplete,
                        "native final human response not completed"
                    );
                    original.check_with_native(stage, original.wall)?;
                }
                (
                    FinalOriginal::Runtime,
                    ConsumerOrigin::Response { .. } | ConsumerOrigin::Autonomous(_),
                ) => {}
                _ => anyhow::bail!("native final human origin changed"),
            }
            self.origin.check_current(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// This token can only be minted by the actual native final-request
    /// supplier after it consumes that request. All fallible negative checks
    /// and native rearm stay inside its owning guard, before Drop is disarmed.
    pub(crate) fn complete_after_native<'scope>(
        mut self,
        mut token: RestoredAppRequestSettlement<'scope, 'request, 'original>,
    ) -> Result<()> {
        token.check_context(&mut self)?;
        token.complete_native()?;
        self.complete = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        if let FinalOriginal::Bound(original) = &mut self.source {
            original.refuse();
        }
        self.origin.refuse();
    }
}

impl Drop for NativeRequestFinalContext<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.refuse();
        }
    }
}

impl<'request> NativeRequestFinalContext<'request, 'static> {
    pub(super) fn startup(
        runtime: &'request Runtime,
        request: &super::request::StartupLease,
    ) -> Result<Self> {
        let native = request.consumer_origin(runtime)?;
        Ok(Self {
            source: FinalOriginal::Runtime,
            runtime,
            origin: ConsumerOrigin::Autonomous(native),
            affinity: NativeConsumerAffinity { same: Rc::new(()) },
            complete: false,
        })
    }
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
    assert_not_impl!(NativeConsumerContext<'static, 'static>, Clone);
    assert_not_impl!(NativeConsumerContext<'static, 'static>, Copy);
    assert_not_impl!(NativeConsumerContext<'static, 'static>, Default);
    assert_not_impl!(NativeConsumerContext<'static, 'static>, std::fmt::Debug);
    assert_not_impl!(NativeConsumerContext<'static, 'static>, Send);
    assert_not_impl!(NativeConsumerContext<'static, 'static>, Sync);
    assert_not_impl!(NativeConsumerContext<'static, 'static>, serde::Serialize);
    assert_not_impl!(
        NativeConsumerContext<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(NativeRequestFinalContext<'static, 'static>, Clone);
    assert_not_impl!(NativeRequestFinalContext<'static, 'static>, Copy);
    assert_not_impl!(NativeRequestFinalContext<'static, 'static>, Default);
    assert_not_impl!(NativeRequestFinalContext<'static, 'static>, std::fmt::Debug);
    assert_not_impl!(NativeRequestFinalContext<'static, 'static>, Send);
    assert_not_impl!(NativeRequestFinalContext<'static, 'static>, Sync);
    assert_not_impl!(
        NativeRequestFinalContext<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        NativeRequestFinalContext<'static, 'static>,
        serde::Deserialize<'static>
    );
};

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;
    use syn::parse::Parser;
    use syn::visit::Visit;

    #[test]
    fn response_binding_is_rechecked_before_each_native_current_or_final_origin_join() {
        fn method(owner: &str, name: &str) -> syn::ImplItemFn {
            syn::parse_file(include_str!("consumer_context.rs")).unwrap().items.into_iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == owner) { return None; }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
            }).unwrap()
        }
        for (owner, name, expected) in [
            (
                "NativeConsumerContext",
                "check",
                vec![
                    syn::parse_quote!(self.require_runtime(runtime)?;),
                    syn::parse_quote!(self.require_response_binding()?;),
                    syn::parse_quote!(self.origin.check_current(stage)?;),
                ],
            ),
            (
                "NativeRequestFinalContext",
                "check_final",
                vec![
                    syn::parse_quote!(self.require_runtime(runtime)?;),
                    syn::parse_quote!(self.require_response_binding()?;),
                    syn::parse_quote!(self.origin.check_current(stage)?;),
                ],
            ),
        ] {
            let actual = method(owner, name);
            let syn::Stmt::Local(result) = &actual.block.stmts[0] else {
                panic!("actual result");
            };
            let syn::Expr::Call(result) = &*result.init.as_ref().unwrap().expr else {
                panic!("actual operation");
            };
            let syn::Expr::Paren(result) = &*result.func else {
                panic!("actual local scope");
            };
            let syn::Expr::Closure(result) = &*result.expr else {
                panic!("actual closed check");
            };
            let syn::Expr::Block(result) = &*result.body else {
                panic!("actual check body");
            };
            let expected: Vec<syn::Stmt> = expected;
            let guarded = |body: &syn::Block| {
                body.stmts
                    .iter()
                    .take(expected.len())
                    .map(|stmt| stmt.to_token_stream().to_string())
                    .collect::<Vec<_>>()
                    == expected
                        .iter()
                        .map(|stmt| stmt.to_token_stream().to_string())
                        .collect::<Vec<_>>()
            };
            assert!(guarded(&result.block));
            let mut skipped = result.block.clone();
            skipped.stmts.remove(1);
            assert!(!guarded(&skipped));
        }
        for owner in ["NativeConsumerContext", "NativeRequestFinalContext"] {
            let actual = method(owner, "require_origin");
            let first: syn::Stmt = syn::parse_quote!(self.require_response_binding()?;);
            assert_eq!(
                actual.block.stmts[0].to_token_stream().to_string(),
                first.to_token_stream().to_string()
            );
            let actual = method(owner, "require_response_binding");
            let tokens = actual.block.to_token_stream().to_string().replace(' ', "");
            assert!(tokens.contains("self.origin.require_request()"));
            assert!(tokens.contains("lease.require_human(sink,original.intent)"));
            assert!(tokens.contains("lease.require_runtime(sink)"));
            assert!(
                !tokens.contains("lease.check(sink)"),
                "a live lease alone cannot prove its binding"
            );
        }
    }

    #[test]
    fn actual_http_origin_checks_the_same_routing_request_and_never_refuses_a_foreign_sink() {
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        let method = |name: &str| {
            file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == "ConsumerOrigin") { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
        }).unwrap()
        };
        let request = method("require_request");
        let expected: syn::Block = syn::parse_quote!({
            match self {
                Self::Http { sink, native } | Self::Response { sink, native, .. } => {
                    native.require_request(&sink.request)
                }
                Self::Autonomous(_) => Ok(()),
            }
        });
        assert_eq!(
            request.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let refused = method("refuse");
        let syn::Stmt::Expr(syn::Expr::Match(selected), _) = &refused.block.stmts[0] else {
            panic!("actual refusal source");
        };
        for arm in &selected.arms[..2] {
            let syn::Expr::Block(body) = &*arm.body else {
                panic!("actual HTTP source");
            };
            let native: syn::Stmt = syn::parse_quote!(native.refuse(););
            assert_eq!(
                body.block.stmts[0].to_token_stream().to_string(),
                native.to_token_stream().to_string()
            );
            let syn::Stmt::Expr(syn::Expr::If(same), None) = &body.block.stmts[1] else {
                panic!("actual routing identity condition");
            };
            let expected: syn::Expr = syn::parse_quote!(native.same_request(&sink.request));
            let guarded = |condition: &syn::Expr| {
                condition.to_token_stream().to_string() == expected.to_token_stream().to_string()
            };
            assert!(guarded(&same.cond));
            assert!(!guarded(&syn::parse_quote!(true)));
            assert_eq!(
                body.block.stmts.len(),
                2,
                "no foreign Sink mutation may follow the guard"
            );
        }
    }

    #[test]
    fn human_http_cannot_select_shell_or_response_purposes() {
        use crate::security_epoch::serving::ServingUse;
        for purpose in [
            ServingUse::Pending,
            ServingUse::Claim,
            ServingUse::Publication,
            ServingUse::StartCommit,
            ServingUse::DispatchCommit,
            ServingUse::ProviderSend,
            ServingUse::FinishCommit,
            ServingUse::DisconnectCommit,
            ServingUse::Verification,
            ServingUse::Callback,
        ] {
            assert!(human_http_purpose(purpose));
        }
        for purpose in [
            ServingUse::Authentication,
            ServingUse::Session,
            ServingUse::Signature,
            ServingUse::Response,
            ServingUse::AppResponseComplete,
            ServingUse::ShellResponseComplete,
        ] {
            assert!(!human_http_purpose(purpose));
        }
    }

    #[test]
    fn actual_human_factory_derives_its_phase_and_commitment_from_the_real_original() {
        fn method(name: &str) -> syn::ImplItemFn {
            syn::parse_file(include_str!("consumer_context.rs")).unwrap().items.into_iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == "NativeConsumerContext") { return None; }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
            }).unwrap()
        }
        fn normalize(stream: proc_macro2::TokenStream) -> String {
            let mut tokens = stream.into_iter().collect::<Vec<_>>();
            if matches!(tokens.last(), Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == ',')
            {
                tokens.pop();
            }
            tokens
                .into_iter()
                .map(|token| match token {
                    proc_macro2::TokenTree::Group(group) => {
                        format!("{:?}[{}]", group.delimiter(), normalize(group.stream()))
                    }
                    token => token.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
        for (name, expected) in [
            (
                "human",
                syn::parse_quote!({
                    Self::bound(runtime, original, ConsumerOrigin::Http { sink, native })
                }),
            ),
            (
                "human_response",
                syn::parse_quote!({
                    Self::bound(
                        runtime,
                        original,
                        ConsumerOrigin::Response {
                            sink,
                            native,
                            lease,
                        },
                    )
                }),
            ),
        ] {
            let actual = method(name);
            let expected: syn::Block = expected;
            assert_eq!(
                normalize(actual.block.to_token_stream()),
                normalize(expected.to_token_stream())
            );
            let syn::FnArg::Typed(original) = &actual.sig.inputs[1] else {
                panic!("actual original input");
            };
            assert!(
                matches!(&*original.ty, syn::Type::Reference(reference) if reference.mutability.is_some() && matches!(&*reference.elem, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == "OriginalPhase"))
            );
            assert_eq!(actual.sig.inputs.len(), if name == "human" { 4 } else { 5 });
            let mut runtime = actual.block.clone();
            runtime.stmts[0] = syn::Stmt::Expr(
                syn::parse_quote!(Self::bound(
                    runtime,
                    original,
                    ConsumerOrigin::Http { sink, native }
                )),
                None,
            );
            if name == "human_response" {
                assert_ne!(
                    normalize(runtime.to_token_stream()),
                    normalize(expected.to_token_stream())
                );
            }
        }
        let actual = method("bound");
        let syn::Stmt::Expr(syn::Expr::Call(returned), None) = actual.block.stmts.last().unwrap()
        else {
            panic!("actual context return");
        };
        assert!(matches!(&*returned.func, syn::Expr::Path(path) if path.path.is_ident("Ok")));
        let syn::Expr::Struct(context) = &returned.args[0] else {
            panic!("actual bound context");
        };
        let expected_context: syn::ExprStruct = syn::parse_quote!(Self {
            source: ConsumerOriginal::Bound(original),
            runtime,
            origin,
            binding,
            purpose: ScopePurpose::Human(purpose),
            affinity: NativeConsumerAffinity { same: Rc::new(()) },
            complete: false,
        });
        let field_guard = |value: &syn::ExprStruct| {
            value.path.is_ident("Self")
                && value.rest.is_none()
                && value.fields.len() == expected_context.fields.len()
                && value
                    .fields
                    .iter()
                    .zip(&expected_context.fields)
                    .all(|(actual, expected)| {
                        normalize(actual.to_token_stream()) == normalize(expected.to_token_stream())
                    })
        };
        assert!(field_guard(context));
        for cut in 0..context.fields.len() {
            let mut missing = context.clone();
            missing.fields = missing
                .fields
                .into_iter()
                .enumerate()
                .filter_map(|(index, field)| (index != cut).then_some(field))
                .collect();
            assert!(!field_guard(&missing));
        }
        let mut runtime_only = context.clone();
        runtime_only.fields[0].expr = syn::parse_quote!(ConsumerOriginal::Runtime);
        assert!(!field_guard(&runtime_only));
        let mut relabelled = context.clone();
        relabelled.fields[4].expr =
            syn::parse_quote!(ScopePurpose::Runtime(RuntimeServingUse::SqlWrite));
        assert!(!field_guard(&relabelled));
        let syn::Stmt::Local(selection) = &actual.block.stmts[1] else {
            panic!("actual selected result");
        };
        let syn::Expr::Match(selection) = &*selection.init.as_ref().unwrap().expr else {
            panic!("actual selection failure");
        };
        let rejected = selection
            .arms
            .iter()
            .find(|arm| arm.pat.to_token_stream().to_string() == "Err (error)")
            .unwrap();
        let expected_rejection: syn::Expr = syn::parse_quote!({
            original.refuse();
            origin.refuse();
            return Err(error);
        });
        assert_eq!(
            normalize(rejected.body.to_token_stream()),
            normalize(expected_rejection.to_token_stream())
        );
        let syn::Stmt::Local(selected) = &actual.block.stmts[0] else {
            panic!("actual selection");
        };
        let syn::Expr::Call(selected) = &*selected.init.as_ref().unwrap().expr else {
            panic!("actual selection call");
        };
        let syn::Expr::Paren(selected) = &*selected.func else {
            panic!("actual closed selection");
        };
        let syn::Expr::Closure(selected) = &*selected.expr else {
            panic!("actual source selection");
        };
        let syn::Expr::Block(selected) = &*selected.body else {
            panic!("actual source body");
        };
        let expected: syn::Block = syn::parse_quote!({
            origin.require_request()?;
            ensure!(
                runtime.uses_native_storage(),
                "native human Runtime required"
            );
            ensure!(
                original.intent.app() == runtime.app(),
                "native human Runtime app changed"
            );
            original.intent.require_oauth_management()?;
            let purpose = super::serving_use(original.phase, NativeRole::AppHost)?;
            ensure!(
                human_origin_matches(&origin, purpose),
                "native human origin purpose changed"
            );
            if let ConsumerOrigin::Response { sink, lease, .. } = &origin {
                lease.require_human(sink, original.intent)?;
            }
            let commitment = original.intent.commitment()?;
            let binding = Digest::of(&("day2-native-human-serving-v1", &commitment, purpose))?;
            Ok((binding, purpose))
        });
        let guarded = |block: &syn::Block| {
            normalize(block.to_token_stream()) == normalize(expected.to_token_stream())
        };
        assert!(guarded(&selected.block));
        for cut in 0..selected.block.stmts.len() {
            let mut changed = selected.block.clone();
            changed.stmts.remove(cut);
            assert!(!guarded(&changed));
        }
        let mut relabel = selected.block.clone();
        relabel.stmts[4] = syn::parse_quote!(let purpose = super::serving_use(Phase::Response, NativeRole::AppHost)?;);
        assert!(!guarded(&relabel));
        let mut foreign = selected.block.clone();
        foreign.stmts[7] = syn::parse_quote!(let commitment = foreign_intent.commitment()?;);
        assert!(!guarded(&foreign));
    }

    #[test]
    fn startup_contexts_require_the_closed_capture_or_whole_lease_and_grant_only_sql_write() {
        fn normalized(stream: proc_macro2::TokenStream) -> String {
            let mut tokens = stream.into_iter().collect::<Vec<_>>();
            if matches!(tokens.last(), Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == ',')
            {
                tokens.pop();
            }
            tokens
                .into_iter()
                .map(|token| match token {
                    proc_macro2::TokenTree::Group(group) => {
                        format!("{:?}[{}]", group.delimiter(), normalized(group.stream()))
                    }
                    token => token.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
        fn fields_match(actual: &syn::ExprStruct, sql: bool) -> bool {
            let expected: syn::ExprStruct = if sql {
                syn::parse_quote!(Self {
                    source: ConsumerOriginal::Runtime,
                    runtime,
                    origin: ConsumerOrigin::Autonomous(native),
                    binding: Digest::of(&("day2-native-runtime-serving-v1", purpose))?,
                    purpose: ScopePurpose::Runtime(purpose),
                    affinity: NativeConsumerAffinity { same: Rc::new(()) },
                    complete: false,
                })
            } else {
                syn::parse_quote!(Self {
                    source: FinalOriginal::Runtime,
                    runtime,
                    origin: ConsumerOrigin::Autonomous(native),
                    affinity: NativeConsumerAffinity { same: Rc::new(()) },
                    complete: false,
                })
            };
            let fields = |value: &syn::ExprStruct| {
                value
                    .fields
                    .iter()
                    .map(|field| {
                        (
                            field.member.to_token_stream().to_string(),
                            normalized(field.expr.to_token_stream()),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            actual.path.is_ident("Self")
                && actual.rest.is_none()
                && actual.fields.len() == expected.fields.len()
                && fields(actual) == fields(&expected)
        }
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        for (owner, name, source_type) in [
            ("NativeConsumerContext", "startup_sql", "StartupRequest"),
            ("NativeRequestFinalContext", "startup", "StartupLease"),
        ] {
            let method = file
                .items
                .iter()
                .find_map(|item| {
                    let syn::Item::Impl(item) = item else {
                        return None;
                    };
                    if !matches!(&*item.self_ty, syn::Type::Path(path)
                    if path.path.segments.len() == 1 && path.path.segments[0].ident == owner)
                    {
                        return None;
                    }
                    item.items.iter().find_map(|item| match item {
                        syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                        _ => None,
                    })
                })
                .unwrap();
            assert_eq!(
                method.sig.inputs.len(),
                2,
                "no scalar phase/clock/binding supplier"
            );
            let syn::FnArg::Typed(request) = &method.sig.inputs[1] else {
                panic!("actual request");
            };
            assert!(matches!(&*request.ty, syn::Type::Reference(reference)
                if matches!(&*reference.elem, syn::Type::Path(path)
                    if path.path.segments.last().unwrap().ident == source_type)));
            let first: syn::Stmt =
                syn::parse_quote!(let native = request.consumer_origin(runtime)?;);
            assert_eq!(
                method.block.stmts[0].to_token_stream().to_string(),
                first.to_token_stream().to_string()
            );
            if name == "startup_sql" {
                let purpose: syn::Stmt =
                    syn::parse_quote!(let purpose = RuntimeServingUse::SqlWrite;);
                let guarded = |stmt: &syn::Stmt| {
                    stmt.to_token_stream().to_string() == purpose.to_token_stream().to_string()
                };
                assert!(guarded(&method.block.stmts[1]));
                let wider: syn::Stmt = syn::parse_quote!(let purpose = RuntimeServingUse::Read;);
                assert!(!guarded(&wider));
            }
            let syn::Stmt::Expr(syn::Expr::Call(returned), _) = method.block.stmts.last().unwrap()
            else {
                panic!("actual constructed context");
            };
            assert!(matches!(&*returned.func, syn::Expr::Path(path) if path.path.is_ident("Ok")));
            let syn::Expr::Struct(actual) = &returned.args[0] else {
                panic!("actual context fields");
            };
            assert!(fields_match(actual, name == "startup_sql"));
            for index in 0..actual.fields.len() {
                let mut missing = actual.clone();
                missing.fields = missing
                    .fields
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, field)| (i != index).then_some(field))
                    .collect();
                assert!(!fields_match(&missing, name == "startup_sql"));
                let mut replaced = actual.clone();
                replaced.fields[index].expr = syn::parse_quote!(unrelated);
                assert!(!fields_match(&replaced, name == "startup_sql"));
            }
            if name == "startup_sql" {
                let mut widened = actual.clone();
                widened.fields.iter_mut().find(|field| matches!(&field.member, syn::Member::Named(name) if name == "purpose")).unwrap().expr = syn::parse_quote!(ScopePurpose::Runtime(RuntimeServingUse::Read));
                assert!(!fields_match(&widened, true));
            }
            assert!(matches!(&method.vis, syn::Visibility::Restricted(_)));
        }
    }

    #[test]
    fn actual_response_context_forwards_both_native_and_response_lease_checks() {
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        for (name, expected) in [
            (
                "check_current",
                syn::parse_quote!({
                    let selected = native.check_current(stage);
                    let live = lease.check(sink);
                    if selected.is_err() || live.is_err() {
                        self.refuse();
                    }
                    selected?;
                    live
                }),
            ),
            (
                "require_same",
                syn::parse_quote!({
                    let selected = native.require_same(actual);
                    let live = lease.check(sink);
                    if selected.is_err() || live.is_err() {
                        self.refuse();
                        actual.refuse();
                    }
                    selected?;
                    live
                }),
            ),
        ] {
            let expected: syn::Expr = expected;
            let actual = file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == "ConsumerOrigin") { return None; }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
            }).unwrap();
            let request: syn::Stmt = syn::parse_quote!(self.require_request()?;);
            assert_eq!(
                actual.block.stmts[0].to_token_stream().to_string(),
                request.to_token_stream().to_string()
            );
            let syn::Stmt::Expr(syn::Expr::Match(selected), _) = &actual.block.stmts[1] else {
                panic!("origin");
            };
            let arm = selected
                .arms
                .iter()
                .find(|arm| {
                    let syn::Pat::Struct(pattern) = &arm.pat else {
                        return false;
                    };
                    pattern.path.to_token_stream().to_string() == "Self :: Response"
                        && pattern.rest.is_none()
                        && pattern
                            .fields
                            .iter()
                            .map(|field| match (&field.member, &*field.pat) {
                                (syn::Member::Named(name), syn::Pat::Ident(binding))
                                    if name == &binding.ident && binding.subpat.is_none() =>
                                {
                                    name.to_string()
                                }
                                _ => String::new(),
                            })
                            .collect::<Vec<_>>()
                            == ["sink", "native", "lease"]
                })
                .unwrap();
            let guarded = |body: &syn::Expr| {
                body.to_token_stream().to_string() == expected.to_token_stream().to_string()
            };
            assert!(guarded(&arm.body));
            for index in 0..2 {
                let mut bypass = arm.body.clone();
                let syn::Expr::Block(body) = &mut *bypass else {
                    panic!("response body");
                };
                body.block.stmts[index] = if index == 0 {
                    syn::parse_quote!(let selected = Ok(());)
                } else {
                    syn::parse_quote!(let live = Ok(());)
                };
                assert!(!guarded(&bypass));
            }
        }
    }

    #[test]
    fn autonomous_view_cannot_relabel_a_human_creator_response_or_other_runtime_purpose() {
        let purposes = [
            RuntimeServingUse::InitialStorage,
            RuntimeServingUse::PendingCapture,
            RuntimeServingUse::Registration,
            RuntimeServingUse::Read,
            RuntimeServingUse::Refresh,
            RuntimeServingUse::SqlRead,
            RuntimeServingUse::SqlWrite,
            RuntimeServingUse::Response,
            RuntimeServingUse::ResponseComplete,
        ];
        for (index, expected) in purposes.into_iter().enumerate() {
            for (actual_index, actual) in purposes.into_iter().enumerate() {
                assert_eq!(
                    runtime_purpose_matches(ScopePurpose::Runtime(actual), expected),
                    index == actual_index && (2..7).contains(&index)
                );
            }
            assert!(!runtime_purpose_matches(
                ScopePurpose::Human(crate::security_epoch::serving::ServingUse::Response),
                expected
            ));
        }
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        let method = file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == "NativeConsumerContext") { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "require_runtime_purpose" => Some(item),
                _ => None,
            })
        }).unwrap();
        let expected: syn::Block = syn::parse_quote!({
            self.require_runtime(runtime)?;
            if !matches!(&self.source, ConsumerOriginal::Runtime)
                || !runtime_purpose_matches(self.purpose, purpose)
            {
                self.refuse();
                anyhow::bail!("native Runtime consumer original or purpose changed");
            }
            Ok(())
        });
        let guarded = |block: &syn::Block| {
            block.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&method.block));
        let mut relabelled = method.block.clone();
        let syn::Stmt::Expr(syn::Expr::If(selected), _) = &mut relabelled.stmts[1] else {
            panic!("selection");
        };
        *selected.cond = syn::parse_quote! { !runtime_purpose_matches(self.purpose, purpose) };
        assert!(!guarded(&relabelled));
        let mut missing_pointer = method.block.clone();
        missing_pointer.stmts.remove(0);
        assert!(!guarded(&missing_pointer));
    }

    #[test]
    fn actual_response_view_requires_the_http_original_and_exact_response_phase_before_native_work()
    {
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        let method = file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == "NativeConsumerContext") { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "require_response" => Some(item),
                _ => None,
            })
        }).unwrap();
        let expected: syn::Block = syn::parse_quote!({
            self.require_runtime(runtime)?;
            self.require_response_binding()?;
            let selected = match (&self.source, &self.origin, self.purpose) {
                (
                    ConsumerOriginal::Bound(original),
                    ConsumerOrigin::Response { .. },
                    ScopePurpose::Human(crate::security_epoch::serving::ServingUse::Response),
                ) => original.phase == Phase::Response,
                (
                    ConsumerOriginal::Runtime,
                    ConsumerOrigin::Response { .. },
                    ScopePurpose::Runtime(RuntimeServingUse::Response),
                ) => true,
                _ => false,
            };
            if !selected {
                self.refuse();
                anyhow::bail!("native response original or purpose changed");
            }
            Ok(())
        });
        let guarded = |block: &syn::Block| {
            block.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&method.block));
        let mut ordinary = method.block.clone();
        ordinary.stmts[2] = syn::parse_quote!(let selected = true;);
        assert!(!guarded(&ordinary));
        let mut missing_pointer = method.block.clone();
        missing_pointer.stmts.remove(0);
        assert!(!guarded(&missing_pointer));
    }

    #[test]
    fn actual_runtime_check_is_pure_and_precedes_native_observation() {
        fn method(owner: &str, name: &str) -> syn::ImplItemFn {
            syn::parse_file(include_str!("consumer_context.rs")).unwrap().items.into_iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == owner)) { return None; }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
            }).unwrap()
        }
        fn pure(method: &syn::ImplItemFn) -> bool {
            let Some(syn::Stmt::Expr(syn::Expr::If(first), _)) = method.block.stmts.first() else {
                return false;
            };
            let condition = first.cond.to_token_stream().to_string().replace(' ', "");
            if condition != "!std::ptr::eq(self.runtime,runtime)" {
                return false;
            }
            let Some(syn::Stmt::Expr(syn::Expr::MethodCall(refused), Some(_))) =
                first.then_branch.stmts.first()
            else {
                return false;
            };
            if refused.method != "refuse"
                || refused.receiver.to_token_stream().to_string() != "self"
                || !refused.args.is_empty()
            {
                return false;
            }
            struct Pure(bool);
            impl<'ast> Visit<'ast> for Pure {
                fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                    let path = call.func.to_token_stream().to_string();
                    self.0 &= path == "std :: ptr :: eq" || path == "Ok";
                    syn::visit::visit_expr_call(self, call);
                }
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    let receiver = call.receiver.to_token_stream().to_string();
                    self.0 &= call.args.is_empty()
                        && ((receiver == "self" && call.method == "refuse")
                            || (receiver == "runtime" && call.method == "uses_native_storage"));
                    syn::visit::visit_expr_method_call(self, call);
                }
                fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                    let args =
                        syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                            .parse2(mac.tokens.clone());
                    self.0 &= mac.path.to_token_stream().to_string() == "anyhow :: bail"
                        && args.is_ok_and(|args| args.len() == 1 && matches!(&args[0], syn::Expr::Lit(value) if matches!(&value.lit, syn::Lit::Str(_))));
                }
            }
            let mut pure = Pure(true);
            pure.visit_block(&method.block);
            pure.0
        }
        fn runtime_is_first(method: &syn::ImplItemFn) -> bool {
            let Some(syn::Stmt::Local(local)) = method.block.stmts.first() else {
                return false;
            };
            let Some(init) = &local.init else {
                return false;
            };
            let syn::Expr::Call(call) = &*init.expr else {
                return false;
            };
            let syn::Expr::Paren(group) = &*call.func else {
                return false;
            };
            let syn::Expr::Closure(closure) = &*group.expr else {
                return false;
            };
            let syn::Expr::Block(block) = &*closure.body else {
                return false;
            };
            block.block.stmts.first().is_some_and(|statement| {
                statement.to_token_stream().to_string() == "self . require_runtime (runtime) ? ;"
            })
        }
        for (owner, entry) in [
            ("NativeConsumerContext", "check"),
            ("NativeRequestFinalContext", "check_final"),
        ] {
            let actual = method(owner, "require_runtime");
            assert!(pure(&actual));
            let mut native_first = actual.clone();
            native_first
                .block
                .stmts
                .insert(0, syn::parse_quote! { stage.check()?; });
            assert!(!pure(&native_first));
            let mut metadata = actual.clone();
            let syn::Stmt::Expr(syn::Expr::If(first), _) = &mut metadata.block.stmts[0] else {
                panic!("pointer first");
            };
            *first.cond = syn::parse_quote! { self.runtime.scope() != runtime.scope() };
            assert!(!pure(&metadata));
            let mut ignored = actual.clone();
            let syn::Stmt::Expr(syn::Expr::If(first), _) = &mut ignored.block.stmts[0] else {
                panic!("pointer first");
            };
            first.then_branch.stmts.remove(0);
            assert!(!pure(&ignored));
            let actual = method(owner, entry);
            assert!(runtime_is_first(&actual));
            let mut late = actual.clone();
            late.block
                .stmts
                .insert(0, syn::parse_quote! { stage.check()?; });
            assert!(!runtime_is_first(&late));
        }
    }

    #[test]
    fn actual_completion_requires_the_matching_owning_token_before_disarm() {
        fn guarded(method: &syn::ImplItemFn, token_type: &str) -> bool {
            let inputs = method.sig.inputs.iter().collect::<Vec<_>>();
            let [syn::FnArg::Receiver(receiver), syn::FnArg::Typed(token)] = inputs.as_slice()
            else {
                return false;
            };
            if receiver.reference.is_some()
                || receiver.mutability.is_none()
                || !matches!(&*token.ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == token_type))
            {
                return false;
            }
            fn propagated(statement: &syn::Stmt, method: &str, context: bool) -> bool {
                let syn::Stmt::Expr(syn::Expr::Try(propagated), Some(_)) = statement else {
                    return false;
                };
                let syn::Expr::MethodCall(call) = &*propagated.expr else {
                    return false;
                };
                if call.method != method
                    || !matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("token"))
                {
                    return false;
                }
                if !context {
                    return call.args.is_empty();
                }
                call.args.len() == 1
                    && matches!(&call.args[0], syn::Expr::Reference(borrow)
                    if borrow.mutability.is_some() && matches!(&*borrow.expr, syn::Expr::Path(path) if path.path.is_ident("self")))
            }
            if method.block.stmts.len() != 4
                || !propagated(&method.block.stmts[0], "check_context", true)
                || !propagated(&method.block.stmts[1], "complete_native", false)
            {
                return false;
            }
            #[derive(Default)]
            struct Flow(Vec<String>);
            impl<'ast> Visit<'ast> for Flow {
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    if matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("token"))
                    {
                        self.0.push(call.method.to_string());
                    }
                    syn::visit::visit_expr_method_call(self, call);
                }
                fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
                    if assignment.left.to_token_stream().to_string() == "self . complete" {
                        self.0.push(if matches!(&*assignment.right, syn::Expr::Lit(value) if matches!(&value.lit, syn::Lit::Bool(flag) if flag.value)) {
                            "disarm"
                        } else { "wrong_disarm" }.into());
                    }
                    syn::visit::visit_expr_assign(self, assignment);
                }
            }
            let mut flow = Flow::default();
            flow.visit_block(&method.block);
            flow.0 == ["check_context", "complete_native", "disarm"]
        }
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        for (owner, method_name, token_type) in [
            (
                "NativeConsumerContext",
                "complete_scope",
                "NativeConsumerCompletion",
            ),
            (
                "NativeRequestFinalContext",
                "complete_after_native",
                "RestoredAppRequestSettlement",
            ),
        ] {
            let actual = file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == owner)) {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == method_name => Some(item.clone()),
                    _ => None,
                })
            }).unwrap();
            assert!(guarded(&actual, token_type), "{method_name}");
            let mut early = actual.clone();
            let disarm = early.block.stmts.remove(2);
            early.block.stmts.insert(0, disarm);
            assert!(!guarded(&early, token_type));
            for index in [0, 1] {
                let mut deleted = actual.clone();
                deleted.block.stmts.remove(index);
                assert!(!guarded(&deleted, token_type));
            }
            let mut ignored_check = actual.clone();
            ignored_check.block.stmts[0] =
                syn::parse_quote! { let _ = token.check_context(&mut self); };
            assert!(!guarded(&ignored_check, token_type));
            let mut ignored_settlement = actual.clone();
            ignored_settlement.block.stmts[1] =
                syn::parse_quote! { let _ = token.complete_native(); };
            assert!(!guarded(&ignored_settlement, token_type));
            let mut foreign = actual.clone();
            let syn::FnArg::Typed(token) = &mut foreign.sig.inputs[1] else {
                panic!("token");
            };
            *token.ty = syn::parse_quote! { NativeConsumerOrigin };
            assert!(!guarded(&foreign, token_type));
        }
    }

    #[test]
    fn runtime_response_and_read_only_purposes_cannot_gain_sql_write() {
        for (purpose, expected) in [
            (RuntimeServingUse::InitialStorage, false),
            (RuntimeServingUse::PendingCapture, false),
            (RuntimeServingUse::Registration, true),
            (RuntimeServingUse::Read, true),
            (RuntimeServingUse::Refresh, true),
            (RuntimeServingUse::SqlRead, false),
            (RuntimeServingUse::SqlWrite, true),
            (RuntimeServingUse::Response, false),
            (RuntimeServingUse::ResponseComplete, false),
        ] {
            assert_eq!(
                runtime_sql_write_allowed(ScopePurpose::Runtime(purpose)),
                expected
            );
        }
        assert!(!runtime_sql_write_allowed(ScopePurpose::Human(
            crate::security_epoch::serving::ServingUse::Response,
        )));
    }

    #[test]
    fn actual_runtime_sql_arm_requires_the_closed_write_allowlist() {
        fn guarded(method: &syn::ImplItemFn) -> bool {
            #[derive(Default)]
            struct Guards(Vec<bool>);
            impl<'ast> Visit<'ast> for Guards {
                fn visit_expr_match(&mut self, selected: &'ast syn::ExprMatch) {
                    if selected.expr.to_token_stream().to_string() == "& self . source" {
                        for arm in &selected.arms {
                            if arm.pat.to_token_stream().to_string()
                                != "ConsumerOriginal :: Runtime"
                            {
                                continue;
                            }
                            let syn::Expr::Macro(guard) = &*arm.body else {
                                self.0.push(false);
                                continue;
                            };
                            let arguments = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                                .parse2(guard.mac.tokens.clone());
                            let valid = arguments.is_ok_and(|arguments| {
                                guard.mac.path.is_ident("ensure")
                                    && arguments.len() == 2
                                    && arguments[0].to_token_stream().to_string()
                                        == "runtime_sql_write_allowed (self . purpose)"
                            });
                            self.0.push(valid);
                        }
                    }
                    syn::visit::visit_expr_match(self, selected);
                }
            }
            let mut guards = Guards::default();
            guards.visit_block(&method.block);
            guards.0 == [true]
        }
        let file = syn::parse_file(include_str!("consumer_context.rs")).unwrap();
        let actual = file.items.into_iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "NativeConsumerContext")) {
                return None;
            }
            item.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "check_sql" => Some(item),
                _ => None,
            })
        }).unwrap();
        assert!(guarded(&actual));
        let text = actual.to_token_stream().to_string();
        let target = "runtime_sql_write_allowed (self . purpose)";
        assert_eq!(text.matches(target).count(), 1);
        let deleted = syn::parse_str::<syn::ImplItemFn>(&text.replacen(target, "true", 1)).unwrap();
        assert!(!guarded(&deleted));
    }
}
