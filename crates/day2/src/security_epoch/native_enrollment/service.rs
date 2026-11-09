use super::issuer_costs::{Costs, Operation, Outcome, Recorder, Subject, preserve_error};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    birth::IssuerOwner,
    channel::Channel,
    policy::{EnrollmentPolicy, decode_key},
    process::{MessageProcess, SelfSnapshot},
    protocol::{self, Packet, ProcessData, SignedStage, StageData},
    runtime::{self, RuntimeBinding},
};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

struct Enrollment {
    public_key: String,
    process: ProcessData,
    runtime: RuntimeBinding,
}

// Closing is irreversible even when the reply is lost. The retained cohort
// owns the actual received Controller anchors and original; a later restore
// request cannot reconstruct this generation from the signed DATA alone.
enum Issuance {
    Open,
    Frozen(Box<FrozenCohort>),
    Refused,
}

struct FrozenCohort {
    statement: protocol::FrozenIssuance,
    signature: String,
    certificate: protocol::IssuerCertificate,
    controller: MessageProcess,
    bound: MessageProcess,
    original: NativeAcquisition,
    restore_attempted: bool,
    restore: Option<AuthorizedRestore>,
    finish_attempted: bool,
    completion: Option<protocol::SignedRestoreIssuerCompletion>,
    role_decision: RestoreRoleDecision,
}

// A retained signed decision is NOT permission for later cold admission.
// The issuer remains Frozen; uncertainty cannot turn this into Open or retry.
enum RestoreRoleDecision {
    Fresh,
    Spent,
    Retained(Box<protocol::SignedRestoreRoleActivation>),
}

struct AuthorizedRestore {
    authorization: protocol::SignedRestoreAuthorization,
    app: RestoreAppAdmission,
}

// One-way attempt state; prepared/retained is deliberately not "delivered".
// No bool/optional-owner combination can reopen a spent admission.
enum RestoreAppAdmission {
    Available,
    Started,
    Retained(Box<AuthorizedRestoreApp>),
}

impl RestoreAppAdmission {
    fn begin(&mut self) -> Result<()> {
        ensure!(
            matches!(self, Self::Available),
            "native_restore_app_attempt_spent"
        );
        *self = Self::Started;
        Ok(())
    }

    fn retain(&mut self, app: AuthorizedRestoreApp) -> Result<()> {
        ensure!(
            matches!(self, Self::Started),
            "native_restore_app_cohort_repeated"
        );
        *self = Self::Retained(Box::new(app));
        Ok(())
    }
}

/// Actual prepared App admission plus the ORIGINAL received hello/bind kernel
/// anchors. Retained before the grant send; this proves neither delivery nor
/// keeper completion, ordinary enrollment, issuer reopening or serving.
struct AuthorizedRestoreApp {
    policy: EnrollmentPolicy,
    certificate: protocol::IssuerCertificate,
    authorization: protocol::SignedRestoreAuthorization,
    admission: protocol::SignedRestoreAdmission,
    hello: MessageProcess,
    bound: MessageProcess,
    original: NativeAcquisition,
    // One-way negative attempt gate, never delivery or ordinary permission.
    confirmation_attempted: bool,
    confirmation: Option<protocol::SignedRestorePreparedConfirmation>,
}

impl AuthorizedRestoreApp {
    // Comparison DATA from this retained, verified grant. The App's actual
    // original was narrowed to this exact signed effective ceiling at receipt.
    // This does not reconstruct that original or adopt its opaque domain.
    fn statement_data(
        &mut self,
        costs: &Costs,
    ) -> Result<super::restore_peer_wire::RestoreAppStatement> {
        self.check(costs)?;
        let requested: Result<_> = {
            let admitted = &self.admission.statement;
            Ok(super::restore_peer_wire::RestoreAppStatement {
                certificate: self.certificate.clone(),
                authorization: self.authorization.clone(),
                admission: self.admission.clone(),
                original: super::restore_peer_wire::RestoreOriginal {
                    domain: admitted.receiver_clock.clone(),
                    origin_ns: admitted.receiver_origin_ns,
                    deadline_ns: admitted.effective_deadline_ns,
                },
            })
        };
        let checked = self.check(costs);
        if requested.is_err() || checked.is_err() {
            self.original.refuse();
        }
        let statement = requested?;
        checked?;
        Ok(statement)
    }

    fn capture(
        issuer: &IssuerOwner,
        authorization: &protocol::SignedRestoreAuthorization,
        admission: protocol::SignedRestoreAdmission,
        originals: (&mut NativeAcquisition, &mut NativeAcquisition),
        peers: (&mut MessageProcess, &mut MessageProcess),
        costs: &Costs,
    ) -> Result<Self> {
        let (frozen, acquisition) = originals;
        let (peer, bound) = peers;
        let requested: Result<Self> = (|| {
            frozen.remaining()?;
            acquisition.remaining()?;
            // Acquisition IDs intentionally differ across requests/processes.
            // Actual admitted node/boot/time-namespace anchors, not equality of
            // opaque IDs, establish the physical clock domain before bounds.
            runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
            admission.verify_data(
                &issuer.policy,
                &issuer.certificate,
                authorization,
                frozen.sample()?.elapsed,
            )?;
            ensure!(
                admission.statement.process == *peer.data() && peer.data() == bound.data(),
                "native_restore_app_retained_actor_changed"
            );
            let (_, frozen_ceiling) = frozen.interval_data()?;
            let (_, request_ceiling) = acquisition.interval_data()?;
            let ceiling =
                std::time::Duration::from_nanos(admission.statement.effective_deadline_ns)
                    .min(frozen_ceiling)
                    .min(request_ceiling);
            // This is a child of the retained FREEZE original, never a fresh
            // request clock or an origin rebased to App admission.
            let mut original = frozen.narrow(5, ceiling)?;
            let mut hello =
                peer.retain_message_anchor(&mut original, &costs.hashes(Subject::Requester))?;
            let mut answer =
                bound.retain_message_anchor(&mut original, &costs.hashes(Subject::Requester))?;
            MessageProcess::check_same_actor(
                &mut [peer, bound, &mut hello, &mut answer],
                &mut original,
                &costs.hashes(Subject::Requester),
            )?;
            admission.verify_data(
                &issuer.policy,
                &issuer.certificate,
                authorization,
                original.sample()?.elapsed,
            )?;
            original.remaining()?;
            acquisition.remaining()?;
            // All admission checks ran on the existing actual owners before
            // this positive resource value is constructed or retained.
            Ok(Self {
                policy: issuer.policy.clone(),
                certificate: issuer.certificate.clone(),
                authorization: authorization.clone(),
                admission,
                hello,
                bound: answer,
                original,
                confirmation_attempted: false,
                confirmation: None,
            })
        })();
        let checked = frozen.remaining();
        if requested.is_err() || checked.is_err() {
            frozen.refuse();
            acquisition.refuse();
        }
        let app = requested?;
        checked?;
        Ok(app)
    }

    fn check(&mut self, costs: &Costs) -> Result<()> {
        let requested: Result<()> = (|| {
            self.admission.verify_data(
                &self.policy,
                &self.certificate,
                &self.authorization,
                self.original.sample()?.elapsed,
            )?;
            ensure!(
                self.admission.statement.process == *self.hello.data()
                    && self.hello.data() == self.bound.data(),
                "native_restore_app_retained_actor_changed"
            );
            MessageProcess::check_same_actor(
                &mut [&mut self.hello, &mut self.bound],
                &mut self.original,
                &costs.hashes(Subject::Requester),
            )?;
            self.original.remaining().map(|_| ())
        })();
        let checked = self.original.remaining();
        if requested.is_err() || checked.is_err() {
            self.original.refuse();
        }
        requested?;
        checked.map(|_| ())
    }
}

struct ClosingFreeze<'issuer> {
    issuance: &'issuer mut Issuance,
}

impl Issuance {
    fn require_open(&self) -> Result<()> {
        ensure!(
            matches!(self, Self::Open),
            "native_enrollment_issuance_closed"
        );
        Ok(())
    }

    fn close(&mut self) -> Result<ClosingFreeze<'_>> {
        self.require_open()?;
        *self = Self::Refused;
        Ok(ClosingFreeze { issuance: self })
    }
}

impl ClosingFreeze<'_> {
    fn retain_frozen(self, cohort: FrozenCohort) -> Result<()> {
        // Only the already-closed successful freeze tail can install this.
        // Open, a prior retained generation and every repeated freeze refuse.
        ensure!(
            matches!(self.issuance, Issuance::Refused),
            "native_restore_freeze_already_retained"
        );
        *self.issuance = Issuance::Frozen(Box::new(cohort));
        Ok(())
    }
}

impl FrozenCohort {
    fn check_prepared_confirmation(&mut self, costs: &Costs) -> Result<()> {
        let Some(RestoreAppAdmission::Retained(app)) =
            self.restore.as_mut().map(|entry| &mut entry.app)
        else {
            return Ok(());
        };
        let Some(confirmation) = app.confirmation.clone() else {
            return Ok(());
        };
        ensure!(
            app.confirmation_attempted,
            "native_restore_prepared_record_without_attempt"
        );
        let completion = self
            .completion
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native_restore_completion_missing"))?;
        let RestoreRoleDecision::Retained(decision) = &self.role_decision else {
            anyhow::bail!("native_restore_role_decision_missing")
        };
        let statement = app.statement_data(costs)?;
        confirmation.verify_data(
            &app.policy,
            &self.certificate,
            (decision, completion),
            &statement,
            (
                &confirmation.statement.request,
                &confirmation.statement.challenge,
            ),
            self.original.sample()?.elapsed,
        )
    }

    fn capture(
        statement: protocol::FrozenIssuance,
        signature: String,
        certificate: &protocol::IssuerCertificate,
        peer: &mut MessageProcess,
        bound: &mut MessageProcess,
        acquisition: &mut NativeAcquisition,
        costs: &Costs,
    ) -> Result<Self> {
        // Cold issuer grants identify the already enrolled actors. Their old
        // expiry is not the lifetime of this authenticated freeze request.
        // Meet BOTH signed Current request ceilings with THIS actual original;
        // narrow preserves its origin, spent time and shared refusal state.
        let ceiling = statement
            .selection
            .current_deadline_data(acquisition.sample()?.elapsed)?;
        let mut original = acquisition.narrow(5, ceiling)?;
        let controller =
            peer.retain_message_anchor(&mut original, &costs.hashes(Subject::Requester))?;
        let bound =
            bound.retain_message_anchor(&mut original, &costs.hashes(Subject::Requester))?;
        let mut cohort = Self {
            statement,
            signature,
            certificate: certificate.clone(),
            controller,
            bound,
            original,
            restore_attempted: false,
            restore: None,
            finish_attempted: false,
            completion: None,
            role_decision: RestoreRoleDecision::Fresh,
        };
        cohort.check(costs)?;
        acquisition.remaining()?;
        Ok(cohort)
    }

    fn check(&mut self, costs: &Costs) -> Result<()> {
        let requested: Result<()> = (|| {
            self.original.remaining()?;
            ensure!(
                self.statement.issuer == self.certificate.digest()?,
                "native_restore_frozen_issuer_changed"
            );
            protocol::verify(
                &self.certificate.data.public_key,
                "restore-issuer-frozen",
                &self.statement,
                &self.signature,
            )?;
            ensure!(
                self.controller.data() == &self.statement.selection.controller.stage.data.process
                    && self.bound.data() == self.controller.data(),
                "native_restore_frozen_controller_changed"
            );
            MessageProcess::check_same_actor(
                &mut [&mut self.controller, &mut self.bound],
                &mut self.original,
                &costs.hashes(Subject::Requester),
            )?;
            self.original.remaining().map(|_| ())
        })();
        // App and Controller native observations remain independent even when
        // the first actor failed. A retained grant is never a delivery receipt.
        let app = match self.restore.as_mut().map(|restore| &mut restore.app) {
            Some(RestoreAppAdmission::Retained(app)) => app.check(costs),
            _ => Ok(()),
        };
        let confirmation = self.check_prepared_confirmation(costs);
        let checked = self.original.remaining();
        if requested.is_err() || app.is_err() || confirmation.is_err() || checked.is_err() {
            self.original.refuse();
        }
        requested?;
        app?;
        confirmation?;
        checked.map(|_| ())
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, Clone);
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, Copy);
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, Default);
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, Send);
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, Sync);
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, std::fmt::Debug);
    assert_not_impl!(AppConfirmationAttempt<'static, 'static>, serde::Serialize);
    assert_not_impl!(
        AppConfirmationAttempt<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(FrozenCohort, Clone);
    assert_not_impl!(FrozenCohort, Copy);
    assert_not_impl!(FrozenCohort, Default);
    assert_not_impl!(FrozenCohort, Send);
    assert_not_impl!(FrozenCohort, Sync);
    assert_not_impl!(FrozenCohort, std::fmt::Debug);
    assert_not_impl!(FrozenCohort, serde::Serialize);
    assert_not_impl!(FrozenCohort, serde::Deserialize<'static>);
    assert_not_impl!(FrozenCohort, std::ops::Deref);
    assert_not_impl!(FrozenCohort, AsRef<std::fs::File>);
    assert_not_impl!(FrozenCohort, std::borrow::Borrow<std::fs::File>);
    assert_not_impl!(AuthorizedRestoreApp, Clone);
    assert_not_impl!(AuthorizedRestoreApp, Copy);
    assert_not_impl!(AuthorizedRestoreApp, Default);
    assert_not_impl!(AuthorizedRestoreApp, Send);
    assert_not_impl!(AuthorizedRestoreApp, Sync);
    assert_not_impl!(AuthorizedRestoreApp, std::fmt::Debug);
    assert_not_impl!(AuthorizedRestoreApp, serde::Serialize);
    assert_not_impl!(AuthorizedRestoreApp, serde::Deserialize<'static>);
    assert_not_impl!(AuthorizedRestoreApp, std::ops::Deref);
    assert_not_impl!(AuthorizedRestoreApp, AsRef<std::fs::File>);
    assert_not_impl!(AuthorizedRestoreApp, std::borrow::Borrow<std::fs::File>);
    assert_not_impl!(ClosingFreeze<'static>, Clone);
    assert_not_impl!(ClosingFreeze<'static>, Copy);
    assert_not_impl!(ClosingFreeze<'static>, Default);
    assert_not_impl!(ClosingFreeze<'static>, Send);
    assert_not_impl!(ClosingFreeze<'static>, Sync);
    assert_not_impl!(ClosingFreeze<'static>, std::fmt::Debug);
    assert_not_impl!(ClosingFreeze<'static>, serde::Serialize);
    assert_not_impl!(ClosingFreeze<'static>, serde::Deserialize<'static>);
    assert_not_impl!(ClosingFreeze<'static>, std::ops::Deref);
    assert_not_impl!(ClosingFreeze<'static>, AsRef<std::fs::File>);
    assert_not_impl!(ClosingFreeze<'static>, std::borrow::Borrow<std::fs::File>);
};

pub(super) fn run() -> Result<()> {
    let mut issuer = IssuerOwner::born()?;
    let mut enrolled = BTreeMap::new();
    let mut issuance = Issuance::Open;
    let mut recorder = Recorder::new(std::io::stderr());
    loop {
        let (mut channel, mut acquisition) = issuer.listener.next()?;
        let mut work = crate::security_epoch::admission_work::begin(
            crate::security_epoch::admission_work::Work::IssuerServiceAdmission,
        );
        let costs = recorder.connection();
        // Parent failure remains fatal; request failure still closes only its
        // own connection. No diagnostic record formats the native error.
        let before = costs.measure(Operation::ParentBefore, || {
            issuer
                .parent
                .check_identity(&mut acquisition, &costs.hashes(Subject::ParentBefore))
        });
        if let Err(error) = before {
            work.finish(false);
            drop(channel);
            drop(acquisition);
            return preserve_error(
                Err(error),
                recorder.emit(&costs, Outcome::ParentBeforeError),
            );
        }
        let served = costs.measure(Operation::Serve, || {
            serve(
                &mut issuer,
                &mut enrolled,
                &mut issuance,
                &mut channel,
                &mut acquisition,
                &costs,
            )
        });
        let checked = (|| {
            let mut check = NativeAcquisition::begin(5)?;
            costs.measure(Operation::ParentAfter, || {
                issuer
                    .parent
                    .check_identity(&mut check, &costs.hashes(Subject::ParentAfter))
            })
        })();
        // Preserve the original connection lifetime THROUGH the post-grant
        // parent check. Only then close it and end both temporary intervals.
        drop(channel);
        drop(acquisition);
        let outcome = if checked.is_err() {
            Outcome::ParentAfterError
        } else if served.is_err() {
            Outcome::RequestError
        } else {
            Outcome::Completed
        };
        work.finish(served.is_ok() && checked.is_ok());
        let exported = recorder.emit(&costs, outcome);
        if checked.is_err() {
            return preserve_error(checked, exported);
        }
        if exported.is_err() {
            return preserve_error(served, exported);
        }
        // As before, a malformed/failed request alone does not restart or
        // reconstruct this issuer generation or clear an enrollment row.
    }
}

fn serve(
    issuer: &mut IssuerOwner,
    enrolled: &mut BTreeMap<(u32, u64, super::NativeRole), Enrollment>,
    issuance: &mut Issuance,
    channel: &mut Channel,
    acquisition: &mut NativeAcquisition,
    costs: &Costs,
) -> Result<()> {
    ensure!(
        super::birth::load_policy(acquisition)? == issuer.policy,
        "native_enrollment_operator_selection_changed"
    );
    let mut current = costs.measure(Operation::IssuerSnapshot, || {
        SelfSnapshot::acquire(
            &issuer.policy.issuer_code,
            acquisition,
            &costs.hashes(Subject::Issuer),
        )
    })?;
    current.require_node_init(acquisition)?;
    ensure!(
        current.data == issuer.certificate.data.process,
        "native_enrollment_issuer_identity_changed"
    );
    // Parse the closed role before selecting its executable pin. An initial
    // untrusted role header cannot create authority; actual receipt observes
    // kernel process handles and later joins the selected runtime role.
    let (packet, mut peer) = costs.measure(Operation::Hello, || {
        channel.receive_role(
            &issuer.policy,
            acquisition,
            &costs.hashes(Subject::Requester),
        )
    })?;
    if let Packet::FreezeHello { selection, request } = packet {
        return freeze(
            issuer,
            enrolled,
            issuance,
            (channel, acquisition),
            (costs, &mut current, &mut peer),
            *selection,
            request,
        );
    }
    match packet {
        Packet::RestorePrepareHello {
            authorization,
            request,
        } => {
            let Issuance::Frozen(cohort) = issuance else {
                anyhow::bail!("native_restore_frozen_generation_required");
            };
            return restore_prepare(
                issuer,
                cohort,
                (channel, acquisition),
                (costs, &mut current, &mut peer),
                *authorization,
                request,
            );
        }
        Packet::RestoreAppHello { request } => {
            let Issuance::Frozen(cohort) = issuance else {
                anyhow::bail!("native_restore_frozen_generation_required");
            };
            return restore_app(
                issuer,
                cohort,
                (channel, acquisition),
                (costs, &mut current, &mut peer),
                *request,
            );
        }
        Packet::RestoreFinishHello {
            completion,
            request,
        } => {
            let Issuance::Frozen(cohort) = issuance else {
                anyhow::bail!("native_restore_frozen_generation_required");
            };
            return restore_finish(
                issuer,
                cohort,
                (channel, acquisition),
                (costs, &mut current, &mut peer),
                *completion,
                request,
            );
        }
        Packet::RestoreAppConfirmHello { decision, request } => {
            let Issuance::Frozen(cohort) = issuance else {
                anyhow::bail!("native_restore_frozen_generation_required")
            };
            return restore_app_confirmation(
                issuer,
                cohort,
                (channel, acquisition),
                (costs, &mut current, &mut peer),
                *decision,
                request,
            );
        }
        Packet::RestoreRoleHello {
            completion,
            request,
        } => {
            let Issuance::Frozen(cohort) = issuance else {
                anyhow::bail!("native_restore_frozen_generation_required");
            };
            return restore_role_decision(
                issuer,
                cohort,
                (channel, acquisition),
                (costs, &mut current, &mut peer),
                *completion,
                request,
            );
        }
        _ => {}
    }
    issuance.require_open()?;
    let Packet::StageHello {
        policy,
        role,
        purpose,
        public_key,
        request,
    } = packet
    else {
        anyhow::bail!("native_enrollment_role_order")
    };
    purpose.require_role(role)?;
    ensure!(
        policy == issuer.policy.digest()?,
        "native_enrollment_policy_mismatch"
    );
    decode_key(&public_key)?;
    let identity = (peer.data().process, peer.data().start_ticks, role);
    if let Some(existing) = enrolled.get(&identity) {
        ensure!(
            existing.public_key == public_key && existing.process == *peer.data(),
            "native_enrollment_process_rekey_refused"
        );
    } else {
        ensure!(enrolled.len() < 1024, "native_enrollment_table_full");
    }
    runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
    let challenge = protocol::nonce("role-bind")?;
    channel.send(
        &Packet::StageNonce {
            request: request.clone(),
            challenge: challenge.clone(),
        },
        acquisition,
    )?;
    let (packet, mut bound) = costs.measure(Operation::Bind, || {
        channel.receive(
            issuer.policy.code(role),
            acquisition,
            &costs.hashes(Subject::Requester),
        )
    })?;
    let Packet::StageBind {
        policy: selected,
        role: selected_role,
        purpose: selected_purpose,
        public_key: selected_key,
        request: echoed,
        challenge: answered,
        signature,
    } = packet
    else {
        anyhow::bail!("native_enrollment_role_order")
    };
    ensure!(
        selected == policy
            && selected_role == role
            && selected_purpose == purpose
            && selected_key == public_key
            && echoed == request
            && answered == challenge
            && peer.data() == bound.data(),
        "native_enrollment_role_binding"
    );
    protocol::verify(
        &public_key,
        "role-bind",
        &(&policy, role, purpose, &public_key, &request, &challenge),
        &signature,
    )?;
    let runtime = costs.measure(Operation::Runtime, || {
        runtime::current(&issuer.policy, role, &mut peer, acquisition, costs)
    })?;
    if let Some(existing) = enrolled.get(&identity) {
        ensure!(
            existing.runtime == runtime,
            "native_enrollment_runtime_incarnation_changed"
        );
    }
    costs.measure(Operation::ParentBeforeGrant, || {
        issuer
            .parent
            .check_identity(acquisition, &costs.hashes(Subject::ParentBefore))
    })?;
    issuer.certificate.verify(&issuer.policy)?;
    MessageProcess::check_same_actor(
        &mut [&mut peer, &mut bound],
        acquisition,
        &costs.hashes(Subject::Requester),
    )?;
    let (origin, _) = acquisition.interval_data()?;
    // Serving this request still has the original five-second issuer budget.
    // A signed closed purpose may carry its separate subsequent interval;
    // it never widens this authentication budget or another purpose.
    let deadline = origin
        .checked_add(purpose.limit())
        .ok_or_else(|| anyhow::anyhow!("native_enrollment_stage_interval_overflow"))?;
    let data = StageData {
        issuer: issuer.certificate.digest()?,
        policy,
        role,
        purpose,
        public_key: public_key.clone(),
        challenge,
        request,
        process: peer.data().clone(),
        runtime: runtime.clone(),
        origin_ns: origin.as_nanos().try_into()?,
        deadline_ns: deadline.as_nanos().try_into()?,
    };
    let stage = SignedStage {
        signature: issuer.key.sign("role-stage", &data)?,
        data,
    };
    // Bind before the ambiguous send. Losing a reply never enables a new key
    // or reconstructs the lost native owner from a stored row.
    enrolled.entry(identity).or_insert_with(|| Enrollment {
        public_key,
        process: peer.data().clone(),
        runtime,
    });
    costs.measure(Operation::ParentBeforePublish, || {
        issuer
            .parent
            .check_identity(acquisition, &costs.hashes(Subject::ParentBefore))
    })?;
    current.check(acquisition)?;
    channel.send(
        &Packet::StageGrant {
            certificate: issuer.certificate.clone(),
            stage: Box::new(stage),
        },
        acquisition,
    )?;
    Ok(())
}

// No replacement enrollment table, expiry pruning or issuer restart adoption.
// Only the actual serial grant loop can close itself. This proves only new
// role/cold-peer exclusion, not termination of any business/remote right.
fn freeze(
    issuer: &mut IssuerOwner,
    enrolled: &BTreeMap<(u32, u64, super::NativeRole), Enrollment>,
    issuance: &mut Issuance,
    transport: (&mut Channel, &mut NativeAcquisition),
    observations: (&Costs, &mut SelfSnapshot, &mut MessageProcess),
    selection: protocol::FreezeSelection,
    request: day2_capabilities::Digest,
) -> Result<()> {
    use super::NativeRole;
    let (channel, acquisition) = transport;
    let (costs, current, peer) = observations;
    issuance.require_open()?;
    let controller = &selection.controller;
    let app = &selection.app;
    let now = acquisition.sample()?.elapsed;
    for (statement, role) in [
        (app, NativeRole::AppHost),
        (controller, NativeRole::EpochController),
    ] {
        ensure!(
            statement.certificate == issuer.certificate
                && statement.stage.data.issuer == issuer.certificate.digest()?
                && statement.stage.data.policy == issuer.policy.digest()?
                && statement.stage.data.role == role,
            "native_restore_issuer_selection_changed"
        );
        statement.validate_issued_request_data(&issuer.policy, &issuer.certificate, role, now)?;
        let key = (
            statement.stage.data.process.process,
            statement.stage.data.process.start_ticks,
            role,
        );
        let actual = enrolled
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("native_restore_actor_not_enrolled"))?;
        ensure!(
            actual.process == statement.stage.data.process
                && actual.runtime == statement.stage.data.runtime
                && actual.public_key == statement.stage.data.public_key,
            "native_restore_actor_changed"
        );
    }
    ensure!(
        peer.data() == &controller.stage.data.process
            && app.stage.data.process != controller.stage.data.process,
        "native_restore_controller_sender_changed"
    );
    let challenge = protocol::nonce("restore-issuer-freeze")?;
    channel.send(
        &Packet::FreezeNonce {
            request: request.clone(),
            challenge: challenge.clone(),
        },
        acquisition,
    )?;
    let (packet, mut bound) = channel.receive(
        issuer.policy.code(NativeRole::EpochController),
        acquisition,
        &costs.hashes(Subject::Requester),
    )?;
    let Packet::FreezeBind {
        selection: selected,
        request: echoed,
        challenge: answered,
        signature,
    } = packet
    else {
        anyhow::bail!("native_restore_freeze_order");
    };
    ensure!(
        *selected == selection && echoed == request && answered == challenge,
        "native_restore_freeze_binding_changed"
    );
    protocol::verify(
        &controller.stage.data.public_key,
        "restore-issuer-freeze",
        &(&selection, &request, &challenge),
        &signature,
    )?;
    MessageProcess::check_same_actor(
        &mut [peer, &mut bound],
        acquisition,
        &costs.hashes(Subject::Requester),
    )?;
    issuer
        .parent
        .check_identity(acquisition, &costs.hashes(Subject::ParentBefore))?;
    // Arm before inspecting/publishing. Unsupported historical actors and a
    // failed/lost reply leave this issuer closed forever, never retryable.
    let closing = issuance.close()?;
    ensure!(enrolled.len() == 2, "native_restore_unclosed_role_cohort");
    let statement = protocol::FrozenIssuance {
        policy: issuer.policy.digest()?,
        issuer: issuer.certificate.digest()?,
        cohort: selection.history_digest()?,
        selection,
        request,
        challenge,
    };
    let signature = issuer.key.sign("restore-issuer-frozen", &statement)?;
    // Recheck this Current request after nonce/bind IO on the same clock.
    // The historical cold grant is identity, never a renewed request deadline.
    // This is DATA validation, not App liveness or complete business Stop.
    let now = acquisition.sample()?.elapsed;
    for (statement, role) in [
        (&statement.selection.app, NativeRole::AppHost),
        (&statement.selection.controller, NativeRole::EpochController),
    ] {
        statement.validate_issued_request_data(&issuer.policy, &issuer.certificate, role, now)?;
    }
    // Same publication guards as enrollment, on the actual entry snapshot and
    // original request acquisition; freezing is not an issuer-check exemption.
    issuer.certificate.verify(&issuer.policy)?;
    issuer
        .parent
        .check_identity(acquisition, &costs.hashes(Subject::ParentBefore))?;
    current.check(acquisition)?;
    acquisition.remaining()?;
    let sent = channel.send(
        &Packet::FreezeGrant {
            statement: Box::new(statement.clone()),
            signature: signature.clone(),
        },
        acquisition,
    );
    // Retained native postchecks are mandatory even on a primary send error.
    // The primary error wins and the closed generation cannot become available.
    let retained = FrozenCohort::capture(
        statement,
        signature,
        &issuer.certificate,
        peer,
        &mut bound,
        acquisition,
        costs,
    );
    sent?;
    let cohort = retained?;
    closing.retain_frozen(cohort)
}

/// The original retained generation and actual kernel sender anchors survive
/// every restore request. New request clocks may only TIGHTEN its ceiling.
fn restore_publish_check(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    acquisition: &mut NativeAcquisition,
    current: &mut SelfSnapshot,
    costs: &Costs,
) -> Result<()> {
    cohort.check(costs)?;
    issuer.certificate.verify(&issuer.policy)?;
    ensure!(
        issuer.certificate == cohort.certificate,
        "native_restore_issuer_generation_changed"
    );
    issuer
        .parent
        .check_identity(acquisition, &costs.hashes(Subject::ParentBefore))?;
    current.check(acquisition)?;
    acquisition.remaining()?;
    cohort.original.remaining()?;
    Ok(())
}

/// One authenticated Controller authorization, armed before the nonce/send.
/// Lost replies or failed posts permanently refuse this retained generation.
fn restore_prepare(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    transport: (&mut Channel, &mut NativeAcquisition),
    observations: (&Costs, &mut SelfSnapshot, &mut MessageProcess),
    authorization: protocol::RestoreAuthorizationData,
    request: day2_capabilities::Digest,
) -> Result<()> {
    let (channel, acquisition) = transport;
    let (costs, current, peer) = observations;
    let requested = (|| {
        ensure!(
            !cohort.restore_attempted && cohort.restore.is_none(),
            "native_restore_authorization_attempt_spent"
        );
        // Permanent one-shot BEFORE any possible restore nonce or grant send.
        cohort.restore_attempted = true;
        restore_publish_check(issuer, cohort, acquisition, current, costs)?;
        let now = acquisition.sample()?.elapsed;
        authorization.validate_data(&issuer.policy, &issuer.certificate, now)?;
        ensure!(
            authorization.frozen
                == day2_capabilities::Digest::of(&(
                    "day2-native-frozen-issuer-v1",
                    &cohort.statement,
                    &cohort.signature
                ))?
                && authorization.controller == cohort.statement.selection.controller.digest()?
                && peer.data() == cohort.controller.data(),
            "native_restore_authorizing_controller_changed"
        );
        runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
        MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer],
            acquisition,
            &costs.hashes(Subject::Requester),
        )?;
        let challenge = protocol::nonce("restore-controller-authorize")?;
        channel.send(
            &Packet::RestorePrepareNonce {
                authorization: authorization.digest_data()?,
                request: request.clone(),
                challenge: challenge.clone(),
            },
            acquisition,
        )?;
        let (packet, mut bound) = channel.receive(
            issuer.policy.code(super::NativeRole::EpochController),
            acquisition,
            &costs.hashes(Subject::Requester),
        )?;
        let Packet::RestorePrepareBind {
            authorization: selected,
            request: echoed,
            challenge: answered,
            signature,
        } = packet
        else {
            anyhow::bail!("native_restore_authorization_order");
        };
        ensure!(
            *selected == authorization && echoed == request && answered == challenge,
            "native_restore_authorization_binding_changed"
        );
        protocol::verify(
            &cohort.statement.selection.controller.stage.data.public_key,
            "restore-controller-authorize",
            &(&authorization, &request, &challenge),
            &signature,
        )?;
        MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer, &mut bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        )?;
        restore_publish_check(issuer, cohort, acquisition, current, costs)?;
        let (_, frozen_ceiling) = cohort.original.interval_data()?;
        let (_, request_ceiling) = acquisition.interval_data()?;
        let effective = std::time::Duration::from_nanos(authorization.parent_deadline_ns)
            .min(frozen_ceiling)
            .min(request_ceiling);
        let statement = protocol::RestoreAuthorizationStatement {
            data: authorization,
            request,
            challenge,
            effective_deadline_ns: effective.as_nanos().try_into()?,
        };
        let signed = protocol::SignedRestoreAuthorization {
            signature: issuer
                .key
                .sign("restore-controller-authorized-v1", &statement)?,
            statement,
        };
        signed.verify_data(
            &issuer.policy,
            &issuer.certificate,
            acquisition.sample()?.elapsed,
        )?;
        let sent = channel.send(
            &Packet::RestorePrepareGrant {
                authorization: Box::new(signed.clone()),
            },
            acquisition,
        );
        // The actual post runs even if sending failed. No DATA is adopted on
        // either failure and the primary send error keeps its identity.
        let post = restore_publish_check(issuer, cohort, acquisition, current, costs);
        let peer_post = MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer, &mut bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        );
        sent?;
        post?;
        peer_post?;
        cohort.restore = Some(AuthorizedRestore {
            authorization: signed,
            app: RestoreAppAdmission::Available,
        });
        Ok(())
    })();
    let checked = restore_publish_check(issuer, cohort, acquisition, current, costs);
    if requested.is_err() || checked.is_err() {
        cohort.original.refuse();
    }
    requested?;
    checked
}

/// Distinct new-App admission; this never constructs an ordinary role stage.
/// The candidate is still non-serving until the fixed writer CAS, its separate
/// full readback/postchecks and the actual keeper promotion all complete.
fn restore_app(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    transport: (&mut Channel, &mut NativeAcquisition),
    observations: (&Costs, &mut SelfSnapshot, &mut MessageProcess),
    request: protocol::RestoreAppRequest,
) -> Result<()> {
    let (channel, acquisition) = transport;
    let (costs, current, peer) = observations;
    let requested =
        (|| {
            let authorized = cohort.restore.as_mut().ok_or_else(|| {
                anyhow::anyhow!("native_restore_controller_authorization_missing")
            })?;
            authorized.app.begin()?;
            let authorization = authorized.authorization.clone();
            restore_publish_check(issuer, cohort, acquisition, current, costs)?;
            authorization.verify_data(
                &issuer.policy,
                &issuer.certificate,
                acquisition.sample()?.elapsed,
            )?;
            decode_key(&request.public_key)?;
            // Process AND key must be new independently; domain separation alone
            // must not reauthorize the old App or its retained signing key.
            ensure!(
                (peer.data().process, peer.data().start_ticks)
                    != (
                        cohort.statement.selection.app.stage.data.process.process,
                        cohort
                            .statement
                            .selection
                            .app
                            .stage
                            .data
                            .process
                            .start_ticks
                    )
                    && request.public_key != cohort.statement.selection.app.stage.data.public_key,
                "native_restore_app_not_distinct"
            );
            runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
            let now = acquisition.sample()?.elapsed.as_nanos();
            ensure!(
                request.receiver_origin_ns < request.receiver_deadline_ns
                    && request.receiver_deadline_ns - request.receiver_origin_ns <= 5_000_000_000
                    && u128::from(request.receiver_origin_ns) <= now
                    && now < u128::from(request.receiver_deadline_ns),
                "native_restore_receiver_interval"
            );
            let challenge = protocol::nonce("restore-app-bind")?;
            channel.send(
                &Packet::RestoreAppNonce {
                    certificate: issuer.certificate.clone(),
                    authorization: Box::new(authorization.clone()),
                    request: request.request.clone(),
                    challenge: challenge.clone(),
                },
                acquisition,
            )?;
            let (packet, mut bound) = channel.receive(
                issuer.policy.code(super::NativeRole::AppHost),
                acquisition,
                &costs.hashes(Subject::Requester),
            )?;
            let Packet::RestoreAppBind {
                authorization: selected_authorization,
                request: selected,
                challenge: answered,
                signature,
            } = packet
            else {
                anyhow::bail!("native_restore_app_order");
            };
            ensure!(
                *selected == request
                    && selected_authorization == authorization.digest_data()?
                    && answered == challenge,
                "native_restore_app_binding_changed"
            );
            protocol::verify(
                &request.public_key,
                "restore-app-bind",
                &(&request, &selected_authorization, &challenge),
                &signature,
            )?;
            MessageProcess::check_same_actor(
                &mut [peer, &mut bound],
                acquisition,
                &costs.hashes(Subject::Requester),
            )?;
            let runtime = costs.measure(Operation::Runtime, || {
                runtime::current(
                    &issuer.policy,
                    super::NativeRole::AppHost,
                    peer,
                    acquisition,
                    costs,
                )
            })?;
            restore_publish_check(issuer, cohort, acquisition, current, costs)?;
            MessageProcess::check_same_actor(
                &mut [peer, &mut bound],
                acquisition,
                &costs.hashes(Subject::Requester),
            )?;
            let (_, frozen_ceiling) = cohort.original.interval_data()?;
            let (_, request_ceiling) = acquisition.interval_data()?;
            let effective = std::time::Duration::from_nanos(request.receiver_deadline_ns)
                .min(std::time::Duration::from_nanos(
                    authorization.statement.effective_deadline_ns,
                ))
                .min(frozen_ceiling)
                .min(request_ceiling);
            let statement = protocol::RestoreAdmissionStatement {
                issuer: issuer.certificate.digest()?,
                policy: issuer.policy.digest()?,
                authorization: authorization.digest_data()?,
                process: peer.data().clone(),
                runtime,
                public_key: request.public_key,
                request: request.request,
                challenge,
                receiver_clock: request.receiver_clock,
                receiver_origin_ns: request.receiver_origin_ns,
                receiver_deadline_ns: request.receiver_deadline_ns,
                effective_deadline_ns: effective.as_nanos().try_into()?,
            };
            let signed = protocol::SignedRestoreAdmission {
                signature: issuer.key.sign("restore-app-admission-v1", &statement)?,
                statement,
            };
            signed.verify_data(
                &issuer.policy,
                &issuer.certificate,
                &authorization,
                acquisition.sample()?.elapsed,
            )?;
            let app = AuthorizedRestoreApp::capture(
                issuer,
                &authorization,
                signed.clone(),
                (&mut cohort.original, &mut *acquisition),
                (&mut *peer, &mut bound),
                costs,
            )?;
            let authorized = cohort.restore.as_mut().ok_or_else(|| {
                anyhow::anyhow!("native_restore_controller_authorization_missing")
            })?;
            // Retain actual handles BEFORE the possibly ambiguous send. An error
            // refuses the same frozen original; it cannot erase/regrant this App.
            authorized.app.retain(app)?;
            let sent = channel.send(
                &Packet::RestoreAppGrant {
                    certificate: issuer.certificate.clone(),
                    admission: Box::new(signed),
                },
                acquisition,
            );
            let post = restore_publish_check(issuer, cohort, acquisition, current, costs);
            // Same actual App anchors are checked after the send as well.
            let peer_post = MessageProcess::check_same_actor(
                &mut [peer, &mut bound],
                acquisition,
                &costs.hashes(Subject::Requester),
            );
            sent?;
            post?;
            peer_post?;
            Ok(())
        })();
    let checked = restore_publish_check(issuer, cohort, acquisition, current, costs);
    if requested.is_err() || checked.is_err() {
        cohort.original.refuse();
    }
    requested?;
    checked
}

// All three actual native actors are observed even after an earlier failure.
// Only comparison DATA crosses this helper; the retained handles stay here.
fn finish_publish_check(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    acquisition: &mut NativeAcquisition,
    current: &mut SelfSnapshot,
    peer: &mut MessageProcess,
    costs: &Costs,
) -> Result<()> {
    let requested = restore_publish_check(issuer, cohort, acquisition, current, costs);
    let checked = MessageProcess::check_same_actor(
        &mut [&mut cohort.controller, &mut cohort.bound, peer],
        acquisition,
        &costs.hashes(Subject::Requester),
    );
    let original_post = cohort.original.remaining();
    if requested.is_err() || checked.is_err() || original_post.is_err() {
        cohort.original.refuse();
        acquisition.refuse();
    }
    requested?;
    checked?;
    original_post.map(|_| ())
}

/// Fixed one-shot Controller completion statement. The frozen generation and
/// actual App handles remain retained even on success: this does NOT reopen
/// admission or manufacture an ordinary App role/Current. A later real owner
/// transition must separately consume/check the completed resources.
fn restore_finish(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    transport: (&mut Channel, &mut NativeAcquisition),
    observations: (&Costs, &mut SelfSnapshot, &mut MessageProcess),
    completion: protocol::RestoreIssuerCompletionData,
    request: day2_capabilities::Digest,
) -> Result<()> {
    let (channel, acquisition) = transport;
    let (costs, current, peer) = observations;
    let requested: Result<()> = (|| {
        ensure!(
            !cohort.finish_attempted && cohort.completion.is_none(),
            "native_restore_finish_attempt_spent"
        );
        cohort.finish_attempted = true;
        finish_publish_check(issuer, cohort, acquisition, current, peer, costs)?;
        ensure!(
            peer.data() == cohort.controller.data(),
            "native_restore_finish_controller_changed"
        );
        runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
        let authorized = cohort
            .restore
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("native_restore_authorization_missing"))?;
        let RestoreAppAdmission::Retained(app) = &mut authorized.app else {
            anyhow::bail!("native_restore_finish_actual_app_required");
        };
        let app = app.statement_data(costs)?;
        completion.validate_data(
            &issuer.policy,
            &issuer.certificate,
            &app,
            cohort.original.sample()?.elapsed,
        )?;
        ensure!(
            completion.frozen
                == day2_capabilities::Digest::of(&(
                    "day2-native-frozen-issuer-v1",
                    &cohort.statement,
                    &cohort.signature
                ))?,
            "native_restore_finish_frozen_generation_changed"
        );
        let challenge = protocol::nonce("restore-issuer-finish-request")?;
        let sent = channel.send(
            &Packet::RestoreFinishNonce {
                completion: completion.digest_data()?,
                request: request.clone(),
                challenge: challenge.clone(),
            },
            acquisition,
        );
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        sent?;
        checked?;
        let received = channel.receive(
            issuer.policy.code(super::NativeRole::EpochController),
            acquisition,
            &costs.hashes(Subject::Requester),
        );
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let (packet, mut bound) = received?;
        checked?;
        let Packet::RestoreFinishBind {
            completion: selected,
            request: echoed,
            challenge: answered,
            signature,
        } = packet
        else {
            anyhow::bail!("native_restore_finish_bind_expected");
        };
        ensure!(
            *selected == completion && echoed == request && answered == challenge,
            "native_restore_finish_bind_changed"
        );
        protocol::verify(
            &cohort.statement.selection.controller.stage.data.public_key,
            "restore-issuer-finish-bind-v1",
            &(&completion, &request, &challenge),
            &signature,
        )?;
        MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer, &mut bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        )?;
        finish_publish_check(issuer, cohort, acquisition, current, peer, costs)?;
        let (_, frozen_ceiling) = cohort.original.interval_data()?;
        let (_, request_ceiling) = acquisition.interval_data()?;
        let effective = std::time::Duration::from_nanos(app.original.deadline_ns)
            .min(frozen_ceiling)
            .min(request_ceiling);
        let statement = protocol::RestoreIssuerCompletionStatement {
            data: completion,
            request,
            challenge,
            effective_deadline_ns: effective.as_nanos().try_into()?,
        };
        let signed = issuer.key.sign("restore-issuer-completed-v1", &statement);
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let signature = signed?;
        checked?;
        let signed = protocol::SignedRestoreIssuerCompletion {
            statement,
            signature,
        };
        signed.verify_data(
            &issuer.policy,
            &issuer.certificate,
            &signed.statement.data,
            &app,
            cohort.original.sample()?.elapsed,
        )?;
        // Retention precedes even an ambiguous send. It is not a delivery flag.
        cohort.completion = Some(signed.clone());
        let sent = channel.send(
            &Packet::RestoreFinishGrant {
                completion: Box::new(signed),
            },
            acquisition,
        );
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let peer_post = MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer, &mut bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        );
        sent?;
        checked?;
        peer_post?;
        Ok(())
    })();
    let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
    if requested.is_err() || checked.is_err() {
        cohort.original.refuse();
        acquisition.refuse();
    }
    requested?;
    checked
}

/// Retain one exact signed role decision on the ACTUAL frozen cohort. This
/// does not reopen enrollment or prove delivery, Controller outer-post success,
/// App acceptance, ordinary admission or successful original retirement.
fn restore_role_decision(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    transport: (&mut Channel, &mut NativeAcquisition),
    observations: (&Costs, &mut SelfSnapshot, &mut MessageProcess),
    completion: protocol::SignedRestoreIssuerCompletion,
    request: day2_capabilities::Digest,
) -> Result<()> {
    let (channel, acquisition) = transport;
    let (costs, current, peer) = observations;
    let requested: Result<()> = (|| {
        let fresh = match &cohort.role_decision {
            RestoreRoleDecision::Fresh => true,
            RestoreRoleDecision::Spent => false,
            RestoreRoleDecision::Retained(decision) => {
                ensure!(
                    decision.statement.completion == completion.digest_data()?,
                    "native_restore_role_decision_replay_changed"
                );
                false
            }
        };
        ensure!(fresh, "native_restore_role_decision_attempt_spent");
        cohort.role_decision = RestoreRoleDecision::Spent;
        finish_publish_check(issuer, cohort, acquisition, current, peer, costs)?;
        ensure!(
            cohort.finish_attempted
                && cohort.completion.as_ref() == Some(&completion)
                && peer.data() == cohort.controller.data(),
            "native_restore_role_decision_completion_changed"
        );
        runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
        let authorized = cohort
            .restore
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("native_restore_authorization_missing"))?;
        let RestoreAppAdmission::Retained(app) = &mut authorized.app else {
            anyhow::bail!("native_restore_role_actual_app_required");
        };
        let app = app.statement_data(costs)?;
        completion.verify_data(
            &issuer.policy,
            &issuer.certificate,
            &completion.statement.data,
            &app,
            cohort.original.sample()?.elapsed,
        )?;
        let challenge = protocol::nonce("restore-app-role-challenge")?;
        let sent = channel.send(
            &Packet::RestoreRoleNonce {
                completion: completion.digest_data()?,
                request: request.clone(),
                challenge: challenge.clone(),
            },
            acquisition,
        );
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        sent?;
        checked?;
        let received = channel.receive(
            issuer.policy.code(super::NativeRole::EpochController),
            acquisition,
            &costs.hashes(Subject::Requester),
        );
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let (packet, mut bound) = received?;
        checked?;
        let Packet::RestoreRoleBind {
            completion: selected,
            request: echoed,
            challenge: answered,
            signature,
        } = packet
        else {
            anyhow::bail!("native_restore_role_bind_expected");
        };
        ensure!(
            *selected == completion && echoed == request && answered == challenge,
            "native_restore_role_bind_changed"
        );
        protocol::verify(
            &cohort.statement.selection.controller.stage.data.public_key,
            "restore-app-role-bind-v1",
            &(&completion, &request, &challenge),
            &signature,
        )?;
        MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer, &mut bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        )?;
        finish_publish_check(issuer, cohort, acquisition, current, peer, costs)?;
        let (_, frozen_ceiling) = cohort.original.interval_data()?;
        let (_, request_ceiling) = acquisition.interval_data()?;
        let effective = std::time::Duration::from_nanos(completion.statement.effective_deadline_ns)
            .min(std::time::Duration::from_nanos(app.original.deadline_ns))
            .min(frozen_ceiling)
            .min(request_ceiling);
        let data = protocol::StageData {
            issuer: issuer.certificate.digest()?,
            policy: issuer.policy.digest()?,
            role: super::NativeRole::AppHost,
            purpose: protocol::StagePurpose::CurrentRole,
            public_key: app.admission.statement.public_key.clone(),
            request: request.clone(),
            challenge: challenge.clone(),
            process: app.admission.statement.process.clone(),
            runtime: app.admission.statement.runtime.clone(),
            origin_ns: app.original.origin_ns,
            deadline_ns: effective.as_nanos().try_into()?,
        };
        let signed = issuer.key.sign("role-stage", &data);
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let signature = signed?;
        checked?;
        let stage = protocol::SignedStage { data, signature };
        let statement = protocol::RestoreRoleActivationStatement {
            completion: completion.digest_data()?,
            stage,
            request,
            challenge,
            effective_deadline_ns: effective.as_nanos().try_into()?,
        };
        let signed = issuer.key.sign("restore-app-role-activated-v1", &statement);
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let signature = signed?;
        checked?;
        let signed = protocol::SignedRestoreRoleActivation {
            statement,
            signature,
        };
        signed.verify_data(
            &issuer.policy,
            &issuer.certificate,
            &completion,
            &app,
            (&signed.statement.request, &signed.statement.challenge),
            cohort.original.sample()?.elapsed,
        )?;
        // Retain BEFORE the possibly ambiguous send. This state deliberately
        // remains frozen and is neither delivery nor future cold eligibility.
        cohort.role_decision = RestoreRoleDecision::Retained(Box::new(signed.clone()));
        let sent = channel.send(
            &Packet::RestoreRoleGrant {
                activation: Box::new(signed),
            },
            acquisition,
        );
        let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
        let peer_post = MessageProcess::check_same_actor(
            &mut [&mut cohort.controller, &mut cohort.bound, peer, &mut bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        );
        sent?;
        checked?;
        peer_post?;
        Ok(())
    })();
    let checked = finish_publish_check(issuer, cohort, acquisition, current, peer, costs);
    if requested.is_err() || checked.is_err() {
        cohort.original.refuse();
        acquisition.refuse();
    }
    requested?;
    checked
}

struct AppConfirmationAttempt<'cohort, 'request> {
    cohort: &'cohort mut FrozenCohort,
    acquisition: &'request mut NativeAcquisition,
    done: bool,
}

impl Drop for AppConfirmationAttempt<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.cohort.original.refuse();
            self.acquisition.refuse();
        }
    }
}

fn prepared_actor_check(
    cohort: &mut FrozenCohort,
    acquisition: &mut NativeAcquisition,
    peer: &mut MessageProcess,
    bound: Option<&mut MessageProcess>,
    costs: &Costs,
) -> Result<()> {
    let Some(RestoreAppAdmission::Retained(app)) =
        cohort.restore.as_mut().map(|entry| &mut entry.app)
    else {
        anyhow::bail!("native_restore_prepared_actual_app_required")
    };
    match bound {
        Some(bound) => MessageProcess::check_same_actor(
            &mut [&mut app.hello, &mut app.bound, peer, bound],
            acquisition,
            &costs.hashes(Subject::Requester),
        ),
        None => MessageProcess::check_same_actor(
            &mut [&mut app.hello, &mut app.bound, peer],
            acquisition,
            &costs.hashes(Subject::Requester),
        ),
    }
}

fn prepared_publish_check(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    acquisition: &mut NativeAcquisition,
    current: &mut SelfSnapshot,
    peer: &mut MessageProcess,
    costs: &Costs,
) -> Result<()> {
    let requested = restore_publish_check(issuer, cohort, acquisition, current, costs);
    let checked = prepared_actor_check(cohort, acquisition, peer, None, costs);
    let tail = cohort.original.remaining();
    if requested.is_err() || checked.is_err() || tail.is_err() {
        cohort.original.refuse();
        acquisition.refuse();
    }
    requested?;
    checked?;
    tail.map(|_| ())
}

/// One direct App proof under the retained frozen generation. Prepared is not
/// Controller acceptance, ordinary role installation, readiness or completion.
fn restore_app_confirmation(
    issuer: &mut IssuerOwner,
    cohort: &mut FrozenCohort,
    transport: (&mut Channel, &mut NativeAcquisition),
    observations: (&Costs, &mut SelfSnapshot, &mut MessageProcess),
    decision: protocol::SignedRestoreRoleActivation,
    request: day2_capabilities::Digest,
) -> Result<()> {
    let (channel, acquisition) = transport;
    let (costs, current, peer) = observations;
    let mut attempt = AppConfirmationAttempt {
        cohort,
        acquisition,
        done: false,
    };
    let requested: Result<()> = (|| {
        let Some(RestoreAppAdmission::Retained(app)) =
            attempt.cohort.restore.as_mut().map(|entry| &mut entry.app)
        else {
            anyhow::bail!("native_restore_prepared_actual_app_required")
        };
        ensure!(
            !app.confirmation_attempted && app.confirmation.is_none(),
            "native_restore_prepared_attempt_spent"
        );
        // One-way before native checks, entropy, signing, transport or waits.
        app.confirmation_attempted = true;
        let RestoreRoleDecision::Retained(retained) = &attempt.cohort.role_decision else {
            anyhow::bail!("native_restore_role_decision_missing")
        };
        ensure!(
            retained.as_ref() == &decision,
            "native_restore_prepared_decision_changed"
        );
        let completion = attempt
            .cohort
            .completion
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native_restore_completion_missing"))?
            .clone();
        prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        )?;
        runtime::require_common(peer.data(), &issuer.certificate.data.process)?;
        let Some(RestoreAppAdmission::Retained(app)) =
            attempt.cohort.restore.as_mut().map(|entry| &mut entry.app)
        else {
            anyhow::bail!("native_restore_prepared_actual_app_required")
        };
        let app = app.statement_data(costs)?;
        decision.verify_data(
            &issuer.policy,
            &issuer.certificate,
            &completion,
            &app,
            (&decision.statement.request, &decision.statement.challenge),
            attempt.acquisition.sample()?.elapsed,
        )?;
        // The newly accepted issuer connection has its own work bound, but
        // every subsequent send/wait is also clipped to ALL earlier known
        // retained originals and the signed decision. narrow preserves THIS
        // acquisition's origin/domain/refusal rather than capturing a new one.
        let (_, frozen_ceiling) = attempt.cohort.original.interval_data()?;
        let Some(RestoreAppAdmission::Retained(actual_app)) =
            attempt.cohort.restore.as_mut().map(|entry| &mut entry.app)
        else {
            anyhow::bail!("native_restore_prepared_actual_app_required")
        };
        let (_, app_ceiling) = actual_app.original.interval_data()?;
        let ceiling = std::time::Duration::from_nanos(decision.statement.effective_deadline_ns)
            .min(frozen_ceiling)
            .min(app_ceiling);
        channel.narrow_restore_app_confirmation(attempt.acquisition, ceiling)?;
        let challenge = protocol::nonce("restore-app-prepared-challenge")?;
        prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        )?;
        let sent = channel.send(
            &Packet::RestoreAppConfirmNonce {
                decision: decision.digest_data()?,
                request: request.clone(),
                challenge: challenge.clone(),
            },
            attempt.acquisition,
        );
        let checked = prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        );
        sent?;
        checked?;
        let received = channel.receive(
            issuer.policy.code(super::NativeRole::AppHost),
            attempt.acquisition,
            &costs.hashes(Subject::Requester),
        );
        let checked = prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        );
        let (packet, mut bound) = received?;
        let sender = prepared_actor_check(
            attempt.cohort,
            attempt.acquisition,
            peer,
            Some(&mut bound),
            costs,
        );
        checked?;
        sender?;
        let Packet::RestoreAppConfirmBind {
            decision: selected,
            request: echoed,
            challenge: answered,
            signature,
        } = packet
        else {
            anyhow::bail!("native_restore_prepared_bind_expected")
        };
        ensure!(
            *selected == decision && echoed == request && answered == challenge,
            "native_restore_prepared_bind_changed"
        );
        protocol::verify(
            &app.admission.statement.public_key,
            "restore-app-prepared-bind-v1",
            &(&decision, &request, &challenge),
            &signature,
        )?;
        prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        )?;
        let (_, frozen_ceiling) = attempt.cohort.original.interval_data()?;
        let (_, request_ceiling) = attempt.acquisition.interval_data()?;
        let effective = std::time::Duration::from_nanos(decision.statement.effective_deadline_ns)
            .min(frozen_ceiling)
            .min(request_ceiling);
        let statement = protocol::RestorePreparedConfirmationStatement {
            issuer: issuer.certificate.digest()?,
            decision: decision.digest_data()?,
            completion: completion.digest_data()?,
            app: app.digest()?,
            request,
            challenge,
            effective_deadline_ns: effective.as_nanos().try_into()?,
        };
        let signed = issuer
            .key
            .sign("restore-app-prepared-confirmed-v1", &statement);
        let checked = prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        );
        let signature = signed?;
        checked?;
        let signed = protocol::SignedRestorePreparedConfirmation {
            statement,
            signature,
        };
        signed.verify_data(
            &issuer.policy,
            &issuer.certificate,
            (&decision, &completion),
            &app,
            (&signed.statement.request, &signed.statement.challenge),
            attempt.acquisition.sample()?.elapsed,
        )?;
        let Some(RestoreAppAdmission::Retained(retained_app)) =
            attempt.cohort.restore.as_mut().map(|entry| &mut entry.app)
        else {
            anyhow::bail!("native_restore_prepared_actual_app_required")
        };
        // Retain exact DATA on the actual App/kernel/original owner before a
        // possibly ambiguous send. Never reset its spent gate or reopen issuer.
        retained_app.confirmation = Some(signed.clone());
        let sent = channel.send(
            &Packet::RestoreAppConfirmGrant {
                confirmation: Box::new(signed),
            },
            attempt.acquisition,
        );
        let checked = prepared_publish_check(
            issuer,
            attempt.cohort,
            attempt.acquisition,
            current,
            peer,
            costs,
        );
        let sender = prepared_actor_check(
            attempt.cohort,
            attempt.acquisition,
            peer,
            Some(&mut bound),
            costs,
        );
        sent?;
        checked?;
        sender?;
        Ok(())
    })();
    let checked = prepared_publish_check(
        issuer,
        attempt.cohort,
        attempt.acquisition,
        current,
        peer,
        costs,
    );
    if requested.is_err() || checked.is_err() {
        attempt.cohort.original.refuse();
        attempt.acquisition.refuse();
    }
    requested?;
    checked?;
    attempt.done = true;
    Ok(())
}

#[cfg(test)]
mod retained_restore_app_tests {
    use super::RestoreAppAdmission;
    use quote::ToTokens;

    fn tokens(source: &str) -> String {
        fn strip(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), strip(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        strip(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    fn implementation(owner_name: &str, name: &str) -> String {
        let file = syn::parse_file(include_str!("service.rs")).unwrap();
        let mut found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(owner) = item else {
                return None;
            };
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident(owner_name)) {
                return None;
            }
            owner.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => {
                    Some(tokens(&method.into_token_stream().to_string()))
                }
                _ => None,
            })
        });
        let body = found.next().unwrap();
        assert!(found.next().is_none());
        body
    }

    #[test]
    fn source_controls_align_question_semicolon_spacing_without_changing_the_actor() {
        assert_eq!(tokens("app.check(costs)?;"), tokens("app.check(costs) ? ;"));
        assert_ne!(tokens("app.check(costs)?;"), tokens("other.check(costs)?;"));
    }

    fn handler(name: &str) -> String {
        let file = syn::parse_file(include_str!("service.rs")).unwrap();
        file.items
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == name => {
                    Some(tokens(&function.into_token_stream().to_string()))
                }
                _ => None,
            })
            .unwrap()
    }

    fn app_request() -> String {
        handler("restore_app")
    }

    fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut rest = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        true
    }

    fn app_is_retained_before_send(body: &str) -> bool {
        ordered(
            body,
            &[
                "authorized.app.begin()?;",
                "restore_publish_check",
                "MessageProcess::check_same_actor",
                "let signed=protocol::SignedRestoreAdmission",
                "signed.verify_data",
                "AuthorizedRestoreApp::capture(issuer,&authorization,signed.clone(),(&mut cohort.original,&mut *acquisition),(&mut *peer,&mut bound),costs)?",
                "authorized.app.retain(app)?;",
                "let sent=channel.send",
                "Packet::RestoreAppGrant",
                "let post=restore_publish_check",
                "let peer_post=MessageProcess::check_same_actor",
                "sent?;post?;peer_post?;",
                "let checked=restore_publish_check",
                "cohort.original.refuse();",
                "requested?;checked",
            ],
        )
    }

    fn capture_is_actual(body: &str) -> bool {
        ordered(
            body,
            &[
                "frozen.remaining()?;acquisition.remaining()?;",
                "runtime::require_common(peer.data(),&issuer.certificate.data.process)?;",
                "admission.verify_data",
                "admission.statement.process==*peer.data()",
                "peer.data()==bound.data()",
                "frozen.interval_data()",
                "acquisition.interval_data()",
                "effective_deadline_ns",
                "let mut original=frozen.narrow(5,ceiling)?;",
                "peer.retain_message_anchor(&mut original,&costs.hashes(Subject::Requester))?;",
                "bound.retain_message_anchor(&mut original,&costs.hashes(Subject::Requester))?;",
                "MessageProcess::check_same_actor",
                "original.sample()",
                "original.remaining()?;acquisition.remaining()?;",
                "policy:issuer.policy.clone()",
                "admission,hello,bound:answer,original,confirmation_attempted:false,confirmation:None",
                "let checked=frozen.remaining();",
                "frozen.refuse();acquisition.refuse();",
                "let app=requested?;checked?;Ok(app)",
            ],
        ) && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    fn retained_check_is_actual(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested:Result<()>",
                "self.admission.verify_data(&self.policy,&self.certificate,&self.authorization,self.original.sample()?.elapsed)?;",
                "self.admission.statement.process==*self.hello.data()",
                "self.hello.data()==self.bound.data()",
                "MessageProcess::check_same_actor(&mut [&mut self.hello,&mut self.bound],&mut self.original,&costs.hashes(Subject::Requester))?;",
                "self.original.remaining().map(|_|())",
                "let checked=self.original.remaining();",
                "if requested.is_err() || checked.is_err() {self.original.refuse();}",
                "requested?;checked.map(|_|())",
            ],
        ) && body
            .matches(&tokens("let checked=self.original.remaining();"))
            .count()
            == 1
            && body.matches(&tokens("requested?")).count() == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    fn frozen_check_joins_independent_app(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested:Result<()>",
                "MessageProcess::check_same_actor(&mut [&mut self.controller,&mut self.bound],&mut self.original,&costs.hashes(Subject::Requester))?;",
                "self.original.remaining().map(|_|())",
                "let app=match self.restore.as_mut().map(|restore|&mut restore.app)",
                "Some(RestoreAppAdmission::Retained(app))=>app.check(costs)",
                "let confirmation=self.check_prepared_confirmation(costs);",
                "let checked=self.original.remaining();",
                "if requested.is_err() || app.is_err() || confirmation.is_err() || checked.is_err() {self.original.refuse();}",
                "requested?;app?;confirmation?;checked.map(|_|())",
            ],
        ) && body.matches(&tokens("requested?")).count() == 1
            && body.matches(&tokens("app.check(costs)")).count() == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    fn finish_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "!cohort.finish_attempted && cohort.completion.is_none()",
                "cohort.finish_attempted=true;",
                "finish_publish_check",
                "peer.data()==cohort.controller.data()",
                "runtime::require_common(peer.data(),&issuer.certificate.data.process)?;",
                "RestoreAppAdmission::Retained(app)",
                "app.statement_data(costs)?",
                "completion.validate_data",
                "completion.frozen==day2_capabilities::Digest::of",
                "Packet::RestoreFinishNonce",
                "let checked=finish_publish_check",
                "sent?;checked?;",
                "let received=channel.receive",
                "let checked=finish_publish_check",
                "let (packet,mut bound)=received?;checked?;",
                "Packet::RestoreFinishBind",
                "*selected==completion && echoed==request && answered==challenge",
                "protocol::verify",
                "\"restore-issuer-finish-bind-v1\"",
                "MessageProcess::check_same_actor(&mut [&mut cohort.controller,&mut cohort.bound,peer,&mut bound],acquisition,&costs.hashes(Subject::Requester))?;",
                "finish_publish_check",
                "cohort.original.interval_data()",
                "acquisition.interval_data()",
                "app.original.deadline_ns",
                ".min(frozen_ceiling).min(request_ceiling)",
                "issuer.key.sign(\"restore-issuer-completed-v1\",&statement)",
                "let checked=finish_publish_check",
                "let signature=signed?;checked?;",
                "signed.verify_data",
                "cohort.completion=Some(signed.clone());",
                "Packet::RestoreFinishGrant",
                "let checked=finish_publish_check",
                "let peer_post=MessageProcess::check_same_actor",
                "sent?;checked?;peer_post?;",
                "let checked=finish_publish_check",
                "cohort.original.refuse();acquisition.refuse();",
                "requested?;checked",
            ],
        ) && !body.contains(&tokens("NativeAcquisition::begin"))
            && !body.contains(&tokens("Issuance::Open"))
    }

    fn finish_post_is_independent(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested=restore_publish_check",
                "let checked=MessageProcess::check_same_actor",
                "let original_post=cohort.original.remaining();",
                "if requested.is_err() || checked.is_err() || original_post.is_err() {cohort.original.refuse();acquisition.refuse();}",
                "requested?;checked?;original_post.map",
            ],
        ) && body.matches(&tokens("requested?")).count() == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    #[test]
    fn actual_app_admission_is_one_attempt_and_a_clock_repair_cannot_reopen_it() {
        // State only, no synthetic native Role/Current or MessageProcess.
        for attempts in 1..=32 {
            let mut actual = RestoreAppAdmission::Available;
            let mut expected_fresh = true;
            for _ in 0..attempts {
                let accepted = actual.begin().is_ok();
                assert_eq!(accepted, expected_fresh);
                expected_fresh = false;
                // No observation or later request resets the actual state.
                assert!(matches!(&actual, RestoreAppAdmission::Started));
            }
        }
    }

    #[test]
    fn actual_handler_retains_kernel_app_anchors_before_even_an_ambiguous_grant_send() {
        let actual = app_request();
        assert!(app_is_retained_before_send(&actual));
        for (before, after) in [
            ("authorized.app.begin()?;", "let _reusable=();"),
            (
                "AuthorizedRestoreApp::capture(issuer,&authorization,signed.clone(),(&mut cohort.original,&mut *acquisition),(&mut *peer,&mut bound),costs)?",
                "AuthorizedRestoreApp::capture(other,&authorization,signed.clone(),(&mut cohort.original,&mut *acquisition),(&mut *peer,&mut bound),costs)?",
            ),
            ("authorized.app.retain(app)?;", "drop(app);"),
            (
                "let post=restore_publish_check",
                "let post=skip_publish_check",
            ),
            ("sent?;post?;peer_post?;", "post?;sent?;peer_post?;"),
        ] {
            let before = tokens(before);
            let after = tokens(after);
            assert!(actual.contains(&before));
            assert!(!app_is_retained_before_send(
                &actual.replacen(&before, &after, 1)
            ));
        }
    }

    #[test]
    fn actual_retained_capture_uses_existing_real_handles_and_same_frozen_original() {
        let actual = implementation("AuthorizedRestoreApp", "capture");
        assert!(capture_is_actual(&actual));
        for (before, after) in [
            (
                "runtime::require_common(peer.data(),&issuer.certificate.data.process)?;",
                "let _unchecked=();",
            ),
            (
                "frozen.narrow(5,ceiling)",
                "NativeAcquisition::begin(std::time::Duration::from_secs(5))",
            ),
            ("admission.statement.process==*peer.data()", "true"),
            ("peer.retain_message_anchor", "other.retain_message_anchor"),
            (
                "let checked=frozen.remaining();",
                "let checked=Ok(std::time::Duration::ZERO);",
            ),
            (
                "let app=requested?;checked?;Ok(app)",
                "checked?;let app=requested?;Ok(app)",
            ),
        ] {
            let before = tokens(before);
            assert!(actual.contains(&before));
            assert!(!capture_is_actual(&actual.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
    }

    #[test]
    fn actual_retained_app_rechecks_signed_actor_kernel_handles_and_original_on_error() {
        let actual = implementation("AuthorizedRestoreApp", "check");
        assert!(retained_check_is_actual(&actual));
        assert!(!retained_check_is_actual(&tokens(
            "fn check(&mut self,costs:&Costs)->Result<()> {Ok(())}"
        )));
        for (before, after) in [
            (
                "self.admission.verify_data(&self.policy,&self.certificate,&self.authorization,self.original.sample()?.elapsed)?;",
                "let _unchecked=();",
            ),
            (
                "self.admission.statement.process==*self.hello.data()",
                "true",
            ),
            ("self.hello.data()==self.bound.data()", "true"),
            (
                "MessageProcess::check_same_actor(&mut [&mut self.hello,&mut self.bound],&mut self.original,&costs.hashes(Subject::Requester))?;",
                "let _unchecked=();",
            ),
            (
                "&mut self.hello,&mut self.bound",
                "&mut self.hello,&mut self.hello",
            ),
            (
                "let checked=self.original.remaining();",
                "let checked=Ok(std::time::Duration::ZERO);",
            ),
            (
                "let checked=self.original.remaining();",
                "requested?;let checked=self.original.remaining();",
            ),
            ("requested.is_err() || checked.is_err()", "checked.is_err()"),
            ("self.original.refuse();", "let _reusable=();"),
            ("requested?;checked.map(|_|())", "checked?;requested"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !retained_check_is_actual(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    #[test]
    fn actual_frozen_check_observes_app_even_after_controller_failure_and_preserves_primary() {
        let actual = implementation("FrozenCohort", "check");
        assert!(frozen_check_joins_independent_app(&actual));
        for (before, after) in [
            ("let app=match", "requested?;let app=match"),
            (
                "let confirmation=self.check_prepared_confirmation(costs);",
                "let confirmation:Result<()>=Ok(());",
            ),
            (
                "Some(RestoreAppAdmission::Retained(app))=>app.check(costs)",
                "Some(RestoreAppAdmission::Retained(app))=>Ok(())",
            ),
            (
                "let checked=self.original.remaining();",
                "let checked=Ok(std::time::Duration::ZERO);",
            ),
            (
                "requested.is_err() || app.is_err() || confirmation.is_err() || checked.is_err()",
                "requested.is_err() || checked.is_err()",
            ),
            ("self.original.refuse();", "let _reusable=();"),
            (
                "requested?;app?;confirmation?;checked.map(|_|())",
                "app?;requested?;confirmation?;checked.map(|_|())",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !frozen_check_joins_independent_app(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    #[test]
    fn actual_finish_retains_generation_actual_app_and_one_attempt_before_any_reply() {
        let actual = handler("restore_finish");
        assert!(finish_is_closed(&actual));
        for (before, after) in [
            ("cohort.finish_attempted=true;", "let _reusable=();"),
            ("app.statement_data(costs)?", "caller_app()"),
            ("completion.validate_data", "skip_completion_check"),
            (
                "*selected==completion && echoed==request && answered==challenge",
                "true",
            ),
            ("\"restore-issuer-finish-bind-v1\"", "\"role-bind\""),
            (
                ".min(frozen_ceiling).min(request_ceiling)",
                ".max(frozen_ceiling).max(request_ceiling)",
            ),
            (
                "let signature=signed?;checked?;",
                "checked?;let signature=signed?;",
            ),
            (
                "cohort.completion=Some(signed.clone());",
                "let _unretained=();",
            ),
            (
                "cohort.original.refuse();acquisition.refuse();",
                "cohort.original.refuse();",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !finish_is_closed(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
        let post = handler("finish_publish_check");
        assert!(finish_post_is_independent(&post));
        assert!(!finish_post_is_independent(&tokens(
            "fn finish_publish_check()->Result<()> {Ok(())}"
        )));
        for (before, after) in [
            (
                "let requested=restore_publish_check",
                "let requested=skip_publish_check",
            ),
            (
                "let checked=MessageProcess::check_same_actor",
                "requested?;let checked=MessageProcess::check_same_actor",
            ),
            (
                "let original_post=cohort.original.remaining();",
                "let original_post=Ok(std::time::Duration::ZERO);",
            ),
            (
                "requested.is_err() || checked.is_err() || original_post.is_err()",
                "false",
            ),
            (
                "cohort.original.refuse();acquisition.refuse();",
                "cohort.original.refuse();",
            ),
            (
                "requested?;checked?;original_post.map",
                "checked?;requested?;original_post.map",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(post.matches(&before).count(), 1, "{before}");
            assert!(
                !finish_post_is_independent(&post.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }
}
