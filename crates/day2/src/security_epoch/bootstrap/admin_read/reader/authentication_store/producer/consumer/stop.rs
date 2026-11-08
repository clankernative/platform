//! One retained native stop/fenced-write owner. DATA plans and a peer ACK
//! cannot construct it; the sole construction path must finish actual known
//! grant-use/root-fence send/readback and the complete real peer/issuer stop.
use super::super::super::super::super::ControllerAdminReadLoan;
use super::super::super::super::ControllerAdminReader;
use super::super::super::RestoreAuthenticationAction;
use super::{
    AuthenticatedRestoreExecution, ExecutionCompletion, RestoreOriginalGuard, SignedApprovalRecord,
    approval_window,
};
use crate::security_epoch::{
    kernel::{self, Snapshot, restore::approval_use},
    native_enrollment::{
        ActivatedRestoredAppRole, AuthorityStopData, FrozenRoleIssuer,
        InstalledRestoredAppConfirmation, IssuerRestoreRoleActivating,
        PreparedRestoredAppConfirmation,
    },
    restore_original::RestoreObservation,
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::Digest;
use std::{cell::Cell, rc::Rc};

mod native_current;
pub(in crate::security_epoch) use native_current::PendingControllerCurrentInstallation;

/// A closed borrow of the actual authenticated executor's fields, keeping its
/// native source separately borrowable. No factory accepts replacement fields
/// or returns a source, stage, clock, descriptor or callback permission.
pub(in crate::security_epoch) struct ExecutionSourceLoan<'borrow, 'metadata, 'storage, 'role> {
    action: &'borrow mut RestoreAuthenticationAction<'metadata, 'storage, 'role>,
    original: &'borrow mut RestoreOriginalGuard,
    completion: &'borrow mut ExecutionCompletion,
    record: &'borrow SignedApprovalRecord,
    operation: &'borrow Digest,
    time_operation: &'borrow Digest,
    refused: &'borrow mut bool,
}

impl AuthenticatedRestoreExecution<'_, '_, '_> {
    /// Fresh local checks inside one closed unpublished archive capture.
    /// This does not read the remote epoch, qualify a new time source or renew
    /// either original. Full current checks remain at capture entry/exit and
    /// each actual worker launch/exchange boundary.
    pub(in crate::security_epoch) fn check_archive_local(
        &mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<RestoreObservation> {
        if self.refused {
            self.refuse();
            anyhow::bail!("restore_executor_refused");
        }
        let requested: Result<()> = (|| {
            self.action.check_local()?;
            self.action
                .intent
                .require_exact(&self.record.statement.request.intent())?;
            self.historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?
                .require(intent, &self.record, &self.operation)?;
            let physical = self
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            self.original.check_join(
                physical.controller_stage()?,
                &self.record.statement.request,
                &self.operation,
            )?;
            self.source.require_qualified(&self.time_operation)?;
            // Observe the SAME already-qualified retained host-clock source.
            // No provider/epoch round, qualification or floor movement occurs.
            let time = self.source.current_fenced_time(physical)?;
            approval_window(&self.record, &time)?;
            Ok(())
        })();
        // Evaluate BOTH actual postchecks regardless of the primary result or
        // the other postcheck. Return only the final original's fresh DATA.
        let local = self.action.check_local();
        let joined = (|| {
            let physical = self
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            self.original.check_join(
                physical.controller_stage()?,
                &self.record.statement.request,
                &self.operation,
            )
        })();
        if requested.is_err() || local.is_err() || joined.is_err() {
            self.refuse();
        }
        requested?;
        local?;
        joined
    }

    /// Exact preparation DATA from this actual authenticated executor. The
    /// archive supplier still consumes/retains the executor; this tuple grants
    /// no native clock, file, stage, key, dispatch or restore permission.
    pub(in crate::security_epoch) fn restore_archive_binding_data(
        &mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<(
        day2_capabilities::security_epoch::EpochStore,
        day2_capabilities::credentials::Namespace,
        i64,
        std::path::PathBuf,
    )> {
        let requested = (|| {
            self.require_historical_keys(intent)?;
            let selected = self.action.reader.loan.selection.clone();
            let approved = &self.record.statement.request.target;
            ensure!(
                approved.scope == selected.scope
                    && approved.selection == Digest::of(&selected)?
                    && approved.authority == selected.authority_key()?
                    && approved.security_epoch == 2,
                "restore_archive_approved_selection_changed"
            );
            let namespace = day2_capabilities::credentials::Namespace {
                installation: approved.scope.installation.clone(),
                environment: approved.scope.environment.clone(),
                app: approved.scope.app.clone(),
                binding_generation: approved.binding_generation,
            };
            namespace.validate()?;
            self.source.require_qualified(&self.time_operation)?;
            let time = self.source.current_time(&mut self.action)?;
            // The measured qualified upper bound supplies the delegation
            // cutoff DATA. It never renews either original or approval grant.
            let at = approval_window(&self.record, &time)?;
            Ok((
                selected,
                namespace,
                at,
                crate::security_epoch::storage_authority::restore_staging_root_path_data(),
            ))
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(super) fn check_source(&mut self) -> Result<RestoreObservation> {
        ExecutionSourceLoan {
            action: &mut self.action,
            original: &mut self.original,
            completion: &mut self.completion,
            record: &self.record,
            operation: &self.operation,
            time_operation: &self.time_operation,
            refused: &mut self.refused,
        }
        .check(&mut self.source)
    }
}

/// Private pre-send phase of the SAME executor. Only a known grant-keyed SQL
/// claim and every original/native/file postcheck can construct it. It exposes
/// neither the executor nor a receipt-to-owner recovery operation.
struct RestoreAttempt<'metadata, 'storage, 'role> {
    auth: Option<AuthenticatedRestoreExecution<'metadata, 'storage, 'role>>,
    intent: kernel::restore::Intent,
    refused: bool,
}

impl<'metadata, 'storage, 'role> AuthenticatedRestoreExecution<'metadata, 'storage, 'role> {
    fn begin_restore_attempt(
        mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<RestoreAttempt<'metadata, 'storage, 'role>> {
        let requested = (|| {
            self.require_historical_keys(intent)?;
            self.completion.record_attempt(
                &mut self.action.reader,
                (
                    self.action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.action.files,
                ),
            )
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        Ok(RestoreAttempt {
            auth: Some(self),
            intent: intent.clone(),
            refused: false,
        })
    }
}

impl RestoreAttempt<'_, '_, '_> {
    fn check(&mut self) -> Result<RestoreObservation> {
        let auth = self.auth.as_mut().context("restore_attempt_owner_closed")?;
        if self.refused {
            auth.refuse();
            anyhow::bail!("restore_attempt_refused");
        }
        self.refused = true;
        let requested = auth.require_historical_keys(&self.intent);
        let checked = auth.check();
        if requested.is_err() || checked.is_err() {
            auth.refuse();
        }
        requested?;
        let observed = checked?;
        self.refused = false;
        Ok(observed)
    }
}

// Normal Rust field destruction drops this actual executor, including its
// RestoreOriginalGuard and NativeApprovalSource terminal refusal destructors.
// No generic destructor, detachable guard or row-based recovery is introduced.

impl AuthenticatedRestoreExecution<'_, '_, '_> {
    /// One native acquisition of the whole exact archive key set, before the
    /// Fenced CAS. The actual executor owns the material across the handoff.
    pub(in crate::security_epoch) fn retain_historical_keys(
        &mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                self.historical_keys.is_none(),
                "restore_keys_already_retained"
            );
            let mut loan = ExecutionSourceLoan {
                action: &mut self.action,
                original: &mut self.original,
                completion: &mut self.completion,
                record: &self.record,
                operation: &self.operation,
                time_operation: &self.time_operation,
                refused: &mut self.refused,
            };
            let keys = self.source.retain_historical_keys(&mut loan, intent)?;
            loan.check(&mut self.source)?;
            self.historical_keys = Some(keys);
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    /// This supplies no list/permission to a caller. Current authority and the
    /// unchanged original are checked before the actual retained material.
    pub(in crate::security_epoch) fn require_historical_keys(
        &mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<()> {
        let requested = (|| {
            self.check()?;
            self.historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?
                .require(intent, &self.record, &self.operation)
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked.map(|_| ())
    }
}

impl ExecutionSourceLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn request_commitment_data(&self) -> Result<Digest> {
        self.record.statement.request.commitment()
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        *self.refused = true;
        self.original.refuse();
        self.action.refuse();
    }

    /// Selection DATA from the actual reader's admitted metadata, with the
    /// exact signed archive/target/operation and unchanged custody. No key or
    /// provider authority is returned by resolving this configuration.
    pub(in crate::security_epoch) fn historical_key_data(
        &mut self,
        selected: &day2_capabilities::security_epoch::EpochStore,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        intent: &kernel::restore::Intent,
    ) -> Result<Vec<crate::artifact::SecurityKeySelection>> {
        let requested = (|| {
            let request = &self.record.statement.request;
            intent.commitment(selected)?;
            ensure!(
                intent.operation == *self.operation
                    && intent.archive.full_archive_digest == request.full_archive_digest
                    && intent.target_incarnation == request.target.incarnation
                    && intent.archive.artifact == request.target.artifact
                    && intent.archive.schema == request.target.schema
                    && request.target.selection == Digest::of(selected)?
                    && request.target.authority == selected.authority_key()?
                    && request.target.scope == selected.scope
                    && request.target.security_epoch == 2
                    && intent
                        .archive
                        .required_keys
                        .iter()
                        .filter(|key| key.purpose == kernel::restore::KeyPurpose::CustodyEncryption)
                        .all(|key| key.binding == request.custody),
                "restore_keys_approval_binding_changed"
            );
            let instance = self.action.reader.metadata.require_native_selection(
                selected,
                &request.target.artifact,
                policy,
            )?;
            ensure!(
                instance.security_key_set(selected.scope.app.as_str())? == selected.key_set,
                "restore_keys_current_key_set_changed"
            );
            instance.security_key_selections(selected.scope.app.as_str())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<RestoreObservation> {
        let requested = (|| {
            ensure!(!*self.refused, "restore_executor_refused");
            self.action
                .check_execution_original(self.original, self.record, self.operation)?;
            self.completion.check_current(
                &mut self.action.reader,
                (
                    self.action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.action.files,
                ),
                self.record,
                self.operation,
            )?;
            source.require_qualified(self.time_operation)?;
            let time = source.current_time(self.action)?;
            approval_window(self.record, &time)?;
            Ok(())
        })();
        // The same original's postcheck still runs on a primary failure.
        // The first failure remains primary; no Source operation can reset it.
        let checked =
            self.action
                .check_execution_original(self.original, self.record, self.operation);
        if requested.is_err() || checked.is_err() {
            *self.refused = true;
            self.original.refuse();
            self.action.refuse();
        }
        requested?;
        checked
    }
}

pub(in crate::security_epoch) struct FencedRestoreContinuation<'metadata, 'storage, 'role> {
    auth: AuthenticatedRestoreExecution<'metadata, 'storage, 'role>,
    issuer: FrozenRoleIssuer,
    plan: approval_use::Plan,
    observed: crate::security_epoch::firestore::RestoreObserved,
    confirmation: crate::security_epoch::firestore::ReservationConfirmation,
    authorization: kernel::restore::Current,
    stopped: AuthorityStopData,
    writer_borrowed: Cell<bool>,
    refused: Rc<Cell<bool>>,
    readiness: Readiness,
    target_attempt: crate::security_epoch::restore_staging::RestoreDisposition,
    settled_target: Option<SettledTarget>,
    receiver_attempted: bool,
    writer_attempt: crate::security_epoch::restore_staging::RestoreDisposition,
}

/// Exclusive, one-use loan. Parent keeps this exact borrow across creation,
/// SQL reset, P3, writer and activation. It has no descriptor/role/HTTP getter.
pub(in crate::security_epoch) struct RestoreWriteLoan<'borrow, 'metadata, 'storage, 'role> {
    owner: &'borrow mut FencedRestoreContinuation<'metadata, 'storage, 'role>,
    _lost: LostRestoreLoan,
}

/// One actual whole-parent reborrow for the fixed pre-CAS receiver exchange.
/// It is not made from request DATA and exposes no action, stage, clock, file,
/// callback or transport getter. Every real transport step must bracket itself
/// with these complete checks, including the post after its primary error.
pub(in crate::security_epoch) struct RestoreWriterExchangeContext<
    'exchange,
    'metadata,
    'storage,
    'role,
> {
    owner: &'exchange mut FencedRestoreContinuation<'metadata, 'storage, 'role>,
}

impl RestoreWriterExchangeContext<'_, '_, '_, '_> {
    /// The receiver lends its ACTUAL busy operation, not a readiness token.
    /// Only its private successful tail can advance to signing Durable.
    pub(in crate::security_epoch) fn durable_target(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>,
    ) -> Result<()> {
        if self.owner.refused.get() {
            target.refuse();
            self.refuse();
            anyhow::bail!("native_restore_receiver_parent_refused");
        }
        self.owner.refused.set(true);
        let requested: Result<()> = (|| {
            self.check_inner(target)?;
            {
                let physical = self
                    .owner
                    .auth
                    .action
                    .reader
                    .loan
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?;
                receiver.check(&mut physical.controller_stage()?.storage()?, target)?;
            }
            let mut executor = ExecutionSourceLoan {
                action: &mut self.owner.auth.action,
                original: &mut self.owner.auth.original,
                completion: &mut self.owner.auth.completion,
                record: &self.owner.auth.record,
                operation: &self.owner.auth.operation,
                time_operation: &self.owner.auth.time_operation,
                refused: &mut self.owner.auth.refused,
            };
            let mut check = RestoreTargetCheck {
                executor: &mut executor,
                issuer: &mut self.owner.issuer,
                keys: self
                    .owner
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.owner.readiness,
                refused: &self.owner.refused,
                source: &mut self.owner.auth.source,
            };
            target.sync_for_receiver(&mut check, receiver)
        })();
        // Both the receiver's retained handles and whole parent are checked
        // after any sync/readback failure. The first error remains primary.
        let native_post = (|| {
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            receiver.check(&mut physical.controller_stage()?.storage()?, target)
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || native_post.is_err() || checked.is_err() {
            target.refuse();
            self.refuse();
        }
        requested?;
        native_post?;
        checked?;
        self.owner.refused.set(false);
        Ok(())
    }

    /// Project this actual target and consumed ledger to the same retained
    /// prepared receiver. This returns no projection or native owner to callers.
    pub(in crate::security_epoch) fn receiver_bind_projection(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverRendezvous,
    ) -> Result<()> {
        if self.owner.refused.get() {
            target.refuse();
            receiver.refuse();
            self.refuse();
            anyhow::bail!("native_restore_receiver_parent_refused");
        }
        self.owner.refused.set(true);
        let requested: Result<()> = (|| {
            self.check_inner(target)?;
            {
                let physical = self
                    .owner
                    .auth
                    .action
                    .reader
                    .loan
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?;
                receiver.check(&mut physical.controller_stage()?.storage()?, target)?;
            }
            let settled = self
                .owner
                .settled_target
                .as_ref()
                .context("restore_writer_target_not_settled")?;
            let report = settled.report.clone();
            let before = settled.known.writer_state_data()?;
            let selectors = self
                .owner
                .plan
                .selectors(&self.owner.auth.action.reader.loan.selection)?;
            let creator = {
                let mut executor = ExecutionSourceLoan {
                    action: &mut self.owner.auth.action,
                    original: &mut self.owner.auth.original,
                    completion: &mut self.owner.auth.completion,
                    record: &self.owner.auth.record,
                    operation: &self.owner.auth.operation,
                    time_operation: &self.owner.auth.time_operation,
                    refused: &mut self.owner.auth.refused,
                };
                let mut check = RestoreTargetCheck {
                    executor: &mut executor,
                    issuer: &mut self.owner.issuer,
                    keys: self
                        .owner
                        .auth
                        .historical_keys
                        .as_mut()
                        .context("restore_keys_not_retained")?,
                    readiness: &self.owner.readiness,
                    refused: &self.owner.refused,
                    source: &mut self.owner.auth.source,
                };
                target.creator_data(&mut check)?
            };
            let approval = &self.owner.auth.record.statement.request;
            let projection = crate::security_epoch::native_enrollment::RestoreFileProjectionData {
                selection: crate::security_epoch::native_enrollment::RestoreSelectionData {
                    operation: self.owner.auth.operation.clone(),
                    approval_request: approval.commitment()?,
                    intent: self.owner.authorization.grant.intent.clone(),
                    full_archive: approval.full_archive_digest.clone(),
                    target: approval.target.clone(),
                },
                creator,
                report,
                consumed_use: Digest::of(&before.consumed.value)?,
                captured_records: before.commitment_data()?,
                ledger: crate::security_epoch::native_enrollment::RestoreLedgerKeysData {
                    initial_create: selectors.bootstrap.create_operation,
                    initial_activation: selectors.activation,
                    advance: selectors.advance,
                    grant: before.consumed.value.grant_id_data().clone(),
                },
            };
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            receiver.bind_projection(
                &mut physical.controller_stage()?.storage()?,
                &projection,
                target,
            )
        })();
        let native_post = (|| {
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            receiver.check(&mut physical.controller_stage()?.storage()?, target)
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || native_post.is_err() || checked.is_err() {
            target.refuse();
            receiver.refuse();
            self.refuse();
        }
        requested?;
        native_post?;
        checked?;
        self.owner.refused.set(false);
        Ok(())
    }

    pub(in crate::security_epoch) fn begin_receiver(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        mut admission: crate::security_epoch::native_enrollment::PreparedRestoreAdmission,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverRendezvous> {
        if self.owner.refused.get() {
            target.refuse();
            admission.refuse();
            self.refuse();
            anyhow::bail!("native_restore_receiver_parent_refused");
        }
        self.owner.refused.set(true);
        let mut requested: Result<_> = (|| {
            self.check_inner(target)?;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            crate::security_epoch::native_enrollment::ReceiverRendezvous::begin(
                &mut physical.controller_stage()?.storage()?,
                admission,
                target,
            )
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            if let Ok(receiver) = &mut requested {
                receiver.refuse();
            }
            target.refuse();
            self.refuse();
        }
        let receiver = requested?;
        checked?;
        self.owner.refused.set(false);
        Ok(receiver)
    }

    pub(in crate::security_epoch) fn receiver_try_send(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverRendezvous,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        self.receiver_step(target, receiver, ReceiverStep::Send)
    }

    pub(in crate::security_epoch) fn receiver_try_receive(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverRendezvous,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        self.receiver_step(target, receiver, ReceiverStep::Receive)
    }

    pub(in crate::security_epoch) fn receiver_poll(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverRendezvous,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        self.receiver_step(target, receiver, ReceiverStep::Poll)
    }

    fn receiver_step(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverRendezvous,
        step: ReceiverStep,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        if self.owner.refused.get() {
            target.refuse();
            receiver.refuse();
            self.refuse();
            anyhow::bail!("native_restore_receiver_parent_refused");
        }
        self.owner.refused.set(true);
        let requested = (|| {
            self.check_inner(target)?;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut storage = physical.controller_stage()?.storage()?;
            match step {
                ReceiverStep::Send => receiver.try_send(&mut storage, target),
                ReceiverStep::Receive => receiver.try_receive(&mut storage, target),
                ReceiverStep::Poll => receiver.poll(&mut storage, target),
            }
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            target.refuse();
            receiver.refuse();
            self.refuse();
        }
        let progress = requested?;
        checked?;
        self.owner.refused.set(false);
        Ok(progress)
    }

    pub(in crate::security_epoch) fn finish_receiver(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        mut receiver: crate::security_epoch::native_enrollment::ReceiverRendezvous,
    ) -> Result<crate::security_epoch::native_enrollment::RestoredWriterPeer> {
        if self.owner.refused.get() {
            target.refuse();
            receiver.refuse();
            self.refuse();
            anyhow::bail!("native_restore_receiver_parent_refused");
        }
        self.owner.refused.set(true);
        let mut requested: Result<_> = (|| {
            self.check_inner(target)?;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            receiver.into_peer(&mut physical.controller_stage()?.storage()?, target)
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            if let Ok(peer) = &mut requested {
                peer.refuse();
            }
            target.refuse();
            self.refuse();
        }
        let peer = requested?;
        checked?;
        self.owner.refused.set(false);
        Ok(peer)
    }

    /// One issuer preparation under the actual full consumed parent. Native
    /// same-owner checks cannot replace approval/UV/keys/readiness/target checks.
    pub(in crate::security_epoch) fn prepare_admission(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::PreparedRestoreAdmission> {
        self.check(target)?;
        if self.owner.receiver_attempted {
            self.refuse();
            target.refuse();
            anyhow::bail!("native_restore_receiver_attempt_spent");
        }
        self.owner.receiver_attempted = true;
        self.owner.refused.set(true);
        let requested: Result<_> = (|| {
            self.check_inner(target)?;
            let actual = self.owner.check_current_inner()?;
            let (clock, origin, deadline) = actual.interval_data();
            let settled = self
                .owner
                .settled_target
                .as_ref()
                .context("restore_writer_target_not_settled")?;
            let before = settled.known.writer_state_data()?;
            let approval = &self.owner.auth.record.statement.request;
            // The immutable pinned file alone is insufficient after a named
            // selector change. This actual metadata validator reloads the same
            // Instance and checks both current-selector joins (including Err).
            self.owner
                .auth
                .action
                .reader
                .metadata
                .require_native_selection(
                    &self.owner.auth.action.reader.loan.selection,
                    &self
                        .owner
                        .auth
                        .action
                        .reader
                        .loan
                        .policy
                        .runtime_profile
                        .app_artifact,
                    &self.owner.auth.action.reader.loan.policy,
                )?;
            let supplied = crate::security_epoch::native_enrollment::RestorePreparationData {
                operation: self.owner.auth.operation.clone(),
                approval: approval.commitment()?,
                grant: approval.grant_id.clone(),
                intent: self.owner.authorization.grant.intent.clone(),
                full_archive: approval.full_archive_digest.clone(),
                desired_instance: self
                    .owner
                    .auth
                    .action
                    .reader
                    .metadata
                    .restore_registry_selector_data()
                    .1,
                target: approval.target.clone(),
                report: settled.report.clone(),
                terminal: Digest::of(&before.terminal.value)?,
                terminal_version: before.terminal.version.clone(),
                records: before.commitment_data()?,
                parent_clock: clock.clone(),
                parent_origin_ns: origin,
                parent_deadline_ns: deadline,
            };
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            self.owner
                .issuer
                .begin_restore_preparation(&mut physical.controller_stage()?.storage()?, &supplied)
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            target.refuse();
            self.refuse();
        }
        let mut pending = requested?;
        checked?;
        self.owner.refused.set(false);
        self.preparation_step(target, &mut pending, RestorePreparationStep::Hello)?;
        self.preparation_step(target, &mut pending, RestorePreparationStep::Nonce)?;
        self.preparation_step(target, &mut pending, RestorePreparationStep::Sign)?;
        self.preparation_step(target, &mut pending, RestorePreparationStep::Bind)?;
        self.preparation_step(target, &mut pending, RestorePreparationStep::Grant)?;
        self.finish_preparation(target, pending)
    }

    fn preparation_step(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        pending: &mut crate::security_epoch::native_enrollment::IssuerRestorePreparation,
        step: RestorePreparationStep,
    ) -> Result<()> {
        if self.owner.refused.get() {
            target.refuse();
            pending.refuse();
            self.refuse();
            anyhow::bail!("native_restore_preparation_parent_refused");
        }
        self.owner.refused.set(true);
        let requested: Result<()> = (|| {
            self.check_inner(target)?;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut storage = physical.controller_stage()?.storage()?;
            match step {
                RestorePreparationStep::Hello => pending.send_hello(&mut storage),
                RestorePreparationStep::Nonce => pending.receive_nonce(&mut storage),
                RestorePreparationStep::Sign => pending.sign_bind(&mut storage),
                RestorePreparationStep::Bind => pending.send_bind(&mut storage),
                RestorePreparationStep::Grant => pending.receive_grant(&mut storage),
            }
        })();
        // End the short actual stage before this independent FULL post, even
        // when the sign/send/receive failed or its outcome is uncertain.
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            target.refuse();
            pending.refuse();
            self.refuse();
        }
        requested?;
        checked?;
        self.owner.refused.set(false);
        Ok(())
    }

    fn finish_preparation(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        pending: crate::security_epoch::native_enrollment::IssuerRestorePreparation,
    ) -> Result<crate::security_epoch::native_enrollment::PreparedRestoreAdmission> {
        if self.owner.refused.get() {
            target.refuse();
            self.refuse();
            anyhow::bail!("native_restore_preparation_parent_refused");
        }
        self.owner.refused.set(true);
        let requested: Result<_> = (|| {
            self.check_inner(target)?;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            pending.finish(&mut physical.controller_stage()?.storage()?)
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            target.refuse();
            self.refuse();
        }
        let prepared = requested?;
        checked?;
        self.owner.refused.set(false);
        Ok(prepared)
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    ) -> Result<()> {
        if self.owner.refused.get() {
            target.refuse();
            self.refuse();
            anyhow::bail!("native_restore_writer_exchange_refused");
        }
        self.owner.refused.set(true);
        let requested = self.check_inner(target);
        if requested.is_ok() {
            self.owner.refused.set(false);
        } else {
            target.refuse();
            self.refuse();
        }
        requested
    }

    /// One fixed receiver boundary, retaining the same whole parent. Native
    /// peer checks get only a short actual Controller storage-stage borrow;
    /// it ends before the independent full parent/target postcheck.
    pub(in crate::security_epoch) fn check_receiver(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<()> {
        if self.owner.refused.get() {
            peer.refuse();
            target.refuse();
            self.refuse();
            anyhow::bail!("native_restore_writer_receiver_refused");
        }
        // Do not make an unwind healthy merely because the peer check was
        // interrupted after the last successful full parent observation.
        self.owner.refused.set(true);
        let requested = (|| {
            self.check_inner(target)?;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            peer.check(&mut physical.controller_stage()?.storage()?)
        })();
        let checked = self.check_inner(target);
        if requested.is_err() || checked.is_err() {
            peer.refuse();
            target.refuse();
            self.refuse();
        }
        requested?;
        checked?;
        self.owner.refused.set(false);
        Ok(())
    }

    fn check_inner(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.owner.check_current_inner()?;
            let expected = self
                .owner
                .settled_target
                .as_ref()
                .context("restore_writer_target_not_settled")?
                .report
                .clone();
            let mut executor = ExecutionSourceLoan {
                action: &mut self.owner.auth.action,
                original: &mut self.owner.auth.original,
                completion: &mut self.owner.auth.completion,
                record: &self.owner.auth.record,
                operation: &self.owner.auth.operation,
                time_operation: &self.owner.auth.time_operation,
                refused: &mut self.owner.auth.refused,
            };
            let mut checks = RestoreTargetCheck {
                executor: &mut executor,
                issuer: &mut self.owner.issuer,
                keys: self
                    .owner
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.owner.readiness,
                refused: &self.owner.refused,
                source: &mut self.owner.auth.source,
            };
            let observed = target.validate(&mut checks)?;
            ensure!(
                observed == expected,
                "restore_writer_settled_target_changed"
            );
            Ok(())
        })();
        let checked = self.owner.check_current_inner();
        if requested.is_err() || checked.is_err() {
            target.refuse();
            self.refuse();
        }
        requested?;
        checked.map(|_| ())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.owner.refuse();
    }
}

/// Closed borrow for the final receiving handoff. There is deliberately NO
/// DATA constructor: only the fixed native writer driver constructs this
/// after its actual CAS, complete readback and separate post-CAS checks. The
/// known record is DATA, not the actual parent/creator/holder permission.
/// Abandonment remains negative-only until the real consuming keeper transfer.
pub(in crate::security_epoch) struct RestoreWriterConfirmation<'confirm, 'metadata, 'storage, 'role>
{
    owner: &'confirm mut FencedRestoreContinuation<'metadata, 'storage, 'role>,
    known: crate::security_epoch::firestore::KnownRestoredWriter,
    request: kernel::restore::writer::Request,
    plan: kernel::restore::writer::Plan,
    target: kernel::restore::completion::TargetReport,
    holder: kernel::Holder,
    activation_creator: Option<crate::security_epoch::native_enrollment::RestoreCreatorData>,
    _lost: LostRestoreWriterConfirmation,
}

struct WriterConfirmationData<'data> {
    known: &'data crate::security_epoch::firestore::KnownRestoredWriter,
    request: &'data kernel::restore::writer::Request,
    plan: &'data kernel::restore::writer::Plan,
    report: &'data kernel::restore::completion::TargetReport,
    holder: &'data kernel::Holder,
}

/// Nonescaping native signing borrow. Only the fixed Confirmation driver may
/// construct it from its actual fields; no DATA or public constructor exists.
/// Full UV/provider/target pre/postchecks remain outside the short native stage
/// borrow. This neither authorizes SQLite nor proves Activated was delivered.
pub(in crate::security_epoch) struct RestoreWriterActivationLoan<'borrow> {
    original: &'borrow mut RestoreOriginalGuard,
    approval: &'borrow crate::security_epoch::restore_approval::ApprovalRequest,
    operation: &'borrow Digest,
    selected: &'borrow day2_capabilities::security_epoch::EpochStore,
    known: &'borrow crate::security_epoch::firestore::KnownRestoredWriter,
    request: &'borrow kernel::restore::writer::Request,
    plan: &'borrow kernel::restore::writer::Plan,
    creator: &'borrow crate::security_epoch::native_enrollment::RestoreCreatorData,
    refused: &'borrow Rc<Cell<bool>>,
    _lost: LostRestoreWriterConfirmation,
}

impl RestoreWriterActivationLoan<'_> {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut crate::security_epoch::native_enrollment::EnrolledStorageStage<'_, '_>,
        projection: &crate::security_epoch::native_enrollment::RestoreFileProjectionData,
        holder: &kernel::Holder,
    ) -> Result<crate::security_epoch::native_enrollment::RestoreWriterActivationData> {
        let requested = (|| {
            // The actual whole Confirmation pessimistically holds this mark
            // until its independent full postcheck. A detached loan is closed.
            ensure!(
                self.refused.get(),
                "restore_writer_activation_outside_confirmation"
            );
            storage.check_restore_original(self.original, self.approval, self.operation)?;
            ensure!(
                projection.creator == *self.creator,
                "restore_writer_activation_creator_changed"
            );
            self.known.peer_activation_data(
                self.selected,
                self.request,
                self.plan,
                projection,
                holder,
            )
        })();
        // Always join the SAME original again, including after projection or
        // strict Known mismatch. Neither branch samples a replacement clock.
        let checked = storage.check_restore_original(self.original, self.approval, self.operation);
        if requested.is_err() || checked.is_err() {
            self.refused.set(true);
            self.original.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused.set(true);
        self.original.refuse();
    }
}

/// A distinct actual final-release borrow. Its only future fixed driver
/// constructor must borrow the same post-ACK frame and its held Controller
/// cohort. An ActivationLoan, ACK DATA or file tuple cannot substitute for it.
/// This checks native/physical continuity only; the full current Known/UV/key/
/// provider checks remain mandatory around each short native operation.
pub(in crate::security_epoch) struct RestoreWriterReleaseLoan<'borrow, 'target, 'selection> {
    original: &'borrow mut RestoreOriginalGuard,
    approval: &'borrow crate::security_epoch::restore_approval::ApprovalRequest,
    operation: &'borrow Digest,
    known: &'borrow crate::security_epoch::firestore::KnownRestoredWriter,
    plan: &'borrow kernel::restore::writer::Plan,
    creator: &'borrow crate::security_epoch::native_enrollment::RestoreCreatorData,
    report: &'borrow kernel::restore::completion::TargetReport,
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    cohort: &'borrow mut crate::security_epoch::restore_staging::RestoreControllerCohort,
    refused: &'borrow Rc<Cell<bool>>,
    _lost: LostRestoreWriterConfirmation,
}
impl RestoreWriterReleaseLoan<'_, '_, '_> {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut crate::security_epoch::native_enrollment::EnrolledStorageStage<'_, '_>,
        activation: &crate::security_epoch::native_enrollment::RestoreWriterActivationData,
        acknowledged: &crate::security_epoch::native_enrollment::SqliteCohort,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(self.refused.get(), "restore_release_outside_actual_frame");
            storage.check_restore_original(self.original, self.approval, self.operation)?;
            self.known.require_activation_data(self.plan, activation)?;
            let held = self.cohort.check(self.target, self.creator, self.report)?;
            ensure!(
                held == *acknowledged,
                "restore_release_keeper_cohort_changed"
            );
            Ok(())
        })();
        let checked = storage.check_restore_original(self.original, self.approval, self.operation);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused.set(true);
        self.target.refuse();
        self.original.refuse();
    }
}

/// Distinct issuer-finish purpose. Its sole fixed constructor is
/// inside the consuming actual Controller installation, never the release
/// frame or receipt DATA. It retains every actual physical/original owner;
/// current Known/UV/key/provider guards bracket the short native operation.
pub(in crate::security_epoch) struct RestoreFinalInstallationLoan<'borrow, 'target, 'selection> {
    original: &'borrow mut RestoreOriginalGuard,
    approval: &'borrow crate::security_epoch::restore_approval::ApprovalRequest,
    operation: &'borrow Digest,
    known: &'borrow crate::security_epoch::firestore::KnownRestoredWriter,
    plan: &'borrow kernel::restore::writer::Plan,
    creator: &'borrow crate::security_epoch::native_enrollment::RestoreCreatorData,
    report: &'borrow kernel::restore::completion::TargetReport,
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    cohort: &'borrow mut crate::security_epoch::restore_staging::RestoreControllerCohort,
    refused: &'borrow Rc<Cell<bool>>,
    _lost: LostRestoreWriterConfirmation,
}
impl RestoreFinalInstallationLoan<'_, '_, '_> {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut crate::security_epoch::native_enrollment::EnrolledStorageStage<'_, '_>,
        activation: &crate::security_epoch::native_enrollment::RestoreWriterActivationData,
        acknowledged: &crate::security_epoch::native_enrollment::SqliteCohort,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                self.refused.get(),
                "restore_issuer_outside_actual_installation"
            );
            storage.check_restore_original(self.original, self.approval, self.operation)?;
            self.known.require_activation_data(self.plan, activation)?;
            let held = self.cohort.check(self.target, self.creator, self.report)?;
            ensure!(
                held == *acknowledged,
                "restore_issuer_installation_cohort_changed"
            );
            Ok(())
        })();
        let checked = storage.check_restore_original(self.original, self.approval, self.operation);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused.set(true);
        self.target.refuse();
        self.original.refuse();
    }
}

// A nongeneric negative-only Drop; its SAME-parent refusal cell can never
// become an approval, permission or successful keeper-transfer constructor.
struct LostRestoreWriterConfirmation {
    refused: Rc<Cell<bool>>,
}

impl Drop for LostRestoreWriterConfirmation {
    fn drop(&mut self) {
        self.refused.set(true);
    }
}

fn require_activation_creator(
    retained: &crate::security_epoch::native_enrollment::RestoreCreatorData,
    fresh: &crate::security_epoch::native_enrollment::RestoreCreatorData,
) -> Result<()> {
    ensure!(
        retained == fresh,
        "restore_writer_activation_creator_changed"
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum ActivationPreparationStep {
    Prepare,
    Sign,
}

impl RestoreWriterConfirmation<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn prepare_activated(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<()> {
        self.activation_preparation(target, peer, ActivationPreparationStep::Prepare)
    }

    pub(in crate::security_epoch) fn sign_activated(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<()> {
        self.activation_preparation(target, peer, ActivationPreparationStep::Sign)
    }

    fn activation_preparation(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
        step: ActivationPreparationStep,
    ) -> Result<()> {
        if matches!(step, ActivationPreparationStep::Prepare) && self.activation_creator.is_some() {
            self.refuse();
            target.refuse();
            peer.refuse();
            anyhow::bail!("restore_writer_activation_preparation_spent");
        }
        self.check_before_activation(target, peer)?;
        self.owner.refused.set(true);
        let captured: Result<_> = (|| {
            let fresh = self.owner.capture_activation_creator(target)?;
            if matches!(step, ActivationPreparationStep::Sign) {
                let retained = self
                    .activation_creator
                    .as_ref()
                    .context("restore_writer_activation_not_prepared")?;
                require_activation_creator(retained, &fresh)?;
            }
            Ok(fresh)
        })();
        let requested: Result<()> = (|| {
            // On an earlier capture failure this placeholder cannot replace
            // its retained primary error, propagated before requested below.
            let creator = captured
                .as_ref()
                .map_err(|_| anyhow::anyhow!("restore_writer_activation_creator_unavailable"))?;
            let selected = &self.owner.auth.action.reader.loan.selection;
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut storage = physical.controller_stage()?.storage()?;
            let mut loan = RestoreWriterActivationLoan {
                original: &mut self.owner.auth.original,
                approval: &self.owner.auth.record.statement.request,
                operation: &self.owner.auth.operation,
                selected,
                known: &self.known,
                request: &self.request,
                plan: &self.plan,
                creator,
                refused: &self.owner.refused,
                _lost: LostRestoreWriterConfirmation {
                    refused: Rc::clone(&self.owner.refused),
                },
            };
            match step {
                ActivationPreparationStep::Prepare => {
                    peer.prepare_activated(&mut storage, &mut loan)?
                }
                ActivationPreparationStep::Sign => peer.sign_activated(&mut storage, &mut loan)?,
            }
            Ok(())
        })();
        // The native stage borrow and loan are closed BEFORE independent peer
        // and whole Known/UV/provider/target posts, even on the primary error.
        let native_post = (|| {
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            peer.check(&mut physical.controller_stage()?.storage()?)
        })();
        let expected = WriterConfirmationData {
            known: &self.known,
            request: &self.request,
            plan: &self.plan,
            report: &self.target,
            holder: &self.holder,
        };
        let checked = self
            .owner
            .check_writer_after_cas_inner(&expected, target, peer);
        // Sample actual ownership metadata again AFTER the full Known post,
        // even if capture, signing, native peer or provider post already failed.
        let creator_post = (|| {
            let fresh = self.owner.capture_activation_creator(target)?;
            let retained = self
                .activation_creator
                .as_ref()
                .or(captured.as_ref().ok())
                .context("restore_writer_activation_creator_unavailable")?;
            require_activation_creator(retained, &fresh)
        })();
        if captured.is_err()
            || requested.is_err()
            || native_post.is_err()
            || checked.is_err()
            || creator_post.is_err()
        {
            self.refuse();
            target.refuse();
            peer.refuse();
        }
        let creator = captured?;
        requested?;
        native_post?;
        checked?;
        creator_post?;
        self.activation_creator = Some(creator);
        self.owner.refused.set(false);
        Ok(())
    }

    /// Separate full authority and ten-record confirmation after known writer
    /// CAS, BEFORE the new App opens a read-write SQLite keeper. The pre-CAS
    /// frozen image is not silently reused after that mechanical transition.
    pub(in crate::security_epoch) fn check_before_activation(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<()> {
        self.owner.check_writer_after_cas(
            &WriterConfirmationData {
                known: &self.known,
                request: &self.request,
                plan: &self.plan,
                report: &self.target,
                holder: &self.holder,
            },
            target,
            peer,
        )
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.owner.refuse();
    }
}

// This private choice is not caller DATA or permission. Frozen is used by
// ordinary confirmation; Activated is selected only by the genuine lexical
// frame below after the final frozen-image check and before possible send.
enum WriterTargetPurpose<'a> {
    Frozen,
    Activated(&'a crate::security_epoch::native_enrollment::RestoreCreatorData),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivationIo {
    Send,
    Poll,
    ReceiveAck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivationProgress {
    FirstSend,
    Send,
    PollSend,
    ReceiveAck,
    PollAck,
    Acknowledged,
    Refused,
}

impl ActivationProgress {
    fn operation(self) -> Result<ActivationIo> {
        match self {
            Self::FirstSend | Self::Send => Ok(ActivationIo::Send),
            Self::PollSend | Self::PollAck => Ok(ActivationIo::Poll),
            Self::ReceiveAck => Ok(ActivationIo::ReceiveAck),
            Self::Acknowledged | Self::Refused => anyhow::bail!("restore_activation_not_pending"),
        }
    }

    fn after(
        self,
        operation: ActivationIo,
        progress: crate::security_epoch::native_enrollment::ReceiverProgress,
    ) -> Result<Self> {
        use crate::security_epoch::native_enrollment::ReceiverProgress as P;
        ensure!(
            self.operation()? == operation,
            "restore_activation_wrong_operation"
        );
        match (self, progress) {
            (Self::FirstSend | Self::Send, P::Delivered) => Ok(Self::ReceiveAck),
            (Self::FirstSend | Self::Send, P::WouldBlock) => Ok(Self::PollSend),
            (Self::FirstSend | Self::Send, P::Interrupted) => Ok(Self::Send),
            (Self::PollSend, P::Advanced) => Ok(Self::Send),
            (Self::PollSend, P::Interrupted) => Ok(Self::PollSend),
            (Self::ReceiveAck, P::Delivered) => Ok(Self::Acknowledged),
            (Self::ReceiveAck, P::WouldBlock) => Ok(Self::PollAck),
            (Self::ReceiveAck, P::Interrupted) => Ok(Self::ReceiveAck),
            (Self::PollAck, P::Advanced) => Ok(Self::ReceiveAck),
            (Self::PollAck, P::Interrupted) => Ok(Self::PollAck),
            _ => anyhow::bail!("restore_activation_unexpected_progress"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReleaseIo {
    Prepare,
    Sign,
    Send,
    Poll,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReleaseProgress {
    Prepare,
    Sign,
    Send,
    Poll,
    Delivered,
    Refused,
}
impl ReleaseProgress {
    fn operation(self) -> Result<ReleaseIo> {
        match self {
            Self::Prepare => Ok(ReleaseIo::Prepare),
            Self::Sign => Ok(ReleaseIo::Sign),
            Self::Send => Ok(ReleaseIo::Send),
            Self::Poll => Ok(ReleaseIo::Poll),
            Self::Delivered | Self::Refused => anyhow::bail!("restore_release_not_pending"),
        }
    }
    fn after(
        self,
        operation: ReleaseIo,
        progress: crate::security_epoch::native_enrollment::ReceiverProgress,
    ) -> Result<Self> {
        use crate::security_epoch::native_enrollment::ReceiverProgress as P;
        ensure!(
            self.operation()? == operation,
            "restore_release_wrong_operation"
        );
        match (self, progress) {
            (Self::Prepare, P::Advanced) => Ok(Self::Sign),
            (Self::Sign, P::Advanced) => Ok(Self::Send),
            (Self::Send, P::Delivered) => Ok(Self::Delivered),
            (Self::Send, P::WouldBlock) => Ok(Self::Poll),
            (Self::Send, P::Interrupted) => Ok(Self::Send),
            (Self::Poll, P::Advanced) => Ok(Self::Send),
            (Self::Poll, P::Interrupted) => Ok(Self::Poll),
            _ => anyhow::bail!("restore_release_unexpected_progress"),
        }
    }
}

/// Actual same-owner frame, never a DATA-to-owner constructor. It retains the
/// genuine Confirmation, completed target and Accepted peer before the first
/// possible Activated byte. MAIN may become mutable during send itself, so
/// only the first precheck uses the frozen image; every postcheck uses exact
/// retained physical identity plus full Known/UV/key/provider/original checks.
/// A keeper ACK is not Released, Controller installation or serving permission.
pub(in crate::security_epoch) struct RestoreWriterActivated<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    confirmation: &'frame mut RestoreWriterConfirmation<'confirm, 'metadata, 'storage, 'role>,
    target:
        &'frame mut crate::security_epoch::restore_staging::NativeStagedTarget<'target, 'selection>,
    peer: &'frame mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    creator: crate::security_epoch::native_enrollment::RestoreCreatorData,
    progress: ActivationProgress,
    cohort: Option<crate::security_epoch::restore_staging::RestoreControllerCohort>,
    release_started: bool,
    release: Option<ReleaseProgress>,
    _lost: LostRestoreWriterConfirmation,
}

impl<'confirm, 'metadata, 'storage, 'role>
    RestoreWriterConfirmation<'confirm, 'metadata, 'storage, 'role>
{
    pub(in crate::security_epoch) fn activate_writer<'frame, 'target, 'selection>(
        &'frame mut self,
        target: &'frame mut crate::security_epoch::restore_staging::NativeStagedTarget<
            'target,
            'selection,
        >,
        peer: &'frame mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<
        RestoreWriterActivated<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>,
    > {
        self.prepare_activated(target, peer)?;
        self.sign_activated(target, peer)?;
        self.check_before_activation(target, peer)?;
        let creator = self
            .activation_creator
            .as_ref()
            .context("restore_writer_activation_not_prepared")?
            .clone();
        self.owner.refused.set(true);
        let lost = LostRestoreWriterConfirmation {
            refused: Rc::clone(&self.owner.refused),
        };
        let mut frame = RestoreWriterActivated {
            confirmation: self,
            target,
            peer,
            creator,
            progress: ActivationProgress::FirstSend,
            cohort: None,
            release_started: false,
            release: None,
            _lost: lost,
        };
        frame.receive_ack()?;
        Ok(frame)
    }
}

/// Action-bound Controller installation resources, not ordinary storage or
/// Current. It consumes the WHOLE actual completed release frame: the same
/// target/root/installed artifact, cohort, peer, Confirmation and original all
/// remain held. No receipt, pathname or recaptured native role can make one.
/// Native issuer completion and the later ordinary-role/file handoff remain
/// distinct; this owner cannot outlive its actual administrative lifetime.
pub(in crate::security_epoch) struct RestoreControllerInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    frame:
        RestoreWriterActivated<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>,
    issuer_progress: IssuerFinishProgress,
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreWriterActivated<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
{
    pub(in crate::security_epoch) fn install_controller(
        mut self,
    ) -> Result<
        RestoreControllerInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        // Do not construct a temporary positive installation for its own
        // admission. Both independent checks use the actual previous frame.
        self.check_completed_resources()?;
        Ok(RestoreControllerInstallation {
            frame: self,
            issuer_progress: IssuerFinishProgress::Fresh,
        })
    }
}

impl RestoreControllerInstallation<'_, '_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        if self.issuer_progress != IssuerFinishProgress::Fresh {
            self.refuse();
            anyhow::bail!("restore_issuer_installation_not_available");
        }
        self.frame.check_completed_resources()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.issuer_progress = IssuerFinishProgress::Refused;
        self.frame.refuse();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IssuerFinishProgress {
    Fresh,
    Hello,
    Nonce,
    Sign,
    Bind,
    Grant,
    Finish,
    Completed,
    RoleHello,
    RoleNonce,
    RoleBind,
    RoleGrant,
    RoleFinish,
    RoleActivated,
    Busy,
    Refused,
}
#[derive(Clone, Copy)]
enum IssuerFinishStep {
    Hello,
    Nonce,
    Sign,
    Bind,
    Grant,
}
impl IssuerFinishStep {
    fn progress(self) -> (IssuerFinishProgress, IssuerFinishProgress) {
        use IssuerFinishProgress as P;
        match self {
            Self::Hello => (P::Hello, P::Nonce),
            Self::Nonce => (P::Nonce, P::Sign),
            Self::Sign => (P::Sign, P::Bind),
            Self::Bind => (P::Bind, P::Grant),
            Self::Grant => (P::Grant, P::Finish),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IssuerRoleActivationStep {
    Hello,
    Nonce,
    Bind,
    Grant,
}

impl IssuerRoleActivationStep {
    fn progress(self) -> (IssuerFinishProgress, IssuerFinishProgress) {
        use IssuerFinishProgress as P;
        match self {
            Self::Hello => (P::RoleHello, P::RoleNonce),
            Self::Nonce => (P::RoleNonce, P::RoleBind),
            Self::Bind => (P::RoleBind, P::RoleGrant),
            Self::Grant => (P::RoleGrant, P::RoleFinish),
        }
    }
}

// Fixed private dispatch, not a callback table or escaping operational API.
// Wrappers keep actual owning variants private; none is caller DATA.
struct IssuerFinishCall<'pending> {
    kind: IssuerFinishCallKind<'pending>,
}
enum IssuerFinishCallKind<'pending> {
    Begin,
    Step {
        pending: &'pending mut crate::security_epoch::native_enrollment::IssuerRestoreFinishing,
        step: IssuerFinishStep,
    },
    Finish(crate::security_epoch::native_enrollment::IssuerRestoreFinishing),
    Check(&'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer),
    RoleHandoff {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        operation: RoleHandoffIo,
    },
    RoleActivationBegin {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
    },
    RoleActivationStep {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        pending: &'pending mut IssuerRestoreRoleActivating,
        step: IssuerRoleActivationStep,
    },
    RoleActivationFinish {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        pending: IssuerRestoreRoleActivating,
    },
    RoleActivationCheck {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
    },
    RoleDecision {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
        operation: RoleHandoffIo,
    },
    RolePreparedConfirmation {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
    },
    RolePreparedConfirmationCheck {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
        confirmation: &'pending mut PreparedRestoredAppConfirmation,
    },
    RolePreparedAcceptance {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
        confirmation: &'pending mut PreparedRestoredAppConfirmation,
        operation: RoleHandoffIo,
    },
    RoleInstalledConfirmation {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
        prepared: &'pending mut PreparedRestoredAppConfirmation,
    },
    RoleInstalledConfirmationCheck {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
        prepared: &'pending mut PreparedRestoredAppConfirmation,
        installed: &'pending mut InstalledRestoredAppConfirmation,
    },
    RoleInstalledAcceptance {
        completed: &'pending mut crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
        activation: &'pending mut ActivatedRestoredAppRole,
        prepared: &'pending mut PreparedRestoredAppConfirmation,
        installed: &'pending mut InstalledRestoredAppConfirmation,
        operation: RoleHandoffIo,
    },
}
struct IssuerFinishReply {
    kind: IssuerFinishReplyKind,
}
enum IssuerFinishReplyKind {
    Begun(crate::security_epoch::native_enrollment::IssuerRestoreFinishing),
    Step,
    Completed(crate::security_epoch::native_enrollment::CompletedRestoreIssuer),
    Progress(crate::security_epoch::native_enrollment::ReceiverProgress),
    RoleBegun(IssuerRestoreRoleActivating),
    RoleActivated(ActivatedRestoredAppRole),
    PreparedConfirmation(PreparedRestoredAppConfirmation),
    InstalledConfirmation(InstalledRestoredAppConfirmation),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RoleHandoffProgress {
    Prepare,
    Sign,
    Send,
    Poll,
    Delivered,
    Refused,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RoleHandoffIo {
    Prepare,
    Sign,
    Send,
    Poll,
}
impl RoleHandoffProgress {
    fn operation(self) -> Result<RoleHandoffIo> {
        match self {
            Self::Prepare => Ok(RoleHandoffIo::Prepare),
            Self::Sign => Ok(RoleHandoffIo::Sign),
            Self::Send => Ok(RoleHandoffIo::Send),
            Self::Poll => Ok(RoleHandoffIo::Poll),
            Self::Delivered | Self::Refused => anyhow::bail!("restore_role_handoff_not_pending"),
        }
    }

    fn after(
        self,
        operation: RoleHandoffIo,
        progress: crate::security_epoch::native_enrollment::ReceiverProgress,
    ) -> Result<Self> {
        use crate::security_epoch::native_enrollment::ReceiverProgress as P;
        ensure!(
            self.operation()? == operation,
            "restore_role_handoff_wrong_operation"
        );
        match (self, progress) {
            (Self::Prepare, P::Advanced) => Ok(Self::Sign),
            (Self::Sign, P::Advanced) => Ok(Self::Send),
            (Self::Send, P::Delivered) => Ok(Self::Delivered),
            (Self::Send, P::WouldBlock) => Ok(Self::Poll),
            (Self::Send, P::Interrupted) => Ok(Self::Send),
            (Self::Poll, P::Advanced) => Ok(Self::Send),
            (Self::Poll, P::Interrupted) => Ok(Self::Poll),
            _ => anyhow::bail!("restore_role_handoff_progress_changed"),
        }
    }
}

/// Non-serving result retaining BOTH actual installed resources and the
/// opaque native issuer lifecycle. No role, file getter or Current conversion
/// exists here; the subsequent ordinary-role/file handoff remains separate.
pub(in crate::security_epoch) struct RestoreIssuerCompletedInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    installation: RestoreControllerInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
    issuer: crate::security_epoch::native_enrollment::CompletedRestoreIssuer,
    role_handoff: Option<RoleHandoffProgress>,
}

/// Non-serving result of the fixed issuer activation and its complete actual
/// parent postcheck. The native grant drops before the retained installation.
/// This grants no App receipt, ordinary role, Runtime or file access. Only the
/// next fixed delivery may consume these SAME owners; no parts escape.
pub(in crate::security_epoch) struct RestoreAppRoleActivatedInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    activation: ActivatedRestoredAppRole,
    installation: RestoreIssuerCompletedInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

/// Only the fixed Controller socket send and its complete independent posts.
/// This is NOT App receipt, App admission, issuer retirement, an ordinary role
/// or Runtime. The same native grant and actual installation stay private.
pub(in crate::security_epoch) struct RestoreAppDecisionSentInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    installation: RestoreAppRoleActivatedInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl RestoreAppDecisionSentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        self.installation.check()
    }
}

/// Authenticated PREPARED confirmation only, retaining the SAME native receipt
/// and Controller installation. It proves neither RoleInstallPort completion,
/// ordinary role/keeper continuity nor final operator restore success.
/// The receipt's negative teardown runs before the retained parent is dropped.
pub(in crate::security_epoch) struct RestoreAppPreparedConfirmationInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    confirmation: PreparedRestoredAppConfirmation,
    installation: RestoreAppDecisionSentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreAppDecisionSentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// The fixed native receive must authenticate the actual App confirmation.
    /// Consuming this carrier forbids resuming an ambiguous receive with a new
    /// original or replacing its retained owners. The per-call loan ends before
    /// issuer_native's complete independent parent post, even on failure.
    pub(in crate::security_epoch) fn receive_prepared_app_confirmation(
        mut self,
    ) -> Result<
        RestoreAppPreparedConfirmationInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let requested =
            self.installation
                .installation
                .installation
                .issuer_native(IssuerFinishCall {
                    kind: IssuerFinishCallKind::RolePreparedConfirmation {
                        completed: &mut self.installation.installation.issuer,
                        activation: &mut self.installation.activation,
                    },
                });
        if requested.is_err() {
            self.installation.refuse();
        }
        let confirmation = match requested?.kind {
            IssuerFinishReplyKind::PreparedConfirmation(confirmation) => confirmation,
            _ => {
                self.installation.refuse();
                anyhow::bail!("restore_app_prepared_confirmation_reply_changed");
            }
        };
        // The real receipt is withheld until the FULL actual parent post has
        // succeeded. No I/O/effect occurs between that post and this carrier.
        Ok(RestoreAppPreparedConfirmationInstallation {
            confirmation,
            installation: self,
        })
    }
}

impl RestoreAppPreparedConfirmationInstallation<'_, '_, '_, '_, '_, '_, '_> {
    /// Freshly check the retained opaque receipt and SAME owners. A saved
    /// prepared confirmation is never permission for installed/serving work.
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        let checked = self
            .installation
            .installation
            .installation
            .installation
            .issuer_native(IssuerFinishCall {
                kind: IssuerFinishCallKind::RolePreparedConfirmationCheck {
                    completed: &mut self.installation.installation.installation.issuer,
                    activation: &mut self.installation.installation.activation,
                    confirmation: &mut self.confirmation,
                },
            });
        match checked {
            Ok(IssuerFinishReply {
                kind: IssuerFinishReplyKind::Step,
            }) => Ok(()),
            Ok(_) => {
                self.refuse();
                anyhow::bail!("restore_app_prepared_confirmation_check_reply_changed");
            }
            Err(error) => {
                self.refuse();
                Err(error)
            }
        }
    }

    fn refuse(&mut self) {
        self.confirmation.refuse();
        self.installation.installation.refuse();
    }
}

/// The fixed Controller acceptance was sent and independently postchecked.
/// This is not an App installation/continuity acknowledgement, ordinary role
/// or final restore success. The same receipt and installation remain private.
pub(in crate::security_epoch) struct RestoreControllerAcceptanceSentInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    installation: RestoreAppPreparedConfirmationInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreAppPreparedConfirmationInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// This carrier can exist only after the actual App prepared ACK and full
    /// parent post. Every possible acceptance send again runs the complete
    /// actual parent pre/post under the same sole loan and original owners.
    /// Transport continuation resends only the native retained same packet.
    pub(in crate::security_epoch) fn send_controller_acceptance(
        mut self,
    ) -> Result<
        RestoreControllerAcceptanceSentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let mut state = RoleHandoffProgress::Send;
        loop {
            if state == RoleHandoffProgress::Delivered {
                break;
            }
            let operation = state.operation()?;
            let requested = self
                .installation
                .installation
                .installation
                .installation
                .issuer_native(IssuerFinishCall {
                    kind: IssuerFinishCallKind::RolePreparedAcceptance {
                        completed: &mut self.installation.installation.installation.issuer,
                        activation: &mut self.installation.installation.activation,
                        confirmation: &mut self.confirmation,
                        operation,
                    },
                });
            if requested.is_err() {
                self.refuse();
            }
            let progress = match requested?.kind {
                IssuerFinishReplyKind::Progress(progress) => progress,
                _ => {
                    self.refuse();
                    anyhow::bail!("restore_controller_acceptance_reply_changed");
                }
            };
            let next = state.after(operation, progress);
            if next.is_err() {
                self.refuse();
            }
            state = next?;
        }
        // Recheck the actual native confirmation and full parent after any
        // possible socket send, not just the saved local transport state.
        self.check()?;
        Ok(RestoreControllerAcceptanceSentInstallation { installation: self })
    }
}

impl RestoreControllerAcceptanceSentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        self.installation.check()
    }

    fn check_installed_confirmation(
        &mut self,
        installed: &mut InstalledRestoredAppConfirmation,
    ) -> Result<()> {
        let checked = self
            .installation
            .installation
            .installation
            .installation
            .installation
            .issuer_native(IssuerFinishCall {
                kind: IssuerFinishCallKind::RoleInstalledConfirmationCheck {
                    completed: &mut self
                        .installation
                        .installation
                        .installation
                        .installation
                        .issuer,
                    activation: &mut self.installation.installation.installation.activation,
                    prepared: &mut self.installation.confirmation,
                    installed,
                },
            });
        match checked {
            Ok(IssuerFinishReply {
                kind: IssuerFinishReplyKind::Step,
            }) => Ok(()),
            Ok(_) => {
                installed.refuse();
                self.installation.refuse();
                anyhow::bail!("restore_installed_confirmation_check_reply_changed");
            }
            Err(error) => {
                installed.refuse();
                self.installation.refuse();
                Err(error)
            }
        }
    }
}

/// A real native installed/continuity receipt and its fresh full parent posts.
/// This neither retires the issuer nor constructs final operator success. The
/// installed receipt drops before the same prepared/acceptance/parent lineage.
pub(in crate::security_epoch) struct RestoreAppInstalledConfirmationInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    installed: InstalledRestoredAppConfirmation,
    installation: RestoreControllerAcceptanceSentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreControllerAcceptanceSentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// Consumes the actual postchecked acceptance. A new receipt is withheld
    /// through both the receive and a separate fresh same-receipt check, each
    /// using the sole short loan and complete independent parent pre/post.
    pub(in crate::security_epoch) fn receive_installed_app_confirmation(
        mut self,
    ) -> Result<
        RestoreAppInstalledConfirmationInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let requested = self
            .installation
            .installation
            .installation
            .installation
            .installation
            .issuer_native(IssuerFinishCall {
                kind: IssuerFinishCallKind::RoleInstalledConfirmation {
                    completed: &mut self
                        .installation
                        .installation
                        .installation
                        .installation
                        .issuer,
                    activation: &mut self.installation.installation.installation.activation,
                    prepared: &mut self.installation.confirmation,
                },
            });
        if requested.is_err() {
            self.installation.refuse();
        }
        let mut installed = match requested?.kind {
            IssuerFinishReplyKind::InstalledConfirmation(installed) => installed,
            _ => {
                self.installation.refuse();
                anyhow::bail!("restore_installed_confirmation_reply_changed");
            }
        };
        self.check_installed_confirmation(&mut installed)?;
        // No I/O/effect/wait follows the final actual native + FULL parent
        // check before this sole owning result construction.
        Ok(RestoreAppInstalledConfirmationInstallation {
            installed,
            installation: self,
        })
    }
}

impl RestoreAppInstalledConfirmationInstallation<'_, '_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        self.installation
            .check_installed_confirmation(&mut self.installed)
    }

    /// Only the actual installed receipt may send its distinct acceptance.
    /// Each native send/poll uses the existing sole short loan and independent
    /// full resource post. Delivered here means the fixed packet was sent,
    /// not that an ordinary App/Controller Current or restore result exists.
    fn send_installed_acceptance(&mut self) -> Result<()> {
        let mut state = RoleHandoffProgress::Send;
        loop {
            if state == RoleHandoffProgress::Delivered {
                break;
            }
            let operation = state.operation()?;
            let requested = self
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .issuer_native(IssuerFinishCall {
                    kind: IssuerFinishCallKind::RoleInstalledAcceptance {
                        completed: &mut self
                            .installation
                            .installation
                            .installation
                            .installation
                            .installation
                            .issuer,
                        activation: &mut self
                            .installation
                            .installation
                            .installation
                            .installation
                            .activation,
                        prepared: &mut self.installation.installation.confirmation,
                        installed: &mut self.installed,
                        operation,
                    },
                });
            if requested.is_err() {
                self.refuse();
            }
            let progress = match requested?.kind {
                IssuerFinishReplyKind::Progress(progress) => progress,
                _ => {
                    self.refuse();
                    anyhow::bail!("restore_installed_acceptance_reply_changed");
                }
            };
            let next = state.after(operation, progress);
            if next.is_err() {
                self.refuse();
            }
            state = next?;
        }
        Ok(())
    }

    fn refuse(&mut self) {
        self.installed.refuse();
        self.installation.installation.refuse();
    }
}

/// Consumes the WHOLE genuine post-ACK carrier, keeping every existing borrow
/// and negative receipt. This is not an owned ordinary Controller continuity.
/// The fixed native_current child may borrow its exact fields, with full
/// checks before and after each short native scope; no parts escape this loan.
pub(in crate::security_epoch) struct ControllerCurrentInstallationLoan<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    installation: RestoreAppInstalledConfirmationInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreAppInstalledConfirmationInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// A move of the actual carrier only. Native prepare still checks the
    /// still-live original; this neither refreshes permission nor closes any
    /// borrowed physical/counter owner or returns an ActiveController.
    pub(in crate::security_epoch) fn into_controller_current_loan(
        self,
    ) -> ControllerCurrentInstallationLoan<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    > {
        ControllerCurrentInstallationLoan { installation: self }
    }

    /// Begin the fixed native join under the genuine installed carrier. The
    /// result retains every scoped borrow and cannot be an ordinary owner.
    pub(in crate::security_epoch) fn prepare_controller_current(
        self,
    ) -> Result<
        PendingControllerCurrentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        PendingControllerCurrentInstallation::prepare(self.into_controller_current_loan())
    }
}

impl ControllerCurrentInstallationLoan<'_, '_, '_, '_, '_, '_, '_> {
    fn send_installed_acceptance(&mut self) -> Result<()> {
        let requested = self.installation.send_installed_acceptance();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    fn check(&mut self) -> Result<()> {
        let checked = self.installation.check();
        if checked.is_err() {
            self.refuse();
        }
        checked
    }

    fn refuse(&mut self) {
        self.installation.installed.refuse();
        self.installation.installation.installation.refuse();
    }
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreAppRoleActivatedInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// Consuming the carrier prevents retry after loss/unwind. The shared
    /// issuer_native entry retires its ACTUAL installation before each check,
    /// preparation, signature, possible send or bounded wait. The local enum
    /// controls only the fixed same-packet transport continuation.
    pub(in crate::security_epoch) fn send_app_decision(
        mut self,
    ) -> Result<
        RestoreAppDecisionSentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let mut state = RoleHandoffProgress::Prepare;
        loop {
            if state == RoleHandoffProgress::Delivered {
                break;
            }
            let operation = state.operation()?;
            let requested = self
                .installation
                .installation
                .issuer_native(IssuerFinishCall {
                    kind: IssuerFinishCallKind::RoleDecision {
                        completed: &mut self.installation.issuer,
                        activation: &mut self.activation,
                        operation,
                    },
                });
            if requested.is_err() {
                self.refuse();
            }
            let progress = match requested?.kind {
                IssuerFinishReplyKind::Progress(progress) => progress,
                _ => {
                    self.refuse();
                    anyhow::bail!("restore_app_decision_reply_changed");
                }
            };
            let next = state.after(operation, progress);
            if next.is_err() {
                self.refuse();
            }
            state = next?;
        }
        // Independent actual grant + FULL resource post after the possible
        // send. A unit result or saved grant cannot skip this last check.
        self.check()?;
        Ok(RestoreAppDecisionSentInstallation { installation: self })
    }
}

impl RestoreAppRoleActivatedInstallation<'_, '_, '_, '_, '_, '_, '_> {
    /// A fresh check, not cached activation permission or an App delivery claim.
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        let checked = self
            .installation
            .installation
            .issuer_native(IssuerFinishCall {
                kind: IssuerFinishCallKind::RoleActivationCheck {
                    completed: &mut self.installation.issuer,
                    activation: &mut self.activation,
                },
            });
        match checked {
            Ok(IssuerFinishReply {
                kind: IssuerFinishReplyKind::Step,
            }) => Ok(()),
            Ok(_) => {
                self.refuse();
                anyhow::bail!("restore_app_role_check_reply_changed");
            }
            Err(error) => {
                self.refuse();
                Err(error)
            }
        }
    }

    fn refuse(&mut self) {
        self.activation.refuse();
        self.installation.refuse();
    }
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreIssuerCompletedInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// Actual RoleReady delivery and its independent full final post MUST
    /// precede this consuming transition. Packet receipt and saved completion
    /// DATA are insufficient. Every native step uses the sole existing loan.
    pub(in crate::security_epoch) fn activate_app_role(
        mut self,
    ) -> Result<
        RestoreAppRoleActivatedInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let delivered = self.role_handoff == Some(RoleHandoffProgress::Delivered);
        // Retire before the first check, native call or possible unwind. The
        // old completed-installation entry cannot be reused after this point.
        self.role_handoff = Some(RoleHandoffProgress::Refused);
        if !delivered {
            self.refuse();
            anyhow::bail!("restore_app_role_requires_postchecked_delivery");
        }
        let begun = self.installation.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::RoleActivationBegin {
                completed: &mut self.issuer,
            },
        });
        if begun.is_err() {
            self.refuse();
        }
        let mut pending = match begun?.kind {
            IssuerFinishReplyKind::RoleBegun(pending) => pending,
            _ => {
                self.refuse();
                anyhow::bail!("restore_app_role_begin_reply_changed");
            }
        };
        for step in [
            IssuerRoleActivationStep::Hello,
            IssuerRoleActivationStep::Nonce,
            IssuerRoleActivationStep::Bind,
            IssuerRoleActivationStep::Grant,
        ] {
            let requested = self.installation.issuer_native(IssuerFinishCall {
                kind: IssuerFinishCallKind::RoleActivationStep {
                    completed: &mut self.issuer,
                    pending: &mut pending,
                    step,
                },
            });
            if requested.is_err() {
                self.refuse();
            }
            if !matches!(requested?.kind, IssuerFinishReplyKind::Step) {
                self.refuse();
                anyhow::bail!("restore_app_role_step_reply_changed");
            }
        }
        let requested = self.installation.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::RoleActivationFinish {
                completed: &mut self.issuer,
                pending,
            },
        });
        if requested.is_err() {
            self.refuse();
        }
        let activation = match requested?.kind {
            IssuerFinishReplyKind::RoleActivated(activation) => activation,
            _ => {
                self.refuse();
                anyhow::bail!("restore_app_role_finish_reply_changed");
            }
        };
        // issuer_native evaluated the FULL actual parent post before making
        // this opaque grant available. No I/O/wait/effect intervenes here.
        Ok(RestoreAppRoleActivatedInstallation {
            activation,
            installation: self,
        })
    }
}

impl RestoreIssuerCompletedInstallation<'_, '_, '_, '_, '_, '_, '_> {
    /// This is a fresh check of the actual retained terminal and physical
    /// installation, not permission cached by the earlier successful exchange.
    /// Every later real transition still has to consume these same owners.
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        if self
            .role_handoff
            .is_some_and(|state| state != RoleHandoffProgress::Delivered)
        {
            self.refuse();
            anyhow::bail!("restore_role_handoff_not_complete");
        }
        let checked = self.installation.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::Check(&mut self.issuer),
        });
        match checked {
            Ok(IssuerFinishReply {
                kind: IssuerFinishReplyKind::Step,
            }) => Ok(()),
            Ok(_) => {
                self.refuse();
                anyhow::bail!("restore_issuer_check_reply_changed");
            }
            Err(error) => {
                self.refuse();
                Err(error)
            }
        }
    }

    fn refuse(&mut self) {
        self.role_handoff = Some(RoleHandoffProgress::Refused);
        self.installation.refuse();
    }

    /// Completes only the fixed RoleReady send and its independent posts. This
    /// does not assert App receipt, ordinary-role admission, Runtime or Current.
    /// The actual App must retain/check its own FIRST keeper and authority.
    pub(in crate::security_epoch) fn release_app_role(&mut self) -> Result<()> {
        if self.role_handoff.is_some() {
            self.refuse();
            anyhow::bail!("restore_role_handoff_attempt_spent");
        }
        self.role_handoff = Some(RoleHandoffProgress::Prepare);
        loop {
            let state = self.role_handoff.context("restore_role_handoff_missing")?;
            if state == RoleHandoffProgress::Delivered {
                break;
            }
            self.role_handoff_operation(state.operation()?)?;
        }
        // Retire again before the final independent actual-terminal check. A
        // caught unwind or failed final post cannot repeat the possible send.
        self.role_handoff = Some(RoleHandoffProgress::Refused);
        let checked = self.installation.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::Check(&mut self.issuer),
        });
        let result = match checked {
            Ok(IssuerFinishReply {
                kind: IssuerFinishReplyKind::Step,
            }) => Ok(()),
            Ok(_) => Err(anyhow::anyhow!("restore_role_handoff_final_reply_changed")),
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.refuse();
        }
        result?;
        self.role_handoff = Some(RoleHandoffProgress::Delivered);
        Ok(())
    }

    fn role_handoff_operation(&mut self, operation: RoleHandoffIo) -> Result<()> {
        let prior = self.role_handoff;
        self.role_handoff = Some(RoleHandoffProgress::Refused);
        let entered: Result<_> = (|| {
            let state = prior.context("restore_role_handoff_missing")?;
            ensure!(
                state.operation()? == operation,
                "restore_role_handoff_actual_order"
            );
            Ok(state)
        })();
        if entered.is_err() {
            self.refuse();
        }
        let state = entered?;
        let requested = self.installation.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::RoleHandoff {
                completed: &mut self.issuer,
                operation,
            },
        });
        let progress = match requested {
            Ok(IssuerFinishReply {
                kind: IssuerFinishReplyKind::Progress(progress),
            }) => Ok(progress),
            Ok(_) => Err(anyhow::anyhow!("restore_role_handoff_reply_changed")),
            Err(error) => Err(error),
        };
        if progress.is_err() {
            self.refuse();
        }
        let next = state.after(operation, progress?);
        if next.is_err() {
            self.refuse();
        }
        self.role_handoff = Some(next?);
        Ok(())
    }
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    RestoreControllerInstallation<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
{
    pub(in crate::security_epoch) fn finish_issuer(
        mut self,
    ) -> Result<
        RestoreIssuerCompletedInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let reply = self.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::Begin,
        })?;
        let mut pending = match reply.kind {
            IssuerFinishReplyKind::Begun(pending) => pending,
            _ => {
                self.refuse();
                anyhow::bail!("restore_issuer_begin_reply_changed");
            }
        };
        for step in [
            IssuerFinishStep::Hello,
            IssuerFinishStep::Nonce,
            IssuerFinishStep::Sign,
            IssuerFinishStep::Bind,
            IssuerFinishStep::Grant,
        ] {
            let reply = self.issuer_native(IssuerFinishCall {
                kind: IssuerFinishCallKind::Step {
                    pending: &mut pending,
                    step,
                },
            })?;
            if !matches!(reply.kind, IssuerFinishReplyKind::Step) {
                self.refuse();
                anyhow::bail!("restore_issuer_step_reply_changed");
            }
        }
        let reply = self.issuer_native(IssuerFinishCall {
            kind: IssuerFinishCallKind::Finish(pending),
        })?;
        let issuer = match reply.kind {
            IssuerFinishReplyKind::Completed(issuer) => issuer,
            _ => {
                self.refuse();
                anyhow::bail!("restore_issuer_final_reply_changed");
            }
        };
        // Native finish and its actual full independent resource post have
        // completed before this sole positive result constructor.
        Ok(RestoreIssuerCompletedInstallation {
            installation: self,
            issuer,
            role_handoff: None,
        })
    }
}

impl RestoreControllerInstallation<'_, '_, '_, '_, '_, '_, '_> {
    fn issuer_native(&mut self, call: IssuerFinishCall<'_>) -> Result<IssuerFinishReply> {
        let (expected, next) = match &call.kind {
            IssuerFinishCallKind::Begin => {
                (IssuerFinishProgress::Fresh, IssuerFinishProgress::Hello)
            }
            IssuerFinishCallKind::Step { step, .. } => step.progress(),
            IssuerFinishCallKind::Finish(_) => (
                IssuerFinishProgress::Finish,
                IssuerFinishProgress::Completed,
            ),
            IssuerFinishCallKind::Check(_) => (
                IssuerFinishProgress::Completed,
                IssuerFinishProgress::Completed,
            ),
            IssuerFinishCallKind::RoleHandoff { .. } => (
                IssuerFinishProgress::Completed,
                IssuerFinishProgress::Completed,
            ),
            IssuerFinishCallKind::RoleActivationBegin { .. } => (
                IssuerFinishProgress::Completed,
                IssuerFinishProgress::RoleHello,
            ),
            IssuerFinishCallKind::RoleActivationStep { step, .. } => step.progress(),
            IssuerFinishCallKind::RoleActivationFinish { .. } => (
                IssuerFinishProgress::RoleFinish,
                IssuerFinishProgress::RoleActivated,
            ),
            IssuerFinishCallKind::RoleActivationCheck { .. } => (
                IssuerFinishProgress::RoleActivated,
                IssuerFinishProgress::RoleActivated,
            ),
            IssuerFinishCallKind::RoleDecision { .. } => (
                IssuerFinishProgress::RoleActivated,
                IssuerFinishProgress::RoleActivated,
            ),
            IssuerFinishCallKind::RolePreparedConfirmation { .. }
            | IssuerFinishCallKind::RolePreparedConfirmationCheck { .. }
            | IssuerFinishCallKind::RolePreparedAcceptance { .. }
            | IssuerFinishCallKind::RoleInstalledConfirmation { .. }
            | IssuerFinishCallKind::RoleInstalledConfirmationCheck { .. }
            | IssuerFinishCallKind::RoleInstalledAcceptance { .. } => (
                IssuerFinishProgress::RoleActivated,
                IssuerFinishProgress::RoleActivated,
            ),
        };
        let prior = self.issuer_progress;
        self.issuer_progress = IssuerFinishProgress::Busy;
        let entered: Result<()> = (|| {
            ensure!(
                prior == expected,
                "restore_issuer_actual_installation_order"
            );
            self.frame.check_completed_resources()
        })();
        if entered.is_err() {
            self.refuse();
        }
        entered?;
        let requested: Result<_> = (|| {
            let owner = &mut *self.frame.confirmation.owner;
            let physical = owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut storage = physical.controller_stage()?.storage()?;
            // Sole ctor, from THIS actual consuming installation only. The
            // peer is a distinct real borrow passed directly to native code.
            let mut loan = RestoreFinalInstallationLoan {
                original: &mut owner.auth.original,
                approval: &owner.auth.record.statement.request,
                operation: &owner.auth.operation,
                known: &self.frame.confirmation.known,
                plan: &self.frame.confirmation.plan,
                creator: &self.frame.creator,
                report: &self.frame.confirmation.target,
                target: self.frame.target,
                cohort: self
                    .frame
                    .cohort
                    .as_mut()
                    .context("restore_release_cohort_missing")?,
                refused: &owner.refused,
                _lost: LostRestoreWriterConfirmation {
                    refused: Rc::clone(&owner.refused),
                },
            };
            let kind = match call.kind {
                IssuerFinishCallKind::Begin => IssuerFinishReplyKind::Begun(
                    owner
                        .issuer
                        .begin_finish_restore(&mut storage, self.frame.peer, &mut loan)?,
                ),
                IssuerFinishCallKind::Step { pending, step } => {
                    match step {
                        IssuerFinishStep::Hello => {
                            pending.send_hello(&mut storage, self.frame.peer, &mut loan)?
                        }
                        IssuerFinishStep::Nonce => {
                            pending.receive_nonce(&mut storage, self.frame.peer, &mut loan)?
                        }
                        IssuerFinishStep::Sign => {
                            pending.sign_bind(&mut storage, self.frame.peer, &mut loan)?
                        }
                        IssuerFinishStep::Bind => {
                            pending.send_bind(&mut storage, self.frame.peer, &mut loan)?
                        }
                        IssuerFinishStep::Grant => {
                            pending.receive_grant(&mut storage, self.frame.peer, &mut loan)?
                        }
                    }
                    IssuerFinishReplyKind::Step
                }
                IssuerFinishCallKind::Finish(pending) => IssuerFinishReplyKind::Completed(
                    pending.finish(&mut storage, self.frame.peer, &mut loan)?,
                ),
                IssuerFinishCallKind::Check(completed) => {
                    completed.check(&mut storage, self.frame.peer, &mut loan)?;
                    IssuerFinishReplyKind::Step
                }
                IssuerFinishCallKind::RoleHandoff {
                    completed,
                    operation,
                } => {
                    use crate::security_epoch::native_enrollment::ReceiverProgress as P;
                    let progress = match operation {
                        RoleHandoffIo::Prepare => {
                            self.frame.peer.prepare_role_handoff(
                                &mut storage,
                                completed,
                                &mut loan,
                            )?;
                            P::Advanced
                        }
                        RoleHandoffIo::Sign => {
                            self.frame.peer.sign_role_handoff(
                                &mut storage,
                                completed,
                                &mut loan,
                            )?;
                            P::Advanced
                        }
                        RoleHandoffIo::Send => self.frame.peer.try_send_role_handoff(
                            &mut storage,
                            completed,
                            &mut loan,
                        )?,
                        RoleHandoffIo::Poll => {
                            self.frame
                                .peer
                                .poll_role_handoff(&mut storage, completed, &mut loan)?
                        }
                    };
                    IssuerFinishReplyKind::Progress(progress)
                }
                IssuerFinishCallKind::RoleActivationBegin { completed } => {
                    IssuerFinishReplyKind::RoleBegun(completed.begin_app_role_activation(
                        &mut storage,
                        self.frame.peer,
                        &mut loan,
                    )?)
                }
                IssuerFinishCallKind::RoleActivationStep {
                    completed,
                    pending,
                    step,
                } => {
                    match step {
                        IssuerRoleActivationStep::Hello => pending.send_hello(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            &mut loan,
                        )?,
                        IssuerRoleActivationStep::Nonce => pending.receive_nonce(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            &mut loan,
                        )?,
                        IssuerRoleActivationStep::Bind => pending.send_bind(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            &mut loan,
                        )?,
                        IssuerRoleActivationStep::Grant => pending.receive_grant(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            &mut loan,
                        )?,
                    }
                    IssuerFinishReplyKind::Step
                }
                IssuerFinishCallKind::RoleActivationFinish { completed, pending } => {
                    IssuerFinishReplyKind::RoleActivated(pending.finish(
                        &mut storage,
                        self.frame.peer,
                        completed,
                        &mut loan,
                    )?)
                }
                IssuerFinishCallKind::RoleActivationCheck {
                    completed,
                    activation,
                } => {
                    activation.check(&mut storage, self.frame.peer, completed, &mut loan)?;
                    IssuerFinishReplyKind::Step
                }
                IssuerFinishCallKind::RoleDecision {
                    completed,
                    activation,
                    operation,
                } => {
                    use crate::security_epoch::native_enrollment::ReceiverProgress as P;
                    let progress = match operation {
                        RoleHandoffIo::Prepare => {
                            self.frame.peer.prepare_role_decision(
                                &mut storage,
                                completed,
                                activation,
                                &mut loan,
                            )?;
                            P::Advanced
                        }
                        RoleHandoffIo::Sign => {
                            self.frame.peer.sign_role_decision(
                                &mut storage,
                                completed,
                                activation,
                                &mut loan,
                            )?;
                            P::Advanced
                        }
                        RoleHandoffIo::Send => self.frame.peer.try_send_role_decision(
                            &mut storage,
                            completed,
                            activation,
                            &mut loan,
                        )?,
                        RoleHandoffIo::Poll => self.frame.peer.poll_role_decision(
                            &mut storage,
                            completed,
                            activation,
                            &mut loan,
                        )?,
                    };
                    IssuerFinishReplyKind::Progress(progress)
                }
                IssuerFinishCallKind::RolePreparedConfirmation {
                    completed,
                    activation,
                } => IssuerFinishReplyKind::PreparedConfirmation(
                    activation.receive_app_confirmation(
                        &mut storage,
                        self.frame.peer,
                        completed,
                        &mut loan,
                    )?,
                ),
                IssuerFinishCallKind::RolePreparedConfirmationCheck {
                    completed,
                    activation,
                    confirmation,
                } => {
                    confirmation.check(
                        &mut storage,
                        self.frame.peer,
                        completed,
                        activation,
                        &mut loan,
                    )?;
                    IssuerFinishReplyKind::Step
                }
                IssuerFinishCallKind::RolePreparedAcceptance {
                    completed,
                    activation,
                    confirmation,
                    operation,
                } => {
                    let progress = match operation {
                        RoleHandoffIo::Send => confirmation.try_send_acceptance(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            activation,
                            &mut loan,
                        )?,
                        RoleHandoffIo::Poll => confirmation.poll_acceptance(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            activation,
                            &mut loan,
                        )?,
                        RoleHandoffIo::Prepare | RoleHandoffIo::Sign => {
                            anyhow::bail!("restore_controller_acceptance_wrong_operation")
                        }
                    };
                    IssuerFinishReplyKind::Progress(progress)
                }
                IssuerFinishCallKind::RoleInstalledConfirmation {
                    completed,
                    activation,
                    prepared,
                } => IssuerFinishReplyKind::InstalledConfirmation(
                    prepared.receive_installed_confirmation(
                        &mut storage,
                        self.frame.peer,
                        completed,
                        activation,
                        &mut loan,
                    )?,
                ),
                IssuerFinishCallKind::RoleInstalledConfirmationCheck {
                    completed,
                    activation,
                    prepared,
                    installed,
                } => {
                    installed.check(
                        &mut storage,
                        self.frame.peer,
                        completed,
                        activation,
                        prepared,
                        &mut loan,
                    )?;
                    IssuerFinishReplyKind::Step
                }
                IssuerFinishCallKind::RoleInstalledAcceptance {
                    completed,
                    activation,
                    prepared,
                    installed,
                    operation,
                } => {
                    let progress = match operation {
                        RoleHandoffIo::Send => installed.try_send_acceptance(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            activation,
                            prepared,
                            &mut loan,
                        )?,
                        RoleHandoffIo::Poll => installed.poll_acceptance(
                            &mut storage,
                            self.frame.peer,
                            completed,
                            activation,
                            prepared,
                            &mut loan,
                        )?,
                        RoleHandoffIo::Prepare | RoleHandoffIo::Sign => {
                            anyhow::bail!("restore_installed_acceptance_wrong_operation")
                        }
                    };
                    IssuerFinishReplyKind::Progress(progress)
                }
            };
            Ok(IssuerFinishReply { kind })
        })();
        // No native stage or loan borrow crosses this independent FULL
        // Known/UV/key/provider/native and physical-cohort post, even on Err.
        let checked = self.frame.check_completed_resources();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let reply = requested?;
        checked?;
        self.issuer_progress = next;
        Ok(reply)
    }
}

impl RestoreWriterActivated<'_, '_, '_, '_, '_, '_, '_> {
    fn check_completed_resources(&mut self) -> Result<()> {
        let prior = self.release;
        self.release = Some(ReleaseProgress::Refused);
        let entered: Result<()> = (|| {
            ensure!(
                prior == Some(ReleaseProgress::Delivered)
                    && self.progress == ActivationProgress::Acknowledged
                    && self.release_started
                    && self.cohort.is_some(),
                "restore_controller_installation_not_complete"
            );
            self.check(false)
        })();
        // Separate cohort post runs even when the full Known/native/UV/key
        // check refused. Retire-before-check also closes a caught unwind.
        let physical = self.check_cohort();
        if entered.is_err() || physical.is_err() {
            self.refuse();
        }
        entered?;
        physical?;
        self.release = Some(ReleaseProgress::Delivered);
        Ok(())
    }

    /// Complete only the authenticated keeper-release exchange. The SAME
    /// frame/resources remain held; this returns no serving owner. The final
    /// consuming Controller/file/issuer installation remains a separate step.
    pub(in crate::security_epoch) fn release_keeper(&mut self) -> Result<()> {
        self.pin_release_cohort()?;
        if self.release.is_some() {
            self.refuse();
            anyhow::bail!("restore_release_dispatch_spent");
        }
        self.release = Some(ReleaseProgress::Prepare);
        loop {
            let state = self.release.context("restore_release_missing")?;
            if state == ReleaseProgress::Delivered {
                break;
            }
            self.release_operation(state.operation()?)?;
        }
        self.release = Some(ReleaseProgress::Refused);
        let checked = self.check(false);
        let cohort = self.check_cohort();
        if checked.is_err() || cohort.is_err() {
            self.refuse();
        }
        checked?;
        cohort?;
        self.release = Some(ReleaseProgress::Delivered);
        Ok(())
    }

    fn check_cohort(&mut self) -> Result<()> {
        self.cohort
            .as_mut()
            .context("restore_release_cohort_missing")?
            .check(self.target, &self.creator, &self.confirmation.target)
            .map(|_| ())
    }

    fn release_operation(&mut self, operation: ReleaseIo) -> Result<()> {
        let state = self.release.context("restore_release_missing")?;
        // Retire before ANY fallible precheck, not just before send. A caught
        // unwind or ambiguous syscall never re-enters this actual operation.
        self.release = Some(ReleaseProgress::Refused);
        let entered: Result<()> = (|| {
            ensure!(
                self.progress == ActivationProgress::Acknowledged
                    && self.release_started
                    && self.cohort.is_some(),
                "restore_release_actual_ack_frame_required"
            );
            ensure!(
                state.operation()? == operation,
                "restore_release_wrong_operation"
            );
            self.check(false)
        })();
        if entered.is_err() {
            self.refuse();
        }
        entered?;
        let requested: Result<_> = (|| {
            let owner = &mut *self.confirmation.owner;
            let physical = owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut storage = physical.controller_stage()?.storage()?;
            // Sole genuine constructor: all resources are actual fields of
            // THIS same completed ACK frame, never caller DATA or new handles.
            let mut loan = RestoreWriterReleaseLoan {
                original: &mut owner.auth.original,
                approval: &owner.auth.record.statement.request,
                operation: &owner.auth.operation,
                known: &self.confirmation.known,
                plan: &self.confirmation.plan,
                creator: &self.creator,
                report: &self.confirmation.target,
                target: self.target,
                cohort: self
                    .cohort
                    .as_mut()
                    .context("restore_release_cohort_missing")?,
                refused: &owner.refused,
                _lost: LostRestoreWriterConfirmation {
                    refused: Rc::clone(&owner.refused),
                },
            };
            match operation {
                ReleaseIo::Prepare => {
                    self.peer.prepare_released(&mut storage, &mut loan)?;
                    Ok(crate::security_epoch::native_enrollment::ReceiverProgress::Advanced)
                }
                ReleaseIo::Sign => {
                    self.peer.sign_released(&mut storage, &mut loan)?;
                    Ok(crate::security_epoch::native_enrollment::ReceiverProgress::Advanced)
                }
                ReleaseIo::Send => self.peer.try_send_released(&mut storage, &mut loan),
                ReleaseIo::Poll => self.peer.poll_release(&mut storage, &mut loan),
            }
        })();
        // Short actual native loan/stage have ended. Always independently
        // check current authority and physical cohort, even on primary error.
        let checked = self.check(false);
        let cohort = self.check_cohort();
        if requested.is_err() || checked.is_err() || cohort.is_err() {
            self.refuse();
        }
        let progress = requested?;
        checked?;
        cohort?;
        let next = state.after(operation, progress);
        if next.is_err() {
            self.refuse();
        }
        self.release = Some(next?);
        Ok(())
    }

    /// Only the actual completed keeper-ACK frame can collect Controller
    /// pins. Entry is spent before full checks or descriptor IO, and the same
    /// actual owner is retained on success. No recapture follows uncertainty.
    fn pin_release_cohort(&mut self) -> Result<()> {
        let prior = self.progress;
        self.progress = ActivationProgress::Refused;
        let entered: Result<()> = (|| {
            ensure!(
                prior == ActivationProgress::Acknowledged
                    && self.cohort.is_none()
                    && !std::mem::replace(&mut self.release_started, true),
                "restore_release_entry_spent"
            );
            self.check(false)
        })();
        if entered.is_err() {
            self.refuse();
        }
        entered?;
        let requested = self.confirmation.owner.capture_release_cohort(
            self.target,
            &self.creator,
            &self.confirmation.target,
        );
        let checked = self.check(false);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let cohort = requested?;
        checked?;
        self.cohort = Some(cohort);
        self.progress = ActivationProgress::Acknowledged;
        Ok(())
    }

    fn check(&mut self, frozen: bool) -> Result<()> {
        let expected = WriterConfirmationData {
            known: &self.confirmation.known,
            request: &self.confirmation.request,
            plan: &self.confirmation.plan,
            report: &self.confirmation.target,
            holder: &self.confirmation.holder,
        };
        if frozen {
            self.confirmation.owner.check_writer_after_cas_inner(
                &expected,
                self.target,
                self.peer,
            )?;
            // The creator capture is immutable from preparation, not a new
            // authority. Compare a fresh actual sample before possible send.
            let fresh = self
                .confirmation
                .owner
                .capture_activation_creator(self.target)?;
            require_activation_creator(&self.creator, &fresh)
        } else {
            self.confirmation.owner.check_writer_active_inner(
                &expected,
                self.target,
                self.peer,
                &self.creator,
            )
        }
    }

    fn operation(&mut self, operation: ActivationIo) -> Result<()> {
        let state = self.progress;
        // Retire entry before ANY fallible parent check as well as IO. A
        // caught unwind cannot make this same frame checkable again.
        self.progress = ActivationProgress::Refused;
        let entered: Result<()> = (|| {
            ensure!(
                self.confirmation.owner.refused.get(),
                "restore_activation_parent_not_retained"
            );
            ensure!(
                state.operation()? == operation,
                "restore_activation_wrong_operation"
            );
            self.check(state == ActivationProgress::FirstSend)
        })();
        if entered.is_err() {
            self.refuse();
        }
        entered?;
        // After this point the App may already have received Activated even
        // before the syscall returns. Never hash the frozen MAIN again.
        let requested = (|| {
            let owner = &mut *self.confirmation.owner;
            let selected = &owner.auth.action.reader.loan.selection;
            let physical = owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut storage = physical.controller_stage()?.storage()?;
            let mut loan = RestoreWriterActivationLoan {
                original: &mut owner.auth.original,
                approval: &owner.auth.record.statement.request,
                operation: &owner.auth.operation,
                selected,
                known: &self.confirmation.known,
                request: &self.confirmation.request,
                plan: &self.confirmation.plan,
                creator: &self.creator,
                refused: &owner.refused,
                _lost: LostRestoreWriterConfirmation {
                    refused: Rc::clone(&owner.refused),
                },
            };
            match operation {
                ActivationIo::Send => self.peer.try_send_activated(&mut storage, &mut loan),
                ActivationIo::Poll => self.peer.poll_activation(&mut storage, &mut loan),
                ActivationIo::ReceiveAck => {
                    self.peer.try_receive_keeper_ack(&mut storage, &mut loan)
                }
            }
        })();
        // Short stage/loan is closed before the independent full authority,
        // peer and physical-owner postcheck, including on an actual IO error.
        let checked = self.check(false);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let observed = requested?;
        checked?;
        let next = state.after(operation, observed);
        if next.is_err() {
            self.refuse();
        }
        self.progress = next?;
        Ok(())
    }

    fn receive_ack(&mut self) -> Result<()> {
        while self.progress != ActivationProgress::Acknowledged {
            let operation = self.progress.operation()?;
            self.operation(operation)?;
        }
        // A final independent current read precedes exposing this actual
        // retained ACK frame; no raw ACK or historical Applied DATA escapes.
        let checked = self.check(false);
        if checked.is_err() {
            self.refuse();
        }
        checked
    }

    fn refuse(&mut self) {
        self.progress = ActivationProgress::Refused;
        self.release = Some(ReleaseProgress::Refused);
        self.target.refuse();
        self.peer.refuse();
        self.confirmation.refuse();
    }
}

// A closed compile-time protocol choice, never request DATA or permission.
enum RestorePreparationStep {
    Hello,
    Nonce,
    Sign,
    Bind,
    Grant,
}

enum ReceiverStep {
    Send,
    Receive,
    Poll,
}

// A negative-only, nongeneric Drop owner. A lost loan irreversibly refuses
// the exact still-retained continuation, including after its last good check.
struct LostRestoreLoan {
    refused: Rc<Cell<bool>>,
}

impl Drop for LostRestoreLoan {
    fn drop(&mut self) {
        self.refused.set(true);
    }
}

/// Fixed post-fence policy loan, created only while borrowing the actual
/// known-CAS owner. The Active reader's freshness path is not reused or widened.
pub(crate) struct FencedReadUnit<'borrow, 'storage, 'role> {
    loan: &'borrow mut ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'borrow crate::store::InitialStoreMetadata,
    expected: &'borrow kernel::Snapshot,
}

impl FencedReadUnit<'_, '_, '_> {
    pub(crate) fn check_current(&mut self) -> Result<()> {
        let requested = (|| {
            self.loan.disposition.require_closed()?;
            self.loan.check_local()?;
            self.metadata.require_native_selection(
                &self.loan.selection,
                &self.loan.policy.runtime_profile.app_artifact,
                &self.loan.policy,
            )?;
            let physical = self
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let names = self
                .loan
                .lineage
                .initial_restore_names_data(&self.loan.selection)?;
            let mut observed =
                self.loan
                    .reads
                    .read(physical.controller_stage()?, &self.loan.selection, &names)?;
            ensure!(
                observed.snapshot() == self.expected
                    && matches!(
                        &observed
                            .snapshot()
                            .root
                            .as_ref()
                            .context("native_restore_fenced_root_missing")?
                            .value
                            .phase,
                        kernel::Phase::Fenced { .. }
                    ),
                "native_restore_fenced_registry_changed"
            );
            self.loan
                .reads
                .check_observation(physical.controller_stage()?, &mut observed)?;
            self.loan.check_local()
        })();
        let checked = self.loan.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check_metadata(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        if !std::ptr::eq(self.metadata, metadata) {
            self.refuse();
            anyhow::bail!("native_restore_fenced_metadata_substituted");
        }
        self.check_current()
    }

    pub(crate) fn check_local(&mut self) -> Result<()> {
        self.loan.check_local()
    }
    pub(crate) fn check_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.check_database(db)
    }
    pub(crate) fn begin_retained_sql(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.begin_retained_sql(db)
    }
    pub(crate) fn end_retained_sql(
        &mut self,
        db: &rusqlite::Connection,
        completed: &Result<()>,
    ) -> Result<()> {
        self.loan.end_retained_sql(db, completed)
    }
    pub(crate) fn end_sql(&mut self, completed: &Result<()>) -> Result<()> {
        self.loan.end_sql(completed)
    }
    pub(crate) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

/// Distinct post-writer-CAS administrative SQL loan. It retains the actual
/// known CAS and accepts only its exact restored snapshot. No Active/Fenced
/// predicate is widened, and this cannot construct a writer or keeper.
pub(crate) struct WriterReadUnit<'borrow, 'storage, 'role> {
    loan: &'borrow mut ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'borrow crate::store::InitialStoreMetadata,
    known: &'borrow crate::security_epoch::firestore::KnownRestoredWriter,
}

impl WriterReadUnit<'_, '_, '_> {
    pub(crate) fn check_current(&mut self) -> Result<()> {
        let requested = (|| {
            self.loan.disposition.require_closed()?;
            self.loan.check_local()?;
            self.metadata.require_native_selection(
                &self.loan.selection,
                &self.loan.policy.runtime_profile.app_artifact,
                &self.loan.policy,
            )?;
            let physical = self
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let names = self
                .loan
                .lineage
                .initial_restore_names_data(&self.loan.selection)?;
            let mut observed =
                self.loan
                    .reads
                    .read(physical.controller_stage()?, &self.loan.selection, &names)?;
            self.known.require_snapshot_data(observed.snapshot())?;
            self.loan
                .reads
                .check_observation(physical.controller_stage()?, &mut observed)?;
            self.loan.check_local()
        })();
        let checked = self.loan.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check_metadata(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        if !std::ptr::eq(self.metadata, metadata) {
            self.refuse();
            anyhow::bail!("native_restore_writer_metadata_substituted");
        }
        self.check_current()
    }

    pub(crate) fn check_local(&mut self) -> Result<()> {
        self.loan.check_local()
    }
    pub(crate) fn check_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.check_database(db)
    }
    pub(crate) fn begin_retained_sql(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.begin_retained_sql(db)
    }
    pub(crate) fn end_retained_sql(
        &mut self,
        db: &rusqlite::Connection,
        completed: &Result<()>,
    ) -> Result<()> {
        self.loan.end_retained_sql(db, completed)
    }
    pub(crate) fn end_sql(&mut self, completed: &Result<()>) -> Result<()> {
        self.loan.end_sql(completed)
    }
    pub(crate) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

/// Only the already-spent writer dispatch may borrow this transitional
/// administrative read purpose. It cannot construct Known, activate, or serve.
pub(crate) struct WriterMayReadUnit<'borrow, 'storage, 'role> {
    loan: &'borrow mut ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'borrow crate::store::InitialStoreMetadata,
    plan: &'borrow kernel::restore::writer::Plan,
}

impl WriterMayReadUnit<'_, '_, '_> {
    pub(crate) fn check_current(&mut self) -> Result<()> {
        let requested = (|| {
            self.loan.disposition.require_closed()?;
            self.loan.check_local()?;
            self.metadata.require_native_selection(
                &self.loan.selection,
                &self.loan.policy.runtime_profile.app_artifact,
                &self.loan.policy,
            )?;
            let physical = self
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let names = self
                .loan
                .lineage
                .initial_restore_names_data(&self.loan.selection)?;
            let mut observed =
                self.loan
                    .reads
                    .read(physical.controller_stage()?, &self.loan.selection, &names)?;
            self.plan.require_may_snapshot_data(observed.snapshot())?;
            self.loan
                .reads
                .check_observation(physical.controller_stage()?, &mut observed)?;
            self.loan.check_local()
        })();
        let checked = self.loan.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check_metadata(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        if !std::ptr::eq(self.metadata, metadata) {
            self.refuse();
            anyhow::bail!("native_restore_writer_may_metadata_substituted");
        }
        self.check_current()
    }

    pub(crate) fn check_local(&mut self) -> Result<()> {
        self.loan.check_local()
    }
    pub(crate) fn check_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.check_database(db)
    }
    pub(crate) fn begin_retained_sql(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.begin_retained_sql(db)
    }
    pub(crate) fn end_retained_sql(
        &mut self,
        db: &rusqlite::Connection,
        completed: &Result<()>,
    ) -> Result<()> {
        self.loan.end_retained_sql(db, completed)
    }
    pub(crate) fn end_sql(&mut self, completed: &Result<()>) -> Result<()> {
        self.loan.end_sql(completed)
    }
    pub(crate) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

pub(in crate::security_epoch) struct FencedRegistryLoan<'borrow, 'metadata, 'storage, 'role> {
    reader: &'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>,
    expected: &'borrow kernel::Snapshot,
}

impl FencedRegistryLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn registry_data(
        &mut self,
    ) -> Result<crate::security_epoch::ControllerRegistryData> {
        let requested: Result<crate::security_epoch::ControllerRegistryData> = (|| {
            let reader = &mut *self.reader;
            let mut unit = FencedReadUnit {
                loan: &mut reader.loan,
                metadata: reader.metadata,
                expected: self.expected,
            };
            let data = reader.sqlite.read_fenced(&mut unit, reader.metadata)?;
            reader.selected.check(&data)?;
            let (selector, instance) = reader.metadata.restore_registry_selector_data();
            Ok(crate::security_epoch::ControllerRegistryData {
                selector,
                instance,
                scope: reader.metadata.scope().to_owned(),
                app: reader.metadata.app().to_owned(),
                artifact: reader.metadata.artifact().id().to_owned(),
                authority: reader.selected.authority.clone(),
                operation: reader.selected.operation.clone(),
                approver: reader.selected.approver.clone(),
                executor: reader.selected.executor.clone(),
            })
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.reader.check_registry_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.reader.refuse();
    }
}

/// A post-CAS purpose held only by the fixed writer confirmation. Registry
/// key selection is still projected from the real retained initial database
/// under its actual writer-specific read unit; receipt DATA cannot make one.
pub(in crate::security_epoch) struct WriterRegistryLoan<'borrow, 'metadata, 'storage, 'role> {
    reader: &'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>,
    known: &'borrow crate::security_epoch::firestore::KnownRestoredWriter,
}

impl WriterRegistryLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn registry_data(
        &mut self,
    ) -> Result<crate::security_epoch::ControllerRegistryData> {
        let requested: Result<crate::security_epoch::ControllerRegistryData> = (|| {
            let reader = &mut *self.reader;
            let mut unit = WriterReadUnit {
                loan: &mut reader.loan,
                metadata: reader.metadata,
                known: self.known,
            };
            let data = reader.sqlite.read_writing(&mut unit, reader.metadata)?;
            reader.selected.check(&data)?;
            let (selector, instance) = reader.metadata.restore_registry_selector_data();
            Ok(crate::security_epoch::ControllerRegistryData {
                selector,
                instance,
                scope: reader.metadata.scope().to_owned(),
                app: reader.metadata.app().to_owned(),
                artifact: reader.metadata.artifact().id().to_owned(),
                authority: reader.selected.authority.clone(),
                operation: reader.selected.operation.clone(),
                approver: reader.selected.approver.clone(),
                executor: reader.selected.executor.clone(),
            })
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.reader.check_registry_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.reader.refuse();
    }
}

/// Distinct May purpose; no old Fenced or known-writer predicate is widened.
pub(in crate::security_epoch) struct WriterMayRegistryLoan<'borrow, 'metadata, 'storage, 'role> {
    reader: &'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>,
    plan: &'borrow kernel::restore::writer::Plan,
}

impl WriterMayRegistryLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn registry_data(
        &mut self,
    ) -> Result<crate::security_epoch::ControllerRegistryData> {
        let requested: Result<crate::security_epoch::ControllerRegistryData> = (|| {
            let reader = &mut *self.reader;
            let mut unit = WriterMayReadUnit {
                loan: &mut reader.loan,
                metadata: reader.metadata,
                plan: self.plan,
            };
            let data = reader.sqlite.read_writer_may(&mut unit, reader.metadata)?;
            reader.selected.check(&data)?;
            let (selector, instance) = reader.metadata.restore_registry_selector_data();
            Ok(crate::security_epoch::ControllerRegistryData {
                selector,
                instance,
                scope: reader.metadata.scope().to_owned(),
                app: reader.metadata.app().to_owned(),
                artifact: reader.metadata.artifact().id().to_owned(),
                authority: reader.selected.authority.clone(),
                operation: reader.selected.operation.clone(),
                approver: reader.selected.approver.clone(),
                executor: reader.selected.executor.clone(),
            })
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.reader.check_registry_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.reader.refuse();
    }
}

/// A fixed local reborrow of the actual Fenced fields. Both the existing loan
/// and completed-target file checks use this SAME implementation. No factory,
/// clock, role, file, transport or callback getter is exposed.
pub(in crate::security_epoch) struct RestoreTargetCheck<
    'borrow,
    'executor,
    'metadata,
    'storage,
    'role,
> {
    executor: &'borrow mut ExecutionSourceLoan<'executor, 'metadata, 'storage, 'role>,
    issuer: &'borrow mut FrozenRoleIssuer,
    keys: &'borrow mut crate::security_epoch::storage_authority::HistoricalKeyAvailability,
    readiness: &'borrow Readiness,
    refused: &'borrow Rc<Cell<bool>>,
    source: &'borrow mut crate::security_epoch::storage_authority::NativeApprovalSource,
}

impl RestoreTargetCheck<'_, '_, '_, '_, '_> {
    /// Same native receiver loan is checked around every durable-target
    /// descriptor operation and readback chunk. No raw stage escapes.
    pub(in crate::security_epoch) fn check_durability_receiver(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.check()?;
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            receiver.check(&mut physical.controller_stage()?.storage()?, target)
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            target.refuse();
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        let requested: Result<_> = (|| {
            self.executor.action.check_local()?;
            self.keys
                .check_retained(self.executor.record, self.executor.operation)?;
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let observed = self.executor.original.check_join(
                physical.controller_stage()?,
                &self.executor.record.statement.request,
                self.executor.operation,
            )?;
            self.issuer
                .check(&mut physical.controller_stage()?.storage()?)?;
            self.source
                .require_qualified(self.executor.time_operation)?;
            let time = self.source.current_fenced_time(physical)?;
            self.readiness
                .check(approval_window(self.executor.record, &time)?)?;
            let (domain, origin, deadline) = observed.interval_data();
            ensure!(
                origin < deadline
                    && observed.observation_data().1 < deadline
                    && !domain.as_str().is_empty(),
                "native_restore_original_changed"
            );
            self.executor.action.check_local()
        })();
        let checked = self.executor.action.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn time_data(&mut self) -> Result<i64> {
        self.check()?;
        let requested: Result<_> = (|| {
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let time = self.source.current_fenced_time(physical)?;
            let at = approval_window(self.executor.record, &time)?;
            self.readiness.check(at)?;
            Ok(at)
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let at = requested?;
        checked?;
        Ok(at)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused.set(true);
        self.readiness.refuse();
        *self.executor.refused = true;
        self.executor.original.refuse();
        self.executor.action.refuse();
        self.issuer.refuse();
        self.source.refuse_target();
    }
}

impl<'metadata, 'storage, 'role> FencedRestoreContinuation<'metadata, 'storage, 'role> {
    pub(in crate::security_epoch) fn borrow_write(
        &mut self,
    ) -> Result<RestoreWriteLoan<'_, 'metadata, 'storage, 'role>> {
        if self.writer_borrowed.replace(true) {
            self.refuse();
            anyhow::bail!("native_restore_writer_loan_spent");
        }
        self.check_current()?;
        let lost = LostRestoreLoan {
            refused: Rc::clone(&self.refused),
        };
        Ok(RestoreWriteLoan {
            owner: self,
            _lost: lost,
        })
    }

    // Pessimistic refusal is set before any real checker. If an unwind is
    // caught while this same loan survives, no success tail ran to restore
    // availability. This needs no generic destructor or reconstructed guard.
    fn check_local(&mut self) -> Result<()> {
        if self.refused.get() {
            self.refuse();
            anyhow::bail!("native_restore_continuation_refused");
        }
        self.refused.set(true);
        let result = self.check_local_inner();
        if result.is_ok() {
            self.refused.set(false);
        } else {
            self.refuse();
        }
        result
    }

    fn check_current(&mut self) -> Result<RestoreObservation> {
        if self.refused.get() {
            self.refuse();
            anyhow::bail!("native_restore_continuation_refused");
        }
        self.refused.set(true);
        let result = self.check_current_inner();
        if result.is_ok() {
            self.refused.set(false);
        } else {
            self.refuse();
        }
        result
    }

    fn check_writer_after_cas(
        &mut self,
        expected: &WriterConfirmationData<'_>,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<()> {
        if self.refused.get() {
            target.refuse();
            peer.refuse();
            self.refuse();
            anyhow::bail!("native_restore_writer_confirmation_refused");
        }
        // A caught unwind leaves this same parent unavailable. The private
        // loan below is used only inside THIS pessimistically marked call;
        // no substep clears the mark or calls the old Fenced checker.
        self.refused.set(true);
        let requested = self.check_writer_after_cas_inner(expected, target, peer);
        if requested.is_err() {
            target.refuse();
            peer.refuse();
            self.refuse();
        }
        requested?;
        self.refused.set(false);
        Ok(())
    }

    fn check_writer_after_cas_inner(
        &mut self,
        expected: &WriterConfirmationData<'_>,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                peer.holder_data()? == *expected.holder,
                "restore_writer_confirmed_holder_changed"
            );
            let input = crate::security_epoch::firestore::RestoreWriterConfirmationInput {
                request: expected.request,
                plan: expected.plan,
                publication: &self.observed.publication,
            };
            let source = std::ptr::from_ref(&self.auth.source);
            let mut loan = WriterConfirmationSourceLoan {
                executor: ExecutionSourceLoan {
                    action: &mut self.auth.action,
                    original: &mut self.auth.original,
                    completion: &mut self.auth.completion,
                    record: &self.auth.record,
                    operation: &self.auth.operation,
                    time_operation: &self.auth.time_operation,
                    refused: &mut self.auth.refused,
                },
                issuer: &mut self.issuer,
                keys: self
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.readiness,
                refused: &self.refused,
                stopped: &self.stopped,
                authorization: &self.authorization,
                known: expected.known,
                target,
                peer,
                report: expected.report,
                input: &input,
                target_purpose: WriterTargetPurpose::Frozen,
                entered: false,
                source,
            };
            self.auth.source.confirm_restored_writer(&mut loan, &input)
        })();
        let checked = self.check_local_inner();
        if requested.is_err() || checked.is_err() {
            target.refuse();
            peer.refuse();
            self.refuse();
        }
        requested?;
        checked?;
        Ok(())
    }

    fn check_writer_active_inner(
        &mut self,
        expected: &WriterConfirmationData<'_>,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
        creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                peer.holder_data()? == *expected.holder,
                "restore_writer_confirmed_holder_changed"
            );
            let input = crate::security_epoch::firestore::RestoreWriterConfirmationInput {
                request: expected.request,
                plan: expected.plan,
                publication: &self.observed.publication,
            };
            let source = std::ptr::from_ref(&self.auth.source);
            let mut loan = WriterConfirmationSourceLoan {
                executor: ExecutionSourceLoan {
                    action: &mut self.auth.action,
                    original: &mut self.auth.original,
                    completion: &mut self.auth.completion,
                    record: &self.auth.record,
                    operation: &self.auth.operation,
                    time_operation: &self.auth.time_operation,
                    refused: &mut self.auth.refused,
                },
                issuer: &mut self.issuer,
                keys: self
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.readiness,
                refused: &self.refused,
                stopped: &self.stopped,
                authorization: &self.authorization,
                known: expected.known,
                target,
                peer,
                report: expected.report,
                input: &input,
                target_purpose: WriterTargetPurpose::Activated(creator),
                entered: false,
                source,
            };
            self.auth.source.confirm_restored_writer(&mut loan, &input)
        })();
        let checked = self.check_local_inner();
        if requested.is_err() || checked.is_err() {
            target.refuse();
            peer.refuse();
            self.refuse();
        }
        requested?;
        checked?;
        Ok(())
    }

    fn capture_release_cohort(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
        report: &kernel::restore::completion::TargetReport,
    ) -> Result<crate::security_epoch::restore_staging::RestoreControllerCohort> {
        let mut executor = ExecutionSourceLoan {
            action: &mut self.auth.action,
            original: &mut self.auth.original,
            completion: &mut self.auth.completion,
            record: &self.auth.record,
            operation: &self.auth.operation,
            time_operation: &self.auth.time_operation,
            refused: &mut self.auth.refused,
        };
        let mut checks = RestoreTargetCheck {
            executor: &mut executor,
            issuer: &mut self.issuer,
            keys: self
                .auth
                .historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?,
            readiness: &self.readiness,
            refused: &self.refused,
            source: &mut self.auth.source,
        };
        target.pin_active_cohort(&mut checks, creator, report)
    }

    fn capture_activation_creator(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::RestoreCreatorData> {
        let mut executor = ExecutionSourceLoan {
            action: &mut self.auth.action,
            original: &mut self.auth.original,
            completion: &mut self.auth.completion,
            record: &self.auth.record,
            operation: &self.auth.operation,
            time_operation: &self.auth.time_operation,
            refused: &mut self.auth.refused,
        };
        let mut checks = RestoreTargetCheck {
            executor: &mut executor,
            issuer: &mut self.issuer,
            keys: self
                .auth
                .historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?,
            readiness: &self.readiness,
            refused: &self.refused,
            source: &mut self.auth.source,
        };
        target.creator_data(&mut checks)
    }

    fn check_local_inner(&mut self) -> Result<()> {
        self.target_attempt.require_live()?;
        self.writer_attempt.require_live()?;
        let mut executor = ExecutionSourceLoan {
            action: &mut self.auth.action,
            original: &mut self.auth.original,
            completion: &mut self.auth.completion,
            record: &self.auth.record,
            operation: &self.auth.operation,
            time_operation: &self.auth.time_operation,
            refused: &mut self.auth.refused,
        };
        RestoreTargetCheck {
            executor: &mut executor,
            issuer: &mut self.issuer,
            keys: self
                .auth
                .historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?,
            readiness: &self.readiness,
            refused: &self.refused,
            source: &mut self.auth.source,
        }
        .check()
    }

    fn check_current_inner(&mut self) -> Result<RestoreObservation> {
        let requested = (|| {
            self.check_local_inner()?;
            super::super::super::require_outside_unit(
                self.auth
                    .action
                    .sqlite
                    .as_ref()
                    .context("restore_auth_sqlite_closed")?,
            )?;
            // This is a separate fixed fenced-policy read. The old Active-only
            // Action/Reader check and terminal route are never widened.
            let reader = &mut self.auth.action.reader;
            let mut loan = FencedRegistryLoan {
                reader,
                expected: &self.observed.snapshot,
            };
            self.auth.completion.check_fenced(
                &mut loan,
                (
                    self.auth
                        .action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.auth.action.files,
                ),
                &self.auth.record,
                &self.auth.operation,
            )?;
            self.auth
                .source
                .require_qualified(&self.auth.time_operation)?;
            let physical = self
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let time = self.auth.source.current_fenced_time(physical)?;
            self.readiness
                .check(approval_window(&self.auth.record, &time)?)?;
            let names = self
                .auth
                .action
                .reader
                .loan
                .lineage
                .initial_restore_names_data(&self.auth.action.reader.loan.selection)?;
            let mut fresh = self.auth.action.reader.loan.reads.read(
                physical.controller_stage()?,
                &self.auth.action.reader.loan.selection,
                &names,
            )?;
            ensure!(
                fresh.snapshot() == &self.observed.snapshot
                    && self.stopped.selection.fenced_root
                        == Digest::of(&self.plan.reservation.advance.root)?
                    && self
                        .observed
                        .snapshot
                        .root
                        .as_ref()
                        .is_some_and(|r| r.value == self.plan.reservation.advance.root)
                    && self
                        .observed
                        .snapshot
                        .sentinel
                        .as_ref()
                        .is_some_and(|r| r.value == self.plan.reservation.advance.sentinel),
                "native_restore_fenced_readset_changed"
            );
            self.auth
                .action
                .reader
                .loan
                .reads
                .check_observation(physical.controller_stage()?, &mut fresh)?;
            physical.require_restore_stopped(&self.stopped)?;
            self.auth.original.check_join(
                physical.controller_stage()?,
                &self.auth.record.statement.request,
                &self.auth.operation,
            )
        })();
        let checked = self.check_local_inner();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let observed = requested?;
        checked?;
        Ok(observed)
    }

    fn refuse(&mut self) {
        self.refused.set(true);
        self.readiness.refuse();
        self.target_attempt.refuse();
        self.writer_attempt.refuse();
        self.auth.refuse();
        self.issuer.refuse();
    }
}

impl<'loan, 'metadata, 'storage, 'role> RestoreWriteLoan<'loan, 'metadata, 'storage, 'role> {
    /// Bind the actual retained plan/approval and namespace generation before
    /// the first source read or creator effect. Neither caller DATA nor root
    /// identity is a substitute for this same-original owner check.
    pub(in crate::security_epoch) fn require_staging_input(
        &mut self,
        intent: &kernel::restore::Intent,
        namespace: &day2_capabilities::credentials::Namespace,
    ) -> Result<()> {
        if self.owner.refused.get() {
            self.refuse();
            anyhow::bail!("native_restore_continuation_refused");
        }
        // An unwind anywhere in this fixed operation leaves the SAME owner
        // refused. Neither a pure match nor an earlier checker can clear it.
        self.owner.refused.set(true);
        let requested = (|| {
            self.owner.check_current_inner()?;
            self.owner.plan.require_staging_input_data(
                &self.owner.auth.action.reader.loan.selection,
                intent,
                namespace,
            )
        })();
        let checked = self.owner.check_current_inner();
        if requested.is_ok() && checked.is_ok() {
            self.owner.refused.set(false);
        } else {
            self.refuse();
        }
        requested?;
        checked.map(|_| ())
    }

    /// Admission precedes Parent construction and its first mkdir/create.
    /// The accepting implementation must bind the target from this actual
    /// owner's Fenced plan, never from a caller flag or a directory identity.
    pub(in crate::security_epoch) fn admit_creator_root(
        &mut self,
        held_root: &std::fs::File,
    ) -> Result<crate::security_epoch::storage_authority::RestoreCreatorRoot> {
        if self.owner.refused.get() {
            self.refuse();
            anyhow::bail!("native_restore_continuation_refused");
        }
        self.owner.refused.set(true);
        let requested = (|| {
            self.owner.check_current_inner()?;
            self.owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?
                .admit_restore_creator_root(held_root)
        })();
        let checked = self.owner.check_current_inner();
        if requested.is_ok() && checked.is_ok() {
            self.owner.refused.set(false);
        } else {
            self.refuse();
        }
        let root = requested?;
        checked?;
        Ok(root)
    }

    /// The report and file are inputs, not completion or P3 authority. The
    /// fixed implementation must verify the actual retained creator and same
    /// reservation, perform one known settlement and check the whole readback.
    pub(in crate::security_epoch) fn settle_target(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    ) -> Result<kernel::restore::completion::Receipt> {
        let requested = self.settle_target_inner(target);
        let post = self.owner.check_current();
        if requested.is_err() || post.is_err() {
            self.owner.refuse();
            target.refuse();
        }
        let receipt = requested?;
        post?;
        Ok(receipt)
    }

    fn settle_target_inner(
        &mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    ) -> Result<kernel::restore::completion::Receipt> {
        if self.owner.refused.get() || self.owner.settled_target.is_some() {
            self.owner.refuse();
            target.refuse();
            anyhow::bail!("native_restore_target_attempt_spent");
        }
        self.owner.refused.set(true);
        let prepared: Result<_> = (|| {
            let mut executor = ExecutionSourceLoan {
                action: &mut self.owner.auth.action,
                original: &mut self.owner.auth.original,
                completion: &mut self.owner.auth.completion,
                record: &self.owner.auth.record,
                operation: &self.owner.auth.operation,
                time_operation: &self.owner.auth.time_operation,
                refused: &mut self.owner.auth.refused,
            };
            let mut check = RestoreTargetCheck {
                executor: &mut executor,
                issuer: &mut self.owner.issuer,
                keys: self
                    .owner
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.owner.readiness,
                refused: &self.owner.refused,
                source: &mut self.owner.auth.source,
            };
            let report = target.validate(&mut check)?;
            let at = check.time_data()?;
            let mut current = self.owner.authorization.clone();
            ensure!(
                at >= current.observed_at,
                "native_restore_target_clock_rewind"
            );
            current.observed_at = at;
            let before = kernel::restore::completion::State {
                snapshot: self.owner.observed.snapshot.clone(),
                advance: self
                    .owner
                    .observed
                    .advance
                    .clone()
                    .context("restore_target_advance_missing")?,
                reservation: self
                    .owner
                    .observed
                    .reservation
                    .clone()
                    .context("restore_target_reservation_missing")?,
            };
            let request = kernel::restore::completion::Request::new(
                &self.owner.auth.action.reader.loan.selection,
                &self.owner.plan.reservation,
                &before,
                &current,
                at,
                kernel::restore::completion::Disposition::Completed {
                    report: report.clone(),
                },
            )?;
            let plan = request.prepare(
                &self.owner.auth.action.reader.loan.selection,
                &current,
                at,
                &before,
                None,
            )?;
            Ok((report, current, at, request, plan))
        })();
        let post = self.owner.check_current_inner();
        if prepared.is_err() || post.is_err() {
            self.owner.refuse();
            target.refuse();
        }
        let (report, current, at, request, plan) = prepared?;
        post?;
        self.owner.refused.set(false);
        let dispatch = Digest::of(&(
            "day2-native-target-attempt-v1",
            &report,
            self.owner.observed.commitment_data()?,
        ))?;
        let flight = self.owner.target_attempt.arm(&dispatch)?;
        let requested: Result<_> = (|| {
            let input = crate::security_epoch::firestore::RestoreTargetInput {
                reservation: &self.owner.plan,
                known: &self.owner.observed,
                confirmation: &self.owner.confirmation,
                request: &request,
                plan: &plan,
                current: &current,
                at,
            };
            let source = std::ptr::from_ref(&self.owner.auth.source);
            let mut loan = TargetSettlementSourceLoan {
                executor: ExecutionSourceLoan {
                    action: &mut self.owner.auth.action,
                    original: &mut self.owner.auth.original,
                    completion: &mut self.owner.auth.completion,
                    record: &self.owner.auth.record,
                    operation: &self.owner.auth.operation,
                    time_operation: &self.owner.auth.time_operation,
                    refused: &mut self.owner.auth.refused,
                },
                issuer: &mut self.owner.issuer,
                keys: self
                    .owner
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.owner.readiness,
                refused: &self.owner.refused,
                stopped: &self.owner.stopped,
                target,
                report: &report,
                input: &input,
                flight: &flight,
                dispatch: &dispatch,
                entered: false,
                source,
            };
            self.owner
                .auth
                .source
                .settle_restore_target(&mut loan, &input)
        })();
        let post = self.owner.check_current();
        if requested.is_err() || post.is_err() {
            self.owner.refuse();
            target.refuse();
        }
        let known = requested?;
        post?;
        let receipt = known.receipt_data()?;
        self.owner.settled_target = Some(SettledTarget {
            request,
            plan,
            known,
            report,
        });
        self.owner.check_current()?;
        flight.known()?;
        Ok(receipt)
    }

    /// The only positive Confirmation origin. Retains the actual candidate's
    /// target and peer through ONE writer CAS; neither holder nor receipt DATA
    /// can substitute for that pair. All ambiguity is terminal for this parent.
    pub(in crate::security_epoch) fn confirm_writer<'confirm>(
        &'confirm mut self,
        target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
        peer: &mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    ) -> Result<RestoreWriterConfirmation<'confirm, 'metadata, 'storage, 'role>> {
        RestoreWriterExchangeContext {
            owner: &mut *self.owner,
        }
        .check_receiver(target, peer)?;
        self.owner.refused.set(true);
        let prepared = (|| {
            let holder = peer.holder_data()?;
            let mut executor = ExecutionSourceLoan {
                action: &mut self.owner.auth.action,
                original: &mut self.owner.auth.original,
                completion: &mut self.owner.auth.completion,
                record: &self.owner.auth.record,
                operation: &self.owner.auth.operation,
                time_operation: &self.owner.auth.time_operation,
                refused: &mut self.owner.auth.refused,
            };
            let mut check = RestoreTargetCheck {
                executor: &mut executor,
                issuer: &mut self.owner.issuer,
                keys: self
                    .owner
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.owner.readiness,
                refused: &self.owner.refused,
                source: &mut self.owner.auth.source,
            };
            let at = check.time_data()?;
            let settled = self
                .owner
                .settled_target
                .as_ref()
                .context("restore_writer_target_not_settled")?;
            let mut current = self.owner.authorization.clone();
            ensure!(
                at >= current.observed_at,
                "native_restore_writer_clock_rewind"
            );
            current.observed_at = at;
            let before = settled.known.writer_state_data()?;
            let input = kernel::restore::writer::Input {
                reservation: self.owner.plan.clone(),
                completion_request: settled.request.clone(),
                completion_plan: settled.plan.clone(),
                before: before.clone(),
                holder: holder.clone(),
            };
            let selected = &self.owner.auth.action.reader.loan.selection;
            let request = kernel::restore::writer::Request::new(selected, input, &current, at)?;
            let plan = request.prepare(selected, &current, at, &before, None)?;
            Ok((holder, settled.report.clone(), current, at, request, plan))
        })();
        let peer_post = (|| {
            let physical = self
                .owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            peer.check(&mut physical.controller_stage()?.storage()?)
        })();
        let post = RestoreWriterExchangeContext {
            owner: &mut *self.owner,
        }
        .check_inner(target);
        if prepared.is_err() || peer_post.is_err() || post.is_err() {
            self.refuse();
            target.refuse();
            peer.refuse();
        }
        let (holder, report, current, at, request, plan) = prepared?;
        peer_post?;
        post?;
        self.owner.refused.set(false);
        // The owned disposition enters May BEFORE even the provider BEGIN.
        // Drop/unwind keeps it refused; no caller can manufacture another.
        let dispatch = plan.commitment()?;
        let flight = self.owner.writer_attempt.arm(&dispatch)?;
        self.owner.refused.set(true);
        let requested = (|| {
            let input = crate::security_epoch::firestore::RestoreWriterSendInput {
                request: &request,
                plan: &plan,
                publication: &self.owner.observed.publication,
                current: &current,
                at,
            };
            let source = std::ptr::from_ref(&self.owner.auth.source);
            let mut loan = WriterSendSourceLoan {
                executor: ExecutionSourceLoan {
                    action: &mut self.owner.auth.action,
                    original: &mut self.owner.auth.original,
                    completion: &mut self.owner.auth.completion,
                    record: &self.owner.auth.record,
                    operation: &self.owner.auth.operation,
                    time_operation: &self.owner.auth.time_operation,
                    refused: &mut self.owner.auth.refused,
                },
                issuer: &mut self.owner.issuer,
                keys: self
                    .owner
                    .auth
                    .historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?,
                readiness: &self.owner.readiness,
                refused: &self.owner.refused,
                stopped: &self.owner.stopped,
                authorization: &self.owner.authorization,
                flight: &flight,
                dispatch: &dispatch,
                peer,
                target,
                report: &report,
                input: &input,
                entered: false,
                source,
            };
            self.owner
                .auth
                .source
                .send_restored_writer(&mut loan, &input)
        })();
        // Local validation is distinct from the now-invalid old Fenced path.
        let checked = self.owner.check_local_inner();
        if requested.is_err() || checked.is_err() {
            self.refuse();
            target.refuse();
            peer.refuse();
        }
        let known = requested?;
        checked?;
        let expected = WriterConfirmationData {
            known: &known,
            request: &request,
            plan: &plan,
            report: &report,
            holder: &holder,
        };
        self.owner.refused.set(false);
        self.owner.check_writer_after_cas(&expected, target, peer)?;
        flight.known()?;
        // Only now can the distinct positive owner be constructed. The checks
        // above used borrowed DATA under the actual parent, never a temporary
        // Confirmation or historical Applied-to-Known conversion.
        let lost = LostRestoreWriterConfirmation {
            refused: Rc::clone(&self.owner.refused),
        };
        Ok(RestoreWriterConfirmation {
            owner: &mut *self.owner,
            known,
            request,
            plan,
            target: report,
            holder,
            activation_creator: None,
            _lost: lost,
        })
    }

    pub(in crate::security_epoch) fn check_current(&mut self) -> Result<RestoreObservation> {
        self.owner.check_current()
    }
    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.owner.check_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.owner.refuse();
    }
}

// The loan is permanently spent before it can escape borrow_write; its
// nongeneric lost-loan owner also refuses the retained continuation on Drop.
// Full owner abandonment drops its real
// OriginalGuard, issuer and CounterUseGuard; the old active continuation was
// pessimistically false before acquisition and is never restored here.

/// Actual known terminal result, retained with its exact request/plan. This
/// DATA cannot construct a writer or recover a lost/refused original.
struct SettledTarget {
    request: kernel::restore::completion::Request,
    plan: kernel::restore::completion::Plan,
    known: crate::security_epoch::firestore::KnownRestoreTarget,
    report: kernel::restore::completion::TargetReport,
}

/// One fixed target-settlement borrow. Unlike the reservation loan, its exact
/// predecessor is already known Fenced and can NEVER move to a new root here.
pub(in crate::security_epoch) struct TargetSettlementSourceLoan<
    'borrow,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    executor: ExecutionSourceLoan<'borrow, 'metadata, 'storage, 'role>,
    issuer: &'borrow mut FrozenRoleIssuer,
    keys: &'borrow mut crate::security_epoch::storage_authority::HistoricalKeyAvailability,
    readiness: &'borrow Readiness,
    refused: &'borrow Rc<Cell<bool>>,
    stopped: &'borrow AuthorityStopData,
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    report: &'borrow kernel::restore::completion::TargetReport,
    input: &'borrow crate::security_epoch::firestore::RestoreTargetInput<'borrow>,
    flight: &'borrow crate::security_epoch::restore_staging::RestoreFlight,
    dispatch: &'borrow Digest,
    entered: bool,
    source: *const crate::security_epoch::storage_authority::NativeApprovalSource,
}

impl TargetSettlementSourceLoan<'_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn begin(
        &mut self,
        source: &crate::security_epoch::storage_authority::NativeApprovalSource,
        selected: &day2_capabilities::security_epoch::EpochStore,
        input: &crate::security_epoch::firestore::RestoreTargetInput<'_>,
    ) -> Result<()> {
        if self.entered
            || self.refused.get()
            || !std::ptr::eq(self.source, std::ptr::from_ref(source))
            || !std::ptr::eq(self.input, input)
            || selected != &self.executor.action.reader.loan.selection
        {
            self.refused.set(true);
            self.target.refuse();
            self.executor.refuse();
            self.issuer.refuse();
            anyhow::bail!("native_restore_target_owner_substituted");
        }
        self.entered = true;
        self.flight.check(self.dispatch)
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<()> {
        if !self.entered
            || self.refused.get()
            || *self.executor.refused
            || !std::ptr::eq(self.source, std::ptr::from_ref(&*source))
        {
            self.refuse(source);
            anyhow::bail!("native_restore_target_refused");
        }
        self.refused.set(true);
        let requested = (|| {
            self.flight.check(self.dispatch)?;
            super::super::super::require_outside_unit(
                self.executor
                    .action
                    .sqlite
                    .as_ref()
                    .context("restore_auth_sqlite_closed")?,
            )?;
            let mut registry = FencedRegistryLoan {
                reader: &mut self.executor.action.reader,
                expected: &self.input.known.snapshot,
            };
            self.executor.completion.check_fenced(
                &mut registry,
                (
                    self.executor
                        .action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.executor.action.files,
                ),
                self.executor.record,
                self.executor.operation,
            )?;
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let names = self
                .executor
                .action
                .reader
                .loan
                .lineage
                .initial_restore_names_data(&self.executor.action.reader.loan.selection)?;
            let mut fresh = self.executor.action.reader.loan.reads.read(
                physical.controller_stage()?,
                &self.executor.action.reader.loan.selection,
                &names,
            )?;
            ensure!(
                fresh.snapshot() == &self.input.known.snapshot
                    && self.input.known.commitment_data()? == self.input.confirmation.records
                    && self.stopped.selection.fenced_root
                        == Digest::of(&self.input.reservation.reservation.advance.root)?,
                "native_restore_target_fenced_readset_changed"
            );
            self.executor
                .action
                .reader
                .loan
                .reads
                .check_observation(physical.controller_stage()?, &mut fresh)?;
            physical.require_restore_stopped(self.stopped)?;
            // The issuer and original are checked again in the concrete local
            // validator before EACH target descriptor operation below.
            let mut check = RestoreTargetCheck {
                executor: &mut self.executor,
                issuer: &mut *self.issuer,
                keys: &mut *self.keys,
                readiness: self.readiness,
                refused: self.refused,
                source: &mut *source,
            };
            let report = self.target.validate(&mut check)?;
            ensure!(
                &report == self.report,
                "native_restore_target_report_changed"
            );
            let at = check.time_data()?;
            self.input.plan.revalidate(
                &check.executor.action.reader.loan.selection,
                self.input.request,
                self.input.current,
                at,
                &kernel::restore::completion::State {
                    snapshot: self.input.known.snapshot.clone(),
                    advance: self
                        .input
                        .known
                        .advance
                        .clone()
                        .context("restore_target_advance_missing")?,
                    reservation: self
                        .input
                        .known
                        .reservation
                        .clone()
                        .context("restore_target_reservation_missing")?,
                },
                None,
            )?;
            self.flight.check(self.dispatch)
        })();
        let checked = RestoreTargetCheck {
            executor: &mut self.executor,
            issuer: &mut *self.issuer,
            keys: &mut *self.keys,
            readiness: self.readiness,
            refused: self.refused,
            source: &mut *source,
        }
        .check();
        if requested.is_err() || checked.is_err() {
            self.refuse(source);
        }
        requested?;
        checked?;
        self.refused.set(false);
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) {
        self.refused.set(true);
        self.readiness.refuse();
        self.executor.refuse();
        self.issuer.refuse();
        self.target.refuse();
        source.refuse_target();
    }
}

/// Fixed post-CAS read source. This borrows every actual parent field once
/// and never accepts an old Fenced snapshot, a caller URL, role, file or clock.
/// The enclosing Confirmation owns its pessimistic refusal mark throughout.
pub(in crate::security_epoch) struct WriterConfirmationSourceLoan<
    'borrow,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    executor: ExecutionSourceLoan<'borrow, 'metadata, 'storage, 'role>,
    issuer: &'borrow mut FrozenRoleIssuer,
    keys: &'borrow mut crate::security_epoch::storage_authority::HistoricalKeyAvailability,
    readiness: &'borrow Readiness,
    refused: &'borrow Rc<Cell<bool>>,
    stopped: &'borrow AuthorityStopData,
    authorization: &'borrow kernel::restore::Current,
    known: &'borrow crate::security_epoch::firestore::KnownRestoredWriter,
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    peer: &'borrow mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    report: &'borrow kernel::restore::completion::TargetReport,
    input: &'borrow crate::security_epoch::firestore::RestoreWriterConfirmationInput<'borrow>,
    target_purpose: WriterTargetPurpose<'borrow>,
    entered: bool,
    source: *const crate::security_epoch::storage_authority::NativeApprovalSource,
}

impl WriterConfirmationSourceLoan<'_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn require_observed_data(
        &mut self,
        observed: &crate::security_epoch::firestore::RestoreWriterObserved,
    ) -> Result<()> {
        let requested = self.known.require_observed_data(observed);
        if requested.is_err() {
            self.refused.set(true);
            self.readiness.refuse();
            self.executor.refuse();
            self.issuer.refuse();
            self.target.refuse();
        }
        requested.map(|_| ())
    }

    pub(in crate::security_epoch) fn begin(
        &mut self,
        source: &crate::security_epoch::storage_authority::NativeApprovalSource,
        selected: &day2_capabilities::security_epoch::EpochStore,
        input: &crate::security_epoch::firestore::RestoreWriterConfirmationInput<'_>,
    ) -> Result<()> {
        if self.entered
            || !self.refused.get()
            || *self.executor.refused
            || !std::ptr::eq(self.source, std::ptr::from_ref(source))
            || !std::ptr::eq(self.input, input)
            || selected != &self.executor.action.reader.loan.selection
        {
            self.refused.set(true);
            self.target.refuse();
            self.executor.refuse();
            self.issuer.refuse();
            anyhow::bail!("native_restore_writer_confirmation_owner_substituted");
        }
        self.entered = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<()> {
        if !self.entered
            || !self.refused.get()
            || *self.executor.refused
            || !std::ptr::eq(self.source, std::ptr::from_ref(&*source))
        {
            self.refuse(source);
            anyhow::bail!("native_restore_writer_confirmation_closed");
        }
        let requested = (|| {
            super::super::super::require_outside_unit(
                self.executor
                    .action
                    .sqlite
                    .as_ref()
                    .context("restore_auth_sqlite_closed")?,
            )?;
            let mut registry = WriterRegistryLoan {
                reader: &mut self.executor.action.reader,
                known: self.known,
            };
            self.executor.completion.check_writer(
                &mut registry,
                (
                    self.executor
                        .action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.executor.action.files,
                ),
                self.executor.record,
                self.executor.operation,
            )?;
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            physical.require_restore_stopped(self.stopped)?;
            self.peer
                .check(&mut physical.controller_stage()?.storage()?)?;
            let mut checks = RestoreTargetCheck {
                executor: &mut self.executor,
                issuer: &mut *self.issuer,
                keys: &mut *self.keys,
                readiness: self.readiness,
                refused: self.refused,
                source: &mut *source,
            };
            match &self.target_purpose {
                WriterTargetPurpose::Frozen => ensure!(
                    self.target.validate(&mut checks)? == *self.report,
                    "native_restore_writer_target_changed"
                ),
                WriterTargetPurpose::Activated(creator) => {
                    self.target
                        .check_active_identity(&mut checks, creator, self.report)?
                }
            }
            let at = checks.time_data()?;
            let mut current = self.authorization.clone();
            ensure!(
                at >= current.observed_at,
                "native_restore_writer_clock_rewind"
            );
            current.observed_at = at;
            self.input.plan.revalidate(
                &checks.executor.action.reader.loan.selection,
                self.input.request,
                &current,
                at,
                &self.input.plan.before,
                None,
            )?;
            ensure!(
                self.known.receipt_data()? == self.input.plan.receipt,
                "native_restore_writer_known_plan_changed"
            );
            Ok(())
        })();
        let peer_checked = (|| {
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            self.peer
                .check(&mut physical.controller_stage()?.storage()?)
        })();
        let checked = RestoreTargetCheck {
            executor: &mut self.executor,
            issuer: &mut *self.issuer,
            keys: &mut *self.keys,
            readiness: self.readiness,
            refused: self.refused,
            source: &mut *source,
        }
        .check();
        if requested.is_err() || peer_checked.is_err() || checked.is_err() {
            self.refuse(source);
        }
        requested?;
        peer_checked?;
        checked
    }

    pub(in crate::security_epoch) fn refuse(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) {
        self.refused.set(true);
        self.readiness.refuse();
        self.executor.refuse();
        self.issuer.refuse();
        self.target.refuse();
        self.peer.refuse();
        source.refuse_target();
    }
}

/// Actual one-shot writer-CAS borrow. May is not Known or serving: this
/// purpose exists only across its already-spent conditional send and readback.
pub(in crate::security_epoch) struct WriterSendSourceLoan<
    'borrow,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    executor: ExecutionSourceLoan<'borrow, 'metadata, 'storage, 'role>,
    issuer: &'borrow mut FrozenRoleIssuer,
    keys: &'borrow mut crate::security_epoch::storage_authority::HistoricalKeyAvailability,
    readiness: &'borrow Readiness,
    refused: &'borrow Rc<Cell<bool>>,
    stopped: &'borrow AuthorityStopData,
    authorization: &'borrow kernel::restore::Current,
    flight: &'borrow crate::security_epoch::restore_staging::RestoreFlight,
    dispatch: &'borrow Digest,
    peer: &'borrow mut crate::security_epoch::native_enrollment::RestoredWriterPeer,
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    report: &'borrow kernel::restore::completion::TargetReport,
    input: &'borrow crate::security_epoch::firestore::RestoreWriterSendInput<'borrow>,
    entered: bool,
    source: *const crate::security_epoch::storage_authority::NativeApprovalSource,
}

impl WriterSendSourceLoan<'_, '_, '_, '_, '_, '_> {
    pub(in crate::security_epoch) fn begin(
        &mut self,
        source: &crate::security_epoch::storage_authority::NativeApprovalSource,
        selected: &day2_capabilities::security_epoch::EpochStore,
        input: &crate::security_epoch::firestore::RestoreWriterSendInput<'_>,
    ) -> Result<()> {
        if self.entered
            || !self.refused.get()
            || *self.executor.refused
            || !std::ptr::eq(self.source, std::ptr::from_ref(source))
            || !std::ptr::eq(self.input, input)
            || selected != &self.executor.action.reader.loan.selection
        {
            self.refused.set(true);
            self.target.refuse();
            self.executor.refuse();
            self.issuer.refuse();
            anyhow::bail!("native_restore_writer_send_owner_substituted");
        }
        self.entered = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<()> {
        if !self.entered
            || !self.refused.get()
            || *self.executor.refused
            || !std::ptr::eq(self.source, std::ptr::from_ref(&*source))
        {
            self.refuse(source);
            anyhow::bail!("native_restore_writer_send_closed");
        }
        let requested = (|| {
            super::super::super::require_outside_unit(
                self.executor
                    .action
                    .sqlite
                    .as_ref()
                    .context("restore_auth_sqlite_closed")?,
            )?;
            let mut registry = WriterMayRegistryLoan {
                reader: &mut self.executor.action.reader,
                plan: self.input.plan,
            };
            self.executor.completion.check_writer_may(
                &mut registry,
                (
                    self.executor
                        .action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.executor.action.files,
                ),
                self.executor.record,
                self.executor.operation,
            )?;
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            physical.require_restore_stopped(self.stopped)?;
            self.peer
                .check(&mut physical.controller_stage()?.storage()?)?;
            let mut checks = RestoreTargetCheck {
                executor: &mut self.executor,
                issuer: &mut *self.issuer,
                keys: &mut *self.keys,
                readiness: self.readiness,
                refused: self.refused,
                source: &mut *source,
            };
            ensure!(
                self.target.validate(&mut checks)? == *self.report,
                "native_restore_writer_target_changed"
            );
            let at = checks.time_data()?;
            let mut current = self.authorization.clone();
            ensure!(
                at >= current.observed_at,
                "native_restore_writer_clock_rewind"
            );
            current.observed_at = at;
            self.input.plan.revalidate(
                &checks.executor.action.reader.loan.selection,
                self.input.request,
                &current,
                at,
                &self.input.plan.before,
                None,
            )?;
            self.flight.check(self.dispatch)?;
            Ok(())
        })();
        // Independent actual peer and local-owner posts run even when UV,
        // target validation, decoding or the primary exchange already failed.
        let peer_checked = (|| {
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            self.peer
                .check(&mut physical.controller_stage()?.storage()?)
        })();
        let checked = RestoreTargetCheck {
            executor: &mut self.executor,
            issuer: &mut *self.issuer,
            keys: &mut *self.keys,
            readiness: self.readiness,
            refused: self.refused,
            source: &mut *source,
        }
        .check();
        if requested.is_err() || peer_checked.is_err() || checked.is_err() {
            self.refuse(source);
        }
        requested?;
        peer_checked?;
        checked
    }

    pub(in crate::security_epoch) fn refuse(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) {
        self.refused.set(true);
        self.readiness.refuse();
        self.executor.refuse();
        self.issuer.refuse();
        self.target.refuse();
        self.peer.refuse();
        source.refuse_target();
    }
}

/// Additional fixed ceiling, never a clock or authorization source. The same
/// captured value moves through known settlement into the Fenced owner.
struct Readiness {
    observed_at: i64,
    ready_until: i64,
    refused: std::cell::Cell<bool>,
}

impl Readiness {
    fn new(observed_at: i64, ready_until: i64) -> Result<Self> {
        ensure!(
            observed_at >= 0 && observed_at < ready_until,
            "native_restore_readiness_interval"
        );
        Ok(Self {
            observed_at,
            ready_until,
            refused: std::cell::Cell::new(false),
        })
    }
    fn check(&self, at: i64) -> Result<()> {
        if self.refused.get() || at < self.observed_at || at >= self.ready_until {
            self.refuse();
            anyhow::bail!("native_restore_reservation_readiness_expired");
        }
        Ok(())
    }
    fn refuse(&self) {
        self.refused.set(true);
    }
}

// A local reducer only, not a source of native authority. The real owner below
// must retain every actual guard; no parsed receipt can construct that owner.
enum ObservationPhase {
    Created,
    Reading,
    May,
    Known(Box<Snapshot>),
    Refused,
}

struct ReservationView {
    before: Snapshot,
    root: kernel::AuthorityRecord,
    sentinel: kernel::SentinelRecord,
    phase: std::cell::RefCell<ObservationPhase>,
}

impl ReservationView {
    fn begin(&mut self) -> Result<()> {
        if !matches!(self.phase.get_mut(), ObservationPhase::Created) {
            self.refuse();
            anyhow::bail!("native_restore_reservation_already_attempted");
        }
        *self.phase.get_mut() = ObservationPhase::Reading;
        Ok(())
    }

    fn arm_commit(&mut self) -> Result<()> {
        if !matches!(self.phase.get_mut(), ObservationPhase::Reading) {
            self.refuse();
            anyhow::bail!("native_restore_reservation_commit_spent");
        }
        // Spend before the first possible commit call, including an unwind.
        *self.phase.get_mut() = ObservationPhase::May;
        Ok(())
    }

    fn is_after(&self, observed: &Snapshot) -> bool {
        observed.create == self.before.create
            && observed.activate == self.before.activate
            && observed.root.as_ref().is_some_and(|row| {
                row.value == self.root
                    && self
                        .before
                        .root
                        .as_ref()
                        .is_some_and(|old| row.version != old.version)
            })
            && observed.sentinel.as_ref().is_some_and(|row| {
                row.value == self.sentinel
                    && self
                        .before
                        .sentinel
                        .as_ref()
                        .is_some_and(|old| row.version != old.version)
            })
    }

    fn check(&self, observed: &Snapshot) -> Result<()> {
        let matches = match &*self.phase.borrow() {
            ObservationPhase::Created | ObservationPhase::Reading => observed == &self.before,
            ObservationPhase::May => observed == &self.before || self.is_after(observed),
            ObservationPhase::Known(known) => observed == known.as_ref(),
            ObservationPhase::Refused => false,
        };
        if !matches {
            self.refuse();
            anyhow::bail!("native_restore_private_reservation_observation_changed");
        }
        Ok(())
    }

    fn known(&mut self, observed: Snapshot) -> Result<()> {
        if !matches!(self.phase.get_mut(), ObservationPhase::May) || !self.is_after(&observed) {
            self.refuse();
            anyhow::bail!("native_restore_reservation_not_known");
        }
        *self.phase.get_mut() = ObservationPhase::Known(Box::new(observed));
        Ok(())
    }

    fn refuse(&self) {
        self.phase.replace(ObservationPhase::Refused);
    }
}

/// A distinct, private-purpose read loan. It never broadens the existing
/// Active-only or Known-Fenced loans and cannot execute business callbacks.
pub(crate) struct ReservationReadUnit<'borrow, 'storage, 'role> {
    loan: &'borrow mut ControllerAdminReadLoan<'storage, 'role>,
    metadata: &'borrow crate::store::InitialStoreMetadata,
    view: &'borrow ReservationView,
}

impl ReservationReadUnit<'_, '_, '_> {
    pub(crate) fn check_current(&mut self) -> Result<()> {
        let requested = (|| {
            self.loan.disposition.require_closed()?;
            self.loan.check_local()?;
            self.metadata.require_native_selection(
                &self.loan.selection,
                &self.loan.policy.runtime_profile.app_artifact,
                &self.loan.policy,
            )?;
            let physical = self
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let names = self
                .loan
                .lineage
                .initial_restore_names_data(&self.loan.selection)?;
            let mut observed =
                self.loan
                    .reads
                    .read(physical.controller_stage()?, &self.loan.selection, &names)?;
            self.view.check(observed.snapshot())?;
            self.loan
                .reads
                .check_observation(physical.controller_stage()?, &mut observed)?;
            self.loan.check_local()
        })();
        let checked = self.loan.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(crate) fn check_metadata(
        &mut self,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        if !std::ptr::eq(self.metadata, metadata) {
            self.refuse();
            anyhow::bail!("native_restore_reservation_metadata_substituted");
        }
        self.check_current()
    }

    pub(crate) fn check_database(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.check_database(db)
    }
    pub(crate) fn begin_retained_sql(&mut self, db: &rusqlite::Connection) -> Result<()> {
        self.loan.begin_retained_sql(db)
    }
    pub(crate) fn end_retained_sql(
        &mut self,
        db: &rusqlite::Connection,
        completed: &Result<()>,
    ) -> Result<()> {
        self.loan.end_retained_sql(db, completed)
    }
    pub(crate) fn end_sql(&mut self, completed: &Result<()>) -> Result<()> {
        self.loan.end_sql(completed)
    }
    pub(crate) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

pub(in crate::security_epoch) struct ReservationRegistryLoan<'borrow, 'metadata, 'storage, 'role> {
    reader: &'borrow mut ControllerAdminReader<'metadata, 'storage, 'role>,
    view: &'borrow ReservationView,
}

impl ReservationRegistryLoan<'_, '_, '_, '_> {
    pub(in crate::security_epoch) fn registry_data(
        &mut self,
    ) -> Result<crate::security_epoch::ControllerRegistryData> {
        let requested: Result<crate::security_epoch::ControllerRegistryData> = (|| {
            let reader = &mut *self.reader;
            let mut unit = ReservationReadUnit {
                loan: &mut reader.loan,
                metadata: reader.metadata,
                view: self.view,
            };
            let data = reader.sqlite.read_reserving(&mut unit, reader.metadata)?;
            reader.selected.check(&data)?;
            let (selector, instance) = reader.metadata.restore_registry_selector_data();
            Ok(crate::security_epoch::ControllerRegistryData {
                selector,
                instance,
                scope: reader.metadata.scope().to_owned(),
                app: reader.metadata.app().to_owned(),
                artifact: reader.metadata.artifact().id().to_owned(),
                authority: reader.selected.authority.clone(),
                operation: reader.selected.operation.clone(),
                approver: reader.selected.approver.clone(),
                executor: reader.selected.executor.clone(),
            })
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let data = requested?;
        checked?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        self.reader.check_registry_local()
    }
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.reader.refuse();
    }
}

/// Only the actual consuming reservation method constructs this lexical loan.
/// It borrows every executor field, the frozen issuer and retained key material;
/// no Source/stage/clock/descriptor getter or transferable dispatch permit exists.
pub(in crate::security_epoch) struct ReservationSourceLoan<'borrow, 'metadata, 'storage, 'role> {
    executor: ExecutionSourceLoan<'borrow, 'metadata, 'storage, 'role>,
    issuer: &'borrow mut crate::security_epoch::native_enrollment::FrozenRoleIssuer,
    keys: &'borrow mut crate::security_epoch::storage_authority::HistoricalKeyAvailability,
    intent: &'borrow kernel::restore::Intent,
    view: &'borrow mut ReservationView,
    plan: &'borrow kernel::restore::approval_use::Plan,
    current: &'borrow kernel::restore::Current,
    readiness: &'borrow Readiness,
    at: i64,
    source: *const crate::security_epoch::storage_authority::NativeApprovalSource,
}

impl ReservationSourceLoan<'_, '_, '_, '_> {
    /// Compare the actual source and exact captured DATA before any SQL or
    /// provider work. Equal selection/clock DATA cannot substitute another owner.
    pub(in crate::security_epoch) fn require_dispatch_data(
        &mut self,
        source: &crate::security_epoch::storage_authority::NativeApprovalSource,
        selected: &day2_capabilities::security_epoch::EpochStore,
        plan: &kernel::restore::approval_use::Plan,
        current: &kernel::restore::Current,
        at: i64,
        publication: &crate::security_epoch::restore_approval::publication::Publication,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                std::ptr::eq(self.source, std::ptr::from_ref(source))
                    && std::ptr::eq(self.plan, plan)
                    && std::ptr::eq(self.current, current)
                    && self.at == at
                    && selected == &self.executor.action.reader.loan.selection,
                "native_restore_reservation_owner_substituted"
            );
            publication.require_exact(selected, self.executor.record)?;
            ensure!(
                plan.reservation.before == self.view.before
                    && plan.reservation.advance.root == self.view.root
                    && plan.reservation.advance.sentinel == self.view.sentinel
                    && current.grant.approval == self.executor.record.statement.request
                    && current.grant.intent == self.intent.commitment(selected)?
                    && self.readiness.observed_at == current.observed_at
                    && self.readiness.ready_until == current.ready_until,
                "native_restore_reservation_data_substituted"
            );
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn begin(&mut self) -> Result<()> {
        self.view.begin()
    }
    pub(in crate::security_epoch) fn arm_commit(&mut self) -> Result<()> {
        self.view.arm_commit()
    }
    pub(in crate::security_epoch) fn known(&mut self, observed: &Snapshot) -> Result<()> {
        self.view.known(observed.clone())
    }

    fn check_local(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<crate::security_epoch::restore_original::RestoreObservation> {
        self.executor.action.check_local()?;
        let physical = self
            .executor
            .action
            .reader
            .loan
            .physical
            .as_mut()
            .context("native_restore_physical_closed")?;
        let observed = self.executor.original.check_join(
            physical.controller_stage()?,
            &self.executor.record.statement.request,
            self.executor.operation,
        )?;
        self.issuer
            .check(&mut physical.controller_stage()?.storage()?)?;
        source.check_phase(physical)?;
        source.require_qualified(self.executor.time_operation)?;
        let time = source.current_fenced_time(physical)?;
        self.readiness
            .check(approval_window(self.executor.record, &time)?)?;
        self.executor.action.check_local()?;
        Ok(observed)
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        source: &mut crate::security_epoch::storage_authority::NativeApprovalSource,
    ) -> Result<crate::security_epoch::restore_original::RestoreObservation> {
        if *self.executor.refused || !std::ptr::eq(self.source, std::ptr::from_ref(&*source)) {
            self.refuse();
            source.refuse_reservation();
            anyhow::bail!("native_restore_reservation_refused");
        }
        // A caught unwind cannot resume this same lexical owner as healthy.
        *self.executor.refused = true;
        let requested: Result<()> = (|| {
            self.check_local(source)?;
            self.keys
                .require(self.intent, self.executor.record, self.executor.operation)?;
            super::super::super::require_outside_unit(
                self.executor
                    .action
                    .sqlite
                    .as_ref()
                    .context("restore_auth_sqlite_closed")?,
            )?;
            let mut registry = ReservationRegistryLoan {
                reader: &mut self.executor.action.reader,
                view: self.view,
            };
            self.executor.completion.check_reservation(
                &mut registry,
                (
                    self.executor
                        .action
                        .sqlite
                        .as_mut()
                        .context("restore_auth_sqlite_closed")?,
                    &mut self.executor.action.files,
                ),
                self.executor.record,
                self.executor.operation,
            )?;
            source.require_qualified(self.executor.time_operation)?;
            let physical = self
                .executor
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let time = source.current_fenced_time(physical)?;
            let at = approval_window(self.executor.record, &time)?;
            self.readiness.check(at)?;
            Ok(())
        })();
        let checked = self.check_local(source).and_then(|observed| {
            ensure!(
                &self.current.grant.clock_domain == observed.interval_data().0,
                "native_restore_reservation_clock_changed"
            );
            Ok(observed)
        });
        if requested.is_err() || checked.is_err() {
            self.refuse();
            source.refuse_reservation();
        }
        requested?;
        let observed = checked?;
        *self.executor.refused = false;
        Ok(observed)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.view.refuse();
        self.readiness.refuse();
        self.executor.refuse();
        self.issuer.refuse();
    }
}

// Sole accepting construction path. All fields below are actual owned guards;
// the scalar kernel plan and ACK projections are not accepted as substitutes.
struct NativeReservation<'metadata, 'storage, 'role> {
    auth: Option<AuthenticatedRestoreExecution<'metadata, 'storage, 'role>>,
    issuer: crate::security_epoch::native_enrollment::FrozenRoleIssuer,
    stopped: crate::security_epoch::native_enrollment::AuthorityStopData,
    intent: kernel::restore::Intent,
    plan: kernel::restore::approval_use::Plan,
    current: kernel::restore::Current,
    readiness: Readiness,
    at: i64,
    view: ReservationView,
}

impl<'metadata, 'storage, 'role> AuthenticatedRestoreExecution<'metadata, 'storage, 'role> {
    /// Consume the actual executor, durably mark this grant before any stop or
    /// reservation packet, drain the genuine incumbent, then make ONE CAS.
    pub(in crate::security_epoch) fn stop_for_restore(
        mut self,
        intent: &kernel::restore::Intent,
    ) -> Result<FencedRestoreContinuation<'metadata, 'storage, 'role>> {
        if self.historical_keys.is_none() {
            self.retain_historical_keys(intent)?;
        }
        let mut attempt = self.begin_restore_attempt(intent)?;
        attempt.check()?;
        let requested = (|| {
            let auth = attempt
                .auth
                .as_mut()
                .context("restore_attempt_owner_closed")?;
            let selection = auth.action.reader.loan.selection.clone();
            let before = auth.action.reader.loan.initial_restore_snapshot_data()?;
            let stop = auth
                .action
                .reader
                .loan
                .lineage
                .initial_restore_stop_selection_data(&selection, intent, &before)?;
            let physical = auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let mut issuer = physical.freeze_restore_issuer(&stop)?;
            physical.announce_restore_stop(&mut issuer)?;
            let stopped = physical.await_restore_stopped()?;
            ensure!(
                stopped.selection == stop,
                "native_restore_stop_selection_changed"
            );
            issuer.check(&mut physical.controller_stage()?.storage()?)?;
            auth.require_historical_keys(intent)?;
            let physical = auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let time = auth.source.current_fenced_time(physical)?;
            let observation = auth.original.check_join(
                physical.controller_stage()?,
                &auth.record.statement.request,
                &auth.operation,
            )?;
            let at = approval_window(&auth.record, &time)?;
            let (domain, _, deadline) = observation.interval_data();
            let remaining = deadline
                .checked_sub(observation.observation_data().1)
                .context("native_restore_original_expired")?;
            // Conservative UTC projection of the ACTUAL unchanged short
            // original. It never creates another native clock or extends it.
            let ready_until = i64::try_from(
                time.lower
                    .checked_add(std::time::Duration::from_nanos(remaining))
                    .context("native_restore_time_overflow")?
                    .as_secs(),
            )?
            .min(auth.record.statement.request.expires_at);
            let root = before
                .root
                .as_ref()
                .context("native_restore_root_missing")?;
            let kernel::Phase::ActiveFirstHolder { completion } = &root.value.phase else {
                anyhow::bail!("native_restore_active_holder_required");
            };
            let current = kernel::restore::Current {
                grant: kernel::restore::Grant {
                    intent: intent.commitment(&selection)?,
                    issuer: issuer.digest_data()?,
                    revision: Digest::of(&auth.action.reader.selected.authority)?,
                    policy: Digest::of(&auth.action.reader.loan.policy)?,
                    clock_domain: domain.clone(),
                    approval: auth.record.statement.request.clone(),
                    fence: kernel::restore::Fence {
                        root: Digest::of(&root.value)?,
                        holder: Digest::of(&completion.holder)?,
                        receipt: stopped.stopped.clone(),
                    },
                },
                target: auth.record.statement.request.target.clone(),
                custody: auth.record.statement.request.custody.clone(),
                executor: auth.record.statement.request.executor.clone(),
                enabled: true,
                observed_at: i64::try_from(time.lower.as_secs())?,
                ready_until,
                available_keys: intent.archive.required_keys.clone(),
            };
            let readiness = Readiness::new(current.observed_at, current.ready_until)?;
            let request =
                kernel::restore::Request::new(&selection, intent.clone(), &current, at, &before)?;
            let reservation = request.prepare(&selection, &current, at, &before, None)?;
            let plan = kernel::restore::approval_use::Plan::new(
                reservation,
                &selection,
                &current,
                at,
                &before,
                None,
                None,
            )?;
            let view = ReservationView {
                before,
                root: plan.reservation.advance.root.clone(),
                sentinel: plan.reservation.advance.sentinel.clone(),
                phase: std::cell::RefCell::new(ObservationPhase::Created),
            };
            let auth = attempt
                .auth
                .take()
                .context("restore_attempt_owner_closed")?;
            NativeReservation {
                auth: Some(auth),
                issuer,
                stopped,
                intent: intent.clone(),
                plan,
                current,
                readiness,
                at,
                view,
            }
            .reserve()
        })();
        if requested.is_err()
            && let Some(auth) = &mut attempt.auth
        {
            auth.refuse();
        }
        requested
    }
}

impl<'metadata, 'storage, 'role> NativeReservation<'metadata, 'storage, 'role> {
    fn check(&mut self) -> Result<crate::security_epoch::restore_original::RestoreObservation> {
        let auth = self
            .auth
            .as_mut()
            .context("native_restore_reservation_closed")?;
        let source = std::ptr::from_ref(&auth.source);
        let mut loan = ReservationSourceLoan {
            executor: ExecutionSourceLoan {
                action: &mut auth.action,
                original: &mut auth.original,
                completion: &mut auth.completion,
                record: &auth.record,
                operation: &auth.operation,
                time_operation: &auth.time_operation,
                refused: &mut auth.refused,
            },
            issuer: &mut self.issuer,
            keys: auth
                .historical_keys
                .as_mut()
                .context("restore_keys_not_retained")?,
            intent: &self.intent,
            view: &mut self.view,
            plan: &self.plan,
            current: &self.current,
            readiness: &self.readiness,
            at: self.at,
            source,
        };
        loan.check(&mut auth.source)
    }

    fn reserve(mut self) -> Result<FencedRestoreContinuation<'metadata, 'storage, 'role>> {
        let requested = (|| {
            self.check()?;
            let (observed, confirmation) = {
                let auth = self
                    .auth
                    .as_mut()
                    .context("native_restore_reservation_closed")?;
                let publication =
                    crate::security_epoch::restore_approval::publication::Publication::record_data(
                        &auth.action.reader.loan.selection,
                        auth.record.clone(),
                    )?;
                let source = std::ptr::from_ref(&auth.source);
                let mut loan = ReservationSourceLoan {
                    executor: ExecutionSourceLoan {
                        action: &mut auth.action,
                        original: &mut auth.original,
                        completion: &mut auth.completion,
                        record: &auth.record,
                        operation: &auth.operation,
                        time_operation: &auth.time_operation,
                        refused: &mut auth.refused,
                    },
                    issuer: &mut self.issuer,
                    keys: auth
                        .historical_keys
                        .as_mut()
                        .context("restore_keys_not_retained")?,
                    intent: &self.intent,
                    view: &mut self.view,
                    plan: &self.plan,
                    current: &self.current,
                    readiness: &self.readiness,
                    at: self.at,
                    source,
                };
                auth.source.reserve_restore(
                    &mut loan,
                    &self.plan,
                    &self.current,
                    self.at,
                    &publication,
                )?
            };
            self.check()?;
            let physical = self
                .auth
                .as_mut()
                .context("native_restore_reservation_closed")?
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            physical.announce_restore_fence(&self.stopped, &confirmation)?;
            self.check()?;
            let physical = self
                .auth
                .as_mut()
                .context("native_restore_reservation_closed")?
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            physical.await_restore_fence_confirmed(&self.stopped, &confirmation)?;
            self.check()?;
            self.auth
                .as_mut()
                .context("native_restore_reservation_closed")?
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?
                .require_restore_stopped(&self.stopped)?;
            Ok((observed, confirmation))
        })();
        let (observed, confirmation) = match requested {
            Ok(known) => known,
            Err(error) => {
                self.refuse();
                return Err(error);
            }
        };
        let mut owner = FencedRestoreContinuation {
            auth: self
                .auth
                .take()
                .context("native_restore_reservation_closed")?,
            issuer: self.issuer,
            plan: self.plan,
            observed,
            confirmation,
            authorization: self.current,
            stopped: self.stopped,
            writer_borrowed: std::cell::Cell::new(false),
            refused: std::rc::Rc::new(std::cell::Cell::new(false)),
            readiness: self.readiness,
            target_attempt: crate::security_epoch::restore_staging::RestoreDisposition::fresh(),
            settled_target: None,
            receiver_attempted: false,
            writer_attempt: crate::security_epoch::restore_staging::RestoreDisposition::fresh(),
        };
        owner.check_current()?;
        Ok(owner)
    }

    fn refuse(&mut self) {
        self.view.refuse();
        self.readiness.refuse();
        if let Some(auth) = &mut self.auth {
            auth.refuse();
        }
        self.issuer.refuse();
    }
}

// Compiler controls complement the exact owning-module API inventory. None of
// these retained owners/loans is reconstructible, transferable or serializable.
const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <LostRestoreLoan as Ambiguous<_>>::check;
            let _ = <RestoreTargetCheck<'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <TargetSettlementSourceLoan<'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <crate::security_epoch::storage_authority::RestoreCreatorRoot as Ambiguous<
                _,
            >>::check;

            let _ = <RestoreAttempt<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ExecutionSourceLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <crate::security_epoch::storage_authority::HistoricalKeyAvailability as Ambiguous<_>>::check;
            let _ =
                <ExecutionSourceLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <FencedRestoreContinuation<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreWriteLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreWriterConfirmation<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreWriterExchangeContext<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <LostRestoreWriterConfirmation as Ambiguous<_>>::check;
            let _ = <RestoreWriterActivationLoan<'static> as Ambiguous<_>>::check;
            let _ = <RestoreWriterReleaseLoan<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreFinalInstallationLoan<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <crate::security_epoch::restore_staging::RestoreControllerCohort as Ambiguous<_>>::check;
            let _ = <RestoreWriterActivated<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreControllerInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreIssuerCompletedInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreAppRoleActivatedInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreAppDecisionSentInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreAppPreparedConfirmationInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreControllerAcceptanceSentInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreAppInstalledConfirmationInstallation<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ControllerCurrentInstallationLoan<'static, 'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <IssuerFinishCall<'static> as Ambiguous<_>>::check;
            let _ = <IssuerFinishReply as Ambiguous<_>>::check;
            let _ = <FencedReadUnit<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <WriterReadUnit<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <WriterMayReadUnit<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <WriterRegistryLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <WriterMayRegistryLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <WriterConfirmationSourceLoan<'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <WriterSendSourceLoan<'static, 'static, 'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <FencedRegistryLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ReservationReadUnit<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ReservationRegistryLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ReservationSourceLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <NativeReservation<'static, 'static, 'static> as Ambiguous<_>>::check;
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
    use super::{LostRestoreLoan, require_activation_creator};
    use anyhow::Result;
    use quote::ToTokens as _;
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn losing_writer_confirmation_refuses_the_same_parent_cell_after_last_good_check() {
        let parent = Rc::new(Cell::new(false));
        {
            let _lost = super::LostRestoreWriterConfirmation {
                refused: Rc::clone(&parent),
            };
            assert!(!parent.get());
        }
        assert!(parent.get());
    }

    fn mutation_tokens(text: &str) -> Result<String> {
        // Match the same AST rendering as the selected method. A raw lexical
        // TokenStream can preserve joint punctuation such as `?;`, while syn
        // emits those statement tokens separately when quoting its AST.
        let text = text.trim();
        if text.starts_with('.') {
            let expression: syn::Expr =
                syn::parse_str(&format!("__restore_mutation_receiver{text}"))
                    .map_err(|_| anyhow::anyhow!("restore_mutation_fragment"))?;
            let rendered = expression.to_token_stream().to_string();
            return rendered
                .strip_prefix("__restore_mutation_receiver")
                .map(|suffix| suffix.trim_start().to_owned())
                .ok_or_else(|| anyhow::anyhow!("restore_mutation_receiver"));
        }
        let block: syn::Block = syn::parse_str(&format!("{{{text}}}"))
            .map_err(|_| anyhow::anyhow!("restore_mutation_fragment"))?;
        let mut tokens = proc_macro2::TokenStream::new();
        for statement in &block.stmts {
            statement.to_tokens(&mut tokens);
        }
        Ok(tokens.to_string())
    }

    fn staging_input_boundary(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let methods: Vec<_> = file.items.iter().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "RestoreWriteLoan")) => Some(item),
            _ => None,
        }).flat_map(|item| &item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "require_staging_input" => Some(item),
            _ => None,
        }).collect();
        if methods.len() != 1 {
            return Ok(false);
        }
        let expected: syn::Block = syn::parse_quote!({
            if self.owner.refused.get() {
                self.refuse();
                anyhow::bail!("native_restore_continuation_refused");
            }
            self.owner.refused.set(true);
            let requested = (|| {
                self.owner.check_current_inner()?;
                self.owner.plan.require_staging_input_data(
                    &self.owner.auth.action.reader.loan.selection,
                    intent,
                    namespace,
                )
            })();
            let checked = self.owner.check_current_inner();
            if requested.is_ok() && checked.is_ok() {
                self.owner.refused.set(false);
            } else {
                self.refuse();
            }
            requested?;
            checked.map(|_| ())
        });
        Ok(
            methods[0].block.to_token_stream().to_string()
                == expected.to_token_stream().to_string(),
        )
    }

    fn mutate_staging_input(source: &str, from: &str, to: &str) -> Result<String> {
        let mut file = syn::parse_file(source)?;
        let mut methods: Vec<_> = file.items.iter_mut().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "RestoreWriteLoan")) => Some(item),
            _ => None,
        }).flat_map(|item| &mut item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "require_staging_input" => Some(item),
            _ => None,
        }).collect();
        anyhow::ensure!(methods.len() == 1, "one actual staging-input method");
        let method = methods.remove(0);
        drop(methods);
        let body = method.block.to_token_stream().to_string();
        let (from, to) = (mutation_tokens(from)?, mutation_tokens(to)?);
        anyhow::ensure!(
            body.matches(&from).count() == 1,
            "one actual staging-boundary mutation target"
        );
        method.block = syn::parse_str(&body.replacen(&from, &to, 1))?;
        Ok(file.to_token_stream().to_string())
    }

    #[test]
    fn actual_staging_input_uses_the_same_owner_and_mandatory_post_before_clearing_refusal()
    -> Result<()> {
        let source = include_str!("stop.rs");
        assert!(staging_input_boundary(source)?);
        for (from, to) in [
            ("self.owner.refused.get()", "false"),
            (
                "self.owner.refused.set(true)",
                "self.owner.refused.set(false)",
            ),
            ("self.owner.check_current_inner()?;", "let _unchecked = ();"),
            (
                "let checked = self.owner.check_current_inner();",
                "let checked = Ok(());",
            ),
            (
                "self.owner.plan.require_staging_input_data",
                "self.owner.plan.unchecked_input_data",
            ),
            ("requested.is_ok() && checked.is_ok()", "requested.is_ok()"),
            ("requested?; checked.map(|_| ())", "checked.map(|_| ())"),
        ] {
            let mutant = mutate_staging_input(source, from, to)?;
            assert_ne!(source, mutant, "actual staging-input boundary target");
            assert!(!staging_input_boundary(&mutant)?);
        }
        Ok(())
    }

    #[test]
    fn staging_mutants_ignore_matching_text_in_an_earlier_source_method() -> Result<()> {
        let mut file = syn::parse_file(include_str!("stop.rs"))?;
        let actual = file.items.iter().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "RestoreWriteLoan")) => Some(item),
            _ => None,
        }).flat_map(|item| &item.items).find_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "require_staging_input" => Some(item.block.clone()),
            _ => None,
        }).ok_or_else(|| anyhow::anyhow!("actual_staging_input_method"))?;
        let earlier = file.items.iter_mut().find_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "AuthenticatedRestoreExecution")) => Some(item),
            _ => None,
        }).ok_or_else(|| anyhow::anyhow!("actual_executor_impl"))?;
        let mut noise: syn::ImplItemFn = syn::parse_quote!(
            fn earlier_input_shadow(&mut self) -> Result<()> {
                Ok(())
            }
        );
        // Parsed source only, never a compiled or constructed native owner.
        // A preceding historical-key checker may share this same result tail.
        noise.block = actual;
        earlier.items.insert(0, syn::ImplItem::Fn(noise));
        let shadowed = file.to_token_stream().to_string();
        assert!(staging_input_boundary(&shadowed)?);
        for (from, to) in [
            ("self.owner.refused.get()", "false"),
            (
                "self.owner.refused.set(true)",
                "self.owner.refused.set(false)",
            ),
            (
                "let checked = self.owner.check_current_inner();",
                "let checked = Ok(());",
            ),
            ("requested?; checked.map(|_| ())", "checked.map(|_| ())"),
        ] {
            assert!(!staging_input_boundary(&mutate_staging_input(
                &shadowed, from, to
            )?)?);
        }
        Ok(())
    }

    fn creator_root_boundary(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let methods: Vec<_> = file.items.iter().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "RestoreWriteLoan")) => Some(item),
            _ => None,
        }).flat_map(|item| &item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "admit_creator_root" => Some(item),
            _ => None,
        }).collect();
        if methods.len() != 1 {
            return Ok(false);
        }
        let expected: syn::Block = syn::parse_quote!({
            if self.owner.refused.get() {
                self.refuse();
                anyhow::bail!("native_restore_continuation_refused");
            }
            self.owner.refused.set(true);
            let requested = (|| {
                self.owner.check_current_inner()?;
                self.owner
                    .auth
                    .action
                    .reader
                    .loan
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?
                    .admit_restore_creator_root(held_root)
            })();
            let checked = self.owner.check_current_inner();
            if requested.is_ok() && checked.is_ok() {
                self.owner.refused.set(false);
            } else {
                self.refuse();
            }
            let root = requested?;
            checked?;
            Ok(root)
        });
        Ok(
            methods[0].block.to_token_stream().to_string()
                == expected.to_token_stream().to_string(),
        )
    }

    fn mutate_creator_root(source: &str, from: &str, to: &str) -> Result<String> {
        let mut file = syn::parse_file(source)?;
        let mut methods: Vec<_> = file.items.iter_mut().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "RestoreWriteLoan")) => Some(item),
            _ => None,
        }).flat_map(|item| &mut item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "admit_creator_root" => Some(item),
            _ => None,
        }).collect();
        anyhow::ensure!(methods.len() == 1, "one actual root-admission method");
        let method = methods.remove(0);
        drop(methods);
        let body = method.block.to_token_stream().to_string();
        let (from, to) = (mutation_tokens(from)?, mutation_tokens(to)?);
        anyhow::ensure!(
            body.matches(&from).count() == 1,
            "one actual root-boundary mutation target"
        );
        method.block = syn::parse_str(&body.replacen(&from, &to, 1))?;
        Ok(file.to_token_stream().to_string())
    }

    #[test]
    fn actual_creator_root_admission_keeps_same_fenced_owner_and_post_before_publication()
    -> Result<()> {
        let source = include_str!("stop.rs");
        assert!(creator_root_boundary(source)?);
        for (from, to) in [
            ("self.owner.refused.get()", "false"),
            (
                "self.owner.refused.set(true)",
                "self.owner.refused.set(false)",
            ),
            ("self.owner.check_current_inner()?;", "let _unchecked = ();"),
            (
                ".admit_restore_creator_root(held_root)",
                ".admit_restore_creator_root(other_root)",
            ),
            (
                "let checked = self.owner.check_current_inner();",
                "let checked = Ok(());",
            ),
            ("requested.is_ok() && checked.is_ok()", "requested.is_ok()"),
            ("let root = requested?; checked?;", "let root = requested?;"),
        ] {
            let mutant = mutate_creator_root(source, from, to)?;
            assert_ne!(source, mutant, "actual creator-root boundary target");
            assert!(!creator_root_boundary(&mutant)?);
        }
        Ok(())
    }

    #[test]
    fn root_boundary_mutants_ignore_identical_guards_in_an_earlier_method() -> Result<()> {
        let mut file = syn::parse_file(include_str!("stop.rs"))?;
        let loan = file.items.iter_mut().find_map(|item| match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(), syn::Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "RestoreWriteLoan")) => Some(item),
            _ => None,
        }).ok_or_else(|| anyhow::anyhow!("actual_restore_loan_impl"))?;
        let root = loan
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "admit_creator_root" => {
                    Some(item.block.clone())
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("actual_creator_root_method"))?;
        let earlier = loan
            .items
            .iter_mut()
            .find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "require_staging_input" => Some(item),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("actual_staging_input_method"))?;
        // Parsed source only: identical earlier text must never divert the
        // mutation away from the named production method. No fixture owner is
        // constructed and this source is not compiled as a native supplier.
        earlier.block = root;
        let shadowed = file.to_token_stream().to_string();
        assert!(creator_root_boundary(&shadowed)?);
        for (from, to) in [
            ("self.owner.refused.get()", "false"),
            (
                "self.owner.refused.set(true)",
                "self.owner.refused.set(false)",
            ),
            ("self.owner.check_current_inner()?;", "let _unchecked = ();"),
            (
                "let checked = self.owner.check_current_inner();",
                "let checked = Ok(());",
            ),
        ] {
            assert!(!creator_root_boundary(&mutate_creator_root(
                &shadowed, from, to
            )?)?);
        }
        Ok(())
    }

    #[test]
    fn mutation_fragments_match_actual_ast_with_or_without_joint_question_semicolon() -> Result<()>
    {
        let source = include_str!("stop.rs");
        for fragment in [
            "self.owner.check_current_inner()?;",
            "self.owner.check_current_inner() ? ;",
        ] {
            assert!(!staging_input_boundary(&mutate_staging_input(
                source,
                fragment,
                "let _unchecked = (); "
            )?)?);
            assert!(!creator_root_boundary(&mutate_creator_root(
                source,
                fragment,
                "let _unchecked = (); "
            )?)?);
        }
        for fragment in [
            "let root = requested?; checked?;",
            "let root = requested ? ; checked ? ;",
        ] {
            assert!(!creator_root_boundary(&mutate_creator_root(
                source,
                fragment,
                "let root = requested?;"
            )?)?);
        }
        for fragment in [
            "requested?; checked.map(|_| ())",
            "requested ? ; checked.map(|_| ())",
        ] {
            assert!(!staging_input_boundary(&mutate_staging_input(
                source,
                fragment,
                "checked.map(|_| ())"
            )?)?);
        }
        Ok(())
    }
    fn attempt_factory_boundary(source: &str) -> Result<bool> {
        let actual = source_method(
            source,
            "AuthenticatedRestoreExecution",
            "begin_restore_attempt",
        )?;
        let expected: syn::Block = syn::parse_quote!({
            let requested = (|| {
                self.require_historical_keys(intent)?;
                self.completion.record_attempt(
                    &mut self.action.reader,
                    (
                        self.action
                            .sqlite
                            .as_mut()
                            .context("restore_auth_sqlite_closed")?,
                        &mut self.action.files,
                    ),
                )
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked?;
            Ok(RestoreAttempt {
                auth: Some(self),
                intent: intent.clone(),
                refused: false,
            })
        });
        Ok(actual.to_token_stream().to_string() == expected.to_token_stream().to_string())
    }

    #[test]
    fn actual_attempt_factory_owns_the_executor_and_original_after_closed_claim_unit() -> Result<()>
    {
        let source = include_str!("stop.rs");
        assert!(attempt_factory_boundary(source)?);
        for (from, to) in [
            (
                "self.require_historical_keys(intent)?;",
                "let _unchecked = ();",
            ),
            (
                "self.completion.record_attempt",
                "self.completion.unchecked_attempt",
            ),
            ("let checked = self.check();", "let checked = Ok(());"),
            ("Some(self)", "None"),
            ("checked?;", "let _ = checked;"),
        ] {
            let changed = archive_binding_mutant(source, "begin_restore_attempt", from, to)?;
            assert_ne!(source, changed, "actual target {from}");
            assert!(
                !attempt_factory_boundary(&changed)?,
                "actual mutation {from}"
            );
        }
        Ok(())
    }

    #[test]
    fn actual_attempt_loss_and_incomplete_check_refuse_the_same_executor() -> Result<()> {
        let source = include_str!("stop.rs");
        let check = source_method(source, "RestoreAttempt", "check")?;
        let expected: syn::Block = syn::parse_quote!({
            let auth = self.auth.as_mut().context("restore_attempt_owner_closed")?;
            if self.refused {
                auth.refuse();
                anyhow::bail!("restore_attempt_refused");
            }
            self.refused = true;
            let requested = auth.require_historical_keys(&self.intent);
            let checked = auth.check();
            if requested.is_err() || checked.is_err() {
                auth.refuse();
            }
            requested?;
            let observed = checked?;
            self.refused = false;
            Ok(observed)
        });
        assert_eq!(
            check.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let parsed = syn::parse_file(source)?;
        let owner = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RestoreAttempt" => Some(item),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("actual attempt owner"))?;
        let auth = owner
            .fields
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|name| name == "auth"))
            .ok_or_else(|| anyhow::anyhow!("actual retained executor field"))?;
        let expected_type: syn::Type =
            syn::parse_quote!(Option<AuthenticatedRestoreExecution<'metadata, 'storage, 'role>>);
        assert_eq!(
            auth.ty.to_token_stream().to_string(),
            expected_type.to_token_stream().to_string()
        );
        assert!(source_method(source, "RestoreAttempt", "drop").is_err());
        let drop = source_method(
            include_str!("../../../../../../restore_original.rs"),
            "RestoreOriginalGuard",
            "drop",
        )?;
        let expected: syn::Block = syn::parse_quote!({
            self.refuse();
        });
        assert_eq!(
            drop.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        Ok(())
    }

    fn source_method(source: &str, owner: &str, name: &str) -> Result<syn::Block> {
        let mut found = Vec::new();
        for item in syn::parse_file(source)?.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let syn::Type::Path(path) = &*item.self_ty else {
                continue;
            };
            if !path
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == owner)
            {
                continue;
            }
            for member in item.items {
                if let syn::ImplItem::Fn(method) = member
                    && method.sig.ident == name
                {
                    found.push(method.block);
                }
            }
        }
        anyhow::ensure!(found.len() == 1, "one actual owning method required");
        Ok(found.remove(0))
    }

    pub(super) fn archive_block_tokens(mut block: syn::Block) -> String {
        fn expression(node: &mut syn::Expr) {
            match node {
                syn::Expr::Call(call) => {
                    expression(&mut call.func);
                    for argument in &mut call.args {
                        expression(argument);
                    }
                    call.args.pop_punct();
                }
                syn::Expr::MethodCall(call) => {
                    expression(&mut call.receiver);
                    for argument in &mut call.args {
                        expression(argument);
                    }
                    call.args.pop_punct();
                }
                syn::Expr::Tuple(tuple) => {
                    for element in &mut tuple.elems {
                        expression(element);
                    }
                    if tuple.elems.len() != 1 {
                        tuple.elems.pop_punct();
                    }
                }
                syn::Expr::Array(array) => {
                    for element in &mut array.elems {
                        expression(element);
                    }
                    array.elems.pop_punct();
                }
                syn::Expr::Struct(value) => {
                    for field in &mut value.fields {
                        expression(&mut field.expr);
                    }
                    if let Some(rest) = &mut value.rest {
                        expression(rest);
                    }
                    // Keep the mandatory field/rest separator. Removing it
                    // could turn a value plus `..base` into a range value.
                    if value.rest.is_none() {
                        value.fields.pop_punct();
                    }
                }
                syn::Expr::Match(value) => {
                    expression(&mut value.expr);
                    for arm in &mut value.arms {
                        if let Some((_, guard)) = &mut arm.guard {
                            expression(guard);
                        }
                        expression(&mut arm.body);
                        arm.comma = Some(Default::default());
                    }
                }
                syn::Expr::ForLoop(node) => {
                    expression(&mut node.expr);
                    normalize(&mut node.body);
                }
                syn::Expr::Try(node) => expression(&mut node.expr),
                syn::Expr::Reference(node) => expression(&mut node.expr),
                syn::Expr::Paren(node) => expression(&mut node.expr),
                syn::Expr::Closure(node) => expression(&mut node.body),
                syn::Expr::Block(node) => normalize(&mut node.block),
                syn::Expr::If(node) => {
                    expression(&mut node.cond);
                    normalize(&mut node.then_branch);
                    if let Some((_, otherwise)) = &mut node.else_branch {
                        expression(otherwise);
                    }
                }
                syn::Expr::Binary(node) => {
                    expression(&mut node.left);
                    expression(&mut node.right);
                }
                _ => {}
            }
        }
        fn normalize(block: &mut syn::Block) {
            for statement in &mut block.stmts {
                match statement {
                    syn::Stmt::Local(local) => {
                        if let Some(init) = &mut local.init {
                            expression(&mut init.expr);
                        }
                    }
                    syn::Stmt::Expr(node, _) => expression(node),
                    _ => {}
                }
            }
        }
        normalize(&mut block);
        block.to_token_stream().to_string()
    }

    fn archive_binding_source(source: &str) -> Result<bool> {
        use syn::parse::Parser as _;
        let body = source_method(
            source,
            "AuthenticatedRestoreExecution",
            "restore_archive_binding_data",
        )?;
        let statements = |text: &str| -> Result<Vec<String>> {
            let block: syn::Block = syn::parse_str(text)?;
            Ok(block
                .stmts
                .iter()
                .map(|s| {
                    archive_block_tokens(syn::Block {
                        brace_token: Default::default(),
                        stmts: vec![s.clone()],
                    })
                })
                .collect())
        };
        if body.stmts.len() != 6 {
            return Ok(false);
        }
        let expected_tail = statements(
            "{ let checked = self.check(); if requested.is_err() || checked.is_err() { self.refuse(); } let data = requested?; checked?; Ok(data) }",
        )?;
        if body.stmts[1..]
            .iter()
            .map(|s| {
                archive_block_tokens(syn::Block {
                    brace_token: Default::default(),
                    stmts: vec![s.clone()],
                })
            })
            .collect::<Vec<_>>()
            != expected_tail
        {
            return Ok(false);
        }
        let syn::Stmt::Local(requested) = &body.stmts[0] else {
            return Ok(false);
        };
        if !matches!(&requested.pat,syn::Pat::Ident(p)if p.ident=="requested") {
            return Ok(false);
        }
        let Some(init) = &requested.init else {
            return Ok(false);
        };
        let syn::Expr::Call(call) = &*init.expr else {
            return Ok(false);
        };
        let syn::Expr::Paren(callee) = &*call.func else {
            return Ok(false);
        };
        let syn::Expr::Closure(closure) = &*callee.expr else {
            return Ok(false);
        };
        let syn::Expr::Block(prepared) = &*closure.body else {
            return Ok(false);
        };
        let inner = &prepared.block.stmts;
        if inner.len() != 10 {
            return Ok(false);
        }
        let expected = statements(
            "{ self.require_historical_keys(intent)?; let selected = self.action.reader.loan.selection.clone(); let approved = &self.record.statement.request.target; let namespace = day2_capabilities::credentials::Namespace { installation: approved.scope.installation.clone(), environment: approved.scope.environment.clone(), app: approved.scope.app.clone(), binding_generation: approved.binding_generation, }; namespace.validate()?; self.source.require_qualified(&self.time_operation)?; let time = self.source.current_time(&mut self.action)?; let at = approval_window(&self.record, &time)?; Ok((selected, namespace, at, crate::security_epoch::storage_authority::restore_staging_root_path_data())) }",
        )?;
        let retained: Vec<_> = inner
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 3)
            .map(|(_, s)| {
                archive_block_tokens(syn::Block {
                    brace_token: Default::default(),
                    stmts: vec![s.clone()],
                })
            })
            .collect();
        if retained != expected {
            return Ok(false);
        }
        let syn::Stmt::Macro(guard) = &inner[3] else {
            return Ok(false);
        };
        if !guard.mac.path.is_ident("ensure") {
            return Ok(false);
        }
        let args = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
            .parse2(guard.mac.tokens.clone())?;
        let expected = syn::punctuated::Punctuated::<syn::Expr,syn::Token![,]>::parse_terminated.parse_str("approved.scope == selected.scope && approved.selection == Digest::of(&selected)? && approved.authority == selected.authority_key()? && approved.security_epoch == 2, \"restore_archive_approved_selection_changed\"")?;
        Ok(args
            .iter()
            .map(|a| a.to_token_stream().to_string())
            .collect::<Vec<_>>()
            == expected
                .iter()
                .map(|a| a.to_token_stream().to_string())
                .collect::<Vec<_>>())
    }

    fn archive_binding_mutant(source: &str, name: &str, from: &str, to: &str) -> Result<String> {
        let mut file = syn::parse_file(source)?;
        let mut count = 0;
        for item in &mut file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty,syn::Type::Path(p)if p.path.segments.last().is_some_and(|s|s.ident=="AuthenticatedRestoreExecution"))
            {
                for method in &mut item.items {
                    if let syn::ImplItem::Fn(method) = method
                        && method.sig.ident == name
                    {
                        count += 1;
                        let body = method.block.to_token_stream().to_string();
                        let (from, to) = (mutation_tokens(from)?, mutation_tokens(to)?);
                        anyhow::ensure!(
                            body.matches(&from).count() == 1,
                            "one actual archive-binding mutation"
                        );
                        method.block = syn::parse_str(&body.replacen(&from, &to, 1))?;
                    }
                }
            }
        }
        anyhow::ensure!(count == 1, "one actual archive-binding method");
        Ok(file.to_token_stream().to_string())
    }

    #[test]
    fn archive_binding_data_comes_from_actual_owner_approval_and_qualified_time() -> Result<()> {
        assert!(archive_binding_source(include_str!("stop.rs"))?);
        Ok(())
    }

    #[test]
    fn archive_binding_rejects_bypassed_keys_foreign_generation_and_lost_postchecks() -> Result<()>
    {
        let source = include_str!("stop.rs");
        for (from, to) in [
            ("self.require_historical_keys(intent)?;", "let _ = intent;"),
            (
                "self.action.reader.loan.selection.clone()",
                "untrusted_selection.clone()",
            ),
            ("approved.binding_generation", "1"),
            (
                "crate::security_epoch::storage_authority::restore_staging_root_path_data()",
                "untrusted_root.clone()",
            ),
            ("approved.scope == selected.scope", "true"),
            (
                "self.source.require_qualified(&self.time_operation)?;",
                "let _ = ();",
            ),
            (
                "self.source.current_time(&mut self.action)?",
                "unqualified_time",
            ),
            ("approval_window(&self.record, &time)?", "0"),
            ("let checked = self.check();", "let checked = Ok(());"),
            (
                "requested.is_err() || checked.is_err()",
                "requested.is_err()",
            ),
            ("self.refuse();", "let _ = ();"),
            ("checked?;", "let _ = checked;"),
        ] {
            assert!(!archive_binding_source(&archive_binding_mutant(
                source,
                "restore_archive_binding_data",
                from,
                to
            )?)?);
        }
        Ok(())
    }

    fn archive_local_source(source: &str) -> Result<bool> {
        let body = source_method(
            source,
            "AuthenticatedRestoreExecution",
            "check_archive_local",
        )?;
        let expected: syn::Block = syn::parse_quote!({
            if self.refused {
                self.refuse();
                anyhow::bail!("restore_executor_refused");
            }
            let requested: Result<()> = (|| {
                self.action.check_local()?;
                self.action
                    .intent
                    .require_exact(&self.record.statement.request.intent())?;
                self.historical_keys
                    .as_mut()
                    .context("restore_keys_not_retained")?
                    .require(intent, &self.record, &self.operation)?;
                let physical = self
                    .action
                    .reader
                    .loan
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?;
                self.original.check_join(
                    physical.controller_stage()?,
                    &self.record.statement.request,
                    &self.operation,
                )?;
                self.source.require_qualified(&self.time_operation)?;
                let time = self.source.current_fenced_time(physical)?;
                approval_window(&self.record, &time)?;
                Ok(())
            })();
            let local = self.action.check_local();
            let joined = (|| {
                let physical = self
                    .action
                    .reader
                    .loan
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?;
                self.original.check_join(
                    physical.controller_stage()?,
                    &self.record.statement.request,
                    &self.operation,
                )
            })();
            if requested.is_err() || local.is_err() || joined.is_err() {
                self.refuse();
            }
            requested?;
            local?;
            joined
        });
        Ok(archive_block_tokens(body) == archive_block_tokens(expected))
    }

    #[test]
    fn actual_archive_local_check_keeps_keys_original_and_independent_posts_without_remote_reads()
    -> Result<()> {
        assert!(archive_local_source(include_str!("stop.rs"))?);
        Ok(())
    }

    #[test]
    fn archive_local_guard_rejects_lost_posts_new_time_qualification_and_wrong_original()
    -> Result<()> {
        let source = include_str!("stop.rs");
        for (from, to) in [
            ("self.refused", "false"),
            ("self.action.check_local()?;", "let _ = ();"),
            (
                ".require(intent, &self.record, &self.operation)",
                ".require(other_intent, &self.record, &self.operation)",
            ),
            (
                "self.source.require_qualified(&self.time_operation)?;",
                "let _ = ();",
            ),
            (
                "self.source.current_fenced_time(physical)?",
                "self.source.qualify_time(physical)?",
            ),
            ("approval_window(&self.record, &time)?;", "let _ = time;"),
            (
                "let local = self.action.check_local();",
                "let local = Ok(());",
            ),
            (
                "requested.is_err() || local.is_err() || joined.is_err()",
                "requested.is_err()",
            ),
            ("local?;", "let _ = local;"),
        ] {
            assert!(!archive_local_source(&archive_binding_mutant(
                source,
                "check_archive_local",
                from,
                to
            )?)?);
        }
        Ok(())
    }

    fn source_loan_wiring(parent: &str, leaf: &str) -> Result<bool> {
        let delegate = source_method(parent, "AuthenticatedRestoreExecution", "check")?;
        let expected_delegate: syn::Block = syn::parse_quote!({ self.check_source() });
        if delegate.to_token_stream().to_string() != expected_delegate.to_token_stream().to_string()
        {
            return Ok(false);
        }
        let borrow = source_method(leaf, "AuthenticatedRestoreExecution", "check_source")?;
        let expected_borrow: syn::Block = syn::parse_quote!({
            ExecutionSourceLoan {
                action: &mut self.action,
                original: &mut self.original,
                completion: &mut self.completion,
                record: &self.record,
                operation: &self.operation,
                time_operation: &self.time_operation,
                refused: &mut self.refused,
            }
            .check(&mut self.source)
        });
        if borrow.to_token_stream().to_string() != expected_borrow.to_token_stream().to_string() {
            return Ok(false);
        }
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'ast> syn::visit::Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0.push(call.method.to_string());
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func
                    && let Some(name) = path.path.get_ident()
                {
                    self.0.push(name.to_string());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let body = source_method(leaf, "ExecutionSourceLoan", "check")?;
        // The mandatory postcheck is a direct top-level call, including when
        // requested already failed; a closure gated on requested is not equal.
        let Some(syn::Stmt::Local(checked)) = body.stmts.get(1) else {
            return Ok(false);
        };
        let syn::Pat::Ident(binding) = &checked.pat else {
            return Ok(false);
        };
        let Some(initializer) = &checked.init else {
            return Ok(false);
        };
        let syn::Expr::MethodCall(call) = &*initializer.expr else {
            return Ok(false);
        };
        let arguments: Vec<_> = call
            .args
            .iter()
            .map(|argument| argument.to_token_stream().to_string())
            .collect();
        if binding.ident != "checked"
            || initializer.diverge.is_some()
            || call.method != "check_execution_original"
            || call.receiver.to_token_stream().to_string() != "self . action"
            || arguments != ["self . original", "self . record", "self . operation"]
        {
            return Ok(false);
        }
        let Some(syn::Stmt::Local(requested)) = body.stmts.first() else {
            return Ok(false);
        };
        let Some(initializer) = &requested.init else {
            return Ok(false);
        };
        let syn::Expr::Call(call) = &*initializer.expr else {
            return Ok(false);
        };
        // The production immediately-invoked closure is parenthesized in
        // syn; inspect that actual callee before checking its closure body.
        let syn::Expr::Paren(callee) = &*call.func else {
            return Ok(false);
        };
        let syn::Expr::Closure(closure) = &*callee.expr else {
            return Ok(false);
        };
        let syn::Expr::Block(requested) = &*closure.body else {
            return Ok(false);
        };
        let Some(syn::Stmt::Macro(guard)) = requested.block.stmts.first() else {
            return Ok(false);
        };
        if !guard.mac.path.is_ident("ensure") {
            return Ok(false);
        }
        use syn::parse::Parser as _;
        let arguments = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
            .parse2(guard.mac.tokens.clone())?;
        let expected: syn::Expr = syn::parse_quote!(!*self.refused);
        let code: syn::Expr = syn::parse_quote!("restore_executor_refused");
        if arguments.len() != 2
            || arguments
                .first()
                .map(|argument| argument.to_token_stream().to_string())
                != Some(expected.to_token_stream().to_string())
            || arguments
                .last()
                .map(|argument| argument.to_token_stream().to_string())
                != Some(code.to_token_stream().to_string())
        {
            return Ok(false);
        }
        let mut calls = Calls::default();
        syn::visit::Visit::visit_block(&mut calls, &body);
        let relevant = [
            "check_execution_original",
            "check_current",
            "require_qualified",
            "current_time",
            "approval_window",
            "is_err",
            "refuse",
        ];
        let flow: Vec<_> = calls
            .0
            .iter()
            .filter(|name| relevant.contains(&name.as_str()))
            .map(String::as_str)
            .collect();
        if flow
            != [
                "check_execution_original",
                "check_current",
                "require_qualified",
                "current_time",
                "approval_window",
                "check_execution_original",
                "is_err",
                "is_err",
                "refuse",
                "refuse",
            ]
        {
            return Ok(false);
        }
        if calls.0.iter().any(|name| {
            ["begin", "capture", "narrow", "authenticate", "clone"].contains(&name.as_str())
        }) || body.stmts.len() != 5
        {
            return Ok(false);
        }
        let refusal: syn::Stmt = syn::parse_quote! {
            if requested.is_err() || checked.is_err() {
                *self.refused = true;
                self.original.refuse();
                self.action.refuse();
            }
        };
        let primary: syn::Stmt = syn::parse_quote! { requested?; };
        let post = syn::Stmt::Expr(syn::parse_quote! { checked }, None);
        Ok(
            body.stmts[2].to_token_stream().to_string() == refusal.to_token_stream().to_string()
                && body.stmts[3].to_token_stream().to_string()
                    == primary.to_token_stream().to_string()
                && body.stmts[4].to_token_stream().to_string()
                    == post.to_token_stream().to_string(),
        )
    }

    #[test]
    fn actual_executor_borrows_its_own_fields_and_source_with_original_postcheck() -> Result<()> {
        let parent = include_str!("../consumer.rs");
        let leaf = include_str!("stop.rs");
        assert!(source_loan_wiring(parent, leaf)?);
        let duplicate = parent.replacen(
            "self.check_source()",
            "self.check_source()?; self.check_source()",
            1,
        );
        assert_ne!(parent, duplicate);
        assert!(!source_loan_wiring(&duplicate, leaf)?);
        let mut conditional = syn::parse_file(leaf)?;
        let mut replacements = 0;
        for item in &mut conditional.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            let syn::Type::Path(path) = &*item.self_ty else {
                continue;
            };
            if !path
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == "ExecutionSourceLoan")
            {
                continue;
            }
            for member in &mut item.items {
                let syn::ImplItem::Fn(method) = member else {
                    continue;
                };
                if method.sig.ident != "check" {
                    continue;
                }
                method.block.stmts[1] = syn::parse_quote! {
                    let checked = (|| {
                        requested.as_ref().map_err(|_| anyhow::anyhow!("skip"))?;
                        self.action.check_execution_original(self.original, self.record, self.operation)
                    })();
                };
                replacements += 1;
            }
        }
        assert_eq!(replacements, 1, "actual unconditional production postcheck");
        assert!(!source_loan_wiring(
            parent,
            &conditional.to_token_stream().to_string()
        )?);
        let wrong_borrow = leaf.replacen("refused: &mut self.refused,", "refused: &mut false,", 1);
        assert_ne!(leaf, wrong_borrow, "actual source-loan constructor target");
        assert!(!source_loan_wiring(parent, &wrong_borrow)?);
        // Mutate the actual check body, not the first matching text elsewhere
        // in this owning module. New fixed methods may contain the same guards.
        for cut in 0..6 {
            let mut changed = syn::parse_file(leaf)?;
            let mut targets = 0;
            for item in &mut changed.items {
                let syn::Item::Impl(item) = item else {
                    continue;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "ExecutionSourceLoan"))
                {
                    continue;
                }
                for member in &mut item.items {
                    let syn::ImplItem::Fn(method) = member else {
                        continue;
                    };
                    if method.sig.ident != "check" {
                        continue;
                    }
                    targets += 1;
                    let body = &mut method.block;
                    match cut {
                        0..=2 => {
                            let syn::Stmt::Local(local) = &mut body.stmts[0] else {
                                unreachable!()
                            };
                            let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr
                            else {
                                unreachable!()
                            };
                            let syn::Expr::Paren(callee) = &mut *call.func else {
                                unreachable!()
                            };
                            let syn::Expr::Closure(closure) = &mut *callee.expr else {
                                unreachable!()
                            };
                            let syn::Expr::Block(requested) = &mut *closure.body else {
                                unreachable!()
                            };
                            if cut == 0 {
                                requested.block.stmts[0] = syn::parse_quote! { ensure!(true, "restore_executor_refused"); };
                            } else {
                                let target: syn::Stmt = if cut == 1 {
                                    syn::parse_quote! { source.require_qualified(self.time_operation)?; }
                                } else {
                                    syn::parse_quote! { approval_window(self.record, &time)?; }
                                };
                                let before = requested.block.stmts.len();
                                requested.block.stmts.retain(|stmt| {
                                    stmt.to_token_stream().to_string()
                                        != target.to_token_stream().to_string()
                                });
                                assert_eq!(
                                    requested.block.stmts.len() + 1,
                                    before,
                                    "one actual required check"
                                );
                            }
                        }
                        3 => {
                            body.stmts[2] = syn::parse_quote! {
                                if requested.is_err() {
                                    *self.refused = true;
                                    self.original.refuse();
                                    self.action.refuse();
                                }
                            }
                        }
                        4 => {
                            let syn::Stmt::Expr(syn::Expr::If(refusal), _) = &mut body.stmts[2]
                            else {
                                unreachable!()
                            };
                            let target: syn::Stmt = syn::parse_quote! { self.original.refuse(); };
                            let before = refusal.then_branch.stmts.len();
                            refusal.then_branch.stmts.retain(|stmt| {
                                stmt.to_token_stream().to_string()
                                    != target.to_token_stream().to_string()
                            });
                            assert_eq!(
                                refusal.then_branch.stmts.len() + 1,
                                before,
                                "one actual original refusal"
                            );
                        }
                        5 => {
                            body.stmts[3] = syn::parse_quote! { checked?; };
                            body.stmts[4] = syn::Stmt::Expr(
                                syn::parse_quote! { requested.map(|_| unreachable!()) },
                                None,
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }
            assert_eq!(targets, 1, "one actual execution-source checker");
            assert!(
                !source_loan_wiring(parent, &changed.to_token_stream().to_string())?,
                "actual checker mutation {cut}"
            );
        }
        Ok(())
    }

    #[test]
    fn actual_negative_loan_owner_refuses_after_last_good_check_or_unwind() {
        for unwind in [false, true] {
            let refused = Rc::new(Cell::new(false));
            let lost = LostRestoreLoan {
                refused: Rc::clone(&refused),
            };
            // A preceding successful checker cannot settle the loan itself.
            refused.set(true);
            refused.set(false);
            if unwind {
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _lost = lost;
                    panic!("lost restore-loan fixture");
                }));
                assert!(caught.is_err());
            } else {
                drop(lost);
            }
            assert!(refused.get());
        }
    }

    fn retained_refusal_boundary(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let owner = file.items.iter().find_map(|item| match item {
            syn::Item::Impl(item) if item.trait_.is_none()
                && matches!(item.self_ty.as_ref(), syn::Type::Path(t) if t.path.segments.last().is_some_and(|s|s.ident=="FencedRestoreContinuation")) => Some(item),
            _ => None,
        }).unwrap();
        for (method, inner) in [
            ("check_local", "check_local_inner"),
            ("check_current", "check_current_inner"),
        ] {
            let actual = owner
                .items
                .iter()
                .find_map(|item| match item {
                    syn::ImplItem::Fn(f) if f.sig.ident == method => Some(&f.block),
                    _ => None,
                })
                .unwrap();
            let inner = syn::Ident::new(inner, proc_macro2::Span::call_site());
            let expected: syn::Block = syn::parse_quote!({
                if self.refused.get() {
                    self.refuse();
                    anyhow::bail!("native_restore_continuation_refused");
                }
                self.refused.set(true);
                let result = self.#inner();
                if result.is_ok() {
                    self.refused.set(false);
                } else {
                    self.refuse();
                }
                result
            });
            if actual.to_token_stream().to_string() != expected.to_token_stream().to_string() {
                return Ok(false);
            }
        }
        let loan = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RestoreWriteLoan" => Some(item),
                _ => None,
            })
            .unwrap();
        if !loan.fields.iter().any(|f| {
            f.ident.as_ref().is_some_and(|i| i == "_lost")
                && f.ty.to_token_stream().to_string() == "LostRestoreLoan"
        }) {
            return Ok(false);
        }
        let borrow = owner
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(f) if f.sig.ident == "borrow_write" => Some(&f.block),
                _ => None,
            })
            .unwrap();
        let expected: syn::Block = syn::parse_quote!({
            if self.writer_borrowed.replace(true) {
                self.refuse();
                anyhow::bail!("native_restore_writer_loan_spent");
            }
            self.check_current()?;
            let lost = LostRestoreLoan {
                refused: Rc::clone(&self.refused),
            };
            Ok(RestoreWriteLoan {
                owner: self,
                _lost: lost,
            })
        });
        if borrow.to_token_stream().to_string() != expected.to_token_stream().to_string() {
            return Ok(false);
        }
        Ok(true)
    }

    #[test]
    fn actual_continuation_spends_before_every_checker_and_carries_lost_loan_refusal() -> Result<()>
    {
        let source = include_str!("stop.rs");
        assert!(retained_refusal_boundary(source)?);
        for (method, old, new) in [
            ("check_local", "self.refused.get()", "false"),
            ("check_current", "self.refused.get()", "false"),
            (
                "check_local",
                "self.refused.set(true);\n        let result = self.check_local_inner();",
                "let result = self.check_local_inner();",
            ),
            (
                "check_current",
                "self.refused.set(true);\n        let result = self.check_current_inner();",
                "let result = self.check_current_inner();",
            ),
            ("check_local", "result.is_ok()", "true"),
            ("check_current", "result.is_ok()", "true"),
            (
                "borrow_write",
                "writer_borrowed.replace(true)",
                "writer_borrowed.replace(false)",
            ),
        ] {
            let mut file = syn::parse_file(source)?;
            let mut changed = 0;
            for item in &mut file.items {
                let syn::Item::Impl(item) = item else {
                    continue;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident=="FencedRestoreContinuation"))
                {
                    continue;
                }
                for member in &mut item.items {
                    let syn::ImplItem::Fn(member) = member else {
                        continue;
                    };
                    if member.sig.ident != method {
                        continue;
                    }
                    let body = member.block.to_token_stream().to_string();
                    let from = mutation_tokens(old)?;
                    anyhow::ensure!(
                        body.matches(&from).count() == 1,
                        "one actual continuation target"
                    );
                    member.block =
                        syn::parse_str(&body.replacen(&from, &mutation_tokens(new)?, 1))?;
                    changed += 1;
                }
            }
            anyhow::ensure!(changed == 1, "one actual continuation method");
            let mutant = file.to_token_stream().to_string();
            assert!(!retained_refusal_boundary(&mutant)?);
        }
        let mut file = syn::parse_file(source)?;
        let mut changed = 0;
        for item in &mut file.items {
            if let syn::Item::Struct(item) = item
                && item.ident == "RestoreWriteLoan"
            {
                for field in &mut item.fields {
                    if field.ident.as_ref().is_some_and(|name| name == "_lost") {
                        field.ty = syn::parse_quote!(bool);
                        changed += 1;
                    }
                }
            }
        }
        assert_eq!(changed, 1);
        assert!(!retained_refusal_boundary(
            &file.to_token_stream().to_string()
        )?);
        let mut file = syn::parse_file(source)?;
        let mut changed = 0;
        for item in &mut file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident=="FencedRestoreContinuation"))
            {
                continue;
            }
            for member in &mut item.items {
                let syn::ImplItem::Fn(member) = member else {
                    continue;
                };
                if member.sig.ident != "borrow_write" {
                    continue;
                }
                let Some(syn::Stmt::Expr(syn::Expr::Call(call), None)) =
                    member.block.stmts.last_mut()
                else {
                    anyhow::bail!("actual borrow_write result");
                };
                let Some(syn::Expr::Struct(actual)) = call.args.first_mut() else {
                    anyhow::bail!("actual RestoreWriteLoan constructor");
                };
                anyhow::ensure!(
                    actual.path.is_ident("RestoreWriteLoan"),
                    "actual loan nominal result"
                );
                for field in &mut actual.fields {
                    if matches!(&field.member,syn::Member::Named(name) if name=="_lost") {
                        field.expr = syn::parse_quote!(false);
                        changed += 1;
                    }
                }
            }
        }
        assert_eq!(changed, 1);
        assert!(!retained_refusal_boundary(
            &file.to_token_stream().to_string()
        )?);
        Ok(())
    }
    fn writer_registry_source(stop: &str, sql: &str, ceremony: &str) -> Result<bool> {
        let check = archive_block_tokens(source_method(stop, "WriterReadUnit", "check_current")?);
        let read = "self . loan . reads . read (physical . controller_stage () ? , & self . loan . selection , & names) ?";
        let known = "self . known . require_snapshot_data (observed . snapshot ()) ?";
        let post = "self . loan . reads . check_observation (physical . controller_stage () ? , & mut observed) ?";
        let Some(read_at) = check.find(read) else {
            return Ok(false);
        };
        let Some(known_at) = check.find(known) else {
            return Ok(false);
        };
        let Some(post_at) = check.find(post) else {
            return Ok(false);
        };
        if !(read_at < known_at && known_at < post_at)
            || check.matches(known).count() != 1
            || !check.contains("let checked = self . loan . check_local () ;")
            || !check
                .contains("if requested . is_err () || checked . is_err () { self . refuse () ; }")
            || !check.contains("requested ? ; checked")
        {
            return Ok(false);
        }
        let registry =
            archive_block_tokens(source_method(stop, "WriterRegistryLoan", "registry_data")?);
        if !registry.contains("known : self . known")
            || !registry
                .contains("reader . sqlite . read_writing (& mut unit , reader . metadata) ?")
            || !registry.contains("reader . selected . check (& data) ?")
        {
            return Ok(false);
        }
        let actual =
            archive_block_tokens(source_method(sql, "ControllerAdminSqlite", "read_writing")?);
        let expected: syn::Block =
            syn::parse_quote!({ self.read_unit(ReadLoan::Writing(loan), metadata) });
        let ceremony = archive_block_tokens(source_method(
            ceremony,
            "ExecutionCompletion",
            "check_writer",
        )?);
        let expected_ceremony: syn::Block = syn::parse_quote!({
            self.check_transition(TransitionReader::Writing(reader), sql, signed, operation)
        });
        Ok(actual == archive_block_tokens(expected)
            && ceremony == archive_block_tokens(expected_ceremony))
    }

    #[test]
    fn writer_registry_keeps_distinct_known_snapshot_and_actual_shared_sql_uv_paths() -> Result<()>
    {
        let source = include_str!("stop.rs");
        let sql =
            include_str!("../../../../../../../store/native_storage/controller_admins/reader.rs");
        let ceremony =
            include_str!("../../../../../../restore_webauthn/registry/controller/execution.rs");
        assert!(writer_registry_source(source, sql, ceremony)?);
        for (owner, method, from, to) in [
            (
                "WriterReadUnit",
                "check_current",
                "self.known.require_snapshot_data(observed.snapshot())?;",
                "let _unchecked = ();",
            ),
            (
                "WriterReadUnit",
                "check_current",
                "let checked = self.loan.check_local();",
                "let checked = Ok(());",
            ),
            (
                "WriterReadUnit",
                "check_current",
                "requested?;",
                "let _ignored = requested;",
            ),
            (
                "WriterRegistryLoan",
                "registry_data",
                "let data = reader.sqlite.read_writing(&mut unit, reader.metadata)?;",
                "let data = reader.sqlite.read(&mut unit, reader.metadata)?;",
            ),
        ] {
            let mut parsed = syn::parse_file(source)?;
            let from = syn::parse_str::<syn::Stmt>(from)?
                .to_token_stream()
                .to_string();
            let mut changed = 0;
            for item in &mut parsed.items {
                let syn::Item::Impl(item) = item else {
                    continue;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner))
                {
                    continue;
                }
                for item in &mut item.items {
                    let syn::ImplItem::Fn(item) = item else {
                        continue;
                    };
                    if item.sig.ident != method {
                        continue;
                    }
                    // The actual mandatory call is in the requested closure;
                    // the other cuts are top-level outcome/post statements.
                    fn cut(
                        block: &mut syn::Block,
                        from: &str,
                        to: &str,
                        changed: &mut usize,
                    ) -> Result<()> {
                        for statement in &mut block.stmts {
                            if statement.to_token_stream().to_string() == from {
                                *statement = syn::parse_str(to)?;
                                *changed += 1;
                                continue;
                            }
                            if let syn::Stmt::Local(local) = statement
                                && let Some(init) = &mut local.init
                                && let syn::Expr::Call(call) = &mut *init.expr
                                && let syn::Expr::Paren(paren) = &mut *call.func
                                && let syn::Expr::Closure(closure) = &mut *paren.expr
                                && let syn::Expr::Block(body) = &mut *closure.body
                            {
                                cut(&mut body.block, from, to, changed)?;
                            }
                        }
                        Ok(())
                    }
                    cut(&mut item.block, &from, to, &mut changed)?;
                }
            }
            assert_eq!(changed, 1);
            assert!(!writer_registry_source(
                &parsed.to_token_stream().to_string(),
                sql,
                ceremony
            )?);
        }
        Ok(())
    }

    fn writer_confirmation_source(stop: &str, provider: &str) -> Result<bool> {
        let outer = archive_block_tokens(source_method(
            stop,
            "FencedRestoreContinuation",
            "check_writer_after_cas",
        )?);
        let inner = archive_block_tokens(source_method(
            stop,
            "FencedRestoreContinuation",
            "check_writer_after_cas_inner",
        )?);
        let mark = "self . refused . set (true)";
        let invoke = "self . check_writer_after_cas_inner (expected , target , peer)";
        if outer
            .find(mark)
            .zip(outer.find(invoke))
            .is_none_or(|(mark, invoke)| mark >= invoke)
            || !outer.contains("requested ? ; self . refused . set (false) ; Ok (())")
            || !inner.contains("self . auth . source . confirm_restored_writer")
            || !inner.contains("let checked = self . check_local_inner () ;")
            || !inner.contains("requested ? ; checked ? ; Ok (())")
            || inner.contains("set (false)")
        {
            return Ok(false);
        }
        let check = archive_block_tokens(source_method(
            stop,
            "WriterConfirmationSourceLoan",
            "check",
        )?);
        for required in [
            "completion . check_writer",
            "self . target . validate (& mut checks) ?",
            "self . input . plan . revalidate",
            "self . known . receipt_data () ?",
            "let checked = RestoreTargetCheck",
            "requested ? ; peer_checked ? ; checked",
        ] {
            if !check.contains(required) {
                return Ok(false);
            }
        }
        if check
            .matches("self . peer . check (& mut physical . controller_stage () ? . storage () ?)")
            .count()
            != 2
        {
            return Ok(false);
        }
        if check.contains("set (false)") || check.contains("check_fenced") {
            return Ok(false);
        }
        let actual = archive_block_tokens(source_method(
            provider,
            "NativeApprovalSource",
            "confirm_restored_writer",
        )?);
        for required in [
            "loan . begin (self , & self . store , input) ?",
            "input . publication",
            "names . strong_body () ?",
            "loan . require_observed_data (& observed) ?",
            "budget . remaining_decoding",
            "let checked = loan . check (self) ;",
            "requested ? ; checked",
        ] {
            if !actual.contains(required) {
                return Ok(false);
            }
        }
        if actual.contains("commit_and_readback") || actual.contains("check_fenced") {
            return Ok(false);
        }
        let post = archive_block_tokens(source_method(provider, "WriterConfirmationPort", "post")?);
        let pre = "self . loan . check (self . source) ?";
        let io = "self . source . material . http . request_with_ceiling";
        let after = "let checked = self . loan . check (self . source) ;";
        let primary = "let body = sent ? ;";
        let returned = "checked ? ;";
        let mut previous = 0;
        for (index, required) in [pre, io, after, primary, returned].into_iter().enumerate() {
            let Some(position) = post.find(required) else {
                return Ok(false);
            };
            if index > 0 && position <= previous {
                return Ok(false);
            }
            previous = position;
        }
        Ok(post.contains("EpochRoute :: EpochRead")
            && !post.contains("EpochRoute :: EpochCommit")
            && !post.contains("EpochRoute :: EpochRollback"))
    }

    // Target only the selected nominal method and actual closure, so text in
    // another method or quoted fixture cannot satisfy or absorb a mutation.
    fn writer_mutation_statement(source: &str) -> Result<syn::Stmt> {
        let mut block: syn::Block = syn::parse_str(&format!("{{{source}}}"))?;
        anyhow::ensure!(block.stmts.len() == 1, "one actual mutation statement");
        Ok(block.stmts.remove(0))
    }

    fn writer_confirmation_cut(
        source: &str,
        owner: &str,
        method: &str,
        from: &str,
        to: &str,
    ) -> Result<String> {
        fn normalized(statement: &syn::Stmt) -> Result<String> {
            use syn::parse::Parser as _;
            if let syn::Stmt::Macro(statement) = statement
                && statement.mac.path.is_ident("ensure")
            {
                let mut arguments =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(statement.mac.tokens.clone())?;
                arguments.pop_punct();
                return Ok(arguments.to_token_stream().to_string());
            }
            Ok(archive_block_tokens(syn::Block {
                brace_token: Default::default(),
                stmts: vec![statement.clone()],
            }))
        }
        fn descend(
            expression: &mut syn::Expr,
            from: &str,
            to: &str,
            changed: &mut usize,
        ) -> Result<()> {
            match expression {
                syn::Expr::Call(node) => descend(&mut node.func, from, to, changed)?,
                syn::Expr::Paren(node) => descend(&mut node.expr, from, to, changed)?,
                syn::Expr::Closure(node) => descend(&mut node.body, from, to, changed)?,
                syn::Expr::Block(node) => cut(&mut node.block, from, to, changed)?,
                syn::Expr::If(node) => {
                    cut(&mut node.then_branch, from, to, changed)?;
                    if let Some((_, other)) = &mut node.else_branch {
                        descend(other, from, to, changed)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
        fn cut(block: &mut syn::Block, from: &str, to: &str, changed: &mut usize) -> Result<()> {
            for statement in &mut block.stmts {
                if normalized(statement)? == from {
                    *statement = writer_mutation_statement(to)?;
                    *changed += 1;
                    continue;
                }
                match statement {
                    syn::Stmt::Local(local) if local.init.is_some() => {
                        descend(&mut local.init.as_mut().unwrap().expr, from, to, changed)?
                    }
                    syn::Stmt::Expr(expression, _) => descend(expression, from, to, changed)?,
                    _ => {}
                }
            }
            Ok(())
        }
        let from = normalized(&writer_mutation_statement(from)?)?;
        let mut parsed = syn::parse_file(source)?;
        let mut changed = 0;
        for item in &mut parsed.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner))
            {
                continue;
            }
            for member in &mut item.items {
                let syn::ImplItem::Fn(member) = member else {
                    continue;
                };
                if member.sig.ident == method {
                    cut(&mut member.block, &from, to, &mut changed)?;
                }
            }
        }
        anyhow::ensure!(changed == 1, "exact actual writer confirmation mutation");
        Ok(parsed.to_token_stream().to_string())
    }

    #[test]
    fn writer_confirmation_mutations_reach_nested_guards_and_ignore_only_optional_call_commas()
    -> Result<()> {
        let source = r#"
            impl Decoy { fn check() { ensure!(current,"same"); } }
            impl Actual { fn check() {
                let observed=(|| {
                    if selected { ensure!(current,"same",); }
                    accept(&actual,)
                })();
                observed?;
            } }
        "#;
        let guard = writer_confirmation_cut(
            source,
            "Actual",
            "check",
            "ensure!(current,\"same\");",
            "ensure!(false,\"same\");",
        )?;
        let actual = archive_block_tokens(source_method(&guard, "Actual", "check")?);
        assert!(actual.contains("ensure ! (false , \"same\")"));
        assert!(archive_block_tokens(source_method(&guard, "Decoy", "check")?).contains("current"));
        let call = writer_confirmation_cut(
            source,
            "Actual",
            "check",
            "accept(&actual)",
            "refuse(&actual)",
        )?;
        assert!(
            archive_block_tokens(source_method(&call, "Actual", "check")?)
                .contains("refuse (& actual)")
        );
        assert!(
            writer_confirmation_cut(
                source,
                "Actual",
                "check",
                "accept((actual,))",
                "refuse(&actual)"
            )
            .is_err()
        );
        let duplicate = source.replace("if selected {", "ensure!(current,\"same\"); if selected {");
        assert!(
            writer_confirmation_cut(
                &duplicate,
                "Actual",
                "check",
                "ensure!(current,\"same\");",
                "ensure!(false,\"same\");"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn actual_writer_confirmation_has_separate_strong_read_and_unconditional_native_posts()
    -> Result<()> {
        let stop = include_str!("stop.rs");
        let provider =
            include_str!("../../../../../../storage_authority/native_volume/restore_approval.rs");
        assert!(writer_confirmation_source(stop, provider)?);
        for (owner, method, from, to) in [
            (
                "FencedRestoreContinuation",
                "check_writer_after_cas",
                "self.refused.set(true);",
                "let _unarmed = ();",
            ),
            (
                "FencedRestoreContinuation",
                "check_writer_after_cas_inner",
                "let checked = self.check_local_inner();",
                "let checked = Ok(());",
            ),
            (
                "FencedRestoreContinuation",
                "check_writer_after_cas",
                "requested?;",
                "let _ignored = requested;",
            ),
        ] {
            let mutant = writer_confirmation_cut(stop, owner, method, from, to)?;
            assert!(!writer_confirmation_source(&mutant, provider)?);
        }
        for (owner, method, from, to) in [
            (
                "NativeApprovalSource",
                "confirm_restored_writer",
                "loan.require_observed_data(&observed)?;",
                "let _unverified = ();",
            ),
            (
                "NativeApprovalSource",
                "confirm_restored_writer",
                "let checked = loan.check(self);",
                "let checked = Ok(());",
            ),
            (
                "WriterConfirmationPort",
                "post",
                "let checked = self.loan.check(self.source);",
                "let checked = Ok(());",
            ),
            (
                "WriterConfirmationPort",
                "post",
                "let body = sent?;",
                "let body = sent.unwrap_or_default();",
            ),
        ] {
            let mutant = writer_confirmation_cut(provider, owner, method, from, to)?;
            assert!(!writer_confirmation_source(stop, &mutant)?);
        }
        Ok(())
    }

    fn writer_may_source(stop: &str, sql: &str, ceremony: &str) -> Result<bool> {
        let current =
            archive_block_tokens(source_method(stop, "WriterMayReadUnit", "check_current")?);
        let registry = archive_block_tokens(source_method(
            stop,
            "WriterMayRegistryLoan",
            "registry_data",
        )?);
        let projected = archive_block_tokens(source_method(
            sql,
            "ControllerAdminSqlite",
            "read_writer_may",
        )?);
        let verified = archive_block_tokens(source_method(
            ceremony,
            "ExecutionCompletion",
            "check_writer_may",
        )?);
        Ok(current.contains("self . plan . require_may_snapshot_data (observed . snapshot ()) ?")
            && current.contains("reads . check_observation")
            && current.contains("let checked = self . loan . check_local () ;")
            && current.contains("requested ? ; checked")
            && registry.contains("reader . sqlite . read_writer_may (& mut unit , reader . metadata) ?")
            && projected.contains("self . read_unit (ReadLoan :: WriterMay (loan) , metadata)")
            && verified.contains("self . check_transition (TransitionReader :: WriterMay (reader) , sql , signed , operation)")
            && !current.contains("require_snapshot_data") && !verified.contains("TransitionReader :: Active"))
    }

    #[test]
    fn writer_may_uses_its_distinct_snapshot_and_actual_shared_sql_uv_units() -> Result<()> {
        let stop = include_str!("stop.rs");
        let sql =
            include_str!("../../../../../../../store/native_storage/controller_admins/reader.rs");
        let ceremony =
            include_str!("../../../../../../restore_webauthn/registry/controller/execution.rs");
        assert!(writer_may_source(stop, sql, ceremony)?);
        for (owner, method, from, to) in [
            (
                "WriterMayReadUnit",
                "check_current",
                "self.plan.require_may_snapshot_data(observed.snapshot())?;",
                "let _unchecked=();",
            ),
            (
                "WriterMayReadUnit",
                "check_current",
                "let checked=self.loan.check_local();",
                "let checked=Ok(());",
            ),
            (
                "WriterMayReadUnit",
                "check_current",
                "requested?;",
                "let _ignored=requested;",
            ),
            (
                "WriterMayRegistryLoan",
                "registry_data",
                "let data=reader.sqlite.read_writer_may(&mut unit,reader.metadata)?;",
                "let data=reader.sqlite.read(&mut unit,reader.metadata)?;",
            ),
        ] {
            let changed = writer_confirmation_cut(stop, owner, method, from, to)?;
            assert!(!writer_may_source(&changed, sql, ceremony)?);
        }
        Ok(())
    }

    fn unique_writer_confirmation_origin(block: &syn::Block) -> bool {
        use syn::visit::Visit;
        struct Origins {
            count: usize,
            nominal: bool,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if value
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "RestoreWriterConfirmation")
                {
                    self.count += 1;
                    self.nominal &= value.path.leading_colon.is_none()
                        && value.path.segments.len() == 1
                        && value.rest.is_none();
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let mut origins = Origins {
            count: 0,
            nominal: true,
        };
        origins.visit_block(block);
        origins.count == 1 && origins.nominal
    }

    fn writer_send_source(stop: &str, provider: &str) -> Result<bool> {
        let outer_block = source_method(stop, "RestoreWriteLoan", "confirm_writer")?;
        let unique_origin = unique_writer_confirmation_origin(&outer_block);
        let outer = archive_block_tokens(outer_block);
        let mut previous = 0;
        for (index, part) in [
            "check_receiver (target , peer) ?",
            "self . owner . refused . set (true)",
            "let prepared =",
            "let peer_post =",
            "let post =",
            "let (holder , report , current , at , request , plan) = prepared ?",
            "self . owner . writer_attempt . arm (& dispatch) ?",
            "self . owner . auth . source . send_restored_writer",
            "let checked = self . owner . check_local_inner () ;",
            "let known = requested ? ;",
            "self . owner . check_writer_after_cas (& expected , target , peer) ?",
            "flight . known () ?",
            "Ok (RestoreWriterConfirmation",
        ]
        .into_iter()
        .enumerate()
        {
            let Some(position) = outer.find(part) else {
                return Ok(false);
            };
            if index > 0 && position <= previous {
                return Ok(false);
            }
            previous = position;
        }
        if !unique_origin
            || !outer.contains("peer_post ? ; post ? ;")
            || outer.contains("self . owner . check_current")
        {
            return Ok(false);
        }
        let check = archive_block_tokens(source_method(stop, "WriterSendSourceLoan", "check")?);
        if !check.contains("completion . check_writer_may")
            || check.contains("check_fenced")
            || check.contains("set (false)")
            || !check.contains("self . flight . check (self . dispatch) ?")
            || !check.contains("self . target . validate (& mut checks) ?")
            || check
                .matches(
                    "self . peer . check (& mut physical . controller_stage () ? . storage () ?)",
                )
                .count()
                != 2
            || !check.contains("requested ? ; peer_checked ? ; checked")
        {
            return Ok(false);
        }
        let send = archive_block_tokens(source_method(
            provider,
            "NativeApprovalSource",
            "send_restored_writer",
        )?);
        let mut previous = 0;
        for (index, part) in [
            "loan . begin (self , & self . store , input) ?",
            "names . begin_body () ?",
            "names . transaction (& bytes) ?",
            "transaction . commit_and_readback",
            "let checked = loan . check (self) ;",
            "let known = requested ? ;",
            "checked ? ;",
            "Ok (known)",
        ]
        .into_iter()
        .enumerate()
        {
            let Some(position) = send.find(part) else {
                return Ok(false);
            };
            if index > 0 && position <= previous {
                return Ok(false);
            }
            previous = position;
        }
        let post = archive_block_tokens(source_method(provider, "WriterSendPort", "post")?);
        let mut previous = 0;
        for (index, part) in [
            "self . loan . check (self . source) ?",
            "self . source . material . http . matches (& route , url) ?",
            "self . source . material . http . request_with_ceiling",
            "let checked = self . loan . check (self . source) ;",
            "let body = sent ? ;",
            "checked ? ;",
        ]
        .into_iter()
        .enumerate()
        {
            let Some(position) = post.find(part) else {
                return Ok(false);
            };
            if index > 0 && position <= previous {
                return Ok(false);
            }
            previous = position;
        }
        Ok(post.contains("EpochRoute :: EpochRead")
            && post.contains("EpochRoute :: EpochCommit")
            && post.contains("EpochRoute :: EpochRollback")
            && post.contains("restore_writer_send_provider_route")
            && !send.contains("kernel :: reconcile")
            && !send.contains("restore_original :: RestoreOriginalGuard :: capture"))
    }

    #[test]
    fn actual_writer_send_spends_once_and_only_strict_known_then_separate_posts_construct_confirmation()
    -> Result<()> {
        let stop = include_str!("stop.rs");
        let provider =
            include_str!("../../../../../../storage_authority/native_volume/restore_approval.rs");
        assert!(writer_send_source(stop, provider)?);
        // Similar spelling is not an owner constructor. A second actual
        // nominal constructor is still rejected, even inside a closure/block.
        let one: syn::Block = syn::parse_quote!({
            let lost = LostRestoreWriterConfirmation { refused };
            Ok(RestoreWriterConfirmation { owner, known })
        });
        assert!(unique_writer_confirmation_origin(&one));
        let only_lost: syn::Block =
            syn::parse_quote!({ LostRestoreWriterConfirmation { refused } });
        assert!(!unique_writer_confirmation_origin(&only_lost));
        let duplicate: syn::Block = syn::parse_quote!({
            let premature = RestoreWriterConfirmation { owner, known };
            Ok(RestoreWriterConfirmation { owner, known })
        });
        assert!(!unique_writer_confirmation_origin(&duplicate));
        let foreign: syn::Block =
            syn::parse_quote!({ foreign::RestoreWriterConfirmation { owner, known } });
        assert!(!unique_writer_confirmation_origin(&foreign));
        for (owner, method, from, to) in [
            (
                "RestoreWriteLoan",
                "confirm_writer",
                "let flight=self.owner.writer_attempt.arm(&dispatch)?;",
                "let flight=other_flight;",
            ),
            (
                "RestoreWriteLoan",
                "confirm_writer",
                "let lost=LostRestoreWriterConfirmation {refused:Rc::clone(&self.owner.refused),};",
                "let lost={let premature=RestoreWriterConfirmation {owner,known}; LostRestoreWriterConfirmation {refused:Rc::clone(&self.owner.refused)}};",
            ),
            (
                "RestoreWriteLoan",
                "confirm_writer",
                "let known=requested?;",
                "let known=historical_applied;",
            ),
            (
                "RestoreWriteLoan",
                "confirm_writer",
                "self.owner.check_writer_after_cas(&expected,target,peer)?;",
                "let _unchecked=();",
            ),
            (
                "RestoreWriteLoan",
                "confirm_writer",
                "flight.known()?;",
                "let _lost=flight;",
            ),
            (
                "WriterSendSourceLoan",
                "check",
                "self.flight.check(self.dispatch)?;",
                "let _unchecked=();",
            ),
            (
                "WriterSendSourceLoan",
                "check",
                "peer_checked?;",
                "let _ignored=peer_checked;",
            ),
        ] {
            let changed = writer_confirmation_cut(stop, owner, method, from, to)?;
            assert!(!writer_send_source(&changed, provider)?);
        }
        for (owner, method, from, to) in [
            (
                "NativeApprovalSource",
                "send_restored_writer",
                "let checked=loan.check(self);",
                "let checked=Ok(());",
            ),
            (
                "NativeApprovalSource",
                "send_restored_writer",
                "let known=requested?;",
                "let known=historical_applied;",
            ),
            (
                "WriterSendPort",
                "post",
                "let checked=self.loan.check(self.source);",
                "let checked=Ok(());",
            ),
            (
                "WriterSendPort",
                "post",
                "let body=sent?;",
                "let body=sent.unwrap_or_default();",
            ),
        ] {
            let changed = writer_confirmation_cut(provider, owner, method, from, to)?;
            assert!(!writer_send_source(stop, &changed)?);
        }
        Ok(())
    }

    fn activation_loan_source(stop: &str, native: &str) -> Result<bool> {
        let loan =
            archive_block_tokens(source_method(stop, "RestoreWriterActivationLoan", "check")?);
        let bridge = archive_block_tokens(source_method(
            native,
            "EnrolledStorageStage",
            "check_restore_original",
        )?);
        Ok(loan.contains("self . known . peer_activation_data (self . selected , self . request , self . plan , projection , holder)")
            && loan.contains("projection . creator == * self . creator")
            && loan.matches("storage . check_restore_original (self . original , self . approval , self . operation)").count()==2
            && loan.contains("let checked = storage . check_restore_original")
            && loan.contains("let data = requested ? ; checked ? ; Ok (data)")
            && !loan.contains("set (false)") && !loan.contains("capture") && !loan.contains("narrow")
            && bridge.contains("let requested = original . check_join (self . stage , expected , operation) . map (| _ | ()) ;")
            && bridge.contains("let checked = self . stage . check () ;")
            && bridge.contains("requested ? ; checked")
            && !bridge.contains("capture") && !bridge.contains("narrow"))
    }

    #[test]
    fn actual_activation_loan_keeps_known_binding_and_same_original_with_independent_posts()
    -> Result<()> {
        let stop = include_str!("stop.rs");
        let native = include_str!("../../../../../../native_enrollment/owner.rs");
        assert!(activation_loan_source(stop, native)?);
        for (from, to) in [
            (
                "ensure!(projection.creator == *self.creator, \"restore_writer_activation_creator_changed\");",
                "let _unchecked=();",
            ),
            (
                "self.known.peer_activation_data(self.selected,self.request,self.plan,projection,holder)",
                "self.known.peer_activation_data(self.selected,self.request,other_plan,projection,holder)",
            ),
            (
                "let checked=storage.check_restore_original(self.original,self.approval,self.operation);",
                "let checked=Ok(());",
            ),
            ("let data=requested?;", "let data=caller_data;"),
            ("checked?;", "let _ignored=checked;"),
        ] {
            let changed =
                writer_confirmation_cut(stop, "RestoreWriterActivationLoan", "check", from, to)?;
            assert!(!activation_loan_source(&changed, native)?);
        }
        for (from, to) in [
            (
                "let requested=original.check_join(self.stage,expected,operation).map(|_|());",
                "let requested=Ok(());",
            ),
            ("let checked=self.stage.check();", "let checked=Ok(());"),
            ("requested?;", "let _ignored=requested;"),
        ] {
            let changed = writer_confirmation_cut(
                native,
                "EnrolledStorageStage",
                "check_restore_original",
                from,
                to,
            )?;
            assert!(!activation_loan_source(stop, &changed)?);
        }
        Ok(())
    }

    fn activation_preparation_source(stop: &str) -> Result<bool> {
        let body = archive_block_tokens(source_method(
            stop,
            "RestoreWriterConfirmation",
            "activation_preparation",
        )?);
        let capture = archive_block_tokens(source_method(
            stop,
            "FencedRestoreContinuation",
            "capture_activation_creator",
        )?);
        if !capture.contains("target . creator_data (& mut checks)")
            || !capture.contains("original : & mut self . auth . original")
        {
            return Ok(false);
        }
        let mut previous = 0;
        for (index,part) in [
            "self . check_before_activation (target , peer) ?",
            "self . owner . refused . set (true)",
            "let captured : Result < _ > =",
            "self . owner . capture_activation_creator (target) ?",
            "require_activation_creator (retained , & fresh) ?",
            "let requested : Result < () > =",
            "let mut loan = RestoreWriterActivationLoan",
            "peer . prepare_activated (& mut storage , & mut loan) ?",
            "peer . sign_activated (& mut storage , & mut loan) ?",
            "let native_post =",
            "let checked = self . owner . check_writer_after_cas_inner (& expected , target , peer) ;",
            "let creator_post =",
            "let creator = captured ? ;",
            "requested ? ; native_post ? ; checked ? ; creator_post ? ;",
            "self . activation_creator = Some (creator)",
            "self . owner . refused . set (false)",
        ].into_iter().enumerate() {
            let Some(position)=body.find(part) else{return Ok(false);};
            if index>0 && position<=previous{return Ok(false);}
            previous=position;
        }
        Ok(
            body.contains("original : & mut self . owner . auth . original")
                && body.contains("creator ,")
                && body
                    .matches("self . owner . capture_activation_creator (target) ?")
                    .count()
                    == 2
                && body
                    .matches("require_activation_creator (retained , & fresh)")
                    .count()
                    == 2
                && !body.contains("try_send_activated")
                && !body.contains("begin_current")
                && !body.contains("NativeAcquisition ::"),
        )
    }

    #[test]
    fn actual_activation_prepare_and_sign_retain_full_parent_and_independent_post_before_publishing_data()
    -> Result<()> {
        let stop = include_str!("stop.rs");
        assert!(activation_preparation_source(stop)?);
        for (from, to) in [
            (
                "self.check_before_activation(target,peer)?;",
                "let _unchecked=();",
            ),
            ("self.owner.refused.set(true);", "let _unmarked=();"),
            (
                "let checked=self.owner.check_writer_after_cas_inner(&expected,target,peer);",
                "let checked=Ok(());",
            ),
            ("let creator=captured?;", "let creator=caller_data;"),
            ("native_post?;", "let _ignored=native_post;"),
            ("checked?;", "let _ignored=checked;"),
            (
                "require_activation_creator(retained,&fresh)?;",
                "let _unchecked=();",
            ),
            ("require_activation_creator(retained,&fresh)", "Ok(())"),
            ("creator_post?;", "let _ignored=creator_post;"),
        ] {
            let changed = writer_confirmation_cut(
                stop,
                "RestoreWriterConfirmation",
                "activation_preparation",
                from,
                to,
            )?;
            assert!(!activation_preparation_source(&changed)?);
        }
        let changed = writer_confirmation_cut(
            stop,
            "FencedRestoreContinuation",
            "capture_activation_creator",
            "target.creator_data(&mut checks)",
            "Ok(cached_creator)",
        )?;
        assert!(!activation_preparation_source(&changed)?);
        Ok(())
    }

    #[test]
    fn activation_creator_comparison_refuses_each_changed_metadata_dimension_without_replacing_capture()
    -> Result<()> {
        use crate::security_epoch::native_enrollment::RestoreCreatorData;
        let retained = RestoreCreatorData {
            device_major: 8,
            device_minor: 1,
            inode: 200,
            length: 4096,
            user: 10001,
            group: 10001,
        };
        require_activation_creator(&retained, &retained)?;
        for field in 0..6 {
            let mut changed = retained.clone();
            match field {
                0 => changed.device_major += 1,
                1 => changed.device_minor += 1,
                2 => changed.inode += 1,
                3 => changed.length += 1,
                4 => changed.user += 1,
                _ => changed.group += 1,
            }
            // Rechecking the same captured reference cannot adopt a changed
            // owner after a later equal-data check. This helper grants no role.
            assert!(
                require_activation_creator(&retained, &changed).is_err(),
                "metadata dimension {field}"
            );
            require_activation_creator(&retained, &retained)?;
        }
        Ok(())
    }

    fn receiver_context_source(source: &str) -> Result<bool> {
        let body = archive_block_tokens(source_method(
            source,
            "RestoreWriterExchangeContext",
            "check_receiver",
        )?);
        let mark = "self . owner . refused . set (true)";
        let pre = "self . check_inner (target) ?";
        let peer = "peer . check (& mut physical . controller_stage () ? . storage () ?)";
        let post = "let checked = self . check_inner (target) ;";
        let primary = "requested ? ;";
        let success = "checked ? ; self . owner . refused . set (false)";
        let mut previous = 0;
        for (index, part) in [mark, pre, peer, post, primary, success]
            .into_iter()
            .enumerate()
        {
            let Some(position) = body.find(part) else {
                return Ok(false);
            };
            if index > 0 && position <= previous {
                return Ok(false);
            }
            previous = position;
        }
        if body.matches(mark).count() != 1 || body.matches(pre).count() != 1
            || body.matches(peer).count() != 1 || body.matches(post).count() != 1
            || !body.contains("if requested . is_err () || checked . is_err () { peer . refuse () ; target . refuse () ; self . refuse () ; }") {
            return Ok(false);
        }
        let inner = archive_block_tokens(source_method(
            source,
            "RestoreWriterExchangeContext",
            "check_inner",
        )?);
        Ok(inner
            .matches("self . owner . check_current_inner ()")
            .count()
            == 2
            && inner.contains("let observed = target . validate (& mut checks) ? ;")
            && !inner.contains("set (false)")
            && !body.contains("NativeAcquisition :: begin"))
    }

    #[test]
    fn actual_receiver_boundary_keeps_whole_parent_short_peer_and_sticky_unwind_mark() -> Result<()>
    {
        let source = include_str!("stop.rs");
        assert!(receiver_context_source(source)?);
        for (from, to) in [
            ("self.owner.refused.set(true);", "let _not_armed = ();"),
            ("self.check_inner(target)?;", "let _unchecked = ();"),
            (
                "peer.check(&mut physical.controller_stage()?.storage()?)",
                "Ok(())",
            ),
            (
                "let checked = self.check_inner(target);",
                "let checked = Ok(());",
            ),
            ("requested?;", "let _ignored = requested;"),
            ("checked?;", "let _ignored_post = checked;"),
        ] {
            let mutant = writer_confirmation_cut(
                source,
                "RestoreWriterExchangeContext",
                "check_receiver",
                from,
                to,
            )?;
            assert!(!receiver_context_source(&mutant)?);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "stop/reservation_tests.rs"]
mod reservation_tests;

#[cfg(test)]
mod restore_prepare_binding_tests {
    use syn::visit::Visit;

    fn method(file: &syn::File, name: &str) -> syn::ImplItemFn {
        file.items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(implementation) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*implementation.self_ty else {
                    return None;
                };
                if path
                    .path
                    .segments
                    .last()
                    .is_none_or(|part| part.ident != "RestoreWriterExchangeContext")
                {
                    return None;
                }
                implementation.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method.clone()),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn self_call(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression,syn::Expr::MethodCall(call) if call.method==name
            && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("self"))
            && call.args.len()==1 && matches!(&call.args[0],syn::Expr::Path(path) if path.path.is_ident("target")))
    }

    fn local_name(pat: &syn::Pat, name: &str) -> bool {
        match pat {
            syn::Pat::Ident(pat) => pat.ident == name,
            syn::Pat::Type(pat) => local_name(&pat.pat, name),
            _ => false,
        }
    }

    #[derive(Default)]
    struct Calls {
        full: usize,
        native: Vec<String>,
        steps: Vec<String>,
        new_original: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "check_inner" {
                self.full += 1;
            }
            if [
                "begin_restore_preparation",
                "send_hello",
                "receive_nonce",
                "sign_bind",
                "send_bind",
                "receive_grant",
                "finish",
                "try_send",
                "try_receive",
                "poll",
                "into_peer",
            ]
            .iter()
            .any(|name| call.method == *name)
            {
                self.native.push(call.method.to_string());
            }
            if call.method == "preparation_step"
                && let Some(syn::Expr::Path(path)) = call.args.last()
            {
                self.steps
                    .push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.new_original |= path
                    .path
                    .segments
                    .iter()
                    .any(|part| part.ident == "NativeAcquisition")
                    && path
                        .path
                        .segments
                        .last()
                        .is_some_and(|part| part.ident == "begin");
                if path
                    .path
                    .segments
                    .iter()
                    .any(|part| part.ident == "ReceiverRendezvous")
                    && path
                        .path
                        .segments
                        .last()
                        .is_some_and(|part| part.ident == "begin")
                {
                    self.native.push("begin".to_owned());
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }

    fn full_post(method: &syn::ImplItemFn) -> bool {
        method.block.stmts.iter().any(|statement|matches!(statement,syn::Stmt::Local(local)
            if local_name(&local.pat,"checked") && local.init.as_ref().is_some_and(|init|self_call(&init.expr,"check_inner"))))
            && method.block.stmts.iter().any(|statement|matches!(statement,syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
                if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident("checked"))))
    }

    #[test]
    fn actual_full_parent_brackets_each_fixed_issuer_step_and_completion() {
        let file = syn::parse_file(include_str!("stop.rs")).unwrap();
        let begin = method(&file, "prepare_admission");
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(&begin);
        assert!(full_post(&begin) && !calls.new_original);
        assert_eq!(calls.steps, ["Hello", "Nonce", "Sign", "Bind", "Grant"]);
        assert_eq!(calls.native, ["begin_restore_preparation"]);
        for (name, expected) in [
            (
                "preparation_step",
                vec![
                    "send_hello",
                    "receive_nonce",
                    "sign_bind",
                    "send_bind",
                    "receive_grant",
                ],
            ),
            ("finish_preparation", vec!["finish"]),
            ("begin_receiver", vec!["begin"]),
            ("receiver_step", vec!["try_send", "try_receive", "poll"]),
            ("finish_receiver", vec!["into_peer"]),
        ] {
            let actual = method(&file, name);
            let mut calls = Calls::default();
            calls.visit_impl_item_fn(&actual);
            assert!(full_post(&actual) && calls.full == 2 && !calls.new_original);
            assert_eq!(calls.native, expected);
            let mut missing = actual.clone();
            let post=missing.block.stmts.iter_mut().find(|statement|matches!(statement,syn::Stmt::Local(local) if local_name(&local.pat,"checked"))).unwrap();
            *post = syn::parse_quote!(let checked:Result<()>=Ok(()););
            assert!(!full_post(&missing));
            let mut discarded = actual.clone();
            let post=discarded.block.stmts.iter_mut().find(|statement|matches!(statement,syn::Stmt::Expr(syn::Expr::Try(tried),Some(_)) if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident("checked")))).unwrap();
            *post = syn::parse_quote!(let _ = checked;);
            assert!(!full_post(&discarded));
        }
    }
}

#[cfg(test)]
mod desired_instance_binding_tests {
    use quote::ToTokens as _;
    use syn::visit::Visit;

    fn binding(
        source: &str,
        owner_name: &str,
        method_name: &str,
        type_name: &str,
        expected: syn::Expr,
    ) -> bool {
        let file = syn::parse_file(source).unwrap();
        let mut methods = file.items.iter().filter_map(|item| {
            let syn::Item::Impl(owner) = item else {
                return None;
            };
            let syn::Type::Path(path) = &*owner.self_ty else {
                return None;
            };
            if path
                .path
                .segments
                .last()
                .is_none_or(|part| part.ident != owner_name)
            {
                return None;
            }
            owner.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == method_name => Some(method),
                _ => None,
            })
        });
        let Some(method) = methods.next() else {
            return false;
        };
        if methods.next().is_some() {
            return false;
        }
        struct Constructor<'a> {
            name: &'a str,
            expected: String,
            count: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Constructor<'_> {
            fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
                if node
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == self.name)
                {
                    self.count += 1;
                    let fields:Vec<_>=node.fields.iter().filter(|field|matches!(&field.member,syn::Member::Named(name) if name=="desired_instance")).collect();
                    self.valid &= fields.len() == 1
                        && fields[0].expr.to_token_stream().to_string() == self.expected;
                }
                syn::visit::visit_expr_struct(self, node);
            }
        }
        let mut constructors = Constructor {
            name: type_name,
            expected: expected.to_token_stream().to_string(),
            count: 0,
            valid: true,
        };
        constructors.visit_block(&method.block);
        struct MetadataCall {
            count: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for MetadataCall {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if call.method == "require_native_selection" {
                    self.count += 1;
                    let receiver: syn::Expr =
                        syn::parse_quote!(self.owner.auth.action.reader.metadata);
                    let expected: [syn::Expr; 3] = [
                        syn::parse_quote!(&self.owner.auth.action.reader.loan.selection),
                        syn::parse_quote!(
                            &self
                                .owner
                                .auth
                                .action
                                .reader
                                .loan
                                .policy
                                .runtime_profile
                                .app_artifact
                        ),
                        syn::parse_quote!(&self.owner.auth.action.reader.loan.policy),
                    ];
                    self.valid &= call.receiver.to_token_stream().to_string()
                        == receiver.to_token_stream().to_string()
                        && call.args.len() == 3
                        && call.args.iter().zip(expected).all(|(actual, expected)| {
                            actual.to_token_stream().to_string()
                                == expected.to_token_stream().to_string()
                        });
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut metadata = MetadataCall {
            count: 0,
            valid: true,
        };
        metadata.visit_block(&method.block);
        let body = method.block.to_token_stream().to_string();
        constructors.count == 1
            && constructors.valid
            && (owner_name != "RestoreWriterExchangeContext"
                || metadata.count == 1
                    && metadata.valid
                    && body
                        .find("metadata . require_native_selection")
                        .zip(body.find("let supplied ="))
                        .is_some_and(|(check, copy)| check < copy))
    }

    fn source_binding(stop: &str, client: &str) -> bool {
        binding(
            stop,
            "RestoreWriterExchangeContext",
            "prepare_admission",
            "RestorePreparationData",
            syn::parse_quote!(
                self.owner
                    .auth
                    .action
                    .reader
                    .metadata
                    .restore_registry_selector_data()
                    .1
            ),
        ) && binding(
            client,
            "FrozenRoleIssuer",
            "begin_restore_preparation",
            "RestoreAuthorizationData",
            syn::parse_quote!(supplied.desired_instance.clone()),
        )
    }

    #[test]
    fn actual_current_instance_digest_is_copied_only_from_the_guarded_metadata_and_bound_in_signed_authorization()
     {
        let stop = include_str!("stop.rs");
        let client = include_str!("../../../../../../native_enrollment/owner/restore.rs");
        assert!(source_binding(stop, client));
        for (source, owner, method, type_name) in [
            (
                stop,
                "RestoreWriterExchangeContext",
                "prepare_admission",
                "RestorePreparationData",
            ),
            (
                client,
                "FrozenRoleIssuer",
                "begin_restore_preparation",
                "RestoreAuthorizationData",
            ),
        ] {
            let mut file = syn::parse_file(source).unwrap();
            let mut changed = 0;
            for item in &mut file.items {
                let syn::Item::Impl(implementation) = item else {
                    continue;
                };
                if !matches!(&*implementation.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner))
                {
                    continue;
                }
                for item in &mut implementation.items {
                    let syn::ImplItem::Fn(actual) = item else {
                        continue;
                    };
                    if actual.sig.ident != method {
                        continue;
                    }
                    // Mutation of the actual constructor's expression, selected
                    // nominally; quoted fixtures cannot absorb this change.
                    fn replace_expr(expr: &mut syn::Expr, name: &str, changed: &mut usize) {
                        match expr {
                            syn::Expr::Struct(value)
                                if value
                                    .path
                                    .segments
                                    .last()
                                    .is_some_and(|part| part.ident == name) =>
                            {
                                for field in &mut value.fields {
                                    if matches!(&field.member,syn::Member::Named(member) if member=="desired_instance")
                                    {
                                        field.expr =
                                            syn::parse_quote!(day2_capabilities::Digest::new(
                                                b"caller-lookalike-instance"
                                            ));
                                        *changed += 1;
                                    }
                                }
                            }
                            syn::Expr::Block(body) => replace(&mut body.block, name, changed),
                            syn::Expr::Paren(paren) => replace_expr(&mut paren.expr, name, changed),
                            syn::Expr::Closure(closure) => {
                                replace_expr(&mut closure.body, name, changed)
                            }
                            syn::Expr::Call(call) => replace_expr(&mut call.func, name, changed),
                            syn::Expr::Try(tried) => replace_expr(&mut tried.expr, name, changed),
                            _ => {}
                        }
                    }
                    fn replace(block: &mut syn::Block, name: &str, changed: &mut usize) {
                        for statement in &mut block.stmts {
                            match statement {
                                syn::Stmt::Local(local) => {
                                    if let Some(init) = &mut local.init {
                                        replace_expr(&mut init.expr, name, changed);
                                    }
                                }
                                syn::Stmt::Expr(expr, _) => replace_expr(expr, name, changed),
                                _ => {}
                            }
                        }
                    }
                    replace(&mut actual.block, type_name, &mut changed);
                }
            }
            assert_eq!(changed, 1);
            let mutated = file.to_token_stream().to_string();
            assert!(!if owner == "RestoreWriterExchangeContext" {
                source_binding(&mutated, client)
            } else {
                source_binding(stop, &mutated)
            });
        }
    }
}

#[cfg(test)]
mod activation_transport_source_tests {
    use super::{ActivationIo as I, ActivationProgress as S};
    use crate::security_epoch::native_enrollment::ReceiverProgress as P;
    use quote::ToTokens as _;

    #[test]
    fn activation_progress_allows_only_the_same_packet_continuation_and_ack_is_terminal() {
        let allowed = [
            (S::FirstSend, I::Send, P::Delivered, S::ReceiveAck),
            (S::FirstSend, I::Send, P::WouldBlock, S::PollSend),
            (S::FirstSend, I::Send, P::Interrupted, S::Send),
            (S::Send, I::Send, P::Delivered, S::ReceiveAck),
            (S::Send, I::Send, P::WouldBlock, S::PollSend),
            (S::Send, I::Send, P::Interrupted, S::Send),
            (S::PollSend, I::Poll, P::Advanced, S::Send),
            (S::PollSend, I::Poll, P::Interrupted, S::PollSend),
            (S::ReceiveAck, I::ReceiveAck, P::Delivered, S::Acknowledged),
            (S::ReceiveAck, I::ReceiveAck, P::WouldBlock, S::PollAck),
            (S::ReceiveAck, I::ReceiveAck, P::Interrupted, S::ReceiveAck),
            (S::PollAck, I::Poll, P::Advanced, S::ReceiveAck),
            (S::PollAck, I::Poll, P::Interrupted, S::PollAck),
        ];
        for state in [
            S::FirstSend,
            S::Send,
            S::PollSend,
            S::ReceiveAck,
            S::PollAck,
            S::Acknowledged,
            S::Refused,
        ] {
            for operation in [I::Send, I::Poll, I::ReceiveAck] {
                for progress in [P::Advanced, P::WouldBlock, P::Interrupted, P::Delivered] {
                    let expected = allowed
                        .iter()
                        .find(|row| (row.0, row.1, row.2) == (state, operation, progress));
                    let actual = state.after(operation, progress);
                    match expected {
                        Some(row) => assert_eq!(actual.unwrap(), row.3),
                        None => assert!(actual.is_err()),
                    }
                }
            }
        }
    }

    fn actual_owner(ty: &syn::Type, name: &str) -> bool {
        let syn::Type::Path(path) = ty else {
            return false;
        };
        path.qself.is_none()
            && path.path.leading_colon.is_none()
            && path.path.segments.len() == 1
            && path.path.segments.first().is_some_and(|part| {
                part.ident == name
                    && match &part.arguments {
                        syn::PathArguments::None => true,
                        syn::PathArguments::AngleBracketed(args) => args
                            .args
                            .iter()
                            .all(|argument| matches!(argument, syn::GenericArgument::Lifetime(_))),
                        _ => false,
                    }
            })
    }

    fn block(source: &str, owner: &str, name: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let mut selected = file.items.iter().filter_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if item.trait_.is_some() || !actual_owner(&item.self_ty, owner) {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method.block.clone()),
                _ => None,
            })
        });
        let result = selected.next().expect("actual nominal implementation");
        assert!(selected.next().is_none());
        super::tests::archive_block_tokens(result)
    }
    fn ordered(body: &str, expected: &[&str]) -> bool {
        let mut cursor = 0;
        for part in expected {
            let Some(offset) = body[cursor..].find(part) else {
                return false;
            };
            cursor += offset + part.len();
        }
        true
    }

    fn cut_actual_method(source: &str, owner: &str, name: &str, from: &str, to: &str) -> String {
        fn fragment(text: &str) -> String {
            fn normalized(tokens: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
                tokens
                    .into_iter()
                    .map(|token| match token {
                        proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                            proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                                '?',
                                proc_macro2::Spacing::Alone,
                            ))
                        }
                        proc_macro2::TokenTree::Group(group) => proc_macro2::TokenTree::Group(
                            proc_macro2::Group::new(group.delimiter(), normalized(group.stream())),
                        ),
                        other => other,
                    })
                    .collect()
            }
            normalized(text.parse().unwrap()).to_string()
        }
        let mut file = syn::parse_file(source).unwrap();
        let mut selected = 0;
        for item in &mut file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if item.trait_.is_some() || !actual_owner(&item.self_ty, owner) {
                continue;
            }
            for member in &mut item.items {
                let syn::ImplItem::Fn(method) = member else {
                    continue;
                };
                if method.sig.ident != name {
                    continue;
                }
                let body = super::tests::archive_block_tokens(method.block.clone());
                let from = fragment(from);
                assert_eq!(
                    body.matches(&from).count(),
                    1,
                    "one actual nominal mutation target: {owner}::{name}"
                );
                method.block = syn::parse_str(&body.replacen(&from, &fragment(to), 1)).unwrap();
                selected += 1;
            }
        }
        assert_eq!(selected, 1, "one actual nominal method");
        file.to_token_stream().to_string()
    }
    fn actual_active_branch(source: &str) -> bool {
        use syn::visit::Visit;
        struct Branch {
            count: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Branch {
            fn visit_expr_match(&mut self, value: &'ast syn::ExprMatch) {
                if value.expr.to_token_stream().to_string() == "& self . target_purpose" {
                    self.count += 1;
                    self.valid &= value.arms.len() == 2;
                    let arm = value.arms.iter().find(|arm| {
                        arm.pat.to_token_stream().to_string()
                            == "WriterTargetPurpose :: Activated (creator)"
                    });
                    self.valid &= arm.is_some_and(|arm| {
                        if arm.guard.is_some(){return false;}
                        let mut expression=&*arm.body;
                        while let syn::Expr::Block(block)=expression {
                            let [syn::Stmt::Expr(inner,None)]=block.block.stmts.as_slice() else{return false;};
                            expression=inner;
                        }
                        expression.to_token_stream().to_string().replace(" , )"," )")
                            =="self . target . check_active_identity (& mut checks , creator , self . report) ?"
                    });
                }
                syn::visit::visit_expr_match(self, value);
            }
        }
        let actual: syn::Block =
            syn::parse_str(&block(source, "WriterConfirmationSourceLoan", "check")).unwrap();
        let mut branch = Branch {
            count: 0,
            valid: true,
        };
        branch.visit_block(&actual);
        branch.count == 1 && branch.valid
    }

    fn retained(source: &str) -> bool {
        let create = block(source, "RestoreWriterConfirmation", "activate_writer");
        let operation = block(source, "RestoreWriterActivated", "operation");
        let check = block(source, "RestoreWriterActivated", "check");
        let finish = block(source, "RestoreWriterActivated", "receive_ack");
        let active = block(
            source,
            "FencedRestoreContinuation",
            "check_writer_active_inner",
        );
        let shared = block(source, "WriterConfirmationSourceLoan", "check");
        let refused = block(source, "RestoreWriterActivated", "refuse");
        ordered(&create,&[
            "self . prepare_activated (target , peer) ?", "self . sign_activated (target , peer) ?",
            "self . check_before_activation (target , peer) ?", "self . owner . refused . set (true)",
            "let mut frame = RestoreWriterActivated", "frame . receive_ack () ?", "Ok (frame)",
        ]) && create.matches("RestoreWriterActivated {").count()==1
        && ordered(&operation,&[
            "self . progress = ActivationProgress :: Refused",
            "self . check (state == ActivationProgress :: FirstSend)", "entered ?", "let requested =",
            "original : & mut owner . auth . original", "creator : & self . creator",
            "self . peer . try_send_activated (& mut storage , & mut loan)",
            "self . peer . poll_activation (& mut storage , & mut loan)",
            "self . peer . try_receive_keeper_ack (& mut storage , & mut loan)",
            "let checked = self . check (false)", "requested . is_err () || checked . is_err ()",
            "let observed = requested ?", "checked ?", "let next = state . after (operation , observed)",
            "self . progress = next ?",
        ]) && !operation.contains("refused . set (false)")
        && check.contains("self . confirmation . owner . check_writer_after_cas_inner (& expected , self . target , self . peer)")
        && ordered(&check,&[
            "self . confirmation . owner . check_writer_after_cas_inner (& expected , self . target , self . peer) ?",
            "self . confirmation . owner . capture_activation_creator (self . target) ?",
            "require_activation_creator (& self . creator , & fresh)",
        ])
        && check.contains("self . confirmation . owner . check_writer_active_inner (& expected , self . target , self . peer , & self . creator)")
        && active.contains("target_purpose : WriterTargetPurpose :: Activated (creator)")
        && actual_active_branch(source)
        && shared.contains("self . target . validate (& mut checks) ? == * self . report")
        && ordered(&finish,&["ActivationProgress :: Acknowledged", "self . operation (operation) ?", "let checked = self . check (false)", "self . refuse ()", "checked"])
        && ordered(&refused,&["ActivationProgress :: Refused", "self . target . refuse ()", "self . peer . refuse ()", "self . confirmation . refuse ()"])
    }

    #[test]
    fn actual_activation_transport_retains_same_owners_and_posts_after_possible_send_without_frozen_rehash()
     {
        let source = include_str!("stop.rs");
        assert!(retained(source));
        for (owner, method, from, to) in [
            (
                "RestoreWriterConfirmation",
                "activate_writer",
                "self.prepare_activated(target, peer)?;",
                "Ok::<(),anyhow::Error>(())?;",
            ),
            (
                "RestoreWriterConfirmation",
                "activate_writer",
                "self.sign_activated(target, peer)?;",
                "Ok::<(),anyhow::Error>(())?;",
            ),
            (
                "RestoreWriterActivated",
                "operation",
                "self.progress = ActivationProgress::Refused;",
                "self.progress = ActivationProgress::Send;",
            ),
            (
                "RestoreWriterActivated",
                "check",
                "require_activation_creator(&self.creator, &fresh)",
                "Ok(())",
            ),
            (
                "RestoreWriterActivated",
                "operation",
                "let checked = self.check(false);",
                "let checked:Result<()>=Ok(());",
            ),
            (
                "RestoreWriterActivated",
                "operation",
                "let observed = requested?;",
                "let observed = requested.unwrap_or(crate::security_epoch::native_enrollment::ReceiverProgress::Delivered);",
            ),
            (
                "FencedRestoreContinuation",
                "check_writer_active_inner",
                "WriterTargetPurpose::Activated(creator)",
                "WriterTargetPurpose::Frozen",
            ),
            (
                "WriterConfirmationSourceLoan",
                "check",
                "self.target\n                        .check_active_identity(&mut checks, creator, self.report)?",
                "Ok::<(),anyhow::Error>(())?",
            ),
        ] {
            let mutated = cut_actual_method(source, owner, method, from, to);
            assert!(!retained(&mutated), "mutation rejected: {from}");
        }
    }

    #[test]
    fn source_body_normalizes_optional_call_commas_without_erasing_tuple_arguments() {
        let one = "impl Chosen {fn actual(){call(a,b);}}";
        let formatted = "impl Chosen {fn actual(){call(a,b,);}}";
        let tuple = "impl Chosen {fn actual(){call((a,),b);}}";
        assert_eq!(
            block(one, "Chosen", "actual"),
            block(formatted, "Chosen", "actual")
        );
        assert_ne!(
            block(one, "Chosen", "actual"),
            block(tuple, "Chosen", "actual")
        );
        let loop_plain = "impl Chosen {fn actual(){for item in [a,b]{call(S{a:item,b:y});}}}";
        let loop_formatted =
            "impl Chosen {fn actual(){for item in [a,b,]{call(S{a:item,b:y,},);}}}";
        assert_eq!(
            block(loop_plain, "Chosen", "actual"),
            block(loop_formatted, "Chosen", "actual")
        );
        assert_ne!(
            block(loop_plain, "Chosen", "actual"),
            block(
                "impl Chosen {fn actual(){for item in [a,c]{call(S{a:item,b:y});}}}",
                "Chosen",
                "actual"
            )
        );
        let original = "impl Chosen {fn actual(){match selected {Some(x)=>call(S{a:x,b:y},[x,y]),None=>stop()}}}";
        let formatted = "impl Chosen {fn actual(){match selected {Some(x)=>call(S{a:x,b:y,},[x,y,],),None=>stop(),}}}";
        assert_eq!(
            block(original, "Chosen", "actual"),
            block(formatted, "Chosen", "actual")
        );
        assert_ne!(
            block(
                "impl Chosen {fn actual(){call(S{a:x,..base});}}",
                "Chosen",
                "actual"
            ),
            block(
                "impl Chosen {fn actual(){call(S{a:x..base});}}",
                "Chosen",
                "actual"
            )
        );
    }

    #[test]
    fn activation_mutants_cannot_be_absorbed_by_an_earlier_same_spelled_method() {
        let source = "impl Earlier {fn operation(){self.progress=ActivationProgress::Refused;}} impl Chosen {fn operation(){self.progress=ActivationProgress::Refused;}}";
        let mutated = cut_actual_method(
            source,
            "Chosen",
            "operation",
            "self.progress=ActivationProgress::Refused;",
            "self.progress=ActivationProgress::Send;",
        );
        assert!(block(&mutated, "Earlier", "operation").contains("ActivationProgress :: Refused"));
        assert!(block(&mutated, "Chosen", "operation").contains("ActivationProgress :: Send"));
        let parameterized = "impl<'a> Earlier<'a> {fn operation(){self.progress=ActivationProgress::Refused;}} impl<'a> foreign::Chosen<'a> {fn operation(){self.progress=ActivationProgress::Refused;}} impl<'a> Chosen<'a> {fn operation(){self.progress=ActivationProgress::Refused;}}";
        let mutated = cut_actual_method(
            parameterized,
            "Chosen",
            "operation",
            "self.progress=ActivationProgress::Refused;",
            "self.progress=ActivationProgress::Send;",
        );
        assert!(block(&mutated, "Earlier", "operation").contains("ActivationProgress :: Refused"));
        assert!(block(&mutated, "Chosen", "operation").contains("ActivationProgress :: Send"));
        assert!(!actual_owner(
            &syn::parse_str::<syn::Type>("foreign::Chosen<'a>").unwrap(),
            "Chosen"
        ));
        assert!(!actual_owner(
            &syn::parse_str::<syn::Type>("Chosen<Foreign>").unwrap(),
            "Chosen"
        ));
    }
    fn release_loan_guard(body: &str) -> bool {
        ordered(
            body,
            &[
                "ensure ! (self . refused . get ()",
                "storage . check_restore_original (self . original , self . approval , self . operation) ?",
                "self . known . require_activation_data (self . plan , activation) ?",
                "let held = self . cohort . check (self . target , self . creator , self . report) ?",
                "ensure ! (held == * acknowledged",
                "let checked = storage . check_restore_original (self . original , self . approval , self . operation)",
                "if requested . is_err () || checked . is_err () { self . refuse () ; }",
                "requested ? ; checked",
            ],
        ) && body.matches("storage . check_restore_original").count() == 2
            && !body.contains("capture")
            && !body.contains("set (false)")
    }
    #[test]
    fn actual_release_loan_requires_same_original_known_activation_and_actual_held_ack_cohort() {
        let body = block(include_str!("stop.rs"), "RestoreWriterReleaseLoan", "check");
        assert!(release_loan_guard(&body));
        for (from, to) in [
            (
                "self . known . require_activation_data (self . plan , activation) ?",
                "Ok::<(),anyhow::Error> (()) ?",
            ),
            (
                "self . cohort . check (self . target , self . creator , self . report) ?",
                "self . cohort . check (other_target , self . creator , self . report) ?",
            ),
            ("ensure ! (held == * acknowledged", "ensure ! (true"),
            (
                "let checked = storage . check_restore_original (self . original , self . approval , self . operation)",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            ("requested ? ; checked", "checked ? ; requested"),
        ] {
            assert_eq!(body.matches(from).count(), 1);
            assert!(!release_loan_guard(&body.replacen(from, to, 1)), "{from}");
        }
    }

    #[test]
    fn actual_release_cohort_is_born_only_after_the_same_keeper_ack_and_full_posts() {
        let source = include_str!("stop.rs");
        let body = block(source, "RestoreWriterActivated", "pin_release_cohort");
        let valid = |body: &str| {
            ordered(
                body,
                &[
                    "self . progress = ActivationProgress :: Refused",
                    "prior == ActivationProgress :: Acknowledged",
                    "self . cohort . is_none ()",
                    "std :: mem :: replace (& mut self . release_started , true)",
                    "self . check (false)",
                    "entered ?",
                    "let requested = self . confirmation . owner . capture_release_cohort (self . target , & self . creator , & self . confirmation . target)",
                    "let checked = self . check (false)",
                    "requested . is_err () || checked . is_err ()",
                    "let cohort = requested ? ; checked ?",
                    "self . cohort = Some (cohort)",
                ],
            )
        };
        assert!(valid(&body));
        for (from, to) in [
            ("prior == ActivationProgress :: Acknowledged", "true"),
            (
                "std :: mem :: replace (& mut self . release_started , true)",
                "false",
            ),
            (
                "self . target , & self . creator , & self . confirmation . target",
                "other_target , & self . creator , & self . confirmation . target",
            ),
            (
                "let checked = self . check (false)",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let cohort = requested ? ; checked ?",
                "let cohort = requested ? ; let _=checked",
            ),
        ] {
            assert!(body.contains(from));
            assert!(!valid(&body.replacen(from, to, 1)), "{from}");
        }
        let leaf = block(
            source,
            "FencedRestoreContinuation",
            "capture_release_cohort",
        );
        assert!(leaf.contains("original : & mut self . auth . original"));
        assert!(leaf.contains("target . pin_active_cohort (& mut checks , creator , report)"));
    }

    #[test]
    fn release_progress_only_signs_once_and_resumes_the_same_packet_until_known_delivery() {
        use super::{ReleaseIo as I, ReleaseProgress as S};
        let allowed = [
            (S::Prepare, I::Prepare, P::Advanced, S::Sign),
            (S::Sign, I::Sign, P::Advanced, S::Send),
            (S::Send, I::Send, P::Delivered, S::Delivered),
            (S::Send, I::Send, P::WouldBlock, S::Poll),
            (S::Send, I::Send, P::Interrupted, S::Send),
            (S::Poll, I::Poll, P::Advanced, S::Send),
            (S::Poll, I::Poll, P::Interrupted, S::Poll),
        ];
        for state in [
            S::Prepare,
            S::Sign,
            S::Send,
            S::Poll,
            S::Delivered,
            S::Refused,
        ] {
            for operation in [I::Prepare, I::Sign, I::Send, I::Poll] {
                for progress in [P::Advanced, P::WouldBlock, P::Interrupted, P::Delivered] {
                    let expected = allowed
                        .iter()
                        .find(|row| (row.0, row.1, row.2) == (state, operation, progress));
                    let actual = state.after(operation, progress);
                    match expected {
                        Some(row) => assert_eq!(actual.unwrap(), row.3),
                        None => assert!(actual.is_err()),
                    }
                }
            }
        }
    }
    fn release_driver(body: &str) -> bool {
        ordered(
            body,
            &[
                "self . release = Some (ReleaseProgress :: Refused)",
                "self . progress == ActivationProgress :: Acknowledged",
                "self . release_started",
                "state . operation () ? == operation",
                "self . check (false)",
                "entered ?",
                "let mut loan = RestoreWriterReleaseLoan",
                "original : & mut owner . auth . original",
                "known : & self . confirmation . known",
                "plan : & self . confirmation . plan",
                "creator : & self . creator",
                "target : self . target",
                "cohort : self . cohort . as_mut ()",
                "self . peer . prepare_released (& mut storage , & mut loan)",
                "self . peer . sign_released (& mut storage , & mut loan)",
                "self . peer . try_send_released (& mut storage , & mut loan)",
                "self . peer . poll_release (& mut storage , & mut loan)",
                "let checked = self . check (false)",
                "let cohort = self . check_cohort ()",
                "requested . is_err () || checked . is_err () || cohort . is_err ()",
                "let progress = requested ? ; checked ? ; cohort ?",
                "let next = state . after (operation , progress)",
                "self . release = Some (next ?)",
            ],
        ) && body
            .matches("let mut loan = RestoreWriterReleaseLoan")
            .count()
            == 1
            && !body.contains("RestoreWriterActivationLoan")
            && !body.contains("set (false)")
    }
    #[test]
    fn actual_release_driver_lends_only_the_same_completed_ack_frame_and_keeps_all_independent_posts()
     {
        let source = include_str!("stop.rs");
        let actual = block(source, "RestoreWriterActivated", "release_operation");
        assert!(release_driver(&actual));
        for (from, to) in [
            (
                "self . release = Some (ReleaseProgress :: Refused)",
                "self . release = Some (ReleaseProgress :: Send)",
            ),
            ("target : self . target", "target : other_target"),
            (
                "original : & mut owner . auth . original",
                "original : & mut other_original",
            ),
            (
                "let checked = self . check (false)",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let cohort = self . check_cohort ()",
                "let cohort = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let progress = requested ? ; checked ? ; cohort ?",
                "let progress = requested ? ; let _=(checked,cohort)",
            ),
        ] {
            assert!(actual.contains(from));
            assert!(!release_driver(&actual.replacen(from, to, 1)), "{from}");
        }
        let whole = block(source, "RestoreWriterActivated", "release_keeper");
        assert!(ordered(
            &whole,
            &[
                "self . pin_release_cohort () ?",
                "self . release = Some (ReleaseProgress :: Prepare)",
                "self . release_operation (state . operation () ?) ?",
                "self . release = Some (ReleaseProgress :: Refused)",
                "let checked = self . check (false)",
                "let cohort = self . check_cohort ()",
                "checked ? ; cohort ?",
                "self . release = Some (ReleaseProgress :: Delivered)"
            ]
        ));
    }

    #[test]
    fn actual_controller_installation_consumes_the_whole_release_frame_after_independent_posts() {
        fn unique_installation(source: &str) -> bool {
            use syn::visit::Visit;
            struct Origins(usize);
            impl<'ast> Visit<'ast> for Origins {
                fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                    if value
                        .path
                        .segments
                        .last()
                        .is_some_and(|part| part.ident == "RestoreControllerInstallation")
                    {
                        self.0 += 1;
                    }
                    syn::visit::visit_expr_struct(self, value);
                }
            }
            let file = syn::parse_file(source).unwrap();
            let mut origins = Origins(0);
            origins.visit_file(&file);
            origins.0 == 1
        }
        let source = include_str!("stop.rs");
        assert!(unique_installation(source));
        let premature=source.replacen("self.check_completed_resources()?;","let premature=RestoreControllerInstallation {frame:other};self.check_completed_resources()?;",1);
        assert_ne!(source, premature);
        assert!(!unique_installation(&premature));
        let consume = block(source, "RestoreWriterActivated", "install_controller");
        assert!(ordered(
            &consume,
            &[
                "self . check_completed_resources () ?",
                "Ok (RestoreControllerInstallation { frame : self , issuer_progress : IssuerFinishProgress :: Fresh"
            ]
        ));
        let check = block(
            source,
            "RestoreWriterActivated",
            "check_completed_resources",
        );
        let valid = |body: &str| {
            ordered(
                body,
                &[
                    "self . release = Some (ReleaseProgress :: Refused)",
                    "prior == Some (ReleaseProgress :: Delivered)",
                    "self . progress == ActivationProgress :: Acknowledged",
                    "self . release_started && self . cohort . is_some ()",
                    "self . check (false)",
                    "let physical = self . check_cohort ()",
                    "entered . is_err () || physical . is_err ()",
                    "entered ? ; physical ?",
                    "self . release = Some (ReleaseProgress :: Delivered)",
                ],
            )
        };
        assert!(valid(&check));
        for (from, to) in [
            ("prior == Some (ReleaseProgress :: Delivered)", "true"),
            (
                "self . release = Some (ReleaseProgress :: Refused)",
                "self . release = Some (ReleaseProgress :: Delivered)",
            ),
            (
                "let physical = self . check_cohort ()",
                "let physical = Ok::<(),anyhow::Error>(())",
            ),
            ("entered ? ; physical ?", "let _=(entered,physical)"),
        ] {
            assert!(check.contains(from));
            assert!(!valid(&check.replacen(from, to, 1)), "{from}");
        }
        let actual = block(source, "RestoreControllerInstallation", "check");
        assert!(actual.contains("self . issuer_progress != IssuerFinishProgress :: Fresh"));
        assert!(actual.ends_with("self . frame . check_completed_resources () }"));
        assert!(
            !consume.contains("clone") && !consume.contains("take") && !consume.contains("capture")
        );
    }

    #[test]
    fn issuer_finish_has_a_distinct_actual_resource_loan_with_unconditional_original_post() {
        let body = block(
            include_str!("stop.rs"),
            "RestoreFinalInstallationLoan",
            "check",
        );
        assert!(release_loan_guard(&body));
        assert!(body.contains("restore_issuer_outside_actual_installation"));
        assert!(body.contains("restore_issuer_installation_cohort_changed"));
        assert!(!body.contains("RestoreWriterReleaseLoan") && !body.contains("capture"));
    }

    fn activation_call_tokens(call: &syn::ExprMethodCall) -> String {
        let mut call = call.clone();
        call.args.pop_punct();
        call.to_token_stream().to_string()
    }

    fn activation_native_calls_are_exact(body: &str) -> bool {
        use syn::visit::Visit;
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                let name = call.method.to_string();
                if name == "begin_app_role_activation"
                    || name == "receive_app_confirmation"
                    || name == "receive_installed_confirmation"
                    || (call.args.len() == 6
                        && matches!(
                            name.as_str(),
                            "check" | "try_send_acceptance" | "poll_acceptance"
                        ))
                    || (call.args.len() == 5
                        && matches!(
                            name.as_str(),
                            "check" | "try_send_acceptance" | "poll_acceptance"
                        ))
                    || (call.args.len() == 4
                        && matches!(
                            name.as_str(),
                            "send_hello"
                                | "receive_nonce"
                                | "send_bind"
                                | "receive_grant"
                                | "finish"
                                | "check"
                                | "prepare_role_decision"
                                | "sign_role_decision"
                                | "try_send_role_decision"
                                | "poll_role_decision"
                        ))
                {
                    self.0.push(activation_call_tokens(call));
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let Ok(block) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        let mut calls = Calls(vec![]);
        calls.visit_block(&block);
        let expected: [syn::ExprMethodCall; 19] = [
            syn::parse_quote!(completed.begin_app_role_activation(
                &mut storage,
                self.frame.peer,
                &mut loan
            )),
            syn::parse_quote!(pending.send_hello(
                &mut storage,
                self.frame.peer,
                completed,
                &mut loan
            )),
            syn::parse_quote!(pending.receive_nonce(
                &mut storage,
                self.frame.peer,
                completed,
                &mut loan
            )),
            syn::parse_quote!(pending.send_bind(
                &mut storage,
                self.frame.peer,
                completed,
                &mut loan
            )),
            syn::parse_quote!(pending.receive_grant(
                &mut storage,
                self.frame.peer,
                completed,
                &mut loan
            )),
            syn::parse_quote!(pending.finish(&mut storage, self.frame.peer, completed, &mut loan)),
            syn::parse_quote!(activation.check(
                &mut storage,
                self.frame.peer,
                completed,
                &mut loan
            )),
            syn::parse_quote!(self.frame.peer.prepare_role_decision(
                &mut storage,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(self.frame.peer.sign_role_decision(
                &mut storage,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(self.frame.peer.try_send_role_decision(
                &mut storage,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(self.frame.peer.poll_role_decision(
                &mut storage,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(activation.receive_app_confirmation(
                &mut storage,
                self.frame.peer,
                completed,
                &mut loan
            )),
            syn::parse_quote!(confirmation.check(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(confirmation.try_send_acceptance(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(confirmation.poll_acceptance(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(prepared.receive_installed_confirmation(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                &mut loan
            )),
            syn::parse_quote!(installed.check(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                prepared,
                &mut loan
            )),
            syn::parse_quote!(installed.try_send_acceptance(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                prepared,
                &mut loan
            )),
            syn::parse_quote!(installed.poll_acceptance(
                &mut storage,
                self.frame.peer,
                completed,
                activation,
                prepared,
                &mut loan
            )),
        ];
        calls.0
            == expected
                .iter()
                .map(activation_call_tokens)
                .collect::<Vec<_>>()
    }

    fn issuer_native_guard(body: &str) -> bool {
        ordered(
            body,
            &[
                "let prior = self . issuer_progress",
                "self . issuer_progress = IssuerFinishProgress :: Busy",
                "prior == expected",
                "self . frame . check_completed_resources ()",
                "entered . is_err ()",
                "entered ?",
                "let mut storage = physical . controller_stage () ? . storage () ?",
                "let mut loan = RestoreFinalInstallationLoan",
                "original : & mut owner . auth . original",
                "known : & self . frame . confirmation . known",
                "creator : & self . frame . creator",
                "target : self . frame . target",
                "cohort : self . frame . cohort . as_mut ()",
                "owner . issuer . begin_finish_restore (& mut storage , self . frame . peer , & mut loan)",
                "pending . send_hello (& mut storage , self . frame . peer , & mut loan)",
                "pending . receive_nonce (& mut storage , self . frame . peer , & mut loan)",
                "pending . sign_bind (& mut storage , self . frame . peer , & mut loan)",
                "pending . send_bind (& mut storage , self . frame . peer , & mut loan)",
                "pending . receive_grant (& mut storage , self . frame . peer , & mut loan)",
                "pending . finish (& mut storage , self . frame . peer , & mut loan)",
                "completed . check (& mut storage , self . frame . peer , & mut loan)",
                "self . frame . peer . prepare_role_handoff (& mut storage , completed , & mut loan)",
                "self . frame . peer . sign_role_handoff (& mut storage , completed , & mut loan)",
                "self . frame . peer . try_send_role_handoff (& mut storage , completed , & mut loan)",
                "self . frame . peer . poll_role_handoff (& mut storage , completed , & mut loan)",
                "completed . begin_app_role_activation (& mut storage , self . frame . peer , & mut loan)",
                "pending . send_hello (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . receive_nonce (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . send_bind (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . receive_grant (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . finish (& mut storage , self . frame . peer , completed , & mut loan)",
                "activation . check (& mut storage , self . frame . peer , completed , & mut loan)",
                "self . frame . peer . prepare_role_decision (& mut storage , completed , activation , & mut loan)",
                "self . frame . peer . sign_role_decision (& mut storage , completed , activation , & mut loan)",
                "self . frame . peer . try_send_role_decision (& mut storage , completed , activation , & mut loan)",
                "self . frame . peer . poll_role_decision (& mut storage , completed , activation , & mut loan)",
                "activation . receive_app_confirmation (& mut storage , self . frame . peer , completed , & mut loan)",
                "confirmation . check (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . try_send_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . poll_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "RoleHandoffIo :: Prepare | RoleHandoffIo :: Sign =>",
                "restore_controller_acceptance_wrong_operation",
                "prepared . receive_installed_confirmation (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "installed . check (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "installed . try_send_acceptance (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "installed . poll_acceptance (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "restore_installed_acceptance_wrong_operation",
                "let checked = self . frame . check_completed_resources ()",
                "requested . is_err () || checked . is_err ()",
                "self . refuse ()",
                "let reply = requested ? ; checked ?",
                "self . issuer_progress = next",
                "Ok (reply)",
            ],
        ) && body
            .matches("let mut loan = RestoreFinalInstallationLoan")
            .count()
            == 1
            && [
                ("begin_finish_restore", 1),
                ("begin_app_role_activation", 1),
                ("send_hello", 2),
                ("receive_nonce", 2),
                ("sign_bind", 1),
                ("send_bind", 2),
                ("receive_grant", 2),
                ("finish", 2),
                ("check", 4),
                ("prepare_role_handoff", 1),
                ("sign_role_handoff", 1),
                ("try_send_role_handoff", 1),
                ("poll_role_handoff", 1),
                ("prepare_role_decision", 1),
                ("sign_role_decision", 1),
                ("try_send_role_decision", 1),
                ("poll_role_decision", 1),
                ("receive_app_confirmation", 1),
                ("try_send_acceptance", 2),
                ("poll_acceptance", 2),
                ("receive_installed_confirmation", 1),
            ]
            .iter()
            .all(|(name, count)| body.matches(&format!(". {name} (")).count() == *count)
            && !body.contains("RestoreWriterReleaseLoan")
            && !body.contains("NativeAcquisition ::")
            && !body.contains("narrow")
            && !body.contains("set (false)")
            && activation_native_calls_are_exact(body)
    }

    #[test]
    fn issuer_finish_actual_driver_lends_same_installation_and_runs_full_independent_posts() {
        let source = include_str!("stop.rs");
        let actual = block(source, "RestoreControllerInstallation", "issuer_native");
        assert!(issuer_native_guard(&actual));
        for (from, to) in [
            (
                "self . issuer_progress = IssuerFinishProgress :: Busy",
                "self . issuer_progress = IssuerFinishProgress :: Fresh",
            ),
            ("prior == expected", "true"),
            (
                "original : & mut owner . auth . original",
                "original : & mut other_original",
            ),
            ("target : self . frame . target", "target : other_target"),
            (
                "cohort : self . frame . cohort . as_mut ()",
                "cohort : other_cohort . as_mut ()",
            ),
            (
                "self . frame . peer , & mut loan",
                "other_peer , & mut loan",
            ),
            (
                "let checked = self . frame . check_completed_resources ()",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let reply = requested ? ; checked ?",
                "checked ? ; let reply = requested ?",
            ),
            (
                "self . issuer_progress = next",
                "self . issuer_progress = IssuerFinishProgress :: Fresh",
            ),
            (
                "installed . try_send_acceptance (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "installed . try_send_acceptance (& mut storage , other_peer , completed , activation , prepared , & mut loan)",
            ),
            (
                "installed . poll_acceptance (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "other_installed . poll_acceptance (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
            ),
        ] {
            assert!(actual.contains(from));
            assert!(
                !issuer_native_guard(&actual.replacen(from, to, 1)),
                "{from}"
            );
        }
        let terminal = block(source, "RestoreIssuerCompletedInstallation", "check");
        let actual = |body: &str| {
            ordered(
                body,
                &[
                    "self . role_handoff . is_some_and",
                    "state != RoleHandoffProgress :: Delivered",
                    "self . installation . issuer_native (IssuerFinishCall { kind : IssuerFinishCallKind :: Check (& mut self . issuer)",
                    "match checked",
                    "IssuerFinishReplyKind :: Step",
                    "self . refuse ()",
                    "Err (error) => { self . refuse () ; Err (error) }",
                ],
            )
        };
        assert!(actual(&terminal));
        for (from, to) in [
            (
                "self . installation . issuer_native",
                "other_installation . issuer_native",
            ),
            ("& mut self . issuer", "& mut other_issuer"),
            (
                "Err (error) => { self . refuse () ; Err (error) }",
                "Err (_) => Ok (())",
            ),
        ] {
            assert!(terminal.contains(from));
            assert!(!actual(&terminal.replacen(from, to, 1)), "{from}");
        }
    }

    #[test]
    fn issuer_finish_result_consumes_actual_installation_after_fixed_native_completion_only() {
        use syn::visit::Visit;
        struct Origins {
            method: Option<String>,
            loan: Vec<String>,
            complete: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_impl_item_fn(&mut self, value: &'ast syn::ImplItemFn) {
                let prior = self.method.replace(value.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, value);
                self.method = prior;
            }
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if let Some(last) = value.path.segments.last() {
                    match last.ident.to_string().as_str() {
                        "RestoreFinalInstallationLoan" => {
                            self.loan.push(self.method.clone().unwrap_or_default())
                        }
                        "RestoreIssuerCompletedInstallation" => {
                            self.complete.push(self.method.clone().unwrap_or_default())
                        }
                        _ => {}
                    }
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let unique = |source: &str| {
            let mut origins = Origins {
                method: None,
                loan: vec![],
                complete: vec![],
            };
            origins.visit_file(&syn::parse_file(source).unwrap());
            origins.loan == ["issuer_native"] && origins.complete == ["finish_issuer"]
        };
        let source = include_str!("stop.rs");
        assert!(unique(source));
        let mut early = syn::parse_file(source).unwrap();
        let mut changed = 0;
        for item in &mut early.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident=="RestoreControllerInstallation"))
            {
                continue;
            }
            for member in &mut item.items {
                if let syn::ImplItem::Fn(member) = member
                    && member.sig.ident == "finish_issuer"
                {
                    member.block.stmts.insert(0,syn::parse_quote!(let premature=RestoreIssuerCompletedInstallation {installation:other,issuer:other};));
                    changed += 1;
                }
            }
        }
        assert_eq!(changed, 1);
        assert!(!unique(&early.to_token_stream().to_string()));
        let whole = block(source, "RestoreControllerInstallation", "finish_issuer");
        let fixed = |body: &str| {
            ordered(
                body,
                &[
                    "IssuerFinishCallKind :: Begin",
                    "IssuerFinishReplyKind :: Begun (pending)",
                    "for step in [IssuerFinishStep :: Hello",
                    "IssuerFinishStep :: Nonce",
                    "IssuerFinishStep :: Sign",
                    "IssuerFinishStep :: Bind",
                    "IssuerFinishStep :: Grant",
                    "IssuerFinishCallKind :: Step { pending : & mut pending , step }",
                    "IssuerFinishReplyKind :: Step",
                    "IssuerFinishCallKind :: Finish (pending)",
                    "IssuerFinishReplyKind :: Completed (issuer)",
                    "Ok (RestoreIssuerCompletedInstallation { installation : self , issuer",
                ],
            ) && body.matches("IssuerFinishStep ::").count() == 5
        };
        assert!(fixed(&whole));
        for (from, to) in [
            (
                "IssuerFinishCallKind :: Begin",
                "IssuerFinishCallKind :: Skip",
            ),
            ("IssuerFinishStep :: Nonce", "IssuerFinishStep :: Hello"),
            (
                "IssuerFinishCallKind :: Finish (pending)",
                "IssuerFinishCallKind :: Skip",
            ),
            ("installation : self", "installation : other"),
        ] {
            assert!(whole.contains(from));
            assert!(!fixed(&whole.replacen(from, to, 1)), "{from}");
        }
        let file = syn::parse_file(source).unwrap();
        let actual = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item) => Some(item),
                _ => None,
            })
            .flat_map(|item| &item.items)
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "finish_issuer" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(actual.len(), 1);
        assert!(
            matches!(actual[0].sig.inputs.first(),Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none() && receiver.mutability.is_some())
        );
    }

    #[test]
    fn role_handoff_allows_only_fixed_send_continuations_and_no_delivered_reentry() {
        use super::{RoleHandoffIo as I, RoleHandoffProgress as S};
        let allowed = [
            (S::Prepare, I::Prepare, P::Advanced, S::Sign),
            (S::Sign, I::Sign, P::Advanced, S::Send),
            (S::Send, I::Send, P::Delivered, S::Delivered),
            (S::Send, I::Send, P::WouldBlock, S::Poll),
            (S::Send, I::Send, P::Interrupted, S::Send),
            (S::Poll, I::Poll, P::Advanced, S::Send),
            (S::Poll, I::Poll, P::Interrupted, S::Poll),
        ];
        for state in [
            S::Prepare,
            S::Sign,
            S::Send,
            S::Poll,
            S::Delivered,
            S::Refused,
        ] {
            for operation in [I::Prepare, I::Sign, I::Send, I::Poll] {
                for progress in [P::Advanced, P::WouldBlock, P::Interrupted, P::Delivered] {
                    let expected = allowed
                        .iter()
                        .find(|row| (row.0, row.1, row.2) == (state, operation, progress));
                    let actual = state.after(operation, progress);
                    match expected {
                        Some(row) => assert_eq!(actual.unwrap(), row.3),
                        None => assert!(actual.is_err()),
                    }
                }
            }
        }
        assert!(S::Delivered.operation().is_err());
        assert!(S::Refused.operation().is_err());
    }

    fn role_handoff_driver(body: &str) -> bool {
        ordered(
            body,
            &[
                "let prior = self . role_handoff",
                "self . role_handoff = Some (RoleHandoffProgress :: Refused)",
                "let state = prior . context",
                "state . operation () ? == operation",
                "entered . is_err ()",
                "let state = entered ?",
                "let requested = self . installation . issuer_native (IssuerFinishCall { kind : IssuerFinishCallKind :: RoleHandoff { completed : & mut self . issuer , operation",
                "IssuerFinishReplyKind :: Progress (progress)",
                "progress . is_err ()",
                "self . refuse ()",
                "let next = state . after (operation , progress ?)",
                "next . is_err ()",
                "self . refuse ()",
                "self . role_handoff = Some (next ?)",
                "Ok (())",
            ],
        ) && !body.contains("NativeAcquisition ::")
            && !body.contains("clone")
    }

    #[test]
    fn actual_role_handoff_retires_before_checks_and_lends_only_its_completed_owner() {
        let source = include_str!("stop.rs");
        let operation = block(
            source,
            "RestoreIssuerCompletedInstallation",
            "role_handoff_operation",
        );
        assert!(role_handoff_driver(&operation));
        for (from, to) in [
            (
                "self . role_handoff = Some (RoleHandoffProgress :: Refused)",
                "self . role_handoff = Some (RoleHandoffProgress :: Send)",
            ),
            ("state . operation () ? == operation", "true"),
            (
                "self . installation . issuer_native",
                "other_installation . issuer_native",
            ),
            ("& mut self . issuer", "& mut other_issuer"),
            (
                "let next = state . after (operation , progress ?)",
                "let next = Ok (RoleHandoffProgress :: Delivered)",
            ),
            (
                "self . role_handoff = Some (next ?)",
                "self . role_handoff = Some (RoleHandoffProgress :: Prepare)",
            ),
        ] {
            assert!(operation.contains(from));
            assert!(
                !role_handoff_driver(&operation.replacen(from, to, 1)),
                "{from}"
            );
        }

        let actual = block(
            source,
            "RestoreIssuerCompletedInstallation",
            "release_app_role",
        );
        let fixed = |body: &str| {
            ordered(
                body,
                &[
                    "self . role_handoff . is_some ()",
                    "self . refuse ()",
                    "restore_role_handoff_attempt_spent",
                    "self . role_handoff = Some (RoleHandoffProgress :: Prepare)",
                    "self . role_handoff_operation (state . operation () ?) ?",
                    "self . role_handoff = Some (RoleHandoffProgress :: Refused)",
                    "let checked = self . installation . issuer_native (IssuerFinishCall { kind : IssuerFinishCallKind :: Check (& mut self . issuer)",
                    "IssuerFinishReplyKind :: Step",
                    "result . is_err ()",
                    "self . refuse ()",
                    "result ?",
                    "self . role_handoff = Some (RoleHandoffProgress :: Delivered)",
                    "Ok (())",
                ],
            )
        };
        assert!(fixed(&actual));
        for (from, to) in [
            ("self . role_handoff . is_some ()", "false"),
            (
                "self . role_handoff_operation (state . operation () ?) ?",
                "let _ = state",
            ),
            (
                "let checked = self . installation . issuer_native",
                "let checked = other_installation . issuer_native",
            ),
            ("result ?", "let _ = result"),
        ] {
            assert!(actual.contains(from));
            assert!(!fixed(&actual.replacen(from, to, 1)), "{from}");
        }
    }

    #[test]
    fn role_activation_uses_only_the_four_fixed_native_steps() {
        use super::{IssuerFinishProgress as F, IssuerRoleActivationStep as A};
        for (step, before, after) in [
            (A::Hello, F::RoleHello, F::RoleNonce),
            (A::Nonce, F::RoleNonce, F::RoleBind),
            (A::Bind, F::RoleBind, F::RoleGrant),
            (A::Grant, F::RoleGrant, F::RoleFinish),
        ] {
            assert!(step.progress() == (before, after), "{step:?}");
            assert!(before != F::Fresh && before != F::Completed);
            assert!(after != F::Fresh && after != F::Completed);
        }
    }

    fn app_role_activation_factory(body: &str) -> bool {
        ordered(
            body,
            &[
                "let delivered = self . role_handoff == Some (RoleHandoffProgress :: Delivered)",
                "self . role_handoff = Some (RoleHandoffProgress :: Refused)",
                "if ! delivered",
                "self . refuse ()",
                "restore_app_role_requires_postchecked_delivery",
                "let begun = self . installation . issuer_native",
                "RoleActivationBegin { completed : & mut self . issuer",
                "let mut pending = match begun ? . kind",
                "IssuerFinishReplyKind :: RoleBegun (pending) => pending",
                "IssuerRoleActivationStep :: Hello , IssuerRoleActivationStep :: Nonce , IssuerRoleActivationStep :: Bind , IssuerRoleActivationStep :: Grant",
                "RoleActivationStep { completed : & mut self . issuer , pending : & mut pending , step",
                "if ! matches !",
                "IssuerFinishReplyKind :: Step",
                "restore_app_role_step_reply_changed",
                "RoleActivationFinish { completed : & mut self . issuer , pending",
                "let activation = match requested ? . kind",
                "IssuerFinishReplyKind :: RoleActivated (activation) => activation",
                "restore_app_role_finish_reply_changed",
                "Ok (RestoreAppRoleActivatedInstallation { activation , installation : self })",
            ],
        ) && body.matches("self . installation . issuer_native").count() == 3
            && body
                .matches("RestoreAppRoleActivatedInstallation {")
                .count()
                == 1
            && !["clone", "NativeAcquisition", "narrow", "set (false)"]
                .iter()
                .any(|part| body.contains(part))
    }

    #[test]
    fn actual_app_role_activation_requires_postchecked_delivery_and_consumes_the_same_owners() {
        let source = include_str!("stop.rs");
        let actual = block(
            source,
            "RestoreIssuerCompletedInstallation",
            "activate_app_role",
        );
        assert!(app_role_activation_factory(&actual));
        for (from, to) in [
            (
                "self . role_handoff == Some (RoleHandoffProgress :: Delivered)",
                "true",
            ),
            (
                "self . role_handoff = Some (RoleHandoffProgress :: Refused)",
                "self . role_handoff = Some (RoleHandoffProgress :: Delivered)",
            ),
            ("if ! delivered", "if false"),
            (
                "self . installation . issuer_native",
                "other_installation . issuer_native",
            ),
            (
                "completed : & mut self . issuer",
                "completed : & mut other_issuer",
            ),
            (
                "IssuerRoleActivationStep :: Hello , IssuerRoleActivationStep :: Nonce",
                "IssuerRoleActivationStep :: Nonce , IssuerRoleActivationStep :: Hello",
            ),
            ("if ! matches !", "if matches !"),
            (
                "IssuerFinishReplyKind :: Step",
                "IssuerFinishReplyKind :: Completed",
            ),
            ("installation : self", "installation : other_installation"),
        ] {
            assert!(actual.contains(from), "{from}");
            assert!(
                !app_role_activation_factory(&actual.replacen(from, to, 1)),
                "{from}"
            );
        }
        // The real shared entry's old full-pre/post/primary and sole-loan
        // controls now also bind every actual activation operation and arg.
        let dispatch = block(source, "RestoreControllerInstallation", "issuer_native");
        assert!(issuer_native_guard(&dispatch));
        assert!(activation_native_calls_are_exact(&dispatch));
        let plain: syn::ExprMethodCall = syn::parse_quote!(pending.send_hello(
            &mut storage,
            self.frame.peer,
            completed,
            &mut loan
        ));
        let comma: syn::ExprMethodCall = syn::parse_quote!(pending.send_hello(
            &mut storage,
            self.frame.peer,
            completed,
            &mut loan,
        ));
        assert_eq!(
            activation_call_tokens(&plain),
            activation_call_tokens(&comma)
        );
        for (from, to) in [
            (
                "completed . begin_app_role_activation",
                "other_completed . begin_app_role_activation",
            ),
            (
                "pending . send_hello (& mut storage , self . frame . peer , completed , & mut loan)",
                "other_pending . send_hello (& mut storage , self . frame . peer , completed , & mut loan)",
            ),
            (
                "pending . send_hello (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . send_hello (& mut storage , other_peer , completed , & mut loan)",
            ),
            (
                "pending . receive_nonce (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . receive_nonce (& mut storage , self . frame . peer , other_completed , & mut loan)",
            ),
            (
                "pending . send_bind (& mut storage , self . frame . peer , completed , & mut loan)",
                "pending . send_bind (& mut storage , self . frame . peer , completed , & mut other_loan)",
            ),
            (
                "activation . check (& mut storage , self . frame . peer , completed , & mut loan)",
                "Ok::<(),anyhow::Error>(())",
            ),
            (
                "activation . check (& mut storage , self . frame . peer , completed , & mut loan)",
                "other_activation . check (& mut storage , self . frame . peer , completed , & mut loan)",
            ),
        ] {
            assert_eq!(dispatch.matches(from).count(), 1, "{from}");
            assert!(
                !issuer_native_guard(&dispatch.replacen(from, to, 1)),
                "{from}"
            );
        }
    }

    #[test]
    fn app_role_activation_result_is_private_consuming_and_has_one_actual_factory() {
        use syn::visit::Visit;
        struct Factories {
            method: Option<String>,
            found: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Factories {
            fn visit_impl_item_fn(&mut self, value: &'ast syn::ImplItemFn) {
                let prior = self.method.replace(value.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, value);
                self.method = prior;
            }
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if value
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "RestoreAppRoleActivatedInstallation")
                {
                    self.found.push(self.method.clone().unwrap_or_default());
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let source = include_str!("stop.rs");
        let file = syn::parse_file(source).unwrap();
        let mut factories = Factories {
            method: None,
            found: vec![],
        };
        factories.visit_file(&file);
        assert_eq!(factories.found, ["activate_app_role"]);
        let extra = format!(
            "{source}\nfn unexpected_factory() {{ let _=self::RestoreAppRoleActivatedInstallation {{ activation:other_grant,installation:other_installation }}; }}"
        );
        let mut duplicate = Factories {
            method: None,
            found: vec![],
        };
        duplicate.visit_file(&syn::parse_file(&extra).unwrap());
        assert_ne!(duplicate.found, ["activate_app_role"]);
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RestoreAppRoleActivatedInstallation" => {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.fields.len(), 2);
        let fields = carrier.fields.iter().collect::<Vec<_>>();
        assert!(
            fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        );
        assert!(
            fields[0]
                .ident
                .as_ref()
                .is_some_and(|field| field == "activation")
        );
        assert!(
            fields[1]
                .ident
                .as_ref()
                .is_some_and(|field| field == "installation")
        );
        let method = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.trait_.is_some()
                    || !actual_owner(&item.self_ty, "RestoreIssuerCompletedInstallation")
                {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "activate_app_role" => Some(item),
                    _ => None,
                })
            })
            .unwrap();
        assert_eq!(method.sig.inputs.len(), 1);
        assert!(
            matches!(method.sig.inputs.first(),Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_none() && receiver.mutability.is_some())
        );
        let body = block(source, "RestoreAppRoleActivatedInstallation", "check");
        let guarded = |body: &str| {
            ordered(
                body,
                &[
                    "self . installation . installation . issuer_native",
                    "RoleActivationCheck { completed : & mut self . installation . issuer , activation : & mut self . activation",
                    "match checked",
                    "IssuerFinishReplyKind :: Step",
                    "self . refuse ()",
                    "Err (error) => { self . refuse () ; Err (error) }",
                ],
            )
        };
        assert!(guarded(&body));
        for (from, to) in [
            (
                "completed : & mut self . installation . issuer",
                "completed : & mut other_issuer",
            ),
            (
                "activation : & mut self . activation",
                "activation : & mut other_activation",
            ),
            (
                "Err (error) => { self . refuse () ; Err (error) }",
                "Err (_) => Ok (())",
            ),
        ] {
            assert_eq!(body.matches(from).count(), 1);
            assert!(!guarded(&body.replacen(from, to, 1)), "{from}");
        }
        let refusal = block(source, "RestoreAppRoleActivatedInstallation", "refuse");
        assert!(ordered(
            &refusal,
            &[
                "self . activation . refuse ()",
                "self . installation . refuse ()"
            ]
        ));
        // These controls inspect real production methods and a closed DATA
        // transition table; no genuine native role/Current/keeper is faked.
    }

    fn checked_same_carrier_return_is_exact(body: &str, carrier: &str) -> bool {
        fn actual_self(expr: &syn::Expr) -> bool {
            matches!(expr, syn::Expr::Path(path) if path.qself.is_none() && path.path.is_ident("self"))
        }
        let Ok(body) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        let [.., before, last] = body.stmts.as_slice() else {
            return false;
        };
        let syn::Stmt::Expr(syn::Expr::Try(checked), Some(_)) = before else {
            return false;
        };
        let syn::Expr::MethodCall(call) = &*checked.expr else {
            return false;
        };
        if call.method != "check"
            || !call.args.is_empty()
            || call.turbofish.is_some()
            || !actual_self(&call.receiver)
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Call(result), None) = last else {
            return false;
        };
        let syn::Expr::Path(function) = &*result.func else {
            return false;
        };
        if function.qself.is_some() || !function.path.is_ident("Ok") || result.args.len() != 1 {
            return false;
        }
        let Some(syn::Expr::Struct(value)) = result.args.first() else {
            return false;
        };
        if !value.path.is_ident(carrier) || value.rest.is_some() || value.fields.len() != 1 {
            return false;
        }
        let field = value.fields.first().unwrap();
        matches!(&field.member, syn::Member::Named(name) if name == "installation")
            && actual_self(&field.expr)
    }

    fn decision_final_post_is_exact(body: &str) -> bool {
        checked_same_carrier_return_is_exact(body, "RestoreAppDecisionSentInstallation")
    }

    fn decision_send_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "let mut state = RoleHandoffProgress :: Prepare",
                "state == RoleHandoffProgress :: Delivered",
                "let operation = state . operation () ?",
                "self . installation . installation . issuer_native (IssuerFinishCall",
                "RoleDecision { completed : & mut self . installation . issuer , activation : & mut self . activation , operation",
                "requested . is_err ()",
                "self . refuse ()",
                "let progress = match requested ? . kind",
                "IssuerFinishReplyKind :: Progress (progress) => progress",
                "restore_app_decision_reply_changed",
                "let next = state . after (operation , progress)",
                "next . is_err ()",
                "self . refuse ()",
                "state = next ?",
                "} self . check () ? ; Ok (RestoreAppDecisionSentInstallation { installation : self })",
            ],
        ) && body.matches(". issuer_native (").count() == 1
            && body.matches("RestoreAppDecisionSentInstallation {").count() == 1
            && !["clone", "NativeAcquisition", "narrow", "set (false)"]
                .iter()
                .any(|part| body.contains(part))
            && decision_final_post_is_exact(body)
    }

    #[test]
    fn actual_decision_send_consumes_the_same_carrier_and_requires_the_final_full_post() {
        let source = include_str!("stop.rs");
        let actual = block(
            source,
            "RestoreAppRoleActivatedInstallation",
            "send_app_decision",
        );
        assert!(decision_send_is_closed(&actual));
        assert!(decision_final_post_is_exact(&actual));
        let foreign = actual.replacen("self . check () ?", "other_self . check () ?", 1);
        assert_ne!(actual, foreign);
        assert!(!decision_final_post_is_exact(&foreign));
        for (from, to) in [
            (
                "let mut state = RoleHandoffProgress :: Prepare",
                "let mut state = RoleHandoffProgress :: Delivered",
            ),
            (
                "self . installation . installation . issuer_native",
                "other_installation . issuer_native",
            ),
            (
                "completed : & mut self . installation . issuer",
                "completed : & mut other_issuer",
            ),
            (
                "activation : & mut self . activation",
                "activation : & mut other_activation",
            ),
            (
                "IssuerFinishReplyKind :: Progress (progress) => progress",
                "IssuerFinishReplyKind :: Step => ReceiverProgress::Delivered",
            ),
            (
                "state . after (operation , progress)",
                "Ok (RoleHandoffProgress::Delivered)",
            ),
            ("self . check () ?", "other_self . check () ?"),
            ("installation : self", "installation : other_installation"),
        ] {
            assert_eq!(actual.matches(from).count(), 1, "{from}");
            assert!(
                !decision_send_is_closed(&actual.replacen(from, to, 1)),
                "{from}"
            );
        }
        let dispatch = block(source, "RestoreControllerInstallation", "issuer_native");
        assert!(issuer_native_guard(&dispatch));
        assert!(dispatch.contains("IssuerFinishCallKind :: RoleDecision { .. } => (IssuerFinishProgress :: RoleActivated , IssuerFinishProgress :: RoleActivated)"));
        for (from, to) in [
            (
                "self . frame . peer . prepare_role_decision",
                "other_peer . prepare_role_decision",
            ),
            (
                "self . frame . peer . sign_role_decision (& mut storage , completed , activation , & mut loan)",
                "self . frame . peer . sign_role_decision (& mut storage , other_completed , activation , & mut loan)",
            ),
            (
                "self . frame . peer . try_send_role_decision (& mut storage , completed , activation , & mut loan)",
                "self . frame . peer . try_send_role_decision (& mut storage , completed , other_activation , & mut loan)",
            ),
            (
                "self . frame . peer . poll_role_decision (& mut storage , completed , activation , & mut loan)",
                "self . frame . peer . poll_role_decision (& mut storage , completed , activation , & mut other_loan)",
            ),
        ] {
            assert_eq!(dispatch.matches(from).count(), 1, "{from}");
            assert!(
                !issuer_native_guard(&dispatch.replacen(from, to, 1)),
                "{from}"
            );
        }
    }

    #[test]
    fn decision_send_result_has_one_private_consuming_factory_and_only_fresh_checks() {
        use syn::visit::Visit;
        struct Origins {
            method: Option<String>,
            origins: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let prior = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = prior;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "RestoreAppDecisionSentInstallation")
                {
                    self.origins.push(self.method.clone().unwrap_or_default());
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let source = include_str!("stop.rs");
        let file = syn::parse_file(source).unwrap();
        let mut actual = Origins {
            method: None,
            origins: vec![],
        };
        actual.visit_file(&file);
        assert_eq!(actual.origins, ["send_app_decision"]);
        let extra = format!(
            "{source}\nfn unauthorized() {{ let _=self::RestoreAppDecisionSentInstallation {{ installation:other }}; }}"
        );
        let mut duplicate = Origins {
            method: None,
            origins: vec![],
        };
        duplicate.visit_file(&syn::parse_file(&extra).unwrap());
        assert_ne!(duplicate.origins, ["send_app_decision"]);
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RestoreAppDecisionSentInstallation" => {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.fields.len(), 1);
        let field = carrier.fields.iter().next().unwrap();
        assert!(matches!(field.vis, syn::Visibility::Inherited));
        assert!(
            field
                .ident
                .as_ref()
                .is_some_and(|name| name == "installation")
        );
        let factory = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.trait_.is_some()
                    || !actual_owner(&item.self_ty, "RestoreAppRoleActivatedInstallation")
                {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "send_app_decision" => Some(item),
                    _ => None,
                })
            })
            .unwrap();
        assert_eq!(factory.sig.inputs.len(), 1);
        assert!(
            matches!(factory.sig.inputs.first(),Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_none() && receiver.mutability.is_some())
        );
        assert_eq!(
            block(source, "RestoreAppDecisionSentInstallation", "check"),
            "{ self . installation . check () }"
        );
        // Pure syntax/transition observations only; no native App receipt or
        // genuine role/Current/first keeper is constructed by these tests.
    }

    fn prepared_confirmation_return_is_exact(body: &str) -> bool {
        let Ok(body) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        let Some(syn::Stmt::Expr(syn::Expr::Call(result), None)) = body.stmts.last() else {
            return false;
        };
        let syn::Expr::Path(function) = &*result.func else {
            return false;
        };
        if function.qself.is_some() || !function.path.is_ident("Ok") || result.args.len() != 1 {
            return false;
        }
        let Some(syn::Expr::Struct(value)) = result.args.first() else {
            return false;
        };
        if !value
            .path
            .is_ident("RestoreAppPreparedConfirmationInstallation")
            || value.rest.is_some()
            || value.fields.len() != 2
        {
            return false;
        }
        value.fields.iter().zip([("confirmation", "confirmation"), ("installation", "self")]).all(|(field, (member, expression))| {
            matches!(&field.member, syn::Member::Named(name) if name == member)
                && matches!(&field.expr, syn::Expr::Path(path) if path.qself.is_none() && path.path.is_ident(expression))
        })
    }

    fn prepared_confirmation_receive_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested = self . installation . installation . installation . issuer_native (IssuerFinishCall",
                "RolePreparedConfirmation { completed : & mut self . installation . installation . issuer , activation : & mut self . installation . activation",
                "requested . is_err ()",
                "self . installation . refuse ()",
                "let confirmation = match requested ? . kind",
                "IssuerFinishReplyKind :: PreparedConfirmation (confirmation) => confirmation",
                "self . installation . refuse ()",
                "restore_app_prepared_confirmation_reply_changed",
                "Ok (RestoreAppPreparedConfirmationInstallation { confirmation , installation : self })",
            ],
        ) && body.matches(". issuer_native (").count() == 1
            && body
                .matches("RestoreAppPreparedConfirmationInstallation {")
                .count()
                == 1
            && body.matches("self . installation . refuse ()").count() == 2
            && !["clone", "NativeAcquisition", "narrow", "set (false)"]
                .iter()
                .any(|part| body.contains(part))
            && prepared_confirmation_return_is_exact(body)
    }

    #[test]
    fn prepared_app_confirmation_requires_the_actual_receive_and_complete_parent_post() {
        let source = include_str!("stop.rs");
        let actual = block(
            source,
            "RestoreAppDecisionSentInstallation",
            "receive_prepared_app_confirmation",
        );
        assert!(prepared_confirmation_receive_is_closed(&actual));
        for (from, to) in [
            (
                "let requested = self . installation . installation . installation . issuer_native",
                "let requested = other_installation . issuer_native",
            ),
            (
                "completed : & mut self . installation . installation . issuer",
                "completed : & mut other_issuer",
            ),
            (
                "activation : & mut self . installation . activation",
                "activation : & mut other_activation",
            ),
            ("self . installation . refuse ()", "unrelated ()"),
            (
                "IssuerFinishReplyKind :: PreparedConfirmation (confirmation) => confirmation",
                "IssuerFinishReplyKind :: Step => saved_confirmation",
            ),
            (
                "confirmation , installation : self",
                "confirmation : saved_confirmation , installation : self",
            ),
            ("installation : self", "installation : other_installation"),
        ] {
            // The refusal occurs twice: both Err and the wrong-reply branch.
            assert_eq!(
                actual.matches(from).count(),
                if from == "self . installation . refuse ()" {
                    2
                } else {
                    1
                },
                "{from}"
            );
            assert!(
                !prepared_confirmation_receive_is_closed(&actual.replacen(from, to, 1)),
                "{from}"
            );
        }
        let dispatch = block(source, "RestoreControllerInstallation", "issuer_native");
        assert!(issuer_native_guard(&dispatch));
        assert!(dispatch.contains("IssuerFinishCallKind :: RolePreparedConfirmation { .. } | IssuerFinishCallKind :: RolePreparedConfirmationCheck { .. } | IssuerFinishCallKind :: RolePreparedAcceptance { .. } | IssuerFinishCallKind :: RoleInstalledConfirmation { .. } | IssuerFinishCallKind :: RoleInstalledConfirmationCheck { .. } | IssuerFinishCallKind :: RoleInstalledAcceptance { .. } => (IssuerFinishProgress :: RoleActivated , IssuerFinishProgress :: RoleActivated)"));
        for (from, to) in [
            (
                "activation . receive_app_confirmation (& mut storage , self . frame . peer , completed , & mut loan)",
                "other_activation . receive_app_confirmation (& mut storage , self . frame . peer , completed , & mut loan)",
            ),
            (
                "activation . receive_app_confirmation (& mut storage , self . frame . peer , completed , & mut loan)",
                "activation . receive_app_confirmation (& mut storage , other_peer , completed , & mut loan)",
            ),
            (
                "confirmation . check (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "other_confirmation . check (& mut storage , self . frame . peer , completed , activation , & mut loan)",
            ),
            (
                "confirmation . check (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . check (& mut storage , self . frame . peer , other_completed , activation , & mut loan)",
            ),
            (
                "confirmation . check (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . check (& mut storage , self . frame . peer , completed , activation , & mut other_loan)",
            ),
            (
                "let checked = self . frame . check_completed_resources ()",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let reply = requested ? ; checked ?",
                "let reply = requested ? ; let _ = checked",
            ),
        ] {
            assert_eq!(dispatch.matches(from).count(), 1, "{from}");
            assert!(
                !issuer_native_guard(&dispatch.replacen(from, to, 1)),
                "{from}"
            );
        }
    }

    #[test]
    fn prepared_confirmation_carrier_is_consuming_private_and_never_an_installation_receipt() {
        use syn::visit::Visit;
        struct Origins {
            method: Option<String>,
            origins: Vec<String>,
        }
        impl<'ast> Visit<'ast> for Origins {
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let prior = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = prior;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "RestoreAppPreparedConfirmationInstallation")
                {
                    self.origins.push(self.method.clone().unwrap_or_default());
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let source = include_str!("stop.rs");
        let file = syn::parse_file(source).unwrap();
        let mut origins = Origins {
            method: None,
            origins: vec![],
        };
        origins.visit_file(&file);
        assert_eq!(origins.origins, ["receive_prepared_app_confirmation"]);
        let extra = format!(
            "{source}\nfn unauthorized() {{ let _=self::RestoreAppPreparedConfirmationInstallation {{confirmation:other,installation:other}}; }}"
        );
        let mut duplicate = Origins {
            method: None,
            origins: vec![],
        };
        duplicate.visit_file(&syn::parse_file(&extra).unwrap());
        assert_ne!(duplicate.origins, ["receive_prepared_app_confirmation"]);
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item)
                    if item.ident == "RestoreAppPreparedConfirmationInstallation" =>
                {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.fields.len(), 2);
        for (field, (name, owner)) in carrier.fields.iter().zip([
            ("confirmation", "PreparedRestoredAppConfirmation"),
            ("installation", "RestoreAppDecisionSentInstallation"),
        ]) {
            assert!(matches!(field.vis, syn::Visibility::Inherited));
            assert!(field.ident.as_ref().is_some_and(|actual| actual == name));
            assert!(actual_owner(&field.ty, owner));
        }
        let factory = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.trait_.is_some()
                    || !actual_owner(&item.self_ty, "RestoreAppDecisionSentInstallation")
                {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item)
                        if item.sig.ident == "receive_prepared_app_confirmation" =>
                    {
                        Some(item)
                    }
                    _ => None,
                })
            })
            .unwrap();
        assert_eq!(factory.sig.inputs.len(), 1);
        assert!(
            matches!(factory.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none() && receiver.mutability.is_some())
        );
        fn check_is_closed(body: &str) -> bool {
            ordered(
                body,
                &[
                    "let checked = self . installation . installation . installation . installation . issuer_native",
                    "RolePreparedConfirmationCheck { completed : & mut self . installation . installation . installation . issuer , activation : & mut self . installation . installation . activation , confirmation : & mut self . confirmation",
                    "match checked",
                    "IssuerFinishReplyKind :: Step",
                    "self . refuse ()",
                    "restore_app_prepared_confirmation_check_reply_changed",
                    "Err (error)",
                    "self . refuse ()",
                    "Err (error)",
                ],
            ) && body.matches(". issuer_native (").count() == 1
                && body.matches("self . refuse ()").count() == 2
        }
        let checked = block(
            source,
            "RestoreAppPreparedConfirmationInstallation",
            "check",
        );
        assert!(check_is_closed(&checked));
        for (from, to) in [
            (
                "let checked = self . installation . installation . installation . installation . issuer_native",
                "let checked = other_installation . issuer_native",
            ),
            (
                "completed : & mut self . installation . installation . installation . issuer",
                "completed : & mut other_issuer",
            ),
            (
                "activation : & mut self . installation . installation . activation",
                "activation : & mut other_activation",
            ),
            (
                "confirmation : & mut self . confirmation",
                "confirmation : & mut other_confirmation",
            ),
            ("match checked", "match Ok(saved_reply)"),
            ("self . refuse ()", "unrelated ()"),
        ] {
            assert_eq!(
                checked.matches(from).count(),
                if from == "self . refuse ()" { 2 } else { 1 },
                "{from}"
            );
            assert!(!check_is_closed(&checked.replacen(from, to, 1)), "{from}");
        }
        assert_eq!(
            block(
                source,
                "RestoreAppPreparedConfirmationInstallation",
                "refuse"
            ),
            "{ self . confirmation . refuse () ; self . installation . installation . refuse () ; }"
        );
        // These controls inspect actual production ownership and call sites.
        // They construct no native receipt, role, original or keeper.
    }

    fn acceptance_send_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "let mut state = RoleHandoffProgress :: Send",
                "state == RoleHandoffProgress :: Delivered",
                "let operation = state . operation () ?",
                "self . installation . installation . installation . installation . issuer_native (IssuerFinishCall",
                "RolePreparedAcceptance { completed : & mut self . installation . installation . installation . issuer , activation : & mut self . installation . installation . activation , confirmation : & mut self . confirmation , operation",
                "requested . is_err ()",
                "self . refuse ()",
                "let progress = match requested ? . kind",
                "IssuerFinishReplyKind :: Progress (progress) => progress",
                "self . refuse ()",
                "restore_controller_acceptance_reply_changed",
                "let next = state . after (operation , progress)",
                "next . is_err ()",
                "self . refuse ()",
                "state = next ?",
                "} self . check () ? ; Ok (RestoreControllerAcceptanceSentInstallation { installation : self })",
            ],
        ) && body.matches(". issuer_native (").count() == 1
            && body.matches("self . refuse ()").count() == 3
            && body
                .matches("RestoreControllerAcceptanceSentInstallation {")
                .count()
                == 1
            && checked_same_carrier_return_is_exact(
                body,
                "RestoreControllerAcceptanceSentInstallation",
            )
    }

    #[test]
    fn controller_acceptance_requires_the_actual_prepared_owner_and_final_full_post() {
        let source = include_str!("stop.rs");
        let actual = block(
            source,
            "RestoreAppPreparedConfirmationInstallation",
            "send_controller_acceptance",
        );
        assert!(acceptance_send_is_closed(&actual));
        for (from, to) in [
            (
                "let mut state = RoleHandoffProgress :: Send",
                "let mut state = RoleHandoffProgress :: Delivered",
            ),
            (
                "self . installation . installation . installation . installation . issuer_native",
                "other_installation . issuer_native",
            ),
            (
                "completed : & mut self . installation . installation . installation . issuer",
                "completed : & mut other_completed",
            ),
            (
                "activation : & mut self . installation . installation . activation",
                "activation : & mut other_activation",
            ),
            (
                "confirmation : & mut self . confirmation",
                "confirmation : & mut other_confirmation",
            ),
            ("self . refuse ()", "unrelated ()"),
            (
                "IssuerFinishReplyKind :: Progress (progress) => progress",
                "IssuerFinishReplyKind :: Step => ReceiverProgress::Delivered",
            ),
            (
                "state . after (operation , progress)",
                "Ok(RoleHandoffProgress::Delivered)",
            ),
            ("self . check () ?", "other_self . check () ?"),
            ("installation : self", "installation : other_installation"),
        ] {
            assert_eq!(
                actual.matches(from).count(),
                if from == "self . refuse ()" { 3 } else { 1 },
                "{from}"
            );
            assert!(
                !acceptance_send_is_closed(&actual.replacen(from, to, 1)),
                "{from}"
            );
        }
        let dispatch = block(source, "RestoreControllerInstallation", "issuer_native");
        assert!(issuer_native_guard(&dispatch));
        for (from, to) in [
            (
                "confirmation . try_send_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "other_confirmation . try_send_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
            ),
            (
                "confirmation . try_send_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . try_send_acceptance (& mut storage , other_peer , completed , activation , & mut loan)",
            ),
            (
                "confirmation . poll_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . poll_acceptance (& mut storage , self . frame . peer , completed , other_activation , & mut loan)",
            ),
            (
                "confirmation . poll_acceptance (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "confirmation . poll_acceptance (& mut storage , self . frame . peer , completed , activation , & mut other_loan)",
            ),
            ("restore_controller_acceptance_wrong_operation", "unrelated"),
            (
                "let checked = self . frame . check_completed_resources ()",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let reply = requested ? ; checked ?",
                "let reply = requested ? ; let _=checked",
            ),
        ] {
            assert_eq!(dispatch.matches(from).count(), 1, "{from}");
            assert!(
                !issuer_native_guard(&dispatch.replacen(from, to, 1)),
                "{from}"
            );
        }
    }

    #[test]
    fn acceptance_send_result_keeps_the_same_private_prepared_carrier() {
        use syn::visit::Visit;
        struct Origins(usize);
        impl<'ast> Visit<'ast> for Origins {
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "RestoreControllerAcceptanceSentInstallation")
                {
                    self.0 += 1;
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let source = include_str!("stop.rs");
        let file = syn::parse_file(source).unwrap();
        let mut origins = Origins(0);
        origins.visit_file(&file);
        assert_eq!(origins.0, 1);
        let extra = format!(
            "{source}\nfn unauthorized() {{let _=self::RestoreControllerAcceptanceSentInstallation {{installation:other}};}}"
        );
        let mut duplicate = Origins(0);
        duplicate.visit_file(&syn::parse_file(&extra).unwrap());
        assert_eq!(duplicate.0, 2);
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item)
                    if item.ident == "RestoreControllerAcceptanceSentInstallation" =>
                {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.fields.len(), 1);
        let field = carrier.fields.iter().next().unwrap();
        assert!(matches!(field.vis, syn::Visibility::Inherited));
        assert!(
            field
                .ident
                .as_ref()
                .is_some_and(|name| name == "installation")
        );
        assert!(actual_owner(
            &field.ty,
            "RestoreAppPreparedConfirmationInstallation"
        ));
        let factory = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.trait_.is_some()
                    || !actual_owner(&item.self_ty, "RestoreAppPreparedConfirmationInstallation")
                {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "send_controller_acceptance" => {
                        Some(item)
                    }
                    _ => None,
                })
            })
            .unwrap();
        assert_eq!(factory.sig.inputs.len(), 1);
        assert!(
            matches!(factory.sig.inputs.first(),Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none() && receiver.mutability.is_some())
        );
        assert_eq!(
            block(
                source,
                "RestoreControllerAcceptanceSentInstallation",
                "check"
            ),
            "{ self . installation . check () }"
        );
        // Inspection of real production constructors, not a fabricated native
        // confirmation/role/keeper or an assertion of installed success.
    }

    fn installed_final_check_is_exact(body: &str) -> bool {
        let Ok(body) = syn::parse_str::<syn::Block>(body) else {
            return false;
        };
        let [.., before, last] = body.stmts.as_slice() else {
            return false;
        };
        let syn::Stmt::Expr(syn::Expr::Try(checked), Some(_)) = before else {
            return false;
        };
        let syn::Expr::MethodCall(call) = &*checked.expr else {
            return false;
        };
        if call.method != "check_installed_confirmation"
            || call.turbofish.is_some()
            || call.args.len() != 1
        {
            return false;
        }
        if !matches!(&*call.receiver,syn::Expr::Path(path) if path.qself.is_none() && path.path.is_ident("self"))
        {
            return false;
        }
        let Some(syn::Expr::Reference(argument)) = call.args.first() else {
            return false;
        };
        if argument.mutability.is_none()
            || !matches!(&*argument.expr,syn::Expr::Path(path) if path.qself.is_none() && path.path.is_ident("installed"))
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Call(result), None) = last else {
            return false;
        };
        if !matches!(&*result.func,syn::Expr::Path(path) if path.qself.is_none() && path.path.is_ident("Ok"))
            || result.args.len() != 1
        {
            return false;
        }
        let Some(syn::Expr::Struct(value)) = result.args.first() else {
            return false;
        };
        value.path.is_ident("RestoreAppInstalledConfirmationInstallation") && value.rest.is_none() && value.fields.len()==2
            && value.fields.iter().zip([("installed","installed"),("installation","self")]).all(|(field,(member,name))| {
                matches!(&field.member,syn::Member::Named(actual) if actual==member)
                    && matches!(&field.expr,syn::Expr::Path(path) if path.qself.is_none() && path.path.is_ident(name))
            })
    }

    fn installed_receive_is_closed(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested = self . installation . installation . installation . installation . installation . issuer_native (IssuerFinishCall",
                "RoleInstalledConfirmation { completed : & mut self . installation . installation . installation . installation . issuer , activation : & mut self . installation . installation . installation . activation , prepared : & mut self . installation . confirmation }",
                "requested . is_err ()",
                "self . installation . refuse ()",
                "let mut installed = match requested ? . kind",
                "IssuerFinishReplyKind :: InstalledConfirmation (installed) => installed",
                "self . installation . refuse ()",
                "restore_installed_confirmation_reply_changed",
                "self . check_installed_confirmation (& mut installed) ?",
                "Ok (RestoreAppInstalledConfirmationInstallation { installed , installation : self })",
            ],
        ) && body.matches(". issuer_native (").count() == 1
            && body.matches("self . installation . refuse ()").count() == 2
            && installed_final_check_is_exact(body)
    }

    #[test]
    fn installed_confirmation_requires_actual_receipt_and_fresh_full_check_before_return() {
        let source = include_str!("stop.rs");
        let actual = block(
            source,
            "RestoreControllerAcceptanceSentInstallation",
            "receive_installed_app_confirmation",
        );
        assert!(installed_receive_is_closed(&actual));
        for (from, to) in [
            (
                "let requested = self . installation . installation . installation . installation . installation . issuer_native",
                "let requested = other_installation . issuer_native",
            ),
            (
                "completed : & mut self . installation . installation . installation . installation . issuer",
                "completed : & mut other_completed",
            ),
            (
                "activation : & mut self . installation . installation . installation . activation",
                "activation : & mut other_activation",
            ),
            (
                "prepared : & mut self . installation . confirmation",
                "prepared : & mut other_prepared",
            ),
            (
                "IssuerFinishReplyKind :: InstalledConfirmation (installed) => installed",
                "IssuerFinishReplyKind :: Step => saved_installed",
            ),
            ("self . installation . refuse ()", "unrelated ()"),
            (
                "self . check_installed_confirmation (& mut installed) ?",
                "other_self . check_installed_confirmation (& mut installed) ?",
            ),
            (
                "self . check_installed_confirmation (& mut installed) ?",
                "self . check_installed_confirmation (& mut other_installed) ?",
            ),
            (
                "installed , installation : self",
                "installed : other_installed , installation : self",
            ),
            ("installation : self", "installation : other_installation"),
        ] {
            assert_eq!(
                actual.matches(from).count(),
                if from == "self . installation . refuse ()" {
                    2
                } else {
                    1
                },
                "{from}"
            );
            assert!(
                !installed_receive_is_closed(&actual.replacen(from, to, 1)),
                "{from}"
            );
        }
        let dispatch = block(source, "RestoreControllerInstallation", "issuer_native");
        assert!(issuer_native_guard(&dispatch));
        for (from, to) in [
            (
                "prepared . receive_installed_confirmation (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "other_prepared . receive_installed_confirmation (& mut storage , self . frame . peer , completed , activation , & mut loan)",
            ),
            (
                "prepared . receive_installed_confirmation (& mut storage , self . frame . peer , completed , activation , & mut loan)",
                "prepared . receive_installed_confirmation (& mut storage , self . frame . peer , other_completed , activation , & mut loan)",
            ),
            (
                "installed . check (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "other_installed . check (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
            ),
            (
                "installed . check (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "installed . check (& mut storage , self . frame . peer , completed , activation , other_prepared , & mut loan)",
            ),
            (
                "installed . check (& mut storage , self . frame . peer , completed , activation , prepared , & mut loan)",
                "installed . check (& mut storage , self . frame . peer , completed , activation , prepared , & mut other_loan)",
            ),
            (
                "let checked = self . frame . check_completed_resources ()",
                "let checked = Ok::<(),anyhow::Error>(())",
            ),
            (
                "let reply = requested ? ; checked ?",
                "let reply = requested ? ; let _=checked",
            ),
        ] {
            assert_eq!(dispatch.matches(from).count(), 1, "{from}");
            assert!(
                !issuer_native_guard(&dispatch.replacen(from, to, 1)),
                "{from}"
            );
        }
    }

    #[test]
    fn installed_confirmation_result_is_private_consuming_and_keeps_actual_parent_lineage() {
        use syn::visit::Visit;
        struct Origins(usize);
        impl<'ast> Visit<'ast> for Origins {
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "RestoreAppInstalledConfirmationInstallation")
                {
                    self.0 += 1;
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let source = include_str!("stop.rs");
        let file = syn::parse_file(source).unwrap();
        let mut origins = Origins(0);
        origins.visit_file(&file);
        assert_eq!(origins.0, 1);
        let extra = format!(
            "{source}\nfn unauthorized() {{let _=self::RestoreAppInstalledConfirmationInstallation {{installed:other,installation:other}};}}"
        );
        let mut duplicate = Origins(0);
        duplicate.visit_file(&syn::parse_file(&extra).unwrap());
        assert_eq!(duplicate.0, 2);
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item)
                    if item.ident == "RestoreAppInstalledConfirmationInstallation" =>
                {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.fields.len(), 2);
        for (field, (name, owner)) in carrier.fields.iter().zip([
            ("installed", "InstalledRestoredAppConfirmation"),
            (
                "installation",
                "RestoreControllerAcceptanceSentInstallation",
            ),
        ]) {
            assert!(matches!(field.vis, syn::Visibility::Inherited));
            assert!(field.ident.as_ref().is_some_and(|actual| actual == name));
            assert!(actual_owner(&field.ty, owner));
        }
        let factory = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.trait_.is_some()
                    || !actual_owner(&item.self_ty, "RestoreControllerAcceptanceSentInstallation")
                {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item)
                        if item.sig.ident == "receive_installed_app_confirmation" =>
                    {
                        Some(item)
                    }
                    _ => None,
                })
            })
            .unwrap();
        assert_eq!(factory.sig.inputs.len(), 1);
        assert!(
            matches!(factory.sig.inputs.first(),Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none() && receiver.mutability.is_some())
        );
        assert_eq!(
            block(
                source,
                "RestoreAppInstalledConfirmationInstallation",
                "check"
            ),
            "{ self . installation . check_installed_confirmation (& mut self . installed) }"
        );
        let checked = block(
            source,
            "RestoreControllerAcceptanceSentInstallation",
            "check_installed_confirmation",
        );
        fn fresh(body: &str) -> bool {
            ordered(
                body,
                &[
                    "let checked = self . installation . installation . installation . installation . installation . issuer_native",
                    "RoleInstalledConfirmationCheck { completed : & mut self . installation . installation . installation . installation . issuer , activation : & mut self . installation . installation . installation . activation , prepared : & mut self . installation . confirmation , installed }",
                    "match checked",
                    "IssuerFinishReplyKind :: Step",
                    "installed . refuse ()",
                    "self . installation . refuse ()",
                    "restore_installed_confirmation_check_reply_changed",
                    "Err (error)",
                    "installed . refuse ()",
                    "self . installation . refuse ()",
                    "Err (error)",
                ],
            ) && body.matches(". issuer_native (").count() == 1
                && body.matches("installed . refuse ()").count() == 2
                && body.matches("self . installation . refuse ()").count() == 2
        }
        assert!(fresh(&checked));
        for (from, to) in [
            (
                "let checked = self . installation . installation . installation . installation . installation . issuer_native",
                "let checked = other_installation . issuer_native",
            ),
            (
                "prepared : & mut self . installation . confirmation",
                "prepared : & mut other_prepared",
            ),
            (", installed }", ", installed : other_installed }"),
            ("installed . refuse ()", "unrelated ()"),
            ("self . installation . refuse ()", "unrelated ()"),
            ("match checked", "match Ok(saved_reply)"),
        ] {
            assert_eq!(
                checked.matches(from).count(),
                if from.ends_with("refuse ()") { 2 } else { 1 },
                "{from}"
            );
            assert!(!fresh(&checked.replacen(from, to, 1)), "{from}");
        }
        // Only production syntax/ownership is inspected. No installed receipt,
        // role, Runtime, Current or first keeper is fabricated by these tests.
    }
}

#[cfg(test)]
mod controller_current_loan_source_tests {
    use quote::ToTokens;

    fn method(owner: &str, name: &str) -> syn::ImplItemFn {
        syn::parse_file(include_str!("stop.rs"))
            .unwrap()
            .items
            .into_iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|part|part.ident==owner))
                {
                    return None;
                }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn lifetimes(ty: &syn::Type, name: &str) -> Option<Vec<String>> {
        let syn::Type::Path(path) = ty else {
            return None;
        };
        let part = path.path.segments.last()?;
        if part.ident != name {
            return None;
        }
        let syn::PathArguments::AngleBracketed(args) = &part.arguments else {
            return None;
        };
        args.args
            .iter()
            .map(|arg| match arg {
                syn::GenericArgument::Lifetime(arg) => Some(arg.ident.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn controller_current_loan_moves_the_whole_carrier_without_erasing_lifetimes() {
        let expected = [
            "frame",
            "confirm",
            "metadata",
            "storage",
            "role",
            "target",
            "selection",
        ];
        let file = syn::parse_file(include_str!("stop.rs")).unwrap();
        let loan = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "ControllerCurrentInstallationLoan" => {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(loan.fields.len(), 1);
        let field = loan.fields.iter().next().unwrap();
        assert!(matches!(field.vis, syn::Visibility::Inherited));
        assert_eq!(field.ident.as_ref().unwrap(), "installation");
        assert_eq!(
            lifetimes(&field.ty, "RestoreAppInstalledConfirmationInstallation").unwrap(),
            expected
        );
        fn whole(method: &syn::ImplItemFn) -> bool {
            let expected = [
                "frame",
                "confirm",
                "metadata",
                "storage",
                "role",
                "target",
                "selection",
            ];
            if method.sig.inputs.len() != 1 {
                return false;
            }
            let Some(syn::FnArg::Receiver(receiver)) = method.sig.inputs.first() else {
                return false;
            };
            if receiver.reference.is_some()
                || receiver.colon_token.is_some()
                || !method.sig.generics.params.is_empty()
                || method.sig.asyncness.is_some()
            {
                return false;
            }
            let syn::ReturnType::Type(_, output) = &method.sig.output else {
                return false;
            };
            if lifetimes(output, "ControllerCurrentInstallationLoan").as_deref()
                != Some(expected.map(str::to_owned).as_slice())
            {
                return false;
            }
            let [syn::Stmt::Expr(syn::Expr::Struct(value), None)] = method.block.stmts.as_slice()
            else {
                return false;
            };
            value
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == "ControllerCurrentInstallationLoan")
                && value.rest.is_none()
                && value.fields.len() == 1
                && matches!(value.fields.first(),Some(field)
                    if matches!(&field.member,syn::Member::Named(name) if name=="installation")
                    && matches!(&field.expr,syn::Expr::Path(path) if path.path.is_ident("self")))
        }
        let actual = method(
            "RestoreAppInstalledConfirmationInstallation",
            "into_controller_current_loan",
        );
        assert!(whole(&actual));
        let rendered = actual.to_token_stream().to_string();
        for (from, to) in [
            ("self ,", "& self ,"),
            ("installation : self", "installation : other"),
            ("'storage", "'static"),
        ] {
            assert!(rendered.contains(from), "{from}");
            let mutant: syn::ImplItemFn = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(!whole(&mutant), "{from}");
        }
    }

    #[test]
    fn controller_current_loan_checks_actual_installed_parent_and_refuses_both_layers() {
        let check = method("ControllerCurrentInstallationLoan", "check");
        let expected: syn::Block = syn::parse_quote!({
            let checked = self.installation.check();
            if checked.is_err() {
                self.refuse();
            }
            checked
        });
        let body = check.block.to_token_stream().to_string();
        assert_eq!(body, expected.to_token_stream().to_string());
        for (from, to) in [
            (
                "self . installation . check",
                "other . installation . check",
            ),
            ("is_err", "is_ok"),
            ("self . refuse", "other . refuse"),
        ] {
            assert_eq!(body.matches(from).count(), 1);
            assert_ne!(
                syn::parse_str::<syn::Block>(&body.replacen(from, to, 1))
                    .unwrap()
                    .to_token_stream()
                    .to_string(),
                expected.to_token_stream().to_string()
            );
        }
        let refuse = method("ControllerCurrentInstallationLoan", "refuse").block;
        let expected: syn::Block = syn::parse_quote!({
            self.installation.installed.refuse();
            self.installation.installation.installation.refuse();
        });
        assert_eq!(
            refuse.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    #[test]
    fn controller_current_entry_uses_only_the_whole_installed_carrier_and_real_child() {
        fn fixed(method: &syn::ImplItemFn) -> bool {
            let expected = [
                "frame",
                "confirm",
                "metadata",
                "storage",
                "role",
                "target",
                "selection",
            ];
            if method.sig.ident != "prepare_controller_current"
                || method.sig.inputs.len() != 1
                || method.sig.asyncness.is_some()
                || method.sig.constness.is_some()
                || method.sig.unsafety.is_some()
                || method.sig.abi.is_some()
                || !method.sig.generics.params.is_empty()
                || method.sig.generics.where_clause.is_some()
                || method.vis.to_token_stream().to_string() != "pub (in crate :: security_epoch)"
            {
                return false;
            }
            let Some(syn::FnArg::Receiver(receiver)) = method.sig.inputs.first() else {
                return false;
            };
            if receiver.reference.is_some()
                || receiver.colon_token.is_some()
                || receiver.mutability.is_some()
            {
                return false;
            }
            let syn::ReturnType::Type(_, output) = &method.sig.output else {
                return false;
            };
            let syn::Type::Path(result) = &**output else {
                return false;
            };
            if result.qself.is_some() || result.path.segments.len() != 1 {
                return false;
            }
            let part = result.path.segments.first().unwrap();
            if part.ident != "Result" {
                return false;
            }
            let syn::PathArguments::AngleBracketed(args) = &part.arguments else {
                return false;
            };
            if args.args.len() != 1 {
                return false;
            }
            let Some(syn::GenericArgument::Type(pending)) = args.args.first() else {
                return false;
            };
            if lifetimes(pending, "PendingControllerCurrentInstallation").as_deref()
                != Some(expected.map(str::to_owned).as_slice())
            {
                return false;
            }
            let expected: syn::Block = syn::parse_quote!({
                PendingControllerCurrentInstallation::prepare(self.into_controller_current_loan())
            });
            method.block.to_token_stream().to_string() == expected.to_token_stream().to_string()
        }
        let actual = method(
            "RestoreAppInstalledConfirmationInstallation",
            "prepare_controller_current",
        );
        assert!(fixed(&actual));
        let text = actual.to_token_stream().to_string();
        for (from, to) in [
            ("self ,", "& self ,"),
            (
                "self . into_controller_current_loan ()",
                "other . into_controller_current_loan ()",
            ),
            (
                "PendingControllerCurrentInstallation :: prepare",
                "other_prepare",
            ),
            ("'selection", "'static"),
        ] {
            assert_eq!(text.matches(from).count(), 1, "{from}");
            let changed = syn::parse_str(&text.replacen(from, to, 1)).unwrap();
            assert!(!fixed(&changed), "{from}");
        }
        let file = syn::parse_file(include_str!("stop.rs")).unwrap();
        let modules = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(item) if item.ident == "native_current" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(modules.len(), 1);
        assert!(modules[0].attrs.is_empty());
        assert!(matches!(modules[0].vis, syn::Visibility::Inherited));
        assert!(modules[0].content.is_none());
        assert!(modules[0].semi.is_some());
        let reexports = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Use(item)
                    if item.tree.to_token_stream().to_string()
                        == "native_current :: PendingControllerCurrentInstallation" =>
                {
                    Some(item)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(reexports.len(), 1);
        assert_eq!(
            reexports[0].vis.to_token_stream().to_string(),
            "pub (in crate :: security_epoch)"
        );
    }
}

#[cfg(test)]
mod installed_acceptance_source_tests {
    use super::{RoleHandoffIo, RoleHandoffProgress};
    use crate::security_epoch::native_enrollment::ReceiverProgress;
    use quote::ToTokens;
    use syn::visit::Visit;

    fn method(owner: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("stop.rs")).unwrap();
        let found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner)) { return None; }
            item.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident==name => Some(item), _ => None,
            })
        }).collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        found.into_iter().next().unwrap()
    }

    fn sender_guard(body: &syn::Block) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let mut state = RoleHandoffProgress::Send;
            loop {
                if state == RoleHandoffProgress::Delivered {
                    break;
                }
                let operation = state.operation()?;
                let requested = self
                    .installation
                    .installation
                    .installation
                    .installation
                    .installation
                    .installation
                    .issuer_native(IssuerFinishCall {
                        kind: IssuerFinishCallKind::RoleInstalledAcceptance {
                            completed: &mut self
                                .installation
                                .installation
                                .installation
                                .installation
                                .installation
                                .issuer,
                            activation: &mut self
                                .installation
                                .installation
                                .installation
                                .installation
                                .activation,
                            prepared: &mut self.installation.installation.confirmation,
                            installed: &mut self.installed,
                            operation,
                        },
                    });
                if requested.is_err() {
                    self.refuse();
                }
                let progress = match requested?.kind {
                    IssuerFinishReplyKind::Progress(progress) => progress,
                    _ => {
                        self.refuse();
                        anyhow::bail!("restore_installed_acceptance_reply_changed");
                    }
                };
                let next = state.after(operation, progress);
                if next.is_err() {
                    self.refuse();
                }
                state = next?;
            }
            Ok(())
        });
        body.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    #[test]
    fn actual_installed_acceptance_uses_same_receipt_and_short_parent_loan_for_each_packet_step() {
        let actual = method(
            "RestoreAppInstalledConfirmationInstallation",
            "send_installed_acceptance",
        );
        assert!(sender_guard(&actual.block));
        let rendered = actual.block.to_token_stream().to_string();
        for (from, to) in [
            (
                "let mut state = RoleHandoffProgress :: Send",
                "let mut state = RoleHandoffProgress::Delivered",
            ),
            ("RoleInstalledAcceptance", "RolePreparedAcceptance"),
            (
                "installed : & mut self . installed",
                "installed: &mut saved_installed",
            ),
            (
                "prepared : & mut self . installation . installation . confirmation",
                "prepared: &mut other_prepared",
            ),
            (
                "state . after (operation , progress)",
                "Ok(RoleHandoffProgress::Delivered)",
            ),
        ] {
            assert_eq!(rendered.matches(from).count(), 1, "{from}");
            let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(!sender_guard(&changed), "{from}");
        }
        let mut no_refusal = actual.block.clone();
        let syn::Stmt::Expr(syn::Expr::Loop(body), _) = &mut no_refusal.stmts[1] else {
            panic!("sender loop missing");
        };
        body.body.stmts.remove(3);
        assert!(!sender_guard(&no_refusal));
    }

    #[test]
    fn actual_dispatch_uses_only_installed_send_or_poll_on_exact_native_owner_arguments() {
        struct Arms(Vec<syn::Arm>);
        impl<'ast> Visit<'ast> for Arms {
            fn visit_arm(&mut self, arm: &'ast syn::Arm) {
                if matches!(&arm.pat,syn::Pat::Struct(pattern) if pattern.path.segments.last().is_some_and(|part|part.ident=="RoleInstalledAcceptance"))
                {
                    self.0.push(arm.clone());
                }
                syn::visit::visit_arm(self, arm);
            }
        }
        let actual = method("RestoreControllerInstallation", "issuer_native");
        let mut arms = Arms(Vec::new());
        arms.visit_block(&actual.block);
        assert_eq!(arms.0.len(), 1);
        assert!(arms.0[0].attrs.is_empty());
        let expected: syn::Expr = syn::parse_quote!({
            let progress = match operation {
                RoleHandoffIo::Send => installed.try_send_acceptance(
                    &mut storage,
                    self.frame.peer,
                    completed,
                    activation,
                    prepared,
                    &mut loan,
                )?,
                RoleHandoffIo::Poll => installed.poll_acceptance(
                    &mut storage,
                    self.frame.peer,
                    completed,
                    activation,
                    prepared,
                    &mut loan,
                )?,
                RoleHandoffIo::Prepare | RoleHandoffIo::Sign => {
                    anyhow::bail!("restore_installed_acceptance_wrong_operation")
                }
            };
            IssuerFinishReplyKind::Progress(progress)
        });
        let guard = |body: &syn::Expr| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guard(&arms.0[0].body));
        let rendered = arms.0[0].body.to_token_stream().to_string();
        for (from, to) in [
            (
                "installed . try_send_acceptance",
                "prepared.try_send_acceptance",
            ),
            (
                "installed . poll_acceptance",
                "other_installed.poll_acceptance",
            ),
            (
                "completed , activation , prepared",
                "other_completed, activation, prepared",
            ),
        ] {
            let expected_count = if from == "completed , activation , prepared" {
                2
            } else {
                1
            };
            assert_eq!(rendered.matches(from).count(), expected_count);
            let changed: syn::Expr = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(!guard(&changed));
        }
    }

    #[test]
    fn real_packet_progress_never_turns_wait_or_wrong_operation_into_acceptance() {
        let state = RoleHandoffProgress::Send;
        assert!(
            state
                .after(RoleHandoffIo::Poll, ReceiverProgress::Delivered)
                .is_err()
        );
        assert!(
            state
                .after(RoleHandoffIo::Send, ReceiverProgress::Advanced)
                .is_err()
        );
        let state = state
            .after(RoleHandoffIo::Send, ReceiverProgress::WouldBlock)
            .unwrap();
        assert_eq!(state, RoleHandoffProgress::Poll);
        assert!(
            state
                .after(RoleHandoffIo::Poll, ReceiverProgress::Delivered)
                .is_err()
        );
        let state = state
            .after(RoleHandoffIo::Poll, ReceiverProgress::Interrupted)
            .unwrap();
        assert_eq!(state, RoleHandoffProgress::Poll);
        let state = state
            .after(RoleHandoffIo::Poll, ReceiverProgress::Advanced)
            .unwrap();
        assert_eq!(state, RoleHandoffProgress::Send);
        let state = state
            .after(RoleHandoffIo::Send, ReceiverProgress::Interrupted)
            .unwrap();
        assert_eq!(state, RoleHandoffProgress::Send);
        let state = state
            .after(RoleHandoffIo::Send, ReceiverProgress::Delivered)
            .unwrap();
        assert_eq!(state, RoleHandoffProgress::Delivered);
        assert!(state.operation().is_err());
    }
}
