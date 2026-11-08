//! Closed new-writer admission foundation. No production approval, settled-root
//! supplier, P3/writer/peer source or conversion to a serving owner exists here.
//! A future supplier must retain genuine SAME-original rights, not stamp a
//! cloned continuity ID onto separately acquired native authority.
use super::{CHUNK, Checks, MAX_BYTES, Projection, State, execute, sum};
use crate::security_epoch::restore_fencing::{self as fence, ApprovalIdentity, Binding, Session};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use ring::digest::{Context as Hash, SHA256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
};
use zeroize::Zeroizing;

mod dispatch;
mod receiver;
pub(in crate::security_epoch) use dispatch::{Disposition, Flight};

/// Borrow the actual completed target while retaining the genuine Controller
/// peer. The fixed CAS driver can split only these two private fields for its
/// short source loan; it cannot reconstruct either from holder or ACK DATA.
pub(in crate::security_epoch) struct RestoredWriterCandidate<'target, 'state, 'selection> {
    target: &'target mut NativeStagedTarget<'state, 'selection>,
    peer: crate::security_epoch::native_enrollment::RestoredWriterPeer,
}

/// Own the actual consumed executor continuation outside its one borrowed
/// writer frame. There is deliberately no production staging-State producer:
/// a full admitted archive/selection supplier remains necessary for entry.
/// No owner, descriptor, callback or raw transaction getter is provided.
pub(super) struct NativeRestore<'metadata, 'storage, 'role, 'selection> {
    pending: Option<State>,
    selection: super::application::Selection<'selection>,
    artifact: super::archive::CapturedRestoreArtifact<'selection>,
    intent: crate::security_epoch::kernel::restore::Intent,
    owner: crate::security_epoch::bootstrap::FencedRestoreContinuation<'metadata, 'storage, 'role>,
}

impl<'metadata, 'storage, 'role, 'selection> NativeRestore<'metadata, 'storage, 'role, 'selection> {
    pub(super) fn consume(
        mut auth: crate::security_epoch::bootstrap::AuthenticatedRestoreExecution<
            'metadata,
            'storage,
            'role,
        >,
        intent: &crate::security_epoch::kernel::restore::Intent,
        state: State,
        selection: super::application::Selection<'selection>,
        artifact: super::archive::CapturedRestoreArtifact<'selection>,
    ) -> Result<Self> {
        let bound = state
            .require_unstarted()
            .and_then(|()| selection.require_native_input(&state.input, intent))
            .and_then(|()| artifact.require_input(intent));
        if bound.is_err() {
            auth.refuse();
        }
        bound?;
        let owner = auth.stop_for_restore(intent)?;
        Ok(Self {
            pending: Some(state),
            selection,
            artifact,
            intent: intent.clone(),
            owner,
        })
    }

    fn begin(&mut self) -> Result<NativeParent<'_, 'metadata, 'storage, 'role, '_>> {
        let mut loan = self.owner.borrow_write()?;
        let Some(state) = self.pending.take() else {
            loan.refuse();
            anyhow::bail!("native_restore_staging_borrow_spent");
        };
        NativeParent::admit(
            loan,
            state,
            self.selection.reborrow(),
            &self.intent,
            &self.artifact,
        )
    }
}

/// Retains the actual exclusive fenced loan through the same staging state.
/// Its sole private constructor requires the actual exclusive loan, checks its
/// exact bound input and admits the physical root before creating this frame.
/// No DATA plan, staged projection or freshly captured role constructs a loan.
struct NativeParent<'borrow, 'metadata, 'storage, 'role, 'selection> {
    loan: crate::security_epoch::bootstrap::RestoreWriteLoan<'borrow, 'metadata, 'storage, 'role>,
    root: crate::security_epoch::storage_authority::RestoreCreatorRoot,
    state: State,
    selection: super::application::Selection<'selection>,
    artifact: &'selection super::archive::CapturedRestoreArtifact<'selection>,
    installed: Option<super::archive::InstalledRestoreArtifact>,
}

impl<'borrow, 'metadata, 'storage, 'role, 'selection>
    NativeParent<'borrow, 'metadata, 'storage, 'role, 'selection>
{
    fn admit(
        mut loan: crate::security_epoch::bootstrap::RestoreWriteLoan<
            'borrow,
            'metadata,
            'storage,
            'role,
        >,
        state: State,
        selection: super::application::Selection<'selection>,
        intent: &crate::security_epoch::kernel::restore::Intent,
        artifact: &'selection super::archive::CapturedRestoreArtifact<'selection>,
    ) -> Result<Self> {
        let requested: Result<_> = (|| {
            // A directory/DTO cannot supply the retained record or namespace
            // generation. This fixed check precedes every source/file effect.
            loan.require_staging_input(intent, &state.input.namespace)?;
            state.require_unstarted()?;
            selection.require_native_input(&state.input, intent)?;
            let admitted = loan.admit_creator_root(&state.root);
            let post = loan.check_current();
            let root = admitted?;
            post?;
            Ok(root)
        })();
        if requested.is_err() {
            loan.refuse();
        }
        let root = requested?;
        let mut parent = NativeParent {
            loan,
            root,
            state,
            selection,
            artifact,
            installed: None,
        };
        parent.current()?;
        Ok(parent)
    }
}

impl NativeParent<'_, '_, '_, '_, '_> {
    fn execute_staging(&mut self) -> Result<Projection> {
        super::execute_context(&mut StagingContext::native(self))
    }

    /// Use only the actual successful reset result to form observation DATA.
    /// The fixed lower settlement still authenticates the creator and intent.
    fn stage_and_settle(
        &mut self,
        intent: &crate::security_epoch::kernel::restore::Intent,
    ) -> Result<crate::security_epoch::kernel::restore::completion::Receipt> {
        let result = (|| {
            self.selection
                .require_native_input(&self.state.input, intent)?;
            let projection = self.execute_staging()?;
            ensure!(
                self.installed.is_none(),
                "restore_artifact_install_attempt_spent"
            );
            let requested =
                self.artifact
                    .install(&mut self.loan, &mut self.root, &mut self.state, intent);
            let checked = self.current();
            let installed = requested?;
            checked?;
            self.installed = Some(installed);
            // This sole constructor borrows the ACTUAL completed reset frame.
            // A report, path or reopened file cannot construct this target.
            let requested = {
                let mut target = NativeStagedTarget {
                    state: &mut self.state,
                    root: &mut self.root,
                    selection: self.selection.reborrow(),
                    intent,
                    projection,
                    cohort_attempted: false,
                    artifact: self
                        .installed
                        .as_mut()
                        .context("restore_artifact_not_installed")?,
                };
                self.loan.settle_target(&mut target)
            };
            let post = self.current();
            let receipt = requested?;
            post?;
            Ok(receipt)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn state(&mut self) -> &mut State {
        &mut self.state
    }

    fn current(&mut self) -> Result<()> {
        let checked = (|| {
            self.loan.check_current()?;
            let requested = self.root.check(&self.state.root);
            let artifact = match self.installed.as_mut() {
                Some(artifact) => artifact.check(&self.state),
                None => Ok(()),
            };
            let post = self.loan.check_current();
            requested?;
            artifact?;
            post.map(|_| ())
        })();
        if checked.is_err() {
            self.refuse();
        }
        checked
    }

    fn local_sql(&mut self) -> Result<()> {
        // The actual loan and pinned-root checks are SQL-safe. No coherent
        // provider read, peer wait or policy SQL runs inside the builder's unit.
        // Always evaluate the retained postcheck, preserving the root failure.
        let checked = (|| {
            self.loan.check_local()?;
            let requested = self.root.check(&self.state.root);
            let artifact = match self.installed.as_mut() {
                Some(artifact) => artifact.check(&self.state),
                None => Ok(()),
            };
            let post = self.loan.check_local();
            requested?;
            artifact?;
            post
        })();
        if checked.is_err() {
            self.refuse();
        }
        checked
    }

    fn application(
        &mut self,
        _source: &rusqlite::Transaction<'_>,
    ) -> Result<super::application::Selection<'_>> {
        ensure!(
            self.state.attempted && !self.state.refused && self.state.sql.is_none(),
            "native_restore_parent_sql_loan_required"
        );
        // Prepared immutable input only. reset_in still checks the exact
        // staging namespace/epoch/artifact/model before canonical reset.
        Ok(self.selection.reborrow())
    }

    fn refuse(&mut self) {
        self.state.refused = true;
        self.loan.refuse();
    }
}

/// A nonescaping borrow of the real successfully reset target. Its fields and
/// sole constructor are private; it is never made from report/creator DATA.
pub(in crate::security_epoch) struct NativeStagedTarget<'state, 'selection> {
    state: &'state mut State,
    root: &'state mut crate::security_epoch::storage_authority::RestoreCreatorRoot,
    selection: super::application::Selection<'selection>,
    intent: &'state crate::security_epoch::kernel::restore::Intent,
    projection: Projection,
    cohort_attempted: bool,
    artifact: &'state mut super::archive::InstalledRestoreArtifact,
}

impl NativeStagedTarget<'_, '_> {
    /// Actual held-creator metadata only. This returns no file, descriptor or
    /// permission; the full parent and retained native peer remain mandatory.
    pub(in crate::security_epoch) fn creator_data(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::RestoreCreatorData> {
        let requested = (|| {
            self.handles(check)?;
            let metadata = self
                .state
                .creator
                .as_ref()
                .context("restore_creator_missing")?
                .metadata();
            let checked = self.handles(check);
            let metadata = metadata?;
            checked?;
            ensure!(
                metadata.is_file()
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o7777 == 0o600
                    && metadata.len() == self.projection.bytes
                    && self.state.creator_identity == Some((metadata.dev(), metadata.ino())),
                "native_restore_creator_projection_changed"
            );
            #[cfg(target_os = "linux")]
            let device = metadata.dev();
            #[cfg(not(target_os = "linux"))]
            let device: rustix::fs::Dev = metadata.dev().try_into()?;
            Ok(
                crate::security_epoch::native_enrollment::RestoreCreatorData {
                    device_major: rustix::fs::major(device),
                    device_minor: rustix::fs::minor(device),
                    inode: metadata.ino(),
                    length: metadata.len(),
                    user: metadata.uid(),
                    group: metadata.gid(),
                },
            )
        })();
        let checked = self.handles(check);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            check.refuse();
        }
        let creator = requested?;
        checked?;
        Ok(creator)
    }

    /// Same held creator/directory/root, after the actual App's Confirm and
    /// before its Durable packet. There is no returned P3/readiness witness.
    pub(in crate::security_epoch) fn sync_for_receiver(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
        receiver: &mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>,
    ) -> Result<()> {
        let mut peer = Some(receiver);
        let requested: Result<()> = (|| {
            self.handles_with(check, &mut peer)?;
            let synced = self
                .state
                .creator
                .as_ref()
                .context("restore_creator_missing")?
                .sync_all();
            let checked = self.handles_with(check, &mut peer);
            synced?;
            checked?;
            self.handles_with(check, &mut peer)?;
            let synced = self
                .state
                .directory
                .as_ref()
                .context("restore_directory_missing")?
                .sync_all();
            let checked = self.handles_with(check, &mut peer);
            synced?;
            checked?;
            self.handles_with(check, &mut peer)?;
            let synced = self.state.root.sync_all();
            let checked = self.handles_with(check, &mut peer);
            synced?;
            checked?;
            self.validate_with(check, &mut peer)?;
            Ok(())
        })();
        let checked = self.handles_with(check, &mut peer);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            check.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state.refused = true;
    }

    fn check_native(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
        peer: &mut Option<&mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>>,
    ) -> Result<()> {
        match peer.as_deref_mut() {
            Some(receiver) => check.check_durability_receiver(self, receiver),
            None => check.check(),
        }
    }

    fn handles(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
    ) -> Result<()> {
        self.handles_with(check, &mut None)
    }

    /// Only the distinct actual post-Activated borrow uses this identity
    /// purpose. An authorized App may now change MAIN length/content and
    /// create WAL/SHM. The held MAIN/root/directory, ownership, original and
    /// installed artifact must remain exact; this returns no serving owner.
    pub(in crate::security_epoch) fn check_active_identity(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
        creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
        report: &crate::security_epoch::kernel::restore::completion::TargetReport,
    ) -> Result<()> {
        let requested = (|| {
            self.handles(check)?;
            let metadata = self
                .state
                .creator
                .as_ref()
                .context("restore_creator_missing")?
                .metadata();
            let checked = self.handles(check);
            let metadata = metadata?;
            checked?;
            require_active_creator_metadata(&metadata, creator)?;
            ensure!(
                self.selection
                    .native_report(&self.state.input, self.intent, &self.projection)?
                    == *report,
                "restore_writer_active_report_changed"
            );
            Ok(())
        })();
        let checked = self.handles(check);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            check.refuse();
        }
        requested?;
        checked
    }

    /// Called only from the actual post-ACK frame, under its whole Known
    /// pre/post. Each O_PATH observation is locally bracketed by the same
    /// target/original checks; this never creates another SQLite connection.
    pub(in crate::security_epoch) fn pin_active_cohort(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
        creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
        report: &crate::security_epoch::kernel::restore::completion::TargetReport,
    ) -> Result<RestoreControllerCohort> {
        if std::mem::replace(&mut self.cohort_attempted, true) {
            self.refuse();
            check.refuse();
            anyhow::bail!("restore_cohort_capture_spent");
        }
        let requested: Result<_> = (|| {
            self.check_active_identity(check, creator, report)?;
            let main = pin_cohort_member(
                self.state
                    .directory
                    .as_ref()
                    .context("restore_directory_missing")?,
                "app.sqlite",
            );
            let post = self.check_active_identity(check, creator, report);
            let main = main?;
            post?;
            self.check_active_identity(check, creator, report)?;
            let wal = pin_cohort_member(
                self.state
                    .directory
                    .as_ref()
                    .context("restore_directory_missing")?,
                "app.sqlite-wal",
            );
            let post = self.check_active_identity(check, creator, report);
            let wal = wal?;
            post?;
            self.check_active_identity(check, creator, report)?;
            let shm = pin_cohort_member(
                self.state
                    .directory
                    .as_ref()
                    .context("restore_directory_missing")?,
                "app.sqlite-shm",
            );
            let post = self.check_active_identity(check, creator, report);
            let shm = shm?;
            post?;
            let members = [main, wal, shm];
            let mut identities = Vec::with_capacity(3);
            for file in &members {
                self.check_active_identity(check, creator, report)?;
                let identity = cohort_identity(file, creator);
                let post = self.check_active_identity(check, creator, report);
                identities.push(identity?);
                post?;
            }
            let identities: [CohortIdentity; 3] = identities
                .try_into()
                .map_err(|_| anyhow::anyhow!("restore_cohort_member_count"))?;
            let mut cohort = RestoreControllerCohort {
                members,
                identities,
                local: std::marker::PhantomData,
            };
            cohort.check(self, creator, report)?;
            Ok(cohort)
        })();
        let post = self.check_active_identity(check, creator, report);
        if requested.is_err() || post.is_err() {
            self.refuse();
            check.refuse();
        }
        let cohort = requested?;
        post?;
        Ok(cohort)
    }

    fn handles_with(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
        peer: &mut Option<&mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>>,
    ) -> Result<()> {
        self.check_native(check, peer)?;
        let requested = (|| {
            self.state.join()?;
            self.root.check(&self.state.root)?;
            self.artifact.check(self.state)?;
            ensure!(
                self.state.complete
                    && self.state.sql.is_none()
                    && self.state.frozen_image.as_ref()
                        == Some(&(self.projection.image.clone(), self.projection.bytes))
                    && self.state.creator.is_some()
                    && self.state.creator_identity.is_some(),
                "native_restore_completed_target_required"
            );
            self.selection
                .require_native_input(&self.state.input, self.intent)
        })();
        let post = self.check_native(check, peer);
        if requested.is_err() || post.is_err() {
            self.state.refused = true;
            check.refuse();
        }
        requested?;
        post
    }

    fn active_local_identity(
        &mut self,
        creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
        report: &crate::security_epoch::kernel::restore::completion::TargetReport,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                self.state.complete && self.state.sql.is_none(),
                "restore_cohort_target_not_complete"
            );
            self.state.join()?;
            self.root.check(&self.state.root)?;
            self.artifact.check(self.state)?;
            require_active_creator_metadata(
                &self
                    .state
                    .creator
                    .as_ref()
                    .context("restore_creator_missing")?
                    .metadata()?,
                creator,
            )?;
            ensure!(
                self.selection
                    .native_report(&self.state.input, self.intent, &self.projection)?
                    == *report,
                "restore_cohort_target_changed"
            );
            Ok(())
        })();
        let post = self.root.check(&self.state.root);
        if requested.is_err() || post.is_err() {
            self.refuse();
        }
        requested?;
        post
    }

    /// Fixed native-local guards bracket EVERY actual descriptor operation.
    /// This returns only the actual reset's report DATA, not a writer owner.
    pub(in crate::security_epoch) fn validate(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
    ) -> Result<crate::security_epoch::kernel::restore::completion::TargetReport> {
        self.validate_with(check, &mut None)
    }

    fn validate_with(
        &mut self,
        check: &mut crate::security_epoch::bootstrap::RestoreTargetCheck<'_, '_, '_, '_, '_>,
        peer: &mut Option<&mut crate::security_epoch::native_enrollment::ReceiverDurability<'_>>,
    ) -> Result<crate::security_epoch::kernel::restore::completion::TargetReport> {
        let requested = (|| {
            self.handles_with(check, peer)?;
            let seek = self
                .state
                .creator
                .as_mut()
                .context("restore_creator_missing")?
                .seek(SeekFrom::Start(0));
            let post = self.handles_with(check, peer);
            seek?;
            post?;
            let mut hash = Hash::new(&SHA256);
            let mut bytes = Zeroizing::new(vec![0; CHUNK]);
            let mut count = 0_u64;
            loop {
                self.handles_with(check, peer)?;
                let limit = usize::try_from(MAX_BYTES.saturating_sub(count).saturating_add(1))?
                    .min(bytes.len());
                let read = self
                    .state
                    .creator
                    .as_mut()
                    .context("restore_creator_missing")?
                    .read(&mut bytes[..limit]);
                let post = self.handles_with(check, peer);
                let read = read?;
                post?;
                count = count
                    .checked_add(read as u64)
                    .context("restore_byte_count")?;
                ensure!(count <= MAX_BYTES, "restore_writer_image_bound");
                if read == 0 {
                    break;
                }
                hash.update(&bytes[..read]);
            }
            ensure!(
                (sum(hash)?, count) == (self.projection.image.clone(), self.projection.bytes),
                "restore_writer_image_changed"
            );
            self.selection
                .native_report(&self.state.input, self.intent, &self.projection)
        })();
        let post = self.handles_with(check, peer);
        if requested.is_err() || post.is_err() {
            self.state.refused = true;
            check.refuse();
        }
        let report = requested?;
        post?;
        Ok(report)
    }
}

// The actual loan retains its own nongeneric lost-loan refusal owner. Dropping
// this direct field permanently refuses that SAME continuation; the parent
// must not duplicate it with an inadmissible generic destructor or substitute
// a local flag for the actual owner. Failed current/SQL checks still explicitly
// refuse above. The private constructor cannot manufacture the loan or pass
// its fixed supplier checks while their genuine implementations are absent.

/// A fixed borrow of one actual Parent, or the existing unqualified portable
/// source. No callback table, runtime owner getter or native trait bridge is
/// accepted. This struct does not construct its NativeParent.
pub(super) struct StagingContext<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection> {
    source: StagingSource<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>,
}

enum StagingSource<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection> {
    Native(&'owner mut NativeParent<'borrow, 'metadata, 'storage, 'role, 'selection>),
    Portable(&'owner mut dyn Checks),
}

impl<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>
    StagingContext<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>
{
    pub(super) fn portable(owner: &'owner mut impl Checks) -> Self {
        Self {
            source: StagingSource::Portable(owner),
        }
    }

    fn native(
        parent: &'owner mut NativeParent<'borrow, 'metadata, 'storage, 'role, 'selection>,
    ) -> Self {
        Self {
            source: StagingSource::Native(parent),
        }
    }

    pub(super) fn state(&mut self) -> &mut State {
        match &mut self.source {
            StagingSource::Native(parent) => parent.state(),
            StagingSource::Portable(owner) => owner.state(),
        }
    }

    pub(super) fn current(&mut self) -> Result<()> {
        match &mut self.source {
            StagingSource::Native(parent) => parent.current(),
            StagingSource::Portable(owner) => owner.current(),
        }
    }

    pub(super) fn local_sql(&mut self) -> Result<()> {
        match &mut self.source {
            StagingSource::Native(parent) => parent.local_sql(),
            StagingSource::Portable(owner) => owner.local_sql(),
        }
    }

    pub(super) fn application(
        &mut self,
        source: &rusqlite::Transaction<'_>,
    ) -> Result<super::application::Selection<'_>> {
        match &mut self.source {
            StagingSource::Native(parent) => parent.application(source),
            StagingSource::Portable(owner) => owner.application(source),
        }
    }

    pub(super) fn refuse(&mut self) {
        match &mut self.source {
            StagingSource::Native(parent) => parent.refuse(),
            StagingSource::Portable(owner) => owner.refuse(),
        }
    }
}

mod sealed {
    pub trait Source {}
    pub trait WriterOwner {}
}

#[derive(Clone)]
struct Target {
    binding: Binding,
    original: ApprovalIdentity,
    settled_root: Digest,
    image: (Digest, u64),
    creator: (u64, u64),
}

// Deliberately uninhabited outside controlled tests. Neither terminal restore
// DATA nor a staged Projection can construct a genuine current-root/P3/writer.
enum AdmissionOrigin {
    #[cfg(test)]
    UnqualifiedModel,
}
struct Admission {
    origin: AdmissionOrigin,
    target: Target,
}

/// Future supplier must prove the current SETTLED/FENCED root, exact epoch and
/// cohort plus real P3/current-writer/peer admission on THIS held creator file.
/// It borrows the actual Session, not only a copied original ID. Bootstrap
/// purposes, a stored receipt, pidfd death or an independent new clock cannot
/// implement this contract. No production/default implementation is provided.
trait Source<F: fence::Source>: sealed::Source {
    fn admit(
        &mut self,
        session: &mut Session<'_, '_, F>,
        target: &Target,
        creator: &File,
    ) -> Result<Admission>;
    fn check(
        &mut self,
        session: &mut Session<'_, '_, F>,
        admission: &Admission,
        creator: &File,
    ) -> Result<()>;
    /// Terminal local disposition only, even after expiry; no new IO/permission.
    fn refuse(&mut self);
}

/// Sole joined staging entry for a future creator handoff. The opaque original
/// is captured from the ACTUAL borrowed Session before reset or first creation;
/// staging without this entry can never acquire a later admission candidate.
fn stage<A: Checks, F: fence::Source>(
    owner: &mut A,
    session: &mut Session<'_, '_, F>,
    binding: &Binding,
) -> Result<Projection> {
    struct Birth<'a, 'original, 'source, A: Checks, F: fence::Source> {
        owner: &'a mut A,
        session: &'a mut Session<'original, 'source, F>,
        done: bool,
    }
    impl<A: Checks, F: fence::Source> Drop for Birth<'_, '_, '_, A, F> {
        fn drop(&mut self) {
            if !self.done {
                self.owner.state().refused = true;
                self.owner.refuse();
                self.session.refuse();
            }
        }
    }
    let mut guard = Birth {
        owner,
        session,
        done: false,
    };
    let original = guard.session.identity();
    guard.session.require_join(binding, &original)?;
    ensure!(
        !guard.owner.state().attempted && guard.owner.state().birth_original.is_none(),
        "restore_creator_original_already_bound"
    );
    require_input(binding, guard.owner.state())?;
    guard.owner.state().birth_original = Some(original.clone());
    let result = execute(guard.owner);
    let post = guard.session.require_join(binding, &original);
    let value = result?;
    post?;
    guard.done = true;
    Ok(value)
}

fn require_input(binding: &Binding, state: &State) -> Result<()> {
    let ns = &state.input.namespace;
    ensure!(
        ns.installation == binding.scope.installation
            && ns.environment == binding.scope.environment
            && ns.app == binding.scope.app
            && ns.binding_generation == binding.binding_generation
            && state.input.operation == binding.operation
            && state.input.source_epoch == binding.source_epoch
            && state.input.target_incarnation == binding.target_incarnation,
        "restore_creator_input_changed"
    );
    Ok(())
}

impl Target {
    fn same(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.original.same(&other.original)
            && self.settled_root == other.settled_root
            && self.image == other.image
            && self.creator == other.creator
    }
    fn join(&self, state: &State) -> Result<()> {
        let ns = &state.input.namespace;
        ensure!(
            state.complete
                && !state.refused
                && state.sql.is_none()
                && ns.installation == self.binding.scope.installation
                && ns.environment == self.binding.scope.environment
                && ns.app == self.binding.scope.app
                && ns.binding_generation == self.binding.binding_generation
                && state.input.operation == self.binding.operation
                && state.input.source_epoch == self.binding.source_epoch
                && state.input.target_incarnation == self.binding.target_incarnation
                && state.frozen_image.as_ref() == Some(&self.image)
                && state.creator_identity == Some(self.creator),
            "restore_writer_staged_target_changed"
        );
        ensure!(
            state
                .birth_original
                .as_ref()
                .is_some_and(|birth| birth.same(&self.original)),
            "restore_writer_creator_original_changed"
        );
        let file = state.creator.as_ref().context("restore_creator_missing")?;
        let held = file.metadata()?;
        ensure!(
            held.is_file()
                && (held.dev(), held.ino()) == self.creator
                && held.len() == self.image.1
                && held.mode() & 0o777 == 0o600,
            "restore_writer_creator_changed"
        );
        Ok(())
    }
}

/// The existing portable owner drives the common transition/readback body.
/// There is no native implementation: an opaque NativeParent must retain its
/// actual loan through the concrete context, without a manual trait bridge,
/// another Session or another approval consumption. The portable adapter cannot
/// construct native admission. No default, DATA factory or public implementation
/// is provided.
trait WriterOwner: sealed::WriterOwner {
    type Admission;

    fn state(&mut self) -> &mut State;
    fn current(&mut self) -> Result<()>;
    fn refuse(&mut self);
    fn require_original(&mut self, target: &Target) -> Result<()>;
    fn admit_writer(&mut self, target: &Target) -> Result<Self::Admission>;
    fn check_writer(&mut self, target: &Target, admission: &Self::Admission) -> Result<()>;
    fn refuse_writer(&mut self);
}

struct PortableWriter<'a, 'original, 'source, A: Checks, F: fence::Source, W: Source<F>> {
    owner: &'a mut A,
    session: &'a mut Session<'original, 'source, F>,
    source: &'a mut W,
}

impl<A: Checks, F: fence::Source, W: Source<F>> sealed::WriterOwner
    for PortableWriter<'_, '_, '_, A, F, W>
{
}

impl<A: Checks, F: fence::Source, W: Source<F>> WriterOwner
    for PortableWriter<'_, '_, '_, A, F, W>
{
    type Admission = Admission;

    fn state(&mut self) -> &mut State {
        self.owner.state()
    }
    fn current(&mut self) -> Result<()> {
        self.owner.current()
    }
    fn refuse(&mut self) {
        self.owner.refuse();
    }
    fn require_original(&mut self, target: &Target) -> Result<()> {
        self.session.require_join(&target.binding, &target.original)
    }
    fn admit_writer(&mut self, target: &Target) -> Result<Admission> {
        let creator = self
            .owner
            .state()
            .creator
            .as_ref()
            .context("restore_creator_missing")?;
        self.source.admit(self.session, target, creator)
    }
    fn check_writer(&mut self, target: &Target, admission: &Admission) -> Result<()> {
        ensure!(
            admission.target.same(target),
            "restore_writer_admission_changed"
        );
        let creator = self
            .owner
            .state()
            .creator
            .as_ref()
            .context("restore_creator_missing")?;
        self.source.check(self.session, admission, creator)
    }
    fn refuse_writer(&mut self) {
        self.session.refuse();
        self.source.refuse();
    }
}

struct Guard<'a, O: WriterOwner> {
    owner: &'a mut O,
    done: bool,
}
impl<O: WriterOwner> Drop for Guard<'_, O> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.state().refused = true;
            self.owner.refuse();
            self.owner.refuse_writer();
        }
    }
}
impl<O: WriterOwner> Guard<'_, O> {
    fn retained(&mut self, target: &Target) -> Result<()> {
        self.owner.require_original(target)?;
        let checked = self.owner.current().and_then(|()| {
            self.owner.state().join()?;
            target.join(self.owner.state())
        });
        // Metadata/owner work above can take time. The actual original must
        // remain current AFTER it, immediately before the next concrete IO.
        let post = self.owner.require_original(target);
        checked?;
        post
    }
    fn current(&mut self, target: &Target, admission: Option<&O::Admission>) -> Result<()> {
        self.retained(target)?;
        if let Some(admission) = admission {
            let checked = self.owner.check_writer(target, admission);
            let post = self.retained(target);
            checked?;
            post?;
        }
        Ok(())
    }
    fn io<T>(
        &mut self,
        target: &Target,
        admission: Option<&O::Admission>,
        operation: impl FnOnce(&mut File) -> Result<T>,
    ) -> Result<T> {
        self.current(target, admission)?;
        let result = operation(
            self.owner
                .state()
                .creator
                .as_mut()
                .context("restore_creator_missing")?,
        );
        // Run mandatory postchecks on primary IO failure, preserving that cause.
        let post = self.current(target, admission);
        let value = result?;
        post?;
        Ok(value)
    }
    fn readback(&mut self, target: &Target, admission: Option<&O::Admission>) -> Result<()> {
        self.io(target, admission, |file| {
            file.seek(SeekFrom::Start(0))?;
            Ok(())
        })?;
        let mut hash = Hash::new(&SHA256);
        let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
        let mut count = 0u64;
        loop {
            let limit = usize::try_from(MAX_BYTES.saturating_sub(count).saturating_add(1))?
                .min(buffer.len());
            let n = self.io(target, admission, |file| {
                Ok(file.read(&mut buffer[..limit])?)
            })?;
            count = count.checked_add(n as u64).context("restore_byte_count")?;
            ensure!(count <= MAX_BYTES, "restore_writer_image_bound");
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        ensure!(
            (sum(hash)?, count) == target.image,
            "restore_writer_image_changed"
        );
        Ok(())
    }
}

fn admit_owned<O: WriterOwner>(
    owner: &mut O,
    binding: Binding,
    settled_root: Digest,
) -> Result<(Target, O::Admission)> {
    let mut guard = Guard { owner, done: false };
    ensure!(
        !guard.owner.state().writer_attempted,
        "restore_writer_attempt_spent"
    );
    // Known-May BEFORE target extraction and any possible admission send.
    // Every extraction/refusal/unwind below remains under this same guard.
    guard.owner.state().writer_attempted = true;
    let target = Target {
        binding,
        original: guard
            .owner
            .state()
            .birth_original
            .clone()
            .context("restore_creator_original_missing")?,
        settled_root,
        image: guard
            .owner
            .state()
            .frozen_image
            .clone()
            .context("restore_reset_image_missing")?,
        creator: guard
            .owner
            .state()
            .creator_identity
            .context("restore_creator_identity_missing")?,
    };
    guard.readback(&target, None)?;
    let admitted = guard.owner.admit_writer(&target);
    let post = guard.retained(&target);
    let admission = admitted?;
    post?;
    // Consumption checks actual bytes, even with unchanged inode and length.
    guard.readback(&target, Some(&admission))?;
    guard.done = true;
    Ok((target, admission))
}

/// A borrow of the actual staging, drain and admission sources, never a new
/// native writer. No FD/Connection getter, publication or serving conversion.
struct Candidate<'a, 'original, 'source, A: Checks, F: fence::Source, W: Source<F>> {
    owner: &'a mut A,
    session: &'a mut Session<'original, 'source, F>,
    source: &'a mut W,
    target: Target,
    admission: Admission,
}
impl<'a, 'original, 'source, A: Checks, F: fence::Source, W: Source<F>>
    Candidate<'a, 'original, 'source, A, F, W>
{
    fn admit(
        owner: &'a mut A,
        session: &'a mut Session<'original, 'source, F>,
        source: &'a mut W,
        binding: Binding,
        settled_root: Digest,
    ) -> Result<Self> {
        let (target, admission) = admit_owned(
            &mut PortableWriter {
                owner: &mut *owner,
                session: &mut *session,
                source: &mut *source,
            },
            binding,
            settled_root,
        )?;
        Ok(Self {
            owner,
            session,
            source,
            target,
            admission,
        })
    }
    fn check(&mut self) -> Result<()> {
        let mut owner = PortableWriter {
            owner: &mut *self.owner,
            session: &mut *self.session,
            source: &mut *self.source,
        };
        let mut guard = Guard {
            owner: &mut owner,
            done: false,
        };
        guard.readback(&self.target, Some(&self.admission))?;
        guard.done = true;
        Ok(())
    }
}
impl<A: Checks, F: fence::Source, W: Source<F>> Drop for Candidate<'_, '_, '_, A, F, W> {
    fn drop(&mut self) {
        self.owner.state().refused = true;
        self.owner.refuse();
        self.session.refuse();
        self.source.refuse();
    }
}

#[cfg(test)]
mod tests;

// This checks physical identity DATA, not admission or authority. The only
// native caller additionally retains its same actual target/current/peer.
fn require_active_creator_metadata(
    metadata: &std::fs::Metadata,
    creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let device = metadata.dev();
    #[cfg(not(target_os = "linux"))]
    let device: rustix::fs::Dev = metadata.dev().try_into()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && rustix::fs::major(device) == creator.device_major
            && rustix::fs::minor(device) == creator.device_minor
            && metadata.ino() == creator.inode
            && metadata.uid() == creator.user
            && metadata.gid() == creator.group,
        "restore_writer_active_creator_identity_changed"
    );
    Ok(())
}

#[cfg(test)]
mod active_creator_tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn real_active_identity_allows_sqlite_bytes_but_refuses_owner_mode_link_and_inode_changes()
    -> Result<()> {
        // Ordinary filesystem fixture only: this constructs no native target,
        // original, role, known writer, active borrow or keeper permission.
        let root = tempfile::tempdir()?;
        let path = root.path().join("main.sqlite");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(b"frozen fixture")?;
        let metadata = file.metadata()?;
        #[cfg(target_os = "linux")]
        let device = metadata.dev();
        #[cfg(not(target_os = "linux"))]
        let device: rustix::fs::Dev = metadata.dev().try_into()?;
        let creator = crate::security_epoch::native_enrollment::RestoreCreatorData {
            device_major: rustix::fs::major(device),
            device_minor: rustix::fs::minor(device),
            inode: metadata.ino(),
            length: metadata.len(),
            user: metadata.uid(),
            group: metadata.gid(),
        };
        require_active_creator_metadata(&metadata, &creator)?;
        file.write_all(b"legitimate mutable SQLite image and length")?;
        assert_ne!(file.metadata()?.len(), creator.length);
        require_active_creator_metadata(&file.metadata()?, &creator)?;
        for field in 0..5 {
            let mut changed = creator.clone();
            match field {
                0 => changed.device_major += 1,
                1 => changed.device_minor += 1,
                2 => changed.inode += 1,
                3 => changed.user += 1,
                _ => changed.group += 1,
            }
            assert!(require_active_creator_metadata(&file.metadata()?, &changed).is_err());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        assert!(require_active_creator_metadata(&file.metadata()?, &creator).is_err());
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let alias = root.path().join("linked-main");
        std::fs::hard_link(&path, &alias)?;
        assert!(require_active_creator_metadata(&file.metadata()?, &creator).is_err());
        std::fs::remove_file(&alias)?;
        require_active_creator_metadata(&file.metadata()?, &creator)?;
        let foreign = std::fs::File::create(root.path().join("replacement.sqlite"))?;
        foreign.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        assert!(require_active_creator_metadata(&foreign.metadata()?, &creator).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod receiver_durability_source_tests {
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
                    .is_none_or(|part| part.ident != "NativeStagedTarget")
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
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if [
                "handles",
                "handles_with",
                "sync_all",
                "validate",
                "validate_with",
                "metadata",
            ]
            .iter()
            .any(|name| call.method == *name)
            {
                self.0.push(call.method.to_string());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    fn fixed(method: &syn::ImplItemFn, expected: &[&str]) -> bool {
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(method);
        calls.0==expected && method.block.stmts.iter().any(|statement|matches!(statement,syn::Stmt::Local(local)
            if named(&local.pat,"checked") && local.init.as_ref().is_some_and(|init|checked(&init.expr,"handles") || checked(&init.expr,"handles_with"))))
    }
    fn requested(method: &syn::ImplItemFn) -> Option<&syn::Block> {
        let local = method
            .block
            .stmts
            .iter()
            .find_map(|statement| match statement {
                syn::Stmt::Local(local) if named(&local.pat, "requested") => Some(local),
                _ => None,
            })?;
        let syn::Expr::Call(call) = &*local.init.as_ref()?.expr else {
            return None;
        };
        let syn::Expr::Paren(paren) = &*call.func else {
            return None;
        };
        let syn::Expr::Closure(closure) = &*paren.expr else {
            return None;
        };
        let syn::Expr::Block(body) = &*closure.body else {
            return None;
        };
        Some(&body.block)
    }
    fn requested_mut(method: &mut syn::ImplItemFn) -> &mut syn::Block {
        let local = method
            .block
            .stmts
            .iter_mut()
            .find_map(|statement| match statement {
                syn::Stmt::Local(local) if named(&local.pat, "requested") => Some(local),
                _ => None,
            })
            .expect("actual requested");
        let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
            panic!("actual call");
        };
        let syn::Expr::Paren(paren) = &mut *call.func else {
            panic!("actual closure");
        };
        let syn::Expr::Closure(closure) = &mut *paren.expr else {
            panic!("actual closure");
        };
        let syn::Expr::Block(body) = &mut *closure.body else {
            panic!("actual body");
        };
        &mut body.block
    }
    fn field(expression: &syn::Expr, name: &str) -> bool {
        match expression {
            syn::Expr::Try(tried) => field(&tried.expr, name),
            syn::Expr::MethodCall(call)
                if (call.method == "as_ref" && call.args.is_empty())
                    || (call.method == "context" && call.args.len() == 1) =>
            {
                field(&call.receiver, name)
            }
            syn::Expr::Field(leaf) => {
                matches!(&leaf.member,syn::Member::Named(member) if member==name)
                    && matches!(&*leaf.base,syn::Expr::Field(state)
                    if matches!(&state.member,syn::Member::Named(member) if member=="state")
                    && matches!(&*state.base,syn::Expr::Path(path) if path.path.is_ident("self")))
            }
            _ => false,
        }
    }
    fn named(pat: &syn::Pat, name: &str) -> bool {
        match pat {
            syn::Pat::Ident(ident) => ident.ident == name,
            syn::Pat::Type(typed) => named(&typed.pat, name),
            _ => false,
        }
    }
    fn propagated(statement: &syn::Stmt, name: &str) -> bool {
        matches!(statement,syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
            if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident(name)))
    }
    fn checked(expression: &syn::Expr, method: &str) -> bool {
        matches!(expression,syn::Expr::MethodCall(call) if call.method==method
            && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("self"))
            && matches!(call.args.first(),Some(syn::Expr::Path(path)) if path.path.is_ident("check"))
            && if method=="handles" {call.args.len()==1} else {call.args.len()==2 && matches!(&call.args[1],syn::Expr::Reference(reference) if reference.mutability.is_some() && matches!(&*reference.expr,syn::Expr::Path(path) if path.path.is_ident("peer")))})
    }
    fn sync_contract(method: &syn::ImplItemFn) -> bool {
        let Some(body) = requested(method) else {
            return false;
        };
        if body.stmts.len() != 17 || method.block.stmts.len() != 6 {
            return false;
        }
        if !matches!(&method.block.stmts[0],syn::Stmt::Local(local) if named(&local.pat,"peer")
            && matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Call(call))
                if matches!(&*call.func,syn::Expr::Path(path) if path.path.is_ident("Some")) && call.args.len()==1
                    && matches!(&call.args[0],syn::Expr::Path(path) if path.path.is_ident("receiver"))))
        {
            return false;
        }
        for (start, owner) in [(0, "creator"), (5, "directory"), (10, "root")] {
            if !matches!(&body.stmts[start],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_)) if checked(&tried.expr,"handles_with"))
                || !matches!(&body.stmts[start+1],syn::Stmt::Local(local) if named(&local.pat,"synced")
                    && matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::MethodCall(call))
                        if call.method=="sync_all" && call.args.is_empty() && field(&call.receiver,owner)))
                || !matches!(&body.stmts[start+2],syn::Stmt::Local(local) if named(&local.pat,"checked")
                    && local.init.as_ref().is_some_and(|init|checked(&init.expr,"handles_with")))
                || !propagated(&body.stmts[start + 3], "synced")
                || !propagated(&body.stmts[start + 4], "checked")
            {
                return false;
            }
        }
        matches!(&body.stmts[15],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_)) if checked(&tried.expr,"validate_with"))
            && matches!(&method.block.stmts[2],syn::Stmt::Local(local) if named(&local.pat,"checked")
                && local.init.as_ref().is_some_and(|init|checked(&init.expr,"handles_with")))
            && propagated(&method.block.stmts[4], "requested")
            && matches!(&method.block.stmts[5],syn::Stmt::Expr(syn::Expr::Path(path),None) if path.path.is_ident("checked"))
    }
    #[test]
    fn actual_durable_target_keeps_three_held_syncs_readback_and_independent_posts() {
        let file = syn::parse_file(include_str!("writer.rs")).unwrap();
        for (name, expected) in [
            (
                "sync_for_receiver",
                vec![
                    "handles_with",
                    "sync_all",
                    "handles_with",
                    "handles_with",
                    "sync_all",
                    "handles_with",
                    "handles_with",
                    "sync_all",
                    "handles_with",
                    "validate_with",
                    "handles_with",
                ],
            ),
            (
                "creator_data",
                vec!["handles", "metadata", "handles", "handles"],
            ),
        ] {
            let actual = method(&file, name);
            assert!(fixed(&actual, &expected), "{name}");
            let mut missing = actual.clone();
            let post=missing.block.stmts.iter_mut().find(|statement|matches!(statement,syn::Stmt::Local(local) if named(&local.pat,"checked"))).unwrap();
            *post = syn::parse_quote!(let checked:Result<()>=Ok(()););
            assert!(!fixed(&missing, &expected));
        }
    }
    fn loan_flow(method: &syn::ImplItemFn, borrowed: bool) -> bool {
        struct Flow {
            borrowed: bool,
            calls: usize,
            valid: bool,
        }
        impl<'ast> Visit<'ast> for Flow {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if ["handles_with", "validate_with", "check_native"]
                    .iter()
                    .any(|name| call.method == *name)
                {
                    self.calls += 1;
                    self.valid &= call.args.len() == 2
                        && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("self"))
                        && if self.borrowed {
                            matches!(&call.args[1],syn::Expr::Reference(reference) if reference.mutability.is_some() && matches!(&*reference.expr,syn::Expr::Path(path) if path.path.is_ident("peer")))
                        } else {
                            matches!(&call.args[1],syn::Expr::Path(path) if path.path.is_ident("peer"))
                        };
                }
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut flow = Flow {
            borrowed,
            calls: 0,
            valid: true,
        };
        flow.visit_impl_item_fn(method);
        flow.valid && flow.calls >= 2
    }
    #[test]
    fn same_actual_receiver_loan_reaches_all_sync_and_shared_readback_guards() {
        let file = syn::parse_file(include_str!("writer.rs")).unwrap();
        for (name, borrowed) in [
            ("sync_for_receiver", true),
            ("validate_with", false),
            ("handles_with", false),
        ] {
            let actual = method(&file, name);
            assert!(loan_flow(&actual, borrowed), "{name}");
            let mut detached = actual.clone();
            // The same actual body is retained and an extra native boundary
            // deliberately drops the loan. Both representations are refused.
            detached
                .block
                .stmts
                .insert(0, syn::parse_quote!(self.handles_with(check,&mut None)?;));
            assert!(!loan_flow(&detached, borrowed), "detached boundary {name}");
        }
    }
    #[test]
    fn actual_sync_owners_and_primary_post_results_cannot_be_substituted_or_discarded() {
        let file = syn::parse_file(include_str!("writer.rs")).unwrap();
        let actual = method(&file, "sync_for_receiver");
        assert!(sync_contract(&actual));
        let mut wrong = actual.clone();
        let first = requested(&actual).unwrap().stmts[1].clone();
        requested_mut(&mut wrong).stmts[6] = first;
        assert!(
            !sync_contract(&wrong),
            "directory replaced by second creator sync"
        );
        let mut discarded = actual.clone();
        requested_mut(&mut discarded).stmts[6] = syn::parse_quote!(let synced:std::io::Result<()>={let _=self.state.directory.as_ref().context("restore_directory_missing")?.sync_all();Ok(())};);
        assert!(!sync_contract(&discarded), "sync failure hidden by Ok");
        for (index, replacement) in [
            (8, syn::parse_quote!(let _=synced;)),
            (9, syn::parse_quote!(let _=checked;)),
            (
                15,
                syn::parse_quote!(let _=self.validate_with(check,&mut peer);),
            ),
        ] {
            let mut changed = actual.clone();
            requested_mut(&mut changed).stmts[index] = replacement;
            assert!(!sync_contract(&changed), "discarded result {index}");
        }
        let mut missing = actual.clone();
        missing.block.stmts[5] = syn::Stmt::Expr(syn::parse_quote!(Ok(())), None);
        assert!(!sync_contract(&missing), "final post discarded");
        let mut detached = actual.clone();
        detached.block.stmts[0] = syn::parse_quote!(let mut peer=None;);
        assert!(!sync_contract(&detached), "actual receiver loan omitted");
    }
}

#[cfg(test)]
mod active_creator_source_tests {
    use quote::ToTokens as _;
    fn body(source: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let mut methods=file.items.iter().filter_map(|item| {
            let syn::Item::Impl(owner)=item else{return None;};
            if owner.trait_.is_some() || !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.leading_colon.is_none() && path.path.segments.len()==1 && path.path.segments[0].ident=="NativeStagedTarget"){return None;}
            owner.items.iter().find_map(|item|match item {
                syn::ImplItem::Fn(method) if method.sig.ident=="check_active_identity"=>Some(method.block.to_token_stream().to_string().replace(" , )", " )")),_=>None,
            })
        });
        let result = methods.next().expect("actual target method");
        assert!(methods.next().is_none());
        result
    }
    fn guarded(body: &str) -> bool {
        let expected = [
            "let requested =",
            "self . handles (check) ?",
            "let metadata = self . state . creator . as_ref () . context (\"restore_creator_missing\") ? . metadata ()",
            "let checked = self . handles (check)",
            "let metadata = metadata ?",
            "checked ?",
            "require_active_creator_metadata (& metadata , creator) ?",
            "self . selection . native_report (& self . state . input , self . intent , & self . projection) ? == * report",
            "let checked = self . handles (check)",
            "if requested . is_err () || checked . is_err () { self . refuse () ; check . refuse () ; }",
            "requested ? ; checked",
        ];
        let mut cursor = 0;
        for expected in expected {
            let Some(offset) = body[cursor..].find(expected) else {
                return false;
            };
            cursor += offset + expected.len();
        }
        body.matches("self . handles (check)").count() == 3
            && body.matches(". metadata ()").count() == 1
            && body.matches("require_active_creator_metadata").count() == 1
            && !body.contains("self . validate")
            && !body.contains("seek")
            && !body.contains("read (")
    }
    #[test]
    fn actual_active_target_checks_metadata_against_capture_and_keeps_independent_posts_and_primary()
     {
        let actual = body(include_str!("writer.rs"));
        assert!(guarded(&actual));
        for (from, to) in [
            (
                "let metadata = self . state . creator . as_ref () . context (\"restore_creator_missing\") ? . metadata ()",
                "let metadata = other . metadata ()",
            ),
            (
                "require_active_creator_metadata (& metadata , creator) ?",
                "Ok::<(), anyhow::Error> (()) ?",
            ),
            (
                "require_active_creator_metadata (& metadata , creator) ?",
                "require_active_creator_metadata (& metadata , other_creator) ?",
            ),
            (
                "let checked = self . handles (check)",
                "let checked : Result < () > = Ok (())",
            ),
            ("checked ?", "let _ = checked"),
            ("requested ? ; checked", "checked ? ; requested"),
            (
                "if requested . is_err () || checked . is_err ()",
                "if requested . is_err () && checked . is_err ()",
            ),
        ] {
            assert_eq!(
                actual.matches(from).count(),
                if from == "let checked = self . handles (check)" {
                    2
                } else {
                    1
                }
            );
            let mutated = actual.replacen(from, to, 1);
            assert!(!guarded(&mutated), "actual method cut: {from}");
        }
        assert!(!guarded("{ Ok(()) }"));
        // Deleting only the independent outer post also fails. This does not
        // rely on a call elsewhere or on the pure metadata fixture above.
        let cut = actual
            .rfind("let checked = self . handles (check)")
            .unwrap();
        let changed = format!(
            "{}{}",
            &actual[..cut],
            actual[cut..].replacen(
                "let checked = self . handles (check)",
                "let checked = Ok::<(),anyhow::Error>(())",
                1
            )
        );
        assert!(!guarded(&changed));
    }
}

/// Actual Controller-side O_PATH owners of the SAME App SQLite cohort. No
/// path, inode tuple, ACK or descriptor number can construct this owner.
/// O_PATH avoids releasing any process-owned POSIX SQLite locks on close.
pub(in crate::security_epoch) struct RestoreControllerCohort {
    members: [File; 3],
    identities: [CohortIdentity; 3],
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[derive(PartialEq, Eq)]
struct CohortIdentity {
    device: u64,
    inode: u64,
    mount: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(target_os = "linux")]
fn pin_cohort_member(directory: &File, name: &str) -> Result<File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    ensure!(
        matches!(name, "app.sqlite" | "app.sqlite-wal" | "app.sqlite-shm"),
        "restore_cohort_name"
    );
    Ok(File::from(rustix::fs::openat2(
        directory,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?))
}
#[cfg(not(target_os = "linux"))]
fn pin_cohort_member(_: &File, _: &str) -> Result<File> {
    anyhow::bail!("restore_cohort_native_required")
}

#[cfg(target_os = "linux")]
fn cohort_identity(
    file: &File,
    creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
) -> Result<CohortIdentity> {
    use rustix::fs::{AtFlags, StatxFlags};
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600
            && metadata.uid() == creator.user
            && metadata.gid() == creator.group,
        "restore_cohort_file_profile"
    );
    let flags = StatxFlags::BASIC_STATS | StatxFlags::MNT_ID;
    let observed = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, flags)?;
    ensure!(
        observed.stx_mask & flags.bits() == flags.bits() && observed.stx_mnt_id != 0,
        "restore_cohort_mount_missing"
    );
    ensure!(
        rustix::fs::major(metadata.dev()) == creator.device_major
            && rustix::fs::minor(metadata.dev()) == creator.device_minor,
        "restore_cohort_device_changed"
    );
    Ok(CohortIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount: observed.stx_mnt_id,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
    })
}
#[cfg(not(target_os = "linux"))]
fn cohort_identity(
    _: &File,
    _: &crate::security_epoch::native_enrollment::RestoreCreatorData,
) -> Result<CohortIdentity> {
    anyhow::bail!("restore_cohort_native_required")
}

impl RestoreControllerCohort {
    /// Only actual held-member comparison DATA is returned to the genuine
    /// ReleaseLoan. This neither authenticates an ACK nor constructs Current.
    pub(in crate::security_epoch) fn check(
        &mut self,
        target: &mut NativeStagedTarget<'_, '_>,
        creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
        report: &crate::security_epoch::kernel::restore::completion::TargetReport,
    ) -> Result<crate::security_epoch::native_enrollment::SqliteCohort> {
        let requested: Result<_> = (|| {
            target.active_local_identity(creator, report)?;
            for (index, name) in ["app.sqlite", "app.sqlite-wal", "app.sqlite-shm"]
                .into_iter()
                .enumerate()
            {
                target.active_local_identity(creator, report)?;
                let held = cohort_identity(&self.members[index], creator);
                let post = target.active_local_identity(creator, report);
                ensure!(
                    held? == self.identities[index],
                    "restore_cohort_held_member_changed"
                );
                post?;
                target.active_local_identity(creator, report)?;
                let named = pin_cohort_member(
                    target
                        .state
                        .directory
                        .as_ref()
                        .context("restore_directory_missing")?,
                    name,
                );
                let post = target.active_local_identity(creator, report);
                let named = named?;
                post?;
                target.active_local_identity(creator, report)?;
                let observed = cohort_identity(&named, creator);
                let post = target.active_local_identity(creator, report);
                ensure!(
                    observed? == self.identities[index],
                    "restore_cohort_named_member_changed"
                );
                post?;
            }
            ensure!(
                self.identities
                    .iter()
                    .all(|identity| identity.mount == self.identities[0].mount),
                "restore_cohort_cross_mount"
            );
            let metadata = target
                .state
                .creator
                .as_ref()
                .context("restore_creator_missing")?
                .metadata()?;
            ensure!(
                (metadata.dev(), metadata.ino())
                    == (self.identities[0].device, self.identities[0].inode),
                "restore_cohort_main_substituted"
            );
            crate::security_epoch::native_enrollment::SqliteCohort::from_identities(
                (self.identities[0].device, self.identities[0].inode),
                (self.identities[1].device, self.identities[1].inode),
                (self.identities[2].device, self.identities[2].inode),
            )
        })();
        let post = target.active_local_identity(creator, report);
        if requested.is_err() || post.is_err() {
            target.refuse();
        }
        let data = requested?;
        post?;
        Ok(data)
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod cohort_lock_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    const FIXTURE: &str = "DAY2_TEST_RESTORE_COHORT_PIN_LOCK_FIXTURE";
    const EXPECTATION: &str = "DAY2_TEST_RESTORE_COHORT_PIN_LOCK_EXPECTATION";
    const CASE: &str = "security_epoch::restore_staging::writer::cohort_lock_tests::actual_path_pin_close_keeps_the_keeper_kernel_write_lock_against_another_process";

    #[test]
    fn actual_path_pin_close_keeps_the_keeper_kernel_write_lock_against_another_process()
    -> Result<()> {
        // Both branches use ordinary, disposable SQLite fixtures, never native
        // originals or production admission. The normal gate has no marker;
        // the parent necessarily runs the separate-process contender branch.
        if let Some(path) = std::env::var_os(FIXTURE) {
            let expectation = std::env::var(EXPECTATION)?;
            ensure!(
                matches!(expectation.as_str(), "held" | "released"),
                "cohort_lock_fixture_expectation"
            );
            let db = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            db.busy_timeout(std::time::Duration::ZERO)?;
            let result = db.execute_batch("BEGIN IMMEDIATE");
            if expectation == "held" {
                assert!(
                    matches!(result,Err(rusqlite::Error::SqliteFailure(ref failure,_))
                    if matches!(failure.code,rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked))
                );
            } else {
                result?;
                db.execute_batch("ROLLBACK")?;
            }
            return Ok(());
        }
        let root = tempfile::tempdir()?;
        let path = root.path().join("app.sqlite");
        let keeper = rusqlite::Connection::open(&path)?;
        keeper.execute_batch(
            "PRAGMA journal_mode=DELETE; CREATE TABLE value(n INTEGER); BEGIN IMMEDIATE;",
        )?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let contender = |expectation: &str| -> Result<()> {
            let result = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", CASE, "--test-threads=1"])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env(FIXTURE, &path)
                .env(EXPECTATION, expectation)
                .output()?;
            let stdout = String::from_utf8(result.stdout)?;
            ensure!(
                result.status.success()
                    && stdout.contains(&format!("test {CASE} ... ok"))
                    && stdout.contains("1 passed; 0 failed; 0 ignored"),
                "cohort_kernel_lock_contender_failed"
            );
            Ok(())
        };
        contender("held")?;
        let directory = File::open(root.path())?;
        // This is the EXACT production primitive. Changing PATH to ordinary
        // RDONLY/RDWR would close a new MAIN alias and release the parent's
        // process-owned fcntl locks; the separate contender detects that.
        let pin = pin_cohort_member(&directory, "app.sqlite")?;
        drop(pin);
        contender("held")?;
        // Unsafe contrast is confined to this disposable rollback-journal
        // fixture. It demonstrates the child really observes MAIN kernel
        // locks: an ordinary alias close loses them while keeper is still in
        // its transaction. WAL/SHM write locks must not mask this control.
        let unsafe_alias = File::open(&path)?;
        drop(unsafe_alias);
        contender("released")?;
        keeper.execute_batch("ROLLBACK")?;
        drop(keeper);
        contender("released")?;
        Ok(())
    }
}

#[cfg(test)]
mod cohort_source_tests {
    use quote::ToTokens as _;
    fn block(source: &str, owner: &str, name: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let mut bodies=file.items.iter().filter_map(|item| {
            let syn::Item::Impl(item)=item else{return None;};
            if item.trait_.is_some() || !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.len()==1 && path.path.segments[0].ident==owner){return None;}
            item.items.iter().find_map(|item|match item{
                syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(method.block.to_token_stream().to_string().replace(" , )"," )")),_=>None,
            })
        });
        let selected = bodies.next().unwrap();
        assert!(bodies.next().is_none());
        selected
    }
    fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut cursor = 0;
        for part in parts {
            let Some(offset) = body[cursor..].find(part) else {
                return false;
            };
            cursor += offset + part.len();
        }
        true
    }
    fn capture(body: &str) -> bool {
        ordered(
            body,
            &[
                "std :: mem :: replace (& mut self . cohort_attempted , true)",
                "let requested",
                "self . check_active_identity (check , creator , report) ?",
                "pin_cohort_member",
                "\"app.sqlite\"",
                "let post = self . check_active_identity (check , creator , report)",
                "let main = main ? ; post ?",
                "pin_cohort_member",
                "\"app.sqlite-wal\"",
                "let wal = wal ? ; post ?",
                "pin_cohort_member",
                "\"app.sqlite-shm\"",
                "let shm = shm ? ; post ?",
                "let identity = cohort_identity (file , creator)",
                "identities . push (identity ?) ; post ?",
                "RestoreControllerCohort",
                "cohort . check (self , creator , report) ?",
                "let post = self . check_active_identity (check , creator , report)",
                "requested . is_err () || post . is_err ()",
                "let cohort = requested ? ; post ? ; Ok (cohort)",
            ],
        ) && body.matches("pin_cohort_member").count() == 3
            && !body.contains("Connection")
            && !body.contains("try_clone")
    }
    fn retained(body: &str) -> bool {
        ordered(
            body,
            &[
                "target . active_local_identity (creator , report) ?",
                "\"app.sqlite\"",
                "\"app.sqlite-wal\"",
                "\"app.sqlite-shm\"",
                "cohort_identity (& self . members [index] , creator)",
                "let post = target . active_local_identity (creator , report)",
                "held ? == self . identities [index]",
                "post ?",
                "let named = pin_cohort_member",
                "let named = named ? ; post ?",
                "let observed = cohort_identity (& named , creator)",
                "observed ? == self . identities [index]",
                "post ?",
                "identity . mount == self . identities [0] . mount",
                "self . identities [0] . device",
                "self . identities [0] . inode",
                "SqliteCohort :: from_identities",
                "let post = target . active_local_identity (creator , report)",
                "requested . is_err () || post . is_err ()",
                "let data = requested ? ; post ? ; Ok (data)",
            ],
        ) && !body.contains("self . identities =")
            && !body.contains("Connection")
    }
    #[test]
    fn actual_controller_cohort_spends_once_pins_only_three_members_and_rechecks_held_and_named_identity()
     {
        let source = include_str!("writer.rs");
        let actual = block(source, "NativeStagedTarget", "pin_active_cohort");
        assert!(capture(&actual));
        for (from, to) in [
            (
                "std :: mem :: replace (& mut self . cohort_attempted , true)",
                "false",
            ),
            ("\"app.sqlite-wal\"", "\"other.sqlite-wal\""),
            (
                "let post = self . check_active_identity (check , creator , report)",
                "let post = Ok::<(),anyhow::Error>(())",
            ),
            (
                "identities . push (identity ?) ; post ?",
                "identities . push (identity ?) ; let _=post",
            ),
            (
                "cohort . check (self , creator , report) ?",
                "Ok::<(),anyhow::Error>(()) ?",
            ),
        ] {
            assert!(actual.contains(from));
            assert!(
                !capture(&actual.replacen(from, to, 1)),
                "capture cut {from}"
            );
        }
        let actual = block(source, "RestoreControllerCohort", "check");
        assert!(retained(&actual));
        for (from, to) in [
            ("held ? == self . identities [index]", "true"),
            ("observed ? == self . identities [index]", "true"),
            (
                "let post = target . active_local_identity (creator , report)",
                "let post = Ok::<(),anyhow::Error>(())",
            ),
            ("identity . mount == self . identities [0] . mount", "true"),
            (
                "let data = requested ? ; post ? ; Ok (data)",
                "let data = requested ? ; let _=post ; Ok (data)",
            ),
        ] {
            assert!(actual.contains(from));
            assert!(
                !retained(&actual.replacen(from, to, 1)),
                "retained cut {from}"
            );
        }
    }

    fn linux_function(source: &str, name: &str) -> String {
        let file = syn::parse_file(source).unwrap();
        let mut selected = file.items.iter().filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == name
                    && function.attrs.iter().any(|attribute| {
                        attribute.meta.to_token_stream().to_string()
                            == "cfg (target_os = \"linux\")"
                    }) =>
            {
                Some(
                    function
                        .block
                        .to_token_stream()
                        .to_string()
                        .replace(" , )", " )"),
                )
            }
            _ => None,
        });
        let result = selected.next().expect("actual Linux primitive");
        assert!(selected.next().is_none());
        result
    }
    fn path_only(body: &str) -> bool {
        body.contains("rustix :: fs :: openat2 (directory , name")
            && body.contains("OFlags :: PATH | OFlags :: CLOEXEC | OFlags :: NOFOLLOW")
            && body.contains("ResolveFlags :: BENEATH | ResolveFlags :: NO_SYMLINKS | ResolveFlags :: NO_MAGICLINKS | ResolveFlags :: NO_XDEV")
            && body.contains("\"app.sqlite\" | \"app.sqlite-wal\" | \"app.sqlite-shm\"")
            && !body.contains("RDONLY") && !body.contains("RDWR") && !body.contains("CREATE")
    }
    #[test]
    fn actual_cohort_pin_is_closed_path_only_and_metadata_keeps_owner_links_and_mount() {
        let source = include_str!("writer.rs");
        let pin = linux_function(source, "pin_cohort_member");
        assert!(path_only(&pin));
        for (from, to) in [
            ("OFlags :: PATH", "OFlags :: RDONLY"),
            ("ResolveFlags :: NO_XDEV", "ResolveFlags :: empty ()"),
            ("ResolveFlags :: NO_SYMLINKS", "ResolveFlags :: empty ()"),
        ] {
            assert!(pin.contains(from));
            assert!(!path_only(&pin.replacen(from, to, 1)));
        }
        let identity = linux_function(source, "cohort_identity");
        for required in [
            "metadata . is_file ()",
            "metadata . nlink () == 1",
            "metadata . mode () & 0o7777 == 0o600",
            "metadata . uid () == creator . user",
            "metadata . gid () == creator . group",
            "StatxFlags :: BASIC_STATS | StatxFlags :: MNT_ID",
            "AtFlags :: EMPTY_PATH",
            "observed . stx_mnt_id != 0",
            "rustix :: fs :: major (metadata . dev ()) == creator . device_major",
            "rustix :: fs :: minor (metadata . dev ()) == creator . device_minor",
        ] {
            assert!(
                identity.contains(required),
                "actual identity component {required}"
            );
        }
    }
}
