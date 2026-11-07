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
pub(in crate::security_epoch) use dispatch::{Disposition, Flight};

/// Retains the actual exclusive fenced loan through the same staging state.
/// There is deliberately no constructor: exact approval/target binding and the
/// fixed native writer transitions must be supplied before creation can start.
/// A DATA plan, staged image or freshly captured role cannot construct this.
struct NativeParent<'borrow, 'metadata, 'storage, 'role, 'selection> {
    loan: crate::security_epoch::bootstrap::RestoreWriteLoan<'borrow, 'metadata, 'storage, 'role>,
    state: State,
    selection: super::application::Selection<'selection>,
}

impl NativeParent<'_, '_, '_, '_, '_> {
    fn execute_staging(&mut self) -> Result<Projection> {
        super::execute_context(&mut StagingContext::native(self))
    }

    fn state(&mut self) -> &mut State {
        &mut self.state
    }

    fn current(&mut self) -> Result<()> {
        let checked = self.loan.check_current().map(|_| ());
        if checked.is_err() {
            self.refuse();
        }
        checked
    }

    fn local_sql(&mut self) -> Result<()> {
        // Only the SQL-safe retained check. The existing builder owns the
        // transaction; no coherent provider read runs while it is open.
        let checked = self.loan.check_local();
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

// The actual loan retains its own nongeneric lost-loan refusal owner. Dropping
// this direct field permanently refuses that SAME continuation; the parent
// must not duplicate it with an inadmissible generic destructor or substitute
// a local flag for the actual owner. Failed current/SQL checks still explicitly
// refuse above. No accepting constructor exists before that supplier is joined.

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
