//! Closed new-writer admission foundation. No production approval, settled-root
//! supplier, P3/writer/peer source or conversion to a serving owner exists here.
//! A future supplier must retain genuine SAME-original rights, not stamp a
//! cloned continuity ID onto separately acquired native authority.
use super::*;
use crate::security_epoch::restore_fencing::{self as fence, ApprovalIdentity, Binding, Session};
use std::fs::File;

mod sealed {
    pub trait Source {}
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
        session: &mut Session<'_, F>,
        target: &Target,
        creator: &File,
    ) -> Result<Admission>;
    fn check(
        &mut self,
        session: &mut Session<'_, F>,
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
    session: &mut Session<'_, F>,
    binding: &Binding,
) -> Result<Projection> {
    struct Birth<'a, 'original, A: Checks, F: fence::Source> {
        owner: &'a mut A,
        session: &'a mut Session<'original, F>,
        done: bool,
    }
    impl<A: Checks, F: fence::Source> Drop for Birth<'_, '_, A, F> {
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

struct Guard<'a, 'original, A: Checks, F: fence::Source, W: Source<F>> {
    owner: &'a mut A,
    session: &'a mut Session<'original, F>,
    source: &'a mut W,
    done: bool,
}
impl<A: Checks, F: fence::Source, W: Source<F>> Drop for Guard<'_, '_, A, F, W> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.state().refused = true;
            self.owner.refuse();
            self.session.refuse();
            self.source.refuse();
        }
    }
}
impl<A: Checks, F: fence::Source, W: Source<F>> Guard<'_, '_, A, F, W> {
    fn retained(&mut self, target: &Target) -> Result<()> {
        self.session
            .require_join(&target.binding, &target.original)?;
        let checked = self.owner.current().and_then(|()| {
            self.owner.state().join()?;
            target.join(self.owner.state())
        });
        // Metadata/owner work above can take time. The actual original must
        // remain current AFTER it, immediately before the next concrete IO.
        let post = self.session.require_join(&target.binding, &target.original);
        checked?;
        post
    }
    fn current(&mut self, target: &Target, admission: Option<&Admission>) -> Result<()> {
        self.retained(target)?;
        if let Some(admission) = admission {
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
            let checked = self.source.check(self.session, admission, creator);
            let post = self.retained(target);
            checked?;
            post?;
        }
        Ok(())
    }
    fn io<T>(
        &mut self,
        target: &Target,
        admission: Option<&Admission>,
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
    fn readback(&mut self, target: &Target, admission: Option<&Admission>) -> Result<()> {
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

/// A borrow of the actual staging, drain and admission sources, never a new
/// native writer. No FD/Connection getter, publication or serving conversion.
struct Candidate<'a, 'original, A: Checks, F: fence::Source, W: Source<F>> {
    owner: &'a mut A,
    session: &'a mut Session<'original, F>,
    source: &'a mut W,
    target: Target,
    admission: Admission,
}
impl<'a, 'original, A: Checks, F: fence::Source, W: Source<F>> Candidate<'a, 'original, A, F, W> {
    fn admit(
        owner: &'a mut A,
        session: &'a mut Session<'original, F>,
        source: &'a mut W,
        binding: Binding,
        settled_root: Digest,
    ) -> Result<Self> {
        let mut guard = Guard {
            owner: &mut *owner,
            session: &mut *session,
            source: &mut *source,
            done: false,
        };
        ensure!(
            !guard.owner.state().writer_attempted,
            "restore_writer_attempt_spent"
        );
        // Known-May BEFORE any possible P3/writer admission send. Unknown
        // completion cannot retry or adopt the same path under another original.
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
        let creator = guard
            .owner
            .state()
            .creator
            .as_ref()
            .context("restore_creator_missing")?;
        let admitted = guard.source.admit(guard.session, &target, creator);
        let post = guard.retained(&target);
        let admission = admitted?;
        post?;
        // Consumption rechecks actual creator bytes even when dev/inode and
        // length have not changed. A frozen digest is not a current file proof.
        guard.readback(&target, Some(&admission))?;
        guard.done = true;
        drop(guard);
        Ok(Self {
            owner,
            session,
            source,
            target,
            admission,
        })
    }
    fn check(&mut self) -> Result<()> {
        let mut guard = Guard {
            owner: &mut *self.owner,
            session: &mut *self.session,
            source: &mut *self.source,
            done: false,
        };
        guard.readback(&self.target, Some(&self.admission))?;
        guard.done = true;
        Ok(())
    }
}
impl<A: Checks, F: fence::Source, W: Source<F>> Drop for Candidate<'_, '_, A, F, W> {
    fn drop(&mut self) {
        self.owner.state().refused = true;
        self.owner.refuse();
        self.session.refuse();
        self.source.refuse();
    }
}

#[cfg(test)]
mod tests;
