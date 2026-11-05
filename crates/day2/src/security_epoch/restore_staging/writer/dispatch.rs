//! Local disposition only, never approval, fencing, P3 or send authority. The
//! genuine native parent owns exactly one of these alongside its real resources.
//! An unknown outcome cannot be repaired by historical provider reconciliation.
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

enum State {
    Fresh,
    May { target: Digest },
    Known { target: Digest },
    Refused,
}

pub(in crate::security_epoch) struct Disposition {
    state: Rc<Shared>,
}

struct Shared {
    value: RefCell<State>,
    refused: Cell<bool>,
}

pub(in crate::security_epoch) struct Flight {
    state: Rc<Shared>,
    target: Digest,
    done: bool,
}

impl Disposition {
    /// Availability DATA only. This does not create the enclosing native parent
    /// or permission to execute any action; no production source accepts it as
    /// a substitute for actual approval, file, stage or provider owners.
    pub(in crate::security_epoch) fn fresh() -> Self {
        Self {
            state: Rc::new(Shared {
                value: RefCell::new(State::Fresh),
                refused: Cell::new(false),
            }),
        }
    }

    pub(in crate::security_epoch) fn arm(&mut self, target: &Digest) -> Result<Flight> {
        let result = (|| {
            ensure!(
                !self.state.refused.get(),
                "restore_writer_disposition_refused"
            );
            let mut state = self.state.value.try_borrow_mut()?;
            ensure!(
                matches!(*state, State::Fresh),
                "restore_writer_attempt_spent"
            );
            *state = State::May {
                target: target.clone(),
            };
            Ok(Flight {
                state: Rc::clone(&self.state),
                target: target.clone(),
                done: false,
            })
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn require_known(&mut self, target: &Digest) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.state.refused.get(),
                "restore_writer_disposition_refused"
            );
            let state = self.state.value.try_borrow()?;
            ensure!(
                matches!(&*state, State::Known { target: held } if held == target),
                "restore_writer_not_known"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state.refused.set(true);
        if let Ok(mut state) = self.state.value.try_borrow_mut() {
            *state = State::Refused;
        }
    }
}

impl Flight {
    /// Availability continuity only; the actual writer source must separately
    /// retain and check all native/approval owners at every effect boundary.
    pub(in crate::security_epoch) fn check(&self, expected: &Digest) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.state.refused.get() && &self.target == expected,
                "restore_writer_flight_changed"
            );
            let state = self.state.value.try_borrow()?;
            ensure!(
                matches!(&*state, State::May { target } if target == expected),
                "restore_writer_flight_not_pending"
            );
            Ok(())
        })();
        if result.is_err() {
            self.state.refused.set(true);
        }
        result
    }

    /// Called only after the real action and ALL same-original postchecks. This
    /// marks local disposition; it still constructs no writer/serving owner.
    pub(in crate::security_epoch) fn known(mut self) -> Result<()> {
        {
            ensure!(
                !self.state.refused.get(),
                "restore_writer_disposition_refused"
            );
            let mut state = self.state.value.try_borrow_mut()?;
            ensure!(
                matches!(&*state, State::May { target } if target == &self.target),
                "restore_writer_flight_changed"
            );
            *state = State::Known {
                target: self.target.clone(),
            };
        }
        self.done = true;
        Ok(())
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        if !self.done {
            self.state.refused.set(true);
            if let Ok(mut state) = self.state.value.try_borrow_mut() {
                *state = State::Refused;
            }
        }
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> { fn check() {} }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, Clone);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, Copy);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, Default);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, Send);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, Sync);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, serde::Serialize);
    assert_not_impl!(crate::security_epoch::restore_staging::Disposition, serde::Deserialize<'static>);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, Clone);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, Copy);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, Default);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, Send);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, Sync);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, serde::Serialize);
    assert_not_impl!(crate::security_epoch::restore_staging::Flight, serde::Deserialize<'static>);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_unknown_flight_is_permanently_refused_even_during_an_internal_borrow() -> Result<()>
    {
        let target = Digest::new(b"one-exact-writer-target");
        let mut disposition = Disposition::fresh();
        let flight = disposition.arm(&target)?;
        let state = Rc::clone(&disposition.state);
        let held = state.value.borrow();
        drop(flight);
        assert!(state.refused.get());
        drop(held);
        assert!(disposition.require_known(&target).is_err());
        assert!(disposition.arm(&target).is_err());
        Ok(())
    }

    #[test]
    fn second_attempt_or_changed_target_cannot_settle_or_repair_the_same_original() -> Result<()> {
        let target = Digest::new(b"one-exact-writer-target");
        let mut disposition = Disposition::fresh();
        let flight = disposition.arm(&target)?;
        assert!(disposition.arm(&target).is_err());
        assert!(flight.known().is_err());
        assert!(disposition.require_known(&target).is_err());
        let mut disposition = Disposition::fresh();
        disposition.arm(&target)?.known()?;
        assert!(disposition.require_known(&target).is_ok());
        assert!(
            disposition
                .require_known(&Digest::new(b"other-target"))
                .is_err()
        );
        assert!(disposition.require_known(&target).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod flight_tests {
    use super::*;

    #[test]
    fn pending_check_binds_target_and_cannot_repair_unknown_or_changed_flight() -> Result<()> {
        let target = Digest::new(b"one-held-target");
        let mut disposition = Disposition::fresh();
        let flight = disposition.arm(&target)?;
        flight.check(&target)?;
        assert!(flight.check(&Digest::new(b"other-target")).is_err());
        assert!(flight.check(&target).is_err());
        assert!(flight.known().is_err());
        assert!(disposition.arm(&target).is_err());
        Ok(())
    }
}
