//! Test-only access to the real pessimistic continuation decision. This owns
//! no file, physical provider, enrollment, holder or permission.
use super::FilePhaseDisposition;
use anyhow::Result;

pub(in crate::security_epoch) fn phase<T>(
    continuation: &mut bool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mut phase = FilePhaseDisposition::begin(continuation)?;
    phase.check()?;
    match operation() {
        Ok(value) => {
            phase.complete()?;
            Ok(value)
        }
        Err(error) => {
            phase.refuse();
            // Deliberately drop without completion, as on an unknown native
            // result. Neither restoring observations nor DATA reopen rearms it.
            Err(error)
        }
    }
}
