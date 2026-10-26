/// Only the private accounting boundary constructs this consuming control.
/// It selects fixed budget savepoint commands on an existing connection; it
/// supplies no native owner, file, transaction, clock or callback exemption.
pub(crate) struct AtomicControl {
    owner_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

pub(super) fn atomic<T>(
    connection: &rusqlite::Connection,
    body: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    crate::store::budget_atomic(
        connection,
        AtomicControl {
            owner_thread: std::marker::PhantomData,
        },
        body,
    )
}
