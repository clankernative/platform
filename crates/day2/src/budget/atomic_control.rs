/// Only the private accounting boundary constructs this consuming control.
/// It selects fixed budget savepoint commands on an existing connection; it
/// supplies no native owner, file, transaction, clock or callback exemption.
pub(crate) struct AtomicControl {
    owner_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl AtomicControl {
    pub(super) fn new() -> Self {
        Self {
            owner_thread: std::marker::PhantomData,
        }
    }
}
