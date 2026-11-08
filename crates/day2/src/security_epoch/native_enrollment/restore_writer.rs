//! Closed dispatch DATA for the fixed native restore exchange. Actual peers
//! and their constructors live with the retained enrollment owner, never here.

/// One native syscall's progress DATA, never P3, a completed exchange or a
/// permission to skip the complete parent checks around the next operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum ReceiverProgress {
    Advanced,
    WouldBlock,
    Interrupted,
    Delivered,
}

/// Private-driver dispatch DATA only. Every selected operation still requires
/// complete actual-parent checks; no tag constructs an admitted peer or P3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum ReceiverAction {
    Send,
    Receive,
    Poll,
    NeedProjection,
    NeedDurability,
    Complete,
}
