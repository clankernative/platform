//! Shared model and codec representations, independent of the compiler and host.
#![no_std]
#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

extern crate alloc;

pub mod identity;
pub mod names;
pub mod numeric;
pub mod registry;
pub mod text;
