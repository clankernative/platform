//! Build contracts and production decisions without access to platform adapters.
//!
//! Inputs and observations are explicit values. The kernel returns a new state
//! and identifies the next requested effect; it never executes that effect.
//! Production source has no `std` imports. Shared `day2-capabilities` contracts
//! still depend on `std`, so the transitive dependency graph is not yet no_std.
#![no_std]
#![forbid(unsafe_code)]
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros
)]

pub mod contracts;
pub mod kernel;

pub use contracts::{BindingRef, BuildPlan, BuildProfile, Digest, GitOid, Name};
