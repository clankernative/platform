//! `day2 instance deploy`: the non-rolling deploy of an app's checked,
//! preflighted candidate, which the instance's earlier controller ran as
//! `Deployer.deploy` (`maintain.sh backup`, the archive, `maintain.sh
//! activate`, the day2-app apply, the rollout wait and the readback).
//!
//! - **Maintenance** runs the candidate's own SDK operator as a child process
//!   (`day2 platform maintain backup|activate`), so the session's in-pod
//!   protocol always matches the app's tooling image. The operator comes from
//!   the release cache and runs from a private copy whose bytes were checked.
//! - **The request** carries the earlier `maintain.sh`'s values (`request`).
//! - **Backups** are archived where the controller archived them, never
//!   replaced and checked against a local manifest (`archive`).
//! - **The migration fence** decides the path a run takes and what a failure
//!   means (`fence`): before the fence the operator restores the app on its
//!   image (exit 6); after it the old image never restarts and only a rerun of
//!   the same candidate rolls forward (exit 8, `deploy_fenced`). A transient
//!   read before anything stopped is retryable (exit 7).
pub mod archive;
pub mod fence;
pub mod request;

#[cfg(test)]
mod tests;
