#![forbid(unsafe_code)]
pub mod app_create;
pub mod backup;
pub mod infra;
pub mod local_dev;
pub mod maintenance;
pub mod offsite;
pub mod process;
pub mod projection;

#[cfg(test)]
mod workflow_tests;

#[cfg(test)]
mod app_creation_tests;
