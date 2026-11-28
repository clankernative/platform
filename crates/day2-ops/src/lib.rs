#![forbid(unsafe_code)]
pub mod backup;
pub mod chrome_extension;
pub mod ci_check;
pub mod ci_fetch;
pub mod ci_results;
pub mod ci_reuse;
pub mod ci_store;
pub mod ci_workflow;
pub mod infra;
pub mod instance_candidate;
pub mod instance_deploy;
pub mod instance_release;
pub mod instance_roots;
pub mod instance_selection;
pub mod instance_source;
pub mod local_dev;
pub mod maintenance;
pub mod offsite;
pub mod process;
pub mod projection;
pub mod protected_restore;
pub mod source_inputs;

#[cfg(test)]
mod workflow_tests;
