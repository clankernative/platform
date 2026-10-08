//! Every day2-control integration test, linked into one binary.
//!
//! Each file in this directory used to be its own test target. Every one of them
//! linked all of day2-control and its dependencies again, so a one-line library edit
//! relinked dozens of executables. As modules of one binary they link once.
//! Select a former target with its module name as a filter, for example
//! `cargo test -p day2-control --test control_integration -- build::`.

mod build;
mod ci;
mod control_service;
mod durable_release;
mod durable_resource_release;
mod durable_secret_retirement;
mod gcp_secret_conformance;
mod gke_release;
mod iap_service_jwt;
mod journal;
mod journal_guards;
mod journal_storage;
mod kernel_compatibility;
mod kubernetes_conformance;
mod provider_conformance;
mod release;
mod release_catalog;
mod release_execution;
mod remote_source;
mod runtime_secret;
mod secret_retirement;
mod secrets;
mod simulation;
mod simulation_acceptance;
mod simulation_admission;
mod simulation_generation;
mod simulation_retirement;
mod simulation_workflows;
mod source;
mod structural_proofs;

// Helpers shared by several test modules, compiled once.
mod support {
    pub mod release;
}
