//! Every day2 integration test, linked into one binary.
//!
//! Each file in this directory used to be its own test target. Every one of them
//! linked all of day2 and its dependencies again, so a one-line library edit
//! relinked dozens of executables. As modules of one binary they link once.
//! Select a former target with its module name as a filter, for example
//! `cargo test -p day2 --test day2_integration -- admission::`.

mod admission;
mod api_docs;
mod app_contract;
mod app_inference;
mod artifact_hardening;
mod assets;
mod authority;
mod call_context;
mod collection;
mod command_adversarial;
mod command_atomicity;
mod command_recovery;
mod command_simulation;
mod connection_declarations;
mod credential_metadata;
mod delegation;
mod edge;
mod guards;
mod indexes;
mod ingress_hold_gate;
mod instance_capabilities;
mod linux_worker;
mod live_updates;
mod migration_commands;
mod numeric;
mod oauth_setup;
mod operation_catalog;
mod output_schema;
mod owned_runtime;
mod owned_web;
mod page_sdk;
mod pagination;
mod redirect_routes;
mod reports_http;
mod request_identity;
mod resource_admin;
mod retention;
mod routing;
mod runtime;
mod schedule_hold_gate;
mod schedule_source;
mod schedule_sweep;
mod schema;
mod template_routes;
mod templates;
mod web;
mod web_resources;

// Helpers shared by several test modules, compiled once.
mod support {
    pub mod commands;
    pub mod compiler;
    pub mod evidence;
}
