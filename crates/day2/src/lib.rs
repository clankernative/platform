#![forbid(unsafe_code)]
pub mod admin_web;
pub mod admission;
pub mod api_docs;
mod api_examples;
pub mod app_contract;
pub mod app_contracts;
pub mod app_inference;
pub mod app_sources;
pub mod artifact;
pub mod audit;
pub mod authority;
pub mod authority_state;
pub mod automation;
pub mod branding;
pub mod budget;
pub mod build_dependencies;
pub mod capabilities;
pub mod carta;
pub mod carta_live;
pub mod compatibility;
pub mod credential_authority;
pub mod credential_codegen;
pub mod credential_declaration;
pub mod delegation;
pub mod delegation_commands;
pub mod delegation_wire;
pub mod deployment;
pub mod development;
pub mod domain;
mod error;
mod execution;
mod freetool_executor;
mod host;
pub mod host_inputs;
mod host_loop;
pub mod iap;
pub mod iap_workload;
pub mod identity;
pub mod import;
pub mod import_codegen;
pub mod ingress;
pub mod input_shape;
pub mod instance_catalog;
pub mod integration_host;
pub mod integrations;
pub mod invocations;
pub mod journal;
pub mod json;
mod live;
#[allow(dead_code)]
mod managed_credentials;
pub mod mcp;
pub mod migration;
mod release_binding;
// Protocol kernels are staged behind host-only verification and custody wiring.
#[allow(dead_code)]
mod oauth;
pub use oauth::declaration as connection_declaration;
pub mod connection_codegen;
pub mod openapi;
pub mod operation_catalog;
pub mod operation_contract;
pub mod operation_metadata;
pub mod output_schema;
pub mod packaging;
pub mod people_providers;
mod preparation;
pub mod presentation;
pub mod properties;
pub mod protocol;
pub mod redirects;
pub mod registry;
pub mod resource_admin;
mod resource_catalog_history;
mod resources;
pub mod retention;
pub mod rollup;
pub mod routing;
pub mod sandbox;
pub mod schedules;
pub mod schema;
pub mod sdk;
pub mod security_admission;
// Private external-epoch protocol; live enrollment producers remain unqualified.
#[allow(dead_code)]
mod security_epoch;
pub mod simulation;
pub mod simulations;
pub mod store;
pub mod ui_lock;
pub(crate) mod ui_values;
pub mod web;
mod web_api;
mod web_assets;
mod web_forms;
mod web_html;
mod web_query_bindings;
pub mod web_resources;
mod web_security;
pub mod web_templates;
pub mod worker;
pub mod workspace_directory;
pub mod write_queue;

use ring::digest::{SHA256, digest as hash};

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", digest_hex(bytes))
}
pub(crate) fn digest_hex(bytes: &[u8]) -> String {
    hex(hash(&SHA256, bytes).as_ref())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod digest_tests {
    #[test]
    fn sha256_formats_match_known_answers() {
        for (bytes, expected) in [
            (
                b"".as_slice(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".as_slice(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ] {
            assert_eq!(super::digest_hex(bytes), expected);
            assert_eq!(super::digest(bytes), format!("sha256:{expected}"));
            assert_eq!(
                day2_capabilities::Digest::new(bytes).as_str(),
                super::digest(bytes)
            );
        }
    }
}

mod codegen;

mod structural_proofs;

#[cfg(test)]
mod chart_live_tests;
