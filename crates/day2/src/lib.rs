#![forbid(unsafe_code)]
pub mod admin_web;
pub mod admission;
pub mod api_docs;
mod api_examples;
pub mod app_contract;
pub mod app_inference;
pub mod app_sources;
pub mod artifact;
pub mod assets;
pub mod audit;
pub mod authority;
pub mod authority_state;
pub mod automation;
pub mod branding;
pub mod budget;
pub mod capabilities;
pub mod carta;
pub mod compatibility;
pub mod credential_declaration;
pub mod delegation;
pub mod deployment;
pub mod development;
pub mod domain;
mod error;
mod execution;
mod host;
pub mod iap;
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
pub mod numeric;
mod release_binding;
// Protocol kernels are staged behind host-only verification and custody wiring.
#[allow(dead_code)]
mod oauth;
pub mod openapi;
pub mod operation_catalog;
pub mod operation_contract;
pub mod operation_metadata;
pub mod output_schema;
pub mod packaging;
pub mod people_providers;
mod preparation;
pub mod properties;
pub mod protocol;
pub mod redirects;
pub mod registry;
pub mod resource_admin;
mod resource_catalog_history;
mod resources;
pub mod retention;
pub mod routing;
pub mod sandbox;
pub mod schedules;
pub mod schema;
pub mod sdk;
pub mod security_admission;
pub mod simulation;
pub mod simulations;
pub mod store;
pub mod web;
mod web_api;
mod web_assets;
mod web_forms;
mod web_html;
pub mod web_resources;
mod web_security;
pub mod web_templates;
pub mod worker;
pub mod write_queue;

use sha2::{Digest, Sha256};

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
mod codegen;
