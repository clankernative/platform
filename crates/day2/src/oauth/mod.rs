//! Private OAuth protocol state. These primitives are not app capabilities.
pub mod account;
pub(crate) mod admission;
pub(crate) mod approval_keys;
pub(crate) mod approval_registry;
pub(crate) mod catalog;
pub(crate) mod clients;
pub mod connect;
pub mod custody;
pub mod declaration;
pub(crate) mod effects;
pub mod exchange;
pub mod external;
pub(crate) mod gitlab;
pub(crate) mod google;
pub(crate) mod host;
pub mod inbound;
pub mod outbound;
pub mod profiles;
pub mod protocol;
pub(crate) mod registration;
mod schema;
pub(crate) mod security_shell;
pub(crate) mod shell_oidc;
pub(crate) mod shell_transport;
pub mod store;
pub(crate) mod workload;

#[cfg(test)]
pub(crate) mod simulation;
