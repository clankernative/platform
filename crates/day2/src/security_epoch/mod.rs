//! Private, initial-only external security-epoch protocol.
//!
//! Records, receipts and observations below are historical DATA. None is a
//! current authority, clock, holder or credential-readiness proof. In particular,
//! the live execution-context producer is deliberately absent: ordinary app
//! startup cannot initialize a counter or adopt an existing database here.
mod authenticated_reads;
mod credential_material;
mod firestore;
mod identity_protocol;
pub(crate) mod journal;
mod kernel;
mod native_clock;
mod native_identity;
mod transport;

pub(crate) use authenticated_reads::AuthenticatedReads;
pub(crate) use credential_material::CredentialMaterial;
pub(crate) use firestore::EpochObservation;
pub(crate) use native_clock::NativeAcquisition;
pub(crate) use native_identity::NativeProcessObservation;

#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod tests;
