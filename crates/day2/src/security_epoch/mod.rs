//! Private, initial-only external security-epoch protocol.
//!
//! Records, receipts and observations below are historical DATA. None is a
//! current authority, clock, holder or credential-readiness proof. In particular,
//! the live execution-context producer is deliberately absent: ordinary app
//! startup cannot initialize a counter or adopt an existing database here.
mod authenticated_reads;
mod control_slot;
mod control_slot_firestore;
pub(crate) mod control_slot_io;
mod credential_material;
mod firestore;
mod identity_protocol;
pub(crate) mod journal;
mod kernel;
mod namespace_protocol;
mod native_clock;
mod native_connection_peer;
pub(crate) mod native_enrollment;
mod native_identity;
mod native_namespace;
mod preparation_image;
mod runtime_profile;
mod seed_core;
pub(crate) mod serving;
mod storage_authority;
mod transport;

pub(crate) use authenticated_reads::AuthenticatedReads;
pub(crate) use credential_material::CredentialMaterial;
pub(crate) use firestore::EpochObservation;
pub(crate) use native_clock::NativeAcquisition;
pub(crate) use native_connection_peer::NativeConnectionPeerObservation;
pub(crate) use native_identity::NativeProcessObservation;
pub(crate) use native_namespace::NativeNamespaceObservation;
pub(crate) use storage_authority::NativeStorageCreationAuthority;
pub(crate) use storage_authority::{
    AppFileContinuity, AppPreparedFile, BeforeAttemptRefusal, CurrentPhysicalFilePhase,
    CurrentPreparedFilePhase, NativeOriginalPreparationOutcome, OriginalCreatorFd,
    PreparationCoordinator, PreparedFileContinuity, PreparedFileProjection, PreparedInitialFile,
    PreparedRetentionOutcome, RefusedOriginalPreparation,
};

#[cfg(test)]
mod runtime_identity_tests;

#[cfg(test)]
mod control_slot_tests;
#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod tests;
