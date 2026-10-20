//! Private, initial-only external security-epoch protocol.
//!
//! Records, receipts and observations below are historical DATA. None is a
//! current authority, clock, holder or credential-readiness proof. The native execution context
//! retains a joined Controller/file/peer phase through the consuming dispatch.
//! Ordinary startup cannot initialize a counter or adopt an existing database;
//! the serving supplier and lifecycle still need composition and qualification.
mod authenticated_reads;
mod bootstrap;
mod control_slot;
mod control_slot_firestore;
pub(crate) mod control_slot_io;
pub(crate) mod controller;
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
pub(crate) use serving::ServingParticipant;
mod storage_authority;
mod transport;

/// Desired schema metadata only; this creates no native original or authority.
pub(crate) fn native_schema_metadata(
    instance: &std::path::Path,
    app: &str,
) -> anyhow::Result<serde_json::Value> {
    preparation_image::operator_schema_metadata(instance, app)
}

pub(crate) use authenticated_reads::{AuthenticatedReads, ControllerPort, RetainedEpochReads};
pub(crate) use bootstrap::{
    ActiveAppStorageContinuity, ActiveControllerStorageContinuity, AppStorageBootstrap,
    CurrentAppServingPhase,
};
pub(crate) use credential_material::CredentialMaterial;
pub(crate) use firestore::EpochObservation;
pub(crate) use native_clock::NativeAcquisition;
pub(crate) use native_connection_peer::NativeConnectionPeerObservation;
pub(crate) use native_identity::NativeProcessObservation;
pub(crate) use native_namespace::NativeNamespaceObservation;
pub(crate) use storage_authority::NativeStorageCreationAuthority;
pub(crate) use storage_authority::{
    AppFileContinuity, AppInitialStorageContinuity, AppPreparedFile, BeforeAttemptRefusal,
    CurrentAppStorageBootstrapPhase, CurrentAppStoragePhase, CurrentControllerStoragePhase,
    CurrentPhysicalFilePhase, CurrentPreparedFilePhase, CurrentStorageBootstrapPhase,
    InitialStorageContinuity, InitialStorageOutcome, NativeOriginalPreparationOutcome,
    OriginalCreatorFd, PreparationCoordinator, PreparedFileContinuity, PreparedFileProjection,
    PreparedInitialFile, PreparedRetentionOutcome, RefusedOriginalPreparation,
};

#[cfg(test)]
mod runtime_identity_tests;

#[cfg(test)]
mod control_slot_tests;
#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod tests;
