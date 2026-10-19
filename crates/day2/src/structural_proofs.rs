//! Production type checks for selected authority handles. These compile in the
//! normal crate as well as tests, so a cfg(not(test)) trait impl cannot evade them.
//! Type inference becomes ambiguous if a protected type implements the trait.
macro_rules! assert_not_impl {
    ($type:ty, $trait:path) => {{
        trait AmbiguousIfImpl<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
        impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}
        let _ = <$type as AmbiguousIfImpl<_>>::check;
    }};
}

macro_rules! assert_consuming {
    ($type:ty) => {
        assert_not_impl!($type, Clone);
        assert_not_impl!($type, Copy);
        assert_not_impl!($type, Default);
        assert_not_impl!($type, serde::Serialize);
        assert_not_impl!($type, serde::Deserialize<'static>);
    };
}

macro_rules! assert_secret_references {
    ($type:ty) => {
        assert_not_impl!(&$type, std::fmt::Debug);
        assert_not_impl!(&mut $type, std::fmt::Debug);
        assert_not_impl!(&$type, serde::Serialize);
        assert_not_impl!(&mut $type, serde::Serialize);
    };
}

const _: () = {
    assert_consuming!(crate::oauth::native_management::AppCreator<'static>);
    assert_not_impl!(crate::oauth::native_management::AppCreator<'static>, Send);
    assert_not_impl!(crate::oauth::native_management::AppCreator<'static>, Sync);
    assert_consuming!(crate::oauth::management::app::CaptureStart);
    assert_not_impl!(crate::oauth::management::app::CaptureStart, Send);
    assert_not_impl!(crate::oauth::management::app::CaptureStart, Sync);
    assert_consuming!(crate::oauth::management::app::CommittedCapture<'static>);
    assert_not_impl!(
        crate::oauth::management::app::CommittedCapture<'static>,
        Send
    );
    assert_not_impl!(
        crate::oauth::management::app::CommittedCapture<'static>,
        Sync
    );
    assert_consuming!(crate::oauth::native_management::OriginalPhase<'static>);
    assert_not_impl!(
        crate::oauth::native_management::OriginalPhase<'static>,
        Send
    );
    assert_not_impl!(
        crate::oauth::native_management::OriginalPhase<'static>,
        Sync
    );
    assert_consuming!(crate::oauth::native_management::RoleStage<'static>);
    assert_not_impl!(crate::oauth::native_management::RoleStage<'static>, Send);
    assert_not_impl!(crate::oauth::native_management::RoleStage<'static>, Sync);
    assert_consuming!(crate::security_epoch::native_enrollment::EnrolledProcessRoleOwner);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledProcessRoleOwner,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledProcessRoleOwner,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledProcessRoleOwner,
        std::fmt::Debug
    );
    assert_consuming!(crate::security_epoch::native_enrollment::EnrolledRoleStage<'static>);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledRoleStage<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledRoleStage<'static>,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledRoleStage<'static>,
        std::fmt::Debug
    );
    assert_consuming!(crate::security_epoch::native_enrollment::EnrolledOriginalClock);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledOriginalClock,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledOriginalClock,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledOriginalClock,
        std::fmt::Debug
    );
    assert_consuming!(crate::security_epoch::NativeConnectionPeerObservation);
    assert_not_impl!(
        crate::security_epoch::NativeConnectionPeerObservation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::NativeConnectionPeerObservation, Send);
    assert_not_impl!(crate::security_epoch::NativeConnectionPeerObservation, Sync);
    assert_consuming!(crate::security_epoch::PreparationCoordinator);
    assert_not_impl!(
        crate::security_epoch::PreparationCoordinator,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::PreparationCoordinator, Send);
    assert_not_impl!(crate::security_epoch::PreparationCoordinator, Sync);
    assert_consuming!(crate::security_epoch::NativeOriginalPreparationOutcome);
    assert_not_impl!(
        crate::security_epoch::NativeOriginalPreparationOutcome,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::NativeOriginalPreparationOutcome,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::NativeOriginalPreparationOutcome,
        Sync
    );
    assert_consuming!(crate::security_epoch::OriginalCreatorFd);
    assert_not_impl!(crate::security_epoch::OriginalCreatorFd, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::OriginalCreatorFd, Send);
    assert_not_impl!(crate::security_epoch::OriginalCreatorFd, Sync);
    assert_consuming!(crate::security_epoch::BeforeAttemptRefusal);
    assert_not_impl!(crate::security_epoch::BeforeAttemptRefusal, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::BeforeAttemptRefusal, Send);
    assert_not_impl!(crate::security_epoch::BeforeAttemptRefusal, Sync);
    assert_consuming!(crate::security_epoch::RefusedOriginalPreparation);
    assert_not_impl!(
        crate::security_epoch::RefusedOriginalPreparation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::RefusedOriginalPreparation, Send);
    assert_not_impl!(crate::security_epoch::RefusedOriginalPreparation, Sync);
    assert_consuming!(crate::security_epoch::NativeStorageCreationAuthority);
    assert_not_impl!(
        crate::security_epoch::NativeStorageCreationAuthority,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::NativeStorageCreationAuthority, Send);
    assert_not_impl!(crate::security_epoch::NativeStorageCreationAuthority, Sync);
    assert_consuming!(crate::security_epoch::NativeNamespaceObservation);
    assert_not_impl!(
        crate::security_epoch::NativeNamespaceObservation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::NativeNamespaceObservation, Send);
    assert_not_impl!(crate::security_epoch::NativeNamespaceObservation, Sync);
    assert_consuming!(crate::security_epoch::control_slot_io::SlotObservation);
    assert_consuming!(crate::security_epoch::control_slot_io::Mutation);
    assert_consuming!(crate::security_epoch::control_slot_io::SlotMaintenanceMutation);
    assert_consuming!(crate::security_epoch::control_slot_io::SlotClaimMutation);
    assert_consuming!(crate::security_epoch::control_slot_io::KnownClaim);
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotObservation,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotObservation,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotObservation,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::Mutation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::control_slot_io::Mutation, Send);
    assert_not_impl!(crate::security_epoch::control_slot_io::Mutation, Sync);
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotMaintenanceMutation,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotClaimMutation,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::KnownClaim,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::control_slot_io::KnownClaim, Send);
    assert_not_impl!(crate::security_epoch::control_slot_io::KnownClaim, Sync);
    assert_consuming!(crate::security_epoch::AuthenticatedReads);
    assert_not_impl!(crate::security_epoch::AuthenticatedReads, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::AuthenticatedReads, Send);
    assert_not_impl!(crate::security_epoch::AuthenticatedReads, Sync);
    assert_consuming!(crate::security_epoch::NativeAcquisition);
    assert_not_impl!(crate::security_epoch::NativeAcquisition, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::NativeAcquisition, Send);
    assert_not_impl!(crate::security_epoch::NativeAcquisition, Sync);
    assert_consuming!(crate::security_epoch::NativeProcessObservation);
    assert_not_impl!(
        crate::security_epoch::NativeProcessObservation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::NativeProcessObservation, Send);
    assert_not_impl!(crate::security_epoch::NativeProcessObservation, Sync);
    assert_consuming!(crate::security_epoch::CredentialMaterial);
    assert_not_impl!(crate::security_epoch::CredentialMaterial, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::CredentialMaterial, Send);
    assert_not_impl!(crate::security_epoch::CredentialMaterial, Sync);
    assert_secret_references!(crate::security_epoch::CredentialMaterial);
    assert_consuming!(crate::security_epoch::EpochObservation);
    assert_not_impl!(crate::security_epoch::EpochObservation, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::EpochObservation, Send);
    assert_not_impl!(crate::security_epoch::EpochObservation, Sync);
    assert_consuming!(crate::security_epoch::journal::CurrentBootstrapExecution);
    assert_not_impl!(
        crate::security_epoch::journal::CurrentBootstrapExecution,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::journal::CurrentBootstrapExecution,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::journal::CurrentBootstrapExecution,
        Sync
    );
    assert_consuming!(crate::execution::DispatchPermit);
    assert_consuming!(crate::oauth::exchange::ExchangeDispatchPermit);
    assert_consuming!(crate::oauth::store::RefreshDispatchPermit);
    assert_consuming!(crate::oauth::refresh::ClientCredential);
    assert_consuming!(crate::oauth::refresh::PreparedReplacement);
    assert_consuming!(crate::oauth::refresh::Resolution);
    assert_not_impl!(crate::oauth::refresh::ClientCredential, std::fmt::Debug);
    assert_not_impl!(crate::oauth::refresh::PreparedReplacement, std::fmt::Debug);
    assert_not_impl!(crate::oauth::refresh::Resolution, std::fmt::Debug);
    assert_secret_references!(crate::oauth::refresh::ClientCredential);
    assert_secret_references!(crate::oauth::refresh::PreparedReplacement);
    assert_secret_references!(crate::oauth::refresh::Resolution);
    assert_consuming!(crate::managed_credentials::store::HumanRevealPermit);
    assert_consuming!(crate::managed_credentials::store::PendingReveal);
    assert_not_impl!(
        crate::managed_credentials::store::HumanRevealPermit,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::managed_credentials::store::PendingReveal,
        std::fmt::Debug
    );
    assert_secret_references!(crate::managed_credentials::store::HumanRevealPermit);
    assert_secret_references!(crate::managed_credentials::store::PendingReveal);
};
