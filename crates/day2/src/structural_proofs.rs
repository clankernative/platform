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
    assert_consuming!(crate::store::RuntimeSql<'static>);
    assert_not_impl!(crate::store::RuntimeSql<'static>, std::fmt::Debug);
    assert_not_impl!(crate::store::RuntimeSql<'static>, Send);
    assert_not_impl!(crate::store::RuntimeSql<'static>, Sync);
    assert_secret_references!(crate::store::RuntimeSql<'static>);
    assert_consuming!(crate::oauth::native_management::SqlOwner<'static>);
    assert_not_impl!(
        crate::oauth::native_management::SqlOwner<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(crate::oauth::native_management::SqlOwner<'static>, Send);
    assert_not_impl!(crate::oauth::native_management::SqlOwner<'static>, Sync);
    assert_secret_references!(crate::oauth::native_management::SqlOwner<'static>);
    assert_consuming!(crate::security_epoch::native_enrollment::PendingAppCurrentPeer<'static>);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::PendingAppCurrentPeer<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::PendingAppCurrentPeer<'static>,
        Sync
    );
    assert_consuming!(
        crate::security_epoch::native_enrollment::ControllerCurrentRendezvous<'static>
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerCurrentRendezvous<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerCurrentRendezvous<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::ShellServingConnection);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ShellServingConnection,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ShellServingConnection,
        Sync
    );
    assert_consuming!(
        crate::security_epoch::native_enrollment::ControllerServingRendezvous<'static>
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingRendezvous<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingRendezvous<'static>,
        Sync
    );
    assert_consuming!(crate::oauth::native_management::RuntimeConsumer<'static, 'static>);
    assert_not_impl!(
        crate::oauth::native_management::RuntimeConsumer<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::oauth::native_management::RuntimeConsumer<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::oauth::native_management::RuntimeConsumer<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::oauth::native_management::PendingWriter<'static, 'static>);
    assert_not_impl!(
        crate::oauth::native_management::PendingWriter<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::oauth::native_management::PendingWriter<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::oauth::native_management::PendingWriter<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::InitialHolderListener);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::InitialHolderListener,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::InitialHolderListener,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::InitialHolderListener,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::ShellServingPeer);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ShellServingPeer,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ShellServingPeer,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ShellServingPeer,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::ControllerServingPeer);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingPeer,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingPeer,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingPeer,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::ControllerServingListener);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingListener,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingListener,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerServingListener,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::CurrentServingPeerPhase<'static>);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::CurrentServingPeerPhase<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::CurrentServingPeerPhase<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::CurrentServingPeerPhase<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::AppInitialStorageContinuity);
    assert_not_impl!(
        crate::security_epoch::AppInitialStorageContinuity,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::AppInitialStorageContinuity, Send);
    assert_not_impl!(crate::security_epoch::AppInitialStorageContinuity, Sync);
    assert_consuming!(crate::security_epoch::CurrentAppStorageBootstrapPhase<'static>);
    assert_not_impl!(
        crate::security_epoch::CurrentAppStorageBootstrapPhase<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::CurrentAppStorageBootstrapPhase<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::CurrentAppStorageBootstrapPhase<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::InitialStorageOutcome);
    assert_not_impl!(
        crate::security_epoch::InitialStorageOutcome,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::InitialStorageOutcome, Send);
    assert_not_impl!(crate::security_epoch::InitialStorageOutcome, Sync);
    assert_consuming!(crate::security_epoch::InitialStorageContinuity);
    assert_not_impl!(
        crate::security_epoch::InitialStorageContinuity,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::InitialStorageContinuity, Send);
    assert_not_impl!(crate::security_epoch::InitialStorageContinuity, Sync);
    assert_consuming!(crate::security_epoch::CurrentStorageBootstrapPhase<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::CurrentStorageBootstrapPhase<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::CurrentStorageBootstrapPhase<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::CurrentStorageBootstrapPhase<'static, 'static>,
        Sync
    );
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
    assert_consuming!(crate::oauth::native_management::Consumer<'static, 'static, 'static>);
    assert_not_impl!(
        crate::oauth::native_management::Consumer<'static, 'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::oauth::native_management::Consumer<'static, 'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::SameEnrolledOwner);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::SameEnrolledOwner,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::SameEnrolledOwner,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::SameEnrolledOwner,
        std::fmt::Debug
    );
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
    assert_consuming!(
        crate::security_epoch::native_enrollment::EnrolledStorageStage<'static, 'static>
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledStorageStage<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledStorageStage<'static, 'static>,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::EnrolledStorageStage<'static, 'static>,
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
    assert_consuming!(
        crate::security_epoch::native_enrollment::InitialHolderServer<'static, 'static>
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::InitialHolderServer<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::InitialHolderServer<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::InitialHolderServer<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::AppHolderPeerContinuity);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AppHolderPeerContinuity,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AppHolderPeerContinuity,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AppHolderPeerContinuity,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::ControllerHolderPeerContinuity);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerHolderPeerContinuity,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerHolderPeerContinuity,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::ControllerHolderPeerContinuity,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::CurrentStoragePeerPhase<'static>);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::CurrentStoragePeerPhase<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::CurrentStoragePeerPhase<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::CurrentStoragePeerPhase<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::native_enrollment::AuthenticatedInitialHolderOffer);
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedInitialHolderOffer,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedInitialHolderOffer,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedInitialHolderOffer,
        Sync
    );
    assert_consuming!(
        crate::security_epoch::native_enrollment::AuthenticatedAppFirstHolder<'static, 'static>
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedAppFirstHolder<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedAppFirstHolder<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedAppFirstHolder<'static, 'static>,
        Sync
    );
    assert_consuming!(
        crate::security_epoch::native_enrollment::AuthenticatedControllerFirstHolder<
            'static,
            'static,
        >
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedControllerFirstHolder<
            'static,
            'static,
        >,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedControllerFirstHolder<
            'static,
            'static,
        >,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::native_enrollment::AuthenticatedControllerFirstHolder<
            'static,
            'static,
        >,
        Sync
    );
    assert_consuming!(crate::security_epoch::NativeConnectionPeerObservation);
    assert_not_impl!(
        crate::security_epoch::NativeConnectionPeerObservation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::NativeConnectionPeerObservation, Send);
    assert_not_impl!(crate::security_epoch::NativeConnectionPeerObservation, Sync);
    assert_consuming!(crate::security_epoch::PreparationCoordinator<'static>);
    assert_not_impl!(
        crate::security_epoch::PreparationCoordinator<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::PreparationCoordinator<'static>, Send);
    assert_not_impl!(crate::security_epoch::PreparationCoordinator<'static>, Sync);
    assert_consuming!(crate::security_epoch::NativeOriginalPreparationOutcome<'static>);
    assert_not_impl!(
        crate::security_epoch::NativeOriginalPreparationOutcome<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::NativeOriginalPreparationOutcome<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::NativeOriginalPreparationOutcome<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::OriginalCreatorFd<'static>);
    assert_not_impl!(
        crate::security_epoch::OriginalCreatorFd<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::OriginalCreatorFd<'static>, Send);
    assert_not_impl!(crate::security_epoch::OriginalCreatorFd<'static>, Sync);
    assert_consuming!(crate::security_epoch::PreparedInitialFile<'static>);
    assert_not_impl!(
        crate::security_epoch::PreparedInitialFile<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::PreparedInitialFile<'static>, Send);
    assert_not_impl!(crate::security_epoch::PreparedInitialFile<'static>, Sync);
    assert_consuming!(crate::security_epoch::PreparedFileContinuity);
    assert_not_impl!(
        crate::security_epoch::PreparedFileContinuity,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::PreparedFileContinuity, Send);
    assert_not_impl!(crate::security_epoch::PreparedFileContinuity, Sync);
    assert_consuming!(crate::security_epoch::CurrentPhysicalFilePhase<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::CurrentPhysicalFilePhase<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        crate::security_epoch::CurrentPhysicalFilePhase<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::CurrentPhysicalFilePhase<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::CurrentPreparedFilePhase<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::CurrentPreparedFilePhase<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        crate::security_epoch::CurrentPreparedFilePhase<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::CurrentPreparedFilePhase<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::PreparedRetentionOutcome<'static>);
    assert_not_impl!(
        crate::security_epoch::PreparedRetentionOutcome<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::PreparedRetentionOutcome<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::PreparedRetentionOutcome<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::AppFileContinuity);
    assert_not_impl!(crate::security_epoch::AppFileContinuity, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::AppFileContinuity, serde::Serialize);
    assert_not_impl!(crate::security_epoch::AppFileContinuity, Send);
    assert_not_impl!(crate::security_epoch::AppFileContinuity, Sync);
    assert_consuming!(crate::security_epoch::AppPreparedFile<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::AppPreparedFile<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::AppPreparedFile<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::AppPreparedFile<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::BeforeAttemptRefusal<'static>);
    assert_not_impl!(
        crate::security_epoch::BeforeAttemptRefusal<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::BeforeAttemptRefusal<'static>, Send);
    assert_not_impl!(crate::security_epoch::BeforeAttemptRefusal<'static>, Sync);
    assert_consuming!(crate::security_epoch::RefusedOriginalPreparation<'static>);
    assert_not_impl!(
        crate::security_epoch::RefusedOriginalPreparation<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::RefusedOriginalPreparation<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::RefusedOriginalPreparation<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::NativeStorageCreationAuthority<'static>);
    assert_not_impl!(
        crate::security_epoch::NativeStorageCreationAuthority<'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::NativeStorageCreationAuthority<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::NativeStorageCreationAuthority<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::NativeNamespaceObservation);
    assert_not_impl!(
        crate::security_epoch::NativeNamespaceObservation,
        std::fmt::Debug
    );
    assert_not_impl!(crate::security_epoch::NativeNamespaceObservation, Send);
    assert_not_impl!(crate::security_epoch::NativeNamespaceObservation, Sync);
    assert_consuming!(crate::security_epoch::control_slot_io::SlotObservation);
    assert_consuming!(crate::security_epoch::control_slot_io::Mutation<'static, 'static>);
    assert_consuming!(
        crate::security_epoch::control_slot_io::SlotMaintenanceMutation<'static, 'static>
    );
    assert_consuming!(crate::security_epoch::control_slot_io::SlotClaimMutation<'static, 'static>);
    assert_consuming!(crate::security_epoch::control_slot_io::KnownClaim<'static, 'static>);
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
        crate::security_epoch::control_slot_io::Mutation<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::Mutation<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::Mutation<'static, 'static>,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotMaintenanceMutation<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::SlotClaimMutation<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::KnownClaim<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::KnownClaim<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::control_slot_io::KnownClaim<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::AuthenticatedReads<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::AuthenticatedReads<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::AuthenticatedReads<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::AuthenticatedReads<'static, 'static>,
        Sync
    );
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
    assert_consuming!(crate::security_epoch::journal::CurrentBootstrapExecution<'static, 'static>);
    assert_consuming!(crate::security_epoch::journal::PreparedDispatch<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::journal::PreparedDispatch<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::journal::PreparedDispatch<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::journal::PreparedDispatch<'static, 'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::journal::CounterResponse<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::journal::CounterResponse<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::journal::CounterResponse<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::journal::CounterResponse<'static, 'static>,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::journal::CurrentBootstrapExecution<'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(
        crate::security_epoch::journal::CurrentBootstrapExecution<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::journal::CurrentBootstrapExecution<'static, 'static>,
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

const _: () = {
    assert_consuming!(crate::security_epoch::AppStorageBootstrap);
    assert_consuming!(crate::security_epoch::ActiveAppStorageContinuity);
    assert_not_impl!(crate::security_epoch::AppStorageBootstrap, Send);
    assert_not_impl!(crate::security_epoch::AppStorageBootstrap, Sync);
    assert_not_impl!(crate::security_epoch::ActiveAppStorageContinuity, Send);
    assert_not_impl!(crate::security_epoch::ActiveAppStorageContinuity, Sync);
};

const _: () = {
    assert_consuming!(crate::security_epoch::ActiveControllerStorageContinuity);
    assert_consuming!(crate::security_epoch::ControllerPort<'static, 'static>);
    assert_not_impl!(
        crate::security_epoch::ActiveControllerStorageContinuity,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::ActiveControllerStorageContinuity,
        Sync
    );
    assert_not_impl!(
        crate::security_epoch::ControllerPort<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::ControllerPort<'static, 'static>,
        Sync
    );
};

const _: () = {
    assert_consuming!(crate::security_epoch::RetainedEpochReads);
    assert_not_impl!(crate::security_epoch::RetainedEpochReads, Send);
    assert_not_impl!(crate::security_epoch::RetainedEpochReads, Sync);
};

const _: () = {
    assert_consuming!(crate::security_epoch::CurrentAppStoragePhase<'static>);
    assert_consuming!(crate::security_epoch::CurrentControllerStoragePhase<'static, 'static>);
    assert_not_impl!(crate::security_epoch::CurrentAppStoragePhase<'static>, Send);
    assert_not_impl!(crate::security_epoch::CurrentAppStoragePhase<'static>, Sync);
    assert_not_impl!(
        crate::security_epoch::CurrentControllerStoragePhase<'static, 'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::CurrentControllerStoragePhase<'static, 'static>,
        Sync
    );
};

const _: () = {
    assert_consuming!(crate::security_epoch::serving::CurrentShellServingPhase<'static>);
    assert_not_impl!(
        crate::security_epoch::serving::CurrentShellServingPhase<'static>,
        Send
    );
    assert_not_impl!(
        crate::security_epoch::serving::CurrentShellServingPhase<'static>,
        Sync
    );
    assert_consuming!(crate::security_epoch::ServingParticipant);
    assert_consuming!(crate::security_epoch::CurrentAppServingPhase<'static>);
    assert_not_impl!(crate::security_epoch::ServingParticipant, Send);
    assert_not_impl!(crate::security_epoch::ServingParticipant, Sync);
    assert_not_impl!(crate::security_epoch::CurrentAppServingPhase<'static>, Send);
    assert_not_impl!(crate::security_epoch::CurrentAppServingPhase<'static>, Sync);
};
