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
    assert_consuming!(crate::security_epoch::journal::CurrentBootstrapExecution);
    assert_consuming!(crate::security_epoch::journal::InitialEpochCreatePermit);
    assert_consuming!(crate::security_epoch::journal::InitialFirstHolderActivationPermit);
    assert_not_impl!(crate::security_epoch::journal::CurrentBootstrapExecution, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::journal::InitialEpochCreatePermit, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::journal::InitialFirstHolderActivationPermit, std::fmt::Debug);
    assert_not_impl!(crate::security_epoch::journal::CurrentBootstrapExecution, Send);
    assert_not_impl!(crate::security_epoch::journal::CurrentBootstrapExecution, Sync);
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
