// Type inference becomes ambiguous if the protected type implements the trait.
// Unlike an external import failure, this checks private types in their crate.
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

#[test]
fn dispatch_and_reveal_permits_cannot_be_reconstructed_or_duplicated() {
    assert_consuming!(crate::oauth::exchange::ExchangeDispatchPermit);
    assert_consuming!(crate::oauth::store::RefreshDispatchPermit);
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
}
