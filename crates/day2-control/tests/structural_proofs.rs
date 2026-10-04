use day2_control::release::{ApprovedRelease, ReadyRelease};

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

#[test]
fn historical_release_handles_can_clone_but_cannot_decode_or_default() {
    let _ = <ApprovedRelease as Clone>::clone;
    let _ = <ReadyRelease as Clone>::clone;
    assert_not_impl!(ApprovedRelease, Default);
    assert_not_impl!(ReadyRelease, Default);
    assert_not_impl!(ApprovedRelease, serde::Deserialize<'static>);
    assert_not_impl!(ReadyRelease, serde::Deserialize<'static>);
}
