use day2_control::release::{ApprovedRelease, ReadyRelease};

#[test]
fn historical_release_handles_keep_the_reviewed_clone_api() {
    let _ = <ApprovedRelease as Clone>::clone;
    let _ = <ReadyRelease as Clone>::clone;
}
