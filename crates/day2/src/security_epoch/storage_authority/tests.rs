//! DATA and unqualified filesystem controls. No test fixture supplies the
//! production runtime/role/provider issuer that is deliberately absent.

use super::*;
use crate::security_epoch::{control_slot_tests, seed_core::Incarnations, tests as epoch_tests};
use serde_json::{Value, json};
use std::time::Duration;

fn data() -> Value {
    let store = epoch_tests::selection();
    let policy = control_slot_tests::policy(&store);
    let seed = OriginalSeedCore::new(&policy, &store, Incarnations {
        record: Digest::new(b"storage-record"), database: Digest::new(b"storage-database"),
        activation: Digest::new(b"storage-activation"),
    }).unwrap();
    json!({"policy":policy,"store":store,"seed":seed})
}

fn selection() -> ReviewedStorageSelection {
    ReviewedStorageSelection::decode(&serde_json::to_vec(&data()).unwrap()).unwrap()
}

fn acquisition(domain: &[u8], at: u64) -> NativeAcquisition {
    NativeAcquisition::fixture(Digest::new(domain), std::process::id(),
        Duration::from_secs(at), Duration::from_secs(5))
}

#[test]
fn selection_reuses_exact_existing_policy_store_and_original_seed_data() {
    let selected = selection();
    assert_eq!(selected.seed().provider_volume_uid, selected.policy().fresh_storage.provider_volume_uid);
    assert_eq!(selected.seed().scope, selected.store().scope);
    assert_eq!(selected.digest(), selection().digest());
    // Different generated incarnations remain DATA with a different digest;
    // neither valid selection can instantiate the empty production issuer.
    let mut other = data();
    other["seed"]["incarnations"]["record"] = json!(Digest::new(b"another-record"));
    let other = ReviewedStorageSelection::decode(&serde_json::to_vec(&other).unwrap()).unwrap();
    assert_ne!(selected.digest(), other.digest());
}

#[test]
fn selection_rejects_unknown_duplicate_oversized_and_cross_bound_fields() {
    let good = data();
    for (path, value) in [
        ("/seed/provider_volume_uid",json!("another-volume")),
        ("/seed/mount_binding",json!(Digest::new(b"another-mount"))),
        ("/seed/schema_contract",json!(Digest::new(b"another-schema"))),
        ("/policy/epoch_store/revision",json!(Digest::new(b"another-store"))),
        ("/policy/fresh_storage/provider_volume_uid",json!("another-volume")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(ReviewedStorageSelection::decode(&serde_json::to_vec(&bad).unwrap()).is_err(),"{path}");
    }
    let mut unknown = good.clone();unknown["current"] = json!(true);
    assert!(ReviewedStorageSelection::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    let duplicate = format!("{{\"store\":{},\"store\":{},\"policy\":{},\"seed\":{}}}",
        good["store"],good["store"],good["policy"],good["seed"]);
    assert!(ReviewedStorageSelection::decode(duplicate.as_bytes()).is_err());
    assert!(ReviewedStorageSelection::decode(&vec![b' ';65_537]).unwrap_err().to_string().contains("selection_bound"));
}

#[test]
fn native_budget_keeps_original_origin_when_later_samples_have_a_new_window() {
    let mut original = acquisition(b"same-domain",100);
    let mut budget = original.budget().unwrap();
    let mut later = acquisition(b"same-domain",104);
    assert_eq!(budget.remaining_native(&mut later).unwrap(),Duration::from_secs(1));
    let mut expired = acquisition(b"same-domain",105);
    assert!(budget.remaining_native(&mut expired).is_err());
    let mut other = acquisition(b"other-domain",104);
    assert!(budget.remaining_native(&mut other).is_err());
}

#[cfg(not(target_os="linux"))]
#[test]
fn unsupported_directory_profile_never_qualifies_a_test_owner() {
    let directory = File::open(std::env::temp_dir()).unwrap();
    let mut interval = acquisition(b"unsupported-directory",100);
    assert!(NativeStorageCreationAuthority::filesystem_fixture(selection(),directory,&mut interval).is_err());
    assert!(interval.remaining().is_err());
}

#[cfg(target_os="linux")]
fn fixture() -> (tempfile::TempDir, NativeStorageCreationAuthority, NativeAcquisition) {
    let directory = tempfile::tempdir().unwrap();
    let mut interval = acquisition(b"unqualified-directory",100);
    let authority = NativeStorageCreationAuthority::filesystem_fixture(selection(),File::open(directory.path()).unwrap(),&mut interval).unwrap();
    (directory,authority,interval)
}

#[cfg(target_os="linux")]
#[test]
fn directory_fixture_domain_failure_retains_descriptor_and_is_absorbing() {
    let (_directory,mut authority,mut original) = fixture();
    let mut wrong = acquisition(b"another-domain",100);
    assert!(authority.check_current(&mut wrong).is_err());
    assert!(wrong.remaining().is_err());
    assert!(directory_identity(&authority.directory).unwrap() == authority.identity);
    assert!(authority.check_current(&mut original).is_err());
    assert!(original.remaining().is_err());
}

#[cfg(target_os="linux")]
#[test]
fn directory_fixture_detects_descriptor_substitution_without_reopening_original() {
    let (_directory,mut authority,mut original) = fixture();
    let replacement = tempfile::tempdir().unwrap();
    let old = std::mem::replace(&mut authority.directory,File::open(replacement.path()).unwrap());
    assert!(authority.check_current(&mut original).is_err());
    assert!(directory_identity(&old).unwrap() == authority.identity);
    assert!(original.remaining().is_err());
}

#[cfg(target_os="linux")]
#[test]
fn explicit_preparation_refusal_retains_actual_anchor_and_forbids_later_use() {
    let (_directory,mut authority,mut original) = fixture();
    authority.refuse_preparation(&mut original);
    assert!(directory_identity(&authority.directory).unwrap() == authority.identity);
    let mut later = acquisition(b"unqualified-directory",101);
    assert!(authority.check_current(&mut later).is_err());
    assert!(later.remaining().is_err());
}
