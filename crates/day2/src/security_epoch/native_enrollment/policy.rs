use super::NativeRole;
use super::root_kms::KmsRootSelection;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{GkeRoleSelection, InitialBootstrapPolicy},
    },
};
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", test))]
use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", test))]
pub(super) const MAX_POLICY_BYTES: u64 = 65_536;

/// One bounded DATA interpretation on one actual stage. This owns no file,
/// clock, process or current permission. The native caller must freshly read
/// and check the selected file before EVERY observation, including byte hits.
#[cfg(any(target_os = "linux", test))]
pub(super) struct PolicyInterpretation {
    current: Option<(Zeroizing<Vec<u8>>, EnrollmentPolicy)>,
    refused: bool,
    #[cfg(test)]
    decodes: usize,
}

#[cfg(any(target_os = "linux", test))]
impl PolicyInterpretation {
    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn decodes_for_fixture(&self) -> usize {
        self.decodes
    }

    pub(super) fn new() -> Self {
        Self {
            current: None,
            refused: false,
            #[cfg(test)]
            decodes: 0,
        }
    }

    pub(super) fn observe(
        &mut self,
        fresh: Result<Zeroizing<Vec<u8>>>,
        expected: &EnrollmentPolicy,
    ) -> Result<()> {
        ensure!(
            !self.refused,
            "native_enrollment_policy_interpretation_refused"
        );
        let result = (|| {
            let bytes = fresh?;
            ensure!(
                !bytes.is_empty() && bytes.len() as u64 <= MAX_POLICY_BYTES,
                "native_enrollment_operator_file_bound"
            );
            let unchanged = self
                .current
                .as_ref()
                .is_some_and(|(previous, _)| previous.as_slice() == bytes.as_slice());
            if !unchanged {
                #[cfg(test)]
                {
                    self.decodes += 1;
                }
                let policy: EnrollmentPolicy = crate::json::decode(&bytes)?;
                policy.validate()?;
                self.current = Some((bytes, policy));
            }
            // Equality against the actual owner's immutable expected policy
            // is required on hits too. Raw bytes alone never select a policy.
            ensure!(
                self.current
                    .as_ref()
                    .is_some_and(|(_, policy)| policy == expected),
                "native_enrollment_operator_selection_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.current = None;
            self.refused = true;
        }
        result
    }
}

/// Operator selections only. Role, workload, container, code and profile have
/// one canonical source in the shared initial-bootstrap contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnrollmentPolicy {
    pub bootstrap: InitialBootstrapPolicy,
    /// Routing/identity DATA; enrollment does not read or require an epoch.
    pub store: EpochStore,
    pub root: KmsRootSelection,
    pub provisioner_code: Digest,
    pub issuer_code: Digest,
    pub runtime: RuntimeSelection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeSelection {
    pub containerd_code: Digest,
    pub containerd_version: String,
    pub containerd_revision: String,
    pub cri_version: String,
    pub node_name: String,
    pub node_uid: String,
    pub kernel_release: String,
    pub architecture: String,
}

impl EnrollmentPolicy {
    pub(super) fn validate(&self) -> Result<()> {
        self.bootstrap
            .validate(&std::collections::BTreeMap::from([(
                self.bootstrap.epoch_store.id.clone(),
                self.store.clone(),
            )]))?;
        self.root.validate()?;
        self.root_key()?;
        // Some reviewed distro builds report an explicitly empty revision.
        // It remains required selection DATA and is compared exactly at RPC.
        let revision = &self.runtime.containerd_revision;
        ensure!(
            revision.len() <= 253
                && !revision
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace()),
            "native_enrollment_runtime_revision_selection"
        );
        for value in [
            &self.runtime.containerd_version,
            &self.runtime.cri_version,
            &self.runtime.node_name,
            &self.runtime.node_uid,
            &self.runtime.kernel_release,
            &self.runtime.architecture,
        ] {
            ensure!(
                !value.is_empty()
                    && value.len() <= 253
                    && !value.chars().any(|c| c.is_control() || c.is_whitespace()),
                "native_enrollment_runtime_selection"
            );
        }
        Ok(())
    }

    pub(super) fn root_key(&self) -> Result<[u8; 32]> {
        decode_key(&self.root.public_key)
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-native-enrollment-policy-v1", self))
    }

    pub(super) fn code(&self, role: NativeRole) -> &Digest {
        self.bootstrap.native_role(role).code
    }

    pub(super) fn workload(&self, role: NativeRole) -> &GkeRoleSelection {
        self.bootstrap.native_role(role).workload
    }
}

pub(super) fn decode_key(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 43, "native_enrollment_key_encoding");
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&bytes) == value,
        "native_enrollment_key_encoding"
    );
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("native_enrollment_key_length"))
}

#[cfg(test)]
mod interpretation_tests {
    use super::*;
    use crate::security_epoch::native_enrollment::{protocol::KeyOwner, tests::policy};

    fn fixture() -> (EnrollmentPolicy, Vec<u8>) {
        let expected = policy(&KeyOwner::generate().unwrap());
        expected.validate().unwrap();
        let bytes = serde_json::to_vec(&expected).unwrap();
        (expected, bytes)
    }

    fn fresh(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    fn assert_terminal(
        interpretation: &mut PolicyInterpretation,
        expected: &EnrollmentPolicy,
        restored: &[u8],
    ) {
        assert!(interpretation.refused);
        assert!(interpretation.current.is_none());
        let attempts = interpretation.decodes;
        assert!(interpretation.observe(fresh(restored), expected).is_err());
        assert_eq!(interpretation.decodes, attempts);
        assert!(interpretation.current.is_none());
    }

    #[test]
    fn exact_fresh_bytes_reuse_only_decoding_and_keep_one_bounded_entry() {
        let (expected, bytes) = fixture();
        let mut interpretation = PolicyInterpretation::new();
        interpretation.observe(fresh(&bytes), &expected).unwrap();
        interpretation.observe(fresh(&bytes), &expected).unwrap();
        assert_eq!(interpretation.decodes, 1);
        let (retained, decoded) = interpretation.current.as_ref().unwrap();
        assert_eq!(retained.as_slice(), bytes);
        assert_eq!(decoded, &expected);
        assert!(retained.len() as u64 <= MAX_POLICY_BYTES);
    }

    #[test]
    fn equal_reencoding_is_redecoded_and_replaces_the_single_entry() {
        let (expected, bytes) = fixture();
        let pretty = serde_json::to_vec_pretty(&expected).unwrap();
        assert_ne!(bytes, pretty);
        let mut interpretation = PolicyInterpretation::new();
        interpretation.observe(fresh(&bytes), &expected).unwrap();
        interpretation.observe(fresh(&pretty), &expected).unwrap();
        assert_eq!(interpretation.decodes, 2);
        assert_eq!(
            interpretation.current.as_ref().unwrap().0.as_slice(),
            pretty
        );
        interpretation.observe(fresh(&pretty), &expected).unwrap();
        assert_eq!(interpretation.decodes, 2);
        interpretation.observe(fresh(&bytes), &expected).unwrap();
        assert_eq!(interpretation.decodes, 3);
        assert_eq!(interpretation.current.as_ref().unwrap().0.as_slice(), bytes);
    }

    #[test]
    fn fresh_read_refusal_cannot_use_a_hit_or_revive_after_restoration() {
        // These are pure observation-boundary controls, not simulated native
        // file owners. Real NOFOLLOW/profile/read checks stay in selected_file.
        for cause in [
            "mode", "uid", "symlink", "missing", "oversize", "read", "clock",
        ] {
            let (expected, bytes) = fixture();
            let mut interpretation = PolicyInterpretation::new();
            interpretation.observe(fresh(&bytes), &expected).unwrap();
            let error = interpretation
                .observe(Err(anyhow::anyhow!(cause)), &expected)
                .unwrap_err();
            assert_eq!(error.to_string(), cause);
            assert_eq!(interpretation.decodes, 1);
            assert_terminal(&mut interpretation, &expected, &bytes);
        }
    }

    #[test]
    fn changed_bytes_still_require_strict_key_shape_depth_and_node_validation() {
        let (expected, bytes) = fixture();
        let mut unknown = serde_json::to_value(&expected).unwrap();
        unknown["unexpected"] = true.into();
        let duplicate = format!(
            "{{\"issuer_code\":{},{}",
            serde_json::to_string(&expected.issuer_code).unwrap(),
            std::str::from_utf8(&bytes)
                .unwrap()
                .strip_prefix('{')
                .unwrap()
        )
        .into_bytes();
        let cases = [
            (b"{".to_vec(), "EOF"),
            (serde_json::to_vec(&unknown).unwrap(), "unknown field"),
            (duplicate, "duplicate JSON key"),
            (
                format!("{}0{}", "[".repeat(33), "]".repeat(33)).into_bytes(),
                "JSON structure budget",
            ),
            (
                serde_json::to_vec(&vec![0_u8; 20_000]).unwrap(),
                "JSON structure budget",
            ),
        ];
        for (changed, reason) in cases {
            assert!(changed.len() as u64 <= MAX_POLICY_BYTES);
            let mut interpretation = PolicyInterpretation::new();
            interpretation.observe(fresh(&bytes), &expected).unwrap();
            let error = interpretation
                .observe(fresh(&changed), &expected)
                .unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
            assert_eq!(interpretation.decodes, 2);
            assert_terminal(&mut interpretation, &expected, &bytes);
        }
    }

    #[test]
    fn changed_invalid_policy_is_validated_even_with_matching_expected_data() {
        let (expected, bytes) = fixture();
        let mut invalid = expected.clone();
        invalid.runtime.node_name.clear();
        let encoded = serde_json::to_vec(&invalid).unwrap();
        let mut interpretation = PolicyInterpretation::new();
        interpretation.observe(fresh(&bytes), &expected).unwrap();
        let error = interpretation
            .observe(fresh(&encoded), &invalid)
            .unwrap_err();
        assert_eq!(error.to_string(), "native_enrollment_runtime_selection");
        assert_eq!(interpretation.decodes, 2);
        assert_terminal(&mut interpretation, &expected, &bytes);
    }

    #[test]
    fn changed_semantics_or_different_expected_policy_refuse_including_hits() {
        let (expected, bytes) = fixture();
        let mut changed = expected.clone();
        changed.runtime.node_name = "different-node".into();
        changed.validate().unwrap();
        let different = serde_json::to_vec(&changed).unwrap();
        for hit in [false, true] {
            let mut interpretation = PolicyInterpretation::new();
            interpretation.observe(fresh(&bytes), &expected).unwrap();
            let (observed, owner) = if hit {
                (&bytes, &changed)
            } else {
                (&different, &expected)
            };
            let error = interpretation.observe(fresh(observed), owner).unwrap_err();
            assert_eq!(
                error.to_string(),
                "native_enrollment_operator_selection_changed"
            );
            assert_eq!(interpretation.decodes, if hit { 1 } else { 2 });
            assert_terminal(&mut interpretation, &expected, &bytes);
        }
    }

    #[test]
    fn maximum_entry_is_bounded_and_empty_or_oversized_observations_refuse() {
        let (expected, mut bytes) = fixture();
        bytes.resize(MAX_POLICY_BYTES as usize, b' ');
        for changed in [Vec::new(), vec![b' '; MAX_POLICY_BYTES as usize + 1]] {
            let mut interpretation = PolicyInterpretation::new();
            interpretation.observe(fresh(&bytes), &expected).unwrap();
            assert_eq!(
                interpretation.current.as_ref().unwrap().0.len(),
                MAX_POLICY_BYTES as usize
            );
            let error = interpretation
                .observe(fresh(&changed), &expected)
                .unwrap_err();
            assert_eq!(error.to_string(), "native_enrollment_operator_file_bound");
            assert_eq!(interpretation.decodes, 1);
            assert_terminal(&mut interpretation, &expected, &bytes);
        }
    }
}
