use super::{
    policy::decode_key,
    protocol::{self, KeyOwner},
};
use super::{
    policy::{EnrollmentPolicy, RuntimeSelection},
    protocol::{IssuerCertificate, IssuerData, ProcessData},
};
use day2_capabilities::Digest;

fn enrolled_self_reborrow_shape(source: &str) -> bool {
    use syn::visit::Visit;

    fn fields(expression: &syn::Expr, expected: &[&str]) -> bool {
        match (expression, expected.split_last()) {
            (syn::Expr::Path(path), Some((last, []))) => path.path.is_ident(last),
            (syn::Expr::Field(field), Some((last, rest))) => {
                matches!(&field.member, syn::Member::Named(name) if name == last)
                    && fields(&field.base, rest)
            }
            _ => false,
        }
    }

    #[derive(Default)]
    struct Calls {
        captures: usize,
        clocks: usize,
        owner_checks: usize,
        stage_checks: usize,
    }

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let path = path.path.segments.iter().collect::<Vec<_>>();
                self.captures += usize::from(
                    path.len() == 2
                        && path[0].ident == "SelfSnapshot"
                        && path[1].ident == "acquire",
                );
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.clocks += usize::from(call.method == "into_connection_clock");
            self.owner_checks +=
                usize::from(call.method == "check" && fields(&call.receiver, &["self", "current"]));
            self.stage_checks += usize::from(
                call.method == "check" && fields(&call.receiver, &["self", "owner", "current"]),
            );
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let source = syn::parse_file(source).unwrap();
    let mut enrollment = None;
    let mut begin = None;
    let mut check = None;
    for item in source.items {
        let syn::Item::Impl(implementation) = item else {
            continue;
        };
        let syn::Type::Path(owner) = &*implementation.self_ty else {
            continue;
        };
        let owner = owner.path.segments.last().unwrap().ident.to_string();
        for item in implementation.items {
            let syn::ImplItem::Fn(function) = item else {
                continue;
            };
            let mut calls = Calls::default();
            calls.visit_block(&function.block);
            if owner == "EnrolledProcessRoleOwner" && function.sig.ident == "enroll_current_thread"
            {
                assert!(enrollment.replace(calls).is_none());
            } else if owner == "EnrolledProcessRoleOwner" && function.sig.ident == "begin_stage" {
                assert!(begin.replace(calls).is_none());
            } else if owner == "EnrolledRoleStage" && function.sig.ident == "check" {
                assert!(check.replace(calls).is_none());
            }
        }
    }
    matches!(
        enrollment,
        Some(Calls {
            captures: 1,
            clocks: 1,
            ..
        })
    ) && matches!(
        begin,
        Some(Calls {
            captures: 0,
            owner_checks: 1,
            ..
        })
    ) && matches!(
        check,
        Some(Calls {
            captures: 0,
            stage_checks: 1,
            ..
        })
    )
}

#[test]
fn actual_enrolled_owner_retains_self_resources_for_request_checks() {
    assert!(enrolled_self_reborrow_shape(include_str!("owner.rs")));
}

#[test]
fn enrolled_self_guard_rejects_recapture_or_omitted_retained_checks() {
    let source = include_str!("owner.rs");
    for (before, after) in [
        ("SelfSnapshot::acquire(", "SelfSnapshot::metadata_only("),
        (
            "acquisition.into_connection_clock()?",
            "acquisition.discard_clock()?",
        ),
        (
            "self.current.check(&mut authentication)?",
            "SelfSnapshot::acquire(&mut authentication)?",
        ),
        (
            "self.owner.current.check(&mut self.acquisition)?",
            "self.owner.current.skip(&mut self.acquisition)?",
        ),
    ] {
        let mutated = source.replacen(before, after, 1);
        assert_ne!(mutated, source);
        assert!(!enrolled_self_reborrow_shape(&mutated));
    }
}

pub(super) fn policy(root: &KeyOwner) -> EnrollmentPolicy {
    let store = crate::security_epoch::tests::selection();
    let bootstrap = crate::security_epoch::control_slot_tests::policy(&store);
    EnrollmentPolicy {
        bootstrap,
        store,
        root: super::root_kms::KmsRootSelection {
            version: "projects/test-project/locations/us-central1/keyRings/enrollment/cryptoKeys/root/cryptoKeyVersions/1".into(),
            public_key: root.public(),
        },
        provisioner_code: Digest::new(b"provisioner"),
        issuer_code: Digest::new(b"issuer"),
        runtime: RuntimeSelection {
            containerd_code: Digest::new(b"containerd"),
            containerd_version: "v2.2.0".into(),
            containerd_revision: "selected-revision".into(),
            cri_version: "v1".into(),
            node_name: "node-one".into(),
            node_uid: "node-uid".into(),
            kernel_release: "6.12.0".into(),
            architecture: "arm64".into(),
        },
    }
}

fn process(code: Digest) -> ProcessData {
    ProcessData {
        process: 71,
        start_ticks: 123,
        code,
        boot: "boot-one".into(),
        namespaces: ["time", "time_for_children", "pid", "mnt", "user", "cgroup"]
            .into_iter()
            .map(|name| (name.to_owned(), (7, 9)))
            .collect(),
    }
}

#[test]
fn runtime_revision_may_be_explicitly_empty_but_cannot_be_omitted_or_normalized() {
    let root = KeyOwner::generate().unwrap();
    let mut selected = policy(&root);
    selected.runtime.containerd_version = "2.1.5-0ubuntu0~24.04.1~gke1".into();
    selected.runtime.containerd_revision.clear();
    selected.validate().unwrap();
    let empty_revision = selected.digest().unwrap();
    let mut encoded = serde_json::to_value(&selected).unwrap();
    let decoded: EnrollmentPolicy =
        crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert_eq!(decoded, selected);
    encoded["runtime"]
        .as_object_mut()
        .unwrap()
        .remove("containerd_revision");
    assert!(
        crate::json::decode::<EnrollmentPolicy>(&serde_json::to_vec(&encoded).unwrap()).is_err()
    );

    selected.runtime.containerd_revision = "selected-revision".into();
    assert_ne!(selected.digest().unwrap(), empty_revision);
    for revision in [" ".to_owned(), "\n".to_owned(), "x".repeat(254)] {
        selected.runtime.containerd_revision = revision;
        assert!(selected.validate().is_err());
    }
    selected.runtime.containerd_revision.clear();
    selected.runtime.containerd_version.clear();
    assert!(selected.validate().is_err());
}

#[test]
fn signatures_are_purpose_and_value_bound_and_canonical() {
    let key = KeyOwner::generate().unwrap();
    let signature = key.sign("birth", &"one").unwrap();
    protocol::verify(&key.public(), "birth", &"one", &signature).unwrap();
    assert!(protocol::verify(&key.public(), "stage", &"one", &signature).is_err());
    assert!(protocol::verify(&key.public(), "birth", &"two", &signature).is_err());
    assert!(decode_key(&(key.public() + "=")).is_err());
    assert!(protocol::verify(&key.public(), "birth", &"one", &(signature + "=")).is_err());
}

#[test]
fn packet_parser_refuses_duplicate_unknown_and_oversized_fields() {
    assert!(
        protocol::decode(br#"{"kind":"birth_challenge","policy":"x","policy":"y","nonce":"z"}"#)
            .is_err()
    );
    assert!(protocol::decode(br#"{"kind":"birth_grant","unexpected":true}"#).is_err());
    assert!(protocol::decode(&vec![b' '; protocol::MAX_PACKET + 1]).is_err());
}

#[test]
fn issuer_certificate_requires_selected_root_generation_code_and_company() {
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let selected = policy(&root);
    let data = IssuerData {
        policy: selected.digest().unwrap(),
        root_version: selected.root.version.clone(),
        nonce: Digest::new(b"original-birth"),
        public_key: issuer.public(),
        process: process(selected.issuer_code.clone()),
        provisioner: process(selected.provisioner_code.clone()),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    };
    certificate.verify(&selected).unwrap();
    for changed in ["root", "version", "scope", "code", "profile"] {
        let mut policy = selected.clone();
        match changed {
            "root" => policy.root.public_key = KeyOwner::generate().unwrap().public(),
            "version" => policy.root.version = policy.root.version.replace("/1", "/2"),
            "scope" => policy.bootstrap.scope.app = serde_json::from_str("\"other\"").unwrap(),
            "code" => policy.issuer_code = Digest::new(b"replacement"),
            "profile" => {
                policy.bootstrap.runtime_profile.manifest = Digest::new(b"replacement-profile")
            }
            _ => unreachable!(),
        }
        assert!(certificate.verify(&policy).is_err(), "{changed}");
    }
    let mut changed = certificate.clone();
    changed.data.nonce = Digest::new(b"different-birth");
    assert!(changed.verify(&selected).is_err());
    let mut changed = certificate;
    changed.data.process.start_ticks += 1;
    assert!(changed.verify(&selected).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_never_installs_a_role_or_replaces_the_clock() {
    let scope = crate::security_epoch::tests::selection().scope;
    assert!(
        super::EnrolledProcessRoleOwner::enroll_current_thread(&scope, super::NativeRole::AppHost)
            .is_err()
    );
    assert!(super::run(false).is_err());
}

#[test]
fn role_bind_signature_and_packet_require_the_exact_closed_stage_purpose() {
    use super::{
        NativeRole,
        protocol::{Packet, StagePurpose},
    };
    let key = KeyOwner::generate().unwrap();
    let policy = Digest::new(b"policy");
    let request = Digest::new(b"request");
    let challenge = Digest::new(b"challenge");
    let public = key.public();
    let binding = (
        &policy,
        NativeRole::AppHost,
        StagePurpose::InitialFirstHolder,
        &public,
        &request,
        &challenge,
    );
    let signature = key.sign("role-bind", &binding).unwrap();
    protocol::verify(&public, "role-bind", &binding, &signature).unwrap();
    let other = (
        &policy,
        NativeRole::AppHost,
        StagePurpose::CurrentRole,
        &public,
        &request,
        &challenge,
    );
    assert!(protocol::verify(&public, "role-bind", &other, &signature).is_err());
    let packet = Packet::StageHello {
        policy,
        role: NativeRole::AppHost,
        purpose: StagePurpose::InitialFirstHolder,
        public_key: public,
        request,
    };
    let bytes = serde_json::to_vec(&packet).unwrap();
    assert!(protocol::decode(&bytes).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value.as_object_mut().unwrap().remove("purpose");
    assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["purpose"] = serde_json::json!("any_stage");
    assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn storage_stage_purposes_are_closed_and_role_restricted_independent_of_duration() {
    use super::{NativeRole, protocol::StagePurpose};
    for purpose in [
        StagePurpose::CurrentRole,
        StagePurpose::InitialFirstHolder,
        StagePurpose::StorageBootstrap,
        StagePurpose::StorageMetadataObservation,
    ] {
        for role in [
            NativeRole::AppHost,
            NativeRole::EpochController,
            NativeRole::SecurityShell,
        ] {
            let expected = match purpose {
                StagePurpose::CurrentRole => true,
                StagePurpose::InitialFirstHolder | StagePurpose::StorageBootstrap => {
                    role != NativeRole::SecurityShell
                }
                StagePurpose::StorageMetadataObservation => role == NativeRole::EpochController,
            };
            assert_eq!(purpose.require_role(role).is_ok(), expected);
        }
    }
    assert_eq!(
        StagePurpose::CurrentRole.limit(),
        std::time::Duration::from_secs(5)
    );
    assert_eq!(
        StagePurpose::InitialFirstHolder.limit(),
        std::time::Duration::from_secs(10)
    );
    assert_eq!(
        StagePurpose::StorageBootstrap.limit(),
        std::time::Duration::from_secs(60)
    );
    assert_eq!(
        StagePurpose::StorageMetadataObservation.limit(),
        std::time::Duration::from_secs(10)
    );
}

#[test]
fn validly_signed_short_bootstrap_and_metadata_grants_fail_the_ordinary_current_purpose_gate() {
    // Cryptographic DATA only. This is the exact comparison used by the real
    // EnrolledRoleStage::require_current_role gate, not a native-stage fixture.
    use super::{
        NativeRole,
        protocol::{RuntimeBinding, SignedStage, StageData, StagePurpose},
    };
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let key = KeyOwner::generate().unwrap();
    let selected = policy(&root);
    let issuer_data = IssuerData {
        policy: selected.digest().unwrap(),
        root_version: selected.root.version.clone(),
        nonce: Digest::new(b"purpose-test-issuer"),
        public_key: issuer.public(),
        process: process(selected.issuer_code.clone()),
        provisioner: process(selected.provisioner_code.clone()),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &issuer_data).unwrap(),
        data: issuer_data,
    };
    certificate.verify(&selected).unwrap();
    for (purpose, role) in [
        (StagePurpose::CurrentRole, NativeRole::AppHost),
        (StagePurpose::CurrentRole, NativeRole::EpochController),
        (StagePurpose::InitialFirstHolder, NativeRole::AppHost),
        (
            StagePurpose::InitialFirstHolder,
            NativeRole::EpochController,
        ),
        (StagePurpose::StorageBootstrap, NativeRole::AppHost),
        (StagePurpose::StorageBootstrap, NativeRole::EpochController),
        (
            StagePurpose::StorageMetadataObservation,
            NativeRole::EpochController,
        ),
    ] {
        for seconds in [1_u64, 5] {
            purpose.require_role(role).unwrap();
            let workload = selected.workload(role);
            let data = StageData {
                issuer: certificate.digest().unwrap(),
                policy: selected.digest().unwrap(),
                role,
                purpose,
                public_key: key.public(),
                challenge: Digest::new(b"purpose-challenge"),
                request: Digest::new(b"purpose-request"),
                process: process(selected.code(role).clone()),
                runtime: RuntimeBinding {
                    container: crate::security_epoch::runtime_profile::ContainerFacts {
                        pod_name: workload.workload.name.clone(),
                        pod_uid: format!("purpose-test-{role:?}"),
                        node_name: selected.runtime.node_name.clone(),
                        container_name: workload.container.name.clone(),
                        container_id: "a".repeat(64),
                        image: workload.container.image.clone(),
                        restart_count: 0,
                    },
                    node_uid: "node-uid".into(),
                    boot: "boot-one".into(),
                },
                origin_ns: 100_000_000_000,
                deadline_ns: 100_000_000_000 + seconds * 1_000_000_000,
            };
            let stage = SignedStage {
                signature: issuer.sign("role-stage", &data).unwrap(),
                data,
            };
            protocol::verify(
                &certificate.data.public_key,
                "role-stage",
                &stage.data,
                &stage.signature,
            )
            .unwrap();
            assert_eq!(
                stage
                    .data
                    .purpose
                    .require_exact(StagePurpose::CurrentRole)
                    .is_ok(),
                purpose == StagePurpose::CurrentRole
            );
            for expected in [
                StagePurpose::CurrentRole,
                StagePurpose::InitialFirstHolder,
                StagePurpose::StorageBootstrap,
                StagePurpose::StorageMetadataObservation,
            ] {
                assert_eq!(
                    stage.data.purpose.require_exact(expected).is_ok(),
                    purpose == expected
                );
                if expected != purpose {
                    let mut substituted = stage.clone();
                    substituted.data.purpose = expected;
                    assert!(
                        protocol::verify(
                            &certificate.data.public_key,
                            "role-stage",
                            &substituted.data,
                            &substituted.signature
                        )
                        .is_err()
                    );
                }
            }
        }
    }
}

#[test]
fn hello_bind_and_grant_signature_never_substitute_a_storage_stage_purpose() {
    use super::{
        NativeRole,
        protocol::{Packet, StagePurpose},
    };
    let key = KeyOwner::generate().unwrap();
    let policy = Digest::new(b"purpose-policy");
    let request = Digest::new(b"purpose-request");
    let challenge = Digest::new(b"purpose-challenge");
    let public = key.public();
    for purpose in [
        StagePurpose::CurrentRole,
        StagePurpose::InitialFirstHolder,
        StagePurpose::StorageBootstrap,
        StagePurpose::StorageMetadataObservation,
    ] {
        let role = NativeRole::EpochController;
        let binding = (&policy, role, purpose, &public, &request, &challenge);
        let signature = key.sign("role-bind", &binding).unwrap();
        protocol::verify(&public, "role-bind", &binding, &signature).unwrap();
        for other in [
            StagePurpose::CurrentRole,
            StagePurpose::InitialFirstHolder,
            StagePurpose::StorageBootstrap,
            StagePurpose::StorageMetadataObservation,
        ] {
            if other != purpose {
                let changed = (&policy, role, other, &public, &request, &challenge);
                assert!(protocol::verify(&public, "role-bind", &changed, &signature).is_err());
            }
        }
        for packet in [
            Packet::StageHello {
                policy: policy.clone(),
                role,
                purpose,
                public_key: public.clone(),
                request: request.clone(),
            },
            Packet::StageBind {
                policy: policy.clone(),
                role,
                purpose,
                public_key: public.clone(),
                request: request.clone(),
                challenge: challenge.clone(),
                signature: signature.clone(),
            },
        ] {
            let mut value = serde_json::to_value(&packet).unwrap();
            assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_ok());
            value.as_object_mut().unwrap().remove("purpose");
            assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
            value["purpose"] = serde_json::json!("any_storage");
            assert!(protocol::decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
}
