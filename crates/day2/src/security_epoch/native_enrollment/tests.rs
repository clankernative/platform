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

    fn linux_body(statement: &syn::Stmt) -> Option<&syn::Block> {
        let syn::Stmt::Expr(syn::Expr::Block(block), _) = statement else {
            return None;
        };
        (block.label.is_none()
            && block.attrs.len() == 1
            && matches!(&block.attrs[0].meta, syn::Meta::List(meta)
                if meta.path.is_ident("cfg") && meta.tokens.to_string() == "target_os = \"linux\""))
        .then_some(&block.block)
    }

    // Follow only the actual result closure and unconditional Linux blocks.
    // A counted call hidden under an impossible runtime condition is not a
    // production check, and dropping its error is not a successful check.
    fn result_body(body: &syn::Block) -> Option<&syn::Block> {
        for statement in &body.stmts {
            if let Some(body) = linux_body(statement) {
                if let Some(result) = result_body(body) {
                    return Some(result);
                }
            } else if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result")
                && let Some(initializer) = &local.init
                && let syn::Expr::Call(call) = &*initializer.expr
                && let syn::Expr::Paren(parenthesized) = &*call.func
                && let syn::Expr::Closure(closure) = &*parenthesized.expr
                && let syn::Expr::Block(result) = &*closure.body
            {
                return Some(&result.block);
            }
        }
        None
    }

    fn direct_retained_check(body: &syn::Block, owner: &[&str], clock: &[&str]) -> usize {
        body.stmts
            .iter()
            .map(|statement| {
                if let Some(body) = linux_body(statement) {
                    return direct_retained_check(body, owner, clock);
                }
                let syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_)) = statement else {
                    return 0;
                };
                let syn::Expr::MethodCall(call) = &*attempt.expr else {
                    return 0;
                };
                usize::from(
                    call.method == "check"
                        && fields(&call.receiver, owner)
                        && call.args.len() == 1
                        && matches!(&call.args[0], syn::Expr::Reference(reference)
                            if reference.mutability.is_some() && fields(&reference.expr, clock)),
                )
            })
            .sum()
    }

    fn retained_check_runs(function: &syn::ImplItemFn, owner: &[&str], clock: &[&str]) -> bool {
        #[derive(Default)]
        struct EarlyReturn(bool);
        impl<'ast> Visit<'ast> for EarlyReturn {
            fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
                self.0 = true;
            }
        }
        let Some(body) = result_body(&function.block) else {
            return false;
        };
        let mut early = EarlyReturn::default();
        early.visit_block(body);
        !early.0 && direct_retained_check(body, owner, clock) == 1
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
    let mut begin_runs = false;
    let mut check_runs = false;
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
                begin_runs =
                    retained_check_runs(&function, &["self", "current"], &["authentication"]);
                assert!(begin.replace(calls).is_none());
            } else if owner == "EnrolledRoleStage" && function.sig.ident == "check" {
                check_runs = retained_check_runs(
                    &function,
                    &["self", "owner", "current"],
                    &["self", "acquisition"],
                );
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
    ) && begin_runs
        && check_runs
        && matches!(
            begin,
            Some(Calls {
                captures: 0,
                owner_checks: 1,
                ..
            })
        )
        && matches!(
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

#[test]
fn enrolled_self_guard_requires_unconditional_fallible_checks_of_the_actual_request() {
    let source = include_str!("owner.rs");
    for call in [
        "self.current.check(&mut authentication)?;",
        "self.owner.current.check(&mut self.acquisition)?;",
    ] {
        for replacement in [
            format!("if false {{ {call} }}"),
            call.replace("?;", ";"),
            call.replace("&mut authentication", "&mut unrelated"),
            call.replace("&mut self.acquisition", "&mut unrelated"),
        ] {
            if replacement == call {
                continue;
            }
            let changed = source.replacen(call, &replacement, 1);
            assert_ne!(changed, source);
            assert!(!enrolled_self_reborrow_shape(&changed));
        }
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

fn actual_read_cap_handoff(source: &str) -> bool {
    fn is_path(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Path(path) if path.path.is_ident(expected))
    }
    fn is_field(expression: &syn::Expr, owner: &str, member: &str) -> bool {
        matches!(expression, syn::Expr::Field(field)
            if is_path(&field.base, owner) && matches!(&field.member, syn::Member::Named(name) if name == member))
    }
    let syntax = syn::parse_file(source).unwrap();
    let Some(function) = syntax.items.iter().find_map(|item| {
        let syn::Item::Impl(implementation) = item else { return None; };
        if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident("SameEnrolledOwner")) { return None; }
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "meet_current_read_view" => Some(function),
            _ => None,
        })
    }) else { return false; };
    let Some(syn::Stmt::Local(result)) = function.block.stmts.first() else {
        return false;
    };
    let Some(initializer) = &result.init else {
        return false;
    };
    let syn::Expr::Call(invocation) = &*initializer.expr else {
        return false;
    };
    let syn::Expr::Paren(parenthesized) = &*invocation.func else {
        return false;
    };
    let syn::Expr::Closure(closure) = &*parenthesized.expr else {
        return false;
    };
    let syn::Expr::Block(body) = &*closure.body else {
        return false;
    };
    if body.block.stmts.len() != 4 {
        return false;
    }
    for (index, method, receiver, argument) in [
        (0, "check", "self", Some("stage")),
        (1, "require_purpose", "stage", Some("CURRENT_PURPOSE")),
        (2, "exchange_current_views", "acquisition", Some("actual")),
        (3, "check", "stage", None),
    ] {
        let syn::Stmt::Expr(expression, semicolon) = &body.block.stmts[index] else {
            return false;
        };
        let expression = if index < 3 {
            let syn::Expr::Try(attempt) = expression else {
                return false;
            };
            if semicolon.is_none() {
                return false;
            }
            &*attempt.expr
        } else {
            if semicolon.is_some() {
                return false;
            }
            expression
        };
        let syn::Expr::MethodCall(call) = expression else {
            return false;
        };
        let correct_receiver = if index == 2 {
            is_field(&call.receiver, "stage", "acquisition")
        } else {
            is_path(&call.receiver, receiver)
        };
        if call.method != method
            || !correct_receiver
            || match argument {
                Some("CURRENT_PURPOSE") => {
                    call.args.len() != 1
                        || !matches!(&call.args[0], syn::Expr::Path(path)
                    if path.path.segments.iter().map(|segment|segment.ident.to_string()).collect::<Vec<_>>() == ["StagePurpose", "CurrentRole"])
                }
                Some(argument) => call.args.len() != 1 || !is_path(&call.args[0], argument),
                None => !call.args.is_empty(),
            }
        {
            return false;
        }
    }
    let Some(syn::Stmt::Expr(syn::Expr::If(failed), _)) = function.block.stmts.get(1) else {
        return false;
    };
    fn field_path(expression: &syn::Expr, names: &[&str]) -> bool {
        match (expression, names.split_last()) {
            (syn::Expr::Path(path), Some((name, []))) => path.path.is_ident(name),
            (syn::Expr::Field(field), Some((name, parent))) => {
                matches!(&field.member, syn::Member::Named(actual) if actual == name)
                    && field_path(&field.base, parent)
            }
            _ => false,
        }
    }
    fn latch(statement: &syn::Stmt, names: &[&str]) -> bool {
        matches!(statement, syn::Stmt::Expr(syn::Expr::Assign(assign), Some(_))
            if field_path(&assign.left,names)
            && matches!(&*assign.right,syn::Expr::Lit(value) if matches!(value.lit,syn::Lit::Bool(syn::LitBool{value:true,..}))))
    }
    fn refuse(statement: &syn::Stmt, names: &[&str]) -> bool {
        matches!(statement,syn::Stmt::Expr(syn::Expr::MethodCall(call),Some(_))
            if call.method=="refuse" && call.args.is_empty() && field_path(&call.receiver,names))
    }
    function.block.stmts.len() == 3
        && matches!(function.block.stmts.last(),Some(syn::Stmt::Expr(value,None)) if is_path(value,"result"))
        && matches!(&*failed.cond, syn::Expr::MethodCall(call) if call.method == "is_err" && is_path(&call.receiver, "result"))
        && failed.then_branch.stmts.len() == 4
        && latch(&failed.then_branch.stmts[0], &["self", "refused"])
        && latch(&failed.then_branch.stmts[1], &["stage", "owner", "refused"])
        && refuse(&failed.then_branch.stmts[2], &["stage", "acquisition"])
        && refuse(&failed.then_branch.stmts[3], &["actual"])
}

#[test]
fn actual_read_handoff_meets_the_real_child_into_the_release_stage_without_a_scalar_clock() {
    assert!(actual_read_cap_handoff(include_str!("owner.rs")));
}

#[test]
fn read_cap_handoff_guard_rejects_skipped_meets_wrong_views_and_lost_refusal() {
    let source = include_str!("owner.rs");
    let (prefix, body) = source.split_once("fn meet_current_read_view").unwrap();
    for (before, after) in [
        ("self.check(stage)?;", "let _ = self.check(stage);"),
        (
            "stage.require_purpose(StagePurpose::CurrentRole)?;",
            "stage.check()?;",
        ),
        (
            "stage.acquisition.exchange_current_views(actual)?;",
            "if false { stage.acquisition.exchange_current_views(actual)?; }",
        ),
        (
            "stage.acquisition.exchange_current_views(actual)?;",
            "let _ = stage.acquisition.exchange_current_views(actual);",
        ),
        (
            "stage.acquisition.exchange_current_views(actual)?;",
            "stage.acquisition.exchange_current_views(unrelated)?;",
        ),
        ("stage.check()", "Ok(())"),
        ("self.refused = true;", "self.refused = false;"),
        (
            "stage.owner.refused = true;",
            "stage.owner.refused = false;",
        ),
        ("stage.acquisition.refuse();", ""),
        ("actual.refuse();", ""),
    ] {
        let changed = body.replacen(before, after, 1);
        assert_ne!(changed, body);
        assert!(!actual_read_cap_handoff(&format!(
            "{prefix}fn meet_current_read_view{changed}"
        )));
    }
}
