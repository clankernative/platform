//! Generated cryptographic DATA controls only. No real native process, stage,
//! message pidfd, original file, P3 or first-holder owner is constructed here.

use super::*;

// Cryptographic DATA tests alone cannot detect a repeated native observation
// at the caller. Inspect the actual Linux method as well, without constructing
// fake native handles or treating a macOS run as kernel qualification.
fn native_accept_observation_shape(source: &str) -> (usize, usize, usize) {
    use syn::visit::Visit;

    #[derive(Default)]
    struct Calls {
        verifiers: usize,
        checks: usize,
        final_checks: usize,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if matches!(&*node.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "verify_message_then_observe"))
            {
                self.verifiers += 1;
                let syn::Expr::Closure(observe) = &node.args[3] else {
                    panic!("native post-verification observation must be a closed callback");
                };
                let mut final_calls = Calls::default();
                final_calls.visit_expr(&observe.body);
                self.final_checks += final_calls.checks;
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.checks += usize::from(node.method == "check");
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let file = syn::parse_file(source).unwrap();
    let method = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(&*item.self_ty, syn::Type::Path(path)
            if path.path.is_ident("Peer")) =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| &item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "accept_message" => Some(method),
            _ => None,
        })
        .expect("actual native message acceptance");
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    (calls.verifiers, calls.checks, calls.final_checks)
}

#[test]
fn native_accept_caller_has_only_the_post_verification_full_observation() {
    assert_eq!(
        native_accept_observation_shape(include_str!("../storage_peer_native.rs")),
        (1, 1, 1),
    );
}

#[test]
fn native_accept_caller_guard_rejects_restoring_the_pre_verification_check() {
    let source = include_str!("../storage_peer_native.rs");
    let repeated = source.replacen(
        "super::storage_peer_wire::verify_message_then_observe(",
        "self.check(stage, acquisition)?; super::storage_peer_wire::verify_message_then_observe(",
        1,
    );
    assert_ne!(source, repeated);
    assert_ne!(native_accept_observation_shape(&repeated), (1, 1, 1));
}

#[test]
fn current_hello_selects_the_queued_ready_and_exact_request_even_when_validly_signed() {
    let (_, app, key) = fixture(NativeRole::AppHost);
    let initial = Digest::new(b"one retained peer");
    let ready_nonce = Digest::new(b"one controller ready");
    let request = StoragePeerRequest::CurrentServing {
        binding: Digest::new(b"actual consumer"),
    };
    let hello = signed(
        &app,
        &key,
        Body::CurrentHello {
            app: Box::new(app.clone()),
            initial: initial.clone(),
            sequence: 1,
            request: request.clone(),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: ready_nonce.clone(),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    let decoded = decode(&encoded).unwrap();
    decoded.verify(&app).unwrap();
    decoded
        .current_hello(&initial, 1, &ready_nonce, None)
        .unwrap();
    decoded
        .current_hello(&initial, 1, &ready_nonce, Some(&request))
        .unwrap();
    assert!(
        decoded
            .current_hello(&initial, 1, &Digest::new(b"other ready"), None)
            .is_err()
    );
    assert!(
        decoded
            .current_hello(&initial, 2, &ready_nonce, None)
            .is_err()
    );
    assert!(
        decoded
            .current_hello(&Digest::new(b"other original"), 1, &ready_nonce, None)
            .is_err()
    );
    let foreign = StoragePeerRequest::CurrentServing {
        binding: Digest::new(b"another consumer"),
    };
    assert!(
        decoded
            .current_hello(&initial, 1, &ready_nonce, Some(&foreign))
            .is_err()
    );
    let bootstrap = StoragePeerRequest::BootstrapCreate {
        binding: request.binding().clone(),
    };
    let wrong_purpose = signed(
        &app,
        &key,
        Body::CurrentHello {
            app: Box::new(app.clone()),
            initial: initial.clone(),
            sequence: 1,
            request: bootstrap.clone(),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: ready_nonce.clone(),
        },
    );
    assert!(wrong_purpose.verify(&app).is_err());
    assert!(
        wrong_purpose
            .current_hello(&initial, 1, &ready_nonce, None)
            .is_err()
    );
    assert!(
        wrong_purpose
            .current_hello(&initial, 1, &ready_nonce, Some(&bootstrap))
            .is_err()
    );
    let mut missing = serde_json::to_value(&hello).unwrap();
    missing["body"]
        .as_object_mut()
        .unwrap()
        .remove("controller_nonce");
    assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
}

#[test]
fn current_begin_ready_cannot_be_replaced_by_a_later_grant_clock_or_nonce() {
    let (_, controller, key, issuer) = fixture_with_issuer(NativeRole::EpochController);
    let nonce = Digest::new(b"one current ready");
    let initial = Digest::new(b"original peer");
    let ready = signed(
        &controller,
        &key,
        Body::CurrentBeginReady {
            controller: Box::new(controller.clone()),
            initial: initial.clone(),
            sequence: 1,
            nonce: nonce.clone(),
        },
    );
    let bytes = serde_json::to_vec(&ready).unwrap();
    decode(&bytes).unwrap().verify(&controller).unwrap();
    let exchange = CurrentExchange {
        initial,
        sequence: 1,
        request: StoragePeerRequest::CurrentServing {
            binding: Digest::new(b"consumer"),
        },
        app_stage: Digest::new(b"fresh app stage"),
        controller_stage: controller.digest().unwrap(),
        app_nonce: Digest::new(b"fresh app nonce"),
        controller_nonce: nonce.clone(),
    };
    exchange
        .require_begin_ready(&controller, &nonce, &controller)
        .unwrap();
    let mut replacement = controller.clone();
    replacement.stage.data.challenge = Digest::new(b"later role grant");
    replacement.stage.signature = issuer.sign("role-stage", &replacement.stage.data).unwrap();
    assert!(replacement.same_enrollment(&controller));
    assert!(
        exchange
            .require_begin_ready(&controller, &nonce, &replacement)
            .is_err()
    );
    let mut replacement = controller.clone();
    replacement.original.origin_ns += 1;
    assert!(
        exchange
            .require_begin_ready(&controller, &nonce, &replacement)
            .is_err()
    );
    assert!(
        exchange
            .require_begin_ready(&controller, &Digest::new(b"different ready"), &controller)
            .is_err()
    );
    assert!(
        controller
            .require_new_request(&controller.original)
            .is_err()
    );
    let original = serde_json::to_value(&ready).unwrap();
    for path in [
        "/body/controller",
        "/body/controller/stage",
        "/body/controller/original",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = serde_json::json!([]);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    for field in ["initial", "sequence", "nonce"] {
        let mut changed = original.clone();
        changed["body"].as_object_mut().unwrap().remove(field);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1");
    assert!(decode(duplicate.as_bytes()).is_err());
}
use crate::security_epoch::{
    native_enrollment::{
        protocol::{IssuerData, KeyOwner, RuntimeBinding, StageData},
        tests::policy,
    },
    runtime_profile::ContainerFacts,
};
use std::collections::BTreeMap;

fn process(code: Digest, process: u32) -> ProcessData {
    ProcessData {
        process,
        start_ticks: u64::from(process) + 100,
        code,
        boot: "fixture-boot".into(),
        namespaces: BTreeMap::from([("time".into(), (7, 9))]),
    }
}

#[test]
fn app_holder_candidate_keeps_pod_process_and_key_identities_separate() {
    let (_, mut statement, _) = fixture(NativeRole::AppHost);
    assert!(statement.app_holder().is_err()); // fixture's non-UUID Pod is not admitted
    statement.stage.data.runtime.container.pod_uid = "a6b27e63-16d8-4b99-92f6-2437e5b20f43".into();
    let original = statement.app_holder().unwrap();
    let mut changed = statement.clone();
    changed.stage.data.challenge = Digest::new(b"another-grant-challenge");
    assert_eq!(changed.app_holder().unwrap(), original);
    changed.stage.data.process.start_ticks += 1;
    let process = changed.app_holder().unwrap();
    assert_ne!(process.process_incarnation, original.process_incarnation);
    assert_eq!(process.principal, original.principal);
    assert_eq!(process.ephemeral_key, original.ephemeral_key);
    let mut changed = statement.clone();
    changed.stage.data.public_key = KeyOwner::generate().unwrap().public();
    let key = changed.app_holder().unwrap();
    assert_ne!(key.ephemeral_key, original.ephemeral_key);
    assert_eq!(key.principal, original.principal);
    let mut changed = statement.clone();
    changed.stage.data.runtime.container.pod_uid = "b6b27e63-16d8-4b99-92f6-2437e5b20f43".into();
    let pod = changed.app_holder().unwrap();
    assert_ne!(pod.principal, original.principal);
    assert_ne!(pod.process_incarnation, original.process_incarnation);
    statement.stage.data.role = NativeRole::EpochController;
    assert!(statement.app_holder().is_err());
}

fn fixture(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner) {
    let (policy, statement, key, _issuer) = fixture_with_issuer(role);
    (policy, statement, key)
}

fn fixture_with_issuer(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner, KeyOwner) {
    let root = KeyOwner::generate().unwrap();
    let issuer = KeyOwner::generate().unwrap();
    let key = KeyOwner::generate().unwrap();
    let policy = policy(&root);
    let data = IssuerData {
        policy: policy.digest().unwrap(),
        root_version: policy.root.version.clone(),
        nonce: Digest::new(b"fixture-issuer-generation"),
        public_key: issuer.public(),
        process: process(policy.issuer_code.clone(), 70),
        provisioner: process(policy.provisioner_code.clone(), 71),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data).unwrap(),
        data,
    };
    let data = StageData {
        issuer: certificate.digest().unwrap(),
        policy: policy.digest().unwrap(),
        role,
        purpose: StagePurpose::CurrentRole,
        public_key: key.public(),
        challenge: Digest::new(b"fixture-role-challenge"),
        request: Digest::new(b"fixture-role-request"),
        process: process(policy.code(role).clone(), 80),
        runtime: RuntimeBinding {
            container: ContainerFacts {
                pod_name: "app".into(),
                pod_uid: "pod-uid".into(),
                node_name: "node-one".into(),
                container_name: "app".into(),
                container_id: "a".repeat(64),
                image: Digest::new(b"app-image"),
                restart_count: 0,
            },
            node_uid: "node-uid".into(),
            boot: "fixture-boot".into(),
        },
        origin_ns: 100_000_000_000,
        deadline_ns: 105_000_000_000,
    };
    let stage = SignedStage {
        signature: issuer.sign("role-stage", &data).unwrap(),
        data,
    };
    (
        policy,
        StageStatement {
            certificate,
            stage,
            original: OriginalInterval {
                purpose: StagePurpose::CurrentRole,
                domain: Digest::new(b"actual-domain-would-come-from-native-stage"),
                origin_ns: 100_000_000_000,
                deadline_ns: 105_000_000_000,
            },
        },
        key,
        issuer,
    )
}

fn signed(statement: &StageStatement, key: &KeyOwner, body: Body) -> Message {
    let sender = statement.digest().unwrap();
    let signature = key
        .sign("initial-storage-message", &(&sender, &body))
        .unwrap();
    Message {
        sender,
        body,
        signature,
    }
}

#[test]
fn received_message_has_exactly_one_final_observation_after_valid_signature() {
    let (_, statement, key) = fixture(NativeRole::AppHost);
    let message = signed(
        &statement,
        &key,
        Body::CurrentAck {
            exchange: Digest::new(b"one exact exchange"),
        },
    );
    struct Owner {
        statement: StageStatement,
        observations: u32,
    }
    let original = statement.original.clone();
    let mut owner = Owner {
        statement,
        observations: 0,
    };
    verify_message_then_observe(
        &mut owner,
        &message,
        |owner| &owner.statement,
        |owner| {
            owner.observations += 1;
            assert!(owner.statement.original == original);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(owner.observations, 1);
}

#[test]
fn invalid_message_never_reaches_a_successful_native_observation() {
    let (_, mut statement, key) = fixture(NativeRole::AppHost);
    let mut message = signed(
        &statement,
        &key,
        Body::CurrentAck {
            exchange: Digest::new(b"one exact exchange"),
        },
    );
    message.signature = "invalid".into();
    let mut observed = false;
    let result = verify_message_then_observe(
        &mut statement,
        &message,
        |statement| statement,
        |_| {
            observed = true;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!observed);
}

#[test]
fn every_valid_message_reobserves_and_preserves_the_actual_observation_refusal() {
    let (_, mut statement, key) = fixture(NativeRole::AppHost);
    let message = signed(
        &statement,
        &key,
        Body::CurrentAck {
            exchange: Digest::new(b"one exact exchange"),
        },
    );
    let mut observations = 0;
    for allowed in [true, false, false] {
        let result = verify_message_then_observe(
            &mut statement,
            &message,
            |statement| statement,
            |_| {
                observations += 1;
                anyhow::ensure!(allowed, "actual sender observation refused");
                Ok(())
            },
        );
        if allowed {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                "actual sender observation refused"
            );
        }
    }
    assert_eq!(
        observations, 3,
        "a prior observation is never a cached grant"
    );
}

#[test]
fn stage_data_requires_the_same_issuer_role_process_and_live_original_interval() {
    let (policy, stage, _key) = fixture(NativeRole::AppHost);
    let now = Duration::from_secs(102);
    stage
        .validate(
            &policy,
            &stage.certificate,
            NativeRole::AppHost,
            &stage.stage.data.process,
            now,
            StagePurpose::CurrentRole,
        )
        .unwrap();
    for role in [NativeRole::EpochController, NativeRole::SecurityShell] {
        assert!(
            stage
                .validate(
                    &policy,
                    &stage.certificate,
                    role,
                    &stage.stage.data.process,
                    now,
                    StagePurpose::CurrentRole,
                )
                .is_err()
        );
    }
    let mut process = stage.stage.data.process.clone();
    process.start_ticks += 1;
    assert!(
        stage
            .validate(
                &policy,
                &stage.certificate,
                NativeRole::AppHost,
                &process,
                now,
                StagePurpose::CurrentRole,
            )
            .is_err()
    );
    let mut issuer = stage.certificate.clone();
    issuer.data.nonce = Digest::new(b"replacement-issuer");
    assert!(
        stage
            .validate(
                &policy,
                &issuer,
                NativeRole::AppHost,
                &stage.stage.data.process,
                now,
                StagePurpose::CurrentRole,
            )
            .is_err()
    );
    for time in [Duration::from_secs(99), Duration::from_secs(105)] {
        assert!(
            stage
                .validate(
                    &policy,
                    &stage.certificate,
                    NativeRole::AppHost,
                    &stage.stage.data.process,
                    time,
                    StagePurpose::CurrentRole,
                )
                .is_err()
        );
    }
    let mut changed = stage.clone();
    changed.original.deadline_ns += 1;
    assert!(
        changed
            .validate(
                &policy,
                &stage.certificate,
                NativeRole::AppHost,
                &stage.stage.data.process,
                now,
                StagePurpose::CurrentRole,
            )
            .is_err()
    );
    let mut changed = stage.clone();
    changed.stage.data.public_key = KeyOwner::generate().unwrap().public();
    assert!(
        changed
            .validate(
                &policy,
                &stage.certificate,
                NativeRole::AppHost,
                &stage.stage.data.process,
                now,
                StagePurpose::CurrentRole,
            )
            .is_err()
    );
}

#[test]
fn storage_messages_bind_original_stage_nonce_step_and_projection() {
    let (_policy, stage, key) = initial_fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::Hello {
            app: Box::new(stage.clone()),
            nonce: Digest::new(b"app-nonce"),
            controller_nonce: Digest::new(b"controller-ready-nonce"),
        },
    );
    hello.verify(&stage).unwrap();
    let mut encoded = serde_json::to_value(&hello).unwrap();
    encoded["body"]["nonce"] = serde_json::to_value(Digest::new(b"other-nonce")).unwrap();
    let changed: Message = crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed.verify(&stage).is_err());
    let mut original = stage.clone();
    original.original.domain = Digest::new(b"replacement-acquisition");
    assert!(hello.verify(&original).is_err());
    let confirm = signed(
        &stage,
        &key,
        Body::Confirm {
            exchange: Digest::new(b"exchange"),
            projection: Digest::new(b"actual-file"),
        },
    );
    confirm.verify(&stage).unwrap();
    let mut encoded = serde_json::to_value(&confirm).unwrap();
    encoded["body"]["projection"] = serde_json::to_value(Digest::new(b"foreign-file")).unwrap();
    let changed: Message = crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed.verify(&stage).is_err());
    let wrong_role = signed(
        &stage,
        &key,
        Body::Complete {
            exchange: Digest::new(b"exchange"),
        },
    );
    assert!(wrong_role.verify(&stage).is_err());
    let mut encoded = serde_json::to_value(&confirm).unwrap();
    encoded["body"] = serde_json::json!({"step":"accepted","exchange":Digest::new(b"exchange")});
    let changed: Message = crate::json::decode(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(changed.verify(&stage).is_err());
}

#[test]
fn initial_ready_requires_a_controller_signature_and_closed_record_shape() {
    let (_, controller, key) = initial_fixture(NativeRole::EpochController);
    let (_, app, _) = initial_fixture(NativeRole::AppHost);
    let ready = signed(
        &controller,
        &key,
        Body::InitialReady {
            controller: Box::new(controller.clone()),
            nonce: Digest::new(b"one ready nonce"),
        },
    );
    let encoded = serde_json::to_vec(&ready).unwrap();
    decode(&encoded).unwrap().verify(&controller).unwrap();
    assert!(decode(&encoded).unwrap().verify(&app).is_err());
    let original = serde_json::to_value(&ready).unwrap();
    for path in [
        "/body/controller",
        "/body/controller/stage",
        "/body/controller/original",
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = serde_json::json!([]);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    for replacement in [serde_json::Value::Null, serde_json::json!([])] {
        let mut changed = original.clone();
        changed["body"]["nonce"] = replacement;
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut changed = original.clone();
    changed["body"].as_object_mut().unwrap().remove("nonce");
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = original.clone();
    changed["body"]["unknown"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = original;
    changed["body"]["nonce"] = serde_json::to_value(Digest::new(b"tampered ready")).unwrap();
    assert!(
        decode(&serde_json::to_vec(&changed).unwrap())
            .unwrap()
            .verify(&controller)
            .is_err()
    );
    let duplicate = String::from_utf8(encoded).unwrap().replace(
        "\"step\":\"initial_ready\"",
        &format!(
            "\"step\":\"initial_ready\",\"nonce\":{}",
            serde_json::to_string(&Digest::new(b"duplicate")).unwrap()
        ),
    );
    assert!(decode(duplicate.as_bytes()).is_err());
}

#[test]
fn initial_hello_must_echo_the_ready_nonce_even_with_a_valid_app_signature() {
    let (_, app, key) = initial_fixture(NativeRole::AppHost);
    let nonce = Digest::new(b"controller ready");
    let hello = signed(
        &app,
        &key,
        Body::Hello {
            app: Box::new(app.clone()),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: nonce.clone(),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    let decoded = decode(&encoded).unwrap();
    decoded.verify(&app).unwrap();
    let (selected, _) = decoded.initial_hello(&nonce).unwrap();
    assert!(*selected == app);
    assert!(
        decoded
            .initial_hello(&Digest::new(b"different ready"))
            .is_err()
    );
    let wrong = signed(
        &app,
        &key,
        Body::Hello {
            app: Box::new(app.clone()),
            nonce: Digest::new(b"app nonce"),
            controller_nonce: Digest::new(b"other controller ready"),
        },
    );
    wrong.verify(&app).unwrap();
    assert!(wrong.initial_hello(&nonce).is_err());
    let mut missing = serde_json::to_value(&hello).unwrap();
    missing["body"]
        .as_object_mut()
        .unwrap()
        .remove("controller_nonce");
    assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    let other = signed(
        &app,
        &key,
        Body::Confirm {
            exchange: Digest::new(b"not hello"),
            projection: Digest::new(b"no projection"),
        },
    );
    assert!(other.initial_hello(&nonce).is_err());
}

#[test]
fn first_offer_cannot_replace_the_ready_stage_clock_or_nonce() {
    let (_, ready, _, issuer) = initial_fixture_with_issuer(NativeRole::EpochController);
    let nonce = Digest::new(b"controller ready nonce");
    let exchange = Exchange {
        app_stage: Digest::new(b"app stage"),
        controller_stage: ready.digest().unwrap(),
        app_nonce: Digest::new(b"app nonce"),
        controller_nonce: nonce.clone(),
        projection: Digest::new(b"initial image"),
    };
    exchange
        .require_initial_ready(&ready, &nonce, &ready)
        .unwrap();
    let mut replacement = ready.clone();
    replacement.stage.data.challenge = Digest::new(b"later issuer grant");
    replacement.stage.signature = issuer.sign("role-stage", &replacement.stage.data).unwrap();
    assert!(ready.same_enrollment(&replacement));
    assert!(
        exchange
            .require_initial_ready(&ready, &nonce, &replacement)
            .is_err()
    );
    let mut changed_clock = ready.clone();
    changed_clock.original.origin_ns += 1;
    assert!(
        exchange
            .require_initial_ready(&ready, &nonce, &changed_clock)
            .is_err()
    );
    let mut changed = exchange.clone();
    changed.controller_nonce = Digest::new(b"other ready nonce");
    assert!(
        changed
            .require_initial_ready(&ready, &nonce, &ready)
            .is_err()
    );
    let mut changed = exchange;
    changed.controller_stage = replacement.digest().unwrap();
    assert!(
        changed
            .require_initial_ready(&ready, &nonce, &ready)
            .is_err()
    );
}

#[test]
fn transcript_changes_do_not_alias_another_exchange() {
    let exchange = Exchange {
        app_stage: Digest::new(b"app"),
        controller_stage: Digest::new(b"controller"),
        app_nonce: Digest::new(b"app-nonce"),
        controller_nonce: Digest::new(b"controller-nonce"),
        projection: Digest::new(b"projection"),
    };
    for field in [
        "app_stage",
        "controller_stage",
        "app_nonce",
        "controller_nonce",
        "projection",
    ] {
        let mut value = serde_json::to_value(&exchange).unwrap();
        value[field] = serde_json::to_value(Digest::new(b"different")).unwrap();
        let changed: Exchange = crate::json::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_ne!(exchange.digest().unwrap(), changed.digest().unwrap());
    }
}

#[test]
fn storage_wire_refuses_duplicate_unknown_array_and_oversized_records() {
    let (_policy, stage, key) = initial_fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::Hello {
            app: Box::new(stage.clone()),
            nonce: Digest::new(b"nonce"),
            controller_nonce: Digest::new(b"controller-ready-nonce"),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    decode(&encoded).unwrap().verify(&stage).unwrap();
    assert!(decode(br#"{"sender":"x","sender":"y","body":{},"signature":"x"}"#).is_err());
    assert!(decode(&vec![b' '; protocol::MAX_PACKET + 1]).is_err());
    let original = serde_json::to_value(&hello).unwrap();
    for path in [
        "/body",
        "/body/app",
        "/body/app/certificate",
        "/body/app/certificate/data",
        "/body/app/stage",
        "/body/app/stage/data",
        "/body/app/stage/data/runtime",
        "/body/app/original",
    ] {
        let mut changed = original.clone();
        let record = changed.pointer(path).unwrap().as_object().unwrap();
        let sequence = record.values().cloned().collect::<Vec<_>>();
        *changed.pointer_mut(path).unwrap() = serde_json::Value::Array(sequence);
        assert!(
            decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted sequence at {path}"
        );
    }
    let mut changed = original;
    changed["body"]["app"]["original"]["unexpected"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
}

#[test]
fn privileged_controller_attestation_is_role_and_actual_kernel_sender_bound_data() {
    let (policy, controller, key) = initial_fixture(NativeRole::EpochController);
    let now = Duration::from_secs(102);
    controller
        .validate_attested_controller(
            &policy,
            &controller.certificate,
            controller.stage.data.process.process,
            now,
            StagePurpose::InitialFirstHolder,
        )
        .unwrap();
    assert!(
        controller
            .validate_attested_controller(
                &policy,
                &controller.certificate,
                controller.stage.data.process.process + 1,
                now,
                StagePurpose::InitialFirstHolder,
            )
            .is_err()
    );
    let complete = signed(
        &controller,
        &key,
        Body::Complete {
            exchange: Digest::new(b"exchange"),
        },
    );
    complete.verify(&controller).unwrap();
    let (policy, app, _key) = initial_fixture(NativeRole::AppHost);
    assert!(
        app.validate_attested_controller(
            &policy,
            &app.certificate,
            app.stage.data.process.process,
            now,
            StagePurpose::InitialFirstHolder,
        )
        .is_err()
    );
}

#[test]
fn repeated_exchange_data_keeps_the_http_original_and_rejects_replay_or_widening() {
    let (_, admitted, key, _) = fixture_with_issuer(NativeRole::AppHost);
    let initial = Digest::new(b"actual-initial-exchange-required-by-native-factory");
    let request = StoragePeerRequest::CurrentServing {
        binding: Digest::new(b"same-http-operation"),
    };
    let mut previous = admitted.original.clone();
    for sequence in 1..=2 {
        let mut current = admitted.clone();
        current.original.deadline_ns = previous.deadline_ns - 1;
        current.require_request_continuity(&previous).unwrap();
        current
            .validate_request(
                &admitted,
                Duration::from_secs(102),
                StagePurpose::CurrentRole,
            )
            .unwrap();
        assert_eq!(current.original.domain, admitted.original.domain);
        assert_eq!(current.original.origin_ns, admitted.original.origin_ns);
        let ready_nonce = Digest::of(&("new-controller-nonce", sequence)).unwrap();
        let hello = signed(
            &current,
            &key,
            Body::CurrentHello {
                app: Box::new(current.clone()),
                initial: initial.clone(),
                sequence,
                request: request.clone(),
                nonce: Digest::of(&("new-app-nonce", sequence)).unwrap(),
                controller_nonce: ready_nonce.clone(),
            },
        );
        hello.verify(&current).unwrap();
        hello
            .current_hello(&initial, sequence, &ready_nonce, Some(&request))
            .unwrap();
        assert!(
            hello
                .current_hello(&initial, sequence + 1, &ready_nonce, Some(&request))
                .is_err()
        );
        assert!(
            hello
                .current_hello(
                    &initial,
                    sequence,
                    &Digest::new(b"stale-ready"),
                    Some(&request)
                )
                .is_err()
        );
        for change in 0..4 {
            let mut wrong = current.clone();
            match change {
                0 => wrong.original.origin_ns += 1,
                1 => wrong.original.domain = Digest::new(b"same-origin-new-envelope"),
                2 => wrong.original.deadline_ns = previous.deadline_ns + 1,
                _ => wrong.original.purpose = StagePurpose::StorageBootstrap,
            }
            assert!(
                wrong.require_request_continuity(&previous).is_err(),
                "case {change}"
            );
        }
        assert!(
            current
                .validate_request(
                    &admitted,
                    Duration::from_secs(105),
                    StagePurpose::CurrentRole
                )
                .is_err()
        );
        previous = current.original;
    }
    // These are signed DATA controls; actual retained Peer, sequence state,
    // kernel receipts, live clock and fresh counter checks are still mandatory.
}

#[test]
fn cold_admission_still_expires_and_fresh_requests_bind_historical_admission_data() {
    let (policy, old, key, _) = fixture_with_issuer(NativeRole::AppHost);
    let mut fresh = old.clone();
    fresh.original.origin_ns += 10_000_000_000;
    fresh.original.deadline_ns += 10_000_000_000;
    fresh.original.domain = Digest::new(b"new-original-acquisition");
    assert!(old.same_enrollment(&fresh));
    // Merely replacing a domain does not make a later bounded request.
    let mut rewrapped = old.clone();
    rewrapped.original.domain = Digest::new(b"different-envelope-only");
    assert_ne!(old.digest().unwrap(), rewrapped.digest().unwrap());
    assert_eq!(old.stage, fresh.stage);
    assert!(old.require_new_request(&old.original).is_err());
    assert!(rewrapped.require_new_request(&old.original).is_err());
    fresh.require_new_request(&old.original).unwrap();
    assert!(fresh.require_new_request(&fresh.original).is_err());
    let now = Duration::from_secs(112);
    assert!(
        old.validate(
            &policy,
            &old.certificate,
            NativeRole::AppHost,
            &old.stage.data.process,
            now,
            StagePurpose::CurrentRole,
        )
        .is_err()
    );
    assert!(
        fresh
            .validate(
                &policy,
                &old.certificate,
                NativeRole::AppHost,
                &old.stage.data.process,
                now,
                StagePurpose::CurrentRole,
            )
            .is_err()
    );
    // This is DATA validation, not a native owner or permission factory.
    // Production additionally borrows the actual admitted Peer and receives
    // this request's original kernel packet handle before it can escape.
    fresh
        .validate_request(&old, now, StagePurpose::CurrentRole)
        .unwrap();
    let mut wrong = fresh.clone();
    wrong.stage.signature.push('x');
    assert!(
        wrong
            .validate_request(&old, now, StagePurpose::CurrentRole)
            .is_err()
    );
    let mut wrong = fresh.clone();
    wrong.original.purpose = StagePurpose::StorageBootstrap;
    assert!(
        wrong
            .validate_request(&old, now, StagePurpose::CurrentRole)
            .is_err()
    );
    assert!(
        fresh
            .validate_request(&old, Duration::from_secs(115), StagePurpose::CurrentRole)
            .is_err()
    );
    let hello = signed(
        &fresh,
        &key,
        Body::CurrentHello {
            app: Box::new(fresh.clone()),
            initial: Digest::new(b"original-known-exchange"),
            sequence: 1,
            request: StoragePeerRequest::CurrentServing {
                binding: Digest::new(b"exact-request"),
            },
            nonce: Digest::new(b"fresh-app-nonce"),
            controller_nonce: Digest::new(b"controller-ready"),
        },
    );
    hello.verify(&fresh).unwrap();
    assert!(hello.verify(&old).is_err());
    for path in [
        "/certificate/data/nonce",
        "/stage/data/public_key",
        "/stage/data/process/code",
        "/stage/data/runtime/container/image",
    ] {
        let mut changed = serde_json::to_value(&fresh).unwrap();
        *changed.pointer_mut(path).unwrap() =
            serde_json::to_value(Digest::new(b"changed")).unwrap();
        if path.ends_with("public_key") {
            *changed.pointer_mut(path).unwrap() =
                serde_json::json!(KeyOwner::generate().unwrap().public());
        }
        let changed: StageStatement =
            crate::json::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(!old.same_enrollment(&changed), "identity changed at {path}");
    }
}

#[test]
fn current_exchange_binds_sequence_purpose_request_and_both_fresh_intervals() {
    let exchange = CurrentExchange {
        initial: Digest::new(b"initial"),
        sequence: 1,
        request: StoragePeerRequest::CurrentServing {
            binding: Digest::new(b"intent-action-body"),
        },
        app_stage: Digest::new(b"current-app-stage"),
        controller_stage: Digest::new(b"current-controller-stage"),
        app_nonce: Digest::new(b"current-app-nonce"),
        controller_nonce: Digest::new(b"current-controller-nonce"),
    };
    for path in [
        "/initial",
        "/app_stage",
        "/controller_stage",
        "/app_nonce",
        "/controller_nonce",
        "/request/binding",
        "/request/purpose",
        "/sequence",
    ] {
        let mut changed = serde_json::to_value(&exchange).unwrap();
        *changed.pointer_mut(path).unwrap() = match path {
            "/sequence" => serde_json::json!(2),
            "/request/purpose" => serde_json::json!("bootstrap_complete"),
            _ => serde_json::to_value(Digest::new(b"changed")).unwrap(),
        };
        let changed: CurrentExchange =
            crate::json::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_ne!(
            exchange.digest().unwrap(),
            changed.digest().unwrap(),
            "unbound {path}"
        );
    }
}

#[test]
fn current_wire_stays_closed_and_rejects_nested_arrays_and_unknown_fields() {
    let (_policy, stage, key) = bootstrap_fixture(NativeRole::AppHost);
    let hello = signed(
        &stage,
        &key,
        Body::CurrentHello {
            app: Box::new(stage.clone()),
            initial: Digest::new(b"initial"),
            sequence: 1,
            request: StoragePeerRequest::BootstrapCreate {
                binding: Digest::new(b"request"),
            },
            nonce: Digest::new(b"nonce"),
            controller_nonce: Digest::new(b"controller-ready"),
        },
    );
    let encoded = serde_json::to_vec(&hello).unwrap();
    decode(&encoded).unwrap().verify(&stage).unwrap();
    for path in [
        "/body/request",
        "/body/app/stage/data",
        "/body/app/original",
    ] {
        let mut changed = serde_json::to_value(&hello).unwrap();
        let values = changed
            .pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        *changed.pointer_mut(path).unwrap() = serde_json::Value::Array(values);
        assert!(
            decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted array {path}"
        );
    }
    let mut changed = serde_json::to_value(&hello).unwrap();
    changed["body"]["request"]["extra"] = serde_json::json!(true);
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut changed = serde_json::to_value(&hello).unwrap();
    changed["body"]["sequence"] = serde_json::json!("1");
    assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
}

#[test]
fn phase_result_consumption_and_release_require_the_exact_signed_transcript() {
    let (_, controller, controller_key) = fixture(NativeRole::EpochController);
    let (_, app, app_key) = fixture(NativeRole::AppHost);
    let exchange = Digest::new(b"this-exact-current-native-exchange");
    let foreign = Digest::new(b"other-executor-or-exchange");
    let cases = [
        (
            Body::CurrentResult {
                exchange: exchange.clone(),
            },
            CompletionKind::Result,
            &controller,
            &controller_key,
        ),
        (
            Body::CurrentConsumed {
                exchange: exchange.clone(),
            },
            CompletionKind::Consumed,
            &app,
            &app_key,
        ),
        (
            Body::CurrentReleased {
                exchange: exchange.clone(),
            },
            CompletionKind::Released,
            &controller,
            &controller_key,
        ),
    ];
    for (body, kind, sender, key) in cases {
        let message = signed(sender, key, body);
        let encoded = serde_json::to_vec(&message).unwrap();
        let mut message = decode(&encoded).unwrap();
        message.verify(sender).unwrap();
        assert!(message.body.matches_completion(&exchange, kind));
        assert!(!message.body.matches_completion(&foreign, kind));
        for other in [
            CompletionKind::Result,
            CompletionKind::Consumed,
            CompletionKind::Released,
        ] {
            let expected = matches!(
                (&message.body, other),
                (Body::CurrentResult { .. }, CompletionKind::Result)
                    | (Body::CurrentConsumed { .. }, CompletionKind::Consumed)
                    | (Body::CurrentReleased { .. }, CompletionKind::Released)
            );
            assert_eq!(message.body.matches_completion(&exchange, other), expected);
        }
        for (field, value) in [
            ("unexpected", serde_json::json!(true)),
            ("exchange", serde_json::Value::Null),
            ("step", serde_json::json!("current_unknown")),
        ] {
            let mut changed = serde_json::to_value(&message).unwrap();
            changed["body"][field] = value;
            assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut missing = serde_json::to_value(&message).unwrap();
        missing["body"].as_object_mut().unwrap().remove("exchange");
        assert!(decode(&serde_json::to_vec(&missing).unwrap()).is_err());
        let exchange_json = serde_json::to_string(&exchange).unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        let duplicate = encoded.replacen(
            &format!("\"exchange\":{exchange_json}"),
            &format!("\"exchange\":{exchange_json},\"exchange\":{exchange_json}"),
            1,
        );
        assert_ne!(duplicate, encoded);
        assert!(decode(duplicate.as_bytes()).is_err());
        match &mut message.body {
            Body::CurrentResult { exchange }
            | Body::CurrentConsumed { exchange }
            | Body::CurrentReleased { exchange } => *exchange = foreign.clone(),
            _ => unreachable!(),
        }
        assert!(message.verify(sender).is_err());
    }
    let handshake = Body::CurrentReady {
        exchange: exchange.clone(),
    };
    for kind in [
        CompletionKind::Result,
        CompletionKind::Consumed,
        CompletionKind::Released,
    ] {
        assert!(!handshake.matches_completion(&exchange, kind));
    }
    assert!(
        signed(
            &app,
            &app_key,
            Body::CurrentResult {
                exchange: exchange.clone()
            }
        )
        .verify(&app)
        .is_err()
    );
    assert!(
        signed(
            &controller,
            &controller_key,
            Body::CurrentConsumed { exchange }
        )
        .verify(&controller)
        .is_err()
    );
}

fn bootstrap_fixture(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner) {
    let (policy, mut statement, key, issuer) = fixture_with_issuer(role);
    statement.stage.data.purpose = StagePurpose::StorageBootstrap;
    statement.original.purpose = StagePurpose::StorageBootstrap;
    statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
    (policy, statement, key)
}

#[test]
fn bootstrap_request_rejects_valid_ordinary_grant_even_when_both_are_short() {
    for purpose in [
        StoragePeerPurpose::BootstrapCreate,
        StoragePeerPurpose::BootstrapComplete,
    ] {
        let (policy, current, key, issuer) = fixture_with_issuer(NativeRole::AppHost);
        let mut bootstrap = current.clone();
        bootstrap.stage.data.purpose = StagePurpose::StorageBootstrap;
        bootstrap.original.purpose = StagePurpose::StorageBootstrap;
        bootstrap.stage.signature = issuer.sign("role-stage", &bootstrap.stage.data).unwrap();
        bootstrap
            .validate(
                &policy,
                &bootstrap.certificate,
                NativeRole::AppHost,
                &bootstrap.stage.data.process,
                Duration::from_secs(102),
                StagePurpose::StorageBootstrap,
            )
            .unwrap();
        let request =
            StoragePeerRequest::operation(purpose, Digest::new(b"fixed-bootstrap-request"))
                .unwrap();
        let nonce = Digest::new(b"ready");
        let initial = Digest::new(b"initial-peer");
        let body = |statement: &StageStatement| Body::CurrentHello {
            app: Box::new(statement.clone()),
            initial: initial.clone(),
            sequence: 1,
            request: request.clone(),
            nonce: Digest::new(b"app"),
            controller_nonce: nonce.clone(),
        };
        let correct = signed(&bootstrap, &key, body(&bootstrap));
        correct.verify(&bootstrap).unwrap();
        correct
            .current_hello(&initial, 1, &nonce, Some(&request))
            .unwrap();
        assert!(correct.verify(&current).is_err());
        let wrong = signed(&current, &key, body(&current));
        assert!(wrong.verify(&current).is_err());
        assert!(
            wrong
                .current_hello(&initial, 1, &nonce, Some(&request))
                .is_err()
        );
    }
}

#[test]
fn every_current_completion_binds_actual_stage_purpose_and_excludes_metadata() {
    for (role, completion) in [
        (NativeRole::EpochController, CompletionKind::Result),
        (NativeRole::AppHost, CompletionKind::Consumed),
        (NativeRole::EpochController, CompletionKind::Released),
    ] {
        let (_, ordinary, key, issuer) = fixture_with_issuer(role);
        for purpose in [
            StagePurpose::CurrentRole,
            StagePurpose::StorageBootstrap,
            StagePurpose::InitialFirstHolder,
            StagePurpose::StorageMetadataObservation,
        ] {
            let mut statement = ordinary.clone();
            statement.stage.data.purpose = purpose;
            statement.original.purpose = purpose;
            statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
            let exchange = Digest::new(b"exact-purpose-exchange");
            let body = match completion {
                CompletionKind::Result => Body::CurrentResult {
                    exchange: exchange.clone(),
                },
                CompletionKind::Consumed => Body::CurrentConsumed {
                    exchange: exchange.clone(),
                },
                CompletionKind::Released => Body::CurrentReleased {
                    exchange: exchange.clone(),
                },
            };
            let message = signed(&statement, &key, body);
            let permitted = matches!(
                purpose,
                StagePurpose::CurrentRole | StagePurpose::StorageBootstrap
            );
            assert_eq!(message.verify(&statement).is_ok(), permitted);
            if permitted {
                let mut replacement = statement.clone();
                replacement.stage.data.purpose = if purpose == StagePurpose::CurrentRole {
                    StagePurpose::StorageBootstrap
                } else {
                    StagePurpose::CurrentRole
                };
                replacement.stage.signature =
                    issuer.sign("role-stage", &replacement.stage.data).unwrap();
                assert!(message.verify(&replacement).is_err());
                assert!(message.body.matches_completion(&exchange, completion));
            }
        }
    }
}

#[test]
fn metadata_statement_is_not_storage_peer_evidence_even_with_a_valid_short_grant() {
    let (policy, mut statement, _key, issuer) = fixture_with_issuer(NativeRole::EpochController);
    statement.stage.data.purpose = StagePurpose::StorageMetadataObservation;
    statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
    assert!(
        statement
            .validate_attested_controller(
                &policy,
                &statement.certificate,
                statement.stage.data.process.process,
                Duration::from_secs(102),
                StagePurpose::StorageMetadataObservation,
            )
            .is_err()
    );
}

fn initial_fixture(role: NativeRole) -> (EnrollmentPolicy, StageStatement, KeyOwner) {
    let (policy, statement, key, _) = initial_fixture_with_issuer(role);
    (policy, statement, key)
}

fn initial_fixture_with_issuer(
    role: NativeRole,
) -> (EnrollmentPolicy, StageStatement, KeyOwner, KeyOwner) {
    let (policy, mut statement, key, issuer) = fixture_with_issuer(role);
    statement.stage.data.purpose = StagePurpose::InitialFirstHolder;
    statement.original.purpose = StagePurpose::InitialFirstHolder;
    statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
    (policy, statement, key, issuer)
}

#[test]
fn initial_ten_second_grants_never_authorize_current_or_serving_work() {
    use crate::security_epoch::native_clock::INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT;
    use crate::security_epoch::native_enrollment::serving_peer_wire::Statement;
    assert_eq!(StagePurpose::CurrentRole.limit(), Duration::from_secs(5));
    assert_eq!(
        StagePurpose::InitialFirstHolder.limit(),
        INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT
    );
    assert!(
        StagePurpose::InitialFirstHolder
            .require_role(NativeRole::SecurityShell)
            .is_err()
    );
    for role in [NativeRole::AppHost, NativeRole::EpochController] {
        let (policy, mut statement, _, issuer) = initial_fixture_with_issuer(role);
        let deadline = Duration::from_nanos(statement.stage.data.origin_ns)
            + INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT;
        statement.stage.data.deadline_ns = deadline.as_nanos().try_into().unwrap();
        statement.original.deadline_ns = statement.stage.data.deadline_ns;
        statement.stage.signature = issuer.sign("role-stage", &statement.stage.data).unwrap();
        let check = |statement: &StageStatement, now, purpose| {
            statement.validate(
                &policy,
                &statement.certificate,
                role,
                &statement.stage.data.process,
                now,
                purpose,
            )
        };
        check(
            &statement,
            Duration::from_millis(106_300),
            StagePurpose::InitialFirstHolder,
        )
        .unwrap();
        assert!(
            check(
                &statement,
                Duration::from_secs(110),
                StagePurpose::InitialFirstHolder
            )
            .is_err()
        );
        assert!(
            check(
                &statement,
                Duration::from_secs(99),
                StagePurpose::InitialFirstHolder
            )
            .is_err()
        );
        assert!(
            check(
                &statement,
                Duration::from_secs(102),
                StagePurpose::CurrentRole
            )
            .is_err()
        );
        let serving = Statement {
            certificate: statement.certificate.clone(),
            stage: statement.stage.clone(),
            original: statement.original.clone(),
        };
        assert!(
            serving
                .validate(
                    &policy,
                    &statement.certificate,
                    role,
                    statement.stage.data.process.process,
                    Some(&statement.stage.data.process),
                    Duration::from_secs(102)
                )
                .is_err()
        );
        // Even a correctly signed CurrentRole cannot acquire a ten-second span.
        let mut ordinary = statement.clone();
        ordinary.stage.data.purpose = StagePurpose::CurrentRole;
        ordinary.stage.signature = issuer.sign("role-stage", &ordinary.stage.data).unwrap();
        assert!(
            check(
                &ordinary,
                Duration::from_secs(102),
                StagePurpose::CurrentRole
            )
            .is_err()
        );
        let mut over = statement.clone();
        over.stage.data.deadline_ns += 1;
        over.original.deadline_ns += 1;
        over.stage.signature = issuer.sign("role-stage", &over.stage.data).unwrap();
        assert!(
            check(
                &over,
                Duration::from_secs(102),
                StagePurpose::InitialFirstHolder
            )
            .is_err()
        );
        let mut changed = statement.clone();
        changed.stage.data.purpose = StagePurpose::CurrentRole;
        changed.stage.data.deadline_ns = 105_000_000_000;
        changed.original.deadline_ns = 105_000_000_000;
        assert!(
            check(
                &changed,
                Duration::from_secs(102),
                StagePurpose::CurrentRole
            )
            .is_err()
        );
        // A short initial grant still cannot be replayed as ordinary authority.
        let mut short = statement.clone();
        short.stage.data.deadline_ns = 105_000_000_000;
        short.original.deadline_ns = 105_000_000_000;
        short.stage.signature = issuer.sign("role-stage", &short.stage.data).unwrap();
        check(
            &short,
            Duration::from_secs(102),
            StagePurpose::InitialFirstHolder,
        )
        .unwrap();
        assert!(check(&short, Duration::from_secs(102), StagePurpose::CurrentRole).is_err());
    }
}

#[test]
fn signed_storage_messages_cannot_cross_initial_and_current_purposes() {
    let (_, initial, key) = initial_fixture(NativeRole::AppHost);
    let message = signed(
        &initial,
        &key,
        Body::CurrentAck {
            exchange: Digest::new(b"current"),
        },
    );
    assert!(message.verify(&initial).is_err());
    let (_, current, key) = fixture(NativeRole::AppHost);
    let message = signed(
        &current,
        &key,
        Body::Hello {
            app: Box::new(current.clone()),
            nonce: Digest::new(b"app"),
            controller_nonce: Digest::new(b"controller"),
        },
    );
    assert!(message.verify(&current).is_err());
}

// This composition never has an enrolled role, a physical file or native P3.
// Its signed packets and consuming counter contexts are explicit test DATA.
mod activation_histories {
    use super::*;
    use crate::security_epoch::{
        bootstrap,
        firestore::{Port, Sample},
        journal::{CurrentBootstrapExecution, Journal, Purpose},
        kernel::{
            self, AuthorityRecord, Holder, Outcome, Receipt, Request, SentinelRecord, Snapshot,
            Versions,
        },
        native_enrollment::handshake::{Actor, Direction, Observation, Protocol, Transcript},
        seed_core::{Incarnations, OriginalSeedCore},
        storage_authority,
        tests::{self as epoch, lifecycle_provider as provider_data},
    };
    use anyhow::{Context, Result, ensure};
    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json};
    use std::{collections::BTreeMap, path::Path};

    const MAX_EVENTS: usize = 40;
    const MAX_BYTES: u64 = 16 * 1024 * 1024;
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Fault {
        None,
        Signature,
        Role,
        Nonce,
        Projection,
        Process,
        Certificate,
        PacketKind,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum HolderChange {
        Same,
        Key,
        Process,
        Pod,
        Namespace,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Commit {
        Known,
        MalformedAck,
        Rollback,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Event {
        Wire(u8),
        Time(u64),
        Select(HolderChange),
        Send(Commit),
        Finish,
        Historical,
        Reopen,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Control {
        Correct,
        LostAckDidNotApply,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        version: u8,
        source: Digest,
        seed: u64,
        policy: EnrollmentPolicy,
        core: OriginalSeedCore,
        app: StageStatement,
        controller: StageStatement,
        projection: PreparedFileProjection,
        packets: Vec<Vec<u8>>,
        fault: Fault,
        fault_at: u8,
        events: Vec<Event>,
    }
    fn source() -> Result<Digest> {
        Digest::of(&(
            "signed-storage-composition-v1",
            std::env::consts::OS,
            [
                include_str!("tests.rs"),
                include_str!("../storage_peer_wire.rs"),
                include_str!("../handshake.rs"),
                include_str!("../protocol.rs"),
                include_str!("../../bootstrap.rs"),
                include_str!("../../storage_authority/initial.rs"),
                include_str!("../../journal.rs"),
                include_str!("../../kernel.rs"),
                include_str!("../../firestore.rs"),
                include_str!("../../tests.rs"),
                include_str!("../../tests/lifecycle_provider.rs"),
                include_str!("../../../json.rs"),
                include_str!("../policy.rs"),
                include_str!("../tests.rs"),
                include_str!("../../seed_core.rs"),
                include_str!("../../control_slot.rs"),
                include_str!("../../storage_authority/preparation.rs"),
                include_str!("../../../../../../Cargo.lock"),
            ],
        ))
    }
    fn shape(input: &Input) -> Result<()> {
        ensure!(
            input.version == 1
                && input.source == source()?
                && input.packets.len() == 6
                && input
                    .packets
                    .iter()
                    .all(|p| !p.is_empty() && p.len() <= protocol::MAX_PACKET)
                && input.fault_at < 6
                && !input.events.is_empty()
                && input.events.len() <= MAX_EVENTS,
            "signed_storage_history_shape"
        );
        ensure!(
            serde_json::to_vec(input)?.len() <= 128 * 1024
                && input.policy.store == epoch::selection(),
            "signed_storage_fixture_input_bound"
        );
        input
            .core
            .validate(&input.policy.bootstrap, &input.policy.store)?;
        input
            .projection
            .validate_selection(&input.policy.bootstrap, &input.policy.store)?;
        ensure!(
            input.events.iter().all(|e| match e {
                Event::Wire(n) => *n < 6,
                Event::Time(n) => *n <= 110_000_000_000,
                _ => true,
            }),
            "signed_storage_event_bound"
        );
        Ok(())
    }
    fn time(n: u64) -> Duration {
        Duration::from_nanos(n)
    }
    fn altered(mut holder: Holder, change: HolderChange) -> Holder {
        match change {
            HolderChange::Same | HolderChange::Namespace => {}
            HolderChange::Key => holder.ephemeral_key = Digest::new(b"foreign-key"),
            HolderChange::Process => holder.process_incarnation = Digest::new(b"foreign-process"),
            HolderChange::Pod => holder.pod_uid = "b6b27e63-16d8-4b99-92f6-2437e5b20f43".into(),
        };
        holder
    }
    fn fixture(seed: u64, fault: Fault, fault_at: u8, events: Vec<Event>) -> Result<Input> {
        let (policy, mut app, app_key, issuer) = initial_fixture_with_issuer(NativeRole::AppHost);
        app.stage.data.runtime.container.pod_uid = "a6b27e63-16d8-4b99-92f6-2437e5b20f43".into();
        app.original.domain = Digest::new(b"app-original-domain");
        if fault == Fault::Certificate {
            app.certificate.signature = "invalid".into();
            app.stage.data.issuer = app.certificate.digest()?;
        }
        app.stage.signature = issuer.sign("role-stage", &app.stage.data)?;
        let controller_key = KeyOwner::generate()?;
        let mut controller = app.clone();
        controller.stage.data.role = NativeRole::EpochController;
        controller.stage.data.public_key = controller_key.public();
        controller.stage.data.process =
            process(policy.code(NativeRole::EpochController).clone(), 81);
        controller.original.domain = Digest::new(b"controller-original-domain");
        controller.stage.signature = issuer.sign("role-stage", &controller.stage.data)?;
        let core = OriginalSeedCore::new(
            &policy.bootstrap,
            &policy.store,
            Incarnations {
                record: Digest::of(&("history-record", seed))?,
                database: Digest::of(&("history-db", seed))?,
                activation: Digest::of(&("history-activation", seed))?,
            },
        )?;
        let projection: PreparedFileProjection = serde_json::from_value(
            json!({"core":core,"marker":core.marker()?,"image":Digest::of(&("synthetic-image",seed))?,"length":1024,
            "identity":{"device_major":1,"device_minor":2,"inode":3,"mount":4,"uid":10001}}),
        )?;
        let ready = Digest::of(&("ready", seed))?;
        let nonce = Digest::of(&("hello", seed))?;
        let exchange = Exchange {
            app_stage: app.digest()?,
            controller_stage: controller.digest()?,
            app_nonce: nonce.clone(),
            controller_nonce: ready.clone(),
            projection: projection.digest()?,
        };
        let id = exchange.digest()?;
        let mut packets = vec![];
        for n in 0..6 {
            let (statement, key) = if matches!(n, 1 | 3 | 5) {
                (&app, &app_key)
            } else {
                (&controller, &controller_key)
            };
            let body = match n {
                0 => Body::InitialReady {
                    controller: Box::new(controller.clone()),
                    nonce: ready.clone(),
                },
                1 => Body::Hello {
                    app: Box::new(app.clone()),
                    nonce: nonce.clone(),
                    controller_nonce: ready.clone(),
                },
                2 => Body::Offer {
                    controller: Box::new(controller.clone()),
                    exchange: exchange.clone(),
                    projection: Box::new(projection.clone()),
                },
                3 => Body::Confirm {
                    exchange: id.clone(),
                    projection: projection.digest()?,
                },
                4 => Body::Complete {
                    exchange: id.clone(),
                },
                _ => Body::Accepted {
                    exchange: id.clone(),
                },
            };
            let mut message = signed(statement, key, body);
            if n == fault_at {
                match fault {
                    Fault::None | Fault::Certificate => {}
                    Fault::Signature => message.signature = "invalid".into(),
                    Fault::PacketKind => {
                        message.body = Body::Complete {
                            exchange: id.clone(),
                        };
                        message.signature =
                            key.sign("initial-storage-message", &(&message.sender, &message.body))?;
                    }

                    Fault::Role => {
                        let mut wrong = statement.clone();
                        wrong.stage.data.role = if n % 2 == 0 {
                            NativeRole::AppHost
                        } else {
                            NativeRole::EpochController
                        };
                        wrong.stage.signature = issuer.sign("role-stage", &wrong.stage.data)?;
                        message = signed(&wrong, key, message.body);
                    }
                    Fault::Nonce => {
                        if let Body::Hello {
                            controller_nonce, ..
                        } = &mut message.body
                        {
                            *controller_nonce = Digest::new(b"foreign-ready");
                        } else {
                            message.sender = Digest::new(b"foreign-sender");
                        }
                        message.signature =
                            key.sign("initial-storage-message", &(&message.sender, &message.body))?;
                    }
                    Fault::Projection => {
                        if let Body::Offer { exchange, .. } = &mut message.body {
                            exchange.projection = Digest::new(b"foreign-file");
                        } else {
                            message.sender = Digest::new(b"foreign-sender");
                        }
                        message.signature =
                            key.sign("initial-storage-message", &(&message.sender, &message.body))?;
                    }
                    Fault::Process => {
                        let mut wrong = statement.clone();
                        wrong.stage.data.process.start_ticks += 1;
                        wrong.stage.signature = issuer.sign("role-stage", &wrong.stage.data)?;
                        message = signed(&wrong, key, message.body);
                    }
                }
            }
            packets.push(serde_json::to_vec(&message)?);
        }
        Ok(Input {
            version: 1,
            source: source()?,
            seed,
            policy,
            core,
            app,
            controller,
            projection,
            packets,
            fault,
            fault_at,
            events,
        })
    }
    fn create(input: &Input) -> Result<Request> {
        Ok(Request::CreateInitialAuthority {
            bootstrap: input.core.bootstrap()?,
        })
    }
    fn sample(at: u64) -> Sample {
        Sample {
            domain: Digest::new(b"controller-process-clock"),
            elapsed: time(at),
        }
    }
    fn context(
        input: &Input,
        request: &Request,
        snapshot: &Snapshot,
        purpose: Purpose,
    ) -> Result<CurrentBootstrapExecution<'static, 'static>> {
        // Fixed original, never the later action's time. No native owner is created.
        CurrentBootstrapExecution::fixture(
            &input.policy.store,
            request,
            snapshot,
            purpose,
            sample(100_000_000_000),
        )
    }
    fn journal_rows(db: &rusqlite::Connection) -> Result<Value> {
        let mut q=db.prepare("SELECT authority,stage,operation,request_digest,request_json,state,dispatch_count,receipt_json FROM external_epoch_operations ORDER BY stage")?;
        let rows=q.query_map([],|r|Ok(json!({"authority":r.get::<_,String>(0)?,"stage":r.get::<_,String>(1)?,"operation":r.get::<_,String>(2)?,"request_digest":r.get::<_,String>(3)?,"request_json":r.get::<_,String>(4)?,"state":r.get::<_,String>(5)?,"dispatch_count":r.get::<_,i64>(6)?,"receipt_json":r.get::<_,Option<String>>(7)?})))?;
        Ok(Value::Array(rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum SetupStep {
        ReadAbsent,
        CreateJournal,
        AcceptCreate,
        AuthorizeCreate,
        SendCreate,
        ReadPending,
        ReconcileCreate,
        DeriveHolder,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    enum Reply {
        Ok,
        Refused,
        Applied,
        NotApplied,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct State {
        at: u64,
        refused: bool,
        setup_progress: Vec<(SetupStep, bool)>,
        journal_readable: bool,
        position: u8,
        selected: Option<Value>,
        binding: Option<Value>,
        completed_data: bool,
        transcripts: Value,
        provider: Value,
        auxiliary_reads: Vec<Value>,
        journal: Value,
    }
    struct Actual {
        directory: tempfile::TempDir,
        db: rusqlite::Connection,
        provider: epoch::Provider,
        create: Request,
        pending: Option<Snapshot>,
        first: Option<Holder>,
        setup_progress: Vec<(SetupStep, bool)>,
        auxiliary_reads: Vec<Value>,
        candidate: Option<Request>,
        binding: Option<StoragePeerRequest>,
        transcripts: [Transcript; 2],
        at: u64,
        refused: bool,
        position: u8,
        completed: bool,
    }
    impl Actual {
        fn new(input: &Input) -> Result<Self> {
            // Allocate only the disposable adapters first. The fallible protocol
            // prelude below keeps its phase and every available row/call.
            let directory = tempfile::tempdir()?;
            let provider = provider_data::open(&directory.path().join("provider.sqlite"));
            let db = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
            let mut value = Self {
                directory,
                db,
                provider,
                create: create(input)?,
                pending: None,
                first: None,
                setup_progress: vec![],
                auxiliary_reads: vec![],
                candidate: None,
                binding: None,
                transcripts: [
                    Transcript::new(Protocol::InitialStorage, Actor::Controller),
                    Transcript::new(Protocol::InitialStorage, Actor::App),
                ],
                at: 100_000_000_000,
                refused: false,
                position: 0,
                completed: false,
            };
            let setup = (|| -> Result<()> {
                macro_rules! attempted {
                    ($step:ident,$call:expr) => {{
                        let result = $call;
                        value
                            .setup_progress
                            .push((SetupStep::$step, result.is_ok()));
                        result?
                    }};
                }
                let absent =
                    attempted!(ReadAbsent, value.provider.observe(&value.create)).into_data();
                let mut journal = attempted!(CreateJournal, Journal::create(&mut value.db));
                attempted!(
                    AcceptCreate,
                    journal.accept(&input.policy.store, &value.create)
                );
                let permit = attempted!(
                    AuthorizeCreate,
                    journal.authorize_create(
                        &input.policy.store,
                        &value.create,
                        &absent,
                        context(input, &value.create, &absent, Purpose::Dispatch)?,
                        &mut value.provider
                    )
                );
                attempted!(
                    SendCreate,
                    permit.send(&input.policy.store, &mut value.provider)
                );
                let pending =
                    attempted!(ReadPending, value.provider.observe(&value.create)).into_data();
                attempted!(
                    ReconcileCreate,
                    journal.reconcile_attempt(
                        &input.policy.store,
                        &value.create,
                        &pending,
                        context(input, &value.create, &pending, Purpose::Reconcile)?,
                        &mut value.provider
                    )
                );
                value.pending = Some(pending);
                value.first = Some(attempted!(DeriveHolder, input.app.app_holder()));
                Ok(())
            })();
            if setup.is_err() {
                value.refuse();
            }
            Ok(value)
        }
        fn refuse(&mut self) {
            self.refused = true;
            self.provider.refuse();
            for t in &mut self.transcripts {
                t.refuse();
            }
        }
        fn wire(&mut self, input: &Input, n: u8) -> Result<()> {
            ensure!(!self.refused, "history_refused");
            let expected_controller = matches!(n, 0 | 2 | 4);
            let statement = if expected_controller {
                &input.controller
            } else {
                &input.app
            };
            statement.validate(
                &input.policy,
                &input.app.certificate,
                if expected_controller {
                    NativeRole::EpochController
                } else {
                    NativeRole::AppHost
                },
                &statement.stage.data.process,
                time(self.at),
                StagePurpose::InitialFirstHolder,
            )?;
            let message = decode(&input.packets[usize::from(n)])
                .map_err(|_| anyhow::anyhow!("history_wire_decode"))?;
            message.verify(statement)?;
            let frame = message.body.frame();
            let exchange = Exchange {
                app_stage: input.app.digest()?,
                controller_stage: input.controller.digest()?,
                app_nonce: Digest::of(&("hello", input.seed))?,
                controller_nonce: Digest::of(&("ready", input.seed))?,
                projection: input.projection.digest()?,
            };
            match &message.body {
                Body::InitialReady { controller, nonce } => ensure!(
                    **controller == input.controller && *nonce == exchange.controller_nonce,
                    "history_ready"
                ),
                Body::Hello { .. } => {
                    let (app, nonce) = message.initial_hello(&exchange.controller_nonce)?;
                    ensure!(
                        *app == input.app && *nonce == exchange.app_nonce,
                        "history_hello"
                    );
                }
                Body::Offer {
                    controller,
                    exchange: offered,
                    projection,
                } => {
                    offered.require_initial_ready(
                        &input.controller,
                        &exchange.controller_nonce,
                        controller,
                    )?;
                    projection.validate_selection(&input.policy.bootstrap, &input.policy.store)?;
                    ensure!(
                        *offered == exchange && **projection == input.projection,
                        "history_offer"
                    );
                }
                Body::Confirm {
                    exchange: id,
                    projection,
                } => ensure!(
                    *id == exchange.digest()? && *projection == input.projection.digest()?,
                    "history_confirm"
                ),
                Body::Complete { exchange: id } | Body::Accepted { exchange: id } => {
                    ensure!(*id == exchange.digest()?, "history_completion")
                }
                _ => anyhow::bail!("history_initial_message"),
            }
            for (index, t) in self.transcripts.iter_mut().enumerate() {
                ensure!(
                    t.next().is_some_and(|(_, next)| next == frame),
                    "history_wire_order"
                );
                let direction = if expected_controller == (index == 0) {
                    Direction::Send
                } else {
                    Direction::Receive
                };
                let stage = if index == 0 {
                    &input.controller
                } else {
                    &input.app
                };
                let observation = || Observation {
                    domain: stage.original.domain.clone(),
                    origin: time(stage.original.origin_ns),
                    deadline: time(stage.original.deadline_ns),
                    now: time(self.at),
                };
                t.begin(direction, observation())?;
                t.delivered(frame, observation())?;
            }
            self.position += 1;
            Ok(())
        }
        fn apply(&mut self, input: &Input, event: Event) -> Result<Reply> {
            if let Event::Time(at) = event {
                self.at = at;
                self.provider.set_slot_fixture_time(time(at));
                return Ok(Reply::Ok);
            }
            if event == Event::Reopen {
                self.db = rusqlite::Connection::open(self.directory.path().join("journal.sqlite"))?;
                Journal::open(&mut self.db)?;
                return Ok(Reply::Ok);
            }
            if event == Event::Historical {
                let request = self.candidate.as_ref().unwrap_or(&self.create);
                let (read, captured) = provider_data::observe_read_only_captured(
                    &self.directory.path().join("provider.sqlite"),
                    &input.policy.store,
                    request,
                );
                self.auxiliary_reads.push(captured);
                let read = read?;
                return Ok(
                    if matches!(
                        kernel::reconcile(&input.policy.store, request, &read)?,
                        Outcome::Applied(_)
                    ) {
                        Reply::Applied
                    } else {
                        Reply::NotApplied
                    },
                );
            }
            ensure!(!self.refused, "history_refused");
            match event {
                Event::Wire(n) => self.wire(input, n)?,
                Event::Select(change) => {
                    ensure!(
                        self.transcripts.iter().all(Transcript::complete),
                        "history_incomplete_transcript"
                    );
                    let first = self.first.clone().context("history_holder_missing")?;
                    let mut candidate = bootstrap::completion_request_fixture(
                        &input.policy.store,
                        &self.create,
                        &input.core,
                        self.pending.as_ref().context("history_pending_missing")?,
                        altered(first, change),
                    )?;
                    if change == HolderChange::Namespace {
                        let mut foreign = serde_json::to_value(&candidate)?;
                        foreign["bootstrap"]["scope"]["environment"] = json!("foreign");
                        candidate = serde_json::from_value(foreign)?;
                    }
                    let binding = storage_authority::request_binding_fixture(
                        self.create.bootstrap(),
                        self.first.as_ref().context("history_holder_missing")?,
                        &input.policy.store,
                        &candidate,
                    )?;
                    Journal::open(&mut self.db)?.accept(&input.policy.store, &candidate)?;
                    self.candidate = Some(candidate);
                    self.binding = Some(binding);
                }
                Event::Send(mode) => {
                    let request = self
                        .candidate
                        .as_ref()
                        .context("history_candidate_missing")?;
                    match mode {
                        Commit::Known => {}
                        Commit::MalformedAck => {
                            provider_data::malformed_ack_after_commit(&mut self.provider)
                        }
                        Commit::Rollback => provider_data::fail_during_commit(&mut self.provider),
                    }
                    Journal::open(&mut self.db)?
                        .authorize_activate(
                            &input.policy.store,
                            request,
                            self.pending.as_ref().context("history_pending_missing")?,
                            context(
                                input,
                                request,
                                self.pending.as_ref().context("history_pending_missing")?,
                                Purpose::Dispatch,
                            )?,
                            &mut self.provider,
                        )?
                        .send(&input.policy.store, &mut self.provider)?;
                }
                Event::Finish => {
                    let request = self
                        .candidate
                        .as_ref()
                        .context("history_candidate_missing")?;
                    let observed = self.provider.observe(request)?.into_data();
                    ensure!(
                        matches!(
                            Journal::open(&mut self.db)?.reconcile_attempt(
                                &input.policy.store,
                                request,
                                &observed,
                                context(input, request, &observed, Purpose::Reconcile)?,
                                &mut self.provider
                            )?,
                            Outcome::Applied(_)
                        ),
                        "history_activation_not_applied"
                    );
                    self.completed = true;
                }
                _ => unreachable!(),
            }
            Ok(Reply::Ok)
        }
        fn state(&self) -> Result<State> {
            let journal = journal_rows(&self.db);
            Ok(State {
                at: self.at,
                refused: self.refused,
                setup_progress: self.setup_progress.clone(),
                journal_readable: journal.is_ok(),
                position: self.position,
                selected: self
                    .candidate
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()?,
                binding: self
                    .binding
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()?,
                completed_data: self.completed,
                transcripts: serde_json::to_value(&self.transcripts)?,
                provider: provider_data::snapshot(&self.provider),
                auxiliary_reads: self.auxiliary_reads.clone(),
                journal: journal.unwrap_or(Value::Null),
            })
        }
    }
    // Schema/hash primitives are shared. Decisions, phases, conditional versions,
    // row contents and holder identities below never read actual adapter output.
    fn fields(value: &Value) -> Value {
        Value::Object(
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        match v {
                            Value::String(_) => json!({"stringValue":v}),
                            Value::Object(_) => json!({"mapValue":{"fields":fields(v)}}),
                            _ => panic!("fixture string/map contract"),
                        },
                    )
                })
                .collect(),
        )
    }
    fn records(request: &Request) -> Result<[Value; 3]> {
        let v = serde_json::to_value(request)?;
        let phase = match request {
            Request::CreateInitialAuthority { .. } => json!({"phase":"pending_first_holder"}),
            Request::CompleteInitialFirstActivation { .. } => {
                json!({"phase":"active_first_holder","completion":{"operation":v["operation"],"request":Digest::of(&("day2-external-epoch-request-v1",request))?,"parent_receipt":v["parent_receipt"],"before":v["before"],"holder":v["holder"]}})
            }
        };
        let root = json!({"format":"day2_credential_authority_v1","bootstrap":v["bootstrap"],"epoch":"1","phase":phase});
        let sentinel = json!({"format":"day2_credential_bootstrap_v1","bootstrap":v["bootstrap"],"initial_epoch":"1","phase":phase});
        let a: AuthorityRecord = serde_json::from_value(root.clone())?;
        let b: SentinelRecord = serde_json::from_value(sentinel.clone())?;
        let receipt = json!({"format":"day2_credential_epoch_receipt_v1","request":v,"request_digest":Digest::of(&("day2-external-epoch-request-v1",request))?,"after_root":Digest::of(&a)?,"after_sentinel":Digest::of(&b)?});
        Ok([root, sentinel, receipt])
    }
    fn timestamp(n: u64) -> String {
        format!("2026-10-14T00:00:00.{n:06}Z")
    }
    fn names(request: &Request) -> [String; 3] {
        let b = request.bootstrap();
        let prefix = "projects/project-seven/databases/security/documents";
        let root = format!(
            "{prefix}/day2_credential_authority_v1/{}",
            &b.authority.as_str()[7..]
        );
        let sentinel = format!(
            "{prefix}/day2_credential_bootstrap_v1/{}",
            &b.authority.as_str()[7..]
        );
        let operation = match request {
            Request::CreateInitialAuthority { bootstrap } => &bootstrap.create_operation,
            Request::CompleteInitialFirstActivation { operation, .. } => operation,
        };
        let receipt = format!("{root}/operations/{}", &operation.as_str()[7..]);
        [root, sentinel, receipt]
    }
    fn reference_holder(input: &Input) -> Result<Holder> {
        use base64::Engine;
        let d = &input.app.stage.data;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&d.public_key)?;
        Ok(Holder {
            principal: Digest::of(&(
                "day2-enrolled-app-principal-v1",
                &d.policy,
                &d.runtime.container.pod_uid,
            ))?,
            pod_uid: d.runtime.container.pod_uid.clone(),
            process_incarnation: Digest::of(&(
                "day2-enrolled-app-process-v1",
                &d.process,
                &d.runtime,
            ))?,
            ephemeral_key: Digest::new(&bytes),
        })
    }
    fn reference_request(input: &Input, holder: Holder) -> Result<Request> {
        let seed = Digest::of(&("day2-original-seed-core-v1", &input.core))?;
        let create = create(input)?;
        let before = Versions {
            root: timestamp(1).try_into()?,
            sentinel: timestamp(1).try_into()?,
        };
        let receipt: Receipt = serde_json::from_value(records(&create)?[2].clone())?;
        let parent = Digest::of(&("day2-external-epoch-receipt-v1", &receipt))?;
        let holder_core = Digest::of(&(
            "day2-control-holder-core-v1",
            &seed,
            &parent,
            &before,
            &holder,
        ))?;
        let operation = Digest::of(&(
            "day2-control-complete-operation-v1",
            &create.bootstrap().authority,
            &seed,
            holder_core,
        ))?;
        Ok(Request::CompleteInitialFirstActivation {
            bootstrap: create.bootstrap().clone(),
            operation,
            parent_receipt: parent,
            before,
            holder,
        })
    }
    struct Reference {
        at: u64,
        refused: bool,
        position: u8,
        last: Option<u64>,
        candidate: Option<Request>,
        binding: Option<Value>,
        completed: bool,
        applied: bool,
        dispatch: u64,
        documents: BTreeMap<String, Value>,
        calls: Vec<Value>,
        auxiliary_reads: Vec<Value>,
        journal: BTreeMap<String, Value>,
    }
    impl Reference {
        fn new(input: &Input) -> Result<Self> {
            let create = create(input)?;
            let mut model = Self {
                at: 100_000_000_000,
                refused: false,
                position: 0,
                last: None,
                candidate: None,
                binding: None,
                completed: false,
                applied: false,
                dispatch: 0,
                documents: BTreeMap::new(),
                calls: vec![],
                auxiliary_reads: vec![],
                journal: BTreeMap::new(),
            };
            model.read(&create)?;
            model.commit(&create, true, Duration::from_secs(5))?;
            model.read(&create)?;
            model
                .journal
                .insert("create".into(), model.row(&create, "observed", 1, true)?);
            Ok(model)
        }
        fn row(&self, request: &Request, state: &str, count: u64, receipt: bool) -> Result<Value> {
            Ok(
                json!({"authority":request.bootstrap().authority,"stage":if matches!(request,Request::CreateInitialAuthority{..}){"create"}else{"activate"},"operation":match request{Request::CreateInitialAuthority{bootstrap}=>&bootstrap.create_operation,Request::CompleteInitialFirstActivation{operation,..}=>operation},"request_digest":Digest::of(&("day2-external-epoch-request-v1",request))?,"request_json":serde_json::to_string(request)?,"state":state,"dispatch_count":count,"receipt_json":if receipt {Some(serde_json::to_string(&serde_json::from_value::<Receipt>(records(request)?[2].clone())?)?)}else{None::<String>}}),
            )
        }
        fn call(&mut self, kind: &str, body: Value, timeout: Duration) {
            self.calls.push(json!([format!("https://firestore.googleapis.com/v1/projects/project-seven/databases/security/documents:{kind}"),body,timeout]));
        }
        fn read(&mut self, request: &Request) -> Result<()> {
            let c = create_for(request);
            let base = names(&c);
            let mut documents = Vec::from(base);
            if matches!(request, Request::CompleteInitialFirstActivation { .. }) {
                documents.push(names(request)[2].clone());
            }
            self.call(
                "batchGet",
                json!({"documents":documents,"newTransaction":{"readOnly":{}}}),
                Duration::from_secs(5),
            );
            self.call(
                "rollback",
                json!({"transaction":"dHhuLTE="}),
                Duration::from_secs(5),
            );
            Ok(())
        }
        fn commit(&mut self, request: &Request, applied: bool, timeout: Duration) -> Result<()> {
            let names = names(request);
            let values = records(request)?;
            let active = matches!(request, Request::CompleteInitialFirstActivation { .. });
            let writes:Vec<_>=(0..3).map(|i|json!({"update":{"name":names[i],"fields":fields(&values[i])},"currentDocument":if active && i<2 {json!({"updateTime":timestamp(1)})}else{json!({"exists":false})}})).collect();
            self.call("commit", json!({"writes":writes}), timeout);
            if applied {
                for n in 0..3 {
                    self.documents.insert(names[n].clone(),json!({"name":names[n],"fields":fields(&values[n]),"version":if active{2}else{1}}));
                }
            }
            Ok(())
        }
        fn apply(&mut self, input: &Input, event: Event, control: Control) -> Result<Reply> {
            if let Event::Time(at) = event {
                self.at = at;
                return Ok(Reply::Ok);
            }
            if event == Event::Reopen {
                return Ok(Reply::Ok);
            }
            if event == Event::Historical {
                let request = self.candidate.clone().unwrap_or(create(input)?);
                let before = self.calls.len();
                self.read(&request)?;
                let calls = self.calls.split_off(before);
                self.auxiliary_reads
                    .push(json!({"opened":true,"calls":calls,"port_refused":false}));
                return Ok(if self.candidate.is_none() || self.applied {
                    Reply::Applied
                } else {
                    Reply::NotApplied
                });
            }
            if self.refused {
                return Ok(Reply::Refused);
            }
            let ok = match event {
                Event::Wire(n) => {
                    let good = n == self.position
                        && !(input.fault != Fault::None && n == input.fault_at)
                        && self.at >= 100_000_000_000
                        && self.at < 105_000_000_000
                        && self.last.is_none_or(|last| self.at >= last);
                    if good {
                        self.position += 1;
                        self.last = Some(self.at)
                    }
                    good
                }
                Event::Select(change) => {
                    if self.position == 6 && change == HolderChange::Same {
                        let candidate = reference_request(input, reference_holder(input)?)?;
                        self.binding = Some(
                            json!({"purpose":StoragePeerPurpose::BootstrapComplete,"binding":Digest::of(&("day2-external-epoch-request-v1",&candidate))?}),
                        );
                        if self.candidate.is_none() {
                            self.journal.insert(
                                "activate".into(),
                                self.row(&candidate, "prepared", 0, false)?,
                            );
                        }
                        self.candidate = Some(candidate);
                        true
                    } else {
                        false
                    }
                }
                Event::Send(mode) => {
                    if let Some(request) = self.candidate.clone()
                        && self.dispatch == 0
                        && self.at >= 100_000_000_000
                        && self.at < 105_000_000_000
                    {
                        self.dispatch = 1;
                        self.journal.insert(
                            "activate".into(),
                            self.row(&request, "may_have_been_sent", 1, false)?,
                        );
                        let applied = mode != Commit::Rollback;
                        self.commit(
                            &request,
                            applied
                                && !(control == Control::LostAckDidNotApply
                                    && mode == Commit::MalformedAck),
                            time(105_000_000_000 - self.at),
                        )?;
                        self.applied = applied;
                        mode == Commit::Known
                    } else {
                        false
                    }
                }
                Event::Finish => {
                    if let Some(request) = self.candidate.clone() {
                        self.read(&request)?;
                        if self.applied && self.at >= 100_000_000_000 && self.at < 105_000_000_000 {
                            self.journal.insert(
                                "activate".into(),
                                self.row(&request, "observed", 1, true)?,
                            );
                            self.completed = true;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                _ => unreachable!(),
            };
            if !ok {
                self.refused = true;
            }
            Ok(if ok { Reply::Ok } else { Reply::Refused })
        }
        fn state(&self, input: &Input) -> Result<State> {
            let transcript = |index: usize| {
                let stage = if index == 0 {
                    &input.controller
                } else {
                    &input.app
                };
                json!({"protocol":Protocol::InitialStorage,"purpose":StagePurpose::InitialFirstHolder,"actor":if index==0{Actor::Controller}else{Actor::App},"sequence":0,"position":self.position,"busy":false,"waiting":false,"refused":self.refused,"clock":self.last.map(|at|json!({"domain":stage.original.domain,"origin":time(100_000_000_000),"deadline":time(105_000_000_000),"now":time(at)}))})
            };
            Ok(State {
                at: self.at,
                refused: self.refused,
                setup_progress: [
                    SetupStep::ReadAbsent,
                    SetupStep::CreateJournal,
                    SetupStep::AcceptCreate,
                    SetupStep::AuthorizeCreate,
                    SetupStep::SendCreate,
                    SetupStep::ReadPending,
                    SetupStep::ReconcileCreate,
                    SetupStep::DeriveHolder,
                ]
                .into_iter()
                .map(|step| (step, true))
                .collect(),
                journal_readable: true,
                position: self.position,
                selected: self
                    .candidate
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()?,
                binding: self.binding.clone(),
                completed_data: self.completed,
                transcripts: json!([transcript(0), transcript(1)]),
                provider: json!({"documents":self.documents.values().collect::<Vec<_>>(),"sends":1+self.dispatch,"calls":self.calls}),
                auxiliary_reads: self.auxiliary_reads.clone(),
                journal: Value::Array(self.journal.values().cloned().collect()),
            })
        }
    }
    fn create_for(request: &Request) -> Request {
        Request::CreateInitialAuthority {
            bootstrap: request.bootstrap().clone(),
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Cut {
        event: Event,
        expected: Reply,
        actual: Reply,
        reference: State,
        observed: State,
        matched: bool,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Run {
        initial: State,
        expected_initial: State,
        cuts: Vec<Cut>,
        failed_at: Option<usize>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pair {
        input: Input,
        control: Control,
        runs: [Run; 2],
    }
    // Each part uses the unchanged central JSON evidence limits. The bounded
    // archive does not turn a larger aggregate into one oversized JSON value.
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "part", deny_unknown_fields)]
    enum Part {
        Header {
            format: u8,
            input: Box<Input>,
            control: Control,
            cuts: [usize; 2],
        },
        Begin {
            run: u8,
            initial: Box<State>,
            expected_initial: Box<State>,
            failed_at: Option<usize>,
        },
        Cut {
            run: u8,
            index: usize,
            cut: Box<Cut>,
        },
    }
    fn encode(pair: &Pair) -> Result<Vec<u8>> {
        use std::io::Write;
        let mut raw = vec![];
        let mut append = |part: Part| -> Result<()> {
            let line = serde_json::to_vec(&part)?;
            ensure!(line.len() <= 4 * 1024 * 1024, "signed_storage_part_bytes");
            raw.write_all(&line)?;
            raw.push(b'\n');
            ensure!(
                raw.len() <= MAX_BYTES as usize,
                "signed_storage_history_bytes"
            );
            Ok(())
        };
        append(Part::Header {
            format: 1,
            input: Box::new(pair.input.clone()),
            control: pair.control,
            cuts: [pair.runs[0].cuts.len(), pair.runs[1].cuts.len()],
        })?;
        for (run, value) in pair.runs.iter().enumerate() {
            append(Part::Begin {
                run: run as u8,
                initial: Box::new(value.initial.clone()),
                expected_initial: Box::new(value.expected_initial.clone()),
                failed_at: value.failed_at,
            })?;
            for (index, cut) in value.cuts.iter().enumerate() {
                append(Part::Cut {
                    run: run as u8,
                    index,
                    cut: Box::new(cut.clone()),
                })?;
            }
        }
        Ok(raw)
    }
    fn decode_parts(raw: &[u8]) -> Result<Pair> {
        ensure!(
            raw.len() <= MAX_BYTES as usize && raw.ends_with(b"\n"),
            "signed_storage_part_framing"
        );
        let lines: Vec<_> = raw[..raw.len() - 1].split(|b| *b == b'\n').collect();
        ensure!(
            lines.len() <= 3 + 2 * MAX_EVENTS,
            "signed_storage_part_count"
        );
        let mut parts = Vec::with_capacity(lines.len());
        for line in lines {
            let value: Value = crate::json::decode_evidence(line)
                .map_err(|_| anyhow::anyhow!("signed_storage_replay_decode"))?;
            let part: Part = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("signed_storage_replay_shape"))?;
            ensure!(
                serde_json::to_value(&part)? == value,
                "signed_storage_replay_shape"
            );
            parts.push(part);
        }
        let mut parts = parts.into_iter();
        let Some(Part::Header {
            format: 1,
            input,
            control,
            cuts,
        }) = parts.next()
        else {
            anyhow::bail!("signed_storage_part_header")
        };
        ensure!(
            cuts.iter().all(|n| *n <= MAX_EVENTS),
            "signed_storage_part_count"
        );
        let mut runs = vec![];
        for (run, &count) in cuts.iter().enumerate() {
            let Some(Part::Begin {
                run: observed,
                initial,
                expected_initial,
                failed_at,
            }) = parts.next()
            else {
                anyhow::bail!("signed_storage_part_begin")
            };
            ensure!(usize::from(observed) == run, "signed_storage_part_run");
            let mut values = vec![];
            for index in 0..count {
                let Some(Part::Cut {
                    run: observed,
                    index: seen,
                    cut,
                }) = parts.next()
                else {
                    anyhow::bail!("signed_storage_part_cut")
                };
                ensure!(
                    usize::from(observed) == run && seen == index,
                    "signed_storage_part_order"
                );
                values.push(*cut);
            }
            runs.push(Run {
                initial: *initial,
                expected_initial: *expected_initial,
                cuts: values,
                failed_at,
            });
        }
        ensure!(parts.next().is_none(), "signed_storage_part_trailing");
        Ok(Pair {
            input: *input,
            control,
            runs: runs
                .try_into()
                .map_err(|_| anyhow::anyhow!("signed_storage_part_runs"))?,
        })
    }
    fn run(input: &Input, control: Control) -> Result<Run> {
        shape(input)?;
        let mut actual = Actual::new(input)?;
        let mut reference = Reference::new(input)?;
        let initial = actual.state()?;
        let expected_initial = reference.state(input)?;
        let mut result = Run {
            failed_at: (initial != expected_initial).then_some(0),
            initial,
            expected_initial,
            cuts: vec![],
        };
        if result.failed_at.is_some() {
            return Ok(result);
        }
        for (index, &event) in input.events.iter().enumerate() {
            let expected = reference.apply(input, event, control)?;
            let observed = match actual.apply(input, event) {
                Ok(value) => value,
                Err(_) => {
                    actual.refuse();
                    Reply::Refused
                }
            };
            let reference = reference.state(input)?;
            let state = actual.state()?;
            let matched = expected == observed && reference == state;
            result.cuts.push(Cut {
                event,
                expected,
                actual: observed,
                reference,
                observed: state,
                matched,
            });
            if !matched {
                result.failed_at = Some(index + 1);
                break;
            }
        }
        Ok(result)
    }
    fn pair(input: &Input, control: Control) -> Result<Pair> {
        Ok(Pair {
            input: input.clone(),
            control,
            runs: [run(input, control)?, run(input, control)?],
        })
    }
    fn retain(pair: &Pair) -> Result<std::path::PathBuf> {
        use std::{
            io::Write,
            os::unix::fs::{OpenOptionsExt, PermissionsExt},
        };
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/control-slot-replays");
        std::fs::create_dir_all(&root)?;
        let directory = tempfile::Builder::new()
            .prefix("signed-first-holder-")
            .tempdir_in(root)?
            .keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let bytes = encode(pair)?;
        ensure!(
            bytes.len() <= MAX_BYTES as usize,
            "signed_storage_history_bytes"
        );
        let path = directory.join("replay.json.gz");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        encoder.write_all(&bytes)?;
        encoder.finish()?.sync_all()?;
        Ok(path)
    }
    fn validate_saved(pair: &Pair) -> Result<()> {
        shape(&pair.input)?;
        for run in &pair.runs {
            let mut reference = Reference::new(&pair.input)?;
            let initial = reference.state(&pair.input)?;
            ensure!(
                run.expected_initial == initial,
                "signed_storage_saved_initial"
            );
            let mut first = (run.initial != initial).then_some(0);
            ensure!(
                run.cuts.len() <= pair.input.events.len(),
                "signed_storage_saved_events"
            );
            for (index, cut) in run.cuts.iter().enumerate() {
                ensure!(
                    first.is_none() && cut.event == pair.input.events[index],
                    "signed_storage_saved_order"
                );
                let expected = reference.apply(&pair.input, cut.event, pair.control)?;
                let state = reference.state(&pair.input)?;
                let matched = cut.actual == expected && cut.observed == state;
                ensure!(
                    cut.expected == expected && cut.reference == state && cut.matched == matched,
                    "signed_storage_saved_state"
                );
                if !matched {
                    first = Some(index + 1)
                }
            }
            ensure!(
                first == run.failed_at
                    && (first.is_some() || run.cuts.len() == pair.input.events.len()),
                "signed_storage_saved_failure"
            );
        }
        Ok(())
    }
    fn replay(path: &Path) -> Result<()> {
        use std::io::Read;
        ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_file(),
            "signed_storage_replay_regular"
        );
        let mut compressed = vec![];
        std::fs::File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut compressed)?;
        ensure!(
            compressed.len() <= MAX_BYTES as usize,
            "signed_storage_replay_bytes"
        );
        let mut raw = vec![];
        let mut decoder = flate2::bufread::GzDecoder::new(&compressed[..]);
        (&mut decoder)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut raw)
            .map_err(|_| anyhow::anyhow!("signed_storage_replay_compression"))?;
        ensure!(
            decoder.get_ref().is_empty(),
            "signed_storage_replay_trailing_compression"
        );
        ensure!(
            raw.len() <= MAX_BYTES as usize,
            "signed_storage_replay_bytes"
        );
        let saved = decode_parts(&raw)?;
        validate_saved(&saved)?;
        let actual = pair(&saved.input, saved.control)?;
        ensure!(actual.runs == saved.runs, "signed_storage_replay_changed");
        Ok(())
    }
    fn verify(input: &Input) -> Result<Pair> {
        let result = pair(input, Control::Correct)?;
        if result.runs[0] != result.runs[1] || result.runs.iter().any(|r| r.failed_at.is_some()) {
            let path = retain(&result)?;
            anyhow::bail!(
                "signed storage history divergence; replay {}",
                path.display()
            );
        }
        Ok(result)
    }
    fn generated(seed: u64) -> Result<Input> {
        let mut events = vec![Event::Historical];
        let mut random = seed.wrapping_add(1);
        let mut now = 100_000_000_000;
        for n in 0..6 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            now += 1 + random % 20_000_000;
            events.push(Event::Time(now));
            events.push(Event::Wire(n));
            if (seed + n as u64).is_multiple_of(3) {
                events.push(Event::Historical);
            }
        }
        events.extend([
            Event::Select(HolderChange::Same),
            Event::Send(match seed % 3 {
                0 => Commit::Known,
                1 => Commit::MalformedAck,
                _ => Commit::Rollback,
            }),
            Event::Historical,
            Event::Reopen,
            Event::Finish,
            Event::Send(Commit::Known),
            Event::Historical,
            Event::Time(105_000_000_000),
            Event::Select(HolderChange::Same),
            Event::Time(100_000_000_000),
            Event::Send(Commit::Known),
            Event::Historical,
        ]);
        let fault = match seed % 10 {
            0..=2 => Fault::None,
            3 => Fault::Signature,
            4 => Fault::Role,
            5 => Fault::Nonce,
            6 => Fault::Projection,
            7 => Fault::Process,
            8 => Fault::Certificate,
            _ => Fault::PacketKind,
        };
        fixture(
            seed,
            fault,
            if fault == Fault::Nonce {
                1
            } else if fault == Fault::Projection {
                2
            } else if matches!(fault, Fault::Certificate | Fault::PacketKind) {
                0
            } else {
                (seed % 6) as u8
            },
            events,
        )
    }
    #[test]
    fn signed_first_holder_and_conditional_activation_histories_match_independent_complete_state()
    -> Result<()> {
        for seed in 0..20 {
            let input = generated(seed)?;
            let pair = verify(&input)?;
            if input.fault == Fault::None {
                for run in &pair.runs {
                    let send = run
                        .cuts
                        .iter()
                        .find(|cut| matches!(cut.event, Event::Send(_)))
                        .context("activation send not reached")?;
                    ensure!(
                        send.observed.position == 6 && send.observed.provider["sends"] == 2,
                        "generated activation did not reach actual transaction"
                    );
                    let documents = send.observed.provider["documents"]
                        .as_array()
                        .context("provider documents")?;
                    match seed % 3 {
                        0 => {
                            ensure!(
                                send.actual == Reply::Ok
                                    && run.cuts.iter().any(|cut| cut.event == Event::Finish
                                        && cut.observed.completed_data),
                                "known completion not witnessed"
                            )
                        }
                        1 => ensure!(
                            send.actual == Reply::Refused && documents.len() == 4,
                            "committed uncertainty not witnessed"
                        ),
                        _ => ensure!(
                            send.actual == Reply::Refused && documents.len() == 3,
                            "actual rollback not witnessed"
                        ),
                    }
                }
            }
        }
        Ok(())
    }
    #[test]
    fn real_applied_write_with_malformed_ack_is_not_absence_or_retry_permission() -> Result<()> {
        let mut input = generated(1)?;
        input.fault = Fault::None;
        let value = pair(&input, Control::LostAckDidNotApply)?;
        ensure!(
            value.runs.iter().all(|r| r.failed_at.is_some()
                && r.cuts
                    .last()
                    .is_some_and(|cut| cut.event == Event::Send(Commit::MalformedAck)
                        && cut.actual == Reply::Refused
                        && cut.observed.provider["documents"]
                            .as_array()
                            .is_some_and(|a| a.len() == 4)
                        && cut.observed.journal[0]["state"] == "may_have_been_sent")),
            "signed_storage_wrong_oracle_not_observed"
        );
        let path = retain(&value)?;
        replay(&path)?;
        Ok(())
    }
    #[test]
    fn foreign_holder_bindings_and_original_clock_cuts_cannot_recover_a_continuation() -> Result<()>
    {
        for change in [
            HolderChange::Key,
            HolderChange::Process,
            HolderChange::Pod,
            HolderChange::Namespace,
        ] {
            let mut input = generated(0)?;
            input.events = Vec::from_iter((0..6).map(Event::Wire));
            input.events.extend([
                Event::Select(change),
                Event::Select(HolderChange::Same),
                Event::Send(Commit::Known),
                Event::Historical,
            ]);
            let value = verify(&input)?;
            ensure!(
                value.runs.iter().all(|r| r.cuts[6].actual == Reply::Refused
                    && r.cuts.last().unwrap().observed.provider["sends"] == 1),
                "foreign_holder_not_refused"
            );
        }
        for at in [99_000_000_000, 105_000_000_000] {
            let mut input = generated(0)?;
            input.events = vec![
                Event::Wire(0),
                Event::Time(at),
                Event::Wire(1),
                Event::Time(100_000_000_000),
                Event::Wire(1),
                Event::Select(HolderChange::Same),
                Event::Send(Commit::Known),
            ];
            verify(&input)?;
        }
        let mut input = generated(0)?;
        input.events = vec![
            Event::Time(100_500_000_000),
            Event::Wire(0),
            Event::Time(100_250_000_000),
            Event::Wire(1),
            Event::Time(100_750_000_000),
            Event::Wire(1),
            Event::Select(HolderChange::Same),
            Event::Send(Commit::Known),
        ];
        verify(&input)?;
        let mut input = generated(0)?;
        input.events = (0..5).map(Event::Wire).collect();
        input.events.extend([
            Event::Select(HolderChange::Same),
            Event::Wire(5),
            Event::Send(Commit::Known),
            Event::Historical,
        ]);
        verify(&input)?;
        Ok(())
    }
    #[test]
    fn saved_signed_history_requires_both_complete_runs_source_and_closed_shape() -> Result<()> {
        let input = generated(1)?;
        let value = pair(&input, Control::LostAckDidNotApply)?;
        let path = retain(&value)?;
        replay(&path)?;
        for side in 0..2 {
            let mut changed = serde_json::to_value(&value)?;
            changed["runs"][side]["cuts"][0]["observed"]["completed_data"] = json!(true);
            let bad: Pair = serde_json::from_value(changed)?;
            ensure!(
                validate_saved(&bad).is_err(),
                "saved_false_completion_accepted"
            );
        }
        let mut changed = serde_json::to_value(&value)?;
        changed["input"]["source"] = json!(Digest::new(b"foreign-source"));
        let bad: Pair = serde_json::from_value(changed)?;
        ensure!(validate_saved(&bad).is_err(), "saved_source_accepted");
        let bytes = std::fs::read(&path)?;
        std::fs::write(&path, &bytes[..bytes.len() / 2])?;
        ensure!(replay(&path).is_err(), "truncated_history_accepted");
        std::fs::write(&path, bytes)?;
        replay(&path)?;
        Ok(())
    }
    #[test]
    fn maximum_signed_history_retains_every_original_event_and_both_runs() -> Result<()> {
        let mut input = generated(0)?;
        while input.events.len() < MAX_EVENTS {
            input.events.push(Event::Historical)
        }
        let value = verify(&input)?;
        ensure!(
            value.runs.iter().all(|r| r.cuts.len() == MAX_EVENTS),
            "signed_storage_events_truncated"
        );
        let path = retain(&value)?;
        replay(&path)?;
        Ok(())
    }
    #[test]
    fn replay_requires_one_bounded_gzip_member_and_never_formats_foreign_values() -> Result<()> {
        use std::io::Write;
        let value = pair(&generated(1)?, Control::LostAckDidNotApply)?;
        let path = retain(&value)?;
        let original = std::fs::read(&path)?;
        let mut trailing = original.clone();
        trailing.extend_from_slice(b"PRIVATE_REPLAY_VALUE");
        std::fs::write(&path, trailing)?;
        ensure!(replay(&path).is_err(), "trailing_compression_accepted");
        for raw in [
            b"PRIVATE_REPLAY_VALUE\n".as_slice(),
            b"{\"PRIVATE_REPLAY_VALUE\":null}\n",
        ] {
            let mut gzip = flate2::write::GzEncoder::new(vec![], flate2::Compression::fast());
            gzip.write_all(raw)?;
            std::fs::write(&path, gzip.finish()?)?;
            let error = replay(&path).err().context("foreign shape must refuse")?;
            ensure!(
                !error.to_string().contains("PRIVATE_REPLAY_VALUE")
                    && error.downcast_ref::<serde_json::Error>().is_none(),
                "foreign_parser_value_escaped"
            );
        }
        std::fs::write(&path, vec![b' '; MAX_BYTES as usize + 1])?;
        ensure!(replay(&path).is_err(), "compressed_limit_accepted");
        std::fs::write(&path, original)?;
        replay(&path)?;
        Ok(())
    }
    #[test]
    fn multipart_archive_rejects_missing_duplicate_reordered_cross_run_and_foreign_parts()
    -> Result<()> {
        let pair = pair(&generated(1)?, Control::LostAckDidNotApply)?;
        let raw = encode(&pair)?;
        let value = decode_parts(&raw)?;
        validate_saved(&value)?;
        let original: Vec<Vec<u8>> = raw[..raw.len() - 1]
            .split(|b| *b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        let assemble = |lines: Vec<Vec<u8>>| {
            let mut bytes = vec![];
            for line in lines {
                bytes.extend(line);
                bytes.push(b'\n');
            }
            bytes
        };
        let mut missing = original.clone();
        missing.pop();
        ensure!(
            decode_parts(&assemble(missing)).is_err(),
            "missing_part_accepted"
        );
        let mut repeated = original.clone();
        repeated.insert(2, repeated[2].clone());
        ensure!(
            decode_parts(&assemble(repeated)).is_err(),
            "duplicate_part_accepted"
        );
        let mut reordered = original.clone();
        reordered.swap(2, 3);
        ensure!(
            decode_parts(&assemble(reordered)).is_err(),
            "reordered_parts_accepted"
        );
        let mut cross = original.clone();
        let mut part: Value = crate::json::decode_evidence(&cross[2])?;
        part["run"] = json!(1);
        cross[2] = serde_json::to_vec(&part)?;
        ensure!(
            decode_parts(&assemble(cross)).is_err(),
            "cross_run_part_accepted"
        );
        let mut foreign = original.clone();
        let mut part: Value = crate::json::decode_evidence(&foreign[0])?;
        part["unexpected"] = json!(true);
        foreign[0] = serde_json::to_vec(&part)?;
        ensure!(
            decode_parts(&assemble(foreign)).is_err(),
            "unknown_part_field_accepted"
        );
        let mut duplicate = original.clone();
        let header = String::from_utf8(duplicate[0].clone())?;
        let changed = header.replacen("\"format\":1", "\"format\":1,\"format\":1", 1);
        ensure!(changed != header, "duplicate_target_missing");
        duplicate[0] = changed.into_bytes();
        ensure!(
            decode_parts(&assemble(duplicate)).is_err(),
            "duplicate_json_key_accepted"
        );
        Ok(())
    }
    #[test]
    fn setup_refusal_retains_actual_committed_prefix_and_both_runs() -> Result<()> {
        let mut input = generated(0)?;
        // Drive the actual app_holder validation failure after the real pending
        // authority prelude. This is an intentional invalid-fixture control.
        input.app.stage.data.runtime.container.pod_uid = "invalid-pod".into();
        let value = pair(&input, Control::Correct)?;
        ensure!(
            value.runs.iter().all(|run| run.failed_at == Some(0)
                && run.cuts.is_empty()
                && run.initial.setup_progress.last() == Some(&(SetupStep::DeriveHolder, false))
                && run.initial.provider["documents"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 3)
                && run.initial.provider["sends"] == 1
                && run.initial.journal[0]["state"] == "observed"),
            "setup_prefix_not_actual"
        );
        let path = retain(&value)?;
        replay(&path)?;
        Ok(())
    }
    #[test]
    fn historical_semantic_refusal_keeps_its_real_batch_and_rollback_prefix() -> Result<()> {
        let input = generated(0)?;
        let mut actual = Actual::new(&input)?;
        let before = actual.state()?;
        let root = before.provider["documents"]
            .as_array()
            .context("fixture documents")?
            .iter()
            .find(|row| {
                row["name"].as_str().is_some_and(|name| {
                    !name.contains("/operations/")
                        && name.contains("/day2_credential_authority_v1/")
                })
            })
            .context("fixture root")?;
        let mut bad = root.clone();
        bad["fields"]["epoch"] = json!({"stringValue":"not-an-epoch"});
        provider_data::replace_document(
            &mut actual.provider,
            root["name"].as_str().unwrap(),
            Some(&bad),
        )?;
        let main_before = provider_data::snapshot(&actual.provider);
        let (result, captured) = provider_data::observe_read_only_captured(
            &actual.directory.path().join("provider.sqlite"),
            &input.policy.store,
            &actual.create,
        );
        ensure!(
            result.is_err() && captured["opened"] == true,
            "historical_refusal_not_actual"
        );
        let calls = captured["calls"].as_array().context("auxiliary calls")?;
        ensure!(
            calls.len() == 2
                && calls[0][0]
                    .as_str()
                    .is_some_and(|url| url.ends_with(":batchGet"))
                && calls[1][0]
                    .as_str()
                    .is_some_and(|url| url.ends_with(":rollback")),
            "historical_refusal_prefix_lost"
        );
        let mut model = Reference::new(&input)?;
        let start = model.calls.len();
        model.read(&actual.create)?;
        ensure!(
            calls.as_slice() == &model.calls[start..]
                && provider_data::snapshot(&actual.provider) == main_before,
            "historical_capture_changed_writer_or_protocol"
        );
        let pair = verify(&generated(1)?)?;
        let mut changed = serde_json::to_value(&pair)?;
        changed["runs"][1]["cuts"][0]["observed"]["auxiliary_reads"][0]["calls"]
            .as_array_mut()
            .context("auxiliary mutation target")?
            .pop();
        let changed: Pair = serde_json::from_value(changed)?;
        ensure!(
            validate_saved(&changed).is_err(),
            "omitted_auxiliary_call_accepted"
        );
        Ok(())
    }
    fn actual_wire_method(source: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(source).expect("Rust source");
        let items = file
            .items
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Mod(module) if module.ident == "activation_histories" => {
                    module.content.map(|v| v.1)
                }
                _ => None,
            })
            .expect("history module");
        items.into_iter().find_map(|item|match item {syn::Item::Impl(owner) if matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident("Actual"))=>owner.items.into_iter().find_map(|item|match item {syn::ImplItem::Fn(method) if method.sig.ident=="wire"=>Some(method),_=>None}),_=>None}).expect("actual wire method")
    }
    fn wire_uses_actual_frame(method: &syn::ImplItemFn) -> bool {
        use syn::visit::Visit;
        let bindings:Vec<_>=method.block.stmts.iter().filter_map(|statement|match statement {syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="frame")=>Some(local),_=>None}).collect();
        if bindings.len() != 1 {
            return false;
        }
        let local = bindings[0];
        let exact = matches!((&local.pat,&local.init),(syn::Pat::Ident(name),Some(init)) if name.mutability.is_none() && init.diverge.is_none() && matches!(&*init.expr,syn::Expr::MethodCall(call) if call.method=="frame" && call.args.is_empty() && matches!(&*call.receiver,syn::Expr::Field(field) if matches!(&field.member,syn::Member::Named(name) if name=="body") && matches!(&*field.base,syn::Expr::Path(path) if path.path.is_ident("message")))));
        #[derive(Default)]
        struct Calls {
            frames: usize,
            delivered: usize,
            assigned: usize,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.frames += usize::from(call.method == "frame");
                self.delivered += usize::from(
                    call.method == "delivered"
                        && matches!(call.args.first(),Some(syn::Expr::Path(path)) if path.path.is_ident("frame")),
                );
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
                self.assigned += usize::from(
                    matches!(&*assign.left,syn::Expr::Path(path) if path.path.is_ident("frame")),
                );
                syn::visit::visit_expr_assign(self, assign);
            }
        }
        let mut calls = Calls::default();
        calls.visit_block(&method.block);
        exact && calls.frames == 1 && calls.delivered == 1 && calls.assigned == 0
    }
    #[test]
    fn campaign_uses_production_frame_mapping_and_rejects_a_duplicate_fixture_mapper() -> Result<()>
    {
        let actual = actual_wire_method(include_str!("tests.rs"));
        ensure!(wire_uses_actual_frame(&actual), "actual_frame_not_used");
        let mut changed = actual.clone();
        let mut targets = 0;
        for statement in &mut changed.block.stmts {
            if let syn::Stmt::Local(local) = statement
                && matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="frame")
            {
                *local.init.as_mut().unwrap().expr = syn::parse_quote!(Frame {
                    protocol: Protocol::InitialStorage,
                    step: Step::BeginReady,
                    sequence: None
                });
                targets += 1;
            }
        }
        ensure!(
            targets == 1 && !wire_uses_actual_frame(&changed),
            "fixture_mapper_restoration_accepted"
        );
        changed
            .block
            .stmts
            .push(syn::parse_quote!(message.body.frame();));
        ensure!(
            !wire_uses_actual_frame(&changed),
            "unused_frame_call_accepted"
        );
        Ok(())
    }
    #[test]
    fn validly_signed_complete_at_ready_cannot_advance_either_transcript() -> Result<()> {
        use crate::security_epoch::native_enrollment::handshake::Step;
        let input = fixture(
            91,
            Fault::PacketKind,
            0,
            vec![
                Event::Wire(0),
                Event::Wire(1),
                Event::Select(HolderChange::Same),
                Event::Send(Commit::Known),
            ],
        )?;
        let message = decode(&input.packets[0])?;
        message.verify(&input.controller)?;
        ensure!(
            matches!(&message.body, Body::Complete { .. })
                && message.body.frame().step == Step::Complete,
            "wrong_kind_control_not_real_signed_complete"
        );
        let value = verify(&input)?;
        ensure!(
            value
                .runs
                .iter()
                .all(|run| run.cuts[0].actual == Reply::Refused
                    && run.cuts[0].observed.position == 0
                    && run.cuts[0].observed.transcripts[0]["position"] == 0
                    && run.cuts[0].observed.transcripts[1]["position"] == 0
                    && run.cuts.last().unwrap().observed.provider["sends"] == 1),
            "wrong_kind_advanced_or_dispatched"
        );
        // Show why the deleted n-to-step fixture mapper was insufficient: it
        // supplies the expected Ready frame while ignoring this valid body.
        for (index, actor) in [Actor::Controller, Actor::App].into_iter().enumerate() {
            let mut legacy = Transcript::new(Protocol::InitialStorage, actor);
            let (direction, manufactured) = legacy.next().context("legacy initial frame")?;
            ensure!(
                manufactured.step == Step::BeginReady && manufactured != message.body.frame(),
                "legacy_control_not_different_kind"
            );
            let statement = if index == 0 {
                &input.controller
            } else {
                &input.app
            };
            let observation = || Observation {
                domain: statement.original.domain.clone(),
                origin: time(100_000_000_000),
                deadline: time(105_000_000_000),
                now: time(100_000_000_000),
            };
            legacy.begin(direction, observation())?;
            legacy.delivered(manufactured, observation())?;
            ensure!(
                legacy
                    .next()
                    .is_some_and(|(_, frame)| frame.step == Step::Hello),
                "legacy_control_did_not_advance"
            );
        }
        Ok(())
    }
    #[test]
    fn external_signed_storage_history_replays_twice_when_supplied() -> Result<()> {
        let Some(path) = std::env::var_os("DAY2_SIGNED_STORAGE_REPLAY") else {
            return Ok(());
        };
        replay(Path::new(&path))
    }
}

#[test]
fn admin_read_is_signed_distinct_and_exact_with_a_mandatory_cohort() {
    let (_, app, key) = fixture(NativeRole::AppHost);
    let initial = Digest::new(b"retained peer");
    let ready = Digest::new(b"fresh controller ready");
    let operation = Digest::new(b"exact admin operation");
    let cohort = SqliteCohort::from_identities((9, 10), (9, 11), (9, 12)).unwrap();
    let request = StoragePeerRequest::AdminRead {
        binding: operation.clone(),
        cohort,
    };
    let hello = signed(
        &app,
        &key,
        Body::CurrentHello {
            app: Box::new(app.clone()),
            initial: initial.clone(),
            sequence: 2,
            request: request.clone(),
            nonce: Digest::new(b"fresh app"),
            controller_nonce: ready.clone(),
        },
    );
    let decoded = decode(&serde_json::to_vec(&hello).unwrap()).unwrap();
    decoded.verify(&app).unwrap();
    decoded
        .current_hello_expected(
            &initial,
            2,
            &ready,
            &CurrentExpectation::AdminRead(&operation),
        )
        .unwrap();
    assert!(decoded.current_hello(&initial, 2, &ready, None).is_err());
    assert!(
        decoded
            .current_hello_expected(
                &initial,
                2,
                &ready,
                &CurrentExpectation::AdminRead(&Digest::new(b"other operation"))
            )
            .is_err()
    );
    assert!(
        decoded
            .current_hello_expected(
                &initial,
                3,
                &ready,
                &CurrentExpectation::AdminRead(&operation)
            )
            .is_err()
    );
    assert!(
        decoded
            .current_hello_expected(
                &initial,
                2,
                &Digest::new(b"old ready"),
                &CurrentExpectation::AdminRead(&operation)
            )
            .is_err()
    );
    let ordinary = StoragePeerRequest::CurrentServing {
        binding: operation.clone(),
    };
    assert!(
        decoded
            .current_hello(&initial, 2, &ready, Some(&ordinary))
            .is_err()
    );
    assert!(
        StoragePeerRequest::operation(StoragePeerPurpose::AdminRead, operation.clone()).is_err()
    );
    for identities in [
        ((9, 0), (9, 11), (9, 12)),
        ((9, 10), (9, 10), (9, 12)),
        ((9, 10), (8, 11), (9, 12)),
    ] {
        assert!(SqliteCohort::from_identities(identities.0, identities.1, identities.2).is_err());
    }
    let original = serde_json::to_value(&hello).unwrap();
    for (path, value) in [
        ("/body/request", serde_json::json!([])),
        ("/body/request/cohort", serde_json::json!([])),
        ("/body/request/cohort/main", serde_json::json!([9, 99])),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = value;
        let changed = decode(&serde_json::to_vec(&changed).unwrap());
        if path.ends_with("main") {
            assert!(changed.unwrap().verify(&app).is_err());
        } else {
            assert!(changed.is_err());
        }
    }
    for field in ["binding", "cohort", "purpose"] {
        let mut changed = original.clone();
        changed["body"]["request"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut ordinary_with_cohort = original.clone();
    ordinary_with_cohort["body"]["request"]["purpose"] = serde_json::json!("current_serving");
    assert!(decode(&serde_json::to_vec(&ordinary_with_cohort).unwrap()).is_err());
    for field in ["purpose", "binding", "cohort"] {
        let raw = serde_json::to_string(&original).unwrap();
        let value = serde_json::to_string(&original["body"]["request"][field]).unwrap();
        let fragment = format!("\"{field}\":{value}");
        let duplicate = raw.replacen(&fragment, &format!("{fragment},{fragment}"), 1);
        assert!(
            raw != duplicate,
            "duplicate-field mutation must change the exact wire bytes"
        );
        assert!(decode(duplicate.as_bytes()).is_err());
    }
}
