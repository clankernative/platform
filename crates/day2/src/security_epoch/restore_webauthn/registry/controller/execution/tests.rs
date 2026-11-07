//! Real cryptographic DATA and actual-source controls. No portable native
//! reader, current executor, file loan or consumed approval is invented here.
use super::*;
use crate::security_epoch::{
    restore_approval::{AdminIdentity, ApprovalRequest, TargetBinding},
    restore_webauthn::{
        registry::tests::configuration,
        tests::{Fixture, fixture},
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::{
    BindingRef, Name, restore_signing::KeySelection, security_epoch::AuthorityScope,
};
use quote::ToTokens;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use syn::parse::Parser;
use syn::visit::Visit;

fn signing_key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[11; 32]).unwrap()
}

fn sign(record: &mut SignedApprovalRecord) -> Result<()> {
    // Independent fixed-purpose encoder; do not use signature_input_data to
    // construct the positive evidence for its own verifier.
    record.signature = URL_SAFE_NO_PAD.encode(
        signing_key()
            .sign(&serde_json::to_vec(&(
                "day2-restore-approval-grant-ed25519-v1",
                &record.statement,
            ))?)
            .as_ref(),
    );
    Ok(())
}

fn data() -> Result<(
    Instance,
    ControllerRegistryData,
    SignedApprovalRecord,
    Fixture,
)> {
    let mut instance = configuration();
    let authenticator = fixture();
    let public = authenticator.signer.public_key().as_ref();
    let cose = [
        vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20],
        public[1..33].to_vec(),
        vec![0x22, 0x58, 0x20],
        public[33..].to_vec(),
    ]
    .concat()
    .try_into()?;
    let control = instance.control.as_mut().unwrap();
    let registry = control.restore_passkeys.as_mut().unwrap();
    let mut executor = registry.keys.values().next().unwrap().clone();
    executor.email = "executor@example.test".into();
    executor.subject = "actual-executor-subject".into();
    executor.credential_id = authenticator.key.record.credential_id.clone();
    executor.user_handle = authenticator.key.record.user_handle.clone();
    executor.cose_key = cose;
    registry
        .keys
        .insert(Name::try_from("executor".to_owned())?, executor);
    let signing = KeySelection {
        version: "projects/approval-project/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/7".to_owned().try_into()?,
        public_key: signing_key().public_key().as_ref().try_into()?,
    };
    control.restore_approval_signing = Some(signing.clone());
    let d = |label: &str| Digest::new(label.as_bytes());
    let request = ApprovalRequest {
        grant_id: d("one-grant"),
        full_archive_digest: d("complete-archive"),
        target: TargetBinding {
            scope: AuthorityScope {
                installation: "company".to_owned().try_into()?,
                environment: "canary".to_owned().try_into()?,
                app: "app".to_owned().try_into()?,
            },
            binding_generation: 3,
            authority: d("authority"),
            selection: d("selection"),
            incarnation: d("incarnation"),
            security_epoch: 2,
            artifact: d("artifact"),
            schema: d("schema"),
        },
        executor: AdminIdentity {
            email: "executor@example.test".into(),
            subject: "actual-executor-subject".into(),
        },
        custody: BindingRef {
            id: "vault".to_owned().try_into()?,
            revision: d("vault-version"),
        },
        approved_at: 100,
        expires_at: 3700,
    };
    let context = ControllerRegistryData {
        selector: "/reviewed/instance.json".into(),
        instance: Digest::of(&instance)?,
        scope: instance.scope("app")?,
        app: "app".into(),
        artifact: "artifact".into(),
        authority: crate::authority_state::AuthorityStamp {
            epoch: d("epoch").as_str().into(),
            revision: 7,
        },
        operation: request.intent().commitment()?,
        approver: "álîce@example.test".into(),
        executor: request.executor.email.clone(),
    };
    let registry = instance
        .control
        .as_ref()
        .unwrap()
        .restore_passkeys
        .as_ref()
        .unwrap();
    let mut signed = SignedApprovalRecord {
        statement: crate::security_epoch::restore_approval::signed::ApprovalStatement {
            request,
            approver: AdminIdentity {
                email: context.approver.clone(),
                subject: "opaque-主体".into(),
            },
            registry: Digest::of(&(
                "day2-restore-registry-selection-v1",
                d("held file"),
                Digest::of(&instance)?,
                registry.content_digest()?,
                &context.authority,
            ))?,
            credential: Digest::new(&[1, 2, 3]),
            assertion: d("genuine approval assertion DATA"),
            signing_key: signing.commitment()?,
        },
        signature: String::new(),
    };
    sign(&mut signed)?;
    Ok((instance, context, signed, authenticator))
}

#[test]
fn current_grant_checks_approver_and_executor_separately_against_real_signatures() -> Result<()> {
    let (instance, context, signed, authenticator) = data()?;
    approval_record(&instance, &context, Digest::new(b"held file"), &signed)?;
    let executor = executor_record(
        &instance,
        &context,
        Digest::new(b"held file"),
        &authenticator.key.record.credential_id,
        &signed,
    )?;
    assert_eq!(
        executor.credential_id,
        authenticator.key.record.credential_id
    );
    assert_eq!(
        executor.admin,
        Digest::of(&(
            "day2-restore-registry-admin-v1",
            &context.scope,
            &signed.statement.request.executor.email,
            &signed.statement.request.executor.subject,
            &context.authority
        ))?
    );
    // The approver's valid key is not the executor's authentication.
    assert!(
        executor_record(
            &instance,
            &context,
            Digest::new(b"held file"),
            &[1, 2, 3],
            &signed
        )
        .is_err()
    );
    for change in 0..8 {
        let mut wrong = signed.clone();
        match change {
            0 => wrong.statement.approver.subject = "different-subject".into(),
            1 => wrong.statement.approver.email = context.executor.clone(),
            2 => wrong.statement.registry = Digest::new(b"other registry"),
            3 => wrong.statement.credential = Digest::new(b"removed credential"),
            4 => wrong.statement.signing_key = Digest::new(b"other signing version"),
            5 => wrong.statement.request.executor.subject = "different-executor-subject".into(),
            6 => wrong.statement.request.executor.email = context.approver.clone(),
            _ => wrong.statement.request.target.scope.app = "other-app".to_owned().try_into()?,
        }
        // Re-sign the wrong DATA with the valid fixture approval key: the
        // current selection checks, not merely a signature failure, must deny.
        sign(&mut wrong)?;
        let mut actual = ControllerRegistryData {
            operation: wrong.statement.request.intent().commitment()?,
            ..context.clone_for_test()
        };
        actual.instance = Digest::of(&instance)?;
        assert!(
            executor_record(
                &instance,
                &actual,
                Digest::new(b"held file"),
                &authenticator.key.record.credential_id,
                &wrong
            )
            .is_err()
        );
    }
    Ok(())
}

// Context projection DATA only. It constructs no reader or authentication.
impl ControllerRegistryData {
    fn clone_for_test(&self) -> Self {
        Self {
            selector: self.selector.clone(),
            instance: self.instance.clone(),
            scope: self.scope.clone(),
            app: self.app.clone(),
            artifact: self.artifact.clone(),
            authority: self.authority.clone(),
            operation: self.operation.clone(),
            approver: self.approver.clone(),
            executor: self.executor.clone(),
        }
    }
}

#[test]
fn removing_either_key_or_changing_current_policy_file_or_signer_refuses_old_grant() -> Result<()> {
    let (instance, context, signed, authenticator) = data()?;
    for change in 0..9 {
        let mut now = instance.clone();
        let mut actual = context.clone_for_test();
        let mut binding = Digest::new(b"held file");
        match change {
            0=>{now.control.as_mut().unwrap().restore_passkeys.as_mut().unwrap().keys.remove(&Name::try_from("primary".to_owned())?);},
            1=>{now.control.as_mut().unwrap().restore_passkeys.as_mut().unwrap().keys.remove(&Name::try_from("executor".to_owned())?);},
            2=>now.control.as_mut().unwrap().restore_approval_signing=None,
            3=>now.control.as_mut().unwrap().restore_approval_signing.as_mut().unwrap().version=
                "projects/approval-project/locations/global/keyRings/restore/cryptoKeys/approval/cryptoKeyVersions/8".to_owned().try_into()?,
            4=>now.control.as_mut().unwrap().restore_approval_signing.as_mut().unwrap().public_key=[77;32],
            5=>actual.approver=actual.executor.clone(),
            6=>actual.executor=actual.approver.clone(),
            7=>actual.authority.revision+=1,
            _=>binding=Digest::new(b"replaced actual config file"),
        }
        actual.instance = Digest::of(&now)?;
        assert!(
            executor_record(
                &now,
                &actual,
                binding,
                &authenticator.key.record.credential_id,
                &signed
            )
            .is_err()
        );
    }
    let mut corrupt = signed.clone();
    corrupt.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(approval_record(&instance, &context, Digest::new(b"held file"), &corrupt).is_err());
    Ok(())
}

#[test]
fn the_same_admin_may_approve_and_authenticate_execution_with_the_same_key() -> Result<()> {
    let (instance, mut context, mut signed, _) = data()?;
    signed.statement.request.executor = signed.statement.approver.clone();
    context.executor = context.approver.clone();
    context.operation = signed.statement.request.intent().commitment()?;
    sign(&mut signed)?;
    let selected = executor_record(
        &instance,
        &context,
        Digest::new(b"held file"),
        &[1, 2, 3],
        &signed,
    )?;
    assert_eq!(selected.credential_id, [1, 2, 3]);
    Ok(())
}

#[test]
fn execution_challenge_requires_uv_and_cannot_reuse_approval_or_another_operation() -> Result<()> {
    let (instance, context, signed, mut authenticator) = data()?;
    let operation = Digest::new(b"actual execution");
    authenticator.key.record = executor_record(
        &instance,
        &context,
        Digest::new(b"held file"),
        &authenticator.key.record.credential_id,
        &signed,
    )?;
    authenticator.challenge.request = execution_request(&signed, &operation)?;
    authenticator.challenge.enrollment = authenticator.key.binding()?;
    let correct = authenticator.assertion(1, 0x0d);
    let execution = authenticator.challenge.request.clone();
    authenticator.challenge.request = signed.statement.request.intent().commitment()?;
    let approval_assertion = authenticator.assertion(1, 0x0d);
    authenticator.challenge.request = execution;
    let verify = |a: &Assertion, expected: &Digest, counter| {
        crate::security_epoch::restore_webauthn::verify(
            &authenticator.key,
            &authenticator.challenge,
            expected,
            counter,
            a,
        )
    };
    verify(&correct, &authenticator.challenge.request, 0)?;
    assert!(
        verify(
            &authenticator.assertion(1, 0x09),
            &authenticator.challenge.request,
            0
        )
        .is_err()
    );
    assert!(verify(&correct, &authenticator.challenge.request, 1).is_err());
    for expected in [
        signed.statement.request.intent().commitment()?,
        execution_request(&signed, &Digest::new(b"other execution"))?,
    ] {
        assert!(verify(&correct, &expected, 0).is_err());
    }
    let mut altered = signed.clone();
    altered.statement.assertion = Digest::new(b"other approval assertion");
    sign(&mut altered)?;
    assert_ne!(
        execution_request(&signed, &operation)?,
        execution_request(&altered, &operation)?
    );
    // An actually valid assertion over the approval challenge has the same
    // key and counter but cannot be the execution assertion.
    assert!(verify(&approval_assertion, &authenticator.challenge.request, 0).is_err());
    Ok(())
}

fn wiring(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    struct Calls(Vec<String>, Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if node.path.is_ident("ensure") {
                let arguments =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(node.tokens.clone())
                        .unwrap();
                for expression in &arguments {
                    self.visit_expr(expression);
                }
            }
            syn::visit::visit_macro(self, node);
        }

        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            syn::visit::visit_expr_struct(self, node);
            self.0
                .push(node.path.segments.last().unwrap().ident.to_string());
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            syn::visit::visit_expr_method_call(self, node);
            self.0.push(node.method.to_string());
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            syn::visit::visit_expr_call(self, node);
            if let syn::Expr::Path(path) = node.func.as_ref() {
                let name = path.path.segments.last().unwrap().ident.to_string();
                if name == "complete" {
                    self.1.push(
                        node.args
                            .iter()
                            .map(|arg| arg.to_token_stream().to_string())
                            .collect::<Vec<_>>()
                            .join(" | "),
                    );
                }
                self.0.push(name);
            }
        }
    }
    let mut methods = std::collections::BTreeMap::new();
    let mut complete = Vec::new();
    for item in &file.items {
        if let syn::Item::Fn(function) = item {
            // The same real verified-row SQL unit is now a free helper used
            // by both closed Active/Fenced borrowers, not a second verifier.
            let mut calls = Calls(Vec::new(), Vec::new());
            calls.visit_block(&function.block);
            complete.extend(calls.1);
            methods.insert(function.sig.ident.to_string(), calls.0);
        }
        if let syn::Item::Impl(item) = item {
            for member in &item.items {
                if let syn::ImplItem::Fn(method) = member {
                    let mut calls = Calls(Vec::new(), Vec::new());
                    calls.visit_block(&method.block);
                    complete.extend(calls.1);
                    methods.insert(method.sig.ident.to_string(), calls.0);
                }
            }
        }
    }
    let ordered = |method: &str, required: &[&str]| -> bool {
        let Some(calls) = methods.get(method) else {
            return false;
        };
        let mut at = 0;
        for item in required {
            let Some(found) = calls[at..].iter().position(|c| c == item) else {
                return false;
            };
            at += found + 1;
        }
        true
    };
    ordered(
        "issue_durable",
        &[
            "observe",
            "check_sqlite",
            "transaction_with_behavior",
            "issue",
            "check_sqlite",
            "commit",
            "check_sqlite",
            "check_authentication_sqlite",
            "check_registry_local",
            "observe",
            "refuse",
        ],
    ) && ordered(
        "complete_durable",
        &[
            "begin_attempt",
            "observe",
            "complete",
            "check_authentication_sqlite",
            "check_registry_local",
            "observe",
            "settle_verification",
            "refuse",
            "counter_data",
            "completion_snapshot",
            "from_ref",
            "ExecutionCompletion",
        ],
    ) && ordered(
        "completion_snapshot",
        &[
            "observe",
            "Active",
            "AuthenticationBorrow",
            "TrustedKey",
            "verified_completion_snapshot",
            "check_authentication_sqlite",
            "check_registry_local",
            "observe",
            "refuse",
        ],
    ) && ordered(
        "verified_completion_snapshot",
        &[
            "check_sqlite",
            "transaction",
            "verified_snapshot",
            "check_sqlite",
            "commit",
            "check_sqlite",
        ],
    ) && ordered(
        "check_fenced",
        &[
            "eq",
            "observe",
            "Fenced",
            "AuthenticationBorrow",
            "TrustedKey",
            "verified_completion_snapshot",
            "check_authentication_sqlite",
            "check_local",
            "observe",
            "refuse",
        ],
    ) && ordered(
        "check_current",
        &["eq", "completion_snapshot", "set", "refuse"],
    ) && source.contains("let Some (facts) = result ? else")
        && source.contains("current . 0 == self . version && current . 1 == self . snapshot")
        && complete == ["db | & key | id | & self . ceremony . request | at | assertion"]
}

#[test]
fn actual_execution_units_keep_opaque_native_loan_commit_postchecks_and_purpose() {
    let source = syn::parse_file(include_str!("../execution.rs"))
        .unwrap()
        .to_token_stream()
        .to_string();
    assert!(wiring(&source));
    for (before, after) in [
        ("self . ceremony . begin_attempt () ? ;", ""),
        (
            "verified_completion_snapshot (db , & key , & challenge , counter)",
            "unreachable!()",
        ),
        (
            "verified_completion_snapshot (db , & key , & challenge , self . counter)",
            "unreachable!()",
        ),
        (
            "AuthenticationReader :: Fenced (& mut * reader)",
            "AuthenticationReader :: Active (& mut * reader)",
        ),
        (
            "let native = reader . check_local () ;",
            "let native = Ok (()) ;",
        ),
        ("key . check_sqlite (& tx) ? ;", ""),
        (
            "let checked = key . check_sqlite (db) ;",
            "let checked = Ok (()) ;",
        ),
        (
            "let native = reader . check_registry_local () ;",
            "let native = Ok (()) ;",
        ),
        (
            "& self . ceremony . request , at , assertion",
            "& self . signed . statement . request . intent () . commitment () ? , at , assertion",
        ),
        (
            "let Some (facts) = result ? else",
            "let Some (facts) = Some (unsafe_facts ()) else",
        ),
        (
            "std :: ptr :: eq (self . database , std :: ptr :: from_ref (db))",
            "true",
        ),
        (
            "current . 0 == self . version && current . 1 == self . snapshot",
            "true",
        ),
        ("self . ceremony . ceremony . refused . set (true) ;", ""),
    ] {
        assert!(source.contains(before));
        assert!(!wiring(&source.replace(before, after)), "{before}");
    }
}
