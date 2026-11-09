//! Synthetic signed DATA only. No native issuer, parent, receiver, clock,
//! file/P3/keeper or serving owner is constructed by these fixtures.
use super::*;
use serde_json::{Value, json};
use std::time::Duration;

struct Fixture {
    policy: EnrollmentPolicy,
    certificate: IssuerCertificate,
    issuer: KeyOwner,
    authorization: SignedRestoreAuthorization,
    admission: SignedRestoreAdmission,
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

fn fixture() -> Result<Fixture> {
    let root = KeyOwner::generate()?;
    let issuer = KeyOwner::generate()?;
    let app = KeyOwner::generate()?;
    let policy = super::super::tests::policy(&root);
    let data = IssuerData {
        policy: policy.digest()?,
        root_version: policy.root.version.clone(),
        nonce: Digest::new(b"restore-codec-issuer"),
        public_key: issuer.public(),
        process: process(policy.issuer_code.clone()),
        provisioner: process(policy.provisioner_code.clone()),
    };
    let certificate = IssuerCertificate {
        signature: root.sign("issuer-birth", &data)?,
        data,
    };
    let f = crate::security_epoch::kernel::restore::writer::tests::fixture(1700, true)?;
    ensure!(
        f.selected == policy.store,
        "restore_codec_fixture_selection"
    );
    let terminal = serde_json::to_value(&f.before.terminal.value)?;
    let report = serde_json::from_value(terminal["disposition"]["completed"]["report"].clone())?;
    let data = RestoreAuthorizationData {
        issuer: certificate.digest()?,
        policy: policy.digest()?,
        frozen: Digest::new(b"synthetic-frozen-cohort"),
        controller: Digest::new(b"synthetic-controller-stage"),
        operation: f.request.operation().clone(),
        approval: f.authority.grant.approval.commitment()?,
        grant: f.before.consumed.value.grant_id_data().clone(),
        intent: f.authority.grant.intent.clone(),
        full_archive: f.authority.grant.approval.full_archive_digest.clone(),
        desired_instance: Digest::new(b"synthetic-admitted-current-instance"),
        target: f.authority.target.clone(),
        report,
        terminal: Digest::of(&f.before.terminal.value)?,
        terminal_version: f.before.terminal.version.clone(),
        records: f.before.commitment_data()?,
        parent_clock: Digest::new(b"synthetic-parent-clock"),
        parent_origin_ns: 1_000_000_000,
        parent_deadline_ns: 6_000_000_000,
    };
    let statement = RestoreAuthorizationStatement {
        data,
        request: Digest::new(b"prepare-request"),
        challenge: Digest::new(b"prepare-challenge"),
        effective_deadline_ns: 5_500_000_000,
    };
    let authorization = SignedRestoreAuthorization {
        signature: issuer.sign("restore-controller-authorized-v1", &statement)?,
        statement,
    };
    let workload = policy.workload(NativeRole::AppHost);
    let mut peer = process(policy.code(NativeRole::AppHost).clone());
    peer.process = 73;
    peer.start_ticks = 124;
    let statement = RestoreAdmissionStatement {
        issuer: certificate.digest()?,
        policy: policy.digest()?,
        authorization: authorization.digest_data()?,
        process: peer,
        runtime: RuntimeBinding {
            container: crate::security_epoch::runtime_profile::ContainerFacts {
                pod_name: workload.workload.name.clone(),
                pod_uid: "new-restore-pod".into(),
                node_name: policy.runtime.node_name.clone(),
                container_name: workload.container.name.clone(),
                container_id: "a".repeat(64),
                image: workload.container.image.clone(),
                restart_count: 0,
            },
            node_uid: policy.runtime.node_uid.clone(),
            boot: "boot-one".into(),
        },
        public_key: app.public(),
        request: Digest::new(b"app-request"),
        challenge: Digest::new(b"app-challenge"),
        receiver_clock: Digest::new(b"synthetic-receiver-clock"),
        receiver_origin_ns: 1_500_000_000,
        receiver_deadline_ns: 6_500_000_000,
        effective_deadline_ns: 5_000_000_000,
    };
    let admission = SignedRestoreAdmission {
        signature: issuer.sign("restore-app-admission-v1", &statement)?,
        statement,
    };
    Ok(Fixture {
        policy,
        certificate,
        issuer,
        authorization,
        admission,
    })
}

fn packets(f: &Fixture) -> Vec<Packet> {
    let authorization = &f.authorization;
    let client = RestoreAppRequest {
        public_key: f.admission.statement.public_key.clone(),
        request: f.admission.statement.request.clone(),
        receiver_clock: f.admission.statement.receiver_clock.clone(),
        receiver_origin_ns: f.admission.statement.receiver_origin_ns,
        receiver_deadline_ns: f.admission.statement.receiver_deadline_ns,
    };
    let mut packets = vec![
        Packet::RestorePrepareHello {
            authorization: Box::new(authorization.statement.data.clone()),
            request: authorization.statement.request.clone(),
        },
        Packet::RestorePrepareNonce {
            authorization: authorization.statement.data.digest_data().unwrap(),
            request: authorization.statement.request.clone(),
            challenge: authorization.statement.challenge.clone(),
        },
        Packet::RestorePrepareBind {
            authorization: Box::new(authorization.statement.data.clone()),
            request: authorization.statement.request.clone(),
            challenge: authorization.statement.challenge.clone(),
            signature: "fixture-controller-signature".into(),
        },
        Packet::RestorePrepareGrant {
            authorization: Box::new(authorization.clone()),
        },
        Packet::RestoreAppHello {
            request: Box::new(client.clone()),
        },
        Packet::RestoreAppNonce {
            certificate: f.certificate.clone(),
            authorization: Box::new(f.authorization.clone()),
            request: client.request.clone(),
            challenge: f.admission.statement.challenge.clone(),
        },
        Packet::RestoreAppBind {
            authorization: f.authorization.digest_data().unwrap(),
            request: Box::new(client),
            challenge: f.admission.statement.challenge.clone(),
            signature: "fixture-app-signature".into(),
        },
        Packet::RestoreAppGrant {
            certificate: f.certificate.clone(),
            admission: Box::new(f.admission.clone()),
        },
    ];
    let (_, completion, signed) = completion_fixture(f).unwrap();
    packets.extend([
        Packet::RestoreFinishHello {
            completion: Box::new(completion.clone()),
            request: signed.statement.request.clone(),
        },
        Packet::RestoreFinishNonce {
            completion: completion.digest_data().unwrap(),
            request: signed.statement.request.clone(),
            challenge: signed.statement.challenge.clone(),
        },
        Packet::RestoreFinishBind {
            completion: Box::new(completion),
            request: signed.statement.request.clone(),
            challenge: signed.statement.challenge.clone(),
            signature: "fixture-controller-finish-signature".into(),
        },
        Packet::RestoreFinishGrant {
            completion: Box::new(signed),
        },
    ]);
    packets
}

fn completion_fixture(
    f: &Fixture,
) -> Result<(
    super::super::restore_peer_wire::RestoreAppStatement,
    RestoreIssuerCompletionData,
    SignedRestoreIssuerCompletion,
)> {
    let mut admission = f.admission.clone();
    // Synthetic signed DATA, with the existing runtime metadata syntax. No
    // native process, acquisition, kernel handle or keeper is manufactured.
    admission.statement.runtime.container.container_id = format!("containerd://{}", "a".repeat(64));
    admission.signature = f
        .issuer
        .sign("restore-app-admission-v1", &admission.statement)?;
    let app = super::super::restore_peer_wire::RestoreAppStatement {
        certificate: f.certificate.clone(),
        authorization: f.authorization.clone(),
        original: super::super::restore_peer_wire::RestoreOriginal {
            domain: admission.statement.receiver_clock.clone(),
            origin_ns: admission.statement.receiver_origin_ns,
            deadline_ns: admission.statement.effective_deadline_ns,
        },
        admission,
    };
    let data = RestoreIssuerCompletionData {
        frozen: f.authorization.statement.data.frozen.clone(),
        authorization: f.authorization.digest_data()?,
        app: app.digest()?,
        activation: Digest::new(b"synthetic-final-activation"),
        cohort: super::super::storage_peer_wire::SqliteCohort::from_identities(
            (9, 11),
            (9, 12),
            (9, 13),
        )?,
    };
    let statement = RestoreIssuerCompletionStatement {
        data: data.clone(),
        request: Digest::new(b"finish-request"),
        challenge: Digest::new(b"finish-challenge"),
        effective_deadline_ns: 4_500_000_000,
    };
    let signed = SignedRestoreIssuerCompletion {
        signature: f.issuer.sign("restore-issuer-completed-v1", &statement)?,
        statement,
    };
    Ok((app, data, signed))
}

#[test]
fn completion_signature_binds_exact_restore_app_activation_and_file_cohort_without_renewal()
-> Result<()> {
    let f = fixture()?;
    let (app, expected, signed) = completion_fixture(&f)?;
    let now = Duration::from_secs(2);
    signed.verify_data(&f.policy, &f.certificate, &expected, &app, now)?;
    for field in ["frozen", "authorization", "app", "activation", "cohort"] {
        let mut value = serde_json::to_value(&signed)?;
        value["statement"]["data"][field] = if field == "cohort" {
            serde_json::to_value(
                super::super::storage_peer_wire::SqliteCohort::from_identities(
                    (9, 21),
                    (9, 22),
                    (9, 23),
                )?,
            )?
        } else {
            serde_json::to_value(Digest::new(field.as_bytes()))?
        };
        let mut changed: SignedRestoreIssuerCompletion = serde_json::from_value(value)?;
        // Even a valid issuer signature cannot substitute a different actual
        // expected peer/activation/cohort binding supplied by the native caller.
        changed.signature = f
            .issuer
            .sign("restore-issuer-completed-v1", &changed.statement)?;
        assert!(
            changed
                .verify_data(&f.policy, &f.certificate, &expected, &app, now)
                .is_err(),
            "{field}"
        );
    }
    for instant in [
        Duration::from_secs(1),
        Duration::from_nanos(4_500_000_000),
        Duration::from_secs(5),
    ] {
        assert!(
            signed
                .verify_data(&f.policy, &f.certificate, &expected, &app, instant)
                .is_err()
        );
    }
    let mut extended = signed.clone();
    extended.statement.effective_deadline_ns = 5_000_000_001;
    extended.signature = f
        .issuer
        .sign("restore-issuer-completed-v1", &extended.statement)?;
    assert!(
        extended
            .verify_data(&f.policy, &f.certificate, &expected, &app, now)
            .is_err()
    );
    let mut foreign = signed.clone();
    foreign.signature = f.issuer.sign("role-stage", &foreign.statement)?;
    assert!(
        foreign
            .verify_data(&f.policy, &f.certificate, &expected, &app, now)
            .is_err()
    );
    Ok(())
}

#[test]
fn final_completion_wire_rejects_missing_duplicate_unknown_and_sequence_records() -> Result<()> {
    let f = fixture()?;
    let (_, _, signed) = completion_fixture(&f)?;
    let packet = Packet::RestoreFinishGrant {
        completion: Box::new(signed),
    };
    let value = serde_json::to_value(&packet)?;
    for path in [
        "/completion",
        "/completion/statement",
        "/completion/statement/data",
        "/completion/statement/data/cohort",
    ] {
        for replacement in [Value::Null, json!([]), json!({"unknown":true})] {
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = replacement;
            assert!(decode(&serde_json::to_vec(&changed)?).is_err(), "{path}");
        }
    }
    for field in ["frozen", "authorization", "app", "activation", "cohort"] {
        let mut changed = value.clone();
        changed
            .pointer_mut("/completion/statement/data")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(decode(&serde_json::to_vec(&changed)?).is_err(), "{field}");
    }
    let bytes = serde_json::to_vec(&value)?;
    assert!(bytes.len() <= MAX_PACKET);
    let text = String::from_utf8(bytes)?;
    let duplicate = text.replacen("\"activation\":", "\"activation\":null,\"activation\":", 1);
    assert!(decode(duplicate.as_bytes()).is_err());
    Ok(())
}

#[test]
fn distinct_restore_codec_roundtrips_without_a_stage_purpose_or_native_owner() -> Result<()> {
    let f = fixture()?;
    let now = Duration::from_secs(2);
    f.authorization
        .verify_data(&f.policy, &f.certificate, now)?;
    f.admission
        .verify_data(&f.policy, &f.certificate, &f.authorization, now)?;
    for packet in packets(&f) {
        let bytes = serde_json::to_vec(&packet)?;
        assert!(bytes.len() <= MAX_PACKET);
        let decoded = decode(&bytes)?;
        assert_eq!(
            serde_json::to_value(decoded)?,
            serde_json::to_value(packet)?
        );
    }
    let mut wrong = f.admission.clone();
    wrong.signature = f.issuer.sign("role-stage", &wrong.statement)?;
    assert!(
        wrong
            .verify_data(&f.policy, &f.certificate, &f.authorization, now)
            .is_err()
    );
    let mut value = serde_json::to_value(Packet::RestoreAppGrant {
        certificate: f.certificate.clone(),
        admission: Box::new(f.admission),
    })?;
    value["kind"] = json!("stage_grant");
    assert!(decode(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn desired_instance_is_mandatory_signed_and_bound_to_the_exact_app_admission() -> Result<()> {
    let f = fixture()?;
    let now = Duration::from_secs(2);
    let original = serde_json::to_value(&f.authorization)?;
    for cut in 0..3 {
        let mut changed = original.clone();
        let data = changed["statement"]["data"].as_object_mut().unwrap();
        match cut {
            0 => {
                data.remove("desired_instance");
            }
            1 => {
                data.insert("desired_instance".into(), Value::Null);
            }
            _ => {
                data.insert("desired_instance".into(), json!([]));
            }
        }
        assert!(
            crate::json::decode::<SignedRestoreAuthorization>(&serde_json::to_vec(&changed)?)
                .is_err()
        );
    }
    let mut substituted = f.authorization.clone();
    substituted.statement.data.desired_instance = Digest::new(b"different-current-instance");
    assert!(
        substituted
            .verify_data(&f.policy, &f.certificate, now)
            .is_err()
    );
    // Even an independently signed different selection cannot be substituted
    // beneath the already issued App admission. This is DATA binding only;
    // the real App additionally retains and checks its actual selected file.
    substituted.signature = f
        .issuer
        .sign("restore-controller-authorized-v1", &substituted.statement)?;
    substituted.verify_data(&f.policy, &f.certificate, now)?;
    assert!(
        f.admission
            .verify_data(&f.policy, &f.certificate, &substituted, now)
            .is_err()
    );
    let raw = serde_json::to_string(&f.authorization)?;
    assert_eq!(raw.matches("\"desired_instance\":").count(), 1);
    let duplicate = raw.replacen(
        "\"desired_instance\":",
        "\"desired_instance\":null,\"desired_instance\":",
        1,
    );
    assert!(crate::json::decode::<SignedRestoreAuthorization>(duplicate.as_bytes()).is_err());
    for packet in packets(&f) {
        let bytes = serde_json::to_vec(&packet)?;
        assert!(bytes.len() <= MAX_PACKET);
        decode(&bytes)?;
    }
    Ok(())
}

#[test]
fn validly_signed_restore_data_cannot_expand_parent_receiver_or_exact_target_bounds() -> Result<()>
{
    let f = fixture()?;
    let now = Duration::from_secs(2);
    for cut in 0..9 {
        let mut changed = f.authorization.clone();
        match cut {
            0 => changed.statement.data.target.binding_generation = 0,
            1 => changed.statement.data.target.security_epoch = 1,
            2 => changed.statement.data.target.selection = Digest::new(b"other-selection"),
            3 => changed.statement.data.report.target_incarnation = Digest::new(b"other-target"),
            4 => changed.statement.data.report.schema = Digest::new(b"other-schema"),
            5 => {
                changed.statement.data.parent_deadline_ns =
                    changed.statement.data.parent_origin_ns + 5_000_000_001
            }
            6 => changed.statement.data.parent_origin_ns = 2_000_000_001,
            7 => changed.statement.effective_deadline_ns = 6_000_000_001,
            _ => changed.statement.effective_deadline_ns = 2_000_000_000,
        }
        changed.signature = f
            .issuer
            .sign("restore-controller-authorized-v1", &changed.statement)?;
        assert!(
            changed.verify_data(&f.policy, &f.certificate, now).is_err(),
            "authorization cut {cut}"
        );
    }
    for cut in 0..8 {
        let mut changed = f.admission.clone();
        match cut {
            0 => changed.statement.authorization = Digest::new(b"other-authorization"),
            1 => changed.statement.process.code = Digest::new(b"other-code"),
            2 => changed.statement.receiver_origin_ns = changed.statement.receiver_deadline_ns,
            3 => {
                changed.statement.receiver_deadline_ns =
                    changed.statement.receiver_origin_ns + 5_000_000_001
            }
            4 => changed.statement.effective_deadline_ns = 6_000_000_000,
            5 => changed.statement.effective_deadline_ns = 2_000_000_000,
            6 => changed.statement.receiver_origin_ns = 2_000_000_001,
            _ => changed.statement.public_key = "invalid-key".into(),
        }
        changed.signature = f
            .issuer
            .sign("restore-app-admission-v1", &changed.statement)?;
        assert!(
            changed
                .verify_data(&f.policy, &f.certificate, &f.authorization, now)
                .is_err(),
            "admission cut {cut}"
        );
    }
    assert!(
        f.admission
            .verify_data(
                &f.policy,
                &f.certificate,
                &f.authorization,
                Duration::from_secs(5)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn restore_packets_reject_nested_arrays_unknown_duplicate_and_oversize_input() -> Result<()> {
    let f = fixture()?;
    for packet in packets(&f) {
        let value = serde_json::to_value(packet)?;
        let mut unknown = value.clone();
        unknown["unexpected"] = json!(true);
        assert!(decode(&serde_json::to_vec(&unknown)?).is_err());
        let raw = serde_json::to_string(&value)?;
        let duplicate = raw.replacen("\"kind\":", "\"kind\":\"unknown\",\"kind\":", 1);
        assert_ne!(raw, duplicate);
        assert!(decode(duplicate.as_bytes()).is_err());
        for path in [
            "/authorization",
            "/authorization/target",
            "/authorization/target/scope",
            "/authorization/report",
            "/authorization/statement",
            "/authorization/statement/data",
            "/request",
            "/admission",
            "/admission/statement",
            "/admission/statement/process",
            "/admission/statement/process/namespaces",
            "/admission/statement/runtime",
            "/admission/statement/runtime/container",
            "/certificate",
            "/certificate/data",
        ] {
            if value.pointer(path).is_some_and(Value::is_object) {
                let mut changed = value.clone();
                *changed.pointer_mut(path).unwrap() = json!([]);
                assert!(
                    decode(&serde_json::to_vec(&changed)?).is_err(),
                    "map boundary {path}"
                );
            }
        }
    }
    assert!(decode(&vec![b' '; MAX_PACKET + 1]).is_err());
    Ok(())
}

#[test]
fn complete_positional_records_that_serde_would_accept_are_refused_by_actual_decoder() -> Result<()>
{
    let f = fixture()?;
    let authorization = &[
        "issuer",
        "policy",
        "frozen",
        "controller",
        "operation",
        "approval",
        "grant",
        "intent",
        "full_archive",
        "desired_instance",
        "target",
        "report",
        "terminal",
        "terminal_version",
        "records",
        "parent_clock",
        "parent_origin_ns",
        "parent_deadline_ns",
    ][..];
    let target = &[
        "scope",
        "binding_generation",
        "authority",
        "selection",
        "incarnation",
        "security_epoch",
        "artifact",
        "schema",
    ][..];
    let scope = &["installation", "environment", "app"][..];
    let report = &[
        "intent",
        "archive",
        "target_incarnation",
        "target_epoch",
        "image",
        "schema",
        "artifact",
        "reset_observation",
    ][..];
    let process = &["process", "start_ticks", "code", "boot", "namespaces"][..];
    let records: &[(&str, &[&str])] = &[
        ("/authorization", authorization),
        ("/authorization", &["statement", "signature"]),
        ("/authorization/target", target),
        ("/authorization/target/scope", scope),
        ("/authorization/report", report),
        (
            "/authorization/statement",
            &["data", "request", "challenge", "effective_deadline_ns"],
        ),
        ("/authorization/statement/data", authorization),
        ("/authorization/statement/data/target", target),
        ("/authorization/statement/data/target/scope", scope),
        ("/authorization/statement/data/report", report),
        (
            "/request",
            &[
                "public_key",
                "request",
                "receiver_clock",
                "receiver_origin_ns",
                "receiver_deadline_ns",
            ],
        ),
        ("/admission", &["statement", "signature"]),
        (
            "/admission/statement",
            &[
                "issuer",
                "policy",
                "authorization",
                "process",
                "runtime",
                "public_key",
                "request",
                "challenge",
                "receiver_clock",
                "receiver_origin_ns",
                "receiver_deadline_ns",
                "effective_deadline_ns",
            ],
        ),
        ("/admission/statement/process", process),
        (
            "/admission/statement/runtime",
            &["container", "node_uid", "boot"],
        ),
        (
            "/admission/statement/runtime/container",
            &[
                "pod_name",
                "pod_uid",
                "node_name",
                "container_name",
                "container_id",
                "image",
                "restart_count",
            ],
        ),
        ("/certificate", &["data", "signature"]),
        (
            "/certificate/data",
            &[
                "policy",
                "root_version",
                "nonce",
                "public_key",
                "process",
                "provisioner",
            ],
        ),
        ("/certificate/data/process", process),
        ("/certificate/data/provisioner", process),
    ];
    let mut exercised = std::collections::BTreeSet::new();
    for packet in packets(&f) {
        let value = serde_json::to_value(packet)?;
        for (path, fields) in records {
            let Some(Value::Object(record)) = value.pointer(path) else {
                continue;
            };
            // The same path has a DATA record in PrepareHello/Bind and a
            // distinct signed envelope in PrepareGrant; exercise both.
            if !fields.iter().all(|field| record.contains_key(*field)) {
                continue;
            }
            assert_eq!(fields.len(), record.len());
            let positional =
                Value::Array(fields.iter().map(|field| record[*field].clone()).collect());
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = positional;
            // Prove these are complete alternate shapes, not empty arrays
            // rejected independently by serde's missing-field checks.
            assert!(
                serde_json::from_value::<Packet>(changed.clone()).is_ok(),
                "complete sequence {path}"
            );
            assert!(
                decode(&serde_json::to_vec(&changed)?).is_err(),
                "actual closed decoder {path}"
            );
            exercised.insert((*path, fields.len()));
        }
    }
    assert_eq!(exercised.len(), records.len());
    let packet = packets(&f)
        .into_iter()
        .find(|packet| matches!(packet, Packet::RestoreAppHello { .. }))
        .unwrap();
    let raw = serde_json::to_string(&packet)?;
    let clock = serde_json::to_string(&f.admission.statement.receiver_clock)?;
    let changed = raw.replacen(
        "\"receiver_clock\":",
        &format!("\"receiver_clock\":{clock},\"receiver_clock\":"),
        1,
    );
    assert_ne!(raw, changed);
    assert!(serde_json::from_str::<Value>(&changed).is_ok());
    assert!(decode(changed.as_bytes()).is_err());
    Ok(())
}

fn role_activation_fixture(
    f: &Fixture,
) -> Result<(
    super::super::restore_peer_wire::RestoreAppStatement,
    SignedRestoreIssuerCompletion,
    SignedRestoreRoleActivation,
)> {
    let (app, _, completion) = completion_fixture(f)?;
    let request = Digest::new(b"final-role-request");
    let challenge = Digest::new(b"final-role-challenge");
    let data = StageData {
        issuer: f.certificate.digest()?,
        policy: f.policy.digest()?,
        role: NativeRole::AppHost,
        purpose: StagePurpose::CurrentRole,
        public_key: app.admission.statement.public_key.clone(),
        challenge: challenge.clone(),
        request: request.clone(),
        process: app.admission.statement.process.clone(),
        runtime: app.admission.statement.runtime.clone(),
        origin_ns: app.original.origin_ns,
        deadline_ns: 4_000_000_000,
    };
    let stage = SignedStage {
        signature: f.issuer.sign("role-stage", &data)?,
        data,
    };
    let statement = RestoreRoleActivationStatement {
        completion: completion.digest_data()?,
        stage,
        request,
        challenge,
        effective_deadline_ns: 4_000_000_000,
    };
    let signed = SignedRestoreRoleActivation {
        signature: f.issuer.sign("restore-app-role-activated-v1", &statement)?,
        statement,
    };
    Ok((app, completion, signed))
}

#[test]
fn final_role_data_binds_existing_app_key_process_runtime_completion_and_original_ceiling()
-> Result<()> {
    let f = fixture()?;
    let (app, completion, signed) = role_activation_fixture(&f)?;
    let request = &signed.statement.request;
    let challenge = &signed.statement.challenge;
    signed.verify_data(
        &f.policy,
        &f.certificate,
        &completion,
        &app,
        (request, challenge),
        Duration::from_secs(2),
    )?;
    let digest = || serde_json::to_value(Digest::new(b"foreign-role-binding")).unwrap();
    let changes = [
        ("/completion", digest()),
        ("/request", digest()),
        ("/challenge", digest()),
        ("/stage/data/request", digest()),
        ("/stage/data/challenge", digest()),
        ("/stage/data/issuer", digest()),
        ("/stage/data/policy", digest()),
        (
            "/stage/data/role",
            serde_json::to_value(NativeRole::EpochController)?,
        ),
        (
            "/stage/data/purpose",
            serde_json::to_value(StagePurpose::StorageBootstrap)?,
        ),
        (
            "/stage/data/public_key",
            json!(KeyOwner::generate()?.public()),
        ),
        ("/stage/data/process/process", json!(7001)),
        ("/stage/data/process/start_ticks", json!(7002)),
        ("/stage/data/process/code", digest()),
        ("/stage/data/process/boot", json!("other-boot")),
        ("/stage/data/process/namespaces/time", json!([70, 90])),
        ("/stage/data/runtime/container/pod_uid", json!("other-pod")),
        ("/stage/data/runtime/node_uid", json!("other-node")),
        ("/stage/data/runtime/boot", json!("other-runtime-boot")),
        ("/stage/data/origin_ns", json!(1_600_000_000u64)),
        ("/stage/data/deadline_ns", json!(4_500_000_001u64)),
        ("/effective_deadline_ns", json!(4_500_000_001u64)),
    ];
    for (path, value) in changes {
        let mut changed = serde_json::to_value(&signed.statement)?;
        *changed.pointer_mut(path).unwrap() = value;
        let mut statement: RestoreRoleActivationStatement = serde_json::from_value(changed)?;
        statement.stage.signature = f.issuer.sign("role-stage", &statement.stage.data)?;
        let changed = SignedRestoreRoleActivation {
            signature: f.issuer.sign("restore-app-role-activated-v1", &statement)?,
            statement,
        };
        ensure!(
            changed
                .verify_data(
                    &f.policy,
                    &f.certificate,
                    &completion,
                    &app,
                    (request, challenge),
                    Duration::from_secs(2)
                )
                .is_err(),
            "validly re-signed foreign role binding {path}"
        );
    }
    for now in [
        Duration::from_nanos(app.original.origin_ns - 1),
        Duration::from_secs(4),
        Duration::from_secs(5),
    ] {
        ensure!(
            signed
                .verify_data(
                    &f.policy,
                    &f.certificate,
                    &completion,
                    &app,
                    (request, challenge),
                    now
                )
                .is_err(),
            "changed or expired comparison time"
        );
    }
    let mut changed = signed.clone();
    changed.statement.effective_deadline_ns = 4_500_000_001;
    changed.statement.stage.data.deadline_ns = 4_500_000_001;
    changed.statement.stage.signature =
        f.issuer.sign("role-stage", &changed.statement.stage.data)?;
    changed.signature = f
        .issuer
        .sign("restore-app-role-activated-v1", &changed.statement)?;
    ensure!(
        changed
            .verify_data(
                &f.policy,
                &f.certificate,
                &completion,
                &app,
                (request, challenge),
                Duration::from_secs(2)
            )
            .is_err(),
        "both re-signed deadlines cannot exceed original completion"
    );
    // Comparison DATA has no refusal memory or admission authority. The real
    // pending/received owners must enforce irreversible clock refusal.
    Ok(())
}

#[test]
fn final_role_wire_requires_exact_nested_records_and_both_actual_signature_domains() -> Result<()> {
    let f = fixture()?;
    let (app, completion, signed) = role_activation_fixture(&f)?;
    let request = signed.statement.request.clone();
    let challenge = signed.statement.challenge.clone();
    let packets = [
        Packet::RestoreRoleHello {
            completion: Box::new(completion.clone()),
            request: request.clone(),
        },
        Packet::RestoreRoleNonce {
            completion: completion.digest_data()?,
            request: request.clone(),
            challenge: challenge.clone(),
        },
        Packet::RestoreRoleBind {
            completion: Box::new(completion.clone()),
            request: request.clone(),
            challenge: challenge.clone(),
            signature: "synthetic-bind-only".into(),
        },
        Packet::RestoreRoleGrant {
            activation: Box::new(signed.clone()),
        },
    ];
    for packet in &packets {
        let value = serde_json::to_value(packet)?;
        let bytes = serde_json::to_vec(packet)?;
        ensure!(bytes.len() <= MAX_PACKET);
        ensure!(serde_json::to_value(decode(&bytes)?)? == value);
        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("discarded".into(), json!(true));
        ensure!(decode(&serde_json::to_vec(&unknown)?).is_err());
        let kind = value["kind"].as_str().unwrap();
        let raw = String::from_utf8(bytes)?;
        let duplicate = raw.replacen(
            &format!("\"kind\":\"{kind}\""),
            &format!("\"kind\":\"{kind}\",\"kind\":\"{kind}\""),
            1,
        );
        ensure!(duplicate != raw && decode(duplicate.as_bytes()).is_err());
    }
    let records: &[(&str, &[&str])] = &[
        ("/completion", &["statement", "signature"]),
        (
            "/completion/statement",
            &["data", "request", "challenge", "effective_deadline_ns"],
        ),
        (
            "/completion/statement/data",
            &["frozen", "authorization", "app", "activation", "cohort"],
        ),
        ("/completion/statement/data/cohort", &["main", "wal", "shm"]),
        ("/activation", &["statement", "signature"]),
        (
            "/activation/statement",
            &[
                "completion",
                "stage",
                "request",
                "challenge",
                "effective_deadline_ns",
            ],
        ),
        ("/activation/statement/stage", &["data", "signature"]),
        (
            "/activation/statement/stage/data",
            &[
                "issuer",
                "policy",
                "role",
                "purpose",
                "public_key",
                "challenge",
                "request",
                "process",
                "runtime",
                "origin_ns",
                "deadline_ns",
            ],
        ),
        (
            "/activation/statement/stage/data/process",
            &["process", "start_ticks", "code", "boot", "namespaces"],
        ),
        (
            "/activation/statement/stage/data/runtime",
            &["container", "node_uid", "boot"],
        ),
        (
            "/activation/statement/stage/data/runtime/container",
            &[
                "pod_name",
                "pod_uid",
                "node_name",
                "container_name",
                "container_id",
                "image",
                "restart_count",
            ],
        ),
    ];
    let mut exercised = std::collections::BTreeSet::new();
    for packet in &packets {
        let original = serde_json::to_value(packet)?;
        for (path, fields) in records {
            let Some(Value::Object(record)) = original.pointer(path) else {
                continue;
            };
            assert_eq!(record.len(), fields.len());
            let positional =
                Value::Array(fields.iter().map(|field| record[*field].clone()).collect());
            let mut value = original.clone();
            *value.pointer_mut(path).unwrap() = positional;
            ensure!(
                serde_json::from_value::<Packet>(value.clone()).is_ok(),
                "complete declared-order role record {path}"
            );
            ensure!(
                decode(&serde_json::to_vec(&value)?).is_err(),
                "actual role object guard {path}"
            );
            exercised.insert((original["kind"].as_str().unwrap().to_owned(), *path));
        }
    }
    assert_eq!(
        exercised.len(),
        15,
        "Hello4+Bind4+Grant7 complete record cuts"
    );
    // Namespace anchors are a map, not a record with positional Serde form.
    // Keep this distinct from the guard-specific struct-array witnesses.
    let mut namespace_sequence = serde_json::to_value(&packets[3])?;
    *namespace_sequence
        .pointer_mut("/activation/statement/stage/data/process/namespaces")
        .unwrap() = json!([]);
    ensure!(serde_json::from_value::<Packet>(namespace_sequence.clone()).is_err());
    ensure!(decode(&serde_json::to_vec(&namespace_sequence)?).is_err());
    let mut bad_inner = signed.clone();
    bad_inner.statement.stage.signature =
        KeyOwner::generate()?.sign("role-stage", &bad_inner.statement.stage.data)?;
    bad_inner.signature = f
        .issuer
        .sign("restore-app-role-activated-v1", &bad_inner.statement)?;
    ensure!(
        bad_inner
            .verify_data(
                &f.policy,
                &f.certificate,
                &completion,
                &app,
                (&request, &challenge),
                Duration::from_secs(2)
            )
            .is_err()
    );
    let mut bad_outer = signed.clone();
    bad_outer.signature =
        KeyOwner::generate()?.sign("restore-app-role-activated-v1", &bad_outer.statement)?;
    ensure!(
        bad_outer
            .verify_data(
                &f.policy,
                &f.certificate,
                &completion,
                &app,
                (&request, &challenge),
                Duration::from_secs(2)
            )
            .is_err()
    );
    ensure!(decode(&vec![b' '; MAX_PACKET + 1]).is_err());
    Ok(())
}

#[test]
fn actual_final_role_issuer_retains_a_decision_without_reopening_or_renewing() {
    use quote::ToTokens;
    fn tokens(value: &str) -> String {
        fn normalized(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), normalized(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        normalized(value.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }
    let file = syn::parse_file(include_str!("../service.rs")).unwrap();
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "restore_role_decision" => Some(item),
            _ => None,
        })
        .unwrap();
    fn requested_body(function: &syn::ItemFn) -> syn::Block {
        function
            .block
            .stmts
            .iter()
            .find_map(|statement| {
                let syn::Stmt::Local(local) = statement else {
                    return None;
                };
                let pattern = match &local.pat {
                    syn::Pat::Type(typed) => &*typed.pat,
                    other => other,
                };
                if !matches!(pattern,syn::Pat::Ident(name) if name.ident=="requested") {
                    return None;
                }
                let syn::Expr::Call(call) = &*local.init.as_ref()?.expr else {
                    return None;
                };
                let syn::Expr::Paren(paren) = &*call.func else {
                    return None;
                };
                let syn::Expr::Closure(closure) = &*paren.expr else {
                    return None;
                };
                let syn::Expr::Block(body) = &*closure.body else {
                    return None;
                };
                Some(body.block.clone())
            })
            .unwrap()
    }
    fn fresh_only(block: &syn::Block) -> bool {
        use syn::parse::Parser;
        let Some(syn::Stmt::Local(binding)) = block.stmts.first() else {
            return false;
        };
        if !matches!(&binding.pat,syn::Pat::Ident(name) if name.ident=="fresh") {
            return false;
        }
        let Some(init) = &binding.init else {
            return false;
        };
        let syn::Expr::Match(selected) = &*init.expr else {
            return false;
        };
        if tokens(&selected.expr.to_token_stream().to_string()) != tokens("&cohort.role_decision")
            || selected.arms.len() != 3
        {
            return false;
        }
        let expected = [
            ("RestoreRoleDecision::Fresh", true),
            ("RestoreRoleDecision::Spent", false),
        ];
        for (arm, (pattern, value)) in selected.arms.iter().zip(expected) {
            if arm.guard.is_some()
                || tokens(&arm.pat.to_token_stream().to_string()) != tokens(pattern)
                || !matches!(&*arm.body,syn::Expr::Lit(literal) if matches!(&literal.lit,syn::Lit::Bool(actual) if actual.value==value))
            {
                return false;
            }
        }
        let retained = &selected.arms[2];
        if retained.guard.is_some()
            || tokens(&retained.pat.to_token_stream().to_string())
                != tokens("RestoreRoleDecision::Retained(decision)")
        {
            return false;
        }
        let syn::Expr::Block(retained) = &*retained.body else {
            return false;
        };
        if retained.block.stmts.len() != 2
            || !matches!(retained.block.stmts.last(),Some(syn::Stmt::Expr(syn::Expr::Lit(literal),None)) if matches!(&literal.lit,syn::Lit::Bool(actual) if !actual.value))
        {
            return false;
        }
        let Some(syn::Stmt::Macro(guard)) = block.stmts.get(1) else {
            return false;
        };
        if !guard.mac.path.is_ident("ensure") {
            return false;
        }
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        let Ok(arguments) = parser.parse2(guard.mac.tokens.clone()) else {
            return false;
        };
        if arguments.len() != 2
            || !matches!(arguments.first(),Some(syn::Expr::Path(path)) if path.path.is_ident("fresh"))
        {
            return false;
        }
        block.stmts.get(2).is_some_and(|statement| {
            tokens(&statement.to_token_stream().to_string())
                == tokens("cohort.role_decision=RestoreRoleDecision::Spent;")
        })
    }
    let actual = requested_body(function);
    assert!(fresh_only(&actual));
    // Independent expected table: only Fresh may proceed. Exercise changes
    // to the actual parsed production arms and guard, never a fake owner.
    for cut in 0..5 {
        let mut changed = actual.clone();
        match cut {
            0 => changed.stmts[1] = syn::parse_quote!(let _removed_guard=();),
            1 => changed.stmts[1] = syn::parse_quote!(ensure!(!fresh,"inverted");),
            2 | 3 => {
                let syn::Stmt::Local(binding) = &mut changed.stmts[0] else {
                    panic!()
                };
                let syn::Expr::Match(selected) = &mut *binding.init.as_mut().unwrap().expr else {
                    panic!()
                };
                if cut == 2 {
                    selected.arms[1].body = syn::parse_quote!(true);
                } else {
                    let syn::Expr::Block(retained) = &mut *selected.arms[2].body else {
                        panic!()
                    };
                    *retained.block.stmts.last_mut().unwrap() =
                        syn::Stmt::Expr(syn::parse_quote!(true), None);
                }
            }
            _ => {
                changed.stmts[2] =
                    syn::parse_quote!(cohort.role_decision=RestoreRoleDecision::Fresh;)
            }
        }
        assert!(
            !fresh_only(&changed),
            "actual role decision repeat cut {cut}"
        );
    }
    let body = tokens(&function.to_token_stream().to_string());
    let names = [
        "RestoreRoleDecision::Fresh",
        "RestoreRoleDecision::Spent",
        "RestoreRoleDecision::Retained",
    ];
    for name in names {
        assert!(body.contains(&tokens(name)));
    }
    // Source assertions use complete Rust expressions. No actual kernel or
    // native Current can be manufactured by this portable inspection.
    let spend = tokens("cohort.role_decision = RestoreRoleDecision::Spent;");
    let check = tokens("finish_publish_check(issuer,cohort,acquisition,current,peer,costs)?;");
    let nonce = tokens("protocol::nonce(\"restore-app-role-challenge\")?");
    assert!(body.find(&spend).unwrap() < body.find(&check).unwrap());
    assert!(body.find(&check).unwrap() < body.find(&nonce).unwrap());
    assert!(body.contains(&tokens("cohort.completion.as_ref()==Some(&completion)")));
    assert!(body.contains(&tokens("app.statement_data(costs)?")));
    assert!(body.contains(&tokens("origin_ns:app.original.origin_ns")));
    let retain =
        tokens("cohort.role_decision=RestoreRoleDecision::Retained(Box::new(signed.clone()));");
    let grant = tokens("Packet::RestoreRoleGrant");
    assert!(body.find(&retain).unwrap() < body.rfind(&grant).unwrap());
    assert!(body.contains(&tokens("requested?;checked")));
    assert!(!body.contains(&tokens("Issuance::Open")));
    assert!(!body.contains(&tokens("NativeAcquisition::begin")));
    assert!(!body.contains(&tokens("enrolled.insert")));
    assert!(!body.contains(&tokens("enrolled.entry")));
}

#[test]
fn prepared_confirmation_data_binds_the_actual_chain_attempt_and_strict_existing_ceiling()
-> Result<()> {
    // Synthetic signed comparison DATA only: no native issuer, receipt, keeper,
    // refusal memory, Controller post or ordinary role is constructed here.
    let f = fixture()?;
    let (app, completion, decision) = role_activation_fixture(&f)?;
    let request = Digest::new(b"prepared-app-request");
    let challenge = Digest::new(b"prepared-app-challenge");
    let statement = RestorePreparedConfirmationStatement {
        issuer: f.certificate.digest()?,
        decision: decision.digest_data()?,
        completion: completion.digest_data()?,
        app: app.digest()?,
        request: request.clone(),
        challenge: challenge.clone(),
        effective_deadline_ns: 3_500_000_000,
    };
    let signed = SignedRestorePreparedConfirmation {
        signature: f
            .issuer
            .sign("restore-app-prepared-confirmed-v1", &statement)?,
        statement,
    };
    signed.verify_data(
        &f.policy,
        &f.certificate,
        (&decision, &completion),
        &app,
        (&request, &challenge),
        Duration::from_secs(2),
    )?;
    for cut in 0..7 {
        let mut changed = signed.clone();
        let foreign = Digest::new(b"another-prepared-confirmation-world");
        match cut {
            0 => changed.statement.issuer = foreign,
            1 => changed.statement.decision = foreign,
            2 => changed.statement.completion = foreign,
            3 => changed.statement.app = foreign,
            4 => changed.statement.request = foreign,
            5 => changed.statement.challenge = foreign,
            6 => {
                changed.statement.effective_deadline_ns =
                    decision.statement.effective_deadline_ns + 1
            }
            _ => unreachable!(),
        }
        changed.signature = f
            .issuer
            .sign("restore-app-prepared-confirmed-v1", &changed.statement)?;
        assert!(
            changed
                .verify_data(
                    &f.policy,
                    &f.certificate,
                    (&decision, &completion),
                    &app,
                    (&request, &challenge),
                    Duration::from_secs(2)
                )
                .is_err(),
            "cut{cut}"
        );
    }
    for now in [Duration::from_nanos(3_500_000_000), Duration::from_secs(4)] {
        assert!(
            signed
                .verify_data(
                    &f.policy,
                    &f.certificate,
                    (&decision, &completion),
                    &app,
                    (&request, &challenge),
                    now
                )
                .is_err()
        );
    }
    let foreign = Digest::new(b"other-actual-attempt");
    for exchange in [(&foreign, &challenge), (&request, &foreign)] {
        assert!(
            signed
                .verify_data(
                    &f.policy,
                    &f.certificate,
                    (&decision, &completion),
                    &app,
                    exchange,
                    Duration::from_secs(2)
                )
                .is_err()
        );
    }
    let mut changed = signed.clone();
    changed.signature = f
        .issuer
        .sign("restore-app-role-activated-v1", &changed.statement)?;
    assert!(
        changed
            .verify_data(
                &f.policy,
                &f.certificate,
                (&decision, &completion),
                &app,
                (&request, &challenge),
                Duration::from_secs(2)
            )
            .is_err()
    );
    let mut changed = signed;
    changed.signature =
        KeyOwner::generate()?.sign("restore-app-prepared-confirmed-v1", &changed.statement)?;
    assert!(
        changed
            .verify_data(
                &f.policy,
                &f.certificate,
                (&decision, &completion),
                &app,
                (&request, &challenge),
                Duration::from_secs(2)
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn prepared_confirmation_wire_is_closed_and_preserves_complete_nested_object_shapes() -> Result<()>
{
    let f = fixture()?;
    let (app, completion, decision) = role_activation_fixture(&f)?;
    let request = Digest::new(b"prepared-wire-request");
    let challenge = Digest::new(b"prepared-wire-challenge");
    let statement = RestorePreparedConfirmationStatement {
        issuer: f.certificate.digest()?,
        decision: decision.digest_data()?,
        completion: completion.digest_data()?,
        app: app.digest()?,
        request: request.clone(),
        challenge: challenge.clone(),
        effective_deadline_ns: 3_500_000_000,
    };
    let confirmation = SignedRestorePreparedConfirmation {
        signature: f
            .issuer
            .sign("restore-app-prepared-confirmed-v1", &statement)?,
        statement,
    };
    let packets = [
        Packet::RestoreAppConfirmHello {
            decision: Box::new(decision.clone()),
            request: request.clone(),
        },
        Packet::RestoreAppConfirmNonce {
            decision: decision.digest_data()?,
            request: request.clone(),
            challenge: challenge.clone(),
        },
        Packet::RestoreAppConfirmBind {
            decision: Box::new(decision.clone()),
            request,
            challenge,
            signature: "synthetic-codec-proof-only".into(),
        },
        Packet::RestoreAppConfirmGrant {
            confirmation: Box::new(confirmation),
        },
    ];
    let records: &[(&str, &[&str])] = &[
        ("/decision", &["statement", "signature"]),
        (
            "/decision/statement",
            &[
                "completion",
                "stage",
                "request",
                "challenge",
                "effective_deadline_ns",
            ],
        ),
        ("/decision/statement/stage", &["data", "signature"]),
        (
            "/decision/statement/stage/data",
            &[
                "issuer",
                "policy",
                "role",
                "purpose",
                "public_key",
                "challenge",
                "request",
                "process",
                "runtime",
                "origin_ns",
                "deadline_ns",
            ],
        ),
        (
            "/decision/statement/stage/data/process",
            &["process", "start_ticks", "code", "boot", "namespaces"],
        ),
        (
            "/decision/statement/stage/data/runtime",
            &["container", "node_uid", "boot"],
        ),
        (
            "/decision/statement/stage/data/runtime/container",
            &[
                "pod_name",
                "pod_uid",
                "node_name",
                "container_name",
                "container_id",
                "image",
                "restart_count",
            ],
        ),
        ("/confirmation", &["statement", "signature"]),
        (
            "/confirmation/statement",
            &[
                "issuer",
                "decision",
                "completion",
                "app",
                "request",
                "challenge",
                "effective_deadline_ns",
            ],
        ),
    ];
    let mut boundary = serde_json::to_vec(packets.last().unwrap())?;
    assert!(boundary.len() < MAX_PACKET);
    boundary.resize(MAX_PACKET, b' ');
    assert!(
        decode(&boundary).is_ok(),
        "valid packet exactly at byte bound"
    );
    boundary.push(b' ');
    assert!(
        serde_json::from_slice::<Packet>(&boundary).is_ok(),
        "oversized witness remains complete valid JSON"
    );
    assert!(
        decode(&boundary).is_err(),
        "only the closed packet byte bound rejects this witness"
    );
    let mut cuts = 0;
    for packet in packets {
        let value = serde_json::to_value(&packet)?;
        let bytes = serde_json::to_vec(&packet)?;
        assert_eq!(serde_json::to_value(decode(&bytes)?)?, value);
        let mut changed = value.clone();
        changed
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(true));
        assert!(decode(&serde_json::to_vec(&changed)?).is_err());
        let raw = String::from_utf8(bytes)?;
        let kind = value["kind"].as_str().unwrap();
        let duplicate = raw.replacen(
            &format!("\"kind\":\"{kind}\""),
            &format!("\"kind\":\"{kind}\",\"kind\":\"{kind}\""),
            1,
        );
        assert_ne!(raw, duplicate);
        assert!(decode(duplicate.as_bytes()).is_err());
        for (path, fields) in records {
            let Some(Value::Object(record)) = value.pointer(path) else {
                continue;
            };
            assert_eq!(fields.len(), record.len(), "{path}");
            let positional =
                Value::Array(fields.iter().map(|field| record[*field].clone()).collect());
            let mut changed = value.clone();
            *changed.pointer_mut(path).unwrap() = positional;
            assert!(
                serde_json::from_value::<Packet>(changed.clone()).is_ok(),
                "complete declared-order {path}"
            );
            assert!(
                decode(&serde_json::to_vec(&changed)?).is_err(),
                "closed packet {path}"
            );
            cuts += 1;
        }
    }
    assert_eq!(cuts, 16);
    Ok(())
}

#[test]
fn actual_prepared_issuer_spends_the_retained_app_and_posts_before_retaining_or_delivery() {
    use quote::ToTokens;
    fn tokens(value: &str) -> String {
        fn normalize(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(p) if p.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(g) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(g.delimiter(), normalize(g.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        normalize(value.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }
    fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut remaining = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = remaining.find(&part) else {
                return false;
            };
            remaining = &remaining[at + part.len()..];
        }
        true
    }
    // syn emits the comparison operator separately from the following borrow;
    // raw adjacent punctuation in an expectation must not change that shape.
    let comparison: syn::Expr = syn::parse_str("retained.as_ref()==&decision").unwrap();
    assert_eq!(
        tokens(&comparison.to_token_stream().to_string()),
        tokens("retained.as_ref() == &decision")
    );
    assert_ne!(
        tokens("retained.as_ref()==&decision"),
        tokens("retained.as_ref() == &decision")
    );
    let source = include_str!("../service.rs");
    let file = syn::parse_file(source).unwrap();
    let actual = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "restore_app_confirmation" => {
                Some(tokens(&item.to_token_stream().to_string()))
            }
            _ => None,
        })
        .unwrap();
    let parts = [
        "let mut attempt=AppConfirmationAttempt {cohort,acquisition,done:false};",
        r#"ensure!(!app.confirmation_attempted && app.confirmation.is_none(),"native_restore_prepared_attempt_spent");"#,
        "app.confirmation_attempted=true;",
        "RestoreRoleDecision::Retained(retained)",
        r#"ensure!(retained.as_ref()== &decision,"native_restore_prepared_decision_changed");"#,
        "prepared_publish_check(issuer,attempt.cohort,attempt.acquisition,current,peer,costs)?;",
        "app.statement_data(costs)?;",
        "decision.verify_data",
        "let (_,frozen_ceiling)=attempt.cohort.original.interval_data()?;",
        "let (_,app_ceiling)=actual_app.original.interval_data()?;",
        "let ceiling=std::time::Duration::from_nanos(decision.statement.effective_deadline_ns).min(frozen_ceiling).min(app_ceiling);",
        "channel.narrow_restore_app_confirmation(attempt.acquisition,ceiling)?;",
        r#"let challenge=protocol::nonce("restore-app-prepared-challenge")?;"#,
        "Packet::RestoreAppConfirmNonce",
        "let checked=prepared_publish_check",
        "sent?;checked?;",
        "let received=channel.receive",
        "let checked=prepared_publish_check",
        "let (packet,mut bound)=received?;",
        "prepared_actor_check(attempt.cohort,attempt.acquisition,peer,Some(&mut bound),costs);",
        "checked?;sender?;",
        r#"protocol::verify(&app.admission.statement.public_key,"restore-app-prepared-bind-v1",&(&decision,&request,&challenge),&signature)?;"#,
        "decision.statement.effective_deadline_ns",
        ".min(frozen_ceiling).min(request_ceiling)",
        r#"issuer.key.sign("restore-app-prepared-confirmed-v1",&statement)"#,
        "let checked=prepared_publish_check",
        "let signature=signed?;checked?;",
        "signed.verify_data",
        "retained_app.confirmation=Some(signed.clone());",
        "Packet::RestoreAppConfirmGrant",
        "let checked=prepared_publish_check",
        "let sender=prepared_actor_check",
        "sent?;checked?;sender?;",
        "let checked=prepared_publish_check",
        "requested.is_err() || checked.is_err()",
        "attempt.cohort.original.refuse();attempt.acquisition.refuse();",
        "requested?;checked?;attempt.done=true;Ok(())",
    ];
    assert!(ordered(&actual, &parts));
    for before in [
        "done:false",
        "app.confirmation_attempted=true;",
        r#"ensure!(retained.as_ref()== &decision,"native_restore_prepared_decision_changed");"#,
        r#"protocol::verify(&app.admission.statement.public_key,"restore-app-prepared-bind-v1",&(&decision,&request,&challenge),&signature)?;"#,
        "retained_app.confirmation=Some(signed.clone());",
        "requested?;checked?;attempt.done=true;Ok(())",
    ] {
        let before = tokens(before);
        assert_eq!(actual.matches(&before).count(), 1, "{before}");
        assert!(
            !ordered(&actual.replacen(&before, "", 1), &parts),
            "{before}"
        );
    }
    let guarded = tokens(
        r#"ensure!(!app.confirmation_attempted && app.confirmation.is_none(),"native_restore_prepared_attempt_spent");"#,
    );
    assert_eq!(actual.matches(&guarded).count(), 1);
    for replacement in [
        r#"ensure!(true || (!app.confirmation_attempted && app.confirmation.is_none()),"native_restore_prepared_attempt_spent");"#,
        r#"ensure!(!(!app.confirmation_attempted && app.confirmation.is_none()),"native_restore_prepared_attempt_spent");"#,
        r#"ensure!(app.confirmation.is_none(),"native_restore_prepared_attempt_spent");"#,
        r#"ensure!(!app.confirmation_attempted,"native_restore_prepared_attempt_spent");"#,
        r#"ensure!(true,"native_restore_prepared_attempt_spent");"#,
    ] {
        assert!(!ordered(
            &actual.replacen(&guarded, &tokens(replacement), 1),
            &parts
        ));
    }
    let clamp = tokens("channel.narrow_restore_app_confirmation(attempt.acquisition,ceiling)?;");
    assert_eq!(actual.matches(&clamp).count(), 1);
    for replacement in [
        "let _unclipped=();",
        "*attempt.acquisition=NativeAcquisition::begin(5)?;",
    ] {
        assert!(!ordered(
            &actual.replacen(&clamp, &tokens(replacement), 1),
            &parts
        ));
    }
    for forbidden in [
        "NativeAcquisition::begin",
        "Issuance::Open",
        "enrolled.insert",
        "confirmation_attempted=false",
    ] {
        assert!(!actual.contains(&tokens(forbidden)));
    }
    let root=file.items.iter().find_map(|item|match item {
        syn::Item::Impl(item) if item.trait_.as_ref().is_some_and(|(_,path,_)|path.is_ident("Drop"))
            && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident=="AppConfirmationAttempt"))=>Some(tokens(&item.to_token_stream().to_string())),_=>None,
    }).unwrap();
    assert!(root.contains(&tokens(
        "if !self.done {self.cohort.original.refuse();self.acquisition.refuse();}"
    )));
    // This inspects actual Linux source; it creates no kernel actor, grant,
    // native clock, keeper, ordinary role or successful confirmation fixture.
}

#[test]
fn actual_confirmation_wait_meets_the_same_channel_transcript_and_native_acquisition() {
    use quote::ToTokens;
    fn normalize(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
        stream
            .into_iter()
            .filter_map(|token| match token {
                proc_macro2::TokenTree::Punct(p) if p.as_char() == ',' => None,
                proc_macro2::TokenTree::Punct(p) if p.as_char() == '?' => {
                    Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                        '?',
                        proc_macro2::Spacing::Alone,
                    )))
                }
                proc_macro2::TokenTree::Group(g) => Some(proc_macro2::TokenTree::Group(
                    proc_macro2::Group::new(g.delimiter(), normalize(g.stream())),
                )),
                other => Some(other),
            })
            .collect()
    }
    let tokens = |s: &str| normalize(s.parse::<proc_macro2::TokenStream>().unwrap()).to_string();
    let file = syn::parse_file(include_str!("../channel.rs")).unwrap();
    let body = file
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.is_ident("Channel")) {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == "narrow_restore_app_confirmation" => {
                    Some(tokens(&item.to_token_stream().to_string()))
                }
                _ => None,
            })
        })
        .unwrap();
    let parts = [
        "acquisition.remaining()?;",
        "*acquisition=acquisition.narrow(5,ceiling)?;",
        "self.transcript.as_mut()",
        ".narrow_restore_app_confirmation(Self::observation(acquisition))?;",
        "acquisition.remaining().map(|_|())",
        "if requested.is_err()",
        "self.refuse();acquisition.refuse();",
        "requested",
    ];
    let ordered = |body: &str| {
        let mut rest = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        true
    };
    assert!(ordered(&body));
    for before in [
        "*acquisition=acquisition.narrow(5,ceiling)?;",
        ".narrow_restore_app_confirmation(Self::observation(acquisition))?;",
        "self.refuse();acquisition.refuse();",
    ] {
        let before = tokens(before);
        assert_eq!(body.matches(&before).count(), 1);
        assert!(!ordered(&body.replacen(&before, "", 1)));
    }
    for forbidden in [
        "NativeAcquisition::begin",
        "Transcript::new",
        "self.transcript=",
        "self.clock=None",
    ] {
        assert!(!body.contains(&tokens(forbidden)));
    }
}
