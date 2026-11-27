//! Synthetic DATA signatures only. No qualified event source, native role,
//! actual CREATE, original, slot reservation or source owner is constructed.
use super::*;
use crate::security_epoch::native_enrollment::protocol::{IssuerData, KeyOwner, ProcessData};
use serde_json::{Value, json};

fn digest(text: &str) -> Digest {
    Digest::new(text.as_bytes())
}

fn uid(n: u32) -> WorkloadUid {
    format!("00000000-0000-0000-0000-{n:012}")
        .try_into()
        .unwrap()
}

fn certificate(
    root: &KeyOwner,
    issuer: &KeyOwner,
    policy: &EnrollmentPolicy,
    salt: u8,
) -> Result<IssuerCertificate> {
    let process = |code| ProcessData {
        process: 71 + u32::from(salt),
        start_ticks: 123 + u64::from(salt),
        code,
        boot: "synthetic-boot".into(),
        namespaces: ["time", "time_for_children", "pid", "mnt", "user", "cgroup"]
            .into_iter()
            .map(|name| (name.to_owned(), (7, 9)))
            .collect(),
    };
    let data = IssuerData {
        policy: policy.digest()?,
        root_version: policy.root.version.clone(),
        nonce: Digest::new(&[salt]),
        public_key: issuer.public(),
        process: process(policy.issuer_code.clone()),
        provisioner: process(policy.provisioner_code.clone()),
    };
    Ok(IssuerCertificate {
        signature: root.sign("issuer-birth", &data)?,
        data,
    })
}

struct Fixture {
    root: KeyOwner,
    issuer: KeyOwner,
    policy: EnrollmentPolicy,
    certificate: IssuerCertificate,
    record: SignedCreateAttestationData,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = KeyOwner::generate()?;
        let issuer = KeyOwner::generate()?;
        let mut policy = crate::security_epoch::native_enrollment::tests::policy(&root);
        for role in [
            &mut policy.bootstrap.app,
            &mut policy.bootstrap.controller,
            &mut policy.bootstrap.shell,
        ] {
            role.namespace.uid = "00000000-0000-0000-0000-000000000002".into();
        }
        let mut selected =
            crate::security_epoch::scheduled_backup::requester::policy_fixture_data()?;
        selected.scope = policy.bootstrap.scope.clone();
        selected.cluster = Digest::of(&policy.bootstrap.cluster)?;
        selected.node_name = policy.runtime.node_name.clone();
        selected.node = Digest::of(&(
            "day2-scheduled-backup-node-v1",
            &policy.runtime.node_name,
            &policy.runtime.node_uid,
        ))?;
        selected.namespace = policy.bootstrap.app.namespace.clone();
        selected.image = policy.bootstrap.app.container.image.clone();
        let binding = CreateBindingData {
            namespace_uid: selected.namespace.uid.clone().try_into()?,
            cron_job_uid: selected.cron_job.uid.clone().try_into()?,
            service_account_uid: selected.service_account.uid.clone().try_into()?,
            job_uid: uid(3),
            pod_uid: uid(4),
            slot: "2026-11-26T17:00:00Z".to_owned().try_into()?,
            cron_spec: selected.cron_spec.clone(),
            job_spec: digest("whole-persisted-job-spec"),
            pod_spec: digest("whole-persisted-pod-spec"),
            admission: selected.admission_generation_data()?,
            policy: digest("replaced-after-policy-selection"),
            request: digest("complete-saved-request-intent-original-and-nonces"),
        };
        let tap = TapSelectionData {
            registry: digest("reviewed-registry-revision"),
            profile: digest("qualified-source-profile"),
            tap_code: digest("reviewed-tap-code"),
            channel_peer_key: digest("pinned-channel-peer-key"),
            key_version: digest("reviewed-channel-key-generation"),
            feed_epoch: digest("durable-feed-incarnation"),
            cluster_incarnation: selected.cluster.clone(),
        };
        let event = |uid, owner_uid, spec, subject: &str, sequence| -> Result<CreateEventData> {
            let subject = Digest::of(&("day2-create-original-subject-v1", subject))?;
            Ok(CreateEventData {
                verb: CreateVerbData::Create,
                resource: if sequence == 11 {
                    CreateResourceData::BatchV1Job
                } else {
                    CreateResourceData::CoreV1Pod
                },
                audit_id: Digest::new(&[sequence as u8]),
                journal_sequence: sequence,
                uid,
                owner_uid,
                spec,
                original_subject: subject.clone(),
                effective_subject: subject,
                impersonation: ImpersonationData::Absent,
                identity_complete: true,
                spec_complete: true,
                stage: CreateStageData::ResponseComplete,
                status: 201,
                dry_run: false,
            })
        };
        let job = event(
            binding.job_uid.clone(),
            binding.cron_job_uid.clone(),
            binding.job_spec.clone(),
            &selected.cron_controller,
            11,
        )?;
        let pod = event(
            binding.pod_uid.clone(),
            binding.job_uid.clone(),
            binding.pod_spec.clone(),
            &selected.job_controller,
            19,
        )?;
        policy.scheduled_backup = Some(selected);
        policy.validate()?;
        let certificate = certificate(&root, &issuer, &policy, 1)?;
        let mut data = CreateAttestationData {
            tap,
            issuer: certificate.digest()?,
            challenge: digest("actual-current-issuer-challenge"),
            binding,
            job,
            pod,
        };
        data.binding.policy = policy.digest()?;
        let record = SignedCreateAttestationData {
            signature: issuer.sign(PURPOSE, &data)?,
            data,
        };
        Ok(Self {
            root,
            issuer,
            policy,
            certificate,
            record,
        })
    }

    fn check(&self, record: &SignedCreateAttestationData) -> Result<()> {
        record.verify_data(
            &self.policy,
            &self.certificate,
            &self.record.data.tap,
            &self.record.data.binding,
            &self.record.data.challenge,
        )
    }

    fn signed(&self, value: Value) -> Result<SignedCreateAttestationData> {
        let data: CreateAttestationData = serde_json::from_value(value)?;
        Ok(SignedCreateAttestationData {
            signature: self.issuer.sign(PURPOSE, &data)?,
            data,
        })
    }
}

#[test]
fn signed_create_data_binds_every_uid_template_slot_registry_and_saved_request() -> Result<()> {
    let f = Fixture::new()?;
    f.check(&f.record)?;
    let original = serde_json::to_value(&f.record.data)?;
    for section in ["tap", "binding"] {
        for (key, value) in original[section].as_object().unwrap() {
            let mut changed = original.clone();
            changed[section][key] = if key.ends_with("_uid") {
                serde_json::to_value(uid(99))?
            } else if key == "slot" {
                json!("2026-11-26T17:01:00Z")
            } else {
                assert!(value.as_str().unwrap().starts_with("sha256:"));
                serde_json::to_value(digest("changed-even-when-resigned"))?
            };
            assert!(f.check(&f.signed(changed)?).is_err(), "{section}.{key}");
        }
    }
    for key in ["issuer", "challenge"] {
        let mut changed = original.clone();
        changed[key] = serde_json::to_value(digest("different-live-cohort-or-challenge"))?;
        assert!(f.check(&f.signed(changed)?).is_err(), "{key}");
    }
    Ok(())
}

#[test]
fn original_creator_and_persisted_success_are_required_for_both_events() -> Result<()> {
    let f = Fixture::new()?;
    let original = serde_json::to_value(&f.record.data)?;
    for event in ["job", "pod"] {
        for (key, replacement) in [
            ("uid", serde_json::to_value(uid(99))?),
            ("owner_uid", serde_json::to_value(uid(99))?),
            ("spec", serde_json::to_value(digest("different-spec"))?),
            (
                "original_subject",
                serde_json::to_value(digest("human-original"))?,
            ),
            (
                "effective_subject",
                serde_json::to_value(digest("different-effective"))?,
            ),
            ("impersonation", json!("present")),
            ("impersonation", json!("unknown")),
            ("identity_complete", json!(false)),
            ("spec_complete", json!(false)),
            (
                "resource",
                json!(if event == "job" {
                    "core_v1_pod"
                } else {
                    "batch_v1_job"
                }),
            ),
            ("stage", json!("request_received")),
            ("stage", json!("response_started")),
            ("status", json!(200)),
            ("status", json!(403)),
            ("status", json!(500)),
            ("dry_run", json!(true)),
            ("journal_sequence", json!(0)),
        ] {
            let mut changed = original.clone();
            changed[event][key] = replacement;
            assert!(f.check(&f.signed(changed)?).is_err(), "{event}.{key}");
        }
    }
    // Deliberately strict durable arrival order: reverse/equal refuses.
    // This does not claim upstream causal order or absence/completeness.
    for (key, value) in [
        ("audit_id", original["job"]["audit_id"].clone()),
        ("journal_sequence", json!(11)),
        ("journal_sequence", json!(10)),
    ] {
        let mut changed = original.clone();
        changed["pod"][key] = value;
        assert!(f.check(&f.signed(changed)?).is_err(), "pair.{key}");
    }
    Ok(())
}

#[test]
fn held_cohort_and_current_selection_are_not_packet_selected_or_renewed() -> Result<()> {
    let f = Fixture::new()?;
    // Repeating comparison DATA is allowed. It cannot consume/reopen a slot
    // or confer authority, and a different actual challenge still refuses.
    for _ in 0..2 {
        f.check(&f.record)?;
    }
    let mut old = f.record.clone();
    old.signature = f.issuer.sign("other-purpose", &old.data)?;
    assert!(f.check(&old).is_err());
    let other_issuer = KeyOwner::generate()?;
    let other_certificate = certificate(&f.root, &other_issuer, &f.policy, 2)?;
    let mut changed = f.record.clone();
    changed.data.issuer = other_certificate.digest()?;
    changed.signature = other_issuer.sign(PURPOSE, &changed.data)?;
    assert!(f.check(&changed).is_err());
    let mut disabled = f.policy.clone();
    disabled.scheduled_backup = None;
    let disabled_certificate = certificate(&f.root, &f.issuer, &disabled, 1)?;
    let mut changed = f.record.clone();
    changed.data.issuer = disabled_certificate.digest()?;
    changed.data.binding.policy = disabled.digest()?;
    changed.signature = f.issuer.sign(PURPOSE, &changed.data)?;
    assert!(
        changed
            .verify_data(
                &disabled,
                &disabled_certificate,
                &changed.data.tap,
                &changed.data.binding,
                &changed.data.challenge
            )
            .is_err()
    );
    let mut replacement = f.record.data.tap.clone();
    replacement.feed_epoch = digest("new-feed-incarnation");
    assert!(
        f.record
            .verify_data(
                &f.policy,
                &f.certificate,
                &replacement,
                &f.record.data.binding,
                &f.record.data.challenge
            )
            .is_err()
    );
    assert!(
        f.record
            .verify_data(
                &f.policy,
                &f.certificate,
                &f.record.data.tap,
                &f.record.data.binding,
                &digest("new-challenge")
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn canonical_bounded_data_refuses_duplicates_sequences_unknowns_and_foreign_errors() -> Result<()> {
    let f = Fixture::new()?;
    let bytes = f.record.encode_data()?;
    assert!(bytes.len() <= MAX_DATA_BYTES);
    f.check(&SignedCreateAttestationData::decode_data(&bytes)?)?;
    let mut maximal = f.record.clone();
    maximal.data.job.journal_sequence = u64::MAX - 1;
    maximal.data.pod.journal_sequence = u64::MAX;
    maximal.signature = f.issuer.sign(PURPOSE, &maximal.data)?;
    let maximal_bytes = maximal.encode_data()?;
    assert!(maximal_bytes.len() <= MAX_DATA_BYTES);
    f.check(&SignedCreateAttestationData::decode_data(&maximal_bytes)?)?;
    let base = serde_json::to_value(&f.record)?;
    for event in ["job", "pod"] {
        for verb in [
            json!("update"),
            json!("patch"),
            json!("delete"),
            Value::Null,
        ] {
            let mut value = base.clone();
            value["data"][event]["verb"] = verb;
            assert!(
                SignedCreateAttestationData::decode_data(&serde_json::to_vec(&value)?).is_err()
            );
        }
        let mut value = base.clone();
        value["data"][event].as_object_mut().unwrap().remove("verb");
        assert!(SignedCreateAttestationData::decode_data(&serde_json::to_vec(&value)?).is_err());
    }
    for pointer in [
        "",
        "/data",
        "/data/tap",
        "/data/binding",
        "/data/job",
        "/data/pod",
    ] {
        let mut value = base.clone();
        let slot = if pointer.is_empty() {
            &mut value
        } else {
            value.pointer_mut(pointer).unwrap()
        };
        *slot = Value::Array(slot.as_object().unwrap().values().cloned().collect());
        assert!(SignedCreateAttestationData::decode_data(&serde_json::to_vec(&value)?).is_err());
    }
    let text = String::from_utf8(bytes.clone())?;
    for key in [
        "signature",
        "issuer",
        "registry",
        "job_uid",
        "original_subject",
        "status",
    ] {
        let target = format!("\"{key}\":");
        assert!(text.contains(&target));
        let duplicate = text.replacen(&target, &format!("\"{key}\":null,{target}"), 1);
        assert!(
            SignedCreateAttestationData::decode_data(duplicate.as_bytes()).is_err(),
            "{key}"
        );
    }
    for pointer in [
        "/data",
        "/data/tap",
        "/data/binding",
        "/data/job",
        "/data/pod",
    ] {
        let mut value = base.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("untrusted".into(), json!("PRIVACY_CANARY"));
        let error = SignedCreateAttestationData::decode_data(&serde_json::to_vec(&value)?)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("PRIVACY_CANARY"));
    }
    for invalid in [
        vec![b'x'; MAX_DATA_BYTES + 1],
        bytes[..bytes.len() - 1].to_vec(),
        b"{\"data\":\"PRIVACY_CANARY\"}".to_vec(),
    ] {
        let error = SignedCreateAttestationData::decode_data(&invalid)
            .err()
            .unwrap();
        assert!(!error.to_string().contains("PRIVACY_CANARY"));
    }
    for (key, invalid) in [
        ("job_uid", "not-a-uid"),
        ("slot", "2026-11-26T17:00:00+00:00"),
    ] {
        let mut value = base.clone();
        value["data"]["binding"][key] = json!(invalid);
        assert!(SignedCreateAttestationData::decode_data(&serde_json::to_vec(&value)?).is_err());
    }
    Ok(())
}

#[test]
fn each_policy_tie_refuses_even_self_consistent_resigned_expected_data() -> Result<()> {
    let f = Fixture::new()?;
    f.check(&f.record)?;
    let original = serde_json::to_value(&f.record.data)?;
    for (key, replacement) in [
        ("namespace_uid", serde_json::to_value(uid(99))?),
        ("cron_job_uid", serde_json::to_value(uid(99))?),
        ("service_account_uid", serde_json::to_value(uid(99))?),
        ("cron_spec", serde_json::to_value(digest("wrong-selected-cron-spec"))?),
        ("admission", serde_json::to_value(digest("wrong-selected-admission"))?),
        ("policy", serde_json::to_value(digest("wrong-selected-policy"))?),
    ] {
        let mut value = original.clone();
        value["binding"][key] = replacement.clone();
        if key == "cron_job_uid" {
            // Keep the event chain internally consistent. Otherwise its owner
            // equality could mask deletion of the actual selected-policy tie.
            value["job"]["owner_uid"] = replacement;
        }
        let signed = f.signed(value)?;
        assert!(signed.verify_data(
            &f.policy,
            &f.certificate,
            &signed.data.tap,
            &signed.data.binding,
            &signed.data.challenge,
        ).is_err(), "{key}");
    }
    let mut value = original;
    value["tap"]["cluster_incarnation"] = serde_json::to_value(digest("wrong-selected-cluster"))?;
    let signed = f.signed(value)?;
    assert!(signed.verify_data(
        &f.policy,
        &f.certificate,
        &signed.data.tap,
        &signed.data.binding,
        &signed.data.challenge,
    ).is_err());
    // Dynamic Job/Pod identities and registry fields are intentionally not
    // tested against a fictitious global-current registry: their independent
    // expected values must come from the actual retained caller context.
    Ok(())
}
