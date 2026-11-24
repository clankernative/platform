use super::*;
use crate::security_epoch::scheduled_backup::{Destination, Requester, Slot, Source, Transport};

#[test]
fn submit_wire_is_one_canonical_purpose_and_preserves_the_complete_intent() -> Result<()> {
    let fixture = Fixture::new()?;
    let intent = serde_json::to_vec(&fixture.intent)?;
    require_submit_original_data(&intent, &fixture.intent.transport.original)?;
    assert!(require_submit_original_data(&intent, &digest("a-later-original")).is_err());
    let encoded = encode_submit_data(&intent)?;
    assert_eq!(decode_submit_data(&encoded)?, intent);
    let overhead = b"{\"type\":\"submit_backup_v1\",\"intent\":}".len();
    assert_eq!(encoded.len(), intent.len() + overhead);
    assert_eq!(MAX_SUBMIT_BYTES, super::super::MAX_PAYLOAD + overhead);
    assert!(decode_submit_data(&intent).is_err());
    let good: Value = serde_json::from_slice(&encoded)?;
    for malformed in [
        json!({"type":"submit_backup_v2", "intent":good["intent"]}),
        json!({"type":"submit_backup_v1", "intent":good["intent"], "extra":true}),
        json!({"type":"submit_backup_v1"}),
        json!({"type":"submit_backup_v1", "intent":null}),
        json!([good.clone()]),
        Value::Null,
    ] {
        assert!(decode_submit_data(&serde_json::to_vec(&malformed)?).is_err());
    }
    let text = String::from_utf8(encoded.clone())?;
    let duplicate_type = text.replacen(
        "\"type\":\"submit_backup_v1\"",
        "\"type\":\"submit_backup_v1\",\"type\":\"submit_backup_v1\"",
        1,
    );
    assert!(decode_submit_data(duplicate_type.as_bytes()).is_err());
    let nested_duplicate = text.replacen(
        "\"policy_generation\":",
        "\"policy_generation\":null,\"policy_generation\":",
        1,
    );
    assert_ne!(nested_duplicate, text);
    assert!(decode_submit_data(nested_duplicate.as_bytes()).is_err());
    let mut trailing = encoded.clone();
    trailing.push(b'\n');
    assert!(decode_submit_data(&trailing).is_err());
    assert!(decode_submit_data(&vec![b' '; MAX_SUBMIT_BYTES + 1]).is_err());
    assert!(encode_submit_data(&vec![b' '; super::super::MAX_PAYLOAD + 1]).is_err());
    let mut changed = fixture.intent;
    changed.operation = digest("another-operation");
    let changed_wire = encode_submit_data(&serde_json::to_vec(&changed)?)?;
    let changed_intent = decode_submit_data(&changed_wire)?;
    assert_ne!(
        intent_digest_data(&changed_intent)?,
        intent_digest_data(&intent)?
    );
    Ok(())
}

fn offer_data() -> SubmitOfferData {
    SubmitOfferData::new_data(
        digest("actual-controller"),
        digest("actual-job-sender"),
        17,
        (digest("requester-hello"), digest("controller-offer")),
        digest("actual-submitted-original"),
    )
    .unwrap()
}

#[test]
fn hello_and_offer_are_strict_canonical_bounded_comparison_data() -> Result<()> {
    let offer = offer_data();
    offer.require_connection_data(17)?;
    assert!(offer.require_connection_data(18).is_err());
    assert!(offer.require_connection_data(0).is_err());
    assert!(
        SubmitOfferData::new_data(
            offer.controller.clone(),
            offer.job.clone(),
            0,
            (
                offer.requester_nonce.clone(),
                offer.controller_nonce.clone()
            ),
            offer.original.clone()
        )
        .is_err()
    );
    let hello = encode_hello_data(offer.requester_nonce.clone())?;
    assert_eq!(decode_hello_data(&hello)?, offer.requester_nonce);
    let bytes = encode_offer_data(&offer)?;
    assert!(decode_offer_data(&bytes)? == offer);
    assert!(hello.len() < MAX_HELLO_BYTES && bytes.len() < MAX_OFFER_BYTES);
    let good: Value = serde_json::from_slice(&bytes)?;
    for value in [
        json!({"type":"hello_backup_v1","requester_nonce":offer.requester_nonce,"extra":true}),
        json!({"type":"hello_backup_v2","requester_nonce":offer.requester_nonce}),
        json!({"type":"hello_backup_v1"}),
        json!({"type":"hello_backup_v1","requester_nonce":null}),
        json!({"type":"hello_backup_v1","requester_nonce":offer.requester_nonce,"offer":good["offer"]}),
        json!([]),
        Value::Null,
    ] {
        assert!(decode_hello_data(&serde_json::to_vec(&value)?).is_err());
    }
    for value in [
        json!({"type":"offer_backup_v2","offer":good["offer"]}),
        json!({"type":"offer_backup_v1","offer":good["offer"],"extra":true}),
        json!({"type":"offer_backup_v1"}),
        json!({"type":"offer_backup_v1","offer":null}),
        json!([]),
        Value::Null,
    ] {
        assert!(decode_offer_data(&serde_json::to_vec(&value)?).is_err());
    }
    for field in [
        "controller",
        "job",
        "connection",
        "requester_nonce",
        "controller_nonce",
        "original",
    ] {
        let mut value = good.clone();
        value["offer"].as_object_mut().unwrap().remove(field);
        assert!(decode_offer_data(&serde_json::to_vec(&value)?).is_err());
        let mut value = good.clone();
        value["offer"][field] = Value::Null;
        assert!(decode_offer_data(&serde_json::to_vec(&value)?).is_err());
    }
    let mut unknown = good.clone();
    unknown["offer"]["extra"] = json!(true);
    assert!(decode_offer_data(&serde_json::to_vec(&unknown)?).is_err());
    let text = String::from_utf8(bytes.clone())?;
    for (before, after) in [
        (
            "\"type\":\"offer_backup_v1\"",
            "\"type\":\"offer_backup_v1\",\"type\":\"offer_backup_v1\"",
        ),
        ("\"connection\":", "\"connection\":null,\"connection\":"),
    ] {
        assert_eq!(text.matches(before).count(), 1);
        assert!(decode_offer_data(text.replacen(before, after, 1).as_bytes()).is_err());
    }
    let htext = String::from_utf8(hello.clone())?;
    assert_eq!(htext.matches("\"requester_nonce\":").count(), 1);
    assert!(
        decode_hello_data(
            htext
                .replacen(
                    "\"requester_nonce\":",
                    "\"requester_nonce\":null,\"requester_nonce\":",
                    1
                )
                .as_bytes()
        )
        .is_err()
    );
    let mut reflected = offer.clone();
    reflected.controller_nonce = reflected.requester_nonce.clone();
    assert!(encode_offer_data(&reflected).is_err());
    let value = json!({"type":"offer_backup_v1","offer":reflected});
    assert!(decode_offer_data(&serde_json::to_vec(&value)?).is_err());
    for (original, limit, is_offer) in [
        (&bytes, MAX_OFFER_BYTES, true),
        (&hello, MAX_HELLO_BYTES, false),
    ] {
        let mut oversized = original.clone();
        oversized.resize(limit + 1, b' ');
        // A valid JSON packet, so the bound controls are independent of parsing.
        let _: Value = serde_json::from_slice(&oversized)?;
        let oversized_error = if is_offer {
            decode_offer_data(&oversized).map(|_| ())
        } else {
            decode_hello_data(&oversized).map(|_| ())
        }
        .unwrap_err();
        assert_eq!(
            oversized_error.to_string(),
            if is_offer {
                "backup_offer_bound"
            } else {
                "backup_hello_bound"
            }
        );
        let mut trailing = original.clone();
        trailing.push(b'\n');
        let trailing_error = if is_offer {
            decode_offer_data(&trailing).map(|_| ())
        } else {
            decode_hello_data(&trailing).map(|_| ())
        }
        .unwrap_err();
        assert_eq!(
            trailing_error.to_string(),
            if is_offer {
                "backup_offer_noncanonical"
            } else {
                "backup_hello_noncanonical"
            }
        );
    }
    assert!(decode_offer_data(&hello).is_err());
    assert!(decode_hello_data(&bytes).is_err());
    Ok(())
}

#[test]
fn candidate_intent_binds_every_saved_offer_field_without_changing_other_data() -> Result<()> {
    let fixture = Fixture::new()?;
    let candidate = serde_json::to_vec(&fixture.intent)?;
    let offer = offer_data();
    let complete = complete_offer_intent_data(&candidate, &offer)?;
    require_submit_offer_data(&complete, &offer)?;
    let parsed = Intent::decode_data(&complete)?;
    let mut expected = fixture.intent;
    expected.requester.process = offer.job.clone();
    expected.transport = Transport {
        controller: offer.controller.clone(),
        connection: offer.connection.clone(),
        requester_nonce: offer.requester_nonce.clone(),
        controller_nonce: offer.controller_nonce.clone(),
        original: offer.original.clone(),
    };
    assert_eq!(parsed, expected);
    let value: Value = serde_json::from_slice(&complete)?;
    for path in [
        ["requester", "process"],
        ["transport", "controller"],
        ["transport", "connection"],
        ["transport", "requester_nonce"],
        ["transport", "controller_nonce"],
        ["transport", "original"],
    ] {
        let mut changed = value.clone();
        changed[path[0]][path[1]] = json!(digest("wrong-field"));
        let intent = super::fixture_intent_bytes(changed)?;
        assert!(require_submit_offer_data(&intent, &offer).is_err());
    }
    let mut reflected = offer.clone();
    reflected.controller_nonce = reflected.requester_nonce.clone();
    assert!(complete_offer_intent_data(&candidate, &reflected).is_err());
    assert!(require_submit_offer_data(&complete, &reflected).is_err());
    Ok(())
}

fn uid(n: u32) -> String {
    format!("00000000-0000-0000-0000-{n:012}")
}

fn digest(text: &str) -> Digest {
    Digest::new(text.as_bytes())
}

fn object_selection(name: &str, n: u32) -> KubernetesObjectSelection {
    KubernetesObjectSelection {
        name: name.into(),
        uid: uid(n),
    }
}

struct Fixture {
    policy: RequesterPolicy,
    intent: Intent,
    objects: [Value; 7],
}

pub(super) fn policy_fixture_data() -> Result<RequesterPolicy> {
    Ok(Fixture::new()?.policy)
}

impl Fixture {
    fn new() -> Result<Self> {
        let scope = AuthorityScope {
            installation: "fixture".to_owned().try_into()?,
            environment: "canary".to_owned().try_into()?,
            app: "calendar".to_owned().try_into()?,
        };
        let mut policy = RequesterPolicy {
            scope: scope.clone(),
            generation: digest("reviewed-generation"),
            eligible_from: "2026-11-22T17:00:00Z".into(),
            cluster: digest("cluster"),
            node: digest("node"),
            node_name: "node-one".into(),
            namespace: object_selection("calendar", 2),
            cron_job: object_selection("calendar-backup", 1),
            service_account: object_selection("backup", 5),
            uploader: EpochIam::GkeWorkloadIdentityV1 {
                service_account: "backup@fixture-project.iam.gserviceaccount.com".into(),
                service_account_uid: "100000000000000000002".to_owned().try_into()?,
            },
            container: "backup".into(),
            image: digest("reviewed-image"),
            executable: digest("reviewed-executable"),
            cron_spec: digest("placeholder"),
            job_pod_spec: digest("placeholder"),
            running_pod_spec: digest("placeholder"),
            admission: object_selection("calendar-backup", 6),
            binding: object_selection("calendar-backup", 7),
            cron_controller: "fixture:qualified-cron-controller".into(),
            job_controller: "fixture:qualified-job-controller".into(),
            cleanup_controller: "fixture:qualified-garbage-collector".into(),
            configuration_writers: vec!["fixture:reviewed-config-writer".into()],
        };
        let annotations = json!({GENERATION:policy.generation,CRON_UID:policy.cron_job.uid});
        let pod_spec = json!({"serviceAccountName":"backup","automountServiceAccountToken":false,"restartPolicy":"Never","enableServiceLinks":false,
            "containers":[{"name":"backup","image":format!("fixture.invalid/image@{}",policy.image.as_str()),"command":["/usr/local/bin/day2-backup"],
              "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"runAsGroup":10001,"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"privileged":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}},
              "volumeMounts":[{"name":"socket","mountPath":"/run/day2-backup","readOnly":true},{"name":"scratch","mountPath":"/tmp"}]}],
            "volumes":[{"name":"socket","hostPath":{"path":"/run/day2-backup/calendar","type":"Directory"}},{"name":"scratch","emptyDir":{"sizeLimit":"64Mi"}}]});
        let mut running = pod_spec.clone();
        running["nodeName"] = json!("node-one");
        let cron_spec = json!({"suspend":false,"schedule":"0 * * * *","timeZone":"Etc/UTC","concurrencyPolicy":"Forbid","startingDeadlineSeconds":60,
            "jobTemplate":{"metadata":{"annotations":annotations},"spec":{"backoffLimit":0,"parallelism":1,"completions":1,"activeDeadlineSeconds":300,"template":{"metadata":{"annotations":annotations},"spec":pod_spec}}}});
        policy.cron_spec = Digest::of(&cron_spec)?;
        policy.job_pod_spec = Digest::of(&pod_spec)?;
        policy.running_pod_spec = Digest::of(&running)?;
        let meta = |name: &str, n: u32| json!({"name":name,"uid":uid(n),"namespace":"calendar","annotations":annotations});
        let namespace = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"calendar","uid":uid(2)}});
        let mut account =
            json!({"apiVersion":"v1","kind":"ServiceAccount","metadata":meta("backup",5)});
        account["metadata"]["annotations"]["iam.gke.io/gcp-service-account"] =
            json!("backup@fixture-project.iam.gserviceaccount.com");
        let cron = json!({"apiVersion":"batch/v1","kind":"CronJob","metadata":meta("calendar-backup",1),"spec":cron_spec});
        let mut job = json!({"apiVersion":"batch/v1","kind":"Job","metadata":meta("calendar-backup-123",3),"spec":{"backoffLimit":0,"parallelism":1,"completions":1,"activeDeadlineSeconds":300,"template":{"metadata":{"annotations":annotations},"spec":pod_spec}},"status":{"active":1}});
        job["metadata"]["annotations"][SLOT] = json!("2026-11-22T17:00:00Z");
        job["metadata"]["ownerReferences"] = json!([{"apiVersion":"batch/v1","kind":"CronJob","name":"calendar-backup","uid":uid(1),"controller":true}]);
        let mut pod = json!({"apiVersion":"v1","kind":"Pod","metadata":meta("calendar-backup-123-abc",4),"spec":running,"status":{"phase":"Running","containerStatuses":[{"name":"backup","containerID":format!("containerd://{}","a".repeat(64)),"imageID":format!("docker-pullable://fixture.invalid/image@{}",policy.image.as_str()),"restartCount":0,"state":{"running":{}}}]}});
        pod["metadata"]["ownerReferences"] = json!([{"apiVersion":"batch/v1","kind":"Job","name":"calendar-backup-123","uid":uid(3),"controller":true}]);
        let admission = json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicy","metadata":{"name":"calendar-backup","uid":uid(6),"generation":1},"spec":policy.policy_spec_data()?,"status":{"observedGeneration":1,"typeChecking":{"expressionWarnings":[]}}});
        let binding = json!({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicyBinding","metadata":{"name":"calendar-backup","uid":uid(7)},"spec":policy.binding_spec_data()});
        let intent = Intent {
            slot: Slot {
                scope,
                cron_job_uid: uid(1).try_into()?,
                scheduled_at: "2026-11-22T17:00:00Z".to_owned().try_into()?,
            },
            policy_generation: policy.generation.clone(),
            admission_generation: policy.admission_generation_data()?,
            cron_job_spec: policy.cron_spec.clone(),
            requester: Requester {
                cluster: policy.cluster.clone(),
                node: policy.node.clone(),
                namespace_uid: uid(2).try_into()?,
                job_uid: uid(3).try_into()?,
                pod_uid: uid(4).try_into()?,
                ksa_uid: uid(5).try_into()?,
                uploader_uid: "100000000000000000002".to_owned().try_into()?,
                image: policy.image.clone(),
                executable: policy.executable.clone(),
                process: digest("actual-process-precondition"),
            },
            source: Source {
                store: digest("store"),
                authority: digest("authority"),
                epoch: 7.try_into()?,
                artifact: digest("artifact"),
            },
            transport: Transport {
                controller: digest("controller"),
                connection: digest("connection"),
                requester_nonce: digest("requester-nonce"),
                controller_nonce: digest("controller-nonce"),
                original: digest("original"),
            },
            operation: digest("operation"),
            destination: Destination {
                bucket: "fixture-private-backups".into(),
                prefix: "calendar/20261122T170000Z".into(),
                readers: digest("readers"),
            },
        };
        Ok(Self {
            policy,
            intent,
            objects: [namespace, account, cron, job, pod, admission, binding],
        })
    }

    fn check(&self) -> Result<WorkloadData> {
        let bytes = self
            .objects
            .iter()
            .map(serde_json::to_vec)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        validate_workload_data(
            &self.policy,
            &ReviewedSubject {
                pod_name: "calendar-backup-123-abc".into(),
                pod_uid: uid(4),
            },
            &serde_json::to_vec(&self.intent)?,
            WorkloadResponses {
                namespace: &bytes[0],
                service_account: &bytes[1],
                cron_job: &bytes[2],
                job: &bytes[3],
                pod: &bytes[4],
                admission: &bytes[5],
                binding: &bytes[6],
            },
        )
    }
}

pub(super) fn comparison_fixture_data() -> Result<(RequesterPolicy, Value, WorkloadData)> {
    let f = Fixture::new()?;
    let data = f.check()?;
    Ok((f.policy, serde_json::to_value(&f.intent)?, data))
}

#[test]
fn full_selected_workload_returns_only_bounded_comparison_data() -> Result<()> {
    let f = Fixture::new()?;
    let data = f.check()?;
    assert_eq!(data.pod_uid, uid(4));
    assert_eq!(data.job_uid, uid(3));
    assert_eq!(data.scheduled_slot, "2026-11-22T17:00:00Z");
    assert_eq!(
        data.container_id,
        format!("containerd://{}", "a".repeat(64))
    );
    assert!(serde_json::to_vec(&data)?.len() < 1024);
    assert!(!serde_json::to_string(&data)?.contains("config-writer"));
    Ok(())
}

#[test]
fn signed_workload_comparison_reuses_the_producer_join_and_rejects_changed_data() -> Result<()> {
    let f = Fixture::new()?;
    let data = f.check()?;
    let bytes = serde_json::to_vec(&f.intent)?;
    require_observed_workload_data(&f.policy, &bytes, &data)?;
    for cut in 0..6 {
        let mut changed = data.clone();
        match cut {
            0 => changed.job_uid = uid(90),
            1 => changed.pod_uid = uid(91),
            2 => changed.scheduled_slot = "2026-11-22T18:00:00Z".into(),
            3 => changed.admission_generation = digest("different-admission"),
            4 => changed.restart_count = 1,
            _ => changed.scheduled_slot = "2026-11-22T16:00:00Z".into(),
        }
        assert!(
            require_observed_workload_data(&f.policy, &bytes, &changed).is_err(),
            "cut {cut}"
        );
    }
    let mut changed = f.intent.clone();
    changed.policy_generation = digest("different-policy");
    assert!(
        require_observed_workload_data(&f.policy, &serde_json::to_vec(&changed)?, &data).is_err()
    );
    let mut selected = f.policy;
    selected.generation = digest("different-selection");
    assert!(require_observed_workload_data(&selected, &bytes, &data).is_err());
    Ok(())
}

#[test]
fn every_live_object_identity_and_owner_is_bound_not_selected_from_the_reply() -> Result<()> {
    for index in 0..7 {
        for path in ["/metadata/uid", "/metadata/name"] {
            let mut f = Fixture::new()?;
            *f.objects[index].pointer_mut(path).unwrap() = json!(if path.ends_with("uid") {
                uid(99)
            } else {
                "foreign".into()
            });
            assert!(f.check().is_err(), "object {index} {path}");
        }
        let mut f = Fixture::new()?;
        f.objects[index]["metadata"]["deletionTimestamp"] = json!("2026-11-22T17:00:01Z");
        assert!(f.check().is_err());
    }
    for index in [3, 4] {
        for field in ["apiVersion", "kind", "name", "uid", "controller"] {
            let mut f = Fixture::new()?;
            f.objects[index]["metadata"]["ownerReferences"][0][field] = json!("foreign");
            assert!(f.check().is_err());
        }
        let mut f = Fixture::new()?;
        f.objects[index]["metadata"]["ownerReferences"] = json!([]);
        assert!(f.check().is_err());
    }
    Ok(())
}

#[test]
fn full_approved_specs_refuse_unknown_mutators_and_never_hash_them_into_selection() -> Result<()> {
    for index in [2, 3, 4] {
        let mut f = Fixture::new()?;
        let pointer = match index {
            2 => "/spec",
            3 => "/spec/template/spec",
            _ => "/spec",
        };
        f.objects[index].pointer_mut(pointer).unwrap()["unknownInjectedMutator"] = json!(true);
        assert!(f.check().is_err());
    }
    // Even deliberately changing the *configured digest* does not bless a
    // forbidden privilege or an unsupported field/volume/security shape.
    for (path, value) in [
        ("/hostPID", json!(true)),
        ("/hostNetwork", json!(true)),
        ("/runtimeClassName", json!("unreviewed")),
        ("/initContainers", json!([{"name":"sidecar"}])),
        ("/ephemeralContainers", json!("wrong-shape")),
        ("/automountServiceAccountToken", json!(true)),
        ("/containers/0/securityContext/privileged", json!(true)),
        ("/containers/0/securityContext/runAsUser", json!(0)),
        (
            "/containers/0/securityContext/seccompProfile/type",
            json!("Unconfined"),
        ),
        (
            "/containers/0/securityContext/capabilities/add",
            json!(["SYS_ADMIN"]),
        ),
        ("/volumes/0/hostPath/path", json!("/proc")),
        ("/containers/0/volumeMounts/0/readOnly", json!(false)),
    ] {
        let mut f = Fixture::new()?;
        let spec = &mut f.objects[4]["spec"];
        if let Some(v) = spec.pointer_mut(path) {
            *v = value;
        } else {
            let key = path.strip_prefix('/').unwrap();
            spec[key] = value;
        }
        f.policy.running_pod_spec = Digest::of(spec)?;
        assert!(f.check().is_err(), "forbidden {path}");
    }
    Ok(())
}

#[test]
fn exact_live_enforcement_refuses_audit_only_ignored_replaced_or_unobserved_policy() -> Result<()> {
    for (index, path, value) in [
        (5, "/spec/failurePolicy", json!("Ignore")),
        (5, "/spec/matchConditions", json!([])),
        (5, "/spec/validations", json!([])),
        (5, "/status/observedGeneration", json!(0)),
        (
            5,
            "/status/typeChecking/expressionWarnings",
            json!([{"warning":"fixture"}]),
        ),
        (
            5,
            "/status/typeChecking/expressionWarnings",
            json!("wrong-shape"),
        ),
        (6, "/spec/validationActions", json!(["Audit"])),
        (6, "/spec/policyName", json!("another")),
    ] {
        let mut f = Fixture::new()?;
        *f.objects[index].pointer_mut(path).unwrap() = value;
        assert!(f.check().is_err(), "enforcement {path}");
    }
    let mut f = Fixture::new()?;
    f.objects[6]["spec"]["matchResources"] =
        json!({"namespaceSelector":{"matchLabels":{"bypass":"yes"}}});
    assert!(f.check().is_err());
    // Matching current enforcement is only DATA, not proof of protection at
    // creation: no constructor here yields a requester/source/role owner.
    Ok(())
}

#[test]
fn scheduler_slot_generation_sandbox_status_and_uploader_selection_are_exact() -> Result<()> {
    for (index, path, value) in [
        (
            1,
            "/metadata/annotations/iam.gke.io~1gcp-service-account",
            json!("other@fixture-project.iam.gserviceaccount.com"),
        ),
        (2, "/spec/suspend", json!(true)),
        (2, "/spec/timeZone", json!("America/Los_Angeles")),
        (
            3,
            "/metadata/annotations/batch.kubernetes.io~1cronjob-scheduled-timestamp",
            json!("2026-11-22T17:00:00+00:00"),
        ),
        (3, "/spec/backoffLimit", json!(1)),
        (3, "/spec/parallelism", json!(2)),
        (4, "/spec/nodeName", json!("foreign-node")),
        (4, "/status/phase", json!("Succeeded")),
        (4, "/status/containerStatuses/0/restartCount", json!(1)),
        (
            4,
            "/status/containerStatuses/0/imageID",
            json!("unreviewed-image"),
        ),
        (
            4,
            "/status/containerStatuses/0/containerID",
            json!("docker://legacy"),
        ),
    ] {
        let mut f = Fixture::new()?;
        *f.objects[index].pointer_mut(path).unwrap() = value;
        assert!(f.check().is_err(), "selection {path}");
    }
    for index in [2, 3, 4] {
        let mut f = Fixture::new()?;
        f.objects[index]["metadata"]["annotations"][GENERATION] = json!(digest("replaced"));
        assert!(f.check().is_err());
    }
    let mut f = Fixture::new()?;
    f.intent.admission_generation = digest("old-policy");
    assert!(f.check().is_err());
    let mut f = Fixture::new()?;
    f.intent.requester.uploader_uid = "100000000000000000003".to_owned().try_into()?;
    assert!(f.check().is_err());
    Ok(())
}

#[test]
fn fixed_enforcement_profile_has_no_caller_cel_expressions_or_subject_fallback() -> Result<()> {
    let mut f = Fixture::new()?;
    let spec = f.policy.policy_spec_data()?;
    assert_eq!(spec["failurePolicy"], "Fail");
    assert_eq!(spec["validations"].as_array().unwrap().len(), 3);
    let text = serde_json::to_string(&spec)?;
    for required in [
        "fixture:qualified-cron-controller",
        "fixture:qualified-job-controller",
        "fixture:reviewed-config-writer",
        "oldObject",
        "ownerReferences",
        "cronjob-scheduled-timestamp",
        "object.spec == oldObject.spec",
    ] {
        assert!(text.contains(required), "missing fixed guard");
    }
    assert_eq!(
        f.policy.binding_spec_data(),
        json!({"policyName":"calendar-backup","validationActions":["Deny"]})
    );
    f.policy.job_controller = f.policy.cron_controller.clone();
    assert!(f.policy.validate_data().is_ok());
    f.policy.job_controller.clear();
    assert!(f.policy.validate_data().is_err());
    let mut f = Fixture::new()?;
    f.policy
        .configuration_writers
        .push(f.policy.cron_controller.clone());
    assert!(f.policy.validate_data().is_err());
    let mut f = Fixture::new()?;
    f.policy.cron_controller = "injected' || true".into();
    assert!(f.policy.validate_data().is_err());
    Ok(())
}

#[test]
fn eligible_cutoff_is_independent_of_current_enforcement_and_cannot_reopen_old_generation()
-> Result<()> {
    let mut f = Fixture::new()?;
    f.policy.eligible_from = "2026-11-22T18:00:00Z".into();
    assert!(f.check().is_err());
    let mut f = Fixture::new()?;
    f.intent.policy_generation = digest("old-generation");
    assert!(f.check().is_err());
    let mut f = Fixture::new()?;
    f.policy.eligible_from = "2026-11-22T17:00:00+00:00".into();
    assert!(f.policy.validate_data().is_err());
    Ok(())
}

#[test]
fn response_codec_refuses_duplicates_arrays_and_oversize_before_comparison() {
    for bytes in [
        b"{\"kind\":\"Job\",\"kind\":\"Pod\"}".as_slice(),
        b"[\"Job\"]",
        b"null",
    ] {
        assert!(
            decode(bytes)
                .and_then(|value| metadata(&value, "batch/v1", "Job").map(|_| ()))
                .is_err()
        );
    }
    assert!(decode(&vec![b' '; MAX_RESPONSE + 1]).is_err());
}

// A deliberately finite test interpreter for the actual generated DELETE
// expressions. It evaluates standard CEL map/list/Boolean operators used by
// these controls, not Kubernetes admission, type checking or provider proofs.
// Unsupported syntax/calls fail the test; they never become a positive result.
#[derive(Clone, Debug, PartialEq)]
enum CelToken {
    Name(String),
    Text(String),
    Number(u64),
    Symbol(String),
}
#[derive(Clone, Debug)]
enum CelNode {
    Literal(Value),
    Root(String),
    Field(Box<Self>, String),
    Index(Box<Self>, usize),
    Array(Vec<Self>),
    Has(Box<Self>),
    Size(Box<Self>),
    Not(Box<Self>),
    Binary(String, Box<Self>, Box<Self>),
    Conditional(Box<Self>, Box<Self>, Box<Self>),
    UnsupportedCall(String, Box<Self>, Vec<Self>),
}
struct CelFixture {
    tokens: Vec<CelToken>,
    at: usize,
}
impl CelFixture {
    fn parse(text: &str) -> Result<CelNode> {
        let bytes = text.as_bytes();
        let mut at = 0;
        let mut tokens = Vec::new();
        while at < bytes.len() {
            let byte = bytes[at];
            if byte.is_ascii_whitespace() {
                at += 1;
                continue;
            }
            if byte == b'\'' || byte == b'"' {
                let quote = byte;
                let start = at;
                at += 1;
                while at < bytes.len() && bytes[at] != quote {
                    ensure!(bytes[at] != b'\\', "unsupported CEL fixture escape");
                    at += 1;
                }
                ensure!(at < bytes.len(), "unterminated CEL fixture string");
                tokens.push(CelToken::Text(text[start + 1..at].into()));
                at += 1;
            } else if byte.is_ascii_alphabetic() || byte == b'_' {
                let start = at;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                tokens.push(CelToken::Name(text[start..at].into()));
            } else if byte.is_ascii_digit() {
                let start = at;
                while at < bytes.len() && bytes[at].is_ascii_digit() {
                    at += 1;
                }
                tokens.push(CelToken::Number(text[start..at].parse()?));
            } else {
                let pair = text.get(at..at + 2).unwrap_or("");
                if ["==", "!=", "&&", "||"].contains(&pair) {
                    tokens.push(CelToken::Symbol(pair.into()));
                    at += 2;
                } else {
                    ensure!(
                        b"!().[],:?".contains(&byte),
                        "unsupported CEL fixture token"
                    );
                    tokens.push(CelToken::Symbol((byte as char).to_string()));
                    at += 1;
                }
            }
        }
        let mut parser = Self { tokens, at: 0 };
        let node = parser.conditional()?;
        ensure!(
            parser.at == parser.tokens.len(),
            "trailing CEL fixture input"
        );
        Ok(node)
    }
    fn take(&mut self, symbol: &str) -> bool {
        if self.tokens.get(self.at) == Some(&CelToken::Symbol(symbol.into())) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn require(&mut self, symbol: &str) -> Result<()> {
        ensure!(self.take(symbol), "missing CEL fixture symbol");
        Ok(())
    }
    fn conditional(&mut self) -> Result<CelNode> {
        let test = self.binary(0)?;
        if self.take("?") {
            let yes = self.conditional()?;
            self.require(":")?;
            let no = self.conditional()?;
            Ok(CelNode::Conditional(
                Box::new(test),
                Box::new(yes),
                Box::new(no),
            ))
        } else {
            Ok(test)
        }
    }
    fn binary(&mut self, level: usize) -> Result<CelNode> {
        if level == 3 {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        loop {
            let op = match self.tokens.get(self.at) {
                Some(CelToken::Symbol(s))
                    if (level == 0 && s == "||")
                        || (level == 1 && s == "&&")
                        || (level == 2 && ["==", "!="].contains(&s.as_str())) =>
                {
                    Some(s.clone())
                }
                Some(CelToken::Name(s)) if level == 2 && s == "in" => Some(s.clone()),
                _ => None,
            };
            let Some(op) = op else {
                break;
            };
            self.at += 1;
            let right = self.binary(level + 1)?;
            left = CelNode::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn unary(&mut self) -> Result<CelNode> {
        if self.take("!") {
            return Ok(CelNode::Not(Box::new(self.unary()?)));
        }
        let mut value = if self.take("(") {
            let value = self.conditional()?;
            self.require(")")?;
            value
        } else if self.take("[") {
            let mut items = Vec::new();
            if !self.take("]") {
                loop {
                    items.push(self.conditional()?);
                    if self.take("]") {
                        break;
                    }
                    self.require(",")?;
                }
            }
            CelNode::Array(items)
        } else {
            let token = self
                .tokens
                .get(self.at)
                .context("missing CEL fixture atom")?
                .clone();
            self.at += 1;
            match token {
                CelToken::Text(s) => CelNode::Literal(json!(s)),
                CelToken::Number(n) => CelNode::Literal(json!(n)),
                CelToken::Name(s) if s == "null" => CelNode::Literal(Value::Null),
                CelToken::Name(s) if s == "true" || s == "false" => {
                    CelNode::Literal(json!(s == "true"))
                }
                CelToken::Name(s) if s == "has" => {
                    self.require("(")?;
                    let v = self.conditional()?;
                    self.require(")")?;
                    CelNode::Has(Box::new(v))
                }
                CelToken::Name(s) => CelNode::Root(s),
                _ => anyhow::bail!("unsupported CEL fixture atom"),
            }
        };
        loop {
            if self.take(".") {
                let Some(CelToken::Name(name)) = self.tokens.get(self.at).cloned() else {
                    anyhow::bail!("missing CEL fixture field")
                };
                self.at += 1;
                if self.take("(") {
                    let mut args = Vec::new();
                    if !self.take(")") {
                        loop {
                            args.push(self.conditional()?);
                            if self.take(")") {
                                break;
                            }
                            self.require(",")?;
                        }
                    }
                    value = if name == "size" && args.is_empty() {
                        CelNode::Size(Box::new(value))
                    } else {
                        CelNode::UnsupportedCall(name, Box::new(value), args)
                    };
                } else {
                    value = CelNode::Field(Box::new(value), name);
                }
            } else if self.take("[") {
                let token = self
                    .tokens
                    .get(self.at)
                    .context("missing CEL fixture index")?
                    .clone();
                self.at += 1;
                self.require("]")?;
                value = match token {
                    CelToken::Number(n) => CelNode::Index(Box::new(value), usize::try_from(n)?),
                    CelToken::Text(key) => CelNode::Field(Box::new(value), key),
                    _ => anyhow::bail!("unsupported CEL fixture index"),
                };
            } else {
                break;
            }
        }
        Ok(value)
    }
}
impl CelNode {
    fn evaluate(&self, context: &Value) -> Result<Value> {
        let boolean = |value: Value| value.as_bool().context("CEL fixture Boolean required");
        match self {
            Self::Literal(v) => Ok(v.clone()),
            Self::Root(name) => context
                .get(name)
                .cloned()
                .context("missing CEL fixture root"),
            Self::Field(parent, key) => parent
                .evaluate(context)?
                .get(key)
                .cloned()
                .context("missing CEL fixture field"),
            Self::Index(parent, index) => parent
                .evaluate(context)?
                .get(index)
                .cloned()
                .context("missing CEL fixture index"),
            Self::Array(items) => Ok(Value::Array(
                items
                    .iter()
                    .map(|v| v.evaluate(context))
                    .collect::<Result<Vec<_>>>()?,
            )),
            Self::Has(value) => Ok(json!(value.evaluate(context).is_ok())),
            Self::Size(value) => {
                let value = value.evaluate(context)?;
                Ok(json!(match &value {
                    Value::Array(v) => v.len(),
                    Value::Object(v) => v.len(),
                    _ => anyhow::bail!("unsupported CEL fixture size"),
                }))
            }
            Self::Not(value) => Ok(json!(!boolean(value.evaluate(context)?)?)),
            Self::Conditional(test, yes, no) => {
                if boolean(test.evaluate(context)?)? {
                    yes.evaluate(context)
                } else {
                    no.evaluate(context)
                }
            }
            Self::Binary(op, left, right) => {
                let left = left.evaluate(context)?;
                let result = match op.as_str() {
                    "&&" => boolean(left)? && boolean(right.evaluate(context)?)?,
                    "||" => boolean(left)? || boolean(right.evaluate(context)?)?,
                    "==" => left == right.evaluate(context)?,
                    "!=" => left != right.evaluate(context)?,
                    "in" => match right.evaluate(context)? {
                        Value::Array(values) => values.contains(&left),
                        Value::Object(values) => {
                            left.as_str().is_some_and(|s| values.contains_key(s))
                        }
                        _ => anyhow::bail!("unsupported CEL fixture membership"),
                    },
                    _ => anyhow::bail!("unsupported CEL fixture operator"),
                };
                Ok(json!(result))
            }
            Self::UnsupportedCall(name, target, args) => {
                let _ = (name, target, args);
                anyhow::bail!("unexecuted CEL fixture call reached")
            }
        }
    }
}

#[test]
fn generated_delete_rules_allow_real_deadline_cleanup_and_refuse_untrusted_or_wrong_owner()
-> Result<()> {
    let f = Fixture::new()?;
    let spec = f.policy.policy_spec_data()?;
    for (resource, index, object, controller) in [
        ("jobs", 1, &f.objects[3], f.policy.cron_controller.as_str()),
        ("pods", 2, &f.objects[4], f.policy.job_controller.as_str()),
    ] {
        let expression = spec["validations"][index]["expression"].as_str().unwrap();
        let program = CelFixture::parse(expression)?;
        let context = |actor: &str, old: Value| json!({"request":{"resource":{"resource":resource},"operation":"DELETE","namespace":"calendar","userInfo":{"username":actor}},"object":null,"oldObject":old});
        assert_eq!(
            program.evaluate(&context(controller, object.clone()))?,
            json!(true)
        );
        assert_eq!(
            program.evaluate(&context("fixture:reviewed-config-writer", object.clone()))?,
            json!(true)
        );
        assert_eq!(
            program.evaluate(&context("fixture:untrusted", object.clone()))?,
            json!(false)
        );
        assert_eq!(
            program.evaluate(&context(&f.policy.cleanup_controller, object.clone()))?,
            json!(true)
        );
        // Old generations still need their real deadline/cleanup path.
        let mut old = object.clone();
        old["metadata"]["annotations"][GENERATION] = json!(digest("old-generation"));
        assert_eq!(program.evaluate(&context(controller, old))?, json!(true));
        for field in ["kind", "apiVersion", "controller"] {
            let mut old = object.clone();
            old["metadata"]["ownerReferences"][0][field] = json!("wrong");
            assert_eq!(program.evaluate(&context(controller, old))?, json!(false));
        }
        let mut old = object.clone();
        if resource == "jobs" {
            old["metadata"]["ownerReferences"][0]["uid"] = json!(uid(99));
        } else {
            old["metadata"]["annotations"][CRON_UID] = json!(uid(99));
        }
        assert_eq!(program.evaluate(&context(controller, old))?, json!(false));
        let mut wrong_cleanup = object.clone();
        if resource == "jobs" {
            wrong_cleanup["metadata"]["ownerReferences"][0]["uid"] = json!(uid(99));
        } else {
            wrong_cleanup["metadata"]["annotations"][CRON_UID] = json!(uid(99));
        }
        assert_eq!(
            program.evaluate(&context(&f.policy.cleanup_controller, wrong_cleanup))?,
            json!(false)
        );
        // Mutation control on the ACTUAL emitted expression, not a duplicate
        // fixture policy: removing the controller alternative denies cleanup.
        let quoted = serde_json::to_string(controller)?;
        let needle = format!("request.userInfo.username == {quoted}");
        let count = expression.matches(&needle).count();
        assert_eq!(count, 2);
        let location = expression.rfind(&needle).unwrap();
        let mut mutant = expression.to_owned();
        mutant.replace_range(location..location + needle.len(), "false");
        assert_eq!(
            CelFixture::parse(&mutant)?.evaluate(&context(controller, object.clone()))?,
            json!(false)
        );
    }
    Ok(())
}

#[test]
fn cron_job_and_running_pod_specs_must_derive_not_merely_have_independent_matching_hashes()
-> Result<()> {
    let mut f = Fixture::new()?;
    f.objects[2]["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["command"] =
        json!(["changed-command"]);
    f.policy.cron_spec = Digest::of(&f.objects[2]["spec"])?;
    f.intent.cron_job_spec = f.policy.cron_spec.clone();
    assert_eq!(
        f.check().unwrap_err().to_string(),
        "backup_requester_cron_job_template_changed"
    );
    let mut f = Fixture::new()?;
    for index in [2, 3] {
        let path = if index == 2 {
            "/spec/jobTemplate/spec/template/spec"
        } else {
            "/spec/template/spec"
        };
        f.objects[index].pointer_mut(path).unwrap()["containers"][0]["command"] =
            json!(["changed-command"]);
    }
    f.policy.cron_spec = Digest::of(&f.objects[2]["spec"])?;
    f.intent.cron_job_spec = f.policy.cron_spec.clone();
    f.policy.job_pod_spec = Digest::of(&f.objects[3]["spec"]["template"]["spec"])?;
    assert_eq!(
        f.check().unwrap_err().to_string(),
        "backup_requester_pod_derivation_changed"
    );
    let mut f = Fixture::new()?;
    for (key, value) in [
        ("serviceAccount", json!("backup")),
        ("priority", json!(0)),
        ("preemptionPolicy", json!("PreemptLowerPriority")),
    ] {
        f.objects[4]["spec"][key] = value;
    }
    f.objects[4]["spec"]["tolerations"] = json!([
        {"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300},
        {"key":"node.kubernetes.io/unreachable","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}
    ]);
    f.policy.running_pod_spec = Digest::of(&f.objects[4]["spec"])?;
    assert!(f.check().is_ok());
    for (key, value) in [
        ("priority", json!(100)),
        ("preemptionPolicy", json!("Never")),
        ("serviceAccount", json!("other")),
        ("tolerations", json!([])),
    ] {
        let mut g = Fixture::new()?;
        g.objects[4]["spec"][key] = value;
        g.policy.running_pod_spec = Digest::of(&g.objects[4]["spec"])?;
        assert!(g.check().is_err());
    }
    Ok(())
}

#[test]
fn coherent_reviewed_hashes_cannot_bless_secret_or_ambient_environment_injection() -> Result<()> {
    for env in [
        json!([{ "name":"PRIVATE", "valueFrom":{"secretKeyRef":{"name":"fixture-custody","key":"fixture-key"}} }]),
        json!([{ "name":"GOOGLE_APPLICATION_CREDENTIALS", "value":"/unreviewed/path" }]),
        json!([{ "name":"NODE", "valueFrom":{"fieldRef":{"fieldPath":"spec.nodeName"}} }]),
        json!([{ "name":"UNSUPPORTED", "unknown":"fixture" }]),
        json!("wrong-shape"),
    ] {
        let mut f = Fixture::new()?;
        for (index, path) in [
            (2, "/spec/jobTemplate/spec/template/spec"),
            (3, "/spec/template/spec"),
            (4, "/spec"),
        ] {
            f.objects[index].pointer_mut(path).unwrap()["containers"][0]["env"] = env.clone();
        }
        f.policy.cron_spec = Digest::of(&f.objects[2]["spec"])?;
        f.intent.cron_job_spec = f.policy.cron_spec.clone();
        f.policy.job_pod_spec = Digest::of(&f.objects[3]["spec"]["template"]["spec"])?;
        f.policy.running_pod_spec = Digest::of(&f.objects[4]["spec"])?;
        assert_eq!(
            f.check().unwrap_err().to_string(),
            "backup_requester_environment"
        );
    }
    let mut f = Fixture::new()?;
    for (index, path) in [
        (2, "/spec/jobTemplate/spec/template/spec"),
        (3, "/spec/template/spec"),
        (4, "/spec"),
    ] {
        f.objects[index].pointer_mut(path).unwrap()["containers"][0]["env"] = json!([]);
    }
    f.policy.cron_spec = Digest::of(&f.objects[2]["spec"])?;
    f.intent.cron_job_spec = f.policy.cron_spec.clone();
    f.policy.job_pod_spec = Digest::of(&f.objects[3]["spec"]["template"]["spec"])?;
    f.policy.running_pod_spec = Digest::of(&f.objects[4]["spec"])?;
    assert!(f.check().is_ok());
    Ok(())
}

#[test]
fn coherent_cron_hash_and_intent_cannot_bless_an_unbounded_or_malformed_start_deadline()
-> Result<()> {
    for deadline in [
        None,
        Some(json!(null)),
        Some(json!(0)),
        Some(json!(-1)),
        Some(json!(3601)),
        Some(json!("60")),
        Some(json!(1.5)),
        Some(json!(true)),
        Some(json!({"seconds":60})),
    ] {
        let mut f = Fixture::new()?;
        let spec = f.objects[2]["spec"].as_object_mut().unwrap();
        match deadline {
            Some(value) => {
                spec.insert("startingDeadlineSeconds".into(), value);
            }
            None => {
                spec.remove("startingDeadlineSeconds");
            }
        }
        f.policy.cron_spec = Digest::of(&f.objects[2]["spec"])?;
        f.intent.cron_job_spec = f.policy.cron_spec.clone();
        assert_eq!(
            f.check().unwrap_err().to_string(),
            "backup_requester_start_deadline"
        );
    }
    for seconds in [1, 60, 3600] {
        let mut f = Fixture::new()?;
        f.objects[2]["spec"]["startingDeadlineSeconds"] = json!(seconds);
        f.policy.cron_spec = Digest::of(&f.objects[2]["spec"])?;
        f.intent.cron_job_spec = f.policy.cron_spec.clone();
        f.check()?;
    }
    Ok(())
}

#[test]
fn process_commitments_are_exact_data_and_do_not_select_an_actor_or_original() -> Result<()> {
    let f = Fixture::new()?;
    let bytes = serde_json::to_vec(&f.intent)?;
    let job = &f.intent.requester.process;
    let controller = &f.intent.transport.controller;
    assert_eq!(
        validate_process_commitments_data(&bytes, job, controller)?,
        intent_digest_data(&bytes)?
    );
    assert!(
        validate_process_commitments_data(&bytes, &Digest::new(b"other real process"), controller)
            .is_err()
    );
    assert!(
        validate_process_commitments_data(&bytes, job, &Digest::new(b"other enrolled Controller"))
            .is_err()
    );
    assert!(intent_digest_data(b"{\"unsupported\":true}").is_err());
    Ok(())
}
