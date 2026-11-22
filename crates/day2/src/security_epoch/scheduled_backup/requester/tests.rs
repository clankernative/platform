use super::*;
use crate::security_epoch::scheduled_backup::{Destination, Requester, Slot, Source, Transport};

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
