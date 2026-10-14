//! Independent fixed kernel/response DATA fixtures. Actual retained descriptors
//! require Linux cases; no fixture promotes JSON/IDs into runtime authority.

use super::{
    identity_protocol::ReviewedSubject,
    namespace_protocol as proc,
    runtime_profile::{self, ContainerSelection},
};
use day2_capabilities::{Digest, security_epoch::bootstrap::GkeRoleSelection};
use serde_json::{Value, json};

fn stat(pid: u32, start: u64) -> Vec<u8> {
    let mut columns = vec!["0".to_owned(); 50];
    columns[0] = "R".to_owned();
    columns[19] = start.to_string();
    format!("{pid} (native ) worker) {}\n", columns.join(" ")).into_bytes()
}

#[test]
fn task_parser_joins_tgid_tid_and_full_starttime_without_comm_column_guessing() {
    let good = stat(79, 987654321);
    let status = b"Name:\tnative\nTgid:\t77\nPid:\t79\n";
    let facts = proc::task(&good, status).unwrap();
    assert_eq!(facts.process, 77);
    assert_eq!(facts.thread, 79);
    assert_eq!(facts.start_ticks, 987654321);
    for bad in [
        &b"Tgid:\t77\nPid:\t78\n"[..],
        &b"Tgid:\t77\nTgid:\t77\nPid:\t79\n"[..],
        &b"Tgid:\t077\nPid:\t79\n"[..],
        &b"Tgid:\t77\nPid:\t79"[..],
    ] {
        assert!(proc::task(&good, bad).is_err());
    }
    assert!(proc::task(&stat(79, 0), status).is_err());
    assert!(proc::task(&vec![b'x'; 16_385], status).is_err());
    let prefix = format!("79 (native) R {} 987654321\n", vec!["0"; 18].join(" "));
    assert!(proc::task(prefix.as_bytes(), status).is_err());
    let extended = String::from_utf8(good.clone())
        .unwrap()
        .trim_end()
        .to_owned()
        + " 0\n";
    assert!(proc::task(extended.as_bytes(), status).is_err());
    let malformed = String::from_utf8(good)
        .unwrap()
        .replacen("R 0 ", "R +0 ", 1);
    assert!(proc::task(malformed.as_bytes(), status).is_err());
}

#[test]
fn time_namespace_offsets_are_complete_canonical_and_never_a_clock_or_root_proof() {
    let zero = proc::offsets(b"monotonic 0 0\nboottime 0 0\n").unwrap();
    proc::require_zero(&zero).unwrap();
    for bad in [
        &b"monotonic 0 0\n"[..],
        &b"monotonic 0 0\nmonotonic 0 0\n"[..],
        &b"monotonic 0 0\nboottime 0 1000000000\n"[..],
        &b"monotonic 00 0\nboottime 0 0\n"[..],
        &b"monotonic +0 0\nboottime 0 0\n"[..],
        &b"monotonic 0 0\n7 0 0\n"[..],
    ] {
        assert!(proc::offsets(bad).is_err());
    }
    let shifted = proc::offsets(b"monotonic -1 1\nboottime 5 0\n").unwrap();
    assert!(proc::require_zero(&shifted).is_err());
    assert!(proc::offsets(&vec![b'x'; 1025]).is_err());
}

#[test]
fn complete_mapping_parser_preserves_paths_and_refuses_overlap_shape_and_truncation() {
    let good=b"00400000-00401000 r-xp 00000000 08:01 73 /usr/lib/native library.so\n00401000-00402000 rw-p 00001000 00:00 0\n";
    let values = proc::mappings(good).unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(
        values[0].path.as_deref(),
        Some("/usr/lib/native library.so")
    );
    assert_eq!(values[1].path, None);
    for bad in [
        &b"00400000-00401000 r-xp 0 08:01 73\n00400800-00402000 r-xp 0 08:01 73\n"[..],
        &b"00400000-00401000 rwxp 0 08:01 73"[..],
        &b"00400000-00401000 r-xz 0 08:01 73\n"[..],
        &b"00400000-00401000 r-xp 0 08:01 -1\n"[..],
    ] {
        assert!(proc::mappings(bad).is_err());
    }
    assert!(proc::mappings(&vec![b'x'; 1_048_577]).is_err());
    let many = (0..4097)
        .map(|i| format!("{:08x}-{:08x} r-xp 0 00:00 0\n", i * 4096, (i + 1) * 4096))
        .collect::<String>();
    assert!(proc::mappings(many.as_bytes()).is_err());
    let full = many.lines().take(4096).collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(proc::mappings(full.as_bytes()).unwrap().len(), 4096);
    // Mapping permissions are DATA. Even r-xp cannot certify immutable memory.
    assert!(proc::mappings(b"00400000-00401000 rwxp 0 08:01 73 /native\n").is_ok());
}

fn fixture() -> (GkeRoleSelection, ReviewedSubject, ContainerSelection, Value) {
    let role: GkeRoleSelection=serde_json::from_value(json!({
        "namespace":{"name":"native","uid":"namespace-uid"},"kubernetes_service_account":{"name":"controller","uid":"ksa-uid"},
        "google_service_account":{"kind":"gke_workload_identity_v1","service_account":"controller@project-seven.iam.gserviceaccount.com","service_account_uid":"100000000000000000007"},
        "workload_kind":"deployment_v1","workload":{"name":"controller","uid":"deployment-uid"},"token_review_audience":"https://native.example/subject"
    })).unwrap();
    let subject = ReviewedSubject {
        pod_name: "controller-abc".into(),
        pod_uid: "pod-uid".into(),
    };
    let image = Digest::new(b"image");
    let selected = ContainerSelection {
        name: "day2".into(),
        image: image.clone(),
    };
    let value = json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"controller-abc","uid":"pod-uid","namespace":"native",
        "ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"controller-rs","uid":"replica-uid","controller":true}]},
        "spec":{"serviceAccountName":"controller","nodeName":"node-seven","containers":[{"name":"day2","image":format!("registry/native@{}",image.as_str())}]},
        "status":{"phase":"Running","containerStatuses":[{"name":"day2","started":true,"ready":true,"state":{"running":{"startedAt":"2026-10-14T00:00:00Z"}},
            "containerID":format!("containerd://{}","7".repeat(64)),"imageID":format!("docker-pullable://registry/native@{}",image.as_str()),"restartCount":0}]}});
    (role, subject, selected, value)
}

#[test]
fn selected_container_response_is_data_and_refuses_replacement_ambiguous_or_unpinned_image() {
    let (role, subject, selected, good) = fixture();
    let bytes = serde_json::to_vec(&good).unwrap();
    let facts = runtime_profile::container(&role, &subject, &selected, &bytes).unwrap();
    assert_eq!(facts.pod_uid, "pod-uid");
    assert_eq!(facts.image, selected.image);
    let mut not_ready = good.clone();
    not_ready["status"]["containerStatuses"][0]["started"] = json!(false);
    not_ready["status"]["containerStatuses"][0]["ready"] = json!(false);
    assert!(
        runtime_profile::container(
            &role,
            &subject,
            &selected,
            &serde_json::to_vec(&not_ready).unwrap()
        )
        .is_ok()
    );
    for (pointer, value) in [
        ("/metadata/uid", json!("replacement")),
        ("/status/containerStatuses/0/state", json!({"waiting":{}})),
        (
            "/status/containerStatuses/0/containerID",
            json!("docker://not-qualified"),
        ),
        ("/spec/containers/0/image", json!("native:latest")),
        (
            "/status/containerStatuses/0/imageID",
            json!(format!(
                "registry/native@{}",
                Digest::new(b"other").as_str()
            )),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            runtime_profile::container(
                &role,
                &subject,
                &selected,
                &serde_json::to_vec(&bad).unwrap()
            )
            .is_err(),
            "{pointer}"
        );
    }
    let mut duplicate = good.clone();
    let extra = duplicate["status"]["containerStatuses"][0].clone();
    duplicate["status"]["containerStatuses"]
        .as_array_mut()
        .unwrap()
        .push(extra);
    assert!(
        runtime_profile::container(
            &role,
            &subject,
            &selected,
            &serde_json::to_vec(&duplicate).unwrap()
        )
        .is_err()
    );
    // No CurrentRuntimeBinding factory or role permission exists in this codec.
}

#[test]
fn selected_container_profile_refuses_malformed_names_and_digest_references() {
    let (role, subject, selected, good) = fixture();
    for name in ["-day2", "day2-", "Day2", "day2..other", ""] {
        let bad = ContainerSelection {
            name: name.into(),
            image: selected.image.clone(),
        };
        assert!(
            runtime_profile::container(&role, &subject, &bad, &serde_json::to_vec(&good).unwrap())
                .unwrap_err()
                .to_string()
                .contains("container_selection")
        );
    }
    for node in [
        "node..seven",
        "-node",
        "node-",
        "node.",
        ".node",
        "node/other",
        "",
    ] {
        let mut bad = good.clone();
        bad["spec"]["nodeName"] = json!(node);
        assert!(
            runtime_profile::container(
                &role,
                &subject,
                &selected,
                &serde_json::to_vec(&bad).unwrap()
            )
            .is_err()
        );
    }
    for repository in [
        "",
        "registry@other",
        "https://registry/native",
        "registry/native path",
    ] {
        let mut bad = good.clone();
        bad["status"]["containerStatuses"][0]["imageID"] =
            json!(format!("{repository}@{}", selected.image.as_str()));
        assert!(
            runtime_profile::container(
                &role,
                &subject,
                &selected,
                &serde_json::to_vec(&bad).unwrap()
            )
            .is_err()
        );
    }
}

#[test]
fn process_time_offsets_require_exact_current_thread_namespace_join() {
    use super::native_namespace::{NamespaceIdentity, require_process_time_join_data};
    let current = NamespaceIdentity { device: 5, inode: 17 };
    let other = NamespaceIdentity { device: 5, inode: 23 };
    let other_device = NamespaceIdentity { device: 7, inode: 17 };
    let zero = NamespaceIdentity { device: 5, inode: 0 };
    assert!(require_process_time_join_data(&current, &current, &current).is_ok());
    assert!(require_process_time_join_data(&current, &other, &current).is_err());
    assert!(require_process_time_join_data(&current, &current, &other).is_err());
    assert!(require_process_time_join_data(&current, &other_device, &other_device).is_err());
    assert!(require_process_time_join_data(&zero, &zero, &zero).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_namespace_observation_refuses_original_acquisition() {
    use super::{native_clock::NativeAcquisition, native_namespace::NativeNamespaceObservation};
    let mut acquisition = NativeAcquisition::fixture(
        Digest::new(b"domain"),
        std::process::id(),
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    );
    assert!(NativeNamespaceObservation::acquire(&mut acquisition).is_err());
    assert!(acquisition.remaining().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn actual_linux_namespace_observation_retains_self_descriptors_with_no_pod_authority() {
    use super::{native_clock::NativeAcquisition, native_namespace::NativeNamespaceObservation};
    let mut acquisition = NativeAcquisition::begin(5).unwrap();
    let mut observed = NativeNamespaceObservation::acquire(&mut acquisition).unwrap();
    observed.check(&mut acquisition).unwrap();
    let maps = observed.mappings(&mut acquisition).unwrap();
    assert!(!maps.is_empty());
    let data = observed.into_data();
    assert_eq!(data.task.process, std::process::id());
    assert_eq!(data.namespaces.len(), 6);
    // This Linux descriptor test does not qualify the missing node runtime join.
}
