//! A separate request-only Job observer. It never calls or relaxes the native
//! role workload/namespace matcher and returns only current comparison DATA.
//! Persisted protected CREATE provenance and all higher admission remain
//! mandatory; current Pod/Job/VAP responses alone authorize no source read.
use crate::security_epoch::native_enrollment::{
    issuer_costs::{Costs, Operation, Subject},
    policy::EnrollmentPolicy,
    process::MessageProcess,
    protocol::{ProcessData, RuntimeBinding},
    runtime, runtime_reads,
};
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    identity_protocol::{self, ReviewedSubject},
    native_clock::NativeAcquisition,
    scheduled_backup::requester::{WorkloadData, WorkloadResponses, validate_workload_data},
    transport::{NativeHttp, Route},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{io::Read, os::unix::net::UnixStream};
use zeroize::Zeroizing;

pub(super) struct ScheduledRuntimeData {
    pub runtime: RuntimeBinding,
    pub workload: WorkloadData,
}

pub(super) fn current(
    policy: &EnrollmentPolicy,
    peer: &mut MessageProcess,
    intent: &[u8],
    original: &mut NativeAcquisition,
    costs: &Costs,
) -> Result<ScheduledRuntimeData> {
    policy.validate()?;
    let selected = policy
        .scheduled_backup
        .as_ref()
        .context("native_backup_requester_disabled")?;
    runtime::require_kernel(policy, original)?;
    peer.check_identity(original, &costs.hashes(Subject::Requester))?;
    // This new purpose does not reuse require_common's host-PID exception.
    // The fixed trusted runtime still owns every container/CRI RPC below.
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )?;
    rustix::net::connect(
        &socket,
        &rustix::net::SocketAddrUnix::new("/run/containerd/containerd.sock")?,
    )?;
    let stream = UnixStream::from(socket);
    original.remaining()?;
    let mut runtime = MessageProcess::runtime_peer(
        &stream,
        &policy.runtime.containerd_code,
        original,
        &costs.hashes(Subject::Containerd),
    )?;
    require_job_namespace(peer.data(), runtime.data())?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let observed = costs.measure(Operation::ContainerdRpcGroup, || {
        executor.block_on(async {
            let socket = tokio::net::UnixStream::from_std(stream)?;
            let mut socket = Some(socket);
            let endpoint = tonic::transport::Endpoint::from_static("http://[::1]:50051");
            let connecting = endpoint.connect_with_connector(tower::service_fn(move |_| {
                let socket = socket.take();
                async move {
                    socket.map(hyper_util::rt::TokioIo::new).ok_or_else(|| {
                        std::io::Error::other("native_backup_runtime_reconnect_refused")
                    })
                }
            }));
            let channel = tokio::time::timeout(original.remaining()?, connecting).await??;
            runtime_reads::observe(channel, &policy.runtime, peer.data().process, original).await
        })
    });
    let runtime_checked = runtime.check_identity(original, &costs.hashes(Subject::Containerd));
    let peer_checked = peer.check_identity(original, &costs.hashes(Subject::Requester));
    if observed.is_err() || runtime_checked.is_err() || peer_checked.is_err() {
        original.refuse();
    }
    let (container, cri) = observed?;
    runtime_checked?;
    peer_checked?;
    let label = |key: &str| -> Result<String> {
        ensure!(
            container.labels.len() <= 128,
            "native_backup_runtime_label_bound"
        );
        let value = container
            .labels
            .get(key)
            .context("native_backup_runtime_label")?;
        ensure!(
            !value.is_empty() && value.len() <= 253,
            "native_backup_runtime_label_bound"
        );
        Ok(value.clone())
    };
    ensure!(
        label("io.kubernetes.pod.namespace")? == selected.namespace.name
            && label("io.kubernetes.container.name")? == selected.container,
        "native_backup_runtime_selection"
    );
    let subject = ReviewedSubject {
        pod_name: label("io.kubernetes.pod.name")?,
        pod_uid: label("io.kubernetes.pod.uid")?,
    };
    let requested: Result<_> = costs.measure(Operation::KubernetesGroup, || {
        let mut ca = Vec::new();
        let file = std::fs::File::open("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")?;
        ensure!(file.metadata()?.is_file(), "native_backup_ca_regular");
        file.take(65_537).read_to_end(&mut ca)?;
        original.remaining()?;
        let mut http = NativeHttp::new(&policy.store, &policy.bootstrap.cluster, &ca)?;
        let source = CredentialMaterial::metadata_source(original)?;
        identity_protocol::project(
            &policy.store,
            &http.request(Route::Project, &source.authorization()?, None, original)?,
        )?;
        http.verify_cluster(&ca, &source.authorization()?, original)?;
        let api = CredentialMaterial::kubernetes_api(original)?;
        let authorization = api.authorization()?;
        let ns = &selected.namespace.name;
        let namespace =
            Zeroizing::new(http.request(Route::Namespace(ns), &authorization, None, original)?);
        let account = Zeroizing::new(http.request(
            Route::ServiceAccount {
                namespace: ns,
                name: &selected.service_account.name,
            },
            &authorization,
            None,
            original,
        )?);
        identity_protocol::google_service_account(
            &selected.uploader,
            &policy.bootstrap.cluster.project,
            &http.request(
                Route::GoogleAccount(&selected.uploader),
                &source.authorization()?,
                None,
                original,
            )?,
        )?;
        let pod = Zeroizing::new(http.request(
            Route::Pod {
                namespace: ns,
                name: &subject.pod_name,
            },
            &authorization,
            None,
            original,
        )?);
        // Route the next fixed GET from this actual runtime-selected Pod, not
        // a Job name supplied by the requester or a received artifact.
        let pod_data: Value = crate::json::decode(&pod)?;
        let owners = pod_data
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array)
            .context("native_backup_job_owner")?;
        ensure!(owners.len() == 1, "native_backup_job_owner_count");
        let job_name = owners[0]
            .get("name")
            .and_then(Value::as_str)
            .context("native_backup_job_owner_name")?;
        ensure!(
            !job_name.is_empty()
                && job_name.len() <= 253
                && job_name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'),
            "native_backup_job_name"
        );
        let job = Zeroizing::new(http.request(
            Route::ScheduledJob {
                namespace: ns,
                name: job_name,
            },
            &authorization,
            None,
            original,
        )?);
        let cron = Zeroizing::new(http.request(
            Route::ScheduledCronJob {
                namespace: ns,
                name: &selected.cron_job.name,
            },
            &authorization,
            None,
            original,
        )?);
        let admission = Zeroizing::new(http.request(
            Route::BackupAdmissionPolicy(&selected.admission.name),
            &authorization,
            None,
            original,
        )?);
        let binding = Zeroizing::new(http.request(
            Route::BackupAdmissionBinding(&selected.binding.name),
            &authorization,
            None,
            original,
        )?);
        let workload = validate_workload_data(
            selected,
            &subject,
            intent,
            WorkloadResponses {
                namespace: &namespace,
                service_account: &account,
                cron_job: &cron,
                job: &job,
                pod: &pod,
                admission: &admission,
                binding: &binding,
            },
        )?;
        ensure!(
            workload.container_id == format!("containerd://{}", container.id)
                && container
                    .image
                    .ends_with(&format!("@{}", selected.image.as_str())),
            "native_backup_container_join"
        );
        let metadata = cri
            .metadata
            .as_ref()
            .context("native_backup_cri_metadata")?;
        ensure!(
            cri.id == container.id
                && cri.state == 1
                && metadata.name == selected.container
                && u64::from(metadata.attempt) == workload.restart_count
                && (cri.image_ref == selected.image.as_str()
                    || cri
                        .image_ref
                        .ends_with(&format!("@{}", selected.image.as_str()))),
            "native_backup_cri_join"
        );
        for key in [
            "io.kubernetes.pod.namespace",
            "io.kubernetes.pod.name",
            "io.kubernetes.pod.uid",
            "io.kubernetes.container.name",
        ] {
            ensure!(
                cri.labels.get(key) == container.labels.get(key),
                "native_backup_cri_label_join"
            );
        }
        let node: Value = crate::json::decode(&http.request(
            Route::Node(&policy.runtime.node_name),
            &authorization,
            None,
            original,
        )?)?;
        ensure!(
            node.get("apiVersion").and_then(Value::as_str) == Some("v1")
                && node.get("kind").and_then(Value::as_str) == Some("Node")
                && node.pointer("/metadata/name").and_then(Value::as_str)
                    == Some(policy.runtime.node_name.as_str())
                && node.pointer("/metadata/uid").and_then(Value::as_str)
                    == Some(policy.runtime.node_uid.as_str())
                && node
                    .pointer("/metadata/deletionTimestamp")
                    .is_none_or(Value::is_null),
            "native_backup_node_selection"
        );
        for (path, expected) in [
            ("/status/nodeInfo/bootID", peer.data().boot.as_str()),
            (
                "/status/nodeInfo/kernelVersion",
                policy.runtime.kernel_release.as_str(),
            ),
            (
                "/status/nodeInfo/architecture",
                policy.runtime.architecture.as_str(),
            ),
            ("/status/nodeInfo/operatingSystem", "linux"),
        ] {
            ensure!(
                node.pointer(path).and_then(Value::as_str) == Some(expected),
                "native_backup_node_profile"
            );
        }
        Ok(ScheduledRuntimeData {
            runtime: RuntimeBinding {
                container: crate::security_epoch::runtime_profile::ContainerFacts {
                    pod_name: workload.pod_name.clone(),
                    pod_uid: workload.pod_uid.clone(),
                    node_name: policy.runtime.node_name.clone(),
                    container_name: selected.container.clone(),
                    container_id: workload.container_id.clone(),
                    image: selected.image.clone(),
                    restart_count: workload.restart_count,
                },
                node_uid: policy.runtime.node_uid.clone(),
                boot: peer.data().boot.clone(),
            },
            workload,
        })
    });
    let runtime_checked = runtime.check_identity(original, &costs.hashes(Subject::Containerd));
    let peer_checked = peer.check_identity(original, &costs.hashes(Subject::Requester));
    if requested.is_err() || runtime_checked.is_err() || peer_checked.is_err() {
        original.refuse();
    }
    let value = requested?;
    runtime_checked?;
    peer_checked?;
    original.remaining()?;
    Ok(value)
}

fn require_job_namespace(job: &ProcessData, node: &ProcessData) -> Result<()> {
    ensure!(job.boot == node.boot, "native_backup_common_boot");
    for name in ["time", "time_for_children", "user"] {
        ensure!(
            job.namespaces.contains_key(name)
                && job.namespaces.get(name) == node.namespaces.get(name),
            "native_backup_common_namespace"
        );
    }
    for name in ["pid", "mnt"] {
        ensure!(
            job.namespaces.contains_key(name)
                && node.namespaces.contains_key(name)
                && job.namespaces.get(name) != node.namespaces.get(name),
            "native_backup_private_sandbox"
        );
    }
    Ok(())
}
