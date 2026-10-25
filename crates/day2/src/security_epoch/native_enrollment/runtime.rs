//! Actual fixed containerd connection + authenticated Kubernetes current reads.
//! The selected trusted containerd/shim/runc and node init are in the TCB. This
//! profile admits only task-init native hosts, never ancestor/cgroup guesses.

use super::issuer_costs::{Costs, Operation, Subject};
use crate::security_epoch::native_enrollment::{
    NativeRole, policy::EnrollmentPolicy, process::MessageProcess, runtime_wire as wire,
};
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    identity_protocol::{self, ReviewedSubject},
    native_clock::NativeAcquisition,
    runtime_profile,
    transport::{NativeHttp, Route},
};
use anyhow::{Context, Result, ensure};
use std::{io::Read, os::unix::net::UnixStream};
use zeroize::Zeroizing;

pub(super) use crate::security_epoch::native_enrollment::protocol::RuntimeBinding;

/// The runtime socket is created here within this acquisition. Connection peer
/// identity is sufficient only for this fixed, trusted, non-forwarding service;
/// it is not substituted for enrollment messages' SCM_PIDFD.
pub(super) fn current(
    policy: &EnrollmentPolicy,
    role: NativeRole,
    peer: &mut MessageProcess,
    acquisition: &mut NativeAcquisition,
    costs: &Costs,
) -> Result<RuntimeBinding> {
    peer.check_identity(acquisition, &costs.hashes(Subject::Requester))?;
    require_kernel(policy, acquisition)?;
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
    acquisition.remaining()?;
    let mut runtime = MessageProcess::runtime_peer(
        &stream,
        &policy.runtime.containerd_code,
        acquisition,
        &costs.hashes(Subject::Containerd),
    )?;
    require_common(peer.data(), runtime.data())?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let container = costs.measure(Operation::ContainerdRpcGroup, || {
        executor.block_on(async {
            let socket = tokio::net::UnixStream::from_std(stream)?;
            let mut socket = Some(socket);
            let endpoint = tonic::transport::Endpoint::from_static("http://[::1]:50051");
            let connection = endpoint.connect_with_connector(tower::service_fn(move |_| {
                let socket = socket.take();
                async move {
                    socket.map(hyper_util::rt::TokioIo::new).ok_or_else(|| {
                        std::io::Error::other("native_enrollment_runtime_reconnect_refused")
                    })
                }
            }));
            let channel = tokio::time::timeout(acquisition.remaining()?, connection).await??;
            super::runtime_reads::observe(
                channel,
                &policy.runtime,
                peer.data().process,
                acquisition,
            )
            .await
        })
    })?;
    runtime.check_identity(acquisition, &costs.hashes(Subject::Containerd))?;
    peer.check_identity(acquisition, &costs.hashes(Subject::Requester))?;
    let binding = costs.measure(Operation::KubernetesGroup, || {
        kubernetes(
            policy,
            role,
            &container.0,
            &container.1,
            peer.data(),
            acquisition,
        )
    })?;
    runtime.check_identity(acquisition, &costs.hashes(Subject::Containerd))?;
    peer.check_identity(acquisition, &costs.hashes(Subject::Requester))?;
    Ok(binding)
}

pub(super) fn require_common(
    a: &super::protocol::ProcessData,
    b: &super::protocol::ProcessData,
) -> Result<()> {
    ensure!(a.boot == b.boot, "native_enrollment_common_boot");
    for name in ["time", "time_for_children", "pid", "user"] {
        ensure!(
            a.namespaces.contains_key(name) && a.namespaces.get(name) == b.namespaces.get(name),
            "native_enrollment_common_namespace"
        );
    }
    Ok(())
}

fn label<'a>(container: &'a wire::Container, key: &str) -> Result<&'a str> {
    ensure!(
        container.labels.len() <= 128,
        "native_enrollment_label_bound"
    );
    container
        .labels
        .get(key)
        .map(String::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 253)
        .context("native_enrollment_runtime_label")
}

fn require_kernel(policy: &EnrollmentPolicy, acquisition: &mut NativeAcquisition) -> Result<()> {
    use crate::security_epoch::native_namespace as ns;
    acquisition.remaining()?;
    let mut file = std::fs::File::from(rustix::fs::open(
        "/proc/sys/kernel/osrelease",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?);
    ns::require_proc(&file)?;
    let bytes = ns::read_proc(&mut file, 254, acquisition)?;
    ensure!(
        bytes == format!("{}\n", policy.runtime.kernel_release).as_bytes(),
        "native_enrollment_kernel_release"
    );
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => anyhow::bail!("native_enrollment_architecture_unsupported"),
    };
    ensure!(
        architecture == policy.runtime.architecture,
        "native_enrollment_architecture_selection"
    );
    Ok(())
}

fn kubernetes(
    policy: &EnrollmentPolicy,
    role: NativeRole,
    container: &wire::Container,
    cri: &wire::CriStatus,
    process: &super::protocol::ProcessData,
    acquisition: &mut NativeAcquisition,
) -> Result<RuntimeBinding> {
    let selected = policy.workload(role);
    let image = &selected.container;
    ensure!(
        label(container, "io.kubernetes.pod.namespace")? == selected.namespace.name
            && label(container, "io.kubernetes.container.name")? == image.name,
        "native_enrollment_runtime_role"
    );
    let reviewed = ReviewedSubject {
        pod_name: label(container, "io.kubernetes.pod.name")?.to_owned(),
        pod_uid: label(container, "io.kubernetes.pod.uid")?.to_owned(),
    };
    let mut ca = Vec::new();
    let file = std::fs::File::open("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")?;
    ensure!(file.metadata()?.is_file(), "native_enrollment_ca_regular");
    file.take(65_537).read_to_end(&mut ca)?;
    acquisition.remaining()?;
    let mut http = NativeHttp::new(&policy.store, &policy.bootstrap.cluster, &ca)?;
    let source = CredentialMaterial::metadata_source(acquisition)?;
    identity_protocol::project(
        &policy.store,
        &http.request(Route::Project, &source.authorization()?, None, acquisition)?,
    )?;
    http.verify_cluster(&ca, &source.authorization()?, acquisition)?;
    let api = CredentialMaterial::kubernetes_api(acquisition)?;
    let authorization = api.authorization()?;
    let ns = &selected.namespace.name;
    identity_protocol::namespace(
        selected,
        &http.request(Route::Namespace(ns), &authorization, None, acquisition)?,
    )?;
    identity_protocol::service_account(
        selected,
        &http.request(
            Route::ServiceAccount {
                namespace: ns,
                name: &selected.kubernetes_service_account.name,
            },
            &authorization,
            None,
            acquisition,
        )?,
    )?;
    identity_protocol::google_service_account(
        &selected.google_service_account,
        &policy.bootstrap.cluster.project,
        &http.request(
            Route::GoogleAccount(&selected.google_service_account),
            &source.authorization()?,
            None,
            acquisition,
        )?,
    )?;
    let pod = Zeroizing::new(http.request(
        Route::Pod {
            namespace: ns,
            name: &reviewed.pod_name,
        },
        &authorization,
        None,
        acquisition,
    )?);
    let observed = runtime_profile::container(selected, &reviewed, &pod)?;
    let owner = observed.owner;
    let facts = observed.facts;
    ensure!(
        facts.container_id == format!("containerd://{}", container.id)
            && facts.node_name == policy.runtime.node_name,
        "native_enrollment_runtime_pod_join"
    );
    let metadata = cri
        .metadata
        .as_ref()
        .context("native_enrollment_cri_metadata")?;
    ensure!(
        cri.id == container.id
            && cri.state == 1
            && metadata.name == image.name
            && u64::from(metadata.attempt) == facts.restart_count,
        "native_enrollment_cri_lifecycle"
    );
    for name in [
        "io.kubernetes.pod.namespace",
        "io.kubernetes.pod.name",
        "io.kubernetes.pod.uid",
        "io.kubernetes.container.name",
    ] {
        ensure!(
            cri.labels.get(name) == container.labels.get(name),
            "native_enrollment_cri_pod_join"
        );
    }
    let digest = image.image.as_str();
    ensure!(
        container.image.ends_with(&format!("@{digest}"))
            && (cri.image_ref == digest || cri.image_ref.ends_with(&format!("@{digest}"))),
        "native_enrollment_runtime_image_join"
    );
    use day2_capabilities::security_epoch::bootstrap::WorkloadKind;
    let replica = match selected.workload_kind {
        WorkloadKind::DeploymentV1 => Some(
            http.request(
                Route::ReplicaSet {
                    namespace: ns,
                    name: owner
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .context("native_enrollment_replica_name")?,
                },
                &authorization,
                None,
                acquisition,
            )?,
        ),
        WorkloadKind::StatefulSetV1 => None,
    };
    let route = match selected.workload_kind {
        WorkloadKind::DeploymentV1 => Route::Deployment {
            namespace: ns,
            name: &selected.workload.name,
        },
        WorkloadKind::StatefulSetV1 => Route::StatefulSet {
            namespace: ns,
            name: &selected.workload.name,
        },
    };
    identity_protocol::workload(
        selected,
        &owner,
        replica.as_deref(),
        &http.request(route, &authorization, None, acquisition)?,
    )?;
    let node: serde_json::Value = crate::json::decode(&http.request(
        Route::Node(&policy.runtime.node_name),
        &authorization,
        None,
        acquisition,
    )?)?;
    ensure!(
        node.pointer("/apiVersion")
            .and_then(serde_json::Value::as_str)
            == Some("v1")
            && node.pointer("/kind").and_then(serde_json::Value::as_str) == Some("Node")
            && node
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                == Some(policy.runtime.node_name.as_str())
            && node
                .pointer("/metadata/uid")
                .and_then(serde_json::Value::as_str)
                == Some(policy.runtime.node_uid.as_str())
            && node
                .pointer("/metadata/deletionTimestamp")
                .is_none_or(serde_json::Value::is_null),
        "native_enrollment_node_selection"
    );
    for (pointer, expected) in [
        ("/status/nodeInfo/bootID", process.boot.as_str()),
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
            node.pointer(pointer).and_then(serde_json::Value::as_str) == Some(expected),
            "native_enrollment_node_boot_profile"
        );
    }
    acquisition.remaining()?;
    Ok(RuntimeBinding {
        container: facts,
        node_uid: policy.runtime.node_uid.clone(),
        boot: process.boot.clone(),
    })
}
