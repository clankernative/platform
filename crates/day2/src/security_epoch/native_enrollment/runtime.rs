//! Actual fixed containerd connection + authenticated Kubernetes current reads.
//! The selected trusted containerd/shim/runc and node init are in the TCB. This
//! profile admits only task-init native hosts, never ancestor/cgroup guesses.

use crate::security_epoch::native_enrollment::{
    policy::{EnrollmentPolicy, NativeRole},
    process::MessageProcess,
    runtime_wire as wire,
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
use tonic::{client::Grpc, transport::Channel};
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
) -> Result<RuntimeBinding> {
    peer.check_identity(acquisition)?;
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
    let credentials =
        nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
    let pid = u32::try_from(credentials.pid())?;
    let pidfd = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerPidfd)?;
    // This private adapter is the sole connection-peer construction. It owns
    // the socket created above, not a caller-adopted descriptor or PID.
    let received = rustix::net::ReceivedPidfdPacket {
        bytes: 0,
        flags: rustix::net::ReturnFlags::empty(),
        process: pidfd,
        credentials: rustix::net::KernelCredentialsData {
            process: rustix::net::KernelPidVisibility::Visible(
                std::num::NonZeroU32::new(pid).context("native_enrollment_runtime_peer_pid")?,
            ),
            user: credentials.uid(),
            group: credentials.gid(),
        },
    };
    let mut runtime =
        MessageProcess::receive(received, &policy.runtime.containerd_code, acquisition)?;
    require_common(peer.data(), runtime.data())?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let container = executor.block_on(async {
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
        let mut grpc = Grpc::new(channel)
            .max_decoding_message_size(1_048_576)
            .max_encoding_message_size(8192);
        let version: wire::Version = request(
            &mut grpc,
            wire::Empty {},
            "/containerd.services.version.v1.Version/Version",
            acquisition,
        )
        .await?;
        ensure!(
            version.version == policy.runtime.containerd_version
                && version.revision == policy.runtime.containerd_revision,
            "native_enrollment_containerd_version"
        );
        let cri: wire::CriVersion = request(
            &mut grpc,
            wire::CriVersionRequest {
                version: "0.1.0".to_owned(),
            },
            "/runtime.v1.RuntimeService/Version",
            acquisition,
        )
        .await?;
        ensure!(
            cri.runtime_name == "containerd"
                && cri.runtime_version == policy.runtime.containerd_version
                && cri.runtime_api_version == policy.runtime.cri_version,
            "native_enrollment_cri_version"
        );
        let tasks: wire::Tasks = request(
            &mut grpc,
            wire::Empty {},
            "/containerd.services.tasks.v1.Tasks/List",
            acquisition,
        )
        .await?;
        let id = task_id(&tasks, peer.data().process)?;
        let first: wire::TaskReply = request(
            &mut grpc,
            wire::GetTask {
                container_id: id.clone(),
                exec_id: String::new(),
            },
            "/containerd.services.tasks.v1.Tasks/Get",
            acquisition,
        )
        .await?;
        require_task(
            first
                .process
                .as_ref()
                .context("native_enrollment_runtime_task_missing")?,
            peer.data().process,
            &id,
        )?;
        let response: wire::ContainerReply = request(
            &mut grpc,
            wire::GetContainer { id: id.clone() },
            "/containerd.services.containers.v1.Containers/Get",
            acquisition,
        )
        .await?;
        let container = response
            .container
            .context("native_enrollment_container_missing")?;
        ensure!(
            container.id == id
                && container
                    .runtime
                    .as_ref()
                    .is_some_and(|r| r.name == "io.containerd.runc.v2"),
            "native_enrollment_runtime_kind"
        );
        let cri: wire::CriStatusReply = request(
            &mut grpc,
            wire::CriStatusRequest {
                container_id: id.clone(),
                verbose: false,
            },
            "/runtime.v1.RuntimeService/ContainerStatus",
            acquisition,
        )
        .await?;
        let cri = cri.status.context("native_enrollment_cri_status_missing")?;
        let last: wire::TaskReply = request(
            &mut grpc,
            wire::GetTask {
                container_id: id.clone(),
                exec_id: String::new(),
            },
            "/containerd.services.tasks.v1.Tasks/Get",
            acquisition,
        )
        .await?;
        ensure!(first == last, "native_enrollment_task_changed");
        Ok::<_, anyhow::Error>((container, cri))
    })?;
    runtime.check_identity(acquisition)?;
    peer.check_identity(acquisition)?;
    let binding = kubernetes(
        policy,
        role,
        &container.0,
        &container.1,
        peer.data(),
        acquisition,
    )?;
    runtime.check_identity(acquisition)?;
    peer.check_identity(acquisition)?;
    Ok(binding)
}

async fn request<
    I: prost::Message + Send + Sync + 'static,
    O: prost::Message + Default + Send + Sync + 'static,
>(
    grpc: &mut Grpc<Channel>,
    input: I,
    path: &'static str,
    acquisition: &mut NativeAcquisition,
) -> Result<O> {
    let timeout = acquisition.remaining()?;
    tokio::time::timeout(timeout, grpc.ready()).await??;
    let mut request = tonic::Request::new(input);
    request
        .metadata_mut()
        .insert("containerd-namespace", "k8s.io".parse()?);
    request.set_timeout(acquisition.remaining()?);
    let response = tokio::time::timeout(
        acquisition.remaining()?,
        grpc.unary(
            request,
            tonic::codegen::http::uri::PathAndQuery::from_static(path),
            tonic_prost::ProstCodec::default(),
        ),
    )
    .await??;
    acquisition.remaining()?;
    Ok(response.into_inner())
}

pub(super) fn require_common(
    a: &super::protocol::ProcessData,
    b: &super::protocol::ProcessData,
) -> Result<()> {
    ensure!(a.boot == b.boot, "native_enrollment_common_boot");
    for name in ["time", "time_for_children", "pid", "user"] {
        ensure!(
            a.namespaces.get(name).is_some() && a.namespaces.get(name) == b.namespaces.get(name),
            "native_enrollment_common_namespace"
        );
    }
    Ok(())
}

fn task_id(tasks: &wire::Tasks, pid: u32) -> Result<String> {
    ensure!(
        tasks.tasks.len() <= 128 && tasks.encoded_len() <= 1_048_576,
        "native_enrollment_task_bound"
    );
    let matching = tasks
        .tasks
        .iter()
        .filter(|t| t.pid == pid)
        .collect::<Vec<_>>();
    ensure!(matching.len() == 1, "native_enrollment_task_ambiguous");
    let id = matching[0].id.clone();
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native_enrollment_task_id"
    );
    require_task(matching[0], pid, &id)?;
    Ok(id)
}

use prost::Message;

fn require_task(task: &wire::Task, pid: u32, id: &str) -> Result<()> {
    // Tasks.Get/List report init ID in Process.id. ContainerID is omitted by
    // containerd's task state adapter; do not mistake an exec ID for init.
    ensure!(
        task.pid == pid && task.id == id && task.container_id.is_empty() && task.status == 2,
        "native_enrollment_task_init_mismatch"
    );
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
    let (selected, image) = policy.workload(role);
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
    let mut http = NativeHttp::new(&policy.runtime.store, &policy.runtime.cluster, &ca)?;
    let source = CredentialMaterial::metadata_source(acquisition)?;
    identity_protocol::project(
        &policy.runtime.store,
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
        &policy.runtime.cluster.project,
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
    let owner = identity_protocol::pod(selected, &reviewed, &pod)?;
    let facts = runtime_profile::container(selected, &reviewed, image, &pod)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_join_requires_exact_live_init_and_complete_bounded_list() {
        let task = wire::Task {
            container_id: String::new(),
            id: "7".repeat(64),
            pid: 91,
            status: 2,
        };
        let mut tasks = wire::Tasks {
            tasks: vec![task.clone()],
        };
        assert_eq!(task_id(&tasks, 91).unwrap(), task.id);
        assert!(task_id(&tasks, 92).is_err());
        tasks.tasks.push(task.clone());
        assert!(task_id(&tasks, 91).is_err());
        tasks.tasks = vec![task.clone(); 129];
        assert!(task_id(&tasks, 91).is_err());
        for status in [0, 1, 3, 4, 5] {
            let mut bad = task.clone();
            bad.status = status;
            assert!(require_task(&bad, 91, &task.id).is_err());
        }
        let mut exec = task.clone();
        exec.id = "exec-debug".into();
        assert!(require_task(&exec, 91, &task.id).is_err());
        let mut misleading = task.clone();
        misleading.container_id = task.id.clone();
        assert!(require_task(&misleading, 91, &task.id).is_err());
    }
}
