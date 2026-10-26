//! Closed current-container reads on the issuer's already observed connection.
//! Returned protobuf values are DATA, not a native role or runtime witness.
//! The caller retains the actual process/socket owners and all before/after
//! checks. No response or observation is reused across calls.

use super::{policy::RuntimeSelection, runtime_wire as wire};
use crate::security_epoch::native_clock::NativeAcquisition;
use anyhow::{Context, Result, ensure};
use prost::Message;
use tonic::{client::Grpc, transport::Channel};

pub(super) async fn observe(
    channel: Channel,
    selected: &RuntimeSelection,
    process: u32,
    acquisition: &mut NativeAcquisition,
) -> Result<(wire::Container, wire::CriStatus)> {
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
        version.version == selected.containerd_version
            && version.revision == selected.containerd_revision,
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
            && cri.runtime_version == selected.containerd_version
            && cri.runtime_api_version == selected.cri_version,
        "native_enrollment_cri_version"
    );
    let tasks: wire::Tasks = request(
        &mut grpc,
        wire::Empty {},
        "/containerd.services.tasks.v1.Tasks/List",
        acquisition,
    )
    .await?;
    // The complete, uniquely selected List row already satisfies every
    // initial Get field. No use or effect intervenes before metadata.
    // Retain that actual row, never reconstruct it from scalar IDs.
    let first = selected_task(&tasks, process)?.clone();
    let id = first.id.clone();
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
    require_task_reobservation(&first, &last)?;
    Ok::<_, anyhow::Error>((container, cri))
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

fn selected_task(tasks: &wire::Tasks, pid: u32) -> Result<&wire::Task> {
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
    let id = &matching[0].id;
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native_enrollment_task_id"
    );
    require_task(matching[0], pid, id)?;
    Ok(matching[0])
}

fn require_task(task: &wire::Task, pid: u32, id: &str) -> Result<()> {
    // Tasks.Get/List report init ID in Process.id. ContainerID is omitted by
    // containerd's task state adapter; do not mistake an exec ID for init.
    ensure!(
        task.pid == pid && task.id == id && task.container_id.is_empty() && task.status == 2,
        "native_enrollment_task_init_mismatch"
    );
    Ok(())
}

fn require_task_reobservation(first: &wire::Task, last: &wire::TaskReply) -> Result<()> {
    ensure!(
        last.process.as_ref() == Some(first),
        "native_enrollment_task_changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
        time::Duration,
    };

    const PATHS: [&str; 6] = [
        "/containerd.services.version.v1.Version/Version",
        "/runtime.v1.RuntimeService/Version",
        "/containerd.services.tasks.v1.Tasks/List",
        "/containerd.services.containers.v1.Containers/Get",
        "/runtime.v1.RuntimeService/ContainerStatus",
        "/containerd.services.tasks.v1.Tasks/Get",
    ];

    fn task() -> wire::Task {
        wire::Task {
            container_id: String::new(),
            id: "7".repeat(64),
            pid: 91,
            status: 2,
        }
    }

    struct Fixture {
        calls: Mutex<Vec<String>>,
        tasks: wire::Tasks,
        last: wire::TaskReply,
    }

    async fn reply<I, O>(
        request: hyper::Request<hyper::body::Incoming>,
        expected: I,
        output: O,
    ) -> hyper::Response<tonic::body::Body>
    where
        I: prost::Message + Default + Clone + PartialEq + Send + Sync + 'static,
        O: prost::Message + Default + Clone + Send + Sync + 'static,
    {
        let service = tower::service_fn(move |request: tonic::Request<I>| {
            let expected = expected.clone();
            let output = output.clone();
            async move {
                if request
                    .metadata()
                    .get("containerd-namespace")
                    .and_then(|v| v.to_str().ok())
                    != Some("k8s.io")
                    || request.get_ref() != &expected
                {
                    return Err(tonic::Status::invalid_argument("fixture request binding"));
                }
                Ok(tonic::Response::new(output))
            }
        });
        tonic::server::Grpc::new(tonic_prost::ProstCodec::<O, I>::default())
            .unary(service, request)
            .await
    }

    async fn handle(
        fixture: Arc<Fixture>,
        request: hyper::Request<hyper::body::Incoming>,
    ) -> Result<hyper::Response<tonic::body::Body>, Infallible> {
        let path = request.uri().path().to_owned();
        let accepted = {
            let mut calls = fixture.calls.lock().unwrap();
            // One bounded fixed operation; an early or second Tasks.Get fails.
            let accepted = PATHS
                .get(calls.len())
                .is_some_and(|expected| *expected == path);
            if calls.len() < PATHS.len() {
                calls.push(path.clone());
            }
            accepted
        };
        if !accepted {
            return Ok(tonic::Status::failed_precondition("fixture RPC order").into_http());
        }
        let id = task().id;
        let response = match path.as_str() {
            "/containerd.services.version.v1.Version/Version" => {
                reply(
                    request,
                    wire::Empty {},
                    wire::Version {
                        version: "v2.2.0".into(),
                        revision: "selected-revision".into(),
                    },
                )
                .await
            }
            "/runtime.v1.RuntimeService/Version" => {
                reply(
                    request,
                    wire::CriVersionRequest {
                        version: "0.1.0".into(),
                    },
                    wire::CriVersion {
                        version: "0.1.0".into(),
                        runtime_name: "containerd".into(),
                        runtime_version: "v2.2.0".into(),
                        runtime_api_version: "v1".into(),
                    },
                )
                .await
            }
            "/containerd.services.tasks.v1.Tasks/List" => {
                reply(request, wire::Empty {}, fixture.tasks.clone()).await
            }
            "/containerd.services.containers.v1.Containers/Get" => {
                reply(
                    request,
                    wire::GetContainer { id: id.clone() },
                    wire::ContainerReply {
                        container: Some(wire::Container {
                            id,
                            labels: Default::default(),
                            image: "fixture-image".into(),
                            runtime: Some(wire::Runtime {
                                name: "io.containerd.runc.v2".into(),
                            }),
                        }),
                    },
                )
                .await
            }
            "/runtime.v1.RuntimeService/ContainerStatus" => {
                reply(
                    request,
                    wire::CriStatusRequest {
                        container_id: id.clone(),
                        verbose: false,
                    },
                    wire::CriStatusReply {
                        status: Some(wire::CriStatus {
                            id,
                            metadata: None,
                            state: 1,
                            image_ref: "fixture-image".into(),
                            labels: Default::default(),
                        }),
                    },
                )
                .await
            }
            "/containerd.services.tasks.v1.Tasks/Get" => {
                reply(
                    request,
                    wire::GetTask {
                        container_id: id,
                        exec_id: String::new(),
                    },
                    fixture.last.clone(),
                )
                .await
            }
            _ => unreachable!(),
        };
        Ok(response)
    }

    // Actual loopback HTTP/2 + protobuf adapter only. These fixtures do not
    // construct a process, runtime witness, enrollment or current permission.
    type RuntimeReply = (wire::Container, wire::CriStatus);

    fn loopback(
        tasks: wire::Tasks,
        last: wire::TaskReply,
        limit: Duration,
    ) -> Result<(Result<RuntimeReply>, Vec<String>)> {
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        executor.block_on(async {
            let fixture = Arc::new(Fixture {
                calls: Mutex::new(Vec::new()),
                tasks,
                last,
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let observed = fixture.clone();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let service =
                    hyper::service::service_fn(move |request| handle(observed.clone(), request));
                hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await?;
                Ok::<_, anyhow::Error>(())
            });
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))?
                    .connect()
                    .await?;
                let selected =
                    super::super::tests::policy(&super::super::protocol::KeyOwner::generate()?)
                        .runtime;
                let mut acquisition = NativeAcquisition::fixture(
                    day2_capabilities::Digest::new(b"loopback-data-only"),
                    std::process::id(),
                    Duration::ZERO,
                    limit,
                );
                observe(channel, &selected, 91, &mut acquisition).await
            })
            .await;
            server.abort();
            let _closed = server.await;
            let calls = fixture.calls.lock().unwrap().clone();
            Ok((result?, calls))
        })
    }

    #[test]
    fn actual_rpc_sequence_uses_list_then_metadata_then_one_final_get() -> Result<()> {
        for _ in 0..2 {
            let (result, calls) = loopback(
                wire::Tasks {
                    tasks: vec![task()],
                },
                wire::TaskReply {
                    process: Some(task()),
                },
                Duration::from_secs(5),
            )?;
            let (container, cri) = result?;
            assert_eq!(container.id, task().id);
            assert_eq!(cri.id, task().id);
            assert_eq!(calls, PATHS);
        }
        Ok(())
    }

    #[test]
    fn malformed_or_ambiguous_list_stops_before_metadata_reads() -> Result<()> {
        let mut malformed = task();
        malformed.status = 3;
        for tasks in [vec![], vec![task(), task()], vec![malformed]] {
            let (result, calls) = loopback(
                wire::Tasks { tasks },
                wire::TaskReply {
                    process: Some(task()),
                },
                Duration::from_secs(5),
            )?;
            assert!(result.is_err());
            assert_eq!(calls, PATHS[..3]);
        }
        Ok(())
    }

    #[test]
    fn final_get_refuses_task_death_replacement_and_missing_response() -> Result<()> {
        let mut replacements = Vec::new();
        for field in 0..4 {
            let mut changed = task();
            match field {
                0 => changed.pid += 1,
                1 => changed.id = "8".repeat(64),
                2 => changed.status = 3,
                _ => changed.container_id = changed.id.clone(),
            }
            replacements.push(Some(changed));
        }
        replacements.push(None);
        for process in replacements {
            let (result, calls) = loopback(
                wire::Tasks {
                    tasks: vec![task()],
                },
                wire::TaskReply { process },
                Duration::from_secs(5),
            )?;
            assert_eq!(
                result.unwrap_err().to_string(),
                "native_enrollment_task_changed"
            );
            assert_eq!(calls, PATHS);
        }
        Ok(())
    }

    #[test]
    fn expired_original_cannot_start_the_rpc_operation() -> Result<()> {
        let (result, calls) = loopback(
            wire::Tasks {
                tasks: vec![task()],
            },
            wire::TaskReply {
                process: Some(task()),
            },
            Duration::ZERO,
        )?;
        assert!(result.is_err());
        assert!(calls.is_empty());
        Ok(())
    }

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
        assert_eq!(selected_task(&tasks, 91).unwrap(), &task);
        assert!(selected_task(&tasks, 92).is_err());
        tasks.tasks.push(task.clone());
        assert!(selected_task(&tasks, 91).is_err());
        tasks.tasks = vec![task.clone(); 129];
        assert!(selected_task(&tasks, 91).is_err());
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
