use crate::support::commands::World;
use anyhow::{Context, Result};
use day2::{
    authority_state::LocalOperator,
    invocations,
    rollout::{self, Phase},
    store::{ActingAs, Fault, Runtime},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn fixture() -> Result<(World, PathBuf, LocalOperator)> {
    fixture_with_world(World::new()?)
}

fn fixture_with_world(mut world: World) -> Result<(World, PathBuf, LocalOperator)> {
    let mut instance: Value = serde_json::from_slice(&fs::read(world.runtime.instance_path())?)?;
    instance["control"] = json!({"version":1,"state_directory":world.directory.path().join("control"),"operators":["operator"],"sources":{},"apps":{}});
    instance["apps"]["reports"]["runtime"] = json!({"kind":"linux_sqlite_rwo_v1","resources":{
        "memory_mib":512,"cpu_millis":1000,"process_limit":128,"http_concurrency":16,"shutdown_seconds":30
    }});
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    world.runtime = Runtime::load(world.runtime.instance_path(), "reports")?;
    let staged = world.directory.path().join("candidate-staging");
    copy_tree(world.runtime.artifact().directory(), &staged)?;
    let mut artifact: Value = serde_json::from_slice(&fs::read(staged.join("artifact.json"))?)?;
    artifact["sources"]["app/rolling-release"] = json!(day2::digest(b"candidate"));
    let encoded = serde_json::to_vec(&artifact)?;
    let id = day2::digest(&encoded);
    let selected = world
        .directory
        .path()
        .join("artifacts")
        .join(id.strip_prefix("sha256:").context("digest")?);
    fs::create_dir_all(selected.parent().unwrap())?;
    fs::write(staged.join("artifact.json"), &encoded)?;
    fs::rename(staged, &selected)?;
    instance["apps"]["reports"]["artifact"] = json!(selected);
    let candidate = world.directory.path().join("candidate.json");
    fs::write(&candidate, serde_json::to_vec(&instance)?)?;
    Ok((world, candidate, LocalOperator::assert_local("operator")?))
}

fn prepare(world: &World, candidate: &Path, operator: &LocalOperator) -> Result<()> {
    rollout::prepare(
        &world.runtime,
        candidate,
        &format!("registry/app@{}", day2::digest(b"old-image")),
        &format!("registry/app@{}", day2::digest(b"new-image")),
        "release-one",
        operator,
    )?;
    Ok(())
}

fn hold_execution_stripe(world: &World, id: &str) -> Result<fs::File> {
    let stripe = u16::from_str_radix(&day2::digest(id.as_bytes())[7..11], 16)? % 1024;
    let directory = world.runtime.db().parent().unwrap().join("execution-locks");
    fs::create_dir_all(&directory)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(format!("reports-{stripe}.lock")))?;
    lock.try_lock()?;
    Ok(lock)
}

#[test]
fn deferred_queries_drain_under_their_original_artifact_after_source_exit() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let reads = [
        ("api-query-deferred-source-read", "reports.list"),
        ("page-deferred-source-read", "$page.reports"),
    ];
    for (id, operation) in reads {
        world.runtime.accept_on_behalf_of(
            operation,
            ActingAs {
                authenticated: "viewer",
                actor: "viewer",
                trigger: day2::audit::Trigger::Request,
            },
            id,
            &json!({"after":"","limit":1}),
            100,
        )?;
    }
    let replacement = Runtime::load(&candidate, "reports")?;
    // The source performs no more execution. Its successor owns the backlog.
    let completed = invocations::drain(&replacement, 16)?;
    for (id, operation) in reads {
        assert!(
            completed
                .iter()
                .any(|entry| entry.id == id && entry.status == "success")
        );
        let receipt = invocations::status(&replacement, id, "viewer")?;
        assert_eq!(receipt.status, "success");
        let trace = replacement.trace(id)?;
        assert_eq!(trace.artifact, world.runtime.artifact().id());
        assert_eq!(trace.request.context.actor, "viewer");
        assert_eq!(trace.request.operation, operation);
    }
    assert_eq!(
        invocations::status(&replacement, reads[0].0, "viewer")?.result["items"],
        json!([])
    );
    assert_eq!(
        invocations::status(&replacement, reads[1].0, "viewer")?.result["items"],
        json!([])
    );
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Serving,
        Phase::Draining,
        &operator,
    )?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Draining,
        Phase::Complete,
        &operator,
    )?;
    Ok(())
}

#[test]
fn deferred_queries_keep_their_captured_authority_when_grants_are_restored() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let id = "api-query-revoked-source-read";
    world.runtime.accept(
        "reports.list",
        "viewer",
        id,
        &json!({"after":"","limit":1}),
        100,
    )?;
    let replacement = Runtime::load(&candidate, "reports")?;
    let mut actors = std::collections::BTreeSet::new();
    world.change_policy(|policy| {
        actors = std::mem::take(&mut policy.operations.get_mut("reports.list").unwrap().actors);
    })?;
    // Activation already fences pending work; the pump must leave it blocked.
    assert!(invocations::drain(&replacement, 16)?.is_empty());
    world.change_policy(|policy| {
        policy.operations.get_mut("reports.list").unwrap().actors = actors;
    })?;
    assert!(invocations::drain(&replacement, 16)?.is_empty());
    let receipt = invocations::status(&replacement, id, "viewer")?;
    assert_eq!(receipt.status, "blocked");
    assert!(receipt.result.is_null());
    assert_eq!(
        world
            .runtime
            .invoke(
                "reports.list",
                "viewer",
                "fresh-read",
                &json!({"after":"","limit":1}),
                101,
                Fault::None
            )?
            .status,
        "success"
    );
    Ok(())
}

#[test]
fn queries_do_not_wait_for_unrelated_command_execution_stripes() -> Result<()> {
    let (world, _, _) = fixture()?;
    let id = "command-shaped-query-identity";
    let lock = hold_execution_stripe(&world, id)?;
    let outcome = world.runtime.invoke(
        "reports.list",
        "viewer",
        id,
        &json!({"after":"","limit":1}),
        100,
        Fault::None,
    )?;
    assert_eq!(outcome.status, "success");
    assert_eq!(outcome.result["items"], json!([]));
    drop(lock);
    Ok(())
}

#[test]
fn pages_do_not_wait_for_unrelated_command_execution_stripes() -> Result<()> {
    let (world, _, _) = fixture()?;
    let id = "command-shaped-page-identity";
    let lock = hold_execution_stripe(&world, id)?;
    let outcome =
        world
            .runtime
            .render_page("reports", "viewer", id, &json!({"after":"","limit":1}), 100)?;
    assert_eq!(outcome.status, "success");
    assert_eq!(outcome.result["items"], json!([]));
    drop(lock);
    Ok(())
}

#[test]
fn overlapping_query_executors_return_the_same_committed_receipt() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let source = world.runtime.instance_path().to_path_buf();
    for attempt in 0..8 {
        let id = format!("overlapping-read-{attempt}");
        world.runtime.accept(
            "reports.list",
            "viewer",
            &id,
            &json!({"after":"","limit":1}),
            100,
        )?;
        let barrier = std::sync::Barrier::new(2);
        let outcomes = std::thread::scope(|scope| -> Result<_> {
            let first = scope.spawn(|| -> Result<_> {
                let runtime = Runtime::load(&source, "reports");
                barrier.wait();
                runtime?.execute(&id, Fault::None)
            });
            let second = scope.spawn(|| -> Result<_> {
                let runtime = Runtime::load(&candidate, "reports");
                barrier.wait();
                runtime?.execute(&id, Fault::None)
            });
            Ok((first.join().unwrap()?, second.join().unwrap()?))
        })?;
        assert_eq!(outcomes.0.status, "success");
        assert_eq!(outcomes.1.status, "success");
        assert_eq!(outcomes.0.result, outcomes.1.result);
    }
    Ok(())
}

#[test]
fn candidate_requires_admission_and_survives_incumbent_loss_with_pinned_work() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    assert!(Runtime::load(&candidate, "reports").is_err());
    prepare(&world, &candidate, &operator)?;
    assert!(Runtime::load(&candidate, "reports").is_err());
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    prepare(&world, &candidate, &operator)?; // lost prepare response
    let replacement = Runtime::load(&candidate, "reports")?;
    replacement.initialize()?;
    world.submit("incumbent-command", Fault::None)?;
    // Only the replacement remains to drive the old artifact's continuations.
    invocations::drain(&replacement, 16)?;
    let receipt = invocations::status(&replacement, "incumbent-command", "alice")?;
    assert_eq!(receipt.status, "success");
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Serving,
        Phase::Draining,
        &operator,
    )?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Draining,
        Phase::Complete,
        &operator,
    )?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Draining,
        Phase::Complete,
        &operator,
    )?;
    assert!(world.runtime.initialize().is_err());
    assert_eq!(
        invocations::status(&replacement, "incumbent-command", "alice")?.status,
        "success"
    );
    Ok(())
}

#[test]
fn failed_candidate_does_not_revoke_incumbent_and_release_ids_cannot_be_reused() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    assert!(
        rollout::transition(
            &world.runtime,
            "another-release",
            Phase::Prepared,
            Phase::Serving,
            &operator
        )
        .is_err()
    );
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Aborted,
        &operator,
    )?;
    world.runtime.initialize()?;
    assert!(Runtime::load(&candidate, "reports").is_err());
    assert!(
        rollout::prepare(
            &world.runtime,
            &candidate,
            &format!("registry/app@{}", day2::digest(b"old-image")),
            &format!("registry/app@{}", day2::digest(b"different-image")),
            "release-one",
            &operator
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn policy_revocation_preserves_overlap_without_regranting_business_authority() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let replacement = Runtime::load(&candidate, "reports")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.submit")
            .unwrap()
            .actors
            .clear();
    })?;
    assert!(
        replacement
            .invoke(
                "reports.submit",
                "alice",
                "revoked",
                &json!({"title":"x","text":"y"}),
                100,
                Fault::None
            )
            .is_err()
    );
    replacement.initialize()?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Serving,
        Phase::Draining,
        &operator,
    )?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Draining,
        Phase::Complete,
        &operator,
    )?;
    assert!(
        replacement
            .invoke(
                "reports.submit",
                "alice",
                "still-revoked",
                &json!({"title":"x","text":"y"}),
                101,
                Fault::None
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn concurrent_processes_reuse_one_invocation_across_both_artifacts() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let source = world.runtime.instance_path().to_path_buf();
    let gate = world.directory.path().join("process-gate");
    fs::create_dir(&gate)?;
    let executable = std::env::current_exe()?;
    let outputs = std::thread::scope(|scope| {
        // Two long-lived processes model the two pods. Admit each artifact
        // before releasing six requests; cold executable startup is not the
        // command ownership boundary being tested here.
        let workers: Vec<_> = (0..2)
            .map(|index| {
                let instance = if index == 0 { &source } else { &candidate };
                let gate = &gate;
                let executable = &executable;
                scope.spawn(move || {
                    crate::support::compiler::output(
                        std::process::Command::new(executable)
                            .args(["--exact", "rolling::process_client", "--nocapture"])
                            .env("DAY2_TEST_ROLLING_INSTANCE", instance)
                            .env("DAY2_TEST_ROLLING_GATE", gate)
                            .env("DAY2_TEST_ROLLING_CLIENT", index.to_string()),
                        std::time::Duration::from_secs(30),
                    )
                })
            })
            .collect();
        let started = std::time::Instant::now();
        while !(0..2).all(|index| gate.join(format!("ready-{index}")).exists())
            && !workers.iter().any(|worker| worker.is_finished())
        {
            anyhow::ensure!(
                started.elapsed() < std::time::Duration::from_secs(15),
                "process admission timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        fs::write(gate.join("go"), [])?;
        workers
            .into_iter()
            .map(|worker| worker.join().expect("invocation process supervisor"))
            .collect::<Result<Vec<_>>>()
    })?;
    for output in outputs {
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let count: i64 = db.query_row(
        "SELECT count(*) FROM day2_invocations WHERE id='shared-command'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    assert_eq!(
        invocations::children(&world.runtime, "shared-command")?.len(),
        1
    );
    Ok(())
}

#[test]
fn process_client() -> Result<()> {
    let Some(instance) = std::env::var_os("DAY2_TEST_ROLLING_INSTANCE") else {
        return Ok(());
    };
    let gate = PathBuf::from(std::env::var_os("DAY2_TEST_ROLLING_GATE").context("process gate")?);
    let index = std::env::var("DAY2_TEST_ROLLING_CLIENT")?;
    let runtime = Runtime::load(Path::new(&instance), "reports")?;
    fs::write(gate.join(format!("ready-{index}")), [])?;
    let started = std::time::Instant::now();
    while !gate.join("go").exists() {
        anyhow::ensure!(
            started.elapsed() < std::time::Duration::from_secs(15),
            "process gate timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..3 {
        let outcome = runtime.invoke(
            "reports.submit",
            "alice",
            "shared-command",
            &json!({"title":"One report","text":"One committed invocation"}),
            100,
            Fault::None,
        )?;
        assert!(matches!(outcome.status.as_str(), "success" | "pending"));
    }
    Ok(())
}

struct Server {
    origin: String,
    login: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Result<()>>>,
}

impl Server {
    fn start(runtime: Runtime) -> Result<Self> {
        let (send, receive) = std::sync::mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async {
                    let server = day2::web::LocalServer::bind(runtime, "alice", 0).await?;
                    send.send((server.origin.clone(), server.login_url.clone()))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let (origin, login) = receive.recv_timeout(std::time::Duration::from_secs(30))?;
        Ok(Self {
            origin,
            login,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            assert!(thread.join().expect("HTTP owner").is_ok());
        }
    }
}

fn form(
    html: &str,
    selector: &str,
) -> Result<(String, std::collections::BTreeMap<String, String>)> {
    let document = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse(selector).unwrap();
    let selected = document.select(&selector).next().context("form")?;
    let inputs = scraper::Selector::parse("input[name]").unwrap();
    Ok((
        selected.value().attr("action").context("action")?.into(),
        selected
            .select(&inputs)
            .map(|input| {
                (
                    input.value().attr("name").unwrap().into(),
                    input.value().attr("value").unwrap_or_default().into(),
                )
            })
            .collect(),
    ))
}

#[test]
fn old_page_assets_session_and_form_survive_replacement() -> Result<()> {
    use reqwest::{StatusCode, blocking::Client};
    let (world, candidate, operator) = fixture()?;
    let old = Server::start(world.runtime.clone())?;
    let client = Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let login = client.get(&old.login).send()?.error_for_status()?.text()?;
    let (action, fields) = form(&login, "form")?;
    assert_eq!(
        client
            .post(format!("{}{action}", old.origin))
            .header("Origin", &old.origin)
            .form(&fields)
            .send()?
            .status(),
        StatusCode::SEE_OTHER
    );
    let page = client
        .get(format!("{}/", old.origin))
        .send()?
        .error_for_status()?
        .text()?;
    let (action, mut fields) = form(&page, "#create-report")?;
    let document = scraper::Html::parse_document(&page);
    let selector = scraper::Selector::parse("link[href]").unwrap();
    let asset = document
        .select(&selector)
        .filter_map(|link| link.value().attr("href"))
        .find(|href| href.contains(world.runtime.artifact().id().trim_start_matches("sha256:")))
        .context("artifact stylesheet")?
        .to_owned();
    let bytes = client
        .get(format!("{}{asset}", old.origin))
        .send()?
        .error_for_status()?
        .bytes()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let runtime = Runtime::load(&candidate, "reports")?;
    let new = Server::start(runtime.clone())?;
    assert_eq!(
        client
            .get(format!("{}/health/ready", new.origin))
            .send()?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        client
            .get(format!("{}/health/candidate", new.origin))
            .send()?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{}/health/ready", old.origin))
            .send()?
            .status(),
        StatusCode::OK
    );
    rollout::transition(
        &runtime,
        "release-one",
        Phase::Serving,
        Phase::Draining,
        &operator,
    )?;
    drop(old);
    rollout::transition(
        &runtime,
        "release-one",
        Phase::Draining,
        Phase::Complete,
        &operator,
    )?;
    assert_eq!(
        client
            .get(format!("{}{asset}", new.origin))
            .send()?
            .error_for_status()?
            .bytes()?,
        bytes
    );
    fields.insert("title".into(), "Submitted from old page".into());
    fields.insert(
        "text".into(),
        "Session and form survived replacement".into(),
    );
    let result = client
        .post(format!("{}{action}", new.origin))
        .header("Origin", &new.origin)
        .form(&fields)
        .send()?;
    assert_eq!(result.status(), StatusCode::SEE_OTHER, "{}", result.text()?);
    let count: i64 = rusqlite::Connection::open(runtime.db())?.query_row(
        "SELECT count(*) FROM reports WHERE title='Submitted from old page'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn placement_is_immutable_and_startup_never_repairs_private_schema() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    let placement = rollout::Placement {
        namespace: "apps".into(),
        controller_uid: "controller".into(),
        pvc_uid: "claim".into(),
        node: "node-a".into(),
        request_digest: day2::digest(b"request"),
    };
    rollout::bind_placement(&world.runtime, "release-one", placement.clone(), &operator)?;
    let mut changed = placement;
    changed.pvc_uid = "recreated-claim".into();
    assert!(rollout::bind_placement(&world.runtime, "release-one", changed, &operator).is_err());
    let db = rusqlite::Connection::open(world.runtime.db())?;
    db.execute_batch("CREATE TABLE unexpected_private_state(id INTEGER)")?;
    assert!(world.runtime.initialize().is_err());
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='unexpected_private_state')",
        [],
        |row| row.get(0),
    )?;
    assert!(exists);
    Ok(())
}

#[test]
fn a_paused_executor_keeps_ownership_until_its_kernel_lock_is_released() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let id = "api-query-shaped-command-identity";
    let lock = hold_execution_stripe(&world, id)?;
    let replacement = Runtime::load(&candidate, "reports")?;
    let deferred = replacement.invoke(
        "reports.submit",
        "alice",
        id,
        &json!({"title":"Paused","text":"Only one owner"}),
        100,
        Fault::None,
    )?;
    assert_eq!(deferred.status, "pending");
    assert!(invocations::children(&replacement, id)?.is_empty());
    drop(lock);
    replacement.execute(id, Fault::None)?;
    assert_eq!(invocations::children(&replacement, id)?.len(), 1);
    Ok(())
}

#[test]
fn offline_activation_uses_target_configuration_and_requires_exclusive_ownership() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    let mut desired: Value = serde_json::from_slice(&fs::read(&candidate)?)?;
    desired["apps"]["reports"]["readers"] = json!(["viewer", "target-reader"]);
    fs::write(&candidate, serde_json::to_vec(&desired)?)?;
    let target = day2::artifact::LoadedArtifact::load(Path::new(
        desired["apps"]["reports"]["artifact"].as_str().unwrap(),
    ))?;
    let plan = day2::migration::plan(&world.runtime, &target)?;
    day2::migration::apply(&world.runtime, &target, &plan)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let active = day2::authority_state::current(&db)?;
    let lease = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(
            world
                .runtime
                .db()
                .parent()
                .unwrap()
                .join("reports.serve.lock"),
        )?;
    lease.try_lock_shared()?;
    assert!(
        day2::deployment::activate_maintenance(
            &world.runtime,
            &target,
            &candidate,
            &operator,
            &active.stamp,
            "offline-release"
        )
        .is_err()
    );
    assert_eq!(day2::authority_state::current(&db)?.stamp, active.stamp);
    drop(lease);
    day2::deployment::activate_maintenance(
        &world.runtime,
        &target,
        &candidate,
        &operator,
        &active.stamp,
        "offline-release",
    )?;
    let replacement = Runtime::load(&candidate, "reports")?;
    day2::deployment::admit_maintenance_store(&replacement, &operator)?;
    replacement.initialize()?;
    let active = day2::authority_state::current(&db)?;
    assert_eq!(active.artifact_id, target.id());
    assert!(active.document.readers.contains("target-reader"));
    assert!(rollout::inspect(&replacement)?.is_none());
    Ok(())
}

#[test]
fn policy_revision_during_draining_keeps_target_serving_and_fences_old_work() -> Result<()> {
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let replacement = Runtime::load(&candidate, "reports")?;
    world.submit("before-policy-revision", Fault::None)?;
    invocations::drain(&world.runtime, 64)?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Serving,
        Phase::Draining,
        &operator,
    )?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.submit")
            .unwrap()
            .actors
            .remove("bob");
    })?;
    replacement.initialize()?;
    let server = Server::start(replacement.clone())?;
    let response = reqwest::blocking::get(format!("{}/health/ready", server.origin))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        replacement
            .invoke(
                "reports.submit",
                "alice",
                "after-policy-revision",
                &json!({"title":"x","text":"y"}),
                101,
                Fault::None
            )?
            .status,
        "success"
    );
    assert!(
        replacement
            .invoke(
                "reports.submit",
                "bob",
                "bob-revoked",
                &json!({"title":"x","text":"y"}),
                101,
                Fault::None
            )
            .is_err()
    );
    assert!(invocations::status(&replacement, "before-policy-revision", "alice").is_err());
    invocations::drain(&replacement, 64)?;
    rollout::transition(
        &replacement,
        "release-one",
        Phase::Draining,
        Phase::Complete,
        &operator,
    )?;
    replacement.initialize()?;
    Ok(())
}

fn stock_fixture() -> Result<(World, PathBuf, LocalOperator)> {
    let artifact = std::env::var_os("DAY2_TEST_STOCK_LEDGER_ARTIFACT")
        .context("build stock-ledger fixture")?;
    let directory = tempfile::tempdir()?;
    let model = json!({"read":true,"create":true,"rows":{"kind":"owner_or_admin","field":"owner"}});
    let path = directory.path().join("instance.json");
    fs::write(
        &path,
        serde_json::to_vec(
            &json!({"installation":"rollout_probe","environment":"test","apps":{"reports":{
                "artifact":PathBuf::from(artifact),"readers":["alice"],"writers":["alice"],
                "authority":{"version":1,"admins":["operator"],"operations":{
                    "stock_ledger.reserve":{"actors":["alice"],"mode":{"kind":"current_state"},"models":{"reservations":model}},
                    "stock_ledger.available":{"actors":["alice"],"mode":{"kind":"read"},"models":{"reservations":{"read":true,"rows":{"kind":"owner_or_admin","field":"owner"}}}}
                }}
            }}}),
        )?,
    )?;
    let runtime = Runtime::load(&path, "reports")?;
    runtime.initialize()?;
    fixture_with_world(World { directory, runtime })
}

#[test]
fn canary_runs_in_the_pinned_candidate_host_and_retries_do_not_repeat_writes() -> Result<()> {
    use rollout::{ProbeDefinition, ProbeStatus};
    let (world, candidate, operator) = stock_fixture()?;
    #[cfg(target_os = "macos")]
    {
        let supervisor = day2::digest(&fs::read(std::env::current_exe()?)?);
        for path in [world.runtime.instance_path(), candidate.as_path()] {
            let mut value: Value = serde_json::from_slice(&fs::read(path)?)?;
            let artifact = day2::artifact::Instance::load(path)?.apps["reports"]
                .artifact
                .clone();
            let loaded = day2::artifact::LoadedArtifact::load(Path::new(&artifact))?;
            value["apps"]["reports"]["security"] =
                serde_json::to_value(day2::security_admission::Requirements {
                    version: 1,
                    artifact: loaded.id().into(),
                    platform_inventory: day2::security_admission::platform_inventory_digest(
                        &loaded,
                    )?,
                    roc_version: loaded.contract().roc_version.clone(),
                    containment: day2::security_admission::Containment::MacosSandboxV1 {
                        supervisor: supervisor.clone(),
                    },
                })?;
            fs::write(path, serde_json::to_vec(&value)?)?;
        }
        let active =
            day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
        day2::authority_state::apply_desired(
            &world.runtime,
            &operator,
            "pin-supervisor",
            Some(active.stamp),
        )?;
    }
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    let definition = ProbeDefinition {
        actor: "alice".into(),
        command: "stock_ledger.reserve".into(),
        input: json!({"quantity":1}),
        query: "stock_ledger.available".into(),
        query_input: json!({}),
        expected: json!({"available":99,"reserved":1,"count":1}),
    };
    assert!(
        rollout::request_probe(
            &world.runtime,
            "release-one",
            definition.clone(),
            &LocalOperator::assert_local("outsider")?
        )
        .is_err()
    );
    assert!(rollout::inspect(&world.runtime)?.unwrap().probe.is_none());
    // Tooling can publish the operator request even though its executable is
    // not the pinned app supervisor. It must never invoke the app itself.
    let probe_file = world.directory.path().join("probe.json");
    fs::write(&probe_file, serde_json::to_vec(&definition)?)?;
    let output = crate::support::compiler::output(
        std::process::Command::new(env!("CARGO_BIN_EXE_day2")).args([
            "rollout-probe",
            world.runtime.instance_path().to_str().unwrap(),
            "reports",
            probe_file.to_str().unwrap(),
            "release-one",
            "operator",
        ]),
        std::time::Duration::from_secs(30),
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    #[cfg(target_os = "macos")]
    {
        let denied = crate::support::compiler::output(
            std::process::Command::new(env!("CARGO_BIN_EXE_day2")).args([
                "invoke",
                candidate.to_str().unwrap(),
                "reports",
                "stock_ledger.available",
                "alice",
                "wrong-supervisor",
                "{}",
            ]),
            std::time::Duration::from_secs(30),
        )?;
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("security_runtime_mismatch"));
    }
    let _incumbent = Server::start(world.runtime.clone())?;
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(
        rollout::inspect(&world.runtime)?
            .unwrap()
            .probe
            .unwrap()
            .status,
        ProbeStatus::Pending
    );
    let replacement = Runtime::load(&candidate, "reports")?;
    let candidate_server = Server::start(replacement.clone())?;
    assert_eq!(await_probe(&replacement)?, ProbeStatus::Verified);
    drop(candidate_server);
    rollout::request_probe(&world.runtime, "release-one", definition.clone(), &operator)?;
    let count: i64 = rusqlite::Connection::open(replacement.db())?.query_row(
        "SELECT count(*) FROM reservations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    let mut changed = definition;
    changed.input = json!({"quantity":2});
    assert!(rollout::request_probe(&world.runtime, "release-one", changed, &operator).is_err());
    #[cfg(target_os = "macos")]
    {
        let mut value: Value = serde_json::from_slice(&fs::read(world.runtime.instance_path())?)?;
        value["apps"]["reports"]["security"]["containment"]["supervisor"] =
            json!(day2::digest(b"a different supervisor"));
        fs::write(world.runtime.instance_path(), serde_json::to_vec(&value)?)?;
        let active =
            day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
        day2::authority_state::apply_desired(
            &world.runtime,
            &operator,
            "replace-supervisor-pin",
            Some(active.stamp),
        )?;
        let error = replacement
            .invoke(
                "stock_ledger.available",
                "alice",
                "new-pin-denied",
                &json!({}),
                103,
                Fault::None,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("security_runtime_mismatch"));
    }
    Ok(())
}

#[test]
fn failed_candidate_canaries_preserve_the_incumbent_and_current_authority() -> Result<()> {
    use rollout::{ProbeDefinition, ProbeStatus};
    for actor in ["alice", "bob"] {
        let (world, candidate, operator) = stock_fixture()?;
        prepare(&world, &candidate, &operator)?;
        rollout::transition(
            &world.runtime,
            "release-one",
            Phase::Prepared,
            Phase::Serving,
            &operator,
        )?;
        let definition = ProbeDefinition {
            actor: actor.into(),
            command: "stock_ledger.reserve".into(),
            input: json!({"quantity":1}),
            query: "stock_ledger.available".into(),
            query_input: json!({}),
            expected: json!({"available":123,"reserved":1,"count":1}),
        };
        rollout::request_probe(&world.runtime, "release-one", definition, &operator)?;
        let replacement = Runtime::load(&candidate, "reports")?;
        let _server = Server::start(replacement.clone())?;
        assert_eq!(await_probe(&replacement)?, ProbeStatus::Failed);
        let same = rollout::inspect(&replacement)?
            .unwrap()
            .probe
            .unwrap()
            .definition;
        rollout::request_probe(&world.runtime, "release-one", same, &operator)?;
        assert_eq!(await_probe(&replacement)?, ProbeStatus::Failed);
        world.runtime.initialize()?;
        assert_eq!(
            world
                .runtime
                .invoke(
                    "stock_ledger.reserve",
                    "alice",
                    "incumbent-still-allowed",
                    &json!({"quantity":1}),
                    102,
                    Fault::None
                )?
                .status,
            "success"
        );
        let count: i64 = rusqlite::Connection::open(world.runtime.db())?.query_row(
            "SELECT count(*) FROM reservations WHERE owner='bob'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
    }
    Ok(())
}

#[test]
fn candidate_probe_refuses_child_commands_before_the_write() -> Result<()> {
    use rollout::{ProbeDefinition, ProbeStatus};
    let (world, candidate, operator) = fixture()?;
    prepare(&world, &candidate, &operator)?;
    rollout::transition(
        &world.runtime,
        "release-one",
        Phase::Prepared,
        Phase::Serving,
        &operator,
    )?;
    rollout::request_probe(
        &world.runtime,
        "release-one",
        ProbeDefinition {
            actor: "alice".into(),
            command: "reports.submit".into(),
            input: json!({"title":"x","text":"y"}),
            query: "reports.list".into(),
            query_input: json!({"after":"","limit":10}),
            expected: json!({}),
        },
        &operator,
    )?;
    let replacement = Runtime::load(&candidate, "reports")?;
    let _server = Server::start(replacement.clone())?;
    assert_eq!(await_probe(&replacement)?, ProbeStatus::Failed);
    let count: i64 = rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT count(*) FROM reports",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

fn await_probe(runtime: &Runtime) -> Result<rollout::ProbeStatus> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let status = rollout::inspect(runtime)?
            .context("prepared release")?
            .probe
            .context("requested probe")?
            .status;
        if status != rollout::ProbeStatus::Pending {
            return Ok(status);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "candidate probe did not finish"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
