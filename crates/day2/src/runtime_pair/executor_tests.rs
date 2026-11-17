use super::*;
use crate::artifact::LoadedArtifact;
use rusqlite::params;
use serde_json::json;

#[path = "handoff_tests.rs"]
mod handoff_tests;

// Synthetic qualification metadata exercises the real SQLite/role guards. The
// positive supplied-code cases are not native image or two-runtime qualification.
struct World {
    root: tempfile::TempDir,
    runtime: Runtime,
    db: Connection,
    release: Release,
}

impl World {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let instance = root.path().join("instance.json");
        let directory = root.path().join("artifact");
        std::fs::create_dir(&directory)?;
        std::fs::create_dir(root.path().join(".state"))?;
        std::fs::write(
            &instance,
            serde_json::to_vec(&json!({
                "installation":"pair","environment":"test",
                "control":{"version":1,"state_directory":root.path().join("control"),"operators":["operator"],"sources":{},"apps":{}},
                "apps":{"app":{"artifact":directory,"readers":["alice"],"writers":["alice"],
                    "runtime":{"kind":"linux_sqlite_rwo_v1","resources":{"memory_mib":512,"cpu_millis":1000,
                        "process_limit":128,"http_concurrency":16,"shutdown_seconds":30}}}}
            }))?,
        )?;
        let contract = serde_json::from_value(json!({
            "format":crate::artifact::CURRENT_FORMAT,
            "verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
            "roc_version":"metadata","worker_digest":crate::digest(b"worker"),
            "schema_digest":crate::digest(b"schema"),
            "schema":{"models":{},"inputs":{"input":{"fields":{}}},"foreign_keys":[]},
            "operations":[{"name":"run","kind":"command","input_type":"input","output_type":""}],
            "sources":{},"admission":"local-spike-only"
        }))?;
        let artifact = LoadedArtifact::from_contract_for_tests(
            crate::digest(b"artifact"),
            directory,
            contract,
        );
        let path = root.path().join(".state/app.sqlite");
        let runtime =
            Runtime::from_artifact_for_tests(instance, "app".into(), path.clone(), artifact)?;
        let mut db = Connection::open(path)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL")?;
        let receipt = super::super::tests::receipt();
        let generation = |identity: RuntimeIdentity, label: &[u8]| Generation {
            artifact: runtime.artifact().id().into(),
            runtime: identity,
            instance_digest: runtime.instance_digest().into(),
            image: format!("registry/sdk@{}", crate::digest(label)),
        };
        let release = Release {
            id: "pair-one".into(),
            scope: runtime.scope().into(),
            source: generation(receipt.source.runtime.clone(), b"source"),
            target: generation(receipt.target.runtime.clone(), b"target"),
            kind: ReleaseKind::RuntimePair {
                admission: Box::new(super::super::tests::review(&receipt, &receipt.source)?),
                execution: Execution::Unadmitted,
            },
            target_instance_digest: crate::digest(b"instance bytes"),
            authority: authority_state::AuthorityStamp {
                epoch: crate::digest(b"epoch"),
                revision: 1,
            },
            target_security: None,
            probe: None,
            placement: Some(rollout::Placement {
                namespace: "app-pair".into(),
                controller_uid: "controller-one".into(),
                pvc_uid: "pvc-one".into(),
                node: "node-one".into(),
                request_digest: crate::digest(b"request"),
            }),
            phase: Phase::Prepared,
        };
        let tx = db.transaction()?;
        tx.execute_batch(crate::store::PLATFORM_DDL)?;
        for (key, value) in [
            ("scope", runtime.scope()),
            (
                "schema",
                runtime.artifact().contract().schema_digest.as_str(),
            ),
        ] {
            tx.execute("INSERT INTO day2_meta VALUES(?1,?2)", params![key, value])?;
        }
        crate::audit::upgrade(&tx)?;
        authority_state::upgrade(&tx)?;
        crate::invocations::upgrade(&tx)?;
        crate::execution::upgrade(&tx)?;
        rollout::install(&tx)?;
        tx.execute(
            "INSERT INTO day2_authority VALUES(1,?1,1,?2,?3,?4)",
            params![
                release.authority.epoch,
                json!({"enabled":true,"readers":["alice"],"writers":["alice"]}).to_string(),
                runtime.artifact().id(),
                runtime.artifact().directory().to_string_lossy()
            ],
        )?;
        let source =
            runtime_generation::register_expected(&tx, runtime.scope(), &release.source.runtime)?;
        tx.execute("INSERT INTO day2_rollout_runtime VALUES(1,?1)", [&source])?;
        // These are journal fixtures, not work accepted by a fake native host.
        for id in ["parent", "child"] {
            tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES(?1,'run','alice','{}',?2,1,'pending')",
                params![id,runtime.artifact().id()])?;
            authority_state::pin_invocation(&tx, id, &release.authority)?;
            tx.execute(
                "INSERT INTO day2_invocation_runtime VALUES(?1,?2)",
                params![id, source],
            )?;
        }
        rollout::write(&tx, &release)?;
        tx.commit()?;
        Ok(Self {
            root,
            runtime,
            db,
            release,
        })
    }

    fn selection(&self, role: ExecutorRole) -> Selection {
        Selection {
            release: self.release.id.clone(),
            placement: self.release.placement.clone().unwrap(),
            image: if role == ExecutorRole::Source {
                self.release.source.image.clone()
            } else {
                self.release.target.image.clone()
            },
            role,
        }
    }

    fn code(&self, role: ExecutorRole) -> Result<HostCode> {
        if role == ExecutorRole::Source {
            self.release.source.runtime.code()
        } else {
            self.release.target.runtime.code()
        }
    }

    fn admit(&mut self) -> Result<Release> {
        let tx = self.db.transaction()?;
        let release = admit_in(&self.runtime, &tx, &self.release.id)?;
        tx.commit()?;
        Ok(release)
    }
}

fn check(generation: String, attempt: u64) -> CandidateCheck {
    CandidateCheck {
        generation,
        attempt,
        snapshot: crate::digest(b"complete snapshot"),
        checks: crate::digest(b"complete checks"),
    }
}

#[test]
fn admission_rollback_and_retry_preserve_source_selection_and_work_owners() -> Result<()> {
    let mut world = World::new()?;
    let source =
        runtime_generation::expected_id(world.runtime.scope(), &world.release.source.runtime)?;
    let target =
        runtime_generation::expected_id(world.runtime.scope(), &world.release.target.runtime)?;
    {
        let tx = world.db.transaction()?;
        admit_in(&world.runtime, &tx, &world.release.id)?;
    }
    assert!(matches!(
        rollout::state(&world.db)?.unwrap().kind,
        ReleaseKind::RuntimePair {
            execution: Execution::Unadmitted,
            ..
        }
    ));
    assert!(
        runtime_generation::require_expected(
            &world.db,
            world.runtime.scope(),
            &target,
            &world.release.target.runtime
        )
        .is_err()
    );
    let admitted = world.admit()?;
    assert_eq!(world.admit()?, admitted);
    let mut request = world.release.clone();
    request.placement = None;
    assert_eq!(super::super::persist(&world.db, request.clone())?, admitted);
    request.target_instance_digest = crate::digest(b"changed reviewed input");
    assert!(super::super::persist(&world.db, request).is_err());
    runtime_generation::require_active(&world.db, &source)?;
    let foreign: bool = world.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_invocation_runtime WHERE generation!=?1)",
        [&source],
        |row| row.get(0),
    )?;
    assert!(!foreign);
    assert!(
        rollout::transition(
            &world.runtime,
            "pair-one",
            Phase::Prepared,
            Phase::Serving,
            &LocalOperator::assert_local("operator")?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn exact_placement_image_role_and_measured_code_are_all_required() -> Result<()> {
    let mut world = World::new()?;
    let source = world.selection(ExecutorRole::Source);
    let candidate = world.selection(ExecutorRole::Candidate);
    let source_code = world.code(ExecutorRole::Source)?;
    let candidate_code = world.code(ExecutorRole::Candidate)?;
    assert!(require_executor(&world.runtime, &world.db, &candidate, &candidate_code).is_err());
    world.admit()?;
    require_executor(&world.runtime, &world.db, &source, &source_code)?;
    require_executor(&world.runtime, &world.db, &candidate, &candidate_code)?;
    assert!(require_executor(&world.runtime, &world.db, &source, &candidate_code).is_err());
    assert!(require_executor(&world.runtime, &world.db, &candidate, &source_code).is_err());
    assert!(
        require_executor(
            &world.runtime,
            &world.db,
            &candidate,
            &crate::security_admission::host_code()?
        )
        .is_err(),
        "synthetic metadata cannot qualify this actual process"
    );
    for field in [
        "namespace",
        "controller_uid",
        "pvc_uid",
        "node",
        "request_digest",
    ] {
        let mut changed = serde_json::to_value(&candidate)?;
        changed["placement"][field] = json!("different");
        let changed: Selection = crate::json::decode(&serde_json::to_vec(&changed)?)?;
        assert!(
            require_executor(&world.runtime, &world.db, &changed, &candidate_code).is_err(),
            "{field}"
        );
    }
    let mut changed = candidate.clone();
    changed.image = source.image.clone();
    assert!(require_executor(&world.runtime, &world.db, &changed, &candidate_code).is_err());
    changed = candidate.clone();
    changed.release = "another-pair".into();
    assert!(require_executor(&world.runtime, &world.db, &changed, &candidate_code).is_err());
    let mut code = candidate_code.clone();
    code.sandbox = None;
    assert!(require_executor(&world.runtime, &world.db, &candidate, &code).is_err());
    assert!(Candidate::open(world.runtime.instance_path(), "app", source).is_err());
    assert!(source_drain(world.runtime.instance_path(), "app", &candidate, 1).is_err());
    Ok(())
}

#[test]
fn lost_checks_and_competing_attempts_cannot_republish_old_readiness() -> Result<()> {
    let mut world = World::new()?;
    world.admit()?;
    let selection = world.selection(ExecutorRole::Candidate);
    let code = world.code(ExecutorRole::Candidate)?;
    let (first, generation, a) = begin_check(&world.runtime, &world.db, &selection, &code)?;
    let (second, _, b) = begin_check(&world.runtime, &world.db, &selection, &code)?;
    assert!(b > a);
    assert!(
        finish_check(
            &world.runtime,
            &world.db,
            &selection,
            &code,
            &first,
            &check(generation.clone(), a)
        )
        .is_err()
    );
    finish_check(
        &world.runtime,
        &world.db,
        &selection,
        &code,
        &second,
        &check(generation.clone(), b),
    )?;
    finish_check(
        &world.runtime,
        &world.db,
        &selection,
        &code,
        &second,
        &check(generation, b),
    )?;
    let (_, _, c) = begin_check(&world.runtime, &world.db, &selection, &code)?;
    assert!(c > b);
    let reopened = Connection::open(world.runtime.db())?;
    assert!(matches!(
        rollout::state(&reopened)?.unwrap().kind,
        ReleaseKind::RuntimePair {
            execution: Execution::Admitted { check: None, .. },
            ..
        }
    ));
    assert!(
        finish_check(
            &world.runtime,
            &reopened,
            &selection,
            &code,
            &second,
            &check(crate::digest(b"foreign generation"), b)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn source_binding_survives_reopen_and_abort_but_revocation_fences_both_roles() -> Result<()> {
    let mut world = World::new()?;
    world.admit()?;
    let source = world.selection(ExecutorRole::Source);
    let candidate = world.selection(ExecutorRole::Candidate);
    let code = world.code(ExecutorRole::Source)?;
    let restarted = Runtime::from_artifact_for_tests(
        world.runtime.instance_path().into(),
        "app".into(),
        world.runtime.db().into(),
        world.runtime.artifact().clone(),
    )?;
    let reopened = Connection::open(world.runtime.db())?;
    require_executor(&restarted, &reopened, &source, &code)?;
    let mut release = rollout::state(&reopened)?.unwrap();
    release.phase = Phase::Aborted;
    rollout::write(&reopened, &release)?;
    require_executor(&restarted, &reopened, &source, &code)?;
    assert!(
        require_executor(
            &restarted,
            &reopened,
            &candidate,
            &world.code(ExecutorRole::Candidate)?
        )
        .is_err()
    );
    reopened.execute("UPDATE day2_authority SET revision=2", [])?;
    assert!(require_executor(&restarted, &reopened, &source, &code).is_err());
    let owner: String = reopened.query_row(
        "SELECT generation FROM day2_invocation_runtime WHERE invocation='parent'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        owner,
        runtime_generation::expected_id(world.runtime.scope(), &world.release.source.runtime)?
    );
    Ok(())
}

#[test]
fn authority_change_during_check_and_malformed_journal_never_become_admission() -> Result<()> {
    let mut world = World::new()?;
    world.admit()?;
    let selection = world.selection(ExecutorRole::Candidate);
    let code = world.code(ExecutorRole::Candidate)?;
    let (release, generation, attempt) = begin_check(&world.runtime, &world.db, &selection, &code)?;
    world
        .db
        .execute("UPDATE day2_authority SET revision=2", [])?;
    assert!(
        finish_check(
            &world.runtime,
            &world.db,
            &selection,
            &code,
            &release,
            &check(generation, attempt)
        )
        .is_err()
    );
    world
        .db
        .execute("UPDATE day2_authority SET revision=1", [])?;
    let mut encoded = serde_json::to_value(&release)?;
    encoded["kind"].as_object_mut().unwrap().remove("execution");
    assert!(crate::json::decode::<Release>(&serde_json::to_vec(&encoded)?).is_err());
    encoded = serde_json::to_value(&release)?;
    encoded["kind"]["execution"]["candidate"] = json!(crate::digest(b"foreign generation"));
    let invalid: Release = crate::json::decode(&serde_json::to_vec(&encoded)?)?;
    rollout::write(&world.db, &invalid)?;
    assert!(rollout::state(&world.db).is_err());
    Ok(())
}

#[test]
fn selections_are_closed_bounded_regular_files_and_cannot_follow_symlinks() -> Result<()> {
    let world = World::new()?;
    let path = world.root.path().join("selection.json");
    let selection = world.selection(ExecutorRole::Candidate);
    std::fs::write(&path, serde_json::to_vec(&selection)?)?;
    assert_eq!(Selection::load(&path)?, selection);
    let link = world.root.path().join("selection-link");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(Selection::load(&link).is_err());
    assert!(Selection::load(world.root.path()).is_err());
    let mut value = serde_json::to_value(&selection)?;
    value["permission"] = json!(true);
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    assert!(Selection::load(&path).is_err());
    value = serde_json::to_value(&selection)?;
    value["role"] = json!("private-input-must-not-be-echoed");
    std::fs::write(&path, serde_json::to_vec(&value)?)?;
    let failure = Selection::load(&path)
        .err()
        .context("invalid role accepted")?
        .to_string();
    assert_eq!(failure, "runtime_pair_selection_invalid");
    assert!(!failure.contains("private-input"));
    std::fs::write(&path, vec![b' '; 1_048_577])?;
    assert!(Selection::load(&path).is_err());
    Ok(())
}

#[tokio::test]
async fn standby_http_never_exposes_public_readiness_or_application_routes() -> Result<()> {
    let mut world = World::new()?;
    world.admit()?;
    let candidate = Candidate {
        selection: world.selection(ExecutorRole::Candidate),
        runtime: world.runtime,
        _serving: tempfile::tempfile()?,
        health_capacity: Arc::new(tokio::sync::Semaphore::new(4)),
    };
    let router = candidate_router(Arc::new(candidate));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (stop, done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
    });
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("http://{address}/health/live"))
            .send()
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    for path in [
        "/health/ready",
        "/health/candidate",
        "/",
        "/mcp",
        "/api/run",
    ] {
        assert_eq!(
            client
                .get(format!("http://{address}{path}"))
                .send()
                .await?
                .status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
    let _ = stop.send(());
    server.await??;
    Ok(())
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(24))]
    #[test]
    fn seeded_attempt_histories_preserve_original_owners_and_match_an_independent_counter(
        steps in proptest::collection::vec((0u8..6, proptest::prelude::any::<u8>()), 1..32)
    ) {
        let mut world = World::new().unwrap();
        world.admit().unwrap();
        let selection = world.selection(ExecutorRole::Candidate);
        let code = world.code(ExecutorRole::Candidate).unwrap();
        let source_code = world.code(ExecutorRole::Source).unwrap();
        let source = runtime_generation::expected_id(world.runtime.scope(), &world.release.source.runtime).unwrap();
        let mut frames: Vec<(Release,CandidateCheck)> = Vec::new();
        let mut counter = 0u64;
        let mut blocked = false;
        for (action,index) in steps {
            match action {
                0 => {
                    let actual = begin_check(&world.runtime,&world.db,&selection,&code);
                    proptest::prop_assert_eq!(actual.is_ok(), !blocked);
                    if let Ok((release,generation,attempt)) = actual {
                        counter += 1;
                        proptest::prop_assert_eq!(attempt, counter);
                        frames.push((release,check(generation,attempt)));
                    }
                }
                1 if !frames.is_empty() => {
                    let (release,check) = &frames[usize::from(index) % frames.len()];
                    let actual = finish_check(&world.runtime,&world.db,&selection,&code,release,check);
                    proptest::prop_assert_eq!(actual.is_ok(), !blocked && check.attempt == counter);
                }
                2 => {
                    world.db.execute("UPDATE day2_authority SET revision=2",[]).unwrap();
                    blocked = true;
                }
                3 => {
                    let reopened = Connection::open(world.runtime.db()).unwrap();
                    let actual = require_executor(&world.runtime,&reopened,&world.selection(ExecutorRole::Source),&source_code);
                    proptest::prop_assert_eq!(actual.is_ok(), !blocked);
                }
                4 => proptest::prop_assert!(require_executor(&world.runtime,&world.db,&selection,&source_code).is_err()),
                5 => {
                    world.db.execute("UPDATE day2_authority SET epoch=?1",[crate::digest(b"restored epoch")]).unwrap();
                    blocked = true;
                }
                _ => {}
            }
            let foreign: bool = world.db.query_row("SELECT EXISTS(SELECT 1 FROM day2_invocation_runtime WHERE generation!=?1)",[&source],|row|row.get(0)).unwrap();
            proptest::prop_assert!(!foreign);
        }
    }
}

#[test]
fn failed_property_evidence_requires_a_private_directory_not_a_link_or_public_path() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    let private = root.path().join("private");
    private_evidence_directory(&private)?;
    assert_eq!(std::fs::metadata(&private)?.permissions().mode() & 0o077, 0);
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&private, &link)?;
    assert!(private_evidence_directory(&link).is_err());
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755))?;
    assert!(private_evidence_directory(&private).is_err());
    let regular = root.path().join("file");
    std::fs::write(&regular, b"not a directory")?;
    assert!(private_evidence_directory(&regular).is_err());
    Ok(())
}

#[tokio::test]
async fn health_exhaustion_refuses_without_queuing_more_native_work() -> Result<()> {
    let mut world = World::new()?;
    world.admit()?;
    let candidate = Arc::new(Candidate {
        selection: world.selection(ExecutorRole::Candidate),
        runtime: world.runtime,
        _serving: tempfile::tempfile()?,
        health_capacity: Arc::new(tokio::sync::Semaphore::new(0)),
    });
    assert_eq!(
        candidate_health(axum::extract::State(candidate)).await,
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}
