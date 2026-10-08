use anyhow::Result;
use day2_capabilities::{AppControl, ControlScope, InstallationControl, SourceProvider};
use day2_control::{
    Digest, Name,
    local_source::{SourceBundle, SourceChange},
    service::{Service, SourceState},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

fn name(value: &str) -> Name {
    Name::try_from(value.to_owned()).expect("fixture name")
}
fn configuration(directory: &std::path::Path) -> InstallationControl {
    InstallationControl {
        version: 1,
        state_directory: directory.join("state").display().to_string(),
        operators: BTreeSet::from(["operator@example.com".to_owned()]),
        sources: BTreeMap::from([(
            name("links-source"),
            SourceProvider::LocalGit {
                repository: directory
                    .join("repositories/links.git")
                    .display()
                    .to_string(),
            },
        )]),
        apps: BTreeMap::from([(
            name("links"),
            AppControl {
                source: name("links-source"),
                build: None,
                provider_secrets: BTreeMap::new(),
            },
        )]),
        builders: BTreeMap::new(),
        runtimes: BTreeMap::new(),
        secrets: BTreeMap::new(),
        security_epochs: BTreeMap::new(),
    }
}
fn scope() -> ControlScope {
    ControlScope {
        installation: name("example"),
        environment: name("development"),
    }
}
fn bundle(value: &str) -> Result<SourceBundle> {
    SourceBundle::from_files(BTreeMap::from([
        ("App.roc".to_owned(), value.as_bytes().to_vec()),
        (
            "pages/index.html".to_owned(),
            b"<main>Links</main>".to_vec(),
        ),
    ]))
}

#[test]
fn installed_operator_exports_real_git_and_proposes_without_mutating_main() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().canonicalize()?;
    let config = configuration(&directory);
    let service = Service::open(scope(), config.clone(), ["links"])?;
    let handle = service.authorize("operator@example.com", &name("links"))?;
    let change = SourceChange::Export {
        bundle: bundle("first")?,
    };
    let accepted = service.submit(&handle, name("export-one"), change.clone())?;
    assert!(matches!(accepted.state, SourceState::Pending));
    assert!(!directory.join("repositories/links.git").exists());
    assert_eq!(service.pending(&handle)?, vec![accepted.id.clone()]);
    assert_eq!(
        service.submit(&handle, name("export-one"), change)?.id,
        accepted.id
    );
    let service = Service::open(scope(), config, ["links"])?;
    let completed = service.advance_at(&handle, &accepted.id, 10)?;
    let SourceState::Completed { receipt } = completed.state else {
        panic!("source export did not complete");
    };
    assert_eq!(receipt.reference, "refs/heads/main");
    assert_eq!(
        service.source(&handle)?.snapshot(&receipt.commit)?.files(),
        bundle("first")?.files()
    );
    let proposed = service.submit(
        &handle,
        name("proposal-one"),
        SourceChange::Propose {
            base: receipt.commit.clone(),
            bundle: bundle("second")?,
        },
    )?;
    let SourceState::Completed { receipt: proposal } =
        service.advance_at(&handle, &proposed.id, 20)?.state
    else {
        panic!("proposal did not complete");
    };
    assert!(proposal.reference.starts_with("refs/heads/day2/"));
    assert_ne!(proposal.commit, receipt.commit);
    assert_eq!(
        service.source(&handle)?.snapshot(&receipt.commit)?.files(),
        bundle("first")?.files()
    );
    assert_eq!(
        service.source(&handle)?.snapshot(&proposal.commit)?.files(),
        bundle("second")?.files()
    );
    assert!(service.pending(&handle)?.is_empty());
    assert!(matches!(
        service.advance_at(&handle, &accepted.id, 30)?.state,
        SourceState::Completed { .. }
    ));
    Ok(())
}

#[test]
fn source_authority_conflicts_and_scope_are_fail_closed() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let config = configuration(&root);
    let service = Service::open(scope(), config.clone(), ["links"])?;
    assert!(
        service
            .authorize("reader@example.com", &name("links"))
            .is_err()
    );
    assert!(
        service
            .authorize("operator@example.com", &name("other"))
            .is_err()
    );
    let handle = service.authorize("operator@example.com", &name("links"))?;
    let accepted = service.submit(
        &handle,
        name("request"),
        SourceChange::Export {
            bundle: bundle("first")?,
        },
    )?;
    assert!(
        service
            .submit(
                &handle,
                name("request"),
                SourceChange::Export {
                    bundle: bundle("different")?
                }
            )
            .is_err()
    );
    let mut changed = config.clone();
    changed.sources.insert(
        name("links-source"),
        SourceProvider::LocalGit {
            repository: root.join("repositories/other.git").display().to_string(),
        },
    );
    let changed = Service::open(scope(), changed, ["links"])?;
    assert!(changed.advance_at(&handle, &accepted.id, 10).is_err());
    let mut another_scope = scope();
    another_scope.environment = name("production");
    assert!(Service::open(another_scope, config, ["links"]).is_err());
    assert!(
        service
            .build_plan(&handle, name("build"), "1".repeat(40).try_into()?)
            .is_err()
    );
    Ok(())
}

#[test]
fn source_reconciliation_after_commit_before_journal_completion_reuses_exact_commit() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let service = Service::open(
        scope(),
        configuration(&directory.path().canonicalize()?),
        ["links"],
    )?;
    let handle = service.authorize("operator@example.com", &name("links"))?;
    let change = SourceChange::Export {
        bundle: bundle("first")?,
    };
    let accepted = service.submit(&handle, name("crash"), change.clone())?;
    let externally_applied = service.source(&handle)?.apply(&accepted.id, &change)?;
    let SourceState::Completed { receipt } = service.advance_at(&handle, &accepted.id, 10)?.state
    else {
        panic!("recovery failed");
    };
    assert_eq!(receipt, externally_applied);
    let conflicting = service.submit(
        &handle,
        name("second-export"),
        SourceChange::Export {
            bundle: bundle("second")?,
        },
    )?;
    assert!(matches!(
        service.advance_at(&handle, &conflicting.id, 20)?.state,
        SourceState::Rejected { .. }
    ));
    let invalid_base = service.submit(
        &handle,
        name("invalid-base"),
        SourceChange::Propose {
            base: "0".repeat(40).try_into()?,
            bundle: bundle("third")?,
        },
    )?;
    assert!(matches!(
        service.advance_at(&handle, &invalid_base.id, 30)?.state,
        SourceState::Rejected { .. }
    ));
    Ok(())
}

#[test]
fn source_admission_rejects_authority_expansion_and_ignores_only_vcs_metadata() -> Result<()> {
    for path in [
        "../App.roc",
        "build.sh",
        "package.json",
        ".env",
        ".github/workflows/ci.yml",
        "safe/../../App.roc",
    ] {
        assert!(
            SourceBundle::from_files(BTreeMap::from([(path.to_owned(), b"bad".to_vec())])).is_err(),
            "{path}"
        );
    }
    let directory = tempfile::tempdir()?;
    fs::create_dir(directory.path().join(".git"))?;
    fs::write(directory.path().join(".git/config"), b"not source")?;
    fs::write(directory.path().join("App.roc"), b"source")?;
    let bundle = SourceBundle::capture(directory.path())?;
    assert_eq!(bundle.files().len(), 1);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("App.roc", directory.path().join("copy.roc"))?;
        assert!(SourceBundle::capture(directory.path()).is_err());
    }
    Ok(())
}

#[test]
fn local_control_cli_uses_the_real_instance_and_resumes_accepted_work() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let instance = root.join("instance.json");
    fs::write(
        &instance,
        serde_json::to_vec(&serde_json::json!({
            "installation":"example","environment":"development",
            "apps":{"links":{"artifact":"fixture","readers":[],"writers":[]}},
            "control":configuration(&root)
        }))?,
    )?;
    let source = root.join("source");
    fs::create_dir(&source)?;
    fs::write(source.join("App.roc"), b"source")?;
    let run = |actor: &str, arguments: &[&str]| -> Result<std::process::Output> {
        Ok(std::process::Command::new(env!("CARGO_BIN_EXE_control"))
            .arg("--local")
            .arg(&instance)
            .args([actor, "links"])
            .args(arguments)
            .output()?)
    };
    let accepted = run(
        "operator@example.com",
        &["export", "cli-export", source.to_str().unwrap()],
    )?;
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted: day2_control::service::SourceStatus = serde_json::from_slice(&accepted.stdout)?;
    assert!(matches!(accepted.state, SourceState::Pending));
    assert!(
        !run("reader@example.com", &["run", accepted.id.as_str()])?
            .status
            .success()
    );
    let completed = run("operator@example.com", &["run", accepted.id.as_str()])?;
    assert!(
        completed.status.success(),
        "{}",
        String::from_utf8_lossy(&completed.stderr)
    );
    let completed: day2_control::service::SourceStatus = serde_json::from_slice(&completed.stdout)?;
    assert!(matches!(completed.state, SourceState::Completed { .. }));
    assert!(
        run("operator@example.com", &["status", accepted.id.as_str()])?
            .status
            .success()
    );
    Ok(())
}

#[test]
fn installation_rejects_missing_apps_duplicate_authority_and_unknown_fields() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut config = configuration(&directory.path().canonicalize()?);
    assert!(config.validate(["other"]).is_err());
    config
        .apps
        .insert(name("other"), config.apps[&name("links")].clone());
    assert!(config.validate(["links", "other"]).is_err());
    let mut json = serde_json::to_value(configuration(&directory.path().canonicalize()?))?;
    json["arbitrary_shell"] = serde_json::json!("bash");
    assert!(serde_json::from_value::<InstallationControl>(json).is_err());
    assert_ne!(
        Digest::of(&scope())?,
        Digest::of(&ControlScope {
            installation: name("example_development"),
            environment: name("x")
        })?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-pinned native build plus isolated real Temporal; requires DAY2_TEST_BUILD_* paths"]
async fn real_installation_export_build_and_temporal_completion() -> Result<()> {
    use anyhow::Context;
    use day2_capabilities::{BuildProvider, DurabilityProvider};
    use day2_control::local_build::{BuildRuntime, PreparedBuild};
    use durable_temporal::{
        StepOutcome,
        local::{LOCAL_TASK_QUEUE, LocalServer},
    };
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    #[cfg(unix)]
    anyhow::ensure!(
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&root)?.permissions()) & 0o777
            == 0o700,
        "operator installation evidence root must be private"
    );
    // Direct stderr survives successful libtest capture; keep only after it succeeds.
    std::io::Write::write_fmt(
        &mut std::io::stderr().lock(),
        format_args!("retained installation evidence: {}\n", root.display()),
    )?;
    let _retained_root = directory.keep();
    let platform = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let mut server = LocalServer::start(&root.join("temporal")).await?;
    let operator_path = |name: &str| -> Result<String> {
        Ok(std::path::PathBuf::from(
            std::env::var_os(name).with_context(|| format!("missing {name}"))?,
        )
        .canonicalize()?
        .display()
        .to_string())
    };
    let mut config = configuration(&root);
    config.builders.insert(
        name("local-builder"),
        BuildProvider::LocalMacos {
            platform_root: platform.display().to_string(),
            toolchains: platform
                .join("../.toolchains")
                .canonicalize()?
                .display()
                .to_string(),
            xtask: operator_path("DAY2_TEST_BUILD_XTASK")?,
            rust: operator_path("DAY2_TEST_BUILD_RUST")?,
            registry: operator_path("DAY2_TEST_BUILD_REGISTRY")?,
        },
    );
    config.runtimes.insert(
        name("local-temporal"),
        DurabilityProvider::TemporalLocal {
            endpoint: server.address().to_string(),
            namespace: server.namespace().to_owned(),
            task_queue: LOCAL_TASK_QUEUE.to_owned(),
        },
    );
    let service = Service::open(scope(), config.clone(), ["links"])?;
    let handle = service.authorize("operator@example.com", &name("links"))?;
    let accepted = service.submit(
        &handle,
        name("export"),
        SourceChange::Export {
            bundle: SourceBundle::capture(
                &platform.join("fixtures/row-authority-web-conformance"),
            )?,
        },
    )?;
    let SourceState::Completed { receipt } = service.advance(&handle, &accepted.id)?.state else {
        panic!("source export failed");
    };
    // Admission and pinning are offline even when the selected durable runtime is unavailable.
    server.stop()?;
    let prepared = PreparedBuild::capture(
        &service,
        &handle,
        &name("local-builder"),
        &name("local-temporal"),
    )?;
    config
        .apps
        .get_mut(&name("links"))
        .context("app fixture")?
        .build = Some(prepared.profile().clone());
    let service = Service::open(scope(), config, ["links"])?;
    let runtime: BuildRuntime = prepared.activate(&service, &handle)?;
    let id = service.submit_build(
        &handle,
        &runtime.host,
        name("build"),
        receipt.commit.clone(),
    )?;
    assert!(
        matches!(day2_control::journal::Journal::open(&service.build_journal())?.accepted_by(&id)?,
        day2_control::journal::AcceptanceProvenance::Operator { actor } if actor.as_str() == "operator@example.com")
    );
    assert_eq!(
        id,
        service.submit_build(&handle, &runtime.host, name("build"), receipt.commit)?
    );
    server.restart().await?;
    assert_eq!(runtime.run(&id).await?, StepOutcome::Succeeded);
    assert!(matches!(
        service.build_status(&handle, &id)?.state,
        day2_control::kernel::State::Succeeded { .. }
    ));
    server.stop()?;
    Ok(())
}
