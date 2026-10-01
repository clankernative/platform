use anyhow::{Context, Result, bail, ensure};
use day2::{digest, schema::Schema, worker::Worker};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod build_native;
mod control_simulation;
mod formatter_bootstrap;
mod formatting;
mod linux_provisioning_fixture;
mod linux_qualification;
mod linux_runtime_qualification;
mod native_toolchain;
mod provider_conformance;
mod tooling;
mod verification;
mod workflows;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    namespace: String,
    operations: Vec<day2::artifact::Operation>,
    properties: Vec<String>,
    pages: Vec<day2::artifact::Page>,
    #[serde(default)]
    schedules: Vec<day2::artifact::Schedule>,
    #[serde(default)]
    ingress: Vec<day2::artifact::Endpoint>,
    #[serde(default)]
    redirects: Vec<day2::artifact::Redirect>,
}

const DEFAULT_CAMPAIGN_BUDGET_SECONDS: u64 = 600;

fn run(root: &Path, command: &mut Command) -> Result<()> {
    run_with_budget(
        root,
        command,
        std::time::Duration::from_secs(DEFAULT_CAMPAIGN_BUDGET_SECONDS),
    )
}

fn run_with_budget(root: &Path, command: &mut Command, budget: std::time::Duration) -> Result<()> {
    let display = format!("{command:?}");
    let mut child = command
        .current_dir(root)
        .spawn()
        .with_context(|| display.clone())?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > budget {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "subprocess exceeded {} second campaign budget: {display}",
                budget.as_secs()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    ensure!(status.success(), "{display} failed: {status}");
    Ok(())
}

fn snapshot(
    source: &Path,
    target: &Path,
    hashes: &mut BTreeMap<String, String>,
    prefix: &str,
) -> Result<()> {
    ensure!(
        prefix.split('/').count() <= 16,
        "source nesting budget exceeded"
    );
    ensure!(
        !fs::symlink_metadata(source)?.file_type().is_symlink(),
        "source root symlink forbidden"
    );
    fs::create_dir_all(target)?;
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= 256, "source directory budget exceeded");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid filename"))?;
        // Version-control metadata is never app input: an app that lives in its
        // own repository carries it beside its sources.
        if [".git", ".gitignore", ".gitattributes"].contains(&name.as_str()) {
            continue;
        }
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "source symlinks forbidden");
        if prefix == "app" && ["assets", "ui"].contains(&name.as_str()) {
            ensure!(kind.is_dir(), "{name} must be a directory");
        }
        let key = format!("{prefix}/{name}");
        if kind.is_dir() {
            snapshot(&entry.path(), &target.join(&name), hashes, &key)?;
        } else {
            ensure!(kind.is_file(), "special source file forbidden");
            let resource = prefix.starts_with("app/ui") || prefix.starts_with("app/assets");
            if name.ends_with(".md") && !resource {
                continue;
            }
            ensure!(
                name.ends_with(".roc")
                    || resource
                    || (prefix == "app" && name == day2::identity::REGISTRY_FILE),
                "app-owned non-Roc input: {key}"
            );
            if !resource
                && (day2::admission::reserved_module(&name)
                    || [
                        "main.roc",
                        "schema-platform.roc",
                        "app-platform.roc",
                        "AppIdentity.roc",
                        "SchemaSource.roc",
                        "Selectors.roc",
                        "Domains.roc",
                        "Errors.roc",
                        "Catalog.roc",
                        "Data.roc",
                        "Inputs.roc",
                        "Outputs.roc",
                        "Assets.roc",
                        "Templates.roc",
                        "Commands.roc",
                        "Reads.roc",
                        "AppContract.roc",
                        "ImportedContracts.roc",
                        "Credentials.roc",
                        "SecurityActions.roc",
                        "ProductReturns.roc",
                        "Registry.roc",
                    ]
                    .contains(&name.as_str()))
            {
                bail!("app-owned generated platform input forbidden: {name}");
            }
            let bytes = fs::read(entry.path())?;
            ensure!(
                bytes.len() <= if resource { 4 * 1024 * 1024 } else { 128_000 }
                    && hashes.len() < 512,
                "source budget exceeded"
            );
            hashes.insert(key, digest(&bytes));
            fs::write(target.join(name), bytes)?;
        }
    }
    Ok(())
}

fn build(root: &Path, app: &Path) -> Result<PathBuf> {
    build_with_overrides(root, app, None)
}

fn build_with_overrides(root: &Path, app: &Path, overrides: Option<&Path>) -> Result<PathBuf> {
    build_recipe(root, app, overrides, None, None)
}

struct BuildImportContext {
    instance: PathBuf,
    lock: PathBuf,
}

fn build_recipe(
    root: &Path,
    app: &Path,
    overrides: Option<&Path>,
    isolated_job: Option<&Path>,
    imports: Option<&BuildImportContext>,
) -> Result<PathBuf> {
    let runner = if let Some(job) = isolated_job {
        for (name, expected) in day2::automation::SOURCES {
            ensure!(
                fs::read(root.join(name))? == *expected,
                "isolated workflow source differs from trusted runner: {name}"
            );
        }
        job.join("day2-workflows")
    } else {
        workflows::build(root)?
    };
    build_native::execute(root, app, overrides, isolated_job, imports, &runner)
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args.next().unwrap_or_else(|| "build".into());
    let mut isolated_app = None;
    let root = if action == "build-isolated" {
        let root = PathBuf::from(
            args.next()
                .context("usage: xtask build-isolated PLATFORM_ROOT APP_ROOT")?,
        )
        .canonicalize()?;
        isolated_app = Some(
            PathBuf::from(
                args.next()
                    .context("usage: xtask build-isolated PLATFORM_ROOT APP_ROOT")?,
            )
            .canonicalize()?,
        );
        ensure!(
            args.next().is_none(),
            "usage: xtask build-isolated PLATFORM_ROOT APP_ROOT"
        );
        root
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?
    };
    // These closed native helpers read addressed artifacts or write only their
    // explicit new package output. They run as unprivileged tooling users and
    // do not need writable access to the platform's build workspace.
    let _lock = if [
        "linux-runtime-evidence",
        "linux-artifact-evidence",
        "linux-runtime-package",
        "linux-strict-denial",
        "linux-provision-package",
        "linux-provision-inspect",
    ]
    .contains(&action.as_str())
    {
        None
    } else {
        fs::create_dir_all(root.join("artifacts"))?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("artifacts/task.lock"))?;
        lock.try_lock()
            .context("another xtask holds the workspace build lock")?;
        Some(lock)
    };
    match action.as_str() {
        "source-check" => {
            ensure!(args.next().is_none(), "source-check accepts no arguments");
            tooling::source_check(&root)?;
        }
        "source-export" => {
            let destination = PathBuf::from(
                args.next()
                    .context("usage: xtask source-export NEW_DIRECTORY")?,
            );
            ensure!(
                args.next().is_none(),
                "usage: xtask source-export NEW_DIRECTORY"
            );
            tooling::source_export(&root, &destination)?;
        }
        "configure-tofu" => {
            let binary = args.next().map(PathBuf::from);
            ensure!(
                args.next().is_none(),
                "usage: xtask configure-tofu [BINARY]"
            );
            tooling::configure_tofu(&root, binary)?;
        }
        "notices" => {
            ensure!(args.next().is_none(), "notices accepts no arguments");
            tooling::notices(&root)?;
        }
        "provider-conformance" | "provider-conformance-resume" => {
            let usage =
                "usage: xtask provider-conformance[-resume] PROFILE TOKEN_FILE EVIDENCE_DIRECTORY";
            let profile = PathBuf::from(args.next().context(usage)?);
            let token = PathBuf::from(args.next().context(usage)?);
            let evidence = PathBuf::from(args.next().context(usage)?);
            ensure!(args.next().is_none(), "{usage}");
            provider_conformance::execute(
                &root,
                &profile,
                &token,
                &evidence,
                action.ends_with("-resume"),
            )?;
        }
        "simulate-control" => {
            let seed = args
                .next()
                .map(|value| value.parse::<u64>())
                .transpose()?
                .unwrap_or(day2_control::simulation_campaign::DEFAULT_SEED);
            let cases = args
                .next()
                .map(|value| value.parse::<u32>())
                .transpose()?
                .unwrap_or(day2_control::simulation_campaign::VERIFY_CASES);
            ensure!(
                args.next().is_none(),
                "usage: xtask simulate-control [SEED CASES]"
            );
            control_simulation::simulate(&root, seed, cases)?;
        }
        "replay-control" => {
            let trace = PathBuf::from(args.next().context("usage: xtask replay-control TRACE")?);
            ensure!(args.next().is_none(), "usage: xtask replay-control TRACE");
            control_simulation::replay(&root, &trace)?;
        }
        "register-model" | "retire-model" => {
            let app = PathBuf::from(args.next().context(
                "usage: xtask register-model APP TABLE Models.Type | retire-model APP TABLE",
            )?)
            .canonicalize()?;
            let table = args.next().context("missing table")?;
            if action == "register-model" {
                let roc_type = args.next().context("missing nominal Roc model type")?;
                ensure!(args.next().is_none(), "unexpected register-model arguments");
                day2::identity::register_model(&app, &table, &roc_type)?;
            } else {
                ensure!(args.next().is_none(), "unexpected retire-model arguments");
                day2::identity::retire_model(&app, &table)?;
            }
            println!(
                "Updated {}",
                app.join(day2::identity::REGISTRY_FILE).display()
            );
        }
        "contract-diff" => {
            let previous = PathBuf::from(
                args.next()
                    .context("usage: xtask contract-diff PREVIOUS NEXT")?,
            );
            let next = PathBuf::from(
                args.next()
                    .context("usage: xtask contract-diff PREVIOUS NEXT")?,
            );
            ensure!(args.next().is_none(), "unexpected contract-diff arguments");
            let report = day2::compatibility::compare(
                &day2::artifact::LoadedArtifact::load(&previous)?,
                &day2::artifact::LoadedArtifact::load(&next)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        "rename-model" => {
            let app = PathBuf::from(
                args.next()
                    .context("usage: xtask rename-model APP OLD_TABLE NEW_TABLE Models.Type")?,
            )
            .canonicalize()?;
            let old = args.next().context("missing old table")?;
            let table = args.next().context("missing new table")?;
            let roc_type = args.next().context("missing Roc type")?;
            ensure!(args.next().is_none(), "unexpected rename-model arguments");
            day2::identity::rename_registered(&app, &old, &table, &roc_type)?;
            println!(
                "Preserved the model's ID prefix in {}",
                app.join(day2::identity::REGISTRY_FILE).display()
            );
        }
        "fmt" | "fmt-check" => {
            ensure!(
                args.next().is_none(),
                "{action} accepts no source overrides"
            );
            format_sources(&root, action == "fmt-check")?;
        }
        "fmt-reports" | "fmt-check-reports" => {
            ensure!(
                args.next().is_none(),
                "{action} accepts no source overrides"
            );
            let check = action == "fmt-check-reports";
            let mut cargo = Command::new("cargo");
            cargo.args(["fmt", "--all"]);
            if check {
                cargo.args(["--", "--check"]);
            }
            run(&root, &mut cargo)?;
            let mode = if check {
                formatting::Mode::Check
            } else {
                formatting::Mode::Write
            };
            let count = formatting::reports(&root, mode)?;
            println!("Roc formatter {mode:?}: {count} authored files");
        }
        "build-isolated" => {
            build_recipe(
                &root,
                &isolated_app.context("isolated app root")?,
                None,
                Some(root.parent().context("isolated workspace parent")?),
                None,
            )?;
        }
        "build" => {
            let app = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join("examples/reports"));
            let context = match args.next() {
                None => None,
                Some(flag) => {
                    ensure!(
                        flag == "--instance",
                        "usage: xtask build APP [--instance INSTANCE_JSON --imports IMPORT_LOCK_JSON]"
                    );
                    let instance = PathBuf::from(args.next().context("missing build instance")?);
                    ensure!(
                        args.next().as_deref() == Some("--imports"),
                        "missing --imports build lock"
                    );
                    let lock = PathBuf::from(args.next().context("missing build import lock")?);
                    ensure!(args.next().is_none(), "unexpected build argument");
                    Some(BuildImportContext { instance, lock })
                }
            };
            build_recipe(&root, &app, None, None, context.as_ref())?;
        }
        "catalog-candidate" => {
            let instance = PathBuf::from(
                args.next()
                    .context("usage: xtask catalog-candidate INSTANCE_JSON")?,
            );
            ensure!(
                args.next().is_none(),
                "usage: xtask catalog-candidate INSTANCE_JSON"
            );
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            println!("{}", serde_json::to_string_pretty(&catalog)?);
        }
        "catalog-pin" => {
            let instance = PathBuf::from(
                args.next()
                    .context("usage: xtask catalog-pin INSTANCE_JSON OPERATION...")?,
            );
            let operations = args.collect::<Vec<_>>();
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&catalog.pin(&operations)?)?
            );
        }
        "catalog-resolve" => {
            let instance = PathBuf::from(
                args.next()
                    .context("usage: xtask catalog-resolve INSTANCE_JSON IMPORT_LOCK_JSON")?,
            );
            let lock = PathBuf::from(
                args.next()
                    .context("usage: xtask catalog-resolve INSTANCE_JSON IMPORT_LOCK_JSON")?,
            );
            ensure!(
                args.next().is_none() && fs::metadata(&lock)?.len() <= 1_048_576,
                "import lock byte budget or usage"
            );
            let lock: day2::instance_catalog::ImportLock = day2::json::decode(&fs::read(lock)?)?;
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&catalog.resolve(&lock)?)?
            );
        }
        "catalog-check-consumers" => {
            let instance = PathBuf::from(args.next().context(
                "usage: xtask catalog-check-consumers INSTANCE_JSON CONSUMER_LOCKS_JSON",
            )?);
            let locks = PathBuf::from(args.next().context(
                "usage: xtask catalog-check-consumers INSTANCE_JSON CONSUMER_LOCKS_JSON",
            )?);
            ensure!(
                args.next().is_none() && fs::metadata(&locks)?.len() <= 1_048_576,
                "consumer locks byte budget or usage"
            );
            let locks: BTreeMap<String, day2::instance_catalog::ImportLock> =
                day2::json::decode(&fs::read(locks)?)?;
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&catalog.check_consumers(&locks)?)?
            );
        }
        "catalog-active" => {
            let journal = PathBuf::from(args.next().context(
                "usage: xtask catalog-active RELEASE_JOURNAL ARTIFACT_STORE COMPANY ENVIRONMENT",
            )?);
            let store = PathBuf::from(args.next().context(
                "usage: xtask catalog-active RELEASE_JOURNAL ARTIFACT_STORE COMPANY ENVIRONMENT",
            )?);
            let company: day2_control::Name = args.next().context(
                "usage: xtask catalog-active RELEASE_JOURNAL ARTIFACT_STORE COMPANY ENVIRONMENT",
            )?.try_into()?;
            let environment: day2_control::Name = args.next().context(
                "usage: xtask catalog-active RELEASE_JOURNAL ARTIFACT_STORE COMPANY ENVIRONMENT",
            )?.try_into()?;
            ensure!(
                args.next().is_none() && fs::metadata(&journal)?.is_file(),
                "release journal or usage"
            );
            let control = day2_control::journal::Journal::open(&journal)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&control.active_catalog(
                    &company,
                    &environment,
                    &store
                )?)?
            );
        }
        "catalog-release-candidate" => {
            let journal = PathBuf::from(args.next().context(
                "usage: xtask catalog-release-candidate RELEASE_JOURNAL ARTIFACT_STORE RELEASE_ID [INSTANCE]",
            )?);
            let store = PathBuf::from(args.next().context(
                "usage: xtask catalog-release-candidate RELEASE_JOURNAL ARTIFACT_STORE RELEASE_ID [INSTANCE]",
            )?);
            let id: day2_control::Digest = args.next().context(
                "usage: xtask catalog-release-candidate RELEASE_JOURNAL ARTIFACT_STORE RELEASE_ID [INSTANCE]",
            )?.try_into()?;
            let instance = args.next().map(PathBuf::from);
            ensure!(
                args.next().is_none() && fs::metadata(&journal)?.is_file(),
                "release journal or usage"
            );
            let control = day2_control::journal::Journal::open(&journal)?;
            let approved = control.load_approved_release(&id)?;
            let candidate = if let Some(instance) = instance {
                let now_ms = i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_millis(),
                )?;
                control.candidate_catalog_with_instance(&approved, &store, &instance, now_ms)?
            } else {
                control.candidate_catalog(&approved, &store)?
            };
            println!("{}", serde_json::to_string_pretty(&candidate)?);
        }
        "build-receipt" => {
            let source = PathBuf::from(
                args.next()
                    .context("usage: xtask build-receipt SOURCE NEW_RECEIPT")?,
            );
            let receipt = PathBuf::from(
                args.next()
                    .context("usage: xtask build-receipt SOURCE NEW_RECEIPT")?,
            );
            ensure!(
                args.next().is_none() && !receipt.exists(),
                "new build receipt required"
            );
            let artifact = build(&root, &source)?;
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(receipt)?;
            file.write_all(&serde_json::to_vec(
                &serde_json::json!({"artifact":artifact}),
            )?)?;
            file.sync_all()?;
        }
        "cli" => {
            ensure!(args.next().is_none(), "xtask cli accepts no arguments");
            build_cli(&root)?;
        }
        "build-migration-fixture" => {
            build_migration_fixture(&root)?;
        }
        "build-http-conformance" => {
            ensure!(
                args.next().is_none(),
                "build-http-conformance accepts no arguments"
            );
            build_with_overrides(
                &root,
                &root.join("fixtures/row-authority-web-conformance"),
                Some(&root.join("fixtures/http-conformance")),
            )?;
        }
        "bootstrap" => {
            ensure!(args.next().is_none(), "usage: xtask bootstrap");
            bootstrap(&root)?;
        }
        "bootstrap-compiler" => {
            let candidate = args.next().map(PathBuf::from);
            ensure!(
                args.next().is_none(),
                "usage: xtask bootstrap-compiler [REVIEWED_BINARY]"
            );
            native_toolchain::install(&root, candidate.as_deref())?;
        }
        "bootstrap-formatter" => {
            let candidate = args.next().map(PathBuf::from);
            ensure!(
                args.next().is_none(),
                "usage: bootstrap-formatter [REVIEWED_BINARY]"
            );
            bootstrap(&root)?;
            formatter_bootstrap::install(&root, candidate.as_deref())?;
        }
        "build-formatter" => {
            ensure!(
                args.next().is_none(),
                "build-formatter accepts no overrides"
            );
            bootstrap(&root)?;
            formatter_bootstrap::build_candidate(&root)?;
        }
        "build-row-authority-adversaries" => {
            build_row_authority_adversaries(&root)?;
        }
        "build-command-target-adversaries" => {
            build_with_overrides(
                &root,
                &root.join("examples/reports"),
                Some(&root.join("fixtures/command-target-adversaries")),
            )?;
        }
        "brand" => {
            let source = PathBuf::from(args.next().context("usage: xtask brand SOURCE OUTPUT")?);
            let output = PathBuf::from(args.next().context("usage: xtask brand SOURCE OUTPUT")?);
            println!("{}", day2::branding::build(&source, &output)?.display());
        }
        "control-verify" => {
            ensure!(
                args.next().is_none(),
                "control-verify accepts no app-owned recipe arguments"
            );
            control_verify(&root)?;
        }
        "verify-fast" => {
            ensure!(args.next().is_none(), "verify-fast accepts no arguments");
            verification::execute(&root, "verify-fast")?;
        }
        "verify" => {
            ensure!(args.next().is_none(), "verify accepts no arguments");
            verification::execute(&root, "verify")?;
        }
        "qualify-linux" => {
            let output = PathBuf::from(
                args.next()
                    .context("usage: xtask qualify-linux NEW_DIRECTORY")?,
            );
            ensure!(
                args.next().is_none(),
                "qualify-linux accepts one new output directory"
            );
            linux_qualification::execute(&root, &output)?;
        }
        "provision-linux" => {
            let qualified = PathBuf::from(args.next().context("qualification directory required")?);
            let output = PathBuf::from(
                args.next()
                    .context("new provisioning smoke directory required")?,
            );
            ensure!(
                args.next().is_none(),
                "usage: xtask provision-linux QUALIFICATION_DIRECTORY NEW_OUTPUT"
            );
            linux_runtime_qualification::provision(&root, &qualified, &output)?;
        }
        "strict-linux" => {
            let qualified = PathBuf::from(args.next().context("qualification directory required")?);
            let output = PathBuf::from(args.next().context("new strict smoke directory required")?);
            ensure!(
                args.next().is_none(),
                "usage: xtask strict-linux QUALIFICATION_DIRECTORY NEW_OUTPUT"
            );
            linux_runtime_qualification::strict(&root, &qualified, &output)?;
        }
        "diagnose-linux" => {
            let failed = PathBuf::from(args.next().context(
                "usage: xtask diagnose-linux FAILED_DIRECTORY NEW_OUTPUT [--runtime-image SHA256] [--prior-native-suites DIAGNOSTIC_JSON]",
            )?);
            let output = PathBuf::from(
                args.next()
                    .context("new Linux diagnostic output required")?,
            );
            let mut runtime_image = None;
            let mut prior_suites = None;
            while let Some(option) = args.next() {
                match option.as_str() {
                    "--runtime-image" => {
                        ensure!(
                            runtime_image.is_none(),
                            "duplicate diagnostic runtime image"
                        );
                        runtime_image = Some(
                            args.next()
                                .context("pinned diagnostic runtime image required")?,
                        );
                    }
                    "--prior-native-suites" => {
                        ensure!(
                            prior_suites.is_none(),
                            "duplicate prior native suite evidence"
                        );
                        prior_suites = Some(PathBuf::from(
                            args.next().context("prior diagnostic evidence required")?,
                        ));
                    }
                    _ => bail!("unknown Linux diagnostic option"),
                }
            }
            linux_runtime_qualification::diagnose(
                &root,
                &failed,
                &output,
                runtime_image.as_deref(),
                prior_suites.as_deref(),
            )?;
        }
        "linux-test-suite" => {
            let suite = args
                .next()
                .context("usage: xtask linux-test-suite SUITE ARTIFACT")?;
            let artifact = PathBuf::from(args.next().context("Linux artifact required")?);
            let probe = PathBuf::from(
                args.next()
                    .context("Linux Reports probe artifact required")?,
            );
            ensure!(
                args.next().is_none(),
                "Linux test suite accepts no additional arguments"
            );
            verification::linux_tests(&root, &suite, &artifact, &probe)?;
        }
        "linux-build-probe" => {
            ensure!(
                cfg!(target_os = "linux") && args.next().is_none(),
                "closed native Linux probe build required"
            );
            let artifact = build_with_overrides(
                &root,
                &root.join("examples/reports"),
                Some(&root.join("fixtures/command-target-adversaries")),
            )?;
            println!("{}", serde_json::json!({"artifact":artifact}));
        }
        "linux-runtime-evidence" => {
            let instance = PathBuf::from(
                args.next()
                    .context("Linux qualification instance required")?,
            );
            ensure!(
                args.next().is_none(),
                "Linux runtime evidence accepts one instance"
            );
            println!(
                "{}",
                linux_runtime_qualification::native_evidence(&instance)?
            );
        }
        "linux-artifact-evidence" => {
            let artifact = PathBuf::from(args.next().context("Linux artifact required")?);
            ensure!(
                args.next().is_none(),
                "Linux artifact evidence accepts one artifact"
            );
            println!(
                "{}",
                linux_runtime_qualification::native_artifact_evidence(&artifact)?
            );
        }
        "linux-runtime-package" => {
            let artifact = PathBuf::from(args.next().context("Linux artifact required")?);
            let output = PathBuf::from(args.next().context("new Linux package output required")?);
            let installation = args.next().context("disposable installation required")?;
            let port = args
                .next()
                .context("Linux package port required")?
                .parse::<u16>()?;
            let image = args
                .next()
                .context("immutable Linux runtime image required")?;
            let security_receipt = args.next().map(PathBuf::from);
            ensure!(
                args.next().is_none(),
                "Linux runtime package accepts five arguments and optional security receipt"
            );
            println!(
                "{}",
                linux_runtime_qualification::native_package(
                    &artifact,
                    &output,
                    &installation,
                    port,
                    &image,
                    security_receipt.as_deref()
                )?
            );
        }
        "linux-strict-denial" => {
            let instance = PathBuf::from(args.next().context("strict instance required")?);
            ensure!(args.next().is_none(), "strict denial accepts one instance");
            println!(
                "{}",
                linux_runtime_qualification::native_strict_denial(&instance)?
            );
        }
        "linux-provision-package" => {
            let artifact = PathBuf::from(args.next().context("provisioning artifact required")?);
            let output = PathBuf::from(args.next().context("new provisioning fixture required")?);
            let installation = args.next().context("provisioning installation required")?;
            let port = args
                .next()
                .context("provisioning port required")?
                .parse::<u16>()?;
            let runtime_image = args.next().context("provisioning runtime image required")?;
            let tooling_image = args.next().context("provisioning tooling image required")?;
            ensure!(
                args.next().is_none(),
                "native provisioning fixture accepts six arguments"
            );
            println!(
                "{}",
                linux_provisioning_fixture::package(
                    &artifact,
                    &output,
                    &installation,
                    port,
                    &runtime_image,
                    &tooling_image
                )?
            );
        }
        "linux-provision-inspect" => {
            let instance = PathBuf::from(args.next().context("provisioned instance required")?);
            ensure!(
                args.next().is_none(),
                "native provisioning inspection accepts one instance"
            );
            println!("{}", linux_provisioning_fixture::inspect(&instance)?);
        }
        "workflows" => {
            ensure!(args.next().is_none(), "workflows accepts no arguments");
            workflows::build(&root)?;
        }
        "verify-reports" => {
            ensure!(args.next().is_none(), "verify-reports accepts no arguments");
            verify_reports(&root)?;
        }
        _ => bail!("unsupported task: {action}"),
    }
    Ok(())
}

fn format_sources(root: &Path, check: bool) -> Result<()> {
    let mut cargo = Command::new("cargo");
    cargo.args(["fmt", "--all"]);
    if check {
        cargo.args(["--", "--check"]);
    }
    run(root, &mut cargo)?;
    let mode = if check {
        formatting::Mode::Check
    } else {
        formatting::Mode::Write
    };
    let count = formatting::run(root, mode)?;
    println!("Roc formatter {mode:?}: {count} authored files");
    Ok(())
}

fn verify_reports(root: &Path) -> Result<()> {
    verification::execute(root, "verify-reports")
}

// Replacing an executable in place can leave macOS's cached signature bound to
// its previous bytes. Install a fresh inode atomically, including on repeat builds.
fn install_cli_file(source: impl AsRef<Path>, destination: impl AsRef<Path>) -> Result<()> {
    let destination = destination.as_ref();
    let temporary = tempfile::NamedTempFile::new_in(
        destination.parent().context("CLI destination directory")?,
    )?;
    fs::copy(source, temporary.path())?;
    temporary.as_file().sync_all()?;
    temporary.persist(destination)?;
    Ok(())
}

fn build_cli(root: &Path) -> Result<()> {
    let runner = workflows::build(root)?;
    install_cli_file(&runner, root.join("cli/day2-workflows"))?;
    install_cli_file(
        runner.with_extension("json"),
        root.join("cli/day2-workflows.json"),
    )?;
    let native_pin = native_toolchain::load(root)?;
    let roc = native_pin.verified_compiler(root)?;
    let pin = native_pin.value;
    let mut completed = std::collections::BTreeSet::new();
    day2::automation::run(&runner, &["cli"], |request| {
        let args: BTreeMap<String, String> = request.decode()?;
        let effect = match request.action.as_str() {
            "cli-native" => {
                ensure!(args.is_empty(), "native build accepts no overrides");
                run(
                    root,
                    Command::new("cargo").args([
                        "build",
                        "--locked",
                        "-p",
                        "day2-ops",
                        "--bin",
                        "day2-host",
                    ]),
                )?;
                run(
                    root,
                    Command::new("cargo").args([
                        "build",
                        "--locked",
                        "-p",
                        "day2-sandbox",
                        "--bins",
                    ]),
                )?;
                for name in [
                    "day2-sandbox",
                    "day2-compiler-sandbox",
                    "day2-sandbox-probe",
                ] {
                    install_cli_file(
                        root.join("target/debug").join(name),
                        root.join("cli").join(name),
                    )?;
                }
                install_cli_file(
                    root.join("target/debug/day2-host"),
                    root.join("cli/day2-host"),
                )?;
                install_cli_file(std::env::current_exe()?, root.join("cli/xtask"))?;
                "native".to_owned()
            }
            "cli-roc" => {
                ensure!(args.len() == 1, "one compiler operation required");
                let operation = args.get("operation").context("compiler operation")?;
                ensure!(
                    ["check", "test", "build"].contains(&operation.as_str()),
                    "unsupported CLI compiler operation"
                );
                let mut command = Command::new(&roc);
                command.arg(operation).arg("main.roc");
                if operation == "build" {
                    command.arg("--output=day2");
                }
                run(
                    &root.join("cli"),
                    command.env("ROC_CACHE_DIR", root.join("cli/.cache")),
                )?;
                operation.clone()
            }
            "cli-workflow-tests" => {
                ensure!(args.is_empty(), "workflow tests accept no overrides");
                run(
                    root,
                    Command::new(&roc)
                        .args(["test", "ops/Runner.roc"])
                        .env("ROC_CACHE_DIR", root.join("cli/.cache")),
                )?;
                "workflows".to_owned()
            }
            "cli-receipt" => {
                ensure!(
                    ["native", "check", "test", "build", "workflows"]
                        .iter()
                        .all(|step| completed.contains(*step)),
                    "CLI distribution incomplete"
                );
                for name in [
                    "LICENSE",
                    "THIRD-PARTY-NOTICES.txt",
                    "dependency-inventory.json",
                ] {
                    fs::copy(root.join(name), root.join("cli").join(name))?;
                }
                let mut binaries = BTreeMap::new();
                for name in [
                    "day2",
                    "day2-host",
                    "xtask",
                    "day2-workflows",
                    "day2-sandbox",
                    "day2-compiler-sandbox",
                    "day2-sandbox-probe",
                ] {
                    binaries.insert(name, digest(&fs::read(root.join("cli").join(name))?));
                }
                fs::write(
                    root.join("cli/distribution.json"),
                    serde_json::to_vec_pretty(
                        &serde_json::json!({"format":1,"protocol":1,"toolchain":pin,"workflow":day2::automation::source_digest(),"binaries":binaries,"kind":"local-source-distribution"}),
                    )?,
                )?;
                return Ok(serde_json::json!({}));
            }
            _ => bail!("unknown CLI compiler capability"),
        };
        ensure!(completed.insert(effect), "duplicate CLI compilation effect");
        Ok(serde_json::json!({}))
    })?;
    Ok(())
}

fn control_verify(root: &Path) -> Result<()> {
    verification::execute(root, "control-verify")
}

fn hash_tree(root: &Path, directory: &Path, hashes: &mut BTreeMap<String, String>) -> Result<()> {
    if directory == root.join("crates/worker/generated") {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if day2_control::build::local_platform_input(&entry.path()) {
            continue;
        }
        ensure!(!entry.file_type()?.is_symlink(), "platform source symlink");
        let path = entry.path();
        if path.is_dir() {
            hash_tree(root, &path, hashes)?;
        } else {
            let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ["rs", "roc", "toml"].contains(&extension)
                || ["assets", "deploy", "toolchains"]
                    .iter()
                    .any(|directory| path.starts_with(root.join(directory)))
            {
                hashes.insert(
                    path.strip_prefix(root)?.to_string_lossy().to_string(),
                    digest(&fs::read(&path)?),
                );
            }
        }
    }
    Ok(())
}

fn bootstrap(root: &Path) -> Result<()> {
    native_toolchain::bootstrap(root)
}

fn build_migration_fixture(root: &Path) -> Result<PathBuf> {
    build_with_overrides(
        root,
        &root.join("fixtures/relational-conformance"),
        Some(&root.join("fixtures/migration-add-optional-text")),
    )
}

fn build_row_authority_adversaries(root: &Path) -> Result<PathBuf> {
    build_with_overrides(
        root,
        &root.join("fixtures/row-authority-web-conformance"),
        Some(&root.join("fixtures/row-authority-adversaries")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_snapshot_rejects_project_files_headers_and_symlinks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("App.roc"), "App :: [].{}\n")?;
        snapshot(
            &source,
            &directory.path().join("valid"),
            &mut BTreeMap::new(),
            "app",
        )?;
        for name in [
            "Cargo.toml",
            "main.roc",
            "schema-platform.roc",
            "app-platform.roc",
            "AppIdentity.roc",
            "Catalog.roc",
            "Data.roc",
            "Inputs.roc",
            "Outputs.roc",
            "Assets.roc",
            "Templates.roc",
            "Commands.roc",
            "Reads.roc",
            "Registry.roc",
            "AppContract.roc",
            "CollectionPage.roc",
            "Cursor.roc",
            "PageSize.roc",
            "Context.roc",
            "Write.roc",
            "Read.roc",
            "Product.roc",
        ] {
            let path = source.join(name);
            fs::write(&path, "unexpected input")?;
            assert!(
                snapshot(
                    &source,
                    &directory.path().join("invalid"),
                    &mut BTreeMap::new(),
                    "app"
                )
                .is_err()
            );
            fs::remove_file(path)?;
        }
        std::os::unix::fs::symlink(source.join("App.roc"), source.join("Linked.roc"))?;
        assert!(
            snapshot(
                &source,
                &directory.path().join("linked"),
                &mut BTreeMap::new(),
                "app"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn version_control_metadata_is_not_app_input() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir_all(source.join(".git/objects"))?;
        fs::write(source.join(".git/HEAD"), "ref: refs/heads/main\n")?;
        fs::write(source.join(".gitignore"), "artifacts/\n")?;
        fs::write(source.join(".gitattributes"), "* text=auto\n")?;
        fs::write(source.join("App.roc"), "App :: [].{}\n")?;
        let target = directory.path().join("stage");
        let mut hashes = BTreeMap::new();
        snapshot(&source, &target, &mut hashes, "app")?;
        assert_eq!(hashes.keys().collect::<Vec<_>>(), ["app/App.roc"]);
        for name in [".git", ".gitignore", ".gitattributes"] {
            assert!(!target.join(name).exists(), "{name} was captured");
        }
        // Any other dotfile is still refused.
        fs::write(source.join(".env"), "SECRET=1\n")?;
        assert!(
            snapshot(
                &source,
                &directory.path().join("dotfile"),
                &mut BTreeMap::new(),
                "app"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn resources_overlays_and_identity_history_share_the_captured_tree() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir_all(source.join("ui/pages"))?;
        fs::write(source.join("App.roc"), "App :: [].{}\n")?;
        fs::write(source.join("ui/app.css"), "body { color: red }")?;
        fs::write(source.join("ui/pages/home.html"), "<p>Captured</p>")?;
        fs::write(
            source.join(day2::identity::REGISTRY_FILE),
            "{\"format\":1,\"models\":[]}",
        )?;
        let target = directory.path().join("stage");
        let mut hashes = BTreeMap::new();
        snapshot(&source, &target, &mut hashes, "app")?;
        fs::write(source.join("ui/app.css"), "body { color: blue }")?;
        fs::remove_file(source.join(day2::identity::REGISTRY_FILE))?;
        assert_eq!(
            fs::read_to_string(target.join("ui/app.css"))?,
            "body { color: red }"
        );
        assert!(target.join(day2::identity::REGISTRY_FILE).exists());
        let overlay = directory.path().join("overlay");
        fs::create_dir_all(overlay.join("ui"))?;
        fs::write(overlay.join("ui/app.css"), "body { color: green }")?;
        snapshot(&overlay, &target, &mut hashes, "app")?;
        assert_eq!(
            hashes["app/ui/app.css"],
            digest(&fs::read(target.join("ui/app.css"))?)
        );
        assert_eq!(
            fs::read_to_string(target.join("ui/app.css"))?,
            "body { color: green }"
        );
        Ok(())
    }
}
