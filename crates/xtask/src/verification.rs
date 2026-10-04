//! Native regression-check capabilities. Verify.roc selects fixtures, suites
//! and their order. Only passing native effects can enter a verification receipt.
use super::*;
use serde_json::json;
use std::{
    collections::BTreeSet,
    io::Write,
    time::{Duration, Instant},
};

const CACHE_FORMAT: u32 = 1;

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationCache {
    format: u32,
    scope: String,
    snapshot: String,
    fixtures: BTreeMap<String, String>,
}

impl VerificationCache {
    fn empty(scope: &str, snapshot: &str) -> Self {
        Self {
            format: CACHE_FORMAT,
            scope: scope.into(),
            snapshot: snapshot.into(),
            fixtures: BTreeMap::new(),
        }
    }
}

struct Timings {
    started: Instant,
    steps_ms: BTreeMap<String, u64>,
}

impl Timings {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            steps_ms: BTreeMap::new(),
        }
    }

    fn complete(&mut self, step: impl Into<String>, started: Instant) -> Result<()> {
        let step = step.into();
        let elapsed = milliseconds(started.elapsed());
        ensure!(
            self.steps_ms.insert(step.clone(), elapsed).is_none(),
            "duplicate verification timing: {step}"
        );
        println!("Verification step {step}: {:.3}s", elapsed as f64 / 1_000.0);
        Ok(())
    }
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestCampaign {
    suite: String,
    #[serde(default = "default_test_budget_seconds")]
    budget_seconds: u64,
}

fn default_test_budget_seconds() -> u64 {
    DEFAULT_CAMPAIGN_BUDGET_SECONDS
}

impl TestCampaign {
    fn budget(&self) -> Result<std::time::Duration> {
        let maximum = match self.suite.as_str() {
            "all-runtime" => 9000,
            "workspace-runtime" => 12600,
            "control" => 3600,
            "isolated-build" | "installation-build" => 1800,
            _ => DEFAULT_CAMPAIGN_BUDGET_SECONDS,
        };
        ensure!(
            (1..=maximum).contains(&self.budget_seconds),
            "test campaign budget must be between 1 and {maximum} seconds"
        );
        Ok(std::time::Duration::from_secs(self.budget_seconds))
    }
}

pub fn execute(root: &Path, recipe: &str) -> Result<()> {
    let scope = recipe_scope(recipe)?;
    architecture::check(root)?;
    architecture_dependencies::check(root)?;
    architecture_proofs::check(root)?;
    let snapshot = verification_snapshot(root, recipe)?;
    let runner = workflows::build(root)?;
    let mut fixtures: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut passed = BTreeSet::new();
    let mut simulation = None;
    let mut simulation_started = None;
    let mut timings = Timings::new();
    let mut cache = load_cache(root, scope, &snapshot)?;
    day2::automation::run(&runner, &[recipe], |request| {
        if request.action.starts_with("simulation-") {
            if simulation.is_none() {
                ensure!(
                    request.action == "simulation-open",
                    "open simulation before requesting effects"
                );
                simulation_started = Some(Instant::now());
                simulation = Some(control_simulation::session(
                    root,
                    day2_control::simulation_campaign::DEFAULT_SEED,
                    day2_control::simulation_campaign::VERIFY_CASES,
                )?);
            }
            let session = simulation.as_mut().context("simulation session")?;
            let result = session.effect(request)?;
            if session.is_complete() {
                ensure!(
                    passed.insert("control-simulation".into()),
                    "duplicate simulation campaign"
                );
                println!(
                    "Control simulation evidence: {}",
                    session.directory().display()
                );
                ensure_stable(root, recipe, &snapshot)?;
                timings.complete(
                    "control-simulation",
                    simulation_started.take().context("simulation start time")?,
                )?;
            }
            return Ok(result);
        }
        if request.action == "verify-tests" {
            let campaign: TestCampaign = request.decode()?;
            let budget = campaign.budget()?;
            let started = Instant::now();
            tests(root, &campaign.suite, &fixtures, budget)?;
            ensure_stable(root, recipe, &snapshot)?;
            let step = format!("test-{}", campaign.suite);
            ensure!(passed.insert(step.clone()), "duplicate verification effect");
            timings.complete(step, started)?;
            return Ok(json!({}));
        }
        let parameters: BTreeMap<String, String> = request.decode()?;
        let value = |key: &str| -> Result<&str> {
            ensure!(parameters.len() == 1, "one capability parameter required");
            parameters
                .get(key)
                .map(String::as_str)
                .context("missing capability parameter")
        };
        let started = Instant::now();
        let key = match request.action.as_str() {
            "verify-format" => {
                let scope = value("scope")?;
                if scope == "all" {
                    format_sources(root, true)?;
                } else {
                    ensure!(scope == "reports", "unknown formatter scope");
                    run(
                        root,
                        Command::new("cargo").args(["fmt", "--all", "--", "--check"]),
                    )?;
                    formatting::reports(root, formatting::Mode::Check)?;
                }
                format!("format-{scope}")
            }
            "verify-lint" => {
                ensure!(parameters.is_empty(), "lint accepts no overrides");
                architecture::check(root)?;
                architecture_dependencies::check(root)?;
                architecture_proofs::check(root)?;
                run(
                    root,
                    Command::new("cargo").args([
                        "clippy",
                        "--locked",
                        "--workspace",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ]),
                )?;
                "lint".into()
            }
            "verify-cli" => {
                ensure!(parameters.is_empty(), "CLI build accepts no overrides");
                build_cli(root)?;
                "cli".into()
            }
            "verify-build" => {
                let fixture = value("fixture")?;
                ensure!(!fixtures.contains_key(fixture), "duplicate fixture");
                let cached = cache
                    .fixtures
                    .get(fixture)
                    .map_or(Ok(None), |artifact| cached_fixture(root, artifact));
                let artifact = match cached {
                    Ok(Some(artifact)) => {
                        println!("Reusing verified {fixture} fixture: {}", artifact.display());
                        artifact
                    }
                    Ok(None) => build_fixture(root, fixture, &fixtures)?,
                    Err(error) => {
                        eprintln!("Ignoring invalid cached {fixture} fixture: {error:#}");
                        build_fixture(root, fixture, &fixtures)?
                    }
                };
                let loaded = day2::artifact::LoadedArtifact::load(&artifact)?;
                cache
                    .fixtures
                    .insert(fixture.into(), loaded.id().to_owned());
                save_cache(root, &cache)?;
                fixtures.insert(fixture.into(), artifact);
                format!("build-{fixture}")
            }
            "verify-receipt" => {
                let scope = value("scope")?;
                ensure_stable(root, recipe, &snapshot)?;
                receipt(
                    root,
                    scope,
                    &fixtures,
                    &passed,
                    &snapshot,
                    &timings.steps_ms,
                    milliseconds(timings.started.elapsed()),
                )?;
                return Ok(
                    json!({"status":"passed","scope":scope,"workflow":day2::automation::source_digest()}),
                );
            }
            _ => bail!("unknown verification capability: {}", request.action),
        };
        ensure_stable(root, recipe, &snapshot)?;
        ensure!(passed.insert(key.clone()), "duplicate verification effect");
        timings.complete(key, started)?;
        Ok(json!({}))
    })?;
    Ok(())
}

fn build_fixture(
    root: &Path,
    fixture: &str,
    fixtures: &BTreeMap<String, PathBuf>,
) -> Result<PathBuf> {
    match fixture {
        "app-ownership" => build(root, &root.join("examples/app-ownership")),
        "notifications" => {
            let peer = fixtures
                .get("app-ownership")
                .context("build ownership before notifications")?;
            let inputs = tempfile::tempdir()?;
            let instance = inputs.path().join("instance.json");
            let lock = inputs.path().join("imports.json");
            fs::write(
                &instance,
                serde_json::to_vec(
                    &json!({"installation":"notifications_fixture","environment":"test","apps":{"app_ownership":{"artifact":peer,"readers":["alice"],"writers":["operator"]}}}),
                )?,
            )?;
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            fs::write(
                &lock,
                serde_json::to_vec(&catalog.pin(&["app_ownership.check".into()])?)?,
            )?;
            build_recipe(
                root,
                &root.join("examples/notifications"),
                None,
                None,
                Some(&BuildImportContext { instance, lock }),
            )
        }
        "stock-ledger" => build(root, &root.join("fixtures/stock-ledger")),
        "request-desk" => {
            let peer = fixtures
                .get("stock-ledger")
                .context("build stock ledger before request desk")?;
            let inputs = tempfile::tempdir()?;
            let instance = inputs.path().join("instance.json");
            let lock = inputs.path().join("imports.json");
            fs::write(
                &instance,
                serde_json::to_vec(
                    &json!({"installation":"delegation_fixture","environment":"test","apps":{"stock_ledger":{"artifact":peer,"readers":["alice"],"writers":["alice"]}}}),
                )?,
            )?;
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            fs::write(
                &lock,
                serde_json::to_vec(&catalog.pin(&[
                    "stock_ledger.available".into(),
                    "stock_ledger.reserve".into(),
                ])?)?,
            )?;
            build_recipe(
                root,
                &root.join("fixtures/request-desk"),
                None,
                None,
                Some(&BuildImportContext { instance, lock }),
            )
        }
        "reports" => build(root, &root.join("examples/reports")),
        "reports-probe" => build_with_overrides(
            root,
            &root.join("examples/reports"),
            Some(&root.join("fixtures/command-target-adversaries")),
        ),
        "http" => build_with_overrides(
            root,
            &root.join("fixtures/row-authority-web-conformance"),
            Some(&root.join("fixtures/http-conformance")),
        ),
        "relational" => build(root, &root.join("fixtures/relational-conformance")),
        "collection" => build(root, &root.join("fixtures/collection-conformance")),
        "credential-metadata" => {
            build(root, &root.join("fixtures/credential-metadata-conformance"))
        }
        "connection-declaration" => build(
            root,
            &root.join("fixtures/connection-declaration-conformance"),
        ),
        "oauth-calendar" => build(root, &root.join("fixtures/oauth-calendar-canary")),
        "delegation-peer" => build_with_overrides(
            root,
            &root.join("fixtures/delegation-conformance"),
            Some(&root.join("fixtures/delegation-peer")),
        ),
        "delegation" => {
            let peer = fixtures
                .get("delegation-peer")
                .context("build delegation peer before caller")?;
            let inputs = tempfile::tempdir()?;
            let instance = inputs.path().join("instance.json");
            let lock = inputs.path().join("imports.json");
            fs::write(
                &instance,
                serde_json::to_vec(&json!({
                    "installation":"delegation_fixture","environment":"test",
                    "apps":{"peer_identity":{"artifact":peer,"readers":["alice"],"writers":["alice"]}}
                }))?,
            )?;
            let catalog = day2::instance_catalog::CandidateCatalog::from_instance_file(&instance)?;
            fs::write(
                &lock,
                serde_json::to_vec(
                    &catalog.pin(&["peer_identity.who".into(), "peer_identity.record".into()])?,
                )?,
            )?;
            build_recipe(
                root,
                &root.join("fixtures/delegation-conformance"),
                None,
                None,
                Some(&BuildImportContext { instance, lock }),
            )
        }
        "redirect" => build(root, &root.join("fixtures/redirect-conformance")),
        "relational-next" => build_migration_fixture(root),
        "owned" => build(root, &root.join("fixtures/row-authority-web-conformance")),
        "repeated-field" => build(root, &root.join("fixtures/repeated-field-conformance")),
        "owned-probe" => build_row_authority_adversaries(root),
        _ => bail!("unknown fixture"),
    }
}

pub fn build_delegation(root: &Path) -> Result<()> {
    build_delegation_recipe(root, "build-delegation", "delegation-fixtures.json")
}

pub fn build_delegation_business(root: &Path) -> Result<()> {
    build_delegation_recipe(
        root,
        "build-delegation-business",
        "delegation-business-fixtures.json",
    )
}

fn build_delegation_recipe(root: &Path, recipe: &str, output: &str) -> Result<()> {
    let runner = workflows::build(root)?;
    let mut fixtures = BTreeMap::new();
    day2::automation::run(&runner, &[recipe], |request| {
        ensure!(
            request.action == "verify-build",
            "unexpected delegation build action"
        );
        let parameters: BTreeMap<String, String> = request.decode()?;
        ensure!(parameters.len() == 1, "invalid delegation build parameter");
        let fixture = parameters.get("fixture").context("missing fixture")?;
        let artifact = build_fixture(root, fixture, &fixtures)?;
        println!("{fixture} artifact: {}", artifact.display());
        fixtures.insert(fixture.clone(), artifact.clone());
        Ok(json!({"artifact":artifact}))
    })?;
    fs::write(
        root.join("artifacts").join(output),
        serde_json::to_vec_pretty(&fixtures)?,
    )?;
    Ok(())
}

fn recipe_scope(recipe: &str) -> Result<&'static str> {
    match recipe {
        "verify-fast" => Ok("fast"),
        "verify-reports" => Ok("reports"),
        "verify" => Ok("all"),
        "control-verify" => Ok("control"),
        _ => bail!("unknown verification recipe: {recipe}"),
    }
}

fn verification_snapshot(root: &Path, recipe: &str) -> Result<String> {
    let mut hashes = build_native::platform_sources(root)?;
    let mut sources = vec![
        ("sdk", root.join("sdk")),
        ("cli", root.join("cli")),
        ("fixtures", root.join("fixtures")),
        ("infra-config", root.join("infra")),
        ("apps/app-ownership", root.join("examples/app-ownership")),
        ("apps/notifications", root.join("examples/notifications")),
    ];
    if ["verify-fast", "verify-reports", "verify"].contains(&recipe) {
        sources.push(("apps/reports", root.join("examples/reports")));
    }
    for (label, directory) in sources {
        hash_verification_tree(&directory, &directory, label, &mut hashes)?;
    }
    Ok(digest(&serde_json::to_vec(&json!({
        "recipe":recipe,
        "host":std::env::consts::OS,
        "architecture":std::env::consts::ARCH,
        "sources":hashes,
    }))?))
}

fn hash_verification_tree(
    base: &Path,
    directory: &Path,
    label: &str,
    hashes: &mut BTreeMap<String, String>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        ensure!(!file_type.is_symlink(), "verification source symlink");
        let path = entry.path();
        let relative = path.strip_prefix(base)?;
        if file_type.is_dir() {
            if [".git", ".cache", "target"].contains(
                &entry
                    .file_name()
                    .to_str()
                    .context("verification source filename")?,
            ) {
                continue;
            }
            hash_verification_tree(base, &path, label, hashes)?;
            continue;
        }
        ensure!(file_type.is_file(), "verification source special file");
        if !verification_source_file(label, relative) {
            continue;
        }
        hashes.insert(
            format!("{label}/{}", relative.to_string_lossy()),
            digest(&fs::read(path)?),
        );
    }
    Ok(())
}

fn verification_source_file(label: &str, relative: &Path) -> bool {
    let extension = relative.extension().and_then(|value| value.to_str());
    if label == "cli" {
        return ["roc", "rs", "toml"].contains(&extension.unwrap_or(""))
            || relative.file_name().and_then(|name| name.to_str()) == Some("help.txt")
            || relative.starts_with("checks/compile-fail") && extension == Some("txt")
            || relative.starts_with("fixtures") && extension == Some("json");
    }
    let resource = relative
        .components()
        .any(|part| ["assets", "ui"].contains(&part.as_os_str().to_str().unwrap_or("")));
    resource
        || (extension != Some("md")
            && relative.file_name().and_then(|name| name.to_str()) != Some(".DS_Store"))
}

fn ensure_stable(root: &Path, recipe: &str, expected: &str) -> Result<()> {
    ensure!(
        verification_snapshot(root, recipe)? == expected,
        "verification inputs changed; rerun from one stable snapshot"
    );
    Ok(())
}

fn cache_path(root: &Path, scope: &str) -> PathBuf {
    root.join(format!("artifacts/{scope}-verification-cache.json"))
}

fn load_cache(root: &Path, scope: &str, snapshot: &str) -> Result<VerificationCache> {
    let path = cache_path(root, scope);
    let Ok(bytes) = fs::read(&path) else {
        return Ok(VerificationCache::empty(scope, snapshot));
    };
    let cache: VerificationCache = match day2::json::decode(&bytes) {
        Ok(cache) => cache,
        Err(error) => {
            eprintln!(
                "Ignoring invalid verification cache {}: {error:#}",
                path.display()
            );
            return Ok(VerificationCache::empty(scope, snapshot));
        }
    };
    if cache.format != CACHE_FORMAT || cache.scope != scope || cache.snapshot != snapshot {
        return Ok(VerificationCache::empty(scope, snapshot));
    }
    Ok(cache)
}

fn save_cache(root: &Path, cache: &VerificationCache) -> Result<()> {
    let directory = root.join("artifacts");
    fs::create_dir_all(&directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&serde_json::to_vec_pretty(cache)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(cache_path(root, &cache.scope))?;
    Ok(())
}

fn cached_fixture(root: &Path, artifact: &str) -> Result<Option<PathBuf>> {
    let directory = root
        .join("artifacts")
        .join(artifact.trim_start_matches("sha256:"));
    if !directory.exists() {
        return Ok(None);
    }
    let loaded = day2::artifact::LoadedArtifact::load(&directory)?;
    ensure!(loaded.id() == artifact, "cached artifact identity changed");
    let evidence: serde_json::Value =
        day2::json::decode(&fs::read(directory.join("verification.json"))?)?;
    ensure!(
        evidence["artifact"] == loaded.id()
            && evidence["verification_complete"] == true
            && evidence["failure"].is_null(),
        "cached artifact has incomplete verification evidence"
    );
    Ok(Some(directory))
}

pub(super) fn linux_delegation_tests(root: &Path) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "native Linux test host required");
    let mut fixtures = BTreeMap::new();
    for (fixture, variable) in [
        ("delegation", "DAY2_TEST_DELEGATION_ARTIFACT"),
        ("delegation-peer", "DAY2_TEST_DELEGATION_PEER_ARTIFACT"),
        ("request-desk", "DAY2_TEST_REQUEST_DESK_ARTIFACT"),
        ("app-ownership", "DAY2_TEST_APP_OWNERSHIP_ARTIFACT"),
        ("notifications", "DAY2_TEST_NOTIFICATIONS_ARTIFACT"),
        ("stock-ledger", "DAY2_TEST_STOCK_LEDGER_ARTIFACT"),
    ] {
        let path = PathBuf::from(std::env::var_os(variable).context(variable)?);
        let artifact = day2::artifact::LoadedArtifact::load(&path)?;
        artifact.require_current_api()?;
        fixtures.insert(fixture.to_owned(), artifact.directory().to_owned());
    }
    tests(
        root,
        "linux-delegation",
        &fixtures,
        std::time::Duration::from_secs(1800),
    )
}

pub(super) fn linux_tests(root: &Path, suite: &str, artifact: &Path, probe: &Path) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "native Linux test host required");
    ensure!(
        ["sandbox", "worker", "http", "backup"].contains(&suite),
        "unknown Linux qualification suite"
    );
    let artifact = day2::artifact::LoadedArtifact::load(artifact)
        .context("native Reports artifact required for Linux qualification")?;
    let probe = day2::artifact::LoadedArtifact::load(probe)
        .context("native Reports probe artifact required for Linux qualification")?;
    artifact.require_current_api()?;
    probe.require_current_api()?;
    let fixtures = BTreeMap::from([
        ("reports".to_owned(), artifact.directory().to_owned()),
        ("reports-probe".to_owned(), probe.directory().to_owned()),
    ]);
    tests(
        root,
        &format!("linux-{suite}"),
        &fixtures,
        std::time::Duration::from_secs(1800),
    )
}

fn tests(
    root: &Path,
    suite: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    budget: std::time::Duration,
) -> Result<()> {
    let arguments: &[&str] = match suite {
        "libraries" | "fast-libraries" => &["--workspace", "--exclude", "day2-roc-worker", "--lib"],
        "linux-sandbox" => &["-p", "day2-sandbox", "--test", "isolation"],
        "linux-worker" => &["-p", "day2", "--test", "linux_worker"],
        "linux-delegation" => &["-p", "day2-control", "--test", "release_execution"],
        "linux-http" => &[
            "-p",
            "day2",
            "--test",
            "reports_http",
            "--test",
            "command_recovery",
        ],
        // Matches the online backup/restore test and the runtime image's
        // day2-backup CLI test; a renamed test drops out of this filter.
        "linux-backup" => &["-p", "day2-ops", "--test", "reports", "online_backup_"],
        "xtask" => &["-p", "xtask", "--bin", "xtask"],
        "operations" => &[
            "-p",
            "day2-ops",
            "--test",
            "reports",
            "--test",
            "local_dev",
            "--test",
            "backup_scale",
        ],
        "reports-runtime" => &[
            "-p",
            "day2",
            "--test",
            "admission",
            "--test",
            "assets",
            "--test",
            "authority",
            "--test",
            "instance_capabilities",
            "--test",
            "linux_worker",
            "--test",
            "numeric",
            "--test",
            "output_schema",
            "--test",
            "page_sdk",
            "--test",
            "pagination",
            "--test",
            "templates",
            "--test",
            "template_routes",
            "--test",
            "web_resources",
            "--test",
            "artifact_hardening",
            "--test",
            "app_contract",
            "--test",
            "owned_runtime",
            "--test",
            "owned_web",
            "--test",
            "app_inference",
            "--test",
            "operation_catalog",
            "--test",
            "api_docs",
            "--test",
            "routing",
            "--test",
            "command_atomicity",
            "--test",
            "command_adversarial",
            "--test",
            "command_recovery",
            "--test",
            "command_simulation",
            "--test",
            "migration_commands",
            "--test",
            "reports_http",
            "--test",
            "live_updates",
        ],
        "all-runtime" => &[
            "-p",
            "day2",
            "-p",
            "xtask",
            "-p",
            "day2-ops",
            "-p",
            "day2-cli-checks",
        ],
        // The full gate used to invoke this package set as separate
        // `all-runtime` and `control` campaigns. Keeping it in one Cargo
        // invocation preserves the tests and serial execution policy while
        // avoiding a second, differently resolved compile/link graph.
        "workspace-runtime" => &[
            "-p",
            "day2",
            "-p",
            "xtask",
            "-p",
            "day2-ops",
            "-p",
            "day2-cli-checks",
            "-p",
            "day2-control",
            "-p",
            "day2-capabilities",
            "-p",
            "day2-kernel",
            "-p",
            "durable-temporal",
        ],
        // Select the same package graph as `workspace-runtime`, but execute the
        // two independently isolated integration binaries with bounded
        // intra-binary parallelism. Matching the package graph lets Cargo reuse
        // the already-linked test executables.
        "parallel-runtime" => &[
            "-p",
            "day2",
            "-p",
            "xtask",
            "-p",
            "day2-ops",
            "-p",
            "day2-cli-checks",
            "-p",
            "day2-control",
            "-p",
            "day2-capabilities",
            "-p",
            "day2-kernel",
            "-p",
            "durable-temporal",
            "--test",
            "app_inference",
        ],
        "control" => &[
            "-p",
            "day2-control",
            "-p",
            "day2-capabilities",
            "-p",
            "day2-kernel",
            "-p",
            "durable-temporal",
        ],
        "isolated-build" => &[
            "-p",
            "day2-control",
            "--test",
            "build",
            "real_isolated_owned_links_build_produces_bound_evidence_and_recovers_receipt",
        ],
        "installation-build" => &[
            "-p",
            "day2-control",
            "--test",
            "control_service",
            "real_installation_export_build_and_temporal_completion",
        ],
        _ => bail!("unknown test suite"),
    };
    #[cfg(target_os = "linux")]
    prepare_linux_test_installation(root)?;
    let mut command = Command::new("cargo");
    command.args(["test", "--locked"]).args(arguments).arg("--");
    if ["isolated-build", "installation-build"].contains(&suite) {
        let rust = Command::new("rustc")
            .args(["--print", "sysroot"])
            .current_dir(root)
            .output()?;
        ensure!(rust.status.success(), "resolve pinned Rust sysroot");
        let rust = PathBuf::from(String::from_utf8(rust.stdout)?.trim());
        let cargo_cache = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
            .context("Cargo cache required")?;
        command
            .args(["--ignored", "--exact"])
            .env("DAY2_TEST_BUILD_XTASK", std::env::current_exe()?)
            .env("DAY2_TEST_BUILD_RUST", rust)
            .env("DAY2_TEST_BUILD_REGISTRY", cargo_cache.join("registry"));
    }
    command
        .arg(if suite == "parallel-runtime" {
            "--test-threads=4"
        } else {
            "--test-threads=1"
        })
        .env("DAY2_TEST_TOFU_CONFIG", root.join(".cache/tofu.json"));
    if suite == "workspace-runtime" {
        // These cases run in the explicitly bounded parallel campaign. Exact
        // names make this coverage-safe: a renamed or new test stops matching
        // here and therefore still runs in the serial workspace campaign.
        for test in [
            "ordinary_reports_requires_its_complete_root_in_both_profiles",
            "separate_internal_commands_infer_independent_nominal_types_and_require_complete_definitions",
            "a_structural_request_alias_is_rejected_during_codec_binding",
            "resource_handles_and_issuance_context_cannot_be_forged_or_broadened",
            "omissions_stale_references_and_forged_factories_fail_compilation",
        ] {
            command.args(["--skip", test]);
        }
    }
    if suite == "fast-libraries" {
        command.args([
            "--skip",
            "delegation::delegation_capability_tests::the_grant_decides_what_may_be_called_and_the_request_decides_who_calls_it",
            "--skip",
            "tests::reports_discovery_accepts_current_contract_and_hides_internal_commands",
        ]);
    }
    // Native issuance cases require the credential fixture. They run in the
    // full workspace campaign with its artifact, while metadata-free fast and
    // Reports campaigns do not claim that coverage. Exact names preserve the
    // full gate and make new/renamed cases fail rather than silently disappear.
    if !fixtures.contains_key("credential-metadata") {
        for test in [
            "managed_credentials::issuance::tests::native_issuance_rolls_back_and_recovers_the_same_public_receipt",
            "managed_credentials::issuance::tests::personal_issuance_uses_the_confirmed_subject_and_missing_readiness_denies",
            "managed_credentials::issuance::tests::hostile_issue_rejects_changed_label_family_principal_and_second_mutation",
            "managed_credentials::issuance::tests::expired_confirmation_prevents_issuance_but_completed_receipt_is_recoverable",
            "managed_credentials::issuance::tests::native_lifecycle_is_atomic_terminal_and_recovers_after_reopen",
            "managed_credentials::issuance::tests::native_lifecycle_rejects_changed_target_and_personal_subject",
            "oauth::security_shell::tests::credential_browser_issues_native_product_commands_and_protects_delivery",
            "oauth::security_shell::tests::credential_browser_rotates_revokes_and_fences_accepted_work",
            "oauth::security_shell::tests::credential_api_admits_only_current_tokens_and_rechecks_durable_execution",
            "oauth::security_shell::tests::credential_browser_requires_fresh_auth_and_current_readiness",
            "oauth::security_shell::tests::credential_app_navigation_only_freezes_canonical_intent",
        ] {
            command.args(["--skip", test]);
        }
    }
    for (fixture, variable) in [
        ("reports", "DAY2_TEST_REPORTS_ARTIFACT"),
        ("reports", "DAY2_TEST_REPORTS_API_ARTIFACT"),
        ("reports-probe", "DAY2_TEST_REPORTS_PROBE_ARTIFACT"),
        ("relational", "DAY2_TEST_RELATIONAL_ARTIFACT"),
        ("collection", "DAY2_TEST_COLLECTION_ARTIFACT"),
        ("delegation", "DAY2_TEST_DELEGATION_ARTIFACT"),
        (
            "credential-metadata",
            "DAY2_TEST_CREDENTIAL_METADATA_ARTIFACT",
        ),
        ("delegation-peer", "DAY2_TEST_DELEGATION_PEER_ARTIFACT"),
        ("stock-ledger", "DAY2_TEST_STOCK_LEDGER_ARTIFACT"),
        ("request-desk", "DAY2_TEST_REQUEST_DESK_ARTIFACT"),
        ("redirect", "DAY2_TEST_REDIRECT_ARTIFACT"),
        ("app-ownership", "DAY2_TEST_APP_OWNERSHIP_ARTIFACT"),
        ("notifications", "DAY2_TEST_NOTIFICATIONS_ARTIFACT"),
        (
            "connection-declaration",
            "DAY2_TEST_CONNECTION_DECLARATION_ARTIFACT",
        ),
        ("oauth-calendar", "DAY2_TEST_OAUTH_CALENDAR_ARTIFACT"),
        ("relational-next", "DAY2_TEST_RELATIONAL_NEXT_ARTIFACT"),
        ("http", "DAY2_TEST_HTTP_ARTIFACT"),
        ("owned", "DAY2_TEST_OWNED_ARTIFACT"),
        ("owned-probe", "DAY2_TEST_OWNED_PROBE_ARTIFACT"),
        ("repeated-field", "DAY2_TEST_REPEATED_FIELD_ARTIFACT"),
    ] {
        command.env_remove(variable);
        if let Some(path) = fixtures.get(fixture) {
            command.env(variable, path);
        }
    }
    run_with_budget(root, &mut command, budget)
}

/// Cargo places integration tests in `deps`, while normal executables live one
/// directory above it. Install the freshly built trusted launchers beside the
/// test supervisors so tests use the same fixed-sibling lookup as deployment.
/// Production worker lookup and confinement are unchanged.
#[cfg(target_os = "linux")]
fn prepare_linux_test_installation(root: &Path) -> Result<()> {
    let output = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "-p",
            "day2-sandbox",
            "--bins",
            "--message-format=json",
        ])
        .current_dir(root)
        .stderr(std::process::Stdio::inherit())
        .output()?;
    ensure!(output.status.success(), "build Linux test launchers");
    let mut installed = BTreeSet::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let artifact: serde_json::Value = serde_json::from_slice(line)?;
        if artifact["reason"] != "compiler-artifact" {
            continue;
        }
        let Some(name @ ("day2-sandbox" | "day2-sandbox-probe")) =
            artifact["target"]["name"].as_str()
        else {
            continue;
        };
        let executable = Path::new(
            artifact["executable"]
                .as_str()
                .context("Linux test launcher executable missing")?,
        );
        let directory = executable
            .parent()
            .context("Linux test launcher directory")?
            .join("deps");
        ensure!(
            fs::symlink_metadata(&directory)?.file_type().is_dir(),
            "regular Cargo test directory required"
        );
        install_cli_file(executable, directory.join(name))?;
        ensure!(
            installed.insert(name.to_owned()),
            "duplicate Linux test launcher"
        );
    }
    ensure!(
        installed.len() == 2,
        "complete Linux test installation required"
    );
    Ok(())
}

fn receipt(
    root: &Path,
    scope: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    passed: &BTreeSet<String>,
    snapshot: &str,
    timings_ms: &BTreeMap<String, u64>,
    total_ms: u64,
) -> Result<()> {
    let required = required_steps(scope)?;
    ensure!(
        required.iter().all(|step| passed.contains(*step)),
        "incomplete verification receipt"
    );
    let artifact = |name: &str| -> Result<PathBuf> {
        fixtures
            .get(name)
            .cloned()
            .with_context(|| format!("missing verified fixture: {name}"))
    };
    if scope == "all" {
        let web = artifact("http")?;
        let redirect = artifact("redirect")?;
        let credential_metadata = artifact("credential-metadata")?;
        let connection_declaration = artifact("connection-declaration")?;
        let oauth_calendar = artifact("oauth-calendar")?;
        let app_ownership = artifact("app-ownership")?;
        let notifications = artifact("notifications")?;
        let baseline = artifact("relational")?;
        let collection = artifact("collection")?;
        let next = artifact("relational-next")?;
        let owned = artifact("owned")?;
        let owned_probe = artifact("owned-probe")?;
        let reports = artifact("reports")?;
        let reports_probe = artifact("reports-probe")?;
        let repeated_field = artifact("repeated-field")?;
        let artifact_id =
            |path: &Path| format!("sha256:{}", path.file_name().unwrap().to_string_lossy());
        let mut report = serde_json::json!({
            "status":"passed", "scope":"all", "workflow":day2::automation::source_digest(),
            "relational":artifact_id(&baseline), "relational_next":artifact_id(&next), "http":artifact_id(&web),
            "redirect":artifact_id(&redirect),
            "credential_metadata":artifact_id(&credential_metadata),
            "connection_declaration":artifact_id(&connection_declaration),
            "oauth_calendar":artifact_id(&oauth_calendar),
            "app_ownership":artifact_id(&app_ownership), "notifications":artifact_id(&notifications),
            "collection":artifact_id(&collection),
            "owned":artifact_id(&owned), "owned_probe":artifact_id(&owned_probe),
            "reports":artifact_id(&reports), "reports_probe":artifact_id(&reports_probe),
            "reports_api_contract":artifact_id(&reports),
            "operations":{"protocol":1,"cli":"platform/cli","examples_and_generators":"Reports, native command execution and independent statistics","backup_restore":"online SQLite snapshot and isolated restore","infra":"Roc graph -> OpenTofu JSON; real pinned terraform_data plan","source_ingress":"authenticated GitHub event adapter, durable exact-SHA delivery deduplication"},
            "host":std::env::consts::OS, "architecture":std::env::consts::ARCH,
            "completed_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            "proptest":{"seed":0xDA72_2026u64,"cases":24,"schedule_length":"4..12","max_shrink_iters":4096},
            "coverage":["real SQLite","native Roc execution","crash recovery","rollback at each write","decision replay","state-machine reference","app-owned invariant checks","property failure replay","nominal reference guards","generated indexed queries","domain input and row codecs","additive migration","compiler guards","runtime capability canaries","real HTTP MPA and Datastar","signed idempotent forms","web authorization and CSRF","atomic redacted audit changes","compiler-derived output contracts","HTML template admission and escaping","pinned no-npm browser resources","explicit typed routes","shared URL roundtrips and conflict rejection","checked template navigation","typed page registration and defaults","registered-query page dispatch and exact input/output handles","dual-profile generated-factory admission","required instance operation policies","owner-scoped reads and immutable ownership","host-enforced update fields and text constraints","pre-handler edit version guards","policy-bound cached receipts","owned-edit native forms and Datastar conflicts","adversarial Roc effects and partial-write rollback"],
            "admission":"local-spike-only",
            "contract_hardening": {
                "artifact_format":day2::artifact::CURRENT_FORMAT,
                "registry":"compiler-derived exact command/query handler records",
                "context":"opaque; transport and generated factories sealed by admission",
                "pagination":{"items_per_page":day2::output_schema::MAX_PAGE_ITEMS,"aggregate_output_items":day2::output_schema::MAX_TOTAL_COLLECTION_ITEMS,"bare_list_outputs":"rejected"},
                "selection":{"find":"zero-or-one visible row; ambiguous matches rejected","predicates":"typed equality, LIKE, AND and OR; SQL before limits","ordering":"declared fields with stable ID tie-breaker"},
                "uniqueness":{"schema":"single and compound keys","writes":"atomic SQLite enforcement on insert and update","migration":"additive, transactional and duplicate-rejecting"},
                "backup":"complete copied-state structural validation independent of the bounded app-property snapshot; reviewed local provider stores retained; cross-store coherence requires quiesced managed work",
                "audit":"mandatory redacted receipts, mutation changes and lifecycle events; app-owner-only filtered platform APIs; operation-granted app history observation; append-only and replacement guards",
                "model_retirement":"explicit identity-ledger retirement preserves historical tables and audit, freezes archived rows and applies transactionally",
                "definition_order_lint":"not implemented; pinned compiler metadata is insufficient"
            },
            "control_plane": {
                "status":"passed", "temporal_sdk":"1.0.0", "temporal_cli":"1.6.1",
                "source":"GitHub HTTP conformance fixtures, no live writes",
                "secrets":"GCP numeric-version and CRC32C HTTP conformance fixtures",
                "durability":"real persisted local Temporal server restart and replay",
                "build":"real isolated macOS row-authority conformance build and receipt recovery",
                "property_seed":0xDA72_C101u64, "property_cases":48,
                "scope":"local capability foundation; not hosted CI, production admission or full fleet parity"
            },
        });
        let report = report
            .as_object_mut()
            .context("verification receipt object")?;
        report.insert(
            "repeated_field".into(),
            serde_json::Value::String(artifact_id(&repeated_field)),
        );
        report.insert(
            "input_snapshot".into(),
            serde_json::Value::String(snapshot.into()),
        );
        report.insert(
            "timings_ms".into(),
            json!({"steps":timings_ms,"total":total_ms}),
        );
        fs::write(
            root.join("artifacts/verification.json"),
            serde_json::to_vec_pretty(&report)?,
        )?;
        fs::write(
            root.join("artifacts/current.json"),
            serde_json::to_vec_pretty(&serde_json::json!({"artifact":artifact_id(&reports)}))?,
        )?;
    } else {
        let report = json!({
            "status":"passed", "scope":scope,"workflow":day2::automation::source_digest(),
            "reports":fixtures.get("reports").map(|path| format!("sha256:{}", path.file_name().unwrap().to_string_lossy())),
            "probe":fixtures.get("reports-probe").map(|path| format!("sha256:{}", path.file_name().unwrap().to_string_lossy())),
            "api_contract":fixtures.get("reports").map(|path| format!("sha256:{}", path.file_name().unwrap().to_string_lossy())),
            "effects":passed,"cli_protocol":1,"tofu":"1.11.5, built-in terraform_data only",
            "host":std::env::consts::OS,"architecture":std::env::consts::ARCH,
            "input_snapshot":snapshot,
            "timings_ms":{"steps":timings_ms,"total":total_ms},
            "completed_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
        });
        fs::write(
            root.join(format!("artifacts/{scope}-verification.json")),
            serde_json::to_vec_pretty(&report)?,
        )?;
    }
    Ok(())
}

fn required_steps(scope: &str) -> Result<&'static [&'static str]> {
    Ok(match scope {
        "fast" => &["format-all", "lint", "test-fast-libraries"],
        "control" => &[
            "control-simulation",
            "test-control",
            "test-isolated-build",
            "test-installation-build",
        ],
        "reports" => &[
            "control-simulation",
            "format-reports",
            "lint",
            "cli",
            "build-reports",
            "build-reports-probe",
            "build-owned",
            "build-owned-probe",
            "build-repeated-field",
            "test-libraries",
            "test-xtask",
            "test-operations",
            "test-reports-runtime",
            "test-control",
            "test-isolated-build",
            "test-installation-build",
        ],
        "all" => &[
            "control-simulation",
            "format-all",
            "lint",
            "cli",
            "test-workspace-runtime",
            "test-parallel-runtime",
            "build-reports",
            "build-reports-probe",
            "build-owned",
            "build-owned-probe",
            "build-repeated-field",
            "build-http",
            "build-delegation",
            "build-credential-metadata",
            "build-connection-declaration",
            "build-oauth-calendar",
            "build-delegation-peer",
            "build-stock-ledger",
            "build-request-desk",
            "build-app-ownership",
            "build-notifications",
            "build-redirect",
            "build-relational",
            "build-collection",
            "build-relational-next",
            "test-isolated-build",
            "test-installation-build",
        ],
        _ => bail!("unknown receipt scope"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_campaign_budget_defaults_and_aggregate_override_are_bounded() -> Result<()> {
        for suite in [
            "all-runtime",
            "workspace-runtime",
            "parallel-runtime",
            "libraries",
            "control",
            "reports-runtime",
            "isolated-build",
            "installation-build",
        ] {
            let campaign: TestCampaign = serde_json::from_value(json!({"suite":suite}))?;
            assert_eq!(campaign.budget()?.as_secs(), 600);
        }
        for (suite, seconds) in [
            ("all-runtime", 3600),
            ("all-runtime", 9000),
            ("workspace-runtime", 12600),
            ("control", 3600),
            ("libraries", 600),
            ("control", 1),
            ("isolated-build", 1),
            ("isolated-build", 1800),
            ("installation-build", 1),
            ("installation-build", 1800),
        ] {
            let campaign: TestCampaign =
                serde_json::from_value(json!({"suite":suite,"budget_seconds":seconds}))?;
            assert_eq!(campaign.budget()?.as_secs(), seconds);
        }
        for (suite, seconds) in [
            ("all-runtime", 0),
            ("all-runtime", 9001),
            ("all-runtime", u64::MAX),
            ("workspace-runtime", 0),
            ("workspace-runtime", 12601),
            ("workspace-runtime", u64::MAX),
            ("libraries", 0),
            ("libraries", 601),
            ("control", 0),
            ("control", 3601),
            ("control", u64::MAX),
            ("reports-runtime", 2400),
            ("isolated-build", 0),
            ("isolated-build", 1801),
            ("isolated-build", u64::MAX),
            ("installation-build", 0),
            ("installation-build", 1801),
            ("installation-build", u64::MAX),
        ] {
            let campaign: TestCampaign =
                serde_json::from_value(json!({"suite":suite,"budget_seconds":seconds}))?;
            assert!(campaign.budget().is_err(), "{suite}: {seconds}");
        }
        Ok(())
    }

    #[test]
    fn test_campaign_arguments_require_numeric_budget_and_exact_fields() {
        for input in [
            r#"{"suite":"all-runtime","budget_seconds":"2400"}"#,
            r#"{"suite":"all-runtime","budget_seconds":null}"#,
            r#"{"suite":"all-runtime","budget_seconds":2400.0}"#,
            r#"{"suite":"all-runtime","budget_seconds":-1}"#,
            r#"{"suite":"all-runtime","budget_seconds":true}"#,
            r#"{"suite":"all-runtime","budget_seconds":600,"budget_seconds":2400}"#,
            r#"{"suite":"all-runtime","budget_seconds":2400,"args":[]}"#,
            r#"{"budget_seconds":2400}"#,
        ] {
            assert!(
                serde_json::from_str::<TestCampaign>(input).is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn full_receipt_requires_each_conformance_build_and_all_runtime_tests() -> Result<()> {
        let required = required_steps("all")?;
        for obligation in [
            "build-delegation",
            "build-credential-metadata",
            "build-connection-declaration",
            "build-oauth-calendar",
            "build-redirect",
            "build-relational",
            "build-collection",
            "build-relational-next",
            "build-http",
            "build-reports-probe",
            "build-owned-probe",
            "build-repeated-field",
            "test-workspace-runtime",
            "test-parallel-runtime",
        ] {
            assert!(required.contains(&obligation));
        }
        for omitted in required {
            let directory = tempfile::tempdir()?;
            let passed = required
                .iter()
                .filter(|step| *step != omitted)
                .map(|step| (*step).into())
                .collect();
            let error = receipt(
                directory.path(),
                "all",
                &BTreeMap::new(),
                &passed,
                "snapshot",
                &BTreeMap::new(),
                0,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("incomplete verification receipt"),
                "{omitted}: {error}"
            );
            assert!(
                !directory
                    .path()
                    .join("artifacts/verification.json")
                    .exists()
            );
        }
        Ok(())
    }

    #[test]
    fn passing_step_names_without_built_artifacts_cannot_issue_a_receipt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let passed = required_steps("all")?
            .iter()
            .map(|step| (*step).into())
            .collect();
        let error = receipt(
            directory.path(),
            "all",
            &BTreeMap::new(),
            &passed,
            "snapshot",
            &BTreeMap::new(),
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("missing verified fixture"));
        assert!(
            !directory
                .path()
                .join("artifacts/verification.json")
                .exists()
        );
        Ok(())
    }

    #[test]
    fn full_receipt_requires_and_pins_the_redirect_artifact() -> Result<()> {
        let directory = tempfile::tempdir()?;
        fs::create_dir_all(directory.path().join("artifacts"))?;
        let required = required_steps("all")?;
        let passed = required.iter().map(|step| (*step).into()).collect();
        let mut fixtures: BTreeMap<String, PathBuf> = required
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                step.strip_prefix("build-")
                    .map(|name| (name.into(), PathBuf::from(format!("{index:064x}"))))
            })
            .collect();
        let redirect = "d".repeat(64);
        fixtures.insert("redirect".into(), PathBuf::from(&redirect));
        let mut missing = fixtures.clone();
        missing.remove("redirect");
        let error = receipt(
            directory.path(),
            "all",
            &missing,
            &passed,
            "snapshot",
            &BTreeMap::new(),
            0,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "missing verified fixture: redirect");
        let path = directory.path().join("artifacts/verification.json");
        assert!(!path.exists());
        receipt(
            directory.path(),
            "all",
            &fixtures,
            &passed,
            "snapshot",
            &BTreeMap::new(),
            0,
        )?;
        let report: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        assert_eq!(report["redirect"], format!("sha256:{redirect}"));
        Ok(())
    }

    #[test]
    fn fast_receipt_requires_only_the_short_feedback_gate() -> Result<()> {
        assert_eq!(
            required_steps("fast")?,
            &["format-all", "lint", "test-fast-libraries"]
        );
        let directory = tempfile::tempdir()?;
        fs::create_dir(directory.path().join("artifacts"))?;
        let passed = required_steps("fast")?
            .iter()
            .map(|step| (*step).into())
            .collect();
        let timings = BTreeMap::from([
            ("format-all".into(), 11),
            ("lint".into(), 22),
            ("test-fast-libraries".into(), 33),
        ]);
        receipt(
            directory.path(),
            "fast",
            &BTreeMap::new(),
            &passed,
            "snapshot",
            &timings,
            66,
        )?;
        let report: serde_json::Value = day2::json::decode(&fs::read(
            directory.path().join("artifacts/fast-verification.json"),
        )?)?;
        assert_eq!(report["input_snapshot"], "snapshot");
        assert_eq!(report["timings_ms"]["total"], 66);
        assert_eq!(report["timings_ms"]["steps"]["lint"], 22);
        Ok(())
    }
}
