//! Native regression-check capabilities. Verify.roc selects fixtures, suites
//! and their order. Only passing native effects can enter a verification receipt.
use super::*;
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

mod shards;

const CACHE_FORMAT: u32 = 2;

/// Atomic setup for the hosted Linux compiler domain. The instance workflow
/// supplies the private cgroup; neither an app nor a cache may select quotas,
/// mount paths or a weaker compiler policy.
pub(super) fn linux_context(root: &Path) -> Result<()> {
    ensure!(
        std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64",
        "native Linux x86_64 CI context required"
    );
    ensure!(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"),
        "hosted CI setup only"
    );
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let memory = fs::read_to_string("/sys/fs/cgroup/memory.max")?;
    validate_linux_context(&cgroup, &memory)?;
    let root = root.canonicalize()?;
    // The generated output directory also contains this checked-in ABI seed.
    // Preserve its exact checkout bytes and permissions across the tmpfs mount;
    // fresh source checks and the reviewed generator still admit it normally.
    let abi = root.join("crates/worker/generated/roc_platform_abi.rs");
    let abi_metadata: fs::Metadata = fs::symlink_metadata(&abi)?;
    ensure!(
        abi_metadata.is_file() && abi_metadata.len() <= 1024 * 1024,
        "bounded regular checked-in worker ABI seed required"
    );
    let abi_seed = fs::read(&abi)?;
    for (relative, bytes) in [
        ("artifacts", 1024_u64 * 1024 * 1024),
        ("crates/worker/generated", 64_u64 * 1024 * 1024),
    ] {
        let path = root.join(relative);
        fs::create_dir_all(&path)?;
        ensure!(
            path.canonicalize()? == path && fs::symlink_metadata(&path)?.is_dir(),
            "CI compiler output must be a regular owned directory"
        );
        let mounts = fs::read_to_string("/proc/self/mountinfo")?;
        ensure!(
            !mounts
                .lines()
                .any(|line| line.split_whitespace().nth(4) == path.to_str()),
            "CI output mount already exists; setup must precede cache/transport restoration"
        );
        run_with_budget(
            &root,
            Command::new("/usr/bin/mount")
                .args(["-t", "tmpfs", "-o"])
                .arg(format!("rw,exec,nosuid,nodev,size={bytes}"))
                .arg("day2-ci-output")
                .arg(&path),
            Duration::from_secs(30),
        )?;
    }
    fs::write(&abi, &abi_seed)?;
    fs::set_permissions(&abi, abi_metadata.permissions())?;
    ensure!(
        fs::read(&abi)? == abi_seed,
        "worker ABI seed changed across bounded output setup"
    );
    let run = std::env::var("GITHUB_RUN_ID")?;
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT")?;
    ensure!(
        run.parse::<u64>().is_ok_and(|value| value > 0)
            && attempt.parse::<u64>().is_ok_and(|value| value > 0),
        "actual hosted context identity required"
    );
    let evidence = json!({"run":run,"attempt":attempt,"host":"linux","architecture":"x86_64",
        "workspace":root,"cgroup":cgroup,"memory_max":memory.trim(),
        "checkout_abi_seed":{"path":"crates/worker/generated/roc_platform_abi.rs",
            "digest":day2::digest(&abi_seed),"bytes":abi_seed.len()},
        "mountinfo":fs::read_to_string("/proc/self/mountinfo")?,
        "compiler_policy":"unchanged mandatory native cgroup/tmpfs/Landlock/seccomp admission"});
    fs::write(
        "/tmp/day2-ci-linux-context.json",
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!("Established private Linux compiler context; native confinement remains mandatory");
    Ok(())
}

fn validate_linux_context(cgroup: &str, memory: &str) -> Result<()> {
    ensure!(
        cgroup.trim() == "0::/",
        "private cgroup v2 namespace required"
    );
    let memory: u64 = memory
        .trim()
        .parse()
        .context("finite Linux CI memory quota required")?;
    ensure!(
        (1..=6 * 1024_u64 * 1024 * 1024).contains(&memory),
        "Linux compiler cgroup exceeds6GiB"
    );
    Ok(())
}

// Every test campaign in the full gate selects the same Cargo packages and
// targets. Only libtest filters change: selecting a narrower Cargo test target
// can disable dev-dependency features and rebuild shared dependencies.
const WORKSPACE_TEST_ARGUMENTS: &[&str] = &[
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
    "day2-assets",
    "-p",
    "day2-contracts",
    "-p",
    "day2-capabilities",
    "-p",
    "day2-kernel",
    "-p",
    "durable-temporal",
];

// These compiler probes own private staging directories and only read the
// admitted fixtures/toolchain. Add individual cases after checking their I/O;
// future tests in the same modules retain serial execution by default.
const PARALLEL_RUNTIME_TESTS: &[&str] = &[
    "app_inference::ordinary_reports_requires_its_complete_root_in_both_profiles",
    "app_inference::separate_internal_commands_infer_independent_nominal_types_and_require_complete_definitions",
    "app_inference::a_structural_request_alias_is_rejected_during_codec_binding",
    "app_inference::resource_handles_and_issuance_context_cannot_be_forged_or_broadened",
    "app_inference::omissions_stale_references_and_forged_factories_fail_compilation",
    "app_contract::native_error_cases_preserve_typed_command_query_inputs_and_singleton_authoring",
    "app_contract::native_required_all_rows_builders_preserve_typed_definitions",
    "guards::checked_compiler_rejects_wrong_models_forged_values_and_unavailable_io",
    "credential_metadata::native_compiler_preserves_family_types_and_seals_host_read_constructors",
    "connection_declarations::native_connection_declarations_require_nominal_access_and_account_policy",
    "connection_use::native_connection_use_is_nominal_and_private_in_both_profiles",
    "connection_use::native_reflected_use_cannot_enter_nested_public_codecs",
    "connection_use::native_calendar_preparation_frames_bound_escaped_and_accumulated_results",
    "numeric::native_generated_numeric_codecs_roundtrip_boundaries_and_reject_negative_values",
    "schema::native_structured_inputs_reflect_and_roundtrip_without_flattening_records",
];

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationCache {
    format: u32,
    scope: String,
    snapshot: String,
    compiler: Option<shards::BuildIdentity>,
    fixtures: BTreeMap<String, FixtureCacheEntry>,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureCacheEntry {
    artifact: String,
    snapshot: String,
}

impl VerificationCache {
    fn empty(scope: &str, snapshot: &str, compiler: Option<shards::BuildIdentity>) -> Self {
        Self {
            format: CACHE_FORMAT,
            scope: scope.into(),
            snapshot: snapshot.into(),
            compiler,
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

pub fn queue_receipt(root: &Path, recipe: &str) -> Result<()> {
    let snapshot = verification_snapshot(root, "verify")?;
    let runner = workflows::build(root)?;
    day2::automation::run(&runner, &[recipe], |request| {
        let parameters: BTreeMap<String, String> = request.decode()?;
        ensure!(
            parameters.is_empty() && request.action == recipe,
            "closed queue admission capability required"
        );
        match request.action.as_str() {
            "verify-queue-find" => shards::reuse::find(root, &snapshot),
            "verify-queue-admit" => shards::reuse::admit(root, &snapshot),
            _ => bail!("unknown queue receipt capability"),
        }
    })?;
    ensure_stable(root, "verify", &snapshot)
}

impl TestCampaign {
    fn budget(&self) -> Result<std::time::Duration> {
        let maximum = match self.suite.as_str() {
            "all-runtime" => 9000,
            "workspace-runtime" | "workspace-day2" | "workspace-control" | "workspace-other" => {
                12600
            }
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
    let snapshot = verification_snapshot(root, if scope == "all" { "verify" } else { recipe })?;
    let runner = workflows::build(root)?;
    let mut fixtures: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut passed = BTreeSet::new();
    let mut executed_binaries = BTreeSet::new();
    let mut mac_campaigns = BTreeMap::new();
    let mut simulation = None;
    let mut simulation_started = None;
    let mut timings = Timings::new();
    let mut cache = load_cache(root, scope, &snapshot)?;
    let mut prepared = if recipe.starts_with("verify-shard-") || recipe == "verify-compose" {
        let prepared = shards::load(root, &snapshot)?;
        fixtures = shards::fixtures(root, &prepared)?;
        Some(prepared)
    } else {
        None
    };
    let arguments = if let Some(part) = recipe.strip_prefix("verify-prepare-part-") {
        vec!["verify-prepare-part", part]
    } else {
        recipe
            .strip_prefix("verify-shard-")
            .map_or_else(|| vec![recipe], |shard| vec!["verify-shard", shard])
    };
    day2::automation::run(&runner, &arguments, |request| {
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
        if ["verify-tests", "verify-prebuilt-tests"].contains(&request.action.as_str()) {
            let campaign: TestCampaign = request.decode()?;
            let budget = campaign.budget()?;
            let started = Instant::now();
            if request.action == "verify-prebuilt-tests" {
                executed_binaries = shards::tests(
                    root,
                    prepared
                        .as_ref()
                        .context("prepared test binaries required")?,
                    &campaign.suite,
                    &fixtures,
                    budget,
                )?;
            } else {
                tests(root, &campaign.suite, &fixtures, budget)?;
            }
            if recipe == "verify-mac" {
                mac_campaigns.insert(campaign.suite.clone(), executed_binaries.clone());
            }
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
            "verify-test-build" => {
                ensure!(parameters.is_empty(), "test build accepts no overrides");
                shards::build(root, &snapshot)?;
                "test-binaries".into()
            }
            "verify-mac-prepared" => {
                ensure!(
                    recipe == "verify-mac" && parameters.is_empty(),
                    "closed native Mac preparation required"
                );
                prepared = Some(shards::mac::prepare(
                    root,
                    &snapshot,
                    &fixtures,
                    &passed,
                    &timings.steps_ms,
                )?);
                return Ok(json!({}));
            }
            "verify-mac-native" => {
                ensure!(
                    recipe == "verify-mac" && parameters.is_empty(),
                    "closed native Mac cases required"
                );
                shards::mac::focused(
                    root,
                    prepared.as_ref().context("Mac preparation required")?,
                    &fixtures,
                )?;
                "test-mac-native".into()
            }
            "verify-mac-receipt" => {
                ensure!(
                    recipe == "verify-mac" && parameters.is_empty(),
                    "closed native Mac receipt required"
                );
                ensure_stable(root, recipe, &snapshot)?;
                shards::mac::finish(
                    root,
                    prepared.take().context("Mac preparation required")?,
                    &passed,
                    &timings.steps_ms,
                    &mac_campaigns,
                )?;
                return Ok(json!({}));
            }
            "verify-test-docs" => {
                ensure!(parameters.is_empty(), "doc tests accept no overrides");
                run_with_budget(
                    root,
                    Command::new("cargo")
                        .args(["test", "--locked", "--doc"])
                        .args(WORKSPACE_TEST_ARGUMENTS)
                        .args(["--", "--test-threads=1"]),
                    Duration::from_secs(12600),
                )?;
                "test-docs".into()
            }
            "verify-prepared" => {
                ensure!(parameters.is_empty(), "preparation accepts no overrides");
                ensure_stable(root, recipe, &snapshot)?;
                shards::save(
                    root,
                    &snapshot,
                    &fixtures,
                    &passed,
                    &timings.steps_ms,
                    "all",
                )?;
                return Ok(json!({}));
            }
            "verify-prepared-part" => {
                let part = value("part")?;
                ensure!(
                    recipe == format!("verify-prepare-part-{part}"),
                    "preparation receipt must match the selected part"
                );
                ensure_stable(root, recipe, &snapshot)?;
                shards::save(root, &snapshot, &fixtures, &passed, &timings.steps_ms, part)?;
                return Ok(json!({}));
            }
            "verify-preparation-join" => {
                ensure!(
                    parameters.is_empty(),
                    "preparation join accepts no overrides"
                );
                ensure_stable(root, recipe, &snapshot)?;
                shards::combine(root, &snapshot)?;
                return Ok(json!({}));
            }
            "verify-shard-receipt" => {
                let shard = value("shard")?;
                ensure_stable(root, recipe, &snapshot)?;
                shards::receipt(
                    root,
                    prepared.as_ref().context("prepared tests required")?,
                    shard,
                    &passed,
                    &timings.steps_ms,
                    &executed_binaries,
                )?;
                return Ok(json!({}));
            }
            "verify-join" => {
                ensure!(parameters.is_empty(), "join accepts no overrides");
                (passed, timings.steps_ms) =
                    shards::join(root, prepared.as_ref().context("prepared tests required")?)?;
                return Ok(json!({}));
            }
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
                let build = fixture_build(root, fixture, &fixtures)?;
                let cached: Result<Option<PathBuf>> = cache
                    .fixtures
                    .get(fixture)
                    .filter(|entry| {
                        cache.compiler.is_some()
                            && reusable_fixture_snapshot(
                                build.imports.is_some(),
                                &entry.snapshot,
                                &snapshot,
                            )
                    })
                    .map_or(Ok(None), |entry| {
                        let artifact = cached_fixture(root, &entry.artifact)?;
                        if let Some(artifact) = &artifact {
                            build_native::admit_cached_fixture(
                                root,
                                &build.app,
                                build.overrides.as_deref(),
                                build.imports.as_ref(),
                                artifact,
                            )?;
                        }
                        Ok(artifact)
                    });
                let artifact = match cached {
                    Ok(Some(artifact)) => {
                        println!("Reusing verified {fixture} fixture: {}", artifact.display());
                        artifact
                    }
                    Ok(None) => build.build(root)?,
                    Err(error) => {
                        eprintln!("Ignoring invalid cached {fixture} fixture: {error:#}");
                        build.build(root)?
                    }
                };
                let loaded = day2::artifact::LoadedArtifact::load(&artifact)
                    .context("verification fixture artifact admission")?;
                cache.fixtures.insert(
                    fixture.into(),
                    FixtureCacheEntry {
                        artifact: loaded.id().to_owned(),
                        snapshot: snapshot.clone(),
                    },
                );
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

struct FixtureBuild {
    app: PathBuf,
    overrides: Option<PathBuf>,
    imports: Option<BuildImportContext>,
    _inputs: Option<tempfile::TempDir>,
}

impl FixtureBuild {
    fn plain(root: &Path, app: &str) -> Result<Self> {
        Ok(Self {
            app: root.join(app),
            overrides: None,
            imports: None,
            _inputs: None,
        })
    }

    fn overlay(root: &Path, app: &str, overrides: &str) -> Result<Self> {
        Ok(Self {
            overrides: Some(root.join(overrides)),
            ..Self::plain(root, app)?
        })
    }

    fn build(&self, root: &Path) -> Result<PathBuf> {
        build_recipe(
            root,
            &self.app,
            self.overrides.as_deref(),
            None,
            self.imports.as_ref(),
        )
    }
}

fn build_fixture(
    root: &Path,
    fixture: &str,
    fixtures: &BTreeMap<String, PathBuf>,
) -> Result<PathBuf> {
    fixture_build(root, fixture, fixtures)?.build(root)
}

fn fixture_build(
    root: &Path,
    fixture: &str,
    fixtures: &BTreeMap<String, PathBuf>,
) -> Result<FixtureBuild> {
    match fixture {
        "app-ownership" => FixtureBuild::plain(root, "examples/app-ownership"),
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
            Ok(FixtureBuild {
                app: root.join("examples/notifications"),
                overrides: None,
                imports: Some(BuildImportContext { instance, lock }),
                _inputs: Some(inputs),
            })
        }
        "stock-ledger" => FixtureBuild::plain(root, "fixtures/stock-ledger"),
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
            Ok(FixtureBuild {
                app: root.join("fixtures/request-desk"),
                overrides: None,
                imports: Some(BuildImportContext { instance, lock }),
                _inputs: Some(inputs),
            })
        }
        "reports" => FixtureBuild::plain(root, "examples/reports"),
        "reports-probe" => FixtureBuild::overlay(
            root,
            "examples/reports",
            "fixtures/command-target-adversaries",
        ),
        "http" => FixtureBuild::overlay(
            root,
            "fixtures/row-authority-web-conformance",
            "fixtures/http-conformance",
        ),
        "relational" => FixtureBuild::plain(root, "fixtures/relational-conformance"),
        "lifecycle" => FixtureBuild::plain(root, "fixtures/lifecycle-conformance"),
        "collection" => FixtureBuild::plain(root, "fixtures/collection-conformance"),
        "credential-metadata" => {
            FixtureBuild::plain(root, "fixtures/credential-metadata-conformance")
        }
        "connection-declaration" => {
            FixtureBuild::plain(root, "fixtures/connection-declaration-conformance")
        }
        "oauth-calendar" => FixtureBuild::plain(root, "fixtures/oauth-calendar-canary"),
        "oauth-gitlab" => FixtureBuild::plain(root, "fixtures/oauth-gitlab-canary"),
        "delegation-peer" => FixtureBuild::overlay(
            root,
            "fixtures/delegation-conformance",
            "fixtures/delegation-peer",
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
            Ok(FixtureBuild {
                app: root.join("fixtures/delegation-conformance"),
                overrides: None,
                imports: Some(BuildImportContext { instance, lock }),
                _inputs: Some(inputs),
            })
        }
        "redirect" => FixtureBuild::plain(root, "fixtures/redirect-conformance"),
        "relational-next" => FixtureBuild::overlay(
            root,
            "fixtures/relational-conformance",
            "fixtures/migration-add-optional-text",
        ),
        "owned" => FixtureBuild::plain(root, "fixtures/row-authority-web-conformance"),
        "repeated-field" => FixtureBuild::plain(root, "fixtures/repeated-field-conformance"),
        "owned-probe" => FixtureBuild::overlay(
            root,
            "fixtures/row-authority-web-conformance",
            "fixtures/row-authority-adversaries",
        ),
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
        "verify"
        | "verify-prepare"
        | "verify-prepare-join"
        | "verify-compose"
        | "verify-mac"
        | "verify-prepare-part-inputs"
        | "verify-prepare-part-tests" => Ok("all"),
        shard
            if shard
                .strip_prefix("verify-shard-")
                .is_some_and(shards::valid) =>
        {
            Ok("all")
        }
        "control-verify" => Ok("control"),
        _ => bail!("unknown verification recipe: {recipe}"),
    }
}

fn verification_snapshot(root: &Path, recipe: &str) -> Result<String> {
    verification_snapshot_for(root, recipe, std::env::consts::OS, std::env::consts::ARCH)
}

fn verification_source_identity(root: &Path, recipe: &str) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&verification_sources(
        root, recipe,
    )?)?))
}

fn verification_snapshot_for(
    root: &Path,
    recipe: &str,
    host: &str,
    architecture: &str,
) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({
        "recipe":recipe,
        "host":host,
        "architecture":architecture,
        "sources":verification_sources(root, recipe)?,
    }))?))
}

fn verification_sources(root: &Path, recipe: &str) -> Result<BTreeMap<String, String>> {
    let mut hashes = build_native::platform_sources(root)?;
    for pin in [
        ".github/workflows/ci.yml",
        ".github/temporal.sha256",
        ".github/temporal-linux.sha256",
    ] {
        hashes.insert(pin.into(), digest(&fs::read(root.join(pin))?));
    }
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
    Ok(hashes)
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
    let recipe = if recipe_scope(recipe)? == "all" {
        "verify"
    } else {
        recipe
    };
    ensure!(
        verification_snapshot(root, recipe)? == expected,
        "verification inputs changed; rerun from one stable snapshot"
    );
    Ok(())
}

fn cache_path(root: &Path, scope: &str) -> PathBuf {
    root.join(format!("artifacts/{scope}-verification-cache.json"))
}

fn reusable_fixture_snapshot(imports: bool, retained: &str, current: &str) -> bool {
    // Imported fixtures carry a selected peer's disposable verification oracle.
    // Keep their original whole-snapshot requirement; unrelated standalone
    // outputs are admitted independently through the ordinary source capture.
    !imports || retained == current
}

fn fixture_compiler_sources(root: &Path) -> Result<BTreeMap<String, String>> {
    let root = root.canonicalize()?;
    let mut sources = build_native::platform_sources(&root)?;
    let dependency_file = fs::read_to_string(root.join("target/debug/xtask.d"))?;
    let dependencies = compiler_dependency_paths(&dependency_file)?;
    ensure!(
        dependencies.contains(&root.join("crates/xtask/src/main.rs"))
            && dependencies.contains(&root.join("crates/day2/src/development.rs")),
        "compiler dep-info does not close the fixture adapter"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    ensure!(
        executable == root.join("target/debug/xtask").canonicalize()?,
        "ordinary fixture compiler adapter executable required"
    );
    sources.insert("compiler/xtask".into(), digest(&fs::read(executable)?));
    for path in dependencies {
        ensure!(path.is_absolute(), "absolute compiler dependency required");
        if let Ok(relative) = path.strip_prefix(&root) {
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "compiler dependency must be regular"
            );
            ensure!(
                path.canonicalize()?.starts_with(&root),
                "compiler dependency escaped workspace"
            );
            sources.insert(
                format!("compiler-inputs/{}", relative.to_string_lossy()),
                digest(&fs::read(path)?),
            );
        }
    }
    Ok(sources)
}

fn compiler_dependency_paths(contents: &str) -> Result<Vec<PathBuf>> {
    // Cargo's normal unescaped single-line dep-info is authoritative for embedded
    // non-Rust inputs too. Unsupported escaping disables reuse, never full builds.
    let line = contents
        .lines()
        .next()
        .context("compiler dep-info missing")?;
    let (target, dependencies) = line
        .split_once(": ")
        .context("compiler dep-info target missing")?;
    ensure!(
        !line.contains(['\\', '\r']) && Path::new(target).is_absolute(),
        "unsupported compiler dep-info encoding"
    );
    let paths: Vec<_> = dependencies.split_whitespace().map(PathBuf::from).collect();
    ensure!(!paths.is_empty(), "compiler dep-info dependencies missing");
    Ok(paths)
}

fn fixture_compiler_identity(root: &Path) -> Result<shards::BuildIdentity> {
    let sources = fixture_compiler_sources(root)?;
    shards::build_identity(root, &digest(&serde_json::to_vec(&sources)?))
}

fn load_cache(root: &Path, scope: &str, snapshot: &str) -> Result<VerificationCache> {
    let compiler = match fixture_compiler_identity(root) {
        Ok(identity) => Some(identity),
        Err(error) => {
            eprintln!(
                "Fixture output reuse unavailable; ordinary builds remain selected: {error:#}"
            );
            None
        }
    };
    let path = cache_path(root, scope);
    let Ok(bytes) = fs::read(&path) else {
        return Ok(VerificationCache::empty(scope, snapshot, compiler));
    };
    let mut cache: VerificationCache = match day2::json::decode(&bytes) {
        Ok(cache) => cache,
        Err(error) => {
            eprintln!(
                "Ignoring invalid verification cache {}: {error:#}",
                path.display()
            );
            return Ok(VerificationCache::empty(scope, snapshot, compiler));
        }
    };
    if cache.format != CACHE_FORMAT
        || cache.scope != scope
        || compiler.is_none()
        || cache.compiler != compiler
    {
        return Ok(VerificationCache::empty(scope, snapshot, compiler));
    }
    cache.snapshot = snapshot.into();
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
    ensure!(
        artifact.len() == 71
            && artifact.starts_with("sha256:")
            && artifact[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "cached artifact must be a canonical SHA-256 identity"
    );
    let directory = root
        .join("artifacts")
        .join(artifact.trim_start_matches("sha256:"));
    if !directory.exists() {
        return Ok(None);
    }
    let loaded = day2::artifact::LoadedArtifact::load(&directory)?;
    ensure!(loaded.id() == artifact, "cached artifact identity changed");
    let evidence: serde_json::Value =
        day2::json::decode_evidence(&fs::read(directory.join("verification.json"))?)?;
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

fn test_command(suite: &str) -> Result<Command> {
    // Each crate links its integration tests into one binary. A module filter
    // after `--` selects the tests of what used to be a separate test target.
    let (arguments, modules): (&[&str], &[&str]) = match suite {
        "libraries" => (
            &["--workspace", "--exclude", "day2-roc-worker", "--lib"],
            &[],
        ),
        // The compile-fail checks drive the Roc compiler for about a minute;
        // workspace-runtime and libraries keep them in the full gates.
        "fast-libraries" => (
            &[
                "--workspace",
                "--exclude",
                "day2-roc-worker",
                "--exclude",
                "day2-cli-checks",
                "--lib",
            ],
            &[],
        ),
        "linux-sandbox" => (&["-p", "day2-sandbox", "--test", "isolation"], &[]),
        "linux-worker" => (
            &["-p", "day2", "--test", "day2_integration"],
            &["linux_worker::"],
        ),
        "linux-delegation" => (
            &["-p", "day2-control", "--test", "control_integration"],
            &["release_execution::"],
        ),
        "linux-http" => (
            &["-p", "day2", "--test", "day2_integration"],
            &["reports_http::", "command_recovery::"],
        ),
        // Matches the online backup/restore test and the runtime image's
        // day2-backup CLI test; a renamed test drops out of this filter.
        "linux-backup" => (
            &["-p", "day2-ops", "--test", "reports", "online_backup_"],
            &[],
        ),
        "xtask" => (&["-p", "xtask", "--bin", "xtask"], &[]),
        "operations" => (
            &[
                "-p",
                "day2-ops",
                "--test",
                "reports",
                "--test",
                "local_dev",
                "--test",
                "backup_scale",
            ],
            &[],
        ),
        "reports-runtime" => (
            &["-p", "day2", "--test", "day2_integration"],
            &[
                "admission::",
                "assets::",
                "authority::",
                "instance_capabilities::",
                "linux_worker::",
                "numeric::",
                "output_schema::",
                "page_sdk::",
                "pagination::",
                "templates::",
                "template_routes::",
                "web_resources::",
                "artifact_hardening::",
                "app_contract::",
                "owned_runtime::",
                "owned_web::",
                "app_inference::",
                "operation_catalog::",
                "api_docs::",
                "routing::",
                "command_atomicity::",
                "command_adversarial::",
                "command_recovery::",
                "command_simulation::",
                "migration_commands::",
                "reports_http::",
                "live_updates::",
                // Shared helper cases the selected modules used to compile in.
                "support::",
            ],
        ),
        "all-runtime" => (
            &[
                "-p",
                "day2",
                "-p",
                "xtask",
                "-p",
                "day2-ops",
                "-p",
                "day2-cli-checks",
            ],
            &[],
        ),
        "workspace-runtime" => (&[], &[]),
        "parallel-runtime" => (&[], PARALLEL_RUNTIME_TESTS),
        "control" => (
            &[
                "-p",
                "day2-control",
                "-p",
                "day2-capabilities",
                "-p",
                "day2-kernel",
                "-p",
                "durable-temporal",
            ],
            &[],
        ),
        "isolated-build" => (
            &[],
            &[
                "build::real_isolated_owned_links_build_produces_bound_evidence_and_recovers_receipt",
            ],
        ),
        "installation-build" => (
            &[],
            &["control_service::real_installation_export_build_and_temporal_completion"],
        ),
        _ => bail!("unknown test suite"),
    };
    let mut command = Command::new("cargo");
    command.args(["test", "--locked"]);
    if [
        "workspace-runtime",
        "parallel-runtime",
        "isolated-build",
        "installation-build",
    ]
    .contains(&suite)
    {
        command.args(WORKSPACE_TEST_ARGUMENTS);
    }
    command.args(arguments).arg("--").args(modules);
    // libtest applies --exact to both inclusion and skip filters. With no
    // inclusion filters, the serial campaign still runs every other test.
    if ["workspace-runtime", "parallel-runtime"].contains(&suite) {
        command.arg("--exact");
    }
    if suite == "workspace-runtime" {
        for test in PARALLEL_RUNTIME_TESTS {
            command.args(["--skip", test]);
        }
    }
    Ok(command)
}

fn tests(
    root: &Path,
    suite: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    budget: std::time::Duration,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    prepare_linux_test_installation(root)?;
    let mut command = test_command(suite)?;
    configure_tests(root, suite, fixtures, &mut command)?;
    run_with_budget(root, &mut command, budget)
}

fn configure_tests(
    root: &Path,
    suite: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    command: &mut Command,
) -> Result<()> {
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
    // Library unit tests own their temporary state, so the fast gate uses
    // libtest's default parallelism; the reviewed probes use four threads.
    match suite {
        "parallel-runtime" => {
            command.arg("--test-threads=4");
        }
        "fast-libraries" => {}
        _ => {
            command.arg("--test-threads=1");
        }
    }
    command.env("DAY2_TEST_TOFU_CONFIG", root.join(".cache/tofu.json"));
    if suite == "fast-libraries" {
        command.args([
            "--skip",
            "delegation::delegation_capability_tests::the_grant_decides_what_may_be_called_and_the_request_decides_who_calls_it",
            "--skip",
            "tests::reports_discovery_accepts_current_contract_and_hides_internal_commands",
            // A complete simulation campaign (~48s); the full gates run it.
            "--skip",
            "simulation_campaign::tests::completed_campaign_pins_coverage_and_trace_association",
        ]);
    }
    // Native issuance cases require the credential fixture. They run in the
    // full workspace campaign with its artifact, while metadata-free fast and
    // Reports campaigns do not claim that coverage. Exact names preserve the
    // full gate and make new/renamed cases fail rather than silently disappear.
    if !fixtures.contains_key("credential-metadata") {
        for test in [
            "managed_credentials::simulation::actual_credential_http_inherits_ports_and_replays_exact_ids",
            "managed_credentials::store::tests::schema_native_runtime_initialization_reopens_with_installed_peers",
            "unsecured_restore_refuses_declared_credentials_and_oauth_before_output_mutation",
            "managed_credentials::issuance::tests::native_issuance_rolls_back_and_recovers_the_same_public_receipt",
            "managed_credentials::issuance::tests::personal_issuance_uses_the_confirmed_subject_and_missing_readiness_denies",
            "managed_credentials::issuance::tests::hostile_issue_rejects_changed_label_family_principal_and_second_mutation",
            "managed_credentials::issuance::tests::expired_confirmation_prevents_issuance_but_completed_receipt_is_recoverable",
            "managed_credentials::issuance::tests::native_lifecycle_is_atomic_terminal_and_recovers_after_reopen",
            "managed_credentials::issuance::tests::native_lifecycle_rejects_changed_target_and_personal_subject",
            "managed_credentials::issuance::tests::final_selected_role_refuses_disposable_history_including_terminal_reuse",
            "managed_credentials::issuance::tests::provider_pause_rehash_and_expiry_refuse_actual_business_commit",
            "managed_credentials::issuance::tests::captured_fence_is_required_even_without_a_lifecycle_observation",
            "managed_credentials::issuance::tests::two_real_executors_reuse_one_record_and_one_business_transition",
            "managed_credentials::issuance::tests::compiled_worker_reply_corruption_rolls_back_exact_staging_and_recovers",
            "oauth::security_shell::tests::credential_browser_issues_native_product_commands_and_protects_delivery",
            "oauth::security_shell::tests::credential_browser_rotates_revokes_and_fences_accepted_work",
            "oauth::security_shell::tests::credential_api_admits_only_current_tokens_and_rechecks_durable_execution",
            "oauth::security_shell::tests::credential_browser_requires_fresh_auth_and_current_readiness",
            "oauth::security_shell::tests::credential_signed_google_session_keeps_original_intent_across_three_roles",
            "oauth::security_shell::tests::signed_replay::signed_google_replay_two_positive_owner_histories",
            "oauth::security_shell::tests::signed_replay::signed_google_replay_six_paired_negative_owner_histories",
            "oauth::security_shell::tests::signed_replay::signed_credential_initial_commit_loss_retains_original_record_and_deadline",
            "oauth::security_shell::tests::credential_app_navigation_only_freezes_canonical_intent",
        ] {
            command.args(["--skip", test]);
        }
    }
    if !fixtures.contains_key("oauth-calendar") {
        command.args([
            "--skip",
            "oauth::usage::tests::compiled_calendar_runtime_uses_real_custody_and_fences_dispatch_and_completion",
        ]);
        command.args([
            "--skip",
            "oauth::usage::refresh_tests::compiled_calendar_refresh_publishes_versions_and_fences_failure_recovery",
        ]);
        command.args([
            "--skip",
            "oauth::usage::refresh_tests::compiled_refresh_crash_recovery_uses_sealed_dispatch_and_publication",
        ]);
    }
    if !fixtures.contains_key("oauth-calendar") && fixtures.contains_key("credential-metadata") {
        command.args([
            "--skip",
            "unsecured_restore_refuses_declared_credentials_and_oauth_before_output_mutation",
        ]);
    }
    for (fixture, variable) in [
        ("reports", "DAY2_TEST_REPORTS_ARTIFACT"),
        ("reports", "DAY2_TEST_REPORTS_API_ARTIFACT"),
        ("reports-probe", "DAY2_TEST_REPORTS_PROBE_ARTIFACT"),
        ("relational", "DAY2_TEST_RELATIONAL_ARTIFACT"),
        ("lifecycle", "DAY2_TEST_LIFECYCLE_ARTIFACT"),
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
        ("oauth-gitlab", "DAY2_TEST_OAUTH_GITLAB_ARTIFACT"),
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
    Ok(())
}

/// Cargo places integration tests in `deps`, while normal executables live one
/// directory above it. Install the freshly built trusted launchers beside the
/// test supervisors so tests use the same fixed-sibling lookup as deployment.
/// Production worker lookup and confinement are unchanged.
#[cfg(target_os = "linux")]
fn prepare_linux_test_installation(root: &Path) -> Result<()> {
    shards::prepare_linux_installation(root)
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
        let oauth_gitlab = artifact("oauth-gitlab")?;
        let app_ownership = artifact("app-ownership")?;
        let notifications = artifact("notifications")?;
        let baseline = artifact("relational")?;
        let lifecycle = artifact("lifecycle")?;
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
            "lifecycle":artifact_id(&lifecycle),
            "redirect":artifact_id(&redirect),
            "credential_metadata":artifact_id(&credential_metadata),
            "connection_declaration":artifact_id(&connection_declaration),
            "oauth_calendar":artifact_id(&oauth_calendar),
            "oauth_gitlab":artifact_id(&oauth_gitlab),
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
            json!({"steps":timings_ms,"total":total_ms,"total_scope":"elapsed on this receipt host; distributed campaign work is recorded per step"}),
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
            "timings_ms":{"steps":timings_ms,"total":total_ms,"total_scope":"elapsed on this receipt host; distributed campaign work is recorded per step"},
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
            "build-oauth-gitlab",
            "build-delegation-peer",
            "build-stock-ledger",
            "build-request-desk",
            "build-app-ownership",
            "build-notifications",
            "build-redirect",
            "build-relational",
            "build-lifecycle",
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
    fn linux_context_requires_private_finite_native_compiler_limits() -> Result<()> {
        validate_linux_context("0::/\n", "6442450944\n")?;
        for (group, memory) in [
            ("0::/host/job", "6442450944"),
            ("0::/", "max"),
            ("0::/", "0"),
            ("0::/", "6442450945"),
            ("0::/", "-1"),
        ] {
            assert!(validate_linux_context(group, memory).is_err());
        }
        Ok(())
    }

    #[test]
    fn full_gate_filters_keep_the_same_cargo_package_and_target_graph() -> Result<()> {
        let cargo_arguments = |command: &Command| {
            command
                .get_args()
                .take_while(|argument| *argument != "--")
                .map(|argument| argument.to_os_string())
                .collect::<Vec<_>>()
        };
        let expected = cargo_arguments(&test_command("workspace-runtime")?);
        assert!(expected.iter().any(|argument| argument == "day2"));
        assert!(expected.iter().any(|argument| argument == "day2-control"));
        assert!(!expected.iter().any(|argument| argument == "--test"));
        for suite in ["parallel-runtime", "isolated-build", "installation-build"] {
            let command = test_command(suite)?;
            assert_eq!(cargo_arguments(&command), expected, "{suite}");
        }
        assert!(test_command("unknown").is_err());
        Ok(())
    }

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
            ("workspace-day2", 12600),
            ("workspace-control", 12600),
            ("workspace-other", 12600),
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
            ("workspace-day2", 12601),
            ("workspace-control", 12601),
            ("workspace-other", 12601),
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
            "build-oauth-gitlab",
            "build-redirect",
            "build-relational",
            "build-lifecycle",
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
    fn full_receipt_requires_and_pins_lifecycle_and_redirect_artifacts() -> Result<()> {
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
        let lifecycle = "e".repeat(64);
        fixtures.insert("redirect".into(), PathBuf::from(&redirect));
        fixtures.insert("lifecycle".into(), PathBuf::from(&lifecycle));
        let path = directory.path().join("artifacts/verification.json");
        for name in ["redirect", "lifecycle"] {
            let mut missing = fixtures.clone();
            missing.remove(name);
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
            assert_eq!(
                error.to_string(),
                format!("missing verified fixture: {name}")
            );
            assert!(!path.exists());
        }
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
        assert_eq!(report["lifecycle"], format!("sha256:{lifecycle}"));
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

#[cfg(test)]
mod fixture_cache_tests {
    use super::*;

    #[test]
    fn imported_fixture_oracles_keep_whole_snapshot_admission() {
        assert!(reusable_fixture_snapshot(false, "old", "current"));
        assert!(reusable_fixture_snapshot(true, "current", "current"));
        assert!(!reusable_fixture_snapshot(true, "old", "current"));
    }

    #[test]
    fn compiler_dep_info_preserves_embedded_fixture_inputs_and_rejects_unknown_encoding()
    -> Result<()> {
        let paths = compiler_dependency_paths(
            "/work/platform/target/debug/xtask: /work/platform/crates/xtask/src/main.rs /work/platform/fixtures/authority-policies/reports.json\n",
        )?;
        assert!(paths.contains(&PathBuf::from(
            "/work/platform/fixtures/authority-policies/reports.json"
        )));
        for contents in [
            "",
            "missing target",
            "/xtask: ",
            "relative: /input",
            "/xtask: /escaped\\ input",
            "/xtask: /first \\\n/second",
        ] {
            assert!(compiler_dependency_paths(contents).is_err(), "{contents:?}");
        }
        Ok(())
    }

    #[test]
    fn cache_artifact_identity_cannot_select_paths_or_noncanonical_digests() -> Result<()> {
        let root = tempfile::tempdir()?;
        for artifact in [
            "../worker",
            "sha256:../worker",
            "sha256:abc",
            "worker",
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(cached_fixture(root.path(), artifact).is_err());
        }
        assert!(cached_fixture(root.path(), &digest(b"missing artifact"))?.is_none());
        Ok(())
    }
}
