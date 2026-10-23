//! The focused native Mac domain: real ABI/runtime/confinement plus the two
//! unsupported-on-Linux build campaigns. Outcomes are fresh, never cache entries.
use super::{
    BUILD_CACHE, Binary, BuildCache, BuildIdentity, Identity, Prepared, Receipt, Targets,
    admit_build_cache, build_identity, compiler_targets, configure_tests, effects, identity,
    program_output, validate_receipt,
};
use crate::run_with_budget;
use anyhow::{Context, Result, ensure};
use day2::digest;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(in super::super) const PATH: &str = "artifacts/ci-mac-compatibility.json";
const FIXTURES: &[&str] = &[
    "reports",
    "reports-probe",
    "relational",
    "oauth-calendar",
    "verification-setup",
];
const CASES: &[(&str, &str, &str, &str, bool)] = &[
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::exact_literal_protocol_accepts_every_fragmentation_width",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::each_complete_ordered_prefix_is_incomplete_not_malformed",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::every_partial_record_tail_is_truncated_at_eof",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::unknown_duplicate_and_out_of_order_streams_never_resynchronize",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::complete_seven_then_garbage_is_invalid_and_still_fully_drained",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::interrupted_read_retries_but_real_read_fault_does_not_claim_eof",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::late_invalid_or_truncated_tail_does_not_rewrite_earlier_snapshot",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestones::tests::late_valid_markers_belong_only_to_the_final_snapshot",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::collector_setup_refusal_happens_before_a_child_owner_exists",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::real_spawn_refusal_cancels_and_joins_the_preexisting_collector",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::missing_pipe_refuses_without_releasing_an_already_retained_descriptor",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::partial_construction_faults_reap_the_exact_new_child_and_join_every_created_thread",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::successful_original_frames_keep_the_same_child_alive_until_owner_close",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::failed_one_shot_handoff_keeps_the_exact_parent_descriptor_owner",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::no_child_cancellation_closes_the_one_collector_and_is_idempotent",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::only_observed_terminal_status_permits_release_not_kill_or_wait_fault",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::mac_lifetime::tests::retained_owner_survives_reader_fault_and_collector_unwind",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestone_producer::tests::literal_first_request_producer_emits_exactly_fifty_six_bytes_once",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestone_producer::tests::producer_cannot_duplicate_or_skip_to_a_later_record",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::child_milestone_producer::tests::producer_write_fault_is_best_effort_without_a_second_attempt",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "host_loop::tests::native::native_timers_skip_busy_deliveries_and_stop_awaits_real_sqlite_commits",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "host_loop::tests::native::native_shutdown_refuses_blocking_tasks_queued_behind_uninterruptible_work",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "host_loop::tests::native::native_stop_before_dispatch_and_undeclared_schedules_never_run",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "host_loop::tests::native::journal_batches_use_real_sqlite_and_keep_pending_young_and_audit_rows",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::tests::child_phase_diagnostics_keep_late_invalid_tail_separate_and_category_unchanged",
        false,
    ),
    (
        "day2",
        "day2",
        "lib",
        "worker::tests::child_diagnostic_text_has_a_fixed_bound_even_for_maximal_numeric_fields",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_inference::ordinary_reports_requires_its_complete_root_in_both_profiles",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_inference::separate_internal_commands_infer_independent_nominal_types_and_require_complete_definitions",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_inference::a_structural_request_alias_is_rejected_during_codec_binding",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_inference::resource_handles_and_issuance_context_cannot_be_forged_or_broadened",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_inference::omissions_stale_references_and_forged_factories_fail_compilation",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_contract::native_error_cases_preserve_typed_command_query_inputs_and_singleton_authoring",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "app_contract::native_required_all_rows_builders_preserve_typed_definitions",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "guards::checked_compiler_rejects_wrong_models_forged_values_and_unavailable_io",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "credential_metadata::native_compiler_preserves_family_types_and_seals_host_read_constructors",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "connection_declarations::native_connection_declarations_require_nominal_access_and_account_policy",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "connection_use::native_connection_use_is_nominal_and_private_in_both_profiles",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "connection_use::native_reflected_use_cannot_enter_nested_public_codecs",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "connection_use::native_calendar_preparation_frames_bound_escaped_and_accumulated_results",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "numeric::native_generated_numeric_codecs_roundtrip_boundaries_and_reject_negative_values",
        false,
    ),
    (
        "day2",
        "day2_integration",
        "test",
        "schema::native_structured_inputs_reflect_and_roundtrip_without_flattening_records",
        false,
    ),
    (
        "day2-control",
        "control_integration",
        "test",
        "build::a_fast_successful_process_cannot_bypass_the_log_budget_or_forge_verification",
        false,
    ),
    (
        "day2-control",
        "control_integration",
        "test",
        "build::bazel_stage_sandbox_allows_private_reads_but_denies_host_data_and_writes",
        false,
    ),
    (
        "xtask",
        "xtask",
        "bin",
        "formatting::tests::formatter_native_spacing_width_check_idempotence_and_parse_failure",
        true,
    ),
    (
        "day2",
        "day2",
        "lib",
        "sandbox::tests::selected_developer_profile_keeps_outside_file_and_network_refusals",
        false,
    ),
];
const BUILD_CASES: &[(&str, &str)] = &[
    (
        "isolated-build",
        "build::real_isolated_owned_links_build_produces_bound_evidence_and_recovers_receipt",
    ),
    (
        "installation-build",
        "control_service::real_installation_export_build_and_temporal_completion",
    ),
];

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    package: String,
    target: String,
    kind: String,
    name: String,
    ignored: bool,
    executable: PathBuf,
    status: String,
    elapsed_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    prepared: Prepared,
    compiler: BuildIdentity,
    cases: Vec<Case>,
    native_elapsed_ms: u64,
    campaigns: Vec<Receipt>,
}

fn preparation_effects() -> BTreeSet<String> {
    ["bazel-controls", "cli", "test-binaries"]
        .into_iter()
        .map(String::from)
        .chain(FIXTURES.iter().map(|fixture| format!("build-{fixture}")))
        .collect()
}

fn required_cases() -> Vec<(String, String, String, String, bool)> {
    CASES
        .iter()
        .map(|(p, t, k, n, i)| ((*p).into(), (*t).into(), (*k).into(), (*n).into(), *i))
        .collect()
}

pub(in super::super) fn prepare(
    root: &Path,
    snapshot: &str,
    fixtures: &BTreeMap<String, PathBuf>,
    passed: &BTreeSet<String>,
    timings: &BTreeMap<String, u64>,
) -> Result<Prepared> {
    ensure!(
        std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64",
        "focused compatibility requires real native Mac ARM64"
    );
    ensure!(
        *passed == preparation_effects(),
        "complete focused Mac preparation required"
    );
    let cache: BuildCache = day2::json::decode(&fs::read(root.join(BUILD_CACHE))?)?;
    let targets = compiler_targets(root)?;
    let directories = targets.members.values().cloned().collect();
    admit_build_cache(
        root,
        &cache,
        &build_identity(root, snapshot)?,
        &targets.tests,
        &targets.programs,
        &targets.auxiliaries,
        &directories,
    )?;
    Ok(Prepared {
        identity: identity(root, snapshot)?,
        binaries: cache.binaries,
        programs: cache.programs,
        auxiliaries: cache.auxiliaries,
        fixtures: fixtures
            .iter()
            .map(|(name, path)| {
                Ok((
                    name.clone(),
                    day2::artifact::LoadedArtifact::load(path)?.id().to_owned(),
                ))
            })
            .collect::<Result<_>>()?,
        passed: passed.clone(),
        timings_ms: timings.clone(),
    })
}

fn case_binary<'a>(
    prepared: &'a Prepared,
    package: &str,
    target: &str,
    kind: &str,
) -> Result<&'a Binary> {
    let matches: Vec<_> = prepared
        .binaries
        .iter()
        .filter(|b| b.package == package && b.target == target && b.kind == [kind])
        .collect();
    ensure!(
        matches.len() == 1,
        "exact focused Mac Bazel harness required: {package}/{target}"
    );
    Ok(matches[0])
}

fn list(root: &Path, binary: &Binary, name: &str, ignored: bool) -> Result<bool> {
    let file = tempfile::NamedTempFile::new()?;
    let mut command = Command::new(root.join(&binary.executable));
    command.args([name, "--exact", "--list"]);
    if ignored {
        command.arg("--ignored");
    }
    command.stdout(Stdio::from(file.reopen()?));
    run_with_budget(root, &mut command, Duration::from_secs(60))?;
    let output: &fs::File = file.as_file();
    ensure!(
        output.metadata()?.len() <= 1024 * 1024,
        "bounded libtest case inventory required"
    );
    let expected = format!("{name}: test");
    let count = fs::read_to_string(file.path())?
        .lines()
        .filter(|line| *line == expected)
        .count();
    ensure!(count <= 1, "duplicate native test case");
    Ok(count == 1)
}

fn require_case(root: &Path, binary: &Binary, name: &str, ignored: bool) -> Result<()> {
    ensure!(
        list(root, binary, name, false)? && list(root, binary, name, true)? == ignored,
        "missing or changed ignored status for native case: {name}"
    );
    Ok(())
}

pub(in super::super) fn focused(
    root: &Path,
    prepared: &Prepared,
    fixtures: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let started = Instant::now();
    // The genuine child canaries compile their fixed probe with this exact
    // configured tool; bare prebuilt launches do not inherit Bazel runfiles.
    let rustc = crate::bazel::tool(root, "rustc")?;
    let mut cases = Vec::new();
    for (package, target, kind, name, ignored) in CASES {
        let binary = case_binary(prepared, package, target, kind)?;
        require_case(root, binary, name, *ignored)?;
        let mut command = Command::new(root.join(&binary.executable));
        command.args([*name, "--exact", "--nocapture"]);
        if *package == "day2-control" && *target == "control_integration" {
            command.env("DAY2_TEST_RUSTC", &rustc);
        }
        if *ignored {
            command.arg("--ignored");
        }
        configure_tests(root, "mac-native", fixtures, None, &mut command)?;
        let remaining = Duration::from_secs(3600)
            .checked_sub(started.elapsed())
            .context("focused Mac native case allowance exhausted")?;
        let case_start = Instant::now();
        run_with_budget(root, &mut command, remaining)?;
        cases.push(Case {
            package: (*package).into(),
            target: (*target).into(),
            kind: (*kind).into(),
            name: (*name).into(),
            ignored: *ignored,
            executable: binary.executable.clone(),
            status: "passed".into(),
            elapsed_ms: super::super::milliseconds(case_start.elapsed()),
        });
    }
    // Enforce real campaign case presence before libtest's successful-zero-match
    // behavior can be mistaken for an isolated build/install success.
    for (_, name) in BUILD_CASES {
        require_case(
            root,
            case_binary(prepared, "day2-control", "control_integration", "test")?,
            name,
            true,
        )?;
    }
    fs::write(
        root.join("artifacts/ci-mac-cases.json"),
        serde_json::to_vec_pretty(&cases)?,
    )?;
    Ok(())
}

pub(in super::super) fn finish(
    root: &Path,
    prepared: Prepared,
    passed: &BTreeSet<String>,
    timings: &BTreeMap<String, u64>,
    executed: &BTreeMap<String, BTreeSet<PathBuf>>,
) -> Result<()> {
    let mut required = preparation_effects();
    required.extend([
        "test-mac-native".into(),
        "test-isolated-build".into(),
        "test-installation-build".into(),
    ]);
    ensure!(
        *passed == required && timings.keys().cloned().collect::<BTreeSet<_>>() == required,
        "focused Mac recipe incomplete"
    );
    let campaigns = BUILD_CASES
        .iter()
        .map(|(shard, _)| {
            let effects = effects(shard);
            let binaries = executed
                .get(*shard)
                .context("missing real Mac campaign")?
                .clone();
            let result = Receipt {
                prepared_digest: digest(&serde_json::to_vec(&prepared)?),
                shard: (*shard).into(),
                passed: effects.clone(),
                timings_ms: effects
                    .iter()
                    .map(|step| {
                        Ok((
                            step.clone(),
                            *timings.get(step).context("Mac campaign timing missing")?,
                        ))
                    })
                    .collect::<Result<_>>()?,
                binaries,
            };
            validate_receipt(&prepared, &result, shard)?;
            Ok(result)
        })
        .collect::<Result<_>>()?;
    let proof = Proof {
        compiler: build_identity(root, &prepared.identity.snapshot)?,
        prepared,
        cases: day2::json::decode(&fs::read(root.join("artifacts/ci-mac-cases.json"))?)?,
        native_elapsed_ms: *timings
            .get("test-mac-native")
            .context("native Mac case timing missing")?,
        campaigns,
    };
    fs::write(root.join(PATH), serde_json::to_vec_pretty(&proof)?)?;
    Ok(())
}

pub(super) fn admit(
    proof: &Proof,
    current: &Identity,
    expected_snapshot: &str,
    compiler: &BuildIdentity,
    targets: &Targets,
) -> Result<()> {
    let p = &proof.prepared;
    let id = &p.identity;
    let c = &proof.compiler;
    ensure!(
        id.checkout == current.checkout
            && id.tree == current.tree
            && id.source_identity == current.source_identity
            && id.workflow == current.workflow
            && id.run == current.run
            && id.attempt == current.attempt
            && id.host == "macos"
            && id.architecture == "aarch64"
            && id.snapshot == expected_snapshot
            && id.workspace.is_absolute()
            && p.passed == preparation_effects()
            && p.timings_ms.keys().cloned().collect::<BTreeSet<_>>() == p.passed
            && p.fixtures.keys().cloned().collect::<BTreeSet<_>>()
                == FIXTURES.iter().copied().map(String::from).collect(),
        "missing/foreign/incomplete same-source native Mac preparation"
    );
    ensure!(
        c.snapshot == id.snapshot
            && c.workflow == id.workflow
            && c.workspace == id.workspace
            && c.host == id.host
            && c.architecture == id.architecture
            && c.ci_workflow == compiler.ci_workflow
            && c.bazel_configuration == compiler.bazel_configuration
            && c.rustc.lines().next() == compiler.rustc.lines().next()
            && c.rustc
                .lines()
                .any(|line| line == "host: aarch64-apple-darwin")
            && c.bazel == compiler.bazel
            && !c.cc.trim().is_empty()
            && valid_digest(&c.environment),
        "Mac compiler/config/profile proof changed"
    );
    for (binaries, expected, programs) in [
        (&p.binaries, &targets.tests, false),
        (&p.programs, &targets.programs, true),
    ] {
        let observed: BTreeSet<_> = binaries
            .iter()
            .map(|b| (b.package.clone(), b.target.clone(), b.kind.clone()))
            .collect();
        ensure!(
            observed == *expected && observed.len() == binaries.len(),
            "incomplete Mac native Bazel graph"
        );
        for b in binaries {
            ensure!(
                targets
                    .members
                    .values()
                    .any(|(name, path)| name == &b.package && path == &b.directory)
                    && b.permissions & 0o111 != 0
                    && b.permissions & !0o777 == 0
                    && valid_digest(&b.digest)
                    && b.executable
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_)))
                    && b.executable.parent()
                        == Some(Path::new(if programs {
                            "build-out/bin"
                        } else {
                            "build-out/tests"
                        })),
                "invalid Mac native executable identity"
            );
            if programs {
                ensure!(
                    b.executable == program_output(&b.target),
                    "exact Mac supporting program path required"
                );
            }
        }
    }
    ensure!(
        p.auxiliaries.is_empty() && p.fixtures.values().all(|id| valid_digest(id)),
        "Mac domain cannot claim Linux auxiliary or unbound fixture outputs"
    );
    let observed: Vec<_> = proof
        .cases
        .iter()
        .map(|case| {
            (
                case.package.clone(),
                case.target.clone(),
                case.kind.clone(),
                case.name.clone(),
                case.ignored,
            )
        })
        .collect();
    ensure!(
        observed == required_cases(),
        "exact focused Mac native case set required"
    );
    for case in &proof.cases {
        ensure!(
            case.status == "passed"
                && case.executable
                    == case_binary(p, &case.package, &case.target, &case.kind)?.executable,
            "failed or foreign native Mac case"
        );
    }
    ensure!(
        proof.campaigns.len() == BUILD_CASES.len(),
        "both real Mac build campaigns required"
    );
    for (shard, _) in BUILD_CASES {
        let matches: Vec<_> = proof
            .campaigns
            .iter()
            .filter(|r| r.shard == *shard)
            .collect();
        ensure!(matches.len() == 1, "missing or duplicate Mac campaign");
        validate_receipt(p, matches[0], shard)?;
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub(super) fn campaigns(proof: &Proof) -> &[Receipt] {
    &proof.campaigns
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::expected_binaries;
    use super::*;
    pub(in crate::verification::shards) fn sample(
        original: &Prepared,
        compiler: &BuildIdentity,
    ) -> Result<Proof> {
        let mut prepared: Prepared = serde_json::from_value(serde_json::to_value(original)?)?;
        prepared.identity.host = "macos".into();
        prepared.identity.architecture = "aarch64".into();
        prepared.identity.workspace = "/Users/runner/work/platform/platform".into();
        prepared.identity.snapshot = "mac-snapshot".into();
        prepared.auxiliaries.clear();
        prepared
            .fixtures
            .retain(|name, _| FIXTURES.contains(&name.as_str()));
        prepared.passed = preparation_effects();
        prepared.timings_ms = prepared.passed.iter().map(|s| (s.clone(), 100)).collect();
        let mut native_compiler: BuildIdentity =
            serde_json::from_value(serde_json::to_value(compiler)?)?;
        native_compiler.host = "macos".into();
        native_compiler.architecture = "aarch64".into();
        native_compiler.workspace = prepared.identity.workspace.clone();
        native_compiler.snapshot = "mac-snapshot".into();
        native_compiler.rustc = "rust\nhost: aarch64-apple-darwin".into();
        let cases = required_cases()
            .into_iter()
            .map(|(package, target, kind, name, ignored)| {
                let executable = case_binary(&prepared, &package, &target, &kind)?
                    .executable
                    .clone();
                Ok(Case {
                    package,
                    target,
                    kind,
                    name,
                    ignored,
                    executable,
                    status: "passed".into(),
                    elapsed_ms: 100,
                })
            })
            .collect::<Result<_>>()?;
        let campaigns = BUILD_CASES
            .iter()
            .map(|(shard, _)| Receipt {
                prepared_digest: digest(&serde_json::to_vec(&prepared).unwrap()),
                shard: (*shard).into(),
                passed: effects(shard),
                timings_ms: effects(shard).into_iter().map(|s| (s, 100)).collect(),
                binaries: expected_binaries(&prepared, shard),
            })
            .collect();
        Ok(Proof {
            prepared,
            compiler: native_compiler,
            cases,
            native_elapsed_ms: 100,
            campaigns,
        })
    }

    #[test]
    fn focused_preparation_inventory_matches_the_roc_recipe() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let mut prepared = BTreeSet::new();
        day2::automation::run(
            &crate::workflows::build(&root)?,
            &["verify-mac"],
            |request| {
                match request.action.as_str() {
                    "verify-bazel-controls" => {
                        prepared.insert("bazel-controls".into());
                    }
                    "verify-cli" => {
                        prepared.insert("cli".into());
                    }
                    "verify-build" => {
                        let input: BTreeMap<String, String> = request.decode()?;
                        prepared.insert(format!("build-{}", input["fixture"]));
                    }
                    "verify-test-build" => {
                        prepared.insert("test-binaries".into());
                    }
                    _ => {}
                }
                Ok(serde_json::json!({}))
            },
        )?;
        assert_eq!(prepared, preparation_effects());
        assert!(prepared.contains("build-verification-setup"));
        Ok(())
    }

    #[test]
    fn focused_case_inventory_preserves_three_connection_probes_and_refuses_duplicate_or_ignored_guardian()
     {
        let cases = required_cases();
        let unique: BTreeSet<_> = cases.iter().collect();
        assert_eq!(unique.len(), cases.len());
        assert_eq!(
            cases
                .iter()
                .filter(|c| c.3.starts_with("connection_use::"))
                .count(),
            3
        );
        assert!(!cases.iter().any(|c| c.3.contains("parked_child_guardian")));
    }
}
