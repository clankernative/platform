//! Preserve the actual compiler-driver outcome before decoding its evidence.
//! Public diagnostics contain fixed observations and bounded numeric fields,
//! never raw source text, argv or environment values.
use crate::{CommandStatusError, command_status_with_budget};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read, path::Path, process::Command, time::Duration};

const MAX_CAPTURE: usize = 16 * 1024 * 1024;

/// Advisory counters from the pinned Bazel BEP schema. Missing/default-omitted
/// fields stay unknown. Action requests include spawn-cache hits but exclude
/// local action-cache hits; they are not codegen counts. The counters overlap
/// and must not be added together.
#[derive(Debug, PartialEq, Eq, Serialize)]
struct BuildMetrics {
    wall_time_ms: Option<u64>,
    analysis_time_ms: Option<u64>,
    execution_time_ms: Option<u64>,
    action_requests_including_cache: Option<u64>,
    rustc_requests_including_cache: Option<u64>,
    disk_cache_hit_spawns: Option<u64>,
    local_action_cache_hits: Option<u64>,
    local_action_cache_misses: Option<u64>,
}

fn metric_number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::String(value)
            if !value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse().ok()
        }
        value => value.as_u64(),
    }
}

fn build_metrics(bytes: &[u8]) -> Option<BuildMetrics> {
    if bytes.len() > MAX_CAPTURE {
        return None;
    }
    let mut metrics = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = day2::json::decode(line).ok()?;
        if value.pointer("/id/buildMetrics").is_none() {
            continue;
        }
        if metrics.is_some() {
            return None;
        }
        let data = value.get("buildMetrics")?.as_object()?;
        let action = data.get("actionSummary");
        let timing = data.get("timingMetrics");
        let number = |value: Option<&Value>, path: &str| {
            metric_number(value.and_then(|value| value.pointer(path)))
        };
        let named = |array: &str, field: &str, name: &str, count: &str| {
            let mut matches = action?
                .get(array)?
                .as_array()?
                .iter()
                .filter(|entry| entry.get(field).and_then(Value::as_str) == Some(name));
            let entry = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            metric_number(entry.get(count))
        };
        metrics = Some(BuildMetrics {
            wall_time_ms: number(timing, "/wallTimeInMs"),
            analysis_time_ms: number(timing, "/analysisPhaseTimeInMs"),
            execution_time_ms: number(timing, "/executionPhaseTimeInMs"),
            action_requests_including_cache: number(action, "/actionsExecuted"),
            rustc_requests_including_cache: named(
                "actionData",
                "mnemonic",
                "Rustc",
                "actionsExecuted",
            ),
            disk_cache_hit_spawns: named("runnerCount", "name", "disk cache hit", "count"),
            local_action_cache_hits: number(action, "/actionCacheStatistics/hits"),
            local_action_cache_misses: number(action, "/actionCacheStatistics/misses"),
        });
    }
    metrics
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Outcome {
    category: &'static str,
    code: Option<i32>,
    signal: Option<i32>,
    os_error: Option<i32>,
}

impl Outcome {
    fn observe(value: std::result::Result<std::process::ExitStatus, CommandStatusError>) -> Self {
        match value {
            Ok(status) => {
                #[cfg(unix)]
                let signal = {
                    use std::os::unix::process::ExitStatusExt;
                    status.signal()
                };
                #[cfg(not(unix))]
                let signal = None;
                Self {
                    category: if status.success() { "success" } else { "exit" },
                    code: status.code(),
                    signal,
                    os_error: None,
                }
            }
            Err(CommandStatusError::Spawn(error)) => Self {
                category: "spawn",
                code: None,
                signal: None,
                os_error: error.raw_os_error(),
            },
            Err(CommandStatusError::Wait(error)) => Self {
                category: "wait",
                code: None,
                signal: None,
                os_error: error.raw_os_error(),
            },
            Err(CommandStatusError::Timeout) => Self {
                category: "timeout",
                code: None,
                signal: None,
                os_error: None,
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) process: Outcome,
    capture: Option<&'static str>,
    retained: bool,
    observations: BTreeSet<&'static str>,
    children: BTreeSet<ChildStatus>,
    child_statuses_truncated: bool,
    actions: ActionDiagnostics,
    rust_diagnostics: RustDiagnostics,
    oom_kill_delta: Option<u64>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bazel build failed: primary={}, code={:?}, signal={:?}, os_error={:?}; evidence={:?}; retained={}; observations={:?}; children={:?}; child_statuses_truncated={}; actions={:?}; rust_diagnostics={:?}; cgroup_oom_kill_delta={:?}",
            if self.process.category == "success" {
                "capture"
            } else {
                self.process.category
            },
            self.process.code,
            self.process.signal,
            self.process.os_error,
            self.capture,
            self.retained,
            self.observations,
            self.children,
            self.child_statuses_truncated,
            self.actions,
            self.rust_diagnostics,
            self.oom_kill_delta
        )
    }
}

impl std::error::Error for Failure {}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_CAPTURE as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn finished(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_CAPTURE, "Bazel event capture budget");
    let mut terminal = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = day2::json::decode(line)?;
        if value.pointer("/id/buildFinished").is_some() {
            ensure!(terminal.is_none(), "duplicate Bazel build-finished event");
            // Protobuf JSON omits the default numeric zero. The hosted Linux
            // build emits {"name":"SUCCESS"}; absence alone is never success.
            let exit = value
                .pointer("/finished/exitCode")
                .context("Bazel exit status required")?;
            let code = exit.get("code").and_then(Value::as_i64);
            terminal = Some(match (exit.get("name").and_then(Value::as_str), code) {
                (Some("SUCCESS"), None | Some(0)) => 0,
                (Some(name), Some(code)) if name != "SUCCESS" && code != 0 => code,
                _ => anyhow::bail!("inconsistent Bazel build-finished exit status"),
            });
        }
    }
    ensure!(
        terminal == Some(0),
        "Bazel successful build-finished event required"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct ChildStatus {
    code: Option<i32>,
    signal: Option<u8>,
    metadata_kill_requested: bool,
}

fn child_statuses(bytes: &[u8]) -> BTreeSet<ChildStatus> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let line = std::str::from_utf8(line)
                .ok()?
                .strip_suffix('\r')
                .unwrap_or(std::str::from_utf8(line).ok()?);
            let fields = line
                .strip_prefix("RR_CHILD_V1 ")?
                .split(' ')
                .collect::<Vec<_>>();
            if fields.len() != 5 {
                return None;
            }
            let get = |index: usize, key: &str| fields[index].strip_prefix(key);
            let code_present = get(0, "code_present=")?;
            let code = get(1, "code=")?.parse::<i32>().ok()?;
            let signal_present = get(2, "signal_present=")?;
            let signal = get(3, "signal=")?.parse::<u8>().ok()?;
            let requested = get(4, "metadata_kill_requested=")?;
            if !["0", "1"].contains(&code_present)
                || !["0", "1"].contains(&signal_present)
                || !["0", "1"].contains(&requested)
            {
                return None;
            }
            if (code_present == "0" && code != 0)
                || (signal_present == "0" && signal != 0)
                || (signal_present == "1" && !(1..=64).contains(&signal))
            {
                return None;
            }
            Some(ChildStatus {
                code: (code_present == "1").then_some(code),
                signal: (signal_present == "1").then_some(signal),
                metadata_kill_requested: requested == "1",
            })
        })
        .collect()
}

/// Advisory fixed markers only. Never export a diagnostic line, source text,
/// path, argument or environment value, and never attribute a kill or OOM.
fn diagnostic_observations(bytes: &[u8]) -> BTreeSet<&'static str> {
    let text = String::from_utf8_lossy(bytes);
    [
        ("No such file or directory", "missing_path"),
        ("Permission denied", "os_access_refused"),
        ("Operation not permitted", "os_access_refused"),
        ("Read-only file system", "read_only_output"),
        ("sandbox_init", "sandbox_initialization"),
        ("sandbox_apply", "sandbox_initialization"),
        ("download is disabled", "offline_download_refused"),
        ("lockfile is no longer up-to-date", "module_lock_changed"),
        ("no such package", "package_not_found"),
        ("no such target", "target_not_found"),
        ("error[E0432]", "rust_unresolved_import"),
        ("error[E0433]", "rust_unresolved_module"),
        ("error[E0463]", "rust_missing_crate"),
        ("error[E0786]", "rust_invalid_metadata"),
        ("error: linking with", "native_link_failed"),
        ("library not found for", "link_library_not_found"),
    ]
    .into_iter()
    .filter_map(|(marker, observation)| text.contains(marker).then_some(observation))
    .collect()
}

const MAX_RUST_DIAGNOSTICS: usize = 16;
const MAX_DIAGNOSTIC_LINE: usize = 128 * 1024;
const MAX_DIAGNOSTIC_CATALOG: usize = 4 * 1024 * 1024;
const MAX_MACRO_LOCATION_DEPTH: usize = 8;

// Closed public code vocabulary from pinned rustc 1.100.0 -W help. Unknown
// or custom lint names remain private; no arbitrary identifier is exported.
const RUSTC_LINT_CODES: &str = "
aarch64_softfloat_neon absolute_paths_not_starting_with_crate aligned_fields_in_packed
ambiguous_associated_items ambiguous_derive_helpers ambiguous_glob_imported_traits
ambiguous_glob_imports ambiguous_glob_reexports ambiguous_import_visibilities
ambiguous_negative_literals ambiguous_panic_imports ambiguous_wide_pointer_comparisons
anonymous_parameters arithmetic_overflow array_into_iter asm_sub_register async_fn_in_trait
bad_asm_style bare_trait_objects binary_asm_labels bindings_with_variant_name boxed_slice_into_iter
break_with_label_and_loop c_void_returns clashing_extern_declarations closure_returning_async_block
coherence_leak_check conflicting_repr_hints confusable_idents const_evaluatable_unchecked
const_item_interior_mutations const_item_mutation dangerous_implicit_autorefs
dangling_pointers_from_locals dangling_pointers_from_temporaries dead_code dead_code_pub_in_binary
default_overrides_default_fields deprecated deprecated_in_future deprecated_llvm_intrinsic
deprecated_safe_2024 deprecated_where_clause_location deref_into_dyn_supertrait deref_nullptr
double_negations drop_bounds dropping_copy_types dropping_references duplicate_features
duplicate_macro_attributes duplicate_tools dyn_drop edition_2024_expr_fragment_specifier
elided_lifetimes_in_paths ellipsis_inclusive_range_patterns enum_intrinsics_non_enums
explicit_builtin_cfgs_in_flags explicit_outlives_requirements exported_private_dependencies
ffi_unwind_calls float_literal_f32_fallback for_loops_over_fallibles forbidden_lint_groups
forgetting_copy_types forgetting_references function_casts_as_integer function_item_references
hidden_glob_reexports if_let_rescope ill_formed_attribute_input impl_trait_overcaptures
impl_trait_redundant_captures implicit_provenance_casts improper_ctypes improper_ctypes_definitions
improper_gpu_kernel_arg incomplete_features incomplete_include ineffective_unstable_reexports
ineffective_unstable_trait_impl inline_no_sanitize integer_to_ptr_transmutes
internal_eq_trait_method_impls internal_features invalid_atomic_ordering invalid_doc_attributes
invalid_from_utf8 invalid_from_utf8_unchecked invalid_macro_export_arguments invalid_nan_comparisons
invalid_null_arguments invalid_reference_casting invalid_runtime_symbol_definitions
invalid_type_param_default invalid_value irrefutable_let_patterns keyword_idents_2018
keyword_idents_2024 large_assignments late_bound_lifetime_arguments legacy_derive_helpers
let_underscore_drop let_underscore_lock linker_info linker_messages long_running_const_eval
macro_expanded_macro_exports_accessed_by_absolute_paths macro_use_extern_crate
malformed_diagnostic_attributes malformed_diagnostic_filters malformed_diagnostic_format_literals
map_unit_fn meta_variable_misuse method_call_on_diverging_infer_var mismatched_lifetime_syntaxes
misplaced_diagnostic_attributes missing_abi missing_copy_implementations
missing_debug_implementations missing_docs missing_gpu_kernel_export_name missing_unsafe_on_extern
mixed_script_confusables multiple_supertrait_upcastable must_not_suspend mutable_transmutes
named_arguments_used_positionally named_asm_labels never_type_fallback_flowing_into_unsafe
no_mangle_const_items non_ascii_idents non_camel_case_types non_contiguous_range_endpoints
non_exhaustive_omitted_patterns non_fmt_panics non_local_definitions non_shorthand_field_patterns
non_snake_case non_upper_case_globals noop_method_call opaque_hidden_inferred_bound
out_of_scope_macro_calls overflowing_literals overlapping_range_endpoints path_statements
patterns_in_fns_without_body private_bounds private_interfaces proc_macro_derive_resolution_fallback
ptr_to_integer_transmute_in_consts pub_use_of_private_extern_crate raw_borrows_via_references
recursion_depth_exceeding_limit redundant_imports redundant_lifetimes redundant_semicolons
refining_impl_trait_internal refining_impl_trait_reachable renamed_and_removed_lints repeated_reprs
repr_c_enums_larger_than_int resolving_to_items_shadowing_supertrait_items rtsan_nonblocking_async
rust_2021_incompatible_closure_captures rust_2021_incompatible_or_patterns
rust_2021_prefixes_incompatible_syntax rust_2021_prelude_collisions
rust_2024_guarded_string_incompatible_syntax rust_2024_incompatible_pat rust_2024_prelude_collisions
self_constructor_from_outer_item semicolon_in_expressions_from_macros
semicolon_in_expressions_from_non_local_macros shadowing_supertrait_items single_use_lifetimes
special_module_name stable_features static_mut_refs suspicious_double_ref_op
suspicious_runtime_symbol_definitions tail_call_track_caller tail_expr_drop_order test_unstable_lint
text_direction_codepoint_in_comment text_direction_codepoint_in_literal trivial_bounds trivial_casts
trivial_numeric_casts type_alias_bounds tyvar_behind_raw_pointer uncommon_codepoints
unconditional_panic unconditional_recursion uncovered_param_in_projection undropped_manually_drops
unexpected_cfgs unfulfilled_lint_expectations ungated_async_fn_track_caller uninhabited_static
unit_bindings unknown_crate_types unknown_diagnostic_attributes unknown_lints unnameable_test_items
unnameable_types unnecessary_transmutes unpredictable_function_pointer_comparisons
unqualified_local_imports unreachable_cfg_select_predicates unreachable_code unreachable_patterns
unreachable_pub unsafe_attr_outside_unsafe unsafe_code unsafe_op_in_unsafe_fn unstable_features
unstable_name_collisions unstable_syntax_pre_expansion unsupported_calling_conventions
unused_allocation unused_assignments unused_associated_type_bounds unused_attributes unused_braces
unused_comparisons unused_crate_dependencies unused_doc_comments unused_extern_crates
unused_features unused_import_braces unused_imports unused_labels unused_lifetimes
unused_macro_rules unused_macros unused_must_use unused_mut unused_parens unused_qualifications
unused_results unused_unsafe unused_variables unused_visibilities useless_deprecated
useless_ptr_null_checks uses_power_alignment varargs_without_pattern variant_size_differences
warnings while_true x86_softfloat_sse
";

#[derive(Debug, Serialize)]
struct RustDiagnostic {
    code: String,
    location: Option<RustDiagnosticLocation>,
}

#[derive(Debug, Serialize)]
struct RustDiagnosticLocation {
    source: String,
    line: u32,
    column: u32,
    kind: RustLocationKind,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RustLocationKind {
    Primary,
    MacroCallsite,
}

#[derive(Debug, Serialize)]
struct RustDiagnostics {
    records: Vec<RustDiagnostic>,
    catalog_available: bool,
    input_truncated: bool,
    oversized_lines: usize,
    malformed_json_lines: usize,
    rejected_diagnostics: usize,
    missing_or_non_string_codes: usize,
    unadmitted_codes: usize,
    records_truncated: bool,
    unlocated_diagnostics: usize,
    macro_depth_limited: bool,
}

impl RustDiagnostics {
    fn push(&mut self, code: &str, location: Option<RustDiagnosticLocation>) {
        if self.records.len() == MAX_RUST_DIAGNOSTICS {
            self.records_truncated = true;
            return;
        }
        self.records.push(RustDiagnostic {
            code: code.to_owned(),
            location,
        });
    }
}

// The only public paths come from the checked-in architecture catalog, never
// from compiler-owned strings. A missing/invalid catalog exports no locations.
fn diagnostic_sources(bytes: &[u8]) -> Option<BTreeSet<String>> {
    if bytes.len() > MAX_DIAGNOSTIC_CATALOG {
        return None;
    }
    // This is the same bounded persisted-evidence decoder used by the
    // architecture gate, not the smaller application/worker transport decoder.
    let value: Value = day2::json::decode_evidence(bytes).ok()?;
    if value.get("version")?.as_u64()? != 1 {
        return None;
    }
    let sources = value.get("sources")?.as_array()?;
    if sources.is_empty() || sources.len() > 4096 {
        return None;
    }
    sources
        .iter()
        .map(|source| {
            let source = source.as_str()?;
            (source.len() <= 256
                && source.ends_with(".rs")
                && (source.starts_with("crates/")
                    || source.starts_with("cli/checks/")
                    || source == "build.rs")
                && source.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                }))
            .then(|| source.to_owned())
        })
        .collect()
}

// A macro's primary span can be in the private toolchain. Follow only the
// bounded typed callsite chain, exporting a location solely from this catalog.
// No macro name, definition path, source text or whole expansion is copied.
fn diagnostic_location(
    mut span: &Value,
    allowed: &BTreeSet<String>,
    root: &Path,
) -> (Option<RustDiagnosticLocation>, bool) {
    for depth in 0..MAX_MACRO_LOCATION_DEPTH {
        let source = span
            .get("file_name")
            .and_then(Value::as_str)
            .and_then(|source| diagnostic_source(source, allowed, root));
        let number = |key| {
            span.get(key)
                .and_then(Value::as_u64)
                .and_then(|number| u32::try_from(number).ok())
                .filter(|number| *number > 0)
        };
        if let (Some(source), Some(line), Some(column)) =
            (source, number("line_start"), number("column_start"))
        {
            return (
                Some(RustDiagnosticLocation {
                    source: source.clone(),
                    line,
                    column,
                    kind: if depth == 0 {
                        RustLocationKind::Primary
                    } else {
                        RustLocationKind::MacroCallsite
                    },
                }),
                false,
            );
        }
        let Some(callsite) = span.pointer("/expansion/span") else {
            return (None, false);
        };
        span = callsite;
    }
    (None, true)
}

fn diagnostic_source<'a>(
    source: &str,
    allowed: &'a BTreeSet<String>,
    root: &Path,
) -> Option<&'a String> {
    if let Some(source) = allowed.get(source).or_else(|| {
        source
            .strip_prefix("./")
            .and_then(|relative| allowed.get(relative))
    }) {
        return Some(source);
    }
    if !root.is_absolute() {
        return None;
    }
    // Accept only exact known workspace spellings, never an arbitrary path
    // suffix, traversal, symlink resolution or a foreign workspace prefix.
    for base in [
        root.to_owned(),
        root.join(".cache/bazel-executor/execroot/_main"),
    ] {
        let Some(base) = base.to_str() else { continue };
        if let Some(relative) = source
            .strip_prefix(base.trim_end_matches('/'))
            .and_then(|path| path.strip_prefix('/'))
            && let Some(source) = allowed.get(relative)
        {
            return Some(source);
        }
    }
    None
}

// Closed lint names from the pinned clippy 0.1.100 (0ef1bc3860) -Whelp.
// Unknown/custom identifiers and every free-form message remain private.
const CLIPPY_LINT_CODES: &str = "
clippy::absolute_paths clippy::absurd_extreme_comparisons clippy::alloc_instead_of_core clippy::allow_attributes
clippy::allow_attributes_without_reason clippy::almost_complete_range clippy::almost_swapped
clippy::approx_constant clippy::arbitrary_source_item_ordering clippy::arc_with_non_send_sync
clippy::arithmetic_side_effects clippy::as_conversions clippy::as_pointer_underscore clippy::as_ptr_cast_mut
clippy::as_underscore clippy::assert_is_empty clippy::assertions_on_constants
clippy::assertions_on_result_states clippy::assign_op_pattern clippy::assigning_clones
clippy::async_yields_async clippy::await_holding_invalid_type clippy::await_holding_lock
clippy::await_holding_refcell_ref clippy::bad_bit_mask clippy::big_endian_bytes clippy::bind_instead_of_map
clippy::blanket_clippy_restriction_lints clippy::block_scrutinee clippy::blocks_in_conditions
clippy::bool_assert_comparison clippy::bool_comparison clippy::bool_to_int_with_if clippy::borrow_as_ptr
clippy::borrow_deref_ref clippy::borrow_interior_mutable_const clippy::borrowed_box clippy::box_collection
clippy::box_default clippy::boxed_local clippy::branches_sharing_code clippy::builtin_type_shadow
clippy::by_ref_peekable_peek clippy::byte_char_slices clippy::bytes_count_to_len clippy::bytes_nth
clippy::cargo_common_metadata clippy::case_sensitive_file_extension_comparisons clippy::cast_abs_to_unsigned
clippy::cast_enum_constructor clippy::cast_enum_truncation clippy::cast_lossless clippy::cast_nan_to_int
clippy::cast_possible_truncation clippy::cast_possible_wrap clippy::cast_precision_loss
clippy::cast_ptr_alignment clippy::cast_sign_loss clippy::cast_slice_different_sizes
clippy::cast_slice_from_raw_parts clippy::cfg_not_test clippy::char_indices_as_byte_indices
clippy::char_lit_as_u8 clippy::chars_last_cmp clippy::chars_next_cmp clippy::checked_conversions
clippy::chunks_exact_to_as_chunks clippy::clear_with_drain clippy::clone_on_copy clippy::clone_on_ref_ptr
clippy::cloned_instead_of_copied clippy::cloned_ref_to_slice_refs clippy::cmp_null clippy::cmp_owned
clippy::coerce_container_to_any clippy::cognitive_complexity clippy::collapsible_else_if clippy::collapsible_if
clippy::collapsible_match clippy::collapsible_str_replace clippy::collection_is_never_read
clippy::comparison_chain clippy::comparison_to_empty clippy::confusing_method_to_numeric_cast
clippy::const_is_empty clippy::copy_iterator clippy::crate_in_macro_def clippy::create_dir
clippy::crosspointer_transmute clippy::dbg_macro clippy::debug_assert_with_mut_call
clippy::decimal_bitwise_operands clippy::decimal_literal_representation clippy::declare_interior_mutable_const
clippy::default_constructed_unit_structs clippy::default_instead_of_iter_empty clippy::default_numeric_fallback
clippy::default_trait_access clippy::default_union_representation clippy::definition_in_module_root
clippy::deprecated_cfg_attr clippy::deprecated_clippy_cfg_attr clippy::deprecated_semver clippy::deref_addrof
clippy::deref_by_slicing clippy::derivable_impls clippy::derive_ord_xor_partial_ord
clippy::derive_partial_eq_without_eq clippy::derived_hash_with_manual_eq clippy::disallowed_fields
clippy::disallowed_macros clippy::disallowed_methods clippy::disallowed_names clippy::disallowed_script_idents
clippy::disallowed_types clippy::diverging_sub_expression clippy::doc_broken_link
clippy::doc_comment_double_space_linebreaks clippy::doc_include_without_cfg clippy::doc_lazy_continuation
clippy::doc_link_code clippy::doc_link_with_quotes clippy::doc_markdown clippy::doc_nested_refdefs
clippy::doc_overindented_list_items clippy::doc_paragraphs_missing_punctuation clippy::doc_suspicious_footnotes
clippy::double_comparisons clippy::double_ended_iterator_last clippy::double_must_use clippy::double_parens
clippy::drain_collect clippy::drop_non_drop clippy::duplicate_mod clippy::duplicate_underscore_argument
clippy::duplicated_attributes clippy::duration_suboptimal_units clippy::duration_subsec clippy::eager_transmute
clippy::elidable_lifetime_names clippy::else_if_without_else clippy::empty_docs clippy::empty_drop
clippy::empty_enum_variants_with_brackets clippy::empty_enums clippy::empty_line_after_doc_comments
clippy::empty_line_after_outer_attr clippy::empty_loop clippy::empty_structs_with_brackets
clippy::enum_clike_unportable_variant clippy::enum_glob_use clippy::enum_variant_names clippy::eq_op
clippy::equatable_if_let clippy::erasing_op clippy::err_expect clippy::error_impl_error
clippy::excessive_nesting clippy::excessive_precision clippy::exhaustive_enums clippy::exhaustive_structs
clippy::exit clippy::expect_fun_call clippy::expect_used clippy::expl_impl_clone_on_copy
clippy::explicit_auto_deref clippy::explicit_counter_loop clippy::explicit_deref_methods
clippy::explicit_into_iter_loop clippy::explicit_iter_loop clippy::explicit_write clippy::extend_with_drain
clippy::extra_unused_lifetimes clippy::extra_unused_type_parameters clippy::fallible_impl_from
clippy::field_reassign_with_default clippy::field_scoped_visibility_modifiers clippy::filetype_is_file
clippy::filter_map_bool_then clippy::filter_map_identity clippy::filter_map_next clippy::filter_next
clippy::flat_map_identity clippy::flat_map_option clippy::float_arithmetic clippy::float_cmp
clippy::float_cmp_const clippy::float_equality_without_abs clippy::fn_params_excessive_bools
clippy::fn_to_numeric_cast clippy::fn_to_numeric_cast_any clippy::fn_to_numeric_cast_with_truncation
clippy::for_kv_map clippy::for_unbounded_range clippy::forget_non_drop clippy::format_collect
clippy::format_in_format_args clippy::format_push_string clippy::four_forward_slashes clippy::from_over_into
clippy::from_raw_with_void_ptr clippy::from_str_radix_10 clippy::future_not_send clippy::get_first
clippy::get_last_with_len clippy::get_unwrap clippy::host_endian_bytes clippy::identity_op clippy::if_let_mutex
clippy::if_not_else clippy::if_same_then_else clippy::if_then_some_else_none clippy::ifs_same_cond
clippy::ignore_without_reason clippy::ignored_unit_patterns clippy::impl_hash_borrow_with_str_and_bytes
clippy::impl_trait_in_params clippy::implicit_clone clippy::implicit_hasher clippy::implicit_return
clippy::implicit_saturating_add clippy::implicit_saturating_sub clippy::implied_bounds_in_impls
clippy::impossible_comparisons clippy::imprecise_flops clippy::incompatible_msrv
clippy::inconsistent_digit_grouping clippy::inconsistent_struct_constructor clippy::index_refutable_slice
clippy::indexing_slicing clippy::ineffective_bit_mask clippy::ineffective_open_options
clippy::inefficient_to_string clippy::infallible_destructuring_match clippy::infallible_try_from
clippy::infinite_iter clippy::infinite_loop clippy::inherent_to_string clippy::inherent_to_string_shadow_display
clippy::init_numbered_fields clippy::inline_always clippy::inline_asm_x86_att_syntax
clippy::inline_asm_x86_intel_syntax clippy::inline_fn_without_body clippy::inline_modules
clippy::inline_trait_bounds clippy::inspect_for_each clippy::int_plus_one clippy::integer_division
clippy::integer_division_remainder_used clippy::into_iter_on_ref clippy::into_iter_without_iter
clippy::invalid_regex clippy::invalid_upcast_comparisons clippy::inverted_saturating_sub
clippy::invisible_characters clippy::io_other_error clippy::ip_constant clippy::is_digit_ascii_radix
clippy::items_after_statements clippy::items_after_test_module clippy::iter_cloned_collect clippy::iter_count
clippy::iter_filter_is_ok clippy::iter_filter_is_some clippy::iter_kv_map clippy::iter_next_loop
clippy::iter_next_slice clippy::iter_not_returning_iterator clippy::iter_nth clippy::iter_nth_zero
clippy::iter_on_empty_collections clippy::iter_on_single_items clippy::iter_out_of_bounds
clippy::iter_over_hash_type clippy::iter_overeager_cloned clippy::iter_skip_next clippy::iter_skip_zero
clippy::iter_with_drain clippy::iter_without_into_iter clippy::iterator_step_by_zero clippy::join_absolute_paths
clippy::just_underscores_and_digits clippy::large_const_arrays clippy::large_digit_groups
clippy::large_enum_variant clippy::large_futures clippy::large_include_file clippy::large_stack_arrays
clippy::large_stack_frames clippy::large_types_passed_by_value clippy::legacy_numeric_constants
clippy::len_without_is_empty clippy::len_zero clippy::let_and_return clippy::let_underscore_future
clippy::let_underscore_lock clippy::let_underscore_must_use clippy::let_underscore_untyped
clippy::let_unit_value clippy::let_with_type_underscore clippy::lines_filter_map_ok clippy::linkedlist
clippy::lint_groups_priority clippy::literal_string_with_formatting_args clippy::little_endian_bytes
clippy::lossy_float_literal clippy::macro_metavars_in_unsafe clippy::macro_use_imports clippy::main_recursion
clippy::manual_abs_diff clippy::manual_assert clippy::manual_assert_eq clippy::manual_async_fn
clippy::manual_bit_width clippy::manual_bits clippy::manual_c_str_literals clippy::manual_checked_ops
clippy::manual_clamp clippy::manual_clear clippy::manual_contains clippy::manual_dangling_ptr
clippy::manual_div_ceil clippy::manual_filter clippy::manual_filter_map clippy::manual_find
clippy::manual_find_map clippy::manual_flatten clippy::manual_hash_one clippy::manual_ignore_case_cmp
clippy::manual_ilog2 clippy::manual_inspect clippy::manual_instant_elapsed clippy::manual_is_ascii_check
clippy::manual_is_finite clippy::manual_is_infinite clippy::manual_is_multiple_of clippy::manual_is_power_of_two
clippy::manual_is_variant_and clippy::manual_isolate_lowest_one clippy::manual_let_else
clippy::manual_main_separator_str clippy::manual_map clippy::manual_memcpy clippy::manual_midpoint
clippy::manual_next_back clippy::manual_non_exhaustive clippy::manual_noop_waker clippy::manual_ok_err
clippy::manual_ok_or clippy::manual_option_as_slice clippy::manual_option_zip
clippy::manual_pattern_char_comparison clippy::manual_pop_if clippy::manual_range_contains
clippy::manual_range_patterns clippy::manual_rem_euclid clippy::manual_repeat_n clippy::manual_retain
clippy::manual_rotate clippy::manual_saturating_arithmetic clippy::manual_slice_fill
clippy::manual_slice_size_calculation clippy::manual_split_once clippy::manual_str_repeat
clippy::manual_string_new clippy::manual_strip clippy::manual_swap clippy::manual_take clippy::manual_try_fold
clippy::manual_unwrap_or clippy::manual_unwrap_or_default clippy::manual_while_let_some
clippy::many_single_char_names clippy::map_all_any_identity clippy::map_clone clippy::map_collect_result_unit
clippy::map_entry clippy::map_err_ignore clippy::map_flatten clippy::map_identity clippy::map_or_identity
clippy::map_unwrap_or clippy::map_with_unused_argument_over_ranges clippy::match_as_ref clippy::match_bool
clippy::match_like_matches_macro clippy::match_overlapping_arm clippy::match_ref_pats clippy::match_result_ok
clippy::match_same_arms clippy::match_single_binding clippy::match_str_case_mismatch clippy::match_wild_err_arm
clippy::match_wildcard_for_single_variants clippy::maybe_infinite_iter clippy::mem_forget
clippy::mem_replace_option_with_none clippy::mem_replace_option_with_some clippy::mem_replace_with_default
clippy::mem_replace_with_uninit clippy::min_ident_chars clippy::min_max clippy::mismatched_bit_width_type
clippy::mismatching_type_param_order clippy::misnamed_getters clippy::misrefactored_assign_op
clippy::missing_assert_message clippy::missing_asserts_for_indexing clippy::missing_const_for_fn
clippy::missing_const_for_thread_local clippy::missing_docs_in_private_items
clippy::missing_enforced_import_renames clippy::missing_errors_doc clippy::missing_fields_in_debug
clippy::missing_inline_in_public_items clippy::missing_panics_doc clippy::missing_safety_doc
clippy::missing_spin_loop clippy::missing_trait_methods clippy::missing_transmute_annotations
clippy::mistyped_literal_suffixes clippy::mixed_attributes_style clippy::mixed_case_hex_literals
clippy::mixed_read_write_in_expression clippy::mod_module_files clippy::module_inception
clippy::module_name_repetitions clippy::modulo_arithmetic clippy::modulo_one clippy::multi_assignments
clippy::multiple_bound_locations clippy::multiple_crate_versions clippy::multiple_inherent_impl
clippy::multiple_unsafe_ops_per_block clippy::must_use_candidate clippy::must_use_unit clippy::mut_from_ref
clippy::mut_mut clippy::mut_mutex_lock clippy::mut_range_bound clippy::mutable_key_type clippy::mutex_atomic
clippy::mutex_integer clippy::naive_bytecount clippy::needless_arbitrary_self_type clippy::needless_as_bytes
clippy::needless_bitwise_bool clippy::needless_bool clippy::needless_bool_assign clippy::needless_borrow
clippy::needless_borrowed_reference clippy::needless_borrows_for_generic_args
clippy::needless_character_iteration clippy::needless_collect clippy::needless_continue
clippy::needless_doctest_main clippy::needless_else clippy::needless_for_each clippy::needless_ifs
clippy::needless_late_init clippy::needless_lifetimes clippy::needless_match clippy::needless_maybe_sized
clippy::needless_nonzero_get clippy::needless_option_as_deref clippy::needless_option_take
clippy::needless_parens_on_range_literals clippy::needless_pass_by_ref_mut clippy::needless_pass_by_value
clippy::needless_pub_self clippy::needless_question_mark clippy::needless_range_loop
clippy::needless_raw_string_hashes clippy::needless_raw_strings clippy::needless_return
clippy::needless_return_with_question_mark clippy::needless_splitn clippy::needless_type_cast
clippy::needless_update clippy::neg_cmp_op_on_partial_ord clippy::neg_multiply clippy::negative_feature_names
clippy::never_loop clippy::new_ret_no_self clippy::new_without_default clippy::no_effect
clippy::no_effect_replace clippy::no_effect_underscore_binding clippy::no_mangle_with_rust_abi
clippy::non_ascii_literal clippy::non_canonical_clone_impl clippy::non_canonical_partial_ord_impl
clippy::non_minimal_cfg clippy::non_octal_unix_permissions clippy::non_send_fields_in_send_ty
clippy::non_std_lazy_statics clippy::non_zero_suggestions clippy::nonminimal_bool
clippy::nonnull_unchecked_on_box_ptr clippy::nonsensical_open_options clippy::nonstandard_macro_braces
clippy::not_unsafe_ptr_arg_deref clippy::obfuscated_if_else clippy::octal_escapes clippy::ok_expect
clippy::only_used_in_recursion clippy::op_ref clippy::option_as_ref_cloned clippy::option_as_ref_deref
clippy::option_env_unwrap clippy::option_filter_map clippy::option_if_let_else clippy::option_map_or_none
clippy::option_map_unit_fn clippy::option_option clippy::option_zip_none clippy::or_fun_call
clippy::or_then_unwrap clippy::out_of_bounds_indexing clippy::overly_complex_bool_expr clippy::owned_cow
clippy::panic clippy::panic_in_result_fn clippy::panicking_overflow_checks clippy::panicking_unwrap
clippy::partial_pub_fields clippy::partialeq_ne_impl clippy::partialeq_to_none clippy::path_buf_push_overwrite
clippy::path_ends_with_ext clippy::pathbuf_init_then_push clippy::pattern_type_mismatch
clippy::permissions_set_readonly_false clippy::pointer_format clippy::pointers_in_nomem_asm_block
clippy::possible_missing_comma clippy::possible_missing_else clippy::precedence clippy::precedence_bits
clippy::print_in_format_impl clippy::print_literal clippy::print_stderr clippy::print_stdout
clippy::print_with_newline clippy::println_empty_string clippy::ptr_arg clippy::ptr_as_ptr
clippy::ptr_cast_constness clippy::ptr_eq clippy::ptr_offset_by_literal clippy::ptr_offset_with_cast
clippy::pub_underscore_fields clippy::pub_use clippy::pub_with_shorthand clippy::pub_without_shorthand
clippy::question_mark clippy::question_mark_used clippy::range_minus_one clippy::range_plus_one
clippy::range_zip_with_len clippy::rc_buffer clippy::rc_clone_in_vec_init clippy::rc_mutex
clippy::read_line_without_trim clippy::read_zero_byte_vec clippy::readonly_write_lock
clippy::recursive_format_impl clippy::redundant_allocation clippy::redundant_as_str
clippy::redundant_async_block clippy::redundant_at_rest_pattern clippy::redundant_clone
clippy::redundant_closure clippy::redundant_closure_call clippy::redundant_closure_for_method_calls
clippy::redundant_comparisons clippy::redundant_else clippy::redundant_feature_names
clippy::redundant_field_names clippy::redundant_guards clippy::redundant_iter_cloned clippy::redundant_locals
clippy::redundant_pattern clippy::redundant_pattern_matching clippy::redundant_pub_crate
clippy::redundant_slicing clippy::redundant_static_lifetimes clippy::redundant_test_prefix
clippy::redundant_type_annotations clippy::ref_as_ptr clippy::ref_binding_to_reference clippy::ref_option
clippy::ref_option_ref clippy::ref_patterns clippy::regex_creation_in_loops clippy::renamed_function_params
clippy::repeat_once clippy::repeat_vec_with_capacity clippy::replace_box clippy::repr_packed_without_abi
clippy::reserve_after_initialization clippy::rest_pat_in_fully_bound_structs
clippy::rest_pattern_accessible_field clippy::result_filter_map clippy::result_large_err
clippy::result_map_or_into_option clippy::result_map_unit_fn clippy::result_unit_err clippy::return_and_then
clippy::return_self_not_must_use clippy::reversed_empty_ranges clippy::same_functions_in_if_condition
clippy::same_item_push clippy::same_length_and_capacity clippy::same_name_method clippy::search_is_some
clippy::seek_from_current clippy::seek_to_start_instead_of_rewind clippy::self_assignment
clippy::self_named_constructors clippy::self_named_module_files clippy::self_only_used_in_recursion
clippy::semicolon_if_nothing_returned clippy::semicolon_inside_block clippy::semicolon_outside_block
clippy::separated_literal_suffix clippy::serde_api_misuse clippy::set_contains_or_insert clippy::shadow_reuse
clippy::shadow_same clippy::shadow_unrelated clippy::short_circuit_statement clippy::should_implement_trait
clippy::should_panic_without_expect clippy::significant_drop_in_scrutinee clippy::significant_drop_tightening
clippy::similar_names clippy::single_call_fn clippy::single_char_add_str clippy::single_char_lifetime_names
clippy::single_char_pattern clippy::single_component_path_imports clippy::single_element_loop
clippy::single_match clippy::single_match_else clippy::single_option_map clippy::single_range_in_vec_init
clippy::size_of_in_element_count clippy::size_of_ref clippy::skip_while_next clippy::sliced_string_as_bytes
clippy::slow_vector_initialization clippy::some_filter clippy::stable_sort_primitive
clippy::std_instead_of_alloc clippy::std_instead_of_core clippy::str_split_at_newline clippy::str_to_string
clippy::string_add clippy::string_add_assign clippy::string_extend_chars clippy::string_from_utf8_as_bytes
clippy::string_lit_as_bytes clippy::string_lit_chars_any clippy::string_slice clippy::strlen_on_c_strings
clippy::struct_excessive_bools clippy::struct_field_names clippy::suboptimal_flops
clippy::suspicious_arithmetic_impl clippy::suspicious_assignment_formatting clippy::suspicious_command_arg_space
clippy::suspicious_doc_comments clippy::suspicious_else_formatting clippy::suspicious_map
clippy::suspicious_op_assign_impl clippy::suspicious_open_options clippy::suspicious_operation_groupings
clippy::suspicious_splitn clippy::suspicious_to_owned clippy::suspicious_unary_op_formatting
clippy::suspicious_xor_used_as_pow clippy::swap_ptr_to_ref clippy::swap_with_temporary
clippy::tabs_in_doc_comments clippy::temporary_assignment clippy::test_attr_in_doctest
clippy::tests_outside_test_module clippy::to_digit_is_some clippy::to_string_in_format_args
clippy::to_string_trait_impl clippy::todo clippy::too_long_first_doc_paragraph clippy::too_many_arguments
clippy::too_many_lines clippy::toplevel_ref_arg clippy::trailing_empty_array clippy::trait_duplication_in_bounds
clippy::transmute_bytes_to_str clippy::transmute_int_to_bool clippy::transmute_int_to_non_zero
clippy::transmute_null_to_fn clippy::transmute_ptr_to_ptr clippy::transmute_ptr_to_ref
clippy::transmute_undefined_repr clippy::transmutes_expressible_as_ptr_casts clippy::transmuting_null
clippy::trim_split_whitespace clippy::trivial_regex clippy::trivially_copy_pass_by_ref clippy::try_err
clippy::tuple_array_conversions clippy::type_complexity clippy::type_id_on_box clippy::type_repetition_in_bounds
clippy::unbuffered_bytes clippy::unchecked_time_subtraction clippy::unconditional_recursion
clippy::undocumented_unsafe_blocks clippy::unicode_not_nfc clippy::unimplemented clippy::uninhabited_references
clippy::uninit_assumed_init clippy::uninit_vec clippy::uninlined_format_args clippy::unit_arg clippy::unit_cmp
clippy::unit_hash clippy::unit_return_expecting_ord clippy::unnecessary_box_returns clippy::unnecessary_cast
clippy::unnecessary_clippy_cfg clippy::unnecessary_debug_formatting clippy::unnecessary_fallible_conversions
clippy::unnecessary_filter_map clippy::unnecessary_find_map clippy::unnecessary_first_then_check
clippy::unnecessary_fold clippy::unnecessary_get_then_check clippy::unnecessary_join
clippy::unnecessary_lazy_evaluations clippy::unnecessary_literal_bound clippy::unnecessary_literal_unwrap
clippy::unnecessary_map_on_constructor clippy::unnecessary_map_or clippy::unnecessary_min_or_max
clippy::unnecessary_mut_passed clippy::unnecessary_operation clippy::unnecessary_option_map_or_else
clippy::unnecessary_owned_empty_strings clippy::unnecessary_rest_pattern clippy::unnecessary_result_map_or_else
clippy::unnecessary_safety_comment clippy::unnecessary_safety_doc clippy::unnecessary_self_imports
clippy::unnecessary_semicolon clippy::unnecessary_sort_by clippy::unnecessary_struct_initialization
clippy::unnecessary_to_owned clippy::unnecessary_trailing_comma clippy::unnecessary_unwrap
clippy::unnecessary_unwrap_unchecked clippy::unnecessary_wraps clippy::unneeded_field_pattern
clippy::unneeded_struct_pattern clippy::unneeded_wildcard_pattern clippy::unnested_or_patterns
clippy::unreachable clippy::unreadable_literal clippy::unsafe_derive_deserialize
clippy::unsafe_removed_from_name clippy::unseparated_literal_suffix clippy::unsound_collection_transmute
clippy::unused_async clippy::unused_async_trait_impl clippy::unused_enumerate_index clippy::unused_format_specs
clippy::unused_io_amount clippy::unused_peekable clippy::unused_result_ok clippy::unused_rounding
clippy::unused_self clippy::unused_trait_names clippy::unused_unit clippy::unusual_byte_groupings
clippy::unwrap_in_result clippy::unwrap_or_default clippy::unwrap_used clippy::upper_case_acronyms
clippy::use_debug clippy::use_self clippy::used_underscore_binding clippy::used_underscore_items
clippy::useless_asref clippy::useless_attribute clippy::useless_borrows_in_formatting clippy::useless_concat
clippy::useless_conversion clippy::useless_format clippy::useless_let_if_seq
clippy::useless_nonzero_new_unchecked clippy::useless_transmute clippy::useless_vec clippy::vec_box
clippy::vec_init_then_push clippy::vec_resize_to_zero clippy::verbose_bit_mask clippy::verbose_file_reads
clippy::volatile_composites clippy::waker_clone_wake clippy::while_float clippy::while_immutable_condition
clippy::while_let_loop clippy::while_let_on_iterator clippy::wildcard_dependencies
clippy::wildcard_enum_match_arm clippy::wildcard_imports clippy::wildcard_in_or_patterns
clippy::with_capacity_zero clippy::write_literal clippy::write_with_newline clippy::writeln_empty_string
clippy::wrong_self_convention clippy::wrong_transmute clippy::zero_divided_by_zero clippy::zero_prefixed_literal
clippy::zero_ptr clippy::zero_repeat_side_effects clippy::zero_sized_map_values clippy::zombie_processes
clippy::zst_offset
";

fn diagnostic_code_allowed(code: &str) -> bool {
    code.len() <= 64
        && ((code.len() == 5
            && code.starts_with('E')
            && code.as_bytes()[1..].iter().all(u8::is_ascii_digit))
            || RUSTC_LINT_CODES
                .split_ascii_whitespace()
                .any(|lint| lint == code)
            || CLIPPY_LINT_CODES
                .split_ascii_whitespace()
                .any(|lint| lint == code))
}

// rules_rust's JSON mode preserves the original rustc diagnostic before its
// rendered-message conversion. Rust E-codes and closed builtin lint codes survive
// even without an admitted location. Never serialize messages, rendered output,
// source text or labels.
fn rust_diagnostics(bytes: &[u8], allowed: &BTreeSet<String>, root: &Path) -> RustDiagnostics {
    coded_diagnostics(bytes, allowed, root, CodedLevels::CompilerErrors)
}

#[derive(Clone, Copy)]
enum CodedLevels {
    CompilerErrors,
    ClippyRefusals,
}

fn coded_diagnostics(
    bytes: &[u8],
    allowed: &BTreeSet<String>,
    root: &Path,
    levels: CodedLevels,
) -> RustDiagnostics {
    let mut result = RustDiagnostics {
        records: Vec::new(),
        catalog_available: !allowed.is_empty(),
        input_truncated: bytes.len() > MAX_CAPTURE,
        oversized_lines: 0,
        malformed_json_lines: 0,
        rejected_diagnostics: 0,
        missing_or_non_string_codes: 0,
        unadmitted_codes: 0,
        records_truncated: false,
        unlocated_diagnostics: 0,
        macro_depth_limited: false,
    };
    let bytes = &bytes[..bytes.len().min(MAX_CAPTURE)];
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if result.input_truncated && !line.ends_with(b"\n") {
            break;
        }
        if !line.starts_with(b"{") {
            continue;
        }
        if line.len() > MAX_DIAGNOSTIC_LINE {
            result.oversized_lines += 1;
            continue;
        }
        let Ok(value) = day2::json::decode::<Value>(line) else {
            result.malformed_json_lines += 1;
            continue;
        };
        if value.get("$message_type").and_then(Value::as_str) != Some("diagnostic") {
            continue;
        }
        let included = matches!(
            (levels, value.get("level").and_then(Value::as_str)),
            (_, Some("error"))
                | (
                    CodedLevels::ClippyRefusals,
                    Some("warning" | "failure-note")
                )
        );
        if !included {
            continue;
        }
        let code = value.pointer("/code/code").and_then(Value::as_str);
        let Some(code) = code else {
            result.rejected_diagnostics += 1;
            result.missing_or_non_string_codes += 1;
            continue;
        };
        if !diagnostic_code_allowed(code) {
            result.rejected_diagnostics += 1;
            result.unadmitted_codes += 1;
            continue;
        }
        let mut admitted = false;
        for span in value
            .get("spans")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if span.get("is_primary").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let (location, limited) = diagnostic_location(span, allowed, root);
            result.macro_depth_limited |= limited;
            if location.is_some() {
                admitted = true;
                result.push(code, location);
            }
        }
        if !admitted {
            result.unlocated_diagnostics += 1;
            result.push(code, None);
        }
    }
    result
}

/// Safe supplementary classification for declared Clippy producer files.
/// Called after an actual failed build; never admits/retries/replaces it.
pub(crate) fn clippy_failure_context(
    root: &Path,
    primary: anyhow::Error,
    readback: Option<(&[u8], [usize; 5])>,
) -> anyhow::Error {
    let sources = read_bounded(&root.join("architecture-rules.json"))
        .ok()
        .and_then(|bytes| diagnostic_sources(&bytes))
        .unwrap_or_default();
    let coverage = readback.as_ref().map(|(_, coverage)| *coverage);
    let diagnostics = readback
        .map(|(bytes, _)| coded_diagnostics(bytes, &sources, root, CodedLevels::ClippyRefusals));
    primary.context(format!(
        "declared Clippy producer diagnostics (observed files only, no cause attribution; coverage(expected,available,missing,rejected,size_limited)={coverage:?}): {diagnostics:?}"
    ))
}

#[derive(Debug, Serialize)]
struct FailedAction {
    owner: Option<String>,
    kind: &'static str,
    exit_code: Option<i32>,
}

#[derive(Debug, Serialize)]
struct ActionDiagnostics {
    records: Vec<FailedAction>,
    reported_failures: usize,
    catalog_available: bool,
    parse_complete: bool,
    truncated: bool,
    child_signal_attribution: bool,
}

// Export only owners present in the current public platform target catalog.
// BEP messages, paths, command lines and unknown/external labels stay private.
fn action_diagnostics(bytes: &[u8], allowed: &BTreeSet<String>) -> ActionDiagnostics {
    let mut result = ActionDiagnostics {
        records: Vec::new(),
        reported_failures: 0,
        catalog_available: !allowed.is_empty(),
        parse_complete: bytes.len() <= MAX_CAPTURE,
        truncated: false,
        child_signal_attribution: false,
    };
    if !result.parse_complete {
        return result;
    }
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Ok(value) = day2::json::decode::<Value>(line) else {
            result.parse_complete = false;
            break;
        };
        let Some(action) = value.get("action").and_then(Value::as_object) else {
            continue;
        };
        match action.get("success") {
            Some(Value::Bool(true)) => continue,
            None | Some(Value::Bool(false)) => {}
            _ => {
                result.parse_complete = false;
                continue;
            }
        }
        let Some(id) = value
            .pointer("/id/actionCompleted")
            .and_then(Value::as_object)
        else {
            result.parse_complete = false;
            continue;
        };
        result.reported_failures += 1;
        if result.records.len() == 8 {
            result.truncated = true;
            continue;
        }
        let owner = id.get("label").and_then(Value::as_str).and_then(|label| {
            allowed
                .get(label.strip_prefix("@@").unwrap_or(label))
                .cloned()
        });
        let kind = match action.get("type").and_then(Value::as_str) {
            Some("Rustc") => "rustc",
            Some("RustcClippy") => "clippy",
            Some("CppCompile") => "c_compile",
            Some("CppLink") => "native_link",
            Some("CargoBuildScriptRun") => "build_script",
            _ => "other",
        };
        let exit_code = action
            .get("exitCode")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok());
        result.records.push(FailedAction {
            owner,
            kind,
            exit_code,
        });
    }
    result
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

fn memory(directory: &Path) -> serde_json::Value {
    let read = |name: &str| -> Option<String> {
        let mut bytes = Vec::new();
        fs::File::open(directory.join(name))
            .ok()?
            .take(4097)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= 4096)
            .then(|| String::from_utf8(bytes).ok())
            .flatten()
    };
    let number = |name: &str| read(name)?.trim().parse::<u64>().ok();
    let events = read("memory.events");
    let event = |name: &str| {
        events.as_ref()?.lines().find_map(|line| {
            let (key, value) = line.split_once(' ')?;
            (key == name).then(|| value.parse::<u64>().ok()).flatten()
        })
    };
    json!({"limit_bytes":number("memory.max"),"current_bytes":number("memory.current"),"peak_bytes":number("memory.peak"),"oom_events":event("oom"),"oom_kills":event("oom_kill"),"cause_attribution":false})
}

fn memory_delta(before: &Value, after: &Value, key: &str) -> Option<u64> {
    let limit = before["limit_bytes"].as_u64().filter(|limit| *limit > 0)?;
    if after["limit_bytes"].as_u64() != Some(limit) {
        return None;
    }
    after[key].as_u64()?.checked_sub(before[key].as_u64()?)
}

fn memory_observations(before: &Value, after: &Value) -> Value {
    let snapshot = |value: &Value| {
        json!({
            "limit_bytes": value["limit_bytes"].as_u64(),
            "current_bytes": value["current_bytes"].as_u64(),
            "peak_bytes": value["peak_bytes"].as_u64(),
            "oom_events": value["oom_events"].as_u64(),
            "oom_kills": value["oom_kills"].as_u64(),
        })
    };
    json!({
        "before": snapshot(before),
        "after": snapshot(after),
        "oom_events_delta": memory_delta(before, after, "oom_events"),
        "oom_kill_delta": memory_delta(before, after, "oom_kills"),
        "cause_attribution": false,
    })
}

fn report(
    root: &Path,
    process: Outcome,
    events: std::io::Result<Vec<u8>>,
    log: &[u8],
    memory_before: Value,
) -> Result<()> {
    let capture = match &events {
        Err(_) => Some("read"),
        Ok(bytes) if bytes.len() > MAX_CAPTURE => Some("budget"),
        Ok(bytes) if finished(bytes).is_err() => Some("events"),
        Ok(_) => None,
    };
    let memory_after = memory(Path::new("/sys/fs/cgroup"));
    let oom_kill_delta = memory_delta(&memory_before, &memory_after, "oom_kills");
    // Fixed numeric fields only. The kernel peak is cumulative for this cgroup,
    // not a per-action RSS measurement or proof of which child was killed.
    eprintln!(
        "BAZEL_CGROUP_MEMORY_V1 {}",
        memory_observations(&memory_before, &memory_after)
    );
    if process.category == "success" && capture.is_none() {
        return Ok(());
    }
    let catalog = crate::bazel::targets(root)
        .map(|targets| targets.into_iter().map(|target| target.label).collect())
        .unwrap_or_default();
    let mut actions = action_diagnostics(events.as_deref().unwrap_or_default(), &catalog);
    actions.parse_complete &= events.is_ok();
    let sources = read_bounded(&root.join("architecture-rules.json"))
        .ok()
        .and_then(|bytes| diagnostic_sources(&bytes))
        .unwrap_or_default();
    let rust_diagnostics = rust_diagnostics(log, &sources, root);
    let retain = (|| -> Result<()> {
        let base = root.join("artifacts/bazel/failures");
        fs::create_dir_all(&base)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("build-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir_in(base)?.keep();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let bytes = events.as_ref().map(Vec::as_slice).unwrap_or_default();
        let manifest = json!({"format":1,"build_process":process,"capture_problem":capture,"captured_bytes":bytes.len(),"retained_bytes":bytes.len().min(MAX_CAPTURE),"complete":bytes.len() <= MAX_CAPTURE && events.is_ok(),"child_statuses":child_statuses(log),"failed_actions":actions,"diagnostic_observations":diagnostic_observations(log),"rust_diagnostics":rust_diagnostics,"cause_attribution":false,"cgroup_memory_before":memory_before,"cgroup_memory_at_failure":memory_after,"cgroup_memory_event_deltas":{"oom_events":memory_delta(&memory_before,&memory_after,"oom_events"),"oom_kills":oom_kill_delta,"cause_attribution":false},"diagnostic_only_not_a_preparation_or_runtime_receipt":true,"raw_retention":"private job-workspace only; never an Actions artifact input"});
        private_write(
            &directory.join("events.jsonl"),
            &bytes[..bytes.len().min(MAX_CAPTURE)],
        )?;
        private_write(
            &directory.join("stderr.bin"),
            &log[..log.len().min(MAX_CAPTURE)],
        )?;
        private_write(
            &directory.join("outcome.json"),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok(())
    })();
    let children = child_statuses(log);
    let child_statuses_truncated = children.len() > 8;
    Err(Failure {
        process,
        capture,
        retained: retain.is_ok(),
        observations: diagnostic_observations(log),
        children: children.into_iter().take(8).collect(),
        child_statuses_truncated,
        actions,
        rust_diagnostics,
        oom_kill_delta,
    }
    .into())
}

fn capture(root: &Path, command: &mut Command, budget: Duration, events: &Path) -> Result<()> {
    let stdout = tempfile::NamedTempFile::new()?;
    let stderr = tempfile::NamedTempFile::new()?;
    command
        .stdout(stdout.as_file().try_clone()?)
        .stderr(stderr.as_file().try_clone()?);
    let memory_before = memory(Path::new("/sys/fs/cgroup"));
    let process = Outcome::observe(command_status_with_budget(root, command, budget));
    let output = read_bounded(stdout.path());
    let errors = read_bounded(stderr.path());
    let events = read_bounded(events);
    let metrics = events.as_deref().ok().and_then(build_metrics);
    let result = report(
        root,
        process,
        events,
        errors.as_deref().unwrap_or_default(),
        memory_before,
    );
    // Free-form compiler/Bazel diagnostics remain private local evidence. The
    // public error exports only the actual numeric outcome, fixed classes and
    // bounded coded-error locations from the reviewed source catalog.
    if result.is_ok() {
        ensure!(output.is_ok() && errors.is_ok(), "Bazel log capture failed");
        // Fixed numeric fields only, never the event object, labels, argv or
        // environment. Advisory metrics cannot admit a failed build or replace
        // its existing completion/capture checks. Keep CLI path stdout intact.
        if let Some(metrics) = metrics
            && let Ok(summary) = serde_json::to_string(&metrics)
        {
            eprintln!("BAZEL_BUILD_METRICS_V1 {summary}");
        }
    }
    result
}

pub(crate) enum DiagnosticFormat {
    RustcJson,
    Configured,
}

fn capture_arguments(command: &mut Command, format: DiagnosticFormat, events: &Path) {
    // Keep original structured diagnostics inside the existing private capture.
    // The upstream wrapper otherwise replaces them with free-form rendering.
    // Clippy already configures its own diagnostic outputs; preserve its flags.
    if matches!(format, DiagnosticFormat::RustcJson) {
        command.arg("--@rules_rust//rust/settings:error_format=json");
    }
    command.arg(format!("--build_event_json_file={}", events.display()));
}

pub(crate) fn run(
    root: &Path,
    command: &mut Command,
    budget: Duration,
    format: DiagnosticFormat,
) -> Result<()> {
    let events = tempfile::NamedTempFile::new()?;
    capture_arguments(command, format, events.path());
    capture(root, command, budget, events.path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_preserves_clippy_configuration_and_normal_build_json_diagnostics() {
        use std::ffi::OsStr;
        let original = [
            "build",
            "--config=ci-linux",
            "--aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect",
            "--output_groups=clippy_checks,clippy_output",
            "--@rules_rust//rust/settings:clippy_flag=-Dwarnings",
            "//crates/day2:unit_lib",
        ];
        for format in [DiagnosticFormat::Configured, DiagnosticFormat::RustcJson] {
            let json = matches!(format, DiagnosticFormat::RustcJson);
            let mut command = Command::new("bazel");
            command.args(original);
            capture_arguments(&mut command, format, Path::new("/owned/events.jsonl"));
            let mut expected = original.to_vec();
            if json {
                expected.push("--@rules_rust//rust/settings:error_format=json");
            }
            expected.push("--build_event_json_file=/owned/events.jsonl");
            // Never print arguments or inherited environment on a test failure.
            assert!(command.get_args().eq(expected.iter().map(OsStr::new)));
        }
    }

    #[test]
    fn numeric_metrics_never_export_private_event_fields() -> Result<()> {
        let bytes = serde_json::to_vec(&json!({
            "id":{"buildMetrics":{}},
            "buildMetrics":{
                "timingMetrics":{"wallTimeInMs":"1200","analysisPhaseTimeInMs":200,"executionPhaseTimeInMs":"900"},
                "actionSummary":{
                    "actionsExecuted":"12",
                    "actionData":[{"mnemonic":"Rustc","actionsExecuted":"7","commandLine":"PRIVATE-ARGS"}],
                    "runnerCount":[{"name":"disk cache hit","count":5},{"name":"PRIVATE-RUNNER","count":91}],
                    "actionCacheStatistics":{"hits":3,"misses":2},
                    "environment":"PRIVATE-ENV"
                },
                "privatePath":"PRIVATE-PATH"
            }
        }))?;
        let metrics = build_metrics(&bytes).context("fixed numeric metrics")?;
        assert_eq!(metrics.wall_time_ms, Some(1200));
        assert_eq!(metrics.analysis_time_ms, Some(200));
        assert_eq!(metrics.execution_time_ms, Some(900));
        assert_eq!(metrics.action_requests_including_cache, Some(12));
        assert_eq!(metrics.rustc_requests_including_cache, Some(7));
        assert_eq!(metrics.disk_cache_hit_spawns, Some(5));
        assert_eq!(metrics.local_action_cache_hits, Some(3));
        assert_eq!(metrics.local_action_cache_misses, Some(2));
        let public = serde_json::to_value(&metrics)?;
        assert_eq!(public.as_object().context("numeric object")?.len(), 8);
        assert!(public.as_object().unwrap().values().all(Value::is_u64));
        assert!(!public.to_string().contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn missing_invalid_and_duplicate_metric_counters_remain_unknown() -> Result<()> {
        let bytes = serde_json::to_vec(&json!({
            "id":{"buildMetrics":{}},
            "buildMetrics":{
                "timingMetrics":{"wallTimeInMs":"18446744073709551616","analysisPhaseTimeInMs":-1,"executionPhaseTimeInMs":1.5},
                "actionSummary":{
                    "actionsExecuted":"PRIVATE",
                    "actionData":[{"mnemonic":"Rustc","actionsExecuted":"7"},{"mnemonic":"Rustc","actionsExecuted":"3"}],
                    "runnerCount":[{"name":"disk cache hit","count":5},{"name":"disk cache hit","count":2}]
                }
            }
        }))?;
        let public = serde_json::to_value(build_metrics(&bytes).context("unknown metrics")?)?;
        assert!(public.as_object().unwrap().values().all(Value::is_null));
        let empty = br#"{"id":{"buildMetrics":{}},"buildMetrics":{}}"#;
        let public = serde_json::to_value(build_metrics(empty).context("omitted metrics")?)?;
        assert!(public.as_object().unwrap().values().all(Value::is_null));
        assert!(build_metrics(&vec![b' '; MAX_CAPTURE + 1]).is_none());
        Ok(())
    }

    #[test]
    fn metrics_neither_supply_completion_nor_replace_a_valid_process_outcome() {
        let event =
            br#"{"id":{"buildMetrics":{}},"buildMetrics":{"timingMetrics":{"wallTimeInMs":"12"}}}"#;
        assert!(build_metrics(event).is_some());
        assert!(finished(event).is_err());
        let mut duplicate = event.to_vec();
        duplicate.push(b'\n');
        duplicate.extend_from_slice(event);
        assert!(build_metrics(&duplicate).is_none());
        let mut complete = success_events();
        complete.extend_from_slice(b"\n");
        complete.extend_from_slice(br#"{"id":{"buildMetrics":{}},"buildMetrics":false}"#);
        assert!(build_metrics(&complete).is_none());
        assert!(finished(&complete).is_ok());
        let mut failed = event.to_vec();
        failed.extend_from_slice(
            br#"
{"id":{"buildFinished":{}},"finished":{"exitCode":{"name":"BUILD_FAILURE","code":1}}}"#,
        );
        assert!(build_metrics(&failed).is_some());
        assert!(finished(&failed).is_err());
        assert!(build_metrics(&success_events()).is_none());
    }

    #[test]
    fn public_diagnostics_export_only_fixed_markers_and_bounded_numeric_children() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut log = b"PRIVATE-SDK Permission denied /PRIVATE/ENV=SECRET\n".to_vec();
        for code in 1..=12 {
            log.extend_from_slice(format!("RR_CHILD_V1 code_present=1 code={code} signal_present=0 signal=0 metadata_kill_requested=0\n").as_bytes());
        }
        let error = report(
            root.path(),
            failed(),
            Ok(success_events()),
            &log,
            Value::Null,
        )
        .unwrap_err();
        let display = error.to_string();
        assert!(display.contains("os_access_refused"));
        assert!(display.contains("child_statuses_truncated=true"));
        assert!(!display.contains("PRIVATE") && !display.contains("SECRET"));
        let failure = error.downcast_ref::<Failure>().unwrap();
        assert_eq!(failure.children.len(), 8);
        assert_eq!(failure.process.code, Some(7));
        Ok(())
    }

    #[test]
    fn unknown_private_diagnostics_do_not_create_a_cause_or_escape_the_allowlist() {
        assert!(diagnostic_observations(b"PRIVATE-SDK PRIVATE-ENV PRIVATE-ARGS").is_empty());
        assert_eq!(
            diagnostic_observations(b"PRIVATE sandbox_apply: Operation not permitted"),
            BTreeSet::from(["os_access_refused", "sandbox_initialization"])
        );
        assert_eq!(
            diagnostic_observations(b"error[E0432]: unresolved import PRIVATE"),
            BTreeSet::from(["rust_unresolved_import"])
        );
    }

    fn coded_diagnostic(source: &str) -> Value {
        json!({
            "$message_type":"diagnostic", "level":"error",
            "code":{"code":"E0308","explanation":"PRIVATE-EXPLANATION"},
            "message":"PRIVATE-MESSAGE", "rendered":"PRIVATE-RENDERED",
            "children":[{"message":"PRIVATE-CHILD"}],
            "spans":[{"file_name":source,"is_primary":true,"line_start":17,"column_start":9,
                "text":[{"text":"PRIVATE-SOURCE"}],"label":"PRIVATE-LABEL",
                "expansion":{"span":{"file_name":"PRIVATE-EXPANSION"}}}]
        })
    }

    #[test]
    fn pinned_clippy_codes_export_only_closed_codes_locations_and_preserve_primary() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = "crates/day2/src/lib.rs";
        fs::write(
            root.path().join("architecture-rules.json"),
            serde_json::to_vec(&json!({"version":1,"sources":[source],"allowances":[]}))?,
        )?;
        let codes = CLIPPY_LINT_CODES
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(codes.len(), 832);
        assert!(codes.windows(2).all(|w| w[0] < w[1]));
        for code in [
            "clippy::collapsible_if",
            "clippy::large_enum_variant",
            "clippy::unused_self",
        ] {
            assert!(diagnostic_code_allowed(code));
            let mut diagnostic = coded_diagnostic(source);
            diagnostic["code"]["code"] = json!(code);
            let bytes = serde_json::to_vec(&diagnostic)?;
            let primary = anyhow::Error::new(std::io::Error::other("original build failure"));
            let pointer = primary.downcast_ref::<std::io::Error>().unwrap() as *const _;
            let error =
                clippy_failure_context(root.path(), primary, Some((&bytes, [1, 1, 0, 0, 0])));
            assert_eq!(
                pointer,
                error.downcast_ref::<std::io::Error>().unwrap() as *const _
            );
            let public = error.to_string();
            assert!(public.contains(code));
            assert!(public.contains(source));
            assert!(!public.contains("PRIVATE"));
        }
        for code in [
            "clippy::private_token",
            "clippy::collapsible_if PRIVATE",
            "PRIVATE",
        ] {
            let mut diagnostic = coded_diagnostic("/PRIVATE/other.rs");
            diagnostic["code"]["code"] = json!(code);
            let error = clippy_failure_context(
                root.path(),
                anyhow::anyhow!("original"),
                Some((&serde_json::to_vec(&diagnostic)?, [1, 1, 0, 0, 0])),
            );
            assert!(!error.to_string().contains("PRIVATE"));
        }
        let error = clippy_failure_context(root.path(), anyhow::anyhow!("original"), None);
        assert!(error.to_string().contains("None"));
        assert_eq!(error.root_cause().to_string(), "original");
        Ok(())
    }

    #[test]
    fn clippy_failure_projection_includes_refused_warnings_without_widening_compiler_errors()
    -> Result<()> {
        let source = "crates/xtask/src/bazel.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for level in ["warning", "failure-note"] {
            let mut diagnostic = coded_diagnostic(source);
            diagnostic["level"] = json!(level);
            diagnostic["code"]["code"] = json!("clippy::collapsible_if");
            let bytes = serde_json::to_vec(&diagnostic)?;
            assert!(
                rust_diagnostics(&bytes, &allowed, Path::new("/reviewed"))
                    .records
                    .is_empty()
            );
            let actual = coded_diagnostics(
                &bytes,
                &allowed,
                Path::new("/reviewed"),
                CodedLevels::ClippyRefusals,
            );
            assert_eq!(actual.records.len(), 1);
            assert_eq!(actual.records[0].code, "clippy::collapsible_if");
            let error = clippy_failure_context(
                &root,
                anyhow::anyhow!("actual original failure"),
                Some((&bytes, [1, 1, 0, 0, 0])),
            );
            assert!(error.to_string().contains("clippy::collapsible_if"));
            assert!(!error.to_string().contains("PRIVATE"));
            assert_eq!(error.root_cause().to_string(), "actual original failure");
            assert!(!serde_json::to_string(&actual)?.contains("PRIVATE"));
        }
        Ok(())
    }

    #[test]
    fn full_current_architecture_catalog_admits_a_coded_error_location() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bytes = read_bounded(&root.join("architecture-rules.json"))?;
        let sources = diagnostic_sources(&bytes).context("complete reviewed source catalog")?;
        let source = "crates/xtask/src/build_capture.rs";
        assert!(sources.contains(source));
        let summary = rust_diagnostics(
            &serde_json::to_vec(&coded_diagnostic(source))?,
            &sources,
            &root,
        );
        assert!(summary.catalog_available);
        assert_eq!(summary.records.len(), 1);
        assert_eq!(summary.records[0].location.as_ref().unwrap().source, source);
        assert_eq!(summary.records[0].code, "E0308");
        assert!(diagnostic_sources(&vec![b' '; MAX_DIAGNOSTIC_CATALOG + 1]).is_none());
        Ok(())
    }

    #[test]
    fn coded_errors_export_only_reviewed_locations_and_fixed_fields() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        let bytes = serde_json::to_vec(&coded_diagnostic(source))?;
        let public = serde_json::to_value(rust_diagnostics(
            &bytes,
            &allowed,
            Path::new("/reviewed/workspace"),
        ))?;
        assert_eq!(
            public["records"],
            json!([{"code":"E0308","location":{"source":source,"line":17,"column":9,"kind":"primary"}}])
        );
        assert_eq!(public["rejected_diagnostics"], 0);
        assert!(!public.to_string().contains("PRIVATE"));
        let mut warning = coded_diagnostic(source);
        warning["level"] = json!("warning");
        assert!(
            rust_diagnostics(
                &serde_json::to_vec(&warning)?,
                &allowed,
                Path::new("/reviewed/workspace")
            )
            .records
            .is_empty()
        );
        // No alternate normalizer may turn foreign, generated or absolute
        // compiler locations into a reviewed public source name.
        for foreign in [
            "/PRIVATE/lib.rs",
            "../crates/day2/src/lib.rs",
            "external/PRIVATE.rs",
            "crates/day2/src/PRIVATE.rs",
        ] {
            let summary = rust_diagnostics(
                &serde_json::to_vec(&coded_diagnostic(foreign))?,
                &allowed,
                Path::new("/reviewed/workspace"),
            );
            assert_eq!(summary.records.len(), 1);
            assert_eq!(summary.records[0].code, "E0308");
            assert!(summary.records[0].location.is_none());
            assert_eq!(summary.unlocated_diagnostics, 1);
            assert!(!serde_json::to_string(&summary)?.contains("PRIVATE"));
        }
        Ok(())
    }

    #[test]
    fn invalid_codes_spans_and_catalogs_fail_closed() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        for code in [
            json!("E0308-PRIVATE"),
            json!("E12345"),
            json!("E12x4"),
            json!(null),
            json!(308),
        ] {
            let mut diagnostic = coded_diagnostic(source);
            diagnostic["code"]["code"] = code;
            assert!(
                rust_diagnostics(
                    &serde_json::to_vec(&diagnostic)?,
                    &allowed,
                    Path::new("/reviewed/workspace")
                )
                .records
                .is_empty()
            );
        }
        for bad in [
            json!(0),
            json!(-1),
            json!(1.5),
            json!(4294967296_u64),
            json!("PRIVATE"),
        ] {
            for key in ["line_start", "column_start"] {
                let mut diagnostic = coded_diagnostic(source);
                diagnostic["spans"][0][key] = bad.clone();
                let summary = rust_diagnostics(
                    &serde_json::to_vec(&diagnostic)?,
                    &allowed,
                    Path::new("/reviewed/workspace"),
                );
                assert_eq!(summary.records.len(), 1);
                assert!(summary.records[0].location.is_none());
            }
        }
        let mut secondary = coded_diagnostic(source);
        secondary["spans"][0]["is_primary"] = json!(false);
        let summary = rust_diagnostics(
            &serde_json::to_vec(&secondary)?,
            &allowed,
            Path::new("/reviewed/workspace"),
        );
        assert_eq!(summary.records.len(), 1);
        assert!(summary.records[0].location.is_none());
        let sources = diagnostic_sources(&serde_json::to_vec(
            &json!({"version":1,"sources":[source]}),
        )?)
        .unwrap();
        assert_eq!(sources, allowed);
        for bad in [
            json!({"version":2,"sources":[source]}),
            json!({"version":1,"sources":[source,"/PRIVATE.rs"]}),
            json!({"version":1,"sources":[]}),
        ] {
            assert!(diagnostic_sources(&serde_json::to_vec(&bad)?).is_none());
        }
        let unavailable = rust_diagnostics(
            &serde_json::to_vec(&coded_diagnostic(source))?,
            &BTreeSet::new(),
            Path::new("/reviewed/workspace"),
        );
        assert!(!unavailable.catalog_available);
        assert_eq!(unavailable.records.len(), 1);
        assert_eq!(unavailable.records[0].code, "E0308");
        assert!(unavailable.records[0].location.is_none());
        Ok(())
    }

    #[test]
    fn denied_builtin_lints_admit_only_reviewed_workspace_source_spellings() -> Result<()> {
        let root = Path::new("/reviewed/workspace");
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        for code in ["unused_imports", "dead_code", "unused_variables"] {
            for path in [
                source.to_owned(),
                format!("./{source}"),
                format!("/reviewed/workspace/{source}"),
                format!("/reviewed/workspace/.cache/bazel-executor/execroot/_main/{source}"),
            ] {
                let mut diagnostic = coded_diagnostic(&path);
                diagnostic["code"]["code"] = json!(code);
                let public = serde_json::to_value(rust_diagnostics(
                    &serde_json::to_vec(&diagnostic)?,
                    &allowed,
                    root,
                ))?;
                assert_eq!(
                    public["records"],
                    json!([{"code":code,"location":{"source":source,"line":17,"column":9,"kind":"primary"}}])
                );
                assert_eq!(public["rejected_diagnostics"], 0);
                assert!(!public.to_string().contains("PRIVATE"));
                assert!(!public.to_string().contains("/reviewed/workspace"));
            }
        }
        for foreign in [
            format!("/foreign/workspace/{source}"),
            format!("/reviewed/workspace-other/{source}"),
            format!("/reviewed/workspace/../{source}"),
            format!("/reviewed/workspace/.cache/bazel-executor/execroot/foreign/{source}"),
            format!("./../{source}"),
        ] {
            let mut diagnostic = coded_diagnostic(&foreign);
            diagnostic["code"]["code"] = json!("unused_imports");
            let summary = rust_diagnostics(&serde_json::to_vec(&diagnostic)?, &allowed, root);
            assert_eq!(summary.records[0].code, "unused_imports");
            assert!(summary.records[0].location.is_none());
            assert_eq!(summary.unlocated_diagnostics, 1);
        }
        Ok(())
    }

    #[test]
    fn unknown_lint_codes_and_missing_codes_have_closed_rejection_reasons() -> Result<()> {
        let root = Path::new("/reviewed/workspace");
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        for code in [
            "PRIVATE_TOKEN",
            "private_token_123",
            "unused_imports PRIVATE",
            "clippy::private_token",
        ] {
            let mut diagnostic = coded_diagnostic(source);
            diagnostic["code"]["code"] = json!(code);
            let summary = rust_diagnostics(&serde_json::to_vec(&diagnostic)?, &allowed, root);
            assert!(summary.records.is_empty());
            assert_eq!(summary.rejected_diagnostics, 1);
            assert_eq!(summary.unadmitted_codes, 1);
            assert_eq!(summary.missing_or_non_string_codes, 0);
            assert!(!serde_json::to_string(&summary)?.contains(code));
        }
        for missing in [Value::Null, json!(17), json!({"code":null})] {
            let mut diagnostic = coded_diagnostic(source);
            diagnostic["code"] = missing;
            let summary = rust_diagnostics(&serde_json::to_vec(&diagnostic)?, &allowed, root);
            assert!(summary.records.is_empty());
            assert_eq!(summary.rejected_diagnostics, 1);
            assert_eq!(summary.missing_or_non_string_codes, 1);
            assert_eq!(summary.unadmitted_codes, 0);
        }
        Ok(())
    }

    #[test]
    fn macro_errors_keep_codes_and_only_admitted_bounded_callsite_locations() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        // Observed pinned rustc E0277 shape: the primary span is a toolchain
        // macro definition; only its callsite is a reviewed workspace source.
        let mut diagnostic = coded_diagnostic("/PRIVATE/definition.rs");
        diagnostic["code"]["code"] = json!("E0277");
        diagnostic["spans"][0]["expansion"] = json!({
            "span":{"file_name":source,"is_primary":false,"line_start":3,"column_start":13},
            "macro_decl_name":"PRIVATE-MACRO", "def_site_span":{"file_name":"PRIVATE-DEFINITION"}
        });
        let public = serde_json::to_value(rust_diagnostics(
            &serde_json::to_vec(&diagnostic)?,
            &allowed,
            Path::new("/reviewed/workspace"),
        ))?;
        assert_eq!(
            public["records"],
            json!([{"code":"E0277","location":{"source":source,"line":3,"column":13,"kind":"macro_callsite"}}])
        );
        assert!(!public.to_string().contains("PRIVATE"));
        diagnostic["spans"][0]["expansion"]["span"]["file_name"] =
            json!("../crates/day2/src/lib.rs");
        let public = serde_json::to_value(rust_diagnostics(
            &serde_json::to_vec(&diagnostic)?,
            &allowed,
            Path::new("/reviewed/workspace"),
        ))?;
        assert_eq!(public["records"], json!([{"code":"E0277","location":null}]));
        assert_eq!(public["unlocated_diagnostics"], 1);
        assert!(!public.to_string().contains("PRIVATE"));
        let mut nested = json!({"file_name":source,"line_start":3,"column_start":13});
        for _ in 0..MAX_MACRO_LOCATION_DEPTH {
            nested = json!({"file_name":"PRIVATE-DEFINITION","expansion":{"span":nested}});
        }
        nested["is_primary"] = json!(true);
        diagnostic["spans"][0] = nested;
        let summary = rust_diagnostics(
            &serde_json::to_vec(&diagnostic)?,
            &allowed,
            Path::new("/reviewed/workspace"),
        );
        assert!(summary.macro_depth_limited);
        assert!(summary.records[0].location.is_none());
        assert_eq!(summary.records[0].code, "E0277");
        Ok(())
    }

    #[test]
    fn compiler_diagnostic_bounds_are_explicit_and_never_export_partial_json() -> Result<()> {
        let source = "crates/day2/src/lib.rs";
        let allowed = BTreeSet::from([source.to_owned()]);
        let mut line = serde_json::to_vec(&coded_diagnostic(source))?;
        line.push(b'\n');
        let summary = rust_diagnostics(
            &line.repeat(MAX_RUST_DIAGNOSTICS + 1),
            &allowed,
            Path::new("/reviewed/workspace"),
        );
        assert_eq!(summary.records.len(), MAX_RUST_DIAGNOSTICS);
        assert!(summary.records_truncated);
        let mut oversized = vec![b' '; MAX_DIAGNOSTIC_LINE + 1];
        oversized[0] = b'{';
        oversized.extend_from_slice(b"\n{broken}\n");
        oversized.extend_from_slice(&line);
        let summary = rust_diagnostics(&oversized, &allowed, Path::new("/reviewed/workspace"));
        assert_eq!(summary.oversized_lines, 1);
        assert_eq!(summary.malformed_json_lines, 1);
        assert_eq!(summary.records.len(), 1);
        let summary = rust_diagnostics(
            &vec![b'{'; MAX_CAPTURE + 1],
            &allowed,
            Path::new("/reviewed/workspace"),
        );
        assert!(summary.input_truncated);
        assert!(summary.records.is_empty());
        Ok(())
    }

    #[test]
    fn failed_build_retains_safe_diagnostics_without_replacing_primary_outcome() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = "crates/day2/src/lib.rs";
        fs::write(
            root.path().join("architecture-rules.json"),
            serde_json::to_vec(&json!({"version":1,"sources":[source]}))?,
        )?;
        let log = serde_json::to_vec(&coded_diagnostic(source))?;
        let error = report(
            root.path(),
            failed(),
            Ok(success_events()),
            &log,
            Value::Null,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("original typed failure")?;
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.rust_diagnostics.records.len(), 1);
        assert!(!error.to_string().contains("PRIVATE"));
        let directory = fs::read_dir(root.path().join("artifacts/bazel/failures"))?
            .next()
            .context("retained build directory")??
            .path();
        let outcome: Value = day2::json::decode(&fs::read(directory.join("outcome.json"))?)?;
        assert_eq!(outcome["build_process"]["code"], 7);
        assert_eq!(outcome["rust_diagnostics"]["records"][0]["code"], "E0308");
        assert!(!outcome.to_string().contains("PRIVATE"));
        assert!(
            fs::read(directory.join("stderr.bin"))?
                .windows(b"PRIVATE-RENDERED".len())
                .any(|part| part == b"PRIVATE-RENDERED")
        );
        Ok(())
    }

    #[test]
    fn failed_action_diagnostics_expose_only_current_catalog_owners_and_closed_fields() -> Result<()>
    {
        let allowed = BTreeSet::from(["//crates/day2:unit_lib".into()]);
        let mut bytes = Vec::new();
        for (label, kind, success) in [
            ("@@//crates/day2:unit_lib", "Rustc", false),
            ("//PRIVATE:SECRET", "PRIVATE", false),
            ("//crates/day2:unit_lib", "Rustc", true),
        ] {
            bytes.extend(serde_json::to_vec(&json!({
                "id":{"actionCompleted":{"label":label,"primaryOutput":"/PRIVATE/PATH"}},
                "action":{"success":success,"type":kind,"exitCode":1,
                    "commandLine":["PRIVATE-ARGV"],"stderr":{"uri":"file:///PRIVATE"},
                    "failureDetail":{"message":"PRIVATE-ENV"}}
            }))?);
            bytes.push(b'\n');
        }
        let summary = action_diagnostics(&bytes, &allowed);
        assert_eq!(summary.reported_failures, 2);
        assert_eq!(summary.records.len(), 2);
        assert_eq!(
            summary.records[0].owner.as_deref(),
            Some("//crates/day2:unit_lib")
        );
        assert_eq!(summary.records[0].kind, "rustc");
        assert_eq!(summary.records[0].exit_code, Some(1));
        assert_eq!(summary.records[1].owner, None);
        assert_eq!(summary.records[1].kind, "other");
        assert!(!summary.child_signal_attribution);
        assert!(summary.parse_complete);
        assert!(!serde_json::to_string(&summary)?.contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn failed_action_diagnostics_preserve_limits_multiplicity_and_inconclusive_inputs() -> Result<()>
    {
        let event = serde_json::to_vec(&json!({
            "id":{"actionCompleted":{"label":"//crates/day2:unit_lib"}},
            "action":{"type":"Rustc","exitCode":1}
        }))?;
        let allowed = BTreeSet::from(["//crates/day2:unit_lib".into()]);
        let mut bytes = Vec::new();
        for _ in 0..10 {
            bytes.extend(&event);
            bytes.push(b'\n');
        }
        let summary = action_diagnostics(&bytes, &allowed);
        assert_eq!(summary.reported_failures, 10);
        assert_eq!(summary.records.len(), 8);
        assert!(summary.truncated);
        assert!(summary.parse_complete);
        bytes.extend(b"malformed PRIVATE");
        assert!(!action_diagnostics(&bytes, &allowed).parse_complete);
        let missing = action_diagnostics(&event, &BTreeSet::new());
        assert!(!missing.catalog_available);
        assert_eq!(missing.records[0].owner, None);
        assert!(!action_diagnostics(&vec![b'x'; MAX_CAPTURE + 1], &allowed).parse_complete);
        Ok(())
    }

    #[test]
    fn memory_event_deltas_never_invent_zero_or_identify_a_killed_child() {
        let before = json!({"limit_bytes":6442450944_u64,"oom_kills":3});
        let after = json!({"limit_bytes":6442450944_u64,"oom_kills":4});
        assert_eq!(memory_delta(&before, &after, "oom_kills"), Some(1));
        assert_eq!(memory_delta(&after, &before, "oom_kills"), None);
        assert_eq!(memory_delta(&Value::Null, &after, "oom_kills"), None);
        assert_eq!(
            memory_delta(
                &before,
                &json!({"limit_bytes":1,"oom_kills":4}),
                "oom_kills"
            ),
            None
        );
        assert_eq!(
            memory_delta(&before, &json!({"limit_bytes":6442450944_u64}), "oom_kills"),
            None
        );
    }

    #[test]
    fn public_memory_observations_keep_only_numeric_facts_and_unknown_deltas() {
        let before = json!({
            "limit_bytes": 6442450944_u64,
            "current_bytes": 100,
            "oom_kills": 2,
            "private": "PRIVATE",
        });
        let after = json!({
            "limit_bytes": 6442450944_u64,
            "current_bytes": "PRIVATE",
            "peak_bytes": 6000000000_u64,
            "oom_kills": 3,
            "cause_attribution": true,
        });
        let value = memory_observations(&before, &after);
        assert_eq!(value["oom_kill_delta"], 1);
        assert!(value["oom_events_delta"].is_null());
        assert!(value["after"]["current_bytes"].is_null());
        assert_eq!(value["after"]["peak_bytes"], 6000000000_u64);
        assert_eq!(value["cause_attribution"], false);
        assert!(!value.to_string().contains("PRIVATE"));
        assert_eq!(value["before"].as_object().unwrap().len(), 5);
        assert_eq!(value["after"].as_object().unwrap().len(), 5);
        for snapshot in [&value["before"], &value["after"]] {
            assert!(
                snapshot
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|value| value.is_u64() || value.is_null())
            );
        }
        let changed = json!({"limit_bytes": 8589934592_u64, "oom_kills": 3});
        assert!(memory_observations(&before, &changed)["oom_kill_delta"].is_null());
        assert!(memory_observations(&Value::Null, &after)["oom_kill_delta"].is_null());
    }

    fn failed() -> Outcome {
        Outcome {
            category: "exit",
            code: Some(7),
            signal: None,
            os_error: None,
        }
    }
    fn success_events() -> Vec<u8> {
        serde_json::to_vec(
            &json!({"id":{"buildFinished":{}},"finished":{"exitCode":{"name":"SUCCESS"}}}),
        )
        .unwrap()
    }
    #[test]
    fn nonzero_is_primary_even_with_valid_or_malformed_events() -> Result<()> {
        for events in [success_events(), b"malformed".to_vec()] {
            let root = tempfile::tempdir()?;
            let error = report(root.path(), failed(), Ok(events), b"", Value::Null).unwrap_err();
            assert_eq!(
                error.downcast_ref::<Failure>().unwrap().process.code,
                Some(7)
            );
        }
        Ok(())
    }
    #[test]
    fn success_requires_one_complete_successful_build_event() {
        assert!(finished(&success_events()).is_ok());
        assert!(finished(b"{}").is_err());
        assert!(finished(b"malformed").is_err());
        let mut duplicate = success_events();
        duplicate.push(b'\n');
        duplicate.extend(success_events());
        assert!(finished(&duplicate).is_err());
    }
    #[test]
    fn optional_child_numeric_status_never_replaces_the_outer_process() -> Result<()> {
        let log = b"RR_CHILD_V1 code_present=0 code=0 signal_present=1 signal=9 metadata_kill_requested=0\nPRIVATE RR_CHILD_V1 code_present=1 code=0 signal_present=0 signal=0 metadata_kill_requested=0\n";
        assert_eq!(child_statuses(log).len(), 1);
        let root = tempfile::tempdir()?;
        let error = report(
            root.path(),
            failed(),
            Ok(success_events()),
            log,
            Value::Null,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Failure>().unwrap().process.code,
            Some(7)
        );
        assert!(!error.to_string().contains("PRIVATE"));
        Ok(())
    }
    #[test]
    fn capture_and_retention_errors_stay_secondary() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("artifacts"), b"not a directory")?;
        let error = report(
            root.path(),
            failed(),
            Err(std::io::Error::from_raw_os_error(5)),
            b"",
            Value::Null,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<Failure>().unwrap();
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.capture, Some("read"));
        assert!(!failure.retained);
        Ok(())
    }
    #[test]
    fn timeout_does_not_invent_an_original_signal() {
        let outcome = Outcome::observe(Err(CommandStatusError::Timeout));
        assert_eq!(outcome.category, "timeout");
        assert_eq!(outcome.code, None);
        assert_eq!(outcome.signal, None);
    }
    fn fixture_command(mode: &str) -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "build_capture::tests::real_child_fixture",
                "--nocapture",
            ])
            .env("DAY2_BAZEL_CAPTURE_FIXTURE", mode);
        Ok(command)
    }

    // A subprocess fixture for the controls below, not a separate control.
    #[test]
    fn real_child_fixture() {
        let Ok(mode) = std::env::var("DAY2_BAZEL_CAPTURE_FIXTURE") else {
            return;
        };
        eprintln!("PRIVATE-COMPILER-OUTPUT");
        if mode == "timeout" {
            std::thread::sleep(Duration::from_secs(10));
        }
        std::process::exit(if mode == "success" { 0 } else { 7 });
    }

    #[test]
    fn real_nonzero_is_primary_when_events_are_malformed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let events = root.path().join("events");
        fs::write(&events, b"malformed")?;
        let error = capture(
            root.path(),
            &mut fixture_command("failure")?,
            Duration::from_secs(3),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "exit");
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.capture, Some("events"));
        assert!(failure.retained);
        assert!(!error.to_string().contains("PRIVATE"));

        // Even valid success events and useful metrics cannot override the
        // genuine nonzero child. Exercise the same capture/report wiring.
        let events = root.path().join("metric-events");
        let mut bytes = success_events();
        bytes.extend_from_slice(
            br#"
{"id":{"buildMetrics":{}},"buildMetrics":{"timingMetrics":{"wallTimeInMs":"12"}}}"#,
        );
        private_write(&events, &bytes)?;
        let error = capture(
            root.path(),
            &mut fixture_command("failure")?,
            Duration::from_secs(3),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("real child outcome")?;
        assert_eq!(failure.process.category, "exit");
        assert_eq!(failure.process.code, Some(7));
        assert_eq!(failure.capture, None);
        Ok(())
    }

    #[test]
    fn real_success_cannot_admit_malformed_events() -> Result<()> {
        let root = tempfile::tempdir()?;
        let events = root.path().join("events");
        fs::write(&events, b"malformed")?;
        let error = capture(
            root.path(),
            &mut fixture_command("success")?,
            Duration::from_secs(3),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "success");
        assert_eq!(failure.process.code, Some(0));
        assert!(error.to_string().contains("primary=capture"));
        Ok(())
    }

    #[test]
    fn real_timeout_remains_primary_without_an_invented_signal() -> Result<()> {
        let root = tempfile::tempdir()?;
        let events = root.path().join("events");
        fs::write(&events, b"")?;
        let started = std::time::Instant::now();
        let error = capture(
            root.path(),
            &mut fixture_command("timeout")?,
            Duration::from_millis(100),
            &events,
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "timeout");
        assert_eq!(failure.process.signal, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        Ok(())
    }

    #[test]
    fn real_spawn_failure_retains_errno_without_the_command_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let error = capture(
            root.path(),
            &mut Command::new(root.path().join("PRIVATE-MISSING")),
            Duration::from_secs(1),
            &root.path().join("events"),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<Failure>()
            .context("typed process outcome")?;
        assert_eq!(failure.process.category, "spawn");
        assert!(failure.process.os_error.is_some());
        assert!(!error.to_string().contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn protobuf_defaults_require_an_explicit_consistent_success_name() {
        for exit in [
            json!({}),
            json!({"code":0}),
            json!({"name":"SUCCESS","code":1}),
            json!({"name":"BUILD_FAILURE","code":0}),
        ] {
            let bytes = serde_json::to_vec(
                &json!({"id":{"buildFinished":{}},"finished":{"exitCode":exit}}),
            )
            .unwrap();
            assert!(finished(&bytes).is_err());
        }
        let explicit = serde_json::to_vec(
            &json!({"id":{"buildFinished":{}},"finished":{"exitCode":{"name":"SUCCESS","code":0}}}),
        )
        .unwrap();
        assert!(finished(&explicit).is_ok());
    }

    #[test]
    fn status_parser_refuses_free_text_and_out_of_range_signals() {
        for line in [
            "RR_CHILD_V1 code_present=0 code=1 signal_present=0 signal=0 metadata_kill_requested=0",
            "RR_CHILD_V1 code_present=0 code=0 signal_present=1 signal=65 metadata_kill_requested=0",
            "RR_CHILD_V1 code_present=1 code=7 signal_present=0 signal=0 metadata_kill_requested=0 PRIVATE",
        ] {
            assert!(child_statuses(line.as_bytes()).is_empty());
        }
    }

    #[test]
    fn bounded_private_evidence_never_claims_complete_oversized_capture() -> Result<()> {
        let root = tempfile::tempdir()?;
        report(
            root.path(),
            failed(),
            Ok(vec![b'x'; MAX_CAPTURE + 1]),
            b"PRIVATE",
            Value::Null,
        )
        .unwrap_err();
        let directory = fs::read_dir(root.path().join("artifacts/bazel/failures"))?
            .next()
            .context("retained failure")??
            .path();
        let manifest: Value = day2::json::decode(&fs::read(directory.join("outcome.json"))?)?;
        assert_eq!(manifest["complete"], false);
        assert_eq!(manifest["retained_bytes"], MAX_CAPTURE);
        assert_eq!(
            fs::metadata(directory.join("events.jsonl"))?.len(),
            MAX_CAPTURE as u64
        );
        assert!(!manifest.to_string().contains("PRIVATE"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.join("events.jsonl"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&directory)?.permissions().mode() & 0o777,
                0o700
            );
        }
        Ok(())
    }

    #[test]
    fn memory_diagnostics_are_optional_numeric_kernel_facts() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::write(root.path().join("memory.max"), b"6442450944")?;
        fs::write(root.path().join("memory.current"), b"1234")?;
        fs::write(root.path().join("memory.peak"), b"PRIVATE")?;
        fs::write(
            root.path().join("memory.events"),
            b"oom 2\noom_kill 1\nPRIVATE",
        )?;
        let value = memory(root.path());
        assert_eq!(value["limit_bytes"], 6442450944_u64);
        assert_eq!(value["current_bytes"], 1234);
        assert!(value["peak_bytes"].is_null());
        assert_eq!(value["oom_events"], 2);
        assert_eq!(value["oom_kills"], 1);
        assert_eq!(value["cause_attribution"], false);
        assert!(!value.to_string().contains("PRIVATE"));
        Ok(())
    }

    #[test]
    fn successful_complete_build_creates_no_failure_receipt() -> Result<()> {
        let root = tempfile::tempdir()?;
        let process = Outcome {
            category: "success",
            code: Some(0),
            signal: None,
            os_error: None,
        };
        report(root.path(), process, Ok(success_events()), b"", Value::Null)?;
        assert!(!root.path().join("artifacts").exists());
        Ok(())
    }
}
