# Isolated Bazel/Roc representative experiment

This experiment measures a possible build-system change. It does not replace
production CI, change compiler pins, authorize deployment, or establish a full
platform qualification or speedup.

## Fixed initial source and scope

The initial source is main `78a05f846d85206b53ddf948e4926a46d7a2b187`.
Rust remains `1.98.1`; the native Roc pins, ABI generators, profiles, compiler
admission, worker confinement, and operational recipes remain unchanged.
Bazel `9.3.0` and `rules_rust` `0.74.0` are pinned separately for this experiment.

The representative workload is the actual `xtask` build driver, Reports, and
the existing `day2_integration` executable. Its Reports command-atomicity
selection must execute the exact same registered cases on both build systems.
Compiling the executable is not evidence that any cases ran.

## Staged feasibility gates

1. Linux Rust integration: resolve the unchanged Cargo lock, build real `xtask`
   and the complete existing integration executable with Bazel, and retain
   action graphs, tool identities, profiles, source facts, logs, generated
   metadata and compiler outcomes. Run current source/architecture checks and
   strict Cargo lint first. No runtime, Roc-action cache or performance claim.
2. Native runtime integration: use the built driver to compile Reports through
   its ordinary Roc build recipe and run the selected fresh verification cases.
   Keep mandatory Linux context and native compiler/worker admission. Repeat the
   same feasibility scope on genuine Mac hardware with that target's real pins.
3. Roc build actions: model all declared compiler, SDK, app, resource and native
   inputs and outputs explicitly. Adapt the fixed workspace layout and regular
   source requirements without weakening admission. Prove artifact admission
   after a build-cache hit. A wrapper around an opaque whole-workspace Cargo
   invocation is not an action-level compilation experiment.
4. Controlled comparison: independent backend output/cache directories; a
   baseline build, unchanged rebuild, one Rust edit, one Reports Roc edit, and
   one shared SDK edit. Each mutation starts from the exact baseline bytes and
   restores them. Record invalidation, target/features/profile/host equality,
   binaries, artifacts, actual fresh test statuses, total wall time, runner work,
   cache and transfer overhead. A missing or failed case prevents comparison.

Each gate requires an independently bounded hosted allocation after review of
the concrete source. Stop after an actual failure and all job/tool closure;
diagnose that boundary before allocating another gate. Never use an experiment
receipt as production full or merge-queue reuse evidence.

## Build graph

The dependency resolver consumes the existing workspace manifests and lock.
Local Rust targets use the existing source modules; literal embedded inputs are
declared as compile data. Source-derived Cargo and Bazel feature graphs must be
compared before a timing comparison is admitted: workspace dependency feature
unification may differ even when package versions match.

The initial targets preserve workspace opt-level 1, dependency opt-level 2,
debug-info 0, debug assertions and overflow checks. Actual compiler commands are
authoritative; these declarations alone do not prove equivalence.

The first gate deliberately does not claim a hermetic Roc rule. Current native
builds use regular source files, a fixed workspace, generated ABI files and
explicit runtime paths. Those constraints must be handled by the next gate.

Operational build/verification order remains owned by Roc recipes. Bazel owns
compilation dependency actions. Existing Rust owns native admission and process
enforcement. GitHub Actions provides OS-specific runners and reports evidence.

Runtime, documentation, private outcomes and installation results are never
selected from Bazel's test-result cache. No remote service, runner fleet,
organization setting, queue or production cache is created by these sources.

## Gate-one commands

The isolated diagnostic builds these concrete targets:

```
bazel build //crates/xtask:xtask //crates/day2:day2_integration
bazel aquery --include_param_files --output=jsonproto 'deps(set(//crates/xtask:xtask //crates/day2:day2_integration))'
```

The diagnostic workflow selection edits are temporary and must never be merged.
The source and generated lock/action metadata are retained before any later
integration or benchmark allocation.
