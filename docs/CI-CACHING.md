# CI compilation caches

Platform CI restores two compilation caches before its first Cargo command.
Every gate retains the full verification recipe's checks. Cache hits are build
inputs, never verification receipts or a reason to skip a step.

`Swatinem/rust-cache` restores Cargo registry downloads, Git dependencies and
compiled dependency outputs in the workspace target directory. Workspace crate
outputs and Cargo-installed tools are excluded. Its keys include the runner OS
and architecture, Rust compiler versions, Cargo manifests and lockfile, toolchain
configuration and compilation environment. Commit SHAs are deliberately absent,
so a source edit can reuse dependencies. Cargo still checks artifact freshness.

`sccache` uses GitHub Actions storage for matching Rust library compilations,
including workspace libraries that Cargo recompiles after a fresh checkout.
`RUSTC_WRAPPER` applies only to the hosted verification job. Incremental compilation
remains disabled. Linked binaries, test executables and proc macros are outside
sccache's Rust cache coverage; their compilation and linking still run.

The hosted job disables sccache's idle shutdown so its compiler statistics survive
the long runtime campaigns. This setting is confined to the disposable CI runner;
it does not change compiler inputs, the cache namespace or local configuration.

Both actions are pinned to immutable commits. The sccache executable version is
pinned separately. The setup action checks its release archive's SHA-256 checksum.
The repository's `rust-toolchain.toml` remains the Rust version authority.

The dependency cache is saved only after a successful job. Compiler outputs can
be cached as compilation finishes, regardless of later test outcomes. Neither
cache stores runtime state, exported installations or completed verification
receipts. Separate source-bound caches below store completed fixture and test
compiler outputs. Isolated builds retain their cleared environment, private
target directories and offline Cargo inputs; they receive no cache service token
or compiler wrapper from the outer job.

## Scope and invalidation

GitHub allows PRs to read their base/default branch's caches. A cache written by
one PR is scoped to that PR and cannot seed other PRs or `main`. The first
successful run on `main` populates the shared base cache; later PRs can reuse it.
The first run in an empty namespace is still cold.

`day2-platform-ci-v2` is the dependency cache prefix and compiler cache namespace.
Change both only when deliberately retiring a cache generation. Toolchain,
dependency and compiler input changes already invalidate the corresponding
entries automatically; do not add a commit SHA or run ID to either namespace.

The initial v1 seed failed in a live-update test after writing compiler outputs.
The test now finishes its executor-local fault before starting the HTTP scheduler
and asserts that rollback preserves both the live revision and application data.
The v2 generation starts empty so that failed run is not used as a cold baseline.

## Measurement

Use complete hosted verification runs on fresh runners:

1. Seed the empty cache namespace and retain its full log.
2. Rerun the same commit in the same PR scope after the seed run completes.
3. Measure a small Rust source change in that same scope while keeping the
   compiler, manifests, lockfile, features and profile fixed.

For each run, record its exact head, runner/toolchain, all verification outcomes,
total verify job duration, initial Cargo preparation, the 28 recipe step timings,
cache restore/save durations and archive size. The compiler cache action publishes
hits, misses, non-cacheable requests, cache errors and read/write timings in its
post-job log and summary. An idle server restart can reset these counters; an
empty or partial report does not establish whole-job hit, miss or error counts.
Include that overhead in the total, and report failures
or weak cache reuse rather than attributing every timing difference to caching.

Compare total CI time as well as compilation time. Native fixture compilation,
control simulation and runtime campaigns remain substantial costs. A passing
gate establishes correctness; a cache hit rate alone does not establish faster CI.

## Hosted verification campaigns

CI preparation runs two jobs concurrently. The inputs job retains the full
recipe's formatting, CLI, twenty fixture builds and lint checks, including all
fixture dependency ordering. The tests job compiles the ordinary complete Cargo
test package and target graph once, then runs documentation tests. The preparation
join requires both exact current-run manifests, disjoint and exhaustive effects,
all fixture identities and the complete executable inventory. It re-admits every
transported executable digest and native fixture before publishing the combined
workspace. Missing, swapped, incomplete or foreign parts fail preparation. The
prepared binaries and fixtures travel in a permission-preserving archive scoped
to one Actions run attempt; this is separate from the dependency/compiler caches.

`Verify.roc` selects seven hosted campaigns: disjoint serial day2, control and
remaining-package tests, control simulation, the reviewed four-thread compiler
probes, isolated build and installation build. The test binaries receive the
same libtest filters and fixture environment as ordinary full verification.
Each binary runs from its Cargo package directory. Compiler inputs, package/target
graph, worker limits and isolated-build environment remain unchanged.

The required `verify` job fails if preparation or any campaign fails or skips.
Its native admission also requires all seven receipts from the same checkout,
source snapshot, workflow, run attempt, host and workspace path, plus unchanged
test executable hashes and admitted fixtures. Missing test targets, effects or
timings prevent a full receipt. It joins the original 28 steps and twenty fixtures;
the combined workspace campaign retains its original 12,600-second budget.
Rerun the entire workflow when retrying: partial job reruns cannot mix prepared
artifacts and successful receipts from different attempts.

Manual `Platform CI` dispatch supports `serial-prepare` for the original sequential
preparation followed by the same seven campaigns, `full` for the ordinary `xtask verify`
recipe, `compare` for both pipelines on one checkout, and `diagnostics` for hosted
formatting and admission inventories. Diagnostics provide no verification claim.
Use complete prepare-to-join timestamps for sharded latency, including queue,
archive, upload/download and setup costs. The short join job's duration is not
the full gate duration; joined step timings sum campaign work across hosts.
The additional runners also increase runner minutes. Qualify correctness and
measure that cost before claiming a latency improvement.

Compare `serial-prepare` and `sharded` on the exact same checkout and cache scope,
one complete workflow at a time. Start the preparation clock at the first selected
preparation job, including the two-part join, queues and every artifact transfer.
Include both preparation jobs in runner minutes. The parts are run-scoped outputs,
not cross-run caches; no runtime outcome is reused by this change.

## Completed build outputs

Preparation jobs use separate `day2-fixtures-v1` and `day2-test-outputs-v1`
GitHub caches. Their immutable action pin and content keys include the host,
architecture, workflow and complete reviewed source directories, manifests,
lockfile and toolchain inputs. They have no prefix restore keys or commit/run
IDs. Each selected preparation job saves its own outputs only on job success;
the dependency and compiler cache namespaces remain unchanged.

The fixture cache contains only content-addressed artifact directories and the
existing source-snapshot fixture index. That index is admitted against its
format, scope and current full input snapshot. Each selected artifact is loaded
again, its identity checked, and complete successful artifact verification
required. Missing, stale or invalid entries rebuild through the original fixture
recipe. CLI checks, formatting and lint still execute.

The test cache contains completed ordinary test executables and their compilation
manifest, without run receipts or runtime state. Native admission checks the
current full source snapshot, embedded workflow, canonical workspace, host and
architecture, actual Rust/Cargo/C compiler versions, compiler/profile environment
digest and repository Cargo configuration. Fresh Cargo metadata must match every
default target and package directory. Every executable must be unique, regular,
within the ordinary Cargo output directory and match its recorded byte digest.
An unavailable or invalid cache compiles the original complete target graph.
Valid outputs produce a new current-run inventory and preparation receipt;
documentation tests and all seven runtime campaigns execute fresh. Source changes
invalidate the completed-output proof. No source timestamps are rewritten to
claim Cargo freshness, and isolated/private-target builds remain uncached.

These caches can reduce repeated compilation on unchanged sources, including
queue/push checkouts with the same inputs. A small source edit may still rebuild
the completed outputs; the existing library/compiler cache handles matching
compilation requests. Measure complete cold/warm runs, a nonfunctional Rust edit
and restored-tree final qualification in one cache scope before reporting a
speedup. Retain archive sizes, save/restore costs, current-source admission,
coverage, compiler counters and complete pipeline latency and runner work.

References: [Completed output cache action](https://github.com/actions/cache/blob/0057852bfaa89a56745cba8c7296529d2fc39830/README.md),
[Cargo cache action](https://github.com/Swatinem/rust-cache),
[sccache action](https://github.com/mozilla-actions/sccache-action),
[Rust cache coverage](https://github.com/mozilla/sccache/blob/main/docs/Rust.md),
[Pinned server idle behavior](https://github.com/mozilla/sccache/blob/v0.18.0/src/server.rs),
[GitHub cache scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
