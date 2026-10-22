# CI compilation caches

Platform CI restores two compilation caches before its first Cargo command.
Compilation cache hits are build inputs and never a reason to skip verification.
The separate exact merge-group receipt admission described below can reuse a
complete full outcome on the identical landed main commit.

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

`day2-platform-ci-linux-v1` is the Linux dependency/compiler namespace; the focused
Mac lane retains `day2-platform-ci-v2`. OS and architecture remain cache inputs.
Neither lane can admit the other host's executables.
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
total verify job duration, initial Cargo preparation, the 29 recipe step timings,
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

The secret scan and dependency audit finish before CI starts ordinary compilation
or looks up a main-push queue receipt. If either fails, preparation and runtime
campaigns do not allocate runners. The required `verify` job runs its failure
guard on Ubuntu; skipped preparation cannot produce a successful full check.
This avoids spending native compilation time on already-rejected changes. Passing
runs retain the full gate and incur the initial security-check wait.

Hosted `diagnostics` remains independent of those checks so maintainers can
generate and review a dependency repair when the original lockfile fails audit.
Diagnostics never qualify a source or replace any required check.

CI preparation runs two jobs concurrently. The inputs job retains the full
recipe's formatting, CLI, twenty-one fixture builds and lint checks, including all
fixture dependency ordering. The tests job compiles the ordinary complete Cargo
test package and target graph once, then runs documentation tests. The preparation
join requires both exact current-run manifests, disjoint and exhaustive effects,
all fixture identities and the complete executable inventory. It re-admits every
transported executable digest and native fixture before publishing the combined
workspace. Missing, swapped, incomplete or foreign parts fail preparation. The
prepared binaries and fixtures travel in a permission-preserving archive scoped
to one Actions run attempt; this is separate from the dependency/compiler caches.

`Verify.roc` selects seven hosted campaigns. Five run on native Linux x86_64:
disjoint serial day2, control and remaining-package tests, control simulation,
and the reviewed four-thread compiler probes. Their ordinary default package,
profile, target and filter inventories remain complete. The three Linux sandbox,
compiler-sandbox and probe launchers are a separate mandatory inventory: built
once in preparation, byte/mode/ELF-admitted and transported at their fixed native
sibling paths. Shards never Cargo-build these launchers again.

One focused native Mac ARM64 job runs the real isolated-build and installation-build
campaigns because the production build sandbox supports that host. It also runs
an explicit source-owned inventory of native ABI, worker lifetime, confinement,
formatter and compiler cases, including all three connection-use probes. Each
exact case must exist in the actual Cargo harness with its expected ignored status;
zero matches cannot qualify compatibility. The Mac job compiles the ordinary
default graph once but runs this focused inventory instead of the full workspace
runtime suite. Its native Reports, Reports-probe, relational and OAuth-calendar
fixture prerequisites, compiler, executables and fresh case outcomes have separate
evidence. Installation and private build outcomes are uncached.

Linux jobs use the pinned Rust OCI image on Ubuntu with a finite private cgroup,
6 GiB memory/no swap and bounded owned artifact/generated tmpfs directories.
Trusted outer CI setup creates those mounts and preserves the exact checked-in
worker ABI seed across the generated-output mount. Each Linux job retains its
current cgroup, mount and seed-digest evidence. Inner native compiler and worker
Landlock/seccomp, memory and fixed launcher admission remain mandatory; this
is not a port of the production Mac isolated Cargo builder. Native ELF/glibc/loader
inputs are independently re-captured before fixture cache admission.

The required `verify` job fails if either preparation part, any portable campaign,
or the Mac job fails or skips. Its native join binds exact checkout/tree, closed
source catalog, workflow, run and attempt across both domains. Native snapshots,
workspace paths, compiler/configuration identities and executable digests remain
host-specific. The joined proof carries the mandatory Mac preparation, compiler,
focused cases and two real campaign receipts inside the existing six JSON proof
files. Missing, foreign or incomplete native evidence fails admission. All 29
steps and twenty-one Linux fixtures remain required; the combined Linux workspace
campaign keeps its original 12,600-second budget.

Manual `Platform CI` dispatch selects `sharded` for this complete mixed-host
pipeline or `diagnostics` for independent hosted formatting and inventories.
The earlier same-host comparison modes are removed. Local `xtask verify` retains
its ordinary native maintainer recipe. Rerun every job when retrying a workflow;
run-scoped preparation and case outcomes cannot mix attempts.

Measure security wait through final join, starting preparation at the earliest
selected native job. Include both Linux preparation jobs, their join, five
portable campaigns, the focused Mac job, final verification, setup, queues and
all transfers. Report Linux and Mac runner work separately. Historical Mac-only
timings do not qualify this source or establish a mixed-host speedup.

## Completed build outputs

Preparation jobs use separate `day2-fixtures-v2` and `day2-test-outputs-v1`
GitHub caches. Fixture keys retain shared platform, SDK, compiler configuration,
workflow, host and architecture inputs as a common prefix. A source-specific
suffix saves changed app and fixture trees separately. Prefix restoration may
supply older fixture outputs; native admission decides each selected entry.
The ordinary test output cache keeps its complete reviewed source key and has
no prefix restoration. Dependency and compiler caches remain separate from these completed-output keys.

The fixture cache contains only content-addressed artifact directories and the
format-2 fixture index. Cargo's ordinary compiler dep-info captures embedded
non-Rust inputs, and the current xtask executable digest binds the compiler
adapter. Its source closure and the existing Rust/Cargo/C compiler, profile,
environment, workspace and CI workflow identity must match before reuse.
Missing or unsupported compiler evidence disables reuse and selects normal builds.

Each candidate is loaded and its complete successful artifact verification
required. The same native build adapter re-captures its current app and overlay,
explicit SDK catalog, pinned Roc compiler, locked UI package/provider inputs,
platform source hashes and consumed import contract. Its identity ledger is
re-derived against the admitted checked types. The resulting complete source
map must equal the artifact's source map, excluding only the host archive output
already bound by the worker digest and exact compiler identity. A missing, added,
changed or invalid input rebuilds through the original fixture recipe.

Imported fixtures retain their per-entry whole verification snapshot requirement
because their build verification consumes a selected peer's disposable oracle.
An unrelated source edit may reuse independently admitted standalone fixtures;
it still rebuilds imported fixtures. CLI checks, formatting, lint, documentation,
all runtime campaigns, current-run preparation joins and whole-source stability
checks execute normally. This change does not narrow ordinary test target keys
or cache private/isolated build outputs.

The test cache contains completed ordinary test harnesses, the normal programs
Bazel builds for integration tests, and their compilation manifest, without run
receipts or runtime state. Cargo’s authoritative compiler messages and fresh
metadata must close both inventories. Supporting programs are cached separately
from Cargo’s ordinary output directory; only admitted programs are restored to
the exact `CARGO_BIN_EXE_*` paths with executable permissions preserved. The
current-run preparation join and every campaign re-admit their byte digests and
exact executable permissions. Linux auxiliary programs are admitted separately.
Native admission checks the
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

## Exact merge-group receipt reuse

PR and merge-group workflows always execute the complete gate. A main push first
looks for the latest merge-group run of this repository's active `ci.yml` workflow
at the exact checked-out SHA and tree. A different SHA with an identical tree is
insufficient. Authenticated GitHub metadata must show a completed successful
latest attempt, all ten successful required jobs and their actual GitHub Actions
app15368 checks, plus the successful actual `verify-mac-compatibility` job with
its native runner label and app pin, and its unexpired immutable full-receipt artifact. This job has
only contents, Actions and checks read permissions; it accepts no caller-selected
repository, URL, workflow, run, artifact or source override.

The small receipt artifact carries both preparation parts, prepared inventory,
compiler-input manifest, seven-campaign join and original full verification
receipt. Native admission requires the exact current snapshot and Roc/CI workflow,
host/architecture, canonical workspace, compiler/config/profile identity, fresh
Cargo metadata for all default targets and supporting programs, exhaustive fixture
and campaign evidence, original step timings and campaign budgets. Downloaded
proof is read as confined bounded JSON; its executables are never downloaded or
run. The authenticated latest run, jobs, checks and artifact identities are checked
again after artifact admission. The current source independently derives the Mac
snapshot and exact native case/target requirements; a Linux-only receipt cannot
be reused as a complete full outcome.

Missing, expired, foreign, incomplete, changed or unavailable proof selects
ordinary complete preparation and all seven fresh campaigns. A setup, lookup,
download, admission or reuse-artifact upload failure also selects that fallback.
The required `verify` job succeeds only after either the full preparation and all
campaigns succeed, or the exact receipt-admission job succeeds and its proof is
transported. The other nine required checks always run on the current source.

Reused evidence is named `reused-trusted-merge-group-full` and retains the original
run/attempt and all original receipts alongside the current run identity. It
explicitly records that this main push did not execute fresh runtime campaigns;
it is not a new full execution or a cross-source performance result. Actual
end-to-end reuse must be observed after an explicitly user-queued eligible PR
lands. A passing PR full gate or synthetic admission test alone does not establish
that runtime receipt. No unrelated merge is needed to qualify the implementation.

The [workflow-run API](https://docs.github.com/en/rest/actions/workflow-runs),
[artifact API](https://docs.github.com/en/rest/actions/artifacts) and pinned
[artifact download action](https://github.com/actions/download-artifact/tree/d3f86a106a0bac45b974a628896c90dbdf5c8093)
provide the authenticated metadata and cross-run artifact transport.
