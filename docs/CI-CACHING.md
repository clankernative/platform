# CI compilation caches

Platform CI restores Bazel action and repository caches before compilation. It
uses a commit-pinned `bazel-contrib/setup-bazel` action and GitHub Actions storage,
restored into the runner's content-addressed disk cache. There is no cache server,
new bucket, paid storage setting, Cargo build cache or sccache wrapper.
`.bazelversion`, `MODULE.bazel` and the reviewed toolchain/profile declarations
bind compiler inputs. [Build commands and profiles](BAZEL.md) describe the graph.

The source-controlled disk-cache garbage-collection settings are size/age targets,
not a hard per-snapshot bound; batch invocations do not establish that idle
collection ran. Actual saved/restored bytes and repository eviction must be
measured. OS/architecture partitions cannot supply another host's executables. Main
pushes and merge-group workflows may publish shared caches. Pull requests may
read their trusted base caches and save only under GitHub's isolated PR ref;
those entries cannot seed main or another PR. Existing repository storage limits
and eviction apply. No paid cache allowance is enabled.

Compilation reuse never skips a verification campaign. Test result reuse is
disabled with `--cache_test_results=no`. Runtime, documentation, private build
and installation outcomes remain fresh. Isolated Mac builders receive pinned
source/repository snapshots with their environment and network confinement;
they receive no outer action cache or cache-service credentials.

## Hosted verification campaigns

Secret scanning and dependency auditing finish before ordinary native work.
Independent diagnostics can collect repair facts but cannot replace required
checks. The required `verify` job rejects missing, failed or skipped preparation,
portable campaigns or Mac obligations.

Preparation runs inputs and tests jobs concurrently. Inputs retains formatting,
CLI compilation, all required fixture builds and lint checks in their existing
Roc order. Tests builds the complete selected normal-program/harness graph once,
then executes documentation tests. The join requires exact current-run
identities, disjoint and exhaustive effects, admitted fixtures and a complete
executable inventory. Permission-preserving transport belongs to that run and
attempt; it is separate from persistent build caches.

Five Linux campaigns execute the disjoint day2, control and remaining-package
suites, control simulation and the reviewed parallel compiler probes. The three
Linux sandbox/compilation launchers are a separate mandatory inventory. Their
current bytes, permissions and native target are admitted before installation
beside test supervisors and rechecked after transport. Shards execute the
prepared programs without rebuilding their platform code.

The native Apple Silicon lane retains the real isolated-build and installation
campaigns, its source-owned ABI/worker/confinement/formatter/compiler inventory
and all fixture prerequisites. Exact cases must exist in the current executable
with the expected ignored status; zero matches cannot qualify compatibility.
The lane compiles the ordinary default graph and executes its focused campaign
rather than substituting a Linux result. Neither real native campaign is cached.

Linux jobs keep the pinned OCI image, private 6 GiB cgroup without swap, four CPU
allocation, 512 PID limit and bounded artifact/generated tmpfs mounts. Trusted
setup preserves and rechecks the checked-in ABI seed. Inner compiler/worker
confinement and ELF/glibc/loader admission remain mandatory. This is separate
from the production Mac private builder; no Linux production builder is added.

The native join binds checkout/tree, source catalog, workflow, run/attempt and
all required Linux and Mac evidence. Snapshots, compiler/configuration identities,
workspace paths and executable digests remain host-specific. The original
campaign budgets and coverage remain required. A retry cannot mix preparation
or outcomes from different attempts.

## Completed build outputs

The `day2-fixtures-v3-bazel` and `day2-test-outputs-v2-bazel` caches contain
completed compilation outputs, not completed verification. Their keys include
OS/architecture, Bazel and compiler inputs, the closed build definitions/patches,
workflow and current source inputs. Fixture prefix restoration may supply an
older candidate; each entry must independently pass current admission. The
whole test-output key has no prefix restoration.

The fixture cache stores content-addressed artifact directories and the existing
format-2 index. `artifacts/bazel-compiler-inputs.json` binds the actual configured
xtask producer and executable bytes with the current Bazel/module/compiler and
platform inputs. Cargo depfiles no longer provide this identity. Missing,
unsupported or changed compiler evidence selects ordinary fresh builds.

Admission loads the candidate and requires complete successful artifact
verification. The same native build adapter re-captures app/overlay sources,
the explicit SDK catalog, Roc compiler, UI package/provider inputs, shared
platform inputs and consumed import contracts. Checked types re-derive the
identity ledger. The complete source map must match, excluding only the native
archive output already bound to its compiler and digest. Missing, added,
changed or invalid inputs rebuild through the ordinary Roc recipe.

Imported fixtures retain their whole verification-snapshot requirement because
they consume a selected peer's disposable oracle. Unrelated edits can reuse only
independently admitted standalone fixture outputs. CLI checks, formatting,
lint, documentation, current joins, source stability and all runtime campaigns
still execute. Private/isolated build outputs and outcomes are excluded.

The test cache contains current harnesses, integration-supporting normal programs,
Linux auxiliaries and their compilation manifest. Successful Bazel build evidence
and actual configured Rust providers must close the inventory. Every declared
producer must match its source, crate name, kind and test identity; every output
must be unique, regular and confined to the owned compiler context. Installed
programs use fixed `build-out` paths with executable permissions preserved.

The architecture gate independently compares every manifest default program,
bin-unit and integration harness against the declared target catalog. Prepared
output admission additionally checks complete package/target sets, source,
workflow, canonical workspace, host/architecture, actual configured compiler,
profile/environment/configuration and executable digests/modes. Missing, extra,
foreign or invalid outputs select full compilation. No timestamps are rewritten
and no runtime result is inferred from a compiler cache hit.

## Measurement

Use complete hosted runs on fresh runners: an empty action-cache run, a restored
warm run of the same source and representative Rust and Roc edits. Keep target,
feature, profile, linker, concurrency, fixtures and test coverage matched. Record
security/queue wait, setup, cache restore/save time and bytes, compilation, fresh
campaign work, final join, critical-path time and runner minutes by OS. Account
for all preparation, shard, Mac and transport work.

Retain actual Bazel action summaries and cache API coverage. Do not convert Cargo
freshness or a warm action hit into a machine-code generation count. Partial
logs, missing counters or overlapping wrappers cannot establish whole-run hit,
miss, error or cost totals. Compiler/bootstrap work and earlier cache activity
must be disclosed before calling a measurement cold. Passing CI establishes
coverage, not a speedup by itself; historical failed/warm experiments remain
separate evidence.

## Exact merge-group receipt reuse

PR and merge-group workflows execute the complete gate. A main push may instead
look up the latest successful merge-group attempt of this repository's active
`ci.yml` workflow at the exact checked-out SHA and tree. Tree equality under a
different SHA is insufficient. Current GitHub run/job/check identities, required
conclusions, the genuine Mac runner label, Actions app pin and immutable receipt
artifact must all authenticate. The read-only job accepts no caller-selected
repository, URL, workflow, run, artifact or source override.

The bounded JSON receipt carries preparation, compiler/output inventory, complete
campaign joins and original full evidence. Current source independently derives
the package/target and Mac-case requirements. It requires exact snapshot,
Roc/CI workflow, host/compiler/configuration, exhaustive fixtures/campaigns,
original timings and budgets. Downloaded executables are never run. API identities
are checked again after admission. A Linux-only receipt cannot stand for the
complete native gate.

Any missing, expired, changed, incomplete or unavailable proof, lookup/setup/
download/admission/upload failure selects ordinary complete preparation and
fresh campaigns. Independent cheap checks always execute on current source.
Authenticated reuse is named `reused-trusted-merge-group-full`; it retains the
original receipts and explicitly records that the main push did not run fresh
runtime campaigns. A passing PR or synthetic test does not establish actual
main-push reuse or a performance result.

References: [Bazel caching](https://bazel.build/remote/caching),
[setup-bazel](https://github.com/bazel-contrib/setup-bazel),
[GitHub cache scopes and limits](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching),
[workflow runs](https://docs.github.com/en/rest/actions/workflow-runs),
[artifact API](https://docs.github.com/en/rest/actions/artifacts).
