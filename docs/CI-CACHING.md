# CI compilation caches

Platform CI restores two compilation caches before its first Cargo command.
Every run still executes the existing full verification recipe. Cache hits are
build inputs, never verification receipts or a reason to skip a step.

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

Both actions are pinned to immutable commits. The sccache executable version is
pinned separately. The setup action checks its release archive's SHA-256 checksum.
The repository's `rust-toolchain.toml` remains the Rust version authority.

The dependency cache is saved only after a successful job. Compiler outputs can
be cached as compilation finishes, regardless of later test outcomes. Neither
cache stores runtime state, exported installations, fixture artifacts or completed
verification receipts. Isolated builds retain their cleared environment, private
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
post-job log and summary. Include that overhead in the total, and report failures
or weak cache reuse rather than attributing every timing difference to caching.

Compare total CI time as well as compilation time. Native fixture compilation,
control simulation and runtime campaigns remain substantial costs. A passing
gate establishes correctness; a cache hit rate alone does not establish faster CI.

References: [Cargo cache action](https://github.com/Swatinem/rust-cache),
[sccache action](https://github.com/mozilla-actions/sccache-action),
[Rust cache coverage](https://github.com/mozilla/sccache/blob/main/docs/Rust.md),
[GitHub cache scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
