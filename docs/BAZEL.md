# Building and verifying with Bazel

Bazel is the platform's Rust build executor. Bazelisk selects the version in
`.bazelversion`; `MODULE.bazel` pins rules_rust and the Rust compiler. Install
Xcode Command Line Tools on Apple Silicon. Linux images keep their existing
pinned Debian, linker and runtime-library inputs.

Cargo manifests and Cargo.lock describe dependency inputs for crate_universe.
They are also read by dependency governance and the vulnerability audit. They do
not define a second platform build/test entry point. Compiler profiles live in
`.bazelrc`, `build/bazel/rust.bzl` and the reviewed rules_rust patches.

## Commands

Run these from the platform checkout:

```console
bazel run //crates/xtask:xtask -- bootstrap
bazel run //crates/xtask:xtask -- cli
bazel run //crates/xtask:xtask -- fmt-check
bazel run //crates/xtask:xtask -- verify-fast
bazel run //crates/xtask:xtask -- verify
```

Roc still owns verification and operational recipe order. The Rust backend
builds the declared targets and admits their actual configured outputs, then the
ordinary recipes execute the current campaigns. A compiled harness is not a
successful test run. Full verification still requires its fixtures, ignored
native build campaigns, genuine Mac checks and complete evidence.

For a focused Rust test, use the checked harness entry point. It builds the
selected test and supporting programs, then runs from the workspace directory:

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:day2_integration command_atomicity:: --test-threads=1
bazel run //crates/xtask:xtask -- build-rust-test //crates/day2:unit_lib
```

For a focused Apple Silicon private-builder diagnosis after bootstrap, use
`bazel run //crates/xtask:xtask -- verify-private-build-probe`. The Roc recipe
prepares the normal CLI and executes the existing real isolated-build case in
its current integration harness. It uses the ordinary pinned offline builder,
sandbox and admission, and publishes no full verification receipt. Compiler
failure messages expose only fixed observations, bounded numeric child
statuses and failed action owners found in the current platform target catalog.
Unknown/external owners stay absent; action kinds use a closed vocabulary. The
uploaded outcome includes bounded numeric cgroup snapshots before the build and
at failure, with nondecreasing OOM-counter deltas when the limits match. These
are cgroup observations, not attribution of a signal or OOM to a particular PID
or action. Free-form app/SDK diagnostics, command lines and environment values
remain protected local evidence.

The second command only compiles and prints the admitted executable path. It
runs no cases. The first accepts declared test labels and bounded libtest
filters/options. It does not prepare missing native fixtures or turn ignored
cases into ordinary tests.

Programs are installed under `build-out/bin`, harnesses under `build-out/tests`
and worker archives under `build-out/lib`. Run installed operator programs
from your own working directory to preserve relative instance/artifact paths.
The xtask Bazel entry point restores the original invocation directory itself;
ordinary `bazel run` changes a program's directory to its runfiles tree.

## Inputs and profiles

`build/bazel/targets.json` records the normal programs, libraries and harnesses.
The architecture gate compares it with every manifest-declared default target;
missing programs, bin-unit harnesses, integration harnesses or extra targets
refuse qualification. Actual configured Rust providers must also match each
record's source, name, type and test identity before output installation.

Development workspace crates use optimization level 1; dependencies and build
tools use level 2, with assertions and overflow checks enabled and debug info
disabled. Native non-incremental builds leave codegen partitioning at the
compiler default; Linux CI applies its existing explicit256 and disabled-LTO
test settings to target units while build tools retain their own defaults.
The Linux test-preparation job also supplies an empty private GNU jobserver FIFO
through `CARGO_MAKEFLAGS`, which the CI configuration forwards to compiler
actions. Each compiler keeps its one implicit slot; no extra backend jobs can
acquire a token. This constrains LLVM concurrency inside one rustc process,
which Bazel's `--jobs=1` alone does not constrain. Codegen partitioning,
optimization, assertions, overflow checks and the complete target set stay the
same; the container memory allowance is not increased.
Debug-disabled compilation strips debug information as before. Linux selects the existing GNU binutils linker instead of Bazel's
default deprecated gold selection. Release programs and native worker archives retain the previous release
panic/profile policy; build tools keep their separate build-override profile.
The distribution image additionally strips executable symbols as before.

The reviewed dependency contexts distinguish native Linux x86_64, Linux ARM64
and Apple Silicon targets from build tools. Verification uses the complete
all-target feature graph. `--config=production` excludes development dependencies
and their feature additions; the native archive and distribution commands select
it together with the release compiler profile. Release test harnesses still
unwind panics. Their source models are checked against actual configured actions.
Cross compilation is not qualified by a
successful native build. Cargo metadata alone does not establish compiler,
build-script dynamic-value or runtime equivalence.

Dependency changes require reviewing both native feature contexts, updating the
crate_universe lock and refreshing `build/bazel/cargo-context-inputs.json` only
after the derived declarations have been reviewed. That descriptor binds every
workspace manifest, Cargo.lock and both context tables. The verifier refuses a
changed, missing or extra input rather than silently using stale feature data.
Refreshing checksums alone does not establish that a feature model is correct.

The private Mac builder receives only the pinned standalone Bazel binary,
byte/mode-pinned source inputs and prefetched repositories. The selected system Xcode bundle or CommandLineTools directory is resolved through
the fixed OS selector and validated before granting its trusted dependency-builder
read/execute access; other application paths remain refused. Its ordinary
filesystem/network confinement and native admission still apply. It receives
neither operator build caches nor credentials; no Linux production builder port
is introduced. Preparation omits Bazel's generated output-base bridge and copies
only dependency aliases that resolve inside the same approved vendor tree into
regular files. It rejects escaped targets, directory cycles, credentials, VCS
metadata and special files, then pins exactly the prepared repositories. The
private loader still refuses every alias and rechecks the complete byte/mode
manifest under its existing input limits. This does not certify a hostile or
concurrently changing filesystem.

## Native images

The Native image qualification workflow executes the existing `qualify-linux`
Roc recipe and separately builds the native enrollment runtime image. It runs
on Dockerfile/workflow pull-request changes and supports manual dispatch. Its
artifacts contain image identities and public qualification receipts; protected
operation logs remain local to the job. It adds no installation prerequisite or
cloud resource. Ordinary full platform CI retains its existing test selection.

The tooling image keeps its reviewed worker ABI seed outside the generated-output
tmpfs and installs it inside the running container. Docker archive copy does not
support tmpfs destinations. Fresh glue generation still compares exact bytes
against that seed before the Bazel worker archive is built; no pin is inferred or
changed and all native confinement limits remain mandatory.

## CI cache and measurements

The commit-pinned setup-bazel action persists Bazel action/repository caches in
GitHub Actions storage. Compiled-output snapshots use exact checkout commit plus run/attempt keys with
same-source, same-role and OS/architecture fallbacks. Each run can save newly
compiled actions, including when a previous immutable snapshot was partial. A Rust-only edit can save new actions
without discarding reusable prior actions. Valid compiled actions may be saved
after a later fresh-runtime failure, while cancelled runs do not save them.
The native preparation builders, main's Linux verifier bootstrap and the
post-verification Mac cache publisher write these snapshots; consumer jobs restore them. Each runner restores its OS/architecture partition into
the local content-addressed disk cache. Trusted main/merge-group runs may save
shared outputs. PRs can read trusted base caches and save only their own
GitHub-isolated pull-request cache scope; they cannot seed the main branch. There is no new cache server, bucket
or paid storage setting. Eviction within the existing repository allowance can
reduce hits.

When main reuses exact queue proof, the Mac publisher transfers only compiler
actions from that fully admitted origin run and attempt. Other events publish
their own completed Mac actions after the full gate. Missing or failed cache
transport is a cache miss, never an alternative verification result. See
[cache publication](CI-CACHING.md) for the branch boundary.

The ordinary Roc verification recipes execute the complete patched compiler-wrapper
control module on Linux and Mac. The Mac campaign also executes the actual trusted
builder outside-file and network refusal control. These are permanent gates.

Test results are never reused (`--cache_test_results=no`). Runtime, private,
docs and installation outcomes remain fresh and source-bound. Prepared native
outputs have their existing complete-inventory and byte/mode admission before
transport; a cache archive alone does not qualify them.

For a controlled full run, dispatch CI with `compilation_cache=empty` to skip
downloading all prior-run compiled-output snapshots. Fetched repositories and
current-run transport stay enabled. Repeat the same source/ref with
`compilation_cache=reuse` to measure restored compiled outputs. Both modes run
the same fresh verification campaigns; neither asserts empty tool/download caches.

Report queue/setup, restore/save, compilation, fresh test work, runner minutes
and the critical path separately. A warm action hit is compiled-output reuse,
not test execution or a count of generated machine-code actions. The migration
PR remains unqualified for a speedup until matched full Linux/Mac runs retain
those measurements and unchanged verification coverage.

References: [Bazel run and test behavior](https://bazel.build/docs/user-manual),
[Bazel caching](https://bazel.build/remote/caching),
[setup-bazel](https://github.com/bazel-contrib/setup-bazel).
