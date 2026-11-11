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
measured. OS/architecture partitions cannot supply another host's executables.
Only trusted main can publish shared Linux actions. Its bootstrap job may publish
the actions it just compiled before queue-proof admission or the full gate. The
separate publisher of completed-test archives still requires an admitted full
proof and exact origin. Pull requests may read trusted base caches; saves from a
PR's Mac compatibility job remain under its isolated PR ref and cannot seed main
or another PR. Existing storage limits and eviction apply; no paid allowance is
enabled.

GitHub release archives fetched by Bazel use the existing checksum-addressed
repository cache, restored before compilation on both hosts. In CI, formatting
uses the same configured Bazel command builder as ordinary builds and queries,
so `@rules_rust//:rustfmt` receives the shared repository and compiled-action
cache flags before the run target and argument separator. It still formats the
complete authored target catalog, with the same check mode and deadline.

This matters during GitHub's anonymous-download incidents: an unconfigured
formatter can fetch a release again even after a successful source-cache restore.
In [run 42568126112, attempt 3](https://github.com/clankernative/platform/actions/runs/42568126112/attempts/3),
the inputs lane restored the main source cache but failed fetching `rules_license`
1.0.0 during formatting. A recent retained source-cache snapshot contains that
archive with its independently checked pinned SHA-256. The formatter previously
omitted the CI cache configuration, so it used Bazel's default cache instead.

Prefer this existing cache path over adding a credential helper for this failure.
The exact dependency-key snapshot stays first; a miss may restore an older
dependency-key snapshot within the same OS/architecture partition. Only the
download cache's `content_addressable` tree is restored, excluding resolved
repository contents and compiled outputs. Bazel checks each requested archive
against its current checksum before use, so older snapshots cannot supply a
different pinned version or replace current verification. Publication scopes,
primary dependency keys and downloader retry limits stay unchanged. No token is added to
Bazel's environment, arguments, repository cache or native build sandbox. A cold
or evicted cache still needs network access. A future authenticated miss path
would need separately reviewed token lifetime and host/redirect scope, a helper
available before Bazel bootstraps, and proof that GitHub authenticates the release
endpoint it uses. This cache correction does not authenticate cold downloads or
make cached compiler/test outcomes authoritative.

Main publishes the Linux bootstrap actions it already compiled. Its queue-proof
fast path skips native preparation, so the separate Linux publisher downloads only
the compiler-action archives from the exact origin run and attempt admitted by
the existing full-proof guard. The origin identifiers are emitted only after
source, latest-attempt, checks and receipt admission succeed. On ordinary full
runs the publisher uses that same run after verification succeeds. It does not
compile again or publish runtime, fixture, documentation or installation
outcomes. All existing verification and native admission remain mandatory.

Linux test preparation retains its completed compiler-action archive after the
ordinary recipe succeeds. The Linux publisher uses the existing test-action keys,
avoiding duplicate snapshots within a branch. All Linux consumers prefer those
keys over older bootstrap-only fallbacks; exact-source keys still take precedence.
A missing archive, including on a
failed-jobs-only rerun with an earlier producer attempt, merely loses this optional
acceleration. It cannot supply a receipt or skip the current verification gate.

Linux preparation, runtime shards and final verification restore only the
existing source-keyed Actions compiler cache before their mandatory current-source
Bazel bootstrap. They do not download compiler-action artifacts from preparation.
A cache miss, error or four-minute restore timeout falls back to ordinary source
compilation. A failed restore first discards its incomplete compiler-cache data;
cleanup failure refuses the job. No cached verifier is installed directly, and
cache status cannot waive compilation, native context, authenticated artifact
selection, source/byte/mode admission or the complete receipt join.

The final compose recipe only joins authenticated evidence; it does not build
fixtures. It therefore does not initialize the optional fixture-output cache or
rebuild a configured verifier just to calculate that cache's identity. The current
source bootstrap, architecture/compiler/proof checks, all prepared executable and
native fixture admission, live producer authentication and complete receipt join
still run. Every other recipe retains its existing fixture-cache behavior, and
the final job still has a separate orchestration deadline. A warm initial bootstrap
does not guarantee an otherwise redundant configured build would stay warm.

In the November 9 sample, PR 433's compose took 2m34s and PR 448's took 2m28s.
PR 446's successful rerun took 12m56s in compose: its captured configured-verifier
build alone took 11m17s, with 568 local action-cache misses and 565 Rust compiler
action requests. Those requests are not a native code-generation count. The
corresponding build in 433 and 448 took about thirteen seconds and one action
request. Both older 446 and 448 merge-group jobs hit twenty minutes after their
architecture checks, before that captured build returned, although their initial
bootstraps took only forty and thirty-six seconds. Their exact unfinished build
outcomes remain unknown. Skipping unused fixture-cache initialization removes the
known redundant build; it does not skip source compilation or reuse test outcomes.
The hosted follow-up must measure the new compose time before claiming a saving.

Preparation and final verification each have a thirty-minute orchestration
budget. The measured cold bootstrap reached 17m31s; admission and output work
takes about five minutes. Four optional cache minutes, one cleanup minute,
eighteen estimated cold-build minutes and five admission minutes total twenty-eight,
leaving orchestration margin. This is an estimate from observed work, not a
worst-case throughput guarantee. The unused configured-verifier rebuild has been
removed from compose, so its former extra budget is unnecessary. These job budgets
do not change any test, provider/native/authority clock, target, filter, concurrency,
memory, swap or PID limit. Runtime shards keep their existing job budgets.

In [453's merge group](https://github.com/clankernative/platform/actions/runs/42670487237/job/129352726024),
two optional downloads of a 3.93 GB archive each reached four minutes, then the
current guard built in 5m35s. The job reached output retention but hit its old
20-minute deadline. Its existing 3.03 GB Actions cache had downloaded in about
28 seconds on the same runner; general bandwidth starvation is not established.
The separate bootstrap snapshot was 3.54 GB and was offered to all six shards
and final verify. Removing those duplicate handoffs avoids about 28.73 GB of
scheduled consumer payload per full entry before retries, plus the bootstrap
snapshot upload. These are scheduled bytes, not completed-transfer measurements.

The [same-source successful PR run](https://github.com/clankernative/platform/actions/runs/42657572318)
had neither compiler artifact: preparation passed in 12m14s and final verify in
11m26s, using ordinary source builds. A successful retained cache can still save
build time, so removal is not a general speedup claim. Actual before/after build
and admission times must be measured. The completed-test archive remains only
for the existing post-full-gate trusted-main publisher; its origin/run/attempt
and full-proof publication rules are unchanged. There is no separate bootstrap
snapshot or compatibility fallback. Prepared programs, native fixtures and test
receipts retain their existing authenticated transport and freshness requirements.

The independent Mac compatibility workflow publishes its own completed compiler actions directly
after native admission in that existing Mac job; no second Mac allocation or queue artifact is
needed. Both platforms retain their OS/architecture partition and source/run/attempt keys.
The publisher runs in the caller's GitHub cache scope: PRs still cannot write
main's cache. The trusted main push is what makes its snapshot available to
later PRs and merge groups. Artifact download has a two-minute deadline and one automatic retry;
cache-only transport/extraction/save failures fall back to normal compilation.
No new server, cloud resource, permission to write repository contents, or paid
storage setting is introduced.

Action snapshots use source/run/attempt keys with same-source, role and host
restoration prefixes; an earlier partial immutable snapshot does not prevent a
later run from saving additional actions. Owned manual measurement runs save
within their branch cache scope.

Compilation reuse never skips a verification campaign. Test result reuse is
disabled with `--cache_test_results=no`. Runtime, documentation, private build
and installation outcomes remain fresh. Isolated Mac builders receive pinned
source/repository snapshots with their environment and network confinement;
they receive no outer action cache or cache-service credentials.

## Hosted verification campaigns

Secret scanning and dependency auditing finish before ordinary native work.
Independent diagnostics can collect repair facts but cannot replace required
checks. The required `verify` job qualifies Linux releases and rejects missing, failed
or skipped preparation and any of the six Linux campaigns. Its receipt has
`scope: linux` in `linux-verification.json`; it makes no claim about native Mac
builds. The required check names and branch protection remain unchanged.

`mac-compatibility.yml` runs independently on pull requests, main pushes and
manual dispatch. It is visible but not required for Linux merges/releases, and
never runs on a merge group. Its separate security jobs use distinct check names.
Mac failure or unavailable runner capacity cannot delay Linux `verify`, artifact
selection or exact-commit queue receipt reuse.

Preparation runs inputs, fixtures and tests jobs concurrently. Inputs retains
formatting, CLI compilation, eight fixture builds, browser checks
and lint. Fixtures builds the remaining eighteen fixtures; all imported-peer
pairs stay in the inputs part in their original order. Both fixture parts retain
their existing compiler and artifact admission, and have separate cache keys.
Tests builds the complete selected normal-program/harness graph once, then
executes documentation tests. The join requires all three authenticated parts,
exact current-run identities, disjoint and exhaustive effects, admitted fixtures and a complete
executable inventory. Missing, swapped, duplicated or foreign parts refuse the
join, including an incomplete second fixture set. Permission-preserving transport records its original run
and producer attempt; it is separate from persistent build caches.

Six Linux campaigns execute the two day2 partitions, control and remaining-package
suites, control simulation and the reviewed parallel compiler probes. The three
Linux sandbox/compilation launchers are a separate mandatory inventory. Their
current bytes, permissions and native target are admitted before installation
beside test supervisors and rechecked after transport. Shards execute the
prepared test programs; their current-source bootstrap builds the admission guard,
not another set of test programs.

The native Apple Silicon lane retains the real isolated-build and installation
campaigns, its source-owned ABI/worker/confinement/formatter/compiler inventory
and all fixture prerequisites. Exact cases must exist in the current executable
with the expected ignored status; zero matches cannot qualify compatibility.
The lane compiles the ordinary default graph and executes its focused campaign
rather than substituting a Linux result. Neither real native campaign is cached.

Linux jobs keep the pinned OCI image, private cgroup without swap, four CPU
allocation, 512 PID limit and bounded artifact/generated tmpfs mounts. Test
preparation alone gets 8 GiB on the existing standard 16 GB Linux runner; the
other preparation parts and runtime shards retain 6 GiB. Setup accepts only
the explicit workflow purposes `standard` and `test-preparation`, checks their
fixed finite ceilings, and records the selected purpose and actual allowance.
This uses existing runner RAM, with no larger-runner allocation. Trusted
setup preserves and rechecks the checked-in ABI seed. Inner compiler/worker
confinement and ELF/glibc/loader admission remain mandatory. This is separate
from the production Mac private builder; no Linux production builder is added.

The four Linux compiler/admission jobs check the container's zero-swap quota
immediately after checkout, before downloading tools, restoring caches or
compiling the verifier. The fixed, quiet read requires a complete `0` line from
`/sys/fs/cgroup/memory.swap.max`; nonzero/unlimited quotas and read errors fail
the step. Its one-minute limit does not change any job deadline. This is an early
runner preflight: the existing Rust context guard still independently checks
zero swap, the private cgroup, purpose-specific memory ceiling and all native
admission requirements after bootstrap. No cgroup or host swap setting is written.

This responds to a rare, recurring hosted-container setup refusal. A survey of
281 Platform runs created in the 72 hours before November 9, 2026 at 07:02 UTC
covered all 294 attempts recorded then: 1,767 completed context checks passed and three refused swap, on three
different runners. All three used Ubuntu image `20261101.360.1` and requested
equal Docker memory and memory-plus-swap limits; passing jobs used that image too.
None logged an unsupported-swap warning. The latest refusal was
[tests preparation on run 42568126112](https://github.com/clankernative/platform/actions/runs/42568126112/job/129021678641):
the request was `8g`/`8g`, but the kernel readback was
`memory.swap.max=max; memory.max=8589934592`. It spent 8m40s before refusal.
The value establishes an unlimited swap allowance, not observed swap use or an
image-wide failure. The earlier two refusals predated quota-value diagnostics.

Retry this setup failure on a fresh hosted allocation, retaining the failed
attempt. Repeating a check in the same unchanged container does not repair its
quota. The early step provides a narrow setup-failure signal; it does not add
automatic reruns or make compiler errors, OOMs or later native failures retryable.
The Docker request is already the
[documented no-swap configuration](https://docs.docker.com/engine/containers/resource_constraints/#--memory-swap-details). Its observed
failure to take effect needs runner/runtime investigation; host-wide `swapoff`
would not establish the required per-cgroup zero quota.

The native join binds checkout/tree, source catalog, workflow, run/attempt and
all required Linux evidence. Snapshots, compiler/configuration identities,
workspace paths and executable digests remain host-specific. The original
campaign budgets and coverage remain required. Retried jobs can consume successful
outputs from earlier attempts of the same run and exact source. They never consume
another run's preparation or substitute a different prepared executable set.

### Rerunning sharded verification

GitHub's **Re-run failed jobs**, individual job reruns and **Re-run all jobs** are
supported. The preparation join, runtime shards and final `verify` job select the
latest successful producer artifact for each required role across attempts of
that same run. Download still has a two-minute deadline and one automatic retry.

The selector authenticates the repository, workflow, run ID, head SHA and latest
attempt, including the actual merge checkout for a pull request. Each immutable
artifact ID must belong to a successful producer job with a matching GitHub
Actions check. Missing, expired, duplicate or foreign artifacts fail admission;
an earlier success cannot hide a newer failed producer. Common metadata and
binary partitions must share their preparation origin, and every Linux receipt
must match the exact prepared-output digest.

Inventory reads require complete bounded pages with unique positive IDs. If a
count and its entries disagree or the count changes between pages, the selector
discards that entire snapshot and restarts from page one, at most three times.
It never truncates extra entries or combines pages from different snapshots.
Malformed identities, duplicates and budget overruns refuse immediately;
persistent inconsistency also refuses. The complete jobs index binds producer
identity and uniqueness. Each selected producer's exact numeric job endpoint
refreshes its current outcome without changing the indexed run, attempt, SHA,
job ID, name, URL or runner labels. Refresh also refuses to erase observed
runner assignment or execution evidence. A known terminal failure cannot be
overwritten by a conflicting success; a fresh failed producer still refuses
older artifacts.

Read-only metadata GETs request revalidation. Only a genuinely closed child with
numeric exit code 1 can retry, at most three requests sharing the original
120-second monotonic budget. Each attempt uses a fresh response file. Spawn,
wait, timeout, other or nonnumeric exit, and malformed or oversized successful
JSON errors refuse without retry. A successful response reporting a failed
producer is not a transport failure and still refuses admission. Diagnostics
identify only the fixed refused field or closed endpoint and numeric exit, never
process arguments, environments, API values or private output.

`ci-artifact-selection.json` in the final verification receipt records the current
consumer and each original producer attempt, job, check, artifact ID and digest.
Earlier receipts retain their execution identity; a retry does not claim that
successful campaigns executed again. The selector rechecks live metadata before
joining all Linux obligations. If a required artifact has
expired, use **Re-run all jobs** to regenerate the complete run.

### Mac runner acquisition

GitHub can cancel a `macos-15` allocation before any runner starts, independently
of the job's six-hour execution timeout. The independent Mac workflow requests one new allocation
only after a read-only API guard authenticates the unique original job in the
same run, attempt and head, cancelled with runner ID zero, an empty runner name,
and no steps. The cheap guard reads the actual API state after the original job
instead of requiring the scheduler's `needs.result` to report `cancelled`.
A completed ordinary success or executed failure emits `admitted=false` and
cannot allocate a retry; only the exact unacquired shape emits `admitted=true`.
The normal workflow-cancellation conditions still apply to both guard and retry.
Partial job inventories, missing or duplicated jobs, wrong heads
and executed failures refuse the retry. Cancelling the entire workflow also
prevents it. The retry uses the identical steps, runner, verification recipe,
cache policy, and source/run/attempt-bound Mac receipt as the original job.

A second acquisition failure leaves Mac compatibility incomplete; test failures
and execution timeouts are not automatically retried. These results remain
visible in the Mac workflow and do not affect Linux release qualification.
`verify-mac` still requires every native case, fixture and both real build
campaigns before publishing `ci-mac-compatibility.json`. The local `verify` full
recipe retains its Mac build campaigns; Linux evidence cannot replace them.

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

Use complete hosted runs on fresh runners. Dispatch the same source/ref first
with `compilation_cache=empty`, then with `compilation_cache=reuse`. The empty
selection performs cache metadata lookup without downloading prior-run action,
fixture or harness snapshots. Repository/tool downloads and transport from the
current preparation jobs remain enabled and must be disclosed. Measure
representative Rust and Roc edits separately. Keep target,
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

PR and merge-group `ci.yml` workflows execute complete Linux qualification. A
main push may instead look up the latest successful merge-group attempt of this
repository's active `ci.yml` workflow at the exact checked-out SHA and tree. Tree
equality under a different SHA is insufficient. Current GitHub run/job/check
identities, required conclusions, Actions app pin and immutable Linux receipt
artifact must all authenticate. The read-only job accepts no caller-selected
repository, URL, workflow, run, artifact or source override.

The bounded JSON receipt carries preparation, compiler/output inventory, all
six Linux campaign joins and `scope: linux` evidence. Current source independently
derives the package/target requirements. It requires exact snapshot, Roc/CI
workflow, host/compiler/configuration, exhaustive fixtures/campaigns, original
timings and budgets. Downloaded executables are never run. API identities are
checked again after admission. Mac evidence belongs to the independent developer
workflow and is neither required nor claimed by Linux receipt reuse.

Any missing, expired, changed, incomplete or unavailable proof, lookup/setup/
download/admission/upload failure selects ordinary complete preparation and
fresh campaigns. Independent cheap checks always execute on current source.
Authenticated reuse is named `reused-trusted-merge-group-linux`; it retains the
original receipts and explicitly records that the main push did not run fresh
runtime campaigns. A passing PR or synthetic test does not establish actual
main-push reuse or a performance result.

References: [Bazel caching](https://bazel.build/remote/caching),
[setup-bazel](https://github.com/bazel-contrib/setup-bazel),
[GitHub cache scopes and limits](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching),
[workflow runs](https://docs.github.com/en/rest/actions/workflow-runs),
[artifact API](https://docs.github.com/en/rest/actions/artifacts).

### Day2 runtime partitions

The day2 binary group serves both `workspace-day2` and `workspace-day2-runtime`;
it is still admitted by exact compiler/preparation identity before either job
executes it. The runtime part runs the integration harness and OAuth lifecycle library
histories; the other part runs the remaining library and bin-unit cases. The
jobs run disjoint actual case inventories, not cached test results. Composition requires both authenticated result artifacts, current
executable inventory equality and complete joined DST observations. A main queue
reuse receipt without the additional part and its completed case evidence refuses.
The binary group is shared transport data; it does not let either part stand in
for the other's fresh runtime outcomes.

## Pinned release archives

Before downloading a GitHub release input, CI restores the exact SHA-256 key
`day2-release-v1-<OS>-<architecture>-<digest>`. A miss uses authenticated
`gh release download` with the job's read-only contents token. Acquisition allows
four retries, five seconds between attempts and at most sixty seconds per attempt;
the complete acquisition step has a two-minute ceiling, including cache I/O.
There is no cross-version restore prefix. Every restored or downloaded file must
pass its current SHA-256 check before use. Only a verified input from a main push
may be published to the shared cache, matching the main-only publication boundary
for compiled actions. PR and merge-group runs only read this cache.

This covers Bazel, OpenTofu, scanners, Temporal, the formatter, and the pinned Roc
and managed UI archives. The original checksum files, archive-size checks,
extraction limits and executable/bundle admission remain mandatory. Roc and UI
capabilities receive fixed digest-named files in `.cache/day2-release`; they
recheck the existing pins and never treat an archive cache as an installed or
verified runtime outcome. Ordinary local callers retain their existing bounded
source-pinned acquisition when no CI input was supplied. Cache absence loses
acceleration; corruption refuses instead of being accepted or silently repaired.

The acquisition action is explicitly included in verification source identity.
Its token is available only to the download step, not to compilers or tests.
