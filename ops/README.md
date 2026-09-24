# Platform operations

The CLI, operations, SDK and Rust runtime are one platform product. `cli/` owns
arguments and presentation. [Workflow.roc](Workflow.roc) routes operations to
Roc recipes; the recipes select steps, their order, examples, and checks.
[day2-ops](../crates/day2-ops/src/main.rs) supplies native capabilities.
`sdk/` is the only public app API. Apps cannot register operational callbacks.

| Roc source | Operational decisions |
| --- | --- |
| [Build.roc](Build.roc) | Stage → checked schema → bind → admission → ABI → native host → check → link → publish |
| [Check.roc](Check.roc) | Select examples, iterate generated cases, replay, duplicate delivery, invalid inputs, properties and command completion |
| [LocalDev.roc](LocalDev.roc) | Managed development sessions, seed selection, watch/rebuild, checkpoint/migration, recovery and lifecycle commands |
| [Backup.roc](Backup.roc) | Take a consistent snapshot → verify the bundle; verify → restore into a new directory |
| [Authority.roc](Authority.roc) | Inspect active authority; explicitly activate desired grants or an artifact with an expected stamp and retry identity |
| [Infra.roc](Infra.roc) | Construct the resource graph → prepare → version → init → validate → plan → show → receipt |
| [Ci.roc](Ci.roc) | Source-event trigger policy and the mandatory isolated build/admission/check/evidence recipe |
| [Verify.roc](Verify.roc) | Platform fixture selection, regression suites, CLI compilation and verification receipts |
| [Simulation.roc](Simulation.roc) | Run and replay the shared control-world corpus, then generated schedules, before issuing mandatory campaign evidence |
| [Release.roc](Release.roc) | Select the next secret-dependent release step from persisted state; the native host enforces authority and executes it |

Build the distribution inside `platform/` so rustup selects its pinned toolchain:

```console
cd platform
cargo run --locked -p xtask -- cli
cd ..
./cli/day2 platform --help
./cli/day2 platform build examples/reports
./cli/day2 platform check examples/reports 42 16
./cli/day2 platform local-dev examples/reports
```

`xtask cli` builds the Roc CLI, Roc workflow runner, Rust host and source builder together,
records binary/toolchain identities in `cli/distribution.json`, and checks the
pinned compiler. The distribution binaries stay together. This is a source-checkout
distribution on Apple Silicon macOS, not a relocatable production installer.
`xtask workflows` bootstraps just the Roc runner. Rust retains compiler bootstrap,
process supervision, admission, transactions, cryptography and evidence storage.
The `xtask` build/verification commands execute these Roc recipes; they do not
maintain separate Rust recipes. App repositories cannot choose them or pass
arbitrary argv.

[Runner.roc](Runner.roc) runs under a native supervisor and requests one capability
at a time over bounded pipes. Compiler and development state stay in that native
supervisor. A failed effect returns to Roc, whose recipe stops before subsequent
effects. Native evidence guards reject omitted checks. Workflow source and binary
hashes are checked before execution and pinned into the CI recipe/builder binding;
isolated builds receive that same pinned runner. Changes require recompilation.
This is private platform code, with no `automation/sdk` or app effect callbacks.

Every build runs required verification before publishing and selecting an
artifact. `check` and `test` then run a larger campaign in a fresh SQLite instance.
The native host validates typed command/query inputs, checks actual results,
duplicate delivery, rollback and replay, completes requested commands, exercises declared
application failures and evaluates full model property snapshots.
The receipt points to protected `development.json` evidence with artifact, seed,
executed traces, counts and failures. The default is 16 cases per obligation;
requested counts are 1–100 and the complete public-operation campaign is bounded
to 128 steps. Expected and executed obligations must agree. Zero cases cannot
produce a verified receipt. Demo examples are an explicit root choice and are
separate from required operation/error checks.

Reports' examples use generated constructors from its nominal text rules.
Its checks vary Unicode and multiline documents. Rust regression checks independently
check completed byte/line counts. Property assertions that share app code do not
replace independent checks. Seeding always invokes commands and their child invocations.

[Managed local development](LOCAL-DEVELOPMENT.md) builds and watches app code,
keeps local data across restarts, and provides status, stop and logs. It uses
an explicit disposable policy, with
one local actor and broad model grants capped by native constraints. It is not
an instance production-policy template. The underlying Rust harness also accepts
an operator-supplied policy for representative authorization checks. No existing
instance policy or database is rewritten. The foreground server stops on Ctrl-C;
use `--detach` for background operation. Use the printed instance path with
`app describe app --instance PATH` and the backup command below.

```console
./cli/day2 platform backup INSTANCE_PATH app /tmp/reports-backup
./cli/day2 platform restore /tmp/reports-backup /tmp/reports-restored
./cli/day2 platform infra plan platform/infra/local.json /tmp/reports-infra-plan
```

Backups use SQLite's online backup API, preserve the snapshot's active artifact
bundle, and record database/artifact/scope and authority identities. Desired file
edits cannot change the active grants included in a snapshot. Restore verifies
integrity, writes a new instance, rotates its authority epoch, disables grants,
and fences historical invocations. Supply and explicitly activate current policy
before serving; copied backup grants are never fresh approval. See
[transactional authority](../docs/TRANSACTIONAL-AUTHORITY.md). These are local
app data backups, not fleet disaster recovery: company branding, provider/control
configuration and its journal are separate. No cloud secrets are placed in Roc
inputs, command arguments, examples or generated IaC.

[Central CI ingress](../crates/day2-control/src/ci.rs) verifies GitHub HMAC
signatures and installation/repository identity. `Ci.roc` selects branch pushes,
same-repo PR updates, merge groups and check reruns; the adapter creates an exact-SHA request for
the existing durable execution host. Delivery IDs are journaled idempotency keys;
changing the SHA under an existing delivery conflicts. The existing GitHub
adapter fetches the pinned source and publishes `day2 / verification` on that
commit. The mandatory recipe includes the development campaign and its hashed
evidence. There is no app-owned `.github/workflows/check.yml`.

The event receiver is a host integration API. A hosted endpoint, GitHub App
installation, production identity and a qualified Linux runner are still needed
to operate it as a live service. Fork PRs require an explicit source binding.
Existing secret-resolution and source/build adapters remain under `day2-control`;
the [bounded release workflow](../docs/RELEASE-WORKFLOW.md) composes durable
dependency preparation, readiness observations, and guarded activation. Its
provider adapters remain synthetic, not a migration of fleet deployment or secret
mutation. Add qualified provider capabilities to that host, not another app SDK.

Verification is centralized; run these inside `platform/`:

```console
cargo run --locked -p xtask -- verify-fast
cargo run --locked -p xtask -- verify-reports
cargo run --locked -p xtask -- verify
```

The fast recipe is for edit-loop feedback: formatting, workspace lint and
fixture-free library tests only. It issues `artifacts/fast-verification.json`, not a release-quality
receipt. The longer recipes retain native fixture, integration and control-plane
obligations. They reuse a previously completed fixture build only for an exact
unchanged input snapshot; tests and simulations are never resumed from cache.

The Reports campaign covers failure injection into the compiled Roc recipes,
platform libraries, CLI process/compile-fail checks,
real OpenTofu planning, Reports runtime/commands/migrations/HTTP, backup/restore and
the control-plane suites including isolated builds and Temporal restart/replay.
The full verifier additionally builds platform-owned relational, migration and
HTTP conformance fixtures and runs their ported suites. Missing artifacts or failed
tests prevent a passing receipt. See the [acceptance record](../docs/VERIFICATION-COVERAGE.md)
for the required fixtures and evidence scope.
