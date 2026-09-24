# Enterprise capability foundation

This is an executable local control-plane boundary with instance-selected
capabilities alongside the typed Roc command/query runtime. It is not a hosted
service or a claim that all enterprise providers are interchangeable. See
[SDK-CAPABILITIES.md](SDK-CAPABILITIES.md) for the end-to-end authoring walkthrough.

## Ownership

- Roc apps remain pure. No GitHub, Temporal, secret-manager, runner, or raw SQL
  APIs are exposed to apps. Command preparation, decisions and effects use typed
  phase contracts; child commands are requested atomically with local writes.
- `day2-capabilities` contains shared instance and provider-binding contracts.
- `day2-control` owns typed instance profiles, a deterministic release reducer,
  the SQLite execution journal/outbox, and trusted provider composition.
- `durable-temporal` is the private Rust execution adapter. It passes only an
  execution identity and bounded progress/error codes through workflow history.
- Instances select approved bindings. The host calculates revisions from actual
  configurations and inputs; app authors do not supply arbitrary revision strings
  or CI command lines.

The actual installation `instance.json` now contains an optional `control` section
for release workflows. `control.apps` can reference only installed apps;
each app receives a separate repository binding and worker task queue. The legacy
build-plan helper remains for journal tests, not as a second installation config.
`day2-control --bin control` consumes this same file. Its mandatory `--local` flag
identifies a local operator assertion, not authenticated network identity. A
production authenticated control-plane service and approval flows remain gates.

`Service::authorize` returns an opaque app handle. Source exports, change proposals,
build submission/status, and provider-only secret resolution require that handle.
Operators select provider configuration; app authors never supply provider URLs,
repositories, tokens, build recipes, queues or revision digests.

## Execution

```text
Instance profile + app + exact commit + request identity
  -> accepted BuildPlan + dispatch outbox + audit event (one transaction)
  -> ensure-start of an identity-bound Temporal workflow
  -> bounded GitHub source read + protected source snapshot
  -> private platform-controlled Roc build and admission
  -> artifact-bound verification evidence
  -> GitHub check publication or reconciliation
  -> terminal journal receipt
```

The pinned plan includes company/app/request identity, exact Git commit, source
binding, trusted builder binding, platform input digest, recipe digest, and
durable runtime binding. A duplicate request with different inputs is rejected.
Changing instance defaults cannot redirect an existing request.

The pure `kernel::State::observe` reducer validates evidence identity and the
required transition order. The SQLite journal commits effect completion, state,
and audit together. Time is an explicit input to the journal and simulator;
production observes host time before and after external work. Leases fence stale
journal completions. They are not a claim that GitHub implements fencing tokens.
Rejected builds produce separately bound failure evidence and publish a failed
check before reaching their terminal failed state. Source/authorization failures
can terminate earlier when publication authority is unavailable.

No journal transaction remains open during an external call or native build.
An expired or uncertain external mutation is reconciled. In particular, a missing
GitHub check after an ambiguous POST does not authorize another POST. This trades
automatic progress for avoiding duplicate remote mutations when the provider has
no atomic idempotency key. Cancellation cannot erase an uncertain outcome.

## Provider scope

| Area | Implemented now | Still required |
| --- | --- | --- |
| Source | Real local company-owned Git exports/proposal branches with atomic base checks, CLI recovery and app-scoped authority; existing GitHub exact-commit fetch/check adapter | GitHub export/PR provider, merge approval, Gitea/GitLab adapters, live enterprise qualification |
| CI | Instance-selected local build service; generated exact pins; offline acceptance; Temporal execution; isolated Roc build/admission; immutable checked artifact/evidence receipts | Hosted/BYOC Linux execution, production attestation/signing, resource quotas, full per-app state-machine certification, external CI integrations |
| Secrets | Instance-selected GCP numeric versions; app-scoped provider-only logical references; CRC32C verification; injected host access-token provider | Workload-identity bootstrap/refresh implementation, provisioning/rotation workflows, live GCP qualification, other managers |
| Identity | Existing local development authentication remains unchanged | IAP, Entra, Okta and directory-fact/entitlement adapters |
| Database | App SQLite transactions with a durable command journal, plus a separate durable SQLite control journal | Shared SQLite/PostgreSQL semantic conformance, PostgreSQL implementation, HA profiles and restore/failover proofs |
| Durability | Rust SDK 1.0.0; real persisted local Temporal; deterministic IDs; outbox deduplication; activity retries; worker/server restart and history replay tests | Production TLS/identity/placement, operational recovery after exhausted retries/timeouts, complete run-chain history retention and upgrade qualification |

All provider configuration and token resolution is host-owned. GCP access tokens
are injected explicitly; this adapter does not search the environment, run
`gcloud`, load developer ADC credentials, or query metadata automatically.
Secret values have redacted Debug implementations and no serialization API.
Their values are not workflow inputs, source inputs, or build environment values.
This first resolver supports bounded token-shaped credentials, not arbitrary
binary secret payloads. Endpoint and secret-version mappings participate in the
source binding revision, so changing either requires a new admitted binding.
GitHub App token issuance/refresh is not implemented by storing an already-issued
token in Secret Manager; the production credential adapter must own that lifecycle.

## Local runner boundary

The verified target remains Apple Silicon macOS. The trusted Rust supervisor
executes only the pinned platform recipe. Roc compilation and native workers keep
their existing separate sandboxes; the fixed Cargo host-build step has its own
network-denied private-job sandbox. macOS rejects nested sandbox application, so
an outer sandbox around all of xtask is not used or claimed.

App sources are materialized into a fresh directory. Builds have independent
generated files, Cargo homes, dependency caches, targets and output directories.
Credential/config files from Cargo home are excluded. Every copied approved input
is rehashed, including the runner, supervisor, Rust toolchain and registry cache.
The host OS and Xcode remain trusted prerequisites, not fully hermetic inputs.

The local recipe checks compilation/admission, the loaded artifact, application
examples/generators and properties, plus the mandatory control-plane simulation
campaign. Reports is the canonical current app acceptance fixture. Full verification
also requires the ported relational, migration and HTTP conformance suites. Their
[acceptance record](VERIFICATION-COVERAGE.md) defines the required fixture builds
and native checks; the Reports campaign does not qualify those additional suites.

Build logs, source snapshots, artifacts and property snapshots are protected local
objects. They can contain application source or application data; they are not a
redacted enterprise audit export. Production access control, encryption and
retention for these objects remain required. Digests are integrity identifiers,
not signatures or authorization by themselves.

## Verification

The [deterministic control-plane lab](DETERMINISTIC-LAB.md) runs bounded shared
provider worlds against the production host and SQLite journal, including
cross-execution recovery and the [secret-dependent release workflow](RELEASE-WORKFLOW.md).
Its corpus
and generated schedules are separate evidence from the real-Temporal tests below.

`cargo run --locked -p xtask -- control-verify` runs the capability suites, real
persisted Temporal tests and the explicitly pinned native isolated-build smoke.
Full `xtask verify` includes this gate, builds the relational, migration and HTTP
conformance fixtures, and runs every runtime suite. Every required step must pass
before it issues a full-verification receipt. `verify-reports` executes a narrower
gate without claiming those additional conformance checks.
Temporal CLI 1.6.1 (local server 1.30.1), the pinned Rust toolchain, Roc compiler,
Xcode and an already fetched Cargo registry are prerequisites. Missing prerequisites
fail verification; they are not silently replaced by an in-memory implementation.

The evidence is intentionally separated:

- Pure reducer and real-SQLite tests inject transaction failures, lease expiry,
  cancellation, duplicate completion, conflicting evidence and concurrent claims.
- A fixed-seed property campaign generates crash/reopen/duplicate schedules against
  an independent transition-order reference. Failing seeds persist to
  `artifacts/control-journal-regressions.txt` and are replayed on later runs.
- GitHub and GCP adapters run against HTTP fixtures, including malformed responses,
  credential boundaries, corruption and uncertain mutations. No live provider write
  is performed by verification.
- Real Temporal tests hard-stop and restart its persisted server, reconstruct the
  worker/host, lose acknowledgements and replay actual histories. Their provider
  effects are explicitly simulated, not evidence of a live GitHub deployment.
- A separate native test builds the
  [row-authority web conformance fixture](../fixtures/row-authority-web-conformance/README.md)
  through the real isolated recipe, checks the resulting artifact/evidence, and
  reopens the durable receipt.
- A second native test loads installation capabilities, exports actual source to
  company-owned Git, accepts a build while Temporal is stopped, restarts Temporal
  and runs the isolated build through its worker to a terminal receipt.
- Compiled Roc command tests cover atomic child acceptance, replay, captured
  revisions, authority changes, provider acknowledgement loss and completion.
  Adversarial apps probe forged targets and mutation after child acceptance.
  App command execution uses SQLite and does not require Temporal.

The local Temporal workflow has a one-hour execution limit and bounded activity
retries. Exhaustion can leave a nonterminal journal entry requiring operator
recovery. The adapter does not fabricate completion or silently restart a failed
execution with new bindings. Its history helper returns the latest run; production
retention must preserve every continue-as-new run and pinned implementation.
The build host records bounded, deduplicated diagnostic codes. Release provider
faults also use redacted codes, but release diagnostics are not uniformly
deduplicated. Incoming worker configuration is checked as well as dispatch configuration.
If the journal itself is unavailable, recording diagnostics is necessarily best
effort; the underlying execution is not reported as completed.

## Next acceptance gate

The bounded release workflow and shared simulation now provide concrete adapter
obligations. Validate those assumptions against small real-provider sandboxes
next, while retaining replayable regressions and generated schedules as gates.
Complete Linux deployment qualification before a
disposable GCP canary. Identity, deployment/IaC, provider conformance, and the
SQLite/PostgreSQL semantic contract remain explicit gates before production app
ports or cutover; passing the lab does not waive them.
