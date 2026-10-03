# Platform Test Fixtures

These are platform-owned test inputs. They exercise shared contracts and failure
boundaries; they are not a catalog of customer applications or company instances.
A fixture may intentionally contain unsafe application logic so a test can prove
that the host rejects it.

## What Lives Here

| Directory | Kind | Purpose and Consumers |
| --- | --- | --- |
| [`control-simulation/`](control-simulation/) | Shared-world regression schedules | Exercises control-journal recovery, ambiguous publication, tenant isolation, and approved release/secret readiness guards. `ops/Simulation.roc` runs the corpus and generated schedules in central CI and verification. These are synthetic provider operations, not customer apps or live-provider qualification. |
| [`row-authority-web-conformance/`](row-authority-web-conformance/README.md) | Runnable conformance fixture | Tests ownership, immutable fields, stale edits, ordinary HTML forms, and Datastar responses. Built by `xtask verify-reports`; used by `owned_web` and the control-plane source/export/isolated-build tests. This is reusable platform test coverage, not a customer application copy or completed GoLinks migration. |
| [`row-authority-adversaries/`](row-authority-adversaries/README.md) | Adversarial source overlay | Replaces the text descriptor and handlers in the staged conformance fixture. Its broader declared rules and hostile handlers must still be constrained by operator policy and mandatory app preconditions. Built by `build-row-authority-adversaries` and verification; consumed by `owned_runtime`. |
| [`command-target-adversaries/`](command-target-adversaries/README.md) | Adversarial source overlay | Replaces command handlers and their effect bounds in a staged copy of Reports. Tests fabricated child targets, changes after a request, writes to another row, and dependent external effects. Built by the historical `build-command-target-adversaries` command and verification; consumed by `command_adversarial` and `command_recovery`. |
| [`relational-conformance/`](relational-conformance/README.md) | Runnable conformance fixture | Three models and a four-write move; consumed by runtime, schema, compiler-guard and no-page API tests. |
| [`migration-add-optional-text/`](migration-add-optional-text/) | Migration source overlay | Adds nullable Deal.note to relational conformance while retaining model identities; consumed by runtime migration tests. |
| [`http-conformance/`](http-conformance/README.md) | Presentation source overlay | Extends the row-authority app with images, a browser module and signed create/edit forms for HTTP lifecycle, audit, session and cache tests. |
| [`delegation-conformance/`](delegation-conformance/README.md) | Runnable conformance fixture | Real session-authenticated on-behalf-of queries/commands, sealed Roc context, cross-app resource delegation, replay and audit. Full verification builds it for `request_identity`. |
| [`oauth-calendar-canary/`](oauth-calendar-canary/README.md) | Runnable registration target | One mapped-human Calendar read requirement and a pure intent query. Full verification builds its admitted artifact for read-only OAuth setup and SQLite checks. Live Google registration and workload/IAM qualification remain separate. |
| [`redirect-conformance/`](redirect-conformance/README.md) | Runnable conformance fixture | The GoLinks redirect shape: `/go/{path..}` and `/{path..}` redirect routes bound to a visit command with exact and wildcard links, beside two page routes. Full verification builds it for `redirect_routes`, which exercises edge admission, authority, audit, precedence, destination refusal and prefetch/fetch-metadata refusal. |
| [`authority-policies/`](authority-policies/) | Test instance policies | Explicit operation, model, row, field, child-command and capability grants for current tests. Rust tests load these policies into their instance bindings. These are reviewed test inputs, not automatic permissions or production company policy defaults. |
| [`company-branding/`](company-branding/) | Test company branding | The asset and HTTP tests build and bind the Example Company brand and licensed logo independently of app artifacts. This is not a global appearance imposed on applications or companies. |

The executable build and test wiring is in
[`crates/xtask/src/main.rs`](../crates/xtask/src/main.rs). Tests under
[`crates/day2/tests/`](../crates/day2/tests/) use the resulting pinned artifacts;
control-plane tests under
[`crates/day2-control/tests/`](../crates/day2-control/tests/) also use
`row-authority-web-conformance` as a concrete source-export and isolated-build
input. Directory names identify the behavior under test, not company app names.
Many smaller fixtures are created in temporary directories directly by their
Rust tests rather than stored here.

## Ownership

The platform owns reusable SDK behavior, the central verification recipe, and
these conformance examples. Each company owns its instance configuration,
approved authority policies and provider bindings, branding, and application
source in its own repositories. Company applications consume the platform; they
do not belong inside this directory merely because they are deployed with it.

Reports is the canonical sibling example currently exercised by the verifier.
The retired CRM/Links suites have an explicit
[coverage and acceptance record](../docs/VERIFICATION-COVERAGE.md), not an implicit
requirement to recreate those repositories. Keep
company-specific acceptance tests with the company-owned source. Add a small
platform fixture only when it proves a reusable platform guarantee or reproduces
a platform regression.

## Verification

From the platform directory:

```text
cargo run --locked -p xtask -- verify-reports
```

The verifier builds ordinary and adversarial artifacts separately, then passes
their locations to tests through `DAY2_TEST_*_ARTIFACT` variables. Migration and
adversarial overlays are applied to staged copies, not to the original example
repositories or existing company databases. Generated artifacts and verification
evidence live under `artifacts/`, not in this directory.
Full `verify` builds and runs the relational, migration and HTTP ports as required
steps. Compiler failures prevent their acceptance; the Reports receipt does not
claim this additional coverage.

When adding a fixture, state the boundary it proves, whether it is a complete app
or an overlay, and which test consumes it. Include a working positive control
alongside rejection cases so an unrelated compiler or configuration failure
cannot make a security test pass accidentally. Keep credentials, customer data,
and production company configuration out of fixtures.
