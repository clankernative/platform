# Day2 CLI

The Roc CLI now belongs to the platform repository and shares its Rust workspace,
lockfile, toolchain and verification. Arguments, discovery validation, presentation
and operational composition are Roc. The private Rust host owns native effects.
See [platform operations](../ops/README.md) for ownership, commands and limits.

From the platform repository root:

```console
cd platform
cargo run --locked -p xtask -- cli
cd ..
./cli/day2 app describe links --demo
./cli/day2 app describe reports --instance example-instance/instance.json --agent
./cli/day2 platform --help
./cli/day2 platform check examples/reports 42 16
./cli/day2 platform local-dev examples/reports
```

The distribution contains `day2`, `day2-host`, `day2-workflows`, `xtask`,
`day2-workflows.json` and `distribution.json`.
Keep its binaries together. It currently requires this source checkout and Apple
Silicon macOS. The pinned upstream basic-cli 0.22.0 provides the native Roc CLI
host; platform operations call only the adjacent Day2 Rust broker, never an
executable found on a project's PATH. It is a versioned private protocol, not an
app SDK. `platform/ops/Workflow.roc` routes to the individual Roc recipes.
The native supervisor executes their bounded capability requests; the same
recipes also drive native `xtask` callers and centralized CI.

`app describe` retains detailed text and `--agent`/`--json` discovery output.
Its versioned envelope contains outcome, context, operation input/output types,
errors and executable argument arrays for suggested actions. Parsing remains
bounded to 128 UTF-8 arguments/16 KiB. Metadata has a 1 MiB, 32-level, 20,000-value
budget and rejects duplicate decoded keys. Names and complete catalogs are
checked before filtering; opaque Roc types protect checked values.

Instance discovery now consumes a read-only projection from the shared Rust
`Instance` decoder, including current control/background contracts. Unknown
provider fields are rejected. Current artifacts pass runtime admission
before their metadata is projected; legacy metadata is still readable without a
current-artifact guarantee. Typed command results, cursors, page sizes and
CollectionPage results are described. Private job completions are omitted from
the public operation catalog. Discovery does not grant invocation authority or
perform remote authentication. Its conservative `artifact_integrity` label remains
`not_verified` for compatibility across legacy/current discovery responses.

Platform operations return JSON receipts, with errors on stderr and a nonzero
exit. `local-dev` prints a login URL, watches app edits and serves until Ctrl-C.
It preserves local data; `--reset` explicitly starts a fresh managed instance.
Use `--detach`, `--status`, `--stop`, `--logs` and `--follow` for background sessions.
`check`/`test` report reproducible evidence paths. Backup and restore preserve
online SQLite data and artifact identities. IaC currently qualifies a local
OpenTofu resource subset. See [coverage](COVERAGE.md) for outstanding integrations.

`platform authority inspect` reads active database authority. `authority apply`
and `authority activate` require a local operator assertion, expected authority
stamp and request ID; desired file edits alone never authorize running work.
Restores rotate the authority epoch and disable grants until current policy is
explicitly activated. See [transactional authority](../docs/TRANSACTIONAL-AUTHORITY.md).

`platform authority admin INSTANCE LOCAL_OPERATOR` starts the separate local
resource administration service. Reusable policies, scoped handles, durable
approvals, allocations and recovery are described in
[Resource enforcement](../docs/RESOURCE-ENFORCEMENT.md). The `platform resources`
commands expose the same enforced authoring/review actions for operator workflows.

Verification belongs to the platform:

```console
cd platform
cargo run --locked -p xtask -- verify-reports
```

This includes native CLI process tests, positive/negative Roc compilation,
malformed metadata, current Reports discovery and a real pinned OpenTofu plan.
The broader `xtask verify` additionally builds and tests the platform's relational,
migration and HTTP conformance fixtures. Their [acceptance status](../docs/VERIFICATION-COVERAGE.md)
defines the required native checks; a Reports-only receipt does not cover them.
There is no independent CLI Cargo workspace or lockfile.

See [managed local development](../ops/LOCAL-DEVELOPMENT.md) for repo defaults,
watch/rebuild, persistent data, examples, backup import and lifecycle commands.
