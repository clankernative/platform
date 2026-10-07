# Native local development

From the platform repository root:

```console
./cli/day2 platform local-dev examples/reports
```

Or inside Reports:

```console
../cli/day2 platform local-dev
```

The first launch builds and admits the app, initializes empty SQLite data, checks
its properties, and starts loopback HTTP plus the command scheduler. It prints the
login URL, API origin, instance path, configuration path and log path. No login,
cloud credentials, containers, app startup scripts or production settings are
needed. The platform supplies the development identity (`developer` by default).

The foreground session watches Roc modules, UI files and assets. After a successful
build it pauses requests and command execution, checkpoints the database, applies an admitted
migration to a candidate copy, checks app properties, and serves that candidate on
the same port. Each successfully served build also writes `app-contracts.json` into
the session directory. `--status` reports its path, served artifact digest and file
SHA-256. The export is atomically replaced with mode `0600`; stale output is
removed before attempting export. On failure, status contains only the served
`artifact` and `error` (no successful `path` or `sha256`) without stopping the app.
If stale cleanup fails, a remaining file is not current: consumers must use status
and match its artifact/digest, not infer success from file existence. Refresh the
browser to see the change. Compiler failures keep the
working server available. Migration/property failures return to the previous
instance. Destructive schema changes require an explicit reset or migration work;
they do not silently discard local data. Checkpoint restore clears authentication
sessions and signing secrets; use the newly printed login URL after a cutover.

Checkpoint cutovers explicitly recreate the disposable local resource grants
for the selected actor and recover the copied budget ledger before serving.
Recovery retains recorded consumption and unresolved holds; it does not reset
capacity. A checkpoint with company-backed allocations fails this automatic local
recovery and leaves the previous instance selected. Ordinary `platform restore`
keeps authority disabled and accounting frozen until explicit operator recovery.
Customized active resource grants also stop automatic cutover: budgets, narrower
limits, topics and expiry must be deliberately reviewed and activated for the new
artifact. Rebuild never substitutes an unmetered fixture for a customized grant.

Ctrl-C stops the foreground session. Repeating the command preserves data and
reuses a running session. Use explicit data options to initialize a fresh session:

```console
./cli/day2 platform local-dev examples/reports --reset --example demo
./cli/day2 platform local-dev examples/reports --reset --generated 16 --seed 42
./cli/day2 platform local-dev examples/reports --reset --empty
```

Examples and generated commands go through the shared Roc check recipe, normal
app transactions, durable commands, replay and property checks. Artifact-owned
examples may include internal scheduled commands when the provider host is
simulated; attempts to run those examples with live providers are refused. Internal
commands remain unavailable through HTTP, CLI and MCP. Seeding happens once;
restarts and rebuilds do not duplicate it. `--reset` selects a new managed instance
and retains the old instance/checkpoints. It never deletes an unrelated directory.

For background operation:

```console
./cli/day2 platform local-dev examples/reports --detach
./cli/day2 platform local-dev examples/reports --status
./cli/day2 platform local-dev examples/reports --logs
./cli/day2 platform local-dev examples/reports --follow
./cli/day2 platform local-dev examples/reports --stop
```

Status remains available during builds. Stop cancels an active build and waits for
the session to release its directory lock. Lifecycle commands use a private local
control socket; they never signal a PID read from a stale file. Events and compiler
diagnostics are recorded in bounded local logs.

State defaults to `platform/artifacts/local-dev/<source-path-hash>/`, outside the
app's compiler inputs and Git repository. `--directory /tmp/reports-local` chooses
another managed directory. The same source/directory identifies the session for
all lifecycle commands. `config.json` contains `format`, canonical `source`,
`actor`, `port` and `watch`; it is initialized once and is never overwritten.
`--actor`, `--port` and `--no-watch` override those settings for a launch. Port zero
selects an available port on first launch, then reuses the recorded port. Changing
the actor requires a reset so existing data is not silently re-seeded as someone
else. Stop a running session before changing its settings.

A verified local backup can supply business data:

```console
./cli/day2 platform local-dev examples/reports --reset --backup /tmp/reports-backup
```

The backup must use the same admitted schema, including typed inputs, as the dev
build. Its business rows and IDs are copied into clean local storage. Production authority, sessions,
provider configuration, audit history and pending invocations are not imported. Use app
commands to request new local work. The input bundle stays unchanged. Existing
local `platform backup` and `platform restore` commands remain available.

## Comparison with the previous CLI

| Previous local-dev responsibility | Native equivalent |
| --- | --- |
| Resolve repo; build and launch Compose/native processes | Current directory or SOURCE; admitted native build, HTTP and commands |
| Disposable/persistent local data | Empty first launch, persistent restarts, explicit reset and pure seeding |
| Local identity and environment overrides | Checked local actor/port/watch config; no arbitrary app environment |
| Development rebuilds | Roc-controlled rebuild, checkpoint, migration, property check and cutover |
| Native status/stop/follow | Private session control and bounded logs, including detached mode |
| Backup hydration | Verified local bundle, business data only |
| Registry authentication and .NET/Compose sidecars | No image pull or .NET runtime in this platform |
| Trusted local HTTPS | Loopback HTTP currently; HTTPS remains a separate option to add |
| Fresh/latest remote backup and production secrets | Requires the future authorized provider integration |

The original explicit `local-dev SOURCE NEW_DIRECTORY EXAMPLE` invocation remains
compatible. It creates a single disposable seeded server without managed state or
watching. New development sessions should use the options above.

[LocalDev.roc](LocalDev.roc) owns the workflow and CLI option policy.
[The native capabilities](../crates/day2-ops/src/local_dev.rs) own filesystem,
SQLite, HTTP/command supervision, change detection and local control. Reports defines
no task callbacks or operational SDK.

Native lifecycle and backup tests run in the Reports verification gate. The full
CLI regression test also edits a disposable Reports copy, checks HTTP during a
compiler failure, and verifies data, login and port preservation across rebuilds
and restarts. Run it after building the CLI, with no other xtask build running:

```console
cargo run --locked -p xtask -- cli
cargo test --locked -p day2-ops --test local_dev_cli -- --ignored
```

These commands run from `platform/`. The CLI test is separate from the gate
because its watched builds need the same exclusive platform build lock.
