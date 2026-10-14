# Public verification coverage

`ops/Verify.roc` is the executable regression policy. `xtask verify` builds only
the public Reports example and fixtures under `fixtures/`. It runs platform,
SDK, CLI, real SQLite, native worker, HTTP, authority, migration, simulation and
Temporal tests, including isolated build/receipt recovery checks.

`xtask verify-fast` is a narrower edit-loop gate. `xtask verify-reports` exercises
the teaching example and selected platform contracts. Neither replaces the full
gate. Receipts are written under ignored `artifacts/` and name their input snapshot;
historical receipts are not evidence for a modified source tree.

The shared lint capability also runs `xtask architecture-check`. Its explicit
source catalog and reviewed ambient-effect allowances are in
`architecture-rules.json`; the policy bytes enter build and verification
fingerprints. New/increased effects, unknown sources and obsolete exceptions
fail the gate. See [the structural rollout](PLATFORM-STRUCTURAL-RULES.md) for
enforcement scope and the remaining dependency/proof/runtime slices.

Private app migrations and company acceptance tests belong to downstream private
repositories. Passing this public gate makes no claim about those applications.
Linux kernel/runtime qualification is a separate native campaign documented in
[the runtime guide](../deploy/linux-sqlite/README.md).

Current artifacts declare one property-verification profile: 10,000 facts in
total, at most 10,000 rows per model, 32 MiB of encoded snapshot data, 512 MiB of
live Roc-owned allocation layouts and a 30-second evaluation deadline. The
`worker_heap_bytes` quota includes ABI allocation prefixes; alloc/realloc reject
excess before allocating, and deallocation returns that quota. This is not a
whole-process RSS or address-space guarantee: Rust protocol frames have separate
length bounds, and system mappings and allocator overhead are outside Roc heap
accounting. Ordinary properties capture only live rows through a privately
constructed snapshot contract. Operation verification captures separate
live/deleted views in one SQLite read transaction; their combined facts and
bytes share the declared budget. Overflow fails rather than truncating state.
Generated decoders enforce the same bounds.

Property evaluation requires the current artifact contract and the qualified
native profile on macOS or Linux. Both enforce the Roc heap quota, framed
protocol bounds and host evaluation deadline; neither falls back to ordinary
invocation limits. Linux additionally enforces a 512 MiB process address-space
ceiling and a CPU-time bound through its sandbox launcher. macOS does not claim
that process-wide address-space ceiling. Other hosts refuse evaluation. The
native worker allocator tests reject aggregate/growing/oversized allocations;
the shared property-worker suite exercises larger frames, 10,000 typed rows and
artifact-bound replay on both supported hosts. Linux resource-limit tests remain
separate. Passing host-side budget tests alone does not qualify native behavior.

OAuth's required seeded host/protocol campaigns, effect-boundary guard, catalog
coverage gate, implementation-bound replay, and durable schema upgrades are
documented in [OAuth simulation and durable invariants](OAUTH-SIMULATION.md).
They run in both library gates and complement real adapter/crash qualification.

Private native host-loop campaigns share the production supervisor reducer and
retain source-bound event histories with independent-oracle snapshots. Replay a
saved history from the repository root with:

```console
DAY2_HOST_LOOP_REPLAY=/absolute/path/to/trace.json cargo test --locked -p day2 --lib host_loop::tests::replay_saved_host_loop_history -- --exact
```

Campaign evidence prints this command with its exact saved path. The reader admits
only regular files of at most 1 MiB, at most 132 events, a supported format and the
current reducer source identity; malformed or divergent evidence fails. Replay
preserves the saved file and checks the supervisor decisions against recorded
snapshots and the independent oracle. Native SQLite, Tokio timer and blocking-task
conformance remain separate tests; decision replay does not repeat native work or
reproduce database/provider effects.

The synthetic runtime-input fixtures retain source-bound histories for scoped ID
seeds, generated IDs, wall/elapsed clocks, phase deadlines, and complete selected
pages and cursor rows in real SQLite. Each history saves its inputs before
execution and atomically checkpoints observations and failure position after
each step. Fixture and native-step errors and panics retain their cause and stage.
The producer prints the exact command for either history type:

```console
DAY2_RUNTIME_INPUT_REPLAY=/absolute/path/history.json cargo test --locked -p day2 --lib store::input_replay_tests::replay_saved_runtime_input_history -- --exact
```

Replay checks recorded observations and the independent fixture expectations,
including every remaining step of an interrupted history. It preserves the
input file and refuses stale source/fixture identities, unknown formats or
fields, duplicate JSON keys, invalid failure positions, and excessive input
sizes. Reads use one regular-file descriptor with a one-MiB byte limit and one
lookahead byte; histories contain at most 16 actions. These host-input fixtures
do not replay native Roc worker execution, OS watchdog timing, or provider I/O.
