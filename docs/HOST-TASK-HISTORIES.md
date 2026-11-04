# Host task, commit and shutdown histories

The bounded `host_loop::tests::native::execution_histories` campaign runs the
production host loop with real Tokio blocking tasks and real SQLite WAL
transactions. Controlled Work inputs distinguish failure before a write,
returned failure after commit, and a Rust task panic before or after commit.
A failed completion is not evidence that its transaction rolled back.

Four seeded histories run twice. Closed script events choose the pump, result
and stop cut. The independent event reference derives outstanding dispatches,
readiness and drain state without calling the production State transitions.
Independent expected rows and progress derive only from the script. Every cut
compares the complete event prefix, all state observations, committed rows and
execution milestones. The maximum history keeps all sixteen calls and its final
drain cut. This is a bounded sequential task history with a concurrent stop cut,
not arbitrary multi-pump or process scheduling coverage.

Explicit channels order ticks, task entry, release and completion. Shutdown
while a task is already admitted must drain that task, including a later commit.
A native-owner-thread returned failure instead closes admission permanently;
later timer work is not a replacement grant. The tests use the actual private
loop modes but never construct a genuine native execution owner.

The wrong reference assumes a panic after commit erased that row. It must fail
at an actual observation, retain the full prefix, and reproduce twice. Unexpected
observation/driver errors also retain the partial prefix and a separate cleanup
record. A controlled observation refusal proves that an already admitted task
can commit during cleanup; cleanup cannot be described as rollback. Unresolved
cleanup is explicit and cannot pass saved replay. Failure watchdogs bound fixture
waits; they do not assert production timing or hard OS termination.

Records contain only source identity, closed fixture inputs, row numbers,
progress categories and complete observations. They have a two-MiB bound and
are retained at `/tmp/dst-platform-host-loops/task-execution/replay-*.json`, under
the existing failed host-loop CI artifact path. Unknown fields, duplicate fields,
noncanonical shapes, changed source, oversized/truncated inputs and altered
observations refuse. A supplied record is replayed twice and must match both
complete runs. Optional external input being absent is not a saved-corpus pass.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib host_loop::tests::native::execution_histories:: --test-threads=1
DAY2_HOST_TASK_REPLAY=/absolute/path/to/replay.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib host_loop::tests::native::execution_histories::external_task_history_replays_twice_when_explicitly_supplied --exact
```

This exercises task, SQLite and host-loop adapters. A Rust task panic is not a
worker-process crash, and a controlled returned failure is not an observed
worker timeout. Actual Roc/worker, process startup/socket scheduling, native
admission, power-loss durability, live provider and browser qualification remain
separate. Runtime behavior, deadlines and native authority constructors are
unchanged.
