# Real worker exchange histories

The private worker history campaign calls the production `Worker::spawn`,
`exchange`, `exchange_bounded`, `terminate` and Drop paths. Disposable fixed
system children provide echo, natural exit and deliberate silence; an absent
path exercises real startup refusal. These are supervisor/pipe/thread checks,
not admitted Roc workers or sandbox/native execution qualification.

The event-only reference owns each transport lifetime, accepted request count,
completed response count and terminal state. Eight generated histories run
twice, including empty frames, multiple requests on one Worker, invalid budgets,
invalid frames, timeout/EOF, terminal reuse, repeated close and explicit fresh
lifetimes. Expected decisions do not read the actual Worker or its counters.
The same selected progress owner must survive all operations in that lifetime.
Once terminated, both request/response channels must remain closed; later calls
must not enqueue or complete another request. Drop must release the final
progress owner after the real cleanup path has joined its threads.

A silent child causes the actual receive watchdog to expire; no manufactured
WorkerTimeout is supplied. That fixture selects an existing permitted two-ms
exchange bound, without asserting wall-time accuracy. Ordinary echo/exit calls
use the unchanged production default of three seconds. A source-AST guard and
mutants pin that real default and its bounded-exchange path. Zero/oversized
budgets must refuse before enqueue and leave a live echo transport usable.

Records retain every selected transport counter and both runs. Actual thread
entry, dequeue, flush and pipe-error observations may vary with OS scheduling;
the independent model checks explicit causal bounds instead of demanding a
fabricated exact schedule. Enqueued/completed counts, actual results, ownership,
terminal state and release are compared exactly on replay. All counters must
become completely stable once termination joins the threads. The saved-input
control changes a later closed snapshot inside the ordinary race bounds and
requires refusal, so normalization cannot hide post-terminal work.

The wrong oracle claims a real typed timeout completed a frame. It must disagree
at that actual call and reproduce twice. Both full observations are retained,
including a disagreement in either run. Replay checks source/platform identity,
canonical closed shapes, duplicate/unknown fields, bounds, operation order and
complete recorded states before starting child work. Invalid input never becomes
an owner or permission. Limits are eight lifetimes, 128 cuts and 512 KiB, with
no sampling or truncated prefix.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib worker::exchange_histories:: --test-threads=1
DAY2_WORKER_HISTORY_REPLAY=/absolute/path/to/replay.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib worker::exchange_histories::external_worker_history_replays_twice_when_supplied --exact
```

Private records use `/tmp/dst-platform-host-loops/worker-exchange/replay-*.json`
and the existing CI retention glob. They contain closed fixture inputs,
response lengths/digests and primitive counters, never environments, process
arguments, error messages, paths or application material. Missing optional
external input is not a saved-corpus pass. This does not model arbitrary OS
startup/socket scheduling, hostile children, native enrollment, live providers,
application effects, resource containment or power-loss durability. No serving
code, production deadline, authority constructor or compiler pin is changed.
