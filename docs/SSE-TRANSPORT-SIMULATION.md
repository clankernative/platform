# SSE transport lifecycle histories

The `transport_histories` module in `web_live_simulation.rs` extends the existing
refresh-decision campaign through the production `LiveBody`. It uses actual
bounded Tokio data channels, an independent terminal channel and explicit polls
with a counting waker. No wall-clock sleeps, sockets, browser, worker, database or
native execution owner is required.

Thirty-two generated seeds plus fixed seed 71 each execute an 87-event history
twice in fresh channel worlds. A mandatory prefix covers queued-data revocation,
pending-reader wakeups, saturation and producer loss, receiver cancellation,
terminal-channel cancellation and a new independent connection. The generated
suffix varies operations across all five connections. A final drain checks all
remaining queued frames and stable termination; it does not silently stop at an
earlier closed stream. Reopening an existing fixture connection label is refused
by the harness; a reconnect receives a new channel and fresh initial fixture.

The reference model owns its queue, terminal priority, lifecycle and delivery
history. It never polls a production receiver to choose expected results. Every
cut compares actual decisions and polls, queue length, producer/receiver state,
terminal wiring, permanent termination and delivered frames for every connection.
When a pending poll must become ready, the actual waker must be notified. Extra
notifications are allowed and recorded; their count is not an authority proof.

Production `elements` encodes the fixture frames. An independent strict SSE
parser checks one event, the exact mode/data fields and the reconstructed public
fixture input. CR/LF and forged-looking field text must remain inside that one
event. A source-AST control also binds the fixture to the actual Host factory's
one-slot queue, terminal receiver, initial frame and `LiveWork` senders, and the
production producer's saturation exits and terminal-classification/send path.
Mutants alter those actual production locations and must fail the control.

A deliberately wrong oracle that releases queued data before terminal clearing
must disagree at the real poll, retain its complete expected/actual prefix and
reproduce the same failure. Both replay prefixes are retained when an ordinary
history fails or differs between runs. Records contain only public synthetic
frame inputs, closed decisions and transport state; no session, token, provider
body or native-owner material is captured. The two-MiB replay input uses the
shared strict JSON decoder, rejects unknown/duplicate fields, and binds the
compiled transport and campaign sources. Programs are limited to 128 events,
five connection labels and sixteen patch values. This slice does not minimize
counterexamples.

Run with the normal pinned verifier:

```text
build-out/bin/xtask test-rust //crates/day2:unit_lib web::live::simulation_tests::transport_histories:: --test-threads=1
```

Set `DAY2_WEB_TRANSPORT_REPLAY` to a retained record to compare it with two fresh
executions. Absent input is optional and is not a saved-corpus pass. Retained
records live under `/tmp/dst-platform-host-loops/live-transport/replay-*.json`,
within the existing failed workspace-day2 host-loop artifact retention glob; no
new CI channel or policy allowance is introduced.

These are bounded transport/component histories. Revocation is a controlled
terminal notification, not a constructed authentication or native authority
proof. The existing refresh campaign separately checks pre/post-render session
and policy decisions. This does not qualify the full Host producer loop,
real HTTP scheduling, Datastar/browser DOM behavior, live native OAuth/SSE
ownership, arbitrary provider parity or kernel containment. Those remain
separate conformance obligations.
