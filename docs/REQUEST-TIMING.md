# Request timing lines

An app served at the edge writes one JSON line to stdout per HTTP request.
GKE ships stdout to Cloud Logging, where each line becomes a structured
`jsonPayload` with a `severity`. The lines answer one question: where did this
request's time go?

They are diagnostics only. Durations come from the OS monotonic clock, and no
decision reads them. The implementation is `crates/day2/src/request_timing.rs`.

## Turning it on and off

The instance's app binding decides:

```json
"apps": { "home": { "request_timing": false, ... } }
```

| `request_timing` | Edge serving (`day2-serve --edge`) | Local development |
| ---------------- | ---------------------------------- | ----------------- |
| absent           | on                                 | off               |
| `false`          | off                                | off               |
| `true`           | on                                 | on                |

The GKE stack exposes this as the `request_timing` variable (null keeps the
default). The setting is read once at startup.

## One line per request

The line is written when the request's last holder lets go: the async handler,
a blocking dispatch that is still running after the client left, or the native
transport once it has finished writing the response. Requests that are refused
as busy, time out, or lose their client still get exactly one line. Health
probes get none.

```json
{"severity":"INFO","event":"day2_request","request":4182,
 "inflight":3,"method":"GET","trace":"105445aa7843bc8bf206b12000100000",
 "category":"page","actor":"a:Xq3v9bKpL2mN0rTw","route":"launcher_refresh",
 "delivery":"delivered","status":200,"outcome":"complete","error":null,
 "reached":"render","total_ms":23011.4,
 "phases":[
  {"phase":"accept_wait","at_ms":0.0,"ms":9120.3},
  {"phase":"admission","at_ms":9120.5,"ms":0.0},
  {"phase":"body_read","at_ms":9120.6,"ms":0.1},
  {"phase":"authenticate","at_ms":9120.8,"ms":41.2},
  {"phase":"access_log","at_ms":9162.1,"ms":18.4},
  {"phase":"dispatch","at_ms":9180.6,"ms":13820.1},
  {"phase":"authorize","at_ms":9181.0,"ms":6.3},
  {"phase":"preparation","at_ms":9187.4,"ms":4110.9,"operation":"resolve_membership",
   "invocation":"page-prepare-0-…","result":"success",
   "totals":{"sql_reads":9,"sql_read_ms":22.0,"sql_writes":7,"sql_write_ms":1480.2,
             "writer_turns":7,"writer_wait_ms":1012.7,"writer_begin_ms":0.4,
             "writer_hold_ms":455.1,"writer_busy":0,"worker_starts":2,
             "worker_start_ms":210.4,"worker_exchanges":3,"worker_exchange_ms":390.8,
             "trace_writes":1,"trace_bytes":78211,"trace_write_ms":9.1,
             "provider_calls":3,"provider_ms":1650.3}},
  {"phase":"prepare","at_ms":9190.2,"ms":2900.4},
  {"phase":"observe","at_ms":9301.7,"ms":1702.0,"capability":"WorkspaceDirectory.userPath"},
  {"phase":"provider_client","at_ms":9301.9,"ms":3.2},
  {"phase":"provider","at_ms":9305.2,"ms":12.4,"capability":"workspace_directory",
   "endpoint":"metadata_token","status":200},
  {"phase":"provider","at_ms":9317.8,"ms":610.0,"capability":"workspace_directory",
   "endpoint":"iam_token","status":200},
  {"phase":"provider","at_ms":9928.1,"ms":1027.9,"capability":"workspace_directory",
   "endpoint":"directory_user","status":200},
  {"phase":"decide","at_ms":12092.0,"ms":1205.3},
  {"phase":"preparation","at_ms":13298.4,"ms":7015.2,"operation":"refresh_directory", …},
  {"phase":"page_query","at_ms":20313.8,"ms":2510.6,"operation":"launcher", …},
  {"phase":"render","at_ms":22824.6,"ms":150.2},
  {"phase":"access_log","at_ms":23000.8,"ms":9.9},
  {"phase":"respond","at_ms":23010.9,"ms":0.5}],
 "dropped_phases":0,
 "totals":{"sql_reads":31,"sql_read_ms":80.4,"sql_writes":22,"sql_write_ms":4800.0,
           "writer_turns":24,"writer_wait_ms":3300.0,"writer_begin_ms":1.1,
           "writer_hold_ms":1450.0,"writer_busy":0,"writer_wait_max_ms":610.0,
           "worker_starts":5,"worker_start_ms":530.0,"worker_exchanges":9,
           "worker_exchange_ms":1210.0,"trace_writes":3,"trace_bytes":235000,
           "trace_write_ms":27.0,"provider_calls":4,"provider_ms":2900.0}}
```

(Illustrative values; `…` marks elided entries.)

### Top-level fields

| Field | Meaning |
| ----- | ------- |
| `request` | Process-local sequence number. Join with the pod name for uniqueness. |
| `trace` | The load balancer's trace id from `X-Cloud-Trace-Context`, hex only. Joins this line with the LB request log. |
| `method` | Standard HTTP method, otherwise `OTHER`. |
| `category` | Platform route class: `page`, `command`, `api`, `asset`, `live_read`, `app_call`, `oauth`, … |
| `route` | The app-declared page or operation served. Never the path or query. |
| `actor` | `a:` plus 16 characters of an HMAC of the actor under the installation's session secret: stable per person, not reversible without the secret. Absent when unauthenticated. |
| `inflight` | Native transport only: connections already open when this one was accepted. |
| `status` | HTTP status the handler produced; null if none. |
| `outcome` | `complete`, `busy` (no execution slot within the queue wait), `not_admitting` (draining), `aborted` (the client went away or the connection timed out before a response), or `unknown`. |
| `aborted_at_ms`, `aborted_in` | For `aborted`: when, and the last phase started at that moment. Work still running after the abort keeps being recorded. |
| `delivery` | Native transport only: `delivered`, `failed` (write failed or client gone), `connection_timeout` (the 30 s connection bound). |
| `error` | Closed platform failure code (`invalid_identity_assertion`, `storage_busy`, `request_body_timeout`, `worker_timeout`, …). Never a message. |
| `reached` | The last phase started. |
| `total_ms` | Start to the line being written. In native mode the start is the TCP accept. |

### Phases

Each entry has `at_ms` (offset from the start) and `ms` (duration). Phases
nest: `dispatch` contains `preparation`, which contains `prepare`, `observe`,
`provider` and `decide`. Read the timeline by start offset.

| Phase | What it covers |
| ----- | -------------- |
| `accept_wait` | Native transport: TCP accept until the request's headers reached the handler. The native host runs every request on one owner thread, so this is mostly waiting for other requests to finish. |
| `admission` | Waiting for one of the `http_concurrency` execution slots. `queued` is the queue length when it had to wait. |
| `body_read` | Reading the request body (3 s bound). |
| `dispatch_queue` | Non-native host: waiting for a blocking-pool thread. |
| `authenticate` | IAP assertion verification, subject binding and session lookup or issue. |
| `access_log` | The two request audit events (admission and status). |
| `dispatch` | Route handling. |
| `authorize` | A page's all-or-nothing authorization preflight. |
| `preparation` / `fallback` | One page preparation command (or its failure fallback), with `operation`, host `invocation` id, `result` and its own `totals`. |
| `page_query` | The page's read query, with `operation`, `result` and `totals`. |
| `command` | A form command (`POST /actions`). |
| `api_invocation` | A JSON API operation. |
| `effects` | Continuing a command's admitted external effects. |
| `prepare` | Running a handler's preparation phase (observations and their journal writes). |
| `observe` | One capability read, with the app-declared `capability` name. |
| `provider_client` | Building a provider HTTP client. |
| `provider` | One provider HTTP exchange: fixed `capability`, `endpoint` kind (`metadata_token`, `iam_token`, `iam_sign_jwt`, `oauth_token`, `directory_user`, `directory_orgunits`) and HTTP `status` (0: no response). |
| `decide` | The decision transaction: authority checks, handler execution, trace and outcome write, commit. |
| `render` | Template or view rendering and form binding. |
| `app_call`, `oauth` | Platform app-to-app calls and the OAuth receiver. |
| `respond` | Native transport: handler return until the response was written. |

A line keeps at most 128 phases; `dropped_phases` counts the rest.

### Totals

Summed over the request; `preparation`, `fallback`, `page_query`, `command`
and `api_invocation` entries carry the same breakdown for their own span, with
zero groups left out.

| Key | Meaning |
| --- | ------- |
| `sql_reads`, `sql_read_ms` | Runtime SQL read units (each opens a connection and a snapshot). |
| `sql_writes`, `sql_write_ms` | Runtime SQL write units, including their writer wait. |
| `writer_turns` | Write transactions begun. |
| `writer_wait_ms`, `writer_wait_max_ms` | Waiting for this process's FIFO write turn: in-process writer contention. |
| `writer_begin_ms` | `BEGIN IMMEDIATE` after the turn: waiting for a writer in another process. |
| `writer_hold_ms` | Time write transactions held the writer. |
| `writer_busy` | Write attempts refused as busy (turn or SQLite lock not granted in time). |
| `worker_starts`, `worker_start_ms` | Sandboxed Roc worker processes started. |
| `worker_exchanges`, `worker_exchange_ms` | Handler execution inside workers. |
| `trace_writes`, `trace_bytes`, `trace_write_ms` | Invocation traces serialized and stored. |
| `provider_calls`, `provider_ms` | Provider HTTP exchanges. |

Categories overlap: a `sql_write` contains its writer wait, hold, worker
exchange and trace write.

## Background pumps

The host's command, schedule and journal-compaction pumps compete for the same
writer and, in native mode, the same owner thread. A run writes its own
`"event":"day2_background"` line, with `pump` and the same totals, when it took
at least 100 ms, failed, waited at least 10 ms for the writer or was refused
as busy. Every minute one `"event":"day2_background_summary"` line reports
each pump's runs, failures, total and maximum duration, writer wait and hold,
and trace bytes.

The hourly backup runs in a separate Job and is not timed here. Its effect
shows up on requests as `writer_begin_ms` (another process holding SQLite's
lock) rather than `writer_wait_ms`.

## What is never logged

Tokens, cookies, assertions, request paths and queries, request bodies, form
values, provider URLs, accounts and payloads, raw actor addresses and app
error text. Identifiers that are not app-declared names are replaced with
`<undeclared>`. Tests in `request_timing_tests.rs` and
`workspace_directory.rs` check this against real requests.

## Reading the lines

In native (OAuth) mode the host serves requests one at a time on its owner
thread. A request accepted while another runs waits in `accept_wait`; one that
arrives while the thread is blocked waits in the kernel's accept queue before
that. The load balancer's latency minus `total_ms` is that kernel queue time.
