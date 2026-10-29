# OAuth original owners and HTTP execution (T7)

The selected App and Security Shell use one dedicated OS thread to poll their
HTTP/1 connections, run native OAuth dispatch, and write response headers and
bodies to the socket. Hyper is polled directly by a local executor. Tokio supplies
readiness and timers; its task pool does not poll these connections. Runtime
entry is limited to socket acceptance and timer construction, because the
existing blocking provider adapter must run outside an entered Tokio runtime.
The provider adapter may use its own internal networking thread. This design
does not claim that provider network packets originate on the HTTP owner thread.

This is the T7 choice. Returning a Send response or signature from a blocking
task would lose the original's executor at the actual browser response sink.
Keeping the service and the socket in one local future avoids that transfer.
No unsafe Send/Sync implementation, generic app task queue, or public executor
callback is introduced. Normal apps without the selected OAuth receiver keep
their ordinary web transport.

Selected App dispatch, live-page refreshes, and the existing command/schedule/
journal pump stay on the same owner as well. Live refreshes use a bounded queue
of one closed host continuation type. The pump uses its existing state machine,
with synchronous native work on the owner and explicit cooperative yields.
Neither path moves native role owners to a blocking pool.

The selected deployment also initializes on that same owner. Its closed
`NativeAppStartup` carries runtime/instance selections and the existing native
configuration until enrollment succeeds. It then admits the store, configures
the adapters, constructs the edge host and starts the local HTTP/pump loop.
`InitialStorage` is a nonhuman current-role phase for S3's actual first-file
consumer; the startup precheck does not itself grant storage authority. Earlier
layout and active-binding selection remain data inputs, and S3 must cover any
protected payload access there separately. Ordinary hosts retain their existing
startup path.

The thread enrolls each selected authority scope before accepting requests. The
first S1 operator profile admits exactly one scope; a shared shell with other
selected scopes refuses startup unless every scope can actually enroll. It
never borrows the first app's enrollment for another app. The private registry
retains nonclone, nonserializable originals on that thread. Request IDs, SQLite
rows, Google navigation metadata, and the connection's original index
are data. None can recreate an original after restart or on another executor.

App time starts at entry to `Manager::capture`, before SQLite, IAP binding,
selection and entropy. Only its actual committed View/FreshIntent binds that
creator, once. Shell time starts on first `Begins::reserve` before naming entropy
and Claim. Reopening a manual page, retrying a lost publication reply, and a
callback retain the same original. Each has its own 300-second ceiling on the
enrolled common continuous clock. Earlier local deadlines only tighten it.
Signed provider timestamps require their own qualified interpretation; they are
not converted into BOOTTIME by subtraction.

Each accepted native HTTP operation also owns one native request with an original
five-second interval. App capture runs before body parsing, cookies, operation
entropy or protected I/O. Shell captures an unselected original at that same
boundary, then consumes it once when binding the selected actual Shell owner.
That handoff retains its origin, domain, task and namespace anchors. The
unselected value grants no app permission. The existing sealed literal health
producer needs no application or native authority; application responses cannot
manufacture its seal.

An explicitly non-native profile retains ordinary prerequisite, registration
and application HTTP behavior on this executor. Its request record tracks only
transport completion and refusal; it cannot bind a native role, lend a stage or
lease native authority. A selected native profile with a missing owner fails
capture instead of taking this path. Capture failure cannot be retried as a
non-native request.

`native_management` callbacks borrow the actual stored request through
`borrow_current_request`; they never create a replacement clock. Its stage
checks actual owner identity, process, thread, handles and shared refusal. Counter
and peer ceilings tighten the stored acquisition itself, so a later SQL or
response callback cannot recover a wider ceiling. The separate human original
still checks its exact intent and 300-second ceiling through that stage. Each
closed SQL unit uses a distinct serving phase under the same request, without
rearming a completed phase. Its snapshot or transaction closes and postchecks
before any provider action. A final human commit remains one-shot.

Test binaries have an explicit scripted supplier within the existing complete
effect simulation scope. Its HTTP clock models the same operation interval but
cannot construct a native role, enrolled request or stage. Serving binaries
contain no scripted enrollment or clock constructor.

Every connection carries the accepted request's shared holder and a private
index of its exact human original, when applicable. Routing clones share the
holder; they cannot clone its native value. Enlisting a second role or attempt
refuses. The socket wrapper resolves the index and rechecks the original
before write, flush and shutdown. Both HTTP headers and body bytes go through
that wrapper; checking only `Body::poll_frame` would miss buffered headers and
writes. There is one request per connection, with keepalive and pipelining
disabled. Accepted connections are bounded, including slow responses. Header
and request-body reads have short bounds; asynchronous connection delivery has
a 30-second timeout measured from acceptance. It cannot preempt synchronous
native work, which keeps its slot until it returns. Excess connections wait in the OS listener rather
than accumulating an unbounded in-process task queue.

A finite App response moves the actual request, role and storage participant
into its response lease. One borrowed response phase stays live across socket
polls; no RefCell borrow guard crosses suspension. Cancellation or an unknown
result refuses those actual owners. Known transport completion and final
checks consume the request before publishing completion. A shared refusal latch
also survives an abort caught while a synchronous callback holds the original.
Neither callback reentry nor later restoration can reopen that accepted request.

A background command, schedule or journal wake captures its own request around
the whole pump operation, before wall time or SQL. An active response reservation
excludes an unstarted wakeup before owner lookup or clock capture, because that
response has moved the actual owner out of the available map. A refused
reservation is an error, not retryable busy permission. SQL units never create
their own root requests. Startup operations have their own explicit entry;
full connection admission remains distinct from warm HTTP requests.

A disconnected browser cannot cancel an already executing synchronous native
operation or release its slot while it is still executing. Graceful shutdown
stops admission and waits for the owned connections. Failed or timed out writes
are never retried as new handlers. The originals remain in the process-local
registry; S3 retains external unknown outcomes and owns completion or exclusion.
Local successful write completion is not evidence that a human received data,
nor a universal guarantee about the last network byte before an expiry. Native
admission, local commit and physical delivery remain distinct events.

These consumers require the real enrollment and storage/current suppliers; they
cannot create a fresh-human proof or substitute metadata for a missing supplier.
Source and model checks do not establish native enrollment, live Firestore,
signed Google claims or browser lifecycle qualification.

Initial storage, ordinary read and refresh consumers borrow a current App role for their exact
authority scope through `with_current_app_role`. They do not borrow a human
management original or acquire another 300 seconds. Their current epoch, writer
and response-disposition checks remain S3's consuming boundary.

Native web-host construction uses the actual Current SQL owner to admit its
existing binding, current audit schema, activated artifact and security contract.
It never calls the ordinary initializer or repairs native state. A native path
or simulated role cannot supply that owner; the later session-secret write also
retains its own real SQL scope.

Initial Runtime admission and subsequent host construction are distinct fixed
startup operations. Host construction captures one App request original before
configuration or provider setup, and every SQL unit reborrows that same original.
Only known settlement of the operation permits returning its completed host.
SQL adapters cannot create a replacement request clock.

During `NativeAppStartup::prepare` and native web construction, an unfinished
phase emits `day2-native-app-startup-refusal` with a
closed `stage` label and `outcome: not_completed`. The outer startup and inner
web builder can each report their boundary. These records contain no error
chain, path, actor, provider value or serving permission. Successful construction
emits no refusal record. A phase label localizes a failure; it does not prove its
underlying cause or turn an earlier completed scope into whole-App readiness.
