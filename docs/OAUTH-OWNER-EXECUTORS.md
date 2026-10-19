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

The thread enrolls each selected authority scope before accepting requests. The
first S1 operator profile admits exactly one scope; a shared shell with other
selected scopes refuses startup unless every scope can actually enroll. It
never borrows the first app's enrollment for another app. The private registry
retains nonclone, nonserializable originals on that thread. Request IDs, SQLite
rows, Google navigation metadata, and the connection's list of original indexes
are data. None can recreate an original after restart or on another executor.

App time starts at entry to `Manager::capture`, before SQLite, IAP binding,
selection and entropy. Only its actual committed View/FreshIntent binds that
creator, once. Shell time starts on first `Begins::reserve` before naming entropy
and Claim. Reopening a manual page, retrying a lost publication reply, and a
callback retain the same original. Each has its own 300-second ceiling on the
enrolled common continuous clock. Earlier local deadlines only tighten it.
Signed provider timestamps require their own qualified interpretation; they are
not converted into BOOTTIME by subtraction.

`native_management::with_current_original` borrows the real original and a fresh
enrolled role stage through one closed consumer phase. Its callback cannot
return either borrow. The phase's original check samples that retained clock
and checks exact intent identity and the original ceiling. S3 adds current
epoch, selection, writer and known-commit checks inside this borrow. A role
stage is at most five seconds; acquiring another stage never replaces the
original or extends its deadline. Test binaries have an explicit scripted
supplier within the existing full effect simulation scope. Serving binaries
contain no scripted enrollment or clock constructor.

Every connection carries a private list of exact original indexes used by its
request. The socket wrapper resolves those indexes and rechecks the originals
before write, flush and shutdown. Both HTTP headers and body bytes go through
that wrapper; checking only `Body::poll_frame` would miss buffered headers and
writes. There is one request per connection, with keepalive and pipelining
disabled. Accepted connections are bounded, including slow responses. Header
and request-body reads have short bounds; the complete connection has a
30-second delivery bound. Excess connections wait in the OS listener rather
than accumulating an unbounded in-process task queue.

A disconnected browser cannot cancel an already executing synchronous native
operation or release its slot while it is still executing. Graceful shutdown
stops admission and waits for the owned connections. Failed or timed out writes
are never retried as new handlers. The originals remain in the process-local
registry; S3 retains external unknown outcomes and owns completion or exclusion.
Local successful write completion is not evidence that a human received data,
nor a universal guarantee about the last network byte before an expiry. Native
admission, local commit and physical delivery remain distinct events.

These owners do not implement the missing epoch/storage authority or create a
fresh-human proof. The existing production proof refusal remains until S1, S2
and S3 are composed and qualified together.
