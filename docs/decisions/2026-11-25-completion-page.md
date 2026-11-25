# Narrow Linux completion publication ABI

The user approved the reviewed completion-publication design on 25 November
2026. This is the sole additional authored-unsafe exception: only
`crates/day2-completion-page/src/linux.rs`. The app worker remains pure and the
day2 runtime retains its unsafe prohibition. No deployment, IAM, cloud or live
qualification action is authorized by this source decision.

The fixed page binds the complete intent, connection/nonces, operation, original,
creator/receiver, destination and full immutable archive commitment. Pending
bytes/signatures/ancillary receipt are not completed native handoff. Existing
channel code must independently authenticate the actual creator and retain the
genuine whole request, original, peer and exclusion through all required posts.
No new role, signing getter, source grant, original or upload constructor is added.

Publication returns an owning DATA hold. No map/FD/native-wrapper cleanup is
hidden after Known; later disposal is separately reported resource cleanup and
cannot replace a source/Connection/native post or alter historical Known. The
only networking operation is one fixed pending envelope plus its own read-only
page descriptor on the existing Unix sequence-packet socket. It accepts no
arbitrary payload, descriptor, flags, URL, callback, reconnect or socket factory.

Future-write seals do not revoke older writable aliases. A matching mechanical
page or received descriptor therefore proves neither a genuine creator nor
permission. Fresh actual Controller construction and no writer export/adoption/
fork remain required native supplier obligations. Accepting upload remains
unwired until component review and real cross-process Linux qualification under
both rustix backends, followed by actual native integration qualification.

The concrete terminal operation is one Release-success Pending→Known CAS, with
Relaxed failure and no loop. A competing Known or malformed/Refused byte returns
local refusal DATA; it never grants local completion or overwrites a terminal
byte. Pending Drop can CAS only Pending→Refused. These are guarantees of this
component, not protection against an unqualified older/forked writable alias.

The receiver never maps an incoming descriptor or creates a Rust reference to
foreign shared memory. It performs exactly one bounded `pread` of the state byte
into owned storage; short/EOF/error/unknown refuses without read-exact or retry.
A following Acquire fence orders local work only. This is a Linux x86_64 coherent
memfd/MAP_SHARED byte-observation ABI, **not** Rust release/acquire synchronization
or a happens-before claim about mutable payload. All image/header data must be
independently immutable and verified. This avoids imposing an undocumented Rust
atomic-access precondition on arbitrary received descriptors, including older
non-atomic/wider aliases. Only the fresh private producer mapping holds an
AtomicU8 view; its safety argument does not depend on authenticating a receiver.

Qualification is confined to Linux x86_64 with one-byte atomics. The build-only
libc qualification selects the same backend in rustix's library and its owner
build-script. Tests embed that actual selected producer's cfg flags and refuse a
mismatched backend; a workflow label is insufficient. Other architectures and
macOS expose DATA definitions only, with no accepting mechanics fallback.
Kernel tests cannot qualify creator authenticity, native deadlines/final posts,
F execution or upload. No native consumer is wired in this PR.
