# Kernel connection-peer observations

This native leaf retains an actual kernel `SO_PEERPIDFD` result from a supplied
connected Unix stream or sequence-packet socket. It uses the pinned Nix safe
`PeerPidfd` getter returning `OwnedFd`; no authored unsafe conversion or numeric
PID reopening is used.

Before and after each socket-option or zero-timeout pidfd poll, the leaf checks
the original native acquisition. Revalidation retains the original pidfd and
checks the same owning process, thread and acquisition domain. A changed or
expired acquisition, dead or unknown peer, unsupported platform/kernel or
malformed socket refuses the observation and acquisition permanently. There is
no retry, clock replacement, raw descriptor getter or wire constructor.

The returned credentials describe the connection creator at connection time.
They do not attribute a message, prove current effective credentials, establish
that the connection is still serving, authenticate its endpoint or bind a
process to a Pod, image, initial time namespace, provider or volume. A connection
can be forwarded; this observation does not rule that out. Consuming it into
DATA drops the retained descriptors and cannot recreate their ownership.

The caller supplies an actual socket. This leaf cannot establish when that
socket was opened. A future qualified transport must open and use its fixed,
reviewed endpoint under the same original acquisition and qualify its actual
server/node/runtime trust and sender semantics. No such transport or production
runtime/storage authority factory is introduced here.

The proposed direct Linux Nix dependency and `socket`/`poll` features require
exact dependency, feature, lock, license and native-effect review. Linux kernel
and process-exit cases must run on the supported profile before a native runtime
qualification claim; macOS unsupported-platform refusal proves only refusal.
