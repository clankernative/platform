# Restore host-clock observations

The credential proposal already trusts current host time and requires a safe
persistent high-water policy, with rollback or untrusted time refusing closed.
This component implements the actual native sampling half of that contract.
It does not supply the outside-archive durable high-water owner or qualify an
approval timestamp. It creates no approval, signer or consumed grant.

`UnfencedHostClock::capture` can only capture an actual enrolled App stage. Its child
acquisition comes from the same stage's original, without beginning a request
or resetting time. The existing same-owner meet requires the actual shared
observation/refusal state, domain, process and origin and retains the shorter
deadline. A new stage, identical timestamp data or a matching domain string
cannot substitute for that actual view. No owner survives human wait by this
API; the original native interval remains at most five seconds.

The separate fixed `UnfencedControllerClock` constructor instead requires the
actual `CurrentControllerStoragePhase`, including its retained physical file
and App peer. It checks the exact scope and `EpochController` role before
sampling, and runs the physical postcheck even when sampling fails. Every later
observation again requires that actual phase and its physical pre/postchecks;
the same-owner/core view meet rejects a replacement original. Failure refuses
both the clock and the supplied physical phase, preserving the first sampling
error when both checks fail. The object exposes no inner clock, stage, role
selector, callback, arm or finish operation. It cannot turn an App observation
into Controller authority, and it does not accept a bootstrap stage.

Both fixed constructors use one private sampling implementation. The native
kernel read, interval/rate calculation, original five-second deadline and
permanent-refusal behavior are unchanged. The Controller object is still
UNFENCED; a native ledger writer, initial floor installation, known conditional
commit and actual approval/signing/publication owners remain separate work.

Each observation brackets a real Linux REALTIME read with actual BOOTTIME
samples and the retained native owner checks. It accounts for the final checks
when projecting conservative UTC bounds. An excessive bracket, reversed clock,
discontinuous mapping, native refusal or arithmetic failure permanently refuses
the same acquisition. A later repaired clock cannot recover it. The conservative
rate-error bound is an acceptance condition; observations outside it refuse.
There is no non-Linux, SystemTime, replay or configuration-scalar fallback.

The returned interval and domain are explicitly unfenced DATA. Actual approval
still needs a known high-water commit outside the restored archive, current
registry/passkey/executor authority, the exact signer and final publication
checks. Native role possession and this sampler cannot replace any of those
owners. A historical interval cannot reconstruct the sampler after process,
namespace, boot or owner changes.

The controls distinguish independent generated host-clock histories, step,
rewind, uncertainty, overflow and repair; actual lower original-view fixtures
exercise foreign/shorter/refused views. Production wiring controls cover removal
of either same-original meet and replacement of the actual kernel result.
Linux's direct clock-leaf test is kernel-read evidence only, not an enrolled
native supplier qualification. Existing real enrollment/kernel conformance
tests remain unchanged.

Controller wiring controls inspect the actual typed factory, same stage flow,
both independently evaluated Results and returned sample. They reject role
substitution, dropped physical checks and forged successful observations.
These source/clock controls do not supply a portable native physical-phase
fixture or establish Linux Controller qualification.
