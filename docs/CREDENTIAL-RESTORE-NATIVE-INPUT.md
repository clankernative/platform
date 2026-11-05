# Closed native restore approval consumer

The drain entry consumes Credential's actual `NativeRestoreApproval` once and
moves its `ConsumedRestoreApproval` into the private approval origin. That owner
and its source lifetime remain held through the drain session, staging birth and
writer candidate. There is no replaceable borrowed token, receipt-to-owner
conversion, serialization, clone, default or independent clock acquisition.

Before consumption, the entry checks the selected authority and store, complete
archive commitment, artifact/schema, target incarnation/epoch, generation, exact
intent and operation. The complete unchanged approval request and operation go
to the actual native input. That producer must separately authenticate current
admins/registry, executor, existing custody, actual archive availability, signature,
qualified time/high-water and the durable single-use operation. Matching DATA
alone proves none of these things.

`consume` is the single consumption entry, not an after-the-fact permission
conversion. Its eventual native implementation must retain the actual one-shot
owner and delegate the existing atomic reservation/grant-use protocol exactly
once. A stored receipt, known-row boolean or historical `Applied` classification
cannot construct this input or reconstruct a consumed owner after uncertainty.
No second grant store or transaction is added by this bridge.

The actual typed observation fixes the request clock domain, origin and deadline
in nanoseconds. Signed approval time plus exactly one hour stays inside the genuine
input and is never substituted for that short original. Every native refresh
checks the actual consumed producer before and after the retained stop source;
the mandatory postcheck runs on source error and preserves that primary error.
All prior source-clock binding, window and monotonic checks remain mandatory.
Their bounds may add refusal but cannot replace the final producer observation.
Changed domain/origin/deadline, rewind, expiry equality and refusal remain closed.

The input's `NativeOrigin` is empty in production **and tests**. Complete stop and
writer suppliers also remain absent. The local lifecycle model still uses its
explicit unqualified origin, which cannot become a native input. Source controls
trace the owned factory, exact argument forwarding, observation dataflow and
mandatory postcheck, including actual-source mutations and transitive rejection
of an added test-only native origin. Binding tests return DATA only.

This source-only composition is not compiled, qualified or operational restore.
Actual producer/storage integration, complete old-rights exclusion, captured-file
ownership, physical fencing and current-root/P3/writer qualification remain owed.
No operator execution, cloud changes or new native time ceiling is introduced.
