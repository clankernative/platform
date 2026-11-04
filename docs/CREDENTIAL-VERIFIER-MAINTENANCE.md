# Exact-version verifier maintenance core

This private controlled-port core changes the keyed verifier for the same
presented managed token. It does not rotate the bearer, decrypt stored custody,
reveal a token, or authorize an operator. The existing one-row maintenance module
supplies one actual joined current-row reader for encryption and verifier work.

A separate verifier authority must select the exact accepted previous key and
replacement under the family’s verifier binding, current epoch and maintenance
policy. A stored key-version string and a valid token do not confer maintenance
permission. Only `CustodyVerifier` leases are requested; returned binding,
version and purpose must match. Preparation occurs outside the writer
transaction and reselects the full row and authority after each provider call.
The previous HMAC must authenticate the same canonical presented token before a
replacement HMAC is computed. Plaintext is not retained in the prepared value.

The verifier record is co-located with the credential version but has its own
monotonic `verifier_revision`, independent of bearer, material, envelope and
lineage revisions. New versions start at one. Staging consumes one opaque
preparation, reselects the active exact head and complete row under the caller’s
transaction, and rechecks current maintenance authority immediately before CAS.
Only the verifier, verifier-key version and verifier revision change. Grant,
principal, epoch, expiry, selector, encrypted material, receipts and delivery
state remain unchanged. Counter exhaustion refuses before key access.

Rotation, revoke, another verifier replacement, encryption rewrap or changed
material defeats stale preparation. Returning to the exact old key and HMAC
does not erase the verifier revision. Encryption rewrap also compares that
revision and cannot publish its old preparation after verifier maintenance.
Readiness and credential expiry are separate cutoffs; equality at expiry and
clock rewind refuse, and the latest provider observation is retained.

`VerifierPending` proves staging only. The existing caller must settle its real
commit and preserve an unknown outcome as unknown; rollback is not successful
maintenance. This core supplies no native maintenance purpose, operator route,
background executor, accepted-key retirement policy or key-retirement action.
Ingress still requires current lifecycle, epoch, grant and caller policy.

The current private layout requires the verifier revision. Older layouts refuse
without alteration and disposable installations must be redeployed. No schema
upgrade, dual reader or compatibility path is added; the existing GoLinks
empty-version-one exception and its frozen fixture are unchanged.

Real SQLite controls cover identity preservation, rollback, competing writes,
old→new→old keys, rotation, revoke, rewrap, exact-key substitution and clocks.
Generated multi-step histories compare actual outcomes and bounded private state
with a separate symbolic model, then replay twice. Retained failures bind the
source and fixture contract, contain only closed decisions/counts and input
events, and replay through `DAY2_CREDENTIAL_VERIFIER_REPLAY`. Full private rows
and tokens stay in memory. This is not native/operator or power-loss
qualification.
