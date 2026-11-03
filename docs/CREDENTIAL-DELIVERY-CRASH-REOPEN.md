# Reveal authorization and acknowledgement after process loss

The Unix credential crash/reopen campaign builds on the admitted credential
metadata fixture and the fixed client/personal issuance harness. Each history
first issues through the real disposable Runtime, then kills a real child at one
of five private store coordination cuts: before reveal authorization commit,
after that commit, after decryption, before acknowledgement commit, and after
acknowledgement commit. Both families run three seeds and replay every history
twice. The parent requires the exact checkpoint, SIGKILL and EOF.

The existing independent lifecycle model predicts whether delivery remains open.
An additional authorization count distinguishes an uncommitted row from a
durable authorization. The parent reopens through the real Runtime, validates
the complete bounded private state in memory, and checks that material, product
registration and issuance receipts remain unchanged. Retried reveal needs a new
verified fixture POST and attempt; acknowledgement is terminal and idempotent.
Foreign recipient, session, epoch, namespace and version inputs must leave every
private row unchanged. Tokens and ciphertext never enter retained evidence.

A committed authorization is not completed delivery. Neither a durable row nor
a constructed response body proves that the browser received a secret. Every
killed history records completed transport as not observed. The dead process's
permit is not recovered from its receipt. The campaign exercises the same store
transaction and permit conversion used by the browser handler; it does not
exercise fresh Google authentication, the native human-purpose producer, HTTP
transport, power loss, or delivery to a real browser.

Receipts and source/artifact-bound failed cases use the existing
`artifacts/credential-crash-reopen` retention path. Replay uses the single
`DAY2_CREDENTIAL_CRASH_REPLAY` reader. Current descriptors reject unknown cuts,
fields, source identities and oversized input. Normal exit and a missing
checkpoint are negative controls, never crash coverage.
