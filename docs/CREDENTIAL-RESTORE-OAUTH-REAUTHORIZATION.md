# Fresh OAuth authorization after a restore cut

The offline cut closes every captured continuation and makes each current slot
require reauthorization. It preserves provider ambiguity, intent history and
ciphertext. This component allows the existing managed Connect path to obtain
new material after that cut; it does not revive the previous material or grant
an ordinary raw SQL adapter permission to adopt it.

The cut captures a fixed per-slot maximum generation from current slots, pending
connects, private tokens, quarantine and refresh attempts. A fresh captured
management view includes that floor and the complete current reauth-required
slot fence. Existing whole-view Google authentication and shell confirmation
bind both. Every original consumer and SQL post still checks the actual view,
authority, selection and exact current slot. A raw connect adapter refuses any
floored slot. New generation allocation is checked and strictly greater than
all captured generations, even when only a pending exchange exists and no slot
was published. Historical intents retain their own captured floor; schema
admission never reinterprets them against a later floor.

Only the actual restore cut releases a pre-send dispatch claim, and only if both
its same-slot Connect and management originals are permanently closed by that
same cut. Ordinary timeout/retry never releases that barrier. Already-armed
provider work can still finish; release is not an assertion that an old send
was undone or never happened. The physical incumbent drain remains a separate
mandatory prerequisite of operational restore.

Disconnect cleanup is bound to the newly current generation, local epoch,
account, profile and material version. It excludes all restore-closed attempts,
including unknown refresh outcomes. Old ciphertext and closed intent records
remain historical; expiry cleanup does not delete them. The fixed cut/floor and
closed-ID rows refuse update, delete and replacement. A second cut on the same
image is not supported. Current schema and required wire fields replace their
old forms in place; no migration or fallback is added.

These are real SQLite/private crypto and controlled provider/original fixtures.
They are not native first-holder, passkey approval, P3/writer, deployed provider,
Linux physical exclusion or whole secure-restore qualification. Operational
restore still needs the genuine approval/consumption owner, complete app reset,
old-owner quiescence and new-writer admission.
