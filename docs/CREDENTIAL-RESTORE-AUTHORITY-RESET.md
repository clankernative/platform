# Restore authority denial leaf

This is a SQL-only part of complete secure restore, not an accepting restore
command, passkey approval, incumbent exclusion, new writer or serving authority.
Ordinary restore still refuses managed credential history; it keeps its existing
initialization path and caller progress-handler ownership. Session and ticket
material clearing is shared with that ordinary path instead of duplicated in ops.

`PreparedRestoreFence` contains denial DATA. The actual secure owner must supply
the exact admitted artifact, fresh epoch and qualified delegation cutoff outside
the reset transaction, bind them to the approved archive and target, and retain
its genuine approval and physical-exclusion owners. Neither an admin string nor
this prepared value supplies any of those rights.

`RestoreFenceSchema` builds a trusted in-memory reference using the actual audit,
authority, budget (including capacity-return guards), and delegation installers.
It never runs an installer against imported state. The prepared leaf requires an
already active, same-connection cumulative admission scope. The enclosing raw
adapter owns its temporary progress callback; an actual Runtime loan retains its
permanent callback. The leaf neither installs a callback nor assumes one exists
on an arbitrary raw connection.

Within that scope, the leaf requires current affected object sets, exact layouts,
indexes, guards, bounded rows, foreign keys and per-table integrity. This includes
the invocation rows read when permanently blocking old pending work. Missing,
partial, shadow, attached or unknown shapes and old or empty budget metadata
refuse before mutation. This is structural admission of the denial dependencies,
not semantic admission of every serialized receipt or every application unit.
The complete restore owner must separately validate all remaining state and app
properties before creating or admitting the target.

The same SQL unit then freezes the existing budget ledger, advances the delegation
cutoff without lowering a prior cutoff, writes a fresh disabled authority stamp,
permanently blocks old pending invocations and discards old sessions and ticket
secret. It preserves the ledger identity, spent capacity, held and unknown usage,
provider uncertainty, invocation pins and history. It never frees capacity,
re-tags old work, acknowledges an ambiguous effect or enables restored authority.
The complete reset owns rollback and commit; no intermediate result authorizes
publication. A later authority activation cannot re-pin the blocked old work.

The user-approved final restore policy remains unchanged: a current instance
admin authenticated by a reviewed-registry passkey approves the exact archive,
target, security epoch and executor; a signed approval is single use, non-renewable
and valid for one hour. Custody stays on the existing vault binding. The final
composition must revoke credentials, close callbacks and require fresh OAuth
authorization, then admit a new writer on the same held target after real fencing.
This leaf implements none of those missing accepting suppliers.

Qualification covers real SQLite and bounded test inputs, not native exclusion,
power loss, production approval, provider outcomes or usable operational restore.
