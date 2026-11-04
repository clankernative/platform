# Closed credential intent protocol

The existing private Shell/App fresh-owner exchange distinguishes three intent
purposes: `credential_issue_intent`, `credential_rotate_intent` and
`credential_revoke_intent`. The host derives the choice from the actual typed
Pending lifecycle action. It is not a browser-supplied operation, provider,
resource, key, epoch or authority selector.

The immutable FreshIntent includes that closed action alongside the exact
scope, app, artifact, origins, identity, attempt, Pending challenge and original
interval. The challenge still commits to the whole Pending, including its
active authority, binding, input, selected grant and rotation preview. Changing
either the action or another original field changes the commitment. No wire or
restored row can construct FreshIntent or a live native owner.

All fresh-owner purposes have one canonical string encoding. The old generic
credential intent tag, unknown tags, reveal/ack actions and map/sequence forms
refuse. Claim and publish remain separate closed operations. Both transport
ends use the same bounded routing classifier; the receiver still authenticates
machine and human identities before resolving the App's current Pending.

Before any allocation/publication write, the existing transaction adapter checks
the call's exact action, attempt and complete original against that resolved
intent. Replies bind the complete call, original interval and operation. SQLite
also binds each credential purpose to its context action, so bypassing the RPC
decoder does not admit an issue row with rotate/revoke context. Original fields
remain immutable and terminal rows remain terminal. Duplicate replies describe
the same allocation; they do not grant another original or a fresh human proof.

This private schema and its callers change in place. Unknown prior layouts
refuse without alteration; disposable installations must be redeployed. No
compatibility codec, schema conversion or alternate path is supplied. Historical
confirmation DATA is unchanged and remains unable to construct authentication.

This is the protocol prerequisite, not a credential authentication producer.
The existing native producer and App manager still accept only OAuth connect
and disconnect. All three credential intents continue to refuse before instance
or SQL acquisition there. Reveal and acknowledgement do not enter this protocol.
There is no new session, token delivery, key/epoch adapter, native owner, clock,
operator route or deployment qualification.

Tests cover all six exact purpose strings through raw and Value decoding,
wrong-action and cross-operation substitution before real SQLite changes,
immutable allocation/publication replies, duplicate claims, expiry equality,
SQL-level action mismatches, unknown-schema refusal and both routing classes.
The existing admitted-artifact/signed-Google fixture checks the actual credential
constructor selects issue, while retaining its production-producer refusal.
Controlled DATA/SQLite cases do not qualify a native role, fresh human, browser
receipt or deployed installation.
