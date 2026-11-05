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
decoder does not admit an issue row with rotate/revoke context. A shared credential-attempt uniqueness constraint prevents the three actions
from forking one attempt into multiple originals, including after terminal
history. Original fields remain immutable and terminal rows remain terminal. Duplicate replies describe
the same allocation; they do not grant another original or a fresh human proof.

This private schema and its callers change in place. Unknown prior layouts
refuse without alteration; disposable installations must be redeployed. No
compatibility codec, schema conversion or alternate path is supplied. Historical
confirmation DATA is unchanged and remains unable to construct authentication.

This is the protocol prerequisite, not a credential authentication producer.
Pending navigation creation and installation-registry lookup now use the
existing runtime-owned SQL writer. Current authority, exact Pending identity,
FIFO admission, commit, connection close and final owner checks finish before
a navigation URL or resolved Runtime/Pending is returned. Lookup remains a
writer because binding the verified human's subject can mutate durable state.
An owner failure after commit withholds the result; it does not imply rollback
or permit a new clock, replacement human original or automatic retry.

The real-SQLite controlled-owner cases cover unchanged navigation idempotency,
postcommit owner loss for both creation and lookup, permanent refusal and
missing-native-supplier refusal. Their simulated owner is not native admission
or a fresh-human proof. The existing producer gate remains closed below.

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
