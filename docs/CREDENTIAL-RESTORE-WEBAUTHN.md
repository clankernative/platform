# Restore WebAuthn assertion profile

This private verifier checks a narrow ES256 WebAuthn assertion profile using the
already admitted ring signature implementation. It does not register keys,
issue approval, select a clock or grant restore permission. The trusted-key input
has private fields and no codec. Its sole production source borrows an actual
native runtime SQL owner and retained instance-configuration handles; it cannot
be constructed from a registry record or an ordinary SQL runtime. See
[the reviewed-registry source](CREDENTIAL-RESTORE-PASSKEY-SOURCE.md).

The selected key binds the exact admin subject commitment, registry and version,
credential identifier, user handle, P-256 public key, RP ID, HTTPS origin and
backup eligibility. The RP ID is exactly the origin's DNS host in this profile;
parent-domain RPs and alternate origins are unsupported. The server challenge
hash binds that entire enrollment, the complete restore request digest and a
32-byte nonce. The eventual issuer must obtain real entropy and derive the
request digest from the complete archive, target, epoch and executor binding.

The verifier checks the exact selected credential and any returned user handle,
bounded unique-key client JSON, `webauthn.get`, the exact challenge and origin,
the RP hash and required user presence and user verification. Cross-origin
assertions, AppID, unknown client fields, reserved flags, attested credential
data, authenticator extensions and algorithms other than ES256 are unsupported.
Authentication data must be exactly 37 bytes. Backup state is permitted only
for a key registered as backup eligible; its eligibility cannot change. The
signature covers the original authentication bytes followed by the SHA-256 of
the original client JSON bytes, without reserializing signed content.

A zero stored counter and zero received counter are valid. If either is nonzero,
the received counter must strictly increase. Counterless passkeys still require
durable one-use challenge consumption: repeated stateless verification is not a
replay barrier. Signature/counter results are DATA, never an approval owner.

The durable-store integration must atomically condition completion on the exact live
enrollment and current admin-policy version, consume the challenge and update
the stored counter. It must reject key removal or replacement, policy changes,
stale writes and replay, including two valid assertions racing one challenge.
The store belongs outside the restored application's rollback domain. A known
commit plus actual current-authority/clock postchecks is required before any
future approval producer may use its result. Unknown completion cannot grant or
be retried as permission. No such producer or production installer exists here.

The user-approved signed grant remains single use, non-renewable and valid for
exactly one hour from actual approval. This verifier changes no native admission,
current request, original-clock, custody or permanent-refusal rule. It does not
authenticate an ordinary IAP session as a passkey ceremony.

References: [WebAuthn assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
and [signature counters](https://www.w3.org/TR/webauthn-3/#sctn-sign-counter).

## Durable challenge store (closed source)

The private store accepts only the verifier's closed trusted-key input. It adds
no production installer, database path, global credential database or native
authority factory. Its real SQLite fixtures use a separate instance-auth store,
never a restored app database. Production still requires actual owned-handle,
filesystem, SQL, current-policy and qualified-clock admission.

Pending challenges are create-only and bind the complete request/enrollment
digests, nonce, exact key storage version/counter and a bounded ceremony interval
of at most five minutes. This ceremony interval is separate from the signed
approval's fixed one-hour lifetime and does not extend an HTTP original.

Completion first commits a pending-to-claimed tombstone under the exact active
key/version condition. Only then does it verify the assertion and its observed
time. Failed signatures, equality at expiry, rewind, death or unknown completion
cannot make that challenge pending again. A lost in-memory continuation cannot
be reconstructed from a claimed or verified row.

After signature verification, a second transaction freshly compares the active
key binding, storage version and counter. It atomically increments that version,
updates the counter and changes the challenge to verified. Key removal, changed
stored enrollment bindings and equal-value rewrites with a new version refuse. Counterless
passkeys also advance the storage version. Two valid assertions racing one
challenge have at most one successful durable completion.

The store refuses memory/off journals and synchronous modes weaker than FULL.
These settings are not native or power-loss qualification. Results and all
claimed/verified rows are DATA: they do not sign approval, authenticate a current
admin, construct VerifiedApproval, renew clocks or authorize a restore. A future
producer must retain the real current authority and check it after known commits
and before signing. An error after a commit withholds the result without
pretending that durable writes rolled back.

All ledger DDL, reads and writes explicitly name `main`, as do the durability
PRAGMAs. TEMP tables cannot substitute current-key data or absorb a claim that
disappears on close; an attached database is never a fallback for missing main
state. The conformance controls inspect the complete main snapshot after reopen.

The stored binding/version/enabled checks do not themselves authenticate a
current `policy.admins` member. The registry-change test changes stored binding
DATA, not a genuine policy owner. Likewise the scalar time is an observation
used by the store, not a fresh post-commit qualified-clock proof. Actual current
admin policy, the exact SQL/FD/storage selection and fresh original-clock checks
must fence both commits and final signing in the future producer. Neither a raw
connection nor returned assertion facts can supply that producer's authority.

## Existing authentication-store schema

The closed `restore_webauthn::store::require_existing_schema` check admits only
the complete main-database catalog derived from the store's existing canonical
table declarations, including their implicit primary-key indexes. Missing or
changed tables, constraints, indexes, views and triggers refuse. The check reads
one transaction snapshot, requires no caller transaction to be open, and never
creates, migrates or repairs the store. Temporary tables cannot replace a missing
main table. Successful reads leave challenge/key rows unchanged.

This is SQL shape admission only. Its native caller must retain the actual
authentication-file lease, check the same original before and after the complete
SQL unit, and withhold results on any failure. It proves neither outside-archive
placement nor durable storage, current key trust, qualified time, single-use
approval publication or restore authority. Native store admission and explicit
store birth remain separate work.

### Grant-keyed reservation-attempt marker

The canonical authentication schema also contains a create-only execution-attempt
row keyed by the approval's grant ID. It binds the complete signed record,
operation, executor challenge, current key binding/version/counter and verified
completion snapshot. Fresh authentication or a different operation cannot insert
another attempt for that same grant. Checking the row only compares historical
DATA; it cannot recover a native completion, stop, original or send permission.

These transaction primitives do not yet supply the accepting native stop. That
caller must commit the marker and finish all same-file, registry, authority and
original postchecks before any reservation send, closing SQL first. After a
committed or possibly committed marker it must neither delete the row nor adopt
it into another owner. A later failure can leave the grant unavailable without
proving any provider write or response completed. The external five-write CAS
remains the actual atomic grant consumption and root transition.

The controls use real SQLite, synthetic verified assertions, independent seeded
histories, reopen, competing connections and actual child-death cuts before the
claim, before its commit and after its commit. They do not establish a native
execution owner, live-provider behavior or power-loss durability. Missing or old
schema shapes refuse; no migration or repair path is supplied.

### Existing native authentication-ledger admission

The current-reader admission consumes the actual accepting admin reader and keeps
its unchanged original, App exclusion, native volume and counter/peer lifetime.
It performs genuine provider/attachment and WAL/FULL filesystem qualification
for the fixed authority-keyed sibling ledger, then compares SQLite's actual MAIN
before configuration and retains the complete actual MAIN/WAL/SHM descriptor
identities. The producer's canonical schema validator refuses missing, unknown
or changed state; this path never creates or repairs a ledger.

Full checks first inspect the actual authentication connection's autocommit
state. Checks inside its SQL units are local owned-resource/original checks;
policy/config/provider work happens only outside the unit. Completion closes the
actual connection, runs native/file postchecks even on a close failure, releases
the file pins, and only then settles the same reader. A later failed postcheck
withholds results and makes no rollback promise.

The first Linux profile uses O_PATH pins, so dropping a metadata pin does not
close a regular alias that could release another connection's POSIX locks.
Last-connection SQLite close may unlink WAL/SHM; that case refuses the retained
postclose cohort check. This does not supply a standalone persistent keeper,
PERSIST_WAL support, ledger birth, whole-volume rollback protection, approval,
complete old-rights fencing or a new App writer. Genuine initialization with an
external create-only birth record remains a separate operation. Target binding
generation is committed DATA here; this admission does not invent a current
namespace-generation producer or equate proposed target epoch/incarnation with
the incumbent.
