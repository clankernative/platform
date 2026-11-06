# Signed restore approval record

This component defines signature and request DATA. It does not construct an
accepting approval, a signing key, a qualified clock or a consumed restore grant.
It does not enable an operator restore command.

The pending `ApprovalIntent` commits to the exact grant identifier, complete
archive digest, target, executor and existing vault binding. It contains no
approval timestamp. A human wait cannot consume the eventual one-hour interval,
and completing a later request cannot renew an already signed grant. The actual
producer must choose one qualified completion time and persist that time with
its exactly 3,600-second expiry. Recovery retains those same times.

`ApprovalStatement` includes the entire final request, approver identity,
reviewed-registry binding, credential and assertion commitments, and signing-key
identity. Ed25519 signs the canonical statement under the fixed
`day2-restore-approval-grant-ed25519-v1` domain. No caller chooses an algorithm,
domain or arbitrary payload. The complete timestamps and every target/archive/
executor/custody field are covered. Transport is bounded and rejects unknown or
duplicate fields and noncanonical signatures.

`verify_signature_data` checks cryptographic DATA against the exact expected
statement and the exact selected KMS version/public-key pair; neither argument
is authenticated by this function. The signing-key commitment includes the full
canonical resource version, so reimporting the same public bytes elsewhere does
not preserve that identity.
Computing a key digest or verifying an intact signature creates no current
registry trust, passkey proof, time witness, single use or native owner. A caller
cannot obtain `VerifiedApproval` from this API. No production signer or accepting
factory is introduced by this component. Test keys exist only in test code.

The production producer still needs all of the following together:

- A genuine passkey assertion against the current reviewed registry and current
  admin policy, with pending key removal or replacement refusing permanently.
- A known durable challenge/counter completion outside the archive's rollback
  domain; a row or historical completion cannot reconstruct a lost owner.
- A qualified UTC interval joined to the actual retained monotonic original,
  and an exact-purpose signing owner retained through signing and publication.
- An explicit commit/CAS protocol around signing. No app or ledger SQL
  transaction may remain open across a KMS or other external provider call.
- The consumer's known atomic grant-keyed external single-use commit and
  postchecks, with expiry equality, rewind, revocation and unknown completion
  refusing. One hour never replaces the existing five-second request bound.

The existing KMS issuer-birth signer and OAuth session/view signers do not supply
restore signing authority. BOOTTIME, a `SystemTime` scalar, authentication time
and a Firestore update timestamp do not by themselves qualify approval UTC.
Those existing purposes and bounds remain unchanged.
