# Restore approval producer

The user selected the single-admin policy on 4 November 2026. An instance admin
in the current `policy.admins` approves with a WebAuthn assertion requiring user
verification. The signed approval must bind the exact archive, target, epoch
and executor. The executor is an authenticated current instance admin running
the operator command; the approver and executor may be the same person.

Each grant is single use and valid for exactly one hour from approval. It cannot
be renewed by a fresh observation, consumption, recovery or a repaired clock.
Expiry or consumption requires a new approval. This hour does not extend the
existing request originals or Current readiness bounds.

Custody stays on the app's existing vault binding. Restore closes or revokes
pre-restore credentials and callbacks, which must be reissued. OAuth connections
require reauthorization. No preservation or custody-migration profile is enabled.

## Shared request DATA

`security_epoch::restore_approval` defines the canonical `TargetBinding` and
`ApprovalRequest` shared with the restore consumer. The target includes exact
scope, binding generation, authority, complete selection, fresh incarnation,
security epoch, artifact and schema. The request also carries the unique grant
identifier, full archive digest, executor's exact email/subject, existing custody
binding and fixed approval/expiry times.

`full_archive_digest` identifies the complete captured archive bytes/inventory.
It is distinct from a digest of backup metadata, the SQLite image digest and the
later reset-image digest. The consumer must validate the real archive and its
metadata independently and compare every target field with its actual selected,
fenced state and held target. Equality of a request commitment is insufficient.

Decoding, shape validation, complete comparison and the domain-separated
commitment create DATA only. They authenticate no admin, public key or archive
and construct no native original, approval, consumed grant, fence or writer.
In particular, a decoded executor pair cannot replace the actual verified owner.

## Remaining producer and consumer work

The WebAuthn verifier, trusted enrolled-passkey registry, first-enrollment policy,
server challenge ceremony and exact-purpose signing producer are not implemented
by this request contract. Google signed authentication timing and ordinary IAP
identity do not prove that a passkey was used. `LocalOperator::assert_local`
explicitly supplies no production authentication. A client-selected key, CLI
flag, boolean or saved record cannot fill these boundaries.

The [native producer composition](CREDENTIAL-RESTORE-APPROVAL-PRODUCER.md) retains
its actual short-action owner through verification, signing and publication.
No native owner survives the human wait or is reconstructed from a signed
record. The accepting executor needs its own fresh authenticated native action,
current registry/time/target checks and actual external storage owner through
drain, staging and writer work. Only a known atomic commit plus actual
postchecks may create a consumed grant.
Consumption must be keyed by the grant identifier outside the restored app's
rollback domain, joined to the restore reservation/epoch transition. An uncertain
send or historical receipt cannot reconstruct permission or justify a retry.
