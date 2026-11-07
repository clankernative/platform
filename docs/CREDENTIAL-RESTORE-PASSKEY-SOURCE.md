# Current reviewed passkeys

The registry source selects a restore-verification key from the actual runtime's
instance configuration, using `control.restore_passkeys`. Registry records are
public data. They become a verifier input only inside the closed verification
method, while borrowing the actual native runtime SQL owner for that runtime.
Ordinary SQL, an OAuth human original, a runtime clone alone, desired policy and a
serialized record cannot supply that owner.

Capture reads the configuration and the currently activated, enabled app policy.
The selected registry email must be in that policy's `admins`. The configured
security-shell origin, exact app scope and active artifact must agree. The key's
subject, actual credential identifier, user handle, public key, backup flag,
RP ID and origin are all bound, together with the complete configuration, held
file identity and current authority stamp. Changing another registry entry also
invalidates this conservative selection. A new capture rereads the file: a
removed key cannot authorize a new attempt.
Every observation also requires the retained path to be the actual current
runtime's original published selector, before reading retained bytes. Native
input capture retains that selector before startup canonicalization. Ordinary
runtimes carry no restore selector; this metadata is never permission.

The source opens the absolute, bounded published configuration path through
descriptor-relative operations that refuse symlinks at every component. It
retains the directory and file handles. The regular file must have one link, be
at most one MiB and have no group/other write permission. Every selection rereads
the bounded contents through the held descriptor, checks fresh path identity,
and compares file metadata and the immediate parent directory's change time.
A startup-resolved version file cannot replace the published selector. Relative
inputs and symlink-based configuration projections are unsupported and refused
before any key is trusted. Replacement, removal and readdition, an in-place
write, an added hard link or a
changed parent refuse the retained ceremony. Paths with symlink ancestors must
be corrected in deployment configuration before use.

These checks do not make a mutable file immutable. This source trusts the
already admitted node, kernel and reviewed configuration publisher. It is not
fs-verity, protection from a hostile root restoring metadata, or a general
filesystem rollback proof. Operators publish registry changes through reviewed
instance configuration only; this component has no enrollment endpoint.

Capture obtains fresh server entropy and returns a server-owned ceremony with
challenge data, no current permission. It retains no native owner across the
human interaction. Verification requires a fresh genuine request owner; that
does not renew the original clock of any previous request. The ceremony permits
only one local attempt and cannot be cloned, serialized or reconstructed from
saved rows. Restart requires a new capture and nonce.

Verification checks current registry and admin authority before the actual
signature operation and again afterwards, including when verification fails.
The signature error remains primary if both signature verification and the
postcheck refuse. Any error permanently refuses that ceremony and its borrowed
SQL owner. Only the scoped key's origin checks actual local native/handle state;
no provider or second SQL acquisition is hidden inside a ledger transaction.
Configuration reads, entropy and signature work run outside app transactions.

The returned assertion facts are data. This component does not persist a
signature counter, consume a durable challenge or approve a restore. The
outside-backup challenge ledger, original deadline, exact counter/version
completion, signing and durable single-use approval grant still need their
production integration. The one-hour grant is separate from the challenge and
from a native request's original bound.

This is a pre-fence app-policy source. The ordinary native runtime correctly
refuses after the authority root changes. This source does not bypass that
refusal or provide the future post-fence restore-maintenance owner. Tests use
real local files and ordinary SQLite refusal controls, plus selection data and
actual production-source mutation controls. They do not construct a positive
native owner or claim deployed qualification.
