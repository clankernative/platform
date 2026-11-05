# Reviewed restore passkey registry

The selected enrollment policy is a reviewed instance configuration change. There
is no browser, IAP or database self-enrollment path. This change adds the public
configuration contract, not an authenticating supplier or a restore command.

`InstallationControl.restore_passkeys`, when present, is an object with
`version: 1` and a `keys` object keyed by bounded configuration labels. The
operator-only packaging projection cannot contain it. An absent registry is
allowed for instances that do not use restore; an eventual restore producer must
refuse when it is absent, without choosing a different key source.

Each key contains exactly these fields:

| Field | Meaning and bound |
| --- | --- |
| `email` | Exact admin email under the existing identity grammar, at most 256 bytes. ASCII uppercase is refused; Unicode bytes are preserved without normalization. |
| `subject` | Exact authenticated admin subject, 1–1,024 bytes, no control characters. |
| `credential_id` | Public credential identifier, a JSON array of 1–1,023 unsigned bytes. |
| `user_handle` | The actual authenticator enrollment user handle, 1–64 unsigned bytes. Never derive one from email or subject. |
| `cose_key` | The 77-byte public COSE key below, as an array of unsigned bytes. |
| `backup_eligible` | Required reviewed Boolean matching the authenticator's enrollment state. No default or inference from a later assertion. |
| `rp_id` | Canonical lowercase DNS name with at least two labels; no IP address or trailing dot. |
| `origin` | Exact HTTPS origin on that same host, optionally with a canonical nondefault port. No path, credentials, query or fragment. |

The registry admits at most 128 keys and 512 KiB in its canonical JSON encoding.
Credential identifiers must be unique. One email cannot name different subjects,
and one subject cannot name different emails. Multiple authenticators for the
same exact admin pair are supported. Configuration objects reject duplicate and
unknown fields, sequence-shaped structs and duplicate labels even when a JSON
escape spells the same label differently. Byte arrays reject strings, negative
or fractional numbers, and values above 255. Parsing errors use closed categories.

The only COSE profile is a five-entry CBOR map: `1: 2` (EC2), `3: -7` (ES256),
`-1: 1` (P-256), `-2: x` and `-3: y`. Each coordinate is exactly 32 bytes, including
leading zeroes. Map order may vary. Minimal integer and byte-string encodings are
required; duplicate, unknown and private labels, tags, indefinite forms and
trailing bytes are refused. Conversion returns the public 65-byte uncompressed
point. This is a shape check, not proof that the point is on the curve or that an
admin possesses the key. The actual assertion signature still needs verification
under the ES256 WebAuthn rules, including DER-encoded ECDSA signatures.

`content_digest()` identifies canonical registry DATA only. Removing a key and
restoring identical bytes restores the same digest. It is therefore explicitly
not an authenticated configuration revision, removal fence, replay defense or
native capability. No code in this contract constructs a trusted key or approval.

The genuine producer still needs to select the current admitted instance config,
join the exact email and subject to current `policy.admins`, retain the actual
config, SQL, clock and native owners, and recheck them at its real boundaries.
Removal must immediately close in-flight work. It must bind a non-reusable
admitted revision and retain counter and challenge tombstone history across key
removal and re-addition; the content hash alone cannot prevent that ABA. No
caller-supplied public key, IAP identity, SQLite enrollment row or copied registry
object can substitute for this current source. Signing, durable approval
consumption and deployed qualification remain separate work.

The tests cover all 120 COSE map orders, malformed and private key encodings,
exact RP/origin boundaries, ambiguous principal and credential selections,
duplicate-object and byte/size controls, operator-only packaging, and the
deliberate same-content ABA counterexample. They do not claim genuine admission
or live passkey/restore qualification.
