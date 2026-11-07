# Create a restore passkey for a reviewed registry change

The restore trust policy is a reviewed instance registry. This procedure creates
a candidate public record on an authenticator. The export page never submits
that record to the server, enrolls a key, approves a restore or updates policy.
An IAP sign-in protects access to the page; it does not authorize the new key.

The public registry format is introduced separately in
[PR 377](https://github.com/clankernative/platform/pull/377). The export page is
independent of its trusted-key source. A working export is not evidence that
restore approval, key removal enforcement or the accepting restore command is
available; those producer/consumer integrations remain separate work.

## Generate and export

1. Find the reviewed instance's exact `security_shell.origin`. Its existing
   admitted HTTPS shell must be serving this version. Use that origin, including
   any nondefault port. Do not use localhost, a public demonstration site, an
   iframe or another installation. This profile uses the shell hostname as the
   exact RP ID; changing that hostname requires a new passkey.
2. Sign in at that shell and open `/restore/passkeys/export`. Check the displayed
   account. The page takes the exact account subject from the verified edge
   identity; no query string or input field can substitute it. A reviewer must
   independently establish that this identity is an administrator in the target
   application's current `policy.admins`.
3. Choose **Create passkey**, then complete the browser/authenticator's user
   verification prompt. This may use the authenticator's PIN or biometric. Keep
   the private passkey on the authenticator; the platform never requests or
   exports it. Cancellation or an unsupported authenticator produces no record.
4. Copy the **Public record for review** exactly. It contains the credential ID,
   public COSE key, actual random user handle supplied during creation, actual
   backup-eligibility flag, exact email/subject and RP/origin. It contains no
   private key, PIN, attestation, session cookie or approval. Save this public
   record with the proposed instance-config change, not in an app database.

The browser requests discoverable ES256 credentials and required user
verification. It checks the actual registration's flags, RP hash, origin,
challenge and credential identifier. It extracts the public COSE key from the
actual attested credential data and compares its point to the browser's SPKI
public key through Web Crypto. SPKI bytes are never relabelled as COSE. These
are export consistency checks, not server authentication or attestation trust.
See [WebAuthn registration data](https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data).

## Review and publish configuration

1. In the target instance's ordinary reviewed configuration, create or update
   `control.restore_passkeys` with `version: 1` and a `keys` object. Select a
   bounded, unique label and use the complete exported object as its value.
   This is public policy configuration; a browser response or SQLite row cannot
   activate it. Do not put it in the operator-only packaging projection.
2. The reviewer checks the exact target installation/environment, the shell RP
   and origin, the admin email/subject binding and current `policy.admins`, and
   the ownership of the authenticator through the normal reviewed-change
   process. Ordinary IAP access, or possession of a candidate JSON file, is not
   enough. Do not normalize Unicode identity bytes, invent a user handle or
   infer backup eligibility from an option requested by the browser.
3. Run the existing instance/release admission for that configuration. The
   registry decoder admits only public EC2/P-256/ES256 keys with two 32-byte
   coordinates, unique credential IDs and unambiguous admin pairs. Unknown,
   duplicate, private and malformed fields fail. Apply through the instance's
   reviewed release process; merging a config proposal alone does not change
   the running instance. This procedure creates no cloud resources.
4. After the genuine approval producer is available, use a fresh restore
   ceremony with its server-issued request-bound challenge. Exporting a key is
   not an approval and cannot bypass that ceremony or durable single use.

## Remove or replace a key

Remove its credential entry through the same reviewed config/release process.
The trusted-key source must use the current deployed registry at every new
approval boundary, so a removed credential cannot be accepted from an old
database row or cached enrollment. Replacing an authenticator creates a new
credential and a new reviewed record; keep the old credential's counter and
challenge tombstones. Re-adding identical public bytes cannot revive old work.
The registry content hash is not a non-reusable revision or revocation fence.

If creation fails, the page displays a fixed message and no record. Verify the
exact origin and user-verifying ES256 support before retrying; never weaken UV,
switch to an unrelated RP or paste a caller-supplied key into a live enrollment
endpoint. There is no such endpoint in this workflow.
