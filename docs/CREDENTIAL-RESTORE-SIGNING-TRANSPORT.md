# Restore approval signing transport

The private `security_epoch::storage_authority::native_volume::restore_approval` module implements the fixed
Google KMS Ed25519 request. Its fields, constructor and methods are private even
to the parent module. It has no production caller, route, credential acquisition
or accepting approval factory. Tests exercise the actual HTTP implementation
against a loopback peer using fixture credentials and clocks.

The request signs only the canonical complete restore-approval statement with
the fixed `day2-restore-approval-grant-ed25519-v1` domain. Its identity includes
the exact key version and public bytes. It cannot sign an arbitrary frame,
choose an algorithm, follow a redirect, use a proxy or retry an uncertain call.
One client allows one attempt; failure permanently refuses the supplied
original acquisition, including all its shared narrowed views. A new clock
cannot revive the spent client. Successful output is signature DATA only.

Each attempt reads the exact version, requires `ENABLED`, `EC_SIGN_ED25519` and
`SOFTWARE`, reads and checks the selected RFC8410 public key, signs the raw
canonical frame, validates request/response CRC32C integrity, and locally checks
the actual signature. A final version read must still report the exact enabled
selection. All calls and response reads spend the same supplied original with
fresh remaining timeouts. Both the IO result and its postcheck are evaluated;
the IO failure stays primary when both fail. Errors expose fixed local codes,
never the provider's response body or bearer credentials.

Replies are capped at 16 KiB, including unknown-length bodies. Base64 expansion
of the existing bounded statement is allowed within a separate 24 KiB request
cap. There is no streaming result, alternate origin or configured endpoint in
production. Unknown JSON shape, duplicate fields, missing checksums, a different
version, foreign public key, wrong-purpose signature, timeout, disabled key or
uncertain exchange refuses the attempt without retry.

Opening this transport requires a separate reviewed production join. That join
must retain genuine current registry/admin evidence, durable one-use challenge
and counter completion outside the archive, qualified host time after a known
conditional high-water update, the exact current signing selection and a real
purpose-specific signing owner. It must preserve the current/future-target
distinction and every real original/check at effects and publication. An App
request cannot be relabelled as Controller authority. Existing issuer-birth and
bootstrap writers are not restore signers. A statement, clock, bearer header,
successful signature, stored completion or historical receipt cannot supply any
of these owners. The one-hour grant and durable consumption are not implemented
by this transport, and no production approval is available yet.

Provider contracts: [asymmetricSign](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign),
[getPublicKey](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey),
and [end-to-end integrity](https://docs.cloud.google.com/kms/docs/data-integrity-guidelines).
