# Restore approval signing-key selection

`control.restore_approval_signing` is a reviewed public instance input for one
fixed restore-approval signing purpose. It selects an exact Google KMS key
version and 32-byte Ed25519 public key. Aliases, URLs, path substitution and
noncanonical version numbers are refused. The algorithm is fixed by the private
protocol; instance configuration cannot choose it or supply private key material.

The selection and its digest are DATA. Neither config presence nor a digest
creates a signer, verifies key possession, authenticates a clock or approves a
restore. Public-key shape validation is not curve, provider-state or permission
qualification. The actual native client must check the exact selected version,
enabled state, fixed algorithm/protection profile and actual public key, then
verify the returned signature. It must retain current reviewed configuration,
passkey/admin proof, durable completion and the original native clock around the
external call and final publication.

The identity commitment includes both the full version resource and public
bytes. Re-importing the same public material at another version is a different
selection. The final approval statement and accepting owner must bind the exact
version as well as the public key before production signing is enabled. The
current signature DATA component is not an accepting KMS factory.

This is a separate restore-only key selection. No fallback to issuer-birth or
OAuth session/view keys is permitted. An omitted selection means restore signing
is unconfigured; it does not activate another signing path. Existing vault
custody remains unchanged. Operator-only control projections without app
bindings cannot carry this otherwise unused provider selection.

No KMS key, service account, IAM grant or cloud resource is created here. The
operator/coordinator must approve any future resource or spend before a live
action. Configuration should contain only the public key returned for the
reviewed exact version; KMS private material never belongs in instance config.
