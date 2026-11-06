# Restore passkey assertion denial

The Controller ceremony returns `Ok(None)` for a closed, typed rejection of the
submitted assertion only after the actual current registry and native-reader
postchecks succeed. The ceremony is spent and cannot be retried. The reader
remains held; the accepting action must still close its actual SQL connection
and settle its native loan before publishing a denial.

Malformed or mismatched browser assertion data, a missing user-verification
flag and a non-advancing counter are assertion denials.
Trusted-key, server-intent, enrollment, native-owner, SQL, configuration and
unknown failures remain errors and permanently refuse the reader. A native
postcheck error takes precedence over a known assertion denial;
two actual source errors preserve the primary error. Every such error refuses
the reader; the outer caller never reclassifies that error as DATA. Strings
that resemble a denial are not typed evidence of a denial.

Ring cannot distinguish an invalid signature from an invalid configured curve
point. Such cryptographic failures remain terminal errors; this change does not
claim that coordinate shape proves a valid P-256 public key.

Successful assertion facts remain DATA. This change does not sign or publish an
approval, consume a durable challenge, authenticate an executor, qualify time,
accept a restore or change any native check, deadline or custody rule.
