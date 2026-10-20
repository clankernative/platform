# Calendar connection and read canary

This complete app declares one current-human, mapped company-account requirement
for reading Calendar events. The admitted artifact is a small deployment target
for the installation's native security-shell registration campaign. The ordinary
`inspect` query reports app-owned intent. The `list_events` product query resolves
the current verified human's requirement and reads their primary Calendar through
private host custody. Both preserve an empty product database.

Build it with the ordinary platform recipe:

```text
cargo run --locked -p xtask -- build fixtures/oauth-calendar-canary
```

Keep company domains, identities, real Google client IDs, exact Secret Manager
versions, and deployment selectors in the company's instance repository. Select
the resulting artifact as `oauthcalendar`, then run `day2 oauth-setup INSTANCE`
to derive the desired binding pins and exact provider callback. Review the
emitted `instance` document before saving it. Desired metadata proves no live
readiness; the authenticated shell campaign must publish a fresh native receipt.

Reads accept an increasing RFC3339 window of at most 31 days. The host admits
one GET, 100 events, 128 KiB per response and 30 KiB in the complete
result. Provider cursors and credentials stay private. Exceeding the limits returns
a problem; a provider continuation always returns capacity_deferred. It never
returns a truncated success. Local sign-in or workload actor
text does not establish a human connection.

The host selects authenticated current token material. For the reviewed Google
reusable profile it refreshes privately during resolution when at most 60 seconds
remain, including an expired access token whose connection has not already been
refused. Refresh verifies the unchanged provider account and exact consented
scopes. One transaction replaces ciphertext, advances the material version and
records the attempt receipt. A failed or ambiguous send never authorizes another
automatic refresh. Recovery reads the committed replacement or requires a new
connection. A committed expiry, material or clock refusal is never cleared.

The native conformance fixture exercises Calendar reads using material versions
2 and 3, stale Uses, concurrent successor publication, and real process exits at
the dispatch fence, ciphertext write and publication commit. Only the provider,
readiness and clock ports are simulated. Calendar writes, live Google
connect/use/refresh, effective IAM/workload qualification and production-role
authority remain separate implementation and qualification work.

Expiry and clock rollback observed at custody, dispatch and post-read readiness
checks persist refusal for the exact token generation/version. Final and replay
checks reject an invalid Use inside their decision transaction; a failed decision
does not separately publish a persistent clock refusal. A qualified clock producer
and complete cross-clock qualification remain follow-up work.

Refresh also carries its latest checked clock and exact published material
through Use issuance. A late refusal for version 2 cannot disable an independently
authenticated version 3. Whole-database rollback and qualified clock/workload
authority are not established by these local tests.
