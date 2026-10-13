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

Reads accept an increasing RFC3339 window of at most 31 days. The host admits at
most four provider pages, 100 events, 128 KiB per response and 30 KiB in the complete
result. Provider cursors and credentials stay private. Exceeding the limits returns
a problem; it never returns a truncated success. Local sign-in or workload actor
text does not establish a human connection.

This slice uses original activation token material only. Expired tokens require
reauthorization; real refresh publication, Calendar writes, live Google consent,
effective IAM/workload qualification and production-role authority remain separate
implementation and qualification work.
