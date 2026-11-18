# Native restore conformance overlay

Build with `xtask build-restore-native`. The ordinary builder stages the existing
credential-metadata-conformance app once, then overlays these paths. No copied
credential handlers, models, identity history or second operation catalog is
introduced. This single app selects namespace `oauthcalendar`, the actual Calendar
requirement, and the credential-family contracts needed by the F fixture. It does
not contact Calendar during the marker query or establish provider readiness.
It deliberately has no app pages or credential-management UI query: the base
UI's command-link oracle pins its own namespace. F uses the declared API
operations and platform security pages, without copying or weakening that oracle.

`record_use` creates public `use_` labels through its normal declared transaction.
`restore_markers` reads the complete bounded marker set without truncation; its
check compares the full prior verification snapshot, including duplicate counts,
and requires no state change. A future native campaign chooses markers before
backup, writes different later markers, then compares restored results against
that independent expectation. The query itself is not the oracle or permission.

The artifact still needs a complete reviewed instance configuration matching its
credentials, OAuth/catalog/client/custody/native profile and all operations. The
Shell's native selection requires real OAuth bindings. Do not deploy this over an
old artifact's policy or relax admission. A local Build is not the missing genuine
Controller/Shell pair, a backup producer, an approved restore or a live campaign.

Nonempty callback, OAuth, uncertain-effect and budget-debt cases need their own
supported seed/consumer suppliers. Empty tables do not qualify those obligations.
The requester/destination policy for native backup remains undecided. There is
no backup requester, passkey route, private download or accepting owner here.
