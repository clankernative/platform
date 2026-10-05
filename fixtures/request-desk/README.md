# Request desk

An independent business caller for `stock-ledger`. Its normal build resolves and
pins the ledger's exported query and command, then generates the nominal typed
client. Each app owns a separate SQLite database and domain model.

`request_desk.request` reads advisory availability, records a local request, sends
the reservation command and stores its acceptance receipt. Acceptance is not a
business success. `request_desk.progress` asks for the closed receiver status.

`xtask build-delegation-business` builds both apps through the normal build recipe.
The platform verification gate runs a seeded public HTTP campaign against the
separate native hosts. Its stock oracle uses only public observations, including
owned totals and counts, and repeats every public command with the same key.
Protected artifact-bound transcripts remain under
`artifacts/delegation-business-evidence/`. No IAP assertions, browser cookies or
CSRF tokens are saved. A failing campaign preserves its last action and completed
observations.

For offline model replay, set `DAY2_REPLAY_DELEGATION_EVIDENCE` to a trace and run
the `release_execution` test
`replay_recorded_business_observations_without_hosts_or_providers`. Replay loads
no runtime, database or provider and makes no live calls. It checks the recorded
business observations, not the original host execution or authentication.

The local HTTP campaign uses signed IAP protocol fixtures and a selected serving
fixture. Native Linux qualification repeats it on the x86 kernel and exports
its four addressed app artifacts and replay evidence. Actual GKE authentication
is a separate canary requirement.
