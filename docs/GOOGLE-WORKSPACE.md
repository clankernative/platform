# Google Workspace: organization reads and one narrow write

`GoogleWorkspace` is the provider for work an application does across a Google
Workspace organization on nobody's personal behalf: reading shared calendars,
finding the Meet conferences scheduled on them, and sharing a finished Meet
recording with the group a calendar is shared with. It is keyless, every action
has a fixed scope and a fixed identity, and the only write it exposes is
*share this conference's artifact with this group as a reader*.

It is distinct from two neighbours:

- The [OAuth Calendar connection](OAUTH-INSTANCE.md) acts for one consenting
  person with their own grant. `GoogleWorkspace` acts through domain-wide
  delegation, without per-person consent, so it is far narrower in what it
  exposes.
- [`WorkspaceDirectory`](LIVE-INTEGRATIONS.md#workspace-directory-hierarchy-reads)
  delivers Home's organizational-unit hierarchy and user paths. It keeps its own
  provider and world; only the token acquisition is shared.

The motivating application is recording sharing: a schedule scans calendars,
and for each recorded meeting shares the recording, Gemini notes and transcript
with the group that can see the calendar. Business policy (which calendars,
which groups, when a meeting has settled, when to give up) stays in the
application.

## One provider, one world

Calendar, Meet, Drive and Directory are one provider with one simulated world,
`google_workspace.simulated.sqlite`. The flow crosses products: an event's Meet
code names conference records, whose recordings are Drive files shared with a
group that a calendar's ACL names. Separate worlds could not express
*schedule a meeting, record it, let the file finish, share it* in one
deterministic campaign. Policies still grant per action, so an application can
be granted calendar reads without the share.

## Connection and authentication

```json
{"provider":"google_workspace",
 "service_account":"day2-recordings@example-project.iam.gserviceaccount.com"}
```

No secret is mounted. The runtime's workload identity reads the fixed metadata
token endpoint, then asks IAM Credentials for a token for the service account:

| Identity | Exchange | Used by |
| --- | --- | --- |
| The service account itself | `serviceAccounts/{sa}:generateAccessToken` with the action's scopes | Directory reads |
| A delegated subject | `serviceAccounts/{sa}:signJwt` (`iss` = account, `sub` = subject, `aud` = Google's token endpoint, five-minute lifetime, the action's scopes), then the JWT-bearer grant at `oauth2.googleapis.com/token` | Calendar, Meet and Drive |

Every claim of the signed JWT is checked before it is exchanged, as
`WorkspaceDirectory` already does; that code becomes the shared
`google_auth` module both providers use. Tokens live for one action and are
never cached. Origins are fixed in the adapter; nothing about a URL is
configurable.

Operator prerequisites, none of which the platform performs:

1. The runtime identity holds `roles/iam.serviceAccountTokenCreator` on the
   service account.
2. The service account holds a Workspace admin role that can read groups and
   memberships (Google's *Groups Reader*).
3. The service account's OAuth client is authorized for domain-wide delegation
   in the Admin console for exactly `calendar.readonly`,
   `calendar.acls.readonly`, `meetings.space.readonly` and `drive`.

## Resource target

```json
{"kind":"google_workspace_domain","email_domain":"example.com",
 "calendar_reader":"calendar-reader@example.com",
 "grantee_domains":["example.com"]}
```

- `email_domain`: the only domain whose people may be impersonated.
- `calendar_reader`: the one person Calendar is read as. Calendar reads see
  exactly the calendars shared with this account, and the ACL read requires
  that it can see them; this is how an operator bounds which calendars are in
  play, without listing them in configuration.
- `grantee_domains`: the domains a group may belong to in order to be looked
  up, tested for membership or granted access. Strictly sorted and unique.

All three are lowercase ASCII and `calendar_reader` must be in `email_domain`.

## Who is impersonated

An application never names a subject. Meet and Drive run as **the owner of a
calendar event**, derived by the adapter from the event it reads as
`calendar_reader`:

- the organizer, if it is a person in `email_domain`;
- otherwise, when the organizer is a group or resource calendar
  (`@group.calendar.google.com`, `@resource.calendar.google.com`), the creator,
  if that is a person in `email_domain`;
- otherwise there is no owner and nothing is impersonated.

So an application can only act as someone who organized a meeting on a calendar
shared with the reader, and only for that meeting.

## Actions

| Capability | Mode | Runs as | Scopes |
| --- | --- | --- | --- |
| `google_workspace.group.v1` | read | service account | `admin.directory.group.readonly` |
| `google_workspace.group_member.v1` | read | service account | `admin.directory.group.readonly`, `admin.directory.group.member.readonly` |
| `google_workspace.calendar.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.calendar_events.v1` | read | `calendar_reader` | `calendar.readonly` |
| `google_workspace.calendar_event.v1` | read | `calendar_reader` | `calendar.readonly` |
| `google_workspace.event_conferences.v1` | read | `calendar_reader`, then the event's owner | `calendar.readonly`; `meetings.space.readonly` |
| `google_workspace.share_artifact.v1` | write | `calendar_reader`, then the event's owner | `calendar.readonly`; `meetings.space.readonly drive` |

- **group** — `GET admin/directory/v1/groups/{group}?fields=id,email,name`.
  `Found {id, email, name}` or `NotFound`. The requested address must be in a
  `grantee_domains` domain, and so must the primary address Google reports,
  which may differ from an alias that was asked about
  (`google_workspace_group_outside_grant` otherwise).
- **group_member** — the group read above, then
  `GET …/groups/{group}/hasMember/{member}` (direct or nested). `Member`,
  `NotMember` or `GroupNotFound`. The group is looked up first because a `404`
  from `hasMember` alone cannot say whether the group or the member is missing;
  a `404` once the group exists is `NotMember`. The member must be in
  `email_domain` or a grantee domain.
- **calendar** — the calendar's `id` and `summary`, and the role one named group
  holds in its ACL (`none`, `free_busy_reader`, `reader`, `writer`, `owner`).
  The ACL is paged inside the action up to a fixed page ceiling and never
  returned. `NotFound` covers both a missing calendar and one the reader cannot
  see.
- **calendar_events** — one page of single events in a window of at most 31
  days, including cancelled ones, ordered by start. Each event has `id`,
  `status`, `visibility`, `start`, `end`, the original start of a recurrence
  instance, `organizer`, `creator` and the Meet code from `conferenceData` (or
  the `hangoutLink` path). All-day events are omitted. The page size is fixed
  so a page fits one observation; the application persists the page token.
- **calendar_event** — one event in the same shape, or `NotFound`.
- **event_conferences** — for one event: its derived owner and Meet code, the
  conference records for that code starting within thirty minutes of the
  event, and each record's recordings, smart notes and transcripts with their
  `state` (`started`, `ended`, `file_generated`) and generated Drive file or
  document ID. `NoOwner` and `NoMeeting` are outcomes, not errors.
- **share_artifact** — for one event, one artifact name and one group: the
  adapter re-reads the event, re-derives its owner, confirms through Meet that
  the artifact belongs to one of that event's conference records and has
  `file_generated`, lists the file's permissions as the owner and, only if the
  group does not already hold reader or better, creates
  `{type: group, role: reader}` with `sendNotificationEmail=false`. `Shared`,
  `AlreadyShared`, `NotReady`, `NotFound` or `NoOwner`.

There is no revoke, no other role, no user or domain grantee, no file the Meet
API did not name, and no Drive search. Nothing is ever deleted.

## Retries and unknown outcomes

Reads are side-effect free. `share_artifact` is reconcilable: it always lists
before it creates, and a duplicate creation (Google answers `409` or returns the
existing permission) re-lists. A share whose response was lost is therefore
safe to run again with the same effect identity, and the second run answers
`AlreadyShared`. This is verified reconciliation in the sense of
[COMMAND-RUNTIME.md](COMMAND-RUNTIME.md#rust-enforcement-boundaries), not an
idempotency key: a group removed by someone else between the two runs is shared
again, which is the intended outcome.

## Bounds

Each action reserves its complete call and byte envelope, including the token
exchanges, against the physical connection `google_workspace/{service_account}`.
Every response is read with a maximum-plus-one bound, no redirect is followed,
nothing is retried inside an action, and provider values never reach error
strings, receipts or correlation. Failure codes are stable and redacted
(`google_workspace_*`).

## Simulation

The simulated port answers the same HTTP requests the native port sends —
metadata, IAM, token exchange, Directory, Calendar, Meet and Drive — from the
SQLite world, so token handling, URL construction, paging and parsing run on the
real path in both lanes. The world holds users, groups and nested memberships,
the delegation client's authorized scopes, calendars and ACLs, events (recurring
instances, cancellations, reschedules, private and confidential visibility,
group and resource organizers), Meet spaces and conference records (a rejoin is
a second record), artifacts that advance `started` → `ended` →
`file_generated`, Drive files and permissions. Delegation fails as Google does
for a scope the client is not authorized for and for a subject outside the
domain.

Scenarios schedule faults per endpoint: `429`, `5xx`, a timeout, a malformed or
oversized body, and a lost reply after a permission was created. The gates are
the ones [PROVIDER-REGISTRY.md](PROVIDER-REGISTRY.md#what-this-does-not-do)
requires: a parity suite, coverage of every action and every adapter error, and
a saboteur that a broken simulation must fail. A seeded campaign runs histories
of meetings, recordings, rejoins, faults and duplicate deliveries against an
independent model: every share lands only on an artifact of the named event, to
a group in `grantee_domains`, as reader, as the event's owner, and a retried
share never creates a second permission.

## Live qualification

`google-workspace-qualify` is an explicit operator recipe in
`ops/GoogleWorkspaceQualification.roc`, like `carta-qualify`. It runs every
read against a profile naming a test calendar and group, and optionally one
share of a designated test recording, and publishes a receipt of shapes,
statuses and counts with no provider values. Receipts report
`provider_qualified: false` until reviewed.

## Status

`group` and `group_member` are implemented; the other actions in the table are
the planned contract and are not yet declared in the registry. Addresses are
exact lowercase ASCII and are never normalised on the way in, so an application
lowercases what it stores.

A Directory action reserves three or four calls (metadata, IAM, then one call
per question), 32 KiB of request payload and 16 KiB plus a probe byte for each
response, and settles what it actually used. A failure keeps the phase,
status and `Retry-After` of its final exchange as correlation, never content.
Codes are `google_workspace_` followed by `workload_identity_unavailable`,
`authentication_failed`, `denied` (a `403` from the Directory: the service
account lacks its admin role or the API is off), `rate_limited`, `unavailable`,
`request_refused`, `response_invalid`, `response_too_large`, `request_budget` or
`group_outside_grant`. Malformed application input is
`google_workspace_request_invalid`, and an address outside the grant is
refused as a resource authorization; neither reaches the network.

Simulated tokens are self-describing and verified by recomputing their tag, so
serving a read changes nothing in the world but its request log. The parity
bases follow Google's published response shapes until the qualification recipe
records real ones (`crates/day2/fixtures/provider-responses/GOOGLE-WORKSPACE-PROVENANCE.md`).

## Delivery

1. `google_auth` extracted from `WorkspaceDirectory`; the connection, target,
   registry entry, port, world and the two Directory reads. (Done.)
2. The three Calendar reads.
3. `event_conferences`.
4. `share_artifact`, with reconciliation and the saboteur.
5. Live qualification.
