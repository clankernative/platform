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

Today the target carries what the Directory and Calendar reads use:

```json
{"kind":"google_workspace_domain","calendar_reader":"calendar-reader@example.com",
 "grantee_domains":["example.com"]}
```

- `calendar_reader`: the one person Calendar is read as, by domain-wide
  delegation. It is also the bound on which calendars are in play: a
  calendar is in play only if its ACL holds the reader's own rule,
  `user:{calendar_reader}`, with role `writer` or `owner`. Every Calendar
  action reads that rule first. Seeing a calendar is not enough. Google also
  shows calendars to the reader through group, domain and default rules, and
  through organization-wide sharing (which appears as a domain rule). None of
  those count, and neither does the reader's own rule with `reader` or
  `freeBusyReader`. An exact lowercase address, never normalised. A narrower
  grant keeps the same reader. Until `email_domain` arrives with step 3, the
  reader's domain is not separately constrained: the operator chooses it, and
  Google refuses delegation to anyone who is not a person in the organization.
- `grantee_domains`: the domains a group may belong to in order to be looked
  up, tested for membership or named in a calendar's ACL. Lowercase ASCII,
  strictly sorted and unique. A narrower grant may only drop domains.

The last field arrives with the first action that reads it, so a target never
carries authority nothing enforces yet:

- `email_domain` (step 3, impersonation): the only domain whose people may be
  impersonated. `calendar_reader` will then have to be in it.

## Who is impersonated

An application never names a subject.

Calendar is read as `calendar_reader` and no one else. The operator puts a
calendar in play by giving that account an explicit `writer` rule on it, one
calendar at a time:

- Use a dedicated reader account, such as `calendar-reader@example.com`, that
  belongs to no person and is in no group. Then the calendars in play are
  exactly the ones an operator shared with it.
- Give the account `writer` on each calendar, with its own address as the
  grantee. Sharing with a group it belongs to, the domain or the public does
  not put a calendar in play.
- `writer` is the least role that lets Google show the reader a calendar's
  sharing, and the adapter needs the sharing for `calendar`. The delegated
  token carries only `calendar.readonly` and `calendar.acls.readonly`, so the
  account's write access is never used.
- To take a calendar out of play, remove the reader's rule. Its next read is
  `NotShared`.

Planned for step 3: Meet and Drive run as **the owner of a calendar event**,
derived by the adapter from the event it reads as `calendar_reader`:

- the organizer, if it is a person in `email_domain`;
- otherwise, when the organizer is a group or resource calendar
  (`@group.calendar.google.com`, `@resource.calendar.google.com`), the creator,
  if that is a person in `email_domain`;
- otherwise there is no owner and nothing is impersonated.

So an application can only act as someone who organized a meeting on a calendar
in play, and only for that meeting.

## Actions

| Capability | Mode | Runs as | Scopes |
| --- | --- | --- | --- |
| `google_workspace.group.v1` | read | service account | `admin.directory.group.readonly` |
| `google_workspace.group_member.v1` | read | service account | `admin.directory.group.readonly`, `admin.directory.group.member.readonly` |
| `google_workspace.calendar.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.calendar_events.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.calendar_event.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.event_conferences.v1` | read | `calendar_reader`, then the event's owner | `calendar.readonly calendar.acls.readonly`; `meetings.space.readonly` |
| `google_workspace.share_artifact.v1` | write | `calendar_reader`, then the event's owner | `calendar.readonly calendar.acls.readonly`; `meetings.space.readonly drive` |

Every request carries `prettyPrint=false`, Directory included, and nothing in
its route or query comes from anywhere but the reviewed constants and the
validated inputs.

- **group** — `GET admin/directory/v1/groups/{group}?fields=id,email,name`.
  `Found {id, email, name}` or `NotFound`. The requested address must be in a
  `grantee_domains` domain, and so must the primary address Google reports,
  which may differ from an alias that was asked about
  (`google_workspace_group_outside_grant` otherwise).
- **group_member** — the group read above, then
  `GET …/groups/{group}/hasMember/{member}` (direct or nested). `Member`,
  `NotMember` or `GroupNotFound`. The group is looked up first because a `404`
  from `hasMember` alone cannot say whether the group or the member is missing;
  a `404` once the group exists is `NotMember`. The member must be in the
  group's own domain: Google answers a nested membership question only when
  member and group share a domain (otherwise `400 Invalid Input`), so a
  question it cannot answer is refused before dispatch. The member key is a
  user, as the reference defines it.
- **The reader's rule**, before every Calendar action:
  `GET calendar/v3/calendars/{calendar}/acl/user:{calendar_reader}?fields=scope(type,value),role`.
  The rule ID is one path segment. The action goes on only if the rule is the
  reader's own with `writer` or `owner`; a lesser role is the outcome
  `NotShared`. Without the rule Google answers `404`, or `403` when the reader
  may not read rules at all (that needs `writer` or `owner`). A `403` with a
  rate or quota reason is `rate_limited`. Otherwise the adapter reads
  `GET calendar/v3/calendars/{calendar}?fields=id,summary` to tell the cases
  apart:
  - a calendar the reader can see is `NotShared`;
  - a `404` there is `NotFound`;
  - a refusal there too is `denied`, for example a disabled API, never a
    calendar that is merely not shared.

  A rule reported for any other scope is `google_workspace_response_invalid`.
- **calendar** — after the reader's rule, `GET calendar/v3/calendars/{calendar}?fields=id,summary`, then
  `GET …/acl?maxResults=250[&pageToken]&fields=items(scope(type,value),role),nextPageToken`
  until the first rule whose scope is the named group (compared ignoring ASCII
  case, as Google treats addresses). `Found {id, summary, group_role}` with
  `group_role` one of `None`, `FreeBusyReader`, `Reader`, `Writer`, `Owner`,
  `NotShared` or `NotFound`. The ACL is never returned. At most four ACL pages
  are read. A longer ACL fails with `google_workspace_acl_page_budget` rather
  than answering from part of it. The group must be in a grantee domain.
- **calendar_events** — after the reader's rule, one page of
  `GET …/events?singleEvents=true&orderBy=startTime&showDeleted=true&maxResults=25&timeMin&timeMax[&pageToken]`
  with the item mask
  `id,originalStartTime,start,end,status,visibility,creator/email,organizer/email,conferenceData(conferenceId,conferenceSolution/key/type),hangoutLink`.
  `time_min` and `time_max` are RFC 3339 with whole seconds and an explicit
  offset (`Z` or `±HH:MM`), increasing, and at most 31 days apart; an event is
  on the page when it overlaps the window. `Found {events, next_page_token,
  all_day_omitted}`, `NotShared` or `NotFound`. Each event has `id`,
  `status`, `visibility` (`Default`, `Public`, `Private`, `Confidential`),
  `original_start` for a recurring instance, `organizer`, `creator` and
  `meeting_code`, as reported. The status carries the times it implies:
  `Confirmed {start, end}`, `Tentative {start, end}`, `Cancelled {start, end}`,
  or `CancelledUntimed` for a cancelled exception Google reports by `id` and
  `originalStartTime` alone. Only a cancelled event can lack its times.
  (`Cancelled([Timed(Times), Untimed])` would be the nested spelling, but the
  pinned Roc compiler crashes deriving a decoder for a union that carries
  `Times` both directly and nested.) The Meet code is `conferenceData.conferenceId`
  only when `conferenceSolution.key.type` is `hangoutsMeet`. Otherwise it is the
  path of a `https://meet.google.com/{code}` `hangoutLink`. Either way it is
  kept only in Meet's `xxx-xxxx-xxx` shape. An all-day event carries no time and
  is omitted, and so is a cancelled instance of an all-day series (a date
  `originalStartTime` and no `start`). `all_day_omitted` counts both. The
  application persists the page token, which continues only the query that
  issued it.
- **calendar_event** — after the reader's rule, `GET …/events/{event}` with the
  same item mask. `Found(Event)`; `AllDay` for an all-day event or a cancelled
  instance of an all-day series; `NotShared`; or `NotFound` (`404` or `410`).
  A cancelled instance of a timed series is `Found` with `CancelledUntimed`
  or `Cancelled {start, end}`.
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

Calendar IDs are exact: lowercase ASCII, one `@`, a local part of letters,
digits and `._+-`, and a domain of lowercase labels, which covers people's
calendars and Google's `@group.calendar.google.com` and
`@resource.calendar.google.com` IDs. Event IDs are ASCII letters, digits and
`_`, up to 1,024 characters, which covers recurring instances'
`_YYYYMMDDTHHMMSSZ` suffix. Every accepted character is safe in a URL path
segment, so nothing an application supplies can change a route.

A page of 25 events journals within one observation by construction. Every
reported field is bounded to characters JSON does not escape:

- addresses are at most 254 bytes of letters, digits, `.` `_` `%` `+` `-` `'`
  and one `@`;
- IDs are at most 1,024 bytes of letters, digits and `_`;
- times are at most 25 bytes;
- page tokens are at most 1,024 printable bytes other than `"` and `\`.

Anything else is `google_workspace_response_invalid`. The largest event
encodes to 1,803 bytes. Twenty-five of them with the longest token come to
46,196 bytes, or 47,310 once journaled with its quotes escaped. That is under
the 56 KiB page bound, and with a 4 KiB request, under the 64 KiB observation.
A test builds that page and passes it through `bounded_observation`. The page
is still measured against the bound, never assumed to fit.

## Retries and unknown outcomes

Reads are side-effect free. The rest of this section is the planned contract
for `share_artifact` (step 4). `share_artifact` is reconcilable: it always lists
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

Google reports rate and quota limits as `403` as well as `429`. A `403` is
classified by `error.errors[].reason`:

- `rateLimitExceeded`, `userRateLimitExceeded`, `quotaExceeded` or
  `dailyLimitExceeded` is `rate_limited`;
- any other reason, such as a usage limit or a disabled API, is `denied`;
- a body without reasons is `response_invalid`.

The reason itself never leaves the classifier. Only `404`, and `410` on
`events.get`, mean not found.

## Simulation

The simulated port answers the same HTTP requests the native port sends from
the provider's world, so token handling, URL construction and parsing run on the
real path in both lanes.

Today the world serves:

- the metadata server;
- IAM `generateAccessToken` and `signJwt`;
- the JWT-bearer token exchange;
- the two Directory routes;
- the five Calendar routes: `calendars.get`, `acl.get`, `acl.list`,
  `events.list` and `events.get`.

It holds:

- the service account, and whether it has the Directory admin role;
- the delegation client's authorized scopes;
- users;
- groups, with nested memberships and aliases;
- calendars, with their ACLs and single events.

Who can see a calendar is its ACL, resolved as Google resolves it:

- The subject's highest role from its own `user` rule, a `group` rule for any
  group it belongs to (nested membership included), a `domain` rule for its
  domain, and the `default` rule.
- Organization-wide sharing is modelled as a domain rule.
- `reader` or more shows the calendar and its events; anything less is `404`.
- Reading the ACL, a single rule or the whole list, needs `writer` or `owner`;
  anything less is `403`.
- The service account itself has no calendars.

Events cover:

- timed and all-day events;
- recurring instances with `originalStartTime`;
- cancelled instances reported by id alone, of timed and of all-day series;
- private and confidential visibility;
- group and resource organizers;
- Meet codes in `conferenceData` (with its solution type) or in `hangoutLink`
  only.

`timeMin`/`timeMax` select overlapping events in start order. Every route
answers `400` to any query or fields mask other than the reviewed constants,
`prettyPrint=false` included, so the simulation cannot serve a request the
adapter was not reviewed to send. Page tokens are opaque and bound to the
query that issued them, and another query's token, even a real one, is
`400`. That binding is a simulation assumption that live qualification
checks.

Simulated tokens are self-describing and verified by recomputing their tag:

- a forged or workload bearer gets `401`;
- a token without a route's scope gets `403`;
- only the service account itself holds the Directory role.

Delegation fails as Google does, for a scope the client is not authorized for
(`401 unauthorized_client`) and for a subject that is not a person in the
organization (`400 invalid_grant`). Addresses are matched exactly, never
normalised. `hasMember` takes a user key, and answers a nested question across
domains with `400 Invalid Input`.

Errors use Google's envelope with a reason in `errors[]`. Scenarios schedule
per-endpoint faults on every endpoint:

- `400`;
- `403` refused, and `403 rateLimitExceeded`;
- `429` with `Retry-After`;
- `5xx`;
- a lost connection;
- a non-JSON body;
- an oversized body.

The gates are the ones
[PROVIDER-REGISTRY.md](PROVIDER-REGISTRY.md#what-this-does-not-do) requires: a
parity suite, coverage of every action, every failure code produced through an
action, and saboteurs that a constant or world-mutating simulation must fail.
Host tests run the actions through admission, reservation and settlement.

Planned, by delivery step:

- Step 3: Meet spaces and conference records (a rejoin is a second record), and
  artifacts that advance `started` → `ended` → `file_generated`.
- Step 4: Drive files and permissions, a lost-reply fault after a permission
  was created, and a seeded campaign of meetings, recordings, rejoins, faults
  and duplicate deliveries against an independent model. That model checks
  that every share lands only on an artifact of the named event, to a group in
  `grantee_domains`, as reader and as the event's owner, and that a retried
  share never creates a second permission.

## Live qualification

Planned for step 5; neither the recipe nor the command exists yet.
`google-workspace-qualify` will be an explicit operator recipe in
`ops/GoogleWorkspaceQualification.roc`, like `carta-qualify`. It will run every
read against a profile naming a test calendar and group, and optionally one
share of a designated test recording, and publish a receipt of shapes,
statuses and counts with no provider values. Receipts will report
`provider_qualified: false` until reviewed.

### Qualify live (step 5)

What the simulation assumes and only Google can settle:

- [ ] `403` versus `404` for a calendar the reader has no access to, and for
      one shared with it as free/busy only, on `acl.get`, `calendars.get`,
      `acl.list`, `events.list` and `events.get`. Record the `403` reasons
      seen.
- [ ] Private-event detail hiding for `reader`: which fields a private event
      reports to a reader below `writer`.
- [ ] Cancelled and deleted shapes under `singleEvents=true&showDeleted=true`:
      cancelled exceptions of timed and all-day series, and deleted events.
      Google may report a deleted item by `id` alone, without `status`. The
      adapter refuses that as `response_invalid`, and the simulation cannot
      serve it today. Decide whether to model it and how to report it.
- [ ] Page tokens: whether `events.list` binds a token to the query that issued
      it, and short or empty pages that still carry a `nextPageToken`.
- [ ] `acl.list` page size with `prettyPrint=false`. 250 rules at the
      longest addresses would exceed the 64 KiB response bound, which fails
      as `response_too_large`. Check real page sizes and lower the page size
      if needed.
- [ ] `conferenceSolution.key.type` values for Meet, add-on and third-party
      conferences, and which of them carry a `hangoutLink`.

## Status

`group`, `group_member`, `calendar`, `calendar_events` and `calendar_event` are
implemented; `event_conferences` and `share_artifact` are the planned contract
and are not yet declared in the registry. Addresses are
exact lowercase ASCII and are never normalised on the way in, so an application
lowercases what it stores.

A Directory action reserves three or four calls: metadata, IAM, then one call
per question. A Calendar action reserves the three delegated authentication
exchanges (metadata, `signJwt`, the token exchange), the reader's rule, and
then one more call: five in all. `calendar` instead reserves the calendar and
every ACL page up to the ceiling, nine in all.
Each reserves 32 KiB of request payload and, for each response, 16 KiB
(authentication and Directory) or 64 KiB (Calendar) plus a probe byte, and
settles what it actually used. Its grant must admit the whole envelope:
`max_request_bytes` of at least 32 KiB and `max_response_bytes` of at least
the action's largest response (16 KiB for Directory reads, 64 KiB for Calendar
reads), or the action is refused before anything is reserved. The
simulated or native source is frozen when the capability is authorized. A failure keeps the phase,
status and `Retry-After` of its final exchange as correlation, never content.
Codes are `google_workspace_` followed by `workload_identity_unavailable`,
`authentication_failed`, `denied` (a `403` whose reason is not a rate or quota
limit, from either API: for example the service account lacks its Directory
role, or an API is off), `rate_limited` (a `429`, or a `403` with a rate or
quota reason), `unavailable`,
`request_refused`, `response_invalid`, `response_too_large`,
`group_outside_grant` or `acl_page_budget`. Malformed application input is
`google_workspace_request_invalid`, and an address outside the grant is
refused as a resource authorization; neither reaches the network.

Serving a read changes nothing in the world but its request log. The parity
bases follow Google's published response shapes until the qualification recipe
records real ones (`crates/day2/fixtures/provider-responses/GOOGLE-WORKSPACE-PROVENANCE.md`).

## Delivery

1. `google_auth` extracted from `WorkspaceDirectory`; the connection, target,
   registry entry, port, world and the two Directory reads. (Done.)
2. The three Calendar reads, by delegation as `calendar_reader` and bounded by
   its own `writer` or `owner` rule. (Done.)
3. `event_conferences`.
4. `share_artifact`, with reconciliation and the saboteur.
5. Live qualification.
