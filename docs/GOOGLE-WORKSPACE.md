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
{"kind":"google_workspace_domain","calendar_reader":"calendar-reader@example.com",
 "email_domain":"example.com","grantee_domains":["example.com"]}
```

- `calendar_reader`: the one person Calendar is read as, by domain-wide
  delegation. It is also the bound on which calendars are in play: a
  calendar is in play only if its ACL holds the reader's own rule,
  `user:{calendar_reader}`, with role `writer` or `owner`. Every Calendar
  action reads that rule first. Seeing a calendar is not enough. Google also
  shows calendars to the reader through group, domain and default rules, and
  through organization-wide sharing (which appears as a domain rule). None of
  those count, and neither does the reader's own rule with `reader` or
  `freeBusyReader`. An exact lowercase address in `email_domain`, never
  normalised. A narrower grant keeps the same reader.
- `email_domain`: the only domain whose people may be impersonated, the
  reader and an event's owner alike. Lowercase ASCII. A narrower grant keeps
  the same domain.
- `grantee_domains`: the domains a group may belong to in order to be looked
  up, tested for membership or named in a calendar's ACL. Lowercase ASCII,
  strictly sorted and unique. A narrower grant may only drop domains.

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

Meet and Drive run as **the owner of a calendar event**.
The adapter derives the owner from the event it reads as `calendar_reader`,
and the owner is always the event's **creator**:

- the creator, when the creator is a person in `email_domain` and is also the
  organizer, exactly;
- the creator, when the creator is a person in `email_domain` and the
  organizer is a group or resource calendar (`@group.calendar.google.com`,
  `@resource.calendar.google.com`);
- otherwise there is no owner, the outcome is `NoOwner`, and nothing is
  impersonated.

The organizer alone is never trusted. Google's Events reference makes
`organizer` read-only *except when importing an event*, and `conferenceData`
is writable, so a writer on any calendar in play could `events.import` an
event naming anyone in the domain as organizer, with that person's meeting
code. `creator` is set by Google and cannot be written. Reading a group or
resource calendar's event as its creator is safe for the same reason: Meet
lists only the conferences that creator owns.

This fails closed. An assistant who creates an event on an executive's
calendar is its creator but not its organizer, so the event has no owner and
its conferences are not read.

A person in `email_domain` is an exact Workspace address, the rule
`calendar_reader` follows (lowercase letters, digits and `._+-`), whose domain
is exactly `email_domain`: not a subdomain, not another case. The owner is
delegated to with `meetings.space.readonly` alone. No other subject is ever
asked for: a test checks every `signJwt` the world served, and neither an
event organized from outside the domain nor one whose in-domain organizer did
not create it produces a token request for its organizer.

So an application can only act as someone who created a meeting on a calendar
in play, and only for that meeting.

When the token endpoint refuses the owner with OAuth's `invalid_grant`, as
Google does for a suspended, deleted or unknown person, the action fails with
`google_workspace_owner_refused`. Google also answers `invalid_grant` for an
assertion it will not accept, such as one outside its time window or with a
bad signature; the owner's exchange follows the reader's, which has just
succeeded with the same signer and clock, so the refusal is attributed to the
owner. It is a failure rather than an outcome because `invalid_grant` alone
cannot say which of those it is, and only its standard code is read, never
Google's description. A refused reader stays
`google_workspace_authentication_failed`: the reader is configuration.

## Actions

| Capability | Mode | Runs as | Scopes |
| --- | --- | --- | --- |
| `google_workspace.group.v1` | read | service account | `admin.directory.group.readonly` |
| `google_workspace.group_member.v1` | read | service account | `admin.directory.group.readonly`, `admin.directory.group.member.readonly` |
| `google_workspace.calendar.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.calendar_events.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.calendar_event.v1` | read | `calendar_reader` | `calendar.readonly`, `calendar.acls.readonly` |
| `google_workspace.event_conferences.v1` | read | `calendar_reader`, then the event's owner | `calendar.readonly`, `calendar.acls.readonly`; then `meetings.space.readonly` |
| `google_workspace.share_artifact.v1` | write | `calendar_reader`, then the event's owner | `calendar.readonly`, `calendar.acls.readonly`; then `meetings.space.readonly`, `drive` |

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
  `GET …/acl?maxResults=100[&pageToken]&fields=items(scope(type,value),role),nextPageToken`
  until the first rule whose scope is the named group (compared ignoring ASCII
  case, as Google treats addresses). `Found {id, summary, group_role}` with
  `group_role` one of `None`, `FreeBusyReader`, `Reader`, `Writer`, `Owner`,
  `NotShared` or `NotFound`. The ACL is never returned. At most four ACL pages
  are read, 400 rules when Google fills each page. A longer ACL fails with
  `google_workspace_acl_page_budget` rather than answering from part of it. The group must be in a grantee domain.
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
- **event_conferences** — `{calendar_id, event_id}`. As `calendar_reader`:
  the reader's rule and `events.get`, exactly as `calendar_event`, so
  `NotShared`, `NotFound` and `AllDay` mean what they mean there. Then, in
  order:
  - a cancelled event Google reports without times is `NotFound`: there is no
    window to search. A cancelled event that keeps its times and code is read
    like any other, since the meeting may have happened; whether to act on it
    is the application's policy, and `calendar_event` reports its status;
  - no Meet code is `NoMeeting`, derived as the Calendar actions derive it
    (`conferenceId` only for `hangoutsMeet`, else a `meet.google.com`
    `hangoutLink`);
  - no owner is `NoOwner`.

  Then, as the owner, one page at a time up to the ceiling:
  `GET meet.googleapis.com/v2/conferenceRecords?pageSize=5&filter=…&fields=conferenceRecords(name,space,startTime,endTime),nextPageToken`
  with exactly the filter
  `space.meeting_code = "{code}" AND start_time >= "{start − 30m}" AND start_time <= "{end + 30m}"`,
  times in whole UTC seconds (`YYYY-MM-DDTHH:MM:SSZ`). Each record's start is
  checked against the window again. A record outside it means Google did not
  apply the filter, so the page is refused as `response_invalid` rather than
  filtered. Records in more than one space are the outcome `Conflict`: one
  code names one space, and choosing between two is not the adapter's to do.
  For each record, `…/recordings`, `…/smartNotes` and `…/transcripts` with
  `pageSize=5` and the masks
  `recordings(name,state,driveDestination(file)),nextPageToken` and
  `{smartNotes|transcripts}(name,state,docsDestination(document)),nextPageToken`.

  `Found {owner, meeting_code, records}` lists records as Meet orders them,
  latest start first. Each record is `{name, space, start_time, end_time?,
  recordings, smart_notes, transcripts}`, and each artifact is
  `{name, state, file_id?}` or `{name, state, document_id?}` with `state` one of
  `Started`, `Ended`, `FileGenerated`. The Meet reference does not say a file
  or document ID is set only once `FILE_GENERATED`, so it is optional at every
  state. `STATE_UNSPECIFIED` is refused. File and document IDs are bare, as
  the reference gives them; a prefixed one (`files/…`, `documents/…`) is
  `response_invalid`. Names are checked exactly: `conferenceRecords/{id}`,
  `spaces/{id}` and `conferenceRecords/{record}/{collection}/{id}` for exactly
  the record listed, with IDs of at most 128 letters, digits, `-` and `_`.
  Timestamps are UTC with `Z` and 0, 3, 6 or 9 fractional digits. A `404` on
  an artifact list means the record was deleted after it was listed (Meet
  deletes a record 30 days after it ends), and the action fails with
  `google_workspace_conference_record_gone`: reading the event again lists its
  records as they are now.
- **share_artifact** — the only write, `(write, data)` in the registry and
  never destroying: `{calendar_id, event_id, artifact, group_email}`.
  `artifact` is one exact Meet name,
  `conferenceRecords/{r}/{recordings|smartNotes|transcripts}/{a}`, checked
  with the `event_conferences` name rules. `group_email` must be in a grantee
  domain or the action is refused before anything is reserved. It is
  admitted only as an effect of a command (`Api.external`), never as an
  observation. Every part is read again; nothing an earlier read returned is
  trusted:
  1. As `calendar_reader`, the reader's rule and `events.get`, then the
     owner, exactly as `event_conferences` derives them: `NotShared`,
     `NotFound`, `AllDay`, `NoMeeting` and `NoOwner` mean what they mean
     there.
  2. One token for the owner with `meetings.space.readonly` and `drive`; a
     refused owner is `google_workspace_owner_refused`.
  3. The event's conference records with the same pinned filter, window and
     paging. Records in two spaces are `Conflict`. The artifact's
     `conferenceRecords/{r}` must be one of them, or the outcome is
     `NotFound`: an artifact of another event is never shared.
  4. `GET meet.googleapis.com/v2/{artifact}?fields=name,state,driveDestination(file)`
     (or `docsDestination(document)`), whose name must repeat exactly. Only
     `FILE_GENERATED` with a bare file or document ID goes on; anything else
     is `NotReady`, and a `404` is `NotFound`.
  5. `GET www.googleapis.com/drive/v3/files/{id}/permissions?supportsAllDrives=true&pageSize=100&fields=permissions(id,type,role,emailAddress,deleted),nextPageToken`,
     up to two pages. A live (`deleted` false) `group` permission whose
     address equals the group ignoring ASCII case (as Google treats
     addresses, and as the ACL read compares them) with any role from
     `reader` up (`reader`, `commenter`, `writer`, `fileOrganizer`,
     `organizer`, `owner`) is `AlreadyShared {permission_id}`. A third page
     is `google_workspace_permission_page_budget`: never an answer from part
     of the list and never a create on top of one. A `404` is `NotFound`.
  6. Only then
     `POST …/files/{id}/permissions?supportsAllDrives=true&sendNotificationEmail=false&fields=id,type,role,emailAddress`
     with exactly `{"type":"group","role":"reader","emailAddress":"{group}"}`.
     The reply must echo a group, `reader` and the group's address:
     `Shared {permission_id}`.

  How the create's reply is read:
  - `200` echoing the request is `Shared`.
  - `409` lists again and answers `AlreadyShared`.
  - `400 invalidSharingRequest` is the outcome `SharingRefused`, for a group
    Drive does not know or a change the organization's sharing policy
    forbids. It is an outcome because Drive answered definitely and nothing
    was created; the application decides what to do.
  - `404` is `NotFound`.
  - Any other `400`, `401`, `403` (classified by reason, below) or `429` is a
    definite failure: nothing was created.
  - A lost reply, a `5xx`, an oversized or unreadable body, a `200` that
    does not echo the request, or a `409` the second list cannot confirm is
    `google_workspace_share_outcome_unknown`. See
    [Retries and unknown outcomes](#retries-and-unknown-outcomes).

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

An ACL page fits one 64 KiB Calendar response the same way. It is never
journaled, but it must be read whole:

- The largest rule Google can report under the fixed mask (no rule ID),
  compact, is 315 bytes. That is a `group` scope with a 254-byte address and
  the `freeBusyReader` role.
- A page of 100 of them with a 1,024-byte token is 32,654 bytes, half the
  bound.
- Google's own maximum of 250 per page could reach 80,054 bytes, so the
  adapter asks for 100.

`share_artifact` reserves both delegations (six exchanges), the reader's rule
and the event, two record pages, the artifact, two permission pages, the one
create, and two more permission pages for a `409`'s second list: sixteen in
all. Its posted payload, the two `signJwt` bodies, two token forms, every
query and the share body, fits the same 32 KiB request reservation as every
other action. A permission page holds at most 100 entries of a 128-character
ID, a role, a type and a 254-character address, well inside the 64 KiB
response bound.

Four pages, one reserved call each, cover 400 rules. A test builds the maximal
page against the response bound, and serves four of them through the
simulation.

An event's conferences are bounded the same way, and past a bound the action
fails rather than truncates:

- At most five conference records: two pages of five, so a short or empty
  first page can continue. A sixth record, or a continuation after the second
  page, is `google_workspace_conference_record_budget`.
- At most five recordings, five smart notes and five transcripts per record:
  one page of five each. A sixth, or any continuation, is
  `google_workspace_artifact_budget`.
- Every ID is at most 128 characters JSON does not escape, so a record name
  is at most 146 characters and an artifact name at most 287. The owner is at
  most 254, and a timestamp at most 30.

The largest outcome, five records each with five of every artifact at those
bounds, encodes to 38,193 bytes, 39,377 journaled. That is under the 56 KiB
page bound, and with a 4 KiB request, under the 64 KiB observation. A test
builds it and passes it through `bounded_observation`.

## Retries and unknown outcomes

Reads are side-effect free.

`share_artifact` is reconcilable rather than idempotent: Drive has no
idempotency key for permissions, so it always lists before it creates.

- **Unknown outcomes.** Once the create is sent, anything but a definite
  answer is `google_workspace_share_outcome_unknown`, and its usage is
  reported as not known. As for every write the platform cannot settle, the
  whole reservation stays held: it is never settled as a definite failure.
  That covers a lost reply, a `5xx`, an oversized or unreadable body, a reply
  that does not echo the request, and a `409` the second list cannot confirm.
- **Retries.** The capability is declared retry-safe the platform's way:
  `Authorized::retries_are_idempotent` names it, so the effect executor admits
  a second attempt of the same effect after an unknown outcome. That attempt
  lists the file's permissions, finds the first one and answers
  `AlreadyShared`; it never creates a second permission. Tests show this for
  a reply lost after Drive created the permission, in the pipeline and
  through the host.
- **What reconciliation does not promise.** It is verified reconciliation in
  the sense of [COMMAND-RUNTIME.md](COMMAND-RUNTIME.md#rust-enforcement-boundaries),
  not an idempotency key: a group removed by someone else between two runs is
  shared again, which is the intended outcome.
- **Duplicate creates.** Drive's documentation does not say what creating a
  permission that already exists returns. The simulation answers the existing
  permission with `200`, which the adapter reports as `Shared` with that ID.
  Since the adapter lists first, that only arises in a race. The real
  behaviour is a live qualification item.

## Bounds

Each action reserves its complete call and byte envelope, including the token
exchanges, against the physical connection `google_workspace/{service_account}`.
Every response is read with a maximum-plus-one bound, no redirect is followed,
nothing is retried inside an action, and provider values never reach error
strings, receipts or correlation. Failure codes are stable and redacted
(`google_workspace_*`).

Google reports rate and quota limits as `403` as well as `429`. A `403` is
classified by its reasons: Calendar's and the Directory's `error.errors[].reason`,
or, beside Meet's `error.status`, the `reason` of an `error.details[]` entry
whose `@type` is `google.rpc.ErrorInfo`; no other detail's fields are read.

- `rateLimitExceeded`, `userRateLimitExceeded`, `quotaExceeded`,
  `dailyLimitExceeded`, Drive's `sharingRateLimitExceeded`,
  `RATE_LIMIT_EXCEEDED` or `RESOURCE_QUOTA_EXCEEDED` is `rate_limited`;
- any other reason, such as a usage limit or a disabled API, or a status with
  no reason (`PERMISSION_DENIED`), is `denied`;
- a body with neither is `response_invalid`.

The reason itself never leaves the classifier. Only `404`, and `410` on
`events.get`, mean not found; on a Meet artifact list a `404` is a record
gone since it was listed.

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
  `events.list` and `events.get`;
- the four Meet routes: `conferenceRecords.list` and each record's
  `recordings`, `smartNotes` and `transcripts`.

It holds:

- the service account, and whether it has the Directory admin role;
- the delegation client's authorized scopes;
- users;
- groups, with nested memberships and aliases;
- calendars, with their ACLs and single events;
- suspended people, whom the token endpoint refuses as it refuses a stranger;
- Meet spaces, each with its meeting code and owner;
- conference records with start and end times, a rejoin being another record
  in the same space, and their recordings, smart notes and transcripts;
- the Drive files and Docs documents Meet generated, each with its owner and
  permissions, the owner's own first;
- the domains Drive may share with, when the organization restricts sharing.

An artifact advances `STARTED` → `ENDED` → `FILE_GENERATED` through
`google_meet_advance`, a scenario step. Generating it saves its Drive file or
Docs document, owned by the space's owner, and puts the ID on the artifact, as
Meet does; the next read reports it.

Who can see a calendar is its ACL, resolved as Google resolves it:

- The subject's highest role from its own `user` rule, a `group` rule for any
  group it belongs to (nested membership included), a `domain` rule for its
  domain, and the `default` rule.
- Organization-wide sharing is modelled as a domain rule.
- `reader` or more shows the calendar and its events; anything less is `404`.
- Reading the ACL, a single rule or the whole list, needs `writer` or `owner`;
  anything less is `403`.
- The service account itself has no calendars.

Who can see a conference record is its space's owner. Another person lists no
records for the code and is refused (`403 PERMISSION_DENIED`) a record's
artifacts. Whether co-hosts and participants see them too is a live
qualification item. A scenario can make the records list serve short or empty
pages that still continue, as AIP-158 allows (`meet_record_pages`).

Events cover:

- timed and all-day events;
- recurring instances with `originalStartTime`;
- cancelled instances reported by id alone, of timed and of all-day series;
- private and confidential visibility;
- group and resource organizers;
- Meet codes in `conferenceData` (with its solution type) or in `hangoutLink`
  only.

`timeMin`/`timeMax` select overlapping events in start order. The records
filter is parsed for exactly the pinned grammar; Meet records are listed latest
start first. Every route answers `400` to any query, filter or fields mask
other than the reviewed constants, `prettyPrint=false` included, so the
simulation cannot serve a request the adapter was not reviewed to send. Page tokens are opaque and bound to the
query that issued them, and another query's token, even a real one, is
`400`. That binding is a simulation assumption that live qualification
checks.

Simulated tokens are self-describing and verified by recomputing their tag:

- a forged or workload bearer gets `401`;
- a token without a route's scope gets `403`;
- only the service account itself holds the Directory role.

Delegation fails as Google does, for a scope the client is not authorized for
(`401 unauthorized_client`) and for a subject that is not an active person in
the organization, unknown or suspended (`400 invalid_grant`). The request log
names the subject of each `signJwt`, so a test sees exactly who was
impersonated. Addresses are matched exactly, never
normalised. `hasMember` takes a user key, and answers a nested question across
domains with `400 Invalid Input`.

Calendar and Directory errors use Google's envelope with a reason in
`errors[]`; Meet's use the newer envelope, a status and an `ErrorInfo` reason.
Scenarios schedule per-endpoint faults on every endpoint:

- `400`;
- `403` refused, and `403 rateLimitExceeded`;
- `404` for something just listed, such as an expired conference record;
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

Drive is served at its two permission routes and Meet at the single-artifact
route the share reads:

- Only the file's owner can list or change its permissions; a file the
  subject does not own is `404` (`writersCanShare` is not modelled).
- A create admits exactly the reviewed query and body: a group as `reader`.
- A group the world does not know, or one outside the trusted domains when
  sharing is restricted, is `400 invalidSharingRequest`.
- A group that already has a permission gets that permission back, unchanged,
  with `200`.
- Each created permission records the subject that created it, for
  invariants; the wire never carries it.
- The `ReplyLost` fault serves a request, so a create lands, and drops its
  reply, as a lost connection after Google acted would.

Planned: a seeded campaign of meetings, recordings, rejoins, faults and
duplicate deliveries against an independent model. That model checks that
every share lands only on an artifact of the named event, to a group in
`grantee_domains`, as reader and as the event's owner, and that a retried share
never creates a second permission.

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
      it, and short or empty pages that still carry a `nextPageToken`, on
      `events.list`, `acl.list` and `conferenceRecords.list` under a filter.
      A short ACL page still spends one of the four, so fewer than 400 rules
      may be covered; two empty record pages reach the records ceiling.
- [ ] `conferenceSolution.key.type` values for Meet, add-on and third-party
      conferences, and which of them carry a `hangoutLink`.
- [ ] Conference record visibility: whether `conferenceRecords.list` and the
      artifact lists show a space's records to co-hosts and participants, or
      to the owner alone as the simulation models it, and whether artifacts
      are refused with `403` or `404`.
- [ ] Who Meet treats as a meeting's organizer for `conferenceRecords.list`:
      the event's organizer or its creator, for an event a delegate created on
      someone else's calendar and for a group calendar's event.
- [ ] Forged organizers: the `creator` Google reports on an event created with
      `events.import`, and whether an external invitation whose `ORGANIZER`
      names an in-domain person appears with that organizer.
- [ ] The filter: that Meet accepts whole-second `Z` times (its examples use
      milliseconds), the spacing around operators, and a query string that
      encodes spaces as `+`.
- [ ] Artifact state progression and timing: how long `ENDED` lasts before
      `FILE_GENERATED`, and whether a file or document ID ever appears before
      it.
- [ ] A prefix on artifact IDs: whether `driveDestination.file` or
      `docsDestination.document` ever carries `files/` or `documents/`, which
      the adapter refuses.
- [ ] `smartNotes` availability on v2 for the organization's licence, and its
      answer where smart notes are off.
- [ ] Owner delegation: the token endpoint's answer for a suspended, deleted
      and archived person, all `invalid_grant` in the simulation.
- [ ] Meet's `403` and `429` bodies, and the `ErrorInfo` reasons it gives for
      each: which reasons come with `403` and which with `429`.
- [ ] Meet ID lengths and character sets for records, spaces and artifacts,
      against the 128-character bound.
- [ ] Drive's answer to creating a permission a group already has: `200` with
      the existing permission, as simulated, a `409`, or an error.
- [ ] Drive's refusal when the organization restricts sharing to trusted
      domains: `400 invalidSharingRequest`, as simulated, or a `403` with
      which reason. Also its answer for a group address with no Google
      account.
- [ ] Permission visibility: who besides the file's owner can list a Meet
      recording's permissions, and whether a non-owner's create is
      `403 insufficientFilePermissions`.
- [ ] Shared-drive files: whether Meet ever saves into a shared drive, and the
      permissions a shared drive adds or inherits.
- [ ] Permission propagation: how soon after a create the permission appears
      in the list, which matters to a retry's reconciliation.

## Status

`group`, `group_member`, `calendar`, `calendar_events`, `calendar_event`,
`event_conferences` and `share_artifact` are implemented. Addresses are
exact lowercase ASCII and are never normalised on the way in, so an application
lowercases what it stores.

A Directory action reserves three or four calls: metadata, IAM, then one call
per question. A Calendar action reserves the three delegated authentication
exchanges (metadata, `signJwt`, the token exchange), the reader's rule, and
then one more call: five in all. `calendar` instead reserves the calendar and
every ACL page up to the ceiling, nine in all. `event_conferences` reserves
both delegations (six exchanges), the reader's rule and the event, two pages
of records, and three artifact lists for each of the five records the ceiling
admits: twenty-five in all, so its grant's `max_calls_per_invocation` must be
at least 25. `share_artifact` reserves sixteen (see Bounds).
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
`group_outside_grant`, `acl_page_budget`, `owner_refused`,
`conference_record_budget`, `artifact_budget`, `conference_record_gone`,
`permission_page_budget` or `share_outcome_unknown`. Malformed application input is
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
3. `event_conferences`, with `email_domain` on the target and impersonation of
   the event's derived owner. (Done.)
4. `share_artifact`, reconciled by listing before it creates, with the
   saboteurs. (Done.)
5. Live qualification.
