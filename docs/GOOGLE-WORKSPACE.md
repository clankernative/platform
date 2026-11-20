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
| `google_workspace.share_artifact.v1` | write | `calendar_reader`, the service account, then the event's owner | `calendar.readonly`, `calendar.acls.readonly`; `admin.directory.group.readonly`; then `meetings.space.readonly`, `drive` |

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
  `originalStartTime` and no `start`). `all_day_omitted` counts both.

  The application persists `next_page_token` and sends it back only with the
  calendar, `time_min` and `time_max` that issued it, as exact strings. Google
  does not enforce that: given another window's token it answered an empty
  page with no error (observed 2026-11-20, see
  [Qualify live (step 6)](#qualify-live-step-6)), as applying the token's
  position, or a cursor, to the new window would. So the adapter binds every
  token it hands out:

  - The token is `v1.{binding}.{google}`. `binding` is the first 32 hex digits
    of the SHA-256 of the identity that read the page (the source, simulated
    or native, the service account and the Calendar reader) and of the one
    request the query sends, built by the same code that sends it, with its
    `pageToken` left out: the route, the window and every fixed parameter and
    field mask. `google` is Google's own token, at most 988 bytes, so the
    whole token stays within the 1,024-byte bound; a longer one is
    `google_workspace_response_invalid`. Whether Google's tokens come close is
    not observed (see [Qualify live (step 6)](#qualify-live-step-6)).
  - A continuation is sent to Google, unwrapped, only when its binding is this
    request's. Anything else is `google_workspace_request_invalid`, refused
    when the capability is authorized, before anything is reserved or sent:
    another window's or calendar's token; one issued under another reader,
    service account or source; one from before the request or a reviewed
    constant changed (a test pins the binding, so such a change is
    deliberate); a bare Google token; or a token of another shape.
  - That is the code for every application input the adapter refuses before
    the network. A mismatched token is input for the wrong query, and the
    remedy is the same as for any invalid input: start the query again
    without a token. A distinct code would invite repairing a token instead.
  - The digest is unkeyed. It catches a mistake, not a forger: an application
    can only send a token for a calendar its grant already lets it read, so a
    forged token gains nothing the grant does not already allow.

  Tokens of internal paging (ACL pages, conference records, artifact and
  permission lists) never leave the action, and each is sent back only with
  the identical request.
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
  2. As the service account, with `admin.directory.group.readonly`, the
     Directory's `groups.get` for `group_email`. Its primary address must be
     in a grantee domain and equal `group_email` exactly. An alias, in the
     grant or not, is `GroupNotPrimary`, and an unknown group is
     `GroupNotFound`. Nothing is ever shared to an alias: Drive grants the
     group itself, so the permission would name an address the application
     did not.
  3. One token for the owner with `meetings.space.readonly` and `drive`; a
     refused owner is `google_workspace_owner_refused`.
  4. The event's conference records with the same pinned filter, window and
     paging. Records in two spaces are `Conflict`. The artifact's
     `conferenceRecords/{r}` must be one of them, or the outcome is
     `NotFound`: an artifact of another event is never shared.
  5. `GET meet.googleapis.com/v2/{artifact}?fields=name,state,driveDestination(file)`
     (or `docsDestination(document)`), whose name must repeat exactly. Only
     `FILE_GENERATED` with a bare file or document ID goes on; anything else
     is `NotReady`, and a `404` is `NotFound`.
  6. `GET www.googleapis.com/drive/v3/files/{id}/permissions?supportsAllDrives=true&pageSize=100&fields=permissions(id,type,role,emailAddress,deleted),nextPageToken`,
     up to two pages. A live (`deleted` false) `group` permission whose
     address equals the group ignoring ASCII case (as Google treats
     addresses, and as the ACL read compares them) with any role from
     `reader` up (`reader`, `commenter`, `writer`, `fileOrganizer`,
     `organizer`, `owner`) is `AlreadyShared {permission_id}`. A third page
     is `google_workspace_permission_page_budget`: never an answer from part
     of the list and never a create on top of one. A `404` is `NotFound`.
  7. Only then
     `POST …/files/{id}/permissions?supportsAllDrives=true&sendNotificationEmail=false&fields=id,type,role,emailAddress`
     with exactly `{"type":"group","role":"reader","emailAddress":"{group}"}`.
     The reply must echo a group, `reader` and the group's address:
     `Shared {permission_id}`.

  How the create's reply is read:
  - `200` echoing the request is `Shared`.
  - A lost reply, a `5xx` or any status not named here, an oversized or
    unreadable body, a `200` that does not echo the request, and a `409`
    list the file's permissions again, within the same attempt, on the two
    pages reserved for it. A live group permission from `reader` up is
    `Shared` (the create plausibly landed), or `AlreadyShared` after a `409`,
    which says it existed. A failed list or a permission still absent is
    `google_workspace_share_outcome_unknown`. See
    [Retries and unknown outcomes](#retries-and-unknown-outcomes).
  - `400 invalidSharingRequest` lists again too. A permission found is
    `Shared`; none is the outcome `SharingRefused`, a share the
    organization's sharing policy forbids (or a group deleted since step 2).
    It is an outcome because Drive answered definitely and nothing was
    created; the application decides what to do. A failed list is
    `share_outcome_unknown`.
  - `404` is `NotFound`: the file went, or the owner lost it, between the
    list and the create, and nothing was created.
  - Any other `400`, `401`, `403` (classified by reason, below) or `429` is a
    definite failure: nothing was created.

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
- page tokens are at most 1,024 printable bytes other than `"` and `\`, and
  Google's events token at most 988, so that its binding fits.

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

`share_artifact` reserves both delegations (six exchanges), the service
account's own token (two), the reader's rule and the event, the group, two
record pages, the artifact, two permission pages, the one create, and two
more permission pages for the second list: nineteen in all. Its posted
payload, the two `signJwt` bodies, the `generateAccessToken` body, two token
forms, every query and the share body, fits the same 32 KiB request reservation as every
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
idempotency key for permissions, so it lists before it creates, and an attempt
that cannot read the create's answer lists again before it answers.

- **Reconciled inside the attempt.** A second list that finds the group's
  permission answers `Shared` or `AlreadyShared` (see the share contract
  above) and settles the calls the attempt actually made. Its usage is known
  whenever the meter knows it.
- **Unknown outcomes.** A second list that fails, or does not find the
  permission, is `google_workspace_share_outcome_unknown`, and its usage is
  reported as not known. As for every write the platform cannot settle, the
  whole reservation stays held: it is never settled as a definite failure,
  and the effect is never attempted again. Running the same effect again
  replays the settled failure without calling Google.
- **What `retries_are_idempotent` covers.** It names the share, so the effect
  executor admits a second attempt of an effect whose first attempt was
  admitted but never settled: a worker that crashed between the two. That
  attempt lists first and answers `AlreadyShared` if the first one landed.
  It admits nothing after an unknown outcome.
- **After an unknown outcome.** The held reservation blocks every later
  action on its budget until an installation administrator reconciles it, as
  a Linear write's does under a one-slot budget
  ([LINEAR-SIMULATION.md](LINEAR-SIMULATION.md)):

  ```text
  day2 platform resources reconcile-usage INSTANCE APP LOCAL_OPERATOR RECONCILIATION_JSON_FILE
  ```

  The `proof` is the failure's correlation, which names the Drive phase,
  status and `Retry-After` of the last exchange, with the file's permissions
  as its owner sees them. See
  [RESOURCE-ENFORCEMENT.md](RESOURCE-ENFORCEMENT.md) for the request. Then
  the application issues a new command; the new share lists first, so it
  answers `AlreadyShared` if the first one landed.
- **Give shares their own budget.** A slot that grants `share_artifact` must
  bind a budget with `concurrency` 1, or resource validation refuses it
  (`google_workspace_share_requires_a_serial_budget`). Shares on that budget
  never run at once, so two creates never race on one file. Concurrency is
  per budget: two budgets that both grant shares to one grant can still
  race, so bind one. Keep reads on another budget, so a held share does not
  block them.
- **Propagation.** A permission Drive created may not appear in a list at
  once. A second list that misses it makes the outcome unknown, never a
  second create inside the attempt. How long that delay lasts is a live
  qualification item.
- **What reconciliation does not promise.** It is verified reconciliation in
  the sense of [COMMAND-RUNTIME.md](COMMAND-RUNTIME.md#rust-enforcement-boundaries),
  not an idempotency key: a group removed by someone else between two
  commands is shared again, which is the intended outcome.
- **Duplicate creates.** Drive's documentation does not say what creating a
  permission that already exists returns. The simulation answers the existing
  permission with `200`, which the adapter reports as `Shared` with that ID,
  and a `409` is reconciled to `AlreadyShared`. Since the adapter lists first
  and shares are serial, that only arises when someone outside the platform
  shares the same file at the same moment. The real behaviour is a live
  qualification item.

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
- `reader` or more shows the calendar and its events.
- `freeBusyReader` shows the calendar itself (`calendars.get` is `200`) and
  refuses its ACL with `403 forbidden`; the adapter answers `NotShared`. Live,
  on 2026-11-20, only `acl.get` on `user:{reader}` (`403 forbidden`) and
  `calendars.get` (`200`) were observed; the ACL list's answer is assumed.
  Its events stay `404`, also not observed: the adapter never reads the
  events of a calendar out of play.
- No access at all is `404` for every route. Live, `acl.get` and
  `calendars.get` were both `404`.
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
simulation cannot serve a request the adapter was not reviewed to send. Page
tokens are opaque and tagged, so a forged one is `400`. An events token is
bound only to its calendar: another window's token is accepted and its
position applied to the new window, a short or empty page. Live, on
2026-11-20, Google answered another window's token with an empty page, which
an offset and a cursor both explain; refusing another calendar's token is an
assumption. ACL and record tokens stay bound to their whole query, another
query's being `400`; that is an assumption the adapter never tests, since it
resends those tokens only with the identical request.

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
- an oversized body;
- a `409` served after the request was, so a create lands and Drive answers
  that the permission exists.

The gates are the ones
[PROVIDER-REGISTRY.md](PROVIDER-REGISTRY.md#what-this-does-not-do) requires: a
parity suite, coverage of every action, every failure code produced through an
action, and saboteurs that a constant or world-mutating simulation must fail.
The share's coverage runs it twice and then for another of the owner's
meetings' artifacts: `Shared`, `AlreadyShared`, `NotFound`, with exactly one
permission added. Its saboteurs patch the port the adapter reads through, not
the world afterwards: one hides the group's permission from every list, so the
second run answers `Shared` for a permission that exists; one adds the other
meeting's record to the event's records, so the third run lands a permission on
the other meeting's file. Both must fail the gate. Host tests run the actions
through admission, reservation and settlement.

Drive is served at its two permission routes and Meet at the single-artifact
route the share reads:

- Only the file's owner can list or change its permissions; a file the
  subject does not own is `404` (`writersCanShare` is not modelled).
- A create admits exactly the reviewed query and body: a group as `reader`.
- A create may name a group by its primary address or an alias. Drive grants
  the group itself, so the permission stores the primary address.
- A group the world does not know, or one outside the trusted domains when
  sharing is restricted, is `400 invalidSharingRequest`.
- A group that already has a permission gets that permission back, unchanged,
  with `200`.
- Each created permission records the subject that created it, for
  invariants; the wire never carries it.
- The `ReplyLost` fault serves a request, so a create lands, and drops its
  reply, as a lost connection after Google acted would.

A seeded campaign drives the share against an independent ordered model,
modelled on the [Linear campaign](LINEAR-SIMULATION.md):

- Six fixed seeds each run up to forty logical steps, and every history runs
  twice and must match.
- Each history opens with a fixed prefix that witnesses every definite
  outcome, then composes seeded steps over a meeting and its rejoin, a second
  meeting of the same owner, and a group calendar's review.
- Steps cover:
  - artifacts advancing `STARTED` → `ENDED` → `FILE_GENERATED`;
  - shares to three groups, an alias and a group nobody has;
  - duplicate deliveries;
  - a forged organizer;
  - artifacts of another event, including one of the same owner's other
    meeting, which only the check that a record belongs to the event
    refuses;
  - the calendar leaving and re-entering play;
  - sharing restricted to a domain no group is in (`SharingRefused`);
  - faults on the create: a reply lost after the permission landed and a
    `409` after it landed, both reconciled inside the attempt, a refusal, and
    a `5xx` or lost connection before it.
- A history ends at its first unknown outcome. Its reservation would stay
  held until an operator reconciles it, which the campaign does not model.
  At least one history must run its full length.
- The model knows each artifact's state, whether the calendar is in play,
  whether sharing is restricted and which shares have landed. Its table of
  artifacts names each one's record, collection, ID, event and owner
  outright, rather than parsing names the way the adapter does. It predicts
  every answer, and after every step the world's group permissions must
  equal its prediction exactly:
  - each is a group `reader` in a grantee domain;
  - it is on the file Meet named for that artifact of that event;
  - it was created as that event's derived owner;
  - none is created twice;
  - none exists for a forged, not-shared or foreign-event share.
- Independently of the model, a `Shared` answer must find no group
  permission on that file before the attempt.
- A failure saves a bundle of only the format, the campaign source digest and
  the seed under `artifacts/google-workspace-share-simulation/`.

To replay a saved bundle:

```console
DAY2_GOOGLE_WORKSPACE_SHARE_REPLAY=<failure.json> bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib google_workspace::tests::campaign::replay_saved_share_history --exact
```

Replay at the revision that failed. The bundle pins the campaign file, not the
adapter, the simulation or the compiler it ran against, so the same seed at
another revision may take another path. Unknown fields, oversized bundles and
changed campaign sources are refused before anything runs.

The campaign runs the real pipeline against the simulated port; host
admission, reservation and settlement are covered by the host tests. It is not
published as a CI receipt the way the Linear campaign is. These are synthetic
adapter checks, not host, live-provider or production qualification.

## Live qualification

`google-workspace-qualify` is the explicit operator qualification. It is not
part of any verification recipe:

```console
bazel run //crates/xtask:xtask -- google-workspace-qualify PROFILE TOKEN_FILE NEW_EVIDENCE_DIRECTORY
```

It follows the [Carta qualification](CARTA.md#remaining-qualification). The
private [`ops/GoogleWorkspaceQualification.roc`](../ops/GoogleWorkspaceQualification.roc)
recipe owns the step order and runs through `ops/Runner.roc`:

1. `open` the inputs;
2. the read steps: `directory`, `calendars`, `events`, `event`, `conferences`
   and `share-alias`;
3. `share`, the one write;
4. `check`, repeated until the permission is listed or seven checks have
   run;
5. `discard` the run;
6. publish the `receipt`.

Every step is a closed native operation with an empty input. The native
session
([`crates/xtask/src/google_workspace_qualify.rs`](../crates/xtask/src/google_workspace_qualify.rs))
and the run
([`google_workspace_qualification`](../crates/day2/src/google_workspace_qualification.rs))
enforce what must hold whatever order the recipe chooses:

- `open` first, then the run's steps, then `discard`, then `receipt`;
- each read step once, and all of them before the share;
- the share once;
- checks only after a share whose outcome leaves something to check (`Shared`
  or `share_outcome_unknown`), only until one finds the permission, and at
  most seven, each after its minimum wait.

A step out of order, with arguments, unknown or replayed is refused before
anything is sent. A failed step closes the session and drops the run, with its
port, its copy of the token and every provider value it held. Nothing is
retried: the recipe stops at the first failure, the adapter never retries, and
no step can run twice.

- **Inputs.** The profile is admitted from its exact bytes before the token is
  read: a format, the fixtures, and an expiry no more than a week away. Every
  probe's request must pass the adapter's own `Plan::authorize`, so a profile
  naming a group outside the grant, or a malformed calendar, event or
  artifact, is refused before anything is sent. The token's shape is checked
  next, before the evidence directory exists: one token of printable ASCII,
  not JSON. Both files are read through `NOFOLLOW` as regular files of at most
  16 KiB, and the token file must be owner-private. The evidence directory
  must be new; it is created `0700`.
- **Probes.** Every probe is an ordinary action, planned by `Plan::authorize`
  and run by `google_workspace::observe` through the native port: the same
  pipeline, bounds and classification the host runs. Between the adapter and
  the port a recording layer keeps only closed classifications of each
  exchange:
  - its reviewed endpoint name, status and byte count;
  - reviewed error reasons and statuses (anything else is counted as
    `reason_other`);
  - counts of reviewed field forms, such as an event's conference type or a
    permission's role. An unknown form is counted as `*_other`.

  A successful authentication reply is never parsed: it holds a token. A
  refusal's reason is classified.
- **One write.** The recording layer also fences requests. It passes:
  - a request without a body to one of the reviewed read endpoints;
  - the one permission create, during the share step only.

  Anything else, such as a create during a read step or a check, or a request
  to any other endpoint, is refused unsent and recorded as `fenced`. A run
  therefore creates at most one permission whatever any probe does. The
  receipt's `creates_sent` and `requests_fenced` count both.
- **Marker.** Before the share step can send its create, the session writes
  `share-started.json` (`0600`, create-new) into the evidence directory. A run
  killed afterwards still shows that a permission may exist.
- **Receipt.** `receipt.json` is created `0600`. It names each fixture by its
  role in the profile, never by its address or ID. Its `profile_digest` is
  `sha256:` followed by the SHA-256 of the exact profile bytes, as
  `sha256sum profile.json` prints it. `adapter` names the receipt's format,
  not a code revision. `recipe_sources` is the digest of the private recipe
  sources the run was built with, which does not cover the adapter's Rust, so
  record the platform commit with the receipt. Before publishing, the session
  refuses a receipt that claims `provider_qualified`, contains the token or
  contains any string value of the profile. A profile value that happens to
  occur in the receipt's own text, such as inside a digest, blocks publishing;
  run again. Every receipt reports `provider_qualified: false` until a
  reviewer accepts it.

A simulated rehearsal of the whole session, through the same probes, fences
and guards, runs in the unit tests
([`google_workspace_qualification_tests.rs`](../crates/day2/src/google_workspace_qualification_tests.rs)
and the session tests).

### The workload token

The runtime gets its workload token from the metadata server, and an operator's
machine has none. The session reads the operator's own short-lived access token
from an owner-private file instead. The run presents it to IAM exactly where
the runtime presents its workload token, and nowhere else. Everything after
that is unchanged and runs as in the runtime:

- IAM `generateAccessToken` for the Directory, as the service account;
- `signJwt` and the JWT-bearer exchange for Calendar, Meet and Drive, by
  domain-wide delegation.

The run therefore exercises the same keyless chain and the same delegation
client authorization.

```console
(umask 077 && gcloud auth print-access-token > token)
```

**Authority.** The operator's principal needs
`roles/iam.serviceAccountTokenCreator` on the one service account the profile
names. That is the authority the runtime's workload identity already holds,
granted to a person for one session:

- grant it on that service account, not the project;
- give it an IAM condition that expires with the profile;
- remove it after the run.

The platform gains nothing: no key, no new role, no new API and no stored
credential. A service-account key file is never accepted. The token must be
a single token of printable ASCII without spaces, which a key file is not.

**Why not a Compute Engine host.** The other keyless option is a host whose
attached service account holds Token Creator on the target service account.
That authority would be standing, and every process on the host would hold
it; on the shared qualification runner, that means every CI job. It also
needs a host in the organization's project. The operator's token instead:

- expires within an hour;
- can be attributed to a person in the IAM Data Access audit logs, when
  those logs are on and stored (see the fixture setup);
- is sent only to IAM.

**Where the substitution can run.** What holds:

- `OperatorWorkload` is a private type of
  [`google_workspace_qualification`](../crates/day2/src/google_workspace_qualification.rs).
  It answers only the metadata exchange and passes every other exchange
  through.
- Only `Qualification`'s two constructors build it, and a `Qualification`
  runs nothing but its fixed steps.
- `Qualification::native` is an architecture hazard: every call site needs
  its own reviewed allowance in `architecture-rules.json`, and the only one is
  `xtask google-workspace-qualify`. A call anywhere else, in the runtime or
  another crate, fails `architecture-check`.
- The runtime's `NativeGooglePort::new()` takes no token, and
  `google_auth::acquire` is unchanged.
- The only reads of a bearer from a file are the reviewed allowances of the
  shared qualification input module in xtask.

What does not hold: `GooglePort`, `Reply` and `google_workspace::observe` are
public, so Rust does not stop other code in the crate from writing its own port
that answers the metadata exchange. Such a port is new code that only review
catches.

### The profile

```json
{
  "format": 1,
  "service_account": "workspace-reader@example-project.iam.gserviceaccount.com",
  "calendar_reader": "calendar-reader@example.com",
  "email_domain": "example.com",
  "grantee_domains": ["example.com"],
  "calendars": {
    "in_play": "c_qualify@group.calendar.google.com",
    "free_busy": "c_free_busy@group.calendar.google.com",
    "unshared": "c_unshared@group.calendar.google.com"
  },
  "window": {"time_min": "2026-01-05T00:00:00Z", "time_max": "2026-02-04T00:00:00Z"},
  "events": {"recorded": "recordedevent0001", "imported": "importedevent0002"},
  "group": "qualify-team@example.com",
  "group_alias": "qualify-alias@example.com",
  "group_member": "member@example.com",
  "artifact": "conferenceRecords/RECORD/recordings/RECORDING",
  "expires_at": 1767225600
}
```

The calendars, events, groups and artifact must be distinct where their roles
differ. The window may be at most 31 days, as for `calendar_events`.

### Live fixture setup

An administrator creates these in the organization before a run. This is the
instance checklist for a live run:

1. **The connection.** The service account and its domain-wide delegation, as
   for any `google_workspace` connection:
   - the Groups Reader admin role;
   - a delegation client authorized for exactly `calendar.readonly`,
     `calendar.acls.readonly`, `meetings.space.readonly` and `drive`.
2. **The operator's authority.** Token Creator for the operator on that service
   account, conditioned to expire with the profile. Turn on IAM Data
   Access audit logs (`DATA_READ`) in the project. On 2026-11-20 the IAM
   policy API refused `iamcredentials.googleapis.com` as an audit-config
   service (`INVALID_ARGUMENT`) and accepted `iam.googleapis.com`. Before the
   run, make one test impersonation and confirm that its
   `generateAccessToken` call appears in a stored `data_access` log: the
   project's `_Default` sink, another project sink or an organization or
   folder aggregated sink must keep it. On 2026-11-20 the project's `_Default`
   sink was disabled and no stored entry was found, so that run's calls are
   not attributable.
3. **The reader.** `calendar_reader`, a user in `email_domain` that nobody
   signs in as.
4. **The in-play calendar** (`calendars.in_play`). A secondary calendar on
   which the reader holds its own "Make changes to events" (`writer`) rule,
   holding:
   - **The recorded event** (`events.recorded`). Created on that calendar by
     a person in `email_domain`, with Google Meet. Hold the meeting, record
     it and turn on transcripts, then wait until Meet has generated the
     recording's file. Its organizer is the calendar and its creator the
     person, which is the group-calendar case the adapter reads as the
     creator.
   - **The imported event** (`events.imported`). Made with `events.import`
     on the calendar, naming another in-domain person as organizer, so that
     its creator is not its organizer.
     On 2026-11-20 Google refused the import
     (`participantIsNeitherOrganizerNorAttendee`) until the in-play calendar
     was listed as an attendee, so list it as one. Copy the recorded event's
     `conferenceData` onto it (`conferenceDataVersion=1`): without a Meet
     code the action answers `NoMeeting` before it derives an owner, and
     `conferences_imported` cannot show `NoOwner`.
   - **Within the window**:
     - a daily timed recurring event of at least 26 instances, with one
       instance deleted;
     - an all-day recurring event with one instance deleted;
     - one event created and then deleted.

     That is more than one page of 25 events, so the paging and token probes
     run, and it exercises Google's cancelled and deleted shapes. Place the
     deleted event and the deleted instances after the 25th event by start
     time. Google may report a deleted event by its ID alone, which the
     adapter refuses; on the first page that would leave the paging and token
     probes unsettled. An event with an add-on or third-party conference is
     optional.
5. **The free/busy calendar** (`calendars.free_busy`). Shared with the reader
   as "See only free/busy".
6. **The unshared calendar** (`calendars.unshared`). Not shared with the
   reader in any way.
7. **The group** (`group`), in a grantee domain:
   - an alias added in the Admin console (`group_alias`), also in a grantee
     domain;
   - one direct member (`group_member`) in the group's own domain;
   - no permission on the artifact's file.
8. **The artifact** (`artifact`). The recorded event's recording, by its exact
   Meet name, read with the Meet API's `conferenceRecords.list` and
   `recordings.list` as the meeting's host.
9. **The profile.** It must expire within a week.

### After a run

The run never deletes anything. Remove its one permission by hand:

1. As the recording's owner, open the file's sharing dialog in Drive and
   remove the group. Alternatively, find the group's permission with Drive's
   `permissions.list` and delete it with `permissions.delete`.
2. Remove the operator's Token Creator binding.
3. Delete the token file.

A second run needs the permission removed first: otherwise the share finds it,
answers `AlreadyShared`, and no create is exercised (`creates_sent: 0`). An
evidence directory holding `share-started.json` but no receipt is a run killed
after the share step began: check the file's permissions by hand.

### Qualify live (step 6)

What the simulation assumes and only Google can settle. A reviewer settles
each item; a receipt only records evidence. Each item names the receipt field
that records it, as `probe` → field, or is **manual**: a person must set it
up or judge it, and the doc says why. "Shape" is an exchange's `shape`
counts.

- [x] `403` versus `404` for a calendar the reader has no access to, and for
      one shared with it as free/busy only, on `acl.get`, `calendars.get`,
      `acl.list`, `events.list` and `events.get`. Record the `403` reasons
      seen.
      **Automated** for the two the adapter sends to a calendar out of play:
      `calendar_unshared` and `calendar_free_busy` → the
      `calendar_reader_rule` (`acl.get`) and `calendar_get` exchanges'
      status and reasons. The adapter never sends `acl.list`, `events.list`
      or `events.get` to such a calendar, so their answers there cannot
      affect it.
      **Live, 2026-11-20:** Unshared: `acl.get` `404` and `calendars.get`
      `404`, so `NotFound`. Free/busy only: `acl.get` `403` with reason
      `forbidden` and `calendars.get` `200`, so `NotShared`.
- [ ] Private-event detail hiding for `reader`: which fields a private event
      reports to a reader below `writer`.
      **Manual, and moot for the adapter**: it never reads a calendar as
      less than `writer`.
- [ ] Cancelled and deleted shapes under `singleEvents=true&showDeleted=true`:
      cancelled exceptions of timed and all-day series, and deleted events.
      Google may report a deleted item by `id` alone, without `status`. The
      adapter refuses that as `response_invalid`, and the simulation cannot
      serve it today. Decide whether to model it and how to report it.
      **Automated**: `events_page` → shape `cancelled`, `id_only`,
      `all_day`, and each page's outcome (`Found` or `response_invalid`). The
      decision stays with the reviewer. A refused first page leaves the
      paging and token probes unsettled, and the receipt says so
      (`events_token_other_query` → `unsettled_first_page_refused`).
      **Live, 2026-11-20:** Three cancelled items (`cancelled` 3) and no
      `id_only`, and both pages were `Found`, for fixtures that deleted one
      timed instance, one all-day instance and one event. One run does not
      show that Google never sends an id-only item; the decision is open.
- [ ] Page tokens: whether `events.list` binds a token to the query that issued
      it, and short or empty pages that still carry a `nextPageToken`, on
      `events.list`, `acl.list` and `conferenceRecords.list` under a filter.
      A short ACL page still spends one of the four, so fewer than 400 rules
      may be covered; two empty record pages reach the records ceiling.
      **Automated** for the adapter: `events_token_other_query` offers the
      first page's token with another query, the same calendar and start and
      a window one day long. The adapter binds each token to its query (see
      `calendar_events`), so it must answer
      `google_workspace_request_invalid` with no calls; a receipt whose probe
      reached Google would show the binding missing. The probe no longer
      observes Google: doing so would need a request the adapter never sends,
      outside its reviewed requests and the fence, and Google's answer,
      recorded below, no longer affects the adapter. `unsettled_single_page`
      and `unsettled_first_page_refused` mean the probe could not run. The
      page forms are observed, not forced: every list exchange's shape
      `items` and `next_page_token_present` / `_empty`.
      **Live, 2026-11-20**, from the probe as it then was:
      `events_token_other_query` was `Found` with shape `items` 0 and
      `events_at_or_after_time_max` 0. Google accepted another query's token
      instead of refusing it, and answered an empty page although the one-day
      window held timed events: it applied the token's position to the new
      window. The adapter now binds tokens, and the simulation answers as
      Google did. Pages were full (25) or final; no short page with a token
      was seen.
- [ ] `conferenceSolution.key.type` values for Meet, add-on and third-party
      conferences, and which of them carry a `hangoutLink`.
      **Automated** for the events in the window: `events_page` → shape
      `conference_*`, `hangout_link` and `hangout_link_without_conference`.
      An add-on or third-party conference needs its optional fixture.
      **Live, 2026-11-20:** `hangoutsMeet` with a `hangoutLink`, on two events
      sharing one Meet. Add-on and third-party conferences were not
      exercised.
- [ ] Conference record visibility: whether `conferenceRecords.list` and the
      artifact lists show a space's records to co-hosts and participants, or
      to the owner alone as the simulation models it, and whether artifacts
      are refused with `403` or `404`.
      **Manual**: the adapter reads only as the owner. Read the same lists
      as a participant in the Meet API explorer.
- [ ] Who Meet treats as a meeting's organizer for `conferenceRecords.list`:
      the event's organizer or its creator, for an event a delegate created on
      someone else's calendar and for a group calendar's event.
      **Automated** for a group calendar's event: `event_recorded` →
      `organizer` (`group_calendar`), with `conferences_recorded` → `records`
      and `artifact_listed`. **Moot** for a delegate's event: it has no owner
      (`NoOwner`), so the adapter never asks Meet.
      **Live, 2026-11-20:** For a group calendar's event, Meet listed the
      record and its artifacts to the event's creator. The creator also
      hosted the meeting, so participant visibility explains it as well;
      the item stays open with conference record visibility.
- [ ] Forged organizers: the `creator` Google reports on an event created with
      `events.import`, and whether an external invitation whose `ORGANIZER`
      names an in-domain person appears with that organizer.
      **Automated** for `events.import`: `event_imported` → `organizer`
      (`person_in_domain` when the creator differs) and `creator_in_domain`,
      and `conferences_imported` → `NoOwner`. **Manual** for an external
      invitation, which needs a sender outside the organization.
      **Live, 2026-11-20:** The imported event reported an organizer in the
      domain who is not its creator, with a creator in the domain; seen by
      hand, the creator was the importer. The adapter answered `NoOwner` and
      asked for no owner token. The external invitation is still open.
- [x] The filter: that Meet accepts whole-second `Z` times (its examples use
      milliseconds), the spacing around operators, and a query string that
      encodes spaces as `+`.
      **Automated**: `conferences_recorded` → `Found` with `records` above
      zero. A refused filter is `google_workspace_request_refused`.
      **Live, 2026-11-20:** Accepted: one record found by meeting code and
      window.
- [ ] Artifact state progression and timing: how long `ENDED` lasts before
      `FILE_GENERATED`, and whether a file or document ID ever appears before
      it.
      **Partly automated**: the artifact lists' shape `state_*` and
      `destination_*` at run time. **Manual** timing: watch the lists in the
      hours after a meeting.
      **Live, 2026-11-20:** At run time the recording, transcript and smart
      notes were `FILE_GENERATED` with bare destinations. Seen once by hand:
      polling the Meet API as the owner, the recording had no file ID while
      `ENDED`, and became `FILE_GENERATED` about six minutes after the
      conference ended.
- [x] A prefix on artifact IDs: whether `driveDestination.file` or
      `docsDestination.document` ever carries `files/` or `documents/`, which
      the adapter refuses.
      **Automated**: shape `destination_prefixed` versus
      `destination_bare`.
      **Live, 2026-11-20:** Bare (`destination_bare` on every artifact list
      and the artifact `GET`).
- [ ] `smartNotes` availability on v2 for the organization's licence, and its
      answer where smart notes are off.
      **Automated**: `conferences_recorded` → the `meet_smart_notes`
      exchange's status and reasons.
      **Live, 2026-11-20:** Available where smart notes are on: `200`, and a
      `FILE_GENERATED` note with a bare document ID. The answer where they
      are off is still open.
- [ ] Owner delegation: the token endpoint's answer for a suspended, deleted
      and archived person, all `invalid_grant` in the simulation.
      **Manual**: it needs an event whose creator an administrator has
      suspended, deleted or archived. The run then reports
      `google_workspace_owner_refused`, with the `oauth_token` exchange's
      reason.
- [ ] Meet's `403` and `429` bodies, and the `ErrorInfo` reasons it gives for
      each: which reasons come with `403` and which with `429`.
      **Observed** when they occur: every Meet exchange's reasons. Forcing
      them is manual.
- [x] Meet ID lengths and character sets for records, spaces and artifacts,
      against the 128-character bound.
      **Automated**: shape `ids_outside_bound` on records and artifacts
      (absent when every ID fits).
      **Live, 2026-11-20:** One record, its space and three artifacts all fit
      the bound (no `ids_outside_bound`).
- [ ] Drive's answer to creating a permission a group already has: `200` with
      the existing permission, as simulated, a `409`, or an error. And for a
      group that already holds `writer`: whether the create changes its role.
      **Manual**: the run's one create is for a group with no permission,
      and the fence refuses a second one.
- [ ] Group aliases: whether Drive accepts an alias in `emailAddress`, and
      which address the created permission and later lists report. The
      adapter never sends one.
      **Automated** up to Drive:
      - `directory_group_alias` → `primary_is_group` settles that the
        Directory resolves the alias to its primary address;
      - `share_alias` → `GroupNotPrimary` settles that the adapter refuses
        the alias before Drive.

      **Manual** in Drive itself.
      **Live, 2026-11-20:** The Directory resolved the alias to its group's
      primary address, and `share_alias` was `GroupNotPrimary` with no Drive
      call. Drive itself is still open.
- [ ] Drive's refusal when the organization restricts sharing to trusted
      domains: `400 invalidSharingRequest`, as simulated, or a `403` with
      which reason. Also whether `invalidSharingRequest` can follow a create
      that landed, and its answer for a group address with no Google account.
      **Manual**: an administrator must change the sharing policy.
- [ ] A user's address sent as `type: group`: Drive's refusal. The adapter
      resolves the address as a Directory group first, so only an address
      reused between the lookup and the create could reach Drive.
      **Manual**: the adapter never sends one.
- [ ] Two creates for one group racing on one file: whether both land, and
      what each returns. Shares are serial per budget; this settles what an
      outside actor's race does.
      **Manual**: it needs a second writer.
- [ ] Permission visibility: who besides the file's owner can list a Meet
      recording's permissions, and whether a non-owner's create is
      `403 insufficientFilePermissions`. Also whether a writer can share
      under `writersCanShare`, and how lists report permissions inherited
      from a folder and `view: published` permissions; the simulation models
      none of them.
      **Manual**: the adapter acts only as the owner. The run's
      `drive_permissions` shape (`type_*`, `role_*`, `deleted`) shows what
      the owner's list reports.
- [ ] Meet's answer to a single artifact `GET` by someone other than the
      space's owner: `403` (`denied`) or `404` (`NotFound`).
      **Manual**: the adapter reads only as the owner.
- [ ] Shared-drive files: whether Meet ever saves into a shared drive, and the
      permissions a shared drive adds or inherits.
      **Manual**. A `role_organizer` or `role_file_organizer` count in the
      `drive_permissions` shape is a hint.
- [ ] Permission propagation: how soon after a create the permission appears
      in the list. A delay longer than the attempt makes a reconcilable
      outcome unknown.
      **Automated**: `visible_after_ms`, and each `share_again` probe's
      `elapsed_ms`: monotonic time from the create's reply to that check's
      first permission list, so it includes the exchanges each check makes
      before it lists. Each check first waits its minimum delay,
      `check_delays_seconds` (0, 1, 2, 4, 8, 16 and 32 seconds), recorded as
      its `delay_seconds`. Each check is the share with the fence closed: it
      answers `AlreadyShared` once Drive lists the permission, and any create
      it would send instead is refused unsent.
      **Live, 2026-11-20:** Listed at the first check, 2,177 ms after the
      create's reply, including the exchanges before the list. One fast
      sample does not bound how slow propagation can be.
- [x] Drive's reply to the create echoes the request as the adapter requires.
      **Automated**: `share` → the `drive_permission_create` exchange's shape
      `echo_type_group`, `echo_role_reader` and `echo_address_exact` (or
      `_case_only`, `_other`, `_absent`).
      **Live, 2026-11-20:** Exact: `echo_type_group`, `echo_role_reader`,
      `echo_address_exact`.

## Status

`group`, `group_member`, `calendar`, `calendar_events`, `calendar_event`,
`event_conferences` and `share_artifact` are implemented. Addresses are
exact lowercase ASCII and are never normalised on the way in, so an application
lowercases what it stores. The operator qualification
(`google-workspace-qualify`) has run once, on 2026-11-20 (UTC), against a
real organization, from platform commit `cfa04a9c` with `recipe_sources`
`sha256:096b91f1123d910b99c60ede5f845e90886322c4036a367370ba4499a78b2e7c`.
Its receipt was reviewed: one share was created and nothing was fenced. Two
probes contradicted the simulation: Google accepted another query's page
token and answered an empty page, and a free/busy calendar answered `403`
then `200` rather than `404`. Both are fixed: the adapter binds each events
page token to its query and identity, and the simulation answers a free/busy
calendar as Google did and models its empty page for another window's token.
The items ticked in [Qualify live (step 6)](#qualify-live-step-6) are
settled; the provider is not yet qualified.

A Directory action reserves three or four calls: metadata, IAM, then one call
per question. A Calendar action reserves the three delegated authentication
exchanges (metadata, `signJwt`, the token exchange), the reader's rule, and
then one more call: five in all. `calendar` instead reserves the calendar and
every ACL page up to the ceiling, nine in all. `event_conferences` reserves
both delegations (six exchanges), the reader's rule and the event, two pages
of records, and three artifact lists for each of the five records the ceiling
admits: twenty-five in all, so its grant's `max_calls_per_invocation` must be
at least 25. `share_artifact` reserves nineteen (see Bounds), on a budget of
its own with `concurrency` 1 (see
[Retries and unknown outcomes](#retries-and-unknown-outcomes)).
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
bases follow Google's published response shapes until a reviewed
qualification receipt settles the real ones (`crates/day2/fixtures/provider-responses/GOOGLE-WORKSPACE-PROVENANCE.md`).

## Delivery

1. `google_auth` extracted from `WorkspaceDirectory`; the connection, target,
   registry entry, port, world and the two Directory reads. (Done.)
2. The three Calendar reads, by delegation as `calendar_reader` and bounded by
   its own `writer` or `owner` rule. (Done.)
3. `event_conferences`, with `email_domain` on the target and impersonation of
   the event's derived owner. (Done.)
4. `share_artifact`, reconciled by listing before it creates, with the
   saboteurs. (Done.)
5. Live qualification: the `google-workspace-qualify` session, its profile,
   receipt and fixture checklist. (Done.)
6. A live run against an instance's fixtures, and review of its receipt.
   (First run reviewed 2026-11-20; its follow-ups, page-token binding and the
   simulation's free/busy and token answers, are done.)
