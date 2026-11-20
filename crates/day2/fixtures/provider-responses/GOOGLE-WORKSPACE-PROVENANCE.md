# Google Workspace wire fixtures

No live response has been recorded yet. Each body follows the response shape in
Google's published reference, with illustrative values; none is produced by the
adapter or its simulation.

- `google_workspace.metadata_token.json`: the Compute metadata server's
  service-account token response,
  https://cloud.google.com/compute/docs/access/authenticate-workloads
- `google_workspace.generate_access_token.json`: IAM Credentials
  `projects.serviceAccounts.generateAccessToken`,
  https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
- `google_workspace.groups.get.json`: Admin SDK Directory `groups.get` with the
  adapter's fixed `fields=id,email,name` mask, which returns exactly those
  members of the `Group` resource,
  https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/get
- `google_workspace.groups.has_member.json`: Admin SDK Directory
  `members.hasMember`,
  https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/hasMember

- `google_workspace.sign_jwt.json`: IAM Credentials
  `projects.serviceAccounts.signJwt` (`keyId`, `signedJwt`). Tests replace the
  JWT with one carrying the plan's claims, since its claims are what the
  adapter checks.
  https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt
- `google_workspace.oauth_token.json`: the JWT-bearer grant at Google's token
  endpoint,
  https://developers.google.com/identity/protocols/oauth2/service-account#httprest
- `google_workspace.calendar.acl.get.json`: Calendar `acl.get` for the rule ID
  `user:{email}` with the adapter's `fields=scope(type,value),role` mask, the
  reader's own rule every Calendar action reads first,
  https://developers.google.com/workspace/calendar/api/v3/reference/acl/get
- `google_workspace.calendar.error.rate_limit.json` and
  `google_workspace.calendar.error.forbidden.json`: Google's error envelope for
  a `403`, with `errors[].reason`. The rate limit follows the Calendar errors
  guide's `rateLimitExceeded` example. The refusal's `forbidden` reason is
  illustrative: the reason Google gives a reader without access is a live
  qualification item,
  https://developers.google.com/workspace/calendar/api/guides/errors
- `google_workspace.calendars.get.json`: Calendar `calendars.get` with the
  adapter's `fields=id,summary` mask,
  https://developers.google.com/workspace/calendar/api/v3/reference/calendars/get
- `google_workspace.calendar.acl.list.json`: Calendar `acl.list` with the
  `items(scope(type,value),role),nextPageToken` mask, including the `default`
  scope, which carries no value,
  https://developers.google.com/workspace/calendar/api/v3/reference/acl/list
- `google_workspace.calendar.events.list.json`: Calendar `events.list` with
  `singleEvents=true` and the adapter's item mask: a timed event with
  `conferenceData` and its `conferenceSolution.key.type`, a private recurring instance with `originalStartTime` whose
  organizer is a group calendar, a cancelled instance reported with only `id`,
  `status` and `originalStartTime` (the fields Google guarantees for cancelled
  exceptions), and an all-day event,
  https://developers.google.com/workspace/calendar/api/v3/reference/events/list
  and https://developers.google.com/workspace/calendar/api/v3/reference/events
- `google_workspace.calendar.events.get.json`: Calendar `events.get` with the
  same item mask,
  https://developers.google.com/workspace/calendar/api/v3/reference/events/get

- `google_workspace.meet.conference_records.list.json`: Meet
  `conferenceRecords.list` with the adapter's
  `conferenceRecords(name,space,startTime,endTime),nextPageToken` mask: a
  rejoin still in progress (no `endTime`) and the first call, latest start
  first as the reference orders them, both in one space. Timestamps follow
  protobuf's JSON mapping (`Z`, 0, 3, 6 or 9 fractional digits). The
  `ConferenceRecord` resource: "`name` … Format:
  `conferenceRecords/{conferenceRecord}`", "`endTime` … Unset if the conference
  is ongoing", "`space` … The space where the conference was held",
  https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords/list
  and https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords
- `google_workspace.meet.recordings.list.json`: `recordings.list` with
  `recordings(name,state,driveDestination(file)),nextPageToken`: a generated
  recording with its Drive file and an ended one without. The reference names
  the states `STARTED`, `ENDED` and `FILE_GENERATED` ("Recording file is
  generated and ready to download") and describes `driveDestination.file` as
  "The `fileId` for the underlying MP4 file"; it does not say the file is set
  only once generated, so the adapter keeps it optional. The file ID is the
  reference's own example,
  https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.recordings
- `google_workspace.meet.smart_notes.list.json` and
  `google_workspace.meet.transcripts.list.json`: `smartNotes.list` and
  `transcripts.list` with `{smartNotes|transcripts}(name,state,docsDestination(document)),nextPageToken`.
  `DocsDestination.document` is "The document ID for the underlying Google
  Docs transcript file",
  https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.smartNotes/list,
  https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.transcripts/list
  and https://developers.google.com/workspace/meet/api/reference/rest/v2/DocsDestination
- `google_workspace.meet.error.permission_denied.json` and
  `google_workspace.meet.error.rate_limit.json`: the error envelope Google's
  newer APIs send, a `status` name and, for a rate limit, an `ErrorInfo`
  detail with its `reason`. The message and metadata are illustrative,
  https://cloud.google.com/apis/design/errors

- `google_workspace.meet.recordings.get.json`: Meet `recordings.get` with the
  adapter's `name,state,driveDestination(file)` mask: one generated
  recording, named exactly,
  https://developers.google.com/workspace/meet/api/reference/rest/v2/conferenceRecords.recordings/get
- `google_workspace.drive.permissions.list.json`: Drive v3 `permissions.list`
  with `permissions(id,type,role,emailAddress,deleted),nextPageToken`: the
  owner, another group as commenter, and an `anyone` grant, which carries no
  address. The reference allows at most 100 per page,
  https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/list
- `google_workspace.drive.permissions.create.json`: Drive v3
  `permissions.create` with `id,type,role,emailAddress`: "the response body
  contains a newly created instance of" a Permission. The reference says
  nothing about creating a permission that already exists; that is a live
  qualification item,
  https://developers.google.com/workspace/drive/api/reference/rest/v3/permissions/create
- `google_workspace.drive.error.insufficient_permissions.json` and
  `google_workspace.drive.error.invalid_sharing.json`: Drive's documented
  `403 insufficientFilePermissions` and `400 invalidSharingRequest` ("the ACL
  change isn't allowed") in the `errors[]` envelope. Messages are
  illustrative,
  https://developers.google.com/workspace/drive/api/guides/handle-errors

These establish field names and types only. The live qualification recipe
replaces them with redacted recordings.
