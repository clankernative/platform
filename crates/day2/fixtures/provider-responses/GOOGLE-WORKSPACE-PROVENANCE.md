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
- `google_workspace.calendars.get.json`: Calendar `calendars.get` with the
  adapter's `fields=id,summary` mask,
  https://developers.google.com/workspace/calendar/api/v3/reference/calendars/get
- `google_workspace.calendar.acl.list.json`: Calendar `acl.list` with the
  `items(scope(type,value),role),nextPageToken` mask, including the `default`
  scope, which carries no value,
  https://developers.google.com/workspace/calendar/api/v3/reference/acl/list
- `google_workspace.calendar.events.list.json`: Calendar `events.list` with
  `singleEvents=true` and the adapter's item mask: a timed event with
  `conferenceData`, a private recurring instance with `originalStartTime` whose
  organizer is a group calendar, a cancelled instance reported with only `id`,
  `status` and `originalStartTime` (the fields Google guarantees for cancelled
  exceptions), and an all-day event,
  https://developers.google.com/workspace/calendar/api/v3/reference/events/list
  and https://developers.google.com/workspace/calendar/api/v3/reference/events
- `google_workspace.calendar.events.get.json`: Calendar `events.get` with the
  same item mask,
  https://developers.google.com/workspace/calendar/api/v3/reference/events/get

These establish field names and types only. The live qualification recipe
replaces them with redacted recordings.
