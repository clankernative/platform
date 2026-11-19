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

These establish field names and types only. The live qualification recipe
replaces them with redacted recordings.
