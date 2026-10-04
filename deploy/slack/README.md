# Day2 notification bot

Create an app in the intended workspace from `day2-bot-manifest.json`, install it
using Slack's OAuth & Permissions **Install to Workspace** button, and invite Day2
to the reviewed channel. The manifest requests only the bot `chat:write` scope;
there are no user scopes, events, webhooks, interactivity or custom OAuth callbacks.
Token rotation is off because this adapter consumes an exact versioned bot token,
not an OAuth refresh-token exchange. Rotate by explicitly provisioning a new token
and numbered credential/Secret Manager version before withdrawing the old one.

For the Wonderly qualification, the user selected
`#alerts-internal-tools-platform`, channel `C0BQV4YPM0F` in workspace `TK903Q3JN`.
Those identifiers were read from Slack; app installation, bot membership and a
successful live provider call need their own evidence.

Register the private token through the existing provider credential provisioning:
`day2-app.provider_credentials` names its exact Secret Manager version and reviewed
fingerprint, and `app-edge.runtime_secret_ids` grants that runtime identity access.
The normal credential init containers copy and register the mounted token before
the app starts. Never add token bytes to the manifest, catalog, Terraform values,
artifact, public receipts or version control.

The Notifications `notification_channel` slot needs one `slack_channel` resource,
a `slack` live connection with that exact workspace and credential revision, only
`slack_post`, and at least two provider calls per invocation: `auth.test` plus one
post. Attach the reviewed channel grant to `notifications.set_enabled` and
`notifications.publish`; both need `slack.post.v1` in operation authority for the
channel binding to survive the authority ceiling. The enablement artifact declares
only local writes, so binding cannot post a message; only publication declares
the external effect. Other operations do not need the posting grant. These resources are
operator-owned; source builds never auto-grant a real workspace.

Slack's [setup guide](https://docs.slack.dev/app-management/quickstart-app-settings/)
describes scope selection, installation and inviting the bot. Its
[manifest reference](https://docs.slack.dev/reference/app-manifest/) defines the
checked JSON settings.
