# Slack dashboard pilot

Owners can edit a single HTML file and share a pinned preview with employees who have access to the app. Each viewer reads Slack through the ordinary `slackdashboard.history` query under their own Day2 session. The query takes no input and reads at most 20 messages from the channel selected by the operator's `dashboard_channel` resource binding.

Start the disposable example from the platform checkout.

```console
./cli/day2 platform local-dev examples/slack-dashboard
```

Open the printed login URL. Local development uses synthetic Slack messages. To use an installed copy with live Slack, its operator must activate the exact channel resource, reviewed Slack connection and `slack.read.v1` grant for the intended viewers.

## Edit and share

1. Sign in as an app owner and open `/_prototype/published`. Edit the starter HTML in its editor and choose **Save & preview**. This appends a new revision. It does not rebuild the Roc app.
2. Share the resulting `/_prototype/revisions/<id>` URL. Each viewer gets the pinned HTML and a fresh Slack read under their own session. Saving another edit from this page produces a new link.
3. Inside the HTML, `await day2.call("history")` returns the assigned channel, `messages.items` and `has_more`. Each message has a `timestamp` and `text`.

For an editor or agent outside the browser, copy the [starter HTML](prototype/index.html) outside the watched app source before editing. As an owner, save the edited file with the normal API. This example uses a signed-in Day2 CLI pointed at the installed app.

```console
cp prototype/index.html /tmp/dashboard.html
# Edit /tmp/dashboard.html, then submit its contents.
jq -Rs '{html: .}' /tmp/dashboard.html > /tmp/dashboard-revision.json
day2 call slackdashboard.save_revision --input-file /tmp/dashboard-revision.json --idempotency-key dashboard_edit_001
```

The result contains the numeric `id` for the preview URL. The `html` field accepts nonblank, NUL-free HTML up to 16,384 UTF-8 bytes. Use a new idempotency key for each intentional save, and reuse the same key when retrying that exact request. To recover a saved revision, call `slackdashboard.revision` with its numeric `id`.

## Publish a revision

As an owner, open the pinned preview and use its source download link. The link includes the pin for the reviewed revision and app artifact. Submit the downloaded app source through ordinary Day2 source review, app CI, access policy activation and deployment. The exported app uses the separate ID `channelhistory` and registers the single query `channelhistory.history`. Its own operator-approved channel grant is required. After deployment its packaged dashboard is available at `/_prototype/published`.
