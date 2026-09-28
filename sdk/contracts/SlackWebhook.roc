import Effects
import Api
import Resource

# The operator pins one incoming-webhook destination. Apps supply plain text only.
SlackWebhook :: [].{
	post_effect = Api.external("slack_webhook.post.v1")

	Receipt : { status : Str }

	post : Resource, Str -> Effects(Receipt)
	post = |resource, text| Effects.capability(
		"slack_webhook.post.v1",
		Json.to_str({ handle: Resource.token(resource), text }),
	).and_then(
		|raw| {
			parsed : Try(Receipt, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_slack_webhook_receipt"))
		},
	)
}
