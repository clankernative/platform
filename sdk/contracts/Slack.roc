import Observe
import Effects
import Api
import Resource

# The activated resource fixes the workspace and channel. Apps cannot select
# another recipient, identity, attachment, URL, or provider method.
Slack :: [].{
	post_effect = Api.external("slack.post.v1")

	Message : { timestamp : Str, text : Str }

	History : { channel : Str, messages : List(Message), has_more : Bool }

	Receipt : { channel : Str, timestamp : Str, status : Str }

	read : Resource, U64 -> Observe(History)
	read = |resource, limit| Observe.capability(
		"slack.read.v1",
		Json.to_str({ handle: Resource.token(resource), limit }),
	).and_then(
		|raw| {
			parsed : Try(History, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_slack_history"))
		},
	)

	post : Resource, Str -> Effects(Receipt)
	post = |resource, text| Effects.capability(
		"slack.post.v1",
		Json.to_str({ handle: Resource.token(resource), text }),
	).and_then(
		|raw| {
			parsed : Try(Receipt, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_slack_receipt"))
		},
	)
}
