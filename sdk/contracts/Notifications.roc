import Observe
import Effects
import Api
import Resource
import Context

# An admitted capability pack. The instance host owns its adapter, credentials,
# protocol, idempotency and simulator. Application code receives typed values.
Notifications :: [].{
	send_effect = Api.external("notifications.send.v1")

	Recipient :: { actor : Str, resource : Resource }

	Receipt : { id : Str, status : Str }

	Delivery : { id : Str, status : Str, count : U64 }

	resolve : Context -> Observe(Recipient)
	resolve =
		|context| Resource.bind(context, "notifications").and_then(|resource| resolve_with(resource, context.actor()))

	resolve_with : Resource, Str -> Observe(Recipient)
	resolve_with = |resource, actor| Observe.capability(
		"notifications.recipient.v1",
		Json.to_str({
			actor: actor,
			handle: Resource.token(resource),
		}),
	)
		.and_then(
			|raw| {
				parsed : Try({ actor : Str }, _)
				parsed = Json.parse(raw)
				Observe.from_host(parsed.map_err(|_| "invalid_notification_recipient"))
					.map(|value| { actor: value.actor, resource })
			},
		)

	latest : Context, Str -> Observe(Delivery)
	latest = |context, topic| Resource.bind(context, "notifications").and_then(|resource| latest_with(resource, topic))

	latest_with : Resource, Str -> Observe(Delivery)
	latest_with = |resource, topic| Observe.capability(
		"notifications.latest.v1",
		Json.to_str({
			topic: topic,
			handle: Resource.token(resource),
		}),
	)
		.and_then(
			|raw| {
				parsed : Try(Delivery, _)
				parsed = Json.parse(raw)
				Observe.from_host(parsed.map_err(|_| "invalid_notification_delivery"))
			},
		)

	send : Recipient, Str, Str -> Effects(Receipt)
	send =
		|
			recipient,
			topic,
			body,
		|
			Effects.capability(
				"notifications.send.v1",
				Json.to_str({ actor: recipient.actor, handle: Resource.token(recipient.resource), topic, body }),
			)
				.and_then(
					|raw| {
						parsed : Try(Receipt, _)
						parsed = Json.parse(raw)
						Effects.from_host(parsed.map_err(|_| "invalid_notification_receipt"))
					},
				)
}
