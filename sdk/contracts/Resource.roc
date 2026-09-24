import Observe
import Context

# An opaque, host-issued reference. Every use is checked against the invocation,
# actor, operation, resource, actions and activated authority which issued it.
Resource :: { token : Str }.{
	Limits : { max_request_bytes : U64, max_response_bytes : U64, max_calls_per_invocation : U64 }

	bind : Context, Str -> Observe(Resource)
	bind = |context, binding| Observe.capability(
		"resources.bind.v1",
		Json.to_str({
			binding,
			invocation: Context.invocation_id(context),
		}),
	)
		.and_then(decode)

	# Attenuation preserves budget ownership and may only remove actions.
	restrict_actions : Resource, List(Str) -> Observe(Resource)
	restrict_actions = |resource, actions| Observe.capability(
		"resources.attenuate.v1",
		Json.to_str({ handle: resource.token, actions }),
	).and_then(decode)

	only_topics : Resource, List(Str) -> Observe(Resource)
	only_topics = |resource, topics| Observe.capability(
		"resources.attenuate.v1",
		Json.to_str({ handle: resource.token, topics: { kind: "only", topics } }),
	).and_then(decode)

	restrict_limits : Resource, Limits -> Observe(Resource)
	restrict_limits = |resource, limits| Observe.capability(
		"resources.attenuate.v1",
		Json.to_str({ handle: resource.token, limits }),
	).and_then(decode)

	# Absolute Unix milliseconds on the host clock; an existing expiry can only shorten.
	expires_at : Resource, I64 -> Observe(Resource)
	expires_at = |resource, expires_at_ms| Observe.capability(
		"resources.attenuate.v1",
		Json.to_str({ handle: resource.token, expires_at_ms }),
	).and_then(decode)

	decode : Str -> Observe(Resource)
	decode = |raw| {
		parsed : Try({ token : Str }, _)
		parsed = Json.parse(raw)
		Observe.from_host(parsed.map_err(|_| "invalid_resource_handle")).map(|value| { token: value.token })
	}

	# Private transport access; the two admission profiles hide this from apps.
	token : Resource -> Str
	token = |resource| resource.token
}
