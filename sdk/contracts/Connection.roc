import Observe

# Availability is a preparation observation. The host binds the effective
# principal and rechecks authority and connection generation at each use.
Connection :: [].{
	Problem : [
		NeedsConnection,
		ReauthRequired,
		AccountApprovalRequired,
		PermissionDenied,
		BindingUnavailable,
		ProviderUnavailable,
		CapacityDeferred,
	]

	Resolution(a) : [Available(a), Unavailable(Problem)]

	resolve : Str -> Observe(Resolution(Str))
	resolve = |registration| Observe.capability(
		"connection.resolve.v1",
		Json.to_str({ registration: registration }),
	).and_then(
		|raw| {
			parsed : Try(Resolution(Str), _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_connection_resolution"))
		},
	)
}
