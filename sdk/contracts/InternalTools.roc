import Observe
import Resource
import Context

# The internal-tools control plane's app library. The activated resource fixes
# the control plane and the domain tools launch under; the app selects nothing.
InternalTools :: [].{
	# Only what launching needs: never owners, repository or custom fields.
	# `url` is `https://<subdomain>.<app domain>/`.
	App : { app_id : Str, name : Str, url : Str }

	# Every registered tool with a subdomain, at most 1,000, sorted by name
	# (case-insensitive) then `app_id`, one entry per `app_id`. A larger library
	# fails; it is never truncated. Each call is a provider read: nothing is
	# cached, so call it when a person asks, not on every page load.
	Library : { apps : List(App), captured_at : I64 }

	app_library : Context -> Observe(Library)
	app_library = |context| Resource.bind(context, "internal_tools").and_then(app_library_with)

	app_library_with : Resource -> Observe(Library)
	app_library_with = |resource| Observe.capability(
		"internal_tools.app_library.v1",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(Library, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_internal_tools_library"))
		},
	)
}
