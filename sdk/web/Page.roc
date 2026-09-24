import Read
import PageBinding
import Template

# Bind an explicit route to generated read/template handles; the app owns its HTML.
Page(a) :: { binding : PageBinding, complete : a -> PageBinding }.{
	Config : PageBinding.Config

	define : Config, Read(a, b) -> Page(a)
	define = |config, read| {
		binding: PageBinding.from_read(config, read),
		complete: |input| PageBinding.from_read_with_defaults(config, read, input),
	}

	# The App.definition.pages record supplies the registered identity.
	route : { title : Str, path : Str, template : Template }, Read(a, b) -> Page(a)
	route = |config, read| define({ name: "", title: config.title, path: config.path, template: config.template }, read)

	# Complete defaults are checked by the read's input type and generated codec.
	with_defaults : Page(a), a -> Page(a)
	with_defaults = |page, input| {
		..page,
		binding: PageBinding.with_defaults_from(page.binding, (page.complete)(input)),
	}

	# Partial defaults are checked at artifact admission. Path fields cannot default;
	# use explicit integer types for numeric literals to avoid accidental decimals.
	with_query_defaults : Page(a), _ -> Page(a)
	with_query_defaults = |page, defaults| { ..page, binding: PageBinding.with_query_defaults(page.binding, defaults) }

	# Subscribe to database changes through the platform's Datastar SSE transport.
	live : Page(a) -> Page(a)
	live = |page| { ..page, binding: PageBinding.live(page.binding) }

	# Also refresh reads whose external or time-dependent results can change without
	# a database write. Admission bounds the server interval to 1–60 seconds.
	live_refresh_every : Page(a), U64 -> Page(a)
	live_refresh_every = |page, milliseconds| {
		..page,
		binding: PageBinding.live_refresh_every(page.binding, milliseconds),
	}

	register : Page(a) -> PageBinding
	register = |page| page.binding
}
