import Write
import Failure
import RedirectBinding

# A GET route that runs one existing command and redirects to a URL the command
# returned. The mirror of Page for commands: a page renders a query's result; a
# redirect route answers `302 Found` with one field of a command's result.
#
# The path is a literal prefix followed by one rest parameter that captures the
# remaining segments, such as "/go/{path..}" or "/{path..}". The rest parameter
# names the command's only input field, which receives the decoded segments
# joined by "/". The query string is never passed to the command, and nothing
# from the request reaches `Location` except through the command's result.
#
# Page routes and the platform's own paths always take precedence; a redirect
# route answers only the paths nothing else claims. Between redirect routes, the
# longest literal prefix wins.
# Templates link with `routes.go(path=value)` using logical decoded text; the
# helper encodes each slash-separated segment once, as page route helpers do.
#
#     go : Redirect(VisitTypes.Input)
#     go = Redirect.route(
#         { path: "/{path..}", location: "url", schemes: AnyScheme, not_found: [Errors.missing] },
#         Commands.visit,
#     )
Redirect(a) :: { binding : RedirectBinding }.{
	# Which destinations the host will send a browser to. The platform always
	# refuses javascript:, vbscript:, data:, blob:, file: and filesystem: destinations,
	# whichever is chosen here.
	Schemes : [
		# http and https only.
		Web,
		# Any absolute URI, so a link can open an application such as slack:// or
		# zoommtg:, as go links historically could.
		AnyScheme,
	]

	route : { path : Str, location : Str, schemes : Schemes, not_found : List(Failure) }, Write(a, b) -> Redirect(a)
	route = |config, command| {
		operation = command.metadata()
		{
			binding: RedirectBinding.define({
				# The App.definition.redirects record supplies the registered name,
				# exactly as it supplies a page's and a schedule's.
				name: "",
				path: config.path,
				operation: operation.name,
				input_type: operation.input_type,
				output_type: operation.output_type,
				location: config.location,
				schemes: match config.schemes {
					Web => "web"
					AnyScheme => "any"
				},
				not_found: config.not_found.map(Failure.code),
			}),
		}
	}

	register : Redirect(a) -> RedirectBinding
	register = |redirect| redirect.binding
}
