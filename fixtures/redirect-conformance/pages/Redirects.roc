import pf.Redirect
import Commands
import Errors
import VisitLinkTypes
import Routes

# The GoLinks shape: `go/<name>` and bare `/<name>` both resolve through the visit
# command, including multi-segment wildcard paths such as `docs/<page>`. The
# longest literal prefix wins, so `/go/x` visits `x` and a bare `/go` visits `go`.
Redirects :: [].{
	prefixed : Redirect(VisitLinkTypes.Input)
	prefixed = Redirect.route(
		{ path: "/go/{path..}", location: "url", schemes: AnyScheme, not_found: [Errors.missing_link] },
		Commands.visit,
	).on_not_found(Routes.missing_link)

	bare : Redirect(VisitLinkTypes.Input)
	bare = Redirect.route(
		{ path: "/{path..}", location: "url", schemes: AnyScheme, not_found: [Errors.missing_link] },
		Commands.visit,
	)
}
