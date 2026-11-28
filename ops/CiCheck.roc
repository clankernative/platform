import Capability
import Check
import ChromeExtension

## `day2 ci check`: an app repository's CI over local source trees. The CLI hands over a request naming the head tree,
## an optional base tree, the instance's case count, a new output directory and, for a push run, `ci reuse`'s directory;
## the host action fixes the mode. This recipe owns the order. The host validates the request first (and verifies a
## reused result again before any step), refuses a step out of order or outside its lane, and owns the fixed seed, the
## routing rules and the receipt.
CiCheck :: [].{

	## The lanes the change selects, from the platform's own rules: a captured build input or any Roc source selects
	## native, extension sources select extension, JavaScript selects javascript; no base tree selects all three.
	## `reused` says the host verified an earlier main run's result for this push run, which replaces the build.
	Route : { root : Str, seed : U64, cases : U64, native : Bool, extension : Bool, javascript : Bool, reused : Bool }

	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| {
		_ = Capability.call!("ci-check-prepare", Json.to_str({ request: request }), host!)?
		route : Route
		route = Json.parse(step!("route", host!)?).map_err(|_| "invalid CI route")?
		if route.javascript {
			_ = step!("javascript", host!)?
		}
		if route.native {
			_ = step!("format", host!)?
			if route.reused {
				# The build's own extension check; the reused result stands for the build and its campaign.
				_ = ChromeExtension.verify!(route.root, host!)?
			} else {
				# The extension check, then the build with the instance's campaign as its required verification; its
				# tested recipe also runs the top-level expects of every captured app module, imported or not, before
				# linking.
				_ = Check.tested!(route.root, route.seed, route.cases, host!)?
			}
			# The host recorded the build it ran, or the result it verified; write its artifact.
			_ = step!("artifact", host!)?
		}
		# The native lane's check already verified the extension release.
		if route.extension and !route.native {
			_ = ChromeExtension.verify!(route.root, host!)?
		}
		step!("result", host!)
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("ci-check-step", Json.to_str({ name: name }), host!)
