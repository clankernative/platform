import Capability

## `day2 ci fetch`: the first step of an app's org-scoped CI run. The CLI hands over a request naming a new directory;
## the host reads the Gitea Actions environment, the event and the job token, and refuses any step out of order. This
## recipe owns the order: the repository the token reads must be the event's, then the event's commits (a pull
## request's current head and merge base, or a push to main without a base), then each tree, then the run's record.
CiFetch :: [].{

	## What the event selects: a pull request has a base tree to route against; a push has none.
	Plan : { base : Bool }

	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| {
		_ = Capability.call!("ci-fetch-prepare", Json.to_str({ request: request }), host!)?
		_ = step!("repository", host!)?
		plan : Plan
		plan = Json.parse(step!("event", host!)?).map_err(|_| "invalid CI fetch plan")?
		_ = step!("head", host!)?
		if plan.base {
			_ = step!("base", host!)?
		}
		step!("result", host!)
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("ci-fetch-step", Json.to_str({ name: name }), host!)
