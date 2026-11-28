import Capability

## `day2 ci reuse`: the second step of an app's org-scoped CI run, after fetch and before check. The CLI hands over a
## request naming the run's directory and the instance's case count; the host reads the run's record, the job token and
## the store inputs, and refuses any step out of order. A pull request run never reuses. For main's push run this recipe
## owns the order: the forge's record of this run (it names the CI repository), git-oidc's token, Google STS's read-only
## token, the key's listing, then each stored attempt newest first until one passes the deploy reader's custody checks,
## then the result, which writes what check reads. Every lookup step that misses ends the lookup; the result always runs,
## so a miss never fails the run.
CiReuse :: [].{

	## Whether a push run's inputs were read, so there is a key to look under.
	Plan : { lookup : Bool }

	## A lookup step's outcome: whether the lookup ended with nothing reused.
	Reply : { missed : Bool }

	## The stored attempts under the key that will be tried, newest first.
	Listed : { missed : Bool, candidates : List({ run : U64, attempt : U64 }) }

	## One stored attempt's outcome.
	Tried : { missed : Bool, accepted : Bool }

	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| {
		plan : Plan
		plan =
			Json.parse(Capability.call!("ci-reuse-prepare", Json.to_str({ request: request }), host!)?)
				.map_err(|_| "invalid CI reuse plan")?
		if plan.lookup {
			_ = lookup!(host!)?
		}
		step!("result", host!)
	}

	## The lookup's steps, until one ends it.
	lookup! : (Str => Try(Str, Str)) => Try({}, Str)
	lookup! = |host!| {
		for name in ["run", "mint", "exchange"] {
			reply : Reply
			reply = Json.parse(step!(name, host!)?).map_err(|_| "invalid CI reuse step")?
			if reply.missed {
				return Ok({})
			}
		}
		listed : Listed
		listed = Json.parse(step!("list", host!)?).map_err(|_| "invalid CI reuse listing")?
		if listed.missed {
			return Ok({})
		}
		for _candidate in listed.candidates {
			tried : Tried
			tried = Json.parse(step!("candidate", host!)?).map_err(|_| "invalid CI reuse candidate")?
			if tried.missed or tried.accepted {
				return Ok({})
			}
		}
		Ok({})
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("ci-reuse-step", Json.to_str({ name: name }), host!)
