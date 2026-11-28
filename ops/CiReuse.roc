import Capability

## `day2 ci reuse`: the second step of an app's org-scoped CI run, after fetch and before check. The CLI hands over a
## request naming the run's directory and the instance's case count; the host reads the run's record, the job token and
## the store inputs, refuses any step out of order, and fails the command on misconfiguration. A pull request run never
## reuses. For main's push run this recipe owns the order: the forge's record of this run (it names the CI repository),
## git-oidc's token, Google STS's read-only token and the key's listing; then each stored attempt, newest first, through
## its custody steps until one is accepted; then the result, which writes what check reads. Every step that misses ends
## the lookup, and the result always runs, so a miss never fails the run.
CiReuse :: [].{

	## Whether this is a push run, which looks under its key.
	Plan : { lookup : Bool }

	## A lookup step's outcome: whether the lookup ended with nothing reused.
	Reply : { missed : Bool }

	## The stored attempts under the key that will be tried, newest first.
	Listed : { missed : Bool, candidates : List({ run : U64, attempt : U64 }) }

	## One custody step of a stored attempt: whether it refused that attempt, and whether the lookup ended.
	Custody : { missed : Bool, refused : Bool }

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
			examined = examine!(host!)?
			# A refused attempt gives way to the next; an accepted one, or a miss, ends the lookup.
			if examined.missed or !examined.refused {
				return Ok({})
			}
		}
		Ok({})
	}

	## One stored attempt, in the deploy reader's custody order: the forge's record of its run, the forge's archive of
	## that run's commit (whose app/ source inputs must be this run's), its receipt, its artifact and the artifact's
	## bytes, then its run again. The first step that refuses the attempt, or ends the lookup, stops it; an attempt
	## through every step is accepted.
	examine! : (Str => Try(Str, Str)) => Try(Custody, Str)
	examine! = |host!| {
		for name in ["candidate", "source", "receipt", "artifact", "download", "attempt"] {
			custody : Custody
			custody = Json.parse(step!(name, host!)?).map_err(|_| "invalid CI reuse custody step")?
			if custody.missed or custody.refused {
				return Ok(custody)
			}
		}
		Ok({ missed: Bool.False, refused: Bool.False })
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("ci-reuse-step", Json.to_str({ name: name }), host!)
