import Capability

## `day2 instance plan`: read-only OpenTofu plans of an instance's core roots. The CLI renders each root's
## backend and variables from day2.json into a request file. This recipe owns the order: validate and stage the
## request, read the cluster and DNS credentials once, then init, plan and show each root in apply order, then
## the receipt. A root that fails, including one whose credentials could not be read, is recorded and the rest
## still plan, so one broken root never hides another's plan. It never applies and never takes a state lock.
InstancePlan :: [].{
	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| {
		raw = Capability.call!("instance-plan-prepare", Json.to_str({ request: request }), host!)?
		prepared : { roots : List(Str) }
		prepared = Json.parse(raw).map_err(|_| "invalid instance plan preparation")?
		_ = Capability.call!("instance-plan-credentials", "{}", host!)?
		for label in prepared.roots {
			plan_root!(label, ["init", "plan", "show"], host!)?
		}
		Capability.call!("instance-plan-receipt", "{}", host!)
	}
}

## Run a root's operations in order and stop that root at its first failure.
plan_root! : Str, List(Str), (Str => Try(Str, Str)) => Try({}, Str)
plan_root! = |label, operations, host!| match operations {
	[] => Ok({})
	[operation, .. as rest] => {
		raw = Capability.call!("instance-plan-root", Json.to_str({ label, operation }), host!)?
		step : { ok : Bool }
		step = Json.parse(raw).map_err(|_| "invalid instance plan step")?
		if step.ok plan_root!(label, rest, host!) else Ok({})
	}
}
