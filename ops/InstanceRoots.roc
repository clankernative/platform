import Capability

## `day2 instance plan` and `day2 instance apply`: OpenTofu runs of an instance's core roots. The CLI renders each
## root's backend and variables from day2.json into a request file, and the host action fixes the mode. This recipe
## owns the order: validate and stage the request, read the cluster and DNS credentials once, run each root in apply
## order, then the receipt.
InstanceRoots :: [].{

	## Read-only: init, plan and show every root. A root that fails, including one whose credentials could not be
	## read, is recorded and the rest still plan, so one broken root never hides another's plan. It never applies
	## and never takes a state lock.
	plan! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	plan! = |request, host!| {
		for root in prepare!(request, host!)? {
			_ = run_root!(root.label, ["init", "plan", "show"], host!)?
		}
		Capability.call!("instance-roots-receipt", "{}", host!)
	}

	## Init, plan with the state lock, show, then apply exactly that saved plan, root by root. The host refuses a
	## plan that deletes, replaces or forgets a resource. A failed shared root (project, cluster, tenancy) stops the
	## apply, since every later root reads its state; a failed app edge stops only itself.
	apply! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	apply! = |request, host!| {
		apply_roots!(prepare!(request, host!)?, host!)?
		Capability.call!("instance-roots-receipt", "{}", host!)
	}
}

Prepared : { label : Str, shared : Bool }

prepare! : Str, (Str => Try(Str, Str)) => Try(List(Prepared), Str)
prepare! = |request, host!| {
	raw = Capability.call!("instance-roots-prepare", Json.to_str({ request: request }), host!)?
	prepared : { roots : List(Prepared) }
	prepared = Json.parse(raw).map_err(|_| "invalid instance preparation")?
	_ = Capability.call!("instance-roots-credentials", "{}", host!)?
	Ok(prepared.roots)
}

apply_roots! : List(Prepared), (Str => Try(Str, Str)) => Try({}, Str)
apply_roots! = |roots, host!| match roots {
	[] => Ok({})
	[root, .. as rest] => {
		applied = run_root!(root.label, ["init", "plan", "show", "apply"], host!)?
		if applied or !root.shared apply_roots!(rest, host!) else Ok({})
	}
}

## Run a root's operations in order, stop that root at its first failure, and say whether every one succeeded.
run_root! : Str, List(Str), (Str => Try(Str, Str)) => Try(Bool, Str)
run_root! = |label, operations, host!| match operations {
	[] => Ok(Bool.True)
	[operation, .. as rest] => {
		raw = Capability.call!("instance-roots-operation", Json.to_str({ label, operation }), host!)?
		step : { ok : Bool }
		step = Json.parse(raw).map_err(|_| "invalid instance root step")?
		if step.ok run_root!(label, rest, host!) else Ok(Bool.False)
	}
}
