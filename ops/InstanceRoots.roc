import Capability

## `day2 instance plan` and `day2 instance apply`: OpenTofu runs of an instance's core roots, and a deploy's run of one
## app's day2-app root. The CLI renders each root's backend and variables from day2.json into a request file, and the
## host action fixes the mode. This recipe owns the order: validate and stage the request, read the cluster and DNS
## credentials once, run each root in apply order, then the receipt. A day2-app root reads its release first.
InstanceRoots :: [].{

	## Read-only: read each day2-app root's release, then init, plan and show every root. A root that fails, including
	## one whose credentials could not be read, is recorded and the rest still plan, so one broken root never hides
	## another's plan; an app with no release selection is not planned. It never applies and never takes a state lock.
	plan! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	plan! = |request, host!| {
		for root in prepare!(request, host!)? {
			_ = run_root!(root, ["init", "plan", "show"], host!)?
		}
		Capability.call!("instance-roots-receipt", "{}", host!)
	}

	## Init, plan with the state lock, show, then apply exactly that saved plan, root by root. The host refuses a
	## plan that deletes, replaces or forgets a resource. A failed shared root (project, cluster, tenancy) stops the
	## apply, since every later root reads its state; a failed app edge stops only itself and its app's day2-app root,
	## which reads its platform contract; a failed day2-app root stops only itself.
	apply! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	apply! = |request, host!| {
		apply_roots!(prepare!(request, host!)?, [], host!)?
		Capability.call!("instance-roots-receipt", "{}", host!)
	}

	## A deploy's day2-app root, first step: validate and stage the deploy request, read the cluster credentials,
	## check the request's candidate (as `instance candidate check` does, its SDK release and native evidence) and
	## initialize the root. Nothing is planned yet. Err when the root failed; the receipt says how.
	open! : Str, (Str => Try(Str, Str)) => Try(Release, Str)
	open! = |request, host!| {
		label = deployed(prepare!(request, host!)?)?
		released : { ok : Bool, released : Bool, release : Try(Release, [Null]) }
		released = Json.parse(step!(label, "release", host!)?).map_err(|_| "invalid release result")?
		# A refused candidate has no release.
		release = released.release.map_err(|_| "the deploy's candidate was refused; see the roots receipt")?
		if ok(step!(label, "init", host!)?)? {
			Ok(release)
		} else {
			Err("the deploy's root could not initialize; see the roots receipt")
		}
	}

	## The instance.json the root's plan would publish with the candidate: a plan of only the instance ConfigMap,
	## without the state lock, shown and never applied. It is the target of `day2 platform maintain activate`. At most
	## once, after open! and before release!.
	target! : (Str => Try(Str, Str)) => Try(File, Str)
	target! = |host!| {
		label = deployed(summary!(host!)?)?
		rendered : { ok : Bool, instance : Try(File, [Null]) }
		rendered = Json.parse(step!(label, "target", host!)?).map_err(|_| "invalid target result")?
		# A failed render has no file.
		rendered.instance.map_err(|_| "the deploy's target could not be rendered; see the roots receipt")
	}

	## After activation: require the app's selection to name exactly the request's candidate, then plan with the
	## state lock, show, and apply exactly that saved plan; a plan that deletes, replaces or forgets is refused.
	## Bool.True when it applied or had nothing to change, Bool.False when the root failed or was refused.
	release! : (Str => Try(Str, Str)) => Try(Bool, Str)
	release! = |host!| {
		label = deployed(summary!(host!)?)?
		run_steps!(label, ["selected", "plan", "show", "apply"], host!)
	}

	## The roots receipt, written to the output directory. Call it last, whether the deploy succeeded or not.
	receipt! : (Str => Try(Str, Str)) => Try(Str, Str)
	receipt! = |host!| Capability.call!("instance-roots-receipt", "{}", host!)

	## What a deploy's root releases: its candidate record's digest, source commit, image, artifact and tooling image.
	Release : { candidate : Str, commit : Str, image : Str, artifact_id : Str, tooling_image : Str }

	## A file the host wrote: its path, sha256 digest and size.
	File : { path : Str, digest : Str, bytes : U64 }
}

Prepared : { label : Str, shared : Bool, needs : List(Str), release : Bool }

prepare! : Str, (Str => Try(Str, Str)) => Try(List(Prepared), Str)
prepare! = |request, host!| {
	raw = Capability.call!("instance-roots-prepare", Json.to_str({ request: request }), host!)?
	_ = Capability.call!("instance-roots-credentials", "{}", host!)?
	roots(raw)
}

summary! : (Str => Try(Str, Str)) => Try(List(Prepared), Str)
summary! = |host!| roots(Capability.call!("instance-roots-summary", "{}", host!)?)

roots : Str -> Try(List(Prepared), Str)
roots = |raw| {
	prepared : { roots : List(Prepared) }
	prepared = Json.parse(raw).map_err(|_| "invalid instance preparation")?
	Ok(prepared.roots)
}

## A deploy runs exactly one day2-app root.
deployed : List(Prepared) -> Try(Str, Str)
deployed = |prepared| match prepared {
	[root] if root.release => Ok(root.label)
	_ => Err("a deploy runs exactly one day2-app root")
}

## Run each root, in order, unless a root it needs did not apply. A failed shared root stops every later root.
apply_roots! : List(Prepared), List(Str), (Str => Try(Str, Str)) => Try({}, Str)
apply_roots! = |prepared, unapplied, host!| match prepared {
	[] => Ok({})
	[root, .. as rest] => {
		if root.needs.any(|needed| unapplied.contains(needed)) {
			apply_roots!(rest, unapplied.append(root.label), host!)
		} else {
			applied = run_root!(root, ["init", "plan", "show", "apply"], host!)?
			if applied {
				apply_roots!(rest, unapplied, host!)
			} else if root.shared {
				Ok({})
			} else {
				apply_roots!(rest, unapplied.append(root.label), host!)
			}
		}
	}
}

## Run a root: its release first if it reads one (an unreleased root runs nothing else), then its operations in order,
## stopping at the first failure. Bool.True when every step succeeded or the root is unreleased.
run_root! : Prepared, List(Str), (Str => Try(Str, Str)) => Try(Bool, Str)
run_root! = |root, operations, host!| {
	if root.release {
		released : { ok : Bool, released : Bool }
		released = Json.parse(step!(root.label, "release", host!)?).map_err(|_| "invalid release result")?
		if !released.ok {
			return Ok(Bool.False)
		}
		if !released.released {
			return Ok(Bool.True)
		}
	}
	run_steps!(root.label, operations, host!)
}

## A root's operations in order; stop at the first failure and say whether every one succeeded.
run_steps! : Str, List(Str), (Str => Try(Str, Str)) => Try(Bool, Str)
run_steps! = |label, operations, host!| match operations {
	[] => Ok(Bool.True)
	[operation, .. as rest] => if
		ok(step!(label, operation, host!)?)?
		run_steps!(label, rest, host!)
	else
		Ok(Bool.False)
}

step! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |label, operation, host!| Capability.call!("instance-roots-operation", Json.to_str({ label, operation }), host!)

## Whether a step succeeded.
ok : Str -> Try(Bool, Str)
ok = |raw| {
	step : { ok : Bool }
	step = Json.parse(raw).map_err(|_| "invalid instance root step")?
	Ok(step.ok)
}
