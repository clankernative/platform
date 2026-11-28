import Capability

## `day2 instance candidate`: an app's deployment candidate. The CLI renders the request from day2.json (the forge, its
## org, the registry, the state bucket, the project, zone, apply identity and build host, and each app's sdk and
## verification cases), or, on the build host, names only the private job directory. The host action fixes the mode.
## This recipe owns the order; the host validates the request first, refuses a step out of order, and reports a
## transient forge read as retryable.
InstanceCandidate :: [].{

	## The candidate for a binding and a commit: the stored candidate record, else the checked-inputs record for the
	## same app inputs, else a native build of the commit's checked main artifact. Repository-local CI requires its
	## archive controls before reuse. The last step writes the candidate record if it is new, and its bytes.
	build! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	build! = |request, host!| {
		prepare!(request, host!)?
		stored : { found : Bool, verify_legacy_controls : Bool }
		stored = Json.parse(step!("stored", host!)?).map_err(|_| "invalid stored candidate lookup result")?
		if stored.found {
			return step!("record", host!)
		}
		for name in ["archive", "inputs"] {
			_ = step!(name, host!)?
		}
		if stored.verify_legacy_controls {
			_ = step!("controls", host!)?
		}
		if found(step!("cached", host!)?)? {
			_ = step!("reuse", host!)?
		} else {
			# The checked artifact, the release's evidence, then the build host: stage the job, build, collect.
			for name in ["run", "job", "artifact", "download", "attempt", "release", "stage", "native", "collect"] {
				_ = step!(name, host!)?
			}
		}
		step!("record", host!)
	}

	## Validate a candidate record, then prove its tooling image's maintenance protocol on the build host.
	preflight! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	preflight! = |request, host!| {
		prepare!(request, host!)?
		for name in ["validate", "stage"] {
			_ = step!(name, host!)?
		}
		step!("probe", host!)
	}

	## Validate a candidate record for an app.
	check! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	check! = |request, host!| {
		prepare!(request, host!)?
		step!("validate", host!)
	}

	## On the build host: check the job's request and files, take a build slot, check the source inputs and the
	## checked artifact, start the pinned tooling, prove its maintenance protocol, admit and package the artifact,
	## push it, and write the result.
	native_build! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	native_build! = |request, host!| {
		prepare!(request, host!)?
		for name in ["request", "slot", "inputs", "artifact", "tooling", "protocol", "security", "package", "push"] {
			_ = step!(name, host!)?
		}
		step!("result", host!)
	}

	## On the build host: check the job's request and files, then prove the tooling image's maintenance protocol.
	native_probe! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	native_probe! = |request, host!| {
		prepare!(request, host!)?
		_ = step!("request", host!)?
		step!("probe", host!)
	}
}

prepare! : Str, (Str => Try(Str, Str)) => Try({}, Str)
prepare! = |request, host!| {
	_ = Capability.call!("instance-candidate-prepare", Json.to_str({ request: request }), host!)?
	Ok({})
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("instance-candidate-step", Json.to_str({ name: name }), host!)

## Whether a lookup step found its record.
found : Str -> Try(Bool, Str)
found = |raw| {
	decoded : { found : Bool }
	decoded = Json.parse(raw).map_err(|_| "invalid candidate lookup result")?
	Ok(decoded.found)
}
