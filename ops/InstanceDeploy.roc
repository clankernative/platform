import Capability
import InstanceRoots

## `day2 instance deploy` for a non-rolling app. The host fixes both session modes and the admissible candidate.
## Render the activation target before the first stop. After any failure, archive the operator's evidence and let
## the deploy session classify it using the live migration checkpoint.
InstanceDeploy :: [].{
	run! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, roots, host!| {
		_ = Capability.call!("instance-deploy-prepare", Json.to_str({ request: request }), host!)?
		opened = setup!(roots, host!)
		outcome = match opened {
			Ok(release) => deploy!(release, host!)
			Err(error) => Err(error)
		}
		archive = step!("archive-after", "null", host!)
		receipt = InstanceRoots.receipt!(host!)
		error : Try(Str, [Null])
		error = match (outcome, archive, receipt) {
			(Err(failed), _, _) => Ok(failed)
			# The host preserves the archive's error and classifies it at its own stage.
			(Ok(_), Err(_), _) => Err(Null)
			(Ok(_), Ok(_), Err(failed)) => Ok(failed)
			(Ok(_), Ok(_), Ok(_)) => Err(Null)
		}
		step!("finish", Json.to_str({ error: error }), host!)
	}
}

setup! : Str, (Str => Try(Str, Str)) => Try(InstanceRoots.Release, Str)
setup! = |roots, host!| {
	_ = step!("operator", "null", host!)?
	_ = step!("credentials", "null", host!)?
	InstanceRoots.open!(roots, host!)
}

deploy! : InstanceRoots.Release, (Str => Try(Str, Str)) => Try(Str, Str)
deploy! = |release, host!| {
	raw = step!("observe", Json.to_str(release), host!)?
	observed : { path : Str }
	observed = Json.parse(raw).map_err(|_| "invalid deploy path")?
	if observed.path == "fresh" {
		file = InstanceRoots.target!(host!)?
		_ = step!("target", Json.to_str(file), host!)?
		for name in ["deadline", "backup", "archive-before", "activate"] {
			_ = step!(name, "null", host!)?
		}
	} else {
		_ = step!("deadline", "null", host!)?
	}
	_ = step!("apply", "null", host!)?
	applied = InstanceRoots.release!(host!)?
	_ = step!("applied", Json.to_str({ ok: applied }), host!)?
	_ = step!("rollout", "null", host!)?
	step!("readback", "null", host!)
}

step! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! =
	|name, detail, host!| Capability.call!("instance-deploy-step", Json.to_str({ name: name, detail: detail }), host!)
