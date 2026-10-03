import Capability

# The existing Release recipe selects each journal step. This recipe owns the
# bounded deployment driver and the final durable selector publication.
GkeRelease :: [].{
	drive! : Str, Str, U64, (Str => Try(Str, Str)) => Try({}, Str)
	drive! = |advance, execution, remaining, host!| {
		if remaining == 0 {
			return Err("release is pending; rerun to continue the same durable execution")
		}
		raw = Capability.call!(
			advance,
			Json.to_str(
				{ execution: execution },
			),
			host!,
		)?
		progress : { state : Str, wait_millis : U64 }
		progress = Json.parse(raw).map_err(|_| "invalid release progress")?
		match progress.state {
			"active" => Ok({})
			"pending" => {
				_ = Capability.call!("gke-release-wait", Json.to_str({ millis: progress.wait_millis }), host!)?
				drive!(advance, execution, remaining - 1, host!)
			}
			_ => Err("release requires intervention or has lost authority")
		}
	}

	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		raw = Capability.call!("gke-release-open", "{}", host!)?
		settings : { executions : List(Str) }
		settings = Json.parse(raw).map_err(|_| "invalid release settings")?
		for execution in settings.executions {
			_ = drive!("gke-release-advance", execution, 60, host!)?
		}
		Capability.call!("gke-release-publish", "{}", host!)
	}

	build! : (Str => Try(Str, Str)) => Try(Str, Str)
	build! = |host!| {
		raw = Capability.call!("gke-build-open", "{}", host!)?
		settings : { executions : List(Str) }
		settings = Json.parse(raw).map_err(|_| "invalid qualified build settings")?
		for execution in settings.executions {
			_ = drive!("gke-build-advance", execution, 6, host!)?
		}
		Capability.call!("gke-build-finish", "{}", host!)
	}
}
