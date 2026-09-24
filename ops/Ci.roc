import Capability
import Check
import Simulation

# The provider adapter authenticates the event and binds its repository/SHA.
# This mandatory recipe runs under the durable host's pinned build capability.
Ci :: [].{
	Binding : { artifact : Str, output : Str }

	event : Str, Str, Bool -> Try(Bool, Str)
	event = |event_name, action, deleted| match event_name {
		"push" => Ok(!deleted)
		"pull_request" => Ok(["opened", "reopened", "synchronize", "ready_for_review"].contains(action))
		"merge_group" => Ok(action == "checks_requested")
		"check_run" => Ok(action == "rerequested")
		_ => Err("unsupported source event")
	}

	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Simulation.campaign!(3_664_912_422, 8, host!)?
		_ = Capability.call!("ci-materialize", "{}", host!)?
		_ = Capability.call!("ci-build", "{}", host!)?
		_ = Capability.call!("ci-admit", "{}", host!)?
		_ = Capability.call!("ci-properties", "{}", host!)?
		raw = Capability.call!("ci-development", "{}", host!)?
		settings : Binding
		settings = Json.parse(raw).map_err(|_| "invalid CI development binding")?
		_ =
			Check.campaign!(
				{ artifact: settings.artifact, output: settings.output, example: "", seed: "3664912422", count: 16 },
				host!,
			)?
		Capability.call!("ci-evidence", "{}", host!)
	}
}

expect Ci.event("pull_request", "closed", Bool.False) == Ok(Bool.False)
expect Ci.event("pull_request", "synchronize", Bool.False) == Ok(Bool.True)
expect Ci.event("push", "", Bool.True) == Ok(Bool.False)
expect Ci.event("merge_group", "checks_requested", Bool.False) == Ok(Bool.True)
