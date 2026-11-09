import Capability

# Operational composition. Only phase/operation metadata enters the pure recipe.
AppSecrets :: [].{
	Transition : { operation : Str, phase : Str, step : Str }

	transitions : List(Transition)
	transitions = [
		{ operation: "create", phase: "admitted", step: "create_container" },
		{ operation: "create", phase: "container_created", step: "add_version" },
		{ operation: "rotate", phase: "admitted", step: "add_version" },
		{ operation: "delete", phase: "admitted", step: "delete_container" },
		{ operation: "reveal", phase: "admitted", step: "access_version" },
		{ operation: "reveal", phase: "revealed", step: "complete" },
		{ operation: "reveal", phase: "refused", step: "complete" },
		{ operation: "reveal", phase: "unknown", step: "complete" },
		{ operation: "delete", phase: "deleted", step: "complete" },
		{ operation: "delete", phase: "refused", step: "complete" },
		{ operation: "delete", phase: "unknown", step: "complete" },
		{ operation: "create", phase: "stored", step: "complete" },
		{ operation: "rotate", phase: "stored", step: "complete" },
		{ operation: "create", phase: "refused", step: "complete" },
		{ operation: "rotate", phase: "refused", step: "complete" },
		{ operation: "create", phase: "unknown", step: "complete" },
		{ operation: "rotate", phase: "unknown", step: "complete" },
	]

	# Live test values and credentials remain inside native adapters. Cleanup also
	# runs on native unwinding; this recipe never retries provider writes.
	canary! : (Str => Try(Str, Str)) => Try(Str, Str)
	canary! = |host!| {
		settings : { apps : List(Str) }
		settings =
			Json.parse(Capability.call!("secret-canary-settings", "{}", host!)?).map_err(|_| "invalid canary settings")?
		for application in settings.apps {
			_ = Capability.call!("secret-canary-open", Json.to_str({ app_name: application }), host!)?
			for action in [
				"secret-canary-create",
				"secret-canary-read-first",
				"secret-canary-rotate",
				"secret-canary-read-both",
				"secret-canary-cleanup",
			] {
				_ = Capability.call!(action, "{}", host!)?
			}
		}
		Ok(Json.to_str({ complete: Bool.True }))
	}

	# The deployed host embeds this generated data; no source checkout or runner is needed on requests.
	table : {} -> Str
	table = |_| Json.to_str(transitions)

	run : Str -> Try(Str, Str)
	run = |raw| {
		input : { operation : Str, phase : Str }
		input = Json.parse(raw).map_err(|_| "invalid secret workflow metadata")?
		for transition in transitions {
			if transition.operation == input.operation and transition.phase == input.phase {
				return Ok(Json.to_str(transition.step))
			}
		}
		Err("invalid secret workflow transition")
	}
}
