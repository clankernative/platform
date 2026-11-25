import Capability

Build :: [].{
	# What the build's required verification proved, and where the selected
	# artifact keeps the full evidence.
	Verification : { artifact : Str, seed : Str, examples : U64, generated : U64, checks : List(Str), evidence : Str }

	# Every build selects one artifact after its required verification.
	Receipt : { artifact : Str, verification : Verification }

	source! : Str, (Str => Try(Str, Str)) => Try(Receipt, Str)
	source! = |source, host!| {
		# Enter the locked compiler adapter. It executes recipe! below in its
		# own supervisor, including when the source is an isolated CI checkout.
		raw = Capability.call!("build-source", Json.to_str({ source: source }), host!)?
		Json.parse(raw).map_err(|_| "invalid build receipt")
	}

	# The same build, with the requested seed and case count (at least the build's
	# own two) as its required verification.
	checked! : Str, U64, U64, (Str => Try(Str, Str)) => Try(Receipt, Str)
	checked! = |source, seed, cases, host!| {
		request = { source: source, seed: seed.to_str(), cases: cases }
		raw = Capability.call!("build-source", Json.to_str(request), host!)?
		Json.parse(raw).map_err(|_| "invalid build receipt")
	}

	# `day2 ci check`: the checked build, whose compiler adapter executes
	# tested_recipe! below, so it also runs the app's own tests.
	tested! : Str, U64, U64, (Str => Try(Str, Str)) => Try(Receipt, Str)
	tested! = |source, seed, cases, host!| {
		request = { source: source, seed: seed.to_str(), cases: cases, tests: Bool.True }
		raw = Capability.call!("build-source", Json.to_str(request), host!)?
		Json.parse(raw).map_err(|_| "invalid build receipt")
	}

	recipe! : (Str => Try(Str, Str)) => Try(Str, Str)
	recipe! = |host!| steps!(Bool.False, host!)

	# The same recipe, which also runs the top-level expects of every captured app module, imported or not, on
	# the checked stage before it links the worker.
	tested_recipe! : (Str => Try(Str, Str)) => Try(Str, Str)
	tested_recipe! = |host!| steps!(Bool.True, host!)
}

steps! : Bool, (Str => Try(Str, Str)) => Try(Str, Str)
steps! = |tests, host!| {
	_ = Capability.call!("build-stage", "{}", host!)?
	_ = Capability.call!("build-schema", "{}", host!)?
	_ = Capability.call!("build-data", "{}", host!)?
	_ = Capability.call!("build-app-shape", "{}", host!)?
	_ = Capability.call!("build-witnesses", "{}", host!)?
	_ = Capability.call!("build-app-types", "{}", host!)?
	_ = Capability.call!("build-glue", "{}", host!)?
	_ = Capability.call!("build-host", "{}", host!)?
	_ = Capability.call!("build-connection-contract", "{}", host!)?
	_ = Capability.call!("build-operation-handles", "{}", host!)?
	_ = Capability.call!("build-credential-contract", "{}", host!)?
	_ = Capability.call!("build-bind", "{}", host!)?
	_ = Capability.call!("build-app-check", "{}", host!)?
	_ = Capability.call!("build-admission", "{}", host!)?
	_ = Capability.call!("build-check", "{}", host!)?
	if tests {
		_ = Capability.call!("build-test", "{}", host!)?
	}
	_ = Capability.call!("build-link", "{}", host!)?
	_ = Capability.call!("build-publish", "{}", host!)?
	_ = Capability.call!("build-verify", "{}", host!)?
	Capability.call!("build-select", "{}", host!)
}
