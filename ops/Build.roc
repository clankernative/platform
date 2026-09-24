import Capability

Build :: [].{
	Receipt : { artifact : Str }

	source! : Str, (Str => Try(Str, Str)) => Try(Receipt, Str)
	source! = |source, host!| {
		# Enter the locked compiler adapter. It executes recipe! below in its
		# own supervisor, including when the source is an isolated CI checkout.
		raw = Capability.call!("build-source", Json.to_str({ source: source }), host!)?
		Json.parse(raw).map_err(|_| "invalid build receipt")
	}

	recipe! : (Str => Try(Str, Str)) => Try(Str, Str)
	recipe! = |host!| {
		_ = Capability.call!("build-stage", "{}", host!)?
		_ = Capability.call!("build-schema", "{}", host!)?
		_ = Capability.call!("build-data", "{}", host!)?
		_ = Capability.call!("build-app-shape", "{}", host!)?
		_ = Capability.call!("build-witnesses", "{}", host!)?
		_ = Capability.call!("build-app-types", "{}", host!)?
		_ = Capability.call!("build-bind", "{}", host!)?
		_ = Capability.call!("build-app-check", "{}", host!)?
		_ = Capability.call!("build-admission", "{}", host!)?
		_ = Capability.call!("build-glue", "{}", host!)?
		_ = Capability.call!("build-host", "{}", host!)?
		_ = Capability.call!("build-check", "{}", host!)?
		_ = Capability.call!("build-link", "{}", host!)?
		_ = Capability.call!("build-publish", "{}", host!)?
		_ = Capability.call!("build-verify", "{}", host!)?
		Capability.call!("build-select", "{}", host!)
	}
}
