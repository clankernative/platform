import Capability

# A Platform release selects and approves this build dependency. Apps select only
# locked package content; they cannot supply download URLs or executables.
UiDependency :: [].{
	install! : (Str => Try(Str, Str)) => Try(Str, Str)
	install! = |host!| {
		raw = Capability.call!("ui-dependency-inspect", "{}", host!)?
		status : { installed : Bool }
		status = Json.parse(raw).map_err(|_| "invalid UI dependency status")?
		if !status.installed {
			_ = Capability.call!("ui-dependency-fetch", "{}", host!)?
			_ = Capability.call!("ui-dependency-extract", "{}", host!)?
			_ = Capability.call!("ui-dependency-verify", "{}", host!)?
			_ = Capability.call!("ui-dependency-publish", "{}", host!)?
		}
		Capability.call!("ui-dependency-receipt", "{}", host!)
	}

	lock! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	lock! = |source, host!| Capability.call!(
		"ui-lock",
		Json.to_str(
			{ source: source },
		),
		host!,
	)
}
