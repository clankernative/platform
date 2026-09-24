import Capability

# Private control-plane policy. Each host call runs or replays one bounded
# schedule; this recipe owns corpus-first ordering and campaign completion.
Simulation :: [].{
	Catalog : { regressions : List(U32), cases : List(U32) }

	campaign! : U64, U32, (Str => Try(Str, Str)) => Try(Str, Str)
	campaign! = |seed, count, host!| {
		if count < 1 or count > 128 {
			return Err("control simulation cases must be 1..128")
		}
		raw = Capability.call!("simulation-open", Json.to_str({ seed: seed.to_str(), cases: count }), host!)?
		catalog : Catalog
		catalog = Json.parse(raw).map_err(|_| "invalid control simulation catalog")?
		for index in catalog.regressions {
			_ = Capability.call!("simulation-regression", Json.to_str({ index: index }), host!)?
			_ = Capability.call!("simulation-check-replay", "{}", host!)?
		}
		for index in catalog.cases {
			_ = Capability.call!("simulation-case", Json.to_str({ index: index }), host!)?
			_ = Capability.call!("simulation-check-replay", "{}", host!)?
		}
		Capability.call!("simulation-receipt", "{}", host!)
	}

	replay! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	replay! = |trace, host!| Capability.call!("simulation-replay", Json.to_str({ trace: trace }), host!)
}
