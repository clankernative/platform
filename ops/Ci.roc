import Capability
import Check
import Simulation

# The provider adapter authenticates the event and binds its repository/SHA.
# This mandatory recipe runs under the durable host's pinned build capability.
Ci :: [].{
	Binding : { artifact : Str, output : Str }

	CacheEntry : { id : U64, family : Str, generation : Str, shared : Bool, retired : Bool, canonical : Bool }

	CacheInventory : { caches : List(CacheEntry), publishing : Str, current : Str, families : List(Str) }

	CachePlan : { include : List({ id : U64 }), deferred : U64 }

	# Inventory is complete and newest-first. Reserve this publication's generation
	# before it is saved; deletion jobs cannot run until that save succeeds.
	cache_choose : CacheInventory -> CachePlan
	cache_choose = |snapshot| {
		var $seen = snapshot.families.map(|family| { family, generation: snapshot.publishing })
		var $copies = []
		var $include = []
		var $deferred = 0.U64
		for entry in snapshot.caches {
			pair = { family: entry.family, generation: entry.generation }
			known = $seen.contains(pair)
			protected = entry.generation == snapshot.current or entry.generation == snapshot.publishing
			older =
				entry.shared and !protected and !known and $seen.keep_if(|item| item.family == entry.family).len() >= 2
			canonical_exists =
				snapshot
					.caches
					.any(
						|
							other,
						|
							other.shared
								and other.canonical
									and other.family == entry.family and other.generation == entry.generation,
					)
			redundant = entry.shared and ($copies.contains(pair) or (!entry.canonical and canonical_exists))
			if entry.shared and !older and !known {
				$seen = $seen.append(pair)
			}
			if entry.retired or older or redundant {
				if $include.len() < 16 {
					$include = $include.append({ id: entry.id })
				} else {
					$deferred = $deferred + 1
				}
			} else if entry.shared {
				$copies = $copies.append(pair)
			}
		}
		{ include: $include, deferred: $deferred }
	}

	cache_plan! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	cache_plan! = |target, host!| {
		raw = Capability.call!("ci-cache-inventory", Json.to_str({ target: target }), host!)?
		snapshot : CacheInventory
		snapshot = Json.parse(raw).map_err(|_| "invalid cache inventory")?
		Capability.call!("ci-cache-plan-output", Json.to_str(cache_choose(snapshot)), host!)
	}

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

# Newest-first inventory includes a live private ref, a retired ref, and more
# shared generations than fit. Active refs and the two newest generations stay.
expect {
	entry =
		{
			id: 1.U64,
			family: "linux-tests",
			generation: "new",
			shared: Bool.True,
			retired: Bool.False,
			canonical: Bool.True,
		}
	chosen = Ci.cache_choose({
		publishing: "new",
		current: "new",
		families: ["linux-tests"],
		caches: [
			entry,
			{ ..entry, id: 2, generation: "previous" },
			{ ..entry, id: 3, generation: "old" },
			{ ..entry, id: 4, shared: Bool.False },
			{ ..entry, id: 5, shared: Bool.False, retired: Bool.True },
		],
	})
	chosen == { include: [{ id: 3 }, { id: 5 }], deferred: 0 }
}

# Retry archives cannot displace the canonical cache for the same source.
expect {
	entry =
		{ id: 1.U64, family: "mac", generation: "new", shared: Bool.True, retired: Bool.False, canonical: Bool.False }
	Ci.cache_choose({
		publishing: "new",
		current: "new",
		families: ["mac"],
		caches: [entry, { ..entry, id: 2, canonical: Bool.True }],
	})
		== { include: [{ id: 1 }], deferred: 0 }
}

# A slower publisher never prunes a newer actual main generation.
expect {
	entry =
		{
			id: 1.U64,
			family: "mac",
			generation: "publishing",
			shared: Bool.True,
			retired: Bool.False,
			canonical: Bool.True,
		}
	Ci.cache_choose({
		publishing: "publishing",
		current: "new-main",
		families: ["mac"],
		caches: [entry, { ..entry, id: 2, generation: "new-main" }, { ..entry, id: 3, generation: "old" }],
	})
		== { include: [{ id: 3 }], deferred: 0 }
}

# Cleanup work is bounded explicitly; deferred entries are reported, not hidden.
expect {
	entries =
		[1.U64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
			.map(|id| { id, family: "", generation: "", shared: Bool.False, retired: Bool.True, canonical: Bool.False })
	chosen = Ci.cache_choose({ publishing: "new", current: "new", families: ["mac"], caches: entries })
	chosen.include.len() == 16 and chosen.deferred == 1
}
