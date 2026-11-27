import Capability

## `day2 instance release publish` and `day2 instance release fetch`: a qualified SDK release in the instance's state
## bucket. The CLI renders the request from day2.json (its derived state bucket and its project's registry) and the
## host action fixes the mode. This recipe owns the order; the host validates every step and refuses one out of order.
InstanceRelease :: [].{

	## For operators. The host validates the whole publication first: the files' identities, the manifest, and that
	## the distribution and evidence bind it. Then both images must pull as the qualified image IDs, each blob is
	## created only if absent (an existing object counts only once its exact generation downloads to the same
	## digest), and the manifest file is written and published last, so an incomplete publication is never a
	## selectable release.
	publish! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	publish! = |request, host!| {
		prepare!(request, host!)?
		for image in ["runtime", "tooling"] {
			_ = Capability.call!("instance-release-image", Json.to_str({ name: image }), host!)?
		}
		for blob in ["native", "strict", "distribution"] {
			_ = Capability.call!("instance-release-blob", Json.to_str({ name: blob }), host!)?
		}
		rolling_evidence!("operator", host!)?
		Capability.call!("instance-release-manifest", "{}", host!)
	}

	## Read the approved manifest, then the distribution and the evidence it names, each through the local cache
	## (verified again on every hit) and bound to the one before it, then the operator CLI, whose files are verified
	## one by one on every fetch.
	fetch! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	fetch! = |request, host!| {
		prepare!(request, host!)?
		for blob in ["manifest", "distribution", "native"] {
			_ = Capability.call!("instance-release-blob", Json.to_str({ name: blob }), host!)?
		}
		rolling_evidence!("strict", host!)?
		Capability.call!("instance-release-operator", "{}", host!)
	}
}

rolling_evidence! : Str, (Str => Try(Str, Str)) => Try({}, Str)
rolling_evidence! = |previous, host!| {
	text = Capability.call!("instance-release-blob", Json.to_str({ name: previous }), host!)?
	result : Try({ rolling_required : Bool }, _)
	result = Json.parse(text)
	status = result.map_err(|_| "Invalid release evidence receipt")?
	if status.rolling_required {
		_ = Capability.call!("instance-release-blob", Json.to_str({ name: "rolling" }), host!)?
	}
	Ok({})
}

prepare! : Str, (Str => Try(Str, Str)) => Try({}, Str)
prepare! = |request, host!| {
	_ = Capability.call!("instance-release-prepare", Json.to_str({ request: request }), host!)?
	Ok({})
}
