import Capability

## `day2 instance source`: an app's source on the instance's Gitea forge. The CLI renders the request from day2.json
## (the forge, its org, the registry, the state bucket and each app's sdk and verification cases) and the host action
## fixes the mode. This recipe owns the order; the host validates the request and the binding first, refuses a step out
## of order, and reports a transient read as retryable.
InstanceSource :: [].{

	## The binding's branch head: the repository must still be the bound one, and its branch an exact commit.
	head! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	head! = |request, host!| {
		prepare!(request, host!)?
		step!("head", host!)
	}

	## A commit's archive, written to a new file.
	archive! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	archive! = |request, host!| {
		prepare!(request, host!)?
		step!("archive", host!)
	}

	## The CI-control digest of a local source archive.
	controls! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	controls! = |request, host!| {
		prepare!(request, host!)?
		step!("controls", host!)
	}

	## Check the archive's control digest against the binding's approved one, and the release it selects, before
	## anything is read from the bucket; then read the binding's qualified release manifest through the release cache
	## and check the app's CI configuration against it and the binding's verification profile.
	verify_controls! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	verify_controls! = |request, host!| {
		prepare!(request, host!)?
		_ = step!("controls", host!)?
		step!("release", host!)
	}

	## Wait for the exact main commit's push run to succeed, bind its one native job and the one receipt that job's
	## log carries, check the upload the receipt names and download and verify it. Only once the run is still the same
	## successful attempt is the archive written and the proof returned.
	checked_artifact! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	checked_artifact! = |request, host!| {
		prepare!(request, host!)?
		for name in ["run", "job", "artifact", "download"] {
			_ = step!(name, host!)?
		}
		step!("attempt", host!)
	}
}

prepare! : Str, (Str => Try(Str, Str)) => Try({}, Str)
prepare! = |request, host!| {
	_ = Capability.call!("instance-source-prepare", Json.to_str({ request: request }), host!)?
	Ok({})
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("instance-source-step", Json.to_str({ name: name }), host!)
