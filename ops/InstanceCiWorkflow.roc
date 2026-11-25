import Capability

## `day2 instance ci-workflow`: what app CI's rendered workflow needs that day2.json cannot spell. The CLI renders the
## workflow itself; the host validates the request's names and refuses a step out of order. This recipe owns the
## order: the project's number, then each app's tooling image from its selected SDK release.
InstanceCiWorkflow :: [].{
	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| {
		_ = Capability.call!("instance-ci-workflow-prepare", Json.to_str({ request: request }), host!)?
		_ = step!("project", host!)?
		step!("releases", host!)
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("instance-ci-workflow-step", Json.to_str({ name: name }), host!)
