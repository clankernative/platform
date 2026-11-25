import Capability

## `day2 ci store`: the last step of an app's org-scoped CI run. The CLI hands over a request naming the run's directory;
## the host reads the run's record, the store inputs and ci check's output, and refuses any step out of order. This
## recipe owns the order: git-oidc's token, then Google STS's federated access token, then the artifact, then its
## receipt last, the marker that the artifact beside it is complete. A routed pull request run has nothing to store.
CiStore :: [].{

	## Whether ci check wrote an artifact to store.
	Plan : { artifact : Bool }

	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| {
		plan : Plan
		plan =
			Json.parse(Capability.call!("ci-store-prepare", Json.to_str({ request: request }), host!)?)
				.map_err(|_| "invalid CI store plan")?
		if plan.artifact {
			for name in ["mint", "exchange", "artifact", "receipt"] {
				_ = step!(name, host!)?
			}
		}
		step!("result", host!)
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("ci-store-step", Json.to_str({ name: name }), host!)
