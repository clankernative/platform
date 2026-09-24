import Capability

# Operator-only setup for an exported deployment. The native validation reads
# only the explicitly mounted credentials and checks the reviewed metadata.
# Each registration is independently idempotent; no provider calls are made.
Provision :: [].{
	run! : Str, Str, Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |instance, app_name, operator, plan_file, host!| {
		raw = Capability.call!(
			"credential-provision-inputs",
			Json.to_str({ instance, app_name, operator, plan_file }),
			host!,
		)?
		inputs : List(Str)
		inputs = Json.parse(raw).map_err(|_| "invalid credential provisioning inputs")?
		for input_json in inputs {
			_ = Capability.call!(
				"credential-provision-mount",
				Json.to_str({ instance, operator, input_json }),
				host!,
			)?
		}
		Ok(Json.to_str({ registered: inputs.len(), provider_qualified: Bool.False }))
	}

	smoke! : (Str => Try(Str, Str)) => Try(Str, Str)
	smoke! = |host!| {
		for action in [
			"linux-provision-package",
			"linux-provision-apply",
			"linux-provision-retry",
			"linux-provision-start",
			"linux-provision-inspect",
			"linux-provision-stop",
		] {
			_ = Capability.call!(action, "{}", host!)?
		}
		Capability.call!("linux-provision-receipt", "{}", host!)
	}
}
