# Private, pure release decisions. Rust checks every transition and owns provider
# I/O; this recipe receives no secret material, credentials, or provider handles.
Release :: [].{
	Phase := [Accepted, WaitingSecret, SecretReady, WaitingDeployment, DeploymentReady, Active, Stopped]

	Snapshot : { phase : Str, next_step : U64 }

	Step : { name : Str, ordinal : U64, operation : Str }

	phase : Str -> Try(Phase, Str)
	phase = |value| match value {
		"accepted" => Ok(Accepted)
		"waiting_secret" => Ok(WaitingSecret)
		"secret_ready" => Ok(SecretReady)
		"waiting_deployment" => Ok(WaitingDeployment)
		"deployment_ready" => Ok(DeploymentReady)
		"active" => Ok(Active)
		"stopped" => Ok(Stopped)
		_ => Err("unsupported release phase")
	}

	choose : Snapshot -> Try(Step, Str)
	choose = |snapshot| {
		operation = match phase(snapshot.phase)? {
			Accepted => "prepare_dependency"
			WaitingSecret => "observe_secret"
			SecretReady => "prepare_deployment"
			WaitingDeployment => "observe_deployment"
			DeploymentReady => "activate"
			Active | Stopped => return Err("terminal release has no next step")
		}
		Ok({ name: operation, ordinal: snapshot.next_step, operation: operation })
	}

	run : Str -> Try(Str, Str)
	run = |raw| {
		snapshot : Snapshot
		snapshot = Json.parse(raw).map_err(|_| "invalid release decision input")?
		step = choose(snapshot)?
		Ok(Json.to_str(step))
	}
}
