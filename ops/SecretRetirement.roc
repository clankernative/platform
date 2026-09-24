# A protected disable, not destruction. Only the host can inspect consumers,
# authorize a mutation or validate its receipt; Roc owns their ordering.
SecretRetirement :: [].{
	Phase := [WaitingConsumers, Eligible, WaitingDisabled, Disabled, Complete, Stopped]

	Snapshot : { phase : Str, next_step : U64 }

	Step : { name : Str, ordinal : U64, operation : Str }

	phase : Str -> Try(Phase, Str)
	phase = |value| match value {
		"waiting_consumers" => Ok(WaitingConsumers)
		"eligible" => Ok(Eligible)
		"waiting_disabled" => Ok(WaitingDisabled)
		"disabled" => Ok(Disabled)
		"complete" => Ok(Complete)
		"stopped" => Ok(Stopped)
		_ => Err("unsupported secret retirement phase")
	}

	choose : Snapshot -> Try(Step, Str)
	choose = |snapshot| {
		operation = match phase(snapshot.phase)? {
			WaitingConsumers => "wait_consumers"
			Eligible => "disable_version"
			WaitingDisabled => "observe_disabled"
			Disabled => "complete"
			Complete | Stopped => return Err("terminal retirement has no next step")
		}
		Ok({ name: operation, ordinal: snapshot.next_step, operation: operation })
	}

	run : Str -> Try(Str, Str)
	run = |raw| {
		snapshot : Snapshot
		snapshot = Json.parse(raw).map_err(|_| "invalid secret retirement input")?
		step = choose(snapshot)?
		Ok(Json.to_str(step))
	}
}
