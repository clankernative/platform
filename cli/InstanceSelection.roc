import InstanceSpec
import Problem

InstanceSelection :: [].{
	Snapshot : { status : Str, generation : Str, commit : Str, image : Str, artifact_id : Str }

	Receipt : { format : U64, app_id : Str, selection : Try(Snapshot, [Null]), blocked_activation : Bool }

	request : InstanceSpec, Str -> Try(Str, Problem)
	request = |spec, app_id| {
		names = spec.derived()
		if !names.apps.any(|entry| entry.id == app_id) {
			return Err(Problem.InvalidArguments("instance selection requires an app declared in day2.json."))
		}
		Ok(
			Json.to_str({
				project: names.gcp_project,
				app_id,
				releases: {
					bucket: names.tofu_state_bucket,
					registry: names.artifact_registry,
					forge: { server: names.forge_server, org: names.forge_org },
				},
			}),
		)
	}

	receipt : Str, Str -> Try(Receipt, [InvalidReceipt])
	receipt = |raw, app_id| {
		value : Receipt
		value = Json.parse(raw).map_err(|_| InvalidReceipt)?
		if value.format != 1 or value.app_id != app_id {
			return Err(InvalidReceipt)
		}
		valid = match value.selection {
			Ok(selection) => selection.status
				== "activating"
				or (selection.status == "ready" and !value.blocked_activation)
			Err(Null) => !value.blocked_activation
		}
		if valid Ok(value) else Err(InvalidReceipt)
	}
}
