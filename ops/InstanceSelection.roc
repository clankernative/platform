import Capability

## Inspect one app's durable selection. Only an activating selection can have
## a recovery block, and the host checks that it names this exact candidate.
InstanceSelection :: [].{
	Snapshot : { status : Str, generation : Str, commit : Str, image : Str, artifact_id : Str }

	Receipt : { format : U64, app_id : Str, selection : Try(Snapshot, [Null]), blocked_activation : Bool }

	read! : (Str => Try(Str, Str)) => Try(Str, Str)
	read! = |host!| {
		raw = Capability.call!("instance-selection-read", "{}", host!)?
		saved : { app_id : Str, selection : Try(Snapshot, [Null]) }
		saved = Json.parse(raw).map_err(|_| "invalid selection snapshot")?
		blocked = match saved.selection {
			Ok(selection) if selection.status == "activating" => {
				value = Capability.call!("instance-selection-blocked", "{}", host!)?
				Json.parse(value).map_err(|_| "invalid blocked activation")
			}
			_ => Ok(Bool.False)
		}?
		receipt : Receipt
		receipt = { format: 1, app_id: saved.app_id, selection: saved.selection, blocked_activation: blocked }
		Ok(Json.to_str(receipt))
	}
}
