import Capability

# GKE maintenance of one day2 app (deploy/gke): stop it, run day2's own
# workflows against its state volume in a short-lived pod, then bring it back.
# This recipe only orders the steps. The Rust session behind the maintenance-*
# capabilities removes the pod on every exit, restores the app on any failure
# before the migration fence, and refuses steps taken out of order.
Maintain :: [].{
	run! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |operation, request, host!| {
		_ = Capability.call!("maintenance-open", Json.to_str({ operation, request }), host!)?
		_ = Capability.call!("maintenance-artifacts", "{}", host!)?
		_ = Capability.call!("maintenance-stop", "{}", host!)?
		_ = Capability.call!("maintenance-pod", "{}", host!)?
		_ = match operation {
			"inspect" => workflow!("authority-inspect", host!)?
			"backup" => backup!(host!)?
			"authority-apply" => {
				_ = backup!(host!)?
				_ = workflow!("authority-inspect", host!)?
				_ = Capability.call!("maintenance-confirm", "{}", host!)?
				workflow!("authority-apply", host!)?
			}
			"activate" => {
				_ = backup!(host!)?
				_ = Capability.call!("maintenance-migration", Json.to_str({ step: "plan" }), host!)?
				_ = Capability.call!("maintenance-confirm", "{}", host!)?
				# Past the fence the old image never restarts on this volume.
				_ = Capability.call!("maintenance-fence", "{}", host!)?
				_ = Capability.call!("maintenance-migration", Json.to_str({ step: "apply" }), host!)?
				_ = workflow!("authority-inspect", host!)?
				workflow!("authority-activate", host!)?
			}
			_ => return Err("maintain operation must be inspect, backup, authority-apply or activate")
		}
		Capability.call!("maintenance-finish", "{}", host!)
	}

	# A verified backup in the pod, then a verified private copy beside the operator.
	backup! : (Str => Try(Str, Str)) => Try(Str, Str)
	backup! = |host!| {
		_ = workflow!("backup", host!)?
		Capability.call!("maintenance-copy-backup", "{}", host!)
	}

	workflow! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	workflow! = |name, host!| Capability.call!("maintenance-workflow", Json.to_str({ workflow: name }), host!)
}
