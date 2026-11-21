import Capability

# GKE maintenance of one day2 app (deploy/gke): stop it, run day2's own
# workflows against its state volume in a short-lived pod, then bring it back.
# This recipe only orders the steps. The Rust session behind the maintenance-*
# capabilities removes the pod on every exit, restores the app on any failure
# before the migration fence, and refuses steps taken out of order.
Maintain :: [].{
	run! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |operation, request, host!| {
		if operation == "recover" {
			_ = Capability.call!("maintenance-recovery-open", Json.to_str({ journal: request }), host!)?
			_ = Capability.call!("maintenance-recovery-claim", "{}", host!)?
			_ = Capability.call!("maintenance-recovery-cleanup", "{}", host!)?
			return Capability.call!("maintenance-recovery-restore", "{}", host!)
		}
		_ = Capability.call!("maintenance-open", Json.to_str({ operation, request }), host!)?
		_ = Capability.call!("maintenance-artifacts", "{}", host!)?
		if operation == "mark-activated" {
			_ = Capability.call!("maintenance-begin-preparation", "{}", host!)?
		}
		if operation == "activate" {
			raw = Capability.call!("maintenance-begin-preparation", "{}", host!)?
			preparation : { source_serving : Bool }
			preparation = Json.parse(raw).map_err(|_| "invalid activation preparation observation")?
			# Pull, schedule, size and populate the helper while the source serves.
			# These steps inspect file sizes, never open the live SQLite stores.
			_ = Capability.call!("maintenance-measure", "{}", host!)?
			_ = Capability.call!("maintenance-pod", "{}", host!)?
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
			if preparation.source_serving {
				_ = backup!(host!)?
				_ = Capability.call!("maintenance-rehearsal-copy", "{}", host!)?
				_ = Capability.call!("maintenance-migration", Json.to_str({ step: "plan" }), host!)?
				_ = Capability.call!("maintenance-admission", "{}", host!)?
				_ = Capability.call!("maintenance-online-prepared", "{}", host!)?
			}
		}
		_ = Capability.call!("maintenance-stop", "{}", host!)?
		if operation == "activate" {
			# Preparation sizes are not a checkpoint: bound growth after the stop.
			_ = Capability.call!("maintenance-verify-preparation", "{}", host!)?
		} else {
			_ = Capability.call!("maintenance-measure", "{}", host!)?
			_ = Capability.call!("maintenance-pod", "{}", host!)?
		}
		if operation == "rollout" {
			return rolling!(host!)
		}
		if operation == "runtime-rollout" {
			return runtime_rolling!(host!)
		}
		if operation != "activate" {
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
		}
		_ = match operation {
			"inspect" => workflow!("authority-inspect", host!)?
			"backup" => backup!(host!)?
			"authority-apply" => {
				_ = backup!(host!)?
				_ = workflow!("authority-inspect", host!)?
				_ = Capability.call!("maintenance-confirm", "{}", host!)?
				workflow!("authority-apply", host!)?
			}
			"recovery-abandon" => {
				# Each listed blocked invocation is abandoned with the app stopped,
				# after a verified backup of the store it changes and a confirmation.
				_ = backup!(host!)?
				_ = Capability.call!("maintenance-confirm", "{}", host!)?
				workflow!("recovery-abandon", host!)?
			}
			"activate" => {
				_ = backup!(host!)?
				_ = Capability.call!("maintenance-rehearsal-copy", "{}", host!)?
				_ = Capability.call!("maintenance-migration", Json.to_str({ step: "plan" }), host!)?
				# Rehearse the target's post-fence maintenance admission with this
				# request's operator; a refusal stops here with the app restored.
				_ = Capability.call!("maintenance-admission", "{}", host!)?
				_ = Capability.call!("maintenance-confirm", "{}", host!)?
				# Past the fence the old image never restarts on this volume.
				_ = Capability.call!("maintenance-fence", "{}", host!)?
				_ = Capability.call!("maintenance-migration", Json.to_str({ step: "apply" }), host!)?
				_ = workflow!("authority-inspect", host!)?
				_ = workflow!("authority-activate", host!)?
				_ = Capability.call!("maintenance-store-admission", "{}", host!)?
				# Only now may a release or an apply roll the app to the target image.
				Capability.call!("maintenance-mark-activated", "{}", host!)?
			}
			"mark-activated" => {
				# Recovery when activate's own mark failed for a new artifact: stamp
				# the target image only if the database already activates its artifact.
				_ = workflow!("authority-inspect", host!)?
				Capability.call!("maintenance-mark-activated", "{}", host!)?
			}
			_ => return Err(
				"maintain operation must be inspect, backup, authority-apply, recovery-abandon, activate, mark-activated, rollout or runtime-rollout",
			)
		}
		Capability.call!("maintenance-finish", "{}", host!)
	}

	rolling! : (Str => Try(Str, Str)) => Try(Str, Str)
	rolling! = |host!| {
		raw = Capability.call!("maintenance-rollout-resume", "{}", host!)?
		previous : { resuming : Bool }
		previous = Json.parse(raw).map_err(|_| "invalid rollout resume observation")?
		if !previous.resuming {
			_ = Capability.call!("maintenance-offsite-backup", "{}", host!)?
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
			_ = backup!(host!)?
			_ = Capability.call!("maintenance-rehearsal-copy", "{}", host!)?
			_ = Capability.call!("maintenance-migration", Json.to_str({ step: "plan" }), host!)?
			_ = Capability.call!("maintenance-admission", "{}", host!)?
			_ = Capability.call!("maintenance-confirm", "{}", host!)?
		} else {
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
		}
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "prepare" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "bind" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "admit" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "deploy" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "observe" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "probe" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "promote" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "wait" }), host!)?
		_ = Capability.call!("maintenance-rollout", Json.to_str({ step: "complete" }), host!)?
		Capability.call!("maintenance-finish", "{}", host!)
	}

	# Runtime-only changes keep Source serving through isolated checks, public
	# Target admission and actual backend health. Adoption reuses the running
	# Target ReplicaSet; recovery always executes accepted work with Source code.
	runtime_rolling! : (Str => Try(Str, Str)) => Try(Str, Str)
	runtime_rolling! = |host!| {
		_ = runtime_step!("reap-helpers", host!)?
		_ = runtime_step!("settle-backups", host!)?
		raw = runtime_step!("resume", host!)?
		previous : { resuming : Bool, aborted : Bool }
		previous = Json.parse(raw).map_err(|_| "invalid runtime resume observation")?
		if previous.aborted {
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
			_ = runtime_step!("abort-cleanup", host!)?
			return Capability.call!("maintenance-finish", "{}", host!)
		}
		if !previous.resuming {
			_ = Capability.call!("maintenance-offsite-backup", "{}", host!)?
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
			_ = backup!(host!)?
		} else {
			_ = Capability.call!("maintenance-operation-claim", "{}", host!)?
		}
		for step in [
			"blueprint",
			"rehearsal-copy",
			"rehearsal-check",
			"rehearsal-remove",
			"confirm",
			"claim",
			"prepare",
			"placement",
			"executors",
			"candidate",
			"bind",
			"check",
			"promote",
			"probe",
			"withdraw",
			"drain",
			"quiesce",
			"transport-stop",
			"pause",
			"retarget",
			"adopt",
			"unpause",
			"source-gone",
		] {
			_ = runtime_step!(step, host!)?
		}
		var $remaining = Bool.True
		var $attempts = 0.U64
		while $remaining {
			if $attempts >= 32 {
				return Err("runtime source recovery budget exhausted; resume the same request")
			}
			recovery_raw = runtime_step!("recover", host!)?
			status : { remaining : Bool }
			status = Json.parse(recovery_raw).map_err(|_| "invalid runtime recovery observation")?
			$remaining = status.remaining
			$attempts = $attempts + 1
		}
		_ = runtime_step!("complete", host!)?
		_ = runtime_step!("backup-select", host!)?
		_ = runtime_step!("release", host!)?
		Capability.call!("maintenance-finish", "{}", host!)
	}

	runtime_step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	runtime_step! =
		|step_name, host!| Capability.call!("maintenance-runtime-rollout", Json.to_str({ step: step_name }), host!)

	# A verified backup in the pod, then a verified private copy beside the operator.
	backup! : (Str => Try(Str, Str)) => Try(Str, Str)
	backup! = |host!| {
		_ = workflow!("backup", host!)?
		Capability.call!("maintenance-copy-backup", "{}", host!)
	}

	workflow! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	workflow! = |name, host!| Capability.call!("maintenance-workflow", Json.to_str({ workflow: name }), host!)
}
