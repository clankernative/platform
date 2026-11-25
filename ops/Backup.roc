import Capability

Backup :: [].{
	take! : Str, Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	take! = |instance, app_name, output, host!| {
		# A consistent SQLite snapshot and its addressed artifact form one
		# native operation. Verify the stored bundle before returning success.
		receipt = Capability.call!("backup-snapshot", Json.to_str({ instance, app_name, output }), host!)?
		_ = Capability.call!("backup-verify", Json.to_str({ directory: output }), host!)?
		Ok(receipt)
	}

	# The native broker retains its actual exclusion and selected archive across
	# these calls. Receipt DATA and successful recipe return confer no ownership.
	scheduled! : Str, Str, Str, Bool, (Str => Try(Str, Str)) => Try(Str, Str)
	scheduled! = |instance, app_name, output, upload, host!| {
		_ = take!(instance, app_name, output, host!)?
		_ = if upload {
			Capability.call!("backup-upload", "{}", host!)?
		} else {
			"{}"
		}
		Ok(Json.to_str({ scheduled_backup: "complete" }))
	}

	restore! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	restore! = |backup, output, host!| {
		_ = Capability.call!("backup-verify", Json.to_str({ directory: backup }), host!)?
		Capability.call!("backup-restore", Json.to_str({ backup, output }), host!)
	}

	# Historical archive identity only. This does not obtain or consume approval,
	# fence a holder, copy files, select current epochs or admit a new writer.
	inspect! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	inspect! = |backup, host!| Capability.call!("backup-verify", Json.to_str({ directory: backup }), host!)

	# A navigation leaf, not approval or restore execution. Browser IAP/passkey
	# ceremonies retain their actual native channel and accepting owner.
	protected! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	protected! =
		|
			instance,
			app_name,
			host!,
		| Capability.call!("restore-browser-entry", Json.to_str({ instance, app_name }), host!)
}
