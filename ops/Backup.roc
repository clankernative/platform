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

	restore! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	restore! = |backup, output, host!| {
		_ = Capability.call!("backup-verify", Json.to_str({ directory: backup }), host!)?
		Capability.call!("backup-restore", Json.to_str({ backup, output }), host!)
	}
}
