import Capability

# Operator-run live Google Workspace qualification against an expiring profile.
# The native session reads the profile and the owner-private operator token and
# enforces every guard: each read step once and before the share, one create,
# checks only after it, at most seven, each after its minimum wait. This recipe
# owns the order: the reads, the one share, then checks until the permission is
# listed or seven have run, then the run is dropped before the receipt is
# published. A failed step closes the session. No step is retried and no step
# accepts workflow-selected arguments.
GoogleWorkspaceQualification :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("google-workspace-qualification-open", "{}", host!)?
		for action in [
			"google-workspace-qualification-directory",
			"google-workspace-qualification-calendars",
			"google-workspace-qualification-events",
			"google-workspace-qualification-event",
			"google-workspace-qualification-conferences",
			"google-workspace-qualification-share-alias",
		] {
			_ = Capability.call!(action, "{}", host!)?
		}
		shared_raw = Capability.call!("google-workspace-qualification-share", "{}", host!)?
		shared : { check : Bool }
		shared = Json.parse(shared_raw).map_err(|_| "invalid google workspace share observation")?
		var $pending = shared.check
		var $checks = 0.U64
		while $pending {
			check_raw = Capability.call!("google-workspace-qualification-check", "{}", host!)?
			check : { visible : Bool }
			check = Json.parse(check_raw).map_err(|_| "invalid google workspace visibility check")?
			$checks = $checks + 1
			$pending = if check.visible Bool.False else $checks < 7
		}
		_ = Capability.call!("google-workspace-qualification-discard", "{}", host!)?
		Capability.call!("google-workspace-qualification-receipt", "{}", host!)
	}
}
