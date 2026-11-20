import Capability

# Operator-run live Google Workspace qualification against an expiring profile.
# The native session reads the profile and the owner-private operator token, runs
# every probe through the adapter and enforces every evidence guard; this recipe
# owns step order. Every read runs before the one write, and the run is dropped
# before the receipt is published. A failed step closes the session and drops
# the run. No step is retried and no step accepts workflow-selected arguments.
GoogleWorkspaceQualification :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("google-workspace-qualification-open", "{}", host!)?
		_ = Capability.call!("google-workspace-qualification-read", "{}", host!)?
		_ = Capability.call!("google-workspace-qualification-share", "{}", host!)?
		_ = Capability.call!("google-workspace-qualification-discard", "{}", host!)?
		Capability.call!("google-workspace-qualification-receipt", "{}", host!)
	}
}
