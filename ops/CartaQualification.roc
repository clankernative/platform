import Capability

# Operator-run live Carta qualification against an expiring playground profile.
# The native session reads the profile and owner-private secret, holds the
# scratch store and enforces every evidence guard; this recipe owns step order.
# A failed step closes the session and discards the scratch store. No step is
# retried and no step accepts workflow-selected arguments.
CartaQualification :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("carta-qualification-open", "{}", host!)?
		_ = Capability.call!("carta-qualification-scratch", "{}", host!)?
		_ = Capability.call!("carta-qualification-collect", "{}", host!)?
		_ = Capability.call!("carta-qualification-discard", "{}", host!)?
		Capability.call!("carta-qualification-receipt", "{}", host!)
	}
}
