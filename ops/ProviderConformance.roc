import Capability

# Private operator probes against explicitly admitted disposable resources.
# The host binds the profile, records dispatch before I/O, and decides whether
# observations satisfy each obligation. This recipe never retries a mutation.
ProviderConformance :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("provider-open", "{}", host!)?
		_ = Capability.call!("provider-aliases", "{}", host!)?
		_ = Capability.call!("provider-lost-ack-dispatch", "{}", host!)?
		_ = Capability.call!("provider-lost-ack-observe", "{}", host!)?
		_ = Capability.call!("provider-late-hold", "{}", host!)?
		_ = Capability.call!("provider-late-observe", "{}", host!)?
		_ = Capability.call!("provider-late-deliver", "{}", host!)?
		_ = Capability.call!("provider-late-reconcile", "{}", host!)?
		_ = Capability.call!("provider-quiescence", "{}", host!)?
		Capability.call!("provider-receipt", "{}", host!)
	}
}
