import Capability

# Explicit user-run recordings only. Credentials are read by the native host
# from the user's terminal; neither the recipe nor its pipes receive them.
# No retries, pagination continuation, production Carta, or raw persistence.
ProviderRecording :: [].{
	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |provider, host!| {
		_ = Capability.call!("provider-recording-open", "{}", host!)?
		_ = match provider {
			"carta" => {
				_ = Capability.call!("provider-recording-token", "{}", host!)?
				_ = Capability.call!("provider-recording-stakeholders", "{}", host!)?
				Capability.call!("provider-recording-grants", "{}", host!)?
			}
			"openai" => {
				Capability.call!("provider-recording-openai", "{}", host!)?
			}
			_ => return Err("unknown recording provider")
		}
		Capability.call!("provider-recording-publish", "{}", host!)
	}
}
