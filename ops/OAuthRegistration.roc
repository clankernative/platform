import Capability

# The native session holds exact client/callback selections and secret material.
# Each step is fenced before I/O; failure requires a new canary, never a retry.
OAuthRegistration :: [].{

	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("oauth-registration-open", "{}", host!)?
		_ = Capability.call!("oauth-registration-reject-pkce", "{}", host!)?
		_ = Capability.call!("oauth-registration-verify-pkce", "{}", host!)?
		_ = Capability.call!("oauth-registration-reject-credential", "{}", host!)?
		_ = Capability.call!("oauth-registration-exchange", "{}", host!)?
		_ = Capability.call!("oauth-registration-account", "{}", host!)?
		_ = Capability.call!("oauth-registration-refresh", "{}", host!)?
		_ = Capability.call!("oauth-registration-refresh-account", "{}", host!)?
		Capability.call!("oauth-registration-seal", "{}", host!)
	}
}
