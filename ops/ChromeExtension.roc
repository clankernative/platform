import Capability

# Self-hosted Chrome extension releases. A person packs a release with the app's
# signing key; `platform check` and CI verify the committed release without one.
ChromeExtension :: [].{
	verify! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	verify! = |source, host!| Capability.call!("chrome-extension-verify", Json.to_str({ source: source }), host!)

	pack! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	pack! = |source, key, host!| {
		packed = Capability.call!("chrome-extension-pack", Json.to_str({ source: source, key: key }), host!)?
		_ = verify!(source, host!)?
		Ok(packed)
	}

	local! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	local! = |source, output, host!| Capability.call!(
		"chrome-extension-local",
		Json.to_str({ source: source, output: output }),
		host!,
	)

	policy! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	policy! = |source, host!| Capability.call!("chrome-extension-policy", Json.to_str({ source: source }), host!)
}
