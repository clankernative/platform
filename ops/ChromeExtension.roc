import Capability

## `day2 instance extension`: self-hosted Chrome extension releases, against the extension day2.json pins for the app.
## A person packs a release with the extension's signing key; app CI verifies the committed release without one. The
## host holds the request, with the pin, and runs only its mode's step; this recipe owns the order.
ChromeExtension :: [].{
	run! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |mode, host!| match mode {
		# Sign a release, then verify what was written as app CI will.
		"pack" => {
			packed = step!("pack", host!)?
			_ = step!("verify", host!)?
			Ok(packed)
		}
		# Verify the committed release; write an unpacked build; print the browser policy; or read the release's
		# uptake from the instance project's edge request logs, read-only.
		"verify" | "local" | "policy" | "fleet" => step!(mode, host!)
		_ => Err("unknown instance extension command: ${mode}")
	}
}

step! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
step! = |name, host!| Capability.call!("instance-extension-step", Json.to_str({ name: name }), host!)
