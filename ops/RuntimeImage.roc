import Capability

# Measure the fixed artifact-only composition of two immutable registry images.
# This is per-app packaging evidence; SDK compilation and qualification are shared.
RuntimeImage :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		for action in [
			"runtime-image-capture",
			"runtime-image-layers",
			"runtime-image-artifact",
		] {
			_ = Capability.call!(action, "{}", host!)?
		}
		Capability.call!("runtime-image-receipt", "{}", host!)
	}

	assemble_pair! : (Str => Try(Str, Str)) => Try(Str, Str)
	assemble_pair! = |host!| {
		_ = Capability.call!("runtime-pair-release-source", "{}", host!)?
		_ = Capability.call!("runtime-pair-release-target", "{}", host!)?
		_ = Capability.call!("runtime-pair-release-receipt", "{}", host!)?
		Capability.call!("runtime-pair-release-index", "{}", host!)
	}
}
