import Capability

# Freeze shared native outputs once, when producing a platform tooling image.
# Application builds consume the resulting distribution without invoking Rust.
Tooling :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("tooling-cli", "{}", host!)?
		_ = Capability.call!("tooling-worker", "{}", host!)?
		Capability.call!("tooling-package", "{}", host!)
	}
}
