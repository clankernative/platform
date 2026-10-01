import Capability

# Platform-owned qualification of the actual Linux image and packaged app.
# This scoped campaign excludes formatting and the complete platform test gate.
Linux :: [].{
	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("linux-capture", "{}", host!)?
		_ = Capability.call!("linux-build-tooling", "{}", host!)?
		_ = Capability.call!("linux-build-runtime", "{}", host!)?
		_ = Capability.call!("linux-start-tooling", "{}", host!)?
		_ = Capability.call!("linux-build-check", "{}", host!)?
		_ = Capability.call!("linux-build-probe", "{}", host!)?
		_ = Capability.call!("linux-build-owned", "{}", host!)?
		_ = Capability.call!("linux-build-delegation", "{}", host!)?
		_ = Capability.call!("linux-build-delegation-business", "{}", host!)?
		_ = Capability.call!("linux-test-delegation", "{}", host!)?
		for suite in ["sandbox", "worker", "http", "backup"] {
			_ = Capability.call!(
				"linux-test-suite",
				Json.to_str({ suite: suite }),
				host!,
			)?
		}
		for action in [
			"linux-runtime-package",
			"linux-runtime-start",
			"linux-runtime-read-write",
			"linux-runtime-revoke",
			"linux-runtime-graceful-restart",
			"linux-runtime-forced-restart",
			"linux-runtime-isolation",
			"linux-runtime-restore",
			"linux-runtime-stop",
		] {
			_ = Capability.call!(action, "{}", host!)?
		}
		_ = Capability.call!("linux-stop-tooling", "{}", host!)?
		Capability.call!("linux-receipt", "{}", host!)
	}

	strict! : (Str => Try(Str, Str)) => Try(Str, Str)
	strict! = |host!| {
		for action in [
			"linux-strict-package",
			"linux-strict-activate",
			"linux-strict-start",
			"linux-strict-query",
			"linux-strict-denial",
			"linux-strict-stop",
		] {
			_ = Capability.call!(action, "{}", host!)?
		}
		Capability.call!("linux-strict-receipt", "{}", host!)
	}
}
