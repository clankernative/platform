import Capability

# The provisioner retains its actual child and native guards in Rust. Roc owns
# the lifecycle order; no serialized workflow response can recreate that owner.
NativeEnrollment :: [].{
	supervise! : (Str => Try(Str, Str)) => Try(Str, Str)
	supervise! = |host!| {
		_ = Capability.call!("native-enrollment-current", "{}", host!)?
		_ = Capability.call!("native-enrollment-wait", "{}", host!)?
		supervise!(host!)
	}

	run! : (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |host!| {
		_ = Capability.call!("native-enrollment-start", "{}", host!)?
		supervise!(host!)
	}

	qualify! : (Str => Try(Str, Str)) => Try(Str, Str)
	qualify! = |host!| {
		for action in [
			"native-qualification-enroll",
			"native-qualification-current",
			"native-qualification-original-clock",
			"native-qualification-wait",
			"native-qualification-clock-continuity",
			"native-qualification-role-refusal",
		] {
			_ = Capability.call!(action, "{}", host!)?
		}
		Capability.call!("native-qualification-receipt", "{}", host!)
	}
}
