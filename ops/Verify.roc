import Capability
import Simulation

# Platform regression policy, shared by xtask and operator CLI commands.
Verify :: [].{
	cli! : (Str => Try(Str, Str)) => Try(Str, Str)
	cli! = |host!| {
		_ = Capability.call!("cli-native", "{}", host!)?
		for operation in ["check", "test", "build"] {
			_ = Capability.call!("cli-roc", Json.to_str({ operation: operation }), host!)?
		}
		_ = Capability.call!("cli-workflow-tests", "{}", host!)?
		Capability.call!("cli-receipt", "{}", host!)
	}

	# Fast maintainer feedback. This deliberately excludes native fixture builds,
	# integration histories and control-plane qualification; those remain final
	# stable-snapshot obligations in reports! and all!.
	fast! : (Str => Try(Str, Str)) => Try(Str, Str)
	fast! = |host!| {
		_ = Capability.call!("verify-format", Json.to_str({ scope: "all" }), host!)?
		_ = Capability.call!("verify-lint", "{}", host!)?
		_ = Capability.call!("verify-tests", Json.to_str({ suite: "fast-libraries" }), host!)?
		Capability.call!("verify-receipt", Json.to_str({ scope: "fast" }), host!)
	}

	reports! : (Str => Try(Str, Str)) => Try(Str, Str)
	reports! = |host!| {
		_ = Capability.call!("verify-format", Json.to_str({ scope: "reports" }), host!)?
		_ = Capability.call!("verify-cli", "{}", host!)?
		for fixture in [
			"reports",
			"reports-probe",
			"reports-deferrals",
			"oncall",
			"owned",
			"owned-probe",
			"repeated-field",
		] {
			_ = Capability.call!("verify-build", Json.to_str({ fixture: fixture }), host!)?
		}
		_ = Capability.call!("verify-lint", "{}", host!)?
		for suite in ["libraries", "xtask", "operations", "reports-runtime"] {
			_ = Capability.call!("verify-tests", Json.to_str({ suite: suite }), host!)?
		}
		_ = control!(host!)?
		Capability.call!("verify-receipt", Json.to_str({ scope: "reports" }), host!)
	}

	all! : (Str => Try(Str, Str)) => Try(Str, Str)
	all! = |host!| {
		_ = Capability.call!("verify-format", Json.to_str({ scope: "all" }), host!)?
		_ = Capability.call!("verify-cli", "{}", host!)?
		for fixture in [
			"http",
			"delegation",
			"redirect",
			"relational",
			"relational-next",
			"collection",
			"owned",
			"owned-probe",
			"repeated-field",
			"reports",
			"reports-probe",
			"reports-deferrals",
			"oncall",
		] {
			_ = Capability.call!("verify-build", Json.to_str({ fixture: fixture }), host!)?
		}
		_ = Capability.call!("verify-lint", "{}", host!)?
		_ = Simulation.campaign!(3_664_912_422, 32, host!)?
		# One Cargo invocation covers the former all-runtime and control package sets.
		# Tests remain serial; the combined allowance preserves their former 9000s + 3600s ceilings.
		_ =
			Capability.call!(
				"verify-tests",
				Json.to_str({ suite: "workspace-runtime", budget_seconds: 12_600.U64 }),
				host!,
			)?
		# The isolated compiler-inference binary measured safe and materially faster
		# with four test threads; its exact cases are skipped by the serial suite.
		_ = Capability.call!("verify-tests", Json.to_str({ suite: "parallel-runtime" }), host!)?
		for suite in ["isolated-build", "installation-build"] {
			_ = Capability.call!("verify-tests", Json.to_str({ suite: suite, budget_seconds: 1800.U64 }), host!)?
		}
		Capability.call!("verify-receipt", Json.to_str({ scope: "all" }), host!)
	}

	control! : (Str => Try(Str, Str)) => Try(Str, Str)
	control! = |host!| {
		_ = Simulation.campaign!(3_664_912_422, 32, host!)?
		_ = Capability.call!("verify-tests", Json.to_str({ suite: "control", budget_seconds: 3600.U64 }), host!)?
		for suite in ["isolated-build", "installation-build"] {
			_ = Capability.call!("verify-tests", Json.to_str({ suite: suite, budget_seconds: 1800.U64 }), host!)?
		}
		Capability.call!("verify-receipt", Json.to_str({ scope: "control" }), host!)
	}
}
