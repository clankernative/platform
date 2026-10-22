import Capability
import Simulation
import UiDependency

# Platform regression policy, shared by xtask and operator CLI commands.
Verify :: [].{
	cli! : (Str => Try(Str, Str)) => Try(Str, Str)
	cli! = |host!| {
		_ = UiDependency.install!(host!)?
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
		for fixture in ["reports", "reports-probe", "owned", "owned-probe", "repeated-field"] {
			_ = Capability.call!("verify-build", Json.to_str({ fixture: fixture }), host!)?
		}
		_ = Capability.call!("verify-lint", "{}", host!)?
		for suite in ["libraries", "xtask", "operations", "reports-runtime"] {
			_ = Capability.call!("verify-tests", Json.to_str({ suite: suite }), host!)?
		}
		_ = control!(host!)?
		Capability.call!("verify-receipt", Json.to_str({ scope: "reports" }), host!)
	}

	inputs! : (Str => Try(Str, Str)) => Try(Str, Str)
	inputs! = |host!| {
		_ = Capability.call!("verify-format", Json.to_str({ scope: "all" }), host!)?
		_ = Capability.call!("verify-cli", "{}", host!)?
		for fixture in [
			"http",
			"delegation-peer",
			"delegation",
			"credential-metadata",
			"connection-declaration",
			"oauth-calendar",
			"oauth-gitlab",
			"stock-ledger",
			"request-desk",
			"app-ownership",
			"notifications",
			"chart-live",
			"redirect",
			"relational",
			"lifecycle",
			"verification-actors",
			"relational-next",
			"collection",
			"owned",
			"owned-probe",
			"repeated-field",
			"reports",
			"reports-probe",
		] {
			_ = Capability.call!("verify-build", Json.to_str({ fixture: fixture }), host!)?
		}
		_ = Capability.call!("verify-browser", "{}", host!)?
		_ = Capability.call!("verify-lint", "{}", host!)?
		Ok("{}")
	}

	all! : (Str => Try(Str, Str)) => Try(Str, Str)
	all! = |host!| {
		_ = inputs!(host!)?
		_ = Simulation.campaign!(3_664_912_422, 32, host!)?
		# One declared Bazel build covers the former all-runtime and control package sets.
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

	prepare! : (Str => Try(Str, Str)) => Try(Str, Str)
	prepare! = |host!| {
		_ = inputs!(host!)?
		_ = Capability.call!("verify-test-build", "{}", host!)?
		_ = Capability.call!("verify-test-docs", "{}", host!)?
		Capability.call!("verify-prepared", "{}", host!)
	}

	prepare_part! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	prepare_part! = |part, host!| {
		_ = match part {
			"inputs" => inputs!(host!)
			"tests" => {
				_ = Capability.call!("verify-test-build", "{}", host!)?
				Capability.call!("verify-test-docs", "{}", host!)
			}
			_ => Err("unknown verification preparation part")
		}?
		Capability.call!("verify-prepared-part", Json.to_str({ part: part }), host!)
	}

	prepare_join! : (Str => Try(Str, Str)) => Try(Str, Str)
	prepare_join! = |host!| Capability.call!("verify-preparation-join", "{}", host!)

	shard! : Str, (Str => Try(Str, Str)) => Try(Str, Str)
	shard! = |shard, host!| {
		_ = match shard {
			"simulation" => Simulation.campaign!(3_664_912_422, 32, host!)
			"workspace-day2" | "workspace-control" | "workspace-other" =>
				Capability.call!(
					"verify-prebuilt-tests",
					Json.to_str({ suite: shard, budget_seconds: 12_600.U64 }),
					host!,
				)
			"parallel-runtime" => Capability.call!("verify-prebuilt-tests", Json.to_str({ suite: shard }), host!)
			"isolated-build" | "installation-build" =>
				Capability.call!(
					"verify-prebuilt-tests",
					Json.to_str({ suite: shard, budget_seconds: 1800.U64 }),
					host!,
				)
			_ => Err("unknown verification shard")
		}?
		Capability.call!("verify-shard-receipt", Json.to_str({ shard: shard }), host!)
	}

	# One real private build for diagnosis. This publishes no full verification receipt.
	private_build_probe! : (Str => Try(Str, Str)) => Try(Str, Str)
	private_build_probe! = |host!| {
		_ = Capability.call!("verify-cli", "{}", host!)?
		Capability.call!(
			"verify-tests",
			Json.to_str({ suite: "isolated-build-probe", budget_seconds: 1800.U64 }),
			host!,
		)
	}

	# Only native Mac obligations stay here. Portable workspace campaigns run on Linux.
	mac! : (Str => Try(Str, Str)) => Try(Str, Str)
	mac! = |host!| {
		_ = Capability.call!("verify-cli", "{}", host!)?
		for fixture in ["reports", "reports-probe", "relational", "oauth-calendar"] {
			_ = Capability.call!("verify-build", Json.to_str({ fixture: fixture }), host!)?
		}
		_ = Capability.call!("verify-test-build", "{}", host!)?
		_ = Capability.call!("verify-mac-prepared", "{}", host!)?
		_ = Capability.call!("verify-mac-native", "{}", host!)?
		for suite in ["isolated-build", "installation-build"] {
			_ =
				Capability.call!(
					"verify-prebuilt-tests",
					Json.to_str({ suite: suite, budget_seconds: 1800.U64 }),
					host!,
				)?
		}
		Capability.call!("verify-mac-receipt", "{}", host!)
	}

	compose! : (Str => Try(Str, Str)) => Try(Str, Str)
	compose! = |host!| {
		_ = Capability.call!("verify-join", "{}", host!)?
		Capability.call!("verify-receipt", Json.to_str({ scope: "all" }), host!)
	}

	# Mandatory native guards bind authenticated GitHub proof to the exact main
	# checkout. Absence selects the ordinary full workflow; downloaded proof is
	# never executed and every PR/merge-group still runs the full recipe.
	queue_find! : (Str => Try(Str, Str)) => Try(Str, Str)
	queue_find! = |host!| Capability.call!("verify-queue-find", "{}", host!)

	queue_admit! : (Str => Try(Str, Str)) => Try(Str, Str)
	queue_admit! = |host!| Capability.call!("verify-queue-admit", "{}", host!)

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
