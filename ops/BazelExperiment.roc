import Capability
import Build

# Measurement-branch workflow only. Application construction keeps the ordinary
# Build recipe; no build or test outcome here is a production verification receipt.
BazelExperiment :: [].{
	timings! : (Str => Try(Str, Str)) => Try(Str, Str)
	timings! = |host!| {
		for backend in ["cargo", "bazel"] {
			if backend == "bazel" {
				_ = Capability.call!("bazel-timing-resources", Json.to_str("before-bazel-build"), host!)?
			}
			for phase in ["cold", "warm-1", "warm-2", "warm-3"] {
				result = Capability.call!("bazel-timing-build", Json.to_str({ backend, phase }), host!)
				observed = if backend == "bazel" {
					Capability.call!("bazel-timing-resources", Json.to_str("after-bazel-build"), host!)
				} else {
					Ok("{}")
				}
				_ = result?
				_ = observed?
			}
		}
		Ok("{}")
	}

	reports! : (Str => Try(Str, Str)) => Try(Str, Str)
	reports! = |host!| {
		report = Build.source!("examples/reports", host!)?
		raw = Capability.call!("bazel-reports-cases", "{}", host!)?
		cases : List(Str)
		cases = Json.parse(raw).map_err(|_| "invalid experiment case inventory")?
		for name in cases {
			_ = Capability.call!("bazel-reports-case", Json.to_str({ artifact: report.artifact, name: name }), host!)?
		}
		Capability.call!("bazel-reports-receipt", "{}", host!)
	}
}
