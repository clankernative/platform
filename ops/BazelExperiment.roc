import Capability
import Build

# Measurement-branch workflow only. Application construction keeps the ordinary
# Build recipe; no build or test outcome here is a production verification receipt.
BazelExperiment :: [].{
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
