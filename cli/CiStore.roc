import Cli
import Problem
import "fixtures/ci-store-report.json" as golden_report : Str

## `day2 ci store`: the request the CLI hands the platform host and the report the host returns.
CiStore :: [].{

	## One stored object, created only while absent.
	Object : { name : Str, bytes : U64, digest : Str, generation : Str }

	## The host's report (crates/day2-ops/src/ci_store.rs `Report`). The host owns the shape;
	## cli/fixtures/ci-store-report.json pins it for both sides. A run that stored nothing says why and names no bucket,
	## prefix or object.
	Outcome : {
		format : U64,
		repository : Str,
		event : Str,
		run : U64,
		attempt : U64,
		stored : Bool,
		reason : Try(Str, [Null]),
		bucket : Try(Str, [Null]),
		prefix : Try(Str, [Null]),
		objects : List(Object),
	}

	## A decoded report and the host's exact text, which `--agent` output carries verbatim.
	Report : { outcome : Outcome, text : Str }

	## The request the recipe hands the host, which validates it again.
	request : Cli.CiRun -> Str
	request = |run| Json.to_str({ directory: run.parts().directory.to_str() })

	## A report is accepted only in format 1: a push run's stored artifact and its receipt in the bucket, or a reason and
	## nothing.
	report : Str -> Try(Report, [InvalidReport])
	report = |text| {
		parsed : Try(Outcome, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReport)?
		stored = decoded.stored
		explained = decoded.reason.is_ok() != stored
		placed = decoded.bucket.is_ok() == stored and decoded.prefix.is_ok() == stored
		counted = decoded.objects.len() == (if stored 2 else 0)
		# Only main's push run is stored; a pull request run is verified, not stored.
		pushed = !stored or decoded.event == "push"
		if decoded.format == 1 and explained and placed and counted and pushed {
			Ok({ outcome: decoded, text })
		} else {
			Err(InvalidReport)
		}
	}

	## A failed store exits 6 with the host's message, and so fails the required job.
	problem : Str -> Problem
	problem = |error| Problem.CiStoreFailed(error)
}

store : List(Str) -> Try(Cli.CiRun, Problem)
store = |args| match Cli.parse(["ci", "store"].concat(args)) {
	Ok(Cli.Request.CiStore(value)) => Ok(value)
	Ok(_) => Err(Problem.UnknownCommand)
	Err(problem) => Err(problem)
}

# The request names only the run's directory; the inputs come from the CI environment.
expect match store(["/work/ci"]) {
	Ok(value) => CiStore.request(value) == "{\"directory\":\"/work/ci\"}"
	Err(_) => Bool.False
}
expect match Cli.parse(["ci", "store"]) {
	Err(problem) => problem.exit_code() == 2
	Ok(_) => Bool.False
}
expect store(["/work/ci", "--demo"]).is_err()
expect Cli.requested(["ci", "store", "/work/ci"]).name() == "ci.store"

# The host's golden report decodes and keeps its exact text.
expect match CiStore.report(golden_report) {
	Ok(decoded) => decoded.text
		== golden_report
		and decoded.outcome.stored
			and decoded.outcome.objects.map(|object| object.name.ends_with("/receipt.json"))
				== [Bool.False, Bool.True]
	Err(_) => Bool.False
}

# A stored report without its objects, or one that also gives a reason, is refused.
expect CiStore.report(golden_report.replace_first("\"format\": 1", "\"format\": 2")).is_err()
expect CiStore.report(golden_report.replace_first("\"reason\": null", "\"reason\": \"routed\"")).is_err()
expect CiStore.report(golden_report.replace_first("\"stored\": true", "\"stored\": false")).is_err()
expect CiStore.report(golden_report.replace_first("\"event\": \"push\"", "\"event\": \"pull_request\"")).is_err()
expect CiStore.problem("git-oidc refused the token request with HTTP 403").exit_code() == 6
