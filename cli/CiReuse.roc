import Cli
import Problem
import "fixtures/ci-reuse-report.json" as golden_report : Str

## `day2 ci reuse`: the request the CLI hands the platform host and the report the host returns.
CiReuse :: [].{

	## One object of the reused attempt, as the bucket described it.
	Object : { name : Str, generation : Str, time_created : Str }

	## The stored attempt a result was reused from: its run and attempt as the forge reported them, the commit it
	## checked and its two objects.
	Source : {
		run : U64,
		attempt : U64,
		head : Str,
		workflow_commit : Str,
		started_at : Str,
		completed_at : Str,
		bucket : Str,
		receipt : Object,
		artifact : Object,
	}

	## `DIRECTORY/reuse/reuse.json` (crates/day2-ops/src/ci_reuse.rs `Record`): a reused result's source, or why nothing
	## was reused. `ci check --reuse` reads it and reports it.
	Record : { format : U64, reused : Bool, reason : Try(Str, [Null]), source : Try(Source, [Null]) }

	## One stored attempt the lookup tried, newest first, and why it was refused.
	Tried : { run : U64, attempt : U64, accepted : Bool, reason : Try(Str, [Null]) }

	## The host's report (crates/day2-ops/src/ci_reuse.rs `Report`). The host owns the shape;
	## cli/fixtures/ci-reuse-report.json pins it for both sides. A run that reused nothing says why.
	Outcome : {
		format : U64,
		repository : Str,
		event : Str,
		run : U64,
		attempt : U64,
		reused : Bool,
		reason : Try(Str, [Null]),
		bucket : Try(Str, [Null]),
		key : Try(Str, [Null]),
		listed : U64,
		tried : List(Tried),
		source : Try(Source, [Null]),
		output : Try(Str, [Null]),
	}

	## A decoded report and the host's exact text, which `--agent` output carries verbatim.
	Report : { outcome : Outcome, text : Str }

	## The request the recipe hands the host, which validates it again.
	request : Cli.CiReuseRequest -> Str
	request = |reuse| {
		parts = reuse.parts()
		Json.to_str({ directory: parts.directory.to_str(), cases: parts.cases })
	}

	## A report is accepted only in format 1: a push run's reused result with its source and the one accepted attempt,
	## or a reason; a push run always names its output directory, a pull request run never does.
	report : Str -> Try(Report, [InvalidReport])
	report = |text| {
		parsed : Try(Outcome, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReport)?
		push = decoded.event == "push"
		explained = decoded.reason.is_ok() != decoded.reused
		sourced = decoded.source.is_ok() == decoded.reused
		# Only main's push run reuses, and only it writes DIRECTORY/reuse for ci check.
		pushed = !decoded.reused or push
		written = decoded.output.is_ok() == push
		accepted = decoded.tried.keep_if(|tried| tried.accepted).len() == (if decoded.reused 1 else 0)
		if decoded.format == 1 and explained and sourced and pushed and written and accepted {
			Ok({ outcome: decoded, text })
		} else {
			Err(InvalidReport)
		}
	}

	## A failed reuse, which is misconfiguration, exits 6 with the host's message. A lookup that found nothing, read
	## transiently or ran out of time is a success that says why.
	problem : Str -> Problem
	problem = |error| Problem.CiReuseFailed(error)
}

reuse : List(Str) -> Try(Cli.CiReuseRequest, Problem)
reuse = |args| match Cli.parse(["ci", "reuse"].concat(args)) {
	Ok(Cli.Request.CiReuse(value)) => Ok(value)
	Ok(_) => Err(Problem.UnknownCommand)
	Err(problem) => Err(problem)
}

# The request names the run's directory and the instance's case count; the inputs come from the CI environment.
expect match reuse(["/work/ci", "6"]) {
	Ok(value) => CiReuse.request(value) == "{\"cases\":6,\"directory\":\"/work/ci\"}"
	Err(_) => Bool.False
}
expect match Cli.parse(["ci", "reuse", "/work/ci"]) {
	Err(problem) => problem.exit_code() == 2
	Ok(_) => Bool.False
}
expect reuse(["/work/ci", "3"]).is_err()
expect reuse(["/work/ci", "six"]).is_err()
expect reuse(["/work/ci", "6", "extra"]).is_err()
expect reuse(["/work/ci", "6", "--demo"]).is_err()
expect reuse(["--reuse", "/work/ci/reuse", "/work/ci", "6"]).is_err()
expect Cli.requested(["ci", "reuse", "/work/ci", "6"]).name() == "ci.reuse"
expect match reuse(["/work/ci", "6"]) {
	Ok(value) => Cli.arguments(Cli.Request.CiReuse(value)) == ["day2", "ci", "reuse", "/work/ci", "6"]
	Err(_) => Bool.False
}

# The host's golden report decodes and keeps its exact text.
expect match CiReuse.report(golden_report) {
	Ok(decoded) => match decoded.outcome.source {
		Ok(source) => decoded.text
			== golden_report
			and source.run
				== 39
				and decoded.outcome.tried.map(|tried| tried.accepted)
					== [Bool.False, Bool.True]
					and decoded.outcome.output
						== Ok("/tmp/day2-ci/reuse")
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

# A reuse without its source or with a reason, a pull request that reused, a push without its output, two accepted
# attempts and a miss that still names a source are refused.
expect CiReuse.report(golden_report.replace_first("\"format\": 1", "\"format\": 2")).is_err()
expect CiReuse.report(
	golden_report.replace_first("\"reason\": null,\n  \"bucket\"", "\"reason\": \"x\",\n  \"bucket\""),
)
	.is_err()
expect CiReuse.report(golden_report.replace_first("\"event\": \"push\"", "\"event\": \"pull_request\"")).is_err()
expect CiReuse.report(golden_report.replace_first("\"output\": \"/tmp/day2-ci/reuse\"", "\"output\": null")).is_err()
expect CiReuse.report(golden_report.replace_first("\"accepted\": false", "\"accepted\": true")).is_err()
expect {
	missed =
		golden_report
			.replace_first("\"reused\": true", "\"reused\": false")
			.replace_first("\"reason\": null,\n  \"bucket\"", "\"reason\": \"absent\",\n  \"bucket\"")
			.replace_first("\"accepted\": true", "\"accepted\": false")
	CiReuse.report(missed).is_err()
}

# A miss says why; a pull request run names no output directory.
miss =
	\\{"format": 1, "repository": "tools/links", "event": "push", "run": 41, "attempt": 2, "reused": false,
	\\"reason": "no earlier push run on main stored a result under this key", "bucket": "exampleco-tools-links-ci",
	\\"key": null, "listed": 0, "tried": [], "source": null, "output": "/tmp/day2-ci/reuse"}

expect CiReuse.report(miss).is_ok()
expect CiReuse.report(miss.replace_first("\"event\": \"push\"", "\"event\": \"pull_request\"")).is_err()
expect CiReuse.report(miss.replace_first("\"reason\": \"no earlier", "\"reason\": null, \"x\": \"")).is_err()
expect CiReuse.problem("ci reuse runs once per run").exit_code() == 6
