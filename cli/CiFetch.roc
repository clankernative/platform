import Cli
import Problem
import "fixtures/ci-fetch-report.json" as golden_report : Str

## `day2 ci fetch`: the request the CLI hands the platform host and the report the host returns.
CiFetch :: [].{

	## `DIRECTORY/event.json`: the run `day2 ci store` records and stores under.
	Event : {
		format : U64,
		repository : Str,
		repository_id : U64,
		event : Str,
		head : Str,
		base : Try(Str, [Null]),
		pull_request : Try(U64, [Null]),
		run : U64,
		attempt : U64,
		workflow_commit : Try(Str, [Null]),
	}

	## One tree the host wrote: the commit's Gitea archive, unpacked.
	Tree : {
		path : Str,
		commit : Str,
		archive : { digest : Str, bytes : U64 },
		files : U64,
		bytes : U64,
		directories : U64,
		links : U64,
	}

	## The host's report (crates/day2-ops/src/ci_fetch.rs `Report`). The host owns the shape;
	## cli/fixtures/ci-fetch-report.json pins it for both sides.
	Outcome : {
		format : U64,
		directory : Str,
		event : Event,
		head : Tree,
		base : Try(Tree, [Null]),
		source_inputs : Str,
	}

	## A decoded report and the host's exact text, which `--agent` output carries verbatim.
	Report : { outcome : Outcome, text : Str }

	## The request the recipe hands the host, which validates it again.
	request : Cli.CiRun -> Str
	request = |run| Json.to_str({ directory: run.parts().directory.to_str() })

	## A report is accepted only in format 1, for a pull request with its merge base tree or a push without one.
	report : Str -> Try(Report, [InvalidReport])
	report = |text| {
		parsed : Try(Outcome, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReport)?
		event = decoded.event
		pull = event.event == "pull_request"
		known = pull or event.event == "push"
		based = event.base.is_ok() == pull
		numbered = event.pull_request.is_ok() == pull
		fetched = decoded.base.is_ok() == pull
		if decoded.format == 1 and event.format == 1 and known and based and numbered and fetched {
			Ok({ outcome: decoded, text })
		} else {
			Err(InvalidReport)
		}
	}

	## A failed fetch exits 6 with the host's message; a forge read that stayed transient exits 7, as `instance source` does.
	problem : Str -> Problem
	problem = |error| {
		retryable = "retryable: "
		if error.starts_with(retryable) {
			Problem.CiFetchUnavailable(error.drop_prefix(retryable))
		} else {
			Problem.CiFetchFailed(error)
		}
	}
}

fetch : List(Str) -> Try(Cli.CiRun, Problem)
fetch = |args| match Cli.parse(["ci", "fetch"].concat(args)) {
	Ok(Cli.Request.CiFetch(value)) => Ok(value)
	Ok(_) => Err(Problem.UnknownCommand)
	Err(problem) => Err(problem)
}

# The request names only the new directory; the run comes from the CI environment.
expect match fetch(["/work/ci"]) {
	Ok(value) => CiFetch.request(value) == "{\"directory\":\"/work/ci\"}"
	Err(_) => Bool.False
}
expect match Cli.parse(["ci", "fetch"]) {
	Err(problem) => problem.exit_code() == 2
	Ok(_) => Bool.False
}
expect fetch(["/work/ci", "extra"]).is_err()
expect Cli.requested(["ci", "fetch", "/work/ci"]).name() == "ci.fetch"

# The host's golden report decodes and keeps its exact text.
expect match CiFetch.report(golden_report) {
	Ok(decoded) => decoded.text
		== golden_report
		and decoded.outcome.event.pull_request
			== Ok(9)
			and decoded.outcome.head.files
				== 5
				and decoded.outcome.event.workflow_commit
					== Ok("3333333333333333333333333333333333333333")
	Err(_) => Bool.False
}

# A report in another format, or a pull request without its base tree, is refused.
expect CiFetch.report(golden_report.replace_first("\"format\": 1", "\"format\": 2")).is_err()
expect CiFetch.report(golden_report.replace_first("\"event\": \"pull_request\"", "\"event\": \"push\"")).is_err()
expect CiFetch.problem("app CI runs only for pull_request and push events").exit_code() == 6
# A forge read that stayed transient exits 7 and is retryable, as an `instance source` read is.
expect CiFetch.problem("retryable: source_temporarily_unavailable").exit_code() == 7
expect CiFetch.problem("retryable: source_temporarily_unavailable").dto().retryable
expect CiFetch.problem("retryable: source_temporarily_unavailable").dto().message == "source_temporarily_unavailable"
