import Cli
import CiReuse
import Problem
import "fixtures/ci-check-report.json" as golden_report : Str

## `day2 ci check`: the request the CLI hands the platform host and the report the host returns.
CiCheck :: [].{

	## `receipt.json`, beside `app.tar.gz` in the output directory.
	Receipt : {
		version : U64,
		source_inputs : Str,
		artifact_id : Str,
		sdk_distribution : { digest : Str, bytes : U64 },
		verification : { version : U64, seed : U64, cases : U64 },
		archive : { digest : Str, bytes : U64 },
		examples : U64,
		generated : U64,
		lanes : List(Str),
	}

	## The host's report (crates/day2-ops/src/ci_check.rs `Report`): what the CLI prints. The host owns the shape;
	## cli/fixtures/ci-check-report.json pins it for both sides. A lane that did not run reports null. `artifact` says what
	## became of the artifact: `not_built`, `routed` (a routed run skipped a lane), `no_sdk_identity`, `written` or
	## `reused` (an earlier main run's result, verified again instead of built); the output directory and its receipt
	## exist only once written or reused. `reuse` is `ci reuse`'s record when `--reuse` named one.
	Outcome : {
		format : U64,
		lanes : List(Str),
		base : Bool,
		changed : U64,
		reasons : List({ path : Str, change : Str, lanes : List(Str), rules : List(Str) }),
		javascript_files : Try(U64, [Null]),
		roc_files : Try(U64, [Null]),
		extension_declared : Try(Bool, [Null]),
		source_inputs : Str,
		artifact : Str,
		output : Try(Str, [Null]),
		receipt : Try(Receipt, [Null]),
		reuse : Try(CiReuse.Record, [Null]),
	}

	## A decoded report and the host's exact text, which `--agent` output carries verbatim.
	Report : { outcome : Outcome, text : Str }

	## The request the recipe hands the host, which validates it again.
	request : Cli.CiCheckRequest -> Str
	request = |check| {
		parts = check.parts()
		base : Try(Str, [Null])
		base = parts.base.map_ok(|path| path.to_str())
		reuse : Try(Str, [Null])
		reuse = parts.reuse.map_ok(|path| path.to_str())
		Json.to_str({ head: parts.head.to_str(), base, cases: parts.cases, output: parts.output.to_str(), reuse })
	}

	## A report is accepted only in format 1, with an output directory and a receipt exactly when the artifact was written
	## or reused, and a reused artifact only with the record of the result `ci reuse` reused.
	report : Str -> Try(Report, [InvalidReport])
	report = |text| {
		parsed : Try(Outcome, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReport)?
		written = ["written", "reused"].contains(decoded.artifact)
		known = ["not_built", "routed", "no_sdk_identity", "written", "reused"].contains(decoded.artifact)
		recorded = match decoded.reuse {
			Ok(record) => record.reused
			Err(Null) => Bool.False
		}
		reused = (decoded.artifact == "reused") == recorded
		if
			decoded.format == 1
				and known and reused and decoded.output.is_ok() == written and decoded.receipt.is_ok() == written
				{
					Ok({ outcome: decoded, text })
				} else {
					Err(InvalidReport)
				}
	}

	## A failed check exits 6 with the host's message: the failing lane's findings or the refusal.
	problem : Str -> Problem
	problem = |error| Problem.CiCheckFailed(error)
}

check : List(Str) -> Try(Cli.CiCheckRequest, Problem)
check = |args| match Cli.parse(["ci", "check"].concat(args)) {
	Ok(Cli.Request.CiCheck(value)) => Ok(value)
	Ok(_) => Err(Problem.UnknownCommand)
	Err(problem) => Err(problem)
}

# Without a base tree the request says so; the host then runs every lane.
expect match check(["head", "4", "out"]) {
	Ok(value) => CiCheck.request(value)
		== "{\"base\":null,\"cases\":4,\"head\":\"head\",\"output\":\"out\",\"reuse\":null}"
	Err(_) => Bool.False
}
expect match check(["head", "base", "6", "out"]) {
	Ok(value) => CiCheck.request(value).contains("\"base\":\"base\"") and CiCheck.request(value).contains("\"cases\":6")
	Err(_) => Bool.False
}

# The case count is the instance's verification: an integer from 4 to 100.
expect check(["head", "3", "out"]).is_err()
expect check(["head", "101", "out"]).is_err()
expect check(["head", "four", "out"]).is_err()
expect match Cli.parse(["ci", "check", "head"]) {
	Err(problem) => problem.exit_code() == 2
	Ok(_) => Bool.False
}

# The host's golden report decodes and keeps its exact text.
expect match CiCheck.report(golden_report) {
	Ok(decoded) => match decoded.outcome.receipt {
		Ok(receipt) => decoded.text
			== golden_report
			and receipt.verification
				== { version: 1, seed: 42, cases: 4 }
				and receipt.archive.bytes
					== 2900
					and decoded.outcome.lanes
						== ["native", "extension", "javascript"]
						and decoded.outcome.output
							== Ok("/work/ci")
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

# A report in another format, or with a receipt but no output directory, is refused.
expect CiCheck.report(golden_report.replace_first("\"format\": 1", "\"format\": 2")).is_err()
expect CiCheck.report(golden_report.replace_first("\"output\": \"/work/ci\"", "\"output\": null")).is_err()
expect CiCheck.report(golden_report.replace_first("\"artifact\": \"written\"", "\"artifact\": \"routed\"")).is_err()
expect CiCheck.report(golden_report.replace_first("\"artifact\": \"written\"", "\"artifact\": \"maybe\"")).is_err()
# A push run names ci reuse's directory; a run with a base tree never reuses, and only ci check takes --reuse.
expect match check(["--reuse", "/work/ci/reuse", "head", "6", "out"]) {
	Ok(value) => CiCheck.request(value).contains("\"reuse\":\"/work/ci/reuse\"")
		and Cli.arguments(Cli.Request.CiCheck(value))
			== ["day2", "ci", "check", "--reuse", "/work/ci/reuse", "head", "6", "out"]
	Err(_) => Bool.False
}
expect check(["head", "6", "out", "--reuse=/work/ci/reuse"]).is_ok()
expect check(["--reuse", "/work/ci/reuse", "head", "base", "6", "out"]).is_err()
expect check(["--reuse", "a", "--reuse", "b", "head", "6", "out"]).is_err()
expect check(["--reuse"]).is_err()
expect Cli.parse(["ci", "store", "/work/ci", "--reuse", "/work/ci/reuse"]).is_err()
expect Cli.parse(["instance", "check", "dir", "--reuse", "/work/ci/reuse"]).is_err()

# A reused artifact decodes only with the record of the result it reused.
reused_record =
	\\{"format": 1, "reused": true, "reason": null, "source": {"run": 39, "attempt": 1,
	\\"head": "4444444444444444444444444444444444444444", "workflow_commit": "3333333333333333333333333333333333333333",
	\\"started_at": "2026-11-25T18:00:00Z", "completed_at": "2026-11-25T18:20:00Z", "bucket": "exampleco-tools-links-ci",
	\\"receipt": {"name": "a/b-4/39/1/receipt.json", "generation": "2", "time_created": "2026-11-25T18:15:00Z"},
	\\"artifact": {"name": "a/b-4/39/1/artifact.tar.gz", "generation": "1", "time_created": "2026-11-25T18:15:00Z"}}}

reused_report = golden_report
	.replace_first("\"artifact\": \"written\"", "\"artifact\": \"reused\"")
	.replace_first("\"reuse\": null", "\"reuse\": ${reused_record}")

expect match CiCheck.report(reused_report) {
	Ok(decoded) => match decoded.outcome.reuse {
		Ok(record) => record.reused and record.source.map_ok(|source| source.run) == Ok(39)
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}
expect CiCheck.report(golden_report.replace_first("\"artifact\": \"written\"", "\"artifact\": \"reused\"")).is_err()
expect CiCheck.report(reused_report.replace_first("\"artifact\": \"reused\"", "\"artifact\": \"written\"")).is_err()
expect CiCheck.problem("1 JavaScript finding(s)").exit_code() == 6
