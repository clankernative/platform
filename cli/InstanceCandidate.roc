import Cli
import Problem
import InstanceSpec
import "fixtures/candidate-receipt.json" as golden_receipt : Str

## `day2 instance candidate`: the request the CLI hands the platform host, rendered from day2.json, and the receipt the
## host returns. On the build host the request names only the private job directory; the host reads the job's own
## request there.
InstanceCandidate :: [].{

	## A file the host wrote or read.
	File : { path : Str, digest : Str, bytes : U64 }

	## The host's receipt (crates/day2-ops/src/instance_candidate.rs `Receipt`): what the CLI prints. The host owns the
	## shape; cli/fixtures/candidate-receipt.json pins it for both sides. Each mode reports only its own fields:
	## - build: the app, the commit, the outcome (stored, reused or built), the new file holding the candidate
	##   record's bytes, the record, the build log, the image and the artifact, and the copy to the build host when it
	##   built;
	## - check: the app, the commit, the build log, the image and the artifact;
	## - preflight: the app, the commit, the tooling image and the copy to the build host;
	## - native-build: the app, the commit, the slot, result.json, build.log, the image and the artifact;
	## - native-probe: the app and the tooling image.
	Receipt : {
		format : U64,
		mode : Str,
		app_id : Try(Str, [Null]),
		commit : Try(Str, [Null]),
		outcome : Try(Str, [Null]),
		candidate : Try({ path : Str, digest : Str, bytes : U64 }, [Null]),
		record : Try(Str, [Null]),
		build_log : Try(Str, [Null]),
		image : Try(Str, [Null]),
		artifact_id : Try(Str, [Null]),
		tooling_image : Try(Str, [Null]),
		transfer : Try({ bytes : U64, milliseconds : U64 }, [Null]),
		slot : Try(U64, [Null]),
		result : Try({ path : Str, digest : Str, bytes : U64 }, [Null]),
		log : Try({ path : Str, digest : Str, bytes : U64 }, [Null]),
	}

	## A decoded receipt and the host's exact text, which `--agent` output carries verbatim.
	Report : { receipt : Receipt, text : Str }

	## The request a candidate command hands its recipe. The host validates every field again and refuses a request
	## whose mode differs from the command that started it.
	request : Try(InstanceSpec, [Null]), Cli.CandidateAction -> Str
	request = |loaded, action| {
		none : Try(Str, [Null])
		none = Err(Null)
		instance : Try(
			{
				server : Str,
				org : Str,
				registry : Str,
				bucket : Str,
				project : Str,
				zone : Str,
				apply_identity : Str,
				build_host : Str,
				apps : List({ id : Str, sdk : Str, verification : U64 }),
			},
			[Null],
		)
		instance = match loaded {
			Ok(spec) => {
				names = spec.derived()
				Ok({
					server: names.forge_server,
					org: names.forge_org,
					registry: names.artifact_registry,
					bucket: names.tofu_state_bucket,
					project: names.gcp_project,
					zone: names.gcp_zone,
					apply_identity: names.apply_identity,
					build_host: names.build_host.name,
					apps: names.apps.map(|entry| { id: entry.id, sdk: entry.sdk, verification: entry.verification }),
				})
			}
			Err(Null) => Err(Null)
		}
		paths = match action {
			Cli.CandidateAction.Build(given) => {
				binding: Ok(given.binding.to_str()),
				commit: Ok(given.commit),
				app_id: none,
				candidate: none,
				output: Ok(given.output.to_str()),
				job: none,
			}
			Cli.CandidateAction.Preflight(given) => {
				binding: none,
				commit: none,
				app_id: none,
				candidate: Ok(given.candidate.to_str()),
				output: none,
				job: none,
			}
			Cli.CandidateAction.Check(given) => {
				binding: none,
				commit: none,
				app_id: Ok(given.app_id),
				candidate: Ok(given.candidate.to_str()),
				output: none,
				job: none,
			}
			Cli.CandidateAction.NativeBuild(job) | Cli.CandidateAction.NativeProbe(job) => {
				binding: none,
				commit: none,
				app_id: none,
				candidate: none,
				output: none,
				job: Ok(job.to_str()),
			}
		}
		Json.to_str({
			mode: action.verb(),
			instance,
			binding: paths.binding,
			commit: paths.commit,
			app_id: paths.app_id,
			candidate: paths.candidate,
			output: paths.output,
			job: paths.job,
		})
	}

	## A receipt is accepted only in format 1, for the command that was run, reporting exactly that mode's fields.
	## A build's copy to the build host is reported only when it built.
	receipt : Str, Cli.CandidateAction -> Try(Report, [InvalidReceipt])
	receipt = |text, action| {
		parsed : Try(Receipt, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReceipt)?
		# Which of app, commit, outcome, candidate, record, build_log, image, artifact_id, tooling_image, slot, result
		# and log are reported.
		reported = Str.join_with(
			[
				decoded.app_id.is_ok(),
				decoded.commit.is_ok(),
				decoded.outcome.is_ok(),
				decoded.candidate.is_ok(),
				decoded.record.is_ok(),
				decoded.build_log.is_ok(),
				decoded.image.is_ok(),
				decoded.artifact_id.is_ok(),
				decoded.tooling_image.is_ok(),
				decoded.slot.is_ok(),
				decoded.result.is_ok(),
				decoded.log.is_ok(),
			]
				.map(|present| if present "1" else "0"),
			"",
		)
		matches = match action {
			Cli.CandidateAction.Build(given) => {
				reported
					== "111111110000"
					and decoded.commit == Ok(given.commit)
						and decoded.transfer.is_ok() == (decoded.outcome == Ok("built"))
			}
			Cli.CandidateAction.Check(given) => {
				reported == "110001110000" and decoded.app_id == Ok(given.app_id) and decoded.transfer.is_err()
			}
			Cli.CandidateAction.Preflight(_) => reported == "110000001000" and decoded.transfer.is_ok()
			Cli.CandidateAction.NativeBuild(_) => reported == "110000110111" and decoded.transfer.is_err()
			Cli.CandidateAction.NativeProbe(_) => reported == "100000001000" and decoded.transfer.is_err()
		}
		if decoded.format == 1 and decoded.mode == action.verb() and matches {
			Ok({ receipt: decoded, text })
		} else {
			Err(InvalidReceipt)
		}
	}

	## The problem a failed host run reports: a transient forge read, which the host marks `retryable: <code>`, exits 7
	## with its code; anything else is a permanent refusal and exits 6 with the host's message.
	problem : Str -> Problem
	problem = |error| {
		if error.starts_with(retryable) {
			Problem.SourceUnavailable(error.drop_prefix(retryable))
		} else {
			Problem.CandidateFailed(error)
		}
	}
}

retryable : Str
retryable = "retryable: "

sample : Str
sample =
	\\{"kind":"instance","version":1,"installation":"exampleco",
	\\"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
	\\"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com"],
	\\"apps":{"links":{"sdk":"sha256:1cf71b18b153b05c89206328b10f81c9a672aa7317a122c25ba41fead2669f01",
	\\"delivery":"automatic","extension":null,"owners":["ada@example.com"],"size":"standard","verification":4,
	\\"schedules":"enabled"}}}

commit : Str
commit = "0123456789abcdef0123456789abcdef01234567"

written : Str
written = "/work/candidate.json"

built : Str -> Try(Cli.CandidateAction, Problem)
built = |output| match Cli.parse(["instance", "candidate", "build", ".", "b.json", commit, output]) {
	Ok(Cli.Request.Candidate(value)) => Ok(value.parts().action)
	Ok(_) => Err(Problem.UnknownCommand)
	Err(problem) => Err(problem)
}

# The request carries the forge, its org, the registry, the bucket, the project, zone, apply identity and build host
# and each app's sdk and cases, and only its mode's paths.
expect match (InstanceSpec.from_json(sample), built(written)) {
	(Ok(spec), Ok(action)) => {
		rendered = InstanceCandidate.request(Ok(spec), action)
		rendered.contains("\"mode\":\"build\"")
			and rendered.contains("\"server\":\"https://git.example.com\"")
				and rendered.contains("\"registry\":\"us-central1-docker.pkg.dev/exampleco-tools\"")
					and rendered.contains("\"bucket\":\"exampleco-tools-tofu-state\"")
						and rendered.contains("\"zone\":\"us-central1-a\"")
							and rendered
								.contains("\"apply_identity\":\"tools-infra@exampleco-tools.iam.gserviceaccount.com\"")
								and rendered.contains("\"build_host\":\"day2-x86-qualify\"")
									and rendered.contains("\"job\":null")
										and rendered.contains("\"commit\":\"${commit}\"")
	}
	_ => Bool.False
}

# The build host's commands read no spec, so their request names no instance, only the job.
expect match Cli.parse(["instance", "candidate", "native-build", "/tmp/day2-build-job"]) {
	Ok(Cli.Request.Candidate(value)) => {
		rendered = InstanceCandidate.request(Err(Null), value.parts().action)
		rendered.contains("\"instance\":null")
			and rendered.contains("\"job\":\"/tmp/day2-build-job\"")
				and rendered.contains("\"mode\":\"native-build\"")
	}
	_ => Bool.False
}

# The host's golden build receipt decodes and keeps its exact text.
expect match built(written) {
	Ok(action) => match InstanceCandidate.receipt(golden_receipt, action) {
		Ok(report) => report.text
			== golden_receipt
			and report.receipt.outcome
				== Ok("built")
				and report.receipt.candidate.map_ok(|file| file.path) == Ok("/work/candidate.json")
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

# A receipt must be the command's own: its mode, its fields and the commit it was asked for.
expect match built(written) {
	Ok(action) => {
		other = "fedcba9876543210fedcba9876543210fedcba98"
		changed = golden_receipt.replace_first("\"commit\": \"${commit}\"", "\"commit\": \"${other}\"")
		InstanceCandidate.receipt(changed, action)
			.is_err()
			and InstanceCandidate.receipt(golden_receipt.replace_first("\"slot\": null", "\"slot\": 1"), action)
				.is_err()
				and InstanceCandidate.receipt(golden_receipt.replace_first("\"format\": 1", "\"format\": 2"), action)
					.is_err()
					and InstanceCandidate.receipt(
						golden_receipt.replace_first("\"outcome\": \"built\"", "\"outcome\": \"reused\""),
						action,
					)
						.is_err()
	}
	Err(_) => Bool.False
}
expect match Cli.parse(["instance", "candidate", "check", ".", "links", "c.json"]) {
	Ok(Cli.Request.Candidate(value)) => InstanceCandidate.receipt(golden_receipt, value.parts().action).is_err()
	_ => Bool.False
}

# Only the host's retryable marker exits 7.
expect InstanceCandidate.problem("retryable: source_temporarily_unavailable").exit_code() == 7
expect InstanceCandidate.problem("retryable: checked_main_artifact_not_ready").dto().retryable
expect InstanceCandidate.problem("builder returned another source or toolchain").exit_code() == 6
expect InstanceCandidate.problem("native build pool wait budget exhausted").message()
	== "native build pool wait budget exhausted"
expect !InstanceCandidate.problem("release belongs to another app").dto().retryable
