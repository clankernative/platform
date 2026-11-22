import Cli
import Problem
import InstanceSpec
import "fixtures/source-receipt.json" as golden_receipt : Str

## `day2 instance source`: the request the CLI hands the platform host, rendered from day2.json, and the receipt the
## host returns. The host checks the binding against these derived names: its source server is the forge, its
## repository is in the forge's org, and its app, qualified release and verification cases are the app's in day2.json.
InstanceSource :: [].{

	## A file the host wrote or read.
	File : { path : Str, digest : Str, bytes : U64 }

	## The host's receipt (crates/day2-ops/src/instance_source.rs `Receipt`): what the CLI prints. The host owns the
	## shape; cli/fixtures/source-receipt.json pins it for both sides. Each mode reports only its own fields:
	## - head: the app, its repository and the branch's commit;
	## - archive: the app, repository, commit and the archive written;
	## - controls: the archive read and its CI-control digest;
	## - verify-controls: the app, repository, archive read, its control digest and the release's platform commit;
	## - checked-artifact: the app, repository, commit, archive written, source inputs and the provenance proof.
	Receipt : {
		format : U64,
		mode : Str,
		app_id : Try(Str, [Null]),
		repository : Try(Str, [Null]),
		commit : Try(Str, [Null]),
		archive : Try({ path : Str, digest : Str, bytes : U64 }, [Null]),
		controls : Try(Str, [Null]),
		platform_commit : Try(Str, [Null]),
		source_inputs : Try(Str, [Null]),
		proof : Try(
			{
				version : U64,
				run : U64,
				attempt : U64,
				job : U64,
				receipt : {
					version : U64,
					repository : Str,
					source_commit : Str,
					source_inputs : Str,
					artifact_id : Str,
					sdk_release : { digest : Str, bytes : U64 },
					verification : { version : U64, seed : U64, cases : U64 },
					archive : { digest : Str, bytes : U64 },
					artifact_name : Str,
					examples : U64,
					generated : U64,
					upload_id : U64,
				},
			},
			[Null],
		),
	}

	## A decoded receipt and the host's exact text, which `--agent` output carries verbatim.
	Report : { receipt : Receipt, text : Str }

	## The request a source command hands its recipe. The host validates every field again, refuses a request whose
	## mode differs from the command that started it, and reads the binding file itself.
	request : Try(InstanceSpec, [Null]), Cli.SourceAction -> Str
	request = |loaded, action| {
		none : Try(Str, [Null])
		none = Err(Null)
		instance : Try(
			{
				server : Str,
				org : Str,
				registry : Str,
				bucket : Str,
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
					apps: names.apps.map(|entry| { id: entry.id, sdk: entry.sdk, verification: entry.verification }),
				})
			}
			Err(Null) => Err(Null)
		}
		paths = match action {
			Cli.SourceAction.Head(given) => {
				binding: Ok(given.binding.to_str()),
				commit: none,
				inputs: none,
				archive: none,
				output: none,
			}
			Cli.SourceAction.Archive(given) => {
				binding: Ok(given.binding.to_str()),
				commit: Ok(given.commit),
				inputs: none,
				archive: none,
				output: Ok(given.output.to_str()),
			}
			Cli.SourceAction.Controls(archive) => {
				binding: none,
				commit: none,
				inputs: none,
				archive: Ok(archive.to_str()),
				output: none,
			}
			Cli.SourceAction.VerifyControls(given) => {
				binding: Ok(given.binding.to_str()),
				commit: none,
				inputs: none,
				archive: Ok(given.archive.to_str()),
				output: none,
			}
			Cli.SourceAction.CheckedArtifact(given) => {
				binding: Ok(given.binding.to_str()),
				commit: Ok(given.commit),
				inputs: Ok(given.inputs),
				archive: none,
				output: Ok(given.output.to_str()),
			}
		}
		Json.to_str({
			mode: action.verb(),
			instance,
			binding: paths.binding,
			commit: paths.commit,
			inputs: paths.inputs,
			archive: paths.archive,
			output: paths.output,
		})
	}

	## A receipt is accepted only in format 1, for the command that was run, reporting exactly that mode's fields and
	## the commit and source inputs it was asked for.
	receipt : Str, Cli.SourceAction -> Try(Report, [InvalidReceipt])
	receipt = |text, action| {
		parsed : Try(Receipt, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidReceipt)?
		# Which of app, repository, commit, archive, controls, platform_commit, source_inputs and proof are reported.
		reported = Str.join_with(
			[
				decoded.app_id.is_ok(),
				decoded.repository.is_ok(),
				decoded.commit.is_ok(),
				decoded.archive.is_ok(),
				decoded.controls.is_ok(),
				decoded.platform_commit.is_ok(),
				decoded.source_inputs.is_ok(),
				decoded.proof.is_ok(),
			]
				.map(|present| if present "1" else "0"),
			"",
		)
		matches = match action {
			Cli.SourceAction.Head(_) => reported == "11100000"
			Cli.SourceAction.Archive(given) => reported == "11110000" and decoded.commit == Ok(given.commit)
			Cli.SourceAction.Controls(_) => reported == "00011000"
			Cli.SourceAction.VerifyControls(_) => reported == "11011100"
			Cli.SourceAction.CheckedArtifact(given) => {
				reported
					== "11110011"
					and decoded.commit == Ok(given.commit) and decoded.source_inputs == Ok(given.inputs)
			}
		}
		if decoded.format == 1 and decoded.mode == action.verb() and matches {
			Ok({ receipt: decoded, text })
		} else {
			Err(InvalidReceipt)
		}
	}

	## The problem a failed host run reports: a transient read, which the host marks `retryable: <code>`, exits 7 with
	## its code; anything else is a permanent refusal and exits 6 with the host's message.
	problem : Str -> Problem
	problem = |error| {
		if error.starts_with(retryable) {
			Problem.SourceUnavailable(error.drop_prefix(retryable))
		} else {
			Problem.SourceFailed(error)
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

inputs : Str
inputs = "sha256:abababababababababababababababababababababababababababababababab"

written : Str
written = "/work/ci-artifact.tar.gz"

checked : Str -> Try(Cli.SourceAction, Problem)
checked = |output| match Cli.parse(["instance", "source", "checked-artifact", ".", "b.json", commit, inputs, output]) {
	Ok(Cli.Request.Source(value)) => Ok(value.parts().action)
	Ok(_) => Err(Problem.UnknownCommand)
	Err(problem) => Err(problem)
}

# The request carries the forge, its org, the registry, the bucket and each app's sdk and cases, and only its mode's
# paths.
expect match (InstanceSpec.from_json(sample), checked(written)) {
	(Ok(spec), Ok(action)) => {
		rendered = InstanceSource.request(Ok(spec), action)
		rendered.contains("\"mode\":\"checked-artifact\"")
			and rendered.contains("\"server\":\"https://git.example.com\"")
				and rendered.contains("\"org\":\"tools\"")
					and rendered.contains("\"registry\":\"us-central1-docker.pkg.dev/exampleco-tools\"")
						and rendered.contains("\"bucket\":\"exampleco-tools-tofu-state\"")
							and rendered.contains("\"verification\":4")
								and rendered.contains("\"archive\":null")
									and rendered.contains("\"inputs\":\"${inputs}\"")
	}
	_ => Bool.False
}

# `controls` reads no spec, so its request names no instance.
expect match Cli.parse(["instance", "source", "controls", "source.tar.gz"]) {
	Ok(Cli.Request.Source(value)) => {
		rendered = InstanceSource.request(Err(Null), value.parts().action)
		rendered.contains("\"instance\":null")
			and rendered.contains("\"archive\":\"source.tar.gz\"")
				and rendered.contains("\"binding\":null")
	}
	_ => Bool.False
}

# The host's golden checked-artifact receipt decodes, keeps its exact text and carries the proof's integers exactly.
expect match checked(written) {
	Ok(action) => match InstanceSource.receipt(golden_receipt, action) {
		Ok(report) => match report.receipt.proof {
			Ok(proof) => report.text
				== golden_receipt
				and proof.run
					== 7
					and proof.receipt.upload_id
						== 9_223_372_036_854_775_807
						and report.receipt.archive
							== Ok({
								path: "/work/ci-artifact.tar.gz",
								digest: "sha256:a789e3fa1ffe742748bda51e387abc56427e3e1a35c1d220cf52be0d9a7f6195",
								bytes: 2900,
							})
			Err(_) => Bool.False
		}
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

# A receipt must be the command's own: its mode, its fields, the commit and inputs it was asked for.
expect match checked(written) {
	Ok(action) => {
		other = "fedcba9876543210fedcba9876543210fedcba98"
		changed = golden_receipt.replace_first("\"commit\": \"${commit}\"", "\"commit\": \"${other}\"")
		InstanceSource.receipt(changed, action)
			.is_err()
			and InstanceSource.receipt(
				golden_receipt.replace_first("\"controls\": null", "\"controls\": \"x\""),
				action,
			)
				.is_err()
				and InstanceSource.receipt(golden_receipt.replace_first("\"format\": 1", "\"format\": 2"), action)
					.is_err()
	}
	Err(_) => Bool.False
}
expect match Cli.parse(["instance", "source", "head", ".", "b.json"]) {
	Ok(Cli.Request.Source(value)) => InstanceSource.receipt(golden_receipt, value.parts().action).is_err()
	_ => Bool.False
}

# Only the host's retryable marker exits 7.
expect InstanceSource.problem("retryable: source_temporarily_unavailable").exit_code() == 7
expect InstanceSource.problem("retryable: checked_main_artifact_not_ready").dto().retryable
expect InstanceSource.problem("source_metadata_http_404").exit_code() == 6
expect InstanceSource.problem("source_metadata_http_404").message() == "source_metadata_http_404"
expect !InstanceSource.problem("main CI did not succeed; retry deployment after fixing CI").dto().retryable
