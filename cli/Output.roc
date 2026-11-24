import Cli
import Catalog
import Source
import Problem
import Names
import InstanceSpec
import InstanceRender
import InstanceRelease
import InstanceSource
import InstanceCandidate

## Status, error, stream, and exit code are projections of one closed outcome.
Output :: { outcome : Outcome }.{
	Outcome := [
		Help(Cli.Format),
		Version(Cli.Format),
		Described(Source),
		Checked(Cli.Instance, Names.LocalPath, InstanceSpec),
		Rendered(Cli.Instance, Names.LocalPath, InstanceSpec),
		Ran(Cli.Roots, Names.LocalPath, InstanceSpec, InstanceRender.Receipt),
		Released(Cli.Release, Names.LocalPath, InstanceSpec, InstanceRelease.Report),
		Sourced(Cli.SourceRequest, Try(Names.LocalPath, [Null]), InstanceSource.Report),
		Candidated(Cli.CandidateRequest, Try(Names.LocalPath, [Null]), InstanceCandidate.Report),
		Failed(Problem, Cli.Format, Cli.Command),
	]

	version = "0.3.0-spike"

	new : Outcome -> Output
	new = |outcome| { outcome: outcome }

	exit_code : Output -> I32
	exit_code = |response| match response.outcome {
		Outcome.Failed(problem, _, _) => problem.exit_code()
		# A root that failed or was refused fails the command, as a run that cannot start does.
		Outcome.Ran(request, _, _, receipt) => if receipt.ok 0 else roots_failed(request.parts().mode, "").exit_code()
		_ => 0
	}

	stream : Output -> [Stdout, Stderr]
	stream = |response| match response.outcome {
		Outcome.Failed(_, Cli.Format.Text, _) => Stderr
		_ => Stdout
	}

	body : Output -> Str
	body = |response| match format(response.outcome) {
		Cli.Format.Json => json(response.outcome)
		Cli.Format.Text => match response.outcome {
			Outcome.Help(_) => Cli.help
			Outcome.Version(_) => "day2 ${version}"
			Outcome.Described(loaded) => description_text(loaded)
			Outcome.Checked(request, path, spec) => checked_text(request, path, spec)
			Outcome.Rendered(request, path, spec) => rendered_text(request, path, spec)
			Outcome.Ran(request, path, spec, receipt) => ran_text(request, path, spec, receipt)
			Outcome.Released(request, path, spec, receipt) => released_text(request, path, spec, receipt)
			Outcome.Sourced(request, path, report) => sourced_text(request, path, report)
			Outcome.Candidated(request, path, report) => candidated_text(request, path, report)
			Outcome.Failed(problem, _, _) => error_text(problem)
		}
	}

	## The problem a failed `instance plan` or `apply` reports.
	roots_failed : InstanceRender.Mode, Str -> Problem
	roots_failed = |mode, detail| match mode {
		InstanceRender.Mode.Plan => Problem.PlanFailed(detail)
		InstanceRender.Mode.Apply(_) | InstanceRender.Mode.Deploy => Problem.ApplyFailed(detail)
	}

	safe : Str -> Str
	safe = |value| Str.from_utf8_lossy(value.to_utf8().map(|byte| if byte < 32 or byte == 127 63 else byte))

	wrap : Str, Str -> Str
	wrap =
		|
			value,
			indent,
		|
			Str.join_with(
				wrap_words(safe(value).split_on(" ").keep_if(|word| !word.is_empty()), indent, indent, []),
				"\n",
			)
}

format : Output.Outcome -> Cli.Format
format = |outcome| match outcome {
	Output.Outcome.Help(value) | Output.Outcome.Version(value) | Output.Outcome.Failed(_, value, _) => value
	Output.Outcome.Described(loaded) => loaded.request().parts().format
	Output.Outcome.Checked(request, _, _) | Output.Outcome.Rendered(request, _, _) => request.parts().format
	Output.Outcome.Ran(request, _, _, _) => request.parts().format
	Output.Outcome.Released(request, _, _, _) => request.parts().format
	Output.Outcome.Sourced(request, _, _) => request.parts().format
	Output.Outcome.Candidated(request, _, _) => request.parts().format
}

next_actions : Source -> List(Cli.Action)
next_actions = |loaded| {
	request = loaded.request()
	parts = request.parts()
	format_action = Cli.Action.new(
		match parts.format {
			Cli.Format.Json => "Read the same catalog as detailed text."
			Cli.Format.Text => "Get the same result as structured JSON."
		},
		Cli.Request.Describe(
			request.with_format(
				match parts.format {
					Cli.Format.Json => Cli.Format.Text
					Cli.Format.Text => Cli.Format.Json
				},
			),
		),
	)
	detail_action = match parts.filter {
		Cli.Filter.All => match loaded.view().names().first() {
			Ok(name) => [
				Cli.Action.new(
					"Focus on ${name.to_str()} and its input contract.",
					Cli.Request.Describe(request.with_filter(Cli.Filter.One(name))),
				),
			]
			Err(_) => []
		}
		Cli.Filter.One(_) => [
			Cli.Action.new(
				"Return to the complete operation catalog.",
				Cli.Request.Describe(request.with_filter(Cli.Filter.All)),
			),
		]
	}
	[format_action].concat(detail_action)
}

help_action : {} -> Cli.Action
help_action = |_| Cli.Action.new("Read command usage and supported options.", Cli.Request.Help(Cli.Format.Json))

demo_actions : List(Str) -> List(Cli.Action)
demo_actions = |args| match Cli.parse(args) {
	Ok(request) => [Cli.Action.new("Explore the bundled Links app.", request)]
	Err(_) => [help_action({})]
}

json : Output.Outcome -> Str
json = |outcome| match outcome {
	Output.Outcome.Described(loaded) => success_json(loaded)
	Output.Outcome.Checked(request, path, spec) => checked_json(request, path, spec)
	Output.Outcome.Rendered(request, path, spec) => rendered_json(request, path, spec)
	Output.Outcome.Ran(request, path, spec, receipt) => ran_json(request, path, spec, receipt)
	Output.Outcome.Released(request, path, spec, receipt) => released_json(request, path, spec, receipt)
	Output.Outcome.Sourced(request, path, report) => sourced_json(request, path, report)
	Output.Outcome.Candidated(request, path, report) => candidated_json(request, path, report)
	Output.Outcome.Failed(problem, _, command) => error_json(problem, command)
	Output.Outcome.Help(_) => info_json(Bool.True)
	Output.Outcome.Version(_) => info_json(Bool.False)
}

success_json : Source -> Str
# Keep the wire record concrete here: this compiler nightly crashes deriving
# a nested encoder directly from Source.ResultDto. Trusted values still enter
# exclusively through Source; the projection only copies presentation fields.
success_json = |loaded| {
	result = loaded.result_dto()
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: "app.describe",
		exit_code: 0.I32,
		context: loaded.context_dto(),
		result: {
			app_name: result.app_name,
			description: result.description,
			operation_count: result.operation_count,
			total_operations: result.total_operations,
			example_note: result.example_note,
			operations: result
				.operations
				.map(
					|
						operation,
					|
						{
							name: operation.name,
							kind: operation.kind,
							effect: operation.effect,
							description: operation.description,
							description_source: operation.description_source,
							input_type: operation.input_type,
							output_type: operation.output_type,
							example_input_json: operation.example_input_json,
							input_fields: operation
								.input_fields
								.map(
									|
										field,
									|
										{
											name: field.name,
											json_type: field.json_type,
											roc_type: field.roc_type,
											required: field.required,
											nullable: field.nullable,
											description: field.description,
										},
								),
						},
				),
		},
		error: null,
		next_actions: next_actions(loaded).map(|action| action.dto()),
	})
}

check_actions : Cli.Instance -> List(Cli.Action)
check_actions = |request| [
	Cli.Action.new(
		match request.parts().format {
			Cli.Format.Json => "Read the same derived names as text."
			Cli.Format.Text => "Get the same derived names as structured JSON."
		},
		Cli.Request.Check(toggled(request)),
	),
	Cli.Action.new("Render the OpenTofu inputs this spec implies.", Cli.Request.Render(request)),
]

render_actions : Cli.Instance -> List(Cli.Action)
render_actions = |request| [
	Cli.Action.new(
		match request.parts().format {
			Cli.Format.Json => "Read the same OpenTofu inputs as text."
			Cli.Format.Text => "Get the same OpenTofu inputs as structured JSON."
		},
		Cli.Request.Render(toggled(request)),
	),
	Cli.Action.new("Validate the spec and list every derived name.", Cli.Request.Check(request)),
]

roots_actions : Cli.Roots -> List(Cli.Action)
roots_actions = |request| [
	Cli.Action.new(
		"Show the rendered backends and variables this ${request.parts().mode.name()} used.",
		Cli.Request.Render(request.instance()),
	),
	Cli.Action.new("Validate the spec and list every derived name.", Cli.Request.Check(request.instance())),
]

ran_json : Cli.Roots, Names.LocalPath, InstanceSpec, InstanceRender.Receipt -> Str
# Keep the wire record concrete, as success_json does for the same compiler reason.
ran_json = |request, path, spec, receipt| {
	# A root that failed or was refused fails the command, so the envelope carries its error beside the receipt.
	error : Try(Problem.Dto, [Null])
	error = if receipt.ok Err(Null) else Ok(Output.roots_failed(request.parts().mode, failed_roots(receipt)).dto())
	Json.to_str({
		schema_version: 1.U64,
		ok: receipt.ok,
		command: request.command().name(),
		exit_code: Output.new(Output.Outcome.Ran(request, path, spec, receipt)).exit_code(),
		context: { spec_path: path.to_str(), spec_validation: "checked" },
		result: {
			installation: spec.derived().installation,
			receipt,
		},
		error,
		next_actions: roots_actions(request).map(|action| action.dto()),
	})
}

failed_roots : InstanceRender.Receipt -> Str
failed_roots = |receipt| {
	failed =
		receipt.roots
			.keep_if(|root| root.status.starts_with("failed_") or root.status.starts_with("refused_"))
			.map(|root| root.label)
	"${failed.len().to_str()} of ${receipt.roots.len().to_str()} roots failed: ${Str.join_with(failed, ", ")}"
}

## One root's outcome in words.
root_status :
	{ status : Str, new_root : Bool, changes : List({ address : Str, actions : List(Str) }), logs : Str } -> Str
root_status = |root| {
	outcome = match root.status {
		"no_changes" => "no changes"
		"changes" => "${root.changes.len().to_str()} to change"
		"applied" => "applied ${root.changes.len().to_str()} changes"
		"unreleased" => "not run: the app has no release selection yet"
		"not_applied" => "not applied: the deploy stopped before its apply"
		"skipped" => "not run: a root it reads failed"
		"refused_destroy" => "refused: the plan deletes, replaces or forgets a resource; nothing applied"
		"refused_unreviewed" => "refused: its plan or release differs from the reviewed plan's; nothing applied"
		"failed_credentials" => "not run: its cluster or DNS credentials could not be read"
		"failed_inputs" => "not run: its committed inputs set a variable the platform owns; see ${root.logs}"
		"failed_release" => "not run: its release could not be read or was refused; see ${root.logs}"
		"failed_target" => "failed at its target render; logs in ${root.logs}"
		"failed_init" => "failed at init; logs in ${root.logs}"
		"failed_plan" => "failed at plan; logs in ${root.logs}"
		"failed_show" => "failed at show; logs in ${root.logs}"
		"failed_apply" => "failed at apply; logs in ${root.logs}"
		unknown => "unknown status ${unknown}"
	}
	if root.new_root and root.status == "changes" "${outcome} (new root, planned against empty state)"
	else if root.new_root and root.status == "applied" "${outcome} (new root, state created)"
	else outcome
}

ran_text : Cli.Roots, Names.LocalPath, InstanceSpec, InstanceRender.Receipt -> Str
ran_text = |request, path, spec, receipt| {
	mode = request.parts().mode
	# The label column fits the longest label (app IDs reach 20 bytes) with two spaces to spare.
	width = receipt.roots.fold(
		24,
		|widest, root| {
			needed = root.label.count_utf8_bytes() + 2
			if needed > widest needed else widest
		},
	)
	column = |label| "  ${Output.safe(label)}${Str.repeat(" ", width - label.count_utf8_bytes())}"
	planned = Str.join_with(
		receipt.roots.map(
			|root| {
				status =
					root_status(
						{ status: root.status, new_root: root.new_root, changes: root.changes, logs: root.logs },
					)
				# A day2-app root's release: its source commit, image digest and selection status.
				released = match root.release {
					Ok(release) => {
						digest = release.image.split_on("@").last() ?? release.image
						state = release.status ?? release.source
						["      release ${Output.safe(release.commit)}  ${Output.safe(digest)}  ${Output.safe(state)}"]
					}
					Err(_) => []
				}
				Str.join_with(
					["${column(root.label)}${Output.safe(status)}"].concat(released).concat(
						root.changes.map(
							|
								change,
							|
								"      ${Output.safe(Str.join_with(change.actions, ", "))}  ${
									Output.safe(
										change.address,
									)
								}",
						),
					),
					"\n",
				)
			},
		),
		"\n",
	)
	next =
		Str.join_with(
			roots_actions(request)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	title = match mode {
		InstanceRender.Mode.Plan => "OpenTofu plan, read-only"
		InstanceRender.Mode.Apply(_) | InstanceRender.Mode.Deploy => "OpenTofu apply"
	}
	reviewed = match mode {
		InstanceRender.Mode.Plan | InstanceRender.Mode.Deploy => []
		InstanceRender.Mode.Apply(directory) => ["REVIEWED PLAN", "  ${Output.safe(directory)}/receipt.json", ""]
	}
	review = match mode {
		InstanceRender.Mode.Plan => [
			"",
			"REVIEW",
			"  Each root's plan.txt shows what it would change. instance apply applies a root only if its new",
			"  plan makes exactly the changes this plan shows, and a day2-app root only with the same release.",
		]
		InstanceRender.Mode.Apply(_) | InstanceRender.Mode.Deploy => []
	}
	Str.join_with(
		[
			"DAY2  /  instance ${spec.derived().installation}  /  ${title}",
			"",
			"SPEC",
			"  ${Output.safe(path.to_str())}",
			"",
			"PLATFORM",
			"  ${Output.safe(receipt.checkout)} @ ${Output.safe(receipt.commit)}",
			"  OpenTofu ${Output.safe(receipt.engine.version)}",
			"",
		]
			.concat(reviewed)
			.concat(["ROOTS  /  ${receipt.roots.len().to_str()}, in apply order", planned])
			.concat(review)
			.concat(["", "RECEIPT", "  ${Output.safe(receipt.directory)}/receipt.json", "", "NEXT", next]),
		"\n",
	)
}

## After a publication, fetch what was published as a deploy job would; after a fetch, check the spec.
release_actions : Cli.Release, InstanceRelease.Report -> List(Cli.Action)
release_actions = |request, report| {
	check = Cli.Action.new("Validate the spec and list every derived name.", Cli.Request.Check(request.instance()))
	match request.parts().action {
		Cli.ReleaseAction.Publish(_) => [
			Cli.Action.new(
				"Fetch and verify the published release, as a deploy job would.",
				Cli.Request.Release(request.fetching(report.receipt.reference)),
			),
			check,
		]
		Cli.ReleaseAction.Fetch(_) => [check]
	}
}

released_json : Cli.Release, Names.LocalPath, InstanceSpec, InstanceRelease.Report -> Str
# Keep the wire record concrete, as success_json does for the same compiler reason. The host's receipt goes out
# verbatim: the envelope is encoded with `"receipt":null`, which only that key can spell (quotes inside a string are
# escaped), and the host's text replaces it.
released_json = |request, path, spec, report| {
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: request.command().name(),
		exit_code: 0.I32,
		context: { spec_path: path.to_str(), spec_validation: "checked" },
		result: { installation: spec.derived().installation, receipt: null },
		error: null,
		next_actions: release_actions(request, report).map(|action| action.dto()),
	})
		.replace_first("\"receipt\":null", "\"receipt\":${report.text}")
}

released_text : Cli.Release, Names.LocalPath, InstanceSpec, InstanceRelease.Report -> Str
released_text = |request, path, spec, report| {
	receipt = report.receipt
	row = |label, value| "  ${label}${Str.repeat(" ", 10 - label.count_utf8_bytes())}${Output.safe(value)}"
	next =
		Str.join_with(
			release_actions(request, report)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	outcome = match (receipt.cache, receipt.cli) {
		(Ok(cache), Ok(cli)) => [
			"OPERATOR  /  every file verified against the distribution",
			"  ${Output.safe(cli)}",
			"",
			"CACHE  /  integrity and qualification evidence verified; approval is the digest you pinned",
			"  ${Output.safe(cache)}",
		]
		_ => [
			"MANIFEST  /  published last",
			"  ${Output.safe(receipt.files.manifest)}",
			"",
			"APPROVE",
			"  Select it by pinning an app's sdk in day2.json to ${Output.safe(receipt.reference.digest)}.",
		]
	}
	title = match request.parts().action {
		Cli.ReleaseAction.Publish(_) => "SDK release published"
		Cli.ReleaseAction.Fetch(_) => "SDK release fetched and verified"
	}
	Str.join_with(
		[
			"DAY2  /  instance ${spec.derived().installation}  /  ${title}",
			"",
			"SPEC",
			"  ${Output.safe(path.to_str())}",
			"",
			"RELEASE",
			"  ${Output.safe(receipt.reference.digest)} (${receipt.reference.bytes.to_str()} bytes)",
			row("Platform", "${receipt.platform_commit} / ${receipt.profile} / ${receipt.target}"),
			row("Runtime", receipt.runtime_image),
			row("Tooling", receipt.tooling_image),
			row("Objects", receipt.objects),
			"",
		]
			.concat(outcome)
			.concat(["", "NEXT", next]),
		"\n",
	)
}

## After a source command, validate the spec it read; `controls` read none.
source_actions : Cli.SourceRequest -> List(Cli.Action)
source_actions = |request| match request.instance() {
	Ok(instance) => [Cli.Action.new("Validate the spec and list every derived name.", Cli.Request.Check(instance))]
	Err(Null) => [help_action({})]
}

sourced_json : Cli.SourceRequest, Try(Names.LocalPath, [Null]), InstanceSource.Report -> Str
# As released_json: the envelope is encoded with `"receipt":null`, which only that key can spell, and the host's text
# replaces it verbatim.
sourced_json = |request, path, report| {
	null : Try({}, [Null])
	null = Err(Null)
	spec_path : Try(Str, [Null])
	spec_path = path.map_ok(|value| value.to_str())
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: request.command().name(),
		exit_code: 0.I32,
		context: {
			spec_path,
			spec_validation: match path {
				Ok(_) => "checked"
				Err(Null) => "not_read"
			},
		},
		result: { receipt: null },
		error: null,
		next_actions: source_actions(request).map(|action| action.dto()),
	})
		.replace_first("\"receipt\":null", "\"receipt\":${report.text}")
}

sourced_text : Cli.SourceRequest, Try(Names.LocalPath, [Null]), InstanceSource.Report -> Str
sourced_text = |request, path, report| {
	receipt = report.receipt
	row = |label, value| ["  ${label}${Str.repeat(" ", 10 - label.count_utf8_bytes())}${Output.safe(value)}"]
	optional = |label, value| match value {
		Ok(text) => row(label, text)
		Err(Null) => []
	}
	bound = match (receipt.app_id, receipt.repository) {
		(Ok(name), Ok(repository)) => row("App", "${name} (${repository})")
		_ => []
	}
	archive = match receipt.archive {
		Ok(file) => row("Archive", "${file.path} (${file.digest}, ${file.bytes.to_str()} bytes)")
		Err(Null) => []
	}
	proof = match receipt.proof {
		Ok(value) => row(
			"Proof",
			"run ${
				value
					.run
					.to_str()
			}, attempt ${
				value
					.attempt
					.to_str()
			}, job ${value.job.to_str()}, upload ${value.receipt.upload_id.to_str()}",
		)
		Err(Null) => []
	}
	title = match request.parts().action {
		Cli.SourceAction.Head(_) => "branch head"
		Cli.SourceAction.Archive(_) => "source archive written"
		Cli.SourceAction.Controls(_) => "CI-control digest"
		Cli.SourceAction.VerifyControls(_) => "CI controls verified against the binding"
		Cli.SourceAction.CheckedArtifact(_) => "checked artifact verified and written"
	}
	spec = match path {
		Ok(value) => ["SPEC", "  ${Output.safe(value.to_str())}", ""]
		Err(Null) => []
	}
	next =
		Str.join_with(
			source_actions(request)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	Str.join_with(
		["DAY2  /  instance source  /  ${title}", ""]
			.concat(spec)
			.concat(["SOURCE"])
			.concat(bound)
			.concat(optional("Commit", receipt.commit))
			.concat(archive)
			.concat(optional("Controls", receipt.controls))
			.concat(optional("Platform", receipt.platform_commit))
			.concat(optional("Inputs", receipt.source_inputs))
			.concat(proof)
			.concat(["", "NEXT", next]),
		"\n",
	)
}

## After a candidate command, validate the spec it read; the build host's commands read none.
candidate_actions : Cli.CandidateRequest -> List(Cli.Action)
candidate_actions = |request| match request.instance() {
	Ok(instance) => [Cli.Action.new("Validate the spec and list every derived name.", Cli.Request.Check(instance))]
	Err(Null) => [help_action({})]
}

candidated_json : Cli.CandidateRequest, Try(Names.LocalPath, [Null]), InstanceCandidate.Report -> Str
# As sourced_json: the envelope is encoded with `"receipt":null`, which only that key can spell, and the host's text
# replaces it verbatim.
candidated_json = |request, path, report| {
	null : Try({}, [Null])
	null = Err(Null)
	spec_path : Try(Str, [Null])
	spec_path = path.map_ok(|value| value.to_str())
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: request.command().name(),
		exit_code: 0.I32,
		context: {
			spec_path,
			spec_validation: match path {
				Ok(_) => "checked"
				Err(Null) => "not_read"
			},
		},
		result: { receipt: null },
		error: null,
		next_actions: candidate_actions(request).map(|action| action.dto()),
	})
		.replace_first("\"receipt\":null", "\"receipt\":${report.text}")
}

candidated_text : Cli.CandidateRequest, Try(Names.LocalPath, [Null]), InstanceCandidate.Report -> Str
candidated_text = |request, path, report| {
	receipt = report.receipt
	row = |label, value| ["  ${label}${Str.repeat(" ", 10 - label.count_utf8_bytes())}${Output.safe(value)}"]
	optional = |label, value| match value {
		Ok(text) => row(label, text)
		Err(Null) => []
	}
	file = |label, value| match value {
		Ok(written) => row(label, "${written.path} (${written.digest}, ${written.bytes.to_str()} bytes)")
		Err(Null) => []
	}
	transfer = match receipt.transfer {
		Ok(copied) => row(
			"Transfer",
			"${copied.bytes.to_str()} bytes in ${copied.milliseconds.to_str()} ms",
		)
		Err(Null) => []
	}
	slot = match receipt.slot {
		Ok(index) => row("Slot", index.to_str())
		Err(Null) => []
	}
	title = match request.parts().action {
		Cli.CandidateAction.Build(_) => "deployment candidate"
		Cli.CandidateAction.Preflight(_) => "maintenance protocol verified on the build host"
		Cli.CandidateAction.Check(_) => "candidate record valid"
		Cli.CandidateAction.NativeBuild(_) => "native build"
		Cli.CandidateAction.NativeProbe(_) => "native maintenance protocol verified"
	}
	spec = match path {
		Ok(value) => ["SPEC", "  ${Output.safe(value.to_str())}", ""]
		Err(Null) => []
	}
	next =
		Str.join_with(
			candidate_actions(request)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	Str.join_with(
		["DAY2  /  instance candidate  /  ${title}", ""]
			.concat(spec)
			.concat(["CANDIDATE"])
			.concat(optional("App", receipt.app_id))
			.concat(optional("Commit", receipt.commit))
			.concat(optional("Outcome", receipt.outcome))
			.concat(optional("Image", receipt.image))
			.concat(optional("Artifact", receipt.artifact_id))
			.concat(optional("Tooling", receipt.tooling_image))
			.concat(optional("Record", receipt.record))
			.concat(optional("Log", receipt.build_log))
			.concat(file("Candidate", receipt.candidate))
			.concat(file("Result", receipt.result))
			.concat(file("Build log", receipt.log))
			.concat(slot)
			.concat(transfer)
			.concat(["", "NEXT", next]),
		"\n",
	)
}

toggled : Cli.Instance -> Cli.Instance
toggled = |request| request.with_format(
	match request.parts().format {
		Cli.Format.Json => Cli.Format.Text
		Cli.Format.Text => Cli.Format.Json
	},
)

checked_json : Cli.Instance, Names.LocalPath, InstanceSpec -> Str
# Keep the wire record concrete, as success_json does for the same compiler reason.
checked_json = |request, path, spec| {
	names = spec.derived()
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: "instance.check",
		exit_code: 0.I32,
		context: { spec_path: path.to_str(), spec_validation: "checked" },
		result: {
			installation: names.installation,
			platform_repository: names.platform_repository,
			platform_commit: names.platform_commit,
			forge: { kind: names.forge_kind, server: names.forge_server, org: names.forge_org },
			gcp: { project: names.gcp_project, region: names.gcp_region, zone: names.gcp_zone },
			domains: { people: names.people_domain, apps: names.apps_domain },
			operators: names.operators,
			apply_identity: names.apply_identity,
			repositories: { instance: names.instance_repository, app_ci: names.app_ci_repository },
			required_check: names.required_check,
			artifact_registry: names.artifact_registry,
			sdk_registry: names.sdk_registry,
			tofu_state_bucket: names.tofu_state_bucket,
			platform_state_prefixes: names.platform_state_prefixes,
			cluster: names.cluster,
			build_host: names.build_host,
			app_namespace_prefix: names.app_namespace_prefix,
			apps: names
				.apps
				.map(
					|
						bound,
					|
						{
							id: bound.id,
							delivery: bound.delivery,
							sdk: bound.sdk,
							owners: bound.owners,
							admins: bound.admins,
							size: bound.size,
							verification: bound.verification,
							schedules: bound.schedules,
							extension: bound.extension,
							repository: bound.repository,
							hostname: bound.hostname,
							namespace: bound.namespace,
							image: bound.image,
							state_bucket: bound.state_bucket,
							state_prefix: bound.state_prefix,
							edge_state_prefix: bound.edge_state_prefix,
							backup_bucket: bound.backup_bucket,
							runtime_resources: bound.runtime_resources,
							sqlite_storage_gb: bound.sqlite_storage_gb,
						},
				),
		},
		error: null,
		next_actions: check_actions(request).map(|action| action.dto()),
	})
}

checked_text : Cli.Instance, Names.LocalPath, InstanceSpec -> Str
checked_text = |request, path, spec| {
	names = spec.derived()
	row = |label, value| "  ${label}${Str.repeat(" ", 22 - label.count_utf8_bytes())}${Output.safe(value)}"
	apps =
		Str.join_with(
			names
				.apps
				.map(
					|
						bound,
					|
						Str.join_with(
							[
								"  ${bound.id}  /  ${bound.delivery}  /  ${bound.sdk}",
								row("  owners", Str.join_with(bound.owners, ", ")),
								row("  admins", Str.join_with(bound.admins, ", ")),
								row(
									"  runtime",
									"${
										bound
											.size
									} / ${
										bound
											.verification
											.to_str()
									} verification cases / schedules ${bound.schedules}",
								),
								row("  repository", bound.repository),
								row("  hostname", bound.hostname),
								row("  namespace", bound.namespace),
								row("  image", bound.image),
								row("  state", "${bound.state_bucket} / ${bound.state_prefix}"),
								row("  edge state", "${names.tofu_state_bucket} / ${bound.edge_state_prefix}"),
								row("  backups", bound.backup_bucket),
								row(
									"  resources",
									"${bound.runtime_resources.memory_mib.to_str()} MiB / ${
										bound.runtime_resources.cpu_millis.to_str()
									}m CPU / ${bound.runtime_resources.process_limit.to_str()} processes / ${
										bound.sqlite_storage_gb.to_str()
									} GiB SQLite",
								),
							].concat(
								match bound.extension {
									Ok(extension) => [
										row("  extension", extension.id),
										row("  update URL", extension.update_url),
										row("  downloads", Str.join_with(extension.downloads, ", ")),
										row("  signing key", extension.signing_secret),
									]
									Err(_) => [row("  extension", "none")]
								},
							),
							"\n",
						),
				),
			"\n\n",
		)
	next =
		Str.join_with(
			check_actions(request)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	Str.join_with(
		[
			"DAY2  /  instance ${names.installation}",
			"",
			"SPEC",
			row("File", path.to_str()),
			row("Platform", "${names.platform_repository} @ ${names.platform_commit}"),
			row("Forge", "${names.forge_kind} ${names.forge_server} / ${names.forge_org}"),
			row("GCP", "${names.gcp_project} / ${names.gcp_zone}"),
			row("Domains", "people ${names.people_domain} / apps ${names.apps_domain}"),
			row("Operators", Str.join_with(names.operators, ", ")),
			"",
			"DERIVED NAMES",
			row("Apply identity", names.apply_identity),
			row("Instance repository", names.instance_repository),
			row("App CI repository", names.app_ci_repository),
			row("Required app check", names.required_check),
			row("Artifact registry", names.artifact_registry),
			row("SDK registry", names.sdk_registry),
			row("OpenTofu state", names.tofu_state_bucket),
			row(
				"Platform state",
				"project ${names.platform_state_prefixes.project} / cluster ${
					names.platform_state_prefixes.cluster
				} / tenancy ${names.platform_state_prefixes.tenancy} / app edges ${
					names.platform_state_prefixes.app_edge
				}/<id> / opt-in roots ${names.platform_state_prefixes.day2}/<root>",
			),
			row("Cluster", "${names.cluster.name} / ${names.cluster.kube_context}"),
			row("Build host", "${names.build_host.name} / ${names.build_host.zone}"),
			row("App namespaces", "${names.app_namespace_prefix}<id>"),
			"",
			"APPS  /  ${names.apps.len().to_str()}",
			apps,
			"",
			"NEXT",
			next,
		],
		"\n",
	)
}

rendered_json : Cli.Instance, Names.LocalPath, InstanceSpec -> Str
# Keep the wire record concrete, as success_json does for the same compiler reason.
rendered_json = |request, path, spec| {
	names = spec.derived()
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: "instance.render",
		exit_code: 0.I32,
		context: { spec_path: path.to_str(), spec_validation: "checked" },
		result: {
			installation: names.installation,
			roots: InstanceRender.roots(spec)
				.map(
					|
						root,
					| {
						backend = root.backend(names)
						{
							root: root.name(),
							app_id: root.app_id(),
							stack: root.stack(),
							backend: { bucket: backend.bucket, prefix: backend.prefix },
							tfvars_json: root.tfvars_json(names),
						}
					},
				),
		},
		error: null,
		next_actions: render_actions(request).map(|action| action.dto()),
	})
}

rendered_text : Cli.Instance, Names.LocalPath, InstanceSpec -> Str
rendered_text = |request, path, spec| {
	names = spec.derived()
	roots = InstanceRender.roots(spec)
	# The label column fits the longest label (app IDs reach 20 bytes) with two spaces to spare.
	width = roots.fold(
		24,
		|widest, root| {
			needed = root.label().count_utf8_bytes() + 2
			if needed > widest needed else widest
		},
	)
	row = |root| {
		label = root.label()
		backend = root.backend(names)
		"  ${Output.safe(label)}${Str.repeat(" ", width - label.count_utf8_bytes())}${Output.safe(backend.bucket)} / ${
			Output.safe(backend.prefix)
		}"
	}
	variables = |root|
		Str.join_with(
			["  ${Output.safe(root.label())}"].concat(
				root
					.variables(names)
					.map(variable_line),
			),
			"\n",
		)
	next =
		Str.join_with(
			render_actions(request)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	Str.join_with(
		[
			"DAY2  /  instance ${names.installation}  /  OpenTofu inputs",
			"",
			"SPEC",
			"  ${Output.safe(path.to_str())}",
			"",
			"STATE BACKENDS  /  ${roots.len().to_str()} core roots, in apply order",
			Str.join_with(roots.map(row), "\n"),
			"",
			"VARIABLES  /  rendered from the spec; the instance commits every other input",
			Str.join_with(roots.map(variables), "\n\n"),
			"",
			"NEXT",
			next,
		],
		"\n",
	)
}

## One rendered variable as a tfvars line: its JSON value is also a valid OpenTofu expression.
variable_line : (Str, InstanceRender.Value) -> Str
variable_line = |pair| "    ${Output.safe(pair.0)} = ${Output.safe(pair.1.json())}"

error_json : Problem, Cli.Command -> Str
error_json = |problem, command| {
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.False,
		command: command.name(),
		exit_code: problem.exit_code(),
		context: null,
		result: null,
		error: problem.dto(),
		next_actions: [help_action({}).dto()],
	})
}

info_json : Bool -> Str
info_json = |is_help| {
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.True,
		command: if is_help "help" else "version",
		exit_code: 0.I32,
		context: null,
		result: {
			text: if is_help Cli.help else Output.version,
			version: Output.version,
			implemented_commands: [
				"app.describe",
				"instance.check",
				"instance.render",
				"instance.plan",
				"instance.apply",
				"instance.release.publish",
				"instance.release.fetch",
				"instance.source.head",
				"instance.source.archive",
				"instance.source.controls",
				"instance.source.verify-controls",
				"instance.source.checked-artifact",
				"instance.candidate.build",
				"instance.candidate.preflight",
				"instance.candidate.check",
				"instance.candidate.native-build",
				"instance.candidate.native-probe",
			],
			platform_commands: [
				"platform.build",
				"platform.check",
				"platform.test",
				"platform.local-dev",
				"platform.backup",
				"platform.restore",
				"platform.restore.inspect",
				"platform.infra.plan",
				"platform.authority.inspect",
				"platform.authority.admin",
				"platform.resources",
				"platform.authority.apply",
				"platform.authority.activate",
			],
			supports_invocation: Bool.False,
			supports_authentication: Bool.False,
			supports_remote_access: Bool.False,
		},
		error: null,
		next_actions: demo_actions(["app", "describe", "links", "--demo", "--agent"]).map(|action| action.dto()),
	})
}

description_text : Source -> Str
description_text = |loaded| {
	context = loaded.context_dto()
	result = loaded.result_dto()
	actions = next_actions(loaded).map(|action| action.dto())
	reads = result.operations.keep_if(|operation| operation.kind == "query").len()
	writes = result.operations.len() - reads
	mode = if loaded.is_demo() "DEMO / bundled example" else "LOCAL / instance metadata"
	location = if loaded.is_demo() "" else "\n  Instance     ${Output.safe(context.instance_path)}"
	intro =
		"DAY2  /  ${Output.safe(result.app_name)}\n\n${
			Output.wrap(
				result.description,
				"",
			)
		}\n\nCONTEXT\n  Company      ${
			Output.safe(
				context.installation,
			)
		}\n  Environment  ${
			Output.safe(
				context.environment,
			)
		}\n  Source       ${mode}${location}\n\nOPERATIONS  /  ${
			result
				.operation_count
				.to_str()
		} of ${result.total_operations.to_str()} shown; ${reads.to_str()} read, ${writes.to_str()} write\n"
	operations = Str.join_with(result.operations.map(operation_text), "\n\n")
	next =
		Str.join_with(
			actions.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	"${intro}\n${operations}\n\nNOTES\n${
		Output.wrap(
			result.example_note,
			"  ",
		)
	}\n  Catalog contracts checked; permissions and artifact integrity are unverified.\n  Invoking these operations is outside this one-command spike.\n\nNEXT\n${next}"
}

error_text : Problem -> Str
error_text =
	|
		problem,
	|
		"DAY2  /  ${
			problem
				.code()
		}\n\n${Output.safe(problem.message())}\n\nNEXT\n  ${Output.safe(problem.hint())}\n\nExit ${
			problem
				.exit_code()
				.to_str()
		} / action required before retrying"

wrap_words : List(Str), Str, Str, List(Str) -> List(Str)
wrap_words = |words, indent, line, lines| match words {
	[] => lines.append(line)
	[word, .. as rest] => {
		candidate = if line == indent "${line}${word}" else "${line} ${word}"
		if candidate.count_utf8_bytes() > 88 and line != indent {
			wrap_words(rest, indent, "${indent}${word}", lines.append(line))
		} else {
			wrap_words(rest, indent, candidate, lines)
		}
	}
}

operation_text : Catalog.OperationDto -> Str
operation_text = |operation| {
	label = if operation.effect == "read" "READ " else "WRITE"
	fields = if operation.input_fields.is_empty() {
		"    No fields. Supply an empty JSON object."
	} else {
		Str.join_with(
			operation
				.input_fields
				.map(
					|
						field,
					|
						"    ${Output.safe(field.name)}  : ${Output.safe(field.roc_type)}  / required\n${
							Output.wrap(
								field.description,
								"      ",
							)
						}",
				),
			"\n",
		)
	}
	"  ${label}  ${
		operation
			.name
	}\n${Output.wrap(operation.description, "    ")}\n\n    Inputs / ${
		Output.safe(
			operation.input_type,
		)
	}\n${fields}\n\n    Example input\n      ${
		Output.safe(
			operation.example_input_json,
		)
	}\n\n    Returns\n${
		Output.wrap(
			operation.output_type,
			"      ",
		)
	}"
}

planned_spec : Str
planned_spec =
	\\{"kind":"instance","version":1,"installation":"exampleco",
	\\"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
	\\"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com"],
	\\"apps":{"go":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"automatic",
	\\"extension":null,"owners":["ada@example.com"],"size":"standard","verification":4,"schedules":"enabled"}}}

planned_receipt : Str
planned_receipt =
	\\{"format":2,"mode":"plan","ok":false,"commit":"c","stacks_tree":"t","checkout":"/p","instance":"/i",
	\\"instance_commit":"","instance_clean":false,"engine":{"version":"1.12.3","digest":"sha256:e"},
	\\"roots":[{"label":"project","stack":"project","backend":{"bucket":"b","prefix":"foundation"},"new_root":false,
	\\"inputs":{"path":"gcp/config/project.tfvars","digest":"sha256:i"},"variables":"sha256:v","status":"failed_plan","review":"",
	\\"changes":[],"plan_digest":"","show_digest":"","logs":"/o/project","release":null,"target":null},
	\\{"label":"day2-app/go","stack":"day2-app","backend":{"bucket":"exampleco-tools-go-state","prefix":"day2-app/go"},
	\\"new_root":false,"inputs":{"path":"gcp/config/apps/go.tfvars","digest":"sha256:i"},"variables":"sha256:v",
	\\"status":"no_changes","review":"sha256:r","changes":[],"plan_digest":"sha256:p","show_digest":"sha256:s",
	\\"logs":"/o/day2-app-go","release":{"source":"selection",
	\\"record":"gs://exampleco-tools-tofu-state/day2/app-releases/go/selection.json","generation":"7","status":"ready",
	\\"digest":"sha256:d","candidate":"sha256:c","commit":"abababababababababababababababababababab",
	\\"image":"us-central1-docker.pkg.dev/exampleco-tools/go/go@sha256:66","artifact_id":"ef",
	\\"tooling_image":"us-central1-docker.pkg.dev/exampleco-tools/go/day2-tooling@sha256:22",
	\\"qualified_release":{"digest":"sha256:q","bytes":1236},"variables":"sha256:r"},"target":null}],"directory":"/o"}

# A plan whose root failed exits 6 and reports plan_failed beside its receipt; a day2-app root names its release.
expect match (
	Cli.parse(["instance", "plan", "d", "p", "o", "--agent"]),
	InstanceSpec.from_json(planned_spec),
	Names.LocalPath.from_str("d/day2.json"),
	InstanceRender.receipt(planned_receipt, InstanceRender.Mode.Plan),
) {
	(Ok(Cli.Request.Roots(request)), Ok(spec), Ok(path), Ok(receipt)) => {
		response = Output.new(Output.Outcome.Ran(request, path, spec, receipt))
		response.exit_code()
			== 6
			and response.body().contains("\"code\":\"plan_failed\"")
				and response.body().contains("\"command\":\"instance.plan\"")
					and response.body().contains("1 of 2 roots failed: project")
						and response
							.body()
							.contains("\"image\":\"us-central1-docker.pkg.dev/exampleco-tools/go/go@sha256:66\"")
							and !response.body().contains("not_planned")
	}
	_ => Bool.False
}

# The text output names a day2-app root's release: its commit, image digest and selection status.
expect match (
	Cli.parse(["instance", "plan", "d", "p", "o"]),
	InstanceSpec.from_json(planned_spec),
	Names.LocalPath.from_str("d/day2.json"),
	InstanceRender.receipt(planned_receipt, InstanceRender.Mode.Plan),
) {
	(Ok(Cli.Request.Roots(request)), Ok(spec), Ok(path), Ok(receipt)) => {
		body = Output.new(Output.Outcome.Ran(request, path, spec, receipt)).body()
		body.contains("ROOTS  /  2, in apply order")
			and body.contains("release abababababababababababababababababababab  sha256:66  ready")
				and !body.contains("NOT RUN")
	}
	_ => Bool.False
}

applied_receipt : Str
applied_receipt =
	planned_receipt
		.replace_first("\"mode\":\"plan\"", "\"mode\":\"apply\"")
		.replace_first("\"status\":\"failed_plan\"", "\"status\":\"refused_destroy\"")

# An apply that refused a destructive plan exits 6, reports apply_failed, and says what it refused.
expect match (
	Cli.parse(["instance", "apply", "d", "p", "r", "o"]),
	InstanceSpec.from_json(planned_spec),
	Names.LocalPath.from_str("d/day2.json"),
	InstanceRender.receipt(applied_receipt, InstanceRender.Mode.Apply("r")),
) {
	(Ok(Cli.Request.Roots(request)), Ok(spec), Ok(path), Ok(receipt)) => {
		response = Output.new(Output.Outcome.Ran(request, path, spec, receipt))
		response.exit_code()
			== 6
			and response.body().contains("OpenTofu apply")
				and response.body().contains("REVIEWED PLAN\n  r/receipt.json")
					and response.body().contains("refused: the plan deletes, replaces or forgets a resource")
	}
	_ => Bool.False
}

published_receipt : Str
published_receipt =
	\\{"format":1,"mode":"publish","reference":{"digest":"sha256:cc689326c54b7a9cba772211381d9e7442a3e4d7137a3ede128593d6e0e76432","bytes":1236},
	\\"platform_commit":"c","profile":"linux_sqlite_single_v1","target":"linux-x86_64","runtime_image":"r","tooling_image":"t",
	\\"objects":"gs://b/day2/platform-releases/sha256",
	\\"files":{"manifest":"/i/new.json","distribution":null,"native":null,"strict":null},"cache":null,"cli":null}

# A publication reports its reference and suggests fetching exactly that release; a fetch receipt cannot stand in.
expect match (
	Cli.parse(["instance", "release", "publish", "d", "r.json", "new.json"]),
	InstanceSpec.from_json(planned_spec),
	Names.LocalPath.from_str("d/day2.json"),
) {
	(Ok(Cli.Request.Release(request)), Ok(spec), Ok(path)) => match InstanceRelease.receipt(
		published_receipt,
		request.parts().action,
	) {
		Ok(receipt) => {
			text = Output.new(Output.Outcome.Released(request, path, spec, receipt)).body()
			agent =
				Output.new(Output.Outcome.Released(request.with_format(Cli.Format.Json), path, spec, receipt)).body()
			text.contains("SDK release published")
				and text
					.contains(
						"day2 instance release fetch d 'sha256:cc689326c54b7a9cba772211381d9e7442a3e4d7137a3ede128593d6e0e76432' 1236",
					)
					and agent.contains("\"command\":\"instance.release.publish\"")
						and agent.contains("\"receipt\":${published_receipt}}")
							and text.contains("MANIFEST  /  published last\n  /i/new.json")
								and agent.contains("\"argv\":[\"day2\",\"instance\",\"release\",\"fetch\",\"d\",")
									and InstanceRelease.receipt(
										published_receipt.replace_first("\"cli\":null", "\"cli\":\"/c\""),
										request.parts().action,
									)
										.is_err()
		}
		Err(_) => Bool.False
	}
	_ => Bool.False
}
