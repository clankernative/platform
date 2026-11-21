import Cli
import Catalog
import Source
import Problem
import Names
import InstanceSpec
import InstanceRender

## Status, error, stream, and exit code are projections of one closed outcome.
Output :: { outcome : Outcome }.{
	Outcome := [
		Help(Cli.Format),
		Version(Cli.Format),
		Described(Source),
		Checked(Cli.Instance, Names.LocalPath, InstanceSpec),
		Rendered(Cli.Instance, Names.LocalPath, InstanceSpec),
		Ran(Cli.Roots, Names.LocalPath, InstanceSpec, InstanceRender.Receipt),
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
			Outcome.Failed(problem, _, _) => error_text(problem)
		}
	}

	## The problem a failed `instance plan` or `apply` reports.
	roots_failed : InstanceRender.Mode, Str -> Problem
	roots_failed = |mode, detail| match mode {
		InstanceRender.Mode.Plan => Problem.PlanFailed(detail)
		InstanceRender.Mode.Apply(_) => Problem.ApplyFailed(detail)
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

## The roots `instance plan` and `apply` leave to the release controller.
not_planned : InstanceSpec -> List(Str)
not_planned = |spec| InstanceRender.roots(spec).drop_if(|root| root.plannable()).map(|root| root.label())

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
			not_planned: not_planned(spec),
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
		"skipped" => "not run: a shared root before it failed"
		"refused_destroy" => "refused: the plan deletes, replaces or forgets a resource; nothing applied"
		"refused_unreviewed" => "refused: its plan differs from the reviewed plan; nothing applied"
		"failed_credentials" => "not run: its cluster or DNS credentials could not be read"
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
				Str.join_with(
					["${column(root.label)}${Output.safe(status)}"].concat(
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
	skipped = not_planned(spec)
	next =
		Str.join_with(
			roots_actions(request)
				.map(|action| action.dto())
				.map(|action| "  ${Output.safe(action.description)}\n    ${Output.safe(action.command)}"),
			"\n\n",
		)
	title = match mode {
		InstanceRender.Mode.Plan => "OpenTofu plan, read-only"
		InstanceRender.Mode.Apply(_) => "OpenTofu apply"
	}
	reviewed = match mode {
		InstanceRender.Mode.Plan => []
		InstanceRender.Mode.Apply(directory) => ["REVIEWED PLAN", "  ${Output.safe(directory)}/receipt.json", ""]
	}
	review = match mode {
		InstanceRender.Mode.Plan => [
			"",
			"REVIEW",
			"  Each root's plan.txt shows what it would change. instance apply applies a root only if its new",
			"  plan makes exactly the changes this plan shows.",
		]
		InstanceRender.Mode.Apply(_) => []
	}
	not_run =
		if skipped.is_empty() [] else [
			"",
			"NOT RUN  /  their image and artifact inputs come from the release controller",
			Str.join_with(skipped.map(|label| "  ${Output.safe(label)}"), "\n"),
		]
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
			.concat(["CORE ROOTS  /  ${receipt.roots.len().to_str()}, in apply order", planned])
			.concat(review)
			.concat(not_run)
			.concat(["", "RECEIPT", "  ${Output.safe(receipt.directory)}/receipt.json", "", "NEXT", next]),
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
			repositories: { instance: names.instance_repository, app_ci: names.app_ci_repository },
			required_check: names.required_check,
			sdk_registry: names.sdk_registry,
			tofu_state_bucket: names.tofu_state_bucket,
			platform_state_prefixes: names.platform_state_prefixes,
			cluster: names.cluster,
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
			row("Instance repository", names.instance_repository),
			row("App CI repository", names.app_ci_repository),
			row("Required app check", names.required_check),
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
	\\{"format":1,"mode":"plan","ok":false,"commit":"c","stacks_tree":"t","checkout":"/p","instance":"/i",
	\\"instance_commit":"","instance_clean":false,"engine":{"version":"1.12.3","digest":"sha256:e"},
	\\"roots":[{"label":"project","stack":"project","backend":{"bucket":"b","prefix":"foundation"},"new_root":false,
	\\"inputs":{"path":"gcp/config/project.tfvars","digest":"sha256:i"},"variables":"sha256:v","status":"failed_plan","review":"",
	\\"changes":[],"plan_digest":"","show_digest":"","logs":"/o/project"}],"directory":"/o"}

# A plan whose root failed exits 6 and reports plan_failed beside its receipt.
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
					and response.body().contains("1 of 1 roots failed: project")
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
