import Cli
import Catalog
import Source
import Problem

## Status, error, stream, and exit code are projections of one closed outcome.
Output :: { outcome : Outcome }.{
	Outcome := [Help(Cli.Format), Version(Cli.Format), Described(Source), Failed(Problem, Cli.Format)]

	version = "0.3.0-spike"

	new : Outcome -> Output
	new = |outcome| { outcome: outcome }

	exit_code : Output -> I32
	exit_code = |response| match response.outcome {
		Outcome.Failed(problem, _) => problem.exit_code()
		_ => 0
	}

	stream : Output -> [Stdout, Stderr]
	stream = |response| match response.outcome {
		Outcome.Failed(_, Cli.Format.Text) => Stderr
		_ => Stdout
	}

	body : Output -> Str
	body = |response| match format(response.outcome) {
		Cli.Format.Json => json(response.outcome)
		Cli.Format.Text => match response.outcome {
			Outcome.Help(_) => Cli.help
			Outcome.Version(_) => "day2 ${version}"
			Outcome.Described(loaded) => description_text(loaded)
			Outcome.Failed(problem, _) => error_text(problem)
		}
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
	Output.Outcome.Help(value) | Output.Outcome.Version(value) | Output.Outcome.Failed(_, value) => value
	Output.Outcome.Described(loaded) => loaded.request().parts().format
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
	Output.Outcome.Failed(problem, _) => error_json(problem)
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

error_json : Problem -> Str
error_json = |problem| {
	null : Try({}, [Null])
	null = Err(Null)
	Json.to_str({
		schema_version: 1.U64,
		ok: Bool.False,
		command: "app.describe",
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
			implemented_commands: ["app.describe"],
			platform_commands: [
				"platform.build",
				"platform.check",
				"platform.test",
				"platform.local-dev",
				"platform.backup",
				"platform.restore",
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
