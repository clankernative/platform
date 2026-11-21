import InstanceRender
import Names
import Problem
import "help.txt" as help_text : Str

Cli :: [].{
	Format := [Text, Json]

	Filter := [All, One(Names.Operation)]

	Source := [Demo, Instance(Names.LocalPath), Environment]

	Request := [Help(Format), Version(Format), Describe(Describe), Check(Instance), Render(Instance), Roots(Roots)]

	## The command a response reports, including failures before a request exists.
	Command := [AppDescribe, InstanceCheck, InstanceRender, InstancePlan, InstanceApply].{
		name : Command -> Str
		name = |command| match command {
			AppDescribe => "app.describe"
			InstanceCheck => "instance.check"
			InstanceRender => "instance.render"
			InstancePlan => "instance.plan"
			InstanceApply => "instance.apply"
		}
	}

	## day2 instance check|render DIRECTORY reads exactly DIRECTORY/day2.json.
	Instance :: { directory : Names.LocalPath, format : Format }.{
		parts : Instance -> { directory : Names.LocalPath, format : Format }
		parts = |request| { directory: request.directory, format: request.format }

		with_format : Instance, Format -> Instance
		with_format = |request, format| { ..request, format }
	}

	## day2 instance plan|apply DIRECTORY PLATFORM NEW_DIRECTORY: a read-only plan, or an apply, of DIRECTORY's core
	## roots, run in PLATFORM (a checkout at day2.json's platform commit), with plans and logs in NEW_DIRECTORY.
	Roots :: {
		mode : InstanceRender.Mode,
		directory : Names.LocalPath,
		checkout : Names.LocalPath,
		output : Names.LocalPath,
		format : Format,
	}.{
		parts :
			Roots ->
				{
					mode : InstanceRender.Mode,
					directory : Names.LocalPath,
					checkout : Names.LocalPath,
					output : Names.LocalPath,
					format : Format,
				}
		parts =
			|
				request,
			|
				{
					mode: request.mode,
					directory: request.directory,
					checkout: request.checkout,
					output: request.output,
					format: request.format,

				}

		with_format : Roots, Format -> Roots
		with_format = |request, format| { ..request, format }

		## The command a response reports.
		command : Roots -> Command
		command = |request| match request.mode {
			InstanceRender.Mode.Plan => Command.InstancePlan
			InstanceRender.Mode.Apply => Command.InstanceApply
		}

		## The same instance, as `check` and `render` read it.
		instance : Roots -> Instance
		instance = |request| Instance.{ directory: request.directory, format: request.format }
	}

	## The scanner's optional fields and positionals never escape parsing.
	Describe :: { app_name : Names.App, source : Source, filter : Filter, format : Format }.{
		parts : Describe -> { app_name : Names.App, source : Source, filter : Filter, format : Format }
		parts =
			|
				request,
			| { app_name: request.app_name, source: request.source, filter: request.filter, format: request.format }

		with_instance : Describe, Names.LocalPath -> Describe
		with_instance = |request, path| { ..request, source: Instance(path) }

		with_filter : Describe, Filter -> Describe
		with_filter = |request, filter| { ..request, filter }

		with_format : Describe, Format -> Describe
		with_format = |request, format| { ..request, format }
	}

	## An action contains a typed request, never an independently authored argv.
	ActionDto : { description : Str, argv : List(Str), command : Str }

	Action :: { description : Str, request : Request }.{
		new : Str, Request -> Action
		new = |description, request| { description, request }

		dto : Action -> ActionDto
		dto = |action| {
			argv = arguments(action.request)
			{ description: action.description, argv, command: command(argv) }
		}
	}

	parse : List(Str) -> Try(Request, Problem)
	parse = |args| {
		if args.len() > 128 or args.fold(0.U64, |count, arg| count + arg.count_utf8_bytes()) > 16_384 {
			return Err(Problem.InvalidArguments("at most 128 arguments and 16 KiB are supported"))
		}
		if args.any(|arg| arg.to_utf8().any(|byte| byte < 32 or byte == 127)) {
			return Err(Problem.InvalidArguments("control characters are unsupported"))
		}
		raw = scan(args, { source: Unset, filter: Unset, intent: Run, format: Text, positionals: [] })?
		match raw.intent {
			Version => {
				if raw.positionals != [] or has_options(raw) {
					return Err(
						Problem.ConflictingOptions("--version cannot be combined with a command or describe options."),
					)
				}
				Ok(Request.Version(raw.format))
			}
			Help => {
				if has_options(raw) {
					return Err(
						Problem.ConflictingOptions(
							"--help cannot be combined with --demo, --instance, or --operation.",
						),
					)
				}
				match raw.positionals {
					[]
					| ["app", "describe"]
					| ["instance", "check"]
					| ["instance", "render"]
					| ["instance", "plan"]
					| ["instance", "apply"] => Ok(Request.Help(raw.format))
					["instance", "check", _] | ["instance", "render", _] => Ok(Request.Help(raw.format))
					["instance", "plan", ..] | ["instance", "apply", ..] => Ok(Request.Help(raw.format))
					["app", "describe", name] => {
						_ = Names.App.from_str(name).map_err(|_| Problem.InvalidAppName(name))?
						Ok(Request.Help(raw.format))
					}
					_ => Err(Problem.UnknownCommand)
				}
			}
			Run => match raw.positionals {
				[] => if has_options(raw) Err(Problem.MissingCommand) else Ok(Request.Help(raw.format))
				["app", "describe"] | ["instance", "check"] | ["instance", "render"] => Err(Problem.MissingArgument)
				["instance", "plan"]
				| ["instance", "plan", _]
				| ["instance", "plan", _, _]
				| ["instance", "apply"]
				| ["instance", "apply", _]
				| ["instance", "apply", _, _] => Err(Problem.MissingArgument)
				["instance", "plan", directory, checkout, output] => Ok(
					Request.Roots(roots(InstanceRender.Mode.Plan, directory, checkout, output, raw)?),
				)
				["instance", "apply", directory, checkout, output] => Ok(
					Request.Roots(roots(InstanceRender.Mode.Apply, directory, checkout, output, raw)?),
				)
				["instance", "check", value] => Ok(Request.Check(instance("check", value, raw)?))
				["instance", "render", value] => Ok(Request.Render(instance("render", value, raw)?))
				["app", "describe", name] => {
					app_name = Names.App.from_str(name).map_err(|_| Problem.InvalidAppName(name))?
					source = match raw.source {
						Unset => Environment
						Demo => Demo
						Instance(path) => Instance(path)
					}
					filter = match raw.filter {
						Unset => All
						Set(operation) => One(operation)
					}
					Ok(Request.Describe(Describe.{ app_name, source, filter, format: raw.format }))
				}
				_ => Err(Problem.UnknownCommand)
			}
		}
	}

	## Agrees with parse: the first positional names the command family. Values
	## of --instance and --operation are skipped so they cannot select it.
	requested : List(Str) -> Command
	requested = |args| match args {
		["--instance", _, .. as rest] | ["--operation", _, .. as rest] => requested(rest)
		["instance", .. as rest] => instance_command(rest)
		[arg, .. as rest] if arg.starts_with("-") => requested(rest)
		_ => AppDescribe
	}

	output_format : List(Str) -> Format
	output_format = |args| if args.contains("--json") or args.contains("--agent") Json else Text

	request_format : Request -> Format
	request_format = |request| match request {
		Request.Help(format) | Request.Version(format) => format
		Request.Describe(value) => value.format
		Request.Check(value) | Request.Render(value) => value.format
		Request.Roots(value) => value.format
	}

	quote : Str -> Str
	quote = |value| "'${value.replace_each("'", "'\"'\"'")}'"

	command : List(Str) -> Str
	command =
		|
			args,
		| Str.join_with(args.map(|arg| if !arg.is_empty() and arg.to_utf8().all(safe_byte) arg else quote(arg)), " ")

	arguments : Request -> List(Str)
	arguments = |request| {
		base = match request {
			Request.Help(_) => ["day2", "app", "describe", "--help"]
			Request.Version(_) => ["day2", "--version"]
			Request.Describe(value) => {
				source = match value.source {
					Demo => ["--demo"]
					Instance(path) => ["--instance", path.to_str()]
					Environment => []
				}
				filter = match value.filter {
					All => []
					One(name) => ["--operation", name.to_str()]
				}
				["day2", "app", "describe", value.app_name.to_str()].concat(source).concat(filter)
			}
			Request.Check(value) => ["day2", "instance", "check", value.directory.to_str()]
			Request.Render(value) => ["day2", "instance", "render", value.directory.to_str()]
			Request.Roots(value) => [
				"day2",
				"instance",
				value.mode.name(),
				value.directory.to_str(),
				value.checkout.to_str(),
				value.output.to_str(),
			]
		}
		base.concat(
			match request_format(request) {
				Text => []
				Json => ["--agent"]
			},
		)
	}

	help = help_text
}

Raw : {
	source : [Unset, Demo, Instance(Names.LocalPath)],
	filter : [Unset, Set(Names.Operation)],
	intent : [Run, Help, Version],
	format : Cli.Format,
	positionals : List(Str),
}

instance : Str, Str, Raw -> Try(Cli.Instance, Problem)
instance = |verb, value, raw| {
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("instance ${verb} accepts only --agent or --json."))
	}
	directory =
		Names.LocalPath.from_str(value)
			.map_err(|_| Problem.InvalidArguments("instance ${verb} requires a directory of at most 4096 bytes"))?
	Ok(Cli.Instance.{ directory, format: raw.format })
}

roots : InstanceRender.Mode, Str, Str, Str, Raw -> Try(Cli.Roots, Problem)
roots = |mode, directory, checkout, output, raw| {
	verb = mode.name()
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("instance ${verb} accepts only --agent or --json."))
	}
	path = |value, role|
		Names.LocalPath.from_str(value)
			.map_err(|_| Problem.InvalidArguments("instance ${verb} requires ${role} of at most 4096 bytes"))
	Ok(
		Cli.Roots.{
			mode,
			directory: path(directory, "an instance directory")?,
			checkout: path(checkout, "a platform checkout")?,
			output: path(output, "a new output directory")?,
			format: raw.format,
		},
	)
}

## The instance verb follows the family, after any flags.
instance_command : List(Str) -> Cli.Command
instance_command = |args| match args {
	["--instance", _, .. as rest] | ["--operation", _, .. as rest] => instance_command(rest)
	["render", ..] => Cli.Command.InstanceRender
	["plan", ..] => Cli.Command.InstancePlan
	["apply", ..] => Cli.Command.InstanceApply
	[arg, .. as rest] if arg.starts_with("-") => instance_command(rest)
	_ => Cli.Command.InstanceCheck
}

has_options : Raw -> Bool
has_options = |raw| match (raw.source, raw.filter) {
	(Unset, Unset) => Bool.False
	_ => Bool.True
}

scan : List(Str), Raw -> Try(Raw, Problem)
scan = |args, raw| match args {
	[] => Ok(raw)
	["--agent", .. as rest] | ["--json", .. as rest] => scan(rest, { ..raw, format: Cli.Format.Json })
	["--help", .. as rest] | ["-h", .. as rest] => match raw.intent {
		Version => Err(Problem.ConflictingOptions("Choose either --help or --version."))
		_ => scan(rest, { ..raw, intent: Help })
	}
	["--version", .. as rest] => match raw.intent {
		Help => Err(Problem.ConflictingOptions("Choose either --help or --version."))
		_ => scan(rest, { ..raw, intent: Version })
	}
	["--demo", .. as rest] => match raw.source {
		Unset => scan(rest, { ..raw, source: Demo })
		Demo => Err(Problem.DuplicateOption("--demo"))
		Instance(_) => Err(Problem.ConflictingOptions("Choose one source: --demo or --instance."))
	}
	["--instance", value, .. as rest] => set_option("--instance", value, rest, raw)
	["--operation", value, .. as rest] => set_option("--operation", value, rest, raw)
	["--instance"] => Err(Problem.MissingOptionValue("--instance"))
	["--operation"] => Err(Problem.MissingOptionValue("--operation"))
	[arg, .. as rest] if arg
		.starts_with("--instance=") => set_option("--instance", arg.drop_prefix("--instance="), rest, raw)
	[arg, .. as rest] if arg
		.starts_with("--operation=") => set_option("--operation", arg.drop_prefix("--operation="), rest, raw)
	[arg, .. as rest] => if
		arg.starts_with("-")
		Err(Problem.UnknownOption(arg))
	else
		scan(rest, { ..raw, positionals: raw.positionals.append(arg) })
}

set_option : Str, Str, List(Str), Raw -> Try(Raw, Problem)
set_option = |flag, value, rest, raw| {
	if value.is_empty() or value.starts_with("-") {
		return Err(Problem.MissingOptionValue(flag))
	}
	if flag == "--instance" {
		match raw.source {
			Unset => {
				path =
					Names.LocalPath.from_str(value)
						.map_err(
							|_| Problem.InvalidArguments("--instance requires a nonblank path of at most 4096 bytes"),
						)?
				scan(rest, { ..raw, source: Instance(path) })
			}
			Demo => Err(Problem.ConflictingOptions("Choose one source: --demo or --instance."))
			Instance(_) => Err(Problem.DuplicateOption(flag))
		}
	} else {
		match raw.filter {
			Unset => {
				name = Names.Operation.from_str(value).map_err(|_| Problem.InvalidOperationName(value))?
				scan(rest, { ..raw, filter: Set(name) })
			}
			Set(_) => Err(Problem.DuplicateOption(flag))
		}
	}
}

safe_byte : U8 -> Bool
safe_byte =
	|
		byte,
	|
		(byte >= 'a' and byte <= 'z')
			or (byte >= 'A' and byte <= 'Z') or (byte >= '0' and byte <= '9') or [45, 95, 46, 47].contains(byte)

expect match Cli.parse(["--operation", "links.list"]) {
	Err(Problem.MissingCommand) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["--help", "--version"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["app", "describe", "links", "--demo", "--instance", "a.json"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["--agent", "app", "describe", "links", "--instance=a b.json"]) {
	Ok(Cli.Request.Describe(value)) => match value.parts().source {
		Cli.Source.Instance(path) => path.to_str() == "a b.json"
		_ => Bool.False
	}
	_ => Bool.False
}
expect Cli.quote("a'b") == "'a'\"'\"'b'"
expect match Cli.parse(["instance", "check", ".", "--agent"]) {
	Ok(Cli.Request.Check(value)) => value.parts().directory.to_str() == "."
	_ => Bool.False
}
expect match Cli.parse(["instance", "check", ".", "--demo"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["instance", "check"]) {
	Err(Problem.MissingArgument) => Bool.True
	_ => Bool.False
}
expect Cli.requested(["--agent", "instance", "check", "."]).name() == "instance.check"
expect Cli.requested(["instance", "--agent", "render", "."]).name() == "instance.render"
expect Cli.requested(["instance", "--operation", "render", "check", "."]).name() == "instance.check"
expect match Cli.parse(["instance", "render", "../acme", "--json"]) {
	Ok(Cli.Request.Render(value)) => value.parts().directory.to_str() == "../acme"
	_ => Bool.False
}
expect match Cli.parse(["instance", "render", ".", "--operation", "x"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["instance", "render"]) {
	Err(Problem.MissingArgument) => Bool.True
	_ => Bool.False
}
expect Cli.requested(["--operation", "instance", "app", "describe", "links"]).name() == "app.describe"
