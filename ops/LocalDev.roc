import Build
import Check
import Capability

# Session policy is Roc. Native capabilities hold the managed directory lock,
# supervise HTTP/commands, watch admitted source files and protect database cutovers.
LocalDev :: [].{
	Options : {
		source : Str,
		directory : Str,
		action : Str,
		example : Str,
		generated : U64,
		seed : Str,
		actor : Str,
		port : Str,
		watch : Str,
		reset : Bool,
		backup : Str,
		detach : Bool,
		data_requested : Bool,
	}

	defaults : Options
	defaults =
		{
			source: ".",
			directory: "",
			action: "start",
			example: "",
			generated: 0,
			seed: "3664912422",
			actor: "",
			port: "",
			watch: "",
			reset: Bool.False,
			backup: "",
			detach: Bool.False,
			data_requested: Bool.False,

		}

	parse : List(Str) -> Try(Options, Str)
	parse = |args| match args {
		[source, .. as rest] if !source.starts_with("--") => flags(rest, { ..defaults, source }, [])
		_ => flags(args, defaults, [])
	}

	flags : List(Str), Options, List(Str) -> Try(Options, Str)
	flags = |args, options, seen| match args {
		[] => {
			if
				options.action
					!= "start"
					and (options.data_requested
						or options.reset
							or options.detach
								or !options.actor.is_empty() or !options.port.is_empty() or !options.watch.is_empty())
					{
						return Err("lifecycle commands cannot change development settings")
					}
			Ok(options)
		}
		[flag, .. as rest] => {
			if seen.contains(flag) {
				return Err(Str.join_with(["duplicate local-dev option: ", flag], ""))
			}
			next = seen.append(flag)
			match flag {
				"--help" => flags(rest, { ..options, action: "help" }, next)
				"--status" | "--stop" | "--logs" | "--follow" => {
					if options.action != "start" {
						return Err("choose one lifecycle command")
					}
					flags(rest, { ..options, action: flag.drop_prefix("--") }, next)
				}
				"--detach" => flags(rest, { ..options, detach: Bool.True }, next)
				"--reset" => flags(rest, { ..options, reset: Bool.True }, next)
				"--no-watch" => flags(rest, { ..options, watch: "off" }, next)
				"--empty" => {
					if options.data_requested {
						return Err("choose empty, example, generated or backup data")
					}
					flags(rest, { ..options, data_requested: Bool.True }, next)
				}
				"--directory"
				| "--actor"
				| "--port"
				| "--example"
				| "--generated"
				| "--seed"
				| "--backup" => match rest {
					[value, .. as remaining] if !value.is_empty() and !value.starts_with("--") => {
						if ["--example", "--generated", "--backup"].contains(flag) and options.data_requested {
							return Err("choose empty, example, generated or backup data")
						}
						updated = match flag {
							"--directory" => { ..options, directory: value }
							"--actor" => { ..options, actor: value }
							"--port" => {
								port = U64.from_str(value).map_err(|_| "port must be 0..65535")?
								if port > 65_535 {
									return Err("port must be 0..65535")
								}
								{ ..options, port: port.to_str() }
							}
							"--example" => { ..options, example: value, data_requested: Bool.True }
							"--backup" => { ..options, backup: value, data_requested: Bool.True }
							"--generated" => {
								count = U64.from_str(value).map_err(|_| "generated count must be 1..100")?
								if count < 1 or count > 100 {
									return Err("generated count must be 1..100")
								}
								{ ..options, generated: count, data_requested: Bool.True }
							}
							_ => {
								seed = U64.from_str(value).map_err(|_| "seed must be a U64")?
								{ ..options, seed: seed.to_str() }
							}
						}
						flags(remaining, updated, next)
					}
					_ => Err(Str.join_with(["missing value for ", flag], ""))
				}
				_ => Err(Str.join_with(["unsupported local-dev option: ", flag], ""))
			}
		}
	}

	run! : List(Str), (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |args, host!| {
		# Keep the original explicit disposable invocation compatible.
		match args {
			[source, output, example] if !source.starts_with("--")
				and !output.starts_with("--") and !example.starts_with("--") => {
				built = Build.source!(source, host!)?
				_ = Check.campaign!({ artifact: built.artifact, output, example, seed: "3664912422", count: 0 }, host!)?
				return Capability.call!("dev-serve", "{}", host!)
			}
			_ => {}
		}
		options = parse(args)?
		if options.action == "help" {
			return Ok(
				Json.to_str({
					usage: "day2 platform local-dev [SOURCE] [OPTIONS]",
					options: [
						"--example NAME | --generated COUNT [--seed SEED] | --empty | --backup DIRECTORY",
						"--directory DIRECTORY",
						"--actor NAME",
						"--port PORT",
						"--reset",
						"--no-watch",
						"--detach",
						"--status | --stop | --logs | --follow",
					],
					defaults: "current app directory; empty on first launch; preserve data on restart; watch app edits; loopback HTTP",
				}),
			)
		}
		raw = Capability.call!("local-resolve", Json.to_str(options), host!)?
		resolved : Options
		resolved = Json.parse(raw).map_err(|_| "invalid local settings")?
		match resolved.action {
			"status" => Capability.call!("local-status", "{}", host!)
			"stop" => Capability.call!("local-stop", "{}", host!)
			"logs" => Capability.call!("local-logs", "{}", host!)
			"follow" => Capability.call!("local-follow", "{}", host!)
			_ => if resolved.detach {
				Capability.call!("local-launch", Json.to_str({ ..resolved, detach: Bool.False }), host!)
			} else session!(resolved, host!)
		}
	}

	session! : Options, (Str => Try(Str, Str)) => Try(Str, Str)
	session! = |options, host!| {
		raw = Capability.call!("local-prepare", "{}", host!)?
		prepared : { running : Bool }
		prepared = Json.parse(raw).map_err(|_| "invalid local session")?
		if prepared.running {
			return Capability.call!("local-status", "{}", host!)
		}
		built = Build.source!(options.source, host!)?
		opened = Capability.call!("local-open", Json.to_str(built), host!)?
		state : { fresh : Bool }
		state = Json.parse(opened).map_err(|_| "invalid local instance")?
		if state.fresh {
			if !options.backup.is_empty() {
				_ = Capability.call!("local-import", "{}", host!)?
			} else if !options.example.is_empty() or options.generated > 0 {
				_ = Capability.call!("local-campaign", "{}", host!)?
				_ = Check.exercise!(options.example, options.generated, host!)?
			}
		} else {
			_ = Capability.call!("local-drain", "{}", host!)?
			_ = Capability.call!("local-snapshot", "{}", host!)?
			_ = Capability.call!("local-migrate", Json.to_str(built), host!)?
		}
		_ = Capability.call!("local-properties", "{}", host!)?
		_ = Capability.call!("local-activate", "{}", host!)?
		while Bool.True {
			event = Capability.call!("local-wait", "{}", host!)?
			change : { changed : Bool, stopped : Bool }
			change = Json.parse(event).map_err(|_| "invalid local event")?
			if change.stopped {
				break
			}
			if change.changed {
				match rebuild!(options.source, host!) {
					Ok(_) => {}
					Err(error) => {
						_ = Capability.call!(
							"local-error",
							Json.to_str(
								{
									error
								},
							),
							host!,
						)?
						_ = Capability.call!("local-recover", "{}", host!)?
					}
				}
			}
		}
		Capability.call!("local-shutdown", "{}", host!)
	}

	rebuild! : Str, (Str => Try(Str, Str)) => Try({}, Str)
	rebuild! = |source, host!| {
		built = Build.source!(source, host!)?
		_ = Capability.call!("local-pause", "{}", host!)?
		_ = Capability.call!("local-drain", "{}", host!)?
		_ = Capability.call!("local-snapshot", "{}", host!)?
		_ = Capability.call!("local-migrate", Json.to_str(built), host!)?
		_ = Capability.call!("local-properties", "{}", host!)?
		_ = Capability.call!("local-activate", "{}", host!)?
		Ok({})
	}
}

expect LocalDev.parse([]) == Ok(LocalDev.defaults)
expect LocalDev.parse(["--port", "70000"]).is_err()
expect LocalDev.parse(["--status", "--reset"]).is_err()
expect LocalDev.parse(["--example", "demo", "--empty"]).is_err()
