import InstanceRender
import pf.Env
import pf.Path
import pf.Cmd
import pf.OsStr

# The native broker is distributed beside this CLI. Never resolve it from PATH
# or a project-controlled executable name. Its protocol is private and versioned.
Host :: [].{
	Response : { protocol : U32, ok : Bool, result : Str, error : Str }

	Request : { protocol : U32, action : Str, input : Str }

	workflow! : List(Str) => Try(Str, Str)
	workflow! = |args| {
		call!(Json.to_str({ protocol: 1.U32, action: "workflow", input: Json.to_str(args) }))
	}

	## `day2 instance plan|apply`: the action fixes the mode; the host reads the rendered request from this file and
	## validates it again, including that it asks for the same mode.
	instance_roots! : InstanceRender.Mode, Str => Try(Str, Str)
	instance_roots! = |mode, request| {
		call!(
			Json.to_str(
				{ protocol: 1.U32, action: "instance-${mode.name()}", input: Json.to_str({ request: request }) },
			),
		)
	}

	## `day2 instance release publish|fetch`: as for plan and apply, the action fixes the mode and the host reads the
	## rendered request from this file and validates it again.
	instance_release! : Str, Str => Try(Str, Str)
	instance_release! = |verb, request| {
		call!(
			Json.to_str(
				{ protocol: 1.U32, action: "instance-release-${verb}", input: Json.to_str({ request: request }) },
			),
		)
	}

	## `day2 instance source`: as for release, the action fixes the mode and the host reads the rendered request from
	## this file and validates it again. The host's progress, such as the wait for a main CI run, goes to stderr.
	instance_source! : Str, Str => Try(Str, Str)
	instance_source! = |verb, request| {
		exchange!(
			Json.to_str(
				{ protocol: 1.U32, action: "instance-source-${verb}", input: Json.to_str({ request: request }) },
			),
			Progress,
		)
	}

	## `day2 instance candidate`: as for source, the action fixes the mode and the host reads the rendered request from
	## this file and validates it again. The host's progress, such as a build's evidence line, goes to stderr.
	instance_candidate! : Str, Str => Try(Str, Str)
	instance_candidate! = |verb, request| {
		exchange!(
			Json.to_str(
				{ protocol: 1.U32, action: "instance-candidate-${verb}", input: Json.to_str({ request: request }) },
			),
			Progress,
		)
	}

	instance_selection! : Str => Try(Str, Str)
	instance_selection! = |request| call!(
		Json.to_str({
			protocol: 1.U32,
			action: "instance-selection",
			input: request,
		}),
	)

	## A deploy owns one deploy session and one day2-app root. Both requests travel as private files.
	instance_deploy! : Str, Str => Try(Str, Str)
	instance_deploy! = |request, roots| {
		exchange!(
			Json.to_str({
				protocol: 1.U32,
				action: "instance-deploy",
				input: Json.to_str({ request: request, roots: roots }),
			}),
			Progress,
		)
	}

	## `day2 instance ci-workflow`: the host reads the project number and each app's tooling image the rendered
	## workflow needs, under the names in the request file, which it validates again.
	instance_ci_workflow! : Str => Try(Str, Str)
	instance_ci_workflow! = |request| {
		call!(
			Json.to_str({ protocol: 1.U32, action: "instance-ci-workflow", input: Json.to_str({ request: request }) }),
		)
	}

	## `day2 ci check|fetch|store`: the action starts that CI session; the host reads the request from this file and
	## validates it again. The host's progress goes to stderr.
	ci! : Str, Str => Try(Str, Str)
	ci! = |verb, request| {
		exchange!(
			Json.to_str({ protocol: 1.U32, action: "ci-${verb}", input: Json.to_str({ request: request }) }),
			Progress,
		)
	}

	call! : Str => Try(Str, Str)
	call! = |request| exchange!(request, Quiet)

	exchange! : Str, [Quiet, Progress] => Try(Str, Str)
	exchange! = |request, progress| {
		executable = Env.exe_path!().map_err(|_| "cannot locate platform CLI")?
		text = Path.to_str(executable).map_err(|_| "CLI path must be UTF-8")?
		directory = Str.join_with(text.split_on("/").drop_last(1), "/")
		host = Cmd.new(OsStr.from_str("${directory}/day2-host")).args([OsStr.from_str(request)])
		command = match progress {
			Quiet => host
			Progress => host.stderr(Inherit)
		}
		decoded : Request
		decoded = Json.parse(request).map_err(|_| "invalid host request")?
		streaming = if decoded.action == "workflow" {
			values : List(Str)
			values = Json.parse(decoded.input).map_err(|_| "invalid workflow arguments")?
			values.first() == Ok("local-dev")
				or (values.first() == Ok("authority") and values.drop_first(1).first() == Ok("admin"))
					or values.first() == Ok("maintain")
		} else Bool.False
		if streaming {
			# The host has already written its own error to the terminal.
			result = command.inherit_stdio().run!().map_err(|_| "cannot start the platform host; run xtask cli")?
			return if result.status == Exited(0) Ok("") else Err("platform workflow failed")
		}
		result = command.run!().map_err(|_| "cannot start platform host; run xtask cli")?
		_ = result.require_success().map_err(|_| "cannot start platform host; run xtask cli")?
		raw = result.stdout_utf8().map_err(|_| "invalid platform host response")?
		response : Response
		response = Json.parse(raw).map_err(|_| "invalid platform host response")?
		if response.protocol != 1 {
			return Err("incompatible platform host protocol")
		}
		if response.ok Ok(response.result) else Err(response.error)
	}
}
