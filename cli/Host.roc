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

	call! : Str => Try(Str, Str)
	call! = |request| {
		executable = Env.exe_path!().map_err(|_| "cannot locate platform CLI")?
		text = Path.to_str(executable).map_err(|_| "CLI path must be UTF-8")?
		directory = Str.join_with(text.split_on("/").drop_last(1), "/")
		command = Cmd.new(OsStr.from_str("${directory}/day2-host")).args([OsStr.from_str(request)])
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
