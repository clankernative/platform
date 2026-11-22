app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.26.0-rc2/Gj3zVDr3qrQa6aTh7Z1zgUfe9NeBE6R76T5ho3xrc8af.tar.zst",
	ops: "../ops/main.roc",
}

import pf.Env
import pf.Path
import pf.Stdout
import pf.Stderr
import pf.OsStr
import Cli
import Source
import Output
import Problem
import Host
import InstanceSpec
import InstanceRender
import InstanceRelease
import InstanceSource
import Names

main! : List(OsStr.OsStr) => Try({}, [Exit(I32)])
main! = |args| {
	format = Cli.output_format(args.map(OsStr.display))
	command = Cli.requested(args.map(OsStr.display))
	if args.len() > 128 {
		return emit!(
			Output.new(
				Output.Outcome.Failed(Problem.InvalidArguments("at most 128 arguments are supported"), format, command),
			),
		)
	}
	values = match decode_args(args, [], 0) {
		Ok(decoded) => decoded
		Err(problem) => return emit!(Output.new(Output.Outcome.Failed(problem, format, command)))
	}
	if values.first() == Ok("platform") {
		outcome = run_platform!(values.drop_first(1))
		match outcome {
			Ok(body) => {
				if !body.is_empty() {
					Stdout.line!(body).map_err(|_| Exit(1))?
				}
				return Ok({})
			}
			Err(error) => {
				Stderr.line!(Output.safe(error)).map_err(|_| Exit(1))?
				return Err(Exit(2))
			}
		}
	}
	parsed = Cli.parse(values)
	request = match parsed {
		Ok(value) => value
		Err(problem) => return emit!(Output.new(Output.Outcome.Failed(problem, format, command)))
	}
	outcome = match request {
		Cli.Request.Help(value) => Output.Outcome.Help(value)
		Cli.Request.Version(value) => Output.Outcome.Version(value)
		Cli.Request.Describe(description) => match Source.load!(description) {
			Ok(loaded) => Output.Outcome.Described(loaded)
			Err(problem) => Output.Outcome.Failed(problem, description.parts().format, Cli.Command.AppDescribe)
		}
		Cli.Request.Check(check) => match InstanceSpec.load!(check.parts().directory) {
			Ok((path, spec)) => Output.Outcome.Checked(check, path, spec)
			Err(problem) => Output.Outcome.Failed(problem, check.parts().format, Cli.Command.InstanceCheck)
		}
		Cli.Request.Render(render) => match InstanceSpec.load!(render.parts().directory) {
			Ok((path, spec)) => Output.Outcome.Rendered(render, path, spec)
			Err(problem) => Output.Outcome.Failed(problem, render.parts().format, Cli.Command.InstanceRender)
		}
		Cli.Request.Roots(roots) => ran!(roots)
		Cli.Request.Release(release) => released!(release)
		Cli.Request.Source(source) => sourced!(source)
	}
	emit!(Output.new(outcome))
}

## Validate and render the spec here, then plan or apply its core roots through the platform host, which checks the
## request again before it runs OpenTofu.
ran! : Cli.Roots => Output.Outcome
ran! = |roots| {
	parts = roots.parts()
	failed = |problem| Output.Outcome.Failed(problem, parts.format, roots.command())
	broken = |detail| failed(Output.roots_failed(parts.mode, detail))
	match InstanceSpec.load!(parts.directory) {
		Ok((path, spec)) => {
			request = InstanceRender.request(
				spec,
				parts.mode,
				{
					instance: parts.directory.to_str(),
					checkout: parts.checkout.to_str(),
					output: parts.output.to_str(),
				},
			)
			# The request can exceed an argument's size, so it travels as a private temporary file.
			ran = Env.with_temp_dir!(
				|directory| {
					file = Path.join(directory, "request.json")
					Path.write_utf8!(file, request).map_err(|_| "cannot write the ${parts.mode.name()} request")?
					Host.instance_roots!(
						parts.mode,
						Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?,
					)
				},
			)
			match ran {
				Ok(raw) => match InstanceRender.receipt(raw, parts.mode) {
					Ok(receipt) => Output.Outcome.Ran(roots, path, spec, receipt)
					Err(_) => broken("the platform host returned an unreadable receipt")
				}
				Err(CallbackErr(error)) => broken(error)
				Err(_) => broken("cannot use a private temporary directory")
			}
		}
		Err(problem) => failed(problem)
	}
}

## Validate the spec and derive its bucket and registry here, then publish or fetch the release through the platform
## host, which checks the request again before it runs gcloud or docker.
released! : Cli.Release => Output.Outcome
released! = |release| {
	parts = release.parts()
	verb = parts.action.verb()
	failed = |problem| Output.Outcome.Failed(problem, parts.format, release.command())
	match InstanceSpec.load!(parts.directory) {
		Ok((path, spec)) => {
			request = InstanceRelease.request(spec, parts.action)
			# The request travels as a private temporary file, as plan and apply requests do.
			ran = Env.with_temp_dir!(
				|directory| {
					file = Path.join(directory, "request.json")
					Path.write_utf8!(file, request).map_err(|_| "cannot write the release ${verb} request")?
					Host.instance_release!(verb, Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
				},
			)
			match ran {
				Ok(raw) => match InstanceRelease.receipt(raw, parts.action) {
					Ok(receipt) => Output.Outcome.Released(release, path, spec, receipt)
					Err(_) => failed(Problem.ReleaseFailed("the platform host returned an unreadable receipt"))
				}
				Err(CallbackErr(error)) => failed(Problem.ReleaseFailed(error))
				Err(_) => failed(Problem.ReleaseFailed("cannot use a private temporary directory"))
			}
		}
		Err(problem) => failed(problem)
	}
}

## Validate the spec (except for `controls`, which reads only an archive) and derive the instance names here, then run
## the source command through the platform host, which checks the request and the binding again before it reads the
## forge. A retryable failure exits 7; any other refusal exits 6.
sourced! : Cli.SourceRequest => Output.Outcome
sourced! = |source| {
	parts = source.parts()
	verb = parts.action.verb()
	failed = |problem| Output.Outcome.Failed(problem, parts.format, source.command())
	none : Try(Names.LocalPath, [Null])
	none = Err(Null)
	unread : Try(InstanceSpec, [Null])
	unread = Err(Null)
	(path, spec) = match parts.action.directory() {
		Ok(directory) => match InstanceSpec.load!(directory) {
			Ok((loaded, checked)) => (Ok(loaded), Ok(checked))
			Err(problem) => return failed(problem)
		}
		Err(Null) => (none, unread)
	}
	request = InstanceSource.request(spec, parts.action)
	# The request travels as a private temporary file, as release requests do.
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, request).map_err(|_| "cannot write the source ${verb} request")?
			Host.instance_source!(verb, Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match InstanceSource.receipt(raw, parts.action) {
			Ok(report) => Output.Outcome.Sourced(source, path, report)
			Err(_) => failed(Problem.SourceFailed("the platform host returned an unreadable receipt"))
		}
		Err(CallbackErr(error)) => failed(InstanceSource.problem(error))
		Err(_) => failed(Problem.SourceFailed("cannot use a private temporary directory"))
	}
}

run_platform! : List(Str) => Try(Str, Str)
run_platform! = |args| {
	if args.any(|arg| arg.to_utf8().any(|byte| byte < 32 or byte == 127)) {
		return Err("control characters are unsupported")
	}
	Host.workflow!(args)
}

decode_args : List(OsStr.OsStr), List(Str), U64 -> Try(List(Str), Problem)
decode_args = |args, done, bytes| match args {
	[] => Ok(done)
	[first, .. as rest] => {
		value = OsStr.to_str_try(first).map_err(|_| Problem.InvalidArguments("arguments must be valid UTF-8 text"))?
		count = bytes + value.count_utf8_bytes()
		if count > 16_384 {
			return Err(Problem.InvalidArguments("at most 16 KiB of arguments are supported"))
		}
		decode_args(rest, done.append(value), count)
	}
}

emit! : Output => Try({}, [Exit(I32)])
emit! = |response| {
	match response.stream() {
		Stdout => Stdout.line!(response.body()).map_err(|_| Exit(1))?
		Stderr => Stderr.line!(response.body()).map_err(|_| Exit(1))?
	}
	code = response.exit_code()
	if code == 0 Ok({}) else Err(Exit(code))
}
