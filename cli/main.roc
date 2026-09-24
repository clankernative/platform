app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.22.0/F1JVZPYfWP71s8vk6tHcV1Qx1Ef6CZkwswGoCn8VHZmL.tar.zst",
	ops: "../ops/main.roc",
}

import pf.Stdout
import pf.Stderr
import pf.OsStr
import Cli
import Source
import Output
import Problem
import Host

main! : List(OsStr.OsStr) => Try({}, [Exit(I32)])
main! = |raw_args| {
	args = raw_args.drop_first(1)
	format = Cli.output_format(args.map(OsStr.display))
	if args.len() > 128 {
		return emit!(
			Output.new(Output.Outcome.Failed(Problem.InvalidArguments("at most 128 arguments are supported"), format)),
		)
	}
	values = match decode_args(args, [], 0) {
		Ok(decoded) => decoded
		Err(problem) => return emit!(Output.new(Output.Outcome.Failed(problem, format)))
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
		Err(problem) => return emit!(Output.new(Output.Outcome.Failed(problem, format)))
	}
	outcome = match request {
		Cli.Request.Help(value) => Output.Outcome.Help(value)
		Cli.Request.Version(value) => Output.Outcome.Version(value)
		Cli.Request.Describe(description) => match Source.load!(description) {
			Ok(loaded) => Output.Outcome.Described(loaded)
			Err(problem) => Output.Outcome.Failed(problem, description.parts().format)
		}
	}
	emit!(Output.new(outcome))
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
