app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.22.0/F1JVZPYfWP71s8vk6tHcV1Qx1Ef6CZkwswGoCn8VHZmL.tar.zst",
	ops: "main.roc",
}

import pf.OsStr
import pf.Stdin
import pf.Stdout
import ops.Workflow
import ops.LocalDev
import ops.Build
import ops.Check
import ops.Ci
import ops.Verify
import ops.Linux
import ops.Provision
import ops.Simulation
import ops.ProviderConformance
import ops.Release
import ops.SecretRetirement

# Only the native supervisor launches this executable. Its stdout is a bounded
# request/response pipe, never a terminal or an app-accessible effect channel.
Response : { protocol : U32, ok : Bool, result : Str, error : Str }

call! : Str => Try(Str, Str)
call! = |request| {
	Stdout.line!(request).map_err(|_| "supervisor pipe closed")?
	raw = Stdin.line!().map_err(|_| "supervisor response missing")?
	response : Response
	response = Json.parse(raw).map_err(|_| "invalid supervisor response")?
	if response.protocol != 1 {
		return Err("incompatible supervisor")
	}
	if response.ok Ok(response.result) else Err(response.error)
}

run! : List(Str) => Try(Str, Str)
run! = |args| match args {
	["platform", .. as rest] => Workflow.run!(Workflow.parse(rest)?, call!)
	["local-dev-session", raw] => {
		options : LocalDev.Options
		options = Json.parse(raw).map_err(|_| "invalid local session settings")?
		LocalDev.session!(options, call!)
	}
	["build-recipe"] => Build.recipe!(call!)
	["exercise", example, count] => Check.exercise!(example, U64.from_str(count).map_err(|_| "invalid count")?, call!)
	["ci-event", event_name, action, deleted] => {
		should_run = Ci.event(event_name, action, deleted == "true")?
		Ok(Json.to_str({ run: should_run }))
	}
	["ci-recipe"] => Ci.run!(call!)
	["simulate-control", seed, count] => Simulation.campaign!(
		U64.from_str(seed).map_err(|_| "invalid simulation seed")?,
		U32.from_str(count).map_err(|_| "invalid simulation count")?,
		call!,
	)
	["replay-control", trace] => Simulation.replay!(trace, call!)
	["provider-conformance"] => ProviderConformance.run!(call!)
	["release-step", snapshot] => Release.run(snapshot)
	["secret-retirement-step", snapshot] => SecretRetirement.run(snapshot)
	["cli"] => Verify.cli!(call!)
	["verify-fast"] => Verify.fast!(call!)
	["verify-reports"] => Verify.reports!(call!)
	["verify"] => Verify.all!(call!)
	["qualify-linux"] => Linux.run!(call!)
	["strict-linux"] => Linux.strict!(call!)
	["provision-linux"] => Provision.smoke!(call!)
	["control-verify"] => Verify.control!(call!)
	_ => Err("unknown private workflow")
}

main! : List(OsStr.OsStr) => Try({}, [Exit(I32)])
main! = |args| {
	outcome = run!(args.drop_first(1).map(OsStr.display))
	message = match outcome {
		Ok(result) => { protocol: 1.U32, action: "complete", input: result }
		Err(error) => { protocol: 1.U32, action: "failed", input: error }
	}
	Stdout.line!(Json.to_str(message)).map_err(|_| Exit(1))
}
