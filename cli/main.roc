app [main!] {
	pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.28.1/7brgwR8YUqfeGrkdfF1V4GPPN7DnP7ftqub9KcrTEZtr.tar.zst",
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
import InstanceCandidate
import InstanceDeploy
import InstanceSelection
import InstanceCiWorkflow
import CiCheck
import CiFetch
import CiReuse
import CiStore
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
		Cli.Request.Candidate(candidate) => candidated!(candidate)
		Cli.Request.Deploy(deploy) => deployed!(deploy)
		Cli.Request.Selection(selection) => selected!(selection)
		Cli.Request.CiCheck(check) => ci_checked!(check)
		Cli.Request.CiFetch(run) => ci_fetched!(run)
		Cli.Request.CiReuse(reuse) => ci_reused!(reuse)
		Cli.Request.CiStore(run) => ci_stored!(run)
		Cli.Request.CiWorkflow(render) => ci_workflow_rendered!(render)
	}
	emit!(Output.new(outcome))
}

## Validate and render the spec here, then plan or apply its core roots through the platform host, which checks the
## request again before it runs OpenTofu.
ran! : Cli.Roots => Output.Outcome
ran! = |roots| {
	parts = roots.parts()
	failed = |problem| Output.Outcome.Failed(problem, parts.format, roots.reported_command())
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
	failed = |problem| Output.Outcome.Failed(problem, parts.format, release.reported_command())
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
	failed = |problem| Output.Outcome.Failed(problem, parts.format, source.reported_command())
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

## Validate the spec (except on the build host, whose commands read only their job directory) and derive the instance
## names here, then run the candidate command through the platform host, which checks the request again. A retryable
## forge read exits 7; any other refusal exits 6.
candidated! : Cli.CandidateRequest => Output.Outcome
candidated! = |candidate| {
	parts = candidate.parts()
	verb = parts.action.verb()
	failed = |problem| Output.Outcome.Failed(problem, parts.format, candidate.reported_command())
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
	request = InstanceCandidate.request(spec, parts.action)
	# The request travels as a private temporary file, as source requests do.
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, request).map_err(|_| "cannot write the candidate ${verb} request")?
			Host.instance_candidate!(verb, Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match InstanceCandidate.receipt(raw, parts.action) {
			Ok(report) => Output.Outcome.Candidated(candidate, path, report)
			Err(_) => failed(Problem.CandidateFailed("the platform host returned an unreadable receipt"))
		}
		Err(CallbackErr(error)) => failed(InstanceCandidate.problem(error))
		Err(_) => failed(Problem.CandidateFailed("cannot use a private temporary directory"))
	}
}

deployed! : Cli.Deploy => Output.Outcome
deployed! = |deploy| {
	failed = |problem| Output.Outcome.Failed(problem, deploy.format, Cli.Command.InstanceDeploy)
	(path, spec) = match InstanceSpec.load!(deploy.directory) {
		Ok(loaded) => loaded
		Err(problem) => return failed(problem)
	}
	output = deploy.output.to_str()
	roots = match InstanceRender.deploy_request(
		spec,
		deploy.app_id,
		deploy.candidate.to_str(),
		{
			instance: deploy.directory.to_str(),
			checkout: deploy.checkout.to_str(),
			output: "${output}/roots",
		},
	) {
		Ok(request) => request
		Err(UnknownApp(app_id)) => return failed(Problem.InvalidSpec("the app ${app_id} is not in day2.json"))
	}
	request = InstanceDeploy.request(spec, deploy)
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "deploy.json")
			root_file = Path.join(directory, "roots.json")
			Path.write_utf8!(file, request).map_err(|_| "cannot write the deploy request")?
			Path.write_utf8!(root_file, roots).map_err(|_| "cannot write the deploy root request")?
			Host.instance_deploy!(
				Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?,
				Path.to_str(root_file).map_err(|_| "the temporary directory is not UTF-8")?,
			)
		},
	)
	match ran {
		Ok(raw) => match InstanceDeploy.receipt(raw, deploy.app_id) {
			Ok(report) => Output.Outcome.Deployed(deploy, path, report)
			Err(_) => failed(Problem.DeployFailed("the platform host returned an unreadable receipt"))
		}
		Err(CallbackErr(error)) => failed(InstanceDeploy.problem(error))
		Err(_) => failed(Problem.DeployFailed("cannot use a private temporary directory"))
	}
}

selected! : Cli.Selection => Output.Outcome
selected! = |selection| {
	failed = |problem| Output.Outcome.Failed(problem, selection.format, Cli.Command.InstanceSelection)
	(path, spec) = match InstanceSpec.load!(selection.directory) {
		Ok(found) => found
		Err(problem) => return failed(problem)
	}
	request = match InstanceSelection.request(spec, selection.app_id) {
		Ok(value) => value
		Err(problem) => return failed(problem)
	}
	match Host.instance_selection!(request) {
		Ok(raw) => match InstanceSelection.receipt(raw, selection.app_id) {
			Ok(value) => Output.Outcome.Selected(selection, path, value)
			Err(_) => failed(Problem.SelectionFailed("the platform host returned an unreadable selection receipt"))
		}
		Err(error) => failed(Problem.SelectionFailed(error))
	}
}

## Run an app repository's CI over local source trees through the platform host, which validates the request again.
## Any failure, including a lane's findings, exits 6 with the host's message.
ci_checked! : Cli.CiCheckRequest => Output.Outcome
ci_checked! = |check| {
	failed = |problem| Output.Outcome.Failed(problem, check.parts().format, Cli.Command.CiCheck)
	# The request travels as a private temporary file, as source requests do.
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, CiCheck.request(check)).map_err(|_| "cannot write the ci check request")?
			Host.ci!("check", Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match CiCheck.report(raw) {
			Ok(report) => Output.Outcome.CiChecked(check, report)
			Err(_) => failed(Problem.CiCheckFailed("the platform host returned an unreadable report"))
		}
		Err(CallbackErr(error)) => failed(CiCheck.problem(error))
		Err(_) => failed(Problem.CiCheckFailed("cannot use a private temporary directory"))
	}
}

## Fetch an app CI run's trees and record through the platform host, which reads the CI environment and the job token
## itself and validates the request again. Any failure exits 6 with the host's message.
ci_fetched! : Cli.CiRun => Output.Outcome
ci_fetched! = |run| {
	failed = |problem| Output.Outcome.Failed(problem, run.parts().format, Cli.Command.CiFetch)
	# The request travels as a private temporary file, as ci check requests do.
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, CiFetch.request(run)).map_err(|_| "cannot write the ci fetch request")?
			Host.ci!("fetch", Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match CiFetch.report(raw) {
			Ok(report) => Output.Outcome.CiFetched(run, report)
			Err(_) => failed(Problem.CiFetchFailed("the platform host returned an unreadable report"))
		}
		Err(CallbackErr(error)) => failed(CiFetch.problem(error))
		Err(_) => failed(Problem.CiFetchFailed("cannot use a private temporary directory"))
	}
}

## Look for an earlier main push run's stored result under this run's key through the platform host, which reads the CI
## environment, the job token and the store inputs itself and validates the request again. Finding nothing, a transient
## read or the deadline is reported and succeeds; misconfiguration exits 6.
ci_reused! : Cli.CiReuseRequest => Output.Outcome
ci_reused! = |reuse| {
	failed = |problem| Output.Outcome.Failed(problem, reuse.parts().format, Cli.Command.CiReuse)
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, CiReuse.request(reuse)).map_err(|_| "cannot write the ci reuse request")?
			Host.ci!("reuse", Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match CiReuse.report(raw) {
			Ok(report) => Output.Outcome.CiReused(reuse, report)
			Err(_) => failed(Problem.CiReuseFailed("the platform host returned an unreadable report"))
		}
		Err(CallbackErr(error)) => failed(CiReuse.problem(error))
		Err(_) => failed(Problem.CiReuseFailed("cannot use a private temporary directory"))
	}
}

## Validate the spec, have the platform host read the project number and each app's tooling image, then render app
## CI's org-scoped workflow here, purely. The host validates the request again.
ci_workflow_rendered! : Cli.Instance => Output.Outcome
ci_workflow_rendered! = |render| {
	parts = render.parts()
	failed = |problem| Output.Outcome.Failed(problem, parts.format, Cli.Command.InstanceCiWorkflow)
	(path, spec) = match InstanceSpec.load!(parts.directory) {
		Ok(loaded) => loaded
		Err(problem) => return failed(problem)
	}
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, InstanceCiWorkflow.request(spec))
				.map_err(|_| "cannot write the ci-workflow request")?
			Host.instance_ci_workflow!(Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match InstanceCiWorkflow.inputs(raw) {
			Ok(given) => match InstanceCiWorkflow.render(spec, given) {
				Ok(workflow) => Output.Outcome.CiWorkflowRendered(render, path, spec, workflow)
				Err(Unrendered(detail)) => failed(InstanceCiWorkflow.problem(detail))
			}
			Err(_) => failed(Problem.CiWorkflowFailed("the platform host returned unreadable inputs"))
		}
		Err(CallbackErr(error)) => failed(InstanceCiWorkflow.problem(error))
		Err(_) => failed(Problem.CiWorkflowFailed("cannot use a private temporary directory"))
	}
}

## Store an app CI run's checked artifact through the platform host, which reads the store inputs and the git-oidc
## request token itself and validates the request again. Any failure exits 6, so the required job fails.
ci_stored! : Cli.CiRun => Output.Outcome
ci_stored! = |run| {
	failed = |problem| Output.Outcome.Failed(problem, run.parts().format, Cli.Command.CiStore)
	ran = Env.with_temp_dir!(
		|directory| {
			file = Path.join(directory, "request.json")
			Path.write_utf8!(file, CiStore.request(run)).map_err(|_| "cannot write the ci store request")?
			Host.ci!("store", Path.to_str(file).map_err(|_| "the temporary directory is not UTF-8")?)
		},
	)
	match ran {
		Ok(raw) => match CiStore.report(raw) {
			Ok(report) => Output.Outcome.CiStored(run, report)
			Err(_) => failed(Problem.CiStoreFailed("the platform host returned an unreadable report"))
		}
		Err(CallbackErr(error)) => failed(CiStore.problem(error))
		Err(_) => failed(Problem.CiStoreFailed("cannot use a private temporary directory"))
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
