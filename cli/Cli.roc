import InstanceRender
import Names
import Problem
import "help.txt" as help_text : Str

Cli :: [].{
	Format := [Text, Json]

	Filter := [All, One(Names.Operation)]

	Source := [Demo, Instance(Names.LocalPath), Environment]

	Request := [
		Help(Format),
		Version(Format),
		Describe(Describe),
		Check(Instance),
		Render(Instance),
		Roots(Roots),
		Release(Release),
		Source(SourceRequest),
		Candidate(CandidateRequest),
		Deploy(Deploy),
		CiCheck(CiCheckRequest),
		CiFetch(CiRun),
		CiStore(CiRun),
		CiWorkflow(Instance),
	]

	## The command a response reports, including failures before a request exists.
	Command := [
		AppDescribe,
		InstanceCheck,
		InstanceRender,
		InstancePlan,
		InstanceApply,
		InstanceReleasePublish,
		InstanceReleaseFetch,
		InstanceSourceHead,
		InstanceSourceArchive,
		InstanceSourceControls,
		InstanceSourceVerifyControls,
		InstanceSourceCheckedArtifact,
		InstanceCandidateBuild,
		InstanceCandidatePreflight,
		InstanceCandidateCheck,
		InstanceCandidateNativeBuild,
		InstanceCandidateNativeProbe,
		InstanceDeploy,
		CiCheck,
		CiFetch,
		CiStore,
		InstanceCiWorkflow,
	].{
		name : Command -> Str
		name = |command| match command {
			AppDescribe => "app.describe"
			InstanceCheck => "instance.check"
			InstanceRender => "instance.render"
			InstancePlan => "instance.plan"
			InstanceApply => "instance.apply"
			InstanceReleasePublish => "instance.release.publish"
			InstanceReleaseFetch => "instance.release.fetch"
			InstanceSourceHead => "instance.source.head"
			InstanceSourceArchive => "instance.source.archive"
			InstanceSourceControls => "instance.source.controls"
			InstanceSourceVerifyControls => "instance.source.verify-controls"
			InstanceSourceCheckedArtifact => "instance.source.checked-artifact"
			InstanceCandidateBuild => "instance.candidate.build"
			InstanceCandidatePreflight => "instance.candidate.preflight"
			InstanceCandidateCheck => "instance.candidate.check"
			InstanceCandidateNativeBuild => "instance.candidate.native-build"
			InstanceCandidateNativeProbe => "instance.candidate.native-probe"
			InstanceDeploy => "instance.deploy"
			CiCheck => "ci.check"
			CiFetch => "ci.fetch"
			CiStore => "ci.store"
			InstanceCiWorkflow => "instance.ci-workflow"
		}
	}

	## day2 instance check|render DIRECTORY reads exactly DIRECTORY/day2.json.
	Instance :: { directory : Names.LocalPath, format : Format }.{
		parts : Instance -> { directory : Names.LocalPath, format : Format }
		parts = |request| { directory: request.directory, format: request.format }

		with_format : Instance, Format -> Instance
		with_format = |request, format| { ..request, format }
	}

	## day2 instance plan DIRECTORY PLATFORM NEW_DIRECTORY: a read-only plan of DIRECTORY's core roots, run in PLATFORM
	## (a checkout at day2.json's platform commit), with plans and logs in NEW_DIRECTORY. day2 instance apply DIRECTORY
	## PLATFORM PLAN_DIRECTORY NEW_DIRECTORY applies them, root by root, only as reviewed in PLAN_DIRECTORY, a prior
	## plan's output; its mode carries that directory.
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
			# The parser never builds a deploy here: a deploy's roots run inside its own command, which reports them.
			InstanceRender.Mode.Apply(_) | InstanceRender.Mode.Deploy => Command.InstanceApply
		}

		## The same instance, as `check` and `render` read it.
		instance : Roots -> Instance
		instance = |request| Instance.{ directory: request.directory, format: request.format }
	}

	## An approved release manifest, named by its digest and size.
	Reference : { digest : Str, bytes : U64 }

	## day2 instance release publish DIRECTORY REQUEST NEW_MANIFEST publishes the qualified SDK release REQUEST
	## describes into DIRECTORY's state bucket and writes its manifest to NEW_MANIFEST. day2 instance release fetch
	## DIRECTORY DIGEST BYTES fetches and verifies the approved release DIGEST into the local release cache.
	ReleaseAction := [Publish({ request : Names.LocalPath, output : Names.LocalPath }), Fetch(Reference)].{
		verb : ReleaseAction -> Str
		verb = |action| match action {
			Publish(_) => "publish"
			Fetch(_) => "fetch"
		}
	}

	Release :: { action : ReleaseAction, directory : Names.LocalPath, format : Format }.{
		parts : Release -> { action : ReleaseAction, directory : Names.LocalPath, format : Format }
		parts = |request| { action: request.action, directory: request.directory, format: request.format }

		with_format : Release, Format -> Release
		with_format = |request, format| { ..request, format }

		## The same instance fetching an approved release, such as the one just published.
		fetching : Release, Reference -> Release
		fetching = |request, reference| { ..request, action: ReleaseAction.Fetch(reference) }

		## The command a response reports.
		command : Release -> Command
		command = |request| match request.action {
			ReleaseAction.Publish(_) => Command.InstanceReleasePublish
			ReleaseAction.Fetch(_) => Command.InstanceReleaseFetch
		}

		## The same instance, as `check` and `render` read it.
		instance : Release -> Instance
		instance = |request| Instance.{ directory: request.directory, format: request.format }
	}

	## A source command and its paths. BINDING is the file holding the deploy controller's source binding for the app;
	## COMMIT is a full lowercase commit and INPUTS the checked source inputs, sha256:<hex>.
	## - head DIRECTORY BINDING: the bound branch's commit.
	## - archive DIRECTORY BINDING COMMIT NEW_ARCHIVE: the commit's archive, written to NEW_ARCHIVE.
	## - controls ARCHIVE: the CI-control digest of a source archive.
	## - verify-controls DIRECTORY BINDING ARCHIVE: ARCHIVE's controls against the binding and its qualified release.
	## - checked-artifact DIRECTORY BINDING COMMIT INPUTS NEW_ARCHIVE: the checked artifact of COMMIT's main CI run,
	##   written to NEW_ARCHIVE, and its provenance.
	SourceAction := [
		Head({ directory : Names.LocalPath, binding : Names.LocalPath }),
		Archive({ directory : Names.LocalPath, binding : Names.LocalPath, commit : Str, output : Names.LocalPath }),
		Controls(Names.LocalPath),
		VerifyControls({ directory : Names.LocalPath, binding : Names.LocalPath, archive : Names.LocalPath }),
		CheckedArtifact(
			{
				directory : Names.LocalPath,
				binding : Names.LocalPath,
				commit : Str,
				inputs : Str,
				output : Names.LocalPath,
			},
		),
	].{
		verb : SourceAction -> Str
		verb = |action| match action {
			Head(_) => "head"
			Archive(_) => "archive"
			Controls(_) => "controls"
			VerifyControls(_) => "verify-controls"
			CheckedArtifact(_) => "checked-artifact"
		}

		## The instance directory whose day2.json a command validates; `controls` reads none.
		directory : SourceAction -> Try(Names.LocalPath, [Null])
		directory = |action| match action {
			Head(paths) => Ok(paths.directory)
			Archive(paths) => Ok(paths.directory)
			Controls(_) => Err(Null)
			VerifyControls(paths) => Ok(paths.directory)
			CheckedArtifact(paths) => Ok(paths.directory)
		}

		## The command's arguments after its verb.
		arguments : SourceAction -> List(Str)
		arguments = |action| match action {
			Head(paths) => [paths.directory.to_str(), paths.binding.to_str()]
			Archive(paths) => [paths.directory.to_str(), paths.binding.to_str(), paths.commit, paths.output.to_str()]
			Controls(archive) => [archive.to_str()]
			VerifyControls(paths) => [paths.directory.to_str(), paths.binding.to_str(), paths.archive.to_str()]
			CheckedArtifact(paths) => [
				paths.directory.to_str(),
				paths.binding.to_str(),
				paths.commit,
				paths.inputs,
				paths.output.to_str(),
			]
		}
	}

	SourceRequest :: { action : SourceAction, format : Format }.{
		parts : SourceRequest -> { action : SourceAction, format : Format }
		parts = |request| { action: request.action, format: request.format }

		with_format : SourceRequest, Format -> SourceRequest
		with_format = |request, format| { ..request, format }

		## The command a response reports.
		command : SourceRequest -> Command
		command = |request| match request.action {
			SourceAction.Head(_) => Command.InstanceSourceHead
			SourceAction.Archive(_) => Command.InstanceSourceArchive
			SourceAction.Controls(_) => Command.InstanceSourceControls
			SourceAction.VerifyControls(_) => Command.InstanceSourceVerifyControls
			SourceAction.CheckedArtifact(_) => Command.InstanceSourceCheckedArtifact
		}

		## The same instance, as `check` and `render` read it; `controls` has none.
		instance : SourceRequest -> Try(Instance, [Null])
		instance = |request| match request.action.directory() {
			Ok(directory) => Ok(Instance.{ directory, format: request.format })
			Err(Null) => Err(Null)
		}
	}

	## `instance deploy` runs a selected candidate on a single-replica app.
	Deploy : {
		directory : Names.LocalPath,
		checkout : Names.LocalPath,
		app_id : Str,
		candidate : Names.LocalPath,
		output : Names.LocalPath,
		deadline : Try(U64, [Null]),
		format : Format,
	}

	## A candidate command and its paths. BINDING is the deploy controller's binding file for the app, COMMIT a full
	## lowercase commit, CANDIDATE a candidate record file and JOB the build host's private job directory.
	## - build DIRECTORY BINDING COMMIT NEW_CANDIDATE: the candidate for the binding and commit; its record's bytes are
	##   written to NEW_CANDIDATE.
	## - preflight DIRECTORY CANDIDATE: the candidate's tooling maintenance protocol, proven on the build host.
	## - check DIRECTORY APP CANDIDATE: the candidate record, validated for APP.
	## - native-build JOB and native-probe JOB: on the build host, as root.
	CandidateAction := [
		Build({ directory : Names.LocalPath, binding : Names.LocalPath, commit : Str, output : Names.LocalPath }),
		Preflight({ directory : Names.LocalPath, candidate : Names.LocalPath }),
		Check({ directory : Names.LocalPath, app_id : Str, candidate : Names.LocalPath }),
		NativeBuild(Names.LocalPath),
		NativeProbe(Names.LocalPath),
	].{
		verb : CandidateAction -> Str
		verb = |action| match action {
			Build(_) => "build"
			Preflight(_) => "preflight"
			Check(_) => "check"
			NativeBuild(_) => "native-build"
			NativeProbe(_) => "native-probe"
		}

		## The instance directory whose day2.json a command validates; the build host's commands read none.
		directory : CandidateAction -> Try(Names.LocalPath, [Null])
		directory = |action| match action {
			Build(paths) => Ok(paths.directory)
			Preflight(paths) => Ok(paths.directory)
			Check(paths) => Ok(paths.directory)
			NativeBuild(_) | NativeProbe(_) => Err(Null)
		}

		## The command's arguments after its verb.
		arguments : CandidateAction -> List(Str)
		arguments = |action| match action {
			Build(paths) => [paths.directory.to_str(), paths.binding.to_str(), paths.commit, paths.output.to_str()]
			Preflight(paths) => [paths.directory.to_str(), paths.candidate.to_str()]
			Check(paths) => [paths.directory.to_str(), paths.app_id, paths.candidate.to_str()]
			NativeBuild(job) | NativeProbe(job) => [job.to_str()]
		}
	}

	CandidateRequest :: { action : CandidateAction, format : Format }.{
		parts : CandidateRequest -> { action : CandidateAction, format : Format }
		parts = |request| { action: request.action, format: request.format }

		with_format : CandidateRequest, Format -> CandidateRequest
		with_format = |request, format| { ..request, format }

		## The command a response reports.
		command : CandidateRequest -> Command
		command = |request| match request.action {
			CandidateAction.Build(_) => Command.InstanceCandidateBuild
			CandidateAction.Preflight(_) => Command.InstanceCandidatePreflight
			CandidateAction.Check(_) => Command.InstanceCandidateCheck
			CandidateAction.NativeBuild(_) => Command.InstanceCandidateNativeBuild
			CandidateAction.NativeProbe(_) => Command.InstanceCandidateNativeProbe
		}

		## The same instance, as `check` and `render` read it; the build host's commands have none.
		instance : CandidateRequest -> Try(Instance, [Null])
		instance = |request| match request.action.directory() {
			Ok(directory) => Ok(Instance.{ directory, format: request.format })
			Err(Null) => Err(Null)
		}
	}

	## day2 ci check HEAD [BASE] CASES NEW_DIRECTORY: an app repository's CI over the source tree HEAD. A BASE tree
	## routes the change between them to its lanes; without one every lane runs. CASES is the instance's verification
	## case count; NEW_DIRECTORY receives the checked artifact and its receipt when the native lane runs.
	CiCheckRequest :: {
		head : Names.LocalPath,
		base : Try(Names.LocalPath, [Null]),
		cases : U64,
		output : Names.LocalPath,
		format : Format,
	}.{
		parts :
			CiCheckRequest ->
				{
					head : Names.LocalPath,
					base : Try(Names.LocalPath, [Null]),
					cases : U64,
					output : Names.LocalPath,
					format : Format,
				}
		parts =
			|
				request,
			|
				{
					head: request.head,
					base: request.base,
					cases: request.cases,
					output: request.output,
					format: request.format,

				}

		with_format : CiCheckRequest, Format -> CiCheckRequest
		with_format = |request, format| { ..request, format }

		## The command's arguments after `day2 ci check`.
		arguments : CiCheckRequest -> List(Str)
		arguments = |request| {
			base = match request.base {
				Ok(path) => [path.to_str()]
				Err(Null) => []
			}
			[request.head.to_str()].concat(base).concat([request.cases.to_str(), request.output.to_str()])
		}
	}

	## day2 ci fetch DIRECTORY and day2 ci store DIRECTORY: the first and last steps of an app's org-scoped CI run. Fetch
	## writes the run's trees and record into the new directory DIRECTORY for `ci check`; store stores what `ci check`
	## wrote there.
	CiRun :: { directory : Names.LocalPath, format : Format }.{
		parts : CiRun -> { directory : Names.LocalPath, format : Format }
		parts = |request| { directory: request.directory, format: request.format }

		with_format : CiRun, Format -> CiRun
		with_format = |request, format| { ..request, format }
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
		raw =
			scan(
				args,
				{ source: Unset, filter: Unset, intent: Run, format: Text, deadline: Err(Null), positionals: [] },
			)?
		if raw.deadline.is_ok() and (raw.intent != Run or requested(raw.positionals).name() != "instance.deploy") {
			return Err(Problem.ConflictingOptions("--deadline is only for instance deploy."))
		}
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
					["instance", "release", ..] => Ok(Request.Help(raw.format))
					["instance", "source", ..] => Ok(Request.Help(raw.format))
					["instance", "candidate", ..] => Ok(Request.Help(raw.format))
					["instance", "deploy", ..] => Ok(Request.Help(raw.format))
					["instance", "ci-workflow", ..] => Ok(Request.Help(raw.format))
					["ci", ..] => Ok(Request.Help(raw.format))
					["app", "describe", name] => {
						_ = Names.App.from_str(name).map_err(|_| Problem.InvalidAppName(name))?
						Ok(Request.Help(raw.format))
					}
					_ => Err(Problem.UnknownCommand)
				}
			}
			Run => match raw.positionals {
				[] => if has_options(raw) Err(Problem.MissingCommand) else Ok(Request.Help(raw.format))
				["app", "describe"]
				| ["instance", "check"]
				| ["instance", "render"]
				| ["instance", "ci-workflow"] => Err(
					Problem.MissingArgument,
				)
				["instance", "plan"]
				| ["instance", "plan", _]
				| ["instance", "plan", _, _]
				| ["instance", "apply"]
				| ["instance", "apply", _]
				| ["instance", "apply", _, _]
				| ["instance", "apply", _, _, _] => Err(Problem.MissingArgument)
				["instance", "plan", directory, checkout, output] => Ok(
					Request.Roots(roots(InstanceRender.Mode.Plan, directory, checkout, output, raw)?),
				)
				["instance", "apply", directory, checkout, reviewed, output] => {
					plan = local_path("apply", reviewed, "a reviewed plan directory")?
					Ok(
						Request.Roots(
							roots(InstanceRender.Mode.Apply(plan.to_str()), directory, checkout, output, raw)?,
						),
					)
				}
				["instance", "deploy", directory, checkout, app_id, candidate, output] => {
					if has_options(raw) {
						return Err(
							Problem.ConflictingOptions("instance deploy accepts only --deadline, --agent or --json."),
						)
					}
					path = |value, role| local_path("deploy", value, role)
					Ok(
						Request.Deploy({
							directory: path(directory, "an instance directory")?,
							checkout: path(checkout, "a platform checkout")?,
							app_id: candidate_app(app_id, "instance deploy")?,
							candidate: path(candidate, "a candidate file")?,
							output: path(output, "a new output directory")?,
							deadline: raw.deadline,
							format: raw.format,
						}),
					)
				}
				["instance", "deploy", ..] if raw.positionals.len() < 7 => Err(Problem.MissingArgument)
				["instance", "release"]
				| ["instance", "release", "publish"]
				| ["instance", "release", "publish", _]
				| ["instance", "release", "publish", _, _]
				| ["instance", "release", "fetch"]
				| ["instance", "release", "fetch", _]
				| ["instance", "release", "fetch", _, _] => Err(Problem.MissingArgument)
				["instance", "release", "publish", directory, request, output] => {
					action = ReleaseAction.Publish({
						request: release_path("publish", request, "a publication request file")?,
						output: release_path("publish", output, "a new manifest file")?,
					})
					Ok(Request.Release(release(action, directory, raw)?))
				}
				["instance", "release", "fetch", directory, digest, bytes] => Ok(
					Request.Release(release(ReleaseAction.Fetch(reference(digest, bytes)?), directory, raw)?),
				)
				["instance", "source"]
				| ["instance", "source", "head"]
				| ["instance", "source", "head", _]
				| ["instance", "source", "archive"]
				| ["instance", "source", "archive", _]
				| ["instance", "source", "archive", _, _]
				| ["instance", "source", "archive", _, _, _]
				| ["instance", "source", "controls"]
				| ["instance", "source", "verify-controls"]
				| ["instance", "source", "verify-controls", _]
				| ["instance", "source", "verify-controls", _, _]
				| ["instance", "source", "checked-artifact"]
				| ["instance", "source", "checked-artifact", _]
				| ["instance", "source", "checked-artifact", _, _]
				| ["instance", "source", "checked-artifact", _, _, _]
				| ["instance", "source", "checked-artifact", _, _, _, _] => Err(Problem.MissingArgument)
				["instance", "source", "head", directory, binding] => {
					path = |value, role| source_path("head", value, role)
					action = SourceAction.Head({
						directory: path(directory, "an instance directory")?,
						binding: path(binding, "a binding file")?,
					})
					Ok(Request.Source(source_request(action, raw)?))
				}
				["instance", "source", "archive", directory, binding, revision, output] => {
					path = |value, role| source_path("archive", value, role)
					action = SourceAction.Archive({
						directory: path(directory, "an instance directory")?,
						binding: path(binding, "a binding file")?,
						commit: source_commit("archive", revision)?,
						output: path(output, "a new archive file")?,
					})
					Ok(Request.Source(source_request(action, raw)?))
				}
				["instance", "source", "controls", archive] => Ok(
					Request.Source(
						source_request(
							SourceAction.Controls(source_path("controls", archive, "a source archive")?),
							raw,
						)?,
					),
				)
				["instance", "source", "verify-controls", directory, binding, archive] => {
					path = |value, role| source_path("verify-controls", value, role)
					action = SourceAction.VerifyControls({
						directory: path(directory, "an instance directory")?,
						binding: path(binding, "a binding file")?,
						archive: path(archive, "a source archive")?,
					})
					Ok(Request.Source(source_request(action, raw)?))
				}
				["instance", "source", "checked-artifact", directory, binding, revision, inputs, output] => {
					path = |value, role| source_path("checked-artifact", value, role)
					action = SourceAction.CheckedArtifact({
						directory: path(directory, "an instance directory")?,
						binding: path(binding, "a binding file")?,
						commit: source_commit("checked-artifact", revision)?,
						inputs: source_inputs(inputs)?,
						output: path(output, "a new archive file")?,
					})
					Ok(Request.Source(source_request(action, raw)?))
				}
				["instance", "candidate"]
				| ["instance", "candidate", "build"]
				| ["instance", "candidate", "build", _]
				| ["instance", "candidate", "build", _, _]
				| ["instance", "candidate", "build", _, _, _]
				| ["instance", "candidate", "preflight"]
				| ["instance", "candidate", "preflight", _]
				| ["instance", "candidate", "check"]
				| ["instance", "candidate", "check", _]
				| ["instance", "candidate", "check", _, _]
				| ["instance", "candidate", "native-build"]
				| ["instance", "candidate", "native-probe"] => Err(Problem.MissingArgument)
				["instance", "candidate", "build", directory, binding, revision, output] => {
					path = |value, role| candidate_path("build", value, role)
					action = CandidateAction.Build({
						directory: path(directory, "an instance directory")?,
						binding: path(binding, "a binding file")?,
						commit: candidate_commit(revision)?,
						output: path(output, "a new candidate file")?,
					})
					Ok(Request.Candidate(candidate_request(action, raw)?))
				}
				["instance", "candidate", "preflight", directory, candidate] => {
					path = |value, role| candidate_path("preflight", value, role)
					action = CandidateAction.Preflight({
						directory: path(directory, "an instance directory")?,
						candidate: path(candidate, "a candidate file")?,
					})
					Ok(Request.Candidate(candidate_request(action, raw)?))
				}
				["instance", "candidate", "check", directory, id, candidate] => {
					path = |value, role| candidate_path("check", value, role)
					action = CandidateAction.Check({
						directory: path(directory, "an instance directory")?,
						app_id: candidate_app(id, "instance candidate check")?,
						candidate: path(candidate, "a candidate file")?,
					})
					Ok(Request.Candidate(candidate_request(action, raw)?))
				}
				["instance", "candidate", "native-build", job] => Ok(
					Request.Candidate(
						candidate_request(
							CandidateAction.NativeBuild(candidate_path("native-build", job, "a job directory")?),
							raw,
						)?,
					),
				)
				["instance", "candidate", "native-probe", job] => Ok(
					Request.Candidate(
						candidate_request(
							CandidateAction.NativeProbe(candidate_path("native-probe", job, "a job directory")?),
							raw,
						)?,
					),
				)
				["ci"]
				| ["ci", "check"]
				| ["ci", "check", _]
				| ["ci", "check", _, _]
				| ["ci", "fetch"]
				| ["ci", "store"] => Err(
					Problem.MissingArgument,
				)
				["ci", "fetch", directory] => Ok(Request.CiFetch(ci_run("fetch", directory, raw)?))
				["ci", "store", directory] => Ok(Request.CiStore(ci_run("store", directory, raw)?))
				["ci", "check", head, cases, output] => Ok(
					Request.CiCheck(ci_check(head, Err(Null), cases, output, raw)?),
				)
				["ci", "check", head, base, cases, output] => Ok(
					Request.CiCheck(ci_check(head, Ok(base), cases, output, raw)?),
				)
				["instance", "check", value] => Ok(Request.Check(instance("check", value, raw)?))
				["instance", "render", value] => Ok(Request.Render(instance("render", value, raw)?))
				["instance", "ci-workflow", value] => Ok(Request.CiWorkflow(instance("ci-workflow", value, raw)?))
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

	## Agrees with parse: the first positional names the command family.
	requested : List(Str) -> Command
	requested = |args| match args {
		["--instance", _, .. as rest]
		| ["--operation", _, .. as rest]
		| ["--deadline", _, .. as rest] => requested(rest)
		["instance", .. as rest] => instance_command(rest)
		["ci", "fetch", ..] => CiFetch
		["ci", "store", ..] => CiStore
		["ci", ..] => CiCheck
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
		Request.Release(value) => value.format
		Request.Source(value) => value.parts().format
		Request.Candidate(value) => value.parts().format
		Request.Deploy(value) => value.format
		Request.CiCheck(value) => value.parts().format
		Request.CiFetch(value) => value.parts().format
		Request.CiStore(value) => value.parts().format
		Request.CiWorkflow(value) => value.format
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
			]
				.concat(
					match value.mode {
						InstanceRender.Mode.Plan | InstanceRender.Mode.Deploy => []
						InstanceRender.Mode.Apply(reviewed) => [reviewed]
					},
				)
				.concat([value.output.to_str()])
			Request.Release(value) => ["day2", "instance", "release", value.action.verb(), value.directory.to_str()]
				.concat(
					match value.action {
						ReleaseAction.Publish(paths) => [paths.request.to_str(), paths.output.to_str()]
						ReleaseAction.Fetch(approved) => [approved.digest, approved.bytes.to_str()]
					},
				)
			Request.Source(value) => ["day2", "instance", "source", value.parts().action.verb()]
				.concat(value.parts().action.arguments())
			Request.Candidate(value) => ["day2", "instance", "candidate", value.parts().action.verb()]
				.concat(value.parts().action.arguments())
			Request.Deploy(value) => [
				"day2",
				"instance",
				"deploy",
				value.directory.to_str(),
				value.checkout.to_str(),
				value.app_id,
				value.candidate.to_str(),
				value.output.to_str(),
			].concat(
				match value.deadline {
					Ok(deadline) => ["--deadline", deadline.to_str()]
					Err(Null) => []
				},
			)
			Request.CiCheck(value) => ["day2", "ci", "check"].concat(value.arguments())
			Request.CiFetch(value) => ["day2", "ci", "fetch", value.parts().directory.to_str()]
			Request.CiStore(value) => ["day2", "ci", "store", value.parts().directory.to_str()]
			Request.CiWorkflow(value) => ["day2", "instance", "ci-workflow", value.directory.to_str()]
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
	deadline : Try(U64, [Null]),
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

## day2 ci check: the trees and the output are paths; the case count is the instance's verification, 4 to 100.
ci_check : Str, Try(Str, [Null]), Str, Str, Raw -> Try(Cli.CiCheckRequest, Problem)
ci_check = |head, base, cases, output, raw| {
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("ci check accepts only --agent or --json."))
	}
	path = |value, role|
		Names.LocalPath.from_str(value)
			.map_err(|_| Problem.InvalidArguments("ci check requires ${role} of at most 4096 bytes"))
	count =
		U64.from_str(cases)
			.map_err(
				|_| Problem.InvalidArguments("ci check requires the verification cases as an integer from 4 to 100"),
			)?
	if count < 4 or count > 100 {
		return Err(Problem.InvalidArguments("ci check requires the verification cases as an integer from 4 to 100"))
	}
	Ok(
		Cli.CiCheckRequest.{
			head: path(head, "a head source tree")?,
			base: match base {
				Ok(value) => Ok(path(value, "a base source tree")?)
				Err(Null) => Err(Null)
			},
			cases: count,
			output: path(output, "a new output directory")?,
			format: raw.format,
		},
	)
}

## day2 ci fetch|store: the run's directory is a path; everything else comes from the CI run's environment.
ci_run : Str, Str, Raw -> Try(Cli.CiRun, Problem)
ci_run = |verb, directory, raw| {
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("ci ${verb} accepts only --agent or --json."))
	}
	path =
		Names.LocalPath.from_str(directory)
			.map_err(|_| Problem.InvalidArguments("ci ${verb} requires a directory of at most 4096 bytes"))?
	Ok(Cli.CiRun.{ directory: path, format: raw.format })
}

roots : InstanceRender.Mode, Str, Str, Str, Raw -> Try(Cli.Roots, Problem)
roots = |mode, directory, checkout, output, raw| {
	verb = mode.name()
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("instance ${verb} accepts only --agent or --json."))
	}
	path = |value, role| local_path(verb, value, role)
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

local_path : Str, Str, Str -> Try(Names.LocalPath, Problem)
local_path = |verb, value, role|
	Names.LocalPath.from_str(value)
		.map_err(|_| Problem.InvalidArguments("instance ${verb} requires ${role} of at most 4096 bytes"))

release : Cli.ReleaseAction, Str, Raw -> Try(Cli.Release, Problem)
release = |action, directory, raw| {
	verb = action.verb()
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("instance release ${verb} accepts only --agent or --json."))
	}
	Ok(Cli.Release.{ action, directory: release_path(verb, directory, "an instance directory")?, format: raw.format })
}

release_path : Str, Str, Str -> Try(Names.LocalPath, Problem)
release_path = |verb, value, role|
	Names.LocalPath.from_str(value)
		.map_err(|_| Problem.InvalidArguments("instance release ${verb} requires ${role} of at most 4096 bytes"))

## A manifest reference as the instance approves it: sha256:<64 lowercase hex digits>, and its size in canonical
## decimal, 1 to 65536 bytes.
reference : Str, Str -> Try(Cli.Reference, Problem)
reference = |digest, bytes| {
	hex = digest.drop_prefix("sha256:").to_utf8()
	if
		!digest.starts_with("sha256:")
			or hex.len() != 64 or !hex.all(|byte| decimal(byte) or (byte >= 'a' and byte <= 'f'))
			{
				return Err(
					Problem.InvalidArguments(
						"instance release fetch requires the manifest digest as sha256:<64 lowercase hex digits>",
					),
				)
			}
	digits = bytes.to_utf8()
	size = match U64.from_str(bytes) {
		Ok(value) if digits.all(decimal) and !bytes.starts_with("0") => value
		_ => 0
	}
	if size < 1 or size > 65_536 {
		return Err(Problem.InvalidArguments("instance release fetch requires the manifest size, 1 to 65536 bytes"))
	}
	Ok({ digest, bytes: size })
}

decimal : U8 -> Bool
decimal = |byte| byte >= '0' and byte <= '9'

source_request : Cli.SourceAction, Raw -> Try(Cli.SourceRequest, Problem)
source_request = |action, raw| {
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("instance source ${action.verb()} accepts only --agent or --json."))
	}
	Ok(Cli.SourceRequest.{ action, format: raw.format })
}

source_path : Str, Str, Str -> Try(Names.LocalPath, Problem)
source_path = |verb, value, role|
	Names.LocalPath.from_str(value)
		.map_err(|_| Problem.InvalidArguments("instance source ${verb} requires ${role} of at most 4096 bytes"))

lower_hex : List(U8) -> Bool
lower_hex = |bytes| bytes.all(|byte| decimal(byte) or (byte >= 'a' and byte <= 'f'))

## A full lowercase commit.
source_commit : Str, Str -> Try(Str, Problem)
source_commit = |verb, value| {
	bytes = value.to_utf8()
	if bytes.len() == 40 and lower_hex(bytes) {
		Ok(value)
	} else {
		Err(Problem.InvalidArguments("instance source ${verb} requires the commit as 40 lowercase hex digits"))
	}
}

## The checked source inputs: sha256:<64 lowercase hex digits>.
source_inputs : Str -> Try(Str, Problem)
source_inputs = |value| {
	hex = value.drop_prefix("sha256:").to_utf8()
	if value.starts_with("sha256:") and hex.len() == 64 and lower_hex(hex) {
		Ok(value)
	} else {
		Err(
			Problem.InvalidArguments(
				"instance source checked-artifact requires the source inputs as sha256:<64 lowercase hex digits>",
			),
		)
	}
}

candidate_request : Cli.CandidateAction, Raw -> Try(Cli.CandidateRequest, Problem)
candidate_request = |action, raw| {
	if has_options(raw) {
		return Err(Problem.ConflictingOptions("instance candidate ${action.verb()} accepts only --agent or --json."))
	}
	Ok(Cli.CandidateRequest.{ action, format: raw.format })
}

candidate_path : Str, Str, Str -> Try(Names.LocalPath, Problem)
candidate_path = |verb, value, role|
	Names.LocalPath.from_str(value)
		.map_err(|_| Problem.InvalidArguments("instance candidate ${verb} requires ${role} of at most 4096 bytes"))

## A full lowercase commit.
candidate_commit : Str -> Try(Str, Problem)
candidate_commit = |value| {
	bytes = value.to_utf8()
	if bytes.len() == 40 and lower_hex(bytes) {
		Ok(value)
	} else {
		Err(Problem.InvalidArguments("instance candidate build requires the commit as 40 lowercase hex digits"))
	}
}

## A deployment app ID: a lowercase letter, then at most 39 lowercase letters, digits and hyphens.
candidate_app : Str, Str -> Try(Str, Problem)
candidate_app = |value, command| {
	bytes = value.to_utf8()
	valid = match bytes {
		[first, ..] => {
			first
				>= 'a'
				and first
					<= 'z'
					and bytes.len()
						<= 40
						and bytes.all(|byte| (byte >= 'a' and byte <= 'z') or decimal(byte) or byte == '-')
		}
		[] => Bool.False
	}
	if valid {
		Ok(value)
	} else {
		Err(Problem.InvalidArguments("${command} requires a deployment app ID"))
	}
}

## The instance verb follows the family, after any flags.
instance_command : List(Str) -> Cli.Command
instance_command = |args| match args {
	["--instance", _, .. as rest]
	| ["--operation", _, .. as rest]
	| ["--deadline", _, .. as rest] => instance_command(rest)
	["render", ..] => Cli.Command.InstanceRender
	["plan", ..] => Cli.Command.InstancePlan
	["apply", ..] => Cli.Command.InstanceApply
	["deploy", ..] => Cli.Command.InstanceDeploy
	["ci-workflow", ..] => Cli.Command.InstanceCiWorkflow
	["release", .. as rest] => release_command(rest)
	["source", .. as rest] => source_command(rest)
	["candidate", .. as rest] => candidate_command(rest)
	[arg, .. as rest] if arg.starts_with("-") => instance_command(rest)
	_ => Cli.Command.InstanceCheck
}

## The release verb follows `release`, after any flags. An incomplete release command reports the read-only fetch.
release_command : List(Str) -> Cli.Command
release_command = |args| match args {
	["--instance", _, .. as rest] | ["--operation", _, .. as rest] => release_command(rest)
	["publish", ..] => Cli.Command.InstanceReleasePublish
	[arg, .. as rest] if arg.starts_with("-") => release_command(rest)
	_ => Cli.Command.InstanceReleaseFetch
}

## The source verb follows `source`, after any flags. An incomplete source command reports the read-only head.
source_command : List(Str) -> Cli.Command
source_command = |args| match args {
	["--instance", _, .. as rest] | ["--operation", _, .. as rest] => source_command(rest)
	["archive", ..] => Cli.Command.InstanceSourceArchive
	["controls", ..] => Cli.Command.InstanceSourceControls
	["verify-controls", ..] => Cli.Command.InstanceSourceVerifyControls
	["checked-artifact", ..] => Cli.Command.InstanceSourceCheckedArtifact
	[arg, .. as rest] if arg.starts_with("-") => source_command(rest)
	_ => Cli.Command.InstanceSourceHead
}

## The candidate verb follows `candidate`, after any flags. An incomplete candidate command reports the read-only check.
candidate_command : List(Str) -> Cli.Command
candidate_command = |args| match args {
	["--instance", _, .. as rest] | ["--operation", _, .. as rest] => candidate_command(rest)
	["build", ..] => Cli.Command.InstanceCandidateBuild
	["preflight", ..] => Cli.Command.InstanceCandidatePreflight
	["native-build", ..] => Cli.Command.InstanceCandidateNativeBuild
	["native-probe", ..] => Cli.Command.InstanceCandidateNativeProbe
	[arg, .. as rest] if arg.starts_with("-") => candidate_command(rest)
	_ => Cli.Command.InstanceCandidateCheck
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
	["--deadline", value, .. as rest] => set_deadline(value, rest, raw)
	["--instance"] => Err(Problem.MissingOptionValue("--instance"))
	["--operation"] => Err(Problem.MissingOptionValue("--operation"))
	["--deadline"] => Err(Problem.MissingOptionValue("--deadline"))
	[arg, .. as rest] if arg
		.starts_with("--instance=") => set_option("--instance", arg.drop_prefix("--instance="), rest, raw)
	[arg, .. as rest] if arg
		.starts_with("--operation=") => set_option("--operation", arg.drop_prefix("--operation="), rest, raw)
	[arg, .. as rest] if arg.starts_with("--deadline=") => set_deadline(arg.drop_prefix("--deadline="), rest, raw)
	[arg, .. as rest] => if
		arg.starts_with("-")
		Err(Problem.UnknownOption(arg))
	else
		scan(rest, { ..raw, positionals: raw.positionals.append(arg) })
}

set_deadline : Str, List(Str), Raw -> Try(Raw, Problem)
set_deadline = |value, rest, raw| {
	if raw.deadline.is_ok() {
		return Err(Problem.DuplicateOption("--deadline"))
	}
	if value.is_empty() or value.starts_with("--") {
		return Err(Problem.MissingOptionValue("--deadline"))
	}
	match U64.from_str(value) {
		Ok(seconds) if seconds > 0 and value.to_utf8().all(decimal) => scan(rest, { ..raw, deadline: Ok(seconds) })
		_ => Err(Problem.InvalidArguments("--deadline requires a positive Unix timestamp in seconds"))
	}
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
expect match Cli.parse(
	["instance", "release", "fetch", "../acme", "sha256:${Str.repeat("ab", 32)}", "1236", "--agent"],
) {
	Ok(Cli.Request.Release(value)) => match value.parts().action {
		Cli.ReleaseAction.Fetch(approved) => approved.bytes
			== 1236
			and value.command().name() == "instance.release.fetch"
		_ => Bool.False
	}
	_ => Bool.False
}
expect match Cli.parse(["instance", "release", "publish", ".", "request.json", "new.json"]) {
	Ok(Cli.Request.Release(value)) => Cli.Action.new("", Cli.Request.Release(value)).dto().argv
		== ["day2", "instance", "release", "publish", ".", "request.json", "new.json"]
	_ => Bool.False
}
# A digest or size that is not the canonical approved reference is refused before anything runs.
expect
	[
		["sha256:${Str.repeat("AB", 32)}", "1236"],
		["sha256:${Str.repeat("ab", 31)}", "1236"],
		["${Str.repeat("ab", 32)}", "1236"],
		["sha256:${Str.repeat("ab", 32)}", "0"],
		["sha256:${Str.repeat("ab", 32)}", "01236"],
		["sha256:${Str.repeat("ab", 32)}", "65537"],
		["sha256:${Str.repeat("ab", 32)}", "+12"],
		["sha256:${Str.repeat("ab", 32)}", "12 "],
	]
		.all(
			|pair| match Cli.parse(["instance", "release", "fetch", "."].concat(pair)) {
				Err(Problem.InvalidArguments(_)) => Bool.True
				_ => Bool.False
			},
		)
expect match Cli.parse(["instance", "release", "fetch", ".", "sha256:${Str.repeat("ab", 32)}"]) {
	Err(Problem.MissingArgument) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["instance", "release", "publish", ".", "r.json", "n.json", "--demo"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["instance", "release", "list", ".", "a", "b"]) {
	Err(Problem.UnknownCommand) => Bool.True
	_ => Bool.False
}
expect Cli.requested(["instance", "release", "--agent", "publish", "."]).name() == "instance.release.publish"
expect Cli.requested(["--agent", "instance", "release", "fetch"]).name() == "instance.release.fetch"
expect match Cli.parse([
	"instance",
	"source",
	"checked-artifact",
	"../acme",
	"binding.json",
	Str.repeat("ab", 20),
	"sha256:${Str.repeat("cd", 32)}",
	"new.tar.gz",
	"--agent",
]) {
	Ok(Cli.Request.Source(value)) => value.command().name()
		== "instance.source.checked-artifact"
		and Cli.Action.new("", Cli.Request.Source(value)).dto().argv
			== [
				"day2",
				"instance",
				"source",
				"checked-artifact",
				"../acme",
				"binding.json",
				Str.repeat("ab", 20),
				"sha256:${Str.repeat("cd", 32)}",
				"new.tar.gz",
				"--agent",
			]
	_ => Bool.False
}
expect match Cli.parse(["instance", "source", "controls", "source.tar.gz"]) {
	Ok(Cli.Request.Source(value)) => value.command().name() == "instance.source.controls" and value.instance().is_err()
	_ => Bool.False
}
expect match Cli.parse(["instance", "source", "verify-controls", ".", "binding.json", "source.tar.gz"]) {
	Ok(Cli.Request.Source(value)) => value.parts().action.directory().is_ok()
		and value.command().name()
			== "instance.source.verify-controls"
	_ => Bool.False
}
# Each source verb needs all of its arguments.
expect
	[
		["instance", "source"],
		["instance", "source", "head", "."],
		["instance", "source", "archive", ".", "b.json", Str.repeat("ab", 20)],
		["instance", "source", "controls"],
		["instance", "source", "verify-controls", ".", "b.json"],
		["instance", "source", "checked-artifact", ".", "b.json", Str.repeat("ab", 20), "sha256:x"],
	]
		.all(
			|args| match Cli.parse(args) {
				Err(Problem.MissingArgument) => Bool.True
				_ => Bool.False
			},
		)
# A commit or source inputs that are not exact are refused before anything runs.
expect
	[
		["instance", "source", "archive", ".", "b.json", Str.repeat("AB", 20), "new.tar.gz"],
		["instance", "source", "archive", ".", "b.json", Str.repeat("ab", 19), "new.tar.gz"],
		["instance", "source", "checked-artifact", ".", "b.json", Str.repeat("ab", 20), "sha256:x", "new.tar.gz"],
		["instance", "source", "checked-artifact", ".", "b.json", Str.repeat("ab", 20), Str.repeat("cd", 32), "n"],
	]
		.all(
			|args| match Cli.parse(args) {
				Err(Problem.InvalidArguments(_)) => Bool.True
				_ => Bool.False
			},
		)
expect match Cli.parse(["instance", "source", "head", ".", "b.json", "--demo"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
expect match Cli.parse(["instance", "source", "fetch", ".", "b.json"]) {
	Err(Problem.UnknownCommand) => Bool.True
	_ => Bool.False
}
expect Cli.requested(["instance", "source", "--agent", "checked-artifact", "."]).name()
	== "instance.source.checked-artifact"
expect Cli.requested(["--agent", "instance", "source"]).name() == "instance.source.head"
expect Cli.requested(["instance", "source", "verify-controls"]).name() == "instance.source.verify-controls"

deploy_args : List(Str)
deploy_args = ["instance", "deploy", ".", "../platform", "links", "candidate.json", "/tmp/new-deploy"]

expect match Cli.parse(deploy_args.concat(["--deadline", "1800000000", "--agent"])) {
	Ok(Cli.Request.Deploy(deploy)) => deploy.app_id == "links" and deploy.deadline == Ok(1_800_000_000)
	_ => Bool.False
}

expect match Cli.parse(deploy_args.concat(["--deadline=1800000000", "--deadline=1800000001"])) {
	Err(Problem.DuplicateOption("--deadline")) => Bool.True
	_ => Bool.False
}

expect match Cli.parse(deploy_args.concat(["--deadline", "0"])) {
	Err(Problem.InvalidArguments(_)) => Bool.True
	_ => Bool.False
}

expect match Cli.parse(["instance", "check", ".", "--deadline=1800000000"]) {
	Err(Problem.ConflictingOptions(_)) => Bool.True
	_ => Bool.False
}
