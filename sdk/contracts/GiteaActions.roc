import Observe
import Resource

# Read-only Gitea Actions. The activated resource fixes the server and organization.
# All instants are Unix seconds; -1 means the provider has no timestamp.
GiteaActions :: [].{
	Run : {
		id : I64,
		attempt : I64,
		owner : Str,
		repo : Str,
		title : Str,
		path : Str,
		event : Str,
		branch : Str,
		sha : Str,
		status : Str,
		conclusion : Str,
		started_at : I64,
		completed_at : I64,
		url : Str,
	}

	Job : {
		id : I64,
		run_id : I64,
		attempt : I64,
		owner : Str,
		repo : Str,
		name : Str,
		status : Str,
		conclusion : Str,
		created_at : I64,
		started_at : I64,
		completed_at : I64,
		runner_id : I64,
		runner_name : Str,
		labels : List(Str),
		url : Str,
	}

	Runner : {
		id : I64,
		name : Str,
		status : Str,
		busy : Bool,
		disabled : Bool,
		ephemeral : Bool,
		labels : List(Str),
	}

	Runs : { items : List(Run), has_more : Bool, next_page : U64, total : U64 }

	Jobs : { items : List(Job), has_more : Bool, next_page : U64, total : U64 }

	Runners : { items : List(Runner) }

	Log : { available : Bool, text : Str, truncated : Bool }

	# Gitea returns newest runs first. Pages have 1–50 items; callers must
	# account for concurrent insertion and reconcile unfinished runs separately.
	runs : Resource, U64, U64, Str -> Observe(Runs)
	runs = |resource, page, limit, status| Observe.capability(
		"gitea.runs.v1",
		Json.to_str({ handle: Resource.token(resource), page, limit, status }),
	).and_then(
		|raw| {
			parsed : Try(Runs, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_gitea_runs"))
		},
	)

	run : Resource, Str, I64, I64 -> Observe(Run)
	run = |resource, repo, id, attempt| Observe.capability(
		"gitea.run.v1",
		Json.to_str({ handle: Resource.token(resource), repo, id, attempt }),
	).and_then(
		|raw| {
			parsed : Try(Run, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_gitea_run"))
		},
	)

	run_jobs : Resource, Str, I64, I64, U64, U64 -> Observe(Jobs)
	run_jobs = |resource, repo, id, attempt, page, limit| Observe.capability(
		"gitea.run_jobs.v1",
		Json.to_str({ handle: Resource.token(resource), repo, id, attempt, page, limit }),
	).and_then(
		|raw| {
			parsed : Try(Jobs, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_gitea_jobs"))
		},
	)

	job : Resource, Str, I64 -> Observe(Job)
	job = |resource, repo, id| Observe.capability(
		"gitea.job.v1",
		Json.to_str({ handle: Resource.token(resource), repo, id }),
	).and_then(
		|raw| {
			parsed : Try(Job, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_gitea_job"))
		},
	)

	# A UTF-8 log tail, at most 12 KB. Truncated means earlier content was
	# omitted; absence of a signature does not prove absence of an error.
	# The host refuses logs exceeding its bounded wire budget.
	job_log : Resource, Str, I64 -> Observe(Log)
	job_log = |resource, repo, id| Observe.capability(
		"gitea.job_log.v1",
		Json.to_str({ handle: Resource.token(resource), repo, id }),
	).and_then(
		|raw| {
			parsed : Try(Log, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_gitea_log"))
		},
	)

	# This API requires Gitea runner-management permission. Missing authority
	# fails visibly; an inaccessible runner pool is never reported as empty.
	runners : Resource -> Observe(Runners)
	runners = |resource| Observe.capability(
		"gitea.runners.v1",
		Json.to_str({ handle: Resource.token(resource) }),
	).and_then(
		|raw| {
			parsed : Try(Runners, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_gitea_runners"))
		},
	)
}
