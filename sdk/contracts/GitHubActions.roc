import Observe
import Resource

# GitHub Actions: whether a CI job finished, and where to read its log.
#
# The activated resource fixes the repository. An application reads jobs in the
# repository it was granted and in no other — which matters more here than for
# most providers, because a build log can contain whatever the build printed:
# tokens, customer data, source.
#
# Reads only. Watching CI and driving it are different authorities, and
# re-running somebody's workflow is not something this contract can express.
GitHubActions :: [].{
	Job : {
		# GitHub's own status string, passed through rather than mapped, so a
		# state GitHub adds later is visible rather than silently reinterpreted.
		status : Str,
		# Empty until GitHub decides one.
		conclusion : Str,
		# Whether the job has stopped. Anything other than an explicitly running
		# state counts as finished: a watcher that only closed on `completed`
		# would hold a job open forever when GitHub introduces a new terminal
		# state.
		finished : Bool,
		# Still waiting for a runner. Distinct from running, because a job that
		# has not started cannot be stuck in the way a running one can.
		queued : Bool,
		# Milliseconds from the Unix epoch, or -1 when GitHub reports no time.
		# These are GitHub's own timings, so a record corrected from them carries
		# the real times rather than the moment the poller happened to look.
		started_at_ms : I64,
		completed_at_ms : I64,
		name : Str,
		html_url : Str,
	}

	# One job's current state.
	job : Resource, Str -> Observe(Job)
	job = |resource, job_id| Observe.capability(
		"github.job.v1",
		Json.to_str({ handle: Resource.token(resource), job_id }),
	).and_then(
		|raw| {
			parsed : Try(Job, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_github_job"))
		},
	)

	# Where a job's log can be read, and for how long.
	LogLocation : {
		# A signed URL, or empty when the job has no log — a job still queued has
		# produced nothing, and that is an answer rather than a failure.
		url : Str,
		# Seconds the URL stays usable. Short: it is a bearer capability for
		# whatever the build printed.
		expires_in : U64,
	}

	# Where to read one job's log.
	#
	# **The log itself never passes through the platform.** GitHub answers with a
	# redirect to a signed blob, and a build log is unbounded — exactly the kind
	# of payload a bounded observation cannot carry. So this returns the location
	# and the transfer happens between whoever needs it and GitHub, the same
	# shape as an object-store download.
	job_log : Resource, Str -> Observe(LogLocation)
	job_log = |resource, job_id| Observe.capability(
		"github.job_log.v1",
		Json.to_str({ handle: Resource.token(resource), job_id }),
	).and_then(
		|raw| {
			parsed : Try(LogLocation, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_github_log_location"))
		},
	)
}
