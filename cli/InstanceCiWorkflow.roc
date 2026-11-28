import InstanceSpec
import Problem
import "fixtures/ci-workflow-inputs.json" as golden_inputs : Str
import "fixtures/ci-workflow.yml" as golden_workflow : Str

## Step 4 of docs/INSTANCE.md: app CI is one org-scoped workflow in <org>/day2-ci, required for every app repository,
## so an app repository can neither edit, skip nor impersonate it. This renders it from day2.json and the two inputs
## the host reads for it: the project's number, which the workload identity provider's audience names, and each app's
## tooling image from its selected SDK release manifest.
##
## The workflow is named `day2` with one job, `verification`, so Gitea posts the status context
## `day2 / verification (pull_request)` (and `(push)`), which InstanceSpec's required check names. The job runs only in
## the repositories of a map rendered inline into each expression: never a repository or org variable, which an app
## repository could override to redirect its own CI. Its four steps run one `day2` command each: fetch, reuse, check and
## store. Only fetch and reuse, which run before any app code, receive the job token, only reuse and store the git-oidc
## request token, and check, which runs the app's code, neither. The token reads the app repository's own run records
## (`actions: read`), which reuse checks an earlier main run's custody against.
InstanceCiWorkflow :: [].{

	## Where the rendered file lives in <org>/day2-ci.
	path = ".gitea/scoped_workflows/verification.yml"

	## One app's selected SDK release, as the host read it: its tooling image and its precompiled tooling distribution,
	## the SDK identity a checked artifact's receipt records.
	Tooling : { id : Str, tooling_image : Str, distribution : Str }

	## The host's report (crates/day2-ops/src/ci_workflow.rs `Report`); cli/fixtures/ci-workflow-inputs.json pins it.
	Inputs : { format : U64, project_number : Str, apps : List(Tooling) }

	## The request the recipe hands the host, which validates it again: the names the host reads under.
	request : InstanceSpec -> Str
	request = |spec| {
		names = spec.derived()
		Json.to_str({
			project: names.gcp_project,
			registry: names.artifact_registry,
			bucket: names.tofu_state_bucket,
			apps: names.apps.map(|bound| { id: bound.id, sdk: bound.sdk }),
		})
	}

	## The host's inputs, in format 1.
	inputs : Str -> Try(Inputs, [InvalidInputs])
	inputs = |text| {
		parsed : Try(Inputs, _)
		parsed = Json.parse(text)
		decoded = parsed.map_err(|_| InvalidInputs)?
		if decoded.format == 1 Ok(decoded) else Err(InvalidInputs)
	}

	## The file's exact bytes. Every app needs a tooling image digest-pinned under the instance's registry, and the
	## project number is decimal digits.
	render : InstanceSpec, Inputs -> Try(Str, [Unrendered(Str)])
	render = |spec, given| {
		names = spec.derived()
		# The store step requests its OIDC token from the instance's broker; without one it could store nothing.
		token_request = match names.ci_token_request {
			Ok(url) => url
			Err(Null) => return Err(
				Unrendered(
					"app CI's workflow needs day2.json's forge.oidc, the git-oidc broker its store step requests an OIDC token from",
				),
			)
		}
		number = given.project_number
		if
			number.is_empty()
				or number.count_utf8_bytes() > 20 or !number.to_utf8().all(|byte| byte >= '0' and byte <= '9')
				{
					return Err(Unrendered("the project number must be decimal digits"))
				}
		if given.apps.map(|tooling| tooling.id) != names.apps.map(|bound| bound.id) {
			return Err(Unrendered("the host read another set of apps than day2.json's"))
		}
		for tooling in given.apps {
			if !digest(tooling.distribution) {
				return Err(Unrendered("the SDK distribution of ${tooling.id} is not a sha256 digest"))
			}
			if !pinned(tooling.tooling_image, names.artifact_registry) {
				return Err(
					Unrendered("the tooling image of ${tooling.id} is not digest-pinned under the instance's registry"),
				)
			}
		}
		identity = names.ci_workload_identity
		audience = "https://iam.googleapis.com/projects/${number}/locations/global/workloadIdentityPools/${
			identity.pool
		}/providers/${identity.provider}"
		selected = |id| match given.apps.find_first(|tooling| tooling.id == id) {
			Ok(tooling) => tooling
			Err(_) => { id, tooling_image: "", distribution: "" }
		}
		entries =
			names.apps.map(
				|bound| {
					value = Json.to_str({
						audience,
						bucket: bound.ci_bucket,
						cases: bound.verification,
						distribution: selected(bound.id).distribution,
						image: selected(bound.id).tooling_image,
						sdk: bound.sdk,
					})
					"${Json.to_str(bound.repository)}:${value}"
				},
			)
		# An expression string literal escapes a quote by doubling it; the map holds none.
		map = "{${Str.join_with(entries, ",")}}".replace_each("'", "''")
		# A literal `$` before `{{`: the `$` itself, so the expression opener is not an interpolation.
		dollar = "$"
		lookup = |field| "${dollar}{{ fromJSON('${map}')[github.repository]${field} }}"
		cli = "/workspace/platform/cli/day2"
		run = "/tmp/day2-ci"
		# The store inputs, each in its step's own `env:`: store's, and reuse's, which reads the same ones.
		store_inputs = [
			"          ACTIONS_ID_TOKEN_REQUEST_URL: ${token_request}&repository=${dollar}{{ github.repository }}",
			"          ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${dollar}{{ secrets.GITHUB_TOKEN }}",
			"          DAY2_CI_BUCKET: ${lookup(".bucket")}",
			"          DAY2_CI_AUDIENCE: ${lookup(".audience")}",
			"          DAY2_CI_SDK: ${lookup(".sdk")}",
			"          DAY2_CI_DISTRIBUTION: ${lookup(".distribution")}",
		]
		Ok(
			Str.join_with(
				[
					"# Rendered by `day2 instance ci-workflow` from day2.json for ${names.ci_repository}, at",
					"# ${path}. Do not edit it: render it again after day2.json changes.",
					"name: day2",
					"",
					"on:",
					"  pull_request:",
					"  push:",
					"    branches: [main]",
					"",
					"permissions:",
					"  contents: read",
					"  actions: read",
					"  id-token: write",
					"",
					"jobs:",
					"  verification:",
					"    name: verification",
					"    if: ${dollar}{{ fromJSON('${map}')[github.repository] != null }}",
					"    runs-on: [self-hosted, ${names.forge_org}, linux, X64]",
					"    timeout-minutes: 45",
					"    container:",
					"      image: ${lookup(".image")}",
					"      options: >-",
					"        --memory=6g --memory-swap=6g --cpus=4 --pids-limit=512",
					"        --tmpfs=/workspace/platform/artifacts:rw,exec,nosuid,nodev,size=1073741824",
					"        --tmpfs=/workspace/platform/crates/worker/generated:rw,exec,nosuid,nodev,size=67108864",
					"    steps:",
					"      - name: fetch",
					"        env:",
					"          GITHUB_TOKEN: ${dollar}{{ secrets.GITHUB_TOKEN }}",
					"        run: ${cli} ci fetch ${run}",
					"      - name: reuse",
					"        env:",
					"          GITHUB_TOKEN: ${dollar}{{ secrets.GITHUB_TOKEN }}",
				]
					.concat(store_inputs)
					.concat([
						"        run: ${cli} ci reuse ${run} ${lookup(".cases")}",
						"      - name: check",
						"        run: ${cli} ci check ${run}/head ${dollar}{{ github.event_name == 'pull_request' && '${run}/base' || '--reuse ${run}/reuse' }} ${
							lookup(".cases")
						} ${run}/out",
						"      - name: store",
						"        env:",
					])
					.concat(store_inputs)
					.concat(["        run: ${cli} ci store ${run}", ""]),
				"\n",
			),
		)
	}

	## A failed read or render exits 6 with its message.
	problem : Str -> Problem
	problem = |error| Problem.CiWorkflowFailed(error)
}

## `<registry>/<repository>/<name>@sha256:<64 lowercase hex>`, as a qualified release pins its images.
pinned : Str, Str -> Bool
pinned = |image, registry| match image.drop_prefix("${registry}/").split_on("@") {
	[path, pin] => {
		parts = path.split_on("/")
		image.starts_with("${registry}/")
			and parts.len() == 2
				and parts.all(|part| !part.is_empty() and part.to_utf8().all(segment))
					and digest(pin)
	}
	_ => Bool.False
}

## `sha256:<64 lowercase hex>`.
digest : Str -> Bool
digest = |value| {
	hex = value.drop_prefix("sha256:").to_utf8()
	value.starts_with("sha256:")
		and hex.len() == 64
			and hex.all(|byte| (byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))
}

segment : U8 -> Bool
segment = |byte| (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9') or byte == '-'

sample =
	\\{"kind":"instance","version":1,"installation":"exampleco",
	\\"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
	\\"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools",
	\\"oidc":"https://git-oidc.example.com"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com","grace@example.com"],
	\\"apps":{"go":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"automatic",
	\\"extension":"jldmikbinomhomcbmeppagennfohakni","owners":["lin@example.com"],"size":"standard",
	\\"verification":4,"schedules":"enabled"},
	\\"home":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"manual","extension":null,
	\\"owners":["kay@example.com","lin@example.com"],"size":"large","verification":6,"schedules":"paused"}}}

rendered : (Str -> Str) -> Try(Str, [Unrendered(Str), Invalid])
rendered = |change| {
	spec = InstanceSpec.from_json(sample).map_err(|_| Invalid)?
	given = InstanceCiWorkflow.inputs(change(golden_inputs)).map_err(|_| Invalid)?
	InstanceCiWorkflow.render(spec, given)
}

# The fixture instance's workflow, byte for byte.
expect rendered(|text| text) == Ok(golden_workflow)

# The host reads under the spec's derived names.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => InstanceCiWorkflow.request(spec)
		== "{\"apps\":[{\"id\":\"go\",\"sdk\":\"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848\"},{\"id\":\"home\",\"sdk\":\"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848\"}],\"bucket\":\"exampleco-tools-tofu-state\",\"project\":\"exampleco-tools\",\"registry\":\"us-central1-docker.pkg.dev/exampleco-tools\"}"
	Err(_) => Bool.False
}

# The repository map is the only source of each app's image, cases, bucket, audience and SDK; no variable is read.
expect match rendered(|text| text) {
	Ok(text) => !text.contains("vars.") and !text.contains("env.") and text.contains("\"tools/home\":{")
	Err(_) => Bool.False
}

# A tooling image that is not digest-pinned under the registry, another app set or a project number that is not
# decimal is refused.
expect rendered(|text| text.replace_first("@sha256:0788", "@sha256:X788")).is_err()
expect rendered(|text| text.replace_first("exampleco-tools/home/", "other-project/home/")).is_err()
expect rendered(|text| text.replace_first("/home/day2-tooling@", "/home/a/b@")).is_err()
expect rendered(|text| text.replace_first("\"id\": \"home\"", "\"id\": \"links\"")).is_err()
expect rendered(|text| text.replace_first("123456789012", "12345678901x")).is_err()
expect rendered(|text| text.replace_first("\"distribution\": \"sha256:", "\"distribution\": \"md5:")).is_err()
expect rendered(|text| text.replace_first("\"format\": 1", "\"format\": 2")).is_err()
# Without forge.oidc there is no token request for the store step: nothing is rendered.
expect match InstanceSpec.from_json(sample.replace_first(",\n\"oidc\":\"https://git-oidc.example.com\"", "")) {
	Ok(spec) => match InstanceCiWorkflow.inputs(golden_inputs) {
		Ok(given) => match InstanceCiWorkflow.render(spec, given) {
			Err(Unrendered(detail)) => detail.contains("forge.oidc")
			Ok(_) => Bool.False
		}
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}
expect InstanceCiWorkflow.problem("PERMISSION_DENIED").exit_code() == 6
