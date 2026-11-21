import InstanceSpec
import "InstanceSpec.roc" as instance_spec_source : Str
import "InstanceRender.roc" as instance_render_source : Str
import "Names.roc" as names_source : Str
import "JsonValue.roc" as json_value_source : Str

## Step 2 of docs/INSTANCE.md: the OpenTofu inputs the platform renders from an
## instance spec, so instance repositories stop committing them. It renders the
## core roots every instance applies to serve apps, in apply order: project,
## cluster and tenancy, then app-edge and day2-app for each app. Every bucket and
## prefix is one of InstanceSpec's derived names.
##
## Not rendered until the spec models them: the installation security shell
## (security-shell-edge and security-shell), opt-in integrations under
## deploy/integrations/ such as gitea-instance-ci, optional stacks such as
## qualification-runner, and roots an instance owns itself.
InstanceRender :: [].{

	## One OpenTofu invocation. A per-app root carries the app it renders, so a
	## per-app root without its app, or a platform root with one, cannot exist.
	Root := [Project, Cluster, Tenancy, AppEdge(InstanceSpec.App), Day2App(InstanceSpec.App)].{
		name : Root -> Str
		name = |root| match root {
			Project => "project"
			Cluster => "cluster"
			Tenancy => "tenancy"
			AppEdge(_) => "app-edge"
			Day2App(_) => "day2-app"
		}

		app_id : Root -> Try(Str, [Null])
		app_id = |root| match root {
			AppEdge(bound) | Day2App(bound) => Ok(bound.id)
			Project | Cluster | Tenancy => Err(Null)
		}

		## The root's name as one word: "cluster", or "app-edge/<id>" for a per-app root.
		label : Root -> Str
		label = |root| match root.app_id() {
			Ok(id) => "${root.name()}/${id}"
			Err(_) => root.name()
		}

		## The platform source directory OpenTofu runs in: every rendered root is a core stack.
		stack : Root -> Str
		stack = |root| "deploy/gke/stacks/${root.name()}"

		backend : Root, InstanceSpec.Derived -> { bucket : Str, prefix : Str }
		backend = |root, names| match root {
			Project => { bucket: names.tofu_state_bucket, prefix: names.platform_state_prefixes.project }
			Cluster => { bucket: names.tofu_state_bucket, prefix: names.platform_state_prefixes.cluster }
			Tenancy => { bucket: names.tofu_state_bucket, prefix: names.platform_state_prefixes.tenancy }
			AppEdge(bound) => { bucket: names.tofu_state_bucket, prefix: bound.edge_state_prefix }
			Day2App(bound) => { bucket: bound.state_bucket, prefix: bound.state_prefix }
		}

		## The variables the platform renders for this root, named exactly as its stack declares them. Each is
		## a derived name, the app's size preset or a fixed platform constant. An input at its stack default is
		## rendered only when another rendered value is computed from it, so two roots read one constant.
		## Everything else is still the instance's to commit: identity lists that may name its CI service
		## accounts (state readers and writers, platform automation), node counts and other cluster
		## choices, discovered IDs, images and digests, access policy, extension routes, and per-app
		## identities, secrets, catalogs and labels.
		variables : Root, InstanceSpec.Derived -> List((Str, Value))
		variables = |root, names| {
			prefixes = names.platform_state_prefixes
			operators = names.operators.map(|email| "user:${email}")
			match root {
				Project => [
					("project_id", Text(names.gcp_project)),
					("region", Text(names.gcp_region)),
					("state_bucket_name", Text(names.tofu_state_bucket)),
					# Byte-exact: each key and value names a conditional IAM binding, so a change replaces it.
					(
						"state_prefixes",
						Fields([
							("foundation", Text("${prefixes.project}/")),
							("cluster", Text("${prefixes.cluster}/")),
							("tenancy", Text("${prefixes.tenancy}/")),
							("app", Text("${prefixes.app_edge}/")),
							("day2", Text("${prefixes.day2}/")),
						]),
					),
				]

				Cluster => [
					("project_id", Text(names.gcp_project)),
					("region", Text(names.gcp_region)),
					("zone", Text(names.gcp_zone)),
					("cluster_name", Text(names.cluster.name)),
					(
						"cluster_labels",
						Fields([
							("managed_by", Text("opentofu")),
							("stack", Text("platform-cluster")),
							# The label names the cluster, not the apps' "production" environment.
							("environment", Text(names.cluster.name)),
						]),
					),
					("subnet_cidr", Text(network.subnet_cidr)),
					("pod_cidr", Text(network.pod_cidr)),
					("service_cidr", Text(network.service_cidr)),
					("shared_node_pod_pids_limit", Whole(pod_pids_limit)),
				]

				Tenancy => [
					("kube_context", Text(names.cluster.kube_context)),
					("app_namespace_prefix", Text(names.app_namespace_prefix)),
				]

				AppEdge(bound) => [
					("project_id", Text(names.gcp_project)),
					("region", Text(names.gcp_region)),
					("cluster_name", Text(names.cluster.name)),
					("cluster_location", Text(names.gcp_zone)),
					("kube_context", Text(names.cluster.kube_context)),
					("app_id", Text(bound.id)),
					("namespace_prefix", Text(names.app_namespace_prefix)),
					("domain", Text(bound.hostname)),
					# Everyone in the people domain reaches every app. Operators are also bound by name, which
					# the domain already covers.
					("iap_members", Texts(["domain:${names.people_domain}"].concat(operators))),
					# Only operators deploy an app by hand; owners never get deploy authority. CI service accounts
					# hold project-level grants from the instance's bootstrap and are never listed here.
					("deployer_subjects", Texts(operators)),
					# Operators keep custody of every app's off-site backups.
					("offsite_backup_readers", Texts(operators)),
					("sqlite_storage_gb", Whole(bound.sqlite_storage_gb)),
					("storage_class_name", Text(storage_class_name)),
					("kube_dns_service_ip", Text(network.dns_service_ip)),
					("cluster_cidrs", Texts([network.pod_cidr, network.service_cidr, network.subnet_cidr])),
				]

				Day2App(bound) => [
					("kube_context", Text(names.cluster.kube_context)),
					("app_id", Text(bound.id)),
					("namespace", Text(bound.namespace)),
					("installation", Text(names.installation)),
					("environment", Text(environment)),
					("hosted_domain", Text(names.people_domain)),
					("edge_origin", Text("https://${bound.hostname}")),
					(
						"runtime_resources",
						Fields([
							("memory_mib", Whole(bound.runtime_resources.memory_mib)),
							("cpu_millis", Whole(bound.runtime_resources.cpu_millis)),
							("process_limit", Whole(bound.runtime_resources.process_limit)),
							("http_concurrency", Whole(bound.runtime_resources.http_concurrency)),
							("shutdown_seconds", Whole(bound.runtime_resources.shutdown_seconds)),
						]),
					),
					("pod_pids_limit", Whole(pod_pids_limit)),
					("backup_bucket", Text(bound.backup_bucket)),
				]
			}
		}

		## The root's rendered variables as one .tfvars.json document.
		tfvars_json : Root, InstanceSpec.Derived -> Str
		tfvars_json = |root, names| Value.Fields(root.variables(names)).json()

		## Where the instance commits this root's inputs the spec cannot describe yet, relative to the instance
		## directory. `instance plan` and `apply` pass the file before the rendered variables, so a rendered value
		## wins.
		committed_inputs : Root -> Str
		committed_inputs = |root| match root {
			Project | Cluster | Tenancy => "gcp/config/${root.name()}.tfvars"
			AppEdge(bound) => "gcp/config/app-edge/${bound.id}.tfvars"
			Day2App(bound) => "gcp/config/apps/${bound.id}.tfvars"
		}

		## `instance plan` and `apply` run every core root except day2-app, whose image and artifact inputs come
		## from the release controller (step 3 of docs/INSTANCE.md).
		plannable : Root -> Bool
		plannable = |root| match root {
			Day2App(_) => Bool.False
			Project | Cluster | Tenancy | AppEdge(_) => Bool.True
		}
	}

	## An OpenTofu variable value: a string, a whole number, a list of strings, or an object or map.
	Value := [Text(Str), Whole(U64), Texts(List(Str)), Fields(List((Str, Value)))].{
		json : Value -> Str
		json = |value| match value {
			Text(text) => Json.to_str(text)
			Whole(number) => number.to_str()
			Texts(items) => "[${Str.join_with(items.map(|item| Json.to_str(item)), ",")}]"
			Fields(pairs) => "{${Str.join_with(pairs.map(|pair| "${Json.to_str(pair.0)}:${pair.1.json()}"), ",")}}"
		}
	}

	## What a run of the core roots does: `instance plan` is read-only; `instance apply` applies each saved plan.
	Mode := [Plan, Apply].{
		name : Mode -> Str
		name = |mode| match mode {
			Plan => "plan"
			Apply => "apply"
		}
	}

	## The request `instance plan` or `apply` hands its recipe. The host validates every field again, and refuses
	## a request whose mode differs from the command that started it.
	request : InstanceSpec, Mode, { instance : Str, checkout : Str, output : Str } -> Str
	request = |spec, mode, paths| {
		names = spec.derived()
		Json.to_str({
			mode: mode.name(),
			instance: paths.instance,
			checkout: paths.checkout,
			output: paths.output,
			commit: names.platform_commit,
			project: names.gcp_project,
			zone: names.gcp_zone,
			cluster: names.cluster.name,
			# The host compares these with its own copies and with the platform commit's.
			renderer: [
				{ path: "cli/InstanceSpec.roc", text: instance_spec_source },
				{ path: "cli/InstanceRender.roc", text: instance_render_source },
				{ path: "cli/Names.roc", text: names_source },
				{ path: "cli/JsonValue.roc", text: json_value_source },
			],
			roots: roots(spec)
				.keep_if(|root| root.plannable())
				.map(
					|root| {
						backend = root.backend(names)
						{
							label: root.label(),
							stack: root.name(),
							app_id: root.app_id(),
							bucket: backend.bucket,
							prefix: backend.prefix,
							inputs: root.committed_inputs(),
							variables: root.tfvars_json(names),
						}
					},
				),
		})
	}

	## What the host reports after a run: its mode, the exact stacks and engine, and every root's backend, inputs,
	## status and changed resources. `instance_commit` is empty when the instance is not a git checkout.
	Receipt : {
		format : U64,
		mode : Str,
		ok : Bool,
		commit : Str,
		stacks_tree : Str,
		checkout : Str,
		instance : Str,
		instance_commit : Str,
		instance_clean : Bool,
		engine : { version : Str, digest : Str },
		roots : List(
			{
				label : Str,
				stack : Str,
				backend : { bucket : Str, prefix : Str },
				new_root : Bool,
				inputs : { path : Str, digest : Str },
				variables : Str,
				status : Str,
				changes : List({ address : Str, actions : List(Str) }),
				plan_digest : Str,
				show_digest : Str,
				logs : Str,
			},
		),
		directory : Str,
	}

	## A receipt is accepted only in format 1, for the mode that was run, with that mode's statuses and an `ok`
	## that agrees with them. Only an apply has applied or skipped roots, and a root is skipped only after a failure.
	receipt : Str, Mode -> Try(Receipt, [InvalidReceipt])
	receipt = |raw, mode| {
		parsed : Try(Receipt, _)
		parsed = Json.parse(raw)
		decoded = parsed.map_err(|_| InvalidReceipt)?
		failures = ["failed_credentials", "failed_init", "failed_plan", "failed_show"]
		known = match mode {
			Mode.Plan => ["no_changes", "changes"].concat(failures)
			Mode.Apply => ["no_changes", "applied", "skipped", "failed_apply", "refused_destroy"].concat(failures)
		}
		failed = decoded.roots.any(|root| root.status.starts_with("failed_") or root.status.starts_with("refused_"))
		skipped = decoded.roots.any(|root| root.status == "skipped")
		if
			decoded.format
				== 1
				and decoded.mode
					== mode.name()
					and decoded.roots.all(|root| known.contains(root.status))
						and decoded.ok
							== !failed
							and (failed or !skipped)
				{
					Ok(decoded)
				} else {
					Err(InvalidReceipt)
				}
	}

	roots : InstanceSpec -> List(Root)
	roots = |spec| {
		apps = spec.derived().apps
		[Root.Project, Root.Cluster, Root.Tenancy]
			.concat(apps.map(|bound| Root.AppEdge(bound)))
			.concat(apps.map(|bound| Root.Day2App(bound)))
	}
}

## The cluster's dedicated VPC: the node subnet, the pod and service ranges, and kube-dns at the service range's
## tenth address. App edges admit egress to exactly these ranges.
network : { subnet_cidr : Str, pod_cidr : Str, service_cidr : Str, dns_service_ip : Str }
network = {
	subnet_cidr: "10.10.0.0/20",
	pod_cidr: "10.20.0.0/16",
	service_cidr: "${service_base}.0/20",
	dns_service_ip: "${service_base}.10",
}

service_base : Str
service_base = "10.30.0"

## GKE's minimum pod PID limit, set on the shared node pool and declared by every app pod. day2-app requires it
## to be at most each app's process_limit, so no size preset may go below it.
pod_pids_limit : U64
pod_pids_limit = 1024

## The tenancy root's zonal persistent-disk class for an app's SQLite volume.
storage_class_name : Str
storage_class_name = "app-sqlite-rwo"

## Fixed at an app's first start. Every instance app runs as production.
environment : Str
environment = "production"

sample : Str
sample =
	\\{"kind":"instance","version":1,"installation":"exampleco",
	\\"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
	\\"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com"],
	\\"apps":{"go":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"automatic",
	\\"extension":null,"owners":["ada@example.com"],"size":"standard","verification":4,"schedules":"enabled"},
	\\"home":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"manual",
	\\"extension":null,"owners":["ada@example.com"],"size":"large","verification":6,"schedules":"paused"}}}

backends : Str -> List(Str)
backends = |raw| match InstanceSpec.from_json(raw) {
	Ok(spec) => {
		names = spec.derived()
		InstanceRender.roots(spec)
			.map(
				|
					root,
				| {
					backend = root.backend(names)
					"${root.label()} ${root.stack()} ${backend.bucket}/${backend.prefix}"
				},
			)
	}
	Err(_) => []
}

expect
	backends(sample)
		== [
			"project deploy/gke/stacks/project exampleco-tools-tofu-state/foundation",
			"cluster deploy/gke/stacks/cluster exampleco-tools-tofu-state/platform/cluster",
			"tenancy deploy/gke/stacks/tenancy exampleco-tools-tofu-state/platform/tenancy",
			"app-edge/go deploy/gke/stacks/app-edge exampleco-tools-tofu-state/platform/app/go",
			"app-edge/home deploy/gke/stacks/app-edge exampleco-tools-tofu-state/platform/app/home",
			"day2-app/go deploy/gke/stacks/day2-app exampleco-tools-go-state/day2-app/go",
			"day2-app/home deploy/gke/stacks/day2-app exampleco-tools-home-state/day2-app/home",
		]

tfvars : Str -> List(Str)
tfvars = |raw| match InstanceSpec.from_json(raw) {
	Ok(spec) => {
		names = spec.derived()
		InstanceRender.roots(spec).map(|root| "${root.label()} ${root.tfvars_json(names)}")
	}
	Err(_) => []
}

expect
	tfvars(sample)
		== [
			"project {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"state_bucket_name\":\"exampleco-tools-tofu-state\",\"state_prefixes\":{\"foundation\":\"foundation/\",\"cluster\":\"platform/cluster/\",\"tenancy\":\"platform/tenancy/\",\"app\":\"platform/app/\",\"day2\":\"day2/\"}}",
			"cluster {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"zone\":\"us-central1-a\",\"cluster_name\":\"day2\",\"cluster_labels\":{\"managed_by\":\"opentofu\",\"stack\":\"platform-cluster\",\"environment\":\"day2\"},\"subnet_cidr\":\"10.10.0.0/20\",\"pod_cidr\":\"10.20.0.0/16\",\"service_cidr\":\"10.30.0.0/20\",\"shared_node_pod_pids_limit\":1024}",
			"tenancy {\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_namespace_prefix\":\"app-\"}",
			"app-edge/go {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"cluster_name\":\"day2\",\"cluster_location\":\"us-central1-a\",\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"go\",\"namespace_prefix\":\"app-\",\"domain\":\"go.apps.example.com\",\"iap_members\":[\"domain:example.com\",\"user:ada@example.com\"],\"deployer_subjects\":[\"user:ada@example.com\"],\"offsite_backup_readers\":[\"user:ada@example.com\"],\"sqlite_storage_gb\":5,\"storage_class_name\":\"app-sqlite-rwo\",\"kube_dns_service_ip\":\"10.30.0.10\",\"cluster_cidrs\":[\"10.20.0.0/16\",\"10.30.0.0/20\",\"10.10.0.0/20\"]}",
			"app-edge/home {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"cluster_name\":\"day2\",\"cluster_location\":\"us-central1-a\",\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"home\",\"namespace_prefix\":\"app-\",\"domain\":\"home.apps.example.com\",\"iap_members\":[\"domain:example.com\",\"user:ada@example.com\"],\"deployer_subjects\":[\"user:ada@example.com\"],\"offsite_backup_readers\":[\"user:ada@example.com\"],\"sqlite_storage_gb\":5,\"storage_class_name\":\"app-sqlite-rwo\",\"kube_dns_service_ip\":\"10.30.0.10\",\"cluster_cidrs\":[\"10.20.0.0/16\",\"10.30.0.0/20\",\"10.10.0.0/20\"]}",
			"day2-app/go {\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"go\",\"namespace\":\"app-go\",\"installation\":\"exampleco\",\"environment\":\"production\",\"hosted_domain\":\"example.com\",\"edge_origin\":\"https://go.apps.example.com\",\"runtime_resources\":{\"memory_mib\":512,\"cpu_millis\":1000,\"process_limit\":1024,\"http_concurrency\":4,\"shutdown_seconds\":30},\"pod_pids_limit\":1024,\"backup_bucket\":\"exampleco-tools-go-backups\"}",
			"day2-app/home {\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"home\",\"namespace\":\"app-home\",\"installation\":\"exampleco\",\"environment\":\"production\",\"hosted_domain\":\"example.com\",\"edge_origin\":\"https://home.apps.example.com\",\"runtime_resources\":{\"memory_mib\":2048,\"cpu_millis\":1000,\"process_limit\":1024,\"http_concurrency\":4,\"shutdown_seconds\":30},\"pod_pids_limit\":1024,\"backup_bucket\":\"exampleco-tools-home-backups\"}",
		]

# day2-app's precondition: the node pool's pod PID limit is the only process bound, so it must be at most each
# app's process_limit. The sample has one app of each size.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => spec.derived().apps.all(|bound| pod_pids_limit <= bound.runtime_resources.process_limit)
	Err(_) => Bool.False
}

# A string value is JSON-escaped.
expect InstanceRender.Value.Fields([("a\"b", Text("c\\d"))]).json() == "{\"a\\\"b\":\"c\\\\d\"}"

receipt_sample : Str, Bool -> Str
receipt_sample = |status, ok|
	\\{"format":1,"mode":"plan","ok":OK,"commit":"c","stacks_tree":"t","checkout":"/p","instance":"/i",
	\\"instance_commit":"","instance_clean":false,"engine":{"version":"1.12.3","digest":"sha256:e"},
	\\"roots":[{"label":"project","stack":"project","backend":{"bucket":"b","prefix":"foundation"},"new_root":false,
	\\"inputs":{"path":"gcp/config/project.tfvars","digest":"sha256:i"},"variables":"sha256:v","status":"STATUS",
	\\"changes":[],"plan_digest":"sha256:p","show_digest":"sha256:s","logs":"/o/project"}],"directory":"/o"}
		.replace_first("OK", if ok "true" else "false")
		.replace_first("STATUS", status)

apply_sample : Str, Bool -> Str
apply_sample = |status, ok| receipt_sample(status, ok).replace_first("\"mode\":\"plan\"", "\"mode\":\"apply\"")

expect InstanceRender.receipt(receipt_sample("no_changes", Bool.True), InstanceRender.Mode.Plan).is_ok()
expect InstanceRender.receipt(receipt_sample("failed_plan", Bool.False), InstanceRender.Mode.Plan).is_ok()
# An ok that disagrees with the statuses, an unknown status or another mode's receipt is refused.
expect InstanceRender.receipt(receipt_sample("failed_plan", Bool.True), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(receipt_sample("no_changes", Bool.False), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(receipt_sample("planned", Bool.True), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(receipt_sample("no_changes", Bool.True), InstanceRender.Mode.Apply).is_err()
# A plan never applies or skips; an apply's refusals and failures fail it, and it skips only after one.
expect InstanceRender.receipt(receipt_sample("applied", Bool.True), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(apply_sample("applied", Bool.True), InstanceRender.Mode.Apply).is_ok()
expect InstanceRender.receipt(apply_sample("refused_destroy", Bool.False), InstanceRender.Mode.Apply).is_ok()
expect InstanceRender.receipt(apply_sample("refused_destroy", Bool.True), InstanceRender.Mode.Apply).is_err()
expect InstanceRender.receipt(apply_sample("failed_apply", Bool.True), InstanceRender.Mode.Apply).is_err()
expect InstanceRender.receipt(apply_sample("skipped", Bool.True), InstanceRender.Mode.Apply).is_err()
expect InstanceRender.receipt(apply_sample("changes", Bool.True), InstanceRender.Mode.Apply).is_err()

# The request carries its mode and the CLI's own rendering sources.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		request = InstanceRender.request(spec, InstanceRender.Mode.Apply, { instance: "i", checkout: "p", output: "o" })
		request.contains("\"path\":\"cli/InstanceRender.roc\"") and request.contains("\"mode\":\"apply\"")
	}
	Err(_) => Bool.False
}
