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
##
## App CI's federation (project) and results buckets (app-edge) render only when day2.json sets forge.oidc; without it
## every root renders exactly what it did before app CI existed.
InstanceRender :: [].{

	## `app_ci_repository` is the forge repository whose IDs the root's app CI variables need, which plan and apply
	## read from the forge: none without forge.oidc.
	RootRequest : {
		label : Str,
		stack : Str,
		app_id : Try(Str, [Null]),
		bucket : Str,
		prefix : Str,
		inputs : Str,
		variables : Str,
		app_ci_repository : Try(Str, [Null]),
	}

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
		## choices, discovered IDs, images and digests, extension routes, and per-app identities, secrets,
		## catalogs and labels. App CI's variable comes last, and only with forge.oidc.
		variables : Root, InstanceSpec.Derived -> List((Str, Value))
		variables = |root, names| root.core_variables(names).concat(root.app_ci(names))

		## App CI's rendered variable when day2.json sets forge.oidc: the project root's federation (the issuer and the CI
		## repository) and each app edge's results bucket (its derived name, and the apply identity, which reads results
		## when it builds candidates). Without forge.oidc nothing renders, so neither stack creates anything for app CI.
		app_ci : Root, InstanceSpec.Derived -> List((Str, Value))
		app_ci = |root, names| match (root, names.forge_oidc) {
			(Project, Ok(issuer)) => [
				("app_ci", Fields([("issuer_uri", Text(issuer)), ("repository", Text(names.ci_repository))])),
			]
			(AppEdge(bound), Ok(_)) => [
				(
					"app_ci",
					Fields(
						[("bucket", Text(bound.ci_bucket)), ("reader", Text("serviceAccount:${names.apply_identity}"))],
					),
				),
			]
			_ => []
		}

		## The forge repository whose IDs the root's app CI variable needs: the CI repository for the project root, the
		## app's repository for its edge, and none without forge.oidc. Plan and apply read the IDs on every run.
		app_ci_repository : Root, InstanceSpec.Derived -> Try(Str, [Null])
		app_ci_repository = |root, names| match (root, names.forge_oidc) {
			(Project, Ok(_)) => Ok(names.ci_repository)
			(AppEdge(bound), Ok(_)) => Ok(bound.repository)
			_ => Err(Null)
		}

		core_variables : Root, InstanceSpec.Derived -> List((Str, Value))
		core_variables = |root, names| {
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
					# The only paths that bypass IAP: the pinned extension's CRX and update manifest, or none. The
					# platform always renders them, so a committed copy can never publish another path.
					(
						"public_download_paths",
						Texts(
							match bound.extension {
								Ok(extension) => extension.downloads
								Err(Null) => []
							},
						),
					),
				]

				Day2App(bound) => [
					("kube_context", Text(names.cluster.kube_context)),
					("app_id", Text(bound.id)),
					("namespace", Text(bound.namespace)),
					("installation", Text(names.installation)),
					("environment", Text(environment)),
					("hosted_domain", Text(names.people_domain)),
					# Day2 renders the app's access policy from these at activation.
					("admins", Texts(bound.admins)),
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
		## wins; app CI's forge IDs come next, and a day2-app root's release variables, read from the app's selection,
		## come last.
		committed_inputs : Root -> Str
		committed_inputs = |root| match root {
			Project | Cluster | Tenancy => "gcp/config/${root.name()}.tfvars"
			AppEdge(bound) => "gcp/config/app-edge/${bound.id}.tfvars"
			Day2App(bound) => "gcp/config/apps/${bound.id}.tfvars"
		}

		## The root as the request names it to the host.
		as_request : Root, InstanceSpec.Derived -> RootRequest
		as_request = |root, names| {
			root_backend = root.backend(names)
			{
				label: root.label(),
				stack: root.name(),
				app_id: root.app_id(),
				bucket: root_backend.bucket,
				prefix: root_backend.prefix,
				inputs: root.committed_inputs(),
				variables: root.tfvars_json(names),
				app_ci_repository: root.app_ci_repository(names),
			}
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

	## What a run of the roots does: `instance plan` is read-only; `instance apply` applies each root's saved plan
	## only if its changes equal the ones reviewed in a prior plan's output directory, which it carries; a deploy
	## (`instance deploy`) applies one app's day2-app root for the candidate its selection names.
	Mode := [Plan, Apply(Str), Deploy].{
		name : Mode -> Str
		name = |mode| match mode {
			Plan => "plan"
			Apply(_) => "apply"
			Deploy => "deploy"
		}

		## The reviewed plan directory an apply checks every root against; a plan and a deploy have none.
		reviewed : Mode -> Try(Str, [Null])
		reviewed = |mode| match mode {
			Plan | Deploy => Err(Null)
			Apply(directory) => Ok(directory)
		}
	}

	## The request `instance plan` or `apply` hands its recipe: every root, in apply order. The host validates every
	## field again, and refuses a request whose mode differs from the command that started it.
	request : InstanceSpec, Mode, { instance : Str, checkout : Str, output : Str } -> Str
	request = |spec, mode, paths| {
		names = spec.derived()
		no_candidate : Try(Str, [Null])
		no_candidate = Err(Null)
		rendered(spec, mode, paths, roots(spec).map(|root| root.as_request(names)), no_candidate)
	}

	## The request a deploy (`instance deploy`) hands the roots recipe: only the app `id`'s day2-app root, rendered
	## exactly as `request` renders it, and the candidate record file being deployed. `paths.output` must be a new
	## directory.
	deploy_request :
		InstanceSpec,
		Str,
		Str,
		{ instance : Str, checkout : Str, output : Str } ->
			Try(Str, [UnknownApp(Str)])
	deploy_request = |spec, id, candidate, paths| {
		names = spec.derived()
		match names.apps.keep_if(|bound| bound.id == id).first() {
			Ok(bound) => Ok(rendered(spec, Mode.Deploy, paths, [Root.Day2App(bound).as_request(names)], Ok(candidate)))
			Err(_) => Err(UnknownApp(id))
		}
	}

	## A day2-app root's release, as the receipt records it: where it came from (the app's `selection`, or a
	## deploy's `candidate` file, at `record`), the selection it was read from or checked against (its generation,
	## status and record digest; null before a deploy checks it), and what it renders.
	Release : {
		source : Str,
		record : Str,
		generation : Try(Str, [Null]),
		status : Try(Str, [Null]),
		digest : Try(Str, [Null]),
		candidate : Str,
		commit : Str,
		image : Str,
		artifact_id : Str,
		tooling_image : Str,
		qualified_release : { digest : Str, bytes : U64 },
		variables : Str,
	}

	## What the host reports after a run: its mode, the exact stacks and engine, and every root's backend, inputs,
	## status and changed resources; a day2-app root's release, and a deploy's target. `instance_commit` is empty
	## when the instance is not a git checkout.
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
				review : Str,
				changes : List({ address : Str, actions : List(Str) }),
				plan_digest : Str,
				show_digest : Str,
				logs : Str,
				release : Try(Release, [Null]),
				target : Try({ path : Str, digest : Str, bytes : U64 }, [Null]),
			},
		),
		directory : Str,
	}

	## A receipt is accepted only in format 2, for the mode that was run, with that mode's statuses and an `ok`
	## that agrees with them. Only an apply has skipped roots, and a root is skipped only after a failure. An app
	## with no release selection is unreleased in a plan or an apply; a deploy's root is not applied when the deploy
	## stopped before its apply.
	receipt : Str, Mode -> Try(Receipt, [InvalidReceipt])
	receipt = |raw, mode| {
		parsed : Try(Receipt, _)
		parsed = Json.parse(raw)
		decoded = parsed.map_err(|_| InvalidReceipt)?
		failures = [
			"failed_credentials",
			"failed_forge",
			"failed_inputs",
			"failed_release",
			"failed_init",
			"failed_plan",
			"failed_show",
		]
		known = match mode {
			Mode.Plan => ["no_changes", "changes", "unreleased"].concat(failures)
			Mode.Apply(_) => [
				"no_changes",
				"applied",
				"unreleased",
				"skipped",
				"failed_apply",
				"refused_destroy",
				"refused_unreviewed",
			]
				.concat(failures)
			Mode.Deploy => [
				"no_changes",
				"applied",
				"not_applied",
				"failed_target",
				"failed_apply",
				"refused_destroy",
			]
				.concat(failures)
		}
		failed = decoded.roots.any(|root| root.status.starts_with("failed_") or root.status.starts_with("refused_"))
		skipped = decoded.roots.any(|root| root.status == "skipped")
		if
			decoded.format
				== 2
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

	## Every root an instance applies, in apply order.
	roots : InstanceSpec -> List(Root)
	roots = |spec| {
		apps = spec.derived().apps
		[Root.Project, Root.Cluster, Root.Tenancy]
			.concat(apps.map(|bound| Root.AppEdge(bound)))
			.concat(apps.map(|bound| Root.Day2App(bound)))
	}
}

## The request for `roots` in `mode`, with the CLI's own rendering sources and the instance's releases.
rendered :
	InstanceSpec,
	InstanceRender.Mode,
	{ instance : Str, checkout : Str, output : Str },
	List(InstanceRender.RootRequest),
	Try(Str, [Null]) ->
		Str
rendered = |spec, mode, paths, selected, candidate| {
	names = spec.derived()
	Json.to_str({
		mode: mode.name(),
		reviewed: mode.reviewed(),
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
		roots: selected,
		# Where a day2-app root's release selection, candidate and SDK release are read and admitted.
		releases: {
			bucket: names.tofu_state_bucket,
			registry: names.artifact_registry,
			forge: { server: names.forge_server, org: names.forge_org },
		},
		candidate,
	})
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
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools",
	\\"oidc":"https://git-oidc.example.com"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com"],
	\\"apps":{"go":{"sdk":"sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848","delivery":"automatic",
	\\"extension":"jldmikbinomhomcbmeppagennfohakni","owners":["ada@example.com"],"size":"standard","verification":4,"schedules":"enabled"},
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

## The sample without forge.oidc: an instance that has not turned app CI on.
sample_without_oidc : Str
sample_without_oidc = sample.replace_first(",\n\"oidc\":\"https://git-oidc.example.com\"", "")

tfvars : Str -> List(Str)
tfvars = |raw| match InstanceSpec.from_json(raw) {
	Ok(spec) => {
		names = spec.derived()
		InstanceRender.roots(spec).map(|root| "${root.label()} ${root.tfvars_json(names)}")
	}
	Err(_) => []
}

# Golden: without forge.oidc. Only the edges carry an extension's download paths, and an edge without one renders none.
expect
	tfvars(sample_without_oidc)
		== [
			"project {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"state_bucket_name\":\"exampleco-tools-tofu-state\",\"state_prefixes\":{\"foundation\":\"foundation/\",\"cluster\":\"platform/cluster/\",\"tenancy\":\"platform/tenancy/\",\"app\":\"platform/app/\",\"day2\":\"day2/\"}}",
			"cluster {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"zone\":\"us-central1-a\",\"cluster_name\":\"day2\",\"cluster_labels\":{\"managed_by\":\"opentofu\",\"stack\":\"platform-cluster\",\"environment\":\"day2\"},\"subnet_cidr\":\"10.10.0.0/20\",\"pod_cidr\":\"10.20.0.0/16\",\"service_cidr\":\"10.30.0.0/20\",\"shared_node_pod_pids_limit\":1024}",
			"tenancy {\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_namespace_prefix\":\"app-\"}",
			"app-edge/go {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"cluster_name\":\"day2\",\"cluster_location\":\"us-central1-a\",\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"go\",\"namespace_prefix\":\"app-\",\"domain\":\"go.apps.example.com\",\"iap_members\":[\"domain:example.com\",\"user:ada@example.com\"],\"deployer_subjects\":[\"user:ada@example.com\"],\"offsite_backup_readers\":[\"user:ada@example.com\"],\"sqlite_storage_gb\":5,\"storage_class_name\":\"app-sqlite-rwo\",\"kube_dns_service_ip\":\"10.30.0.10\",\"cluster_cidrs\":[\"10.20.0.0/16\",\"10.30.0.0/20\",\"10.10.0.0/20\"],\"public_download_paths\":[\"/downloads/go.crx\",\"/downloads/updates.xml\"]}",
			"app-edge/home {\"project_id\":\"exampleco-tools\",\"region\":\"us-central1\",\"cluster_name\":\"day2\",\"cluster_location\":\"us-central1-a\",\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"home\",\"namespace_prefix\":\"app-\",\"domain\":\"home.apps.example.com\",\"iap_members\":[\"domain:example.com\",\"user:ada@example.com\"],\"deployer_subjects\":[\"user:ada@example.com\"],\"offsite_backup_readers\":[\"user:ada@example.com\"],\"sqlite_storage_gb\":5,\"storage_class_name\":\"app-sqlite-rwo\",\"kube_dns_service_ip\":\"10.30.0.10\",\"cluster_cidrs\":[\"10.20.0.0/16\",\"10.30.0.0/20\",\"10.10.0.0/20\"],\"public_download_paths\":[]}",
			"day2-app/go {\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"go\",\"namespace\":\"app-go\",\"installation\":\"exampleco\",\"environment\":\"production\",\"hosted_domain\":\"example.com\",\"admins\":[\"ada@example.com\",\"tools-infra@exampleco-tools.iam.gserviceaccount.com\"],\"edge_origin\":\"https://go.apps.example.com\",\"runtime_resources\":{\"memory_mib\":512,\"cpu_millis\":1000,\"process_limit\":1024,\"http_concurrency\":4,\"shutdown_seconds\":30},\"pod_pids_limit\":1024,\"backup_bucket\":\"exampleco-tools-go-backups\"}",
			"day2-app/home {\"kube_context\":\"gke_exampleco-tools_us-central1-a_day2\",\"app_id\":\"home\",\"namespace\":\"app-home\",\"installation\":\"exampleco\",\"environment\":\"production\",\"hosted_domain\":\"example.com\",\"admins\":[\"ada@example.com\",\"tools-infra@exampleco-tools.iam.gserviceaccount.com\"],\"edge_origin\":\"https://home.apps.example.com\",\"runtime_resources\":{\"memory_mib\":2048,\"cpu_millis\":1000,\"process_limit\":1024,\"http_concurrency\":4,\"shutdown_seconds\":30},\"pod_pids_limit\":1024,\"backup_bucket\":\"exampleco-tools-home-backups\"}",
		]

# With forge.oidc, only the project root and each app edge gain app CI's variable, last; every other byte stays.
expect {
	without = tfvars(sample_without_oidc)
	with_oidc = tfvars(sample)
	project_ci = ",\"app_ci\":{\"issuer_uri\":\"https://git-oidc.example.com\",\"repository\":\"tools/day2-ci\"}}"
	edge_ci =
		|
			id,
		|
			",\"app_ci\":{\"bucket\":\"exampleco-tools-${id}-ci\",\"reader\":\"serviceAccount:tools-infra@exampleco-tools.iam.gserviceaccount.com\"}}"
	extended = |line, extra| "${line.drop_suffix("}")}${extra}"
	expected = without.map_with_index(
		|line, index| match index {
			0 => extended(line, project_ci)
			3 => extended(line, edge_ci("go"))
			4 => extended(line, edge_ci("home"))
			_ => line
		},
	)
	with_oidc == expected and with_oidc.len() == 7
}

# The host reads app CI's forge IDs only with forge.oidc: the CI repository for the project root, each app's own
# repository for its edge, and nothing for any other root.
expect {
	repositories = |raw| match InstanceSpec.from_json(raw) {
		Ok(spec) => {
			names = spec.derived()
			InstanceRender.roots(spec).map(|root| root.app_ci_repository(names))
		}
		Err(_) => []
	}
	none : Try(Str, [Null])
	none = Err(Null)
	repositories(sample) == [Ok("tools/day2-ci"), none, none, Ok("tools/go"), Ok("tools/home"), none, none]
		and repositories(sample_without_oidc) == [none, none, none, none, none, none, none]
}

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
	\\{"format":2,"mode":"plan","ok":OK,"commit":"c","stacks_tree":"t","checkout":"/p","instance":"/i",
	\\"instance_commit":"","instance_clean":false,"engine":{"version":"1.12.3","digest":"sha256:e"},
	\\"roots":[{"label":"project","stack":"project","backend":{"bucket":"b","prefix":"foundation"},"new_root":false,
	\\"inputs":{"path":"gcp/config/project.tfvars","digest":"sha256:i"},"variables":"sha256:v","status":"STATUS","review":"",
	\\"changes":[],"plan_digest":"sha256:p","show_digest":"sha256:s","logs":"/o/project","release":null,"target":null}],
	\\"directory":"/o"}
		.replace_first("OK", if ok "true" else "false")
		.replace_first("STATUS", status)

apply_sample : Str, Bool -> Str
apply_sample = |status, ok| receipt_sample(status, ok).replace_first("\"mode\":\"plan\"", "\"mode\":\"apply\"")

deploy_sample : Str, Bool -> Str
deploy_sample = |status, ok| receipt_sample(status, ok).replace_first("\"mode\":\"plan\"", "\"mode\":\"deploy\"")

# A day2-app root's release, as the host records it.
release_sample : Str
release_sample =
	\\"release":{"source":"selection","record":"gs://b/day2/app-releases/go/selection.json",
	\\"generation":"7","status":"ready","digest":"sha256:s","candidate":"sha256:c","commit":"c","image":"i",
	\\"artifact_id":"a","tooling_image":"t","qualified_release":{"digest":"sha256:q","bytes":1236},
	\\"variables":"sha256:v"}

released_sample : Str
released_sample = receipt_sample("no_changes", Bool.True).replace_first("\"release\":null", release_sample)

expect InstanceRender.receipt(receipt_sample("no_changes", Bool.True), InstanceRender.Mode.Plan).is_ok()
expect InstanceRender.receipt(receipt_sample("failed_plan", Bool.False), InstanceRender.Mode.Plan).is_ok()
# An ok that disagrees with the statuses, an unknown status or another mode's receipt is refused.
expect InstanceRender.receipt(receipt_sample("failed_plan", Bool.True), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(receipt_sample("no_changes", Bool.False), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(receipt_sample("planned", Bool.True), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(receipt_sample("no_changes", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
# A plan never applies or skips; an apply's refusals and failures fail it, and it skips only after one.
expect InstanceRender.receipt(receipt_sample("applied", Bool.True), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(apply_sample("applied", Bool.True), InstanceRender.Mode.Apply("/r")).is_ok()
expect InstanceRender.receipt(apply_sample("refused_destroy", Bool.False), InstanceRender.Mode.Apply("/r")).is_ok()
expect InstanceRender.receipt(apply_sample("refused_destroy", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
expect InstanceRender.receipt(apply_sample("failed_apply", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
expect InstanceRender.receipt(apply_sample("skipped", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
expect InstanceRender.receipt(apply_sample("changes", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
expect InstanceRender.receipt(apply_sample("refused_unreviewed", Bool.False), InstanceRender.Mode.Apply("/r")).is_ok()
# An unreleased app is not a failure in a plan or an apply; a failed release or refused committed input is.
expect InstanceRender.receipt(receipt_sample("unreleased", Bool.True), InstanceRender.Mode.Plan).is_ok()
expect InstanceRender.receipt(apply_sample("unreleased", Bool.True), InstanceRender.Mode.Apply("/r")).is_ok()
expect InstanceRender.receipt(receipt_sample("failed_release", Bool.False), InstanceRender.Mode.Plan).is_ok()
expect InstanceRender.receipt(receipt_sample("failed_inputs", Bool.True), InstanceRender.Mode.Plan).is_err()
# So is an app CI repository the forge could not read.
expect InstanceRender.receipt(receipt_sample("failed_forge", Bool.False), InstanceRender.Mode.Plan).is_ok()
expect InstanceRender.receipt(apply_sample("failed_forge", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
# A deploy applies or not, never plans, skips or is unreleased; only it fails at its target.
expect InstanceRender.receipt(deploy_sample("applied", Bool.True), InstanceRender.Mode.Deploy).is_ok()
expect InstanceRender.receipt(deploy_sample("not_applied", Bool.True), InstanceRender.Mode.Deploy).is_ok()
expect InstanceRender.receipt(deploy_sample("failed_target", Bool.False), InstanceRender.Mode.Deploy).is_ok()
expect InstanceRender.receipt(deploy_sample("unreleased", Bool.True), InstanceRender.Mode.Deploy).is_err()
expect InstanceRender.receipt(deploy_sample("skipped", Bool.True), InstanceRender.Mode.Deploy).is_err()
expect InstanceRender.receipt(receipt_sample("failed_target", Bool.False), InstanceRender.Mode.Plan).is_err()
expect InstanceRender.receipt(deploy_sample("applied", Bool.True), InstanceRender.Mode.Apply("/r")).is_err()
# A receipt of the earlier format is refused.
expect
	InstanceRender.receipt(
		receipt_sample("no_changes", Bool.True).replace_first("\"format\":2", "\"format\":1"),
		InstanceRender.Mode.Plan,
	)
		.is_err()
# A day2-app root's release decodes with its selection.
expect match InstanceRender.receipt(released_sample, InstanceRender.Mode.Plan) {
	Ok(receipt) => match receipt.roots.first() {
		Ok(root) => match root.release {
			Ok(release) => release.image == "i" and release.status == Ok("ready")
			Err(_) => Bool.False
		}
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

# The request carries its mode and the CLI's own rendering sources.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		request =
			InstanceRender.request(
				spec,
				InstanceRender.Mode.Apply("/reviewed"),
				{ instance: "i", checkout: "p", output: "o" },
			)
		request.contains("\"path\":\"cli/InstanceRender.roc\"")
			and request.contains("\"mode\":\"apply\"")
				and request.contains("\"reviewed\":\"/reviewed\"")
					and request.contains("\"candidate\":null")
	}
	Err(_) => Bool.False
}

request_summary :
	Str ->
		Try(
			{
				mode : Str,
				reviewed : Try(Str, [Null]),
				roots : List(InstanceRender.RootRequest),
				releases : { bucket : Str, registry : Str, forge : { server : Str, org : Str } },
				candidate : Try(Str, [Null]),
			},
			Str,
		)
request_summary = |request| Json.parse(request).map_err(|_| "invalid app root request")

# Plan and apply run every root, the day2-app roots last, with where the instance's releases live.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		request = InstanceRender.request(spec, InstanceRender.Mode.Plan, { instance: "i", checkout: "p", output: "o" })
		match request_summary(request) {
			Ok(decoded) => match decoded.roots.last() {
				Ok(home) =>
					home.label == "day2-app/home" and home.stack == "day2-app" and home.app_id == Ok("home")
						and home.bucket == "exampleco-tools-home-state" and home.prefix == "day2-app/home"
							and home.inputs == "gcp/config/apps/home.tfvars" and decoded.releases == {
								bucket: "exampleco-tools-tofu-state",
								registry: "us-central1-docker.pkg.dev/exampleco-tools",
								forge: { server: "https://git.example.com", org: "tools" },
							}
				Err(_) => Bool.False
			}
			Err(_) => Bool.False
		}
	}
	Err(_) => Bool.False
}

# A deploy's request holds only its app's day2-app root and the candidate it deploys.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		paths = { instance: "i", checkout: "p", output: "o/roots" }
		match InstanceRender.deploy_request(spec, "go", "/c/candidate.json", paths) {
			Ok(request) => match request_summary(request) {
				Ok(decoded) => decoded.mode == "deploy" and decoded.reviewed == Err(Null)
					and decoded.roots.map(|root| root.label) == ["day2-app/go"]
						and decoded.candidate == Ok("/c/candidate.json")
				Err(_) => Bool.False
			}
			Err(_) => Bool.False
		}
			and InstanceRender.deploy_request(spec, "notes", "/c/candidate.json", paths) == Err(UnknownApp("notes"))
	}
	Err(_) => Bool.False
}
