import InstanceSpec

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
	}

	roots : InstanceSpec -> List(Root)
	roots = |spec| {
		apps = spec.derived().apps
		[Root.Project, Root.Cluster, Root.Tenancy]
			.concat(apps.map(|bound| Root.AppEdge(bound)))
			.concat(apps.map(|bound| Root.Day2App(bound)))
	}
}

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
