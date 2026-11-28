import Names
import JsonValue
import Problem
import Metadata

## An instance repository's only authored input: DIRECTORY/day2.json.
## Every object is exact (each field required, unknown fields rejected) and
## lists are strictly sorted, so one spec has one spelling. Repository,
## hostname, namespace, image, bucket and state names are derived here and
## cannot be configured, restated or overridden.
InstanceSpec :: {
	installation : Names.Identifier,
	commit : Str,
	project : Str,
	region : Str,
	zone : Str,
	server : Str,
	org : Str,
	oidc : Try(Str, [Null]),
	people : Str,
	domain : Str,
	operators : List(Str),
	apps : List(SpecApp),
}.{

	## The platform's own source. An instance selects a commit, never a fork.
	platform_repository = "github.com/clankernative/platform"

	## The job context of <org>/day2-ci's required org-scoped workflow. Gitea posts
	## it as "<org>/day2-ci: day2 / verification (pull_request)". The derived name is
	## the required pattern of that workflow's org registration, not a branch
	## protection context: Gitea then counts only a status its Actions user produced
	## for that source workflow, so neither an app workflow nor an API caller can
	## satisfy it. The gate applies to any branch that has a protection rule.
	required_context = "day2 / verification (pull_request)"

	App : {
		id : Str,
		delivery : Str,
		sdk : Str,
		owners : List(Str),

		## day2-app's `admins`: the owners and the instance's apply identity, sorted. Day2 renders the app's access
		## policy from them at activation. The apply identity is an admin so the instance's automatic maintenance
		## can act on the app; the `owners` selector still admits only the people.
		admins : List(Str),
		size : Str,
		verification : U64,
		schedules : Str,
		extension : Try(Extension, [Null]),
		repository : Str,
		hostname : Str,
		namespace : Str,
		image : Str,
		state_bucket : Str,
		state_prefix : Str,
		edge_state_prefix : Str,
		backup_bucket : Str,

		## App CI's result bucket: the required workflow stores each checked artifact and its receipt here.
		ci_bucket : Str,

		## The size preset's runtime limits, exactly day2-app's runtime_resources.
		runtime_resources : Resources,

		## The size preset's SQLite volume in GiB. Every preset uses one size until resizing is designed, because
		## moving an app to a size with a smaller volume would try to shrink its PVC.
		sqlite_storage_gb : U64,
	}

	Resources : {
		memory_mib : U64,
		cpu_millis : U64,
		process_limit : U64,
		http_concurrency : U64,
		shutdown_seconds : U64,
	}

	## A self-hosted Chrome extension: every name is derived from the app and its pinned ID.
	Extension : {
		id : Str,
		update_url : Str,

		## The CRX and update manifest paths, sorted: exactly the app edge's `public_download_paths`.
		downloads : List(Str),
		signing_secret : Str,
	}

	Derived : {
		installation : Str,
		platform_repository : Str,
		platform_commit : Str,
		forge_kind : Str,
		forge_server : Str,
		forge_org : Str,

		## The instance's OIDC broker for its forge's Actions jobs (git-oidc), an https origin. Gitea mints no OIDC token
		## itself; app CI's store step requests one here.
		forge_oidc : Try(Str, [Null]),
		gcp_project : Str,
		gcp_region : Str,
		gcp_zone : Str,
		people_domain : Str,
		apps_domain : Str,
		operators : List(Str),

		## The service account the instance applies its roots and maintains its apps as. The instance's bootstrap
		## creates it; the platform only names it.
		apply_identity : Str,
		instance_repository : Str,
		ci_repository : Str,
		required_check : Str,

		## The workload identity pool and provider app CI's store step federates through: Google STS exchanges the
		## git-oidc token for their audience, which also needs the project's number, discovered when the workflow renders.
		ci_workload_identity : { pool : Str, provider : Str },

		## The OIDC token request app CI's store step sends, before it names its repository: `<forge.oidc>/token?v=1`.
		## None without forge.oidc: such an instance cannot render app CI's workflow yet.
		ci_token_request : Try(Str, [Null]),

		## The project's Artifact Registry, <region>-docker.pkg.dev/<project>. Every derived image is under it, and so are
		## the images a qualified SDK release pins.
		artifact_registry : Str,
		sdk_registry : Str,
		tofu_state_bucket : Str,
		platform_state_prefixes : { project : Str, cluster : Str, tenancy : Str, app_edge : Str, day2 : Str },
		cluster : { name : Str, kube_context : Str },

		## The VM that builds app candidates: the qualification runner stack's, in the instance's zone, reached through
		## IAP as the apply identity.
		build_host : { name : Str, zone : Str },
		app_namespace_prefix : Str,
		apps : List(App),
	}

	file_name = "day2.json"

	load! : Names.LocalPath => Try((Names.LocalPath, InstanceSpec), Problem)
	load! = |directory| {
		root = Metadata.absolute!(directory)?
		trimmed = trim_directory(root.to_str())
		path =
			Names.LocalPath.from_str("${trimmed}/${file_name}")
				.map_err(|_| Problem.InvalidContext("spec path exceeds the path budget"))?
		spec = from_json(Metadata.read!(path)?)?
		Ok((path, spec))
	}

	from_json : Str -> Try(InstanceSpec, Problem)
	from_json = |raw| checked(raw).map_err(|BadJson(detail)| Problem.InvalidSpec(detail))

	derived : InstanceSpec -> Derived
	derived = |spec| {
		registry = "${spec.region}-docker.pkg.dev/${spec.project}"
		tofu_state_bucket = "${spec.project}-tofu-state"
		apply_identity = "${spec.org}-infra@${spec.project}.iam.gserviceaccount.com"
		{
			installation: spec.installation.to_str(),
			platform_repository,
			platform_commit: spec.commit,
			forge_kind: "gitea",
			forge_server: spec.server,
			forge_org: spec.org,
			forge_oidc: spec.oidc,
			gcp_project: spec.project,
			gcp_region: spec.region,
			gcp_zone: spec.zone,
			people_domain: spec.people,
			apps_domain: spec.domain,
			operators: spec.operators,
			apply_identity,
			instance_repository: "${spec.org}/day2-instance",
			ci_repository: "${spec.org}/day2-ci",
			required_check: "${spec.org}/day2-ci: ${required_context}",
			ci_workload_identity: { pool: "day2-ci", provider: "gitea" },
			ci_token_request: spec.oidc.map_ok(|oidc| "${oidc}/token?v=1"),
			artifact_registry: registry,
			sdk_registry: "${registry}/day2",
			tofu_state_bucket,
			platform_state_prefixes,
			cluster: { name: cluster_name, kube_context: "gke_${spec.project}_${spec.zone}_${cluster_name}" },
			build_host: { name: build_host_name, zone: spec.zone },
			app_namespace_prefix,
			apps: spec
				.apps
				.map(|bound| derive_app(spec.org, spec.domain, spec.project, registry, apply_identity, bound)),
		}
	}
}

## Where platform state lives in tofu_state_bucket: the core roots, every app edge (app_edge/<id>) and the roots an
## instance opts into, such as its CI integration (day2/<root>). "foundation" predates the platform/<root> scheme;
## moving it is a state move. The installation security shell's prefix is not derived until the shell is rendered.
platform_state_prefixes : { project : Str, cluster : Str, tenancy : Str, app_edge : Str, day2 : Str }
platform_state_prefixes = {
	project: "foundation",
	cluster: "platform/cluster",
	tenancy: "platform/tenancy",
	app_edge: "platform/app",
	day2: "day2",
}

## The one GKE cluster every instance runs.
cluster_name : Str
cluster_name = "day2"

## The qualification runner stack's VM, which builds every app candidate.
build_host_name : Str
build_host_name = "day2-x86-qualify"

## Every app namespace is this prefix and the app ID; tenancy's admission policies match on it.
app_namespace_prefix : Str
app_namespace_prefix = "app-"

## What each size runs with. Only memory differs; every preset has the same 5 GiB volume.
size_preset : Size -> { runtime_resources : InstanceSpec.Resources, sqlite_storage_gb : U64 }
size_preset = |size| {
	memory_mib = match size {
		Standard => 512
		Large => 2048
	}
	{
		runtime_resources: {
			memory_mib,
			cpu_millis: 1000,
			process_limit: 1024,
			http_concurrency: 4,
			shutdown_seconds: 30,
		},
		sqlite_storage_gb: 5,
	}
}

Delivery : [Automatic, Manual, Paused]

Size : [Standard, Large]

Schedules : [Enabled, Paused]

ExtensionPin : [NoExtension, Pinned(Str)]

SpecApp : {
	id : Names.AppId,
	sdk : Str,
	delivery : Delivery,
	extension : ExtensionPin,
	owners : List(Str),
	size : Size,
	verification : U64,
	schedules : Schedules,
}

derive_app : Str, Str, Str, Str, Str, SpecApp -> InstanceSpec.App
derive_app = |org, domain, project, registry, apply_identity, bound| {
	id = bound.id.to_str()
	hostname = "${id}.${domain}"
	preset = size_preset(bound.size)
	{
		id,
		delivery: delivery_name(bound.delivery),
		sdk: bound.sdk,
		owners: bound.owners,
		admins: bound.owners.append(apply_identity).sort_with(Names.order),
		size: match bound.size {
			Standard => "standard"
			Large => "large"
		},
		verification: bound.verification,
		schedules: match bound.schedules {
			Enabled => "enabled"
			Paused => "paused"
		},
		extension: match bound.extension {
			NoExtension => Err(Null)
			Pinned(extension_id) => Ok({
				id: extension_id,
				update_url: "https://${hostname}/downloads/updates.xml",
				downloads: ["/downloads/${id}.crx", "/downloads/updates.xml"].sort_with(Names.order),
				signing_secret: "${id}-chrome-extension-signing-key",
			})
		},
		repository: "${org}/${id}",
		hostname,
		namespace: "${app_namespace_prefix}${id}",
		image: "${registry}/${id}/${id}",
		state_bucket: "${project}-${id}-state",
		state_prefix: "day2-app/${id}",
		edge_state_prefix: "${platform_state_prefixes.app_edge}/${id}",
		backup_bucket: "${project}-${id}-backups",
		ci_bucket: "${project}-${id}-ci",
		runtime_resources: preset.runtime_resources,
		sqlite_storage_gb: preset.sqlite_storage_gb,
	}
}

delivery_name : Delivery -> Str
delivery_name = |delivery| match delivery {
	Automatic => "automatic"
	Manual => "manual"
	Paused => "paused"
}

trim_directory : Str -> Str
trim_directory = |value| {
	if value.ends_with("/.") {
		trim_directory(value.drop_suffix("/."))
	} else if value.ends_with("/") and value != "/" {
		trim_directory(value.drop_suffix("/"))
	} else {
		value
	}
}

checked : Str -> Try(InstanceSpec, [BadJson(Str)])
checked = |raw| {
	root = JsonValue.parse(raw)?
	exact(
		root,
		"day2.json",
		["kind", "version", "installation", "platform", "gcp", "forge", "domains", "operators", "apps"],
	)?
	kind = text(root, "kind")?
	if kind != "instance" {
		return Err(BadJson("kind must be instance"))
	}
	version = root.get("version")?.u64().map_err(|_| BadJson("version must be 1"))?
	if version != 1 {
		return Err(BadJson("version must be 1"))
	}
	installation =
		Names.Identifier.from_str(text(root, "installation")?)
			.map_err(|_| BadJson("installation must be a lowercase identifier of at most 48 bytes"))?
	commit = text(root, "platform")?
	if !(commit.to_utf8().len() == 40 and commit.to_utf8().all(hex)) {
		return Err(BadJson("platform must be a full 40-character lowercase commit"))
	}
	gcp = root.get("gcp")?
	exact(gcp, "gcp", ["project", "region", "zone"])?
	project = text(gcp, "project")?
	if !valid_project(project) {
		return Err(BadJson("gcp.project must be a 6-30 byte GCP project ID"))
	}
	region = text(gcp, "region")?
	if !valid_region(region) {
		return Err(BadJson("gcp.region must be a GCP region such as us-central1"))
	}
	zone = text(gcp, "zone")?
	if !valid_zone(zone, region) {
		return Err(BadJson("gcp.zone must be a zone of gcp.region, such as ${region}-a"))
	}
	forge = root.get("forge")?
	# forge.oidc is optional, so an instance can add it once its platform pin reads it; forge is exact otherwise.
	has_oidc = forge.get("oidc").is_ok()
	exact(forge, "forge", if has_oidc ["kind", "server", "org", "oidc"] else ["kind", "server", "org"])?
	forge_kind = text(forge, "kind")?
	if forge_kind != "gitea" {
		return Err(BadJson("forge.kind must be gitea"))
	}
	server = text(forge, "server")?
	if !(server.starts_with("https://") and valid_domain(server.drop_prefix("https://"))) {
		return Err(BadJson("forge.server must be https:// and a lowercase host, with no port or path"))
	}
	org = text(forge, "org")?
	if !valid_org(org) {
		return Err(BadJson("forge.org must be 2-24 lowercase letters, digits or inner hyphens, starting with a letter"))
	}
	oidc : Try(Str, [Null])
	oidc = if has_oidc {
		broker = text(forge, "oidc")?
		if !(broker.starts_with("https://") and valid_domain(broker.drop_prefix("https://"))) or broker == server {
			return Err(
				BadJson(
					"forge.oidc must be https:// and a lowercase host other than forge.server, with no port or path",
				),
			)
		}
		Ok(broker)
	} else {
		Err(Null)
	}
	domains = root.get("domains")?
	exact(domains, "domains", ["people", "apps"])?
	people = text(domains, "people")?
	# Every owner is one of an app's rendered admins, and day2-app requires a person among them.
	if !valid_domain(people) or people == "gserviceaccount.com" or people.ends_with(".gserviceaccount.com") {
		return Err(BadJson("domains.people must be a lowercase DNS name, not a service-account domain"))
	}
	domain = text(domains, "apps")?
	if !valid_domain(domain) or domain.count_utf8_bytes() > 232 {
		return Err(BadJson("domains.apps must be a lowercase DNS name of at most 232 bytes"))
	}
	operator_nodes = root.get("operators")?.array().map_err(|_| BadJson("operators must be an array"))?
	if operator_nodes.is_empty() or operator_nodes.len() > 32 {
		return Err(BadJson("operators must list 1 to 32 people"))
	}
	operators = strings(operator_nodes, "operators", [])?
	for operator in operators {
		if !valid_email(operator, people) {
			return Err(BadJson("operators must be lowercase addresses at domains.people"))
		}
	}
	if !ascending(operators) {
		return Err(BadJson("operators must be sorted and unique"))
	}
	app_pairs = root.get("apps")?.object().map_err(|_| BadJson("apps must be an object"))?
	if app_pairs.is_empty() or app_pairs.len() > 128 {
		return Err(BadJson("apps must bind 1 to 128 apps"))
	}
	if !ascending(app_pairs.map(|pair| pair.0)) {
		return Err(BadJson("apps must be sorted by id"))
	}
	apps = check_apps(app_pairs, people, [])?
	# A Chrome extension ID is one global identity: one key, one update URL, one
	# Admin policy entry. Two apps can never pin the same one.
	if !ascending(pinned_extensions(apps, []).sort_with(Names.order)) {
		return Err(BadJson("apps must not pin the same Chrome extension ID"))
	}
	Ok(
		InstanceSpec.{
			installation,
			commit,
			project,
			region,
			zone,
			server,
			org,
			oidc,
			people,
			domain,
			operators,
			apps,
		},
	)
}

check_apps : List((Str, JsonValue)), Str, List(SpecApp) -> Try(List(SpecApp), [BadJson(Str)])
check_apps = |pairs, people, done| match pairs {
	[] => Ok(done)
	[(key, node), .. as rest] => {
		id =
			Names.AppId.from_str(key)
				.map_err(
					|
						_,
					|
						BadJson(
							"app id ${
								Json.to_str(
									key,
								)
							} must be 2-20 lowercase letters or digits starting with a letter; tofu and every id starting with day2 are reserved",
						),
				)?
		at = "apps.${key}"
		exact(node, at, ["sdk", "delivery", "extension", "owners", "size", "verification", "schedules"])?
		sdk = text(node, "sdk")?
		if !(sdk.starts_with("sha256:") and sdk.drop_prefix("sha256:").to_utf8().len() == 64)
			or !sdk.drop_prefix("sha256:").to_utf8().all(hex) {
			return Err(BadJson("${at}.sdk must be a sha256: release manifest digest"))
		}
		delivery = match text(node, "delivery")? {
			"automatic" => Automatic
			"manual" => Manual
			"paused" => Paused
			_ => return Err(BadJson("${at}.delivery must be automatic, manual or paused"))
		}
		extension_node = node.get("extension")?
		extension =
			if extension_node.is_null() {
				NoExtension
			} else {
				pinned =
					extension_node
						.string()
						.map_err(|_| BadJson("${at}.extension must be null or a Chrome extension ID"))?
				if !(pinned.to_utf8().len() == 32 and pinned.to_utf8().all(|byte| byte >= 'a' and byte <= 'p')) {
					return Err(BadJson("${at}.extension must be null or 32 letters a-p, a Chrome extension ID"))
				}
				Pinned(pinned)
			}
		owner_nodes = node.get("owners")?.array().map_err(|_| BadJson("${at}.owners must be an array"))?
		if owner_nodes.is_empty() or owner_nodes.len() > 32 {
			return Err(BadJson("${at}.owners must list 1 to 32 people"))
		}
		owners = strings(owner_nodes, "${at}.owners", [])?
		for owner in owners {
			if !valid_email(owner, people) {
				return Err(BadJson("${at}.owners must be lowercase addresses at domains.people"))
			}
		}
		if !ascending(owners) {
			return Err(BadJson("${at}.owners must be sorted and unique"))
		}
		size = match text(node, "size")? {
			"standard" => Standard
			"large" => Large
			_ => return Err(BadJson("${at}.size must be standard or large"))
		}
		verification =
			node.get("verification")?.u64().map_err(|_| BadJson("${at}.verification must be an integer from 4 to 100"))?
		if verification < 4 or verification > 100 {
			return Err(BadJson("${at}.verification must be an integer from 4 to 100"))
		}
		schedules = match text(node, "schedules")? {
			"enabled" => Enabled
			"paused" => Paused
			_ => return Err(BadJson("${at}.schedules must be enabled or paused"))
		}
		check_apps(
			rest,
			people,
			done.append({ id, sdk, delivery, extension, owners, size, verification, schedules }),
		)
	}
}

exact : JsonValue, Str, List(Str) -> Try({}, [BadJson(Str)])
exact = |node, at, fields| {
	pairs = node.object().map_err(|_| BadJson("${at} must be an object"))?
	if pairs.len() != fields.len() or !pairs.all(|pair| fields.contains(pair.0)) {
		return Err(BadJson("${at} must have exactly the fields ${Str.join_with(fields, ", ")}"))
	}
	Ok({})
}

text : JsonValue, Str -> Try(Str, [BadJson(Str)])
text = |node, key| node.get(key)?.string().map_err(|_| BadJson("${key} must be a string"))

strings : List(JsonValue), Str, List(Str) -> Try(List(Str), [BadJson(Str)])
strings = |nodes, at, done| match nodes {
	[] => Ok(done)
	[node, .. as rest] => {
		value = node.string().map_err(|_| BadJson("${at} must contain only strings"))?
		strings(rest, at, done.append(value))
	}
}

pinned_extensions : List(SpecApp), List(Str) -> List(Str)
pinned_extensions = |remaining, done| match remaining {
	[] => done
	[bound, .. as rest] => match bound.extension {
		Pinned(pinned) => pinned_extensions(rest, done.append(pinned))
		NoExtension => pinned_extensions(rest, done)
	}
}

ascending : List(Str) -> Bool
ascending = |values| match values {
	[first, second, .. as rest] => match Names.order(first, second) {
		Before => ascending([second].concat(rest))
		_ => Bool.False
	}
	_ => Bool.True
}

lower : U8 -> Bool
lower = |byte| byte >= 'a' and byte <= 'z'

digit : U8 -> Bool
digit = |byte| byte >= '0' and byte <= '9'

hex : U8 -> Bool
hex = |byte| digit(byte) or (byte >= 'a' and byte <= 'f')

# Lowercase letters/digits with inner hyphens, bounded by length.
hyphenated : Str, U64, U64 -> Bool
hyphenated = |value, min, max| {
	bytes = value.to_utf8()
	match (bytes.first(), bytes.last()) {
		(Ok(first), Ok(last)) => bytes.len()
			>= min
			and bytes.len()
				<= max
				and lower(first)
					and (lower(last) or digit(last))
						and bytes.all(|byte| lower(byte) or digit(byte) or byte == '-')
		_ => Bool.False
	}
}

valid_project : Str -> Bool
valid_project = |value| hyphenated(value, 6, 30)

## `<org>-infra` is the apply identity's service-account ID, which GCP caps at 30 bytes.
valid_org : Str -> Bool
valid_org = |value| hyphenated(value, 2, 24) and !value.contains("--")

# area-locationN, for example us-central1 or northamerica-northeast2.
valid_region : Str -> Bool
valid_region = |value| match value.split_on("-") {
	[area, location] => !area.is_empty()
		and area.to_utf8().all(lower)
			and letters_then_digits(location.to_utf8(), Bool.False, Bool.False)
	_ => Bool.False
}

letters_then_digits : List(U8), Bool, Bool -> Bool
letters_then_digits = |bytes, seen_letter, seen_digit| match bytes {
	[] => seen_letter and seen_digit
	[byte, .. as rest] => if
		lower(byte) and !seen_digit
		letters_then_digits(rest, Bool.True, Bool.False)
	else if
		digit(byte) and seen_letter
		letters_then_digits(rest, Bool.True, Bool.True)
	else
		Bool.False
}

valid_zone : Str, Str -> Bool
valid_zone = |zone, region| {
	suffix = zone.drop_prefix("${region}-").to_utf8()
	zone.starts_with("${region}-") and suffix.len() == 1 and suffix.all(lower)
}

valid_label : Str -> Bool
valid_label = |label| {
	bytes = label.to_utf8()
	match (bytes.first(), bytes.last()) {
		(Ok(first), Ok(last)) => bytes.len()
			<= 63
			and (lower(first) or digit(first))
				and (lower(last) or digit(last))
					and bytes.all(|byte| lower(byte) or digit(byte) or byte == '-')
		_ => Bool.False
	}
}

valid_domain : Str -> Bool
valid_domain = |value| {
	labels = value.split_on(".")
	top = match labels.last() {
		Ok(label) => match label.to_utf8().first() {
			Ok(byte) => lower(byte)
			Err(_) => Bool.False
		}
		Err(_) => Bool.False
	}
	value.count_utf8_bytes() <= 253 and labels.len() >= 2 and labels.all(valid_label) and top
}

## An address is at most 256 bytes, the longest authority actor day2 accepts.
valid_email : Str, Str -> Bool
valid_email = |value, domain| match value.split_on("@") {
	[local, host] => {
		bytes = local.to_utf8()
		host
			== domain
			and value.count_utf8_bytes()
				<= 256
				and !bytes.is_empty()
					and bytes.len()
						<= 64
						and !local.starts_with(".")
							and !local.ends_with(".")
								and bytes.all(|byte| lower(byte) or digit(byte) or [46, 45, 95].contains(byte))
	}
	_ => Bool.False
}

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

expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		names = spec.derived()
		first = names.apps.first()
		names.instance_repository
			== "tools/day2-instance"
			and names.ci_repository
				== "tools/day2-ci"
				and names.required_check
					== "tools/day2-ci: day2 / verification (pull_request)"
					and names.sdk_registry
						== "us-central1-docker.pkg.dev/exampleco-tools/day2"
						and names.tofu_state_bucket
							== "exampleco-tools-tofu-state"
							and first
								== Ok({
									id: "go",
									delivery: "automatic",
									sdk: "sha256:98fb0ae80067840dd056a3c71ddfb482c756ce9475ec34a572cd8698c733f848",
									owners: ["lin@example.com"],
									admins: ["lin@example.com", "tools-infra@exampleco-tools.iam.gserviceaccount.com"],
									size: "standard",
									verification: 4,
									schedules: "enabled",
									extension: Ok({
										id: "jldmikbinomhomcbmeppagennfohakni",
										update_url: "https://go.apps.example.com/downloads/updates.xml",
										downloads: ["/downloads/go.crx", "/downloads/updates.xml"],
										signing_secret: "go-chrome-extension-signing-key",
									}),
									repository: "tools/go",
									hostname: "go.apps.example.com",
									namespace: "app-go",
									image: "us-central1-docker.pkg.dev/exampleco-tools/go/go",
									state_bucket: "exampleco-tools-go-state",
									state_prefix: "day2-app/go",
									edge_state_prefix: "platform/app/go",
									backup_bucket: "exampleco-tools-go-backups",
									ci_bucket: "exampleco-tools-go-ci",
									runtime_resources: {
										memory_mib: 512,
										cpu_millis: 1000,
										process_limit: 1024,
										http_concurrency: 4,
										shutdown_seconds: 30,
									},
									sqlite_storage_gb: 5,
								})
	}
	Err(_) => Bool.False
}

# The download paths are sorted, so an app whose name sorts after `updates` lists its update manifest first.
expect {
	wiki =
		sample
			.replace_first("\"home\":", "\"wiki\":")
			.replace_first(
				"\"manual\",\"extension\":null",
				"\"manual\",\"extension\":\"abcdefghijklmnopabcdefghijklmnop\"",
			)
	match InstanceSpec.from_json(wiki) {
		Ok(spec) => match spec.derived().apps {
			[_, bound] =>
				bound.extension
					== Ok({
						id: "abcdefghijklmnopabcdefghijklmnop",
						update_url: "https://wiki.apps.example.com/downloads/updates.xml",
						downloads: ["/downloads/updates.xml", "/downloads/wiki.crx"],
						signing_secret: "wiki-chrome-extension-signing-key",
					})
			_ => Bool.False
		}
		Err(_) => Bool.False
	}
}

expect match InstanceSpec.from_json(sample) {
	Ok(spec) => spec.derived().apply_identity == "tools-infra@exampleco-tools.iam.gserviceaccount.com"
	Err(_) => Bool.False
}

# forge.oidc is optional: without it the spec checks and derives no token request. forge is exact otherwise.
expect match InstanceSpec.from_json(sample.replace_first(",\n\"oidc\":\"https://git-oidc.example.com\"", "")) {
	Ok(spec) => spec.derived().forge_oidc == Err(Null) and spec.derived().ci_token_request == Err(Null)
	Err(_) => Bool.False
}
expect InstanceSpec.from_json(sample.replace_first("\"oidc\":", "\"broker\":")).is_err()
expect InstanceSpec.from_json(sample.replace_first("\"oidc\":\"https://git-oidc.example.com\"", "\"oidc\":null"))
	.is_err()

# App CI requests its OIDC token from forge.oidc and federates through one derived pool and provider; each app stores
# its results in its own bucket. The broker is an https origin other than the forge.
expect InstanceSpec.from_json(sample.replace_first("\"oidc\":\"https://git-oidc", "\"oidc\":\"http://git-oidc"))
	.is_err()
expect InstanceSpec.from_json(
	sample.replace_first("\"oidc\":\"https://git-oidc.example.com\"", "\"oidc\":\"https://git.example.com\""),
)
	.is_err()
expect InstanceSpec.from_json(
	sample
		.replace_first("\"oidc\":\"https://git-oidc.example.com\"", "\"oidc\":\"https://git-oidc.example.com/token\""),
)
	.is_err()
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		names = spec.derived()
		names.ci_token_request == Ok("https://git-oidc.example.com/token?v=1")
			and names.ci_workload_identity == { pool: "day2-ci", provider: "gitea" }
				and names.apps.map(|bound| bound.ci_bucket) == ["exampleco-tools-go-ci", "exampleco-tools-home-ci"]
	}
	Err(_) => Bool.False
}

# The longest org still names a 30-byte service-account ID.
expect match InstanceSpec.from_json(sample.replace_first("\"org\":\"tools\"", "\"org\":\"${Str.repeat("t", 24)}\"")) {
	Ok(spec) => spec.derived().apply_identity
		== "${Str.repeat("t", 24)}-infra@exampleco-tools.iam.gserviceaccount.com"
	Err(_) => Bool.False
}

# Admins are sorted, so an owner may sort after the apply identity.
expect match InstanceSpec.from_json(
	sample.replace_first("\"owners\":[\"lin@example.com\"]", "\"owners\":[\"zed@example.com\"]"),
) {
	Ok(spec) => match spec.derived().apps.first() {
		Ok(go) => go.admins == ["tools-infra@exampleco-tools.iam.gserviceaccount.com", "zed@example.com"]
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

expect match InstanceSpec.from_json(sample) {
	Ok(spec) => {
		names = spec.derived()
		names.platform_state_prefixes
			== {
				project: "foundation",
				cluster: "platform/cluster",
				tenancy: "platform/tenancy",
				app_edge: "platform/app",
				day2: "day2",
			}
			and names.cluster
				== { name: "day2", kube_context: "gke_exampleco-tools_us-central1-a_day2" }
				and names.app_namespace_prefix
					== "app-"
	}
	Err(_) => Bool.False
}

expect match InstanceSpec.from_json(sample) {
	Ok(spec) => match spec.derived().apps.last() {
		Ok(home) => home.runtime_resources.memory_mib == 2048 and home.sqlite_storage_gb == 5
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

expect match InstanceSpec.from_json(sample) {
	Ok(spec) => match spec.derived().apps.last() {
		Ok(home) => home.extension
			== Err(Null)
			and home.owners
				== ["kay@example.com", "lin@example.com"]
				and home.size
					== "large"
					and home.verification
						== 6
						and home.schedules
							== "paused"
		Err(_) => Bool.False
	}
	Err(_) => Bool.False
}

# Every preset fits day2-app's runtime_resources bounds and default container_max (4000m CPU, 4096 MiB), keeps a
# process_limit no lower than the cluster's 1024 pod PID limit, and shares one volume size.
expect [Standard, Large]
	.map(size_preset)
	.all(
		|preset| {
			limits = preset.runtime_resources
			limits.memory_mib
				>= 64
				and limits.memory_mib
					<= 4096
					and limits.cpu_millis
						>= 50
						and limits.cpu_millis
							<= 4000
							and limits.process_limit
								>= 1024
								and limits.process_limit
									<= 4096
									and limits.http_concurrency
										>= 1
										and limits.http_concurrency
											<= 32
											and limits.shutdown_seconds
												>= 5
												and limits.shutdown_seconds
													<= 300
													and preset.sqlite_storage_gb
														== size_preset(Standard).sqlite_storage_gb
		},
	)

rejects : Str, Str -> Bool
rejects = |old, new| {
	edited = sample.replace_first(old, new)
	edited != sample and InstanceSpec.from_json(edited).is_err()
}

expect rejects("\"kind\":\"instance\"", "\"kind\":\"app\"")
expect rejects("\"version\":1", "\"version\":2")
expect rejects("\"installation\":\"exampleco\"", "\"installation\":\"Example Co\"")
expect rejects("\"version\":1,", "\"version\":1,\"extra\":true,")
expect rejects("\"version\":1,", "")
expect rejects("fe4320b189b98ed08fccc183db3e70aee76319ee", "fe4320b1")
expect rejects("\"zone\":\"us-central1-a\"", "\"zone\":\"europe-west4-a\"")
expect rejects("\"region\":\"us-central1\"", "\"region\":\"us_central1\"")
expect rejects("\"project\":\"exampleco-tools\"", "\"project\":\"exampleco-tools-\"")
expect rejects("\"kind\":\"gitea\"", "\"kind\":\"github\"")
expect rejects("https://git.example.com", "https://git.example.com/tools")
expect rejects("https://git.example.com", "http://git.example.com")
expect rejects("\"org\":\"tools\"", "\"org\":\"Tools\"")
expect rejects("\"org\":\"tools\"", "\"org\":\"${Str.repeat("t", 25)}\"")
expect rejects("\"org\":\"tools\"", "\"org\":\"1tools\"")
expect rejects("\"org\":\"tools\"", "\"org\":\"tools-\"")
expect rejects("\"apps\":\"apps.example.com\"", "\"apps\":\"localhost\"")
expect rejects("\"ada@example.com\",\"grace@example.com\"", "\"grace@example.com\",\"ada@example.com\"")
expect rejects("\"ada@example.com\",\"grace@example.com\"", "\"ada@example.com\",\"ada@example.com\"")
expect rejects("\"ada@example.com\"", "\"ada@elsewhere.com\"")
expect rejects("\"ada@example.com\",\"grace@example.com\"", "")
expect rejects("\"go\":", "\"golinks-v2\":")
expect rejects("\"go\":", "\"instance\":")
expect rejects("\"go\":", "\"zebra\":")
expect rejects("\"delivery\":\"manual\"", "\"delivery\":\"auto\"")
expect rejects("\"delivery\":\"manual\"", "\"delivery\":\"manual\",\"cases\":6")
expect rejects("sha256:98fb0ae8", "sha512:98fb0ae8")
expect rejects("\"verification\":4", "\"verification\":3")
expect rejects("\"verification\":4", "\"verification\":101")
expect rejects("\"verification\":4", "\"verification\":\"4\"")
expect rejects("\"verification\":4", "\"verification\":4.5")
expect rejects("\"verification\":4", "\"verification\":-4")
expect rejects("\"size\":\"standard\"", "\"size\":\"small\"")
expect rejects("\"schedules\":\"enabled\"", "\"schedules\":\"disabled\"")
expect rejects(",\"schedules\":\"enabled\"", "")
expect rejects("\"extension\":null", "\"extension\":\"\"")
expect rejects("\"extension\":null,", "")
expect rejects("\"extension\":null", "\"extension\":\"jldmikbinomhomcbmeppagennfohakni\"")
expect rejects("jldmikbinomhomcbmeppagennfohakni", "jldmikbinomhomcbmeppagennfohakn")
expect rejects("jldmikbinomhomcbmeppagennfohakni", "qldmikbinomhomcbmeppagennfohakni")
expect rejects("jldmikbinomhomcbmeppagennfohakni", "JLDMIKBINOMHOMCBMEPPAGENNFOHAKNI")
expect rejects("\"owners\":[\"lin@example.com\"]", "\"owners\":[]")
expect rejects("\"owners\":[\"lin@example.com\"]", "\"owners\":\"lin@example.com\"")
expect rejects("\"owners\":[\"lin@example.com\"]", "\"owners\":[\"lin@elsewhere.com\"]")
expect rejects("[\"kay@example.com\",\"lin@example.com\"]", "[\"lin@example.com\",\"kay@example.com\"]")
expect rejects("[\"kay@example.com\",\"lin@example.com\"]", "[\"kay@example.com\",\"kay@example.com\"]")

# An address is capped at the 256-byte authority actor limit, below what its parts' own limits allow.
expect {
	long = "${Str.repeat("a", 63)}.${Str.repeat("b", 63)}.${Str.repeat("c", 63)}.com"
	valid_email("${Str.repeat("x", 60)}@${long}", long) and !valid_email("${Str.repeat("x", 61)}@${long}", long)
}

# A service-account people domain is refused even when every address is at it.
expect {
	moved = sample.replace_each("example.com\"", "corp.iam.gserviceaccount.com\"")
	moved != sample and InstanceSpec.from_json(moved).is_err()
		and InstanceSpec.from_json(sample.replace_each("example.com\"", "corp.example.org\"")).is_ok()
}

expect match InstanceSpec.from_json(sample) {
	Ok(spec) => spec.derived().artifact_registry == "us-central1-docker.pkg.dev/exampleco-tools"
	Err(_) => Bool.False
}

# Every candidate is built on the qualification runner's VM, in the instance's zone.
expect match InstanceSpec.from_json(sample) {
	Ok(spec) => spec.derived().build_host == { name: "day2-x86-qualify", zone: "us-central1-a" }
	Err(_) => Bool.False
}
