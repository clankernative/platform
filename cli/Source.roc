import pf.Env
import pf.Path
import pf.OsStr
import Cli
import Names
import Instance
import Catalog
import Problem
import Host
import JsonValue
import "fixtures/links-artifact.json" as demo_artifact : Str

## A loaded description binds context, the resolved request, and a checked view.
## There is no public constructor accepting an independently supplied context.
Source :: { request : Cli.Describe, context : Context, view : Catalog.View }.{
	ContextDto : {
		source : Str,
		installation : Str,
		environment : Str,
		instance_path : Str,
		artifact_path : Str,
		catalog_validation : Str,
		artifact_integrity : Str,
		permissions : Str,
	}

	ResultDto : {
		app_name : Str,
		description : Str,
		operation_count : U64,
		total_operations : U64,
		operations : List(Catalog.OperationDto),
		example_note : Str,
	}

	load! : Cli.Describe => Try(Source, Problem)
	load! = |request| {
		parts = request.parts()
		match parts.source {
			Cli.Source.Demo => {
				if parts.app_name.to_str() != "links" {
					return Err(Problem.AppNotFound(parts.app_name.to_str(), ["links"]))
				}
				catalog = Catalog.from_json(demo_artifact)?
				view = catalog.select(parts.filter)?
				Ok({ request, context: Demo, view })
			}
			Cli.Source.Instance(path) => load_local!(request, path)
			Cli.Source.Environment => {
				text = match Env.var_str!("DAY2_INSTANCE") {
					Ok(value) => value
					Err(VarNotFound(_)) => return Err(Problem.ContextRequired)
					Err(_) => return Err(Problem.InvalidContext("DAY2_INSTANCE must contain UTF-8 text"))
				}
				if text.is_empty() {
					return Err(Problem.ContextRequired)
				}
				path =
					Names.LocalPath.from_str(text)
						.map_err(
							|
								_,
							|
								Problem.InvalidContext(
									"DAY2_INSTANCE must contain a nonblank path of at most 4096 bytes",
								),
						)?
				load_local!(request, path)
			}
		}
	}

	request : Source -> Cli.Describe
	request = |loaded| loaded.request

	view : Source -> Catalog.View
	view = |loaded| loaded.view

	is_demo : Source -> Bool
	is_demo = |loaded| match loaded.context {
		Demo => Bool.True
		Local(_) => Bool.False
	}

	context_dto : Source -> ContextDto
	context_dto = |loaded| {
		common = match loaded.context {
			Demo => {
				source: "demo",
				installation: "Example Co",
				environment: "sandbox",
				instance_path: "",
				artifact_path: "bundled:links-artifact.json",
			}
			Local(local) => {
				identity = local.instance.identity()
				{
					source: "local_instance",
					installation: identity.installation,
					environment: identity.environment,
					instance_path: local.instance_path.to_str(),
					artifact_path: local.artifact_path.to_str(),
				}
			}
		}
		{
			source: common.source,
			installation: common.installation,
			environment: common.environment,
			instance_path: common.instance_path,
			artifact_path: common.artifact_path,
			catalog_validation: "checked",
			artifact_integrity: "not_verified",
			permissions: "not_evaluated",
		}
	}

	result_dto : Source -> ResultDto
	result_dto = |loaded| {
		result = loaded.view.dto(is_demo(loaded))
		{
			operation_count: result.operation_count,
			total_operations: result.total_operations,
			operations: result.operations,
			example_note: result.example_note,
			app_name: loaded.request.parts().app_name.to_str(),
			description: if
				is_demo(loaded)
				"A shared directory of useful links. Discover, create, and archive links."
			else
				"Operation catalog read from the app's local artifact metadata.",
		}
	}
}

Context : [Demo, Local({ instance : Instance, instance_path : Names.LocalPath, artifact_path : Names.LocalPath })]

load_local! : Cli.Describe, Names.LocalPath => Try(Source, Problem)
load_local! = |request, path| {
	raw_path = path.to_str()
	instance_path = if raw_path.starts_with("/") path else {
		cwd = Env.cwd!().map_err(|_| Problem.ContextUnavailable)?
		cwd_text = OsStr.to_str_try(Path.to_os_str(cwd)).map_err(|_| Problem.ContextUnavailable)?
		if !cwd_text.starts_with("/") {
			return Err(Problem.ContextUnavailable)
		}
		Names.LocalPath.from_str("${cwd_text}/${raw_path}")
			.map_err(|_| Problem.InvalidContext("resolved path exceeds the path budget"))?
	}
	# Check all original JSON keys, including undisplayed metadata, before asking
	# the Rust contract for the versioned discovery projection.
	_ = JsonValue.parse(read_metadata!(instance_path)?).map_err(|BadJson(detail)| Problem.InvalidInstance(detail))?
	projection =
		Host.call!(
			Json.to_str(
				{ protocol: 1.U32, action: "instance-project", input: Json.to_str({ path: instance_path.to_str() }) },
			),
		)
			.map_err(|error| Problem.InvalidInstance(error))?
	instance = Instance.from_json(projection)?
	artifact_directory = instance.select(request.parts().app_name)?
	directory = artifact_directory.to_str()
	parent = Str.join_with(instance_path.to_str().split_on("/").drop_last(1), "/")
	full_directory = if directory.starts_with("/") directory else "${parent}/${directory}"
	artifact_path =
		Names.LocalPath.from_str("${full_directory}/artifact.json")
			.map_err(|_| Problem.InvalidContext("artifact path exceeds the path budget"))?
	raw_catalog = read_metadata!(artifact_path)?
	metadata = JsonValue.parse(raw_catalog).map_err(|BadJson(detail)| Problem.InvalidArtifact(detail))?
	version =
		metadata
			.get("format")
			.map_err(|BadJson(detail)| Problem.InvalidArtifact(detail))?
			.u64()
			.map_err(|BadJson(detail)| Problem.InvalidArtifact(detail))?
	# Current contracts are admitted by the shared Rust runtime before projection.
	# Legacy metadata remains readable without pretending it is a current artifact.
	current = if version >= 10 {
		raw =
			Host.call!(Json.to_str({ protocol: 1.U32, action: "artifact-version", input: "{}" }))
				.map_err(|error| Problem.InvalidArtifact(error))?
		supported : { version : U64 }
		supported = Json.parse(raw).map_err(|_| Problem.InvalidArtifact("invalid host artifact version"))?
		if version > supported.version {
			return Err(Problem.UnsupportedArtifact(version))
		}
		version == supported.version
	} else Bool.False
	catalog = if current {
		projected =
			Host.call!(
				Json.to_str(
					{ protocol: 1.U32, action: "artifact-project", input: Json.to_str({ path: full_directory }) },
				),
			)
				.map_err(|error| Problem.InvalidArtifact(error))?
		Catalog.from_projection(projected)?
	} else Catalog.from_json(raw_catalog)?
	view = catalog.select(request.parts().filter)?
	Ok(
		Source.{
			request: request.with_instance(instance_path),
			context: Local({ instance, instance_path, artifact_path }),
			view,
		},
	)
}

# These are local development metadata reads. The stat/read checks do not claim
# atomic filesystem admission; the resulting content is independently validated.
read_metadata! : Names.LocalPath => Try(Str, Problem)
read_metadata! = |path| {
	text = path.to_str()
	file_path = Path.utf8(text)
	regular = Path.is_file!(file_path).map_err(|_| Problem.MetadataUnreadable(text))?
	if !regular {
		return Err(Problem.MetadataUnreadable(text))
	}
	size = Path.size_in_bytes!(file_path).map_err(|_| Problem.MetadataUnreadable(text))?
	if size > 1_048_576 {
		return Err(Problem.MetadataTooLarge)
	}
	raw = Path.read_utf8!(file_path).map_err(|_| Problem.MetadataUnreadable(text))?
	if raw.count_utf8_bytes() > 1_048_576 {
		return Err(Problem.MetadataTooLarge)
	}
	Ok(raw)
}
