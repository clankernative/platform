import Names
import JsonValue
import Problem

Instance :: {
	installation : Names.Identifier,
	environment : Names.Identifier,
	apps : List((Names.App, Names.LocalPath)),
}.{
	from_json : Str -> Try(Instance, Problem)
	from_json = |raw| {
		node = JsonValue.parse(raw).map_err(|BadJson(detail)| Problem.InvalidInstance(detail))?
		checked(node).map_err(|BadJson(detail)| Problem.InvalidInstance(detail))
	}

	select : Instance, Names.App -> Try(Names.LocalPath, Problem)
	select = |instance, name| {
		match instance.apps.keep_if(|binding| binding.0.to_str() == name.to_str()).first() {
			Ok(binding) => Ok(binding.1)
			Err(_) => Err(
				Problem.AppNotFound(
					name.to_str(),
					instance.apps.map(|binding| binding.0.to_str()).sort_with(Names.order),
				),
			)
		}
	}

	identity : Instance -> { installation : Str, environment : Str }
	identity = |instance| { installation: instance.installation.to_str(), environment: instance.environment.to_str() }
}

checked : JsonValue -> Try(Instance, [BadJson(Str)])
checked = |node| {
	node.keys(["installation", "environment", "apps", "branding"])?
	installation =
		Names.Identifier.from_str(node.get("installation")?.string()?)
			.map_err(|_| BadJson("installation must be a valid identifier"))?
	environment =
		Names.Identifier.from_str(node.get("environment")?.string()?)
			.map_err(|_| BadJson("environment must be a valid identifier"))?
	match node.optional("branding")? {
		Absent => {}
		Present(value) => {
			_ = Names.LocalPath.from_str(value.string()?).map_err(|_| BadJson("invalid branding path"))?
		}
	}
	apps = node.get("apps")?.object()?
	if apps.is_empty() or apps.len() > 128 {
		return Err(BadJson("instance must bind 1 to 128 apps"))
	}
	bindings = check_apps(apps, [])?
	Ok(Instance.{ installation, environment, apps: bindings })
}

check_apps :
	List((Str, JsonValue)),
	List((Names.App, Names.LocalPath)) ->
		Try(List((Names.App, Names.LocalPath)), [BadJson(Str)])
check_apps = |apps, done| match apps {
	[] => Ok(done)
	[(name, binding), .. as rest] => {
		app_name = Names.App.from_str(name).map_err(|_| BadJson("invalid bound app name"))?
		binding.keys(["artifact", "readers", "writers", "auditors", "authority"])?
		path =
			Names.LocalPath.from_str(binding.get("artifact")?.string()?).map_err(|_| BadJson("invalid artifact path"))?
		check_actors(binding.get("readers")?)?
		check_actors(binding.get("writers")?)?
		match binding.optional("auditors")? {
			Absent => {}
			Present(actors) => {
				check_actors(actors)?
			}
		}
		match binding.optional("authority")? {
			Absent => {}
			Present(policy) => {
				_ = policy.object()?
			}
		}
		check_apps(rest, done.append((app_name, path)))
	}
}

check_actors : JsonValue -> Try({}, [BadJson(Str)])
check_actors = |node| {
	actors = node.array()?
	if actors.len() > 512 {
		return Err(BadJson("actor metadata exceeds budget"))
	}
	for actor in actors {
		name = actor.string()?
		if
			name.trim().is_empty()
				or name.count_utf8_bytes() > 256 or name.to_utf8().any(|byte| byte < 32 or byte == 127)
				{
					return Err(BadJson("invalid actor label"))
				}
	}
	Ok({})
}
