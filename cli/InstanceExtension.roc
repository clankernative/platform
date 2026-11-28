import Cli
import InstanceSpec
import JsonValue
import Problem

## `day2 instance extension`: one app's Chrome extension, against the extension day2.json pins for it. The CLI derives
## the request here: the app, its source and its pin (the ID, the CRX filename `<app>.crx` and the update URL), the
## signing key file for `pack`, the new directory for `local` and the instance's GCP project for `fleet`. The host
## validates it again, runs only the command's own step, and `pack`'s verification after it, and owns the receipt,
## which output carries verbatim.
InstanceExtension :: [].{

	## The host's exact receipt text: a JSON object.
	Report : { text : Str }

	request : InstanceSpec, Cli.Extension -> Try(Str, Problem)
	request = |spec, command| {
		names = spec.derived()
		bound = match names.apps.find_first(|entry| entry.id == command.app_id) {
			Ok(found) => found
			Err(_) => return Err(Problem.InvalidArguments("instance extension requires an app declared in day2.json."))
		}
		pin : Try({ id : Str, crx : Str, update_url : Str }, [Null])
		pin = bound.extension.map_ok(|pinned| { id: pinned.id, crx: pinned.crx, update_url: pinned.update_url })
		none : Try(Str, [Null])
		none = Err(Null)
		inputs = match command.action {
			Cli.ExtensionAction.Pack(key) => { key: Ok(key.to_str()), output: none, project: none }
			Cli.ExtensionAction.Local(output) => { key: none, output: Ok(output.to_str()), project: none }
			Cli.ExtensionAction.Fleet => { key: none, output: none, project: Ok(names.gcp_project) }
			Cli.ExtensionAction.Verify | Cli.ExtensionAction.Policy => { key: none, output: none, project: none }
		}
		Ok(
			Json.to_str({
				mode: command.action.verb(),
				app_id: command.app_id,
				source: command.source.to_str(),
				extension: pin,
				key: inputs.key,
				output: inputs.output,
				project: inputs.project,
			}),
		)
	}

	## A receipt is the host's JSON object, carried verbatim.
	receipt : Str -> Try(Report, [InvalidReceipt])
	receipt = |raw| match JsonValue.parse(raw) {
		Ok(node) => if JsonValue.object(node).is_ok() Ok({ text: raw }) else Err(InvalidReceipt)
		Err(_) => Err(InvalidReceipt)
	}

	## A refused or failed command exits 6 with the host's message.
	problem : Str -> Problem
	problem = |error| Problem.ExtensionFailed(error)
}

sample : Str
sample =
	\\{"kind":"instance","version":1,"installation":"exampleco",
	\\"platform":"fe4320b189b98ed08fccc183db3e70aee76319ee",
	\\"gcp":{"project":"exampleco-tools","region":"us-central1","zone":"us-central1-a"},
	\\"forge":{"kind":"gitea","server":"https://git.example.com","org":"tools",
	\\"oidc":"https://git-oidc.example.com"},
	\\"domains":{"people":"example.com","apps":"apps.example.com"},
	\\"operators":["ada@example.com"],
	\\"apps":{"go":{"sdk":"sha256:1cf71b18b153b05c89206328b10f81c9a672aa7317a122c25ba41fead2669f01",
	\\"delivery":"automatic","extension":"jldmikbinomhomcbmeppagennfohakni","owners":["ada@example.com"],
	\\"size":"standard","verification":4,"schedules":"enabled"},
	\\"home":{"sdk":"sha256:1cf71b18b153b05c89206328b10f81c9a672aa7317a122c25ba41fead2669f01",
	\\"delivery":"automatic","extension":null,"owners":["ada@example.com"],"size":"standard","verification":4,
	\\"schedules":"enabled"}}}

## The request `day2 instance extension ARGS` hands the host for the sample instance.
requested : List(Str) -> Try(Str, [Unrequested])
requested = |args| {
	spec = InstanceSpec.from_json(sample).map_err(|_| Unrequested)?
	match Cli.parse(["instance", "extension"].concat(args)) {
		Ok(Cli.Request.Extension(command)) => InstanceExtension.request(spec, command).map_err(|_| Unrequested)
		_ => Err(Unrequested)
	}
}

# Every name comes from day2.json: the pin, the CRX filename and update URL derived from it, and for fleet the project.
expect
	requested(["pack", ".", "go", "app", "/dev/fd/63"])
		== Ok(
			"{\"app_id\":\"go\",\"extension\":{\"crx\":\"go.crx\",\"id\":\"jldmikbinomhomcbmeppagennfohakni\",\"update_url\":\"https://go.apps.example.com/downloads/updates.xml\"},\"key\":\"/dev/fd/63\",\"mode\":\"pack\",\"output\":null,\"project\":null,\"source\":\"app\"}",
		)
expect
	requested(["fleet", ".", "go", "app"])
		.map_ok(|text| text.contains("\"project\":\"exampleco-tools\"") and text.contains("\"key\":null"))
		== Ok(Bool.True)
expect
	requested(["local", ".", "go", "app", "unpacked"])
		.map_ok(|text| text.contains("\"output\":\"unpacked\"") and text.contains("\"mode\":\"local\""))
		== Ok(Bool.True)

# An app without a pin is named with a null pin; the host lets only verify run for it.
expect requested(["verify", ".", "home", "app"]).map_ok(|text| text.contains("\"extension\":null")) == Ok(Bool.True)

# Only an app declared in day2.json, only the five commands, and each with exactly its own arguments.
expect requested(["verify", ".", "wiki", "app"]).is_err()
expect requested(["sign", ".", "go", "app"]).is_err()
expect requested(["pack", ".", "go", "app"]).is_err()
expect requested(["verify", ".", "go", "app", "extra"]).is_err()
expect match Cli.parse(["instance", "extension", "pack", ".", "go", "app"]) {
	Err(problem) => problem.code() == "missing_argument"
	Ok(_) => Bool.False
}
expect match Cli.parse(["instance", "extension", "policy", ".", "go", "app", "--agent"]) {
	Ok(request) => Cli.arguments(request) == ["day2", "instance", "extension", "policy", ".", "go", "app", "--agent"]
	Err(_) => Bool.False
}
expect Cli.requested(["instance", "extension", "fleet"]).name() == "instance.extension.fleet"
expect Cli.requested(["instance", "extension"]).name() == "instance.extension.verify"
expect InstanceExtension.receipt("[1]").is_err() and InstanceExtension.receipt("{\"pinned\":false}").is_ok()
