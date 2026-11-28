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
