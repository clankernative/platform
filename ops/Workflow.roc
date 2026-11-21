# Private platform operations. App packages cannot import this package. The
# callback exposes fixed Rust capabilities; no shell or arbitrary argv crosses it.
import Build
import Check
import ChromeExtension
import LocalDev
import Backup
import Infra
import Authority
import Provision
import Maintain
import UiDependency

Workflow :: [].{
	Request := [
		Help,
		Build(Str),
		UiLock(Str),
		ExtensionVerify(Str),
		ExtensionPack(Str, Str),
		ExtensionLocal(Str, Str),
		ExtensionPolicy(Str),
		ExtensionFleet(Str, Str),
		Check(Str, U64, U64),
		LocalDev(List(Str)),
		Backup(Str, Str, Str),
		Restore(Str, Str),
		RestoreInspect(Str),
		RestoreProtected(Str, Str),
		Infra(Str, Str),
		AuthorityInspect(Str, Str),
		AuthorityApply(Str, Str, Str, Str, Str),
		AuthorityActivate(Str, Str, Str, Str, Str, Str),
		AuthorityAdmin(Str, Str),
		Owners(Str, Str, Str, Str, Str),
		Resources(Str, Str, Str, Str, Str),
		Provision(Str, Str, Str, Str),
		Maintain(Str, Str),
	]

	LocalReceipt : { instance : Str }

	parse : List(Str) -> Try(Request, Str)
	parse = |args| match args {
		[] | ["--help"] => Ok(Help)
		["build", source] => Ok(Build(source))
		["ui-lock", source] => Ok(UiLock(source))
		["extension", "verify", source] => Ok(ExtensionVerify(source))
		["extension", "pack", source, key] => Ok(ExtensionPack(source, key))
		["extension", "local", source, output] => Ok(ExtensionLocal(source, output))
		["extension", "policy", source] => Ok(ExtensionPolicy(source))
		["extension", "fleet", source, project] => Ok(ExtensionFleet(source, project))
		["check", source] | ["test", source] => Ok(Check(source, 3_664_912_422, 16))
		["check", source, seed, count] | ["test", source, seed, count] => {
			checked_seed = U64.from_str(seed).map_err(|_| "seed must be a U64")?
			checked_count = U64.from_str(count).map_err(|_| "case count must be 1..100")?
			if checked_count < 1 or checked_count > 100 {
				return Err("case count must be 1..100")
			}
			Ok(Check(source, checked_seed, checked_count))
		}
		["local-dev", .. as local_args] => Ok(LocalDev(local_args))
		["maintain", "inspect", request_file] => Ok(Maintain("inspect", request_file))
		["maintain", "backup", request_file] => Ok(Maintain("backup", request_file))
		["maintain", "authority-apply", request_file] => Ok(Maintain("authority-apply", request_file))
		["maintain", "activate", request_file] => Ok(Maintain("activate", request_file))
		["maintain", "recover", journal_file] => Ok(Maintain("recover", journal_file))
		["maintain", "rollout", request_file] => Ok(Maintain("rollout", request_file))
		["maintain", "runtime-rollout", request_file] => Ok(Maintain("runtime-rollout", request_file))
		["maintain", "mark-activated", request_file] => Ok(Maintain("mark-activated", request_file))
		["maintain", "recovery-abandon", request_file] => Ok(Maintain("recovery-abandon", request_file))
		["backup", instance, app_name, output] => Ok(Backup(instance, app_name, output))
		["restore", "inspect", backup] => Ok(RestoreInspect(backup))
		["restore", "protected", instance, app_name] => Ok(RestoreProtected(instance, app_name))
		["restore", "protected"] | ["restore", "protected", _] => Err("usage: restore protected INSTANCE APP")
		["restore", backup, output] => Ok(Restore(backup, output))
		["infra", "plan", configuration, output] => Ok(Infra(configuration, output))
		["authority", "inspect", instance, app_name] => Ok(AuthorityInspect(instance, app_name))
		["authority", "admin", instance, operator] => Ok(AuthorityAdmin(instance, operator))
		["owners", action, instance, app_name, operator, input_json] => {
			if ["list", "check", "add", "remove"].contains(action) {
				Ok(Owners(action, instance, app_name, operator, input_json))
			} else {
				Err("unknown owner operation")
			}
		}
		["provision-credentials", instance, app_name, operator, plan_file] => {
			Ok(Provision(instance, app_name, operator, plan_file))
		}
		["resources", action, instance, app_name, operator] => {
			if ["preview", "reviews", "catalog", "company-setup", "company-budget"].contains(action) {
				Ok(Resources(action, instance, app_name, operator, ""))
			} else {
				Err("resource mutation requires an input JSON file")
			}
		}
		["resources", action, instance, app_name, operator, input_file] => {
			if [
				"save",
				"attach",
				"propose",
				"decide",
				"allocate",
				"recover",
				"resolve-overruns",
				"reconcile-usage",
				"credential-mount",
				"security-review",
				"pool-propose",
				"pool-return",
				"pool-decide",
				"pool-import",
			].contains(action) {
				Ok(Resources(action, instance, app_name, operator, input_file))
			} else {
				Err("unknown resource operation")
			}
		}
		["authority", "apply", instance, app_name, operator, expected, request_id] => {
			Ok(AuthorityApply(instance, app_name, operator, expected, request_id))
		}
		["authority", "activate", instance, app_name, target, operator, expected, request_id] => {
			Ok(AuthorityActivate(instance, app_name, target, operator, expected, request_id))
		}
		_ => Err(
			"usage: day2 platform build SOURCE | ui-lock SOURCE | extension verify|policy SOURCE | extension pack SOURCE SIGNING_KEY_PEM | extension fleet SOURCE GCP_PROJECT | extension local SOURCE NEW_DIRECTORY | check SOURCE [SEED CASES] | local-dev [SOURCE] [OPTIONS] | backup INSTANCE APP NEW_DIRECTORY | restore BACKUP NEW_DIRECTORY | restore inspect BACKUP | restore protected INSTANCE APP | infra plan CONFIG NEW_DIRECTORY | maintain inspect|backup|authority-apply|recovery-abandon|activate|mark-activated|rollout|runtime-rollout REQUEST_JSON_FILE | maintain recover SESSION_JOURNAL_FILE",
		)
	}

	run! : Request, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| match request {
		Help => Ok(
			Json.to_str({
				protocol: 1.U32,
				commands: [
					"build SOURCE",
					"ui-lock SOURCE",
					"extension verify SOURCE",
					"extension pack SOURCE SIGNING_KEY_PEM",
					"extension local SOURCE NEW_DIRECTORY",
					"extension policy SOURCE",
					"extension fleet SOURCE GCP_PROJECT",
					"check SOURCE [SEED CASES]",
					"local-dev [SOURCE] [OPTIONS]",
					"backup INSTANCE APP NEW_DIRECTORY",
					"restore BACKUP NEW_DIRECTORY",
					"restore inspect BACKUP",
					"restore protected INSTANCE APP (browser navigation only)",
					"infra plan CONFIG NEW_DIRECTORY",
					"authority inspect INSTANCE APP",
					"authority admin INSTANCE LOCAL_OPERATOR",
					"owners list|check|add|remove INSTANCE APP LOCAL_OPERATOR INPUT_JSON",
					"provision-credentials OPERATOR_INSTANCE APP LOCAL_OPERATOR PROVISIONING_PLAN",
					"resources preview|reviews|catalog|company-setup INSTANCE APP LOCAL_OPERATOR",
					"resources save|attach|propose|decide|allocate|recover|resolve-overruns INSTANCE APP LOCAL_OPERATOR INPUT_JSON_FILE",
					"authority apply INSTANCE APP LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID",
					"authority activate INSTANCE APP TARGET LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID",
					"maintain inspect|backup|authority-apply|recovery-abandon|activate|mark-activated|rollout|runtime-rollout REQUEST_JSON_FILE | maintain recover SESSION_JOURNAL_FILE",
				],
			}),
		)
		Build(source) => {
			receipt = Build.source!(source, host!)?
			Ok(Json.to_str(receipt))
		}
		UiLock(source) => UiDependency.lock!(source, host!)
		ExtensionVerify(source) => ChromeExtension.verify!(source, host!)
		ExtensionPack(source, key) => ChromeExtension.pack!(source, key, host!)
		ExtensionLocal(source, output) => ChromeExtension.local!(source, output, host!)
		ExtensionPolicy(source) => ChromeExtension.policy!(source, host!)
		ExtensionFleet(source, project) => ChromeExtension.fleet!(source, project, host!)
		Check(source, seed, count) => Check.run!(source, seed, count, host!)
		LocalDev(args) => LocalDev.run!(args, host!)
		Backup(instance, app_name, output) => Backup.take!(instance, app_name, output, host!)
		Restore(backup, output) => Backup.restore!(backup, output, host!)
		RestoreInspect(backup) => Backup.inspect!(backup, host!)
		RestoreProtected(instance, app_name) => Backup.protected!(instance, app_name, host!)
		Infra(configuration, output) => Infra.run!(configuration, output, host!)
		AuthorityInspect(instance, app_name) => Authority.inspect!(instance, app_name, host!)
		AuthorityAdmin(instance, operator) => Authority.admin!(instance, operator, host!)
		Owners(action, instance, app_name, operator, input_json) => {
			Authority.owners!(action, instance, app_name, operator, input_json, host!)
		}
		Provision(instance, app_name, operator, plan_file) => {
			Provision.run!(instance, app_name, operator, plan_file, host!)
		}
		Resources(action, instance, app_name, operator, input_file) => {
			Authority.resources!(action, instance, app_name, operator, input_file, host!)
		}
		AuthorityApply(instance, app_name, operator, expected, request_id) => {
			Authority.apply!(instance, app_name, operator, expected, request_id, host!)
		}
		AuthorityActivate(instance, app_name, target, operator, expected, request_id) => {
			Authority.activate!(instance, app_name, target, operator, expected, request_id, host!)
		}
		Maintain(operation, request_file) => Maintain.run!(operation, request_file, host!)
	}

}

expect match Workflow.parse(["check", "reports-app", "42", "0"]) {
	Err(_) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["maintain", "restart", "request.json"]) {
	Err(_) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["maintain", "activate", "request.json"]) {
	Ok(Maintain("activate", "request.json")) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["maintain", "mark-activated", "request.json"]) {
	Ok(Maintain("mark-activated", "request.json")) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["maintain", "recovery-abandon", "request.json"]) {
	Ok(Maintain("recovery-abandon", "request.json")) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["extension", "pack", "app", "/dev/fd/63"]) {
	Ok(ExtensionPack("app", "/dev/fd/63")) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["extension", "pack", "app"]) {
	Err(_) => Bool.True
	_ => Bool.False
}

expect match Workflow.parse(["extension", "fleet", "app", "exampleco-tools"]) {
	Ok(ExtensionFleet("app", "exampleco-tools")) => Bool.True
	_ => Bool.False
}
