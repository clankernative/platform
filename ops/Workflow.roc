# Private platform operations. App packages cannot import this package. The
# callback exposes fixed Rust capabilities; no shell or arbitrary argv crosses it.
import Build
import Check
import LocalDev
import Backup
import Infra
import Authority
import Provision
import Maintain

Workflow :: [].{
	Request := [
		Help,
		Build(Str),
		Check(Str, U64, U64),
		LocalDev(List(Str)),
		Backup(Str, Str, Str),
		Restore(Str, Str),
		Infra(Str, Str),
		AuthorityInspect(Str, Str),
		AuthorityApply(Str, Str, Str, Str, Str),
		AuthorityActivate(Str, Str, Str, Str, Str, Str),
		AuthorityAdmin(Str, Str),
		Resources(Str, Str, Str, Str, Str),
		Provision(Str, Str, Str, Str),
		Maintain(Str, Str),
	]

	BuildReceipt : { artifact : Str }

	LocalReceipt : { instance : Str }

	parse : List(Str) -> Try(Request, Str)
	parse = |args| match args {
		[] | ["--help"] => Ok(Help)
		["build", source] => Ok(Build(source))
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
		["backup", instance, app_name, output] => Ok(Backup(instance, app_name, output))
		["restore", backup, output] => Ok(Restore(backup, output))
		["infra", "plan", configuration, output] => Ok(Infra(configuration, output))
		["authority", "inspect", instance, app_name] => Ok(AuthorityInspect(instance, app_name))
		["authority", "admin", instance, operator] => Ok(AuthorityAdmin(instance, operator))
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
			"usage: day2 platform build SOURCE | check SOURCE [SEED CASES] | local-dev [SOURCE] [OPTIONS] | backup INSTANCE APP NEW_DIRECTORY | restore BACKUP NEW_DIRECTORY | infra plan CONFIG NEW_DIRECTORY | maintain inspect|backup|authority-apply|activate REQUEST_JSON_FILE",
		)
	}

	run! : Request, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |request, host!| match request {
		Help => Ok(
			Json.to_str({
				protocol: 1.U32,
				commands: [
					"build SOURCE",
					"check SOURCE [SEED CASES]",
					"local-dev [SOURCE] [OPTIONS]",
					"backup INSTANCE APP NEW_DIRECTORY",
					"restore BACKUP NEW_DIRECTORY",
					"infra plan CONFIG NEW_DIRECTORY",
					"authority inspect INSTANCE APP",
					"authority admin INSTANCE LOCAL_OPERATOR",
					"provision-credentials OPERATOR_INSTANCE APP LOCAL_OPERATOR PROVISIONING_PLAN",
					"resources preview|reviews|catalog|company-setup INSTANCE APP LOCAL_OPERATOR",
					"resources save|attach|propose|decide|allocate|recover|resolve-overruns INSTANCE APP LOCAL_OPERATOR INPUT_JSON_FILE",
					"authority apply INSTANCE APP LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID",
					"authority activate INSTANCE APP TARGET LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID",
					"maintain inspect|backup|authority-apply|activate REQUEST_JSON_FILE",
				],
			}),
		)
		Build(source) => {
			receipt = Build.source!(source, host!)?
			Ok(Json.to_str(receipt))
		}
		Check(source, seed, count) => Check.run!(source, seed, count, host!)
		LocalDev(args) => LocalDev.run!(args, host!)
		Backup(instance, app_name, output) => Backup.take!(instance, app_name, output, host!)
		Restore(backup, output) => Backup.restore!(backup, output, host!)
		Infra(configuration, output) => Infra.run!(configuration, output, host!)
		AuthorityInspect(instance, app_name) => Authority.inspect!(instance, app_name, host!)
		AuthorityAdmin(instance, operator) => Authority.admin!(instance, operator, host!)
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
