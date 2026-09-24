import Capability

# Local operator operations. The native host verifies expected revisions and
# commits active policy and its receipt atomically. These are never app effects.
Authority :: [].{
	admin! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	admin! = |instance, operator, host!| {
		Capability.call!("resource-admin-serve", Json.to_str({ instance, operator }), host!)
	}

	resources! : Str, Str, Str, Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	resources! = |action, instance, app_name, operator, input_file, host!| {
		Capability.call!(
			"resource-admin-operation",
			Json.to_str({ action, instance, app_name, operator, input_file }),
			host!,
		)
	}

	inspect! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	inspect! = |instance, app_name, host!| {
		Capability.call!("authority-inspect", Json.to_str({ instance, app_name }), host!)
	}

	apply! : Str, Str, Str, Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	apply! = |instance, app_name, operator, expected, request_id, host!| {
		Capability.call!("authority-apply", Json.to_str({ instance, app_name, operator, expected, request_id }), host!)
	}

	activate! : Str, Str, Str, Str, Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	activate! = |instance, app_name, target, operator, expected, request_id, host!| {
		Capability.call!(
			"authority-activate",
			Json.to_str({ instance, app_name, target, operator, expected, request_id }),
			host!,
		)
	}
}
