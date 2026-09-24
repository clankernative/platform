import infra.Stack
import Capability

Infra :: [].{
	run! : Str, Str, (Str => Try(Str, Str)) => Try(Str, Str)
	run! = |configuration, output, host!| {
		raw = Capability.call!("infra-settings", Json.to_str({ configuration: configuration }), host!)?
		settings : Stack.Settings
		settings = Json.parse(raw).map_err(|_| "invalid infrastructure settings")?
		graph = Stack.graph(settings)
		_ =
			Capability.call!(
				"infra-prepare",
				Json.to_str({ configuration, configuration_digest: settings.configuration_digest, output, graph }),
				host!,
			)?
		for operation in ["version", "init", "validate", "plan", "show"] {
			_ = Capability.call!("infra-command", Json.to_str({ operation: operation }), host!)?
		}
		Capability.call!("infra-receipt", "{}", host!)
	}
}
