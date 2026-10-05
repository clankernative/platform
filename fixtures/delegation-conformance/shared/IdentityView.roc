import pf.Context

IdentityView :: [].{
	Value := { actor : Str, authenticated : Str, rule : Str, caller : Str, authentication : Str }

	fields = {
		actor: "Effective actor authorized by the host.",
		authenticated: "Verified requester, or app-prefixed immediate calling application.",
		rule: "Captured operator delegation rule; empty for a direct request.",
		caller: "Application call chain, oldest first, separated by dots; empty for an external request.",
		authentication: "Host-established invocation cause.",
	}

	from_context : Context -> Value
	from_context = |context| {
		identity = match context.acting() {
			Directly => { authenticated: context.actor(), rule: "" }
			ForAnother(acting) => {
				authenticated = match acting.by {
					Person(name) => name
					Application(name) => "app:${name}"
				}
				{ authenticated, rule: acting.rule }
			}
		}
		caller = match context.caller() {
			External => ""
			Internal(call) => Str.join_with(call.chain, ".")
		}
		authentication = match context.authentication() {
			Request => "request"
			Schedule => "schedule"
			CommandRequest => "command_request"
			Ingress => "ingress"
			Delegated => "delegated"
			Other(value) => value
		}
		{ actor: context.actor(), authenticated: identity.authenticated, rule: identity.rule, caller, authentication }
	}

	sample : {} -> Value
	sample = |_| { actor: "alice", authenticated: "alice", rule: "", caller: "", authentication: "request" }

	valid : Value -> Bool
	valid = |value| !value.actor.is_empty() and !value.authenticated.is_empty() and !value.authentication.is_empty()
}
