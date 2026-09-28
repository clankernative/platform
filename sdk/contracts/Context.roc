import Wire

# Captured host context, not ambient I/O. Its constructor is sealed from app code.
# The actor identifies the caller; authorization remains an independent host check.
Context :: { value : Wire.Context }.{
	from_wire : Wire.Context -> Context
	from_wire = |value| { value: value }

	actor : Context -> Str
	actor = |context| context.value.actor

	invocation_id : Context -> Str
	invocation_id = |context| context.value.invocation_id

	# Stable invocation time in Unix seconds, including during deterministic replay.
	now : Context -> I64
	now = |context| context.value.now

	# What established this invocation's authority.
	#
	# Server-verified and read from the invocation record, never from input: an
	# application that could name its own caller could name a better one. It is
	# the same fact the audit log records, so what an application branches on and
	# what an operator reads afterwards cannot disagree.
	Authentication : [
		# An actor asked, and the host authenticated them: HTTP, MCP, a form, the
		# CLI. `Context.actor` is who the invocation acts for; `acting` says
		# whether that differs from the authenticated requester.
		Request,
		# No actor asked. The instance bound a declared schedule and it fired.
		Schedule,
		# Another command in this application requested it inside its own
		# transaction. The actor is the one that command was running as.
		CommandRequest,
		# No actor asked now; a command deferred this earlier and this instance
		# admitted it afresh when due. `Context.actor` is the deferring actor.
		Deferral,
		# No actor asked now; an operator reissued a blocked invocation and this
		# instance admitted it afresh. `Context.actor` is the original actor.
		Recovery,
		# A verified inbound delivery. No actor asked; a signature established
		# the sender, and the instance bound the endpoint.
		Ingress,
		# Another application in this instance asked, on behalf of the same
		# actor. `Context.caller` says which, and through what.
		Delegated,
		# Something this SDK does not have a name for yet.
		#
		# Present so that a cause added to the platform is not a breaking change
		# to every application that matches on this. An application that reaches
		# this case is being asked to make a decision on evidence it does not
		# understand, and refusing is usually the right answer.
		Other(Str),
	]

	# Which application asked, when one did.
	#
	# `External` is the ordinary case and means a person reached this application
	# directly. `Internal` means another application in this instance asked on
	# the same actor's behalf: `application` is the immediate caller and `chain`
	# is every application the call passed through, oldest first.
	#
	# The actor is the same either way. A delegated call carries a request across
	# an application boundary and never authority, so `Context.actor` is the
	# person in both cases and this says only how their request arrived.
	Caller : [External, Internal({ application : Str, chain : List(Str) })]

	caller : Context -> Caller
	caller = |context|
		match context.value.caller.last() {
			Err(_) => External
			Ok(immediate) => Internal({ application: immediate, chain: context.value.caller })
		}

	# Who the host verified, when that is not who the work is for.
	#
	# `Context.actor` is the principal this invocation acts for, and it is what
	# the operation's policy authorized. This says who was actually at the other
	# end: an administrator acting for a customer, or an application acting for
	# the person who asked it.
	#
	# Settled once, at the outermost invocation, and immutable for the whole call
	# tree: a later hop inherits the principal rather than choosing one, so "on
	# whose behalf" has a single answer however many applications it passed
	# through.
	Authenticated : [Person(Str), Application(Str)]

	Acting : [Directly, ForAnother({ by : Authenticated, rule : Str })]

	acting : Context -> Acting
	acting = |context|
		if context.value.authenticated.is_empty() {
			Directly
		} else {
			by = if context.value.authenticated.starts_with("app:") {
				Application(context.value.authenticated.drop_prefix("app:"))
			} else {
				Person(context.value.authenticated)
			}
			ForAnother({ by, rule: context.value.delegation_rule })
		}

	authentication : Context -> Authentication
	authentication = |context|
		match context.value.authentication {
			"request" => Request
			"schedule" => Schedule
			"command_request" => CommandRequest
			"deferral" => Deferral
			"recovery" => Recovery
			"ingress" => Ingress
			"delegated" => Delegated
			other => Other(other)
		}
}
