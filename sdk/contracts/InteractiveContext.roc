import Context

# Host-created context for one confirmed management invocation. The constructor
# is sealed; current confirmation and policy are checked again by the host.
InteractiveContext :: { context : Context }.{
	from_context : Context -> InteractiveContext
	from_context = |context| { context: context }

	actor : InteractiveContext -> Str
	actor = |context| context.context.actor()

	invocation_id : InteractiveContext -> Str
	invocation_id = |context| context.context.invocation_id()

	now : InteractiveContext -> I64
	now = |context| context.context.now()
}
