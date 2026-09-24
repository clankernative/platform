import Observe
import Resource
import Api

# Reading another application's published operation, inside this instance.
#
# **A delegated call carries a request across an application boundary, never
# authority.** It runs as the same actor the caller was already running as, and
# the callee's own policy decides independently whether that actor may run that
# operation. The grant says this application may ask; it never says the answer
# is yes. So the worst a compromised caller can reach is what the person it is
# acting for could already reach by calling the callee directly.
#
# The answer arrives as the callee's JSON. There is no shared type: the callee's
# types live in the callee's artifact, and importing them would make one
# application's build depend on another's source. What stands in for that is the
# grant, which pins the digest of the operation's input and output schemas — so
# a callee that changes its shape fails this application's *deployment* rather
# than one of its invocations at an inconvenient hour.
Delegate :: [].{
	read_observation = Api.external("app.query.v1")

	# Ask another application's query, as the current actor.
	#
	# A read, and prepared like any other observation: it resolves before the
	# decision, is recorded, and replays. That is what makes it usable in a
	# decision at all — a call that could answer differently on replay could not
	# be part of one.
	query : Resource, Str -> Observe(Str)
	query = |resource, input| Observe.capability(
		"app.query.v1",
		Json.to_str({ handle: Resource.token(resource), input }),
	)
}
