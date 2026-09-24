# Registered endpoint metadata. The host verifies the signature, extracts the
# delivery identity and supplies the actor; this binding carries no secret, no
# identity rule and no authority. Possessing one grants nothing — admission checks
# that the bound command exists and is internal, and the instance binds what the
# endpoint runs as and which secret establishes the sender.
IngressBinding :: { metadata : Metadata }.{
	Metadata : {
		name : Str,
		operation : Str,
		input_type : Str,
		# The registered provider capability, such as "slack.events.v1". The
		# provider owns its signature scheme, its envelope and the rule that
		# identifies one delivery; an application states none of those.
		provider : Str,
	}

	define : Metadata -> IngressBinding
	define = |metadata| { metadata: metadata }

	metadata : IngressBinding -> Metadata
	metadata = |binding| binding.metadata

	named : Str, IngressBinding -> IngressBinding
	named = |name, binding| { ..binding, metadata: { ..binding.metadata, name } }
}
