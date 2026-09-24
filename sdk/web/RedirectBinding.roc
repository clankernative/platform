# Registered redirect route metadata. The host matches the path, admits the
# person, runs the bound command under its ordinary authority and audit, and
# answers with the named result field as `Location` once it validates. This
# binding carries no URL, no identity rule and no authority: possessing one grants
# nothing, and admission checks every field against the command's contract.
RedirectBinding :: { metadata : Metadata }.{
	Metadata : {
		name : Str,
		path : Str,
		operation : Str,
		input_type : Str,
		output_type : Str,
		# The command result field that becomes `Location`, checked at admission to
		# be a top-level text field of the command's output.
		location : Str,
		# "web" (http and https only) or "any" (any absolute URI scheme except the
		# script-, content- and local-file-bearing ones the platform always refuses).
		schemes : Str,
		# Application failures that mean "nothing is at this address", answered
		# 404. Every one must be declared by the bound command.
		not_found : List(Str),
	}

	define : Metadata -> RedirectBinding
	define = |metadata| { metadata: metadata }

	metadata : RedirectBinding -> Metadata
	metadata = |binding| binding.metadata

	named : Str, RedirectBinding -> RedirectBinding
	named = |name, binding| { ..binding, metadata: { ..binding.metadata, name } }
}
