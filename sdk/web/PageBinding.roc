import Read
import Template

# Registered page metadata. The host validates routes, templates, and defaults;
# this binding carries no app renderer or independently callable query handler.
PageBinding :: { metadata : Metadata }.{
	Config : { name : Str, title : Str, path : Str, template : Template }

	Metadata : {
		name : Str,
		title : Str,
		path : Str,
		operation : Str,
		defaults : Str,
		template : Str,
		input_type : Str,
		output_type : Str,
		live : Bool,
		live_refresh_ms : U64,
	}

	from_read : Config, Read(a, b) -> PageBinding
	from_read = |config, read| {
		operation = read.metadata()
		{
			metadata: {
				name: config.name,
				title: config.title,
				path: config.path,
				operation: operation.name,
				defaults: "{}",
				template: config.template.path(),
				input_type: operation.input_type,
				output_type: operation.output_type,
				live: Bool.False,
				live_refresh_ms: 0,
			},
		}
	}

	from_read_with_defaults : Config, Read(a, b), a -> PageBinding
	from_read_with_defaults = |config, read, input| {
		with_read_defaults(from_read(config, read), read, input)
	}

	with_read_defaults : PageBinding, Read(a, b), a -> PageBinding
	with_read_defaults = |binding, read, input| {
		..binding,
		metadata: { ..binding.metadata, defaults: read.encode_input(input) },
	}

	with_defaults_from : PageBinding, PageBinding -> PageBinding
	with_defaults_from = |binding, completed| {
		..binding,
		metadata: { ..binding.metadata, defaults: completed.metadata.defaults },
	}

	with_query_defaults : PageBinding, _ -> PageBinding
	with_query_defaults =
		|binding, defaults| { ..binding, metadata: { ..binding.metadata, defaults: Json.to_str(defaults) } }

	live : PageBinding -> PageBinding
	live = |binding| { ..binding, metadata: { ..binding.metadata, live: Bool.True } }

	live_refresh_every : PageBinding, U64 -> PageBinding
	live_refresh_every = |binding, milliseconds| {
		..binding,
		metadata: { ..binding.metadata, live: Bool.True, live_refresh_ms: milliseconds },
	}

	metadata : PageBinding -> Metadata
	metadata = |binding| binding.metadata

	named : Str, PageBinding -> PageBinding
	named = |name, binding| { ..binding, metadata: { ..binding.metadata, name } }

	route : PageBinding -> Str
	route = |binding| "$page.${binding.metadata.name}"
}
