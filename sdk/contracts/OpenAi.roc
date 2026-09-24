import Effects
import Api
import Resource

# Synchronous text-only generation under an activated project/model profile.
# Generation spends an admitted budget and belongs to the effects phase.
OpenAi :: [].{
	generate_effect = Api.external("openai.generate.v1")

	Text : { text : Str, input_tokens : U64, output_tokens : U64 }

	generate : Resource, Str, U64 -> Effects(Text)
	generate = |resource, text, max_output_tokens| Effects.capability(
		"openai.generate.v1",
		Json.to_str({ handle: Resource.token(resource), text, max_output_tokens }),
	).and_then(
		|raw| {
			parsed : Try(Text, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_model_result"))
		},
	)
}
