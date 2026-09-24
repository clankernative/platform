import pf.Handler
import pf.TextMap
import pf.TextSet
import pf.Api
import pf.Tx
import pf.Context
import TagThingTypes
import ThingView
import Data

TagThing :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state([Api.create(Data.things)]),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, TagThingTypes.Input -> Tx(ThingView.Saved)
	handle = |context, input| Tx.create(
		Data.things,
		{
			name: input.name,
			# Joined in submitted order so a test can assert document order survived.
			tags_joined: ThingView.joined(input.tags),
			tag_count: input.tags.len(),
			attributes_joined: ThingView.joined(
				input.attributes.to_entries().map(|entry| "${entry.key}=${entry.value}"),
			),
			groups_joined: ThingView.joined(input.groups.to_list()),
			owner: context.actor(),
		},
	).map(|row| { id: row.id, version: row.version })

	contract = {
		title: "Tag a thing",
		usage: {
			purpose: "Store a name with an ordered list of tags supplied by repeated form controls.",
			use_when: ["Exercising repeated form field decoding."],
			avoid_when: ["Anything other than conformance testing."],
			preconditions: [],
			effects: ["Creates one row owned by the current actor."],
			result: "The saved identifier and revision.",
		},
		inputs: {
			name: "Single-valued name; it may not repeat in a submission.",
			tags: {
				description: "Ordered tags. Repeated controls supply the list; one empty control is the empty list.",
				each: "One tag, in submitted document order.",
			},
			attributes: {
				description: "Keyed attributes with unique nonblank keys, canonically ordered by key.",
				each: "One attribute value.",
			},
			groups: {
				description: "Unique group members, canonically ordered; duplicates are rejected.",
				each: "One group member.",
			},
		},
		outputs: ThingView.saved_fields,
		example: example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [],
	}

	example : {} -> Try({ input : TagThingTypes.Input, output : ThingView.Saved }, Str)
	example = |_| {
		row = ThingView.sample({})?
		attributes = TextMap.from_entries([{ key: "role", value: "reader" }]).map_err(|_| "invalid sample map")?
		groups = TextSet.from_list(["eng"]).map_err(|_| "invalid sample set")?
		Ok({ input: { name: "sample", tags: ["docs", "runbook"], attributes, groups }, output: row })
	}

	verify_input : Str, U64 -> Try(TagThingTypes.Input, Str)
	verify_input = |_snapshot, seed| {
		attributes = TextMap.from_entries([{ key: "role", value: "reader" }]).map_err(|_| "invalid map")?
		groups = TextSet.from_list(["eng"]).map_err(|_| "invalid set")?
		Ok({ name: "generated-${seed.to_str()}", tags: ["alpha", "beta"], attributes, groups })
	}

	verify_result : Str, ThingView.Saved, Str -> Try(Bool, Str)
	verify_result = |before, saved, after| {
		old = Data.snapshot(before)?
		next = Data.snapshot(after)?
		Ok(
			next.things.len()
				== old.things.len() + 1
				and next.things.any(|row| row.id == saved.id and row.version == saved.version),
		)
	}
}
