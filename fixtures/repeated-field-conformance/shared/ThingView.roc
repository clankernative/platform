import pf.Model
import pf.Ref
import pf.RowVersion
import pf.CollectionPage
import Models

ThingView :: [].{
	Saved : { id : Ref(Models.Thing), version : RowVersion }

	Thing : {
		id : Ref(Models.Thing),
		version : RowVersion,
		name : Str,
		tag_count : U64,
		tags_joined : Str,
		attributes_joined : Str,
		groups_joined : Str,
	}

	Page : CollectionPage(Thing)

	from_row : Model.Entity(Models.Thing) -> Thing
	from_row = |row| {
		id: row.id,
		version: row.version,
		name: row.value.name,
		tag_count: row.value.tag_count,
		tags_joined: row.value.tags_joined,
		attributes_joined: row.value.attributes_joined,
		groups_joined: row.value.groups_joined,
	}

	# Joined in submitted order so a test can assert document order survived decoding.
	joined : List(Str) -> Str
	joined = |tags| match tags {
		[] => ""
		[first, .. as rest] => if rest.is_empty() first else "${first},${joined(rest)}"
	}

	fields = {
		id: "Platform identifier for this row.",
		version: "Stored row revision.",
		name: "Single-valued name supplied alongside the repeated tags.",
		tag_count: "Number of decoded tags; zero for the empty-list marker.",
		tags_joined: "Decoded tags joined in their submitted order.",
		attributes_joined: "Decoded map entries as key=value, in canonical key order.",
		groups_joined: "Decoded set members in canonical order.",
	}

	saved_fields = { id: "Identifier of the saved row.", version: "Revision of the saved row." }

	sample : {} -> Try(Saved, Str)
	sample = |_| {
		id = Ref.from_str("thg_0000000000e008000000000000").map_err(|_| "invalid sample id")?
		version = RowVersion.from_u64(1).map_err(|_| "invalid sample revision")?
		Ok({ id, version })
	}

	sample_view : {} -> Try(Thing, Str)
	sample_view = |_| {
		row = sample({})?
		Ok({
			id: row.id,
			version: row.version,
			name: "sample",
			tag_count: 2,
			tags_joined: "docs,runbook",
			attributes_joined: "role=reader",
			groups_joined: "eng",
		})
	}
}
