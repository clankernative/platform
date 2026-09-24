Models :: [].{
	# Storage is relational, so each decoded collection is persisted as its
	# canonical join. The fields under test are the command inputs, not the columns.
	Thing := {
		name : Str,
		tags_joined : Str,
		tag_count : U64,
		attributes_joined : Str,
		groups_joined : Str,
		owner : Str,
	}
}
