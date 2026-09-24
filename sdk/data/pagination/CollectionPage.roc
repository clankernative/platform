import Cursor

# Required API collection envelope. The host also validates nested page budgets.
CollectionPage(a) :: { items : List(a), has_more : Bool, next_after : Cursor }.{
	# Smart construction checks size and continuation shape, not cursor provenance.
	from_parts : List(a), Bool, Cursor -> Try(CollectionPage(a), Str)
	from_parts = |values, more, next| {
		if values.len() > 100 or (more and (values.is_empty() or next.is_start())) {
			Err("invalid_collection_page")
		} else {
			Ok({ items: values, has_more: more, next_after: next })
		}
	}

	# A collection with nothing in it and nothing after it.
	#
	# Total, because it satisfies every check `from_parts` makes and so cannot be
	# the invalid case. It exists so that code returning a page it computed rather
	# than read has a lawful value for a branch it cannot reach: an application
	# may not declare an error it cannot demonstrate, so an unreachable failure
	# needs somewhere lawful to go.
	empty : CollectionPage(a)
	empty = { items: [], has_more: Bool.False, next_after: Cursor.start }

	# The whole of a collection small enough to be one page.
	#
	# Total, and that is the point. A collection fixed by the artifact -- a
	# published catalog, a capability list -- is a constant, so the compiler
	# evaluates it, proves the failing branch of `from_parts` unreachable, and
	# refuses the build for a branch the types still demand. There has to be
	# nothing to branch on.
	#
	# A list over the page bound yields the empty page. Truncating would answer
	# a different question convincingly, while an empty collection is visibly
	# wrong; a collection that can outgrow a page should be paged instead.
	complete : List(a) -> CollectionPage(a)
	complete = |values| if values.len() > 100 {
		empty
	} else {
		{ items: values, has_more: Bool.False, next_after: Cursor.start }
	}

	# Transform items without changing their count or continuation metadata.
	map : CollectionPage(a), (a -> b) -> CollectionPage(b)
	map = |page, convert| { items: page.items.map(convert), has_more: page.has_more, next_after: page.next_after }

	items : CollectionPage(a) -> List(a)
	items = |page| page.items

	has_more : CollectionPage(a) -> Bool
	has_more = |page| page.has_more

	next_after : CollectionPage(a) -> Cursor
	next_after = |page| page.next_after
}
