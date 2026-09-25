import pf.Model
import pf.Ref
import pf.CollectionPage
import Models

LinkView :: [].{
	Value : { id : Ref(Models.Link), name : Str, url : Str, visits : U64 }

	Page : CollectionPage(Value)

	Saved : { id : Ref(Models.Link), name : Str }

	Visit : { id : Ref(Models.Link), url : Str, visits : U64 }

	fields = {
		id: "The stable link identifier.",
		name: "The link name, such as docs or docs/%s.",
		url: "The stored destination; a wildcard's contains one %s.",
		visits: "How many times the link was followed.",
	}

	saved_fields = { id: "The saved link identifier.", name: "The saved link name." }

	visit_fields = {
		id: "The visited link.",
		url: "The destination to redirect to, with any wildcard capture encoded.",
		visits: "The visit count including this visit.",
	}

	example_id : {} -> Try(Ref(Models.Link), Str)
	example_id = |_| Ref.from_str("lnk_0000000000e008000000000000").map_err(|_| "invalid example id")

	example : {} -> Try(Value, Str)
	example = |_| Ok({ id: example_id({})?, name: "docs", url: "https://example.com/docs", visits: 0 })

	from_row : Model.Entity(Models.Link) -> Value
	from_row = |row| { id: row.id, name: row.value.name, url: row.value.url, visits: row.value.visits }
}
