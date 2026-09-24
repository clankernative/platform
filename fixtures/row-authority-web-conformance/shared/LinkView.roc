import pf.Model
import pf.Ref
import pf.RowVersion
import pf.Text
import pf.CollectionPage
import Models
import Title
import Domains

LinkView :: [].{
	Value : { id : Ref(Models.Link), version : RowVersion, title : Text(Title), destination : Str, owner : Str }

	Page : CollectionPage(Value)

	Saved : { id : Ref(Models.Link), version : RowVersion }

	fields =
		{
			id: "The stable link identifier.",
			version: "The current row revision.",
			title: "The link's display title.",
			destination: "The external destination URL.",
			owner: "The actor who created the link.",

		}

	saved_fields = { id: "The saved link identifier.", version: "The committed row revision." }

	example : {} -> Try(Value, Str)
	example = |_| {
		id = Ref.from_str("lin_0000000000e008000000000000").map_err(|_| "invalid example id")?
		title = Domains.title("Example link")?
		Ok({ id, version: RowVersion.one, title, destination: "https://example.com/", owner: "alice" })
	}

	from_row : Model.Entity(Models.Link) -> Value
	from_row =
		|
			row,
		|
			{
				id: row.id,
				version: row.version,
				title: row.value.title,
				destination: row.value.destination.to_str(),
				owner: row.value.owner,
			}
}
