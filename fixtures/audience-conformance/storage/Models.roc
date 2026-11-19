import pf.WebUrl
import Title
import pf.Text
import pf.Table

Models :: [].{
	Link := { title : Text(Title), destination : WebUrl, owner : Str }.{
		table : Table(Link, _)
		table = Table.keyed(|row| { owned_by: Table.owner({ owner: row.owner }) })
	}
}
