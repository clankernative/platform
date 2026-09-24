import Title
import Document
import pf.Text
import pf.Table

# Persistent values are nominal. Model.Entity adds host-owned ID and revision fields.
Models :: [].{
	# announced records that the ready revision was actually told to someone.
	# Without it "ready but never announced" is not a question state can answer,
	# and the reconciliation sweep would have nothing to reconcile against.
	Report := {
		title : Text(Title),
		text : Text(Document),
		owner : Str,
		ready : Bool,
		announced : Bool,
		bytes : U64,
		lines : U64,
	}.{
		table : Table(Report, _)
		table = Table.keyed(
			|row| {
				by_announcement: Table.non_unique({ announced: row.announced, ready: row.ready }),
			},
		)
	}
}
