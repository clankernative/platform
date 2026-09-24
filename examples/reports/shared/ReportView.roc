import pf.Model
import pf.Ref
import pf.RowVersion
import pf.Text
import pf.CollectionPage
import Models
import Title
import Document
import Domains
import pf.Notifications

ReportView :: [].{
	Value : {
		id : Ref(Models.Report),
		version : RowVersion,
		title : Text(Title),
		text : Text(Document),
		ready : Bool,
		bytes : U64,
		lines : U64,
	}

	Page : CollectionPage(Value)

	Detail : {
		id : Ref(Models.Report),
		version : RowVersion,
		title : Text(Title),
		text : Text(Document),
		ready : Bool,
		bytes : U64,
		lines : U64,
		delivery : Notifications.Delivery,
	}

	Saved : { id : Ref(Models.Report), version : RowVersion }

	fields = {
		id: "The stable report identifier.",
		version: "The current row revision. Pass it when revising this report.",
		title: "The title supplied by the report's author.",
		text: "The current document text.",
		ready: "Whether analysis has completed for this revision.",
		bytes: "UTF-8 bytes in the analyzed document. Meaningful only when ready is true.",
		lines: "Lines in the analyzed document. Meaningful only when ready is true.",
	}

	saved_fields = {
		id: "Identifier of the saved report.",
		version: "The committed revision. Background completion may advance it; read current state before editing.",
	}

	detail_fields =
		{
			id: fields.id,
			version: fields.version,
			title: fields.title,
			text: fields.text,
			ready: fields.ready,
			bytes: fields.bytes,
			lines: fields.lines,
			delivery: {
				description: "Notification acceptance for this report and actor.",
				fields: {
					id: "The latest notification receipt for the current actor.",
					status: "Notification acceptance status; none when no notification has been accepted.",
					count: "Accepted notifications for this report and actor.",
				},
			},

		}

	with_delivery : Value, Notifications.Delivery -> Detail
	with_delivery =
		|
			row,
			delivery,
		|
			{
				id: row.id,
				version: row.version,
				title: row.title,
				text: row.text,
				ready: row.ready,
				bytes: row.bytes,
				lines: row.lines,
				delivery,

			}

	example : {} -> Try(Value, Str)
	example = |_| {
		id = Ref.from_str("rep_0000000000e008000000000000").map_err(|_| "invalid example reference")?
		title = Domains.title("Weekly report")?
		text = Domains.document("A\nB")?
		Ok({ id, version: RowVersion.one, title, text, ready: Bool.True, bytes: 3, lines: 2 })
	}

	from_row : Model.Entity(Models.Report) -> Value
	from_row = |row| {
		id: row.id,
		version: row.version,
		title: row.value.title,
		text: row.value.text,
		ready: row.value.ready,
		bytes: row.value.bytes,
		lines: row.value.lines,
	}
}
