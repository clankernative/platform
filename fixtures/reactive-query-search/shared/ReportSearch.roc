import pf.Model
import pf.CollectionPage
import pf.Ref
import pf.RowVersion
import pf.Text
import Models
import Title
import ReportView

ReportSearch :: [].{
	Match : { id : Ref(Models.Report), version : RowVersion, title : Text(Title), ready : Bool }

	Result : { term : Str, matches : CollectionPage(Match), searched_all : Bool }

	fields = {
		term: "The raw, case-sensitive title substring used for this search.",
		matches: {
			description: "Matching summaries among the first 100 visible reports, ordered by report ID.",
			fields: {
				items: {
					description: "Matching report summaries.",
					each: {
						id: ReportView.fields.id,
						version: ReportView.fields.version,
						title: ReportView.fields.title,
						ready: ReportView.fields.ready,
					},
				},
				has_more: "False: every match within the bounded scan is returned.",
				next_after: "Empty because the matches are not paged.",
			},
		},
		searched_all: "Whether the bounded scan covered every visible report. When false, refine the term or browse the paginated directory.",
	}

	from_row : Model.Entity(Models.Report) -> Match
	from_row = |row| { id: row.id, version: row.version, title: row.value.title, ready: row.value.ready }
}
