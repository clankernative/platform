import Models
import Title
import Document
import pf.Index

# Persistence is registered here once and passed explicitly to App.definition.
Storage :: [].{
	Tables : { reports : List(Models.Report) }

	schema : Tables -> Tables
	schema = |tables| tables

	definition = {
		schema,
		identities: "model-identities.json",
		domains: { title: Title.rules, document: Document.rules },
		indexes: {
			# The sweep selects ready-but-unannounced reports. Filtering an
			# unindexed field is refused by the host, which is what keeps a
			# recurring job from turning into a recurring full scan.
			reports: { by_announcement: Index.non_unique({ ready: Index.field, announced: Index.field }) },
		},
	}
}
