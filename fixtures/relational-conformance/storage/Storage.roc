import Models
import Title
import pf.Index

Storage :: [].{
	Tables : { stages : List(Models.Stage), deals : List(Models.Deal), history : List(Models.History) }

	schema : Tables -> Tables
	schema = |tables| tables

	definition = {
		schema,
		identities: "model-identities.json",
		domains: { title: Title.rules },
		indexes: {
			stages: { by_name: Index.unique({ name: Index.field }) },
			deals: { by_stage_title: Index.unique({ stage_id: Index.field, title: Index.field }) },
			history: {
				by_time: Index.non_unique({
					occurred_at: Index.field,
					deal_id: Index.field,
					from_stage_id: Index.field,
					to_stage_id: Index.field,
				}),
			},
		},
	}
}
