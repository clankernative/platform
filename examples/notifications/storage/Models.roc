import pf.Table
import pf.Ref

Models :: [].{
	Definition := { app_id : Str, event_key : Str, description : Str, revision : U64, enabled : Bool }.{
		table : Table(Definition, _)
		table = Table.keyed(|row| { by_app_event: Table.unique({ app_id: row.app_id, event_key: row.event_key }) })
	}

	ContractVersion := {
		definition : Ref(Definition),
		number : U64,
		fields_json : Str,
		template : Str,
		template_revision : U64,
	}.{
		table : Table(ContractVersion, _)
		table =
			Table.keyed(
				|row| { by_definition_number: Table.unique({ definition: row.definition, number: row.number }) },
			)
	}

	ConfigurationChange := { definition : Ref(Definition), revision : U64, actor : Str }.{
		table : Table(ConfigurationChange, _)
		table =
			Table.keyed(
				|row| { by_definition_revision: Table.unique({ definition: row.definition, revision: row.revision }) },
			)
	}

	Publication := {
		app_id : Str,
		publication_id : Str,
		definition : Ref(Definition),
		contract_version : Ref(ContractVersion),
		latest_version : U64,
		template_revision : U64,
		fields_json : Str,
		payload_json : Str,
		message : Str,
		actor : Str,
		invocation : Str,
		accepted_at : I64,
		slack_accepted : Bool,
		channel : Str,
		timestamp : Str,
	}.{
		table : Table(Publication, _)
		table = Table.keyed(
			|row| {
				by_app_publication: Table.unique({ app_id: row.app_id, publication_id: row.publication_id }),
			},
		)
	}
}
