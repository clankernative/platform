import pf.Table
import pf.Ref

Models :: [].{
	Definition := { app_id : Str, event_key : Str, description : Str, revision : U64 }.{
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
}
