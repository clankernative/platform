import pf.Selection
import pf.Predicate
import Data

Configurations :: [].{
	definition = |app_id, event_key| Selection.filter(
		Data.definitions,
		Predicate.all([
			Data.definitions_app_id_equal(app_id),
			Data.definitions_event_key_equal(event_key),
		]),
	)

	versions =
		|definition_id| Selection.filter(Data.contract_versions, Data.contract_versions_definition_equal(definition_id))

	version = |definition_id, number| Selection.filter(
		Data.contract_versions,
		Predicate.all([
			Data.contract_versions_definition_equal(definition_id),
			Data.contract_versions_number_equal(number),
		]),
	)
}
