import pf.Selection
import pf.Predicate
import pf.Model
import pf.Ref
import Models
import Data
import NotificationRules

Publications :: [].{
	Output : {
		notification_id : Ref(Models.Publication),
		duplicate : Bool,
		slack_accepted : Bool,
		channel : Str,
		timestamp : Str,
		status_url : Str,
	}

	find = |app_id, publication_id| Selection.filter(
		Data.publications,
		Predicate.all([
			Data.publications_app_id_equal(app_id),
			Data.publications_publication_id_equal(publication_id),
		]),
	)

	valid_id : Str -> Bool
	valid_id = |value| !value.trim().is_empty() and NotificationRules.length(value) <= 128

	# Payload order and unused structural codec fields do not change business identity.
	normalize : List(NotificationRules.Value) -> List(NotificationRules.Value)
	normalize = |values| values.map(
		|value| {
			name: value.name,
			kind: value.kind,
			text: if value.kind == "text" value.text else "",
			integer: if value.kind == "integer" value.integer else 0,
			boolean: if value.kind == "boolean" value.boolean else Bool.False,
		},
	)

	valid_payload : List(NotificationRules.Value) -> Bool
	valid_payload = |values| values.len() <= 20 and values.all(
		|value| {
			NotificationRules.valid_field_name(value.name)
				and (value.kind == "text" or value.kind == "integer" or value.kind == "boolean")
					and values.keep_if(|other| other.name == value.name).len() == 1
						and NotificationRules.length(value.text) <= 1000
		},
	) and Json.to_str(normalize(values)).to_utf8().len() <= 16_384

	same_payload : Str, List(NotificationRules.Value) -> Bool
	same_payload = |stored, input| {
		parsed : Try(List(NotificationRules.Value), _)
		parsed = Json.parse(stored)
		match parsed {
			Err(_) => Bool.False
			Ok(values) => values.len()
				== input.len()
				and values.all(|value| normalize(input).any(|other| value == other))
		}
	}

	output : Model.Entity(Models.Publication), Bool -> Output
	output = |row, duplicate| {
		notification_id: row.id,
		duplicate,
		slack_accepted: row.value.slack_accepted,
		channel: row.value.channel,
		timestamp: row.value.timestamp,
		status_url: "/api/invocations/${row.value.invocation}",
	}

	output_fields = {
		notification_id: "Durably accepted publication.",
		duplicate: "An existing publication identity was reused without another provider attempt.",
		slack_accepted: "A validated Slack acceptance receipt was committed; false does not prove non-delivery.",
		channel: "Pinned channel from the validated receipt, empty until confirmed.",
		timestamp: "Slack acceptance timestamp, empty until confirmed.",
		status_url: "Original command status. The host separately authorizes the original actor and current authority.",
	}

	example : {} -> Try(Output, Str)
	example = |_| {
		id = Ref.from_str("npub_0000000000e008000000000000").map_err(|_| "invalid example reference")?
		Ok({
			notification_id: id,
			duplicate: Bool.False,
			slack_accepted: Bool.True,
			channel: "C123",
			timestamp: "1.000001",
			status_url: "/api/invocations/00000000-0000-4000-8000-000000000001",
		})
	}
}
