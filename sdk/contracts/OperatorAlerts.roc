import Effects
import Resource
import Api

# The operator chooses the destination in resource authority. Apps supply message
# content only; the synthetic adapter is not a promise of live Slack deduplication.
OperatorAlerts :: [].{
	send_effect = Api.external("operator_alerts.send.v1")

	Problem : { code : Str, message : Str, retryable : Bool }

	Outcome : [Accepted(Str), Disabled, Failed(Problem)]

	send : Resource, Str, Str -> Effects(Outcome)
	send = |resource, topic, body| Effects.capability(
		"operator_alerts.send.v1",
		Json.to_str({ handle: Resource.token(resource), topic, body }),
	).and_then(
		|raw| {
			parsed : Try(Outcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_operator_alert_outcome"))
		},
	)
}
