import Effects
import Resource
import Api

# One admitted organization; lookup, invitation reconciliation and suspension are
# provider semantics. Application policy and cross-provider ordering stay in Roc.
Linear :: [].{
	ensure_effect = Api.external("linear.ensure_access.v1")

	suspend_effect = Api.external("linear.suspend.v1")

	Problem : { code : Str, message : Str, retryable : Bool }

	EnsureOutcome : [Active(Str), Reactivated(Str), PendingInvitation(Str), Invited(Str), Disabled, Failed(Problem)]

	SuspendOutcome : [Suspended(Str), AlreadySuspended(Str), NotFound, Disabled, Failed(Problem)]

	ensure_access : Resource, Str -> Effects(EnsureOutcome)
	ensure_access = |resource, primary_email| Effects.capability(
		"linear.ensure_access.v1",
		Json.to_str({ handle: Resource.token(resource), primary_email }),
	).and_then(
		|raw| {
			parsed : Try(EnsureOutcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_linear_ensure_outcome"))
		},
	)

	suspend : Resource, Str -> Effects(SuspendOutcome)
	suspend = |resource, primary_email| Effects.capability(
		"linear.suspend.v1",
		Json.to_str({ handle: Resource.token(resource), primary_email }),
	).and_then(
		|raw| {
			parsed : Try(SuspendOutcome, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_linear_suspend_outcome"))
		},
	)
}
