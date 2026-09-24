import Write
import IngressBinding

# A platform-owned trigger for an existing internal command, where the trigger is a
# verified inbound request rather than a clock. The mirror of Schedule.
#
# **The bound command's input is the provider's envelope.** A delivery is admitted
# with the verified payload exactly as the provider sent it, so the command that
# receives it is shaped by that provider.
#
# An application that does not want its domain command shaped by a provider binds a
# thin adapter command instead, and has that request the domain command:
#
#     # commands/slack-approval/SlackApproval.roc — input is the Slack envelope
#     handle = |_context, event| Commands.approve.request(
#         Data.websites,
#         target,
#         { website: event.text, requested_by: event.user },
#     )
#
# That keeps the domain command provider-agnostic, is visible in the application
# rather than hidden in a binding, and carries its own contract and verification
# like any other command. It uses only machinery that already works.
#
# An earlier version of this module accepted a `decode` function here and the
# compiler type-checked it against the bound command. It was never invoked — the
# binding discarded it — so the surface promised a decoupling the runtime did not
# perform. Rather than leave a checked-but-dead parameter, the promise is withdrawn
# and the pattern that does work is written down. Carrying a decode function into
# the worker's dispatch is possible and is recorded in the plan as future work; it
# needs the envelope registered as an inferred input type, which is real generator
# machinery and should wait until an application needs it.
Ingress(a) :: { binding : IngressBinding }.{
	# Slack's Events API: messages, mentions, channel activity. Slack retries a
	# failed delivery three times over about six minutes carrying the same
	# event_id, which is what makes the run exactly-once.
	slack_events : Write(a, b) -> Ingress(a)
	slack_events = |command| bind(command, "slack.events.v1")

	# Slack interactivity: block actions, view submissions, shortcuts. These carry
	# no durable identifier of their own, so the provider composes one from the
	# fields that together identify an interaction. The application surface is the
	# same either way, because identity is never an application's decision: it is
	# extracted before the application is involved, so a replayed delivery is
	# refused without running any application code.
	slack_interactivity : Write(a, b) -> Ingress(a)
	slack_interactivity = |command| bind(command, "slack.interactivity.v1")

	# GitHub webhooks: pushes, pull requests, check runs, releases, deployments.
	# Every delivery carries a GUID in `x-github-delivery`, and GitHub reuses it
	# when a delivery is redelivered from the UI or the API, so a redelivery
	# resolves to the invocation that already ran rather than starting a second.
	#
	# GitHub signs the body alone and sends no timestamp, so unlike Slack there is
	# no signed instant to bound replay with. Identity does that work here instead,
	# which is why the delivery GUID being stable is a property worth relying on
	# rather than a convenience.
	github_webhook : Write(a, b) -> Ingress(a)
	github_webhook = |command| bind(command, "github.webhook.v1")

	bind : Write(a, b), Str -> Ingress(a)
	bind = |command, provider| {
		operation = command.metadata()
		{
			binding: IngressBinding.define({
				# The App.definition.ingress record supplies the registered name,
				# exactly as it supplies a page's and a schedule's.
				name: "",
				operation: operation.name,
				input_type: operation.input_type,
				provider,
			}),
		}
	}

	register : Ingress(a) -> IngressBinding
	register = |ingress| ingress.binding
}
