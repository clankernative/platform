import pf.Api
import pf.Handler
import pf.Context
import pf.Observe
import pf.Query
import pf.CollectionPage
import Reads
import Errors
import NotificationAccess
import NotificationRules
import PreviewNotificationTypes

PreviewNotification :: [].{
	definition =
		Api.query({
			handler: Handler.prepared(prepare, handle),
			contract,
			verification: { input: verify_input, check: verify_result },
		})

	prepare : Context, PreviewNotificationTypes.Input -> Observe(Bool)
	prepare = |_context, input| NotificationAccess.check(input.app_id)

	handle : Context, PreviewNotificationTypes.Input, Bool -> Query(PreviewNotificationTypes.Output)
	handle = |_context, input, allowed| if allowed {
		result = NotificationRules.render(input.fields, input.template, input.payload)
		Query.succeed(
			{ valid: result.valid, message: result.message, findings: CollectionPage.complete(result.findings) },
		)
	} else {
		Query.from_try(Err(Errors.preview_denied))
	}

	contract = {
		title: "Preview a notification message",
		usage: {
			purpose: "Validate and render a message after checking current app ownership.",
			use_when: ["An app owner previews a template before saving it."],
			avoid_when: ["Sending a message or accepting a publication."],
			preconditions: ["Current direct app ownership."],
			effects: [],
			result: "A rendered message or field findings. No delivery or business write occurs.",
		},
		inputs: {
			app_id: "Business app identifier.",
			fields: NotificationRules.field_input,
			template: "Text with declared {{field}} placeholders.",
			payload: NotificationRules.value_input,
		},
		outputs: {
			valid: "Whether schema, template, payload and rendered length are valid.",
			message: "Rendered text only when valid.",
			findings: {
				description: "Complete validation findings.",
				fields: {
					items: {
						description: "Field and code for each validation failure.",
						each: { field: "Affected field.", code: "Validation failure code." },
					},
					has_more: "Always false.",
					next_after: "Empty; this is complete.",
				},
			},
		},
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.preview_denied],
	}

	example : {} -> Try({ input : PreviewNotificationTypes.Input, output : PreviewNotificationTypes.Output }, Str)
	example =
		|
			_,
		| Ok({ input: sample, output: { valid: Bool.True, message: "Build: passed", findings: CollectionPage.empty } })

	sample : PreviewNotificationTypes.Input
	sample =
		{
			app_id: "demo",
			fields: NotificationRules.summary_fields,
			template: "Build: {{summary}}",
			payload: [{ name: "summary", kind: "text", text: "passed", integer: 0, boolean: Bool.False }],
		}

	verify_input : Str, U64 -> Try(PreviewNotificationTypes.Input, Str)
	verify_input = |_snapshot, _seed| Ok(sample)

	verify_result : Str, PreviewNotificationTypes.Output, Str -> Try(Bool, Str)
	verify_result =
		|
			before,
			output,
			after,
		|
			Ok(
				before
					== after
					and output.valid and output.message == "Build: passed" and output.findings.items().is_empty(),
			)

	preview_denied =
		Api.error({
			description: "Current ownership did not authorize this preview.",
			recovery: "Ask an ownership administrator for access.",
			verification: |_| Api.failed_query(Reads.preview, |_snapshot, _seed| Ok({ ..sample, app_id: "" })),
		})
}
