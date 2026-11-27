import pf.Api
import pf.Context
import pf.Selection
import pf.Tx
import pf.Handler
import Commands
import Data
import Errors
import Selectors
import IntakePolicy
import ProposalTerms
import TriageTypes

Triage :: [].{
	definition =
		Api.command({
			audience: Employees,
			handler: Handler.local(handle),
			contract,
			execution: Api.current_state([
				Api.update(
					Data.requests,
					[
						Api.field(Selectors.requests_status),
						Api.field(Selectors.requests_review_note),
						Api.field(Selectors.requests_reviewer),
						Api.field(Selectors.requests_checked_folder),
					],
				),
			]),
			verification: { input: verify_input, check: verify_result },
		})
			.verify_as_actor(IntakePolicy.reviewer)

	handle : Context, TriageTypes.Input -> Tx(TriageTypes.Output)
	handle = |ctx, input| {
		Tx.find(IntakePolicy.selection({})).and_then(
			|configured| match configured {
				None => Tx.reject(Errors.reviewer_required)
				Some(settings) => review(ctx, input, settings.value.reviewer)
			},
		)
	}

	review : Context, TriageTypes.Input, Str -> Tx(TriageTypes.Output)
	review = |ctx, input, reviewer| {
		if !IntakePolicy.direct_reviewer(ctx, reviewer) {
			return Tx.reject(Errors.reviewer_required)
		}
		approves = input.decision == "approved"
		if (!approves and input.decision != "returned") or !ProposalTerms.text(input.review_note, 1000) {
			return Tx.reject(Errors.invalid_review)
		}
		Tx.find(Selection.filter(Data.requests, Data.requests_number_equal(input.id))).and_then(
			|found| match found {
				None => Tx.reject(Errors.unavailable_request)
				Some(row) => {
					if row.value.status != "pending" {
						return Tx.reject(Errors.unavailable_request)
					}
					if input.checked_folder != (approves and row.value.has_contract) {
						return Tx.reject(Errors.invalid_review)
					}
					Tx.update(
						Data.requests,
						row,
						{
							..row.value,
							status: input.decision,
							reviewer: ctx.actor(),
							review_note: input.review_note,
							checked_folder: input.checked_folder,
						},
					)
						.map(|saved| { id: saved.value.number, status: saved.value.status })
				}
			},
		)
	}

	contract = {
		title: "Decide a pending vendor request",
		usage: {
			purpose: "Approve or return the exact stored financial proposal.",
			use_when: ["The assigned reviewer has examined the request and any contract."],
			avoid_when: [],
			preconditions: [
				"Direct assigned reviewer, pending request, explicit folder check for approval with a contract.",
			],
			effects: ["Records a local decision only."],
			result: "Recorded decision.",
		},
		inputs: {
			id: "Immutable request number.",
			decision: "approved or returned.",
			review_note: "Reason visible to the requester.",
			checked_folder: "Confirm having personally checked the linked file is in the configured folder; true only when approving a request with a contract.",
		},
		outputs: { id: "Request number.", status: "Final decision." },
		example: |
			_,
		|
			Ok({
				input: { id: 1, decision: "approved", review_note: "Terms reviewed.", checked_folder: Bool.True },
				output: { id: 1, status: "approved" },
			}),
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.reviewer_required, Errors.unavailable_request, Errors.invalid_review],
	}

	verify_input : Str, U64 -> Try(TriageTypes.Input, Str)
	verify_input = |snapshot, seed| {
		row =
			Data.verification_snapshot(snapshot)?
				.live
				.requests
				.find_first(|r| r.value.status == "pending")
				.map_err(|_| "submit a request first")?
		approves = seed % 4 < 2
		Ok({
			id: row.value.number,
			decision: if approves "approved" else "returned",
			review_note: "Review recorded.",
			checked_folder: approves and row.value.has_contract,
		})
	}

	verify_result : Str, TriageTypes.Output, Str -> Try(Bool, Str)
	verify_result = |before, out, after| {
		old = Data.verification_snapshot(before)?
		new = Data.verification_snapshot(after)?
		ctx = Api.verification_context(before)?
		parsed : Try({ id : U64, decision : Str, review_note : Str, checked_folder : Bool }, _)
		parsed = Json.parse(ctx.input)
		input = parsed.map_err(|_| "invalid review input")?
		original = old.live.requests.find_first(|r| r.value.number == input.id).map_err(|_| "no pending proposal")?
		revised = new.live.requests.find_first(|r| r.id == original.id).map_err(|_| "missing reviewed proposal")?
		expected =
			{
				..original.value,
				status: input.decision,
				reviewer: ctx.actor,
				review_note: input.review_note,
				checked_folder: input.checked_folder,
			}
		Ok(
			out.id
				== input.id
				and out.status
					== input.decision
					and original.value.status
						== "pending"
						and revised.version.to_u64()
							== 2
							and expected == revised.value
								and ctx.actor
									== IntakePolicy.reviewer
									and old.live.requests.len()
										== new.live.requests.len()
										and new.deleted.requests.is_empty()
											and old
												.live
												.requests
												.all(
													|
														r,
													|
														r.id
															== original.id
															or new
																.live
																.requests
																.any(
																	|
																		other,
																	|
																		other.id
																			== r.id
																			and other.version
																				== r.version
																				and r.value == other.value,
																),
												),
		)
	}

	missing_input : Str, U64 -> Try(TriageTypes.Input, Str)
	missing_input = |_, _| Ok({ id: 0, decision: "approved", review_note: "Reviewed.", checked_folder: Bool.False })

	reviewer_required =
		Api.error({
			description: "Only the assigned reviewer acting directly can decide a request.",
			recovery: "Ask the assigned reviewer to sign in.",
			verification: |
				_,
			|
				Api.failed_command_as(
					Commands.triage,
					Api.verification_principal("ada@synthetic.example"),
					missing_input,
				),
		})

	unavailable_request =
		Api.error({
			description: "The request is missing or has already received its final decision.",
			recovery: "Refresh the pending review queue.",
			verification: |
				_,
			| Api.failed_command_as(Commands.triage, Api.verification_principal(IntakePolicy.reviewer), missing_input),
		})

	invalid_review = Api.error({
		description: "The decision, review note or contract confirmation is invalid.",
		recovery: "Provide a decision, a note, and the required contract confirmation.",
		verification: |_| Api.failed_command_as(
			Commands.triage,
			Api.verification_principal(IntakePolicy.reviewer),
			|snapshot, seed| {
				row = Data.verification_snapshot(snapshot)?.live.requests.first().map_err(|_| "submit a request first")?
				Ok({ id: row.value.number, decision: "invalid", review_note: "", checked_folder: seed % 2 == 0 })
			},
		),
	})
}
