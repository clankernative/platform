import pf.Api
import pf.Handler
import pf.InteractiveContext
import pf.Credential
import pf.Tx
import Credentials
import KeyFamilies
import Data
import Selectors
import RotatePersonalTypes

RotatePersonal :: [].{
	Output : { status : Str, lineage : Str, version : Str, revision : U64 }

	definition = Api.command({
		handler: Handler.interactive(handle),
		contract: {
			title: "Rotate a personal credential",
			usage: {
				purpose: "Atomically replace the confirmed predecessor and record its public successor.",
				use_when: ["Replacing an existing key after fresh protected confirmation."],
				avoid_when: [],
				preconditions: ["Current management policy and exact lineage/head/revision confirmation."],
				effects: ["Replaces at most one version and creates a public product receipt."],
				result: "Rotated public identity or Conflict.",
			},
			inputs: {
				lineage: "Public family reference.",
				head: "Expected version identity.",
				revision: "Expected management revision.",
			},
			outputs: {
				status: "rotated or conflict.",
				lineage: "Public lineage.",
				version: "Successor identity.",
				revision: "Successor revision.",
			},
			example: |_| Ok({ input: { lineage: "", head: "", revision: 1 }, output: empty("conflict") }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		execution: Api.current_state([Api.create(Data.key_receipts)]),
		verification: {
			input: |snapshot, _seed| {
				row =
					Data.snapshot(snapshot)?
						.key_receipts
						.find_first(|candidate| candidate.value.family == "personal")
						.map_err(|_| "create a personal first")?
				Ok({ lineage: row.value.lineage, head: row.value.head, revision: row.value.revision })
			},
			check: |before, output, after| {
				old = Data.snapshot(before)?
				next = Data.snapshot(after)?
				Ok(
					if output.status == "conflict" {
						before == after
					} else {
						output.status == "rotated" and next.key_receipts.len() == old.key_receipts.len() + 1
							and next
								.key_receipts
								.any(
									|
										row,
									|
										row.value.lineage
											== output.lineage
											and row.value.head
												== output.version
												and row.value.revision == output.revision,
								)
					},
				)
			},
		},
	}).credentials(Credential.rotate_access(KeyFamilies.personal)).credential_rotation(
		Selectors.rotate_personal_input_lineage,
		Selectors.rotate_personal_input_head,
		Selectors.rotate_personal_input_revision,
	)

	empty : Str -> Output
	empty = |status| { status, lineage: "", version: "", revision: 0 }

	handle : InteractiveContext, RotatePersonalTypes.Input -> Tx(Output)
	handle = |context, input| {
		lineage = match (Credentials.personal.ref_from_str)(input.lineage) {
			Ok(value) => value
			Err(_) => return Tx.succeed(empty("conflict"))
		}
		expected =
			match (Credentials.personal.snapshot_from_parts)({ lineage, head: input.head, revision: input.revision }) {
				Ok(value) => value
				Err(_) => return Tx.succeed(empty("conflict"))
			}
		(Credentials.personal.rotate)(
			context,
			{
				expected: expected,
			},
		).and_then(
			|outcome| match outcome {
				Conflict => Tx.succeed(empty("conflict"))
				Rotated(issued) => {
					receipt =
						{
							family: "personal",
							lineage: issued.lineage().to_str(),
							head: issued.version().id(),
							revision: input.revision + 1,
						}
					Tx.create(Data.key_receipts, receipt)
						.map(
							|
								_,
							|
								{
									status: "rotated",
									lineage: receipt.lineage,
									version: receipt.head,
									revision: receipt.revision,
								},
						)
				}
			},
		)
	}
}
