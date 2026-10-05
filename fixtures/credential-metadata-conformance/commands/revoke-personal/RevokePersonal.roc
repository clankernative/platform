import pf.Api
import pf.Handler
import pf.InteractiveContext
import pf.Credential
import pf.Tx
import Credentials
import KeyFamilies
import Data
import Selectors
import RevokePersonalTypes

RevokePersonal :: [].{
	Output : { status : Str, lineage : Str, revision : U64 }

	definition = Api.command({
		handler: Handler.interactive(handle),
		contract: {
			title: "Revoke a personal credential",
			usage: {
				purpose: "Terminally revoke the confirmed lineage and its pending deliveries.",
				use_when: ["Closing all versions of an existing key."],
				avoid_when: [],
				preconditions: ["Fresh protected confirmation and current revocation rights."],
				effects: ["Closes the lineage and atomically creates a product receipt."],
				result: "Revoked or AlreadyRevoked, with public identity only.",
			},
			inputs: { lineage: "The exact public lineage confirmed for terminal revocation." },
			outputs: {
				status: "revoked or already_revoked.",
				lineage: "Public lineage.",
				revision: "Terminal management revision.",
			},
			example: |_| Ok({ input: { lineage: "" }, output: { status: "invalid", lineage: "", revision: 0 } }),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		execution: Api.current_state([Api.create(Data.entries)]),
		verification: {
			input: |snapshot, _seed| {
				row =
					Data.snapshot(snapshot)?
						.key_receipts
						.find_first(|candidate| candidate.value.family == "personal")
						.map_err(|_| "create a personal first")?
				Ok({ lineage: row.value.lineage })
			},
			check: |before, output, after| {
				old = Data.snapshot(before)?
				next = Data.snapshot(after)?
				Ok(
					(output.status == "revoked" or output.status == "already_revoked")
						and output.revision > 1 and next.entries.len() == old.entries.len() + 1
							and next.entries.any(|row| row.value.note == output.lineage),
				)
			},
		},
	}).credentials(Credential.revoke_access(KeyFamilies.personal)).credential_revocation(
		Selectors.revoke_personal_input_lineage,
	)

	handle : InteractiveContext, RevokePersonalTypes.Input -> Tx(Output)
	handle = |context, input| {
		lineage = match (Credentials.personal.ref_from_str)(input.lineage) {
			Ok(value) => value
			Err(_) => return Tx.succeed({ status: "invalid", lineage: "", revision: 0 })
		}
		(Credentials.personal.revoke)(
			context,
			{
				lineage: lineage,
			},
		).and_then(
			|outcome| {
				result = match outcome {
					Revoked(value) => { status: "revoked", lineage: value.lineage.to_str(), revision: value.revision }
					AlreadyRevoked(value) => {
						status: "already_revoked",
						lineage: value.lineage.to_str(),
						revision: value.revision,
					}
				}
				Tx.create(Data.entries, { note: result.lineage }).map(|_| result)
			},
		)
	}
}
