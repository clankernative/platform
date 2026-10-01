import pf.Api
import pf.Handler
import pf.InteractiveContext
import pf.Credential
import pf.Tx
import CreatePersonalTypes
import KeyFamilies
import Credentials
import Data
import Selectors

CreatePersonal :: [].{
	Output : { lineage : Str, version : Str, label : Str, expires_at : I64 }

	definition = Api.command({
		handler: Handler.interactive(handle),
		contract: {
			title: "Create a personal credential",
			usage: {
				purpose: "Create a personal credential for the confirmed human and its product registration.",
				use_when: ["The current human confirms a personal credential."],
				avoid_when: ["Choosing another human's subject."],
				preconditions: ["Exact security-origin confirmation and ready credential custody."],
				effects: ["Creates one private credential lineage and one public registration."],
				result: "Public identity and metadata, with no credential bytes.",
			},
			inputs: { label: "The exact label confirmed on the security origin." },
			outputs: {
				lineage: "Public family reference.",
				version: "Public version identity.",
				label: "Confirmed label.",
				expires_at: "Expiry in Unix seconds.",
			},
			example: |
				_,
			|
				Ok({
					input: { label: "Personal client" },
					output: {
						lineage: "cr1_personal_example",
						version: "example",
						label: "Personal client",
						expires_at: 3600,
					},
				}),
			errors: [],
			input_sources: |_| [],
			follow_ups: [],
			deprecated: Bool.False,
		},
		execution: Api.current_state([Api.create(Data.entries)]),
		verification: {
			input: |_snapshot, seed| Ok({ label: "Personal ${seed.to_str()}" }),
			check: |before, output, after| {
				old = Data.snapshot(before)?
				next = Data.snapshot(after)?
				Ok(
					next.entries.len()
						== old.entries.len() + 1
						and next.entries.keep_if(|row| row.value.note == output.lineage).len() == 1,
				)
			},
		},
	}).credentials(Credential.issue_access(KeyFamilies.personal)).credential_label(
		Selectors.create_personal_input_label,
	)

	handle : InteractiveContext, CreatePersonalTypes.Input -> Tx(Output)
	handle = |context, input| match Credential.Label.from_str(input.label) {
		Err(_) => Tx.succeed({ lineage: "", version: "", label: "", expires_at: 0 })
		Ok(label) => (Credentials.personal.issue)(
			context,
			{ label: label },
		).and_then(
			|issued| {
				lineage = issued.lineage().to_str()
				Tx.create(Data.entries, { note: lineage }).map(
					|_| {
						{
							lineage,
							version: issued.version().id(),
							label: issued.label(),
							expires_at: issued.expires_at(),
						}
					},
				)
			},
		)
	}
}
