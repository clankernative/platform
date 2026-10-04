import pf.Api
import pf.Handler
import pf.Context
import pf.Tx
import SetOwnerTypes
import Ownership
import Data
import Selectors
import Commands
import Errors

SetOwner :: [].{
	definition = Api.command({
		handler: Handler.local(handle),
		contract,
		execution: Api.current_state(
			[Api.create(Data.ownerships), Api.update(Data.ownerships, [Api.field(Selectors.ownerships_active)])],
		),
		verification: { input: verify_input, check: verify_result },
	})

	handle : Context, SetOwnerTypes.Input -> Tx(SetOwnerTypes.Output)
	handle = |_context, input| {
		if !Ownership.valid_app_id(input.app_id) or !Ownership.valid_principal(input.principal) {
			Tx.reject(Errors.invalid_owner)
		} else {
			Tx.find(Ownership.selection(input.app_id, input.principal)).and_then(
				|found| {
					value = { app_id: input.app_id, principal: input.principal, active: input.active }
					write = match found {
						None => Tx.create(Data.ownerships, value)
						Some(row) => Tx.update(Data.ownerships, row, value)
					}
					write.map(|_| value)
				},
			)
		}
	}

	contract = {
		title: "Set direct app ownership",
		usage: {
			purpose: "Grant or revoke direct ownership under an operator-only instance policy.",
			use_when: ["An authorized ownership administrator changes app ownership."],
			avoid_when: ["Letting an app grant ownership to its caller."],
			preconditions: ["The instance grants ownership administration to this actor."],
			effects: ["Updates one unique app/principal assignment."],
			result: "The current direct ownership assignment.",
		},
		inputs: {
			app_id: "Business app identifier.",
			principal: "Verified human principal to manage.",
			active: "Grant when true; revoke when false.",
		},
		outputs: { app_id: "Business app identifier.", principal: "Managed principal.", active: "Current assignment." },
		example,
		input_sources: |_| [],
		follow_ups: [],
		deprecated: Bool.False,
		errors: [Errors.invalid_owner],
	}

	example : {} -> Try({ input : SetOwnerTypes.Input, output : SetOwnerTypes.Output }, Str)
	example =
		|
			_,
		|
			Ok({
				input: { app_id: "demo", principal: "alice", active: Bool.True },
				output: { app_id: "demo", principal: "alice", active: Bool.True },
			})

	verify_input : Str, U64 -> Try(SetOwnerTypes.Input, Str)
	verify_input = |_snapshot, seed| Ok({ app_id: "demo", principal: "alice", active: seed % 2 == 0 })

	verify_result : Str, SetOwnerTypes.Output, Str -> Try(Bool, Str)
	verify_result = |_before, output, after| {
		state = Data.snapshot(after)?
		Ok(
			state
				.ownerships
				.keep_if(|row| row.value.app_id == output.app_id and row.value.principal == output.principal)
				.len()
				== 1
				and state
					.ownerships
					.any(
						|
							row,
						|
							row.value.app_id
								== output.app_id
								and row.value.principal == output.principal and row.value.active == output.active,
					),
		)
	}

	invalid_owner = Api.error({
		description: "The app identifier or managed principal is invalid.",
		recovery: "Use a valid app slug and a nonblank canonical principal.",
		verification: |
			_,
		|
			Api.failed_command(
				Commands.set_owner,
				|_snapshot, _seed| Ok({ app_id: "", principal: "alice", active: Bool.True }),
			),
	})
}
