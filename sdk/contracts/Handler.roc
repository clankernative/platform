import Context
import Observe
import Tx
import Effects

# One handler specification for commands and queries. Preparation cannot contain
# writes; the transactional body cannot execute preparation or external effects.
Handler(input, body) :: { prepare : Context, input -> Observe(body) }.{

	local : (Context, input -> body) -> Handler(input, body)
	local = |handle| { prepare: |context, input| Observe.value(handle(context, input)) }

	prepared : (Context, input -> Observe(facts)), (Context, input, facts -> body) -> Handler(input, body)
	prepared =
		|
			prepare,
			handle,
		| { prepare: |context, input| prepare(context, input).map(|facts| handle(context, input, facts)) }

	# Generated operation bindings alone lower the two phases to the host protocol.
	effects :
		(Context, input -> Observe(facts)),
		(Context, input, facts -> Tx(decision)),
		(decision -> Effects(result)),
		(Context, input, decision, result -> Tx(output)) ->
			Handler(input, Tx(output))
	effects = |observe, decide, deliver, complete| prepared(
		observe,
		|context, input, facts| {
			decide(context, input, facts).and_then(
				|decision| {
					continuation = Effects.program(deliver(decision)).and_then(
						|result|
							Tx.begin_completion(complete(context, input, decision, result)),
					)
					Tx.begin_effects(continuation)
				},
			)
		},
	)

	# Generated operation bindings alone lower the two phases to the host protocol.
	program : Handler(input, body), Context, input, (body -> Tx(output)) -> Tx(output)
	program = |handler, context, input, transaction|
		(handler.prepare)(context, input).program()
			.and_then(|body| Tx.begin_decision(transaction(body)))
}
