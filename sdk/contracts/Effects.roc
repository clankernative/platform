import Tx

# A dependent sequence of admitted external effects. Database programs cannot be
# embedded here. The host journals each request and outcome outside transactions.
Effects(a) :: { program : Tx(a) }.{
	value : a -> Effects(a)
	value = |item| { program: Tx.succeed(item) }

	map : Effects(a), (a -> b) -> Effects(b)
	map = |effects, transform| { program: effects.program.map(transform) }

	and_then : Effects(a), (a -> Effects(b)) -> Effects(b)
	and_then = |effects, next| { program: effects.program.and_then(|item| next(item).program) }

	# Capability-pack and handler adapters are the only constructors/interpreters.
	capability : Str, Str -> Effects(Str)
	capability = |name, payload| { program: Tx.capability("external", name, payload) }

	from_host : Try(a, Str) -> Effects(a)
	from_host = |result| { program: Tx.from_host(result) }

	program : Effects(a) -> Tx(a)
	program = |effects| effects.program
}
