import Query
import Tx
import Failure

# Read-only preparation. The host records observations before opening the decision
# transaction. A prepared lookup is not an authoritative transaction observation.
Observe(a) :: { program : Tx(a) }.{
	value : a -> Observe(a)
	value = |item| { program: Tx.succeed(item) }

	from_try : Try(a, Failure) -> Observe(a)
	from_try = |result| { program: Tx.from_try(result) }

	local : Query(a) -> Observe(a)
	local = |query| { program: query.as_transaction() }

	map : Observe(a), (a -> b) -> Observe(b)
	map = |observation, transform| { program: observation.program.map(transform) }

	and_then : Observe(a), (a -> Observe(b)) -> Observe(b)
	and_then = |observation, next| { program: observation.program.and_then(|item| next(item).program) }

	# Only trusted capability and handler adapters can cross this representation.
	capability : Str, Str -> Observe(Str)
	capability = |name, payload| { program: Tx.capability("observe", name, payload) }

	from_host : Try(a, Str) -> Observe(a)
	from_host = |result| { program: Tx.from_host(result) }

	# Only trusted capability and handler adapters can cross this representation.
	program : Observe(a) -> Tx(a)
	program = |observation| observation.program
}
