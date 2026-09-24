import Tx
import Model
import Ref
import Selection
import CollectionPage
import Failure

# Read-only plans compose without admitting arbitrary Tx values or mutation effects.
Query(a) :: { transaction : Tx(a) }.{
	# A result the query computed rather than read.
	#
	# The mirror of `Tx.succeed`, and needed for the same reason: not every
	# answer comes out of a row. An operation whose result is fixed by the
	# artifact -- a published catalog, a capability list -- is still a query,
	# still authorized, and still audited as a read of that operation by that
	# actor. Without this, such an operation would have to invent a table to
	# read, which would make an installation able to edit a fact about the
	# release.
	succeed : a -> Query(a)
	succeed = |value| { transaction: Tx.succeed(value) }

	from_try : Try(a, Failure) -> Query(a)
	from_try = |result| { transaction: Tx.from_try(result) }

	page : Selection(a) -> Query(CollectionPage(Model.Entity(a)))
	page = |selection| { transaction: Tx.page(selection) }

	# Collect the complete visible selection from its beginning. Predicate/order are
	# retained; cursor/page size are replaced. Exceeding 1..256 rows fails closed.
	collect : Selection(a), U64 -> Query(List(Model.Entity(a)))
	collect = |selection, maximum_rows| { transaction: Tx.collect(selection, maximum_rows) }

	# A missing row is data; multiple visible matches are a host failure.
	find : Selection(a) -> Query([Some(Model.Entity(a)), None])
	find = |selection| { transaction: Tx.find(selection) }

	get : Model(a), Ref(a) -> Query(Model.Entity(a))
	get = |model, id| { transaction: Tx.get(model, id) }

	# Transform the result without adding reads; and_then may schedule another read.
	map : Query(a), (a -> b) -> Query(b)
	map = |query, fn| { transaction: query.transaction.map(fn) }

	and_then : Query(a), (a -> Query(b)) -> Query(b)
	and_then = |query, next| { transaction: query.transaction.and_then(|value| (next(value)).transaction) }

	# Read plans may participate in commands; the reverse conversion is not exposed.
	as_transaction : Query(a) -> Tx(a)
	as_transaction = |query| query.transaction
}
