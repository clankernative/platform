import Context
import Operation
import Query
import Read
import Tx

QueryBinding :: { value : Operation }.{
	define : Read(a, b), (Context, a -> Query(b)) -> QueryBinding
	define = |query, handle| { value: Operation.query(query.name(), query.input(), handle, query.output()) }

	bind : Read(a, b), (Context, a -> Tx(b)) -> QueryBinding
	bind = |query, handler| { value: Operation.prepared_query(query.name(), query.input(), handler, query.output()) }

	operation : QueryBinding -> Operation
	operation = |binding| binding.value
}
