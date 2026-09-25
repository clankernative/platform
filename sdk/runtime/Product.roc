import Wire
import Tx
import Operation
import Property
import PageBinding
import CommandBinding
import QueryBinding
import ScheduleBinding
import IngressBinding
import RedirectBinding

Product :: [].{
	Contract : {
		namespace : Str,
		commands : List(CommandBinding),
		queries : List(QueryBinding),
		properties : List(Property),
		pages : List(PageBinding),
		schedules : List(ScheduleBinding),
		ingress : List(IngressBinding),
		redirects : List(RedirectBinding),
	}

	step : Contract, Str -> Str
	step = |contract, raw| {
		operations =
			[contract.commands.map(CommandBinding.operation), contract.queries.map(QueryBinding.operation)].join()
		if raw == "manifest" {
			return Json.to_str({
				namespace: contract.namespace,
				operations: operations.map(Operation.metadata),
				properties: contract.properties.map(Property.name),
				pages: contract.pages.map(PageBinding.metadata),
				schedules: contract.schedules.map(ScheduleBinding.metadata),
				ingress: contract.ingress.map(IngressBinding.metadata),
				redirects: contract.redirects.map(RedirectBinding.metadata),
			})
		}

		parsed : Try(Wire.Request, _)
		parsed = Json.parse(raw)
		match parsed {
			Err(_) => Json.to_str(
				{ kind: "failed", instruction: Wire.empty, result: "", error: "invalid_protocol", consumed: 0.U64 },
			)
			Ok(request) => {
				if request.operation == "$properties" {
					checks = contract.properties.map(|property| property.evaluate(request.input))
					Json.to_str({
						kind: "done",
						instruction: Wire.empty,
						result: Json.to_str(checks),
						error: "",
						consumed: 0.U64,
					})
				} else {
					operation = operations.find_first(|op| op.name() == request.operation)
					result = match operation {
						Err(_) => match contract.pages.find_first(|page| page.route() == request.operation) {
							Ok(page) => {
								page_metadata = page.metadata()
								query = operations.find_first(
									|op| {
										metadata = op.metadata()
										metadata.name
											== page_metadata.operation
											and metadata.kind
												== "query"
												and metadata.input_type
													== page_metadata.input_type
													and metadata.output_type == page_metadata.output_type
									},
								)
								match query {
									Ok(op) => op.execute(request.context, request.input)
									Err(_) => Tx.host_reject("unknown_page_query")
								}
							}

							Err(_) => Tx.host_reject("unknown_operation")
						}
						Ok(op) => op.execute(request.context, request.input)
					}
					requires_commit = match operation {
						Ok(op) => op.metadata().kind == "command"

						Err(_) => Bool.False
					}
					guarded = if requires_commit {
						result.guard_commit()
					} else {
						result
					}

					response : Wire.Response
					response = match guarded.evaluate(request.observations) {
						Done(value) => {
							kind: "done",
							instruction: Wire.empty,
							result: value.value,
							error: "",
							consumed: value.consumed,
						}
						Failed(error) => {
							kind: "failed",
							instruction: Wire.empty,
							result: "",
							error: error.error,
							consumed: error.consumed,
						}
						Pending(next) => {
							kind: "pending",
							instruction: next.instruction,
							result: "",
							error: "",
							consumed: next.consumed,
						}
					}
					Json.to_str(response)
				}
			}
		}
	}
}
