import Observe
import Effects
import Api
import Resource
import Context

# Roc composes the complete request plan and owns business state. This pack only
# binds an admitted Resource grant to a sealed Freetool executor service.
FreetoolExecutor :: [].{
	Executor := { resource : Resource }

	fingerprint_observation = Api.external("freetool.fingerprint.v1")

	register_effect = Api.external("freetool.register.v1")

	execute_effect = Api.external("freetool.execute.v1")

	status_observation = Api.external("freetool.status.v1")

	result_observation = Api.external("freetool.result_page.v1")

	Run : {
		resource_id : Str,
		configuration_id : Str,
		immutable_version : U64,
		configuration_digest : Str,
		run_id : Str,
		arguments_digest : Str,
	}

	Header := { name : Str, value : Str }

	SqlValue := [Null, Boolean(Bool), Integer(I64), Decimal(Str), Text(Str), Bytes(List(U8)), Date(Str), Timestamp(Str)]

	Plan := [
		Http({ method : Str, url : Str, headers : List(Header), body : Str }),
		Postgres({ resource_binding_id : Str, statement : Str, parameters : List(SqlValue) }),
	]

	Receipt : {
		state : Str,
		code : Str,
		result_id : Str,
		digest : Str,
		byte_count : U64,
	}

	ResultPage : {
		result_id : Str,
		digest : Str,
		total_bytes : U64,
		offset : U64,
		bytes : List(U8),
	}

	fingerprint : Resource, Str, Str -> Observe({ configuration_digest : Str, arguments_digest : Str })
	fingerprint = |resource, configuration_document, arguments_document|
		Observe.capability(
			"freetool.fingerprint.v1",
			Json.to_str({ configuration_document, arguments_document, handle: Resource.token(resource) }),
		)
			.and_then(
				|raw| {
					parsed : Try({ configuration_digest : Str, arguments_digest : Str }, _)
					parsed = Json.parse(raw)
					Observe.from_host(parsed.map_err(|_| "invalid_freetool_fingerprint"))
				},
			)

	bind : Context -> Observe(Executor)
	bind = |context| Resource.bind(context, "freetool_executor").map(
		|resource| { resource: resource },
	)

	register : Executor, Run, Plan -> Effects(Receipt)
	register = |executor, run, plan| Effects.capability(
		"freetool.register.v1",
		"{\"run\":${Json.to_str(run)},\"plan\":${encode_plan(plan)},\"handle\":${
			Json.to_str(
				Resource.token(executor.resource),
			)
		}}",
	)
		.and_then(
			|raw| {
				parsed : Try(Receipt, _)
				parsed = Json.parse(raw)
				Effects.from_host(parsed.map_err(|_| "invalid_freetool_receipt"))
			},
		)

	execute : Executor, Run -> Effects(Receipt)
	execute = |executor, run| Effects.capability(
		"freetool.execute.v1",
		Json.to_str({ run, handle: Resource.token(executor.resource) }),
	)
		.and_then(
			|raw| {
				parsed : Try(Receipt, _)
				parsed = Json.parse(raw)
				Effects.from_host(parsed.map_err(|_| "invalid_freetool_receipt"))
			},
		)

	status : Executor, Run -> Observe(Receipt)
	status = |executor, run| Observe.capability(
		"freetool.status.v1",
		Json.to_str({ run, handle: Resource.token(executor.resource) }),
	)
		.and_then(
			|raw| {
				parsed : Try(Receipt, _)
				parsed = Json.parse(raw)
				Observe.from_host(parsed.map_err(|_| "invalid_freetool_status"))
			},
		)

	result_page : Executor, Run, U64, U32 -> Observe(ResultPage)
	result_page = |executor, run, offset, limit| Observe.capability(
		"freetool.result_page.v1",
		Json.to_str({ run, offset, limit, handle: Resource.token(executor.resource) }),
	)
		.and_then(
			|raw| {
				parsed : Try(ResultPage, _)
				parsed = Json.parse(raw)
				Observe.from_host(parsed.map_err(|_| "invalid_freetool_result_page"))
			},
		)

	# Encode each closed variant separately; only encoded JSON is interpolated.
	encode_plan : Plan -> Str
	encode_plan = |plan|
		match plan {
			Http(request) => Json.to_str({
				kind: "http",
				method: request.method,
				url: request.url,
				headers: List.map(request.headers, |header| [header.name, header.value]),
				body: Str.to_utf8(request.body),
			})
			Postgres(query) => {
				parameters = Str.join_with(List.map(query.parameters, encode_sql_value), ",")
				"{\"kind\":\"postgres\",\"resource_binding_id\":${
					Json.to_str(
						query.resource_binding_id,
					)
				},\"statement\":${
					Json.to_str(
						query.statement,
					)
				},\"parameters\":[${parameters}]}"
			}
		}

	encode_sql_value : SqlValue -> Str
	encode_sql_value = |value|
		match value {
			Null => Json.to_str({ type: "null" })
			Boolean(boolean) => Json.to_str({ type: "boolean", value: boolean })
			Integer(integer) => Json.to_str({ type: "integer", value: integer })
			Decimal(decimal) => Json.to_str({ type: "decimal", value: decimal })
			Text(text) => Json.to_str({ type: "text", value: text })
			Bytes(bytes) => Json.to_str({ type: "bytes", value: bytes })
			Date(date) => Json.to_str({ type: "date", value: date })
			Timestamp(timestamp) => Json.to_str({ type: "timestamp", value: timestamp })
		}
}
