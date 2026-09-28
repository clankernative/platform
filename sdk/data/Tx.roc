import Wire
import Model
import Ref
import Selection
import CollectionPage
import Cursor
import PageSize
import Failure

# A pure transaction plan. The host executes every effect in one SQLite transaction,
# enforcing current policy and replaying the recorded observations into this plan.
Tx(a) :: { resume : List(Wire.Observation), U64 -> Step(a) }.{
	Step(a) : [
		Done({ value : a, consumed : U64 }),
		Failed({ error : Str, consumed : U64 }),
		Pending({ instruction : Wire.Instruction, consumed : U64 }),
	]

	RowPage : { items : List(Wire.Row), has_more : Bool, next_after : Str }

	succeed : a -> Tx(a)
	succeed = |value| { resume: |_observations, consumed| Done({ value, consumed }) }

	reject : Failure -> Tx(a)
	reject = |failure| host_reject(failure.code())

	from_try : Try(a, Failure) -> Tx(a)
	from_try = |result| match result {
		Ok(value) => succeed(value)
		Err(error) => reject(error)
	}

	# Only trusted SDK adapters may propagate host failures across this boundary.
	host_reject : Str -> Tx(a)
	host_reject = |error| { resume: |_observations, consumed| Failed({ error, consumed }) }

	from_host : Try(a, Str) -> Tx(a)
	from_host = |result| match result {
		Ok(value) => succeed(value)
		Err(error) => host_reject(error)
	}

	# Continue after a result; failure short-circuits and pending effects resume later.
	and_then : Tx(a), (a -> Tx(b)) -> Tx(b)
	and_then = |first, next| {
		resume: |observations, consumed| {
			match (first.resume)(observations, consumed) {
				Done(result) => ((next(result.value)).resume)(observations, result.consumed)
				Failed(error) => Failed(error)
				Pending(request) => Pending(request)
			}
		},
	}

	map : Tx(a), (a -> b) -> Tx(b)
	map = |first, fn| and_then(first, |value| succeed(fn(value)))

	# The generated dispatcher adds this final guard; apps need not remember it.
	guard_commit : Tx(a) -> Tx(a)
	guard_commit = |program| program.and_then(|value| request({ ..Wire.empty, kind: "commit" }).map(|_| value))

	# Host phase boundary. No application transaction remains open during Prepare.
	begin_decision : Tx(a) -> Tx(a)
	begin_decision = |program| request({ ..Wire.empty, kind: "decide" }).and_then(|_| program)

	begin_effects : Tx(a) -> Tx(a)
	begin_effects = |program| request({ ..Wire.empty, kind: "effects" }).and_then(|_| program)

	begin_completion : Tx(a) -> Tx(a)
	begin_completion = |program| request({ ..Wire.empty, kind: "complete" }).and_then(|_| program)

	capability : Str, Str, Str -> Tx(Str)
	capability = |kind, name, payload| request({ ..Wire.empty, kind, model: name, data: payload })

	# Generated command handles supply the operation and its exact codecs.
	invoke_command : Str, Str, Str, Model(model), Model.Entity(model), Str -> Tx({})
	invoke_command =
		|
			command,
			input_type,
			output_type,
			model,
			target,
			payload,
		|
			request({
				..Wire.empty,
				kind: "request",
				model: model.name(),
				id: target.id.to_str(),
				expected_version: target.version.to_i64(),
				data: Json.to_str({ command, input_type, output_type, payload }),
			})
				.map(|_| {})

	invoke_deferral : Str, Str, Str, Model(model), Model.Entity(model), Str, I64 -> Tx({})
	invoke_deferral =
		|
			command,
			input_type,
			output_type,
			model,
			target,
			payload,
			due,
		|
			# The public signature stays I64 to match Context.now. Encoding this record with an
			# I64 field segfaults the pinned compiler's `roc build` (September 12 nightly) although
			# `roc check` passes, so the due time is converted first. The host rejects negative dues.
			match due.to_u64_try() {
				Err(_) => host_reject("invalid_deferral_due")
				Ok(timestamp) =>
					request({
						..Wire.empty,
						kind: "defer",
						model: model.name(),
						id: target.id.to_str(),
						data: Json.to_str({ command, input_type, output_type, payload, due: timestamp }),
					})
						.map(|_| {})
			}

	invoke_deferral_for : Str, Str, Str, Model(model), Model.Entity(model), Str, I64 -> Tx({})
	invoke_deferral_for =
		|
			command,
			input_type,
			output_type,
			model,
			target,
			payload,
			delay,
		|
			# Same boundary as invoke_deferral: passing a U64 from app code through Write into this
			# sealed method segfaults the pinned compiler's `roc build` while `roc check` passes.
			# Accept I64 and convert here; the host computes due = Context.now + delay and bounds it.
			match delay.to_u64_try() {
				Err(_) => host_reject("invalid_deferral_delay")
				Ok(seconds) =>
					request({
						..Wire.empty,
						kind: "defer",
						model: model.name(),
						id: target.id.to_str(),
						data: Json.to_str({ command, input_type, output_type, payload, delay: seconds }),
					})
						.map(|_| {})
			}

	get : Model(a), Ref(a) -> Tx(Model.Entity(a))
	get = |model, id| request({ ..Wire.empty, kind: "get", model: model.name(), id: id.to_str() })
		.and_then(|raw| decode_entity(model, raw))

	# Complete bounded collection in this transaction. Never expose a truncated
	# prefix as a complete policy set. Selection predicates and ordering survive;
	# collection always begins at the start, independently of pagination fields.
	collect : Selection(a), U64 -> Tx(List(Model.Entity(a)))
	collect = |selection, maximum_rows| {
		if maximum_rows == 0 or maximum_rows > 256 {
			host_reject("invalid_collection_bound")
		} else {
			collect_page(selection.paginate(Cursor.start, PageSize.maximum), maximum_rows)
		}
	}

	# Pagination never narrows the host's visible-row cardinality check.
	find : Selection(a) -> Tx([Some(Model.Entity(a)), None])
	find = |selection| {
		model = selection.model()
		request({ ..Wire.empty, kind: "find", model: model.name(), data: selection.encode() })
			.and_then(
				|raw| {
					parsed : Try(List(Wire.Row), _)
					parsed = Json.parse(raw)
					match parsed {
						Ok([]) => succeed(None)
						Ok([row]) => from_host(model.decode_row(row)).map(|entity| Some(entity))
						_ => host_reject("invalid_storage_response")
					}
				},
			)
	}

	create : Model(a), a -> Tx(Model.Entity(a))
	create = |model, value| request({ ..Wire.empty, kind: "create", model: model.name(), data: model.encode(value) })
		.and_then(|raw| decode_entity(model, raw))

	# Mark a row deleted without removing it.
	#
	# **Nothing in this platform removes a row.** There is no hard delete, and
	# adding one is not an oversight waiting to be corrected: an application that
	# can destroy a record can destroy it by accident, and the recovery is an
	# audit log or last night's backup. Physical removal is an operator decision
	# expressed as an instance retention policy, never something application code
	# can reach.
	#
	# A deleted row leaves every read that does not name it: `get` by id reports
	# it missing, `update` cannot edit it, and no selection returns it. A trash
	# view asks for it with `Selection.only_deleted`, and `restore` brings it
	# back — same id, same values, next version.
	#
	# Carries no value, so deleting cannot smuggle an edit. Refused if the row is
	# already deleted, because that means the caller is working from a stale view.
	soft_delete : Model(a), Model.Entity(a) -> Tx(Model.Entity(a))
	soft_delete = |model, row| request({
		..Wire.empty,
		kind: "soft_delete",
		model: model.name(),
		id: row.id.to_str(),
		expected_version: row.version.to_i64(),
	})
		.and_then(|raw| decode_entity(model, raw))

	# Bring a soft-deleted row back. Refused if the row is not deleted.
	restore : Model(a), Model.Entity(a) -> Tx(Model.Entity(a))
	restore = |model, row| request({
		..Wire.empty,
		kind: "restore",
		model: model.name(),
		id: row.id.to_str(),
		expected_version: row.version.to_i64(),
	})
		.and_then(|raw| decode_entity(model, raw))

	# Compare against the observed row revision. A caller's edit precondition is a
	# separate host-policy check; transaction CAS alone does not detect stale forms.
	update : Model(a), Model.Entity(a), a -> Tx(Model.Entity(a))
	update =
		|
			model,
			row,
			value,
		|
			request({
				..Wire.empty,
				kind: "update",
				model: model.name(),
				id: row.id.to_str(),
				expected_version: row.version.to_i64(),
				data: model.encode(value),
			})
				.and_then(|raw| decode_entity(model, raw))

	page : Selection(a) -> Tx(CollectionPage(Model.Entity(a)))
	page = |selection| {
		model = selection.model()
		bounds = selection.bounds()
		if bounds.limit.to_i64() < 1 or bounds.limit.to_i64() > 100 {
			host_reject("invalid_page_bounds")
		} else {
			instruction = if bounds.legacy {
				{
					..Wire.empty,
					kind: "page",
					model: model.name(),
					filter_field: bounds.field,
					filter_value: bounds.value,
					after: bounds.after.to_str(),
					limit: bounds.limit.to_i64(),
				}
			} else {
				{ ..Wire.empty, kind: "select_page", model: model.name(), data: selection.encode() }
			}
			request(instruction)
				.and_then(
					|raw| {
						parsed : Try(RowPage, _)
						parsed = Json.parse(raw)
						match parsed {
							Err(_) => host_reject("invalid_storage_response")
							Ok(page_data) => {
								decoded = page_data.items.map_try(|row| model.decode_row(row))
								from_host(decoded).and_then(
									|items| {
										next =
											Cursor.from_str(page_data.next_after).map_err(|_| "invalid_storage_cursor")
										from_host(next)
											.and_then(
												|
													cursor,
												|
													from_host(
														CollectionPage.from_parts(items, page_data.has_more, cursor),
													),
											)
									},
								)
							}
						}
					},
				)
		}
	}

	# Interpreter boundary used by generated dispatch and replay, not ambient execution.
	evaluate : Tx(a), List(Wire.Observation) -> Step(a)
	evaluate = |program, observations| (program.resume)(observations, 0)
}

collect_page : Selection(a), U64 -> Tx(List(Model.Entity(a)))
collect_page = |selection, remaining| Tx.page(selection).and_then(
	|current| {
		items = current.items()
		if items.len() > remaining or (current.has_more() and items.len() == remaining) {
			Tx.host_reject("collection_limit_exceeded")
		} else if current.has_more() {
			collect_page(selection.paginate(current.next_after(), PageSize.maximum), remaining - items.len())
				.map(|tail| items.concat(tail))
		} else {
			Tx.succeed(items)
		}
	},
)

request : Wire.Instruction -> Tx(Str)
request = |instruction| {
	resume: |observations, consumed| {
		match observations.get(consumed) {
			Err(OutOfBounds) => Pending({ instruction, consumed })
			Ok(observation) => {
				if observation.instruction != instruction {
					Failed({ error: "replay_mismatch", consumed })
				} else if observation.error != "" {
					Failed({ error: observation.error, consumed: consumed + 1 })
				} else {
					Done({ value: observation.result, consumed: consumed + 1 })
				}
			}
		}
	},
}

decode_entity : Model(a), Str -> Tx(Model.Entity(a))
decode_entity = |model, raw| {

	parsed : Try(Wire.Row, _)
	parsed = Json.parse(raw)
	match parsed {
		Ok(row) => Tx.from_host(model.decode_row(row))
		Err(_) => Tx.host_reject("invalid_storage_response")
	}
}
