import Observe
import Resource
import Context

# Typed reads from an immutable Carta capture: an explicitly seeded synthetic
# snapshot, or a live capture the host collects completely when the bound resource
# has a live connection. Record reads never reach the provider.
# Provider arrays are transported as individual records, preserving their parent
# external IDs. Applications own validation, import decisions and calculations.
Carta :: [].{
	OptionalText : [Some(Str), None]

	Snapshot : {
		id : Str,
		issuer_id : Str,
		record_count : U64,
		stakeholder_count : U64,
		grant_count : U64,
		vesting_event_count : U64,
		exercise_count : U64,
		source_profile : Str,
	}

	Stakeholder : {
		id : Str,
		issuer_id : Str,
		full_name : Str,
		email : Str,
		employee_id : OptionalText,
		relationship : Str,
		group : OptionalText,
		entity_type : Str,
		address_country : OptionalText,
	}

	Grant : {
		id : Str,
		issuer_id : Str,
		stakeholder_id : Str,
		equity_incentive_plan_name : Str,
		issue_date : Str,
		vesting_start_date : Str,
		board_approval_date : Str,
		stakeholder_acceptance_date : OptionalText,
		grant_expiration_date : Str,
		iso_nso_split : Bool,
		stock_option_type : Str,
		quantity : Str,
		outstanding_quantity : Str,
		vested_quantity : Str,
		exercised_quantity : Str,
		exercise_price_currency : Str,
		exercise_price_amount : Str,
		security_label : Str,
		early_exercisable : Bool,
		vesting_schedule_name : Str,
		vesting_schedule_last_modified_date : Str,
		vesting_schedule_start_date : Str,
		vesting_schedule_end_date : Str,
		last_modified_datetime : Str,
	}

	VestingEvent : {
		id : Str,
		grant_id : Str,
		vest_date : Str,
		quantity : Str,
		iso_quantity : Str,
		nso_quantity : Str,
		performance_condition : Bool,
		vested : Bool,
		max_quantity : Str,
		target_quantity : Str,
		vested_quantity : OptionalText,
	}

	Exercise : {
		grant_id : Str,
		exercise_id : Str,
		quantity : Str,
		fair_market_value_as_of_date : OptionalText,
		exercise_date : Str,
		status : Str,
		certificate_id : Str,
		exercise_type : Str,
		qualified : Bool,
	}

	ReadResult : [Stakeholder(Stakeholder), Grant(Grant), VestingEvent(VestingEvent), Exercise(Exercise), Done]

	Record : [Stakeholder(Stakeholder), Grant(Grant), VestingEvent(VestingEvent), Exercise(Exercise)]

	# A complete capture held in this application's own database until it calls
	# `release`. Any later invocation can read its records; nothing expires it.
	Delivery : {
		id : Str,
		issuer_id : Str,
		record_count : U64,
		stakeholder_count : U64,
		grant_count : U64,
		vesting_event_count : U64,
		exercise_count : U64,
		source_profile : Str,
	}

	# Records from `from` in provider order: at most the requested limit (1 to
	# 256, one `Tx.create_many` batch) and possibly fewer. `next` is the record to
	# read next; `done` once it is the record count.
	Records : { records : List(Record), next : U64, done : Bool }

	deliver : Context -> Observe(Delivery)
	deliver = |context| Resource.bind(context, "carta").and_then(deliver_with)

	deliver_with : Resource -> Observe(Delivery)
	deliver_with = |resource| Observe.capability("carta.snapshot.v2", Json.to_str({ handle: Resource.token(resource) }))
		.and_then(
			|raw| {
				parsed : Try(Delivery, _)
				parsed = Json.parse(raw)
				Observe.from_host(parsed.map_err(|_| "invalid_carta_delivery"))
			},
		)

	read : Context, Str, U64, U64 -> Observe(Records)
	read = |context, capture_id, from, limit| Resource.bind(context, "carta").and_then(
		|resource| read_with(resource, capture_id, from, limit),
	)

	read_with : Resource, Str, U64, U64 -> Observe(Records)
	read_with = |resource, capture_id, from, limit| Observe.capability(
		"carta.records.v2",
		Json.to_str({ handle: Resource.token(resource), capture_id, from, limit }),
	).and_then(
		|raw| {
			parsed : Try(Records, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_carta_records"))
		},
	)

	# Release a held capture no later read needs, while preparing. Idempotent;
	# `released` is false when nothing was held under that id.
	release : Context, Str -> Observe({ released : Bool })
	release =
		|context, capture_id| Resource.bind(context, "carta").and_then(|resource| release_with(resource, capture_id))

	release_with : Resource, Str -> Observe({ released : Bool })
	release_with = |resource, capture_id| Observe.capability(
		"carta.release.v2",
		Json.to_str({ handle: Resource.token(resource), capture_id }),
	).and_then(
		|raw| {
			parsed : Try({ released : Bool }, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_carta_release"))
		},
	)

	begin : Context -> Observe(Snapshot)
	begin = |context| Resource.bind(context, "carta").and_then(begin_with)

	begin_with : Resource -> Observe(Snapshot)
	begin_with = |resource| Observe.capability("carta.snapshot.v1", Json.to_str({ handle: Resource.token(resource) }))
		.and_then(
			|raw| {
				parsed : Try(Snapshot, _)
				parsed = Json.parse(raw)
				Observe.from_host(parsed.map_err(|_| "invalid_carta_snapshot"))
			},
		)

	next : Context, Str, U64 -> Observe(ReadResult)
	next =
		|
			context,
			snapshot_id,
			cursor,
		| Resource.bind(context, "carta").and_then(|resource| next_with(resource, snapshot_id, cursor))

	next_with : Resource, Str, U64 -> Observe(ReadResult)
	next_with =
		|
			resource,
			snapshot_id,
			cursor,
		| Observe.capability("carta.record.v1", Json.to_str({ handle: Resource.token(resource), snapshot_id, cursor }))
			.and_then(
				|raw| {
					parsed : Try({ kind : Str, data : Str }, _)
					parsed = Json.parse(raw)
					Observe.from_host(parsed.map_err(|_| "invalid_carta_record"))
				},
			)
			.and_then(
				|envelope| match envelope.kind {
					"stakeholder" => {
						parsed : Try(Stakeholder, _)
						parsed = Json.parse(envelope.data)
						Observe.from_host(parsed.map_err(|_| "invalid_carta_stakeholder"))
							.map(|value| Stakeholder(value))
					}
					"grant" => {
						parsed : Try(Grant, _)
						parsed = Json.parse(envelope.data)
						Observe.from_host(parsed.map_err(|_| "invalid_carta_grant")).map(|value| Grant(value))
					}
					"vesting_event" => {
						parsed : Try(VestingEvent, _)
						parsed = Json.parse(envelope.data)
						Observe.from_host(parsed.map_err(|_| "invalid_carta_vesting_event"))
							.map(|value| VestingEvent(value))
					}
					"exercise" => {
						parsed : Try(Exercise, _)
						parsed = Json.parse(envelope.data)
						Observe.from_host(parsed.map_err(|_| "invalid_carta_exercise")).map(|value| Exercise(value))
					}
					"done" => Observe.value(Done)
					_ => Observe.from_host(Err("invalid_carta_record_kind"))
				},
			)
}
