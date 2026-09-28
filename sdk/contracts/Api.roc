import Context
import Tx
import Query
import Model
import Read
import Write
import Path
import Ref
import RowVersion
import Input
import Failure
import Handler

# Required definitions. Generated AppContract checks exact description records.
Api :: [].{
	Usage : {
		purpose : Str,
		use_when : List(Str),
		avoid_when : List(Str),
		preconditions : List(Str),
		effects : List(Str),
		result : Str,
	}

	Target : { operation : Str, input_type : Str, output_type : Str }

	SourceMetadata : { input : Str, source : Target, output : Str }

	InputSource :: { metadata : SourceMetadata }.{
		metadata : InputSource -> SourceMetadata
		metadata = |source| source.metadata
	}

	ModelField(model) :: { name : Str, witness : List(model) }.{
		name : ModelField(model) -> Str
		name = |field| field.name
	}

	FollowUp : { target : Target, when : Str }

	Field : { path : Str, description : Str }

	Entry : {
		target : Target,
		title : Str,
		usage : Usage,
		inputs : List(Field),
		outputs : List(Field),
		input_sources : List(SourceMetadata),
		follow_ups : List(FollowUp),
	}

	ExecutionMetadata : { internal : Bool, model : Str, id_field : Str, version_field : Str, effects : List(Effect) }

	CredentialAccess : { enabled : Bool, local_reads : List(Str) }

	Metadata : {
		intent : Entry,
		request_example : Str,
		response_example : Str,
		deprecated : Bool,
		export_version : U64,
		execution : ExecutionMetadata,
		credential_access : CredentialAccess,
		errors : List(Str),
		required_all_rows : List(Str),
	}

	Presentation : { stylesheet : Str, script : Str }

	Definition : {
		operations : List(Metadata),
		presentation : Presentation,
		identities : Str,
		invariants : List({ model : Str, description : Str }),
		domains : List({ name : Str, rules : { maximum_bytes : U64, nonblank : Bool, description : Str } }),
		errors : List(ErrorMetadata),
	}

	ErrorMetadata : {
		code : Str,
		description : Str,
		recovery : Str,
		operation : Target,
		additional_operations : List(Target),
	}

	ErrorExample : { operation : Target, input : (Str, U64 -> Try(Str, Str)) }

	ErrorDef : { description : Str, recovery : Str, verification : {} -> List(ErrorExample) }

	# Existing single-operation definitions normalize to the same checked shape.
	error : { description : Str, recovery : Str, verification : {} -> ErrorExample } -> ErrorDef
	error = |definition| {
		description: definition.description,
		recovery: definition.recovery,
		verification: |_| [(definition.verification)({})],
	}

	# Admission requires a nonempty list with one typed case for each operation
	# that declares this error; duplicate and undeclared targets are rejected.
	error_cases : ErrorDef -> ErrorDef
	error_cases = |definition| definition

	error_metadata : Str, ErrorDef -> Try(ErrorMetadata, Str)
	error_metadata = |code, definition| match (definition.verification)({}) {
		[] => Err("application error requires a verification case")
		[first, .. as rest] => Ok({
			code,
			description: definition.description,
			recovery: definition.recovery,
			operation: first.operation,
			additional_operations: rest.map(|scenario| scenario.operation),
		})
	}

	failed_command : Write(input, output), (Str, U64 -> Try(input, Str)) -> ErrorExample
	failed_command = |operation, generate| {
		codec = operation.input()
		{
			operation: write(operation),
			input: |snapshot, seed| {
				value = generate(snapshot, seed)?
				Ok(codec.encode(value))
			},
		}
	}

	failed_query : Read(input, output), (Str, U64 -> Try(input, Str)) -> ErrorExample
	failed_query = |operation, generate| {
		codec = operation.input()
		{
			operation: read(operation),
			input: |snapshot, seed| {
				value = generate(snapshot, seed)?
				Ok(codec.encode(value))
			},
		}
	}

	Effect : { kind : Str, model : Str, fields : List(Str), command : Str }

	Execution(input) : {
		internal : Bool,
		model : Str,
		id_field : Str,
		version_field : Str,
		effects : List(Effect),
		witness : (input -> input),
	}

	Contract(input, output, input_fields, output_fields) : {
		title : Str,
		usage : Usage,
		inputs : input_fields,
		outputs : output_fields,
		example : {} -> Try({ input : input, output : output }, Str),
		input_sources : Input(input) -> List(InputSource),
		follow_ups : List(FollowUp),
		deprecated : Bool,
		errors : List(Failure),
	}

	Verification(input, output) : {
		input : (Str, U64 -> Try(input, Str)),
		check : (Str, output, Str -> Try(Bool, Str)),
	}

	VerificationRequest : { action : Str, operation : Str, snapshot : Str, before : Str, output : Str, seed : U64 }

	ModelCheck(model) :: { witness : List(model), description : Str, check : Str -> Try(Bool, Str) }.{
		description : ModelCheck(model) -> Str
		description = |obligation| obligation.description

		check : ModelCheck(model) -> (Str -> Try(Bool, Str))
		check = |obligation| obligation.check
	}

	invariant : Model(model), Str, (Str -> Try(snapshot, Str)), (snapshot -> Bool) -> ModelCheck(model)
	invariant = |_model, description, decode, predicate| {
		witness: [],
		description,
		check: |raw| {
			value = decode(raw)?
			Ok(predicate(value))
		},

	}

	# Lower handler specifications to a private Tx callback before storing them.
	# Explicit codec witnesses retain the definition's input and output types.
	# Generated exported identities commit their layouts for native reflection.
	CommandDef(input, output, input_fields, output_fields) :: {
		input_witness : (input -> input),
		output_witness : (output -> output),
		handler : (Context, input -> Tx(output)),
		contract : Contract(input, output, input_fields, output_fields),
		execution : Execution(input),
		credential_access : CredentialAccess,
		verification : Verification(input, output),
		required_all_rows : List(Str),
		export_version : U64,
	}.{
		cross_app :
			CommandDef(input, output, input_fields, output_fields),
			{ version : U64 } ->
				CommandDef(input, output, input_fields, output_fields)
		cross_app = |definition, options| { ..definition, export_version: options.version }

		# Opt in to a bounded credential authority contract. Every local read
		# reached by this operation must be added with credential_read.
		credential_ready :
			CommandDef(input, output, input_fields, output_fields) ->
				CommandDef(input, output, input_fields, output_fields)
		credential_ready =
			|definition| { ..definition, credential_access: { ..definition.credential_access, enabled: Bool.True } }

		credential_read :
			CommandDef(input, output, input_fields, output_fields),
			Model(model) ->
				CommandDef(input, output, input_fields, output_fields)
		credential_read =
			|
				definition,
				model,
			|
				{
					..definition,
					credential_access: {
						enabled: Bool.True,
						local_reads: definition.credential_access.local_reads.append(model.name()),
					},

				}

		export_version : CommandDef(input, output, input_fields, output_fields) -> U64
		export_version = |definition| definition.export_version

		command_program : CommandDef(input, output, input_fields, output_fields) -> (Context, input -> Tx(output))
		command_program = |definition| definition.handler

		contract :
			CommandDef(input, output, input_fields, output_fields) ->
				Contract(input, output, input_fields, output_fields)
		contract = |definition| definition.contract

		execution : CommandDef(input, output, input_fields, output_fields) -> Execution(input)
		execution = |definition| definition.execution

		credential_access : CommandDef(input, output, input_fields, output_fields) -> CredentialAccess
		credential_access = |definition| definition.credential_access

		verification : CommandDef(input, output, input_fields, output_fields) -> Verification(input, output)
		verification = |definition| definition.verification

		# Refuse execution unless current policy allows every row; grant no access.
		require_all_rows :
			CommandDef(input, output, input_fields, output_fields),
			Model(model) -> CommandDef(input, output, input_fields, output_fields)
		require_all_rows = |definition, model| {
			..definition,
			required_all_rows: definition.required_all_rows.append(model.name()),
		}

		required_all_rows : CommandDef(input, output, input_fields, output_fields) -> List(Str)
		required_all_rows = |definition| definition.required_all_rows
	}

	QueryDef(input, output, input_fields, output_fields) :: {
		input_witness : (input -> input),
		output_witness : (output -> output),
		handler : (Context, input -> Tx(output)),
		contract : Contract(input, output, input_fields, output_fields),
		verification : Verification(input, output),
		credential_access : CredentialAccess,
		required_all_rows : List(Str),
		export_version : U64,
	}.{
		cross_app :
			QueryDef(input, output, input_fields, output_fields),
			{ version : U64 } ->
				QueryDef(input, output, input_fields, output_fields)
		cross_app = |definition, options| { ..definition, export_version: options.version }

		credential_ready :
			QueryDef(input, output, input_fields, output_fields) -> QueryDef(input, output, input_fields, output_fields)
		credential_ready =
			|definition| { ..definition, credential_access: { ..definition.credential_access, enabled: Bool.True } }

		credential_read :
			QueryDef(input, output, input_fields, output_fields),
			Model(model) ->
				QueryDef(input, output, input_fields, output_fields)
		credential_read =
			|
				definition,
				model,
			|
				{
					..definition,
					credential_access: {
						enabled: Bool.True,
						local_reads: definition.credential_access.local_reads.append(model.name()),
					},

				}

		export_version : QueryDef(input, output, input_fields, output_fields) -> U64
		export_version = |definition| definition.export_version

		query_program : QueryDef(input, output, input_fields, output_fields) -> (Context, input -> Tx(output))
		query_program = |definition| definition.handler

		contract :
			QueryDef(input, output, input_fields, output_fields) -> Contract(input, output, input_fields, output_fields)
		contract = |definition| definition.contract

		verification : QueryDef(input, output, input_fields, output_fields) -> Verification(input, output)
		verification = |definition| definition.verification

		credential_access : QueryDef(input, output, input_fields, output_fields) -> CredentialAccess
		credential_access = |definition| definition.credential_access

		# Refuse execution unless current policy allows every row; grant no access.
		require_all_rows :
			QueryDef(input, output, input_fields, output_fields),
			Model(model) -> QueryDef(input, output, input_fields, output_fields)
		require_all_rows = |definition, model| {
			..definition,
			required_all_rows: definition.required_all_rows.append(model.name()),
		}

		required_all_rows : QueryDef(input, output, input_fields, output_fields) -> List(Str)
		required_all_rows = |definition| definition.required_all_rows
	}

	command :
		{
			handler : Handler(input, Tx(output)),
			contract : Contract(input, output, input_fields, output_fields),
			execution : Execution(input),
			verification : Verification(input, output),
		} ->
			CommandDef(input, output, input_fields, output_fields)
	command = |definition| {
		handler = definition.handler
		{
			input_witness: |value| value,
			output_witness: |value| value,
			handler: |context, input| Handler.program(handler, context, input, |body| body),
			contract: definition.contract,
			execution: definition.execution,
			credential_access: { enabled: Bool.False, local_reads: [] },
			verification: definition.verification,
			required_all_rows: [],
			export_version: 0,
		}
	}

	query :
		{
			handler : Handler(input, Query(output)),
			contract : Contract(input, output, input_fields, output_fields),
			verification : Verification(input, output),
		} ->
			QueryDef(input, output, input_fields, output_fields)
	query = |definition| {
		handler = definition.handler
		{
			input_witness: |value| value,
			output_witness: |value| value,
			handler: |context, input| Handler.program(handler, context, input, |body| body.as_transaction()),
			contract: definition.contract,
			verification: definition.verification,
			credential_access: { enabled: Bool.False, local_reads: [] },
			required_all_rows: [],
			export_version: 0,
		}
	}

	read : Read(a, b) -> Target
	read = |read| { operation: read.name(), input_type: read.input().name(), output_type: read.output().name() }

	write : Write(a, b) -> Target
	write = |write| { operation: write.name(), input_type: write.input().name(), output_type: write.output().name() }

	create : Model(a) -> Effect
	create = |model| { kind: "create", model: model.name(), fields: [], command: "" }

	# Declares that an operation may mark rows of this model deleted.
	#
	# Separate from `update` and deliberately field-less: soft deletion changes
	# no field, so there is nothing to enumerate, and an operation authorised to
	# edit a title is not thereby authorised to make the row disappear from every
	# listing. Restoring is covered by the same declaration — an operation that
	# may delete may undo it.
	soft_delete : Model(a) -> Effect
	soft_delete = |model| { kind: "soft_delete", model: model.name(), fields: [], command: "" }

	field : Path(model, value) -> ModelField(model)
	field = |selector| { name: selector.name(), witness: [] }

	update : Model(a), List(ModelField(a)) -> Effect
	update =
		|
			model,
			fields,
		| { kind: "update", model: model.name(), fields: fields.map(|selector| selector.name()), command: "" }

	# Allows Tx.update only for rows whose native creation audit belongs to this invocation.
	# An edit's primary model remains bound to its exact input reference.
	update_created : Model(a), List(ModelField(a)) -> Effect
	update_created =
		|
			model,
			fields,
		| { kind: "update_created", model: model.name(), fields: fields.map(|selector| selector.name()), command: "" }

	read_source : Input(input), Path(input, value), Read(a, output), Path(output, value) -> InputSource
	read_source =
		|
			_codec,
			input,
			operation,
			output,
		| { metadata: { input: input.name(), source: read(operation), output: output.name() } }

	write_source : Input(input), Path(input, value), Write(a, output), Path(output, value) -> InputSource
	write_source =
		|
			_codec,
			input,
			operation,
			output,
		| { metadata: { input: input.name(), source: write(operation), output: output.name() } }

	# A request is accepted atomically with the caller's local changes.
	external : Str -> Effect
	external = |name| { kind: "external", model: "", fields: [], command: name }

	# A request is accepted atomically with the caller's local changes.
	request : Write(a, b) -> Effect
	request = |handle| { kind: "request", model: "", fields: [], command: handle.name() }

	# Internal commands have the same contract but no HTTP, form or MCP entrypoint.
	internal : Execution(input) -> Execution(input)
	internal = |execution| { ..execution, internal: Bool.True }

	current_state : List(Effect) -> Execution(input)
	current_state =
		|effects| { internal: Bool.False, model: "", id_field: "", version_field: "", effects, witness: |value| value }

	edit : Model(model), Path(input, Ref(model)), Path(input, RowVersion), List(Effect) -> Execution(input)
	edit =
		|
			model,
			id_field,
			version_field,
			effects,
		|
			{
				internal: Bool.False,
				model: model.name(),
				id_field: id_field.name(),
				version_field: version_field.name(),
				effects,
				witness: |value| value,
			}
}
