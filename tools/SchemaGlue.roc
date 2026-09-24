app [make_glue] { pf: platform glue }

import pf.Types exposing [Types]
import pf.File exposing [File]
import pf.TypeInfo exposing [TypeInfo]

Node : {
	kind : Str,
	name : Str,
	item : U64,
	fields : List({ name : Str, type_id : U64 }),
	args : List(U64),
	ret : U64,
	tags : List({ name : Str, payload : List(U64) }),
}

node : TypeInfo -> Node
node = |info| {
	empty : Node
	empty = { kind: "unsupported", name: "", item: 0, fields: [], args: [], ret: 0, tags: [] }
	match info.repr {
		RocRecord(record) => {
			..empty,
			kind: "record",
			name: record.name,
			fields: record
				.fields
				.keep_if(|field| !field.is_padding)
				.map(|field| { name: field.name, type_id: field.type_id }),
		}
		RocFunction(fn) => { ..empty, kind: "function", args: fn.args, ret: fn.ret }
		RocList(item) => { ..empty, kind: "list", item }
		RocBox(item) => { ..empty, kind: "box", item }
		RocTagUnion(union) => {
			..empty,
			kind: "union",
			name: union.name,
			tags: union.tags.map(|tag| { name: tag.name, payload: tag.payload }),
		}
		RocStr => { ..empty, kind: "text" }
		RocI64 => { ..empty, kind: "integer" }
		RocU8 => { ..empty, kind: "unsigned", name: "U8" }
		RocU16 => { ..empty, kind: "unsigned", name: "U16" }
		RocU32 => { ..empty, kind: "unsigned", name: "U32" }
		RocU64 => { ..empty, kind: "unsigned", name: "U64" }
		RocBool => { ..empty, kind: "boolean" }
		RocUnit => { ..empty, kind: "unit" }
		_ => empty
	}
}

make_glue : List(Types) -> Try(List(File), Str)
make_glue = |types| {
	documents = types.map(
		|table| {
			entries: table.provides_entries.map(|entry| { symbol: entry.ffi_symbol, type_id: entry.type_id }),
			types: table.types.map(node),
		},
	)
	Ok([{ name: "checked-types.json", content: Json.to_str(documents) }])
}
