import Wire
import Ref
import RowVersion

# Use generated Data model handles; define is restricted to generated codecs.
Model(a) :: { name : Str, prefix : Str, decode : Str -> Try(a, Str), encode : a -> Str }.{
	# Entity metadata describes an observed row, not proof of current authorization.
	Entity(a) : { id : Ref(a), version : RowVersion, created_at : I64, value : a }

	define : Str, Str, (Str -> Try(a, Str)), (a -> Str) -> Model(a)
	define = |name, prefix, decode, encode| { name, prefix, decode, encode }

	name : Model(a) -> Str
	name = |model| model.name

	encode : Model(a), a -> Str
	encode = |model, value| (model.encode)(value)

	decode_row : Model(a), Wire.Row -> Try(Entity(a), Str)
	decode_row = |model, row| {
		value = (model.decode)(row.data)?
		id = Ref.for_model(model.prefix, row.id).map_err(|_| "invalid_row_id")?
		version = RowVersion.from_i64(row.version).map_err(|_| "invalid_row_version")?
		Ok({ id, version, created_at: row.created_at, value })
	}
}
