import pf.Selection
import pf.Predicate
import Data

Ownership :: [].{
	selection = |app_id, principal| Selection.filter(
		Data.ownerships,
		Predicate.all([
			Data.ownerships_app_id_equal(app_id),
			Data.ownerships_principal_equal(principal),
		]),
	)

	valid_app_id : Str -> Bool
	valid_app_id = |value| {
		bytes = value.to_utf8()
		alphanumeric = |byte| (byte >= 97 and byte <= 122) or (byte >= 48 and byte <= 57)
		!bytes.is_empty() and bytes.len() <= 63 and bytes.all(|byte| alphanumeric(byte) or byte == 45)
			and (match bytes.first() {
				Ok(byte) => alphanumeric(byte)
				Err(_) => Bool.False
			})
				and (match bytes.last() {
					Ok(byte) => alphanumeric(byte)
					Err(_) => Bool.False
				})
	}

	valid_principal : Str -> Bool
	valid_principal = |value| !value.is_empty() and value == value.trim() and value.count_utf8_bytes() <= 320
}
