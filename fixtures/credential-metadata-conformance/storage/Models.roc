import pf.Table

Models :: [].{
	KeyReceipt := { family : Str, lineage : Str, head : Str, revision : U64 }.{
		table : Table(KeyReceipt, _)
		table = Table.keyed(|_row| {})
	}

	Entry := { note : Str }.{
		table : Table(Entry, _)
		table = Table.keyed(|_row| {})
	}

	UseReceipt := { note : Str }.{
		table : Table(UseReceipt, _)
		table = Table.keyed(|_row| {})
	}
}
